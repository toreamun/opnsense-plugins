"""Unit tests for leasekeeper.route.DefaultRouteReconciler.

A FakeRoute stands in for /sbin/route (monkeypatched onto subprocess.run) and
tracks a single default nexthop plus the verbs issued, so tests assert both the
resulting FIB and that idempotent / observe / off paths issue no mutation.

Tests reach into private state by design; comments over per-test docstrings."""
# pylint: disable=protected-access, missing-function-docstring
import types

import pytest

from leasekeeper.route import RouteCommand

GW = "185.41.66.1"
GW2 = "185.41.66.9"
CGNAT_GW = "100.64.4.1"   # the production case: a 100.64/10 single-IP CGNAT WAN


class FakeRoute:
    """In-memory stand-in for `/sbin/route`: one default nexthop, verb log."""

    def __init__(self, initial=None, broken=(), lying=()):
        self.gw = initial
        self.calls = []
        self.broken = set(broken)  # verbs that fail with a genuine (non-benign) error
        self.lying = set(lying)    # verbs that exit 0 but do NOT mutate the FIB

    def run(self, cmd, **_kwargs):  # capture_output / errors / timeout -- ignored
        # One return (accumulate rc/out/err) to keep the verb branches readable
        # without tripping too-many-return-statements.
        self.calls.append(list(cmd))
        verb = cmd[2]  # ["/sbin/route","-n",verb,"-inet","default"[,gw]]
        rc, out, err = 0, "", ""
        if verb in self.broken:  # a real failure: stuck route / bad socket, not a no-op
            rc, err = 1, "route: writing to routing socket: permission denied"
        elif verb == RouteCommand.GET:
            has = self.gw is not None  # empty table exits non-zero
            rc = 0 if has else 1
            out = f"   gateway: {self.gw}\n   flags: <UP,GATEWAY>\n" if has else ""
            err = "" if has else "route: not in table"
        elif verb == RouteCommand.ADD:
            if self.gw is not None:  # FreeBSD: add fails when a default already exists
                rc, err = 1, "route: writing to routing socket: File exists"
            elif verb not in self.lying:  # a lying add exits 0 but leaves the FIB unchanged
                self.gw = cmd[-1]
        elif verb == RouteCommand.CHANGE:
            if self.gw is None:  # FreeBSD: change fails when no route exists to change
                rc, err = 1, "route: change net default: not in table"
            else:
                self.gw = cmd[-1]  # on-link swaps in place; off-link is broken={RouteCommand.CHANGE}
        elif verb == RouteCommand.DELETE:
            existed = self.gw is not None
            self.gw = None
            rc, err = (0, "") if existed else (1, "not in table")
        return types.SimpleNamespace(returncode=rc, stdout=out, stderr=err)

    @property
    def verbs(self):
        return [c[2] for c in self.calls]


def _rec(lk, monkeypatch, mode, initial=None, *,  # pylint: disable=too-many-arguments
         broken=(), lying=(), **kw):
    fake = FakeRoute(initial, broken=broken, lying=lying)
    monkeypatch.setattr(lk.subprocess, "run", fake.run)
    return lk.DefaultRouteReconciler(mode=mode, **kw), fake


# ---- off / observe never mutate ----

def test_off_never_touches_fib(lk, monkeypatch):
    rec, fake = _rec(lk, monkeypatch, "off")
    rec.reconcile(True, True, GW)
    assert fake.gw is None
    assert not fake.calls  # off short-circuits before any route call


def test_observe_would_install_does_not_mutate(lk, monkeypatch):
    # observe master+bound: logs a would-install but never writes the FIB.
    rec, fake = _rec(lk, monkeypatch, "observe")
    rec.reconcile(True, True, GW)
    assert fake.gw is None
    assert RouteCommand.ADD not in fake.verbs and RouteCommand.DELETE not in fake.verbs


def test_observe_would_withdraw_does_not_mutate(lk, monkeypatch):
    # observe backup with an existing default: logs a would-withdraw but leaves it.
    rec, fake = _rec(lk, monkeypatch, "observe", initial=GW)
    rec.reconcile(False, False, None)
    assert fake.gw == GW
    assert RouteCommand.DELETE not in fake.verbs


# ---- enforce: install / withdraw / correct / idempotent ----

def test_enforce_master_installs(lk, monkeypatch):
    rec, fake = _rec(lk, monkeypatch, "enforce")
    rec.reconcile(True, True, GW)
    assert fake.gw == GW
    assert RouteCommand.ADD in fake.verbs


def test_enforce_idempotent_no_change_when_correct(lk, monkeypatch):
    rec, fake = _rec(lk, monkeypatch, "enforce", initial=GW)
    rec.reconcile(True, True, GW)
    assert fake.gw == GW
    assert fake.verbs == [RouteCommand.GET]  # compare-then-act: no add/delete, no churn


def test_install_reads_the_fib_back_to_confirm(lk, monkeypatch, caplog):
    # the success path must CONFIRM the FIB (a second get after the add), not
    # trust the add's exit code -- the read-back is what test_lying_add relies on.
    rec, fake = _rec(lk, monkeypatch, "enforce")
    with caplog.at_level("INFO", logger="lease-keeper"):
        rec.reconcile(True, True, GW)
    assert fake.verbs == [RouteCommand.GET, RouteCommand.ADD, RouteCommand.GET]  # top read, install, confirm read-back
    assert any(r.getMessage() == f"installed default via {GW}" for r in caplog.records)


def test_lying_add_success_is_caught_by_confirm(lk, monkeypatch, caplog):
    # route(8) exits 0 but the FIB did not actually take the default (a "lying"
    # success): the confirm read-back, not the exit code, catches it. An
    # implementation that trusted the add's returncode would falsely log success.
    rec, fake = _rec(lk, monkeypatch, "enforce", lying={RouteCommand.ADD})
    with caplog.at_level("INFO", logger="lease-keeper"):
        rec.reconcile(True, True, GW)
    assert fake.gw is None  # never actually installed despite the rc 0
    assert any(f"failed to install default via {GW}" in r.getMessage() for r in caplog.records)
    assert not any(r.getMessage().startswith("installed default via") for r in caplog.records)


def test_enforce_installs_cgnat_gateway(lk, monkeypatch):
    # the plugin exists for a CGNAT single-IP WAN; a 100.64/10 gateway is the
    # production case, so exercise the install through one end to end.
    rec, fake = _rec(lk, monkeypatch, "enforce")
    rec.reconcile(True, True, CGNAT_GW)
    assert fake.gw == CGNAT_GW and RouteCommand.ADD in fake.verbs


def test_enforce_corrects_wrong_nexthop(lk, monkeypatch):
    rec, fake = _rec(lk, monkeypatch, "enforce", initial=GW2)
    rec.reconcile(True, True, GW)
    assert fake.gw == GW
    # atomic replace via `route change`: no delete-then-add, so no no-default gap
    assert fake.verbs == [RouteCommand.GET, RouteCommand.CHANGE, RouteCommand.GET]


def test_enforce_backup_withdraws(lk, monkeypatch):
    rec, fake = _rec(lk, monkeypatch, "enforce", initial=GW)
    rec.reconcile(False, False, None)
    assert fake.gw is None
    assert RouteCommand.DELETE in fake.verbs


def test_enforce_backup_absent_is_noop(lk, monkeypatch):
    rec, fake = _rec(lk, monkeypatch, "enforce")
    rec.reconcile(False, False, None)
    assert fake.gw is None
    assert fake.verbs == [RouteCommand.GET]  # nothing to withdraw


def test_master_without_lease_withdraws_despite_sticky_gateway(lk, monkeypatch):
    # bound=False even though a (sticky) gateway is still known: must not keep
    # the default -- this is the MasterNoLease fail-stop.
    rec, fake = _rec(lk, monkeypatch, "enforce", initial=GW)
    rec.reconcile(True, False, GW)
    assert fake.gw is None
    assert RouteCommand.DELETE in fake.verbs


# ---- unreadable role: fail-safe install, fail-closed withdraw ----

def test_unreadable_role_never_installs(lk, monkeypatch):
    rec, fake = _rec(lk, monkeypatch, "enforce", unreadable_role_strikes=3)
    for _ in range(10):
        rec.reconcile(None, True, GW)
    assert fake.gw is None
    assert RouteCommand.ADD not in fake.verbs


def test_unreadable_role_withdraws_after_strike_limit(lk, monkeypatch):
    rec, fake = _rec(lk, monkeypatch, "enforce", initial=GW, unreadable_role_strikes=3)
    rec.reconcile(None, True, GW)
    rec.reconcile(None, True, GW)
    assert fake.gw == GW              # held for the first strike_limit-1 checks
    assert RouteCommand.DELETE not in fake.verbs
    rec.reconcile(None, True, GW)     # third strike -> fail closed
    assert fake.gw is None
    assert RouteCommand.DELETE in fake.verbs


def test_unreadable_role_but_unbound_withdraws_immediately(lk, monkeypatch):
    # Role unreadable AND no lease held: nothing to be master of, so withdraw at
    # once instead of holding the default through the strike tolerance (which is
    # reserved for a bound node that might still legitimately be master).
    rec, fake = _rec(lk, monkeypatch, "enforce", initial=GW, unreadable_role_strikes=3)
    rec.reconcile(None, False, None)   # probe failed, but we hold no lease
    assert fake.gw is None             # withdrawn on the first call, not after 3 strikes
    assert RouteCommand.DELETE in fake.verbs


def test_unreadable_role_with_unusable_gateway_withdraws_immediately(lk, monkeypatch):
    # Same: an unusable (0.0.0.0) gateway is not a lease to be master of, so an
    # unreadable role does not earn the strike tolerance -- withdraw now.
    rec, fake = _rec(lk, monkeypatch, "enforce", initial=GW, unreadable_role_strikes=3)
    rec.reconcile(None, True, "0.0.0.0")
    assert fake.gw is None and RouteCommand.DELETE in fake.verbs


def test_definite_role_resets_strikes(lk, monkeypatch):
    rec, fake = _rec(lk, monkeypatch, "enforce", initial=GW, unreadable_role_strikes=3)
    rec.reconcile(None, True, GW)
    rec.reconcile(None, True, GW)
    rec.reconcile(True, True, GW)     # definite read resets the counter
    rec.reconcile(None, True, GW)     # strike 1 again, not 4
    assert fake.gw == GW              # still held, not withdrawn


def test_unreadable_role_warns_once_per_episode_and_rearms(lk, monkeypatch, caplog):
    # the fail-closed warning fires once per unreadable EPISODE (not per tick, and
    # not once ever): a definite read re-arms it so a later episode warns again.
    rec, fake = _rec(lk, monkeypatch, "enforce", initial=GW, unreadable_role_strikes=2)
    with caplog.at_level("WARNING", logger="lease-keeper"):
        for _ in range(5):            # first episode, well past the strike limit
            rec.reconcile(None, True, GW)
        assert len([r for r in caplog.records if "failing closed" in r.getMessage()]) == 1
        rec.reconcile(True, True, GW)  # definite: resets strikes, re-arms, reinstalls
        assert fake.gw == GW
        for _ in range(5):            # second episode -> a second, distinct warning
            rec.reconcile(None, True, GW)
    assert len([r for r in caplog.records if "failing closed" in r.getMessage()]) == 2


# ---- liveness gate (split-brain guard) ----

def test_liveness_false_blocks_install(lk, monkeypatch):
    rec, fake = _rec(lk, monkeypatch, "enforce", liveness_probe=lambda: False)
    rec.reconcile(True, True, GW)
    assert fake.gw is None
    assert RouteCommand.ADD not in fake.verbs


def test_liveness_false_withdraws_existing(lk, monkeypatch):
    rec, fake = _rec(lk, monkeypatch, "enforce", initial=GW, liveness_probe=lambda: False)
    rec.reconcile(True, True, GW)
    assert fake.gw is None            # dead-WAN master stops advertising


def test_liveness_none_does_not_block(lk, monkeypatch):
    rec, fake = _rec(lk, monkeypatch, "enforce", liveness_probe=lambda: None)
    rec.reconcile(True, True, GW)
    assert fake.gw == GW


def test_liveness_exception_does_not_block(lk, monkeypatch):
    def boom():
        raise RuntimeError("probe broke")
    rec, fake = _rec(lk, monkeypatch, "enforce", liveness_probe=boom)
    rec.reconcile(True, True, GW)
    assert fake.gw == GW              # a broken probe must not block routing


# ---- get-parsing edge cases ----

def test_empty_table_reads_as_no_default(lk, monkeypatch):
    rec, fake = _rec(lk, monkeypatch, "enforce")
    assert rec._fib_default_gateway() is None  # returncode 1 -> None, not a raise
    assert fake.verbs == [RouteCommand.GET]


def test_get_without_gateway_line_reads_absent(lk, monkeypatch):
    # route get succeeds (rc 0) for an interface-scoped default with no gateway
    # field (e.g. a point-to-point/PPP default) -- parses as "no default".
    monkeypatch.setattr(lk.subprocess, "run", lambda *a, **k: types.SimpleNamespace(
        returncode=0, stdout="   interface: pppoe0\n   flags: <UP>\n", stderr=""))
    rec = lk.DefaultRouteReconciler(mode="enforce")
    assert rec._fib_default_gateway() is None


def test_get_failure_reads_absent_quietly(lk, monkeypatch, caplog):
    # a failed / empty-table `route get` is the quiet steady state on a backup:
    # read as "no default" with NO warning -- route(8) wording varies by
    # platform, so a stuck op is caught by the install/withdraw confirm instead.
    monkeypatch.setattr(lk.subprocess, "run", lambda *a, **k: types.SimpleNamespace(
        returncode=1, stdout="", stderr="route: not in table"))
    rec = lk.DefaultRouteReconciler(mode="enforce")
    with caplog.at_level("WARNING", logger="lease-keeper"):
        assert rec._fib_default_gateway() is None
    assert not [r for r in caplog.records if r.levelname in ("WARNING", "ERROR")]


def test_run_swallows_subprocess_exception(lk, monkeypatch):
    def boom(*_a, **_k):
        raise OSError("route binary missing")
    monkeypatch.setattr(lk.subprocess, "run", boom)
    rec = lk.DefaultRouteReconciler(mode="enforce")
    assert rec._fib_default_gateway() is None
    rec.reconcile(True, True, GW)  # must not raise out of the maintain loop


# ---- unknown / invalid construction ----

def test_unknown_mode_coerces_to_off_and_warns(lk, monkeypatch, caplog):
    with caplog.at_level("WARNING", logger="lease-keeper"):
        rec, fake = _rec(lk, monkeypatch, "bogus")
    assert rec.mode is lk.DefaultRouteMode.OFF and rec.enabled is False
    assert any("unknown default-route mode" in r.getMessage() for r in caplog.records)
    rec.reconcile(True, True, GW)
    assert not fake.calls  # off is inert: never even reads the FIB


def test_valid_mode_maps_through_verbatim(lk, monkeypatch):
    rec, _ = _rec(lk, monkeypatch, "enforce")
    assert rec.mode is lk.DefaultRouteMode.ENFORCE and rec.enabled is True


def test_mode_is_read_only(lk, monkeypatch):
    rec, _ = _rec(lk, monkeypatch, "observe")
    with pytest.raises(AttributeError):
        rec.mode = lk.DefaultRouteMode.ENFORCE  # set-once, no setter


def test_strike_limit_must_be_positive(lk):
    with pytest.raises(ValueError):
        lk.DefaultRouteReconciler(mode="enforce", unreadable_role_strikes=0)


# ---- a bogus / rogue option-3 gateway is never installed ----

def test_bogus_gateway_is_not_installed(lk, monkeypatch):
    rec, fake = _rec(lk, monkeypatch, "enforce")
    rec.reconcile(True, True, "0.0.0.0")  # rogue / malformed option 3
    assert fake.gw is None and RouteCommand.ADD not in fake.verbs


def test_bogus_gateway_withdraws_existing(lk, monkeypatch):
    # master+bound but an unusable gateway must not KEEP a default it can't honour.
    rec, fake = _rec(lk, monkeypatch, "enforce", initial=GW)
    rec.reconcile(True, True, "0.0.0.0")
    assert fake.gw is None and RouteCommand.DELETE in fake.verbs


def test_bound_without_gateway_withdraws(lk, monkeypatch):
    # a lease with no router option (gateway None) cannot back a default -> withdraw,
    # and _sane_ipv4(None) must be handled, not raise.
    rec, fake = _rec(lk, monkeypatch, "enforce", initial=GW)
    rec.reconcile(True, True, None)
    assert fake.gw is None and RouteCommand.DELETE in fake.verbs


# ---- a genuine route-command failure is surfaced, not buried as a no-op ----

def test_failed_withdraw_is_logged_and_default_stays(lk, monkeypatch, caplog):
    rec, fake = _rec(lk, monkeypatch, "enforce", initial=GW, broken={RouteCommand.DELETE})
    with caplog.at_level("ERROR", logger="lease-keeper"):
        rec.reconcile(False, False, None)  # backup -> should withdraw, but delete is stuck
    assert fake.gw == GW  # the default is still in the FIB (the fail-stop breach we must SEE)
    assert any("failed to withdraw default" in r.getMessage() for r in caplog.records)
    assert not any("withdrew default" in r.getMessage() for r in caplog.records)


def test_rejected_change_on_replace_keeps_old_and_errors(lk, monkeypatch, caplog):
    # the atomic `route change` is rejected (bench-confirmed on FreeBSD 14.3 when
    # the new gateway is not on-link, e.g. a cross-subnet lease whose interface has
    # not moved yet): the FIB keeps the OLD default -- never torn down or
    # black-holed -- and the confirm read-back surfaces that the new one is not in.
    rec, fake = _rec(lk, monkeypatch, "enforce", initial=GW, broken={RouteCommand.CHANGE})
    with caplog.at_level("ERROR", logger="lease-keeper"):
        rec.reconcile(True, True, GW2)  # replace GW -> GW2, but the change is rejected
    assert fake.gw == GW  # old gateway kept intact, not withdrawn
    assert RouteCommand.DELETE not in fake.verbs  # the working default is never removed on a failed replace
    assert any("failed to install default via " + GW2 in r.getMessage() for r in caplog.records)


def test_fresh_install_add_failure_is_logged_absent(lk, monkeypatch, caplog):
    # first install (no prior default) and the add itself fails: the replacing=None
    # arm skips the delete, the add fails, and the confirm reads the FIB as absent
    # -> a surfaced ERROR naming the empty FIB, not a silent claim of success.
    rec, fake = _rec(lk, monkeypatch, "enforce", broken={RouteCommand.ADD})
    with caplog.at_level("ERROR", logger="lease-keeper"):
        rec.reconcile(True, True, GW)
    assert fake.gw is None
    assert any(f"failed to install default via {GW}" in r.getMessage()
               and "absent" in r.getMessage() for r in caplog.records)


# ---- desired-state confirmation: INFO on entry/change, then a throttled DEBUG
# heartbeat. The per-tick repeat within the heartbeat window is suppressed (see
# test_reconcile_heartbeat_throttle_cycle) so a quiet node does not churn the log. ----

def _levels_for(caplog, needle):
    return [r.levelname for r in caplog.records if needle in r.getMessage()]


def test_enforce_owning_heartbeat_states_at_info(lk, monkeypatch, caplog):
    # a steady, already-correct master states ownership positively (not silence) at
    # INFO on entry; the immediate per-tick repeat is throttled away.
    rec, _ = _rec(lk, monkeypatch, "enforce", initial=GW)
    with caplog.at_level("DEBUG", logger="lease-keeper"):
        rec.reconcile(True, True, GW)   # already correct -> entry
        rec.reconcile(True, True, GW)   # unchanged repeat -> throttled
    assert _levels_for(caplog, f"owning default via {GW}") == ["INFO"]


def test_enforce_no_default_heartbeat_names_reason(lk, monkeypatch, caplog):
    # a backup that holds the (shared-vMAC) lease but is not master confirms it has
    # correctly no default, with the reason, at INFO on entry (the repeat throttled).
    rec, _ = _rec(lk, monkeypatch, "enforce")
    with caplog.at_level("DEBUG", logger="lease-keeper"):
        rec.reconcile(False, True, GW)
        rec.reconcile(False, True, GW)
    msgs = [r for r in caplog.records if "no default held (CARP backup)" in r.getMessage()]
    assert [r.levelname for r in msgs] == ["INFO"]


def test_observe_would_install_states_at_info(lk, monkeypatch, caplog):
    # observe never writes the FIB, so the would-install condition persists every
    # tick; log it once at INFO instead of forever (the repeat throttled).
    rec, _ = _rec(lk, monkeypatch, "observe")
    with caplog.at_level("DEBUG", logger="lease-keeper"):
        rec.reconcile(True, True, GW)
        rec.reconcile(True, True, GW)
    assert _levels_for(caplog, "would install default") == ["INFO"]


def test_observe_would_withdraw_states_at_info(lk, monkeypatch, caplog):
    rec, _ = _rec(lk, monkeypatch, "observe", initial=GW)
    with caplog.at_level("DEBUG", logger="lease-keeper"):
        rec.reconcile(False, False, None)
        rec.reconcile(False, False, None)
    assert _levels_for(caplog, "would withdraw default") == ["INFO"]


def test_reconcile_heartbeat_throttle_cycle(lk, monkeypatch, caplog):
    # the steady-state decision logs INFO once on entry, suppresses the per-tick
    # repeat within the heartbeat window, emits a single DEBUG once the window
    # elapses, and returns to INFO (re-arming the throttle) the moment the decision
    # actually changes -- so a quiet node cannot fill the log with a per-tick line.
    rec, _ = _rec(lk, monkeypatch, "observe")
    with caplog.at_level("DEBUG", logger="lease-keeper"):
        rec.reconcile(True, True, GW)        # would-install entry -> INFO
        rec.reconcile(True, True, GW)        # within the window -> suppressed
        assert _levels_for(caplog, "would install default") == ["INFO"]
        rec._heartbeat._deadline = 0         # the heartbeat window has elapsed
        rec.reconcile(True, True, GW)        # -> a single DEBUG heartbeat
        assert _levels_for(caplog, "would install default") == ["INFO", "DEBUG"]
        rec.reconcile(False, False, None)    # the decision changes -> INFO, re-arm
        rec.reconcile(False, False, None)    # immediate repeat -> suppressed again
    assert _levels_for(caplog, "no default held") == ["INFO"]


def test_liveness_withdraw_names_the_reason(lk, monkeypatch, caplog):
    # a withdraw forced by the liveness gate says so, so the operator does not
    # misread it as a plain CARP role loss.
    rec, _ = _rec(lk, monkeypatch, "enforce", initial=GW, liveness_probe=lambda: False)
    with caplog.at_level("INFO", logger="lease-keeper"):
        rec.reconcile(True, True, GW)
    assert any("withdrew default" in r.getMessage() and "liveness not confirmed" in r.getMessage()
               for r in caplog.records)


def test_no_default_reason_no_usable_lease(lk, monkeypatch, caplog):
    # master but holding no lease: the no-default heartbeat names "no usable lease"
    # (not "CARP backup"), so the operator sees WHY there is no default.
    rec, _ = _rec(lk, monkeypatch, "enforce")
    with caplog.at_level("INFO", logger="lease-keeper"):
        rec.reconcile(True, False, None)
    assert any("no default held (no usable lease)" in r.getMessage() for r in caplog.records)


def test_gateway_change_relogs_ownership_at_info(lk, monkeypatch, caplog):
    # the desired state is keyed on (want, gateway): a follow to a new gateway is a
    # change, so ownership is stated again at INFO, not silenced as unchanged.
    rec, _ = _rec(lk, monkeypatch, "enforce", initial=GW)
    with caplog.at_level("DEBUG", logger="lease-keeper"):
        rec.reconcile(True, True, GW)     # own via GW (INFO)
        rec.reconcile(True, True, GW2)    # gateway changed -> install GW2 (INFO)
    assert _levels_for(caplog, f"owning default via {GW}") == ["INFO"]
    assert any(r.levelname == "INFO" and f"installed default via {GW2}" in r.getMessage()
               for r in caplog.records)
