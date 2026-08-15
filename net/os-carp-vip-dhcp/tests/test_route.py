"""Unit tests for leasekeeper.route (DefaultRouteReconciler, BackupEgressReconciler
and the module-level withdraw_unless_master).

A FakeRoute stands in for /sbin/route (monkeypatched onto subprocess.run) and
tracks a single default nexthop plus the verbs issued, so tests assert both the
resulting FIB and that idempotent / observe / off paths issue no mutation.

Tests reach into private state by design; comments over per-test docstrings."""
# pylint: disable=protected-access, missing-function-docstring, too-many-lines
import types

import pytest

from leasekeeper.route import BackupEgressConfig, BackupEgressForm, RouteCommand

GW = "185.41.66.1"
GW2 = "185.41.66.9"
CGNAT_GW = "100.64.4.1"   # the production case: a 100.64/10 single-IP CGNAT WAN


class FakeRoute:
    """In-memory stand-in for /sbin/route + /usr/bin/netstat + /sbin/ifconfig: a
    dest->nexthop table (dest 'default' or a CIDR), a verb log, and per-interface
    (addr, prefixlen) for backup-egress peer derivation. `gw` is the default's
    nexthop, kept as a property so the default-route tests read it unchanged."""

    def __init__(self, initial=None, *, broken=(), lying=(),  # pylint: disable=too-many-arguments
                 ifaces=None, netstat_fails=False, local_ips=()):
        self.routes = {}
        if initial is not None:
            self.routes["default"] = initial
        self.calls = []
        self.broken = set(broken)  # verbs that fail with a genuine (non-benign) error
        self.lying = set(lying)    # verbs that exit 0 but do NOT mutate the FIB
        self.ifaces = dict(ifaces or {})   # iface -> (addr, prefixlen)
        self.netstat_fails = netstat_fails  # netstat -rn exits non-zero (unreadable table)
        self.local_ips = set(local_ips)     # addresses a `route get` resolves to lo0 (own IPs)

    @property
    def gw(self):
        return self.routes.get("default")

    @gw.setter
    def gw(self, value):
        if value is None:
            self.routes.pop("default", None)
        else:
            self.routes["default"] = value

    def run(self, cmd, **_kwargs):  # capture_output / errors / timeout -- ignored
        self.calls.append(list(cmd))
        prog = cmd[0]
        if prog.endswith("netstat"):
            if self.netstat_fails:
                return self._reply(1, "", "netstat: routing table unavailable")
            return self._reply(0, self._netstat_body())
        if prog.endswith("ifconfig"):
            return self._ifconfig(cmd[1])
        return self._route(cmd)

    def _route(self, cmd):
        # ["/sbin/route","-n",verb,"-inet",dest[,gw]]; single return to keep the verb
        # branches readable without tripping too-many-return-statements.
        verb, dest = cmd[2], cmd[4]
        rc, out, err = 0, "", ""
        if verb in self.broken:  # a real failure: stuck route / bad socket, not a no-op
            rc, err = 1, "route: writing to routing socket: permission denied"
        elif verb == RouteCommand.GET:
            if dest in self.routes:                 # a known route dest (e.g. "default")
                out = f"   gateway: {self.routes[dest]}\n   interface: vlan0\n"
            elif dest == "default":                 # no default installed
                rc, err = 1, "route: not in table"
            else:                                   # host lookup (used by _gateway_is_own):
                iface = "lo0" if dest in self.local_ips else "vlan0"  # own IP resolves to lo0
                out = f"   gateway: {dest}\n   interface: {iface}\n"
        elif verb == RouteCommand.ADD:
            if self.routes.get(dest) is not None:  # FreeBSD: add fails when it exists
                rc, err = 1, "route: writing to routing socket: File exists"
            elif verb not in self.lying:  # a lying add exits 0 but leaves the FIB unchanged
                self.routes[dest] = cmd[-1]
        elif verb == RouteCommand.CHANGE:
            if self.routes.get(dest) is None:  # change fails when no route exists
                rc, err = 1, "route: change: not in table"
            else:
                self.routes[dest] = cmd[-1]  # on-link swaps in place; off-link is broken={CHANGE}
        elif verb == RouteCommand.DELETE:
            existed = self.routes.pop(dest, None) is not None
            rc, err = (0, "") if existed else (1, "not in table")
        return self._reply(rc, out, err)

    def _netstat_body(self):
        lines = ["Routing tables", "", "Internet:",
                 "Destination        Gateway            Flags     Netif"]
        for dest, gw in self.routes.items():
            shown = dest[:-3] if dest.endswith("/32") else dest  # FreeBSD prints host routes bare
            lines.append(f"{shown}        {gw}        UGS       vlan0")
        return "\n".join(lines) + "\n"

    def _ifconfig(self, iface):
        info = self.ifaces.get(iface)
        if info is None:
            return self._reply(1, "", f"ifconfig: interface {iface} does not exist")
        addr, prefixlen = info
        mask = (0xffffffff << (32 - prefixlen)) & 0xffffffff if prefixlen else 0
        body = f"{iface}: flags=8843<UP>\n\tinet {addr} netmask 0x{mask:08x} broadcast 0.0.0.0\n"
        return self._reply(0, body)

    @staticmethod
    def _reply(rc, out, err=""):
        return types.SimpleNamespace(returncode=rc, stdout=out, stderr=err)

    @property
    def verbs(self):
        return [c[2] for c in self.calls if c[0].endswith("route")]


def _fake(lk, monkeypatch, initial=None, **fake_kw):
    # Build a FakeRoute and route subprocess.run through it -- the setup shared by the
    # three reconciler factories below.
    fake = FakeRoute(initial, **fake_kw)
    monkeypatch.setattr(lk.subprocess, "run", fake.run)
    return fake


def _rec(lk, monkeypatch, mode, initial=None, *,  # pylint: disable=too-many-arguments
         broken=(), lying=(), ifaces=None, netstat_fails=False, local_ips=(), **kw):
    fake = _fake(lk, monkeypatch, initial, broken=broken, lying=lying, ifaces=ifaces,
                 netstat_fails=netstat_fails, local_ips=local_ips)
    return lk.DefaultRouteReconciler(mode=mode, **kw), fake


def _backup(lk, monkeypatch, mode, initial=None, *,  # pylint: disable=too-many-arguments
            broken=(), lying=(), ifaces=None, netstat_fails=False, local_ips=(),
            backup_egress=None):
    # A BackupEgressReconciler over a FakeRoute (the backup-egress tests). A bare call
    # (no backup_egress) yields the disabled reconciler for the inert-path tests.
    fake = _fake(lk, monkeypatch, initial, broken=broken, lying=lying, ifaces=ifaces,
                 netstat_fails=netstat_fails, local_ips=local_ips)
    return lk.BackupEgressReconciler(mode, backup_egress=backup_egress or BackupEgressConfig()), fake


def _pair(lk, monkeypatch, mode, initial=None, *,  # pylint: disable=too-many-arguments
          broken=(), lying=(), ifaces=None, netstat_fails=False, local_ips=(),
          backup_egress=None):
    # Both reconcilers over one shared FakeRoute, for the cross-cutting paths
    # (withdraw_unless_master and the 0/0-vs-backup independence check).
    fake = _fake(lk, monkeypatch, initial, broken=broken, lying=lying, ifaces=ifaces,
                 netstat_fails=netstat_fails, local_ips=local_ips)
    default = lk.DefaultRouteReconciler(mode)
    backup = lk.BackupEgressReconciler(mode, backup_egress=backup_egress or BackupEgressConfig())
    return default, backup, fake


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


def test_default_route_mode_coerce(lk, caplog):
    # Valid values (string or member) pass through; anything else is inert OFF + a warning,
    # so a hand-edited config never activates a mode nor crash-loops the daemon.
    assert lk.DefaultRouteMode.coerce("enforce") is lk.DefaultRouteMode.ENFORCE
    assert lk.DefaultRouteMode.coerce(lk.DefaultRouteMode.OBSERVE) is lk.DefaultRouteMode.OBSERVE
    with caplog.at_level("WARNING", logger="lease-keeper"):
        assert lk.DefaultRouteMode.coerce("bogus") is lk.DefaultRouteMode.OFF
    assert any("unknown default-route mode" in r.getMessage() for r in caplog.records)


def test_backup_egress_form_coerce(lk, caplog):
    # Same contract for the egress form: unrecognised -> leak-safe SPLIT + a warning
    # (previously a bad value raised and crash-looped the supervised daemon).
    assert lk.BackupEgressForm.coerce("prefixes") is lk.BackupEgressForm.PREFIXES
    assert lk.BackupEgressForm.coerce(lk.BackupEgressForm.SPLIT) is lk.BackupEgressForm.SPLIT
    with caplog.at_level("WARNING", logger="lease-keeper"):
        assert lk.BackupEgressForm.coerce("bogus") is lk.BackupEgressForm.SPLIT
    assert any("unknown backup-egress form" in r.getMessage() for r in caplog.records)


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


# ---- backup egress (optional feature; docs/backup-egress.md) ----

BE_GW = "10.168.9.1"


def _becfg(**kw):
    kw.setdefault("enabled", True)
    return BackupEgressConfig(**kw)


def test_backup_egress_disabled_is_inert(lk, monkeypatch):
    # no backup_egress config -> the reconcile is a no-op, issues nothing.
    rec, fake = _backup(lk, monkeypatch, "enforce")
    rec.reconcile_backup_egress(False)
    assert not fake.calls


def test_backup_egress_off_mode_inert(lk, monkeypatch):
    # off mode: even with the feature enabled, nothing runs.
    rec, fake = _backup(lk, monkeypatch, "off", backup_egress=_becfg(gateway=BE_GW))
    rec.reconcile_backup_egress(False)
    assert not fake.calls


def test_backup_egress_installs_split_on_backup(lk, monkeypatch):
    rec, fake = _backup(lk, monkeypatch, "enforce", backup_egress=_becfg(gateway=BE_GW))
    rec.reconcile_backup_egress(False)
    assert fake.routes.get("0.0.0.0/1") == BE_GW
    assert fake.routes.get("128.0.0.0/1") == BE_GW


def test_backup_egress_removed_on_master(lk, monkeypatch):
    rec, fake = _backup(lk, monkeypatch, "enforce", backup_egress=_becfg(gateway=BE_GW))
    fake.routes["0.0.0.0/1"] = fake.routes["128.0.0.0/1"] = BE_GW
    rec.reconcile_backup_egress(True)
    assert "0.0.0.0/1" not in fake.routes and "128.0.0.0/1" not in fake.routes


def test_backup_egress_role_swap(lk, monkeypatch):
    rec, fake = _backup(lk, monkeypatch, "enforce", backup_egress=_becfg(gateway=BE_GW))
    rec.reconcile_backup_egress(False)                 # backup -> installed
    assert fake.routes.get("0.0.0.0/1") == BE_GW
    rec.reconcile_backup_egress(True)                  # master -> removed
    assert "0.0.0.0/1" not in fake.routes
    rec.reconcile_backup_egress(False)                 # backup again -> reinstalled
    assert fake.routes.get("0.0.0.0/1") == BE_GW


def test_backup_egress_idempotent_no_churn(lk, monkeypatch):
    rec, fake = _backup(lk, monkeypatch, "enforce", backup_egress=_becfg(gateway=BE_GW))
    rec.reconcile_backup_egress(False)
    n = len(fake.calls)
    rec.reconcile_backup_egress(False)                 # already correct
    # the second pass reads (own-check route get + netstat) but issues no route mutation.
    mutations = [c for c in fake.calls[n:] if c[0].endswith("route")
                 and c[2] in (RouteCommand.ADD, RouteCommand.CHANGE, RouteCommand.DELETE)]
    assert fake.calls[n:] and not mutations


def test_backup_egress_unknown_role_touches_nothing(lk, monkeypatch):
    rec, fake = _backup(lk, monkeypatch, "enforce", backup_egress=_becfg(gateway=BE_GW))
    rec.reconcile_backup_egress(None)
    assert not fake.calls


def test_backup_egress_derive_peer_on_ptp(lk, monkeypatch):
    # gateway blank + a /30 interface -> derive the other host as the peer/master.
    rec, fake = _backup(lk, monkeypatch, "enforce",
                        backup_egress=_becfg(interface="sync0"),
                        ifaces={"sync0": ("10.168.9.2", 30)})
    rec.reconcile_backup_egress(False)
    assert fake.routes.get("0.0.0.0/1") == "10.168.9.1"


def test_backup_egress_derive_non_ptp_inactive(lk, monkeypatch, caplog):
    # a /24 interface has no unique peer -> warn and install nothing.
    rec, fake = _backup(lk, monkeypatch, "enforce",
                        backup_egress=_becfg(interface="lan0"),
                        ifaces={"lan0": ("10.168.1.3", 24)})
    with caplog.at_level("WARNING", logger="lease-keeper"):
        rec.reconcile_backup_egress(False)
    assert "0.0.0.0/1" not in fake.routes
    assert any("not a point-to-point" in r.getMessage() for r in caplog.records)


def test_backup_egress_derive_form_master_removes_own_route(lk, monkeypatch):
    # Derive form (no configured gateway): ownership rests only on the gateway confirmed
    # this session. A backup that inherits (or installs) its own /1 via the derived peer
    # must still remove it on promotion -- else an empty ownership set on the derived-peer
    # master would treat its own leftover as foreign and loop egress. Regression for the
    # ownership-lost-on-restart bug: ownership is recorded on the confirmed-present path.
    rec, fake = _backup(lk, monkeypatch, "enforce",
                        backup_egress=_becfg(interface="sync0"),
                        ifaces={"sync0": ("10.168.9.2", 30)})
    fake.routes["0.0.0.0/1"] = fake.routes["128.0.0.0/1"] = "10.168.9.1"   # inherited via the peer
    rec.reconcile_backup_egress(False)             # backup tick confirms the set is ours
    rec.reconcile_backup_egress(True)              # promote -> must remove our own /1
    assert "0.0.0.0/1" not in fake.routes and "128.0.0.0/1" not in fake.routes


def test_backup_egress_derive_peer_change_uses_change(lk, monkeypatch):
    # Derive form: when the interface is re-addressed so the derived peer changes, the /1
    # is updated IN PLACE (CHANGE) to the new peer -- the only path that issues CHANGE
    # (its ownership of the old next hop comes from the session-installed gateway).
    rec, fake = _backup(lk, monkeypatch, "enforce",
                        backup_egress=_becfg(interface="sync0"),
                        ifaces={"sync0": ("10.168.9.2", 30)})
    rec.reconcile_backup_egress(False)             # install via peer .1
    assert fake.routes.get("0.0.0.0/1") == "10.168.9.1"
    fake.ifaces["sync0"] = ("10.168.9.5", 30)      # re-addressed -> peer becomes .6
    rec.reconcile_backup_egress(False)
    assert fake.routes.get("0.0.0.0/1") == "10.168.9.6"
    assert RouteCommand.CHANGE in fake.verbs


def test_backup_egress_failed_change_keeps_old_ownership(lk, monkeypatch):
    # Derive form: if the peer changes A->B but `route change` FAILS, the /1 stays at A and
    # ownership of A must be preserved (not overwritten by the unconfirmed B) -- else
    # promotion would treat the still-present /1 at A as foreign and loop egress. (Ownership
    # is recorded only for gateways CONFIRMED to host our prefixes.)
    rec, fake = _backup(lk, monkeypatch, "enforce",
                        backup_egress=_becfg(interface="sync0"),
                        ifaces={"sync0": ("10.168.9.2", 30)})
    rec.reconcile_backup_egress(False)             # install via peer .1
    assert fake.routes.get("0.0.0.0/1") == "10.168.9.1"
    fake.ifaces["sync0"] = ("10.168.9.5", 30)      # peer becomes .6
    fake.broken.add(RouteCommand.CHANGE)           # the change to .6 fails
    rec.reconcile_backup_egress(False)
    assert fake.routes.get("0.0.0.0/1") == "10.168.9.1"   # still at .1 (change did not take)
    fake.broken.discard(RouteCommand.CHANGE)
    rec.reconcile_backup_egress(True)              # promote -> must remove the /1 still at .1
    assert "0.0.0.0/1" not in fake.routes and "128.0.0.0/1" not in fake.routes


def test_backup_egress_ownership_pruned_after_removal(lk, monkeypatch):
    # After removing our /1 on promotion, the old peer must NOT stay owned: if the peer then
    # changes and a route reappears via the OLD peer (e.g. a VPN takes that address), it must
    # be treated as foreign, not CHANGEd/overwritten (ownership is pruned on removal too).
    rec, fake = _backup(lk, monkeypatch, "enforce",
                        backup_egress=_becfg(interface="sync0"),
                        ifaces={"sync0": ("10.168.9.2", 30)})
    rec.reconcile_backup_egress(False)             # backup: install via peer .1 (own .1)
    rec.reconcile_backup_egress(True)              # master: remove -> ownership of .1 pruned
    fake.ifaces["sync0"] = ("10.168.9.5", 30)      # peer changes to .6
    fake.routes["0.0.0.0/1"] = "10.168.9.1"        # a foreign route reappears at the OLD peer .1
    rec.reconcile_backup_egress(False)             # back to backup, peer now .6
    assert fake.routes.get("0.0.0.0/1") == "10.168.9.1"   # old-peer route left untouched (foreign)
    assert RouteCommand.CHANGE not in fake.verbs          # never overwrote it


def test_backup_egress_collision_warns_once_and_rearms(lk, monkeypatch, caplog):
    # A persistent foreign /1 warns once (not per tick); once it clears and re-collides a
    # second warning fires -- rising-edge parity with the unresolved-gateway gate.
    rec, fake = _backup(lk, monkeypatch, "enforce", backup_egress=_becfg(gateway=BE_GW))
    fake.routes["0.0.0.0/1"] = fake.routes["128.0.0.0/1"] = "10.9.9.9"   # both foreign
    with caplog.at_level("WARNING", logger="lease-keeper"):
        for _ in range(3):
            rec.reconcile_backup_egress(False)
    assert len([r for r in caplog.records if "another next hop" in r.getMessage()]) == 1
    caplog.clear()
    fake.routes.pop("0.0.0.0/1")
    fake.routes.pop("128.0.0.0/1")                                  # foreign routes gone
    with caplog.at_level("WARNING", logger="lease-keeper"):
        rec.reconcile_backup_egress(False)                          # collision-free -> re-arm
        fake.routes["0.0.0.0/1"] = fake.routes["128.0.0.0/1"] = "10.9.9.9"
        rec.reconcile_backup_egress(False)                          # re-collide
    assert any("another next hop" in r.getMessage() for r in caplog.records)


def test_backup_egress_observe_dry_run(lk, monkeypatch, caplog):
    rec, fake = _backup(lk, monkeypatch, "observe", backup_egress=_becfg(gateway=BE_GW))
    with caplog.at_level("INFO", logger="lease-keeper"):
        rec.reconcile_backup_egress(False)
    assert "0.0.0.0/1" not in fake.routes              # observe never writes
    assert any("would route backup egress" in r.getMessage() for r in caplog.records)


def test_backup_egress_zero_prefix_dropped_under_enforce(lk, monkeypatch, caplog):
    # a 0.0.0.0/0 inside a specific-prefix list is dropped under enforce (enforce owns
    # the default); the other prefixes still install.
    rec, fake = _backup(lk, monkeypatch, "enforce",
                        backup_egress=_becfg(gateway=BE_GW, form=BackupEgressForm.PREFIXES,
                                             prefixes=("0.0.0.0/0", "192.0.2.0/24")))
    with caplog.at_level("WARNING", logger="lease-keeper"):
        rec.reconcile_backup_egress(False)
    assert "0.0.0.0/0" not in fake.routes and fake.routes.get("192.0.2.0/24") == BE_GW
    assert any("0.0.0.0/0 is owned by enforce" in r.getMessage() for r in caplog.records)


def test_backup_egress_specific_prefixes(lk, monkeypatch):
    rec, fake = _backup(lk, monkeypatch, "enforce",
                        backup_egress=_becfg(gateway=BE_GW, form=BackupEgressForm.PREFIXES,
                                             prefixes=("192.0.2.0/24",)))
    rec.reconcile_backup_egress(False)
    assert fake.routes.get("192.0.2.0/24") == BE_GW
    assert "0.0.0.0/1" not in fake.routes


def test_backup_egress_host_prefix_round_trips(lk, monkeypatch):
    # a /32 host prefix prints without a CIDR suffix in netstat; it must still round-
    # trip so we do not re-add + false-ERROR every tick.
    rec, fake = _backup(lk, monkeypatch, "enforce",
                        backup_egress=_becfg(gateway=BE_GW, form=BackupEgressForm.PREFIXES,
                                             prefixes=("192.0.2.5/32",)))
    rec.reconcile_backup_egress(False)
    assert fake.routes.get("192.0.2.5/32") == BE_GW
    n = len(fake.calls)
    rec.reconcile_backup_egress(False)                 # already correct -> no re-add
    assert not any(c[2] in (RouteCommand.ADD, RouteCommand.CHANGE) for c in fake.calls[n:]
                   if c[0].endswith("route"))


def test_backup_egress_partial_install_adds_missing_only(lk, monkeypatch):
    # one /1 already ours, the other absent -> only the absent one is added (ADD); the
    # correct one is left untouched (no CHANGE).
    rec, fake = _backup(lk, monkeypatch, "enforce", backup_egress=_becfg(gateway=BE_GW))
    fake.routes["0.0.0.0/1"] = BE_GW                   # already ours
    rec.reconcile_backup_egress(False)
    assert fake.routes["0.0.0.0/1"] == BE_GW and fake.routes["128.0.0.0/1"] == BE_GW
    assert RouteCommand.ADD in fake.verbs and RouteCommand.CHANGE not in fake.verbs


def test_backup_egress_install_leaves_foreign_route(lk, monkeypatch, caplog):
    # 0.0.0.0/1 is also the full-tunnel-VPN pair: a /1 already via a FOREIGN next hop is
    # not overwritten (managed by ownership, not by prefix), and the collision is warned.
    rec, fake = _backup(lk, monkeypatch, "enforce", backup_egress=_becfg(gateway=BE_GW))
    fake.routes["0.0.0.0/1"] = "10.9.9.9"              # foreign next hop
    with caplog.at_level("WARNING", logger="lease-keeper"):
        rec.reconcile_backup_egress(False)
    assert fake.routes["0.0.0.0/1"] == "10.9.9.9"      # left untouched
    assert fake.routes.get("128.0.0.0/1") == BE_GW     # the absent one is still ours to add
    assert RouteCommand.CHANGE not in fake.verbs
    assert any("already routed via another next hop" in r.getMessage() for r in caplog.records)


def test_backup_egress_remove_on_unreadable_fib_skips(lk, monkeypatch, caplog):
    # unreadable table -> ownership cannot be verified, and the /1-split is also a VPN
    # full-tunnel pair, so skip rather than blind-delete an unrelated route (retry next tick).
    rec, fake = _backup(lk, monkeypatch, "enforce", backup_egress=_becfg(gateway=BE_GW),
                        netstat_fails=True)
    fake.routes["0.0.0.0/1"] = fake.routes["128.0.0.0/1"] = BE_GW
    with caplog.at_level("WARNING", logger="lease-keeper"):
        rec.reconcile_backup_egress(True)              # master, table unreadable
    assert fake.routes.get("0.0.0.0/1") == BE_GW       # NOT deleted (cannot verify ownership)
    assert any("cannot read the routing table" in r.getMessage() for r in caplog.records)


def test_backup_egress_remove_leaves_foreign_route(lk, monkeypatch, caplog):
    # on the master, a /1 present via a FOREIGN next hop (a VPN's) is left untouched; only
    # our own next hop is removed.
    rec, fake = _backup(lk, monkeypatch, "enforce", backup_egress=_becfg(gateway=BE_GW))
    fake.routes["0.0.0.0/1"] = "10.9.9.9"              # foreign
    fake.routes["128.0.0.0/1"] = BE_GW                 # ours
    with caplog.at_level("WARNING", logger="lease-keeper"):
        rec.reconcile_backup_egress(True)              # master -> remove ours only
    assert fake.routes.get("0.0.0.0/1") == "10.9.9.9"  # foreign left
    assert "128.0.0.0/1" not in fake.routes            # ours removed
    assert any("does not own" in r.getMessage() for r in caplog.records)


def test_backup_egress_install_defers_on_unreadable_fib(lk, monkeypatch, caplog):
    # unreadable table on the backup: do not blind-add (would miss a needed CHANGE);
    # defer to the next tick.
    rec, fake = _backup(lk, monkeypatch, "enforce", backup_egress=_becfg(gateway=BE_GW),
                        netstat_fails=True)
    with caplog.at_level("WARNING", logger="lease-keeper"):
        rec.reconcile_backup_egress(False)
    assert "0.0.0.0/1" not in fake.routes
    assert any("cannot read the routing table" in r.getMessage() for r in caplog.records)


def test_backup_egress_readback_failure_is_error(lk, monkeypatch, caplog):
    # a lying add (exits 0, FIB unchanged) must be caught by the read-back and reported
    # as failed, not success -- the mirror of the 0/0 lying-add test.
    rec, _ = _backup(lk, monkeypatch, "enforce", backup_egress=_becfg(gateway=BE_GW),
                     lying=(RouteCommand.ADD,))
    with caplog.at_level("INFO", logger="lease-keeper"):
        rec.reconcile_backup_egress(False)
    assert any(r.levelname == "ERROR" and "failed to route" in r.getMessage()
               for r in caplog.records)
    assert not any("backup egress routed via" in r.getMessage() for r in caplog.records)


def test_backup_egress_broken_removal_is_error(lk, monkeypatch, caplog):
    # a delete that does not take leaves a looping /1 on the master -> must surface ERROR.
    rec, fake = _backup(lk, monkeypatch, "enforce", backup_egress=_becfg(gateway=BE_GW),
                        broken=(RouteCommand.DELETE,))
    fake.routes["0.0.0.0/1"] = fake.routes["128.0.0.0/1"] = BE_GW
    with caplog.at_level("ERROR", logger="lease-keeper"):
        rec.reconcile_backup_egress(True)
    assert any("would loop its egress" in r.getMessage() for r in caplog.records)
    assert "0.0.0.0/1" in fake.routes                  # the failed delete left the route (the hazard)


def test_backup_egress_orphan_from_form_change_cleaned_on_master(lk, monkeypatch):
    # a prefixes-form daemon still removes an orphaned /1-split (left by a prior split
    # form) when it becomes master, via the union removal set.
    rec, fake = _backup(lk, monkeypatch, "enforce",
                        backup_egress=_becfg(gateway=BE_GW, form=BackupEgressForm.PREFIXES,
                                             prefixes=("192.0.2.0/24",)))
    fake.routes["0.0.0.0/1"] = fake.routes["128.0.0.0/1"] = BE_GW   # orphan from the old form
    rec.reconcile_backup_egress(True)                  # master -> clean the union
    assert "0.0.0.0/1" not in fake.routes and "128.0.0.0/1" not in fake.routes


def test_backup_egress_rejects_own_ip_gateway(lk, monkeypatch, caplog):
    # the config-sync trap: an explicit gateway equal to this node's own IP would route
    # via self -> reject (route get resolves it to lo0) and install nothing.
    rec, fake = _backup(lk, monkeypatch, "enforce",
                        backup_egress=_becfg(gateway="10.168.9.2"), local_ips=("10.168.9.2",))
    with caplog.at_level("WARNING", logger="lease-keeper"):
        rec.reconcile_backup_egress(False)
    assert "0.0.0.0/1" not in fake.routes
    assert any("own address" in r.getMessage() for r in caplog.records)


def test_backup_egress_derive_peer_on_31(lk, monkeypatch):
    # RFC 3021 /31: both addresses are usable; the peer is the other one.
    rec, fake = _backup(lk, monkeypatch, "enforce",
                        backup_egress=_becfg(interface="sync0"),
                        ifaces={"sync0": ("10.168.9.2", 31)})
    rec.reconcile_backup_egress(False)
    assert fake.routes.get("0.0.0.0/1") == "10.168.9.3"


def test_backup_egress_resolve_warns_once_not_per_tick(lk, monkeypatch, caplog):
    # an unresolvable gateway (no gateway, no interface) must warn once, not every tick.
    rec, _ = _backup(lk, monkeypatch, "enforce", backup_egress=_becfg())
    with caplog.at_level("WARNING", logger="lease-keeper"):
        for _ in range(3):
            rec.reconcile_backup_egress(False)
    warns = [r for r in caplog.records if "no gateway set and no interface" in r.getMessage()]
    assert len(warns) == 1


def test_backup_egress_observe_would_remove(lk, monkeypatch, caplog):
    rec, fake = _backup(lk, monkeypatch, "observe", backup_egress=_becfg(gateway=BE_GW))
    fake.routes["0.0.0.0/1"] = BE_GW
    with caplog.at_level("INFO", logger="lease-keeper"):
        rec.reconcile_backup_egress(True)
    assert fake.routes.get("0.0.0.0/1") == BE_GW        # observe never writes
    assert any("would remove backup egress" in r.getMessage() for r in caplog.records)


def test_backup_egress_independent_of_default_reconcile(lk, monkeypatch):
    # the backup /1-split does not touch the 0/0 decision and vice versa.
    default, backup, fake = _pair(lk, monkeypatch, "enforce", initial=GW,
                                  backup_egress=_becfg(gateway=BE_GW))
    default.reconcile(True, True, GW)                   # master: keeps 0/0 via WAN
    backup.reconcile_backup_egress(True)               # master: no /1-split
    assert fake.routes.get("default") == GW and "0.0.0.0/1" not in fake.routes


def test_backup_egress_derive_unreadable_interface_inactive(lk, monkeypatch, caplog):
    # an interface with no readable IPv4 -> no peer, no install (warned).
    rec, fake = _backup(lk, monkeypatch, "enforce",
                        backup_egress=_becfg(interface="sync0"), ifaces={})
    with caplog.at_level("WARNING", logger="lease-keeper"):
        rec.reconcile_backup_egress(False)
    assert "0.0.0.0/1" not in fake.routes
    assert any("cannot read an IPv4 address" in r.getMessage() for r in caplog.records)


def test_backup_egress_resolve_rearms_warning(lk, monkeypatch, caplog):
    # unresolved -> warn; a successful resolve re-arms; unresolved again -> a 2nd warning.
    rec, fake = _backup(lk, monkeypatch, "enforce",
                        backup_egress=_becfg(interface="sync0"), ifaces={})
    with caplog.at_level("WARNING", logger="lease-keeper"):
        rec.reconcile_backup_egress(False)                 # warn #1 (no inet)
        fake.ifaces["sync0"] = ("10.168.9.2", 30)          # now resolvable
        rec.reconcile_backup_egress(False)                 # resolves -> re-arms
        del fake.ifaces["sync0"]                           # unresolvable again
        rec.reconcile_backup_egress(False)                 # warn #2
    warns = [r for r in caplog.records if "cannot read an IPv4 address" in r.getMessage()]
    assert len(warns) == 2


def test_backup_egress_invalid_prefix_dropped(lk, monkeypatch, caplog):
    rec, fake = _backup(lk, monkeypatch, "enforce",
                        backup_egress=_becfg(gateway=BE_GW, form=BackupEgressForm.PREFIXES,
                                             prefixes=("not-an-ip", "192.0.2.0/24")))
    with caplog.at_level("WARNING", logger="lease-keeper"):
        rec.reconcile_backup_egress(False)
    assert fake.routes.get("192.0.2.0/24") == BE_GW
    assert any("ignoring invalid prefix" in r.getMessage() for r in caplog.records)


def test_backup_egress_ipv6_prefix_dropped(lk, monkeypatch, caplog):
    # ip_network() accepts IPv6, but the FIB ops are IPv4-only (netstat/route -inet); a v6
    # prefix must be dropped at validation rather than retried and failing every tick.
    rec, fake = _backup(lk, monkeypatch, "enforce",
                        backup_egress=_becfg(gateway=BE_GW, form=BackupEgressForm.PREFIXES,
                                             prefixes=("2001:db8::/32", "192.0.2.0/24")))
    with caplog.at_level("WARNING", logger="lease-keeper"):
        rec.reconcile_backup_egress(False)
    assert fake.routes.get("192.0.2.0/24") == BE_GW
    assert "2001:db8::/32" not in fake.routes
    assert any("non-IPv4 prefix" in r.getMessage() for r in caplog.records)


def test_backup_egress_boundary_leaves_unowned_split_when_disabled(lk, monkeypatch):
    # 0.0.0.0/1 + 128.0.0.0/1 is also the classic full-tunnel-VPN split; a keeper that
    # never managed backup egress must NOT delete a pre-existing /1 it does not own.
    default, backup, fake = _pair(lk, monkeypatch, "enforce")   # mode enabled, feature OFF
    fake.routes["0.0.0.0/1"] = fake.routes["128.0.0.0/1"] = BE_GW
    lk.withdraw_unless_master(default, backup, lambda: False)
    assert fake.routes.get("0.0.0.0/1") == BE_GW and fake.routes.get("128.0.0.0/1") == BE_GW


def test_backup_egress_empty_prefixes_warns_and_installs_nothing(lk, monkeypatch, caplog):
    rec, fake = _backup(lk, monkeypatch, "enforce",
                        backup_egress=_becfg(gateway=BE_GW, form=BackupEgressForm.PREFIXES,
                                             prefixes=()))
    with caplog.at_level("WARNING", logger="lease-keeper"):
        rec.reconcile_backup_egress(False)
    assert not fake.routes                               # nothing routed
    assert any("no valid prefixes" in r.getMessage() for r in caplog.records)


def test_backup_egress_own_check_transient_defers_then_recovers(lk, monkeypatch, caplog):
    # a transient own-check (route get) failure must defer (not route via a maybe-own
    # gateway) AND not cache the indeterminate result -- it recovers once route get works.
    rec, fake = _backup(lk, monkeypatch, "enforce", backup_egress=_becfg(gateway=BE_GW),
                        broken=(RouteCommand.GET,))
    with caplog.at_level("WARNING", logger="lease-keeper"):
        rec.reconcile_backup_egress(False)               # own-check fails -> defer
    assert "0.0.0.0/1" not in fake.routes
    assert any("could not verify gateway" in r.getMessage() for r in caplog.records)
    fake.broken.discard(RouteCommand.GET)                # own-check now works
    rec.reconcile_backup_egress(False)
    assert fake.routes.get("0.0.0.0/1") == BE_GW         # not permanently disabled


def test_backup_egress_removed_at_shutdown(lk, monkeypatch):
    # the shutdown boundary (withdraw_unless_master) cleans the backup-egress set so no
    # orphan /1 loops if this node later becomes master with no reconciler running.
    default, backup, fake = _pair(lk, monkeypatch, "enforce", backup_egress=_becfg(gateway=BE_GW))
    fake.routes["0.0.0.0/1"] = fake.routes["128.0.0.0/1"] = BE_GW
    lk.withdraw_unless_master(default, backup, lambda: False)   # shutdown as backup
    assert "0.0.0.0/1" not in fake.routes and "128.0.0.0/1" not in fake.routes


def test_backup_egress_shutdown_unconfirmed_removal_warns(lk, monkeypatch, caplog):
    # at shutdown there is no next tick to retry; an unconfirmable removal (unreadable
    # table) must warn loudly rather than silently leave a possible orphan /1 that loops.
    default, backup, fake = _pair(lk, monkeypatch, "enforce", backup_egress=_becfg(gateway=BE_GW),
                                  netstat_fails=True)
    fake.routes["0.0.0.0/1"] = BE_GW
    with caplog.at_level("WARNING", logger="lease-keeper"):
        lk.withdraw_unless_master(default, backup, lambda: False)
    assert any("could not clean up at shutdown" in r.getMessage() for r in caplog.records)
