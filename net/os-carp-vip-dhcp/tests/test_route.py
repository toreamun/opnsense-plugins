"""Unit tests for leasekeeper.route.DefaultRouteReconciler.

A FakeRoute stands in for /sbin/route (monkeypatched onto subprocess.run) and
tracks a single default nexthop plus the verbs issued, so tests assert both the
resulting FIB and that idempotent / observe / off paths issue no mutation.

Tests reach into private state by design; comments over per-test docstrings."""
# pylint: disable=protected-access, missing-function-docstring
import types

GW = "185.41.66.1"
GW2 = "185.41.66.9"


class FakeRoute:
    """In-memory stand-in for `/sbin/route`: one default nexthop, verb log."""

    def __init__(self, initial=None):
        self.gw = initial
        self.calls = []

    def run(self, cmd, **_kwargs):  # capture_output / errors / timeout -- ignored
        self.calls.append(list(cmd))
        verb = cmd[2]  # ["/sbin/route","-n",verb,"-inet","default"[,gw]]
        if verb == "get":
            if self.gw is None:
                return types.SimpleNamespace(returncode=1, stdout="", stderr="not in table")
            return types.SimpleNamespace(
                returncode=0, stdout=f"   gateway: {self.gw}\n   flags: <UP,GATEWAY>\n", stderr="")
        if verb == "add":
            self.gw = cmd[-1]
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")
        if verb == "delete":
            existed = self.gw is not None
            self.gw = None
            return types.SimpleNamespace(
                returncode=0 if existed else 1, stdout="", stderr="" if existed else "not in table")
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    @property
    def verbs(self):
        return [c[2] for c in self.calls]


def _rec(lk, monkeypatch, mode, initial=None, **kw):
    fake = FakeRoute(initial)
    monkeypatch.setattr(lk.subprocess, "run", fake.run)
    return lk.DefaultRouteReconciler(mode=mode, **kw), fake


# ---- off / observe never mutate ----

def test_off_never_touches_fib(lk, monkeypatch):
    rec, fake = _rec(lk, monkeypatch, "off")
    rec.reconcile(True, True, GW)
    assert fake.gw is None
    assert not fake.calls  # off short-circuits before any route call


def test_observe_reads_but_does_not_mutate(lk, monkeypatch):
    rec, fake = _rec(lk, monkeypatch, "observe")
    rec.reconcile(True, True, GW)          # would-install
    assert fake.gw is None                 # no mutation
    assert "add" not in fake.verbs and "delete" not in fake.verbs
    rec2, fake2 = _rec(lk, monkeypatch, "observe", initial=GW)
    rec2.reconcile(False, False, None)     # would-withdraw
    assert fake2.gw == GW
    assert "delete" not in fake2.verbs


# ---- enforce: install / withdraw / correct / idempotent ----

def test_enforce_master_installs(lk, monkeypatch):
    rec, fake = _rec(lk, monkeypatch, "enforce")
    rec.reconcile(True, True, GW)
    assert fake.gw == GW
    assert "add" in fake.verbs


def test_enforce_idempotent_no_change_when_correct(lk, monkeypatch):
    rec, fake = _rec(lk, monkeypatch, "enforce", initial=GW)
    rec.reconcile(True, True, GW)
    assert fake.gw == GW
    assert fake.verbs == ["get"]  # compare-then-act: no add/delete, no churn


def test_enforce_corrects_wrong_nexthop(lk, monkeypatch):
    rec, fake = _rec(lk, monkeypatch, "enforce", initial=GW2)
    rec.reconcile(True, True, GW)
    assert fake.gw == GW
    assert "delete" in fake.verbs and "add" in fake.verbs


def test_enforce_backup_withdraws(lk, monkeypatch):
    rec, fake = _rec(lk, monkeypatch, "enforce", initial=GW)
    rec.reconcile(False, False, None)
    assert fake.gw is None
    assert "delete" in fake.verbs


def test_enforce_backup_absent_is_noop(lk, monkeypatch):
    rec, fake = _rec(lk, monkeypatch, "enforce")
    rec.reconcile(False, False, None)
    assert fake.gw is None
    assert fake.verbs == ["get"]  # nothing to withdraw


def test_master_without_lease_withdraws_despite_sticky_gateway(lk, monkeypatch):
    # bound=False even though a (sticky) gateway is still known: must not keep
    # the default -- this is the MasterNoLease fail-stop.
    rec, fake = _rec(lk, monkeypatch, "enforce", initial=GW)
    rec.reconcile(True, False, GW)
    assert fake.gw is None
    assert "delete" in fake.verbs


# ---- unreadable role: fail-safe install, fail-closed withdraw ----

def test_unreadable_role_never_installs(lk, monkeypatch):
    rec, fake = _rec(lk, monkeypatch, "enforce", unreadable_role_strikes=3)
    for _ in range(10):
        rec.reconcile(None, True, GW)
    assert fake.gw is None
    assert "add" not in fake.verbs


def test_unreadable_role_withdraws_after_strike_limit(lk, monkeypatch):
    rec, fake = _rec(lk, monkeypatch, "enforce", initial=GW, unreadable_role_strikes=3)
    rec.reconcile(None, True, GW)
    rec.reconcile(None, True, GW)
    assert fake.gw == GW              # held for the first strike_limit-1 checks
    assert "delete" not in fake.verbs
    rec.reconcile(None, True, GW)     # third strike -> fail closed
    assert fake.gw is None
    assert "delete" in fake.verbs


def test_definite_role_resets_strikes(lk, monkeypatch):
    rec, fake = _rec(lk, monkeypatch, "enforce", initial=GW, unreadable_role_strikes=3)
    rec.reconcile(None, True, GW)
    rec.reconcile(None, True, GW)
    rec.reconcile(True, True, GW)     # definite read resets the counter
    rec.reconcile(None, True, GW)     # strike 1 again, not 4
    assert fake.gw == GW              # still held, not withdrawn


# ---- liveness gate (split-brain guard) ----

def test_liveness_false_blocks_install(lk, monkeypatch):
    rec, fake = _rec(lk, monkeypatch, "enforce", liveness_probe=lambda: False)
    rec.reconcile(True, True, GW)
    assert fake.gw is None
    assert "add" not in fake.verbs


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
    assert fake.verbs == ["get"]
