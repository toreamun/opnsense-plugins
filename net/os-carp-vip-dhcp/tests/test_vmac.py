"""Tests for leasekeeper/vmac.py: the source-MAC rewrite while CARP master (option E, #131).

FakeNgctl stands in for ngctl and kldload and prints what FreeBSD 15 prints (captured on
the bench). The cases follow the design notes, section 11.7.9: inert when off, build in
one session with read-back, no-flap adoption, teardown, the unknown-role strikes, repair,
every refusal, and every failure path (ngctl missing, kldload, a build failing midway, a
lying build, a lying shutdown, Dropped rising).
"""
# pylint: disable=protected-access, missing-function-docstring
import logging
import os
import re

import pytest

from fakes import FakeNgctl, NgKnobs
from leasekeeper import vmac as vm

VHID = "149"
VMAC = "00:00:5e:00:01:95"
WANTED = (2, 0, 0, ((6, 4, 1, 0x00005e00), (10, 2, 1, 0x0195)))
NODE = "vmac_vtnet0"

# Real ngctl text from the bench (clone 903, FreeBSD 15.1, 2026-11-04).
SHOW_BUILT = """  Name: vmac_vtnet0     Type: patch           ID: 0000000d   Num hooks: 2
  Local hook      Peer name       Peer type    Peer ID         Peer hook
  ----------      ---------       ---------    -------         ---------
  out             vtnet0          ether        00000001        lower
  in              vtnet0          ether        00000001        upper
"""
SHOW_HALF = """  Name: vmac_vtnet0     Type: patch           ID: 0000000d   Num hooks: 1
  Local hook      Peer name       Peer type    Peer ID         Peer hook
  ----------      ---------       ---------    -------         ---------
  in              vtnet0          ether        00000001        upper
"""
SHOW_ETHER = "  Name: vtnet0          Type: ether           ID: 00000001   Num hooks: 0\n"
GETCONFIG = ('Rec\'d response "getconfig" (2) from "[d]:":\n'
             "Args:\t{ count=2 ops=[ { offset=6 length=4 mode=1 value=24064 } "
             "{ offset=10 length=2 mode=1 value=405 } ] }\n")
GETSTATS = 'Rec\'d response "getstats" (3) from "[d]:":\nArgs:\t{ Received=5 Patched=5 }\n'


@pytest.fixture(name="ng")
def _ng(lk, monkeypatch, tmp_path):
    fake = FakeNgctl(ifaces=("vtnet0", "igb0.100"))
    monkeypatch.setattr(lk.subprocess, "run", fake.run)
    monkeypatch.setattr(vm, "_dhclient_running", lambda _iface: False)
    monkeypatch.setattr(vm, "_other_carp_vhid", lambda _iface, _vhid: None)
    monkeypatch.setattr(vm, "_LEFT_MARKER", str(tmp_path / "carpvipdhcp-vmac.left.{}"))
    return fake


def _egress(enabled=True, iface="vtnet0", chaddr=VMAC, vhid: "str | None" = VHID):
    return vm.VmacEgress(iface, chaddr, vhid, enabled=enabled)


def _fake_clock(lk, monkeypatch):
    """A monotonic clock the test moves by hand (clock[0] seconds); _RateLimit reads it."""
    clock = [1000.0]
    monkeypatch.setattr(lk.time, "monotonic", lambda: clock[0])
    return clock


def _warnings(caplog):
    return [r for r in caplog.records if r.levelno >= logging.WARNING]


def _built(ng, name=NODE, ether="vtnet0"):
    node = ng.nodes.get(name)
    return (node is not None and node.type == "patch" and node.config == WANTED
            and node.hooks == {"in": (ether, "ether", "upper"), "out": (ether, "ether", "lower")}
            and ng.nodes[ether].hooks == {"upper": (name, "patch", "in"), "lower": (name, "patch", "out")})


# ---- pure helpers, on the real text ----

def test_parsers_read_the_real_ngctl_text():
    built = vm._parse_show(SHOW_BUILT)
    assert built is not None
    assert (built.type, built.hooks) == ("patch", {"out": ("vtnet0", "ether", "lower"),
                                                   "in": ("vtnet0", "ether", "upper")})
    assert built.ids == {"out": "00000001", "in": "00000001"}
    half = vm._parse_show(SHOW_HALF)
    assert half is not None
    assert (half.type, half.hooks) == ("patch", {"in": ("vtnet0", "ether", "upper")})
    ether = vm._parse_show(SHOW_ETHER)
    assert ether is not None and (ether.type, ether.hooks) == ("ether", {})
    assert vm._parse_show("ngctl: send msg: No such file or directory") is None
    # getconfig prints decimal values in its own field order and drops zero fields.
    assert vm._parse_config(GETCONFIG) == WANTED
    assert vm._parse_config("Args:\t{ count=0 }") is None
    assert vm._parse_dropped(GETSTATS) == 0
    assert vm._parse_dropped("Args:\t{}") == 0
    assert vm._parse_dropped("Args:\t{ Received=9 Patched=7 Dropped=2 }") == 2


@pytest.mark.parametrize("vhid, ops", [
    (1, ((6, 4, 1, 0x00005e00), (10, 2, 1, 0x0101))),
    (149, ((6, 4, 1, 0x00005e00), (10, 2, 1, 0x0195))),   # bench-verified byte order
    (255, ((6, 4, 1, 0x00005e00), (10, 2, 1, 0x01ff)))])
def test_patch_ops_put_the_lease_mac_in_the_source_field(vhid, ops):
    assert vm._patch_ops(vm.carp_vmac(vhid)) == ops


def test_patch_ops_of_any_mac_and_the_setconfig_text():
    assert vm._patch_ops("aa:bb:cc:dd:ee:ff") == ((6, 4, 1, 0xaabbccdd), (10, 2, 1, 0xeeff))
    assert vm._patch_ops("AA-BB-CC-DD-EE-FF") == ((6, 4, 1, 0xaabbccdd), (10, 2, 1, 0xeeff))
    # Exactly the command verified on the bench.
    assert vm._setconfig(VMAC) == ("{ count=2 csum_flags=0 relative_offset=0 ops=[ { mode=1 "
                                   "value=0x00005e00 length=4 offset=6 } { mode=1 value=0x0195 "
                                   "length=2 offset=10 } ] }")
    assert vm._parse_config(vm._setconfig(VMAC)) == WANTED


def test_node_names():
    assert vm.ether_node("igb0.100") == "igb0_100"
    assert vm.vmac_node("igb0.100") == "vmac_igb0_100"
    assert vm.vmac_node("vtnet0") == NODE
    assert len(vm.vmac_node("x" * 40)) == 31          # NG_NODESIZ less the NUL


def test_build_script_is_order_b_in_one_session():
    assert vm._build_script("vtnet0", VMAC).splitlines() == [
        "mkpeer vtnet0: patch upper in",
        "name vtnet0:upper vmac_vtnet0",
        "connect vtnet0: vmac_vtnet0: lower out",
        f"msg vmac_vtnet0: setconfig {vm._setconfig(VMAC)}"]


# ---- inert when off ----

def test_off_is_inert(ng):
    e = _egress(enabled=False)
    probed = []
    for role in (True, False, None):
        e.reconcile(role)
    e.teardown_unless_master(lambda: probed.append(1))
    assert ng.calls == [] and not probed
    assert e.status() is None


def test_off_at_startup_removes_only_a_leftover_without_probing(ng):
    probed = []
    _egress(enabled=False).teardown_unless_master(lambda: probed.append(1), leftover=True)
    # kldstat, then our name and the interface's hooks (an unnamed leftover): no mutation.
    assert ng.verbs() == ["show", "show"] and not ng.mutations() and not probed
    assert ng.calls[0][0] == "/sbin/kldstat"
    ng.add_patch(NODE, "vtnet0", config=WANTED)
    ng.calls.clear()
    _egress(enabled=False).teardown_unless_master(lambda: probed.append(1), leftover=True)
    assert NODE not in ng.nodes and ng.nodes["vtnet0"].hooks == {} and not probed
    assert "shutdown" in ng.verbs()


# ---- the master path ----

def test_master_builds_in_one_session_and_reads_back(ng, caplog):
    e = _egress()
    with caplog.at_level(logging.DEBUG, logger="lease-keeper"):
        e.reconcile(True)
    assert _built(ng)
    builds = [c for c in ng.calls if c[1:3] == ["-f", "-"]]
    assert len(builds) == 1 and builds[0][3] == vm._build_script("vtnet0", VMAC)
    assert [c[2] for c in ng.calls if c[0].endswith("kldload")] == ["ng_ether", "ng_patch"]
    assert e.status() == "built"
    assert "built vmac_vtnet0 (in -> vtnet0.upper, out -> vtnet0.lower), source MAC " + VMAC in caplog.text
    assert not _warnings(caplog)


def test_a_built_graph_is_only_confirmed(ng):
    e = _egress()
    e.reconcile(True)
    ng.calls.clear()
    e.reconcile(True)
    assert ng.mutations() == []
    assert set(ng.verbs()) <= {"show", "msg:getconfig", "msg:getstats"}


def test_a_restart_on_a_master_adopts_without_a_mutation(ng):
    ng.add_patch(NODE, "vtnet0", config=WANTED)
    e = _egress()                                       # a fresh keeper, graph already built
    e.reconcile(True)
    assert [c for c in ng.mutations() if not c[0].endswith("kldload")] == []
    assert _built(ng) and e.status() == "built"


def test_backup_tears_down_and_stays_native(ng, caplog):
    e = _egress()
    e.reconcile(True)
    with caplog.at_level(logging.INFO, logger="lease-keeper"):
        e.reconcile(False)
    assert NODE not in ng.nodes and ng.nodes["vtnet0"].hooks == {}
    assert e.status() == "native"
    assert "removed vmac_vtnet0 (not master)" in caplog.text
    ng.calls.clear()
    e.reconcile(False)                                  # the quiet backup steady state
    assert ng.mutations() == []


# ---- the unknown role ----

def test_unknown_role_never_builds(ng):
    e = _egress()
    for _ in range(5):
        e.reconcile(None)
    assert ng.calls == [] or ng.mutations() == []
    assert NODE not in ng.nodes and e.status() == "unknown"


def test_unknown_role_tears_down_after_three_strikes_and_warns_once(ng, caplog):
    e = _egress()
    e.reconcile(True)
    with caplog.at_level(logging.WARNING, logger="lease-keeper"):
        e.reconcile(None)
        e.reconcile(None)
        assert _built(ng)                               # two glitches: kept
        e.reconcile(None)
        assert NODE not in ng.nodes                     # third: torn down (fail closed)
        e.reconcile(None)
        e.reconcile(None)
    assert sum("CARP role unreadable" in r.getMessage() for r in _warnings(caplog)) == 1


def test_a_definite_role_ends_the_unknown_episode(ng, caplog):
    e = _egress()
    e.reconcile(True)
    e.reconcile(None)
    e.reconcile(None)
    e.reconcile(True)                                   # resets the strikes
    e.reconcile(None)
    e.reconcile(None)
    assert _built(ng)
    with caplog.at_level(logging.DEBUG, logger="lease-keeper"):
        e.reconcile(True)
    # Back to the same healthy state after a blip: no INFO re-announcing it.
    assert not [r for r in caplog.records if r.levelno == logging.INFO]


# ---- repair ----

@pytest.mark.parametrize("hooks", [("in",), ("out",)], ids=["in-only", "out-only"])
def test_a_half_built_graph_is_repaired(ng, caplog, hooks):
    ng.add_patch(NODE, "vtnet0", hooks=hooks, config=WANTED)
    e = _egress()
    with caplog.at_level(logging.WARNING, logger="lease-keeper"):
        e.reconcile(True)
    assert _built(ng)
    assert sum("not the wanted graph" in r.getMessage() for r in _warnings(caplog)) == 1


def test_a_stale_config_is_rebuilt(ng):
    stale = (2, 0, 0, ((6, 4, 1, 0x00005e00), (10, 2, 1, 0x0101)))   # an earlier vhid's MAC
    ng.add_patch(NODE, "vtnet0", config=stale)
    _egress().reconcile(True)
    assert _built(ng)


# ---- refusals ----

def test_netflow_on_the_hooks_is_refused_and_rearmed(ng, caplog):
    ng.nodes["netflow_vtnet0"] = ng.nodes["vtnet0"].__class__("netflow")
    ng.link("vtnet0", "upper", "netflow_vtnet0", "iface0")
    e = _egress()
    with caplog.at_level(logging.WARNING, logger="lease-keeper"):
        e.reconcile(True)
        e.reconcile(True)
    assert NODE not in ng.nodes and not [c for c in ng.calls if c[1:2] == ["-f"]]
    assert e.status() == "refused:hooks-taken"
    warned = [r.getMessage() for r in _warnings(caplog)]
    assert len(warned) == 1 and "netflow_vtnet0 (netflow)" in warned[0] and "NetFlow" in warned[0]
    ng.nodes["vtnet0"].hooks.clear()                    # NetFlow capture disabled
    e.reconcile(True)
    assert _built(ng) and e.status() == "built"
    ng.nodes["netflow2"] = ng.nodes["vtnet0"].__class__("netflow")
    e.reconcile(False)
    ng.link("vtnet0", "upper", "netflow2", "iface0")
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="lease-keeper"):
        e.reconcile(True)
    assert len(_warnings(caplog)) == 1                  # a new episode warns again


def test_an_interface_without_an_ether_node_is_refused(ng):
    e = _egress(iface="lagg9")
    e.reconcile(True)
    assert e.status() == "refused:no-ether-node" and not [c for c in ng.calls if c[1:2] == ["-f"]]


@pytest.mark.parametrize("chaddr, vhid, state", [
    (VMAC, None, "refused:no-vhid"),
    (VMAC, "soon", "refused:bad-vhid"),        # a hand-edited keeper.conf: no crash, refused
    (VMAC, "300", "refused:bad-vhid"),
    ("02:11:22:33:44:55", VHID, "refused:mac-override"),
    ("not-a-mac", VHID, "refused:bad-mac")])
def test_a_config_the_option_cannot_serve_is_refused_and_torn_down(ng, chaddr, vhid, state):
    ng.add_patch(NODE, "vtnet0", config=WANTED)
    e = _egress(chaddr=chaddr, vhid=vhid)
    e.reconcile(True)
    assert e.status() == state
    assert NODE not in ng.nodes and not [c for c in ng.calls if c[1:2] == ["-f"]]


def test_a_dhcp_wan_is_refused_on_both_roles_and_a_graph_removed(ng, monkeypatch, caplog):
    e = _egress()
    e.reconcile(True)
    assert _built(ng)
    monkeypatch.setattr(vm, "_dhclient_running", lambda _iface: True)
    with caplog.at_level(logging.WARNING, logger="lease-keeper"):
        e.reconcile(True)
        e.reconcile(False)
    assert NODE not in ng.nodes and e.status() == "refused:dhcp-wan"
    assert len(_warnings(caplog)) == 1


def test_dhclient_running_reads_a_live_pid(tmp_path, monkeypatch):
    monkeypatch.setattr(vm, "_DHCLIENT_PID", str(tmp_path / "dhclient.{}.pid"))
    assert vm._dhclient_running("vtnet0") is False               # no pid file
    (tmp_path / "dhclient.vtnet0.pid").write_text(f"{os.getpid()}\n")
    assert vm._dhclient_running("vtnet0") is True                # a live process
    (tmp_path / "dhclient.vtnet0.pid").write_text("garbage\n")
    assert vm._dhclient_running("vtnet0") is False
    (tmp_path / "dhclient.vtnet0.pid").write_text("2147483646\n")  # no such process
    assert vm._dhclient_running("vtnet0") is False


def test_a_foreign_node_under_our_name_is_never_touched(ng, caplog):
    ng.nodes[NODE] = ng.nodes["vtnet0"].__class__("tee")
    e = _egress()
    with caplog.at_level(logging.WARNING, logger="lease-keeper"):
        e.reconcile(True)
        e.reconcile(False)
        e.teardown_unless_master(lambda: False)
    assert ng.nodes[NODE].type == "tee"
    assert not [c for c in ng.calls if c[1:2] in (["shutdown"], ["-f"])]
    assert e.status() == "refused:foreign-node" and len(_warnings(caplog)) == 1


# ---- failure paths ----

def test_ngctl_missing_means_no_action(lk, monkeypatch, caplog):
    fake = FakeNgctl(knobs=NgKnobs(missing=True))
    monkeypatch.setattr(lk.subprocess, "run", fake.run)
    monkeypatch.setattr(vm, "_dhclient_running", lambda _iface: False)
    e = _egress()
    with caplog.at_level(logging.WARNING, logger="lease-keeper"):
        e.reconcile(True)
        e.reconcile(True)
        e.teardown_unless_master(lambda: False)
    assert e.status() == "unavailable:ngctl" and len(_warnings(caplog)) == 1
    assert not [c for c in fake.calls if c[1:2] in (["shutdown"], ["-f"])]


def test_kldload_failure_is_refused_and_retried(lk, monkeypatch, caplog):
    fake = FakeNgctl(knobs=NgKnobs(kldload_fails=True))
    monkeypatch.setattr(lk.subprocess, "run", fake.run)
    monkeypatch.setattr(vm, "_dhclient_running", lambda _iface: False)
    e = _egress()
    with caplog.at_level(logging.WARNING, logger="lease-keeper"):
        e.reconcile(True)
        e.reconcile(True)
    assert e.status() == "failed:kldload" and NODE not in fake.nodes and len(_warnings(caplog)) == 1
    assert sum(c[0].endswith("kldload") for c in fake.calls) == 4    # retried every tick
    fake.knobs.kldload_fails = False
    e.reconcile(True)
    assert e.status() == "built"
    fake.calls.clear()
    e.reconcile(True)
    assert not [c for c in fake.calls if c[0].endswith("kldload")]   # loaded once, latched


@pytest.mark.parametrize("fail_after", [1, 2, 3])
def test_a_build_failing_midway_leaves_no_node(lk, monkeypatch, caplog, fail_after):
    fake = FakeNgctl(knobs=NgKnobs(script=f"fail:{fail_after}"))
    monkeypatch.setattr(lk.subprocess, "run", fake.run)
    monkeypatch.setattr(vm, "_dhclient_running", lambda _iface: False)
    e = _egress()
    with caplog.at_level(logging.WARNING, logger="lease-keeper"):
        e.reconcile(True)
        e.reconcile(True)                               # retried: still failing
    # Never a one-hook node left on upper (the self-demoting state); nothing unnamed either.
    assert fake.nodes["vtnet0"].hooks == {} and set(fake.nodes) == {"vtnet0"}
    assert e.status() == "failed:build"
    assert sum(r.levelno == logging.ERROR for r in caplog.records) == 1   # once per episode


def test_an_interrupted_build_does_not_leave_the_unnamed_node(lk, monkeypatch):
    # script="fail:1": mkpeer ran, `name` did not. Shutting our name down cannot reach the
    # unnamed node; left on upper it returns every frame (the self-demoting state).
    fake = FakeNgctl(knobs=NgKnobs(script=f"fail:{1}"))
    monkeypatch.setattr(lk.subprocess, "run", fake.run)
    monkeypatch.setattr(vm, "_dhclient_running", lambda _iface: False)
    _egress().reconcile(True)
    assert "<unnamed>" not in fake.nodes and fake.nodes["vtnet0"].hooks == {}


def test_a_lying_build_is_caught_by_the_readback(lk, monkeypatch, caplog):
    fake = FakeNgctl(knobs=NgKnobs(script="lying"))
    monkeypatch.setattr(lk.subprocess, "run", fake.run)
    monkeypatch.setattr(vm, "_dhclient_running", lambda _iface: False)
    e = _egress()
    with caplog.at_level(logging.ERROR, logger="lease-keeper"):
        e.reconcile(True)
    assert e.status() == "failed:readback"
    assert "did not read back" in caplog.text


def test_a_lying_shutdown_is_reported_and_retried(lk, monkeypatch, caplog):
    fake = FakeNgctl(knobs=NgKnobs(shutdown_lies=True))
    monkeypatch.setattr(lk.subprocess, "run", fake.run)
    monkeypatch.setattr(vm, "_dhclient_running", lambda _iface: False)
    fake.add_patch(NODE, "vtnet0", config=WANTED)
    e = _egress()
    with caplog.at_level(logging.WARNING, logger="lease-keeper"):
        e.reconcile(False)
        first = sum(c[1:2] == ["shutdown"] for c in fake.calls)
        e.reconcile(False)
    assert sum(c[1:2] == ["shutdown"] for c in fake.calls) > first >= 1   # retried
    assert "still present after shutdown" in caplog.text
    # The node is still there: the token must not say native (the backup may be rewriting).
    assert NODE in fake.nodes and e.status() == "failed:teardown"


def test_dropped_rising_warns_once_and_keeps_the_graph(ng, caplog):
    e = _egress()
    e.reconcile(True)
    ng.nodes[NODE].stats = (100, 90, 3)
    with caplog.at_level(logging.WARNING, logger="lease-keeper"):
        e.reconcile(True)
        ng.nodes[NODE].stats = (200, 180, 7)
        e.reconcile(True)
    assert _built(ng) and sum("dropped" in r.getMessage() for r in _warnings(caplog)) == 1
    assert len([c for c in ng.calls if c[1:2] == ["-f"]]) == 1       # not rebuilt


# ---- the process boundaries ----

@pytest.mark.parametrize("role, kept", [(True, True), (False, False), (None, False)])
def test_teardown_unless_master(ng, role, kept):
    _egress().reconcile(True)
    _egress().teardown_unless_master(lambda: role)
    assert _built(ng) is kept


def test_status_token_has_no_spaces():
    assert all(" " not in s.value for s in vm.VmacState)


@pytest.mark.parametrize("role", [True, False], ids=["master", "backup"])
def test_an_unnamed_leftover_on_the_hooks_is_scrubbed(ng, caplog, role):
    # A keeper killed between mkpeer and name (an earlier process) left an unnamed patch
    # node on upper. Not a reason to refuse; on a backup it must go too (it returns
    # every frame the stack sends).
    ng.nodes["<unnamed>"] = ng.nodes["vtnet0"].__class__("patch")
    ng.link("<unnamed>", "in", "vtnet0", "upper")
    e = _egress()
    with caplog.at_level(logging.WARNING, logger="lease-keeper"):
        e.reconcile(role)
    assert "<unnamed>" not in ng.nodes
    assert _built(ng) is role and e.status() == ("built" if role else "native")
    assert sum("unnamed patch node" in r.getMessage() for r in _warnings(caplog)) == 1


# ---- review findings (2026-11-05) ----

def test_a_bad_vhid_never_raises_even_when_off(ng):
    for vhid in ("soon", "-1", "0x95", "999"):
        e = _egress(enabled=False, vhid=vhid)
        e.teardown_unless_master(lambda: True, leftover=True)   # main()'s startup call
        assert e.status() is None
    assert not ng.mutations()


def test_a_shared_interface_is_refused_and_its_node_left_alone_when_off(ng):
    ng.add_patch(NODE, "vtnet0", config=WANTED)             # another keeper's live rewrite
    off = vm.VmacEgress("vtnet0", VMAC, VHID, enabled=False, shared_iface=True)
    off.teardown_unless_master(lambda: True, leftover=True)
    assert _built(ng) and not ng.calls                       # not even a kldstat
    on = vm.VmacEgress("vtnet0", VMAC, VHID, enabled=True, shared_iface=True)
    on.reconcile(True)
    assert on.status() == "refused:shared-iface"


def test_the_off_sweep_runs_no_ngctl_without_ng_patch(lk, monkeypatch):
    fake = FakeNgctl(knobs=NgKnobs(patch_unloaded=True))
    monkeypatch.setattr(lk.subprocess, "run", fake.run)
    _egress(enabled=False).teardown_unless_master(lambda: True, leftover=True)
    assert [c[0] for c in fake.calls] == ["/sbin/kldstat"]   # ngctl could load ng_socket


def test_a_transient_ngctl_error_never_rebuilds_a_working_graph(ng, caplog):
    e = _egress()
    e.reconcile(True)
    ng.knobs.show = "fails"
    with caplog.at_level(logging.WARNING, logger="lease-keeper"):
        e.reconcile(True)
        e.reconcile(True)
    assert len(ng.builds()) == 1 and not [c for c in ng.calls if c[1:2] == ["shutdown"]]
    assert e.status() == "unavailable:ngctl" and len(_warnings(caplog)) == 1
    ng.knobs.show = ""
    e.reconcile(True)
    assert _built(ng) and e.status() == "built" and len(ng.builds()) == 1


def test_a_lying_shutdown_warns_once_per_episode(lk, monkeypatch, caplog):
    fake = FakeNgctl(knobs=NgKnobs(shutdown_lies=True))
    monkeypatch.setattr(lk.subprocess, "run", fake.run)
    monkeypatch.setattr(vm, "_dhclient_running", lambda _iface: False)
    fake.add_patch(NODE, "vtnet0", config=WANTED)
    e = _egress()
    with caplog.at_level(logging.WARNING, logger="lease-keeper"):
        for _ in range(4):
            e.reconcile(False)
    assert sum("still present after shutdown" in r.getMessage() for r in _warnings(caplog)) == 1


def test_a_failed_build_logs_one_error_and_nothing_else(lk, monkeypatch, caplog):
    fake = FakeNgctl(knobs=NgKnobs(script=f"fail:{2}"))
    monkeypatch.setattr(lk.subprocess, "run", fake.run)
    monkeypatch.setattr(vm, "_dhclient_running", lambda _iface: False)
    e = _egress()
    with caplog.at_level(logging.WARNING, logger="lease-keeper"):
        e.reconcile(True)
        e.reconcile(None)                                    # an UNKNOWN blip in between
        e.reconcile(True)
    assert [r.levelno for r in _warnings(caplog)] == [logging.ERROR]
    assert "send msg: File exists" in caplog.text            # ngctl's own text is in the line


def test_dhclient_running_survives_a_huge_pid(tmp_path, monkeypatch):
    monkeypatch.setattr(vm, "_DHCLIENT_PID", str(tmp_path / "dhclient.{}.pid"))
    (tmp_path / "dhclient.vtnet0.pid").write_text("99999999999999999999999\n")
    assert vm._dhclient_running("vtnet0") is False


# ---- PR #135 review (Copilot) ----

def _unnamed_on_upper(ng):
    ng.nodes["<unnamed>"] = ng.nodes["vtnet0"].__class__("patch")
    ng.link("<unnamed>", "in", "vtnet0", "upper")


@pytest.mark.parametrize("enabled, role", [(False, None), (True, False), (True, None)],
                         ids=["off-sweep", "on-not-master", "on-unknown"])
def test_the_process_boundary_removes_an_unnamed_leftover(ng, enabled, role):
    # A keeper killed between mkpeer and name: `show vmac_<e>:` reads absent, but the
    # unnamed node on upper returns every frame. The boundary must still remove it.
    _unnamed_on_upper(ng)
    _egress(enabled=enabled).teardown_unless_master(lambda: role, leftover=True)
    assert "<unnamed>" not in ng.nodes and ng.nodes["vtnet0"].hooks == {}


def test_the_unknown_role_strikes_remove_an_unnamed_leftover(ng):
    _unnamed_on_upper(ng)
    e = _egress()
    for _ in range(3):
        e.reconcile(None)
    assert "<unnamed>" not in ng.nodes and ng.nodes["vtnet0"].hooks == {}


def test_a_failed_teardown_on_a_master_refusal_is_not_native(lk, monkeypatch):
    fake = FakeNgctl(knobs=NgKnobs(shutdown_lies=True))
    monkeypatch.setattr(lk.subprocess, "run", fake.run)
    monkeypatch.setattr(vm, "_dhclient_running", lambda _iface: True)   # refused on a master
    fake.add_patch(NODE, "vtnet0", config=WANTED)
    e = _egress()
    e.reconcile(True)
    assert e.status() == "failed:teardown"


@pytest.mark.parametrize("hangs_after", [1, 2, 3])
def test_a_build_that_does_not_finish_is_scrubbed_at_once(lk, monkeypatch, caplog, hangs_after):
    clock = _fake_clock(lk, monkeypatch)
    fake = FakeNgctl(knobs=NgKnobs(script=f"hang:{hangs_after}"))
    monkeypatch.setattr(lk.subprocess, "run", fake.run)
    monkeypatch.setattr(vm, "_dhclient_running", lambda _iface: False)
    e = _egress()
    with caplog.at_level(logging.ERROR, logger="lease-keeper"):
        e.reconcile(True)
    assert set(fake.nodes) == {"vtnet0"} and fake.nodes["vtnet0"].hooks == {}
    assert e.status() == "failed:build" and "ngctl did not finish" in caplog.text
    e.reconcile(True)                                       # not every tick...
    assert not _built(fake)
    clock[0] += vm.BUILD_RETRY_INTERVAL + 1
    e.reconcile(True)                                       # ...but after the retry interval
    assert _built(fake) and e.status() == "built"


# ---- PR #135 review (Copilot, second round) ----

@pytest.mark.parametrize("chaddr, kldload_fails, state", [
    ("02:11:22:33:44:55", False, "refused:mac-override"),   # a static refusal
    (VMAC, True, "failed:kldload")])                          # modules do not load
def test_a_refusal_does_not_skip_an_unnamed_leftover(lk, monkeypatch, chaddr, kldload_fails, state):
    fake = FakeNgctl(knobs=NgKnobs(kldload_fails=kldload_fails))
    monkeypatch.setattr(lk.subprocess, "run", fake.run)
    monkeypatch.setattr(vm, "_dhclient_running", lambda _iface: False)
    _unnamed_on_upper(fake)
    e = _egress(chaddr=chaddr)
    e.reconcile(True)
    assert "<unnamed>" not in fake.nodes and fake.nodes["vtnet0"].hooks == {}
    assert e.status() == state


@pytest.mark.parametrize("path", ["reconcile", "startup-sweep", "strikes"])
def test_a_foreign_node_under_our_name_survives_a_leftover_cleanup(ng, path):
    _unnamed_on_upper(ng)
    ng.nodes[NODE] = ng.nodes["vtnet0"].__class__("tee")       # another type under our name
    e = _egress(enabled=path != "startup-sweep")
    if path == "reconcile":
        e.reconcile(False)
    elif path == "startup-sweep":
        e.teardown_unless_master(lambda: True, leftover=True)
    else:
        for _ in range(3):
            e.reconcile(None)
    assert "<unnamed>" not in ng.nodes and ng.nodes["vtnet0"].hooks == {}
    assert ng.nodes[NODE].type == "tee"                        # never shut down by name
    assert not [c for c in ng.calls if c[1:3] == ["shutdown", f"{NODE}:"]]


def test_unreadable_hooks_are_not_a_confirmed_removal(lk, monkeypatch):
    # The leftover is seen on the first read; every later read of the hooks fails. The
    # teardown cannot confirm, so the token must not say native.
    fake = FakeNgctl(knobs=NgKnobs(ether_reads=1))
    monkeypatch.setattr(lk.subprocess, "run", fake.run)
    monkeypatch.setattr(vm, "_dhclient_running", lambda _iface: False)
    _unnamed_on_upper(fake)
    e = _egress()
    e.reconcile(False)
    assert "<unnamed>" in fake.nodes                           # not reachable without a read
    assert e.status() == "failed:teardown"


def test_a_teardown_needs_readable_hooks_to_succeed(lk, monkeypatch):
    fake = FakeNgctl(knobs=NgKnobs(ether_reads=0))
    monkeypatch.setattr(lk.subprocess, "run", fake.run)
    fake.add_patch(NODE, "vtnet0", config=WANTED)
    assert _egress()._teardown("test") is False                # node gone, hooks unreadable


# ---- own adversarial review on #135 ----

def test_a_failing_build_is_retried_once_per_interval_not_every_tick(lk, monkeypatch):
    # Each attempt puts a node on upper for a moment (frames return to the stack).
    clock = _fake_clock(lk, monkeypatch)
    fake = FakeNgctl(knobs=NgKnobs(script="fail:2"))
    monkeypatch.setattr(lk.subprocess, "run", fake.run)
    monkeypatch.setattr(vm, "_dhclient_running", lambda _iface: False)
    e = _egress()
    for _ in range(5):
        e.reconcile(True)
    assert len(fake.builds()) == 1 and e.status() == "failed:build"
    clock[0] += vm.BUILD_RETRY_INTERVAL + 1
    e.reconcile(True)
    e.reconcile(True)
    assert len(fake.builds()) == 2
    assert set(fake.nodes) == {"vtnet0"} and fake.nodes["vtnet0"].hooks == {}


def test_a_teardown_with_nothing_there_logs_nothing(ng, caplog):
    with caplog.at_level(logging.INFO, logger="lease-keeper"):
        assert _egress()._teardown("nothing there") is True
    assert "removed" not in caplog.text and not ng.mutations()


def test_unparseable_output_for_our_name_is_unreadable_not_absent(ng):
    # exit 0 with no header for our name: not "no node". A backup still reaches the wired
    # node by its hooks, and the token says unavailable, never native.
    e = _egress()
    e.reconcile(True)
    ng.knobs.show = "garbled"
    e.reconcile(False)
    ng.knobs.show = ""
    assert NODE not in ng.nodes and ng.nodes["vtnet0"].hooks == {}
    assert e.status() == "unavailable:ngctl"


def test_unparseable_output_for_the_hooks_is_unreadable_not_clean(ng):
    # An unnamed leftover on upper, and the hooks read exit 0 with no header: neither
    # "no ether node" nor clean hooks, so the backup must not report native.
    _unnamed_on_upper(ng)
    ng.knobs.show = "garbled-ether"
    e = _egress()
    e.reconcile(False)
    assert e.status() == "unavailable:ngctl"


@pytest.mark.parametrize("path", ["backup-tick", "keeper-stop", "strikes"])
def test_a_wired_node_whose_name_cannot_be_read_is_reached_by_its_hooks(ng, path):
    _egress().reconcile(True)
    ng.knobs.show = "fails"                                # show of our name fails, hooks read fine
    e = _egress()
    if path == "backup-tick":
        e.reconcile(False)
    elif path == "keeper-stop":
        e.teardown_unless_master(lambda: False)
    else:
        for _ in range(3):
            e.reconcile(None)
    ng.knobs.show = ""
    assert NODE not in ng.nodes and ng.nodes["vtnet0"].hooks == {}


def test_a_half_built_graph_that_cannot_be_removed_is_failed_teardown(lk, monkeypatch):
    fake = FakeNgctl(knobs=NgKnobs(shutdown_lies=True))
    monkeypatch.setattr(lk.subprocess, "run", fake.run)
    monkeypatch.setattr(vm, "_dhclient_running", lambda _iface: False)
    fake.add_patch(NODE, "vtnet0", hooks=("in",), config=WANTED)
    e = _egress()
    e.reconcile(True)
    assert e.status() == "failed:teardown" and not fake.builds()


# ---- PR #135 review (Copilot, third round) ----

def test_an_unknown_blip_does_not_open_the_build_cooldown(lk, monkeypatch):
    clock = _fake_clock(lk, monkeypatch)
    fake = FakeNgctl(knobs=NgKnobs(script="fail:2"))
    monkeypatch.setattr(lk.subprocess, "run", fake.run)
    monkeypatch.setattr(vm, "_dhclient_running", lambda _iface: False)
    e = _egress()
    e.reconcile(True)                                       # build fails
    e.reconcile(None)                                       # a probe glitch: state unknown
    e.reconcile(True)
    assert len(fake.builds()) == 1                          # still cooling down
    clock[0] += vm.BUILD_RETRY_INTERVAL + 1
    e.reconcile(True)
    assert len(fake.builds()) == 2


def test_a_refused_config_never_keeps_a_graph_at_a_boundary(ng):
    # No vhid: carp_master() reads True for "nothing to gate on", but a keeper the option
    # cannot serve must not keep a predecessor's graph as if it were a confirmed master.
    ng.add_patch(NODE, "vtnet0", config=WANTED)
    _egress(vhid=None).teardown_unless_master(lambda: True)
    assert NODE not in ng.nodes and ng.nodes["vtnet0"].hooks == {}


@pytest.mark.parametrize("between", [None, False], ids=["unknown", "backup"])
def test_the_token_keeps_the_pending_failure_during_the_cooldown(lk, monkeypatch, between):
    clock = _fake_clock(lk, monkeypatch)
    fake = FakeNgctl(knobs=NgKnobs(script="fail:2"))
    monkeypatch.setattr(lk.subprocess, "run", fake.run)
    monkeypatch.setattr(vm, "_dhclient_running", lambda _iface: False)
    e = _egress()
    e.reconcile(True)
    e.reconcile(between)
    e.reconcile(True)
    assert e.status() == "failed:build" and len(fake.builds()) == 1
    clock[0] += vm.BUILD_RETRY_INTERVAL + 1
    fake.knobs.script = ""
    e.reconcile(True)
    assert _built(fake) and e.status() == "built"


def test_a_dhcp_wan_does_not_keep_a_graph_at_a_boundary(ng, monkeypatch):
    # The keeper may not reach its main loop soon (the capture keeps failing to start),
    # so the D6 guard applies at the process boundary too.
    ng.add_patch(NODE, "vtnet0", config=WANTED)
    monkeypatch.setattr(vm, "_dhclient_running", lambda _iface: True)
    _egress().teardown_unless_master(lambda: True)
    assert NODE not in ng.nodes and ng.nodes["vtnet0"].hooks == {}


def test_a_hook_patch_node_is_shut_down_by_its_id_never_by_hook_path(ng):
    # A hook path (vtnet0:upper) addresses whatever holds the hook at that moment; the
    # ID addresses exactly the node the read saw.
    ng.nodes["<unnamed>"] = ng.nodes["vtnet0"].__class__("patch")
    ng.link("<unnamed>", "in", "vtnet0", "upper")
    _egress().reconcile(False)
    shutdowns = [c[2] for c in ng.calls if c[1:2] == ["shutdown"]]
    assert shutdowns and all(t.startswith("[") and t.endswith("]:") for t in shutdowns)
    assert "<unnamed>" not in ng.nodes


def test_every_state_has_its_status_page_text_and_banner_category():
    # Every reason the keeper can report (VmacState) has a text in the Status page's
    # vmacReasons, and the system status banner's pattern covers every category; a
    # healthy state (built, native, unknown) has neither. A new state added only here
    # would otherwise show as its raw token, or never raise the banner on a master.
    app = os.path.join(os.path.dirname(__file__), "..", "src", "opnsense", "mvc", "app")
    with open(os.path.join(app, "views", "OPNsense", "CarpVipDhcp", "status.volt"), encoding="utf-8") as f:
        volt = f.read()
    with open(os.path.join(app, "library", "OPNsense", "System", "Status", "CarpVipDhcpStatus.php"),
              encoding="utf-8") as f:
        php = f.read()
    table = volt.split("const vmacReasons = {", 1)[1].split("};", 1)[0]
    reasons = set(re.findall(r"'([a-z-]+)':", table))
    banner = re.search(r"vmac=\(([a-z|]+)\):", php)
    assert banner is not None
    categories = set(banner.group(1).split("|"))
    healthy = {vm.VmacState.BUILT, vm.VmacState.NATIVE, vm.VmacState.UNKNOWN}
    for state in vm.VmacState:
        if state in healthy:
            assert ":" not in state
            continue
        category, _, reason = state.partition(":")
        assert reason in reasons, f"{state}: no Status page text"
        assert category in categories, f"{state}: the banner never raises it"
    assert reasons == {s.partition(":")[2] for s in vm.VmacState if s not in healthy}


# ---- ownership by signature, removal by ID, another CARP group, markers ----

@pytest.mark.parametrize("hook, peer_hook, ours", [
    ("upper", "in", True), ("lower", "out", True), ("upper", "out", False), ("lower", "in", False)])
def test_an_unnamed_patch_node_is_ours_only_with_our_signature(ng, hook, peer_hook, ours):
    # Ours: removed even on a backup. Not ours: never shut down; on a master it holds
    # the hooks like any other node, so the option is refused rather than built over it.
    ng.nodes["<unnamed>"] = vm_node("patch")
    ng.link("<unnamed>", peer_hook, "vtnet0", hook)
    e = _egress()
    e.reconcile(False)
    assert ("<unnamed>" not in ng.nodes) is ours
    if not ours:
        assert not [c for c in ng.calls if c[1:2] == ["shutdown"]]
        e.reconcile(True)
        assert "<unnamed>" in ng.nodes and e.status() == vm.VmacState.HOOKS_TAKEN


def vm_node(ntype):
    return FakeNgctl(ifaces=("x",)).nodes["x"].__class__(ntype)


def test_our_named_node_is_shut_down_by_its_id(ng):
    ng.add_patch(NODE, "vtnet0", config=WANTED)
    _egress().reconcile(False)
    shutdowns = [c[2] for c in ng.calls if c[1:2] == ["shutdown"]]
    assert NODE not in ng.nodes
    assert shutdowns and all(t.startswith("[") and t.endswith("]:") for t in shutdowns)


def test_the_header_id_is_parsed():
    built, bare = vm._parse_show(SHOW_BUILT), vm._parse_show("  Name: x  Type: patch\n")
    assert built is not None and built.id == "0000000d"
    assert bare is not None and bare.id == ""


def test_another_carp_group_on_the_interface_is_refused_on_the_master(ng, monkeypatch):
    monkeypatch.setattr(vm, "_other_carp_vhid", lambda _iface, _vhid: "150")
    ng.add_patch(NODE, "vtnet0", config=WANTED)
    e = _egress()
    e.reconcile(True)
    assert NODE not in ng.nodes and e.status() == vm.VmacState.OTHER_CARP
    e.teardown_unless_master(lambda: True)          # nor kept across a keeper stop
    assert NODE not in ng.nodes


def test_other_carp_vhid_reads_ifconfig(lk, monkeypatch):
    text = ("vtnet0: flags=8843\n\tcarp: MASTER vhid 149 advbase 1 advskew 0\n"
            "\tcarp: BACKUP vhid 150 advbase 1 advskew 100\n")
    replies = {"ok": (0, text), "own": (0, "\tcarp: MASTER vhid 149 advbase 1\n"), "fail": (1, "")}
    for case, (rc, out) in replies.items():
        monkeypatch.setattr(lk.subprocess, "run",
                            lambda cmd, rc=rc, out=out, **_k: lk.subprocess.CompletedProcess(cmd, rc, out, ""))
        assert vm._other_carp_vhid("vtnet0", "149") == {"ok": "150", "own": None, "fail": None}[case]


def test_a_healthy_state_clears_the_shell_sides_marker(ng, tmp_path):
    marker = tmp_path / f"carpvipdhcp-vmac.left.{NODE}"
    marker.write_text("")
    e = _egress()
    e.reconcile(True)                    # built: the rewrite is there on purpose
    assert _built(ng) and not marker.exists()
    marker.write_text("")
    e.reconcile(False)                   # torn down and confirmed: native
    assert NODE not in ng.nodes and not marker.exists()


def test_a_failed_teardown_leaves_the_marker(lk, monkeypatch, tmp_path):
    fake = FakeNgctl(knobs=NgKnobs(shutdown_lies=True))
    monkeypatch.setattr(lk.subprocess, "run", fake.run)
    monkeypatch.setattr(vm, "_dhclient_running", lambda _iface: False)
    monkeypatch.setattr(vm, "_LEFT_MARKER", str(tmp_path / "carpvipdhcp-vmac.left.{}"))
    fake.add_patch(NODE, "vtnet0", config=WANTED)
    marker = tmp_path / f"carpvipdhcp-vmac.left.{NODE}"
    marker.write_text("")
    e = _egress()
    e.reconcile(False)
    assert e.status() == vm.VmacState.TEARDOWN and marker.exists()
