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
def _ng(lk, monkeypatch):
    fake = FakeNgctl(ifaces=("vtnet0", "igb0.100"))
    monkeypatch.setattr(lk.subprocess, "run", fake.run)
    monkeypatch.setattr(vm, "_dhclient_running", lambda _iface: False)
    return fake


def _egress(enabled=True, iface="vtnet0", chaddr=VMAC, vhid=VHID):
    return vm.VmacEgress(iface, chaddr, vhid, enabled=enabled)


def _warnings(caplog):
    return [r for r in caplog.records if r.levelno >= logging.WARNING]


def _built(ng, name=NODE, ether="vtnet0"):
    node = ng.nodes.get(name)
    return (node is not None and node.type == "patch" and node.config == WANTED
            and node.hooks == {"in": (ether, "ether", "upper"), "out": (ether, "ether", "lower")}
            and ng.nodes[ether].hooks == {"upper": (name, "patch", "in"), "lower": (name, "patch", "out")})


# ---- pure helpers, on the real text ----

def test_parsers_read_the_real_ngctl_text():
    assert vm._parse_show(SHOW_BUILT) == ("patch", {"out": ("vtnet0", "ether", "lower"),
                                                    "in": ("vtnet0", "ether", "upper")})
    assert vm._parse_show(SHOW_HALF) == ("patch", {"in": ("vtnet0", "ether", "upper")})
    assert vm._parse_show(SHOW_ETHER) == ("ether", {})
    assert vm._parse_show("ngctl: send msg: No such file or directory") is None
    # getconfig prints decimal values in its own field order and drops zero fields.
    assert vm._parse_config(GETCONFIG) == WANTED
    assert vm._parse_config("Args:\t{ count=0 }") is None
    assert vm._parse_stats(GETSTATS) == (5, 5, 0)
    assert vm._parse_stats("Args:\t{}") == (0, 0, 0)
    assert vm._parse_stats("Args:\t{ Received=9 Patched=7 Dropped=2 }") == (9, 7, 2)


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
    assert ng.verbs() == ["show"] and not probed           # one show, no node: nothing else
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
    fake = FakeNgctl(knobs=NgKnobs(fail_after=fail_after))
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
    # fail_after=1: mkpeer ran, `name` did not. Shutting our name down cannot reach the
    # unnamed node; left on upper it returns every frame (the self-demoting state).
    fake = FakeNgctl(knobs=NgKnobs(fail_after=1))
    monkeypatch.setattr(lk.subprocess, "run", fake.run)
    monkeypatch.setattr(vm, "_dhclient_running", lambda _iface: False)
    _egress().reconcile(True)
    assert "<unnamed>" not in fake.nodes and fake.nodes["vtnet0"].hooks == {}


def test_a_lying_build_is_caught_by_the_readback(lk, monkeypatch, caplog):
    fake = FakeNgctl(knobs=NgKnobs(lying=True))
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
        e.reconcile(False)
    assert sum(c[1:2] == ["shutdown"] for c in fake.calls) == 2      # retried
    assert "still present after shutdown" in caplog.text


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
