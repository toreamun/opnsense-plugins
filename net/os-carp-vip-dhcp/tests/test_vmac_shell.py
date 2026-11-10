"""Shell side of the source-MAC rewrite (vmac.sh, the CARP syshook, rc.d stop and
+POST_DEINSTALL), run under a real POSIX sh against FakeNgctl through ngctl_cli.py.

Each test builds a netgraph state, runs the shell function (or the package script
with its system paths pointed at the fakes), and asserts the state afterwards: what
was removed and what was left alone. Runs where a POSIX sh is on PATH; under CI
(Linux) it must run, as for test_reader_conformance.py.
"""
# pylint: disable=missing-function-docstring
import os
import shutil
import subprocess
import sys

import pytest

import ngctl_cli
from fakes import FakeNgctl, NgKnobs

_HERE = os.path.dirname(os.path.abspath(__file__))
_PLUGIN = os.path.join(_HERE, "..")
_SCRIPTS = os.path.join(_PLUGIN, "src", "opnsense", "scripts", "OPNsense", "CarpVipDhcp")
_HAS_SH = shutil.which("sh") is not None
_UNDER_CI = os.environ.get("CI") == "true"
pytestmark = pytest.mark.skipif(not _HAS_SH and not _UNDER_CI, reason="needs a POSIX sh")

WANTED = (2, 0, 0, ((6, 4, 1, 0x00005e00), (10, 2, 1, 0x0195)))
NODE = "vmac_vtnet0"
MASTER_149 = "vtnet0: flags=8843\n\tcarp: MASTER vhid 149 advbase 1 advskew 0\n"
BACKUP_149 = "vtnet0: flags=8843\n\tcarp: BACKUP vhid 149 advbase 1 advskew 100\n"


def _posix(path):
    return str(path).replace("\\", "/")


def _record(iface="vtnet0", vhid="149", on="1", request="100.64.4.102"):
    return f"request={request}|iface={iface}|chaddr=00:00:5e:00:01:{int(vhid):02x}|vhid={vhid}|vmacegress={on}"


class _Bench:
    """A temporary directory with fake ngctl / kldstat / ifconfig and a state file."""

    def __init__(self, tmp_path, fake):
        self.dir = tmp_path
        self.state = tmp_path / "ng.json"
        ngctl_cli.save(self.state, fake)
        (tmp_path / "run").mkdir()
        cli, py = _posix(os.path.join(_HERE, "ngctl_cli.py")), _posix(sys.executable)
        for prog in ("ngctl", "kldstat"):
            self._script(prog, f'exec "{py}" "{cli}" "{_posix(self.state)}" {prog} "$@"')
        self._script("ifconfig", f'cat "{_posix(tmp_path)}/ifconfig.$1" 2>/dev/null')

    def _script(self, name, body):
        path = self.dir / name
        path.write_text(f"#!/bin/sh\n{body}\n", newline="\n")
        path.chmod(0o755)

    def ifconfig(self, ifnet, text):
        (self.dir / f"ifconfig.{ifnet}").write_text(text, newline="\n")

    def conf(self, *records):
        path = self.dir / "keeper.conf"
        path.write_text("# header\n" + "".join(r + "\n" for r in records), newline="\n")
        return _posix(path)

    def run(self, body):
        d = _posix(self.dir)
        script = (f'CARPVIPDHCP_NGCTL="{d}/ngctl" CARPVIPDHCP_KLDSTAT="{d}/kldstat" '
                  f'CARPVIPDHCP_IFCONFIG="{d}/ifconfig" CARPVIPDHCP_RUN="{d}/run"\n'
                  f'. "{_posix(_SCRIPTS)}/vmac.sh"\n{body}\n')
        return subprocess.run(["sh", "-c", script], capture_output=True, text=True, check=False)

    def after(self):
        return ngctl_cli.load(self.state)


def _fake(*, built=True, unnamed=False, unloaded=False, ifaces=("vtnet0", "igb0.100"), **knobs):
    fake = FakeNgctl(ifaces=ifaces, knobs=NgKnobs(patch_unloaded=unloaded, **knobs))
    if built:
        fake.add_patch(NODE, "vtnet0", config=WANTED)
    if unnamed:
        fake.nodes["<unnamed>"] = fake.nodes["vtnet0"].__class__("patch")
        fake.link("<unnamed>", "in", "vtnet0", "upper")
    return fake


def _ngctl_calls(fake):
    return [c for c in fake.calls if c[0].endswith("ngctl")]


def _deinstall(tmp_path):
    d = _posix(tmp_path)
    with open(os.path.join(_PLUGIN, "+POST_DEINSTALL.post"), encoding="utf-8") as f:
        text = f.read()
    for real, fake in (("/sbin/kldstat", f"{d}/kldstat"), ("/usr/sbin/ngctl", f"{d}/ngctl"),
                       ("/usr/local/etc/carpvipdhcp", f"{d}/etc"), ("/var/run", f"{d}/run")):
        text = text.replace(real, fake)
    assert "/usr/local" not in text and "/var/" not in text          # nothing real is touched
    return subprocess.run(["sh", "-c", text], capture_output=True, text=True, check=False)


def _read(*parts):
    with open(os.path.join(_PLUGIN, "src", *parts), encoding="utf-8") as f:
        return f.read()


def _marker(b, node=NODE):
    return (b.dir / "run" / f"carpvipdhcp-vmac.left.{node}").exists()


def _unnamed(fake, ether="vtnet0", hook="upper", peer_hook="in", ntype="patch"):
    """An unnamed node of `ntype` on `ether`'s `hook`, attached by its `peer_hook`."""
    fake.nodes["<unnamed>"] = fake.nodes[ether].__class__(ntype)
    fake.link("<unnamed>", peer_hook, ether, hook)
    return fake


def _shutdowns(b):
    return [c for c in b.after().calls if c[1:2] == ["shutdown"]]


# ---- the CARP syshook guard: what of ours is on the event's interface ----

@pytest.mark.parametrize("state", ["BACKUP", "INIT"])
def test_carp_event_removes_the_rewrite_off_master(tmp_path, state):
    b = _Bench(tmp_path, _fake())
    res = b.run(f'carpvipdhcp_vmac_carp_event 149@vtnet0 {state}')
    assert NODE not in b.after().nodes and b.after().nodes["vtnet0"].hooks == {}
    assert f"removed {NODE}: CARP vhid 149 on vtnet0 is {state}" in res.stdout and not _marker(b)


def test_carp_event_on_master_does_nothing_at_all(tmp_path):
    b = _Bench(tmp_path, _fake())
    b.run('carpvipdhcp_vmac_carp_event 149@vtnet0 MASTER')
    assert NODE in b.after().nodes and not b.after().calls


def test_carp_event_never_reads_keeper_conf(tmp_path):
    # A keeper disabled, deleted or moved since it built is not in keeper.conf any more
    # (or there is none): its rewrite still goes when the interface leaves master.
    b = _Bench(tmp_path, _fake())
    b.run('carpvipdhcp_vmac_carp_event 149@vtnet0 BACKUP')
    assert NODE not in b.after().nodes
    assert "parse_line" not in _read("opnsense", "scripts", "OPNsense", "CarpVipDhcp", "vmac.sh")


def test_carp_event_acts_on_its_interface_only(tmp_path):
    # Another interface's event leaves it; any CARP group on its own interface leaving
    # master removes it (the keeper of a group still master rebuilds it at once).
    b = _Bench(tmp_path, _fake())
    b.run('carpvipdhcp_vmac_carp_event 149@igb0.100 BACKUP')
    assert NODE in b.after().nodes and not _shutdowns(b)
    b.run('carpvipdhcp_vmac_carp_event 150@vtnet0 BACKUP')
    assert NODE not in b.after().nodes


def test_carp_event_removes_an_unnamed_leftover_and_never_a_foreign_node(tmp_path):
    fake = _unnamed(_fake(built=False))
    fake.nodes["vmac_tee0"] = fake.nodes["vtnet0"].__class__("tee")
    b = _Bench(tmp_path, fake)
    b.run('carpvipdhcp_vmac_carp_event 149@vtnet0 BACKUP')
    assert "<unnamed>" not in b.after().nodes and b.after().nodes["vtnet0"].hooks == {}
    b.run('carpvipdhcp_vmac_carp_event 149@tee0 BACKUP')
    assert b.after().nodes["vmac_tee0"].type == "tee"


def test_carp_event_without_ng_patch_runs_no_ngctl(tmp_path):
    b = _Bench(tmp_path, _fake(unloaded=True))
    b.run('carpvipdhcp_vmac_carp_event 149@vtnet0 BACKUP')
    assert not _ngctl_calls(b.after())


def test_a_carp_event_marks_a_removal_it_cannot_confirm(tmp_path):
    # Not confirmed: a marker for the system status and the next stop; confirmed later:
    # the marker goes.
    b = _Bench(tmp_path, _fake(shutdown_lies=True))
    res = b.run('carpvipdhcp_vmac_carp_event 149@vtnet0 BACKUP')
    assert f"could not remove {NODE}" in res.stdout and _marker(b)
    fake = b.after()
    fake.knobs.shutdown_lies = False
    ngctl_cli.save(b.state, fake)
    b.run('carpvipdhcp_vmac_carp_event 149@vtnet0 BACKUP')
    assert NODE not in b.after().nodes and not _marker(b)


# ---- ownership: an unnamed patch node is ours only with our build's signature ----

@pytest.mark.parametrize("hook, peer_hook, ntype, ours", [
    ("upper", "in", "patch", True),         # an interrupted build: mkpeer upper in
    ("lower", "out", "patch", True),
    ("upper", "out", "patch", False),       # hooked another way: not ours
    ("lower", "in", "patch", False),
    ("upper", "in", "tee", False),          # another type: never
])
def test_an_unnamed_node_is_ours_only_with_our_signature(tmp_path, hook, peer_hook, ntype, ours):
    b = _Bench(tmp_path, _unnamed(_fake(built=False), hook=hook, peer_hook=peer_hook, ntype=ntype))
    b.run('carpvipdhcp_vmac_carp_event 149@vtnet0 BACKUP')
    assert ("<unnamed>" not in b.after().nodes) is ours
    if not ours:
        assert not _shutdowns(b)


# ---- the rc.d stop guard: everything of ours, on every interface ----

def test_stop_removes_everything_of_ours_and_nothing_else(tmp_path):
    fake = _fake(ifaces=("vtnet0", "igb0_100", "old0"))
    _unnamed(fake, ether="igb0_100")                                # an interrupted build
    fake.add_patch("vmac_old0", "old0", config=WANTED)              # a removed keeper's
    fake.nodes["vmac_tee0"] = fake.nodes["vtnet0"].__class__("tee")  # foreign, our prefix
    b = _Bench(tmp_path, fake)
    b.ifconfig("vtnet0", MASTER_149)                                # master: removed anyway
    res = b.run('carpvipdhcp_vmac_stop_rule')
    after = b.after()
    assert set(after.nodes) == {"vtnet0", "igb0_100", "old0", "vmac_tee0"}
    assert all(after.nodes[e].hooks == {} for e in ("vtnet0", "igb0_100", "old0"))
    assert f"removed {NODE}: keeper stop" in res.stdout and "removed vmac_old0: keeper stop" in res.stdout


def test_stop_removes_a_named_node_whose_interface_is_gone(tmp_path):
    # vmac_lone0 hooked to nothing and with no ether node lone0 (the interface was
    # removed): only the node list finds it.
    fake = _fake(built=False)
    fake.nodes["vmac_lone0"] = fake.nodes["vtnet0"].__class__("patch", config=WANTED)
    b = _Bench(tmp_path, fake)
    res = b.run('carpvipdhcp_vmac_stop_rule')
    assert "vmac_lone0" not in b.after().nodes and "removed vmac_lone0: keeper stop" in res.stdout


def test_stop_removes_the_node_of_an_interface_named_with_a_hyphen(tmp_path):
    # FreeBSD allows '-' in an interface name (ifconfig name), and netgraph in a node name.
    fake = _fake(built=False, ifaces=("vtnet0", "wan-a0"))
    fake.add_patch("vmac_wan-a0", "wan-a0", config=WANTED)
    b = _Bench(tmp_path, fake)
    res = b.run('carpvipdhcp_vmac_stop_rule')
    assert "vmac_wan-a0" not in b.after().nodes and "removed vmac_wan-a0: keeper stop" in res.stdout


def test_stop_leaves_an_unnamed_node_without_our_signature(tmp_path):
    b = _Bench(tmp_path, _unnamed(_fake(built=False), peer_hook="out"))
    b.run('carpvipdhcp_vmac_stop_rule')
    assert "<unnamed>" in b.after().nodes and not _shutdowns(b)


@pytest.mark.parametrize("show", ["list-fails", "garbled-list"])
def test_stop_reports_a_node_list_it_cannot_read_and_still_tries_the_marked(tmp_path, show):
    b = _Bench(tmp_path, _fake(show=show))
    (tmp_path / "run" / f"carpvipdhcp-vmac.left.{NODE}").write_text("")
    res = b.run('carpvipdhcp_vmac_stop_rule')
    after = b.after()
    assert "could not list the netgraph nodes at keeper stop" in res.stdout
    assert sum(c[1:2] == ["list"] for c in after.calls) == 3
    assert NODE not in after.nodes and not _marker(b)


@pytest.mark.parametrize("ether_reads, confirmed", [(None, True), (0, False)])
def test_an_unlisted_stop_tries_every_interface_ifconfig_lists(tmp_path, ether_reads, confirmed):
    # No marker and no node list: the interfaces ifconfig lists stand in. A removal there
    # that is confirmed leaves nothing; one whose hooks cannot be read leaves a marker.
    knobs = {} if ether_reads is None else {"ether_reads": ether_reads}
    b = _Bench(tmp_path, _fake(show="list-fails", **knobs))
    b.ifconfig("-l", "lo0 vtnet0 igb0.100\n")
    res = b.run('carpvipdhcp_vmac_stop_rule')
    assert "trying every interface ifconfig lists instead" in res.stdout
    assert NODE not in b.after().nodes and _marker(b) is not confirmed
    # No ether node: nothing to read. igb0.100's hooks are as readable as vtnet0's.
    assert not _marker(b, "vmac_lo0") and _marker(b, "vmac_igb0_100") is not confirmed


def test_stop_without_ng_patch_runs_no_ngctl_and_clears_the_markers(tmp_path):
    b = _Bench(tmp_path, _fake(unloaded=True))
    (tmp_path / "run" / f"carpvipdhcp-vmac.left.{NODE}").write_text("")
    b.run('carpvipdhcp_vmac_stop_rule')
    assert not _ngctl_calls(b.after()) and not _marker(b)


def test_a_lying_shutdown_at_stop_is_marked_and_tried_again(tmp_path):
    b = _Bench(tmp_path, _fake(shutdown_lies=True))
    res = b.run('carpvipdhcp_vmac_stop_rule')
    assert f"could not remove {NODE}" in res.stdout and _marker(b)
    fake = b.after()
    fake.knobs.shutdown_lies = False
    ngctl_cli.save(b.state, fake)
    res = b.run('carpvipdhcp_vmac_stop_rule')
    assert f"removed {NODE}: keeper stop" in res.stdout and not _marker(b)


def test_a_marker_whose_node_is_gone_clears_without_a_word(tmp_path):
    b = _Bench(tmp_path, _fake(built=False))
    (tmp_path / "run" / "carpvipdhcp-vmac.left.vmac_gone0").write_text("")
    res = b.run('carpvipdhcp_vmac_stop_rule')
    assert not _marker(b, "vmac_gone0") and res.stdout == ""


@pytest.mark.parametrize("rc", [0, 1])
def test_an_earlier_success_never_clears_a_later_failure(tmp_path, rc):
    # This guard's removal succeeded (0) or found nothing (1); meanwhile the keeper rebuilt
    # and another guard failed and marked. A read right before the unlink sees the node:
    # the marker stays.
    b = _Bench(tmp_path, _fake())
    (tmp_path / "run" / f"carpvipdhcp-vmac.left.{NODE}").write_text("")
    b.run(f'carpvipdhcp_vmac_remove() {{ return {rc}; }}\n'
          'carpvipdhcp_vmac_carp_event 149@vtnet0 BACKUP')
    assert _marker(b) and NODE in b.after().nodes


def test_markers_need_no_lock_one_file_per_node(tmp_path):
    # Two nodes fail in two separate runs: both markers stay, neither overwrites the other.
    fake = _fake(ifaces=("vtnet0", "old0"), shutdown_lies=True)
    fake.add_patch("vmac_old0", "old0", config=WANTED)
    b = _Bench(tmp_path, fake)
    b.run('carpvipdhcp_vmac_carp_event 149@vtnet0 BACKUP')
    b.run('carpvipdhcp_vmac_carp_event 7@old0 BACKUP')
    assert _marker(b) and _marker(b, "vmac_old0")


# ---- scan and removal semantics ----

def test_node_name_of_a_vlan_interface(tmp_path):
    b = _Bench(tmp_path, _fake())
    res = b.run('carpvipdhcp_vmac_node igb0.100; echo; carpvipdhcp_vmac_node vtnet0')
    assert res.stdout.split() == ["vmac_igb0_100", "vmac_vtnet0"]


def test_a_lying_shutdown_is_never_reported_as_removed(tmp_path):
    b = _Bench(tmp_path, _fake(shutdown_lies=True))
    res = b.run(f'carpvipdhcp_vmac_remove {NODE}; echo "rc=$?"')
    assert res.stdout.strip() == "rc=2" and NODE in b.after().nodes


@pytest.mark.parametrize("show", ["fails", "garbled"])
def test_a_wired_node_whose_name_cannot_be_read_goes_by_its_hooks(tmp_path, show):
    b = _Bench(tmp_path, _fake(show=show))
    res = b.run('carpvipdhcp_vmac_carp_event 149@vtnet0 BACKUP')
    # Found through the ether node's hooks, shut down by that ID; then the name reads
    # "no such node", so the removal is confirmed.
    assert NODE not in b.after().nodes and b.after().nodes["vtnet0"].hooks == {}
    assert f"removed {NODE}" in res.stdout and not _marker(b)


@pytest.mark.parametrize("show", ["fails", "garbled"])
def test_an_unreadable_name_is_never_reported_clean(tmp_path, show):
    fake = _fake(show=show)
    fake.nodes["vtnet0"].hooks.clear()
    fake.nodes[NODE].hooks.clear()
    b = _Bench(tmp_path, fake)
    res = b.run('carpvipdhcp_vmac_carp_event 149@vtnet0 BACKUP')
    assert NODE in b.after().nodes and "removed" not in res.stdout
    assert f"could not remove {NODE}" in res.stdout and _marker(b)


@pytest.mark.parametrize("knobs", [{"ether_reads": 0}, {"show": "garbled-ether"}])
def test_hooks_that_cannot_be_read_are_never_clean(tmp_path, knobs):
    b = _Bench(tmp_path, _unnamed(_fake(built=False, **knobs)))
    res = b.run('carpvipdhcp_vmac_carp_event 149@vtnet0 BACKUP')
    assert "<unnamed>" in b.after().nodes and f"could not remove {NODE}" in res.stdout


def test_nothing_there_is_silent(tmp_path):
    b = _Bench(tmp_path, _fake(built=False))
    res = b.run('carpvipdhcp_vmac_carp_event 149@vtnet0 BACKUP')
    assert res.stdout == "" and not _shutdowns(b) and not _marker(b)


def test_the_shell_functions_leave_no_scratch_variables(tmp_path):
    b = _Bench(tmp_path, _fake(shutdown_lies=True))
    res = b.run('carpvipdhcp_vmac_carp_event 149@vtnet0 BACKUP\n'
                'carpvipdhcp_vmac_stop_rule\nset | grep "^_vm_" || echo CLEAN')
    assert res.stdout.strip().endswith("CLEAN")


@pytest.mark.parametrize("stale, ether_reads, want", [
    # An earlier read said both sides read fine; now the hooks cannot be read.
    ("_vm_name_ok=1 _vm_hooks_ok=1 _vm_ids=''", 0, "rc=2"),
    # An earlier read saw a node ID; now nothing is there.
    ("_vm_name_ok=1 _vm_hooks_ok=1 _vm_ids=0000abcd", None, "rc=1"),
])
def test_a_removal_never_acts_on_an_earlier_scan(tmp_path, stale, ether_reads, want):
    knobs = {} if ether_reads is None else {"ether_reads": ether_reads}
    fake = _fake(built=False, **knobs)
    if ether_reads is not None:
        _unnamed(fake)
    b = _Bench(tmp_path, fake)
    res = b.run(f'{stale}\ncarpvipdhcp_vmac_remove {NODE}\necho "rc=$?"')
    assert res.stdout.strip() == want
    assert not _shutdowns(b)


# ---- where rc.d and the syshook call the guards ----

def test_rcd_runs_the_stop_rule_on_the_all_keepers_path_only():
    rcd = _read("etc", "rc.d", "carpvipdhcp")
    stop = rcd[rcd.index("carpvipdhcp_stop()"):rcd.index("carpvipdhcp_restart()")]
    stop_id = rcd[rcd.index("carpvipdhcp_stop_id()"):rcd.index("carpvipdhcp_status()")]
    start = rcd[rcd.index("carpvipdhcp_start()"):rcd.index("carpvipdhcp_stop()")]
    assert stop.index("carpvipdhcp_vmac_stop_rule") > stop.index("_signal_keepers -TERM")
    assert "vmac" not in stop_id and "vmac" not in start
    assert ". /usr/local/opnsense/scripts/OPNsense/CarpVipDhcp/vmac.sh" in rcd
    assert "carpvipdhcp_vmac_stop_rule() { :; }" in rcd     # an upgrade where vmac.sh lands later


def test_syshook_tears_down_before_it_wakes_the_keepers():
    hook = _read("etc", "rc.syshook.d", "carp", "50-carpvipdhcp")
    assert 'carpvipdhcp_vmac_carp_event "$1" "$2"' in hook
    assert hook.index("carpvipdhcp_vmac_carp_event") < hook.index("kill -USR2")


def test_the_system_status_reads_the_markers_vmac_sh_writes():
    vmac = _read("opnsense", "scripts", "OPNsense", "CarpVipDhcp", "vmac.sh")
    php = _read("opnsense", "mvc", "app", "library", "OPNsense", "System", "Status", "CarpVipDhcpStatus.php")
    rules = _read("opnsense", "mvc", "app", "models", "OPNsense", "CarpVipDhcp", "VmacEgressRules.php")
    assert '"${CARPVIPDHCP_RUN}/carpvipdhcp-vmac.left.$1"' in vmac
    assert ': "${CARPVIPDHCP_RUN:=/var/run}"' in vmac
    assert "LEFT_PREFIX = 'carpvipdhcp-vmac.left.'" in rules
    assert "RUN_DIR = '/var/run'" in php and "self::RUN_DIR . '/' . VmacEgressRules::LEFT_PREFIX" in php


# ---- +POST_DEINSTALL: the backstop after the plugin's scripts are gone ----

def test_deinstall_sweeps_every_node_of_ours_and_nothing_else(tmp_path):
    fake = _fake(ifaces=("vtnet0", "igb0_100", "old0"))
    _unnamed(fake, ether="igb0_100")                                # an interface no keeper names
    fake.add_patch("vmac_old0", "old0", hooks=(), config=WANTED)    # a removed keeper's node
    fake.nodes["vmac_tee0"] = fake.nodes["vtnet0"].__class__("tee")
    b = _Bench(tmp_path, fake)
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "keeper.conf").write_text(_record() + "\n")
    (tmp_path / "run" / f"carpvipdhcp-vmac.left.{NODE}").write_text("")
    res = _deinstall(tmp_path)
    after = b.after()
    assert set(after.nodes) == {"vtnet0", "igb0_100", "old0", "vmac_tee0"}
    assert after.nodes["vtnet0"].hooks == {} and after.nodes["igb0_100"].hooks == {}
    assert res.stderr == ""
    assert not (tmp_path / "etc").exists() and not list((tmp_path / "run").glob("carpvipdhcp-vmac.*"))


def test_deinstall_leaves_an_unnamed_node_without_our_signature(tmp_path):
    b = _Bench(tmp_path, _unnamed(_fake(built=False), peer_hook="out"))
    _deinstall(tmp_path)
    assert "<unnamed>" in b.after().nodes


def test_deinstall_without_ng_patch_runs_no_ngctl(tmp_path):
    b = _Bench(tmp_path, _fake(unloaded=True))
    (tmp_path / "etc").mkdir()
    _deinstall(tmp_path)
    assert not _ngctl_calls(b.after()) and not (tmp_path / "etc").exists()


def test_deinstall_warns_when_a_node_will_not_go_and_still_finishes(tmp_path):
    b = _Bench(tmp_path, _fake(shutdown_lies=True))
    (tmp_path / "etc").mkdir()
    res = _deinstall(tmp_path)
    assert NODE in b.after().nodes                                     # the shutdown lied
    assert "could not remove the source-MAC rewrite" in res.stderr
    assert sum(c[1:2] == ["shutdown"] for c in b.after().calls) == 3   # three rounds, then stop
    assert not (tmp_path / "etc").exists()                             # removal still finishes
    with open(os.path.join(_PLUGIN, "+POST_DEINSTALL.post"), encoding="utf-8") as f:
        assert "logger -t carpvipdhcp" in f.read()                     # and the system log


@pytest.mark.parametrize("knobs", [{"ether_reads": 0}, {"show": "garbled-ether"}, {"show": "list-fails"},
                                   {"show": "garbled-list"}],
                         ids=["hooks-fail", "hooks-garbled", "list-fails", "list-garbled"])
def test_deinstall_never_takes_an_unreadable_scan_for_clean(tmp_path, knobs):
    _Bench(tmp_path, _unnamed(_fake(built=False, **knobs)))
    (tmp_path / "etc").mkdir()
    res = _deinstall(tmp_path)
    assert "could not remove the source-MAC rewrite" in res.stderr and "unreadable:" in res.stderr
    assert "unreadable: none" not in res.stderr
    assert not (tmp_path / "etc").exists()


def test_deinstall_with_nothing_there_is_silent(tmp_path):
    b = _Bench(tmp_path, _fake(built=False))
    (tmp_path / "etc").mkdir()
    res = _deinstall(tmp_path)
    assert res.stderr == "" and not _shutdowns(b)
