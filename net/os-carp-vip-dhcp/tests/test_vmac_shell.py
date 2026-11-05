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
                  f'. "{_posix(_SCRIPTS)}/keeperconf.sh"\n. "{_posix(_SCRIPTS)}/vmac.sh"\n{body}\n')
        return subprocess.run(["sh", "-c", script], capture_output=True, text=True, check=False)

    def after(self):
        return ngctl_cli.load(self.state)


def _fake(*, built=True, unnamed=False, unloaded=False, ifaces=("vtnet0", "igb0.100")):
    fake = FakeNgctl(ifaces=ifaces, knobs=NgKnobs(patch_unloaded=unloaded))
    if built:
        fake.add_patch(NODE, "vtnet0", config=WANTED)
    if unnamed:
        fake.nodes["<unnamed>"] = fake.nodes["vtnet0"].__class__("patch")
        fake.link("<unnamed>", "in", "vtnet0", "upper")
    return fake


def _ngctl_calls(fake):
    return [c for c in fake.calls if c[0].endswith("ngctl")]


# ---- the CARP syshook guard ----

@pytest.mark.parametrize("state", ["BACKUP", "INIT"])
def test_carp_event_removes_the_rewrite_off_master(tmp_path, state):
    b = _Bench(tmp_path, _fake())
    res = b.run(f'carpvipdhcp_vmac_carp_event "{b.conf(_record())}" 149@vtnet0 {state}')
    assert NODE not in b.after().nodes and b.after().nodes["vtnet0"].hooks == {}
    assert f"removed {NODE}: CARP vhid 149 on vtnet0 is {state}" in res.stdout


def test_carp_event_on_master_does_nothing_at_all(tmp_path):
    b = _Bench(tmp_path, _fake())
    b.run(f'carpvipdhcp_vmac_carp_event "{b.conf(_record())}" 149@vtnet0 MASTER')
    assert NODE in b.after().nodes and not b.after().calls        # not even kldstat


@pytest.mark.parametrize("event", ["150@vtnet0", "149@igb0.100"])
def test_carp_event_for_another_vhid_or_interface_leaves_it(tmp_path, event):
    b = _Bench(tmp_path, _fake())
    b.run(f'carpvipdhcp_vmac_carp_event "{b.conf(_record())}" {event} BACKUP')
    assert NODE in b.after().nodes


def test_carp_event_does_not_need_the_option_flag(tmp_path):
    # D3: matched from keeper.conf by interface and vhid only, so a graph from an
    # earlier configuration (option since switched off) goes too.
    b = _Bench(tmp_path, _fake())
    b.run(f'carpvipdhcp_vmac_carp_event "{b.conf(_record(on="0"))}" 149@vtnet0 BACKUP')
    assert NODE not in b.after().nodes


def test_carp_event_removes_an_unnamed_leftover_and_never_a_foreign_node(tmp_path):
    fake = _fake(built=False, unnamed=True)
    fake.nodes[NODE] = fake.nodes["vtnet0"].__class__("tee")       # another type under our name
    b = _Bench(tmp_path, fake)
    b.run(f'carpvipdhcp_vmac_carp_event "{b.conf(_record())}" 149@vtnet0 BACKUP')
    after = b.after()
    assert "<unnamed>" not in after.nodes and after.nodes["vtnet0"].hooks == {}
    assert after.nodes[NODE].type == "tee"
    assert not [c for c in after.calls if c[1:3] == ["shutdown", f"{NODE}:"]]


def test_carp_event_without_ng_patch_runs_no_ngctl(tmp_path):
    b = _Bench(tmp_path, _fake(built=False, unloaded=True))
    b.run(f'carpvipdhcp_vmac_carp_event "{b.conf(_record())}" 149@vtnet0 BACKUP')
    assert [c[0] for c in b.after().calls] == ["/fake/kldstat"]


def test_carp_event_without_keeper_conf_does_nothing(tmp_path):
    b = _Bench(tmp_path, _fake())
    b.run(f'carpvipdhcp_vmac_carp_event "{_posix(tmp_path)}/missing.conf" 149@vtnet0 BACKUP')
    assert NODE in b.after().nodes and not b.after().calls


# ---- the rc.d stop rule ----

def test_stop_keeps_the_rewrite_on_a_master_with_the_option_on(tmp_path):
    b = _Bench(tmp_path, _fake())
    b.ifconfig("vtnet0", MASTER_149)
    b.run(f'carpvipdhcp_vmac_stop_rule "{b.conf(_record())}"')
    after = b.after()
    assert NODE in after.nodes and not [c for c in after.calls if c[1:2] == ["shutdown"]]


@pytest.mark.parametrize("case", ["backup", "option-off", "dhcp-wan", "no-record"])
def test_stop_removes_the_rewrite_everywhere_else(tmp_path, case):
    b = _Bench(tmp_path, _fake())
    b.ifconfig("vtnet0", BACKUP_149 if case == "backup" else MASTER_149)
    records = {"backup": [_record()], "option-off": [_record(on="0")], "dhcp-wan": [_record()],
               "no-record": [_record(iface="igb0.100")]}[case]
    body = f'carpvipdhcp_vmac_stop_rule "{b.conf(*records)}"'
    if case == "dhcp-wan":       # a live pid in dhclient.<ifnet>.pid: this shell's own
        body = f'echo $$ > "{_posix(tmp_path)}/run/dhclient.vtnet0.pid"\n' + body
    res = b.run(body)
    assert NODE not in b.after().nodes and b.after().nodes["vtnet0"].hooks == {}
    assert f"removed {NODE} at stop" in res.stdout


def test_stop_keeps_a_shared_interface_whose_option_keeper_is_master(tmp_path):
    b = _Bench(tmp_path, _fake())
    b.ifconfig("vtnet0", MASTER_149)
    b.run(f'carpvipdhcp_vmac_stop_rule "{b.conf(_record(), _record(vhid="150", on="0", request="100.64.4.9"))}"')
    assert NODE in b.after().nodes


def test_stop_never_touches_a_foreign_node_and_cleans_an_unnamed_one(tmp_path):
    fake = _fake(built=False, unnamed=True)
    fake.nodes["vmac_tee0"] = fake.nodes["vtnet0"].__class__("tee")
    b = _Bench(tmp_path, fake)
    b.run(f'carpvipdhcp_vmac_stop_rule "{b.conf(_record(on="0"))}"')
    after = b.after()
    assert after.nodes["vmac_tee0"].type == "tee" and "<unnamed>" not in after.nodes


def test_stop_without_ng_patch_runs_no_ngctl(tmp_path):
    b = _Bench(tmp_path, _fake(built=False, unloaded=True))
    b.run(f'carpvipdhcp_vmac_stop_rule "{b.conf(_record())}"')
    assert [c[0] for c in b.after().calls] == ["/fake/kldstat"]


def test_node_name_of_a_vlan_interface(tmp_path):
    b = _Bench(tmp_path, _fake(built=False))
    assert b.run("carpvipdhcp_vmac_node igb0.100").stdout == "vmac_igb0_100"


# ---- +POST_DEINSTALL ----

def _deinstall(tmp_path):
    d = _posix(tmp_path)
    with open(os.path.join(_PLUGIN, "+POST_DEINSTALL.post"), encoding="utf-8") as f:
        text = f.read()
    for real, fake in (("/sbin/kldstat", f"{d}/kldstat"), ("/usr/sbin/ngctl", f"{d}/ngctl"),
                       ("/usr/local/etc/carpvipdhcp", f"{d}/etc"), ("/var/run", f"{d}/run")):
        text = text.replace(real, fake)
    assert "/usr/local" not in text and "/var/" not in text          # nothing real is touched
    return subprocess.run(["sh", "-c", text], capture_output=True, text=True, check=False)


def test_deinstall_sweeps_every_node_of_ours_and_nothing_else(tmp_path):
    fake = _fake(unnamed=False)
    fake.nodes["<unnamed>"] = fake.nodes["vtnet0"].__class__("patch")
    fake.link("<unnamed>", "in", "igb0_100", "upper")                  # a leftover on a keeper iface
    fake.add_patch("vmac_old0", "igb0_100", hooks=(), config=WANTED)  # a removed keeper's node
    fake.nodes["vmac_tee0"] = fake.nodes["vtnet0"].__class__("tee")
    b = _Bench(tmp_path, fake)
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "keeper.conf").write_text(_record() + "\n" + _record(iface="igb0.100", vhid="7") + "\n")
    _deinstall(tmp_path)
    after = b.after()
    assert set(after.nodes) == {"vtnet0", "igb0_100", "vmac_tee0"}
    assert after.nodes["vtnet0"].hooks == {} and after.nodes["igb0_100"].hooks == {}
    assert not (tmp_path / "etc").exists()                             # the script's own rm still runs


def test_deinstall_without_ng_patch_runs_no_ngctl(tmp_path):
    b = _Bench(tmp_path, _fake(built=False, unloaded=True))
    (tmp_path / "etc").mkdir()
    _deinstall(tmp_path)
    assert [c[0] for c in b.after().calls] == ["/fake/kldstat"]


# ---- where the guards are wired ----

def _read(*parts):
    with open(os.path.join(_PLUGIN, "src", *parts), encoding="utf-8") as f:
        return f.read()


def test_rcd_runs_the_stop_rule_on_the_all_keepers_path_only():
    rcd = _read("etc", "rc.d", "carpvipdhcp")
    stop = rcd[rcd.index("carpvipdhcp_stop()"):rcd.index("carpvipdhcp_restart()")]
    stop_id = rcd[rcd.index("carpvipdhcp_stop_id()"):rcd.index("carpvipdhcp_status()")]
    assert stop.index('carpvipdhcp_vmac_stop_rule "${conf}"') > stop.index("_signal_keepers -TERM")
    assert "vmac" not in stop_id                    # a per-row Stop or a follow keeps it
    assert ". /usr/local/opnsense/scripts/OPNsense/CarpVipDhcp/vmac.sh" in rcd


def test_syshook_tears_down_before_it_wakes_the_keepers():
    hook = _read("etc", "rc.syshook.d", "carp", "50-carpvipdhcp")
    assert hook.index("carpvipdhcp_vmac_carp_event") < hook.index("kill -USR2")


def test_an_unnamed_node_of_another_type_on_the_hooks_is_left_alone(tmp_path):
    # Only a patch node is ours to remove by hook path (an interrupted build's); an
    # unnamed node of any other type on upper belongs to someone else.
    fake = _fake(built=False)
    fake.nodes["<unnamed>"] = fake.nodes["vtnet0"].__class__("netflow")
    fake.link("<unnamed>", "iface0", "vtnet0", "upper")
    b = _Bench(tmp_path, fake)
    b.run(f'carpvipdhcp_vmac_carp_event "{b.conf(_record())}" 149@vtnet0 BACKUP')
    assert b.after().nodes["<unnamed>"].type == "netflow"
