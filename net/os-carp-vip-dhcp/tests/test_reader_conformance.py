"""Conformance between the shell and Python keeper.conf readers.

keeperconf.sh (sourced by the rc.d service and the CARP status hook) is the shell
counterpart of keeperconf.keeper_records. A shared parser already means the two
shell consumers cannot drift from each other; this pins that the shell parser
also extracts exactly what the Python reader does, field for field, so a future
edit to one format that misses the other is caught.
"""
# pylint: disable=missing-function-docstring
import os
import shutil
import subprocess

import pytest

_SCRIPT_DIR = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..",
    "src", "opnsense", "scripts", "OPNsense", "CarpVipDhcp"))
_KEEPERCONF_SH = os.path.join(_SCRIPT_DIR, "keeperconf.sh")

# keeper.conf key -> the shell variable carpvipdhcp_parse_line sets for it. All
# match the key name except the two backup-egress fields (shorter var names).
_KEYS = [
    "request", "iface", "chaddr", "demote", "vhid", "follow", "vendorclass",
    "clientid", "hostname", "arpnudge", "arplistenpromisc", "defaultroutemode",
    "backupegress", "backupegressform", "backupegressgateway",
    "backupegressinterface", "backupegressprefixes",
]
_VAR = {k: k for k in _KEYS}
_VAR["backupegressgateway"] = "backupegressgw"
_VAR["backupegressinterface"] = "backupegressiface"

_FIXTURES = [
    # A full record.
    "request=185.41.66.101|iface=lagg1|chaddr=00:00:5e:00:01:c7|demote=0|vhid=199|"
    "follow=1|vendorclass=|clientid=|hostname=|arpnudge=240|arplistenpromisc=0|"
    "defaultroutemode=enforce|backupegress=1|backupegressform=split|"
    "backupegressgateway=10.0.0.1|backupegressinterface=em0|backupegressprefixes=",
    # Reordered, an unknown key, and several keys missing.
    "vhid=42|newkey=x|request=1.2.3.4|iface=em0|chaddr=aa",
    # Empty values, and a value that itself contains '='.
    "request=1.2.3.4|iface=em0|chaddr=aa|clientid=id=with=eq|hostname=",
    # Leading-dash values (the DHCP-option masks allow them; must survive as the value).
    "request=1.2.3.4|iface=em0|chaddr=aa|vendorclass=-foo|defaultroutemode=-bad",
]


def _sh_parse(line):
    """{key: value} as keeperconf.sh's carpvipdhcp_parse_line extracts it (one
    `printf` per key, in _KEYS order, so the split lines up)."""
    dump = "\n".join(f'printf "%s\\n" "${{{_VAR[k]}}}"' for k in _KEYS)
    script = f'. "$1"\ncarpvipdhcp_parse_line "$2"\n{dump}\n'
    out = subprocess.run(
        ["sh", "-c", script, "sh", _KEEPERCONF_SH, line],
        capture_output=True, text=True, check=True).stdout.split("\n")
    return dict(zip(_KEYS, out))


@pytest.mark.skipif(shutil.which("sh") is None, reason="no POSIX sh available")
@pytest.mark.parametrize("line", _FIXTURES)
def test_sh_reader_matches_python(tmp_path, line):
    from keeperconf import keeper_records  # pylint: disable=import-outside-toplevel
    conf = tmp_path / "keeper.conf"
    conf.write_text(line + "\n")
    records = list(keeper_records(str(conf)))
    assert len(records) == 1
    py = records[0]
    sh = _sh_parse(line)
    for key in _KEYS:
        assert sh[key] == py.get(key, ""), \
            f"key {key}: shell={sh[key]!r} python={py.get(key, '')!r}"
