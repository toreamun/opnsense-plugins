#!/usr/local/bin/python3
"""Emit CARP-VIP DHCP keeper status as JSON (run as root via configd).

Reads the rendered keeper table (keeper.conf) and, per keeper, its supervisor
pidfile and heartbeat file. Output:

    {"carp_demotion": <int|null>, "keepers": [ {per-keeper status}, ... ]}

The heartbeat file is written by lease_keeper.py in one of two forms:
    <epoch> bound=<ip> lease=<seconds> t1=<seconds> t2=<seconds> src=<server|derived>
            [nudge=<epoch|0> arpok=<epoch|0> [gw=<ip>]]
    <epoch> MISMATCH got=<ip> want=<ip>
"""
import json
import os
import re
import subprocess
import time
import xml.etree.ElementTree as ET

from keeperconf import CONFFILE, keeper_id, keeper_lines

CONFIG_XML = "/conf/config.xml"
RUN_DIR = "/var/run"

# A gateway ARP reply counts as reachability confirmation only while fresh: within
# this many nudge intervals, but never less than the floor (guards very short
# intervals). Older = stale -> the GUI shows it as unconfirmed.
ARP_CONFIRM_INTERVALS = 3
ARP_CONFIRM_FLOOR = 90


def pid_alive(path):
    """The live pid recorded in the pidfile, or None (absent/stale/foreign)."""
    try:
        with open(path, encoding="utf-8") as f:
            pid = int(f.read().strip())
        os.kill(pid, 0)
        return pid
    except (OSError, ValueError):
        return None


def _epoch_and_age(value):
    """Parse a heartbeat epoch token into (epoch, age): age = now - epoch, or None
    when the epoch is 0 ('never'). Raises ValueError on a non-integer value."""
    epoch = int(value)
    return epoch, (int(time.time()) - epoch if epoch else None)


def _int_token(value):
    try:
        return int(value)
    except ValueError:
        return None


def _epoch_pair(value):
    """(epoch, age) for the nudge=/arpok= tokens; a 0 epoch means 'never yet'
    and a garbled value parses to nothing -- age stays None either way."""
    try:
        return _epoch_and_age(value)
    except ValueError:
        return None, None


# Heartbeat token dispatch: token -> (result fields, value parser). The parser
# returns one value per field. Tokens are data, not logic -- adding one is a
# table row, in lockstep with what lease_keeper.py's _hb()/_hb_mismatch() emit.
_HB_TOKENS = {
    "bound": (("bound",), lambda v: (None if v == "-" else v,)),
    "lease": (("lease",), lambda v: (_int_token(v),)),
    "t1": (("t1",), lambda v: (_int_token(v),)),
    "t2": (("t2",), lambda v: (_int_token(v),)),
    "src": (("timing_source",), lambda v: (v,)),
    "nudge": (("nudge_epoch", "nudge_age"), _epoch_pair),
    "arpok": (("arp_reply_epoch", "arp_reply_age"), _epoch_pair),
    "gw": (("gw",), lambda v: (v,)),
    "got": (("mismatch_got",), lambda v: (v,)),
    "want": (("mismatch_want",), lambda v: (v,)),
}


def parse_heartbeat(path):
    """Parse one heartbeat file into the per-keeper status fields (all None /
    False when the file is absent or unreadable)."""
    result = {"bound": None, "lease": None, "t1": None, "t2": None, "timing_source": None,
              "mismatch": False, "mismatch_got": None, "mismatch_want": None,
              "hb_epoch": None, "hb_age": None, "nudge_epoch": None, "nudge_age": None, "gw": None,
              "arp_reply_epoch": None, "arp_reply_age": None}
    try:
        with open(path, encoding="utf-8") as f:
            raw = f.read().strip()
    except OSError:
        return result
    parts = raw.split()
    if not parts:
        return result
    try:
        result["hb_epoch"] = int(parts[0])
        result["hb_age"] = int(time.time()) - result["hb_epoch"]
    except ValueError:
        return result

    for part in parts[1:]:
        if part == "MISMATCH":
            result["mismatch"] = True
            continue
        token, sep, value = part.partition("=")
        spec = _HB_TOKENS.get(token) if sep else None
        if spec:
            fields, parse = spec
            result.update(zip(fields, parse(value)))
    return result


def carp_states():
    """Map vhid -> live CARP role (MASTER/BACKUP/INIT) from ifconfig."""
    states = {}
    try:
        out = subprocess.check_output(["/sbin/ifconfig"], errors="replace")
    except (OSError, subprocess.SubprocessError):
        return states
    if isinstance(out, bytes):
        out = out.decode(errors="replace")
    for match in re.finditer(r"carp:\s+(\w+)\s+vhid\s+(\d+)", out):
        states[match.group(2)] = match.group(1)
    return states


def iface_names():
    """Map a device (e.g. igb0_vlan100) to its friendly OPNsense interface name (e.g. WAN)."""
    names = {}
    try:
        interfaces = ET.parse(CONFIG_XML).getroot().find("interfaces")
    except (OSError, ET.ParseError):
        return names
    if interfaces is None:
        return names
    for iface in interfaces:
        device = iface.findtext("if")
        if not device:
            continue
        descr = iface.findtext("descr")
        names[device] = descr if descr else iface.tag.upper()
    return names


def read_keepers(states, names):
    """One status entry per keeper.conf line: config, process, CARP role and
    heartbeat fields, plus the derived arp_confirmed freshness flag."""
    keepers = []
    for parts in keeper_lines(CONFFILE):
        if len(parts) < 4:
            continue
        # keeper.conf field order (keep in lockstep with the template + rc.d readers):
        # 0 request|1 iface|2 chaddr|3 demote|4 vhid|5 follow|6 vendor|7 client-id|
        # 8 hostname|9 arp-nudge|10 arp-listen-promisc
        request, iface, chaddr, demote = parts[0], parts[1], parts[2], parts[3]
        vhid = parts[4] if len(parts) > 4 else ""
        follow = parts[5] if len(parts) > 5 else "0"
        arp_nudge = 0
        if len(parts) > 9:
            arp_nudge = _int_token(parts[9]) or 0
        kid = keeper_id(request)
        pid = pid_alive(f"{RUN_DIR}/carpvipdhcp-{kid}.pid")
        entry = {
            "request": request,
            "iface": iface,
            "iface_name": names.get(iface, iface),
            "chaddr": chaddr,
            "vhid": vhid,
            "carp_state": states.get(vhid) if vhid else None,
            "demote_on_lease_loss": demote == "1",
            "follow_ip": follow == "1",
            "arp_nudge": arp_nudge,
            "running": pid is not None,
            "pid": pid,
        }
        entry.update(parse_heartbeat(f"{RUN_DIR}/carpvipdhcp-{kid}.hb"))
        age = entry.get("arp_reply_age")
        entry["arp_confirmed"] = (
            age is not None and age <= max(ARP_CONFIRM_FLOOR, arp_nudge * ARP_CONFIRM_INTERVALS))
        keepers.append(entry)
    return keepers


def carp_demotion():
    """The kernel CARP demotion counter, or None when unreadable."""
    try:
        out = subprocess.check_output(["/sbin/sysctl", "-n", "net.inet.carp.demotion"])
        return int(out.strip())
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def main():
    """Emit the status JSON document on stdout."""
    print(json.dumps({
        "carp_demotion": carp_demotion(),
        "keepers": read_keepers(carp_states(), iface_names()),
    }))


if __name__ == "__main__":
    main()
