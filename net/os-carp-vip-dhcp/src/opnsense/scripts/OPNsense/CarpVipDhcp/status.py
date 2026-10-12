#!/usr/local/bin/python3
"""Emit CARP-VIP DHCP keeper status as JSON (run as root via configd).

Reads the rendered keeper table (keeper.conf) and, per keeper, its supervisor
pidfile and heartbeat file. Output:

    {"carp_demotion": <int|null>, "vlan_mtag_pcp": <int|null>,
     "keepers": [ {per-keeper status}, ... ]}

The heartbeat file is written by lease_keeper.py in one of two forms:
    <epoch> bound=<ip> lease=<seconds> t1=<seconds> t2=<seconds> src=<server|derived>
            [master=<0|1>] demote_ok=<0|1> [nudge=<epoch|0> arpok=<epoch|0> [gw=<ip>]]
            [pcperr=<errno name>] [cfgerr=1]
    <epoch> MISMATCH got=<ip> want=<ip>
"""
import json
import os
import time
import xml.etree.ElementTree as ET

from keeperconf import (CONFFILE, identity_settings, keeper_id, keeper_records, parse_request_codes,
                        parse_send_options)
from leasekeeper.codec import option_problem
from leasekeeper.constants import DhcpOpt, DhcpOptName
from leasekeeper.dhcpclient import _fmt_client_id, _fmt_send_option, _identity_options
from leasekeeper.ifprobe import carp_roles
from leasekeeper.syscmd import ifconfig, run

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
# table row, in lockstep with what leasekeeper/heartbeat.py writes.
_HB_TOKENS = {
    "bound": (("bound",), lambda v: (None if v == "-" else v,)),
    "lease": (("lease",), lambda v: (_int_token(v),)),
    "t1": (("t1",), lambda v: (_int_token(v),)),
    "t2": (("t2",), lambda v: (_int_token(v),)),
    "src": (("timing_source",), lambda v: (v,)),
    "nudge": (("nudge_epoch", "nudge_age"), _epoch_pair),
    "arpok": (("arp_reply_epoch", "arp_reply_age"), _epoch_pair),
    "gw": (("gw",), lambda v: (v,)),
    "pcperr": (("vlan_pcp_error",), lambda v: (v,)),
    "cfgerr": (("config_error",), lambda v: (v == "1",)),
    "got": (("mismatch_got",), lambda v: (v,)),
    "want": (("mismatch_want",), lambda v: (v,)),
}


def parse_heartbeat_text(raw):
    """Parse heartbeat text into the per-keeper status fields (all None / False
    when the text is empty or malformed) -- the pure parser, no file IO
    (parse_heartbeat reads the file)."""
    result = {"bound": None, "lease": None, "t1": None, "t2": None, "timing_source": None,
              "mismatch": False, "mismatch_got": None, "mismatch_want": None,
              "hb_epoch": None, "hb_age": None, "nudge_epoch": None, "nudge_age": None, "gw": None,
              "arp_reply_epoch": None, "arp_reply_age": None, "vlan_pcp_error": None,
              "config_error": False}
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


def parse_heartbeat(path):
    """Parse one heartbeat file into the per-keeper status fields (all None /
    False when the file is absent or unreadable); parsing lives in
    parse_heartbeat_text."""
    try:
        with open(path, encoding="utf-8") as f:
            raw = f.read()
    except OSError:
        raw = ""
    return parse_heartbeat_text(raw)


def carp_states():
    """Map vhid -> live CARP role token (MASTER/BACKUP/INIT) from ifconfig, for
    the status JSON. Shares the CARP-line parser with the keeper (ifprobe); the
    token is passed through verbatim (any unrecognised state stays visible)."""
    return carp_roles(ifconfig())


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


def _dhcp_identity(rec):
    """(client-id bytes or None, send options) for a keeper.conf record, built as
    the daemon builds them (keeperconf resolves the identity for both). Raises
    ValueError for exactly what the daemon refuses as a configuration error: an
    unusable field, a Client identifier choice that does not go with Send
    Options, or an option the identity fields send too."""
    send_opts = parse_send_options(rec.get("sendopts", ""))
    vendor_class, client_id, problem = identity_settings(
        rec.get("cidmode", ""), rec.get("vendorclass", ""), rec.get("clientid", ""), send_opts)
    if problem is not None:
        raise ValueError(problem)
    id_opts = _identity_options(vendor_class, client_id, rec.get("hostname", ""), rec.get("chaddr", ""))
    if option_problem(id_opts, send_opts) is not None:
        raise ValueError("unusable DHCP options")
    sources = [v for n, v in id_opts if n == DhcpOptName.CLIENT_ID]
    sources += [v for code, v in send_opts if code == DhcpOpt.CLIENT_ID]
    return next(iter(sources), None), send_opts


def client_id_label(rec):
    """The DHCP client-id (option 61) a keeper started from this keeper.conf record
    sends, formatted as the daemon logs it. A running keeper keeps the value it was
    started with until it restarts; its startup log line shows that one. "none"
    when it sends none; "invalid" when the daemon refuses the record (it then
    sends no DHCP at all). Never the value itself, which may hold a credential."""
    try:
        return _fmt_client_id(_dhcp_identity(rec)[0])
    except ValueError:
        return "invalid"


def send_options_label(rec):
    """A keeper.conf record's Send Options as option codes and byte counts, e.g.
    "60 (5 bytes), 77 (44 bytes)": never the values, which may hold a credential.
    "" when there are none; "invalid" for exactly what the daemon refuses."""
    try:
        send_opts = _dhcp_identity(rec)[1]
    except ValueError:
        return "invalid"
    return ", ".join(_fmt_send_option(code, len(value)) for code, value in send_opts)


def request_options_label(setting):
    """The keeper.conf reqopts field as "119, 6"; "" when empty, "invalid" for
    what the daemon refuses too (same parser)."""
    try:
        return ", ".join(str(code) for code in parse_request_codes(setting))
    except ValueError:
        return "invalid"


def vlan_pcp_label(setting):
    """The configured 802.1p priority as the keeper uses it: None for Disabled (blank)
    and for a value outside 0-7, which the keeper drops. 0 sets none of its own
    either; the GUI shows nothing for None or 0."""
    pcp = _int_token(setting)
    return pcp if pcp in range(8) else None


def read_keepers(states, names, conffile=CONFFILE, run_dir=RUN_DIR):
    """One status entry per keeper.conf line: config, process, CARP role and
    heartbeat fields, plus the derived arp_confirmed freshness flag. conffile /
    run_dir default to the production paths and are parameters so a caller (a
    test) can point them at a fixture directory without mutating module state."""
    keepers = []
    for rec in keeper_records(conffile):
        # Fields are keyed by name (see keeperconf.keeper_records); a missing key
        # falls back to its default here.
        request = rec.get("request", "")
        iface = rec.get("iface", "")
        chaddr = rec.get("chaddr", "")
        vhid = rec.get("vhid", "")
        arp_nudge = _int_token(rec.get("arpnudge", "")) or 0
        kid = keeper_id(request)
        pid = pid_alive(f"{run_dir}/carpvipdhcp-{kid}.pid")
        entry = {
            "request": request,
            "iface": iface,
            "iface_name": names.get(iface, iface),
            "chaddr": chaddr,
            "client_id": client_id_label(rec),
            "vhid": vhid,
            "carp_state": states.get(vhid) if vhid else None,
            "demote_on_lease_loss": rec.get("demote", "0") == "1",
            "follow_ip": rec.get("follow", "0") == "1",
            "arp_nudge": arp_nudge,
            "vlan_pcp": vlan_pcp_label(rec.get("vlanpcp", "")),
            "send_options": send_options_label(rec),
            "request_options": request_options_label(rec.get("reqopts", "")),
            "running": pid is not None,
            "pid": pid,
        }
        entry.update(parse_heartbeat(f"{run_dir}/carpvipdhcp-{kid}.hb"))
        age = entry.get("arp_reply_age")
        entry["arp_confirmed"] = (
            age is not None and age <= max(ARP_CONFIRM_FLOOR, arp_nudge * ARP_CONFIRM_INTERVALS))
        keepers.append(entry)
    return keepers


def sysctl_int(name):
    """An integer sysctl, or None when unreadable."""
    res = run(["/sbin/sysctl", "-n", name], quiet=True)
    if res is None or res.returncode != 0:
        return None
    try:
        return int(res.stdout.strip())
    except ValueError:
        return None


def carp_demotion():
    """The kernel CARP demotion counter, or None when unreadable."""
    return sysctl_int("net.inet.carp.demotion")


def vlan_mtag_pcp():
    """net.link.vlan.mtag_pcp, or None when unreadable. At 0 the kernel drops the
    VLAN priority the keeper sets, with no error, so it is read on every call."""
    return sysctl_int("net.link.vlan.mtag_pcp")


def main():
    """Emit the status JSON document on stdout."""
    print(json.dumps({
        "carp_demotion": carp_demotion(),
        "vlan_mtag_pcp": vlan_mtag_pcp(),
        "keepers": read_keepers(carp_states(), iface_names()),
    }))


if __name__ == "__main__":
    main()
