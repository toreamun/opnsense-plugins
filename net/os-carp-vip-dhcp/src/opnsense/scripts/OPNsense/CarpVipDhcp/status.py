#!/usr/local/bin/python3
"""Emit CARP-VIP DHCP keeper status as JSON (run as root via configd).

Reads the rendered keeper table (keeper.conf) and, per keeper, its supervisor
pidfile and heartbeat file. Output:

    {"carp_demotion": <int|null>, "keepers": [ {per-keeper status}, ... ]}

The heartbeat file is written by lease-keeper.py in one of two forms:
    <epoch> bound=<ip> lease=<seconds> t1=<seconds> t2=<seconds> src=<server|derived>
            [nudge=<epoch|0> [gw=<ip>]]
    <epoch> MISMATCH got=<ip> want=<ip>
"""
import json
import os
import re
import subprocess
import time
import xml.etree.ElementTree as ET

CONFFILE = "/usr/local/etc/carpvipdhcp/keeper.conf"
CONFIG_XML = "/conf/config.xml"
RUN_DIR = "/var/run"


def keeper_id(request_ip):
    return re.sub(r"[^A-Za-z0-9]", "_", request_ip)


def pid_alive(path):
    try:
        pid = int(open(path).read().strip())
        os.kill(pid, 0)
        return pid
    except (OSError, ValueError):
        return None


def parse_heartbeat(path):
    result = {"bound": None, "lease": None, "t1": None, "t2": None, "timing_source": None,
              "standby": False, "mismatch": False, "mismatch_got": None, "mismatch_want": None,
              "hb_epoch": None, "hb_age": None, "nudge_epoch": None, "nudge_age": None, "gw": None}
    try:
        raw = open(path).read().strip()
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
        if part.startswith("bound="):
            value = part.split("=", 1)[1]
            result["bound"] = None if value == "-" else value
        elif part.startswith("lease="):
            try:
                result["lease"] = int(part.split("=", 1)[1])
            except ValueError:
                pass
        elif part.startswith("t1="):
            try:
                result["t1"] = int(part.split("=", 1)[1])
            except ValueError:
                pass
        elif part.startswith("t2="):
            try:
                result["t2"] = int(part.split("=", 1)[1])
            except ValueError:
                pass
        elif part.startswith("src="):
            result["timing_source"] = part.split("=", 1)[1]
        elif part.startswith("nudge="):
            # nudge=0 means "enabled but never sent yet" -> age stays None.
            try:
                result["nudge_epoch"] = int(part.split("=", 1)[1])
                if result["nudge_epoch"]:
                    result["nudge_age"] = int(time.time()) - result["nudge_epoch"]
            except ValueError:
                pass
        elif part.startswith("gw="):
            result["gw"] = part.split("=", 1)[1]
        elif part == "STANDBY":
            result["standby"] = True
        elif part == "MISMATCH":
            result["mismatch"] = True
        elif part.startswith("got="):
            result["mismatch_got"] = part.split("=", 1)[1]
        elif part.startswith("want="):
            result["mismatch_want"] = part.split("=", 1)[1]
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
    keepers = []
    try:
        lines = open(CONFFILE).read().splitlines()
    except OSError:
        return keepers
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "|" not in line:
            continue
        parts = line.split("|")
        if len(parts) < 4:
            continue
        request, iface, chaddr, demote = parts[0], parts[1], parts[2], parts[3]
        vhid = parts[4] if len(parts) > 4 else ""
        run_only = parts[5] if len(parts) > 5 else "0"
        follow = parts[6] if len(parts) > 6 else "0"
        try:
            arp_nudge = int(parts[10]) if len(parts) > 10 and parts[10] else 0
        except ValueError:
            arp_nudge = 0
        kid = keeper_id(request)
        pid = pid_alive("%s/carpvipdhcp-%s.pid" % (RUN_DIR, kid))
        entry = {
            "request": request,
            "iface": iface,
            "iface_name": names.get(iface, iface),
            "chaddr": chaddr,
            "vhid": vhid,
            "carp_state": states.get(vhid) if vhid else None,
            "demote_on_lease_loss": demote == "1",
            "run_only_on_master": run_only == "1",
            "follow_ip": follow == "1",
            "arp_nudge": arp_nudge,
            "running": pid is not None,
            "pid": pid,
        }
        entry.update(parse_heartbeat("%s/carpvipdhcp-%s.hb" % (RUN_DIR, kid)))
        keepers.append(entry)
    return keepers


def carp_demotion():
    try:
        out = subprocess.check_output(["/sbin/sysctl", "-n", "net.inet.carp.demotion"])
        return int(out.strip())
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def main():
    print(json.dumps({
        "carp_demotion": carp_demotion(),
        "keepers": read_keepers(carp_states(), iface_names()),
    }))


if __name__ == "__main__":
    main()
