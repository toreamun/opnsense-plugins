#!/usr/local/bin/python3
"""Parse the per-keeper daemon logs into structured JSON records (root, via configd).

Each lease_keeper.py log line looks like:
    2026-07-06 12:34:56,789 INFO some message
Output: a JSON array of {timestamp, keeper, vhid, level, message}, newest first,
which the Diagnostics API feeds to a searchable/sortable bootgrid.
"""
import glob
import json
import os
import re

LOG_GLOB = "/var/log/carpvipdhcp-*.log"
CONFFILE = "/usr/local/etc/carpvipdhcp/keeper.conf"
MAX_PER_FILE = 500
LINE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:,\d+)?\s+(\w+)\s+(.*)$")


def keeper_meta():
    """Map the filesystem-safe keeper id to {ip, vhid} via keeper.conf."""
    meta = {}
    try:
        lines = open(CONFFILE).read().splitlines()
    except OSError:
        return meta
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "|" not in line:
            continue
        parts = line.split("|")
        request = parts[0]
        vhid = parts[4] if len(parts) > 4 else ""
        meta[re.sub(r"[^A-Za-z0-9]", "_", request)] = {"ip": request, "vhid": vhid}
    return meta


def main():
    meta = keeper_meta()
    records = []
    for path in sorted(glob.glob(LOG_GLOB)):
        match = re.match(r"carpvipdhcp-(.+)\.log$", os.path.basename(path))
        kid = match.group(1) if match else os.path.basename(path)
        info = meta.get(kid, {})
        keeper = info.get("ip", kid)
        vhid = info.get("vhid", "")
        try:
            lines = open(path, errors="replace").read().splitlines()[-MAX_PER_FILE:]
        except OSError:
            continue
        for line in lines:
            parsed = LINE_RE.match(line)
            if parsed:
                records.append({
                    "timestamp": parsed.group(1),
                    "keeper": keeper,
                    "vhid": vhid,
                    "level": parsed.group(2),
                    "message": parsed.group(3),
                })
            elif line.strip():
                records.append({
                    "timestamp": "", "keeper": keeper, "vhid": vhid, "level": "", "message": line,
                })
    # Newest first: the grid shows this order by default (the user can still
    # re-sort any column).
    records.sort(key=lambda record: record["timestamp"], reverse=True)
    print(json.dumps(records))


if __name__ == "__main__":
    main()
