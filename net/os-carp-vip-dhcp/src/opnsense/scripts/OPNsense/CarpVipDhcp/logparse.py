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

from keeperconf import CONFFILE, keeper_id, keeper_lines

LOG_GLOB = "/var/log/carpvipdhcp-*.log"
MAX_PER_FILE = 500
LINE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:,\d+)?\s+(\w+)\s+(.*)$")


def keeper_meta():
    """Map the filesystem-safe keeper id to {ip, vhid} via keeper.conf."""
    meta = {}
    for parts in keeper_lines(CONFFILE):
        request = parts[0]
        vhid = parts[4] if len(parts) > 4 else ""
        meta[keeper_id(request)] = {"ip": request, "vhid": vhid}
    return meta


def main():
    """Emit the merged, newest-first JSON array of parsed log records."""
    meta = keeper_meta()
    records = []
    for path in sorted(glob.glob(LOG_GLOB)):
        match = re.match(r"carpvipdhcp-(.+)\.log$", os.path.basename(path))
        kid = match.group(1) if match else os.path.basename(path)
        info = meta.get(kid, {})
        keeper = info.get("ip", kid)
        vhid = info.get("vhid", "")
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                lines = f.read().splitlines()[-MAX_PER_FILE:]
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
