"""Shared keeper.conf access for the CarpVipDhcp configd scripts.

Lives in the same directory as its consumers (status.py, logparse.py), which
Python puts on sys.path when configd runs them, so no packaging is needed.
"""
import re

CONFFILE = "/usr/local/etc/carpvipdhcp/keeper.conf"


def keeper_id(request_ip):
    """Filesystem-safe keeper id (mirrors the daemon's _fs_safe charset; the
    two must stay in lockstep or the per-keeper file names diverge)."""
    return re.sub(r"[^A-Za-z0-9]", "_", request_ip)


def keeper_records(path):
    """Yield each active (non-comment) keeper.conf line as a {key: value} dict.

    Each line is a pipe-separated list of KEY=VALUE fields in no fixed order (see
    the template); we dispatch by key, so a missing key is simply absent from the
    dict and the caller supplies its default. Lines without a request= field are
    skipped, mirroring the rc.d reader. Yields nothing when the file is absent or
    unreadable."""
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        record = {}
        for field in line.split("|"):
            key, sep, value = field.partition("=")
            if sep:
                record[key] = value
        if record.get("request"):
            yield record
