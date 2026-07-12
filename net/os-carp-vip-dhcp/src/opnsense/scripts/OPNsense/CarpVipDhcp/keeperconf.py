"""Shared keeper.conf access for the CarpVipDhcp configd scripts.

Lives in the same directory as its consumers (status.py, logparse.py), which
Python puts on sys.path when configd runs them, so no packaging is needed.
"""


def keeper_lines(path):
    """Yield the |-split field list of each active (non-comment) keeper.conf
    line; yields nothing when the file is absent or unreadable."""
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "|" not in line:
            continue
        yield line.split("|")
