"""Shared keeper.conf access for the CarpVipDhcp configd scripts.

Lives in the same directory as its consumers (lease_keeper.py, status.py,
logparse.py), which Python puts on sys.path when they run, so no packaging is
needed.
"""
import re

CONFFILE = "/usr/local/etc/carpvipdhcp/keeper.conf"


def keeper_id(request_ip):
    """Filesystem-safe keeper id (mirrors the daemon's _fs_safe charset; the
    two must stay in lockstep or the per-keeper file names diverge)."""
    return re.sub(r"[^A-Za-z0-9]", "_", request_ip)


def parse_send_options(raw):
    """The sendopts field ("code:hex,code:hex", as the model writes it) ->
    [(code, bytes), ...]; [] when empty. Raises ValueError on any field that is
    not code:hex with a code of 1-254, so the daemon and the status page agree
    on what is unusable."""
    options = []
    for field in raw.split(",") if raw else []:
        code, sep, value = field.partition(":")
        num = int(code)
        if not sep or not 0 < num < 255:
            raise ValueError(f"send option {field!r} is not code:hex")
        options.append((num, bytes.fromhex(value)))
    return options


def parse_request_codes(raw):
    """The reqopts field ("code,code") -> [code, ...]; [] when empty. Raises
    ValueError on a code that is not 1-254."""
    codes = [int(code) for code in raw.split(",")] if raw else []
    if any(not 0 < code < 255 for code in codes):
        raise ValueError(f"request options {raw!r} have a code outside 1-254")
    return codes


def keeper_records_text(text):
    """Yield each active (non-comment) keeper.conf line in `text` as a {key: value}
    dict -- the pure parser, with no file IO (keeper_records reads the file).

    Each line is a pipe-separated list of KEY=VALUE fields in no fixed order (see
    the template); we dispatch by key, so a missing key is simply absent from the
    dict and the caller supplies its default. Lines without a request= field are
    skipped, mirroring the rc.d reader."""
    for line in text.splitlines():
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


def keeper_records(path):
    """Yield each active keeper.conf record from the file at `path`. Yields nothing
    when the file is absent or unreadable; the parsing lives in keeper_records_text."""
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return
    yield from keeper_records_text(text)
