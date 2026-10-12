"""Shared keeper.conf access for the CarpVipDhcp configd scripts.

Lives in the same directory as its consumers (lease_keeper.py, status.py,
logparse.py), which Python puts on sys.path when they run, so no packaging is
needed.
"""
import re

CONFFILE = "/usr/local/etc/carpvipdhcp/keeper.conf"

# The Client identifier choices (keeper.conf cidmode), in the model's order.
CLIENT_ID_MODES = ("default", "none", "options")
_CLIENT_ID = 61


def keeper_id(request_ip):
    """Filesystem-safe keeper id (mirrors the daemon's _fs_safe charset; the
    two must stay in lockstep or the per-keeper file names diverge)."""
    return re.sub(r"[^A-Za-z0-9]", "_", request_ip)


def parse_send_options(raw):
    """The sendopts field ("code:hex,code:hex", as the model writes it) ->
    [(code, bytes), ...]; [] when empty. Raises ValueError on any field that is
    not code:hex with a code of 1-254, so the daemon and the status page agree
    on what is unusable. The message names the field by position or code only:
    a value may hold a credential, and the daemon logs the message."""
    options = []
    for position, field in enumerate(raw.split(",") if raw else [], start=1):
        code, sep, value = field.partition(":")
        if not sep or not code.isdigit() or not 0 < int(code) < 255:
            raise ValueError(f"send option {position} is not code:hex with a code of 1-254")
        try:
            options.append((int(code), bytes.fromhex(value)))
        except ValueError:
            raise ValueError(f"send option {position} (code {code}) is not hex") from None
    return options


def client_id_mode_problem(mode, send_opts):
    """Why the Client identifier choice cannot go with these parsed Send Options,
    or None: an unknown choice, From Send Options (options) without option 61, or
    None (none) with one. Default sends its own 61, so a second one there is the
    duplicate the option check refuses. The daemon and the status page both ask
    this, as the model does on save."""
    if mode not in CLIENT_ID_MODES:
        return f"unknown Client identifier choice {mode!r}"
    has_client_id = any(code == _CLIENT_ID for code, _value in send_opts)
    if mode == "options" and not has_client_id:
        return "Client identifier From Send Options, but no option 61 there"
    if mode == "none" and has_client_id:
        return "Client identifier None, but option 61 in Send Options"
    return None


def parse_request_codes(raw):
    """The reqopts field ("code,code") -> [code, ...]; [] when empty. Raises
    ValueError on a code that is not 1-254."""
    fields = raw.split(",") if raw else []
    if any(not field.isdigit() or not 0 < int(field) < 255 for field in fields):
        raise ValueError("request options hold a code that is not 1-254")
    return [int(field) for field in fields]


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
