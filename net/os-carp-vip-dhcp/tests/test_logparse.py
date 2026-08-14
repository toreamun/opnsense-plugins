"""Unit tests for logparse.py log-line parsing (comments over docstrings)."""
# pylint: disable=missing-function-docstring
import logparse  # sys.path via conftest  # type: ignore


def test_line_re_matches_standard_line():
    match = logparse.LINE_RE.match("2026-07-06 12:34:56,789 INFO some message")
    assert match is not None
    assert match.group(1) == "2026-07-06 12:34:56"
    assert match.group(2) == "INFO"
    assert match.group(3) == "some message"


def test_line_re_without_millis():
    match = logparse.LINE_RE.match("2026-07-06 12:34:56 WARNING no millis here")
    assert match is not None
    assert match.group(2) == "WARNING"
    assert match.group(3) == "no millis here"


def test_line_re_rejects_garbage():
    assert logparse.LINE_RE.match("not a log line") is None


def test_keeper_meta_reads_name_keyed_conf(tmp_path, monkeypatch):
    # keeper_meta was converted from positional (parts[0]/parts[4]) to name-keyed
    # dict access; confirm it maps keeper id -> {ip, vhid} from the new format.
    conf = tmp_path / "keeper.conf"
    conf.write_text(
        "request=100.64.4.7|iface=eth0|chaddr=aa|vhid=254\n"
        "request=100.64.4.8|iface=eth0|chaddr=bb|vhid=253\n")
    monkeypatch.setattr(logparse, "CONFFILE", str(conf))
    meta = logparse.keeper_meta()
    assert meta["100_64_4_7"] == {"ip": "100.64.4.7", "vhid": "254"}
    assert meta["100_64_4_8"] == {"ip": "100.64.4.8", "vhid": "253"}
