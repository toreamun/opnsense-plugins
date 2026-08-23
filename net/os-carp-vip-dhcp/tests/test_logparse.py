"""Unit tests for logparse.py log-line parsing (comments over docstrings)."""
# pylint: disable=missing-function-docstring
import json

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


def test_main_parses_tags_and_orders(tmp_path, monkeypatch, capsys):
    # main() globs the per-keeper logs, parses each line, tags it with the keeper's
    # ip/vhid, and emits newest-first JSON (the Diagnostics log-viewer feed).
    (tmp_path / "carpvipdhcp-100_64_4_7.log").write_text(
        "2026-07-06 12:00:00,100 INFO older line\n"
        "2026-07-06 12:34:56,789 WARNING newer line\n"
        "a bare continuation line with no timestamp\n")
    monkeypatch.setattr(logparse, "LOG_GLOB", str(tmp_path / "carpvipdhcp-*.log"))
    monkeypatch.setattr(logparse, "keeper_meta",
                        lambda: {"100_64_4_7": {"ip": "100.64.4.7", "vhid": "254"}})
    logparse.main()
    records = json.loads(capsys.readouterr().out)
    # newest-first: 12:34 WARNING, then 12:00 INFO, then the bare line (empty ts) last.
    assert [r["timestamp"] for r in records] == ["2026-07-06 12:34:56", "2026-07-06 12:00:00", ""]
    assert records[0]["level"] == "WARNING" and records[0]["message"] == "newer line"
    assert records[0]["keeper"] == "100.64.4.7" and records[0]["vhid"] == "254"
    assert records[2]["level"] == "" and "bare continuation" in records[2]["message"]


def test_main_unknown_keeper_falls_back_to_id(tmp_path, monkeypatch, capsys):
    # A log with no keeper.conf entry: keeper falls back to the filename id, vhid
    # empty -- the viewer still shows the lines.
    (tmp_path / "carpvipdhcp-1_2_3_4.log").write_text("2026-07-06 12:00:00 INFO x\n")
    monkeypatch.setattr(logparse, "LOG_GLOB", str(tmp_path / "carpvipdhcp-*.log"))
    monkeypatch.setattr(logparse, "keeper_meta", lambda: {})
    logparse.main()
    records = json.loads(capsys.readouterr().out)
    assert records[0]["keeper"] == "1_2_3_4" and records[0]["vhid"] == ""


def test_main_skips_unreadable_file(tmp_path, monkeypatch, capsys):
    # An unreadable path matching the glob (here a directory) is skipped, not fatal.
    (tmp_path / "carpvipdhcp-dir.log").mkdir()
    monkeypatch.setattr(logparse, "LOG_GLOB", str(tmp_path / "carpvipdhcp-*.log"))
    monkeypatch.setattr(logparse, "keeper_meta", lambda: {})
    logparse.main()
    assert not json.loads(capsys.readouterr().out)
