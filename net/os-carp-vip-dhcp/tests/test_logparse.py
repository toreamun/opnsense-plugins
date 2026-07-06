"""Unit tests for logparse.py log-line parsing."""
import logparse


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
