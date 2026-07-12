"""Unit tests for status.py heartbeat / keeper-id parsing (comments over docstrings)."""
# pylint: disable=missing-function-docstring
import time

import status  # sys.path via conftest  # type: ignore  # pylint: disable=import-error


def test_keeper_id():
    assert status.keeper_id("100.64.4.7") == "100_64_4_7"
    assert status.keeper_id("00:00:5e:00:01:fe") == "00_00_5e_00_01_fe"


def test_parse_heartbeat_bound(tmp_path):
    hb = tmp_path / "hb"
    hb.write_text("1783350773 bound=100.64.4.7 lease=1800 t1=900 t2=1575 src=derived\n")
    result = status.parse_heartbeat(str(hb))
    assert result["bound"] == "100.64.4.7"
    assert result["lease"] == 1800
    assert result["t1"] == 900
    assert result["t2"] == 1575
    assert result["timing_source"] == "derived"
    assert not result["mismatch"]


def test_parse_heartbeat_unbound(tmp_path):
    hb = tmp_path / "hb"
    hb.write_text("1783350773 bound=- lease=1800 t1=900 t2=1575 src=derived\n")
    assert status.parse_heartbeat(str(hb))["bound"] is None


def test_parse_heartbeat_mismatch(tmp_path):
    hb = tmp_path / "hb"
    hb.write_text("1783350773 MISMATCH got=1.2.3.4 want=100.64.4.7\n")
    result = status.parse_heartbeat(str(hb))
    assert result["mismatch"] is True
    assert result["mismatch_got"] == "1.2.3.4"
    assert result["mismatch_want"] == "100.64.4.7"


def test_parse_heartbeat_missing(tmp_path):
    assert status.parse_heartbeat(str(tmp_path / "absent"))["bound"] is None


def test_parse_heartbeat_nudge_and_arpok(tmp_path):
    hb = tmp_path / "hb"
    hb.write_text("1783350773 bound=100.64.4.7 lease=1800 t1=900 t2=1575 src=derived"
                  " nudge=1783350700 arpok=1783350710 gw=100.64.4.1\n")
    result = status.parse_heartbeat(str(hb))
    assert result["nudge_epoch"] == 1783350700
    assert isinstance(result["nudge_age"], int) and result["nudge_age"] > 0
    assert result["arp_reply_epoch"] == 1783350710
    assert isinstance(result["arp_reply_age"], int) and result["arp_reply_age"] > 0
    assert result["gw"] == "100.64.4.1"


def test_parse_heartbeat_nudge_and_arpok_zero(tmp_path):
    hb = tmp_path / "hb"
    hb.write_text("1783350773 bound=100.64.4.7 lease=1800 t1=900 t2=1575 src=derived"
                  " nudge=0 arpok=0\n")
    result = status.parse_heartbeat(str(hb))
    assert result["nudge_epoch"] == 0
    assert result["nudge_age"] is None
    assert result["arp_reply_epoch"] == 0
    assert result["arp_reply_age"] is None
    assert result["gw"] is None


def test_parse_heartbeat_without_nudge_tokens(tmp_path):
    hb = tmp_path / "hb"
    hb.write_text("1783350773 bound=100.64.4.7 lease=1800 t1=900 t2=1575 src=derived\n")
    result = status.parse_heartbeat(str(hb))
    assert result["nudge_epoch"] is None
    assert result["nudge_age"] is None


def test_read_keepers_arp_nudge_field(tmp_path, monkeypatch):
    conf = tmp_path / "keeper.conf"
    conf.write_text(
        "100.64.4.7|eth0|00:00:5e:00:01:fe|0|254|1||||240|0\n"
        "100.64.4.8|eth0|00:00:5e:00:01:fd|0|253|1|||\n")   # short line (no arp-nudge field)
    monkeypatch.setattr(status, "CONFFILE", str(conf))
    monkeypatch.setattr(status, "RUN_DIR", str(tmp_path))
    keepers = status.read_keepers({}, {})
    assert keepers[0]["arp_nudge"] == 240
    assert keepers[1]["arp_nudge"] == 0


def _write_hb(path, arpok_age, now):
    path.write_text(
        f"{now} bound=100.64.4.7 lease=1800 t1=900 t2=1575 src=derived"
        f" nudge={now - 5} arpok={now - arpok_age} gw=100.64.4.1\n")


def test_read_keepers_arp_confirmed_fresh_and_stale(tmp_path, monkeypatch):
    now = int(time.time())
    conf = tmp_path / "keeper.conf"
    conf.write_text(
        "100.64.4.7|eth0|00:00:5e:00:01:fe|0|254|1||||240|0\n"    # fresh reply
        "100.64.4.8|eth0|00:00:5e:00:01:fd|0|253|1||||240|0\n"    # stale reply
        "100.64.4.9|eth0|00:00:5e:00:01:fc|0|252|1||||240|0\n")   # no reply seen
    monkeypatch.setattr(status, "CONFFILE", str(conf))
    monkeypatch.setattr(status, "RUN_DIR", str(tmp_path))
    _write_hb(tmp_path / "carpvipdhcp-100_64_4_7.hb", 5, now)       # 5s ago -> fresh
    _write_hb(tmp_path / "carpvipdhcp-100_64_4_8.hb", 5000, now)    # 5000s ago -> stale
    (tmp_path / "carpvipdhcp-100_64_4_9.hb").write_text(
        f"{now} bound=100.64.4.9 lease=1800 t1=900 t2=1575 src=derived"
        f" nudge={now - 5} arpok=0 gw=100.64.4.1\n")                                          # arpok=0 -> never
    by_ip = {k["request"]: k for k in status.read_keepers({}, {})}
    assert by_ip["100.64.4.7"]["arp_confirmed"] is True
    assert by_ip["100.64.4.8"]["arp_confirmed"] is False
    assert by_ip["100.64.4.9"]["arp_confirmed"] is False
