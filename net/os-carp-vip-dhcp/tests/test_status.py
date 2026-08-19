"""Unit tests for status.py heartbeat / keeper-id parsing (comments over docstrings)."""
# pylint: disable=missing-function-docstring
import time

import status  # sys.path via conftest  # type: ignore


def test_keeper_id():
    assert status.keeper_id("100.64.4.7") == "100_64_4_7"
    assert status.keeper_id("00:00:5e:00:01:fe") == "00_00_5e_00_01_fe"


def test_parse_heartbeat_bound():
    result = status.parse_heartbeat_text(
        "1783350773 bound=100.64.4.7 lease=1800 t1=900 t2=1575 src=derived\n")
    assert result["bound"] == "100.64.4.7"
    assert result["lease"] == 1800
    assert result["t1"] == 900
    assert result["t2"] == 1575
    assert result["timing_source"] == "derived"
    assert not result["mismatch"]


def test_parse_heartbeat_unbound():
    text = "1783350773 bound=- lease=1800 t1=900 t2=1575 src=derived\n"
    assert status.parse_heartbeat_text(text)["bound"] is None


def test_parse_heartbeat_mismatch():
    result = status.parse_heartbeat_text("1783350773 MISMATCH got=1.2.3.4 want=100.64.4.7\n")
    assert result["mismatch"] is True
    assert result["mismatch_got"] == "1.2.3.4"
    assert result["mismatch_want"] == "100.64.4.7"


def test_parse_heartbeat_missing(tmp_path):
    # the file-reading wrapper: an absent file parses to the empty result.
    assert status.parse_heartbeat(str(tmp_path / "absent"))["bound"] is None


def test_parse_heartbeat_nudge_and_arpok():
    result = status.parse_heartbeat_text(
        "1783350773 bound=100.64.4.7 lease=1800 t1=900 t2=1575 src=derived"
        " nudge=1783350700 arpok=1783350710 gw=100.64.4.1\n")
    assert result["nudge_epoch"] == 1783350700
    assert isinstance(result["nudge_age"], int) and result["nudge_age"] > 0
    assert result["arp_reply_epoch"] == 1783350710
    assert isinstance(result["arp_reply_age"], int) and result["arp_reply_age"] > 0
    assert result["gw"] == "100.64.4.1"


def test_parse_heartbeat_nudge_and_arpok_zero():
    result = status.parse_heartbeat_text(
        "1783350773 bound=100.64.4.7 lease=1800 t1=900 t2=1575 src=derived"
        " nudge=0 arpok=0\n")
    assert result["nudge_epoch"] == 0
    assert result["nudge_age"] is None
    assert result["arp_reply_epoch"] == 0
    assert result["arp_reply_age"] is None
    assert result["gw"] is None


def test_parse_heartbeat_without_nudge_tokens():
    result = status.parse_heartbeat_text(
        "1783350773 bound=100.64.4.7 lease=1800 t1=900 t2=1575 src=derived\n")
    assert result["nudge_epoch"] is None
    assert result["nudge_age"] is None


def test_read_keepers_arp_nudge_field(tmp_path):
    conf = tmp_path / "keeper.conf"
    conf.write_text(
        "request=100.64.4.7|iface=eth0|chaddr=00:00:5e:00:01:fe|demote=0|vhid=254|follow=1|arpnudge=240\n"
        "request=100.64.4.8|iface=eth0|chaddr=00:00:5e:00:01:fd|demote=0|vhid=253|follow=1\n")  # no arpnudge key
    keepers = status.read_keepers({}, {}, conffile=str(conf), run_dir=str(tmp_path))
    assert keepers[0]["arp_nudge"] == 240
    assert keepers[1]["arp_nudge"] == 0


def _write_hb(path, arpok_age, now):
    path.write_text(
        f"{now} bound=100.64.4.7 lease=1800 t1=900 t2=1575 src=derived"
        f" nudge={now - 5} arpok={now - arpok_age} gw=100.64.4.1\n")


def test_read_keepers_arp_confirmed_fresh_and_stale(tmp_path):
    now = int(time.time())
    conf = tmp_path / "keeper.conf"
    conf.write_text(
        "request=100.64.4.7|iface=eth0|chaddr=00:00:5e:00:01:fe|demote=0|vhid=254|follow=1|arpnudge=240\n"  # fresh
        "request=100.64.4.8|iface=eth0|chaddr=00:00:5e:00:01:fd|demote=0|vhid=253|follow=1|arpnudge=240\n"  # stale
        "request=100.64.4.9|iface=eth0|chaddr=00:00:5e:00:01:fc|demote=0|vhid=252|follow=1|arpnudge=240\n")  # no reply
    _write_hb(tmp_path / "carpvipdhcp-100_64_4_7.hb", 5, now)       # 5s ago -> fresh
    _write_hb(tmp_path / "carpvipdhcp-100_64_4_8.hb", 5000, now)    # 5000s ago -> stale
    (tmp_path / "carpvipdhcp-100_64_4_9.hb").write_text(
        f"{now} bound=100.64.4.9 lease=1800 t1=900 t2=1575 src=derived"
        f" nudge={now - 5} arpok=0 gw=100.64.4.1\n")   # arpok=0 -> never
    by_ip = {k["request"]: k
             for k in status.read_keepers({}, {}, conffile=str(conf), run_dir=str(tmp_path))}
    assert by_ip["100.64.4.7"]["arp_confirmed"] is True
    assert by_ip["100.64.4.8"]["arp_confirmed"] is False
    assert by_ip["100.64.4.9"]["arp_confirmed"] is False
