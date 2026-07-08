"""Unit tests for status.py heartbeat / keeper-id parsing."""
import status


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
    assert not result["standby"]
    assert not result["mismatch"]


def test_parse_heartbeat_unbound(tmp_path):
    hb = tmp_path / "hb"
    hb.write_text("1783350773 bound=- lease=1800 t1=900 t2=1575 src=derived\n")
    assert status.parse_heartbeat(str(hb))["bound"] is None


def test_parse_heartbeat_standby(tmp_path):
    hb = tmp_path / "hb"
    hb.write_text("1783350773 STANDBY\n")
    assert status.parse_heartbeat(str(hb))["standby"] is True


def test_parse_heartbeat_mismatch(tmp_path):
    hb = tmp_path / "hb"
    hb.write_text("1783350773 MISMATCH got=1.2.3.4 want=100.64.4.7\n")
    result = status.parse_heartbeat(str(hb))
    assert result["mismatch"] is True
    assert result["mismatch_got"] == "1.2.3.4"
    assert result["mismatch_want"] == "100.64.4.7"


def test_parse_heartbeat_missing(tmp_path):
    assert status.parse_heartbeat(str(tmp_path / "absent"))["bound"] is None


def test_parse_heartbeat_nudge(tmp_path):
    hb = tmp_path / "hb"
    hb.write_text("1783350773 bound=100.64.4.7 lease=1800 t1=900 t2=1575 src=derived"
                  " nudge=1783350700 gw=100.64.4.1\n")
    result = status.parse_heartbeat(str(hb))
    assert result["nudge_epoch"] == 1783350700
    assert isinstance(result["nudge_age"], int) and result["nudge_age"] > 0
    assert result["gw"] == "100.64.4.1"


def test_parse_heartbeat_nudge_never(tmp_path):
    hb = tmp_path / "hb"
    hb.write_text("1783350773 bound=100.64.4.7 lease=1800 t1=900 t2=1575 src=derived nudge=0\n")
    result = status.parse_heartbeat(str(hb))
    assert result["nudge_epoch"] == 0
    assert result["nudge_age"] is None
    assert result["gw"] is None


def test_parse_heartbeat_arpok(tmp_path):
    hb = tmp_path / "hb"
    hb.write_text("1783350773 bound=100.64.4.7 lease=1800 t1=900 t2=1575 src=derived"
                  " nudge=1783350700 arpok=1783350710 gw=100.64.4.1\n")
    result = status.parse_heartbeat(str(hb))
    assert result["arp_reply_epoch"] == 1783350710
    assert isinstance(result["arp_reply_age"], int) and result["arp_reply_age"] > 0


def test_parse_heartbeat_arpok_never(tmp_path):
    hb = tmp_path / "hb"
    hb.write_text("1783350773 bound=100.64.4.7 lease=1800 t1=900 t2=1575 src=derived"
                  " nudge=1783350700 arpok=0 gw=100.64.4.1\n")
    result = status.parse_heartbeat(str(hb))
    assert result["arp_reply_epoch"] == 0
    assert result["arp_reply_age"] is None


def test_parse_heartbeat_without_nudge_tokens(tmp_path):
    hb = tmp_path / "hb"
    hb.write_text("1783350773 bound=100.64.4.7 lease=1800 t1=900 t2=1575 src=derived\n")
    result = status.parse_heartbeat(str(hb))
    assert result["nudge_epoch"] is None
    assert result["nudge_age"] is None


def test_read_keepers_arp_nudge_field(tmp_path, monkeypatch):
    conf = tmp_path / "keeper.conf"
    conf.write_text(
        "100.64.4.7|eth0|00:00:5e:00:01:fe|0|254|0|1||||240\n"
        "100.64.4.8|eth0|00:00:5e:00:01:fd|0|253|0|1|||\n")   # old 10-field line
    monkeypatch.setattr(status, "CONFFILE", str(conf))
    monkeypatch.setattr(status, "RUN_DIR", str(tmp_path))
    keepers = status.read_keepers({}, {})
    assert keepers[0]["arp_nudge"] == 240
    assert keepers[1]["arp_nudge"] == 0
