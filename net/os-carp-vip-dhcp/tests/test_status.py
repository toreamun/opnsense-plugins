"""Unit tests for status.py heartbeat / keeper-id parsing (comments over docstrings)."""
# pylint: disable=missing-function-docstring
import time
import types

import status  # sys.path via conftest  # type: ignore
from leasekeeper import syscmd  # status runs commands through it  # type: ignore


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


# ---- carp_states / carp_demotion: the two functions that shell out via syscmd.
# Stub subprocess.run (what syscmd calls) so the real syscmd layer is exercised.

def test_carp_states_maps_vhid_to_role(monkeypatch):
    text = ("em0: flags=8843\n\tcarp: MASTER vhid 149 advbase 1 advskew 0\n"
            "em1: flags=8843\n\tcarp: BACKUP vhid 20 advbase 1 advskew 100\n")
    monkeypatch.setattr(syscmd.subprocess, "run",
                        lambda *a, **k: types.SimpleNamespace(returncode=0, stdout=text))
    assert status.carp_states() == {"149": "MASTER", "20": "BACKUP"}


def test_carp_states_empty_when_ifconfig_unavailable(monkeypatch):
    # ifconfig probe fails -> syscmd.ifconfig returns None -> no roles, not a crash.
    def boom(*_a, **_k):
        raise OSError("no ifconfig")
    monkeypatch.setattr(syscmd.subprocess, "run", boom)
    assert not status.carp_states()


def test_carp_demotion_parses_counter(monkeypatch):
    monkeypatch.setattr(syscmd.subprocess, "run",
                        lambda *a, **k: types.SimpleNamespace(returncode=0, stdout="2\n"))
    assert status.carp_demotion() == 2


def test_carp_demotion_none_on_nonzero_exit(monkeypatch):
    monkeypatch.setattr(syscmd.subprocess, "run",
                        lambda *a, **k: types.SimpleNamespace(returncode=1, stdout=""))
    assert status.carp_demotion() is None


def test_carp_demotion_none_on_garbled_value(monkeypatch):
    monkeypatch.setattr(syscmd.subprocess, "run",
                        lambda *a, **k: types.SimpleNamespace(returncode=0, stdout="not-an-int\n"))
    assert status.carp_demotion() is None


def test_carp_demotion_none_on_launch_failure(monkeypatch):
    # sysctl could not be launched -> syscmd.run returns None -> the `res is None`
    # guard arm (distinct from the non-zero-exit arm), no AttributeError.
    def boom(*_a, **_k):
        raise OSError("no sysctl")
    monkeypatch.setattr(syscmd.subprocess, "run", boom)
    assert status.carp_demotion() is None


def test_carp_states_includes_init_and_ignores_non_carp(monkeypatch):
    # INIT is a real role (docstring lists MASTER/BACKUP/INIT); non-CARP lines are skipped.
    text = ("em0: flags\n\tcarp: INIT vhid 30 advbase 1 advskew 0\n"
            "em1: flags\n\tstatus: active\n")
    monkeypatch.setattr(syscmd.subprocess, "run",
                        lambda *a, **k: types.SimpleNamespace(returncode=0, stdout=text))
    assert status.carp_states() == {"30": "INIT"}


def test_carp_states_empty_when_no_carp_interfaces(monkeypatch):
    # ifconfig succeeds but the box has no CARP configured -> {} (distinct from the
    # ifconfig-unavailable case), never a crash.
    monkeypatch.setattr(syscmd.subprocess, "run",
                        lambda *a, **k: types.SimpleNamespace(returncode=0, stdout="em0: flags\n\tstatus: active\n"))
    assert not status.carp_states()
