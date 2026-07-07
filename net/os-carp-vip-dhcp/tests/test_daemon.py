"""Unit tests for the lease-keeper daemon's pure helpers and follow decision."""


def test_sane_ipv4(lk):
    assert lk._sane_ipv4("100.64.4.7")
    assert lk._sane_ipv4("8.8.8.8")
    for bad in ("0.0.0.0", "127.0.0.1", "169.254.1.1", "224.0.0.1", "nonsense"):
        assert not lk._sane_ipv4(bad)


def test_localish_and_class(lk):
    assert lk._is_localish("100.64.4.7")      # CGNAT (RFC 6598)
    assert lk._is_localish("192.168.1.1")     # RFC 1918
    assert not lk._is_localish("8.8.8.8")     # public
    assert lk._same_ip_class("100.64.4.7", "100.64.4.60")
    assert not lk._same_ip_class("100.64.4.7", "8.8.8.8")


def test_fs_safe(lk):
    assert lk._fs_safe("00:00:5e:00:01:fe") == "00_00_5e_00_01_fe"
    assert lk._fs_safe("100.64.4.7") == "100_64_4_7"


def test_timing_derived(lk):
    keeper = lk.Keeper("eth0", "00:00:5e:00:01:fe", "100.64.4.7", hbfile=None)
    keeper.lease = 1800
    assert keeper._timing() == (900, 1575, "derived")


def test_timing_honours_server(lk):
    keeper = lk.Keeper("eth0", "00:00:5e:00:01:fe", "100.64.4.7", hbfile=None)
    keeper.lease = 1800
    keeper.t1_server = 600
    keeper.t2_server = 1200
    assert keeper._timing() == (600, 1200, "server")


def _follow_keeper(lk, tmp_path):
    keeper = lk.Keeper("eth0", "00:00:5e:00:01:fe", "100.64.4.7", hbfile=None, follow=True)
    keeper._follow_state = str(tmp_path / "follow_state")
    keeper.server = "100.64.4.1"
    keeper.yiaddr = "100.64.4.7"
    keeper.fired = []
    keeper._follow_update = keeper.fired.append
    keeper._hb_mismatch = lambda got: None
    keeper.release = lambda: None
    return keeper


def _ack(lk, yiaddr, server="100.64.4.1"):
    return lk.DhcpReply(5, yiaddr, server, 1800, None, None)


def test_follow_accepts_same_class(lk, tmp_path):
    keeper = _follow_keeper(lk, tmp_path)
    assert keeper._handle_changed_address("100.64.4.60", _ack(lk, "100.64.4.60"), "DORA", True) is True
    assert keeper.fired == ["100.64.4.60"]
    assert keeper.request_ip == "100.64.4.60"


def test_follow_rejects_wrong_server(lk, tmp_path):
    keeper = _follow_keeper(lk, tmp_path)
    reply = _ack(lk, "100.64.4.60", server="100.64.4.9")
    assert keeper._handle_changed_address("100.64.4.60", reply, "DORA", True) is False
    assert keeper.fired == []


def test_follow_rejects_cross_class(lk, tmp_path):
    keeper = _follow_keeper(lk, tmp_path)
    assert keeper._handle_changed_address("8.8.8.8", _ack(lk, "8.8.8.8"), "DORA", True) is False
    assert keeper.fired == []


def test_follow_throttled_within_interval(lk, tmp_path):
    keeper = _follow_keeper(lk, tmp_path)
    assert keeper._handle_changed_address("100.64.4.60", _ack(lk, "100.64.4.60"), "DORA", True) is True
    # A second follow inside MIN_FOLLOW_INTERVAL is deferred.
    assert keeper._handle_changed_address("100.64.4.61", _ack(lk, "100.64.4.61"), "DORA", True) is False


def test_enforce_mismatch_refused(lk, tmp_path):
    keeper = lk.Keeper("eth0", "00:00:5e:00:01:fe", "100.64.4.7", hbfile=None, follow=False)
    keeper.server = "100.64.4.1"
    keeper.yiaddr = "100.64.4.7"
    keeper.release = lambda: None
    assert keeper._handle_changed_address("100.64.4.60", _ack(lk, "100.64.4.60"), "DORA", True) is False


def test_id_opts_empty_by_default(lk):
    keeper = lk.Keeper("eth0", "00:00:5e:00:01:fe", "100.64.4.7", hbfile=None)
    assert keeper._id_opts == []


def test_id_opts_built_from_args(lk):
    keeper = lk.Keeper("eth0", "00:00:5e:00:01:fe", "100.64.4.7", hbfile=None,
                       vendor_class="MSFT 5.0", client_id="keeper-1", hostname="vip")
    assert ("vendor_class_id", "MSFT 5.0") in keeper._id_opts
    assert ("client_id", b"keeper-1") in keeper._id_opts
    assert ("hostname", "vip") in keeper._id_opts


def _nudge_keeper(lk, **kwargs):
    keeper = lk.Keeper("eth0", "00:00:5e:00:01:fe", "100.64.4.7", hbfile=None,
                       arp_nudge=kwargs.pop("arp_nudge", 240), **kwargs)
    keeper.yiaddr = "100.64.4.7"
    keeper.server = "100.64.4.1"
    keeper._carp_master_now = lambda: True   # not under test here (needs ifconfig)
    return keeper


def test_nudge_off_by_default(lk):
    keeper = lk.Keeper("eth0", "00:00:5e:00:01:fe", "100.64.4.7", hbfile=None)
    assert keeper.arp_nudge == 0
    keeper._arp_nudge(force=True)   # must be a no-op, not an error
    assert keeper._last_nudge == 0.0


def test_nudge_interval_floor(lk):
    keeper = lk.Keeper("eth0", "00:00:5e:00:01:fe", "100.64.4.7", hbfile=None, arp_nudge=1)
    assert keeper.arp_nudge == lk.ARP_NUDGE_MIN


def test_nudge_respects_interval_and_force(lk):
    keeper = _nudge_keeper(lk)
    keeper._arp_nudge()
    first = keeper._last_nudge
    assert first > 0
    keeper._arp_nudge()             # within the interval -> skipped
    assert keeper._last_nudge == first
    keeper._arp_nudge(force=True)   # forced (BOUND/RENEW/REBIND) -> sent
    assert keeper._last_nudge > first


def test_nudge_requires_gateway_and_lease(lk):
    keeper = _nudge_keeper(lk)
    keeper.server = None            # no router option and no server_id -> no target
    keeper._arp_nudge(force=True)
    assert keeper._last_nudge == 0.0
    keeper.server = "100.64.4.1"
    keeper.yiaddr = None            # not bound -> no source address
    keeper._arp_nudge(force=True)
    assert keeper._last_nudge == 0.0


def test_nudge_works_from_router_option_alone(lk):
    keeper = _nudge_keeper(lk)
    keeper.server = None
    keeper.router = "100.64.4.254"   # DHCP option 3 alone is a valid target
    keeper._arp_nudge(force=True)
    assert keeper._last_nudge > 0


def test_nudge_gated_to_carp_master(lk):
    keeper = _nudge_keeper(lk, vhid=199)
    keeper._carp_master_now = lambda: False
    keeper._arp_nudge(force=True)
    assert keeper._last_nudge == 0.0   # never nudge from a CARP backup


def test_carp_master_now_true_without_vhid(lk):
    keeper = lk.Keeper("eth0", "00:00:5e:00:01:fe", "100.64.4.7", hbfile=None)
    assert keeper._carp_master_now() is True


def test_carp_master_now_fails_closed(lk, monkeypatch):
    keeper = lk.Keeper("eth0", "00:00:5e:00:01:fe", "100.64.4.7", hbfile=None, vhid=199)

    def boom(*a, **k):
        raise OSError("ifconfig unavailable")
    monkeypatch.setattr(lk.subprocess, "check_output", boom)
    assert keeper._carp_master_now() is False


def test_ack_router_option_defaulted(lk):
    # Existing 6-arg constructions (and old pickled replies) must keep working.
    reply = lk.DhcpReply(5, "100.64.4.7", "100.64.4.1", 1800, None, None)
    assert reply.router is None


def test_hb_includes_nudge_state(lk, tmp_path):
    hb = tmp_path / "hb"
    keeper = lk.Keeper("eth0", "00:00:5e:00:01:fe", "100.64.4.7",
                       hbfile=str(hb), arp_nudge=240)
    keeper.yiaddr = "100.64.4.7"
    keeper.router = "100.64.4.1"
    keeper._last_nudge = 1783350000.0
    keeper._hb()
    content = hb.read_text()
    assert " nudge=1783350000" in content
    assert " gw=100.64.4.1" in content


def test_hb_nudge_never_and_no_gateway(lk, tmp_path):
    hb = tmp_path / "hb"
    keeper = lk.Keeper("eth0", "00:00:5e:00:01:fe", "100.64.4.7",
                       hbfile=str(hb), arp_nudge=240)
    keeper._hb()
    content = hb.read_text()
    assert " nudge=0" in content     # enabled but never sent
    assert "gw=" not in content      # no target known yet


def test_hb_no_nudge_tokens_when_off(lk, tmp_path):
    hb = tmp_path / "hb"
    keeper = lk.Keeper("eth0", "00:00:5e:00:01:fe", "100.64.4.7", hbfile=str(hb))
    keeper._hb()
    assert "nudge=" not in hb.read_text()


def test_nudge_fires_immediately_on_master_transition(lk):
    keeper = _nudge_keeper(lk)
    keeper._arp_nudge()                  # master from the start -> sends
    first = keeper._last_nudge
    assert first > 0
    states = iter([False, True, True])
    keeper._carp_master_now = lambda: next(states)
    keeper._arp_nudge()                  # now backup -> no send, remembers the role
    assert keeper._last_nudge == first
    keeper._arp_nudge()                  # backup -> master: forced despite the interval
    assert keeper._last_nudge > first
    second = keeper._last_nudge
    keeper._arp_nudge()                  # still master -> interval applies again
    assert keeper._last_nudge == second


def test_nudge_missing_gateway_warns_once(lk, caplog):
    keeper = _nudge_keeper(lk)
    keeper.server = None             # enabled + bound, but no target
    with caplog.at_level("WARNING", logger="lease-keeper"):
        keeper._arp_nudge(force=True)
        keeper._arp_nudge(force=True)
    warnings = [r for r in caplog.records if "no gateway known" in r.getMessage()]
    assert len(warnings) == 1        # warned, but only once
