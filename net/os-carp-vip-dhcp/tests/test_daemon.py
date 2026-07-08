"""Unit tests for the lease-keeper daemon's pure helpers and follow decision."""
import time
import types


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
    return lk.DhcpReply(5, yiaddr, server, 1800, None, None, None)


class _DhcpPkt:
    """Minimal stand-in for a scapy DHCP reply: p[BOOTP].xid/op/yiaddr and
    p[DHCP].options, with haslayer() so _on_dhcp_reply parses it."""
    def __init__(self, lk, xid, options, yiaddr="100.64.4.7",
                 chaddr=b"\x00\x00\x5e\x00\x01\xfe", op=None):
        self._lk = lk
        self._bootp = types.SimpleNamespace(xid=xid, op=(lk.BOOTREPLY if op is None else op),
                                            yiaddr=yiaddr, chaddr=chaddr)
        self._dhcp = types.SimpleNamespace(options=options)

    def haslayer(self, layer):
        return layer in (self._lk.BOOTP, self._lk.DHCP)

    def __getitem__(self, layer):
        return self._bootp if layer is self._lk.BOOTP else self._dhcp


def test_on_dhcp_reply_captures_option56_message(lk):
    keeper = lk.Keeper("eth0", "00:00:5e:00:01:fe", "100.64.4.7", hbfile=None)
    pkt = _DhcpPkt(lk, keeper.xid, [("message-type", lk.NAK), ("server_id", "100.64.4.1"),
                                    ("message", "pool exhausted"), "end"])
    keeper._on_dhcp_reply(pkt)
    assert keeper._rx.message == "pool exhausted"


def test_dhcpnak_logs_option56_reason(lk, caplog):
    keeper = lk.Keeper("eth0", "00:00:5e:00:01:fe", "100.64.4.7", hbfile=None)
    keeper._rx = lk.DhcpReply(lk.NAK, None, "100.64.4.1", None, None, None, None, "lease not available")
    with caplog.at_level("WARNING", logger="lease-keeper"):
        assert keeper._wait_for_dhcp_reply(lk.ACK, 0.2) == "NAK"
    nak = [r for r in caplog.records if "DHCPNAK" in r.getMessage()]
    assert nak and "lease not available" in nak[0].getMessage()


def test_dhcpnak_reason_bytes_decoded(lk, caplog):
    keeper = lk.Keeper("eth0", "00:00:5e:00:01:fe", "100.64.4.7", hbfile=None)
    keeper._rx = lk.DhcpReply(lk.NAK, None, "100.64.4.1", None, None, None, None, b"bad chaddr")
    with caplog.at_level("WARNING", logger="lease-keeper"):
        keeper._wait_for_dhcp_reply(lk.ACK, 0.2)
    assert any("bad chaddr" in r.getMessage() for r in caplog.records)


def test_dhcpnak_without_message_still_logs(lk, caplog):
    keeper = lk.Keeper("eth0", "00:00:5e:00:01:fe", "100.64.4.7", hbfile=None)
    keeper._rx = lk.DhcpReply(lk.NAK, None, "100.64.4.1", None, None, None, None)   # message defaults to None
    with caplog.at_level("WARNING", logger="lease-keeper"):
        keeper._wait_for_dhcp_reply(lk.ACK, 0.2)
    assert any("DHCPNAK received" in r.getMessage() for r in caplog.records)


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


# ---- observed peer ACK: converge follow from the peer's exchange (single-ip s.3) ----

def _observe_keeper(lk, tmp_path):
    # Same fixture as _follow_keeper (server / yiaddr / _follow_state / fired +
    # _follow_update stubs), plus a known in-flight xid so a peer ACK (different
    # xid) takes the observed path.
    keeper = _follow_keeper(lk, tmp_path)
    keeper.xid = 0x11111111
    return keeper


def _peer_ack(lk, yiaddr, xid=0x22222222, server="100.64.4.1",
              chaddr=b"\x00\x00\x5e\x00\x01\xfe"):
    """A DHCP ACK on our shared chaddr but a DIFFERENT xid -- i.e. the peer's."""
    return _DhcpPkt(lk, xid, [("message-type", lk.ACK), ("server_id", server),
                              ("lease_time", 1800), "end"], yiaddr=yiaddr, chaddr=chaddr)


def test_observed_peer_ack_records_change(lk, tmp_path):
    keeper = _observe_keeper(lk, tmp_path)
    keeper._on_dhcp_reply(_peer_ack(lk, "100.64.4.60"))
    assert keeper._observed_change is not None
    assert keeper._observed_change.yiaddr == "100.64.4.60"
    assert keeper._rx is None          # the first-party slot is untouched


def test_observed_wakes_main_loop(lk, tmp_path):
    keeper = _observe_keeper(lk, tmp_path)
    assert not keeper._wake.is_set()
    keeper._on_dhcp_reply(_peer_ack(lk, "100.64.4.60"))
    assert keeper._wake.is_set()       # sniffer wakes the maintain-loop sleep at once


def test_ignored_observation_does_not_wake(lk, tmp_path):
    keeper = _observe_keeper(lk, tmp_path)
    keeper._on_dhcp_reply(_peer_ack(lk, "100.64.4.7"))     # same address -> no change
    assert keeper._observed_change is None
    assert not keeper._wake.is_set()


def test_observed_ignores_same_address(lk, tmp_path):
    keeper = _observe_keeper(lk, tmp_path)
    keeper._on_dhcp_reply(_peer_ack(lk, "100.64.4.7"))     # no change from what we hold
    assert keeper._observed_change is None


def test_observed_ignores_wrong_chaddr(lk, tmp_path):
    keeper = _observe_keeper(lk, tmp_path)
    keeper._on_dhcp_reply(_peer_ack(lk, "100.64.4.60", chaddr=b"\xaa\xbb\xcc\xdd\xee\xff"))
    assert keeper._observed_change is None


def test_observed_ignores_non_ack(lk, tmp_path):
    keeper = _observe_keeper(lk, tmp_path)
    keeper._on_dhcp_reply(_DhcpPkt(lk, 0x22222222,
                                   [("message-type", lk.OFFER), ("server_id", "100.64.4.1"), "end"],
                                   yiaddr="100.64.4.60"))
    assert keeper._observed_change is None


def test_observed_ignored_when_not_follow(lk, tmp_path):
    keeper = lk.Keeper("eth0", "00:00:5e:00:01:fe", "100.64.4.7", hbfile=None, follow=False)
    keeper.server = "100.64.4.1"
    keeper.yiaddr = "100.64.4.7"
    keeper.xid = 0x11111111
    keeper._on_dhcp_reply(_peer_ack(lk, "100.64.4.60"))
    assert keeper._observed_change is None


def test_own_xid_reply_uses_first_party_path(lk, tmp_path):
    keeper = _observe_keeper(lk, tmp_path)
    keeper._on_dhcp_reply(_DhcpPkt(lk, keeper.xid,
                                   [("message-type", lk.ACK), ("server_id", "100.64.4.1"), "end"],
                                   yiaddr="100.64.4.60"))
    assert keeper._observed_change is None            # not the observed path
    assert keeper._rx is not None and keeper._rx.yiaddr == "100.64.4.60"


def test_observed_latest_wins(lk, tmp_path):
    # Two peer ACKs in quick succession (the sniffer overwrites _observed_change):
    # the handler acts on the LATEST address -- the older one is superseded (the
    # shared lease is now the newer address), so dropping it is correct.
    keeper = _observe_keeper(lk, tmp_path)
    keeper._on_dhcp_reply(_peer_ack(lk, "100.64.4.60"))
    keeper._on_dhcp_reply(_peer_ack(lk, "100.64.4.61"))
    assert keeper._observed_change.yiaddr == "100.64.4.61"
    keeper._check_observed_follow()
    assert keeper.fired == ["100.64.4.61"]
    assert keeper._observed_change is None


def test_observed_same_address_after_follow_is_dropped(lk, tmp_path):
    # After we've followed to the new address, a lingering observation for that
    # same address is a no-op (the == self.yiaddr guard), never a double-follow.
    keeper = _observe_keeper(lk, tmp_path)
    keeper.yiaddr = "100.64.4.61"                 # we already hold the new address
    keeper._observed_change = _ack(lk, "100.64.4.61")
    keeper._check_observed_follow()
    assert keeper.fired == []                     # no redundant follow
    assert keeper._observed_change is None


def test_check_observed_follow_drives_hardened_follow(lk, tmp_path):
    keeper = _observe_keeper(lk, tmp_path)
    keeper._observed_change = _ack(lk, "100.64.4.60")
    keeper._check_observed_follow()
    assert keeper.fired == ["100.64.4.60"]
    assert keeper.request_ip == "100.64.4.60"
    assert keeper._observed_change is None


def test_check_observed_follow_rejects_wrong_server(lk, tmp_path):
    keeper = _observe_keeper(lk, tmp_path)
    keeper._observed_change = _ack(lk, "100.64.4.60", server="100.64.4.9")  # not our server
    keeper._check_observed_follow()
    assert keeper.fired == []          # same hardening as a first-party ACK


def test_observed_serviced_by_maintain_loop(lk, tmp_path):
    keeper = _observe_keeper(lk, tmp_path)
    keeper._observed_change = _ack(lk, "100.64.4.60")
    keeper._wake.set()                 # as the sniffer would -> loop returns at once
    keeper._sleep_gated(1)
    assert keeper.fired == ["100.64.4.60"]


# ---- peer client-id mismatch warning (shared-lease sanity, review item #12) ----

def _cid_keeper(lk, client_id="keeper-A"):
    keeper = lk.Keeper("eth0", "00:00:5e:00:01:fe", "100.64.4.7", hbfile=None, client_id=client_id)
    keeper.xid = 0x11111111                      # OUR in-flight xid
    return keeper


def _peer_request(lk, options, xid=0x22222222, chaddr=b"\x00\x00\x5e\x00\x01\xfe"):
    """A DHCP REQUEST (op=BOOTREQUEST) from the peer on our shared chaddr."""
    return _DhcpPkt(lk, xid, options + ["end"], op=lk.BOOTREQUEST, chaddr=chaddr)


def _has_cid_warn(caplog):
    return any("client-id" in r.getMessage() and "differs" in r.getMessage() for r in caplog.records)


def test_peer_client_id_mismatch_warns(lk, caplog):
    keeper = _cid_keeper(lk, "keeper-A")
    with caplog.at_level("WARNING", logger="lease-keeper"):
        keeper._on_dhcp_reply(_peer_request(lk, [("client_id", b"keeper-B")]))
    assert _has_cid_warn(caplog)


def test_peer_client_id_match_no_warn(lk, caplog):
    keeper = _cid_keeper(lk, "keeper-A")
    with caplog.at_level("WARNING", logger="lease-keeper"):
        keeper._on_dhcp_reply(_peer_request(lk, [("client_id", b"keeper-A")]))
    assert not _has_cid_warn(caplog)


def test_peer_client_id_both_unset_no_warn(lk, caplog):
    keeper = lk.Keeper("eth0", "00:00:5e:00:01:fe", "100.64.4.7", hbfile=None)   # no client-id
    keeper.xid = 0x11111111
    with caplog.at_level("WARNING", logger="lease-keeper"):
        keeper._on_dhcp_reply(_peer_request(lk, [("server_id", "100.64.4.1")]))  # no option 61
    assert not _has_cid_warn(caplog)


def test_peer_client_id_wrong_chaddr_ignored(lk, caplog):
    keeper = _cid_keeper(lk, "keeper-A")
    with caplog.at_level("WARNING", logger="lease-keeper"):
        keeper._on_dhcp_reply(_peer_request(lk, [("client_id", b"keeper-B")],
                                            chaddr=b"\xaa\xbb\xcc\xdd\xee\xff"))
    assert not _has_cid_warn(caplog)


def test_own_request_not_client_id_checked(lk, caplog):
    keeper = _cid_keeper(lk, "keeper-A")
    with caplog.at_level("WARNING", logger="lease-keeper"):
        # our OWN request (our xid) is not the peer path -> no comparison, no warn
        keeper._on_dhcp_reply(_peer_request(lk, [("client_id", b"keeper-B")], xid=keeper.xid))
    assert not _has_cid_warn(caplog)


def test_peer_client_id_warns_once_per_value(lk, caplog):
    keeper = _cid_keeper(lk, "keeper-A")
    with caplog.at_level("WARNING", logger="lease-keeper"):
        keeper._on_dhcp_reply(_peer_request(lk, [("client_id", b"keeper-B")]))
        keeper._on_dhcp_reply(_peer_request(lk, [("client_id", b"keeper-B")]))   # same -> no re-warn
    warns = [r for r in caplog.records if "client-id" in r.getMessage() and "differs" in r.getMessage()]
    assert len(warns) == 1


def test_id_opts_empty_by_default(lk):
    keeper = lk.Keeper("eth0", "00:00:5e:00:01:fe", "100.64.4.7", hbfile=None)
    assert keeper._id_opts == []


def test_id_opts_built_from_args(lk):
    keeper = lk.Keeper("eth0", "00:00:5e:00:01:fe", "100.64.4.7", hbfile=None,
                       vendor_class="MSFT 5.0", client_id="keeper-1", hostname="vip")
    assert ("vendor_class_id", "MSFT 5.0") in keeper._id_opts
    assert ("client_id", b"keeper-1") in keeper._id_opts
    assert ("hostname", "vip") in keeper._id_opts


def _nudge_keeper(lk, arp_nudge=240, hbfile=None, **kwargs):
    keeper = lk.Keeper("eth0", "00:00:5e:00:01:fe", "100.64.4.7",
                       hbfile=hbfile, arp_nudge=arp_nudge, **kwargs)
    keeper.yiaddr = "100.64.4.7"
    keeper.server = "100.64.4.1"
    keeper._probe_carp_master = lambda: True   # the real probe needs ifconfig
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
    keeper._probe_carp_master = lambda: False
    keeper._arp_nudge(force=True)
    assert keeper._last_nudge == 0.0   # never nudge from a CARP backup


def test_probe_carp_master_true_without_vhid(lk):
    keeper = lk.Keeper("eth0", "00:00:5e:00:01:fe", "100.64.4.7", hbfile=None)
    assert keeper._probe_carp_master() is True


def test_probe_failure_skips_nudge(lk, monkeypatch):
    # A failed probe reports None, and the nudge fails closed on anything but
    # a confirmed MASTER.
    keeper = lk.Keeper("eth0", "00:00:5e:00:01:fe", "100.64.4.7", hbfile=None,
                       vhid=199, arp_nudge=240)
    keeper.yiaddr = "100.64.4.7"
    keeper.server = "100.64.4.1"

    def boom(*a, **k):
        raise OSError("ifconfig unavailable")
    monkeypatch.setattr(lk.subprocess, "check_output", boom)
    assert keeper._probe_carp_master() is None
    keeper._arp_nudge(force=True)
    assert keeper._last_nudge == 0.0


def test_hb_includes_nudge_state(lk, tmp_path):
    hb = tmp_path / "hb"
    keeper = _nudge_keeper(lk, hbfile=str(hb))
    keeper.router = "100.64.4.1"
    keeper._last_nudge = 1783350000.0
    keeper._hb()
    content = hb.read_text()
    assert " nudge=1783350000" in content
    assert " gw=100.64.4.1" in content


def test_hb_nudge_never_and_no_gateway(lk, tmp_path):
    hb = tmp_path / "hb"
    keeper = _nudge_keeper(lk, hbfile=str(hb))
    keeper.server = None
    keeper._hb()
    content = hb.read_text()
    assert " nudge=0" in content     # enabled but never sent
    assert "gw=" not in content      # no target known yet


def test_hb_no_nudge_tokens_when_off(lk, tmp_path):
    hb = tmp_path / "hb"
    keeper = _nudge_keeper(lk, arp_nudge=0, hbfile=str(hb))
    keeper._hb()
    assert "nudge=" not in hb.read_text()


def test_master_transition_renews_early_and_nudges(lk):
    keeper = _nudge_keeper(lk, vhid=199)
    states = iter([True, False, True, True, True])
    keeper._probe_carp_master = lambda: next(states)
    keeper._poll_carp_role()             # master from the start -> no transition
    assert keeper._renew_asap is False
    assert keeper._last_nudge == 0.0
    keeper._poll_carp_role()             # backup -> remembers the role
    keeper._poll_carp_role()             # backup -> master (the forced nudge probes again)
    assert keeper._renew_asap is True
    first = keeper._last_nudge
    assert first > 0
    keeper._poll_carp_role()             # still master -> nothing new
    assert keeper._last_nudge == first


def test_losing_master_is_logged(lk, caplog):
    keeper = _nudge_keeper(lk, vhid=199)
    states = iter([True, False])
    keeper._probe_carp_master = lambda: next(states)
    with caplog.at_level("INFO", logger="lease-keeper"):
        keeper._poll_carp_role()         # master
        keeper._poll_carp_role()         # master -> backup
    assert any("lost CARP master" in r.getMessage() for r in caplog.records)
    assert keeper._renew_asap is False   # losing master triggers nothing else


def test_master_transition_renews_even_with_nudge_off(lk):
    keeper = _nudge_keeper(lk, arp_nudge=0, vhid=199)
    states = iter([False, True])
    keeper._probe_carp_master = lambda: next(states)
    keeper._poll_carp_role()
    keeper._poll_carp_role()
    assert keeper._renew_asap is True    # the early renew is not tied to the nudge
    assert keeper._last_nudge == 0.0     # but no nudge was sent


def test_hold_returns_early_for_asap_renew(lk):
    keeper = _nudge_keeper(lk)
    keeper._renew_asap = True
    start = time.time()
    assert keeper._hold_lease(60) is True   # returns as if T1 elapsed -> caller renews
    assert time.time() - start < 2
    assert keeper._renew_asap is False


def test_sigusr1_flag_services_nudge_within_a_second(lk, caplog):
    keeper = _nudge_keeper(lk)
    keeper._nudge_now = True             # what the SIGUSR1 handler sets
    with caplog.at_level("INFO", logger="lease-keeper"):
        keeper._sleep_gated(1)
    assert keeper._nudge_now is False
    assert keeper._last_nudge > 0
    # Operator-triggered nudges must be visible in the log (the README says so).
    assert any("manual ARP nudge" in r.getMessage() for r in caplog.records)


def test_sigusr2_flag_rechecks_carp_role_within_a_second(lk):
    keeper = _nudge_keeper(lk, vhid=199)
    calls = {"n": 0}

    def probe():                          # backup on the first probe, master after
        calls["n"] += 1
        return calls["n"] > 1
    keeper._probe_carp_master = probe
    keeper._poll_carp_role()              # first observation: records backup
    assert keeper._renew_asap is False
    keeper._poll_role_now = True          # what the SIGUSR2 handler sets on a CARP event
    keeper._sleep_gated(1)                # services the flag -> re-check -> transition
    assert keeper._poll_role_now is False
    assert keeper._renew_asap is True     # backup->master: renew early
    assert keeper._last_nudge > 0         # and nudge immediately


def test_nudge_missing_gateway_warns_once(lk, caplog):
    keeper = _nudge_keeper(lk)
    keeper.server = None             # enabled + bound, but no target
    with caplog.at_level("WARNING", logger="lease-keeper"):
        keeper._arp_nudge(force=True)
        keeper._arp_nudge(force=True)
    warnings = [r for r in caplog.records if "no gateway known" in r.getMessage()]
    assert len(warnings) == 1        # warned, but only once


# ---- ARP-reply listening (reachability confirmation) ----

class _ArpPkt:
    """Minimal stand-in for a scapy ARP packet: p[ARP] -> op/psrc/pdst/hwsrc, and
    haslayer(ARP) so the sniffer dispatcher routes it."""
    def __init__(self, lk, op, psrc, pdst, hwsrc=""):
        self._lk = lk
        self._arp = types.SimpleNamespace(op=op, psrc=psrc, pdst=pdst, hwsrc=hwsrc)

    def haslayer(self, layer):
        return layer is self._lk.ARP

    def __getitem__(self, layer):
        return self._arp


def test_arp_reply_stamped_by_sniffer_consumed_on_next_nudge(lk):
    keeper = _nudge_keeper(lk)
    keeper.router = "100.64.4.254"           # nudge target = router (opt 3)
    keeper._nudges_since_reply = 5           # simulate a prior unanswered streak
    assert keeper._last_arp_reply == 0.0
    # The sniffer thread only stamps the reply time -- it must NOT touch the
    # main-thread-owned counter (that is what keeps them race-free).
    keeper._on_arp_reply(_ArpPkt(lk, 2, "100.64.4.254", "100.64.4.7"))
    assert keeper._last_arp_reply > 0
    assert keeper._nudges_since_reply == 5
    # The next nudge (main thread) consumes the reply and clears the streak.
    keeper._arp_nudge(force=True)
    assert keeper._nudges_since_reply == 0


def test_arp_reply_ignores_unrelated(lk):
    keeper = _nudge_keeper(lk)
    keeper.router = "100.64.4.254"
    keeper._on_arp_reply(_ArpPkt(lk, 2, "100.64.4.9", "100.64.4.7"))    # wrong sender
    keeper._on_arp_reply(_ArpPkt(lk, 2, "100.64.4.254", "100.64.4.99"))  # wrong target IP
    keeper._on_arp_reply(_ArpPkt(lk, 1, "100.64.4.254", "100.64.4.7"))   # a request, not a reply
    assert keeper._last_arp_reply == 0.0


def test_sniff_dispatch_routes_arp_reply(lk):
    keeper = _nudge_keeper(lk)
    keeper.router = "100.64.4.254"
    keeper._on_sniff(_ArpPkt(lk, 2, "100.64.4.254", "100.64.4.7"))
    assert keeper._last_arp_reply > 0


def test_arp_reply_logged_at_debug(lk, caplog):
    keeper = _nudge_keeper(lk)
    keeper.router = "100.64.4.1"
    with caplog.at_level("DEBUG", logger="lease-keeper"):
        keeper._on_arp_reply(_ArpPkt(lk, 2, "100.64.4.1", "100.64.4.7"))
    assert any("ARP reply from 100.64.4.1" in r.getMessage() for r in caplog.records)


def test_first_reply_logged_confirmed_at_info(lk, caplog):
    keeper = _nudge_keeper(lk)
    keeper.router = "100.64.4.1"
    with caplog.at_level("INFO", logger="lease-keeper"):
        keeper._arp_nudge(force=True)                                  # sent, no reply yet
        keeper._on_arp_reply(_ArpPkt(lk, 2, "100.64.4.1", "100.64.4.7"))
        keeper._arp_nudge(force=True)                                  # consumes -> first confirmation
    assert any("ARP nudge confirmed" in r.getMessage() for r in caplog.records)


def test_reply_after_unanswered_logs_recovery_at_info(lk, caplog):
    keeper = _nudge_keeper(lk)
    keeper.router = "100.64.4.1"

    def reply():
        keeper._on_arp_reply(_ArpPkt(lk, 2, "100.64.4.1", "100.64.4.7"))

    # Establish confirmed reachability first (so the next event is a recovery, not a first).
    keeper._arp_nudge(force=True)
    reply()
    keeper._arp_nudge(force=True)
    with caplog.at_level("INFO", logger="lease-keeper"):
        for _ in range(lk.ARP_UNANSWERED_WARN):          # unanswered streak
            keeper._arp_nudge(force=True)
        reply()
        keeper._arp_nudge(force=True)                    # consume -> recovery
    assert any("answered again" in r.getMessage() for r in caplog.records)


# ---- ARP conflict detection (another MAC claiming our leased IP) ----

def test_arp_conflict_warns(lk, caplog):
    keeper = _nudge_keeper(lk)                    # yiaddr=100.64.4.7, chaddr=00:00:5e:00:01:fe
    with caplog.at_level("WARNING", logger="lease-keeper"):
        keeper._on_arp_conflict(_ArpPkt(lk, 2, "100.64.4.7", "100.64.4.1", hwsrc="aa:bb:cc:dd:ee:ff"))
    assert any("ARP conflict" in r.getMessage() for r in caplog.records)


def test_arp_conflict_ignores_our_own_mac(lk, caplog):
    keeper = _nudge_keeper(lk)
    with caplog.at_level("WARNING", logger="lease-keeper"):
        # Same as our CARP MAC (the peer node shares it) -> not a conflict.
        keeper._on_arp_conflict(_ArpPkt(lk, 1, "100.64.4.7", "100.64.4.1", hwsrc="00:00:5e:00:01:fe"))
    assert not any("ARP conflict" in r.getMessage() for r in caplog.records)


def test_arp_conflict_ignores_other_ip(lk, caplog):
    keeper = _nudge_keeper(lk)
    with caplog.at_level("WARNING", logger="lease-keeper"):
        keeper._on_arp_conflict(_ArpPkt(lk, 1, "100.64.4.99", "100.64.4.1", hwsrc="aa:bb:cc:dd:ee:ff"))
    assert not any("ARP conflict" in r.getMessage() for r in caplog.records)


def test_arp_conflict_throttled_per_mac(lk, caplog):
    keeper = _nudge_keeper(lk)
    pkt = _ArpPkt(lk, 2, "100.64.4.7", "100.64.4.1", hwsrc="aa:bb:cc:dd:ee:ff")
    with caplog.at_level("WARNING", logger="lease-keeper"):
        keeper._on_arp_conflict(pkt)
        keeper._on_arp_conflict(pkt)              # same MAC within the re-warn window
    warnings = [r for r in caplog.records if "ARP conflict" in r.getMessage()]
    assert len(warnings) == 1


def test_sniffer_filter_tracks_leased_ip(lk):
    keeper = lk.Keeper("eth0", "00:00:5e:00:01:fe", "100.64.4.7", hbfile=None)
    assert "arp[14:4]" not in keeper._sniffer_filter()   # no lease yet -> no conflict clause
    keeper.yiaddr = "100.64.4.7"
    f = keeper._sniffer_filter()
    assert "arp[6:2] = 2" in f                            # reachability clause kept
    assert "arp[14:4]" in f                               # conflict clause added for the leased IP


def test_unanswered_nudges_warn_once(lk, caplog):
    keeper = _nudge_keeper(lk)                # target = server 100.64.4.1, probe -> master
    with caplog.at_level("WARNING", logger="lease-keeper"):
        for _ in range(lk.ARP_UNANSWERED_WARN + 2):
            keeper._arp_nudge(force=True)
    warnings = [r for r in caplog.records if "unanswered" in r.getMessage()]
    assert len(warnings) == 1
    assert keeper._nudges_since_reply >= lk.ARP_UNANSWERED_WARN
    # Not in promiscuous mode -> the hint should point at enabling it.
    assert "promiscuous" in warnings[0].getMessage()


def test_unanswered_warning_omits_promisc_hint_when_already_promisc(lk, caplog):
    keeper = _nudge_keeper(lk, arp_listen_promisc=True)
    with caplog.at_level("WARNING", logger="lease-keeper"):
        for _ in range(lk.ARP_UNANSWERED_WARN):
            keeper._arp_nudge(force=True)
    warnings = [r for r in caplog.records if "unanswered" in r.getMessage()]
    assert len(warnings) == 1
    # Promisc already on -> blame the carrier, do not suggest turning promisc on.
    assert "carrier is likely dropping" in warnings[0].getMessage()


def test_reply_resets_and_rearms_unanswered_warning(lk, caplog):
    keeper = _nudge_keeper(lk)
    keeper.router = "100.64.4.1"
    with caplog.at_level("WARNING", logger="lease-keeper"):
        for _ in range(lk.ARP_UNANSWERED_WARN):
            keeper._arp_nudge(force=True)          # warns once, at the threshold
        # A reply lands (stamped by the sniffer); the next nudge consumes it and clears.
        keeper._on_arp_reply(_ArpPkt(lk, 2, "100.64.4.1", "100.64.4.7"))
        keeper._arp_nudge(force=True)
        assert keeper._nudges_since_reply == 0
        # A fresh unanswered streak warns again -- the reset re-arms it (no latch).
        for _ in range(lk.ARP_UNANSWERED_WARN):
            keeper._arp_nudge(force=True)
    warnings = [r for r in caplog.records if "unanswered" in r.getMessage()]
    assert len(warnings) == 2


def test_hb_includes_arp_reply_state(lk, tmp_path):
    hb = tmp_path / "hb"
    keeper = _nudge_keeper(lk, hbfile=str(hb))
    keeper.router = "100.64.4.1"
    keeper._last_nudge = 1783350000.0
    keeper._last_arp_reply = 1783350050.0
    keeper._hb()
    content = hb.read_text()
    assert " nudge=1783350000" in content
    assert " arpok=1783350050" in content


def test_hb_arpok_zero_when_no_reply(lk, tmp_path):
    hb = tmp_path / "hb"
    keeper = _nudge_keeper(lk, hbfile=str(hb))
    keeper._hb()
    assert " arpok=0" in hb.read_text()


def test_arp_listen_promisc_defaults_off(lk):
    keeper = lk.Keeper("eth0", "00:00:5e:00:01:fe", "100.64.4.7", hbfile=None)
    assert keeper.arp_listen_promisc is False


def test_sniffer_filter_captures_arp_and_honours_promisc(lk, monkeypatch):
    captured = {}

    class _Cap:
        def __init__(self, *a, **k):
            captured.update(k)
            self.thread = types.SimpleNamespace(is_alive=lambda: True)

        def start(self):
            pass

        def stop(self):
            pass

    monkeypatch.setattr(lk, "AsyncSniffer", _Cap)
    keeper = lk.Keeper("eth0", "00:00:5e:00:01:fe", "100.64.4.7", hbfile=None,
                       arp_listen_promisc=True)
    assert keeper._start_sniffer() is True
    assert "arp" in captured["filter"]        # ARP replies now reach the parser
    assert "port 67" in captured["filter"]     # ...alongside DHCP, unchanged
    assert captured["promisc"] is True         # opt-in flag reaches the socket
