"""Unit tests for the lease_keeper daemon's pure helpers and follow decision.

Tests reach into private state/methods by design, and use comments over
per-test docstrings."""
# pylint: disable=protected-access, missing-function-docstring
import os
import re
import time
import types

import pytest


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


def _client(lk, id_opts=None, on_changed=None):
    """A bare DhcpClient with stub hooks and a captured send list -- the
    protocol tests need no Keeper."""
    c = lk.DhcpClient("eth0", "00:00:5e:00:01:fe", "00:00:5e:00:01:fe", id_opts or [],
                      should_stop=lambda: False,
                      ensure_sniffer=lambda: None,
                      on_changed_address=on_changed or (lambda *a: False))
    c.sent = []
    c._send_dhcp = lambda mtype, extra, ciaddr="0.0.0.0": c.sent.append((mtype, extra, ciaddr))
    return c


def test_timing_derived(lk):
    c = _client(lk)
    c.binding.lease_secs = 1800
    assert c.timing() == (900, 1575, "derived")


def test_timing_honours_server(lk):
    c = _client(lk)
    c.binding.lease_secs = 1800
    c.binding.t1_server = 600
    c.binding.t2_server = 1200
    assert c.timing() == (600, 1200, "server")


def test_redora_max_bounded(lk):
    # the re-DORA backoff cap stays bounded so worst-case re-acquire lag is small.
    assert lk.REDORA_MIN <= lk.REDORA_MAX <= 60


def test_dhcpreply_giaddr_defaults_none(lk):
    # the new giaddr field defaults, so shorter DhcpReply constructions stay valid.
    rx = lk.DhcpReply(5, "1.2.3.4", "1.2.3.1", 1800, None, None, None)
    assert rx.giaddr is None


def test_reboot_request_shape_and_bind(lk):
    c = _client(lk)
    c._wait_for_dhcp_reply = lambda want, timeout: lk.DhcpReply(
        lk.ACK, "100.64.4.7", "100.64.4.1", 1800, None, None, None)
    assert c.reboot("100.64.4.7") is True
    assert c.binding.yiaddr == "100.64.4.7" and c.binding.server == "100.64.4.1"
    mtype, extra, ciaddr = c.sent[0]
    assert mtype == "request" and ciaddr == "0.0.0.0"          # INIT-REBOOT: ciaddr stays 0
    assert ("requested_addr", "100.64.4.7") in extra           # option 50 = our known address
    assert not any(o[0] == "server_id" for o in extra if isinstance(o, tuple))  # RFC 4.3.2: no server-id


def test_reboot_nak_falls_through(lk):
    c = _client(lk)
    c._wait_for_dhcp_reply = lambda want, timeout: "NAK"
    assert c.reboot("100.64.4.7") is False
    assert c.binding.yiaddr is None


def test_reboot_skipped_without_request_ip(lk):
    c = _client(lk)
    assert c.reboot(None) is False  # no known address -> nothing to reboot-request


def test_acquire_reboot_first_then_dora(lk):
    c = _client(lk)
    calls = []
    c.reboot = lambda rip: (calls.append("reboot"), False)[1]
    c.dora = lambda rip=None: (calls.append("dora"), True)[1]
    assert c.acquire("100.64.4.7") is True
    assert calls == ["reboot", "dora"]      # first acquire: INIT-REBOOT then DISCOVER fallback
    calls.clear()
    assert c.acquire("100.64.4.7") is True
    assert calls == ["dora"]   # subsequent acquires: DISCOVER only


def test_adopt_binds_and_refreshes_server(lk):
    c = _client(lk)
    c.binding.server = "100.64.4.1"   # from the OFFER
    ack = lk.DhcpReply(lk.ACK, "100.64.4.7", "100.64.4.2", 1800, None, None,
                       "100.64.4.1", None, "255.255.255.0")
    c.adopt(ack)
    assert c.binding.yiaddr == "100.64.4.7"
    assert c.binding.server == "100.64.4.2"          # ACK's server-id wins...
    assert c.binding.lease_secs == 1800 and c.binding.mask_bits == 24
    c.adopt(lk.DhcpReply(lk.ACK, "100.64.4.8", None, 900, None, None, None))
    assert c.binding.server == "100.64.4.2"          # ...and is kept when the ACK has none


def test_expire_unbinds_but_keeps_hints(lk):
    c = _client(lk)
    c.binding.yiaddr, c.binding.server, c.binding.router = "100.64.4.7", "100.64.4.1", "100.64.4.254"
    c.expire()
    assert c.binding.yiaddr is None   # unbound -> the run loop re-acquires
    assert c.binding.server == "100.64.4.1" and c.binding.router == "100.64.4.254"   # hints survive


def test_renew_requires_binding(lk):
    c = _client(lk)
    assert c.renew() is False    # unbound -> nothing to renew
    assert c.sent == []          # and nothing went on the wire


def test_feed_wakes_the_waiting_sequence(lk):
    c = _client(lk)
    rx = lk.DhcpReply(lk.ACK, "100.64.4.7", "100.64.4.1", 1800, None, None, None)
    c.feed(rx)
    assert c._rx is rx
    assert c._ev.is_set()        # the waiting _wait_for_dhcp_reply returns at once


def test_fmt_reply_readable(lk):
    off = lk.DhcpReply(2, "100.64.4.74", "100.64.4.1", 120, 60, 105, "100.64.4.1",
                       None, "255.255.255.0", None)
    s = lk._fmt_reply(off)
    assert "OFFER" in s and "yiaddr=100.64.4.74" in s and "server=100.64.4.1" in s
    assert "giaddr=none" in s          # directly attached: no relay in path
    nak = lk.DhcpReply(6, None, "100.64.4.1", None, None, None, None,
                       b"no free leases", None, "100.64.4.9")
    s2 = lk._fmt_reply(nak)
    assert "NAK" in s2 and "giaddr=100.64.4.9" in s2 and "no free leases" in s2


def _keeper(lk, **kw):
    """A Keeper on the canonical test identity (iface/vMAC/VIP), hbfile off."""
    kw.setdefault("hbfile", None)
    return lk.Keeper("eth0", "00:00:5e:00:01:fe", "100.64.4.7", **kw)


def _link_keeper(lk):
    return _keeper(lk)


def test_iface_link_up_parsing(lk, monkeypatch):
    k = _link_keeper(lk)
    monkeypatch.setattr(lk.subprocess, "check_output",
                        lambda *a, **kw: "igc1: flags=...\n\tstatus: active\n")
    assert k._iface_link_up() is True
    monkeypatch.setattr(lk.subprocess, "check_output",
                        lambda *a, **kw: "igc1: flags=...\n\tstatus: no carrier\n")
    assert k._iface_link_up() is False
    monkeypatch.setattr(lk.subprocess, "check_output",
                        lambda *a, **kw: "igc1: flags=...\n\t(no status line)\n")
    assert k._iface_link_up() is None

    def boom(*a, **kw):
        raise OSError("iface gone")
    monkeypatch.setattr(lk.subprocess, "check_output", boom)
    assert k._iface_link_up() is None


def test_check_link_returned_edge(lk):
    k = _link_keeper(lk)
    seq = []
    k._iface_link_up = lambda: seq.pop(0)
    # initial unknown -> up is NOT a trigger (we were already up)
    seq[:] = [True]
    assert k._check_link_returned() is False
    assert k._link_up is True
    # up -> up: no trigger
    seq[:] = [True]
    assert k._check_link_returned() is False
    # up -> down: recorded, no trigger
    seq[:] = [False]
    assert k._check_link_returned() is False
    assert k._link_up is False
    # down -> up: TRIGGER
    seq[:] = [True]
    assert k._check_link_returned() is True
    # unreadable carrier never disturbs state
    k._iface_link_up = lambda: None
    assert k._check_link_returned() is False


def _gate_keeper(lk, carrier):
    """Unbound keeper with a stubbed carrier probe and recorded acquire calls."""
    k = _keeper(lk)
    k._ensure_sniffer = lambda: None
    k.acquired = []
    k._dhcp.acquire = lambda rip: (k.acquired.append(rip), False)[1]
    k._iface_link_up = lambda: carrier
    k._sleep_interruptible = lambda secs: True
    return k


def test_maintain_holds_acquire_without_carrier(lk, caplog):
    k = _gate_keeper(lk, carrier=False)
    with caplog.at_level("INFO", logger="lease-keeper"):
        k._maintain_step()
        k._maintain_step()
    assert k.acquired == []                  # no DISCOVER burned on a dead link
    assert k._link_up is False
    # one INFO per down-episode, not per loop pass
    waits = [r for r in caplog.records if "no carrier" in r.getMessage()]
    assert len(waits) == 1


def test_maintain_acquire_fails_open_on_unreadable_carrier(lk):
    k = _gate_keeper(lk, carrier=None)
    k._maintain_step()
    assert k.acquired == ["100.64.4.7"]      # None never blocks the acquire


def test_maintain_acquires_with_carrier(lk):
    k = _gate_keeper(lk, carrier=True)
    k._maintain_step()
    assert k.acquired == ["100.64.4.7"]


def test_bound_marks_carrier_up(lk):
    # A completed DORA proves carrier: the last-carrier-state invariant stays
    # honest so the next down-episode always logs its hold line.
    k = _gate_keeper(lk, carrier=True)
    k._link_up = False                       # stale from an earlier down-episode
    k._dhcp.acquire = lambda rip: True
    k._maintain_step()
    assert k._link_up is True


def test_carrier_wait_resumes_via_link_return(lk, caplog):
    k = _gate_keeper(lk, carrier=False)
    k.redora_wait = 40

    def sleep_with_return(_secs):
        k._link_returned = True              # what the fast path sets on the edge
        return True
    k._sleep_interruptible = sleep_with_return
    with caplog.at_level("INFO", logger="lease-keeper"):
        k._maintain_step()
    assert any("re-acquiring now" in r.getMessage() for r in caplog.records)
    assert k.redora_wait == lk.REDORA_MIN    # backoff reset for the immediate retry


def test_check_link_returned_debounce(lk, monkeypatch):
    k = _link_keeper(lk)
    monkeypatch.setattr(lk.time, "time", lambda: 1000.0)
    k._iface_link_up = lambda: True
    k._link_up = False   # pretend we saw the link go down
    assert k._check_link_returned() is True   # first down->up fires (kick_at was 0.0)
    k._link_up = False   # another down at the same instant
    assert k._check_link_returned() is False  # debounced (now - kick_at = 0 < LINK_KICK_DEBOUNCE)


def _follow_keeper(lk, tmp_path):
    keeper = _keeper(lk, follow=True)
    keeper._follow._state_file = str(tmp_path / "follow_state")
    keeper._dhcp.binding.server = "100.64.4.1"
    keeper._dhcp.binding.yiaddr = "100.64.4.7"
    keeper.fired = []
    keeper._follow._follow_update = keeper.fired.append
    keeper._follow._hb_mismatch = lambda got, want: None
    keeper._dhcp.release = lambda *a: None
    return keeper


def _ack(lk, yiaddr, server="100.64.4.1"):
    return lk.DhcpReply(5, yiaddr, server, 1800, None, None, None)


class _DhcpPkt:
    """Minimal stand-in for a scapy DHCP reply: p[BOOTP].xid/op/yiaddr and
    p[DHCP].options, with haslayer() so _on_dhcp_reply parses it."""
    def __init__(self, lk, xid, options, *, yiaddr="100.64.4.7",  # pylint: disable=too-many-arguments
                 chaddr=b"\x00\x00\x5e\x00\x01\xfe", op=None, giaddr="0.0.0.0"):
        self._lk = lk
        self._bootp = types.SimpleNamespace(xid=xid, op=(lk.BOOTREPLY if op is None else op),
                                            yiaddr=yiaddr, chaddr=chaddr, giaddr=giaddr)
        self._dhcp = types.SimpleNamespace(options=options)

    def haslayer(self, layer):
        return layer in (self._lk.BOOTP, self._lk.DHCP)

    def __getitem__(self, layer):
        return self._bootp if layer is self._lk.BOOTP else self._dhcp


def test_parse_reply_extracts_fields_and_relay(lk):
    # The pure wire decoder pulls the acted-on options into a DhcpReply and maps
    # the relay giaddr (0.0.0.0 -> None when directly attached).
    pkt = _DhcpPkt(lk, 0x1234, [("message-type", lk.ACK), ("server_id", "100.64.4.1"),
                                ("lease_time", 1800), ("router", "100.64.4.1"),
                                ("subnet_mask", "255.255.255.0"), "end"],
                   yiaddr="100.64.4.7", giaddr="100.64.4.9")
    rx = lk._parse_reply(pkt, "100.64.4.7")
    assert rx.mtype == lk.ACK and rx.yiaddr == "100.64.4.7"
    assert rx.server_id == "100.64.4.1" and rx.lease == 1800
    assert rx.router == "100.64.4.1" and rx.subnet_mask == "255.255.255.0"
    assert rx.giaddr == "100.64.4.9"           # relay in path
    directly_attached = _DhcpPkt(lk, 0x1234, [("message-type", lk.ACK), "end"], giaddr="0.0.0.0")
    assert lk._parse_reply(directly_attached, "100.64.4.7").giaddr is None


def test_on_dhcp_reply_captures_option56_message(lk):
    keeper = _keeper(lk)
    pkt = _DhcpPkt(lk, keeper._dhcp.xid, [("message-type", lk.NAK), ("server_id", "100.64.4.1"),
                                          ("message", "pool exhausted"), "end"])
    keeper._on_dhcp_reply(pkt)
    assert keeper._dhcp._rx.message == "pool exhausted"


@pytest.mark.parametrize("message, expect", [
    ("lease not available", "lease not available"),   # option-56 text surfaced
    (b"bad chaddr", "bad chaddr"),   # a bytes reason is decoded
    (None, "DHCPNAK received"),   # no reason -> the NAK is still logged
])
def test_dhcpnak_logs_reason(lk, caplog, message, expect):
    keeper = _keeper(lk)
    keeper._dhcp._rx = lk.DhcpReply(lk.NAK, None, "100.64.4.1", None, None, None, None, message)
    with caplog.at_level("WARNING", logger="lease-keeper"):
        assert keeper._dhcp._wait_for_dhcp_reply(lk.ACK, 0.2) == "NAK"
    assert any(expect in r.getMessage() for r in caplog.records)


def test_follow_accepts_same_class(lk, tmp_path):
    keeper = _follow_keeper(lk, tmp_path)
    assert keeper._follow.on_changed_address("100.64.4.60", _ack(lk, "100.64.4.60"), "DORA", True) is True
    assert keeper.fired == ["100.64.4.60"]
    assert keeper._follow.target == "100.64.4.60"


def test_follow_rejects_wrong_server(lk, tmp_path):
    keeper = _follow_keeper(lk, tmp_path)
    reply = _ack(lk, "100.64.4.60", server="100.64.4.9")
    assert keeper._follow.on_changed_address("100.64.4.60", reply, "DORA", True) is False
    assert keeper.fired == []


def test_follow_rejects_cross_class(lk, tmp_path):
    keeper = _follow_keeper(lk, tmp_path)
    assert keeper._follow.on_changed_address("8.8.8.8", _ack(lk, "8.8.8.8"), "DORA", True) is False
    assert keeper.fired == []


def test_follow_throttled_within_interval(lk, tmp_path):
    keeper = _follow_keeper(lk, tmp_path)
    assert keeper._follow.on_changed_address("100.64.4.60", _ack(lk, "100.64.4.60"), "DORA", True) is True
    # A second follow inside MIN_FOLLOW_INTERVAL is deferred.
    assert keeper._follow.on_changed_address("100.64.4.61", _ack(lk, "100.64.4.61"), "DORA", True) is False


def test_enforce_mismatch_refused(lk):
    keeper = _keeper(lk, follow=False)
    keeper._dhcp.binding.server = "100.64.4.1"
    keeper._dhcp.binding.yiaddr = "100.64.4.7"
    released = []
    keeper._dhcp.release = lambda *a: released.append(a)
    assert keeper._follow.on_changed_address("100.64.4.60", _ack(lk, "100.64.4.60"), "DORA", True) is False
    assert released == [("100.64.4.60", "100.64.4.1")]  # the refused grant is released...
    assert keeper._dhcp.binding.yiaddr is None   # ...and not held (run loop re-acquires)


# ---- observed peer ACK: converge follow from the peer's exchange (single-ip s.3) ----

def _observe_keeper(lk, tmp_path):
    # Same fixture as _follow_keeper (server / yiaddr / _state_file / fired +
    # _follow_update stubs), plus a known in-flight xid so a peer ACK (different
    # xid) takes the observed path.
    keeper = _follow_keeper(lk, tmp_path)
    keeper._dhcp.xid = 0x11111111
    return keeper


def _peer_ack(lk, yiaddr, xid=0x22222222, server="100.64.4.1",
              chaddr=b"\x00\x00\x5e\x00\x01\xfe"):
    """A DHCP ACK on our shared chaddr but a DIFFERENT xid -- i.e. the peer's."""
    return _DhcpPkt(lk, xid, [("message-type", lk.ACK), ("server_id", server),
                              ("lease_time", 1800), "end"], yiaddr=yiaddr, chaddr=chaddr)


def test_observed_peer_ack_records_change_and_wakes(lk, tmp_path):
    keeper = _observe_keeper(lk, tmp_path)
    assert not keeper._wake.is_set()
    keeper._on_dhcp_reply(_peer_ack(lk, "100.64.4.60"))
    assert keeper._follow._observed is not None
    assert keeper._follow._observed.yiaddr == "100.64.4.60"
    assert keeper._dhcp._rx is None          # the first-party slot is untouched
    assert keeper._wake.is_set()       # ...and the maintain-loop sleep is woken at once


def test_ignored_observation_does_not_wake(lk, tmp_path):
    keeper = _observe_keeper(lk, tmp_path)
    keeper._on_dhcp_reply(_peer_ack(lk, "100.64.4.7"))     # same address -> no change
    assert keeper._follow._observed is None
    assert not keeper._wake.is_set()


def test_observed_ignores_wrong_chaddr(lk, tmp_path):
    keeper = _observe_keeper(lk, tmp_path)
    keeper._on_dhcp_reply(_peer_ack(lk, "100.64.4.60", chaddr=b"\xaa\xbb\xcc\xdd\xee\xff"))
    assert keeper._follow._observed is None


def test_observed_ignores_non_ack(lk, tmp_path):
    keeper = _observe_keeper(lk, tmp_path)
    keeper._on_dhcp_reply(_DhcpPkt(lk, 0x22222222,
                                   [("message-type", lk.OFFER), ("server_id", "100.64.4.1"), "end"],
                                   yiaddr="100.64.4.60"))
    assert keeper._follow._observed is None


def test_observed_ignored_when_not_follow(lk):
    keeper = _keeper(lk, follow=False)
    keeper._dhcp.binding.server = "100.64.4.1"
    keeper._dhcp.binding.yiaddr = "100.64.4.7"
    keeper._dhcp.xid = 0x11111111
    keeper._on_dhcp_reply(_peer_ack(lk, "100.64.4.60"))
    assert keeper._follow._observed is None


def test_own_xid_reply_uses_first_party_path(lk, tmp_path):
    keeper = _observe_keeper(lk, tmp_path)
    keeper._on_dhcp_reply(_DhcpPkt(lk, keeper._dhcp.xid,
                                   [("message-type", lk.ACK), ("server_id", "100.64.4.1"), "end"],
                                   yiaddr="100.64.4.60"))
    assert keeper._follow._observed is None   # not the observed path
    assert keeper._dhcp._rx is not None and keeper._dhcp._rx.yiaddr == "100.64.4.60"


def test_observed_latest_wins(lk, tmp_path):
    # Two peer ACKs in quick succession (the sniffer overwrites _observed):
    # the handler acts on the LATEST address -- the older one is superseded (the
    # shared lease is now the newer address), so dropping it is correct.
    keeper = _observe_keeper(lk, tmp_path)
    keeper._on_dhcp_reply(_peer_ack(lk, "100.64.4.60"))
    keeper._on_dhcp_reply(_peer_ack(lk, "100.64.4.61"))
    assert keeper._follow._observed.yiaddr == "100.64.4.61"
    keeper._follow.check_observed()
    assert keeper.fired == ["100.64.4.61"]
    assert keeper._follow._observed is None


def test_observed_same_address_after_follow_is_dropped(lk, tmp_path):
    # After we've followed to the new address, a lingering observation for that
    # same address is a no-op (the == binding.yiaddr guard), never a double-follow.
    keeper = _observe_keeper(lk, tmp_path)
    keeper._dhcp.binding.yiaddr = "100.64.4.61"   # we already hold the new address
    keeper._follow._observed = _ack(lk, "100.64.4.61")
    keeper._follow.check_observed()
    assert keeper.fired == []   # no redundant follow
    assert keeper._follow._observed is None


def test_check_observed_drives_hardened_follow(lk, tmp_path):
    keeper = _observe_keeper(lk, tmp_path)
    keeper._follow._observed = _ack(lk, "100.64.4.60")
    keeper._follow.check_observed()
    assert keeper.fired == ["100.64.4.60"]
    assert keeper._follow.target == "100.64.4.60"
    assert keeper._follow._observed is None


def test_check_observed_rejects_wrong_server(lk, tmp_path):
    keeper = _observe_keeper(lk, tmp_path)
    keeper._follow._observed = _ack(lk, "100.64.4.60", server="100.64.4.9")  # not our server
    keeper._follow.check_observed()
    assert keeper.fired == []          # same hardening as a first-party ACK


def test_observed_serviced_by_maintain_loop(lk, tmp_path):
    keeper = _observe_keeper(lk, tmp_path)
    keeper._follow._observed = _ack(lk, "100.64.4.60")
    keeper._wake.set()   # as the sniffer would -> loop returns at once
    keeper._sleep_interruptible(1)
    assert keeper.fired == ["100.64.4.60"]


def test_id_opts_empty_by_default(lk):
    keeper = _keeper(lk)
    assert keeper._dhcp._id_opts == []


def test_id_opts_built_from_args(lk):
    keeper = _keeper(lk, vendor_class="MSFT 5.0", client_id="keeper-1", hostname="vip")
    assert ("vendor_class_id", "MSFT 5.0") in keeper._dhcp._id_opts
    assert ("client_id", b"keeper-1") in keeper._dhcp._id_opts
    assert ("hostname", "vip") in keeper._dhcp._id_opts


def _nudge_keeper(lk, arp_nudge=240, hbfile=None, **kwargs):
    keeper = _keeper(lk, hbfile=hbfile, arp_nudge=arp_nudge, **kwargs)
    keeper._dhcp.binding.yiaddr = "100.64.4.7"
    keeper._dhcp.binding.server = "100.64.4.1"
    keeper._probe_carp_master = lambda: True   # the real probe needs ifconfig
    return keeper


def test_arp_nudge_component_direct(lk):
    # ArpNudge alone (no Keeper): interval floor at construction, the injected
    # master probe gates every send, and the reachability stamp starts at 0.
    role = {"master": True}
    n = lk.ArpNudge("eth0", "00:00:5e:00:01:fe", 1, lambda: role["master"])
    assert n.interval == lk.ARP_NUDGE_MIN     # floored: a typo cannot flood the segment
    assert n.last_reply == 0.0

    n.maybe_nudge("100.64.4.7", "100.64.4.1")
    first = n.last_nudge
    assert first > 0   # master + due -> sent

    role["master"] = False
    n.maybe_nudge("100.64.4.7", "100.64.4.1", force=True)
    assert n.last_nudge == first   # backup: never nudge, even forced


def test_nudge_off_by_default(lk):
    keeper = _keeper(lk)
    assert keeper._nudge.interval == 0
    keeper._arp_nudge(force=True)   # must be a no-op, not an error
    assert keeper._nudge.last_nudge == 0.0


def test_nudge_interval_floor(lk):
    keeper = _keeper(lk, arp_nudge=1)
    assert keeper._nudge.interval == lk.ARP_NUDGE_MIN


def test_nudge_respects_interval_and_force(lk):
    keeper = _nudge_keeper(lk)
    keeper._arp_nudge()
    first = keeper._nudge.last_nudge
    assert first > 0
    keeper._arp_nudge()   # within the interval -> skipped
    assert keeper._nudge.last_nudge == first
    keeper._arp_nudge(force=True)   # forced (BOUND/RENEW/REBIND) -> sent
    assert keeper._nudge.last_nudge > first


def test_nudge_requires_gateway_and_lease(lk):
    keeper = _nudge_keeper(lk)
    keeper._dhcp.binding.server = None   # no router option and no server_id -> no target
    keeper._arp_nudge(force=True)
    assert keeper._nudge.last_nudge == 0.0
    keeper._dhcp.binding.server = "100.64.4.1"
    keeper._dhcp.binding.yiaddr = None   # not bound -> no source address
    keeper._arp_nudge(force=True)
    assert keeper._nudge.last_nudge == 0.0


def test_nudge_works_from_router_option_alone(lk):
    keeper = _nudge_keeper(lk)
    keeper._dhcp.binding.server = None
    keeper._dhcp.binding.router = "100.64.4.254"   # DHCP option 3 alone is a valid target
    keeper._arp_nudge(force=True)
    assert keeper._nudge.last_nudge > 0


def test_nudge_gated_to_carp_master(lk):
    keeper = _nudge_keeper(lk, vhid=199)
    keeper._probe_carp_master = lambda: False
    keeper._arp_nudge(force=True)
    assert keeper._nudge.last_nudge == 0.0   # never nudge from a CARP backup


def test_probe_carp_master_true_without_vhid(lk):
    keeper = _keeper(lk)
    assert keeper._probe_carp_master() is True


def test_probe_failure_skips_nudge(lk, monkeypatch):
    # A failed probe reports None, and the nudge fails closed on anything but
    # a confirmed MASTER.
    keeper = _keeper(lk, vhid=199, arp_nudge=240)
    keeper._dhcp.binding.yiaddr = "100.64.4.7"
    keeper._dhcp.binding.server = "100.64.4.1"

    def boom(*a, **k):
        raise OSError("ifconfig unavailable")
    monkeypatch.setattr(lk.subprocess, "check_output", boom)
    assert keeper._probe_carp_master() is None
    keeper._arp_nudge(force=True)
    assert keeper._nudge.last_nudge == 0.0


def test_hb_nudge_tokens_present(lk, tmp_path):
    hb = tmp_path / "hb"
    keeper = _nudge_keeper(lk, hbfile=str(hb))
    keeper._dhcp.binding.router = "100.64.4.1"
    keeper._nudge.last_nudge = 1783350000.0
    keeper._nudge.last_reply = 1783350050.0
    keeper._hb()
    content = hb.read_text()
    assert " nudge=1783350000" in content
    assert " arpok=1783350050" in content
    assert " gw=100.64.4.1" in content


def test_hb_nudge_zeros_when_never_and_no_target(lk, tmp_path):
    hb = tmp_path / "hb"
    keeper = _nudge_keeper(lk, hbfile=str(hb))
    keeper._dhcp.binding.server = None   # enabled, but no target and nothing sent yet
    keeper._hb()
    content = hb.read_text()
    assert " nudge=0" in content
    assert " arpok=0" in content
    assert "gw=" not in content


def test_hb_no_nudge_tokens_when_off(lk, tmp_path):
    hb = tmp_path / "hb"
    keeper = _nudge_keeper(lk, arp_nudge=0, hbfile=str(hb))
    keeper._hb()
    content = hb.read_text()
    assert "nudge=" not in content
    assert "arpok=" not in content


def test_master_transition_renews_early_and_nudges(lk):
    keeper = _nudge_keeper(lk, vhid=199)
    states = iter([True, False, True, True, True])
    keeper._probe_carp_master = lambda: next(states)
    keeper._poll_carp_role()   # master from the start -> no transition
    assert keeper._renew_asap is False
    assert keeper._nudge.last_nudge == 0.0
    keeper._poll_carp_role()   # backup -> remembers the role
    keeper._poll_carp_role()   # backup -> master (the forced nudge probes again)
    assert keeper._renew_asap is True
    first = keeper._nudge.last_nudge
    assert first > 0
    keeper._poll_carp_role()   # still master -> nothing new
    assert keeper._nudge.last_nudge == first


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
    assert keeper._nudge.last_nudge == 0.0     # but no nudge was sent


def test_hold_returns_early_for_asap_renew(lk):
    keeper = _nudge_keeper(lk)
    keeper._renew_asap = True
    start = time.time()
    assert keeper._hold_lease(60) is True   # returns as if T1 elapsed -> caller renews
    assert time.time() - start < 2
    assert keeper._renew_asap is False


def test_sigusr1_flag_services_nudge_within_a_second(lk, caplog):
    keeper = _nudge_keeper(lk)
    keeper._nudge_now = True   # what the SIGUSR1 handler sets
    with caplog.at_level("INFO", logger="lease-keeper"):
        keeper._sleep_interruptible(1)
    assert keeper._nudge_now is False
    assert keeper._nudge.last_nudge > 0
    # Operator-triggered nudges must be visible in the log (the README says so).
    assert any("manual ARP nudge" in r.getMessage() for r in caplog.records)


def test_sigusr2_flag_rechecks_carp_role_within_a_second(lk):
    keeper = _nudge_keeper(lk, vhid=199)
    calls = {"n": 0}

    def probe():   # backup on the first probe, master after
        calls["n"] += 1
        return calls["n"] > 1
    keeper._probe_carp_master = probe
    keeper._poll_carp_role()   # first observation: records backup
    assert keeper._renew_asap is False
    keeper._poll_role_now = True          # what the SIGUSR2 handler sets on a CARP event
    keeper._sleep_interruptible(1)   # services the flag -> re-check -> transition
    assert keeper._poll_role_now is False
    assert keeper._renew_asap is True     # backup->master: renew early
    assert keeper._nudge.last_nudge > 0         # and nudge immediately


def test_nudge_missing_gateway_warns_once(lk, caplog):
    keeper = _nudge_keeper(lk)
    keeper._dhcp.binding.server = None   # enabled + bound, but no target
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


def test_arp_reply_ignores_unrelated(lk):
    keeper = _nudge_keeper(lk)
    keeper._dhcp.binding.router = "100.64.4.254"
    keeper._on_sniff(_ArpPkt(lk, 2, "100.64.4.9", "100.64.4.7"))    # wrong sender
    keeper._on_sniff(_ArpPkt(lk, 2, "100.64.4.254", "100.64.4.99"))  # wrong target IP
    keeper._on_sniff(_ArpPkt(lk, 1, "100.64.4.254", "100.64.4.7"))   # a request, not a reply
    assert keeper._nudge.last_reply == 0.0


def test_arp_reply_stamps_reachability_and_logs(lk, caplog):
    # A matching is-at reply from the nudge target, dispatched through the
    # sniffer path, stamps the reachability epoch and logs at DEBUG.
    keeper = _nudge_keeper(lk)
    keeper._dhcp.binding.router = "100.64.4.1"
    with caplog.at_level("DEBUG", logger="lease-keeper"):
        keeper._on_sniff(_ArpPkt(lk, 2, "100.64.4.1", "100.64.4.7"))
    assert keeper._nudge.last_reply > 0
    assert any("ARP reply from 100.64.4.1" in r.getMessage() for r in caplog.records)


def test_sniffer_filter_is_static(lk):
    # A fixed BPF boundary: DHCP + ARP replies (nudge reachability), no lease dependence.
    assert "port 67 or port 68" in lk.SNIFFER_FILTER      # DHCP clause
    assert "arp[6:2] = 2" in lk.SNIFFER_FILTER   # reachability clause


def test_sniffer_filter_captures_arp_and_honours_promisc(lk, monkeypatch):
    captured = {}

    class _Cap:
        def __init__(self, *_a, **k):
            captured.update(k)
            self.thread = types.SimpleNamespace(is_alive=lambda: True)

        def start(self):
            pass

        def stop(self):
            pass

    monkeypatch.setattr(lk, "AsyncSniffer", _Cap)
    keeper = _keeper(lk, arp_listen_promisc=True)
    assert keeper._start_sniffer() is True
    assert "arp" in captured["filter"]        # ARP replies now reach the parser
    assert "port 67" in captured["filter"]     # ...alongside DHCP, unchanged
    assert captured["promisc"] is True         # opt-in flag reaches the socket


# ---- follow across a changed gateway (cross-subnet renumber) ----

def _ack_gw(lk, yiaddr, router, server="100.64.4.1", mask=None):
    return lk.DhcpReply(5, yiaddr, server, 1800, None, None, router, None, mask)


def test_follow_across_subnet_with_mask(lk, tmp_path, caplog):
    keeper = _follow_keeper(lk, tmp_path)
    keeper._dhcp.binding.router = "100.64.4.1"
    with caplog.at_level("WARNING", logger="lease-keeper"):
        assert keeper._follow.on_changed_address(
            "100.64.5.60", _ack_gw(lk, "100.64.5.60", "100.64.5.1", mask="255.255.255.0"),
            "DORA", True) is True
    # gateway + prefix are handed to follow_update so outbound follows the new subnet
    assert keeper._follow._gw_args == ["100.64.4.1", "100.64.5.1", "24"]
    assert any("following across the subnet" in r.getMessage() for r in caplog.records)


def test_follow_gateway_change_without_mask_warns(lk, tmp_path, caplog):
    keeper = _follow_keeper(lk, tmp_path)
    keeper._dhcp.binding.router = "100.64.4.1"
    with caplog.at_level("ERROR", logger="lease-keeper"):   # no mask in the ACK
        keeper._follow.on_changed_address(
            "100.64.5.60", _ack_gw(lk, "100.64.5.60", "100.64.5.1"), "DORA", True)
    # without a mask we can't set the prefix: address-only follow + a fix-by-hand warning
    assert keeper._follow._gw_args == []
    assert any("carried no subnet mask" in r.getMessage() for r in caplog.records)


def test_follow_no_gateway_change_no_extra_args(lk, tmp_path):
    keeper = _follow_keeper(lk, tmp_path)
    keeper._dhcp.binding.router = "100.64.4.1"
    keeper._follow.on_changed_address(          # same gateway -> no cross-subnet extras
        "100.64.4.60", _ack_gw(lk, "100.64.4.60", "100.64.4.1"), "DORA", True)
    assert keeper._follow._gw_args == []


def test_follow_update_fires_newwanip_hooks():
    """A follow must run the newwanip plugin hooks for the VIP's interface
    (dynamic DNS, VPN endpoints learn the new address -- the parity promise),
    and must NOT invoke rc.newwanip, which would re-run interface_configure
    and disturb a dhcp-configured WAN's native lease."""
    php = os.path.join(
        os.path.dirname(__file__), "..", "src", "opnsense", "scripts",
        "OPNsense", "CarpVipDhcp", "follow_update.php")
    with open(php, encoding="utf-8") as fh:
        src = fh.read()
    assert "plugins_configure('newwanip'" in src
    code = re.sub(r"/\*.*?\*/|//[^\n]*", "", src, flags=re.S)   # comments may discuss it
    assert "rc.newwanip" not in code


def test_follow_update_action_arity():
    """The configd [follow_update] action must accept as many params as the
    daemon can send: _fire_follow_update passes old_ip + new_ip plus
    _gw_args ([old_gw, new_gw, bits] on a cross-subnet move) = 5. configd
    raises "Parameter mismatch" when more args than %s tokens are passed, so a
    narrower template would silently break every cross-subnet follow via
    configctl (a boundary the direct-call tests above never cross)."""
    conf = os.path.join(
        os.path.dirname(__file__), "..", "src", "opnsense", "service",
        "conf", "actions.d", "actions_carpvipdhcp.conf")
    params = None
    in_section = False
    with open(conf, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if line.startswith("[") and line.endswith("]"):
                in_section = line == "[follow_update]"
            elif in_section and line.startswith("parameters:"):
                params = line.split(":", 1)[1]
                break
    assert params is not None, "[follow_update] action or its parameters line is missing"
    assert params.count("%s") >= 5, "follow_update template narrower than the daemon's 5-arg call"


# ---- RFC 2131/2132 compliance ----

def test_dhcp_options_include_param_req_list(lk):
    # Every DISCOVER/REQUEST must carry the Parameter Request List (RFC 2132 §9.8)
    # so the server returns the subnet mask (1) + router (3) follow-mode needs.
    opts = lk._dhcp_options("discover", [("requested_addr", "100.64.4.7")], [])
    assert opts[0] == ("message-type", "discover")
    assert ("param_req_list", lk.PARAM_REQ_LIST) in opts
    assert 1 in lk.PARAM_REQ_LIST and 3 in lk.PARAM_REQ_LIST
    assert ("requested_addr", "100.64.4.7") in opts
    assert opts[-1] == "end"


def test_absorb_reply_captures_gw_and_mask(lk):
    # The PRL asks for opt 3 (router) + opt 1 (mask); _absorb_reply keeps both so
    # the BOUND log can surface them (and follow mode can use the mask).
    c = _client(lk)
    rx = lk.DhcpReply(lk.ACK, "100.64.4.7", "100.64.4.1", 1800, None, None,
                      "100.64.4.1", None, "255.255.255.0")
    c._absorb_reply(rx, lk.DEFAULT_LEASE)
    assert c.binding.router == "100.64.4.1"
    assert c.binding.mask_bits == 24


def test_renew_omits_server_id_and_requested_addr(lk):
    # RFC 2131 §4.3.2: a RENEWING/REBINDING REQUEST MUST NOT carry server_id or
    # requested_addr, and ciaddr MUST be the client's address.
    c = _client(lk)
    c.binding.server, c.binding.yiaddr, c.binding.lease_secs = "100.64.4.1", "100.64.4.7", 1800
    c._wait_for_dhcp_reply = lambda want, timeout: lk.DhcpReply(
        lk.ACK, c.binding.yiaddr, c.binding.server, 1800, None, None, None)
    assert c.renew() is True   # RENEW (T1)
    assert c.renew(rebind=True) is True  # REBIND (T2)
    assert c.sent, "renew sent nothing"
    for mtype, extra, ciaddr in c.sent:
        assert mtype == "request"
        assert ciaddr == "100.64.4.7"          # ciaddr MUST be the client's address
        # assert on the ACTUAL assembled option list, not the stubbed extras
        # (which are always empty here) -- so a regression that re-added
        # server_id to renew's opts would fail this.
        wire = [o for o in lk._dhcp_options(mtype, extra, c._id_opts) if isinstance(o, tuple)]
        assert all(o[0] != "server_id" for o in wire)
        assert all(o[0] != "requested_addr" for o in wire)


def test_backoff_jitter(lk):
    # RFC 2131 §4.1 randomized backoff: the jittered delay stays within +/-25% of
    # the base and is not constant, so two shared-chaddr nodes de-synchronize.
    vals = [lk._jittered(8) for _ in range(200)]
    assert all(6.0 <= v <= 10.0 for v in vals)   # 8 * [0.75, 1.25]
    assert len(set(vals)) > 1
