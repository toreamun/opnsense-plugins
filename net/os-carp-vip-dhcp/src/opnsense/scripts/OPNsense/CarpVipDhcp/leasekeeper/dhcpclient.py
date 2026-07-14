"""The held lease (Lease) and the RFC 2131 client (DORA / INIT-REBOOT / renew /
rebind / release) with its send/await machinery. Owns the binding but not the
packet capture: sends go through the injected capture backend and xid-matched
replies arrive via feed().
"""
import logging
import threading
import time
from dataclasses import dataclass

from .constants import (
    LOGGER_NAME,
    ACK, ATTEMPT_BACKOFF_CAP, BROADCAST_FLAG, DEFAULT_LEASE, DORA_ATTEMPTS,
    IPV4_BROADCAST, MIN_LEASE, MIN_T1, NAK, OFFER, Phase, REBIND_MARGIN,
    REBOOT_ATTEMPTS, RENEW_ATTEMPTS,
    RENEW_TIMEOUT, REPLY_TIMEOUT, SEND_RETRY_DELAY, T1_FACTOR, T2_FACTOR)
from .util import _jittered, _mask_to_bits, _new_xid, mac2raw
from .wire import DhcpReply, DhcpSend, _dhcp_options, _fmt_reply, _msg_text

LOG = logging.getLogger(LOGGER_NAME)

# Daemon log-and-continue posture: broad catch-alls are deliberate (see the
# package docstring / module docstrings).
# pylint: disable=broad-exception-caught


@dataclass
class Lease:
    """The held DHCP binding: address, granting server, timing, and the
    routing facts (options 3/1) the Parameter Request List asks for. During
    a DORA it briefly holds the unconfirmed OFFER candidate; otherwise it is
    the held (or last-held) binding. yiaddr None = unbound; expire() clears
    only yiaddr, so the other fields survive as hints (logging, the
    ARP-nudge target) until the next bind."""
    yiaddr: str | None = None
    server: str | None = None
    lease_secs: int = DEFAULT_LEASE
    t1_server: int | None = None   # server-provided renewal time (DHCP opt 58)
    t2_server: int | None = None   # server-provided rebinding time (DHCP opt 59)
    router: str | None = None      # default gateway (DHCP opt 3, fallback: server)
    mask_bits: int | None = None   # subnet prefix length from opt 1


class DhcpClient:  # pylint: disable=too-many-instance-attributes
    """RFC 2131 client for one chaddr: owns the held binding (a Lease)
    and the stateful protocol sequences
    (INIT-REBOOT / DORA / RENEW / REBIND / RELEASE) with their send/await
    machinery. It does NOT own the packet capture: sends travel through the
    injected capture backend, and the capture owner hands xid-matched replies
    to feed(). Policy stays with the caller through three
    injected hooks: should_stop (abort mid-sequence), ensure_sniffer (capture
    must be alive before a send), and on_changed_address(got, rx, phase,
    release_on_enforce) -> bool for an ACK whose address differs from the
    expected one (True = the caller validated and adopted it, see adopt())."""

    def __init__(self, capture, chaddr, eth_src, id_opts, *,  # pylint: disable=too-many-arguments
                 should_stop, ensure_sniffer, on_changed_address):
        self._capture = capture
        self.chaddr = chaddr
        self.chraw = mac2raw(chaddr)
        self.eth_src = eth_src

        # Optional DHCP request options (empty -> not sent); added to every
        # DISCOVER/REQUEST/RENEW so the server sees a consistent client identity.
        self._id_opts = id_opts
        self._should_stop = should_stop
        self._ensure_sniffer = ensure_sniffer
        self._on_changed = on_changed_address

        self.xid = _new_xid()
        self.binding = Lease()         # the held (or last-held) DHCP binding
        self._tried_reboot = False     # the first acquire tries INIT-REBOOT before a full DISCOVER

        self._rx = None                # latest DhcpReply snapshot (set via feed(), sniffer thread)
        self._ev = threading.Event()

    def feed(self, rx):
        """Hand a first-party (xid-matched) DhcpReply to the waiting sequence.
        Called on the sniffer thread; a lone ref-assign plus the event set."""
        self._rx = rx
        LOG.debug("DHCP reply: %s", _fmt_reply(rx))
        self._ev.set()

    def _send_dhcp(self, mtype, extra, ciaddr="0.0.0.0"):
        # ciaddr is set for RENEW/REBIND (the client already owns the address);
        # the broadcast flag stays on so the reply is reliably captured by the sniffer.
        self._capture.send_dhcp(DhcpSend(
            eth_src=self.eth_src, ip_src=ciaddr, ip_dst=IPV4_BROADCAST,
            chaddr=self.chraw, xid=self.xid, ciaddr=ciaddr, flags=BROADCAST_FLAG,
            options=_dhcp_options(mtype, extra, self._id_opts)))

    def _wait_for_dhcp_reply(self, want, timeout) -> DhcpReply | None:
        """Wait up to timeout for a reply of message-type `want`. Returns the
        DhcpReply on a match OR on a DHCPNAK (the caller checks rx.mtype == NAK
        to tell them apart -- a NAK ends the attempt, a match proceeds), or None
        on timeout. Returning the snapshot avoids re-reading self._rx (set by the
        sniffer thread) after the wait."""
        end = time.time() + timeout
        while time.time() < end and not self._should_stop():
            self._ev.clear()
            self._ev.wait(min(1.0, max(0.05, end - time.time())))

            rx = self._rx
            if rx and rx.mtype == want:
                return rx
            if rx and rx.mtype == NAK:
                # Surface the server's option-56 text (why it refused) if present;
                # it is the operator's main clue for a rejected renew.
                txt = _msg_text(rx.message)
                reason = f" -- {txt}" if txt else ""
                LOG.warning("DHCPNAK received (server %s, xid 0x%08x%s)%s",
                            rx.server_id or "unknown", self.xid,
                            f" via relay {rx.giaddr}" if rx.giaddr else "", reason)
                return rx
        return None

    def _absorb_reply(self, rx, default_lease):
        """Adopt lease timing, gateway (opt 3) and subnet mask (opt 1) from an ACK
        -- the one place that knows which DhcpReply fields carry lease state.
        gateway + mask are what the Parameter Request List asks for; keep them for
        logging + the cross-subnet follow decision. The lease time is floored at
        MIN_LEASE so a server (or a spoofed ACK) offering a 1-second lease cannot
        drive the renew loop into a tight broadcast/CPU spin."""
        self.binding.lease_secs = max(rx.lease or default_lease, MIN_LEASE)
        self.binding.t1_server, self.binding.t2_server = rx.t1, rx.t2
        self.binding.router = rx.router or self.binding.router
        self.binding.mask_bits = _mask_to_bits(rx.subnet_mask) or self.binding.mask_bits

    def adopt(self, rx):
        """Bind to the address in rx: the ACK that completes a DORA, or a
        validated changed address the caller's follow policy accepted (the
        on_changed_address hook calls this, so the lease state stays owned here
        while the decision stays with the caller). The server refreshes from
        the ACK's server-id, keeping the previous one when the ACK has none."""
        self.binding.yiaddr = rx.yiaddr
        self.binding.server = rx.server_id or self.binding.server
        self._absorb_reply(rx, DEFAULT_LEASE)

    def expire(self):
        """Forget the held binding WITHOUT a RELEASE (on-time lease expiry, or a
        grant the policy refused to keep): yiaddr clears so the next cycle
        re-acquires via DISCOVER; server/router stay as hints for logging and
        the caller's nudge target."""
        self.binding.yiaddr = None

    def acquire(self, request_ip):
        """Get a lease. The first acquire after (re)start tries INIT-REBOOT (a
        direct REQUEST for our known address) before a full DISCOVER; after that,
        the normal DORA. INIT-REBOOT is one exchange and surfaces a NAK when the
        server is reachable but refuses the address.

        Startup-only (the `_tried_reboot` latch): a genuine on-time lease expiry
        re-acquires via DISCOVER (RFC 2131 4.4.5), NOT INIT-REBOOT. We do not track
        lease expiry across a restart -- the server arbitrates the requested address
        (ACK if still ours, NAK/silence -> fall back to DISCOVER)."""
        if not self._tried_reboot:
            self._tried_reboot = True
            if request_ip:
                if self.reboot(request_ip):
                    return True
                LOG.info("INIT-REBOOT did not bind %s -- falling back to DISCOVER", request_ip)

        return self.dora(request_ip)

    def dora(self, request_ip=None):
        """Acquire a lease via the DHCP DORA handshake: the SELECTING phase
        (DISCOVER until an OFFER arrives) then the REQUESTING phase (REQUEST
        the offer until the ACK lands). Returns True once BOUND, False on
        failure/NAK."""
        self.xid = _new_xid()
        return self._discover(request_ip) and self._request_offer(request_ip)

    def _discover(self, request_ip):
        """SELECTING: broadcast DISCOVER until a server OFFERs; record the
        offered address and server. False on NAK/timeout/stop."""
        extra = [("requested_addr", request_ip)] if request_ip else []
        for attempt in range(1, DORA_ATTEMPTS + 1):
            if self._should_stop():
                return False
            self._ensure_sniffer()
            self._rx = None
            try:
                self._send_dhcp("discover", extra)
            except Exception as e:
                LOG.error("DHCP DISCOVER send failed: %s", e)
                time.sleep(SEND_RETRY_DELAY)
                continue
            rx = self._wait_for_dhcp_reply(OFFER, REPLY_TIMEOUT)
            if rx and rx.mtype == NAK:
                return False
            if rx:
                self.binding.yiaddr, self.binding.server = rx.yiaddr, rx.server_id
                return True
            # xid included so the exchange can be matched against a packet capture.
            LOG.info("no DHCP OFFER (attempt %d, xid 0x%08x)", attempt, self.xid)
            time.sleep(min(_jittered(2 ** attempt), ATTEMPT_BACKOFF_CAP))
        return False

    def _request_offer(self, request_ip):
        """REQUESTING: REQUEST the offered address until the ACK lands and we
        are BOUND. False on NAK/timeout/stop; an ACK for a different address
        goes through the on_changed_address policy hook."""
        for attempt in range(1, DORA_ATTEMPTS + 1):
            if self._should_stop():
                return False
            self._ensure_sniffer()   # an interface flap between OFFER and here would leave us deaf
            self._rx = None
            try:
                self._send_dhcp(
                    "request",
                    [("server_id", self.binding.server), ("requested_addr", self.binding.yiaddr)],
                )
            except Exception as e:
                LOG.error("DHCP REQUEST send failed: %s", e)
                time.sleep(SEND_RETRY_DELAY)
                continue
            rx = self._wait_for_dhcp_reply(ACK, REPLY_TIMEOUT)
            if rx and rx.mtype == NAK:
                return False   # NAK -> back to INIT; the run loop re-acquires (DISCOVER)
            if rx:
                got = rx.yiaddr
                if request_ip and got != request_ip:
                    return self._on_changed(got, rx, Phase.DORA, True)
                self.adopt(rx)
                return True
            LOG.info("no DHCP ACK from %s for %s (attempt %d, xid 0x%08x)",
                     self.binding.server, self.binding.yiaddr, attempt, self.xid)
            time.sleep(min(_jittered(2 ** attempt), ATTEMPT_BACKOFF_CAP))
        return False

    # reboot() and renew() share _request_offer's REQUEST->ACK shape: they are
    # the RFC 2131 REBOOTING and RENEWING/REBINDING states next to REQUESTING.
    # They stay separate linear loops on purpose -- the three differ on nine
    # axes (options, ciaddr, attempts, timeout, backoff, send-failure policy,
    # expected address, changed-address phase, bind action), so a shared
    # parametrized engine would turn each into config that is harder to audit
    # against the RFC than the plain loop it replaces.
    def reboot(self, request_ip):
        """INIT-REBOOT (RFC 2131 4.3.2): we already know the address we want
        (request_ip), so REQUEST it directly instead of a full DISCOVER -- one
        exchange, and a server that is reachable but refuses the address answers
        with a NAK (a DISCOVER it may just ignore), surfacing 'reachable but
        refused' in the log. server_id MUST NOT be set and ciaddr stays 0 (we do
        not own the address on the interface). Returns True once BOUND, False on
        NAK/timeout so the caller falls back to a full DORA."""
        if not request_ip:
            return False

        self.xid = _new_xid()
        extra = [("requested_addr", request_ip)]
        for attempt in range(1, REBOOT_ATTEMPTS + 1):
            if self._should_stop():
                return False
            self._ensure_sniffer()
            self._rx = None
            try:
                self._send_dhcp("request", extra)
            except Exception as e:
                LOG.error("DHCP INIT-REBOOT send failed: %s", e)
                time.sleep(SEND_RETRY_DELAY)
                continue
            rx = self._wait_for_dhcp_reply(ACK, REPLY_TIMEOUT)
            if rx and rx.mtype == NAK:
                return False   # server refused our known address -> full DISCOVER
            if rx:
                got = rx.yiaddr
                if got and got != request_ip:
                    return self._on_changed(got, rx, Phase.REBOOT, True)
                self.adopt(rx)
                if not self.binding.yiaddr:
                    self.binding.yiaddr = request_ip   # ACK without yiaddr: we asked for it
                return True
            LOG.info("no DHCP ACK to INIT-REBOOT for %s (attempt %d, xid 0x%08x)",
                     request_ip, attempt, self.xid)
            if attempt < REBOOT_ATTEMPTS:   # no backoff after the last try -- fall to DORA at once
                time.sleep(min(_jittered(2 ** attempt), ATTEMPT_BACKOFF_CAP))
        return False

    # One return per protocol gate (unbound/stop/send-fail/NAK/changed/ok);
    # folding them into an attempt-helper trades readable gates for plumbing.
    def renew(self, rebind=False):  # pylint: disable=too-many-return-statements
        """REQUEST an extension of the held lease. Returns True on a fresh ACK,
        False on NAK/timeout/unbound (the caller escalates: RENEW -> REBIND ->
        re-acquire)."""
        # RENEWING/REBINDING (RFC 2131 4.3.2): ciaddr identifies the lease, so
        # server_id AND requested_addr MUST NOT be set in either state. We always
        # broadcast (the co-resident non-promiscuous sniffer needs the reply
        # broadcast), so any server may answer, which is fine for a single-server
        # ISP WAN. `rebind` is still load-bearing: it picks the log label AND
        # (via the `phase` it sets) relaxes the expected-server check in the
        # caller's on_changed_address hook, since at T2 any server may
        # legitimately answer.
        yiaddr = self.binding.yiaddr
        if not yiaddr:
            return False   # nothing bound -> nothing to renew

        for _ in range(RENEW_ATTEMPTS):
            if self._should_stop():
                return False
            self._ensure_sniffer()
            self._rx = None
            try:
                # RENEW/REBIND carry no extra options -- ciaddr identifies the lease.
                self._send_dhcp("request", [], ciaddr=yiaddr)
            except Exception as e:
                LOG.error("DHCP %s send failed: %s", Phase.REBIND if rebind else Phase.RENEW, e)
                return False
            rx = self._wait_for_dhcp_reply(ACK, RENEW_TIMEOUT)
            if rx and rx.mtype == NAK:
                return False   # NAK -> re-DORA
            if rx:
                got = rx.yiaddr
                if got and got != self.binding.yiaddr:
                    # Some dynamic servers change the address at renewal (ACK with a
                    # new yiaddr) instead of NAKing. Route it through the same
                    # follow / enforce decision (and hardening) as the initial DORA.
                    phase = Phase.REBIND if rebind else Phase.RENEW
                    return self._on_changed(got, rx, phase, False)
                self._absorb_reply(rx, self.binding.lease_secs)
                return True
        return False

    def release(self, yiaddr=None, server=None):
        """RELEASE a lease -- the held one by default, or an explicit
        (yiaddr, server) pair (the enforce path releases an address it was
        granted but refuses to keep)."""
        if yiaddr is None:
            yiaddr, server = self.binding.yiaddr, self.binding.server
        if not yiaddr:
            return

        try:
            # No broadcast flag: RELEASE expects no reply to capture.
            self._capture.send_dhcp(DhcpSend(
                eth_src=self.eth_src, ip_src=yiaddr, ip_dst=server or IPV4_BROADCAST,
                chaddr=self.chraw, xid=self.xid, ciaddr=yiaddr, flags=0,
                options=[("message-type", "release"), ("server_id", server), "end"]))
            LOG.info("DHCP RELEASE of lease %s sent (server %s)", yiaddr, server or "broadcast")
        except Exception as e:
            LOG.error("RELEASE failed: %s", e)

    def timing(self):
        """Effective renew (T1) / rebind (T2) seconds and where they came from.

        Uses server-provided DHCP option 58/59 when present and sane, otherwise
        the RFC-suggested 0.5 / 0.875 of the lease time.
        """
        lease = max(1, self.binding.lease_secs)
        t1 = self.binding.t1_server if self.binding.t1_server else int(lease * T1_FACTOR)
        t2 = self.binding.t2_server if self.binding.t2_server else int(lease * T2_FACTOR)
        # Keep both timers inside the lease; only apply the MIN_T1 floor when the
        # lease is long enough to accommodate it (very short leases renew sooner).
        t1 = min(t1, lease)
        if lease > MIN_T1:
            t1 = max(MIN_T1, t1)
        t2 = min(max(t1 + REBIND_MARGIN, t2), lease)
        src = "server" if (self.binding.t1_server or self.binding.t2_server) else "derived"
        return t1, t2, src
