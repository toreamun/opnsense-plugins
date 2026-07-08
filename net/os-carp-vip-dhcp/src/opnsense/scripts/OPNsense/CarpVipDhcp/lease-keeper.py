#!/usr/local/bin/python3
"""Robust DHCP lease-keeper: keep a lease alive for a chosen chaddr.

Keeps a DHCP lease alive for a given ``chaddr`` WITHOUT binding it to the
interface's hardware MAC, so the leased address (typically a CARP virtual IP)
stays routed by the ISP. The broadcast flag is set so OFFER/ACK are broadcast.
This does lease maintenance ONLY; ARP for the address and data traffic are
handled by CARP. Optionally (--arp-nudge) it also refreshes the upstream
gateway's ARP entry for the leased address, for gateways that ignore
gratuitous ARP and never re-ARP an expired entry (traffic to the address
silently blackholes until the gateway receives an ARP *request* from it). It
also watches for the gateway's ARP reply to that nudge as a reachability
signal, warns if repeated nudges go unanswered (a likely sign the carrier is
dropping them), and flags an ARP conflict if another MAC claims the leased
address. By default it is ungated and runs on both HA nodes for redundancy;
opt-in run-only-on-master gating restricts it to the CARP master.

Robustness:
  * Full DHCP lifecycle: DORA (Discover / Offer / Request / Ack, the lease
    acquisition handshake) -> BOUND, RENEW at T1, REBIND at T2, re-DORA at expiry.
  * Single instance via pidfile; heartbeat file (fresh = the lease is renewing).
  * Resilient sniffer: restarted if its thread dies (e.g. the interface flaps).
  * All I/O wrapped in try/except so the main loop never crashes; a non-zero
    exit on a fatal error lets the supervisor restart it.
  * RELEASE is NOT sent on a normal stop (SIGTERM) -- only with
    --once/--release-on-exit -- so the address is not given up needlessly.

Security posture (this daemon parses untrusted WAN traffic as root):
  * The sniffer is NOT promiscuous by default: DHCP requests carry the BOOTP
    broadcast flag so the server broadcasts its replies to a non-promiscuous
    socket, and the gateway's unicast ARP reply to a nudge reaches us because
    the CARP master already accepts the VIP's virtual MAC (its own traffic).
    --arp-listen-promisc is an opt-in fallback (default off) for NICs that drop
    non-primary unicast; it widens capture to the whole segment, so it warns
    when enabled.
  * The BPF filter is the next boundary: only DHCP (udp port 67/68), ARP
    *replies*, and (once bound) ARP claiming our leased IP reach Python;
    everything else -- including the segment's broadcast who-has flood -- is
    dropped in the kernel.
  * A DHCP reply must carry the BOOTREPLY op; our own xid gates the first-party
    path, and in follow mode a reply on our shared chaddr (the peer node's ACK)
    is read too, but only to RECORD an observed address change for the main
    thread's hardened follow path (see _on_dhcp_reply). An ARP reply must come
    from the nudge target for our leased IP (see _on_arp_reply) -- other packets
    are dropped early.
  * Only the handful of DHCP options the keeper needs is extracted; there is
    no full dissection of the reply's other option data (untrusted network
    input -- it came from whatever answered on the wire, e.g. a rogue or
    spoofed DHCP server).
  * Follow mode never rewrites the CARP VIP from a single ACK: the new address
    is validated for plausibility, routability class and expected server, and
    rate-throttled against flap/spoof storms (see _handle_changed_address).
  * A parse error in the sniffer callback is dropped (debug-logged); malformed
    input can never take the main loop down.

Cooperating with ISP access-network policing (DHCP snooping, Dynamic ARP
Inspection, gratuitous-ARP filtering, IP source guard, per-subscriber MAC
limits): the design keeps the lease on the CARP virtual MAC and shapes the ARP
nudge to match the snooped binding, so the carrier's guards see legitimate,
consistent state. The README's "Playing nicely with ISP access-network
security" section is the full map from each mechanism to how this code
satisfies it; the load-bearing spots below point back to it.

Usage:
  lease-keeper.py --iface <if> --chaddr <mac> --request <ip>
  lease-keeper.py ... --once            # one-shot claim+verify+release (test)
"""
import argparse
import ipaddress
import logging
import os
import random
import re
import signal
import subprocess
import sys
import threading
import time
from collections import namedtuple
from logging.handlers import RotatingFileHandler

from scapy.all import ARP, Ether, IP, UDP, BOOTP, DHCP, AsyncSniffer, sendp

LOG = logging.getLogger("lease-keeper")

# DHCP message types (RFC 2131).
OFFER, ACK, NAK = 2, 5, 6
BOOTREPLY = 2              # BOOTP op field: a server->client reply (unrelated to OFFER)

# Timing / retry tunables (seconds unless noted).
GATE_POLL = 5              # between CARP-master checks when run-only-on-master is set
HB_REFRESH = 30            # rewrite the heartbeat at least this often while holding a lease
DEFAULT_LEASE = 3600       # fallback lease time if the server sends none
DORA_ATTEMPTS = 5          # DISCOVER and REQUEST attempts per acquire
RENEW_ATTEMPTS = 3         # REQUEST attempts per renew
REPLY_TIMEOUT = 4          # wait for an OFFER/ACK during acquire
RENEW_TIMEOUT = 3          # wait for an ACK during renew
ATTEMPT_BACKOFF_CAP = 8    # max wait between acquire attempts
SEND_RETRY_DELAY = 2       # wait after a failed packet send before retrying
REBIND_POLL_STEP = 10      # how often to re-try RENEW during the REBIND window
REDORA_MIN = 10            # initial wait after a failed acquire
REDORA_MAX = 300           # max exponential-backoff wait after a failed acquire
SNIFFER_RETRY = 5          # wait before retrying a failed packet-sniffer start
LOOP_ERROR_BACKOFF = 10    # wait after an unexpected main-loop error before retrying
MIN_FOLLOW_INTERVAL = 60   # min seconds between follow (VIP rewrite) events -- damps flap/spoof storms
FOLLOW_RETRY_DEADLINE = 120  # re-drive follow_update if we are not restarted within this after firing
T1_FACTOR = 0.5            # renew at this fraction of the lease (RFC default)
T2_FACTOR = 0.875          # rebind by this fraction of the lease (RFC default)
MIN_T1 = 30                # floor for the renew timer (very short leases)
REBIND_MARGIN = 15         # ensure T2 is at least this far past T1
BROADCAST_FLAG = 0x8000    # BOOTP flags: ask the server to broadcast OFFER/ACK
ARP_NUDGE_MIN = 30         # floor for --arp-nudge so a typo cannot flood the segment
ARP_UNANSWERED_WARN = 3    # warn after this many consecutive nudges with no gateway reply
ARP_CONFLICT_REWARN = 3600  # re-warn about a persistent ARP conflict at most this often
LOG_MAX_BYTES = 512 * 1024
LOG_BACKUPS = 3

# A parsed DHCP reply, snapshotted from the sniffer thread.
# `message` (DHCP option 56) is the server's optional human-readable text, mainly
# a NAK reason. Defaulted so existing 7-field constructions stay valid.
DhcpReply = namedtuple("DhcpReply", "mtype yiaddr server_id lease t1 t2 router message",
                       defaults=(None,))
MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")


_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def _sane_ipv4(ip):
    """True for a plausible host IPv4 lease address (rejects 0.0.0.0, multicast,
    reserved, loopback and link-local) -- used to avoid rewriting the CARP VIP
    from a malformed or rogue ACK."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (addr.version == 4 and not addr.is_unspecified and not addr.is_multicast
            and not addr.is_reserved and not addr.is_loopback and not addr.is_link_local)


def _is_localish(ip):
    """True if the address is private (RFC 1918) or CGNAT (RFC 6598) -- i.e. not a
    globally routable public address (independent of the Python version's view of
    CGNAT)."""
    addr = ipaddress.ip_address(ip)
    return addr.is_private or addr in _CGNAT


def _same_ip_class(a, b):
    """True if a and b are in the same routability class (both local-ish or both
    public). A follow that crosses classes (e.g. CGNAT -> a public IP) is almost
    certainly a spoofed/rogue ACK, not a legitimate reassignment."""
    try:
        return _is_localish(a) == _is_localish(b)
    except ValueError:
        return False


def _fs_safe(s):
    """Filesystem-safe token (same charset as the keeper id)."""
    return re.sub(r"[^A-Za-z0-9]", "_", s or "")


def mac2raw(m):
    return bytes.fromhex(m.replace(":", "").replace("-", ""))


class Keeper:
    def __init__(self, iface, chaddr, request_ip=None, eth_src=None,
                 hbfile=None, release_on_exit=False, only_when_master=False, vhid=None,
                 follow=False, vendor_class=None, client_id=None, hostname=None,
                 arp_nudge=0, arp_listen_promisc=False):
        self.iface = iface
        self.chaddr = chaddr.lower()
        self.chraw = mac2raw(chaddr)
        self.request_ip = request_ip
        self.eth_src = (eth_src or chaddr).lower()
        self.hbfile = hbfile
        self.release_on_exit = release_on_exit
        self.only_when_master = only_when_master
        self.vhid = str(vhid) if vhid else None
        self.follow = follow
        # ARP nudge: keep the upstream gateway's ARP entry for the leased address
        # fresh, for gateways that ignore gratuitous ARP and never re-ARP an
        # expired entry (see the README's "ARP nudge" section for the full story).
        self.arp_nudge = max(ARP_NUDGE_MIN, arp_nudge) if arp_nudge else 0
        # Promiscuous ARP capture: off by default (the CARP master already
        # accepts the VIP MAC, so the unicast reply reaches a normal socket).
        # Opt-in fallback for NICs that drop non-primary unicast MACs.
        self.arp_listen_promisc = arp_listen_promisc
        self.router = None             # default gateway (DHCP opt 3, fallback: server_id)
        self._last_nudge = 0.0
        self._nudge_gw = None          # last nudge target we logged (log again on change)
        self._nudge_warned = False     # warned once about a missing nudge target
        # ARP-reply reachability, split cleanly across threads: the sniffer thread
        # only stamps _last_arp_reply (a lone atomic float write); the "consumed up
        # to here" bookmark and the unanswered counter are touched ONLY by the main
        # thread (in _arp_nudge), so there is no cross-thread read-modify-write.
        self._last_arp_reply = 0.0     # epoch of the gateway's last ARP reply (sniffer-written, 0 = none)
        self._reply_seen_at = 0.0      # last _last_arp_reply the main thread has accounted for
        self._nudges_since_reply = 0   # consecutive nudges with no new reply (unanswered detector)
        # ARP conflict (another MAC claiming our leased IP). Detected + throttled
        # entirely on the sniffer thread, so these are single-owner too.
        self._sniffer_yiaddr = None    # leased IP the current sniffer filter was built for
        self._last_conflict_warn = 0.0  # throttle for the conflict warning
        self._conflict_mac = None       # last foreign MAC seen using our IP
        self._was_master = None        # CARP role at the last nudge check (None = unknown yet)
        self._nudge_now = False        # operator asked for an immediate nudge (SIGUSR1)
        self._poll_role_now = False    # a CARP transition fired -> re-check role now (SIGUSR2)
        self._renew_asap = False       # renew at the next _hold_lease tick instead of waiting for T1
        # Optional DHCP request options (empty -> not sent); built once and added to
        # every DISCOVER/REQUEST/RENEW so the server sees a consistent client identity.
        # ISP interplay: satisfies servers that only lease to a known vendor-class
        # (opt 60), client-id (61) or hostname (12) -- the "client identity checks"
        # row of the README's ISP-security section.
        self._id_opts = []
        if vendor_class:
            self._id_opts.append(("vendor_class_id", vendor_class))
        if client_id:
            self._id_opts.append(("client_id", client_id.encode()))
        if hostname:
            self._id_opts.append(("hostname", hostname))
        self._followed_ip = None       # last address we asked configd to follow to
        self._follow_from = None       # address we followed FROM (for the retry watchdog)
        self._follow_fired_at = 0.0    # when we last dispatched follow_update (retry deadline)
        self._last_master = True       # last known CARP-master decision (fail to this)
        self._gated_standby = False    # currently standing by as CARP backup (run-only-on-master)
        # Follow throttle state, keyed by chaddr so it survives the follow-induced
        # restart (the request-IP-keyed runtime paths change on every follow).
        self._follow_state = "/var/run/carpvipdhcp-follow-%s" % _fs_safe(self.chaddr)
        self.redora_wait = REDORA_MIN
        self.xid = random.randint(1, 0xFFFFFFFF)
        self.server = None
        self.yiaddr = None
        self.lease = DEFAULT_LEASE
        self.t1_server = None          # server-provided renewal time (DHCP opt 58)
        self.t2_server = None          # server-provided rebinding time (DHCP opt 59)
        self.stop = False
        self._rx = None                # latest DhcpReply snapshot (set by the sniffer thread)
        # Follow mode: a changed ISP address first seen in the PEER's ACK (both
        # HA nodes run an identical keeper on the same shared chaddr). The sniffer
        # writes it (a lone atomic ref-assign); the main thread consumes it and
        # drives the hardened follow -- see _on_dhcp_reply / _check_observed_follow.
        self._observed_change = None
        self._ev = threading.Event()
        self._sniffer = None

    # ---- sniffer (resilient) ----
    def _sniffer_filter(self):
        # DHCP (broadcast OFFER/ACK) + ARP replies to our nudge (arp[6:2]=2). Once
        # we hold a lease, also capture ARP whose SENDER protocol address is our
        # leased IP (arp[14:4]) -- to spot another MAC claiming our address. The
        # BPF filter is a boundary, not an optimization: it keeps everything else
        # (incl. the segment's broadcast who-has flood) out of the Python parser.
        f = "(udp and (port 67 or port 68)) or (arp and arp[6:2] = 2)"
        try:
            if self.yiaddr:
                f += " or (arp and arp[14:4] = %d)" % int(ipaddress.IPv4Address(self.yiaddr))
        except ValueError:
            pass
        return f

    def _start_sniffer(self):
        try:
            if self._sniffer:
                try:
                    self._sniffer.stop()
                except Exception:
                    pass
            # Non-promiscuous by default: the BOOTP broadcast flag makes the
            # server broadcast OFFER/ACK, and the gateway's unicast ARP reply to a
            # nudge reaches us because the CARP master already accepts the VIP's
            # virtual MAC. arp_listen_promisc is the opt-in fallback for NICs that
            # drop non-primary unicast (widens capture -- warned at startup).
            self._sniffer_yiaddr = self.yiaddr   # what the filter below is built for
            self._sniffer = AsyncSniffer(
                iface=self.iface, filter=self._sniffer_filter(),
                prn=self._on_sniff, store=0, promisc=self.arp_listen_promisc)
            self._sniffer.start()
            return True
        except Exception as e:
            LOG.error("DHCP-reply sniffer start failed: %s", e)
            return False

    def _sniffer_alive(self):
        t = getattr(self._sniffer, "thread", None)
        return bool(self._sniffer and t is not None and t.is_alive())

    def _ensure_sniffer(self):
        if not self._sniffer_alive():
            LOG.warning("DHCP-reply sniffer down -- (re)starting")
            self._start_sniffer()
            time.sleep(1)
        elif self.yiaddr != self._sniffer_yiaddr:
            # Our leased IP became known (or changed) -> rebuild the filter so the
            # conflict clause (ARP sender == our IP) tracks the current address.
            LOG.debug("rebuilding sniffer filter for leased IP %s", self.yiaddr)
            self._start_sniffer()

    def _on_sniff(self, p):
        # One sniffer feeds two parsers; keep the DHCP and ARP concerns separate.
        # The BPF filter already narrowed traffic to DHCP + ARP replies, so this
        # only routes by layer -- each handler does its own validation/guarding.
        if p.haslayer(BOOTP):
            self._on_dhcp_reply(p)
        elif p.haslayer(ARP):
            self._on_arp_reply(p)      # gateway answering our nudge (reachability)
            self._on_arp_conflict(p)   # someone else claiming our leased IP

    def _on_arp_reply(self, p):
        """Record the gateway's ARP reply to our nudge as a reachability signal.
        Only the reply to OUR who-has counts: op=2 (is-at), sender = the nudge
        target gateway, target protocol address = our leased IP. Anything else on
        the segment is ignored. Runs on the sniffer thread and does ONE thing --
        stamp _last_arp_reply (a lone atomic write); the main thread consumes it
        in _arp_nudge, so the counter/warn state is single-owner (no race).

        The signal is advisory: an on-segment attacker could forge a reply (or
        withhold one), so a green "reachable" is not proof. It only drives a
        diagnostic; nothing here feeds lease/CARP/follow decisions."""
        try:
            arp = p[ARP]
            if arp.op != 2:                     # 2 = is-at (reply); requests are filtered out in BPF
                return
            gw = self._nudge_target()
            if not gw or not self.yiaddr:
                return
            if arp.psrc == gw and arp.pdst == self.yiaddr:
                self._last_arp_reply = time.time()
                # Routine confirmation at DEBUG, mirroring "ARP nudge sent"; the
                # main thread logs the first reply / recovery at INFO.
                LOG.debug("ARP reply from %s (is-at) for %s", gw, self.yiaddr)
        except Exception as e:
            LOG.debug("ARP reply parse error: %s", e)

    def _on_arp_conflict(self, p):
        """Warn if another MAC claims our leased IP -- an ARP whose sender IP is
        ours but whose sender MAC is not our CARP MAC (the peer node shares that
        MAC, so it is excluded). Signals a duplicate address / ISP reassignment.
        Passive and advisory (spoofable); it only logs, never acts. Throttled so a
        persistent conflict does not flood the log: re-warns only when the
        offending MAC changes or after ARP_CONFLICT_REWARN (a new impostor thus
        surfaces at once). Detection and throttle state are touched only here
        (sniffer thread) -> single-owner."""
        try:
            if not self.yiaddr:
                return
            arp = p[ARP]
            if arp.psrc != self.yiaddr:
                return
            mac = (arp.hwsrc or "").lower()
            if not mac or mac == self.chaddr:   # our own / peer's CARP MAC -> not a conflict
                return
            now = time.time()
            if mac == self._conflict_mac and now - self._last_conflict_warn < ARP_CONFLICT_REWARN:
                return
            self._conflict_mac = mac
            self._last_conflict_warn = now
            LOG.warning("ARP conflict: %s is using our leased IP %s (our MAC is %s) "
                        "-- possible duplicate address or ISP reassignment",
                        mac, self.yiaddr, self.chaddr)
        except Exception as e:
            LOG.debug("ARP conflict parse error: %s", e)

    def _parse_reply(self, p, yiaddr):
        """Snapshot only the handful of DHCP options the keeper acts on into a
        DhcpReply; the rest of the reply's option data -- untrusted, from
        whatever answered on the wire -- is left untouched."""
        mt = sid = lt = rt = bt = ro = msg = None
        for o in p[DHCP].options:
            if isinstance(o, tuple):
                if o[0] == "message-type":
                    mt = o[1]
                elif o[0] == "server_id":
                    sid = o[1]
                elif o[0] == "lease_time":
                    lt = o[1]
                elif o[0] == "renewal_time":
                    rt = o[1]
                elif o[0] == "rebinding_time":
                    bt = o[1]
                elif o[0] == "router":
                    ro = o[1]
                elif o[0] == "message":     # option 56: server's text (e.g. a NAK reason)
                    msg = o[1]
        return DhcpReply(mt, yiaddr, sid, lt, rt, bt, ro, msg)

    def _chaddr_matches(self, b):
        """True if the reply's BOOTP client hardware address is our chaddr (the
        CARP virtual MAC). Used to accept the PEER's ACK on the shared chaddr:
        the peer node runs an identical keeper on the very same chaddr."""
        try:
            raw = bytes(getattr(b, "chaddr", b"") or b"")
        except (TypeError, ValueError):
            return False
        return raw[:6] == self.chraw

    def _on_dhcp_reply(self, p):
        try:
            if not (p.haslayer(BOOTP) and p.haslayer(DHCP)):
                return
            b = p[BOOTP]
            if b.op != BOOTREPLY:
                return
            # First-party path: a reply to OUR in-flight exchange (random xid,
            # regenerated per DORA). Parsed and handed to the waiting main thread.
            if b.xid == self.xid:
                self._rx = self._parse_reply(p, b.yiaddr)
                self._ev.set()
                return
            # Not our xid. In follow mode, still watch for the PEER's ACK: both HA
            # nodes run an identical keeper on the SAME chaddr (the CARP virtual
            # MAC), so the peer's ACK reveals a changed ISP address one exchange
            # sooner than our own renewal timer -- closing the window where the
            # two nodes hold different VIP prefixes long enough for CARP to
            # dual-master (see docs/single-ip-wan-carp.md, section 3). This is a
            # deliberately narrow relaxation of the xid trust gate: it requires
            # our chaddr and an ACK for a plausible, different address, and it
            # only RECORDS the observation (one atomic ref write) for the main
            # thread -- which routes it through the same follow hardening
            # (sane / same-class / expected-server / throttle) as a first-party
            # ACK and never acts on the sniffer thread.
            if not self.follow or not self.yiaddr or not self._chaddr_matches(b):
                return
            rx = self._parse_reply(p, b.yiaddr)
            if (rx.mtype == ACK and rx.yiaddr and rx.yiaddr != self.yiaddr
                    and _sane_ipv4(rx.yiaddr)):
                self._observed_change = rx
        except Exception as e:
            LOG.debug("DHCP reply parse error: %s", e)

    # ---- DHCP protocol (send / await reply / DORA / renew / release) ----

    def _send_dhcp(self, mtype, extra, ciaddr="0.0.0.0"):
        # ciaddr is set for RENEW/REBIND (the client already owns the address);
        # the broadcast flag stays on so the reply is reliably captured by the sniffer.
        pkt = (Ether(src=self.eth_src, dst="ff:ff:ff:ff:ff:ff") /
               IP(src=ciaddr, dst="255.255.255.255") /
               UDP(sport=68, dport=67) /
               BOOTP(chaddr=self.chraw, xid=self.xid, ciaddr=ciaddr, flags=BROADCAST_FLAG) /
               DHCP(options=[("message-type", mtype)] + self._id_opts + extra + ["end"]))
        sendp(pkt, iface=self.iface, verbose=0)

    def _wait_for_dhcp_reply(self, want, timeout):
        """Wait up to timeout for a reply of message-type `want`. Returns the
        DhcpReply on match, the string "NAK" on DHCPNAK, or None on timeout.
        Returning the snapshot avoids re-reading self._rx (set by the sniffer
        thread) after the wait."""
        end = time.time() + timeout
        while time.time() < end and not self.stop:
            self._ev.clear()
            self._ev.wait(min(1.0, max(0.05, end - time.time())))
            rx = self._rx
            if rx and rx.mtype == want:
                return rx
            if rx and rx.mtype == NAK:
                # Surface the server's option-56 text (why it refused) if present;
                # it is the operator's main clue for a rejected renew.
                reason = ""
                if rx.message:
                    m = rx.message
                    if isinstance(m, bytes):
                        m = m.decode(errors="replace")
                    reason = " -- %s" % str(m).strip()
                LOG.warning("DHCPNAK received (server %s, xid 0x%08x)%s",
                            rx.server_id or "unknown", self.xid, reason)
                return "NAK"
        return None

    def _absorb_reply(self, rx, default_lease):
        """Adopt lease timing and gateway (DHCP option 3) from an ACK -- the one
        place that knows which DhcpReply fields carry keeper state."""
        self.lease = rx.lease or default_lease
        self.t1_server, self.t2_server = rx.t1, rx.t2
        self.router = rx.router or self.router

    def dora(self):
        """Acquire a lease via the DHCP DORA handshake -- Discover, Offer,
        Request, Ack. Returns True once BOUND, False on failure/NAK."""
        self.xid = random.randint(1, 0xFFFFFFFF)
        extra = [("requested_addr", self.request_ip)] if self.request_ip else []
        for attempt in range(1, DORA_ATTEMPTS + 1):
            if self.stop:
                return False
            if self.only_when_master and not self._is_master():
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
            if rx == "NAK":
                return False
            if rx:
                self.yiaddr, self.server = rx.yiaddr, rx.server_id
                break
            # xid included so the exchange can be matched against a packet capture.
            LOG.info("no DHCP OFFER (attempt %d, xid 0x%08x)", attempt, self.xid)
            time.sleep(min(2 * attempt, ATTEMPT_BACKOFF_CAP))
        else:
            return False
        for attempt in range(1, DORA_ATTEMPTS + 1):
            if self.stop:
                return False
            if self.only_when_master and not self._is_master():
                return False
            self._rx = None
            try:
                self._send_dhcp(
                    "request",
                    [("server_id", self.server), ("requested_addr", self.yiaddr)],
                )
            except Exception as e:
                LOG.error("DHCP REQUEST send failed: %s", e)
                time.sleep(SEND_RETRY_DELAY)
                continue
            rx = self._wait_for_dhcp_reply(ACK, REPLY_TIMEOUT)
            if rx == "NAK":
                return False   # NAK -> back to INIT; the run loop re-acquires (DISCOVER)
            if rx:
                got = rx.yiaddr
                if self.request_ip and got != self.request_ip:
                    return self._handle_changed_address(got, rx, "DORA", release_on_enforce=True)
                self.yiaddr = got
                self._absorb_reply(rx, DEFAULT_LEASE)
                return True
            LOG.info("no DHCP ACK from %s for %s (attempt %d, xid 0x%08x)",
                     self.server, self.yiaddr, attempt, self.xid)
            time.sleep(min(2 * attempt, ATTEMPT_BACKOFF_CAP))
        return False

    def renew(self, rebind=False):
        # RENEWING/REBINDING (RFC 2131 4.3.2/4.4.5): ciaddr identifies the lease,
        # so requested_addr is omitted. RENEW (T1) still names the leasing server;
        # REBIND (T2) drops server_id so ANY DHCP server may answer.
        opts = [] if rebind or not self.server else [("server_id", self.server)]
        for _ in range(RENEW_ATTEMPTS):
            if self.stop:
                return False
            self._ensure_sniffer()
            self._rx = None
            try:
                self._send_dhcp("request", opts, ciaddr=self.yiaddr)
            except Exception as e:
                LOG.error("DHCP %s send failed: %s", "REBIND" if rebind else "RENEW", e)
                return False
            rx = self._wait_for_dhcp_reply(ACK, RENEW_TIMEOUT)
            if rx == "NAK":
                return False   # NAK -> re-DORA
            if rx:
                got = rx.yiaddr
                if got and got != self.yiaddr:
                    # Some dynamic servers change the address at renewal (ACK with a
                    # new yiaddr) instead of NAKing. Route it through the same
                    # follow / enforce decision (and hardening) as the initial DORA.
                    phase = "REBIND" if rebind else "RENEW"
                    return self._handle_changed_address(got, rx, phase, release_on_enforce=False)
                self._absorb_reply(rx, self.lease)
                return True
        return False

    def release(self):
        if not self.yiaddr:
            return
        try:
            pkt = (Ether(src=self.eth_src, dst="ff:ff:ff:ff:ff:ff") /
                   IP(src=self.yiaddr, dst=self.server or "255.255.255.255") /
                   UDP(sport=68, dport=67) /
                   BOOTP(chaddr=self.chraw, xid=self.xid, ciaddr=self.yiaddr) /
                   DHCP(options=[("message-type", "release"),
                                 ("server_id", self.server), "end"]))
            sendp(pkt, iface=self.iface, verbose=0)
            LOG.info("DHCP RELEASE of lease %s sent (server %s)", self.yiaddr, self.server or "broadcast")
        except Exception as e:
            LOG.error("RELEASE failed: %s", e)

    # ---- lease timing ----

    def _timing(self):
        """Effective renew (T1) / rebind (T2) seconds and where they came from.

        Uses server-provided DHCP option 58/59 when present and sane, otherwise
        the RFC-suggested 0.5 / 0.875 of the lease time.
        """
        lease = max(1, self.lease)
        t1 = self.t1_server if self.t1_server else int(lease * T1_FACTOR)
        t2 = self.t2_server if self.t2_server else int(lease * T2_FACTOR)
        # Keep both timers inside the lease; only apply the MIN_T1 floor when the
        # lease is long enough to accommodate it (very short leases renew sooner).
        t1 = min(t1, lease)
        if lease > MIN_T1:
            t1 = max(MIN_T1, t1)
        t2 = min(max(t1 + REBIND_MARGIN, t2), lease)
        src = "server" if (self.t1_server or self.t2_server) else "derived"
        return t1, t2, src

    def _clock_at(self, offset):
        """Local wall-clock HH:MM of a moment `offset` seconds from now. Log
        lines state future moments (renew/rebind/lease expiry) as relative
        durations; the clock time saves the reader the mental arithmetic."""
        return time.strftime("%H:%M", time.localtime(time.time() + offset))

    # ---- heartbeat / status file ----

    def _write_hb(self, content):
        # Write atomically (temp + rename) so a crash mid-write can't leave a partial file.
        if not self.hbfile:
            return
        tmp = "%s.tmp" % self.hbfile
        try:
            with open(tmp, "w") as f:
                f.write(content)
            os.replace(tmp, self.hbfile)
        except Exception as e:
            # The heartbeat drives CARP gating, so a write failure is worth surfacing.
            LOG.warning("heartbeat write failed (%s): %s", self.hbfile, e)

    def _hb(self):
        t1, t2, src = self._timing()
        # Publish nudge state so the status page can show it: nudge=<epoch of the
        # last sent nudge, 0 = never>, arpok=<epoch of the gateway's last ARP reply,
        # 0 = none seen> and the current target gateway (if known).
        extra = ""
        if self.arp_nudge:
            extra = " nudge=%d arpok=%d" % (int(self._last_nudge), int(self._last_arp_reply))
            gw = self._nudge_target()
            if gw:
                extra += " gw=%s" % gw
        self._write_hb("%d bound=%s lease=%d t1=%d t2=%d src=%s%s\n"
                       % (int(time.time()), self.yiaddr or "-", self.lease, t1, t2, src, extra))

    def _hb_mismatch(self, got):
        # Write a clear marker into the heartbeat file so a supervisor/human sees the mismatch.
        self._write_hb("%d MISMATCH got=%s want=%s\n" % (int(time.time()), got, self.request_ip))

    # ---- follow mode (adopt a changed ISP address, with spoof hardening) ----

    def _last_follow_time(self):
        """Epoch of this chaddr's last follow (persisted so the throttle survives
        the follow-induced restart). 0 if never / unreadable."""
        try:
            return float(open(self._follow_state).read().strip())
        except (OSError, ValueError):
            return 0.0

    def _record_follow(self):
        try:
            tmp = self._follow_state + ".tmp"
            with open(tmp, "w") as f:
                f.write("%d" % int(time.time()))
            os.replace(tmp, self._follow_state)
        except OSError as e:
            LOG.warning("could not persist follow timestamp: %s", e)

    def _handle_changed_address(self, got, rx, phase, release_on_enforce):
        """An ACK arrived whose address differs from the one we hold/request.

        In follow mode: validate the address (sane, same routability class, from
        the expected server), throttle against flap/spoof storms, then adopt it
        (rewrite the CARP VIP). Otherwise (enforce): alarm on the mismatch.
        Returns True if we are now bound to `got`, False if the caller should
        re-acquire.
        """
        if self.follow:
            if not _sane_ipv4(got):
                LOG.error("%s: ACK yiaddr %r from server %s implausible -- not following",
                          phase, got, rx.server_id)
                return False
            if not _same_ip_class(self.request_ip, got):
                LOG.error("%s: refusing to follow %s -> %s across address class "
                          "(possible spoofed ACK from %s)", phase, self.request_ip, got,
                          rx.server_id)
                return False
            if phase != "REBIND" and rx.server_id and self.server and rx.server_id != self.server:
                LOG.error("%s: ACK from unexpected server %s (leased from %s) -- not following",
                          phase, rx.server_id, self.server)
                return False
            waited = time.time() - self._last_follow_time()
            if waited < MIN_FOLLOW_INTERVAL:
                LOG.warning("%s: follow %s -> %s throttled (%.0fs < %ds) -- deferring",
                            phase, self.request_ip, got, waited, MIN_FOLLOW_INTERVAL)
                return False
            LOG.warning("ISP gave %s (VIP was %s) at %s -- following: updating the CARP VIP",
                        got, self.request_ip, phase)
            self._record_follow()
            # _follow_update reads request_ip as the old address, so remember it
            # (for the retry watchdog) and fire before overwriting request_ip.
            self._follow_from = self.request_ip
            self._follow_update(got)
            self.request_ip = got
            self.yiaddr, self.server = got, rx.server_id or self.server
            self._absorb_reply(rx, DEFAULT_LEASE)
            return True
        # Enforce: a fixed reservation must always return request_ip.
        LOG.error("%s: IP mismatch -- server %s gave %s, requested %s (reservation problem?)",
                  phase, rx.server_id, got, self.request_ip)
        self._hb_mismatch(got)
        if release_on_enforce:
            self.yiaddr, self.server = got, rx.server_id
            self.release()
            self.yiaddr = None
        return False

    def _follow_update(self, new_ip):
        """Ask configd to rewrite the CARP VIP (and this keeper's reference) from
        request_ip to new_ip, then reconfigure. Fire-and-forget: the resulting
        service restart replaces this daemon with one bound to the new address."""
        if new_ip == self._followed_ip:
            return   # already asked for this address
        try:
            self._fire_follow_update(self.request_ip, new_ip)
            # Only mark as handled once the request was actually dispatched, so a
            # spawn failure is retried next cycle instead of getting stuck.
            self._followed_ip = new_ip
            LOG.info("requested CARP VIP update %s -> %s", self.request_ip, new_ip)
        except Exception as e:
            LOG.error("follow_update request failed: %s", e)

    def _fire_follow_update(self, old_ip, new_ip):
        """Dispatch the configd follow_update action (old -> new) and stamp the
        retry deadline. Separate from _follow_update so the watchdog can re-drive
        a stalled follow without tripping the _followed_ip equality guard."""
        subprocess.Popen(["/usr/local/sbin/configctl", "-d", "carpvipdhcp",
                          "follow_update", old_ip, new_ip])
        self._follow_fired_at = time.time()

    def _follow_watchdog(self):
        """Re-drive a follow that never took effect. After a successful follow,
        follow_update restarts this daemon within a few seconds; if we are still
        alive well past FOLLOW_RETRY_DEADLINE, its apply failed or stalled, so
        re-dispatch it (idempotent: it reconverges whether the config already
        moved or not, and its rc.d restart <old-id> eventually replaces us)."""
        if not (self.follow and self._followed_ip and self._follow_from):
            return
        if time.time() - self._follow_fired_at < FOLLOW_RETRY_DEADLINE:
            return
        LOG.warning("follow %s -> %s not applied within %ds -- re-driving",
                    self._follow_from, self._followed_ip, FOLLOW_RETRY_DEADLINE)
        try:
            self._fire_follow_update(self._follow_from, self._followed_ip)
        except Exception as e:
            LOG.error("follow_update retry failed: %s", e)

    def _check_observed_follow(self):
        """Adopt an address change first seen in the PEER's DHCP ACK (same shared
        chaddr) without waiting for our own renewal timer. The sniffer only
        records the observation; the follow itself runs here on the main thread,
        through the same hardening/throttle as a first-party ACK. This collapses
        the follow window that would otherwise leave the two nodes on different
        VIP prefixes long enough for the backup to promote (transient
        dual-master; see docs/single-ip-wan-carp.md section 3)."""
        rx = self._observed_change
        if rx is None:
            return
        self._observed_change = None
        if not self.follow or not rx.yiaddr or rx.yiaddr == self.yiaddr:
            return
        LOG.info("observed peer DHCP ACK for %s (we hold %s) -- following early to converge",
                 rx.yiaddr, self.yiaddr)
        self._handle_changed_address(rx.yiaddr, rx, "OBSERVED", release_on_enforce=False)

    # ---- CARP role, gating & standby ----

    def _hb_standby(self):
        # Run-only-on-master: we are CARP backup and intentionally hold no lease.
        self._write_hb("%d STANDBY\n" % int(time.time()))

    def _probe_carp_master(self):
        """Raw CARP-role probe for our vhid: True/False from ifconfig, None when
        the probe itself fails; no vhid configured -> True (nothing to gate on).
        Callers apply their own failure policy: _is_master fails open with the
        last known role, the ARP nudge fails closed."""
        if not self.vhid:
            return True
        try:
            out = subprocess.check_output(["/sbin/ifconfig", self.iface], errors="replace")
            if isinstance(out, bytes):
                out = out.decode(errors="replace")
            return ("carp: MASTER vhid %s " % self.vhid) in out
        except (OSError, subprocess.SubprocessError):
            return None

    def _is_master(self):
        """True if we should act as a DHCP client now: gating off, or this node is
        CARP master for our vhid. On a failed probe, keep the last known decision
        (fail open) so a transient ifconfig failure does not flap both nodes to
        master at once."""
        if not self.only_when_master or not self.vhid:
            return True
        probed = self._probe_carp_master()
        if probed is not None:
            self._last_master = probed
        return self._last_master

    def _poll_carp_role(self):
        """Watch for a backup->master transition (called on the heartbeat
        cadence). Becoming master renews the lease early and, when enabled,
        nudges immediately: the failover -- or the link flap that re-elected
        CARP -- may just have disturbed the upstream gateway's ARP entry and the
        access node's DHCP-snooping binding, so neither should wait out its
        normal timer. Independent of the ARP nudge setting."""
        if not self.vhid:
            return
        master = self._probe_carp_master()
        if master is None:
            return
        if master and self._was_master is False:
            LOG.info("became CARP master for vhid %s -- immediate ARP nudge and early lease renew",
                     self.vhid)
            self._renew_asap = True
            self._arp_nudge(force=True)
        elif not master and self._was_master:
            # The symmetric event: without it, "why did the nudges stop?" needs
            # ifconfig instead of the log.
            LOG.info("lost CARP master for vhid %s -- ARP nudges pause on this node", self.vhid)
        self._was_master = master

    # ---- ARP nudge ----

    def _nudge_target(self):
        """The gateway whose ARP cache the nudge maintains: DHCP option 3 from
        the last ACK, falling back to the leasing server's address."""
        return self.router or self.server

    def _arp_nudge(self, force=False):
        """Refresh the upstream gateway's ARP entry for the leased address by
        broadcasting an ARP request from (yiaddr, chaddr). No-op unless enabled,
        bound, due (or forced) and CARP master -- never nudge from a backup (it
        would steal the VIP's traffic), so a failed role probe skips the nudge
        (fails closed; the next interval retries)."""
        if not self.arp_nudge or not self.yiaddr:
            return
        if not force and time.time() - self._last_nudge < self.arp_nudge:
            return
        if self._probe_carp_master() is not True:
            return
        gw = self._nudge_target()
        if not gw:
            # Enabled but no target: without this warning the nudge would be a
            # silent no-op and the operator would believe they are protected.
            if not self._nudge_warned:
                LOG.warning("ARP nudge enabled but no gateway known "
                            "(no DHCP router option or server-id) -- cannot nudge")
                self._nudge_warned = True
            return
        try:
            # This frame is shaped to satisfy three ISP access-network guards at
            # once (README "Playing nicely" section):
            #   * op=1 (a REQUEST, not a gratuitous announcement) -- gear that
            #     filters unsolicited/gratuitous ARP still processes a request,
            #     which is what refreshes the entry;
            #   * sender (psrc=leased IP, hwsrc=chaddr=CARP MAC) is exactly the
            #     DHCP-snooped IP<->MAC binding, so Dynamic ARP Inspection passes it;
            #   * sending it at all exists for gateways that never re-ARP an
            #     expired entry ("secured ARP") and would otherwise blackhole the
            #     VIP. Only the CARP master sends it (gated above).
            sendp(Ether(src=self.chaddr, dst="ff:ff:ff:ff:ff:ff") /
                  ARP(op=1, hwsrc=self.chaddr, psrc=self.yiaddr,
                      hwdst="00:00:00:00:00:00", pdst=gw),
                  iface=self.iface, verbose=0)
            self._last_nudge = time.time()
            # Reachability accounting (main-thread-only; the sniffer just stamps
            # _last_arp_reply). If a reply landed since we last looked, we are
            # reachable -> clear the counter; otherwise this nudge went unanswered.
            # The counter only steps +1 or resets to 0, so it lands on the threshold
            # exactly once per streak -> warn there (no separate "warned" latch). The
            # hint depends on whether we are already promiscuous: if we are, promisc
            # is not the fix (the carrier is dropping it); if not, that NIC may simply
            # not surface the unicast reply.
            if self._last_arp_reply > self._reply_seen_at:
                # A reply arrived since the last nudge -> reachable. Log the
                # positive transitions at INFO (first confirmation, or recovery
                # after an unanswered streak), mirroring the nudge-active INFO and
                # the unanswered WARNING; every individual reply is at DEBUG.
                if self._reply_seen_at == 0.0:
                    LOG.info("ARP nudge confirmed: %s replied for %s", gw, self.yiaddr)
                elif self._nudges_since_reply >= ARP_UNANSWERED_WARN:
                    LOG.info("ARP nudge answered again by %s after %d unanswered",
                             gw, self._nudges_since_reply)
                self._reply_seen_at = self._last_arp_reply
                self._nudges_since_reply = 0
            else:
                self._nudges_since_reply += 1
            if self._nudges_since_reply == ARP_UNANSWERED_WARN:
                if self.arp_listen_promisc:
                    hint = ("the gateway is not answering -- with promiscuous "
                            "listening already on, the carrier is likely dropping "
                            "the nudge (DAI/DHCP snooping)")
                else:
                    hint = ("the gateway may be dropping it (DAI/DHCP snooping), or "
                            "this NIC may not surface the unicast reply without "
                            "'ARP listen in promiscuous mode'")
                LOG.warning("ARP nudge unanswered: %d sent to %s for %s with no reply "
                            "-- %s", self._nudges_since_reply, gw, self.yiaddr, hint)
            # Every fire is logged, but at the right level: the first one (and any
            # target change) at INFO so the default log shows the nudge is active;
            # the routine repeats at DEBUG, so they are there in "Debug (all)"
            # without flooding INFO (nudges fire every arp_nudge seconds, oftener
            # than DHCP renews).
            if gw != self._nudge_gw:
                LOG.info("ARP nudge active: who-has %s tell %s (src %s) every %ds",
                         gw, self.yiaddr, self.chaddr, self.arp_nudge)
                self._nudge_gw = gw
            else:
                LOG.debug("ARP nudge sent: who-has %s tell %s", gw, self.yiaddr)
        except Exception as e:
            LOG.warning("ARP nudge failed (target %s): %s", gw, e)

    # ---- main loop / sleeps ----

    def _sleep(self, secs):
        slept = 0
        while slept < secs and not self.stop:
            time.sleep(1)
            slept += 1
        return slept

    def _sleep_gated(self, secs):
        """Sleep up to secs (1s steps). Return False early on stop or, when
        run-only-on-master is set, on CARP-master loss (checked every GATE_POLL).
        Also services an operator-requested immediate nudge (SIGUSR1) and a
        CARP-transition re-check (SIGUSR2) so both act within a second instead of
        at the next heartbeat tick."""
        slept = 0
        while slept < secs and not self.stop:
            if self._poll_role_now:
                self._poll_role_now = False
                # A CARP transition just fired (kernel -> devd -> rc.syshook.d/carp
                # -> SIGUSR2); re-check the role now so a backup->master keeper
                # nudges + renews immediately instead of at the next ~30s poll.
                self._poll_carp_role()
            if self._nudge_now:
                self._nudge_now = False
                # Operator actions are rare and intentional -- always log them,
                # unlike the periodic nudges (whose freshness the status page
                # already shows without flooding the log every interval).
                LOG.info("manual ARP nudge requested (SIGUSR1)")
                self._arp_nudge(force=True)
                self._hb()   # publish the new nudge age right away for the status page
            if self._observed_change is not None:
                # The peer's ACK revealed a changed ISP address -> follow now
                # (within ~1s) instead of at our own renewal timer, so the two
                # nodes converge before CARP's ~3s timeout can dual-master us.
                self._check_observed_follow()
            if self.only_when_master and slept % GATE_POLL == 0 and not self._is_master():
                return False
            time.sleep(1)
            slept += 1
        return not self.stop

    def _hold_lease(self, secs):
        """Sleep up to secs while holding a lease, rewriting the heartbeat every
        HB_REFRESH so a healthy keeper never looks stale (leases can be hours and
        the CARP demotion hook only sees heartbeat freshness). Returns False early
        on stop or CARP-master loss."""
        remaining = secs
        while remaining > 0 and not self.stop:
            if self._renew_asap:
                # Return as if T1 elapsed: the caller renews right away, which
                # re-teaches upstream DHCP-snooping state after a master change.
                self._renew_asap = False
                return not self.stop
            chunk = min(HB_REFRESH, remaining)
            if not self._sleep_gated(chunk):
                return False
            remaining -= chunk
            self._hb()
            self._follow_watchdog()   # re-drive a follow whose apply stalled
            self._poll_carp_role()    # backup->master? renew early + nudge now
            self._arp_nudge()
        return not self.stop

    def run(self):
        # Start the packet sniffer, retrying forever: a keeper must self-heal, not
        # die, if the interface is briefly unavailable at startup.
        while not self.stop and not self._start_sniffer():
            LOG.warning("sniffer start failed -- retrying in %ds", SNIFFER_RETRY)
            self._sleep(SNIFFER_RETRY)
        gate = (" (only when CARP master, vhid %s)" % self.vhid) if self.only_when_master else ""
        # eth-src matters for L2 debugging but only when it differs from the chaddr.
        ethsrc = (" eth-src=%s" % self.eth_src) if self.eth_src != self.chaddr else ""
        LOG.info("lease-keeper active on %s: chaddr=%s%s request=%s%s",
                 self.iface, self.chaddr, ethsrc, self.request_ip or "any", gate)
        time.sleep(0.5)
        while not self.stop:
            # The keeper must NEVER die on a bad DHCP state: catch any unexpected
            # error, keep the heartbeat fresh so CARP does not falsely demote us,
            # and retry after a short backoff.
            try:
                self._run_once()
            except Exception:
                LOG.exception("unexpected error in main loop -- recovering")
                try:
                    self._hb()
                except Exception:
                    pass
                self._sleep(LOOP_ERROR_BACKOFF)
        # shutdown
        if self.release_on_exit:
            self.release()
        try:
            self._sniffer.stop()
        except Exception:
            pass
        LOG.info("stopped")
        return 0

    def _run_once(self):
        """One iteration of the maintain loop. Returns to run() (which loops again)
        on every state transition; any exception it raises is caught by run() and
        retried, so a transient fault can never terminate the keeper."""
        # Run-only-on-master gating: stand by (no DHCP) while we are CARP backup.
        # Log the master<->backup mode change once per transition (not every poll).
        if self.only_when_master:
            if not self._is_master():
                if not self._gated_standby:
                    LOG.info("CARP backup for vhid %s -- releasing the lease and standing by", self.vhid)
                    self._gated_standby = True
                if self.yiaddr:
                    self.release()
                    self.yiaddr = None
                self._hb_standby()
                self._sleep(GATE_POLL)
                return
            if self._gated_standby:
                LOG.info("CARP master for vhid %s -- resuming DHCP (re-acquiring the lease)", self.vhid)
                self._gated_standby = False
        # Acquire a lease if we do not hold one.
        if not self.yiaddr:
            self._ensure_sniffer()  # a dead sniffer would silently fail every DORA
            self._hb()  # active but not holding yet -> publish bound=- (not STANDBY)
            if self.dora():
                LOG.info("DHCP BOUND %s (lease=%ss, expires ~%s, server=%s)",
                         self.yiaddr, self.lease, self._clock_at(self.lease), self.server)
                self._hb()
                self._arp_nudge(force=True)
                self.redora_wait = REDORA_MIN
            else:
                LOG.warning("DHCP acquire (DISCOVER/REQUEST) failed -- retrying in %ds", self.redora_wait)
                self._sleep_gated(self.redora_wait)
                self.redora_wait = min(self.redora_wait * 2, REDORA_MAX)
            return
        # Maintain: wait until T1, then RENEW; bail early on stop or master loss.
        t1, t2, src = self._timing()
        # The renew/rebind plan is verbose and identical every cycle for a stable
        # lease, so log it at DEBUG -- the default (INFO) log stays clean and
        # "RENEW ok" already carries the lease + expiry. Raise the keeper's log
        # level to see it.
        LOG.debug("DHCP lease %ds; renew at T1=%ds (~%s), rebind by T2=%ds (~%s) (timing source: %s)",
                  self.lease, t1, self._clock_at(t1), t2, self._clock_at(t2), src)
        if not self._hold_lease(t1):
            return
        if self.renew():
            LOG.info("DHCP RENEW ok %s (lease=%ss, expires ~%s)",
                     self.yiaddr, self.lease, self._clock_at(self.lease))
            self._hb()
            self._arp_nudge(force=True)
            return
        LOG.warning("DHCP RENEW failed at T1 -- trying REBIND until T2")
        elapsed = t1
        ok = False
        while elapsed < t2 and not self.stop:
            step = min(REBIND_POLL_STEP, t2 - elapsed)
            if not self._sleep_gated(step):
                break
            elapsed += step
            self._hb()   # still holding the lease until T2 -- keep the heartbeat fresh
            if self.renew(rebind=True):
                ok = True
                break
        if ok:
            LOG.info("DHCP REBIND ok %s (lease=%ss, expires ~%s)",
                     self.yiaddr, self.lease, self._clock_at(self.lease))
            self._hb()
            self._arp_nudge(force=True)
            return
        if self.only_when_master and not self._is_master():
            return  # lost master -> top of loop releases and stands by
        LOG.error("DHCP lease expired -- re-acquiring (back to DISCOVER)")
        self.yiaddr = None


def acquire_pidfile(path):
    if not path:
        return None
    # Atomic create (O_EXCL) so two near-simultaneous starts can't both win.
    while True:
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            os.write(fd, str(os.getpid()).encode())
            os.close(fd)
            return path
        except FileExistsError:
            try:
                old = int(open(path).read().strip())
                os.kill(old, 0)
                LOG.error("already running (pid %d) -- exiting", old)
                sys.exit(4)
            except (ValueError, ProcessLookupError, PermissionError):
                # Stale pidfile (dead/foreign pid): remove it and retry the create.
                try:
                    os.unlink(path)
                except OSError:
                    pass
        except OSError as e:
            LOG.error("cannot write pidfile %s: %s", path, e)
            sys.exit(5)


def main():
    ap = argparse.ArgumentParser(description="Robust DHCP lease-keeper (chaddr decoupled from the iface MAC)")
    ap.add_argument("--iface", required=True)
    ap.add_argument("--chaddr", required=True)
    ap.add_argument("--request", default=None)
    ap.add_argument("--eth-src", default=None)
    ap.add_argument("--pidfile", default="/var/run/lease-keeper.pid")
    ap.add_argument("--hbfile", default="/var/run/lease-keeper.hb")
    ap.add_argument("--logfile", default="/var/log/lease-keeper.log")
    ap.add_argument("--vhid", default=None)
    ap.add_argument("--only-when-master", action="store_true")
    ap.add_argument("--follow", action="store_true")
    ap.add_argument("--vendor-class", default=None)
    ap.add_argument("--client-id", default=None)
    ap.add_argument("--hostname", default=None)
    ap.add_argument("--arp-nudge", type=int, default=0, metavar="SECS",
                    help="periodically broadcast an ARP request from the leased IP "
                         "for the gateway, so upstream gear that never re-ARPs keeps "
                         "a fresh entry (0 = off, suggested 240)")
    ap.add_argument("--arp-listen-promisc", action="store_true",
                    help="put the capture socket in promiscuous mode so the gateway's "
                         "unicast ARP reply is seen on NICs that filter non-primary "
                         "unicast MACs (default off; only needed if replies aren't seen)")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--release-on-exit", action="store_true")
    a = ap.parse_args()

    handlers = [logging.StreamHandler()]
    if a.logfile:
        try:
            handlers.append(RotatingFileHandler(a.logfile, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUPS))
        except Exception:
            pass
    # Write DEBUG too (routine detail like the renew/rebind plan). The volume is
    # low here, and the log page defaults to hiding DEBUG -- selecting a lower
    # level in its filter reveals it, so "turning up the log level" needs no
    # daemon restart.
    logging.basicConfig(level=logging.DEBUG, handlers=handlers,
                        format="%(asctime)s %(levelname)s %(message)s")

    for label, mac in (("chaddr", a.chaddr), ("eth-src", a.eth_src)):
        if mac and not MAC_RE.match(mac):
            LOG.error("invalid %s MAC address: %r", label, mac)
            return 2

    k = Keeper(a.iface, a.chaddr, a.request, a.eth_src,
               hbfile=a.hbfile, release_on_exit=a.release_on_exit or a.once,
               only_when_master=a.only_when_master, vhid=a.vhid, follow=a.follow,
               vendor_class=a.vendor_class, client_id=a.client_id, hostname=a.hostname,
               arp_nudge=a.arp_nudge, arp_listen_promisc=a.arp_listen_promisc)

    if a.arp_listen_promisc:
        LOG.warning("ARP listen: PROMISCUOUS capture enabled on %s -- the daemon now "
                    "sees all traffic on the segment (opt-in fallback for NICs that "
                    "drop the gateway's unicast ARP reply otherwise)", a.iface)

    def _sig(*_):
        LOG.info("signal received -- stopping")
        k.stop = True
    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    def _sig_arp_nudge(*_):
        # Operator-requested immediate ARP nudge (configd action / kill -USR1).
        # Only sets a flag; the sleep loops service it within a second, so no
        # network I/O happens inside the signal handler itself.
        k._nudge_now = True
    signal.signal(signal.SIGUSR1, _sig_arp_nudge)

    def _sig_carp(*_):
        # CARP transition (rc.syshook.d/carp/50-carpvipdhcp sends SIGUSR2). Only
        # sets a flag; the sleep loop re-checks the CARP role within a second.
        k._poll_role_now = True
    signal.signal(signal.SIGUSR2, _sig_carp)

    if a.once:
        if not k._start_sniffer():
            return 3
        time.sleep(0.5)
        ok = k.dora()
        LOG.info("DHCP claim %s -> %s", k.chaddr, k.yiaddr if ok else "FAIL")
        if ok:
            k.release()
        try:
            k._sniffer.stop()
        except Exception:
            pass
        return 0 if ok else 1

    pf = acquire_pidfile(a.pidfile)
    try:
        return k.run()
    finally:
        if pf and os.path.exists(pf):
            try:
                os.unlink(pf)
            except Exception:
                pass


if __name__ == "__main__":
    sys.exit(main())
