#!/usr/local/bin/python3
"""Robust DHCP lease-keeper: keep a lease alive for a chosen chaddr.

Keeps a DHCP lease alive for a given ``chaddr`` WITHOUT binding it to the
interface's hardware MAC, so the leased address (typically a CARP virtual IP)
stays routed by the ISP. Lease maintenance ONLY -- ARP for the address and data
traffic are handled by CARP. The BOOTP broadcast flag is set so OFFER/ACK are
broadcast. Optionally (--arp-nudge) it refreshes the upstream gateway's ARP
entry for the leased address, for gateways that never re-ARP an expired entry
(traffic then silently blackholes until they get an ARP *request*). Runs on both
HA nodes for redundancy. Packet capture and send go through a pluggable backend
(--capture-backend): scapy (the default), or a dependency-free raw /dev/bpf
backend (experimental).

Robustness:
  * Full DHCP lifecycle: DORA (Discover/Offer/Request/Ack) -> BOUND, RENEW at
    T1, REBIND at T2, re-DORA at expiry.
  * Single instance via pidfile; heartbeat file (fresh = the lease is renewing).
  * Resilient capture: restarted if its thread dies (e.g. the interface flaps).
  * All I/O wrapped in try/except so the main loop never crashes; a non-zero
    exit lets the supervisor restart it.
  * RELEASE is NOT sent on a normal stop (SIGTERM) -- only with
    --once/--release-on-exit -- so the address is not given up needlessly.

Security posture (this daemon parses untrusted WAN traffic as root):
  * The capture is NOT promiscuous by default: the BOOTP broadcast flag makes
    the server broadcast its replies to a non-promiscuous socket, and the
    gateway's unicast ARP reply to a nudge reaches us because the CARP master
    already accepts the VIP's virtual MAC. --arp-listen-promisc is an opt-in
    fallback (warned when enabled) for NICs that drop non-primary unicast.
  * The BPF filter is the next boundary: only DHCP (udp 67/68) and ARP replies
    reach Python; everything else -- including the who-has flood -- is dropped
    in the kernel.
  * A reply must carry BOOTREPLY; our own xid gates the first-party path, and in
    follow mode a reply on our shared chaddr (the peer's ACK) is read only to
    RECORD an observed address change (see _on_dhcp_reply). Only the DHCP options
    the keeper needs are extracted -- no dissection of the rest (untrusted input).
  * Follow mode never rewrites the CARP VIP from a single ACK: the new address
    is validated (plausibility, routability class, expected server) and
    rate-throttled against flap/spoof storms (see FollowPolicy.on_changed_address).
  * A parse error in the sniffer callback is dropped (debug-logged).

Cooperating with ISP access-network policing (DHCP snooping, Dynamic ARP
Inspection, IP source guard, per-subscriber MAC limits): the lease stays on the
CARP virtual MAC and the ARP nudge is shaped to match the snooped binding, so
the carrier's guards see consistent state. The README's "Playing nicely with
ISP access-network security" section is the full map.

Usage:
  lease_keeper.py --iface <if> --chaddr <mac> --request <ip>
  lease_keeper.py ... --once            # one-shot claim+verify+release (test)
"""
# The daemon must never die on unexpected input: catch-all with logging is
# the documented posture (see "All I/O wrapped in try/except" above).
# pylint: disable=broad-exception-caught
# A single deployable file is a deliberate constraint of this daemon.
# pylint: disable=too-many-lines
import argparse
import ctypes
import ipaddress
import logging
import os
import random
import re
import select
import signal
import struct
import subprocess
import sys
import threading
import time
from collections import namedtuple
from dataclasses import dataclass
from logging.handlers import RotatingFileHandler
from typing import Any

# The raw /dev/bpf backend drives its ioctls through fcntl, which does not
# exist on non-POSIX development hosts. Import it defensively (same pattern as
# scapy below) so the module still loads there; BpfCapture.start() reports the
# missing module at runtime instead.
try:
    import fcntl as _fcntl_module
    # Typed Any: the POSIX-only stubs would flag every ioctl call on the
    # non-POSIX hosts this guard exists for.
    fcntl: Any = _fcntl_module
except ImportError:
    fcntl = None  # pylint: disable=invalid-name

# Scapy is the one heavy third-party dependency (needed only by the default
# scapy capture backend) and the usual suspect when the daemon won't start
# (missing after an upgrade, ABI mismatch, partial install).
# Import it defensively: a bare module-level import that throws would kill the
# process before any log handler exists -> a silent non-start with the traceback
# going to daemon(8)'s /dev/null. Capture it instead and let main() log it once
# logging is configured (only when the scapy backend is actually selected).
try:
    from scapy.all import (  # type: ignore  # pylint: disable=import-error
        ARP, Ether, IP, UDP, BOOTP, DHCP, AsyncSniffer, sendp)
    _SCAPY_IMPORT_ERROR = None
except Exception as _scapy_exc:   # ImportError, or scapy's own import-time failures
    _SCAPY_IMPORT_ERROR = _scapy_exc
    # Bind the names so the module still loads (main() exits with the captured
    # error before any of them is used). Typed Any so type checkers do not
    # flag every scapy call site as calling None.
    _MISSING: Any = None
    ARP = Ether = IP = UDP = BOOTP = DHCP = AsyncSniffer = sendp = _MISSING  # pylint: disable=invalid-name

LOG = logging.getLogger("lease-keeper")

# DHCP message types (RFC 2131).
OFFER, ACK, NAK = 2, 5, 6
BOOTREPLY = 2              # BOOTP op field: a server->client reply (unrelated to OFFER)

# Options we ask the server to include on every DISCOVER/REQUEST (RFC 2132 option
# 55, Parameter Request List). Subnet mask (1) + router (3) drive follow mode's
# cross-subnet decision; lease/server-id/T1/T2 (51/54/58/59) drive renew timing.
# Many servers return ONLY options named in the PRL, so without this the keeper
# can silently miss the mask/router it needs to follow a cross-subnet renumber.
PARAM_REQ_LIST = [1, 3, 51, 54, 58, 59]

# Timing / retry tunables (seconds unless noted).
HB_REFRESH = 30            # rewrite the heartbeat at least this often while holding a lease
DEFAULT_LEASE = 3600       # fallback lease time if the server sends none
DORA_ATTEMPTS = 5          # DISCOVER and REQUEST attempts per acquire
REBOOT_ATTEMPTS = 2        # INIT-REBOOT REQUEST attempts before falling back to a full DISCOVER
RENEW_ATTEMPTS = 3         # REQUEST attempts per renew
REPLY_TIMEOUT = 4          # wait for an OFFER/ACK during acquire
RENEW_TIMEOUT = 3          # wait for an ACK during renew
ATTEMPT_BACKOFF_CAP = 8    # max wait between acquire attempts
SEND_RETRY_DELAY = 2       # wait after a failed packet send before retrying
REBIND_POLL_STEP = 10      # how often to re-try RENEW during the REBIND window
REDORA_MIN = 10            # initial wait after a failed acquire; also the hold-poll cadence while no carrier
# Caps worst-case re-acquire lag at ~45s even if the link-return fast path (below)
# is missed; the backoff doubles 10 -> 20 -> 40 -> 45.
REDORA_MAX = 45            # max exponential-backoff wait after a failed acquire
LINK_POLL_STEP = 3         # while UNBOUND, poll interface carrier this often (s) for the link-return fast path
LINK_KICK_DEBOUNCE = 8     # min seconds between link-return re-DORA kicks (damps a flapping link)
SNIFFER_RETRY = 5          # wait before retrying a failed packet-sniffer start
SNIFFER_WARMUP = 0.5       # let the capture thread attach before the first send
LOOP_ERROR_BACKOFF = 10    # wait after an unexpected main-loop error before retrying
MIN_FOLLOW_INTERVAL = 60   # min seconds between follow (VIP rewrite) events -- damps flap/spoof storms
FOLLOW_RETRY_DEADLINE = 120  # re-drive follow_update if we are not restarted within this after firing
T1_FACTOR = 0.5            # renew at this fraction of the lease (RFC default)
T2_FACTOR = 0.875          # rebind by this fraction of the lease (RFC default)
MIN_T1 = 30                # floor for the renew timer (very short leases)
MIN_LEASE = 2 * MIN_T1     # floor for an accepted lease time, so a tiny (even hostile) opt-51 can't spin renews
REBIND_MARGIN = 15         # ensure T2 is at least this far past T1
BROADCAST_FLAG = 0x8000    # BOOTP flags: ask the server to broadcast OFFER/ACK
ETHER_BROADCAST = "ff:ff:ff:ff:ff:ff"
ETHER_ZERO = "00:00:00:00:00:00"     # ARP "target unknown" hardware address
IPV4_BROADCAST = "255.255.255.255"   # limited broadcast (never routed off-link)
DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68
ARP_NUDGE_MIN = 30         # floor for --arp-nudge so a typo cannot flood the segment
LOG_MAX_BYTES = 512 * 1024
LOG_BACKUPS = 3

# ---- DHCP wire format: parse / format / build ----
# Pure encode/decode helpers with no client state: they turn scapy packets into a
# DhcpReply and turn a message type into an option list. The stateful protocol
# sequences (DORA / INIT-REBOOT / renew) live in the DhcpClient class further down.

# A parsed DHCP reply, snapshotted from the capture thread.
# `message` (DHCP option 56) is the server's optional human-readable text, mainly
# a NAK reason; `subnet_mask` (option 1) is used to follow a cross-subnet renumber;
# `giaddr` (BOOTP header) is the relay agent, None when the server is directly
# attached (no relay in path). The trailing fields are defaulted so existing
# shorter constructions stay valid.
DhcpReply = namedtuple("DhcpReply", "mtype yiaddr server_id lease t1 t2 router message subnet_mask giaddr",
                       defaults=(None, None, None))

# A received BOOTP/DHCP frame in backend-neutral shape: both capture backends
# (scapy packet / raw bytes) decode to this before the keeper sees it. chaddr
# is raw bytes; options is a list of (name, value) tuples in the keeper's own
# option vocabulary (the names in _OPT_ENCODERS/_OPT_DECODERS), which
# _parse_reply reads regardless of backend. The names are deliberately
# scapy-compatible: ScapyCapture relays outbound option lists to scapy
# verbatim (see its docstring).
BootpFrame = namedtuple("BootpFrame", "op xid yiaddr chaddr giaddr options")

# A received ARP frame (the capture filter already narrows ARP to replies, but
# op still travels so the handler re-checks rather than trusting the filter).
ArpFrame = namedtuple("ArpFrame", "op psrc pdst")

# Changed-address phase labels: which exchange saw the differing ACK. Log
# text and policy input at once -- FollowPolicy relaxes its expected-server
# check on PHASE_REBIND (at T2 any server may legitimately answer).
PHASE_DORA = "DORA"
PHASE_REBOOT = "REBOOT"
PHASE_RENEW = "RENEW"
PHASE_REBIND = "REBIND"
PHASE_OBSERVED = "OBSERVED"

# DHCP message-type names (option 53), for readable reply logging.
MTYPE_NAMES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
               5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}


def _msg_text(msg):
    """DHCP option-56 server text (usually a NAK reason) as a sanitized str, or
    "" when absent. Option 56 may arrive as bytes or str depending on the server.

    The text is attacker-controlled (any host on the segment can race a NAK with
    a matching xid) and is written to the log, so strip control characters --
    newlines that would forge log lines and terminal escape sequences -- before
    it goes anywhere. Printable content is preserved."""
    if isinstance(msg, bytes):
        msg = msg.decode(errors="replace")
    if not msg:
        return ""
    return re.sub(r"[\x00-\x1f\x7f]", "?", str(msg)).strip()


def _fmt_reply(rx):
    """One readable line decoding a received first-party DHCP reply. Logged at
    DEBUG (the keeper's default level), so every reply's fields (type, addresses,
    timers, gateway, mask, relay, server text) show in the log without a capture."""
    txt = _msg_text(rx.message)
    mtype = MTYPE_NAMES.get(rx.mtype, f"type={rx.mtype}")
    msg = f" msg={txt!r}" if txt else ""
    return (f"{mtype} yiaddr={rx.yiaddr or '-'} server={rx.server_id or '-'} "
            f"giaddr={rx.giaddr or 'none'} lease={'-' if rx.lease is None else rx.lease} "
            f"t1={'-' if rx.t1 is None else rx.t1} t2={'-' if rx.t2 is None else rx.t2} "
            f"gw={rx.router or '-'} mask={rx.subnet_mask or '-'}{msg}")


def _parse_reply(frame):
    """Snapshot only the handful of DHCP options the keeper acts on from a
    BootpFrame into a DhcpReply; the rest of the reply's option data --
    untrusted, from whatever answered on the wire -- is left untouched."""
    mt = sid = lt = rt = bt = ro = msg = sm = None
    for o in frame.options:
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
            elif o[0] == "subnet_mask":  # option 1: to follow a cross-subnet renumber
                sm = o[1]
    gi = frame.giaddr   # relay agent; 0.0.0.0 = directly attached
    if gi in (None, "0.0.0.0", 0):
        gi = None
    return DhcpReply(mt, frame.yiaddr, sid, lt, rt, bt, ro, msg, sm, gi)


def _dhcp_options(mtype, extra, id_opts):
    """The DHCP option list for a message: type, our Parameter Request List
    (so the server returns the mask/router/timers the keeper acts on), the
    identity options, then the per-message extras."""
    return ([("message-type", mtype), ("param_req_list", PARAM_REQ_LIST)]
            + id_opts + extra + ["end"])


def _mask_to_bits(mask):
    """Dotted-quad subnet mask (DHCP option 1) -> prefix length, or None if absent
    or unparseable."""
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except (ValueError, TypeError):
        return None


MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")


_CGNAT = ipaddress.ip_network("100.64.0.0/10")

# Static BPF capture filter: DHCP (broadcast OFFER/ACK) + ARP replies to our nudge
# (arp[6:2]=2). A boundary, not an optimization -- it keeps everything else (incl. the
# segment's broadcast who-has flood) out of the Python parser.
SNIFFER_FILTER = f"(udp and (port {DHCP_SERVER_PORT} or port {DHCP_CLIENT_PORT})) or (arp and arp[6:2] = 2)"

# ---- raw wire codec (bpf backend) ----
# Hand encoders/decoders for exactly the frames the keeper exchanges, so the
# bpf backend needs no packet library. The decoders parse untrusted WAN input:
# every access is bounds-checked and a malformed frame decodes to None
# (dropped) rather than raising.

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHER_MIN_FRAME = 60         # minimum Ethernet frame (without FCS); short ARP frames are padded
DHCP_MAGIC = b"\x63\x82\x53\x63"   # RFC 2131 options magic cookie
BOOTP_HDR_LEN = 236          # fixed BOOTP header before the magic cookie
BOOTP_MIN_PAYLOAD = 300      # RFC 1542 4.1 minimum BOOTP message; reference clients pad to it
DHCP_OPT_PAD = 0
DHCP_OPT_END = 255
IPPROTO_UDP = 17
IPV4_TTL = 64                # conventional default TTL (BSD/Linux/scapy send 64)

# DHCP message types the keeper SENDS, by the names the option lists carry
# (the inverse, code -> display name, is MTYPE_NAMES above).
_MTYPE_CODES = {"discover": 1, "request": 3, "release": 7}


def _ip4(ip):
    """Dotted-quad string (None -> 0.0.0.0) -> 4 raw bytes."""
    return ipaddress.IPv4Address(ip or "0.0.0.0").packed


def _ip4_str(raw):
    """4 raw bytes -> dotted-quad string."""
    return str(ipaddress.IPv4Address(bytes(raw)))


def _opt_text(v):
    """Text-ish option value -> bytes (client-id arrives pre-encoded)."""
    return v if isinstance(v, bytes) else str(v).encode()


# Outbound option encoders: option name -> (wire code, value encoder) for
# exactly the options the keeper sends. These names ARE the keeper's option
# vocabulary (BootpFrame.options and _dhcp_options use them).
_OPT_ENCODERS = {
    "message-type": (53, lambda v: bytes([_MTYPE_CODES[v]])),
    "param_req_list": (55, bytes),        # list of option codes
    "requested_addr": (50, _ip4),
    "server_id": (54, _ip4),
    "hostname": (12, _opt_text),
    "vendor_class_id": (60, _opt_text),
    "client_id": (61, _opt_text),
}


def _encode_dhcp_options(options):
    """A scapy-style option list (name/value tuples + "end") -> the raw options
    field. Options with a None value are dropped (a broadcast RELEASE carries
    no server-id); the end option is always appended."""
    out = bytearray()
    for o in options:
        if not isinstance(o, tuple) or o[1] is None:
            continue   # the "end" marker (appended below) or a valueless option
        code, encode = _OPT_ENCODERS[o[0]]
        raw = encode(o[1])
        out += bytes([code, len(raw)]) + raw
    out.append(DHCP_OPT_END)
    return bytes(out)


def _encode_bootp_request(chaddr, xid, ciaddr, flags, options):
    """A BOOTREQUEST payload: fixed BOOTP header + cookie + options, padded to
    the RFC 1542 minimum message size (some servers drop shorter ones)."""
    hdr = struct.pack("!4BIHH", 1, 1, 6, 0, xid, 0, flags)   # op htype hlen hops xid secs flags
    hdr += _ip4(ciaddr) + b"\x00" * 12                       # ciaddr, then yiaddr/siaddr/giaddr zero
    hdr += chaddr.ljust(16, b"\x00")[:16]                    # chaddr field (16 bytes)
    hdr += b"\x00" * 192                                     # sname (64) + file (128), unused
    payload = hdr + DHCP_MAGIC + _encode_dhcp_options(options)
    return payload.ljust(BOOTP_MIN_PAYLOAD, b"\x00")


def _inet_checksum(data):
    """RFC 1071 ones-complement sum over 16-bit words (odd length zero-padded)."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(int.from_bytes(data[i:i + 2], "big") for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _encode_ipv4_udp(src, dst, sport, dport, payload):
    """An IPv4+UDP datagram around payload, checksums computed. A UDP checksum
    of 0 means "none sent", so a sum that works out to 0 transmits as 0xFFFF
    (RFC 768)."""
    udp_len = 8 + len(payload)
    pseudo = _ip4(src) + _ip4(dst) + struct.pack("!BBH", 0, IPPROTO_UDP, udp_len)
    udp_hdr = struct.pack("!4H", sport, dport, udp_len, 0)
    cksum = _inet_checksum(pseudo + udp_hdr + payload) or 0xFFFF
    udp_hdr = struct.pack("!4H", sport, dport, udp_len, cksum)
    # version/ihl, tos, total, id, flags/frag, ttl, proto, checksum (zeroed, then patched)
    ip_hdr = struct.pack("!BBHHHBBH", 0x45, 0, 20 + udp_len, 0, 0, IPV4_TTL, IPPROTO_UDP, 0) + _ip4(src) + _ip4(dst)
    ip_hdr = ip_hdr[:10] + _inet_checksum(ip_hdr).to_bytes(2, "big") + ip_hdr[12:]
    return ip_hdr + udp_hdr + payload


def _encode_ether(dst, src, ethertype, payload):
    """An Ethernet II frame."""
    return mac2raw(dst) + mac2raw(src) + ethertype.to_bytes(2, "big") + payload


# The fixed Ethernet/IPv4 ARP header prefix (htype/ptype/hlen/plen), shared by
# the encoder and the decoder so the two cannot drift.
_ARP_ETH_IPV4 = struct.pack("!HHBB", 1, ETHERTYPE_IPV4, 6, 4)


def _encode_arp_request(hwsrc, psrc, pdst):
    """An ARP who-has pdst tell psrc with sender hardware hwsrc (the nudge
    frame; the shaping rationale lives at the ArpNudge call site)."""
    return (_ARP_ETH_IPV4 + struct.pack("!H", 1)
            + mac2raw(hwsrc) + _ip4(psrc) + mac2raw(ETHER_ZERO) + _ip4(pdst))


def _u32(v):
    """4-byte big-endian option value -> int (a shorter value is malformed)."""
    if len(v) < 4:
        raise ValueError("short integer option")
    return int.from_bytes(v[:4], "big")


def _first_ip(v):
    """First IPv4 address in an option value (option 3 may list several)."""
    if len(v) < 4:
        raise ValueError("short address option")
    return _ip4_str(v[:4])


# Inbound option decoders: wire code -> (option name, value decoder) for
# exactly the options _parse_reply acts on; everything else is skipped unread
# (untrusted input, narrow surface).
_OPT_DECODERS = {
    1: ("subnet_mask", _first_ip),
    3: ("router", _first_ip),
    51: ("lease_time", _u32),
    53: ("message-type", lambda v: v[0]),
    54: ("server_id", _first_ip),
    56: ("message", bytes),
    58: ("renewal_time", _u32),
    59: ("rebinding_time", _u32),
}


def _decode_dhcp_options(data):
    """Bounds-checked TLV walk over the options field of an untrusted reply.
    Unknown options are skipped without decoding; any truncation ends the walk
    with what was parsed so far. Never raises on malformed input.

    Option overload (option 52), where a server continues its options into the
    BOOTP sname/file fields, is deliberately NOT handled: with the keeper's
    6-entry parameter request list every reply fits the options field many
    times over, so no server the keeper talks to overloads."""
    options = []
    pos = 0
    while pos < len(data):
        code = data[pos]
        if code == DHCP_OPT_PAD:        # a single padding byte, no length/value
            pos += 1
            continue
        if code == DHCP_OPT_END:        # explicit end of options
            break
        if pos + 2 > len(data):         # the length byte itself is missing
            break
        length = data[pos + 1]
        value = data[pos + 2:pos + 2 + length]
        if len(value) < length:         # the value runs past the end of the buffer
            break
        decoder = _OPT_DECODERS.get(code)
        if decoder is not None:
            name, decode_value = decoder
            try:
                options.append((name, decode_value(value)))
            except (ValueError, IndexError):
                pass                    # malformed value in a known option: skip, keep walking
        pos += 2 + length
    return options


def _decode_arp(pkt):
    """Raw ARP payload -> ArpFrame, or None unless it is a well-formed
    Ethernet/IPv4 ARP."""
    if len(pkt) < 28 or pkt[:6] != _ARP_ETH_IPV4:
        return None
    return ArpFrame(int.from_bytes(pkt[6:8], "big"), _ip4_str(pkt[14:18]), _ip4_str(pkt[24:28]))


def _decode_ipv4_bootp(pkt):
    """Raw IPv4 payload of an Ethernet frame -> BootpFrame, or None unless it
    is an unfragmented UDP datagram carrying a plausible BOOTP message with
    the DHCP cookie. Every bound is checked (untrusted WAN input)."""
    if len(pkt) < 20 or pkt[0] >> 4 != 4:
        return None
    ihl = (pkt[0] & 0x0F) * 4
    total = int.from_bytes(pkt[2:4], "big")
    if ihl < 20 or total < ihl + 8 or len(pkt) < ihl + 8:
        return None
    is_udp = pkt[9] == IPPROTO_UDP
    is_unfragmented = (int.from_bytes(pkt[6:8], "big") & 0x3FFF) == 0   # no MF bit, no frag offset
    if not (is_udp and is_unfragmented):
        return None
    # Bound the BOOTP slice by the UDP length too, not just the IP total: a
    # datagram whose UDP length is shorter than the IP payload would otherwise
    # let trailing bytes be parsed as DHCP options. Trust the smallest of the
    # three lengths (untrusted input); a UDP length shorter than its own header
    # is malformed.
    udp_len = int.from_bytes(pkt[ihl + 4:ihl + 6], "big")
    if udp_len < 8:
        return None
    end = min(total, ihl + udp_len, len(pkt))
    bootp = pkt[ihl + 8:end]                        # UDP payload, minus any link padding
    if len(bootp) < BOOTP_HDR_LEN + 4 or bootp[BOOTP_HDR_LEN:BOOTP_HDR_LEN + 4] != DHCP_MAGIC:
        return None
    # The options walk only pays off for server replies; on a shared segment
    # the filter also passes other clients' broadcast BOOTREQUESTs, which the
    # keeper drops on op anyway -- skip their TLV walk in this hot path.
    op = bootp[0]
    return BootpFrame(op=op,
                      xid=int.from_bytes(bootp[4:8], "big"),
                      yiaddr=_ip4_str(bootp[16:20]),
                      chaddr=bytes(bootp[28:44]),
                      giaddr=_ip4_str(bootp[24:28]),
                      options=_decode_dhcp_options(bootp[BOOTP_HDR_LEN + 4:]) if op == BOOTREPLY else [])


# ---- /dev/bpf plumbing (bpf backend) ----
# FreeBSD ioctl codes for the LP64 platforms OPNsense ships on (amd64/aarch64),
# precomputed from net/bpf.h so no C headers are needed at runtime.
BIOCGBLEN = 0x40044266       # _IOR('B', 102, u_int): kernel capture buffer size
BIOCSETF = 0x80104267        # _IOW('B', 103, struct bpf_program): attach the filter
BIOCPROMISC = 0x20004269     # _IO('B', 105): promiscuous mode
BIOCGDLT = 0x4004426A        # _IOR('B', 106, u_int): the interface's data-link type
BIOCSETIF = 0x8020426C       # _IOW('B', 108, struct ifreq): bind to the interface
BIOCIMMEDIATE = 0x80044270   # _IOW('B', 112, u_int): deliver per packet, not per full buffer
BIOCSHDRCMPLT = 0x80044275   # _IOW('B', 117, u_int): we supply the Ethernet source MAC
DLT_EN10MB = 1               # Ethernet: the only link type this codec's offsets assume
BPF_ALIGNMENT = 8            # capture records align to sizeof(long)
BPF_HDR_FIXED = 26           # bh_tstamp(16) + bh_caplen(4) + bh_datalen(4) + bh_hdrlen(2)

# SNIFFER_FILTER compiled to classic-BPF opcodes, embedded so the daemon needs
# no runtime filter compiler. MUST stay in lockstep with SNIFFER_FILTER;
# regenerate on any FreeBSD/OPNsense host with:
#   tcpdump -i <ethernet-iface> -dd '(udp and (port 67 or port 68)) or (arp and arp[6:2] = 2)'
# The trailing comment on each row is the `tcpdump -d` mnemonic so the table can
# be audited by eye against the filter string without a FreeBSD box; jump
# targets are absolute instruction indices (tcpdump's relative jt/jf + here+1).
# A bench test (testbench repo) asserts `tcpdump -ddd SNIFFER_FILTER` still
# equals this table, turning the lockstep requirement into an enforced invariant.
_BPF_FILTER = (
    (0x28, 0, 0, 0x0000000C),   # 00 ldh  [12]                 ; ethertype
    (0x15, 0, 10, 0x00000800),  # 01 jeq  #0x800  -> 02, ->12  ; IPv4?
    (0x30, 0, 0, 0x00000017),   # 02 ldb  [23]                 ; IPv4 proto
    (0x15, 0, 21, 0x00000011),  # 03 jeq  #17     -> 04, ->25  ; UDP?
    (0x28, 0, 0, 0x00000014),   # 04 ldh  [20]                 ; flags+frag
    (0x45, 19, 0, 0x00001FFF),  # 05 jset #0x1fff ->25, -> 06  ; fragment? drop
    (0xB1, 0, 0, 0x0000000E),   # 06 ldxb 4*([14]&0xf)         ; X = IP hdr len
    (0x48, 0, 0, 0x0000000E),   # 07 ldh  [x+14]               ; UDP src port
    (0x15, 15, 0, 0x00000043),  # 08 jeq  #67     ->24, -> 09  ; sport 67? accept
    (0x15, 14, 0, 0x00000044),  # 09 jeq  #68     ->24, -> 10  ; sport 68? accept
    (0x48, 0, 0, 0x00000010),   # 10 ldh  [x+16]               ; UDP dst port
    (0x15, 12, 8, 0x00000043),  # 11 jeq  #67     ->24, ->20   ; dport 67? accept
    (0x15, 0, 8, 0x000086DD),   # 12 jeq  #0x86dd -> 13, ->21  ; IPv6? (else ARP)
    (0x30, 0, 0, 0x00000014),   # 13 ldb  [20]                 ; IPv6 next header
    (0x15, 0, 10, 0x00000011),  # 14 jeq  #17     -> 15, ->25  ; UDP?
    (0x28, 0, 0, 0x00000036),   # 15 ldh  [54]                 ; UDP src port (14+40)
    (0x15, 7, 0, 0x00000043),   # 16 jeq  #67     ->24, -> 17  ; sport 67? accept
    (0x15, 6, 0, 0x00000044),   # 17 jeq  #68     ->24, -> 18  ; sport 68? accept
    (0x28, 0, 0, 0x00000038),   # 18 ldh  [56]                 ; UDP dst port
    (0x15, 4, 0, 0x00000043),   # 19 jeq  #67     ->24, ->20   ; dport 67? accept
    (0x15, 3, 4, 0x00000044),   # 20 jeq  #68     ->24, ->25   ; dport 68? accept
    (0x15, 0, 3, 0x00000806),   # 21 jeq  #0x806  -> 22, ->25  ; ARP?
    (0x28, 0, 0, 0x00000014),   # 22 ldh  [20]                 ; ARP opcode
    (0x15, 0, 1, 0x00000002),   # 23 jeq  #2      ->24, ->25   ; is-at reply?
    (0x6, 0, 0, 0x00040000),    # 24 ret  #262144              ; ACCEPT (snap len)
    (0x6, 0, 0, 0x00000000),    # 25 ret  #0                   ; DROP
)


def _bpf_align(nbytes):
    """Round a record length up to the BPF record alignment (sizeof(long))."""
    return (nbytes + BPF_ALIGNMENT - 1) & ~(BPF_ALIGNMENT - 1)


def _bpf_frames(data):
    """Yield each captured Ethernet frame from a raw BPF read buffer.

    One read(2) can return several packets back to back, each prefixed by a
    struct bpf_hdr and padded to the record alignment. bh_tstamp occupies the
    first 16 bytes; bh_caplen, bh_datalen and bh_hdrlen follow. A record whose
    header or length is inconsistent ends the walk rather than risk misparsing
    the rest of the buffer (it is only as trustworthy as the kernel handed it
    over)."""
    pos = 0
    while pos + BPF_HDR_FIXED <= len(data):
        # bh_caplen (u_int), bh_datalen (u_int), bh_hdrlen (u_short), in host
        # byte order, immediately after the 16-byte bh_tstamp.
        caplen, _datalen, hdrlen = struct.unpack_from("=IIH", data, pos + 16)
        record_end = pos + hdrlen + caplen
        if hdrlen < BPF_HDR_FIXED or record_end > len(data):
            break
        yield data[pos + hdrlen:record_end]
        pos += _bpf_align(hdrlen + caplen)


# ---- capture backends ----
# Both backends expose the same surface: start/stop/alive for the capture
# side (decoded BootpFrame/ArpFrame handed to the constructor callbacks on
# the capture thread) and send_dhcp/send_arp_request for the send side.

def _deliver(handler, frame):
    """Run a keeper frame callback under its own guard: a failure in there is
    a handler bug, not a parse error, and must neither kill the capture
    thread nor be mislabelled as malformed input."""
    if frame is None:
        return
    try:
        handler(frame)
    except Exception as e:
        LOG.debug("frame handler error: %s", e)


class ScapyCapture:
    """Capture/send via scapy (AsyncSniffer + sendp): the default backend.
    Decodes scapy packets into the same neutral frames as the bpf backend, so
    the rest of the keeper never touches a packet object. Outbound option
    lists are relayed to scapy verbatim, which is why the keeper's option
    vocabulary must stay scapy-compatible."""

    def __init__(self, iface, promisc, on_bootp, on_arp):
        self.iface = iface
        self.promisc = promisc
        self._on_bootp = on_bootp
        self._on_arp = on_arp
        self._sniffer = None

    def start(self):
        """(Re)start the sniffer. False on failure (the caller retries)."""
        try:
            self.stop()
            # Non-promiscuous by default: the BOOTP broadcast flag makes the
            # server broadcast OFFER/ACK, and the gateway's unicast ARP reply to a
            # nudge reaches us because the CARP master already accepts the VIP's
            # virtual MAC. promisc is the opt-in fallback for NICs that
            # drop non-primary unicast (widens capture -- warned at startup).
            self._sniffer = AsyncSniffer(
                iface=self.iface, filter=SNIFFER_FILTER,
                prn=self._on_packet, store=0, promisc=self.promisc)
            self._sniffer.start()
            return True
        except Exception as e:
            LOG.error("DHCP-reply sniffer start failed: %s", e)
            return False

    def stop(self):
        """Best-effort capture stop (scapy may raise if it never ran).

        Join with a bound: scapy's own stop() joins the sniffer thread with no
        timeout, so a sniffer that fails to break its loop would hang the main
        thread here -- and because this runs from _ensure_sniffer mid-sequence,
        that would freeze the heartbeat and trip a false CARP demotion. Ask it
        not to join, then join the thread ourselves with a ceiling."""
        try:
            if self._sniffer:
                self._sniffer.stop(join=False)
                thread = getattr(self._sniffer, "thread", None)
                if thread is not None:
                    thread.join(timeout=2)
        except Exception:
            pass

    def alive(self):
        """True while the sniffer thread is running."""
        thread = getattr(self._sniffer, "thread", None)
        return thread is not None and thread.is_alive()

    def _on_packet(self, p):
        """Sniffer callback: scapy packet -> neutral frame -> keeper callback
        (via _deliver, so a handler failure is labelled as such). A parse
        error in the untrusted input is dropped (debug-logged)."""
        frame = handler = None
        try:
            if p.haslayer(BOOTP) and p.haslayer(DHCP):
                b = p[BOOTP]
                try:
                    chaddr = bytes(getattr(b, "chaddr", b"") or b"")
                except (TypeError, ValueError):
                    chaddr = b""
                frame = BootpFrame(b.op, b.xid, b.yiaddr, chaddr,
                                   getattr(b, "giaddr", None), p[DHCP].options)
                handler = self._on_bootp
            elif p.haslayer(ARP):
                arp = p[ARP]
                frame, handler = ArpFrame(arp.op, arp.psrc, arp.pdst), self._on_arp
        except Exception as e:
            LOG.debug("sniffed packet parse error: %s", e)
            return
        _deliver(handler, frame)

    # The DHCP wire tuple: one parameter per field that goes on the wire.
    def send_dhcp(self, *, eth_src, ip_src, ip_dst, chaddr,  # pylint: disable=too-many-arguments
                  xid, ciaddr, flags, options):
        """Broadcast one DHCP client message as scapy layers."""
        sendp(Ether(src=eth_src, dst=ETHER_BROADCAST) /
              IP(src=ip_src, dst=ip_dst) /
              UDP(sport=DHCP_CLIENT_PORT, dport=DHCP_SERVER_PORT) /
              BOOTP(chaddr=chaddr, xid=xid, ciaddr=ciaddr, flags=flags) /
              DHCP(options=options),
              iface=self.iface, verbose=0)

    def send_arp_request(self, hwsrc, psrc, pdst):
        """Broadcast an ARP who-has pdst tell psrc from hwsrc."""
        sendp(Ether(src=hwsrc, dst=ETHER_BROADCAST) /
              ARP(op=1, hwsrc=hwsrc, psrc=psrc,
                  hwdst=ETHER_ZERO, pdst=pdst),
              iface=self.iface, verbose=0)


class BpfCapture:  # pylint: disable=too-many-instance-attributes
    """Capture/send on a raw /dev/bpf descriptor -- no packet library. A
    reader thread walks the BPF buffer and hands decoded neutral frames to
    the same callbacks the scapy backend feeds. FreeBSD-only (OPNsense's
    platform); selected with --capture-backend bpf (experimental).

    Shutdown uses a self-pipe rather than a poll timeout: the reader blocks in
    select() on both the bpf fd and a wake pipe, and stop() writes one byte to
    the pipe so the reader returns at once (no periodic wakeups, no up-to-1s
    stop latency). The stop signal and the wake pipe are created fresh per
    start(), and the reader owns and closes its own bpf fd on exit, so a reader
    that outlives its stop() (e.g. stalled in a slow log write) can neither be
    revived by the next start() nor have its fd number reused underneath it."""

    def __init__(self, iface, promisc, on_bootp, on_arp):
        self.iface = iface
        self.promisc = promisc
        self._on_bootp = on_bootp
        self._on_arp = on_arp
        self._fd = None                # the live capture fd, or None when stopped
        self._buflen = 0               # kernel buffer size, from BIOCGBLEN in _configure
        self._thread = None            # the current reader thread
        self._stop_event = None        # set to ask the current reader to exit
        self._wake_writer = None       # write end of this generation's wake pipe

    def start(self):
        """(Re)open /dev/bpf, bind + filter it to the interface, and start the
        reader thread. Returns False on any failure (the caller retries)."""
        if fcntl is None:
            LOG.error("bpf backend unavailable: no fcntl module on this platform")
            return False
        self.stop()
        wake_reader, wake_writer = os.pipe()
        try:
            fd = os.open("/dev/bpf", os.O_RDWR)
        except OSError as e:
            os.close(wake_reader)
            os.close(wake_writer)
            LOG.error("bpf capture start failed on %s: %s", self.iface, e)
            return False
        try:
            self._configure(fd)
        except Exception as e:
            os.close(fd)
            os.close(wake_reader)
            os.close(wake_writer)
            LOG.error("bpf capture start failed on %s: %s", self.iface, e)
            return False
        stop_event = threading.Event()
        # The reader owns fd and wake_reader and closes them when it exits.
        self._thread = threading.Thread(
            target=self._read_loop, args=(fd, wake_reader, stop_event),
            name="bpf-capture", daemon=True)
        self._fd = fd
        self._stop_event = stop_event
        self._wake_writer = wake_writer
        self._thread.start()
        return True

    def _configure(self, fd):
        """Bind, tune and filter a fresh bpf descriptor.

        BIOCSETIF (bind) has to come first -- it is what libpcap does and what
        BIOCGDLT needs -- so the filter is attached immediately after, keeping
        the window in which the descriptor would accept unfiltered traffic to a
        single ioctl."""
        fcntl.ioctl(fd, BIOCSETIF, struct.pack("16s16x", self.iface.encode()))
        # The codec's frame offsets assume Ethernet; a PPPoE/tun WAN would make
        # both capture and injection meaningless. Fail loudly instead of leaving
        # only a "no DHCP OFFER" symptom.
        dlt = struct.unpack("I", fcntl.ioctl(fd, BIOCGDLT, b"\x00" * 4))[0]
        if dlt != DLT_EN10MB:
            raise OSError(f"{self.iface} is not Ethernet (bpf data-link type {dlt}); "
                          "the bpf backend supports Ethernet only")
        # Attach the capture filter right after the bind (and before the rest of
        # the tuning) so almost no unfiltered traffic can enter the buffer.
        program = b"".join(struct.pack("HBBI", *insn) for insn in _BPF_FILTER)
        program_buf = ctypes.create_string_buffer(program)   # kernel copies it during the ioctl
        # struct bpf_program is { u_int bf_len; struct bpf_insn *bf_insns; };
        # "@IQ" gives the native u_int + pointer layout on LP64.
        fcntl.ioctl(fd, BIOCSETF,
                    struct.pack("@IQ", len(_BPF_FILTER), ctypes.addressof(program_buf)))
        # Immediate mode: hand packets over as they arrive; the DHCP exchanges
        # wait on second-scale timeouts, so buffering a full block is not an option.
        fcntl.ioctl(fd, BIOCIMMEDIATE, struct.pack("I", 1))
        # Header-complete: our frames carry the CARP vMAC as the Ethernet source;
        # without this the kernel would overwrite it with the NIC's own MAC.
        fcntl.ioctl(fd, BIOCSHDRCMPLT, struct.pack("I", 1))
        if self.promisc:
            fcntl.ioctl(fd, BIOCPROMISC)
        # bpf read(2) calls must request exactly the kernel buffer size.
        self._buflen = struct.unpack("I", fcntl.ioctl(fd, BIOCGBLEN, b"\x00" * 4))[0]

    def stop(self):
        """Ask the current reader to exit and wait briefly for it. The reader
        closes its own fd, so stop() only signals and joins; a reader still
        alive after the join (stuck in a slow callback) is left to exit on its
        own -- it holds its own fd, so nothing here can be reused under it."""
        thread = self._thread
        stop_event = self._stop_event
        wake_writer = self._wake_writer
        self._fd = None
        self._thread = None
        self._stop_event = None
        self._wake_writer = None

        if stop_event is not None:
            stop_event.set()
        if wake_writer is not None:
            try:
                os.write(wake_writer, b"\x00")   # wake the reader's select() at once
            except OSError:
                pass
            try:
                os.close(wake_writer)
            except OSError:
                pass
        if thread is not None and thread.is_alive():
            thread.join(timeout=2)
            if thread.is_alive():
                LOG.warning("bpf reader did not exit within 2s -- leaving it to "
                            "finish; its fd is not reused")

    def alive(self):
        """True while the descriptor is open and the reader thread runs."""
        return self._fd is not None and self._thread is not None and self._thread.is_alive()

    def _read_loop(self, fd, wake_reader, stop_event):
        """Reader thread: block in select() on the bpf fd and the wake pipe;
        stop() writes to the pipe to end the wait. Owns fd and wake_reader and
        closes both on exit, so the fd's lifetime ends exactly when this thread
        does."""
        try:
            while not stop_event.is_set():
                try:
                    readable, _, _ = select.select([fd, wake_reader], [], [])
                except OSError:
                    return
                if wake_reader in readable:      # stop() rang -- loop condition ends us
                    continue
                try:
                    data = os.read(fd, self._buflen)
                except (OSError, ValueError):
                    if not stop_event.is_set():
                        LOG.warning("bpf read failed -- capture thread exiting")
                    return
                for frame in _bpf_frames(data):
                    self._dispatch(frame)
        finally:
            for owned_fd in (fd, wake_reader):
                try:
                    os.close(owned_fd)
                except OSError:
                    pass

    def _dispatch(self, frame):
        """Decode one captured Ethernet frame and route it by ethertype to the
        keeper callback (via _deliver, so a handler failure is labelled as
        such). A parse error in the untrusted input is dropped (debug-logged)."""
        decoded = None
        handler = None
        try:
            if len(frame) >= 14:
                ethertype = int.from_bytes(frame[12:14], "big")
                if ethertype == ETHERTYPE_ARP:
                    decoded, handler = _decode_arp(frame[14:]), self._on_arp
                elif ethertype == ETHERTYPE_IPV4:
                    decoded, handler = _decode_ipv4_bootp(frame[14:]), self._on_bootp
        except Exception as e:
            LOG.debug("bpf frame parse error: %s", e)
            return
        _deliver(handler, decoded)

    def _write(self, frame):
        """Inject one raw Ethernet frame on the interface. Main-thread only (the
        capture thread never sends), so reading self._fd needs no lock."""
        fd = self._fd
        if fd is None:
            raise OSError("bpf capture not started")
        os.write(fd, frame)

    # The DHCP wire tuple: one parameter per field that goes on the wire.
    def send_dhcp(self, *, eth_src, ip_src, ip_dst, chaddr,  # pylint: disable=too-many-arguments
                  xid, ciaddr, flags, options):
        """Broadcast one DHCP client message as raw encoded frames."""
        payload = _encode_bootp_request(chaddr, xid, ciaddr, flags, options)
        dgram = _encode_ipv4_udp(ip_src, ip_dst, DHCP_CLIENT_PORT, DHCP_SERVER_PORT, payload)
        self._write(_encode_ether(ETHER_BROADCAST, eth_src, ETHERTYPE_IPV4, dgram))

    def send_arp_request(self, hwsrc, psrc, pdst):
        """Broadcast an ARP who-has pdst tell psrc from hwsrc."""
        frame = _encode_ether(ETHER_BROADCAST, hwsrc, ETHERTYPE_ARP,
                              _encode_arp_request(hwsrc, psrc, pdst))
        self._write(frame.ljust(ETHER_MIN_FRAME, b"\x00"))   # runt guard: ARP is 42 bytes bare


# The capture-backend registry: flag value -> implementation. The argparse
# choices and Keeper's lookup both read this, so a future backend is added in
# exactly one place (plus its rc.conf documentation).
CAPTURE_BACKENDS = {"scapy": ScapyCapture, "bpf": BpfCapture}


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
    """Filesystem-safe token (keeperconf.keeper_id mirrors this charset for
    the configd scripts)."""
    return re.sub(r"[^A-Za-z0-9]", "_", s or "")


def _new_xid():
    """A fresh random transaction id (nonzero 32-bit, regenerated per exchange
    so stale replies cannot match)."""
    return random.randint(1, 0xFFFFFFFF)


def _jittered(base):
    """A retransmit/backoff delay with +/-25% uniform jitter (RFC 2131 4.1
    recommends a randomized backoff). Both HA nodes share the chaddr, so
    jittering the acquire and REBIND retransmit cadences keeps them from
    broadcasting in lockstep and colliding at the server. (The T1/T2 lease
    timers are deterministic and shared too, but jittering those is a
    lease-timing change, not a 4.1 retransmit concern, so they stay exact.)"""
    return base * random.uniform(0.75, 1.25)


def mac2raw(m):
    """Colon/dash-separated MAC string -> 6 raw bytes (BOOTP chaddr)."""
    return bytes.fromhex(m.replace(":", "").replace("-", ""))


def _atomic_write(path, content):
    """Write via tmp + rename so a crash mid-write cannot leave a partial file."""
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(content)
    os.replace(tmp, path)


def _clock_at(offset):
    """Local wall-clock HH:MM of a moment `offset` seconds from now. Log
    lines state future moments (renew/rebind/lease expiry) as relative
    durations; the clock time saves the reader the mental arithmetic."""
    return time.strftime("%H:%M", time.localtime(time.time() + offset))


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
        self._capture.send_dhcp(
            eth_src=self.eth_src, ip_src=ciaddr, ip_dst=IPV4_BROADCAST,
            chaddr=self.chraw, xid=self.xid, ciaddr=ciaddr, flags=BROADCAST_FLAG,
            options=_dhcp_options(mtype, extra, self._id_opts))

    def _wait_for_dhcp_reply(self, want, timeout):
        """Wait up to timeout for a reply of message-type `want`. Returns the
        DhcpReply on match, the string "NAK" on DHCPNAK, or None on timeout.
        Returning the snapshot avoids re-reading self._rx (set by the sniffer
        thread) after the wait."""
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
                return "NAK"
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
            if rx == "NAK":
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
            if rx == "NAK":
                return False   # NAK -> back to INIT; the run loop re-acquires (DISCOVER)
            if rx:
                got = rx.yiaddr
                if request_ip and got != request_ip:
                    return self._on_changed(got, rx, PHASE_DORA, True)
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
            if rx == "NAK":
                return False   # server refused our known address -> full DISCOVER
            if rx:
                got = rx.yiaddr
                if got and got != request_ip:
                    return self._on_changed(got, rx, PHASE_REBOOT, True)
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

        opts = []
        for _ in range(RENEW_ATTEMPTS):
            if self._should_stop():
                return False
            self._ensure_sniffer()
            self._rx = None
            try:
                self._send_dhcp("request", opts, ciaddr=yiaddr)
            except Exception as e:
                LOG.error("DHCP %s send failed: %s", PHASE_REBIND if rebind else PHASE_RENEW, e)
                return False
            rx = self._wait_for_dhcp_reply(ACK, RENEW_TIMEOUT)
            if rx == "NAK":
                return False   # NAK -> re-DORA
            if rx:
                got = rx.yiaddr
                if got and got != self.binding.yiaddr:
                    # Some dynamic servers change the address at renewal (ACK with a
                    # new yiaddr) instead of NAKing. Route it through the same
                    # follow / enforce decision (and hardening) as the initial DORA.
                    phase = PHASE_REBIND if rebind else PHASE_RENEW
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
            self._capture.send_dhcp(
                eth_src=self.eth_src, ip_src=yiaddr, ip_dst=server or IPV4_BROADCAST,
                chaddr=self.chraw, xid=self.xid, ciaddr=yiaddr, flags=0,
                options=[("message-type", "release"), ("server_id", server), "end"])
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


class ArpNudge:  # pylint: disable=too-many-instance-attributes
    """Keep the upstream gateway's ARP entry for the leased address fresh, for
    gateways that ignore gratuitous ARP and never re-ARP an expired entry (see
    the README's "ARP nudge" section). Owns the nudge pacing and the gateway
    reachability stamp; the caller supplies the current lease binding
    (yiaddr, gateway) per call and a CARP-role probe at construction -- never
    nudge from a backup (it would steal the VIP's traffic), so anything but a
    confirmed MASTER fails closed (the next interval retries)."""

    def __init__(self, capture, chaddr, interval, is_master):
        self._capture = capture
        self.chaddr = chaddr
        # Interval floor so a typo cannot flood the segment; 0 = disabled.
        self.interval = max(ARP_NUDGE_MIN, interval) if interval else 0
        self._is_master = is_master    # callable -> True/False/None (None = probe failed)

        self.last_nudge = 0.0          # epoch of the last sent nudge (0 = never)
        # Reachability: the sniffer stamps last_reply when the gateway answers
        # a nudge (a lone atomic float write); the status page surfaces its age.
        self.last_reply = 0.0          # epoch of the gateway's last ARP reply (0 = none)
        self._gw = None                # last nudge target we logged (log again on change)
        self._warned = False           # warned once about a missing nudge target

    def maybe_nudge(self, yiaddr, gateway, force=False):
        """Refresh the gateway's ARP entry for yiaddr by broadcasting an ARP
        request from (yiaddr, chaddr). No-op unless enabled, bound, due (or
        forced) and CARP master."""
        if not self.interval or not yiaddr:
            return
        if not force and time.time() - self.last_nudge < self.interval:
            return
        if self._is_master() is not True:
            return

        if not gateway:
            # Enabled but no target: without this warning the nudge would be a
            # silent no-op and the operator would believe they are protected.
            if not self._warned:
                LOG.warning("ARP nudge enabled but no gateway known "
                            "(no DHCP router option or server-id) -- cannot nudge")
                self._warned = True
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
            self._capture.send_arp_request(self.chaddr, yiaddr, gateway)
            self.last_nudge = time.time()
            # Log the first nudge (and any target change) at INFO so the default log
            # shows the nudge is active; routine repeats at DEBUG (they fire oftener
            # than DHCP renews). Whether the gateway actually answered is surfaced by
            # age on the status page (via last_reply -> the heartbeat's arpok=).
            if gateway != self._gw:
                LOG.info("ARP nudge active: who-has %s tell %s (src %s) every %ds",
                         gateway, yiaddr, self.chaddr, self.interval)
                self._gw = gateway
            else:
                LOG.debug("ARP nudge sent: who-has %s tell %s", gateway, yiaddr)
        except Exception as e:
            LOG.warning("ARP nudge failed (target %s): %s", gateway, e)

    def on_arp_reply(self, frame, yiaddr, gateway):
        """Stamp last_reply when the gateway answers our nudge -- a reachability
        signal the status page surfaces by age. Only the reply to OUR who-has
        counts: op=2 (is-at), sender = the nudge target gateway, target = our
        leased IP. Runs on the capture thread; the stamp is a lone atomic write.
        Advisory only (an on-segment attacker could forge or withhold it);
        nothing here feeds lease/CARP/follow decisions."""
        if frame.op != 2:                       # 2 = is-at (reply); requests are filtered out in BPF
            return
        if not gateway or not yiaddr:
            return
        if frame.psrc == gateway and frame.pdst == yiaddr:
            self.last_reply = time.time()
            LOG.debug("ARP reply from %s (is-at) for %s", gateway, yiaddr)


class FollowPolicy:  # pylint: disable=too-many-instance-attributes
    """Decides what happens when the server grants a DIFFERENT address than
    the target this keeper exists to hold. In follow mode: validate the new
    address (plausibility, routability class, expected server), throttle
    against flap/spoof storms, drive the configd VIP rewrite and adopt it
    into the DHCP client. Otherwise (enforce, a fixed reservation): alarm,
    release the refused grant and stay unbound. Owns the target address
    (rewritten on a successful follow), the persisted follow throttle, the
    apply-retry watchdog and the peer-ACK observation handoff."""

    def __init__(self, target, follow, chaddr, dhcp, hb_mismatch):
        self.target = target           # the address this keeper is meant to hold
        self.follow = follow
        self._dhcp = dhcp
        self._hb_mismatch = hb_mismatch

        self._followed_ip = None       # last address we asked configd to follow to
        self._follow_from = None       # address we followed FROM (for the retry watchdog)
        self._fired_at = 0.0           # when we last dispatched follow_update (retry deadline)
        self._gw_args = []             # extra follow_update args on a cross-subnet move: [old_gw, new_gw, bits]

        # Throttle state, keyed by chaddr so it survives the follow-induced
        # restart (the target-keyed runtime paths change on every follow).
        self._state_file = f"/var/run/carpvipdhcp-follow-{_fs_safe(chaddr)}"

        # A changed ISP address first seen in the PEER's ACK (both HA nodes run
        # an identical keeper on the same shared chaddr). The sniffer thread
        # records it via observe() -- a lone atomic ref-assign -- and the main
        # thread consumes it in check_observed().
        self._observed = None

    def _last_follow_time(self):
        """Epoch of this chaddr's last follow (persisted so the throttle survives
        the follow-induced restart). 0 if never / unreadable."""
        try:
            with open(self._state_file, encoding="utf-8") as f:
                return float(f.read().strip())
        except (OSError, ValueError):
            return 0.0

    def _record_follow(self):
        try:
            _atomic_write(self._state_file, str(int(time.time())))
        except OSError as e:
            LOG.warning("could not persist follow timestamp: %s", e)

    def on_changed_address(self, got, rx, phase, release_on_enforce):
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
            if not _same_ip_class(self.target, got):
                LOG.error("%s: refusing to follow %s -> %s across address class "
                          "(possible spoofed ACK from %s)", phase, self.target, got,
                          rx.server_id)
                return False
            leased_from = self._dhcp.binding.server
            if phase != PHASE_REBIND and rx.server_id and leased_from and rx.server_id != leased_from:
                LOG.error("%s: ACK from unexpected server %s (leased from %s) -- not following",
                          phase, rx.server_id, leased_from)
                return False

            waited = time.time() - self._last_follow_time()
            if waited < MIN_FOLLOW_INTERVAL:
                LOG.warning("%s: follow %s -> %s throttled (%.0fs < %ds) -- deferring",
                            phase, self.target, got, waited, MIN_FOLLOW_INTERVAL)
                return False

            LOG.warning("ISP gave %s (VIP was %s) at %s -- following: updating the CARP VIP",
                        got, self.target, phase)
            # If the ISP also moved the gateway (a cross-subnet renumber), follow the
            # new gateway + prefix too so outbound keeps working -- parity with what a
            # plain DHCP interface does. Needs the new subnet mask (opt 1) to set the
            # VIP prefix; without it we can only move the address, so warn instead.
            self._gw_args = []
            old_router = self._dhcp.binding.router
            if rx.router and old_router and rx.router != old_router:
                bits = _mask_to_bits(rx.subnet_mask)
                if bits:
                    LOG.warning("follow %s -> %s also moves the gateway (%s -> %s), subnet "
                                "/%d -- following across the subnet", self.target, got,
                                old_router, rx.router, bits)
                    self._gw_args = [old_router, rx.router, str(bits)]
                else:
                    LOG.error("follow %s -> %s changes the gateway (%s -> %s) but the ACK "
                              "carried no subnet mask -- updating the VIP address only; fix the "
                              "interface prefix + System->Gateways by hand", self.target,
                              got, old_router, rx.router)

            self._record_follow()
            # _follow_update reads target as the old address, so remember it
            # (for the retry watchdog) and fire before overwriting target.
            self._follow_from = self.target
            self._follow_update(got)
            self.target = got
            self._dhcp.adopt(rx)
            return True
        # Enforce: a fixed reservation must always return the target.
        LOG.error("%s: IP mismatch -- server %s gave %s, requested %s (reservation problem?)",
                  phase, rx.server_id, got, self.target)
        self._hb_mismatch(got, self.target)
        if release_on_enforce:
            self._dhcp.release(got, rx.server_id)
            # DORA's OFFER phase already recorded a tentative yiaddr; drop it so
            # the run loop re-acquires instead of renewing the refused grant.
            self._dhcp.expire()
        return False

    def _follow_update(self, new_ip):
        """Ask configd to rewrite the CARP VIP (and this keeper's reference) from
        the target to new_ip, then reconfigure. Fire-and-forget: the resulting
        service restart replaces this daemon with one bound to the new address."""
        if new_ip == self._followed_ip:
            return   # already asked for this address
        try:
            self._fire_follow_update(self.target, new_ip)
            # Only mark as handled once the request was actually dispatched, so a
            # spawn failure is retried next cycle instead of getting stuck.
            self._followed_ip = new_ip
            LOG.info("requested CARP VIP update %s -> %s", self.target, new_ip)
        except Exception as e:
            LOG.error("follow_update request failed: %s", e)

    def _fire_follow_update(self, old_ip, new_ip):
        """Dispatch the configd follow_update action (old -> new) and stamp the
        retry deadline. Separate from _follow_update so the watchdog can re-drive
        a stalled follow without tripping the _followed_ip equality guard."""
        cmd = ["/usr/local/sbin/configctl", "-d", "carpvipdhcp", "follow_update", old_ip, new_ip]
        cmd += self._gw_args   # cross-subnet: [old_gw, new_gw, bits]; empty on a same-subnet move
        subprocess.Popen(cmd)  # pylint: disable=consider-using-with
        self._fired_at = time.time()

    def watchdog(self):
        """Re-drive a follow that never took effect. After a successful follow,
        follow_update restarts this daemon within a few seconds; if we are still
        alive well past FOLLOW_RETRY_DEADLINE, its apply failed or stalled, so
        re-dispatch it (idempotent: it reconverges whether the config already
        moved or not, and its rc.d restart <old-id> eventually replaces us)."""
        if not (self.follow and self._followed_ip and self._follow_from):
            return
        if time.time() - self._fired_at < FOLLOW_RETRY_DEADLINE:
            return
        LOG.warning("follow %s -> %s not applied within %ds -- re-driving",
                    self._follow_from, self._followed_ip, FOLLOW_RETRY_DEADLINE)
        try:
            self._fire_follow_update(self._follow_from, self._followed_ip)
        except Exception as e:
            LOG.error("follow_update retry failed: %s", e)

    def observe(self, rx):
        """Record a peer-ACK observation (capture thread; a lone ref-assign);
        the main loop consumes it in check_observed().

        The read-then-clear in check_observed is not atomic against this store,
        so a peer ACK landing in that narrow window can be dropped. Accepted:
        the next peer ACK or our own renewal re-detects the change, and the 1s
        maintain tick keeps polling -- convergence is delayed, never lost."""
        self._observed = rx

    def check_observed(self):
        """Adopt an address change first seen in the PEER's DHCP ACK (same shared
        chaddr) without waiting for our own renewal timer. The sniffer only
        records the observation; the follow itself runs here on the main thread,
        through the same hardening/throttle as a first-party ACK. This collapses
        the follow window that would otherwise leave the two nodes on different
        VIP prefixes long enough for the backup to promote (transient
        dual-master; see docs/single-ip-wan-carp.md section 3)."""
        rx = self._observed
        if rx is None:
            return
        self._observed = None
        if not self.follow or not rx.yiaddr or rx.yiaddr == self._dhcp.binding.yiaddr:
            return
        LOG.info("observed peer DHCP ACK for %s (we hold %s) -- following early to converge",
                 rx.yiaddr, self._dhcp.binding.yiaddr)
        self.on_changed_address(rx.yiaddr, rx, PHASE_OBSERVED, release_on_enforce=False)


class Keeper:  # pylint: disable=too-many-instance-attributes
    """Orchestration around the components: owns the capture backend (feeding
    DHCP replies to DhcpClient, ARP replies to ArpNudge and peer-ACK
    observations to FollowPolicy), the heartbeat, the CARP role watch, the
    acquire pacing (backoff + link-return fast path) and the signal-driven
    operator actions. The lease lives in DhcpClient; the changed-address
    decision and the target address live in FollowPolicy."""

    def __init__(self, iface, chaddr, request_ip=None, eth_src=None, *,  # pylint: disable=too-many-arguments
                 hbfile=None, release_on_exit=False, vhid=None,
                 follow=False, vendor_class=None, client_id=None, hostname=None,
                 arp_nudge=0, arp_listen_promisc=False, capture_backend="scapy"):
        self.iface = iface
        self.chaddr = chaddr.lower()
        self.eth_src = (eth_src or chaddr).lower()
        self.hbfile = hbfile
        self.release_on_exit = release_on_exit
        self.vhid = str(vhid) if vhid else None

        # Capture backend component: owns the capture socket/thread and the
        # wire codec on both directions, and hands decoded neutral frames
        # back (DHCP replies and ARP replies, routed below). Promiscuous
        # capture is off by default; the rationale lives in the module
        # docstring's security section.
        self._capture = CAPTURE_BACKENDS[capture_backend](
            iface, arp_listen_promisc, self._on_dhcp_reply, self._on_arp_reply)

        # ARP nudge component: owns the pacing and reachability state; the
        # keeper supplies the lease binding per nudge (_arp_nudge) and the
        # CARP-role probe (via the _carp_master_probe shim).
        self._nudge = ArpNudge(self._capture, self.chaddr, arp_nudge, self._carp_master_probe)

        self._was_master = None        # CARP role at the last nudge check (None = unknown yet)
        self._nudge_now = False        # operator asked for an immediate nudge (SIGUSR1)
        self._poll_role_now = False    # a CARP transition fired -> re-check role now (SIGUSR2)
        self._renew_asap = False       # renew at the next _hold_lease tick instead of waiting for T1

        # DHCP client component: owns the lease state and the protocol sequences;
        # the keeper owns the capture (feeding it xid-matched replies) and the
        # policy hooks.
        self._dhcp = DhcpClient(
            self._capture, self.chaddr, self.eth_src,
            _identity_options(vendor_class, client_id, hostname),
            should_stop=lambda: self._stop,
            ensure_sniffer=self._ensure_sniffer,
            on_changed_address=self._on_changed_address)

        # Follow/enforce policy component: owns the target address and the
        # follow bookkeeping; drives the client via adopt()/release()/expire().
        self._follow = FollowPolicy(request_ip, follow, self.chaddr, self._dhcp,
                                    self._hb_mismatch)

        self.redora_wait = REDORA_MIN
        # Link-return fast path (only while UNBOUND): a carrier down->up edge resets
        # the backoff and re-DORAs at once, like dhclient's link-up -> state_reboot.
        self._link_up = None           # last carrier state seen (None = unknown / not probed)
        self._link_kick_at = 0.0       # epoch of the last link-return kick (debounce)
        self._link_returned = False    # set by _sleep_interruptible on a carrier return while unbound

        self._stop = False
        # General early-wake for the maintain-loop sleep (_sleep_interruptible): lets it
        # return before the 1s tick when there is pending work. Currently the
        # sniffer sets it on an observed address change so the follow fires in
        # milliseconds; a future fast-wake need should reuse this rather than mint
        # a second event. Set only by the capture thread; waited/cleared only by
        # the main thread.
        self._wake = threading.Event()

    # ---- capture (resilient) ----
    def _ensure_sniffer(self):
        if not self._capture.alive():
            LOG.warning("DHCP-reply capture down -- (re)starting")
            self._capture.start()
            time.sleep(1)

    def _on_arp_reply(self, frame):
        """Capture-backend ARP callback: the gateway answering our nudge
        (reachability stamp); the nudge component does the matching."""
        self._nudge.on_arp_reply(frame, self._dhcp.binding.yiaddr, self._nudge_target())

    def _chaddr_matches(self, frame):
        """True if the reply's BOOTP client hardware address is our chaddr (the
        CARP virtual MAC). Used to accept the PEER's ACK on the shared chaddr:
        the peer node runs an identical keeper on the very same chaddr."""
        return frame.chaddr[:6] == self._dhcp.chraw

    def _on_dhcp_reply(self, frame):
        # Runs on the capture thread under the backend's handler guard
        # (_deliver), so an unexpected failure here is logged and dropped there.
        if frame.op != BOOTREPLY:
            return
        # First-party path: a reply to OUR in-flight exchange (random xid,
        # regenerated per DORA). Parsed and fed to the waiting client sequence.
        if frame.xid == self._dhcp.xid:
            self._dhcp.feed(_parse_reply(frame))
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
        # ACK and never acts on the capture thread.
        if not self._follow.follow or not self._dhcp.binding.yiaddr or not self._chaddr_matches(frame):
            return
        rx = _parse_reply(frame)
        if (rx.mtype == ACK and rx.yiaddr and rx.yiaddr != self._dhcp.binding.yiaddr
                and _sane_ipv4(rx.yiaddr)):
            self._follow.observe(rx)
            self._wake.set()   # wake the maintain-loop sleep now, don't wait for the tick

    # ---- heartbeat / status file ----

    def _write_hb(self, content):
        if not self.hbfile:
            return
        try:
            _atomic_write(self.hbfile, content)
        except Exception as e:
            # The heartbeat drives CARP gating, so a write failure is worth surfacing.
            LOG.warning("heartbeat write failed (%s): %s", self.hbfile, e)

    def _hb(self):
        t1, t2, src = self._dhcp.timing()
        # Publish nudge state so the status page can show it: nudge=<epoch of the
        # last sent nudge, 0 = never>, arpok=<epoch of the gateway's last ARP reply,
        # 0 = none seen> and the current target gateway (if known). status.py's
        # _HB_TOKENS table is the reader -- keep the tokens in lockstep.
        extra = ""
        if self._nudge.interval:
            extra = f" nudge={int(self._nudge.last_nudge)} arpok={int(self._nudge.last_reply)}"
            gw = self._nudge_target()
            if gw:
                extra += f" gw={gw}"
        self._write_hb(f"{int(time.time())} bound={self._dhcp.binding.yiaddr or '-'} "
                       f"lease={self._dhcp.binding.lease_secs} t1={t1} t2={t2} src={src}{extra}\n")

    def _hb_mismatch(self, got, want):
        # Write a clear marker into the heartbeat file so a supervisor/human sees the mismatch.
        self._write_hb(f"{int(time.time())} MISMATCH got={got} want={want}\n")

    def _on_changed_address(self, got, rx, phase, release_on_enforce):
        """DhcpClient's changed-address hook -> the FollowPolicy decision. A
        shim because the client is constructed before the policy exists."""
        return self._follow.on_changed_address(got, rx, phase, release_on_enforce)

    # ---- CARP role (master probe, transitions) ----

    def _ifconfig(self):
        """Captured `ifconfig <iface>` text, or None if the probe failed. Shared by
        the CARP-role probe and the carrier check so the ifconfig invocation, decode
        and error policy live in exactly one place."""
        try:
            out = subprocess.check_output(["/sbin/ifconfig", self.iface], errors="replace")
        except (OSError, subprocess.SubprocessError):
            return None
        return out.decode(errors="replace") if isinstance(out, bytes) else out

    def _probe_carp_master(self):
        """Raw CARP-role probe for our vhid: True/False from ifconfig, None when
        the probe itself fails; no vhid configured -> True (nothing to gate on).
        Callers apply their own policy on a None probe -- the ARP nudge fails closed
        (no nudge unless a confirmed MASTER); the CARP-transition poll just skips."""
        if not self.vhid:
            return True
        out = self._ifconfig()
        if out is None:
            return None
        return f"carp: MASTER vhid {self.vhid} " in out

    def _carp_master_probe(self):
        """ArpNudge's is_master hook -> the CARP probe (late-bound through the
        attribute so tests can stub _probe_carp_master)."""
        return self._probe_carp_master()

    def _iface_link_up(self):
        """Interface carrier from ifconfig: True on 'status: active', False on a
        present-but-inactive status (no carrier / no link), None when it cannot be
        read (probe failed, or the NIC reports no status line). Used by the
        unbound link-return fast path and the acquire carrier gate; a None
        result never disturbs the backoff and never holds an acquire."""
        out = self._ifconfig()
        if out is None:
            return None
        if "status: active" in out:
            return True
        if "status: " in out:
            return False
        return None

    def _check_link_returned(self):
        """While UNBOUND, detect a carrier down->up edge so the keeper re-DORAs at
        once instead of waiting out the backoff (mirrors dhclient link-up ->
        state_reboot). Returns True only on a *seen-down* -> up transition, debounced
        against a flapping link. An initial unknown->up is NOT a trigger (we were
        already up), so this never fires spuriously at startup."""
        up = self._iface_link_up()
        if up is None:
            return False
        prev = self._link_up
        self._link_up = up
        if up and prev is False:
            now = time.time()
            if now - self._link_kick_at < LINK_KICK_DEBOUNCE:
                return False
            self._link_kick_at = now
            return True
        return False

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
        return self._dhcp.binding.router or self._dhcp.binding.server

    def _arp_nudge(self, force=False):
        """Hand the current lease binding (leased address, nudge target) to the
        ArpNudge component; it owns the pacing, the master gate and the send."""
        self._nudge.maybe_nudge(self._dhcp.binding.yiaddr, self._nudge_target(), force=force)

    # ---- operator/signal API (set flags only; the loops act within a second) ----

    def request_stop(self):
        """Ask the daemon to exit at the next loop tick (SIGINT/SIGTERM)."""
        self._stop = True

    def trigger_nudge(self):
        """Request an immediate ARP nudge (SIGUSR1 / configd action). Flag
        only: no network I/O happens in signal context."""
        self._nudge_now = True

    def recheck_carp_role(self):
        """Re-check the CARP role within a second (SIGUSR2 from the CARP
        syshook) instead of waiting for the next ~30s poll."""
        self._poll_role_now = True

    # ---- main loop / sleeps ----

    def _sleep(self, secs):
        slept = 0
        while slept < secs and not self._stop:
            time.sleep(1)
            slept += 1
        return slept

    def _sleep_interruptible(self, secs):
        """Sleep up to secs (1s steps). Return False early on stop. Also services an
        operator-requested immediate nudge (SIGUSR1) and a CARP-transition re-check
        (SIGUSR2) so both act within a second instead of at the next heartbeat tick."""
        slept = 0
        while slept < secs and not self._stop:
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

            # A pending peer-ACK observation follows now (rationale + the
            # dual-master window it closes: FollowPolicy.check_observed).
            self._follow.check_observed()

            # Link-return fast path: only while UNBOUND, poll carrier every few
            # seconds; a down->up edge means the WAN just came back, so stop waiting
            # and let _maintain_step re-DORA immediately (the bound path skips this).
            if self._dhcp.binding.yiaddr is None and slept % LINK_POLL_STEP == 0 and self._check_link_returned():
                self._link_returned = True
                return not self._stop

            # Event-driven sleep: return at once when the sniffer signals a fresh
            # observation, otherwise time out after ~1s to run the periodic checks.
            if self._wake.wait(1.0):
                self._wake.clear()
            slept += 1
        return not self._stop

    def _hold_lease(self, secs):
        """Sleep up to secs while holding a lease, rewriting the heartbeat every
        HB_REFRESH so a healthy keeper never looks stale (leases can be hours and
        the CARP demotion hook only sees heartbeat freshness). Returns False early
        on stop."""
        remaining = secs
        while remaining > 0 and not self._stop:
            if self._renew_asap:
                # Return as if T1 elapsed: the caller renews right away, which
                # re-teaches upstream DHCP-snooping state after a master change.
                self._renew_asap = False
                return not self._stop

            chunk = min(HB_REFRESH, remaining)
            if not self._sleep_interruptible(chunk):
                return False
            remaining -= chunk

            self._hb()
            self._follow.watchdog()   # re-drive a follow whose apply stalled
            self._poll_carp_role()    # backup->master? renew early + nudge now
            self._arp_nudge()
        return not self._stop

    def run(self):
        """The daemon main loop: capture up, then maintain the lease until
        stopped. Never raises; returns the process exit code."""
        # Start the packet capture, retrying forever: a keeper must self-heal, not
        # die, if the interface is briefly unavailable at startup.
        while not self._stop and not self._capture.start():
            LOG.warning("capture start failed -- retrying in %ds", SNIFFER_RETRY)
            self._sleep(SNIFFER_RETRY)

        # eth-src matters for L2 debugging but only when it differs from the chaddr.
        ethsrc = f" eth-src={self.eth_src}" if self.eth_src != self.chaddr else ""
        LOG.info("lease-keeper active on %s: chaddr=%s%s request=%s",
                 self.iface, self.chaddr, ethsrc, self._follow.target or "any")
        time.sleep(SNIFFER_WARMUP)

        while not self._stop:
            # The keeper must NEVER die on a bad DHCP state: catch any unexpected
            # error, keep the heartbeat fresh so CARP does not falsely demote us,
            # and retry after a short backoff.
            try:
                self._maintain_step()
            except Exception:
                LOG.exception("unexpected error in main loop -- recovering")
                try:
                    self._hb()
                except Exception:
                    pass
                self._sleep(LOOP_ERROR_BACKOFF)

        # shutdown
        if self.release_on_exit:
            self._dhcp.release()
        self._capture.stop()
        LOG.info("stopped")
        return 0

    def _maintain_step(self):
        """One iteration of the maintain loop. Returns to run() (which loops again)
        on every state transition; any exception it raises is caught by run() and
        retried, so a transient fault can never terminate the keeper."""
        b = self._dhcp.binding
        if not b.yiaddr:
            self._acquire_step()
            return

        # Maintain: wait until T1, then RENEW; bail early on stop.
        t1, t2, src = self._dhcp.timing()
        # The renew/rebind plan is verbose and identical every cycle for a stable
        # lease, so log it at DEBUG -- the default (INFO) log stays clean and
        # "RENEW ok" already carries the lease + expiry. Raise the keeper's log
        # level to see it.
        LOG.debug("DHCP lease %ds; renew at T1=%ds (~%s), rebind by T2=%ds (~%s) (timing source: %s)",
                  b.lease_secs, t1, _clock_at(t1), t2, _clock_at(t2), src)
        if not self._hold_lease(t1):
            return
        if self._dhcp.renew():
            LOG.info("DHCP RENEW ok %s (lease=%ss, expires ~%s)",
                     b.yiaddr, b.lease_secs, _clock_at(b.lease_secs))
            self._hb()
            self._arp_nudge(force=True)
            return
        LOG.warning("DHCP RENEW failed at T1 -- trying REBIND until T2")

        elapsed = t1
        ok = False
        while elapsed < t2 and not self._stop:
            # Jitter the REBIND retransmit cadence: both nodes hit T2 together
            # (identical lease timers), so an un-jittered step would broadcast
            # REBIND in lockstep. Overshooting t2 slightly is harmless (the guard
            # re-checks). Account the actual jittered wait so elapsed tracks it.
            step = _jittered(min(REBIND_POLL_STEP, t2 - elapsed))
            if not self._sleep_interruptible(step):
                break
            elapsed += step
            self._hb()   # still holding the lease until T2 -- keep the heartbeat fresh
            if self._dhcp.renew(rebind=True):
                ok = True
                break
        if ok:
            LOG.info("DHCP REBIND ok %s (lease=%ss, expires ~%s)",
                     b.yiaddr, b.lease_secs, _clock_at(b.lease_secs))
            self._hb()
            self._arp_nudge(force=True)
            return

        LOG.error("DHCP lease expired -- re-acquiring (back to DISCOVER)")
        self._dhcp.expire()

    def _acquire_step(self):
        """The unbound arm of the maintain loop: hold while there is no
        carrier, otherwise try one acquire with the jittered re-DORA backoff;
        the link-return fast path cuts either wait short."""
        self._ensure_sniffer()  # a dead sniffer would silently fail every DORA
        self._hb()  # active but not holding yet -> publish bound=-

        # No point broadcasting DISCOVERs on a dead link (native dhclient
        # does not either): wait for the carrier instead of burning DORA
        # attempts. The unbound sleep polls the link and the link-return
        # fast path resumes within seconds of it coming back. Fail open:
        # only a confirmed "no carrier" (False) holds the acquire; an
        # unreadable probe (None) never blocks it.
        if self._iface_link_up() is False:
            if self._link_up is not False:   # log once per down-episode
                LOG.info("no carrier on %s -- waiting for the link before the DHCP acquire",
                         self.iface)
            self._link_up = False
            self._link_returned = False
            self._sleep_interruptible(REDORA_MIN)
            if self._link_returned:
                LOG.info("WAN link returned while unbound -- re-acquiring now")
                self.redora_wait = REDORA_MIN
            return

        b = self._dhcp.binding
        if self._dhcp.acquire(self._follow.target):
            self._link_up = True   # a completed DORA proves carrier
            LOG.info("DHCP BOUND %s (lease=%ss, expires ~%s, server=%s, gw=%s, mask=%s)",
                     b.yiaddr, b.lease_secs, _clock_at(b.lease_secs),
                     b.server, b.router or "?",
                     f"/{b.mask_bits}" if b.mask_bits else "none")
            self._hb()
            self._arp_nudge(force=True)
            self.redora_wait = REDORA_MIN
        else:
            LOG.warning("DHCP acquire (DISCOVER/REQUEST) failed -- retrying in %ds", self.redora_wait)
            self._link_returned = False
            self._sleep_interruptible(_jittered(self.redora_wait))
            if self._link_returned:
                # WAN carrier returned mid-backoff: re-acquire now instead of
                # waiting out the next backoff (matches native dhclient).
                LOG.info("WAN link returned while unbound -- re-acquiring now")
                self.redora_wait = REDORA_MIN
            else:
                self.redora_wait = min(self.redora_wait * 2, REDORA_MAX)


def _identity_options(vendor_class, client_id, hostname):
    """Optional DHCP identity options (empty -> not sent), added to every
    DISCOVER/REQUEST/RENEW so the server sees a consistent client identity.
    ISP interplay: satisfies servers that only lease to a known vendor-class
    (opt 60), client-id (61) or hostname (12) -- the "client identity checks"
    row of the README's ISP-security section."""
    id_opts = []
    if vendor_class:
        id_opts.append(("vendor_class_id", vendor_class))
    if client_id:
        id_opts.append(("client_id", client_id.encode()))
    if hostname:
        id_opts.append(("hostname", hostname))
    return id_opts


def acquire_pidfile(path):
    """Single-instance guard: atomically claim the pidfile, replacing a stale
    one; exits the process if another live instance holds it."""
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
                with open(path, encoding="utf-8") as f:
                    old = int(f.read().strip())
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


def _build_arg_parser():
    """The daemon's CLI."""
    ap = argparse.ArgumentParser(description="Robust DHCP lease-keeper (chaddr decoupled from the iface MAC)")
    ap.add_argument("--iface", required=True)
    ap.add_argument("--chaddr", required=True)
    ap.add_argument("--request", default=None)
    ap.add_argument("--eth-src", default=None)
    ap.add_argument("--pidfile", default="/var/run/lease-keeper.pid")
    ap.add_argument("--hbfile", default="/var/run/lease-keeper.hb")
    ap.add_argument("--logfile", default="/var/log/lease-keeper.log")
    ap.add_argument("--vhid", default=None)
    ap.add_argument("--follow", action="store_true")
    ap.add_argument("--vendor-class", default=None)
    ap.add_argument("--client-id", default=None)
    ap.add_argument("--hostname", default=None)
    ap.add_argument("--arp-nudge", type=int, default=0, metavar="SECS",
                    help="periodically broadcast an ARP request from the leased IP "
                         "for the gateway, so upstream gear that never re-ARPs keeps "
                         "a fresh entry (0 = off, suggested 120)")
    ap.add_argument("--arp-listen-promisc", action="store_true",
                    help="put the capture socket in promiscuous mode so the gateway's "
                         "unicast ARP reply is seen on NICs that filter non-primary "
                         "unicast MACs (default off; only needed if replies aren't seen)")
    ap.add_argument("--capture-backend", choices=sorted(CAPTURE_BACKENDS), default="scapy",
                    help="packet capture/send backend: scapy (default), or bpf -- a raw "
                         "/dev/bpf backend with no packet-library dependency (experimental)")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--release-on-exit", action="store_true")
    return ap


def _setup_logging(logfile):
    """stderr plus a rotating file. DEBUG is always written (routine detail
    like the renew/rebind plan): the volume is low, the log page hides DEBUG
    by default, and its filter reveals it -- so "turning up the log level"
    needs no daemon restart."""
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if logfile:
        try:
            handlers.append(RotatingFileHandler(logfile, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUPS))
        except Exception:
            pass
    logging.basicConfig(level=logging.DEBUG, handlers=handlers,
                        format="%(asctime)s %(levelname)s %(message)s")


# The one-shot mode drives the Keeper/DhcpClient internals directly.
# pylint: disable=protected-access
def _claim_once(k):
    """--once mode: claim, report, release -- a wiring test, not service mode."""
    if not k._capture.start():
        return 3
    time.sleep(SNIFFER_WARMUP)
    ok = k._dhcp.dora(k._follow.target)
    LOG.info("DHCP claim %s -> %s", k.chaddr, k._dhcp.binding.yiaddr if ok else "FAIL")
    if ok:
        k._dhcp.release()
    k._capture.stop()
    return 0 if ok else 1
# pylint: enable=protected-access


def main():
    """CLI entry point: parse args, wire up the Keeper and signals, run."""
    a = _build_arg_parser().parse_args()
    _setup_logging(a.logfile)

    if a.capture_backend == "scapy" and _SCAPY_IMPORT_ERROR is not None:
        LOG.critical("cannot import scapy -- the lease keeper cannot run: %s. "
                     "Install the matching py3<minor>-scapy package (see the plugin "
                     "docs) and restart the service.", _SCAPY_IMPORT_ERROR)
        return 3
    LOG.info("capture backend: %s", a.capture_backend)

    for label, mac in (("chaddr", a.chaddr), ("eth-src", a.eth_src)):
        if mac and not MAC_RE.match(mac):
            LOG.error("invalid %s MAC address: %r", label, mac)
            return 2

    k = Keeper(a.iface, a.chaddr, a.request, a.eth_src,
               hbfile=a.hbfile, release_on_exit=a.release_on_exit or a.once,
               vhid=a.vhid, follow=a.follow,
               vendor_class=a.vendor_class, client_id=a.client_id, hostname=a.hostname,
               arp_nudge=a.arp_nudge, arp_listen_promisc=a.arp_listen_promisc,
               capture_backend=a.capture_backend)

    if a.arp_listen_promisc:
        LOG.warning("ARP listen: PROMISCUOUS capture enabled on %s -- the daemon now "
                    "sees all traffic on the segment (opt-in fallback for NICs that "
                    "drop the gateway's unicast ARP reply otherwise)", a.iface)

    def _sig(*_):
        LOG.info("signal received -- stopping")
        k.request_stop()
    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    def _sig_arp_nudge(*_):
        # Operator-requested immediate ARP nudge (configd action / kill -USR1).
        k.trigger_nudge()
    signal.signal(signal.SIGUSR1, _sig_arp_nudge)  # type: ignore[attr-defined]  # pylint: disable=no-member

    def _sig_carp(*_):
        # CARP transition (rc.syshook.d/carp/50-carpvipdhcp sends SIGUSR2).
        k.recheck_carp_role()
    signal.signal(signal.SIGUSR2, _sig_carp)  # type: ignore[attr-defined]  # pylint: disable=no-member

    if a.once:
        return _claim_once(k)

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
