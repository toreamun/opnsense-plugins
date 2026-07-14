"""Raw wire codec and the embedded BPF filter for the bpf capture backend.

Hand encoders/decoders for exactly the frames the keeper exchanges (no packet
library), plus the /dev/bpf ioctl constants, the precompiled classic-BPF filter
and the capture-buffer walk. The decoders parse untrusted WAN input: every
access is bounds-checked and a malformed frame decodes to None (dropped).
"""
import ipaddress
import struct

from .constants import ArpOp, BOOTREPLY, ETHER_ZERO, MsgType
from .util import mac2raw
from .wire import ArpFrame, BootpFrame


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
IP_HDR_LEN = 20             # fixed IPv4 header we build (no options)
UDP_HDR_LEN = 8             # UDP header (src/dst port, length, checksum)

# The DHCP message types the keeper SENDS, keyed by the scapy-style option name
# the outbound option lists carry (the lowercased MsgType name -- "discover"
# etc.). Derived from MsgType so nothing is hand-duplicated; only these three
# are ever sent.
_MTYPE_CODES = {m.name.lower(): m for m in (MsgType.DISCOVER, MsgType.REQUEST, MsgType.RELEASE)}


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
    udp_len = UDP_HDR_LEN + len(payload)
    pseudo = _ip4(src) + _ip4(dst) + struct.pack("!BBH", 0, IPPROTO_UDP, udp_len)
    udp_hdr = struct.pack("!4H", sport, dport, udp_len, 0)
    cksum = _inet_checksum(pseudo + udp_hdr + payload) or 0xFFFF
    udp_hdr = struct.pack("!4H", sport, dport, udp_len, cksum)
    # version/ihl, tos, total, id, flags/frag, ttl, proto, checksum (zeroed, then patched)
    ip_hdr = (struct.pack("!BBHHHBBH", 0x45, 0, IP_HDR_LEN + udp_len, 0, 0, IPV4_TTL, IPPROTO_UDP, 0)
              + _ip4(src) + _ip4(dst))
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
    return (_ARP_ETH_IPV4 + struct.pack("!H", ArpOp.REQUEST)
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
    if len(pkt) < IP_HDR_LEN or pkt[0] >> 4 != 4:
        return None
    ihl = (pkt[0] & 0x0F) * 4
    total = int.from_bytes(pkt[2:4], "big")
    if ihl < IP_HDR_LEN or total < ihl + UDP_HDR_LEN or len(pkt) < ihl + UDP_HDR_LEN:
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
    if udp_len < UDP_HDR_LEN:
        return None
    end = min(total, ihl + udp_len, len(pkt))
    bootp = pkt[ihl + UDP_HDR_LEN:end]              # UDP payload, minus any link padding
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
