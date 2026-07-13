"""Unit tests for the raw wire codec behind the bpf capture backend: golden
bytes for the frames the keeper sends, defensive decoding of untrusted
replies (bounds-checked TLV walk), and the BPF capture-buffer walk.

Tests reach into private helpers by design, and use comments over
per-test docstrings."""
# pylint: disable=protected-access, missing-function-docstring
import struct

from conftest import CHADDR


# ---- helpers: hand-built server replies (the encoder only builds requests) ----

def _bootp_reply(lk, *, op=2, xid=0x1234, yiaddr="100.64.4.7", giaddr="0.0.0.0",  # pylint: disable=too-many-arguments
                 chaddr=CHADDR, options=b"", cookie=None):
    """A raw BOOTP reply payload: fixed header + magic cookie + options."""
    hdr = struct.pack("!4BIHH", op, 1, 6, 0, xid, 0, 0)
    hdr += lk._ip4("0.0.0.0") + lk._ip4(yiaddr) + lk._ip4("0.0.0.0") + lk._ip4(giaddr)
    hdr += chaddr.ljust(16, b"\x00") + b"\x00" * 192
    return hdr + (lk.DHCP_MAGIC if cookie is None else cookie) + bytes(options)


def _ack_options(lk):
    """Raw TLVs of a typical ACK: type, server-id, lease, router, mask, end."""
    return bytes(
        [53, 1, lk.ACK,
         54, 4, 100, 64, 4, 1,
         51, 4, 0, 0, 7, 8,           # lease 1800
         3, 4, 100, 64, 4, 1,
         1, 4, 255, 255, 255, 0,
         255])


# ---- outbound: golden bytes ----

def test_encode_dhcp_options_golden(lk):
    raw = lk._encode_dhcp_options([
        ("message-type", "discover"),
        ("param_req_list", [1, 3, 51, 54, 58, 59]),
        ("requested_addr", "100.64.4.7"),
        "end",
    ])
    assert raw == bytes([53, 1, 1,
                         55, 6, 1, 3, 51, 54, 58, 59,
                         50, 4, 100, 64, 4, 7,
                         255])


def test_encode_dhcp_options_drops_none_values(lk):
    # A broadcast RELEASE carries no server-id: the None option vanishes
    # instead of encoding garbage, and end is still appended exactly once.
    raw = lk._encode_dhcp_options([("message-type", "release"), ("server_id", None), "end"])
    assert raw == bytes([53, 1, 7, 255])


def test_encode_dhcp_options_identity_options(lk):
    raw = lk._encode_dhcp_options([
        ("hostname", "fw1"),
        ("vendor_class_id", "acme"),
        ("client_id", b"\x01abc"),      # arrives pre-encoded from the CLI
    ])
    assert raw == bytes([12, 3]) + b"fw1" + bytes([60, 4]) + b"acme" + bytes([61, 4]) + b"\x01abc" + bytes([255])


def test_encode_bootp_request_layout(lk):
    payload = lk._encode_bootp_request(CHADDR, 0x11223344, "0.0.0.0", lk.BROADCAST_FLAG,
                                       [("message-type", "discover"), "end"])
    assert len(payload) == lk.BOOTP_MIN_PAYLOAD          # padded to the RFC 1542 minimum
    assert payload[0] == 1 and payload[1] == 1 and payload[2] == 6   # BOOTREQUEST, Ethernet, hlen 6
    assert payload[4:8] == b"\x11\x22\x33\x44"           # xid, network order
    assert struct.unpack("!H", payload[10:12])[0] == lk.BROADCAST_FLAG
    assert payload[28:44] == CHADDR.ljust(16, b"\x00")   # chaddr field, zero-padded
    assert payload[lk.BOOTP_HDR_LEN:lk.BOOTP_HDR_LEN + 4] == lk.DHCP_MAGIC
    assert payload[lk.BOOTP_HDR_LEN + 4:lk.BOOTP_HDR_LEN + 8] == bytes([53, 1, 1, 255])


def test_encode_bootp_request_renew_sets_ciaddr(lk):
    payload = lk._encode_bootp_request(CHADDR, 1, "100.64.4.7", 0, [])
    assert payload[12:16] == bytes([100, 64, 4, 7])      # ciaddr
    assert payload[16:20] == b"\x00" * 4                 # yiaddr stays zero on a request


def test_ipv4_and_udp_checksums_validate(lk):
    dgram = lk._encode_ipv4_udp("100.64.4.7", "255.255.255.255", 68, 67, b"payload")
    # A correct ones-complement checksum makes the checksum-of-the-whole zero.
    assert lk._inet_checksum(dgram[:20]) == 0            # IP header
    udp_len = len(dgram) - 20
    pseudo = dgram[12:16] + dgram[16:20] + struct.pack("!BBH", 0, lk.IPPROTO_UDP, udp_len)
    assert lk._inet_checksum(pseudo + dgram[20:]) == 0   # UDP with pseudo-header
    assert dgram[9] == lk.IPPROTO_UDP
    assert struct.unpack("!H", dgram[2:4])[0] == len(dgram)


def test_inet_checksum_known_vector(lk):
    # The classic worked example (an IP header whose checksum field is zeroed).
    hdr = bytes.fromhex("45000073000040004011" + "0000" + "c0a80001c0a800c7")
    assert lk._inet_checksum(hdr) == 0xB861


def test_encode_arp_request_golden(lk):
    raw = lk._encode_arp_request("00:00:5e:00:01:fe", "100.64.4.7", "100.64.4.1")
    assert raw == (struct.pack("!HHBBH", 1, lk.ETHERTYPE_IPV4, 6, 4, 1)
                   + CHADDR + bytes([100, 64, 4, 7])
                   + b"\x00" * 6 + bytes([100, 64, 4, 1]))


def test_encode_ether_golden(lk):
    frame = lk._encode_ether(lk.ETHER_BROADCAST, "00:00:5e:00:01:fe", lk.ETHERTYPE_ARP, b"x")
    assert frame == b"\xff" * 6 + CHADDR + b"\x08\x06" + b"x"


# ---- inbound: defensive decoding of untrusted replies ----

def test_decode_dhcp_options_typical_ack(lk):
    opts = dict(lk._decode_dhcp_options(_ack_options(lk)))
    assert opts["message-type"] == lk.ACK
    assert opts["server_id"] == "100.64.4.1" and opts["router"] == "100.64.4.1"
    assert opts["lease_time"] == 1800 and opts["subnet_mask"] == "255.255.255.0"


def test_decode_dhcp_options_pad_end_and_unknown(lk):
    # pads are stepped over, unknown options (here 42) are skipped unread,
    # and nothing after the end option is parsed.
    data = bytes([0, 0, 42, 2, 9, 9, 53, 1, 5, 255, 54, 4, 1, 2, 3, 4])
    assert lk._decode_dhcp_options(data) == [("message-type", 5)]


def test_decode_dhcp_options_truncations_never_raise(lk):
    assert lk._decode_dhcp_options(b"") == []
    assert lk._decode_dhcp_options(bytes([53])) == []                # length byte missing
    assert lk._decode_dhcp_options(bytes([53, 4, 5])) == []          # value truncated
    # a malformed value inside a known option is skipped; the walk continues
    assert lk._decode_dhcp_options(bytes([51, 2, 1, 2, 53, 1, 5])) == [("message-type", 5)]
    assert lk._decode_dhcp_options(bytes([53, 0])) == []             # empty message-type


def test_decode_dhcp_options_message_stays_bytes(lk):
    # option 56 arrives as bytes; _msg_text does the decoding later.
    assert lk._decode_dhcp_options(bytes([56, 4]) + b"nope") == [("message", b"nope")]


def test_decode_arp(lk):
    good = lk._encode_arp_request("00:00:5e:00:01:fe", "100.64.4.7", "100.64.4.1")
    assert lk._decode_arp(good) == lk.ArpFrame(1, "100.64.4.7", "100.64.4.1")
    assert lk._decode_arp(good[:20]) is None                         # truncated
    assert lk._decode_arp(b"\x00\x02" + good[2:]) is None            # not Ethernet hardware
    reply = b"\x00\x01\x08\x00\x06\x04\x00\x02" + good[8:]
    assert lk._decode_arp(reply).op == 2


def test_decode_ipv4_bootp_end_to_end(lk):
    payload = _bootp_reply(lk, options=_ack_options(lk), giaddr="100.64.4.9")
    frame = lk._decode_ipv4_bootp(lk._encode_ipv4_udp("100.64.4.1", "255.255.255.255", 67, 68, payload))
    assert frame.op == lk.BOOTREPLY and frame.xid == 0x1234
    assert frame.yiaddr == "100.64.4.7" and frame.giaddr == "100.64.4.9"
    assert frame.chaddr[:6] == CHADDR
    # ...and the frame satisfies the backend-neutral reply parser end to end.
    rx = lk._parse_reply(frame)
    assert rx.mtype == lk.ACK and rx.yiaddr == "100.64.4.7"
    assert rx.server_id == "100.64.4.1" and rx.lease == 1800
    assert rx.subnet_mask == "255.255.255.0" and rx.giaddr == "100.64.4.9"


def test_decode_ipv4_bootp_bounds_by_udp_length(lk):
    # A UDP length shorter than the IP payload must not let trailing bytes be
    # parsed as options: bytes past udp_len are dropped like link padding.
    payload = _bootp_reply(lk, options=bytes([53, 1, 5, 255]))
    dgram = bytearray(lk._encode_ipv4_udp("100.64.4.1", "255.255.255.255", 67, 68, payload))
    ihl = (dgram[0] & 0x0F) * 4
    # append attacker bytes that look like an option, then shrink UDP length to exclude them
    dgram += bytes([54, 4, 9, 9, 9, 9])
    dgram[2:4] = (len(dgram)).to_bytes(2, "big")                 # IP total covers the extra bytes
    true_udp_len = ihl + 8 + len(payload) - ihl                 # = 8 + len(payload)
    dgram[ihl + 4:ihl + 6] = (8 + len(payload)).to_bytes(2, "big")
    frame = lk._decode_ipv4_bootp(bytes(dgram))
    assert dict(frame.options) == {"message-type": 5}           # the trailing option is excluded
    assert true_udp_len == 8 + len(payload)


def test_decode_ipv4_bootp_rejects_short_udp_length(lk):
    payload = _bootp_reply(lk, options=bytes([53, 1, 5, 255]))
    dgram = bytearray(lk._encode_ipv4_udp("100.64.4.1", "255.255.255.255", 67, 68, payload))
    ihl = (dgram[0] & 0x0F) * 4
    dgram[ihl + 4:ihl + 6] = (4).to_bytes(2, "big")             # UDP length < its own 8-byte header
    assert lk._decode_ipv4_bootp(bytes(dgram)) is None


def test_decode_ipv4_bootp_trims_link_padding(lk):
    # Ethernet pads short frames: bytes past the IP total length must not
    # leak into the options walk.
    payload = _bootp_reply(lk, options=bytes([53, 1, 5, 255]))
    dgram = lk._encode_ipv4_udp("100.64.4.1", "255.255.255.255", 67, 68, payload)
    frame = lk._decode_ipv4_bootp(dgram + b"\x35\x01\x06" * 4)   # padding that mimics option bytes
    assert dict(frame.options)["message-type"] == 5


def test_decode_ipv4_bootp_rejects_malformed(lk):
    payload = _bootp_reply(lk, options=bytes([53, 1, 5, 255]))
    dgram = lk._encode_ipv4_udp("100.64.4.1", "255.255.255.255", 67, 68, payload)
    assert lk._decode_ipv4_bootp(b"") is None
    assert lk._decode_ipv4_bootp(dgram[:30]) is None                      # truncated
    assert lk._decode_ipv4_bootp(b"\x65" + dgram[1:]) is None             # not IPv4
    not_udp = dgram[:9] + b"\x06" + dgram[10:]
    assert lk._decode_ipv4_bootp(not_udp) is None                         # TCP proto
    fragged = dgram[:6] + b"\x20\x00" + dgram[8:]
    assert lk._decode_ipv4_bootp(fragged) is None                         # MF set
    bad_cookie = lk._encode_ipv4_udp("100.64.4.1", "255.255.255.255", 67, 68,
                                     _bootp_reply(lk, cookie=b"\x00\x00\x00\x00"))
    assert lk._decode_ipv4_bootp(bad_cookie) is None
    short_bootp = lk._encode_ipv4_udp("100.64.4.1", "255.255.255.255", 67, 68, b"\x02" * 100)
    assert lk._decode_ipv4_bootp(short_bootp) is None


# ---- the BPF capture-buffer walk ----

def _bpf_record(lk, frame):
    hdr = struct.pack("=16xIIH", len(frame), len(frame), lk.BPF_HDR_FIXED)
    record = hdr + frame
    pad = -len(record) % lk.BPF_ALIGNMENT
    return record + b"\x00" * pad


def test_bpf_frames_walks_records(lk):
    frames = [b"first-frame!", b"the-second-frame-is-longer"]
    data = b"".join(_bpf_record(lk, f) for f in frames)
    assert list(lk._bpf_frames(data)) == frames


def test_bpf_frames_stops_on_malformed(lk):
    good = _bpf_record(lk, b"good-frame")
    truncated = struct.pack("=16xIIH", 4096, 4096, lk.BPF_HDR_FIXED) + b"tiny"
    assert list(lk._bpf_frames(good + truncated)) == [b"good-frame"]
    assert not list(lk._bpf_frames(b"\x00" * 10))                    # shorter than a header
    bad_hdrlen = struct.pack("=16xIIH", 4, 4, 2) + b"\x00" * 8
    assert not list(lk._bpf_frames(bad_hdrlen))


# ---- BpfCapture: dispatch + send paths (no descriptor needed) ----

def _bpf_capture(lk):
    frames = {"bootp": [], "arp": [], "sent": []}
    cap = lk.BpfCapture("eth0", False, frames["bootp"].append, frames["arp"].append)
    cap._write = frames["sent"].append
    return cap, frames


def test_bpf_dispatch_routes_by_ethertype(lk):
    cap, frames = _bpf_capture(lk)
    arp = lk._encode_ether(lk.ETHER_BROADCAST, "00:00:5e:00:01:fe", lk.ETHERTYPE_ARP,
                           b"\x00\x01\x08\x00\x06\x04\x00\x02" + CHADDR
                           + bytes([100, 64, 4, 1]) + b"\x00" * 6 + bytes([100, 64, 4, 7]))
    cap._dispatch(arp)
    dhcp = lk._encode_ether(lk.ETHER_BROADCAST, "00:00:5e:00:01:fe", lk.ETHERTYPE_IPV4,
                            lk._encode_ipv4_udp("100.64.4.1", "255.255.255.255", 67, 68,
                                                _bootp_reply(lk, options=_ack_options(lk))))
    cap._dispatch(dhcp)
    cap._dispatch(b"\x00" * 5)          # runt garbage is dropped quietly
    assert frames["arp"] == [lk.ArpFrame(2, "100.64.4.1", "100.64.4.7")]
    assert len(frames["bootp"]) == 1 and frames["bootp"][0].yiaddr == "100.64.4.7"


def test_bpf_send_dhcp_round_trips(lk):
    # What send_dhcp writes must decode back through our own defensive parser:
    # broadcast Ethernet/IP framing, the right ports, and the option list intact.
    cap, frames = _bpf_capture(lk)
    cap.send_dhcp(eth_src="00:00:5e:00:01:fe", ip_src="0.0.0.0", ip_dst="255.255.255.255",
                  chaddr=CHADDR, xid=0xABCD, ciaddr="0.0.0.0", flags=lk.BROADCAST_FLAG,
                  options=[("message-type", "discover"), ("requested_addr", "100.64.4.7"), "end"])
    frame = frames["sent"][0]
    assert frame[:6] == b"\xff" * 6 and frame[6:12] == CHADDR
    assert frame[12:14] == b"\x08\x00"
    ip = frame[14:]
    assert struct.unpack("!HH", ip[20:24]) == (lk.DHCP_CLIENT_PORT, lk.DHCP_SERVER_PORT)
    decoded = lk._decode_ipv4_bootp(ip)
    assert decoded.op == 1 and decoded.xid == 0xABCD and decoded.chaddr[:6] == CHADDR


def test_bpf_send_arp_pads_to_min_frame(lk):
    cap, frames = _bpf_capture(lk)
    cap.send_arp_request("00:00:5e:00:01:fe", "100.64.4.7", "100.64.4.1")
    frame = frames["sent"][0]
    assert len(frame) == lk.ETHER_MIN_FRAME
    assert lk._decode_arp(frame[14:]) == lk.ArpFrame(1, "100.64.4.7", "100.64.4.1")


def test_bpf_filter_program_shape(lk):
    # The embedded opcode table must be a plausible classic-BPF program:
    # 4-field instructions ending in the two return statements tcpdump emits.
    assert all(len(insn) == 4 for insn in lk._BPF_FILTER)
    assert lk._BPF_FILTER[-2][0] == 0x6 and lk._BPF_FILTER[-1][0] == 0x6
    assert lk._BPF_FILTER[-1][3] == 0                    # default: drop
