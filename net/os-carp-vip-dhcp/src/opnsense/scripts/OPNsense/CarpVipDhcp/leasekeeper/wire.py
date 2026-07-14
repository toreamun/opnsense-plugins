"""Backend-neutral wire layer: the frame types both capture backends decode
into, plus the reply parse/format/build helpers and the static capture filter.

These carry no client state; the stateful protocol sequences live in
dhcpclient. The option (name, value) vocabulary used here is the keeper's own
and is deliberately scapy-compatible (ScapyCapture relays outbound option lists
to scapy verbatim).
"""
import logging
import re
from typing import NamedTuple

from .constants import (
    LOGGER_NAME, DHCP_CLIENT_PORT, DHCP_SERVER_PORT, DhcpOptName, PARAM_REQ_LIST, mtype_name)

LOG = logging.getLogger(LOGGER_NAME)


class DhcpReply(NamedTuple):
    """A parsed DHCP reply, snapshotted from the capture thread.

    `message` (option 56) is the server's optional text, mainly a NAK reason;
    `subnet_mask` (option 1) drives the cross-subnet follow; `giaddr` (BOOTP
    header) is the relay agent, None when the server is directly attached. The
    trailing three default so shorter constructions stay valid."""
    mtype: int | None
    yiaddr: str | None
    server_id: str | None
    lease: int | None
    t1: int | None
    t2: int | None
    router: str | None
    message: bytes | str | None = None
    subnet_mask: str | None = None
    giaddr: str | None = None


class BootpFrame(NamedTuple):
    """A received BOOTP/DHCP frame in backend-neutral shape: both capture
    backends (scapy packet / raw bytes) decode to this before the keeper sees
    it. `chaddr` is raw bytes; `options` is a list of (name, value) tuples in
    the keeper's own option vocabulary (the names in codec's
    _OPT_ENCODERS/_OPT_DECODERS), which _parse_reply reads regardless of
    backend."""
    op: int
    xid: int
    yiaddr: str
    chaddr: bytes
    giaddr: str | None
    options: list


class ArpFrame(NamedTuple):
    """A received ARP frame (the capture filter already narrows ARP to replies,
    but op still travels so the handler re-checks rather than trusting it)."""
    op: int
    psrc: str
    pdst: str


class DhcpSend(NamedTuple):
    """One outbound DHCP client message in backend-neutral shape: the fields
    that go on the wire (Ethernet source, IP src/dst, the BOOTP
    chaddr/xid/ciaddr/flags, and the option list). DhcpClient builds it; the
    backend either encodes it (bpf) or relays it to scapy. The send-side
    counterpart to the received BootpFrame."""
    eth_src: str
    ip_src: str
    ip_dst: str
    chaddr: bytes
    xid: int
    ciaddr: str
    flags: int
    options: list


# Static BPF capture filter: DHCP (broadcast OFFER/ACK) + ARP replies to our nudge
# (arp[6:2]=2). A boundary, not an optimization -- it keeps everything else (incl. the
# segment's broadcast who-has flood) out of the Python parser.
SNIFFER_FILTER = f"(udp and (port {DHCP_SERVER_PORT} or port {DHCP_CLIENT_PORT})) or (arp and arp[6:2] = 2)"


def _msg_text(msg) -> str:
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


def _fmt_reply(rx) -> str:
    """One readable line decoding a received first-party DHCP reply. Logged at
    DEBUG (the keeper's default level), so every reply's fields (type, addresses,
    timers, gateway, mask, relay, server text) show in the log without a capture."""
    txt = _msg_text(rx.message)
    mtype = mtype_name(rx.mtype)
    msg = f" msg={txt!r}" if txt else ""
    return (f"{mtype} yiaddr={rx.yiaddr or '-'} server={rx.server_id or '-'} "
            f"giaddr={rx.giaddr or 'none'} lease={'-' if rx.lease is None else rx.lease} "
            f"t1={'-' if rx.t1 is None else rx.t1} t2={'-' if rx.t2 is None else rx.t2} "
            f"gw={rx.router or '-'} mask={rx.subnet_mask or '-'}{msg}")


def _parse_reply(frame) -> DhcpReply:
    """Snapshot only the handful of DHCP options the keeper acts on from a
    BootpFrame into a DhcpReply; the rest of the reply's option data --
    untrusted, from whatever answered on the wire -- is left untouched.

    message (opt 56) is the server's text (e.g. a NAK reason); subnet_mask
    (opt 1) drives the cross-subnet follow."""
    # Last value wins per name (as the old assignment chain did). A comprehension
    # rather than dict(frame.options) so a multi-value option that decodes to a
    # 3+-tuple is still read by its first value (o[1]) instead of raising.
    opts = {o[0]: o[1] for o in frame.options if isinstance(o, tuple)}
    gi = frame.giaddr   # relay agent; 0.0.0.0 = directly attached
    if gi in (None, "0.0.0.0", 0):
        gi = None
    return DhcpReply(
        mtype=opts.get(DhcpOptName.MESSAGE_TYPE), yiaddr=frame.yiaddr,
        server_id=opts.get(DhcpOptName.SERVER_ID), lease=opts.get(DhcpOptName.LEASE_TIME),
        t1=opts.get(DhcpOptName.RENEWAL_TIME), t2=opts.get(DhcpOptName.REBINDING_TIME),
        router=opts.get(DhcpOptName.ROUTER), message=opts.get(DhcpOptName.MESSAGE),
        subnet_mask=opts.get(DhcpOptName.SUBNET_MASK), giaddr=gi)


def _dhcp_options(mtype, extra, id_opts):
    """The DHCP option list for a message: type, our Parameter Request List
    (so the server returns the mask/router/timers the keeper acts on), the
    identity options, then the per-message extras."""
    return ([(DhcpOptName.MESSAGE_TYPE, mtype), (DhcpOptName.PARAM_REQ_LIST, PARAM_REQ_LIST)]
            + id_opts + extra + ["end"])


def _deliver(handler, frame):
    """Run a keeper frame callback under its own guard: a failure in there is
    a handler bug, not a parse error, and must neither kill the capture
    thread nor be mislabelled as malformed input. Shared by both capture
    backends (it lives here, the lowest layer both import, not in the capture
    registry, to keep the backend imports acyclic)."""
    if frame is None:
        return
    try:
        handler(frame)
    except Exception as e:  # pylint: disable=broad-exception-caught
        LOG.debug("frame handler error: %s", e)
