"""The scapy capture backend (default): AsyncSniffer + sendp, decoding scapy
packets into the neutral frames the rest of the keeper consumes.

The scapy import is guarded so the module still loads where scapy is absent
(main reports _SCAPY_IMPORT_ERROR when the scapy backend is actually selected).
"""
import logging
from typing import Any

from .constants import DHCP_CLIENT_PORT, DHCP_SERVER_PORT, ETHER_BROADCAST, ETHER_ZERO
from .wire import ArpFrame, BootpFrame, SNIFFER_FILTER, _deliver

LOG = logging.getLogger("lease-keeper")


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

