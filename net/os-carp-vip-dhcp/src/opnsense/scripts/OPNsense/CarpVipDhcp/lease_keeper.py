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


LOG = logging.getLogger("lease-keeper")

from leasekeeper.constants import (
    ACK, ARP_NUDGE_MIN, ATTEMPT_BACKOFF_CAP, BOOTREPLY, BROADCAST_FLAG,
    DEFAULT_LEASE, DHCP_CLIENT_PORT, DHCP_SERVER_PORT, DORA_ATTEMPTS,
    ETHER_BROADCAST, ETHER_ZERO, FOLLOW_RETRY_DEADLINE, HB_REFRESH,
    IPV4_BROADCAST, LINK_KICK_DEBOUNCE, LINK_POLL_STEP, LOG_BACKUPS,
    LOG_MAX_BYTES, LOOP_ERROR_BACKOFF, MIN_FOLLOW_INTERVAL, MIN_LEASE, MIN_T1,
    MTYPE_NAMES, NAK, OFFER, PARAM_REQ_LIST, PHASE_DORA, PHASE_OBSERVED,
    PHASE_REBIND, PHASE_REBOOT, PHASE_RENEW, REBIND_MARGIN, REBIND_POLL_STEP,
    REBOOT_ATTEMPTS, REDORA_MAX, REDORA_MIN, RENEW_ATTEMPTS, RENEW_TIMEOUT,
    REPLY_TIMEOUT, SEND_RETRY_DELAY, SNIFFER_RETRY, SNIFFER_WARMUP, T1_FACTOR,
    T2_FACTOR)
from leasekeeper.util import (
    MAC_RE, _atomic_write, _clock_at, _fs_safe, _is_localish, _jittered,
    _mask_to_bits, _new_xid, _same_ip_class, _sane_ipv4, mac2raw)
from leasekeeper.wire import (
    ArpFrame, BootpFrame, DhcpReply, SNIFFER_FILTER, _dhcp_options, _fmt_reply,
    _msg_text, _parse_reply)

from leasekeeper.capture import CAPTURE_BACKENDS
from leasekeeper.capture_scapy import _SCAPY_IMPORT_ERROR
# Transitional re-exports: the tests reach these via the lease_keeper module
# (lk.*); they move to importing from leasekeeper.* directly in the final
# commit of the split, when these lines go away.
from leasekeeper.capture_scapy import (  # noqa: F401  pylint: disable=unused-import
    ARP, BOOTP, DHCP, Ether, IP, UDP, AsyncSniffer, sendp, ScapyCapture)
from leasekeeper.capture_bpf import BpfCapture  # noqa: F401  pylint: disable=unused-import
from leasekeeper.codec import (  # noqa: F401  pylint: disable=unused-import
    BOOTP_HDR_LEN, BOOTP_MIN_PAYLOAD, BPF_ALIGNMENT, BPF_HDR_FIXED, DHCP_MAGIC,
    ETHERTYPE_ARP, ETHERTYPE_IPV4, ETHER_MIN_FRAME, IPPROTO_UDP, _BPF_FILTER,
    _bpf_frames, _decode_arp, _decode_dhcp_options, _decode_ipv4_bootp,
    _encode_arp_request, _encode_bootp_request, _encode_dhcp_options,
    _encode_ether, _encode_ipv4_udp, _inet_checksum, _ip4)






# exactly one place (plus its rc.conf documentation).



from leasekeeper.keeper import Keeper
# Transitional re-exports (removed when the tests import from leasekeeper.*):
from leasekeeper.dhcpclient import DhcpClient, Lease  # noqa: F401  pylint: disable=unused-import
from leasekeeper.policy import ArpNudge, FollowPolicy  # noqa: F401  pylint: disable=unused-import

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
