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

# The daemon must never die on unexpected input: the components log-and-continue
# on a catch-all (see the docstring); main() and one-shot mode do the same.
# pylint: disable=broad-exception-caught
import argparse
import logging
import os
import signal
import sys
from logging.handlers import RotatingFileHandler

from leasekeeper.capture import CAPTURE_BACKENDS
from leasekeeper.constants import LOGGER_NAME
from leasekeeper.keeper import Keeper, carp_master
from leasekeeper.route import (
    BackupEgressConfig, BackupEgressForm, DefaultRouteMode, DefaultRouteReconciler)
from leasekeeper.util import MAC_RE

LOG = logging.getLogger(LOGGER_NAME)

# Rotating log-file sizing for _setup_logging. Logging infrastructure for the
# entry point, not DHCP protocol or a daemon tunable, so it lives here with its
# only consumer rather than in the shared constants module.
LOG_MAX_BYTES = 512 * 1024
LOG_BACKUPS = 3


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
            except (OSError, ValueError):
                old = None      # unreadable / garbage pidfile content -> treat as stale
            if old is not None:
                try:
                    os.kill(old, 0)
                except ProcessLookupError:
                    pass        # dead pid -> stale, fall through to remove and retry
                except PermissionError:
                    # The pid exists but is owned by another user: a LIVE process,
                    # not a stale file. Removing its pidfile would let a second
                    # instance start, so exit instead.
                    LOG.error("pidfile %s held by a live process (pid %d, foreign "
                              "owner) -- exiting", path, old)
                    sys.exit(4)
                else:
                    LOG.error("already running (pid %d, %s) -- exiting", old, path)
                    sys.exit(4)
            # Stale (dead pid or unreadable content): remove it and retry the create.
            try:
                os.unlink(path)
                LOG.info("replaced stale pidfile %s (dead pid %s)",
                         path, old if old is not None else "unreadable")
            except OSError as e:
                # If the stale file cannot be removed (e.g. a permission problem
                # that will not self-heal), exit instead of spinning the
                # create/unlink loop forever with no log.
                LOG.error("cannot remove stale pidfile %s: %s -- exiting", path, e)
                sys.exit(5)
        except OSError as e:
            LOG.critical("cannot write pidfile %s: %s -- exiting", path, e)
            sys.exit(5)


def _split_prefixes(raw):
    """Split a backup-egress prefix list on commas and/or whitespace (both are documented
    and allowed by the model mask), dropping empty tokens. Returns a tuple, empty for a
    blank/None field."""
    return tuple((raw or "").replace(",", " ").split())


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
    ap.add_argument("--default-route-mode", choices=[m.value for m in DefaultRouteMode],
                    default=DefaultRouteMode.OFF.value,
                    help="own the IPv4 default route by CARP role: off (default), observe "
                         "(log what it would do, no FIB write), or enforce (install/withdraw "
                         "0/0 via the lease gateway while CARP master holding a lease)")
    ap.add_argument("--backup-egress", action="store_true",
                    help="while CARP backup, route this node's own internet traffic to the "
                         "master (needs default-route-mode observe/enforce); see backup-egress docs")
    ap.add_argument("--backup-egress-form", choices=[f.value for f in BackupEgressForm],
                    default=BackupEgressForm.SPLIT.value,
                    help="split (0.0.0.0/1+128.0.0.0/1, the default) or prefixes")
    ap.add_argument("--backup-egress-gateway", default=None,
                    help="stable next hop for backup egress (a CARP VIP or fallback-WAN gateway); "
                         "blank derives the point-to-point peer of --backup-egress-interface")
    ap.add_argument("--backup-egress-interface", default=None,
                    help="interface to derive the backup-egress peer from when no gateway is set")
    ap.add_argument("--backup-egress-prefixes", default=None,
                    help="comma-separated prefixes for --backup-egress-form prefixes")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--release-on-exit", action="store_true")
    return ap


def _setup_logging(logfile):
    """stderr plus a rotating file. DEBUG is always written (routine detail
    like the renew/rebind plan): the volume is low, the log page hides DEBUG
    by default, and its filter reveals it -- so "turning up the log level"
    needs no daemon restart."""
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    logfile_error = None
    if logfile:
        try:
            handlers.append(RotatingFileHandler(logfile, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUPS))
        except Exception as e:
            # No log sink is configured yet, so stash the reason and emit it
            # once logging is up -- otherwise a bad --logfile (unwritable dir,
            # bad path) leaves an empty log with no explanation.
            logfile_error = e
    logging.basicConfig(level=logging.DEBUG, handlers=handlers,
                        format="%(asctime)s %(levelname)s %(message)s")
    if logfile_error is not None:
        LOG.warning("could not open log file %s: %s -- logging to stderr only",
                    logfile, logfile_error)


def main():
    """CLI entry point: parse args, wire up the Keeper and signals, run."""
    a = _build_arg_parser().parse_args()
    _setup_logging(a.logfile)

    # Single-instance guard BEFORE any FIB mutation: the startup fail-stop withdraw
    # below deletes a default, so a duplicate start (pidfile held by the live owner)
    # must exit HERE -- already running -- rather than clobber the owner's default
    # and only then discover it is the duplicate. Held across the withdraw and the
    # backend/arg checks; the finally releases it on every exit. --once is a wiring
    # test: no guard and no FIB mutation, so it takes neither (pf stays None).
    pf = None if a.once else acquire_pidfile(a.pidfile)
    try:
        # Built before the fail-stop so the startup reconciler can clean the backup-egress
        # routes this feature manages when it is enabled (else a node coming up as master
        # with a stale /1 a crashed predecessor left would loop its egress).
        backup_egress = BackupEgressConfig(
            enabled=a.backup_egress,
            form=BackupEgressForm(a.backup_egress_form),
            gateway=a.backup_egress_gateway or None,
            interface=a.backup_egress_interface or None,
            prefixes=_split_prefixes(a.backup_egress_prefixes))

        # Fail-stop: a crashed predecessor (backend now missing, or a bad arg) may
        # have left a default in the FIB, still redistributed by FRR. Drop it here --
        # pure route(8), no capture backend -- BEFORE the backend preflight and the
        # arg checks, each of which can return before Keeper.run() would. The gate
        # (a master keeps its default, a backup withdraws; probe only when the mode
        # acts) lives in withdraw_unless_master. Skipped for --once and no vhid.
        if not a.once and a.vhid:
            DefaultRouteReconciler(a.default_route_mode, backup_egress=backup_egress) \
                .withdraw_unless_master(lambda: carp_master(a.iface, a.vhid))

        # Fail fast (with a logged reason) if the selected backend cannot run on
        # this host -- checked uniformly through the registry so a future backend
        # with an optional dependency is covered without a special case here.
        reason = CAPTURE_BACKENDS[a.capture_backend].unavailable_reason()
        if reason is not None:
            LOG.critical("capture backend %r cannot run: %s -- the lease keeper cannot start",
                         a.capture_backend, reason)
            return 3

        for label, mac in (("chaddr", a.chaddr), ("eth-src", a.eth_src)):
            if mac and not MAC_RE.match(mac):
                LOG.critical("invalid %s MAC address %r -- the lease keeper cannot start", label, mac)
                return 2

        k = Keeper(a.iface, a.chaddr, a.request, a.eth_src,
                   hbfile=a.hbfile, release_on_exit=a.release_on_exit or a.once,
                   vhid=a.vhid, follow=a.follow,
                   vendor_class=a.vendor_class, client_id=a.client_id, hostname=a.hostname,
                   arp_nudge=a.arp_nudge, arp_listen_promisc=a.arp_listen_promisc,
                   capture_backend=a.capture_backend, default_route_mode=a.default_route_mode,
                   backup_egress=backup_egress)

        # Warn only when promiscuous capture is ACTUALLY in effect: it is gated on the ARP
        # nudge (see Keeper.__init__), so a stale flag with the nudge disabled is ignored,
        # not promiscuous -- warning off the raw flag would contradict that and misstate the
        # node's security posture.
        if a.arp_listen_promisc and a.arp_nudge > 0:
            LOG.warning("ARP listen: PROMISCUOUS capture enabled on %s -- the daemon now "
                        "sees all traffic on the segment (opt-in fallback for NICs that "
                        "drop the gateway's unicast ARP reply otherwise)", a.iface)

        def _sig(*_):
            # Flag only -- no logging or other non-async-signal-safe work in the
            # handler (like the SIGUSR1/2 handlers below). set_wakeup_fd wakes the
            # loop at once; run() logs "stopped" when it exits.
            k.request_stop()
        signal.signal(signal.SIGINT, _sig)
        signal.signal(signal.SIGTERM, _sig)

        # SIGUSR1/SIGUSR2 are POSIX-only (the daemon runs on FreeBSD); access them
        # dynamically so a non-POSIX static-analysis host neither errors nor needs a
        # suppression that is then flagged as useless where the attributes do exist.
        def _sig_arp_nudge(*_):
            # Operator-requested immediate ARP nudge (configd action / kill -USR1).
            k.trigger_nudge()
        signal.signal(getattr(signal, "SIGUSR1"), _sig_arp_nudge)

        def _sig_carp(*_):
            # CARP transition (rc.syshook.d/carp/50-carpvipdhcp sends SIGUSR2).
            k.recheck_carp_role()
        signal.signal(getattr(signal, "SIGUSR2"), _sig_carp)

        if a.once:
            return k.claim_once()

        # Wake the maintain-loop sleep the instant a signal is delivered: Python's
        # C-level signal machinery writes the signal number to this fd, which is
        # async-signal-safe and needs no work in the handler (the _sig* handlers
        # above only set a flag). The loop selects on the read end and drains it.
        signal.set_wakeup_fd(k.wake_fileno())
        try:
            return k.run()
        finally:
            # Stop the C-level signal machinery from writing to the wake socket
            # before run() closes it; otherwise a signal in the shutdown window
            # writes to a closed fd (harmless, but noisy on stderr).
            signal.set_wakeup_fd(-1)
    finally:
        if pf and os.path.exists(pf):
            try:
                os.unlink(pf)
            except Exception:
                pass


if __name__ == "__main__":
    sys.exit(main())
