#!/usr/local/bin/python3
"""Robust DHCP lease-keeper: keep a lease alive for a chosen chaddr.

Keeps a DHCP lease alive for a given ``chaddr`` WITHOUT binding it to the
interface's hardware MAC, so the leased address (typically a CARP virtual IP)
stays routed by the ISP. Lease maintenance ONLY -- ARP for the address and data
traffic are handled by CARP. The BOOTP broadcast flag is set so OFFER/ACK are
broadcast. Optionally (--arp-nudge) it refreshes the upstream gateway's ARP
entry for the leased address, for gateways that never re-ARP an expired entry
(traffic then silently blackholes until they get an ARP *request*). Runs on both
HA nodes for redundancy. Packet capture and send go through a dependency-free
raw /dev/bpf backend (pure Python stdlib, no packet library).

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
    reach Python -- untagged or 802.1Q priority-tagged (VID 0, treated as
    untagged); everything else -- including the who-has flood and frames of
    any real VLAN -- is dropped in the kernel. The few frame kinds the filter
    admits but the decoder does not route (IPv6, 802.1ad/QinQ tags) are
    dropped unparsed in Python.
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
  lease_keeper.py --conf <keeper.conf> --keeper-id <id> ...  # as rc.d starts it
  lease_keeper.py --iface <if> --chaddr <mac> --request <ip>
  lease_keeper.py ... --once            # one-shot claim+verify+release (test)

rc.d passes only the keeper id and the file paths; the daemon reads its settings
from its own keeper.conf record, so values such as the DHCP client-id never
appear on the command line (visible to every local user in ps). A value option
given on the command line wins over the record; a flag is on if either sets it.
The full option set stays for manual runs, --once, and a daemon(8) supervisor
started by an older version, which respawns this script with every setting on
its command line.
"""

import argparse
import logging
import os
import signal
import sys
from logging.handlers import RotatingFileHandler

import keeperconf
from leasekeeper.capture_bpf import BpfCapture
from leasekeeper.constants import LOGGER_NAME
from leasekeeper.keeper import Keeper, carp_master
from leasekeeper.route import (
    BackupEgressConfig, BackupEgressForm, BackupEgressReconciler, DefaultRouteMode,
    DefaultRouteReconciler, withdraw_unless_master)
from leasekeeper.util import MAC_RE

LOG = logging.getLogger(LOGGER_NAME)

# Rotating log-file sizing for _setup_logging. Logging infrastructure for the
# entry point, not DHCP protocol or a daemon tunable, so it lives here with its
# only consumer rather than in the shared constants module.
LOG_MAX_BYTES = 512 * 1024
LOG_BACKUPS = 3

# Exit status when --keeper-id has no record in --conf (or the file is unreadable).
# configd re-renders keeper.conf by truncating it first, so a restart can briefly
# find the file empty; daemon(8) -r restarts the child after its restart delay and
# the next start finds the record.
EXIT_NO_RECORD = 6

# keeper.conf keys and the argparse destinations they fill (template keys; see
# keeperconf.py). "demote" is read only by the CARP status hook.
_CONF_VALUES = {
    "request": "request",
    "iface": "iface",
    "chaddr": "chaddr",
    "vhid": "vhid",
    "vendorclass": "vendor_class",
    "clientid": "client_id",
    "hostname": "hostname",
    "arpnudge": "arp_nudge",
    "defaultroutemode": "default_route_mode",
    "backupegressform": "backup_egress_form",
    "backupegressgateway": "backup_egress_gateway",
    "backupegressinterface": "backup_egress_interface",
    "backupegressprefixes": "backup_egress_prefixes",
}
_CONF_FLAGS = {
    "follow": "follow",
    "arplistenpromisc": "arp_listen_promisc",
    "backupegress": "backup_egress",
}


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


def _find_record(conf, keeper_id):
    """This keeper's keeper.conf record, or None when the file has no line for it."""
    for record in keeperconf.keeper_records(conf):
        if keeperconf.keeper_id(record["request"]) == keeper_id:
            return record
    return None


def _record_defaults(record):
    """Parser defaults from a keeper.conf record, so an option given on the command
    line still wins. An empty field means "not set" in keeper.conf and leaves the
    parser default; a flag field turns the flag on only when it is "1". An ARP nudge
    interval that is not a number (only reachable via a hand-edited config.xml) is
    dropped with a warning, so the nudge stays off instead of argparse exiting 2 into
    a daemon(8) -r crash loop."""
    defaults = {dest: record[key] for key, dest in _CONF_VALUES.items() if record.get(key)}
    defaults.update({dest: True for key, dest in _CONF_FLAGS.items() if record.get(key) == "1"})
    try:
        int(defaults.get("arp_nudge", 0))
    except ValueError:
        LOG.warning("invalid ARP nudge interval %r -- the nudge stays off", defaults.pop("arp_nudge"))
    return defaults


def _build_arg_parser():
    """The daemon's CLI."""
    ap = argparse.ArgumentParser(description="Robust DHCP lease-keeper (chaddr decoupled from the iface MAC)")
    ap.add_argument("--conf", default=None,
                    help="keeper.conf to read this keeper's settings from (with --keeper-id)")
    ap.add_argument("--keeper-id", default=None,
                    help="filesystem-safe id of the keeper.conf record to use (the request IP)")
    # --iface and --chaddr are required, but may come from the keeper.conf record; main()
    # checks them once the record is applied.
    ap.add_argument("--iface", default=None)
    ap.add_argument("--chaddr", default=None)
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
    # Backward compatibility for one upgrade cycle: the capture-backend selector
    # was removed (bpf is the only backend now), but a keeper started by the
    # previous version has a daemon(8) supervisor whose command line still carries
    # --capture-backend. Accept and ignore it so that supervisor's next restart
    # runs this script without exiting 2 and crash-looping until a reconfigure
    # re-renders the arguments.
    ap.add_argument("--capture-backend", help=argparse.SUPPRESS)
    # No argparse `choices` on the two enum args below: an unrecognised value is
    # coerced to a safe default with a warning in main() (see DefaultRouteMode /
    # BackupEgressForm .coerce), not rejected with exit 2 -- which daemon(8) -r
    # would turn into a crash loop. The keeper.conf record carries any string.
    ap.add_argument("--default-route-mode", default=DefaultRouteMode.OFF.value,
                    help="own the IPv4 default route by CARP role: off (default), observe "
                         "(log what it would do, no FIB write), or enforce (install/withdraw "
                         "0/0 via the lease gateway while CARP master holding a lease)")
    ap.add_argument("--backup-egress", action="store_true",
                    help="while CARP backup, route this node's own internet traffic to the "
                         "master (needs default-route-mode observe/enforce); see backup-egress docs")
    ap.add_argument("--backup-egress-form", default=BackupEgressForm.SPLIT.value,
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
        except OSError as e:
            # No log sink is configured yet, so stash the reason and emit it
            # once logging is up -- otherwise a bad --logfile (unwritable dir,
            # bad path) leaves an empty log with no explanation.
            logfile_error = e
    logging.basicConfig(level=logging.DEBUG, handlers=handlers,
                        format="%(asctime)s %(levelname)s %(message)s")
    if logfile_error is not None:
        LOG.warning("could not open log file %s: %s -- logging to stderr only",
                    logfile, logfile_error)


def _settings():
    """Parse the command line and set up logging. With --conf/--keeper-id, this
    keeper's keeper.conf record becomes the parser defaults and the command line is
    parsed again; the free-string enum values are then coerced now that logging is
    up. Returns the settings, or an exit status when the daemon cannot start."""
    parser = _build_arg_parser()
    args = parser.parse_args()
    _setup_logging(args.logfile)
    if args.conf or args.keeper_id:
        if not (args.conf and args.keeper_id):
            LOG.critical("--conf and --keeper-id must be given together -- the lease keeper cannot start")
            return 2
        record = _find_record(args.conf, args.keeper_id)
        if record is None:
            LOG.error("no keeper %s in %s (being rewritten, or the keeper was removed) -- "
                      "exiting; the supervisor retries", args.keeper_id, args.conf)
            return EXIT_NO_RECORD
        parser.set_defaults(**_record_defaults(record))
        args = parser.parse_args()
    args.default_route_mode = DefaultRouteMode.coerce(args.default_route_mode)
    args.backup_egress_form = BackupEgressForm.coerce(args.backup_egress_form)
    if not args.iface or not args.chaddr:
        LOG.critical("no interface or client MAC (chaddr) given -- the lease keeper cannot start")
        return 2
    return args


def main():
    """CLI entry point: parse args, wire up the Keeper and signals, run."""
    args = _settings()
    if isinstance(args, int):
        return args

    # Single-instance guard BEFORE any FIB mutation: the startup fail-stop withdraw
    # below deletes a default, so a duplicate start (pidfile held by the live owner)
    # must exit HERE -- already running -- rather than clobber the owner's default
    # and only then discover it is the duplicate. Held across the withdraw and the
    # backend/arg checks; the finally releases it on every exit. --once is a wiring
    # test: no guard and no FIB mutation, so it takes neither (pf stays None).
    pf = None if args.once else acquire_pidfile(args.pidfile)
    try:
        # Built before the fail-stop so the startup reconciler can clean the backup-egress
        # routes this feature manages when it is enabled (else a node coming up as master
        # with a stale /1 a crashed predecessor left would loop its egress).
        backup_egress = BackupEgressConfig(
            enabled=args.backup_egress,
            form=args.backup_egress_form,
            gateway=args.backup_egress_gateway or None,
            interface=args.backup_egress_interface or None,
            prefixes=_split_prefixes(args.backup_egress_prefixes))

        # Fail-stop: a crashed predecessor (backend now missing, or a bad arg) may
        # have left a default in the FIB, still redistributed by FRR. Drop it here --
        # pure route(8), no capture backend -- BEFORE the backend preflight and the
        # arg checks, each of which can return before Keeper.run() would. The gate
        # (a master keeps its default, a backup withdraws; probe only when the mode
        # acts) lives in withdraw_unless_master. Skipped for --once and no vhid.
        if not args.once and args.vhid:
            # args.default_route_mode is already coerced (above), so both reconcilers take
            # it verbatim; the backup set is cleaned before the 0/0 withdraw inside
            # withdraw_unless_master, the one sequence that spans the two reconcilers.
            withdraw_unless_master(
                DefaultRouteReconciler(args.default_route_mode),
                BackupEgressReconciler(args.default_route_mode, backup_egress=backup_egress),
                lambda: carp_master(args.iface, args.vhid))

        # Fail fast (with a logged reason) if the raw /dev/bpf backend cannot run
        # on this host (e.g. fcntl missing off FreeBSD).
        reason = BpfCapture.unavailable_reason()
        if reason is not None:
            LOG.critical("capture backend cannot run: %s -- the lease keeper cannot start", reason)
            return 3

        for label, mac in (("chaddr", args.chaddr), ("eth-src", args.eth_src)):
            if mac and not MAC_RE.match(mac):
                LOG.critical("invalid %s MAC address %r -- the lease keeper cannot start", label, mac)
                return 2

        keeper = Keeper(args.iface, args.chaddr, args.request, args.eth_src,
                        hbfile=args.hbfile, release_on_exit=args.release_on_exit or args.once,
                        vhid=args.vhid, follow=args.follow,
                        vendor_class=args.vendor_class, client_id=args.client_id, hostname=args.hostname,
                        arp_nudge=args.arp_nudge, arp_listen_promisc=args.arp_listen_promisc,
                        default_route_mode=args.default_route_mode,
                        backup_egress=backup_egress)

        # The Keeper is constructed, so its wake socketpair is now open: guarantee
        # keeper.close() on EVERY path from here -- the --once return, a normal run,
        # or an exception during signal setup -- via one outer finally, not a
        # per-path close. Otherwise a path that skips it leaks the socketpair (a
        # repeated in-process main() would leak two fds per call).
        try:
            # Warn only when promiscuous capture is ACTUALLY in effect: it is gated on the ARP
            # nudge (see Keeper.__init__), so a stale flag with the nudge disabled is ignored,
            # not promiscuous -- warning off the raw flag would contradict that and misstate the
            # node's security posture.
            if args.arp_listen_promisc and args.arp_nudge > 0:
                LOG.warning("ARP listen: PROMISCUOUS capture enabled on %s -- the daemon now "
                            "sees all traffic on the segment (opt-in fallback for NICs that "
                            "drop the gateway's unicast ARP reply otherwise)", args.iface)

            def _sig(*_):
                # Flag only -- no logging or other non-async-signal-safe work in the
                # handler (like the SIGUSR1/2 handlers below). set_wakeup_fd wakes the
                # loop at once; run() logs "stopped" when it exits.
                keeper.request_stop()
            signal.signal(signal.SIGINT, _sig)
            signal.signal(signal.SIGTERM, _sig)

            # SIGUSR1/SIGUSR2 are POSIX-only (the daemon runs on FreeBSD); access them
            # dynamically so a non-POSIX static-analysis host neither errors nor needs a
            # suppression that is then flagged as useless where the attributes do exist.
            def _sig_arp_nudge(*_):
                # Operator-requested immediate ARP nudge (configd action / kill -USR1).
                keeper.trigger_nudge()
            signal.signal(getattr(signal, "SIGUSR1"), _sig_arp_nudge)

            def _sig_carp(*_):
                # CARP transition (rc.syshook.d/carp/50-carpvipdhcp sends SIGUSR2).
                keeper.recheck_carp_role()
            signal.signal(getattr(signal, "SIGUSR2"), _sig_carp)

            if args.once:
                return keeper.claim_once()   # --once never arms set_wakeup_fd; outer finally closes

            # Wake the maintain-loop sleep the instant a signal is delivered: Python's
            # C-level signal machinery writes the signal number to this fd, which is
            # async-signal-safe and needs no work in the handler (the _sig* handlers
            # above only set a flag). The loop selects on the read end and drains it.
            signal.set_wakeup_fd(keeper.wake_fileno())
            try:
                return keeper.run()
            finally:
                # Order matters: unregister the C-level signal wakeup fd BEFORE the
                # outer finally closes the wake socket it points at. Otherwise a signal
                # in the shutdown window makes the C machinery write to a closed (or, in
                # the worst case, a reused) fd. This inner finally runs first.
                signal.set_wakeup_fd(-1)
        finally:
            keeper.close()
    finally:
        if pf and os.path.exists(pf):
            try:
                os.unlink(pf)
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())
