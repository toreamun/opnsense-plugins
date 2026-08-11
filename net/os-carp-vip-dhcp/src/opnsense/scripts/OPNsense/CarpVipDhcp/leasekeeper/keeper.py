"""Keeper orchestration: owns the capture backend (feeding DHCP replies to
DhcpClient, ARP replies to ArpNudge and peer-ACK observations to FollowPolicy),
the heartbeat, the CARP role watch, the acquire pacing and the signal-driven
operator actions.
"""
import logging
import select
import socket
import subprocess
import time
from dataclasses import dataclass

from . import __version__
from .capture import CAPTURE_BACKENDS
from .constants import (
    LOGGER_NAME,
    ACK, BootpOp, DhcpOptName, HB_REFRESH, LINK_KICK_DEBOUNCE, LINK_POLL_STEP,
    LOOP_ERROR_BACKOFF, Phase, REBIND_POLL_STEP, REDORA_MAX, REDORA_MIN,
    SNIFFER_RETRY, SNIFFER_WARMUP)
from .dhcpclient import DhcpClient
from .policy import ArpNudge, FollowPolicy
from .route import DefaultRouteReconciler
from .util import _atomic_write, _clock_at, _jittered, _sane_ipv4
from .wire import _parse_reply

LOG = logging.getLogger(LOGGER_NAME)

# Daemon log-and-continue posture: broad catch-alls are deliberate (see the
# package docstring / module docstrings).
# pylint: disable=broad-exception-caught

# The keeper's dependency on ifconfig(8) output text, named in one place. The
# trailing space in the CARP format is load-bearing: it stops vhid 1 matching
# "vhid 11".
CARP_MASTER_FMT = "carp: MASTER vhid {vhid} "
IFCONFIG_STATUS_ACTIVE = "status: active"    # carrier up
IFCONFIG_STATUS = "status: "                 # any status line present (up or down)

# "CARP-master value not supplied" sentinel: the maintain loop probes the role
# once per tick and shares it, but None is a valid probe result, so a distinct
# sentinel means "probe it now".
_UNSET = object()


def _ifconfig_text(iface):
    """Raw `ifconfig <iface>` text, or None if it could not run (no logging -- each
    caller adds its own error policy)."""
    try:
        out = subprocess.check_output(["/sbin/ifconfig", iface], errors="replace")
    except (OSError, subprocess.SubprocessError):
        return None
    return out.decode(errors="replace") if isinstance(out, bytes) else out


def _carp_master(ifconfig_text, vhid):
    """CARP-master decision from ifconfig text: True/False for the vhid, None when
    the text is missing (probe failed), True when no vhid (nothing to gate on)."""
    if not vhid:
        return True
    if ifconfig_text is None:
        return None
    return CARP_MASTER_FMT.format(vhid=vhid) in ifconfig_text


def carp_master(iface, vhid):
    """CARP-master role for `vhid` on `iface` (True/False, None on probe failure).
    Standalone -- no Keeper -- so the daemon entry point can gate its startup
    fail-stop default withdraw on the role before the Keeper / capture backend
    exist; the Keeper's per-tick probe (_probe_carp_master) shares CARP_MASTER_FMT
    through _carp_master."""
    return _carp_master(_ifconfig_text(iface), vhid)


@dataclass
class _SignalFlags:
    """The only shared state a signal handler may write, behind a tiny protocol
    that makes the safe usage the only usage.

    A signal handler (request_stop / request_nudge / request_recheck_role) runs
    on the MAIN thread, between bytecodes; the single safe thing it does is flip
    one of these booleans to True -- one bytecode, hence atomic w.r.t. signal
    delivery (never torn), and independent of the others. The maintain loop
    drains each edge flag with take_*() (check-and-clear in one place) and polls
    the terminal stop flag via `stopping`. The fields are private and reached
    only through these methods so the rule "a handler only ever sets True, the
    loop only ever clears" is structural, not a comment a later edit can quietly
    break: this is what makes the path correct WITHOUT a lock. Do NOT let a
    handler do more (no I/O, no mutation of the binding / lease / role), and do
    NOT set a flag from another thread -- either reintroduces re-entrancy and
    consistency bugs. Add a new signal-driven request as another private bool
    plus a request_*/take_* pair, never by doing work in the handler.
    """
    _stop: bool = False           # SIGINT / SIGTERM
    _nudge: bool = False          # SIGUSR1
    _recheck_role: bool = False   # SIGUSR2 (CARP transition / route_reload)

    # -- handler side: set True (idempotent, async-signal-safe: one bytecode) --
    def request_stop(self):
        """Ask the loop to exit (SIGINT/SIGTERM handler)."""
        self._stop = True

    def request_nudge(self):
        """Ask for an immediate ARP nudge (SIGUSR1 handler)."""
        self._nudge = True

    def request_recheck_role(self):
        """Ask for a CARP-role re-check (SIGUSR2 handler)."""
        self._recheck_role = True

    # -- main-loop side --
    # take_*() reads-then-clears and is NOT masked against signal delivery: a
    # signal landing between the read and the store can be erased by the store,
    # dropping that one edge. This needs no lock or signal masking because each
    # edge has a periodic fallback -- a dropped CARP re-check (SIGUSR2) is caught
    # by the next per-tick role poll, and the periodic ARP nudge keeps reachability
    # fresh regardless of a dropped manual nudge (SIGUSR1) -- so a lost edge costs
    # at most one poll interval of latency, never a missed state change.
    # The one stretch where that interval is longer than a tick is inside a
    # blocking DhcpClient.renew()/reboot() reply wait, which services only the stop
    # callback: a CARP edge that lands there is reconciled when the call returns
    # (the renew/rebind-success arms and the REBIND loop all reconcile), so failover
    # convergence is delayed by at most one renew/rebind attempt there, not lost.
    @property
    def stopping(self):
        """Terminal stop flag; polled (never cleared) by every loop/sleep guard."""
        return self._stop

    def take_nudge(self):
        """Whether an immediate ARP nudge was requested; clears it (loop only)."""
        pending, self._nudge = self._nudge, False
        return pending

    def take_recheck_role(self):
        """Whether a CARP-role re-check was requested; clears it (loop only)."""
        pending, self._recheck_role = self._recheck_role, False
        return pending


@dataclass(frozen=True)
class _Config:
    """The keeper's fixed identity/config, set once from the constructor and
    never mutated -- so a frozen dataclass."""
    iface: str
    chaddr: str
    eth_src: str
    hbfile: "str | None"
    release_on_exit: bool
    vhid: "str | None"


@dataclass
class _LinkState:
    """WAN-carrier state for the unbound link-return fast path (main-loop only).
    up: last carrier seen (None = not probed). ifconfig_failed: gate to log an
    ifconfig probe failure once per episode. kick_at: epoch of the last
    link-return kick (debounce). returned: set by _sleep_interruptible on a
    carrier return while unbound."""
    up: "bool | None" = None
    ifconfig_failed: bool = False
    kick_at: float = 0.0
    returned: bool = False


class Keeper:  # pylint: disable=too-many-instance-attributes
    """Orchestration around the components: owns the capture backend (feeding
    DHCP replies to DhcpClient, ARP replies to ArpNudge and peer-ACK
    observations to FollowPolicy), the heartbeat, the CARP role watch, the
    acquire pacing (backoff + link-return fast path) and the signal-driven
    operator actions. The lease lives in DhcpClient; the changed-address
    decision and the target address live in FollowPolicy."""

    def __init__(self, iface, chaddr, request_ip=None,  # pylint: disable=too-many-arguments,too-many-locals
                 eth_src=None, *,
                 hbfile=None, release_on_exit=False, vhid=None,
                 follow=False, vendor_class=None, client_id=None, hostname=None,
                 arp_nudge=0, arp_listen_promisc=False, capture_backend="scapy",
                 default_route_mode="off"):
        # Fixed identity/config, immutable once set (see _Config).
        self._cfg = _Config(
            iface=iface,
            chaddr=chaddr.lower(),
            eth_src=(eth_src or chaddr).lower(),
            hbfile=hbfile,
            release_on_exit=release_on_exit,
            vhid=str(vhid) if vhid else None)

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
        self._nudge = ArpNudge(self._capture, self._cfg.chaddr, arp_nudge, self._carp_master_probe)

        self._was_master = None        # CARP role at the last nudge check (None = unknown yet)

        # The only shared state a signal handler may write (invariant on the type).
        self._signals = _SignalFlags()

        # Main-loop-only state (set by the loop itself, never by a handler):
        self._renew_asap = False       # renew at the next _hold_lease tick instead of waiting for T1

        # DHCP client component: owns the lease state and the protocol sequences;
        # the keeper owns the capture (feeding it xid-matched replies) and the
        # policy hooks.
        self._dhcp = DhcpClient(
            self._capture, self._cfg.chaddr, self._cfg.eth_src,
            _identity_options(vendor_class, client_id, hostname),
            should_stop=lambda: self._signals.stopping,
            ensure_sniffer=self._ensure_sniffer,
            on_changed_address=self._on_changed_address)

        # Follow/enforce policy component: owns the target address and the
        # follow bookkeeping; drives the client via adopt()/release()/expire().
        self._follow = FollowPolicy(request_ip, follow, self._cfg.chaddr, self._dhcp,
                                    self._hb_mismatch,
                                    dispatch=self._dispatch_follow_update)

        # Default-route ownership component (opt-in via defaultRouteMode): owns
        # the IPv4 default route as a function of (CARP role, lease-held, lease
        # gateway) -- off/observe/enforce, where off and observe never touch the
        # FIB. Driven from the main loop only, on the CARP-role cadence
        # (_reconcile_default_route). liveness_probe is left unset for now: the
        # split-brain install-gate is a deliberate follow-up that needs a
        # debounced carrier signal (a single transient ifconfig miss must not
        # flap the default); see docs/single-ip-wan-carp.md.
        self._defroute = DefaultRouteReconciler(default_route_mode)

        self.redora_wait = REDORA_MIN
        # Link-return fast path (only while UNBOUND): a carrier down->up edge
        # resets the backoff and re-DORAs at once, like dhclient's link-up ->
        # state_reboot. Its carrier state is grouped in _LinkState.
        self._link = _LinkState()

        # Wake pipe for the maintain-loop sleep: _sleep_interruptible selects on
        # the read end, and _signal_wake() writes one byte to make it return at
        # once instead of waiting out the 1s tick. Woken from two places: the
        # capture thread on an observed peer ACK (so the follow fires in
        # milliseconds), and the operator signal handlers (SIGTERM/USR1/USR2) so
        # stop/nudge/carp-recheck act at once. A socketpair (not os.pipe) so
        # select() works on every platform, incl. the test host; os.write on the
        # fd is async-signal-safe, unlike threading.Event.set().
        self._wake_r, self._wake_w = socket.socketpair()
        self._wake_r.setblocking(False)
        self._wake_w.setblocking(False)

    # ---- capture (resilient) ----
    def _ensure_sniffer(self):
        if not self._capture.alive():
            LOG.warning("DHCP-reply capture down -- (re)starting")
            if not self._capture.start():
                # The backend already logged why at ERROR; make the persistent
                # case explicit so the preceding "(re)starting" is not read as
                # success -- until the capture recovers, every exchange times out.
                LOG.error("DHCP-reply capture restart failed -- exchanges will "
                          "time out until it recovers")
            time.sleep(1)

    def _on_arp_reply(self, frame):
        """Capture-backend ARP callback: the gateway answering our nudge
        (reachability stamp); the nudge component does the matching."""
        self._nudge.on_arp_reply(frame, self._dhcp.binding.yiaddr, self._nudge_target())

    def _chaddr_matches(self, frame):
        """True if the reply's BOOTP client hardware address is our chaddr (the
        CARP virtual MAC). Used to accept the PEER's ACK on the shared chaddr:
        the peer node runs an identical keeper on the very same chaddr."""
        # The BOOTP chaddr field is 16 bytes; compare only the 6-byte MAC.
        return frame.chaddr[:6] == self._dhcp.chraw

    def _on_dhcp_reply(self, frame):
        # Runs on the capture thread under the backend's handler guard
        # (_deliver), so an unexpected failure here is logged and dropped there.
        if frame.op != BootpOp.REPLY:
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
        # _sane_ipv4 here is only a cheap pre-filter to suppress a spurious
        # main-loop wake for an obviously-bogus peer ACK; it is NOT the
        # authoritative check. FollowPolicy re-validates plausibility (plus
        # class / expected-server / throttle) when it consumes the observation.
        if (rx.mtype == ACK and rx.yiaddr and rx.yiaddr != self._dhcp.binding.yiaddr
                and _sane_ipv4(rx.yiaddr)):
            self._follow.observe(rx)
            self._signal_wake()   # wake the maintain-loop sleep now, don't wait for the tick

    # ---- heartbeat / status file ----

    def _write_hb(self, content):
        if not self._cfg.hbfile:
            return
        try:
            _atomic_write(self._cfg.hbfile, content)
        except Exception as e:
            # The heartbeat drives CARP gating, so a write failure is worth surfacing.
            LOG.warning("heartbeat write failed (%s): %s", self._cfg.hbfile, e)

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

    def _dispatch_follow_update(self, old_ip, new_ip, gw_args):
        """FollowPolicy's injected side-effect seam: dispatch the configd
        follow_update action (the CARP-VIP rewrite). The one place the follow
        path touches a system binary lives here in the orchestration layer, not
        in the decision module. Fire-and-forget: the resulting service restart
        replaces this daemon with one bound to the new address."""
        cmd = ["/usr/local/sbin/configctl", "-d", "carpvipdhcp", "follow_update", old_ip, new_ip]
        cmd += gw_args   # cross-subnet: [old_gw, new_gw, bits]; empty on a same-subnet move
        subprocess.Popen(cmd)  # pylint: disable=consider-using-with

    # ---- CARP role (master probe, transitions) ----

    def _ifconfig(self) -> "str | None":
        """Captured `ifconfig <iface>` text, or None if the probe failed. Shared by
        the CARP-role probe and the carrier check so the ifconfig invocation, decode
        and error policy live in exactly one place.

        A persistent probe failure silently degrades both callers (the CARP
        nudge fails closed, the transition poll skips), so warn once per failure
        episode -- otherwise a wrong --iface or a broken ifconfig looks identical
        to a healthy backup in the log."""
        out = _ifconfig_text(self._cfg.iface)
        if out is None:
            if not self._link.ifconfig_failed:
                LOG.warning("ifconfig %s probe failed -- CARP role and carrier "
                            "state unknown until it recovers", self._cfg.iface)
                self._link.ifconfig_failed = True
            return None
        if self._link.ifconfig_failed:
            LOG.info("ifconfig %s probe recovered", self._cfg.iface)
            self._link.ifconfig_failed = False
        return out

    def _probe_carp_master(self) -> "bool | None":
        """Raw CARP-role probe for our vhid: True/False from ifconfig, None when
        the probe itself fails; no vhid configured -> True (nothing to gate on).
        Callers apply their own policy on a None probe -- the ARP nudge fails closed
        (no nudge unless a confirmed MASTER); the CARP-transition poll just skips.
        Uses the warn-once _ifconfig(), unlike the standalone carp_master()."""
        return _carp_master(self._ifconfig(), self._cfg.vhid)

    def _carp_master_probe(self) -> "bool | None":
        """ArpNudge's is_master hook -> the CARP probe (late-bound through the
        attribute so tests can stub _probe_carp_master)."""
        return self._probe_carp_master()

    def _iface_link_up(self) -> "bool | None":
        """Interface carrier from ifconfig: True on 'status: active', False on a
        present-but-inactive status (no carrier / no link), None when it cannot be
        read (probe failed, or the NIC reports no status line). Used by the
        unbound link-return fast path and the acquire carrier gate; a None
        result never disturbs the backoff and never holds an acquire."""
        out = self._ifconfig()
        if out is None:
            return None
        if IFCONFIG_STATUS_ACTIVE in out:
            return True
        if IFCONFIG_STATUS in out:
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
        prev = self._link.up
        self._link.up = up
        if up and prev is False:
            now = time.time()
            if now - self._link.kick_at < LINK_KICK_DEBOUNCE:
                return False
            self._link.kick_at = now
            return True
        return False

    def _poll_carp_role(self, master=_UNSET):
        """Watch for a backup->master transition (called on the heartbeat
        cadence). Becoming master renews the lease early and, when enabled,
        nudges immediately: the failover -- or the link flap that re-elected
        CARP -- may just have disturbed the upstream gateway's ARP entry and the
        access node's DHCP-snooping binding, so neither should wait out its
        normal timer. Independent of the ARP nudge setting. `master` lets the
        maintain loop pass the role it already probed this tick."""
        if not self._cfg.vhid:
            return
        if master is _UNSET:
            master = self._probe_carp_master()
        if master is None:
            return
        if master and self._was_master is False:
            LOG.info("became CARP master for vhid %s -- immediate ARP nudge and early lease renew",
                     self._cfg.vhid)
            self._renew_asap = True
            self._arp_nudge(force=True, master=master)
        elif not master and self._was_master:
            # The symmetric event: without it, "why did the nudges stop?" needs
            # ifconfig instead of the log.
            LOG.info("lost CARP master for vhid %s -- ARP nudges pause on this node", self._cfg.vhid)
        self._was_master = master

    def _reconcile_default_route(self, master=_UNSET):
        """Drive the IPv4 default route toward its CARP-role-owned desired state
        (install 0/0 via the lease gateway only while master AND holding a lease;
        withdraw it otherwise -- see leasekeeper/route.py). Level-triggered and
        idempotent, so it can ride every point that changes the inputs -- the
        per-tick heartbeat probe (bound), the acquire arm (unbound and just after
        a successful acquire), the SIGUSR2 CARP edge, and a fail-stop non-master
        withdraw at startup and on shutdown -- converging without having to catch
        every transition. No-op unless a
        vhid is configured (no CARP role to key on) and the mode is
        observe/enforce. `master` reuses the tick's probe when the caller has it.

        Passes bound=yiaddr-is-set and gateway=binding.lease_router (the CURRENT
        lease's own opt-3 gateway, not the sticky binding.router hint), so a new
        lease that omits option 3 never installs a default via a stale gateway;
        reconcile() owns the contract for why bound must not be inferred from it."""
        if not self._cfg.vhid or not self._defroute.enabled:
            return
        if master is _UNSET:
            master = self._probe_carp_master()
        b = self._dhcp.binding
        self._defroute.reconcile(master, b.yiaddr is not None, b.lease_router)

    def _role_tick(self, master=_UNSET):
        """One shared CARP-role probe driving both the role poll and the
        default-route reconcile, so a heartbeat tick, the SIGUSR2 edge and the
        REBIND loop never spawn two ifconfigs or let the poll and the reconcile
        drift apart. Returns the probed role for any further per-tick use (the ARP
        nudge). Pass an already-probed role to skip the ifconfig."""
        if master is _UNSET:
            master = self._probe_carp_master()
        self._poll_carp_role(master)
        self._reconcile_default_route(master)
        return master

    def _on_lease_extended(self, phase):
        """A RENEW or REBIND (the Phase) landed a fresh lease: refresh the heartbeat
        and force an ARP nudge. The default route is reconciled by the loop-head
        reconcile on the next _maintain_step entry (a renewed lease can carry a new
        option-3 gateway), so it is not repeated here."""
        b = self._dhcp.binding
        LOG.info("DHCP %s ok %s (lease=%ss, expires ~%s)", phase, b.yiaddr, b.lease_secs,
                 _clock_at(b.lease_secs))
        self._hb()
        self._arp_nudge(force=True)

    def _on_lease_revoked(self, phase):
        """A RENEW or REBIND (the Phase) drew a DHCPNAK: renew() has already
        forgotten the binding (RFC 2131 4.4.5 -> INIT, not keep REBINDing a refused
        address), so the next _maintain_step entry is unbound and its loop-head
        reconcile withdraws any default we owned; just log the revoke here."""
        LOG.warning("DHCP %s got NAK -- lease revoked, re-acquiring", phase)

    # ---- ARP nudge ----

    def _nudge_target(self):
        """The gateway whose ARP cache the nudge maintains: DHCP option 3 from
        the last ACK, falling back to the leasing server's address."""
        return self._dhcp.binding.router or self._dhcp.binding.server

    def _arp_nudge(self, force=False, master=_UNSET):
        """Hand the current lease binding (leased address, nudge target) to the
        ArpNudge component; it owns the pacing, the master gate and the send.
        `master` (when the maintain loop already probed the CARP role this tick)
        is passed through so the nudge does not spawn a second ifconfig; other
        callers omit it and the nudge probes on its own."""
        yiaddr, gateway = self._dhcp.binding.yiaddr, self._nudge_target()
        if master is _UNSET:
            self._nudge.maybe_nudge(yiaddr, gateway, force=force)
        else:
            self._nudge.maybe_nudge(yiaddr, gateway, force=force, master=master)

    # ---- operator/signal API (signal handlers set a flag only -- see the
    # _SignalFlags invariant for why that rule is load-bearing; the
    # loop wakes via the wake socket -- from the capture thread through
    # _signal_wake, and from signal delivery through signal.set_wakeup_fd(
    # wake_fileno) wired in main(), which is async-signal-safe C-level machinery) ----

    def wake_fileno(self):
        """The wake socket's write-end fd, for signal.set_wakeup_fd() so any
        delivered signal wakes the maintain-loop sleep at once."""
        return self._wake_w.fileno()

    def _signal_wake(self):
        """Wake the maintain-loop sleep by sending one byte to the wake socket.
        Called from the capture thread (a normal thread) on a peer-ACK
        observation; socket.send works on every platform. The operator SIGNAL
        path does not call this (socket.send is not async-signal-safe) -- it
        relies on set_wakeup_fd instead. A full buffer just drops the byte, the
        loop still wakes on its 1s tick."""
        try:
            self._wake_w.send(b"\x00")
        except (BlockingIOError, OSError):
            pass

    def request_stop(self):
        """Ask the daemon to exit (SIGINT/SIGTERM). Flag only; set_wakeup_fd
        wakes the loop so it exits at once."""
        self._signals.request_stop()

    def trigger_nudge(self):
        """Request an immediate ARP nudge (SIGUSR1 / configd action). Flag only;
        no network I/O in signal context."""
        self._signals.request_nudge()

    def recheck_carp_role(self):
        """Re-check the CARP role now (SIGUSR2 from the CARP syshook) instead of
        waiting for the next ~30s poll. Flag only."""
        self._signals.request_recheck_role()

    # ---- main loop / sleeps ----

    def _sleep(self, secs):
        slept = 0
        while slept < secs and not self._signals.stopping:
            time.sleep(1)
            slept += 1
        return slept

    def _sleep_interruptible(self, secs):
        """Sleep up to secs (1s steps). Return False early on stop. Also services an
        operator-requested immediate nudge (SIGUSR1) and a CARP-transition re-check
        (SIGUSR2) so both act within a second instead of at the next heartbeat tick."""
        slept = 0
        while slept < secs and not self._signals.stopping:
            if self._signals.take_recheck_role():
                # A CARP transition just fired (kernel -> devd -> rc.syshook.d/carp
                # -> SIGUSR2); re-check the role now so a backup->master keeper
                # nudges + renews immediately instead of at the next ~30s poll, and
                # re-own the default route on the same edge (a failover flips which
                # node installs 0/0). One shared CARP probe feeds both, as the tick does.
                self._role_tick()

            if self._signals.take_nudge():
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
                self._link.returned = True
                return not self._signals.stopping

            # Event-driven sleep: return at once when the wake socket is written
            # (a fresh observation or an operator signal), otherwise time out
            # after ~1s to run the periodic checks.
            ready, _, _ = select.select([self._wake_r], [], [], 1.0)
            if ready:
                try:
                    self._wake_r.recv(4096)   # drain the wake byte(s)
                except (BlockingIOError, OSError):
                    pass
            slept += 1
        return not self._signals.stopping

    def _hold_lease(self, secs):
        """Sleep up to secs while holding a lease, rewriting the heartbeat every
        HB_REFRESH so a healthy keeper never looks stale (leases can be hours and
        the CARP demotion hook only sees heartbeat freshness). Returns False early
        on stop."""
        remaining = secs
        while remaining > 0 and not self._signals.stopping:
            if self._renew_asap:
                # Return as if T1 elapsed: the caller renews right away, which
                # re-teaches upstream DHCP-snooping state after a master change.
                self._renew_asap = False
                return not self._signals.stopping

            chunk = min(HB_REFRESH, remaining)
            if not self._sleep_interruptible(chunk):
                return False
            remaining -= chunk

            self._hb()
            self._follow.watchdog()   # re-drive a follow whose apply stalled
            # One CARP-role probe per tick, shared by the role poll, the route
            # reconcile (both via _role_tick) and the nudge below.
            master = self._role_tick()
            self._arp_nudge(master=master)
        return not self._signals.stopping

    def run(self):
        """The daemon main loop: capture up, then maintain the lease until
        stopped. Never raises; returns the process exit code.

        The startup fail-stop withdraw (a crashed predecessor's stale default) runs
        in main() before the backend preflight, so it happens even when a backend/arg
        early-exit means run() is never reached; the shutdown withdraw below is the
        graceful counterpart. Both go through withdraw_unless_master (kept on a
        master, so a keeper restart does not flap 0/0)."""
        # Start the packet capture, retrying forever: a keeper must self-heal, not
        # die, if the interface is briefly unavailable at startup.
        while not self._signals.stopping and not self._capture.start():
            LOG.warning("capture start failed -- retrying in %ds", SNIFFER_RETRY)
            self._sleep(SNIFFER_RETRY)

        # eth-src matters for L2 debugging but only when it differs from the chaddr.
        ethsrc = f" eth-src={self._cfg.eth_src}" if self._cfg.eth_src != self._cfg.chaddr else ""
        LOG.info("lease-keeper %s active on %s: chaddr=%s%s request=%s",
                 __version__, self._cfg.iface, self._cfg.chaddr, ethsrc, self._follow.target or "any")
        time.sleep(SNIFFER_WARMUP)

        while not self._signals.stopping:
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

        # shutdown: relinquish an owned default unless we are the CARP master, so a
        # keeper restart on a master does not flap 0/0 (the rationale and the accepted
        # trade-off live in withdraw_unless_master).
        self._defroute.withdraw_unless_master(self._probe_carp_master)
        if self._cfg.release_on_exit:
            self._dhcp.release()
        self._capture.stop()
        self._wake_r.close()
        self._wake_w.close()
        LOG.info("stopped (lease-keeper %s)", __version__)
        return 0

    def claim_once(self):
        """--once mode: claim, report, release -- a wiring test, not service
        mode. Lives on the keeper so it uses the components directly instead of
        the entry point reaching into private attributes."""
        if not self._capture.start():
            return 3
        time.sleep(SNIFFER_WARMUP)
        ok = self._dhcp.dora(self._follow.target)
        LOG.info("DHCP claim %s -> %s", self._cfg.chaddr, self._dhcp.binding.yiaddr if ok else "FAIL")
        if ok:
            self._dhcp.release()
        self._capture.stop()
        return 0 if ok else 1

    def _maintain_step(self):
        """One iteration of the maintain loop. Returns to run() (which loops again)
        on every state transition; any exception it raises is caught by run() and
        retried, so a transient fault can never terminate the keeper."""
        b = self._dhcp.binding
        if not b.yiaddr:
            # Unbound: withdraw any default we still own (the role is irrelevant when
            # unbound -- every value withdraws -- so master=False, no ifconfig), then
            # try to (re)acquire.
            self._reconcile_default_route(master=False)
            self._acquire_step()
            return
        # Bound: own the default by CARP role, here at the loop head. _maintain_step
        # is re-entered after every transition (a just-acquired lease, a renew that
        # changed the gateway, a NAK, an expiry), so this single reconcile tracks
        # them all; only the long blocking waits below (which do not return to the
        # loop head) add their own periodic reconcile.
        self._reconcile_default_route()

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
            self._on_lease_extended(Phase.RENEW)
            return
        if not b.yiaddr:            # renew() drew a NAK and forgot the binding
            self._on_lease_revoked(Phase.RENEW)
            return
        LOG.warning("DHCP %s failed at T1 -- trying %s until T2", Phase.RENEW, Phase.REBIND)

        elapsed = t1
        ok = False
        while elapsed < t2 and not self._signals.stopping:
            # Jitter the REBIND retransmit cadence: both nodes hit T2 together
            # (identical lease timers), so an un-jittered step would broadcast
            # REBIND in lockstep. Overshooting t2 slightly is harmless (the guard
            # re-checks). Account the actual jittered wait so elapsed tracks it.
            step = _jittered(min(REBIND_POLL_STEP, t2 - elapsed))
            if not self._sleep_interruptible(step):
                break
            elapsed += step
            self._hb()   # still holding the lease until T2 -- keep the heartbeat fresh
            # REBIND can span the whole T1..T2 window; keep the CARP-role
            # bookkeeping and the default route reconciled here too, exactly as
            # _hold_lease does per tick. Otherwise a failover during this degraded
            # path relies solely on the SIGUSR2 edge, with no periodic fallback
            # for a missed one until REBIND exits.
            self._role_tick()
            if self._dhcp.renew(rebind=True):
                ok = True
                break
            if not b.yiaddr:            # a NAK during REBIND likewise revoked the lease
                self._on_lease_revoked(Phase.REBIND)
                return
        if ok:
            self._on_lease_extended(Phase.REBIND)
            return

        LOG.error("DHCP lease expired -- re-acquiring (back to %s)", Phase.DORA)
        self._dhcp.expire()

    def _wait_unbound(self, secs):
        """Sleep up to secs while UNBOUND, watching for the WAN carrier to
        return. Returns True (and resets the re-DORA backoff) if the link-return
        fast path fired during the sleep, so the caller re-acquires at once
        instead of waiting out the backoff (matches native dhclient)."""
        self._link.returned = False
        self._sleep_interruptible(secs)
        if self._link.returned:
            LOG.info("WAN link returned while unbound -- re-acquiring now")
            self.redora_wait = REDORA_MIN
            return True
        return False

    def _acquire_step(self):
        """The unbound arm of the maintain loop: hold while there is no
        carrier, otherwise try one acquire with the jittered re-DORA backoff;
        the link-return fast path cuts either wait short."""
        self._ensure_sniffer()  # a dead sniffer would silently fail every DORA
        self._hb()  # active but not holding yet -> publish bound=-
        # (The default-route withdraw for the unbound state is the loop-head
        # reconcile in _maintain_step, before this arm runs.)

        # No point broadcasting DISCOVERs on a dead link (native dhclient
        # does not either): wait for the carrier instead of burning DORA
        # attempts. The unbound sleep polls the link and the link-return
        # fast path resumes within seconds of it coming back. Fail open:
        # only a confirmed "no carrier" (False) holds the acquire; an
        # unreadable probe (None) never blocks it.
        if self._iface_link_up() is False:
            if self._link.up is not False:   # log once per down-episode
                LOG.info("no carrier on %s -- waiting for the link before the DHCP acquire",
                         self._cfg.iface)
            self._link.up = False
            self._wait_unbound(REDORA_MIN)
            return

        b = self._dhcp.binding
        if self._dhcp.acquire(self._follow.target):
            self._link.up = True   # a completed DORA proves carrier
            LOG.info("DHCP BOUND %s (lease=%ss, expires ~%s, server=%s, gw=%s, mask=%s)",
                     b.yiaddr, b.lease_secs, _clock_at(b.lease_secs),
                     b.server, b.router or "?",
                     f"/{b.mask_bits}" if b.mask_bits else "none")
            self._hb()
            self._arp_nudge(force=True)
            self.redora_wait = REDORA_MIN
            # Owning the default is the loop-head reconcile on the next _maintain_step
            # entry (now bound): _acquire_step returns straight to run(), which
            # re-enters at once, so the install is immediate without a call here.
        else:
            LOG.warning("DHCP acquire (DISCOVER/REQUEST) failed -- retrying in %ds", self.redora_wait)
            if not self._wait_unbound(_jittered(self.redora_wait)):
                self.redora_wait = min(self.redora_wait * 2, REDORA_MAX)


def _identity_options(vendor_class, client_id, hostname):
    """Optional DHCP identity options (empty -> not sent), added to every
    DISCOVER/REQUEST/RENEW so the server sees a consistent client identity.
    ISP interplay: satisfies servers that only lease to a known vendor-class
    (opt 60), client-id (61) or hostname (12) -- the "client identity checks"
    row of the README's ISP-security section."""
    id_opts = []
    if vendor_class:
        id_opts.append((DhcpOptName.VENDOR_CLASS_ID, vendor_class))
    if client_id:
        id_opts.append((DhcpOptName.CLIENT_ID, client_id.encode()))
    if hostname:
        id_opts.append((DhcpOptName.HOSTNAME, hostname))
    return id_opts
