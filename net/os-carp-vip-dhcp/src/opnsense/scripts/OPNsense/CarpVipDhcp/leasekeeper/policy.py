"""Two cooperating components: ArpNudge (keep the upstream gateway's ARP entry
for the leased address fresh, CARP-master-gated) and FollowPolicy (decide what
to do when the server grants a different address than the VIP -- follow and
rewrite the VIP, or alarm and refuse).
"""
import logging
import time
from dataclasses import dataclass, field
from typing import Callable

from .constants import (
    LOGGER_NAME,
    ARP_NUDGE_MIN, ArpOp, FOLLOW_RETRY_DEADLINE, MIN_FOLLOW_INTERVAL,
    NUDGE_FAIL_LOG_INTERVAL, Phase)
from .util import (
    _UNSET, _RateLimit, _atomic_write, _fs_safe, _mask_to_bits, _same_ip_class, _sane_ipv4)

LOG = logging.getLogger(LOGGER_NAME)

# _UNSET marks "CARP-master value not supplied by the caller": the maintain loop
# passes the role it already probed this tick, but None is itself a valid probe
# result (probe failed), so the sentinel means "probe it yourself". Shared via
# util so the identity check is the same object everywhere (see util._UNSET).


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
        self._logged_gw = None                # last nudge target we logged (log again on change)
        self._warned = False           # warned once about a missing nudge target
        # Throttle a failing send so a persistent fault stays periodically visible
        # (with a suppressed count) instead of spamming or latching fully silent.
        self._nudge_fail_log = _RateLimit(NUDGE_FAIL_LOG_INTERVAL)

    def maybe_nudge(self, yiaddr, gateway, force=False, master=_UNSET):
        """Refresh the gateway's ARP entry for yiaddr by broadcasting an ARP
        request from (yiaddr, chaddr). No-op unless enabled, bound, due (or
        forced) and CARP master. `master` lets a caller that already probed the
        CARP role this tick pass it in (avoiding a duplicate ifconfig); omitted,
        the nudge probes via its own hook."""
        if not self.interval or not yiaddr:
            return
        if not force and time.time() - self.last_nudge < self.interval:
            return
        if master is _UNSET:
            master = self._is_master()
        if master is not True:
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
            if gateway != self._logged_gw:
                LOG.info("ARP nudge active: who-has %s tell %s (src %s) every %ds",
                         gateway, yiaddr, self.chaddr, self.interval)
                self._logged_gw = gateway
            else:
                LOG.debug("ARP nudge sent: who-has %s tell %s", gateway, yiaddr)
        except Exception as e:  # pylint: disable=broad-exception-caught
            # A persistently failing send stays periodically visible (throttled with
            # a suppressed count), not spammed every interval nor latched silent.
            self._nudge_fail_log.emit(LOG.warning, "ARP nudge failed (target %s): %s", gateway, e)

    def on_arp_reply(self, frame, yiaddr, gateway):
        """Stamp last_reply when the gateway answers our nudge -- a reachability
        signal the status page surfaces by age. Only the reply to OUR who-has
        counts: op=2 (is-at), sender = the nudge target gateway, target = our
        leased IP. Runs on the capture thread; the stamp is a lone atomic write.
        Advisory only (an on-segment attacker could forge or withhold it);
        nothing here feeds lease/CARP/follow decisions."""
        if frame.op != ArpOp.REPLY:            # is-at reply; requests are filtered out in BPF
            return
        if not gateway or not yiaddr:
            return
        if frame.psrc == gateway and frame.pdst == yiaddr:
            self.last_reply = time.time()
            LOG.debug("ARP reply from %s (is-at) for %s", gateway, yiaddr)


@dataclass
class _FollowAttempt:
    """The in-flight follow (the current VIP rewrite the watchdog may re-drive):
    the address we asked configd to move TO, the address we moved FROM, when we
    last dispatched it (the retry deadline), and any cross-subnet gateway args."""
    followed_ip: str | None = None   # last address we asked configd to follow to
    follow_from: str | None = None   # address we followed FROM (for the retry watchdog)
    fired_at: float = 0.0            # when we last dispatched follow_update (retry deadline)
    gw_args: list = field(default_factory=list)  # [old_gw, new_gw, bits] cross-subnet; else []


@dataclass(frozen=True)
class FollowHooks:
    """FollowPolicy's two injected side-effect seams, grouped so the system
    coupling stays out of this decision module: hb_mismatch(got, want) records a
    lease vs heartbeat disagreement, and dispatch(old, new, gw_args) drives the
    configd CARP-VIP rewrite. Both return values are ignored (fire-and-forget)."""
    hb_mismatch: Callable[[str, str], None]
    dispatch: Callable[[str, str, list], None]


class FollowPolicy:  # pylint: disable=too-many-instance-attributes
    """Decides what happens when the server grants a DIFFERENT address than
    the target this keeper exists to hold. In follow mode: validate the new
    address (plausibility, routability class, expected server), throttle
    against flap/spoof storms, drive the configd VIP rewrite and adopt it
    into the DHCP client. Otherwise (enforce, a fixed reservation): alarm,
    release the refused grant and stay unbound. Owns the target address
    (rewritten on a successful follow), the persisted follow throttle, the
    apply-retry watchdog and the peer-ACK observation handoff."""

    def __init__(self, target, follow, chaddr, dhcp, *, hooks: FollowHooks):
        self.target = target           # the address this keeper is meant to hold
        self.follow = follow
        self._dhcp = dhcp
        self._hb_mismatch = hooks.hb_mismatch
        self._dispatch = hooks.dispatch    # configd CARP-VIP rewrite; see FollowHooks

        self._attempt = _FollowAttempt()   # the in-flight follow (watchdog re-drive state)

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
        except FileNotFoundError:
            return 0.0          # never followed yet -- the normal first-run case
        except (OSError, ValueError) as e:
            # A present-but-corrupt/unreadable state file returns 0.0, which
            # disarms the MIN_FOLLOW_INTERVAL spoof-storm throttle on the next
            # changed-address ACK -- a security-relevant fail-open, so warn (it is
            # rare: only a corrupt state file, only on a changed-address ACK).
            LOG.warning("follow-throttle state %s unreadable (%s) -- treating as never "
                        "followed (throttle disarmed until the next follow)", self._state_file, e)
            return 0.0

    def _record_follow(self):
        try:
            _atomic_write(self._state_file, str(int(time.time())))
        except OSError as e:
            LOG.warning("could not persist follow timestamp: %s", e)

    def on_changed_address(self, got, rx, phase, release_on_enforce):  # pylint: disable=too-many-return-statements
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
            if phase != Phase.REBIND and rx.server_id and leased_from and rx.server_id != leased_from:
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
            self._attempt.gw_args = []
            old_router = self._dhcp.binding.router
            if rx.router and old_router and rx.router != old_router:
                bits = _mask_to_bits(rx.subnet_mask)
                if bits:
                    LOG.warning("follow %s -> %s also moves the gateway (%s -> %s), subnet "
                                "/%d -- following across the subnet", self.target, got,
                                old_router, rx.router, bits)
                    self._attempt.gw_args = [old_router, rx.router, str(bits)]
                else:
                    LOG.error("follow %s -> %s changes the gateway (%s -> %s) but the ACK "
                              "carried no subnet mask -- updating the VIP address only; fix the "
                              "interface prefix + System->Gateways by hand", self.target,
                              got, old_router, rx.router)

            # _follow_update reads target as the old address, so remember it
            # (for the retry watchdog) and fire before overwriting target.
            self._attempt.follow_from = self.target
            if not self._follow_update(got):
                # The dispatch could not even be launched (e.g. fork/exec failure).
                # Do NOT advance the target, adopt the binding, or arm the throttle
                # below: leaving all three untouched means the next renewal ACK for
                # `got` re-enters here and re-drives the follow promptly. The
                # throttle is only for real, dispatched follows (a spoof/flap
                # storm), so a never-dispatched attempt must not delay its own
                # retry. Advancing would strand the daemon on `got` with the CARP
                # VIP config still on the old address and no way to re-fire.
                return False
            # A real follow was dispatched: arm the spoof-storm throttle now (only
            # on success -- arming before the dispatch would make a failed launch
            # throttle its own retry). Persisted so it survives the follow-induced
            # restart.
            self._record_follow()
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
        service restart replaces this daemon with one bound to the new address.
        Returns True once the request was dispatched (or was already asked for),
        False if the dispatch failed -- launch failure or any other exception from
        the dispatch hook -- in which case the caller defers without advancing the
        target, so the next renewal re-drives (see on_changed_address)."""
        if new_ip == self._attempt.followed_ip:
            return True   # already asked for this address
        try:
            self._fire_follow_update(self.target, new_ip)
            # Only mark as handled once the request was actually dispatched, so a
            # dispatch that could not be launched is retried, not latched.
            self._attempt.followed_ip = new_ip
            LOG.info("requested CARP VIP update %s -> %s", self.target, new_ip)
            return True
        except Exception as e:  # pylint: disable=broad-exception-caught
            LOG.error("follow_update request failed: %s -- deferring to the next renewal", e)
            return False

    def _fire_follow_update(self, old_ip, new_ip):
        """Dispatch the follow_update side effect (old -> new, plus any
        cross-subnet gw args) through the injected hook and stamp the retry
        deadline. Separate from _follow_update so the watchdog can re-drive a
        stalled follow without tripping the followed_ip equality guard."""
        # gw_args: cross-subnet [old_gw, new_gw, bits]; empty on a same-subnet move.
        self._dispatch(old_ip, new_ip, self._attempt.gw_args)
        self._attempt.fired_at = time.time()

    def watchdog(self):
        """Re-drive a follow that never took effect. After a successful follow,
        follow_update restarts this daemon within a few seconds; if we are still
        alive well past FOLLOW_RETRY_DEADLINE, its apply failed or stalled, so
        re-dispatch it (idempotent: it reconverges whether the config already
        moved or not, and its rc.d restart <old-id> eventually replaces us)."""
        att = self._attempt
        if not (self.follow and att.followed_ip and att.follow_from):
            return
        if time.time() - att.fired_at < FOLLOW_RETRY_DEADLINE:
            return
        LOG.warning("follow %s -> %s not applied within %ds -- re-driving",
                    att.follow_from, att.followed_ip, FOLLOW_RETRY_DEADLINE)
        try:
            self._fire_follow_update(att.follow_from, att.followed_ip)
        except Exception as e:  # pylint: disable=broad-exception-caught
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
        self.on_changed_address(rx.yiaddr, rx, Phase.OBSERVED, release_on_enforce=False)
