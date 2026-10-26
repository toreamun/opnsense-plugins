"""The CARP-role state machine for one keeper: it watches the master/backup role,
owns the early-renew latch and the demote-on-lease-loss grace clock, and fires the
promotion side effects through an injected hook. Kept in its own module so the role
logic (which a planned enforce-mode fail-stop follow-up builds on) has one home, separate
from the maintain loop that drives it. The raw ifconfig probe and the promotion side
effects (ARP nudge + default-route resync) and the role-change hook (the keeper's
heartbeat) are injected, so this object stays pure
role logic with no capture / route / nudge dependencies. The module also holds the
CARP-master decision helpers (_carp_master on ifconfig text; carp_master runs the
ifconfig probe itself, while RoleWatcher still has it injected).
"""
import logging
from typing import Callable

from .constants import DEMOTE_GRACE, LOGGER_NAME
from .ifprobe import is_carp_master
from .syscmd import ifconfig
from .util import _UNSET

LOG = logging.getLogger(LOGGER_NAME)


class RoleWatcher:
    """Owns this keeper's CARP-role state: `was_master` (True/False, or None until the
    first definite probe), the early-renew latch (`renew_pending`/`take_renew`/
    `request_renew`/`cancel_renew`), and the unbound-as-master grace clock
    (`demote_ok`). Transitions are driven by `poll()`."""

    def __init__(self, vhid, probe: "Callable[[], bool | None]",
                 on_promote: "Callable[[], None]", on_change: "Callable[[], None]"):
        self._vhid = vhid
        self._probe = probe            # the keeper's CARP-master probe (late-bound; None = probe failed)
        # Promotion side effects (force ARP nudge + request default-route resync). poll()
        # calls it BEFORE committing was_master, so a promotion whose side effects raise
        # is seen (and retried) on the next poll. on_change runs after either transition,
        # once the role is committed (the keeper publishes its heartbeat with it).
        self._on_promote = on_promote
        self._on_change = on_change
        # None until the first definite probe (a vhid keeper is unknown until then); a
        # no-vhid keeper has no CARP role to watch and is the permanent sole master.
        self.was_master: "bool | None" = None if vhid else True
        # Raw latch / grace fields, managed through the methods below (renew_pending /
        # take_renew / cancel_renew / demote_ok); private so a caller cannot bypass the
        # role gate or shift the grace epoch by writing them directly.
        self._renew_asap = False
        self._unbound_master_since = None

    def poll(self, master=_UNSET):
        """Watch for a backup->master transition (called on the heartbeat cadence).
        Becoming master arms an early lease renew and fires the promotion hook
        (immediate ARP nudge + route resync): the failover -- or the link flap that
        re-elected CARP -- may just have disturbed the upstream gateway's ARP entry and
        the access node's DHCP-snooping binding, so neither should wait out its normal
        timer. Either transition then fires on_change (the keeper publishes its heartbeat
        at once). `master` lets the maintain loop pass the role it already probed this tick."""
        if not self._vhid:
            return
        if master is _UNSET:
            master = self._probe()
        if master is None:
            return
        prev = self.was_master
        if prev is None:
            # First definite role after an unknown initial probe (a transient ifconfig
            # failure at startup): announce it so the log does not stay stuck at
            # "unknown", but take no failover action -- this is the initial
            # determination, not a promotion or demotion.
            LOG.info("CARP role for vhid %s: %s", self._vhid, "MASTER" if master else "BACKUP")
            self.was_master = bool(master)
            return
        if master and prev is False:
            LOG.info("became CARP master for vhid %s -- immediate ARP nudge and early lease renew",
                     self._vhid)
            self._renew_asap = True
            self._on_promote()
        elif not master and prev:
            # The symmetric event: without it, "why did the nudges stop?" needs ifconfig
            # instead of the log. A pending early-renew latch is left as-is:
            # renew_pending()/take_renew() gate on the role, so it goes inert now that
            # this node is backup (a backup must not renew), and the next promotion
            # re-arms it -- no by-hand clear here to drift out of sync.
            LOG.info("lost CARP master for vhid %s -- ARP nudges pause on this node", self._vhid)
        self.was_master = bool(master)   # a definite role here: _UNSET was probed, None returned above
        if self.was_master != prev:
            self._on_change()

    def log_initial(self):
        """Announce the CARP role once at startup and seed was_master, so the role is in
        the log immediately instead of only on the next transition (a keeper that starts
        master and stays master would otherwise never state it). Seed only a DEFINITE
        result: an unknown (a transient startup ifconfig failure) is left unseeded so
        poll() announces the first definite role rather than the log staying 'unknown'."""
        if not self._vhid:
            return
        master = self._probe()
        role = "unknown" if master is None else ("MASTER" if master else "BACKUP")
        LOG.info("initial CARP role for vhid %s: %s", self._vhid, role)
        if master is not None:
            self.was_master = master

    def renew_pending(self):
        """Whether the early-renew latch is live: armed by a promotion AND this node is
        not a confirmed backup. Role-gating the read makes the latch inert on a backup
        with no by-hand clear, so a demotion that never consumed it cannot later fire a
        renew from the shared vMAC; an unknown role stays live (the transmit fail-safe)."""
        return self._renew_asap and self.was_master is not False

    def take_renew(self):
        """Consume the early-renew latch once: the hold loop renews immediately instead
        of waiting out T1. A no-op (and no clear) on a confirmed backup -- see
        renew_pending()."""
        if self.renew_pending():
            self._renew_asap = False
            return True
        return False

    def request_renew(self):
        """Arm the early renew (as a promotion does): the hold loop renews at once, e.g.
        to confirm a lease whose network differs from the configuration. Inert on a
        confirmed backup, like the promotion latch (see renew_pending())."""
        self._renew_asap = True

    def cancel_renew(self):
        """Drop a pending early renew: a fresh DORA supersedes it (the node just bound,
        so it need not also renew immediately)."""
        self._renew_asap = False

    def demote_ok(self, now, bound):
        """Whether a demote=1 keeper should now be demoted: it is the CARP master but has
        been unable to hold the requested lease (`bound` is False) for longer than
        DEMOTE_GRACE. A just-promoted master's normal acquire DORA falls inside the grace,
        so it is not demoted mid-acquire; a passive backup (never master) and a healthy
        bound master never qualify. Level-based: the unbound-as-master epoch is set on the
        first master-and-lease-less tick and cleared the moment the node binds or leaves
        master (so a promote->demote flap resets the clock, and a probe glitch does not,
        since was_master keeps its last definite role). Published unconditionally -- the
        daemon does not know the demote flag (it lives only in keeperconf for the hook),
        so the hook's own demote=1 gate decides which keepers act on this token."""
        if self.was_master is True and not bound:
            if self._unbound_master_since is None:
                self._unbound_master_since = now
            return now - self._unbound_master_since > DEMOTE_GRACE
        self._unbound_master_since = None
        return False


def _carp_master(ifconfig_text, vhid):
    """CARP-master decision from ifconfig text: True/False for the vhid, None when
    the text is missing (probe failed), True when no vhid (nothing to gate on).
    Parsing lives in ifprobe.is_carp_master; this adds only the keeper policy that
    a keeper with no vhid has nothing to gate on."""
    if not vhid:
        return True
    return is_carp_master(ifconfig_text, vhid)


def carp_master(iface, vhid):
    """CARP-master role for `vhid` on `iface` (True/False, None on probe failure).
    Needs no Keeper, so the daemon entry point can gate its startup default
    withdraw on the role before the Keeper exists. Keeper._probe_carp_master
    uses the same _carp_master decision."""
    return _carp_master(ifconfig(iface), vhid)
