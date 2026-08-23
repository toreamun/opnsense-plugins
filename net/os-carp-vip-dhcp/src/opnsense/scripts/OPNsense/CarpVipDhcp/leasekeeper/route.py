"""Default-route ownership keyed on CARP role.

The keeper owns the IPv4 WAN default route (0.0.0.0/0) as a function of its CARP
role and whether it currently holds a DHCP lease: only the CARP-master node that
actually holds a lease keeps a default in the FIB; every other state has none. A
node with no default advertises none (via os-frr redistribute kernel), so the
failure mode is a withdrawn default, never a black-holed one. See
docs/single-ip-wan-carp.md.

Two independent reconcilers live here: DefaultRouteReconciler owns the 0/0
decision, and the optional BackupEgressReconciler owns the backup-egress route
set (docs/backup-egress.md). They share nothing but the /sbin/route exec helpers
below; the one cross-cutting sequence -- clean the backup set BEFORE withdrawing
0/0 at a process boundary -- lives in the module-level withdraw_unless_master().

Concurrency: reconcile() must be called only from the keeper's main loop thread;
the caller is Keeper._reconcile_default_route -- the per-tick poll, the acquire
arm (unbound and just after a successful acquire) and the SIGUSR2 CARP edge, plus
a fail-stop non-master withdraw at startup and on shutdown. Signal handlers and the capture thread never
touch the FIB -- they only set flags / hand off observations, exactly as the
lease path does. So there is no in-process route race; the only shared mutable
state is the kernel FIB, and cross-process / cross-subsystem contention is
handled outside this module (a single managing keeper, and force_down so
OPNsense does not also manage the default). Every route operation is idempotent
and error-tolerant, so a redundant add/delete -- or a burst of coalesced signals
collapsed onto one boolean flag -- converges quietly rather than raising.
"""
import ipaddress
import logging
from dataclasses import dataclass
from enum import StrEnum

from .constants import LOGGER_NAME, RECONCILE_HEARTBEAT_INTERVAL
from .ifprobe import iface_ipv4
from .syscmd import run
from .util import _UNSET, _RateLimit, _sane_ipv4

LOG = logging.getLogger(LOGGER_NAME)


def _drop(*_args, **_kwargs):
    """A log-callable that discards its call: what _at returns for a throttled
    steady-state repeat, so a suppressed heartbeat is a no-op with the same
    call shape as LOG.debug/LOG.info."""


class DefaultRouteMode(StrEnum):
    """Per-keeper default-route mode (the values the model's defaultRouteMode
    field carries). StrEnum (like constants.Phase) so a member both is its config
    string and compares by value -- the value flows in from the model verbatim.
    off: inert (default). observe: log what it would do, no FIB write. enforce:
    actually install/withdraw."""
    OFF = "off"
    OBSERVE = "observe"
    ENFORCE = "enforce"

    @classmethod
    def coerce(cls, value):
        """The mode for a config string, falling back to OFF (inert) with a warning
        for any unrecognised value -- so a hand-edited config never activates an
        unintended mode nor crash-loops the supervised daemon."""
        try:
            return cls(value)
        except ValueError:
            LOG.warning("unknown default-route mode %r -- treating as off", value)
            return cls.OFF


class BackupEgressForm(StrEnum):
    """The route form the backup installs for its own egress (docs/backup-egress.md).
    split: 0.0.0.0/1 + 128.0.0.0/1 -- full internet, but not the default, so it never
    redistributes as a default nor collides with enforce (the recommended default, and
    the fail-safe fallback for an unrecognised value). prefixes: a curated list of
    specific destinations. (A plain 0.0.0.0/0 is deliberately not offered: it can only
    run under observe/enforce, and enforce owns 0/0, so it could never install.)"""
    SPLIT = "split"
    PREFIXES = "prefixes"

    @classmethod
    def coerce(cls, value):
        """The form for a config string, falling back to SPLIT (leak-safe) with a
        warning for any unrecognised value -- so a hand-edited config never
        crash-loops the supervised daemon."""
        try:
            return cls(value)
        except ValueError:
            LOG.warning("unknown backup-egress form %r -- treating as split", value)
            return cls.SPLIT


class _BackupState(StrEnum):
    """The backup-egress desired state for a tick: present (install the set via the
    gateway), absent (this node is master -- remove any managed route), or unresolved
    (the gateway could not be worked out -- leave the FIB alone). Recorded per tick so
    a change re-arms the heartbeat, like the 0/0 decision's _last_desired."""
    PRESENT = "present"
    ABSENT = "absent"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True)
class BackupEgressConfig:
    """Config for the optional backup-egress feature: while a node is the CARP backup
    (no WAN default) route its own internet traffic to the master. Flows in from the
    model via argparse. Disabled by default; the reconciler is a no-op unless enabled.
    gateway: a stable next hop (a CARP VIP or a fallback-WAN gateway); when blank the
    peer is derived from `interface` (the other host of a point-to-point /30 or /31)."""
    enabled: bool = False
    form: BackupEgressForm = BackupEgressForm.SPLIT
    gateway: "str | None" = None
    interface: "str | None" = None
    prefixes: "tuple[str, ...]" = ()


@dataclass
class _WarnGates:
    """The backup reconciler's rising-edge one-shot warn flags, each re-armed when
    its condition clears so a node that sits as backup for a long time does not
    churn the log with a repeated warning."""
    unresolved: bool = False       # the backup gateway could not be resolved
    fib_unreadable: bool = False   # netstat could not read the routing table
    collision: bool = False        # a backup prefix is present via a foreign next hop


class RouteCommand(StrEnum):
    """The `/sbin/route` commands we issue (route(8) calls add/delete/get
    'commands'). StrEnum so a member drops straight into the argv list and logs
    as its bare value (a plain Enum would render 'RouteCommand.ADD' and need
    .value)."""
    ADD = "add"
    CHANGE = "change"
    DELETE = "delete"
    GET = "get"


# The IPv4 default. IPv6 is out of scope: no v6 BGP fw<->pve, so no v6 default
# leak to gate.
_DEFAULT = "default"

# _UNSET (shared, from util) marks "no desired state recorded yet". The first
# reconcile then reads as a change, so the entry state (owning / no default /
# would-install / ...) is logged once at INFO -- the mode-entry heartbeat -- and
# every unchanged repeat after it drops to DEBUG, keeping steady state out of the
# default INFO view.

# Consecutive unreadable CARP-role probes tolerated while we still hold a
# default before we withdraw it. An unreadable probe (ifconfig failed) is
# fail-safe on the INSTALL side (do nothing) but must fail *closed* on the
# WITHDRAW side, or a former master with a flaky ifconfig keeps advertising a
# default it should have dropped. A genuine role loss reads as False within a
# tick; only a stuck probe reaches this ceiling.
DEFAULT_UNREADABLE_ROLE_STRIKES = 3

_ROUTE = "/sbin/route"
_NETSTAT = "/usr/bin/netstat"
_IFCONFIG = "/sbin/ifconfig"
_NUMERIC = "-n"              # numeric output, no name resolution
_AF_INET = "-inet"          # IPv4 address family modifier; the v6 twin: -inet6
_GATEWAY_FIELD = "gateway:"  # the field label parsed from `route get` output

# The /1-split: two half-internet routes that together cover 0.0.0.0/0 but are each
# more specific than it (so they win over any default) and are not the default (so
# redistribute kernel's exact-0/0 route-map never picks them up, and enforce, which
# only manages 0/0, ignores them). See docs/backup-egress.md.
_SPLIT_PREFIXES = ("0.0.0.0/1", "128.0.0.0/1")
_DEFAULT_NET = ipaddress.ip_network("0.0.0.0/0")
# Point-to-point prefix lengths a backup-egress peer can be derived from unambiguously.
_PTP_PREFIXLENS = (30, 31)


# ---- /sbin/route helpers (stateless; wrap syscmd.run; shared by both reconcilers) ----

def _route(command, dest, gateway=None):
    """Issue a `/sbin/route` command (best effort). The caller confirms the
    resulting FIB state, so a non-zero exit -- an idempotent no-op or a real
    failure alike -- is only debug-logged and left for that confirm to judge,
    rather than guessed from route(8)'s wording here."""
    cmd = [_ROUTE, _NUMERIC, command, _AF_INET, dest]
    if gateway is not None:
        cmd.append(gateway)
    res = run(cmd)
    if res is not None and res.returncode != 0:
        LOG.debug("route %s %s exit %d: %s", command, dest, res.returncode,
                  (res.stderr or "").strip())


def _at(changed, heartbeat):
    """Pick the log callable for a desired-state confirmation. A state change
    logs at INFO the first time the state is entered, and re-arms the heartbeat
    so the identical DEBUG repeat does not fire on the very next tick. An
    unchanged repeat logs at DEBUG at most once per RECONCILE_HEARTBEAT_INTERVAL
    (proof the reconciler is alive and its decision); the ticks in between are
    dropped, so a steady node does not fill the log file with a per-tick
    heartbeat and churn the rotation. `heartbeat` is the deciding reconciler's own
    throttle -- the 0/0 and backup-egress decisions pass separate ones so the two
    do not interfere."""
    if changed:
        heartbeat.reset()
        return LOG.info
    ok, _ = heartbeat.ready()
    return LOG.debug if ok else _drop


def withdraw_unless_master(default_route, backup_egress, probe):
    """Drop an owned default UNLESS this node is the CARP master, cleaning the
    backup-egress set first. `probe` is a callable() -> bool|None returning the
    CARP-master role; it runs only once the mode would act, so off never spawns it.
    A confirmed master KEEPS its default (a keeper restart -- a config change or an
    upgrade -- must not tear it down and flap 0/0; the maintain loop re-adopts it).
    A backup or an unreadable role (False / None) withdraws, fail-closed, so a stale
    default is never left for FRR to keep advertising with nothing managing it.

    Run at the two process boundaries: main()'s startup fail-stop (on throwaway
    reconcilers, before the Keeper / capture backend exist and ahead of any
    arg/backend early-exit that would skip Keeper.run()) and Keeper.run()'s
    graceful shutdown. off is a no-op; observe logs a would-withdraw without
    touching the FIB; enforce actually withdraws. The caller gates on a CARP vhid.

    Ordering: the backup-egress set is cleaned BEFORE the 0/0 withdraw so a stopped
    keeper leaves no route a later master would loop through (withdraw_backup_egress
    no-ops when the feature is disabled and cleans only what it owns; see it for why).
    This is the one sequence that spans the two reconcilers, so it lives here rather
    than in either object.

    Trade-off: a GENUINE permanent stop (an operator disabling the plugin) on a
    node that is still CARP master keeps the default in the FIB with nothing
    managing it after -- the state this withdraw otherwise prevents. That window
    is narrow (the node is still master, so the default is at least
    static-correct) and telling it apart from a restart would need a fragile
    stop-vs-restart signal, so it is accepted."""
    if not default_route.enabled:
        return    # off is fully inert: no FIB read/write, no probe.
    backup_egress.withdraw_backup_egress()
    if probe() is True:
        return
    default_route.reconcile(is_master=False, bound=False, gateway=None)


class DefaultRouteReconciler:
    """Reconciles the IPv4 default route against (CARP role, lease-held,
    gateway). Level-triggered and idempotent: reconcile() may be called as often
    as the loop likes (edge or poll) and converges to the desired state,
    emitting a route change only when the FIB actually differs.

    All methods run on the keeper's main loop thread only; the class holds no
    lock because nothing else in the keeper mutates routes."""

    def __init__(self, mode: "str | DefaultRouteMode" = DefaultRouteMode.OFF, *,
                 unreadable_role_strikes=DEFAULT_UNREADABLE_ROLE_STRIKES,
                 liveness_probe=None):
        # mode flows in from the model verbatim (keeper.conf -> rc.d -> argparse)
        # as a plain string; coerce it, treating any unrecognised value as inert
        # OFF (never guess an active mode). Set-once: exposed read-only via `mode`.
        self._mode = DefaultRouteMode.coerce(mode)
        if unreadable_role_strikes < 1:
            raise ValueError("unreadable_role_strikes must be >= 1")
        self._strike_limit = unreadable_role_strikes
        # liveness_probe: optional callable() -> bool|None gating the INSTALL side
        # (the split-brain guard). None (no callable) or a None result means "no
        # opinion" and never blocks; only an explicit False blocks. It must be
        # debounced by the caller -- a single transient miss must not read False,
        # or a healthy master would flap its default (see the README).
        self._liveness_probe = liveness_probe
        self._strikes = 0
        self._unreadable_warned = False   # rising-edge gate for the fail-closed warning
        # Last (want, gateway) we logged, so a steady desired state is confirmed
        # once at INFO then repeats at DEBUG (see _at / _UNSET).
        self._last_desired = _UNSET
        # Throttle for the unchanged steady-state DEBUG heartbeat, so a quiet
        # backup/master does not log its (identical) decision every tick and churn
        # the log rotation. A change re-arms it (see _at).
        self._heartbeat = _RateLimit(RECONCILE_HEARTBEAT_INTERVAL)

    @property
    def mode(self):
        """The active mode, set once at construction (coerced/validated)."""
        return self._mode

    @property
    def enabled(self):
        """True in observe/enforce (off is inert); see DefaultRouteMode."""
        return self._mode in (DefaultRouteMode.OBSERVE, DefaultRouteMode.ENFORCE)

    def reconcile(self, is_master, bound, gateway):
        """Drive the FIB default toward the desired state for the current
        (is_master, bound, gateway). Call from the main loop thread only.

        is_master: True / False, or None when the CARP probe itself failed.
        bound:     True iff a lease is currently held (binding.yiaddr set). This
                   is the lease-held signal; do NOT infer it from `gateway`,
                   which can linger non-None after a lease loss (expire() clears
                   only yiaddr).
        gateway:   the current lease's own gateway (binding.lease_router), used
                   as the route's gateway and only when bound.
        """
        if not self.enabled:
            return

        # A live binding plus a sane, non-zero unicast gateway is a usable lease
        # (the guard rejects a 0.0.0.0 / malformed option-3, and a stale gateway
        # lingering past a lease loss -- see the bound/gateway contract above).
        # Role-independent: without a usable lease there is nothing to be master OF,
        # so the default must go regardless of the CARP role.
        holds_lease = bound and _sane_ipv4(gateway)

        # Role unreadable AND a lease is held: we might still legitimately be
        # master, so tolerate a bounded number of unreadable probes (fail-safe on
        # install, fail-closed on withdraw) rather than flapping the default on a
        # transient ifconfig failure. Every other state -- role readable, or no
        # usable lease -- is decided normally below, so an unreadable role on an
        # unbound node withdraws at once instead of holding for the strike limit.
        if is_master is None and holds_lease:
            self._on_unknown_role()
            return
        self._strikes = 0
        self._unreadable_warned = False   # not in an unreadable-while-bound episode -> re-arm

        want = (is_master is True) and holds_lease

        blocked = want and self._liveness_blocks()
        if blocked:
            # Master with a lease but liveness is explicitly not confirmed
            # (possible split-brain / dead WAN with a stale lease): do not keep a
            # default we may be unable to honour. Fall through to the withdraw arm,
            # tagged so the log says why (not a plain CARP role loss).
            want = False

        have = self._fib_default_gateway()

        # Confirm the desired state once per change at INFO, then quietly at DEBUG:
        # a steady master ("owning default via X") or backup ("no default held")
        # states its ownership at the default log view without per-tick spam, and
        # observe's would-install/would-withdraw stops repeating every tick.
        desired = (want, gateway if want else None)
        changed = desired != self._last_desired
        self._last_desired = desired

        if want:
            if have == gateway:
                self._confirm_owned(changed, gateway)  # already correct -- no route change
            else:
                self._install(changed, gateway, replacing=have)
        else:
            reason = self._no_default_reason(blocked, is_master, holds_lease)
            # A route-get failure (for any reason) also reads as None here, so we
            # skip the withdraw. Treating an unreadable table as "absent" is a
            # deliberate trade-off: an empty table -- the common quiet state on a
            # backup -- is the overwhelming case, route(8)'s empty-table wording
            # varies by platform/version, and warning on every empty read would be
            # noise. The genuine stuck case (a default present while route get
            # fails) is rare (get and delete share one routing socket) and
            # self-corrects: the reconcile re-reads every tick, and once the read
            # succeeds the withdraw runs and confirms the FIB. A bounded delay
            # beats a per-tick false alarm.
            if have is None:
                self._confirm_no_default(changed, reason)  # already absent
            else:
                self._withdraw(changed, have, reason)

    @staticmethod
    def _no_default_reason(blocked, is_master, holds_lease):
        """Why the desired state is 'no default' -- the informative half of the
        backup/no-lease/liveness heartbeat and of a withdraw."""
        if blocked:
            return "liveness not confirmed (possible split-brain / dead WAN)"
        if not holds_lease:
            return "no usable lease"
        if is_master is not True:
            return "CARP backup"
        return "not owned"

    def _confirm_owned(self, changed, gateway):
        """Steady-state master heartbeat: the FIB default already matches the lease
        gateway, so there is nothing to install -- state ownership positively
        instead of returning silently."""
        if self._mode == DefaultRouteMode.OBSERVE:
            _at(changed, self._heartbeat)("[observe] default already via %s -- would own", gateway)
        else:
            _at(changed, self._heartbeat)("owning default via %s", gateway)

    def _confirm_no_default(self, changed, reason):
        """Steady-state no-default heartbeat: there is correctly no default to
        hold (backup / no lease / liveness-gated)."""
        if self._mode == DefaultRouteMode.OBSERVE:
            _at(changed, self._heartbeat)("[observe] no default held (%s) -- as wanted", reason)
        else:
            _at(changed, self._heartbeat)("no default held (%s)", reason)

    def _on_unknown_role(self):
        """An unreadable (is_master is None) probe: do not install when unsure,
        but after a bounded number of consecutive unknown probes, withdraw any
        default we still hold so a former master stops advertising once its role
        can no longer be confirmed. The warning fires once per unreadable episode
        (re-armed when the role reads definite again), not every tick."""
        self._strikes += 1
        if self._strikes < self._strike_limit:
            return
        have = self._fib_default_gateway()
        if have is None:
            return
        first_time = not self._unreadable_warned
        if first_time:
            LOG.warning("CARP role unreadable for %d checks -- failing closed on "
                        "the default", self._strikes)
            self._unreadable_warned = True
        self._withdraw(first_time, have, "CARP role unreadable")

    def _liveness_blocks(self):
        """True only when the liveness probe is present and returns an explicit
        False. A missing probe or a None result never blocks."""
        if self._liveness_probe is None:
            return False
        try:
            return self._liveness_probe() is False
        except Exception:  # pylint: disable=broad-exception-caught
            # A broken liveness probe must not block routing.
            return False

    # ---- FIB operations (idempotent, error-tolerant, main-loop only) ----

    def _install(self, changed, gateway, replacing=None):
        if self._mode == DefaultRouteMode.OBSERVE:
            _at(changed, self._heartbeat)("[observe] would install default via %s%s", gateway,
                                          "" if replacing is None else f" (replacing {replacing})")
            return
        # Replace atomically with `route change`, not delete-then-add. A bench
        # check on FreeBSD 14.3 confirmed both halves: `route change` to an on-link
        # gateway swaps in place (no momentary no-default gap for FRR
        # redistribute-kernel to flap on), and to an off-link gateway it fails
        # ("Invalid argument") and leaves the old default intact -- so a still-usable
        # default is never torn down for one we cannot install (e.g. a cross-subnet
        # lease whose new gateway is not on-link until the interface moves). A first
        # install (no prior default) uses `add`: `change` requires the route to
        # exist. Then CONFIRM the FIB reached the desired state -- reading the result
        # back is wording-independent, unlike parsing route(8)'s exit/stderr, and a
        # rejected change simply reads back as the old gateway (surfaced below).
        verb = RouteCommand.ADD if replacing is None else RouteCommand.CHANGE
        _route(verb, _DEFAULT, gateway)
        have = self._fib_default_gateway()
        if have == gateway:
            LOG.info("installed default via %s%s", gateway,
                     "" if replacing is None else f" (was {replacing})")
        else:
            LOG.error("failed to install default via %s (the FIB default is now %s)",
                      gateway, have or "absent")

    def _withdraw(self, changed, current, reason):
        if self._mode == DefaultRouteMode.OBSERVE:
            _at(changed, self._heartbeat)("[observe] would withdraw default (currently via %s) -- %s",
                                          current, reason)
            return
        _route(RouteCommand.DELETE, _DEFAULT)
        # Confirm the FIB, not the exit code: a silently failed delete would leave
        # a backup advertising a black-hole default -- the one outcome this feature
        # exists to prevent -- so surface it at ERROR. The level-triggered
        # reconcile retries the withdraw next tick.
        if self._fib_default_gateway() is None:
            LOG.info("withdrew default (was via %s) -- %s", current, reason)
        else:
            LOG.error("failed to withdraw default (still via %s) -- this node keeps "
                      "advertising it", current)

    def _fib_default_gateway(self):
        """Current IPv4 default gateway, or None when there is no default. Any
        `route get` failure (an empty table exits non-zero) reads as 'no default'
        -- the common, quiet steady state on a backup -- rather than an error; a
        genuinely stuck route op is surfaced by the install/withdraw confirm, not
        by second-guessing this read."""
        res = run([_ROUTE, _NUMERIC, RouteCommand.GET, _AF_INET, _DEFAULT])
        if res is None or res.returncode != 0:
            return None
        for line in res.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith(_GATEWAY_FIELD):
                return stripped[len(_GATEWAY_FIELD):].strip() or None
        return None


class BackupEgressReconciler:
    """Reconciles the optional backup-egress route set (docs/backup-egress.md):
    while a node is the CARP backup (no WAN default) it routes its own internet
    traffic to the master via a leak-safe /1-split (or configured prefixes), and
    removes that set while it is master (the inverse of the 0/0 the default-route
    reconciler manages). Level-triggered and idempotent, main-loop thread only.

    Ownership, not shape, decides what it touches: the /1-split is also the classic
    full-tunnel-VPN pair, so a foreign next hop is never overwritten or removed."""

    def __init__(self, mode: "str | DefaultRouteMode" = DefaultRouteMode.OFF, *,
                 backup_egress: "BackupEgressConfig | None" = None):
        # mode is coerced (as in DefaultRouteReconciler) so an unrecognised value is
        # inert OFF; the backup set only acts under observe/enforce.
        self._mode = DefaultRouteMode.coerce(mode)
        self._backup = backup_egress or BackupEgressConfig()
        self._last_backup_desired = _UNSET
        self._backup_heartbeat = _RateLimit(RECONCILE_HEARTBEAT_INTERVAL)
        self._valid_prefixes = None            # cached validated prefixes (warn-once via the cache)
        self._backup_installed_gws = set()     # gateways our prefixes are confirmed at (ownership)
        self._warn = _WarnGates()              # rising-edge one-shot warn flags

    @property
    def enabled(self):
        """True when the backup-egress feature is active (mode observe/enforce AND the
        feature enabled). Lets the caller decide whether the unbound path must probe the
        real CARP role for backup egress (the 0/0 withdraw there uses a fictional role)."""
        return (self._mode in (DefaultRouteMode.OBSERVE, DefaultRouteMode.ENFORCE)
                and self._backup.enabled)

    def withdraw_backup_egress(self):
        """Remove the backup-egress routes (the /1-split plus any configured prefixes) at a
        process boundary, so a stopped keeper leaves none that a later master would loop
        through. A no-op unless the feature is enabled: the /1-split (0.0.0.0/1 +
        128.0.0.0/1) is also the classic full-tunnel-VPN split, so a keeper that never
        managed backup egress must not delete a /1 it does not own -- routes are cleaned by
        ownership, not by matching a shape. observe logs, enforce deletes. Unlike the
        reconcile loop there is no next tick to retry, so an unconfirmable removal is
        surfaced loudly here rather than left to a silent re-check.

        Accepted limit: a /1 left by a crashed predecessor whose feature (or mode) is then
        disabled before restart is not cleaned, because it can no longer be told apart from
        an unrelated VPN /1. That narrow crash-then-disable case needs manual cleanup (or
        the deferred persisted-ownership follow-up); see docs/backup-egress.md."""
        if not self.enabled:
            return
        self._backup_remove(self._backup_removal_set(), changed=True, reason="keeper stopping")
        if self._mode == DefaultRouteMode.ENFORCE and self._fib_routes() is None:
            LOG.warning("backup egress: could not clean up at shutdown (routing table "
                        "unreadable) -- a leftover /1 would loop egress if this node is master")

    def reconcile_backup_egress(self, is_master):
        """Keep the backup-egress route set present while this node is the CARP
        backup and absent while it is master (the inverse of the 0/0 it manages).
        Call from the same tick as the default-route reconcile, after it. A no-op
        unless the feature is enabled and the mode is observe/enforce (off is inert).
        is_master None (an unreadable role) touches nothing, like the 0/0 side."""
        if not self.enabled or is_master is None:
            return
        if is_master:
            self._warn.unresolved = False   # re-arm so a returning backup re-warns once
            desired = (_BackupState.ABSENT, None)
        else:
            gateway = self._resolve_backup_gateway()
            desired = ((_BackupState.PRESENT, gateway) if gateway
                       else (_BackupState.UNRESOLVED, None))
        changed = desired != self._last_backup_desired
        self._last_backup_desired = desired
        state, gateway = desired
        if state is _BackupState.PRESENT:
            self._backup_install(self._backup_route_set(), gateway, changed)
        elif state is _BackupState.ABSENT:
            # Remove the UNION of every form's prefixes, not just the current one, so a
            # form change that orphaned an old set (e.g. split -> prefixes) is cleaned
            # up here too -- a leftover /1 on the master would loop all egress.
            self._backup_remove(self._backup_removal_set(), changed)
        # UNRESOLVED: the gateway could not be worked out (warned, rising-edge); leave
        # the FIB as-is rather than tearing down a possibly-good route.

    # ---- backup-egress route sets (cached: form/prefixes/mode are set-once) ----

    def _backup_route_set(self):
        """The prefixes to install for the configured form. SPLIT (and any unrecognised
        form) is the leak-safe /1-split; PREFIXES is the validated configured list."""
        if self._backup.form == BackupEgressForm.PREFIXES:
            return self._backup_prefixes()
        return _SPLIT_PREFIXES

    def _backup_removal_set(self):
        """The /1-split plus the CURRENT configured prefixes -- the set removed on the
        master. This covers a form change (split <-> prefixes; the /1-split is always
        included) but NOT a prefixes-LIST change across an ungraceful exit: a prefix
        dropped from the config while a crashed predecessor still had it installed is not
        known here and would orphan (a black-hole for that one prefix, not egress-wide).
        A graceful restart removes the old set at shutdown; only crash-then-list-change
        leaves it. Persisting the managed set is deferred (see docs/backup-egress.md)."""
        return tuple(dict.fromkeys(_SPLIT_PREFIXES + self._backup_prefixes()))

    def _backup_prefixes(self):
        """The validated configured prefixes, cached so the drop warnings (invalid
        prefix, 0.0.0.0/0 under enforce, empty prefixes list) each fire once."""
        if self._valid_prefixes is None:
            valid = []
            for prefix in self._backup.prefixes:
                try:
                    net = ipaddress.ip_network(prefix, strict=False)
                except ValueError:
                    LOG.warning("backup egress: ignoring invalid prefix %r", prefix)
                    continue
                if net.version != 4:   # the FIB ops are IPv4-only (netstat/route -inet)
                    LOG.warning("backup egress: ignoring non-IPv4 prefix %r (IPv4 only)", prefix)
                    continue
                if self._mode == DefaultRouteMode.ENFORCE and net == _DEFAULT_NET:
                    LOG.warning("backup egress: 0.0.0.0/0 is owned by enforce and cannot be "
                                "a backup-egress route -- ignoring it (use the /1-split)")
                    continue
                valid.append(prefix)
            if self._backup.form == BackupEgressForm.PREFIXES and not valid:
                LOG.warning("backup egress: form is 'prefixes' but no valid prefixes are set")
            self._valid_prefixes = tuple(valid)
        return self._valid_prefixes

    # ---- gateway resolution ----

    def _resolve_backup_gateway(self):
        """The next hop for the backup-egress route: the configured stable gateway (a
        CARP VIP or a fallback-WAN gateway), or, when blank, the derived point-to-point
        peer of the configured interface. None (warned, rising-edge) when it cannot be
        worked out; a successful resolve re-arms the warning."""
        gateway = self._backup_gateway()
        self._warn.unresolved = gateway is None
        return gateway

    def _backup_gateway(self):
        cfg = self._backup
        if cfg.gateway:
            own = self._gateway_is_own(cfg.gateway)   # True / False / None (could not check)
            if own is None:
                self._warn_unresolved("backup egress: could not verify gateway %s (route get "
                                      "failed) -- deferring rather than routing via a maybe-own "
                                      "address", cfg.gateway)
                return None
            if own:
                self._warn_unresolved("backup egress: gateway %s is this node's own address "
                                      "(config-sync trap) -- not routing via self", cfg.gateway)
                return None
            return cfg.gateway
        if not cfg.interface:
            self._warn_unresolved("backup egress: no gateway set and no interface to derive "
                                  "one from")
            return None
        return self._derive_peer(cfg.interface)

    def _warn_unresolved(self, fmt, *args):
        """Log a gateway-resolution failure at most once per unresolved episode: a node
        can sit as backup for a long time, so the message must not churn the log."""
        if not self._warn.unresolved:
            LOG.warning(fmt, *args)

    def _gateway_is_own(self, gateway):
        """Tri-state: True if `gateway` is this node's own address (FreeBSD routes a local
        address via lo0), False if it is not, None if the check could not run (route get
        failed). Catches the config-sync trap of an explicit peer unicast that is correct
        on the peer but equals this node's own IP. A CARP VIP this node is backup for is
        not active locally, so it resolves via the real interface, not lo0 -- the
        recommended VIP gateway is not caught. Never cached: a transient route-get failure
        must not permanently disable the guard, so the caller defers on None and re-checks."""
        res = run([_ROUTE, _NUMERIC, RouteCommand.GET, _AF_INET, gateway])
        if res is None or res.returncode != 0:
            return None   # could not determine -> caller defers rather than routing blind
        for line in res.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("interface:"):
                return stripped.split(":", 1)[1].strip() == "lo0"
        return False

    def _derive_peer(self, iface):
        """The other host of a point-to-point (/30 or /31) subnet on `iface` = the
        peer/master. None (warned) on a non-point-to-point interface or an unreadable
        address, so we never guess a peer."""
        info = self._iface_ipv4(iface)
        if info is None:
            self._warn_unresolved("backup egress: cannot read an IPv4 address on %s", iface)
            return None
        own, prefixlen = info
        if prefixlen not in _PTP_PREFIXLENS:
            self._warn_unresolved("backup egress: %s is /%d, not a point-to-point /30 or /31 "
                                  "-- the peer is not unique, set an explicit gateway",
                                  iface, prefixlen)
            return None
        net = ipaddress.ip_network(f"{own}/{prefixlen}", strict=False)
        # The peer is the other host of the /30 or /31 (the one that is not us).
        return next((str(host) for host in net.hosts() if str(host) != own), None)

    def _iface_ipv4(self, iface):
        """(address, prefixlen) of the first IPv4 on `iface`, or None. Runs
        `ifconfig <iface> inet`; ifprobe.iface_ipv4 does the parse."""
        res = run([_IFCONFIG, iface, "inet"])
        if res is None or res.returncode != 0:
            return None
        return iface_ipv4(res.stdout)

    # ---- backup-egress FIB operations (idempotent, fail-safe on an unreadable table) ----

    def _backup_owned_gateways(self):
        """Gateway strings that mark a backup-egress route as managed by THIS feature: the
        configured explicit gateway (stable across role and restart) plus every gateway our
        prefixes are currently confirmed present at this session. A FIB entry for one of our
        prefixes is ours -- safe to change or remove -- only when its next hop is one of
        these; any other next hop is a foreign route (a full-tunnel VPN's /1, a static or
        connected route) we must never touch. Empty when nothing is known (e.g. a derived
        peer on a fresh master), which makes cleanup best-effort there rather than risk
        clobbering an unrelated route."""
        gateways = set(self._backup_installed_gws)
        if self._backup.gateway:
            gateways.add(self._backup.gateway)
        return gateways

    def _note_backup_collisions(self, prefixes, gateway):
        """Warn (rising-edge) that a backup-egress prefix already has a foreign next hop, so
        the operator sees it; re-arm the gate once a pass is collision-free. `gateway` is our
        intended next hop on install; None on the master-side removal, where an unattributable
        /1 might actually be our own stale leftover looping this node's egress."""
        if not prefixes:
            self._warn.collision = False
            return
        if not self._warn.collision:
            if gateway is None:
                LOG.warning("backup egress: %s present via a next hop this node does not own "
                            "-- leaving it untouched; if it is a stale backup-egress route this "
                            "node is now looping its own egress (clean it up, or set an explicit "
                            "backup-egress gateway so ownership survives a restart)",
                            " ".join(prefixes))
            else:
                LOG.warning("backup egress: %s already routed via another next hop (not %s) -- "
                            "leaving it untouched (not managed by this feature)",
                            " ".join(prefixes), gateway)
            self._warn.collision = True

    def _classify_backup_prefixes(self, route_set, gateway, have):
        """Split the desired prefixes against the current FIB `have` into (pending,
        collisions): pending are absent or present via a gateway we already own (ADD/CHANGE
        toward `gateway`); collisions are present via a foreign next hop we must never
        overwrite. A prefix already correct via `gateway` needs neither."""
        owned = self._backup_owned_gateways() | {gateway}
        pending, collisions = [], []
        for prefix in route_set:
            cur = have.get(self._net(prefix))
            if cur == gateway:
                continue                       # already ours and correct
            if cur is None or cur in owned:
                pending.append(prefix)         # absent -> ADD; our own stale gateway -> CHANGE
            else:
                collisions.append(prefix)      # foreign next hop -> never overwrite
        return pending, collisions

    def _prune_backup_ownership(self, state, route_set):
        """Keep only owned gateways still hosting one of our prefixes in `state`, so a route
        that was removed or migrated does not leave its old next hop retained as owned --
        which would let a later CHANGE overwrite an unrelated route that reappears via it."""
        self._backup_installed_gws = {
            gw for gw in self._backup_installed_gws
            if any(state.get(self._net(p)) == gw for p in route_set)
        }

    def _record_backup_ownership(self, gateway, state, route_set):
        """Fold in the just-resolved `gateway`, then prune to gateways still hosting one of
        our prefixes. Never speculative -- a failed change keeps the still-present old next
        hop owned (so promotion still removes it), while a succeeded change retires it."""
        self._backup_installed_gws.add(gateway)
        self._prune_backup_ownership(state, route_set)

    def _backup_install(self, route_set, gateway, changed):
        if not route_set:
            return
        if self._mode == DefaultRouteMode.OBSERVE:
            _at(changed, self._backup_heartbeat)(
                "[observe] would route backup egress via %s (%s)", gateway, " ".join(route_set))
            return
        have = self._fib_routes()
        if have is None:
            # netstat unreadable (already warned in _fib_routes); defer rather than
            # blind-add, which would miss a needed change / stale-gateway correction.
            return
        pending, collisions = self._classify_backup_prefixes(route_set, gateway, have)
        self._note_backup_collisions(collisions, gateway)
        state = have
        if pending:
            for prefix in pending:
                verb = RouteCommand.ADD if have.get(self._net(prefix)) is None else RouteCommand.CHANGE
                _route(verb, prefix, gateway)
            state = self._fib_routes()
            if state is None:
                return   # writes issued but cannot confirm (already warned); re-check next tick
        self._record_backup_ownership(gateway, state, route_set)
        if not pending:
            if not collisions:
                _at(changed, self._backup_heartbeat)(
                    "backup egress via %s (%s)", gateway, " ".join(route_set))
            return
        missing = [p for p in pending if state.get(self._net(p)) != gateway]
        if not missing:
            LOG.info("backup egress routed via %s (%s)", gateway, " ".join(pending))
        else:
            LOG.error("backup egress: failed to route %s via %s", " ".join(missing), gateway)

    def _backup_remove(self, removal_set, changed, reason="now master"):
        # `reason` distinguishes callers so the log does not assert a role change that
        # did not happen: the reconcile master path uses the default, the shutdown
        # boundary passes "keeper stopping".
        if self._mode == DefaultRouteMode.OBSERVE:
            _at(changed, self._backup_heartbeat)(
                "[observe] would remove backup egress (%s)", " ".join(removal_set))
            return
        have = self._fib_routes()
        if have is None:
            # Unreadable table: ownership cannot be verified, and the /1-split is also a
            # full-tunnel-VPN pair, so a blind delete could tear down an unrelated route.
            # Skip (already warned in _fib_routes); the next readable tick removes ours.
            return
        owned = self._backup_owned_gateways()
        present, collisions = [], []
        for prefix in removal_set:
            cur = have.get(self._net(prefix))
            if cur is None:
                continue                       # not in the table
            if cur in owned:
                present.append(prefix)         # our next hop -> safe to remove
            else:
                collisions.append(prefix)      # foreign next hop -> leave it
        self._note_backup_collisions(collisions, None)
        if not present:
            self._prune_backup_ownership(have, removal_set)   # nothing of ours here -> drop stale gws
            _at(changed, self._backup_heartbeat)("no backup egress (%s)", reason)
            return
        for prefix in present:
            _route(RouteCommand.DELETE, prefix)
        now = self._fib_routes()
        if now is None:
            return   # deletes issued but cannot confirm (already warned); re-check next tick
        self._prune_backup_ownership(now, removal_set)        # removed routes -> retire their gws
        still_present = [p for p in present if now.get(self._net(p)) in owned]
        if not still_present:
            LOG.info("removed backup egress -- %s", reason)
        else:
            LOG.error("backup egress: failed to remove %s -- this node would loop its egress",
                      " ".join(still_present))

    def _fib_routes(self):
        """{network: gateway} for the IPv4 FIB from one `netstat -rn` pass, or None when
        the table cannot be read -- callers must not mistake an unreadable table for 'no
        routes' and skip the master-side removal. A bare host address parses as /32;
        header and default rows that are not a network are skipped."""
        res = run([_NETSTAT, "-rn", "-f", "inet"])
        if res is None or res.returncode != 0:
            if not self._warn.fib_unreadable:   # once per unreadable episode (re-armed below)
                # Neutral wording: on install this defers the write, but on the master
                # removal path the deletes ARE issued and only the confirm is deferred.
                LOG.warning("backup egress: cannot read the routing table (netstat) -- route "
                            "state cannot be confirmed until it is readable")
                self._warn.fib_unreadable = True
            return None
        self._warn.fib_unreadable = False
        routes = {}
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            try:
                net = ipaddress.ip_network(parts[0], strict=False)
            except ValueError:
                continue
            routes.setdefault(net, parts[1])
        return routes

    @staticmethod
    def _net(prefix):
        """Parse a (pre-validated) prefix string to a network, for FIB comparison."""
        return ipaddress.ip_network(prefix, strict=False)
