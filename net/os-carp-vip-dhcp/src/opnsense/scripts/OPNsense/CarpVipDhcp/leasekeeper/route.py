"""Default-route ownership keyed on CARP role.

The keeper owns the IPv4 WAN default route (0.0.0.0/0) as a function of its CARP
role and whether it currently holds a DHCP lease: only the CARP-master node that
actually holds a lease keeps a default in the FIB; every other state has none. A
node with no default advertises none (via os-frr redistribute kernel), so the
failure mode is a withdrawn default, never a black-holed one. See
docs/single-ip-wan-carp.md.

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
import logging
import subprocess
from enum import StrEnum

from .constants import LOGGER_NAME
from .util import _sane_ipv4

LOG = logging.getLogger(LOGGER_NAME)

# Daemon log-and-continue posture: broad catch-alls are deliberate (see the
# package docstring / module docstrings).
# pylint: disable=broad-exception-caught


class DefaultRouteMode(StrEnum):
    """Per-keeper default-route mode (the values the model's defaultRouteMode
    field carries). StrEnum (like constants.Phase) so a member both is its config
    string and compares by value -- the value flows in from the model verbatim.
    off: inert (default). observe: log what it would do, no FIB write. enforce:
    actually install/withdraw."""
    OFF = "off"
    OBSERVE = "observe"
    ENFORCE = "enforce"


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

# Consecutive unreadable CARP-role probes tolerated while we still hold a
# default before we withdraw it. An unreadable probe (ifconfig failed) is
# fail-safe on the INSTALL side (do nothing) but must fail *closed* on the
# WITHDRAW side, or a former master with a flaky ifconfig keeps advertising a
# default it should have dropped. A genuine role loss reads as False within a
# tick; only a stuck probe reaches this ceiling.
DEFAULT_UNREADABLE_ROLE_STRIKES = 3

_ROUTE = "/sbin/route"
_NUMERIC = "-n"              # numeric output, no name resolution
_AF_INET = "-inet"          # IPv4 address family modifier; the v6 twin: -inet6
_GATEWAY_FIELD = "gateway:"  # the field label parsed from `route get` output
_SUBPROC_TIMEOUT = 5


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
        # as a plain string; coerce it, and treat any unrecognised value as inert
        # OFF. Set-once: exposed read-only via the `mode` property.
        try:
            self._mode = DefaultRouteMode(mode)
        except ValueError:
            LOG.warning("unknown default-route mode %r -- treating as off", mode)
            self._mode = DefaultRouteMode.OFF  # never guess an active mode
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
        # (rejects a 0.0.0.0 / malformed option-3 from a rogue or broken DHCP
        # server, and a gateway that lingers after a lease loss -- expire() clears
        # only yiaddr). Role-independent: without a usable lease there is nothing to
        # be master OF, so the default must go regardless of the CARP role.
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

        if want and self._liveness_blocks():
            # Master with a lease but liveness is explicitly not confirmed
            # (possible split-brain / dead WAN with a stale lease): do not keep a
            # default we may be unable to honour. Fall through to the withdraw arm.
            want = False

        have = self._fib_default_gateway()
        if want:
            if have == gateway:
                return  # already correct -- silent, no route change, no churn
            self._install(gateway, replacing=have)
        else:
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
                return  # already absent (or unreadable -- see above)
            self._withdraw(have)

    # ---- role-unknown handling ----

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
        if not self._unreadable_warned:
            LOG.warning("CARP role unreadable for %d checks -- failing closed on "
                        "the default", self._strikes)
            self._unreadable_warned = True
        self._withdraw(have)

    def _liveness_blocks(self):
        """True only when the liveness probe is present and returns an explicit
        False. A missing probe or a None result never blocks."""
        if self._liveness_probe is None:
            return False
        try:
            return self._liveness_probe() is False
        except Exception:
            # A broken liveness probe must not block routing.
            return False

    # ---- FIB operations (idempotent, error-tolerant, main-loop only) ----

    def _install(self, gateway, replacing=None):
        if self._mode == DefaultRouteMode.OBSERVE:
            LOG.info("[observe] would install default via %s%s", gateway,
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
        self._route(verb, _DEFAULT, gateway)
        have = self._fib_default_gateway()
        if have == gateway:
            LOG.info("installed default via %s%s", gateway,
                     "" if replacing is None else f" (was {replacing})")
        else:
            LOG.error("failed to install default via %s (the FIB default is now %s)",
                      gateway, have or "absent")

    def _withdraw(self, current):
        if self._mode == DefaultRouteMode.OBSERVE:
            LOG.info("[observe] would withdraw default (currently via %s)", current)
            return
        self._route(RouteCommand.DELETE, _DEFAULT)
        # Confirm the FIB, not the exit code: a silently failed delete would leave
        # a backup advertising a black-hole default -- the one outcome this feature
        # exists to prevent -- so surface it at ERROR. The level-triggered
        # reconcile retries the withdraw next tick.
        if self._fib_default_gateway() is None:
            LOG.info("withdrew default (was via %s)", current)
        else:
            LOG.error("failed to withdraw default (still via %s) -- this node keeps "
                      "advertising it", current)

    def _fib_default_gateway(self):
        """Current IPv4 default gateway, or None when there is no default. Any
        `route get` failure (an empty table exits non-zero) reads as 'no default'
        -- the common, quiet steady state on a backup -- rather than an error; a
        genuinely stuck route op is surfaced by the install/withdraw confirm, not
        by second-guessing this read."""
        res = self._run([_ROUTE, _NUMERIC, RouteCommand.GET, _AF_INET, _DEFAULT])
        if res is None or res.returncode != 0:
            return None
        for line in res.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith(_GATEWAY_FIELD):
                return stripped[len(_GATEWAY_FIELD):].strip() or None
        return None

    def _route(self, command, dest, gateway=None):
        """Issue a `/sbin/route` command (best effort). The caller confirms the
        resulting FIB state, so a non-zero exit -- an idempotent no-op or a real
        failure alike -- is only debug-logged and left for that confirm to judge,
        rather than guessed from route(8)'s wording here."""
        cmd = [_ROUTE, _NUMERIC, command, _AF_INET, dest]
        if gateway is not None:
            cmd.append(gateway)
        res = self._run(cmd)
        if res is not None and res.returncode != 0:
            LOG.debug("route %s %s exit %d: %s", command, dest, res.returncode,
                      (res.stderr or "").strip())

    def _run(self, cmd):
        """Run a `/sbin/route` argv, capturing output and bounded by a timeout;
        return the CompletedProcess, or None if it could not be executed at all
        (logged)."""
        try:
            return subprocess.run(cmd, capture_output=True, errors="replace",
                                  timeout=_SUBPROC_TIMEOUT, check=False)
        except (OSError, subprocess.SubprocessError) as e:
            LOG.warning("route command failed to run (%s): %s", " ".join(cmd), e)
            return None
