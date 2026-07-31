"""Default-route ownership keyed on CARP role.

The keeper owns the IPv4 WAN default route (0.0.0.0/0) as a function of its CARP
role and whether it currently holds a DHCP lease: only the CARP-master node that
actually holds a lease keeps a default in the FIB; every other state has none. A
node with no default advertises none (via os-frr redistribute kernel), so the
failure mode is a withdrawn default, never a black-holed one. See
docs/default-route-carp-ownership.md.

Concurrency: reconcile() must be called only from the keeper's main loop thread;
the intended caller is Keeper._poll_carp_role (the per-tick poll and the SIGUSR2
CARP / route_reload edge), wired in a later change. Signal handlers and the capture thread never
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

LOG = logging.getLogger(LOGGER_NAME)

# Daemon log-and-continue posture: broad catch-alls are deliberate (see the
# package docstring / module docstrings).
# pylint: disable=broad-exception-caught


class DefaultRouteMode(StrEnum):
    """Per-keeper default-route mode (the values the model's defaultRouteMode
    field will carry). StrEnum (like constants.Phase) so a member both is its
    config string and compares by value -- the value flows in from the model
    verbatim. off:
    inert (default). observe: log what it would do, no FIB write. enforce:
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
    DELETE = "delete"
    GET = "get"


# The IPv4 default. IPv6 is out of scope (docs section 12): no v6 BGP fw<->pve,
# so no v6 default leak to gate.
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

    def __init__(self, mode=DefaultRouteMode.OFF, *,
                 unreadable_role_strikes=DEFAULT_UNREADABLE_ROLE_STRIKES,
                 liveness_probe=None):
        try:
            self.mode = DefaultRouteMode(mode)
        except ValueError:
            self.mode = DefaultRouteMode.OFF  # unknown mode string -> inert, never guess
        self._strike_limit = unreadable_role_strikes
        # liveness_probe: optional callable() -> bool|None gating the INSTALL
        # side (the split-brain guard). None (no callable) or a None result means
        # "no opinion" and never blocks; only an explicit False blocks. It must
        # be debounced by the caller -- a single transient miss must not read
        # False, or a healthy master would flap its default. See docs section 2.
        self._liveness_probe = liveness_probe
        self._strikes = 0

    @property
    def enabled(self):
        return self.mode in (DefaultRouteMode.OBSERVE, DefaultRouteMode.ENFORCE)

    def reconcile(self, is_master, bound, gateway):
        """Drive the FIB default toward the desired state for the current
        (is_master, bound, gateway). Call from the main loop thread only.

        is_master: True / False, or None when the CARP probe itself failed.
        bound:     True iff a lease is currently held (binding.yiaddr set). This
                   is the lease-held signal; do NOT infer it from `gateway`,
                   which is a sticky last-known hint that survives a lease loss.
        gateway:   the lease gateway (binding.router), used as the route's
                   gateway and only when bound.
        """
        if not self.enabled:
            return

        # Guard the unreadable-role case first, before any FIB read: fail-safe on
        # install, fail-closed (bounded) on withdraw.
        if is_master is None:
            self._on_unknown_role()
            return
        self._strikes = 0

        want = is_master and bound and gateway is not None
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
            if have is None:
                return  # already absent -- silent
            self._withdraw(have)

    # ---- role-unknown handling ----

    def _on_unknown_role(self):
        """An unreadable (is_master is None) probe: do not install when unsure,
        but after a bounded number of consecutive unknown probes, withdraw any
        default we still hold so a former master stops advertising once its role
        can no longer be confirmed."""
        self._strikes += 1
        if self._strikes < self._strike_limit:
            return
        have = self._fib_default_gateway()
        if have is not None:
            LOG.warning("CARP role unreadable for %d checks -- withdrawing default "
                        "(fail-closed)", self._strikes)
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
        if self.mode == DefaultRouteMode.OBSERVE:
            LOG.info("[observe] would install default via %s%s", gateway,
                     "" if replacing is None else " (replacing %s)" % replacing)
            return
        # Match the base's set-default idiom (delete then add) so a wrong gateway
        # is corrected; the delete is tolerated when there is nothing to remove.
        if replacing is not None:
            self._route(RouteCommand.DELETE, _DEFAULT)
        if self._route(RouteCommand.ADD, _DEFAULT, gateway):
            LOG.info("installed default via %s%s", gateway,
                     "" if replacing is None else " (was %s)" % replacing)

    def _withdraw(self, current):
        if self.mode == DefaultRouteMode.OBSERVE:
            LOG.info("[observe] would withdraw default (currently via %s)", current)
            return
        if self._route(RouteCommand.DELETE, _DEFAULT):
            LOG.info("withdrew default (was via %s)", current)

    def _fib_default_gateway(self):
        """Current IPv4 default gateway, or None when there is no default. A
        query error (`route get` on an empty table exits non-zero with 'not in
        table') is treated as 'no default', not as a probe failure."""
        res = self._run([_ROUTE, _NUMERIC, RouteCommand.GET, _AF_INET, _DEFAULT])
        if res is None or res.returncode != 0:
            return None
        for line in res.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith(_GATEWAY_FIELD):
                return stripped[len(_GATEWAY_FIELD):].strip() or None
        return None

    def _route(self, command, dest, gateway=None):
        """Issue a `/sbin/route` command; return True on success. A non-zero exit
        (route already present on add, or absent on delete) is tolerated and
        logged at debug -- the reconcile is idempotent, so a redundant op is
        expected, not an error."""
        cmd = [_ROUTE, _NUMERIC, command, _AF_INET, dest]
        if gateway is not None:
            cmd.append(gateway)
        res = self._run(cmd)
        if res is None:
            return False
        if res.returncode != 0:
            LOG.debug("route %s %s exit %d (tolerated): %s", command, dest,
                      res.returncode, (res.stderr or "").strip())
            return False
        return True

    def _run(self, cmd):
        """Run a `/sbin/route` argv, capturing output and bounded by a timeout;
        return the CompletedProcess, or None if it could not be executed at all.
        A non-zero exit is a normal, tolerated outcome (idempotent ops), so it is
        left for the caller to interpret rather than folded into None here."""
        try:
            return subprocess.run(cmd, capture_output=True, errors="replace",
                                  timeout=_SUBPROC_TIMEOUT)
        except (OSError, subprocess.SubprocessError) as e:
            LOG.warning("route command failed to run (%s): %s", " ".join(cmd), e)
            return None
