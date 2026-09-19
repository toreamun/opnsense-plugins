"""The signal-driven request flags shared between the async signal handlers and
the maintain loop, behind a tiny protocol that makes the safe usage the only
usage. Kept in its own module so the concurrency invariant ("a handler only ever
sets True, the loop only ever clears") lives in one small, self-contained place.
"""
from dataclasses import dataclass


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
