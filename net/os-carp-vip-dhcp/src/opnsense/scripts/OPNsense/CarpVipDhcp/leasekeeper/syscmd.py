"""One place the lease keeper runs system commands.

Every shell-out goes through here, argv only -- never a shell, so there is no
injection surface -- in one of two named shapes:

  * run() -- synchronous (route / netstat / ifconfig / sysctl): wait, capture
    output, bounded by a timeout; a failure to LAUNCH returns None rather than
    raising, so callers branch on None. A non-zero exit is not a launch failure:
    run() still returns the CompletedProcess so the caller reads the code/output.
  * spawn() -- fire-and-forget (the configctl dispatch that restarts this very
    daemon): return at once, no wait, detached; a launch failure RAISES so the
    caller keeps its retry policy.

The raw /dev/bpf capture/inject (capture_bpf: ioctl + os.read/write) is the one
system boundary not funnelled here: it is packet IO, not a command, and lives in
BpfCapture.
"""
import logging
import subprocess

from .constants import LOGGER_NAME

LOG = logging.getLogger(LOGGER_NAME)
SUBPROC_TIMEOUT = 5


def run(cmd, *, timeout=SUBPROC_TIMEOUT, quiet=False):
    """Run argv `cmd`, capturing output, bounded by `timeout`; return the
    CompletedProcess, or None if it could not be executed at all. A launch
    failure is logged at WARNING unless `quiet` -- the per-tick ifconfig probes
    keep their own throttled, warn-once error policy and want silence here.
    text=True (implied by errors= but stated) so stdout/stderr are str."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                              timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as e:
        if not quiet:
            LOG.warning("command failed to run (%s): %s", " ".join(cmd), e)
        return None


def spawn(cmd):
    """Launch argv `cmd` fire-and-forget: return immediately, do not wait, capture
    nothing. For a command that will outlive or REPLACE this process -- the
    configctl follow_update restarts the daemon -- where run() (which waits) would
    block until we are killed. Detached into its own session (start_new_session)
    so our own restart/termination cannot race-kill the in-flight child, with all
    stdio to /dev/null so nothing leaks into the daemon's log as it is torn down.
    A launch failure PROPAGATES (Popen raises -- OSError on fork/exec failure,
    ValueError on invalid argv -- and spawn does not catch it), unlike run's None:
    the caller owns the retry policy, because a follow that could not be dispatched
    must be re-driven, not silently marked done."""
    subprocess.Popen(cmd, stdin=subprocess.DEVNULL,  # pylint: disable=consider-using-with
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     start_new_session=True)


def ifconfig(iface=None, *, quiet=True):
    """`ifconfig [iface]` stdout, or None if it could not run or exited non-zero.
    Quiet by default: the callers (CARP-role probe, CARP-state map) each apply
    their own error policy, and the caller parses the field it needs -- the CARP
    line, the inet address -- from the text."""
    res = run(["/sbin/ifconfig"] + ([iface] if iface else []), quiet=quiet)
    return res.stdout if res is not None and res.returncode == 0 else None
