"""The heartbeat file: one status line the keeper rewrites at least every
HB_REFRESH seconds. This module owns its format; the readers are status.py
(_HB_TOKENS), the system status banner (CarpVipDhcpStatus.php) and the CARP
eligibility hook (rc.carp_service_status.d), so a token added or changed here
must be added or changed there too.

    <epoch> bound=<ip|-> lease=<s> t1=<s> t2=<s> src=<server|derived>
            [master=<0|1>] demote_ok=<0|1> [nudge=<epoch> arpok=<epoch> [gw=<ip>]]
            [pcperr=<errno name>] [cfgerr=1]
    <epoch> MISMATCH got=<ip> want=<ip>
"""
import logging
from typing import NamedTuple

from .constants import LOGGER_NAME
from .util import _atomic_write

LOG = logging.getLogger(LOGGER_NAME)


class Heartbeat(NamedTuple):
    """What one heartbeat line reports; heartbeat_line() renders it."""
    now: float
    bound: str | None        # the held address, None while unbound
    lease: int
    t1: int
    t2: int
    src: str                 # where T1/T2 come from (server or derived)
    master: bool | None      # the CARP role, None before the first probe
    demote_ok: bool
    nudge: tuple | None      # (last nudge epoch, last ARP reply epoch, gateway) when the nudge is on
    pcperr: str | None       # why the VLAN priority could not be set
    config_error: bool


def heartbeat_line(hb):
    """The heartbeat line for hb. Token by token:

    master: the CARP role, omitted only for a vhid keeper before its first probe.
        Lease-holding is judged only on the master (a passive backup nudges nothing
        and holds no lease) by the banner and the CARP eligibility hook; status.py
        takes the live role from ifconfig instead, so it does not read this token.
    demote_ok=1: tells the CARP eligibility hook (when demote is set) to demote this
        node: it is the master and has not held the lease past the grace.
    nudge/arpok: epoch of the last nudge sent and of the gateway's last ARP reply
        (0 = never), and gw the nudge target when known; only while the nudge is on.
    pcperr: the VLAN priority could not be set, so frames go out without it.
    cfgerr=1: a configuration error stops all DHCP; the reason is in the log.
        The banner shows cfgerr and pcperr first, on both nodes."""
    line = f"{int(hb.now)} bound={hb.bound or '-'} lease={hb.lease} t1={hb.t1} t2={hb.t2} src={hb.src}"
    if hb.master is not None:
        line += f" master={1 if hb.master else 0}"
    line += f" demote_ok={1 if hb.demote_ok else 0}"
    if hb.nudge is not None:
        last_nudge, last_reply, gw = hb.nudge
        line += f" nudge={int(last_nudge)} arpok={int(last_reply)}"
        if gw:
            line += f" gw={gw}"
    if hb.pcperr:
        line += f" pcperr={hb.pcperr}"
    if hb.config_error:
        line += " cfgerr=1"
    return line + "\n"


def mismatch_line(now, got, want):
    """The heartbeat line for an ISP address that differs from the VIP."""
    return f"{int(now)} MISMATCH got={got} want={want}\n"


def write_heartbeat(path, content):
    """Write the heartbeat file atomically (no-op without a path). A failure is
    logged: the heartbeat drives CARP gating, so it must not fail silently."""
    if not path:
        return
    try:
        _atomic_write(path, content)
    except OSError as e:
        LOG.warning("heartbeat write failed (%s): %s", path, e)
