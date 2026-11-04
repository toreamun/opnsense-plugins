"""Send from the lease MAC while CARP master (experimental, opt-in; #131).

FreeBSD CARP sends a VIP's traffic from the node's own MAC. An ISP that forwards only
traffic whose source MAC is the MAC the lease is bound to (strict IP source guard, for
example Orange France, #110) leases the VIP fine and then drops everything it sends.
This module puts a netgraph node on the WAN interface while the node is CARP master:

    ether <e>: upper  ->  patch vmac_<e>  ->  ether <e>: lower

ng_patch overwrites bytes 6 to 11 of every frame the kernel sends (the Ethernet source)
with the keeper's lease MAC. Nothing on the interface changes; the backup is untouched.

Failure mode: the behaviour of today (frames leave from the own MAC). The graph is torn
down on demotion by three independent guards: this module (every role tick), the CARP
syshook and rc.d stop (both in the shell side). An unknown CARP role never builds and
tears down only after DEFAULT_UNREADABLE_ROLE_STRIKES consecutive unreadable probes, the
fail-closed rule route.py uses for the default route.

Inert when off: a disabled VmacEgress runs no command from reconcile() or at keeper
shutdown and reports no status; only main()'s startup call removes a leftover node of
ours (one `kldstat`, and one `ngctl show` when ng_patch is loaded at all), which is how
a graph goes away after the option was switched off.

One interface has one upper hook, so one rewrite: a keeper whose interface also carries
another keeper's CARP VIP refuses the option (that VIP would send from this MAC too), and
an off keeper there leaves the node alone at startup (it may be the other keeper's).

Concurrency: main loop thread only (Keeper._role_tick, the _maintain_step gate, the
process boundaries). Never kldload or build from the capture thread or a signal handler.
Design and decisions: the testbench design notes, section 11.7.
"""
import logging
import os
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import NamedTuple

from .constants import LOGGER_NAME, RECONCILE_HEARTBEAT_INTERVAL
from .route import DEFAULT_UNREADABLE_ROLE_STRIKES, _UnreadableRole, _log_at
from .syscmd import run
from .util import MAC_RE, _RateLimit

LOG = logging.getLogger(LOGGER_NAME)

NGCTL = "/usr/sbin/ngctl"
KLDLOAD = "/sbin/kldload"
KLDSTAT = "/sbin/kldstat"
_MODULES = ("ng_ether", "ng_patch")
_NODE_PREFIX = "vmac_"
_NODE_NAME_MAX = 31                       # NG_NODESIZ (32) less the terminating NUL
_DHCLIENT_PID = "/var/run/dhclient.{}.pid"
_HOOK_IN = "in"                           # patch hook fed by the ether node's upper
_HOOK_OUT = "out"                         # patch hook that feeds the ether node's lower
_ETHER_HOOKS = ("upper", "lower")         # the ether node's hooks the graph takes
_UNNAMED = "<unnamed>"                    # how ngctl show names a peer without a name
_ENOENT = "No such file or directory"     # ngctl's text (exit 71) for a node that is not there


class VmacState(StrEnum):
    """The heartbeat token `vmac=<state[:reason]>` (no spaces). BUILT and NATIVE are the
    two healthy states (master rewriting, backup native); UNKNOWN is the unreadable-role
    episode. Every other value says why the rewrite is not active."""
    BUILT = "built"
    NATIVE = "native"
    UNKNOWN = "unknown"
    NO_VHID = "refused:no-vhid"
    BAD_VHID = "refused:bad-vhid"
    MAC_OVERRIDE = "refused:mac-override"
    BAD_MAC = "refused:bad-mac"
    SHARED_IFACE = "refused:shared-iface"
    DHCP_WAN = "refused:dhcp-wan"
    NO_ETHER_NODE = "refused:no-ether-node"
    HOOKS_TAKEN = "refused:hooks-taken"
    FOREIGN_NODE = "refused:foreign-node"
    KLDLOAD = "failed:kldload"
    BUILD = "failed:build"
    READBACK = "failed:readback"
    TEARDOWN = "failed:teardown"
    NGCTL = "unavailable:ngctl"


# What each state means for the operator, appended to the line that enters it.
_WHY = {
    VmacState.NO_VHID: "the keeper has no CARP vhid, so there is no master to gate on",
    VmacState.BAD_VHID: "the CARP vhid is not a number from 1 to 255",
    VmacState.MAC_OVERRIDE: "a Client MAC override is set (not supported with this option)",
    VmacState.BAD_MAC: "the lease MAC is not a valid MAC address",
    VmacState.SHARED_IFACE: "another keeper's CARP VIP is on this interface; it would send from "
                            "this MAC too, and an interface has room for one rewrite",
    VmacState.DHCP_WAN: "a DHCP client runs on the interface; the node's own traffic would "
                        "also leave from the lease MAC (the option needs a static WAN address)",
    VmacState.NO_ETHER_NODE: "the interface has no netgraph ether node (not an Ethernet interface)",
    VmacState.HOOKS_TAKEN: "another netgraph node holds the interface's hooks",
    VmacState.FOREIGN_NODE: "a node of another type already uses the name",
    VmacState.KLDLOAD: "the kernel modules ng_ether and ng_patch could not load",
    VmacState.BUILD: "the netgraph build failed",
    VmacState.READBACK: "the built graph did not read back as wanted; removed",
    VmacState.TEARDOWN: "the rewrite could not be removed and may still be active; retrying every tick",
    VmacState.NGCTL: "ngctl could not run",
}
_HEALTHY = (VmacState.BUILT, VmacState.NATIVE)
_ERRORS = (VmacState.BUILD, VmacState.READBACK, VmacState.TEARDOWN)   # ERROR, the rest WARNING


class _Presence(StrEnum):
    """What `ngctl show vmac_<e>:` found. ABSENT is the quiet backup's steady state;
    HALF is any patch node of ours that is not exactly the wanted graph (one hook, a
    wrong peer, a wrong config); FOREIGN is a node of another type under our name;
    UNREADABLE means ngctl could not run or failed otherwise (no action either way)."""
    ABSENT = "absent"
    BUILT = "built"
    HALF = "half"
    FOREIGN = "foreign"
    UNREADABLE = "unreadable"


_OURS = (_Presence.BUILT, _Presence.HALF)   # a patch node of ours that a teardown removes


class _Peer(NamedTuple):
    """One hook row of `ngctl show`: the node across the hook."""
    name: str
    type: str
    hook: str


class _Shown(NamedTuple):
    """`ngctl show` parsed: the node's type and {local hook: _Peer}."""
    type: str
    hooks: dict


def ether_node(iface):
    """The netgraph name of an interface's ether node: the ifnet name with `.` as `_`."""
    return iface.replace(".", "_")


def vmac_node(iface):
    """Our patch node's name on `iface` (kept under the 31-character name limit)."""
    return (_NODE_PREFIX + ether_node(iface))[:_NODE_NAME_MAX]


def carp_vmac(vhid):
    """The CARP virtual MAC of `vhid` (00:00:5e:00:01:<vhid>)."""
    return f"00:00:5e:00:01:{int(vhid):02x}"


def _patch_ops(mac):
    """The two ng_patch SET operations for `mac`, as (offset, length, mode, value): bytes
    6 to 9 and 10 to 11 of the frame (the Ethernet source), values in network order."""
    raw = bytes.fromhex(re.sub(r"[:-]", "", mac))
    return ((6, 4, 1, int.from_bytes(raw[0:4], "big")),
            (10, 2, 1, int.from_bytes(raw[4:6], "big")))


def _setconfig(mac):
    """The `setconfig` argument for `mac`. getconfig prints the values back in decimal
    and drops zero fields, so the read-back compares parsed integers, never text."""
    ops = " ".join(f"{{ mode={mode} value=0x{value:0{length * 2}x} length={length} offset={offset} }}"
                   for offset, length, mode, value in _patch_ops(mac))
    return f"{{ count=2 csum_flags=0 relative_offset=0 ops=[ {ops} ] }}"


def _build_script(iface, mac):
    """The one `ngctl -f-` session that builds the graph. Order B: the patch node goes on
    `upper` first (a frame sent in between is returned to the stack, counted nowhere),
    then `lower`, then the config. No setdlt, never rmhook. One session on stdin, never
    four spawns: a gap between mkpeer and connect is a window for a returned frame."""
    e, node = ether_node(iface), vmac_node(iface)
    return (f"mkpeer {e}: patch upper {_HOOK_IN}\n"
            f"name {e}:upper {node}\n"
            f"connect {e}: {node}: lower {_HOOK_OUT}\n"
            f"msg {node}: setconfig {_setconfig(mac)}\n")


_HEADER_RE = re.compile(r"Name:\s+(\S+)\s+Type:\s+(\S+)")
_FIELD_RE = re.compile(r"(\w+)=(0x[0-9A-Fa-f]+|-?\d+)")


def _parse_show(text):
    """`ngctl show` text -> _Shown, or None without a Name/Type header. Hook rows follow
    the dashed separator line and have five columns (local, peer name, peer type, peer
    id, peer hook)."""
    header = _HEADER_RE.search(text or "")
    if header is None:
        return None
    hooks, rows = {}, False
    for line in text.splitlines():
        if line.strip().startswith("---"):
            rows = True
            continue
        parts = line.split()
        if rows and len(parts) == 5:
            hooks[parts[0]] = _Peer(parts[1], parts[2], parts[4])
    return _Shown(header.group(2), hooks)


def _fields(text):
    return {k: int(v, 0) for k, v in _FIELD_RE.findall(text)}


def _parse_config(text):
    """getconfig text -> (count, csum_flags, relative_offset, sorted ops), or None when
    it has no ops list. A zero field is not printed, so a missing one reads as 0."""
    m = re.search(r"ops=\[(.*)\]", text or "", re.S)
    if m is None:
        return None
    head = _fields(text[:m.start()])
    ops = sorted((f.get("offset", 0), f.get("length", 0), f.get("mode", 0), f.get("value", 0))
                 for f in map(_fields, re.findall(r"\{([^{}]*)\}", m.group(1))))
    return head.get("count", 0), head.get("csum_flags", 0), head.get("relative_offset", 0), tuple(ops)


def _parse_dropped(text):
    """The Dropped counter of getstats text (a zero counter is not printed)."""
    return _fields(text or "").get("Dropped", 0)


def _ngctl(*args, stdin=None):
    return run([NGCTL, *args], quiet=True, stdin=stdin)


def _enoent(res):
    """True when an ngctl result failed because the node is not there."""
    return res.returncode != 0 and _ENOENT in (res.stderr or "") + (res.stdout or "")


def _patch_module_loaded():
    """True when ng_patch is in the kernel, so a patch node of ours can exist at all.
    Asked with kldstat, which changes nothing (an ngctl call can load ng_socket)."""
    res = run([KLDSTAT, "-q", "-m", "ng_patch"], quiet=True)
    return res is not None and res.returncode == 0


def _dhclient_running(iface):
    """True when OPNsense's DHCP client runs on `iface`: its pid file names a live
    process. The lease files under /var/db are no signal (stale ones remain)."""
    try:
        with open(_DHCLIENT_PID.format(iface), encoding="ascii") as f:
            pid = int(f.read().strip())
        os.kill(pid, 0)
    except PermissionError:
        return True        # the process exists (we may not signal it)
    except (OSError, ValueError, OverflowError):
        return False
    return True


def _static_refusal(chaddr, vhid, shared_iface):
    """Why the configuration itself rules the option out, or None."""
    if not vhid:
        return VmacState.NO_VHID
    try:
        vmac = carp_vmac(vhid)
    except ValueError:
        return VmacState.BAD_VHID
    if not 1 <= int(vhid) <= 255:
        return VmacState.BAD_VHID
    if not MAC_RE.match(chaddr):
        return VmacState.BAD_MAC
    if chaddr.replace("-", ":") != vmac:
        # D4: a Client MAC override is refused. Rewriting to the CARP virtual MAC would
        # send the VIP's traffic from a MAC the ISP never leased to; rewriting to the
        # override would make CARP's ARP replies carry the virtual MAC inside and the
        # override outside (gear with dynamic ARP inspection may drop them) and send the
        # CARP advertisements from the override. If ever needed: rewrite to the override
        # after a bench round that checks both.
        return VmacState.MAC_OVERRIDE
    return VmacState.SHARED_IFACE if shared_iface else None


@dataclass(frozen=True)
class _Target:
    """The fixed wiring: interface, node names, the rewrite MAC, whether another keeper
    shares the interface, and any reason the configuration rules the option out."""
    iface: str
    ether: str
    node: str
    mac: str
    shared_iface: bool
    static_refusal: "VmacState | None"


@dataclass
class _Gates:
    """Warn-once flags, each re-armed when its condition clears (like route._WarnGates)."""
    half: bool = False        # our node was not the wanted graph (re-armed once built)
    dropped: bool = False     # ng_patch Dropped rose while built (re-armed on a rebuild)
    teardown: bool = False    # a shutdown left the node (re-armed by a successful one)


@dataclass
class _Runtime:
    """Main-loop state of one VmacEgress."""
    state: VmacState = VmacState.NATIVE
    logged: "VmacState | None" = None     # the last state logged: an UNKNOWN blip does not re-log
    modules_loaded: bool = False          # kldload succeeded once (then latched)
    gates: _Gates = field(default_factory=_Gates)
    dropped: int = 0                      # the last Dropped count seen while built
    hooks_owner: str = ""                 # who holds the hooks, for the refused:hooks-taken line
    leftover: bool = False                # an interrupted build's unnamed node is on the hooks


class VmacEgress:
    """The source-MAC rewrite for one keeper (see the module docstring). reconcile() is
    level-triggered and idempotent; status() is the heartbeat token (None when off)."""

    def __init__(self, iface, chaddr, vhid, *, enabled=False, shared_iface=False):
        mac = (chaddr or "").lower()
        self.enabled = enabled
        self._t = _Target(iface, ether_node(iface), vmac_node(iface), mac, shared_iface,
                          _static_refusal(mac, vhid, shared_iface))
        self._run = _Runtime()
        self._unreadable = _UnreadableRole(DEFAULT_UNREADABLE_ROLE_STRIKES)
        self._heartbeat = _RateLimit(RECONCILE_HEARTBEAT_INTERVAL)

    def status(self):
        """The heartbeat token value, or None when the feature is off (no token)."""
        return str(self._run.state) if self.enabled else None

    # ---- the decision ----

    def reconcile(self, is_master):
        """Converge the graph on the CARP role: True builds (or confirms), False tears
        down, None (unreadable) never builds and tears down only after the strikes. Off
        is fully inert. A keeper restart on a master never rebuilds: the first tick reads
        the graph as built and only confirms."""
        if not self.enabled:
            return
        if is_master is None:
            self._on_unknown_role()
            return
        self._unreadable.reset()
        presence = self._present()
        if presence in (_Presence.UNREADABLE, _Presence.FOREIGN):
            if presence is _Presence.UNREADABLE:
                self._set_state(VmacState.NGCTL)
            else:
                self._set_state(VmacState.FOREIGN_NODE, f"({self._t.node}: never touched)")
            return
        refusal = self._refusal(presence)
        if not self._clear_leftover():
            self._set_state(VmacState.TEARDOWN)
        elif not is_master or refusal is not None:
            self._stand_down(presence, refusal)
        else:
            self._converge(presence)

    def _clear_leftover(self):
        """Remove an interrupted build's unnamed node found on the hooks (on either role:
        left on upper it returns every frame). True when there was none or it is gone."""
        if not self._run.leftover:
            return True
        self._run.leftover = False
        LOG.warning("vmac egress on %s: removing an unnamed patch node an interrupted "
                    "build left on %s", self._t.iface, self._t.ether)
        return self._teardown("an interrupted build's leftover")

    def _stand_down(self, presence, refusal):
        """Not master, or refused: no rewrite. A teardown that could not be confirmed is
        reported as such, never as native (the node may still be rewriting)."""
        if presence in _OURS and not self._teardown("not master" if refusal is None else str(refusal)):
            self._set_state(VmacState.TEARDOWN)   # never "native" while it may still rewrite
            return
        self._set_state(refusal or VmacState.NATIVE)

    def _converge(self, presence):
        """Master, not refused: confirm a built graph, else (re)build it."""
        if presence is _Presence.BUILT:
            self._confirm_built()
            return
        if presence is _Presence.HALF:
            if not self._run.gates.half:
                self._run.gates.half = True
                LOG.warning("vmac egress on %s: %s is not the wanted graph -- rebuilding",
                            self._t.iface, self._t.node)
            self._teardown("half-built")
        self._build()

    def teardown_unless_master(self, probe, *, leftover=False):
        """Process-boundary twin of route.withdraw_unless_master (keeper start in main()
        and keeper shutdown): keep the graph only on a confirmed master, tear it down on
        False or None. Off, it does nothing unless `leftover` (main()'s startup call):
        then it removes a leftover node of ours without probing the role (how the graph
        goes away after the option was switched off), skipped when ng_patch is not loaded
        or another keeper shares the interface (the node may be that keeper's).

        Trade-off (as for the default route): a keeper stopped for good while its node
        is still master keeps the rewrite with nothing managing it, until the next CARP
        event (the syshook) or rc.d stop. Telling a stop from a restart here would need a
        fragile signal, and a restart must not open a window of own-MAC frames."""
        if not self.enabled:
            if not leftover or self._t.shared_iface or not _patch_module_loaded():
                return
        elif probe() is True:
            return
        if self._present() in _OURS or self._unnamed_on_hooks():
            self._teardown("not master at a keeper start or stop" if self.enabled else "option off")

    # ---- states ----

    def _on_unknown_role(self):
        """Unreadable role: never build; after the strikes, tear down an existing graph
        (fail closed), warning once per episode. The token says unknown meanwhile."""
        self._run.state = VmacState.UNKNOWN
        if not self._unreadable.record():
            return
        if self._present() in _OURS or self._unnamed_on_hooks():
            if self._unreadable.take_warning():
                LOG.warning("vmac egress on %s: CARP role unreadable for %d probes -- removing "
                            "the source MAC rewrite (fail closed)", self._t.iface, self._unreadable.strikes)
            self._teardown("CARP role unreadable")

    def _refusal(self, presence):
        """Why the rewrite must not be active on this node, or None. Checked on the
        backup too (pre-staging: the status page shows the would-be result before a
        failover). The hook checks are skipped once our graph is built (it holds them)."""
        if self._t.static_refusal is not None:
            return self._t.static_refusal
        if not self._run.modules_loaded:
            loaded = [run([KLDLOAD, "-n", m], quiet=True) for m in _MODULES]
            if any(r is None or r.returncode != 0 for r in loaded):
                return VmacState.KLDLOAD
            self._run.modules_loaded = True
        refusal = None if presence is _Presence.BUILT else self._hooks_refusal()
        if refusal is None and _dhclient_running(self._t.iface):
            refusal = VmacState.DHCP_WAN
        return refusal

    def _hooks_refusal(self):
        """The interface's ether node must exist and its upper and lower hooks must be
        free (or ours): NetFlow capture holds the same hooks. An unnamed patch node there
        is a leftover of an interrupted build (ours: mkpeer ran, `name` did not), marked
        for the scrub, never a reason to refuse."""
        res = _ngctl("show", f"{self._t.ether}:")
        if res is None or (res.returncode != 0 and not _enoent(res)):
            return VmacState.NGCTL
        shown = _parse_show(res.stdout) if res.returncode == 0 else None
        if shown is None:
            return VmacState.NO_ETHER_NODE
        for hook in _ETHER_HOOKS:
            peer = shown.hooks.get(hook)
            if peer is None or peer.name == self._t.node:
                continue
            if peer.name == _UNNAMED and peer.type == "patch":
                self._run.leftover = True
                continue
            self._run.hooks_owner = f"{peer.name} ({peer.type})"
            return VmacState.HOOKS_TAKEN
        return None

    def _set_state(self, state, detail=""):
        """Record the token; log a change of state once (ERROR for a failed build or
        read-back, WARNING into another problem, INFO into a healthy state), the
        unchanged repeat at DEBUG on the heartbeat."""
        self._run.state = state
        changed = state != self._run.logged
        self._run.logged = state
        if state in _HEALTHY:
            what = "rewriting the source MAC to " + self._t.mac if state is VmacState.BUILT else "native"
            _log_at(changed, self._heartbeat)("vmac egress on %s: %s", self._t.iface, what)
            return
        if not changed:
            return
        if state is VmacState.HOOKS_TAKEN:
            # NetFlow capture is the one known holder (ng_netflow on the same hooks).
            detail = (f"{self._run.hooks_owner}; if that is NetFlow capture, disable it on this "
                      "interface or leave this option off")
        log = LOG.error if state in _ERRORS else LOG.warning
        log("vmac egress on %s not active (%s): %s %s", self._t.iface, state, _WHY.get(state, ""), detail)

    # ---- graph operations ----

    def _present(self):
        """Classify our node (see _Presence). BUILT needs exactly the two wanted hook
        rows and a getconfig equal to the wanted ops. Only "no such node" is ABSENT: any
        other ngctl failure is UNREADABLE, so a transient error never triggers a build
        over a working graph."""
        res = _ngctl("show", f"{self._t.node}:")
        if res is None:
            return _Presence.UNREADABLE
        if res.returncode != 0:
            return _Presence.ABSENT if _enoent(res) else _Presence.UNREADABLE
        shown = _parse_show(res.stdout)
        if shown is None or shown.type != "patch":
            return _Presence.FOREIGN
        want = {_HOOK_IN: _Peer(self._t.ether, "ether", "upper"),
                _HOOK_OUT: _Peer(self._t.ether, "ether", "lower")}
        if shown.hooks != want or self._t.static_refusal is not None:
            return _Presence.HALF   # (a refused config is never "built": it is torn down)
        return self._config_presence()

    def _config_presence(self):
        """BUILT when getconfig equals the wanted ops, HALF when it differs (a stale
        config, such as an earlier lease MAC), UNREADABLE when ngctl failed."""
        cfg = _ngctl("msg", f"{self._t.node}:", "getconfig")
        if cfg is None or cfg.returncode != 0:
            return _Presence.UNREADABLE
        wanted = (2, 0, 0, tuple(sorted(_patch_ops(self._t.mac))))
        return _Presence.BUILT if _parse_config(cfg.stdout) == wanted else _Presence.HALF

    def _build(self):
        """Build in one session, read back, and scrub at once on any failure (never leave
        a one-hook node). A build that did not finish (ngctl timed out or could not run:
        run() returns None for both) may have attached the node to upper already, so it
        is scrubbed too."""
        res = _ngctl("-f", "-", stdin=_build_script(self._t.iface, self._t.mac))
        if res is None or res.returncode != 0:
            self._scrub()
            detail = ("ngctl did not finish" if res is None
                      else (res.stderr or res.stdout or "").strip() or f"exit {res.returncode}")
            self._set_state(VmacState.BUILD, detail)
            return
        if self._present() is not _Presence.BUILT:
            self._scrub()
            self._set_state(VmacState.READBACK)
            return
        LOG.info("vmac egress on %s: built %s (in -> %s.upper, out -> %s.lower), source MAC %s",
                 self._t.iface, self._t.node, self._t.ether, self._t.ether, self._t.mac)
        self._run.dropped = 0
        self._run.gates = _Gates()
        auto = _ngctl("msg", f"{self._t.ether}:", "getautosrc")
        if auto is not None:
            LOG.debug("vmac egress on %s: %s getautosrc: %s (want 0)", self._t.iface,
                      self._t.ether, " ".join(auto.stdout.split()[-1:]))
        self._set_state(VmacState.BUILT)

    def _scrub(self):
        """Remove what a failed build left: our named node, and a patch node mkpeer put on
        the interface's hooks before `name` ran. Shutting our name down cannot reach that
        unnamed node, and left on `upper` it returns every frame the stack sends (the
        self-demoting state). Only a patch node that is ours or unnamed is touched: the
        hooks were checked free before the build, so nothing else can be there."""
        _ngctl("shutdown", f"{self._t.node}:")
        for hook in self._patch_peers():
            _ngctl("shutdown", f"{self._t.ether}:{hook}")

    def _patch_peers(self):
        """{hook: peer name} of the interface's hooks held by a patch node that is ours
        or unnamed (an interrupted build's): what a scrub may shut down. Empty when the
        ether node is unreadable."""
        res = _ngctl("show", f"{self._t.ether}:")
        shown = _parse_show(res.stdout) if res is not None and res.returncode == 0 else None
        peers = {hook: shown.hooks.get(hook) for hook in _ETHER_HOOKS} if shown else {}
        return {hook: peer.name for hook, peer in peers.items()
                if peer is not None and peer.type == "patch" and peer.name in (_UNNAMED, self._t.node)}

    def _unnamed_on_hooks(self):
        """True when an unnamed patch node sits on the interface's hooks (an interrupted
        build in this or an earlier process): `ngctl show` of our name cannot see it."""
        return _UNNAMED in self._patch_peers().values()

    def _confirm_built(self):
        """A built graph: confirm, and warn once when Dropped rises (memory pressure in
        ng_patch, not a half-built graph: do not rebuild)."""
        self._run.gates.half = False
        stats = _ngctl("msg", f"{self._t.node}:", "getstats")
        if stats is not None and stats.returncode == 0:
            dropped = _parse_dropped(stats.stdout)
            if dropped > self._run.dropped and not self._run.gates.dropped:
                self._run.gates.dropped = True
                LOG.warning("vmac egress on %s: ng_patch dropped %d frames (memory pressure); "
                            "the graph is kept", self._t.iface, dropped)
            self._run.dropped = dropped
        self._set_state(VmacState.BUILT)

    def _teardown(self, reason):
        """Remove the rewrite (our node and any unnamed patch node on the hooks) and
        confirm both are gone; True when confirmed. Always safe to retry: a node still
        present is retried on the next tick, warned once until a teardown works."""
        self._scrub()
        if self._present() is _Presence.ABSENT and not self._patch_peers():
            self._run.gates.teardown = False
            LOG.info("vmac egress on %s: removed %s (%s)", self._t.iface, self._t.node, reason)
            return True
        if not self._run.gates.teardown:
            self._run.gates.teardown = True
            LOG.warning("vmac egress on %s: %s still present after shutdown (%s) -- retrying "
                        "every tick", self._t.iface, self._t.node, reason)
        return False
