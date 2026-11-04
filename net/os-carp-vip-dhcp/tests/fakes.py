"""Shared test fakes for the route and daemon suites.

FakeRoute is an in-memory stand-in for /sbin/route + /usr/bin/netstat +
/sbin/ifconfig (monkeypatched onto subprocess.run) plus the WAN gateway
constants both suites use. It lives here, not in test_route.py, so test_daemon.py
can share it without importing another test module. FakeNgctl is the same kind of
stand-in for /usr/sbin/ngctl and /sbin/kldload (option E, leasekeeper/vmac.py).
"""
# pylint: disable=missing-function-docstring
import types
from dataclasses import dataclass, field

from leasekeeper.route import RouteCommand
from leasekeeper.vmac import _parse_config

GW = "185.41.66.1"
GW2 = "185.41.66.9"
CGNAT_GW = "100.64.4.1"   # the production case: a 100.64/10 single-IP CGNAT WAN


class FakeRoute:  # pylint: disable=too-many-instance-attributes
    """In-memory stand-in for /sbin/route + /usr/bin/netstat + /sbin/ifconfig: a
    dest->nexthop table (dest 'default' or a CIDR), a verb log, and per-interface
    (addr, prefixlen) for backup-egress peer derivation. `gw` is the default's
    nexthop, kept as a property so the default-route tests read it unchanged."""

    def __init__(self, initial=None, *, broken=(), lying=(), none=(),  # pylint: disable=too-many-arguments
                 ifaces=None, netstat_fails=False, local_ips=()):
        self.routes = {}
        if initial is not None:
            self.routes["default"] = initial
        self.calls = []
        self.broken = set(broken)  # verbs that fail with a genuine (non-benign) error
        self.lying = set(lying)    # verbs that exit 0 but do NOT mutate the FIB
        self.none = set(none)      # verbs whose run() could not launch at all (returns None)
        self.ifaces = dict(ifaces or {})   # iface -> (addr, prefixlen)
        self.netstat_fails = netstat_fails  # netstat -rn exits non-zero (unreadable table)
        self.local_ips = set(local_ips)     # addresses a `route get` resolves to lo0 (own IPs)

    @property
    def gw(self):
        return self.routes.get("default")

    @gw.setter
    def gw(self, value):
        if value is None:
            self.routes.pop("default", None)
        else:
            self.routes["default"] = value

    def run(self, cmd, **_kwargs):  # capture_output / errors / timeout -- ignored
        self.calls.append(list(cmd))
        prog = cmd[0]
        if prog.endswith("netstat"):
            if self.netstat_fails:
                return self._reply(1, "", "netstat: routing table unavailable")
            return self._reply(0, self._netstat_body())
        if prog.endswith("ifconfig"):
            # Only route._iface_ipv4 shells ifconfig here, always as
            # `ifconfig -f inet:cidr <iface> inet` -> iface is the token before "inet".
            iface = cmd[cmd.index("inet") - 1] if "inet" in cmd else cmd[-1]
            return self._ifconfig(iface)
        return self._route(cmd)

    def _route(self, cmd):  # pylint: disable=too-many-branches
        # ["/sbin/route","-n",verb,"-inet",dest[,gw]]; single return to keep the verb
        # branches readable without tripping too-many-return-statements.
        verb, dest = cmd[2], cmd[4]
        if verb in self.none:  # run() could not launch the command at all -> None
            return None
        rc, out, err = 0, "", ""
        if verb in self.broken:  # a real failure: stuck route / bad socket, not a no-op
            rc, err = 1, "route: writing to routing socket: permission denied"
        elif verb == RouteCommand.GET:
            if dest in self.routes:                 # a known route dest (e.g. "default")
                out = f"   gateway: {self.routes[dest]}\n   interface: vlan0\n"
            elif dest == "default":                 # no default installed
                rc, err = 1, "route: not in table"
            else:                                   # host lookup (used by _gateway_is_own):
                iface = "lo0" if dest in self.local_ips else "vlan0"  # own IP resolves to lo0
                out = f"   gateway: {dest}\n   interface: {iface}\n"
        elif verb == RouteCommand.ADD:
            if self.routes.get(dest) is not None:  # FreeBSD: add fails when it exists
                rc, err = 1, "route: writing to routing socket: File exists"
            elif verb not in self.lying:  # a lying add exits 0 but leaves the FIB unchanged
                self.routes[dest] = cmd[-1]
        elif verb == RouteCommand.CHANGE:
            if self.routes.get(dest) is None:  # change fails when no route exists
                rc, err = 1, "route: change: not in table"
            else:
                self.routes[dest] = cmd[-1]  # on-link swaps in place; off-link is broken={CHANGE}
        elif verb == RouteCommand.DELETE:
            existed = self.routes.pop(dest, None) is not None
            rc, err = (0, "") if existed else (1, "not in table")
        return self._reply(rc, out, err)

    def _netstat_body(self):
        lines = ["Routing tables", "", "Internet:",
                 "Destination        Gateway            Flags     Netif"]
        for dest, gw in self.routes.items():
            shown = dest[:-3] if dest.endswith("/32") else dest  # FreeBSD prints host routes bare
            lines.append(f"{shown}        {gw}        UGS       vlan0")
        return "\n".join(lines) + "\n"

    def _ifconfig(self, iface):
        # Mirrors `ifconfig -f inet:cidr`: the address prints as A.B.C.D/NN.
        info = self.ifaces.get(iface)
        if info is None:
            return self._reply(1, "", f"ifconfig: interface {iface} does not exist")
        addr, prefixlen = info
        body = f"{iface}: flags=8843<UP>\n\tinet {addr}/{prefixlen} broadcast 0.0.0.0\n"
        return self._reply(0, body)

    @staticmethod
    def _reply(rc, out, err=""):
        return types.SimpleNamespace(returncode=rc, stdout=out, stderr=err)

    @property
    def verbs(self):
        return [c[2] for c in self.calls if c[0].endswith("route")]


# ---- netgraph (option E, vmac.py) ----

@dataclass
class NgKnobs:
    """Failure knobs for FakeNgctl. missing: every command could not run (None).
    kldload_fails: kldload exits 1. lying: `-f -` exits 0 and changes nothing.
    fail_after: `-f -` applies its first N lines, then exits 1. shutdown_lies:
    shutdown exits 0 and leaves the node."""
    missing: bool = False
    kldload_fails: bool = False
    lying: bool = False
    fail_after: "int | None" = None
    shutdown_lies: bool = False


@dataclass
class NgNode:
    """One netgraph node: its type, its hooks {local: (peer name, peer type, peer
    hook)}, a patch node's config (vmac._parse_config shape) and its stats."""
    type: str
    hooks: dict = field(default_factory=dict)
    config: "tuple | None" = None
    stats: tuple = (0, 0, 0)


_NG_MISSING = "ngctl: send msg: No such file or directory"
_NG_UNNAMED = "<unnamed>"   # how ngctl show names a node without a name


class FakeNgctl:
    """In-memory stand-in for /usr/sbin/ngctl + /sbin/kldload (monkeypatched onto
    subprocess.run), printing what the real tools print on FreeBSD 15 (captured on the
    bench, 2026-11-04). `nodes` holds the ether node of each interface and any patch
    node; `calls` logs every argv (with the stdin script appended for `-f -`)."""

    def __init__(self, ifaces=("vtnet0",), knobs=None):
        self.nodes = {i.replace(".", "_"): NgNode("ether") for i in ifaces}
        self.calls = []
        self.knobs = knobs or NgKnobs()

    # -- setup helpers --

    def link(self, a, a_hook, b, b_hook):
        """Connect a.a_hook <-> b.b_hook (both nodes must exist)."""
        self.nodes[a].hooks[a_hook] = (b, self.nodes[b].type, b_hook)
        self.nodes[b].hooks[b_hook] = (a, self.nodes[a].type, a_hook)

    def add_patch(self, name, ether, hooks=("in", "out"), config=None):
        """A patch node `name` on `ether` with the given hooks (in -> upper, out ->
        lower) and config: a pre-existing graph (adopted, half-built or stale)."""
        self.nodes[name] = NgNode("patch", config=config)
        for hook in hooks:
            self.link(name, hook, ether, "upper" if hook == "in" else "lower")

    def mutations(self):
        """The calls that change the graph or load modules (an inert path runs none)."""
        return [c for c in self.calls if c[1:2] in (["-f"], ["shutdown"]) or c[0].endswith("kldload")]

    def verbs(self):
        """The ngctl verbs called, in order (msg calls as msg:<what>)."""
        return [c[1] if c[1] != "msg" else f"msg:{c[3]}" for c in self.calls if c[0].endswith("ngctl")]

    # -- the fake commands --

    def run(self, cmd, **kwargs):
        script = kwargs.get("input")
        self.calls.append(list(cmd) + ([script] if script else []))
        if self.knobs.missing:
            return None
        if cmd[0].endswith("kldload"):
            return _ng_reply(1 if self.knobs.kldload_fails else 0, "", "kldload: can't load")
        handlers = {"show": lambda a: self._show(a[0].rstrip(":")),
                    "msg": lambda a: self._msg(a[0].rstrip(":"), a[1]),
                    "shutdown": lambda a: self._shutdown(a[0].rstrip(":")),
                    "-f": lambda a: self._script(script or "")}
        handler = handlers.get(cmd[1])
        return handler(cmd[2:]) if handler else _ng_reply(1, "", f"ngctl: unknown command {cmd[1]}")

    def _show(self, name):
        node = self.nodes.get(name)
        if node is None:
            return _ng_reply(71, "", _NG_MISSING)
        out = f"  Name: {name:<15} Type: {node.type:<15} ID: 0000000d   Num hooks: {len(node.hooks)}\n"
        if node.hooks:
            out += ("  Local hook      Peer name       Peer type    Peer ID         Peer hook      \n"
                    "  ----------      ---------       ---------    -------         ---------      \n")
            for local, (peer, ptype, phook) in node.hooks.items():
                out += f"  {local:<15} {peer:<15} {ptype:<12} 00000001        {phook:<15}\n"
        return _ng_reply(0, out)

    def _msg(self, name, what):
        node = self.nodes.get(name)
        if node is None:
            return _ng_reply(71, "", _NG_MISSING)
        head = f'Rec\'d response "{what}" (2) from "[d]:":\n'
        if what == "getautosrc":
            return _ng_reply(0, head + "Args:\t0\n")
        if what == "getstats":
            fields = " ".join(f"{k}={v}" for k, v in zip(("Received", "Patched", "Dropped"), node.stats) if v)
            return _ng_reply(0, head + (f"Args:\t{{ {fields} }}\n" if fields else "Args:\t{}\n"))
        if what == "getconfig":
            # As FreeBSD prints it: decimal values, zero fields left out, its own order.
            count, _csum, _rel, ops = node.config or (0, 0, 0, ())
            body = " ".join(f"{{ offset={o} length={n} mode={m} value={v} }}" for o, n, m, v in ops)
            return _ng_reply(0, head + f"Args:\t{{ count={count} ops=[ {body} ] }}\n")
        return _ng_reply(1, "", f"ngctl: {what}: unknown")

    def _shutdown(self, name):
        if ":" in name:                 # a path, <node>:<hook>: the peer across that hook
            here, hook = name.split(":")
            name = self.nodes.get(here, NgNode("")).hooks.get(hook, (None,))[0]
        node = self.nodes.get(name)
        if node is None:
            return _ng_reply(71, "", "ngctl: shutdown: No such file or directory")
        if not self.knobs.shutdown_lies:
            for peer, _ptype, phook in node.hooks.values():
                self.nodes[peer].hooks.pop(phook, None)
            del self.nodes[name]
        return _ng_reply(0, "")

    def _script(self, script):
        if self.knobs.lying:
            return _ng_reply(0, "")
        apply = {"mkpeer": self._mkpeer, "name": self._name, "connect": self._connect,
                 "msg": self._setconfig}
        for n, line in enumerate(script.strip().splitlines()):
            words = line.split()
            if self.knobs.fail_after is not None and n >= self.knobs.fail_after:
                return _ng_reply(1, "", f"ngctl: line {n + 1}: send msg: File exists")
            if not apply.get(words[0], lambda _w: False)(words):
                return _ng_reply(1, "", f"ngctl: line {n + 1}: {line}: failed")
        return _ng_reply(0, "")

    def _mkpeer(self, words):          # mkpeer <e>: patch upper in
        ether = words[1].rstrip(":")
        if words[3] in self.nodes[ether].hooks:
            return False                # the hook is taken: real ngctl fails here
        self.nodes[_NG_UNNAMED] = NgNode("patch")
        self.link(_NG_UNNAMED, words[4], ether, words[3])
        return True

    def _name(self, words):            # name <e>:upper <node>
        ether, hook = words[1].split(":")
        peer = self.nodes[ether].hooks.get(hook, (None,))[0]
        if peer != _NG_UNNAMED or words[2] in self.nodes:
            return False                # the name is taken: the unnamed node stays on upper
        node = self.nodes.pop(peer)
        self.nodes[words[2]] = node
        for p, _t, ph in node.hooks.values():
            self.nodes[p].hooks[ph] = (words[2], "patch", self.nodes[p].hooks[ph][2])
        return True

    def _connect(self, words):         # connect <e>: <node>: lower out
        a, b = words[1].rstrip(":"), words[2].rstrip(":")
        if b not in self.nodes or words[3] in self.nodes[a].hooks:
            return False
        self.link(b, words[4], a, words[3])
        return True

    def _setconfig(self, words):       # msg <node>: setconfig { ... }
        node = self.nodes.get(words[1].rstrip(":"))
        if node is None or words[2] != "setconfig":
            return False
        node.config = _parse_config(" ".join(words[3:]))
        return True


def _ng_reply(rc, out, err=""):
    return types.SimpleNamespace(returncode=rc, stdout=out, stderr=err)
