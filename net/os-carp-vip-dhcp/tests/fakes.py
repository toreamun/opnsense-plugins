"""Shared test fakes for the route and daemon suites.

FakeRoute is an in-memory stand-in for /sbin/route + /usr/bin/netstat +
/sbin/ifconfig (monkeypatched onto subprocess.run) plus the WAN gateway
constants both suites use. It lives here, not in test_route.py, so test_daemon.py
can share it without importing another test module.
"""
# pylint: disable=missing-function-docstring
import types

from leasekeeper.route import RouteCommand

GW = "185.41.66.1"
GW2 = "185.41.66.9"
CGNAT_GW = "100.64.4.1"   # the production case: a 100.64/10 single-IP CGNAT WAN


class FakeRoute:
    """In-memory stand-in for /sbin/route + /usr/bin/netstat + /sbin/ifconfig: a
    dest->nexthop table (dest 'default' or a CIDR), a verb log, and per-interface
    (addr, prefixlen) for backup-egress peer derivation. `gw` is the default's
    nexthop, kept as a property so the default-route tests read it unchanged."""

    def __init__(self, initial=None, *, broken=(), lying=(),  # pylint: disable=too-many-arguments
                 ifaces=None, netstat_fails=False, local_ips=()):
        self.routes = {}
        if initial is not None:
            self.routes["default"] = initial
        self.calls = []
        self.broken = set(broken)  # verbs that fail with a genuine (non-benign) error
        self.lying = set(lying)    # verbs that exit 0 but do NOT mutate the FIB
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
            return self._ifconfig(cmd[1])
        return self._route(cmd)

    def _route(self, cmd):
        # ["/sbin/route","-n",verb,"-inet",dest[,gw]]; single return to keep the verb
        # branches readable without tripping too-many-return-statements.
        verb, dest = cmd[2], cmd[4]
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
        info = self.ifaces.get(iface)
        if info is None:
            return self._reply(1, "", f"ifconfig: interface {iface} does not exist")
        addr, prefixlen = info
        mask = (0xffffffff << (32 - prefixlen)) & 0xffffffff if prefixlen else 0
        body = f"{iface}: flags=8843<UP>\n\tinet {addr} netmask 0x{mask:08x} broadcast 0.0.0.0\n"
        return self._reply(0, body)

    @staticmethod
    def _reply(rc, out, err=""):
        return types.SimpleNamespace(returncode=rc, stdout=out, stderr=err)

    @property
    def verbs(self):
        return [c[2] for c in self.calls if c[0].endswith("route")]
