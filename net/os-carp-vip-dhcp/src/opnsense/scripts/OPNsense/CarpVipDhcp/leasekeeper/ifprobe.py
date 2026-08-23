"""Parse ifconfig(8) output text.

The counterpart to syscmd, which *runs* ifconfig: this module *reads* its text,
so keeper.py and status.py agree on exactly how a CARP line and a status line
are interpreted instead of each carrying its own parser (they used to -- keeper
matched the CARP role by substring, status by a separate regex). Pure text in,
values out; no IO.
"""
import ipaddress
import re
from enum import StrEnum

# One regex owns the CARP line shape ("carp: <ROLE> vhid <N> ..."). The role is a
# complete whitespace-bounded token (\S+, so the lossless contract holds even for a
# token with non-word characters). The vhid is the whole number followed by (?!\S) --
# whitespace or end of text -- so vhid 199 matches neither 19, 1990, nor a malformed
# "199x" / "199-foo" (a bare \b would still accept a trailing non-word char like '-').
_CARP_LINE = re.compile(r"carp:\s+(\S+)\s+vhid\s+(\d+)(?!\S)")
_STATUS_ACTIVE = "status: active"    # carrier up
_STATUS_ANY = "status: "             # a status line is present at all (up or down)


class CarpRole(StrEnum):
    """The CARP states ifconfig(8) reports. StrEnum (like constants.Phase) so a
    member is its own ifconfig token; used as the typed MASTER constant below."""
    MASTER = "MASTER"
    BACKUP = "BACKUP"
    INIT = "INIT"


def carp_roles(ifconfig_text):
    """Map vhid (str) -> role token (str) for every CARP line in `ifconfig_text`
    (empty dict when the text is None/empty). The role token is passed through
    verbatim -- an unrecognised state is kept, not dropped, so the status view
    never loses a VIP (CarpRole names the three states carp(4) actually emits)."""
    roles = {}
    if not ifconfig_text:
        return roles
    for role, vhid in _CARP_LINE.findall(ifconfig_text):
        roles[vhid] = role
    return roles


def is_carp_master(ifconfig_text, vhid):
    """True/False whether `vhid` is CARP MASTER in `ifconfig_text`, or None when
    the text is missing (probe failed) -- distinct from present-but-not-master
    (False). vhid is matched exactly, so 199 never reads as 19 or 1990."""
    if ifconfig_text is None:
        return None
    return carp_roles(ifconfig_text).get(str(vhid)) == CarpRole.MASTER


def carrier_up(ifconfig_text):
    """Interface carrier from `ifconfig_text`: True on 'status: active', False on
    a present-but-inactive status line, None when it cannot be read (text missing,
    or the NIC reports no status line at all)."""
    if ifconfig_text is None:
        return None
    if _STATUS_ACTIVE in ifconfig_text:
        return True
    if _STATUS_ANY in ifconfig_text:
        return False
    return None


def iface_ipv4(ifconfig_text):
    """(address, prefixlen) of the first IPv4 in `ifconfig -f inet:cidr <iface> inet`
    text ('inet A.B.C.D/NN ...'), or None when the text is missing or has no valid inet
    address with a prefix length.

    The caller (route._iface_ipv4) always requests `-f inet:cidr`, so the address carries
    its prefix length inline -- no hex netmask (0xMMMMMMMM) to convert. Text without a
    /NN (an ifconfig that did not honour -f) returns None, and the caller defers."""
    if not ifconfig_text:
        return None
    toks = ifconfig_text.split()
    for i, tok in enumerate(toks):
        if tok == "inet" and i + 1 < len(toks):
            addr, slash, bits = toks[i + 1].partition("/")
            if not slash:
                return None            # not the -f inet:cidr form -> no prefix length
            try:
                prefixlen = int(bits)
                ipaddress.IPv4Address(addr)   # IPv4 only: reject an inet6 slipping through
            except ValueError:
                return None
            return (addr, prefixlen) if 0 <= prefixlen <= 32 else None
    return None
