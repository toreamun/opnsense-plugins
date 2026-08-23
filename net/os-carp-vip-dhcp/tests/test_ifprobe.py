"""Unit tests for ifprobe: parsing ifconfig(8) CARP-role and carrier text.

The one parser both keeper.py (is a vhid master?) and status.py (map every vhid
to its role for the GUI) now share, so their two former parsers cannot drift.
Comments over docstrings.
"""
# pylint: disable=missing-function-docstring
from leasekeeper import ifprobe  # sys.path via conftest  # type: ignore
from leasekeeper.ifprobe import CarpRole


def test_carp_roles_maps_every_vhid():
    # The role token is passed through verbatim (plain str), keyed by vhid.
    text = ("em0: flags\n\tcarp: MASTER vhid 149 advbase 1 advskew 0\n"
            "em1: flags\n\tcarp: BACKUP vhid 20 advbase 1 advskew 100\n"
            "em2: flags\n\tcarp: INIT vhid 30 advbase 1\n")
    assert ifprobe.carp_roles(text) == {"149": "MASTER", "20": "BACKUP", "30": "INIT"}


def test_carp_roles_empty_on_none_blank_or_no_carp():
    assert not ifprobe.carp_roles(None)
    assert not ifprobe.carp_roles("")
    assert not ifprobe.carp_roles("em0: flags\n\tstatus: active\n")   # no carp lines


def test_carp_roles_keeps_a_non_word_role_token_whole():
    # The lossless contract holds for a token with non-word characters too: \S+ keeps
    # it whole rather than truncating (\w+ would stop at the '-' and drop the line).
    assert ifprobe.carp_roles("\tcarp: PRE-INIT vhid 9 advbase 1\n") == {"9": "PRE-INIT"}


def test_carp_roles_keeps_unrecognised_role():
    # An unknown role token is kept verbatim, not dropped, so a VIP never vanishes
    # from the status view (carp(4) only emits INIT/BACKUP/MASTER, but be lossless).
    text = "\tcarp: WOBBLE vhid 7 advbase 1\n\tcarp: MASTER vhid 8 advbase 1\n"
    assert ifprobe.carp_roles(text) == {"7": "WOBBLE", "8": "MASTER"}


def test_carp_roles_tolerates_extra_whitespace():
    assert ifprobe.carp_roles("carp:   MASTER   vhid   5 ") == {"5": "MASTER"}


def test_is_carp_master():
    m = "\tcarp: MASTER vhid 199 advbase 1\n"
    assert ifprobe.is_carp_master(m, "199") is True
    assert ifprobe.is_carp_master(m, 199) is True                 # int vhid coerced
    assert ifprobe.is_carp_master("\tcarp: BACKUP vhid 199\n", "199") is False
    # Populated text, but the requested vhid is not in it -> False (the .get miss
    # path, distinct from the empty-text short-circuit below).
    assert ifprobe.is_carp_master("\tcarp: MASTER vhid 5 advbase 1\n", "199") is False
    assert ifprobe.is_carp_master("", "199") is False             # empty text present
    assert ifprobe.is_carp_master(None, "199") is None            # probe failed


def test_is_carp_master_matches_vhid_exactly():
    # 199 must never read as 19 or 1990 (the whole number is captured, not a prefix),
    # and a trailing non-digit must not let "199x" read as vhid 199 (\b bounds it).
    assert ifprobe.is_carp_master("carp: MASTER vhid 19 advbase 1\n", "199") is False
    assert ifprobe.is_carp_master("carp: MASTER vhid 1990 advbase 1\n", "199") is False
    assert ifprobe.is_carp_master("carp: MASTER vhid 199x advbase 1\n", "199") is False


def test_carrier_up():
    assert ifprobe.carrier_up("igc0: flags\n\tstatus: active\n") is True
    assert ifprobe.carrier_up("igc0: flags\n\tstatus: no carrier\n") is False
    assert ifprobe.carrier_up("igc0: flags\n\t(no status line)\n") is None   # no status line
    assert ifprobe.carrier_up(None) is None                                  # probe failed


def test_iface_ipv4():
    # `ifconfig -f inet:cidr` prints the prefix inline; /24 plus /30 and /31 (the
    # backup-egress peer-derivation cases) all parse.
    assert ifprobe.iface_ipv4(
        "\tinet 100.64.4.7/24 broadcast 100.64.4.255\n") == ("100.64.4.7", 24)
    assert ifprobe.iface_ipv4("\tinet 10.0.0.2/30\n") == ("10.0.0.2", 30)
    assert ifprobe.iface_ipv4("\tinet 10.0.0.2/31\n") == ("10.0.0.2", 31)


def test_iface_ipv4_none_cases():
    assert ifprobe.iface_ipv4(None) is None
    assert ifprobe.iface_ipv4("") is None
    assert ifprobe.iface_ipv4("igc0: flags\n\tstatus: active\n") is None       # no inet
    assert ifprobe.iface_ipv4("\tinet 100.64.4.7\n") is None                   # no /NN (not -f cidr)
    assert ifprobe.iface_ipv4("\tinet nope/24\n") is None                      # bad address
    assert ifprobe.iface_ipv4("\tinet 100.64.4.7/33\n") is None                # prefix out of range
    assert ifprobe.iface_ipv4("\tinet 100.64.4.7/xx\n") is None                # bad prefix
    assert ifprobe.iface_ipv4("\tinet 2001:db8::1/32\n") is None               # IPv6 rejected


def test_carp_role_values_are_the_ifconfig_tokens():
    # .value is what status.py puts on the wire (JSON); keep it the exact token.
    assert CarpRole.MASTER.value == "MASTER"
    assert CarpRole.BACKUP.value == "BACKUP"
    assert CarpRole.INIT.value == "INIT"
