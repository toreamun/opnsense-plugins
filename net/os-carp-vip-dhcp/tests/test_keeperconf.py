"""keeperconf.keeper_records: the name-keyed keeper.conf reader.

The format is one line per keeper, pipe-separated KEY=VALUE fields in no fixed
order. These tests pin the robustness that motivated the name-keyed format:
field order does not matter, an unknown key is ignored, a missing key is simply
absent (the caller defaults it), and a line without a request is skipped.
"""
# pylint: disable=missing-function-docstring
import importlib.util
import os
import re

import pytest

_PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_SCRIPT_DIR = os.path.join(
    _PLUGIN_ROOT, "src", "opnsense", "scripts", "OPNsense", "CarpVipDhcp")


def _load_keeperconf():
    path = os.path.join(_SCRIPT_DIR, "keeperconf.py")
    spec = importlib.util.spec_from_file_location("keeperconf", path)
    assert spec and spec.loader, path
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


keeperconf = _load_keeperconf()


def _records(text):
    return list(keeperconf.keeper_records_text(text))


def test_fields_are_keyed_by_name_not_position():
    recs = _records(
        "request=100.64.0.7|iface=eth0|chaddr=00:00:5e:00:01:fe|vhid=254\n")
    assert recs == [{
        "request": "100.64.0.7", "iface": "eth0",
        "chaddr": "00:00:5e:00:01:fe", "vhid": "254"}]


def test_field_order_does_not_matter():
    recs = _records(
        "vhid=254|chaddr=aa|iface=eth0|request=100.64.0.7\n")
    assert recs[0] == {
        "request": "100.64.0.7", "iface": "eth0", "chaddr": "aa", "vhid": "254"}


def test_unknown_key_is_kept_but_harmless_and_missing_key_absent():
    # An added/unknown key round-trips into the dict; a caller reads only the
    # keys it knows and defaults the rest. An empty value stays an empty string.
    recs = _records(
        "request=100.64.0.7|newfield=x|vendorclass=\n")
    assert recs[0]["newfield"] == "x"
    assert recs[0]["vendorclass"] == ""
    assert "arpnudge" not in recs[0]


def test_lines_without_request_and_comments_are_skipped():
    recs = _records(
        "# a comment\n"
        "iface=eth0|chaddr=aa\n"          # no request key -> skipped
        "request=|iface=eth0\n"           # empty request value -> skipped
        "\n"
        "request=100.64.0.7|iface=eth0\n")
    assert [r["request"] for r in recs] == ["100.64.0.7"]


def test_missing_file_yields_nothing(tmp_path):
    # the file-reading wrapper: an absent/unreadable file yields nothing.
    assert not list(keeperconf.keeper_records(str(tmp_path / "absent.conf")))


@pytest.mark.parametrize("raw", ["300:73656372657431", "73656372657431", "60:zz73656372657431",
                                 "60:01,secret:01"])
def test_parse_send_options_errors_never_show_the_value(raw):
    # The daemon logs this message; a Send Option value may hold a credential.
    with pytest.raises(ValueError) as exc:
        keeperconf.parse_send_options(raw)
    assert "7365637265" not in str(exc.value) and "secret" not in str(exc.value)


def test_parse_dhcp_options():
    assert keeperconf.parse_send_options("") == []
    assert keeperconf.parse_send_options("60:7361676d,90:01") == [(60, b"sagm"), (90, b"\x01")]
    assert keeperconf.parse_request_codes("") == []
    assert keeperconf.parse_request_codes("119,6") == [119, 6]
    with pytest.raises(ValueError):
        keeperconf.parse_request_codes("1,abc")


_CID = [(61, bytes.fromhex("0100005e000108"))]


@pytest.mark.parametrize("mode, send_opts, want", [
    ("default", [], None),
    ("default", _CID, None),          # the duplicate is option_problem's to refuse
    ("none", [], None),
    ("none", _CID, "option 61 in Send Options"),
    ("options", _CID, None),
    ("options", [(60, b"acme")], "no option 61 there"),
    ("bogus", [], "unknown Client identifier choice"),
])
def test_client_id_mode_problem(mode, send_opts, want):
    problem = keeperconf.client_id_mode_problem(mode, send_opts)
    assert (problem is None) if want is None else (want in problem)


@pytest.mark.parametrize("args, want", [
    (("", "acme", "mac", []), ("acme", "mac", None)),           # 1.17 form, as before
    (("", "", "", []), (None, None, None)),                     # 1.17 empty: no option 61
    (("default", "", "", []), (None, "mac", None)),
    (("none", "", "", []), (None, None, None)),
    (("options", "", "", _CID), (None, None, None)),            # 61 comes from Send Options
    (("options", "", "", []), (None, None, "no option 61 there")),
    (("bogus", "", "", []), (None, None, "unknown Client identifier choice")),
    (("none", "", "isp-login", []), (None, "isp-login", None)),  # a client-id value wins
])
def test_identity_settings(args, want):
    vendor_class, client_id, problem = keeperconf.identity_settings(*args)
    assert (vendor_class, client_id) == want[:2]
    assert (problem is None) if want[2] is None else (want[2] in problem)


def _read_plugin_file(rel):
    with open(os.path.join(_PLUGIN_ROOT, rel), encoding="utf-8") as f:
        return f.read()


def test_keeper_conf_key_names_agree_across_readers():
    """The keeper.conf key names are hand-duplicated across the template (producer)
    and every reader (the shared shell parser and the Python/PHP readers), which
    have no common source. A rename in one but not the others degrades SILENTLY --
    worst case the shell parser matches nothing, rc.d skips every line and
    lease-keeping stops ("Started 0 keeper(s)"). Pin the contract: every key a
    reader consumes must be one the template emits. Catches the rename-divergence
    class without a Volt/sh runtime (test_reader_conformance runs the shell parser
    for real)."""
    template = _read_plugin_file(
        "src/opnsense/service/templates/OPNsense/CarpVipDhcp/keeper.conf")
    emitted = set(re.findall(r"(\w+)=\{\{", template))
    # Guard the regex itself: the template really does emit the core keys.
    assert {"request", "iface", "chaddr", "defaultroutemode"} <= emitted

    def sh_keys(rel):                       # keeperconf.sh `case` arms: `key=*)`
        return set(re.findall(r"^\s*(\w+)=\*\)", _read_plugin_file(rel), re.MULTILINE))

    def py_get_keys(rel):                   # Python readers: `rec.get("key"...)`
        return set(re.findall(r'rec\.get\("(\w+)"', _read_plugin_file(rel)))

    def php_field_keys(rel):                # PHP readers: `$field` tested against "key="
        # Anchor to the $field comparison so a heartbeat literal like 'bound='
        # elsewhere in the file is not mistaken for a keeper.conf key.
        return set(re.findall(r'\$field\b[^;\n]*?["\'](\w+)=', _read_plugin_file(rel)))

    readers = {
        # The rc.d service and the CARP status hook both source this one parser.
        "keeperconf.sh": sh_keys(
            "src/opnsense/scripts/OPNsense/CarpVipDhcp/keeperconf.sh"),
        "status.py": py_get_keys(
            "src/opnsense/scripts/OPNsense/CarpVipDhcp/status.py"),
        "logparse.py": py_get_keys(
            "src/opnsense/scripts/OPNsense/CarpVipDhcp/logparse.py"),
        "CarpVipDhcpStatus.php": php_field_keys(
            "src/opnsense/mvc/app/library/OPNsense/System/Status/CarpVipDhcpStatus.php"),
        "follow_update.php": php_field_keys(
            "src/opnsense/scripts/OPNsense/CarpVipDhcp/follow_update.php"),
    }
    for name, consumed in readers.items():
        assert consumed, f"{name}: extracted no keys (regex or format drift?)"
        missing = consumed - emitted
        assert not missing, f"{name} consumes keys the template never emits: {sorted(missing)}"
