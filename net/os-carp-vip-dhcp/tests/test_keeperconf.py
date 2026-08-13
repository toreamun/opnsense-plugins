"""keeperconf.keeper_records: the name-keyed keeper.conf reader.

The format is one line per keeper, pipe-separated KEY=VALUE fields in no fixed
order. These tests pin the robustness that motivated the name-keyed format:
field order does not matter, an unknown key is ignored, a missing key is simply
absent (the caller defaults it), and a line without a request is skipped.
"""
import importlib.util
import os
import re

_PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_SCRIPT_DIR = os.path.join(
    _PLUGIN_ROOT, "src", "opnsense", "scripts", "OPNsense", "CarpVipDhcp")


def _load_keeperconf():
    path = os.path.join(_SCRIPT_DIR, "keeperconf.py")
    spec = importlib.util.spec_from_file_location("keeperconf", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


keeperconf = _load_keeperconf()


def _records(tmp_path, text):
    conf = tmp_path / "keeper.conf"
    conf.write_text(text)
    return list(keeperconf.keeper_records(str(conf)))


def test_fields_are_keyed_by_name_not_position(tmp_path):
    recs = _records(
        tmp_path,
        "request=100.64.0.7|iface=eth0|chaddr=00:00:5e:00:01:fe|vhid=254\n")
    assert recs == [{
        "request": "100.64.0.7", "iface": "eth0",
        "chaddr": "00:00:5e:00:01:fe", "vhid": "254"}]


def test_field_order_does_not_matter(tmp_path):
    recs = _records(
        tmp_path,
        "vhid=254|chaddr=aa|iface=eth0|request=100.64.0.7\n")
    assert recs[0] == {
        "request": "100.64.0.7", "iface": "eth0", "chaddr": "aa", "vhid": "254"}


def test_unknown_key_is_kept_but_harmless_and_missing_key_absent(tmp_path):
    # An added/unknown key round-trips into the dict; a caller reads only the
    # keys it knows and defaults the rest. An empty value stays an empty string.
    recs = _records(
        tmp_path,
        "request=100.64.0.7|newfield=x|vendorclass=\n")
    assert recs[0]["newfield"] == "x"
    assert recs[0]["vendorclass"] == ""
    assert "arpnudge" not in recs[0]


def test_lines_without_request_and_comments_are_skipped(tmp_path):
    recs = _records(
        tmp_path,
        "# a comment\n"
        "iface=eth0|chaddr=aa\n"          # no request key -> skipped
        "request=|iface=eth0\n"           # empty request value -> skipped
        "\n"
        "request=100.64.0.7|iface=eth0\n")
    assert [r["request"] for r in recs] == ["100.64.0.7"]


def test_missing_file_yields_nothing(tmp_path):
    assert list(keeperconf.keeper_records(str(tmp_path / "absent.conf"))) == []


def _read_plugin_file(rel):
    with open(os.path.join(_PLUGIN_ROOT, rel), encoding="utf-8") as f:
        return f.read()


def test_keeper_conf_key_names_agree_across_readers():
    """The keeper.conf key names are hand-duplicated across the template (producer)
    and every reader (the two sh scripts and the Python readers), which have no
    shared source. A rename in one but not the others degrades SILENTLY -- worst
    case rc.d skips every line and lease-keeping stops ("Started 0 keeper(s)").
    Pin the contract: every key a reader consumes must be one the template emits.
    Catches the rename-divergence class without a Volt/sh runtime."""
    template = _read_plugin_file(
        "src/opnsense/service/templates/OPNsense/CarpVipDhcp/keeper.conf")
    emitted = set(re.findall(r"(\w+)=\{\{", template))
    # Guard the regex itself: the template really does emit the core keys.
    assert {"request", "iface", "chaddr", "defaultroutemode"} <= emitted

    def sh_keys(rel):                       # rc.d/hook `case` arms: `key=*)`
        return set(re.findall(r"^\s*(\w+)=\*\)", _read_plugin_file(rel), re.MULTILINE))

    def py_get_keys(rel):                   # Python readers: `rec.get("key"...)`
        return set(re.findall(r'rec\.get\("(\w+)"', _read_plugin_file(rel)))

    def php_field_keys(rel):                # PHP readers: `$field` tested against "key="
        # Anchor to the $field comparison so a heartbeat literal like 'bound='
        # elsewhere in the file is not mistaken for a keeper.conf key.
        return set(re.findall(r'\$field\b[^;\n]*?["\'](\w+)=', _read_plugin_file(rel)))

    readers = {
        "rc.d": sh_keys("src/etc/rc.d/carpvipdhcp"),
        "carp-hook": sh_keys("src/etc/rc.carp_service_status.d/carpvipdhcp"),
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
