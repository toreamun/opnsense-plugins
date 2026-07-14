"""Pytest bootstrap: make the plugin's configd scripts importable and stub scapy.

lease_keeper.py imports scapy at module load, but the daemon logic under test
never touches the network, so a lightweight stub lets the suite run without the
dependency (and without root or a live interface). status.py / logparse.py are
plain-stdlib and import directly once their directory is on sys.path.
"""
import importlib.util
import os
import sys
import types
from typing import Any

import pytest

SCRIPT_DIR = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..",
    "src", "opnsense", "scripts", "OPNsense", "CarpVipDhcp"))
sys.path.insert(0, SCRIPT_DIR)

# The canonical test identity (CARP vMAC for vhid 0xfe), shared by the test
# modules so the fixture MAC lives in exactly one place.
CHADDR_STR = "00:00:5e:00:01:fe"
CHADDR = bytes.fromhex(CHADDR_STR.replace(":", ""))


def _stub_scapy():
    if "scapy.all" in sys.modules:
        return
    # Typed Any: module attributes are assigned dynamically below.
    scapy: Any = types.ModuleType("scapy")
    allmod: Any = types.ModuleType("scapy.all")

    class _Sniffer:
        def __init__(self, *_args, **_kwargs):
            self.thread = types.SimpleNamespace(is_alive=lambda: True)

        def start(self):
            """No-op (no capture in unit tests)."""

        def stop(self):
            """No-op."""

    class _Layer:  # pylint: disable=too-few-public-methods
        """Composable no-op protocol layer: Ether(...) / IP(...) / ... works."""
        def __init__(self, *_args, **_kwargs):
            pass

        def __truediv__(self, other):
            return self

    # Distinct subclasses (not one shared class) so haslayer()/p[Layer] identity
    # checks can tell ARP from BOOTP, as they do with the real scapy layers.
    for _name in ("ARP", "Ether", "IP", "UDP", "BOOTP", "DHCP"):
        setattr(allmod, _name, type(_name, (_Layer,), {}))
    allmod.sendp = lambda *a, **k: None
    allmod.AsyncSniffer = _Sniffer
    scapy.all = allmod
    sys.modules["scapy"] = scapy
    sys.modules["scapy.all"] = allmod


_stub_scapy()


def _load(filename, modname):
    path = os.path.join(SCRIPT_DIR, filename)
    spec = importlib.util.spec_from_file_location(modname, path)
    assert spec and spec.loader, path
    module = importlib.util.module_from_spec(spec)
    # Register before exec: dataclasses (and anything else that resolves
    # annotations) looks the module up in sys.modules by __module__.
    sys.modules[modname] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def lk():
    """Facade over the leasekeeper package: every public name from the submodules
    under one namespace, so the tests reach them as lk.* without the daemon
    entry point (../lease_keeper.py) re-exporting its whole API. Also exposes the
    subprocess and time modules the tests monkeypatch. scapy stays stubbed
    (registered above before capture_scapy imports it)."""
    # Imported lazily (inside the fixture) so _stub_scapy() has already run when
    # capture_scapy is first imported -- hence the intentional import-outside-toplevel.
    import subprocess  # pylint: disable=import-outside-toplevel
    import time  # pylint: disable=import-outside-toplevel
    from leasekeeper import (  # pylint: disable=import-outside-toplevel
        capture, capture_bpf, capture_scapy, codec, constants, dhcpclient,
        keeper, policy, util, wire)

    ns = types.SimpleNamespace()
    for mod in (constants, util, wire, codec, capture, capture_scapy,
                capture_bpf, dhcpclient, policy, keeper):
        for name in dir(mod):
            if not name.startswith("__"):
                setattr(ns, name, getattr(mod, name))
    ns.subprocess = subprocess
    ns.time = time
    return ns
