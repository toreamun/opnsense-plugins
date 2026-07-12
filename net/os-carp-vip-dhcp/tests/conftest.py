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
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def lk():
    """The lease_keeper daemon module (loaded via importlib so scapy stays stubbed)."""
    return _load("lease_keeper.py", "lease_keeper")
