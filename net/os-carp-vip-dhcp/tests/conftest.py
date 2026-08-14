"""Pytest bootstrap: make the plugin's configd scripts importable.

The daemon is pure Python stdlib over raw /dev/bpf with no third-party imports
at module load, so the suite runs without any dependency, root, or a live
interface. status.py / logparse.py are plain-stdlib and import directly once
their directory is on sys.path.
"""
import importlib.util
import os
import sys
import types

import pytest

SCRIPT_DIR = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..",
    "src", "opnsense", "scripts", "OPNsense", "CarpVipDhcp"))
sys.path.insert(0, SCRIPT_DIR)

# The canonical test identity (CARP vMAC for vhid 0xfe), shared by the test
# modules so the fixture MAC lives in exactly one place.
CHADDR_STR = "00:00:5e:00:01:fe"
CHADDR = bytes.fromhex(CHADDR_STR.replace(":", ""))


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
    subprocess and time modules the tests monkeypatch."""
    # Imported lazily (inside the fixture) so the package loads only when a test
    # needs it, after SCRIPT_DIR is on sys.path -- hence import-outside-toplevel.
    import subprocess  # pylint: disable=import-outside-toplevel
    import time  # pylint: disable=import-outside-toplevel
    from leasekeeper import (  # pylint: disable=import-outside-toplevel
        capture, capture_bpf, codec, constants, dhcpclient,
        keeper, policy, route, util, wire)

    ns = types.SimpleNamespace()
    for mod in (constants, util, wire, codec, capture,
                capture_bpf, dhcpclient, policy, route, keeper):
        for name in dir(mod):
            if not name.startswith("__"):
                setattr(ns, name, getattr(mod, name))
    ns.subprocess = subprocess
    ns.time = time
    return ns
