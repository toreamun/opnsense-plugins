"""The capture-backend registry: flag value -> implementation.

The daemon's --capture-backend choices and the Keeper's lookup both read this,
so a future backend is added in exactly one place (plus its rc.conf docs).
"""
from typing import Any, Callable, Protocol

from .capture_bpf import BpfCapture
from .capture_scapy import ScapyCapture
from .wire import DhcpSend


class Capture(Protocol):
    """The structural interface both capture backends satisfy: constructed with
    the interface, a promiscuous flag and the two neutral-frame callbacks, then
    driven by the keeper (start/stop/alive + the two send methods), with a
    static availability probe main() checks before starting. Typing the registry
    against this catches a backend that drifts from the shape the keeper drives."""
    # Interface stubs: the class docstring documents the contract.
    # pylint: disable=missing-function-docstring

    def __init__(self, iface: str, promisc: bool,
                 on_bootp: "Callable[[Any], None]", on_arp: "Callable[[Any], None]") -> None: ...

    @staticmethod
    def unavailable_reason() -> "str | None": ...

    def start(self) -> bool: ...

    def stop(self) -> None: ...

    def alive(self) -> bool: ...

    def send_dhcp(self, msg: DhcpSend) -> None: ...

    def send_arp_request(self, hwsrc, psrc, pdst) -> None: ...


CAPTURE_BACKENDS: "dict[str, type[Capture]]" = {"scapy": ScapyCapture, "bpf": BpfCapture}
