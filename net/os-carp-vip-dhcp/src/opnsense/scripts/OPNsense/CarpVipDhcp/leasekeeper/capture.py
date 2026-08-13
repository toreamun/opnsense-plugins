"""The capture-backend contract.

Only the dependency-free raw /dev/bpf backend (capture_bpf.BpfCapture) exists;
the Capture protocol is the seam a second backend would implement, kept so the
keeper is typed against the shape it drives rather than a concrete class.
"""
from typing import Any, Callable, Protocol

from .wire import DhcpSend


class Capture(Protocol):
    """The structural interface a capture backend satisfies: constructed with
    the interface, a promiscuous flag and the two neutral-frame callbacks, then
    driven by the keeper (start/stop/alive + the two send methods), with a
    static availability probe main() checks before starting. Typing the keeper's
    backend against this catches an implementation that drifts from the shape it
    drives."""
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
