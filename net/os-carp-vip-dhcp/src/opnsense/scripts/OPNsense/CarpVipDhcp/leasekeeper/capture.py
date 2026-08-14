"""The capture-backend contract.

Only the dependency-free raw /dev/bpf backend (capture_bpf.BpfCapture) exists;
the Capture protocol is the seam a second backend would implement, kept so the
keeper is typed against the shape it drives rather than a concrete class.
"""
from typing import Protocol

from .wire import DhcpSend


class Capture(Protocol):
    """The interface a capture backend satisfies once constructed (with the
    interface, a promiscuous flag and the two neutral-frame callbacks): the
    keeper drives it via start/stop/alive and the two send methods, and main()
    probes the static availability check before starting. Typing the keeper's
    backend against this catches an implementation that drifts from the shape it
    drives. Construction is not part of the protocol (nothing builds a backend
    through it), so an untyped backend __init__ does not have to match here."""
    # Interface stubs: the class docstring documents the contract.
    # pylint: disable=missing-function-docstring

    @staticmethod
    def unavailable_reason() -> "str | None": ...

    def start(self) -> bool: ...

    def stop(self) -> None: ...

    def alive(self) -> bool: ...

    def send_dhcp(self, msg: DhcpSend) -> None: ...

    def send_arp_request(self, hwsrc, psrc, pdst) -> None: ...
