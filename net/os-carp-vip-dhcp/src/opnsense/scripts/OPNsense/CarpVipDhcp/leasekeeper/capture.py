"""The capture-backend contract.

Only the dependency-free raw /dev/bpf backend (capture_bpf.BpfCapture) exists;
the Capture protocol is the seam a second backend would implement, kept so the
keeper is typed against the shape it drives rather than a concrete class.
"""
from typing import Protocol

from .wire import DhcpSend


class Capture(Protocol):
    """The interface a capture backend satisfies once constructed (with the
    interface, a promiscuous flag, the two neutral-frame callbacks and a VLAN
    priority): the keeper drives it via start/stop/alive and the two send methods,
    and main() probes the static availability check before starting. The keeper
    also reads vlan_pcp_error (why the VLAN priority could not be set at the last
    start, or None) for its heartbeat. Typing the keeper's
    backend against this catches an implementation that drifts from the shape it
    drives. Construction is not part of the protocol (nothing builds a backend
    through it), so an untyped backend __init__ does not have to match here."""
    # Interface stubs: the class docstring documents the contract.
    # pylint: disable=missing-function-docstring

    vlan_pcp_error: "str | None"

    @staticmethod
    def unavailable_reason() -> "str | None": ...

    def start(self) -> bool: ...

    def stop(self) -> None: ...

    def alive(self) -> bool: ...

    def send_dhcp(self, msg: DhcpSend) -> None: ...

    def send_arp_request(self, hwsrc, psrc, pdst) -> None: ...
