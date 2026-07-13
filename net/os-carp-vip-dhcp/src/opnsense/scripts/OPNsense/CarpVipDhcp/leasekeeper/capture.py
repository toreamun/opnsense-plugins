"""The capture-backend registry: flag value -> implementation.

The daemon's --capture-backend choices and the Keeper's lookup both read this,
so a future backend is added in exactly one place (plus its rc.conf docs).
"""
from .capture_bpf import BpfCapture
from .capture_scapy import ScapyCapture

CAPTURE_BACKENDS = {"scapy": ScapyCapture, "bpf": BpfCapture}
