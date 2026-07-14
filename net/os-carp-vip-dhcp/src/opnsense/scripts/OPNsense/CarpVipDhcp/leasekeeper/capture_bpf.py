"""The raw /dev/bpf capture backend: no packet library, FreeBSD only.

fcntl (for the ioctls) is imported defensively so the module still loads on
non-POSIX dev hosts; BpfCapture.start() reports the missing module at runtime.
"""
import ctypes
import logging
import os
import select
import struct
import threading
from typing import Any

from .constants import (
    DHCP_CLIENT_PORT, DHCP_SERVER_PORT, ETHER_BROADCAST, THREAD_JOIN_TIMEOUT)
from .codec import (BIOCGBLEN, BIOCGDLT, BIOCIMMEDIATE, BIOCPROMISC, BIOCSETF,
                    BIOCSETIF, BIOCSHDRCMPLT, DLT_EN10MB, ETHERTYPE_ARP,
                    ETHERTYPE_IPV4, ETHER_MIN_FRAME, _BPF_FILTER, _bpf_frames,
                    _decode_arp, _decode_ipv4_bootp, _encode_arp_request,
                    _encode_bootp_request, _encode_ether, _encode_ipv4_udp)
from .wire import _deliver

LOG = logging.getLogger("lease-keeper")

# Daemon log-and-continue posture: broad catch-alls are deliberate (see the
# package docstring / module docstrings).
# pylint: disable=broad-exception-caught


# The raw /dev/bpf backend drives its ioctls through fcntl, which does not
# exist on non-POSIX development hosts. Import it defensively (same pattern as
# scapy below) so the module still loads there; BpfCapture.start() reports the
# missing module at runtime instead.
try:
    import fcntl as _fcntl_module
    # Typed Any: the POSIX-only stubs would flag every ioctl call on the
    # non-POSIX hosts this guard exists for.
    fcntl: Any = _fcntl_module
except ImportError:
    fcntl = None  # pylint: disable=invalid-name


class BpfCapture:  # pylint: disable=too-many-instance-attributes
    """Capture/send on a raw /dev/bpf descriptor -- no packet library. A
    reader thread walks the BPF buffer and hands decoded neutral frames to
    the same callbacks the scapy backend feeds. FreeBSD-only (OPNsense's
    platform); selected with --capture-backend bpf (experimental).

    Shutdown uses a self-pipe rather than a poll timeout: the reader blocks in
    select() on both the bpf fd and a wake pipe, and stop() writes one byte to
    the pipe so the reader returns at once (no periodic wakeups, no up-to-1s
    stop latency). The stop signal and the wake pipe are created fresh per
    start(), and the reader owns and closes its own bpf fd on exit, so a reader
    that outlives its stop() (e.g. stalled in a slow log write) can neither be
    revived by the next start() nor have its fd number reused underneath it."""

    def __init__(self, iface, promisc, on_bootp, on_arp):
        self.iface = iface
        self.promisc = promisc
        self._on_bootp = on_bootp
        self._on_arp = on_arp
        self._fd = None                # the live capture fd, or None when stopped
        self._buflen = 0               # kernel buffer size, from BIOCGBLEN in _configure
        self._thread = None            # the current reader thread
        self._stop_event = None        # set to ask the current reader to exit
        self._wake_writer = None       # write end of this generation's wake pipe

    def start(self):
        """(Re)open /dev/bpf, bind + filter it to the interface, and start the
        reader thread. Returns False on any failure (the caller retries)."""
        if fcntl is None:
            LOG.error("bpf backend unavailable: no fcntl module on this platform")
            return False
        self.stop()
        wake_reader, wake_writer = os.pipe()
        try:
            fd = os.open("/dev/bpf", os.O_RDWR)
        except OSError as e:
            os.close(wake_reader)
            os.close(wake_writer)
            LOG.error("bpf capture start failed on %s: %s", self.iface, e)
            return False
        try:
            self._configure(fd)
        except Exception as e:
            os.close(fd)
            os.close(wake_reader)
            os.close(wake_writer)
            LOG.error("bpf capture start failed on %s: %s", self.iface, e)
            return False
        stop_event = threading.Event()
        # The reader owns fd and wake_reader and closes them when it exits.
        self._thread = threading.Thread(
            target=self._read_loop, args=(fd, wake_reader, stop_event),
            name="bpf-capture", daemon=True)
        self._fd = fd
        self._stop_event = stop_event
        self._wake_writer = wake_writer
        self._thread.start()
        return True

    def _configure(self, fd):
        """Bind, tune and filter a fresh bpf descriptor.

        BIOCSETIF (bind) has to come first -- it is what libpcap does and what
        BIOCGDLT needs -- so the filter is attached immediately after, keeping
        the window in which the descriptor would accept unfiltered traffic to a
        single ioctl."""
        fcntl.ioctl(fd, BIOCSETIF, struct.pack("16s16x", self.iface.encode()))
        # The codec's frame offsets assume Ethernet; a PPPoE/tun WAN would make
        # both capture and injection meaningless. Fail loudly instead of leaving
        # only a "no DHCP OFFER" symptom.
        dlt = struct.unpack("I", fcntl.ioctl(fd, BIOCGDLT, b"\x00" * 4))[0]
        if dlt != DLT_EN10MB:
            raise OSError(f"{self.iface} is not Ethernet (bpf data-link type {dlt}); "
                          "the bpf backend supports Ethernet only")
        # Attach the capture filter right after the bind (and before the rest of
        # the tuning) so almost no unfiltered traffic can enter the buffer.
        program = b"".join(struct.pack("HBBI", *insn) for insn in _BPF_FILTER)
        program_buf = ctypes.create_string_buffer(program)   # kernel copies it during the ioctl
        # struct bpf_program is { u_int bf_len; struct bpf_insn *bf_insns; };
        # "@IQ" gives the native u_int + pointer layout on LP64.
        fcntl.ioctl(fd, BIOCSETF,
                    struct.pack("@IQ", len(_BPF_FILTER), ctypes.addressof(program_buf)))
        # Immediate mode: hand packets over as they arrive; the DHCP exchanges
        # wait on second-scale timeouts, so buffering a full block is not an option.
        fcntl.ioctl(fd, BIOCIMMEDIATE, struct.pack("I", 1))
        # Header-complete: our frames carry the CARP vMAC as the Ethernet source;
        # without this the kernel would overwrite it with the NIC's own MAC.
        fcntl.ioctl(fd, BIOCSHDRCMPLT, struct.pack("I", 1))
        if self.promisc:
            fcntl.ioctl(fd, BIOCPROMISC)
        # bpf read(2) calls must request exactly the kernel buffer size.
        self._buflen = struct.unpack("I", fcntl.ioctl(fd, BIOCGBLEN, b"\x00" * 4))[0]

    def stop(self):
        """Ask the current reader to exit and wait briefly for it. The reader
        closes its own fd, so stop() only signals and joins; a reader still
        alive after the join (stuck in a slow callback) is left to exit on its
        own -- it holds its own fd, so nothing here can be reused under it."""
        thread = self._thread
        stop_event = self._stop_event
        wake_writer = self._wake_writer
        self._fd = None
        self._thread = None
        self._stop_event = None
        self._wake_writer = None

        if stop_event is not None:
            stop_event.set()
        if wake_writer is not None:
            try:
                os.write(wake_writer, b"\x00")   # wake the reader's select() at once
            except OSError:
                pass
            try:
                os.close(wake_writer)
            except OSError:
                pass
        if thread is not None and thread.is_alive():
            thread.join(timeout=THREAD_JOIN_TIMEOUT)
            if thread.is_alive():
                LOG.warning("bpf reader did not exit within 2s -- leaving it to "
                            "finish; its fd is not reused")

    def alive(self):
        """True while the descriptor is open and the reader thread runs."""
        return self._fd is not None and self._thread is not None and self._thread.is_alive()

    def _read_loop(self, fd, wake_reader, stop_event):
        """Reader thread: block in select() on the bpf fd and the wake pipe;
        stop() writes to the pipe to end the wait. Owns fd and wake_reader and
        closes both on exit, so the fd's lifetime ends exactly when this thread
        does."""
        try:
            while not stop_event.is_set():
                try:
                    readable, _, _ = select.select([fd, wake_reader], [], [])
                except OSError:
                    return
                if wake_reader in readable:      # stop() rang -- loop condition ends us
                    continue
                try:
                    data = os.read(fd, self._buflen)
                except (OSError, ValueError):
                    if not stop_event.is_set():
                        LOG.warning("bpf read failed -- capture thread exiting")
                    return
                for frame in _bpf_frames(data):
                    self._dispatch(frame)
        finally:
            for owned_fd in (fd, wake_reader):
                try:
                    os.close(owned_fd)
                except OSError:
                    pass

    def _dispatch(self, frame):
        """Decode one captured Ethernet frame and route it by ethertype to the
        keeper callback (via _deliver, so a handler failure is labelled as
        such). A parse error in the untrusted input is dropped (debug-logged)."""
        decoded = None
        handler = None
        try:
            if len(frame) >= 14:
                ethertype = int.from_bytes(frame[12:14], "big")
                if ethertype == ETHERTYPE_ARP:
                    decoded, handler = _decode_arp(frame[14:]), self._on_arp
                elif ethertype == ETHERTYPE_IPV4:
                    decoded, handler = _decode_ipv4_bootp(frame[14:]), self._on_bootp
        except Exception as e:
            LOG.debug("bpf frame parse error: %s", e)
            return
        _deliver(handler, decoded)

    def _write(self, frame):
        """Inject one raw Ethernet frame on the interface. Main-thread only (the
        capture thread never sends), so reading self._fd needs no lock."""
        fd = self._fd
        if fd is None:
            raise OSError("bpf capture not started")
        os.write(fd, frame)

    # The DHCP wire tuple: one parameter per field that goes on the wire.
    def send_dhcp(self, *, eth_src, ip_src, ip_dst, chaddr,  # pylint: disable=too-many-arguments
                  xid, ciaddr, flags, options):
        """Broadcast one DHCP client message as raw encoded frames."""
        payload = _encode_bootp_request(chaddr, xid, ciaddr, flags, options)
        dgram = _encode_ipv4_udp(ip_src, ip_dst, DHCP_CLIENT_PORT, DHCP_SERVER_PORT, payload)
        self._write(_encode_ether(ETHER_BROADCAST, eth_src, ETHERTYPE_IPV4, dgram))

    def send_arp_request(self, hwsrc, psrc, pdst):
        """Broadcast an ARP who-has pdst tell psrc from hwsrc."""
        frame = _encode_ether(ETHER_BROADCAST, hwsrc, ETHERTYPE_ARP,
                              _encode_arp_request(hwsrc, psrc, pdst))
        self._write(frame.ljust(ETHER_MIN_FRAME, b"\x00"))   # runt guard: ARP is 42 bytes bare


# The capture-backend registry: flag value -> implementation. The argparse
# choices and Keeper's lookup both read this, so a future backend is added in
