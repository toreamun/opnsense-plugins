"""The CARP-VIP DHCP lease keeper, split into focused modules.

The daemon entry point is ../lease_keeper.py (invoked by the rc.d service); it
wires up and runs the Keeper defined here. Modules, leaf-first:

  constants  -- protocol codes, timing tunables, phase/message-type tables
  util       -- pure helpers (MAC/IP/mask, jitter, atomic write, clock)
  wire       -- neutral BootpFrame/ArpFrame, DhcpReply/DhcpSend, reply parse/format/build
  codec      -- raw wire encode/decode + the embedded BPF filter (bpf backend)
  capture_scapy / capture_bpf -- the two capture backends
  capture    -- the Capture protocol + the backend registry
  dhcpclient -- Lease + the RFC 2131 client (DORA/renew/release)
  policy     -- ArpNudge + FollowPolicy
  keeper     -- Keeper orchestration
"""

# Single source of truth for the plugin version: the Makefile derives
# PLUGIN_VERSION from this line (so the package version and the daemon's own
# reported version can never drift). Keep the assignment on one line as
# __version__ = "X.Y.Z" so the Makefile's sed can read it.
__version__ = "1.10.2"
