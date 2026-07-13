"""The CARP-VIP DHCP lease keeper, split into focused modules.

The daemon entry point is ../lease_keeper.py (invoked by the rc.d service); it
wires up and runs the Keeper defined here. Modules, leaf-first:

  constants  -- protocol codes, timing tunables, phase/message-type tables
  util       -- pure helpers (MAC/IP/mask, jitter, atomic write, clock)
  wire       -- neutral BootpFrame/ArpFrame, DhcpReply, reply parse/format
  codec      -- raw wire encode/decode + the embedded BPF filter (bpf backend)
  capture_scapy / capture_bpf -- the two capture backends
  capture    -- the backend registry
  dhcpclient -- Lease + the RFC 2131 client (DORA/renew/release)
  policy     -- ArpNudge + FollowPolicy
  keeper     -- Keeper orchestration
"""
