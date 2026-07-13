# lease_keeper.py -> leasekeeper/ package split (planned refactor)

Branch `module-split`, off `bpf-backend`. Lands as its own PR **after** the bpf
backend merges; then rebased onto main. Pure structural move -- no behaviour
change, no version bump. Verified the same way as any change: 123 unit tests,
flake8, pylint 10/10, pyright 0, then the fake-bench suites.

## Why

`lease_keeper.py` is ~2225 lines and carries 11 `too-many-*` pragmas that are
symptoms of everything living in one module. The components are already cleanly
separated; this move makes the file boundaries match them, isolates the risky
hand-rolled raw code in one place, and quarantines the scapy dependency so
dropping it later is a file deletion. Several `too-many-*` pragmas fall away.

## Layout

Entry points invoked by path (rc.d / configd / controllers) stay at top level;
the daemon's internals move into a `leasekeeper/` package. `status.py`,
`logparse.py`, `keeperconf.py` are unchanged.

```
scripts/OPNsense/CarpVipDhcp/
  lease_keeper.py          # thin entry: docstring, arg parsing, logging, signals, main()
  leasekeeper/
    __init__.py            # empty (package marker)
    constants.py           # message types, PRL, timing tunables, ETHER_*/ports, PHASE_*, MTYPE_NAMES
    util.py                # mac2raw, _sane_ipv4, _is_localish, _same_ip_class, _fs_safe,
                           #   _new_xid, _jittered, _atomic_write, _clock_at, _mask_to_bits, MAC_RE, _CGNAT
    wire.py                # BootpFrame, ArpFrame, DhcpReply, _parse_reply, _dhcp_options,
                           #   _msg_text, _fmt_reply, SNIFFER_FILTER
    codec.py               # raw encode/decode (the hand-rolled wire codec) + BPF filter table + _bpf_frames
    capture.py             # _deliver + CAPTURE_BACKENDS registry
    capture_scapy.py       # scapy import guard + ScapyCapture
    capture_bpf.py         # fcntl import guard + BpfCapture (uses codec)
    dhcpclient.py          # Lease + DhcpClient
    policy.py              # ArpNudge + FollowPolicy
    keeper.py              # Keeper + _identity_options
```

## Dependency order (leaves first; no cycles)

`constants` -> `util` -> `wire` -> `codec` -> {`capture_scapy`, `capture_bpf`}
-> `capture` -> {`dhcpclient`, `policy`} -> `keeper` -> `lease_keeper`.

- `LOG` is re-obtained per module with `logging.getLogger("lease-keeper")` (same
  instance by name -- no shared import needed).
- Each optional dependency's import guard lives with its backend:
  `capture_scapy.py` owns the scapy try/except, `capture_bpf.py` owns fcntl.
- Internal imports are relative (`from .wire import BootpFrame`) so they do not
  depend on sys.path ordering.

## Source line map (current HEAD, for the carve)

- imports 58-75; fcntl guard 81-94 -> capture_bpf; scapy guard 96-106 -> capture_scapy
- LOG 108
- constants 110-156; PHASE_* 188-192; MTYPE_NAMES 195-196 -> constants.py
- DhcpReply/BootpFrame/ArpFrame 169-185; _msg_text 199; _fmt_reply 214;
  _parse_reply 227; _dhcp_options 256; SNIFFER_FILTER 281 -> wire.py
- _mask_to_bits 264; MAC_RE 273; _CGNAT 276; _sane_ipv4 906; _is_localish 918;
  _same_ip_class 926; _fs_safe 936; _new_xid 942; _jittered 948; mac2raw 958;
  _atomic_write 963; _clock_at 971 -> util.py
- raw codec 289-511 (_ip4 .. _decode_ipv4_bootp); BPF plumbing 515-589
  (BIOC*, _BPF_FILTER, _bpf_align, _bpf_frames) -> codec.py
- _deliver 596; CAPTURE_BACKENDS 903 -> capture.py
- ScapyCapture 608-702 -> capture_scapy.py
- BpfCapture 704-901 -> capture_bpf.py
- Lease 978; DhcpClient 995-1309 -> dhcpclient.py
- ArpNudge 1311; FollowPolicy 1396-1581 -> policy.py
- Keeper 1583; _identity_options 2057-2071 -> keeper.py
- acquire_pidfile 2073; _build_arg_parser 2103; _setup_logging 2134;
  _claim_once 2151; main 2165-end -> lease_keeper.py (thin)

## Test + packaging follow-ups

- `tests/conftest.py`: put the package dir on sys.path (already inserts
  SCRIPT_DIR), stub scapy before importing `leasekeeper.capture_scapy`, and load
  modules as `leasekeeper.*`. `test_codec.py` imports the codec from
  `leasekeeper.codec` (or a re-export), `test_daemon.py` from `leasekeeper.keeper`.
- Testbench JIT-deploy: fetch the package dir (mkdir -p leasekeeper + the module
  files) instead of one file; content-gate each. rc.d still runs lease_keeper.py.
- Makefile/plist: nested files under src/ are packaged automatically.

## Execution

Carve leaf-first, running the unit-test battery after each module is extracted,
so there is never a big-bang broken state; only advance when green.
