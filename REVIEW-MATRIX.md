# Duty matrix review

A diff review reads the lines that changed. It misses the lines that should have changed and
did not: a wait loop that skips a duty the other loops run, a state that never sends a signal
the other states send. The duty matrix catches that class. It is review gate 9 in
[RELEASE.md](RELEASE.md).

Example: the REBIND loop in the keeper refreshed the heartbeat and polled the CARP role, but
never ran the ARP nudge or the follow watchdog. Its comment said it did "exactly as
`_hold_lease` does". A master stuck in REBIND for hours sent no nudges (#128, fixed in #140).
Row R2 of the matrix below would have shown the empty cells.

## The method

1. **Rows: every state or wait** the component can sit in. Find them in the code, not in the
   docs: every loop, every sleep, every blocking call. A row is "where can time pass here?".
2. **Columns: every duty** that must happen while time passes, and every rule that must
   hold, for example "never transmit on a backup".
3. **Write down what each cell should be before reading the code.** The reference is the
   intended behaviour: the RFC, the docs, the design. Neither the comments nor the code are
   the reference: both can be wrong, and they can be wrong the same way.
4. **Then fill each cell from what the code does**, with the function that does it. Allowed
   values:
   - **yes** with where (`_maintenance_tick`, loop head, ...);
   - **no, on purpose** with the reason, and that reason is also a comment at the site;
   - **n/a** with why the duty cannot apply (no lease, no binding);
   - **gap**: an empty cell with no reason. A gap is a bug or an open question, never a
     pass.
   A cell where the code differs from step 3 is a finding, whatever the comment says.
5. **Trust no claim, in a comment or in a reviewer's reading.** A comment that says "as X
   does" or "the same as" is checked against X, cell by cell. Where comment and code disagree,
   decide from step 3 which is wrong; it may be both. A cell filled by reading the code is
   still a claim: mark which cells a test or a live run confirms (**T** below) and treat the
   rest as read only.
6. **Keep one source per duty.** When several rows need the same duties, they call one shared
   function (the keeper's `_maintenance_tick`), and a row that skips a duty says so with an
   explicit argument (`pulse=False`), not by leaving a line out.
7. **Test the negative rows.** A row only the failure paths reach (REBIND, no carrier, a
   config error) gets a test that drives it, ideally through the real loop on a fake clock,
   and a bench case where the DHCP server ignores the client.

### When to use it

- Any change to a loop, a sleep, a state or a duty in a component listed below.
- Adding a duty (fill its column for every row) or a state (fill its row for every column).
- Before a release (gate 9): re-check the cells the release touched, and any row marked gap.
- As a periodic full review, given to a reviewer without the diff: "find the cells that are
  gaps".

## Keeper (`leasekeeper/keeper.py`)

State of the code after #140 (1.19.1), filled by reading the code. Rows are the places the
daemon waits; the loop head is `_maintain_step`, which every row except R6 and R7 returns to
after each transition. **T** marks a cell a test in `tests/test_daemon.py` drives through the
real loop; every other cell is read only and still needs a test or a bench run.

### Rows

| Row | State | Where time passes |
|---|---|---|
| R1 | Bound master, waiting for T1 | `_hold_lease`: `_sleep_interruptible` (30 s chunks), then `_maintenance_tick()` |
| R2 | Bound master, RENEW failed, REBIND until T2 | `_renew_bound_lease` loop: `_sleep_interruptible` (~10 s, jittered), then `_maintenance_tick(pulse=False)` |
| R3 | Passive backup | `_passive_backup_step`: `_maintenance_tick(master=False)`, then `_sleep_interruptible(30, poll_link=False)` |
| R4 | Configuration error (any role) | `_config_error_step`: `_maintenance_tick(master=role)`, then `_sleep_interruptible(30, poll_link=False)` |
| R5 | Unbound master or unknown role: acquire and backoff | loop head, `_acquire_step` (DORA, then `_wait_unbound` backoff 10 to 45 s) |
| R6 | Unexpected error in the main loop | `run()`: `_hb()`, then `_sleep(10)` |
| R7 | Startup, capture not yet open | `run()`: `_sleep(5)` until the capture starts |

### Duties and rules

| Column | Duty or rule |
|---|---|
| D1 | Heartbeat refreshed (the CARP hook and the banner judge its age) |
| D2 | CARP role polled, with promotion and demotion side effects (`_role.poll`) |
| D3 | Lease MAC rewrite reconciled (`_vmac.reconcile`) |
| D4 | Default route and backup egress reconciled |
| D5 | Follow watchdog (re-drive a stalled follow) |
| D6 | Peer ACK observation handled (`_follow.check_observed`) |
| D7 | Periodic ARP nudge to the gateway |
| D8 | Hourly "lease healthy" line |
| D9 | Stop, SIGUSR1 (manual nudge) and SIGUSR2 (role re-check) handled within about 1 s |
| D10 | DHCP transmit: when, and never on a confirmed backup |
| D11 | Link-return poll (re-acquire at once when the carrier comes back) |

### Matrix

| | D1 | D2 | D3 | D4 | D5 | D6 | D7 | D8 | D9 | D10 | D11 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| R1 | yes, tick | yes, tick | yes, tick | yes, tick **T** | yes, tick | yes, sleep | yes, tick | yes, tick | yes, sleep | RENEW at T1, or at once after a promotion; not if demoted during the wait | n/a, bound |
| R2 | yes, tick | yes, tick | yes, tick | yes, tick **T** | yes, tick **T** | yes, sleep | yes, tick **T** | no, on purpose: the lease is not healthy **T** | yes, sleep | REBIND each step until the T2 deadline (wall time) while the role is not backup; an unreadable probe keeps the last known role **T** | n/a, bound |
| R3 | yes, tick | yes, tick and loop head | yes, loop head | yes, tick | yes, tick | yes, sleep | no, on purpose: backup (gated in the nudge) **T** | silent: no held lease | yes, sleep | never **T** | no, on purpose: a backup cannot act on it |
| R4 | yes, tick | yes, tick and loop head | yes, loop head | yes, tick | yes, tick | yes, sleep | gated in the nudge: needs a lease and master | silent unless a lease is held | yes, sleep | never | no, on purpose |
| R5 | yes, each acquire step | yes, loop head | yes, loop head **T** | backup egress before the acquire, default withdrawn after a failed one **T** | gap, see Q1 | yes, backoff sleep | n/a until bound; one forced nudge on BOUND | n/a | yes during backoff; not during a DORA exchange | DORA while master or role unknown (fail-safe) | yes **T** |
| R6 | yes, once | no | no | no | no | no | no | no | stop only | no | no |
| R7 | no, see Q2 | no | no | no | no | no | no | no | stop only | no | no |

### Open questions

Cells marked gap, or rows not yet checked end to end. Each is a question, not a known bug.

- **Q1 (R5, D5):** the follow watchdog does not run while unbound. A follow fires only from a
  bound lease, and a successful follow restarts the keeper; check whether a lease lost after a
  follow fired, but before it applied, can leave the follow never re-driven.
- **Q2 (R7, D1):** no heartbeat is written while the capture cannot open. Check what the CARP
  hook and the status banner do with a keeper that never wrote one, on a master.
- **Q3 (R2, D10):** REBIND runs from T1 and the lease is given up at T2, where RFC 2131 renews
  (unicast) from T1, rebinds (broadcast) from T2 and keeps the lease until it expires. An early
  RENEW after a promotion that fails also enters REBIND at once and gives the lease up T2 - T1
  later, before its real T2. RENEW is also broadcast (`dhcpclient.renew`, so the sniffer sees
  the reply), where RFC 2131 and dhclient unicast it to the server; a server that ignores a
  broadcast RENEW would never answer the keeper. See #128.
- **Q4 (R6):** the error backoff uses `_sleep`, not `_sleep_interruptible`, so SIGUSR1/SIGUSR2
  wait up to 10 s. Probably fine for a rare path; confirm it is intended.
- **Q5 (R1, R2, R5, D10):** a DHCP exchange sends up to `RENEW_ATTEMPTS` requests and checks
  only for stop between them, not the CARP role, so a demotion in the middle of one can still
  send up to two requests from the shared MAC. Likely the same for DORA. (Found by the #140
  review; to be fixed separately.)
- **Q6 (R2):** a stop request during REBIND leaves the loop the same way an expired window does,
  so it logs "DHCP lease expired" and calls `expire()` on a lease that has not expired.

## Other components to give a matrix

Not filled yet. The same method applies.

- **Lease MAC rewrite (vmac egress):** rows are the ways the rewrite can end (demotion, CARP
  syshook, `rc.d stop`, `+POST_DEINSTALL`, keeper crash, option turned off, keeper disabled,
  downgrade); columns are "node removed", "marker cleaned", "status page correct", "read back".
- **Status banner (`CarpVipDhcpStatus.php`):** rows are heartbeat states (fresh, stale,
  missing, config error, backup, master, unknown role); columns are each banner reason and
  whether it may fire there.
- **Follow (`follow_update.php`):** rows are the steps (lock, VIP rewrite, gateway, alias,
  newwanip hooks, keeper restart); columns are "idempotent on re-drive", "logged",
  "lock held", "safe to interrupt".
