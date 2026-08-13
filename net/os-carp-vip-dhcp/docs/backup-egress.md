# Backup egress: internet for the non-master node

Companion to the default-route-by-CARP-role feature (`Own default route by CARP
role` = observe/enforce). That feature makes the keeper own the WAN default as a
function of CARP role: the master installs `0.0.0.0/0`, every other state has
none (fail-stop). A direct consequence is that **the CARP backup node has no
route to the internet for its own traffic** (pkg/firmware updates, NTP, DNS,
remote reachability), because the single ISP-assigned WAN address lives on the
master.

Backup egress is an opt-in feature (default off) that gives the backup node
egress **via the master**, without reintroducing the leak or black-hole that the
default-route feature eliminated.

## What it does

The reconcile loop keeps a **backup-egress route set** installed while this node
is the CARP **backup**, and removes it when the node becomes **master**. Exactly
one of these exists at a time, keyed on role:

- **Master:** `0.0.0.0/0` via the WAN gateway (the default-route feature).
- **Backup:** the configured backup-egress route via a gateway that means "the
  current master".

They are mirror images, so they can never collide: the backup never holds a
`0/0`, the master never holds the backup-egress route. Removing the route on the
master is essential, because the default route form (a `/1`-split) is more
specific than `0/0` and would otherwise beat the master's own default and loop
its egress back at itself.

## Prerequisites

- `Own default route by CARP role` must be **observe** or **enforce** on this
  keeper. Backup egress rides the same reconcile loop; in **off** the loop is
  inert and backup egress does nothing.
- **observe** logs what it would install/remove without touching the routing
  table; **enforce** actually installs and removes.

## Route form

What gets installed on the backup. Two options; the `/1`-split is the default.

- **`/1`-split** (`0.0.0.0/1` + `128.0.0.0/1`) - **default, recommended.** Covers
  the whole internet but is not "the default route":
  - it wins over any existing `0.0.0.0/0` by longest-prefix match (so it
    overrides a black-hole WAN default the backup cannot use),
  - it is never redistributed as a default: if you redistribute kernel routes
    into a routing protocol with a route-map that permits only exact
    `0.0.0.0/0`, a `/1` is filtered out,
  - it never collides with **enforce**, which only ever touches `0/0`.

  This is the safe universal choice, and the only correct one when this node
  redistributes its default into a routing protocol.
- **Specific prefixes** - a curated IPv4 CIDR list (for example your pkg mirror
  and NTP hosts), separated by comma or space. Limited egress, leak-safe by the
  same longest-prefix argument. A `0.0.0.0/0` entry in this list is dropped under
  **enforce** with a one-time warning (it would both leak and fight enforce);
  non-IPv4 entries are ignored (the feature is IPv4-only).

A plain `0.0.0.0/0` route form is deliberately not offered: the feature runs only
under observe/enforce, enforce owns `0/0` and would withdraw it, and observe
never writes, so a plain default could never actually install.

## The gateway (= "the current master")

The route's next hop must resolve to whichever node is currently master. There
are three ways to name that; all share the same reconcile core.

### CARP VIP (recommended)

Point the gateway at an existing internal CARP VIP (for example the LAN VIP). A
CARP VIP is by definition answered by whoever is master, so "send to the VIP"
means "send to the current master". The backup ARPs for the VIP (it is in CARP
backup state locally, so it does not treat the VIP as its own address) and the
master answers, NATs, and forwards out the WAN.

- One fixed address in config, identical on both nodes, so config sync is
  trivial.
- Follows failover automatically: the VIP moves to the new master and the route
  keeps working with no change.
- No peer derivation, no `/30` constraint, no new VIP needed.

### Derive the peer from a point-to-point interface (fallback)

Leave the gateway blank and name an **interface** instead. The plugin reads this
node's own IPv4 on that interface and uses the **other** host of a `/30` or `/31`
subnet as the gateway. This is config-sync-safe because the synced value is a
rule ("derive"), not an address, so each node computes its own correct peer. Only
valid on a two-address (`/30`/`/31`) link; anything else refuses to derive and
installs no route (warned).

### A separate uplink gateway (most robust, needs hardware)

If the backup has its own second uplink (LTE/DSL), point the gateway at that
uplink. The backup then egresses independently of the master, so it keeps
internet even when the master is down (unlike the VIP/peer options, which
black-hole harmlessly in a common-mode outage where the master has no internet
either). Larger multi-uplink setups usually use OPNsense native multi-WAN
instead.

### Why not an explicit peer address

Config syncs identically between the two nodes, so an explicit peer address (for
example the master's own point-to-point address) is wrong on the node whose own
address equals it: as backup, it would route via itself. A VIP (stable) or a
derive rule (per-node) avoids this. The plugin **rejects a gateway equal to this
node's own address** (resolved via `route get`, which sends a local address to
`lo0`); the check runs every tick and is never cached, so a transient failure
cannot permanently disable the guard. A CARP VIP the node is backup for is not
active locally, so the recommended VIP gateway is not caught by this guard.

## Fail-safe behaviour

- **Unreadable routing table:** the master-side removal deletes the route set
  unconditionally rather than concluding "absent" (a leftover `/1` on the master
  would loop all egress); the install side defers rather than blind-adding. The
  unreadable condition is warned once per episode.
- **Role probe unreadable (`is_master` unknown):** nothing is touched, matching
  the `0/0` side, to avoid thrashing on a transient failure.
- **Startup and graceful shutdown:** the `/1`-split is cleared at both process
  boundaries so a crashed or stopped keeper leaves no orphan that a later master
  would loop through. The split is cleared even when the feature has since been
  disabled, because a predecessor may have installed it.
- **Form change:** the master-side removal covers the `/1`-split plus the current
  configured prefixes, so a form change (split to prefixes or back) that orphaned
  the old set is still cleaned up.

## Known limits (accepted)

- **IPv6:** out of scope, like the default-route logic. IPv4 only.
- **prefixes-list change across a crash:** the master-side cleanup removes the
  `/1`-split plus the **current** configured prefixes, so a `prefixes`-form list
  changed **after an ungraceful exit** that left an old prefix installed can
  orphan that one prefix (a black-hole for that destination only, not
  egress-wide). A graceful restart removes the old set at shutdown; only
  crash-then-list-change leaves it, and the default `/1`-split form is never
  affected.
- **Compound failure:** if the routing table is persistently unreadable and a
  `route delete` genuinely fails at the same time, a stuck `/1` on the master can
  only be surfaced by the once-per-episode "cannot read the routing table"
  warning, not the specific "would loop egress" error (which needs a readable
  table). Best-effort deletes are re-issued every tick and the true state
  surfaces once the table is readable again.
- **Master without a lease + healthy backup:** the backup routes via a master
  that itself cannot reach the internet, a short black-hole until CARP demotes
  the lease-less master. Self-correcting.

## Config fields

| Field | Meaning |
|---|---|
| Enable backup egress | Off by default. Turn on to give the backup node egress via the master. |
| Route form | `/1`-split (default, full internet, leak-safe) or specific prefixes. |
| Gateway | A stable next hop that means "the master": a CARP VIP (recommended) or a separate uplink gateway. Leave blank to derive the peer from an interface. |
| Interface | Required when Gateway is blank (derive the `/30`/`/31` peer); otherwise the on-link interface the route binds to. |
| Prefixes | For the specific-prefixes form: IPv4 CIDRs separated by comma or space. |

## Leak-safety guardrail

The backup-egress routes are kernel routes, so if you run `redistribute kernel`
into a routing protocol they are considered for redistribution. The guardrail is
a route-map that permits only exact `0.0.0.0/0`, which filters out anything that
is not exactly `0/0` (a `/1` and any specific prefix are dropped). The plugin
does not read or manage your FRR configuration, so keeping that exact-match
route-map in place is an operator responsibility, the same guardrail the
default-route feature relies on. This is also why `0.0.0.0/0` is rejected as a
specific-prefix entry: it would both leak and fight enforce.
