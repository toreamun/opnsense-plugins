# os-carp-vip-dhcp

**Keep a DHCP lease alive for a CARP virtual IP — so a CARP VIP can live on a DHCP-assigned WAN and fail over between two OPNsense nodes.**

[![OPNsense plugin](https://img.shields.io/badge/OPNsense-plugin-d94f00)](https://opnsense.org/)
[![License: BSD-2-Clause](https://img.shields.io/badge/license-BSD--2--Clause-blue)](../../LICENSE)
[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-donate-ffdd00?logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/toreamun)

## Installing

On the OPNsense box, as **root**, run the installer. It resolves the latest signed
release, **verifies its maintainer signature**, installs the Scapy dependency for
your box's Python, and installs the plugin:

```sh
fetch -o - https://raw.githubusercontent.com/toreamun/opnsense-plugins/main/install.sh | sh
```

The plugin then appears under **Interfaces → Virtual IPs DHCP**. Remove it with
`pkg delete os-carp-vip-dhcp` (the Scapy dependency is left in place).

<details>
<summary>Manual install (step by step, no script)</summary>

On the OPNsense box, as **root**. Make an empty directory and download the plugin
`.pkg`, `SHA256SUMS` and `SHA256SUMS.sig` into it from the
[latest release](https://github.com/toreamun/opnsense-plugins/releases/latest), then:

```sh
# 1. Fetch the maintainer's public key (one-time).
fetch -o release.pub https://raw.githubusercontent.com/toreamun/opnsense-plugins/main/keys/release.pub

# 2. Verify the checksum manifest was signed by that key.
openssl base64 -d -in SHA256SUMS.sig -out SHA256SUMS.sig.bin
openssl dgst -sha256 -verify release.pub -signature SHA256SUMS.sig.bin SHA256SUMS   # -> Verified OK

# 3. Verify the package matches the signed manifest.
h=$(sha256 -q os-carp-vip-dhcp-*.pkg); grep -q "$h" SHA256SUMS && echo "package OK"

# 4. Install the Scapy dependency. `pkg add` of a standalone file does NOT pull it
#    from the repo (only `pkg install <name>` does). py<XY> = your box's Python:
#    OPNsense 26.x = py313, older releases = py311.
pkg install -y py313-scapy

# 5. Install the plugin.
pkg add ./os-carp-vip-dhcp-*.pkg
```

Then find it under **Interfaces → Virtual IPs DHCP**.
</details>

## Where to find it in the GUI

After installing, the plugin lives under **Interfaces → Virtual IPs DHCP**, with three pages:

- **Settings** — the keeper table (add / edit / enable keepers).
- **Status** — effective configuration + runtime (bound lease, heartbeat age, CARP demotion), and per-keeper mode.
- **Log** — the keeper log (searchable/filterable, with a clear button).

The privilege that grants access is **“Interfaces: Virtual IPs DHCP”**.

## When is this relevant?

Use this plugin when **all** of the following hold:

1. You want an **HA pair** (two OPNsense nodes) sharing a service IP via **CARP**.
2. The WAN gets its address from the **ISP's DHCP** (not a static or PPPoE assignment).
3. The ISP hands out **several concurrent addresses** on your line. This is the crux: an HA CARP
   setup needs at least three active DHCP leases at once — one for each node's own WAN address, plus
   one for the shared CARP VIP — so a single-address line cannot work. It is also why the plugin fits
   **CGNAT** links best: carrier shared space (RFC 6598, `100.64.0.0/10`) is abundant, so CGNAT ISPs
   readily lease you multiple addresses, whereas public IPv4 is scarce and rarely handed out
   several-per-line over DHCP. (The mechanism itself is about DHCP, not CGNAT — a public DHCP WAN that
   *does* offer several addresses works exactly the same.)
4. You therefore need the **CARP VIP address to hold its own live DHCP lease** — otherwise the ISP never
   routes it to you and the VIP stays dark.

In other words: CARP alone gives you a shared *static* VIP, but on a DHCP link a static IP receives no traffic.
This plugin fetches and continuously renews a DHCP lease **for the VIP address** (bound to the CARP virtual
MAC), so the shared IP is actually routed and can fail over. If your WAN uses a static/PPPoE assignment instead
of DHCP, you do **not** need this plugin.

> **Only a single ISP address?** A single-address line cannot use the straightforward setup above (it needs
> several concurrent leases). There is a **theoretical, untested** design that works around it — private
> per-node WAN IPs used only for CARP advertisements, plus one floating VIP that holds the single public lease.
> See [docs/single-ip-wan-carp.md](docs/single-ip-wan-carp.md).

## The problem

On a DHCP-assigned WAN (a CGNAT link is the typical example), the ISP/DHCP server only routes an address
**while it has an active DHCP lease** bound to a MAC (`add-arp`). A *static* CARP virtual IP therefore gets zero
traffic — the address is never routed to you. Standard `dhclient` cannot help because it cannot decouple the
DHCP `chaddr` from the interface hardware MAC.

## What this plugin does

A small daemon keeps a DHCP lease alive for a **chosen `chaddr`** — normally the CARP virtual MAC
(`00:00:5e:00:01:<VHID>`) of an existing CARP VIP. The ISP then routes the VIP address to that MAC, and native
OPNsense CARP answers ARP + egresses data as usual. The VIP becomes failover-capable on a DHCP interface.

- **References an existing CARP VirtualIP** (Interfaces → Virtual IPs) and derives interface + VHID→chaddr + IP.
- **Follows the server's lease** (RENEW at T1, REBIND at T2, re-DORA at expiry).
- Runs **ungated on both nodes** by default (both hold the same lease — redundant, seamless failover, no split-brain).
- **CARP failover on lease loss (optional):** a `rc.carp_service_status.d` hook demotes the node if the keeper
  stops holding the *correct* lease (stale heartbeat **or** an ISP IP mismatch), so the VIP moves to the peer
  that *does* hold it.
- **Run only on CARP master (optional, niche):** the keeper stays running on both nodes but only sends DHCP
  while this node is CARP master (stands by / releases the lease on backup) — for ISPs that reject two
  clients with the same chaddr. Adds a failover DORA gap; the default ungated mode fails over seamlessly.
- **Follow a dynamic address (default on):** if the DHCP server hands out a *different* address than the
  configured VIP, the keeper adopts it and rewrites the CARP VIP to match, so the VIP stays online on a
  dynamic line. Both nodes converge on the same address (shared chaddr → one lease per chaddr). Turn it
  **off** to *enforce* a fixed reservation instead (a mismatch then alarms, and optionally hands the VIP
  to the peer).
- **Sync a firewall alias (optional):** name a firewall Host alias and the plugin keeps it set to the
  VIP's current address, so outbound NAT and rules pointed at the alias follow a dynamic address
  automatically. See *Following a dynamic address* below.
- **Optional HA config sync:** the keeper configuration can be replicated to the peer via OPNsense HA
  sync — a checkbox under **System → High Availability → Settings** (off by default) — so you configure
  keepers once on the master. It is safe because the keeper config is node-agnostic (it stores VIP
  *addresses*, not per-node UUIDs; interface and chaddr are derived at render time).
- **DHCP request options (optional):** set a **vendor-class (option 60)**, **client-id (61)** or
  **hostname (12)** per keeper (advanced) for ISPs that only lease when they see a specific value. Empty
  = not sent. Give the keeper its *own* client-id — do not copy the WAN interface's, or the server may
  treat them as one client.
- **ARP nudge (on by default, advanced):** periodically broadcast an ARP *request* from the VIP (with its CARP
  MAC) for the upstream gateway, refreshing the gateway's ARP entry for the VIP. Some ISP gateways/BNGs
  ignore gratuitous ARP (spoofing protection) and **never re-ARP an expired entry** — the symptom is that
  traffic NATed to the VIP works right after a CARP event or DHCP exchange, then **silently blackholes
  some minutes later** (outbound packets leave, nothing returns; even the gateway stops answering pings
  from the VIP). A DHCP RENEW does *not* refresh such a gateway's ARP cache, but a received ARP request
  does. Default interval: 240 s (well under typical 15–20 min ARP timeouts) — one broadcast ARP per
  interval is negligible next to CARP's one advertisement per second, and harmless on gateways that
  behave normally, so it is **on by default**. The nudge is only sent while this node is CARP **master**
  for the VIP (never from a backup, which would steal the VIP's traffic), and the gateway address is
  taken from DHCP option 3 (fallback: the DHCP server address). Set 0 to disable.
- **Self-healing:** the daemon never exits on a transient DHCP/interface fault — it catches errors, keeps
  its heartbeat fresh (so CARP does not falsely demote the node) and retries.

## Prerequisites

1. Create a **CARP VirtualIP** on the target interface first, then select it in this plugin and enable it.
2. **Fixed vs. dynamic address.** By default the plugin **follows** whatever address the DHCP server
   gives the VIP's MAC (see *Following a dynamic address* below), so a static reservation is **not**
   required. If you *do* have a static DHCP reservation (MAC → IP) and want the plugin to insist on it,
   turn **Follow dynamic DHCP address** off to run in *enforce* mode (a mismatch is then treated as an
   error/alarm instead of being adopted).

## Following a dynamic address

When **Follow dynamic DHCP address** is on (the default) and the server assigns a different address than
the configured VIP, the plugin rewrites the CARP VirtualIP (and the keeper's reference) to the new
address, so the VIP keeps working on a dynamic line. Both HA nodes reach the same address independently
because they share the CARP virtual MAC (`chaddr`) and the server issues one lease per chaddr — no
cross-node signalling is needed.

**Making NAT and rules follow.** The plugin rewrites the *VIP address*, but not your NAT rules or
port-forwards. To let outbound NAT (and any firewall rule) follow a changing address, use a firewall
alias:

1. In the keeper, set **Sync firewall alias** to a name, e.g. `wan_carp_vip`. The plugin creates a
   firewall **Host** alias of that name and keeps its content equal to the VIP's current address.
2. Point your **outbound NAT** translation address (Firewall → NAT → Outbound) — and any firewall rule
   that must follow the address — at that **alias** instead of a literal IP. OPNsense renders the alias
   as a pf table, and on a follow the plugin updates the alias and reapplies the filter (state-preserving,
   so established connections are kept), so the rules track the new address automatically.

The alias is created and updated automatically; the plugin never deletes it (it may be referenced
elsewhere), so clearing the field just leaves a stale alias you can remove by hand.

**Inbound is different.** A **port-forward cannot follow** a dynamic address: the upstream only routes
inbound traffic to the address it has reserved/bound, so inbound to a freshly-assigned dynamic address
has no path until the upstream is updated (e.g. a static reservation, or dynamic DNS on the far side).
Follow keeps *outbound* connectivity online; inbound services need a stable reserved address.

**HA note.** Firewall aliases are covered by OPNsense HA config sync, so an alias update on the master
also propagates to the backup via XMLRPC — in addition to the backup updating its own alias when its
keeper follows. (The CARP VIP itself is intentionally *not* synced, because `advskew` differs per node.)
The keeper *configuration* itself can optionally be synced too: tick **CARP-VIP DHCP lease keepers**
under System → High Availability → Settings (off by default) to replicate it to the backup.

## Playing nicely with ISP access-network security

Carrier access equipment (BNG / access switches / OLTs) polices subscribers with a family of
mechanisms that all key off the DHCP exchange. The plugin's strategy — a real DHCP lease held on the
CARP virtual MAC, plus an ARP nudge that repeats exactly that binding — is designed to satisfy each
of them:

| ISP mechanism | What it does | How the plugin cooperates |
|---|---|---|
| **DHCP snooping** | builds the trusted IP↔MAC binding table from DHCP exchanges seen on the subscriber port | the lease is acquired and renewed *through the subscriber port* with `chaddr` = CARP MAC, so the binding matches what CARP presents on the wire |
| **Dynamic ARP Inspection (DAI)** | drops ARP whose sender (IP, MAC) does not match the snooped binding | the nudge's sender is (leased IP, `chaddr`) — exactly the snooped binding, so it passes inspection |
| **Gratuitous-ARP filtering** | ignores unsolicited ARP announcements (ARP-spoofing defence) — CARP's own gratuitous ARP on failover is silently dropped | the nudge is a normal ARP **request**, which the gateway must process in order to answer; that is the one ARP path such gear reliably learns from |
| **No re-ARP on expiry** ("secured ARP") | the gateway never broadcasts who-has for a subscriber address; an expired entry silently blackholes all downstream traffic | the periodic nudge (default 240 s, well under typical 15–20 min ARP timeouts) keeps the entry permanently fresh; becoming CARP master triggers an immediate nudge so a failover or link flap never waits out the interval |
| **IP Source Guard (IP-only)** | drops upstream packets whose source IP is not in the binding table | the leased VIP *is* in the table — fine |
| **IP Source Guard (strict IP+MAC)** | additionally requires the source *MAC* to match the binding | ⚠ **known limitation**: FreeBSD egresses data from a CARP VIP with the interface's *physical* MAC, not the CARP MAC. Under strict IPSG, outbound VIP traffic is dropped even though the lease and ARP are healthy. Symptom: the gateway answers ARP/pings *to* the VIP, but anything *sourced from* it never gets a reply, fresh nudge or not. There is no clean per-packet fix; the workaround is spoofing the interface MAC to equal the lease MAC (see the single-IP scenario doc) |
| **Client identity checks** | the server only leases to a known vendor-class (opt 60), client-id (61) or hostname (12) | per-keeper DHCP request options (advanced fields) |
| **Per-subscriber MAC / session limits** | the port accepts a limited number of source MACs or DHCP sessions | mind the budget: each node's own MAC plus the CARP MAC all appear on the ISP-facing segment. With a strict one-IP/one-MAC ISP, see [docs/single-ip-wan-carp.md](docs/single-ip-wan-carp.md) |

Failover interplay: because the ISP binds the lease to the CARP **virtual** MAC, a CARP failover does
not invalidate anything upstream — the same MAC simply starts answering from the new master (CARP's
advertisements re-teach the switch fabric within a second, and the new master sends an immediate
ARP nudge). This is the core reason the lease lives on the CARP MAC rather than either node's own.

## Scope / caveats

- **IPv4 DHCP only** (DHCPv6/ND out of scope for now — the ARP nudge has no IPv6 equivalent here
  either; IPv6 neighbor discovery is a separate mechanism).
- WAN is the typical — but not required — placement.
- You must own the MAC/reservation you keep a lease for; holding a foreign lease is an ISP violation.
- Requires **root** (raw L2/BPF socket) and depends on **Scapy**.

## License

BSD-2-Clause. See [LICENSE](../../LICENSE).
