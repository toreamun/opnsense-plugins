# os-carp-vip-dhcp

> **Give a CARP virtual IP its own DHCP lease — so a shared, failover service IP works on a DHCP-assigned WAN.**

[![OPNsense plugin](https://img.shields.io/badge/OPNsense-plugin-d94f00)](https://opnsense.org/)
[![License: BSD-2-Clause](https://img.shields.io/badge/license-BSD--2--Clause-blue)](../../LICENSE)
[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-donate-ffdd00?logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/toreamun)

---

## What it does

On a DHCP-assigned WAN (typically **CGNAT**), the ISP only routes an address while it holds a **live DHCP lease** bound to a MAC. A plain CARP virtual IP is *static* — it never gets a lease, so it never receives traffic.

This plugin runs a small daemon that keeps a DHCP lease alive **for the CARP VIP's virtual MAC**. The ISP then routes the VIP to that MAC, native OPNsense CARP handles ARP and failover as usual, and the shared IP works — and fails over between two nodes — on a dynamic line.

## Is this for you?

You need it only if **all** of these are true:

- ✅ An **HA pair** (two OPNsense nodes) sharing an IP via **CARP**.
- ✅ The WAN is addressed by the **ISP's DHCP** (not static, not PPPoE).
- ✅ The line hands out **several concurrent leases** — one for each node's WAN, plus one for the VIP.

The third point is why it fits **CGNAT** best: carrier shared space (`100.64.0.0/10`) is abundant, so CGNAT ISPs readily lease several addresses per line. If your WAN is static or PPPoE, you don't need this plugin.

> **Only one ISP address?** The standard setup needs several leases. A **theoretical, untested** single-address design exists — see [docs/single-ip-wan-carp.md](docs/single-ip-wan-carp.md).

## Getting started

On the OPNsense box, as **root**:

1. **Create a CARP VirtualIP** on the WAN (Interfaces → Virtual IPs).
2. **Install** — resolves the latest signed release, verifies its maintainer signature, and installs Scapy + the plugin:
   ```sh
   fetch -o - https://raw.githubusercontent.com/toreamun/opnsense-plugins/main/install.sh | sh
   ```
3. Open **Interfaces → Virtual IPs DHCP**, add a keeper pointing at that CARP VIP, and **enable** it.

That's it — the VIP now holds a live lease. The defaults are sensible: it follows a dynamic address, keeps the gateway's ARP fresh, and runs on both nodes for seamless failover.

- **Update:** re-run the exact same command (it always fetches the latest signed release and reinstalls in place; settings are preserved). Pin a version by appending its tag, e.g. `… | sh -s -- os-carp-vip-dhcp v1.3.10`.
- **Uninstall:** `pkg delete os-carp-vip-dhcp` — stops the daemons and cleans up (Scapy is left in place). *(A manual, no-script install is documented at the bottom.)*

## Where it lives in the GUI

Everything is under **Interfaces → Virtual IPs DHCP**:

| Page | What you get |
|---|---|
| **Settings** | add / edit / enable keepers |
| **Status** | live per-keeper state — lease, CARP role, heartbeat, ARP-nudge age + gateway reachability |
| **Log** | the keeper log (searchable, with a level filter) |

A **“CARP-VIP DHCP” dashboard widget** shows one row per keeper for an at-a-glance view. Access is granted by the **“Interfaces: Virtual IPs DHCP”** privilege.

## How it works

A small root daemon keeps a DHCP lease alive for a chosen `chaddr` — the CARP virtual MAC (`00:00:5e:00:01:<VHID>`) of an existing CARP VIP. Standard `dhclient` can't do this because it ties the DHCP `chaddr` to the interface's hardware MAC; the daemon decouples them via a raw L2 socket (Scapy).

Once the ISP routes the VIP address to that MAC, native OPNsense CARP answers ARP and egresses data as usual — so the VIP becomes failover-capable on a DHCP interface. The daemon references an existing CARP VirtualIP (deriving interface, VHID→chaddr and IP), follows the lease (RENEW at T1, REBIND at T2, re-DORA at expiry), and by default runs on **both** nodes redundantly — same lease, seamless failover, no split-brain. Because the lease lives on the CARP **virtual** MAC, a failover invalidates nothing upstream: the same MAC simply starts answering from the new master.

---

<details>
<summary><b>Options &amp; behaviour</b></summary>

All per-keeper; sensible defaults mean most setups only pick a CARP VIP and enable.

- **Follow a dynamic address** *(default on)* — if the server assigns a different address than the configured VIP, the keeper adopts it and rewrites the CARP VIP to match, so the VIP stays online on a dynamic line. Turn **off** to *enforce* a fixed reservation (a mismatch then alarms).
- **Sync a firewall alias** *(optional)* — name a Host alias and the plugin keeps it set to the VIP's current address, so outbound NAT/rules pointed at the alias follow a dynamic address. See *Following a dynamic address*.
- **ARP nudge** *(default on)* — keeps the upstream gateway's ARP entry for the VIP fresh, listens for the reply as a reachability signal, and flags an ARP conflict. See *ARP nudge, reachability &amp; conflicts*.
- **CARP failover on lease loss** *(optional)* — demote this node (hand the VIP to the peer) if the keeper stops holding the correct lease.
- **Run only on CARP master** *(niche)* — hold the lease only while master (idle on backup); for ISPs that reject two clients with the same `chaddr`. Adds a failover DORA gap.
- **DHCP identity options** *(advanced)* — set a vendor-class (opt 60), client-id (61) or hostname (12) for servers that only lease to a known value. Give the keeper its *own* client-id.
- **HA config sync** *(optional)* — replicate the keeper config to the peer (System → High Availability → Settings), so you configure once on the master. Safe: the config is node-agnostic.
- **Self-healing & health banner** — the daemon never exits on a transient fault (it keeps its heartbeat fresh so CARP doesn't falsely demote the node), and a GUI banner warns if any enabled keeper stops holding its lease — closing the silent-failure gap on a redundant spare.

</details>

<details>
<summary><b>ARP nudge, reachability &amp; conflicts</b></summary>

Some ISP gateways/BNGs ignore gratuitous ARP and **never re-ARP an expired entry**. The symptom: traffic to the VIP works right after a CARP event or DHCP exchange, then **silently blackholes** minutes later. A DHCP RENEW doesn't refresh such a gateway's ARP cache, but a received ARP *request* does.

- **The nudge:** a periodic ARP *request* from the VIP (source = leased IP + CARP MAC) for the gateway. Default 240 s — well under typical 15–20 min ARP timeouts, and one broadcast per interval is negligible. Sent **only while CARP master** (never from a backup). Set 0 to disable.
- **On becoming master** (failover or a link flap re-electing CARP): an immediate nudge **and** an early lease RENEW, within ~1 s of the kernel CARP transition — neither waits for its timer.
- **Manual nudge:** the ⚡ button on the Status page (shown on the master), or `kill -USR1` on the daemon.
- **Reachability:** the keeper watches for the gateway's ARP **reply**; the Status page/widget show a green check when confirmed, and if several nudges go **unanswered** (a carrier dropping them) it logs a warning and flags it. No promiscuous mode is needed — the master already accepts the VIP MAC. A NIC that filters non-primary unicast can enable the advanced **“ARP listen in promiscuous mode”** fallback *(default off; it warns when on)*.
- **Conflict detection:** if another MAC is seen using the leased IP (duplicate address / ISP reassignment), the keeper logs a warning. Advisory only; the peer node shares the CARP MAC, so it's never mistaken for a conflict.

</details>

<details>
<summary><b>Following a dynamic address (NAT, aliases, inbound, HA)</b></summary>

When **Follow dynamic DHCP address** is on (default) and the server assigns a different address, the plugin rewrites the CARP VirtualIP to the new address. Both HA nodes reach the same address independently — they share the CARP `chaddr` and the server issues one lease per `chaddr`, so no cross-node signalling is needed.

**Make NAT and rules follow** — the plugin rewrites the *VIP address*, not your rules:

1. In the keeper, set **Sync firewall alias** to a name (e.g. `wan_carp_vip`). The plugin creates a Host alias of that name and keeps it equal to the VIP's current address.
2. Point your **outbound NAT** translation address — and any rule that must follow — at that **alias** instead of a literal IP. On a follow, the plugin updates the alias and reapplies the filter (state-preserving), so rules track the new address.

The alias is created/updated automatically and never deleted (it may be referenced elsewhere).

**Inbound is different:** a **port-forward cannot follow** a dynamic address — the upstream only routes inbound to the address it has reserved. Follow keeps *outbound* online; inbound services need a stable reserved address.

**HA note:** firewall aliases are covered by OPNsense HA config sync, so an alias update propagates to the backup too. The CARP VIP itself is intentionally *not* synced (`advskew` differs per node).

</details>

<details>
<summary><b>Playing nicely with ISP access-network security</b></summary>

Carrier access gear (BNG / access switches / OLTs) polices subscribers with mechanisms that key off the DHCP exchange. The plugin's strategy — a real lease held on the CARP virtual MAC, plus an ARP nudge that repeats exactly that binding — is designed to satisfy each:

| ISP mechanism | What it does | How the plugin cooperates |
|---|---|---|
| **DHCP snooping** | builds the trusted IP↔MAC table from DHCP seen on the port | the lease is acquired/renewed through the subscriber port with `chaddr` = CARP MAC, matching what CARP presents |
| **Dynamic ARP Inspection** | drops ARP whose (IP, MAC) ≠ the snooped binding | the nudge's sender is exactly (leased IP, CARP MAC) — it passes |
| **Gratuitous-ARP filtering** | ignores unsolicited ARP (drops CARP's own gratuitous ARP) | the nudge is a normal ARP **request**, which the gateway must process to answer — the one path such gear learns from |
| **No re-ARP on expiry** | gateway never re-ARPs; an expired entry blackholes traffic | the periodic nudge keeps the entry permanently fresh; becoming master nudges immediately |
| **IP Source Guard** (IP-only) | drops source IPs not in the binding table | the leased VIP is in the table — fine |
| **IP Source Guard** (strict IP+MAC) | also requires the source MAC to match | ⚠️ **known limitation:** FreeBSD egresses VIP data with the interface's *physical* MAC, so strict IPSG drops it (ARP/pings *to* the VIP work, but nothing *sourced from* it). Workaround: spoof the WAN MAC to the CARP MAC (Interfaces → [WAN] → Spoof MAC) — messy, topology-dependent |
| **Client identity checks** | leases only to a known vendor-class/client-id/hostname | per-keeper DHCP identity options |
| **Per-subscriber MAC/session limits** | limits source MACs / DHCP sessions on the port | budget for each node's MAC plus the CARP MAC; a strict one-IP/one-MAC ISP → see [single-ip doc](docs/single-ip-wan-carp.md) |

</details>

<details>
<summary><b>Scope, caveats &amp; design notes</b></summary>

- **IPv4 DHCP only.** DHCPv6 / IPv6 Neighbor Discovery are out of scope (a separate mechanism; the ARP nudge has no IPv6 equivalent here).
- WAN is the typical — not required — placement.
- Requires **root** (raw L2/BPF socket) and depends on **Scapy**.

*Deliberately not included:* DHCP option 82 (inserted by the ISP, not the client); RFC 5227 conflict *arbitration* (CARP arbitrates between our nodes; a rogue host is beyond a subscriber device — we detect and warn, above, but don't act); DAI rate-limit pacing (one nudge / 240 s is orders of magnitude under any limit); a unicast-RENEW mode (the broadcast flag makes RFC-2131 servers broadcast OFFER/ACK to a non-promiscuous socket; a server that unicasts to the CARP MAC is still received on the master).

</details>

<details>
<summary><b>Manual install (step by step, no script)</b></summary>

As **root**, download the plugin `.pkg`, `SHA256SUMS` and `SHA256SUMS.sig` from the [latest release](https://github.com/toreamun/opnsense-plugins/releases/latest) into an empty directory, then:

```sh
# 1. Fetch the maintainer's public key (one-time).
fetch -o release.pub https://raw.githubusercontent.com/toreamun/opnsense-plugins/main/keys/release.pub

# 2. Verify the checksum manifest was signed by that key.
openssl base64 -d -in SHA256SUMS.sig -out SHA256SUMS.sig.bin
openssl dgst -sha256 -verify release.pub -signature SHA256SUMS.sig.bin SHA256SUMS   # -> Verified OK

# 3. Verify the package matches the signed manifest.
h=$(sha256 -q os-carp-vip-dhcp-*.pkg); grep -q "$h" SHA256SUMS && echo "package OK"

# 4. Install the Scapy dependency (py<XY> = your box's Python: 26.x = py313, older = py311).
pkg install -y py313-scapy

# 5. Install the plugin.
pkg add ./os-carp-vip-dhcp-*.pkg
```

</details>

## License

BSD-2-Clause. See [LICENSE](../../LICENSE).
