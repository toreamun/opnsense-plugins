# ISPs that check the source MAC (IP + MAC binding)

Some ISPs only forward traffic when the packet's source MAC matches the MAC the DHCP lease is
bound to. Orange France is one ([issue #110](https://github.com/toreamun/opnsense-plugins/issues/110));
it is also what carrier gear calls strict IP Source Guard (IP + MAC). On such a line this
plugin keeps the lease alive, but **traffic from the CARP VIP does not work** out of the box.
Most ISPs do not do this; if traffic works through the VIP today, you are not affected.

The unsupported workaround below made traffic and failover work on a test bench; it has not
been tested with a real ISP that checks the MAC. Use it at your own risk.

## What happens and why

The keeper holds the lease on the CARP virtual MAC (`00:00:5e:00:01:<vhid>`, the vhid in
hex), so the ISP binds the leased address to that MAC. FreeBSD CARP, however, sends traffic
from a CARP VIP with the interface's **own** MAC. Only CARP's own packets (advertisements, and
ARP for the VIP) and the keeper's DHCP and ARP packets leave from the virtual MAC. That is how
FreeBSD CARP works for any VIP, static or DHCP; there is no CARP option to change it.

An ISP that binds IP to MAC therefore drops everything the master sends from the VIP. Traffic
towards the VIP may still arrive (the ISP sends it to the virtual MAC, which the master
answers).

The plugin still gets and keeps the lease on the virtual MAC across a failover. Making the
master send from it is left to you, because changing a NIC's MAC on every CARP transition is
risky in ways a lease keeper cannot control (see the risks below).

## How to recognise it

- The keeper reports the lease as held, on both the Status page and in the log.
- Pings and other traffic **to** the VIP from outside may work, but nothing **from** the VIP
  gets an answer: no internet through the VIP.
- A packet capture on the WAN shows your outgoing packets with the right source IP but the
  node's own MAC, and no replies.
- Setting the virtual MAC on the master's WAN interface by hand makes traffic work at once.

## Do not set the virtual MAC on both nodes

Setting the virtual MAC as the WAN MAC on **both** nodes (Interfaces, WAN, MAC address) looks
like the simple fix, but every frame the backup sends on the WAN (gateway monitoring, ARP)
then teaches the switch that the virtual MAC is on the backup's port. Traffic for the master
goes to the backup until the master sends again. Do not do this.

Setting it on the **primary only** works while the primary is master. After a failover the
backup has no internet through the VIP, and the primary, now backup but still on the virtual
MAC, pulls the virtual MAC to its own switch port whenever it sends. Unicast DHCP replies to
the new master can then go astray. If you keep the virtual MAC on the primary, clear it
whenever the primary is backup, for example during maintenance.

## Workaround: swap the MAC on CARP transitions (unsupported)

A small script, run by OPNsense on every CARP transition, gives the WAN interface the virtual
MAC while the node is master and its own MAC otherwise. It is **not part of the plugin and not
supported**: test it on your hardware before you rely on it.

### Risks you take on

- **Only with static node addresses on the WAN.** While a node is master and on the virtual
  MAC, its own WAN address also sends from the virtual MAC. A node's own DHCP lease on the
  WAN is bound to its own MAC and breaks while that node is master. Use the workaround only
  when the nodes' own WAN addresses are static, for example the private node IPs of the
  [single-IP setup](single-ip-wan-carp.md). Untested otherwise.
- **On a NIC, OPNsense sets the MAC back** whenever it configures the WAN interface: an
  apply on the interface page, a boot, and every link-up event. With the MAC field empty it
  puts back the NIC's own MAC, and no CARP event follows to swap it again, so the master is
  left on its own MAC and its traffic is dropped. Run the script every minute as well (see
  [Re-run it every minute](#re-run-it-every-minute)). A VLAN interface keeps the MAC the
  script gave it: OPNsense does not reset a VLAN's MAC.
- **Changing a MAC can reset the NIC.** On some drivers a MAC change resets the NIC and drops
  the link for seconds. The link-up then makes OPNsense set the MAC back (above), and if
  CARP fails over meanwhile, the other node swaps its MAC and the two can keep failing over.
  If you see repeated CARP transitions after installing, remove the script. On the test
  bench (virtio NIC) and in one user's VLAN in a virtual machine the change was instant.
- **lagg and shared VLAN parents:** a MAC change on a lagg can renegotiate LACP; on a VLAN,
  check that other VLANs on the same parent are not affected on your NIC.
- **Both nodes on the virtual MAC:** at a failover the old master gives the MAC up and the
  new master takes it. On the test bench the overlap was 1 to 2 ms with the `00-` name, and
  about 6 s with a later name. If the script fails on the node that loses master, the overlap
  lasts until the script runs again, and traffic for the master goes astray. If both nodes
  become master at once (they lose each other's CARP advertisements), both send from the
  virtual MAC until one returns to backup.
- **One CARP VIP per WAN interface.** An interface has one MAC, so the script handles one
  vhid. Traffic from a second CARP VIP on the same interface would leave from the first one's
  virtual MAC.
- **IPv6 and other protocols** on the WAN also leave from the virtual MAC on the master. The
  IPv6 link-local address keeps the node's own MAC embedded in it. Untested beyond IPv4.

### Install

First, on **both** nodes, leave the **MAC address** field of the WAN interface empty
(Interfaces, WAN) and apply. OPNsense applies that field whenever it configures the
interface, so a virtual MAC set there would come back on the backup too. On a VLAN, clearing
the field does not change the MAC that is set now: check with `ifconfig <WAN_IF>`, and if it
still shows the virtual MAC, set the own MAC back by hand (`ifconfig <WAN_IF> ether <own MAC>`,
the parent interface's MAC for a VLAN) or reboot.

Then, on **both** nodes, as root, create `/usr/local/etc/rc.syshook.d/carp/00-carp-vmac` with
the content below and make it executable (`chmod 755`). Keep the `00-` prefix (see
[What has been tested](#what-has-been-tested)). Set:

- `WAN_IF`: the interface the CARP VIP is on, as `ifconfig` names it.
- `VHID`: the vhid of that CARP VIP.
- `OWN_MAC`: this node's own MAC on that interface. It differs per node. If you leave it
  empty, the script detects it (for a VLAN, the parent interface's MAC), and refuses to act
  (with a log line) when it cannot tell the own MAC from the virtual one. On a VLAN, leaving
  it empty is the safest choice. If you set it, read it with `ifconfig` while the interface
  still has its own MAC.

The file is not synced by HA, and a reinstall or a configuration restore does not bring it
back: create it again after either. Then run it once by hand on each node.

```sh
#!/bin/sh

# Unsupported workaround for ISPs that drop traffic whose source MAC is not the
# MAC the DHCP lease is bound to: give the WAN interface the CARP virtual MAC
# while this node is CARP master, and its own MAC otherwise. Install steps and
# risks: docs/isp-mac-binding.md in os-carp-vip-dhcp.
#
# The script ignores its arguments and reads the current role itself, so any
# run (a CARP event, cron or by hand) corrects the MAC.

WAN_IF="vlan01"   # ifconfig name of the interface the CARP VIP is on
VHID="8"          # vhid of that CARP VIP, in decimal
OWN_MAC=""        # this node's own MAC on WAN_IF; empty = detect (see the guide)

log() { logger -t carp-vmac "$*"; }

# One run at a time: several CARP events can arrive together.
if [ -z "${CARP_VMAC_LOCKED}" ]; then
    CARP_VMAC_LOCKED=1 lockf -k -t 30 /var/run/carp-vmac.lock /bin/sh "$0" "$@" ||
        log "another run held the lock for 30 s; nothing changed"
    exit 0
fi

# Problems are logged and end with exit 0, so OPNsense does not report the hook
# as failed. A VHID that is not on WAN_IF (0, 300, "08") fails the CARP check.
case "${VHID}" in
    '' | *[!0-9]*) log "VHID must be a number; nothing changed"; exit 0 ;;
esac
OWN_MAC=$(echo "${OWN_MAC}" | tr 'A-F' 'a-f')   # ifconfig prints lower case
if [ -n "${OWN_MAC}" ] && ! echo "${OWN_MAC}" | grep -Eq '^([0-9a-f]{2}:){5}[0-9a-f]{2}$'; then
    log "OWN_MAC is not a MAC address; nothing changed"; exit 0
fi
if ! ifconfig "${WAN_IF}" >/dev/null 2>&1; then
    log "interface ${WAN_IF} not found; nothing changed"; exit 0
fi
if ! ifconfig "${WAN_IF}" | grep -q "carp: [A-Z]* vhid ${VHID} "; then
    log "no CARP vhid ${VHID} on ${WAN_IF}; nothing changed"; exit 0
fi
VMAC=$(printf '00:00:5e:00:01:%02x' "${VHID}")

own_mac() {
    [ -n "${OWN_MAC}" ] && { echo "${OWN_MAC}"; return; }
    # A VLAN takes the MAC of its parent interface. A NIC whose MAC was changed
    # lists its burnt-in address as hwaddr; without hwaddr, ether is its own.
    ifc="${WAN_IF}"
    parent=$(ifconfig "${WAN_IF}" | sed -n 's/.*parent interface: \([^ ]*\).*/\1/p')
    [ -n "${parent}" ] && ifc="${parent}"
    mac=$(ifconfig "${ifc}" | awk '/hwaddr/ {print $2; exit}')
    [ -z "${mac}" ] && mac=$(ifconfig "${ifc}" | awk '/ether/ {print $2; exit}')
    echo "${mac}"
}

# Set the MAC, then read the role again: it may have changed meanwhile.
for _ in 1 2 3; do
    current=$(ifconfig "${WAN_IF}" | awk '/ether/ {print $2; exit}')
    if ifconfig "${WAN_IF}" | grep -q "carp: MASTER vhid ${VHID} "; then
        want="${VMAC}"
    else
        want=$(own_mac)
        if [ -z "${want}" ] || [ "${want}" = "${VMAC}" ]; then
            # Do not "restore" the virtual MAC on a node that is not master.
            log "cannot tell the own MAC of ${WAN_IF}; set OWN_MAC in $0"
            exit 0
        fi
    fi
    [ "${current}" = "${want}" ] && exit 0
    if ! ifconfig "${WAN_IF}" ether "${want}"; then
        log "failed to set ${WAN_IF} to ${want}"; exit 0
    fi
    log "${WAN_IF} now sends from ${want} (was ${current})"
done
log "the CARP role kept changing; the next run sets the MAC"
exit 0
```

A failed change is not retried until the next run.

### Re-run it every minute

Needed on a NIC (OPNsense sets the MAC back, see the risks); on a VLAN it is optional, but it
also bounds how long a missed or failed change lasts. The script does nothing when the MAC is
already right. On **both** nodes:

1. Create `/usr/local/opnsense/service/conf/actions.d/actions_carpvmac.conf`:

   ```ini
   [run]
   command:/usr/local/etc/rc.syshook.d/carp/00-carp-vmac
   parameters:
   type:script
   message:checking the CARP virtual MAC on the WAN
   description:Check the CARP virtual MAC on the WAN
   ```

2. Run `service configd restart`, then `configctl carpvmac run` to check that it works.
3. In System, Settings, Cron, add a job with minute `*` (every minute) and the command
   **Check the CARP virtual MAC on the WAN**.

Like the script, the action file is not synced by HA and does not survive a reinstall.

### Check it

- On the master, `ifconfig <WAN_IF>` shows the virtual MAC as `ether`; on the backup, its own.
- Traffic through the VIP works on the master.
- Fail over (for example with CARP maintenance mode on the master) and check both again.
- Watch the system log for `carp-vmac` lines, and for CARP transitions that you did not cause.
  Not every change reached the log on the test bench, so trust `ifconfig` over the log.

### Remove it

Delete the script (and the action file and cron job, if you added them) on both nodes, then
set each WAN interface back to its own MAC (`ifconfig <WAN_IF> ether <own MAC>`, or reboot).

## What has been tested

On a test pair of OPNsense 26.7 (FreeBSD 15.1) virtual machines, with the CARP VIP on a virtio
NIC and frames captured per node, so each frame is attributed to the node that sent it:

- The master sends all its WAN traffic from the virtual MAC and the backup only from its own
  MAC; traffic from the VIP works on the master.
- Failover in both directions: the old master's last frame from the virtual MAC and the new
  master's first came within 1 to 2 ms of each other. Changing the MAC caused no CARP
  transitions of its own.
- A reboot of the master, and OPNsense reconfiguring the WAN interface (which itself caused a
  failover), ended with the right MAC on each node.
- `configctl interface reconfigure wan` on a virtio NIC set the MAC back to the NIC's own; a
  VLAN interface showed no `hwaddr` after a MAC change, so OPNsense leaves its MAC as it is.
- With the master's MAC set back by hand and no CARP event, `configctl carpvmac run` (the
  action the cron job runs) gave it the virtual MAC again. The cron job itself was not run.
- With the script named `60-carp-vmac` instead of `00-carp-vmac`, the swap came about 6 s
  late, and both nodes sent from the virtual MAC for that long.
- Three runs started at once on each node finished cleanly (they are serialised).

Not tested: physical NICs, a real link-up event, lagg, the CARP swap on a VLAN interface (a
user on a VLAN in a virtual machine reported that swapping the MAC by hand works at once),
OPNsense 26.1, and a real ISP that checks the MAC.
