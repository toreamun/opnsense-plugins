#!/usr/local/bin/php
<?php

/*
 * follow_update.php <old_ip> <new_ip>
 *
 * Triggered by a follow-mode keeper daemon when the ISP hands out a different
 * address. Rewrites the CARP VIP (whose current subnet is <old_ip>) and every
 * keeper that references it to <new_ip>, then re-applies the VIP and restarts
 * the keepers. Both HA nodes run this independently and converge on the same
 * address because they share the same chaddr (one ISP lease per chaddr).
 */

require_once("config.inc");
require_once("util.inc");
require_once("interfaces.inc");

if ($argc < 3) {
    fwrite(STDERR, "usage: follow_update.php <old_ip> <new_ip>\n");
    exit(1);
}
$old_ip = $argv[1];
$new_ip = $argv[2];

foreach ([$old_ip, $new_ip] as $ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        fwrite(STDERR, "invalid IPv4 argument: {$ip}\n");
        exit(1);
    }
}
if ($old_ip === $new_ip) {
    exit(0);
}

// Single-writer per node. Two follow_update runs racing on the same node (a
// second keeper event, or a retry overlapping the original) would both call
// write_config + reconfigure_vips and clobber each other. Take a non-blocking
// exclusive lock; if another run already holds it, that run converges to the
// same address (both nodes share the chaddr, so the ISP hands out one lease),
// so this one can simply bow out. The lock releases automatically on exit.
$lockfh = fopen('/var/run/carpvipdhcp-follow_update.lock', 'c');
if ($lockfh === false || !flock($lockfh, LOCK_EX | LOCK_NB)) {
    fwrite(STDERR, "another follow_update is already running; skipping\n");
    exit(0);
}

global $config;
$vip_changed = false;
$keeper_changed = false;
$old_vip_iface = '';

// 1. Rewrite the CARP VIP whose current subnet is old_ip.
if (isset($config['virtualip']['vip']) && is_array($config['virtualip']['vip'])) {
    foreach ($config['virtualip']['vip'] as $idx => $vip) {
        if (($vip['mode'] ?? '') === 'carp' && ($vip['subnet'] ?? '') === $old_ip) {
            $config['virtualip']['vip'][$idx]['subnet'] = $new_ip;
            $old_vip_iface = $vip['interface'] ?? '';
            $vip_changed = true;
        }
    }
}

// 2. Update every keeper that referenced the old address. Use direct assignment
// (not a &reference to the subtree) so write_config serializes the change.
if (isset($config['OPNsense']['CarpVipDhcp']['keepers']['keeper'])) {
    $keepers = $config['OPNsense']['CarpVipDhcp']['keepers']['keeper'];
    if (isset($keepers['carpVip']) || isset($keepers['@attributes'])) {
        // single keeper (associative)
        if (($keepers['carpVip'] ?? '') === $old_ip) {
            $config['OPNsense']['CarpVipDhcp']['keepers']['keeper']['carpVip'] = $new_ip;
            $keeper_changed = true;
        }
    } else {
        // list of keepers
        foreach ($keepers as $k => $entry) {
            if (($entry['carpVip'] ?? '') === $old_ip) {
                $config['OPNsense']['CarpVipDhcp']['keepers']['keeper'][$k]['carpVip'] = $new_ip;
                $keeper_changed = true;
            }
        }
    }
}

if (!$vip_changed && !$keeper_changed) {
    // Nothing referenced old_ip. Either there is genuinely nothing to do, or a
    // previous run (or the peer node) already migrated the config to new_ip and
    // this is a retry. If a CARP VIP already carries new_ip, fall through and
    // re-apply the derived state (VIP assignment, keeper.conf, alias) so a
    // half-finished migration is repaired idempotently; otherwise nothing to do.
    $already_migrated = false;
    foreach ($config['virtualip']['vip'] ?? [] as $vip) {
        if (($vip['mode'] ?? '') === 'carp' && ($vip['subnet'] ?? '') === $new_ip) {
            $already_migrated = true;
            break;
        }
    }
    if (!$already_migrated) {
        fwrite(STDERR, "no CARP VIP or keeper with address {$old_ip}\n");
        exit(0);
    }
    fwrite(STDERR, "already at {$new_ip}; re-applying derived state (idempotent retry)\n");
} else {
    if (!$vip_changed) {
        // A keeper referenced old_ip but no CARP VIP has that subnet. keeper.conf is
        // rendered by resolving the keeper's carpVip against a matching VIP, so
        // without a VIP the keeper is dropped from the render (lease-keeping stops).
        // Surface it rather than silently restart into an empty table.
        fwrite(STDERR, "warning: keeper referenced {$old_ip} but no CARP VIP has that subnet\n");
    }

    write_config("carpvipdhcp: follow ISP address {$old_ip} -> {$new_ip}");
}

// Re-assign the VIP address on the interface. Abort BEFORE restarting keepers if
// this fails, so we never DHCP-maintain an address CARP is not advertising.
$out = array();
$rc = 0;
exec('/usr/local/opnsense/scripts/interfaces/reconfigure_vips.php 2>&1', $out, $rc);
if ($rc !== 0) {
    fwrite(STDERR, "reconfigure_vips failed (rc={$rc}): " . implode(' | ', $out) . "\n");
    exit(1);
}

// reconfigure_vips ADDS the new CARP VIP but leaves the old address on the
// interface as a runtime alias, so repeated follows would accumulate stale VIPs
// (harmless -- nothing leases the old address -- but untidy). Best-effort remove
// it; never fatal (a reboot would clear it anyway).
if ($old_vip_iface !== '' && $old_ip !== $new_ip) {
    $dev = get_real_interface($old_vip_iface);
    if (!empty($dev)) {
        mwexec('/sbin/ifconfig ' . escapeshellarg($dev) . ' -alias ' . escapeshellarg($old_ip));
    }
}

// Re-render keeper.conf, then WAIT until it actually reflects new_ip before
// restarting. configd caches config.xml, so right after write_config the
// template can still render the OLD address (sub-second mtime race). Restarting
// on a stale render would rebind the daemon to old_ip -> follow fires again ->
// restart loop. Reload+verify (crossing the mtime second) before restarting.
$keeperconf = '/usr/local/etc/carpvipdhcp/keeper.conf';
$rendered_ok = false;
for ($i = 0; $i < 10; $i++) {
    exec('/usr/local/sbin/configctl template reload OPNsense/CarpVipDhcp 2>&1');
    $conf = @file_get_contents($keeperconf);
    if ($conf !== false) {
        foreach (explode("\n", $conf) as $line) {
            if (strpos($line, "{$new_ip}|") === 0) {
                $rendered_ok = true;
                break 2;
            }
        }
    }
    sleep(1);
}
if (!$rendered_ok) {
    fwrite(STDERR, "keeper.conf never reflected {$new_ip} after reload; not restarting\n");
    exit(1);
}

// Replace only the keeper that just changed address, not every keeper on the
// node. The daemon is keyed by a filesystem-safe id derived from its request IP,
// so a follow renames it old_id -> new_id. We must stop old_id and start new_id
// SEPARATELY: `restart <old_id>` would stop the old daemon but then
// carpvipdhcp_start (honouring svc_id=old_id) skips the renamed new_ip line in
// keeper.conf -> 0 keepers started -> nothing renews the lease -> the WAN
// silently blackholes at the next expiry. Same _id() mapping as the rc script.
$old_id = preg_replace('/[^A-Za-z0-9]/', '_', $old_ip);
$new_id = preg_replace('/[^A-Za-z0-9]/', '_', $new_ip);
$out = array();
$rc = 0;
exec('/usr/local/etc/rc.d/carpvipdhcp stop ' . escapeshellarg($old_id) . ' 2>&1', $out, $rc);
$out2 = array();
$rc2 = 0;
exec('/usr/local/etc/rc.d/carpvipdhcp start ' . escapeshellarg($new_id) . ' 2>&1', $out2, $rc2);
if ($rc2 !== 0) {
    fwrite(STDERR, "keeper start failed (rc={$rc2}): " . implode(' | ', $out2) . "\n");
    exit(1);
}

// Mirror the new address into any firewall Host alias the keepers manage. Runs in
// a SEPARATE php process so its MVC Config singleton sees the write_config above
// (the legacy write here is not visible to a model loaded in this same process).
$out = array();
$rc = 0;
exec('/usr/local/opnsense/scripts/OPNsense/CarpVipDhcp/manage_alias.php 2>&1', $out, $rc);
if ($rc !== 0) {
    // Non-fatal: the address has followed and CARP is advertising it; only the
    // firewall alias mirror lags. Surface it so `sync_aliases` can be re-run.
    fwrite(STDERR, "manage_alias failed (rc={$rc}): " . implode(' | ', $out) . "\n");
}

echo "updated CARP VIP {$old_ip} -> {$new_ip}\n";
