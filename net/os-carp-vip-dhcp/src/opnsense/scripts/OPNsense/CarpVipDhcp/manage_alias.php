#!/usr/local/bin/php
<?php

/*
 * manage_alias.php
 *
 * Reconcile the firewall Host aliases that mirror each keeper's CARP VIP address.
 * For every ENABLED keeper with a non-empty aliasName, ensure a firewall Host
 * alias of that name exists and its content equals the keeper's current carpVip.
 *
 * Point outbound NAT (and any rule that must follow a dynamic address) at the
 * alias: on a follow the plugin updates the alias content and the pf table is
 * refreshed live, so the rules follow without a ruleset reload.
 *
 * Any change (create or content update) is applied with a full `filter reload`,
 * which re-renders the alias definitions from the saved config and is
 * state-preserving. A bare `refresh_aliases` only reloads the last-rendered
 * tables and would leave the pf table stale. The plugin never deletes aliases -
 * they may be referenced elsewhere - so clearing aliasName just leaves a stale
 * alias the operator can remove by hand. A same-named **Host** alias created by
 * hand is ADOPTED (stamped with the plugin marker and kept in sync), so an
 * operator can pre-create the alias and stage NAT/rules that reference it before
 * the keeper first runs; a non-Host alias of that name is left untouched.
 *
 * Run standalone (configd action `carpvipdhcp sync_aliases`) so it reads the
 * current on-disk config; do NOT call it in the same php process that just did a
 * legacy write_config (the MVC Config singleton would not see that write).
 */

require_once('config.inc');
require_once('util.inc');

use OPNsense\Core\Config;
use OPNsense\Core\Backend;
use OPNsense\Firewall\Alias;

$cfg = Config::getInstance()->object();

// Collect desired alias name -> IP from enabled keepers.
$wanted = [];
if (isset($cfg->OPNsense->CarpVipDhcp->keepers->keeper)) {
    foreach ($cfg->OPNsense->CarpVipDhcp->keepers->keeper as $keeper) {
        $name = trim((string)$keeper->aliasName);
        $ip = trim((string)$keeper->carpVip);
        if ((string)$keeper->enabled === '1' && $name !== '' && $ip !== '') {
            $wanted[$name] = $ip;
        }
    }
}
if (empty($wanted)) {
    exit(0);
}

$mdl = new Alias();
$existing = [];
foreach ($mdl->aliases->alias->iterateItems() as $item) {
    $existing[(string)$item->name] = $item;
}

$created = false;
$changed = false;
$marker = 'os-carp-vip-dhcp';
$managed_desc = 'Managed by os-carp-vip-dhcp (current CARP VIP address)';
foreach ($wanted as $name => $ip) {
    if (isset($existing[$name])) {
        $item = $existing[$name];
        if (strpos((string)$item->description, $marker) === false) {
            // A same-named alias exists that the plugin did not create. Adopt it
            // -- stamp the marker and take over its content -- so an operator can
            // pre-create the alias and stage NAT/rules that reference it before
            // the keeper first runs. Only a Host alias, though: taking over a
            // Network/URL/port/etc. alias would change its meaning, so those are
            // left untouched with a warning.
            if ((string)$item->type !== 'host') {
                fwrite(STDERR, sprintf(
                    "alias '%s' exists as a '%s' alias (not Host) -- leaving it untouched\n",
                    $name,
                    (string)$item->type
                ));
                continue;
            }
            $item->description = $managed_desc;
            $item->content = $ip;
            $changed = true;
            fwrite(STDERR, sprintf("adopted pre-existing Host alias '%s'\n", $name));
            continue;
        }
        if ((string)$item->type !== 'host' || (string)$item->content !== $ip) {
            $item->type = 'host';
            $item->content = $ip;
            $changed = true;
        }
    } else {
        $item = $mdl->aliases->alias->Add();
        $item->name = $name;
        $item->type = 'host';
        $item->content = $ip;
        $item->description = $managed_desc;
        $created = true;
    }
}

if (!$created && !$changed) {
    exit(0);
}

$val = $mdl->performValidation();
if ($val->count() > 0) {
    foreach ($val as $msg) {
        fwrite(STDERR, sprintf("alias validation: %s %s\n", $msg->getField(), $msg->getMessage()));
    }
    exit(1);
}

$mdl->serializeToConfig();
Config::getInstance()->save();

// Apply via a full filter reload. A bare `refresh_aliases` only reloads the
// LAST-RENDERED alias tables, so a content change written here would not reach
// pf (the table would keep the old address). `filter reload` re-renders the
// alias definitions from the saved config and is state-preserving, so
// established connections are not dropped.
(new Backend())->configdRun('filter reload');
echo $created ? "alias created + reloaded\n" : "alias updated + reloaded\n";
