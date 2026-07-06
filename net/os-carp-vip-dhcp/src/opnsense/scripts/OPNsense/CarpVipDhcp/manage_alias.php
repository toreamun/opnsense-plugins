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
 * alias the operator can remove by hand. It also never touches an alias it does
 * not own (one whose description lacks the plugin marker).
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
foreach ($wanted as $name => $ip) {
    if (isset($existing[$name])) {
        $item = $existing[$name];
        if (strpos((string)$item->description, $marker) === false) {
            fwrite(STDERR, sprintf(
                "alias '%s' exists but is not managed by %s -- leaving it untouched\n",
                $name,
                $marker
            ));
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
        $item->description = 'Managed by os-carp-vip-dhcp (current CARP VIP address)';
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
