<?php

/*
 * Tests for OPNsense\CarpVipDhcp\VmacEgressRules: the save-time requirements of
 * "Send from the lease MAC while master" (experimental, #131). Each requirement the
 * keeper refuses at run time (leasekeeper/vmac.py) must also be refused here, on the
 * keeper's vmacEgress field; a keeper with the option off is never refused. Plain
 * php, no framework:
 *     php net/os-carp-vip-dhcp/tests/php/test_vmac_egress_rules.php
 */

if (!function_exists('gettext')) {
    function gettext($text)
    {
        return $text;
    }
}

require __DIR__ . '/../../src/opnsense/mvc/app/models/OPNsense/CarpVipDhcp/VmacEgressRules.php';

use OPNsense\CarpVipDhcp\VmacEgressRules;

$failures = 0;
$checks = 0;

function check($cond, $what)
{
    global $failures, $checks;
    $checks++;
    if (!$cond) {
        $failures++;
        echo "FAIL: $what\n";
    }
}

/* A keeper as the model gives it; "changed": this save changes it. */
function keeper($ref, $vip, $on = true, $override = '', $changed = true)
{
    return ['ref' => $ref, 'vmacEgress' => $on, 'carpVip' => $vip, 'chaddrOverride' => $override,
            'changed' => $changed];
}

function vip($subnet, $iface, $vhid, $mode = 'carp')
{
    return ['mode' => $mode, 'subnet' => $subnet, 'interface' => $iface, 'vhid' => $vhid];
}

/* The errors for one setup, as "field: message" lines. */
function errors($keepers, $vips, $ifaces)
{
    return array_map(function ($e) {
        return $e[0] . ': ' . $e[1];
    }, VmacEgressRules::check($keepers, $vips, $ifaces));
}

/* Exactly one error, on $field, whose message contains $needle. */
function refused($what, $errs, $field, $needle)
{
    check(count($errs) === 1, "$what: want one error, got " . count($errs) . ': ' . implode(' | ', $errs));
    check(
        count($errs) === 1 && strpos($errs[0], "$field: ") === 0 && strpos($errs[0], $needle) !== false,
        "$what: want '$needle' on $field, got " . implode(' | ', $errs)
    );
}

$wanStatic = ['wan' => ['if' => 'vtnet0', 'ipaddr' => '100.64.4.2'], 'lan' => ['if' => 'vtnet1', 'ipaddr' => '10.0.0.2']];
$oneVip = [vip('100.64.4.102', 'wan', '149'), vip('10.0.0.1', 'lan', '1')];
$k = 'carpvipdhcp.keepers.keeper.a';

// The supported setup: a static WAN, one keeper and one CARP VIP on it, no override.
check(errors([keeper($k, '100.64.4.102')], $oneVip, $wanStatic) === [], 'static WAN, one VIP: accepted');

// Off is never refused, whatever the setup.
foreach (['dhcp', 'pppoe'] as $type) {
    $ifaces = $wanStatic;
    $ifaces['wan']['ipaddr'] = $type;
    check(errors([keeper($k, '100.64.4.102', false, '02:00:00:00:00:01')], $oneVip, $ifaces) === [], "off on a $type WAN with an override: accepted");
}

// D4: a Client MAC override.
refused('override', errors([keeper($k, '100.64.4.102', true, '02:00:00:00:00:01')], $oneVip, $wanStatic), "$k.vmacEgress", 'Client MAC override');

// D6: the node's own WAN address leased; every dynamic type, and a static one passes.
foreach (VmacEgressRules::DYNAMIC_TYPES as $type) {
    $ifaces = $wanStatic;
    $ifaces['wan']['ipaddr'] = $type;
    refused("$type WAN", errors([keeper($k, '100.64.4.102')], $oneVip, $ifaces), "$k.vmacEgress", 'static address');
}
foreach (['', '100.64.4.2'] as $type) {
    $ifaces = $wanStatic;
    $ifaces['wan']['ipaddr'] = $type;
    check(errors([keeper($k, '100.64.4.102')], $oneVip, $ifaces) === [], "ipaddr '$type': accepted");
}

// Another keeper's VIP on the same device, on or off, enabled or not: the keeper refuses
// at run time (shared-iface), so the save does too, on the keeper being saved.
$twoOnWan = [vip('100.64.4.102', 'wan', '149'), vip('100.64.4.103', 'wan', '149')];
$k2 = 'carpvipdhcp.keepers.keeper.b';
refused('another keeper on the device, saving the option', errors([keeper($k, '100.64.4.102'), keeper($k2, '100.64.4.103', false, '', false)], $twoOnWan, $wanStatic), "$k.vmacEgress", 'Another keeper');
// Saving the other keeper (added, or its VIP moved there): the message is on its own VIP
// field, which its dialog shows, not on a field of the keeper it does not edit.
refused('another keeper on the device, saving that one', errors([keeper($k, '100.64.4.102', true, '', false), keeper($k2, '100.64.4.103', false)], $twoOnWan, $wanStatic), "$k2.carpVip", 'sends from its lease MAC');
// Both saved with the option on: each refused on its own option and on its VIP.
$both = errors([keeper($k, '100.64.4.102'), keeper($k2, '100.64.4.103')], $twoOnWan, $wanStatic);
check(count($both) === 4, 'both keepers on and saved: four errors, got ' . count($both) . ': ' . implode(' | ', $both));
foreach (["$k.vmacEgress", "$k2.vmacEgress", "$k.carpVip", "$k2.carpVip"] as $f) {
    check(count(array_filter($both, function ($e) use ($f) {
        return strpos($e, "$f: ") === 0;
    })) === 1, "both saved: one error on $f");
}

// Only what is saved is judged: a keeper with the option on that this save does not
// change is not refused for what changed elsewhere (a WAN switched to DHCP, a CARP VIP
// added, an override), so an unrelated keeper can still be saved.
$ifaces = $wanStatic;
$ifaces['wan']['ipaddr'] = 'dhcp';
check(errors([keeper($k, '100.64.4.102', true, '02:00:00:00:00:01', false)], [vip('100.64.4.102', 'wan', '149'), vip('100.64.4.50', 'wan', '150')], $ifaces) === [], 'unchanged keeper: not judged');
check(errors([keeper($k, '100.64.4.102', true, '', false), keeper($k2, '10.0.0.1')], [vip('100.64.4.102', 'wan', '149'), vip('10.0.0.1', 'lan', '1')], $ifaces) === [], 'saving a keeper on another device: accepted');

// A keeper on another device does not count.
$otherDev = [vip('100.64.4.102', 'wan', '149'), vip('10.0.0.1', 'lan', '1')];
check(errors([keeper($k, '100.64.4.102'), keeper($k2, '10.0.0.1')], $otherDev, $wanStatic) === [], 'other keeper on another device: accepted');

// Two interface keys on the same device (assignments that share a device) count as one.
$sameDev = $wanStatic + ['opt1' => ['if' => 'vtnet0', 'ipaddr' => '100.64.5.2']];
refused('another keeper via another key, same device', errors([keeper($k, '100.64.4.102'), keeper($k2, '100.64.5.9', false, '', false)], [vip('100.64.4.102', 'wan', '149'), vip('100.64.5.9', 'opt1', '150')], $sameDev), "$k.vmacEgress", 'Another keeper');

// Another CARP VIP (not a keeper's) with a different vhid on the device.
refused('another vhid on the device', errors([keeper($k, '100.64.4.102')], [vip('100.64.4.102', 'wan', '149'), vip('100.64.4.50', 'wan', '150')], $wanStatic), "$k.vmacEgress", 'vhid 150');
// ... also when that VIP is on another interface key of the same device.
refused('another vhid via another key, same device', errors([keeper($k, '100.64.4.102')], [vip('100.64.4.102', 'wan', '149'), vip('100.64.5.9', 'opt1', '150')], $sameDev), "$k.vmacEgress", 'vhid 150');
// The same vhid (a second address of the same CARP group, an IPv6 VIP) is fine, as is
// an IP alias or a VIP on another device.
check(errors([keeper($k, '100.64.4.102')], [vip('100.64.4.102', 'wan', '149'), vip('2001:db8::1', 'wan', '149')], $wanStatic) === [], 'same vhid on the device: accepted');
check(errors([keeper($k, '100.64.4.102')], [vip('100.64.4.102', 'wan', '149'), vip('100.64.4.60', 'wan', '', 'ipalias')], $wanStatic) === [], 'an IP alias on the device: accepted');

// An unresolvable VIP renders no keeper: nothing to check beyond the override.
check(errors([keeper($k, '100.64.9.9')], $oneVip, $wanStatic) === [], 'unresolved VIP: no error');
refused('unresolved VIP with an override', errors([keeper($k, '100.64.9.9', true, '02:00:00:00:00:01')], $oneVip, $wanStatic), "$k.vmacEgress", 'Client MAC override');
check(errors([keeper($k, '100.64.4.102')], $oneVip, ['lan' => $wanStatic['lan']]) === [], 'VIP on an unknown interface key: no error');
// Two keepers whose VIPs both resolve to no device are not "on the same device".
check(errors([keeper($k, '100.64.4.102'), keeper($k2, '100.64.4.103')], $twoOnWan, ['lan' => $wanStatic['lan']]) === [], 'two VIPs on unknown keys: no error');

// IPv6: an address from DHCPv6 or SLAAC is the node's own too; static, none and
// tracking another interface are fine. A dynamic IPv4 type is reported first.
foreach (VmacEgressRules::DYNAMIC_TYPES_V6 as $type) {
    $ifaces = $wanStatic;
    $ifaces['wan']['ipaddrv6'] = $type;
    refused("$type IPv6 WAN", errors([keeper($k, '100.64.4.102')], $oneVip, $ifaces), "$k.vmacEgress", 'static IPv6 address');
}
foreach (['', 'track6', '2001:db8::2'] as $type) {
    $ifaces = $wanStatic;
    $ifaces['wan']['ipaddrv6'] = $type;
    check(errors([keeper($k, '100.64.4.102')], $oneVip, $ifaces) === [], "ipaddrv6 '$type': accepted");
}
$ifaces = $wanStatic;
$ifaces['wan']['ipaddr'] = 'dhcp';
$ifaces['wan']['ipaddrv6'] = 'dhcp6';
refused('DHCP and DHCPv6', errors([keeper($k, '100.64.4.102')], $oneVip, $ifaces), "$k.vmacEgress", 'static address on');

// Two CARP VIPs with the same address (a broken config): the last one counts, as in the
// keeper.conf template.
refused('duplicate VIP address: the last one counts', errors([keeper($k, '100.64.4.102')], [vip('100.64.4.102', 'lan', '1'), vip('100.64.4.102', 'wan', '149')], ['wan' => ['if' => 'vtnet0', 'ipaddr' => 'dhcp'], 'lan' => $wanStatic['lan']]), "$k.vmacEgress", 'vtnet0 uses DHCP');

// Several requirements at once each get their own message.
$ifaces = $wanStatic;
$ifaces['wan']['ipaddr'] = 'dhcp';
check(count(errors([keeper($k, '100.64.4.102', true, '02:00:00:00:00:01')], [vip('100.64.4.102', 'wan', '149'), vip('100.64.4.50', 'wan', '150')], $ifaces)) === 3, 'override, other vhid and DHCP: three errors');

// rendersStaleKeep: a keeper.conf the stop would read is stale when a record keeps the
// rewrite (vmacegress=1) that no enabled keeper with the option on asks for. A fresh
// render never is, so Apply is never refused for a current file.
function enabled($ref, $vip, $on = true, $isEnabled = true)
{
    return ['ref' => $ref, 'enabled' => $isEnabled, 'vmacEgress' => $on, 'carpVip' => $vip];
}
$rec = function ($request, $on, $iface = 'vtnet0') {
    return "request=$request|iface=$iface|chaddr=00:00:5e:00:01:95|vhid=149|vmacegress=$on";
};
$head = "# rendered keeper.conf\n";
check(!VmacEgressRules::rendersStaleKeep($head . $rec('100.64.4.102', '1') . "\n", [enabled($k, '100.64.4.102')]), 'fresh render with the option on: not stale');
check(!VmacEgressRules::rendersStaleKeep($head . $rec('100.64.4.102', '0') . "\n", [enabled($k, '100.64.4.102', false)]), 'option off in both: not stale');
check(!VmacEgressRules::rendersStaleKeep($head, []), 'no keepers, empty render: not stale');
check(!VmacEgressRules::rendersStaleKeep($head . $rec('100.64.4.102', '0') . "\n", []), 'a stale record with the option off keeps nothing: not stale');
check(VmacEgressRules::rendersStaleKeep($head . $rec('100.64.4.102', '1') . "\n", []), 'keeper deleted, old record keeps: stale');
check(VmacEgressRules::rendersStaleKeep($head . $rec('100.64.4.102', '1') . "\n", [enabled($k, '100.64.4.102', true, false)]), 'keeper disabled: stale');
check(VmacEgressRules::rendersStaleKeep($head . $rec('100.64.4.102', '1') . "\n", [enabled($k, '100.64.4.102', false)]), 'option turned off: stale');
check(VmacEgressRules::rendersStaleKeep($head . $rec('100.64.4.102', '1') . "\n", [enabled($k, '100.64.4.103')]), 'VIP changed: stale');
check(VmacEgressRules::rendersStaleKeep("  " . $rec('100.64.4.102', '1') . "  \r\n", []), 'whitespace around a record is ignored, as keeperconf.py does');
check(!VmacEgressRules::rendersStaleKeep("# was: |" . $rec('100.64.4.102', '1') . "\n", []), 'a comment line is not a record');
check(!VmacEgressRules::rendersStaleKeep("iface=vtnet0|vmacegress=1\n", []), 'a line without a request is skipped');
check(VmacEgressRules::rendersStaleKeep("request=100.64.4.102|vmacegress=0|vmacegress=1\n", []), 'the last of a key wins');
check(!VmacEgressRules::rendersStaleKeep("request=100.64.4.102|vmacegress=1|vmacegress=0\n", []), 'the last of a key wins (off)');
check(VmacEgressRules::rendersStaleKeep($head . $rec('100.64.4.9', '0') . "\n" . $rec('100.64.4.102', '1') . "\n", [enabled($k, '100.64.4.9', false)]), 'any stale record counts, not only the first');

// unconfirmedNodes: the stop rule's list for the system status. Missing file, empty,
// one per line, duplicates once, and nothing that is not a node name of ours.
check(VmacEgressRules::unconfirmedNodes(false) === [], 'no file: none');
check(VmacEgressRules::unconfirmedNodes('') === [], 'empty file: none');
check(VmacEgressRules::unconfirmedNodes("vmac_vtnet0\nvmac_igb0_100\nvmac_vtnet0\n") === ['vmac_vtnet0', 'vmac_igb0_100'], 'one per line, duplicates once, in order');
check(VmacEgressRules::unconfirmedNodes("  vmac_vtnet0 \r\n") === ['vmac_vtnet0'], 'whitespace trimmed');
check(VmacEgressRules::unconfirmedNodes("vtnet0\nvmac_<b>x</b>\nvmac_a b\nvmac_\nng0\n") === [], 'anything but a node name of ours is ignored');
check(VmacEgressRules::unconfirmedNodes('vmac_' . str_repeat('a', 27)) === [], 'a name longer than netgraph allows is ignored');

echo "$checks checks, $failures failures\n";
exit($failures ? 1 : 0);
