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

/*
 * A keeper as the model gives it; "changed": the fields this save changes (true: the
 * option itself, false: none).
 */
function keeper($ref, $vip, $on = true, $override = '', $changed = true, $enabled = true)
{
    $changed = $changed === true ? ['vmacEgress'] : ($changed === false ? [] : $changed);
    return ['ref' => $ref, 'vmacEgress' => $on, 'enabled' => $enabled, 'carpVip' => $vip,
            'chaddrOverride' => $override, 'changed' => $changed];
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

// Switching a keeper off is never refused, whatever broke since it was saved; switching
// it on is judged, with the message on the Enabled field (the option's row is
// advanced-only, so a message there would not be seen in basic mode).
$broken = [vip('100.64.4.102', 'wan', '149'), vip('100.64.4.50', 'wan', '150')];
check(errors([keeper($k, '100.64.4.102', true, '02:00:00:00:00:01', ['enabled'], false)], $broken, $ifaces) === [], 'switching a keeper off: accepted');
refused('switching a keeper on', errors([keeper($k, '100.64.4.102', true, '', ['enabled'], true)], $oneVip, $ifaces), "$k.enabled", 'static address');
// Off and another judged field changed in the same save: judged, on that field.
refused('off, and the VIP changed', errors([keeper($k, '100.64.4.102', true, '', ['enabled', 'carpVip'], false)], $oneVip, $ifaces), "$k.carpVip", 'static address');
// The message sits on the field the save changed; on the option when it changed too.
refused('only the VIP changed', errors([keeper($k, '100.64.4.102', true, '', ['carpVip'])], $oneVip, $ifaces), "$k.carpVip", 'static address');
refused('only the override changed', errors([keeper($k, '100.64.4.102', true, '02:00:00:00:00:01', ['chaddrOverride'])], $oneVip, $wanStatic), "$k.chaddrOverride", 'Client MAC override');
refused('the VIP and the option changed', errors([keeper($k, '100.64.4.102', true, '', ['carpVip', 'vmacEgress'])], $oneVip, $ifaces), "$k.vmacEgress", 'static address');
// Another keeper on the device that is only switched off is not refused either.
check(errors([keeper($k, '100.64.4.102', true, '', false), keeper($k2, '100.64.4.103', false, '', ['enabled'], false)], $twoOnWan, $wanStatic) === [], 'switching the other keeper off: accepted');
refused('switching the other keeper on', errors([keeper($k, '100.64.4.102', true, '', false), keeper($k2, '100.64.4.103', false, '', ['enabled'], true)], $twoOnWan, $wanStatic), "$k2.carpVip", 'sends from its lease MAC');

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

// leftoverNodes: the marker files the shell side leaves for removals it could not confirm,
// as the system status reads them. Sorted, once each, and nothing that is not a marker
// of a node name of ours.
$p = '/var/run/carpvipdhcp-vmac.left.';
check(VmacEgressRules::leftoverNodes([]) === [], 'no markers: none');
check(VmacEgressRules::leftoverNodes([$p . 'vmac_vtnet0', $p . 'vmac_igb0_100', $p . 'vmac_vtnet0']) === ['vmac_igb0_100', 'vmac_vtnet0'], 'sorted, once each');
check(VmacEgressRules::leftoverNodes(['carpvipdhcp-vmac.left.vmac_vtnet0']) === ['vmac_vtnet0'], 'a bare file name counts too');
check(VmacEgressRules::leftoverNodes([$p . 'vtnet0', $p . 'vmac_<b>x</b>', $p . 'vmac_a b', $p . 'vmac_', '/var/run/other.vmac_vtnet0', '/var/run/x/carpvipdhcp-vmac.leftvmac_a']) === [], 'anything else is ignored');
check(VmacEgressRules::leftoverNodes([$p . 'vmac_' . str_repeat('a', 27)]) === [], 'a name longer than netgraph allows is ignored');
check(VmacEgressRules::leftoverNodes([$p . 'vmac_wan-a0']) === ['vmac_wan-a0'], 'an interface name may hold a hyphen');
check(VmacEgressRules::leftoverNodes(['/var/run/carpvipdhcp-vmac.LEFT.vmac_vtnet0', '/var/run/carpvipdhcp-xxxx.left.vmac_vtnet0']) === [], 'another prefix of the same length is not a marker');

echo "$checks checks, $failures failures\n";
exit($failures ? 1 : 0);
