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

function keeper($ref, $vip, $on = true, $override = '')
{
    return ['ref' => $ref, 'vmacEgress' => $on, 'carpVip' => $vip, 'chaddrOverride' => $override];
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
foreach (['', 'track6', '100.64.4.2'] as $type) {
    $ifaces = $wanStatic;
    $ifaces['wan']['ipaddr'] = $type;
    check(errors([keeper($k, '100.64.4.102')], $oneVip, $ifaces) === [], "ipaddr '$type': accepted");
}

// Another keeper's VIP on the same device, on or off, enabled or not: the keeper refuses
// at run time (shared-iface), so the save does too. The other keeper itself, with the
// option off, gets no error.
$twoOnWan = [vip('100.64.4.102', 'wan', '149'), vip('100.64.4.103', 'wan', '149')];
$k2 = 'carpvipdhcp.keepers.keeper.b';
refused('another keeper on the device', errors([keeper($k, '100.64.4.102'), keeper($k2, '100.64.4.103', false)], $twoOnWan, $wanStatic), "$k.vmacEgress", 'Another keeper');
$both = errors([keeper($k, '100.64.4.102'), keeper($k2, '100.64.4.103')], $twoOnWan, $wanStatic);
check(count($both) === 2, 'both keepers on: one error each, got ' . count($both));

// A keeper on another device does not count.
$otherDev = [vip('100.64.4.102', 'wan', '149'), vip('10.0.0.1', 'lan', '1')];
check(errors([keeper($k, '100.64.4.102'), keeper($k2, '10.0.0.1')], $otherDev, $wanStatic) === [], 'other keeper on another device: accepted');

// Two interface keys on the same device (assignments that share a device) count as one.
$sameDev = $wanStatic + ['opt1' => ['if' => 'vtnet0', 'ipaddr' => '100.64.5.2']];
refused('another keeper via another key, same device', errors([keeper($k, '100.64.4.102'), keeper($k2, '100.64.5.9', false)], [vip('100.64.4.102', 'wan', '149'), vip('100.64.5.9', 'opt1', '150')], $sameDev), "$k.vmacEgress", 'Another keeper');

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

// Several requirements at once each get their own message.
$ifaces = $wanStatic;
$ifaces['wan']['ipaddr'] = 'dhcp';
check(count(errors([keeper($k, '100.64.4.102', true, '02:00:00:00:00:01')], [vip('100.64.4.102', 'wan', '149'), vip('100.64.4.50', 'wan', '150')], $ifaces)) === 3, 'override, other vhid and DHCP: three errors');

echo "$checks checks, $failures failures\n";
exit($failures ? 1 : 0);
