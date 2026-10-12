<?php

/*
 * Tests for OPNsense\CarpVipDhcp\LegacyKeeperFields (the 1.3.0 -> 1.4.0 field
 * mapping the migration uses). Every old value must migrate without a validation
 * error (one invalid row stops the whole migration) and send the same option 60
 * and 61 bytes as before. Plain php, no framework:
 *     php net/os-carp-vip-dhcp/tests/php/test_legacy_fields.php
 */

require __DIR__ . '/../../src/opnsense/mvc/app/models/OPNsense/CarpVipDhcp/DhcpOptions.php';
require __DIR__ . '/../../src/opnsense/mvc/app/models/OPNsense/CarpVipDhcp/LegacyKeeperFields.php';

use OPNsense\CarpVipDhcp\DhcpOptions;
use OPNsense\CarpVipDhcp\LegacyKeeperFields;

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
 * Migrate one old (vendor class, client-id) pair and check: the Client identifier
 * choice, that the new Send Options validate under the model's rule for that choice
 * (61 only with From Send Options), and the option 60 / 61 bytes they send.
 */
function migrates($vendorClass, $clientId, $wantMode, $want60, $want61)
{
    $r = LegacyKeeperFields::identity($vendorClass, $clientId, '');
    $what = "vendor class '$vendorClass', client-id '$clientId'";
    check($r['clientIdentifier'] === $wantMode, "$what: mode {$r['clientIdentifier']}, want $wantMode");
    $refuse61 = $r['clientIdentifier'] === 'options' ? [] : [61 => 'needs From Send Options'];
    $parsed = DhcpOptions::parseSendOptions($r['sendOptions'], $refuse61);
    check($parsed['errors'] === [], "$what: validates (got " . implode(' | ', $parsed['errors']) . ')');
    $byCode = [];
    foreach ($parsed['options'] as $option) {
        $byCode[$option[0]] = $option[1];
    }
    check(($byCode[60] ?? null) === $want60, "$what: option 60 bytes");
    check(($byCode[61] ?? null) === $want61, "$what: option 61 bytes");
}

/* ---- IPv4 lease policy from followIp / demoteOnLeaseLoss ---- */
check(LegacyKeeperFields::leasePolicy('1', '0') === 'follow', 'follow');
check(LegacyKeeperFields::leasePolicy('0', '0') === 'enforce', 'enforce');
check(LegacyKeeperFields::leasePolicy('0', '1') === 'failover', 'enforce and fail over');
check(LegacyKeeperFields::leasePolicy('1', '1') === 'follow', 'both set (hand edit): follow wins');
check(LegacyKeeperFields::leasePolicy('', '') === 'enforce', 'empty fields: enforce');

/* ---- client-id: mac (any case), empty, text ---- */
migrates('', 'mac', 'default', null, null);           /* the daemon builds type 1 + chaddr */
migrates('', 'MAC', 'default', null, null);
migrates('', 'Mac', 'default', null, null);
migrates('', '', 'none', null, null);
migrates('', 'isp-login.1', 'options', null, 'isp-login.1');
/* Looks like hex but was text before: stays text, never read as hex. */
migrates('', '01:00:5e:00:01:08', 'options', null, '01:00:5e:00:01:08');
/* Every character the old client-id mask allowed, and its longest value. */
migrates('', 'AZaz09:._-', 'options', null, 'AZaz09:._-');
migrates('', str_repeat('a', 128), 'options', null, str_repeat('a', 128));
migrates('', 'ab', 'options', null, 'ab');                /* the shortest */

/* ---- vendor class ---- */
migrates('sagem', 'mac', 'default', 'sagem', null);
/* Every character the old vendor class mask allowed, and its longest value. */
migrates('AZaz09 ._/+-', '', 'none', 'AZaz09 ._/+-', null);
migrates(str_repeat('v', 64), '', 'none', str_repeat('v', 64), null);
migrates(' padded ', '', 'none', ' padded ', null);   /* spaces are part of the value */
migrates('sagem', 'isp-login.1', 'options', 'sagem', 'isp-login.1');

/* ---- Send Options already set are kept, after the migrated lines ---- */
$r = LegacyKeeperFields::identity('sagem', '', "option-90 01\n");
check($r['sendOptions'] === "dhcp-class-identifier \"sagem\"\noption-90 01", 'existing Send Options kept');
check(LegacyKeeperFields::identity('', '', '')['sendOptions'] === '', 'nothing to migrate: no Send Options');

echo "$checks checks, $failures failed\n";
exit($failures === 0 ? 0 : 1);
