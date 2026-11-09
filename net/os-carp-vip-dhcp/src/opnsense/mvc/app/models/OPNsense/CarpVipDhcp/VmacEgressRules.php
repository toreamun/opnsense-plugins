<?php

/*
 * Copyright (C) 2026 Tore Amundsen
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY OR
 * CONSEQUENTIAL DAMAGES ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

namespace OPNsense\CarpVipDhcp;

/**
 * The save-time requirements of "Send from the lease MAC while master" (vmacEgress,
 * experimental, #131). The keeper checks the same things at run time and refuses
 * with a reason on the Status page (leasekeeper/vmac.py); this catches them when
 * the keeper is saved. Plain data in and out, so it is tested without the
 * framework (tests/php/test_vmac_egress_rules.php); CarpVipDhcp::performValidation
 * gathers the data.
 *
 * Every keeper with the option on is checked, enabled or not, and the other
 * keepers count enabled or not, like the model's other cross-keeper invariants:
 * the conflict shows when it is edited, not later when a keeper is enabled.
 */
class VmacEgressRules
{
    /**
     * Interface address types where the node's own WAN address is leased (D6). The
     * node's own traffic would also leave from the lease MAC while master, and an
     * ISP that binds the MAC drops it; the keeper also refuses at run time when a
     * DHCP client runs on the interface.
     */
    public const DYNAMIC_TYPES = ['dhcp', 'pppoe', 'pptp', 'l2tp'];

    /**
     * The device a CARP VIP's interface key maps to (what the template's
     * physical_interface gives), or '' when it does not resolve.
     */
    private static function device($key, array $ifaces)
    {
        return isset($ifaces[$key]['if']) ? (string)$ifaces[$key]['if'] : '';
    }

    /**
     * The CARP VIP a keeper's carpVip names: [interface key, device, vhid], or null.
     */
    private static function resolve($address, array $vips, array $ifaces)
    {
        foreach ($vips as $vip) {
            if (($vip['mode'] ?? '') === 'carp' && ($vip['subnet'] ?? '') === $address) {
                $key = (string)($vip['interface'] ?? '');
                return [$key, self::device($key, $ifaces), (string)($vip['vhid'] ?? '')];
            }
        }
        return null;
    }

    /**
     * @param array $keepers each ['ref' => model reference, 'vmacEgress' => bool,
     *                       'carpVip' => address, 'chaddrOverride' => MAC or '']
     * @param array $vips    the virtualip.vip entries: 'mode', 'subnet', 'interface', 'vhid'
     * @param array $ifaces  interface key => ['if' => device, 'ipaddr' => type or address]
     * @return array         [field reference, message] for every requirement not met
     */
    public static function check(array $keepers, array $vips, array $ifaces)
    {
        $errors = [];
        $devices = [];
        foreach ($keepers as $i => $keeper) {
            $vip = self::resolve((string)($keeper['carpVip'] ?? ''), $vips, $ifaces);
            $devices[$i] = $vip === null ? '' : $vip[1];
        }
        foreach ($keepers as $i => $keeper) {
            if (empty($keeper['vmacEgress'])) {
                continue;
            }
            $field = $keeper['ref'] . '.vmacEgress';
            // D4: rewriting to the CARP virtual MAC would send the VIP's traffic from a
            // MAC the ISP never leased to; rewriting to the override would make CARP's
            // ARP replies carry the virtual MAC inside and the override outside (gear
            // with dynamic ARP inspection may drop them). If ever needed: rewrite to
            // the override after a bench round that checks both.
            if ((string)($keeper['chaddrOverride'] ?? '') !== '') {
                $errors[] = [$field, gettext(
                    'Sending from the lease MAC does not work with a Client MAC override. Clear the override.'
                )];
            }
            $vip = self::resolve((string)($keeper['carpVip'] ?? ''), $vips, $ifaces);
            if ($vip === null || $vip[1] === '') {
                continue;   // the VIP itself is checked elsewhere; the keeper is not rendered
            }
            list($key, $device, $vhid) = $vip;
            $shared = false;
            foreach ($keepers as $j => $other) {
                if ($j !== $i && $devices[$j] === $device) {
                    $errors[] = [$field, sprintf(gettext(
                        'Another keeper\'s CARP VIP is on %s. It would send from this MAC too, '
                        . 'and an interface has room for one rewrite.'
                    ), $device)];
                    $shared = true;
                    break;
                }
            }
            // Any other CARP group on the device (a keeper's is reported above).
            foreach ($shared ? [] : $vips as $other) {
                if (
                    ($other['mode'] ?? '') === 'carp'
                    && self::device((string)($other['interface'] ?? ''), $ifaces) === $device
                    && (string)($other['vhid'] ?? '') !== $vhid
                ) {
                    $errors[] = [$field, sprintf(gettext(
                        'Another CARP VIP (vhid %s) is on %s. It would send from this MAC too while '
                        . 'this node is master.'
                    ), (string)($other['vhid'] ?? ''), $device)];
                    break;
                }
            }
            $type = (string)($ifaces[$key]['ipaddr'] ?? '');
            if (in_array($type, self::DYNAMIC_TYPES, true)) {
                $errors[] = [$field, sprintf(gettext(
                    'Sending from the lease MAC needs a static address on this node\'s WAN (%s uses %s). '
                    . 'Its own traffic would leave from the lease MAC too.'
                ), $device, strtoupper($type))];
            }
        }
        return $errors;
    }
}
