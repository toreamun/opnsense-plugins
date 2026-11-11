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
 * experimental, #131). The keeper refuses most of the same things at run time, with
 * the reason on the Status page (leasekeeper/vmac.py); this catches them when a
 * keeper is saved. Plain data in and out, so it is tested without the framework
 * (tests/php/test_vmac_egress_rules.php); CarpVipDhcp::performValidation gathers the
 * data.
 *
 * Only what is being saved is judged: a keeper with the option on when it changed,
 * and another keeper on the same device when that one changed (the message then sits
 * on its own VIP field, where its dialog shows it). Switching a keeper off is not a
 * change to judge (it must always be possible); switching it on is. A keeper's own
 * refusal sits on the option's field when the save changed the option, else on the
 * field the save did change: the option's row is advanced-only, and a message on a
 * hidden row would not be seen. The other keepers count enabled
 * or not, like the model's other cross-keeper invariants. A requirement broken later
 * outside this model (a WAN switched to DHCP, a CARP VIP added on Interfaces: Virtual
 * IPs) does not block saving an unrelated keeper; the keeper's run-time checks cover
 * a DHCP WAN and another keeper on the interface.
 */
class VmacEgressRules
{
    /**
     * IPv4 address types where the node's own WAN address is leased (D6). The node's
     * own traffic would also leave from the lease MAC while master, and an ISP that
     * binds the MAC drops it; the keeper also refuses at run time when a DHCP client
     * runs on the interface.
     */
    public const DYNAMIC_TYPES = ['dhcp', 'pppoe', 'pptp', 'l2tp'];

    /**
     * The same for IPv6: an address from DHCPv6 or SLAAC is the node's own too, and
     * dhcp6c's own packets would also leave from the lease MAC. Not checked at run
     * time.
     */
    public const DYNAMIC_TYPES_V6 = ['dhcp6', 'slaac'];

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
     * The last match wins, as in the keeper.conf template (its loop never breaks).
     */
    private static function resolve($address, array $vips, array $ifaces)
    {
        $found = null;
        foreach ($vips as $vip) {
            if (($vip['mode'] ?? '') === 'carp' && ($vip['subnet'] ?? '') === $address) {
                $key = (string)($vip['interface'] ?? '');
                $found = [$key, self::device($key, $ifaces), (string)($vip['vhid'] ?? '')];
            }
        }
        return $found;
    }

    /** The fields a keeper's own refusal may sit on, the first one the save changed. */
    private const MESSAGE_FIELDS = ['vmacEgress', 'carpVip', 'enabled', 'chaddrOverride'];

    /**
     * The fields of a keeper this save changes that are judged: all of 'changed',
     * less 'enabled' when the keeper is now disabled (switching it off is never
     * refused).
     */
    private static function changedFields(array $keeper)
    {
        $fields = (array)($keeper['changed'] ?? []);
        if (empty($keeper['enabled'])) {
            $fields = array_diff($fields, ['enabled']);
        }
        return array_values(array_intersect(self::MESSAGE_FIELDS, $fields));
    }

    /**
     * @param array $keepers each ['ref' => model reference, 'vmacEgress' => bool,
     *                       'enabled' => bool, 'carpVip' => address,
     *                       'chaddrOverride' => MAC or '', 'changed' => the names of
     *                       the fields this save changes (of enabled, carpVip,
     *                       chaddrOverride, vmacEgress)]
     * @param array $vips    the virtualip.vip entries: 'mode', 'subnet', 'interface', 'vhid'
     * @param array $ifaces  interface key => ['if' => device, 'ipaddr' => IPv4 type or
     *                       address, 'ipaddrv6' => IPv6 type or address]
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
            $fields = self::changedFields($keeper);
            $changed = $fields !== [];
            $field = $keeper['ref'] . '.' . ($fields[0] ?? 'vmacEgress');
            // D4: rewriting to the CARP virtual MAC would send the VIP's traffic from a
            // MAC the ISP never leased to; rewriting to the override would make CARP's
            // ARP replies carry the virtual MAC inside and the override outside (gear
            // with dynamic ARP inspection may drop them). If ever needed: rewrite to
            // the override after a bench round that checks both.
            if ($changed && (string)($keeper['chaddrOverride'] ?? '') !== '') {
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
                if ($j === $i || $devices[$j] !== $device) {
                    continue;
                }
                $shared = true;
                if ($changed) {
                    $errors[] = [$field, sprintf(gettext(
                        'Another keeper\'s CARP VIP is on %s. It would send from this MAC too, '
                        . 'and an interface has room for one rewrite.'
                    ), $device)];
                }
                if (self::changedFields($other) !== []) {
                    $errors[] = [$other['ref'] . '.carpVip', sprintf(gettext(
                        'The keeper for %s sends from its lease MAC on %s (experimental option), so no other '
                        . 'keeper may use a CARP VIP on that interface.'
                    ), (string)($keeper['carpVip'] ?? ''), $device)];
                }
            }
            if (!$changed) {
                continue;
            }
            // Any other CARP group on the device (another keeper's is reported above).
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
            $type6 = (string)($ifaces[$key]['ipaddrv6'] ?? '');
            if (in_array($type, self::DYNAMIC_TYPES, true)) {
                $errors[] = [$field, sprintf(gettext(
                    'Sending from the lease MAC needs a static address on this node\'s WAN (%s uses %s). '
                    . 'Its own traffic would leave from the lease MAC too.'
                ), $device, strtoupper($type))];
            } elseif (in_array($type6, self::DYNAMIC_TYPES_V6, true)) {
                $errors[] = [$field, sprintf(gettext(
                    'Sending from the lease MAC needs a static IPv6 address, or none, on this node\'s WAN '
                    . '(%s uses %s). Its own IPv6 traffic would leave from the lease MAC too.'
                ), $device, strtoupper($type6))];
            }
        }
        return $errors;
    }

    /** The marker file left for a removal that could not be confirmed (vmac.sh, vmac.py). */
    public const LEFT_PREFIX = 'carpvipdhcp-vmac.left.';

    /**
     * The nodes whose removal could not be confirmed, from the paths of the marker files
     * the shell side and the keeper leave (vmac.sh, vmac.py: one empty file per node,
     * created when a removal fails, removed when one is confirmed). Only well-formed
     * names of ours count (an interface name may hold '-'), so a stray file cannot
     * inject text into the system status message.
     *
     * @param array $paths the marker file paths (a glob of LEFT_PREFIX in the run directory)
     * @return array       the node names, sorted, without duplicates
     */
    public static function leftoverNodes(array $paths)
    {
        $nodes = [];
        foreach ($paths as $path) {
            $name = basename((string)$path);
            if (strncmp($name, self::LEFT_PREFIX, strlen(self::LEFT_PREFIX)) !== 0) {
                continue;
            }
            $node = substr($name, strlen(self::LEFT_PREFIX));
            if (preg_match('/^vmac_[A-Za-z0-9_-]{1,26}$/', $node)) {
                $nodes[$node] = true;
            }
        }
        $nodes = array_keys($nodes);
        sort($nodes);
        return $nodes;
    }
}
