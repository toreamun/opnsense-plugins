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
 * How the keeper fields of model 1.3.0 map onto those of 1.4.0, for the
 * migration (Migrations/M1_4_0.php). Plain PHP with no OPNsense dependency, so a
 * php script tests it in CI. Every mapping keeps what goes on the wire: the
 * same bytes in option 60 and 61 (only their place among the options can move),
 * and the same follow / demote behaviour.
 */
class LegacyKeeperFields
{
    /** The client-id value the daemon reads as hardware type 1 + chaddr (any case). */
    private const CLIENT_ID_MAC = 'mac';

    /**
     * The IPv4 lease policy for the former followIp / demoteOnLeaseLoss
     * checkboxes ('1' = on). Follow and demote never went together (the model
     * refused it), so follow wins if a hand-edited config has both.
     */
    public static function leasePolicy($followIp, $demoteOnLeaseLoss)
    {
        if ((string)$followIp === '1') {
            return 'follow';
        }
        return (string)$demoteOnLeaseLoss === '1' ? 'failover' : 'enforce';
    }

    /**
     * The Client identifier choice and the Send Options for the former vendor
     * class and client-id fields, added to any Send Options already set.
     * Returns ['clientIdentifier' => default|none|options, 'sendOptions' => text].
     *  - client-id "mac" (any case) -> default: type 1 + chaddr, as before;
     *  - empty client-id -> none: no option 61, as before;
     *  - any other client-id -> options, with dhcp-client-identifier "<text>":
     *    quoted, so it stays text bytes as before (never read as hex);
     *  - a vendor class -> a dhcp-class-identifier "<text>" line.
     */
    public static function identity($vendorClass, $clientId, $sendOptions)
    {
        $vendorClass = (string)$vendorClass;
        $clientId = (string)$clientId;
        $lines = [];
        if ($vendorClass !== '') {
            $lines[] = 'dhcp-class-identifier "' . $vendorClass . '"';
        }
        if (strtolower(trim($clientId)) === self::CLIENT_ID_MAC) {
            $mode = 'default';
        } elseif ($clientId === '') {
            $mode = 'none';
        } else {
            $mode = 'options';
            $lines[] = 'dhcp-client-identifier "' . $clientId . '"';
        }
        if (trim((string)$sendOptions) !== '') {
            $lines[] = trim((string)$sendOptions);
        }
        return ['clientIdentifier' => $mode, 'sendOptions' => implode("\n", $lines)];
    }
}
