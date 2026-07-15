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

use OPNsense\Base\BaseModel;
use OPNsense\Base\Messages\Message;

/**
 * Model for the CARP-VIP DHCP lease keeper.
 *
 * Most behaviour comes from BaseModel + the field definitions in CarpVipDhcp.xml.
 * Derived values (interface / chaddr / request-IP from the referenced CARP VIP)
 * are resolved at render time in the configd template.
 */
class CarpVipDhcp extends BaseModel
{
    /**
     * The daemon is IPv4 DHCP only, so a keeper must reference an IPv4 CARP VIP.
     * {@inheritdoc}
     */
    public function performValidation($validateFullModel = false)
    {
        $messages = parent::performValidation($validateFullModel);
        foreach ($this->getFlatNodes() as $key => $node) {
            if (!$validateFullModel && !$node->isFieldChanged()) {
                continue;
            }
            if ($node->getInternalXMLTagName() !== 'carpVip') {
                continue;
            }
            $value = (string)$node;
            if ($value !== '' && !filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $messages->appendMessage(new Message(
                    gettext('This plugin supports IPv4 DHCP only; select an IPv4 CARP virtual IP.'),
                    $key
                ));
            }
        }

        // Cross-keeper invariants. Each CARP VIP and each firewall alias may be
        // driven by at most one keeper (two keepers fighting over the same VIP
        // or alias would flap it), and follow-mode is incompatible with
        // lease-loss demotion: a following keeper adopts a new address instead
        // of losing its lease, so it must never demote CARP on a change.
        $vipSeen = [];
        $aliasSeen = [];
        foreach ($this->keepers->keeper->iterateItems() as $keeper) {
            $base = $keeper->__reference;
            $vip = (string)$keeper->carpVip;
            if ($vip !== '') {
                if (isset($vipSeen[$vip])) {
                    $messages->appendMessage(new Message(
                        gettext('Another keeper already manages this CARP virtual IP.'),
                        $base . '.carpVip'
                    ));
                }
                $vipSeen[$vip] = true;
            }
            $alias = (string)$keeper->aliasName;
            if ($alias !== '') {
                if (isset($aliasSeen[$alias])) {
                    $messages->appendMessage(new Message(
                        gettext('Another keeper already syncs this firewall alias.'),
                        $base . '.aliasName'
                    ));
                }
                $aliasSeen[$alias] = true;
            }
            if ((string)$keeper->followIp === '1' && (string)$keeper->demoteOnLeaseLoss === '1') {
                $messages->appendMessage(new Message(
                    gettext('Follow mode and "demote on lease loss" are mutually exclusive: a '
                        . 'following keeper adopts the new address instead of losing its lease.'),
                    $base . '.demoteOnLeaseLoss'
                ));
            }
        }

        return $messages;
    }
}
