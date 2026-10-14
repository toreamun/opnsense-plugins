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
    /** The option code of the DHCP client identifier. */
    private const CLIENT_ID = 61;

    /**
     * What the encoded fields hold when the text does not parse: code 0, which
     * the daemon refuses, so the keeper reports a configuration error and sends
     * no DHCP instead of quietly leaving the options out (fail safe).
     */
    private const UNUSABLE_SEND = '0:00';
    private const UNUSABLE_REQUEST = '0';

    /**
     * One keeper's parsed [Send Options, Request Options] (see DhcpOptions). A
     * dhcp-client-identifier line belongs in Send Options only when the Client
     * identifier is From Send Options; otherwise the keeper sends its own 61 or
     * none.
     */
    private static function parsedOptions($keeper)
    {
        $refused = (string)$keeper->clientIdentifier === 'options' ? [] : [
            self::CLIENT_ID => 'dhcp-client-identifier (option 61) needs Client identifier set to From Send Options',
        ];
        return [
            DhcpOptions::parseSendOptions((string)$keeper->sendOptions, $refused),
            DhcpOptions::parseRequestOptions((string)$keeper->requestOptions),
        ];
    }

    /**
     * The daemon is IPv4 DHCP only, so a keeper must reference an IPv4 CARP VIP.
     * Send Options and Request Options must parse (DhcpOptions), and a Client
     * identifier From Send Options needs its dhcp-client-identifier line there.
     * {@inheritdoc}
     */
    public function performValidation($validateFullModel = false)
    {
        $messages = parent::performValidation($validateFullModel);
        foreach ($this->keepers->keeper->iterateItems() as $keeper) {
            $base = $keeper->__reference;
            list($send, $request) = self::parsedOptions($keeper);
            foreach ($send['errors'] as $error) {
                $messages->appendMessage(new Message($error, $base . '.sendOptions'));
            }
            foreach ($request['errors'] as $error) {
                $messages->appendMessage(new Message($error, $base . '.requestOptions'));
            }
            $codes = array_column($send['options'], 0);
            if ((string)$keeper->clientIdentifier === 'options' && !in_array(self::CLIENT_ID, $codes, true)) {
                $messages->appendMessage(new Message(
                    gettext('From Send Options needs a dhcp-client-identifier line in Send Options.'),
                    $base . '.clientIdentifier'
                ));
            }
        }
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
        // or alias would flap it).
        $vipSeen = [];
        $aliasSeen = [];
        $enforceSeen = false;
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
            // At most one keeper may enforce the default route: there is a single
            // 0.0.0.0/0, so two enforcing keepers would install/withdraw it against
            // each other. Checked regardless of enabled (like the vip/alias
            // invariants above) so the conflict surfaces at edit time, before a
            // later enable silently creates two FIB-fighters. observe is unlimited.
            if ((string)$keeper->defaultRouteMode === 'enforce') {
                if ($enforceSeen) {
                    $messages->appendMessage(new Message(
                        gettext('Only one keeper may enforce the default route (they would fight over '
                            . 'the single default). Set the other keepers to off or observe.'),
                        $base . '.defaultRouteMode'
                    ));
                }
                $enforceSeen = true;
            }
        }

        return $messages;
    }

    /**
     * Write the keeper.conf form of each keeper's Send Options and Request
     * Options into the derived *Encoded fields before saving, so every save path
     * (the dialog, the API, any save with validation off) stores what the
     * template renders; HA sync copies the saved fields. Text that does not parse
     * is refused by the validation of a normal save; if it is saved anyway, the
     * UNUSABLE_* marker makes the keeper report a configuration error.
     * {@inheritdoc}
     */
    public function serializeToConfig($validateFullModel = false, $disable_validation = false)
    {
        foreach ($this->keepers->keeper->iterateItems() as $keeper) {
            list($send, $request) = self::parsedOptions($keeper);
            $keeper->sendOptionsEncoded = $send['errors']
                ? self::UNUSABLE_SEND : DhcpOptions::encodeSendOptions($send['options']);
            $keeper->requestOptionsEncoded = $request['errors']
                ? self::UNUSABLE_REQUEST : DhcpOptions::encodeRequestOptions($request['codes']);
        }
        return parent::serializeToConfig($validateFullModel, $disable_validation);
    }
}
