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

namespace OPNsense\CarpVipDhcp\Migrations;

use OPNsense\Base\BaseModelMigration;
use OPNsense\CarpVipDhcp\LegacyKeeperFields;
use OPNsense\Core\Config;

/**
 * Model 1.4.0: the followIp / demoteOnLeaseLoss checkboxes become the IPv4 lease
 * policy, and the vendor class / client-id fields become the Client identifier
 * choice plus Send Options lines (see LegacyKeeperFields). The old fields are no
 * longer in the model, so they are read from the stored config by keeper uuid.
 * What goes on the wire does not change: a field missing from the stored config
 * reads as empty, which is also what the 1.3.0 template rendered for it
 * (followIp|default('0'), clientId|default('')).
 *
 * Core finds a migration by this name (M<major>_<minor>_<patch>), so it cannot
 * be PascalCase.
 */
// phpcs:ignore Squiz.Classes.ValidClassName
class M1_4_0 extends BaseModelMigration
{
    public function run($model)
    {
        $config = Config::getInstance()->object();
        if (!isset($config->OPNsense->CarpVipDhcp->keepers->keeper)) {
            return;
        }
        $old = [];
        $byPosition = [];
        foreach ($config->OPNsense->CarpVipDhcp->keepers->keeper as $keeper) {
            $old[(string)$keeper->attributes()->uuid] = $keeper;
            $byPosition[] = $keeper;
        }
        $position = 0;
        foreach ($model->keepers->keeper->iterateItems() as $uuid => $keeper) {
            /* A stored keeper without a uuid gets a new one on load, in the same
               order, so fall back to its position rather than lose its fields. */
            $stored = $old[$uuid] ?? $byPosition[$position] ?? null;
            $position++;
            if ($stored === null) {
                continue;
            }
            $keeper->leasePolicy = LegacyKeeperFields::leasePolicy(
                (string)$stored->followIp,
                (string)$stored->demoteOnLeaseLoss
            );
            $identity = LegacyKeeperFields::identity(
                (string)$stored->vendorClass,
                (string)$stored->clientId,
                (string)$stored->sendOptions
            );
            $keeper->clientIdentifier = $identity['clientIdentifier'];
            $keeper->sendOptions = $identity['sendOptions'];
        }
    }
}
