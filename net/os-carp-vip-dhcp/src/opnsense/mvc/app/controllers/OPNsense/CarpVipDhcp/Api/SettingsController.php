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

namespace OPNsense\CarpVipDhcp\Api;

use OPNsense\Base\ApiMutableModelControllerBase;

/**
 * Settings API for the CARP-VIP DHCP lease keepers (grid CRUD over keepers.keeper).
 */
class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelClass = 'OPNsense\CarpVipDhcp\CarpVipDhcp';
    protected static $internalModelName = 'carpvipdhcp';

    public function searchKeeperAction()
    {
        return $this->searchBase(
            'keepers.keeper',
            ['enabled', 'carpVip', 'demoteOnLeaseLoss', 'followIp', 'aliasName', 'description']
        );
    }

    public function getKeeperAction($uuid = null)
    {
        return $this->getBase('keeper', 'keepers.keeper', $uuid);
    }

    public function addKeeperAction()
    {
        return $this->addBase('keeper', 'keepers.keeper');
    }

    public function setKeeperAction($uuid)
    {
        return $this->setBase('keeper', 'keepers.keeper', $uuid);
    }

    public function delKeeperAction($uuid)
    {
        return $this->delBase('keepers.keeper', $uuid);
    }

    public function toggleKeeperAction($uuid, $enabled = null)
    {
        return $this->toggleBase('keepers.keeper', $uuid, $enabled);
    }
}
