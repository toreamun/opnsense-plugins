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
 * Renders the Status page (Interfaces > Virtual IPs DHCP > Status).
 */
class StatusController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        // Installed plugin version, resolved once per page load (not per status
        // poll), so an operator can confirm an upgrade took and spot HA version
        // skew by comparing each node's Status page.
        $version = trim((string)(new \OPNsense\Core\Backend())->configdRun('carpvipdhcp version'));
        $this->view->pluginVersion = $version !== '' ? $version : gettext('unknown');
        $this->view->pick('OPNsense/CarpVipDhcp/status');
    }
}
