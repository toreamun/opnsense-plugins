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

use OPNsense\Base\ApiMutableServiceControllerBase;

/**
 * Service API: control the keeper daemons (start/stop/restart/reconfigure/status).
 *
 * On reconfigure the base renders the configd template and then starts/stops the
 * daemons based on serviceEnabled(). Since keepers are a list, the service counts
 * as "enabled" when at least one keeper is enabled. Backend actions are defined in
 * src/opnsense/service/conf/actions.d/actions_carpvipdhcp.conf.
 */
class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\OPNsense\CarpVipDhcp\CarpVipDhcp';
    protected static $internalServiceTemplate = 'OPNsense/CarpVipDhcp';
    protected static $internalServiceName = 'carpvipdhcp';

    /**
     * Reconfigure as usual, then create/refresh the firewall aliases that mirror
     * each keeper's VIP address, so rules pointed at them are ready to use.
     */
    public function reconfigureAction()
    {
        $response = parent::reconfigureAction();
        // Only sync aliases when the reconfigure actually ran. The base guards
        // itself behind POST and returns status 'ok' on success; on a GET (or a
        // failed apply) it does not touch the daemons, so we must not fire the
        // alias sync either -- it is a state-changing action.
        if (is_array($response) && ($response['status'] ?? '') === 'ok') {
            (new \OPNsense\Core\Backend())->configdRun('carpvipdhcp sync_aliases');
        }
        return $response;
    }

    /**
     * The service is enabled when at least one keeper is enabled.
     * @return bool
     */
    protected function serviceEnabled()
    {
        foreach ($this->getModel()->keepers->keeper->iterateItems() as $keeper) {
            if ((string)$keeper->enabled === '1') {
                return true;
            }
        }
        return false;
    }
}
