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

    /** The file the template renders, and how often to render it before giving up. */
    private const KEEPER_CONF = '/usr/local/etc/carpvipdhcp/keeper.conf';
    private const RENDER_TRIES = 10;

    /**
     * Reconfigure as usual, then create/refresh the firewall aliases that mirror
     * each keeper's VIP address, so rules pointed at them are ready to use.
     *
     * keeper.conf is rendered first. The base stops the service before it renders
     * the template, and the stop decides from keeper.conf which source-MAC rewrite
     * (send from the lease MAC, experimental) may stay on a master. From the old file
     * it would keep the rewrite of a keeper just disabled, deleted or moved to
     * another VIP, with no keeper left to remove it. configd renders from a cached
     * config.xml, so right after a save the file can still be the old one: render
     * until it allows no rewrite the saved settings do not, and stop nothing if it
     * never does.
     */
    public function reconfigureAction()
    {
        if ($this->request->isPost()) {
            $backend = new \OPNsense\Core\Backend();
            for ($try = 1;; $try++) {
                $backend->configdpRun('template reload', [static::$internalServiceTemplate]);
                $rendered = @file_get_contents(self::KEEPER_CONF);
                if ($rendered !== false && !$this->getModel()->rendersStaleVmacKeep($rendered)) {
                    break;
                }
                if ($try >= self::RENDER_TRIES) {
                    return ['status' => 'failed', 'status_msg' => gettext(
                        'keeper.conf did not reflect the saved settings, so nothing was stopped or restarted. '
                        . 'Apply again.'
                    )];
                }
                sleep(1);
            }
        }
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
