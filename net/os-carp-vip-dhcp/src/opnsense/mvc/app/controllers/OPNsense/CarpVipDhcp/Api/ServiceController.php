<?php

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
        (new \OPNsense\Core\Backend())->configdRun('carpvipdhcp sync_aliases');
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
