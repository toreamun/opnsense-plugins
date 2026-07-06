<?php

namespace OPNsense\CarpVipDhcp;

/**
 * Renders the Log page (Interfaces > Virtual IPs DHCP > Log).
 */
class LogController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->pick('OPNsense/CarpVipDhcp/log');
    }
}
