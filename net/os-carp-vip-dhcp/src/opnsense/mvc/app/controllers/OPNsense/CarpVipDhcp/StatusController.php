<?php

namespace OPNsense\CarpVipDhcp;

/**
 * Renders the Status page (Interfaces > Virtual IPs DHCP > Status).
 */
class StatusController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->pick('OPNsense/CarpVipDhcp/status');
    }
}
