<?php

namespace OPNsense\CarpVipDhcp;

/**
 * Renders the settings page for the CARP-VIP DHCP lease keeper.
 */
class IndexController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->formDialogKeeper = $this->getForm('dialogKeeper');
        $this->view->pick('OPNsense/CarpVipDhcp/index');
    }
}
