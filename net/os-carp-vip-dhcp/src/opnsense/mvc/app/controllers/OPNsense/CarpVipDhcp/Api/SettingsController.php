<?php

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
            ['enabled', 'carpVip', 'demoteOnLeaseLoss', 'runOnlyOnMaster', 'followIp', 'aliasName', 'description']
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
