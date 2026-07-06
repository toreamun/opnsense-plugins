<?php

/**
 * Register each enabled keeper as a system service so they show up individually
 * in the Services overview and can be (re)started from the GUI / pluginctl.
 * One entry per keeper (like OpenVPN instances), each with its own pidfile/id.
 */
function carpvipdhcp_services()
{
    $services = [];
    try {
        $model = new \OPNsense\CarpVipDhcp\CarpVipDhcp();
    } catch (\Exception $e) {
        return $services;
    }
    foreach ($model->keepers->keeper->iterateItems() as $keeper) {
        if ((string)$keeper->enabled !== '1') {
            continue;
        }
        $ip = (string)$keeper->carpVip;
        $id = preg_replace('/[^A-Za-z0-9]/', '_', $ip);
        $services[] = [
            'name' => 'carpvipdhcp',
            'description' => gettext('CARP-VIP DHCP keeper') . ' (' . $ip . ')',
            'pidfile' => "/var/run/carpvipdhcp-{$id}.pid",
            'id' => $id,
            'configd' => [
                'restart' => ['carpvipdhcp restart'],
                'start' => ['carpvipdhcp start'],
                'stop' => ['carpvipdhcp stop'],
            ],
        ];
    }
    return $services;
}

/**
 * Expose the keeper config as an OPTIONAL HA (XMLRPC) sync item.
 *
 * This only ADDS a checkbox under System > High Availability > Settings; nothing
 * is synchronised until the operator ticks it. Keeper config is node-agnostic
 * and therefore safe to replicate: carpVip stores the VIP's ADDRESS (not a
 * per-node UUID), and interface / VHID-chaddr / request-IP are DERIVED from that
 * address at render time, so the same keeper row renders correctly on both nodes.
 * After a sync the backup restarts the keepers to pick up the config.
 *
 * The CARP virtual IPs themselves are intentionally NOT synced (advskew differs
 * per node); with follow mode each node also updates its own VIP independently
 * and converges on the shared lease, so the synced carpVip matches.
 */
function carpvipdhcp_xmlrpc_sync()
{
    return [[
        'description' => gettext('CARP-VIP DHCP lease keepers'),
        'section' => 'OPNsense.CarpVipDhcp',
        'id' => 'carpvipdhcp',
        'services' => ['carpvipdhcp'],
    ]];
}
