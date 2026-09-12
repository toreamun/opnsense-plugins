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
            // Per-keeper actions (id passed through), so each Services overview
            // row controls only its own keeper -- not all of them.
            'configd' => [
                'restart' => ['carpvipdhcp restart_keeper ' . $id],
                'start' => ['carpvipdhcp start_keeper ' . $id],
                'stop' => ['carpvipdhcp stop_keeper ' . $id],
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
 *
 * Nothing syncs by itself. Saving on the master changes nothing on the backup;
 * OPNsense pushes config only from System > High Availability > Status (the
 * per-service "Synchronize and Restart" button, or "Synchronize and reconfigure
 * all") and from the cron job "HA update and reconfigure backup". The
 * 'services' list below is inert: core normalises it and pluginctl -x prints
 * it, but no sync path acts on it. Whether the backup's keepers pick up the
 * new config depends on the path:
 *  - per-service "Synchronize and Restart": syncs, reloads the templates and
 *    restarts that keeper by id. The right button after a keeper change.
 *  - "Synchronize and reconfigure all": same, but restarts every service on
 *    the backup, and it reads the backup's service list BEFORE syncing, so a
 *    keeper added or enabled on the master is not started; start it from its
 *    own row afterwards.
 *  - the cron job: syncs and reloads the templates, but restarts services with
 *    the service NAME passed as the id, which never matches a keeper's id, so
 *    the keepers keep running their previous settings until restarted.
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
