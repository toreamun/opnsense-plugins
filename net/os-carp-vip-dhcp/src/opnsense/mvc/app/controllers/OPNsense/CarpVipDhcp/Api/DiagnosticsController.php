<?php

namespace OPNsense\CarpVipDhcp\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

/**
 * Diagnostics API: expose the keeper's runtime state (pid, current lease,
 * heartbeat freshness and recent log lines) parsed by a root configd script.
 */
class DiagnosticsController extends ApiControllerBase
{
    /**
     * Return keeper status as a structured payload.
     * @return array
     */
    public function statusAction()
    {
        $raw = trim((new Backend())->configdRun('carpvipdhcp diag'));
        $data = json_decode($raw, true);
        if (!is_array($data)) {
            return ['running' => false, 'log' => [], 'error' => 'no data'];
        }
        return $data;
    }

    /**
     * Return parsed daemon log records for a searchable/sortable bootgrid,
     * optionally filtered by level.
     * @return array
     */
    public function logAction()
    {
        $records = json_decode(trim((new Backend())->configdRun('carpvipdhcp log')), true);
        if (!is_array($records)) {
            $records = [];
        }
        $level = $this->request->getPost('level', 'striptags', '');
        $filter_funct = null;
        if (!empty($level)) {
            $filter_funct = function ($record) use ($level) {
                return isset($record['level']) && $record['level'] === $level;
            };
        }
        return $this->searchRecordsetBase(
            $records,
            ['timestamp', 'keeper', 'vhid', 'level', 'message'],
            'timestamp',
            $filter_funct
        );
    }

    /**
     * Truncate the keeper log files (POST-only, state-changing).
     * @return array
     */
    public function clearLogAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }
        (new Backend())->configdRun('carpvipdhcp clear_log');
        return ['status' => 'ok'];
    }

    /**
     * Ask a keeper to send an immediate ARP nudge (POST-only, state-changing).
     * Useful when troubleshooting a suspected stale gateway ARP entry: the
     * daemon fires within a second and the result shows up in the log page.
     * @param string $id the keeper's request address (IPv4)
     * @return array
     */
    public function nudgeAction($id = '')
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }
        // Keeper ids are IPv4 request addresses (same validation as the model
        // and follow_update.php); the shell script re-sanitizes to [A-Za-z0-9_]
        // as a second line of defence.
        if (filter_var((string)$id, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            return ['status' => 'invalid'];
        }
        $raw = trim((string)(new Backend())->configdpRun('carpvipdhcp nudge', [$id]));
        $data = json_decode($raw, true);
        return is_array($data) ? $data : ['status' => 'failed'];
    }
}
