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
}
