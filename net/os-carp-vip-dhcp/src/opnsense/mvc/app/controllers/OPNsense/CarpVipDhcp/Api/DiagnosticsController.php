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
        // Filter by severity threshold ("this level and above"), so choosing
        // INFO hides DEBUG but still shows WARNING/ERROR. Empty = show everything
        // (including DEBUG). The log page defaults its selector to INFO.
        $level = $this->request->getPost('level', 'striptags', '');
        $filter_funct = null;
        if (!empty($level)) {
            $ranks = ['DEBUG' => 10, 'INFO' => 20, 'WARNING' => 30, 'ERROR' => 40, 'CRITICAL' => 50];
            $min = $ranks[$level] ?? 0;
            $filter_funct = function ($record) use ($ranks, $min) {
                return ($ranks[$record['level'] ?? ''] ?? 0) >= $min;
            };
        }
        // No default sort key: searchRecordsetBase only ever sorts ascending on
        // its default, which would show the log oldest-first until the user
        // clicks a header. Passing null keeps logparse.py's newest-first order on
        // the first load; a header click still sorts either way.
        return $this->searchRecordsetBase(
            $records,
            ['timestamp', 'keeper', 'vhid', 'level', 'message'],
            null,
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
