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

namespace OPNsense\System\Status;

use OPNsense\System\AbstractStatus;
use OPNsense\System\SystemStatusCode;

/**
 * Raise a dashboard banner when a CARP-VIP DHCP lease keeper stops holding its
 * lease. Pull-based: core polls collectStatus(); the banner clears by itself
 * once every keeper is healthy again. The keeper daemon needs no changes -- we
 * read the heartbeat files it already writes (the same signals the CARP
 * service-status hook uses), plus a grace period so a reboot or a keeper
 * restart does not flash a false alarm.
 */
class CarpVipDhcpStatus extends AbstractStatus
{
    private const CONF = '/usr/local/etc/carpvipdhcp/keeper.conf';
    private const RUN_DIR = '/var/run';
    private const STATE_FILE = '/var/run/carpvipdhcp-notice.state';
    // A healthy keeper rewrites its heartbeat every ~30s; the largest legitimate
    // gap is a re-acquire backoff (~300s). 600s reliably means a stalled daemon.
    private const STALE = 600;
    // Only alert once a problem has persisted this long, to ride out restarts.
    private const GRACE = 300;

    public function __construct()
    {
        $this->internalPriority = 2;
        $this->internalPersistent = false;
        $this->internalIsBanner = true;
        $this->internalScope = ['*'];
        $this->internalTitle = gettext('CARP-VIP DHCP');
        $this->internalLocation = '/ui/carpvipdhcp/';
    }

    public function collectStatus()
    {
        $problems = [];
        foreach ($this->keeperAddresses() as $request) {
            $reason = $this->unhealthyReason($request);
            if ($reason !== null) {
                $problems[] = sprintf('%s (%s)', $request, $reason);
            }
        }

        if (empty($problems)) {
            @unlink(self::STATE_FILE);
            return;
        }

        // Debounce against the wall clock (survives irregular polling): record
        // when the problem was first seen, alert only once it outlasts GRACE.
        // This also rides out the normal acquire/re-acquire window, where the
        // keeper legitimately publishes bound=- (which reads as "not holding").
        $now = time();
        $since = (int)@file_get_contents(self::STATE_FILE);   // missing file -> 0
        if ($since <= 0) {
            @file_put_contents(self::STATE_FILE, (string)$now);
            return;
        }
        if ($now - $since < self::GRACE) {
            return;
        }

        $this->internalMessage = sprintf(
            gettext('CARP-VIP DHCP lease keeper problem: %s. HA failover may not work until resolved.'),
            implode(', ', $problems)
        );
        $this->internalStatus = SystemStatusCode::WARNING;
    }

    /**
     * The request address (keeper id) of every enabled keeper. keeper.conf only
     * lists enabled, resolvable keepers, so each line is one that should be up.
     */
    private function keeperAddresses(): array
    {
        $out = [];
        $lines = @file(self::CONF, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines === false) {
            return $out;
        }
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#' || strpos($line, '|') === false) {
                continue;
            }
            $out[] = explode('|', $line)[0];
        }
        return $out;
    }

    /**
     * null if the keeper is healthy, otherwise a short reason. Mirrors the CARP
     * service-status hook's heartbeat semantics (STANDBY / MISMATCH / bound==)
     * and adds staleness detection for a dead or stuck daemon.
     */
    private function unhealthyReason(string $request): ?string
    {
        $hb = self::RUN_DIR . '/carpvipdhcp-' . preg_replace('/[^A-Za-z0-9]/', '_', $request) . '.hb';
        $content = trim((string)@file_get_contents($hb));   // missing file -> ''
        if ($content === '') {
            return gettext('no heartbeat');
        }
        $epoch = (int)explode(' ', $content)[0];
        if ($epoch <= 0 || (time() - $epoch) > self::STALE) {
            return gettext('daemon stalled (no fresh heartbeat)');
        }
        if (strpos($content, 'MISMATCH') !== false) {
            return gettext('ISP handed a different address than the VIP');
        }
        if (strpos($content, 'STANDBY') !== false) {
            return null;   // intentionally idle CARP backup, heartbeat fresh
        }
        if (strpos($content, 'bound=' . $request . ' ') !== false) {
            return null;
        }
        return gettext('not holding the lease');
    }
}
