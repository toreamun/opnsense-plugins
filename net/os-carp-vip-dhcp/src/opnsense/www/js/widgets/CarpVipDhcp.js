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

// Dashboard widget: one row per CARP-VIP DHCP keeper (VIP, CARP role, lease
// state, ARP-nudge age). Reuses the diagnostics status API the plugin's Status
// page already polls; no widget-specific backend.
export default class CarpVipDhcp extends BaseTableWidget {
    constructor() {
        super();
        this.tickTimeout = 10;
    }

    getMarkup() {
        const $container = $('<div></div>');
        $container.append(this.createTable('carpvipdhcp-widget-table', {
            headers: [
                this.translations.vip || 'VIP',
                this.translations.carp || 'CARP',
                this.translations.lease || 'Lease',
                this.translations.nudge || 'ARP nudge',
            ],
        }));
        return $container;
    }

    async onWidgetTick() {
        const data = await this.ajaxCall('/api/carpvipdhcp/diagnostics/status');
        if (!data || !Array.isArray(data.keepers)) {
            this.displayError(this.translations.error || 'Unable to load keeper status');
            return;
        }
        if (data.keepers.length === 0) {
            super.updateTable('carpvipdhcp-widget-table', [
                [this._cell(this.translations.none || 'No keepers configured', 'text-muted'), '', '', ''],
            ]);
            return;
        }
        const rows = data.keepers.map((k) => [
            this._vipCell(k),
            this._carpCell(k),
            this._leaseCell(k),
            this._nudgeCell(k),
        ]);
        super.updateTable('carpvipdhcp-widget-table', rows);
    }

    // ---- cell builders (return outerHTML strings, as updateTable expects) ----

    _cell(text, cls) {
        const $s = $('<span></span>').text(text);
        if (cls) {
            $s.addClass(cls);
        }
        return $s.prop('outerHTML');
    }

    _vipCell(k) {
        let html = this._cell(k.request);
        if (k.vhid) {
            html += ' ' + this._cell('vhid ' + k.vhid, 'text-muted');
        }
        return html;
    }

    _carpCell(k) {
        if (!k.carp_state) {
            return this._cell('-', 'text-muted');
        }
        const cls = {MASTER: 'text-success', INIT: 'text-warning'}[k.carp_state] || '';
        return this._cell(k.carp_state, cls);
    }

    _leaseCell(k) {
        if (!k.running) {
            return this._cell(this.translations.stopped || 'stopped', 'text-danger');
        }
        if (k.mismatch) {
            return this._cell(this.translations.mismatch || 'mismatch', 'text-danger');
        }
        if (k.standby) {
            return this._cell(this.translations.standby || 'standby', 'text-muted');
        }
        if (k.bound && k.bound === k.request) {
            return this._cell(this.translations.held || 'held', 'text-success');
        }
        return this._cell(this.translations.notheld || 'not held', 'text-warning');
    }

    _nudgeCell(k) {
        if (!k.arp_nudge) {
            return this._cell(this.translations.off || 'off', 'text-muted');
        }
        if (k.nudge_age === null || k.nudge_age === undefined) {
            return this._cell(this.translations.never || 'never', 'text-warning');
        }
        return this._cell(this._fmtAge(k.nudge_age));
    }

    _fmtAge(sec) {
        if (sec < 60) {
            return sec + ' s';
        }
        if (sec < 3600) {
            return Math.floor(sec / 60) + ' min';
        }
        return Math.floor(sec / 3600) + ' h';
    }
}
