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

// Dashboard widget: one row per CARP-VIP DHCP keeper. Key/value layout (VIP on
// the left, a status line on the right) so it stays readable in a narrow
// dashboard column and scales as a list -- like the built-in CARP Status
// widget, whose MASTER/BACKUP pill it mirrors. Reuses the diagnostics status
// API the plugin's Status page already polls; no widget-specific backend. The
// cell classification mirrors the Status page (status.volt) in a simpler form
// -- keep the two in sync when the health rules change.
export default class CarpVipDhcp extends BaseTableWidget {
    constructor() {
        super();
        // Keeper state moves at CARP/DHCP-lease timescales; a slower tick keeps
        // the backend (status.py forks ifconfig/sysctl + parses config.xml) off
        // a tight loop. The health banner, not this widget, is the alert path.
        this.tickTimeout = 30;
    }

    getGridOptions() {
        // Scroll inside the widget once many keepers push it past this height,
        // instead of growing the dashboard cell unbounded.
        return {
            sizeToContent: 650,
        };
    }

    getMarkup() {
        const $container = $('<div></div>');
        $container.append(this.createTable('carpvipdhcp-widget-table', {
            headerPosition: 'left',
        }));
        return $container;
    }

    async onWidgetTick() {
        const data = await this.ajaxCall('/api/carpvipdhcp/diagnostics/status');
        if (!data || !Array.isArray(data.keepers)) {
            this.displayError(this.translations.error);
            return;
        }
        if (data.keepers.length === 0) {
            super.updateTable('carpvipdhcp-widget-table', [
                [this._cell(this.translations.none, 'text-muted'), ''],
            ]);
            return;
        }
        const rows = data.keepers.map((k) => [this._vipKey(k), this._statusValue(k)]);
        super.updateTable('carpvipdhcp-widget-table', rows);
    }

    displayError(message) {
        $('#carpvipdhcp-widget-table').empty().append($('<div></div>').text(message));
    }

    // ---- cell builders (return outerHTML strings; jQuery .text() escapes) ----

    _cell(text, cls) {
        const $s = $('<span></span>').text(text);
        if (cls) {
            $s.addClass(cls);
        }
        return $s.prop('outerHTML');
    }

    _vipKey(k) {
        let html = this._cell(k.request);
        if (k.vhid) {
            html += ' ' + this._cell('vhid ' + k.vhid, 'text-muted');
        }
        return html;
    }

    // A coloured MASTER/BACKUP pill, matching the built-in CARP Status widget.
    _carpBadge(k) {
        const cls = {MASTER: 'label-success', INIT: 'label-warning'}[k.carp_state] || 'label-default';
        return $('<span></span>').addClass('label').addClass(cls)
            .text(k.carp_state || '-').prop('outerHTML');
    }

    _leaseText(k) {
        if (!k.running) {
            return this._cell(this.translations.stopped, 'text-danger');
        }
        if (k.mismatch) {
            return this._cell(this.translations.mismatch, 'text-danger');
        }
        if (k.standby) {
            return this._cell(this.translations.standby, 'text-muted');
        }
        if (k.bound && k.bound === k.request) {
            return this._cell(this.translations.held, 'text-success');
        }
        return this._cell(this.translations.notheld, 'text-warning');
    }

    _nudgeText(k) {
        let val;
        if (!k.arp_nudge) {
            val = this.translations.off;
        } else if (k.nudge_age === null || k.nudge_age === undefined) {
            val = this.translations.never;
        } else {
            val = this._fmtAge(k.nudge_age);
        }
        return this._cell(this.translations.nudge + ' ' + val, 'text-muted');
    }

    _statusValue(k) {
        const sep = ' <span class="text-muted">·</span> ';
        return this._carpBadge(k) + ' ' + this._leaseText(k) + sep + this._nudgeText(k);
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
