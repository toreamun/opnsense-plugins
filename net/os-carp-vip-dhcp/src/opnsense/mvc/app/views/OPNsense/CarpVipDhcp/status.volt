<script>
    'use strict';

    function fmtAge(sec) {
        if (sec === null || sec === undefined) {
            return '-';
        }
        if (sec < 60) {
            return sec + ' s';
        }
        if (sec < 3600) {
            return Math.floor(sec / 60) + ' min ' + (sec % 60) + ' s';
        }
        return Math.floor(sec / 3600) + ' h ' + Math.floor((sec % 3600) / 60) + ' min';
    }

    function dash(value) {
        return (value === null || value === undefined || value === '') ? '-' : value;
    }

    // Matches the health banner's staleness ceiling: a keeper rewrites its
    // heartbeat every ~30s, so an age past this means a stalled/dead daemon.
    const STALE_MAX_AGE = 600;

    function hbAgeCell(age) {
        if (age === null || age === undefined) {
            return '<span class="text-muted">-</span>';
        }
        let cls = age > STALE_MAX_AGE ? ' class="text-danger"' : '';
        return '<span' + cls + '>' + fmtAge(age) + '</span>';
    }

    function vhidBadge(k) {
        if (!k.vhid) {
            return '';
        }
        // Match Interfaces > Overview: green pill when MASTER, default grey otherwise.
        let style = (k.carp_state === 'MASTER') ? ' style="background-color: green;"' : '';
        let title = k.carp_state ? ' title="' + k.carp_state + '"' : '';
        return ' <span class="badge badge-pill"' + style + title + '>vhid ' + k.vhid + '</span>';
    }

    function badge(running) {
        return running
            ? '<span class="label label-success">' + "{{ lang._('running') }}" + '</span>'
            : '<span class="label label-danger">' + "{{ lang._('stopped') }}" + '</span>';
    }

    function carpStatus(state) {
        if (!state) {
            return '<span class="text-muted">-</span>';
        }
        let icon = {
            'MASTER': 'fa fa-play fa-fw text-success',
            'BACKUP': 'fa fa-play fa-fw text-muted',
            'INIT': 'fa fa-play fa-fw text-warning'
        }[state] || 'fa fa-question-circle fa-fw text-muted';
        return '<span class="' + icon + '"></span> ' + state;
    }

    function modeCell(k) {
        if (k.follow_ip === true) {
            return '<span class="label label-info" title="'
                + "{{ lang._('Accepts a changed DHCP address and rewrites the CARP VIP to match') }}"
                + '">' + "{{ lang._('follow') }}" + '</span>';
        }
        let extra = (k.demote_on_lease_loss === true)
            ? ' + ' + "{{ lang._('demote') }}" : '';
        return '<span class="label label-default" title="'
            + "{{ lang._('Enforces the fixed reservation; a different address raises a mismatch') }}"
            + '">' + "{{ lang._('enforce') }}" + extra + '</span>';
    }

    function leaseCell(k) {
        if (k.mismatch === true) {
            return '<span class="label label-warning">'
                + "{{ lang._('mismatch') }}" + ': ' + dash(k.bound) + '</span>';
        }
        if (k.standby === true) {
            return '<span class="label label-default">' + "{{ lang._('standby (backup)') }}" + '</span>';
        }
        if (k.bound && k.bound === k.request) {
            return '<span class="label label-success">' + "{{ lang._('held') }}" + '</span>';
        }
        if (k.bound) {
            return '<span class="label label-warning">' + dash(k.bound) + '</span>';
        }
        return '<span class="label label-default">' + "{{ lang._('not held') }}" + '</span>';
    }

    function leaseTimeCell(k) {
        if (!k.lease) {
            return '-';
        }
        let txt = k.lease + ' s';
        if (k.t1) {
            let src = (k.timing_source === 'server')
                ? "{{ lang._('from server (opt 58/59)') }}"
                : "{{ lang._('derived 0.5/0.875') }}";
            let tip = "{{ lang._('Renew T1') }}: " + k.t1 + ' s, '
                + "{{ lang._('rebind T2') }}: " + k.t2 + ' s — ' + src;
            txt += ' <i class="fa fa-info-circle text-muted" title="' + tip + '"></i>';
        }
        return txt;
    }

    function nudgeCell(k) {
        if (!k.arp_nudge) {
            return '<span class="text-muted">' + "{{ lang._('off') }}" + '</span>';
        }
        let tip = "{{ lang._('every') }}" + ' ' + k.arp_nudge + ' s'
            + (k.gw ? ' → ' + k.gw : ' (' + "{{ lang._('gateway unknown') }}" + ')');
        let cell;
        if (k.nudge_age == null) {
            // Enabled but never sent: expected on a CARP backup, suspicious on a
            // bound master (no gateway known, or the daemon predates the setting).
            let style = (k.carp_state === 'MASTER' && k.bound) ? 'label-warning' : 'label-default';
            cell = '<span class="label ' + style + '" title="' + tip + '">'
                + "{{ lang._('never') }}" + '</span>';
        } else {
            cell = '<span title="' + tip + '">' + fmtAge(k.nudge_age) + '</span>';
        }
        if (k.running === true && k.carp_state === 'MASTER') {
            cell += ' <button class="btn btn-xs btn-default nudge_now" data-id="' + k.request
                + '" title="' + "{{ lang._('Send an ARP nudge now') }}" + '">'
                + '<i class="fa fa-bolt fa-fw"></i></button>';
        }
        return cell;
    }

    function refreshStatus() {
        ajaxGet('/api/carpvipdhcp/diagnostics/status', {}, function (data) {
            if (data === undefined) {
                return;
            }
            $('#carp_demotion').text(
                (data.carp_demotion === null || data.carp_demotion === undefined) ? '-' : data.carp_demotion
            );

            let keepers = data.keepers || [];
            let rows = '';
            if (keepers.length === 0) {
                rows = '<tr><td colspan="10" class="text-muted">'
                    + "{{ lang._('No keepers configured.') }}" + '</td></tr>';
            }
            keepers.forEach(function (k) {
                rows += '<tr>'
                    + '<td>' + dash(k.request) + vhidBadge(k) + '</td>'
                    + '<td><span title="' + dash(k.iface) + '">' + dash(k.iface_name) + '</span></td>'
                    + '<td>' + modeCell(k) + '</td>'
                    + '<td>' + carpStatus(k.carp_state) + '</td>'
                    + '<td>' + badge(k.running === true) + '</td>'
                    + '<td>' + leaseCell(k) + '</td>'
                    + '<td>' + hbAgeCell(k.hb_age) + '</td>'
                    + '<td>' + leaseTimeCell(k) + '</td>'
                    + '<td>' + nudgeCell(k) + '</td>'
                    + '<td>' + dash(k.chaddr) + '</td>'
                    + '</tr>';
            });
            $('#keeper_rows').html(rows);
        });
    }

    $(document).on('click', '.nudge_now', function () {
        let btn = $(this);
        btn.prop('disabled', true);
        ajaxCall('/api/carpvipdhcp/diagnostics/nudge/' + btn.data('id'), {}, function () {
            // The nudge age refreshes on the next heartbeat write (<= 30 s);
            // poll a little sooner for quicker feedback.
            setTimeout(refreshStatus, 2000);
            btn.prop('disabled', false);
        });
    });

    $(document).ready(function () {
        updateServiceControlUI('carpvipdhcp');
        refreshStatus();
        setInterval(refreshStatus, 5000);
    });
</script>

<div class="content-box" style="padding-bottom: 1.5em;">
    <div class="table-responsive">
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>{{ lang._('CARP virtual IP') }}</th>
                    <th>{{ lang._('Interface') }}</th>
                    <th>{{ lang._('Mode') }}</th>
                    <th>{{ lang._('CARP status') }}</th>
                    <th>{{ lang._('Service') }}</th>
                    <th>{{ lang._('Lease') }}</th>
                    <th>{{ lang._('Heartbeat age') }}</th>
                    <th>{{ lang._('Lease time') }}</th>
                    <th>{{ lang._('ARP nudge') }}</th>
                    <th>{{ lang._('Lease MAC') }}</th>
                </tr>
            </thead>
            <tbody id="keeper_rows"></tbody>
        </table>
    </div>
    <div class="col-md-12">
        {{ lang._('CARP demotion (this node)') }}: <strong id="carp_demotion">-</strong>
    </div>
</div>
