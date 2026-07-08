<script>
    'use strict';

    $(document).ready(function () {
        $("#grid-log").UIBootgrid({
            search: '/api/carpvipdhcp/diagnostics/log',
            options: {
                rowCount: [20, 50, 100, 500],
                selection: false,
                multiSelect: false,
                requestHandler: function (request) {
                    request['level'] = $("#level_filter").val();
                    return request;
                },
                formatters: {
                    keeper: function (column, row) {
                        let ip = row.keeper || '';
                        let badge = row.vhid
                            ? ' <span class="badge badge-pill">vhid ' + row.vhid + '</span>'
                            : '';
                        return ip + badge;
                    },
                    level: function (column, row) {
                        if (!row.level) {
                            return '';
                        }
                        let cls = {
                            'ERROR': 'label-danger',
                            'CRITICAL': 'label-danger',
                            'WARNING': 'label-warning',
                            'INFO': 'label-info'
                        }[row.level] || 'label-default';
                        return '<span class="label ' + cls + '">' + row.level + '</span>';
                    }
                }
            }
        });

        // Move the level filter and clear-log button into the grid's action bar
        // so they share the row with the search / refresh / rowcount / columns /
        // export icons instead of sitting on a line of their own (core
        // Diagnostics/log.volt pattern). The level filter goes to the left of the
        // bar, the clear button to the right with the other command icons.
        let actionBar = $("#grid-log-header .actionBar");
        $("#level-wrapper").detach().prependTo(actionBar);
        $("#command-wrapper").detach().appendTo(actionBar);

        $("#level_filter").change(function () {
            $("#grid-log").bootgrid('reload');
        });

        $("#clear_log").click(function () {
            stdDialogConfirm(
                "{{ lang._('Clear log') }}",
                "{{ lang._('Truncate all keeper log files? This cannot be undone.') }}",
                "{{ lang._('Clear') }}",
                "{{ lang._('Cancel') }}",
                function () {
                    ajaxCall('/api/carpvipdhcp/diagnostics/clearLog', {}, function () {
                        $("#grid-log").bootgrid('reload');
                    });
                }
            );
        });
    });
</script>

<div class="content-box">
    <!-- Action-bar controls. Hidden here to avoid a flash on their own line; the
         script relocates them into the bootgrid action bar once it is built. -->
    <div id="log-controls" style="display: none;">
        <label id="level-wrapper" for="level_filter" style="margin: 0 1em 0 0;">
            <strong>{{ lang._('Level') }}:</strong>
            <select id="level_filter" class="form-control" style="display: inline-block; width: auto;">
                <option value="DEBUG">{{ lang._('Debug (all)') }}</option>
                <option value="INFO" selected="selected">INFO</option>
                <option value="WARNING">WARNING</option>
                <option value="ERROR">ERROR</option>
            </select>
        </label>
        <div id="command-wrapper" class="btn-group">
            <button id="clear_log" class="btn btn-default" title="{{ lang._('Clear log') }}">
                <i class="fa fa-trash fa-fw"></i>
            </button>
        </div>
    </div>
    <table id="grid-log" class="table table-condensed table-hover table-striped">
        <thead>
            <tr>
                <th data-column-id="timestamp" data-type="string" data-width="12em">{{ lang._('Time') }}</th>
                <th data-column-id="keeper" data-type="string" data-formatter="keeper" data-width="12em">{{ lang._('CARP virtual IP') }}</th>
                <th data-column-id="level" data-type="string" data-formatter="level" data-width="5em">{{ lang._('Level') }}</th>
                <th data-column-id="message" data-type="string">{{ lang._('Message') }}</th>
            </tr>
        </thead>
        <tbody></tbody>
    </table>
</div>
