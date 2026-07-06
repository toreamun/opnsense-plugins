<script>
    $(document).ready(function () {
        $("#grid-keepers").UIBootgrid({
            search: '/api/carpvipdhcp/settings/searchKeeper',
            get: '/api/carpvipdhcp/settings/getKeeper/',
            set: '/api/carpvipdhcp/settings/setKeeper/',
            add: '/api/carpvipdhcp/settings/addKeeper/',
            del: '/api/carpvipdhcp/settings/delKeeper/',
            toggle: '/api/carpvipdhcp/settings/toggleKeeper/'
        });
        updateServiceControlUI('carpvipdhcp');
    });
</script>

<div class="content-box">
    <table id="grid-keepers" class="table table-condensed table-hover table-striped"
           data-editDialog="DialogKeeper" data-editAlert="carpvipdhcpChangeMessage">
        <thead>
            <tr>
                <th data-column-id="enabled" data-type="boolean" data-formatter="rowtoggle">{{ lang._('Enabled') }}</th>
                <th data-column-id="carpVip" data-type="string">{{ lang._('CARP virtual IP') }}</th>
                <th data-column-id="demoteOnLeaseLoss" data-type="boolean" data-formatter="boolean">{{ lang._('CARP failover') }}</th>
                <th data-column-id="runOnlyOnMaster" data-type="boolean" data-formatter="boolean">{{ lang._('Master-only') }}</th>
                <th data-column-id="followIp" data-type="boolean" data-formatter="boolean">{{ lang._('Follow IP') }}</th>
                <th data-column-id="aliasName" data-type="string">{{ lang._('Sync alias') }}</th>
                <th data-column-id="description" data-type="string">{{ lang._('Description') }}</th>
                <th data-column-id="uuid" data-type="string" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
                <th data-column-id="commands" data-width="7em" data-formatter="commands" data-sortable="false">{{ lang._('Commands') }}</th>
            </tr>
        </thead>
        <tbody></tbody>
        <tfoot>
            <tr>
                <td></td>
                <td>
                    <button data-action="add" type="button" class="btn btn-xs btn-primary">
                        <span class="fa fa-plus"></span>
                    </button>
                    <button data-action="deleteSelected" type="button" class="btn btn-xs btn-default">
                        <span class="fa fa-trash-o"></span>
                    </button>
                </td>
            </tr>
        </tfoot>
    </table>
    <div class="col-md-12">
        <div id="carpvipdhcpChangeMessage" class="alert alert-info" style="display: none" role="alert">
            {{ lang._('After changing settings, please remember to apply them with the button below.') }}
        </div>
        <hr/>
        {{ partial("layout_partials/base_apply_button", {'data_endpoint': '/api/carpvipdhcp/service/reconfigure'}) }}
    </div>
</div>

{{ partial("layout_partials/base_dialog", ['fields': formDialogKeeper, 'id': 'DialogKeeper', 'label': lang._('Edit CARP-VIP DHCP keeper')]) }}
