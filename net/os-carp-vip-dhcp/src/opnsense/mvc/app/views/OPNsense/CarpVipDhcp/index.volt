{#
 # Copyright (C) 2026 Tore Amundsen
 # All rights reserved.
 #
 # Redistribution and use in source and binary forms, with or without
 # modification, are permitted provided that the following conditions are met:
 #
 # 1. Redistributions of source code must retain the above copyright notice,
 #    this list of conditions and the following disclaimer.
 #
 # 2. Redistributions in binary form must reproduce the above copyright notice,
 #    this list of conditions and the following disclaimer in the documentation
 #    and/or other materials provided with the distribution.
 #
 # THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 # INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 # FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR
 # BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY OR
 # CONSEQUENTIAL DAMAGES ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 # IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 #}

<script>
    // Base dialogs have no declarative "show-if-other-field", so field couplings are
    // toggled in JS, mirroring the core pattern (the OpenVPN instance dialog does the
    // same). Hidden rows keep their values (the daemon ignores an inapplicable field);
    // this only declutters the dialog. Every field toggled here is advanced, so it never
    // appears unless advanced mode is on, gated on the toggle state exactly as core does.
    function cvdToggleConditionalFields() {
        let advancedOn = $("#DialogKeeper [id^='show_advanced_']").hasClass("fa-toggle-on");
        function advRow(id, show) { $("#keeper\\." + id).closest("tr").toggle(show && advancedOn); }

        // CARP failover on lease loss applies only to a fixed reservation, so it is
        // mutually exclusive with "Follow dynamic DHCP address" (a follower adopts a new
        // address instead of losing the lease).
        advRow("demoteOnLeaseLoss", !$("#keeper\\.followIp").is(":checked"));

        // Backup egress needs "Own default route by CARP role" on observe/enforce; its
        // sub-fields need the feature enabled, and the prefix list needs the prefixes form.
        let routeOwned = $("#keeper\\.defaultRouteMode").val() !== "off";
        let backupOn = routeOwned && $("#keeper\\.backupEgress").is(":checked");
        advRow("backupEgress", routeOwned);
        advRow("backupEgressForm", backupOn);
        advRow("backupEgressGateway", backupOn);
        advRow("backupEgressInterface", backupOn);
        advRow("backupEgressPrefixes", backupOn && $("#keeper\\.backupEgressForm").val() === "prefixes");

        // Promiscuous ARP listen only has a reply to catch while the ARP nudge is enabled
        // (interval 0 disables the nudge).
        advRow("arpListenPromisc", parseInt($("#keeper\\.arpNudgeInterval").val(), 10) > 0);
    }

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
        $("#reconfigureAct").SimpleActionButton();

        // Re-evaluate when the dialog opens (values are mapped in without firing change),
        // when any trigger field changes, and after the advanced-mode toggle (deferred so
        // it runs once the framework has shown/hidden the advanced rows).
        let cvdTriggers = "#keeper\\.followIp, #keeper\\.defaultRouteMode, #keeper\\.backupEgress, "
            + "#keeper\\.backupEgressForm, #keeper\\.arpNudgeInterval";
        $("#DialogKeeper").on("shown.bs.modal", function () { setTimeout(cvdToggleConditionalFields, 0); });
        $(cvdTriggers).on("change", cvdToggleConditionalFields);
        $("#DialogKeeper").on("click", "[id^='show_advanced_']", function () {
            setTimeout(cvdToggleConditionalFields, 0);
        });
    });
</script>

<div class="content-box">
    <table id="grid-keepers" class="table table-condensed table-hover table-striped"
           data-editDialog="DialogKeeper" data-editAlert="carpvipdhcpChangeMessage">
        <thead>
            <tr>
                <th data-column-id="enabled" data-width="6em" data-type="boolean" data-formatter="rowtoggle">{{ lang._('Enabled') }}</th>
                <th data-column-id="carpVip" data-width="15em" data-type="string">{{ lang._('CARP virtual IP') }}</th>
                <th data-column-id="followIp" data-width="7em" data-type="boolean" data-formatter="boolean">{{ lang._('Follow IP') }}</th>
                <th data-column-id="aliasName" data-width="10em" data-type="string">{{ lang._('Sync alias') }}</th>
                <th data-column-id="demoteOnLeaseLoss" data-width="9em" data-type="boolean" data-formatter="boolean">{{ lang._('CARP failover') }}</th>
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
</div>

<div id="carpvipdhcpChangeMessage" class="alert alert-info" style="display: none" role="alert">
    {{ lang._('After changing settings, please remember to apply them with the button below.') }}
</div>
{{ partial("layout_partials/base_apply_button", {'data_endpoint': '/api/carpvipdhcp/service/reconfigure', 'data_service_widget': 'carpvipdhcp'}) }}

{{ partial("layout_partials/base_dialog", ['fields': formDialogKeeper, 'id': 'DialogKeeper', 'label': lang._('Edit CARP-VIP DHCP keeper')]) }}
