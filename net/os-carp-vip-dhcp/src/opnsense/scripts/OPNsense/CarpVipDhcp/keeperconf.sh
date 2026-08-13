#!/bin/sh
# Shared keeper.conf line parser for the CARP-VIP DHCP lease keepers.
#
# Sourced by the rc.d service (etc/rc.d/carpvipdhcp) and the CARP status hook
# (etc/rc.carp_service_status.d/carpvipdhcp) so both read keeper.conf through ONE
# implementation and cannot drift from each other. It is the shell counterpart of
# keeperconf.py (the Python reader); tests/test_reader_conformance.py asserts the
# two agree. POSIX sh, no rc.subr dependency, so it is also testable in isolation.
#
# keeper.conf is one keeper per line: pipe-separated KEY=VALUE fields in no fixed
# order (rendered by the configd template).

# carpvipdhcp_parse_line <line>: parse one record into the keeper field variables
# (request, iface, chaddr, demote, vhid, follow, vendorclass, clientid, hostname,
# arpnudge, arplistenpromisc, defaultroutemode, backupegress, backupegressform,
# backupegressgw, backupegressiface, backupegressprefixes). All are reset first,
# then each field is dispatched by key -- an unknown key is ignored and a missing
# key keeps the empty reset. Peels one field at a time with parameter expansion,
# so there are no IFS/glob side effects (the caller may be part-way through
# building an argv with `set --`). Values may contain '=' (split on the first
# only). The caller reads the variables above after the call.
carpvipdhcp_parse_line()
{
    request='' iface='' chaddr='' demote='' vhid='' follow='' vendorclass=''
    clientid='' hostname='' arpnudge='' arplistenpromisc='' defaultroutemode=''
    backupegress='' backupegressform='' backupegressgw='' backupegressiface=''
    backupegressprefixes=''
    # Namespaced scratch temporaries (POSIX sh has no `local`), unset at the end so
    # sourcing this parser does not leak them into the caller's environment.
    _kc_rec="$1"
    while [ -n "${_kc_rec}" ]; do
        _kc_field="${_kc_rec%%|*}"
        case "${_kc_rec}" in *"|"*) _kc_rec="${_kc_rec#*|}" ;; *) _kc_rec='' ;; esac
        case "${_kc_field}" in
            request=*) request="${_kc_field#*=}" ;;
            iface=*) iface="${_kc_field#*=}" ;;
            chaddr=*) chaddr="${_kc_field#*=}" ;;
            demote=*) demote="${_kc_field#*=}" ;;
            vhid=*) vhid="${_kc_field#*=}" ;;
            follow=*) follow="${_kc_field#*=}" ;;
            vendorclass=*) vendorclass="${_kc_field#*=}" ;;
            clientid=*) clientid="${_kc_field#*=}" ;;
            hostname=*) hostname="${_kc_field#*=}" ;;
            arpnudge=*) arpnudge="${_kc_field#*=}" ;;
            arplistenpromisc=*) arplistenpromisc="${_kc_field#*=}" ;;
            defaultroutemode=*) defaultroutemode="${_kc_field#*=}" ;;
            backupegress=*) backupegress="${_kc_field#*=}" ;;
            backupegressform=*) backupegressform="${_kc_field#*=}" ;;
            backupegressgateway=*) backupegressgw="${_kc_field#*=}" ;;
            backupegressinterface=*) backupegressiface="${_kc_field#*=}" ;;
            backupegressprefixes=*) backupegressprefixes="${_kc_field#*=}" ;;
        esac
    done
    unset _kc_rec _kc_field
}
