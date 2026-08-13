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
    _rec="$1"
    while [ -n "${_rec}" ]; do
        _field="${_rec%%|*}"
        case "${_rec}" in *"|"*) _rec="${_rec#*|}" ;; *) _rec='' ;; esac
        case "${_field}" in
            request=*) request="${_field#*=}" ;;
            iface=*) iface="${_field#*=}" ;;
            chaddr=*) chaddr="${_field#*=}" ;;
            demote=*) demote="${_field#*=}" ;;
            vhid=*) vhid="${_field#*=}" ;;
            follow=*) follow="${_field#*=}" ;;
            vendorclass=*) vendorclass="${_field#*=}" ;;
            clientid=*) clientid="${_field#*=}" ;;
            hostname=*) hostname="${_field#*=}" ;;
            arpnudge=*) arpnudge="${_field#*=}" ;;
            arplistenpromisc=*) arplistenpromisc="${_field#*=}" ;;
            defaultroutemode=*) defaultroutemode="${_field#*=}" ;;
            backupegress=*) backupegress="${_field#*=}" ;;
            backupegressform=*) backupegressform="${_field#*=}" ;;
            backupegressgateway=*) backupegressgw="${_field#*=}" ;;
            backupegressinterface=*) backupegressiface="${_field#*=}" ;;
            backupegressprefixes=*) backupegressprefixes="${_field#*=}" ;;
        esac
    done
}
