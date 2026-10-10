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
# the shell callers use (request, iface, chaddr, demote). The daemon reads the rest
# of its record itself (lease_keeper.py --conf), so settings such as the DHCP
# client-id are not handled here. All four are reset first, then each field is
# dispatched by key -- any other key is ignored and a missing key keeps the empty
# reset. Peels one field at a time with parameter expansion, so there are no
# IFS/glob side effects. Values may contain '=' (split on the first only). The
# caller reads the variables above after the call.
carpvipdhcp_parse_line()
{
    request='' iface='' chaddr='' demote=''
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
        esac
    done
    unset _kc_rec _kc_field
}
