#!/bin/sh
# Shell side of the source-MAC rewrite (leasekeeper/vmac.py, #131): removal only,
# never a build. Sourced by the CARP syshook and the rc.d service, after keeperconf.sh
# (it uses carpvipdhcp_parse_line). POSIX sh; the netgraph text it reads is the format
# vmac.py parses (captured on FreeBSD 15).
#
# The keeper builds and tears down the graph on every role tick. These guards cover
# what the keeper cannot: a keeper that is dead or stopped when its node is demoted
# (the syshook), and a node left after the option was switched off or a keeper was
# removed (rc.d stop). Inert when ng_patch is not loaded: no patch node can exist
# then, and an ngctl call could load ng_socket.
#
# What a removal touches is what vmac.py's teardown touches: our node vmac_<e> when
# it is a patch node, and on the interface's hooks a patch node that is ours or
# unnamed (an interrupted build leaves one on upper, where it returns every frame).
# A node of any other type is never shut down.

: "${CARPVIPDHCP_NGCTL:=/usr/sbin/ngctl}"
: "${CARPVIPDHCP_KLDSTAT:=/sbin/kldstat}"
: "${CARPVIPDHCP_IFCONFIG:=/sbin/ifconfig}"
: "${CARPVIPDHCP_RUN:=/var/run}"

# carpvipdhcp_vmac_node <ifnet>: our patch node's name (vmac_ + the ether node name,
# the ifnet with '.' as '_'). An ifnet name is at most 15 characters, so this stays
# under netgraph's 31 and maps back to the ether node by dropping the prefix.
carpvipdhcp_vmac_node()
{
    printf 'vmac_%s' "$(printf '%s' "$1" | tr '.' '_')"
}

# carpvipdhcp_vmac_loaded: true when ng_patch is in the kernel (kldstat changes nothing).
carpvipdhcp_vmac_loaded()
{
    "${CARPVIPDHCP_KLDSTAT}" -q -m ng_patch 2>/dev/null
}

_carpvipdhcp_vmac_log()
{
    echo "carpvipdhcp: $*"
    logger -t carpvipdhcp "$*" 2>/dev/null || :
}

# carpvipdhcp_vmac_remove <node>: remove our node <node> (only if it is a patch node)
# and any patch node that is ours or unnamed on its interface's upper or lower hook.
# True when something was shut down.
carpvipdhcp_vmac_remove()
{
    _vm_node="$1"
    _vm_ether="${1#vmac_}"
    _vm_did=''
    _vm_type=$("${CARPVIPDHCP_NGCTL}" show "${_vm_node}:" 2>/dev/null \
        | awk '$1 == "Name:" { print $4; exit }')
    if [ "${_vm_type}" = patch ]; then
        "${CARPVIPDHCP_NGCTL}" shutdown "${_vm_node}:" >/dev/null 2>&1 && _vm_did=1
    fi
    for _vm_hook in $("${CARPVIPDHCP_NGCTL}" show "${_vm_ether}:" 2>/dev/null | awk -v n="${_vm_node}" \
            '($1 == "upper" || $1 == "lower") && $3 == "patch" && ($2 == "<unnamed>" || $2 == n) { print $1 }'); do
        "${CARPVIPDHCP_NGCTL}" shutdown "${_vm_ether}:${_vm_hook}" >/dev/null 2>&1 && _vm_did=1
    done
    _vm_rc=1
    [ -n "${_vm_did}" ] && _vm_rc=0
    unset _vm_node _vm_ether _vm_did _vm_type _vm_hook
    return "${_vm_rc}"
}

# carpvipdhcp_vmac_master <ifnet> <vhid>: true when ifconfig shows this node as the
# CARP master of <vhid> on <ifnet>.
carpvipdhcp_vmac_master()
{
    "${CARPVIPDHCP_IFCONFIG}" "$1" 2>/dev/null | grep -q "carp: MASTER vhid $2 "
}

# carpvipdhcp_vmac_dhcp_wan <ifnet>: true when OPNsense's DHCP client runs on <ifnet>
# (its pid file names a live process; the option needs a static WAN address, D6).
carpvipdhcp_vmac_dhcp_wan()
{
    _vm_pid=$(cat "${CARPVIPDHCP_RUN}/dhclient.$1.pid" 2>/dev/null)
    case "${_vm_pid}" in ''|*[!0-9]*) unset _vm_pid; return 1 ;; esac
    kill -0 "${_vm_pid}" 2>/dev/null
    _vm_rc=$?
    unset _vm_pid
    return "${_vm_rc}"
}

# shellcheck disable=SC2154  # iface and vhid are assigned by carpvipdhcp_parse_line
# carpvipdhcp_vmac_carp_event <keeper.conf> <vhid>@<ifnet> <state>: the syshook guard.
# On any state but MASTER, remove the rewrite of every keeper with that interface and
# vhid (D3: matched from keeper.conf, the option flag not required, so it also clears
# a graph from an earlier configuration). Teardown only, never a build. Runs without
# the keeper, so a dead or stopped keeper cannot leave the rewrite on a backup.
carpvipdhcp_vmac_carp_event()
{
    [ "$3" = MASTER ] && return 0
    [ -f "$1" ] || return 0
    carpvipdhcp_vmac_loaded || return 0
    _vm_vhid="${2%%@*}"
    _vm_if="${2#*@}"
    while IFS= read -r _vm_line || [ -n "${_vm_line}" ]; do
        case "${_vm_line}" in ''|\#*) continue ;; esac
        carpvipdhcp_parse_line "${_vm_line}"
        [ "${iface}" = "${_vm_if}" ] && [ "${vhid}" = "${_vm_vhid}" ] || continue
        _vm_n=$(carpvipdhcp_vmac_node "${iface}")
        carpvipdhcp_vmac_remove "${_vm_n}" \
            && _carpvipdhcp_vmac_log "removed ${_vm_n}: CARP vhid ${vhid} on ${iface} is $3"
    done < "$1"
    unset _vm_vhid _vm_if _vm_line _vm_n
    return 0
}

# shellcheck disable=SC2154  # iface, vhid and vmacegress are assigned by carpvipdhcp_parse_line
# carpvipdhcp_vmac_stop_rule <keeper.conf>: the rc.d stop guard (D1). Keep a node only
# when a keeper.conf record on its interface has the option on, ifconfig shows this
# node as that vhid's CARP master, and no DHCP client runs there; remove every other
# node of ours (a record's interface, or any vmac_* patch node, such as one from a
# removed keeper). So a restart or a package upgrade on a master keeps the rewrite
# (no window of own-MAC frames), while a keeper disabled, the option switched off or
# a backup loses it. Runs after the keepers stopped.
carpvipdhcp_vmac_stop_rule()
{
    carpvipdhcp_vmac_loaded || return 0
    _vm_keep=' '
    _vm_cands=''
    if [ -f "$1" ]; then
        while IFS= read -r _vm_line || [ -n "${_vm_line}" ]; do
            case "${_vm_line}" in ''|\#*) continue ;; esac
            carpvipdhcp_parse_line "${_vm_line}"
            [ -n "${iface}" ] || continue
            _vm_n=$(carpvipdhcp_vmac_node "${iface}")
            _vm_cands="${_vm_cands} ${_vm_n}"
            if [ "${vmacegress}" = 1 ] && carpvipdhcp_vmac_master "${iface}" "${vhid}" \
                    && ! carpvipdhcp_vmac_dhcp_wan "${iface}"; then
                _vm_keep="${_vm_keep}${_vm_n} "
            fi
        done < "$1"
    fi
    _vm_cands="${_vm_cands} $("${CARPVIPDHCP_NGCTL}" list 2>/dev/null \
        | awk '$1 == "Name:" && $4 == "patch" && $2 ~ /^vmac_/ { print $2 }')"
    for _vm_n in ${_vm_cands}; do
        case "${_vm_keep}" in *" ${_vm_n} "*) continue ;; esac
        carpvipdhcp_vmac_remove "${_vm_n}" && _carpvipdhcp_vmac_log "removed ${_vm_n} at stop"
    done
    unset _vm_keep _vm_cands _vm_line _vm_n
    return 0
}
