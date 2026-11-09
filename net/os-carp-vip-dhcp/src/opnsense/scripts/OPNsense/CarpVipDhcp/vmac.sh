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

# _carpvipdhcp_vmac_scan <node>: read what of ours is there, from scratch every time (a
# result from an earlier read never authorizes a shutdown). Sets _vm_ids to the netgraph
# IDs of what is ours: the node under our name when it is a patch node, and a patch
# node that is ours or unnamed on the interface's upper or lower hook (an interrupted
# build leaves one there). _vm_name_ok and _vm_hooks_ok say which reads succeeded: "no
# such node" (exit 71 with ngctl's ENOENT text) is a successful read of nothing; any
# other failure, or exit 0 without a header, is unreadable and never taken for clean.
# A shutdown then addresses those IDs ([id]:), never a hook path, which could reach a
# node that took the hook since the read.
_carpvipdhcp_vmac_scan()
{
    _vm_name_ok='' _vm_hooks_ok='' _vm_ids=''
    if _vm_out=$("${CARPVIPDHCP_NGCTL}" show "$1:" 2>&1); then
        _vm_t=$(printf '%s\n' "${_vm_out}" | awk '$1 == "Name:" { print $4, $6; exit }')
        if [ -n "${_vm_t}" ]; then
            _vm_name_ok=1
            [ "${_vm_t%% *}" = patch ] && _vm_ids="${_vm_t#* }"
        fi
    else
        case "${_vm_out}" in *"No such file or directory"*) _vm_name_ok=1 ;; esac
    fi
    if _vm_out=$("${CARPVIPDHCP_NGCTL}" show "${1#vmac_}:" 2>&1); then
        if printf '%s\n' "${_vm_out}" | grep -q 'Name:'; then
            _vm_ids="${_vm_ids} $(printf '%s\n' "${_vm_out}" | awk -v n="$1" \
                '($1 == "upper" || $1 == "lower") && $3 == "patch" && ($2 == "<unnamed>" || $2 == n) { print $4 }')"
            _vm_hooks_ok=1
        fi
    else
        case "${_vm_out}" in *"No such file or directory"*) _vm_hooks_ok=1 ;; esac
    fi
    _vm_ids=$(printf '%s\n' "${_vm_ids}" | tr ' ' '\n' | grep . | sort -u)
    unset _vm_out _vm_t
}

# _carpvipdhcp_vmac_clean: true when the last scan read both sides and found nothing of ours.
_carpvipdhcp_vmac_clean()
{
    [ -n "${_vm_name_ok}" ] && [ -n "${_vm_hooks_ok}" ] && [ -z "${_vm_ids}" ]
}

# carpvipdhcp_vmac_remove <node>: remove what of ours is there (see the scan), by node
# ID, then read back, up to three tries a second apart. Returns 0 when something was
# there and is confirmed gone, 1 when nothing of ours was there, 2 when it is still
# there or could not be read (never reported as removed: a shutdown can fail or lie).
carpvipdhcp_vmac_remove()
{
    _carpvipdhcp_vmac_scan "$1"
    _carpvipdhcp_vmac_clean && return 1
    for _vm_try in 1 2 3; do
        for _vm_id in ${_vm_ids}; do
            "${CARPVIPDHCP_NGCTL}" shutdown "[${_vm_id}]:" >/dev/null 2>&1
        done
        _carpvipdhcp_vmac_scan "$1"
        _carpvipdhcp_vmac_clean && return 0
        [ "${_vm_try}" = 3 ] || sleep 1
    done
    return 2
}

# _carpvipdhcp_vmac_report <rc> <node> <why>: log the outcome of a removal.
_carpvipdhcp_vmac_report()
{
    case "$1" in
        0) _carpvipdhcp_vmac_log "removed $2: $3" ;;
        2) _carpvipdhcp_vmac_log "could not remove $2 ($3): still present or unreadable after 3 tries; it may still rewrite the source MAC" ;;
    esac
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
    if kill -0 "${_vm_pid}" 2>/dev/null; then
        unset _vm_pid
        return 0
    fi
    unset _vm_pid
    return 1
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
        carpvipdhcp_vmac_remove "${_vm_n}"
        _carpvipdhcp_vmac_report $? "${_vm_n}" "CARP vhid ${vhid} on ${iface} is $3"
    done < "$1"
    unset _vm_vhid _vm_if _vm_line _vm_n _vm_ids _vm_name_ok _vm_hooks_ok _vm_try _vm_id
    return 0
}

# Two notes in the run directory keep the stop rule looking where keeper.conf no longer
# does. When a keeper is removed or moved, keeper.conf (rendered before the stop) no
# longer names its interface, and an unnamed node from an interrupted build there is
# found only through that interface's hooks.
#   carpvipdhcp-vmac.noted: our node names where a keeper may build (a record with the
#     option on), written by rc.d start (carpvipdhcp_vmac_note).
#   carpvipdhcp-vmac.unconfirmed: the nodes the last stop could not confirm removed,
#     written only by the stop rule, so a start in between never drops them; each stop
#     tries them again.
# Node names, not interface names: vmac_<e> maps back to the ether node by dropping the
# prefix, while the ifnet's '.' does not come back from '_'.
_carpvipdhcp_vmac_noted()
{
    printf '%s/carpvipdhcp-vmac.noted' "${CARPVIPDHCP_RUN}"
}

_carpvipdhcp_vmac_unconfirmed()
{
    printf '%s/carpvipdhcp-vmac.unconfirmed' "${CARPVIPDHCP_RUN}"
}

# shellcheck disable=SC2154  # iface and vmacegress are assigned by carpvipdhcp_parse_line
# carpvipdhcp_vmac_note <keeper.conf> [append]: note the node of every record with the
# option on, for the stop rule. rc.d start calls it: replace on the all-keepers path,
# append when one keeper starts. It only reads keeper.conf and writes one file in the
# run directory: no ngctl, nothing loaded.
carpvipdhcp_vmac_note()
{
    _vm_file=$(_carpvipdhcp_vmac_noted)
    _vm_list=''
    if [ -f "$1" ]; then
        while IFS= read -r _vm_line || [ -n "${_vm_line}" ]; do
            case "${_vm_line}" in ''|\#*) continue ;; esac
            carpvipdhcp_parse_line "${_vm_line}"
            [ -n "${iface}" ] && [ "${vmacegress}" = 1 ] \
                && _vm_list="${_vm_list}$(carpvipdhcp_vmac_node "${iface}")
"
        done < "$1"
    fi
    if [ "$2" = append ] && [ -f "${_vm_file}" ]; then
        _vm_list="$(cat "${_vm_file}")
${_vm_list}"
    fi
    printf '%s' "${_vm_list}" | grep . | sort -u > "${_vm_file}" 2>/dev/null || :
    unset _vm_file _vm_list _vm_line
    return 0
}

# shellcheck disable=SC2154  # iface, vhid and vmacegress are assigned by carpvipdhcp_parse_line
# carpvipdhcp_vmac_stop_rule <keeper.conf>: the rc.d stop guard (D1). Keep a node only
# when a keeper.conf record on its interface has the option on, ifconfig shows this
# node as that vhid's CARP master, and no DHCP client runs there; remove every other
# node of ours (a record's interface, a noted or unconfirmed node, or any vmac_* patch
# node, such as one from a removed keeper). So a restart or a package upgrade on a
# master keeps the rewrite (no window of own-MAC frames), while a keeper disabled, the
# option switched off or a backup loses it. Runs after the keepers stopped.
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
    # The noted and the unconfirmed nodes (see the notes above).
    _vm_cands="${_vm_cands} $(cat "$(_carpvipdhcp_vmac_noted)" "$(_carpvipdhcp_vmac_unconfirmed)" 2>/dev/null)"
    # Every vmac_* patch node, such as a removed keeper's (no record names it). A list
    # that fails or has no header is retried, then logged: never taken for "none".
    _vm_try=0
    while :; do
        if _vm_out=$("${CARPVIPDHCP_NGCTL}" list 2>&1) && printf '%s\n' "${_vm_out}" | grep -q 'Name:'; then
            _vm_cands="${_vm_cands} $(printf '%s\n' "${_vm_out}" \
                | awk '$1 == "Name:" && $4 == "patch" && $2 ~ /^vmac_/ { print $2 }')"
            break
        fi
        _vm_try=$((_vm_try + 1))
        if [ "${_vm_try}" -ge 3 ]; then
            _carpvipdhcp_vmac_log "could not list the netgraph nodes at keeper stop (3 tries): a removed keeper's rewrite may remain and still rewrite the source MAC; check with ngctl list"
            break
        fi
        sleep 1
    done
    _vm_left=''
    for _vm_n in $(printf '%s\n' "${_vm_cands}" | tr ' ' '\n' | grep . | sort -u); do
        case "${_vm_keep}" in *" ${_vm_n} "*) continue ;; esac
        carpvipdhcp_vmac_remove "${_vm_n}"
        _vm_rc=$?
        _carpvipdhcp_vmac_report "${_vm_rc}" "${_vm_n}" "keeper stop"
        [ "${_vm_rc}" = 2 ] && _vm_left="${_vm_left}${_vm_n}
"
    done
    # What could not be confirmed is tried again at the next stop, whatever a start
    # notes in between.
    if [ -n "${_vm_left}" ]; then
        printf '%s' "${_vm_left}" > "$(_carpvipdhcp_vmac_unconfirmed)" 2>/dev/null || :
    else
        rm -f "$(_carpvipdhcp_vmac_unconfirmed)"
    fi
    unset _vm_keep _vm_cands _vm_line _vm_n _vm_ids _vm_name_ok _vm_hooks_ok _vm_try _vm_id _vm_out \
        _vm_left _vm_rc
    return 0
}
