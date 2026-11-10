#!/bin/sh
# Shell side of the source-MAC rewrite (leasekeeper/vmac.py, #131): removal only,
# never a build. Sourced by the CARP syshook and the rc.d service. POSIX sh; the
# netgraph text it reads is the format vmac.py parses (captured on FreeBSD 15).
#
# The keeper builds and tears down the graph on every role tick. These guards cover
# what the keeper cannot, and decide from netgraph alone, never from keeper.conf:
#   - the CARP syshook: on any state but MASTER, remove what of ours is on the event's
#     interface, so a keeper that is dead, stopped or gone cannot leave it on a backup;
#   - rc.d stop (all keepers): remove everything of ours on every interface. The
#     keeper rebuilds it at start on the master, so a restart, an Apply or an upgrade
#     there opens a short window of own-MAC frames (documented).
# Inert when ng_patch is not loaded: no patch node can exist then, and an ngctl call
# could load ng_socket.
#
# Ours, here and in vmac.py: the patch node named vmac_<e> (e = the ether node, the
# ifnet with '.' as '_'), and an unnamed patch node on <e>'s hooks that carries our
# build's signature (its "in" hook on upper, or its "out" hook on lower): an
# interrupted build leaves one on upper, where it returns every frame. A node of any
# other type, or an unnamed patch node hooked any other way, is never shut down.
#
# A removal that cannot be confirmed leaves a marker file, carpvipdhcp-vmac.left.<node>,
# in the run directory; a removal confirmed (or nothing found) clears it, after one more
# read right before (an earlier success never clears a later failure). The system
# status raises the markers (CarpVipDhcpStatus.php). One file per node: creating or
# removing it is atomic, so overlapping CARP events and stops need no lock.

: "${CARPVIPDHCP_NGCTL:=/usr/sbin/ngctl}"
: "${CARPVIPDHCP_KLDSTAT:=/sbin/kldstat}"
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
# IDs of what is ours (see the header): the node under our name when it is a patch
# node, and on the ether node's upper or lower hook a patch node under our name, or an
# unnamed one with our signature. _vm_name_ok and _vm_hooks_ok say which reads
# succeeded: "no such node" (exit 71 with ngctl's ENOENT text) is a successful read of
# nothing; any other failure, or exit 0 without a header, is unreadable and never taken
# for clean. A shutdown then addresses those IDs ([id]:), never a hook path, which
# could reach a node that took the hook since the read.
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
            _vm_ids="${_vm_ids} $(printf '%s\n' "${_vm_out}" | awk -v n="$1" '
                ($1 == "upper" || $1 == "lower") && $3 == "patch" && ($2 == n ||
                    ($2 == "<unnamed>" && (($1 == "upper" && $5 == "in") || ($1 == "lower" && $5 == "out")))) {
                    print $4
                }')"
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

# _carpvipdhcp_vmac_unmark <node>: clear <node>'s marker only if a fresh read still finds
# nothing of ours, right before the unlink. A removal confirmed earlier must not clear the
# marker of a later one that failed: the keeper may have rebuilt in between (master
# again), and another guard then failed to remove it. What is left to race is this read
# and the unlink right after it, not a whole removal and its log; and the other guard
# reads for 2 s before it marks.
_carpvipdhcp_vmac_unmark()
{
    [ -e "${CARPVIPDHCP_RUN}/carpvipdhcp-vmac.left.$1" ] || return 0
    _carpvipdhcp_vmac_scan "$1"
    _carpvipdhcp_vmac_clean && rm -f "${CARPVIPDHCP_RUN}/carpvipdhcp-vmac.left.$1"
    return 0
}

# _carpvipdhcp_vmac_settle <node> <why>: remove <node>, log the outcome, and set or clear
# its marker (see the header).
_carpvipdhcp_vmac_settle()
{
    carpvipdhcp_vmac_remove "$1"
    case "$?" in
        0)
            _carpvipdhcp_vmac_log "removed $1: $2"
            _carpvipdhcp_vmac_unmark "$1"
            ;;
        1)
            _carpvipdhcp_vmac_unmark "$1"
            ;;
        *)
            _carpvipdhcp_vmac_log "could not remove $1 ($2): still present or unreadable after 3 tries; it may still rewrite the source MAC"
            : > "${CARPVIPDHCP_RUN}/carpvipdhcp-vmac.left.$1" 2>/dev/null || :
            ;;
    esac
    unset _vm_ids _vm_name_ok _vm_hooks_ok _vm_try _vm_id
}

# carpvipdhcp_vmac_carp_event <vhid>@<ifnet> <state>: the syshook guard. On any state but
# MASTER, remove what of ours is on <ifnet>, whatever keeper.conf says now (a keeper
# disabled, deleted or moved since it built is no longer in it). Teardown only, never a
# build. Another CARP group on the same interface going to backup also removes it; the
# keeper of the group still master rebuilds it at once (the syshook wakes it next), and
# the save refuses that setup anyway.
carpvipdhcp_vmac_carp_event()
{
    [ "$2" = MASTER ] && return 0
    carpvipdhcp_vmac_loaded || return 0
    _carpvipdhcp_vmac_settle "$(carpvipdhcp_vmac_node "${1#*@}")" "CARP vhid ${1%%@*} on ${1#*@} is $2"
    return 0
}

# carpvipdhcp_vmac_stop_rule: the rc.d stop guard (all keepers). Remove everything of
# ours: every vmac_* patch node, and what of ours is on every ether node's hooks. Runs
# after the keepers stopped; the next start rebuilds where the option is on and the
# node is master. A list that fails or has no header is retried, then logged, never
# taken for "none"; the nodes with a marker are tried in any case.
carpvipdhcp_vmac_stop_rule()
{
    if ! carpvipdhcp_vmac_loaded; then
        rm -f "${CARPVIPDHCP_RUN}"/carpvipdhcp-vmac.left.*    # no patch node can exist
        return 0
    fi
    _vm_cands=''
    for _vm_n in "${CARPVIPDHCP_RUN}"/carpvipdhcp-vmac.left.*; do
        [ -e "${_vm_n}" ] && _vm_cands="${_vm_cands} ${_vm_n##*/carpvipdhcp-vmac.left.}"
    done
    _vm_try=0
    while :; do
        if _vm_out=$("${CARPVIPDHCP_NGCTL}" list 2>&1) && printf '%s\n' "${_vm_out}" | grep -q 'Name:'; then
            _vm_cands="${_vm_cands} $(printf '%s\n' "${_vm_out}" | awk '
                $1 == "Name:" && $4 == "patch" && $2 ~ /^vmac_/ { print $2 }
                $1 == "Name:" && $4 == "ether" { print "vmac_" $2 }')"
            break
        fi
        _vm_try=$((_vm_try + 1))
        if [ "${_vm_try}" -ge 3 ]; then
            _carpvipdhcp_vmac_log "could not list the netgraph nodes at keeper stop (3 tries): a rewrite may remain and still rewrite the source MAC; check with ngctl list"
            break
        fi
        sleep 1
    done
    for _vm_n in $(printf '%s\n' "${_vm_cands}" | tr ' ' '\n' | grep '^vmac_[A-Za-z0-9_]*$' | sort -u); do
        _carpvipdhcp_vmac_settle "${_vm_n}" "keeper stop"
    done
    unset _vm_cands _vm_n _vm_try _vm_out
    return 0
}
