#!/bin/sh
# vmac_unconfirmed.sh <list file> <add> <drop>: update the list of source-MAC rewrite
# removals not confirmed (see vmac.sh). Adds the node names in <add> and drops those in
# <drop> (space-separated), keeping every other entry, so a CARP event and a stop that
# update it about the same time keep each other's entries. vmac.sh runs it under lockf;
# the new list is written to a file of this process's own, then moved into place, and
# the list is removed when it is empty.

f=$1
# shellcheck disable=SC2086  # $2 is a space-separated list of node names
{ cat "${f}" 2>/dev/null; for n in $2; do echo "${n}"; done; } \
    | awk -v drop=" $3 " 'NF && index(drop, " " $0 " ") == 0' | sort -u > "${f}.$$" \
    || { rm -f "${f}.$$"; exit 1; }
if [ -s "${f}.$$" ]; then
    mv -f "${f}.$$" "${f}"
else
    rm -f "${f}.$$" "${f}"
fi
