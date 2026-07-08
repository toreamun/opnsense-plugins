#!/bin/sh
# Ask a running keeper (by request address) to send an ARP nudge right now.
# Sends SIGUSR1 to the daemon; the keeper services it within a second. Emits a
# one-line JSON status for the Diagnostics API.
#
# The argument is mapped to the keeper's filesystem-safe id exactly like rc.d
# and status.py do, so whatever we receive can only ever form a pidfile name
# from [A-Za-z0-9_].

id=$(printf '%s' "$1" | tr -c 'A-Za-z0-9' '_')
pidfile="/var/run/carpvipdhcp-${id}.child.pid"

if [ ! -f "${pidfile}" ]; then
    echo '{"status": "not_running"}'
    exit 0
fi

pid=$(cat "${pidfile}")
case "${pid}" in
    '' | *[!0-9]*)
        echo '{"status": "bad_pidfile"}'
        exit 0
        ;;
esac

if kill -USR1 "${pid}" 2>/dev/null; then
    echo '{"status": "ok"}'
else
    echo '{"status": "signal_failed"}'
fi
