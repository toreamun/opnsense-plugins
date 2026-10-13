#!/bin/sh

# Clear every per-keeper daemon log. Invoked by the configd action
# `carpvipdhcp clear_log` from the Log page's clear button. The current file is
# truncated (the running daemon keeps it open); the files its log rotation
# moved out (.log.1, .log.2, ...) are removed, since the Log page shows them too.
# Best-effort: a missing or unwritable file is skipped, never fatal.
# CARPVIPDHCP_LOG_DIR is for the tests only.

log_dir="${CARPVIPDHCP_LOG_DIR:-/var/log}"
for log in "${log_dir}"/carpvipdhcp-*.log; do
    [ -f "${log}" ] && : > "${log}"
done
rm -f "${log_dir}"/carpvipdhcp-*.log.[0-9] "${log_dir}"/carpvipdhcp-*.log.[0-9][0-9]
exit 0
