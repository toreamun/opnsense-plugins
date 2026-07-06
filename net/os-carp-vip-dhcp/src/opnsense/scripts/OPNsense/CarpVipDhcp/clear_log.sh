#!/bin/sh

# Truncate every per-keeper daemon log. Invoked by the configd action
# `carpvipdhcp clear_log` from the Log page's clear button. Best-effort: a
# missing or unwritable file is skipped, never fatal.

for log in /var/log/carpvipdhcp-*.log; do
    [ -f "${log}" ] && : > "${log}"
done
exit 0
