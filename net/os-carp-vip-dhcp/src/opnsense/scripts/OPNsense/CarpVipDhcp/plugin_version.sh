#!/bin/sh
# Print the installed plugin version (empty if somehow not registered). Read-only;
# wired as the configd "carpvipdhcp version" action and shown on the Status page
# so an operator can confirm an upgrade took and spot HA version skew between
# nodes. Kept out of the per-poll diag so pkg(8) is queried once per page load.
pkg query %v os-carp-vip-dhcp 2>/dev/null || true
