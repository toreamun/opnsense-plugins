PLUGIN_NAME=		carp-vip-dhcp
PLUGIN_VERSION!=	sed -n 's/^__version__ = "\(.*\)"$$/\1/p' ${.CURDIR}/src/opnsense/scripts/OPNsense/CarpVipDhcp/leasekeeper/__init__.py
.if empty(PLUGIN_VERSION)
.error PLUGIN_VERSION could not be derived from leasekeeper/__init__.py
.endif
PLUGIN_COMMENT=		Keep a DHCP lease alive for a CARP virtual IP (DHCP/CGNAT WAN failover)
PLUGIN_MAINTAINER=	tore@amundsen.org
# No PLUGIN_DEPENDS: the daemon is pure Python stdlib over raw /dev/bpf (the
# scapy backend and its py-scapy dependency were dropped), so nothing to install.

.include "../../Mk/plugins.mk"
