PLUGIN_NAME=		carp-vip-dhcp
PLUGIN_VERSION=         1.10.1
PLUGIN_COMMENT=		Keep a DHCP lease alive for a CARP virtual IP (DHCP/CGNAT WAN failover)
PLUGIN_MAINTAINER=	tore@amundsen.org
# PLUGIN_PYTHON (from Mk/plugins.mk) tracks the target release's base Python,
# so the scapy dependency follows OPNsense upgrades without manual bumps.
PLUGIN_DEPENDS=		py${PLUGIN_PYTHON}-scapy

.include "../../Mk/plugins.mk"
