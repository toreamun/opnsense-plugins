PLUGIN_NAME=		carp-vip-dhcp
PLUGIN_VERSION!=	sed -n 's/^__version__ = "\(.*\)"$$/\1/p' ${.CURDIR}/src/opnsense/scripts/OPNsense/CarpVipDhcp/leasekeeper/__init__.py
.if empty(PLUGIN_VERSION)
.error PLUGIN_VERSION could not be derived from leasekeeper/__init__.py
.endif
PLUGIN_COMMENT=		Keep a DHCP lease alive for a CARP virtual IP (DHCP/CGNAT WAN failover)
PLUGIN_MAINTAINER=	tore@amundsen.org
# PLUGIN_PYTHON (from Mk/plugins.mk) tracks the target release's base Python,
# so the scapy dependency follows OPNsense upgrades without manual bumps.
PLUGIN_DEPENDS=		py${PLUGIN_PYTHON}-scapy

.include "../../Mk/plugins.mk"
