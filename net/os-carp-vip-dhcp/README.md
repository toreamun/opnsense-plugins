# os-carp-vip-dhcp

> **Give a CARP virtual IP its own DHCP lease - so a shared, failover service IP works on a DHCP-assigned WAN.**

[![OPNsense plugin](https://img.shields.io/badge/OPNsense-plugin-d94f00)](https://opnsense.org/)
[![License: BSD-2-Clause](https://img.shields.io/badge/license-BSD--2--Clause-blue)](../../LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/toreamun/opnsense-plugins?style=flat&logo=github&label=Star)](https://github.com/toreamun/opnsense-plugins)
[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-donate-ffdd00?logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/toreamun)

📖 **Full documentation lives on the project landing page: the [repository README](../../README.md)** - what it does, when you need it, getting started, the GUI, how it works, all options, ISP-security notes, and the single-IP design.

**In one line:** a small root daemon keeps a DHCP lease alive on a CARP virtual MAC, so a CARP VIP works - and fails over between two OPNsense nodes - on a DHCP/CGNAT WAN.

Quick pointers:

- **Install** (as root): `fetch -o - https://raw.githubusercontent.com/toreamun/opnsense-plugins/main/install.sh | sh` - see the landing page for the verified / manual / build-from-source paths.
- **Single-IP WAN deep-dive:** [docs/single-ip-wan-carp.md](docs/single-ip-wan-carp.md).
- **This directory** holds the plugin sources (`src/`, `tests/`, `docs/`); the repo mirrors the [opnsense/plugins](https://github.com/opnsense/plugins) ports-tree layout.

If this is useful to you, ⭐ [star the repo](https://github.com/toreamun/opnsense-plugins) - I intend to propose it for the official OPNsense community plugins if there's enough interest.

BSD-2-Clause - see [LICENSE](../../LICENSE).
