# opnsense-plugins

Third-party [OPNsense](https://opnsense.org/) plugins by [@toreamun](https://github.com/toreamun).

[![OPNsense plugin](https://img.shields.io/badge/OPNsense-plugin-d94f00)](https://opnsense.org/)
[![License: BSD-2-Clause](https://img.shields.io/badge/license-BSD--2--Clause-blue)](LICENSE)
[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-donate-ffdd00?logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/toreamun)

The repository mirrors the layout of the official
[opnsense/plugins](https://github.com/opnsense/plugins) ports tree
(`<category>/<plugin>/`), so each plugin can be built with the standard OPNsense
plugin build system.

## Plugins

| Plugin | Category | Description |
|--------|----------|-------------|
| [os-carp-vip-dhcp](net/os-carp-vip-dhcp/) | net | Keep a DHCP lease alive for CARP virtual IPs, so a CARP VIP can live on a DHCP-assigned WAN (e.g. a CGNAT link) and fail over between two OPNsense nodes. |

## Installing

On the OPNsense box, as root, the installer resolves the latest signed release,
verifies its signature, installs the dependency, and installs the plugin:

```sh
fetch -o - https://raw.githubusercontent.com/toreamun/opnsense-plugins/main/install.sh | sh -s -- <plugin>
```

`<plugin>` defaults to `os-carp-vip-dhcp`. Each plugin's own README (linked in the
table above) has the details. Releases are signed — verify them (below). OPNsense
packages use a wildcard ABI, so one build works across OPNsense versions.

## Verifying releases

`pkg add` does not verify a standalone package, so each release also ships a
signed checksum manifest (`SHA256SUMS` + `SHA256SUMS.sig`). Verify it on the
OPNsense box before installing:

```sh
# one-time: fetch the maintainer public key
fetch -o release.pub https://raw.githubusercontent.com/toreamun/opnsense-plugins/main/keys/release.pub

# with the release's *.pkg, SHA256SUMS and SHA256SUMS.sig in the current dir:
openssl base64 -d -in SHA256SUMS.sig -out SHA256SUMS.sig.bin
openssl dgst -sha256 -verify release.pub -signature SHA256SUMS.sig.bin SHA256SUMS   # -> Verified OK

# check each package against the signed manifest (format-agnostic: match by hash)
for p in *.pkg; do grep -q "$(sha256 -q "$p")" SHA256SUMS && echo "$p: OK" || echo "$p: MISMATCH"; done
```

`Verified OK` proves the manifest was signed with the maintainer key; the diff
proves each `.pkg` matches the signed manifest.

## Building & releasing

See **[RELEASE.md](RELEASE.md)** for the build → sign → tag → publish process and the
review gates each release passes. Packages must be built **on an OPNsense box** —
GitHub Actions has no OPNsense/FreeBSD runner, and the dependency name differs from
stock FreeBSD (OPNsense 26.x uses `py313-scapy`).

## Building from source (development)

For iterating on a running box, drop the plugin into a plugins checkout and install
it directly, then reload the GUI + configd:

```sh
git clone https://github.com/opnsense/plugins /usr/plugins
cp -a net/os-carp-vip-dhcp /usr/plugins/net/
cd /usr/plugins/net/os-carp-vip-dhcp
make install
configctl webgui restart
```

## Development / linting

- Python: PEP 8, max line length 120 (`flake8`, config in [setup.cfg](setup.cfg)).
- PHP: PSR-12 (`phpcs`).
- Run everything locally with [pre-commit](.pre-commit-config.yaml):

```sh
pre-commit install
pre-commit run --all-files
```

CI ([.github/workflows/lint.yml](.github/workflows/lint.yml)) runs the same checks
on every push and pull request.

## License

BSD-2-Clause. See [LICENSE](LICENSE).
