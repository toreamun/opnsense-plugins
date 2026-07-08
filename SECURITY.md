# Security policy

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue.

Use GitHub's private vulnerability reporting: on this repository, open the
**Security** tab → **Report a vulnerability**. That creates a private advisory
visible only to the maintainer.

This is a personal, best-effort project with a single maintainer. I aim to
acknowledge a report within about a week and to address confirmed issues in a
subsequent signed release.

## Scope

`os-carp-vip-dhcp` runs a **root daemon that parses untrusted WAN traffic**
(DHCP and ARP) and drives OPNsense via `configd`. Reports touching that trust
boundary are especially welcome — packet parsing, privilege use, the
follow/VIP-rewrite decision, and the release-signing chain.

## Verifying a release

Every release ships a `SHA256SUMS` manifest **signed with the maintainer key**
([`keys/release.pub`](keys/release.pub)). Verify the signature before installing:
the bundled `install.sh` does this automatically, or follow the manual steps in
the plugin's README.
