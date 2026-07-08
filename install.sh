#!/bin/sh
#
# One-line installer / updater for a toreamun/opnsense-plugins plugin on OPNsense.
#
# Resolves the LATEST signed release (no version to hard-code), verifies its
# maintainer signature, installs the Scapy runtime dependency for this box's
# Python, and installs the plugin. Run as root on the OPNsense box:
#
#   fetch -o - https://raw.githubusercontent.com/toreamun/opnsense-plugins/main/install.sh | sh
#
# Re-run the exact same command to UPDATE: it always fetches the current latest
# release and reinstalls over whatever is present (see `pkg add -f` below), so a
# fresh install and an in-place upgrade are the same one-liner. Settings live in
# config.xml and are preserved; the plugin's post-install restarts the keepers
# onto the new code.
#
# Pick a specific plugin (default: os-carp-vip-dhcp):
#   fetch -o - .../install.sh | sh -s -- <plugin-name>
#
# It never hard-codes a version: the release ships a signed SHA256SUMS manifest
# under the fixed `/releases/latest/download/` URL, and the package filename
# (with its version) is read FROM that manifest after the signature checks out.
set -e

REPO="toreamun/opnsense-plugins"
PLUGIN="${1:-os-carp-vip-dhcp}"
BASE="https://github.com/${REPO}/releases/latest/download"
RAW="https://raw.githubusercontent.com/${REPO}/main"

if [ "$(id -u)" != "0" ]; then
    echo "error: run as root" >&2
    exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT INT TERM

echo ">>> Fetching the latest signed manifest + maintainer key..."
fetch -qo "${WORK}/SHA256SUMS" "${BASE}/SHA256SUMS"
fetch -qo "${WORK}/SHA256SUMS.sig" "${BASE}/SHA256SUMS.sig"
fetch -qo "${WORK}/release.pub" "${RAW}/keys/release.pub"

echo ">>> Verifying the manifest signature..."
openssl base64 -d -in "${WORK}/SHA256SUMS.sig" -out "${WORK}/sig.bin"
if ! openssl dgst -sha256 -verify "${WORK}/release.pub" \
        -signature "${WORK}/sig.bin" "${WORK}/SHA256SUMS" >/dev/null 2>&1; then
    echo "error: signature verification FAILED -- aborting" >&2
    exit 1
fi

# The package filename (with version) comes from the signed manifest.
pkgfile="$(awk '{print $2}' "${WORK}/SHA256SUMS" | sed 's#^\./##' | grep "^${PLUGIN}-.*\.pkg$" | head -1)"
if [ -z "${pkgfile}" ]; then
    echo "error: no '${PLUGIN}' package in the latest release" >&2
    exit 1
fi
echo "    latest: ${pkgfile}"

echo ">>> Downloading + checksumming the package..."
fetch -qo "${WORK}/${pkgfile}" "${BASE}/${pkgfile}"
want="$(grep " \./${pkgfile}\$" "${WORK}/SHA256SUMS" | awk '{print $1}')"
got="$(sha256 -q "${WORK}/${pkgfile}")"
if [ -z "${want}" ] || [ "${want}" != "${got}" ]; then
    echo "error: checksum mismatch -- aborting" >&2
    exit 1
fi

echo ">>> Installing the Scapy dependency for this box's Python..."
pyver="$(python3 -c 'import sys; print("py3%d" % sys.version_info.minor)' 2>/dev/null || echo py313)"
pkg install -y "${pyver}-scapy"

# Note the currently-installed version (if any) so the final line can say
# "installed" vs "updated". `|| true` keeps set -e happy when it is absent.
prev="$(pkg query '%v' "${PLUGIN}" 2>/dev/null || true)"

if [ -n "${prev}" ]; then verb="Updating"; else verb="Installing"; fi
echo ">>> ${verb} ${PLUGIN}..."
# -f so the verified release is (re)installed even when an older/other build is
# already present -- i.e. the one-liner also upgrades. The Scapy dependency was
# installed just above (set -e aborts otherwise), so it is present.
pkg add -f "${WORK}/${pkgfile}"
new="$(pkg query '%v' "${PLUGIN}" 2>/dev/null || true)"

if [ -z "${prev}" ]; then
    detail="installed"
elif [ "${prev}" = "${new}" ]; then
    detail="reinstalled at ${new}"
else
    detail="updated ${prev} -> ${new}"
fi
echo ">>> Done. ${PLUGIN} ${detail} and signature-verified."
echo "    (os-carp-vip-dhcp: find it in the GUI under Interfaces > Virtual IPs DHCP.)"
