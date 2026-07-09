#!/bin/sh
#
# Build an OPNsense plugin package (.pkg) from this repo.
#
# Run this ON AN OPNsense BOX (or an OPNsense build VM), as root. It uses the
# official plugins tree (which provides Mk/plugins.mk + the build tooling) and
# the correct package/dependency names for the running OPNsense release, so the
# resulting .pkg is installable with `pkg add` / uploadable to a GitHub release.
#
# Usage:
#   ./build.sh [-i|--install] [category/plugin]   # default plugin: net/os-carp-vip-dhcp
#
# Output: ./dist/<pkg>.pkg  (with --install, also pkg-add'd into the running system)
#
set -e

INSTALL=0
PLUGIN="net/os-carp-vip-dhcp"
for arg in "$@"; do
    case "$arg" in
        -i|--install) INSTALL=1 ;;
        -*) echo "error: unknown option '$arg' (use -i/--install)" >&2; exit 1 ;;
        *) PLUGIN="$arg" ;;
    esac
done
REPO_DIR=$(cd "$(dirname "$0")" && pwd)
PLUGINS_TREE="/usr/plugins"
DIST="${REPO_DIR}/dist"

if [ "$(id -u)" != "0" ]; then
    echo "error: run as root (needs to install build deps and write ${PLUGINS_TREE})" >&2
    exit 1
fi

if [ ! -d "${REPO_DIR}/${PLUGIN}" ]; then
    echo "error: plugin '${PLUGIN}' not found under ${REPO_DIR}" >&2
    exit 1
fi

# 1. Make sure the official plugins tree is present (provides Mk/ + tooling).
if [ ! -f "${PLUGINS_TREE}/Mk/plugins.mk" ]; then
    if command -v opnsense-code >/dev/null 2>&1; then
        echo ">>> Fetching OPNsense plugins tree via opnsense-code..."
        opnsense-code plugins
    else
        echo ">>> Cloning opnsense/plugins into ${PLUGINS_TREE}..."
        git clone --depth 1 https://github.com/opnsense/plugins "${PLUGINS_TREE}"
    fi
fi

# 2. Stage our plugin into the tree so ../../Mk/plugins.mk resolves.
DEST="${PLUGINS_TREE}/${PLUGIN}"
echo ">>> Staging ${PLUGIN} -> ${DEST}"
rm -rf "${DEST}"
mkdir -p "$(dirname "${DEST}")"
cp -a "${REPO_DIR}/${PLUGIN}" "${DEST}"

# Strip build/test cruft so it can never end up in the package plist (Python
# bytecode caches in particular are under src/ and would otherwise ship).
find "${DEST}" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
find "${DEST}" -name '*.pyc' -delete 2>/dev/null || true

# 3. Build the package.
echo ">>> make package"
make -C "${DEST}" package

# 4. Collect the resulting .pkg.
mkdir -p "${DIST}"
found=$(find "${DEST}/work" -name '*.pkg' 2>/dev/null)
if [ -z "${found}" ]; then
    found=$(find "${PLUGINS_TREE}" -name '*.pkg' -newer "${DEST}/Makefile" 2>/dev/null)
fi
if [ -z "${found}" ]; then
    echo "error: no .pkg produced — check the build output above" >&2
    exit 1
fi
# The plugin depends on Scapy (py3<minor>-scapy); `pkg add` does not resolve deps,
# so ensure it once up front (as install.sh does) before adding the .pkg.
if [ "${INSTALL}" = "1" ]; then
    pyver="py3$(python3 -c 'import sys; print(sys.version_info.minor)')"
    echo ">>> Ensuring dependency ${pyver}-scapy"
    pkg install -y "${pyver}-scapy"
fi

echo "${found}" | while read -r pkg; do
    cp -v "${pkg}" "${DIST}/"
    if [ "${INSTALL}" = "1" ]; then
        # force = reinstall in place when iterating on the same version from main
        echo ">>> Installing $(basename "${pkg}")"
        pkg add -f "${DIST}/$(basename "${pkg}")"
    fi
done

echo ">>> Done. Packages in ${DIST}:"
ls -1 "${DIST}"/*.pkg
if [ "${INSTALL}" = "1" ]; then
    echo ">>> Installed from source. Reload the GUI if it was open."
fi
