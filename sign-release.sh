#!/bin/sh
#
# Sign the built packages in dist/ for a GitHub release.
#
# Produces, in dist/:
#   SHA256SUMS       - sha256 checksums of every *.pkg
#   SHA256SUMS.sig   - detached RSA signature of SHA256SUMS (base64)
#
# Attach the *.pkg files AND both of these to the GitHub release. Users verify
# with the committed public key (keys/release.pub) - see the repo README.
#
# The signing (private) key is a secret: keep it offline or, in CI, as a GitHub
# Actions secret decoded to a file. Never commit it.
#
# Usage:
#   RELEASE_KEY=/path/to/release.key ./sign-release.sh
#
# Key generation (once; keep release.key secret, commit keys/release.pub):
#   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out release.key
#   openssl pkey -in release.key -pubout -out keys/release.pub
set -e

DIST="$(cd "$(dirname "$0")" && pwd)/dist"
: "${RELEASE_KEY:?set RELEASE_KEY to the path of your RSA signing (private) key}"

# Resolve a relative RELEASE_KEY to an absolute path now, before we cd into
# dist/ (otherwise a relative path would be looked up under dist/ and fail).
case "${RELEASE_KEY}" in
    /*) : ;;
    *) RELEASE_KEY="$(pwd)/${RELEASE_KEY}" ;;
esac

if [ ! -f "${RELEASE_KEY}" ]; then
    echo "error: signing key not found: ${RELEASE_KEY}" >&2
    exit 1
fi

cd "${DIST}" 2>/dev/null || { echo "error: no dist/ directory (build first)" >&2; exit 1; }
if ! ls ./*.pkg >/dev/null 2>&1; then
    echo "error: no *.pkg in ${DIST} (build first)" >&2
    exit 1
fi

# 1. Checksums manifest (portable: prefer BSD `sha256`, fall back to `sha256sum`).
if command -v sha256 >/dev/null 2>&1; then
    sha256 -r ./*.pkg > SHA256SUMS
else
    sha256sum ./*.pkg > SHA256SUMS
fi

# 2. Detached RSA-SHA256 signature over the manifest (base64 for easy attach).
openssl dgst -sha256 -sign "${RELEASE_KEY}" -out SHA256SUMS.sig.bin SHA256SUMS
openssl base64 -in SHA256SUMS.sig.bin -out SHA256SUMS.sig
rm -f SHA256SUMS.sig.bin

echo ">>> Signed. Attach to the release:"
ls -1 ./*.pkg SHA256SUMS SHA256SUMS.sig
