# Release signing keys

`release.pub` is the RSA **public** key used to verify GitHub-release packages
(see the repository README, "Verifying releases"). It is safe to publish.

## Generate the keypair (maintainer, once)

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out release.key
openssl pkey -in release.key -pubout -out keys/release.pub
```

- **Commit `keys/release.pub`** (this file's directory).
- Keep **`release.key` secret** — never commit it (`.gitignore` blocks `*.key`).
  Store it offline (e.g. a password manager / hardware token), or, if release
  signing is ever automated in CI, as a GitHub Actions secret named `RELEASE_KEY`.

## Sign a release

After building the `.pkg` files into `dist/` (see [`../build.sh`](../build.sh)):

```sh
RELEASE_KEY=/path/to/release.key ../sign-release.sh
```

Attach `dist/*.pkg`, `dist/SHA256SUMS` and `dist/SHA256SUMS.sig` to the GitHub
release.

## Rotating the key

Generate a new keypair, commit the new `release.pub`, and re-sign future
releases. Old releases stay verifiable with the old public key from git history.
