# Release process & review gates

Every release candidate passes the reviews below before it is signed and tagged.
Most are runnable on a live OPNsense node (or an `opnsense-devel` VM); the code
reviews are static.

## Review templates

| # | Review | Covers |
|---|--------|--------|
| 1 | **Security** (OWASP + plugin) | no secrets committed; input validated at the model boundary; command/config injection (escaping in templates, shell args, configd); root only where needed; ACL correct; never clobber another owner's config/aliases |
| 2 | **Packaging & lifecycle** | clean install / uninstall / reinstall leaves no trace and no warnings; permissions (`755` scripts, `644` includes); plist complete with no `__pycache__`/`.pyc`/cruft; package ABI is the wildcard OPNsense plugins use and there is no version-pinned dependency; install/deinstall hooks behave |
| 3 | **HA / failover correctness** | no crash if a CARP failover happens mid-operation; no split-brain / false demotion; config-sync correctness; failover/failback timing and flap |
| 4 | **Robustness / edge cases** | daemon self-heals (never dies on a transient fault); rejects spoofed/malformed input; throttle / retry / idempotency |
| 5 | **Code quality / idiomatic** | lint green (flake8 / pylint / pyright / phpcs / shellcheck / xmllint / markdownlint); OPNsense MVC + configd conventions; no dead code, stale docstrings or TODOs |
| 6 | **Functional / integration** | every feature works end-to-end on a live node; GUI pages load; configd actions succeed |
| 7 | **Docs / UX** | README complete and accurate; GUI help text clear; no dead links; no hard-coded release numbers in user docs; LICENSE present |
| 8 | **Release artifact** (sign gate) | version consistent (`__version__` == tag; the README pins no version); build from a **clean `git archive` checkout**, not the working tree; artifact has no cruft; `SHA256SUMS` + `SHA256SUMS.sig` verify with `keys/release.pub`; maintainer correct |

## Cutting a release

Versioning (semver-ish, package and git tag always in lockstep):

- The release number is `__version__` in
  `net/<cat>/<plugin>/src/opnsense/scripts/OPNsense/CarpVipDhcp/leasekeeper/__init__.py`;
  the Makefile derives `PLUGIN_VERSION` from it, so there is one place to bump. Bump **Y**
  for new functionality, **Z** for fixes, docs/help and logging tweaks.
- The **model** `<version>` (`CarpVipDhcp.xml`) is a separate three-part number
  that only changes when the **config schema** changes (new fields / changed
  defaults). It drives OPNsense config migrations, not releases.

```sh
# 1. Bump the version and commit.
#    leasekeeper/__init__.py: __version__ = "<X.Y.Z>"  (the Makefile reads it)

# 2. Build from a CLEAN checkout (never the working tree -- bytecode caches and
#    other ignored files must not leak into the package).
mkdir -p /tmp/rc && git archive HEAD | tar -x -C /tmp/rc && cd /tmp/rc
sh build.sh net/<cat>/<plugin>               # as root -> dist/<plugin>-<X.Y.Z>.pkg

# 3. Sign the built package(s).
RELEASE_KEY=/path/to/release.key ./sign-release.sh   # -> dist/SHA256SUMS(.sig)

# 4. Tag and publish, back in the real repo checkout (the archive has no .git).
git tag -a v<X.Y.Z> -m "<plugin> v<X.Y.Z>"
git push origin v<X.Y.Z>
gh release create v<X.Y.Z> /tmp/rc/dist/*.pkg /tmp/rc/dist/SHA256SUMS /tmp/rc/dist/SHA256SUMS.sig
```

See [`keys/README.md`](keys/README.md) for key handling and the repository README
for how users verify a release.
