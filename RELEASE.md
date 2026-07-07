# Release process & review gates

Every release candidate passes the reviews below before it is signed and tagged.
Most are runnable on a live OPNsense node (or an `opnsense-devel` VM); the code
reviews are static.

## Review templates

| # | Review | Covers |
|---|--------|--------|
| 1 | **Security** (OWASP + plugin) | no secrets committed; input validated at the model boundary; command/config injection (escaping in templates, shell args, configd); root only where needed; ACL correct; never clobber another owner's config/aliases |
| 2 | **Packaging & lifecycle** | clean install / uninstall / reinstall leaves no trace and no warnings; permissions (`755` scripts, `644` includes); plist complete with no `__pycache__`/`.pyc`/cruft; dependency ABI matches the target release; install/deinstall hooks behave |
| 3 | **HA / failover correctness** | no crash if a CARP failover happens mid-operation; no split-brain / false demotion; config-sync correctness; failover/failback timing and flap |
| 4 | **Robustness / edge cases** | daemon self-heals (never dies on a transient fault); rejects spoofed/malformed input; throttle / retry / idempotency |
| 5 | **Code quality / idiomatic** | lint green (flake8 / phpcs / shellcheck / xmllint); OPNsense MVC + configd conventions; no dead code, stale docstrings or TODOs |
| 6 | **Functional / integration** | every feature works end-to-end on a live node; GUI pages load; configd actions succeed |
| 7 | **Docs / UX** | README complete and accurate; GUI help text clear; no dead links; version pins current; LICENSE present |
| 8 | **Release artifact** (sign gate) | version consistent (Makefile == tag == README pin); build from a **clean `git archive` checkout**, not the working tree; artifact has no cruft; `SHA256SUMS` + `SHA256SUMS.sig` verify with `keys/release.pub`; maintainer correct |

## Cutting a release

Versioning (semver-ish, package and git tag always in lockstep):

- `PLUGIN_VERSION=<X.Y.Z>` — bump **Y** for new functionality, **Z** for fixes,
  docs/help and logging tweaks. This is the release number.
- The **model** `<version>` (`CarpVipDhcp.xml`) is a separate three-part number
  that only changes when the **config schema** changes (new fields / changed
  defaults) — it drives OPNsense config migrations, not releases.

```sh
# 1. Bump the version and commit.
#    net/<cat>/<plugin>/Makefile: PLUGIN_VERSION=<X.Y.Z>

# 2. Build from a CLEAN checkout (never the working tree -- bytecode caches and
#    other ignored files must not leak into the package).
git archive HEAD | tar -x -C /tmp/rc && cd /tmp/rc
sudo sh build.sh net/<cat>/<plugin>          # -> dist/<plugin>-<X.Y.Z>.pkg

# 3. Sign the built package(s).
RELEASE_KEY=/path/to/release.key ./sign-release.sh   # -> dist/SHA256SUMS(.sig)

# 4. Tag and publish.
git tag -a v<X.Y.Z> -m "<plugin> v<X.Y.Z>"
git push origin v<X.Y.Z>
gh release create v<X.Y.Z> dist/*.pkg dist/SHA256SUMS dist/SHA256SUMS.sig
```

See [`keys/README.md`](keys/README.md) for key handling and the repository README
for how users verify a release.
