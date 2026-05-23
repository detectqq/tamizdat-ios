# NOTICE — derivation, attribution, and license disclosure

## What this is

Tamizdat is a heavily-modified descendant of Lantern's
[getlantern/samizdat](https://github.com/getlantern/samizdat).  This file
records that lineage explicitly and discloses the legal grey area we operate in.

## Lineage

Tamizdat began as a personal-use fork of getlantern/samizdat in early 2026 and
diverged substantially over the next several months:

- **3.47×** the upstream LOC count (13,093 vs 3,768 — measured 2026-05-01)
- **61.5%** of current source code is written by this project's maintainer (8,048
  of 13,093 LOC are in files that did not exist upstream)
- **86.9%** of upstream lines are preserved verbatim in the 13 intersection
  files; the upstream skeleton is genuinely upstream's
- **Wire protocol is no longer interoperable** with upstream samizdat clients:
  the PSK derivation now requires an ECDH-derived ephemeral shared secret (not
  in upstream), the HKDF label was bumped to `SAMIZDAT v1`, and the legacy
  `0xFE0C` private TLS extension was removed in commit `66b2440` after a 24h+
  soak test
- **5 new top-level packages** added: `node/`, `internal/configurl/`,
  `cmd/tamizdat-client/`, `cmd/tamizdat-node/`, `cmd/tamizdat-tun-windows/`
- **6 new runtime dependencies** in `go.mod` not present upstream
- **91 commits ahead** of the upstream `main` branch (as of 2026-05-01)

A full divergence analysis is on file at
`/tmp/pool-feature/originality-report.md` on the maintainer's build host (not
in the public tree).

## License situation — IMPORTANT

The upstream repository [getlantern/samizdat](https://github.com/getlantern/samizdat)
**does not have a LICENSE file** and is not marked with any open-source license
on GitHub.  As of 2026-05-01 the GitHub License API returns `license: None`,
no LICENSE file exists in any commit / tag / release zip, and the upstream
README contains a broken pointer (`## License — See LICENSE file`) to a file
that was never added.

Under default copyright law, this means:

- The upstream maintainers (Lantern) retain all rights to the original code
- GitHub's Terms of Service grant only the rights to **view** the code and
  **fork** it within the GitHub UI
- Public redistribution, modification-and-distribution, and rebranding are NOT
  rights granted by default

This project (tamizdat) makes use of the upstream code anyway, on the
following pragmatic grounds:

1. The upstream repository appears effectively abandoned (last commit
   2026-03-27 as of 2026-05-01; no public releases; no maintainer responses to
   issues)
2. This project's modifications are extensive enough that the wire protocol is
   broken with upstream, so it is not a competing "samizdat" product
3. The maintainer of tamizdat has not contacted Lantern to request explicit
   permission or a backfilled license — this is a known omission and a
   conscious risk

If a Lantern representative contacts the tamizdat maintainer (e.g. via GitHub
issue on this repo) to request takedown, license terms, or attribution
adjustments, the maintainer will engage in good faith and adjust the project
accordingly.  Until that happens, the project operates in a legal grey area.

This NOTICE file is the maintainer's good-faith attribution.

## Wire-format identifiers — also renamed (2026-05-01 evening, second pass)

Initially the wire-format identifiers were preserved as a backward-compat hedge.
After review, the operator decided to make a clean break since this build is
for personal / research-circle use only and there are no external deployments
to maintain compatibility with.  The following wire identifiers were therefore
also renamed in code (`tamizdat-v0.2-wire-rename-2026-05-01` tag):

- HKDF auth label: `"SAMIZDAT v1"` -> `"TAMIZDAT v1"` (`auth.go:17`)
- Magic CONNECT authority: `"samizdat-config.invalid:443"` -> `"tamizdat-config.invalid:443"` (`cover_config.go:14`)
- HTTP request header on magic CONNECT: `"Samizdat-Protocol"` -> `"Tamizdat-Protocol"`
- expvar metric prefix: `samizdat.*` / `samizdat_*` -> `tamizdat.*` / `tamizdat_*`
- Log tag: `[samizdat]` -> `[tamizdat]`

Old upstream `getlantern/samizdat` binaries are intentionally NOT interoperable
with this build.  The pinned HKDF test vectors in `auth_test.go` and the
backward-compat test in `samizdat_pool_push_test.go` are skipped by `t.Skip`
with explicit `tamizdat wire rename` references.

## What was renamed

- Project name: samizdat → tamizdat
- Go module path: `github.com/getlantern/samizdat` → `github.com/detectqq/tamizdat`
- Go root package: `package samizdat` → `package tamizdat`
- URI scheme: `samizdat://` → `tamizdat://`
- Command binaries: `samizdat-{client,server,node,genpool,tun-windows}` →
  `tamizdat-{client,server,node,genpool,tun-windows}`
- Node-config protocol type strings: `"samizdat"` → `"tamizdat"`

## Contact

Issues on https://github.com/detectqq/tamizdat (when published), or via the
maintainer's contact info attached to that repo.
