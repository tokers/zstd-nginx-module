# Skeleton adoption findings

Findings from the `ci/PROMPT.md` skeleton-adoption rollout (phase 5, PR2) that
do not fit the mechanical step acceptance criteria and need a record for
step 33's reconciliation pass.

## Step 18 — windows-build.yml has no reference equivalent

`windows-build.yml` (MSVC x64 static + MinGW-w64 x64 dynamic build+smoke) has
no counterpart in `nginx-skeleton-module`. **Decision: keep as-is.**

Reason: it gates something no other workflow in this module or the reference
covers at all — the `NGX_WIN32` build paths, which no Linux job compiles, and
the MSVC-vs-MinGW module-loading difference (static-only vs dynamic .so).
Folding it into an existing member (e.g. `build-test.yml`) would mix a
Windows-only toolchain into a Linux self-hosted-runner workflow for no
benefit; it is not a duplicate of any reference gate under another name.

It already carries a badge and a `## CI` table row (added before this phase);
step 20 only had to reposition it to the end of both lists, after CI Deep.

## Step 17 — versions.env / sha256 pinning NOT ported wholesale

The reference's `.github/versions.env` + `.github/scripts/{load-versions,
compute-versions,fetch-verify}.sh` pin nginx/Angie by version string AND a
committed sha256, fetched from the network.

This module's OWN existing convention (`ci/tools/ci-build.sh`'s header,
`build-test.yml`'s `resolve` job, `codeql.yml`/`valgrind.yml`/`fuzzing.yml`/
`security-scanners.yml`/`ci-deep.yml`) resolves nginx mainline dynamically at
CI run time and verifies the tarball via PGP signature against vendored keys
in `ci/tools/keys/` — deliberately chosen over a fetched sha256 pin. The
`ci-build.sh` header explicitly documents this as a considered rejection of
"the sibling nginx-skeleton-module repo['s]" sha256 approach, citing audit
finding e289021-F3: fetching a verification digest from the same origin that
serves the artifact gives an origin compromise the ability to substitute all
three.

Porting `versions.env` as specified ("also port, adapting paths") would
install a second, competing version-pinning mechanism across 8 workflow
files that already have a coherent, documented one — this is a judgment call
beyond a mechanical port and was escalated to the supervisor rather than
decided unilaterally by the phase-5 worker. See the worker's escalation
packet for step 17/PR #129 (or its successor) for the decision once made.
`.github/actions/build-cache/` and the three `.github/scripts/*.sh` were
likewise left unported pending that decision, since they are wired to the
`versions.env` convention specifically (`asan.yml`'s reference version loads
`.github/scripts/load-versions.sh`; this module's ported `asan.yml` instead
reuses the existing dynamic-resolve + PGP-verify pattern, so it does not
depend on them).
