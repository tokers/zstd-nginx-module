# fixture: provenance-noncomparing-sha256

The anchor half failing open, mirroring the scoping half. A step runs
`sha256sum tool.tgz` -- which PRINTS a digest to the log and compares it to
nothing -- and the extract step follows. The first `TRUST_ANCHOR_RE` matched
the bare word `sha256sum`, so this job read as anchored while validating no
bytes at all. A lone `FOO_SHA256:` env declaration nothing tests had the same
effect.

An anchor must show a COMPARISON: `sha256sum -c`, or a captured digest tested
against a pinned `*_SHA256`. `provenance-verified-ok` is the green control
for exactly that shape.

`provenance` must go red here.

Workflow: `.github/workflows/ci.yml`.
