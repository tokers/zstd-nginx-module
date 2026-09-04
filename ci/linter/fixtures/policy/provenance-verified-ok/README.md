# fixture: provenance-verified-ok

The green sibling of `provenance-unverified-extract`: the SAME job, with a
`sha256sum` comparison step inserted between the download and the
extract/execute step. Run as a PAIR -- without this fixture, the red on
`provenance-unverified-extract` would be equally consistent with "any
download in a job is flagged", not specifically "an unverified one is".

Workflow: `.github/workflows/ci.yml`.
