# fixture: provenance-unverified-unzip

An archive's extension is not its format: a downloaded ZIP can be named
`payload` and `unzip payload` still extracts it. With no trust anchor before
that extraction, `provenance` must go red.

Workflow: `.github/workflows/ci.yml`.
