# fixture: provenance-curl-O-unverified

Sibling of `provenance-bare-wget-unverified` for the `curl -O` spelling
(`windows-build.yml:mingw` uses `curl -fsSLO`). The pre-fix scoping regex
required a separate `-O <file>` argument pair and did not match the bundled
`-fsSLO` form, so a job written this way was skipped wholesale rather than
checked.

Exists because the comment on `DOWNLOAD_RE` claims three spellings are
covered; without a probe per spelling, a regression in two of them passes
the selftest.

`provenance` must go red here.

Workflow: `.github/workflows/ci.yml`.
