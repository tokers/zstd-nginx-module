# fixture: provenance-cache-hit-skips-verify

The trap this check exists to close, not just a duplicate of
`provenance-unverified-extract`: the download step is gated
`if: steps.tool-tarball.outputs.cache-hit != 'true'`, so on a cache HIT no
download step runs at all -- and still nothing in the job asserts a
trust-anchor before `tar -xzf` unpacks whatever `actions/cache` restored. A
checker that only looked at the download step's presence/absence would read
this job as having "no download to gate" on a cache hit and pass it; this one
must still go red because the extract/execute step itself has no anchor
before it, regardless of which path fed the file.

Workflow: `.github/workflows/ci.yml`.
