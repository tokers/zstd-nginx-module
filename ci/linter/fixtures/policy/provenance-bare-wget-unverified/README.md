# fixture: provenance-bare-wget-unverified

Same defect as `provenance-unverified-extract`, written with the download
spelling four of this repo's own jobs actually use: `wget -q "<url>"` with
**no** `-O`. The first version of the scoping regex required `-O`/`-o`, so a
job written this way matched no download token at all and was skipped
WHOLESALE -- not passed, never examined. That is a gate failing open: the
seven jobs it silently excluded were verified only by luck, and a future
unverified copy of the idiom would have been invisible.

`curl -O` and PowerShell `Invoke-WebRequest -OutFile` were blind the same
way; `ci-deep.yml:scanners` is a real site the narrow regex never scanned.

`provenance` must go red here.

Workflow: `.github/workflows/ci.yml`.
