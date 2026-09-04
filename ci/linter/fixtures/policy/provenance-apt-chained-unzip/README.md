# fixture: provenance-apt-chained-unzip

An `apt-get install unzip` package token must not hide a separate unverified
archive extraction chained after it. `provenance` must go red.

Workflow: `.github/workflows/ci.yml`.
