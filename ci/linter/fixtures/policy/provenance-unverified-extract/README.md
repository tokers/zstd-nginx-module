# fixture: provenance-unverified-extract

The bypass class this repo hit: a step downloads a tarball with `wget -O`,
and a later step in the SAME job extracts it with `tar -xzf` and immediately
runs the unpacked binary's `configure` -- with no `gpg --verify`, no
`sha256sum` comparison, and no delegation to `ci-build.sh` /
`fetch-verified-nginx.sh` anywhere in between. `provenance` must go red here.

Workflow: `.github/workflows/ci.yml`.
