# Security Policy

`zstd-nginx-module` runs inside the nginx/Angie worker process and
operates on attacker-influenced input (the `Accept-Encoding` request
header, response bodies of arbitrary upstreams). Security reports are
taken seriously.

## Reporting a vulnerability

**Do not open a public issue for security vulnerabilities.**

Report privately via GitHub's
[private vulnerability reporting](https://github.com/myguard-labs/nginx-zstd-module/security/advisories/new)
("Report a vulnerability" under the repository's Security tab). If that
is unavailable, contact the maintainers at the address on the
[deb.myguard.nl](https://deb.myguard.nl/) site.

Please include:

- Affected version / commit (`git rev-parse HEAD` or the release tag)
- nginx or Angie version and libzstd version
- A minimal reproduction: `nginx.conf` snippet + request, or a fuzz
  input / crash artifact
- Observed vs. expected behaviour (crash, hang/CPU spin, memory growth,
  information disclosure, etc.)

## Scope

In scope — issues in this module's code:

- Memory safety: buffer overflow, use-after-free, uninitialised reads
  (the module is built and smoke-tested under ASAN/UBSAN)
- Denial of service: worker crash, infinite loop / CPU spin, unbounded
  memory or input consumption
- Request-parsing flaws in `ngx_http_zstd_accept_encoding()` (this
  function is continuously fuzzed)
- Incorrect output that could mislead a client or cache (e.g. a
  corrupted compressed stream, missing `Vary`)

Out of scope — not this module's layer:

- **CRIME / POODLE** and other TLS-layer attacks — configure
  `ssl_protocols` / TLS appropriately; this module never sees TLS.
- **BREACH** as a class — compression ratio is an inherent side
  channel; no HTTP compressor can be made BREACH-safe while
  compressing. The module provides `zstd_bypass` as a *containment
  lever* (exclude at-risk endpoints); the effective defence is
  application-layer (CSRF token masking, separating secrets from
  reflected input). A report that "compression leaks size" is not a
  vulnerability in this module.
- Vulnerabilities in nginx, Angie, or libzstd themselves — report those
  upstream.
- Misconfiguration (e.g. `zstd_static always` serving `.zst` to
  non-zstd clients) — documented behaviour, not a flaw.

## Handling

- Acknowledgement target: within 7 days.
- Triage and a fix or mitigation plan: as fast as severity warrants;
  worker-crash / RCE / DoS are prioritised.
- Fixes land with a regression test (every historical security bug
  class in this module has a dedicated test) and, where applicable, a
  new fuzz seed.
- Coordinated disclosure: a fix is prepared before public detail; the
  reporter is credited unless they prefer otherwise.

## Verifying a build

Security-relevant CI runs on every change and is reproducible locally:

```bash
# Memory safety
# (build nginx with -fsanitize=address,undefined, then:)
python3 ci/tools/test_encoding.py --nginx-binary /path/to/asan-nginx
bash ci/tools/test_reload_leak.sh /path/to/asan-nginx

# Fuzz the request parser
bash ci/fuzz/build.sh && ./ci/fuzz/fuzz_accept_encoding -max_total_time=60 ci/fuzz/corpus/
```

See [`.github/workflows/`](.github/workflows/) (build-test, codeql,
security-scanners, fuzzing, valgrind, ci-deep, bump) and the
[Testing & CI](README.md#testing--ci) section of the README.
