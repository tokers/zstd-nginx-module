# Fuzzing

Two coverage-guided libFuzzer targets, both slicing verbatim function
bodies out of shipped production source at build time.

## fuzz_accept_encoding

The RFC 7231 Accept-Encoding / q-value parser in
[`../../src/ngx_http_zstd_common.h`](../../src/ngx_http_zstd_common.h): the
entry point `ngx_http_zstd_accept_encoding()` and the
`ngx_http_zstd_eval_qvalue()` helper it calls. Both are sliced into the fuzz
target together.

### Why fuzz_accept_encoding

It parses attacker-controlled header bytes in C, does pointer arithmetic
against `ae->data`/`ae->len`, and runs the NUL-terminated `ngx_strcasestrn()`
over the same buffer. That length-bounded vs. NUL-bounded mix, plus q-value
edge cases, is the bug class the Perl suite cannot reach and that matches this
module's historical bug profile (truncation, terminal-frame, lifetime).

`extract_parser.sh` slices the verbatim bodies of both parser functions
(`ngx_http_zstd_eval_qvalue` then `ngx_http_zstd_accept_encoding`, in
definition order) out of the shipped header into `generated_parser.inc`
at build time, and fails loudly if it cannot find either.

## fuzz_dcz

The Available-Dictionary byte-sequence decoder,
`ngx_http_zstd_dcz_decode_digest()`, in
[`../../src/ngx_http_zstd_filter_module.c`](../../src/ngx_http_zstd_filter_module.c).
It was extracted out of `ngx_http_zstd_dcz_negotiate()` specifically so this
attacker-controlled-byte slice — the RFC 8941 byte-sequence framing gate plus
`ngx_decode_base64()` — could be fuzzed without dragging in
`ngx_http_request_t`.

### Why fuzz_dcz

Same class as `fuzz_accept_encoding`: attacker-controlled header bytes,
length-bounded parsing, a fixed-size destination buffer. `extract_dcz.sh`
slices the verbatim body out of the shipped `.c` file into
`generated_dcz.inc` at build time.

The destination buffer must be `NGX_HTTP_ZSTD_DCZ_DECODE_BUF_LEN` (48) bytes,
not `NGX_HTTP_ZSTD_SHA256_DIGEST_LEN` (32): an unpadded 44-character
byte-sequence — still within the length gate — decodes to 33 bytes before the
post-decode length check runs. This target caught that exact stack-buffer
overflow during development (a too-small buffer introduced while extracting
the helper, fixed before it shipped); `ngx_shim.h`'s
`ngx_decode_base64()`/`ngx_decode_base64_internal()` are a faithful copy of
`src/core/ngx_string.c` so the target exercises real base64 decode
arithmetic, not a stand-in.

## No copy drift

Neither target carries a hand-maintained copy of the function it fuzzes —
both are sliced fresh from the shipped source on every build. `ngx_shim.h`
supplies only the tiny nginx surface each needs (`ngx_str_t`, `ngx_tolower`,
`ngx_strncasecmp`, `ngx_strcasestrn`, `ngx_decode_base64`), copied faithfully
from upstream `src/core/ngx_string.{h,c}` with citations.

## Run locally

```bash
bash ci/fuzz/build.sh          # needs clang with libFuzzer
cd ci/fuzz
./fuzz_accept_encoding -max_total_time=60 corpus/
./fuzz_dcz -max_total_time=60 corpus_dcz/
```

A crash drops a `crash-*` reproducer. Replay it with:

```bash
./fuzz_accept_encoding crash-<hash>
./fuzz_dcz crash-<hash>
```

## CI

[`fuzzing.yml`](../../.github/workflows/fuzzing.yml) provides a targeted manual
run for both targets. The weekly [`ci-deep.yml`](../../.github/workflows/ci-deep.yml)
campaign runs the two targets concurrently in separate lanes for the selected
long duration. Fuzzing stays out of the bounded PR gate.

ASAN+UBSAN are compiled in, so memory and undefined-behaviour bugs abort the
run and fail the job. Each harness also traps if the function under test
ever returns a value other than `NGX_OK`/`NGX_DECLINED`.
