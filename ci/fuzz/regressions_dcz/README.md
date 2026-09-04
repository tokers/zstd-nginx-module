# dcz regression corpus

One file per PAST `fuzz_dcz` crash, named `crash-dcz-<short-description>`,
copied here after triage instead of being discarded. Replayed by
`fuzzing.yml`'s `fuzz-regression` job **before** the time-boxed fresh run,
so a bug that was fixed once is caught again in seconds if it regresses.

Separate from `../regressions/` on purpose: that directory feeds
`fuzz_accept_encoding`, whose input language is an `Accept-Encoding`
header value. This target takes an RFC 8941 byte sequence. Replaying one
corpus through the other target proves nothing.

Add a case with:

```bash
cp ci/fuzz/crash-dcz-<hash> ci/fuzz/regressions_dcz/crash-dcz-<short-description>
```

then verify both halves, the same as any other regression test's negative
control: `ci/fuzz/fuzz_dcz ci/fuzz/regressions_dcz/*` must abort before the
fix and pass after it.

## Recorded cases

`crash-dcz-framing-ok-payload-bad` (`::`) — the two-byte input whose
framing is well-formed but whose payload is empty. It crashed CI on
2026-08-25: PR #172 split `ngx_http_zstd_dcz_decode_digest()`'s failure
return into `NGX_DECLINED` (framing) and `NGX_ERROR` (payload), but this
harness still asserted the old two-value contract and trapped on the new
`NGX_ERROR`. The production code was correct; the oracle was stale.
Verified red/green: exit 77 against the pre-fix harness, exit 0 after.
