# Regression corpus

One file per PAST crash, named by its libFuzzer artifact hash
(`crash-<sha1>`), copied here after triage instead of being discarded.
Replayed by `fuzzing.yml`'s `fuzz-regression` job **before** the
time-boxed fresh run — a bug that was fixed once must be caught again in
seconds if it regresses, not only if the fresh budget happens to
rediscover the same input.

Add a case with:

```bash
cp ci/fuzz/crash-<hash> ci/fuzz/regressions/crash-<hash>-<short-description>
```

then `ci/fuzz/fuzz_accept_encoding ci/fuzz/regressions/*` must abort before the
fix and pass after it — verify both, the same as any other regression
test's negative control.

## Seeded case (PR2 step 24)

`crash-wildcard-precedence-flip` (`*, zstd;q=0`) is not a crash this
target found on its own — libFuzzer's short bounded runs against the
real parser stay clean (verified: 693576 execs / 10s, 0 crashes). It
exists to prove the replay mechanism itself works end to end, and to
give the mutation pass evidence: it trips the semantic differential
oracle in `fuzz_accept_encoding.c` (CI5) when the explicit/wildcard
precedence in `ngx_http_zstd_coding_weight()` is flipped, and passes
clean (0ms) against the real parser. See `ci/adoption-findings.md` for
the exact commands and both outcomes.

The workflow step's empty-glob guard (`shopt -s nullglob`) still matters
for whenever this directory is briefly empty again after a cleanup, or
before the first case existed — an empty directory is a real, valid
state, not a bug, and the step reports its case count explicitly either
way rather than silently no-op'ing forever.
