# Adoption findings (PR2, phase 5)

Findings from steps 21-26 that are not simply "done" — either a mutation
result worth recording, or something the module already had that diverges
from what the phase asked for. Feeds step 33.

## Step 21 — unit tests over the real decision TU

`ci/tests/unit/run.sh` + `test_accept_encoding.c`. Unlike the skeleton's scan
core, the Accept-Encoding parser in `src/ngx_http_zstd_common.h` is pure,
self-contained ASCII walking that needs only `ngx_strncasecmp()` /
`ngx_strcasestrn()` — `ci/fuzz/ngx_shim.h` already supplies faithful copies
of those, so this layer reuses the shim rather than linking a full nginx
build tree's real `ngx_string.c`. That is a deliberate divergence from the
skeleton's convention (which links the real upstream TU because its scan
core calls `ngx_unescape_uri()`), not an oversight: this module's parser has
no such dependency, and the shim's own header cites the exact upstream
functions it copies. `run.sh` still regenerates
`ci/fuzz/generated_parser.inc` from the shipped header via
`extract_parser.sh` before every build, so the shipped parser is what gets
linked, never a hand copy.

24 checks, all green:

```text
$ bash ci/tests/unit/run.sh 2>&1 | tail -3
ok   an unterminated quoted parameter value does not hang the walk and does not fabricate a matching zstd token

24/24 checks passed
```

### Mutation pass: Accept-Encoding parser

All 5 applied to `src/ngx_http_zstd_common.h`, observed, reverted — tree
diffed clean against a pre-mutation backup after each.

1. **Wildcard/explicit precedence flipped** — swapped the order of the two
   `if` blocks at the end of `ngx_http_zstd_coding_weight()` so `star_q` is
   checked before `coding_q`.
   Command: manual `perl -0pi` swap, then `bash ci/tests/unit/run.sh`.
   Result: `22/24 checks passed` — `FAIL explicit 'zstd;q=0' overrides a
   permissive '*'`, `FAIL explicit 'zstd' overrides a restrictive '*;q=0'`.
   Reverted; `diff` against backup identical; re-run confirmed `24/24`.

2. **`scale /= 10` removed** from the fractional-digit loop in
   `ngx_http_zstd_eval_qvalue()` (line ~153) — every digit after the decimal
   point is now weighted 100 instead of decaying ×10 per digit, which also
   breaks the implicit 3-digit cap the `scale > 0` guard enforces.
   Result: `23/24 checks passed` — `FAIL a fourth q decimal digit makes the
   element non-matching`. (Originally expected this to move the 2-digit
   `q=0.05` case instead; it did not, because 2 digits at weight 100 each
   still lands >0 either way. Corrected the code comment in
   `test_accept_encoding.c` to describe the actually-observed failure rather
   than the originally-assumed one — see "a guess phrased like a command result gets acted on as fact".)

3. **Malformed-weight fallback to q=1** — inserted `if (q < 0) { q = 1000; }`
   before the `if (q >= 0)` block in `ngx_http_zstd_coding_weight()`, so a
   malformed `;q=` no longer makes the element non-matching.
   Result: `20/24 checks passed` — 4 checks fail (fourth-digit, missing
   value, bare `q`, end-of-buffer `q=`).

4. **`ngx_http_zstd_skip_quoted()` disabled** — `return p;` inserted before
   its own bounds check, unconditionally.
   Result: **the suite did not FAIL, it HUNG.** `case_skip_quoted_unterminated`'s
   unterminated `"..."` value makes the caller's element-skip loop
   (`while (*p != ',') { if (*p=='"') p = skip_quoted(p,end); else p++; }`)
   call the now-no-op `skip_quoted()` at the same `p` forever.
   Command: built to a distinct binary, ran under `timeout 5`.
   `$ timeout 5 /tmp/t2; echo exit=$?` → `exit=124`.
   This is exactly why `case_skip_quoted_unterminated` exists — a plain
   pass/fail assertion cannot distinguish "quote skip is a no-op" from "quote
   skip is correct but slow"; only a bounded run can. Recorded the observed
   hang, not the originally-assumed FAIL, in the test's own header comment.

5. **Off-by-one in the parameter-name scan** — `p < end` → `p <= end` in the
   name-scan loop inside `ngx_http_zstd_eval_qvalue()` (line 104).
   Ran under `clang -fsanitize=address,undefined` as well as plain `cc`.
   Result: `23/24 checks passed` — `FAIL 'q' with no '=value' makes the
   element non-matching, not an implicit q=1`. **No ASan trap fired** — the
   outer `while (p < end && *p == ';')` guard means the widened inner
   condition is only ever reached with `p == end` already inside the
   caller's bound, so this specific off-by-one is a logic bug, not a memory
   -safety one. Recorded rather than assumed: "off by one" does not
   automatically imply "overread", and asserting it would would have been an
   unverified claim.

All 5 mutations caught (none SURVIVED per rejected-test item 8); each
tripped a different, correctly-attributed check (no rejected-test item 4
shared-counter false-positive — verified per-mutation which named checks
flipped, not just the aggregate count).

## Step 22 — live-server layer

The module already has its own mature live-server driver convention:
separate, purpose-named scripts under `ci/tools/` (`test_reload_under_load.py`,
`test_concurrent_cctx_isolation.py`, `test_slow_drain.py`, `test_dcz.py`,
`test_compression_matrix.py`, ...) rather than the skeleton's single
`ci/tools/test_runtime.py` driver file. Per "adopt the convention, keep the
content", this session kept the module's own multi-script convention rather
than collapsing it into one `test_runtime.py` — the reviewed reason (step
22's "what belongs here" line) is about *placement* (driver vs `ci/t/`), and
every existing script here already only does what the driver's three
exemptions allow (concurrency, a signal at the master mid-traffic, or N
separate own-connection requests), so nothing needed to move.

**Gap found and closed: no baseline loaded-and-blocking control.** None of
the existing driver scripts prove the module is actually acting — they
assert response *correctness* under a stressor, which a module that failed
to load, or whose `enable` predicate silently decided OFF, could still
satisfy by accident (an unmodified passthrough is still byte-correct).
Added `ci/tools/test_baseline_loaded.py`: two live requests against the same
backend, one with `zstd on;` (must compress, decode byte-exact), one with NO
zstd directive at all (must NOT be zstd-encoded — the compiled-in default).
Wired into `build-test.yml`'s `tests-asan` job (`--port 18107
--backend-port 18108 --off-port 18112`, ports checked against every existing
`--port`/`--backend-port` literal in the file to avoid a collision) because
that job's binary is the one static (`--add-module`) build already produced
in this pipeline (asan.yml's own build), and the "no directive" case needs a
build where the module is compiled in but not turned on by config — a
dynamic `load_module`-based build cannot express that distinction cleanly
(no directive → unknown directive, config fails to parse, which the module-
unloaded case already covers via a different binary).

### Mutation pass: Module loading behavior

Ran locally against a hand-built static `--add-module` nginx (not part of
the fast PR lane; the CI wiring above uses the pipeline's own asan.yml
artifact instead).

1. **Module genuinely unloaded** — built the SAME nginx tree with no
   `--add-module` at all, ran the baseline script against it.
   `$ python3 ci/tools/test_baseline_loaded.py --nginx-binary
   /tmp/nginx-no-module`
   Result: `RuntimeError: nothing listening on 127.0.0.1:18110` (nginx fails
   to start at all — `zstd on;` is an unknown directive) — the script itself
   raises rather than silently passing. Confirms the baseline genuinely
   depends on the module being present.

2. **`enable` default flipped ON** — `src/ngx_http_zstd_filter_module.c`
   line 1919, `ngx_conf_merge_value(conf->enable, prev->enable, 0)` →
   `..., 1)`. Rebuilt (`objs/nginx`, distinct mtime/size verified against
   the pre-mutation binary each time — see
   "check artifact mtime before trusting a stack trace"), ran against a build with the
   mutation and a build without.
   Unmutated: `2/2 checks passed`, exit 0.
   Mutated: `FAIL baseline: response was zstd-encoded with NO zstd
   directive present -- compiled-in default is not OFF`, exit 1.
   **First attempt at this mutation test silently passed 2/2 against the
   mutated binary** — the script's own `--off-port` originally defaulted to
   `args.port + 1`, which collided with `--backend-port`'s default
   (18111 == 18110+1), so the "no directive" nginx failed to bind and the
   client request landed directly on the backend instead, which is
   trivially never zstd-encoded regardless of the mutation. Fixed by giving
   the off-case its own `--off-port` argument, distinct from both `--port`
   and `--backend-port`; re-ran and got the FAIL above. Left as a comment in
   the script at the call site so the next port choice does not repeat it.
   This is exactly the class of finding rejected-test item 4 (a shared
   resource that lets one check's assertion satisfy an unrelated one)
   generalizes to outside pure counters — recorded here rather than
   shipping the false-negative test.

Reverted both source and binaries after; `diff` against the pre-mutation
`.c` backup confirmed clean before committing.

## Step 25 note

Out of my 21-26 slice, but investigated because it's adjacent to step 24's
soak evidence and the finding is severe.

**CONFIRMED, not just suspected: `valgrind.suppress` (then at the repo root;
now `ci/suppressions/valgrind.suppress`) is a
copied, generic file, not one derived from this module.** First pass (during
step 22) searched for `valgrind.supp` (the skeleton's filename) and found
nothing, and wrongly concluded no suppression file existed at all. It does
— `ci/tools/soak.sh` then referenced `$(repo root)/valgrind.suppress`
(note the different name, `.suppress` not `.supp`) — correcting that
earlier miss here per "a guess phrased like a command result gets acted on as fact" /
"a grep miss proves the spelling absent, not the gap real" (searched the wrong spelling,
took the miss as proof of absence).

Read the file (218 lines, 28 suppression blocks): **every single block is
still named `<insert_a_suppression_name_here>`** (the valgrind
`--gen-suppressions` template placeholder, never filled in), and at least
two blocks reference symbols that do not exist anywhere in this build —
`fun:ngx_http_lua_ndk_set_var_get` (this module does not vendor or depend on
ngx_http_lua_module) and `fun:drizzle_state_connect` (a MySQL/Drizzle
upstream module, also absent). This is the well-known generic nginx
valgrind suppression file that circulates online, not a suppression set
derived from `USE_VALGRIND=1 ci/tools/soak.sh <this module's binary>`. It
is exactly the "wrong tree" trap this phase's front matter names: a copied
`valgrind.supp`/`.suppress` can suppress the module's OWN errors, and this
one's `Memcheck:Leak` / `Memcheck:Cond` blocks are broad enough (bare
`fun:ngx_alloc` / `fun:memcpy` frames with no caller chain reaching this
module) that a real leak or uninitialized-read bug inside
`ngx_http_zstd_*` could plausibly match one of them by accident, silently
passing the gate.

**Did not patch this.** Fixing it correctly requires a real
`USE_VALGRIND=1 ci/tools/soak.sh <nginx-binary> 60 4` run against this
module's own static build, per the file's own header instructions on how a
suppression must be derived (or the skeleton's `valgrind.supp` header, which
states the same discipline) — building nginx from source plus a 60s
Valgrind soak is a build+soak long-runner, explicitly forbidden for a
worker session to run locally, and blindly deleting or rewriting 28
suppression entries without that real run risks either reintroducing false
leak noise (deleting the entries that ARE legitimate nginx-core lifetime
allocations) or leaving the module under-suppressed against upstream noise
that then reads as a module regression.

**This is a MUST-FIX finding for whoever runs step 25/30 properly, ranked
above the codeql.yml/ci-deep.yml items** (those two were checked and are
already correctly target-scoped — see below): run the real soak, name every
surviving suppression after the actual nginx-core call chain it matches
(per the file's own documented convention), delete every block whose
symbol does not appear in this build's call graph at all (the two
confirmed above, and any others found the same way), and verify
`valgrind --suppressions=ci/suppressions/valgrind.suppress ...`'s
`ERROR SUMMARY` line
shows nonzero suppressed count per surviving block (a suppression matching
nothing is dead weight, same standard the skeleton's own header states).

**codeql.yml and ci-deep.yml, checked in the same pass, are already
correct** — no finding: `codeql.yml`'s `paths:` is `filter`, `static`, `*.c`,
`*.h` with `paths-ignore: nginx-*/**` (module TU only, not copied from the
skeleton), and `ci-deep.yml`'s matrix names this module's own real
flavor/version triples (nginx 1.31.2, 1.30.4, angie 1.12.1), not the
reference's.

## Step 23 — fuzz target, corpus and dictionary

The fuzz target (`ci/fuzz/fuzz_accept_encoding.c`) already satisfied the
hard requirement before this session: it links the real
`ngx_http_zstd_accept_encoding()` / `ngx_http_zstd_eval_qvalue()` /
`ngx_http_zstd_coding_weight()` via `extract_parser.sh` (never a
reimplementation), carries a 9041-file curated corpus, and a
`fuzz.dict` already built from the module's own real Accept-Encoding
grammar (not the skeleton's tokens). It also already has an independent
semantic-differential oracle (`ref_accepts()`), which is stronger than
this phase's baseline ask.

**Gap found and closed: `"dcz"` was missing from `fuzz.dict`.** The module
has no single lookup table of coding names (unlike the skeleton's rule
table) — the tokens are two literal call-site arguments to
`ngx_http_zstd_coding_weight(ae, "TOKEN", ...)`, one in
`src/ngx_http_zstd_filter_module.c` ("dcz") and one in
`src/ngx_http_zstd_common.h`'s own wrapper ("zstd"). Added
`ci/fuzz/gen_dict.sh`, which greps those exact call sites (both `.c` and
`.h` — an earlier version of the script only scanned `.c` and missed
"zstd", caught immediately by running `--check` against the tree; see the
commands below) and replaces a marked block in `fuzz.dict` in place.
Wired `gen_dict.sh --check` into `ci/linter/lint-c.sh`.

```text
$ bash ci/fuzz/gen_dict.sh --check
✓ fuzz.dict coding tokens match src/*.c call sites: "dcz" "zstd"

$ sed -i 's/"dcz"/"xyz"/' ci/fuzz/fuzz.dict && bash ci/fuzz/gen_dict.sh --check; echo exit=$?
✗ fuzz.dict's generated coding-token block is stale.
  Source call sites: "dcz" "zstd"
  Run: ci/fuzz/gen_dict.sh
exit=1
# restored, re-checked clean

$ bash ci/linter/lint-c.sh   # with the same drift reintroduced
  fuzz.dict coding-token drift (ci/fuzz/gen_dict.sh --check)
✗ fuzz.dict's generated coding-token block is stale.
# (rc=1, confirmed the linter gate actually fails on this)
```

Did not attempt to measure a coverage-vs-signature-reach delta the way
the reference module's own step 23 evidence does (PROMPT.md cites a
23→35/645 table-literal reach figure) — this module's "table" is two
literals, not 645, so that specific metric does not apply; noted here so
nobody goes looking for a coverage number that was never produced.

## Step 24 — replay order and the ASan soak

**Replay-then-fuzz order.** Added `ci/fuzz/regressions/` (was entirely
missing) and a "Replay recorded crash regressions" step in
`fuzzing.yml`, before the time-boxed fresh run, with a `nullglob` guard
so an empty directory reports its case count rather than silently
matching nothing forever.

No fuzz-discovered crash existed to seed it with (a bounded local run —
693576 execs in 10s — found none against the current corpus/dict, which
is itself a proof-of-clean, not a gap). Seeded one synthetic case,
`crash-wildcard-precedence-flip` (`*, zstd;q=0`), from mutation 1 of
step 21's mutation pass (wildcard/explicit precedence swap), which trips
the fuzz target's own semantic-differential oracle:

```text
# mutated ngx_http_zstd_coding_weight() (precedence swapped):
$ ./fuzz_target_mutant /tmp/crash-wildcard-precedence-flip
==...== ERROR: libFuzzer: deadly signal
    ... LLVMFuzzerTestOneInput fuzz_accept_encoding.c:281 ...
exit=77

# reverted to the real parser, rebuilt (distinct binary, verified same
# source diffed clean against the pre-mutation backup before commit):
$ ./fuzz_target_clean /tmp/crash-wildcard-precedence-flip
Executed .../crash-wildcard-precedence-flip in 0 ms
exit=0
```

Then ran it through the actual wired CI step's own command
(`shopt -s nullglob; cases=(regressions/crash-*); ./fuzz_accept_encoding
"${cases[@]}"`) against the real build — 0ms, exit 0, matching the
manual run above. This is the "deliberately reintroduced past bug caught
in seconds" acceptance criterion, verified once then reverted, per the
step's own instruction.

**ASan soak reaches the module, with evidence.** `ci/tools/soak.sh`'s
`worker()` requires `ok > 0` and `bad == 0` per worker, where `bad` is
incremented both on a failed request AND on a response that comes back
zstd-magic-prefixed but fails to `zstd -d` cleanly — so a green soak
proves real compressed responses were served and decoded correctly under
the sanitizer, not merely that nginx did not crash. `asan.yml`'s own
comment overstated this as "asserts it saw >=1 block AND >=1 pass" (no
such block/pass counter exists in soak.sh); corrected the comment to
describe the actual mechanism instead of inventing an assertion that
was not there — small, but exactly the kind of comment-vs-code drift the
green-that-proves-nothing checklist warns about, in this case in the
DOCUMENTATION rather than the check itself, so it was worth fixing on
sight without expanding scope to touch soak.sh's logic (which was
already correct).

Did not run a local ASan soak — the build (~1-2 min) plus soak
(60s+) crosses into long-runner territory for a worker session; the
mechanism was verified by reading soak.sh's actual assertions, not by
executing them locally. Flagged for whoever next runs `asan.yml` in CI
to confirm the corrected comment matches the real log output.

## Stopped here

Landed: steps 21, 22, 23, 24 fully, plus a confirmed (not just suspected)
step 25 finding on the then-root `valgrind.suppress` — read and diagnosed, deliberately
NOT patched (needs a real soak run, a long-runner). codeql.yml and
ci-deep.yml (the other two of step 25's "three neighbours") were checked in
the same pass and are already correct, no finding. Step 26 (coverage.sh +
`coverage` ci-build.sh mode) not started this session — it needs its own
build-tree work (a distinct instrumented build, not a flag on `debug`) that
did not fit in the remaining budget at the standard this phase requires.
See the worker return banner for exact scope remaining.

## Step 27 — the security-scanners gate was proven able to fail (supervisor, 2026-08-22)

Verified rather than assumed, because the whole finding was that this gate
could not fail before the fix. A `strcpy` into an 8-byte stack buffer appended
to `src/ngx_http_zstd_filter_module.c`:

```sh
set -o pipefail
flawfinder --minlevel=4 --error-level=4 \
  src/ngx_http_zstd_filter_module.c src/ngx_http_zstd_static_module.c
-> exit 1
```

Restored immediately; `git status src/` clean afterwards.

Before this branch the same probe exited **0**: `--minlevel` only controls what
is PRINTED, and without `--error-level` flawfinder always exits 0 however much
it finds. The `| tee flawfinder.log` pipe would also have swallowed the status,
so `set -o pipefail` on that step is load-bearing, not decoration.

Also re-verified after all of the cycle's workflow edits: `ci.yml` is still the
only workflow carrying a `pull_request:` trigger. Checked by parsing each
workflow's `on:` key with a YAML loader, not by grepping for the string --
`on:` parses as the boolean True in YAML, so a naive grep is not the same test.

## Step 30 — the depth audit: does each gate reach the module? (2026-08-22)

Five subjects, each answered from configuration plus step 26's coverage report.
No long run started by this step.

### 1. The seam — VERIFIED, with a positive control

`UNIT_ENTRY` = `ci/tests/unit/run.sh`; fuzz entry = `ci/fuzz/build.sh`. Neither
compiles `src/*.c` directly: both `#include` `ci/fuzz/generated_parser.inc`,
which `ci/fuzz/extract_parser.sh` slices verbatim out of the shipped
`src/ngx_http_zstd_common.h`. Both entry points regenerate it at build time
(`ci/tests/unit/run.sh:60`, `ci/fuzz/build.sh:19`), so there is no
hand-maintained copy to drift.

Proven, not assumed:

- regenerating in a clean tree reproduces the committed `.inc` byte for byte
  (no drift);
- renaming `ngx_http_zstd_eval_qvalue()` in `src/ngx_http_zstd_common.h` and
  re-running the extractor propagates the change into the generated TU
  (`PROBE` present) — so an edit to production code really does reach the unit
  and fuzz builds. Source restored, regeneration re-diffed clean.

**What it now catches that it did not before:** a parser change that compiles in
`src/` but was never exercised — previously possible only if someone remembered
to re-copy the parser by hand.

### 2. ASan/UBSan — the soak config reaches the module

`ci/tools/soak.sh` enables the module's own directives in more than one
location: `zstd on`, `zstd_min_length`, `zstd_max_length`, `zstd_types`,
`zstd_bypass $arg_nozstd`, `zstd_window_log 21`, and drives `/bypass` and
`/bypass?nozstd=1` plus clients that do not advertise zstd. Step 26's coverage
over `src/` reports 60.0% — the handler's lines execute, and the figure is not
~1%, so nginx core is not padding the denominator.

**Catches now:** a use-after-free or overflow on the bypass and
Vary/no-zstd-client paths, not only on the happy compress path.

### 3. Fuzzing — surface and dictionary match the parse surface

`fuzz.dict` is derived from real call sites and gated against drift by
`gen_dict.sh --check`, which passes: coding tokens `"dcz"` and `"zstd"` match
the `ngx_http_zstd_coding_weight()` call sites across `src/*.c` **and**
`src/*.h` (gen_dict.sh:43 globs both — 2 call sites in
`ngx_http_zstd_filter_module.c`, 2 in `ngx_http_zstd_common.h`, so a
`.c`-only scan would miss the header's). The parser's table literals are `"*"`,
`"identity"`, `"q"` and `"zstd"`; all are reachable — the qvalue surface has 5
dedicated dict entries
(`";q="`, `"q=0"`, `"q=1"`, `"q=0.0"`, `"q=1.0"`) and 597 of the 9280 corpus
inputs carry a `q=`. Two regression inputs replay before each fresh run.

**Catches now:** qvalue arithmetic and precedence defects, which the mutation
pass in step 24 confirmed the target detects.

### 4. Coverage — measured over the module only

`ci/tools/coverage.sh` reports with gcovr filtered to `src/`; unfiltered gcovr
walks the whole configured nginx tree. Measured 60.0%, so the filter is real —
a ~1% figure would have meant nginx core was in the denominator.

### 5. Valgrind / helgrind

**Memcheck: was not trustworthy as a gate — FIXED at step 41 (2026-08-22).**
The former root `valgrind.suppress` (now
`ci/suppressions/valgrind.suppress`) was the generic circulated nginx file:
all 28 blocks had unedited
`<insert_a_suppression_name_here>` placeholders, naming `ngx_http_lua_*` and
`drizzle_state_connect`, symbols this module never links. It is live config, not
dead — `ci/tools/soak.sh:71,79` passes it to both memcheck and helgrind.

The `fun:malloc` / `fun:memcpy` blocks turned out to be **anchored** to full
nginx call stacks (`ngx_alloc` → `ngx_set_environment` → …) and could not reach
this module's frames. The real defect was a single block:

```text
{ <insert_a_suppression_name_here>
  Memcheck:Cond
  obj:* }
```

`Memcheck:Cond` + `obj:*` matches an uninitialised-value conditional in any
object at any depth, muting that whole class — including in
`ngx_http_zstd_filter_module.so`. Measured on a four-line C program reading one
uninitialised int: without suppressions valgrind exits 99 with 1 error; with
that block alone it exits 0 with none. So `Memcheck lite (60s soak)` was green
by construction for the Cond class, however long it ran.

Fixed by replacing the file with an empty one (option 1 of the two the ledger
recorded) carrying the derivation rules — suppress nothing, hide nothing.
Verified that both memcheck and helgrind accept a comment-only suppressions
file and that the previously-muted error becomes visible again. Sent upstream
(skeleton PR #41) because the skeleton ships the same file to every adopter.

**Helgrind: NOT applicable, settled with evidence.** The module has no shared
cross-worker state. Counted over `src/*.c` and `src/*.h`: `ngx_shared_memory_add`
0, `shm_zone` 0, `ngx_slab` 0, `ngx_atomic` 0, `ngx_thread` 0, `pthread` 0. The
only file-scope mutable state is the two filter-chain pointers at
`src/ngx_http_zstd_filter_module.c:215-216`, assigned once in
`ngx_http_zstd_filter_init()` (`:2358` and `:2361`) — the `postconfiguration`
hook, which runs in the master process before fork. All other state is
per-request `ctx` off the request pool. There is no cross-thread sharing for
helgrind to reason about.

## Step 31 — re-audit the gates that drift (2026-08-22)

Six explicit answers. `/proc/loadavg` was 1.4-2.5 (1-min) on a 6-slot box for
every timing below.

**Caching.** `ci/tools/ci-build.sh` is the single chokepoint; no workflow
duplicates cache logic. Measured in PR2: `NO_CACHE=1` cold build of nginx 1.31.2
-> ccache 0/146 (0.00%); a second identical build -> 146/292 (50.00%) cumulative,
i.e. **100% of the second run's own compiles hit**. Not 0%, so it is wired.
`--with-cc="ccache gcc"` is load-bearing — nginx's configure ignores a bare `CC=`.

**zizmor.** `zizmor --pedantic .github/workflows/` audits **11** workflows;
`ls .github/workflows/*.yml` is **11**. Counts match, no member unaudited. "No
findings to report (3 ignored, 11 suppressed)". All three
`# zizmor: ignore[misfeature]` still name a reason that is still true — each sits
on a `shell: cmd` step in `windows-build.yml` (lines 82, 89, 112) that needs the
environment `vcvars64.bat` installs in that same cmd process. No suppression has
outlived its subject.

**actionlint and the fromJSON ternary.** Acknowledged, not used as evidence:
actionlint is clean, and that says nothing about runner labels. The selector is
`${{ fromJSON(vars.POOL || '["ubuntu-latest"]') }}` on all 10 build-test jobs —
the approved form, no inline pool, no fork ternary. That is probe 2's finding,
not actionlint's.

**LINT_ONLY still matches the checkers that exist.** Normalized comparison, both
directions:

```text
on disk (ci/linter/lint-*.sh): c ci-cadence ci-ports ci-runners ci-secrets
                               docs-drift nginx perl python sh spelling yaml
in lint.yml LINT_ONLY:         nginx sh python perl yaml spelling ci-runners
                               ci-ports ci-cadence ci-secrets docs-drift
on disk but NOT in LINT_ONLY:  c        <- deliberate, documented lint.yml:9-12
in LINT_ONLY but NOT on disk:  (empty)
```

`c` is excluded because flawfinder/clang-tidy/semgrep over `src/` are
`security-scanners.yml`'s job at the same thresholds (PR2 paired them). No
orphan in either direction.

**`run-all.sh` reads `git ls-files`** (`ci/linter/lib.sh:50`), so an untracked
file is invisible and the run reads green while checking nothing. Staged before
every timing and lint run in this pass. The oracle is the checker's file COUNT,
not the exit code.

**Hook timing — OVER the ~2s budget on a C change.** Measured, 3 runs each:

```text
docs-only staged change:   0.51 / 0.52 / 0.56 s   OK
real C file staged:        3.59 / 3.59 s          OVER
```

The first C measurement (0.49s) was a false pass: the file was `touch`ed but
unmodified, so pre-commit skipped its hooks. Forcing a real content change gives
3.59s. Per-hook breakdown with a C file staged:

```text
semgrep    2.17s   <- 60% of the total, alone over budget
cppcheck   0.63s
flawfinder 0.13s
shellcheck 0.08s
ruff       0.08s
```

Not fixed here: the cheap levers (`--jobs=1 --metrics=off`) are already set, and
dropping or narrowing semgrep is a gate-weakening change, not a speed fix. A
C-file commit paying 3.6s is the honest cost of the current gate. Ledgered.

## Step 32 — re-measure the CI shape (2026-08-22)

Numbers from `gh run list`/`gh run view` on run **32547163515** (PR2's final
run, 2026-08-22), not estimates.

**Total wall-clock 370s, 18 jobs.** Critical path is
`resolve(6s) -> build(212s) -> tests(145s)` = 370s. Longest single legs:
CodeQL 266s, MinGW 254s, build 212s, validation 215s, tests-asan 180s.

**Exactly one `pull_request:` entry point holds.** Parsed with a YAML loader,
not a grep — `on:` parses as boolean `True` in YAML, so a grep is a different
test. `ci.yml` is the only one; no member carries `push:`. Step 14's demotion
therefore still holds, and step 16's long-runner greps return `ci.yml` alone.

**Every member is reached.** ci.yml calls 8 members (lint, build-test,
security-scanners, codeql, fuzzing, valgrind, asan, windows-build); the set of
workflows declaring `workflow_call` minus the set ci.yml calls is **empty**, so
no member keeps a stale-green badge.

**Peak concurrency 15 against 6 slots at t+21s** — measured, and worse than the
11 recorded at step 29. Two causes:

1. **The step 29 lane fix for `build-old-libzstd` was never actually in the
   tree.** `adoption-findings.md` recorded it as "landed (safe, single-file,
   verified)", but `build-test.yml:484` on master was still bare
   `needs: resolve`. A note claiming a change landed is not evidence it did —
   `git log -- <file>` showed no such commit. **Now genuinely applied** in this
   PR: `needs: [resolve, validation]` with `if: ${{ !cancelled() }}`, dropping
   this workflow's own fan-out from 7 to 6. Job `name:` deliberately unchanged,
   and the ruleset context `Build & Test / Build (libzstd 1.4.x — fallback
   paths)` re-checked against the live ruleset after the edit.
2. **The cross-workflow pile-on is unchanged and unfixable inside step 29.**
   codeql/security-scanners/fuzzing/valgrind/asan all start at t=0 alongside
   build-test's fan-out, because `needs:` cannot cross a reusable-workflow-call
   boundary: `needs:` on a `uses:` job waits for that member's ENTIRE workflow,
   so laning codeql behind build-test would serialize it behind the 370s
   critical path instead. The only real remedies are folding those single jobs
   into build-test.yml's job graph, or adding pool slots. Sent upstream as
   decision-class feedback (skeleton PR #41, finding 3).

No check was deleted and no threshold widened.
