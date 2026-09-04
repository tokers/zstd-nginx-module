# Contributing

Thank you for contributing — genuinely. Small modules like this live or die
on people who show up with a patch, a bug report, or an awkward question.
You are welcome here.

That said: this document is not decoration. Every rule below exists because
someone (usually us) broke something in a way that took a weekend to clean
up. Read it once before your first PR and you will save us both a round
trip. Break the rules and CI will catch you anyway — the robots are
patient, but they do not negotiate.

If anything here is unclear, **ask**. Asking early is a sign you're doing it
right, not that you're slow. Open an issue, open a draft PR, or mail
**github@myguard.nl**. We answer, and we mentor — everyone who works on
this code started by not knowing nginx internals either.

## TL;DR checklist

- [ ] One feature or fix per PR — no stacked PRs, no drive-by refactors.
- [ ] Code follows nginx style and matches the code around it.
- [ ] Every new feature or bugfix ships a test in the same PR.
- [ ] README updated in the same PR if behaviour changed.
- [ ] All CI checks green. No skipping, no "it works on my machine".
- [ ] Commit messages: imperative subject, body explains *why*.
      No AI co-author trailers.
- [ ] The local hook is enabled (see below) — it runs the same checks the
      Lint job runs, so you find them in a second instead of a CI round-trip.

## Enable the local hook

The repository ships its own pre-commit hook. It is **not** active in a fresh
clone — git never enables hooks automatically — so turn it on once:

```sh
git config core.hooksPath .githooks
```

`.githooks/pre-commit` then runs **two** gates on every commit, and fails on
either:

1. `ci/linter/run-all.sh --staged` — the same `ci/linter/` checkers the **Lint**
   workflow runs (nginx-convention, shell, Python, Perl, YAML, spelling, and the
   CI-policy checkers).
2. the `.pre-commit-config.yaml` hooks — secret detection (gitleaks,
   detect-private-key), the C SAST gates (flawfinder, semgrep, cppcheck),
   ast-grep, ruff, actionlint and shellcheck.

Neither list is a superset of the other, which is why the hook runs both.

**`pre-commit` itself is a hard prerequisite.** When `.pre-commit-config.yaml`
is present and the `pre-commit` binary is missing, the hook exits 2 and blocks
the commit rather than warning — a gate that skips itself when its tool is
absent reports green while checking nothing. The same applies to a missing
linter: `run-all.sh` exits 2 and the commit is blocked.

Install everything the hook calls — `pre-commit` included — with:

```sh
ci/linter/install-linters.sh          # apt + pipx + cpan + upstream binaries
ci/linter/install-linters.sh --check  # report what is present; non-zero if any
                                      # required tool is missing
```

`--check` exits non-zero when a tool is missing, so it is safe to use as a gate
in your own scripts — a tool that is absent is never reported as clean.

Verify the hook is actually live before trusting it — this gate was green and
inert for days once, because `core.hooksPath` makes the copy
`pre-commit install` writes into `.git/hooks/` unreachable while every surface
a human checks still looks installed:

```sh
printf 'probe   \n\nno newline at eof' > _p.txt
git add _p.txt && git commit -m probe -- _p.txt   # expect BLOCKED
git reset -q HEAD _p.txt; rm -f _p.txt
```

Both `trim trailing whitespace` and `fix end of files` must report Failed. If
the commit lands, `.pre-commit-config.yaml` is not being consulted.

Timing: the hook takes ~0.5s for a docs-only change and ~3.6s when a C file is
staged (semgrep is most of that). To run the full set by hand without
committing:

```sh
ci/linter/run-all.sh                  # every checker over the tracked tree
LINT_ONLY="sh python" ci/linter/run-all.sh   # narrow to named checkers
```

One trap worth knowing: `run-all.sh` enumerates files with `git ls-files`, so a
**new untracked file is invisible to it** and the run reads green while checking
nothing. `git add -N` the file first.

## How CI works here

Every PR runs bounded merge gates without monopolising the four self-hosted
runner lanes:

- **Lint** — runs the repository's deterministic source, workflow, security,
  documentation-drift, and four-lane topology checks.
- **Build & Test** — builds the module against current nginx (and, where
  applicable, Angie) and runs the unit tests under **ASan/UBSan**.
  AddressSanitizer and UndefinedBehaviorSanitizer are compiler
  instrumentation that make memory bugs (use-after-free, buffer overflows,
  signed overflow) crash loudly at the exact line instead of corrupting
  memory silently. If ASan complains, the bug is real — fix it, don't
  suppress it.
- **Security scanners** (`security-scanners.yml`) — flawfinder, clang-tidy
  (`cert-*`, `clang-analyzer-security.*`) and semgrep over the module
  sources. Static analysis: it reads the code without running it and
  flags dangerous patterns.
- **Harness fault arms** (`harness-fault-arms.yml`) — runs all six shared
  nginx-module-testkit scenarios against an instrumented module build.
  Visible on every PR and rerun on merged `master`, but not yet a required
  check.
- **Windows build** (`windows-build.yml`) — compiles the Win32 paths with
  MSVC and MinGW, which the Linux lanes cannot cover.

Long work — two fuzz targets, full coverage, CodeQL, native sanitizer soak,
compatibility builds, full Memcheck and Helgrind — runs weekly and on manual
dispatch in `ci-deep.yml`. Its dependency chains keep exactly four
self-hosted lanes busy without an uncontrolled ready-job burst. The expanded
coverage report enforces an 85% line floor. That capacity model assumes the
repository `POOL` variable selects the shared pool; if unset, jobs use their
declared GitHub-hosted fallback.

Your PR merges when **all** checks are green. If a gate fails and you
believe the gate is wrong, say so in the PR — with evidence, not vibes.

Before pushing a parser or fuzz-harness change, fuzz locally first:
`ci/fuzz/build.sh` compiles the target under ASAN+UBSAN
(`-fsanitize=address,undefined`), so a stale harness signature or a
sanitizer-caught bug surfaces right there instead of in CI. (The
module's own C sources are compiled `-Werror` — see
[`build-test.yml`](.github/workflows/build-test.yml) — the fuzz
harness itself is not.)

## Coding conventions

- **nginx style.** This is an nginx module: follow the
  [nginx style guide](https://nginx.org/en/docs/dev/development_guide.html#code_style)
  — 4-space indents, `ngx_` types (`ngx_int_t`, `ngx_str_t`, …), K&R-ish
  bracing as used by nginx core, `/* comments */`.
- **Match the surrounding code.** When in doubt, the file you are editing
  is the style guide. A patch that reads like the code around it is a
  patch we can review quickly.
- **Memory comes from pools.** Allocate from the request/config pool
  (`ngx_palloc`) unless you have a documented reason not to. If you
  `malloc`, you own the cleanup handler.
- **Handle every error path.** nginx runs for months; "can't happen"
  happens. Check return values, log with `ngx_log_error`, fail closed.
- **Comments explain *why*, not *what*.** A surprising nginx-internals
  fact, a footgun, a rejected alternative — write it down at the call
  site or in the README. No undocumented behaviour ships.

## Tests

Every function and every feature gets a test **in the same PR** that adds
it. Not a follow-up PR. Not "later". Same PR.

- New parser or handler → a unit or runtime test exercising it, including
  the ugly inputs (empty, oversized, malformed, truncated).
- Bug fix → a regression test that **fails before the fix and passes
  after**. That's the proof the test actually tests something.
- New input parser → a libFuzzer target in `ci/fuzz/`.

Where tests live varies slightly per module (unit suites, `t/*.t`
Test::Nginx files, runtime suites under `ci/tools/`) — look at the existing
tests in this repo and put yours next to them. A PR that adds code without
a test will not be merged, and yes, we check.

## Pull requests

- **One feature or issue per PR.** The title says what it does. If a PR
  grows a second concern, split it.
- **No stacked PRs.** Every PR branches from and targets the default
  branch independently. Stacks fall over the moment PR #1 gets review
  changes, and untangling them costs more than the stacking saved.
- **Open an issue first** for anything non-trivial; the PR references it
  (`Closes #N`).
- **Keep it reviewable in one sitting.** Small PRs merge fast; 2000-line
  PRs grow moss while we find an afternoon to do them justice.
- **Update the README in the same PR** when behaviour, directives, or
  defaults change. The README must never lag the default branch.
- The default branch is protected by convention: changes land via PR with
  green CI, not direct push.

## Commits

- Imperative subject line ("add X", "fix Y"), ≤ 72 chars.
- Body explains *why* — the design choice made and what was rejected.
- No AI co-author trailers. None.

## Ask for help

Stuck on nginx internals? Not sure where a test belongs? Fuzzer output
looks like hieroglyphics? Ask. Open a draft PR with what you have and say
what you're unsure about — a draft PR full of questions is a perfectly
good contribution. We would much rather spend ten minutes pointing you in
the right direction than review a week of effort aimed at the wrong wall.

## Contact

Questions, security reports, or anything that doesn't fit an issue:
**github@myguard.nl**
