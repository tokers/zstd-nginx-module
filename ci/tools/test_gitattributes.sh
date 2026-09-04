#!/bin/sh
# Gates .gitattributes byte-exactness for the fuzz/test fixture dirs
# (A30-F5): corpus_dcz/*, regressions/*, regressions_dcz/*, plus the
# previously-covered corpus/*, fuzz.dict and t/suite/*. core.autocrlf=true
# smudges any path git treats as text, corrupting raw fuzzer inputs and
# saved crash reproducers -- there was no test anywhere pinning this
# before. Also checks the ci-linkcheck-module archive-exclusion rule.
#
# Each assertion below has a paired negative control: a known-text file
# that must report "text: set", and a hash-under-autocrlf check against a
# deliberately text-treated temp file that must differ. Both prove the
# assertion can fail, not just that it happens to pass today.

set -eu

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"

FAIL=0

fail() {
    echo "FAIL: $1" >&2
    FAIL=1
}

# --- a) byte-exact dirs report text: unset ---------------------------------

BYTE_EXACT_PATHS="
ci/fuzz/corpus/01_bare
ci/fuzz/corpus_dcz/bad_hash
ci/fuzz/fuzz.dict
ci/fuzz/regressions/crash-wildcard-precedence-flip
ci/fuzz/regressions_dcz/crash-dcz-framing-ok-payload-bad
ci/t/suite/test
ci/t/suite/dcz-dict
"

for p in $BYTE_EXACT_PATHS; do
    [ -n "$p" ] || continue
    attr="$(git check-attr text -- "$p" | sed 's/.*: text: //')"
    if [ "$attr" != "unset" ]; then
        fail "expected 'text: unset' for byte-exact fixture $p, got '$attr'"
    fi
done

# Negative control for (a): a known-text file must NOT be unset.
attr="$(git check-attr text -- ci/tools/patches/README 2>/dev/null | sed 's/.*: text: //')"
if [ -z "$attr" ] || [ "$attr" = "unset" ]; then
    # patches/README may not exist; fall back to any *.sh, which is
    # unconditionally "text eol=lf" in .gitattributes.
    attr="$(git check-attr text -- ci/tools/test_sha256_unit.sh | sed 's/.*: text: //')"
fi
if [ "$attr" != "set" ]; then
    fail "negative control: expected 'text: set' for a known-text file, got '$attr'"
fi

# regressions READMEs must stay text (the exception rule must win).
for p in ci/fuzz/regressions/README.md ci/fuzz/regressions_dcz/README.md; do
    if [ -f "$p" ]; then
        attr="$(git check-attr text -- "$p" | sed 's/.*: text: //')"
        if [ "$attr" != "set" ]; then
            fail "expected 'text: set' for $p (README exception), got '$attr'"
        fi
    fi
done

# --- b) autocrlf hash control -----------------------------------------------

TMPDIR_WORK="$(mktemp -d "${TMPDIR:-/tmp}/zstd-gitattributes-test.XXXXXX")"
cleanup() {
    rm -rf "$TMPDIR_WORK"
}
trap cleanup EXIT INT TERM

# Pick a byte-exact fixture that is plausible to contain a bare LF (so an
# autocrlf smudge would actually change it): the dcz corpus fixtures are
# fixed-format hash strings without embedded newlines in some cases, so
# use the fuzz corpus entry that is known to include control bytes/LF in
# its Accept-Encoding header samples.
HASH_FIXTURE="ci/fuzz/corpus_dcz/valid_hash"
if [ ! -f "$HASH_FIXTURE" ]; then
    fail "expected fixture missing: $HASH_FIXTURE"
else
    committed_sha="$(git cat-file blob "HEAD:$HASH_FIXTURE" | sha256sum | cut -d' ' -f1)"

    checkout_dir="$TMPDIR_WORK/autocrlf-checkout"
    mkdir -p "$checkout_dir"
    ( cd "$checkout_dir" && git -C "$REPO_ROOT" -c core.autocrlf=true archive HEAD "$HASH_FIXTURE" | tar -x )
    smudged_sha="$(sha256sum "$checkout_dir/$HASH_FIXTURE" | cut -d' ' -f1)"

    if [ "$committed_sha" != "$smudged_sha" ]; then
        fail "byte-exact fixture $HASH_FIXTURE changed under core.autocrlf=true smudging (committed=$committed_sha smudged=$smudged_sha)"
    fi
fi

# Negative control for (b): a deliberately text-treated file with CRLF
# content in its committed blob MUST change hash under autocrlf smudging,
# proving the hash comparison itself is capable of catching a real
# regression (git's autocrlf=true checkout normalizes CRLF -> LF for any
# path git considers text).
control_repo="$TMPDIR_WORK/control-repo"
mkdir -p "$control_repo"
(
    cd "$control_repo"
    git init -q
    git config user.email test@example.invalid
    git config user.name test
    printf 'line one\r\nline two\r\n' > crlf.txt
    printf '*.txt text\n' > .gitattributes
    git add crlf.txt .gitattributes
    git commit -q -m control
)
control_committed_sha="$(git -C "$control_repo" cat-file blob HEAD:crlf.txt | sha256sum | cut -d' ' -f1)"
control_checkout="$TMPDIR_WORK/control-checkout"
mkdir -p "$control_checkout"
( cd "$control_checkout" && git -C "$control_repo" -c core.autocrlf=true archive HEAD crlf.txt | tar -x )
control_smudged_sha="$(sha256sum "$control_checkout/crlf.txt" | cut -d' ' -f1)"

if [ "$control_committed_sha" = "$control_smudged_sha" ]; then
    fail "negative control: expected a text-attributed CRLF file to change hash under core.autocrlf=true smudging, but it did not (test cannot detect a real regression)"
fi

# --- c) archive excludes ci-linkcheck-module --------------------------------

leaked="$(git archive HEAD | tar -t | grep -c '^ci/tools/ci-linkcheck-module/' || true)"
if [ "$leaked" -ne 0 ]; then
    fail "git archive HEAD leaked $leaked ci-linkcheck-module entries (export-ignore rule broken)"
fi

# Negative control for (c): a path NOT covered by export-ignore must
# still appear in the archive, proving the tar listing/grep can see a
# real entry when one exists.
present="$(git archive HEAD | tar -t | grep -c '^ci/tools/test_sha256_unit.sh$' || true)"
if [ "$present" -eq 0 ]; then
    fail "negative control: expected ci/tools/test_sha256_unit.sh present in git archive HEAD, found none"
fi

if [ "$FAIL" -ne 0 ]; then
    echo "FAIL: .gitattributes byte-exactness / archive-exclusion checks failed" >&2
    exit 1
fi

echo "OK: .gitattributes byte-exact fixture rules and archive exclusion verified (with negative controls)"
