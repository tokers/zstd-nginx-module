#!/usr/bin/env bash
#
# Check the upstream release feeds for newer releases than what's pinned in
# this repo, and rewrite those pins in place. Called by
# .github/workflows/bump.yml on a schedule; also runnable locally to preview
# a bump before it lands.
#
#   ci/tools/bump-versions.sh [--dry-run]
#
# What gets bumped:
#   - nginx STABLE pin  -- ci-deep.yml's build-flavors matrix (label: stable)
#   - angie pin         -- ci-deep.yml's build-flavors matrix (label: angie)
#   - NGINX_SHA256       -- ci/tools/ci-build.sh, nginx-stable only (verified
#                            against the tarball's OWN PGP signature via the
#                            vendored keys in ci/tools/keys/ before the digest
#                            is recorded, so a bad bump can't silently pin a
#                            malicious tarball's hash)
#   - ANGIE_SHA256       -- ci/tools/ci-build.sh (angie.software publishes no
#                            PGP signature, so sha256 is the only check)
#   - HARNESS_NGINX_VERSION -- the harness jobs' static mainline pin, in the
#                            env: blocks of ci-deep.yml AND harness-fault-arms.yml
#                            (the two must agree; a disagreement is fatal here
#                            rather than silently bumped into a third value).
#                            No digest is recorded for it: the jobs fetch
#                            through ci/tools/fetch-verified-nginx.sh, which
#                            PGP-verifies at run time.
#   - ci/tools/windows-pins.sh -- the Windows build's sources: nginx
#                            (mainline), pcre2, zlib, OpenSSL and zstd, each
#                            as a VER_X/SHA_X pair. nasm is NOT bumped:
#                            nasm.us publishes no release feed this script can
#                            query, and it changes rarely -- edit by hand.
#
# nginx mainline in the build-flavors matrix (label: mainline) and the
# NGINX_VERSION: "" of build-test.yml / ci-deep.yml are resolved at CI run
# time by each workflow's own nginx.org scrape (build-test.yml's `resolve`
# job, ci-deep.yml's per-job "Resolve latest mainline nginx" steps -- those
# take the highest version on the page, not a section), so they carry no
# static pin. The harness and Windows jobs pin mainline statically
# -- a fault-injection harness and a Windows binary want a build that does
# not change under them between runs -- and those are the mainline pins
# bumped here.
#
# Digests: nginx tarballs (stable and mainline alike) are PGP-verified before
# a digest is recorded. angie, pcre2, zlib, OpenSSL and zstd publish no
# signature this repo has a vendored key for, so their digest is computed
# from the tarball their release URL serves -- the same provenance a
# hand-recorded pin has, minus the copy-paste step. zlib is served by both
# zlib.net (build-windows.sh) and GitHub (windows-build.yml); both are
# fetched and must agree before the digest is pinned.
#
# The GitHub release feeds serve several release lines at once (OpenSSL
# ships an LTS and a current line, sometimes on the same day), so a pin
# taken from a release API only moves FORWARD: a "latest" that sorts below
# the pinned version is reported and left alone, never written.
#
# A version bump with a stale sha256 pin is worse than no pin (ci-build.sh
# treats a missing pin as "print a warning", but a WRONG pin is a hard FATAL
# for a pinned version; build-windows.sh refuses outright) -- so every
# version edit here is paired with a digest computed from the exact tarball
# that version resolves to, never carried over from a previous entry.

set -euo pipefail
# Command substitutions do not inherit -e by default, so a failed curl inside
# `digest="$(fetch ...)"` would be ignored and the EMPTY temp file hashed and
# pinned. Every fetch below also checks curl explicitly; this closes the same
# hole for anything added later.
shopt -s inherit_errexit

DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1

# Derive every repo-relative path from the script's OWN location, never from
# cwd -- a caller running this from elsewhere must not silently miss the
# ci-build.sh / keys move (A30-F4: tools/ -> ci/tools/, verified dead on the
# old paths).
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

CI_BUILD_SH="ci/tools/ci-build.sh"
KEYS_DIR="ci/tools/keys"
MATRIX_FILE=".github/workflows/ci-deep.yml"
PINS_FILE="ci/tools/windows-pins.sh"
HARNESS_FILES=(".github/workflows/ci-deep.yml" ".github/workflows/harness-fault-arms.yml")

# --- discover latest versions -------------------------------------------

# GET an api.github.com path. The runners share an egress IP, so the
# unauthenticated API allowance (60/hr) is routinely exhausted and the call
# 403s; GH_TOKEN, when present, buys the far larger authenticated quota. The
# header goes in through stdin so the token never appears in curl's process
# arguments on a shared runner.
gh_api_json() { # path
    local json
    if [ -n "${GH_TOKEN:-}" ]; then
        json="$(printf 'header = "Authorization: Bearer %s"\n' "$GH_TOKEN" \
            | curl --config - -fsSL "https://api.github.com/$1")" || json=""
    else
        json="$(curl -fsSL "https://api.github.com/$1")" || json=""
    fi
    if [ -z "$json" ]; then
        echo "error: could not query https://api.github.com/$1 (rate limit? set GH_TOKEN)" >&2
        return 1
    fi
    printf '%s\n' "$json"
}

# nginx publishes every release on GitHub as a Release (not just a tag):
# `release-X.Y.Z`, non-draft, carrying the same signed tarball nginx.org
# serves (byte-identical, same .asc, verified by ci/tools/keys). That is a
# structured feed; nginx.org/en/download.html is HTML whose section
# headings a parser has to know by name, and a renamed heading is a
# refusal at best. The stable and mainline lines follow nginx's own
# versioning rule -- even minor is stable, odd minor is mainline -- so
# each line's newest release is the newest of its parity. Tarballs and
# signatures still come from nginx.org (the pinned URLs do not change);
# only "what is newest" moves here.
#
# The feed is paged and ordered by creation time, not by version: a
# security release of an older line (1.28.x) can be created months after
# the current stable's last release, so the first even-minor entry seen
# is not necessarily the newest stable, and a long run of mainline and
# legacy releases can push the real one to a later page. Every page is
# read until a short page ends the list, and the newest of each line is
# the highest version across all of them. The cap bounds a broken feed,
# not a real one (the feed holds every release since nginx moved to
# GitHub, 29 as of 2026-09 at roughly fifteen a year, so five pages of
# thirty is about a decade away); reaching it with a full page is a
# refusal, never a pick from what was read.
NGINX_FEED_PAGE=30
NGINX_FEED_PAGES=5

NGINX_LINE_PY=$(cat <<'PYEOF'
import json, re, sys
# argv: current best even, current best odd ("-" when none yet).
# stdout: "<best even> <best odd> <entries on this page>", "-" when none.
best = {"even": sys.argv[1], "odd": sys.argv[2]}
try:
    releases = json.load(sys.stdin)
except ValueError:
    sys.exit("FATAL: the nginx release feed is not JSON -- refusing to guess")
if not isinstance(releases, list):
    sys.exit("FATAL: the nginx release feed is not a release list -- refusing to guess")
def parse(v):
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", v)
    return tuple(int(x) for x in m.groups()) if m else None
for r in releases:
    if (not isinstance(r, dict) or r.get("draft") is not False
            or r.get("prerelease") is not False):
        continue
    m = re.fullmatch(r"release-(\d+\.\d+\.\d+)", str(r.get("tag_name", "")))
    if not m:
        continue
    v = parse(m.group(1))
    line = "even" if v[1] % 2 == 0 else "odd"
    cur = parse(best[line]) if best[line] != "-" else None
    if cur is None or v > cur:
        best[line] = "%d.%d.%d" % v
print(best["even"], best["odd"], len(releases))
PYEOF
)

# Prints "<stable> <mainline>" with "-" for a line the feed did not show,
# which the blank-version check below reports by name.
nginx_lines() {
    local page even="-" odd="-" json count
    for ((page = 1; page <= NGINX_FEED_PAGES; page++)); do
        json="$(gh_api_json "repos/nginx/nginx/releases?per_page=${NGINX_FEED_PAGE}&page=${page}")"
        read -r even odd count < <(printf '%s' "$json" | python3 -c "$NGINX_LINE_PY" "$even" "$odd")
        if [ "$count" -lt "$NGINX_FEED_PAGE" ]; then
            break   # a short page is the end of the list
        fi
    done
    # The cap is not an end-of-list marker: a full last page means pages
    # beyond it were never read and may hold a newer release of either
    # line, so the answer is unknown, not "the best so far".
    if [ "$count" -ge "$NGINX_FEED_PAGE" ]; then
        echo "FATAL: the nginx release feed did not end within ${NGINX_FEED_PAGES} pages" \
            "of ${NGINX_FEED_PAGE} -- refusing to pick from an incomplete read" >&2
        return 1
    fi
    printf '%s %s\n' "$even" "$odd"
}

# The version carried by OWNER/REPO's latest GitHub release tag, whatever
# the tag's prefix (v1.3.2, pcre2-10.48, openssl-4.0.2).
gh_latest_tag() {
    local repo="$1" json
    json="$(gh_api_json "repos/${repo}/releases/latest")" || return 1
    echo "$json" | grep -m1 '"tag_name"' | grep -oE '[0-9]+(\.[0-9]+)+' | head -1 || true
}

latest_angie() { gh_latest_tag webserver-llc/angie; }
latest_pcre2() { gh_latest_tag PCRE2Project/pcre2; }
latest_zlib() { gh_latest_tag madler/zlib; }
latest_openssl() { gh_latest_tag openssl/openssl; }
latest_zstd() { gh_latest_tag facebook/zstd; }

read -r NEW_STABLE NEW_MAINLINE < <(nginx_lines)
[ "$NEW_STABLE" != "-" ] || NEW_STABLE=""
[ "$NEW_MAINLINE" != "-" ] || NEW_MAINLINE=""
NEW_ANGIE="$(latest_angie)"
NEW_PCRE2="$(latest_pcre2)"
NEW_ZLIB="$(latest_zlib)"
NEW_OPENSSL="$(latest_openssl)"
NEW_ZSTD="$(latest_zstd)"

for v in NEW_STABLE NEW_MAINLINE NEW_ANGIE NEW_PCRE2 NEW_ZLIB NEW_OPENSSL NEW_ZSTD; do
    if [ -z "${!v}" ]; then
        echo "FATAL: could not determine $v -- refusing to bump with a blank version" >&2
        exit 1
    fi
done

echo "latest: nginx stable=$NEW_STABLE mainline=$NEW_MAINLINE angie=$NEW_ANGIE" \
    "pcre2=$NEW_PCRE2 zlib=$NEW_ZLIB openssl=$NEW_OPENSSL zstd=$NEW_ZSTD"

# --- discover current pins ----------------------------------------------

# Read version and label from the same YAML list entry regardless of their
# order. The mutator below deliberately remains format-strict so unexpected
# layout drift fails before anything is installed.
matrix_version_for_label() {
    awk -v want="$1" '
        function emit() {
            if (l == want && v != "") { print v; found = 1; exit }
        }
        /^[[:space:]]*-[[:space:]]/ { emit(); v = ""; l = "" }
        /version:/ { match($0, /"[0-9.]+"/); v = substr($0, RSTART+1, RLENGTH-2) }
        /label:/   { split($0, a, ":"); l = a[2]; gsub(/[ \t]/, "", l) }
        END { if (!found) emit() }
    ' "$MATRIX_FILE"
}

# The value of KEY=value in windows-pins.sh. The file is data-only (its
# header says so), so the key's line IS the pin; a key that is not there is
# fatal up front, before anything is rewritten -- never a blank "current".
pin_value() {
    local line
    line="$(grep -E "^$1=" "$PINS_FILE" || true)"
    if [ -z "$line" ]; then
        echo "FATAL: $PINS_FILE does not set $1 -- refusing to bump a pin that is not there" >&2
        exit 1
    fi
    echo "${line#*=}"
}

harness_pin() { # FILE
    grep -oE '^  HARNESS_NGINX_VERSION: "[0-9.]+"' "$1" | grep -oE '[0-9.]+' || true
}

CUR_STABLE="$(matrix_version_for_label stable)"
CUR_ANGIE="$(matrix_version_for_label angie)"

CUR_HARNESS="$(harness_pin "${HARNESS_FILES[0]}")"
for f in "${HARNESS_FILES[@]}"; do
    v="$(harness_pin "$f")"
    if [ -z "$v" ]; then
        echo "FATAL: no HARNESS_NGINX_VERSION pin found in $f" >&2
        exit 1
    fi
    if [ "$v" != "$CUR_HARNESS" ]; then
        echo "FATAL: $f pins HARNESS_NGINX_VERSION $v but ${HARNESS_FILES[0]} pins $CUR_HARNESS" \
            "-- the harness jobs must build the same nginx; reconcile by hand first" >&2
        exit 1
    fi
done

# Every Windows pin is read (and so checked for presence) before any edit,
# so a pins file missing one line fails here with nothing rewritten. nasm
# is checked too: build-windows.sh requires all twelve keys, and a bump
# that left the file unable to load would be worse than no bump. It has
# no release feed, so it is not in the discovery above and is never
# rewritten here.
WINDOWS_NAMES=(NGINX PCRE2 ZLIB OPENSSL ZSTD NASM)
declare -A CUR_WIN=()
for name in "${WINDOWS_NAMES[@]}"; do
    CUR_WIN[$name]="$(pin_value "VER_$name")"
    pin_value "SHA_$name" >/dev/null
done

echo "pinned: nginx stable=$CUR_STABLE angie=$CUR_ANGIE harness=$CUR_HARNESS" \
    "windows: nginx=${CUR_WIN[NGINX]} pcre2=${CUR_WIN[PCRE2]} zlib=${CUR_WIN[ZLIB]}" \
    "openssl=${CUR_WIN[OPENSSL]} zstd=${CUR_WIN[ZSTD]} nasm=${CUR_WIN[NASM]}"

CHANGED=0

# --- sha256 helpers ---
# A fetch that fails is fatal here, explicitly: the digest of whatever is
# left in the temp file (nothing) must never be the value recorded.
fetch_or_die() { # url out
    if ! curl -fsSL "$1" -o "$2"; then
        rm -f "$2"
        echo "FATAL: could not fetch $1 -- refusing to pin a digest of what was not downloaded" >&2
        exit 1
    fi
}

sha256_for_url() (
    local url="$1" tmp digest
    cleanup_url_digest() {
        [ -z "${tmp:-}" ] || rm -f -- "$tmp"
    }
    trap cleanup_url_digest EXIT
    tmp="$(mktemp)"
    fetch_or_die "$url" "$tmp"
    digest="$(sha256sum "$tmp" | awk '{print $1}')"
    echo "$digest"
)

sha256_for_angie() {
    sha256_for_url "https://download.angie.software/files/angie-${1}.tar.gz"
}

# nginx (stable and mainline) also gets its detached signature checked
# against the vendored keyring (ci/tools/keys/) before we trust the digest
# we're about to pin -- a bump script that records a hash without checking
# provenance first would just be moving the F3 trust gap here instead of
# fixing it.
sha256_for_nginx() (
    local version="$1" url tmp digest gnupghome keyfiles
    cleanup_nginx_verify() {
        [ -z "${gnupghome:-}" ] || rm -rf "$gnupghome"
        [ -z "${tmp:-}" ] || rm -f "$tmp" "${tmp}.asc"
    }
    trap cleanup_nginx_verify EXIT

    url="https://nginx.org/download/nginx-${version}.tar.gz"
    tmp="$(mktemp)"
    fetch_or_die "$url" "$tmp"
    fetch_or_die "${url}.asc" "${tmp}.asc"

    gnupghome="$(mktemp -d)"
    GNUPGHOME="$gnupghome"
    export GNUPGHOME
    chmod 700 "$gnupghome"
    shopt -s nullglob
    keyfiles=("$KEYS_DIR"/*.key)
    shopt -u nullglob
    if [ "${#keyfiles[@]}" -eq 0 ]; then
        echo "FATAL: no keyring found under $KEYS_DIR -- refusing to pin an unverified digest" >&2
        exit 1
    fi
    for keyfile in "${keyfiles[@]}"; do
        gpg --quiet --import "$keyfile" 2>/dev/null
    done
    if ! gpg --quiet --verify "${tmp}.asc" "$tmp" 2>/dev/null; then
        echo "FATAL: PGP verification failed for nginx-${version}.tar.gz -- refusing to pin an unverified digest" >&2
        exit 1
    fi

    digest="$(sha256sum "$tmp" | awk '{print $1}')"
    echo "$digest"
)

# The release tarball a Windows pin names -- the URL windows-build.yml
# fetches (build-windows.sh uses the same, except zlib.net for zlib).
release_url() { # NAME VERSION
    case "$1" in
        PCRE2) echo "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-$2/pcre2-$2.tar.gz" ;;
        ZLIB) echo "https://github.com/madler/zlib/releases/download/v$2/zlib-$2.tar.gz" ;;
        OPENSSL) echo "https://github.com/openssl/openssl/releases/download/openssl-$2/openssl-$2.tar.gz" ;;
        ZSTD) echo "https://github.com/facebook/zstd/releases/download/v$2/zstd-$2.tar.gz" ;;
        *)
            echo "FATAL: no release URL for $1" >&2
            exit 1
            ;;
    esac
}

sha256_for_release() { # NAME VERSION
    local name="$1" version="$2" digest other
    digest="$(sha256_for_url "$(release_url "$name" "$version")")"
    if [ "$name" = ZLIB ]; then
        # Two hosts serve this one pin; a digest that only one of them
        # matches would fail loudly in the consumer that uses the other.
        other="$(sha256_for_url "https://zlib.net/zlib-${version}.tar.gz")"
        if [ "$other" != "$digest" ]; then
            echo "FATAL: zlib.net and GitHub serve different zlib-${version}.tar.gz" \
                "(${other} vs ${digest}) -- refusing to pin either" >&2
            exit 1
        fi
    fi
    echo "$digest"
}

# is_newer NEW CUR -- NEW sorts strictly above CUR as a version.
is_newer() {
    local sorted

    [ "$1" != "$2" ] || return 1
    if ! sorted="$(printf '%s\n%s\n' "$1" "$2" | sort -V)"; then
        echo "FATAL: could not compare versions $1 and $2" >&2
        return 2
    fi
    [ "$(printf '%s\n' "$sorted" | tail -1)" = "$1" ]
}

# should_bump LABEL NEW CUR -- true only for a strict forward move. Equality
# is quiet; an older feed value is reported as a hold; comparison failure is
# propagated as a fatal status for the caller to distinguish from both.
should_bump() {
    local label="$1" new="$2" cur="$3" rc

    [ "$new" != "$cur" ] || return 1
    if is_newer "$new" "$cur"; then
        return 0
    else
        rc=$?
    fi
    [ "$rc" -eq 1 ] || return "$rc"
    echo "hold $label: release feed says $new, pinned $cur is newer -- not moving a pin backwards"
    return 1
}

# --- mutators -------------------------------------------------------------
# Every mutator here writes to a temp file and renames it into place only
# after the edit is confirmed to have actually matched something -- a no-op
# replacement (stale path, drifted format) FAILS LOUDLY instead of silently
# leaving the file untouched while the script reports success (A30-F4).
# The apply phase points them at STAGED COPIES of the tracked files (see
# below), so a mutator failing part-way leaves every tracked file as it
# was; messages name the tracked file, not the copy.
STAGE=""
UPDATES=""
tracked() { echo "${1#"$UPDATES/"}"; }

bump_matrix_pin() {
    local label="$1" old="$2" new="$3" tmp
    [ "$old" = "$new" ] && return 0
    tmp="$(mktemp)"
    if ! python3 - "$label" "$old" "$new" "$MATRIX_FILE" "$tmp" "$(tracked "$MATRIX_FILE")" <<'PYEOF'
import re, sys
label, old, new, path, out, shown = sys.argv[1:7]
text = open(path).read()
pattern = re.compile(
    r'(version:\s*"' + re.escape(old) + r'"\n\s*label:\s*' + re.escape(label) + r')'
)
replaced = pattern.sub(lambda m: m.group(1).replace(old, new), text)
if replaced == text:
    print(f"FATAL: no matrix entry matched for label={label} old={old} in {shown}", file=sys.stderr)
    sys.exit(1)
open(out, "w").write(replaced)
PYEOF
    then
        rm -f "$tmp"
        exit 1
    fi
    mv "$tmp" "$MATRIX_FILE"
    CHANGED=1
}

_bump_sha256_pin() {
    local table="$1" old="$2" new="$3" digest="$4" tmp
    grep -q "\[\"${new}\"\]" "$CI_BUILD_SH" && return 0 # already pinned
    if ! grep -q "declare -A ${table}=(" "$CI_BUILD_SH"; then
        echo "FATAL: no 'declare -A ${table}=(' table found in $(tracked "$CI_BUILD_SH") -- refusing a no-op pin" >&2
        exit 1
    fi
    tmp="$(mktemp)"
    # Insert the new pin right after the table's opening line; leave old
    # entries in place (ci-build.sh keys by version, older callers still work).
    sed "/declare -A ${table}=(/a\\    [\"${new}\"]=\"${digest}\"" "$CI_BUILD_SH" >"$tmp"
    mv "$tmp" "$CI_BUILD_SH"
    CHANGED=1
}

bump_angie_sha256_pin() {
    local old="$1" new="$2" digest="$3"
    _bump_sha256_pin ANGIE_SHA256 "$old" "$new" "$digest"
}

bump_nginx_sha256_pin() {
    local old="$1" new="$2" digest="$3"
    _bump_sha256_pin NGINX_SHA256 "$old" "$new" "$digest"
}

# Rewrite the one `  HARNESS_NGINX_VERSION: "OLD"` line of a workflow's env:
# block. Anchored on the exact line so a same-looking value elsewhere in
# the file (a comment, a step) is never touched.
bump_harness_pin() { # FILE OLD NEW
    local file="$1" old="$2" new="$3" tmp
    tmp="$(mktemp)"
    sed -E "s|^(  HARNESS_NGINX_VERSION: )\"${old//./\\.}\"\$|\\1\"${new}\"|" "$file" >"$tmp"
    if cmp -s "$tmp" "$file"; then
        rm -f "$tmp"
        echo "FATAL: no '  HARNESS_NGINX_VERSION: \"${old}\"' line in $(tracked "$file") -- refusing a no-op pin" >&2
        exit 1
    fi
    mv "$tmp" "$file"
    CHANGED=1
}

# Rewrite one KEY=value line of windows-pins.sh.
bump_pins_line() { # KEY NEW
    local key="$1" new="$2" tmp
    tmp="$(mktemp)"
    sed -E "s|^${key}=.*\$|${key}=${new}|" "$PINS_FILE" >"$tmp"
    if cmp -s "$tmp" "$PINS_FILE"; then
        rm -f "$tmp"
        echo "FATAL: ${key}=${new} changed nothing in $(tracked "$PINS_FILE") -- refusing a no-op pin" >&2
        exit 1
    fi
    mv "$tmp" "$PINS_FILE"
    CHANGED=1
}

# A Windows pin is a VER_X/SHA_X pair; both lines were confirmed present up
# front (pin_value), so the pair lands whole or the script has already died.
bump_windows_pin() { # NAME NEW DIGEST
    bump_pins_line "VER_$1" "$2"
    bump_pins_line "SHA_$1" "$3"
}

# --- resolve: decide every bump and fetch every digest, editing nothing ---
# All network work happens here, before the first file is touched, so a
# download or verification failure part-way through leaves the tree
# exactly as it was -- never a matrix bumped for a digest that was then
# not fetched. The apply phase below is local edits only, each of which
# fails loudly before writing its file (A30-F4).

STABLE_DIGEST=""
ANGIE_DIGEST=""
WIN_NGINX_DIGEST=""
BUMP_HARNESS=0
declare -A LIB_DIGEST=()

if should_bump "nginx stable" "$NEW_STABLE" "$CUR_STABLE"; then
    echo "bump nginx stable: $CUR_STABLE -> $NEW_STABLE"
    CHANGED=1
    if [ "$DRY_RUN" = 0 ]; then
        STABLE_DIGEST="$(sha256_for_nginx "$NEW_STABLE")"
        echo "  sha256 $STABLE_DIGEST"
    fi
else
    rc=$?
    [ "$rc" -eq 1 ] || exit "$rc"
fi

if should_bump angie "$NEW_ANGIE" "$CUR_ANGIE"; then
    echo "bump angie: $CUR_ANGIE -> $NEW_ANGIE"
    CHANGED=1
    if [ "$DRY_RUN" = 0 ]; then
        ANGIE_DIGEST="$(sha256_for_angie "$NEW_ANGIE")"
        echo "  sha256 $ANGIE_DIGEST"
    fi
else
    rc=$?
    [ "$rc" -eq 1 ] || exit "$rc"
fi

# The two static mainline pins are compared on their own, so a hand-bump of
# one does not hide the other falling behind.
if should_bump "windows nginx" "$NEW_MAINLINE" "${CUR_WIN[NGINX]}"; then
    echo "bump windows nginx: ${CUR_WIN[NGINX]} -> $NEW_MAINLINE"
    CHANGED=1
    if [ "$DRY_RUN" = 0 ]; then
        WIN_NGINX_DIGEST="$(sha256_for_nginx "$NEW_MAINLINE")"
        echo "  sha256 $WIN_NGINX_DIGEST"
    fi
else
    rc=$?
    [ "$rc" -eq 1 ] || exit "$rc"
fi

if should_bump "harness nginx" "$NEW_MAINLINE" "$CUR_HARNESS"; then
    echo "bump harness nginx: $CUR_HARNESS -> $NEW_MAINLINE"
    CHANGED=1
    BUMP_HARNESS=1
else
    rc=$?
    [ "$rc" -eq 1 ] || exit "$rc"
fi

declare -A NEW_LIB=([PCRE2]="$NEW_PCRE2" [ZLIB]="$NEW_ZLIB" [OPENSSL]="$NEW_OPENSSL" [ZSTD]="$NEW_ZSTD")
for name in PCRE2 ZLIB OPENSSL ZSTD; do
    new="${NEW_LIB[$name]}"
    cur="${CUR_WIN[$name]}"
    [ "$new" = "$cur" ] && continue
    if should_bump "windows ${name,,}" "$new" "$cur"; then
        :
    else
        rc=$?
        [ "$rc" -eq 1 ] || exit "$rc"
        continue
    fi
    echo "bump windows ${name,,}: $cur -> $new"
    CHANGED=1
    if [ "$DRY_RUN" = 0 ]; then
        LIB_DIGEST[$name]="$(sha256_for_release "$name" "$new")"
        echo "  sha256 ${LIB_DIGEST[$name]}"
    fi
done

if [ "$CHANGED" = 0 ]; then
    echo "everything up to date, nothing to bump"
fi

if [ "$DRY_RUN" = 1 ] || [ "$CHANGED" = 0 ]; then
    echo "CHANGED=$CHANGED"
    exit 0
fi

# --- apply: local edits only, every input already in hand ----------------
# The mutators work on staged copies of the tracked files, installed
# together at the end, so a mutator failing part-way (a drifted format in
# the second file it reaches) leaves every tracked file as it was -- the
# same guarantee the resolve phase gives for the network.
STAGE="$(mktemp -d)"
ORIGINALS="$STAGE/originals"
UPDATES="$STAGE/updates"
INSTALLING=0
INSTALL_TEMP=""
INSTALLED=()
cleanup_stage() {
    local rc=$? f rollback_tmp rollback_failed=0 i
    trap - EXIT INT TERM
    if [ "$INSTALLING" -eq 1 ] && [ "$rc" -ne 0 ]; then
        for ((i = ${#INSTALLED[@]} - 1; i >= 0; i--)); do
            f="${INSTALLED[i]}"
            rollback_tmp="$(mktemp "$(dirname "$f")/.bump-rollback.XXXXXX")" || {
                rollback_failed=1
                continue
            }
            if ! cp -p "$ORIGINALS/$f" "$rollback_tmp" || ! mv -f "$rollback_tmp" "$f"; then
                rm -f -- "$rollback_tmp"
                rollback_failed=1
            fi
        done
        [ "$rollback_failed" -eq 0 ] || echo "FATAL: rollback could not restore every tracked file" >&2
    fi
    [ -z "$INSTALL_TEMP" ] || rm -f -- "$INSTALL_TEMP"
    rm -rf -- "$STAGE"
    [ "$rollback_failed" -eq 0 ] || rc=1
    exit "$rc"
}
trap cleanup_stage EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# ci-deep.yml is both the matrix and a harness workflow. Keep one copy in
# the transaction so each tracked path is installed and rolled back once.
TRACKED=()
declare -A TRACKED_SEEN=()
for f in "$MATRIX_FILE" "$CI_BUILD_SH" "$PINS_FILE" "${HARNESS_FILES[@]}"; do
    if [ -z "${TRACKED_SEEN[$f]:-}" ]; then
        TRACKED+=("$f")
        TRACKED_SEEN[$f]=1
    fi
done
for f in "${TRACKED[@]}"; do
    mkdir -p "$ORIGINALS/$(dirname "$f")" "$UPDATES/$(dirname "$f")"
    cp -p "$f" "$ORIGINALS/$f"
    cp -p "$f" "$UPDATES/$f"
done
MATRIX_FILE="$UPDATES/$MATRIX_FILE"
CI_BUILD_SH="$UPDATES/$CI_BUILD_SH"
PINS_FILE="$UPDATES/$PINS_FILE"
for i in "${!HARNESS_FILES[@]}"; do
    HARNESS_FILES[i]="$UPDATES/${HARNESS_FILES[i]}"
done

if [ -n "$STABLE_DIGEST" ]; then
    bump_matrix_pin stable "$CUR_STABLE" "$NEW_STABLE"
    bump_nginx_sha256_pin "$CUR_STABLE" "$NEW_STABLE" "$STABLE_DIGEST"
fi

if [ -n "$ANGIE_DIGEST" ]; then
    bump_matrix_pin angie "$CUR_ANGIE" "$NEW_ANGIE"
    bump_angie_sha256_pin "$CUR_ANGIE" "$NEW_ANGIE" "$ANGIE_DIGEST"
fi

if [ -n "$WIN_NGINX_DIGEST" ]; then
    bump_windows_pin NGINX "$NEW_MAINLINE" "$WIN_NGINX_DIGEST"
fi

if [ "$BUMP_HARNESS" = 1 ]; then
    for f in "${HARNESS_FILES[@]}"; do
        bump_harness_pin "$f" "$CUR_HARNESS" "$NEW_MAINLINE"
    done
fi

for name in PCRE2 ZLIB OPENSSL ZSTD; do
    if [ -n "${LIB_DIGEST[$name]:-}" ]; then
        bump_windows_pin "$name" "${NEW_LIB[$name]}" "${LIB_DIGEST[$name]}"
    fi
done

# Every edit succeeded. Replace each changed file atomically and roll back
# earlier replacements if a later install fails or the process is interrupted.
INSTALLING=1
INSTALL_COUNT=0
for f in "${TRACKED[@]}"; do
    cmp -s "$UPDATES/$f" "$f" && continue
    INSTALL_COUNT=$((INSTALL_COUNT + 1))
    INSTALL_TEMP="$(mktemp "$(dirname "$f")/.bump-install.XXXXXX")"
    cp -p "$UPDATES/$f" "$INSTALL_TEMP"
    if [ "${BUMP_VERSIONS_TEST_FAIL_INSTALL_AT:-}" = "$INSTALL_COUNT" ]; then
        echo "FATAL: injected install failure at changed file $INSTALL_COUNT" >&2
        false
    fi
    # Register before mv so a signal in the tiny post-rename window still
    # restores this path. Restoring an unchanged path if mv itself fails is safe.
    INSTALLED+=("$f")
    mv -f "$INSTALL_TEMP" "$f"
    INSTALL_TEMP=""
    if [ "${BUMP_VERSIONS_TEST_INTERRUPT_INSTALL_AT:-}" = "$INSTALL_COUNT" ]; then
        kill -TERM "$$"
    fi
done
INSTALLING=0

echo "CHANGED=$CHANGED"
