#!/usr/bin/env bash
#
# Fixture matrix for two G5 hardening rows against zstd_dict_file and
# zstd_dcz_dict_file, both of which route through the shared
# ngx_http_zstd_open_dict_file() helper:
#
#   1. "Reject non-regular dictionary inputs without letting FIFOs block
#      config test/reload" -- neither loader used to test ngx_is_file()
#      before reading. A FIFO opened O_RDONLY blocks the config-parsing
#      master until a writer appears; a directory/device reaches a
#      confusing later error. Every fixture below runs under `timeout`
#      so a regression HANGS THE SCRIPT, not the CI job, and is reported
#      as a failure either way.
#
#   2. "Strict dictionary-path trust policy for privileged reloads" --
#      zstd_dict_strict_path on (default off) refuses a symlink and a
#      group/world-writable target so a less-privileged local writer
#      cannot steer or mutate what the master snapshots on the next
#      reload. A rejected reload (SIGHUP against a mutated dictionary)
#      must leave the OLD cycle serving, not tear the worker down.
#
# Usage: ci/tools/test_dict_path_hardening.sh <nginx-binary> <module-dir>
#
# <module-dir> holds ngx_http_zstd_filter_module.so (and the static
# module, unused here but harmless to have loaded).

set -euo pipefail

NGINX="${1:?usage: test_dict_path_hardening.sh <nginx-binary> <module-dir>}"
MODDIR="${2:?usage: test_dict_path_hardening.sh <nginx-binary> <module-dir>}"

# Both arguments MUST be absolutized before anything else. Every fixture
# below runs nginx with -p "$WORK" (a mktemp dir), and nginx resolves a
# relative load_module path against that prefix -- so a caller passing
# "nginx-1.31.4/objs" yields load_module /tmp/tmp.XXXX/nginx-1.31.4/objs/...
# and dlopen() fails. The damage is not a plain red: every fixture that
# EXPECTS a rejection still "passes", because the config was refused for
# the wrong reason. Resolve here rather than trusting the caller.
NGINX="$(readlink -f -- "$NGINX")"
MODDIR="$(readlink -f -- "$MODDIR")"

if [ ! -x "$NGINX" ]; then
    echo "❌ $NGINX is not an executable nginx binary"
    exit 1
fi

FILTER_MOD="$MODDIR/ngx_http_zstd_filter_module.so"
if [ ! -f "$FILTER_MOD" ]; then
    echo "❌ $FILTER_MOD not found"
    exit 1
fi

# Non-vacuity gate for the whole matrix. A "rejected cleanly" fixture
# only means something if the module loads at all in the baseline; a
# dlopen failure would satisfy every negative fixture for free. Prove
# the plain config loads BEFORE asserting anything about dictionaries.
PRELUDE_WORK="$(mktemp -d)"
mkdir -p "$PRELUDE_WORK/conf" "$PRELUDE_WORK/logs"
cat >"$PRELUDE_WORK/conf/nginx.conf" <<EOF
daemon off;
master_process off;
load_module $FILTER_MOD;
error_log $PRELUDE_WORK/logs/error.log info;
pid $PRELUDE_WORK/logs/nginx.pid;
events { worker_connections 16; }
http { access_log off; }
EOF
if ! timeout 10 "$NGINX" -t -p "$PRELUDE_WORK" \
    -c "$PRELUDE_WORK/conf/nginx.conf" >"$PRELUDE_WORK/out" 2>&1; then
    echo "❌ baseline config with $FILTER_MOD does not even load --"
    echo "   every rejection fixture below would pass vacuously. Aborting."
    cat "$PRELUDE_WORK/out"
    rm -rf "$PRELUDE_WORK"
    exit 1
fi
rm -rf "$PRELUDE_WORK"
echo "✓ baseline: module loads, rejection fixtures are non-vacuous"

# NOT under /tmp directly: /tmp is mode 1777 (world-writable), and the
# strict-path ancestor-directory vetting this file exercises now refuses
# EVERY component of a dictionary path, including /tmp itself, when it
# is group/world-writable -- correctly so, since a world-writable /tmp
# is exactly the attack surface (an unprivileged user renaming a file
# into a sibling of $WORK) that check exists to close. A dictionary
# fixture placed directly under /tmp would therefore fail every
# "strict on, must still load" case for a reason that has nothing to do
# with what that case is testing. $HOME is used as the mktemp base
# instead so the whole ancestor chain (/, /home, $HOME, $WORK) is
# root- or self-owned and non-group/world-writable, matching a real
# deployment's dictionary directory tree.
#
# $HOME is an environment variable, not a trust boundary -- a root-run
# job can inherit a non-root $HOME, and any job can have a
# group-writable one, either of which would make strict mode correctly
# reject every positive fixture through THIS ancestor, for a reason
# unrelated to what each fixture tests. Validate $HOME itself against
# the same rule the module now enforces before trusting it as the
# mktemp base, and fail loudly with a clear precondition error rather
# than let every downstream fixture misreport. Resolve the candidate first so
# a symlink in HOME itself does not become part of the fixture path, then vet
# every component the module will walk.
if [ -z "${HOME:-}" ] || [ ! -d "$HOME" ]; then
    echo "❌ \$HOME is unset or not a directory; cannot pick a safe base" \
        "for the strict-mode fixtures below" >&2
    exit 1
fi

STRICT_BASE="$(readlink -f -- "$HOME")"

validate_strict_ancestor() {
    local candidate="$1" owner mode

    owner="$(stat -c '%u' "$candidate")"
    mode="$(stat -c '%a' "$candidate")"
    if [ "$owner" != "$(id -u)" ] && [ "$owner" != "0" ]; then
        echo "❌ strict fixture ancestor $candidate is owned by uid $owner," \
            "neither this job's uid $(id -u) nor root" >&2
        exit 1
    fi
    if [ $((0$mode & 0022)) -ne 0 ]; then
        echo "❌ strict fixture ancestor $candidate is mode $mode, writable" \
            "by group or other" >&2
        exit 1
    fi
}

current=/
validate_strict_ancestor "$current"
IFS='/' read -r -a strict_parts <<<"${STRICT_BASE#/}"
for part in "${strict_parts[@]}"; do
    [ -n "$part" ] || continue
    current="${current%/}/$part"
    validate_strict_ancestor "$current"
done

if [ ! -w "$STRICT_BASE" ] || [ ! -x "$STRICT_BASE" ]; then
    echo "❌ strict fixture base $STRICT_BASE is not writable and searchable" \
        "by uid $(id -u); mktemp cannot create the fixture directory there" >&2
    exit 1
fi

WORK="$(mktemp -d --tmpdir="$STRICT_BASE" zstd-dict-hardening.XXXXXX)"
cleanup() {
    if [ -n "${NGINX_PID:-}" ]; then
        kill -9 "$NGINX_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$WORK/conf" "$WORK/logs" "$WORK/html"

# mkdir honours umask, which on a typical dev/CI account (002) leaves
# these group-writable (0775) -- exactly the bit the strict-path
# ancestor vetting now refuses on every walked directory. Pin them
# explicitly rather than relying on umask, same reasoning as the
# chmod 0644 a few lines below for the leaf fixture file.
chmod 0755 "$WORK" "$WORK/conf" "$WORK/logs" "$WORK/html"

fail=0

# ── nginx -t against one http_config snippet, bounded ────────────────
# Echoes "OK"/"FAIL: <reason>" on stdout. The `timeout` is the control
# for fixture class 1: a regression (no O_NONBLOCK) blocks in open() on
# a FIFO, so this would hang without it rather than merely fail.
conf_test() {
    local snippet="$1"
    cat >"$WORK/conf/nginx.conf" <<EOF
daemon off;
master_process off;
load_module $FILTER_MOD;
error_log $WORK/logs/error.log info;
pid $WORK/logs/nginx.pid;
events { worker_connections 16; }
http {
    access_log off;
$snippet
    server {
        listen 127.0.0.1:18199;
        location / {
            zstd on;
            zstd_min_length 1;
            zstd_types text/plain;
            default_type text/plain;
            return 200 "ok\n";
        }
    }
}
EOF
    if timeout 10 "$NGINX" -t -p "$WORK" -c "$WORK/conf/nginx.conf" \
        >"$WORK/logs/t.out" 2>&1; then
        echo "OK"
    else
        if [ "$?" -eq 124 ]; then
            echo "FAIL: nginx -t TIMED OUT (hung open — the FIFO-block regression)"
        else
            echo "FAIL: $(tail -3 "$WORK/logs/t.out" | tr '\n' ' ')"
        fi
    fi
}

check() {
    local name="$1" want="$2" got="$3"
    if [ "$want" = "regular" ] && [ "$got" = "OK" ]; then
        echo "✓ $name: OK (expected)"
    elif [ "$want" = "reject" ] && [[ "$got" == FAIL:* ]] && [[ "$got" != *TIMED\ OUT* ]]; then
        echo "✓ $name: rejected cleanly ($got)"
    else
        echo "✗ $name: want=$want got=$got"
        fail=1
    fi
}

# ── Fixture: regular file, must still load ───────────────────────────
# chmod explicit: umask can leave this group-writable (e.g. 0002 ->
# 0664), which would spuriously trip the strict-mode fixtures below
# that are meant to start from a clean, non-writable baseline.
head -c 8192 /dev/urandom | base64 >"$WORK/html/regular.dict"
chmod 0644 "$WORK/html/regular.dict"
r=$(conf_test "    zstd_dict_file_unsafe on;
    zstd_dict_file $WORK/html/regular.dict;")
check "regular file (zstd_dict_file)" regular "$r"

r=$(conf_test "    zstd_dcz_dict_file $WORK/html/regular.dict;")
check "regular file (zstd_dcz_dict_file)" regular "$r"

# ── Fixture: FIFO ─────────────────────────────────────────────────────
mkfifo "$WORK/html/fifo.dict"
r=$(conf_test "    zstd_dict_file_unsafe on;
    zstd_dict_file $WORK/html/fifo.dict;")
check "FIFO (zstd_dict_file)" reject "$r"

r=$(conf_test "    zstd_dcz_dict_file $WORK/html/fifo.dict;")
check "FIFO (zstd_dcz_dict_file)" reject "$r"

# ── Fixture: directory ────────────────────────────────────────────────
mkdir -p "$WORK/html/dir.dict"
r=$(conf_test "    zstd_dict_file_unsafe on;
    zstd_dict_file $WORK/html/dir.dict;")
check "directory (zstd_dict_file)" reject "$r"

r=$(conf_test "    zstd_dcz_dict_file $WORK/html/dir.dict;")
check "directory (zstd_dcz_dict_file)" reject "$r"

# ── Fixture: UNIX domain socket ────────────────────────────────────────
if command -v python3 >/dev/null 2>&1; then
    python3 - "$WORK/html/sock.dict" <<'PYEOF'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sys.argv[1])
PYEOF
    r=$(conf_test "    zstd_dict_file_unsafe on;
    zstd_dict_file $WORK/html/sock.dict;")
    check "socket (zstd_dict_file)" reject "$r"

    r=$(conf_test "    zstd_dcz_dict_file $WORK/html/sock.dict;")
    check "socket (zstd_dcz_dict_file)" reject "$r"
else
    echo "::warning::python3 not found; socket fixture skipped"
fi

# ── Fixture: character device (always present, harmless to open RDONLY) ─
r=$(conf_test "    zstd_dict_file_unsafe on;
    zstd_dict_file /dev/null;")
check "device /dev/null (zstd_dict_file)" reject "$r"

r=$(conf_test "    zstd_dcz_dict_file /dev/null;")
check "device /dev/null (zstd_dcz_dict_file)" reject "$r"

# ── Fixture: symlink, non-strict (default) accepts ────────────────────
ln -s "$WORK/html/regular.dict" "$WORK/html/link.dict"
r=$(conf_test "    zstd_dict_file_unsafe on;
    zstd_dict_file $WORK/html/link.dict;")
check "symlink, strict off / default (zstd_dict_file)" regular "$r"

r=$(conf_test "    zstd_dcz_dict_file $WORK/html/link.dict;")
check "symlink, strict off / default (zstd_dcz_dict_file)" regular "$r"

# ── Fixture: symlink, strict on rejects (the release-symlink escape
#    hatch is validated by the line above: default OFF still follows it) ─
r=$(conf_test "    zstd_dict_strict_path on;
    zstd_dict_file_unsafe on;
    zstd_dict_file $WORK/html/link.dict;")
check "symlink, strict on (zstd_dict_file)" reject "$r"

r=$(conf_test "    zstd_dict_strict_path on;
    zstd_dcz_dict_file $WORK/html/link.dict;")
check "symlink, strict on (zstd_dcz_dict_file)" reject "$r"

# ── M3: INTERMEDIATE symlink component, strict on rejects ────────────
#
# The regression this pins: O_NOFOLLOW on the whole path guards only the
# LEAF. Build /…/rel-1/inter.dict and point a sibling symlink "current"
# at rel-1, then load /…/current/inter.dict -- every component but the
# last is a perfectly ordinary directory to the kernel, so a leaf-only
# O_NOFOLLOW open follows "current" silently and strict mode loads
# whatever the symlink's owner aimed it at. This is the release-symlink
# swap the README warning claims strict mode defends against.
#
# NON-VACUITY: the SAME dictionary reached through its REAL path must
# still load under strict on (the fixture directly below). Without that
# pair, "rejected" here could just mean the file or the directory layout
# is broken, and the assertion would pass for the wrong reason.
mkdir -p "$WORK/html/rel-1"
cp "$WORK/html/regular.dict" "$WORK/html/rel-1/inter.dict"
chmod 0755 "$WORK/html/rel-1"
chmod 0644 "$WORK/html/rel-1/inter.dict"
ln -s "$WORK/html/rel-1" "$WORK/html/current"

r=$(conf_test "    zstd_dict_strict_path on;
    zstd_dict_file_unsafe on;
    zstd_dict_file $WORK/html/current/inter.dict;")
check "intermediate symlink component, strict on (zstd_dict_file)" reject "$r"

r=$(conf_test "    zstd_dict_strict_path on;
    zstd_dcz_dict_file $WORK/html/current/inter.dict;")
check "intermediate symlink component, strict on (zstd_dcz_dict_file)" reject "$r"

# Positive control for the pair above: the identical bytes via the real
# directory path load fine under strict on.
r=$(conf_test "    zstd_dict_strict_path on;
    zstd_dict_file_unsafe on;
    zstd_dict_file $WORK/html/rel-1/inter.dict;")
check "real (non-symlink) path, strict on still loads (zstd_dict_file)" regular "$r"

r=$(conf_test "    zstd_dict_strict_path on;
    zstd_dcz_dict_file $WORK/html/rel-1/inter.dict;")
check "real (non-symlink) path, strict on still loads (zstd_dcz_dict_file)" regular "$r"

# The intermediate-symlink path must STILL LOAD with strict off, so the
# fix cannot be mistaken for a blanket path restriction and the
# documented release-symlink deployment keeps working unconfigured.
r=$(conf_test "    zstd_dict_file_unsafe on;
    zstd_dict_file $WORK/html/current/inter.dict;")
check "intermediate symlink component, strict off / default" regular "$r"

# ── M4: OWNER-writable / foreign-owned dictionary, strict on rejects ──
#
# The regression this pins: strict mode used to test only S_IWGRP |
# S_IWOTH, so a dictionary owned by an unprivileged account with an
# entirely ordinary mode 0644 passed while a root master read it -- and
# that owner can rewrite the file, steering what the next privileged
# reload snapshots. Strict mode now additionally requires the file to be
# owned by the loading principal (geteuid()) or by root.
#
# COVERAGE HONESTY -- READ BEFORE TRUSTING THIS FIXTURE.
#
# Which half runs depends on whether this script has the privilege to
# create a file it does not own:
#
#   * as root  -- chown to an unprivileged uid gives a genuine
#                 foreign-owned dictionary and the real M4 case runs.
#   * non-root -- an unprivileged CI user CANNOT chown a file away from
#                 itself, so the foreign-owner half is NOT COVERED here
#                 and is reported as such. What IS asserted instead is
#                 the complementary, fully observable half: the check is
#                 reached and the positive path (a file owned by
#                 geteuid(), mode 0644) still loads. This is deliberately
#                 NOT dressed up as a pass for the uncovered half.
if [ "$(id -u)" -eq 0 ]; then
    foreign_uid=""
    for cand in nobody daemon bin; do
        if id -u "$cand" >/dev/null 2>&1; then
            foreign_uid="$(id -u "$cand")"
            break
        fi
    done

    if [ -n "$foreign_uid" ]; then
        cp "$WORK/html/regular.dict" "$WORK/html/foreign.dict"
        chmod 0644 "$WORK/html/foreign.dict"
        chown "$foreign_uid" "$WORK/html/foreign.dict"

        r=$(conf_test "    zstd_dict_strict_path on;
    zstd_dict_file_unsafe on;
    zstd_dict_file $WORK/html/foreign.dict;")
        check "foreign-owned 0644 dictionary, strict on (zstd_dict_file)" reject "$r"

        r=$(conf_test "    zstd_dict_strict_path on;
    zstd_dcz_dict_file $WORK/html/foreign.dict;")
        check "foreign-owned 0644 dictionary, strict on (zstd_dcz_dict_file)" reject "$r"

        # Complement: the same foreign-owned file must still load with
        # strict OFF, so the ownership rule is confined to strict mode
        # and does not change the default deployment's behaviour.
        r=$(conf_test "    zstd_dict_file_unsafe on;
    zstd_dict_file $WORK/html/foreign.dict;")
        check "foreign-owned 0644 dictionary, strict off / default" regular "$r"
    else
        echo "::warning::no unprivileged account (nobody/daemon/bin) found;"
        echo "  M4 foreign-owner half NOT COVERED in this run"
    fi
else
    echo "• M4 foreign-owner half NOT COVERED: running as uid $(id -u), which"
    echo "  cannot chown a file away from itself. The observable complement"
    echo "  (self-owned 0644 still loads under strict on) is asserted below."
fi

# Observable in every environment, privileged or not: a dictionary owned
# by the loading principal with a sane mode is accepted under strict on.
# This is what keeps the M4 ownership rule from being a blanket refusal,
# and it is the half the unprivileged CI user genuinely covers.
cp "$WORK/html/regular.dict" "$WORK/html/selfowned.dict"
chmod 0644 "$WORK/html/selfowned.dict"
r=$(conf_test "    zstd_dict_strict_path on;
    zstd_dict_file_unsafe on;
    zstd_dict_file $WORK/html/selfowned.dict;")
check "self-owned 0644 dictionary, strict on loads (zstd_dict_file)" regular "$r"

r=$(conf_test "    zstd_dict_strict_path on;
    zstd_dcz_dict_file $WORK/html/selfowned.dict;")
check "self-owned 0644 dictionary, strict on loads (zstd_dcz_dict_file)" regular "$r"

# ── Fixture: world-writable regular file, strict on rejects ───────────
cp "$WORK/html/regular.dict" "$WORK/html/writable.dict"
chmod 0666 "$WORK/html/writable.dict"
r=$(conf_test "    zstd_dict_strict_path on;
    zstd_dict_file_unsafe on;
    zstd_dict_file $WORK/html/writable.dict;")
check "world-writable, strict on (zstd_dict_file)" reject "$r"

r=$(conf_test "    zstd_dict_strict_path on;
    zstd_dcz_dict_file $WORK/html/writable.dict;")
check "world-writable, strict on (zstd_dcz_dict_file)" reject "$r"

# ── A33-F2: ancestor-DIRECTORY ownership/mode, not just the leaf ──────
#
# The regression this pins: M3 (intermediate-symlink fixture above) made
# the strict-mode walk resolve every path component with
# openat(O_NOFOLLOW|O_DIRECTORY), and M4 (self-owned/world-writable
# fixtures above) added leaf ownership+mode checks. Neither ever
# fstat()-checked the intermediate DIRECTORY fds the walk opens along
# the way. A local user who owns, or can write into, an ancestor
# directory can rename() a root-owned 0644 file into the leaf position
# and pass both leaf checks while still having fully steered which
# bytes strict mode loads -- the directive's promise ("a
# less-privileged local writer cannot steer the bytes") only holds when
# EVERY component is vetted, not just the last one.
#
# Two arms below, one per unsafe-ancestor cause (mode, then ownership),
# each proved against a PARENT directory of the dictionary file, never
# the leaf itself -- the existing M4 fixtures already cover the leaf.

# ── Arm 1: world-writable PARENT directory ─────────────────────────────
mkdir -p "$WORK/html/unsafe-parent-mode"
cp "$WORK/html/regular.dict" "$WORK/html/unsafe-parent-mode/leaf.dict"
chmod 0644 "$WORK/html/unsafe-parent-mode/leaf.dict"
chmod 0777 "$WORK/html/unsafe-parent-mode"
r=$(conf_test "    zstd_dict_strict_path on;
    zstd_dict_file_unsafe on;
    zstd_dict_file $WORK/html/unsafe-parent-mode/leaf.dict;")
check "world-writable PARENT directory, strict on (zstd_dict_file)" reject "$r"

r=$(conf_test "    zstd_dict_strict_path on;
    zstd_dcz_dict_file $WORK/html/unsafe-parent-mode/leaf.dict;")
check "world-writable PARENT directory, strict on (zstd_dcz_dict_file)" reject "$r"

# Complement: the identical layout must still load with strict off, so
# the ancestor rule is confined to strict mode.
r=$(conf_test "    zstd_dict_file_unsafe on;
    zstd_dict_file $WORK/html/unsafe-parent-mode/leaf.dict;")
check "world-writable PARENT directory, strict off / default" regular "$r"

# NO STICKY-BIT EXEMPTION: a sticky world-writable ancestor (the
# /tmp-style layout) still lets an unprivileged user CREATE the next
# path component -- it only stops them deleting/renaming someone
# else's existing entry, which is not the attack here (the attacker
# creates a new file, they don't need to touch an existing one). This
# must reject exactly like the plain 0777 case above, not be
# special-cased into passing.
mkdir -p "$WORK/html/unsafe-parent-sticky"
cp "$WORK/html/regular.dict" "$WORK/html/unsafe-parent-sticky/leaf.dict"
chmod 0644 "$WORK/html/unsafe-parent-sticky/leaf.dict"
chmod 1777 "$WORK/html/unsafe-parent-sticky"
r=$(conf_test "    zstd_dict_strict_path on;
    zstd_dict_file_unsafe on;
    zstd_dict_file $WORK/html/unsafe-parent-sticky/leaf.dict;")
check "sticky world-writable PARENT directory, strict on (zstd_dict_file)" reject "$r"

r=$(conf_test "    zstd_dict_strict_path on;
    zstd_dcz_dict_file $WORK/html/unsafe-parent-sticky/leaf.dict;")
check "sticky world-writable PARENT directory, strict on (zstd_dcz_dict_file)" reject "$r"

# ── Arm 2: PARENT directory owned by a foreign, non-root uid ──────────
# Same coverage-honesty split as the M4 leaf-ownership fixture above:
# only root can chown a directory away from itself, so the genuine
# foreign-owner case runs under root and the observable complement
# (self-owned parent still loads) runs everywhere else.
if [ "$(id -u)" -eq 0 ]; then
    foreign_uid=""
    for cand in nobody daemon bin; do
        if id -u "$cand" >/dev/null 2>&1; then
            foreign_uid="$(id -u "$cand")"
            break
        fi
    done

    if [ -n "$foreign_uid" ]; then
        mkdir -p "$WORK/html/unsafe-parent-owner"
        cp "$WORK/html/regular.dict" "$WORK/html/unsafe-parent-owner/leaf.dict"
        chmod 0644 "$WORK/html/unsafe-parent-owner/leaf.dict"
        chmod 0755 "$WORK/html/unsafe-parent-owner"
        chown "$foreign_uid" "$WORK/html/unsafe-parent-owner"

        r=$(conf_test "    zstd_dict_strict_path on;
    zstd_dict_file_unsafe on;
    zstd_dict_file $WORK/html/unsafe-parent-owner/leaf.dict;")
        check "foreign-owned PARENT directory, strict on (zstd_dict_file)" reject "$r"

        r=$(conf_test "    zstd_dict_strict_path on;
    zstd_dcz_dict_file $WORK/html/unsafe-parent-owner/leaf.dict;")
        check "foreign-owned PARENT directory, strict on (zstd_dcz_dict_file)" reject "$r"

        r=$(conf_test "    zstd_dict_file_unsafe on;
    zstd_dict_file $WORK/html/unsafe-parent-owner/leaf.dict;")
        check "foreign-owned PARENT directory, strict off / default" regular "$r"
    else
        echo "::warning::no unprivileged account (nobody/daemon/bin) found;"
        echo "  A33-F2 foreign-owner-ancestor half NOT COVERED in this run"
    fi
else
    echo "• A33-F2 foreign-owner-ancestor half NOT COVERED: running as uid"
    echo "  $(id -u), which cannot chown a directory away from itself. The"
    echo "  observable complement (self-owned parent, sane mode, strict on"
    echo "  still loads) is asserted by every 'strict on ... loads'"
    echo "  fixture above, whose dictionaries all sit under \$WORK/html,"
    echo "  itself self-owned mode 0755 (pinned above)."
fi

# ── Regression: zstd_dict_strict_path AFTER the dcz directive must not
#    silently skip the check for a dictionary already loaded by that
#    point. ngx_conf_parse() runs top-to-bottom, so a bare
#    "zstd_dict_strict_path on" placed after zstd_dcz_dict_file used to
#    read the flag as still-unset at load time and treat it as off --
#    the dictionary loaded successfully with no error, which is the
#    same as strict mode being silently ignored. init_main_conf() now
#    rejects this ordering outright (a config-load error naming the
#    file), which is what "reject" below actually verifies -- this is
#    NOT the same case as the strict-on-BEFORE fixtures above, and
#    without this case the ordering hazard has zero coverage.
r=$(conf_test "    zstd_dcz_dict_file $WORK/html/writable.dict;
    zstd_dict_strict_path on;")
check "world-writable, strict on declared AFTER dcz directive (ordering)" reject "$r"

r=$(conf_test "    zstd_dcz_dict_file $WORK/html/link.dict;
    zstd_dict_strict_path on;")
check "symlink, strict on declared AFTER dcz directive (ordering)" reject "$r"

# ── Fixture: same world-writable file, strict off (default) accepts ───
r=$(conf_test "    zstd_dict_file_unsafe on;
    zstd_dict_file $WORK/html/writable.dict;")
check "world-writable, strict off / default (zstd_dict_file)" regular "$r"

# ── Behavior: rejected reload leaves the OLD cycle serving ────────────
# Start nginx on a known-good regular dictionary with strict on, then
# SIGHUP after swapping the path in for a symlink. The reload must be
# refused (error.log line) and the OLD worker must keep answering --
# proving a rejected reload does not tear down the running cycle.
cp "$WORK/html/regular.dict" "$WORK/html/live.dict"
chmod 0644 "$WORK/html/live.dict"
cat >"$WORK/conf/nginx.conf" <<EOF
daemon off;
master_process on;
worker_processes 1;
load_module $FILTER_MOD;
error_log $WORK/logs/error.log info;
pid $WORK/logs/nginx.pid;
events { worker_connections 16; }
http {
    access_log off;
    zstd_dict_strict_path on;
    zstd_dict_file_unsafe on;
    zstd_dict_file $WORK/html/live.dict;
    server {
        listen 127.0.0.1:18198;
        location / {
            zstd on;
            zstd_min_length 1;
            zstd_types text/plain;
            default_type text/plain;
            return 200 "dictionary compressed body long enough to compress\n";
        }
    }
}
EOF

"$NGINX" -p "$WORK" -c "$WORK/conf/nginx.conf" &
NGINX_PID=$!

ready=0
for _ in $(seq 1 100); do
    if curl -fsS -o /dev/null "http://127.0.0.1:18198/" 2>/dev/null; then
        ready=1
        break
    fi
    sleep 0.1
done

if [ "$ready" -ne 1 ]; then
    echo "✗ old-cycle-active fixture: nginx did not start"
    fail=1
else
    # Swap the trusted path for a symlink out from under the running
    # config -- exactly the local-writer scenario the row defends
    # against -- then ask for a reload.
    rm "$WORK/html/live.dict"
    ln -s "$WORK/html/regular.dict" "$WORK/html/live.dict"
    kill -HUP "$NGINX_PID"
    sleep 1

    # O_NOFOLLOW makes the open() itself fail (ELOOP, "Too many levels
    # of symbolic links") before ngx_is_link()'s own message can fire;
    # accept either wording as proof the symlink swap was refused.
    if curl -fsS -o /dev/null "http://127.0.0.1:18198/" 2>/dev/null \
        && grep -qE "is a symlink; refused|levels of symbolic links" \
            "$WORK/logs/error.log"; then
        echo "✓ old-cycle-active fixture: reload refused, old cycle still serving"
    else
        echo "✗ old-cycle-active fixture: refusal not logged or old cycle stopped answering"
        tail -10 "$WORK/logs/error.log" || true
        fail=1
    fi

    kill -QUIT "$NGINX_PID" 2>/dev/null || true
    wait "$NGINX_PID" 2>/dev/null || true
    NGINX_PID=""
fi

# ── Read completeness: both loaders must read a dictionary to the end ──
#
# Both loaders used to issue ONE ngx_read_fd() and treat any short count
# as a fatal "incomplete read". read() on a regular file may legally
# return fewer bytes than asked for, and an EINTR-interrupted read
# returns early on any filesystem regardless of O_NONBLOCK -- so a valid
# dictionary could fail config load for no reason. They now loop via
# ngx_http_zstd_read_dict_file().
#
# NOTE ON WHAT THESE FIXTURES DO AND DO NOT PROVE. The read loop itself
# is NOT covered here and cannot be: read() on a local tmpfs/ext4 regular
# file does not return a short count, and a signal cannot be steered into
# the master's read window from a shell. Measured -- with the loop
# reverted to a single read whose short count is fatal, every fixture in
# this file still passed, the 1 MiB dictionary included. The loop's three
# exits (resume-on-short, retry-on-EINTR, fail-on-EOF) are covered by
# ci/tools/test_read_dict_file_unit.sh, which extracts the helper and
# scripts ngx_read_fd; all three mutants are killed there.
#
# What these fixtures DO pin is the config-level contract around it: a
# large dictionary loads, and the two rejections stay rejections.

# A dictionary comfortably larger than one page. This is an end-to-end
# smoke check that a big dictionary loads through the real loader on the
# real filesystem -- it is NOT the short-read regression test (see the
# note above; that lives in test_read_dict_file_unit.sh).
head -c 1048576 /dev/urandom >"$WORK/html/large.dict"
chmod 0644 "$WORK/html/large.dict"
r=$(conf_test "    zstd_dict_file_unsafe on;
    zstd_dict_file $WORK/html/large.dict;")
check "1 MiB dictionary loads (zstd_dict_file)" regular "$r"

r=$(conf_test "    zstd_dcz_dict_file $WORK/html/large.dict;")
check "1 MiB dictionary loads (zstd_dcz_dict_file)" regular "$r"

# Zero-length dictionary: rejected, and rejected the SAME way by both
# loaders. ZSTD_createCDict(buf, 0, level) returns a valid do-nothing
# CDict and a 0-byte read "succeeds", so without an explicit check the
# operator silently gets no dictionary at all.
: >"$WORK/html/empty.dict"
chmod 0644 "$WORK/html/empty.dict"
r=$(conf_test "    zstd_dict_file_unsafe on;
    zstd_dict_file $WORK/html/empty.dict;")
check "zero-length dictionary (zstd_dict_file)" reject "$r"

r=$(conf_test "    zstd_dcz_dict_file $WORK/html/empty.dict;")
check "zero-length dictionary (zstd_dcz_dict_file)" reject "$r"

# Unreadable regular file: config load must fail rather than proceed
# with an unpopulated buffer. This is refused at open() -- it never
# reaches the read loop -- but it pins that a permission failure is
# fatal at config time and not deferred to first use. Skipped under
# root, which bypasses mode 0000 and would make the fixture vacuous.
if [ "$(id -u)" -ne 0 ]; then
    head -c 8192 /dev/urandom >"$WORK/html/noperm.dict"
    chmod 0000 "$WORK/html/noperm.dict"
    r=$(conf_test "    zstd_dict_file_unsafe on;
    zstd_dict_file $WORK/html/noperm.dict;")
    check "unreadable dictionary (zstd_dict_file)" reject "$r"

    r=$(conf_test "    zstd_dcz_dict_file $WORK/html/noperm.dict;")
    check "unreadable dictionary (zstd_dcz_dict_file)" reject "$r"
else
    echo "• unreadable dictionary: skipped (running as root bypasses mode 0000)"
fi

if [ "$fail" -ne 0 ]; then
    echo "❌ dictionary path hardening: one or more fixtures failed"
    exit 1
fi

echo "✓ all dictionary path hardening fixtures passed"
