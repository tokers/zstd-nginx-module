#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# ci/tools/max-port.sh -- prove a job's test port band is safe to bind before
# anything tries to bind it.
#
#   ci/tools/max-port.sh [base] [width]
#     base  : first port of the band (default $TEST_BASE_PORT, else 18880)
#     width : ports in the band      (default $TEST_PORT_WIDTH, else 64)
#
# Prints the highest port in the band on stdout. Exits non-zero, with the
# reason, if the band is unusable.
#
# WHY THIS EXISTS. Two ways a test port band goes wrong, both of which present
# as an unreproducible flake rather than as a configuration error:
#
#   1. THE BAND REACHES THE EPHEMERAL RANGE. Above
#      /proc/sys/net/ipv4/ip_local_port_range's floor (32768 by default) the
#      kernel hands out ports for OUTBOUND connections. A test that binds there
#      races every other process on the box: the kernel wins at random, the
#      listener fails with "Address already in use", and the run dies before a
#      single assertion executes. The victim is arbitrary and a rerun "fixes"
#      it, which is exactly how this masquerades as a fixture flake -- it cost a
#      sibling repo weeks.
#   2. THE BAND IS ALREADY OCCUPIED. On a persistent self-hosted runner a
#      previous run's server can outlive its job. Binding on top of it does not
#      fail loudly; the old process keeps answering and the new suite tests the
#      OLD BINARY. That is worse than a crash -- see
#      [[feedback-stale-redis-squats-test-port-fakes-outage]] for the same shape
#      in another repo.
#
# Both checks are cheap and run before the fixture starts, so the failure names
# the cause instead of leaving a timeout to be interpreted.
#
# Usage in a workflow, once per runtime-bearing job:
#     - run: ci/tools/max-port.sh "$TEST_BASE_PORT"
# ci/linter/lint-ci-ports.sh fails the build if a job starts the runtime suite
# without declaring TEST_BASE_PORT at all.
#
# Extend: a new fixture that binds outside the band is the thing to fix, not
# this script -- the band is the contract.

set -euo pipefail

BASE="${1:-${TEST_BASE_PORT:-18880}}"
WIDTH="${2:-${TEST_PORT_WIDTH:-64}}"

case "$BASE" in
    ''|*[!0-9]*) echo "ERROR: base port must be numeric, got '$BASE'" >&2; exit 2 ;;
esac
case "$WIDTH" in
    ''|*[!0-9]*) echo "ERROR: width must be numeric, got '$WIDTH'" >&2; exit 2 ;;
esac

# Force base 10 before ANY arithmetic. `$(( ))` reads a leading zero as octal,
# so TEST_BASE_PORT=040000 evaluated to 16384 -- a band this script would have
# cleared as safely below the ephemeral floor, while the python driver parses
# --port with int() and binds 40000, inside it. The two disagreeing is worse
# than either being wrong: the check passes and the bind races the kernel.
BASE=$((10#$BASE))
WIDTH=$((10#$WIDTH))

# Port 0 is not a port: bind(0) makes the kernel pick an ephemeral one, so a
# band based at 0 would sail through this preflight while reserving nothing.
if [ "$BASE" -lt 1 ]; then
    echo "ERROR: base port must be at least 1, got $BASE" >&2
    exit 2
fi

if [ "$WIDTH" -lt 1 ]; then
    echo "ERROR: width must be at least 1, got $WIDTH" >&2
    exit 2
fi

MAX=$((BASE + WIDTH - 1))

# The floor is READ, never assumed: this box and a GitHub-hosted runner do not
# have to agree, and a hardcoded 32768 would pass here and fail there.
EPHEMERAL_FLOOR=32768
RANGE_FILE=/proc/sys/net/ipv4/ip_local_port_range
if [ -r "$RANGE_FILE" ]; then
    EPHEMERAL_FLOOR="$(awk '{print $1}' "$RANGE_FILE")"
fi

if [ "$MAX" -ge "$EPHEMERAL_FLOOR" ]; then
    echo "ERROR: port band $BASE..$MAX reaches the kernel ephemeral range" >&2
    echo "       (floor $EPHEMERAL_FLOOR from $RANGE_FILE)." >&2
    echo "       The kernel allocates outbound ports there, so a listener in" >&2
    echo "       this band races it and fails at random. Move the band down." >&2
    exit 1
fi
if [ "$MAX" -gt 65535 ]; then
    echo "ERROR: port band $BASE..$MAX runs past 65535" >&2
    exit 1
fi

# Occupancy check. ss is in iproute2, present on every target runner; if it is
# somehow absent, say so rather than silently skipping -- a check that
# disappears when its tool is missing reports green while checking nothing.
if ! command -v ss >/dev/null 2>&1; then
    echo "ERROR: ss(8) not found; cannot verify the band is free." >&2
    echo "       Install iproute2 rather than skipping this check." >&2
    exit 2
fi

# ss runs on its own first. Under `set -euo pipefail` a non-zero ss inside the
# pipeline below would fail the command substitution and kill the script with no
# message at all -- the unexplained exit this file exists to replace with a
# named cause.
if ! listeners="$(ss -Hltn 2>&1)"; then
    echo "ERROR: ss(8) failed, so the band could not be checked:" >&2
    printf '       %s\n' "$listeners" >&2
    echo "       Not treating an unverifiable band as free." >&2
    exit 2
fi

busy="$(printf '%s\n' "$listeners" \
    | awk -v lo="$BASE" -v hi="$MAX" '
        {
            # Local address is field 4, "addr:port" -- take the last colon so
            # an IPv6 address does not confuse the split.
            n = split($4, a, ":")
            p = a[n] + 0
            if (p >= lo && p <= hi) print p
        }' | sort -un | paste -sd, -)"

if [ -n "$busy" ]; then
    echo "ERROR: ports already listening inside band $BASE..$MAX: $busy" >&2
    echo "       A leftover server from a previous run would keep answering," >&2
    echo "       so this suite would test the OLD binary and pass." >&2
    exit 1
fi

echo "$MAX"
