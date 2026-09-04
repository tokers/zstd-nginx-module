#!/bin/bash
# Download an nginx release tarball and verify its detached PGP signature
# against the signer keys VENDORED in ci/tools/keys/ (never fetched from
# nginx.org at CI time -- see ci-build.sh's file header for why bootstrapping
# the keys from the same origin that serves the tarball+signature would let
# an origin compromise substitute all three, audit sha e289021 F3).
#
# This is the same verification ci-build.sh performs before a full test-suite
# build, factored out for the CI jobs that only need a source tree to
# configure headers from (scan-build, clang-tidy) or to build a debug binary
# for a Valgrind soak (memcheck, helgrind) -- neither wants ci-build.sh's
# .build/ cache tree, coverage mode or dynamic-module test-suite flags.
#
#   ci/tools/fetch-verified-nginx.sh <version>
#
# On success, leaves "nginx-<version>.tar.gz" (verified) in the CURRENT
# directory and extracts it there. A verification failure removes the
# tarball and exits 1 -- callers must not catch and continue past this.
set -euo pipefail

VERSION="${1:?usage: fetch-verified-nginx.sh <version>}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DIR="nginx-${VERSION}"
TARBALL="${DIR}.tar.gz"
URL="https://nginx.org/download/${TARBALL}"

if [ ! -f "$TARBALL" ]; then
	wget -q -O "$TARBALL" "$URL"
fi
if ! "$SCRIPT_DIR/verify-nginx-tarball.sh" "$TARBALL" "${URL}.asc"; then
	echo "PGP signature verification failed for ${TARBALL}" >&2
	rm -f "$TARBALL" "${TARBALL}.asc"
	exit 1
fi

tar -xzf "$TARBALL"
