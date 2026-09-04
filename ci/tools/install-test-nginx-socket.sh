#!/usr/bin/env bash
set -euo pipefail

prefix="${1:-$HOME/perl5}"
version="${TEST_NGINX_SOCKET_VERSION:?TEST_NGINX_SOCKET_VERSION is required}"
dist="${TEST_NGINX_SOCKET_DIST:-AGENT/Test-Nginx-${version}.tar.gz}"
mirror="${CPAN_MIRROR:-https://cpan.metacpan.org}"
lock="${TEST_NGINX_SOCKET_LOCK:-ci/tools/test-nginx-socket.cpan.lock}"
expected="Test::Nginx::Socket@${version}"
author="${dist%%/*}"
author_path="${author:0:1}/${author:0:2}/${dist}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cpanm --info "$expected" 2>/dev/null | awk '/^[A-Z0-9]+\/.*\.tar\.gz$/ {print; exit}' >"$tmp/dist"
if ! grep -qx "$dist" "$tmp/dist"; then
	echo "::error::${expected} resolved to $(cat "$tmp/dist"), expected ${dist}" >&2
	exit 1
fi

cpanm --showdeps "$expected" 2>/dev/null |
	awk '/^[A-Za-z0-9_:]+(~[^[:space:]]+)?$/ {print}' |
	sort >"$tmp/deps"
grep -Ev '^\s*(#|$)' "$lock" | sort >"$tmp/lock"
if ! diff -u "$tmp/lock" "$tmp/deps"; then
	echo "::error::${expected} CPAN dependency graph differs from ${lock}" >&2
	exit 1
fi

cpanm -l "$prefix" --notest "${mirror}/authors/id/${author_path}"
echo "PERL5LIB=${prefix}/lib/perl5:${PERL5LIB:-}" >>"${GITHUB_ENV:-/dev/null}"

installed="$(perl -I "${prefix}/lib/perl5" -MTest::Nginx::Socket -e 'print $Test::Nginx::Socket::VERSION')"
echo "Test::Nginx::Socket installed version: $installed"
if [ "$installed" != "$version" ]; then
	echo "::error::Test::Nginx::Socket version mismatch: pinned $version, got $installed" >&2
	exit 1
fi
