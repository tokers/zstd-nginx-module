#!/usr/bin/env bash
# Verify an existing nginx source tarball against nginx.org's detached PGP
# signature and the vendored signer keys in ci/tools/keys.
#
# Usage: verify-nginx-tarball.sh <tarball> [signature-url]
# Inputs: an existing tarball and, optionally, its detached-signature URL.
# Output: a verified <tarball>.asc file beside the tarball.
# Side effects: downloads only the signature and uses a temporary GNUPGHOME.
# Dry-run: none; the offline test script replaces wget and gpg with fakes.
# Limits: wget uses three attempts and a 20-second network timeout.
# Extend here when nginx changes its signature transport or trusted key set.
set -euo pipefail

usage() {
	cat <<'EOF'
Usage: verify-nginx-tarball.sh <tarball> [signature-url]

Verify an existing nginx source tarball with the vendored nginx signing keys.
The default signature URL is https://nginx.org/download/<tarball>.asc.
EOF
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
	usage
	exit 0
fi
if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
	usage >&2
	exit 2
fi

tarball="$1"
if [ ! -f "$tarball" ]; then
	echo "missing nginx tarball: $tarball" >&2
	exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
keyring_dir="$script_dir/keys"
signature="${tarball}.asc"
signature_url="${2:-https://nginx.org/download/$(basename "$signature")}"

keys=("$keyring_dir"/*.key)
if [ ! -e "${keys[0]}" ]; then
	echo "no vendored nginx signing keys found in $keyring_dir" >&2
	exit 1
fi

gnupghome="$(mktemp -d)"
cleanup() {
	rm -rf "$gnupghome"
}
trap cleanup EXIT
export GNUPGHOME="$gnupghome"
chmod 700 "$gnupghome"

wget --quiet --timeout=20 --tries=3 --output-document="$signature" \
	-- "$signature_url"
for keyfile in "${keys[@]}"; do
	gpg --batch --quiet --import "$keyfile" 2>/dev/null
done
gpg --batch --quiet --verify "$signature" "$tarball"
echo "PGP signature verified for $tarball"
