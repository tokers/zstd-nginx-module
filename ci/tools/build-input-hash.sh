#!/usr/bin/env bash
# Print a stable digest of every path in ci/build-inputs.manifest.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_MODULE_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
MODULE_DIR="${1:-$DEFAULT_MODULE_DIR}"
MANIFEST="$MODULE_DIR/ci/build-inputs.manifest"

if [ ! -f "$MANIFEST" ]; then
    echo "ERROR: build-input manifest not found: $MANIFEST" >&2
    exit 1
fi

hash_file() {
    local relative="$1"
    local digest

    digest="$(sha256sum "$MODULE_DIR/$relative" | cut -d' ' -f1)"
    printf '%s  %s\n' "$digest" "$relative"
}

while IFS= read -r input || [ -n "$input" ]; do
    case "$input" in
        '' | \#*) continue ;;
    esac

    if [ -f "$MODULE_DIR/$input" ]; then
        hash_file "$input"
    elif [ -d "$MODULE_DIR/$input" ]; then
        while IFS= read -r -d '' file; do
            hash_file "${file#"$MODULE_DIR/"}"
        done < <(find "$MODULE_DIR/$input" -type f -print0 | sort -z)
    else
        echo "ERROR: build input does not exist: $input" >&2
        exit 1
    fi
done < "$MANIFEST" | sha256sum | cut -d' ' -f1
