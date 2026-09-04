#!/usr/bin/env bash
# ci/linter/lint-nginx.sh -- nginx-specific source conventions for src/*.[ch].
#
# What no generic C linter knows: an nginx module must use the nginx allocator,
# the nginx string/number helpers and the nginx source style, because it is
# compiled into a worker with a pool-based lifetime and a shared coding
# standard. flawfinder/cppcheck/semgrep all pass code that leaks a malloc()
# into a request pool or calls atoi() on attacker input.
#
# Checks (each one line per finding, "file:line: rule: text"):
#   libc-alloc   malloc/calloc/realloc/free      -> ngx_palloc/ngx_pcalloc/ngx_pfree
#   libc-str     strcpy/strcat/sprintf/strncpy   -> ngx_cpymem/ngx_snprintf
#   libc-num     atoi/atol/strtol on request data -> ngx_atoi/ngx_atoof
#   libc-io      bare printf/fprintf(stderr)     -> ngx_log_error
#   tabs         hard tab in source              -> nginx style is 4 spaces
#   width        line >80 columns                -> nginx style limit
#   trailing     trailing whitespace
#   include      .c must include ngx_config.h before ngx_core.h
#
# Suppress a single justified line with a trailing  /* NOLINT-nginx */ .
# Suppressing a whole rule is not supported on purpose: the exception belongs
# next to the code that needs it, where review can see the reason.
#
# Usage: ci/linter/lint-nginx.sh [files...]   Env: LINT_MODE=staged|all
# Extend: add a rule as one more `rule <name> <regex> <message>` call.

# shellcheck source=ci/linter/lib.sh
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

mapfile_checked FILES lint_files '^src/.*\.[ch]$' "$@"
[ "${#FILES[@]}" -gt 0 ] || { echo "lint-nginx: no C files to check"; exit 0; }

echo "lint-nginx: ${#FILES[@]} file(s)"
rc=0

# rule <name> <ere> <message> -- report every matching line not marked NOLINT.
rule() {
    local name="$1" re="$2" msg="$3" hits
    hits=$(grep -nE "$re" "${FILES[@]}" 2>/dev/null | grep -v 'NOLINT-nginx' || true)
    [ -n "$hits" ] || return 0
    printf '%s\n' "$hits" | sed "s/^/  /; s/$/    [$name: $msg]/"
    rc=1
}

rule libc-alloc '(^|[^_[:alnum:]])(malloc|calloc|realloc|free)[[:space:]]*\(' \
     'use ngx_palloc/ngx_pcalloc/ngx_pfree'
rule libc-str   '(^|[^_[:alnum:]])(strcpy|strcat|sprintf|strncpy|strncat)[[:space:]]*\(' \
     'use ngx_cpymem/ngx_snprintf'
rule libc-num   '(^|[^_[:alnum:]])(atoi|atol|strtol|strtoul)[[:space:]]*\(' \
     'use ngx_atoi/ngx_atoof'
rule libc-io    '(^|[^_[:alnum:]])(printf|fprintf|perror)[[:space:]]*\(' \
     'use ngx_log_error/ngx_conf_log_error'
rule tabs       $'\t' 'nginx style is 4 spaces, no hard tabs'
rule trailing   '[[:space:]]+$' 'trailing whitespace'
rule width      '^.{81,}$' 'nginx style limit is 80 columns'

for f in "${FILES[@]}"; do
    case "$f" in
      *.c)
        # ngx_config.h defines the feature macros every later nginx header
        # reads; including ngx_core.h first silently changes the build. Look at
        # the FIRST ngx_ include, not a fixed head -N window: these files open
        # with a long licence/design comment that would push the includes out
        # of any window and make the check vacuous.
        # Angle brackets only: a local "ngx_http_<mod>_*.h" is this module's
        # own header and carries its own ngx_config.h include -- matching it
        # here reported every well-formed file.
        # Either spelling, not just <...>. A module whose .c files open with
        # #include "ngx_http_<mod>_module.h" satisfies the ordering contract
        # when THAT header leads with <ngx_config.h> -- looking only at angle
        # includes reports the first one after it as a violation. Two false
        # positives on arrival in nginx-cache-turbo-module (2026-08-10), whose
        # every .c has that shape; this repo's own .c files include
        # <ngx_config.h> directly, so the gap never showed here.
        first_ngx=$(grep -nE '^[[:space:]]*#[[:space:]]*include[[:space:]]*[<"]ngx_' "$f" | head -1 || true)
        case "$first_ngx" in
          *'"'*)
            # Leading local ngx_ header: the contract moves to that header.
            local_h="src/$(printf '%s' "$first_ngx" | sed -E 's/.*"([^"]+)".*/\1/')"
            if [ -f "$local_h" ] \
               && grep -nE '^[[:space:]]*#[[:space:]]*include[[:space:]]*<ngx_' "$local_h" \
                  | head -1 | grep -q 'ngx_config\.h'; then
                first_ngx=""
            fi ;;
        esac
        if [ -n "$first_ngx" ] && ! printf '%s' "$first_ngx" | grep -q 'ngx_config\.h'; then
            printf '  %s:    [include: ngx_config.h must be the first ngx_ include]\n' \
                   "$f:${first_ngx%%:*}"
            rc=1
        fi ;;
    esac
done

if [ "$rc" -eq 0 ]; then say "clean"; fi
exit "$rc"
