/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit tests for the Accept-Encoding parser
 * (src/ngx_http_zstd_common.h: ngx_http_zstd_skip_quoted(),
 * ngx_http_zstd_eval_qvalue(), ngx_http_zstd_coding_weight(),
 * ngx_http_zstd_accept_encoding()).
 *
 * WHY THIS EXISTS ALONGSIDE ci/t/ AND ci/fuzz/
 *
 *   ci/t, Test::Nginx    drives the parser through a live nginx request. It
 *                        proves the header actually reaches the module, but
 *                        every boundary (an exact q-value digit count, the
 *                        "*" vs explicit-token precedence, a malformed
 *                        weight) has to be reached by crafting a raw header
 *                        string and is awkward to name.
 *   ci/fuzz targets      drive the same code with random bytes plus an
 *                        independent reference oracle. That proves the
 *                        parser never reads out of bounds and agrees with a
 *                        second implementation on the UNAMBIGUOUS cases --
 *                        but it does not state "q=0.1 must be treated as
 *                        weight 100", it only states agreement or disagreement
 *                        on inputs the oracle is confident about.
 *   this file            states values, at named boundaries, with no nginx
 *                        process, no network, in well under a second.
 *
 * This file, like the fuzz target, does NOT link the real ngx_string.c: the
 * production parser is fully self-contained ASCII walking (see the comment
 * atop ngx_http_zstd_common.h) and needs only ngx_strncasecmp/ngx_strcasestrn,
 * which ci/fuzz/ngx_shim.h reproduces as faithful, cited copies of the
 * upstream implementations -- the same shim the fuzz target links, so this
 * layer and the fuzz layer test the exact same compiled bytes. There is no
 * shim of the DECISION logic itself: run.sh regenerates
 * ci/fuzz/generated_parser.inc from the real src/ngx_http_zstd_common.h via
 * ci/fuzz/extract_parser.sh before every build, so this binary always links
 * the shipped parser, never a copy.
 *
 * SEEN RED -- every mutation below was APPLIED to
 * src/ngx_http_zstd_common.h and the named check was observed failing
 * (see ci/adoption-findings.md for the exact commands). Re-run them after
 * touching the parser or this file: a check that has never failed is not
 * known to be a check.
 *
 *   * wildcard precedence flipped -- in ngx_http_zstd_coding_weight(), return
 *     star_q first when both are set
 *       -> "explicit zstd;q=0 overrides a permissive *" FAILS.
 *   * q-value scale dropped a digit -- in ngx_http_zstd_eval_qvalue(),
 *     `scale /= 10` removed so every fractional digit is worth 100 instead
 *     of decaying by a factor of ten per digit
 *       -> "a fourth q decimal digit makes the element non-matching" FAILS
 *          (the loop no longer stops contributing after 3 digits at
 *          decreasing weight -- the value only exists to bound the digit
 *          count via the `scale > 0` loop guard, so removing the decrement
 *          also breaks the qvalue=0*3DIGIT length limit, caught by the
 *          same check as the malformed-fourth-digit mutation below rather
 *          than by a magnitude check on a 2-digit value).
 *   * malformed weight silently defaults to q=1 -- `if (q < 0) q = 1000;`
 *     inserted in ngx_http_zstd_coding_weight()
 *       -> "a fourth q decimal digit makes the element non-matching" FAILS.
 *   * quote skip disabled -- ngx_http_zstd_skip_quoted() changed to
 *     `return p;` unconditionally (before its own bounds check)
 *       -> the suite does not FAIL, it HANGS: case_skip_quoted_unterminated's
 *          unterminated `"..."` value makes the caller's `while (*p != ',')
 *          skip-quoted-else-advance` loop call skip_quoted() at the same `p`
 *          forever, since it now always returns its input unchanged. Verified
 *          with a 5s `timeout`, observed exit 124 (see
 *          ci/adoption-findings.md for the exact command). This is itself
 *          the reason case_skip_quoted_unterminated exists: an unterminated
 *          quote is exactly the input that turns "quote skip is a no-op"
 *          from a wrong-answer bug into a hang, which a FAIL-only check
 *          would never distinguish from a slow pass.
 *   * boundary off by one -- in ngx_http_zstd_eval_qvalue(), `p <= end`
 *     instead of `p < end` in the parameter-name scan loop condition
 *       -> "'q' with no '=value' makes the element non-matching, not an
 *          implicit q=1" FAILS, both under plain cc and under
 *          clang -fsanitize=address,undefined (no heap-buffer-overflow was
 *          raised by ASan for this specific mutation -- the outer `while (p
 *          < end && *p == ';')` guard means the widened inner condition is
 *          only ever reached with p == end already inside the caller's
 *          bound, so this mutation is a logic bug the tests catch, not a
 *          memory-safety one; recorded here rather than assumed, since
 *          "off by one" does not automatically imply "overread"). No
 *          sanitizer trap fired and no crash occurred; only the checked
 *          assertion moved.
 *   * single-pass cursor: quoted-name fallback dropped -- in
 *     ngx_http_zstd_eval_qvalue(), `*pp = p` unconditionally instead of
 *     only when no DQUOTE was seen inside a parameter name
 *       -> "differential: every hand-written boundary input agrees with
 *          the pre-single-pass parser" FAILS on `gzip;x"y=1,zstd`
 *          (zstd new=1000 old=-1), plus generated divergences, and
 *          "single-pass: DQUOTE inside a parameter name rescans from ';'"
 *          FAILS.
 *   * single-pass cursor: caller's element skip made quote-blind -- in
 *     ngx_http_zstd_coding_weight(), the post-eval skip to the next ','
 *     reduced to a plain `p++` walk
 *       -> the same differential check FAILS on `gzip;q=0.5"a,zstd`
 *          (zstd new=1000 old=-1) and on generated inputs.
 *   * single-pass cursor: caller's element skip removed outright
 *     (`if (0)` around it)
 *       -> the suite HANGS (run.sh's 60s timeout, exit 124): a malformed
 *          element leaves p on its junk byte with nothing advancing it.
 *   * (equivalent mutant, recorded so nobody re-runs it) forcing the
 *     fallback on every -1 return (`quoted_name = 1` under `malformed:`)
 *     survives: a rescan from the ';' and a resume at the junk byte
 *     produce the same element boundary, so the -1 path's single pass is
 *     a cost property, not an observable one.
 *
 * Extend: add a CASE() function and one line in main().
 */

/* Path-relative so any analyser parses this TU without -I flags: an
 * unparsed TU is silently skipped, which reads as clean. */
#include "../../fuzz/ngx_shim.h"
#include "../../fuzz/generated_parser.inc"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static int  failures;
static int  checks;


static void
check(int ok, const char *what)
{
    checks++;
    if (ok) {
        printf("ok   %s\n", what);
        return;
    }
    printf("FAIL %s\n", what);
    failures++;
}


/* Helper: parse `s` (a NUL-terminated C string used only to size the
 * buffer -- the underlying ae.len is exact, no NUL reliance) through the
 * full decision entry point. */
static ngx_int_t
decide(const char *s)
{
    ngx_str_t  ae;

    ae.data = (u_char *) s;
    ae.len  = strlen(s);

    return ngx_http_zstd_accept_encoding(&ae);
}

/* Helper: the generic weight walker, parameterized like the "dcz" caller
 * in the fuzz harness -- exercises the wildcard-not-allowed branch that
 * ngx_http_zstd_accept_encoding() (allow_wildcard=1) never reaches. */
static ngx_int_t
weight_no_wildcard(const char *s, const char *coding)
{
    ngx_str_t  ae;

    ae.data = (u_char *) s;
    ae.len  = strlen(s);

    return ngx_http_zstd_coding_weight(&ae, coding, strlen(coding), 0);
}


static void
case_empty_header(void)
{
    check(decide("") == NGX_DECLINED, "empty header declines");
}

static void
case_explicit_zstd_no_params(void)
{
    check(decide("zstd") == NGX_OK, "bare 'zstd' accepts (implicit q=1)");
}

static void
case_explicit_zstd_q1(void)
{
    check(decide("zstd;q=1") == NGX_OK, "'zstd;q=1' accepts");
}

static void
case_explicit_zstd_q0(void)
{
    check(decide("zstd;q=0") == NGX_DECLINED, "'zstd;q=0' declines");
}

static void
case_explicit_zstd_fractional(void)
{
    /* q=0.05 -> 50 milli-units, which is >0, so still accepted. */
    check(decide("zstd;q=0.05") == NGX_OK, "'zstd;q=0.05' still accepts (>0)");
}

static void
case_zstd_q_exactly_zero_fraction(void)
{
    check(decide("zstd;q=0.000") == NGX_DECLINED,
          "'zstd;q=0.000' declines (exactly zero)");
}

static void
case_wildcard_only(void)
{
    check(decide("*") == NGX_OK, "bare '*' accepts zstd via wildcard");
}

static void
case_wildcard_q0(void)
{
    check(decide("*;q=0") == NGX_DECLINED, "'*;q=0' declines");
}

static void
case_other_coding_only(void)
{
    check(decide("gzip") == NGX_DECLINED,
          "'gzip' alone declines (no zstd, no wildcard)");
}

static void
case_explicit_overrides_permissive_wildcard(void)
{
    /* This is the precedence rule the wildcard-flip mutation breaks. */
    check(decide("*, zstd;q=0") == NGX_DECLINED,
          "explicit 'zstd;q=0' overrides a permissive '*'");
}

static void
case_explicit_overrides_restrictive_wildcard(void)
{
    check(decide("*;q=0, zstd") == NGX_OK,
          "explicit 'zstd' overrides a restrictive '*;q=0'");
}

static void
case_case_insensitive_token(void)
{
    check(decide("ZsTd") == NGX_OK, "coding name match is case-insensitive");
}

static void
case_multiple_codings_with_zstd(void)
{
    check(decide("gzip;q=1, deflate, zstd;q=0.5, br") == NGX_OK,
          "zstd found among several codings");
}

static void
case_stray_commas_and_ows(void)
{
    check(decide(" , ,zstd , ") == NGX_OK,
          "stray commas and OWS around the list are tolerated (RFC 9110)");
}

static void
case_malformed_q_fourth_digit(void)
{
    /* qvalue = 0*3DIGIT after the decimal point; a fourth digit is
     * malformed, so the element must not match -- and there is no
     * wildcard here to fall back on, so DECLINED. */
    check(decide("zstd;q=0.1234") == NGX_DECLINED,
          "a fourth q decimal digit makes the element non-matching");
}

static void
case_malformed_q_missing_value(void)
{
    check(decide("zstd;q=") == NGX_DECLINED,
          "'q=' with no digits makes the element non-matching");
}

static void
case_malformed_q_bare_param(void)
{
    check(decide("zstd;q") == NGX_DECLINED,
          "'q' with no '=value' makes the element non-matching, "
          "not an implicit q=1");
}

static void
case_quoted_param_hides_comma(void)
{
    /*
     * The comma inside the quoted x="..." parameter value must NOT be
     * read as an element separator -- if it were, the bytes after it
     * ("zstd") would be misparsed as a fresh, matching coding name.
     * This is exactly the skip_quoted seam: disabling it makes this
     * case wrongly accept.
     */
    check(decide("gzip;x=\"a, zstd\"") == NGX_DECLINED,
          "a comma inside a quoted parameter value is not an element "
          "boundary (no phantom zstd token)");
}

static void
case_quoted_name_position_not_a_token(void)
{
    /* A quoted-string can never be a valid coding name; the whole quoted
     * blob plus its trailing params must be skipped as one non-matching
     * element, not split on the interior comma. */
    check(decide("\"a,zstd\"") == NGX_DECLINED,
          "a quoted string in name position is not a coding token");
}

static void
case_duplicate_explicit_token_last_wins(void)
{
    check(decide("zstd;q=0, zstd;q=1") == NGX_OK,
          "a later duplicate explicit zstd token wins over an earlier one");
}

static void
case_end_of_buffer_no_trailing_nul_reliance(void)
{
    /* Exercise a q= right at the exact end of the buffer -- ae.len is
     * exact with no allocated trailing NUL (mirrors the fuzz harness's
     * malloc(exact size) contract), so any read at or past ae->len is a
     * bounds violation the boundary-off-by-one mutation introduces. */
    static const char  raw[] = "zstd;q=";
    ngx_str_t           ae;

    ae.data = (u_char *) raw;
    ae.len  = sizeof(raw) - 1;   /* exclude the C-string NUL from the walk */

    check(ngx_http_zstd_accept_encoding(&ae) == NGX_DECLINED,
          "'q=' ending exactly at buffer end is malformed, not an overread");
}

static void
case_generic_weight_wildcard_not_allowed(void)
{
    /* dcz's own contract: a bare "*" must NOT turn dcz on. */
    check(weight_no_wildcard("*", "dcz") == -1,
          "generic weight walker: wildcard does not apply when the caller "
          "disallows it (dcz contract)");
    check(weight_no_wildcard("dcz;q=1", "dcz") == 1000,
          "generic weight walker: explicit token still applies with "
          "allow_wildcard=0");
}

static void
case_nonq_param_is_skipped_trailing_q_honoured(void)
{
    /*
     * Deliberate, specified divergence from nginx core. Core's
     * ngx_http_gzip_accept_encoding() NGX_DECLINEs on any post-';' byte
     * that is not 'q'/'Q'/OWS, so it drops the whole element on
     * "gzip;foo=bar" -- losing any weight the client did express.
     *
     * This parser instead skips an unrecognized parameter's value to the
     * next top-level delimiter and keeps parsing, so a trailing "q" on
     * the SAME element is still found and honoured. That is strictly more
     * faithful to what the client asked for, in both directions:
     * q=0 must still suppress, q=1 must still accept. Ignoring an
     * unrecognized parameter is the standard HTTP robustness posture; the
     * leniency is a superset that only ever compresses for a client that
     * explicitly named zstd.
     */
    check(decide("zstd;foo=bar;q=0") == NGX_DECLINED,
          "a skipped non-q parameter must not swallow the trailing q=0 "
          "(client explicitly refused zstd)");
    check(decide("zstd;foo=bar;q=1") == NGX_OK,
          "a skipped non-q parameter must not swallow the trailing q=1");
    check(decide("zstd;foo=bar") == NGX_OK,
          "an unrecognized parameter with no q defaults to q=1, rather "
          "than dropping an element the client explicitly asked for");
    check(decide("zstd;foo") == NGX_OK,
          "a bare unrecognized parameter is likewise ignored, not fatal");
}


static void
case_nonq_param_quoted_value_delimiter_scan(void)
{
    /*
     * The quoted-string arm of the skip loop: a top-level ';' or ',' that
     * appears INSIDE a quoted parameter value must not be mistaken for the
     * end of the value, or the trailing q would be parsed out of the wrong
     * position (or missed entirely).
     */
    check(decide("zstd;foo=\"a,b;c\";q=0") == NGX_DECLINED,
          "a ';' and ',' inside a quoted non-q value do not end the value; "
          "the real trailing q=0 is still the one honoured");
    check(decide("zstd;foo=a\"b\";q=0") == NGX_DECLINED,
          "a quoted run starting mid-value is skipped as one unit and "
          "parsing resumes at the ';', finding the trailing q=0");
    check(decide("zstd;foo=\"unterm") == NGX_OK,
          "an unterminated quoted non-q value runs to end without an OOB "
          "read and leaves the element at the default q=1");
}


static void
case_skip_quoted_unterminated(void)
{
    /* ngx_http_zstd_skip_quoted() must still terminate (advance past at
     * least the opening DQUOTE) on an unterminated quote, or the caller's
     * loop stalls. Exercised indirectly: an unterminated quote must not
     * hang the whole decision walk. */
    check(decide("gzip;x=\"unterminated, zstd") == NGX_DECLINED,
          "an unterminated quoted parameter value does not hang the walk "
          "and does not fabricate a matching zstd token");
}


/*
 * Direct oracle on ngx_http_zstd_parse_q_fraction() itself -- every case
 * above only ever asks "did the whole header accept or decline", which is
 * satisfied by any weight > 0 (or, for a q=0 case, is satisfied by any
 * weight == 0). Neither shape can tell an exact milliweight, or a wrong
 * cursor, from a correct one: a tens-digit arithmetic mistake that still
 * lands on "some positive number" or "exactly zero" is invisible to
 * decide(). These cases call the pure digit-walk helper directly and
 * assert BOTH of its documented outputs -- the returned weight, and the
 * cursor position it leaves in *p -- which is the only way to observe
 * that "10s digit worth 10" specifically (not just "worth something") and
 * that "a 4th digit is left unconsumed" (the caller's trailing-junk
 * contract, ngx_http_zstd_eval_qvalue()'s q += ... callers all depend on
 * *p pointing AT the offending byte, not past it).
 *
 * OBSERVED: mutating the tens weight from `* 10` to `* 11` in
 * ngx_http_zstd_parse_q_fraction() left all 31 pre-existing checks above
 * still green (every accept/decline decision the header drives is
 * unaffected by an 11-vs-10 tens digit, since every fixture above uses at
 * most one nonzero fractional digit or crosses the q>0/q==0 boundary by a
 * wide margin). case_fraction_exhaustive_three_digit() below is what
 * catches it -- see ci/adoption-findings.md for the exact command and
 * its failing output.
 */
static void
run_one_fraction(const char *digits, ngx_int_t want_frac,
    ptrdiff_t want_consumed, const char *what)
{
    u_char        *p;
    const u_char  *end;
    ngx_int_t      frac;
    ptrdiff_t      consumed;

    p = (u_char *) digits;
    end = (const u_char *) digits + strlen(digits);

    frac = ngx_http_zstd_parse_q_fraction(end, &p);
    consumed = p - (u_char *) digits;

    if (frac != want_frac || consumed != want_consumed) {
        printf("FAIL %s (got frac=%ld consumed=%ld, want frac=%ld "
               "consumed=%ld)\n",
               what, (long) frac, (long) consumed, (long) want_frac,
               (long) want_consumed);
        checks++;
        failures++;
        return;
    }

    check(1, what);
}

static void
case_fraction_empty_input(void)
{
    /* "" -- end == p already, no digit consumed at all. */
    run_one_fraction("", 0, 0, "fraction: empty input -> frac=0, cursor=0");
}

static void
case_fraction_one_digit(void)
{
    run_one_fraction("5", 500, 1, "fraction: one digit '5' -> frac=500, "
                                  "cursor advances 1");
}

static void
case_fraction_two_digit(void)
{
    /* This is exactly the boundary the auditor's tens-weight mutation
     * (10 -> 11) breaks: '5' contributes 50 only if the tens digit is
     * genuinely worth 10 per unit. */
    run_one_fraction("05", 50, 2, "fraction: two digits '05' -> frac=50 "
                                  "(tens digit worth exactly 10/unit), "
                                  "cursor advances 2");
}

static void
case_fraction_three_digit(void)
{
    run_one_fraction("123", 123, 3, "fraction: three digits '123' -> "
                                    "frac=123, cursor advances 3");
}

static void
case_fraction_four_digit_leaves_fourth_unconsumed(void)
{
    /*
     * The documented contract this row exists to pin: after three digits
     * the cursor stops WITHOUT consuming a fourth digit byte, so the
     * caller's trailing-junk check (ngx_http_zstd_eval_qvalue() /
     * ngx_http_zstd_coding_weight()'s post-qvalue scan) sees the '4' and
     * rejects the element. Assert the exact stop position, not just "some
     * prefix was consumed".
     */
    run_one_fraction("1234", 123, 3,
        "fraction: four digits '1234' -> only the first three are "
        "consumed (frac=123), the 4th digit is LEFT UNCONSUMED");
}

static void
case_fraction_truncated_mid_walk(void)
{
    /* `end` reached after one digit: the walk must stop at `end`, not
     * read past it, and the cursor must sit exactly at `end`. */
    u_char        buf[1] = { '7' };
    u_char       *p = buf;
    const u_char *end = buf + 1;
    ngx_int_t     frac = ngx_http_zstd_parse_q_fraction(end, &p);

    check(frac == 700 && p == end,
          "fraction: input truncated after one digit -- cursor stops "
          "exactly at end, frac=700");
}

static void
case_fraction_truncated_mid_walk_two_digits(void)
{
    u_char        buf[2] = { '4', '2' };
    u_char       *p = buf;
    const u_char *end = buf + 2;
    ngx_int_t     frac = ngx_http_zstd_parse_q_fraction(end, &p);

    check(frac == 420 && p == end,
          "fraction: input truncated after two digits -- cursor stops "
          "exactly at end, frac=420");
}

static void
case_fraction_non_digit_terminator_not_consumed(void)
{
    /* A non-digit byte (here ';', the real-world terminator after
     * "q=0.5") must stop the walk WITHOUT consuming it -- the caller
     * needs *p pointing AT that byte, e.g. to continue scanning
     * parameters. */
    run_one_fraction("5;q=1", 500, 1,
        "fraction: non-digit terminator ';' is not consumed, "
        "cursor sits on it");
}

static void
case_fraction_non_digit_terminator_at_start(void)
{
    /* Not even one digit: the very first byte is non-digit, so nothing
     * is consumed and frac stays 0. */
    run_one_fraction("x", 0, 0,
        "fraction: non-digit terminator at position 0 -- frac=0, "
        "cursor=0 (nothing consumed)");
}

static void
case_fraction_exhaustive_three_digit(void)
{
    /*
     * Exhaustive 000..999: every three-digit fraction, asserting the
     * EXACT returned weight (hundreds*100 + tens*10 + units*1) and that
     * the cursor always advances by exactly 3. This is the check that
     * actually catches an arithmetic-weight mutation on any single digit
     * position -- a spot check on a handful of values can miss a
     * mutation whose effect happens to cancel out on those particular
     * inputs, but summing every input in the space cannot.
     */
    /*
     * NUL-terminated for the "%s" diagnostic below; the parser end pointer
     * still targets exactly the first 3 bytes, so the '\0' at digits[3] is
     * never itself in the parsed slice.
     */
    char       digits[4];
    int        n, h, t, u;
    int        local_failures = 0;

    digits[3] = '\0';

    for (n = 0; n < 1000; n++) {
        h = n / 100;
        t = (n / 10) % 10;
        u = n % 10;

        digits[0] = (char) ('0' + h);
        digits[1] = (char) ('0' + t);
        digits[2] = (char) ('0' + u);

        {
            u_char        *p = (u_char *) digits;
            const u_char  *end = (const u_char *) digits + 3;
            ngx_int_t      frac = ngx_http_zstd_parse_q_fraction(end, &p);
            ngx_int_t      want = h * 100 + t * 10 + u;
            ptrdiff_t      consumed = p - (u_char *) digits;

            checks++;

            if (frac != want || consumed != 3) {
                if (local_failures < 5) {
                    printf("FAIL fraction: exhaustive \"%s\" -> got "
                           "frac=%ld consumed=%ld, want frac=%ld "
                           "consumed=3\n",
                           digits, (long) frac, (long) consumed,
                           (long) want);
                }
                local_failures++;
                failures++;
            }
        }
    }

    if (local_failures == 0) {
        printf("ok   fraction: exhaustive 000..999 all match "
               "hundreds*100+tens*10+units*1, cursor always advances 3 "
               "(1000 cases)\n");
    } else {
        printf("FAIL fraction: exhaustive 000..999 -- %d/1000 mismatched "
               "(first 5 shown above)\n", local_failures);
    }
}


/* ------------------------------------------------------------------ *
 * Chained Accept-Encoding field lines (ngx_http_zstd_chain_coding_weight)
 *
 * nginx chains duplicate Accept-Encoding request header lines on
 * ->next. RFC 9110 section 5.3 makes that identical to the single field
 * whose value is the lines joined with commas, so
 *
 *     Accept-Encoding: gzip
 *     Accept-Encoding: zstd
 *
 * IS "gzip, zstd" and accepts zstd. Every case below states one such
 * request as its line list and asserts the decision the joined value
 * would have produced.
 *
 * Duplicate coding values retain the order of the comma-joined field: the
 * later explicit value decides, just as it does within one field line.
 * ------------------------------------------------------------------ */

/*
 * Build a ->next chain over up to 4 literal field values and run the
 * chain walker across it. Storage is static per call site depth, which is
 * fine: each case builds, decides, and discards before the next runs.
 */
static ngx_int_t
chain_weight(const char *coding, ngx_uint_t allow_wildcard,
    const char *l0, const char *l1, const char *l2, const char *l3)
{
    static ngx_table_elt_t  e[4];
    const char             *lines[4];
    ngx_uint_t              n;

    lines[0] = l0; lines[1] = l1; lines[2] = l2; lines[3] = l3;

    for (n = 0; n < 4 && lines[n] != NULL; n++) {
        e[n].value.data = (u_char *) lines[n];
        e[n].value.len  = strlen(lines[n]);
        e[n].next = NULL;
        if (n > 0) {
            e[n - 1].next = &e[n];
        }
    }

    if (n == 0) {
        return -1;
    }

    return ngx_http_zstd_chain_coding_weight(&e[0], coding, strlen(coding),
                                             allow_wildcard);
}

/* zstd decision over a chain: same predicate as ngx_http_zstd_accepts(). */
static ngx_int_t
chain_zstd(const char *l0, const char *l1, const char *l2, const char *l3)
{
    return chain_weight("zstd", 1, l0, l1, l2, l3) > 0
               ? NGX_OK : NGX_DECLINED;
}

/* dcz decision over a chain: explicit token only, no wildcard. */
static ngx_int_t
chain_dcz(const char *l0, const char *l1, const char *l2, const char *l3)
{
    return chain_weight("dcz", 0, l0, l1, l2, l3) > 0
               ? NGX_OK : NGX_DECLINED;
}

/*
 * THE WITNESS. Two lines, the acceptable coding on the SECOND. Before the
 * chain walker only the first line was parsed, so this declined.
 */
static void
case_chain_gzip_then_zstd(void)
{
    check(chain_zstd("gzip", "zstd", NULL, NULL) == NGX_OK,
          "chain: 'gzip' then 'zstd' accepts (joined: \"gzip, zstd\")");
}

static void
case_chain_zstd_then_gzip(void)
{
    check(chain_zstd("zstd", "gzip", NULL, NULL) == NGX_OK,
          "chain: 'zstd' then 'gzip' accepts");
}

/* A single line is unchanged: the walker must not alter the common case. */
static void
case_chain_single_line_unchanged(void)
{
    check(chain_zstd("gzip", NULL, NULL, NULL) == NGX_DECLINED,
          "chain: single 'gzip' line still declines");
    check(chain_zstd("zstd", NULL, NULL, NULL) == NGX_OK,
          "chain: single 'zstd' line still accepts");
}

/* Duplicate explicit values follow the received (comma-joined) order. */
static void
case_chain_q0_first_line(void)
{
    check(chain_zstd("zstd;q=0", "gzip", NULL, NULL) == NGX_DECLINED,
          "chain: 'zstd;q=0' then 'gzip' declines");
}

static void
case_chain_q0_second_line(void)
{
    check(chain_zstd("gzip", "zstd;q=0", NULL, NULL) == NGX_DECLINED,
          "chain: 'gzip' then 'zstd;q=0' declines");
}

static void
case_chain_q0_then_q1_accepts(void)
{
    check(chain_zstd("zstd;q=0", "zstd;q=1", NULL, NULL) == NGX_OK,
          "chain: later 'zstd;q=1' overrides an earlier refusal");
}

static void
case_chain_q1_then_q0_stays_declined(void)
{
    check(chain_zstd("zstd;q=1", "zstd;q=0", NULL, NULL) == NGX_DECLINED,
          "chain: 'zstd;q=1' then 'zstd;q=0' declines");
}

/* The later value wins across field lines, as it does within one line. */
static void
case_chain_two_nonzero_weights(void)
{
    check(chain_weight("zstd", 1, "zstd;q=0.5", "zstd;q=1", NULL, NULL) == 1000,
          "chain: later explicit weight wins (0.5 then 1 -> 1000)");
    check(chain_zstd("zstd;q=0.5", "zstd;q=1", NULL, NULL) == NGX_OK,
          "chain: two non-zero weights still accept");
}

/* A wildcard on a LATER line must still be seen. */
static void
case_chain_wildcard_later_line(void)
{
    check(chain_zstd("gzip", "*", NULL, NULL) == NGX_OK,
          "chain: '*' on the second line accepts");
}

/* An explicit q=0 anywhere overrides a permissive '*' on another line. */
static void
case_chain_wildcard_vs_explicit_q0(void)
{
    check(chain_zstd("*", "zstd;q=0", NULL, NULL) == NGX_DECLINED,
          "chain: explicit 'zstd;q=0' overrides a '*' on an earlier line");
    check(chain_zstd("zstd;q=0", "*", NULL, NULL) == NGX_DECLINED,
          "chain: explicit 'zstd;q=0' overrides a '*' on a later line");
}

/* '*;q=0' on a later line is a refusal too, when nothing names zstd. */
static void
case_chain_wildcard_q0_later(void)
{
    check(chain_zstd("gzip", "*;q=0", NULL, NULL) == NGX_DECLINED,
          "chain: '*;q=0' on the second line declines");
}

/* Three and four lines: the walk must not stop at two. */
static void
case_chain_three_lines(void)
{
    check(chain_zstd("gzip", "br", "zstd", NULL) == NGX_OK,
          "chain: three lines, 'zstd' on the third, accepts");
}

static void
case_chain_four_lines(void)
{
    check(chain_zstd("gzip", "br", "deflate", "zstd") == NGX_OK,
          "chain: four lines, 'zstd' on the fourth, accepts");
    check(chain_zstd("gzip", "br", "deflate", "identity") == NGX_DECLINED,
          "chain: four lines with no zstd and no '*' declines");
}

/* An empty later line contributes nothing and must not break the walk. */
static void
case_chain_empty_line(void)
{
    check(chain_zstd("", "zstd", NULL, NULL) == NGX_OK,
          "chain: empty first line then 'zstd' accepts");
    check(chain_zstd("zstd", "", NULL, NULL) == NGX_OK,
          "chain: 'zstd' then an empty line accepts");
}

/*
 * Splitting a list mid-way across lines is the whole point of RFC 9110
 * section 5.3: these lines joined are "gzip, zstd;q=0.5, br".
 */
static void
case_chain_split_list(void)
{
    check(chain_zstd("gzip", "zstd;q=0.5, br", NULL, NULL) == NGX_OK,
          "chain: a list split across lines negotiates as the joined value");
}

/* --- dcz variants: explicit token only, '*' must never turn dcz on --- */

static void
case_chain_dcz_second_line(void)
{
    check(chain_dcz("zstd", "dcz", NULL, NULL) == NGX_OK,
          "chain/dcz: 'zstd' then 'dcz' accepts");
}

static void
case_chain_dcz_first_line(void)
{
    check(chain_dcz("dcz", "zstd", NULL, NULL) == NGX_OK,
          "chain/dcz: 'dcz' then 'zstd' accepts");
}

static void
case_chain_dcz_q0_second_line(void)
{
    check(chain_dcz("zstd", "dcz;q=0", NULL, NULL) == NGX_DECLINED,
          "chain/dcz: 'zstd' then 'dcz;q=0' declines");
}

static void
case_chain_dcz_q0_first_line(void)
{
    check(chain_dcz("dcz;q=0", "zstd", NULL, NULL) == NGX_DECLINED,
          "chain/dcz: 'dcz;q=0' then 'zstd' declines");
}

static void
case_chain_dcz_q0_then_q1_accepts(void)
{
    check(chain_dcz("dcz;q=0", "dcz;q=1", NULL, NULL) == NGX_OK,
          "chain/dcz: later 'dcz;q=1' overrides an earlier refusal");
}

static void
case_chain_dcz_q1_then_q0_declines(void)
{
    check(chain_dcz("dcz;q=1", "dcz;q=0", NULL, NULL) == NGX_DECLINED,
          "chain/dcz: later 'dcz;q=0' overrides an earlier allowance");
}

/*
 * The wildcard gate survives the chain: a '*' on ANY line must not turn
 * dcz on, because only a client holding the dictionary can decode it.
 */
static void
case_chain_dcz_wildcard_never_matches(void)
{
    check(chain_dcz("zstd", "*", NULL, NULL) == NGX_DECLINED,
          "chain/dcz: '*' on a later line must NOT turn dcz on");
    check(chain_dcz("*", "zstd", NULL, NULL) == NGX_DECLINED,
          "chain/dcz: '*' on an earlier line must NOT turn dcz on");
}

static void
case_chain_dcz_three_lines(void)
{
    check(chain_dcz("gzip", "zstd", "dcz", NULL) == NGX_OK,
          "chain/dcz: three lines, 'dcz' on the third, accepts");
}


/*
 * ---------------------------------------------------------------------------
 * Differential test: single-pass parameter scan vs the pre-single-pass parser
 *
 * ngx_http_zstd_eval_qvalue() used to take its cursor by value, so
 * ngx_http_zstd_coding_weight() rescanned every parameter byte (quoted
 * strings included) to find the next top-level ','. It now advances the
 * caller's cursor. The two functions below are the VERBATIM pre-change
 * bodies (renamed; they share ngx_http_zstd_skip_quoted() and
 * ngx_http_zstd_parse_q_fraction() with the shipped slice, which the change
 * did not touch), kept here as the oracle: for every generated and
 * hand-written input the shipped walker must return the same weight for
 * "zstd" (wildcard allowed), for "dcz" (wildcard refused) and the same
 * accept/decline verdict. Any divergence is a negotiation change, which the
 * single-pass rework is not allowed to make.
 *
 * Every input is copied into a malloc'd buffer of EXACTLY ae.len bytes with
 * no trailing NUL, so an ASan build of this suite traps a read past the
 * field on either implementation.
 */

static ngx_int_t
ref_eval_qvalue(const ngx_str_t *ae, u_char *p)
{
    const u_char  *end = ae->data + ae->len;
    ngx_int_t      q = 1000;   /* no q parameter → q=1 */
    ngx_int_t      q_seen = 0; /* reject a second "q" parameter (RFC 9110) */

    while (p < end && *p == ';') {

        const u_char  *nstart, *nend;
        ngx_int_t      is_q;

        p++;    /* skip ';' */

        while (p < end && (*p == ' ' || *p == '\t')) {
            p++;
        }

        /* parameter name */
        nstart = p;
        while (p < end
               && *p != '=' && *p != ';' && *p != ','
               && *p != ' ' && *p != '\t')
        {
            p++;
        }
        nend = p;

        /*
         * RFC 9110 has no empty-parameter production, so "zstd;;q=1" is
         * malformed rather than "a skipped parameter followed by q=1".
         * Reject it instead of silently resolving the element to q=1.
         */
        if (nend == nstart) {
            return -1;
        }

        is_q = (nend - nstart == 1
                && (nstart[0] == 'q' || nstart[0] == 'Q'));

        while (p < end && (*p == ' ' || *p == '\t')) {
            p++;
        }

        if (p < end && *p == '=') {
            p++;

            while (p < end && (*p == ' ' || *p == '\t')) {
                p++;
            }

            if (is_q) {
                /*
                 * Strict qvalue grammar. Leading digit must be 0 or 1.
                 */
                if (q_seen) {
                    return -1;          /* repeated "q" parameter */
                }
                q_seen = 1;

                if (p >= end) {
                    return -1;          /* "q=" with no value */
                }

                if (*p == '0') {
                    p++;
                    q = 0;

                    if (p < end && *p == '.') {
                        p++;
                        q += ngx_http_zstd_parse_q_fraction(end, &p);
                    }

                } else if (*p == '1') {
                    p++;
                    q = 1000;

                    if (p < end && *p == '.') {
                        int  i = 0;

                        p++;
                        while (p < end && *p == '0' && i < 3) {
                            p++;
                            i++;
                        }
                    }

                } else {
                    return -1;          /* leading digit not 0 or 1 */
                }

                /*
                 * After a valid qvalue only OWS / ';' / ',' / end may
                 * follow. A fourth decimal digit or trailing junk
                 * (q=1x, q=0.0001) lands here as a non-delimiter byte and
                 * is rejected.
                 */
                if (p < end
                    && *p != ' ' && *p != '\t' && *p != ';' && *p != ',')
                {
                    return -1;
                }

            } else {
                /*
                 * non-q parameter: skip its value to the next top-level ';'
                 * (another parameter) or ',' (next element), stepping over a
                 * quoted-string so an embedded delimiter is not mistaken for
                 * the value's end.
                 */
                while (p < end && *p != ';' && *p != ',') {
                    if (*p == '"') {
                        p = ngx_http_zstd_skip_quoted(p, end);
                    } else {
                        p++;
                    }
                }
            }

        } else {
            /* parameter present without a value */
            if (is_q) {
                return -1;              /* "q" with no "=value" is malformed */
            }
        }

        while (p < end && (*p == ' ' || *p == '\t')) {
            p++;
        }

        /*
         * After the OWS that may trail any parameter (its q-specific
         * check above only catches junk BEFORE this OWS skip, e.g.
         * "q=1x"), only ';' (another parameter), ',' (next element), or
         * end may follow -- anything else is trailing junk the loop's own
         * "while (*p == ';')" condition would otherwise silently accept
         * as "no more parameters" instead of rejecting (e.g.
         * "zstd;q=1 garbage" previously parsed as zstd;q=1).
         */
        if (p < end && *p != ';' && *p != ',') {
            return -1;
        }
    }

    return q;
}

static ngx_int_t
ref_coding_weight(const ngx_str_t *ae, const char *coding,
    size_t coding_len, ngx_uint_t allow_wildcard)
{
    u_char        *p   = ae->data;
    const u_char  *end = ae->data + ae->len;
    ngx_int_t      coding_q = -1; /* explicit `coding` weight, -1 = absent */
    ngx_int_t      star_q = -1;   /* "*" wildcard weight,      -1 = absent */

    while (p < end) {

        u_char        *tok;
        const u_char  *name_end;
        ngx_int_t      is_coding, is_star, q;

        /* Skip OWS and empty list elements (RFC 9110 allows stray
         * commas, e.g. ", ,zstd"). */
        while (p < end && (*p == ' ' || *p == '\t' || *p == ',')) {
            p++;
        }
        if (p >= end) {
            break;
        }

        /* The coding name runs until OWS, ';' (params), ',' (next
         * element), or a DQUOTE. A '"' can never be part of a valid coding
         * token; stopping here keeps a quoted-string that opens in
         * name position (e.g. `"a,zstd "`) from being split on a comma
         * inside the quotes — the quote-aware element-skip below then
         * swallows the whole quoted blob and the element declines. Without
         * this stop, the bytes after an in-quote comma are mis-read as a
         * fresh coding name and can fabricate a phantom "zstd" token. */
        tok = p;
        while (p < end
               && *p != ' ' && *p != '\t' && *p != ';' && *p != ','
               && *p != '"')
        {
            p++;
        }
        name_end = p;

        is_coding = ((size_t) (name_end - tok) == coding_len
                     && ngx_strncasecmp(tok, (u_char *) coding,
                                        coding_len) == 0);
        is_star = (name_end - tok == 1 && tok[0] == '*');

        /* Step over any OWS between the name and its ';' or ','. */
        while (p < end && (*p == ' ' || *p == '\t')) {
            p++;
        }

        /*
         * Only ';' (parameters), ',' (next element) or end of field may
         * follow a coding name. RFC 9110 12.5.3 makes `codings` a token,
         * so anything else means this element is not the coding it looked
         * like: `zstd"x` and `zstd "x` advertise nothing, and neither does
         * `zstd x`. nginx's own ngx_http_gzip_accept_encoding() applies
         * the same rule, so accepting these diverged from the sibling
         * filter and compressed for clients that never offered zstd.
         *
         * The check must sit AFTER the OWS skip: the name scan stops on
         * OWS as well as on '"', so testing the stopping byte alone
         * catches `zstd"x` and misses everything hiding behind a space.
         * The quote-aware element-skip below still swallows the rest of
         * the element, so the phantom-token guard is unchanged.
         */
        if (p < end && *p != ';' && *p != ',') {
            is_coding = 0;
            is_star = 0;
        }

        q = 1000;       /* no parameters → q=1 */
        if (p < end && *p == ';') {
            q = ref_eval_qvalue(ae, p);
        }

        if (q >= 0) {
            if (is_coding) {
                coding_q = q;   /* a later duplicate explicit token wins */
            } else if (is_star) {
                star_q = q;
            }
        }
        /* q < 0 → malformed weight: leave this element non-matching. */

        /*
         * Skip the remainder of this element up to the next top-level comma,
         * stepping over any quoted-string so a ',' inside quotes is not
         * mistaken for an element boundary (which would otherwise let a
         * quoted comma fabricate a phantom coding token from the bytes that
         * follow it, e.g. `gzip;x="a, zstd";q=1`).
         */
        while (p < end && *p != ',') {
            if (*p == '"') {
                p = ngx_http_zstd_skip_quoted(p, end);
            } else {
                p++;
            }
        }
    }

    /*
     * An explicit token decides the result (even q=0, which then
     * overrides a permissive "*"). With no explicit token, the "*"
     * wildcard applies if present and permitted by the caller.
     */
    if (coding_q >= 0) {
        return coding_q;
    }
    if (allow_wildcard && star_q >= 0) {
        return star_q;
    }
    return -1;
}

static ngx_int_t
ref_accept_encoding(const ngx_str_t *ae)
{
    return ref_coding_weight(ae, "zstd", 4, 1) > 0 ? NGX_OK : NGX_DECLINED;
}


/* xorshift64*: fixed seed, so a divergence is reproducible by index. */
static uint64_t  diff_rng_state = 0x9e3779b97f4a7c15ULL;

static uint32_t
diff_rng(void)
{
    uint64_t  x = diff_rng_state;

    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    diff_rng_state = x;

    return (uint32_t) ((x * 0x2545f4914f6cdd1dULL) >> 32);
}


/*
 * Fragment alphabet. Weighted toward the delimiters and q spellings the
 * parser branches on; bytes 0x80..0xff and NUL come from the "raw byte"
 * fragment so non-ASCII and embedded-NUL headers are covered too.
 */
static const char *const  diff_frag[] = {
    "zstd", "ZSTD", "Zstd", "gzip", "dcz", "DCZ", "br", "*", "identity",
    ",", ",", ",", ", ", " ,", " , ", ",,", ";", ";", "; ", " ;", ";;",
    " ", "\t", "  ", "=", "= ", " =",
    "q=", "q=1", "q=1.", "q=1.0", "q=1.00", "q=1.000", "q=1.0000", "q=1.001",
    "q=0", "q=0.", "q=0.5", "q=0.05", "q=0.005", "q=0.0001", "q=0.999",
    "q=2", "q=-1", "q=.5", "q= 1", "q =1", "Q=0.3", "q=1x", "q=0.5x", "q",
    "q=\"1\"", "q=1\"", "qq=1", "x=1", "x", "x=", "level=9", "a=b=c",
    "\"", "\"", "\\", "\\\"", "\\,", "\\;",
    "\"a,b\"", "\"a;b\"", "\"a\\\"b\"", "\"a\\,b\"", "\"unterminated",
    "\"zstd\"", "\"a,zstd\"", "\", zstd;q=1\"", "x=\"a,zstd\"",
    "\"\"", "\"\\\"", "\"\\",
    "zstd;q=0", "zstd;q=1", "*;q=0", "*;q=0.5", "zstd;x=\"a,b\";q=0.5",
    "\r", "\n", "\x7f", NULL /* raw byte marker */
};

#define DIFF_NFRAG  (sizeof(diff_frag) / sizeof(diff_frag[0]))
#define DIFF_MAXLEN 8192

static size_t
diff_generate(uint8_t *buf, size_t cap)
{
    size_t  n = 0, i;
    size_t  frags = 1 + diff_rng() % 12;

    /* one case in 64 is a very long list */
    if (diff_rng() % 64 == 0) {
        frags = 200 + diff_rng() % 600;
    }

    for (i = 0; i < frags && n < cap; i++) {
        const char  *f = diff_frag[diff_rng() % DIFF_NFRAG];
        size_t       l;

        if (f == NULL) {
            uint32_t  r = diff_rng();

            /* raw byte: NUL, controls, or high bytes 0x80..0xff */
            buf[n++] = (uint8_t) (r & 1 ? 0x80 | (r >> 8) : (r >> 8) & 0x1f);
            continue;
        }

        l = strlen(f);
        if (l > cap - n) {
            l = cap - n;
        }
        memcpy(buf + n, f, l);
        n += l;
    }

    return n;
}


static void
diff_hex(const uint8_t *d, size_t n, char *out, size_t cap)
{
    size_t  i, o = 0;

    for (i = 0; i < n && o + 4 < cap; i++) {
        if (d[i] >= 0x20 && d[i] < 0x7f && d[i] != '\\') {
            out[o++] = (char) d[i];
        } else {
            o += (size_t) snprintf(out + o, cap - o, "\\x%02x", d[i]);
        }
    }
    out[o] = '\0';
}


/*
 * Returns 1 when old and new agree on every observable for this input,
 * 0 (and prints the input) otherwise.
 */
static int
diff_one(const uint8_t *src, size_t n, const char *label)
{
    ngx_str_t  ae;
    uint8_t   *exact;
    ngx_int_t  nz, oz, ndcz, odcz, na, oa;
    int        ok;

    exact = malloc(n ? n : 1);     /* exact-size: ASan bounds the field */
    if (exact == NULL) {
        printf("FAIL %s: malloc\n", label);
        return 0;
    }
    memcpy(exact, src, n);

    ae.data = exact;
    ae.len  = n;

    nz = ngx_http_zstd_coding_weight(&ae, "zstd", 4, 1);
    oz = ref_coding_weight(&ae, "zstd", 4, 1);
    ndcz = ngx_http_zstd_coding_weight(&ae, "dcz", 3, 0);
    odcz = ref_coding_weight(&ae, "dcz", 3, 0);
    na = ngx_http_zstd_accept_encoding(&ae);
    oa = ref_accept_encoding(&ae);

    ok = (nz == oz && ndcz == odcz && na == oa);

    if (!ok) {
        char  hex[512];

        diff_hex(src, n < 120 ? n : 120, hex, sizeof(hex));
        printf("FAIL %s: zstd new=%ld old=%ld dcz new=%ld old=%ld "
               "accept new=%ld old=%ld len=%zu input=\"%s\"%s\n",
               label, (long) nz, (long) oz, (long) ndcz, (long) odcz,
               (long) na, (long) oa, n, hex, n > 120 ? "..." : "");
    }

    free(exact);
    return ok;
}


/*
 * Hand-written boundary inputs. Each is a case the generator might reach
 * only by chance; naming them here keeps the mutation controls stable.
 */
static const char *const  diff_hand[] = {
    "", ",", ",,,", " ", ";", "zstd;", "zstd; ", "zstd ;", "zstd;;q=1",
    "zstd;q=", "zstd;q=1.000", "zstd;q=0.0001", "zstd;q=2", "zstd;q",
    "zstd;x=1;q=0.5", "zstd;q=0.5;x=1", "zstd;q=0.5;q=1", "zstd;x;q=0.5",
    "zstd;x=\"a;b\";q=0.5", "zstd;x=\"a,b\";q=0.5", "zstd;x=\"a\\\"b\";q=0",
    "zstd;x=\"a\\,b\";q=0", "zstd;x=\"a\\;b\";q=0", "zstd;x=\"unterminated",
    "zstd;x=\"a\\", "zstd;x=\"", "zstd;x=\"\\\"", "gzip;x=\"a,zstd\"",
    "gzip;x=\"a, zstd;q=1\"", "gzip;\"a,zstd,b\"", "gzip;\"a,zstd\"=1",
    "gzip;x\"y=1,zstd", "gzip;x\"y=1,zstd\"", "zstd;x\"y=1", "zstd;x\"=1",
    "gzip;q=2 zstd", "gzip;q=1x,zstd", "gzip;q=1 x,zstd", "gzip;q=0.5\"a,zstd",
    "gzip;q=1.0000\"a,zstd\",br", "gzip;q=\"1\",zstd", "gzip;q= ,zstd",
    "gzip;q=1 \"a,zstd", "gzip;q ,zstd", "gzip;x ,zstd", "gzip;x=,zstd",
    "gzip;x=a\"b,zstd\"c,zstd", "gzip;=1,zstd", "gzip; =1,zstd",
    "zstd;Q=0.3", "zstd;q=1.", "zstd;q=0.", "zstd;q=.5", "zstd;q= 1",
    "zstd;q =1", "zstd;q=-1", "zstd; q=1 ", "zstd;\tq=1\t", "zstd\t;q=1",
    "*;q=0,zstd;x=\"a,b\"", "dcz;q=0.5,zstd", "*,dcz", "dcz;x=\"a\",*",
    "zstd\"x", "zstd \"x", "zstd x", "\"a,zstd \"", "\"zstd\"",
    "zstd;x=\xff\xfe;q=0.5", "zstd;q=0.5\xff", "zstd\xff;q=1",
    "zstd;\xff=1;q=0.5", "zstd;x=\"\xff,\";q=0.5", "zstd;q=0.5;\x80",
    "gzip;x=\"a\", zstd;q=0.5, br;q=1", "gzip;x=\"a\",zstd;q=0.5;y=\"b,c\"",
};

#define DIFF_NHAND  (sizeof(diff_hand) / sizeof(diff_hand[0]))
#define DIFF_CASES  100000


static void
case_differential_hand_written(void)
{
    size_t  i;
    int     bad = 0;

    for (i = 0; i < DIFF_NHAND; i++) {
        if (!diff_one((const uint8_t *) diff_hand[i], strlen(diff_hand[i]),
                      "differential/hand"))
        {
            bad++;
        }
    }

    /* embedded NUL: strlen() cannot express it, so build it by hand */
    if (!diff_one((const uint8_t *) "gzip;x=\0,zstd", 13, "differential/nul")) {
        bad++;
    }

    check(bad == 0, "differential: every hand-written boundary input agrees "
          "with the pre-single-pass parser");
}


static void
case_differential_generated(void)
{
    static uint8_t  buf[DIFF_MAXLEN];
    size_t          i, n, bad = 0, total = 0;

    for (i = 0; i < DIFF_CASES; i++) {
        char  label[48];

        n = diff_generate(buf, sizeof(buf));
        total += n;
        snprintf(label, sizeof(label), "differential/gen#%zu", i);

        if (!diff_one(buf, n, label)) {
            bad++;
            if (bad > 10) {
                printf("... more than 10 divergences, stopping\n");
                break;
            }
        }
    }

    printf("info differential: %d generated inputs, %zu bytes total\n",
           DIFF_CASES, total);
    check(bad == 0, "differential: 100000 generated inputs agree with the "
          "pre-single-pass parser (zstd weight, dcz weight, verdict)");
}


/*
 * Three named pins on the cursor contract, so a mutation that survives the
 * differential (it cannot -- but a pin is cheaper to read than a diff
 * dump) has a value-stating check as well.
 */
static void
case_single_pass_cursor_contract(void)
{
    /*
     * A DQUOTE inside a parameter NAME is the one input where the
     * single-pass cursor must fall back to a rescan from the ';': a
     * quote-aware walk from there swallows `"y=1,zstd` as one quoted
     * blob, so zstd is never advertised. A cursor left after the value
     * would let ",zstd" surface as a second element.
     */
    check(decide("gzip;x\"y=1,zstd") == NGX_DECLINED,
          "single-pass: DQUOTE inside a parameter name rescans from ';' "
          "(no phantom zstd after the quote)");

    /*
     * A malformed weight leaves the cursor on the offending byte; the
     * caller must still skip to the next top-level ',' rather than start
     * a new element there (which would read "zstd" as a fresh token).
     */
    check(decide("gzip;q=2 zstd") == NGX_DECLINED,
          "single-pass: malformed weight still skips the rest of the "
          "element (no phantom zstd after junk)");

    /* well-formed: the cursor lands on the ',' and the next element is
     * read exactly once. */
    check(weight_no_wildcard("gzip;x=\"a,b\";q=0.5, zstd;q=0.25", "zstd")
          == 250,
          "single-pass: cursor resumes at the top-level ',' after a quoted "
          "parameter value");
}


int
main(void)
{
    case_empty_header();
    case_explicit_zstd_no_params();
    case_explicit_zstd_q1();
    case_explicit_zstd_q0();
    case_explicit_zstd_fractional();
    case_zstd_q_exactly_zero_fraction();
    case_wildcard_only();
    case_wildcard_q0();
    case_other_coding_only();
    case_explicit_overrides_permissive_wildcard();
    case_explicit_overrides_restrictive_wildcard();
    case_case_insensitive_token();
    case_multiple_codings_with_zstd();
    case_stray_commas_and_ows();
    case_malformed_q_fourth_digit();
    case_malformed_q_missing_value();
    case_malformed_q_bare_param();
    case_quoted_param_hides_comma();
    case_quoted_name_position_not_a_token();
    case_duplicate_explicit_token_last_wins();
    case_end_of_buffer_no_trailing_nul_reliance();
    case_generic_weight_wildcard_not_allowed();
    case_skip_quoted_unterminated();
    case_nonq_param_is_skipped_trailing_q_honoured();
    case_nonq_param_quoted_value_delimiter_scan();

    case_fraction_empty_input();
    case_fraction_one_digit();
    case_fraction_two_digit();
    case_fraction_three_digit();
    case_fraction_four_digit_leaves_fourth_unconsumed();
    case_fraction_truncated_mid_walk();
    case_fraction_truncated_mid_walk_two_digits();
    case_fraction_non_digit_terminator_not_consumed();
    case_fraction_non_digit_terminator_at_start();
    case_fraction_exhaustive_three_digit();

    /* Chained Accept-Encoding field lines (RFC 9110 section 5.3). */
    case_chain_gzip_then_zstd();
    case_chain_zstd_then_gzip();
    case_chain_single_line_unchanged();
    case_chain_q0_first_line();
    case_chain_q0_second_line();
    case_chain_q0_then_q1_accepts();
    case_chain_q1_then_q0_stays_declined();
    case_chain_two_nonzero_weights();
    case_chain_wildcard_later_line();
    case_chain_wildcard_vs_explicit_q0();
    case_chain_wildcard_q0_later();
    case_chain_three_lines();
    case_chain_four_lines();
    case_chain_empty_line();
    case_chain_split_list();
    case_chain_dcz_second_line();
    case_chain_dcz_first_line();
    case_chain_dcz_q0_second_line();
    case_chain_dcz_q0_first_line();
    case_chain_dcz_q0_then_q1_accepts();
    case_chain_dcz_q1_then_q0_declines();
    case_chain_dcz_wildcard_never_matches();
    case_chain_dcz_three_lines();

    /* Single-pass parameter scan vs the pre-change parser. */
    case_differential_hand_written();
    case_differential_generated();
    case_single_pass_cursor_contract();

    printf("\n%d/%d checks passed\n", checks - failures, checks);
    return failures ? 1 : 0;
}
