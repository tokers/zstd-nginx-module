/*
 * Copyright (C) Alex Zhang
 * Copyright (C) 2026 Thijs Eilander
 *
 * Shared helpers used by both the filter module and the static module.
 * Included as a static inline header to avoid a separate compilation unit
 * while eliminating the duplication between the two modules.
 */

#ifndef NGX_HTTP_ZSTD_COMMON_H
#define NGX_HTTP_ZSTD_COMMON_H


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/*
 * Accept-Encoding parsing per RFC 9110 §12.5.3 (Accept-Encoding) and
 * §12.4.2 (quality values).
 *
 *   Accept-Encoding = #( codings [ weight ] )
 *   codings         = content-coding / "identity" / "*"
 *   weight          = OWS ";" OWS "q=" qvalue
 *   qvalue          = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )
 *
 * The two helpers below walk that grammar strictly bounded by ae->len:
 * every dereference is guarded against `end`, so they never rely on NUL
 * termination even when called with p == end (the libFuzzer target depends
 * on this).
 *
 * qvalues are parsed into integer milli-units (0..1000). The decision for
 * zstd considers both an explicit "zstd" coding and the "*" wildcard
 * (§12.5.3: "*" matches any coding not explicitly listed); an explicit
 * "zstd" token overrides the wildcard. Malformed weights (empty "q=", a
 * fourth decimal digit, trailing junk such as "q=1x", or "1.x" with x!=0)
 * make the element non-matching rather than silently defaulting to q=1.
 */


/*
 * If `p` points at a DQUOTE, consume the whole quoted-string (RFC 9110
 * §5.6.4: DQUOTE *( qdtext / quoted-pair ) DQUOTE) and return the position
 * just past the closing DQUOTE; otherwise return `p` unchanged. A
 * quoted-string may legitimately contain ';' or ',', so both delimiter
 * scanners below route through this helper to avoid mistaking an embedded
 * delimiter for a parameter or element boundary. Strictly bounded by `end`,
 * never NUL-reliant. Always advances past at least the opening DQUOTE when it
 * fires, so the caller's surrounding loop cannot stall.
 */
static u_char *
ngx_http_zstd_skip_quoted(u_char *p, const u_char *end)
{
    if (p >= end || *p != '"') {
        return p;
    }

    p++;    /* opening DQUOTE */

    while (p < end && *p != '"') {
        if (*p == '\\' && p + 1 < end) {
            p++;    /* skip the escaped octet of a quoted-pair */
        }
        p++;
    }

    if (p < end) {
        p++;    /* closing DQUOTE */
    }

    return p;
}


/*
 * Walk the up-to-three fractional digits of a "q=0.NNN" qvalue, starting
 * right after the '.'. Advances *p past each digit consumed and returns
 * the accumulated milli-units contribution (0..900, in multiples of 100,
 * 10 or 1 as digits are consumed) via the return value. Bounded on both
 * sides: the loop stops at `end`, and after three digits `scale` has hit
 * 0 so a fourth or later digit byte is left unconsumed for the caller's
 * trailing-junk check to reject. Pure digit-walk, no other qvalue state:
 * splitting it out of ngx_http_zstd_eval_qvalue() shrinks that function's
 * branching without changing what either side does.
 */
static ngx_int_t
ngx_http_zstd_parse_q_fraction(const u_char *end, u_char **p)
{
    /* ngx_int_t (not int) so each digit*weight product widens before the
     * add — avoids a theoretical int overflow CodeQL flags (the operands
     * are tiny in practice). */
    ngx_int_t  frac = 0;
    u_char    *q = *p;

    /*
     * RFC 9110's qvalue grammar permits at most three fractional digits
     * ("0" "." 0*3DIGIT), so the walk is fixed at three guarded steps
     * with literal weights 100/10/1 instead of a loop counting a
     * runtime `scale` down by dividing by 10 each iteration. Each step
     * is behaviour-identical to one loop iteration of the original: it
     * only fires if the previous step also fired (so a mismatch or
     * end-of-input at digit N leaves N-1..2 unconsumed, exactly as the
     * loop's own condition would stop it), and after the third digit
     * `q` is NOT advanced again -- a fourth or later digit byte is
     * deliberately left for the caller's trailing-junk check to reject,
     * the same contract the loop's `scale > 0` guard enforced.
     */
    if (q < end && *q >= '0' && *q <= '9') {
        frac += (*q - '0') * 100;
        q++;

        if (q < end && *q >= '0' && *q <= '9') {
            frac += (*q - '0') * 10;
            q++;

            if (q < end && *q >= '0' && *q <= '9') {
                frac += (*q - '0') * 1;
                q++;
            }
        }
    }

    *p = q;
    return frac;
}


/*
 * Evaluate the optional parameters of a coding token whose name has just
 * been consumed. `p` points at the ';' that introduces the parameters.
 * Returns the weight in milli-units (0..1000) — 1000 when no "q" parameter
 * is present — or -1 if any parameter is malformed (including a repeated
 * "q", which RFC 9110 §12.4.2 permits at most once). Strictly length-bounded
 * by ae->len.
 *
 * Single-pass cursor contract: `*pp` points at the ';' on entry and is
 * advanced to the resume position on return, so the caller never rescans
 * the parameter bytes. On success that is the next top-level ',' or end
 * (the trailing-junk check below guarantees it); on -1 it is the byte the
 * walk stopped on, from which the caller's quote-aware skip to the next
 * ',' yields exactly what a rescan from the ';' would. The one input that
 * breaks that equivalence is a DQUOTE inside a parameter NAME: the name
 * scan steps over it, whereas a quote-aware rescan from the ';' would open
 * a quoted-string there. For that (malformed, token grammar forbids it)
 * case `*pp` is left at the ';' so the caller's skip reproduces the
 * historical result byte for byte -- a rescan only on that input, not on
 * every parameterized element.
 */
static ngx_int_t
ngx_http_zstd_eval_qvalue(const ngx_str_t *ae, u_char **pp)
{
    u_char        *p = *pp;
    const u_char  *end = ae->data + ae->len;
    ngx_int_t      q = 1000;   /* no q parameter → q=1 */
    ngx_int_t      q_seen = 0; /* reject a second "q" parameter (RFC 9110) */
    ngx_int_t      quoted_name = 0; /* DQUOTE seen inside a parameter name */

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
            if (*p == '"') {
                quoted_name = 1;
            }
            p++;
        }
        nend = p;

        /*
         * RFC 9110 has no empty-parameter production, so "zstd;;q=1" is
         * malformed rather than "a skipped parameter followed by q=1".
         * Reject it instead of silently resolving the element to q=1.
         */
        if (nend == nstart) {
            goto malformed;
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
                    goto malformed;     /* repeated "q" parameter */
                }
                q_seen = 1;

                if (p >= end) {
                    goto malformed;     /* "q=" with no value */
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
                    goto malformed;     /* leading digit not 0 or 1 */
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
                    goto malformed;
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
                goto malformed;     /* "q" with no "=value" is malformed */
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
            goto malformed;
        }
    }

    goto done;

malformed:

    q = -1;

done:

    if (!quoted_name) {
        *pp = p;
    }

    return q;
}


/*
 * Generic weight lookup for one content coding in an Accept-Encoding
 * value. Returns the effective weight for `coding` in milli-units
 * (0..1000), or -1 when the header expresses no preference for it at
 * all. An explicit token always decides (even q=0, which then overrides
 * a permissive "*"); with no explicit token the "*" wildcard applies
 * only when `allow_wildcard` is set — RFC 9110 §12.5.3's "*" matches
 * any coding not explicitly listed, but a caller may legitimately
 * require an explicit opt-in (dcz does: only a dictionary-aware client
 * that actually holds the dictionary can decode a dcz response, so a
 * blanket "*" must not turn it on).
 *
 * This is the walker ngx_http_zstd_accept_encoding() has always been,
 * with the coding name parameterized; the zstd semantics are preserved
 * verbatim by the wrapper below (the fuzz differential oracle depends
 * on that).
 *
 * The _ex form additionally reports the two accumulated weights it had to
 * compute anyway: *explicit_q is the latest explicit `coding` token's
 * weight and *star_q_out the latest "*" weight, each -1 when that form is
 * absent from the value. The chain walker needs both to compose duplicate
 * field lines, and taking them from one pass keeps it from parsing the
 * same line a second time just to learn which of the two produced the
 * answer. Both out-params are mandatory; the return value is exactly the
 * precedence rule applied to them, so ngx_http_zstd_coding_weight() below
 * stays byte-for-byte the function the fuzz differential oracle asserts.
 */
static ngx_int_t
ngx_http_zstd_coding_weight_ex(const ngx_str_t *ae, const char *coding,
    size_t coding_len, ngx_uint_t allow_wildcard, ngx_int_t *explicit_q,
    ngx_int_t *star_q_out)
{
    u_char        *p   = ae->data;
    const u_char  *end = ae->data + ae->len;
    ngx_int_t      coding_q = -1; /* explicit `coding` weight, -1 = absent */
    ngx_int_t      star_q = -1;   /* "*" wildcard weight,      -1 = absent */

#ifdef NGX_HTTP_ZSTD_TEST_COUNT_CODING_WEIGHT
    ngx_http_zstd_test_coding_weight_calls++;
#endif

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
            q = ngx_http_zstd_eval_qvalue(ae, &p);
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
         * follow it, e.g. `gzip;x="a, zstd";q=1`). After a well-formed
         * parameter list this is a no-op: ngx_http_zstd_eval_qvalue() has
         * already advanced `p` to that comma. It still does real work for
         * a malformed element (p sits on the offending byte) and for a
         * DQUOTE inside a parameter name (p is still on the ';').
         */
        while (p < end && *p != ',') {
            if (*p == '"') {
                p = ngx_http_zstd_skip_quoted(p, end);
            } else {
                p++;
            }
        }
    }

    *explicit_q = coding_q;
    *star_q_out = star_q;

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


/*
 * Effective weight for `coding` in one Accept-Encoding field value, with
 * the per-form weights discarded. This is the signature the fuzz
 * differential and the extracted unit suite link against.
 */
static ngx_int_t
ngx_http_zstd_coding_weight(const ngx_str_t *ae, const char *coding,
    size_t coding_len, ngx_uint_t allow_wildcard)
{
    ngx_int_t  explicit_q, star_q;

    return ngx_http_zstd_coding_weight_ex(ae, coding, coding_len,
                                          allow_wildcard,
                                          &explicit_q, &star_q);
}


/*
 * Step to the next duplicate Accept-Encoding field line.
 *
 * nginx grew ngx_table_elt_t.next in 1.23.0 (the linked-list header
 * rework); that is the same version floor every other ->next use in this
 * module guards on -- see the `#if (nginx_version >= 1023000)` sites in
 * the filter and in ngx_http_zstd_push_header() below.
 *
 * On an older nginx the field does not exist. The request-level helper below
 * walks r->headers_in.headers there; this macro remains a single-field step
 * so the common chain walker is safe for callers with one field.
 */
#if (nginx_version >= 1023000)
#define NGX_HTTP_ZSTD_AE_NEXT(ae)  ((const ngx_table_elt_t *) (ae)->next)
#else
#define NGX_HTTP_ZSTD_AE_NEXT(ae)  ((const ngx_table_elt_t *) NULL)
#endif


/*
 * ngx_http_zstd_chain_coding_weight()
 *
 * Effective weight for `coding` across the WHOLE Accept-Encoding header
 * field, i.e. every duplicate field line nginx chained on ->next, not
 * just the first. Returns milli-units (0..1000), or -1 when the field
 * expresses no preference for `coding` at all. `ae` may be NULL (no
 * Accept-Encoding at all), which is -1.
 *
 * WHY THIS EXISTS. nginx does not reject a repeated Accept-Encoding
 * request header; it chains the extra field lines on ae->next. RFC 9110
 * section 5.3 makes a repeated list-valued field semantically identical to
 * the single field whose value is the lines joined in order with commas,
 * so
 *
 *     Accept-Encoding: gzip
 *     Accept-Encoding: zstd
 *
 * IS "gzip, zstd" and accepts zstd. Evaluating only ae->value read that
 * request as "gzip" and declined. The in-code justification used to be
 * parity with nginx's own gzip filter, but parity with a sibling module is
 * not the contract this module advertises: the README documents an
 * Accept-Encoding negotiation, and a client that split its codings across
 * two lines is entitled to the same answer it would have got from one.
 *
 * Duplicate coding values retain that received order: the latest explicit
 * token wins, just as it does within one field line. Thus `zstd;q=0` then
 * `zstd;q=1` accepts, while the reversed order declines. This keeps a
 * comma-joined set of lines equivalent to its single-field representation.
 *
 * The wildcard is accumulated the same way and stays subordinate to an
 * explicit token exactly as in the single-value parser: any explicit token
 * anywhere in the field decides, and "*" applies only when no line named
 * the coding explicitly. `allow_wildcard` has the same meaning as in
 * ngx_http_zstd_coding_weight() and is passed straight through.
 *
 * NOTE the two-level accumulation is deliberate and NOT a contradiction.
 * Within ONE field-line value, ngx_http_zstd_coding_weight() keeps its
 * existing last-wins behaviour for a repeated token, byte for byte — the
 * fuzz differential's independent reference oracle asserts exactly that
 * single-value decision, and changing it would be a behavioural drift the
 * fuzzer is entitled to fail on. This function composes those per-line
 * answers; it never reaches inside one.
 */
static ngx_inline ngx_int_t
ngx_http_zstd_chain_coding_weight(const ngx_table_elt_t *ae,
    const char *coding, size_t coding_len, ngx_uint_t allow_wildcard)
{
    ngx_int_t  coding_q = -1;   /* latest explicit token, -1 = absent */
    ngx_int_t  star_q = -1;     /* latest "*" wildcard, -1 = absent */

    for (/* void */; ae != NULL; ae = NGX_HTTP_ZSTD_AE_NEXT(ae)) {

        ngx_int_t  line_coding_q, line_star_q;

        /*
         * One pass per line. The single-value parser accumulates the
         * explicit and the wildcard weight separately anyway, so the _ex
         * form hands both back and this walker composes them directly.
         * The earlier shape asked the parser twice per line — once with
         * the wildcard suppressed to isolate the explicit weight, then
         * again to learn the effective one — which re-scanned every line
         * that named no explicit token, i.e. the common case.
         *
         * ngx_http_zstd_coding_weight() is unchanged as a symbol: it is
         * the fuzzed, extracted-into-the-unit-suite function, and it is
         * now the wrapper that drops these two out-params.
         */
        (void) ngx_http_zstd_coding_weight_ex(&ae->value, coding, coding_len,
                                              allow_wildcard,
                                              &line_coding_q, &line_star_q);

        if (line_coding_q >= 0) {
            /* Duplicate field lines are comma-joined in received order. */
            coding_q = line_coding_q;
            continue;
        }

        if (allow_wildcard && line_star_q >= 0) {
            star_q = line_star_q;
        }
    }

    /*
     * Same precedence as the single-value parser: an explicit token
     * anywhere in the field decides (even q=0, which then overrides a
     * permissive "*"); with no explicit token the wildcard applies if
     * present and permitted by the caller.
     */
    if (coding_q >= 0) {
        return coding_q;
    }
    if (allow_wildcard && star_q >= 0) {
        return star_q;
    }
    return -1;
}


/*
 * Effective weight across the request's complete Accept-Encoding field.
 * nginx before 1.23.0 does not link duplicate table elements through ->next:
 * accept_encoding names the first one and every later occurrence remains in
 * headers_in.headers. RFC 9110 section 5.3 still requires all occurrences to
 * be treated as one comma-joined field.
 */
static ngx_inline ngx_int_t
ngx_http_zstd_request_coding_weight(ngx_http_request_t *r, const char *coding,
    size_t coding_len, ngx_uint_t allow_wildcard)
{
#if (nginx_version >= 1023000)
    return ngx_http_zstd_chain_coding_weight(r->headers_in.accept_encoding,
                                              coding, coding_len,
                                              allow_wildcard);
#else
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *headers;
    ngx_int_t         coding_q, star_q, line_coding_q, line_star_q;

    coding_q = -1;
    star_q = -1;
    part = &r->headers_in.headers.part;
    headers = part->elts;

    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            headers = part->elts;
            i = 0;
        }

        if (headers[i].key.len != sizeof("Accept-Encoding") - 1
            || ngx_strncasecmp(headers[i].key.data,
                                (u_char *) "Accept-Encoding",
                                sizeof("Accept-Encoding") - 1) != 0)
        {
            continue;
        }

        (void) ngx_http_zstd_coding_weight_ex(&headers[i].value, coding,
                                              coding_len, allow_wildcard,
                                              &line_coding_q, &line_star_q);
        if (line_coding_q >= 0) {
            coding_q = line_coding_q;
            continue;
        }

        if (allow_wildcard && line_star_q >= 0) {
            star_q = line_star_q;
        }
    }

    if (coding_q >= 0) {
        return coding_q;
    }
    if (allow_wildcard && star_q >= 0) {
        return star_q;
    }
    return -1;
#endif
}


/*
 * zstd acceptance predicate over one Accept-Encoding value — the
 * original entry point, now a thin wrapper. Semantics are unchanged:
 * NGX_OK iff the effective weight for "zstd" (explicit token, else "*"
 * wildcard) is > 0. The fuzz harness's independent reference oracle
 * asserts exactly this decision, so any behavioural drift here is a
 * fuzz failure, not just a review nit.
 *
 * SINGLE VALUE ONLY. This evaluates one Accept-Encoding field line. The
 * request path does NOT call it -- ngx_http_zstd_accepts() evaluates the
 * complete request field via ngx_http_zstd_request_coding_weight() -- but
 * the fuzz target (ci/fuzz/fuzz_accept_encoding.c) and the unit suite
 * (ci/tests/unit/test_accept_encoding.c) both link this exact body as the
 * single-value entry point, and its differential oracle is written against
 * it. ngx_inline because no module TU references it any more and a plain
 * `static` would trip -Werror=unused-function in both of them, the same
 * reason ngx_http_zstd_ok() below is inline.
 */
static ngx_inline ngx_int_t
ngx_http_zstd_accept_encoding(const ngx_str_t *ae)
{
    ngx_int_t  q;

    q = ngx_http_zstd_coding_weight(ae, "zstd", sizeof("zstd") - 1, 1);

    return q > 0 ? NGX_OK : NGX_DECLINED;
}


/*
 * ngx_http_zstd_accepts()
 *
 * Side-effect-free acceptance predicate: NGX_OK iff this is a main request
 * whose client advertises acceptable zstd support (Accept-Encoding accepts
 * "zstd" with q > 0, via an explicit token or the "*" wildcard). Does NOT
 * touch r->gzip_tested / r->gzip_ok — callers that only need the decision
 * (e.g. the static module, which must not suppress a gzip_static fallback
 * before it even knows whether a .zst file exists) use this.
 */
static ngx_inline ngx_int_t
ngx_http_zstd_accepts(ngx_http_request_t *r)
{
    if (r != r->main) {
        return NGX_DECLINED;
    }

    /*
     * A "*" wildcard (one byte) can make zstd acceptable, so the old
     * "shorter than 'zstd'" fast-reject is no longer valid; an empty value
     * is still a decline (the walk below returns -1).
     *
     * The whole field is evaluated: linked duplicate lines on nginx >= 1.23,
     * and the complete headers list on older supported nginx. RFC 9110
     * section 5.3 makes them one comma-joined list.
     */
    return ngx_http_zstd_request_coding_weight(r, "zstd", sizeof("zstd") - 1, 1)
               > 0
               ? NGX_OK : NGX_DECLINED;
}


/*
 * ngx_http_zstd_ok()
 *
 * As ngx_http_zstd_accepts(), but additionally latches r->gzip_tested /
 * r->gzip_ok = 0 on a positive result, so a later gzip filter/handler
 * declines and does not double-compress a response we are about to encode as
 * zstd. Only the on-the-fly filter module uses this: it calls
 * ngx_http_zstd_ok() at the point it commits to compressing
 * (Content-Encoding: zstd is set immediately after), so latching gzip off
 * here is always followed by an actual zstd encoding — the latch never
 * strands a response with neither coding. The static module must NOT use
 * this (see ngx_http_zstd_accepts()).
 *
 * ngx_inline: only the filter TU calls this; the static TU includes the header
 * but uses ngx_http_zstd_accepts() instead, so a plain `static` definition
 * trips -Werror=unused-function there. An inline definition is exempt.
 */
static ngx_inline ngx_int_t
ngx_http_zstd_ok(ngx_http_request_t *r)
{
    if (ngx_http_zstd_accepts(r) != NGX_OK) {
        return NGX_DECLINED;
    }

    r->gzip_tested = 1;
    r->gzip_ok = 0;

    return NGX_OK;
}


/*
 * Push a response header with the given key and value. Handles the
 * nginx_version >= 1023000 guard that sets next=NULL to prevent linked-list
 * corruption on HTTP/1.1 responses. Both key and value are NUL-terminated
 * C string literals supplied by the caller.
 *
 * key/value are `const char *` PARAMETERS, not literals in this scope, so
 * ngx_str_set() must not be used here: that macro computes its length via
 * `sizeof(text) - 1`, which is only the string length when `text` is a
 * literal token at the macro's own call site. Applied to a `const char *`
 * parameter it instead yields sizeof(pointer) - 1 (7 on a 64-bit build) --
 * every pushed header key/value here was truncated/overrun to 7 bytes
 * regardless of the real string length, which silently broke every caller
 * of this helper. Use ngx_strlen() on the parameter instead.
 *
 * Returns NGX_OK on success, NGX_ERROR on allocation failure.
 */
static ngx_inline ngx_int_t
ngx_http_zstd_push_header(ngx_http_request_t *r, const char *key,
    const char *value)
{
    ngx_table_elt_t  *h;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
#if (nginx_version >= 1023000)
    h->next = NULL;
#endif
    h->key.len = ngx_strlen(key);
    h->key.data = (u_char *) key;
    h->value.len = ngx_strlen(value);
    h->value.data = (u_char *) value;

    return NGX_OK;
}


/*
 * token_b/has_b and token_c/has_c are each either both NULL or both
 * non-NULL, independently of each other (so a 1-, 2- or 3-token walk is
 * one function).
 */
static ngx_inline void
ngx_http_zstd_vary_find_tokens(ngx_http_request_t *r,
    const char *token_a, size_t token_a_len,
    const char *token_b, size_t token_b_len,
    const char *token_c, size_t token_c_len,
    ngx_uint_t *has_a, ngx_uint_t *has_b, ngx_uint_t *has_c)
{
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;

    *has_a = 0;
    if (has_b != NULL) {
        *has_b = 0;
    }
    if (has_c != NULL) {
        *has_c = 0;
    }

    for (part = &r->headers_out.headers.part, h = part->elts, i = 0;
         /* void */;
         i++)
    {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].hash == 0
            || h[i].key.len != sizeof("Vary") - 1
            || ngx_strncasecmp(h[i].key.data, (u_char *) "Vary",
                               sizeof("Vary") - 1) != 0)
        {
            continue;
        }

        {
            u_char  *end, *p, *start, *tok_end;

            p = h[i].value.data;
            end = p + h[i].value.len;

            while (p < end) {
                while (p < end && (*p == ' ' || *p == '\t' || *p == ',')) {
                    p++;
                }

                start = p;
                while (p < end && *p != ',') {
                    p++;
                }

                /*
                 * `p` is the untrimmed token end (the comma, or `end`);
                 * keep it so the tail advance below can reuse it instead
                 * of re-walking from the OWS-trimmed pointer to find the
                 * same comma again.
                 */
                tok_end = p;

                while (p > start && (p[-1] == ' ' || p[-1] == '\t')) {
                    p--;
                }

                if (!*has_a
                    && (size_t) (p - start) == token_a_len
                    && ngx_strncasecmp(start, (u_char *) token_a,
                                       token_a_len) == 0)
                {
                    *has_a = 1;
                }

                if (has_b != NULL && !*has_b
                    && (size_t) (p - start) == token_b_len
                    && ngx_strncasecmp(start, (u_char *) token_b,
                                       token_b_len) == 0)
                {
                    *has_b = 1;
                }

                if (has_c != NULL && !*has_c
                    && (size_t) (p - start) == token_c_len
                    && ngx_strncasecmp(start, (u_char *) token_c,
                                       token_c_len) == 0)
                {
                    *has_c = 1;
                }

                if (*has_a && (has_b == NULL || *has_b)
                             && (has_c == NULL || *has_c))
                {
                    return;
                }

                p = tok_end;
            }
        }
    }
}


static ngx_inline ngx_uint_t
ngx_http_zstd_vary_has_token(ngx_http_request_t *r, const char *token,
    size_t token_len)
{
    ngx_uint_t  found;

    ngx_http_zstd_vary_find_tokens(r, token, token_len, NULL, 0, NULL, 0,
                                   &found, NULL, NULL);

    return found;
}


/*
 * Add the two request-header dimensions that can select a dcz response.
 * The static content handler and the response filter can both reach this
 * helper on one request. Detect tokens across every active Vary field, so
 * repeated calls and fields flattened or reordered by another filter remain
 * duplicate-free.
 *
 * The two tokens are looked up together in a single header-list walk
 * (ngx_http_zstd_vary_find_tokens()) rather than as two independent
 * calls to ngx_http_zstd_vary_has_token() -- the two lookups are always
 * wanted together here, so paying for the walk and the per-line
 * comma-token scan twice was redundant.
 */
static ngx_inline ngx_int_t
ngx_http_zstd_vary_dcz(ngx_http_request_t *r)
{
    ngx_uint_t  has_available_dictionary, has_sec_fetch_site;

    ngx_http_zstd_vary_find_tokens(
        r, "Available-Dictionary", sizeof("Available-Dictionary") - 1,
        "Sec-Fetch-Site", sizeof("Sec-Fetch-Site") - 1,
        NULL, 0,
        &has_available_dictionary, &has_sec_fetch_site, NULL);

    if (has_available_dictionary && has_sec_fetch_site) {
        return NGX_OK;
    }

    if (has_available_dictionary) {
        return ngx_http_zstd_push_header(r, "Vary", "Sec-Fetch-Site");
    }

    if (has_sec_fetch_site) {
        return ngx_http_zstd_push_header(r, "Vary", "Available-Dictionary");
    }

    return ngx_http_zstd_push_header(
        r, "Vary", "Available-Dictionary, Sec-Fetch-Site");
}


/*
 * ngx_http_zstd_vary_accept_encoding()
 *
 * Make "Vary: Accept-Encoding" safe BY CONSTRUCTION on any response
 * whose representation depends on Accept-Encoding, instead of leaving
 * it to the operator's "gzip_vary" directive.
 *
 * The hazard this closes: r->gzip_vary alone is only a REQUEST for the
 * header. ngx_http_header_filter_module honours it solely when
 * clcf->gzip_vary is on, and otherwise clears the flag outright
 * (ngx_http_header_filter_module.c: "if (r->gzip_vary) { if
 * (clcf->gzip_vary) ... else r->gzip_vary = 0; }"). So under the
 * default "gzip_vary off" the module negotiated on Accept-Encoding and
 * then shipped a response that did not say so — and a shared cache
 * stored the zstd representation under a key a client sending no
 * "Accept-Encoding: zstd" would hit, handing it a body it cannot
 * decode. That correctness property used to belong to a directive this
 * module does not own; now it does not.
 *
 * DUPLICATE-SAFE, which is the whole subtlety. We must not simply push
 * a header line unconditionally: when clcf->gzip_vary IS on, nginx
 * emits its own "Vary: Accept-Encoding" from r->gzip_vary and we would
 * produce two identical field lines. Caches union all Vary fields so
 * the result would still be semantically correct, but a doubled field
 * is sloppy and strict intermediaries have been known to object. The
 * two emitters are mutually exclusive by construction:
 *
 *   clcf->gzip_vary on  -> set r->gzip_vary, push nothing (nginx emits)
 *   clcf->gzip_vary off -> push our own line (nginx emits nothing,
 *                          having cleared r->gzip_vary)
 *
 * Exactly one "Vary: Accept-Encoding" line in both states, verified as
 * a proxy-cache matrix in CI. r->gzip_vary is set in BOTH branches,
 * because other modules read the flag — notably
 * ngx_http_compression_vary_filter_module, which keys on it alone and
 * flattens the Vary fields it finds, so our own line is folded rather
 * than doubled. That is precisely why emitting a real header is
 * compatible with that module where relying on its default-off
 * directive was not.
 *
 * Repeated calls are safe because the response-header scan above makes
 * this helper idempotent. Call it only on a path that is genuinely
 * Accept-Encoding-dependent. "zstd_static always" normally does not call
 * it because that mode ignores Accept-Encoding; the explicit dictionary
 * bypass is the exception, since its routing predicate reads that field.
 *
 * Returns NGX_OK, or NGX_ERROR when the header-list allocation fails.
 *
 * ngx_inline for the same reason as the helpers above: this header is
 * included by TUs that never call it (the fuzz harness), and a plain
 * `static` definition trips -Werror=unused-function there.
 */
static ngx_inline ngx_int_t
ngx_http_zstd_vary_accept_encoding(ngx_http_request_t *r)
{
    ngx_http_core_loc_conf_t  *clcf;

    r->gzip_vary = 1;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (clcf != NULL && clcf->gzip_vary) {
        /* nginx's header filter emits the line from r->gzip_vary */
        return NGX_OK;
    }

    if (ngx_http_zstd_vary_has_token(
            r, "Accept-Encoding", sizeof("Accept-Encoding") - 1))
    {
        return NGX_OK;
    }

    return ngx_http_zstd_push_header(r, "Vary", "Accept-Encoding");
}


/*
 * ngx_http_zstd_vary_ae_dcz()
 *
 * Fused replacement for the ngx_http_zstd_vary_accept_encoding() +
 * ngx_http_zstd_vary_dcz() pair at call sites that always want both.
 * The static module's dict_bypass path has that shape; the filter module's
 * intervening bypass return deliberately keeps the helpers separate.
 * Both original helpers walk r->headers_out.headers once via
 * ngx_http_zstd_vary_find_tokens() and comma-split every Vary
 * value they find; calling them back to back pays for that walk and
 * per-line token scan twice. This helper does it once, for all three
 * tokens ("Accept-Encoding", "Available-Dictionary", "Sec-Fetch-Site"),
 * then pushes exactly the header lines the two original calls would have
 * pushed -- same duplicate-safety, same push shapes, same
 * cache-correctness reasoning (RFC 9842 SS8.3 dictionary/origin binding,
 * the shared-cache poisoning argument in
 * ngx_http_zstd_vary_accept_encoding()'s comment above and in
 * ngx_http_zstd_vary_dcz()'s comment). See both for the full rationale;
 * this comment only covers what fusing changes.
 *
 * `want_dcz` gates the Available-Dictionary/Sec-Fetch-Site half exactly
 * as the callers' own "any dcz dictionaries configured?" guard does
 * today -- pass 0 from a location with no dcz_dicts configured so it
 * does not start emitting Vary tokens for a negotiation that location
 * never performs. Passing the guard in, rather than moving it here,
 * keeps that decision at the call site where the configuration lives.
 *
 * r->gzip_vary is set unconditionally, before any return, exactly as in
 * ngx_http_zstd_vary_accept_encoding() -- other modules (notably
 * ngx_http_compression_vary_filter_module) read the flag regardless of
 * whether this call ends up pushing a header line itself.
 *
 * Caller ordering requirement: run this AFTER any header line the
 * caller itself pushes onto r->headers_out.headers that should count as
 * "already present" to the walk (e.g. filter_module's zstd_bypass_vary
 * push) -- the walk only sees lines already in the list when it starts.
 *
 * Returns NGX_OK, or NGX_ERROR when a header-list allocation fails.
 *
 * ngx_inline for the same reason as the helpers above: this header is
 * included by TUs that never call it (the fuzz harness), and a plain
 * `static` definition trips -Werror=unused-function there.
 */
static ngx_inline ngx_int_t
ngx_http_zstd_vary_ae_dcz(ngx_http_request_t *r, ngx_uint_t want_dcz)
{
    ngx_http_core_loc_conf_t  *clcf;
    ngx_uint_t                 has_ae, has_available_dictionary,
                                has_sec_fetch_site;
    ngx_uint_t                 need_ae;

    r->gzip_vary = 1;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    need_ae = (clcf == NULL || !clcf->gzip_vary);

    if (!need_ae && !want_dcz) {
        return NGX_OK;
    }

    if (need_ae) {
        ngx_http_zstd_vary_find_tokens(
            r,
            "Accept-Encoding", sizeof("Accept-Encoding") - 1,
            want_dcz ? "Available-Dictionary" : NULL,
            want_dcz ? sizeof("Available-Dictionary") - 1 : 0,
            want_dcz ? "Sec-Fetch-Site" : NULL,
            want_dcz ? sizeof("Sec-Fetch-Site") - 1 : 0,
            &has_ae,
            want_dcz ? &has_available_dictionary : NULL,
            want_dcz ? &has_sec_fetch_site : NULL);

    } else {
        has_ae = 1;
        ngx_http_zstd_vary_find_tokens(
            r,
            "Available-Dictionary", sizeof("Available-Dictionary") - 1,
            "Sec-Fetch-Site", sizeof("Sec-Fetch-Site") - 1,
            NULL, 0,
            &has_available_dictionary, &has_sec_fetch_site, NULL);
    }

    if (need_ae && !has_ae) {
        if (ngx_http_zstd_push_header(r, "Vary", "Accept-Encoding")
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    if (!want_dcz) {
        return NGX_OK;
    }

    if (has_available_dictionary && has_sec_fetch_site) {
        return NGX_OK;
    }

    if (has_available_dictionary) {
        return ngx_http_zstd_push_header(r, "Vary", "Sec-Fetch-Site");
    }

    if (has_sec_fetch_site) {
        return ngx_http_zstd_push_header(r, "Vary", "Available-Dictionary");
    }

    return ngx_http_zstd_push_header(
        r, "Vary", "Available-Dictionary, Sec-Fetch-Site");
}


#endif /* NGX_HTTP_ZSTD_COMMON_H */
