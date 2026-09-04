/*
 * Copyright (C) 2026 Thijs Eilander
 *
 * THE authoritative copy of the Cache-Control no-transform detection
 * (RFC 9110 section 7.7 / RFC 9111 section 5.2.2.6): the quote-aware
 * directive-segment walk (#274), the '=' directive-name cut (#254),
 * and the whole-headers_out-list check (#251). Detection is
 * deliberately list-wide rather than reading the parsed
 * headers_out.cache_control chain: only some producers wire that
 * chain, and a Cache-Control pushed straight onto the list by a
 * module or an add_header would be invisible there.
 *
 * Extracted (#270): the compression branch's chassis and the brotli
 * hardened fork each carried a synchronized transplant of this exact
 * logic, and #251 and then #274 were each hand-mirrored into every
 * copy within days of merging. A consumer includes THIS file instead.
 *
 * CONSUMER CONTRACT. Include after the nginx headers; everything here
 * resolves against ngx_core/ngx_http types (the detection reads the
 * live headers_out list, so unlike ngx_http_zstd_frame_probe.h there
 * is no nginx-free consumer to shim for). ngx_inline keeps a consumer
 * that calls only part of the family warning-clean. The function
 * bodies are the filter module's, moved verbatim.
 */

#ifndef NGX_HTTP_ZSTD_CACHE_CONTROL_H
#define NGX_HTTP_ZSTD_CACHE_CONTROL_H


/*
 * Single-pass replacement for the former two-scan walk (find the
 * comma-terminated, quote-aware directive end; then re-walk start..end
 * looking for ';' or '='): this now finds the directive-NAME cut
 * (first unquoted ';' or '=') and the comma-terminated segment end in
 * the same left-to-right scan. Quotes still have to be tracked for the
 * whole segment (a ';' or '=' inside a quoted parameter value must not
 * cut the name, and a ',' inside one must not end the directive), so
 * the scan does not stop at the first ';'/'=' — it keeps going, inside
 * quotes as before, purely to find the segment's real end for the
 * caller's next iteration, while remembering the first '='/';' cut
 * position (if any) the moment it is seen outside quotes.
 */
static ngx_inline u_char *
ngx_http_zstd_cache_control_directive_end(u_char *p, u_char *last,
    u_char **name_end)
{
    ngx_uint_t  cut_seen;

    cut_seen = 0;

    while (p < last) {
        if (*p == '"') {
            p++;

            while (p < last && *p != '"') {
                if (*p == '\\' && p + 1 < last) {
                    p++;
                }
                p++;
            }

            if (p < last) {
                p++;
            }

        } else if (*p == ',') {
            break;

        } else if (!cut_seen && (*p == ';' || *p == '=')) {
            *name_end = p;
            cut_seen = 1;
            p++;

        } else {
            p++;
        }
    }

    if (!cut_seen) {
        *name_end = p;
    }

    return p;
}


static ngx_inline ngx_int_t
ngx_http_zstd_cache_control_value_no_transform(ngx_table_elt_t *cc)
{
    u_char  *p, *last, *start, *end, *directive_end, *name_end;

    if (cc->value.len == 0) {
        return 0;
    }

    p = cc->value.data;
    last = p + cc->value.len;

    while (p < last) {
        start = p;
        while (start < last && (*start == ' ' || *start == '\t')) {
            start++;
        }

        /*
         * Cut at '=' as well as ';': the compared token is then the
         * directive NAME, so "no-transform=arg" -- malformed, since the
         * directive defines no argument (RFC 9111 §5.2.2.6), but clear
         * in intent -- is honored rather than transformed. The quoted
         * parameter-value control is unaffected: extension="no-transform"
         * cuts to "extension" and still does not match.
         */
        directive_end = ngx_http_zstd_cache_control_directive_end(start, last,
                                                                    &name_end);

        end = name_end;

        while (end > start && (end[-1] == ' ' || end[-1] == '\t')) {
            end--;
        }

        if ((size_t) (end - start) == sizeof("no-transform") - 1
            && ngx_strncasecmp(start, (u_char *) "no-transform",
                               sizeof("no-transform") - 1) == 0)
        {
            return 1;
        }

        p = directive_end;
        if (p < last) {
            p++;
        }
    }

    return 0;
}


static ngx_inline ngx_int_t
ngx_http_zstd_cache_control_no_transform(ngx_http_request_t *r)
{
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;

    part = &r->headers_out.headers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].hash == 0 || h[i].key.len != sizeof("Cache-Control") - 1) {
            continue;
        }

        if (ngx_strncasecmp(h[i].key.data, (u_char *) "Cache-Control",
                            sizeof("Cache-Control") - 1) == 0
            && ngx_http_zstd_cache_control_value_no_transform(&h[i]))
        {
            return 1;
        }
    }

    return 0;
}


#endif /* NGX_HTTP_ZSTD_CACHE_CONTROL_H */
