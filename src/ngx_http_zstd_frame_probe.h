/*
 * Copyright (C) 2026 Thijs Eilander
 *
 * THE authoritative copy of the .zst frame-header probe (#270): the
 * verdict set, the RFC 8878 window cap, the bounded skippable-walk
 * limit, ngx_http_zstd_static_probe_frame() and
 * ngx_http_zstd_static_probe_reuse(). Pure arithmetic -- no I/O, no
 * logging, no allocation, no request state -- so every consumer
 * (the static module, the unit fixtures, and the compression
 * branch's static module) includes THIS file instead of carrying a
 * synchronized copy or sed-extracting the body.
 *
 * CONSUMER CONTRACT. Inside nginx, include after the nginx headers
 * and everything below resolves. Outside nginx (shims like the unit
 * fixture's), provide before including:
 *     typedef intptr_t   ngx_int_t;
 *     typedef uintptr_t  ngx_uint_t;
 *     typedef unsigned char  u_char;
 *     #define ngx_memcpy  memcpy
 * ngx_inline defaults to plain inline when nginx has not defined it.
 *
 * The format constants are RFC-frozen and self-defined under #ifndef:
 * a consumer that included <zstd.h> first keeps libzstd's identical
 * spellings, and a consumer with no libzstd at all (the compression
 * branch's dependency-free static module, the shims) needs none.
 */

#ifndef NGX_HTTP_ZSTD_FRAME_PROBE_H
#define NGX_HTTP_ZSTD_FRAME_PROBE_H

#include <stddef.h>
#include <stdint.h>
#ifndef NGX_WIN32
#include <sys/types.h>   /* off_t, ssize_t for probe_reuse() */
#endif

#ifndef ngx_inline
#define ngx_inline  inline
#endif

/* From <zstd.h>, stable since 0.8.0; values frozen by RFC 8878. */
#ifndef ZSTD_MAGICNUMBER
#define ZSTD_MAGICNUMBER             0xFD2FB528U
#endif
#ifndef ZSTD_MAGIC_SKIPPABLE_START
#define ZSTD_MAGIC_SKIPPABLE_START   0x184D2A50U
#endif
#ifndef ZSTD_MAGIC_SKIPPABLE_MASK
#define ZSTD_MAGIC_SKIPPABLE_MASK    0xFFFFFFF0U
#endif

/*
 * The largest decompression window a served .zst frame may declare:
 * 8 MB, the RFC 8878 §3.1.1.1.2 recommended decoder limit, which web
 * clients enforce for Content-Encoding: zstd — Firefox and Chromium
 * reject any frame declaring more WITHOUT decoding a byte
 * (NS_ERROR_INVALID_CONTENT_ENCODING / ERR_CONTENT_DECODING_FAILED).
 * The trap that makes this worth checking at serve time: streaming
 * encoders that were not told the input size stamp the LEVEL's default
 * window into every frame header (a 93 KB asset compressed by a
 * Node-based build pipeline can declare 128 MB), so the file decodes
 * fine with the zstd CLI yet fails in every browser. Matches the
 * filter module's dcz window cap, which exists for the same client
 * guarantee.
 *
 * Changing this value means editing operator-visible prose too: the
 * NGX_HTTP_ZSTD_STATIC_FRAME_WINDOW_BIG log message spells out both
 * "8 MB" and the equivalent "window log <= 23" in words. Neither is
 * derived from this constant, so both go stale silently.
 */
#define NGX_HTTP_ZSTD_STATIC_MAX_WINDOW  (8 * 1024 * 1024)


/*
 * Verdicts from ngx_http_zstd_static_probe_frame(). The caller maps each
 * to the log line and return code the inlined probe used to emit, so the
 * split changes no observable behaviour — only where the arithmetic
 * lives.
 */
#define NGX_HTTP_ZSTD_STATIC_FRAME_OK          0
#define NGX_HTTP_ZSTD_STATIC_FRAME_NOT_ZSTD    1
#define NGX_HTTP_ZSTD_STATIC_FRAME_TRUNCATED   2
#define NGX_HTTP_ZSTD_STATIC_FRAME_WINDOW_BIG  3
#define NGX_HTTP_ZSTD_STATIC_FRAME_SKIP        4
#define NGX_HTTP_ZSTD_STATIC_FRAME_RESERVED    5

/*
 * How many leading skippable frames the caller's walk (in the handler,
 * below) will follow before giving up and declining. A dcz-style prefix
 * (see README "Standards-based dictionary compression") is exactly ONE
 * skippable frame — the 40-byte SHA-256 header — ahead of the real
 * payload frame, so 4 is generous headroom for that shape plus the odd
 * extra marker frame, while still bounding the walk to a handful of
 * pread(2) calls: an attacker cannot turn this into an unbounded scan
 * by chaining skippable frames, because each one past the bound is a
 * hard decline, not a longer search.
 */
#define NGX_HTTP_ZSTD_STATIC_MAX_SKIP_FRAMES   4


/*
 * Pure frame-header probe: decides whether the leading frame of a .zst
 * file may be served, given the first `n` bytes read from offset 0.
 *
 * Reads at most 18 bytes of `hdr` (magic(4) + descriptor(1) + dictionary
 * id(<=4) + content size(<=8)) and NEVER reads past `n`; every layout
 * path checks it got the bytes that layout requires before indexing
 * them. `n` is the byte count the caller's pread(2) actually returned
 * and is >= 4 by contract — the caller rejects a shorter read (and a
 * file smaller than 4 bytes) before calling, because those two cases
 * carry different log lines.
 *
 * On NGX_HTTP_ZSTD_STATIC_FRAME_WINDOW_BIG the declared window is
 * stored through `window` for the caller's error message. On
 * NGX_HTTP_ZSTD_STATIC_FRAME_SKIP the skippable frame's declared
 * 4-byte little-endian skip length (RFC 8878 §3.2) is stored through
 * `window` instead — same out-param, different unit, always read
 * against the matching verdict so there is no ambiguity. `window` is
 * untouched on every other verdict.
 *
 * No I/O, no logging, no allocation, no request state: this is the
 * arithmetic only, so ci/tests/unit/ can state its boundaries directly
 * (a short file, an exact-18-byte file, a valid frame, a bad magic)
 * without standing up an nginx.
 */
static ngx_inline ngx_int_t
ngx_http_zstd_static_probe_frame(const u_char *hdr, size_t n, uint64_t *window)
{
    uint32_t    mw;
    uint64_t    w;
    ngx_uint_t  fhd, fcs_size, off;

#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    ngx_uint_t  i;
#endif

    static const ngx_uint_t  did_len[4] = { 0, 1, 2, 4 };

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    ngx_memcpy(&mw, hdr, sizeof(uint32_t));
#else
    mw = ((uint32_t) hdr[0])
       | ((uint32_t) hdr[1] << 8)
       | ((uint32_t) hdr[2] << 16)
       | ((uint32_t) hdr[3] << 24);
#endif

    if (mw != ZSTD_MAGICNUMBER
        && (mw & ZSTD_MAGIC_SKIPPABLE_MASK) != ZSTD_MAGIC_SKIPPABLE_START)
    {
        return NGX_HTTP_ZSTD_STATIC_FRAME_NOT_ZSTD;
    }

    /*
     * Skippable frame (RFC 8878 §3.2): magic(4) + Frame_Size(4, little-
     * endian) + Frame_Size bytes of opaque payload to skip. The
     * declared window guarantee this probe exists for does not apply
     * to a skippable frame directly — there is no window here, only a
     * length to jump — so the caller does not get to serve on this
     * verdict alone. It must resolve the skip, bounded, and probe
     * whatever frame follows: an attacker-controlled skippable prefix
     * must not be a way to dodge the window check on the frame that
     * actually gets decoded (that was the bug: unconditionally OK-ing
     * every skippable magic let a one-byte-longer file bypass the 8 MB
     * guard entirely). TRUNCATED here, same as a regular frame, means
     * "not enough bytes to decide" — the caller's fail-closed path is
     * identical either way.
     */
    if (mw != ZSTD_MAGICNUMBER) {
        if (n < 8) {
            return NGX_HTTP_ZSTD_STATIC_FRAME_TRUNCATED;
        }

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        {
            uint32_t  skip_size;

            ngx_memcpy(&skip_size, hdr + 4, sizeof(uint32_t));
            *window = skip_size;
        }
#else
        *window = ((uint64_t) hdr[4])
                | ((uint64_t) hdr[5] << 8)
                | ((uint64_t) hdr[6] << 16)
                | ((uint64_t) hdr[7] << 24);
#endif

        return NGX_HTTP_ZSTD_STATIC_FRAME_SKIP;
    }

    /*
     * Declared-window check (RFC 8878 §3.1.1.1) on regular frames —
     * see NGX_HTTP_ZSTD_STATIC_MAX_WINDOW for why: a frame declaring
     * more than 8 MB is rejected by every browser before decoding, so
     * serving it produces a page-breaking decode error that curl and
     * the zstd CLI do not reproduce. Declining keeps the site working
     * (the zstd filter, gzip_static or identity takes over) and puts
     * the actionable cause in the error log.
     *
     * The check covers the LEADING regular frame reached after
     * resolving any leading skippable frames (bounded, see the
     * caller). In a concatenation of regular frames only the first is
     * inspected: a regular frame's header does not declare its
     * compressed length, so walking the sequence would mean decoding
     * every block header in every frame — unbounded I/O for a
     * serve-time guard. Multi-regular-frame .zst web assets are
     * pathological (no common tooling emits them); the README
     * documents that scope.
     */

    if (n < 5) {
        return NGX_HTTP_ZSTD_STATIC_FRAME_TRUNCATED;
    }

    fhd = hdr[4];

    if (fhd & 0x08) {
        return NGX_HTTP_ZSTD_STATIC_FRAME_RESERVED;
    }

    if (!(fhd & 0x20)) {
        /* No Single_Segment flag: Window_Descriptor follows. */
        if (n < 6) {
            return NGX_HTTP_ZSTD_STATIC_FRAME_TRUNCATED;
        }

        w = (uint64_t) 1 << (10 + (hdr[5] >> 3));
        w += (w >> 3) * (hdr[5] & 7);

    } else {
        /*
         * Single_Segment: no Window_Descriptor; the window is the
         * frame content size, read from behind the optional dictionary
         * id. Frame_Content_Size_flag 0 means a 1-byte field here (the
         * flag only means "absent" when Single_Segment is unset).
         */
        fcs_size = (fhd >> 6) ? ((ngx_uint_t) 1 << (fhd >> 6)) : 1;
        off = 5 + did_len[fhd & 3];

        if (n < off + fcs_size) {
            return NGX_HTTP_ZSTD_STATIC_FRAME_TRUNCATED;
        }

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        switch (fcs_size) {
        case 1:
            w = hdr[off];
            break;
        case 2:
            {
                uint16_t  value;

                ngx_memcpy(&value, hdr + off, sizeof(uint16_t));
                w = value;
            }
            break;
        case 4:
            {
                uint32_t  value;

                ngx_memcpy(&value, hdr + off, sizeof(uint32_t));
                w = value;
            }
            break;
        default:
            ngx_memcpy(&w, hdr + off, sizeof(uint64_t));
            break;
        }
#else
        w = 0;
        for (i = 0; i < fcs_size; i++) {
            w |= (uint64_t) hdr[off + i] << (8 * i);
        }
#endif

        if (fcs_size == 2) {
            w += 256;  /* RFC 8878: 2-byte field is offset */
        }
    }

    if (w > NGX_HTTP_ZSTD_STATIC_MAX_WINDOW) {
        *window = w;
        return NGX_HTTP_ZSTD_STATIC_FRAME_WINDOW_BIG;
    }

    return NGX_HTTP_ZSTD_STATIC_FRAME_OK;
}


static ngx_inline ngx_uint_t
ngx_http_zstd_static_probe_reuse(off_t pos, off_t have_base, ssize_t n,
    size_t need, size_t *frame_off, off_t *base)
{
    uint64_t  offset;

    if (n <= 0 || pos < have_base) {
        return 0;
    }

    offset = (uint64_t) (pos - have_base);

    if (offset > (uint64_t) n || (uint64_t) n - offset < need) {
        return 0;
    }

    *frame_off = (size_t) offset;
    *base = have_base;

    return 1;
}


#endif /* NGX_HTTP_ZSTD_FRAME_PROBE_H */
