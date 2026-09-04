/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit tests for the .zst frame-header probe
 * (src/ngx_http_zstd_frame_probe.h: ngx_http_zstd_static_probe_frame()).
 *
 * WHY THIS EXISTS ALONGSIDE ci/t/01-static.t
 *
 *   ci/t/01-static.t   drives the probe through a live nginx serving real
 *                      files from ci/t/suite/. It proves the probe is wired
 *                      into the request path and that a declined file falls
 *                      back correctly -- but every boundary it wants to
 *                      reach has to be reached by materialising a file on
 *                      disk with exactly the right bytes, and a probe
 *                      verdict is only observable through the resulting
 *                      status code plus an error-log line.
 *   this file          states the verdict directly, at named byte
 *                      boundaries, for buffers the on-disk fixtures cannot
 *                      conveniently express (a 4-byte file, an exactly-18-
 *                      byte file, a Single_Segment header whose content-size
 *                      field is one byte short of the buffer), with no
 *                      nginx process and no filesystem, in well under a
 *                      second.
 *
 * The probe is deliberately PURE -- no I/O, no logging, no pool, no
 * request -- precisely so this layer can exist. The handler keeps the
 * pread(2), the directio alignment and every ngx_log_error() call; this
 * function is the arithmetic over the bytes that read returned. That split
 * is what makes the bounds below directly assertable: an off-by-one in the
 * "did I get enough bytes for this layout" checks is the entire risk in
 * this code, and it is invisible from an end-to-end test that only ever
 * feeds it complete frames.
 *
 * Like ci/tests/unit/test_accept_encoding.c this does NOT re-implement the
 * function: it includes src/ngx_http_zstd_frame_probe.h directly (#270),
 * so this binary always links the SHIPPED probe -- the header IS the
 * production code, with no extraction step left to drift or skip.
 *
 * Extend: add a case_*() function and one line in main().
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef intptr_t       ngx_int_t;
typedef uintptr_t      ngx_uint_t;
typedef unsigned char  u_char;

#define ngx_memcpy  memcpy

/*
 * Included by RELATIVE path, not via -I, for the same reason
 * test_accept_encoding.c does: a static analyser invoked from anywhere
 * must be able to resolve it. An analyser that cannot resolve an include
 * SKIPS THE WHOLE TRANSLATION UNIT and reports no findings, which is
 * indistinguishable from a clean result. The header self-defines the
 * RFC-frozen constants and the verdict set, so the mirrored copies this
 * shim used to carry are gone -- one authoritative spelling (#270).
 */
#include "../../../src/ngx_http_zstd_frame_probe.h"


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


/*
 * Poisoned, deliberately unaligned probe buffer: 18 usable bytes preceded
 * and followed by a guard region of 0xA5. The backing array is uint64_t-
 * aligned and the one-byte leading guard offsets every probe address. A read
 * past either end that happens to land on a guard
 * byte changes the verdict (0xA5A5A5A5 is neither magic), and the trailing
 * guard is what would absorb an off-by-one in the "enough bytes for this
 * layout" checks -- so a mutant that reads hdr[n] instead of stopping is
 * reading a defined, wrong value rather than heap garbage that might
 * happen to be correct.
 */
#define GUARD  1

static _Alignas(uint64_t) u_char  buf[GUARD + 18 + GUARD];


static const u_char *
frame(const u_char *bytes, size_t len)
{
    memset(buf, 0xA5, sizeof(buf));
    if (len) {
        memcpy(buf + GUARD, bytes, len);
    }
    return buf + GUARD;
}


static ngx_int_t
probe(const u_char *bytes, size_t len, uint64_t *window)
{
    *window = 0;
    return ngx_http_zstd_static_probe_frame(frame(bytes, len), len, window);
}


/* Little-endian ZSTD_MAGICNUMBER, the leading 4 bytes of a regular frame. */
#define MAGIC  0x28, 0xB5, 0x2F, 0xFD


/*
 * A file shorter than the 18-byte probe buffer: only `n` bytes are valid
 * and the probe must never look past them. Here n == 4 -- a valid magic
 * and nothing else. A regular frame needs at least a Frame_Header_
 * Descriptor at hdr[4], which is not present, so the verdict is TRUNCATED
 * and NOT a window decision made from the guard byte.
 */
static void
case_shorter_than_probe_buffer(void)
{
    static const u_char  f[] = { MAGIC };
    uint64_t             w;

    check(probe(f, sizeof(f), &w) == NGX_HTTP_ZSTD_STATIC_FRAME_TRUNCATED,
          "a 4-byte file (magic only, no descriptor) is TRUNCATED, not "
          "parsed from bytes past the read");

    /*
     * n == 5: descriptor present, Single_Segment clear, so a
     * Window_Descriptor is required at hdr[5] and is past the read.
     * This is the exact off-by-one the `n < 6` guard exists for.
     */
    static const u_char  g[] = { MAGIC, 0x00 };

    check(probe(g, sizeof(g), &w) == NGX_HTTP_ZSTD_STATIC_FRAME_TRUNCATED,
          "a 5-byte streaming frame (descriptor but no Window_Descriptor) "
          "is TRUNCATED");
}


/*
 * n == 6 is the smallest COMPLETE streaming frame header the probe can
 * decide on: descriptor 0x00 (no dict id, no content size, Single_Segment
 * clear) plus one Window_Descriptor byte. 0x00 => exponent 10, mantissa 0
 * => a 1 KB window, far under the cap.
 */
static void
case_smallest_complete_streaming_header(void)
{
    static const u_char  f[] = { MAGIC, 0x00, 0x00 };
    uint64_t             w;

    check(probe(f, sizeof(f), &w) == NGX_HTTP_ZSTD_STATIC_FRAME_OK,
          "a 6-byte streaming frame declaring a 1 KB window is OK");
}


/*
 * A file exactly the size of the probe buffer: all 18 bytes valid, no
 * short-read path involved. Descriptor 0xE0 sets Single_Segment (0x20) and
 * Frame_Content_Size_flag 3 (0xC0 => an 8-byte field), dict-id flag 0, so
 * the content size occupies hdr[5..12] -- entirely inside 18 bytes. Value
 * 4 MB, under the cap.
 */
static void
case_exactly_probe_buffer_size(void)
{
    static const u_char  f[] = {
        MAGIC, 0xE0,
        0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,  /* 4 MB, LE64 */
        0x11, 0x22, 0x33, 0x44, 0x55                     /* trailing payload */
    };
    uint64_t  w;

    check(sizeof(f) == 18, "the exact-size fixture really is 18 bytes");

    check(probe(f, sizeof(f), &w) == NGX_HTTP_ZSTD_STATIC_FRAME_OK,
          "an exactly-18-byte file with a 4 MB single-segment window is OK");
}


/*
 * A valid, ordinary .zst frame -- the shape every real precompressed asset
 * has: streaming frame, no dictionary, a modest window. Window_Descriptor
 * 0x68 => exponent 10 + 13 = 23 (8 MB base), mantissa 0 => exactly the
 * 8 MB cap, which is ACCEPTED (the check is `> MAX`, not `>=`).
 */
static void
case_valid_zst_frame(void)
{
    static const u_char  f[] = { MAGIC, 0x00, 0x68 };
    uint64_t             w;

    check(probe(f, sizeof(f), &w) == NGX_HTTP_ZSTD_STATIC_FRAME_OK,
          "a frame declaring exactly the 8 MB window cap is OK "
          "(the limit is inclusive)");

    /* One mantissa step above the cap must be rejected, and must report
     * the value it computed so the operator's log line is actionable. */
    static const u_char  g[] = { MAGIC, 0x00, 0x69 };

    check(probe(g, sizeof(g), &w) == NGX_HTTP_ZSTD_STATIC_FRAME_WINDOW_BIG,
          "one mantissa step above the 8 MB cap is WINDOW_BIG");
    check(w == (uint64_t) NGX_HTTP_ZSTD_STATIC_MAX_WINDOW
               + (NGX_HTTP_ZSTD_STATIC_MAX_WINDOW / 8),
          "WINDOW_BIG reports the declared window (8 MB + one eighth)");
}


/*
 * Zstd reserves Frame_Header_Descriptor bit 0x08. A static sidecar with that
 * bit set is not a valid frame; the handler must decline it and fall back to
 * the uncompressed file rather than serving undecodable bytes.
 */
static void
case_reserved_descriptor_bit(void)
{
    static const u_char  f[] = { MAGIC, 0x08, 0x00 };
    uint64_t             w;

    check(probe(f, sizeof(f), &w) == NGX_HTTP_ZSTD_STATIC_FRAME_RESERVED,
          "a frame descriptor with reserved bit 0x08 is RESERVED");
}


/*
 * A skippable leading frame is a legal start to a zstd stream, but the
 * probe itself never certifies one OK: it returns SKIP with the declared
 * skip length, and it is the CALLER's job (the handler's bounded walk,
 * covered in ci/t/01-static.t, not here) to resolve the skip and probe
 * whatever frame follows before deciding. All 16 skippable magics must
 * take this path, and none of them may fall through into the
 * regular-frame window parse (which would read a Window_Descriptor out of
 * what is actually a length field) or -- the bug this replaces -- be
 * certified OK on the magic alone.
 */
static void
case_skippable_frame_reports_skip_not_ok(void)
{
    uint64_t  w;
    int       i, ok = 1;

    for (i = 0; i < 16; i++) {
        /* ZSTD_MAGIC_SKIPPABLE_START | i, little-endian, then a
         * declared skip length of 0xFFFFFFFF -- the caller must reject
         * this against of.size, not the probe. */
        u_char  f[] = { 0x50 + (u_char) i, 0x2A, 0x4D, 0x18,
                        0xFF, 0xFF, 0xFF, 0xFF };

        w = 0;

        if (probe(f, sizeof(f), &w) != NGX_HTTP_ZSTD_STATIC_FRAME_SKIP
            || w != 0xFFFFFFFFU)
        {
            ok = 0;
        }
    }

    check(ok, "all 16 skippable-frame magics report SKIP with the declared "
              "skip length, never OK on the magic alone");
}


/*
 * A skippable frame's 8-byte header (magic + Frame_Size) is the outermost
 * bound the probe can check without file-level knowledge: fewer than 8
 * bytes and it cannot even read the length field. These fixtures mirror
 * the "widest header, one byte short" boundary test above, but for the
 * skip-header layout.
 */
static void
case_skippable_frame_header_truncation(void)
{
    uint64_t  w;

    static const u_char  magic_only[] = { 0x50, 0x2A, 0x4D, 0x18 };
    check(probe(magic_only, sizeof(magic_only), &w)
              == NGX_HTTP_ZSTD_STATIC_FRAME_TRUNCATED,
          "a 4-byte skippable magic with no Frame_Size field is TRUNCATED");

    static const u_char  seven[] = { 0x50, 0x2A, 0x4D, 0x18,
                                     0x00, 0x00, 0x00 };
    check(probe(seven, sizeof(seven), &w)
              == NGX_HTTP_ZSTD_STATIC_FRAME_TRUNCATED,
          "a 7-byte skippable header (Frame_Size one byte short) is "
          "TRUNCATED");

    static const u_char  eight[] = { 0x50, 0x2A, 0x4D, 0x18,
                                     0x00, 0x00, 0x00, 0x00 };
    w = 123;
    check(probe(eight, sizeof(eight), &w) == NGX_HTTP_ZSTD_STATIC_FRAME_SKIP
              && w == 0,
          "an exact 8-byte skippable header with a zero-length payload "
          "is SKIP with skip length 0");
}


/*
 * A file whose magic does not match -- the `cp foo.txt foo.zst` case the
 * probe exists for. It must be NOT_ZSTD regardless of what follows, and
 * must not be mistaken for a truncation.
 */
static void
case_magic_mismatch(void)
{
    static const u_char  f[] = { 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o',
                                 'r', 'l', 'd', '\n' };
    uint64_t             w;

    check(probe(f, sizeof(f), &w) == NGX_HTTP_ZSTD_STATIC_FRAME_NOT_ZSTD,
          "plain text is NOT_ZSTD");

    /*
     * One bit off the real magic, and one bit off the skippable range --
     * the two near-misses a naive mask comparison would wave through.
     */
    static const u_char  g[] = { 0x29, 0xB5, 0x2F, 0xFD, 0x00, 0x00 };

    check(probe(g, sizeof(g), &w) == NGX_HTTP_ZSTD_STATIC_FRAME_NOT_ZSTD,
          "a one-bit-off zstd magic is NOT_ZSTD");

    /* 0x184D2A40: one nibble below ZSTD_MAGIC_SKIPPABLE_START. */
    static const u_char  h[] = { 0x40, 0x2A, 0x4D, 0x18, 0x00, 0x00 };

    check(probe(h, sizeof(h), &w) == NGX_HTTP_ZSTD_STATIC_FRAME_NOT_ZSTD,
          "the value one below the skippable magic range is NOT_ZSTD");

    /* 0x184D2A60: one nibble above the range. */
    static const u_char  k[] = { 0x60, 0x2A, 0x4D, 0x18, 0x00, 0x00 };

    check(probe(k, sizeof(k), &w) == NGX_HTTP_ZSTD_STATIC_FRAME_NOT_ZSTD,
          "the value one above the skippable magic range is NOT_ZSTD");
}


/*
 * A zero-length file never reaches the probe: the handler rejects
 * of.size < 4 with its own "too small to be a zstd frame" line, and
 * rejects a pread returning fewer than 4 bytes before calling. The probe's
 * contract is therefore n >= 4, and this case pins the boundary that
 * contract rests on -- the smallest n the probe is ever handed is exactly
 * the 4 bytes the magic compare needs, so the compare itself never reads
 * past the read even at the minimum.
 *
 * Asserting it here rather than trusting the comment: the 4-byte call is
 * the one that would read hdr[4] if the `n < 5` guard were dropped, and
 * the poisoned buffer makes that read a guard byte rather than a lucky
 * zero.
 */
static void
case_zero_length_file_never_reaches_the_probe(void)
{
    static const u_char  f[] = { MAGIC };
    uint64_t             w;

    check(probe(f, 4, &w) == NGX_HTTP_ZSTD_STATIC_FRAME_TRUNCATED,
          "the minimum n the probe accepts (4) decides on the magic alone "
          "and never indexes hdr[4]");
}


/*
 * Single_Segment content-size widths. Frame_Content_Size_flag selects a
 * 1, 2, 4 or 8-byte field (flag 0 means ONE byte when Single_Segment is
 * set -- the flag only means "absent" when it is clear), and the 2-byte
 * form is offset by 256 per RFC 8878. Each width's truncation boundary is
 * one byte before the field ends.
 */
static void
case_single_segment_content_size_widths(void)
{
    uint64_t  w;

    /* flag 0 => 1-byte field at hdr[5]. 0x40 = 64 bytes. */
    static const u_char  a[] = { MAGIC, 0x20, 0x40 };
    check(probe(a, sizeof(a), &w) == NGX_HTTP_ZSTD_STATIC_FRAME_OK,
          "Single_Segment with a 1-byte content size is OK");

    /* ...and one byte short of that field is TRUNCATED. */
    static const u_char  a0[] = { MAGIC, 0x20 };
    check(probe(a0, sizeof(a0), &w) == NGX_HTTP_ZSTD_STATIC_FRAME_TRUNCATED,
          "Single_Segment missing its 1-byte content size is TRUNCATED");

    /* flag 1 (0x40) => 2-byte field, +256 offset. 0x0000 => 256. */
    static const u_char  b[] = { MAGIC, 0x60, 0x00, 0x00 };
    check(probe(b, sizeof(b), &w) == NGX_HTTP_ZSTD_STATIC_FRAME_OK,
          "Single_Segment with a 2-byte content size is OK");

    static const u_char  b0[] = { MAGIC, 0x60, 0x00 };
    check(probe(b0, sizeof(b0), &w) == NGX_HTTP_ZSTD_STATIC_FRAME_TRUNCATED,
          "Single_Segment one byte short of its 2-byte content size is "
          "TRUNCATED");

    /*
     * The +256 offset is load-bearing at the cap: 0xFFFF00 would be
     * (8 MB - 256) without it and (8 MB) with it -- both accepted -- so
     * pin it where it changes the verdict instead. 2-byte field
     * 0xFFFF = 65535, +256 = 65791, comfortably OK; the offset is
     * observable through WINDOW_BIG's reported value below.
     */
    static const u_char  b1[] = { MAGIC, 0x60, 0xFF, 0xFF };
    check(probe(b1, sizeof(b1), &w) == NGX_HTTP_ZSTD_STATIC_FRAME_OK,
          "a 2-byte content size of 65535 (+256) is under the cap");

    /* flag 2 (0x80) => 4-byte field. 16 MB, over the cap. */
    static const u_char  c[] = { MAGIC, 0xA0, 0x00, 0x00, 0x00, 0x01 };
    check(probe(c, sizeof(c), &w) == NGX_HTTP_ZSTD_STATIC_FRAME_WINDOW_BIG,
          "Single_Segment declaring a 16 MB content size is WINDOW_BIG");
    check(w == 16777216, "the 4-byte content size is decoded little-endian");

    static const u_char  c0[] = { MAGIC, 0xA0, 0x00, 0x00, 0x00 };
    check(probe(c0, sizeof(c0), &w) == NGX_HTTP_ZSTD_STATIC_FRAME_TRUNCATED,
          "Single_Segment one byte short of its 4-byte content size is "
          "TRUNCATED");

    /* flag 3 (0xC0) => 8-byte field. */
    static const u_char  d0[] = { MAGIC, 0xE0,
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    check(probe(d0, sizeof(d0), &w) == NGX_HTTP_ZSTD_STATIC_FRAME_TRUNCATED,
          "Single_Segment one byte short of its 8-byte content size is "
          "TRUNCATED");
}


/*
 * The Dictionary_ID_flag widens the offset of the content-size field by
 * 0, 1, 2 or 4 bytes. Getting that table wrong reads the content size
 * from the dictionary id (or from payload), so each width gets a case
 * whose content-size bytes sit at a DIFFERENT offset from the previous
 * one, with dictionary-id bytes chosen so that misreading them would
 * produce a different verdict.
 */
static void
case_dictionary_id_shifts_the_content_size(void)
{
    uint64_t  w;

    /*
     * Single_Segment + 1-byte content size, dict-id flag 1 => a 1-byte
     * dict id at hdr[5], content size at hdr[6]. The dict-id byte is 0xFF
     * and the content size 0x01: reading the wrong one is 255 vs 1, both
     * OK, so pin it via the 4-byte-content-size form instead where the
     * shift changes the magnitude by orders of magnitude.
     *
     * Descriptor 0xA1: Single_Segment(0x20) + FCS flag 2 (0x80 => 4
     * bytes) + dict-id flag 1 (0x01 => 1 byte).
     * Layout: hdr[5] = dict id, hdr[6..9] = content size = 16 MB.
     */
    static const u_char  a[] = { MAGIC, 0xA1,
                                 0xFF,                     /* dict id */
                                 0x00, 0x00, 0x00, 0x01 }; /* 16 MB LE32 */
    check(probe(a, sizeof(a), &w) == NGX_HTTP_ZSTD_STATIC_FRAME_WINDOW_BIG,
          "a 1-byte dictionary id shifts the content-size field by one");
    check(w == 16777216,
          "the content size is read from behind the 1-byte dictionary id");

    /* dict-id flag 2 => 2 bytes; content size at hdr[7..10]. */
    static const u_char  b[] = { MAGIC, 0xA2,
                                 0xFF, 0xFF,
                                 0x00, 0x00, 0x00, 0x01 };
    check(probe(b, sizeof(b), &w) == NGX_HTTP_ZSTD_STATIC_FRAME_WINDOW_BIG
          && w == 16777216,
          "the content size is read from behind a 2-byte dictionary id");

    /* dict-id flag 3 => 4 bytes; content size at hdr[9..12]. */
    static const u_char  c[] = { MAGIC, 0xA3,
                                 0xFF, 0xFF, 0xFF, 0xFF,
                                 0x00, 0x00, 0x00, 0x01 };
    check(probe(c, sizeof(c), &w) == NGX_HTTP_ZSTD_STATIC_FRAME_WINDOW_BIG
          && w == 16777216,
          "the content size is read from behind a 4-byte dictionary id");

    /*
     * The widest layout the probe must handle: 4-byte dict id + 8-byte
     * content size ends at hdr[16], inside the 18-byte buffer. One byte
     * short of it is TRUNCATED -- this is the outermost bound in the
     * function and the one an off-by-one would most plausibly break.
     */
    static const u_char  d[] = { MAGIC, 0xE3,
                                 0xFF, 0xFF, 0xFF, 0xFF,
                                 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00 };   /* 7 of 8 bytes */
    check(sizeof(d) == 16, "the widest-layout truncation fixture is 16 bytes");
    check(probe(d, sizeof(d), &w) == NGX_HTTP_ZSTD_STATIC_FRAME_TRUNCATED,
          "the widest header (4-byte dict id + 8-byte content size) one "
          "byte short is TRUNCATED");

    static const u_char  e[] = { MAGIC, 0xE3,
                                 0xFF, 0xFF, 0xFF, 0xFF,
                                 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00 };  /* all 8 */
    check(sizeof(e) == 17, "the widest-layout complete fixture is 17 bytes");
    check(probe(e, sizeof(e), &w) == NGX_HTTP_ZSTD_STATIC_FRAME_OK,
          "the widest header, complete at 17 bytes, is decided (OK)");
}


/*
 * Window_Descriptor arithmetic on streaming frames: RFC 8878 3.1.1.1.2
 * defines window = (1 << (10 + exponent)) + ((1 << (10 + exponent)) >> 3)
 * * mantissa, where exponent = byte >> 3 and mantissa = byte & 7. The
 * verdict boundary sits between two adjacent byte values, so the pair
 * below is exactly the mutation-sensitive point.
 */
static void
case_window_descriptor_arithmetic(void)
{
    uint64_t  w;

    /* exponent 12 (0x60 >> 3 = 12) => 1 << 22 = 4 MB, mantissa 0. */
    static const u_char  a[] = { MAGIC, 0x00, 0x60 };
    check(probe(a, sizeof(a), &w) == NGX_HTTP_ZSTD_STATIC_FRAME_OK,
          "Window_Descriptor 0x60 (4 MB) is OK");

    /* exponent 13 => 8 MB exactly, mantissa 0 -- the inclusive cap. */
    static const u_char  b[] = { MAGIC, 0x00, 0x68 };
    check(probe(b, sizeof(b), &w) == NGX_HTTP_ZSTD_STATIC_FRAME_OK,
          "Window_Descriptor 0x68 (exactly 8 MB) is OK");

    /* exponent 14 => 16 MB. */
    static const u_char  c[] = { MAGIC, 0x00, 0x70 };
    check(probe(c, sizeof(c), &w) == NGX_HTTP_ZSTD_STATIC_FRAME_WINDOW_BIG,
          "Window_Descriptor 0x70 (16 MB) is WINDOW_BIG");
    check(w == 16777216, "the exponent-only window is 1 << (10 + exponent)");

    /*
     * Mantissa contribution: exponent 13, mantissa 7 => 8 MB + 7/8 MB.
     * A mutant that drops the mantissa term reports exactly 8 MB and
     * flips this to OK.
     */
    static const u_char  d[] = { MAGIC, 0x00, 0x6F };
    check(probe(d, sizeof(d), &w) == NGX_HTTP_ZSTD_STATIC_FRAME_WINDOW_BIG,
          "the mantissa pushes an 8 MB-exponent frame over the cap");
    check(w == (uint64_t) NGX_HTTP_ZSTD_STATIC_MAX_WINDOW
               + (NGX_HTTP_ZSTD_STATIC_MAX_WINDOW / 8) * 7,
          "the mantissa contributes (window >> 3) * mantissa");

    /*
     * The largest Window_Descriptor, 0xFF: exponent 31 => 1 << 41, plus
     * mantissa. This must not overflow the 64-bit accumulator into a
     * small value that reads as OK -- the reason the computation is
     * uint64_t rather than the ngx_uint_t the surrounding code uses.
     */
    static const u_char  e[] = { MAGIC, 0x00, 0xFF };
    check(probe(e, sizeof(e), &w) == NGX_HTTP_ZSTD_STATIC_FRAME_WINDOW_BIG,
          "the maximum Window_Descriptor (0xFF) is WINDOW_BIG, not "
          "wrapped to a small window");
    check(w == ((uint64_t) 1 << 41) + (((uint64_t) 1 << 41) >> 3) * 7,
          "the maximum window is computed in 64 bits without wrapping");
}


/*
 * The window out-param is written ONLY on WINDOW_BIG. The handler reads it
 * only in that branch, but a probe that scribbled on it unconditionally
 * would make the handler's other log lines depend on uninitialised-looking
 * state if that ever changed, and it is free to pin here.
 */
static void
case_window_untouched_unless_oversized(void)
{
    uint64_t  w;

    static const u_char  ok[] = { MAGIC, 0x00, 0x00 };
    w = 0xDEADBEEF;
    ngx_http_zstd_static_probe_frame(frame(ok, sizeof(ok)), sizeof(ok), &w);
    check(w == 0xDEADBEEF, "window is untouched on OK");

    static const u_char  bad[] = { 'n', 'o', 'p', 'e' };
    w = 0xDEADBEEF;
    ngx_http_zstd_static_probe_frame(frame(bad, sizeof(bad)), sizeof(bad), &w);
    check(w == 0xDEADBEEF, "window is untouched on NOT_ZSTD");

    static const u_char  trunc[] = { MAGIC, 0x00 };
    w = 0xDEADBEEF;
    ngx_http_zstd_static_probe_frame(frame(trunc, sizeof(trunc)),
                                     sizeof(trunc), &w);
    check(w == 0xDEADBEEF, "window is untouched on TRUNCATED");
}


int
main(void)
{
    case_shorter_than_probe_buffer();
    case_smallest_complete_streaming_header();
    case_exactly_probe_buffer_size();
    case_valid_zst_frame();
    case_reserved_descriptor_bit();
    case_skippable_frame_reports_skip_not_ok();
    case_skippable_frame_header_truncation();
    case_magic_mismatch();
    case_zero_length_file_never_reaches_the_probe();
    case_single_segment_content_size_widths();
    case_dictionary_id_shifts_the_content_size();
    case_window_descriptor_arithmetic();
    case_window_untouched_unless_oversized();

    printf("\n%d/%d checks passed\n", checks - failures, checks);
    return failures ? 1 : 0;
}
