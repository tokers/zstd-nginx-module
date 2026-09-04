/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit fixture for ngx_http_zstd_static_pread().
 *
 * The helper is `static` inside src/ngx_http_zstd_static_module.c, so it
 * cannot be linked from outside that TU. test_static_pread_unit.sh
 * extracts it verbatim by line range (the repo's established precedent —
 * see test_read_dict_file_unit.sh, whose scripted-stub shape this file
 * follows) and #includes the generated file here, so this test always
 * exercises the CURRENT shipped implementation rather than a hand-copied
 * duplicate.
 *
 * WHY A UNIT FIXTURE AND NOT A CONFIG FIXTURE. The behaviours that matter
 * are EINTR, legal short reads, true EOF and a hard error — on BOTH the
 * buffered probe and the O_DIRECT-aligned one. None is reachable from
 * ci/t/01-static.t: pread() on a local tmpfs/ext4 regular file does not
 * return a short count, a signal cannot be steered into the worker's read
 * window from a test script, and provoking O_DIRECT misalignment requires
 * a device whose block size disagrees with directio_alignment. A config
 * fixture cannot discriminate this change; a stubbed pread can.
 *
 * WHAT THE ALIGNED CASES ASSERT, AND WHY IT IS THE POINT. Under directio
 * the caller hands this function an `align`-aligned buffer, an
 * `align`-aligned offset and a length of 2 * align. O_DIRECT rejects a
 * read whose buffer address, file offset or length is not a multiple of
 * the block size. A naive accumulate loop resuming at buf + n after a
 * short read violates all three at once. The stub below therefore does
 * not merely count bytes: on every call with align > 0 it ASSERTS the
 * offset and the length it was handed are multiples of align, and the
 * harness checks the destination pointer is too. A loop that resumed
 * mid-block fails those assertions rather than quietly working on a
 * filesystem that tolerates it.
 *
 * pread is redefined to a scripted stub so each call's return value and
 * errno are chosen by the test, which is what makes the loop's exits
 * (retry-on-EINTR, continue-on-short, stop-on-EOF, fail-on-error)
 * directly observable.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/types.h>   /* ssize_t, off_t */

/* --- minimal nginx type/macro surface the extracted function needs --- */

typedef intptr_t       ngx_int_t;
typedef uintptr_t      ngx_uint_t;
typedef int            ngx_fd_t;
typedef unsigned char  u_char;

#define NGX_EINTR   EINTR
#define ngx_errno   errno

typedef struct { size_t len; u_char *data; } ngx_str_t;
typedef struct { int unused; } ngx_log_t;

/*
 * The extracted function's Win32 arm is selected by #if (NGX_WIN32).
 * Define it to 0 explicitly: an undefined macro already evaluates to 0
 * in #if, so this changes nothing, but it makes the POSIX build the
 * stated intent rather than a side effect of the macro being absent —
 * and the POSIX arm is the entire subject of this fixture.
 */
#define NGX_WIN32 0

/* --- scripted pread stub ----------------------------------------------
 *
 * Each entry is one call's outcome: n >= 0 is a byte count to deliver
 * (0 = EOF), n < 0 is a failure carrying `err` in errno. The stub fills
 * the destination with a byte pattern derived from the ABSOLUTE FILE
 * OFFSET, not from a running counter, so the harness can prove each byte
 * landed at the buffer slot matching the file position it came from — a
 * loop that re-read into the wrong buffer offset would still satisfy a
 * plain length check.
 */
typedef struct { ssize_t n; int err; } step_t;

static step_t  steps[16];
static int     nsteps;
static int     step_i;

/* Alignment the current case runs at; 0 = buffered. Enforced per call. */
static size_t  cur_align;

/* Set when the stub caught an O_DIRECT-illegal request. */
static int     align_violations;

/* Highest file offset the stub was ever asked to start at. */
static off_t   last_offset;

static u_char
pattern_at(off_t off)
{
    /* +1 so offset 0 is not the same byte as "untouched" (0). */
    return (u_char) (((uint64_t) off + 1) & 0xff);
}

static ssize_t
stub_pread(ngx_fd_t fd, void *buf, size_t size, off_t offset)
{
    step_t  *s;
    size_t   i, give;

    (void) fd;

    last_offset = offset;

    /*
     * O_DIRECT legality, checked on EVERY call including the first. This
     * is the assertion the whole fixture exists for: buffer address,
     * file offset and length must all be multiples of the block size.
     */
    if (cur_align > 0) {
        if (((uintptr_t) buf % cur_align) != 0) {
            fprintf(stderr, "FAIL: call %d buffer %p is not %zu-aligned "
                            "— an O_DIRECT read would fail EINVAL\n",
                    step_i, buf, cur_align);
            align_violations++;
        }
        if (((uint64_t) offset % (uint64_t) cur_align) != 0) {
            fprintf(stderr, "FAIL: call %d offset %lld is not a multiple of "
                            "%zu — an O_DIRECT read would fail EINVAL\n",
                    step_i, (long long) offset, cur_align);
            align_violations++;
        }
        if ((size % cur_align) != 0) {
            fprintf(stderr, "FAIL: call %d length %zu is not a multiple of "
                            "%zu — an O_DIRECT read would fail EINVAL\n",
                    step_i, size, cur_align);
            align_violations++;
        }
    }

    if (step_i >= nsteps) {
        fprintf(stderr, "FAIL: stub ran out of scripted steps "
                        "(loop called pread() more times than expected)\n");
        errno = EIO;
        return -1;
    }

    s = &steps[step_i++];

    if (s->n < 0) {
        errno = s->err;
        return -1;
    }

    give = (size_t) s->n;
    if (give > size) {
        fprintf(stderr, "FAIL: scripted step %d returns %zu for a %zu-byte "
                        "request — the loop asked for less than it should\n",
                step_i - 1, give, size);
        errno = EIO;
        return -1;
    }

    for (i = 0; i < give; i++) {
        ((u_char *) buf)[i] = pattern_at(offset + (off_t) i);
    }

    return (ssize_t) give;
}

#define pread(fd, buf, size, offset)  stub_pread(fd, buf, size, offset)

#include "generated_static_pread.inc"

#undef pread

/* --- harness ---------------------------------------------------------- */

static int  failures;

#define ALIGN  4096u

/* 2 * ALIGN, the directio probe's `want`, plus slack for guard checks. */
static u_char  bigbuf[2 * ALIGN + 64] __attribute__((aligned(ALIGN)));

static void
reset(size_t align)
{
    nsteps = 0;
    step_i = 0;
    cur_align = align;
    align_violations = 0;
    last_offset = -1;
    memset(bigbuf, 0, sizeof(bigbuf));
    errno = 0;
}

static void
push(ssize_t n, int err)
{
    steps[nsteps].n = n;
    steps[nsteps].err = err;
    nsteps++;
}

static void
check(const char *name, int cond, const char *what)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s: %s\n", name, what);
        failures++;
    }
}

/*
 * Assert bytes [0, n) of the buffer carry the pattern for file offsets
 * [base, base + n) — i.e. every byte landed at the slot matching where it
 * came from, contiguously and in order.
 */
static void
check_bytes(const char *name, off_t base, size_t n)
{
    size_t  i;

    for (i = 0; i < n; i++) {
        if (bigbuf[i] != pattern_at(base + (off_t) i)) {
            fprintf(stderr, "FAIL: %s: byte %zu is 0x%02x, expected 0x%02x "
                            "(file offset %lld) — the loop wrote at the "
                            "wrong buffer offset\n",
                    name, i, bigbuf[i], pattern_at(base + (off_t) i),
                    (long long) (base + (off_t) i));
            failures++;
            return;
        }
    }
}

/* ------------------------------------------------------------------ *
 * Buffered probe (align == 0): the 18-byte hdrbuf read.
 * ------------------------------------------------------------------ */

/* One clean read delivers everything: the loop must not call pread twice. */
static void
case_buffered_complete(void)
{
    ssize_t  n;

    reset(0);
    push(18, 0);

    n = ngx_http_zstd_static_pread(3, bigbuf, 18, 0, 0, NULL, NULL);

    check("buffered/complete", n == 18, "expected 18 bytes");
    check("buffered/complete", step_i == 1, "expected exactly one pread call");
    check_bytes("buffered/complete", 0, 18);
}

/*
 * EINTR before any bytes move. Pre-fix this returned -1 and the caller
 * DECLINED a perfectly good .zst; the loop must retry and complete.
 */
static void
case_buffered_eintr(void)
{
    ssize_t  n;

    reset(0);
    push(-1, EINTR);
    push(18, 0);

    n = ngx_http_zstd_static_pread(3, bigbuf, 18, 0, 0, NULL, NULL);

    check("buffered/EINTR", n == 18,
          "EINTR must be retried, not returned to the caller");
    check("buffered/EINTR", step_i == 2, "expected two pread calls");
    check_bytes("buffered/EINTR", 0, 18);
}

/*
 * The audit's named fragments: 6 bytes, then 12, completing the 18-byte
 * probe. Each continuation must resume at the right offset AND the right
 * buffer slot.
 */
static void
case_buffered_fragments(void)
{
    ssize_t  n;

    reset(0);
    push(6, 0);
    push(12, 0);

    n = ngx_http_zstd_static_pread(3, bigbuf, 18, 0, 0, NULL, NULL);

    check("buffered/6+12", n == 18, "expected the fragments to accumulate");
    check("buffered/6+12", step_i == 2, "expected two pread calls");
    check("buffered/6+12", last_offset == 6,
          "the continuation must resume at file offset 6");
    check_bytes("buffered/6+12", 0, 18);
}

/* EINTR interleaved with a partial: progress must not be lost. */
static void
case_buffered_eintr_midway(void)
{
    ssize_t  n;

    reset(0);
    push(6, 0);
    push(-1, EINTR);
    push(12, 0);

    n = ngx_http_zstd_static_pread(3, bigbuf, 18, 0, 0, NULL, NULL);

    check("buffered/6+EINTR+12", n == 18,
          "EINTR after a partial must not discard the bytes already read");
    check("buffered/6+EINTR+12", step_i == 3, "expected three pread calls");
    check_bytes("buffered/6+EINTR+12", 0, 18);
}

/*
 * True EOF short of the request. This is NOT an error: a .zst file may be
 * legitimately shorter than the 18-byte probe, and the caller bounds-checks
 * what it got. The loop must stop and report the partial count.
 */
static void
case_buffered_eof(void)
{
    ssize_t  n;

    reset(0);
    push(6, 0);
    push(0, 0);

    n = ngx_http_zstd_static_pread(3, bigbuf, 18, 0, 0, NULL, NULL);

    check("buffered/EOF", n == 6, "EOF must return the partial count");
    check("buffered/EOF", step_i == 2, "expected two pread calls");
    check_bytes("buffered/EOF", 0, 6);
}

/*
 * A hard error must still be -1, even after a partial transfer. This is
 * the fail-CLOSED direction and the property the fix must not relax:
 * the caller declines on -1, so bytes we could not finish reading are
 * never parsed as a complete header.
 */
static void
case_buffered_hard_error(void)
{
    ssize_t  n;

    reset(0);
    push(6, 0);
    push(-1, EIO);

    n = ngx_http_zstd_static_pread(3, bigbuf, 18, 0, 0, NULL, NULL);

    check("buffered/EIO", n == -1,
          "a hard error after a partial read must still fail closed");
}

/* An immediate hard error on the very first call is -1 too. */
static void
case_buffered_hard_error_first(void)
{
    ssize_t  n;

    reset(0);
    push(-1, EIO);

    n = ngx_http_zstd_static_pread(3, bigbuf, 18, 0, 0, NULL, NULL);

    check("buffered/EIO-first", n == -1, "expected -1");
    check("buffered/EIO-first", step_i == 1, "expected exactly one pread call");
}

/* An immediate EOF (empty file) is 0, not an error. */
static void
case_buffered_eof_immediate(void)
{
    ssize_t  n;

    reset(0);
    push(0, 0);

    n = ngx_http_zstd_static_pread(3, bigbuf, 18, 0, 0, NULL, NULL);

    check("buffered/EOF-immediate", n == 0, "empty file reads 0, not -1");
}

/* ------------------------------------------------------------------ *
 * Direct-I/O probe (align == ALIGN): the caller's 2-block aligned read.
 * Every stub call asserts offset/length/buffer alignment; see the stub.
 * ------------------------------------------------------------------ */

/* One clean 2-block read. Baseline: the aligned path still works. */
static void
case_dio_complete(void)
{
    ssize_t  n;

    reset(ALIGN);
    push(2 * ALIGN, 0);

    n = ngx_http_zstd_static_pread(3, bigbuf, 2 * ALIGN, 0, ALIGN,
                                   NULL, NULL);

    check("dio/complete", n == 2 * ALIGN, "expected both blocks");
    check("dio/complete", step_i == 1, "expected exactly one pread call");
    check("dio/complete", align_violations == 0, "alignment violated");
    check_bytes("dio/complete", 0, 2 * ALIGN);
}

/* EINTR on an aligned probe: retry must reissue the IDENTICAL aligned call. */
static void
case_dio_eintr(void)
{
    ssize_t  n;

    reset(ALIGN);
    push(-1, EINTR);
    push(2 * ALIGN, 0);

    n = ngx_http_zstd_static_pread(3, bigbuf, 2 * ALIGN, 0, ALIGN,
                                   NULL, NULL);

    check("dio/EINTR", n == 2 * ALIGN, "EINTR must be retried");
    check("dio/EINTR", step_i == 2, "expected two pread calls");
    check("dio/EINTR", align_violations == 0, "alignment violated");
    check("dio/EINTR", last_offset == 0,
          "an EINTR retry that moved nothing must reissue at offset 0");
    check_bytes("dio/EINTR", 0, 2 * ALIGN);
}

/*
 * A short read of exactly one block. The continuation must resume at
 * offset ALIGN with length ALIGN into buf + ALIGN — all three aligned.
 * A naive resume would be legal here by luck; the sub-block case below
 * is the one that discriminates.
 */
static void
case_dio_block_short(void)
{
    ssize_t  n;

    reset(ALIGN);
    push(ALIGN, 0);
    push(ALIGN, 0);

    n = ngx_http_zstd_static_pread(3, bigbuf, 2 * ALIGN, 0, ALIGN,
                                   NULL, NULL);

    check("dio/block-short", n == 2 * ALIGN, "expected the blocks to accumulate");
    check("dio/block-short", step_i == 2, "expected two pread calls");
    check("dio/block-short", align_violations == 0, "alignment violated");
    check("dio/block-short", last_offset == (off_t) ALIGN,
          "the continuation must resume at the next block boundary");
    check_bytes("dio/block-short", 0, 2 * ALIGN);
}

/*
 * THE DISCRIMINATING CASE. A short read that stops PAST the first block
 * but mid-way through the second (ALIGN + 12 bytes). A loop that resumed
 * at buf + n / offset + n would issue an unaligned continuation and the
 * stub's assertions above would fire. The shipped loop rounds the resume
 * point DOWN to ALIGN, re-reading the 12-byte tail, and stays legal.
 */
static void
case_dio_subblock_short(void)
{
    ssize_t  n;

    reset(ALIGN);
    push(ALIGN + 12, 0);
    push(ALIGN, 0);

    n = ngx_http_zstd_static_pread(3, bigbuf, 2 * ALIGN, 0, ALIGN,
                                   NULL, NULL);

    check("dio/subblock-short", align_violations == 0,
          "the continuation after a sub-block short read must stay "
          "O_DIRECT-aligned in buffer, offset AND length");
    check("dio/subblock-short", n == 2 * ALIGN, "expected both blocks");
    check("dio/subblock-short", step_i == 2, "expected two pread calls");
    check("dio/subblock-short", last_offset == (off_t) ALIGN,
          "the resume offset must be rounded DOWN to the block boundary");
    check_bytes("dio/subblock-short", 0, 2 * ALIGN);
}

/*
 * The same shape at a non-zero aligned base, which is what the
 * skippable-frame walk produces: the caller rounds `pos` down to `align`
 * and reads two blocks from there.
 */
static void
case_dio_subblock_short_at_base(void)
{
    ssize_t  n;
    off_t    base = (off_t) (4 * ALIGN);

    reset(ALIGN);
    push(ALIGN + 7, 0);
    push(ALIGN, 0);

    n = ngx_http_zstd_static_pread(3, bigbuf, 2 * ALIGN, base, ALIGN,
                                   NULL, NULL);

    check("dio/subblock-at-base", align_violations == 0,
          "alignment violated on a non-zero aligned base");
    check("dio/subblock-at-base", n == 2 * ALIGN, "expected both blocks");
    check("dio/subblock-at-base", last_offset == base + (off_t) ALIGN,
          "the resume offset must be base + one block");
    check_bytes("dio/subblock-at-base", base, 2 * ALIGN);
}

/*
 * A short read that does not even complete ONE block cannot be resumed at
 * an aligned boundary past 0 — re-issuing the identical call could spin if
 * the filesystem keeps answering the same count. The loop must give up and
 * report the partial count, which makes the caller decline: exactly where
 * this path went before the change, so the fail-closed behaviour is
 * preserved for the one case the loop cannot make progress on.
 */
static void
case_dio_tiny_short(void)
{
    ssize_t  n;

    reset(ALIGN);
    push(64, 0);

    n = ngx_http_zstd_static_pread(3, bigbuf, 2 * ALIGN, 0, ALIGN,
                                   NULL, NULL);

    check("dio/tiny-short", n == 64,
          "a sub-block short read must report the partial count, not spin");
    check("dio/tiny-short", step_i == 1, "expected exactly one pread call");
    check("dio/tiny-short", align_violations == 0, "alignment violated");
}

/*
 * TERMINATION at a LATER block boundary. One full block lands, then the
 * filesystem keeps answering sub-block counts that never complete another
 * block. `aligned` then equals the previous resume point forever, so a
 * guard that only tested `aligned == 0` would spin here — hanging the
 * worker on this request, which is strictly worse than the decline the
 * retry loop exists to avoid. The loop must detect no-forward-progress
 * and report the partial count instead.
 *
 * The scripted steps deliberately supply FEWER calls than an unbounded
 * loop would make: if the loop spins, the stub runs out of steps and the
 * case fails loudly rather than hanging the whole suite.
 */
static void
case_dio_stall_at_later_block(void)
{
    ssize_t  n;

    reset(ALIGN);
    push(ALIGN, 0);   /* completes block 0 */
    push(12, 0);      /* never completes block 1 -> no forward progress */

    n = ngx_http_zstd_static_pread(3, bigbuf, 2 * ALIGN, 0, ALIGN,
                                   NULL, NULL);

    check("dio/stall-later-block", step_i == 2,
          "the loop must stop on no-forward-progress, not spin");
    check("dio/stall-later-block", n == (ssize_t) (ALIGN + 12),
          "the partial count actually read must be reported");
    check("dio/stall-later-block", align_violations == 0,
          "alignment violated");
}

/* EOF on the aligned path: a file shorter than two blocks. */
static void
case_dio_eof(void)
{
    ssize_t  n;

    reset(ALIGN);
    push(ALIGN, 0);
    push(0, 0);

    n = ngx_http_zstd_static_pread(3, bigbuf, 2 * ALIGN, 0, ALIGN,
                                   NULL, NULL);

    check("dio/EOF", n == (ssize_t) ALIGN, "EOF must return the partial count");
    check("dio/EOF", step_i == 2, "expected two pread calls");
    check("dio/EOF", align_violations == 0, "alignment violated");
    check_bytes("dio/EOF", 0, ALIGN);
}

/* A hard error on the aligned path is still -1 (fail closed). */
static void
case_dio_hard_error(void)
{
    ssize_t  n;

    reset(ALIGN);
    push(ALIGN, 0);
    push(-1, EIO);

    n = ngx_http_zstd_static_pread(3, bigbuf, 2 * ALIGN, 0, ALIGN,
                                   NULL, NULL);

    check("dio/EIO", n == -1,
          "a hard error after a partial aligned read must fail closed");
}

/*
 * A 64 KB alignment — the NGX_HTTP_ZSTD_STATIC_DIO_PROBE_MAX ceiling PR
 * #208 introduced. Uses its own buffer so the 64 KB alignment is real.
 */
static u_char  hugebuf[2 * 65536] __attribute__((aligned(65536)));

static void
case_dio_max_align(void)
{
    ssize_t  n;
    size_t   a = 65536;

    reset(a);
    push((ssize_t) (a + 100), 0);
    push((ssize_t) a, 0);

    n = ngx_http_zstd_static_pread(3, hugebuf, 2 * a, 0, a, NULL, NULL);

    check("dio/64k-align", align_violations == 0,
          "alignment violated at the 64 KB probe ceiling");
    check("dio/64k-align", n == (ssize_t) (2 * a), "expected both blocks");
    check("dio/64k-align", last_offset == (off_t) a,
          "the resume offset must be rounded down to 64 KB");
}

int
main(void)
{
    case_buffered_complete();
    case_buffered_eintr();
    case_buffered_fragments();
    case_buffered_eintr_midway();
    case_buffered_eof();
    case_buffered_eof_immediate();
    case_buffered_hard_error();
    case_buffered_hard_error_first();

    case_dio_complete();
    case_dio_eintr();
    case_dio_block_short();
    case_dio_subblock_short();
    case_dio_subblock_short_at_base();
    case_dio_tiny_short();
    case_dio_stall_at_later_block();
    case_dio_eof();
    case_dio_hard_error();
    case_dio_max_align();

    if (failures) {
        fprintf(stderr, "\n%d check(s) FAILED\n", failures);
        return 1;
    }

    printf("ngx_http_zstd_static_pread(): all checks passed\n");
    return 0;
}
