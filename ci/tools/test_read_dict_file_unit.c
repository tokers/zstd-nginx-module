/*
 * Unit fixture for ngx_http_zstd_read_dict_file().
 *
 * The helper is `static` inside src/ngx_http_zstd_filter_module.c, so it
 * cannot be linked from outside that TU. test_read_dict_file_unit.sh
 * extracts it verbatim by line range (the repo's established precedent —
 * see test_ceil_log2_unit.sh and the Accept-Encoding fuzz harness) and
 * #includes the generated file here, so this test always exercises the
 * CURRENT shipped implementation rather than a hand-copied duplicate.
 *
 * WHY A UNIT FIXTURE AND NOT A CONFIG FIXTURE. The three behaviours that
 * matter here are short reads, EINTR, and early EOF. None is reachable
 * from ci/tools/test_dict_path_hardening.sh: read() on a local tmpfs/ext4
 * regular file never returns a short count, a signal cannot be steered
 * into the master's read window from a shell, and shrinking the file
 * between fstat() and read() is a race, not a fixture. Measured: with the
 * loop reverted to a single read whose short count is fatal, EVERY
 * config-level fixture still passed — including a 1 MiB dictionary. A
 * config fixture cannot discriminate this change; a stubbed read can.
 *
 * ngx_read_fd is a macro over read(2) in the shipped tree. Here it is
 * redefined to a scripted stub so each call's return value and errno are
 * chosen by the test, which is what makes the loop's three exits
 * (continue-on-short, retry-on-EINTR, fail-on-EOF) directly observable.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/types.h>   /* ssize_t */

/* --- minimal nginx type/macro surface the extracted function needs --- */

typedef intptr_t   ngx_int_t;
typedef uintptr_t  ngx_uint_t;
typedef int        ngx_fd_t;
typedef unsigned char u_char;

#define NGX_OK        0
#define NGX_ERROR    -1
#define NGX_EINTR     EINTR
#define ngx_errno     errno
#define ngx_read_fd_n "read()"

typedef struct { size_t len; u_char *data; } ngx_str_t;
typedef struct { int unused; } ngx_conf_t;

#define NGX_LOG_EMERG 2

/*
 * The extracted function guards its EINTR retry with #if !(NGX_WIN32).
 * Define it to 0 explicitly: an undefined macro already evaluates to 0
 * in #if, so this changes nothing, but it makes the POSIX build the
 * stated intent rather than a side effect of the macro being absent --
 * and it is the branch the EINTR assertion below exercises.
 */
#define NGX_WIN32 0

/*
 * Diagnostics are counted, not printed: the assertions below care that
 * the failing paths REPORT (exactly once, on the right exit), not about
 * the wording. Variadic and ignoring its arguments so any format string
 * the shipped code uses compiles unchanged.
 */
static int  log_calls;
static void ngx_conf_log_error(int level, ngx_conf_t *cf, int err,
    const char *fmt, ...)
{
    (void) level; (void) cf; (void) err; (void) fmt;
    log_calls++;
}

/* --- scripted ngx_read_fd stub ---------------------------------------
 *
 * Each entry is one call's outcome: n >= 0 is a byte count to deliver
 * (0 = EOF), n < 0 is a failure carrying `err` in errno. The stub fills
 * the destination with a byte pattern derived from the running offset so
 * the test can prove the bytes landed CONTIGUOUSLY and in order — a loop
 * that re-read into the wrong offset would still satisfy a length check.
 */
typedef struct { ssize_t n; int err; } step_t;

static step_t  steps[16];
static int     nsteps;
static int     step_i;
static size_t  delivered;

static ssize_t
ngx_read_fd(ngx_fd_t fd, void *buf, size_t size)
{
    step_t  *s;
    size_t   i, give;

    (void) fd;

    if (step_i >= nsteps) {
        fprintf(stderr, "FAIL: stub ran out of scripted steps "
                        "(loop called read() more times than expected)\n");
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
        return -1;
    }

    for (i = 0; i < give; i++) {
        ((u_char *) buf)[i] = (u_char) ((delivered + i) & 0xff);
    }

    delivered += give;
    return (ssize_t) give;
}

#include "generated_read_dict_file.inc"

/* --- harness ---------------------------------------------------------- */

static int  failures;

static void
reset(void)
{
    nsteps = 0; step_i = 0; delivered = 0; log_calls = 0;
}

static void
push(ssize_t n, int err)
{
    steps[nsteps].n = n;
    steps[nsteps].err = err;
    nsteps++;
}

static void
check(const char *name, int got, int want, int want_log_at_least)
{
    if (got != want) {
        printf("✗ %s: rc=%d want=%d\n", name, got, want);
        failures++;
        return;
    }
    if (log_calls < want_log_at_least) {
        printf("✗ %s: rc ok but logged %d times, wanted >= %d\n",
               name, log_calls, want_log_at_least);
        failures++;
        return;
    }
    printf("✓ %s\n", name);
}

/* Verify the buffer holds the contiguous 0,1,2,… pattern for `size`. */
static int
pattern_ok(const u_char *buf, size_t size)
{
    size_t  i;

    for (i = 0; i < size; i++) {
        if (buf[i] != (u_char) (i & 0xff)) {
            printf("  buffer diverges at offset %zu: got %u want %u\n",
                   i, buf[i], (unsigned) (i & 0xff));
            return 0;
        }
    }
    return 1;
}

int
main(void)
{
    u_char      buf[4096];
    ngx_str_t   path;
    ngx_conf_t  cf;
    ngx_int_t   rc;

    path.len = 4;
    path.data = (u_char *) "d.dc";

    /* 1. One full read: the ordinary case must still work. */
    reset();
    memset(buf, 0xee, sizeof(buf));
    push(1024, 0);
    rc = ngx_http_zstd_read_dict_file(&cf, 3, &path, buf, 1024);
    check("single complete read succeeds", (int) rc, NGX_OK, 0);
    if (rc == NGX_OK && !pattern_ok(buf, 1024)) { failures++; }

    /*
     * 2. THE REGRESSION THIS FIX EXISTS FOR. Three short counts that add
     * up to the requested size must succeed. The pre-fix code failed this
     * with "incomplete read" on the first partial count.
     */
    reset();
    memset(buf, 0xee, sizeof(buf));
    push(100, 0); push(400, 0); push(524, 0);
    rc = ngx_http_zstd_read_dict_file(&cf, 3, &path, buf, 1024);
    check("short reads are resumed, not fatal", (int) rc, NGX_OK, 0);
    if (rc == NGX_OK && !pattern_ok(buf, 1024)) { failures++; }
    if (rc == NGX_OK && step_i != 3) {
        printf("✗ short-read case used %d reads, expected 3\n", step_i);
        failures++;
    }

    /* 3. A single-byte dribble still completes (worst-case chunking). */
    reset();
    memset(buf, 0xee, sizeof(buf));
    push(1, 0); push(1, 0); push(1, 0); push(1, 0); push(1, 0);
    rc = ngx_http_zstd_read_dict_file(&cf, 3, &path, buf, 5);
    check("one-byte-at-a-time reads complete", (int) rc, NGX_OK, 0);
    if (rc == NGX_OK && !pattern_ok(buf, 5)) { failures++; }

    /*
     * 4. EINTR is retried and must NOT consume progress or log. Note the
     * interrupt lands BETWEEN two partial reads, which is the arrangement
     * that catches a retry that restarts at offset 0.
     */
    reset();
    memset(buf, 0xee, sizeof(buf));
    push(600, 0); push(-1, EINTR); push(424, 0);
    rc = ngx_http_zstd_read_dict_file(&cf, 3, &path, buf, 1024);
    check("EINTR is retried", (int) rc, NGX_OK, 0);
    if (rc == NGX_OK && !pattern_ok(buf, 1024)) { failures++; }
    if (rc == NGX_OK && log_calls != 0) {
        printf("✗ EINTR case logged %d times; a retry is not an error\n",
               log_calls);
        failures++;
    }

    /* 5. Early EOF with bytes still owed is FATAL and reported. */
    reset();
    push(500, 0); push(0, 0);
    rc = ngx_http_zstd_read_dict_file(&cf, 3, &path, buf, 1024);
    check("early EOF fails and reports", (int) rc, NGX_ERROR, 1);

    /* 6. A hard read error is FATAL and reported (not retried). */
    reset();
    push(500, 0); push(-1, EIO);
    rc = ngx_http_zstd_read_dict_file(&cf, 3, &path, buf, 1024);
    check("read error fails and reports", (int) rc, NGX_ERROR, 1);

    /*
     * 7. An immediate EOF on a size the caller believed non-zero is the
     * "file shrank to nothing between fstat() and read()" case.
     */
    reset();
    push(0, 0);
    rc = ngx_http_zstd_read_dict_file(&cf, 3, &path, buf, 1024);
    check("immediate EOF fails and reports", (int) rc, NGX_ERROR, 1);

    if (failures) {
        printf("❌ %d read_dict_file unit assertion(s) failed\n", failures);
        return 1;
    }

    printf("✓ all read_dict_file unit assertions passed\n");
    return 0;
}
