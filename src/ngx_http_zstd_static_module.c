
/*
 * Copyright (C) Alex Zhang
 * Copyright (C) 2026 Thijs Eilander
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <stdint.h>   /* uint32_t for the magic-number compare */

#if !(NGX_WIN32)
#include <unistd.h>   /* pread(2) for the magic-number probe */
#endif

#include "ngx_http_zstd_common.h"

/*
 * The frame probe -- verdicts, window cap, probe_frame(),
 * probe_reuse() -- lives in its own header (#270) so the unit
 * fixtures and the compression branch's static module share ONE
 * authoritative copy instead of synchronized ones. It self-defines
 * the RFC-frozen magic constants, so this file no longer includes
 * <zstd.h>. Note the scope of that independence: the supported
 * configure path still probes libzstd in auto/zstd before any module
 * here builds -- the header makes the PROBE code library-free, and
 * the build-without-libzstd property is realized where a build
 * actually omits the library, in the compression branch's
 * dependency-free static module.
 */
#include "ngx_http_zstd_frame_probe.h"


/*
 * Whether the serve-time .zst frame probe is compiled in.
 *
 * The probe needs one thing from the platform: an OFFSET-EXPLICIT read
 * that does NOT move the file position of the descriptor it is handed.
 * That constraint is not cosmetic — the fd comes from
 * ngx_open_cached_file() and is SHARED between every request currently
 * serving the same file, so a read(2)+lseek pair here would corrupt the
 * body another request is streaming (see the long comment at the probe
 * call site).
 *
 *   POSIX    pread(2), when nginx's configure found it (NGX_HAVE_PREAD).
 *            Without it we compile the probe out rather than fall back
 *            to lseek+read — a build-time tripwire, since every modern
 *            POSIX target has pread(2).
 *   Win32    ngx_read_file(), whose Win32 implementation
 *            (src/os/win32/ngx_files.c) issues ReadFile() with an
 *            OVERLAPPED carrying the offset. An OVERLAPPED read does not
 *            advance the HANDLE's file pointer, so it satisfies exactly
 *            the same constraint pread(2) does. nginx's own abstraction
 *            is used rather than a raw ReadFile() call so the platform
 *            details (offset splitting, EOF mapping) stay upstream's.
 *
 * Deliberately NOT `ngx_read_file()` everywhere: on a POSIX build
 * without NGX_HAVE_PREAD, ngx_read_file() IS the lseek+read pair this
 * guard exists to avoid.
 */
#if (NGX_WIN32) || (NGX_HAVE_PREAD)
#define NGX_HTTP_ZSTD_STATIC_HAVE_PROBE  1
#else
#define NGX_HTTP_ZSTD_STATIC_HAVE_PROBE  0
#endif

/*
 * Name of the offset-explicit read primitive, for operator-facing error
 * text. Defined here rather than with an #if inside the ngx_log_error()
 * argument list: a preprocessor directive among the arguments of a
 * function-like macro is undefined behaviour (C11 6.10.3p11). gcc and
 * mingw accept it silently, MSVC rejects it with C2121 -- which is why a
 * mingw cross-build is not sufficient evidence that this file compiles
 * on Windows. (Observed on MSVC x64 static, PR #162.)
 */
#if (NGX_WIN32)
#define NGX_HTTP_ZSTD_STATIC_PREAD_NAME  "ReadFile"
#else
#define NGX_HTTP_ZSTD_STATIC_PREAD_NAME  "pread"
#endif


#define NGX_HTTP_ZSTD_STATIC_OFF        0
#define NGX_HTTP_ZSTD_STATIC_ON         1
#define NGX_HTTP_ZSTD_STATIC_ALWAYS     2

/*
 * FLOOR for the probe read size under directio: O_DIRECT requires
 * buffer, offset and length aligned to the device's logical block
 * size. Offset 0 is aligned by definition; 4 KB covers 512-byte and
 * 4K-native devices. A short read at EOF is permitted, so files
 * smaller than the probe work too.
 */
#define NGX_HTTP_ZSTD_STATIC_DIO_PROBE   4096

/*
 * CEILING for the probe alignment. The probe reads a frame HEADER (at
 * most 18 bytes); it is not the body copy, and it does not need the
 * operator's bulk-I/O buffer size.
 *
 * "directio_alignment" is an ngx_conf_set_off_slot with no upper bound
 * in core (ngx_http_core_module.c), and core applies it to the copy
 * filter's body buffer (ngx_http_copy_filter_module.c: ctx->alignment),
 * where a large value is a throughput choice on filesystems such as XFS.
 * O_DIRECT LEGALITY, by contrast, is a property of the device's logical
 * block size (512 or 4096 in practice), not of that directive — so
 * scaling an 18-byte header probe with it buys nothing and costs
 * "directio_alignment" bytes of pmemalign plus that much O_DIRECT read
 * on EVERY request that reaches the probe, including one from a client
 * that does not accept zstd and will be declined moments later (the
 * probe still has to run for it, to decide whether Vary is truthful).
 *
 * 64 KB is a multiple of every logical block size a Linux/BSD block
 * device reports, so the capped value stays O_DIRECT-legal for the
 * descriptor; it is also >= the 4 KB floor, which is what guarantees a
 * whole frame header still fits behind any in-block start position.
 * Everything downstream (frame_off, base, want, avail) is expressed in
 * terms of the SAME "align", so capping it preserves the arithmetic
 * exactly.
 */
#define NGX_HTTP_ZSTD_STATIC_DIO_PROBE_MAX  (64 * 1024)

/*
 * Largest byte count the directio probe can ever ask for: PROBE_MAX,
 * clamped and then doubled to a two-block read (see the "TWO blocks, not
 * one" comment at the probe call site). Fixed now that #208 caps
 * `align`, so a worker-lifetime scratch buffer can be sized against a
 * known ceiling instead of an operator-unbounded one.
 */
#define NGX_HTTP_ZSTD_STATIC_DIO_SCRATCH_MAX  \
    (NGX_HTTP_ZSTD_STATIC_DIO_PROBE_MAX * 2)

/*
 * Bounded worker-local cache of probe VERDICTS, negative and positive.
 *
 * Negative (malformed) side: a broken generated asset otherwise incurs the
 * same probe and NGX_LOG_ERR on every request.
 *
 * Positive (good) side: under "directio", the frame probe is an O_DIRECT
 * read that bypasses the page cache, so it is a real device-touching I/O on
 * every request reaching it -- including one from a client that will not
 * receive the compressed variant at all, because the probe is what decides
 * whether Vary is truthful (see the handler). Caching the good verdict turns
 * that per-request I/O into a per-(path, uniq, mtime, size) one. A
 * non-directio hit is cached too, where it merely saves a buffered read.
 *
 * The exact path plus (uniq, mtime, size) form the identity: changing any of
 * them forces a fresh probe. A positive verdict additionally expires no
 * later than open_file_cache_valid, and is not cached when open_file_cache is
 * disabled. This bounds the same-size, same-timestamp in-place rewrite case
 * that stat identity alone cannot observe. Negative verdicts retain their
 * established identity-based lifetime.
 *
 * ONE table with a verdict flag rather than two parallel arrays: each entry
 * is NGX_MAX_PATH-dominated, so a second table would double a worker's fixed
 * footprint to answer the same question about the same files. Fixed storage
 * avoids an unbounded worker-lifetime allocation surface; overlong paths
 * simply retain the established uncached behaviour.
 */
#define NGX_HTTP_ZSTD_STATIC_VERDICT_CACHE_SLOTS  64

#if (NGX_HTTP_ZSTD_STATIC_HAVE_PROBE)

#define NGX_HTTP_ZSTD_STATIC_VERDICT_NONE  0
#define NGX_HTTP_ZSTD_STATIC_VERDICT_BAD   1
#define NGX_HTTP_ZSTD_STATIC_VERDICT_GOOD  2

typedef struct {
    ngx_file_uniq_t  uniq;
    time_t      mtime;
    time_t      checked;
    off_t       size;
    size_t      len;
    ngx_uint_t  valid;      /* NGX_HTTP_ZSTD_STATIC_VERDICT_* */
    u_char      path[NGX_MAX_PATH];
} ngx_http_zstd_static_verdict_cache_t;

static ngx_http_zstd_static_verdict_cache_t
    ngx_http_zstd_static_verdict_cache[
        NGX_HTTP_ZSTD_STATIC_VERDICT_CACHE_SLOTS];
static ngx_uint_t  ngx_http_zstd_static_verdict_cache_next;
/*
 * High-water mark of slots populated in this worker, capped at SLOTS.
 * Expiring a GOOD verdict clears its validity but does not decrement this:
 * the round-robin cursor still fills each slot in order, and a high-water
 * scan avoids hiding a later refreshed entry behind an expired hole.
 */
static ngx_uint_t  ngx_http_zstd_static_verdict_cache_count;

/*
 * Log rate limit for the directio hard-error probe arm (see the
 * `of->is_directio` branch inside ngx_http_zstd_static_probe_file()).
 *
 * That arm cannot be cached in the bad-file ring above: the ring is keyed
 * on path + mtime, and this failure is an operator config mismatch
 * (`directio_alignment` disagreeing with the device), not a property of
 * the file. Caching it there would misreport a config problem as a
 * corrupt sidecar and keep suppressing the log after the operator fixes
 * `directio_alignment` -- the ring has no config-tied invalidation.
 * `*malformed` on this arm stays 0 (unchanged) for exactly that reason.
 *
 * Instead, this is a bare per-worker window counter: log the first
 * occurrence immediately (an operator must not lose the first signal),
 * then suppress for NGX_HTTP_ZSTD_STATIC_DIO_ERR_WINDOW seconds, folding
 * every suppressed hit into a count reported on the next emitted line --
 * the standard nginx "N times" idiom (see e.g. core's own
 * ngx_log_error_core rate-limited messages).
 *
 * SAFETY -- same file-scope-static, one-body-at-a-time reasoning as the
 * directio scratch buffer above: private per worker process, zeroed at
 * fork, freed with the process image, never touched by two probes at
 * once because this handler is fully synchronous per worker.
 *
 * SAFETY -- ngx_time(): nginx refreshes this cached value once per event
 * loop iteration and it is ordinarily monotonically non-decreasing within
 * a worker's lifetime, so `now - window_start` below is ordinarily
 * correct without touching the wall clock or gettimeofday() on this hot
 * path. An administrative or NTP step backward is still handled
 * explicitly (`now < window_start` below forces a rollover) rather than
 * assumed away: a signed `time_t` subtraction under a backward step goes
 * negative and would otherwise fail the `>=` window test, extending
 * suppression indefinitely instead of the intended fixed window.
 *
 * SAFETY -- worker-cycle lifetime: a config reload forks new worker
 * processes; the old ones drain and exit, so a reload cannot hide a NEW
 * misalignment behind a stale suppression window -- each new worker
 * starts this counter at zero and logs the first occurrence again.
 */
#define NGX_HTTP_ZSTD_STATIC_DIO_ERR_WINDOW  60

static time_t      ngx_http_zstd_static_dio_err_window_start;
static ngx_uint_t  ngx_http_zstd_static_dio_err_suppressed;

/*
 * Nonnegative short reads are malformed-file results, not directio system
 * errors: return 0 for those without consuming the worker-wide error window.
 * For a negative read, return the number of prior worker-wide occurrences to
 * report as suppressed (0 on the first hit or rollover), or (ngx_uint_t) -1
 * when this hit is suppressed. Never allocates; never blocks.
 */
static ngx_uint_t
ngx_http_zstd_static_dio_err_should_log(ngx_log_t *log, ssize_t n)
{
    time_t      now;
    ngx_uint_t  suppressed;

    if (n >= 0) {
        return 0;
    }

    now = ngx_time();

    if (ngx_http_zstd_static_dio_err_window_start == 0
        || now < ngx_http_zstd_static_dio_err_window_start
        || now - ngx_http_zstd_static_dio_err_window_start
               >= NGX_HTTP_ZSTD_STATIC_DIO_ERR_WINDOW)
    {
        suppressed = ngx_http_zstd_static_dio_err_suppressed;
        ngx_http_zstd_static_dio_err_window_start = now;
        ngx_http_zstd_static_dio_err_suppressed = 0;
        return suppressed;
    }

    ngx_http_zstd_static_dio_err_suppressed++;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "zstd static: directio probe error suppressed "
                   "(%ui so far this window)",
                   ngx_http_zstd_static_dio_err_suppressed);

    return (ngx_uint_t) -1;
}
#endif


typedef struct {
    ngx_uint_t  enable;
    ngx_flag_t  dict_bypass;
} ngx_http_zstd_static_conf_t;


/*
 * Combined allocation for the response ngx_buf_t and the ngx_file_t it
 * points b->file at (see the handler's static-GET body-buffer setup).
 * The two objects share this response's lifetime and are freed together
 * with r->pool, so one ngx_pcalloc() of this wrapper replaces the
 * ngx_calloc_buf() + ngx_pcalloc(sizeof(ngx_file_t)) pair without
 * changing zero-initialization, alignment or failure behaviour: either
 * both members exist, zeroed, or the allocation failed and neither does.
 */
typedef struct {
    ngx_buf_t   buf;
    ngx_file_t  file;
} ngx_http_zstd_static_buf_t;


typedef struct {
    /*
     * Conservative "could this cycle possibly serve a precompressed
     * .zst file" latch for ngx_http_zstd_static_init() (TODO row: skip
     * appending the always-declining content-phase handler when
     * zstd_static is off in every merged location). Latched at
     * DIRECTIVE PARSE TIME by ngx_http_zstd_static_set_enable_slot()
     * whenever "zstd_static on;" or "zstd_static always;" is parsed
     * anywhere in the config — main, srv, or loc. Unlike the filter
     * module's "zstd" directive, "zstd_static"'s command flags (above)
     * do not include NGX_HTTP_LIF_CONF, so nginx's config parser itself
     * refuses it inside a rewrite-phase "if" block; there is no "if"
     * loc conf case to reason about here. Latching at parse time rather
     * than the location-conf merge walk is still the conservative
     * choice for the same reason as the filter module: a false positive
     * (installing the handler when every merged location stays off)
     * only costs the handler's own early return, while a false negative
     * would silently stop precompressed files being served. Independent
     * of, and never influencing, the filter module's own any_enabled
     * bit — the two modules latch separately.
     */
    ngx_flag_t  any_enabled;

    /*
     * "zstd_static_dict_bypass on" parsed anywhere in the config,
     * latched at directive parse time by
     * ngx_http_zstd_static_set_dict_bypass_slot() — same conservative
     * shape as any_enabled above. Read once by
     * ngx_http_zstd_static_init() to decide whether the
     * bypass-without-filter warning below applies to this cycle at
     * all.
     */
    ngx_flag_t  dict_bypass_enabled;
} ngx_http_zstd_static_main_conf_t;


static ngx_conf_enum_t  ngx_http_zstd_static[] = {
    { ngx_string("off"), NGX_HTTP_ZSTD_STATIC_OFF },
    { ngx_string("on"), NGX_HTTP_ZSTD_STATIC_ON },
    { ngx_string("always"), NGX_HTTP_ZSTD_STATIC_ALWAYS },
    { ngx_null_string, 0 }
};


static char * ngx_http_zstd_static_set_enable_slot(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char * ngx_http_zstd_static_set_dict_bypass_slot(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_http_zstd_static_commands[] = {

    { ngx_string("zstd_static"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_zstd_static_set_enable_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zstd_static_conf_t, enable),
      &ngx_http_zstd_static },

    { ngx_string("zstd_static_dict_bypass"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_http_zstd_static_set_dict_bypass_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zstd_static_conf_t, dict_bypass),
      NULL },

    ngx_null_command
};


static ngx_int_t ngx_http_zstd_static_handler(ngx_http_request_t *r);
static ngx_uint_t ngx_http_zstd_static_should_bypass(ngx_http_request_t *r);
static void * ngx_http_zstd_static_create_main_conf(ngx_conf_t *cf);
static void * ngx_http_zstd_static_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_zstd_static_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_zstd_static_init(ngx_conf_t *cf);


static ngx_http_module_t  ngx_http_zstd_static_module_ctx = {
    NULL,                                     /* preconfiguration */
    ngx_http_zstd_static_init,                /* postconfiguration */

    ngx_http_zstd_static_create_main_conf,    /* create main configuration */
    NULL,                                     /* init main configuration */

    NULL,                                     /* create server configuration */
    NULL,                                     /* merge server configuration */

    ngx_http_zstd_static_create_loc_conf,  /* create location configuration */
    ngx_http_zstd_static_merge_loc_conf,      /* merge location configuration */
};


ngx_module_t  ngx_http_zstd_static_module = {
    NGX_MODULE_V1,
    &ngx_http_zstd_static_module_ctx,       /* module context */
    ngx_http_zstd_static_commands,          /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


#if (NGX_HTTP_ZSTD_STATIC_HAVE_PROBE)


/*
 * The probe's only platform-dependent step: fetch up to `size` bytes
 * from `offset` WITHOUT moving the descriptor's file position.
 *
 * Everything above this line — the magic check, the window arithmetic,
 * the skippable-frame length — and everything the caller does with the
 * verdicts is shared, byte for byte, between POSIX and Win32. Only the
 * fetch differs, which is the point: a second copy of the verdict logic
 * is how two platforms drift until one of them stops rejecting what the
 * other rejects (that drift is precisely the hole this function closes:
 * before it, Win32 served .zst files with no magic check, no window
 * guard and no skippable-chain bound at all).
 *
 * Returns the byte count read, or -1 on error, matching pread(2)'s
 * convention so the caller's short-read handling is unchanged. On POSIX
 * it retries EINTR and accumulates across legal short reads rather than
 * handing either straight back -- see the loop's own comment, including
 * why `align` (the O_DIRECT block size, or 0 for a buffered read) has to
 * be a parameter. `log`
 * and `name` are only used by the Win32 branch, which routes through
 * ngx_read_file() and therefore needs an ngx_file_t to describe the
 * descriptor (`name` only ever reaches ngx_read_file()'s own error log
 * line); on POSIX both are unused.
 */
static ssize_t
ngx_http_zstd_static_pread(ngx_fd_t fd, u_char *buf, size_t size,
    off_t offset, size_t align, ngx_log_t *log, ngx_str_t *name)
{
#if (NGX_WIN32)

    ssize_t      n;
    ngx_file_t   file;

    /*
     * `align` is POSIX-only. ngx_directio_on() is an upstream no-op stub
     * on Win32, so no descriptor here is ever really O_DIRECT and
     * ngx_read_file() has no alignment constraint to satisfy; it also
     * loops internally, so the EINTR/short-read accumulation the POSIX
     * branch adds below is already handled by the call itself.
     */
    (void) align;

    /*
     * A stack ngx_file_t borrowing the cached fd. The Win32
     * ngx_read_file() passes an OVERLAPPED carrying the explicit
     * offset to ReadFile(), so the read is positioned by argument
     * rather than by the handle's own pointer, and the only offset it
     * advances is file.offset — this local, discarded on return.
     *
     * That this is safe on a descriptor shared between concurrent
     * requests is not a deduction from the API docs alone: nginx's own
     * copy filter (src/core/ngx_output_chain.c, ngx_read_file() on
     * src->file) reads every static file body through exactly this
     * call, against exactly this open_file_cache descriptor, on every
     * Windows build. If an OVERLAPPED read here could disturb another
     * in-flight request on the same cached fd, Windows nginx could not
     * serve static files at all.
     */
    ngx_memzero(&file, sizeof(ngx_file_t));

    file.fd = fd;
    file.log = log;
    file.name = *name;

    n = ngx_read_file(&file, buf, size, offset);

    /*
     * ngx_read_file() returns NGX_ERROR (-1) on failure, having already
     * logged the ReadFile() error itself, and 0 at EOF. Both are short
     * reads to the caller, which declines — fail closed. NGX_ERROR is
     * -1 so the value passes through unchanged; assert that here rather
     * than assume it, since the caller's `n < 4` test is what turns
     * this into a decline.
     */
    if (n == NGX_ERROR) {
        return -1;
    }

    return n;

#else

    size_t   done;
    size_t   prev;   /* last aligned resume point; see the loop's guard */
    ssize_t  n;

    (void) log;
    (void) name;

    /*
     * Retry/accumulate loop. ONE pread(2) is not enough: the syscall may
     * be interrupted by a signal before transferring anything (EINTR),
     * and a positioned read on a regular file is permitted to return
     * fewer bytes than requested. Neither is an error, and neither means
     * the file is bad -- but returning them verbatim made the caller
     * DECLINE an otherwise perfectly valid .zst, so a signal or a
     * short-reading filesystem (9p/drvfs/FUSE, a WSL /mnt/c document
     * root) turned into a 404 plus an error-log line.
     *
     * This is the same shape as ngx_http_zstd_read_dict_file() in the
     * filter module, which already loops for exactly these two reasons;
     * see its comment for the EINTR/short-read argument in full. This
     * one is deliberately written to match it rather than invent a
     * second pattern, with one addition the dictionary loader does not
     * need: O_DIRECT alignment.
     *
     * DIRECT I/O ALIGNMENT -- why `align` exists.
     *
     * This probe runs on an O_DIRECT descriptor whenever the file was
     * opened with directio. O_DIRECT constrains the buffer address, the
     * file offset AND the length, all to the device's block size. The
     * caller satisfies that on the FIRST read: `buf` comes from
     * ngx_http_zstd_static_dio_buf() aligned to `align`, `offset` is
     * rounded down to `align`, and `size` is 2 * align.
     *
     * A naive continuation at buf + n / offset + n after a short read
     * would break all three at once, and the kernel would answer EINVAL
     * -- turning a recoverable short read into the very decline this
     * change exists to remove. So resumption is rounded DOWN to an
     * `align` boundary: `done` only ever advances in whole multiples of
     * `align`, which keeps buf + done aligned (buf is align-aligned),
     * offset + done aligned (offset is align-aligned), and size - done a
     * multiple of align (size is 2 * align). Every continuation read is
     * therefore exactly as O_DIRECT-legal as the first one was.
     *
     * The cost is re-reading the sub-block tail of a short read. That is
     * bounded by align (<= NGX_HTTP_ZSTD_STATIC_DIO_PROBE_MAX, 64 KB),
     * idempotent -- the probe is read-only and parses only after the
     * loop -- and only paid on a path that would previously have failed
     * outright. Correctness over a byte count nobody serves.
     *
     * align == 0 selects the buffered path: the round-down is a no-op
     * (see the guard below) and this is a plain accumulate, which is
     * what the small buffered hdrbuf read wants.
     *
     * Returns the total bytes accumulated (0 at immediate EOF), or -1 on
     * a hard error, matching pread(2)'s convention so the caller's
     * short-read handling is unchanged. A read that reaches true EOF
     * with fewer than `size` bytes returns the partial count and lets the
     * caller decide -- it must, because a file legitimately shorter than
     * the 2-block directio probe is the common case, not a failure.
     */

    prev = 0;

    for (done = 0; done < size; /* void */) {

        n = pread(fd, (void *) (buf + done), size - done,
                  offset + (off_t) done);

        if (n < 0) {
            /*
             * Interrupted before transferring anything: not an error,
             * reissue. ngx_errno is read immediately so nothing between
             * here and the test can clobber it. POSIX-only by
             * construction -- this whole branch is the #else of
             * NGX_WIN32, and win32's ngx_errno.h defines no NGX_EINTR
             * because ReadFile() on a synchronous handle is not
             * interruptible.
             */
            if (ngx_errno == NGX_EINTR) {
                continue;
            }

            /*
             * A hard error after a partial transfer still reports -1.
             * The caller declines on -1, which is the fail-CLOSED
             * direction and the one this function must keep: bytes we
             * could not finish reading must never be parsed as if they
             * were a complete header.
             */
            return -1;
        }

        if (n == 0) {
            /* True EOF. Return what we have; the caller bounds-checks. */
            break;
        }

        done += (size_t) n;

        /*
         * Round the resume point down to an `align` boundary so the next
         * pread() stays O_DIRECT-legal in buffer, offset and length. See
         * the alignment argument above. `align` is 0 on the buffered
         * path, where no rounding is wanted or valid.
         */
        if (align > 1) {
            size_t  aligned = done - (done % align);

            /*
             * TERMINATION, and it is not optional. `prev` is always a
             * multiple of `align` (it is either 0 or the result of a
             * previous round-down), so `aligned == prev` exactly when
             * this read delivered fewer than `align` bytes -- i.e. it
             * did not complete another whole block. Resuming there
             * re-issues the IDENTICAL pread(), and a filesystem that
             * keeps answering the same sub-block count would spin this
             * loop forever, hanging the worker on this request.
             *
             * A hung worker is far worse than the decline this function
             * exists to avoid, so no-forward-progress gives up and
             * reports the partial count. The caller then declines --
             * exactly where this path went BEFORE the retry loop
             * existed, so the fail-closed behaviour is preserved
             * unchanged for the one case the loop cannot advance past.
             *
             * Testing `aligned == prev` rather than `aligned == 0` is
             * the whole guard: `aligned == 0` only catches a stall on
             * the FIRST iteration and lets a stall at any later block
             * boundary loop unbounded.
             */
            if (aligned == prev) {
                done = prev + (size_t) n;   /* report what really landed */
                break;
            }

            done = aligned;
        }

        prev = done;
    }

    return (ssize_t) done;

#endif
}


/*
 * Worker/cycle-lifetime scratch buffer for the directio frame probe.
 *
 * The probe's aligned read exists only to inspect an 18-byte frame
 * header; every byte it reads is discarded the moment
 * ngx_http_zstd_static_probe_frame() returns. Before #208 capped the
 * probe alignment, the buffer's size tracked an operator-controlled,
 * unbounded "directio_alignment", which made a reusable buffer an
 * unbounded-growth hazard; now that the alignment is clamped to
 * NGX_HTTP_ZSTD_STATIC_DIO_PROBE_MAX (see its comment), the largest
 * possible request is the fixed NGX_HTTP_ZSTD_STATIC_DIO_SCRATCH_MAX, so
 * one lazily-grown buffer can serve every request this worker process
 * ever probes under directio, instead of an aligned r->pool allocation
 * (and its implicit free at request end) on every single hit.
 *
 * SAFETY — single-threaded reuse: nginx's event loop runs exactly one
 * content-phase handler body at a time per worker process; this probe
 * is entirely synchronous (a direct pread(2)/ReadFile() via
 * ngx_http_zstd_static_pread(), never posted through a thread pool —
 * "aio threads" and core's own AIO read govern the RESPONSE BODY copy in
 * ngx_output_chain/ngx_http_copy_filter_module, a different code path
 * entirely from this handler-local header probe), so no second request
 * on this worker can be mid-probe while this one is. `busy` still
 * guards that invariant explicitly rather than trusting it silently: if
 * this is ever reached from a path where two probes on the SAME worker
 * really do overlap (a future refactor onto a thread pool, a signal- or
 * reentrant-call path nothing here anticipates), the second caller sees
 * `busy` set and falls back to its own r->pool-scoped ngx_pmemalign()
 * exactly as before this change, rather than corrupting the shared
 * buffer or its bookkeeping.
 *
 * SAFETY — worker/cycle lifetime, not global/cross-reload: this is a
 * file-scope `static`, so it is private per OS PROCESS already — a
 * config reload always forks NEW worker processes (the old ones drain
 * and exit; nginx does not mutate a running worker's cycle in place),
 * and each process gets its own zero-initialized copy of this storage
 * at fork/exec. There is no path by which an old worker's buffer
 * pointer is visible to, or reused by, a new one: they do not share an
 * address space. Freed automatically at worker exit with the rest of
 * the process image — nothing to release explicitly, and nothing for
 * LSan-at-exit to flag as a leak, since a live, still-reachable
 * file-scope pointer is not a leak.
 */
static u_char  *ngx_http_zstd_static_dio_scratch;
static size_t   ngx_http_zstd_static_dio_scratch_cap;
static size_t   ngx_http_zstd_static_dio_scratch_align;
static ngx_uint_t  ngx_http_zstd_static_dio_scratch_busy;

/*
 * Returns a buffer of at least `want` bytes, aligned to `align`, good
 * until the next call on this worker — NOT scoped to `pool`, unlike
 * every other allocation in this file. `pool` is used only for the
 * fallback path (request-scoped, exactly the pre-existing behaviour),
 * so the two return values must not be told apart by the caller: both
 * are simply "a buffer of at least `want` bytes", freed differently.
 *
 * `want` is never above NGX_HTTP_ZSTD_STATIC_DIO_SCRATCH_MAX in this
 * file (the caller derives it from the same clamped `align`), so the
 * scratch buffer converges to that fixed size after its first directio
 * hit and is never grown again; a caller from outside this file passing
 * a larger `want` still gets a correctly-sized buffer, just not a
 * reused one.
 *
 * Reallocates on an ALIGNMENT decrease too, not just a capacity
 * increase: `align` in this file only ever takes NGX_HTTP_ZSTD_STATIC_
 * DIO_PROBE (4096) or _DIO_PROBE_MAX (65536), and 65536 is a multiple
 * of 4096, so in practice a cached 65536-aligned buffer would already
 * satisfy a later 4096-aligned request of adequate size. Checking
 * `align` explicitly here means that property never has to be reasoned
 * about at every call site, or re-verified if either constant's value
 * ever changes: a cached buffer is reused only when it is provably
 * aligned for the CURRENT request, not merely large enough.
 */
static u_char *
ngx_http_zstd_static_dio_buf(ngx_pool_t *pool, size_t want, size_t align)
{
    u_char  *p;

    if (ngx_http_zstd_static_dio_scratch_busy) {
        return ngx_pmemalign(pool, want, align);
    }

    if (ngx_http_zstd_static_dio_scratch_cap < want
        || ngx_http_zstd_static_dio_scratch_align < align)
    {
        /*
         * ngx_cycle->pool, not r->pool: worker-lifetime storage, freed
         * automatically when this worker's cycle pool is destroyed at
         * process exit, and untouched by any single request's pool
         * being reset or destroyed. NOT ngx_pmemalign() into the OLD
         * (too-small) buffer's memory — a fresh allocation, so a probe
         * already using the previous buffer (there cannot be one, see
         * `busy` above, but the allocation itself must not assume it)
         * is never invalidated out from under it.
         */
        p = ngx_pmemalign((ngx_pool_t *) ngx_cycle->pool, want, align);
        if (p == NULL) {
            return ngx_pmemalign(pool, want, align);
        }

        ngx_http_zstd_static_dio_scratch = p;
        ngx_http_zstd_static_dio_scratch_cap = want;
        ngx_http_zstd_static_dio_scratch_align = align;
    }

    ngx_http_zstd_static_dio_scratch_busy = 1;

    return ngx_http_zstd_static_dio_scratch;
}

/*
 * Pairs with ngx_http_zstd_static_dio_buf(): clears `busy` so the next
 * request on this worker can reuse the scratch buffer. A no-op when the
 * caller actually got a pool-scoped fallback buffer instead (busy was
 * never set in that case), which is why this is safe to call
 * unconditionally from every return path after the probe, including the
 * error/decline ones.
 */
static void
ngx_http_zstd_static_dio_buf_release(void)
{
    ngx_http_zstd_static_dio_scratch_busy = 0;
}

#endif /* NGX_HTTP_ZSTD_STATIC_HAVE_PROBE */


static ngx_uint_t
ngx_http_zstd_static_should_bypass(ngx_http_request_t *r)
{
    /*
     * Do not validate Available-Dictionary or consult the configured
     * dictionary store here: those are filter-owned policy.  This cheap
     * routing predicate only asks whether the filter should get the request.
     */
    ngx_uint_t        i, avail_dict_count;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *headers;

    avail_dict_count = 0;

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

        /*
         * Case-SENSITIVE ngx_memcmp against a lowercase literal when nginx
         * supplied lowcase_key. Headers inserted by another module may leave
         * that optional pointer NULL, so retain the case-folding fallback.
         * Core-parsed headers already carry the folded form (see
         * ngx_http_zstd_collect_dcz_headers() in the filter module for
         * the per-protocol citations), so re-folding with
         * ngx_strncasecmp() would redo work nginx has already done, once
         * per header per request.
         */
        if (headers[i].key.len == sizeof("available-dictionary") - 1
            && ((headers[i].lowcase_key != NULL
                 && ngx_memcmp(headers[i].lowcase_key,
                               "available-dictionary",
                               sizeof("available-dictionary") - 1) == 0)
                || (headers[i].lowcase_key == NULL
                    && ngx_strncasecmp(headers[i].key.data,
                                       (u_char *) "Available-Dictionary",
                                       sizeof("Available-Dictionary") - 1)
                       == 0)))
        {
            avail_dict_count++;
            if (avail_dict_count > 1) {
                return 0;
            }
        }
    }

    /*
     * Match the filter's fail-closed disposition (see
     * ngx_http_zstd_collect_dcz_headers() / avail_dict_count > 1 in
     * ngx_http_zstd_filter_module.c): stand aside only when exactly one
     * Available-Dictionary header is present. Zero means there is
     * nothing to serve dcz for; two or more is the ambiguous case the
     * filter refuses outright, so this routing predicate must not bypass
     * to it either -- doing so would forfeit a usable .zst sidecar for
     * dynamic zstd or identity when the filter later declines.
     */
    if (avail_dict_count != 1) {
        return 0;
    }

    return ngx_http_zstd_request_coding_weight(r, "dcz",
               sizeof("dcz") - 1, 0) > 0;
}


#if (NGX_HTTP_ZSTD_STATIC_HAVE_PROBE)

/*
 * Returns the cached verdict for this exact (path, uniq, mtime, size), or
 * NGX_HTTP_ZSTD_STATIC_VERDICT_NONE when the probe must run. A stored entry
 * whose identity no longer matches simply does not match -- it is never
 * refreshed in place, so a rewritten file cannot inherit the previous
 * file's verdict; it misses, gets a fresh probe, and the new verdict is
 * inserted at the round-robin cursor like any other.
 */
static ngx_uint_t
ngx_http_zstd_static_cached_verdict(ngx_str_t *path, ngx_open_file_info_t *of,
    time_t now, time_t good_valid)
{
    ngx_uint_t                             i;
    ngx_http_zstd_static_verdict_cache_t  *entry;

    if (path->len >= NGX_MAX_PATH) {
        return NGX_HTTP_ZSTD_STATIC_VERDICT_NONE;
    }

    if (ngx_http_zstd_static_verdict_cache_count == 0) {
        return NGX_HTTP_ZSTD_STATIC_VERDICT_NONE;
    }

    for (i = 0; i < ngx_http_zstd_static_verdict_cache_count; i++) {
        entry = &ngx_http_zstd_static_verdict_cache[i];

        if (entry->valid != NGX_HTTP_ZSTD_STATIC_VERDICT_NONE
            && entry->uniq == of->uniq
            && entry->mtime == of->mtime && entry->size == of->size
            && entry->len == path->len
            && ngx_memcmp(entry->path, path->data, path->len) == 0)
        {
            if (entry->valid == NGX_HTTP_ZSTD_STATIC_VERDICT_GOOD
                && (good_valid == 0 || now < entry->checked
                    || now - entry->checked >= good_valid))
            {
                /*
                 * Retire the stale entry before continuing.  The caller
                 * records a freshly probed verdict at the ring cursor; if
                 * this matching stale entry remained live and returned
                 * immediately, it could mask that newer duplicate on every
                 * lookup until the cursor eventually evicted it.
                 */
                entry->valid = NGX_HTTP_ZSTD_STATIC_VERDICT_NONE;
                continue;
            }

            return entry->valid;
        }
    }

    return NGX_HTTP_ZSTD_STATIC_VERDICT_NONE;
}


/*
 * Record `verdict` (BAD or GOOD) for this file identity, evicting the entry
 * at the round-robin cursor. Never called with VERDICT_NONE: a caller with
 * nothing to record must not consume a slot.
 */
static void
ngx_http_zstd_static_remember(ngx_str_t *path, ngx_open_file_info_t *of,
    ngx_uint_t verdict, time_t now, time_t good_valid)
{
    ngx_http_zstd_static_verdict_cache_t  *entry;

    if (path->len >= NGX_MAX_PATH
        || (verdict == NGX_HTTP_ZSTD_STATIC_VERDICT_GOOD && good_valid == 0))
    {
        return;
    }

    entry = &ngx_http_zstd_static_verdict_cache[
                ngx_http_zstd_static_verdict_cache_next];
    entry->uniq = of->uniq;
    entry->mtime = of->mtime;
    entry->checked = now;
    entry->size = of->size;
    entry->len = path->len;
    ngx_memcpy(entry->path, path->data, path->len);
    if (entry->valid == NGX_HTTP_ZSTD_STATIC_VERDICT_NONE) {
        if (ngx_http_zstd_static_verdict_cache_count
            < NGX_HTTP_ZSTD_STATIC_VERDICT_CACHE_SLOTS)
        {
            ngx_http_zstd_static_verdict_cache_count++;
        }
    }

    entry->valid = verdict;

    ngx_http_zstd_static_verdict_cache_next++;
    if (ngx_http_zstd_static_verdict_cache_next
        == NGX_HTTP_ZSTD_STATIC_VERDICT_CACHE_SLOTS)
    {
        ngx_http_zstd_static_verdict_cache_next = 0;
    }
}


/*
 * Magic-number sanity check on the .zst file.
 *
 * Without this, a truncated, half-downloaded, mistakenly-renamed
 * (e.g. `cp foo.txt foo.zst`), or otherwise non-zstd file would be
 * served with `Content-Encoding: zstd` and the client would get an
 * undecodable body — a confusing outage class that nginx's built-in
 * gzip_static also doesn't defend against. The probe is cheap (one
 * offset-explicit read of the frame-header prefix at offset 0 — 18
 * bytes, or a pair of aligned blocks under directio — via
 * ngx_http_zstd_static_pread(): pread(2) on POSIX, ngx_read_file()
 * on Win32, both of which take the offset as an argument and so
 * never move the open_file_cache's shared fd position. Using plain
 * read(2)/SetFilePointer would do exactly that and corrupt
 * subsequent requests serving the same cached fd). On mismatch we
 * decline, so nginx falls back to serving the uncompressed original (or
 * returns 404 if it is absent), and the operator sees a clear
 * error log line.
 *
 * Both a regular zstd frame (ZSTD_MAGICNUMBER) and a skippable
 * frame (ZSTD_MAGIC_SKIPPABLE_START..+0xF) are accepted, since
 * either is a valid leading frame in a zstd stream.
 *
 * Gated by NGX_HTTP_ZSTD_STATIC_HAVE_PROBE (see its definition):
 * compiled in on Win32 and on any POSIX build whose configure found
 * pread(2). On a POSIX build WITHOUT pread(2) the probe is skipped
 * rather than degraded to a read+lseek pair that would mutate the
 * shared fd offset — every modern POSIX target has it, so that
 * branch is essentially a build-time tripwire.
 *
 * The probe deliberately runs on Win32 too. It used to be compiled
 * out there, which meant a Windows build served ANY .zst with no
 * magic check, no truncation check, no 8 MB window guard and no
 * skippable-frame chain bound — a strictly weaker validation than
 * the POSIX build, on a target the Windows build CI ships. The
 * verdict logic is shared, so the two platforms cannot drift apart
 * again; only the byte fetch differs.
 *
 * When the file was opened with O_DIRECT (of.is_directio, set by
 * ngx_open_cached_file when "directio <size>" is configured and the
 * file meets the threshold), BOTH the read offset and the length
 * must be block-aligned, so the probe rounds each frame offset down
 * to directio_alignment CLAMPED to
 * [NGX_HTTP_ZSTD_STATIC_DIO_PROBE, NGX_HTTP_ZSTD_STATIC_DIO_PROBE_MAX]
 * and reads two such blocks into an equally-aligned pool buffer,
 * parsing the frame at its offset inside them. The clamp follows the
 * operator's declared geometry only as far as a header probe can
 * use it: the floor is what keeps the read legal on 512-byte and
 * 4K-native devices, and the ceiling is why an unbounded
 * "directio_alignment" cannot turn an 18-byte header check into a
 * multi-megabyte allocation and O_DIRECT read on every request that
 * reaches the probe. Rounding the OFFSET is what the skippable-frame
 * walk needs:
 * the second and later probes are at whatever offset the previous
 * frame's declared length produced (40 for a canonical dcz prefix),
 * which an O_DIRECT descriptor rejects with EINVAL if passed raw.
 *
 * The window check in particular must not be skipped under
 * directio: oversized declared windows are a
 * systematic build-pipeline product, not rare corruption, and every
 * browser rejects them. If the aligned read STILL fails, the file
 * is DECLINED, not served: for a validation read, falling back to
 * another encoding is safer than certifying a file we could not
 * inspect, and the error log tells the operator which knob
 * (directio_alignment) disagrees with the device. On Win32
 * ngx_directio_on() is an upstream no-op stub, so of.is_directio
 * only ever reflects the operator's "directio" directive there and
 * the aligned path costs one pool allocation with no behavioural
 * difference — it is left shared rather than forked, because a
 * Win32-only bypass of this branch is exactly the kind of split
 * that reintroduces the gap this change closes.
 */
static ngx_int_t
ngx_http_zstd_static_probe_verdict(const u_char *frame, size_t avail,
    off_t file_size, off_t *pos, ngx_str_t *path, ngx_log_t *log)
{
    uint64_t   window, skip;

    switch (ngx_http_zstd_static_probe_frame(frame, avail, &window)) {

    case NGX_HTTP_ZSTD_STATIC_FRAME_NOT_ZSTD:
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "zstd static: \"%s\" is not a zstd frame "
                      "(leading bytes 0x%02xd%02xd%02xd%02xd)",
                      path->data,
                      (unsigned) frame[0], (unsigned) frame[1],
                      (unsigned) frame[2], (unsigned) frame[3]);
        return NGX_DECLINED;

    case NGX_HTTP_ZSTD_STATIC_FRAME_TRUNCATED:
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "zstd static: \"%s\" frame header truncated",
                      path->data);
        return NGX_DECLINED;

    case NGX_HTTP_ZSTD_STATIC_FRAME_WINDOW_BIG:
        /*
         * "8 MB" and "window log <= 23" below are prose, not
         * derived: they must be updated by hand whenever
         * NGX_HTTP_ZSTD_STATIC_MAX_WINDOW changes.
         */
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "zstd static: \"%s\" declares a %uL-byte "
                      "decompression window, above the 8 MB limit "
                      "browsers enforce for Content-Encoding: zstd "
                      "(RFC 8878) -- declining so a fallback "
                      "encoding is used; recompress with a window "
                      "log <= 23 (streaming encoders default to "
                      "the compression level's window when not "
                      "told the input size)",
                      path->data, window);
        return NGX_DECLINED;

    case NGX_HTTP_ZSTD_STATIC_FRAME_RESERVED:
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "zstd static: \"%s\" frame header sets reserved "
                      "Frame_Header_Descriptor bit 0x08 -- declining "
                      "static variant",
                      path->data);
        return NGX_DECLINED;

    case NGX_HTTP_ZSTD_STATIC_FRAME_SKIP:
        /*
         * `window` carries the declared skip length here (see
         * the probe's doc comment). Prove the 8-byte skippable
         * header AND the full declared skip both fit within the
         * file before trusting the jump.
         */
        skip = window;

        if ((uint64_t) *pos > (uint64_t) file_size
            || (uint64_t) file_size - (uint64_t) *pos < 8)
        {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "zstd static: \"%s\" skippable frame "
                          "header runs past end of file",
                          path->data);
            return NGX_DECLINED;
        }

        if (skip > (uint64_t) file_size - (uint64_t) *pos - 8) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "zstd static: \"%s\" skippable frame "
                          "declares a %uL-byte skip past end of "
                          "file", path->data, skip);
            return NGX_DECLINED;
        }

        *pos += (off_t) 8 + (off_t) skip;

        return NGX_AGAIN;

    default:
        return NGX_OK;
    }
}


static ngx_uint_t
ngx_http_zstd_static_probe_read_log_level(ssize_t n, ngx_uint_t directio,
    ngx_err_t *err)
{
    if (n >= 0) {
        *err = 0;
        return NGX_LOG_ERR;
    }

    *err = ngx_errno;
    return directio ? NGX_LOG_ERR : NGX_LOG_CRIT;
}


static ngx_int_t
ngx_http_zstd_static_probe_file(ngx_http_request_t *r,
    const ngx_http_core_loc_conf_t *clcf, ngx_open_file_info_t *of,
    ngx_str_t *path, ngx_log_t *log, ngx_uint_t *malformed)
{
    /*
     * 58 bytes covers a canonical 40-byte dcz skippable prefix plus
     * the largest possible 18-byte frame header. This lets the common
     * two-frame shape reuse one read while leaving enough room for the
     * standalone maximum header. Short files return fewer bytes; each
     * parse path checks it got what that frame layout requires.
     */
    u_char       hdrbuf[58];
    u_char      *hdr, *frame;
    size_t       want, align, frame_off, avail, got, need;
    ssize_t      n;
    ngx_uint_t   frames, scratch, have_block, reuse, read_log_level;
    ngx_err_t    read_err;
    off_t        pos, base, have_base;
    ngx_int_t    probe_rc;

    *malformed = 0;

    if (of->size < 4) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "zstd static: \"%s\" too small to be a zstd frame "
                      "(%O bytes)", path->data, of->size);
        *malformed = 1;
        return NGX_DECLINED;
    }

    scratch = 0;
    have_block = 0;
    have_base = 0;
    n = 0;

    if (of->is_directio) {
        /*
         * Clamped to [PROBE, PROBE_MAX]. The floor keeps the read
         * O_DIRECT-legal on 512-byte and 4K-native devices and
         * leaves room for a frame header behind any in-block start;
         * the ceiling stops an unbounded "directio_alignment" from
         * scaling a header probe that never needs more than 18
         * bytes. See NGX_HTTP_ZSTD_STATIC_DIO_PROBE_MAX.
         */
        align = NGX_HTTP_ZSTD_STATIC_DIO_PROBE;
        if ((size_t) clcf->directio_alignment > align) {
            align = (size_t) clcf->directio_alignment;
        }
        if (align > NGX_HTTP_ZSTD_STATIC_DIO_PROBE_MAX) {
            align = NGX_HTTP_ZSTD_STATIC_DIO_PROBE_MAX;
        }

        /*
         * TWO blocks, not one. The probe offset is rounded down to
         * `align` (an O_DIRECT descriptor rejects an unaligned file
         * offset with EINVAL), so a frame header can start as late
         * as `align - 1` bytes into the first block and would then
         * straddle the boundary — parsing only one block would
         * report that legitimate frame as truncated. A second block
         * guarantees at least `align` (>= 4096) bytes behind any
         * in-block start position, far more than the 18 a frame
         * header can need. Both the length and the buffer stay
         * `align`-aligned, which is what O_DIRECT requires.
         */
        want = align * 2;

        /*
         * Worker-lifetime scratch buffer instead of a fresh
         * ngx_pmemalign(r->pool, ...) on every directio hit — see
         * ngx_http_zstd_static_dio_buf()'s own comment for the
         * sizing and reentrancy argument. `scratch` remembers
         * whether THIS call actually got the shared buffer (vs. a
         * pool fallback), so the single release point below only
         * clears the reuse guard when it was this call that set it.
         */
        hdr = ngx_http_zstd_static_dio_buf(r->pool, want, align);
        if (hdr == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        scratch = (hdr == ngx_http_zstd_static_dio_scratch);

    } else {
        align = 0;
        hdr = hdrbuf;
        want = sizeof(hdrbuf);
    }

    pos = 0;

    /*
     * Walk a bounded chain of leading skippable frames to reach the
     * first regular frame, so the window guard below cannot be
     * dodged by prepending one (see NGX_HTTP_ZSTD_STATIC_FRAME_SKIP
     * and NGX_HTTP_ZSTD_STATIC_MAX_SKIP_FRAMES).
     *
     * Each iteration reads at the current offset. Under directio
     * the O_DIRECT descriptor rejects an unaligned file offset with
     * EINVAL, and `pos` after a leading skippable frame is whatever
     * that frame's length made it (40 for the canonical dcz
     * SHA-256 prefix) — almost never a multiple of the block size.
     * So the read offset is rounded DOWN to the alignment and the
     * frame is parsed at its offset inside the block: `base` is the
     * aligned read offset, `frame_off` the distance from there to
     * `pos`, and `avail` the bytes of that block that actually lie
     * at or after `pos`. Off the directio path `base == pos`,
     * `frame_off == 0` and this is byte-for-byte the previous
     * behaviour.
     */
    for (frames = 0; ; frames++) {

        if (of->is_directio) {
            frame_off = (size_t) ((uint64_t) pos % (uint64_t) align);
            base = pos - (off_t) frame_off;

        } else {
            frame_off = 0;
            base = pos;
        }

        need = (size_t) ngx_min((off_t) 18,
                                ngx_max((off_t) 4, of->size - pos));

        reuse = have_block
                && ngx_http_zstd_static_probe_reuse(pos, have_base, n, need,
                                                    &frame_off, &base);

        /*
         * Reuse the block already in `hdr` when this iteration
         * reads the SAME aligned offset and the bytes it needs are
         * inside what the previous read delivered. A skippable
         * frame shorter than `align` leaves `pos` inside the block
         * just read, so `base` is unchanged and the re-read would
         * return byte-for-byte what `hdr` already holds -- the
         * canonical dcz prefix (40-byte frame at offset 0, next
         * frame at 40) with align >= 4096 hits this on every
         * iteration, re-issuing up to 2 * PROBE_MAX of O_DIRECT per
         * skipped frame.
         *
         * The guard above also lets the ordinary 58-byte buffer retain
         * a canonical 40-byte dcz prefix plus the following maximum
         * 18-byte frame header. It requires the whole possible header
         * (or all bytes remaining in a shorter file), so a partial
         * suffix still takes the established offset-read path.
         */
        if (!reuse) {
            n = ngx_http_zstd_static_pread(of->fd, hdr, want, base, align,
                                           log, path);

            if (n > 0) {
                have_block = 1;
                have_base = base;
            }

        } else {
            /*
             * Positive witness that the re-read was elided. Debug
             * level, so it costs nothing in production, but it lets
             * a test assert the optimization actually engaged --
             * serving correctly proves only that the bytes were
             * right, not that they came from the buffer.
             */
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                           "zstd static: reusing %uz-byte block at "
                           "offset %O for next frame", want, base);
        }

        /*
         * Bytes of the block that lie at or after `pos`. A short
         * read that stopped inside the prefix leaves nothing for
         * the frame, which is the same "too few bytes" condition as
         * a short read at offset 0 and takes the same branch.
         */
        got = (size_t) (n > 0 ? n : 0);
        avail = (got > frame_off) ? got - frame_off : 0;

        frame = hdr + frame_off;

        if (n < 0 || avail < 4) {
            read_log_level = ngx_http_zstd_static_probe_read_log_level(
                                 n, of->is_directio, &read_err);

            if (of->is_directio) {
                ngx_uint_t  dio_suppressed;

                if (n >= 0) {
                    ngx_log_error(NGX_LOG_ERR, log, 0,
                                  "zstd static: directio probe on \"%s\" "
                                  "returned %z bytes before a complete "
                                  "frame header -- treating sidecar as "
                                  "malformed",
                                  path->data, n);

                } else {
                    dio_suppressed =
                        ngx_http_zstd_static_dio_err_should_log(log, n);

                    if (dio_suppressed == 0) {
                        ngx_log_error(read_log_level, log, read_err,
                                      "zstd static: %uz-byte aligned probe "
                                      "on directio file \"%s\" returned "
                                      "%z -- declining; check "
                                      "directio_alignment against the "
                                      "device geometry",
                                      align, path->data, n);
                    } else if (dio_suppressed != (ngx_uint_t) -1) {
                        ngx_log_error(read_log_level, log, read_err,
                                      "zstd static: %uz-byte aligned probe "
                                      "on directio file \"%s\" returned "
                                      "%z -- declining; check "
                                      "directio_alignment against the "
                                      "device geometry (%ui more worker-wide "
                                      "occurrence%s suppressed in the "
                                      "last %ds)",
                                      align, path->data, n, dio_suppressed,
                                      dio_suppressed == 1 ? "" : "s",
                                      NGX_HTTP_ZSTD_STATIC_DIO_ERR_WINDOW);
                    }
                }

                probe_rc = NGX_DECLINED;
                *malformed = (n >= 0);
                goto probe_done;
            }

            /*
             * The primitive is named in the log because it is the
             * operator's first clue about which syscall to strace.
             * The POSIX text is preserved verbatim from before the
             * Win32 port so existing log tooling keeps matching;
             * Win32 names ReadFile() instead of claiming a pread(2)
             * it never issued.
             *
             * n >= 0 means the read itself succeeded and simply
             * returned too few bytes (e.g. a sidecar consisting only
             * of skippable frames, n == 0 at offset == size); errno is
             * stale in that case, so log it at ERR with errno 0 rather
             * than CRIT with a misleading ngx_errno. A genuine read
             * failure (n < 0) keeps CRIT and the real ngx_errno.
             */
            ngx_log_error(read_log_level, log, read_err,
                          "zstd static: " NGX_HTTP_ZSTD_STATIC_PREAD_NAME
                          "(\"%s\", frame header) returned %z",
                          path->data, n);
            probe_rc = NGX_DECLINED;
            *malformed = (n >= 0);
            goto probe_done;
        }

        if (of->is_directio) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                           "zstd static: %uz-byte aligned probe on "
                           "directio file \"%s\"", align, path->data);
        }

        probe_rc = ngx_http_zstd_static_probe_verdict(frame, avail, of->size,
                                                      &pos, path, log);
        if (probe_rc == NGX_AGAIN) {
            /*
             * The first four skips are permitted, so probe the frame
             * following the fourth one.  Decline only after observing a
             * fifth skip; rejecting at the top of this loop would reject
             * the regular frame after exactly four skips without probing it.
             */
            if (frames >= NGX_HTTP_ZSTD_STATIC_MAX_SKIP_FRAMES) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "zstd static: \"%s\" has at least %ui "
                              "leading skippable frames -- declining "
                              "rather than searching further for the "
                              "first regular frame",
                              path->data,
                              (ngx_uint_t)
                                  NGX_HTTP_ZSTD_STATIC_MAX_SKIP_FRAMES + 1);
                probe_rc = NGX_DECLINED;
                *malformed = 1;
                goto probe_done;
            }

            continue;
        }

        if (probe_rc != NGX_OK) {
            *malformed = 1;
            goto probe_done;
        }

        break;
    }

    /*
     * Reached only on NGX_HTTP_ZSTD_STATIC_FRAME_OK: the leading
     * frame is a genuine, in-window zstd frame and the file may be
     * served. NGX_OK is not itself a meaningful "keep going"
     * verdict for the caller below (nothing after probe_done reads
     * probe_rc on this path) — it only has to be distinct from
     * NGX_DECLINED/NGX_HTTP_INTERNAL_SERVER_ERROR so a future edit
     * cannot accidentally fall through the release into a stray
     * early return.
     */
    probe_rc = NGX_OK;

probe_done:

    /*
     * Single release point for every exit from this block,
     * including each `goto` above: clears the reuse guard only if
     * THIS call is the one that set it (see `scratch` and
     * ngx_http_zstd_static_dio_buf()'s own comment) — a call that
     * fell back to a pool-scoped buffer never touched the guard and
     * must not clear it out from under a genuinely concurrent
     * caller.
     */
    if (scratch) {
        ngx_http_zstd_static_dio_buf_release();
    }

    return probe_rc;
}

#endif /* NGX_HTTP_ZSTD_STATIC_HAVE_PROBE */


static ngx_int_t
ngx_http_zstd_static_send(ngx_http_request_t *r, ngx_open_file_info_t *of,
    ngx_str_t *path, ngx_log_t *log)
{
    ngx_int_t          rc;
    ngx_buf_t         *b;
    ngx_chain_t        out;
    ngx_table_elt_t   *h;

    r->root_tested = !r->error_page;

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    log->action = (char *) "sending response to client";

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = of->size;
    r->headers_out.last_modified_time = of->mtime;

    if (ngx_http_set_etag(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * ngx_http_set_content_type() uses nginx's URI-extension field, derived
     * from the
     * original URI, not from path. No path manipulation is needed here.
     */
    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    h->hash = 1;
#if (nginx_version >= 1023000)
    h->next = NULL;
#endif
    ngx_str_set(&h->key, "Content-Encoding");
    ngx_str_set(&h->value, "zstd");
    r->headers_out.content_encoding = h;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "zstd static: serving precompressed \"%s\"", path->data);

    /* gzip_static parity: byte ranges address the SELECTED
     * REPRESENTATION (RFC 9110 §14.2) — here the .zst bytes on disk,
     * which a client can fetch, resume and concatenate coherently
     * because the validator is strong and the bytes are stable. That
     * is why gzip_static has always set r->allow_ranges, and ranges
     * only work by opting in: the range filter bails without the
     * flag. The FILTER module's clear_accept_ranges remains correct
     * for the opposite reason — a stream generated on the fly has
     * nothing stable to seek into. */
    r->allow_ranges = 1;

    /* HEAD fast path: send headers only, skip body buffer allocation.
     * r->header_only covers more than HEAD (304/204), so check method
     * explicitly to avoid breaking other status codes. */
    if (r->method == NGX_HTTP_HEAD) {
        return ngx_http_send_header(r);
    }

    /*
     * One ngx_pcalloc() for the ngx_buf_t and its ngx_file_t, instead of
     * ngx_calloc_buf() (itself ngx_pcalloc(pool, sizeof(ngx_buf_t))) plus
     * a second ngx_pcalloc() for b->file: the two objects share the same
     * lifetime (this response) and the same ownership (freed together
     * with the pool), so there is nothing the split allocation buys.
     * Only reached for a non-HEAD GET — the HEAD fast path above returns
     * before this point — so this removes one pool-allocation call per
     * static GET response body, not per request.
     *
     * ngx_http_zstd_static_buf_t is declared solely to size and zero
     * this combined allocation; nothing outside this function names it.
     * Both members keep the same zero-initialized start ngx_calloc_buf()/
     * ngx_pcalloc() gave them, so every field this handler does not set
     * explicitly below (b->pos, b->last, b->temporary, file.offset, ...)
     * is still guaranteed zero.
     */
    {
        ngx_http_zstd_static_buf_t  *wrap;

        wrap = ngx_pcalloc(r->pool, sizeof(ngx_http_zstd_static_buf_t));
        if (wrap == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        b = &wrap->buf;
        b->file = &wrap->file;
    }

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b->file_pos = 0;
    b->file_last = of->size;

    b->in_file = b->file_last ? 1 : 0;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    /* gzip_static parity: a zero-length file served in a subrequest
     * yields a buf with neither in_file nor last_buf — sync marks it
     * so the output chain doesn't reject it as a zero-size buf. Only
     * reachable when the frame-header probe is compiled out (a POSIX
     * build whose configure found no pread(2) — see
     * NGX_HTTP_ZSTD_STATIC_HAVE_PROBE); with the probe active, which
     * now includes Win32, sub-4-byte files never get this far. */
    b->sync = (b->last_buf || b->in_file) ? 0 : 1;

    b->file->fd = of->fd;
    b->file->name = *path;
    b->file->log = log;
    b->file->directio = of->is_directio;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


/*
 * Decide whether this request is a candidate for a precompressed .zst
 * at all, before any filesystem work: method, URI shape, the
 * zstd_static setting, and the RFC 9842 dcz stand-aside. Split out of
 * ngx_http_zstd_static_handler() purely for readability -- the tests,
 * their order, their log lines and their return values are unchanged.
 *
 * Returns NGX_OK to mean "keep going", with the zscf out-param set and
 * the accepts out-param holding the Accept-Encoding verdict the Vary
 * decision needs later. Any other value is the handler return.
 */
static ngx_int_t
ngx_http_zstd_static_negotiate(ngx_http_request_t *r,
    const ngx_http_zstd_static_conf_t **zscfp, ngx_uint_t *accepts)
{
    ngx_int_t                           rc;
    const ngx_http_zstd_static_conf_t  *zscf;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_DECLINED;
    }

    /* Validate URI length before accessing last byte to prevent underflow.
     * While nginx guarantees non-empty URI, add defensive check for safety. */
    if (r->uri.len == 0 || r->uri.data[r->uri.len - 1] == '/') {
        return NGX_DECLINED;
    }

    zscf = ngx_http_get_module_loc_conf(r, ngx_http_zstd_static_module);

    if (zscf->enable == NGX_HTTP_ZSTD_STATIC_OFF) {
        return NGX_DECLINED;
    }

    /*
     * The static content handler runs before the response filter can
     * negotiate RFC 9842 dcz.  With this opt-in, stand aside when the
     * client both presents a dictionary and explicitly accepts dcz, so
     * the ordinary content handler and zstd filter get that opportunity.
     * This deliberately precedes every static Vary/probe side effect,
     * applies to "always" as well as "on", and stays limited to main
     * requests because the dcz filter rejects subrequests.
     */
    if (zscf->dict_bypass && r == r->main
        && ngx_http_zstd_static_should_bypass(r))
    {
        /*
         * Both Vary dimensions are wanted unconditionally here, with no
         * early return in between, so the fused single-walk helper
         * applies cleanly -- see ngx_http_zstd_vary_ae_dcz() in
         * ngx_http_zstd_common.h for what it preserves from the two
         * original calls (duplicate-safety, push shapes, the RFC 9842
         * SS8.3 / shared-cache poisoning reasoning).
         */
        if (ngx_http_zstd_vary_ae_dcz(r, 1) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd static: standing aside for dcz dictionary "
                       "negotiation");
        return NGX_DECLINED;
    }

    if (zscf->enable == NGX_HTTP_ZSTD_STATIC_ON) {
        /*
         * Side-effect-free predicate, NOT ngx_http_zstd_ok(): the latter
         * latches r->gzip_ok = 0, which would suppress a gzip_static / gzip
         * fallback for THIS request even when we go on to decline below
         * (e.g. the .zst file is absent). We only decide here; when we
         * actually serve the .zst the response carries Content-Encoding: zstd,
         * which makes the gzip filter decline on its own.
         */
        rc = ngx_http_zstd_accepts(r);

    } else {
        rc = NGX_OK;
    }

    /*
     * Saved separately from `rc`: this local is reused below for
     * ngx_open_cached_file()'s return, ngx_http_discard_request_body()'s,
     * and others, so the accept-encoding verdict must survive in its own
     * variable to reach the Vary decision after the .zst has been
     * validated (see the emission site near the end of the probe).
     */

    *accepts = (rc == NGX_OK);
    *zscfp = zscf;

    return NGX_OK;
}


static ngx_int_t
ngx_http_zstd_static_handler(ngx_http_request_t *r)
{
    u_char                       *p;
    ngx_int_t                     rc;
    ngx_uint_t                    accepts, malformed, verdict;
    ngx_uint_t                    level;
    time_t                        good_valid;
    size_t                        root;
    ngx_str_t                     path;
    ngx_log_t                    *log;
    ngx_open_file_info_t          of;
    ngx_http_core_loc_conf_t           *clcf;
    const ngx_http_zstd_static_conf_t  *zscf;

    rc = ngx_http_zstd_static_negotiate(r, &zscf, &accepts);
    if (rc != NGX_OK) {
        return rc;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    log = r->connection->log;

    /*
     * Historically this returned early when the client did not accept
     * zstd AND "gzip_vary" was off, on the reasoning that there was
     * then nothing to gain from the stat(): we would decline anyway,
     * and r->gzip_vary would have been cleared by the header filter,
     * so no Vary header could be produced.
     *
     * That shortcut is exactly the caching hazard this module now
     * closes by construction. This module emits "Vary:
     * Accept-Encoding" itself, independent of "gzip_vary", so the
     * probe below is what tells us whether a .zst variant exists — and
     * therefore whether this URI is Accept-Encoding-dependent at all.
     * Skipping it here would serve a Vary-less identity response for
     * precisely the configuration (gzip_vary off) the operator is most
     * likely to be running, and a shared cache would then reuse it for
     * clients that do accept zstd, or reuse an accepting client's
     * stored zstd body for this one.
     *
     * "always" ignores Accept-Encoding and never varies, so it keeps
     * its own shortcut: accepts is forced true for it above, which
     * leaves this test false regardless of gzip_vary.
     */
    if (zscf->enable != NGX_HTTP_ZSTD_STATIC_ON && !accepts) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                       "zstd static: skip, client did not accept zstd");
        return NGX_DECLINED;
    }

    p = ngx_http_map_uri_to_path(r, &path, &root, sizeof(".zst"));
    if (p == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    *p++ = '.';
    *p++ = 'z';
    *p++ = 's';
    *p++ = 't';
    *p = '\0';

    path.len = p - path.data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "http filename: \"%s\"", path.data);

    ngx_memzero(&of, sizeof(ngx_open_file_info_t));

    of.read_ahead = clcf->read_ahead;
    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;

    if (ngx_http_set_disable_symlinks(r, clcf, &path, &of) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
        != NGX_OK)
    {
        switch (of.err) {

        case 0:
            return NGX_HTTP_INTERNAL_SERVER_ERROR;

        case NGX_ENOENT:
        case NGX_ENOTDIR:
        case NGX_ENAMETOOLONG:

            return NGX_DECLINED;

        case NGX_EACCES:
#if (NGX_HAVE_OPENAT)
        case NGX_EMLINK:
        case NGX_ELOOP:
#endif

            level = NGX_LOG_ERR;
            break;

        default:

            level = NGX_LOG_CRIT;
            break;
        }

        ngx_log_error(level, log, of.err,
                      "%s \"%s\" failed", of.failed, path.data);

        return NGX_DECLINED;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "http static fd: %d", of.fd);

    if (of.is_dir) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "http dir");
        return NGX_DECLINED;
    }

#if !(NGX_WIN32) /* the not regular files are probably Unix specific */

    if (!of.is_file) {
        ngx_log_error(NGX_LOG_CRIT, log, 0,
                      "\"%s\" is not a regular file", path.data);

        return NGX_HTTP_NOT_FOUND;
    }

#endif /* !NGX_WIN32 */

#if (NGX_HTTP_ZSTD_STATIC_HAVE_PROBE)
    good_valid = clcf->open_file_cache == NULL
                     ? 0 : clcf->open_file_cache_valid;
    verdict = ngx_http_zstd_static_cached_verdict(&path, &of, ngx_time(),
                                                   good_valid);

    if (verdict == NGX_HTTP_ZSTD_STATIC_VERDICT_BAD) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                       "zstd static: cached malformed verdict for \"%s\"",
                       path.data);
        return NGX_DECLINED;
    }

    if (verdict == NGX_HTTP_ZSTD_STATIC_VERDICT_GOOD) {
        /*
         * Positive witness that the probe was elided; debug level, so it
         * costs nothing in production but lets a test assert the cache
         * actually engaged -- serving correctly proves only that the
         * verdict was right, not that it came from the cache.
         *
         * The probe hands this caller nothing BUT this verdict: its
         * window-size and skippable-chain findings are consumed inside
         * ngx_http_zstd_static_probe_verdict(), which turns each into
         * NGX_DECLINED plus an error-log line. Reaching NGX_OK is the
         * probe's entire output here, so a cached NGX_OK carries
         * everything a fresh one would; nothing downstream re-derives a
         * window cap -- ngx_http_zstd_static_send() only sets
         * Content-Encoding and the body buffer.
         *
         * Skipping the probe also skips ngx_http_zstd_static_dio_buf()
         * entirely, so the scratch buffer's `busy` guard is never taken
         * on this path and cannot be left set: acquire and release stay
         * paired inside ngx_http_zstd_static_probe_file().
         */
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                       "zstd static: cached good frame verdict for \"%s\"",
                       path.data);

    } else {
        rc = ngx_http_zstd_static_probe_file(r, clcf, &of, &path, log,
                                             &malformed);
        if (rc != NGX_OK) {
            if (malformed) {
                ngx_http_zstd_static_remember(&path, &of,
                    NGX_HTTP_ZSTD_STATIC_VERDICT_BAD, ngx_time(), good_valid);
            }
            return rc;
        }

        ngx_http_zstd_static_remember(&path, &of,
                                      NGX_HTTP_ZSTD_STATIC_VERDICT_GOOD,
                                      ngx_time(), good_valid);
    }
#endif /* NGX_HTTP_ZSTD_STATIC_HAVE_PROBE */

    if (zscf->enable == NGX_HTTP_ZSTD_STATIC_ON) {
        /*
         * Reaching here means the .zst on disk survived is_dir,
         * !is_file and (when compiled in) the magic-number/frame-header
         * probe — it is a genuine, usable zstd variant of this URI, so
         * which representation this URI serves now genuinely depends on
         * Accept-Encoding. That is true whether or not THIS client
         * accepts zstd: a shared cache filled by a non-accepting client
         * must not serve that stored identity body to a client that
         * does accept, and one filled by an accepting client must not
         * serve the stored zstd body to one that cannot decode it. So
         * Vary is still emitted on the decline-to-identity path just
         * below — the header list we push onto survives the
         * NGX_DECLINED, landing on whichever response is finally
         * produced — but ONLY now that the .zst has been proven usable.
         * A directory, a non-regular file, a truncated/malformed frame,
         * or an oversized window are not a real negotiated variant: the
         * identity response that follows one of those declines is not
         * Accept-Encoding-dependent and must not claim to be, so none of
         * those earlier bail-outs emit Vary (see m6).
         *
         * Emitted directly rather than requested via r->gzip_vary, so
         * correctness does not depend on the operator's "gzip_vary"
         * directive; duplicate-safe in both of its states. See
         * ngx_http_zstd_vary_accept_encoding().
         *
         * "always" is excluded by the enclosing test on purpose: it
         * ignores Accept-Encoding, so its response is not a negotiated
         * variant and must not claim to vary on it. See C5.
         */
        if (ngx_http_zstd_vary_accept_encoding(r) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (!accepts) {
            return NGX_DECLINED;
        }
    }

    return ngx_http_zstd_static_send(r, &of, &path, log);
}


static void *
ngx_http_zstd_static_create_main_conf(ngx_conf_t *cf)
{
    return ngx_pcalloc(cf->pool, sizeof(ngx_http_zstd_static_main_conf_t));
}


static void *
ngx_http_zstd_static_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_zstd_static_conf_t  *conf;

    /*
     * ngx_palloc(), not ngx_pcalloc(): both fields are unconditionally
     * overwritten below before anything can read them, so zero-filling
     * first is dead work. Do NOT copy this substitution to a conf struct
     * whose fields are conditionally written — the main conf
     * (ngx_http_zstd_static_main_conf_t.any_enabled) deliberately
     * depends on zero-init and must stay ngx_pcalloc().
     */
    conf = ngx_palloc(cf->pool, sizeof(ngx_http_zstd_static_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET_UINT;
    conf->dict_bypass = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_zstd_static_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_zstd_static_conf_t *prev = parent;
    ngx_http_zstd_static_conf_t *conf = child;

    ngx_conf_merge_uint_value(conf->enable, prev->enable,
                              NGX_HTTP_ZSTD_STATIC_OFF);
    ngx_conf_merge_value(conf->dict_bypass, prev->dict_bypass, 0);

    /*
     * G5: there is no longer a gzip_vary-off warning here. The content
     * handler emits "Vary: Accept-Encoding" itself whenever a .zst
     * variant makes this URI Accept-Encoding-dependent (see
     * ngx_http_zstd_vary_accept_encoding()), so the header no longer
     * depends on the operator setting "gzip_vary on", and warning
     * about that directive would be misleading. "always" normally never
     * varies, by construction rather than by warning: it ignores
     * Accept-Encoding. zstd_static_dict_bypass is the explicit exception,
     * because its routing decision consumes that request field.
     */

    return NGX_CONF_OK;
}


/*
 * Wraps the stock ngx_conf_set_enum_slot() for "zstd_static" so every
 * "zstd_static on;"/"zstd_static always;" parsed anywhere in the config
 * (main, srv, or loc — never inside an "if": see the any_enabled field's
 * comment) latches ngx_http_zstd_static_main_conf_t.any_enabled. Only
 * the literal "off" leaves it clear; ngx_conf_set_enum_slot() itself
 * already rejects any value that is not one of the three enum entries
 * (off/on/always), so by the time this runs the argument is always one
 * of exactly those three.
 */
static char *
ngx_http_zstd_static_set_enable_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_str_t                         *value;
    char                              *rc;
    ngx_http_zstd_static_main_conf_t  *zsmcf;

    rc = ngx_conf_set_enum_slot(cf, cmd, conf);
    if (rc != NGX_CONF_OK) {
        return rc;
    }

    value = cf->args->elts;

    if (value[1].len == 3 && ngx_strncmp(value[1].data, "off", 3) == 0) {
        return NGX_CONF_OK;
    }

    zsmcf = ngx_http_conf_get_module_main_conf(cf,
                                                ngx_http_zstd_static_module);
    zsmcf->any_enabled = 1;

    return NGX_CONF_OK;
}


/*
 * Wraps the stock ngx_conf_set_flag_slot() for "zstd_static_dict_bypass"
 * so every literal "on" parsed anywhere latches
 * ngx_http_zstd_static_main_conf_t.dict_bypass_enabled — the same
 * parse-time shape as ngx_http_zstd_static_set_enable_slot() above, and
 * for the same reason: postconfiguration needs one conservative "does
 * this cycle use the feature at all" bit without walking the merge tree.
 */
static char *
ngx_http_zstd_static_set_dict_bypass_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_str_t                         *value;
    char                              *rc;
    ngx_http_zstd_static_main_conf_t  *zsmcf;

    rc = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rc != NGX_CONF_OK) {
        return rc;
    }

    value = cf->args->elts;

    if (value[1].len == 2 && ngx_strncasecmp(value[1].data,
                                             (u_char *) "on", 2) == 0)
    {
        zsmcf = ngx_http_conf_get_module_main_conf(cf,
                                                ngx_http_zstd_static_module);
        zsmcf->dict_bypass_enabled = 1;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_zstd_static_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt               *h;
    ngx_http_core_main_conf_t         *cmcf;
    ngx_http_zstd_static_main_conf_t  *zsmcf;

    zsmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_zstd_static_module);

    /*
     * TODO row: do not append the always-declining content-phase
     * handler when zstd_static is off in every merged location.
     * any_enabled is latched conservatively at directive parse time
     * (ngx_http_zstd_static_set_enable_slot(), see its own and the
     * field's comment). Skipping registration here removes one
     * always-false content-phase check per request in an all-disabled
     * deployment; any location that could serve a .zst file still gets
     * the handler installed exactly as before.
     */
    if (!zsmcf->any_enabled) {
        return NGX_OK;
    }

    /*
     * zstd_static_dict_bypass hands matching requests to the FILTER
     * module's dcz negotiation — a module this one deliberately never
     * links (the routing predicate cannot read its conf, its store, or
     * whether it exists). With the filter module absent that handoff
     * goes nowhere: an HTTPS client that acquired an advertised
     * dictionary sends Available-Dictionary + dcz on every matching
     * request from then on, the static handler stands aside every
     * time, and the response is IDENTITY, permanently, with a usable
     * .zst sidecar on disk. "A later rejection does not revisit the
     * skipped sidecar" covers a filter that declines; here there is no
     * filter to decline. Per-location filter state is unknowable
     * across the module split, but the catastrophic shape — the
     * module not present in the cycle at all — is detectable right
     * here, the same cycle->modules name scan the compression_vary
     * detection used (#110). A warning rather than an error: the
     * operator may be mid-migration, and the identity responses are
     * wrong-but-served, not corrupt.
     */
    if (zsmcf->dict_bypass_enabled) {
        ngx_uint_t  i, filter_present;

        filter_present = 0;

        for (i = 0; cf->cycle->modules[i]; i++) {
            if (ngx_strcmp(cf->cycle->modules[i]->name,
                           "ngx_http_zstd_filter_module") == 0)
            {
                filter_present = 1;
                break;
            }
        }

        if (!filter_present) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "\"zstd_static_dict_bypass on\" but "
                               "ngx_http_zstd_filter_module is not loaded: "
                               "dcz can never be negotiated, so requests "
                               "carrying Available-Dictionary with an "
                               "explicit dcz will bypass their .zst "
                               "sidecar and be served identity. Load the "
                               "filter module or remove "
                               "zstd_static_dict_bypass");
        }
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_zstd_static_handler;

    return NGX_OK;
}
