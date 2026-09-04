[![CI](https://github.com/myguard-labs/nginx-zstd-module/actions/workflows/ci.yml/badge.svg)](https://github.com/myguard-labs/nginx-zstd-module/actions/workflows/ci.yml)
[![Lint](https://github.com/myguard-labs/nginx-zstd-module/actions/workflows/lint.yml/badge.svg)](https://github.com/myguard-labs/nginx-zstd-module/actions/workflows/lint.yml)
[![Build&Test](https://github.com/myguard-labs/nginx-zstd-module/actions/workflows/build-test.yml/badge.svg)](https://github.com/myguard-labs/nginx-zstd-module/actions/workflows/build-test.yml)
[![Security Scanners](https://github.com/myguard-labs/nginx-zstd-module/actions/workflows/security-scanners.yml/badge.svg)](https://github.com/myguard-labs/nginx-zstd-module/actions/workflows/security-scanners.yml)
[![CI Deep](https://github.com/myguard-labs/nginx-zstd-module/actions/workflows/ci-deep.yml/badge.svg)](https://github.com/myguard-labs/nginx-zstd-module/actions/workflows/ci-deep.yml)
[![Windows build](https://github.com/myguard-labs/nginx-zstd-module/actions/workflows/windows-build.yml/badge.svg)](https://github.com/myguard-labs/nginx-zstd-module/actions/workflows/windows-build.yml)

📖 **Background reading:**

- [zstd nginx module: what it does, bugs fixed](https://deb.myguard.nl/articles/zstd-nginx-module-bugs-fixed/)
- [nginx zstd vs brotli vs zlib-ng — a compression comparison](https://deb.myguard.nl/articles/nginx-zstd-vs-brotli-vs-zlib-ng-compression/)

# zstd-nginx-module

An nginx module for [Zstandard (zstd)](https://facebook.github.io/zstd/) compression. Zstandard typically achieves substantially better compression ratios than gzip, making it a good choice for reducing transmitted response sizes. Throughput depends on the level and payload: at the low levels recommended for web traffic, zstd trades some encode speed for that ratio -- see the [measured benchmark table](#benchmarks) rather than assuming a general speed win.

This is a hardened fork: every PR is exercised against **nginx mainline**, the filter/static suites and runtime regressions run under **ASAN/UBSAN**, flawfinder/semgrep/clang-tidy run on every change, and a weekly deep pass fuzzes both parser targets and additionally covers **nginx stable** and **[Angie](https://angie.software/)** (see [Testing & CI](#testing--ci)).

# Table of Contents

* [Status](#status)
* [Synopsis](#synopsis)
* [Set and forget](#set-and-forget)
* [Installation](#installation)
* [Directives](#directives)
  * [ngx_http_zstd_filter_module](#ngx_http_zstd_filter_module)
    * [zstd](#zstd)
    * [zstd_comp_level](#zstd_comp_level)
    * [zstd_min_length](#zstd_min_length)
    * [zstd_max_length](#zstd_max_length)
    * [zstd_types](#zstd_types)
    * [zstd_buffers](#zstd_buffers)
    * [zstd_buffers_unsafe](#zstd_buffers_unsafe)
    * [zstd_target_cblock_size](#zstd_target_cblock_size)
    * [zstd_window_log](#zstd_window_log)
    * [zstd_long](#zstd_long)
    * [zstd_max_cctx_memory](#zstd_max_cctx_memory)
    * [zstd_bypass](#zstd_bypass)
    * [zstd_bypass_vary](#zstd_bypass_vary)
    * [zstd_dict_file](#zstd_dict_file)
    * [zstd_dict_strict_path](#zstd_dict_strict_path)
    * [zstd_dict_file_unsafe](#zstd_dict_file_unsafe)
    * [zstd_dcz_dict_file](#zstd_dcz_dict_file)
    * [zstd_dcz_dict_trust_hashes](#zstd_dcz_dict_trust_hashes)
    * [zstd_dcz_assume_secure_transport](#zstd_dcz_assume_secure_transport)
  * [ngx_http_zstd_static_module](#ngx_http_zstd_static_module)
    * [zstd_static](#zstd_static)
    * [zstd_static_dict_bypass](#zstd_static_dict_bypass)
* [Variables](#variables)
  * [$zstd_ratio](#zstd_ratio)
  * [$zstd_bytes_in](#zstd_bytes_in)
  * [$zstd_bytes_out](#zstd_bytes_out)
  * [$zstd_dcz_dicts_hashed](#zstd_dcz_dicts_hashed)
* [Compatibility](#compatibility)
* [Testing & CI](#testing--ci)
* [Benchmarks](#benchmarks)
* [Operations](#operations)
* [Security](#security)
* [Author](#author)
* [License](#license)

# Status

Production-oriented. The module originates from the upstream
[tokers/zstd-nginx-module](https://github.com/tokers/zstd-nginx-module) and
has since had an extensive audit pass: a regression test for every known
historical bug class, ASAN/UBSAN runtime checks, and continuous fuzzing of
the request-parsing path (see [Testing & CI](#testing--ci)). Bug reports and
pull requests are welcome.

# Synopsis

```nginx
http {
    # Compress text responses for clients that support zstd.
    # Defaults: level 3, web-content MIME types, and a 1024-byte minimum.
    zstd             on;

    # Optional for zstd (it emits Vary: Accept-Encoding itself); set this
    # if gzip or brotli are also enabled so their variants are cached too.
    gzip_vary        on;

    server {
        listen 80;
        server_name example.com;

        # Dynamic compression via filter module
        location /api/ {
            proxy_pass http://backend;
        }

        # Serve pre-compressed .zst files for static assets
        location /static/ {
            zstd_static on;
            root /var/www;
        }
    }
}
```

For pre-compressed static files, generate them alongside the originals:

```bash
# Compress all JS and CSS files in the static directory
find /var/www/static -name "*.js" -o -name "*.css" | \
    xargs -I{} zstd -3 -k {}
# This creates file.js.zst next to file.js, etc.
```

# Set and forget

If you just want sane production compression without reading every
directive, paste this into the `http {}` block of `nginx.conf` and move
on. It is tuned for typical web traffic (HTML/JSON/JS/CSS/SVG) and
relies on the module's built-in defaults for everything not shown.

```nginx
http {
    # --- zstd: set and forget ---
    zstd              on;    # level 3, 1 KiB minimum, common web types

    # Optional for zstd: the module emits Vary: Accept-Encoding itself, so
    # this is only needed if gzip/brotli are also enabled on the location.
    gzip_vary         on;

    # Pre-compressed static assets (optional but free if you ship .zst)
    # zstd_static     on;
}
```

Why these values, and why nothing else is needed:

* **`zstd_comp_level 3`** — the built-in default; for real web content this beats `gzip -6`
  on ratio at comparable or better speed (see [Benchmarks](#benchmarks)).
  Levels ≥ 9 cost CPU steeply for marginal gain; only raise it for
  infrequently-generated, cached responses.
* **`zstd_min_length 1024`** — the built-in default; below about 1 KiB the
  zstd frame overhead and CPU cost usually outweigh the saving.
* **`zstd_types` is intentionally not set.** Its built-in list covers HTML,
  plain text, CSS, JavaScript, JSON, XML/feed formats, SVG, and common
  structured JSON variants (see [`zstd_types`](#zstd_types)).
* **`zstd_buffers` is intentionally not set.** The default is now
  `2 × ZSTD_CStreamOutSize()` — libzstd's own recommended streaming
  output unit (~128 KB each). This lets every compress call flush a
  full internal block without fragmentation. Only override it if you
  run thousands of concurrent connections on a memory-constrained box
  and need to trade some throughput for a lower per-request memory
  floor (see [`zstd_buffers`](#zstd_buffers)).
* **`zstd_long`, `zstd_window_log`, `zstd_dict_file`,
  `zstd_target_cblock_size` are intentionally not set.** They are
  specialist levers (very large repetitive bodies, hard per-request
  memory caps, shared dictionaries). The defaults are correct for
  general traffic; reach for these only with a measured reason.

That is the entire recommended baseline. Everything past this point in
the README is reference detail and tuning for specific workloads — you
do not need it to run the module well.

# Installation

Build nginx with the module using `--add-dynamic-module`:

```bash
./configure --add-dynamic-module=/path/to/zstd-nginx-module
make && make install
```

Then load the modules in `nginx.conf`:

```nginx
load_module modules/ngx_http_zstd_filter_module.so;
load_module modules/ngx_http_zstd_static_module.so;
```

**Notes:**

* Both `ngx_http_zstd_filter_module` and `ngx_http_zstd_static_module` are compiled together.
* If you are using a custom zstd installation, set `ZSTD_INC` (path to `zstd.h`) and `ZSTD_LIB` (path to the library) before running `configure`. If unset, the system-installed zstd is used.
* **This plain `./configure` line does not enable `-DZSTD_STATIC_LINKING_ONLY`.**
  With no `ZSTD_INC`/`ZSTD_LIB` set, `auto/zstd` goes straight to
  auto-discovery (dynamic linking, then pkg-config), and neither of those
  paths ever defines the flag — it is only ever added when `ZSTD_INC` and
  `ZSTD_LIB` are both set *and* they resolve to a static `libzstd.a`
  (`zstd_static.lib` on MSVC) at that exact location. There is no configure
  flag that turns it on directly. A build produced by the command above
  therefore does **not** have the experimental memory-estimator API
  compiled in: `zstd_max_cctx_memory` will fail `nginx -t` with
  `"zstd_max_cctx_memory" requires the module to be built with
  -DZSTD_STATIC_LINKING_ONLY ...`, and the implicit no-budget advisory
  (see [Directives](#directives)) silently does not run. To get the flag,
  point `ZSTD_INC`/`ZSTD_LIB` at a static libzstd build before running
  `configure`; see [`zstd_max_cctx_memory`](#zstd_max_cctx_memory) and
  [Compatibility](#compatibility) for the full requirement.
* **Windows:** MSVC builds the modules statically into `nginx.exe`; MinGW-w64
  can also build them as dynamic `.so`-named PE DLLs.
  [`ci/tools/build-windows.sh`](ci/tools/build-windows.sh) assembles the MSVC build
  (and optionally ngx_brotli, the unified compression module, and headers-more;
  library builds follow the modules selected), with every source version and
  SHA-256 pinned in [`ci/tools/windows-pins.sh`](ci/tools/windows-pins.sh) and
  verified before any compile. The usual Windows-nginx caveats
  apply (effectively single-worker via `select()`, no HTTP/3 — local dev use,
  not production). The `zstd_static` frame probes (magic number, truncation,
  declared-window and skippable-frame-chain checks) run on Windows too: the
  probe needs an offset-explicit read that does not move the shared cached
  descriptor's file position, which is `pread(2)` on POSIX and
  `ngx_read_file()` — `ReadFile()` with an `OVERLAPPED` offset — on Win32.
  The verdict logic itself is one shared function on both platforms.
  [`.github/workflows/windows-build.yml`](.github/workflows/windows-build.yml)
  is the executable MinGW recipe and verifies both toolchains.
* Dynamic modules (`.so`) require dynamic linking against `libzstd.so`. The build scripts auto-detect and prefer this. Ensure the zstd shared library is installed and available at runtime (`libzstd-dev` on Debian/Ubuntu, `libzstd-devel` on RHEL/Fedora).
* On POSIX, when `ZSTD_LIB` is set to a non-standard path, the build embeds an RPATH pointing to that directory in the module `.so`. This means the module will load `libzstd.so` from that exact path at runtime. If the library is later moved (e.g. by a package upgrade), the module will fail to load. Use the system package and leave `ZSTD_LIB` unset to avoid this.

# Compatibility

| Component | Minimum | Recommended | CI-verified |
|---|---|---|---|
| **nginx** | 1.9.11 (first `--add-dynamic-module` release) | latest mainline / stable | latest mainline resolved by the PR gate; pinned mainline, stable, and Angie in CI Deep's weekly matrix |
| **Angie** | 1.x | latest | **1.12.1** |
| **libzstd** | **1.4.0** | **≥ 1.5.7** | 1.5.x (full suite) + **1.4.x** fallback-paths build |
| **OS** | Linux/BSD/RHEL-family | — | Ubuntu (GitHub runners) |

Notes on the libzstd floor — these are enforced in code, not assumed:

* At startup, dynamically linked builds compare the loaded libzstd version
  with the headers used to compile the module and warn on any mismatch. Normal
  ABI-compatible skew remains supported. Startup is refused only when a
  configured compile-gated feature crosses its runtime floor: a negative
  `zstd_comp_level` below 1.4.0, or `zstd_target_cblock_size` below 1.5.6.

* **< 1.4.0**: the streaming API the module uses (`ZSTD_compressStream2`)
  is unavailable; this is the hard minimum. Negative `zstd_comp_level`
  values are also unsupported and are clamped to `1` with a warning
  (guarded by `#if ZSTD_VERSION_NUMBER >= 10400`).
* **< 1.5.6**: `zstd_target_cblock_size` has no effect — the directive
  is accepted as a warned no-op (apply path gated by
  `#if ZSTD_VERSION_NUMBER >= 10506`, with a config-load warning).
  Everything else works. This fallback path is exercised in CI by a
  dedicated "Build (libzstd 1.4.x — fallback paths)" job that links the
  module against a privately built libzstd 1.4.x and runs the
  decode-and-compare smoke test. That lane proves API fallback
  compatibility only — it is not a production-safety signal, and 1.4.5
  is not the recommended version for production traffic.
* **≥ 1.5.6**: every directive is fully functional.
* **≥ 1.5.7 (recommended for production)**: fixes a rare upstream
  dictionary-compression corruption on 32-bit ARM after a long-lived
  `CCtx` is reused across a very large number of operations. This
  module reuses a worker-lifetime `CCtx`, supports dictionaries, and
  allows levels up to 22, so deployments combining dictionaries,
  32-bit builds, and sustained traffic should run 1.5.7 or later; the
  1.4.0 floor above is unaffected and unchanged.
* **`zstd_max_cctx_memory`** additionally requires the module to be
  built with `-DZSTD_STATIC_LINKING_ONLY` so libzstd's experimental
  memory-estimator API is available. This project's own CI opts into
  that flag by pointing `ZSTD_INC`/`ZSTD_LIB` at a static libzstd (see
  [Installation](#installation)) — it is **not** the outcome of the
  plain `./configure --add-dynamic-module=...` command documented
  above, which auto-discovers a dynamic libzstd and never defines the
  flag. Without it, the directive is rejected at config load with a
  clear, actionable error rather than silently no-op'd.

"CI-verified" means the PR or weekly deep workflow builds and runs the full
test suite against that exact version (see [Testing & CI](#testing--ci)). Other
versions within the stated ranges are expected to work but are not
continuously exercised.

# Directives

## ngx_http_zstd_filter_module

This filter module compresses responses on the fly using zstd. It runs after the upstream or file handler generates the response, and before nginx sends it to the client. Compression is applied only when the client signals support via `Accept-Encoding: zstd`. 2xx responses are eligible for compression — except the bodyless `204 No Content` and `205 Reset Content` — as well as `403` and `404` (which often carry compressible error bodies). All other non-2xx statuses are passed through uncompressed.

> **`Vary: Accept-Encoding` is emitted automatically — you do not need `gzip_vary on`.** Whenever a response's encoding depends on `Accept-Encoding`, both this module and `zstd_static on` emit the `Vary: Accept-Encoding` header themselves, so proxies and CDNs keep the compressed and uncompressed variants apart without any directive on your part. Emission is duplicate-safe: with `gzip_vary on` nginx emits the field and the module stays quiet, with `gzip_vary off` the module emits it — exactly one `Vary: Accept-Encoding` line either way.
>
> This used to be a deployment prerequisite backed only by a config-load warning: with the default `gzip_vary off`, nginx *suppresses* the header entirely, so a single overlooked location shipped zstd bodies that a shared cache would then hand to clients unable to decode them. Correctness now belongs to the module rather than to an operator directive, and the warning is gone with it. `gzip_vary on` remains perfectly fine to set (it also covers other encoders such as `gzip`); it is simply no longer load-bearing for zstd.
>
> `zstd_static always` is deliberately excluded when
> [`zstd_static_dict_bypass`](#zstd_static_dict_bypass) is off: it then ignores
> `Accept-Encoding` entirely, so its response is not a negotiated variant and
> correctly carries no `Vary: Accept-Encoding`. The opt-in bypass is the stated
> exception because it routes dictionary-aware requests by that field.
>
> Interoperating with [ngx_http_compression_vary_filter_module](https://github.com/HanadaLee/ngx_http_compression_vary_filter_module) is safe in every combination. That module emits and *flattens* `Vary` from `r->gzip_vary`, which this module still sets; because it folds the fields it finds rather than appending blindly, the header this module emits is merged rather than doubled. With `compression_vary off` (its default) this module's own emission still covers you — previously that exact combination produced no `Vary` at all, which is the residual risk the old summary warning existed to describe. CI asserts the single-`Vary` contract against the real module in both of its states.

> **ETag behaviour:** When a response is compressed, nginx automatically weakens the `ETag` value (converting `"abc"` to `W/"abc"` if it was strong). This is correct per HTTP semantics — a compressed representation is a different entity variant — but it means strong ETag validation (`If-Match`) will not match across compressed and uncompressed responses. CDN edge nodes that cache both variants will see different ETags for each.

> **Coexisting with `gzip` and `brotli`:** It is safe to enable `zstd`, the [`brotli`](https://github.com/google/ngx_brotli) filter, and the built-in [`gzip`](https://nginx.org/en/docs/http/ngx_http_gzip_module.html) filter on the same location with overlapping `*_types`. A response is only ever compressed once: nginx body filters run in a fixed chain, and the first encoder whose `Accept-Encoding` test passes wins, setting `Content-Encoding` so the later encoders skip the already-encoded body. Relative to the built-in `gzip`, `zstd` is always ordered to run **before** it (both in static and dynamic builds), so a client advertising `Accept-Encoding: gzip, zstd` receives `zstd`; clients that do not advertise `zstd` fall through to `gzip`. Each encoded variant is cached separately by proxies and CDNs because every encoder in that chain advertises `Vary: Accept-Encoding`; this module emits it itself, and `gzip`/`brotli` emit theirs via `gzip_vary`, so set `gzip_vary on` if you rely on those encoders too.
>
> **`zstd` vs `brotli` ordering (dynamic builds):** the fixed `before brotli` guarantee holds for **static** builds, where `filter/config` explicitly places `zstd` ahead of `ngx_http_brotli_filter_module` in the module array. For **dynamic** modules, `ngx_brotli` and this module share the same filter anchor and neither constrains itself relative to the other, so the body-filter chain is built in **reverse `load_module` order** — whichever is loaded **last** runs first and wins. To make `zstd` win a `br, zstd` negotiation, load it last:
>
> ```nginx
> load_module modules/ngx_http_brotli_filter_module.so;
> load_module modules/ngx_http_zstd_filter_module.so;   # loaded last → runs first → wins
> ```
>
> Swap the two lines to prefer `brotli`. If you require a fixed winner regardless of operator load order, prefer a static build (or pick one of the two filters per location).
>
> **Selection policy — server preference, not client qvalue ranking.** When several encoders are enabled and the client lists more than one as acceptable, the winner is decided by **server-side filter order** (zstd runs first relative to gzip, and relative to brotli only when static builds or dynamic `load_module` order put zstd first), **not** by the client's relative `q` weights. So `Accept-Encoding: zstd;q=0.5, gzip;q=0.9` still yields `zstd`, even though the client ranked `gzip` higher. This is a deliberate server-preference policy. RFC 9110 §12.5.3 describes preferring the acceptable coding with the highest non-zero qvalue, which a single per-coding filter cannot implement (it cannot see the other codings' weights); honouring it would require a shared negotiation step ahead of the body filters. A coding whose effective explicit `q` value is `0` remains unacceptable — only the *relative* ranking between acceptable codings is server-decided.

> **Repeated `Accept-Encoding` field lines are one comma-joined list.** A client may split its codings across several `Accept-Encoding` request header lines. [RFC 9110 §5.3](https://www.rfc-editor.org/rfc/rfc9110#section-5.3) makes a repeated list-valued field semantically identical to the single field whose value is those lines joined in order with commas, and this module negotiates accordingly — every line is evaluated, not just the first. So
>
> ```http
> Accept-Encoding: gzip
> Accept-Encoding: zstd
> ```
>
> is `gzip, zstd` and negotiates `zstd`, exactly as the one-line form would. The same applies to the [`dcz`](#zstd_dcz_dict_file) token.
>
> **Duplicate codings across lines retain order.** The comma-joined field is parsed in received order, so the **latest explicit token wins**: `zstd;q=0` followed by `zstd;q=1` accepts zstd, while the reverse order declines it. A `*` wildcard stays subordinate to an explicit token, so any line naming the coding explicitly still decides.

---

### zstd

**Syntax:** `zstd on | off;`
**Default:** `zstd off;`
**Context:** `http, server, location, if in location`

Enables or disables on-the-fly zstd compression for responses.

**Example:**

```nginx
http {
    zstd       on;          # enable everywhere
    gzip_vary  on;          # optional for zstd (emitted automatically); covers gzip/brotli too

    server {
        location /downloads/ {
            zstd off;       # already-compressed archives: skip
        }
    }
}
```

---

### zstd_comp_level

**Syntax:** `zstd_comp_level level;`
**Default:** `zstd_comp_level 3;`
**Context:** `http, server, location`

Sets the zstd compression level. Accepted values depend on the installed zstd library version:

| Range | Meaning |
|---|---|
| `1` to `ZSTD_maxCLevel()` (22) | Standard levels — higher = better ratio, slower |
| `0` | Library default (`ZSTD_CLEVEL_DEFAULT`, currently level 3) |
| `ZSTD_minCLevel()` (-131072) to `-1` | Fast/negative levels — lower ratio, minimal CPU cost (requires zstd ≥ 1.4.0) |

**Choosing a level:**

* `1` — Fastest compression; suitable for high-throughput APIs or when latency is critical.
* `3` (default) — Good all-around balance of ratio and speed; the zstd library's own default.
* `6`–`9` — Better ratios with moderate CPU cost; suitable for large, infrequently-changed responses.
* Negative levels (`-1` to `-5`) — Ultra-fast, for cases where you want some compression with nearly zero overhead.

For most web-serving workloads, levels `1`–`3` are recommended. Avoid high levels (> 9) in production unless responses are generated infrequently and cached.

**Example:**

```nginx
http {
    zstd             on;
    zstd_comp_level  3;          # balanced default for live traffic

    server {
        location /api/ {
            zstd_comp_level 1;   # latency-sensitive: fastest level
        }

        location /reports/ {
            zstd_comp_level 12;  # large, cached, infrequently generated
        }
    }
}
```

> **Performance note:** when a response has a known exact
> `Content-Length` (the common proxied/static case), the module passes
> that size to zstd up front (`ZSTD_CCtx_setPledgedSrcSize`). zstd then
> sizes its internals to the input and writes a more compact frame
> header, giving a small speed/ratio improvement at no cost. This is
> automatic, per request, and requires no configuration. Chunked /
> unknown-length responses are unaffected (they stream as before).

---

### zstd_min_length

**Syntax:** `zstd_min_length length;`
**Default:** `zstd_min_length 1024;`
**Context:** `http, server, location`

Sets the minimum response size (in bytes) required for compression to apply. The size is taken from the `Content-Length` response header; responses without `Content-Length` are always eligible.

> **Note:** The built-in default is `1024` bytes. Smaller responses often lose
> their savings to zstd frame overhead while still consuming compression CPU.

> **Caveat — chunked and proxied responses bypass this directive entirely.**
> The threshold can only be applied when the body length is known up front, so
> the check is skipped whenever `Content-Length` is absent — which is the normal
> case for chunked transfer encoding and for most proxied upstreams. Such
> responses are compressed regardless of how small they turn out to be, and a
> body below the threshold can come out *larger* than the original: a 47-byte
> chunked body under `zstd_min_length 1024` is returned as 56 bytes with
> `Content-Encoding: zstd`. Enforcing the threshold on a streaming body would
> require buffering the response until the threshold is decided, which changes
> when headers may be sent; the directive deliberately does not do this. If a
> small-response floor matters for an upstream, ensure the upstream sets
> `Content-Length`, or disable compression for that location.

**Example:**

```nginx
zstd_min_length 1024;  # skip compression for responses smaller than 1 KiB
```

---

### zstd_max_length

**Syntax:** `zstd_max_length length;`
**Default:** `—` (no limit)
**Context:** `http, server, location`

Sets the maximum response size that will be compressed. The limit is enforced in two places:

* **Before compression starts**, when the response advertises a `Content-Length` larger than the limit: the response is passed through uncompressed (no CPU spent).
* **During compression**, the running input total is tracked unconditionally — regardless of whether the response has a declared `Content-Length` — and if it exceeds the limit the request is **aborted** (logged as `zstd: input exceeded zstd_max_length ...`). This covers a chunked/streaming response with no `Content-Length`, and also a known-length upstream that streams more bytes than it declared. Compression has already begun and the client is mid-stream, so the only safe action is to terminate the response — protecting the worker from an unbounded or runaway upstream is preferred over completing one oversized response.

> **Behaviour once compression has started:** the case cannot be served uncompressed-instead (the `Content-Encoding: zstd` stream is already in flight), so exceeding the limit here ends the request rather than transparently passing through. Size the limit with headroom for the largest response you legitimately compress on that location. If you routinely serve very large streaming bodies (proxied video, big downloads), prefer simply not enabling `zstd` on those locations.

By default there is no upper limit. You may want to set one if very large responses (e.g. multi-megabyte file downloads) should bypass compression to avoid holding the worker process busy.

**Example:**

```nginx
zstd_max_length 10m;  # don't compress responses larger than 10 MB
```

---

### zstd_types

**Syntax:** `zstd_types mime-type ...;`
**Default:**

```nginx
zstd_types text/html text/plain text/css text/csv application/json
           application/x-ndjson application/json-seq application/javascript
           text/xml application/xml
           application/xml+rss text/javascript image/svg+xml
           application/atom+xml application/ld+json
           application/manifest+json application/problem+json
           application/rss+xml application/vnd.api+json
           application/xhtml+xml application/wasm text/wgsl;
```

**Context:** `http, server, location`

When omitted, the default covers common textual web representations. If set
explicitly, it follows nginx's usual type-directive behaviour: `text/html` is
included along with the listed MIME types. Use `*` to match all MIME types.

> **Note:** Only compressible content types (text, structured data, SVG, etc.) benefit from compression. Binary formats such as images (JPEG, PNG, WebP), audio, and video are already compressed and should be excluded.

**Example for a typical web application:**

```nginx
zstd_types
    text/plain
    text/css
    text/csv
    text/xml
    text/javascript
    application/json
    application/x-ndjson
    application/json-seq
    application/javascript
    application/xml
    application/xml+rss
    application/atom+xml
    application/ld+json
    application/manifest+json
    application/problem+json
    application/rss+xml
    application/vnd.api+json
    application/xhtml+xml
    application/wasm
    text/wgsl
    image/svg+xml;
```

---

### zstd_buffers

**Syntax:** `zstd_buffers number size;`
**Default:** `zstd_buffers 2 <ZSTD_CStreamOutSize()>;` (the size is libzstd's recommended streaming output unit, ~128 KB)
**Context:** `http, server, location`

Configures the number and size of output buffers used during compression. The total buffer space is `number × size`.

The default buffer **size** is `ZSTD_CStreamOutSize()` — the value libzstd documents as the minimum at which `ZSTD_compressStream2()` can flush a complete internal block in a single call. With any smaller buffer, zstd is forced to fragment a block across calls, costing extra compression round-trips and output-chain allocations per response. Earlier versions used a heuristic (`32 4k`, then `4 32k`) that approximated this; the module now asks libzstd for the exact value so it stays correct if the library changes it.

The default **count** is `2`: one buffer being filled by the compressor while the other is in flight down the output chain. This sets the per-request filter-memory floor at roughly `2 × ZSTD_CStreamOutSize()` (~256 KB), up from the previous ~128 KB — the deliberate cost of never forcing zstd to flush mid-block. If that trade is wrong for your workload (many concurrent connections, memory-constrained), set `zstd_buffers` explicitly to a smaller value; configurations that set it are unaffected by this default.

> **Bounded exception with dictionary responses:** The first output buffer in a response using `zstd_dcz_dict_file` is allocated at `size + 40` bytes to hold the RFC 9842 skippable-frame dictionary-identifier prefix inline. This is a bounded, one-time +40-byte overhead per dcz response, not a per-buffer or per-request scaling change.

Increasing these values allows larger chunks to be accumulated before writing, potentially improving throughput at the cost of higher per-request memory usage.

**Example:**

```nginx
http {
    zstd on;

    # The built-in default (applied when the directive is omitted):
    # 2 buffers sized to ZSTD_CStreamOutSize() (~128 KB each on
    # libzstd 1.5.x), i.e. ~256 KB/request. The line below is that
    # default written explicitly — leaving zstd_buffers unset is
    # equivalent and recommended:
    zstd_buffers 2 128k;

    server {
        # Memory-constrained box with very high concurrency:
        # trade some throughput for a lower per-request floor.
        location /high-fanout/ {
            zstd_buffers 4 16k;   # 64 KB/request instead of ~256 KB
        }
    }
}
```

> The default **size** is whatever `ZSTD_CStreamOutSize()` returns for
> the linked libzstd (~128 KB on 1.5.x); `2 128k` above is the
> human-readable equivalent for that version. Prefer leaving the
> directive unset so the size always tracks the library — only write it
> explicitly when you are deliberately overriding it.

#### Aggregate bound on `number × size`

`number` and `size` are each range-checked on their own by nginx core,
but the **product** was not checked at all until this policy was added —
a typo (`zstd_buffers 100000 100000;` instead of `100 100k;`) or a value
inherited unchanged from an outer block could request an overflowing or
merely enormous per-response output-chain pool, multiplied by every
concurrent response under load. Four tiers apply to the resolved value,
in ascending severity:

1. **`≤ 8 MB`** — silent. This covers nginx's own `zstd_buffers 32 4k`
   default (128 KB) and this module's own `2 × ZSTD_CStreamOutSize()`
   default (~256 KB at level 6) with generous headroom.

2. **`> 8 MB`, `≤ 256 MB`** — a **warning**, not an error. A config that
   loads today keeps loading after an upgrade:

   ```text
   nginx: [warn] "zstd_buffers" (merged value) requests 1 x 8388609 bytes
   = ~8388609 bytes of output-chain memory PER RESPONSE; that is on top
   of the per-request compressor (CCtx) working set -- see the
   "zstd_max_cctx_memory" advisory above for that figure -- and both are
   multiplied by concurrent responses under load
   ```

3. **`> 256 MB`, no acknowledgement** — a **hard config-load error**.
   Unlike the CCtx memory estimate (which depends on libzstd internals
   the operator never directly sees), `number` and `size` are two
   integers the operator typed out literally, so at 256 MB — two hundred
   times nginx's own default — a refusal by default is the safer
   reading of "this is almost certainly a mistake":

   ```text
   nginx: [emerg] "zstd_buffers" (merged value) requests 2147483647 x
   1073741824 bytes = ~2305843008139952128 bytes of output-chain memory
   PER RESPONSE, above the 256 MB hard cap -- that is on top of the
   per-request compressor (CCtx) working set (see the
   "zstd_max_cctx_memory" advisory above) and both are multiplied by
   concurrent responses under load. Lower "zstd_buffers", or set
   "zstd_buffers_unsafe on;" to acknowledge this total is intentional
   ```

4. **`> 256 MB`, with `zstd_buffers_unsafe on;`** — accepted, still
   logged as a **warning** (not silenced) so the acknowledgement remains
   visible in the log:

   ```text
   nginx: [warn] "zstd_buffers" (merged value) requests 2147483647 x
   1073741824 bytes = ~2305843008139952128 bytes of output-chain memory
   PER RESPONSE, above the 256 MB hard cap; accepted because
   "zstd_buffers_unsafe on;" acknowledges it. ...
   ```

`number × size` **overflowing the platform's `size_t`** is refused
unconditionally at every tier, including with `zstd_buffers_unsafe on;`
set — there is no representable acknowledgement for a product that
cannot exist:

```text
nginx: [emerg] "zstd_buffers" (explicit directive) requests
9223372036854775807 buffers of 9223372036854775807 bytes each; that
product overflows the platform's size_t and cannot be a config any
operator meant to write
```

The total named in tiers 2–4 is **per response**; add it to the CCtx
figure from the [`zstd_max_cctx_memory`](#zstd_max_cctx_memory) advisory
to size the full per-request compressor + output-chain budget, then
multiply by expected concurrency.

`zstd_buffers_unsafe` is `http, server, location` scoped and inherits
like any other directive here — set it once at the level that also sets
`zstd_buffers`, or higher up if every location beneath needs the same
acknowledgement.

The check runs once the value is fully resolved (explicit, inherited
from an outer block, or this module's own default) so all three sources
are covered by the same bound; an explicit value that also happens to be
the one that ends up in effect is reported once, not twice.

---

### zstd_buffers_unsafe

**Syntax:** `zstd_buffers_unsafe on | off;`
**Default:** `off`
**Context:** `http, server, location`

Acknowledges and accepts the total memory allocated by [`zstd_buffers`](#zstd_buffers) when the product of `number × size` exceeds 256 MB. By default, such configurations fail to load with a config-load error. Setting this directive to `on` skips the hard error and instead logs a warning (the warning is always emitted, even with `zstd_buffers_unsafe on;`, so the acknowledgement remains visible).

This directive is intended for operators who have calculated their total concurrency, compressor memory, and output-chain memory budgets and deliberately chosen a buffer configuration above the safety threshold. If you are not sure whether you need this, leave it `off` — the hard error is the safer default.

**Example:**

```nginx
http {
    # An unusually large buffer pool, above the 256 MB threshold.
    # Only do this if you have explicitly calculated the total
    # per-request cost and verified that it fits your deployment.
    zstd_buffers          1000 10m;
    zstd_buffers_unsafe   on;
}
```

---

### zstd_target_cblock_size

**Syntax:** `zstd_target_cblock_size size;`
**Default:** `—` (disabled, uses ZSTD library defaults)
**Context:** `http, server, location`
**Requires:** libzstd ≥ v1.5.6

Sets the target compressed block size for zstd frames. Controlling block size improves incremental response parsing, particularly in browsers where CSS/JavaScript in the response head must be available as soon as possible.

> **Rationale:** When the zstd encoder produces large compressed blocks, the entire block must be decompressed before any content within it becomes available to the client. Smaller blocks allow incremental decompression and earlier access to critical resources. For example, CSS in `<head>` can be parsed sooner if it lands in an early, smaller block.

> **Compatibility:** This directive requires libzstd v1.5.6 or later. On older versions, the directive is accepted as a warned no-op. If not set (value 0 or unset), zstd uses its internal defaults, typically yielding blocks of 128–256 KB depending on the compression level and content.

**Example:**

```nginx
http {
    # Smaller blocks = faster incremental parsing, slightly lower compression ratio
    zstd_target_cblock_size 65536;  # 64 KB blocks
}
```

**Effect:** Lower values increase the number of blocks and may reduce compression ratio slightly, but improve streaming/incremental decompression. Common values:

| Value | Use Case |
|---|---|
| Not set | Default behavior; good all-around balance |
| `16384` (16 KB) | Very aggressive incremental parsing; reduces ratio notably |
| `65536` (64 KB) | Moderate; CSS/JS in head typically available faster |
| `262144` (256 KB) | Conservative; minimal ratio impact |

---

### zstd_window_log

**Syntax:** `zstd_window_log exponent;`
**Default:** `—` (disabled; zstd uses its level-derived default)
**Context:** `http, server, location`

Caps the zstd compression **window** at `2^exponent` bytes. zstd's
per-request working memory is dominated by the window size (roughly the
window plus match-table overhead), so without a cap a high compression
level on large response bodies lets each concurrent request inflate the
worker's resident memory unpredictably. Bounding `window_log` gives a
hard, predictable per-request memory ceiling.

Typical values are `20`–`24` (1–16 MB). Lower values reduce memory and
the compression ratio on inputs larger than the window; on responses
smaller than the window there is no ratio impact. Unset (or `0`) keeps
zstd's default window for the configured level.

> **Note:** This bounds compressor memory, not the amount of response
> body buffered by nginx (that is governed by `zstd_buffers`). For a hard
> limit on how much input is ever fed to the compressor regardless of
> `Content-Length`, see also `zstd_max_length`.

**Example:**

```nginx
http {
    zstd on;
    zstd_comp_level   9;
    zstd_window_log   21;   # cap the window at 2 MB per request
}
```

---

### zstd_long

**Syntax:** `zstd_long on | off;`
**Default:** `zstd_long off;`
**Context:** `http, server, location`

Enables zstd **long-distance matching** (`ZSTD_c_enableLongDistanceMatching`). zstd keeps a secondary long-range hash table that finds repeated sequences far beyond the regular match window, which can meaningfully improve the compression ratio on large, internally repetitive bodies — concatenated JSON, HTML with repeated boilerplate, log dumps, sitemaps.

Off by default: the win only appears on inputs large enough to exceed the match window, and it costs a modest, bounded amount of extra per-request memory for the long-range table. Small responses should not pay that allocation, so enable it only on locations that serve large repetitive payloads.

Interacts with [`zstd_window_log`](#zstd_window_log): an explicit `zstd_window_log` still takes precedence over the window zstd would otherwise derive when long mode is on, so the per-request memory ceiling remains under your control.

**Example:**

```nginx
location /api/bulk-export {
    zstd on;
    zstd_comp_level  12;
    zstd_long        on;    # large, highly repetitive JSON
    zstd_window_log  24;    # keep the memory ceiling explicit
}
```

---

### zstd_max_cctx_memory

**Syntax:** `zstd_max_cctx_memory size;`
**Default:** `—` (no budget enforced; see [the advisory](#implicit-advisory-when-no-budget-is-set) below)
**Context:** `http, server, location`
**Requires:** module built with `-DZSTD_STATIC_LINKING_ONLY` against libzstd ≥ 1.4.0. This is **not** the result of the plain `./configure --add-dynamic-module=...` command in [Installation](#installation) — that auto-discovers a dynamic libzstd and never defines the flag. It is only set when `ZSTD_INC`/`ZSTD_LIB` point at a static libzstd build; see [Installation](#installation) and [Compatibility](#compatibility).

Asserts at **config load** that the combined zstd parameters configured
for the location (`zstd_comp_level`, `zstd_window_log`, `zstd_long`,
`zstd_target_cblock_size`) do not need more than `size` bytes of
per-request compressor working memory. If they would, nginx refuses to
start with a clear, actionable error pointing at the smallest set of
parameters to lower.

The budget is checked against libzstd's own
`ZSTD_estimateCStreamSize_usingCCtxParams()`, so the number is
authoritative — it accounts for the level's *strategy tables*
(chain/hash/search), the window, and LDM, not just the window. This
matters because **lowering `zstd_window_log` alone does not bound
memory for high levels**: level 22 at windowLog 20 still allocates
~640 MB, because the table size is driven by the level/strategy, not
the window.

```nginx
http {
    zstd                  on;
    zstd_comp_level       19;       # would otherwise eat ~90 MB / request
    zstd_max_cctx_memory  256m;     # accepted: level 19 fits in 256 MB
}

server {
    location /risky/ {
        zstd_comp_level       22;
        zstd_max_cctx_memory  64m;  # REFUSED at config load:
        # "the configured zstd parameters need ~833 MB of per-request
        # compressor memory, which exceeds zstd_max_cctx_memory 64m;
        # lower zstd_comp_level (currently 22), lower zstd_window_log,
        # disable zstd_long, or raise the budget"
    }
}
```

> **Interaction with `zstd_long`.** Enabling long-distance matching
> raises libzstd's default window to 128 MB (`windowLog` 27) unless
> `zstd_window_log` sets one explicitly, and adds the LDM hash table on
> top. That is a large jump: level 3 costs ~3.6 MB per request without
> `zstd_long` and ~144 MB with it. The budget check accounts for this —
> it derives the same LDM sub-parameters libzstd would and estimates
> against them, so `zstd_long on` with a budget below ~128 MB is
> refused at config load rather than accepted and blown at runtime.
> Pair `zstd_long on` with an explicit `zstd_window_log` to bring it
> back down (level 3 with `zstd_window_log 20` costs ~2.7 MB).

#### Implicit advisory when no budget is set

Setting `zstd_max_cctx_memory` is optional, and most configurations
never do. Compression enabled with **no** `zstd_max_cctx_memory`
anywhere in the inheritance chain therefore still runs the same
estimate at config load, and emits a **warning** — not an error — when
the profile needs more than **32 MB** of per-request compressor memory:

```text
nginx: [warn] the configured zstd parameters need ~144328225 bytes of
per-request compressor memory (zstd_comp_level 3); each worker retains
up to 4 such contexts, so worker RSS can reach ~577312900 bytes, and
that again per worker process. Set "zstd_max_cctx_memory" to a budget
to have this enforced at config load, or "zstd_max_cctx_memory 0" to
acknowledge the profile and silence this warning
```

This exists because the expensive levers are one line away from a
working config: a later `zstd_comp_level 22` or `zstd_long on` commits
hundreds of MB per concurrent response, and without the advisory the
module knew that number at config load and said nothing.

The 32 MB threshold sits in the natural gap between `zstd_comp_level`
11 (~28.7 MB) and 12 (~52.7 MB), so the ordinary web-serving range is
silent and only genuinely large profiles are named:

| profile (level 3 unless stated) | per request | per worker (×4) | advisory |
| --- | ---: | ---: | :---: |
| `zstd_comp_level 1` | 1.3 MB | 5.2 MB | no |
| default (`zstd_comp_level 3`) | 3.5 MB | 14.0 MB | no |
| `zstd_comp_level 9` | 16.7 MB | 67.0 MB | no |
| `zstd_comp_level 11` | 28.7 MB | 115.0 MB | no |
| `zstd_comp_level 12` | 52.7 MB | 211.0 MB | **yes** |
| `zstd_comp_level 19` | 89.5 MB | 358.0 MB | **yes** |
| `zstd_comp_level 22` | 769.5 MB | 3078.0 MB | **yes** |
| `zstd_long on` | 137.6 MB | 550.6 MB | **yes** |
| `zstd_window_log 27` | 129.5 MB | 518.0 MB | **yes** |
| `zstd_long on` + `zstd_window_log 20` | 2.6 MB | 10.3 MB | no |

*(`ZSTD_estimateCStreamSize_usingCCtxParams()`, libzstd 1.5.7,
streaming with unknown content size — the module's own path.)*

Two ways to silence it, and they mean different things:

* **`zstd_max_cctx_memory <size>;`** — you want the bound *enforced*.
  Exceeding it is a hard config-load error, as documented above.
* **`zstd_max_cctx_memory 0;`** — you have read the number and accept
  it. Nothing is enforced and nothing is warned about.

It never fails the configuration on its own: a config that loads today
keeps loading after an upgrade. Note that the advisory requires the
same `-DZSTD_STATIC_LINKING_ONLY` build as the directive; a build
without the estimator API simply does not warn, rather than implying a
guarantee it cannot compute.

**Why a config-load assert and not a runtime cap.** The directive does
**not** silently tune anything. A too-tight budget is a hard error so
operators see the misconfiguration up front, instead of discovering it
as a worker-RSS surprise under concurrency. Without
`-DZSTD_STATIC_LINKING_ONLY` the estimator API is unavailable; in that
case the directive is rejected at config load with the same kind of
clear message, never silently no-op'd.

> **Note:** This bounds **per-request** memory at one CCtx. The total
> worker memory ceiling at the request limit is roughly
> `worker_connections × zstd_max_cctx_memory` in the worst case
> (every connection actively compressing).

> **Retained memory between requests.** Each worker keeps a small ring
> of compression contexts (4 slots) so consecutive responses reuse an
> already-allocated workspace instead of building one per response.
> A slot is keyed on the complete set of parameters that drive that
> workspace — `zstd_comp_level`, `zstd_long` and the **effective** window
> log — and is never re-parameterised, so a slot's retained size stays at
> the figure `zstd_max_cctx_memory` vetted for that profile at config load.
> "Effective" matters for one case: a [dcz](#zstd_dcz_dict_file)
> request derives its own window from the negotiated dictionary rather than
> from `zstd_window_log`, so it is keyed on that derived value and occupies
> its own slot instead of raising a plain request's slot permanently.
> An idle worker therefore holds up to 4 workspaces rather than
> releasing them between requests. Budget that constant, not the number
> of configured profiles: a busy slot is skipped before its profile is
> compared, so concurrent requests on a single profile can seed several
> slots with that same profile. Each retained workspace stays at its own
> profile's vetted figure, so this is a floor well below the
> `worker_connections × zstd_max_cctx_memory` ceiling above, not an
> addition to it.

---

### zstd_bypass

**Syntax:** `zstd_bypass string ...;`
**Default:** `—`
**Context:** `http, server, location`

Disables on-the-fly compression for the current request when at least
one of the given string parameters evaluates to a non-empty value that
is not `"0"`. Each parameter is typically a variable (often driven by a
`map`), so the decision is made per request rather than statically.

```nginx
map $request_uri $no_zstd {
    default              0;
    ~^/wp-admin/         1;   # authenticated admin: reflects input + nonces
    ~^/wp-json/          1;   # REST: responses mix tokens with user data
}

server {
    zstd on;
    zstd_bypass $no_zstd;            # skip those paths
    zstd_bypass $http_x_no_compression;  # honour a client opt-out header
}
```

> **Security note — BREACH:** `zstd_bypass` is the intended lever for
> mitigating [BREACH](https://en.wikipedia.org/wiki/BREACH)-style
> attacks, which exploit the *size* of a compressed HTTP body that
> contains **both** a secret (CSRF token, session data) **and**
> attacker-influenced reflected input. Use it to serve identity on the
> specific endpoints where that combination occurs.
>
> Be honest about what this does and does not do: **no HTTP compressor
> can be made BREACH-safe while still compressing** — the attack is
> inherent to compression ratio as a side channel. `zstd_bypass` only
> lets you *exclude* the at-risk responses. The effective, primary
> BREACH defenses live in the application: per-request CSRF token
> masking, separating secrets from reflected input, and
> referer/origin checks. Treat `zstd_bypass` as a containment tool, not
> a fix. (CRIME and POODLE are unrelated TLS-layer attacks and are not
> addressed — or addressable — here; configure `ssl_protocols`
> appropriately instead.)

> **Why this module does not pad responses (the "anti-BREACH length
> padding" question).** A frequently requested "fix" is to add random
> padding to the compressed body so its length no longer reveals the
> compression ratio. This module deliberately does **not** do that, and
> will not, for concrete reasons:
>
> 1. **Random padding does not remove the signal — it adds noise the
>    attacker averages out.** BREACH is a guess-and-measure oracle: the
>    attacker replays the same request thousands of times, changing one
>    guessed byte at a time. A correct guess compresses ~1 byte smaller.
>    Random padding of variance σ adds zero-mean noise to each
>    measurement; averaging N samples shrinks the noise by √N while the
>    1-byte signal stays put. The attacker simply requests more times.
>    Published BREACH follow-up work (e.g. *Rupture*) automates exactly
>    this statistical recovery against padded/noised responses. Padding
>    raises the request count, not the difficulty class — it buys the
>    *appearance* of a fix while the secret still leaks.
> 2. **Padding that *would* defeat it is not "padding" anymore.** The
>    only length transform that actually closes the oracle is forcing
>    every response to a fixed size (or coarse power-of-two buckets)
>    *independent of content* — which throws away most of the
>    compression you enabled zstd for, on every response, to defend the
>    small subset that mixes a secret with reflected input. That is a
>    strictly worse trade than `zstd_bypass` on those endpoints (full
>    ratio everywhere else, identity exactly where it is unsafe).
> 3. **It moves a security boundary into the wrong layer.** Whether a
>    response safely mixes secrets and attacker input is an
>    application-semantics decision (is this field a CSRF token? is that
>    substring reflected query input?). A compression filter cannot see
>    that distinction; a per-response byte transform here cannot make an
>    application-layer information-flow problem safe, and shipping one
>    would invite operators to *believe* it had.
>
> So the module gives you the one lever that is honest and effective —
> `zstd_bypass`, to serve identity on the specific at-risk endpoints —
> and points you at the real fixes (CSRF token masking, separating
> secrets from reflected input, origin/referer checks). A built-in
> padding knob would trade real bandwidth for false confidence, so it is
> intentionally absent. See [`SECURITY.md`](SECURITY.md) for the
> in-scope / out-of-scope statement.

> **Cache safety with request-driven bypass.** When a `zstd_bypass`
> predicate depends on a **request header or cookie** (e.g.
> `zstd_bypass $http_x_no_compression`), the compressed-vs-identity
> decision now varies on that header. A shared cache (proxy / CDN) that
> does not key on it can store the identity response and serve it to a
> normal client, or store the compressed response and serve it to a
> bypass client. Either declare that variance with
> [`zstd_bypass_vary`](#zstd_bypass_vary) **or** mark such responses
> `Cache-Control: private` / `no-store`. Bypass predicates that depend
> only on `$request_uri`/`$uri` (already part of the cache key) do not
> need this.
>
> The module warns at config load when a `zstd_bypass` predicate reads a
> `$http_*` or `$cookie_*` variable **directly** with no
> `zstd_bypass_vary` configured in the same location — the same
> misconfiguration named above, caught before it reaches a shared cache.
> The check only recognizes the literal `$http_*`/`$cookie_*` spellings;
> an indirect predicate (e.g. a `map` result variable derived from a
> header or cookie) is not resolved and stays silent — pairing
> `zstd_bypass_vary` with a map-derived predicate remains an explicit
> operator responsibility.

---

### zstd_bypass_vary

**Syntax:** `zstd_bypass_vary field-name;`
**Default:** `—`
**Context:** `http, server, location`

Appends `field-name` to the response `Vary` header on every response for
which this module actually reaches the `zstd_bypass` decision — both the
compressed variant and the bypassed-identity variant — so a shared cache
keys on the request header that drives a header/cookie-based
[`zstd_bypass`](#zstd_bypass). A response declined earlier by an
eligibility gate (ineligible status, already encoded, below
`zstd_min_length`, above `zstd_max_length`, header-only, content type not
in [`zstd_types`](#zstd_types), or `Cache-Control: no-transform`) never
reaches that decision: it would be served identity regardless of the
bypass predicate, so no bypass-driven variance exists to declare and this
directive adds no `Vary` field to it. Use it whenever a bypass predicate
reads a request header or cookie:

```nginx
server {
    zstd on;
    zstd_bypass      $http_x_no_compression;  # client opt-out header
    zstd_bypass_vary X-No-Compression;        # so caches key on it
}
```

The module emits this as an additional `Vary` header line; caches union all
`Vary` fields, so it coexists with the `Vary: Accept-Encoding` the module
emits automatically. It does not itself decide anything — it only makes the
existing bypass behaviour cacheable without poisoning.

---

### zstd_dict_file

**Syntax:** `zstd_dict_file /path/to/dict;`
**Default:** `—`
**Context:** `http`

Loads a pre-trained zstd dictionary for use during compression. Dictionaries can significantly improve compression ratios for small, structurally similar responses (e.g. JSON API responses).

> **Requires explicit opt-in.** This directive emits an ordinary `Content-Encoding: zstd` response that was compressed with an external dictionary. That is **not** HTTP dictionary negotiation — [RFC 9842](https://www.rfc-editor.org/rfc/rfc9842) (Sept 2025) defines the `dcz` content coding and `Available-Dictionary` for that, implemented by [zstd_dcz_dict_file](#zstd_dcz_dict_file) below, which is what you want unless you control both ends. A generic client that only advertises `Accept-Encoding: zstd` **cannot decode** the result, and a shared cache keys it as an ordinary zstd variant. nginx therefore refuses to start with `zstd_dict_file` set unless you also set `zstd_dict_file_unsafe on;`, acknowledging that you control both ends and will key any shared cache accordingly.

> **Warning:** The `Content-Encoding: zstd` token in HTTP does not include any mechanism for the client to discover or negotiate which dictionary the server is using. Only use this directive if you control both ends of the connection and can guarantee that both the server and client use the same dictionary (for example, by advertising it via a custom HTTP header). See [tokers/zstd-nginx-module#2](https://github.com/tokers/zstd-nginx-module/issues/2) for background.

> **Parameter precedence with a dictionary.** A `ZSTD_CDict` bakes in the compression parameters it was built with, and libzstd's `ZSTD_CCtx_refCDict()` lets those supersede the per-request CCtx parameters. To keep `zstd_window_log` an effective cap with a dictionary loaded, the CDict is built with `ZSTD_createCDict_advanced()` seeding `windowLog` from `zstd_window_log` (on the static-linked builds this module ships), so the baked window matches the CCtx window and `zstd_max_cctx_memory`'s estimate — computed from the same `windowLog` — stays accurate. The CDict is built per distinct (`zstd_comp_level`, `zstd_window_log`) combination, so changing either in a child `location` rebuilds it rather than silently reusing the parent's. `zstd_long` applies via the CCtx (it is not a `ZSTD_compressionParameters` field, so `refCDict` does not override it). On a non-static-linked build the advanced builder is unavailable and the CDict falls back to a level-only digest; there `zstd_window_log` is not honored while a dictionary is loaded.

**Example:**

```nginx
http {
    # Loaded once per cycle; must be readable by the nginx user.
    # Train it with: zstd --train samples/*.json -o /etc/nginx/api.dict
    zstd_dict_file        /etc/nginx/api.dict;
    zstd_dict_file_unsafe on;   # required: acknowledges non-RFC-9842 mode

    zstd            on;
    zstd_types      application/json;

    server {
        location /api/ {
            # Tell a cooperating client which dictionary was used,
            # since HTTP cannot negotiate it (see warning above).
            add_header X-Zstd-Dict "api.dict-v1" always;
        }
    }
}
```

---

### zstd_dict_file_unsafe

**Syntax:** `zstd_dict_file_unsafe on | off;`
**Default:** `off`
**Context:** `http`

Acknowledges that responses compressed with [`zstd_dict_file`](#zstd_dict_file) are not RFC 9842 negotiated — they carry an ordinary `Content-Encoding: zstd` even though they were compressed with an external dictionary. This is an **unsafe** configuration for shared caches: a generic client that only advertises `Accept-Encoding: zstd` will receive a body compressed against a dictionary it does not possess and cannot decode.

nginx refuses to start if `zstd_dict_file` is configured without `zstd_dict_file_unsafe on;`, acknowledging that you control both ends of the connection (client and server) and will ensure the shared cache keys the response appropriately (or is absent).

Only use this directive when you control both the client and server and can guarantee that both use the same dictionary. If you need standards-based HTTP negotiation, use [`zstd_dcz_dict_file`](#zstd_dcz_dict_file) instead.

**Example:** See [`zstd_dict_file`](#zstd_dict_file) for an example that includes this directive.

---

### zstd_dict_strict_path

**Syntax:** `zstd_dict_strict_path on | off;`
**Default:** `off`
**Context:** `http`

Both dictionary loaders ([`zstd_dict_file`](#zstd_dict_file) and [`zstd_dcz_dict_file`](#zstd_dcz_dict_file)) always reject a FIFO, socket, directory, device node, or empty file — a config-load error either way, `on` or `off`. This directive controls an *additional*, opt-in trust policy on top of that: with it `on`, both loaders also refuse a **symlink at any component of the path** (not only the final one), a target — or an ancestor **directory** — **writable by group or other**, and a target or ancestor directory **not owned by the loading principal or by root**. It additionally requires the path to be **absolute** and free of `.`/`..` components.

> **Why it matters.** A root master reloads its configuration (`nginx -s reload` or a supervisor-driven SIGHUP) and re-reads every dictionary from disk at that moment. If the path is a symlink a less-privileged local writer can repoint, the file itself is group/world-writable, or an **ancestor directory** is group/world-writable or foreign-owned, that writer chooses or mutates the bytes the master snapshots into every worker on the next reload — without ever needing privilege to touch the running nginx process. `on` closes all three. The path is resolved **one component at a time** with `openat(O_NOFOLLOW|O_DIRECTORY)`, so an intermediate symlink (`/srv/current/dict.bin` with `current` a symlink) is refused rather than silently traversed — a whole-path `O_NOFOLLOW` guards only the final component and would follow `current` without complaint. Every directory fd the walk opens along the way — the root `/` included — is `fstat()`-checked against the same rule as the leaf **before** it is trusted as the base for the next component: owned by neither root nor the loading principal, or writable by group or other, and the whole path is refused, naming the offending component. There is **no sticky-bit exemption** for this ancestor check — a sticky world-writable directory (a `/tmp`-style layout) still lets an unprivileged user create a new entry in it, which is the steering this check exists to refuse, sticky bit or not; deploy dictionaries under a directory tree that is itself owned and writable only by the deploying principal, not merely a temp directory with a sane leaf file. The leaf is then opened relative to the verified parent descriptor, and before a single byte is read its own mode is checked against `S_IWGRP|S_IWOTH` **and** its owner against the effective uid of the config-parsing master (root-owned files are also accepted, root not being less privileged than the loader). Owner-writability alone is not enough at either level: a dictionary — or an ancestor directory — owned by an unprivileged account at an entirely ordinary mode (`0644` for a file, `0755` for a directory) lets that owner rewrite or replace the bytes a later privileged reload snapshots, which is precisely the writer this directive exists to exclude. Every check runs against the **already-open file descriptor** — never by re-opening the path — so a rename or symlink swap after the check cannot smuggle in a different file (no TOCTOU window).

> **Platform support.** The component walk needs POSIX.1-2008 `openat()`. Where it is unavailable (including Windows), `zstd_dict_strict_path on` **fails closed** with a config-load error rather than falling back to the weaker leaf-only guarantee — the directive never claims a protection the platform cannot deliver. `off` (the default) is unaffected everywhere.

> **Default is `off`.** A release-symlink layout (`/srv/current -> /srv/releases/<n>/`, with the dictionary loaded from a path through `current`) is a common, legitimate deployment pattern, and it depends on exactly the symlink indirection `on` refuses — at the intermediate `current` component as much as at the leaf. Turning this on is a deliberate hardening step for operators who deploy dictionaries to an immutable, content-addressed path (e.g. a filename embedding the content hash) rather than through a movable symlink — do not enable it against an existing release-symlink deployment without first moving to that layout, or every reload will fail with `nginx -s reload` and the **old worker generation keeps serving** (a rejected reload never tears down the running cycle).

**Example (hardened, content-addressed dictionary path):**

```nginx
http {
    zstd_dict_strict_path on;
    zstd_dcz_dict_file /srv/dicts/app-a1b2c3d4.bin;
}
```

---

### zstd_dcz_dict_file

**Syntax:** `zstd_dcz_dict_file /path/to/dictionary [sha256hex];`
**Default:** `—`
**Context:** `http`, `server`, `location` (repeatable)

Standards-based dictionary compression per [RFC 9842](https://www.rfc-editor.org/rfc/rfc9842) (Compression Dictionary Transport). Each occurrence loads one dictionary — typically a **previous version of the resource** (delta-style) or a trained dictionary — and registers its SHA-256 as a negotiation key. When a request arrives whose `Available-Dictionary` header matches a loaded dictionary **and** whose `Accept-Encoding` lists `dcz` explicitly with a non-zero weight, the response is compressed against that dictionary and sent as `Content-Encoding: dcz`: a fixed 40-byte header (a zstd skippable frame carrying the dictionary's SHA-256) followed by an ordinary zstd frame. Chrome 130+ negotiates this automatically for same-origin resources. Every gate miss — a non-secure context ([see below](#zstd_dcz_assume_secure_transport)), unknown hash, no explicit `dcz` token (`*` deliberately does not match), an effective `dcz;q=0`, a malformed `Available-Dictionary`, or `Sec-Fetch-Site` other than `same-origin`/`none` — falls back to the plain `zstd` path. The `dcz` token is looked for across *every* `Accept-Encoding` field line using the same ordered duplicate-coding rule as plain zstd (see the negotiation notes under [`ngx_http_zstd_filter_module`](#ngx_http_zstd_filter_module)).

Unlike `zstd_dict_file`, no opt-in flag is needed to make dcz *safe*: dcz is real HTTP negotiation, and only clients that advertised the dictionary ever receive it. One flag can still be required by your topology — RFC 9842 §8 restricts dcz to secure contexts, so a deployment where TLS is terminated *in front of* this nginx needs [zstd_dcz_assume_secure_transport](#zstd_dcz_assume_secure_transport). On a listener that terminates TLS itself, nothing extra is needed.

The optional second argument supplies the dictionary's SHA-256 as 64 hex characters. By default it is **verified** against the bytes actually read at config load: it declares what the operator believes the file to be, and a mismatch fails the load with an error naming the file, the supplied hash and the computed one. Use it as a deploy-time guard that the file on this host is the one the config was generated for — a dictionary replaced or truncated behind the config is caught by `nginx -t` instead of reaching clients. Malformed values (wrong length, non-hex) are config-load errors, reported before the file is opened. A running cycle always serves from the bytes loaded at its config parse — a file changing on disk affects nothing until the next parse. What that next parse does is where the policies differ: with no literal, the computed key simply becomes the new file's hash, so clients still holding the old dictionary stop matching and fall back to plain `zstd` (safe); with a literal under the default, the mismatch **fails the load** — the deploy-time guard; with a literal under `trust_hashes on`, the stale literal keeps matching, which is the stated risk below.

`zstd_dcz_dict_trust_hashes on;` (`http` only, default `off`) opts out of the verification: a supplied literal is then trusted **verbatim** as the negotiation key and the load-time SHA-256 is skipped entirely — lines without a literal are hashed as always. The hashing pass is the config-load cost at scale (measured at 737 dictionary lines: `nginx -t` drops from 5.1s to 0.9s, with the user-CPU column — the SHA-256 itself — going from 4.3s to 0.03s), so a content-addressed deployment whose tooling derives each literal from the file it ships can reclaim that on every `nginx -t` and reload. The stated trade: a stale or mistyped literal is advertised verbatim, and clients holding the advertised dictionary receive responses that may fail to decode, or silently decode to wrong content under a same-size stale dictionary. Only use it when the pipeline that writes the literal is the same one that placed the file. The directive must precede every `zstd_dcz_dict_file` carrying a literal; declaring it after one is a config-load error (the earlier literal was verified — correct, but the hashing the directive exists to skip was silently paid).

The module handles the response side; **advertising** the dictionary to clients is one `add_header` on the dictionary resource (usually the resource itself, so today's file becomes the dictionary for tomorrow's):

```nginx
http {
    zstd on;

    server {
        location /app/ {
            # Yesterday's release, now serving as the delta base.
            zstd_dcz_dict_file /var/www/releases/app-v41.js;

            # Today's file is itself the dictionary for the NEXT release:
            # a returning client sends Available-Dictionary: :sha256:.
            add_header Use-As-Dictionary 'match="/app/*.js"';
        }
    }
}
```

Operational notes:

* **Caching.** Whenever dictionaries are configured, the module emits `Vary: Available-Dictionary, Sec-Fetch-Site` on **both** the dcz and the plain-zstd variants — which encoding a client receives depends on that request header for every client, and a shared cache that failed to key on it could serve an undecodable dcz body to a dictionary-less client. `Sec-Fetch-Site` is in that list for the same reason: dcz is refused for any value other than `same-origin`/`none`, so a shared cache that ignored it would hand the dcz representation to a cross-site request — bypassing the origin gate — or suppress dcz for a legitimate same-origin client, depending on which one filled the cache first. Security decision inputs stay in `Vary`. `Vary: Accept-Encoding` is emitted alongside automatically, on its own header line.
* **Dictionary lifecycle.** Files are read once at config parse, and hashed — a supplied hash literal is verified against the bytes read, not substituted for hashing them, unless [`zstd_dcz_dict_trust_hashes on`](#zstd_dcz_dict_file) opts that line out of the pass entirely (`nginx -t` validates everything; empty or > 10 MB files and duplicate dictionary hashes are load errors — under `trust_hashes` a supplied hash is compared as declared, and with computed hashes "duplicate" means identical content). Rotate dictionaries by updating the config and reloading. A location that declares its own `zstd_dcz_dict_file` list replaces the inherited one wholesale. Hashing uses libcrypto's EVP SHA-256 when detected at build time — roughly an order of magnitude faster, which at hundreds of registered dictionaries turns seconds of `nginx -t`/reload time into a blip (`NGX_ZSTD_NO_LIBCRYPTO=1` in the configure environment opts out) — with a portable implementation built in as the fallback.
* **Window and memory.** dcz frames never declare a window above 8 MB (the RFC's unconditional client guarantee), sized down to dictionary + expected content when smaller. Either memory ceiling below that still wins — a dictionary does not void a cap the operator asked for. An explicit [`zstd_window_log`](#zstd_window_log) clamps the dcz window directly, and [`zstd_max_cctx_memory`](#zstd_max_cctx_memory) set to a POSITIVE budget clamps it to the largest window log whose estimated CCtx memory still fits that budget (computed once at config load, so the request path only compares). Both are **opt-in**: with `zstd_window_log` unset and `zstd_max_cctx_memory` either unset or `0` — the default, or an explicit "accept the estimate, do not enforce it" — the dcz window is the dictionary-derived one, unchanged. Note that a budget tight enough to move the window costs ratio on dcz responses, which is the trade an explicit memory bound asks for. Dictionaries are referenced per request via `ZSTD_CCtx_refPrefix()` (RFC 9842 `type=raw` semantics); the per-request table build over the dictionary costs roughly milliseconds per MB of dictionary, so prefer focused dictionaries (the previous version of one resource) over giant blobs.
* **Secure context.** RFC 9842 §8 restricts dictionary transport to secure contexts, so dcz is only negotiated over TLS. A plain-HTTP request that would otherwise match falls back to plain `zstd`. Behind a TLS-terminating proxy, see [zstd_dcz_assume_secure_transport](#zstd_dcz_assume_secure_transport).
* **Cross-origin.** Requests with `Sec-Fetch-Site` other than `same-origin`/`none` fall back to plain zstd rather than attempting RFC 9842's CORS legs. That decision is declared in `Vary` (see Caching above) so a shared cache partitions on it. `Dictionary-ID` is not consumed — the hash is a complete key — so omit `id=` from `Use-As-Dictionary` (clients would echo it, but nothing here needs it).

**Troubleshooting:** if `Vary: Available-Dictionary, Sec-Fetch-Site` appears but dcz never negotiates for hashes you know are right, run `nginx -T | grep dcz_dict_file` and check the loaded entries are your dictionary *files* — a deploy-generated list of directives must be pulled in with `include`, not passed to `zstd_dcz_dict_file` itself (which loyally loads the list file as a one-entry dictionary that matches nothing). Also check the error log for a rejected reload: a failed `nginx -t` leaves the previous configuration running.

Verify a response end-to-end with the zstd CLI (the 40-byte header is a valid skippable frame, so no stripping is needed):

```bash
curl -s -H 'Accept-Encoding: zstd, dcz' \
     -H "Available-Dictionary: :$(openssl dgst -sha256 -binary app-v41.js | base64):" \
     https://example.com/app/app-v42.js \
| zstd -d -D app-v41.js | diff - app-v42.js && echo "byte-exact"
```

---

### zstd_dcz_dict_trust_hashes

**Syntax:** `zstd_dcz_dict_trust_hashes on | off;`
**Default:** `off`
**Context:** `http`

Opts out of verifying the SHA-256 of each dictionary file when a hash literal is supplied to [`zstd_dcz_dict_file`](#zstd_dcz_dict_file). By default, a supplied hash is verified against the file's actual content at config load, catching deployment errors where the file on disk does not match what the config expects. With `zstd_dcz_dict_trust_hashes on;`, the supplied literal is trusted **verbatim** as the negotiation key and the hashing pass is skipped entirely.

This is an optimization for deployments where dictionaries are identified by content-addressed paths and the tooling that generates the config is the same tooling that places the files — a pipeline that can be trusted to derive each literal from the file it ships. It reclaims the config-load cost of hashing: measured on a production config with 737 dictionary lines, `nginx -t` runs 5.10s with the verify pass (4.26s user — the SHA-256 alone) against 0.87s with trusted literals (0.03s user). Lines without a literal are hashed as always; trust changes only what a supplied literal means.

The stated trade: a stale or mistyped literal is advertised verbatim, and clients holding the advertised dictionary receive responses they may fail to decode — or, when the stale dictionary happens to be the same size, that silently decode to wrong content. Only enable this when the pipeline that writes the literal is the same one that placed the file. The directive must precede every [`zstd_dcz_dict_file`](#zstd_dcz_dict_file) that carries a literal; declaring it after one is a config-load error.

**Example (content-addressed deployment with optimized hashing):**

```nginx
http {
    zstd on;
    zstd_dcz_dict_trust_hashes on;   # pipeline places files and generates hashes

    server {
        location /app/ {
            # Hash comes from the same tool that places the file;
            # the verify pass is skipped.
            zstd_dcz_dict_file /srv/dicts/app-v41-a1b2c3d4.bin a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01;
        }
    }
}
```

---

### zstd_dcz_assume_secure_transport

**Syntax:** `zstd_dcz_assume_secure_transport on | off;`
**Default:** `zstd_dcz_assume_secure_transport off;`
**Context:** `http`, `server`, `location`

Asserts that the client-facing hop is TLS even though this nginx sees plaintext, re-enabling [`dcz`](#zstd_dcz_dict_file) negotiation on a non-TLS connection.

[RFC 9842](https://www.rfc-editor.org/rfc/rfc9842) §8 requires compression dictionary transport to be used only in a **secure context**. By default the module enforces that directly: `dcz` is negotiated only when the request arrived on a TLS connection, and a plain-HTTP request that would otherwise match falls back to plain `zstd`. That is the fail-closed direction — dictionary compression over cleartext hands a network attacker a length oracle over content the dictionary already describes.

When TLS is terminated by a load balancer or CDN in front of this nginx, the connection nginx sees *is* plaintext and the check fires even though the client spoke HTTPS. Set this directive on in that deployment:

```nginx
server {
    listen 8080;                                # behind a TLS terminator

    zstd on;
    zstd_dcz_assume_secure_transport on;        # the client hop is HTTPS
    zstd_dcz_dict_file /var/www/releases/app-v41.js;
}
```

The directive is an **operator acknowledgement, not a detection**. The module deliberately does not infer the client's scheme from `X-Forwarded-Proto`, `Forwarded` or any other request header: those are client-supplied on a directly reachable listener, so trusting one would let any client re-enable `dcz` over cleartext simply by sending it. Only enable this on a listener that is genuinely unreachable except through your TLS terminator — if the same listener can be hit directly over HTTP, enabling it puts those clients back in the situation §8 forbids.

---

## ngx_http_zstd_static_module

This module serves pre-compressed `.zst` files in place of the originals, without running compression at request time. It is the zstd equivalent of nginx's `gzip_static` module.

---

### zstd_static

**Syntax:** `zstd_static on | off | always;`
**Default:** `zstd_static off;`
**Context:** `http, server, location`

Controls how pre-compressed `.zst` files are served.

| Value | Behaviour |
|---|---|
| `off` | Disabled. Always serve the original file. |
| `on` | Check whether the client supports zstd (`Accept-Encoding: zstd`). If yes and a `.zst` file exists, serve it. Otherwise fall back to the original. Emits `Vary: Accept-Encoding` automatically on both outcomes. |
| `always` | Serve the `.zst` file if it exists regardless of `Accept-Encoding`, except for dictionary-aware requests when [`zstd_static_dict_bypass`](#zstd_static_dict_bypass) is enabled. Use this when you know all other clients support zstd (e.g. internal services). |

When set to `on`, the module emits a `Vary: Accept-Encoding` response header itself as soon as a `.zst` sibling makes the URI depend on `Accept-Encoding` — including on the fallback path where the client does not accept zstd and the original file is served. Correct caching by proxies and CDNs therefore does not require [`gzip_vary`](https://nginx.org/en/docs/http/ngx_http_gzip_module.html#gzip_vary); setting `gzip_vary on` is compatible and never produces a duplicate header. With [`zstd_static_dict_bypass`](#zstd_static_dict_bypass) off, `zstd_static always` ignores `Accept-Encoding` and emits no `Vary`; the opt-in bypass is the exception described below.

> **Warning (`always` mode):** When `zstd_static always` is set and
> `zstd_static_dict_bypass` is off, this mode is non-conformant by design:
> `.zst` files are served with `Content-Encoding: zstd` to every client,
> including requests with no `Accept-Encoding`, `Accept-Encoding: identity`,
> or `Accept-Encoding: zstd;q=0`. It suppresses `Vary: Accept-Encoding` and
> performs no content-coding negotiation. With the
> bypass on, matching dictionary-aware requests stand aside with the complete
> cache key instead. `always` is safe only when every non-bypassed client is
> guaranteed to decode zstd — for example,
> internal service-to-service calls where you control both ends.

> **Magic-number validation.** Before serving a `.zst`, the module reads the frame header prefix (up to 58 bytes: a canonical 40-byte dcz skippable prefix plus room for the following 18-byte maximum frame header, one offset-explicit read per distinct offset) and verifies each frame it walks starts with the zstd frame magic (`ZSTD_MAGICNUMBER` `0xFD2FB528`) or a skippable-frame magic (`ZSTD_MAGIC_SKIPPABLE_*`). The module walks a bounded chain of up to 4 leading skippable frames — enough for a dcz-style prefix plus an extra marker frame — before requiring the frame that follows to be a regular one; a 5th leading skippable frame is a hard decline rather than a longer search, so the walk cannot be turned into an unbounded scan. On any mismatch — a truncated download, mistaken rename (`cp foo.txt foo.zst`), non-zstd content, or an over-long skippable chain — the handler logs `zstd static: "..." is not a zstd frame (leading bytes 0x...)` (or the matching skippable-chain-length error) and **declines**; nginx then falls back to serving the uncompressed original, or returns 404 if no original is present. Probe verdicts are memoized per worker by exact path, file identity, size, and mtime in one bounded 64-entry cache. Malformed verdicts remain until eviction or an identity change. Valid verdicts are cached only when `open_file_cache` is enabled and expire no later than `open_file_cache_valid`, so even a same-inode, same-size rewrite inside one-second mtime granularity is revalidated on that bound. A replaced file or changed path, size, or mtime is probed immediately, and round-robin eviction permits an earlier re-probe. Without validation, the client could receive a body labelled `Content-Encoding: zstd` that it cannot decode. Each read is offset-explicit so it never disturbs the file position of the `open_file_cache` descriptor shared with other in-flight requests: `pread(2)` on POSIX, `ngx_read_file()` (a `ReadFile()` with an `OVERLAPPED` offset) on Win32. The verdict logic is a single shared function, so both platforms accept and reject exactly the same files. The probe is compiled out only on a POSIX build whose `configure` found no `pread(2)`, rather than degraded to a `read`+`lseek` pair that would corrupt those concurrent requests.
>
> **Declared-window validation.** The same probe parses the frame header (RFC 8878) and **declines any `.zst` whose first regular frame — the one reached after walking the bounded leading-skippable-frame chain above — declares a decompression window above 8 MB** — the limit browsers enforce for `Content-Encoding: zstd`; Firefox (`NS_ERROR_INVALID_CONTENT_ENCODING`) and Chromium (`ERR_CONTENT_DECODING_FAILED`) reject such frames before decoding a single byte. The scope is exactly that first regular frame: leading skippable frames within the bound are stepped over rather than inspected for a window, and in a (pathological, no common tooling emits one) concatenation of regular frames only the first is inspected — a regular frame's header does not declare its compressed length, so walking the sequence would mean decoding every block header in every frame. `zstd -t --memory=8MB` remains the complete pre-deploy check. This traps a nasty build-pipeline failure mode: streaming encoders that are not told the input size stamp the *compression level's* default window into every frame header, so a Node-based bundler can emit a 90 KB asset declaring a 128 MB window — the file decodes fine with the `zstd` CLI and serves byte-identically through nginx, yet fails in every browser. On decline the error log names the file and its declared window, and the request falls through to the zstd filter / `gzip_static` / identity, so the site keeps working while the build gets fixed (recompress with a window log ≤ 23; verify a build with `zstd -t --memory=8MB *.zst`). Single-segment frames are checked against their declared content size, which is their window.

**Example:**

```nginx
gzip_vary on;

location /static/ {
    zstd_static on;
    root /var/www;
}
```

Pre-compress files with a matching level to your workload:

```bash
zstd -3 -k /var/www/static/app.js   # creates app.js.zst alongside app.js
```

### zstd_static_dict_bypass

**Syntax:** `zstd_static_dict_bypass on | off;`
**Default:** `zstd_static_dict_bypass off;`
**Context:** `http, server, location`

When enabled, `zstd_static` stands aside for a main request that carries any
`Available-Dictionary` header and explicitly accepts `dcz` with a non-zero
weight. This lets [`zstd_dcz_dict_file`](#zstd_dcz_dict_file) negotiate a
dictionary response instead of having the content-phase static handler serve
the plain `.zst` sidecar first. The check applies in both `zstd_static on` and
`zstd_static always` modes. Before declining it emits the complete
`Vary: Accept-Encoding, Available-Dictionary, Sec-Fetch-Site` cache key; the
filter reuses those idempotent fields when it runs, while an identity fallback
remains partitioned correctly when the filter is disabled or ineligible.

The directive is deliberately off by default. It is only a routing hint: the
static module does not validate the advertised digest, dictionary store match,
secure context, or origin policy. If any later dcz gate rejects the request,
the filter produces an ordinary zstd or identity response instead of returning
to the skipped sidecar. Enable it only on locations whose dictionary-aware
clients should prefer runtime dcz negotiation over a precompressed sidecar.

---

# Variables

## $zstd_ratio

The compression ratio achieved for the current response, expressed as the ratio of original size to compressed size (e.g. `3.42` means the compressed output is about 29% of the original). Only set when the filter module compressed the response.

Useful in access logs:

```nginx
log_format main '$remote_addr - $request - ratio: $zstd_ratio';
```

---

## $zstd_bytes_in

The number of uncompressed (input) bytes the filter consumed for the
current response. Only set once the filter has finished compressing the
response (log phase); not found otherwise. See
[`$zstd_bytes_out`](#zstd_bytes_out) below for a combined `log_format`
example.

## $zstd_bytes_out

The number of compressed (output) bytes the filter produced for the
current response. Same availability as `$zstd_bytes_in`.

Together these expose the **absolute** transfer saving, where
`$zstd_ratio` only gives the ratio. By construction
`$zstd_bytes_in / $zstd_bytes_out` equals `$zstd_ratio`:

```nginx
log_format zstd '$request in=$zstd_bytes_in out=$zstd_bytes_out '
                'ratio=$zstd_ratio';
```

## $zstd_dcz_dicts_hashed

How many dcz dictionaries were SHA-256-hashed at config load in the
current configuration cycle. By default every registered
[`zstd_dcz_dict_file`](#zstd_dcz_dict_file) entry is counted, including
entries whose supplied hash is verified. With
`zstd_dcz_dict_trust_hashes on`, supplied literals skip the pass and only
entries without literals are counted; `0` therefore proves that every
entry used a trusted literal. Constant for the lifetime of the
configuration (reset on reload), so one probe request answers "did my
deploy tooling's hashes actually take effect?":

```nginx
add_header X-Dcz-Dicts-Hashed $zstd_dcz_dicts_hashed;
```

The regression suite asserts on this variable because the trusted-literal
skip is otherwise unobservable when a supplied hash matches the file.

---

# Testing & CI

[`ci.yml`](.github/workflows/ci.yml) is the single PR gate entry point. It calls
the bounded merge checks below; each member also keeps `workflow_dispatch:` so
it can be run alone from the Actions tab. On merged `master`, CI selects only
the testkit harness to preserve its promotion signal without duplicating the
build, lint, scanner, or Windows jobs.

Long jobs are deliberately not called from it. **CI Deep** runs them weekly in
four explicit self-hosted dependency chains; **Bump** opens version-bump PRs
rather than gating them. The four-lane model applies when repository variable
`POOL` selects the shared self-hosted pool; an unset variable uses each job's
documented `ubuntu-latest` fallback instead.

| Workflow | Cadence | What it does |
|---|---|---|
| **CI** ([`ci.yml`](.github/workflows/ci.yml)) | every PR + focused merged `master` signal + manual | Calls only Lint, Build&Test, Security Scanners, Harness Fault Arms, and the hosted Windows build. Four Linux jobs are initially runnable; dependency chains refill each lane as it becomes free. Only Harness Fault Arms runs on merged `master`. |
| **Lint** ([`lint.yml`](.github/workflows/lint.yml)) | PR via CI + manual | Runs local deterministic checks, including runner trust, port bands, cadence, provenance, and the enforced four-lane topology. |
| **Build&Test** ([`build-test.yml`](.github/workflows/build-test.yml)) | PR via CI + manual | Builds nginx mainline with strict warnings, runs the full functional and runtime regression suites, tests libzstd 1.4.x fallbacks, linkage variants, and arm64. Its sanitizer lane runs the filter and static Test::Nginx suites plus the runtime regressions under ASAN/UBSAN, requiring complete TAP/clean exits and rejecting complete sanitizer reports that contain module frames. Its dependency graph forms four self-hosted lane chains. |
| **Security Scanners** ([`security-scanners.yml`](.github/workflows/security-scanners.yml)) | PR via CI, weekly deep + manual | Runs flawfinder, clang-tidy, and semgrep over the module sources. |
| **Harness Fault Arms** ([`harness-fault-arms.yml`](.github/workflows/harness-fault-arms.yml)) | PR and merged `master` via CI + manual, not required | Builds with the shared [`nginx-module-testkit`](https://github.com/myguard-labs/nginx-module-testkit) and runs all six fault, allocation, codec-count, and parameter-count scenarios through one non-vacuous scenario runner. |
| **Windows build** ([`windows-build.yml`](.github/workflows/windows-build.yml)) | PR via CI + manual | Builds and smoke-checks MSVC x64 static and MinGW-w64 x64 dynamic modules. |
| **CI Deep** ([`ci-deep.yml`](.github/workflows/ci-deep.yml)) | weekly + manual | Runs four explicit chains: two long fuzz targets; Memcheck then coverage, CodeQL, serialized nginx/stable/Angie builds, scanners, and native A/UBSan; and all six testkit scenarios under Memcheck followed by Helgrind. Coverage includes all Test::Nginx suites, broad assertion-bearing runtime drivers, and all testkit scenarios, with an 85% line floor. |
| **Fuzzing** ([`fuzzing.yml`](.github/workflows/fuzzing.yml)) | manual | Provides targeted short runs. CI Deep runs its own long jobs for both parser targets. See [`ci/fuzz/README.md`](ci/fuzz/README.md). |
| **Valgrind** ([`valgrind.yml`](.github/workflows/valgrind.yml)) | manual | Provides a targeted Memcheck-lite run. CI Deep runs its own full Memcheck and Helgrind soaks. |
| **CodeQL** ([`codeql.yml`](.github/workflows/codeql.yml)) | manual/reusable; weekly via CI Deep | Runs GitHub's semantic C/C++ `security-extended` analysis. |
| **A/UBSan** ([`asan.yml`](.github/workflows/asan.yml)) | manual/reusable; weekly via CI Deep | Runs a native mixed-load ASAN/UBSAN soak, complementing Build&Test's sanitizer suite. |
| **Bump** ([`bump.yml`](.github/workflows/bump.yml)) | weekly + manual dispatch | Checks the GitHub release feeds (nginx, Angie, pcre2, zlib, OpenSSL, zstd) for newer releases than what's pinned — nginx-stable/Angie in CI Deep's `build-flavors` matrix, the harness jobs' mainline pin, and the Windows build's sources in [`ci/tools/windows-pins.sh`](ci/tools/windows-pins.sh) — and opens a PR (never pushes directly to protected `master`) with the updated pins + freshly-computed sha256 digests (nginx tarballs PGP-verified first). Does not gate merges itself — normal required checks review the PR. |

The test suite includes a dedicated regression test for every known
historical bug class:

* infinite-loop / CPU-spin DoS on zero-length and sub-stream-size bodies;
* the `proxy_buffering off` chunked-stream truncation ("bug B" —
  zero-size buffer forwarded to the writer), plus a ~504-cell
  compression-correctness matrix that decodes and byte-compares every
  transport × payload × encoding combination;
* per-request `ZSTD_CCtx` isolation (one request's compressor state
  bleeding into another) and reload-under-load response correctness;
* `$zstd_ratio` integer overflow on large bodies;
* filter ordering vs `sub_filter`; negative compression levels;
  `zstd_types` parsing; `zstd_max_length` enforcement (known and
  chunked length); `zstd_window_log`; `zstd_long`/LDM; `zstd_bypass`;
  the pledged-source-size path;
* `zstd_max_cctx_memory` rejects parameters that exceed the budget
  (config-load assertion);
* `zstd_static` declines `.zst` files whose magic number is not a real
  zstd frame (defence-in-depth against truncated / mis-renamed files);
* the multi-occurrence `Accept-Encoding` parser path (a header like
  `notzstd, zstd` must still negotiate zstd — covered by Perl tests
  *and* by continuous libFuzzer with ASAN/UBSAN over a NUL-free
  exact-size buffer);
* the `zstd_dict_file` feature, long-URI `.zst` path handling, and the
  `ZSTD_CDict` config-reload leak.

Run the suites locally:

```bash
# Perl suites (needs Test::Nginx::Socket and a built nginx)
TEST_NGINX_BINARY=/path/to/nginx prove \
  ci/t/00-filter.t ci/t/01-static.t ci/t/02-conf-warn.t ci/t/03-dcz.t

# Unit tests over the Accept-Encoding decision function
ci/tests/unit/run.sh

# End-to-end smoke tests
python3 ci/tools/test_encoding.py --nginx-binary /path/to/nginx

# Build and run the fuzzer (needs clang)
bash ci/fuzz/build.sh && ./ci/fuzz/fuzz_accept_encoding -max_total_time=60 ci/fuzz/corpus/
```

## Repository layout

Everything CI needs lives under `ci/`, so the repository root stays the
module: sources, docs and packaging.

```text
src/                     the module itself
  ngx_http_zstd_filter_module.c    the compression filter
  ngx_http_zstd_static_module.c    the .zst static handler
  ngx_http_zstd_common.h           shared helpers + the Accept-Encoding parser
ci/
  t/                     Test::Nginx::Socket suites (00-filter, 01-static, …)
  tests/unit/            unit tests over the real decision TU
  tools/                 soak.sh, test_encoding.py, benchmark.py, ci-build.sh, …
  fuzz/                  libFuzzer target, corpus, dictionary, regressions
  linter/                the checker set run by the hook and the Lint workflow
  ast-grep/              structural rules
.github/workflows/       ci.yml (the only pull_request entry point) + members
.githooks/pre-commit     the tracked local gate
```

The `Accept-Encoding` parser is sliced out of `src/ngx_http_zstd_common.h`
into the fuzz and unit builds at build time by `ci/fuzz/extract_parser.sh`,
so those targets always compile production code — there is no second copy to
drift.

## Linting

The same checkers run in three places: your commit (via `.githooks/pre-commit`),
`ci/linter/run-all.sh` by hand, and the **Lint** workflow on every PR.

```sh
git config core.hooksPath .githooks    # enable the hook, once per clone
ci/linter/install-linters.sh           # install what the checkers need
ci/linter/install-linters.sh --check   # report presence; non-zero if any missing
ci/linter/run-all.sh                   # run every checker over the tracked tree
```

Full description of each checker, what it is blind to, and how to narrow a run
with `LINT_ONLY`: [`ci/linter/README.md`](ci/linter/README.md). Contributor
setup and the `git ls-files` trap: [CONTRIBUTING.md](CONTRIBUTING.md).

# Benchmarks

Reproduce with `python3 ci/tools/benchmark.py` (drives the `zstd`/`gzip`
CLIs linked against the same libzstd/zlib on the machine that runs it).
Compression **ratio** for a given library/input/settings combination is
stable across runs and machines, but not necessarily across libzstd
versions — encoder heuristics change between releases while staying
format-compatible, so expect the ratios below to shift somewhat on the
recommended 1.5.7 rather than the 1.5.5 measured here. **Throughput** is
not stable at all: it scales with CPU and varies run to run, so treat
any MB/s figure as a rough range, not a point value. These numbers come
from the CLI codecs directly: they exclude nginx's own filter, context,
buffering, and flush overhead, so they are not a measurement of module
throughput. Figures below: **libzstd 1.5.5**, single core, `--repeat 3`,
best wall-time.

For nginx request-path measurements, `ci/tools/ab_bench.py` keeps its existing
plain-zstd workload by default and accepts `--workload dcz` for a focused RFC
9842 dictionary hit or miss. `ci/tools/perf_stat_recipe.py` runs the fixed 1,
4, and 16 configured-dictionary hit/miss matrix, records the response-encoding
preflight and every successful measured request in JSON. Hardware counters
attach only to the pinned nginx worker during measured release runs, excluding
the Python harness, backend, wrk, startup, fixture creation, and cleanup; the
comparison reports cache misses, references, instructions, and cycles per
measured request.

| Payload | Codec | Ratio | MB/s |
|---|---|---:|---:|
| HTML, 58 KB (test fixture) | gzip-6 | 15.5 | 29 |
| | zstd-3 | 16.1 | 12 |
| | zstd-19 | 17.1 | 0.8 |
| JSON API, 256 KB | gzip-6 | 12.5 | 72 |
| | zstd-1 | 43.8 | 52 |
| | zstd-3 | 33.6 | 43 |
| JS, 512 KB | gzip-6 | 12.7 | 108 |
| | zstd-1 | 63.6 | 87 |
| | zstd-3 | 40.8 | 78 |
| Random 256 KB (incompressible) | gzip-6 | 1.00 | 31 |
| | zstd-3 | 1.00 | 36 |

Honest reading of these numbers:

* On **small** payloads (the 58 KB HTML fixture), low-level zstd is
  roughly on par with `gzip -6` and a touch slower — gzip is well tuned
  for small text. zstd's advantage grows with payload size.
* On **larger, structured** payloads zstd at a *low* level beats gzip
  decisively on **ratio** (e.g. ~44× vs ~12× on JSON, ~64× vs ~13× on
  JS). **Throughput is the opposite** in this table: gzip-6 CLI
  throughput is higher than zstd-1/zstd-3 on both JSON (72 MB/s vs 52
  and 43) and JS (108 MB/s vs 87 and 78). Choose zstd here for the
  ratio and CPU-per-byte-stored win, not for raw CLI speed. For typical
  web traffic, `zstd_comp_level 1`–`3` is the sweet spot.
* On the **incompressible** payload, zstd-3 is faster than gzip-6 (36
  vs 31 MB/s) with both codecs at a 1.00 ratio — zstd detects
  incompressible input and gives up cheaply.
* The synthetic JSON/JS generators are deliberately repetitive, so
  ratios there are inflated and *higher zstd levels show a lower ratio*
  — an artefact of trivially-redundant input, **not** representative of
  real assets. The HTML fixture (real-world content) shows the expected
  monotonic "higher level → better ratio, slower".
* High levels (≥ 9) cost CPU steeply for marginal gain on web content —
  reserve them for infrequently-generated, cached responses.

**How recent module changes affect these numbers.** The table above is
driven by the `zstd`/`gzip` CLIs against the same libzstd, so it
measures the *codec* — it is deliberately independent of nginx and does
**not** move when the module's internals change. The compression
**ratio** for a given level is therefore unchanged by any recent work.
What changed is the module's per-response *overhead* inside nginx:

* **Output buffers now default to `2 × ZSTD_CStreamOutSize()`**
  (previously a `4 × 32 KB` heuristic, and originally `32 × 4 KB`).
  Each `ZSTD_compressStream2()` call can now flush a complete internal
  block in one go instead of fragmenting it across calls, removing
  redundant compress round-trips and output-chain allocations per
  response. This shows up as lower CPU-per-response and less allocator
  churn under load — not as a different ratio or a different CLI MB/s
  figure. The trade is a higher per-request memory floor (~256 KB);
  see [`zstd_buffers`](#zstd_buffers).
* **`$zstd_ratio` is computed by exact integer long division**, so it
  stays correct for byte counts near the 64-bit range and for streams
  that expand rather than shrink — a log-path cost only, no effect on
  the response itself.
* **`zstd_long` (off by default)** can materially improve ratio on
  large, internally repetitive bodies that exceed the match window —
  but only when explicitly enabled, and the gain is workload-specific,
  so it is not reflected in the synthetic table above. Measure on your
  own assets before enabling.

In short: the codec figures here are stable by design; the recent
changes make the module *cheaper to run at the same ratio*, and add an
opt-in ratio lever (`zstd_long`) for specific workloads.

# Operations

**Reloads (`nginx -s reload`).** Compression state is per request: a
`ZSTD_CCtx` is created/reset per request and freed via an nginx pool
cleanup. A graceful reload spins up new workers and drains old ones
normally — in-flight responses on old workers finish on their existing
context; new requests use new workers. There is no shared compression
state to corrupt across a reload. The `zstd_dict_file` `ZSTD_CDict` is
loaded once per cycle and freed on the old cycle's cleanup; a
reload-leak regression for exactly this runs under ASAN in CI
(`ci/tools/test_reload_leak.sh`).

**`zstd_dict_file`.** Loaded at config load in the `http` context, into
a `ZSTD_CDict` shared read-only by all workers (dictionary size capped
at 10 MB). The dictionary must be readable by the nginx user at config
load and reload. Changing it requires a reload. **Both ends must agree
on the dictionary**: HTTP has no dictionary negotiation, so only use
this where you control client and server (see the directive's warning).

**Rollback.** The module adds no persistent state, on-disk format, or
schema — it only transforms response bodies in memory. Rolling back is
purely "load the previous `.so` / previous nginx binary and reload":

1. Keep the previously-known-good module `.so` (or full nginx binary).
2. To disable instantly without a binary change: set `zstd off;` (and
   `zstd_static off;`) and `nginx -s reload` — responses immediately
   serve identity; no client/cache corruption. The compressed and
   identity responses are different representations — the body bytes
   differ, not just the `Content-Encoding` field — and the automatic
   `Vary: Accept-Encoding` is what keeps each in its own cache
   variant, so a cache filled before the reload never hands a
   compressed body to a client that did not ask for one.
3. To revert the binary: restore the prior `.so`/binary, `nginx -t`,
   then `nginx -s reload`.

No data migration, no irreversible step. A bad deploy is a one-line
config change or a binary swap away from rolled back.

**Pre-deploy soak.** `ci/tools/soak.sh <nginx> <seconds> <concurrency>`
drives sustained mixed load (tiny/medium/large/compressible payloads,
zstd and non-zstd clients, the bypass path, a chunked upstream) and
fails on any sanitizer report, leak, crash, `[alert]`/`[emerg]`, or
corrupted response. Run it against an ASAN/UBSAN build (optionally
`USE_VALGRIND=1`) before shipping a change. CI runs a 10-minute soak
under ASAN+UBSAN on the weekly schedule (`Soak ASAN+UBSAN` job).

# Security

Compression of HTTP responses has a security dimension. See
[`SECURITY.md`](SECURITY.md) for the vulnerability-disclosure process
and the explicit in-scope / out-of-scope boundary (notably: BREACH
containment is `zstd_bypass`, not a fix; CRIME/POODLE are TLS-layer and
out of scope). The request parser is continuously fuzzed and the module
is built and load-tested under ASAN/UBSAN.

# Author

Alex Zhang (张超) \<zchao1995@gmail.com\>, UPYUN Inc.

Hardening, test suite, fuzzing and CI by Thijs Eilander and the
[deb.myguard.nl](https://deb.myguard.nl/) maintainers.

# License

Licensed under the [BSD 2-Clause License](LICENSE).
