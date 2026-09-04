use Test::Nginx::Socket;
use File::Basename;
use File::Spec;
use lib 'lib';

my @dynamic_modules;
if (defined $ENV{'TEST_NGINX_BINARY'}) {
    my $nginx_dir = dirname($ENV{'TEST_NGINX_BINARY'});
    for my $module_name (qw(ngx_http_zstd_filter_module.so ngx_http_zstd_static_module.so)) {
        my $module_path = "$nginx_dir/$module_name";
        push @dynamic_modules, $module_path if -f $module_path;
    }
}

add_block_preprocessor(sub {
    my $block = shift;
    return if !@dynamic_modules;

    my $main_config = join "\n", map { "load_module $_;" } @dynamic_modules;
    $block->set_value("main_config", $main_config);
});

no_long_string();
log_level 'debug';
repeat_each(3);
check_accum_error_log();
plan 'no_plan';
run_tests();

# COVERAGE NOTES on gaps found by the git-history CI audit
# (kept above __DATA__ so they are not parsed into any test block):
#
# Gap 2 — f7e2ef3 ("clear Accept-Ranges in static module"), since
# REVERSED: the handler now opts IN via r->allow_ranges = 1, covered
# fail-first by TESTS 36–37. The history, for the record: f7e2ef3's
# clear was a no-op (the handler never set r->allow_ranges, and
# ngx_http_range_filter_module.c bails without it — empirically
# verified at the time: identical responses on pre-fix and fixed
# builds), and its rationale misread the RFC it cited. RFC 9110 §14.2
# has ranges address the SELECTED REPRESENTATION — under
# Content-Encoding: zstd, the .zst bytes — which is not an
# "undecipherable fragment" hazard but exactly the coherent,
# resumable-download semantics gzip_static has always provided by
# setting r->allow_ranges = 1 (strong validator, byte-identical
# representation on disk). The filter module's clear remains correct
# for the opposite reason: a stream generated on the fly has nothing
# stable to seek into.
#
# Gap 3 — HTTP/2 transport axis (8281baa bug-B class):
# the build enables --with-http_v2_module but nothing tests the h2
# path. HTTP/2 in nginx requires TLS + ALPN/Upgrade negotiation; h2c
# (cleartext) does not work without Upgrade in nginx config. A Python
# test without TLS cannot easily drive the h2 path. The bug-B defect
# (empty-buffer, flush-state-machine, c->buffered accounting) is
# already well-covered by test_proxy_unbuffered_truncation.py
# (HTTP/1.1) and the matrix under ASAN; the h2-specific framing path
# would be redundant effort without adding coverage for a new code
# path. Left for future work when/if CI adds TLS test infrastructure.


__DATA__


=== TEST 1: zstd_static off
--- config
    location /test {
        zstd_static off;
        root ../suite;
    }
--- request
GET /test
--- response_headers
Content-Length: 59738
ETag: "5be17d33-e95a"
!Content-Encoding
--- no_error_log
[error]



=== TEST 2: zstd_static off (with accept-encoding header)
--- config
    location /test {
        zstd_static off;
        root ../suite;
    }
--- request
GET /test
Accept-Encoding: gzip,zstd
--- response_headers
Content-Length: 59738
ETag: "5be17d33-e95a"
!Content-Encoding
--- no_error_log
[error]



=== TEST 3: zstd_static on
--- config
    location /test {
        zstd_static on;
        root ../suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: gzip, zstd
--- response_headers
Content-Length: 3717
ETag: "5be17d33-e85"
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 4: zstd_static on (without accept-encoding header)
--- config
    location /test {
        zstd_static on;
        root ../suite;
    }
--- request
GET /test
--- response_headers
Content-Length: 59738
ETag: "5be17d33-e95a"
!Content-Encoding
--- no_error_log
[error]



=== TEST 5: zstd_static on (without zstd component in accept-encoding header)
--- config
    location /test {
        zstd_static on;
        root ../suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: gzip, br
--- response_headers
Content-Length: 59738
ETag: "5be17d33-e95a"
!Content-Encoding
--- no_error_log
[error]



=== TEST 6: zstd_static always
--- config
    location /test {
        zstd_static always;
        root ../suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: gzip, br
--- response_headers
Content-Length: 3717
ETag: "5be17d33-e85"
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 7: zstd_static always (without accept-encoding header)
--- config
    location /test {
        zstd_static always;
        root ../suite;
    }
--- request
GET /test
--- response_headers
Content-Length: 3717
ETag: "5be17d33-e85"
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 8: zstd_static always (without zstd component in accept-encoding header)
--- config
    location /test {
        zstd_static always;
        root ../suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: gzip, br
--- response_headers
Content-Length: 3717
ETag: "5be17d33-e85"
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 9: zstd_static always (file does not exist)
--- config
    location /test2 {
        zstd_static always;
        root ../suite;
    }
--- request
GET /test2
--- more_headers
Accept-Encoding: gzip, br
--- error_code: 404



=== TEST 10: zstd_static on (file does not exist)
--- config
    location /test2 {
        zstd_static on;
        root ../suite;
    }
--- request
GET /test2
--- more_headers
Accept-Encoding: gzip, br
--- error_code: 404



=== TEST 11: zstd_static off (file does not exist)
--- config
    location /test2 {
        zstd_static off;
        root ../suite;
    }
--- request
GET /test2
--- more_headers
Accept-Encoding: gzip, br
--- error_code: 404



=== TEST 12: zstd_static on with quality value q=0 (reject)
--- config
    location /test {
        zstd_static on;
        root ../suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: zstd;q=0, gzip;q=1
--- response_headers
Content-Length: 59738
ETag: "5be17d33-e95a"
!Content-Encoding
--- no_error_log
[error]



=== TEST 13: zstd_static on with quality value q=0.5 (accept lower)
--- config
    location /test {
        zstd_static on;
        root ../suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: zstd;q=0.5
--- response_headers
Content-Length: 3717
ETag: "5be17d33-e85"
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 14: zstd_static always with q=0 (still serve zst)
--- config
    location /test {
        zstd_static always;
        root ../suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: zstd;q=0
--- response_headers
Content-Length: 3717
ETag: "5be17d33-e85"
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 15: zstd_static on with gzip_vary and gzip support
--- config
    location /test {
        zstd_static on;
        gzip_vary on;
        root ../suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: gzip, zstd
--- response_headers
Content-Length: 3717
ETag: "5be17d33-e85"
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 16: zstd_static on with gzip_vary but no zstd support
--- config
    location /test {
        zstd_static on;
        gzip_vary on;
        root ../suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: gzip
--- response_headers
Content-Length: 59738
ETag: "5be17d33-e95a"
!Content-Encoding
--- no_error_log
[error]



=== TEST 17: zstd_static on - HEAD request
--- config
    location /test {
        zstd_static on;
        root ../suite;
    }
--- request
HEAD /test
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Length: 3717
ETag: "5be17d33-e85"
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 18: zstd_static on - POST request (not GET/HEAD)
--- config
    location /test {
        zstd_static on;
        root ../suite;
    }
--- request
POST /test
--- more_headers
Accept-Encoding: zstd
--- error_code: 405
--- response_headers
!Content-Encoding



=== TEST 19: zstd_dict_file loads and serves correctly (filter path)
# Regression for the untested zstd_dict_file feature, which had three
# distinct historical bug fixes with NO test: 0fb40d9 (CDict leak on
# cleanup), 50f27a8 (version-specific init error handling), f735a5d
# (cleanup handler size). This is the first test that exercises a
# dictionary at all: nginx must start with zstd_dict_file set and still
# produce a valid compressed response.
# zstd_dict_file is an http{}-context directive (NGX_HTTP_MAIN_CONF), so
# it goes in --- http_config, not --- main_config (global, before http{}).
# Relative paths resolve against the *configuration* prefix (conf/), while
# --- user_files land in <servroot>/html, so use the absolute servroot
# token Test::Nginx exports for this exact purpose.
--- http_config
    zstd_dict_file_unsafe on;
    zstd_dict_file $TEST_NGINX_SERVER_ROOT/html/zstd.dict;
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/src;
    }
    location /src {
        default_type text/plain;
        return 200 "dictionary compressed body, long enough to compress\n";
    }
--- user_files
>>> zstd.dict
the quick brown fox jumps over the lazy dog 0123456789 dictionary sample payload for zstd training corpus padding padding padding
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 20: zstd_static handles a long URI without buffer overflow
# Regression for 9789448 "buffer overflow when appending .zst extension".
# A long request path stresses the .zst path-build reservation made via
# ngx_http_map_uri_to_path(sizeof(".zst")). Missing file -> clean 404,
# no crash, no ASAN abort (the ASAN test job runs this binary too).
--- config
    location /s/ {
        zstd_static on;
        root ../suite;
    }
--- request eval
"GET /s/" . ("a" x 2000) . "/nonexistent-resource-name"
--- error_code: 404
--- response_headers
!Content-Encoding
--- no_error_log
[alert]



=== TEST 21: zstd_static rejects a file whose contents are not a zstd frame
# Defence-in-depth: a .zst whose first 4 bytes are not the zstd magic
# (truncated download, mistakenly renamed text, `cp foo.txt foo.zst`)
# must NOT be served with Content-Encoding: zstd — the client would
# receive an undecodable body. The handler pread()s the leading 4
# bytes, checks them against ZSTD_MAGICNUMBER / ZSTD_MAGIC_SKIPPABLE_*,
# and declines on mismatch. The fixture below contains plain ASCII
# ("HELO ...") with no zstd magic; no uncompressed fallback file is
# placed alongside it, so the request falls through to a clean 404.
--- config
    location /bogus {
        zstd_static on;
        root html;
    }
--- user_files
>>> bogus.zst
HELO this is not a zstd frame
--- request
GET /bogus
--- more_headers
Accept-Encoding: zstd
--- error_code: 404
--- response_headers
!Content-Encoding
!Vary
--- error_log
is not a zstd frame



=== TEST 22: zstd_static always does NOT set Vary even with gzip_vary on
# Locks intentional behaviour: in "always" mode the handler unconditionally
# serves the precompressed .zst and never sets r->gzip_vary. Vary:
# Accept-Encoding would mis-key shared caches for a response that does
# not actually vary on Accept-Encoding (the same .zst comes back no
# matter what the client sends), so the absence of Vary here is the
# correct contract. TEST 6-8 cover "always" without gzip_vary; this
# locks that adding gzip_vary on at the location does not flip the
# behaviour by accident.
--- config
    gzip_vary on;
    location /test {
        zstd_static always;
        root ../suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: gzip, br
--- response_headers
Content-Length: 3717
ETag: "5be17d33-e85"
Content-Encoding: zstd
!Vary
--- no_error_log
[error]



=== TEST 23: zstd_static rejects an empty .zst file
# A zero-byte .zst cannot satisfy the 4-byte pread() magic check;
# the handler must decline rather than serve an empty body with
# Content-Encoding: zstd. TEST 21 covers the wrong-magic case;
# this locks the truncated-to-zero edge specifically. Like TEST 21,
# no uncompressed fallback is placed alongside empty.zst, so a
# benign ENOENT on the fallback path is expected and not asserted
# against.
--- config
    location /empty {
        zstd_static on;
        root html;
    }
--- user_files
>>> empty.zst
--- request
GET /empty
--- more_headers
Accept-Encoding: zstd
--- error_code: 404
--- response_headers
!Content-Encoding
!Vary



=== TEST 24: zstd_static declines a directory-style request
# A request whose URI ends in "/" maps to a path with a trailing
# slash; appending ".zst" would produce ".../.zst". The handler
# short-circuits at the URI-suffix check (uri.data[uri.len - 1]
# == '/') and declines without touching the filesystem, so the
# request falls through to the normal directory-index machinery
# rather than being answered with Content-Encoding: zstd. The
# fallback then 403s the directory and logs the missing index file
# — that log line is from the regular static handler, not from
# zstd_static, and is expected here. The contract being locked is
# only !Content-Encoding (i.e. zstd_static did not falsely claim
# the response was zstd-encoded).
--- config
    location /dir/ {
        zstd_static on;
        root ../suite;
    }
--- request
GET /dir/
--- more_headers
Accept-Encoding: zstd
--- error_code: 404
--- response_headers
!Content-Encoding



=== TEST 25: zstd_static on sets Vary even when declining for a non-accepting client
# Subtle behaviour at static.c:204 — when zstd_static is "on" and
# the .zst exists, the handler sets r->gzip_vary = 1 *before*
# declining for a client that does not accept zstd. That keeps the
# response cacheable by intermediaries that key on Vary, so a later
# request from a zstd-capable client through the same shared cache
# gets the encoded variant rather than the identity one. Without
# this, a CDN that saw the identity response first would pin all
# subsequent clients to it.
--- config
    gzip_vary on;
    location /test {
        zstd_static on;
        root ../suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: gzip
--- response_headers
!Content-Encoding
Vary: Accept-Encoding
--- no_error_log
[error]



=== TEST 25a: zstd_static on sets Vary with gzip_vary OFF (non-accepting client)
# G5: the gzip_vary-off cell of TEST 25, and the one that was broken.
# With no "gzip_vary on", the handler used to return early WITHOUT even
# probing for the .zst, so this identity response carried no Vary at
# all — a shared cache then pinned every later client, including
# zstd-capable ones, to the identity variant. The handler now emits the
# field itself before declining.
--- config
    location /test {
        zstd_static on;
        root ../suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: gzip
--- response_headers
!Content-Encoding
Vary: Accept-Encoding
--- no_error_log
[error]



=== TEST 25b: zstd_static on sets Vary with gzip_vary OFF (accepting client)
# The served-.zst arm of the same cell: the compressed representation
# must announce that it was negotiated on Accept-Encoding, or a cache
# hands it to a client that cannot decode it. Together with TEST 15,
# TEST 16 and TEST 25a this completes the static handler's
# gzip_vary x Accept-Encoding matrix.
--- config
    location /test {
        zstd_static on;
        root ../suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
Vary: Accept-Encoding
--- no_error_log
[error]



=== TEST 26: zstd_static serves a .zst under directio without a failed pread
# Regression for the O_DIRECT magic-probe bug. With "directio" active the
# open_file_cache opens the .zst with O_DIRECT; the 4-byte, unaligned
# magic pread() then fails EINVAL, wrongly declining every .zst above the
# threshold and spamming NGX_LOG_CRIT. The fix skips the probe when
# of.is_directio. Assert the precompressed frame is still served (200 +
# Content-Encoding: zstd) and no CRIT/[error] appears.
#
# NOTE: O_DIRECT support is filesystem-dependent (tmpfs may not honour it),
# so this deterministically catches the "declined + CRIT" regression only
# where O_DIRECT actually engages; everywhere else it still asserts correct
# serving. directio 1 = every file >= 1 byte is eligible (test.zst is 3717B).
--- config
    location /test {
        zstd_static on;
        directio 1;
        root ../suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- error_code: 200
--- no_error_log
[error]



=== TEST 27: zstd_static "on" declining does not suppress the gzip fallback
# Regression for the gzip-fallback latch. ngx_http_zstd_ok() latches
# r->gzip_tested=1 / r->gzip_ok=0 as a side effect; the static handler
# used to call it (before the .zst existence check), so when the .zst was
# absent it declined but left gzip permanently marked "not ok" for the
# request. A later gzip filter/handler then short-circuited on the cached
# decision and served identity instead of gzip. The fix routes the static
# decision through the side-effect-free ngx_http_zstd_accepts().
#
# Reproduces with the always-present gzip *filter* (no gzip_static needed):
# request a plain file that has NO sibling .zst. zstd_static declines; the
# core static handler serves it; the gzip filter must still compress it.
# Pre-fix: Content-Encoding is absent (gzip suppressed). Post-fix: gzip.
--- config
    location /gz/ {
        zstd_static on;
        gzip on;
        gzip_min_length 1;
        gzip_types text/plain;
        root html;
    }
--- user_files
>>> gz/plain.txt
gzip fallback body long enough to exceed gzip_min_length and actually compress padding padding padding padding
--- request
GET /gz/plain.txt
--- more_headers
Accept-Encoding: gzip, zstd
--- response_headers
Content-Encoding: gzip
--- error_code: 200
--- no_error_log
[error]



=== TEST 28: zstd_static coexists with gzip_static; .gz still served
# Interop guard, sibling of TEST 27 but for the gzip_static *module*.
# NOTE: unlike the gzip *filter* (TEST 27), gzip_static is a CONTENT_PHASE
# handler. It is a built-in module, so its handler is pushed onto the
# content-phase array before the dynamically-loaded zstd_static handler and
# runs FIRST -- it serves the .gz before zstd_static ever runs, so the
# ngx_http_zstd_ok() latch could not suppress it even on the pre-fix code.
# (Verified: this test passes on both pre-fix and the fixed tree; the real
# latch regression is covered by TEST 27 via the post-content gzip filter.)
# Kept as a coexistence contract: with both directives on and a .gz but no
# .zst present, zstd_static declines and gzip_static serves the .gz -- the
# two static handlers must not fight over the request.
#
# The request has NO sibling .zst (so zstd_static declines) but DOES have a
# real gzip-compressed plain.txt.gz (so gzip_static must serve it).
--- config
    location /gzs/ {
        zstd_static on;
        gzip_static on;
        root html;
    }
--- user_files eval
my $body = "gzip_static fallback body long enough to matter " x 4;
my $gz;
require IO::Compress::Gzip;
IO::Compress::Gzip::gzip(\$body => \$gz)
    or die "gzip failed: $IO::Compress::Gzip::GzipError";
">>> gzs/plain.txt\n$body>>> gzs/plain.txt.gz\n$gz";
--- request
GET /gzs/plain.txt
--- more_headers
Accept-Encoding: gzip, zstd
--- response_headers
Content-Encoding: gzip
--- error_code: 200
--- no_error_log
[error]


=== TEST 29: Content-Encoding entry leaves the headers_out chain terminated
# Sibling of filter TEST 85 for the static module: the .zst sidecar path
# pushes its own Content-Encoding entry and must terminate the header
# chain the same way (see core ngx_http_gzip_static_module.c).
--- config
    location /test {
        zstd_static on;
        add_header X-Sent-Content-Encoding $sent_http_content_encoding;
        root ../suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: gzip, zstd
--- response_headers
Content-Encoding: zstd
X-Sent-Content-Encoding: zstd
--- error_code: 200
--- no_error_log
[error]



=== TEST 30: a .zst that is a DIRECTORY is declined, origin served instead
# of.is_dir branch in the static handler. ngx_open_cached_file() succeeds on a
# directory, so without the is_dir check the handler would proceed to serve a
# directory fd as a response body. Creating "dir.txt.zst/" as a real directory
# (via a file nested inside it) makes the sibling lookup hit a directory; the
# handler must decline and let the plain origin be served.
--- config
    location /isdir/ {
        zstd_static on;
        root html;
    }
--- user_files
>>> isdir/dir.txt
plain origin body served because the .zst sibling is a directory
>>> isdir/dir.txt.zst/keep.txt
this file only exists to make dir.txt.zst a directory
--- request
GET /isdir/dir.txt
--- more_headers
Accept-Encoding: zstd
--- response_headers
! Content-Encoding
! Vary
--- response_body
plain origin body served because the .zst sibling is a directory
--- error_code: 200
--- no_error_log
[error]



=== TEST 31: a .zst declaring a >8MB window is declined (streaming frame)
# The frame header (built byte-by-byte from RFC 8878 §3.1.1.1) declares
# a 128 MB decompression window: magic, descriptor 0x00 (no
# Single_Segment), Window_Descriptor 0x88 = exponent 17 -> 1 << 27.
# That is what a Node streaming encoder stamps at high levels when not
# told the input size — the file decodes fine with the zstd CLI but
# every browser rejects it before decoding, so the handler must decline
# from the header alone (trailing zeros stand in for the never-read
# block data) and let the identity origin be served.
--- config
    location /bw/ {
        zstd_static on;
        root html;
    }
--- user_files eval
">>> bw/big.js\nbig-window stream body\n>>> bw/big.js.zst\n"
. pack("C*", 0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x88, 0x00, 0x00, 0x00)
--- request
GET /bw/big.js
--- more_headers
Accept-Encoding: gzip, zstd
--- response_headers
! Content-Encoding
--- response_body
big-window stream body
--- error_code: 200
--- error_log
big.js.zst
declares a 134217728-byte decompression window
above the 8 MB limit browsers enforce for Content-Encoding: zstd
recompress with a window log <= 23



=== TEST 31b: a .zst with reserved frame descriptor bit 0x08 is declined
# RFC 8878 reserves Frame_Header_Descriptor bit 3.  The static probe is the
# browser-facing guard before we emit Content-Encoding: zstd, so it must not
# serve a frame that libzstd itself rejects.  The eval block keeps that
# decoder-backed oracle attached to the handcrafted fixture when zstd is
# available locally; hosts without the CLI still run the live fallback check.
--- config
    location /reserved/ {
        zstd_static on;
        root html;
    }
--- user_files eval
my $bad = pack("C*", 0x28, 0xB5, 0x2F, 0xFD, 0x08, 0x00, 0x00);
if (system("zstd", "--version") == 0) {
    require File::Temp;
    my ($fh, $path) = File::Temp::tempfile();
    binmode $fh;
    print $fh $bad;
    close $fh;
    open my $old_stderr, ">&", \*STDERR or die "dup STDERR: $!";
    open STDERR, ">", File::Spec->devnull() or die "redirect STDERR: $!";
    my $rc = system("zstd", "-q", "-t", $path);
    open STDERR, ">&", $old_stderr or die "restore STDERR: $!";
    unlink $path;
    die "decoder unexpectedly accepted reserved descriptor bit 0x08" if $rc == 0;
}
">>> reserved/bit.js\nreserved-bit origin body\n>>> reserved/bit.js.zst\n" . $bad
--- request
GET /reserved/bit.js
--- more_headers
Accept-Encoding: gzip, zstd
--- response_headers
! Content-Encoding
--- response_body
reserved-bit origin body
--- error_code: 200
--- error_log
frame header sets reserved Frame_Header_Descriptor bit 0x08
declining static variant



=== TEST 32: a single-segment .zst with >8MB content size is declined
# Single-segment frames carry no Window_Descriptor — the window IS the
# frame content size, read from behind the optional dictionary id.
# Descriptor 0xA0 = Single_Segment with a 4-byte content size; the
# little-endian field declares 20 MB, over the browser cap, so the
# handler must decline this layout too.
--- config
    location /bw/ {
        zstd_static on;
        root html;
    }
--- user_files eval
">>> bw/single.js\nbig-window single-segment body\n>>> bw/single.js.zst\n"
. pack("C*", 0x28, 0xB5, 0x2F, 0xFD, 0xA0, 0x00, 0x00, 0x40, 0x01,
       0x00, 0x00, 0x00)
--- request
GET /bw/single.js
--- more_headers
Accept-Encoding: gzip, zstd
--- response_headers
! Content-Encoding
--- response_body
big-window single-segment body
--- error_code: 200
--- error_log
single.js.zst
declares a 20971520-byte decompression window
above the 8 MB limit browsers enforce for Content-Encoding: zstd
recompress with a window log <= 23



=== TEST 33: the window check runs under directio too
# The probe historically skipped O_DIRECT files (unaligned preads fail
# EINVAL — see #75); it now uses an aligned read so validation still
# runs. The .zst is padded past the "directio 512" threshold so the
# open really is O_DIRECT, and the oversized declared window must be
# declined the same as TEST 31. Verified fail-first: on the
# directio-skip build this file is served as Content-Encoding: zstd and
# every assertion here fails. The "aligned probe" debug line is the
# positive witness that is_directio was really set for this request —
# without it the block would also pass vacuously through the stack-read
# path on filesystems where O_DIRECT does not take.
--- config
    location /bw/ {
        zstd_static on;
        directio 512;
        root html;
    }
--- user_files eval
">>> bw/dio.js\nbig-window directio body\n>>> bw/dio.js.zst\n"
. pack("C*", 0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x88)
. ("\0" x 1018)
--- request
GET /bw/dio.js
--- more_headers
Accept-Encoding: gzip, zstd
--- response_headers
! Content-Encoding
--- response_body
big-window directio body
--- error_code: 200
--- error_log
dio.js.zst
declares a 134217728-byte decompression window
aligned probe on directio file



=== TEST 34: the directio probe follows directio_alignment up to the cap
# Review: the probe geometry follows the operator's declared alignment
# between the 4 KB floor and the NGX_HTTP_ZSTD_STATIC_DIO_PROBE_MAX
# (64 KB) ceiling, so storage declaring a larger block size than the
# floor still gets an aligned read, and a failed validation read
# DECLINES rather than serving unvalidated. 16 KB is inside that band
# and so is honoured verbatim: the witness line must show a 16384-byte
# probe and the oversized window must still be declined. TEST 34b pins
# the other end of the band.
--- config
    location /bw/ {
        zstd_static on;
        directio 512;
        directio_alignment 16k;
        root html;
    }
--- user_files eval
">>> bw/dioal.js\nbig-window directio alignment body\n>>> bw/dioal.js.zst\n"
. pack("C*", 0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x88)
. ("\0" x 1018)
--- request
GET /bw/dioal.js
--- more_headers
Accept-Encoding: gzip, zstd
--- response_headers
! Content-Encoding
--- response_body
big-window directio alignment body
--- error_code: 200
--- error_log
dioal.js.zst
declares a 134217728-byte decompression window
16384-byte aligned probe on directio file



=== TEST 34b: the probe alignment is capped, and the cap applies to a client that does NOT accept zstd
# s1 regression, two properties in one block.
#
# (1) CAP. "directio_alignment" is ngx_conf_set_off_slot on an off_t
# with no upper bound in core (ngx_http_core_module.c), and core spends
# it on the copy filter's BODY buffer, where a large value is a
# throughput choice. O_DIRECT legality is a property of the device's
# logical block size, not of that directive, so an 18-byte frame-HEADER
# probe has nothing to gain from scaling with it. Uncapped, the probe
# did ngx_pmemalign(align * 2) plus a 2*align O_DIRECT read per
# request; at "directio_alignment 1m" that is a 2 MB allocation and a
# 2 MB read to inspect 18 bytes. The probe alignment is now clamped to
# NGX_HTTP_ZSTD_STATIC_DIO_PROBE_MAX, so the witness must say
# 65536-byte, NOT 1048576-byte.
#
# (2) NON-ACCEPTING CLIENT. TESTs 26/33/34/46 all send an accepting
# client, so nothing covered the directio probe on the path a client
# that does not accept zstd takes — which is precisely the path the
# amplification was reachable on, because #202 moved the
# "return NGX_DECLINED" for such a client to AFTER the probe (the probe
# result is required to decide whether Vary is truthful). This block
# sends "Accept-Encoding: gzip" and still asserts the probe ran, so the
# cap is pinned on the request shape that motivated it.
#
# Falsifiability, both directions:
#   - remove the clamp -> the witness line reads "1048576-byte aligned
#     probe", the 65536 pattern does not match, and this block goes red.
#   - restore the pre-#202 early return for a non-accepting client ->
#     no probe runs at all, so neither the witness line NOR the Vary
#     header appears, and this block goes red on both.
# The 1048576 negative assertion makes the first direction fail loudly
# rather than merely stop matching.
#
# Vary is asserted because it is the reason the probe is allowed to run
# for this client at all: the .zst is a valid, usable variant here (a
# small window, unlike TEST 34), so the identity response really is
# Accept-Encoding-dependent and must say so. The .zst is padded past
# the "directio 512" threshold so the open really is O_DIRECT.
--- config
    location /cap/ {
        zstd_static on;
        directio 512;
        directio_alignment 1m;
        root html;
    }
--- user_files eval
">>> cap/noaccept.js\ncapped probe identity body\n>>> cap/noaccept.js.zst\n"
. pack("C*", 0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00, 0x19, 0x00, 0x00)
. "hi\n"
. ("\0" x 2048)
--- request
GET /cap/noaccept.js
--- more_headers
Accept-Encoding: gzip
--- response_headers
! Content-Encoding
Vary: Accept-Encoding
--- response_body
capped probe identity body
--- error_code: 200
--- error_log
65536-byte aligned probe on directio file
--- no_error_log
1048576-byte aligned probe on directio file
[error]



=== TEST 35: concatenated frames are validated on the leading frame only
# Contract pin for the documented scope (review): a valid small first
# frame followed by an oversized second frame is SERVED — a regular
# frame's header does not declare its compressed length, so the probe
# cannot walk the sequence without decoding block chains. The README
# scopes the guarantee to the leading frame and points at
# `zstd -t --memory=8MB` as the complete pre-deploy check; this block
# exists so any future change to that scope is a deliberate one.
# First frame: 1 KB window, one raw last-block containing "hi\n".
# Second frame: the 128 MB-window header from TEST 31.
--- config
    location /bw/ {
        zstd_static on;
        root html;
    }
--- user_files eval
">>> bw/concat.js\nconcat origin body\n>>> bw/concat.js.zst\n"
. pack("C*", 0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00, 0x19, 0x00, 0x00)
. "hi\n"
. pack("C*", 0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x88, 0x00, 0x00, 0x00)
--- request
GET /bw/concat.js
--- more_headers
Accept-Encoding: gzip, zstd
--- response_headers
Content-Encoding: zstd
--- error_code: 200
--- no_error_log
decompression window



=== TEST 36: a served sidecar advertises Accept-Ranges: bytes
# gzip_static parity (see gzip_static's r->allow_ranges = 1): the
# representation is the .zst bytes and the validator is strong, so
# static-side ranges are coherent — resumable downloads included.
# Fails on builds without the opt-in: no allow_ranges, no header.
--- config
    location /test {
        zstd_static on;
        root ../suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: gzip, zstd
--- response_headers
Content-Encoding: zstd
Accept-Ranges: bytes
--- no_error_log
[error]



=== TEST 37: byte ranges slice the sidecar's bytes (206 + Content-Range)
# RFC 9110 §14.2: ranges address the SELECTED REPRESENTATION — under
# Content-Encoding: zstd that is the .zst bytes themselves, which a
# client can fetch, resume and concatenate before decompressing. The
# fixture is TEST 35's crafted 12-byte frame (magic + 1 KB window +
# raw "hi\n" block), so the slice is byte-pinned: the first four bytes
# are the frame magic. Unfixed code ignores Range and answers 200.
--- config
    location /rg/ {
        zstd_static on;
        root html;
    }
--- user_files eval
">>> rg/tiny.js\ntiny origin body\n>>> rg/tiny.js.zst\n"
. pack("C*", 0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00, 0x19, 0x00, 0x00)
. "hi\n"
--- request
GET /rg/tiny.js
--- more_headers
Accept-Encoding: zstd
Range: bytes=0-3
--- error_code: 206
--- response_headers
Content-Encoding: zstd
Content-Range: bytes 0-3/12
--- response_body eval
pack("C*", 0x28, 0xB5, 0x2F, 0xFD)
--- no_error_log
[error]



=== TEST 38: a 4-byte skippable-magic-only file is declined (truncated skip header)
# sec/g5-static-skippable-frame: ngx_http_zstd_static_probe_frame() must
# see the 4-byte Frame_Size field before it can trust a skippable frame
# at all. A file that is only the magic cannot supply it, so this must
# fail closed exactly like any other truncated header — decline, fall
# back to serving the uncompressed original.
--- config
    location /skip/ {
        zstd_static on;
        root html;
    }
--- user_files eval
">>> skip/magiconly.js\nmagic only origin\n>>> skip/magiconly.js.zst\n"
. pack("C*", 0x50, 0x2A, 0x4D, 0x18)
--- request
GET /skip/magiconly.js
--- more_headers
Accept-Encoding: zstd
--- response_headers
! Content-Encoding
--- response_body
magic only origin
--- error_code: 200
--- error_log
frame header truncated



=== TEST 39: a 7-byte skippable header (Frame_Size one byte short) is declined
--- config
    location /skip/ {
        zstd_static on;
        root html;
    }
--- user_files eval
">>> skip/seven.js\nseven byte origin\n>>> skip/seven.js.zst\n"
. pack("C*", 0x50, 0x2A, 0x4D, 0x18, 0x00, 0x00, 0x00)
--- request
GET /skip/seven.js
--- more_headers
Accept-Encoding: zstd
--- response_headers
! Content-Encoding
--- response_body
seven byte origin
--- error_code: 200
--- error_log
frame header truncated



=== TEST 40: an exact 8-byte skippable header with nothing after it is declined
# A zero-length-payload skippable header parses fine (Frame_Size = 0)
# and passes the bounds check (8 header bytes exactly fill of.size), so
# the walk advances to offset 8 and probes again — there is nothing
# left to read there, so the follow-up pread(2) returns 0 and the
# handler declines exactly as it does for any other pread short-read,
# rather than reading past EOF looking for a frame that isn't there.
--- config
    location /skip/ {
        zstd_static on;
        root html;
    }
--- user_files eval
">>> skip/eightonly.js\neight byte origin\n>>> skip/eightonly.js.zst\n"
. pack("C*", 0x50, 0x2A, 0x4D, 0x18, 0x00, 0x00, 0x00, 0x00)
--- request
GET /skip/eightonly.js
--- more_headers
Accept-Encoding: zstd
--- response_headers
! Content-Encoding
--- response_body
eight byte origin
--- error_code: 200
--- error_log
pread
--- no_error_log
reusing



=== TEST 41: a skippable Frame_Size that overflows 32-bit arithmetic is declined
# Frame_Size 0xFFFFFFFF (4294967295) must not be added to the 8-byte
# header offset with plain 32-bit/size_t arithmetic on a narrow
# platform — the handler does the bounds check in 64-bit so this fails
# closed instead of wrapping into a small, in-bounds offset.
--- config
    location /skip/ {
        zstd_static on;
        root html;
    }
--- user_files eval
">>> skip/overflow.js\noverflow origin\n>>> skip/overflow.js.zst\n"
. pack("C*", 0x50, 0x2A, 0x4D, 0x18, 0xFF, 0xFF, 0xFF, 0xFF)
--- request
GET /skip/overflow.js
--- more_headers
Accept-Encoding: zstd
--- response_headers
! Content-Encoding
--- response_body
overflow origin
--- error_code: 200
--- error_log
skippable frame declares a 4294967295-byte skip past end of file



=== TEST 42: a skippable Frame_Size declaring a skip past EOF is declined
# Frame_Size 1000 in an 8-byte file: 8 + 1000 is nowhere near
# overflowing, but it is far past of.size. This is the "declared skip
# length past EOF" case, distinct from TEST 41's overflow case.
--- config
    location /skip/ {
        zstd_static on;
        root html;
    }
--- user_files eval
">>> skip/pasteof.js\npast eof origin\n>>> skip/pasteof.js.zst\n"
. pack("C*", 0x50, 0x2A, 0x4D, 0x18, 0xE8, 0x03, 0x00, 0x00)
--- request
GET /skip/pasteof.js
--- more_headers
Accept-Encoding: zstd
--- response_headers
! Content-Encoding
--- response_body
past eof origin
--- error_code: 200
--- error_log
skippable frame declares a 1000-byte skip past end of file



=== TEST 43: a valid dcz-style skippable prefix followed by a good regular frame IS served
# The bypass fix must not break the legitimate shape it exists
# alongside: RFC 9842 dcz frames are exactly a skippable frame ahead of
# the real payload frame (see README "Standards-based dictionary
# compression"). One skippable frame (Frame_Size 4, four bytes of
# opaque payload) followed by a small-window regular frame must still
# be served normally.
--- config
    location /skip/ {
        zstd_static on;
        root html;
    }
--- user_files eval
">>> skip/prefix.js\nprefix origin body\n>>> skip/prefix.js.zst\n"
. pack("C*", 0x50, 0x2A, 0x4D, 0x18, 0x04, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00,
             0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00, 0x19, 0x00, 0x00)
. "hi\n"
--- request
GET /skip/prefix.js
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- error_code: 200
--- no_error_log
[error]



=== TEST 44: exactly four leading skippable frames followed by a regular frame are served
# NGX_HTTP_ZSTD_STATIC_MAX_SKIP_FRAMES permits four leading skippable
# frames.  The handler must still probe the following regular frame,
# rather than declining before it reads that frame.
--- config
    location /skip/ {
        zstd_static on;
        root html;
    }
--- user_files eval
">>> skip/four.js\nfour skips origin\n>>> skip/four.js.zst\n"
. (pack("C*", 0x50, 0x2A, 0x4D, 0x18, 0x00, 0x00, 0x00, 0x00) x 4)
. pack("C*", 0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00, 0x19, 0x00, 0x00)
. "hi\n"
--- request
GET /skip/four.js
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- error_code: 200
--- no_error_log
[error]



=== TEST 44b: a fifth leading skippable frame is declined
# The cap is enforced only after the fifth skippable frame is observed.
# This keeps the walk bounded while allowing the regular frame after four.
--- config
    location /skip/ {
        zstd_static on;
        root html;
    }
--- user_files eval
">>> skip/toolong.js\ntoo long origin\n>>> skip/toolong.js.zst\n"
. (pack("C*", 0x50, 0x2A, 0x4D, 0x18, 0x00, 0x00, 0x00, 0x00) x 5)
. pack("C*", 0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00, 0x19, 0x00, 0x00)
. "hi\n"
--- request
GET /skip/toolong.js
--- more_headers
Accept-Encoding: zstd
--- response_headers
! Content-Encoding
--- response_body
too long origin
--- error_code: 200
--- error_log
has at least 5 leading skippable frames



=== TEST 45: a skippable prefix hiding an oversized-window regular frame is REJECTED
# THE BYPASS THIS ITEM FIXES: before this change, ANY skippable magic
# made the probe return OK immediately, so prepending a trivial
# skippable frame to an oversized-window regular frame skipped the 8 MB
# window guard entirely — the whole point of the probe. The handler
# must now resolve the skip and check the frame that actually follows.
--- config
    location /skip/ {
        zstd_static on;
        root html;
    }
--- user_files eval
">>> skip/bypass.js\nbypass origin body\n>>> skip/bypass.js.zst\n"
. pack("C*", 0x50, 0x2A, 0x4D, 0x18, 0x04, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00,
             0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x88, 0x00, 0x00, 0x00)
. "payloadbytes"
--- request
GET /skip/bypass.js
--- more_headers
Accept-Encoding: zstd
--- response_headers
! Content-Encoding
--- response_body
bypass origin body
--- error_code: 200
--- error_log
declares a 134217728-byte decompression window
above the 8 MB limit browsers enforce for Content-Encoding: zstd



=== TEST 46: a dcz-style skippable prefix on a directio file IS served
# M1 regression. Under directio the probe buffer is aligned and the
# first read at offset 0 succeeds, but the skippable walk then moves
# `pos` to 40 (the canonical dcz SHA-256 prefix: 8-byte skippable
# header + 32-byte payload) and the NEXT read used that offset raw. An
# O_DIRECT descriptor rejects an unaligned file offset with EINVAL, so
# the read returned -1, the probe took the "aligned probe ... returned
# -1" branch and DECLINED — every request for a dcz-shaped .zst on a
# directio location silently lost its precompressed variant (a 404 with
# "zstd_static always" and no identity file). The fix rounds the read
# offset down to the alignment and parses the frame at its offset
# inside the block.
#
# Fail-first control (observed): reverting the alignment (reading at
# `pos` instead of `base`) turns this into "! Content-Encoding" plus
# the "returned -1" error line, so both the 200-with-zstd assertion and
# the --- no_error_log [error] assertion go red.
#
# The .zst is padded past the "directio 512" threshold so the open
# really is O_DIRECT; "aligned probe on directio file" is the positive
# witness that is_directio was set for this request, so the block
# cannot pass vacuously through the stack-read path on a filesystem
# where O_DIRECT does not take.
--- config
    location /skip/ {
        zstd_static on;
        directio 512;
        root html;
    }
--- user_files eval
">>> skip/dioprefix.js\ndirectio prefix origin\n>>> skip/dioprefix.js.zst\n"
. pack("C*", 0x50, 0x2A, 0x4D, 0x18, 0x20, 0x00, 0x00, 0x00)
. ("\0" x 32)
. pack("C*", 0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00, 0x19, 0x00, 0x00)
. "hi\n"
. ("\0" x 1024)
--- request
GET /skip/dioprefix.js
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- error_code: 200
--- no_error_log
[error]



=== TEST 47: dictionary bypass defaults off and the sidecar still wins
# This is the default-value negative control. A dictionary-carrying client
# explicitly accepts dcz, but without zstd_static_dict_bypass the static
# handler keeps its historical first claim on the response.
--- config
    location /test {
        zstd_static on;
        root ../suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: zstd, dcz
Available-Dictionary: :AA==:
--- response_headers
Content-Length: 3717
ETag: "5be17d33-e85"
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 48: dictionary bypass requires Available-Dictionary
# Explicit dcz alone must not forfeit a usable sidecar.
--- config
    location /test {
        zstd_static on;
        zstd_static_dict_bypass on;
        root ../suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: zstd, dcz
--- response_headers
Content-Length: 3717
ETag: "5be17d33-e85"
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 49: dictionary bypass does not treat wildcard as dcz
# RFC 9842 requires an explicit dcz token; '*' cannot prove the client can
# decode a dictionary response.
--- config
    location /test {
        zstd_static on;
        zstd_static_dict_bypass on;
        root ../suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: zstd, *
Available-Dictionary: :AA==:
--- response_headers
Content-Length: 3717
ETag: "5be17d33-e85"
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 50: dictionary bypass honors dcz q=0 across duplicate fields
# Repeated Accept-Encoding lines are one list. An explicit refusal on either
# line wins, so this stays on the sidecar path.
--- config
    location /test {
        zstd_static on;
        zstd_static_dict_bypass on;
        root ../suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: zstd, dcz
Accept-Encoding: dcz;q=0
Available-Dictionary: :AA==:
--- response_headers
Content-Length: 3717
ETag: "5be17d33-e85"
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 51: dictionary bypass also applies to zstd_static always
# The bypass is a preference for the filter path, so it must precede the
# always-mode shortcut. With no filter configured here, core serves identity;
# the complete Vary key keeps that fallback separate from the sidecar.
--- config
    location /test {
        zstd_static always;
        zstd_static_dict_bypass on;
        root ../suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: zstd, dcz
Available-Dictionary: :AA==:
--- response_headers
Content-Length: 59738
ETag: "5be17d33-e95a"
! Content-Encoding
Vary: Accept-Encoding, Available-Dictionary, Sec-Fetch-Site
--- no_error_log
[error]



=== TEST 52: dictionary bypass inherits into a location
--- config
    zstd_static on;
    zstd_static_dict_bypass on;

    location /test {
        root ../suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: zstd, dcz
Available-Dictionary: :AA==:
--- response_headers
Content-Length: 59738
ETag: "5be17d33-e95a"
! Content-Encoding
Vary: Accept-Encoding, Available-Dictionary, Sec-Fetch-Site
--- no_error_log
[error]



=== TEST 53: location off overrides inherited dictionary bypass
--- config
    zstd_static on;
    zstd_static_dict_bypass on;

    location /test {
        zstd_static_dict_bypass off;
        root ../suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: zstd, dcz
Available-Dictionary: :AA==:
--- response_headers
Content-Length: 3717
ETag: "5be17d33-e85"
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 54: HEAD dictionary bypass keeps the cache partition
# The response filter deliberately does not encode header-only responses, so
# the static handler must emit the complete Vary key before declining.
--- config
    location /test {
        zstd_static on;
        zstd_static_dict_bypass on;
        root ../suite;
    }
--- request
HEAD /test
--- more_headers
Accept-Encoding: zstd, dcz
Available-Dictionary: :AA==:
--- response_headers
Content-Length: 59738
ETag: "5be17d33-e95a"
! Content-Encoding
Vary: Accept-Encoding, Available-Dictionary, Sec-Fetch-Site
--- no_error_log
[error]



=== TEST 55: dictionary bypass preserves a subrequest sidecar
# auth_request drives /only/test as a real subrequest. The response filter
# refuses every subrequest, so the static handler must ignore dictionary
# bypass there. Only the .zst sidecar exists: removing the r == r->main guard
# makes the subrequest fall through to a 404 and the parent return 500.
--- config
    location = /main {
        auth_request /only/test;
        root html;
    }

    location = /only/test {
        internal;
        zstd_static always;
        zstd_static_dict_bypass on;
        root html;
    }
--- user_files eval
open my $fixture, '<:raw', 'ci/t/suite/test.zst'
    or die "open zstd fixture: $!";
local $/;
my $zst = <$fixture>;
close $fixture or die "close zstd fixture: $!";
[
    [ 'main' => "main response\n" ],
    [ 'only/test.zst' => $zst ],
]
--- request
GET /main
--- more_headers
Accept-Encoding: zstd, dcz
Available-Dictionary: :AA==:
--- response_body
main response
--- no_error_log
[error]



=== TEST 56: the directio skip-frame walk reuses the block it already read
# The canonical dcz shape (8-byte skippable header + 32-byte payload,
# next frame at offset 40) with an alignment of 4096 or more puts BOTH
# frames inside the very first aligned block. The walk still recomputed
# base = 0 on iteration 2 and re-issued an identical 2*align O_DIRECT
# pread for bytes already sitting in `hdr` — at "directio_alignment
# 16k" that is a 32 KB re-read per skipped frame, to look at 18 bytes
# it already had.
#
# TEST 46 pins that this shape is SERVED; it cannot see how many reads
# it took, because both the cached and uncached paths serve identical
# bytes. The "reusing ... block at offset 0" debug line is the witness
# that the second read was actually elided, so this block asserts the
# optimization engaged rather than merely that the response is right.
#
# Falsifiability: drop the cache guard (always pread) and the reuse
# line never appears, so this block goes red while TEST 46 stays green
# — which is precisely the regression TEST 46 cannot catch.
#
# The alignment witness is asserted too, so this cannot pass vacuously
# on a filesystem where O_DIRECT does not engage: with no directio the
# buffered path runs, neither line is logged, and both assertions fail.
--- config
    location /skip/ {
        zstd_static on;
        directio 512;
        directio_alignment 16k;
        root html;
    }
--- user_files eval
">>> skip/dioreuse.js\ndirectio reuse origin\n>>> skip/dioreuse.js.zst\n"
. pack("C*", 0x50, 0x2A, 0x4D, 0x18, 0x20, 0x00, 0x00, 0x00)
. ("\0" x 32)
. pack("C*", 0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00, 0x19, 0x00, 0x00)
. "hi\n"
. ("\0" x 1024)
--- request
GET /skip/dioreuse.js
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- error_code: 200
--- error_log
16384-byte aligned probe on directio file
reusing 32768-byte block at offset 0 for next frame
--- no_error_log
[error]



=== TEST 57: the ordinary probe retains a canonical dcz prefix
# The ordinary probe reads the canonical 40-byte skippable prefix and the
# following maximum 18-byte frame header together. The reuse log proves the
# second frame came from that request-local read-ahead instead of another
# offset read; TEST 45 separately pins malformed and truncated skip handling.
--- config
    location /skip/ {
        zstd_static on;
        root html;
    }
--- user_files eval
">>> skip/read_ahead.js\nordinary read ahead origin\n>>> skip/read_ahead.js.zst\n"
. pack("C*", 0x50, 0x2A, 0x4D, 0x18, 0x20, 0x00, 0x00, 0x00)
. ("\0" x 32)
. pack("C*", 0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00, 0x19, 0x00, 0x00)
. "hi\n"
--- request
GET /skip/read_ahead.js
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- error_code: 200
--- error_log
reusing 58-byte block at offset 0 for next frame
--- no_error_log
[error]



=== TEST 58: malformed sidecar verdict is memoized per path and mtime
# Three repeated requests hit the same malformed sidecar and fixed revision.
# The first path is probed; the later requests use its worker-local verdict.
# Matching only the stable message fragments makes
# grep_error_log_out an exact count assertion independent of the temp path.
#
# Falsifiability: removing the cache lookup yields three "not a zstd frame"
# matches and no cached-verdict matches.
--- config
    error_log logs/error.log debug;
    location /memoized.txt {
        zstd_static on;
        root html;
    }
--- user_files
>>> memoized.txt 202601010000.00
identity fallback
>>> memoized.txt.zst 202601010000.00
HELO malformed sidecar
--- request
GET /memoized.txt
--- more_headers
Accept-Encoding: zstd
--- response_body
identity fallback
--- grep_error_log eval
qr/(?:is not a zstd frame|cached malformed verdict)/
--- grep_error_log_out eval
["is not a zstd frame\n",
 "is not a zstd frame\ncached malformed verdict\n",
 "is not a zstd frame\ncached malformed verdict\n"
 . "cached malformed verdict\n"]
--- no_error_log
[alert]



=== TEST 59: dictionary bypass fails closed on duplicate Available-Dictionary
# Regression for TEST 48's row: should_bypass() must count every
# Available-Dictionary line, not stop at the first, and stand aside only
# when exactly one is present. Two lines is the ambiguous case the dynamic
# filter refuses outright (avail_dict_count > 1 in
# ngx_http_zstd_filter_module.c); the static routing predicate must not
# bypass to it here either, or the client forfeits a usable .zst sidecar
# for a filter that then declines and falls back to identity.
--- config
    location /test {
        zstd_static on;
        zstd_static_dict_bypass on;
        root ../suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: zstd, dcz
Available-Dictionary: :AA==:
Available-Dictionary: :AA==:
--- response_headers
Content-Length: 3717
ETag: "5be17d33-e85"
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 60: valid sidecar probe verdict is reused with open_file_cache
# repeat_each(3) sends the same sidecar through one worker three times. The
# first request probes; requests two and three must emit the debug witness.
# Removing the GOOD-cache lookup keeps the response correct but makes this
# exact-count oracle empty.
--- config
    error_log logs/error.log debug;
    open_file_cache max=10 inactive=60s;
    open_file_cache_valid 60s;
    location /test {
        zstd_static on;
        root ../suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- grep_error_log eval
qr/cached good frame verdict/
--- grep_error_log_out eval
["",
 "cached good frame verdict\n",
 "cached good frame verdict\ncached good frame verdict\n"]
--- no_error_log
[alert]



=== TEST 61: valid verdict is not retained when open_file_cache is off
# The standalone unit can pass good_valid=0 directly; this integration arm
# proves the handler derives that value from nginx's real off sentinel.  A
# positive verdict surviving here would outlive the fresh descriptor/stat
# contract that disabling open_file_cache requests.
--- config
    error_log logs/error.log debug;
    open_file_cache off;
    location /test {
        zstd_static on;
        root ../suite;
    }
--- request
GET /test
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- grep_error_log eval
qr/cached good frame verdict/
--- grep_error_log_out eval
["", "", ""]
--- no_error_log
[alert]
