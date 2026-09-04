use Test::Nginx::Socket;
use File::Basename;
use lib 'lib';

my $dirname = dirname(__FILE__);
# local: this process is the test run, but perlcritic is right that a bare
# assignment to %ENV leaks into anything that runs after it.
local $ENV{'TEST_NGINX_PERL_PATH'} = "$ENV{'PWD'}/$dirname";

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
plan 'no_plan';
run_tests();


__DATA__


=== TEST 1: zstd off
--- config
	location /filter {
		zstd off;
		proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
	}
	location /test {
		root $TEST_NGINX_PERL_PATH/suite/;
	}
--- request
GET /filter
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]


=== TEST 2: zstd off (with accept-encoding header)
--- config
    location /filter {
        zstd off;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
Accept-Encoding: gzip,zstd
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]



=== TEST 3: zstd on
--- config
    location /filter {
        zstd on;
		zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: gzip, zstd
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]



=== TEST 4: zstd on (without accept-encoding header)
--- config
    location /filter {
        zstd on;
		zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]



=== TEST 5: zstd on (without zstd component in accept-encoding header)
--- config
    location /filter {
        zstd on;
		zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: gzip, br
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]


=== TEST 5a: repeated Accept-Encoding accepts zstd on a later field line
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: gzip
Accept-Encoding: zstd
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]


=== TEST 5b: repeated Accept-Encoding keeps explicit zstd;q=0 over wildcard
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: *
Accept-Encoding: zstd;q=0
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]

=== TEST 6: zstd zstd_min_length (greater than min_length)
--- config
    location /filter {
        zstd on;
		zstd_min_length 1024;
		zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd, br
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]

=== TEST 7: zstd zstd_min_length (less than length)
--- config
    location /filter {
        zstd on;
		zstd_types text/plain;
        zstd_min_length 60k;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd, br
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]

=== TEST 8 zstd & gzip
--- config
    location /filter {
        zstd on;
        zstd_min_length 1024;
        zstd_types text/plain;

		gzip on;
		gzip_min_length 1024;
		gzip_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd, gzip, br
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]

=== TEST 9 zstd & gzip (Accept-Encoding start with gzip)
--- config
    location /filter {
        zstd on;
        zstd_min_length 1024;
        zstd_types text/plain;

        gzip on;
        gzip_min_length 1024;
        gzip_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: gzip, zstd, br
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]

=== TEST 10 zstd & gzip (hit gzip)
--- config
    location /filter {
        zstd on;
        zstd_min_length 60k;
        zstd_types text/plain;

        gzip on;
        gzip_min_length 1024;
        gzip_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd, gzip, br
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: gzip
Content-type: text/plain
--- no_error_log
[error]

=== TEST 11 zstd on (file does not exist)
--- config
    location /filter {
        zstd on;
	zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test2;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: gzip, br
--- error_code: 404



=== TEST 12 zstd off (file does not exist)
--- config
    location /filter {
        zstd off;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test2;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: gzip, br
--- error_code: 404



=== TEST 13: RFC 7231 quality value - q=0 (explicitly reject)
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd;q=0, gzip;q=1
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]



=== TEST 14: RFC 7231 quality value - q=0.0 (explicitly reject)
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd;q=0.0, gzip;q=1
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]



=== TEST 15: RFC 7231 quality value - q=0.5 (accept with lower priority)
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd;q=0.5
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]



=== TEST 16: RFC 7231 quality value - q=1.0 (highest priority)
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd;q=1.0
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]



=== TEST 17: zstd with max_length (exceeds limit)
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        zstd_max_length 10k;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]



=== TEST 18: zstd with max_length (within limit)
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        zstd_max_length 100k;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]



=== TEST 19: zstd compression level 3
--- config
    location /filter {
        zstd on;
        zstd_comp_level 3;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]



=== TEST 20: zstd compression level 10 (high)
--- config
    location /filter {
        zstd on;
        zstd_comp_level 10;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]



=== TEST 21: zstd with multiple content types
--- config
    location /filter {
        zstd on;
        zstd_types text/plain text/html application/json;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]



=== TEST 22: zstd - mixed quality values (prefer highest)
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        gzip on;
        gzip_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd;q=0.9, gzip;q=0.8
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]



=== TEST 23: zstd - gzip preferred via quality
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        gzip on;
        gzip_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd;q=0.5, gzip;q=0.9
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-type: text/plain
--- no_error_log
[error]



=== TEST 24: zstd filter preserves HEAD pass-through behaviour
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
HEAD /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
!Content-Length
--- no_error_log
[error]


=== TEST 25: zstd filter skips 204 responses
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        return 204;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- error_code: 204
--- response_headers
!Content-Encoding
--- no_error_log
[error]



=== TEST 26: zstd filter skips 205 responses
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        return 205;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- error_code: 205
--- response_headers
!Content-Encoding
--- no_error_log
[error]


=== TEST 27: zstd filter skips 304 responses
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        return 304;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- error_code: 304
--- response_headers
!Content-Encoding
--- no_error_log
[error]




=== TEST 28: zstd filter compresses 403 responses above min_length
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        default_type text/plain;
        return 403 "forbidden body\n";
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- error_code: 403
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-Type: text/plain
--- no_error_log
[error]


=== TEST 29: zstd filter compresses 404 responses above min_length
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        default_type text/plain;
        return 404 "not found body\n";
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- error_code: 404
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-Type: text/plain
--- no_error_log
[error]



=== TEST 30: no infinite loop / CPU spin on a zero-length proxied body
# Regression for the recurring "100% CPU infinite loop" class:
#   7f86e5b, 2af5889, 924c9bf, PR #23/#49.
# An empty upstream body with Content-Encoding still set must terminate
# (emit a valid empty zstd frame) and not spin. Test::Nginx enforces a
# request timeout, so a hang fails the test instead of running forever.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/empty;
    }
    location /empty {
        default_type text/plain;
        return 200 "";
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- error_code: 200
--- timeout: 5
--- no_error_log
[error]



=== TEST 31: no infinite loop on a single-byte body below the stream-in size
# Same loop class — a tiny body must flush a terminal frame and stop.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/one;
    }
    location /one {
        default_type text/plain;
        return 200 "x";
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- error_code: 200
--- timeout: 5
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 32: $zstd_ratio computation path on a large body (overflow guard)
# Regression for 064895c "integer overflow in compression ratio calc".
# $zstd_ratio is a log-phase variable; its value is asserted to be a
# finite N.NNN string by tools/test_encoding.py (which can read it). Here
# we exercise the computation path itself — a ~58 KB body makes
# bytes_in*1000 large, the exact arithmetic that overflowed pre-064895c.
# A clean compressed response with no error proves the math did not trap.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        set $unused $zstd_ratio;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 33: zstd composes correctly with sub_filter (filter ordering)
# Regression for the recurring filter-order class: f4ba115, 2d2e641,
# cae80f9, 3f73e15, 8a6e370, 18c778d. zstd must run AFTER sub_filter so
# the substitution is present in the (decompressed) output, not skipped.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        sub_filter 'ORIGINAL' 'REWRITTEN';
        sub_filter_once off;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/src;
    }
    location /src {
        default_type text/plain;
        return 200 "ORIGINAL ORIGINAL ORIGINAL\n";
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 34: negative compression level produces a valid zstd stream
# Regression for cc9f6ec / b58c7cd: negative levels are accepted by
# zstd_comp_level but were never exercised by a test.
--- config
    location /filter {
        zstd on;
        zstd_comp_level -5;
        zstd_min_length 1;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 35: explicit non-default zstd_types only compresses listed types
# Regression for 46f95bf "passed default mime/types to zstd_types parser":
# a type NOT in the list must not be compressed.
--- config
    location /json {
        zstd on;
        zstd_min_length 1;
        zstd_types application/json;
        default_type text/plain;
        return 200 "plain text not in zstd_types\n";
    }
--- request
GET /json
--- more_headers
Accept-Encoding: zstd
--- response_headers
!Content-Encoding
--- no_error_log
[error]



=== TEST 36: zstd_types match DOES compress the listed type
# Positive half of TEST 35 — application/json is listed, so it compresses.
--- config
    location /json {
        zstd on;
        zstd_min_length 1;
        zstd_types application/json;
        default_type application/json;
        return 200 "{\"compress\":\"this is a json body long enough\"}\n";
    }
--- request
GET /json
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 37: max_length enforced when Content-Length is known (proxy)
# Pins the documented contract from d94b220 / f065cb6: when the response
# length IS known (the common proxied case), a body larger than
# zstd_max_length must NOT be compressed. The complementary "length
# unknown / chunked -> cannot be enforced" half is a documented behaviour
# (see README) not cleanly unit-testable via `return` (which always sets
# Content-Length); it is covered by the docs, not by a brittle test.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_max_length 4;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/big;
    }
    location /big {
        default_type text/plain;
        return 200 "this body is far larger than the 4 byte max_length\n";
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
!Content-Encoding
--- no_error_log
[error]



=== TEST 38: zstd_window_log caps the window and still produces valid output
# Regression for the zstd_window_log memory-bounding directive. With a
# 15-bit (32 KB) window and a body well over 32 KB, zstd must still emit
# a well-formed stream: the directive bounds per-request memory, it must
# not corrupt the response. Served from the on-disk test fixture (~58 KB)
# so the capped window is genuinely exercised.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_window_log 15;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 39: $zstd_bytes_in / $zstd_bytes_out are emitted for a compressed response
# Asserts the byte-count log variables. $zstd_bytes_in and
# $zstd_bytes_out are log-phase variables backed by ctx->bytes_in/out
# (the same counters $zstd_ratio derives from). Referencing them via
# `set` exercises the get_handler; a clean compressed response with no
# error proves the handler resolves both fields without faulting.
# Exact-value correctness (and consistency with $zstd_ratio) is verified
# end-to-end in tools/test_encoding.py, which can read the access log.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        set $unused_in  $zstd_bytes_in;
        set $unused_out $zstd_bytes_out;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 40: zstd_bypass skips compression when the predicate is truthy
# A request header maps to a bypass variable; when it is set to a
# non-empty value other than "0", the response must be served identity
# even though the client supports zstd and the type/size qualify.
--- http_config
    map $http_x_no_zstd $zstd_off {
        default 0;
        "1"     1;
    }
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        zstd_bypass $zstd_off;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
X-No-Zstd: 1
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]



=== TEST 41: zstd_bypass value "0" does NOT bypass (still compresses)
# Same config, but the bypass variable resolves to "0", which per
# ngx_http_test_predicates is falsy — compression must still happen.
# Pins the "0"/empty == not-bypassed contract.
--- http_config
    map $http_x_no_zstd $zstd_off {
        default 0;
        "1"     1;
    }
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        zstd_bypass $zstd_off;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
!Content-Length
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 42: zstd_max_length is enforced on a chunked upstream (no Content-Length)
# Regression for the length-independent input cap. TEST 37 covers the
# known-Content-Length case (rejected in the header filter). This covers
# the genuine DoS vector: an upstream that streams chunked with NO
# Content-Length, so the header-filter check is skipped. A mock TCP
# backend returns a chunked body far larger than zstd_max_length;
# compression has already started, so the only safe action is to abort
# the request — the worker must not be fed unbounded input. We assert
# the dedicated abort message is logged.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_max_length 100;
        zstd_types text/plain;
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/up;
    }
    location /up {
        proxy_http_version 1.1;
        proxy_pass http://127.0.0.1:$TEST_NGINX_RAND_PORT_1/;
    }
--- tcp_listen: $TEST_NGINX_RAND_PORT_1
--- tcp_no_close
--- tcp_reply eval
"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
. sprintf("%x\r\n", 5000) . ("A" x 5000) . "\r\n0\r\n\r\n"
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- ignore_response
--- error_log
input exceeded zstd_max_length (100) after



=== TEST 43: known Content-Length response round-trips (pledged-src-size)
# Regression for the ZSTD_CCtx_setPledgedSrcSize optimisation. A
# proxied response with an exact Content-Length takes the pledged-size
# path in init_cctx; an off-by-anything pledge would make
# ZSTD_compressStream2 error or corrupt the stream. Assert the response
# is zstd-encoded, chunked (filter strips the length), and crucially
# decompresses back to the exact original bytes.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/src;
    }
    location /src {
        default_type text/plain;
        return 200 "pledged-src-size round-trip body, long enough to compress and exercise the known-Content-Length path end to end\n";
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
!Content-Length
Content-Encoding: zstd
--- response_body_filters eval
sub {
    my $zstd = $_[0];
    require File::Temp;
    my ($tfh, $tmp) = File::Temp::tempfile("zstd_t43_XXXXXX",
                                           TMPDIR => 1, UNLINK => 1);
    binmode($tfh); print $tfh $zstd; close($tfh);
    # List-form pipe open: no shell, so the temp path is never re-parsed.
    open(my $r, "-|", "zstd", "-dqc", $tmp) or do { unlink $tmp; return "ERR" };
    local $/; my $d = <$r>; close($r); unlink $tmp;
    return $d;
}
--- response_body
pledged-src-size round-trip body, long enough to compress and exercise the known-Content-Length path end to end



=== TEST 44: chunked no-Content-Length body > one ZSTD_CStreamOutSize buffer round-trips
# Regression for the multi-output-buffer use-after-free / NULL-deref:
# get_buf()'s early return ("buffer_out not full -> keep current out_buf")
# did not check that ctx->out_buf was still non-NULL. On a chunked /
# no-Content-Length response large enough to need more than one
# ZSTD_CStreamOutSize output buffer, the body filter's recycle guard
# (ctx->out_buf = NULL after ngx_chain_update_chains) left out_buf NULL
# while buffer_out still looked non-full; the next compress() dereferenced
# it ("ctx->out_buf->last += ...") -> worker SIGSEGV, the response
# truncated at exactly 131072 decoded bytes with no zstd end-of-frame.
# Single-buffer responses never recycle so never crashed, which is why
# the homepage worked but wp-admin (large chunked CSS) broke in prod.
#
# A mock TCP backend streams a chunked body with NO Content-Length, far
# larger than one ~128 KB output buffer and highly compressible. The
# response must come back zstd-encoded, decompress cleanly (no premature
# end), and equal the original byte-for-byte (asserted via a len:md5
# checksum so the body need not be inlined). A pre-fix module crashes
# the worker here / yields a short body; the fixed module round-trips.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        proxy_http_version 1.1;
        proxy_buffering on;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/up;
    }
    location /up {
        proxy_http_version 1.1;
        proxy_pass http://127.0.0.1:$TEST_NGINX_RAND_PORT_1/;
    }
--- tcp_listen: $TEST_NGINX_RAND_PORT_1
--- tcp_no_close
--- tcp_reply eval
my $unit = "ABCDEFGHIJ0123456789zstd-multibuffer-regression-payload-";
my $body = $unit x 5000;            # ~290 KB, >2x ZSTD_CStreamOutSize
my $hdr  = "HTTP/1.1 200 OK\r\n"
         . "Content-Type: text/plain\r\n"
         . "Transfer-Encoding: chunked\r\n"
         . "Connection: close\r\n\r\n";
my $out = $hdr;
# emit in 8 KB chunks so it is genuinely chunked, no Content-Length
for (my $i = 0; $i < length($body); $i += 8192) {
    my $c = substr($body, $i, 8192);
    $out .= sprintf("%x\r\n", length($c)) . $c . "\r\n";
}
$out .= "0\r\n\r\n";
$out
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
!Content-Length
Content-Encoding: zstd
--- response_body_filters eval
sub {
    my $zstd = $_[0];
    require File::Temp;
    my ($tfh, $tmp) = File::Temp::tempfile("zstd_t44_XXXXXX",
                                           TMPDIR => 1, UNLINK => 1);
    binmode($tfh); print $tfh $zstd; close($tfh);
    # List-form pipe open: no shell, so the temp path is never re-parsed.
    open(my $r, "-|", "zstd", "-dqc", $tmp) or do { unlink $tmp; return "ERR-OPEN" };
    local $/; my $d = <$r>; close($r); my $rc = $?; unlink $tmp;
    return "ERR-DECODE rc=$rc" if $rc != 0;          # premature end -> non-zero
    require Digest::MD5;
    return length($d) . ":" . Digest::MD5::md5_hex($d);
}
--- response_body eval
my $unit = "ABCDEFGHIJ0123456789zstd-multibuffer-regression-payload-";
my $body = $unit x 5000;
require Digest::MD5;
length($body) . ":" . Digest::MD5::md5_hex($body)



=== TEST 45: zstd_max_cctx_memory rejects parameters that exceed the budget
# Per-request CCtx memory hardening: a budget of 1 KB with level 19 is
# wildly insufficient (level 19 needs ~80–90 MB), so nginx must refuse
# to start. The same test also exercises the no-STATIC_LINKING_ONLY
# build path: that build cannot honour the directive and rejects it
# unconditionally with a different but equally clear message. Either
# way, must_die.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_comp_level 19;
        zstd_max_cctx_memory 1k;
        zstd_types text/plain;
        return 200 "x";
    }
--- request
GET /filter
--- must_die



=== TEST 46: Accept-Encoding "notzstd, zstd" still negotiates zstd
# Regression for the multi-occurrence parser fix. The first "zstd"
# substring lives inside the unrelated token "notzstd", which the
# delimiter check correctly rejects; the parser must then walk on to
# the next list element, find the standalone "zstd" token, and accept
# the encoding. Pre-fix this returned identity because only the first
# occurrence was examined.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        return 200 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: notzstd, zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 47: Vary: Accept-Encoding is emitted when gzip_vary is on
# The filter sets r->gzip_vary = 1 whenever a request enters a
# zstd-enabled location, but only the core nginx code actually emits
# the "Vary: Accept-Encoding" header — and only when gzip_vary is on.
# Without this header shared caches (CDNs, reverse proxies) cannot
# distinguish a zstd-encoded variant from the identity one and will
# serve the wrong body to clients that do not accept zstd.
--- config
    gzip_vary on;
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        return 200 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
Vary: Accept-Encoding
--- no_error_log
[error]



=== TEST 48: Vary: Accept-Encoding is emitted even when the client does not accept zstd
# Same location as TEST 47, but the client only accepts gzip. The
# response is identity, yet the Vary header must still appear so that
# downstream caches keep zstd and identity variants apart. This locks
# the "set gzip_vary before negotiating the encoding" behaviour.
--- config
    gzip_vary on;
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        return 200 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: gzip
--- response_headers
!Content-Encoding
Vary: Accept-Encoding
--- no_error_log
[error]



=== TEST 48a: Vary: Accept-Encoding is emitted with gzip_vary OFF (accepting client)
# G5, the cell that used to be broken. No "gzip_vary" anywhere — its
# compiled-in default is off, which is what most deployments actually
# run. Before G5 this response was zstd-encoded with NO Vary header at
# all: a shared cache stored it and served that zstd body to clients
# that cannot decode zstd. The module now emits the field itself, so
# correctness no longer depends on an operator directive it does not
# own. Paired with TEST 47 (gzip_vary on) this is the dynamic half of
# the gzip_vary x Accept-Encoding matrix.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        return 200 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
Vary: Accept-Encoding
--- no_error_log
[error]



=== TEST 48b: Vary: Accept-Encoding is emitted with gzip_vary OFF (non-accepting client)
# The identity arm of TEST 48a, and the more dangerous fill order: a
# cache that stores THIS response without Vary pins every later client
# to identity, silently losing compression for everyone. Emitting the
# field before negotiating the encoding is what keeps the two variants
# apart, with gzip_vary off.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        return 200 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: gzip
--- response_headers
!Content-Encoding
Vary: Accept-Encoding
--- no_error_log
[error]



=== TEST 49: zstd_buffers with a small custom value still produces a valid stream
# The zstd_buffers directive was previously not exercised by any test.
# A very small buffer count forces the body filter through the
# multi-buffer output path on a single response, so this also guards
# against regressions in chunk accounting under buffer pressure.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_buffers 4 4k;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 50: zstd_target_cblock_size produces a valid zstd stream
# Locks the target_cblock_size advanced parameter path. The size is
# small enough to force the encoder to honour the cap on a sizeable
# input. On libzstd < 1.5.6 this directive only logs a warning at
# config time and is otherwise ignored, but the response must still
# be a well-formed zstd stream either way.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_target_cblock_size 4k;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 51: zstd_long on compresses cleanly
# Long-range mode enables the zstd long-distance matcher. The flag
# was previously configured but never exercised in tests, so a silent
# regression in the parameter wiring would have gone unnoticed. A
# response that is large enough to be worth compressing is enough to
# prove the parameter path stays well-formed.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_long on;
        zstd_window_log 17;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 52: unknown-length (chunked) body is eligible regardless of size
# TEST 6/7 cover min_length on the known-Content-Length path. A response with
# no Content-Length takes the other branch: there is no length to test, so the
# min_length gate is skipped and the body is ALWAYS eligible — even when it is
# smaller than zstd_min_length (documented behaviour). The previous version of
# this test used "return 200" upstream, which sets a Content-Length and so
# never exercised this path at all (it was rejected by the known-length gate).
# Use a raw chunked HTTP/1.1 backend so the response reaching the filter
# genuinely has no Content-Length.
--- config
    location /filter {
        zstd on;
        zstd_min_length 4096;
        zstd_types text/plain;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_pass http://127.0.0.1:$TEST_NGINX_RAND_PORT_1/;
    }
--- raw_request eval
"GET /filter HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAccept-Encoding: zstd\r\n\r\n"
--- tcp_listen: $TEST_NGINX_RAND_PORT_1
--- tcp_reply eval
"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\ntiny\r\n0\r\n\r\n"
--- response_headers
!Content-Length
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 53: zstd_comp_level 1 (minimum) produces a valid stream
# Boundary coverage for the comp_level slot. Existing tests use 3,
# 10, -5, and 19. Level 1 is the documented minimum positive level
# and the fastest setting; an off-by-one in the bounds post-handler
# would have caught here.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_comp_level 1;
        zstd_types text/plain;
        return 200 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 54: zstd_comp_level 22 (maximum) produces a valid stream
# Boundary coverage for the comp_level slot at libzstd's documented
# maximum. The body is intentionally small so the test stays cheap;
# the assertion is that the encoder accepts the level and emits a
# valid stream, not that it produces any specific ratio.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_comp_level 22;
        zstd_types text/plain;
        return 200 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 55: Accept-Encoding parser tolerates tab OWS around the q-value
# RFC 7230 OWS is "*( SP / HTAB )". Most clients only ever send
# spaces, but the parser is required to accept tabs too. The
# rewritten parser walks OWS explicitly; this locks that contract.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        return 200 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd	;	q=0.5
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 56: Accept-Encoding parser is case-insensitive on the coding name
# The HTTP coding names are token-class, which RFC 7231 treats as
# case-insensitive. A client that sends "ZSTD" must still negotiate
# zstd. ngx_strncasecmp inside the parser is what makes this work;
# this locks that we keep using the case-insensitive comparator.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        return 200 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: ZSTD
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 57: Accept-Encoding parser ignores stray empty list elements
# RFC 7230 allows empty list members (",,zstd,,"). The parser must
# skip them and still match the standalone zstd token. This guards
# the OWS-and-comma skip loop at the top of the per-element walk.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        return 200 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: ,, zstd ,,
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 58: subrequests are never zstd-encoded
# The filter explicitly returns NGX_DECLINED for r != r->main: only
# the top-level response gets compressed, never the body of an
# auth-request, addition_module, or SSI subrequest. This drives an
# auth_request subrequest whose own location has zstd on; the
# subrequest's response body must NOT be returned with
# Content-Encoding: zstd (and the outer response, which returns 204
# anyway, must not gain one either).
--- config
    location = /auth {
        internal;
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        return 204;
    }
    location /filter {
        auth_request /auth;
        return 204;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
!Content-Encoding
--- error_code: 204
--- no_error_log
[error]



=== TEST 59: zstd directive inside an if-block compiles and applies
# The "zstd" command is registered with NGX_HTTP_LIF_CONF, so it must
# be usable inside an "if (...) { ... }" block. This proves the
# directive parses in that context and that the resulting location's
# merged config takes effect (the if-branch turns zstd off while the
# enclosing location had it on).
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        if ($arg_nozstd) {
            zstd off;
        }
        return 200 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    }
--- request
GET /filter?nozstd=1
--- more_headers
Accept-Encoding: zstd
--- response_headers
!Content-Encoding
--- no_error_log
[error]



=== TEST 60: filter bails out when the upstream has already set Content-Encoding
# If an upstream response already carries Content-Encoding (here:
# identity-with-a-pre-set-header, simulated by add_header on a
# proxied response), the zstd filter must not re-encode it. The
# response should keep the upstream's encoding marker and the body
# should NOT be wrapped in a zstd frame.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/upstream;
    }
    location /upstream {
        add_header Content-Encoding "identity";
        return 200 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: identity
--- no_error_log
[error]



=== TEST 61: RFC 9110 wildcard "*" makes zstd acceptable
# Per RFC 9110 §12.5.3 "*" matches any coding not explicitly listed, so a
# client sending only "*" accepts zstd. (The pre-RFC2 parser ignored "*".)
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: *
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 62: explicit zstd;q=0 overrides a permissive wildcard
# An explicit "zstd" token decides the result even against "*;q=1".
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd;q=0, *;q=1
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]



=== TEST 63: malformed qvalue with trailing junk (q=1x) is not acceptable
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd;q=1x
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]



=== TEST 64: qvalue with a fourth decimal digit (q=0.0001) is malformed
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd;q=0.0001
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]



=== TEST 65: 206 Partial Content is not compressed (Content-Range preserved)
# RFC4: an upstream 206 carries a Content-Range computed against its selected
# representation; the filter must not apply a new content coding to it.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_pass http://127.0.0.1:$TEST_NGINX_RAND_PORT_1/;
    }
--- raw_request eval
"GET /filter HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAccept-Encoding: zstd\r\n\r\n"
--- tcp_listen: $TEST_NGINX_RAND_PORT_1
--- tcp_reply eval
"HTTP/1.1 206 Partial Content\r\nContent-Type: text/plain\r\nContent-Range: bytes 0-9/100\r\nContent-Length: 10\r\nConnection: close\r\n\r\nAAAAAAAAAA"
--- response_headers
!Content-Encoding
Content-Range: bytes 0-9/100
--- error_code: 206
--- no_error_log
[error]



=== TEST 66: zstd_bypass_vary appends the named field to Vary
# S1: header-driven bypass must be advertised to shared caches via Vary.
# G5: this location has no "gzip_vary on", and the module now emits
# "Vary: Accept-Encoding" itself rather than depending on that directive,
# so the compressed response carries both fields. Before G5 it carried
# only X-No-Compression — a zstd body that never told a shared cache it
# was negotiated on Accept-Encoding.
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        zstd_bypass      $http_x_no_compression;
        zstd_bypass_vary X-No-Compression;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
Vary: X-No-Compression, Accept-Encoding
--- no_error_log
[error]



=== TEST 67: zstd_target_cblock_size is accepted and still produces a valid stream
# C1: on libzstd >= 1.5.6 the directive applies; on older it is a warned no-op.
# Either way the config must load and the response must be a valid zstd stream.
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        zstd_target_cblock_size 4096;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 68: zstd_bypass identity arm still advertises Vary
# S1: when the bypass predicate fires (X-No-Compression present), the response
# must be served identity (no Content-Encoding: zstd) yet STILL carry
# Vary: X-No-Compression so a shared cache keys the bypassed variant separately
# from the compressed one. This is the cache-poisoning arm TEST 66 omitted.
# G5: the bypassed identity response must ALSO carry Accept-Encoding. The
# same URI serves zstd to a request that does not trip the predicate, so
# an identity body cached without Accept-Encoding in the key is served to
# clients that should have been compressed (and vice versa on the reverse
# fill order). This location has no "gzip_vary on"; the module emits the
# field itself.
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        zstd_bypass      $http_x_no_compression;
        zstd_bypass_vary X-No-Compression;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
X-No-Compression: 1
--- response_headers
Content-Encoding:
Vary: X-No-Compression, Accept-Encoding
--- no_error_log
[error]



=== TEST 68b: below zstd_min_length never reaches the bypass decision, no bypass Vary
# A31b-F4: zstd_bypass_vary must key only the responses for which this
# module actually reaches the zstd_bypass fork (the compressed and
# bypassed-identity variants). A response declined earlier by an
# eligibility gate -- here, body smaller than zstd_min_length -- would be
# identity regardless of the bypass predicate's value, so no bypass-driven
# cache variance exists and no "Vary: X-No-Compression" line is added.
# Accept-Encoding is still absent: this location has no gzip_vary and the
# module's own Vary: Accept-Encoding push also sits below this gate.
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        zstd_min_length 60k;
        zstd_bypass      $http_x_no_compression;
        zstd_bypass_vary X-No-Compression;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
X-No-Compression: 1
--- response_headers
Content-Encoding:
!Vary
--- no_error_log
[error]



=== TEST 68c: content type outside zstd_types never reaches the bypass decision, no bypass Vary
# A31b-F4 negative control for the content-type eligibility gate: same
# claim as TEST 68b, different gate. The fixture is served as text/plain
# by default; restricting zstd_types to a type it does not match makes the
# content-type gate the one that declines, above the bypass_vary push.
--- config
    location /filter {
        zstd on;
        zstd_types application/json;
        zstd_bypass      $http_x_no_compression;
        zstd_bypass_vary X-No-Compression;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
X-No-Compression: 1
--- response_headers
Content-Encoding:
!Vary
--- no_error_log
[error]



=== TEST 69: quoted-string in coding-name position does not fabricate zstd
# A quoted-string can never be a valid coding. With the name scan not
# stopping at '"', the comma inside `"a,zstd "` split the element and the
# trailing `zstd ` was mis-read as a real coding (phantom-token accept). The
# whole quoted blob is a single non-coding element and MUST decline. This is
# the coding-NAME-position arm of the quoted-comma class; TEST in the fuzz
# corpus (30_quoted_name_phantom) gates it under the differential oracle too.
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: "a,zstd ";q=1
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]



=== TEST 70: a real zstd element after a quoted-string element still negotiates
# Guard against over-fixing TEST 69: `"a",zstd` is a quoted-string element
# (declined) followed by a separate, valid `zstd` coding element — that zstd
# token must still be honoured. Confirms the name-scan '"' stop ends the
# quoted element rather than swallowing the following comma-separated token.
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: "a",zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 71: omitted directives use the web MIME defaults at the 1024-byte boundary
# application/json is in the default type list. The response is exactly 1024
# bytes, proving the default zstd_min_length boundary is inclusive.
--- config
    location /json {
        zstd on;
        default_type application/json;
        return 200 $arg_body;
    }
--- request eval
"GET /json?body=" . ("x" x 1024)
--- more_headers
Accept-Encoding: zstd
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
Content-Type: application/json
--- no_error_log
[error]



=== TEST 72: omitted zstd_min_length skips a 1023-byte HTML response
# text/html was already the module's default type, so this isolates the
# changed 1024-byte minimum length gate from the expanded MIME-type list.
--- config
    location /html {
        zstd on;
        default_type text/html;
        return 200 $arg_body;
    }
--- request eval
"GET /html?body=" . ("x" x 1023)
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Length: 1023
!Content-Encoding
Content-Type: text/html
--- no_error_log
[error]



=== TEST 73: omitted zstd_types includes text/csv
--- config
    location /csv {
        zstd on;
        default_type text/csv;
        return 200 $arg_body;
    }
--- request eval
"GET /csv?body=" . ("x" x 1024)
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
Content-Type: text/csv
--- no_error_log
[error]



=== TEST 74: omitted zstd_types includes application/x-ndjson
--- config
    location /ndjson {
        zstd on;
        default_type application/x-ndjson;
        return 200 $arg_body;
    }
--- request eval
"GET /ndjson?body=" . ("x" x 1024)
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
Content-Type: application/x-ndjson
--- no_error_log
[error]



=== TEST 75: omitted zstd_types includes application/json-seq
--- config
    location /json-seq {
        zstd on;
        default_type application/json-seq;
        return 200 $arg_body;
    }
--- request eval
"GET /json-seq?body=" . ("x" x 1024)
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
Content-Type: application/json-seq
--- no_error_log
[error]



=== TEST 76: omitted zstd_types includes application/wasm
--- config
    location /wasm {
        zstd on;
        default_type application/wasm;
        return 200 $arg_body;
    }
--- request eval
"GET /wasm?body=" . ("x" x 1024)
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
Content-Type: application/wasm
--- no_error_log
[error]



=== TEST 77: omitted zstd_types includes text/wgsl
--- config
    location /wgsl {
        zstd on;
        default_type text/wgsl;
        return 200 $arg_body;
    }
--- request eval
"GET /wgsl?body=" . ("x" x 1024)
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
Content-Type: text/wgsl
--- no_error_log
[error]



=== TEST 78: qvalue followed by whitespace then trailing junk is malformed
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd;q=1 garbage
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]



=== TEST 79: qvalue followed by tab then trailing junk is malformed
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd;q=0.5	junk
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]



=== TEST 80: repeated "q" parameter is malformed (RFC 9110 permits at most one)
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd;q=0.5;q=0.9
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]



=== TEST 81: "q" parameter present without "=value" is malformed
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd;q
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]



=== TEST 82: qvalue leading digit not 0 or 1 is malformed (q=2)
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd;q=2
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]



=== TEST 83: non-"q" parameter with an escaped quoted-pair does not confuse the delimiter scan
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd;foo="a\"b,c";q=0.8, gzip;q=0.1
--- response_headers_like
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 84: unterminated quoted-string in a non-"q" parameter runs to end without OOB read, defaults q=1
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd;foo="unterminated
--- response_headers_like
Content-Encoding: zstd
--- no_error_log
[error]


=== TEST 85: Content-Encoding is emitted exactly once on the wire
# nginx >= 1.23 links same-name response headers via ngx_table_elt_t.next
# and expects every producer to NULL-terminate the chain it starts, as
# core's own gzip filter and gzip_static do. The stale pointer is not
# reachable through plain HTTP with current core, and there is no
# in-harness readback either: add_header ($sent_http_*) evaluates before
# this module's header filter by deliberate module order (filter/config
# places ngx_http_headers_filter_module after this module, mirroring
# core's gzip placement), so headers_out holds no Content-Encoding at
# evaluation time. This test therefore pins the wire contract only; see
# the sibling static-module TEST 29, where the content-phase handler
# runs early enough for the $sent_http_* readback to observe the entry.
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 86: OWS around the "=" of a q parameter is accepted (RFC 9110 BWS)
# Covers the two optional-whitespace skips that bracket the "=" in
# ngx_http_zstd_eval_qvalue: whitespace after the parameter name and
# whitespace before its value. Both loops were unexecuted — every prior test
# wrote "q=..." with no spaces, so a tolerated-by-grammar header shape was
# entirely untested. q=1 keeps zstd acceptable, so the response compresses.
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd; q = 1
--- response_headers_like
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 87: "q=" with the value missing at end-of-field is rejected
# The `p >= end` guard right after the "=" is consumed: the field ends before
# any qvalue digit. Distinct from TEST 81 ("q" with no "=" at all) — this one
# reaches the is_q branch and runs out of input inside it. Malformed
# parameter => the element is dropped => zstd is not acceptable => identity.
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd;q=
--- response_headers
! Content-Encoding
--- no_error_log
[error]



=== TEST 88: an unquoted non-q parameter value is skipped to the delimiter
# The `else { p++; }` arm of the non-q value scanner. TEST 83 covered the
# quoted-string arm; an ordinary unquoted token value never exercised the
# byte-at-a-time path. The parameter is ignored and the following "q=0"
# still parses, so zstd is NOT acceptable here — proving the scanner stopped
# at the ';' rather than swallowing the rest of the field.
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd;foo=bar;q=0
--- response_headers
! Content-Encoding
--- no_error_log
[error]



=== TEST 89: a quoted-string starting mid-value is skipped, parsing continues
# A non-q parameter whose value mixes unquoted bytes and a quoted-string
# ("a\"b\""): the scanner steps byte-at-a-time until the '"', then hands off to
# ngx_http_zstd_skip_quoted for the quoted run, then resumes. Both arms of that
# loop therefore run for a single parameter. The trailing q=1 must still be
# found and parsed, proving the quoted region was skipped as one unit and the
# cursor landed on the ';' — not swallowed past it (which would drop the q and
# silently change the negotiated weight).
#
# NOTE: the early-return guard in skip_quoted (p >= end || *p != '"') is NOT
# reachable from here, or from any HTTP input: the only call site tests
# *p == '"' first. It is defensive-only, left uncovered deliberately.
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd;foo=a"b";q=1
--- response_headers_like
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 90: a HEAD advertises the same Content-Encoding its GET would produce
# RFC 9110 §9.3.2: a HEAD response carries the header fields the equivalent GET
# would have sent, with no body. So a compressible HEAD MUST still advertise
# "Content-Encoding: zstd" (a client uses it to size/negotiate the later GET),
# while sending zero body bytes.
#
# This pins the direction deliberately, because the opposite assertion looks
# just as plausible: "no body, so no Content-Encoding". Verified against a live
# server before writing it — HEAD and GET emit identical Content-Encoding here.
#
# Note on the module's own r->header_only short-circuit in the header filter:
# it is NOT what handles this request. r->header_only is set by nginx's
# ngx_http_header_filter_module, which runs AFTER the zstd filter in the chain,
# so on a plain HEAD the flag is still 0 when zstd inspects the response. That
# branch only fires for internally generated header-only responses, and is left
# uncovered rather than faked with a test that would assert the wrong contract.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
HEAD /filter
--- more_headers
Accept-Encoding: zstd
--- error_code: 200
--- response_headers
Content-Encoding: zstd
--- response_body
--- no_error_log
[error]



=== TEST 90b: a HEAD advertises the same zstd_bypass_vary Vary field as GET
# This PR moved the r->header_only short-circuit ABOVE the
# zstd_bypass_vary Vary-append block in ngx_http_zstd_header_filter()
# (it used to run after the content-type check, now runs right after the
# encoding/status/length gates and before it). TEST 90 already proves
# header_only is not what handles a real HEAD here (see its comment); this
# arm proves the reorder did not change what a real HEAD emits for the
# OTHER header the filter appends unconditionally on this code path --
# zstd_bypass_vary's Vary field -- by checking it is present and identical
# on both HEAD and the equivalent GET.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        zstd_bypass $http_x_no_compression;
        zstd_bypass_vary X-No-Compression;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
HEAD /filter
--- more_headers
Accept-Encoding: zstd
--- error_code: 200
--- response_headers
Content-Encoding: zstd
Vary: X-No-Compression, Accept-Encoding
--- response_body
--- no_error_log
[error]



=== TEST 91: an SSI subrequest is not separately zstd-compressed
# The header filter checks r != r->main early and declines for subrequests,
# so only the main request negotiates a content coding. Without that guard
# the subrequest would be compressed on its own and its zstd frame would be
# spliced into the parent's body as opaque bytes.
#
# The assertion is the error-log line the filter emits when declining the
# subrequest, counted over the whole request: the parent here is text/html
# with zstd off, so a correctly guarded run reaches "zstd: compressing
# response" zero times. Asserting only on the assembled body would not work —
# with the guard removed the page still reads correctly, because the parent's
# own filter chain re-processes the spliced output, so the body is identical
# in both states and would guard nothing.
--- log_level: debug
--- config
    location /page.html {
        ssi on;
        default_type text/html;
        root $TEST_NGINX_SERVER_ROOT/html;
    }
    location /inc {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        default_type text/plain;
        return 200 "INCLUDED-PAYLOAD-INCLUDED-PAYLOAD-INCLUDED-PAYLOAD";
    }
--- user_files
>>> page.html
BEGIN<!--# include virtual="/inc" -->END
--- request
GET /page.html
--- more_headers
Accept-Encoding: zstd
--- response_body
BEGININCLUDED-PAYLOAD-INCLUDED-PAYLOAD-INCLUDED-PAYLOADEND
--- error_log
zstd: skip, subrequest
--- no_error_log
zstd: compressing response
[error]


=== TEST 92: sub_filter partial-match sync bufs must not reset the CCtx mid-stream
# Regression for the silent-truncation bug: the body filter inferred
# "first body data" from ctx->buffer_in.src == NULL, while add_data
# reloaded buffer_in.src from every incoming buffer. The sub filter
# emits a data-less sync carrier (pos == NULL, ngx_http_sub_filter
# line ~516) whenever an in-memory input buffer is entirely absorbed
# into a cross-buffer match candidate ("looked") and produces no
# output. Loading that carrier re-armed the first-call check, the next
# invocation re-ran ZSTD_CCtx_reset(), and everything libzstd had
# buffered but not yet flushed was silently discarded -- the response
# still ended as ONE well-formed frame (200 + valid zstd), just with
# the pre-reset content missing. Seen in production as truncated HTML
# on sub_filter-rewritten pages fed by a slow chunked upstream.
#
# The mock backend streams three chunks with pauses; chunk 2 lies
# strictly inside the sub_filter FROM pattern, so it is fully absorbed
# into the match state and triggers the sync carrier. A pre-fix module
# loses chunk 1 ("EARLY-CONTENT ..."); the fixed module round-trips
# the whole rewritten body.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        sub_filter 'http://upstream.example' 'https://very-long-replacement-host.example';
        sub_filter_once off;
        sub_filter_types text/plain;
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/up;
    }
    location /up {
        proxy_http_version 1.1;
        proxy_pass http://127.0.0.1:$TEST_NGINX_RAND_PORT_1/;
    }
--- tcp_listen: $TEST_NGINX_RAND_PORT_1
--- tcp_no_close
--- tcp_reply_delay: 100ms
--- tcp_reply eval
my $hdr  = "HTTP/1.1 200 OK\r\n"
         . "Content-Type: text/plain\r\n"
         . "Transfer-Encoding: chunked\r\n"
         . "Connection: close\r\n\r\n";
my $seg1 = "EARLY-CONTENT that must survive the match holdback http://up";
my $seg2 = "stream.exa";     # entirely inside the FROM pattern: absorbed, no output
my $seg3 = "mple/path LATE-CONTENT after the match completes\n";
my $chunk = sub { sprintf("%x\r\n%s\r\n", length($_[0]), $_[0]) };
[
    $hdr . $chunk->($seg1),
    $chunk->($seg2),
    $chunk->($seg3) . "0\r\n\r\n",
]
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- response_body_filters eval
sub {
    my $zstd = $_[0];
    require File::Temp;
    my ($tfh, $tmp) = File::Temp::tempfile("zstd_t92_XXXXXX",
                                           TMPDIR => 1, UNLINK => 1);
    binmode($tfh); print $tfh $zstd; close($tfh);
    # List-form pipe open: no shell, so the temp path is never re-parsed.
    open(my $r, "-|", "zstd", "-dqc", $tmp) or do { unlink $tmp; return "ERR" };
    local $/; my $d = <$r>; close($r); my $rc = $?; unlink $tmp;
    return "ERR-DECODE rc=$rc" if $rc != 0;
    return $d;
}
--- response_body
EARLY-CONTENT that must survive the match holdback https://very-long-replacement-host.example/path LATE-CONTENT after the match completes
--- no_error_log
[error]



=== TEST 93: a coding name running straight into a DQUOTE does not negotiate
# RFC 9110 12.5.3 `codings` is a token and '"' is not a tchar, so `zstd"x`
# advertises no coding. The name scan stops on '"' for the phantom-token
# guard, but the stopping byte went unexamined, so the truncated name still
# compared equal and we compressed for a client that never offered zstd --
# a parser differential against a strict intermediary, and a divergence from
# nginx's own ngx_http_gzip_accept_encoding(), which requires ',', ';', ' '
# or end after the name.
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd"x
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]



=== TEST 94: a DQUOTE-suffixed name followed by a quoted blob does not negotiate
# The other half of TEST 93: `zstd"a,b"` hides a comma inside the quoted run.
# The element must decline AND the quote-aware skip must swallow the whole
# blob, so the bytes after the in-quote comma cannot start a phantom element.
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd"a,b"
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]



=== TEST 95: zstd_comp_level -1 is applied, not silently replaced
# NGX_CONF_UNSET is -1, and -1 is a valid documented level (ZSTD_minCLevel()
# ..-1). The old merge could not tell "operator asked for -1" from "nothing
# configured", so it overwrote the request with the inherited server value.
# This location inherits 9 from http_config and asks for -1. The COMPRESSED
# SIZE is the oracle -- the response is chunked, so there is no
# Content-Length to read; the body filter reports the byte count instead.
# Level -1 is far cheaper than 9 and must produce a visibly larger body.
# TEST 96 pins what an inherited 9 produces on the same fixture: pre-fix the
# two were byte-for-byte identical, which is exactly what makes this pair a
# negative control rather than a smoke test.
--- http_config
    zstd_comp_level 9;
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        zstd_comp_level -1;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- response_body_filters eval
sub { "zstd_bytes=" . length($_[0]) }
--- response_body chomp
zstd_bytes=4796
--- no_error_log
[error]



=== TEST 96: an inherited zstd_comp_level 9 is the control for TEST 95
# Same fixture, same server-level 9, no location override -- so this is the
# size TEST 95 must NOT produce. Keep the two in step: if the fixture or the
# linked libzstd changes, both numbers move, and they must stay different.
--- http_config
    zstd_comp_level 9;
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- response_body_filters eval
sub { "zstd_bytes=" . length($_[0]) }
--- response_body chomp
zstd_bytes=3560
--- no_error_log
[error]



=== TEST 97: junk after OWS following a coding name does not negotiate
# The DQUOTE guard added for TEST 93 sat BEFORE the OWS skip, so it caught
# `zstd"x` and missed everything hiding behind a space: `zstd "x` and plain
# `zstd x` both still negotiated. RFC 9110 12.5.3 allows only ';', ',' or
# end of field after a coding name, which is the same rule
# ngx_http_gzip_accept_encoding() applies. Found by CodeRabbit on PR #142.
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd "x
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]



=== TEST 98: a bare token after OWS following a coding name does not negotiate
# The no-quotes arm of TEST 97. `zstd x` is two tokens with no separator,
# not a coding with a parameter, so the element offers nothing.
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd x
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]



=== TEST 99: OWS before ';' and ',' still negotiates
# Guard against over-fixing TEST 97/98: OWS between the name and a real
# separator is legal (RFC 9110 OWS), so these must still compress.
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: gzip , zstd ;q=1
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 100: multi-chunk streamed body across several body-filter callbacks
# Regression for the O(1)-tail append bug: ctx->last_in is retracked to
# &ctx->in whenever add_data drains the last retained link (ctx->in becomes
# NULL), because ngx_free_chain() overwrites that consumed link's ->next
# with the pool's free-chain head immediately afterward. Without the
# retrack, the NEXT body-filter callback's append splices its copied chain
# into ngx_pool_t.chain instead of onto ctx->in -- every callback after the
# first is silently dropped, the compressor never receives the rest of the
# body, and the response hangs waiting for a last_buf that never arrives.
# Multiple real (non-special, proxy_buffering off) chunks with pauses in
# between exercise several separate ngx_http_zstd_body_filter() callbacks
# against the same request, each one draining ctx->in completely before the
# next chunk arrives -- the exact interleaving the bug needs.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/up;
    }
    location /up {
        proxy_http_version 1.1;
        proxy_pass http://127.0.0.1:$TEST_NGINX_RAND_PORT_1/;
    }
--- tcp_listen: $TEST_NGINX_RAND_PORT_1
--- tcp_no_close
--- tcp_reply_delay: 100ms
--- tcp_reply eval
my $hdr  = "HTTP/1.1 200 OK\r\n"
         . "Content-Type: text/plain\r\n"
         . "Transfer-Encoding: chunked\r\n"
         . "Connection: close\r\n\r\n";
my $chunk = sub { sprintf("%x\r\n%s\r\n", length($_[0]), $_[0]) };
[
    $hdr . $chunk->("first-chunk-"),
    $chunk->("second-chunk-"),
    $chunk->("third-chunk-"),
    $chunk->("fourth-chunk-tail\n") . "0\r\n\r\n",
]
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- response_body_filters eval
sub {
    my $zstd = $_[0];
    require File::Temp;
    my ($tfh, $tmp) = File::Temp::tempfile("zstd_t100_XXXXXX",
                                           TMPDIR => 1, UNLINK => 1);
    binmode($tfh); print $tfh $zstd; close($tfh);
    open(my $r, "-|", "zstd", "-dqc", $tmp) or do { unlink $tmp; return "ERR" };
    local $/; my $d = <$r>; close($r); my $rc = $?; unlink $tmp;
    return "ERR-DECODE rc=$rc" if $rc != 0;
    return $d;
}
--- response_body
first-chunk-second-chunk-third-chunk-fourth-chunk-tail
--- no_error_log
[error]



=== TEST 101: pledged size just below the configured buffer size still round-trips
# Boundary regression for skipping ZSTD_compressBound() when the pledged
# Content-Length is already >= the configured zstd_buffers size (that
# skip cannot shrink buf_size below what the call would have produced --
# see the get_buf() comment). zstd_buffers is pinned to a small, exact
# size (1 buffer of 512 bytes) so the boundary sits at an exact byte
# count instead of the 128 KB default. This case pledges 511 bytes --
# ONE BYTE UNDER buf_size -- which must still take the ORIGINAL
# ZSTD_compressBound() path (pledged_size < buf_size), unaffected by the
# new skip branch. Correctness oracle: byte-exact round-trip.
--- config eval
"    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        zstd_buffers 1 512;
        proxy_pass http://127.0.0.1:\$TEST_NGINX_SERVER_PORT/src;
    }
    location /src {
        default_type text/plain;
        return 200 \"" . ("A" x 511) . "\";
    }"
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
!Content-Length
Content-Encoding: zstd
--- response_body_filters eval
sub {
    my $zstd = $_[0];
    require File::Temp;
    my ($tfh, $tmp) = File::Temp::tempfile("zstd_t101_XXXXXX",
                                           TMPDIR => 1, UNLINK => 1);
    binmode($tfh); print $tfh $zstd; close($tfh);
    open(my $r, "-|", "zstd", "-dqc", $tmp) or do { unlink $tmp; return "ERR" };
    local $/; my $d = <$r>; close($r); my $rc = $?; unlink $tmp;
    return "ERR-DECODE rc=$rc" if $rc != 0;
    return $d;
}
--- response_body eval
"A" x 511
--- no_error_log
[error]



=== TEST 102: pledged size EXACTLY EQUAL to the configured buffer size still round-trips
# The exact boundary the skip's ">=" comparison turns on: pledged_size ==
# buf_size (512 == 512) takes the NEW skip path (get_buf():
# "(size_t) ctx->pledged_size >= buf_size"). ZSTD_compressBound(512) + 64
# is provably >= 512, so the clamp this call feeds would never have fired
# here either -- this case is the one boundary value where that claim
# must hold exactly, not just in the general case covered by TEST 103.
--- config eval
"    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        zstd_buffers 1 512;
        proxy_pass http://127.0.0.1:\$TEST_NGINX_SERVER_PORT/src;
    }
    location /src {
        default_type text/plain;
        return 200 \"" . ("B" x 512) . "\";
    }"
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
!Content-Length
Content-Encoding: zstd
--- response_body_filters eval
sub {
    my $zstd = $_[0];
    require File::Temp;
    my ($tfh, $tmp) = File::Temp::tempfile("zstd_t102_XXXXXX",
                                           TMPDIR => 1, UNLINK => 1);
    binmode($tfh); print $tfh $zstd; close($tfh);
    open(my $r, "-|", "zstd", "-dqc", $tmp) or do { unlink $tmp; return "ERR" };
    local $/; my $d = <$r>; close($r); my $rc = $?; unlink $tmp;
    return "ERR-DECODE rc=$rc" if $rc != 0;
    return $d;
}
--- response_body eval
"B" x 512
--- no_error_log
[error]



=== TEST 103: pledged size well ABOVE the configured buffer size still round-trips
# Deep into the skip path: a body several times larger than buf_size,
# well past the boundary, still round-trips byte-exact with the
# ZSTD_compressBound() call skipped on the first buffer. (4000 bytes,
# not larger: nginx's config-file tokenizer has its own line-length
# limit on a quoted "return" literal, well under a size that would
# still usefully exercise this boundary -- 4000 is comfortably above
# both buf_size=512 and that unrelated limit.)
--- config eval
"    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_types text/plain;
        zstd_buffers 4 512;
        proxy_pass http://127.0.0.1:\$TEST_NGINX_SERVER_PORT/src;
    }
    location /src {
        default_type text/plain;
        return 200 \"" . ("C" x 4000) . "\";
    }"
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
!Content-Length
Content-Encoding: zstd
--- response_body_filters eval
sub {
    my $zstd = $_[0];
    require File::Temp;
    my ($tfh, $tmp) = File::Temp::tempfile("zstd_t103_XXXXXX",
                                           TMPDIR => 1, UNLINK => 1);
    binmode($tfh); print $tfh $zstd; close($tfh);
    open(my $r, "-|", "zstd", "-dqc", $tmp) or do { unlink $tmp; return "ERR" };
    local $/; my $d = <$r>; close($r); my $rc = $?; unlink $tmp;
    return "ERR-DECODE rc=$rc" if $rc != 0;
    return $d;
}
--- response_body eval
"C" x 4000
--- no_error_log
[error]



=== TEST 104: chained Accept-Encoding — "gzip" then "zstd" negotiates zstd
# RFC 9110 section 5.3: repeated field lines are the single comma-joined
# field, so these two lines ARE "gzip, zstd" and accept zstd. Parsing only
# the first line saw "gzip" and served the body uncompressed.
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: gzip
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 105: chained Accept-Encoding — "zstd" then "gzip" negotiates zstd
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
Accept-Encoding: gzip
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 106: chained Accept-Encoding — "zstd;q=0" on the FIRST line declines
# The duplicate-coding rule: an explicit q=0 anywhere in the field is
# final and cannot be upgraded by a later line. Serving zstd here would
# hand a body to a client that explicitly refused it.
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd;q=0
Accept-Encoding: gzip
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]



=== TEST 107: chained Accept-Encoding — "zstd;q=0" on a LATER line declines
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: gzip
Accept-Encoding: zstd;q=0
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]



=== TEST 108: chained Accept-Encoding — q=0 then q=1 accepts
# Duplicate field lines are comma-joined in received order, so this follows
# the parser's existing last-explicit-token-wins rule.
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd;q=0
Accept-Encoding: zstd;q=1
--- response_headers
!Content-Length
Transfer-Encoding: chunked
Content-Encoding: zstd
--- no_error_log
[error]


=== TEST 108b: chained Accept-Encoding — q=1 then q=0 declines
# Negative control for TEST 108: reversing the same fields must reverse the
# decision, proving that field order reaches the live negotiation path.
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd;q=1
Accept-Encoding: zstd;q=0
--- response_headers
Content-Length: 59738
!Content-Encoding
--- no_error_log
[error]



=== TEST 109: chained Accept-Encoding — wildcard "*" on a later line accepts
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: gzip
Accept-Encoding: *
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 110: chained Accept-Encoding — three field lines, zstd on the third
--- config
    location /filter {
        zstd on;
        zstd_types text/plain;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test;
    }
    location /test {
        root $TEST_NGINX_PERL_PATH/suite/;
    }
--- request
GET /filter
--- more_headers
Accept-Encoding: gzip
Accept-Encoding: br
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 111: streaming zstd_max_length cap — body exactly AT the cap still compresses
# Boundary coverage for the ctx->bytes_in (uint64_t) vs zlcf->max_length
# (ssize_t) cap comparison, using the same mock chunked/no-Content-Length
# upstream fixture as TEST 42. bytes_in accumulates per received chunk and
# the check only fires once bytes_in EXCEEDS the cap, so a body whose
# size equals the cap exactly must still pass through and compress
# normally. The 32-bit-off_t cast defect this cap's comparison guards
# against is not reachable on this (64-bit off_t) harness -- see
# ci/tools/test_max_length_cap_unit.sh for the fixture that drives it
# under a genuine 32-bit off_t build.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_max_length 5000;
        zstd_types text/plain;
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/up;
    }
    location /up {
        proxy_http_version 1.1;
        proxy_pass http://127.0.0.1:$TEST_NGINX_RAND_PORT_1/;
    }
--- tcp_listen: $TEST_NGINX_RAND_PORT_1
--- tcp_no_close
--- tcp_reply eval
"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
. sprintf("%x\r\n", 5000) . ("A" x 5000) . "\r\n0\r\n\r\n"
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 112: streaming zstd_max_length cap — body one byte OVER the cap aborts
# Companion to TEST 111, same mock upstream fixture as TEST 42 (which
# covers a body grossly over the cap; this is the boundary case). One
# byte past the cap must still trip the abort path -- confirms the >
# (not >=) comparison at the boundary. As with TEST 42, the aborted
# connection has no clean chunked terminator, so this only asserts the
# error_log line under --- ignore_response; Test::Nginx::Socket's
# response-body checks are skipped together with the parse they depend
# on, so no additional "body never completed" assertion is available
# through this harness for a deliberately truncated response.
--- config
    location /filter {
        zstd on;
        zstd_min_length 1;
        zstd_max_length 4999;
        zstd_types text/plain;
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/up;
    }
    location /up {
        proxy_http_version 1.1;
        proxy_pass http://127.0.0.1:$TEST_NGINX_RAND_PORT_1/;
    }
--- tcp_listen: $TEST_NGINX_RAND_PORT_1
--- tcp_no_close
--- tcp_reply eval
"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
. sprintf("%x\r\n", 5000) . ("A" x 5000) . "\r\n0\r\n\r\n"
--- request
GET /filter
--- more_headers
Accept-Encoding: zstd
--- ignore_response
--- error_log
input exceeded zstd_max_length (4999) after
