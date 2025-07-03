use Test::Nginx::Socket;
use File::Basename;
use lib 'lib';

my $dirname = dirname(__FILE__);
$ENV{'TEST_NGINX_PERL_PATH'}="$ENV{'PWD'}/$dirname";

no_long_string();
log_level 'debug';
repeat_each(3);
plan tests => repeat_each() * (blocks() * 3) + 45;
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
