use Test::Nginx::Socket;
use File::Basename;
use File::Spec;
use Digest::SHA qw(sha256);
use MIME::Base64 qw(encode_base64);
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

    if (@dynamic_modules) {
        my $main_config = join "\n", map { "load_module $_;" } @dynamic_modules;
        $block->set_value("main_config", $main_config);
    }

    # RFC 9842 section 8 restricts dcz to secure contexts, and this
    # harness speaks plain HTTP -- Test::Nginx::Socket has no TLS
    # listener. Every block below therefore runs behind the explicit
    # "TLS is terminated upstream" acknowledgement, which is exactly the
    # deployment those tests model. Blocks named "secure-context:" are
    # the tests OF that gate and are left alone so they see the
    # compiled-in default (off) or set the flag themselves.
    return if $block->name =~ /secure-context:/;

    my $http_config = $block->http_config;
    $http_config = '' if !defined $http_config;
    $block->set_value("http_config",
                      "$http_config\nzstd_dcz_assume_secure_transport on;\n");
});

# The negotiation key is the SHA-256 of the committed dictionary fixture,
# computed here rather than hardcoded so a fixture edit cannot silently
# desynchronize the suite ("passing" against a stale hash).
my $dict_raw = do {
    local $/;
    open my $fh, '<', "$dirname/suite/dcz-dict" or die "dcz-dict: $!";
    binmode $fh;
    my $c = <$fh>;
    close $fh or die "dcz-dict: $!";
    $c;
};
our $dict_b64 = encode_base64(sha256($dict_raw), "");
our $bad_b64  = encode_base64("\x01" x 32, "");

# For the optional supplied-hash directive argument: the fixture's true
# hash as hex, and a deliberately different well-formed hash. The
# supplied literal is VERIFIED against the loaded bytes by default, so
# the wrong one must abort config load (TESTs 17-18) rather than become
# the negotiation key. Under trust_hashes it is used verbatim (TEST 40).
# $zstd_dcz_dicts_hashed counts every loaded dictionary by default
# (TESTs 21-23), but excludes trusted literals (TESTs 41-42).
our $dict_hex = unpack("H*", sha256($dict_raw));
our $dict_hex_upper = uc($dict_hex);
our $odd_hex  = "01" x 32;
our $odd_b64  = encode_base64("\x01" x 32, "");

# A dictionary above the 8 MB dcz window cap but under the 10 MB hard
# limit, generated rather than committed (nobody wants an 8 MB fixture
# in-tree). Exposed to config blocks via $TEST_NGINX_DCZ_BIGDICT.
my $big_path = File::Spec->catfile(File::Spec->tmpdir(),
                                   "zstd-dcz-bigdict-$$.bin");
{
    open my $bf, '>', $big_path or die "bigdict: $!";
    binmode $bf;
    print {$bf} 'A' x (8 * 1024 * 1024 + 17);
    close $bf;
}
local $ENV{'TEST_NGINX_DCZ_BIGDICT'} = $big_path;
END { unlink $big_path if $big_path; }

no_long_string();
log_level 'warn';
repeat_each(1);
plan 'no_plan';
run_tests();

__DATA__


=== TEST 1: dcz negotiated when hash matches and dcz is accepted
# The full happy path: Available-Dictionary carries the SHA-256 of a
# configured dictionary and Accept-Encoding lists dcz explicitly, so the
# response commits to Content-Encoding: dcz and declares the
# Available-Dictionary cache key. Wire-format/byte-exactness assertions
# live in tools/test_dcz.py; this suite pins the negotiation contract.
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: dcz
Vary: Accept-Encoding, Available-Dictionary, Sec-Fetch-Site
--- no_error_log
[error]



=== TEST 2: no Available-Dictionary falls back to zstd, Vary still set
# A dictionary-less client on the same location gets plain zstd — and the
# response STILL varies on Available-Dictionary: which encoding this
# location serves depends on that request header for every client, so a
# shared cache must key both variants on it.
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd, dcz
--- response_headers
Content-Encoding: zstd
Vary: Accept-Encoding, Available-Dictionary, Sec-Fetch-Site
--- no_error_log
[error]



=== TEST 3: unknown dictionary hash falls back to zstd
# A hash we do not hold must never negotiate dcz — the client would
# receive a frame referencing a dictionary it cannot pair with ours.
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::bad_b64:"
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 4: Available-Dictionary without dcz in Accept-Encoding
# Advertising a dictionary is not accepting the coding. Without an
# explicit dcz token the response must stay plain zstd.
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 5: dcz;q=0 is an explicit refusal
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd, dcz;q=0\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 6: the "*" wildcard does not enable dcz
# RFC 9110's "*" matches any coding not explicitly listed, but only a
# client that actually holds the dictionary can decode dcz — the module
# requires the explicit token, so a wildcard-only request stays zstd.
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd, *\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 7: Sec-Fetch-Site cross-site is refused, and still varies on it
# RFC 9842 §8: dictionaries are same-origin-partitioned; compressing a
# cross-site response against one leaks it. Falls back to plain zstd.
# The REFUSAL path must carry "Vary: ... Sec-Fetch-Site" too: it is the
# variant a shared cache would otherwise hand to a same-origin client
# (dcz silently suppressed), and its counterpart is the dcz body handed
# to a cross-site client, bypassing this gate entirely. Proven end to
# end against a real proxy_cache in
# ci/tools/test_dcz_cache_partition.py.
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::dict_b64:\nSec-Fetch-Site: cross-site"
--- response_headers
Content-Encoding: zstd
Vary: Accept-Encoding, Available-Dictionary, Sec-Fetch-Site
--- no_error_log
[error]



=== TEST 8: Sec-Fetch-Site same-origin is allowed
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::dict_b64:\nSec-Fetch-Site: same-origin"
--- response_headers
Content-Encoding: dcz
--- no_error_log
[error]



=== TEST 9: malformed Available-Dictionary (not a byte sequence)
# RFC 8941 byte sequences are colon-delimited; anything else is treated
# as "no usable dictionary", never an error.
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd, dcz
Available-Dictionary: not-a-structured-field
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 10: Available-Dictionary decoding to the wrong length
# ":aGk=:" is valid base64 ("hi") but not a SHA-256; must decline.
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd, dcz
Available-Dictionary: :aGk=:
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 11: a location's own dictionary list replaces the inherited one
# Standard nginx array-directive semantics: the child declares its own
# zstd_dcz_dict_file, so the server-level dictionary the client
# advertises is no longer in scope and negotiation falls back to zstd.
--- config
    zstd on;
    zstd_min_length 16;
    zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;

    location /inherited {
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }

    location /own {
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/test;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request eval
["GET /inherited", "GET /own"]
--- more_headers eval
[
    "Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::dict_b64:",
    "Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::dict_b64:",
]
--- response_headers eval
[
    "Content-Encoding: dcz",
    "Content-Encoding: zstd",
]
--- no_error_log
[error]



=== TEST 12: identity fallback still varies on Available-Dictionary
# PR #92 review: a client sending "Accept-Encoding: dcz" (no zstd) with
# a hash we do not hold gets identity — but the SAME client holding a
# dictionary we DO hold would get dcz, so the identity variant is not
# invariant in Available-Dictionary. Without the Vary a shared cache
# keeps serving the stored identity body after the client acquires the
# right dictionary (silent compression loss). Guards the hoisting of
# the Vary push above the acceptance gate.
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: dcz\nAvailable-Dictionary: :$::bad_b64:"
--- response_headers
!Content-Encoding
Vary: Accept-Encoding, Available-Dictionary, Sec-Fetch-Site
--- no_error_log
[error]



=== TEST 13: a dictionary above the 8 MB window cap warns at config load
# The frame stays well-formed (the RFC client guarantee is a floor of
# max(8 MB, 1.25 x dict)), but dictionary bytes beyond the window cannot
# be referenced — a silent ratio cliff the operator should hear about at
# load time, not discover in telemetry.
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_DCZ_BIGDICT;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- error_log
larger than the 8 MB dcz compression window
--- no_error_log
[error]



=== TEST 14: an empty dictionary file is a config-load error
--- config
    location /t {
        zstd on;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-empty;
        default_type text/plain;
        return 200 "unreachable\n";
    }
--- request
GET /t
--- must_die
--- error_log
is empty
--- no_error_log
[alert]



=== TEST 15: two dictionaries with the same hash are a config-load error
# The negotiation lookup would be ambiguous; for computed hashes that
# means identical content — almost certainly a copy that was meant to be
# a new version. Refuse to start rather than match the first silently.
--- config
    location /t {
        zstd on;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "unreachable\n";
    }
--- request
GET /t
--- must_die
--- error_log
has the same hash as
--- no_error_log
[alert]



=== TEST 16: supplied hash argument — correct value negotiates dcz
--- config eval
"    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file \$TEST_NGINX_PERL_PATH/suite/dcz-dict $::dict_hex;
        default_type text/plain;
        return 200 \"dcz negotiation body: shared-boilerplate compute render\n\";
    }"
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: dcz
Vary: Accept-Encoding, Available-Dictionary, Sec-Fetch-Site
--- no_error_log
[error]



=== TEST 17: a supplied hash that is not the file's aborts config load
# THE regression test for the trusted-literal bug: "new.dict with the
# old dict's hash" used to load happily and advertise a hash no client
# could decode against. The dictionary path EXISTS and its contents are
# fine — only the declared hash is wrong — so nothing but the
# verification can reject this config.
--- config eval
"    location /t {
        zstd on;
        zstd_dcz_dict_file \$TEST_NGINX_PERL_PATH/suite/dcz-dict $::odd_hex;
        default_type text/plain;
        return 200 \"unreachable\n\";
    }"
--- request
GET /t
--- must_die
--- error_log eval
qr/does not match the supplied hash "0101010101010101010101010101010101010101010101010101010101010101": the file's SHA-256 is "$::dict_hex"/
--- no_error_log
[alert]



=== TEST 18: the file's own true hash as the literal still loads and negotiates
# Positive control for TEST 17: verification accepts the matching pair,
# and the negotiation key is the file's real hash. Without this, TEST 17
# would also pass if the directive rejected EVERY supplied literal.
--- config eval
"    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file \$TEST_NGINX_PERL_PATH/suite/dcz-dict $::dict_hex;
        default_type text/plain;
        return 200 \"dcz negotiation body: shared-boilerplate compute render\n\";
    }"
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: dcz
--- no_error_log
[error]



=== TEST 50: an uppercase supplied hash loads and negotiates
# Pins the case-folding branch in ngx_http_zstd_hex_nibble().
--- config eval
"    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file \$TEST_NGINX_PERL_PATH/suite/dcz-dict $::dict_hex_upper;
        default_type text/plain;
        return 200 \"dcz negotiation body: shared-boilerplate compute render\n\";
    }"
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: dcz
--- no_error_log
[error]



=== TEST 19: supplied hash with the wrong length is a config-load error
# The dictionary path deliberately does NOT exist: the hash error must
# surface anyway, pinning that malformed literals are validated before
# ngx_open_file() rather than shadowed by the file error.
--- config
    location /t {
        zstd on;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/no-such-dict abc123;
        default_type text/plain;
        return 200 "unreachable\n";
    }
--- request
GET /t
--- must_die
--- error_log
invalid dcz dictionary hash
--- no_error_log
[alert]



=== TEST 20: supplied hash with non-hex characters is a config-load error
# Nonexistent path for the same reason as TEST 19.
--- config
    location /t {
        zstd on;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/no-such-dict zz23456789012345678901234567890123456789012345678901234567890123;
        default_type text/plain;
        return 200 "unreachable\n";
    }
--- request
GET /t
--- must_die
--- error_log
non-hex character
--- no_error_log
[alert]



=== TEST 21: a supplied hash does NOT skip the load-time hashing pass
# $zstd_dcz_dicts_hashed counts ngx_http_zstd_sha256() calls from the
# dictionary loader this config cycle. The literal is verified, not
# trusted, so the file must be hashed even when one is supplied: this
# is "1". Restoring the old "if (!have_hash)" skip makes it "0" and
# fails here — the counter is what distinguishes verifying the literal
# from substituting it, since both produce the same dict->hash on a
# MATCHING pair.
--- config eval
"    location /t {
        zstd on;
        zstd_dcz_dict_file \$TEST_NGINX_PERL_PATH/suite/dcz-dict $::dict_hex;
        default_type text/plain;
        return 200 \"hashed=\$zstd_dcz_dicts_hashed\n\";
    }"
--- request
GET /t
--- response_body
hashed=1
--- no_error_log
[error]



=== TEST 22: without a supplied hash the loader hashes the file once
# Positive control for TEST 21: the counter is not stuck at zero.
--- config
    location /t {
        zstd on;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "hashed=$zstd_dcz_dicts_hashed\n";
    }
--- request
GET /t
--- response_body
hashed=1
--- no_error_log
[error]



=== TEST 23: mixed supplied and computed entries count BOTH
# Every dictionary is hashed from its own bytes regardless of whether
# a literal was declared, so two dictionaries are two hashes.
--- config eval
"    location /t {
        zstd on;
        zstd_dcz_dict_file \$TEST_NGINX_PERL_PATH/suite/dcz-dict $::dict_hex;
        zstd_dcz_dict_file \$TEST_NGINX_PERL_PATH/suite/test;
        default_type text/plain;
        return 200 \"hashed=\$zstd_dcz_dicts_hashed\n\";
    }"
--- request
GET /t
--- response_body
hashed=2
--- no_error_log
[error]



=== TEST 24: duplicate Sec-Fetch-Site fails closed
# The §8.3 cross-origin gate must not be decided by whichever line sorts
# first. Sec-Fetch-Site is not in nginx's headers_in table, so duplicates
# are chained rather than rejected and reach the module; a proxy that
# merges a client-supplied duplicate, or a smuggling desync, could
# otherwise prepend an agreeable value and switch the gate off. A browser
# never sends two, so more than one falls back to plain zstd.
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::dict_b64:\nSec-Fetch-Site: same-origin\nSec-Fetch-Site: cross-site"
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 25: duplicate Sec-Fetch-Site fails closed regardless of order
# The cross-site line first: still plain zstd, so the result does not
# depend on which duplicate the lookup happens to reach.
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::dict_b64:\nSec-Fetch-Site: cross-site\nSec-Fetch-Site: same-origin"
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 26: duplicate Available-Dictionary fails closed
# Same reasoning: a single-valued structured field, not deduplicated by
# nginx. Two of them is not a browser, and picking the first would let a
# second dictionary hash be smuggled past the operator's expectation.
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::dict_b64:\nAvailable-Dictionary: :$::dict_b64:\nSec-Fetch-Site: same-origin"
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 27: secure-context: plain HTTP falls back to zstd with no directive
# RFC 9842 section 8: compression dictionary transport MUST only be used
# in a secure context. This block is exempt from the suite's
# assume-secure preprocessor, so it exercises the COMPILED-IN default
# (zstd_dcz_assume_secure_transport off) with no directive anywhere in
# the configuration -- a block that opted in explicitly would pass even
# if the default were wrong. Every other dcz gate here is satisfied: the
# only reason this is not dcz is the cleartext connection.
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::dict_b64:\nSec-Fetch-Site: same-origin"
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 28: secure-context: explicit off is the same fail-closed answer
# Pins the directive's off value rather than only its absence, so a
# future default flip cannot silently make TEST 27 vacuous.
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_assume_secure_transport off;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 29: secure-context: the acknowledgement re-enables dcz over cleartext
# The supported TLS-terminating-proxy deployment. Same request as TEST
# 27, one directive different, opposite outcome -- so the pair isolates
# the gate rather than some other difference.
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_assume_secure_transport on;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::dict_b64:\nSec-Fetch-Site: same-origin"
--- response_headers
Content-Encoding: dcz
Vary: Accept-Encoding, Available-Dictionary, Sec-Fetch-Site
--- no_error_log
[error]



=== TEST 30: secure-context: a client-supplied scheme header does not enable dcz
# X-Forwarded-Proto (and every sibling spelling) is settable by anyone
# who can reach a cleartext listener. If the module inferred "secure"
# from one, the gate would be a suggestion. Nothing here is trusted:
# all four requests stay plain zstd.
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request eval
["GET /t", "GET /t", "GET /t", "GET /t"]
--- more_headers eval
[
    "Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::dict_b64:\nX-Forwarded-Proto: https",
    "Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::dict_b64:\nForwarded: proto=https",
    "Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::dict_b64:\nX-Forwarded-Ssl: on",
    "Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::dict_b64:\nFront-End-Https: on",
]
--- response_headers eval
[
    "Content-Encoding: zstd",
    "Content-Encoding: zstd",
    "Content-Encoding: zstd",
    "Content-Encoding: zstd",
]
--- no_error_log
[error]



=== TEST 31: secure-context: the acknowledgement inherits into locations
# http/server/location context: set once at server level, every location
# under it is covered. Pins the merge, which a per-location-only test
# would leave unproven.
--- config
    zstd on;
    zstd_min_length 16;
    zstd_dcz_assume_secure_transport on;
    zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;

    location /child {
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /child
--- more_headers eval
"Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: dcz
--- no_error_log
[error]



=== TEST 32: secure-context: a location can opt back out of an inherited on
# The merge is a real inheritance, not a one-way latch: a location that
# is reachable directly over cleartext can turn the acknowledgement off
# again even when the server block set it.
--- config
    zstd on;
    zstd_min_length 16;
    zstd_dcz_assume_secure_transport on;
    zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;

    location /direct {
        zstd_dcz_assume_secure_transport off;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /direct
--- more_headers eval
"Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 33: $zstd_bytes_out / $zstd_ratio resolve without fault on a dcz response
# Regression for the dcz 40-byte prefix being double-counted:
# ngx_http_zstd_filter_get_buf() writes the prefix into out_buf and
# advances ->last past it, then the emit path in
# ngx_http_zstd_filter_compress() (`ctx->bytes_out += ngx_buf_size(b)`)
# already counts that whole buffer -- prefix included -- when it queues
# the buffer downstream. A second, separate `ctx->bytes_out +=
# NGX_HTTP_ZSTD_DCZ_HEADER_LEN` in get_buf() double-counted the prefix on
# every dcz response.
#
# Exact-value correctness (bytes_out equal to the real wire byte count,
# and the ratio derived from it) is the province of the byte-oracle in
# tools/test_dcz.py, which can read the response bytes and the access
# log; the compressed size otherwise depends on the linked libzstd
# version and is deliberately not pinned here (see TEST 1's own note on
# wire-format assertions). This test instead pins the same contract
# TEST 32/39 in 00-filter.t pin for the plain zstd path: referencing
# both log-phase variables via `set` on a dcz response must resolve
# without the get_handler faulting.
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        set $unused_bytes_out $zstd_bytes_out;
        set $unused_ratio     $zstd_ratio;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: dcz
--- no_error_log
[error]



=== TEST 34: chained Accept-Encoding — "zstd" then "dcz" negotiates dcz
# RFC 9110 section 5.3: repeated field lines are the single comma-joined
# field, so these lines ARE "zstd, dcz" and advertise dcz. The dcz gate
# used to read only the first line and fall back to plain zstd.
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd\nAccept-Encoding: dcz\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: dcz
--- no_error_log
[error]



=== TEST 35: chained Accept-Encoding — "dcz" then "zstd" negotiates dcz
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: dcz\nAccept-Encoding: zstd\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: dcz
--- no_error_log
[error]



=== TEST 36: chained Accept-Encoding — "dcz;q=0" on a later line falls back
# An explicit dcz refusal is the latest matching token, so this falls back
# to plain zstd.
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd\nAccept-Encoding: dcz;q=0\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 37: chained Accept-Encoding — "dcz;q=0" first, "dcz;q=1" later accepts
# Duplicate field lines are comma-joined in received order, so the latest
# explicit dcz token decides just as it does in a single field line.
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd, dcz;q=0\nAccept-Encoding: dcz;q=1\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: dcz
--- no_error_log
[error]


=== TEST 37b: chained Accept-Encoding — "dcz;q=1" first, "dcz;q=0" later falls back
# Negative control for TEST 37: reversing the same fields must reverse the
# dcz decision and leave the plain zstd fallback selected.
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd, dcz;q=1\nAccept-Encoding: dcz;q=0\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 38: chained Accept-Encoding — a "*" on a later line still does not turn dcz on
# The wildcard gate survives the chain walk: only a client that actually
# holds the dictionary can decode dcz, so "*" must never enable it no
# matter which field line carries it.
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd\nAccept-Encoding: *\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 39: chained Accept-Encoding — three field lines, dcz on the third
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: gzip\nAccept-Encoding: zstd\nAccept-Encoding: dcz\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: dcz
--- no_error_log
[error]

=== TEST 40: trust_hashes on — the declared literal IS the negotiation key
# The opt-out's contract, proven the only observable way: the literal
# deliberately does NOT match the file, and the client advertising the
# DECLARED value gets dcz. Under the default this exact config is TEST
# 17's must_die; under trust the operator's pipeline is the authority.
--- http_config
    zstd_dcz_dict_trust_hashes on;
--- config eval
"    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file \$TEST_NGINX_PERL_PATH/suite/dcz-dict $::odd_hex;
        default_type text/plain;
        return 200 \"dcz negotiation body: shared-boilerplate compute render\n\";
    }"
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::odd_b64:"
--- response_headers
Content-Encoding: dcz
--- no_error_log
[error]



=== TEST 41: trust_hashes on — the hashing pass is actually skipped
# The perf contract, witnessed by the same counter that pinned the
# verify pass in TEST 21: a trusted literal must contribute ZERO to
# $zstd_dcz_dicts_hashed. Substituting the literal after hashing
# anyway (trust as a no-op) produces the same negotiation key but
# reads "1" here.
--- http_config
    zstd_dcz_dict_trust_hashes on;
--- config eval
"    location /t {
        zstd on;
        zstd_dcz_dict_file \$TEST_NGINX_PERL_PATH/suite/dcz-dict $::dict_hex;
        default_type text/plain;
        return 200 \"hashed=\$zstd_dcz_dicts_hashed\n\";
    }"
--- request
GET /t
--- response_body
hashed=0
--- no_error_log
[error]



=== TEST 42: trust_hashes on — a line without a literal is still hashed
# Trust changes what a SUPPLIED literal means, nothing else: an
# unhashed line has nothing to trust, so it is computed as always and
# negotiates on the file's real hash.
--- http_config
    zstd_dcz_dict_trust_hashes on;
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "hashed=$zstd_dcz_dicts_hashed\n";
    }
--- request
GET /t
--- response_body
hashed=1
--- no_error_log
[error]



=== TEST 43: trust_hashes declared AFTER a literal line is a config error
# Same ordering trap and same remedy as zstd_dict_strict_path: the
# flag is read at parse time, so a literal above the "on" line was
# verified — correct bytes, but the full hashing pass the directive
# exists to skip was silently paid. Reject rather than be quietly
# position-dependent.
--- http_config eval
"    zstd_dcz_dict_file \$TEST_NGINX_PERL_PATH/suite/dcz-dict $::dict_hex;
    zstd_dcz_dict_trust_hashes on;"
--- config
    location /t { return 200 "x"; }
--- must_die
--- error_log
"zstd_dcz_dict_trust_hashes on" was declared AFTER
--- no_error_log
[alert]



=== TEST 44: trust_hashes on does not excuse a malformed literal
# Trust changes what a well-formed literal means, not what a malformed
# one does: syntax is validated before the file is opened under either
# policy.
--- http_config
    zstd_dcz_dict_trust_hashes on;
--- config
    location /t {
        zstd on;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict zz11;
        default_type text/plain;
        return 200 "unreachable\n";
    }
--- must_die
--- error_log
invalid dcz dictionary hash
--- no_error_log
[alert]



=== TEST 45: static sidecar keeps priority when dictionary bypass is absent
# Default-off compatibility control. Both dictionary negotiation inputs are
# present, but the existing sidecar remains the selected representation.
--- config
    location /test {
        zstd on;
        zstd_types *;
        zstd_min_length 1;
        zstd_static on;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        root $TEST_NGINX_PERL_PATH/suite;
    }
--- request
GET /test
--- more_headers eval
"Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Length: 3717
ETag: "5be17d33-e85"
Content-Encoding: zstd
Vary: Accept-Encoding
--- no_error_log
[error]



=== TEST 46: static dictionary bypass lets the filter negotiate dcz
# The weak origin ETag and missing sidecar Content-Length distinguish this
# response from TEST 45's precompressed representation, while the combined
# Vary proves the static handler declined before emitting its own header.
--- config
    location /test {
        zstd on;
        zstd_types *;
        zstd_min_length 1;
        zstd_static on;
        zstd_static_dict_bypass on;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        root $TEST_NGINX_PERL_PATH/suite;
    }
--- request
GET /test
--- more_headers eval
"Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
! Content-Length
ETag: W/"5be17d33-e95a"
Content-Encoding: dcz
Vary: Accept-Encoding, Available-Dictionary, Sec-Fetch-Site
--- no_error_log
[error]



=== TEST 47: no explicit dcz gate fires before the header-collect gate
# Pins the negotiation gate ORDER, not just the accept/reject outcome.
# This request fails BOTH the cheap "no explicit dcz in Accept-Encoding"
# predicate (Accept-Encoding carries no dcz coding at all) AND the more
# expensive duplicate-Available-Dictionary gate that used to run first
# (behind ngx_http_zstd_collect_dcz_headers()'s header-list walk). The
# gates are pure predicates that only return NULL, so the accept/reject
# answer (fall back to zstd) is identical either way -- but WHICH debug
# line is emitted depends on gate order, and that is what this test
# pins. If a future change reorders the cheap dcz-coding gate back below
# the collect call, this flips: the duplicate-Available-Dictionary line
# would reappear and the "no explicit dcz" line would vanish.
--- log_level: debug
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd\nAvailable-Dictionary: :$::dict_b64:\nAvailable-Dictionary: :$::dict_b64:\nSec-Fetch-Site: same-origin"
--- response_headers
Content-Encoding: zstd
--- error_log eval
qr/zstd dcz: skip, no explicit dcz in Accept-Encoding/
--- no_error_log eval
[
    qr/zstd dcz: skip, \d+ Available-Dictionary headers/,
    qr/\[error\]/,
]



=== TEST 48: vary_dcz folds an already-present token instead of duplicating it
# ngx_http_zstd_vary_dcz() detects both tokens in a single pass
# (ngx_http_zstd_vary_has_two_tokens()) rather than two independent
# ngx_http_zstd_vary_has_token() calls. Coverage for the fold: the
# upstream response already carries "Vary: Available-Dictionary" (only
# ONE of the two tokens), so vary_dcz must detect has_available_dictionary
# = 1 / has_sec_fetch_site = 0 from that single combined pass and push
# exactly "Sec-Fetch-Site" -- not the "both absent" 2-token line every
# other test in this file exercises, and not a duplicated
# Available-Dictionary. A fold that mixed up which flag belongs to which
# token, or that only checked one of the two in the single pass, flips
# this response's Vary line.
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/t-upstream;
    }
    location /t-upstream {
        add_header Vary "Available-Dictionary";
        default_type text/plain;
        return 200 "dcz negotiation body: shared-boilerplate compute render\n";
    }
--- request
GET /t
--- more_headers eval
"Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: dcz
Vary: Available-Dictionary, Accept-Encoding, Sec-Fetch-Site
--- no_error_log
[error]



=== TEST 49: dcz window log is computed exactly once per request
# ngx_http_zstd_dcz_window_log() used to run twice on a cold dcz request:
# once in acquire_cctx() to key the CCtx ring slot, once again in
# init_cctx() to set ZSTD_c_windowLog. Both calls take the same four
# inputs and cannot observably differ, so a plain response-body test
# cannot tell one computation from two -- exactly why TEST 46 above passes
# either way. The debug line at the single memoisation site
# (ctx->dcz_window_log_cache) is the witness that the value is computed
# once, not read twice from a shared source that happens to agree: it is
# logged ONLY on a cache miss, so it appears in the log exactly once per
# request regardless of how many times the cached value is subsequently
# read.
#
# Falsifiability: the witness is emitted at BOTH memoisation sites
# (acquire_cctx() and init_cctx()), each inside its own cache-miss guard,
# so it is logged once per ACTUAL computation rather than once per
# request. Defeating the memoisation (forcing both guards true) makes the
# line appear twice and this test goes red on grep_error_log_out, while
# every byte-level assertion in this suite (TEST 46 included) stays green
# -- verified by mutation, not assumed. Emitting the witness at only one
# of the two sites would make this test pass whether the value is computed
# once or twice; do not "simplify" it that way.
--- config
    error_log logs/error.log debug;
    location /test {
        zstd on;
        zstd_types *;
        zstd_min_length 1;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz window-log single-compute witness body\n";
    }
--- request
GET /test
--- more_headers eval
"Accept-Encoding: zstd, dcz\nAvailable-Dictionary: :$::dict_b64:"
--- response_headers
Content-Encoding: dcz
--- grep_error_log eval
qr/zstd: dcz window log computed once: \d+/
--- grep_error_log_out eval
qr/^zstd: dcz window log computed once: \d+\n?$/
--- no_error_log
[error]



=== TEST 50: missing Available-Dictionary emits its dcz fallback trace
# The response contract matches TEST 2 (ordinary zstd fallback), but that
# outcome alone cannot distinguish a missing header from any other dcz
# negotiation rejection.  The debug line is the operator-facing witness for
# this specific branch.  A valid dcz coding is required here: without it the
# earlier Accept-Encoding gate correctly wins and this assertion would be
# vacuous.
--- log_level: debug
--- config
    location /t {
        zstd on;
        zstd_min_length 16;
        zstd_dcz_dict_file $TEST_NGINX_PERL_PATH/suite/dcz-dict;
        default_type text/plain;
        return 200 "dcz missing Available-Dictionary trace body\n";
    }
--- request
GET /t
--- more_headers
Accept-Encoding: zstd, dcz
--- response_headers
Content-Encoding: zstd
--- error_log
zstd dcz: skip, no Available-Dictionary header
--- no_error_log
[error]
