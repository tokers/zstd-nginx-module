use Test::Nginx::Socket;
use File::Basename;
use File::Spec;
use lib 'lib';

my $dirname = dirname(__FILE__);
# Absolute path to the committed fixture dir (ci/t/suite, holding test +
# test.zst). TEST 14 uses it so the fixture is independent of which safe,
# runner-private servroot a local, PR, deep, or coverage invocation selects.
our $suite_dir = File::Spec->rel2abs("$dirname/suite");
# local: this process is the test run, but perlcritic is right that a bare
# assignment to %ENV leaks into anything that runs after it.
local $ENV{'TEST_NGINX_PERL_PATH'} = "$ENV{'PWD'}/$dirname";

my @dynamic_modules;
our $static_so;    # the static .so alone, for the filterless block
if (defined $ENV{'TEST_NGINX_BINARY'}) {
    my $nginx_dir = dirname($ENV{'TEST_NGINX_BINARY'});
    for my $module_name (qw(ngx_http_zstd_filter_module.so ngx_http_zstd_static_module.so)) {
        my $module_path = "$nginx_dir/$module_name";
        push @dynamic_modules, $module_path if -f $module_path;
        $static_so = $module_path
            if $module_name eq 'ngx_http_zstd_static_module.so'
               && -f $module_path;
    }
}

add_block_preprocessor(sub {
    my $block = shift;
    return if !@dynamic_modules;

    # Blocks named "filterless" model the static-only deployment: load
    # ONLY the static .so, so ngx_http_zstd_filter_module is genuinely
    # absent from the cycle. Possible on dynamic builds alone — those
    # blocks skip_eval themselves away when the .so is not there.
    if (defined($block->name) && $block->name =~ /filterless/ && $static_so) {
        $block->set_value("main_config", "load_module $static_so;");
        return;
    }

    my $main_config = join "\n", map { "load_module $_;" } @dynamic_modules;
    $block->set_value("main_config", $main_config);
});

no_long_string();
log_level 'warn';
# Config-load warnings are emitted ONCE at startup; with repeat_each > 1
# the error.log is wiped between repeats and later iterations cannot
# re-observe them (why these blocks live outside t/00-filter.t).
repeat_each(1);
plan 'no_plan';
run_tests();

__DATA__


=== TEST 1: zstd_bypass_vary without zstd_bypass warns at config load
# zstd_bypass_vary names the header the zstd_bypass decision varies on;
# set alone it emits a Vary field no response varies on (silent cache
# hit-rate degradation). merge_loc_conf warns — assert the warning is
# actually emitted so the misconfig stays visible.
--- config
    location /warn {
        zstd on;
        zstd_bypass_vary X-No-Compression;
        default_type text/plain;
        return 200 "hello world padding padding padding\n";
    }
--- request
GET /warn
--- more_headers
Accept-Encoding: zstd
--- error_log
"zstd_bypass_vary" is set without a "zstd_bypass" predicate
--- no_error_log
[error]



=== TEST 2: zstd_bypass_vary WITH zstd_bypass does not warn
# The complementary half: a correctly paired configuration must load
# silently, so the warning cannot become noise on valid configs.
--- config
    location /paired {
        zstd on;
        zstd_bypass $http_x_no_compression;
        zstd_bypass_vary X-No-Compression;
        default_type text/plain;
        return 200 "hello world padding padding padding\n";
    }
--- request
GET /paired
--- more_headers
Accept-Encoding: zstd
--- no_error_log eval
[qr/zstd_bypass_vary.*without/, qr/\[error\]/]



=== TEST 2b: zstd_bypass on a direct $http_* predicate without vary warns
# Inverse of TEST 1: a zstd_bypass predicate that reads a request header
# DIRECTLY, with no zstd_bypass_vary alongside it, lets a shared cache
# mix an identity response with a compressed one under the same key.
--- config
    location /warn2b {
        zstd on;
        zstd_bypass $http_x_no_compression;
        default_type text/plain;
        return 200 "hello world padding padding padding\n";
    }
--- request
GET /warn2b
--- more_headers
Accept-Encoding: zstd
--- error_log
without a "zstd_bypass_vary"
--- no_error_log
[error]



=== TEST 2c: zstd_bypass on a direct $cookie_* predicate without vary warns
# Same hazard, cookie-driven bypass instead of a request header.
--- config
    location /warn2c {
        zstd on;
        zstd_bypass $cookie_no_compression;
        default_type text/plain;
        return 200 "hello world padding padding padding\n";
    }
--- request
GET /warn2c
--- more_headers
Accept-Encoding: zstd
--- error_log
without a "zstd_bypass_vary"
--- no_error_log
[error]



=== TEST 2d: direct predicate WITH zstd_bypass_vary stays silent
# The correctly-paired configuration (TEST 2's config) must not trip the
# new inverse warning either -- both directions of the coupling check
# must agree on a valid config.
--- config
    location /paired2d {
        zstd on;
        zstd_bypass $http_x_no_compression;
        zstd_bypass_vary X-No-Compression;
        default_type text/plain;
        return 200 "hello world padding padding padding\n";
    }
--- request
GET /paired2d
--- more_headers
Accept-Encoding: zstd
--- no_error_log eval
[qr/without a "zstd_bypass_vary"/, qr/\[error\]/]



=== TEST 2e: a map-based zstd_bypass predicate without vary stays silent
# Indirect variables (map results, etc.) are a documented operator
# responsibility, not something this module can resolve; the raw
# predicate text here is "$zstd_off", which contains neither "$http_"
# nor "$cookie_", so the new check must not fire a false positive.
--- http_config
    map $http_x_no_zstd $zstd_off {
        default 0;
        "1"     1;
    }
--- config
    location /warn2e {
        zstd on;
        zstd_bypass $zstd_off;
        default_type text/plain;
        return 200 "hello world padding padding padding\n";
    }
--- request
GET /warn2e
--- more_headers
Accept-Encoding: zstd
--- no_error_log eval
[qr/without a "zstd_bypass_vary"/, qr/\[error\]/]



=== TEST 2f: a response-only variable predicate without vary stays silent
# A predicate that references neither a request header nor a cookie --
# here a response-side module variable -- must not trip the new check.
--- config
    location /warn2f {
        zstd on;
        zstd_bypass $zstd_ratio;
        default_type text/plain;
        return 200 "hello world padding padding padding\n";
    }
--- request
GET /warn2f
--- more_headers
Accept-Encoding: zstd
--- no_error_log eval
[qr/without a "zstd_bypass_vary"/, qr/\[error\]/]



=== TEST 3: zstd_static rejects an invalid enum value cleanly
# Regression for the missing ngx_null_string sentinel in the
# ngx_http_zstd_static[] ngx_conf_enum_t array. ngx_conf_set_enum_slot()
# scans until name.len == 0; without the terminating { ngx_null_string, 0 }
# an unmatched value walked off the array end (OOB read, wild-pointer
# ngx_strcasecmp -> possible crash / ASAN abort). With the sentinel an
# unknown value is a clean "invalid value" config error. The ASAN CI job
# runs this binary, so a re-introduced OOB read aborts here.
--- config
    location /bad {
        zstd_static maybe;
        root html;
    }
--- must_die
--- error_log
invalid value "maybe"
--- no_error_log
[alert]



=== TEST 4: zstd_static accepts the last valid enum value ("always")
# Positive counterpart: the sentinel must not shorten the valid range.
# "always" is the final real entry, immediately before the sentinel — it
# still parses and loads.
--- config
    location /ok {
        zstd_static always;
        root html;
    }
--- request
GET /ok/nope
--- error_code: 404
--- no_error_log
invalid value



=== TEST 5: zstd_dict_file without zstd_dict_file_unsafe refuses to start
# RFC1 gate (init_main_conf): a dictionary-compressed body is emitted as a
# plain "Content-Encoding: zstd" that no generic client can decode and that
# RFC 9842 (dcz) does not negotiate. Starting without the explicit
# acknowledgement must be a hard config error, not a warning — otherwise the
# non-standard mode ships silently. Guards the operator-acknowledgement gate.
--- http_config
    zstd_dict_file $TEST_NGINX_SERVER_ROOT/html/zstd.dict;
--- user_files
>>> zstd.dict
the quick brown fox jumps over the lazy dog
--- config
    location /d {
        zstd on;
        default_type text/plain;
        return 200 "body";
    }
--- must_die
--- error_log
Set "zstd_dict_file_unsafe on;" to acknowledge you control both ends
--- no_error_log
[alert]



=== TEST 6: zstd_dict_file pointing at a missing file fails at config load
# The open() failure path in merge_loc_conf. A dictionary that vanished (bad
# path, un-deployed asset) must fail startup with the filename in the message,
# rather than starting and silently compressing without the dictionary.
--- http_config
    zstd_dict_file_unsafe on;
    zstd_dict_file $TEST_NGINX_SERVER_ROOT/html/does-not-exist.dict;
--- config
    location /d {
        zstd on;
        default_type text/plain;
        return 200 "body";
    }
--- must_die
--- error_log
does-not-exist.dict" failed
--- no_error_log
[alert]



=== TEST 7: zstd_comp_level above the library maximum is rejected
# ngx_http_zstd_comp_level bounds the level against ZSTD_minCLevel()/
# ZSTD_maxCLevel() at config load. Without the check libzstd would reject the
# value per-request, turning one typo into a 500 on every response for the
# location. Test above the upper bound rather than below the lower one:
# ZSTD_minCLevel() is -131072, so a "clearly too negative" literal would have
# to be enormous to stay invalid.
#
# The value is deliberately far above the bound rather than maxCLevel()+1: the
# module reads the maximum from libzstd at runtime, so a literal 23 would stop
# being invalid the day libzstd raises its ceiling, and this must_die block
# would silently start passing for the wrong reason.
--- config
    location /lvl {
        zstd on;
        zstd_comp_level 999999;
        default_type text/plain;
        return 200 "body";
    }
--- must_die
--- error_log
zstd compression level must be between
--- no_error_log
[alert]



=== TEST 8: zstd_window_log outside the library bounds is rejected
# C3 regression: zstd_window_log is validated against
# ZSTD_cParam_getBounds(ZSTD_c_windowLog) at config load, not hard-coded
# constants. 99 is above upperBound on every supported libzstd; catching it
# here turns a per-request 500 into a clear startup error.
--- config
    location /wl {
        zstd on;
        zstd_window_log 99;
        default_type text/plain;
        return 200 "body";
    }
--- must_die
--- error_log
"zstd_window_log" must be 0 (default) or between
--- no_error_log
[alert]



=== TEST 9: zstd_window_log accepts 0 (explicit "library default")
# Positive counterpart to TEST 8: the bounds check must special-case 0 rather
# than comparing it against lowerBound (which is > 0), or "keep zstd's
# level-derived default" would be unspellable.
--- config
    location /wl0 {
        zstd on;
        zstd_window_log 0;
        zstd_min_length 1;
        zstd_types text/plain;
        default_type text/plain;
        return 200 "compress me compress me compress me compress me";
    }
--- request
GET /wl0
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 10: a non-numeric zstd_window_log is rejected as an invalid number
# ngx_conf_zstd_set_num_slot_with_negatives' ngx_atoi failure path. The custom
# slot parser exists to accept negative levels, so its error handling is the
# module's own code rather than nginx's stock ngx_conf_set_num_slot.
--- config
    location /wlx {
        zstd on;
        zstd_window_log abc;
        default_type text/plain;
        return 200 "body";
    }
--- must_die
--- error_log
invalid number
--- no_error_log
[alert]



=== TEST 11: a duplicate zstd_comp_level in one location is rejected
# The "is duplicate" guard in ngx_conf_zstd_set_num_slot_with_negatives. The
# custom slot must reject a repeated directive exactly like nginx's stock
# num slot, or the second value would silently win.
--- config
    location /dup {
        zstd on;
        zstd_comp_level 3;
        zstd_comp_level 5;
        default_type text/plain;
        return 200 "body";
    }
--- must_die
--- error_log
"zstd_comp_level" directive is duplicate
--- no_error_log
[alert]



=== TEST 12: zstd on without gzip_vary still emits Vary: Accept-Encoding
# G5. Whether the response is zstd or identity depends on
# Accept-Encoding; without Vary a shared cache serves the compressed
# variant to a client that cannot decode it. This used to be a
# config-load WARNING telling the operator to set "gzip_vary on" —
# advice that was silently ignorable, and one missed warning poisoned a
# cache. The module now emits the field itself, so the header is what
# gets asserted, and the warning is gone: a warning about a directive
# that no longer changes the outcome would be misleading.
--- config
    location /gv {
        zstd on;
        zstd_min_length 1;
        default_type text/plain;
        return 200 "gzip_vary warning fixture body, long enough\n";
    }
--- request
GET /gv
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
Vary: Accept-Encoding
--- no_error_log eval
[qr/gzip_vary/, qr/\[error\]/]



=== TEST 13: zstd on WITH gzip_vary emits exactly one Vary line
# The duplicate-safety half. With "gzip_vary on" nginx emits the field
# from r->gzip_vary, so the module must NOT push a second identical
# line. Test::Nginx's response_headers compares the joined value of the
# field, so a doubled emission reads as "Accept-Encoding, Accept-Encoding"
# and fails here.
--- config
    location /gv {
        zstd on;
        zstd_min_length 1;
        gzip_vary on;
        default_type text/plain;
        return 200 "gzip_vary warning fixture body, long enough\n";
    }
--- request
GET /gv
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
Vary: Accept-Encoding
--- no_error_log eval
[qr/gzip_vary/, qr/\[error\]/]



=== TEST 14: zstd_static on without gzip_vary still emits Vary: Accept-Encoding
# G5, static handler, on the DECLINE arm. ci/t/suite holds test +
# test.zst, so this URI is Accept-Encoding-dependent; the client here
# does not accept zstd, so the handler emits the Vary field and then
# declines for the identity file to be served. That identity response
# is exactly the one a shared cache must not pin every later client to,
# and it must carry the field with no "gzip_vary on" configured — which
# is what the old warning could only ask for. TEST 25 in 01-static.t is
# the same arm WITH gzip_vary on.
#
# The fixture dir is addressed by ABSOLUTE path ($::suite_dir), not as
# "root ../suite", so this assertion is independent of the suite's
# runner-private servroot location.
--- config eval
"    location /test {
        zstd_static on;
        root $::suite_dir;
    }"
--- request
GET /test
--- more_headers
Accept-Encoding: gzip
--- response_headers
!Content-Encoding
Vary: Accept-Encoding
--- no_error_log eval
[qr/gzip_vary/, qr/\[error\]/]



=== TEST 15: zstd_static always does not vary and does not mention gzip_vary
# "always" ignores Accept-Encoding: it is not a negotiated variant, so
# it must NOT claim to vary on Accept-Encoding (that would fragment
# every cache key for nothing). The G5 emission is deliberately scoped
# to "on" only. See C5.
--- config
    location /st/ {
        zstd_static always;
        root html;
    }
--- user_files
>>> st/plain.txt
static warn fixture
--- request
GET /st/plain.txt
--- response_headers
!Vary
--- no_error_log eval
[qr/gzip_vary/, qr/\[error\]/]



=== TEST 16: an empty zstd_dict_file is rejected at config load
# A 0-byte trained dictionary used to load as a silent no-op: the read is
# complete (0 == size) and ZSTD_createCDict(buf, 0, level) returns a VALID
# CDict, so nginx started and compressed with no dictionary at all -- after
# the operator had explicitly set zstd_dict_file_unsafe on. The dcz loader
# has always rejected an empty file; both loaders now agree.
--- http_config
    zstd_dict_file_unsafe on;
    zstd_dict_file $TEST_NGINX_SERVER_ROOT/html/empty.dict;
--- user_files
>>> empty.dict
--- config
    location /d {
        zstd on;
        default_type text/plain;
        return 200 "body";
    }
--- must_die
--- error_log
empty.dict" is empty
--- no_error_log
[alert]



=== TEST 17: a duplicate zstd_comp_level is rejected when the first value is -1
# Regression: NGX_CONF_UNSET is -1, and -1 is a valid documented level, so
# the "is duplicate" guard tested the same value a real directive could
# store. "zstd_comp_level -1; zstd_comp_level 5;" was therefore accepted
# silently and 5 won. TEST 11 cannot catch this -- neither of its values is
# the sentinel. The slot now tests NGX_HTTP_ZSTD_LEVEL_UNSET.
--- config
    location /dup {
        zstd on;
        zstd_comp_level -1;
        zstd_comp_level 5;
        default_type text/plain;
        return 200 "body";
    }
--- must_die
--- error_log
"zstd_comp_level" directive is duplicate
--- no_error_log
[alert]



=== TEST 18: both modules in one location emit exactly ONE Vary: Accept-Encoding
# The duplicate-emission cell the G5 matrix missed, and it was REAL:
# with "zstd_static on" + "zstd on" + gzip_vary off, a non-accepting
# client made the static handler emit Vary and DECLINE, after which the
# filter emitted it again on the identity response it also declined to
# encode -- two identical field lines, breaking the exactly-one contract
# ngx_http_zstd_vary_accept_encoding() exists to keep. Reproduced with
# curl before the guard (2 lines), 1 after.
#
# The response_headers check below asserts the VALUE, which Test::Nginx
# joins with ", " when a field repeats -- so a regression reads as
# "Accept-Encoding, Accept-Encoding" and fails here rather than passing
# a mere presence check. That is the whole point of this block.
--- config eval
"    location /test {
        zstd_static on;
        zstd on;
        zstd_types text/plain;
        root $::suite_dir;
    }"
--- request
GET /test
--- more_headers
Accept-Encoding: gzip
--- response_headers
!Content-Encoding
Vary: Accept-Encoding
--- no_error_log eval
[qr/gzip_vary/, qr/\[error\]/]



=== TEST 19: both modules, accepting client, still exactly ONE Vary
# The other half of TEST 18: the zstd client takes the static sidecar
# path, which emits Vary and then SERVES rather than declining. Same
# exactly-one contract on the arm that actually returns a body.
--- config eval
"    location /test {
        zstd_static on;
        zstd on;
        zstd_types text/plain;
        root $::suite_dir;
    }"
--- request
GET /test
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
Vary: Accept-Encoding
--- no_error_log eval
[qr/gzip_vary/, qr/\[error\]/]



=== TEST 21: zstd_dict_strict_path refuses a ".." path component
# The component walk explicitly rejects "." and ".." rather than
# resolving them, because ".." would climb back above a component
# already verified and make the walk's guarantee unstatable.
--- http_config eval
"    zstd_dict_file_unsafe on;
    zstd_dict_strict_path on;
    zstd_dict_file \$TEST_NGINX_SERVER_ROOT/html/../html/zstd.dict;"
--- user_files
>>> zstd.dict
the quick brown fox jumps over the lazy dog
--- post_setup_server_root eval
'my $root = $ENV{TEST_NGINX_SERVER_ROOT} or die "TEST_NGINX_SERVER_ROOT unset";
chmod(0755, $root, "$root/html") == 2
    or die "chmod strict-path fixture: $!";'
--- config
    location /d {
        zstd on;
        default_type text/plain;
        return 200 "body";
    }
--- must_die
--- error_log
contains a "." or ".." component; refused by "zstd_dict_strict_path on"
--- no_error_log
[alert]



=== TEST 22: zstd_dict_strict_path refuses a symlinked intermediate component
# The reason M3 exists: O_NOFOLLOW on the leaf alone guards only the last
# component, so /srv/current/dict.bin with "current" a symlink is
# followed silently by a plain open(). Walking one component at a time
# with openat(O_NOFOLLOW) makes the symlinked "current" fail the walk.
--- http_config eval
"    zstd_dict_file_unsafe on;
    zstd_dict_strict_path on;
    zstd_dict_file \$TEST_NGINX_SERVER_ROOT/html/current/zstd.dict;"
--- post_setup_server_root eval
'my $root = $ENV{TEST_NGINX_SERVER_ROOT} or die "TEST_NGINX_SERVER_ROOT unset";
chmod(0755, $root, "$root/html") == 2
    or die "chmod strict-path fixture: $!";
my $real = "$root/html/real-release";
mkdir $real or die "mkdir $real: $!";
open my $fh, ">", "$real/zstd.dict" or die "open zstd.dict: $!";
print $fh "the quick brown fox jumps over the lazy dog";
close $fh;
symlink $real, "$root/html/current"
    or die "symlink current: $!";'
--- config
    location /d {
        zstd on;
        default_type text/plain;
        return 200 "body";
    }
--- must_die
--- error_log
a symlink at any component is refused, not followed
--- no_error_log
[alert]



=== TEST 23: a tight zstd_max_cctx_memory without dcz dictionaries still loads
# Regression pin for the dcz window-cap floor. ngx_http_zstd_dcz_window_cap()
# walks down from NGX_HTTP_ZSTD_DCZ_MAX_WINDOW_LOG and, if nothing fit, pins
# the cap to NGX_HTTP_ZSTD_DCZ_MIN_WINDOW_LOG and succeeds rather than
# rejecting. That permissive fallthrough must stay permissive: a budget the
# hard gate accepted has to keep loading, so the cap computation can never
# turn a working "nginx -t" into a failure. Level 1 at the default window
# estimates ~1.37 MB (libzstd 1.5.7), so 2m is tight but satisfiable — the
# budget path is genuinely exercised rather than trivially slack, and the
# location configures no zstd_dcz_dict_file, which is the scoping that makes
# the dcz clamp irrelevant here. Asserts a served response, not merely a
# start, so a config that loads but breaks compression still fails.
--- config
    location /budget {
        zstd on;
        zstd_min_length 1;
        zstd_comp_level 1;
        zstd_max_cctx_memory 2m;
        zstd_types text/plain;
        default_type text/plain;
        return 200 "hello world padding padding padding padding padding\n";
    }
--- request
GET /budget
--- more_headers
Accept-Encoding: zstd
--- response_headers
Content-Encoding: zstd
--- no_error_log
[error]



=== TEST 24: filterless dict bypass warns at config load (identity trap)
# The static-only deployment (this module's own reason for the split)
# with zstd_static_dict_bypass on: every matching HTTPS client that
# acquired an advertised dictionary bypasses its .zst sidecar into a
# filter that does not exist, and is served identity permanently. The
# module cannot see per-location filter state across the split, but
# module-absent IS detectable (the #110 cycle->modules name scan) — one
# warning at startup. Only expressible on dynamic builds, where the
# filter .so can genuinely be left unloaded: skip_eval otherwise.
--- skip_eval: 3: !$::static_so
--- config
    location /t {
        zstd_static on;
        zstd_static_dict_bypass on;
        root html;
    }
    location /ok { return 200 "up\n"; }
--- request
GET /ok
--- error_code: 200
--- error_log
"zstd_static_dict_bypass on" but ngx_http_zstd_filter_module is not loaded
--- no_error_log
[emerg]



=== TEST 25: with the filter module loaded, the bypass warning is silent
# Control for TEST 24 in both build shapes: dynamic builds load both
# .so files here (the default preprocessor path), static-linked builds
# have the filter compiled in — either way the module is present and
# the warning must not fire.
--- config
    location /t {
        zstd_static on;
        zstd_static_dict_bypass on;
        root html;
    }
    location /ok { return 200 "up\n"; }
--- request
GET /ok
--- error_code: 200
--- no_error_log eval
[qr/zstd_static_dict_bypass on. but ngx_http_zstd_filter_module/, qr/\[emerg\]/]
