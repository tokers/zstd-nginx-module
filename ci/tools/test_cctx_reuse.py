#!/usr/bin/env python3
"""Regression test for the worker-lifetime ZSTD_CCtx cache.

ZSTD_createCCtx() plus its first-use workspace allocation is 34-75% of the
per-response libzstd CPU at typical body sizes, so the filter lends one
worker-lifetime context to one request at a time instead of creating a fresh
context per response.

Two properties have to hold at once, and a test for either alone is worthless:

  1. The cache actually engages. A green correctness suite proves only that
     nothing broke -- it passes identically if the cache never hits and every
     request builds its own context, which is the bug this optimisation exists
     to avoid. Asserted here from the ngx_log_debug witnesses: N sequential
     requests through one worker must yield exactly ONE "created cctx" and
     N-1 "reusing worker cctx".

  2. Reuse never bleeds state between requests. Asserted by decoding every
     response and byte-comparing it to its own distinct origin body. This
     overlaps test_concurrent_cctx_isolation.py on purpose: that tool proves
     the CONCURRENT case (a second in-flight claimant must not get the loaned
     context), this one proves the SEQUENTIAL case (the reused context must
     carry no residue from the previous response).

Also pins the PROFILE-partition rule: a location whose memory-affecting
profile differs must NOT reuse a context cached for another profile, because
the retained workspace never shrinks on reset. The profile is all three of
zstd_comp_level, zstd_long and zstd_window_log -- measured on libzstd 1.5.7,
streaming at a fixed level 6 with an unknown pledged size, ZSTD_sizeof_CCtx()
is 4.2 MB at window_log 20 and 131 MB at window_log 27, and 147 MB with
zstd_long on and no explicit window. Keying on the level alone would let a
single high-memory location raise the worker's floor for every request of
every other location and silently defeat their zstd_max_cctx_memory budget.

Needs an nginx built --with-debug: the reuse witnesses are debug log lines.
"""

import argparse
import importlib.util
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import time
import urllib.request

MODULE_PATH = pathlib.Path(__file__).with_name("test_encoding.py")
SPEC = importlib.util.spec_from_file_location("test_encoding", MODULE_PATH)
test_encoding = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(test_encoding)

CREATE_WITNESS = "zstd: created cctx"
REUSE_WITNESS = "zstd: reusing worker cctx"

# Enough requests that a one-off cache miss cannot be mistaken for the
# steady state, small enough to stay fast.
ROUNDS = 12

# Comfortably over zstd_min_length, and distinct per request so a stale
# context serving the previous body is a byte mismatch, not a silent pass.
BODY_SIZE = 24 * 1024

# The three locations whose memory profile differs from the default, each
# of which must occupy its OWN ring slot.
ALT_LOCATIONS = (
    ("/alt/b", 999, "zstd_comp_level 9"),
    ("/alt/long", 998, "zstd_long on"),
    ("/alt/wlog", 997, "zstd_window_log 20"),
)

# Requests per /alt location. Must be >= 2: the first seeds that profile's
# slot, the rest are the reuse witnesses that only a per-profile ring can
# produce.
ALT_ROUNDS = 4
assert ALT_ROUNDS >= 2

# One context per distinct profile, and no more.
WANT_CREATED = 1 + len(ALT_LOCATIONS)

# ROUNDS-1 reuses on the default profile (the first /b request seeds its
# slot), plus ALT_ROUNDS-1 on each differing profile.
WANT_REUSED = (ROUNDS - 1) + len(ALT_LOCATIONS) * (ALT_ROUNDS - 1)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Regression test for the worker-lifetime ZSTD_CCtx cache."
    )
    parser.add_argument("--nginx-binary", required=True)
    parser.add_argument("--filter-module")
    parser.add_argument("--port", type=int, default=18116)
    parser.add_argument(
        "--log-level",
        choices=("debug", "warn"),
        default="debug",
        help="Location error_log level. The cache-engagement witnesses are "
        "only asserted at debug. Use warn under sanitizer builds: UBSAN "
        "(-fno-sanitize-recover) fatally traps nginx core's own debug "
        'logging -- every "%%V?%%V" line passes r->args={0,NULL} into '
        "ngx_sprintf_str's nonnull argument on query-less URIs "
        "(ngx_string.c:586) -- so a sanitized nginx cannot log at debug at "
        "all. The byte-exactness oracles still run and still gate; only the "
        "witness counts are skipped.",
    )
    parser.add_argument(
        "--zstd-bin",
        default=test_encoding.shutil.which("zstd") or "zstd",
    )
    return parser.parse_args()


def fixture(rid: int) -> bytes:
    """A distinct, compressible body per request id.

    Distinct matters: if every request shared one body, a context that
    replayed the PREVIOUS response would still decode byte-exact and the
    isolation half of this test would assert nothing.
    """
    seed = f"cctx-reuse-{rid:04d}-".encode()
    return (seed * (BODY_SIZE // len(seed) + 1))[:BODY_SIZE]


def http_get(port: int, path: str) -> bytes:
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        headers={"Accept-Encoding": "zstd"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        if resp.headers.get("Content-Encoding") != "zstd":
            raise RuntimeError(
                f"{path}: expected Content-Encoding: zstd, got "
                f"{resp.headers.get('Content-Encoding')!r} -- the response was "
                f"not compressed, so this run proves nothing about the cache"
            )
        return resp.read()


def main() -> int:
    args = parse_args()
    nginx = pathlib.Path(args.nginx_binary)
    if not nginx.exists():
        raise FileNotFoundError(nginx)

    v = subprocess.run([str(nginx), "-V"], capture_output=True, text=True, check=False)
    if "zstd" not in v.stderr:
        raise RuntimeError("nginx -V shows no zstd module")
    if args.log_level == "debug" and "--with-debug" not in v.stderr:
        raise RuntimeError(
            "the reuse witnesses are ngx_log_debug lines: this tool needs an "
            "nginx built --with-debug, or --log-level warn to skip them"
        )

    filter_so = test_encoding.detect_module_path(
        args.filter_module, nginx, "ngx_http_zstd_filter_module.so"
    )
    load = f"load_module {filter_so};\n" if filter_so else ""

    def decode(blob: bytes) -> bytes:
        r = subprocess.run(
            [args.zstd_bin, "-d", "-q", "-c"],
            input=blob,
            capture_output=True,
            check=False,
        )
        if r.returncode != 0:
            raise RuntimeError(
                "zstd decode failed: " + r.stderr.decode("utf-8", "replace").strip()
            )
        return r.stdout

    os.umask(0o022)
    with tempfile.TemporaryDirectory(prefix="zstd-cctx-reuse-") as td:
        os.chmod(td, 0o755)
        root = pathlib.Path(td)
        (root / "logs").mkdir()
        html = root / "html"
        html.mkdir()
        alt = root / "html-alt"
        alt.mkdir()

        for rid in range(ROUNDS):
            (html / f"b{rid}").write_bytes(fixture(rid))
        # Served by the three locations that must each take the per-request
        # path: one differing only in zstd_comp_level, one differing only in
        # zstd_long, one differing only in zstd_window_log. The latter two
        # sit at the SAME level as the cached default on purpose -- under a
        # level-only cache key they would wrongly borrow it.
        (alt / "b").write_bytes(fixture(999))
        (alt / "long").write_bytes(fixture(998))
        (alt / "wlog").write_bytes(fixture(997))

        lvl = args.log_level
        conf = root / "nginx.conf"
        conf.write_text(
            f"""worker_processes 1;
{load}error_log {root}/logs/error.log warn;
pid {root}/nginx.pid;
events {{ worker_connections 64; }}
http {{
    access_log off;
    default_type application/octet-stream;
    zstd on;
    zstd_min_length 1;
    zstd_types application/octet-stream;
    gzip_vary on;
    server {{
        listen 127.0.0.1:{args.port};
        location /b {{
            error_log {root}/logs/error.log {lvl};
            alias {html}/;
        }}
        location /alt/b {{
            error_log {root}/logs/error.log {lvl};
            alias {alt}/b;
            zstd_comp_level 9;
        }}
        # Same compression level as the cached default context; differs
        # only in a memory-affecting parameter. Each must create its own
        # context rather than borrowing the cached one.
        location /alt/long {{
            error_log {root}/logs/error.log {lvl};
            alias {alt}/long;
            zstd_long on;
        }}
        location /alt/wlog {{
            error_log {root}/logs/error.log {lvl};
            alias {alt}/wlog;
            zstd_window_log 20;
        }}
    }}
}}
""",
            encoding="utf-8",
        )

        nlog_path = root / "logs" / "nginx-stdout.log"
        nlog = open(nlog_path, "w", encoding="utf-8")  # noqa: SIM115
        proc = subprocess.Popen(
            [
                str(nginx),
                "-p",
                str(root),
                "-c",
                str(conf),
                "-g",
                "daemon off; master_process off;",
            ],
            stdout=nlog,
            stderr=subprocess.STDOUT,
            text=True,
        )

        failures: list[str] = []
        try:
            test_encoding.wait_for_port(args.port)
            if proc.poll() is not None:
                nlog.flush()
                raise RuntimeError(
                    "nginx exited during startup; tail:\n"
                    + nlog_path.read_text("utf-8", "replace")[-2000:]
                )

            # --- property 2: no state bleed across reused contexts ---
            for rid in range(ROUNDS):
                want = fixture(rid)
                got = decode(http_get(args.port, f"/b/b{rid}"))
                if got != want:
                    failures.append(
                        f"request {rid}: decoded {len(got)}B != origin "
                        f"{len(want)}B -- the reused context carried state "
                        f"from a previous response"
                    )
                    break

            # Each differing memory profile gets its OWN ring slot: the
            # first request seeds that slot, and every further request to
            # the same location must REUSE it. Requesting each location
            # ALT_ROUNDS times is what makes the per-profile half of the
            # ring observable at all -- with a single request each, a ring
            # and the old single-slot cache produce identical witness
            # counts (one create, no reuse) and this test could not tell
            # them apart. Under the single slot the default /b profile owns
            # the one slot, so every one of these requests is a fresh
            # create and `reused` falls short by ALT_PROFILES *
            # (ALT_ROUNDS - 1).
            for path, rid, label in ALT_LOCATIONS:
                for _ in range(ALT_ROUNDS):
                    if decode(http_get(args.port, path)) != fixture(rid):
                        failures.append(f"{label} location: decoded body mismatch")
                        break

            # Flush the debug log before reading witnesses.
            time.sleep(0.3)
            elog = (root / "logs" / "error.log").read_text("utf-8", "replace")
            created = len(re.findall(re.escape(CREATE_WITNESS), elog))
            reused = len(re.findall(re.escape(REUSE_WITNESS), elog))

            if args.log_level != "debug":
                print(
                    "  witnesses skipped (--log-level warn: a sanitized "
                    "nginx cannot log at debug -- byte-exactness still "
                    "gates, cache engagement is NOT proven in this run)"
                )

            # --- property 1: the cache actually engages ---
            #
            # Exactly four contexts are ever created: the default-profile one
            # seeded by the first /b request, plus one each for the three
            # /alt locations, none of which may borrow it. Fewer than four
            # means the cache lent across differing memory profiles -- the
            # bug this partition exists to prevent, and the two same-level
            # locations are the ones a level-only key gets wrong. More than
            # four means the cache is not holding across requests.
            if args.log_level == "debug" and created != WANT_CREATED:
                failures.append(
                    f"expected exactly {WANT_CREATED} 'created cctx' "
                    f"witnesses (one per distinct memory profile: the "
                    f"default, plus the zstd_comp_level / zstd_long / "
                    f"zstd_window_log locations, each of which must get its "
                    f"OWN ring slot rather than borrowing another "
                    f"profile's), saw {created} -- fewer means a slot was "
                    f"lent across memory profiles, more means slots are not "
                    f"surviving across requests"
                )
            # One create per distinct profile; every other request reuses
            # that profile's slot. The ALT_ROUNDS-1 reuses per /alt
            # location are the per-profile-slot witnesses: a single-slot
            # cache cannot produce them, because the default profile
            # permanently owns the only slot.
            if args.log_level == "debug" and reused != WANT_REUSED:
                failures.append(
                    f"expected {WANT_REUSED} 'reusing worker cctx' "
                    f"witnesses ({ROUNDS - 1} on the default profile plus "
                    f"{ALT_ROUNDS - 1} on each of the {len(ALT_LOCATIONS)} "
                    f"differing profiles, which a single-slot cache cannot "
                    f"produce at all), saw {reused}"
                )

            if not failures:
                print(
                    f"  {ROUNDS} sequential responses decoded byte-exact to "
                    f"their own origins"
                )
                if args.log_level == "debug":
                    print(
                        f"  witnesses: {created} cctx created, {reused} "
                        f"reused -- cache engaged and profile-partitioned"
                    )
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            nlog.close()

        if failures:
            for f in failures:
                print(f"FAIL: {f}", file=sys.stderr)
            return 1

    print(
        f"OK: worker CCtx cache reused across {ROUNDS} sequential requests "
        f"with no cross-request state bleed, and a differing "
        f"zstd_comp_level, zstd_long or zstd_window_log each correctly took "
        f"the per-request path"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
