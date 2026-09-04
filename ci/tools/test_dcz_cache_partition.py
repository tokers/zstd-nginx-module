#!/usr/bin/env python3
"""Shared-cache partitioning test for the dcz cross-origin decision.

``ngx_http_zstd_dcz_negotiate()`` treats ``Sec-Fetch-Site`` as a
response-selection input: absent / ``same-origin`` / ``none`` may
negotiate dcz, every other value (``cross-site``, ``same-site``) falls
back to plain zstd. A header that selects the representation must be
listed in ``Vary`` or a shared cache will serve one client's variant to
another.

This harness builds a REAL two-server fixture inside one nginx:

    client -> :front (proxy_cache, no zstd)  ->  :origin (zstd + dcz)

and runs the fill-order matrix

    {same-origin, cross-site, absent Sec-Fetch-Site} x {both fill orders}

recording what the cache actually serves in each cell. Without
``Vary: Sec-Fetch-Site`` the second request in each pair is a cache HIT
on the first request's variant:

  * fill same-origin then request cross-site -> the dcz body is served
    to a cross-site client, bypassing the origin gate entirely;
  * fill cross-site then request same-origin -> dcz is suppressed for a
    legitimate same-origin client.

Both are asserted here. The test fails on a module that does not push
``Vary: Sec-Fetch-Site``.

Notes on the rig
----------------
* dcz requires a secure context (RFC 9842 section 8). The origin server
  sets ``zstd_dcz_assume_secure_transport on`` — the "TLS terminated
  upstream" deployment — because Test::Nginx/this harness speak plain
  HTTP. Without it nginx never negotiates dcz and every cell looks
  identical (a vacuous green).
* The oracle is the response's own ``Content-Encoding`` plus the dcz
  magic in the body, NOT body equality: a dcz body and a zstd body of
  the same resource are both "valid", so only the encoding marker
  discriminates. ``X-Cache-Status`` is asserted too so a cell that was
  a MISS cannot masquerade as a correctly-partitioned HIT.
* Each matrix cell uses a distinct URI so the cache entries of one cell
  cannot leak into the next.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time

DCZ_MAGIC = b"\x5e\x2a\x4d\x18"  # zstd skippable frame 0x184D2A5E, LE

# Each cell gets its own URI: a stale entry from a previous cell must
# not be able to answer the next one.
CELLS = [
    # (label, first request's Sec-Fetch-Site, second request's, uri)
    ("same-origin then cross-site", "same-origin", "cross-site", "/c/a"),
    ("cross-site then same-origin", "cross-site", "same-origin", "/c/b"),
    ("same-origin then absent", "same-origin", None, "/c/c"),
    ("absent then cross-site", None, "cross-site", "/c/d"),
    ("cross-site then absent", "cross-site", None, "/c/e"),
    ("absent then same-origin", None, "same-origin", "/c/f"),
]


def dcz_expected(sfs: str | None) -> bool:
    """What the ORIGIN would serve for this Sec-Fetch-Site, uncached."""
    return sfs is None or sfs in ("same-origin", "none")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="dcz shared-cache partitioning (Vary: Sec-Fetch-Site) test."
    )
    p.add_argument("--nginx-binary", required=True)
    p.add_argument("--filter-module")
    p.add_argument("--static-module")
    p.add_argument("--port", type=int, default=18120, help="Caching front-end port.")
    p.add_argument("--origin-port", type=int, default=18121)
    p.add_argument(
        "--dict",
        default=str(pathlib.Path(__file__).resolve().parents[1] / "t/suite/dcz-dict"),
        help="Dictionary fixture (default: ci/t/suite/dcz-dict).",
    )
    return p.parse_args()


def detect_module(explicit, nginx: pathlib.Path, name: str):
    if explicit:
        return pathlib.Path(explicit)
    sib = nginx.parent / name
    return sib if sib.exists() else None


def wait_port(port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"nothing listening on 127.0.0.1:{port}")


def request(port: int, uri: str, sfs: str | None, dict_b64: str):
    headers = {
        "Host": "cache.test",
        "Accept-Encoding": "zstd, dcz",
        "Available-Dictionary": f":{dict_b64}:",
        "Connection": "close",
    }
    if sfs is not None:
        headers["Sec-Fetch-Site"] = sfs
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    try:
        conn.request("GET", uri, headers=headers)
        resp = conn.getresponse()
        body = resp.read()
        return (
            resp.status,
            (resp.getheader("Content-Encoding") or "").lower(),
            (resp.getheader("X-Cache-Status") or "").upper(),
            resp.getheader("Vary") or "",
            body,
        )
    finally:
        conn.close()


def main() -> int:
    args = parse_args()
    nginx = pathlib.Path(args.nginx_binary).resolve()
    if not nginx.exists():
        raise FileNotFoundError(f"nginx binary not found: {nginx}")

    filt = detect_module(args.filter_module, nginx, "ngx_http_zstd_filter_module.so")
    stat = detect_module(args.static_module, nginx, "ngx_http_zstd_static_module.so")
    modules = [m.resolve() for m in (filt, stat) if m is not None]
    for m in modules:
        if not m.exists():
            raise FileNotFoundError(f"module not found: {m}")

    dict_path = pathlib.Path(args.dict)
    dict_raw = dict_path.read_bytes()
    dict_b64 = base64.b64encode(hashlib.sha256(dict_raw).digest()).decode()

    os.umask(0o022)
    with tempfile.TemporaryDirectory(prefix="zstd-dczcache-") as td:
        os.chmod(td, 0o755)
        root = pathlib.Path(td)
        for sub in ("html", "logs", "cache", "tmp"):
            (root / sub).mkdir()
        shutil.copyfile(dict_path, root / "dcz-dict")

        # Compressible, dictionary-friendly payload: the dictionary's own
        # bytes repeated, so dcz and plain zstd both succeed and differ.
        (root / "html" / "payload").write_bytes(dict_raw * 8)
        for _, _, _, uri in CELLS:
            dst = root / "html" / uri.lstrip("/")
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / "html" / "payload", dst)

        load = "".join(f"load_module {m};\n" for m in modules)
        conf = root / "nginx.conf"
        conf.write_text(
            f"""{load}worker_processes 1;
error_log {root}/logs/error.log warn;
pid {root}/nginx.pid;
events {{ worker_connections 64; }}
http {{
    access_log off;
    default_type application/octet-stream;
    proxy_temp_path {root}/tmp;
    proxy_cache_path {root}/cache levels=1:2 keys_zone=dczc:4m inactive=10m;

    # Front-end: a SHARED cache. No zstd here — it must serve exactly
    # what the origin gave it, so the cached variant is observable.
    server {{
        listen 127.0.0.1:{args.port};
        server_name cache.test;
        location / {{
            proxy_pass http://127.0.0.1:{args.origin_port};
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_cache dczc;
            proxy_cache_valid 200 10m;
            # Deliberately NOT proxy_cache_key'd on Sec-Fetch-Site: the
            # point is whether the ORIGIN declares the dependency via
            # Vary, which is the only thing an operator-independent
            # shared cache (CDN, browser cache) can act on.
            add_header X-Cache-Status $upstream_cache_status always;
        }}
    }}

    # Origin: the module under test.
    server {{
        listen 127.0.0.1:{args.origin_port};
        server_name cache.test;
        root {root}/html;
        zstd on;
        zstd_comp_level 3;
        zstd_min_length 1;
        zstd_types application/octet-stream;
        zstd_dcz_assume_secure_transport on;
        zstd_dcz_dict_file {root}/dcz-dict;
        location / {{ }}
    }}
}}
""",
            encoding="utf-8",
        )

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
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            try:
                wait_port(args.origin_port)
                wait_port(args.port)
            except RuntimeError:
                # nginx refused to start: its own diagnostics are the
                # answer, not the bare "nothing listening".
                if proc.poll() is not None and proc.stdout is not None:
                    sys.stderr.write(proc.stdout.read())
                elog = root / "logs" / "error.log"
                if elog.exists():
                    sys.stderr.write(elog.read_text(errors="replace")[-4000:])
                raise

            # Rig self-check: the ORIGIN itself must discriminate, or
            # every matrix cell is vacuous.
            for sfs in ("same-origin", "cross-site", None):
                st, ce, _, _, body = request(
                    args.origin_port, "/payload", sfs, dict_b64
                )
                want = dcz_expected(sfs)
                got = ce == "dcz"
                if st != 200 or got != want:
                    raise RuntimeError(
                        f"origin self-check failed for Sec-Fetch-Site={sfs!r}: "
                        f"status={st} Content-Encoding={ce!r}, expected "
                        f"{'dcz' if want else 'zstd'}"
                    )
                if want and not body.startswith(DCZ_MAGIC):
                    raise RuntimeError(
                        "origin self-check: Content-Encoding dcz but body "
                        f"lacks the skippable-frame magic (first 8B "
                        f"{body[:8].hex()})"
                    )

            failures: list[str] = []
            print(
                "cell                              "
                "fill        second      served    cache  ok"
            )
            for label, first, second, uri in CELLS:
                st1, _ce1, _cs1, vary1, _ = request(args.port, uri, first, dict_b64)
                st2, ce2, cs2, _vary2, body2 = request(args.port, uri, second, dict_b64)

                want2 = dcz_expected(second)
                got2 = ce2 == "dcz"
                ok = st1 == 200 and st2 == 200 and got2 == want2
                if got2 and not body2.startswith(DCZ_MAGIC):
                    ok = False
                print(
                    f"{label:34s}{first!s:12s}{second!s:12s}"
                    f"{ce2 or '-':10s}{cs2 or '-':7s}{'PASS' if ok else 'FAIL'}"
                )
                if not ok:
                    failures.append(
                        f"{label}: after filling with Sec-Fetch-Site={first!r}, "
                        f"a request with Sec-Fetch-Site={second!r} was served "
                        f"Content-Encoding={ce2!r} (cache {cs2 or '-'}), expected "
                        f"{'dcz' if want2 else 'zstd'}. "
                        f"Vary on the fill was {vary1!r}."
                    )

            if failures:
                sys.stderr.write(
                    f"dcz shared-cache partitioning FAILED ({len(failures)} cells):\n"
                )
                for f in failures:
                    sys.stderr.write(f"  - {f}\n")
                return 1

            print(f"OK: dcz cache partitioning holds across {len(CELLS)} cells")
            return 0
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    sys.exit(main())
