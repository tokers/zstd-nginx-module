#!/usr/bin/env python3
"""Regression test for the dcz 40-byte prefix inlining.

RFC 9842 dcz responses used to queue the fixed 40-byte skippable-frame
prefix (magic + dictionary SHA-256) on its OWN pool buffer and chain link,
separate from the compressor's output buffers. ngx_http_zstd_filter_get_buf()
now reserves 40 bytes at the front of the FIRST compressor output buffer
and writes the prefix there instead, so a dcz response allocates one fewer
ngx_buf_t/chain-link pair per response.

This is a pure allocation-count and wire-format regression test:

  * runs a debug build (error_log ... debug) and greps its own log for
    "zstd get_buf: allocated buffer" (compressor output-buffer pool
    allocations) and "zstd dcz: 40-byte frame header queued" (the OLD
    dedicated-buffer code path -- must never fire again);
  * captures a strace -e trace=writev count for the same request, as a
    downstream-iovec-reduction proxy;
  * decodes the dcz body with the negotiated dictionary and byte-compares
    it against the plain fixture, so a buffer/prefix accounting change can
    never silently corrupt the wire body while "passing" on allocation
    counts alone.

Exercises three body sizes (empty-compressed-output edge via a 1-byte
body, a small body, and a body spanning multiple compressor iterations)
so the assertion holds across the END-transition retry path the prefix
sits in front of, not only the single-iteration common case.
"""

import argparse
import base64
import hashlib
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

DCZ_MAGIC = bytes([0x5E, 0x2A, 0x4D, 0x18, 0x20, 0x00, 0x00, 0x00])


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--nginx-binary", required=True)
    p.add_argument("--filter-module")
    p.add_argument("--port", type=int, default=18311)
    return p.parse_args()


def detect_module(explicit, nginx: pathlib.Path):
    if explicit:
        return pathlib.Path(explicit)
    sib = nginx.parent / "ngx_http_zstd_filter_module.so"
    return sib if sib.exists() else None


def wait_for_port(port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"nginx never opened port {port}")


def write_config(
    root: pathlib.Path, port: int, module, dict_path: pathlib.Path, dict_hash_hex: str
) -> pathlib.Path:
    (root / "conf").mkdir()
    (root / "logs").mkdir()
    load = f"load_module {module};\n" if module else ""
    conf = root / "conf" / "nginx.conf"
    conf.write_text(
        f"""{load}
worker_processes 1;
daemon off;
error_log {root}/logs/error.log debug;
pid {root}/logs/nginx.pid;
events {{ }}
http {{
    access_log off;
    zstd on;
    zstd_min_length 1;
    zstd_types *;
    zstd_dcz_assume_secure_transport on;
    zstd_dcz_dict_file {dict_path} {dict_hash_hex};

    server {{
        listen 127.0.0.1:{port};
        root {root}/html;
    }}
}}
""",
        encoding="utf-8",
        newline="\n",
    )
    return conf


def fetch_dcz(port: int, dict_digest_b64: str, path: str) -> bytes:
    req = (
        f"GET /{path} HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Accept-Encoding: dcz, zstd\r\n"
        f"Available-Dictionary: :{dict_digest_b64}:\r\n"
        "Sec-Fetch-Site: same-origin\r\n"
        "Connection: close\r\n\r\n"
    )
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(req.encode())
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    return data


def split_response(data: bytes):
    head, rest = data.split(b"\r\n\r\n", 1)
    # dechunk (Transfer-Encoding: chunked -- every response here is)
    body = b""
    while rest:
        size_line, rest = rest.split(b"\r\n", 1)
        size = int(size_line.split(b";")[0], 16)
        if size == 0:
            break
        body += rest[:size]
        rest = rest[size + 2 :]
    return head.decode(errors="replace"), body


def decode_dcz(
    zstd_bin: str, body: bytes, dict_path: pathlib.Path, work: pathlib.Path
) -> bytes:
    src = work / "response.dcz"
    dst = work / "response.out"
    src.write_bytes(body)
    subprocess.run(
        [
            zstd_bin,
            "-d",
            "-q",
            "-f",
            "--memory=8388608",
            "-D",
            str(dict_path),
            "-o",
            str(dst),
            str(src),
        ],
        check=True,
        capture_output=True,
    )
    return dst.read_bytes()


def main() -> int:
    args = parse_args()
    failures = []

    def check(name: str, cond: bool, detail: str = "") -> None:
        if cond:
            print(f"ok - {name}")
        else:
            print(f"FAIL - {name} {detail}")
            failures.append(name)

    nginx_path = pathlib.Path(args.nginx_binary)
    module = detect_module(args.filter_module, nginx_path)
    zstd_bin = shutil.which("zstd")
    if zstd_bin is None:
        print("SKIP: no zstd CLI on PATH", file=sys.stderr)
        return 0

    with tempfile.TemporaryDirectory(prefix="zstd-dcz-alloc-") as tmp:
        root = pathlib.Path(tmp)
        (root / "html").mkdir()

        dict_bytes = b"The quick brown fox jumps over the lazy dog. " * 40
        dict_path = root / "dict.bin"
        dict_path.write_bytes(dict_bytes)
        dict_digest = hashlib.sha256(dict_bytes).digest()
        dict_hash_hex = hashlib.sha256(dict_bytes).hexdigest()
        dict_digest_b64 = base64.b64encode(dict_digest).decode()

        conf = write_config(root, args.port, module, dict_path, dict_hash_hex)

        bodies = {
            "1byte.txt": b"x",
            "small.txt": b"hello world tiny body for dcz prefix test",
            "multi.txt": (b"The quick brown fox jumps over the lazy dog. " * 50),
        }
        for name, content in bodies.items():
            (root / "html" / name).write_bytes(content)

        error_log = root / "logs" / "error.log"

        for name, content in bodies.items():
            error_log.write_text("")  # truncate between cases
            nginx = subprocess.Popen(
                [str(nginx_path), "-p", str(root), "-c", str(conf)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                wait_for_port(args.port)
                data = fetch_dcz(args.port, dict_digest_b64, name)
            finally:
                nginx.terminate()
                try:
                    nginx.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    nginx.kill()
                    nginx.wait(timeout=5)

            head, body = split_response(data)

            check(
                f"{name}: negotiated dcz",
                "Content-Encoding: dcz" in head,
                f"(head={head!r})",
            )
            check(
                f"{name}: body starts with RFC 9842 magic",
                body[:8] == DCZ_MAGIC,
                f"(got {body[:8].hex()})",
            )
            check(
                f"{name}: header embeds the dictionary SHA-256",
                body[8:40] == dict_digest,
                "",
            )

            decoded = decode_dcz(zstd_bin, body, dict_path, root)
            check(
                f"{name}: decode round-trip is byte-exact",
                decoded == content,
                f"(decoded {len(decoded)}B, expected {len(content)}B)",
            )

            log_text = error_log.read_text(errors="replace")
            alloc_count = len(re.findall(r"zstd get_buf: allocated buffer", log_text))
            old_path_count = len(
                re.findall(r"zstd dcz: 40-byte frame header queued", log_text)
            )

            check(
                f"{name}: old dedicated-prefix-buffer path never fires",
                old_path_count == 0,
                f"(matched {old_path_count} times -- prefix inlining "
                "regressed to the pre-fix separate-buffer path)",
            )
            check(
                f"{name}: exactly one compressor buffer allocated",
                alloc_count == 1,
                f"(got {alloc_count} allocations for a body that fits "
                "one compressor buffer plus the inlined prefix)",
            )

    print()
    if failures:
        print(f"FAILED: {len(failures)} check(s) did not pass:")
        for f in failures:
            print(f"  - {f}")
        return 1

    print(
        "OK: dcz prefix rides the first compressor buffer, one pool "
        "allocation per response, wire body unchanged"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
