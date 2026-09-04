#!/usr/bin/env python3
"""End-to-end RFC 9842 dcz test against a real nginx.

Covers what t/03-dcz.t cannot: the bytes on the wire. For every case the
test asserts the negotiated Content-Encoding, and for dcz responses it
additionally verifies the 40-byte frame header (skippable-frame magic +
dictionary SHA-256), decodes the body with `zstd -d -D <dict>` under the
RFC's 8 MB client window guarantee (--memory), and byte-compares against
the origin fixture. The dictionary is a simulated "previous version" of
the resource, so the test also asserts the dictionary actually engaged:
the dcz body must be smaller than the plain zstd body.
"""

import argparse
import base64
import hashlib
import os
import pathlib
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request

DCZ_MAGIC = bytes([0x5E, 0x2A, 0x4D, 0x18, 0x20, 0x00, 0x00, 0x00])
RFC_CLIENT_WINDOW = 8 * 1024 * 1024


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run an end-to-end RFC 9842 dcz test against nginx."
    )
    parser.add_argument(
        "--nginx-binary",
        required=True,
        help="Path to the nginx binary to start for the test.",
    )
    parser.add_argument(
        "--filter-module",
        help=(
            "Optional path to ngx_http_zstd_filter_module.so. "
            "If omitted, a sibling module next to the nginx binary is used."
        ),
    )
    parser.add_argument(
        "--static-module",
        help=(
            "Optional path to ngx_http_zstd_static_module.so. "
            "If omitted, a sibling module next to the nginx binary is used."
        ),
    )
    parser.add_argument(
        "--port",
        type=int,
        default=18106,
        help="Local TCP port for the temporary nginx instance.",
    )
    parser.add_argument(
        "--tls-port",
        type=int,
        default=None,
        help=(
            "Local TCP port for the native-TLS listener "
            "(default: --port + 1). RFC 9842 section 8 restricts dcz to "
            "secure contexts, so the happy path is exercised here."
        ),
    )
    parser.add_argument(
        "--insecure-port",
        type=int,
        default=None,
        help=(
            "Local TCP port for a plain-HTTP listener with NO "
            "zstd_dcz_assume_secure_transport (default: --port + 2). "
            "Used for the fail-closed secure-context checks."
        ),
    )
    parser.add_argument(
        "--zstd-bin",
        default=shutil.which("zstd") or "zstd",
        help="Path to the zstd CLI used for decompression.",
    )
    parser.add_argument(
        "--fixture-lines",
        type=int,
        default=600,
        help="Number of generated source lines shared between dictionary and resource.",
    )
    return parser.parse_args()


def detect_module(explicit, nginx: pathlib.Path, name: str):
    """A dynamic-module build (--add-dynamic-module, e.g. the Coverage CI
    job) needs load_module lines or `zstd on;` is an unknown directive
    and nginx dies at config parse; a static build has no .so and needs
    none. Mirror the sibling tools: an explicit path wins, else use a
    module sitting next to the nginx binary if present."""
    if explicit:
        return pathlib.Path(explicit)
    sib = nginx.parent / name
    return sib if sib.exists() else None


def nginx_has_ssl(nginx: pathlib.Path) -> bool:
    """Whether this binary can parse `listen ... ssl`.

    Same probe shape the sibling tools use for --with-debug
    (test_concurrent_cctx_isolation.py:206, test_slow_drain.py:233): ask
    the binary itself via -V rather than inferring from the environment
    or the job name. The sanitizer and valgrind nginx builds in this
    repo's CI are configured WITHOUT --with-http_ssl_module, where an
    `ssl` listen parameter is a config-time emerg that kills the tool
    before any assertion runs -- including every plain-HTTP check, which
    needs no TLS at all.
    """
    v = subprocess.run([str(nginx), "-V"], capture_output=True, text=True, check=False)
    return "--with-http_ssl_module" in v.stderr


def wait_for_port(port: int, timeout: float = 10.0, stderr_file=None) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)

    # A config-parse failure would otherwise surface only as this silent
    # timeout; include what nginx actually said on stderr.
    detail = ""
    if stderr_file is not None and stderr_file.exists():
        text = stderr_file.read_text(errors="replace").strip()
        if text:
            detail = f"; nginx stderr:\n{text}"
    raise RuntimeError(f"nginx did not start listening on 127.0.0.1:{port}{detail}")


def build_fixtures(root: pathlib.Path, lines: int) -> tuple[bytes, bytes]:
    """Dictionary = version 1; served resource = version 2 sharing most
    of its content. Returns (dict_bytes, resource_bytes)."""
    shared = [
        f"function widget_{i}() {{ return compute({i}) + render('{'x' * 20}'); }}"
        for i in range(lines)
    ]
    v1 = "\n".join(shared) + "\n"
    v2_lines = shared[:]
    for i in range(0, lines, 50):
        v2_lines.insert(i, f"// added in v2: handler {i}")
    v2 = "\n".join(v2_lines) + "\n"

    (root / "dicts").mkdir()
    (root / "html").mkdir()
    dict_path = root / "dicts" / "app-v1.js"
    dict_path.write_text(v1, encoding="utf-8", newline="\n")
    (root / "html" / "app.js").write_text(v2, encoding="utf-8", newline="\n")
    return dict_path.read_bytes(), (root / "html" / "app.js").read_bytes()


def make_selfsigned(root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    """Self-signed localhost cert for the native-TLS listener. Generated
    per run rather than committed: a fixture certificate in-tree expires
    and turns into a rolling CI failure
    (feedback-fixed-date-test-ages-into-failure)."""
    cert = root / "conf" / "test.crt"
    key = root / "conf" / "test.key"
    if shutil.which("openssl") is None:
        # ci/tools/soak.sh already depends on this binary in the same
        # jobs, so a miss here means the image changed, not that the
        # test is optional. Say so instead of surfacing FileNotFoundError.
        raise RuntimeError(
            "the openssl CLI is required to generate the native-TLS "
            "listener's certificate (RFC 9842 secure-context checks); "
            "install the openssl package"
        )
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-subj",
            "/CN=127.0.0.1",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        capture_output=True,
    )
    return cert, key


def write_config(
    root: pathlib.Path,
    port: int,
    tls_port: int,
    insecure_port: int,
    modules,
    with_ssl: bool,
) -> pathlib.Path:
    conf_dir = root / "conf"
    conf_dir.mkdir()
    (root / "logs").mkdir()
    load = "".join(f"load_module {m};\n" for m in modules)

    # Only emitted for an SSL-capable binary: `listen ... ssl` against an
    # nginx without ngx_http_ssl_module is [emerg] at config parse, so an
    # unconditional block would take every non-TLS assertion down with it.
    tls_server = ""
    if with_ssl:
        cert, key = make_selfsigned(root)
        tls_server = f"""
    # Native TLS: the secure context the RFC actually describes, with no
    # acknowledgement directive at all. Proves the gate passes on
    # r->connection->ssl rather than only on the opt-in.
    server {{
        listen 127.0.0.1:{tls_port} ssl;
        ssl_certificate {cert};
        ssl_certificate_key {key};
        root html;
    }}
"""
    conf = conf_dir / "nginx.conf"
    conf.write_text(
        f"""{load}
worker_processes 1;
daemon off;
error_log logs/error.log warn;
pid logs/nginx.pid;
events {{ }}
http {{
    access_log off;
    # $zstd_bytes_out / $zstd_ratio are log-phase variables (only valid
    # once the filter has finished writing the response); this format
    # exists so the dcz byte-accounting oracle below can read the
    # module's own count of bytes it queued downstream and cross-check
    # it against the bytes actually received over the socket.
    log_format zstd_bytes_fmt "$zstd_bytes_out $zstd_ratio";
    types {{ application/javascript js; }}
    default_type application/octet-stream;
    gzip_vary on;
    zstd on;
    zstd_min_length 64;
    zstd_dcz_dict_file {root}/dicts/app-v1.js;

    # Cleartext listener modelling "TLS terminated by a proxy in front":
    # RFC 9842 section 8 forbids dcz outside a secure context, and this
    # listener carries the explicit operator acknowledgement that the
    # client-facing hop was HTTPS. Every pre-existing check in this file
    # runs here.
    server {{
        listen 127.0.0.1:{port};
        zstd_dcz_assume_secure_transport on;
        root html;
        access_log logs/zstd_bytes.log zstd_bytes_fmt;
    }}

{tls_server}
    # Cleartext with NO acknowledgement: the compiled-in default. Nothing
    # a client can send may negotiate dcz here.
    server {{
        listen 127.0.0.1:{insecure_port};
        root html;
    }}
}}
""",
        encoding="utf-8",
        newline="\n",
    )
    return conf


def fetch(port: int, headers: dict, tls: bool = False):
    """Returns (email.message.Message, body). The Message preserves
    repeated header lines — the module legitimately emits two Vary
    lines (Accept-Encoding via gzip_vary, Available-Dictionary its own),
    and a dict would silently keep only one of them.

    tls=True talks to the native-TLS listener. The certificate is the
    per-run self-signed one from make_selfsigned(), so verification is
    switched off deliberately: this asserts the module's view of
    r->connection->ssl, not PKI."""
    scheme = "https" if tls else "http"
    request = urllib.request.Request(
        f"{scheme}://127.0.0.1:{port}/app.js", headers=headers
    )
    context = None
    if tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(request, timeout=10, context=context) as response:
        return response.headers, response.read()


def content_encoding(headers) -> str:
    value = headers.get("Content-Encoding")
    return value.strip() if value else "identity"


def vary_values(headers) -> str:
    return ",".join(headers.get_all("Vary") or []).lower()


def read_last_log_line(path: pathlib.Path, timeout: float = 10.0) -> str:
    """Poll for the access log line the most recent request just wrote.

    $zstd_bytes_out / $zstd_ratio are log-phase variables: nginx writes
    the access_log line only after the response is fully sent, which can
    race a fast local request. Poll instead of reading once, mirroring
    test_encoding.py's validate_ratio_log.
    """
    deadline = time.time() + timeout
    line = ""
    while time.time() < deadline:
        if path.exists():
            content = path.read_text(encoding="utf-8", errors="replace")
            lines = [l for l in content.splitlines() if l.strip()]
            if lines:
                line = lines[-1]
                break
        time.sleep(0.05)
    return line


def decode_dcz(
    zstd_bin: str, body: bytes, dict_path: pathlib.Path, work: pathlib.Path
) -> bytes:
    """Decode a full dcz body (skippable header + frame) with the
    dictionary, capped at the RFC 9842 client window guarantee so a frame
    demanding a larger window fails here instead of on real clients."""
    src = work / "response.dcz"
    dst = work / "response.out"
    src.write_bytes(body)
    subprocess.run(
        [
            zstd_bin,
            "-d",
            "-q",
            "-f",
            f"--memory={RFC_CLIENT_WINDOW}",
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
    failures: list[str] = []

    def check(name: str, condition: bool, detail: str = "") -> None:
        if condition:
            print(f"ok - {name}")
        else:
            print(f"FAIL - {name} {detail}")
            failures.append(name)

    nginx_path = pathlib.Path(args.nginx_binary)
    modules = [
        m
        for m in (
            detect_module(
                args.filter_module, nginx_path, "ngx_http_zstd_filter_module.so"
            ),
            detect_module(
                args.static_module, nginx_path, "ngx_http_zstd_static_module.so"
            ),
        )
        if m
    ]

    # Everything below must stay readable by the workers when run as
    # root (they drop to the compiled-in nginx user): a restrictive
    # inherited umask (e.g. 077) would strip group/other bits from
    # every fixture and subdir created here, 403ing the workers even
    # with the scratch root itself opened up.
    os.umask(0o022)
    with tempfile.TemporaryDirectory(prefix="zstd-dcz-") as tmp:
        # mkdtemp gives 0700: run as root, workers drop to the
        # compiled-in nginx user and cannot enter it -> 403s
        os.chmod(tmp, 0o755)
        root = pathlib.Path(tmp)
        dict_bytes, resource = build_fixtures(root, args.fixture_lines)
        tls_port = args.tls_port if args.tls_port else args.port + 1
        insecure_port = args.insecure_port if args.insecure_port else args.port + 2
        with_ssl = nginx_has_ssl(nginx_path)
        conf = write_config(root, args.port, tls_port, insecure_port, modules, with_ssl)
        dict_hash = hashlib.sha256(dict_bytes).digest()
        dict_b64 = base64.b64encode(dict_hash).decode()
        bad_b64 = base64.b64encode(b"\x01" * 32).decode()

        stderr_file = root / "nginx-stderr.log"
        with stderr_file.open("wb") as stderr_handle:
            nginx = subprocess.Popen(
                [args.nginx_binary, "-p", str(root), "-c", str(conf)],
                stdout=subprocess.DEVNULL,
                stderr=stderr_handle,
            )
        try:
            wait_for_port(args.port, stderr_file=stderr_file)
            wait_for_port(insecure_port, stderr_file=stderr_file)
            if with_ssl:
                wait_for_port(tls_port, stderr_file=stderr_file)

            # -- RFC 9842 section 8: dcz is a secure-context-only coding.
            dcz_headers = {
                "Accept-Encoding": "zstd, dcz",
                "Available-Dictionary": f":{dict_b64}:",
            }

            if with_ssl:
                tls_headers, tls_body = fetch(tls_port, dict(dcz_headers), tls=True)
                check(
                    "secure context: native TLS negotiates dcz with no opt-in",
                    content_encoding(tls_headers) == "dcz",
                    f"(got {content_encoding(tls_headers)})",
                )
                check(
                    "secure context: native-TLS dcz body carries the RFC magic",
                    tls_body[:8] == DCZ_MAGIC and tls_body[8:40] == dict_hash,
                    f"(got {tls_body[:8].hex()})",
                )
            else:
                # Loud and named, not silent: the sanitizer and valgrind
                # builds have no ngx_http_ssl_module, so the native-TLS
                # leg cannot run there. Everything below still gates --
                # the fail-closed default and the spoof cases are the
                # security-relevant assertions and need no TLS.
                print(
                    "  native-TLS checks skipped (nginx -V has no "
                    "--with-http_ssl_module: this binary cannot parse "
                    "`listen ... ssl`); cleartext fail-closed and spoof "
                    "checks below still run"
                )

            insecure_headers, insecure_body = fetch(insecure_port, dict(dcz_headers))
            check(
                "secure context: plain HTTP falls back to zstd "
                "(compiled-in default, no directive)",
                content_encoding(insecure_headers) == "zstd",
                f"(got {content_encoding(insecure_headers)})",
            )
            insecure_src = root / "insecure-fallback.zst"
            insecure_src.write_bytes(insecure_body)
            # check=False on purpose: if the gate regresses, this body is
            # a dcz frame and the dictionary-less decode EXITS NON-ZERO.
            # With check=True that regression surfaces as a traceback
            # that skips every remaining assertion instead of as a
            # readable FAIL line.
            insecure_decode = subprocess.run(
                [args.zstd_bin, "-d", "-q", "-c", str(insecure_src)],
                check=False,
                capture_output=True,
            )
            check(
                "secure context: the plain-HTTP fallback is still decodable "
                "without the dictionary",
                insecure_decode.returncode == 0 and insecure_decode.stdout == resource,
                f"(rc={insecure_decode.returncode}, "
                f"{len(insecure_decode.stdout)} bytes)",
            )

            # An untrusted client-supplied scheme signal must not
            # re-enable dcz: X-Forwarded-Proto is settable by anyone who
            # can reach the listener, so the module never consults it.
            for spoof in (
                {"X-Forwarded-Proto": "https"},
                {"Forwarded": "proto=https"},
                {"X-Forwarded-Ssl": "on"},
                {"Front-End-Https": "on"},
            ):
                spoof_headers, _ = fetch(insecure_port, {**dcz_headers, **spoof})
                name = next(iter(spoof))
                check(
                    f"secure context: spoofed {name} does not enable dcz",
                    content_encoding(spoof_headers) == "zstd",
                    f"(got {content_encoding(spoof_headers)})",
                )

            # -- plain zstd client: baseline and cache-key contract
            headers, plain_body = fetch(args.port, {"Accept-Encoding": "zstd"})
            check(
                "plain client negotiates zstd",
                content_encoding(headers) == "zstd",
                f"(got {content_encoding(headers)})",
            )
            check(
                "plain variant varies on Available-Dictionary",
                "available-dictionary" in vary_values(headers),
                f"(vary: {vary_values(headers)!r})",
            )
            check(
                "plain variant varies on Accept-Encoding",
                "accept-encoding" in vary_values(headers),
                f"(vary: {vary_values(headers)!r})",
            )
            check(
                # Sec-Fetch-Site selects the representation (dcz is
                # refused cross-site), so a shared cache must key on it
                # or it serves one origin's variant to the other.
                "plain variant varies on Sec-Fetch-Site",
                "sec-fetch-site" in vary_values(headers),
                f"(vary: {vary_values(headers)!r})",
            )

            # -- the dcz happy path
            headers, dcz_body = fetch(
                args.port,
                {
                    "Accept-Encoding": "zstd, dcz",
                    "Available-Dictionary": f":{dict_b64}:",
                },
            )
            check(
                "dictionary client negotiates dcz",
                content_encoding(headers) == "dcz",
                f"(got {content_encoding(headers)})",
            )
            check(
                "dcz variant varies on Available-Dictionary",
                "available-dictionary" in vary_values(headers),
                f"(vary: {vary_values(headers)!r})",
            )
            check(
                "dcz variant varies on Sec-Fetch-Site",
                "sec-fetch-site" in vary_values(headers),
                f"(vary: {vary_values(headers)!r})",
            )
            check(
                "dcz body starts with the RFC 9842 magic",
                dcz_body[:8] == DCZ_MAGIC,
                f"(got {dcz_body[:8].hex()})",
            )
            check(
                "dcz header embeds the dictionary SHA-256",
                dcz_body[8:40] == dict_hash,
            )

            decoded = decode_dcz(
                args.zstd_bin, dcz_body, root / "dicts" / "app-v1.js", root
            )
            check(
                "dcz body decodes byte-exact with the dictionary "
                "within the 8 MB client window",
                decoded == resource,
                f"(decoded {len(decoded)} bytes, want {len(resource)})",
            )
            check(
                "dictionary actually engaged (dcz smaller than plain zstd)",
                len(dcz_body) < len(plain_body),
                f"(dcz {len(dcz_body)} vs zstd {len(plain_body)})",
            )

            # -- $zstd_bytes_out / $zstd_ratio byte-accounting oracle.
            #
            # Regression for the 40-byte dcz prefix being counted twice:
            # ngx_http_zstd_filter_get_buf() advances out_buf->last past
            # the 40-byte skippable-frame prefix AND used to separately
            # add 40 to ctx->bytes_out, while the emit path in
            # ngx_http_zstd_filter_compress() already counts the whole
            # buffer (prefix included) via ngx_buf_size(). Ground truth
            # is len(dcz_body): the exact bytes this request put on the
            # wire, already captured above. $zstd_bytes_out must equal it
            # exactly -- not "close", not "within 40" -- and $zstd_ratio
            # (bytes_in*1000/bytes_out, truncated to 3 decimals) must be
            # derivable from that same bytes_out.
            bytes_log_line = read_last_log_line(root / "logs" / "zstd_bytes.log")
            check(
                "$zstd_bytes_out / $zstd_ratio access_log line was written",
                bool(bytes_log_line),
                f"(zstd_bytes.log: {bytes_log_line!r})",
            )
            if bytes_log_line:
                logged_bytes_out_str, logged_ratio_str = bytes_log_line.split(" ", 1)
                logged_bytes_out = int(logged_bytes_out_str)
                check(
                    "$zstd_bytes_out equals the actual dcz response byte "
                    "length (prefix counted exactly once)",
                    logged_bytes_out == len(dcz_body),
                    f"(zstd_bytes_out={logged_bytes_out}, wire body={len(dcz_body)})",
                )

                # Ground truth is len(dcz_body), NOT logged_bytes_out: the
                # ratio must match the ACTUAL wire bytes. Deriving the
                # expectation from logged_bytes_out instead would make
                # this check vacuous under the exact bug this test guards
                # against (bytes_out inflated by 40 would inflate the
                # expectation the same way and the two would always
                # agree, however wrong bytes_out is).
                bytes_in = len(resource)
                scaled = bytes_in * 1000 // len(dcz_body)
                expected_ratio = f"{scaled // 1000}.{scaled % 1000:03d}"
                check(
                    "$zstd_ratio matches bytes_in*1000/bytes_out computed "
                    "from the actual wire byte count",
                    logged_ratio_str == expected_ratio,
                    f"(logged {logged_ratio_str!r}, expected {expected_ratio!r})",
                )

            # -- content checksum (defence in depth): the inner zstd frame
            # starts right after the 40-byte dcz header, so byte 44 is its
            # Frame_Header_Descriptor; Content_Checksum_flag is bit 2.
            fhd = dcz_body[44] if len(dcz_body) > 44 else None
            check(
                "dcz frame declares a content checksum (FHD bit 2)",
                fhd is not None and (fhd & 0x04) != 0,
                f"(FHD {fhd:#04x})" if fhd is not None else "(body too short)",
            )

            # The property the checksum exists for: decoding against a
            # WRONG dictionary of the same size structurally succeeds and
            # yields wrong bytes (raw-prefix references stay in range and
            # nothing else in the frame ties the output to the content).
            # With the checksum the decoder must reject it loudly instead
            # of handing wrong content to the caller.
            dict_path = root / "dicts" / "app-v1.js"
            wrong_dict = root / "wrong-same-size.js"
            wrong_dict.write_bytes(b"Z" * dict_path.stat().st_size)
            wrong_src = root / "response-wrongdict.dcz"
            wrong_src.write_bytes(dcz_body)
            wrong_out = root / "response-wrongdict.out"
            wrong_rc = subprocess.run(
                [
                    args.zstd_bin,
                    "-d",
                    "-q",
                    "-f",
                    f"--memory={RFC_CLIENT_WINDOW}",
                    "-D",
                    str(wrong_dict),
                    "-o",
                    str(wrong_out),
                    str(wrong_src),
                ],
                capture_output=True,
                check=False,
            )
            if wrong_rc.returncode == 0:
                wrong_len = len(wrong_out.read_bytes()) if wrong_out.exists() else 0
                wrong_detail = f"(rc=0, {wrong_len} bytes of wrong content accepted)"
            else:
                wrong_detail = ""
            check(
                "wrong same-size dictionary fails the decode "
                "(checksum turns silent corruption into a loud error)",
                wrong_rc.returncode != 0,
                wrong_detail,
            )

            # -- every gate miss must fall back to zstd, never break
            fallback_cases = [
                (
                    "unknown dictionary hash",
                    {
                        "Accept-Encoding": "zstd, dcz",
                        "Available-Dictionary": f":{bad_b64}:",
                    },
                ),
                (
                    "no dcz token in Accept-Encoding",
                    {
                        "Accept-Encoding": "zstd",
                        "Available-Dictionary": f":{dict_b64}:",
                    },
                ),
                (
                    "explicit dcz;q=0 refusal",
                    {
                        "Accept-Encoding": "zstd, dcz;q=0",
                        "Available-Dictionary": f":{dict_b64}:",
                    },
                ),
                (
                    "wildcard does not enable dcz",
                    {
                        "Accept-Encoding": "zstd, *",
                        "Available-Dictionary": f":{dict_b64}:",
                    },
                ),
                (
                    "cross-site request refused",
                    {
                        "Accept-Encoding": "zstd, dcz",
                        "Available-Dictionary": f":{dict_b64}:",
                        "Sec-Fetch-Site": "cross-site",
                    },
                ),
                (
                    "malformed Available-Dictionary",
                    {
                        "Accept-Encoding": "zstd, dcz",
                        "Available-Dictionary": "junk",
                    },
                ),
            ]
            for name, case_headers in fallback_cases:
                headers, _body = fetch(args.port, case_headers)
                check(
                    f"fallback: {name} -> zstd",
                    content_encoding(headers) == "zstd",
                    f"(got {content_encoding(headers)})",
                )

            # zstd fallbacks must still decode without any dictionary
            src = root / "plain.zst"
            src.write_bytes(plain_body)
            plain_decoded = subprocess.run(
                [args.zstd_bin, "-d", "-q", "-c", str(src)],
                check=True,
                capture_output=True,
            ).stdout
            check(
                "plain zstd variant decodes without the dictionary",
                plain_decoded == resource,
            )

        finally:
            nginx.terminate()
            try:
                # 30s, not 10: gcov-instrumented nginx flushing .gcda
                # at exit on a loaded runner can outlive a tight reap
                # budget; teardown runs after the verdict, so patience
                # costs nothing when healthy.
                nginx.wait(timeout=30)
            except subprocess.TimeoutExpired:
                nginx.kill()
                nginx.wait(timeout=30)

    if failures:
        print(f"FAILED: {len(failures)} dcz check(s): {', '.join(failures)}")
        return 1

    print("OK: verified RFC 9842 dcz negotiation, framing, and roundtrip")
    return 0


if __name__ == "__main__":
    sys.exit(main())
