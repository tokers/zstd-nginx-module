#!/usr/bin/env python3
"""Config-load table for ``zstd_bypass_vary`` — grind-g6-nits owed control.

``ngx_http_zstd_set_bypass_vary()`` (src/ngx_http_zstd_filter_module.c)
hand-validates its single argument as an RFC 9110 field-name token before
storing it: reject ``,``/``;``/``"`` and a bare solitary ``*`` outright,
accept any other tchar including a non-solitary ``*``, and let normal
nginx merge semantics (http-level value overridden by a location-level
one) apply on top. None of that validation is expressible as a Test::Nginx
``--- must_die`` table — ``ci/t/02-conf-warn.t`` covers the *emitted
warning* half of this directive, not the *acceptance/rejection* table,
and no existing file has a rejection-table for this directive.

The policy under test
----------------------
  * a valid mixed-case token loads AND is retained VERBATIM (exact
    spelling, not lower/upper-cased) -- proven via the config-load
    warning ci/t/02-conf-warn.t already asserts fires only when
    zstd_bypass_vary is set without zstd_bypass, which echoes nothing;
    so this test instead asserts acceptance (rc==0) and, using a second
    location, that the RETAINED value round-trips into the emitted Vary
    response header exactly as typed;
  * ``,`` ``;`` ``"`` and a bare solitary ``*`` are each REJECTED, with
    nginx -t exiting non-zero and naming the emerg reason;
  * a non-solitary ``*`` inside a token (``X-Foo*Bar``) is ACCEPTED;
  * an http-level value is overridden by a location-level one (the
    location's Vary reflects the location value, not the http one).

Why config_test on nginx -t alone is not enough for arms 1 and 8: a
config-load PASS does not prove the value was stored correctly (a
setter that silently truncated or normalized the token would still
return NGX_CONF_OK). Those two arms therefore additionally start nginx
and curl a real response, asserting the Vary header's exact bytes.
"""

import argparse
import pathlib
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request


def parse_args():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--nginx-binary", required=True)
    p.add_argument("--filter-module")
    p.add_argument("--port", type=int, default=18170)
    return p.parse_args()


def detect_module(explicit, nginx: pathlib.Path):
    if explicit:
        return pathlib.Path(explicit)
    sib = nginx.parent / "ngx_http_zstd_filter_module.so"
    return sib if sib.exists() else None


def write_conf(root, module, port, http_directive, loc_directive):
    load = f"load_module {module};\n" if module else ""
    (root / "conf" / "nginx.conf").write_text(
        f"{load}"
        "events {}\n"
        "http {\n"
        f"    {http_directive}\n"
        "    server {\n"
        f"        listen 127.0.0.1:{port};\n"
        "        zstd on;\n"
        "        zstd_min_length 1;\n"
        "        zstd_bypass $http_x_no_compression;\n"
        "        default_type text/plain;\n"
        "        location /a {\n"
        f"            {loc_directive}\n"
        '            return 200 "hello world padding padding padding\\n";\n'
        "        }\n"
        "    }\n"
        "}\n"
    )


def config_test(nginx, module, port, http_directive="", loc_directive=""):
    """Run ``nginx -t``; return (returncode, combined output)."""
    with tempfile.TemporaryDirectory() as td:
        root = pathlib.Path(td)
        (root / "conf").mkdir()
        (root / "logs").mkdir()
        write_conf(root, module, port, http_directive, loc_directive)

        proc = subprocess.run(
            [str(nginx), "-p", str(root), "-c", "conf/nginx.conf", "-t"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        return proc.returncode, proc.stdout + proc.stderr


def free_port(start):
    port = start
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
        port += 1


def get_vary_header(nginx, module, port, http_directive, loc_directive):
    """Start nginx, GET /a, return the Vary header value (or None)."""
    with tempfile.TemporaryDirectory() as td:
        root = pathlib.Path(td)
        (root / "conf").mkdir()
        (root / "logs").mkdir()
        write_conf(root, module, port, http_directive, loc_directive)

        proc = subprocess.Popen(
            [str(nginx), "-p", str(root), "-c", "conf/nginx.conf", "-g", "daemon off;"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            deadline = time.time() + 5
            connected = False
            while time.time() < deadline:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    if s.connect_ex(("127.0.0.1", port)) == 0:
                        connected = True
                        break
                time.sleep(0.1)
            if not connected:
                return None, "nginx did not start listening"

            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/a",
                headers={"Accept-Encoding": "zstd", "X-No-Compression": "1"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.headers.get("Vary"), None
        except Exception as e:  # noqa: BLE001 - report, don't hide
            return None, str(e)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)


def main() -> int:
    args = parse_args()
    nginx = pathlib.Path(args.nginx_binary).resolve()
    if not nginx.exists():
        print(f"FAIL: nginx binary not found: {nginx}", file=sys.stderr)
        return 1

    module = detect_module(args.filter_module, nginx)
    if module is not None:
        module = module.resolve()
        if not module.exists():
            print(f"FAIL: filter module not found: {module}", file=sys.stderr)
            return 1

    failures = []
    port = args.port

    # --- Rejection arms: nginx -t must fail, naming the reason. ---
    reject_cases = [
        ("comma", "zstd_bypass_vary X-Foo,Bar;", "comma or semicolon"),
        # nginx's own tokenizer treats an unquoted ';' as the directive
        # terminator, so the literal byte can only reach the setter's
        # argument when quoted in the conf syntax itself.
        ("semicolon", 'zstd_bypass_vary "X-Foo;Bar";', "comma or semicolon"),
        # Likewise an unquoted '"' would be nginx's own quoting; escape it
        # inside a quoted string so a literal '"' byte reaches the setter.
        ("quote", 'zstd_bypass_vary "X-\\"Foo";', "quoted string"),
        ("bare solitary wildcard", "zstd_bypass_vary *;", "bare wildcard"),
    ]
    for name, directive, want_reason in reject_cases:
        port = free_port(port + 1)
        rc, out = config_test(nginx, module, port, loc_directive=directive)
        if rc == 0:
            failures.append(
                f"{name}: expected nginx -t to be REFUSED but it exited 0; "
                f"output: {out.strip()!r}"
            )
        elif want_reason not in out:
            failures.append(
                f"{name}: nginx -t was refused (rc={rc}) but the emerg "
                f"message did not name the reason ({want_reason!r}); "
                f"output: {out.strip()!r}"
            )
        print(
            f"  reject/{name:<24} exit {rc} (want non-zero), reason "
            f"{'yes' if want_reason in out else 'no'}"
        )

    # --- Acceptance arm: non-solitary '*' inside a token. ---
    port = free_port(port + 1)
    rc, out = config_test(
        nginx, module, port, loc_directive="zstd_bypass_vary X-Foo*Bar;"
    )
    if rc != 0:
        failures.append(
            f"non-solitary wildcard token: expected nginx -t to PASS but "
            f"it exited {rc}; output: {out.strip()!r}"
        )
    print(f"  accept/non-solitary-wildcard   exit {rc} (want 0)")

    # --- Retention arm: mixed-case token loads and is echoed verbatim. ---
    port = free_port(port + 1)
    token = "X-My-Header"
    vary, err = get_vary_header(nginx, module, port, "", f"zstd_bypass_vary {token};")
    if err is not None:
        failures.append(f"retention (mixed-case token): {err}")
    elif vary != token:
        failures.append(
            f"retention (mixed-case token): Vary header is {vary!r}, "
            f"want exact spelling {token!r} (verifies the stored value "
            f"is not case-folded, truncated or otherwise normalized)"
        )
    print(f"  retain/mixed-case-token         Vary={vary!r} (want {token!r})")

    # --- Override arm: http-level value overridden by location-level. ---
    port = free_port(port + 1)
    vary, err = get_vary_header(
        nginx,
        module,
        port,
        http_directive="zstd_bypass_vary X-Http-Level;",
        loc_directive="zstd_bypass_vary X-Loc-Level;",
    )
    if err is not None:
        failures.append(f"override (http overridden by location): {err}")
    elif vary != "X-Loc-Level":
        failures.append(
            f"override (http overridden by location): Vary header is "
            f"{vary!r}, want the LOCATION value 'X-Loc-Level' (the "
            f"http-level 'X-Http-Level' must not win)"
        )
    print(f"  override/loc-wins-over-http     Vary={vary!r} (want 'X-Loc-Level')")

    if failures:
        print("\nFAIL: zstd_bypass_vary config-load policy", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1

    print(
        "\nOK: zstd_bypass_vary config-load policy "
        f"({len(reject_cases) + 3}/{len(reject_cases) + 3} arms)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
