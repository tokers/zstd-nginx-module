#!/usr/bin/env python3
import importlib.util
import pathlib
import tempfile
import unittest

MODULE_PATH = pathlib.Path(__file__).with_name("test_encoding.py")
SPEC = importlib.util.spec_from_file_location("test_encoding", MODULE_PATH)
test_encoding = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(test_encoding)


class DetectModulePathTests(unittest.TestCase):
    def test_explicit_path_wins(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            nginx_binary = root / "nginx"
            explicit_module = root / "custom.so"
            sibling_module = root / "ngx_http_zstd_filter_module.so"
            nginx_binary.write_text("")
            explicit_module.write_text("")
            sibling_module.write_text("")

            resolved = test_encoding.detect_module_path(
                str(explicit_module),
                nginx_binary,
                sibling_module.name,
            )

            self.assertEqual(resolved, explicit_module)

    def test_detects_sibling_module(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            nginx_binary = root / "nginx"
            sibling_module = root / "ngx_http_zstd_filter_module.so"
            nginx_binary.write_text("")
            sibling_module.write_text("")

            resolved = test_encoding.detect_module_path(
                None,
                nginx_binary,
                sibling_module.name,
            )

            self.assertEqual(resolved, sibling_module)

    def test_returns_none_when_module_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            nginx_binary = root / "nginx"
            nginx_binary.write_text("")

            resolved = test_encoding.detect_module_path(
                None,
                nginx_binary,
                "ngx_http_zstd_filter_module.so",
            )

            self.assertIsNone(resolved)


class WriteConfigTests(unittest.TestCase):
    def test_writes_load_module_directives_before_worker_processes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            conf_path = root / "nginx.conf"
            html_dir = root / "html"
            html_dir.mkdir()
            filter_module = root / "ngx_http_zstd_filter_module.so"
            static_module = root / "ngx_http_zstd_static_module.so"

            test_encoding.write_config(
                conf_path,
                html_dir,
                18080,
                18081,
                "on",
                [filter_module, static_module],
            )

            config = conf_path.read_text(encoding="utf-8")
            first_lines = config.splitlines()[:3]

            self.assertEqual(
                first_lines,
                [
                    f"load_module {filter_module};",
                    f"load_module {static_module};",
                    "worker_processes  1;",
                ],
            )
            self.assertIn("gzip_vary on;", config)
            self.assertIn("zstd on;", config)

    def test_omits_load_module_directives_when_no_modules_provided(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            conf_path = root / "nginx.conf"
            html_dir = root / "html"
            html_dir.mkdir()

            test_encoding.write_config(conf_path, html_dir, 18080, 18081, "off", [])

            config = conf_path.read_text(encoding="utf-8")
            self.assertTrue(config.startswith("worker_processes  1;\n"))
            self.assertNotIn("load_module", config)
            self.assertIn("gzip_vary off;", config)


if __name__ == "__main__":
    unittest.main()
