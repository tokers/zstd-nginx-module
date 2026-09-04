#!/usr/bin/env python3
import importlib.util
import pathlib
import tempfile
import unittest

MODULE_PATH = pathlib.Path(__file__).with_name("test_package_artifact.py")
SPEC = importlib.util.spec_from_file_location("test_package_artifact", MODULE_PATH)
test_package_artifact = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(test_package_artifact)


class DetectPackageLayoutTests(unittest.TestCase):
    def create_layout(self, root: pathlib.Path, flavor: str) -> pathlib.Path:
        modules_dir = root / "usr" / "lib" / flavor / "modules"
        modules_dir.mkdir(parents=True)
        (modules_dir / "ngx_http_zstd_filter_module.so").write_text("")
        (modules_dir / "ngx_http_zstd_static_module.so").write_text("")

        snippet = (
            root / "usr" / "share" / flavor / "modules-available" / "mod-http-zstd.conf"
        )
        snippet.parent.mkdir(parents=True)
        snippet.write_text(
            # FLY002 suppressed below: a list of load_module lines reads better than an
            # f-string with embedded newlines, and adding a third is one line.
            "\n".join(  # noqa: FLY002
                [
                    "load_module modules/ngx_http_zstd_filter_module.so;",
                    "load_module modules/ngx_http_zstd_static_module.so;",
                ]
            ),
            encoding="utf-8",
        )
        return snippet

    def test_detects_angie_layout(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            snippet = self.create_layout(root, "angie")

            layout = test_package_artifact.detect_package_layout(root)

            self.assertEqual(layout.flavor, "angie")
            self.assertEqual(layout.load_snippet, snippet)
            self.assertEqual(layout.modules_dir, root / "usr/lib/angie/modules")

    def test_detects_nginx_layout(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            snippet = self.create_layout(root, "nginx")

            layout = test_package_artifact.detect_package_layout(root)

            self.assertEqual(layout.flavor, "nginx")
            self.assertEqual(layout.load_snippet, snippet)
            self.assertEqual(layout.modules_dir, root / "usr/lib/nginx/modules")

    def test_raises_when_layout_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)

            with self.assertRaises(FileNotFoundError):
                test_package_artifact.detect_package_layout(root)


class VerifyLoadSnippetTests(unittest.TestCase):
    def test_accepts_snippet_with_both_modules(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            modules_dir = root / "usr/lib/angie/modules"
            modules_dir.mkdir(parents=True)
            filter_module = modules_dir / "ngx_http_zstd_filter_module.so"
            static_module = modules_dir / "ngx_http_zstd_static_module.so"
            filter_module.write_text("")
            static_module.write_text("")
            snippet = root / "usr/share/angie/modules-available/mod-http-zstd.conf"
            snippet.parent.mkdir(parents=True)
            snippet.write_text(
                "load_module modules/ngx_http_zstd_filter_module.so;\n"
                "load_module modules/ngx_http_zstd_static_module.so;\n",
                encoding="utf-8",
            )
            layout = test_package_artifact.PackageLayout(
                package_root=root,
                flavor="angie",
                modules_dir=modules_dir,
                filter_module=filter_module,
                static_module=static_module,
                load_snippet=snippet,
            )

            test_package_artifact.verify_load_snippet(layout)

    def test_rejects_snippet_missing_module(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            modules_dir = root / "usr/lib/nginx/modules"
            modules_dir.mkdir(parents=True)
            filter_module = modules_dir / "ngx_http_zstd_filter_module.so"
            static_module = modules_dir / "ngx_http_zstd_static_module.so"
            filter_module.write_text("")
            static_module.write_text("")
            snippet = root / "usr/share/nginx/modules-available/mod-http-zstd.conf"
            snippet.parent.mkdir(parents=True)
            snippet.write_text(
                "load_module modules/ngx_http_zstd_filter_module.so;\n",
                encoding="utf-8",
            )
            layout = test_package_artifact.PackageLayout(
                package_root=root,
                flavor="nginx",
                modules_dir=modules_dir,
                filter_module=filter_module,
                static_module=static_module,
                load_snippet=snippet,
            )

            with self.assertRaises(RuntimeError):
                test_package_artifact.verify_load_snippet(layout)


if __name__ == "__main__":
    unittest.main()
