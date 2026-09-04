#!/usr/bin/env python3
import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import unittest
from typing import Any
from unittest import mock

TOOLS_DIR = pathlib.Path(__file__).resolve().parent


def load_tool(name: str) -> Any:
    path = TOOLS_DIR / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load test module {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ab_bench = load_tool("ab_bench")
perf_recipe = load_tool("perf_stat_recipe")


class DczWorkloadTests(unittest.TestCase):
    def test_nginx_starts_in_its_own_process_group(self) -> None:
        arm = ab_bench.Arm("baseline", pathlib.Path("/nginx"))
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            mock.patch("builtins.open", mock.mock_open()),
            mock.patch.object(ab_bench.subprocess, "Popen") as popen,
        ):
            ab_bench.start_nginx(
                arm, pathlib.Path("nginx.conf"), pathlib.Path(temp_dir)
            )

        self.assertTrue(popen.call_args.kwargs["start_new_session"])

    def test_hit_configures_requested_dictionaries_and_canonical_headers(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            workload = ab_bench.prepare_workload(root, "dcz", 4, "hit")

            self.assertEqual(workload.config.count("zstd_dcz_dict_file "), 4)
            self.assertIn("zstd_dcz_assume_secure_transport on;", workload.config)
            self.assertNotIn("zstd_dcz_dict_trust_hashes", workload.config)
            self.assertEqual(dict(workload.headers)["Accept-Encoding"], "zstd, dcz")
            self.assertEqual(dict(workload.headers)["Sec-Fetch-Site"], "same-origin")
            self.assertRegex(
                dict(workload.headers)["Available-Dictionary"],
                r"^:[A-Za-z0-9+/]{43}=:$",
            )
            self.assertEqual(workload.expected_encoding, "dcz")
            self.assertEqual(len(list((root / "dictionaries").iterdir())), 4)

    def test_miss_advertises_no_configured_dictionary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            workload = ab_bench.prepare_workload(root, "dcz", 16, "miss")
            advertised = dict(workload.headers)["Available-Dictionary"]
            configured = {
                ab_bench._available_dictionary(path.read_bytes())
                for path in (root / "dictionaries").iterdir()
            }

            self.assertNotIn(advertised, configured)
            self.assertEqual(workload.expected_encoding, "zstd")
            self.assertEqual(len(configured), 16)

    def test_default_zstd_workload_stays_dictionary_free(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workload = ab_bench.prepare_workload(
                pathlib.Path(temp_dir), "zstd", 1, "hit"
            )

            self.assertEqual(workload.headers, (("Accept-Encoding", "zstd"),))
            self.assertEqual(workload.config, "")
            self.assertEqual(workload.expected_encoding, "zstd")

    def test_rejects_unsupported_dictionary_count(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            self.assertRaisesRegex(ValueError, "must be one of"),
        ):
            ab_bench.prepare_workload(pathlib.Path(temp_dir), "dcz", 2, "hit")

    def test_preflight_requires_the_expected_content_encoding(self) -> None:
        response = mock.Mock(status=200)
        response.getheader.return_value = "zstd"
        connection = mock.Mock()
        connection.getresponse.return_value = response
        workload = ab_bench.Workload(
            mode="dcz",
            headers=(("Accept-Encoding", "zstd, dcz"),),
            expected_encoding="dcz",
        )

        with (
            mock.patch.object(
                ab_bench.http.client, "HTTPConnection", return_value=connection
            ),
            self.assertRaisesRegex(RuntimeError, "Content-Encoding='zstd'"),
        ):
            ab_bench.verify_workload(18400, workload)

        connection.request.assert_called_once_with(
            "GET", "/8kb", headers={"Accept-Encoding": "zstd, dcz"}
        )
        response.read.assert_called_once_with()

    def test_readiness_failure_reaps_the_spawned_nginx_process(self) -> None:
        process = mock.Mock()
        process.pid = 4321
        process.wait.side_effect = [
            ab_bench.subprocess.TimeoutExpired(["nginx"], 10),
            0,
        ]
        backend = mock.Mock()
        workload = ab_bench.Workload(
            mode="zstd",
            headers=(("Accept-Encoding", "zstd"),),
            expected_encoding="zstd",
        )
        arm = ab_bench.Arm("baseline", pathlib.Path("/nginx"))

        with (
            mock.patch.object(ab_bench, "PacedBackend", return_value=backend),
            mock.patch.object(ab_bench, "prepare_workload", return_value=workload),
            mock.patch.object(
                ab_bench, "write_conf", return_value=pathlib.Path("/nginx.conf")
            ),
            mock.patch.object(ab_bench, "start_nginx", return_value=process),
            mock.patch.object(
                ab_bench,
                "require_own_nginx_ready",
                side_effect=RuntimeError("readiness failed"),
            ),
            mock.patch.object(ab_bench.os, "killpg") as kill_group,
            self.assertRaisesRegex(RuntimeError, "readiness failed"),
        ):
            ab_bench.run_release_pass(
                [arm], [1], 1, "1s", 1, 18400, 6, "zstd", 1, "hit"
            )

        process.terminate.assert_called_once_with()
        self.assertEqual(
            process.wait.call_args_list,
            [mock.call(timeout=10), mock.call(timeout=5)],
        )
        kill_group.assert_called_once_with(4321, ab_bench.signal.SIGKILL)
        backend.stop.assert_called_once_with()

    def test_nginx_group_cleanup_reaps_when_group_is_already_gone(self) -> None:
        process = mock.Mock(pid=4321)
        process.wait.side_effect = [
            ab_bench.subprocess.TimeoutExpired(["nginx"], 10),
            0,
        ]
        with mock.patch.object(ab_bench.os, "killpg", side_effect=ProcessLookupError):
            ab_bench.stop_nginx(process)

        self.assertEqual(process.wait.call_args_list[-1], mock.call(timeout=5))

    def test_perf_attaches_only_to_resolved_nginx_workers(self) -> None:
        process = mock.Mock()
        process.poll.return_value = None
        attachment = ab_bench.PerfAttachment(
            pathlib.Path("/result.perf"), "cpu_core/cache-misses/"
        )

        with (
            mock.patch.object(ab_bench, "nginx_worker_pids", return_value=[1234]),
            mock.patch.object(
                ab_bench.subprocess, "Popen", return_value=process
            ) as popen,
            mock.patch.object(ab_bench.time, "sleep"),
        ):
            self.assertIs(ab_bench.start_worker_perf(99, 1, attachment), process)

        command = popen.call_args.args[0]
        self.assertEqual(command[command.index("-p") + 1], "1234")
        self.assertNotIn("99", command)

    def test_perf_attachment_rejects_multiple_workers(self) -> None:
        attachment = ab_bench.PerfAttachment(
            pathlib.Path("/result.perf"), "cpu_core/cache-misses/"
        )
        with (
            mock.patch.object(ab_bench.subprocess, "Popen") as popen,
            self.assertRaisesRegex(RuntimeError, "requires --workers 1"),
        ):
            ab_bench.start_worker_perf(99, 2, attachment)

        popen.assert_not_called()

    def test_perf_stop_accepts_the_expected_sigint_exit(self) -> None:
        for returncode in (-ab_bench.signal.SIGINT, 128 + ab_bench.signal.SIGINT):
            with self.subTest(returncode=returncode):
                process = mock.Mock()
                process.poll.return_value = None
                process.wait.return_value = returncode

                ab_bench.stop_worker_perf(process)

                process.send_signal.assert_called_once_with(ab_bench.signal.SIGINT)

    def test_perf_stop_rejects_an_early_clean_exit(self) -> None:
        process = mock.Mock()
        process.poll.return_value = 0

        with self.assertRaisesRegex(RuntimeError, "exited before"):
            ab_bench.stop_worker_perf(process)

        process.send_signal.assert_not_called()


class PerfRecipeTests(unittest.TestCase):
    @staticmethod
    def _matrix_result(
        counters: Any,
        successful_requests: int,
        *,
        core_type: str = "P",
        cpu_mask: str = "0-7",
        cpu_identity: str = "vendor/model/stepping",
    ) -> dict:
        scenarios = {}
        for dictionary_count, case in perf_recipe.dcz_scenarios():
            scenarios[f"dicts-{dictionary_count}-{case}"] = {
                "dictionary_count": dictionary_count,
                "case": case,
                "measured_successful_requests": successful_requests,
                "counters": counters.to_dict(),
                "engagement": {"baseline": "dcz" if case == "hit" else "zstd"},
            }
        return {
            "schema_version": 2,
            "workload": "dcz",
            "core_type": core_type,
            "cpu_mask": cpu_mask,
            "cpu_identity": cpu_identity,
            "normalization": "measured_successful_requests",
            "scenarios": scenarios,
        }

    def test_documented_flag_first_cli_spellings_remain_supported(self) -> None:
        self.assertEqual(
            perf_recipe.normalize_cli_argv(["--nginx", "/nginx"]),
            ["measure", "--nginx", "/nginx"],
        )
        self.assertEqual(
            perf_recipe.normalize_cli_argv(["--compare", "base.json", "opt.json"]),
            ["compare", "base.json", "opt.json"],
        )
        self.assertEqual(perf_recipe.normalize_cli_argv(["--help"]), ["--help"])

    def test_matrix_contains_required_hit_and_miss_cells(self) -> None:
        self.assertEqual(
            perf_recipe.dcz_scenarios(),
            (
                (1, "hit"),
                (1, "miss"),
                (4, "hit"),
                (4, "miss"),
                (16, "hit"),
                (16, "miss"),
            ),
        )

    def test_matrix_measure_orchestrates_every_worker_only_scenario(self) -> None:
        perf_text = "\n".join(
            f"100 cpu_core/{event}/"
            for event in (
                "cache-misses",
                "cache-references",
                "instructions",
                "cycles",
            )
        )

        def fake_run(command: list[str], cpu_mask: str) -> None:
            self.assertEqual(cpu_mask, "0 1")
            count = command[command.index("--dcz-dictionaries") + 1]
            case = command[command.index("--dcz-case") + 1]
            json_path = pathlib.Path(command[command.index("--json") + 1])
            perf_path = pathlib.Path(command[command.index("--perf-stat-output") + 1])
            json_path.write_text(
                json.dumps(
                    {
                        "meta": {
                            "successful_requests": 10,
                            "perf_scope": "nginx-workers-measured-release",
                            "engagement": {
                                "baseline": "dcz" if case == "hit" else "zstd"
                            },
                        }
                    }
                ),
                encoding="utf-8",
            )
            perf_path.write_text(perf_text, encoding="utf-8")
            self.assertIn(count, {"1", "4", "16"})

        with (
            tempfile.TemporaryDirectory() as temp_dir,
            mock.patch.object(
                perf_recipe, "detect_hybrid_cores", return_value=("0 1", "2 3", 0)
            ),
            mock.patch.object(perf_recipe, "cpu_identity", return_value="test-cpu"),
            mock.patch.object(
                perf_recipe, "run_pinned_bench", side_effect=fake_run
            ) as run,
        ):
            result_path = pathlib.Path(temp_dir) / "matrix.json"
            scenarios = perf_recipe.measure_dcz_matrix(
                pathlib.Path(sys.executable), str(result_path), "P"
            )
            saved = json.loads(result_path.read_text())

        self.assertEqual(run.call_count, 6)
        self.assertEqual(
            set(scenarios),
            {f"dicts-{n}-{c}" for n, c in perf_recipe.dcz_scenarios()},
        )
        self.assertEqual(saved["normalization"], "measured_successful_requests")

    def test_matrix_identity_failure_prevents_scenario_execution(self) -> None:
        with (
            mock.patch.object(
                perf_recipe, "detect_hybrid_cores", return_value=("0 1", "2 3", 0)
            ),
            mock.patch.object(
                perf_recipe,
                "cpu_identity",
                side_effect=RuntimeError("missing CPU identity"),
            ),
            mock.patch.object(perf_recipe, "run_pinned_bench") as run,
            self.assertRaisesRegex(RuntimeError, "missing CPU identity"),
        ):
            perf_recipe.measure_dcz_matrix(pathlib.Path(sys.executable))

        run.assert_not_called()

    def test_pinned_bench_timeout_kills_the_process_group(self) -> None:
        process = mock.Mock(pid=4321)
        with (
            mock.patch.object(perf_recipe.subprocess, "Popen", return_value=process),
            mock.patch.object(
                perf_recipe,
                "wait_process_without_reaping",
                side_effect=perf_recipe.subprocess.TimeoutExpired(["taskset"], 600),
            ),
            mock.patch.object(perf_recipe, "kill_process_group") as kill_group,
            self.assertRaisesRegex(RuntimeError, "process group killed"),
        ):
            perf_recipe.run_pinned_bench(["bench"], "0 1")

        kill_group.assert_called_once_with(process)

    def test_pinned_bench_interrupt_kills_the_process_group(self) -> None:
        process = mock.Mock(pid=4321)
        with (
            mock.patch.object(perf_recipe.subprocess, "Popen", return_value=process),
            mock.patch.object(
                perf_recipe,
                "wait_process_without_reaping",
                side_effect=KeyboardInterrupt,
            ),
            mock.patch.object(perf_recipe, "kill_process_group") as kill_group,
            self.assertRaises(KeyboardInterrupt),
        ):
            perf_recipe.run_pinned_bench(["bench"], "0 1")

        kill_group.assert_called_once_with(process)

    def test_pinned_bench_nonzero_exit_kills_the_process_group(self) -> None:
        process = mock.Mock(returncode=1)
        with (
            mock.patch.object(perf_recipe.subprocess, "Popen", return_value=process),
            mock.patch.object(
                perf_recipe, "wait_process_without_reaping", return_value=False
            ),
            mock.patch.object(perf_recipe, "kill_process_group") as kill_group,
            self.assertRaisesRegex(RuntimeError, "exit code 1"),
        ):
            perf_recipe.run_pinned_bench(["bench"], "0 1")

        kill_group.assert_called_once_with(process)

    def test_failed_status_is_observed_without_reaping_the_group_leader(self) -> None:
        process = mock.Mock(pid=4321, args=["bench"])
        status = mock.Mock(si_code=perf_recipe.os.CLD_EXITED, si_status=1)
        with mock.patch.object(perf_recipe.os, "waitid", return_value=status) as waitid:
            self.assertFalse(perf_recipe.wait_process_without_reaping(process, 1))

        waitid.assert_called_once_with(
            perf_recipe.os.P_PID,
            4321,
            perf_recipe.os.WEXITED | perf_recipe.os.WNOHANG | perf_recipe.os.WNOWAIT,
        )
        process.wait.assert_not_called()

    def test_clean_status_is_observed_without_reaping_the_group_leader(self) -> None:
        process = mock.Mock(pid=4321, args=["bench"])
        status = mock.Mock(si_code=perf_recipe.os.CLD_EXITED, si_status=0)
        with mock.patch.object(perf_recipe.os, "waitid", return_value=status):
            self.assertTrue(perf_recipe.wait_process_without_reaping(process, 1))

        process.wait.assert_not_called()

    def test_pinned_bench_success_reaps_without_group_kill(self) -> None:
        process = mock.Mock(pid=4321)
        with (
            mock.patch.object(perf_recipe.subprocess, "Popen", return_value=process),
            mock.patch.object(
                perf_recipe, "wait_process_without_reaping", return_value=True
            ),
            mock.patch.object(perf_recipe, "kill_process_group") as kill_group,
        ):
            perf_recipe.run_pinned_bench(["bench"], "0 1")

        process.wait.assert_called_once_with(timeout=10)
        kill_group.assert_not_called()

    def test_dcz_command_selects_workload_and_evidence_json(self) -> None:
        command = perf_recipe.build_dcz_bench_command(
            pathlib.Path("/nginx"),
            16,
            "miss",
            pathlib.Path("/result.json"),
            pathlib.Path("/result.perf"),
            "cpu_core/cache-misses/",
        )

        self.assertEqual(
            command,
            [
                "python3",
                str(perf_recipe.TOOLS_DIR / "ab_bench.py"),
                "--arm-a",
                "/nginx:baseline",
                "--rounds",
                "1",
                "--workers",
                "1",
                "--duration",
                "5s",
                "--workload",
                "dcz",
                "--dcz-dictionaries",
                "16",
                "--dcz-case",
                "miss",
                "--json",
                "/result.json",
                "--perf-stat-output",
                "/result.perf",
                "--perf-events",
                "cpu_core/cache-misses/",
            ],
        )

    def test_successful_request_denominator_excludes_errors(self) -> None:
        result = {
            "release": {
                "baseline": {
                    "8": {
                        "8kb": [
                            {"requests": 120, "errors": 20},
                            {"requests": 80, "errors": 0},
                        ]
                    }
                }
            }
        }

        self.assertEqual(perf_recipe.successful_requests_from_bench(result), 180)

    def test_measured_request_denominator_excludes_setup_traffic(self) -> None:
        result = {
            "meta": {
                "successful_requests": 100,
                "completed_successful_requests": 141,
            }
        }

        self.assertEqual(perf_recipe.successful_requests_from_bench(result), 100)

    def test_normalization_reverses_misleading_raw_counter_delta(self) -> None:
        baseline = perf_recipe.PerfCounters(1000, 2000, 3000, 4000)
        optimized = perf_recipe.PerfCounters(1500, 3000, 4500, 6000)

        self.assertGreater(optimized.cache_misses, baseline.cache_misses)
        baseline_norm = perf_recipe.normalize_counters(baseline, 100)
        optimized_norm = perf_recipe.normalize_counters(optimized, 300)
        self.assertLess(optimized_norm["cache_misses"], baseline_norm["cache_misses"])

    def test_matrix_compare_uses_normalized_counts_and_prints_all_deltas(self) -> None:
        baseline = self._matrix_result(
            perf_recipe.PerfCounters(1000, 2000, 3000, 4000), 100
        )
        optimized = self._matrix_result(
            perf_recipe.PerfCounters(1500, 3000, 4500, 6000), 300
        )

        output = io.StringIO()
        with mock.patch("sys.stdout", output):
            perf_recipe.compare_dcz_results(baseline, optimized)

        rendered = output.getvalue()
        self.assertIn("dicts-16-miss", rendered)
        self.assertIn("miss delta", rendered)
        self.assertIn("ref delta", rendered)
        self.assertIn("insn delta", rendered)
        self.assertIn("cycle delta", rendered)
        self.assertEqual(rendered.count("-50.0%"), 24)

    def test_matrix_compare_rejects_incompatible_measurements(self) -> None:
        baseline = self._matrix_result(perf_recipe.PerfCounters(1, 2, 3, 4), 1)
        optimized = self._matrix_result(
            perf_recipe.PerfCounters(1, 2, 3, 4),
            1,
            core_type="E",
            cpu_mask="8-15",
        )

        with self.assertRaisesRegex(RuntimeError, "matching core_type"):
            perf_recipe.compare_dcz_results(baseline, optimized)

        optimized = self._matrix_result(
            perf_recipe.PerfCounters(1, 2, 3, 4),
            1,
            cpu_identity="different-cpu",
        )
        with self.assertRaisesRegex(RuntimeError, "matching cpu_identity"):
            perf_recipe.compare_dcz_results(baseline, optimized)

    def test_matrix_compare_rejects_missing_identity_and_wrong_engagement(self) -> None:
        baseline = self._matrix_result(perf_recipe.PerfCounters(1, 2, 3, 4), 1)
        optimized = self._matrix_result(perf_recipe.PerfCounters(1, 2, 3, 4), 1)
        del baseline["core_type"]
        del optimized["core_type"]
        with self.assertRaisesRegex(RuntimeError, "core_type P or E"):
            perf_recipe.compare_dcz_results(baseline, optimized)

        baseline = self._matrix_result(perf_recipe.PerfCounters(1, 2, 3, 4), 1)
        optimized = self._matrix_result(perf_recipe.PerfCounters(1, 2, 3, 4), 1)
        del baseline["cpu_identity"]
        del optimized["cpu_identity"]
        with self.assertRaisesRegex(RuntimeError, "non-empty cpu_identity"):
            perf_recipe.compare_dcz_results(baseline, optimized)

        baseline = self._matrix_result(perf_recipe.PerfCounters(1, 2, 3, 4), 1)
        optimized = self._matrix_result(perf_recipe.PerfCounters(1, 2, 3, 4), 1)
        optimized["scenarios"]["dicts-16-hit"]["engagement"] = {"baseline": "zstd"}
        with self.assertRaisesRegex(RuntimeError, "requires dcz engagement"):
            perf_recipe.compare_dcz_results(baseline, optimized)

    def test_normalization_rejects_zero_successful_requests(self) -> None:
        counters = perf_recipe.PerfCounters(1, 2, 3, 4)
        with self.assertRaisesRegex(RuntimeError, "without successful requests"):
            perf_recipe.normalize_counters(counters, 0)


if __name__ == "__main__":
    unittest.main()
