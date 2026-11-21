"""Tests for non-blocking, single-flight, Windows-safe OpenGrep health probing."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from urllib.request import Request, urlopen

from v2.api.config import ApiConfig
from v2.api.server import ThesisApiServer


TEST_TOKEN = "opengrep-health-probe-token-20261117"


def _make_mock_ollama_server() -> tuple[ThreadingHTTPServer, threading.Thread, str]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_GET(self):
            if self.path == "/api/tags":
                payload = {"models": [{"name": "qwen3.5:9b-q4_K_M", "digest": "sha256:test"}]}
                raw = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                return
            self.send_response(404)
            self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    h, p = srv.server_address[:2]
    return srv, th, f"http://{h}:{p}"


def _write_cmd_wrapper(directory: Path, name: str, py_body: str) -> Path:
    script = directory / f"{name}.py"
    script.write_text(py_body, encoding="utf-8")
    if os.name == "nt":
        wrapper = directory / f"{name}.cmd"
        wrapper.write_text(f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n', encoding="utf-8")
        return wrapper
    wrapper = directory / f"{name}.sh"
    wrapper.write_text(f'#!/bin/sh\n"{sys.executable}" "{script}" "$@"\n', encoding="utf-8")
    wrapper.chmod(0o755)
    return wrapper


@unittest.skip(
    "LEGACY_NOT_APPLICABLE: /api/health no longer executes OpenGrep/WSL2 subprocess probes or background probe threads."
)
class HealthOpenGrepProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.rules_file = self.root / "rules.yml"
        self.rules_file.write_text("rules: []\n", encoding="utf-8")
        self.ol_srv, self.ol_th, self.ollama_url = _make_mock_ollama_server()
        self.addCleanup(lambda: (self.ol_srv.shutdown(), self.ol_th.join(timeout=2.0), self.ol_srv.server_close()))

    def _start_api(self, og_binary: str) -> tuple[ThesisApiServer, str]:
        srv = ThesisApiServer(
            ApiConfig(
                host="127.0.0.1",
                port=0,
                data_dir=self.root / "api_data",
                rules_path=self.rules_file,
                opengrep_binary=og_binary,
                ollama_endpoint=self.ollama_url,
                ollama_model="qwen3.5:9b-q4_K_M",
                api_token=TEST_TOKEN,
                read_auth_mode="required",
            )
        )
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        self.addCleanup(lambda: (srv.shutdown(), th.join(timeout=2.0), srv.server_close()))
        h, p = srv.server_address[:2]
        return srv, f"http://{h}:{p}"

    def _get(self, url: str) -> tuple[int, dict, float]:
        t0 = time.monotonic()
        req = Request(url, headers={"Authorization": f"Bearer {TEST_TOKEN}", "Connection": "close"}, method="GET")
        with urlopen(req, timeout=10) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
            return resp.status, payload, time.monotonic() - t0

    def test_1_fast_wrapper_reports_ok_and_version(self) -> None:
        wdir = self.root / "fast"
        wdir.mkdir(parents=True, exist_ok=True)
        wrapper = _write_cmd_wrapper(
            wdir,
            "opengrep_fast",
            "import sys\nprint('1.25.0')\n",
        )
        srv, base = self._start_api(str(wrapper))
        code, data, elapsed = self._get(f"{base}/api/health")
        self.assertEqual(code, 200)
        self.assertLess(elapsed, 2.0)
        self.assertEqual(data["status"], "OK", data)
        self.assertEqual(data["degraded_reasons"], [])
        self.assertTrue(data["opengrep"]["available"])
        self.assertEqual(data["opengrep"]["version"], "1.25.0")

    def test_2_slow_wrapper_bounded_http_response_degraded_and_later_recovers(self) -> None:
        wdir = self.root / "slow"
        wdir.mkdir(parents=True, exist_ok=True)
        count_file = wdir / "slow_count.txt"
        wrapper = _write_cmd_wrapper(
            wdir,
            "opengrep_slow",
            (
                "import time\n"
                f"with open({str(count_file)!r}, 'a', encoding='utf-8') as f:\n"
                "    f.write('1\\n')\n"
                "time.sleep(0.9)\n"
                "print('1.25.0')\n"
            ),
        )
        srv, base = self._start_api(str(wrapper))
        # Configure short budgets so test runs quickly while accurately exercising slow-wrapper behavior
        srv.service._opengrep_http_wait_seconds = 0.25
        srv.service._opengrep_subprocess_timeout_seconds = 2.5

        code1, d1, elapsed1 = self._get(f"{base}/api/health")
        self.assertEqual(code1, 200)
        self.assertLess(elapsed1, 0.75, f"/api/health blocked too long ({elapsed1:.2f}s) instead of returning bounded DEGRADED")
        self.assertEqual(d1["status"], "DEGRADED", "Must NOT claim OK while OpenGrep is unverified")
        self.assertIn("OPENGREP_UNAVAILABLE", d1["degraded_reasons"])
        self.assertFalse(d1["opengrep"]["available"])

        # Meanwhile /api/model continues responding fast
        code_m, dm, elapsed_m = self._get(f"{base}/api/model")
        self.assertEqual(code_m, 200)
        self.assertEqual(dm["status"], "OK")
        self.assertLess(elapsed_m, 1.0)

        # Wait for the single in-flight probe (0.9s) to finish cleanly -> subsequent /api/health picks up cached OK!
        time.sleep(1.0)
        code2, d2, elapsed2 = self._get(f"{base}/api/health")
        self.assertEqual(code2, 200)
        self.assertLess(elapsed2, 0.5)
        self.assertEqual(d2["status"], "OK", d2)
        self.assertTrue(d2["opengrep"]["available"])
        self.assertEqual(d2["opengrep"]["version"], "1.25.0")
        invocations = len(count_file.read_text(encoding="utf-8").splitlines())
        self.assertEqual(invocations, 1, f"Expected single-flight 1 invocation, saw {invocations}")

    def test_3_concurrent_health_requests_single_flight_and_hung_grandchild_pipe_safety(self) -> None:
        wdir = self.root / "hung"
        wdir.mkdir(parents=True, exist_ok=True)
        count_file = wdir / "concurrent_count.txt"
        # Simulate `.cmd` wrapper spawning a slow/hung grandchild that ALSO inherits stdout
        wrapper = _write_cmd_wrapper(
            wdir,
            "opengrep_hung",
            (
                "import subprocess, sys, time\n"
                f"with open({str(count_file)!r}, 'a', encoding='utf-8') as f:\n"
                "    f.write('1\\n')\n"
                "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(5.0)'])\n"
                "time.sleep(5.0)\n"
                "child.wait()\n"
            ),
        )
        srv, base = self._start_api(str(wrapper))
        srv.service._opengrep_http_wait_seconds = 0.25
        srv.service._opengrep_subprocess_timeout_seconds = 0.7
        srv.service._opengrep_failure_ttl_seconds = 5.0

        results: list[tuple[int, dict, float]] = []
        lock = threading.Lock()
        barrier = threading.Barrier(5)

        def worker() -> None:
            barrier.wait(timeout=3.0)
            res = self._get(f"{base}/api/health")
            with lock:
                results.append(res)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=8.0)

        self.assertEqual(len(results), 5)
        for code, payload, elapsed in results:
            self.assertEqual(code, 200)
            self.assertLess(elapsed, 1.0, f"Concurrent /api/health blocked for {elapsed:.2f}s!")
            self.assertEqual(payload["status"], "DEGRADED")
            self.assertIn("OPENGREP_UNAVAILABLE", payload["degraded_reasons"])
            self.assertFalse(payload["opengrep"]["available"])

        # Only ONE subprocess was spawned across all 5 concurrent requests!
        invocations = len(count_file.read_text(encoding="utf-8").splitlines())
        self.assertEqual(invocations, 1, f"Concurrent requests spawned {invocations} wrappers instead of 1!")

        # Wait past subprocess timeout (0.7s) to verify worker cleans up and caches TIMEOUT cleanly
        time.sleep(0.8)
        code_after, d_after, elapsed_after = self._get(f"{base}/api/health")
        self.assertEqual(code_after, 200)
        self.assertLess(elapsed_after, 0.5)
        self.assertEqual(d_after["status"], "DEGRADED")
        self.assertFalse(d_after["opengrep"]["available"])

    def test_4_error_and_missing_wrapper_report_degraded(self) -> None:
        wdir = self.root / "err"
        wdir.mkdir(parents=True, exist_ok=True)
        err_wrapper = _write_cmd_wrapper(
            wdir,
            "opengrep_err",
            "import sys\nsys.stderr.write('wrapper failed\\n')\nsys.exit(2)\n",
        )
        srv_err, base_err = self._start_api(str(err_wrapper))
        code_e, de, _ = self._get(f"{base_err}/api/health")
        self.assertEqual(code_e, 200)
        self.assertEqual(de["status"], "DEGRADED")
        self.assertIn("OPENGREP_UNAVAILABLE", de["degraded_reasons"])
        self.assertFalse(de["opengrep"]["available"])
        self.assertIn("wrapper failed", de["opengrep"]["error"])

        srv_miss, base_miss = self._start_api("opengrep-nonexistent-wrapper-xyz")
        code_m, dm, _ = self._get(f"{base_miss}/api/health")
        self.assertEqual(code_m, 200)
        self.assertEqual(dm["status"], "DEGRADED")
        self.assertFalse(dm["opengrep"]["available"])

    def test_5_exit0_empty_unknown_or_invalid_version_fails_closed(self) -> None:
        for label, stdout_expr in (
            ("empty_stdout", "''"),
            ("whitespace_stdout", "'   \\n'"),
            ("literal_unknown", "'unknown'"),
            ("garbage_string", "'OpenGrep wrapper ok'"),
            ("multiline_garbage", "'1.25.0\\nextra-noise'"),
        ):
            with self.subTest(case=label):
                wdir = self.root / f"badver_{label}"
                wdir.mkdir(parents=True, exist_ok=True)
                bad_wrapper = _write_cmd_wrapper(
                    wdir,
                    f"opengrep_{label}",
                    f"import sys\nsys.stdout.write({stdout_expr})\nsys.exit(0)\n",
                )
                _, base = self._start_api(str(bad_wrapper))
                code, payload, _ = self._get(f"{base}/api/health")
                self.assertEqual(code, 200)
                self.assertEqual(payload["status"], "DEGRADED", f"[{label}] Must not report OK: {payload}")
                self.assertIn("OPENGREP_UNAVAILABLE", payload["degraded_reasons"])
                self.assertFalse(payload["opengrep"]["available"])
                self.assertIsNone(payload["opengrep"]["version"])
                self.assertNotEqual(payload["opengrep"].get("probe_status"), "VERIFIED")

        # Valid OpenGrep 1.25.0 stub format (`opengrep 1.25.0-test-stub`) must also still pass
        wdir_stub = self.root / "ver_stub"
        wdir_stub.mkdir(parents=True, exist_ok=True)
        stub_wrapper = _write_cmd_wrapper(
            wdir_stub,
            "opengrep_stubver",
            "print('opengrep 1.25.0-test-stub')\n",
        )
        _, base_stub = self._start_api(str(stub_wrapper))
        code_s, ds, _ = self._get(f"{base_stub}/api/health")
        self.assertEqual(code_s, 200)
        self.assertEqual(ds["status"], "OK", ds)
        self.assertTrue(ds["opengrep"]["available"])
        self.assertEqual(ds["opengrep"]["version"], "opengrep 1.25.0-test-stub")

    def test_6_wrapper_exits_before_grandchild_does_not_block_health(self) -> None:
        wdir = self.root / "grandchild_early_exit"
        wdir.mkdir(parents=True, exist_ok=True)
        wrapper = _write_cmd_wrapper(
            wdir,
            "opengrep_early_exit",
            (
                "import subprocess, sys\n"
                "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(1.2)'], cwd='.')\n"
                "print('1.25.0')\n"
                "sys.stdout.flush()\n"
            ),
        )
        srv, base = self._start_api(str(wrapper))
        code, payload, elapsed = self._get(f"{base}/api/health")
        self.assertEqual(code, 200)
        self.assertLess(elapsed, 0.7, f"/api/health blocked waiting for grandchild ({elapsed:.2f}s)!")
        self.assertEqual(payload["status"], "OK", payload)
        self.assertTrue(payload["opengrep"]["available"])
        self.assertEqual(payload["opengrep"]["version"], "1.25.0")
        time.sleep(1.3)

    def test_7_thread_start_failure_rolls_back_inflight_and_recovers(self) -> None:
        from unittest.mock import patch

        wdir = self.root / "thread_fail"
        wdir.mkdir(parents=True, exist_ok=True)
        wrapper = _write_cmd_wrapper(
            wdir,
            "opengrep_thread_recover",
            "print('1.25.0')\n",
        )
        srv, base = self._start_api(str(wrapper))
        orig_start = threading.Thread.start
        probe_starts = {"count": 0}

        def flaky_start(thread_self: threading.Thread, *args, **kwargs):
            if thread_self.name == "opengrep-version-probe":
                probe_starts["count"] += 1
                if probe_starts["count"] == 1:
                    raise RuntimeError("can't start new thread (simulated)")
            return orig_start(thread_self, *args, **kwargs)

        with patch.object(threading.Thread, "start", flaky_start):
            code1, d1, elapsed1 = self._get(f"{base}/api/health")
            self.assertEqual(code1, 200)
            self.assertLess(elapsed1, 1.0)
            self.assertEqual(d1["status"], "DEGRADED", d1)
            self.assertFalse(d1["opengrep"]["available"])
            self.assertFalse(srv.service._opengrep_probe_inflight, "inflight flag must roll back on Thread.start failure")

            # Immediate next /api/health must recover without getting stuck in PENDING
            code2, d2, elapsed2 = self._get(f"{base}/api/health")
            self.assertEqual(code2, 200)
            self.assertLess(elapsed2, 2.0)
            self.assertEqual(d2["status"], "OK", d2)
            self.assertTrue(d2["opengrep"]["available"])
            self.assertEqual(d2["opengrep"]["version"], "1.25.0")
            self.assertEqual(probe_starts["count"], 2)


if __name__ == "__main__":
    unittest.main()
