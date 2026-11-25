"""Tests verifying /api/health stays non-blocking and snapshot-only (never spawning inline subprocesses)
while preserving auth, CORS, /api/model, real scan jobs, and clean bounded shutdown."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import zipfile

from v2.api.config import ApiConfig
from v2.api.server import ThesisApiServer


TEST_TOKEN = "health-decoupled-opengrep-token-20261117"

SAMPLE_JAVA = (
    "package demo;\n"
    "public class DecoupledScanDemo {\n"
    "    public void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement st) throws Exception {\n"
    '        String id = req.getParameter("id");\n'
    '        st.executeQuery("SELECT * FROM users WHERE id=" + id);\n'
    "    }\n"
    "}\n"
)


def _make_java_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("src/DecoupledScanDemo.java", SAMPLE_JAVA)
    return buf.getvalue()


def _make_multipart_zip(filename: str, payload: bytes) -> tuple[str, bytes]:
    boundary = "----DecoupledBoundary20261117"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: application/zip\r\n\r\n"
    ).encode("utf-8") + payload + f"\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"no_llm\"\r\n\r\ntrue\r\n--{boundary}--\r\n".encode("utf-8")
    return f"multipart/form-data; boundary={boundary}", body


def _make_mock_ollama_server() -> tuple[ThreadingHTTPServer, threading.Thread, str]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_GET(self):
            if self.path == "/api/tags":
                raw = json.dumps({"models": [{"name": "qwen3.5:9b-q4_K_M", "digest": "sha256:test"}]}).encode("utf-8")
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


def _write_opengrep_wrapper(directory: Path, log_file: Path, *, sleep_on_version: float = 0.0) -> Path:
    impl = directory / "opengrep_scan_impl.py"
    impl.write_text(
        "import json, pathlib, sys, time\n"
        "args = sys.argv[1:]\n"
        f"with open({str(log_file)!r}, 'a', encoding='utf-8') as lf:\n"
        "    lf.write(' '.join(args) + '\\n')\n"
        "if '--version' in args:\n"
        f"    if {sleep_on_version!r} > 0:\n"
        f"        time.sleep({sleep_on_version!r})\n"
        "    print('1.25.0')\n"
        "    sys.exit(0)\n"
        "target = pathlib.Path(args[-1]).resolve()\n"
        "java_files = sorted(target.rglob('*.java')) if target.is_dir() else [target]\n"
        "jf = java_files[0]\n"
        "rel = jf.relative_to(target).as_posix() if target.is_dir() else jf.name\n"
        "lines = jf.read_text(encoding='utf-8').splitlines()\n"
        "src_ln = next(i + 1 for i, l in enumerate(lines) if 'getParameter' in l)\n"
        "sink_ln = next(i + 1 for i, l in enumerate(lines) if 'executeQuery' in l)\n"
        "src_txt = 'req.getParameter(\"id\")'\n"
        "sink_txt = 'st.executeQuery(\"SELECT * FROM users WHERE id=\" + id)'\n"
        "sc = lines[src_ln - 1].index(src_txt) + 1\n"
        "kc = lines[sink_ln - 1].index(sink_txt) + 1\n"
        "if '--json' in args:\n"
        "    res = {\n"
        "        'check_id': 'v2.g1.java.cwe89.sqli',\n"
        "        'path': rel,\n"
        "        'start': {'line': sink_ln, 'col': kc},\n"
        "        'end': {'line': sink_ln, 'col': kc + len(sink_txt)},\n"
        "        'extra': {\n"
        "            'severity': 'ERROR',\n"
        "            'message': 'SQLi test finding',\n"
        "            'metadata': {'cwe': ['CWE-89: SQL Injection']},\n"
        "            'dataflow_trace': {\n"
        "                'taint_source': ['CliLoc', [{'path': rel, 'start': {'line': src_ln, 'col': sc}, 'end': {'line': src_ln, 'col': sc + len(src_txt)}}, src_txt]],\n"
        "                'taint_sink': ['CliLoc', [{'path': rel, 'start': {'line': sink_ln, 'col': kc}, 'end': {'line': sink_ln, 'col': kc + len(sink_txt)}}, sink_txt]],\n"
        "                'intermediate_vars': [],\n"
        "            },\n"
        "        },\n"
        "    }\n"
        "    print(json.dumps({'results': [res], 'errors': []}))\n"
        "elif '--sarif' in args:\n"
        "    print(json.dumps({'version': '2.1.0', 'runs': [{'results': [{'ruleId': 'v2.g1.java.cwe89.sqli', 'locations': [{'physicalLocation': {'artifactLocation': {'uri': rel}, 'region': {'startLine': sink_ln, 'startColumn': kc, 'endLine': sink_ln, 'endColumn': kc + len(sink_txt)}}}]}]}]}))\n",
        encoding="utf-8",
    )
    if os.name == "nt":
        cmd = directory / "opengrep_test_stub.cmd"
        cmd.write_text(f'@echo off\r\n"{sys.executable}" "{impl}" %*\r\n', encoding="utf-8")
        return cmd
    cmd = directory / "opengrep_test_stub.sh"
    cmd.write_text(f'#!/bin/sh\n"{sys.executable}" "{impl}" "$@"\n', encoding="utf-8")
    cmd.chmod(0o755)
    return cmd


class HealthDecoupledOpenGrepTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.rules_file = self.root / "rules.yml"
        self.rules_file.write_text(
            "rules:\n"
            "  - id: test.cwe89.sqli\n"
            "    mode: taint\n"
            "    languages: [java]\n"
            "    severity: ERROR\n"
            "    message: test sqli\n"
            "    metadata:\n"
            "      cwe: ['CWE-89: SQL Injection']\n"
            "  - id: test.cwe22.path\n"
            "    mode: taint\n"
            "    languages: [java]\n"
            "    severity: ERROR\n"
            "    message: test path\n"
            "    metadata:\n"
            "      cwe: ['CWE-22: Path Traversal']\n",
            encoding="utf-8",
        )
        self.ol_srv, self.ol_th, self.ollama_url = _make_mock_ollama_server()
        self.addCleanup(lambda: (self.ol_srv.shutdown(), self.ol_th.join(timeout=2.0), self.ol_srv.server_close()))

    def _start_api(self, og_binary: str, *, runtime_origin: str = "unverified") -> tuple[ThesisApiServer, str]:
        srv = ThesisApiServer(
            ApiConfig(
                host="127.0.0.1",
                port=0,
                data_dir=self.root / f"data_{time.monotonic_ns()}",
                rules_path=self.rules_file,
                opengrep_binary=og_binary,
                ollama_endpoint=self.ollama_url,
                ollama_model="qwen3.5:9b-q4_K_M",
                api_token=TEST_TOKEN,
                read_auth_mode="required",
                cors_origins=("http://localhost:5173",),
                runtime_origin=runtime_origin,
            )
        )
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        self.addCleanup(lambda: (srv.shutdown(), th.join(timeout=2.0), srv.server_close()))
        h, p = srv.server_address[:2]
        return srv, f"http://{h}:{p}"

    def _http(
        self,
        url: str,
        *,
        method: str = "GET",
        token: str | None = TEST_TOKEN,
        origin: str | None = None,
        body: bytes | None = None,
        content_type: str | None = None,
    ) -> tuple[int, dict, dict, float]:
        headers = {"Connection": "close"}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        if origin is not None:
            headers["Origin"] = origin
        if content_type is not None:
            headers["Content-Type"] = content_type
        req = Request(url, data=body, headers=headers, method=method)
        t0 = time.monotonic()
        try:
            with urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8")), dict(resp.headers), time.monotonic() - t0
        except HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8")), dict(exc.headers), time.monotonic() - t0

    def test_1_health_fast_concurrent_no_subprocess_no_thread_and_not_verified_contract(self) -> None:
        wdir = self.root / "stub_slow"
        wdir.mkdir(parents=True, exist_ok=True)
        log_file = wdir / "invocations.log"
        # Startup launches ONE single-flight background probe (slow 30s wrapper);
        # concurrent GET /api/health requests MUST stay fast, spawn 0 subprocesses/threads inline,
        # and remain DEGRADED / OPENGREP_NOT_VERIFIED while the probe has not completed!
        og_cmd = _write_opengrep_wrapper(wdir, log_file, sleep_on_version=30.0)
        srv, base = self._start_api(str(og_cmd))
        # Wait briefly until the single startup probe enters the wrapper before patching subprocess around GET /api/health
        deadline = time.monotonic() + 5.0
        while not log_file.is_file() and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(log_file.is_file(), "Expected single startup background probe to launch")
        startup_invocations = len(log_file.read_text(encoding="utf-8").splitlines())
        self.assertEqual(startup_invocations, 1)

        # Spy on subprocess.Popen, subprocess.run, and threading.Thread during 8 concurrent GET /api/health calls
        orig_thread_init = threading.Thread.__init__
        spawned_thread_names: list[str | None] = []

        def spy_thread_init(t_self, *args, **kwargs):
            spawned_thread_names.append(kwargs.get("name"))
            return orig_thread_init(t_self, *args, **kwargs)

        def forbid_subprocess(*args, **kwargs):
            raise AssertionError(f"/api/health must NEVER spawn subprocesses inline! args={args}")

        results: list[tuple[int, dict, dict, float]] = []
        lock = threading.Lock()
        barrier = threading.Barrier(8)

        with patch("subprocess.Popen", side_effect=forbid_subprocess), patch("subprocess.run", side_effect=forbid_subprocess), patch.object(threading.Thread, "__init__", spy_thread_init):
            def worker():
                barrier.wait(timeout=3.0)
                r = self._http(f"{base}/api/health", origin="http://localhost:5173")
                with lock:
                    results.append(r)

            threads = [threading.Thread(target=worker) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=5.0)

        self.assertEqual(len(results), 8)
        for code, data, hdrs, elapsed in results:
            self.assertEqual(code, 200)
            self.assertLess(elapsed, 0.8, f"/api/health blocked ({elapsed:.2f}s)")
            self.assertEqual(hdrs.get("Access-Control-Allow-Origin"), "http://localhost:5173")
            self.assertEqual(data["status"], "DEGRADED", "Must NEVER report OK when OpenGrep runtime is unverified")
            self.assertIn("OPENGREP_NOT_VERIFIED", data["degraded_reasons"])
            og = data["opengrep"]
            self.assertFalse(og["available"])
            self.assertIsNone(og["version"])
            self.assertEqual(og["probe_status"], "NOT_VERIFIED")
            self.assertFalse(og["runtime_verified"])
            self.assertEqual(Path(og["resolved_path"]).resolve(), og_cmd.resolve())
            self.assertNotEqual(og["probe_status"], "VERIFIED")

        self.assertEqual(len(log_file.read_text(encoding="utf-8").splitlines()), 1)
        self.assertNotIn("ntk-opengrep-health-probe", spawned_thread_names)

    def test_2_missing_and_invalid_binary_auth_cors_and_model_preserved(self) -> None:
        _, base = self._start_api("opengrep-nonexistent-xyz")

        # 1. Unauthenticated /api/health -> AUTH_REQUIRED
        c_unauth, d_unauth, _, _ = self._http(f"{base}/api/health", token=None)
        self.assertEqual(c_unauth, 200)
        self.assertEqual(d_unauth["status"], "AUTH_REQUIRED")
        self.assertFalse(d_unauth["authenticated"])

        # 2. Forbidden CORS -> 403
        c_cors, d_cors, _, _ = self._http(f"{base}/api/health", origin="https://evil.example")
        self.assertEqual(c_cors, 403)
        self.assertEqual(d_cors["error_code"], "CORS_ORIGIN_FORBIDDEN")

        # 3. Missing OpenGrep binary -> DEGRADED with OPENGREP_UNAVAILABLE
        c_miss, d_miss, _, elapsed_m = self._http(f"{base}/api/health")
        self.assertEqual(c_miss, 200)
        self.assertLess(elapsed_m, 0.8)
        self.assertEqual(d_miss["status"], "DEGRADED")
        self.assertIn("OPENGREP_UNAVAILABLE", d_miss["degraded_reasons"])
        self.assertEqual(d_miss["opengrep"]["probe_status"], "UNAVAILABLE")
        self.assertFalse(d_miss["opengrep"]["available"])
        self.assertIsNone(d_miss["opengrep"]["resolved_path"])

        # 4. /api/model responds 200 OK unchanged
        c_mod, d_mod, _, elapsed_mod = self._http(f"{base}/api/model")
        self.assertEqual(c_mod, 200)
        self.assertLess(elapsed_mod, 1.0)
        self.assertEqual(d_mod["status"], "OK")
        self.assertTrue(d_mod["ollama"]["reachable"])
        self.assertTrue(d_mod["ollama"]["model_installed"])

        # 5. Missing binary on /api/scan-jobs still fails with OPENGREP_UNAVAILABLE (not bypassed or mocked)
        ct, body = _make_multipart_zip("app.zip", _make_java_zip())
        c_sub, d_sub, _, _ = self._http(f"{base}/api/scan-jobs", method="POST", body=body, content_type=ct)
        self.assertEqual(c_sub, 202)
        jid = d_sub["job_id"]
        job_state = None
        for _ in range(50):
            _, job_state, _, _ = self._http(f"{base}/api/scan-jobs/{jid}")
            if job_state["state"] in ("COMPLETED", "FAILED"):
                break
            time.sleep(0.1)
        self.assertEqual(job_state["state"], "FAILED")
        self.assertEqual(job_state["error_code"], "OPENGREP_UNAVAILABLE")

    def test_3_scan_job_still_executes_real_scanner_pipeline_not_mock_and_shutdown_clean(self) -> None:
        wdir = self.root / "stub_real_scan"
        wdir.mkdir(parents=True, exist_ok=True)
        log_file = wdir / "invocations.log"
        og_cmd = _write_opengrep_wrapper(wdir, log_file, sleep_on_version=0.0)
        srv, base = self._start_api(str(og_cmd), runtime_origin="unverified")

        # Wait for the single bounded startup probe to complete before submitting the scan job
        self.assertTrue(srv.service.wait_for_opengrep_probe(timeout=10.0))
        c_h, d_h, _, _ = self._http(f"{base}/api/health")
        self.assertEqual(c_h, 200)
        self.assertIn(d_h["opengrep"]["probe_status"], ("VERIFIED", "CANARY_FAILED"))

        # Submitting a scan job DOES execute og_cmd via SemgrepScanner (--version, --json, --sarif)
        ct, body = _make_multipart_zip("app.zip", _make_java_zip())
        c_sub, d_sub, _, _ = self._http(f"{base}/api/scan-jobs", method="POST", body=body, content_type=ct)
        self.assertEqual(c_sub, 202)
        jid = d_sub["job_id"]
        job_state = None
        for _ in range(80):
            _, job_state, _, _ = self._http(f"{base}/api/scan-jobs/{jid}")
            if job_state["state"] in ("COMPLETED", "FAILED"):
                break
            time.sleep(0.1)
        self.assertEqual(job_state["state"], "COMPLETED", job_state)
        scan_id = job_state["scan_id"]
        self.assertTrue(scan_id)

        invoked_cmds = log_file.read_text(encoding="utf-8").splitlines()
        self.assertTrue(any("--version" in ln for ln in invoked_cmds), invoked_cmds)
        self.assertTrue(any("--json" in ln for ln in invoked_cmds), invoked_cmds)
        self.assertTrue(any("--sarif" in ln for ln in invoked_cmds), invoked_cmds)

        _, sum_doc, _, _ = self._http(f"{base}/api/scans/{scan_id}")
        self.assertEqual(sum_doc["data_origin"], "REAL_SCAN")
        self.assertFalse(sum_doc["is_test_or_mock"])

        # Controlled server shutdown calls jobs.shutdown without needing probe cleanup
        t0 = time.monotonic()
        srv.shutdown()
        srv.server_close()
        self.assertLess(time.monotonic() - t0, 2.0)


if __name__ == "__main__":
    unittest.main()
