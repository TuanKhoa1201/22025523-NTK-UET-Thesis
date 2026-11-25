"""Comprehensive positive and counterexample tests for active OpenGrep health/readiness probing.

Covers all 20 required scenarios:
1. Real OpenGrep 1.25.0 active probe (when configured/available) -> SCAN_VERIFIED + OK
2. Missing binary -> UNAVAILABLE + DEGRADED
3. Broken wrapper / invalid config -> fail-closed
4. Out-of-policy / malformed versions -> VERSION_POLICY_REJECTED / FAILED
5. Non-zero exit codes on --version and canary scan -> fail-closed
6. Timeout with grandchild process-tree kill verification -> TIMEOUT + clean tree
7. Invalid JSON / OpenGrep scan errors -> fail-closed
8. Canary oracle mismatches (empty results, missing CWE, wrong line, wrong rule id, missing trace,
   safe-control violation, JSON version mismatch, unscanned canary file) -> CANARY_FAILED (SCAN_EXECUTED only)
9. Rules SHA-256 mutation -> immediate invalidation + re-probe
10. Binary/wrapper and wrapper target script mutation -> immediate BINARY_IDENTITY_CHANGED invalidation
11. API restart -> never carries VERIFIED from dead process, fresh process_instance_id
12. Snapshot TTL expiry -> immediate fail-closed EXPIRED + single-flight refresh
13. Repeated GET /api/health -> zero repeated OpenGrep invocations
14. Concurrent GET /api/health -> single-flight, bounded latency, no duplicate probes
15. Unauthenticated /api/health -> minimal 8-field AUTH_REQUIRED, never triggers probe
16. Authenticated /api/health -> complete contract + frontend display parity
17. Bearer token and CORS non-regression
18. Failed OpenGrep or other degraded dependency never reports OK
19. Scan jobs unaffected by probe + TTL refresh defers during active Stage 2 scan
20. Clean bounded shutdown cancels in-flight probes without lingering OS processes
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
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
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import zipfile

from v2.api import API_CONTRACT_SCHEMA, API_SERVICE_NAME, API_VERSION, intake
from v2.api.config import ApiConfig, DEFAULT_BACKEND_RULES
from v2.api.opengrep_runner import (
    HEALTH_CANARY_FILENAME,
    HEALTH_CANARY_PATH_LINE,
    HEALTH_CANARY_SQL_LINE,
    OpenGrepHealthProbe,
    parse_and_check_opengrep_version,
)
from v2.api.server import ThesisApiServer
from v2.api.service import TriageApiService
from v2.triage.evidence import digest


TEST_TOKEN = "health-active-probe-token-20261123"

SAMPLE_SCAN_JAVA = (
    "package demo;\n"
    "import java.io.FileInputStream;\n"
    "import java.sql.Statement;\n"
    "import javax.servlet.http.HttpServletRequest;\n"
    "public class RealJobDemo {\n"
    "    public void run(HttpServletRequest req, Statement st) throws Exception {\n"
    '        String id = req.getParameter("id");\n'
    '        st.executeQuery("SELECT * FROM users WHERE id=" + id);\n'
    '        new FileInputStream("/srv/data/" + id);\n'
    "    }\n"
    "}\n"
)

VALID_MINIMAL_RULES_YAML = (
    "rules:\n"
    "  - id: ntk.test.java.cwe89.sql-injection\n"
    "    mode: taint\n"
    "    languages: [java]\n"
    "    severity: ERROR\n"
    "    message: test cwe89\n"
    "    metadata:\n"
    "      cwe:\n"
    "        - 'CWE-89: SQL Injection'\n"
    "  - id: ntk.test.java.cwe22.path-traversal\n"
    "    mode: taint\n"
    "    languages: [java]\n"
    "    severity: ERROR\n"
    "    message: test cwe22\n"
    "    metadata:\n"
    "      cwe:\n"
    "        - 'CWE-22: Path Traversal'\n"
)


def _resolve_real_opengrep_binary() -> str | None:
    env_bin = os.environ.get("OPENGREP_BINARY") or os.environ.get("NTK_TEST_OPENGREP_BINARY")
    if env_bin and Path(env_bin).is_file():
        return str(Path(env_bin).resolve())
    default_win = Path(r"C:\NTK-G1-Private\G1-Runtime\bin\opengrep.cmd")
    if default_win.is_file():
        return str(default_win)
    return None


def _is_os_pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k32.OpenProcess.restype = wintypes.HANDLE
        k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        k32.GetExitCodeProcess.restype = wintypes.BOOL
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = k32.OpenProcess(0x1000, False, int(pid))
        if not handle:
            return False
        try:
            code = wintypes.DWORD(0)
            if not k32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return False
            return code.value == 259  # STILL_ACTIVE
        finally:
            k32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _make_mock_ollama_server(*, installed: bool = True) -> tuple[ThreadingHTTPServer, threading.Thread, str]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return

        def do_GET(self):
            if self.path == "/api/tags":
                models = (
                    [{"name": "qwen3.5:9b-q4_K_M", "digest": "sha256:test-digest-qwen35"}]
                    if installed
                    else []
                )
                raw = json.dumps({"models": models}).encode("utf-8")
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


def _write_canary_wrapper(
    directory: Path,
    *,
    name: str = "opengrep_canary_stub",
    version_stdout: str = "1.25.0",
    version_exit: int = 0,
    scan_exit: int = 0,
    json_version: str | None = "1.25.0",
    include_cwe89: bool = True,
    include_cwe22: bool = True,
    cwe89_line: int = HEALTH_CANARY_SQL_LINE,
    cwe22_line: int = HEALTH_CANARY_PATH_LINE,
    cwe89_rule_id: str = "ntk.test.java.cwe89.sql-injection",
    cwe22_rule_id: str = "ntk.test.java.cwe22.path-traversal",
    include_trace: bool = True,
    flag_safe_control: bool = False,
    raw_scan_stdout: str | None = None,
    errors_list: list | None = None,
    scanned_paths_override: list[str] | None = None,
    sleep_version: float = 0.0,
    sleep_scan: float = 0.0,
    log_file: Path | None = None,
    spawn_grandchild_pid_file: Path | None = None,
) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    cfg = {
        "version_stdout": version_stdout,
        "version_exit": version_exit,
        "scan_exit": scan_exit,
        "json_version": json_version,
        "include_cwe89": include_cwe89,
        "include_cwe22": include_cwe22,
        "cwe89_line": cwe89_line,
        "cwe22_line": cwe22_line,
        "cwe89_rule_id": cwe89_rule_id,
        "cwe22_rule_id": cwe22_rule_id,
        "include_trace": include_trace,
        "flag_safe_control": flag_safe_control,
        "raw_scan_stdout": raw_scan_stdout,
        "errors_list": errors_list or [],
        "scanned_paths_override": scanned_paths_override,
        "sleep_version": sleep_version,
        "sleep_scan": sleep_scan,
        "log_file": str(log_file) if log_file else None,
        "pid_file": str(spawn_grandchild_pid_file) if spawn_grandchild_pid_file else None,
    }
    script = directory / f"{name}.py"
    script.write_text(
        "import json, os, pathlib, subprocess, sys, time\n"
        f"CFG = {cfg!r}\n"
        "args = sys.argv[1:]\n"
        "if CFG['log_file']:\n"
        "    with open(CFG['log_file'], 'a', encoding='utf-8') as lf:\n"
        "        lf.write(' '.join(args) + '\\n')\n"
        "if '--version' in args:\n"
        "    if CFG['pid_file'] and CFG['sleep_version'] > 0:\n"
        "        gc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30.0)'])\n"
        "        with open(CFG['pid_file'], 'a', encoding='utf-8') as pf:\n"
        "            pf.write(f'{os.getpid()}\\n{gc.pid}\\n')\n"
        "    if CFG['sleep_version'] > 0:\n"
        "        time.sleep(CFG['sleep_version'])\n"
        "    if CFG['version_exit'] != 0:\n"
        "        sys.stderr.write('simulated version failure\\n')\n"
        "        sys.exit(CFG['version_exit'])\n"
        "    sys.stdout.write(CFG['version_stdout'])\n"
        "    if CFG['version_stdout'] and not CFG['version_stdout'].endswith('\\n'):\n"
        "        sys.stdout.write('\\n')\n"
        "    sys.exit(0)\n"
        "if CFG['pid_file'] and CFG['sleep_scan'] > 0:\n"
        "    gc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30.0)'])\n"
        "    with open(CFG['pid_file'], 'a', encoding='utf-8') as pf:\n"
        "        pf.write(f'{os.getpid()}\\n{gc.pid}\\n')\n"
        "if CFG['sleep_scan'] > 0:\n"
        "    time.sleep(CFG['sleep_scan'])\n"
        "if CFG['scan_exit'] != 0:\n"
        "    sys.stderr.write('simulated scan failure\\n')\n"
        "    sys.exit(CFG['scan_exit'])\n"
        "if CFG['raw_scan_stdout'] is not None:\n"
        "    sys.stdout.write(CFG['raw_scan_stdout'])\n"
        "    sys.exit(0)\n"
        "target = pathlib.Path(args[-1]).resolve()\n"
        "java_files = sorted(target.rglob('*.java')) if target.is_dir() else [target]\n"
        "jf = java_files[0]\n"
        "is_canary = jf.name == 'OpenGrepHealthCanary.java'\n"
        "raw_bytes = jf.read_bytes()\n"
        "raw_lines = jf.read_text(encoding='utf-8').splitlines()\n"
        "line_starts = [0]\n"
        "for _idx_b, _bt in enumerate(raw_bytes):\n"
        "    if _bt == 10:\n"
        "        line_starts.append(_idx_b + 1)\n"
        "def _loc_with_offset(sl, sc, el, ec):\n"
        "    so = line_starts[sl - 1] + (sc - 1) if sl - 1 < len(line_starts) else 0\n"
        "    eo = line_starts[el - 1] + (ec - 1) if el - 1 < len(line_starts) else so\n"
        "    return {'path': str(jf), 'start': {'line': sl, 'col': sc, 'offset': so}, 'end': {'line': el, 'col': ec, 'offset': eo}}\n"
        "CANARY_EXACT = {\n"
        "    (10, 'CWE-89'): ((9, 21, 9, 43, 'req.getParameter(\"id\")'), (10, 25, 10, 61, '\"SELECT * FROM users WHERE id=\" + id'), (10, 9, 10, 62)),\n"
        "    (15, 'CWE-22'): ((14, 23, 14, 47, 'req.getParameter(\"file\")'), (15, 9, 15, 49, 'new FileInputStream(\"/srv/data/\" + name)'), (15, 9, 15, 49)),\n"
        "}\n"
        "results = []\n"
        "def mk_res(cid, line, cwe_str, trace):\n"
        "    cwe_key = cwe_str.split(':', 1)[0].strip()\n"
        "    spec = CANARY_EXACT.get((line, cwe_key)) if is_canary else None\n"
        "    if spec is not None:\n"
        "        src_sp, snk_sp, res_sp = spec\n"
        "        r_sl, r_sc, r_el, r_ec = res_sp\n"
        "        src_loc = _loc_with_offset(*src_sp[:4])\n"
        "        src_txt = src_sp[4]\n"
        "        snk_loc = _loc_with_offset(*snk_sp[:4])\n"
        "        snk_txt = snk_sp[4]\n"
        "    else:\n"
        "        r_sl = r_el = line\n"
        "        r_sc = 1\n"
        "        ln_txt = raw_lines[line - 1] if 1 <= line <= len(raw_lines) else 'sink'\n"
        "        r_ec = len(ln_txt.encode('utf-8')) + 1\n"
        "        p_ln = max(1, line - 1)\n"
        "        p_txt = raw_lines[p_ln - 1] if 1 <= p_ln <= len(raw_lines) else 'src'\n"
        "        src_loc = _loc_with_offset(p_ln, 1, p_ln, len(p_txt.encode('utf-8')) + 1)\n"
        "        src_txt = p_txt or 'src'\n"
        "        snk_loc = _loc_with_offset(r_sl, 1, r_el, r_ec)\n"
        "        snk_txt = ln_txt or 'sink'\n"
        "    res_loc = _loc_with_offset(r_sl, r_sc, r_el, r_ec)\n"
        "    extra = {'severity': 'ERROR', 'message': 'finding', 'metadata': {'cwe': [cwe_str]}}\n"
        "    if trace:\n"
        "        extra['dataflow_trace'] = {\n"
        "            'taint_source': ['CliLoc', [src_loc, src_txt]],\n"
        "            'taint_sink': ['CliLoc', [snk_loc, snk_txt]],\n"
        "            'intermediate_vars': [],\n"
        "        }\n"
        "    return {'check_id': cid, 'path': str(jf), 'start': res_loc['start'], 'end': res_loc['end'], 'extra': extra}\n"
        "if is_canary:\n"
        "    if CFG['include_cwe89']:\n"
        "        results.append(mk_res(CFG['cwe89_rule_id'], CFG['cwe89_line'], 'CWE-89: SQL Injection', CFG['include_trace']))\n"
        "    if CFG['include_cwe22']:\n"
        "        results.append(mk_res(CFG['cwe22_rule_id'], CFG['cwe22_line'], 'CWE-22: Path Traversal', CFG['include_trace']))\n"
        "    if CFG['flag_safe_control']:\n"
        "        results.append(mk_res(CFG['cwe89_rule_id'], 19, 'CWE-89: SQL Injection', CFG['include_trace']))\n"
        "else:\n"
        "    lines = jf.read_text(encoding='utf-8').splitlines()\n"
        "    sql_ln = next((i + 1 for i, l in enumerate(lines) if 'executeQuery' in l), 1)\n"
        "    results.append(mk_res(CFG['cwe89_rule_id'], sql_ln, 'CWE-89: SQL Injection', True))\n"
        "if '--sarif' in args:\n"
        "    sarif_res = [{'ruleId': r['check_id'], 'locations': [{'physicalLocation': {'artifactLocation': {'uri': r['path']}, 'region': {'startLine': r['start']['line'], 'startColumn': r['start']['col'], 'endLine': r['end']['line'], 'endColumn': r['end']['col']}}}]} for r in results]\n"
        "    print(json.dumps({'version': '2.1.0', 'runs': [{'results': sarif_res}]}))\n"
        "    sys.exit(0)\n"
        "scanned = CFG['scanned_paths_override'] if CFG['scanned_paths_override'] is not None else [str(jf)]\n"
        "doc = {'results': results, 'errors': CFG['errors_list'], 'paths': {'scanned': scanned, 'skipped': []}}\n"
        "if CFG['json_version'] is not None:\n"
        "    doc['version'] = CFG['json_version']\n"
        "print(json.dumps(doc))\n"
        "sys.exit(0)\n",
        encoding="utf-8",
    )
    if os.name == "nt":
        wrapper = directory / f"{name}.cmd"
        wrapper.write_text(f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n', encoding="utf-8")
        return wrapper, script
    wrapper = directory / f"{name}.sh"
    wrapper.write_text(f'#!/bin/sh\n"{sys.executable}" "{script}" "$@"\n', encoding="utf-8")
    wrapper.chmod(0o755)
    return wrapper, script


def _make_java_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("src/RealJobDemo.java", SAMPLE_SCAN_JAVA)
    return buf.getvalue()


def _make_multipart_zip(filename: str, payload: bytes) -> tuple[str, bytes]:
    boundary = "----ActiveHealthProbeBoundary20261123"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: application/zip\r\n\r\n"
    ).encode("utf-8") + payload + (
        f"\r\n--{boundary}\r\n"
        f'Content-Disposition: form-data; name="no_llm"\r\n\r\ntrue\r\n--{boundary}--\r\n'
    ).encode("utf-8")
    return f"multipart/form-data; boundary={boundary}", body


class ActiveOpenGrepHealthProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ntk_active_health_")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.rules_file = self.root / "rules.yml"
        self.rules_file.write_text(VALID_MINIMAL_RULES_YAML, encoding="utf-8")
        self.ol_srv, self.ol_th, self.ollama_url = _make_mock_ollama_server(installed=True)
        self.addCleanup(lambda: (self.ol_srv.shutdown(), self.ol_th.join(timeout=2.0), self.ol_srv.server_close()))

    def _start_api(
        self,
        og_binary: str,
        *,
        rules_path: Path | None = None,
        ollama_endpoint: str | None = None,
        api_token: str | None = TEST_TOKEN,
        read_auth_mode: str = "required",
        data_dir: Path | None = None,
        probe_enabled: bool = True,
        probe_ttl: float = 300.0,
        failure_ttl: float = 30.0,
        probe_timeout: float = 20.0,
        min_version: str = "1.25.0",
        max_major: int = 1,
    ) -> tuple[ThesisApiServer, str]:
        srv = ThesisApiServer(
            ApiConfig(
                host="127.0.0.1",
                port=0,
                data_dir=data_dir or (self.root / f"data_{time.monotonic_ns()}"),
                rules_path=rules_path or self.rules_file,
                opengrep_binary=og_binary,
                ollama_endpoint=ollama_endpoint or self.ollama_url,
                ollama_model="qwen3.5:9b-q4_K_M",
                api_token=api_token,
                read_auth_mode=read_auth_mode,
                cors_origins=("http://localhost:5173",),
                opengrep_health_probe_enabled=probe_enabled,
                opengrep_health_probe_ttl_seconds=probe_ttl,
                opengrep_health_probe_failure_ttl_seconds=failure_ttl,
                opengrep_health_probe_timeout_seconds=probe_timeout,
                opengrep_min_version=min_version,
                opengrep_max_major=max_major,
            )
        )
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        self.addCleanup(lambda: (srv.shutdown(), th.join(timeout=3.0), srv.server_close()))
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
    ) -> tuple[int, dict, dict, float, bytes]:
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
                raw = resp.read()
                return resp.status, json.loads(raw.decode("utf-8")), dict(resp.headers), time.monotonic() - t0, raw
        except HTTPError as exc:
            raw = exc.read()
            parsed = json.loads(raw.decode("utf-8")) if raw else {}
            return exc.code, parsed, dict(exc.headers), time.monotonic() - t0, raw

    def test_01_real_opengrep_probe_succeeds_and_transitions_to_ok(self) -> None:
        real_og = _resolve_real_opengrep_binary()
        if not real_og:
            self.skipTest("Real ADMIN-PC OpenGrep binary not present in this environment")

        srv, base = self._start_api(
            real_og,
            rules_path=DEFAULT_BACKEND_RULES.resolve(),
            probe_timeout=30.0,
        )
        self.assertTrue(srv.service.wait_for_opengrep_probe(timeout=35.0), "Real OpenGrep active probe timed out")

        code, data, _, elapsed, _ = self._http(f"{base}/api/health", origin="http://localhost:5173")
        self.assertEqual(code, 200)
        self.assertLess(elapsed, 0.5, f"Verified /api/health should be fast, got {elapsed:.2f}s")
        self.assertEqual(data["status"], "OK", data)
        self.assertEqual(data["degraded_reasons"], [])
        self.assertTrue(data["api_ready"])
        self.assertEqual(data["service"], API_SERVICE_NAME)
        self.assertEqual(data["api_version"], API_VERSION)
        self.assertEqual(data["contract_schema"], API_CONTRACT_SCHEMA)

        og = data["opengrep"]
        self.assertTrue(og["available"])
        self.assertTrue(og["runtime_verified"])
        self.assertEqual(og["probe_status"], "VERIFIED")
        self.assertEqual(og["verification_level"], "SCAN_VERIFIED")
        self.assertEqual(
            og["verification_stages"],
            {"binary_found": True, "version_identified": True, "scan_executed": True, "scan_verified": True},
        )
        self.assertEqual(og["version"], "1.25.0")
        self.assertEqual(og["version_exit_code"], 0)
        self.assertEqual(og["canary_exit_code"], 0)
        self.assertIsNotNone(og["executable_sha256"])
        self.assertIsNotNone(og["binary_identity_sha256"])
        self.assertEqual(og["rules_sha256"], digest(DEFAULT_BACKEND_RULES.read_bytes()))
        self.assertTrue(any("opengrep_counted.py" in t["path"] for t in og["wrapper_targets"]), og["wrapper_targets"])
        cs = og["canary_summary"]
        self.assertTrue(cs["oracle_matched"])
        self.assertTrue(cs["safe_control_clean"])
        self.assertEqual(cs["expected_cwes"], ["CWE-22", "CWE-89"])
        self.assertEqual(cs["errors_count"], 0)
        self.assertNotIn("model_runtime_verified", data["ollama"])

    def test_02_missing_binary_reports_unavailable_degraded(self) -> None:
        srv, base = self._start_api("opengrep-definitely-missing-xyz")
        self.assertTrue(srv.service.wait_for_opengrep_probe(timeout=2.0))
        code, data, _, elapsed, _ = self._http(f"{base}/api/health")
        self.assertEqual(code, 200)
        self.assertLess(elapsed, 0.5)
        self.assertEqual(data["status"], "DEGRADED")
        self.assertIn("OPENGREP_UNAVAILABLE", data["degraded_reasons"])
        og = data["opengrep"]
        self.assertFalse(og["available"])
        self.assertFalse(og["runtime_verified"])
        self.assertEqual(og["probe_status"], "UNAVAILABLE")
        self.assertEqual(og["verification_level"], "NONE")
        self.assertEqual(og["failure_code"], "BINARY_NOT_FOUND")
        self.assertEqual(srv.service._opengrep_probe.probe_run_count(), 0)

    def test_03_broken_wrapper_and_invalid_config_fail_closed(self) -> None:
        with self.assertRaises(ValueError):
            ApiConfig(data_dir=self.root / "bad_cfg", rules_path=self.rules_file, opengrep_binary="python.exe")

        wdir = self.root / "broken_wrapper"
        wdir.mkdir(parents=True, exist_ok=True)
        bad_cmd = wdir / ("opengrep_broken.cmd" if os.name == "nt" else "opengrep_broken.sh")
        if os.name == "nt":
            bad_cmd.write_text('@echo off\r\n"C:\\nonexistent_dir_xyz\\missing_python.exe" "missing.py" %*\r\n', encoding="utf-8")
        else:
            bad_cmd.write_text("#!/bin/sh\n/nonexistent_dir_xyz/missing_bin \"$@\"\n", encoding="utf-8")
            bad_cmd.chmod(0o755)
        srv, base = self._start_api(str(bad_cmd))
        self.assertTrue(srv.service.wait_for_opengrep_probe(timeout=10.0))
        code, data, _, _, _ = self._http(f"{base}/api/health")
        self.assertEqual(code, 200)
        self.assertEqual(data["status"], "DEGRADED")
        self.assertIn("OPENGREP_UNAVAILABLE", data["degraded_reasons"])
        self.assertFalse(data["opengrep"]["available"])
        self.assertEqual(data["opengrep"]["verification_level"], "BINARY_FOUND")

    def test_04_version_policy_and_malformed_version_rejected(self) -> None:
        # Pure unit check on version parser policy
        for bad_ver, expected_code in (
            ("", "INVALID_VERSION_OUTPUT"),
            ("   \n", "INVALID_VERSION_OUTPUT"),
            ("unknown", "INVALID_VERSION_OUTPUT"),
            ("1.25.0\nextra-line", "INVALID_VERSION_OUTPUT"),
            ("0.99.0", "VERSION_POLICY_REJECTED"),
            ("1.24.9", "VERSION_POLICY_REJECTED"),
            ("2.0.0", "VERSION_POLICY_REJECTED"),
        ):
            ok, _, _, fcode, _ = parse_and_check_opengrep_version(bad_ver, min_version="1.25.0", max_major=1)
            self.assertFalse(ok, bad_ver)
            self.assertEqual(fcode, expected_code, bad_ver)

        for good_ver in ("1.25.0", "1.33.1", "opengrep 1.25.0-test-stub"):
            ok, disp, _, fcode, _ = parse_and_check_opengrep_version(good_ver, min_version="1.25.0", max_major=1)
            self.assertTrue(ok, good_ver)
            self.assertEqual(disp, good_ver)
            self.assertIsNone(fcode)

        # End-to-end API rejection for out-of-policy version (1.24.0) without running canary scan
        log_f = self.root / "ver_policy" / "inv.log"
        wrapper, _ = _write_canary_wrapper(self.root / "ver_policy", version_stdout="1.24.0", log_file=log_f)
        srv, base = self._start_api(str(wrapper))
        self.assertTrue(srv.service.wait_for_opengrep_probe(timeout=10.0))
        code, data, _, _, _ = self._http(f"{base}/api/health")
        self.assertEqual(code, 200)
        self.assertEqual(data["status"], "DEGRADED")
        self.assertIn("OPENGREP_UNAVAILABLE", data["degraded_reasons"])
        og = data["opengrep"]
        self.assertFalse(og["available"])
        self.assertEqual(og["probe_status"], "VERSION_POLICY_REJECTED")
        self.assertEqual(og["failure_code"], "VERSION_POLICY_REJECTED")
        self.assertEqual(og["verification_level"], "BINARY_FOUND")
        self.assertIsNone(og["canary_exit_code"])
        invoked = log_f.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(invoked), 1, f"Must stop before canary scan on version rejection: {invoked}")

    def test_05_nonzero_exit_on_version_and_canary_scan(self) -> None:
        w1, _ = _write_canary_wrapper(self.root / "exit_ver", version_exit=2)
        srv1, base1 = self._start_api(str(w1))
        self.assertTrue(srv1.service.wait_for_opengrep_probe(timeout=10.0))
        _, d1, _, _, _ = self._http(f"{base1}/api/health")
        self.assertEqual(d1["status"], "DEGRADED")
        self.assertEqual(d1["opengrep"]["failure_code"], "VERSION_EXIT_NONZERO")
        self.assertEqual(d1["opengrep"]["version_exit_code"], 2)
        self.assertEqual(d1["opengrep"]["verification_level"], "BINARY_FOUND")

        w2, _ = _write_canary_wrapper(self.root / "exit_scan", scan_exit=3)
        srv2, base2 = self._start_api(str(w2))
        self.assertTrue(srv2.service.wait_for_opengrep_probe(timeout=10.0))
        _, d2, _, _, _ = self._http(f"{base2}/api/health")
        self.assertEqual(d2["status"], "DEGRADED")
        self.assertIn("OPENGREP_UNAVAILABLE", d2["degraded_reasons"])
        self.assertEqual(d2["opengrep"]["probe_status"], "CANARY_FAILED")
        self.assertEqual(d2["opengrep"]["failure_code"], "SCAN_EXIT_NONZERO")
        self.assertEqual(d2["opengrep"]["canary_exit_code"], 3)
        self.assertEqual(d2["opengrep"]["verification_level"], "VERSION_IDENTIFIED")
        self.assertTrue(d2["opengrep"]["verification_stages"]["version_identified"])
        self.assertFalse(d2["opengrep"]["verification_stages"]["scan_executed"])

    def test_06_scanner_timeout_kills_process_tree_and_reports_timeout(self) -> None:
        pid_file = self.root / "timeout_case" / "pids.txt"
        wrapper, _ = _write_canary_wrapper(
            self.root / "timeout_case",
            sleep_scan=20.0,
            spawn_grandchild_pid_file=pid_file,
        )
        srv, base = self._start_api(str(wrapper), probe_timeout=1.2)
        self.assertTrue(srv.service.wait_for_opengrep_probe(timeout=10.0))
        code, data, _, _, _ = self._http(f"{base}/api/health")
        self.assertEqual(code, 200)
        self.assertEqual(data["status"], "DEGRADED")
        self.assertIn("OPENGREP_UNAVAILABLE", data["degraded_reasons"])
        og = data["opengrep"]
        self.assertFalse(og["available"])
        self.assertEqual(og["probe_status"], "TIMEOUT")
        self.assertEqual(og["failure_code"], "PROBE_TIMEOUT")
        self.assertEqual(og["verification_level"], "VERSION_IDENTIFIED")

        # Verify grandchild process tree was killed cleanly
        if pid_file.is_file():
            pids = [int(x.strip()) for x in pid_file.read_text(encoding="utf-8").splitlines() if x.strip().isdigit()]
            self.assertGreaterEqual(len(pids), 2)
            for pid in pids:
                self.assertFalse(_is_os_pid_alive(pid), f"Grandchild/wrapper PID {pid} survived probe timeout cleanup!")
        self.assertEqual(intake._reconcile_lingering_git_jobs(0.2), 0)

    def test_07_invalid_json_and_scan_errors_fail_closed(self) -> None:
        cases = [
            ("corrupt_json", {"raw_scan_stdout": "{not-valid-json"}, "INVALID_JSON"),
            ("nan_json", {"raw_scan_stdout": '{"results": [], "errors": [], "score": NaN}'}, "INVALID_JSON"),
            ("non_dict_json", {"raw_scan_stdout": "[1, 2, 3]"}, "INVALID_JSON_ENVELOPE"),
            ("scan_errors", {"errors_list": [{"message": "Java parse error"}]}, "OPENGREP_SCAN_ERRORS"),
        ]
        for label, kwargs, exp_code in cases:
            with self.subTest(case=label):
                w, _ = _write_canary_wrapper(self.root / f"json_{label}", **kwargs)
                srv, base = self._start_api(str(w))
                self.assertTrue(srv.service.wait_for_opengrep_probe(timeout=10.0))
                _, data, _, _, _ = self._http(f"{base}/api/health")
                self.assertEqual(data["status"], "DEGRADED")
                self.assertFalse(data["opengrep"]["available"])
                self.assertEqual(data["opengrep"]["probe_status"], "CANARY_FAILED")
                self.assertEqual(data["opengrep"]["failure_code"], exp_code)
                self.assertEqual(data["opengrep"]["verification_level"], "VERSION_IDENTIFIED")

    def test_08_canary_oracle_mismatches_fail_closed(self) -> None:
        cases = [
            ("empty_results", {"include_cwe89": False, "include_cwe22": False}, "CANARY_ORACLE_MISMATCH"),
            ("missing_cwe22", {"include_cwe22": False}, "CANARY_ORACLE_MISMATCH"),
            ("wrong_line_sqli", {"cwe89_line": 9}, "CANARY_ORACLE_MISMATCH"),
            ("undeclared_rule_id", {"cwe89_rule_id": "fake.other.rule"}, "CANARY_ORACLE_MISMATCH"),
            ("missing_taint_trace", {"include_trace": False}, "CANARY_ORACLE_MISMATCH"),
            ("safe_control_flagged", {"flag_safe_control": True}, "CANARY_SAFE_CONTROL_VIOLATED"),
            ("json_version_mismatch", {"json_version": "1.33.1"}, "CANARY_VERSION_MISMATCH"),
            ("canary_not_in_scanned", {"scanned_paths_override": ["Other.java"]}, "CANARY_FILE_NOT_SCANNED"),
        ]
        for label, kwargs, exp_code in cases:
            with self.subTest(case=label):
                w, _ = _write_canary_wrapper(self.root / f"oracle_{label}", **kwargs)
                srv, base = self._start_api(str(w))
                self.assertTrue(srv.service.wait_for_opengrep_probe(timeout=10.0))
                _, data, _, _, _ = self._http(f"{base}/api/health")
                self.assertEqual(data["status"], "DEGRADED", data)
                self.assertIn("OPENGREP_UNAVAILABLE", data["degraded_reasons"])
                og = data["opengrep"]
                self.assertFalse(og["available"])
                self.assertFalse(og["runtime_verified"])
                self.assertEqual(og["probe_status"], "CANARY_FAILED")
                self.assertEqual(og["failure_code"], exp_code)
                # Proves SCAN_EXECUTED vs SCAN_VERIFIED distinction!
                self.assertEqual(og["verification_level"], "SCAN_EXECUTED")
                self.assertTrue(og["verification_stages"]["scan_executed"])
                self.assertFalse(og["verification_stages"]["scan_verified"])
                self.assertFalse(og["canary_summary"]["oracle_matched"])

    def test_09_rules_sha256_change_invalidates_and_reprobes(self) -> None:
        rules_mut = self.root / "rules_mut.yml"
        rules_mut.write_text(VALID_MINIMAL_RULES_YAML, encoding="utf-8")
        sha_v1 = digest(rules_mut.read_bytes())

        w, _ = _write_canary_wrapper(self.root / "rules_mut_og")
        srv, base = self._start_api(str(w), rules_path=rules_mut)
        self.assertTrue(srv.service.wait_for_opengrep_probe(timeout=10.0))
        _, d1, _, _, _ = self._http(f"{base}/api/health")
        self.assertEqual(d1["status"], "OK")
        self.assertEqual(d1["opengrep"]["rules_sha256"], sha_v1)

        # Mutate rules file to invalid empty rules -> immediate fail-closed invalidation!
        rules_mut.write_text("rules: []\n", encoding="utf-8")
        _, d2, _, _, _ = self._http(f"{base}/api/health")
        self.assertEqual(d2["status"], "DEGRADED")
        self.assertFalse(d2["opengrep"]["available"])
        self.assertEqual(d2["opengrep"]["invalidation_reason"], "RULES_SHA256_CHANGED")

        self.assertTrue(srv.service.wait_for_opengrep_probe(timeout=10.0))
        _, d3, _, _, _ = self._http(f"{base}/api/health")
        self.assertEqual(d3["status"], "DEGRADED")
        self.assertEqual(d3["opengrep"]["probe_status"], "RULES_INVALID")

        # Restore valid rules with a comment change (new SHA-256) -> re-verifies cleanly!
        rules_mut.write_text(VALID_MINIMAL_RULES_YAML + "# updated ruleset\n", encoding="utf-8")
        sha_v2 = digest(rules_mut.read_bytes())
        self.assertNotEqual(sha_v1, sha_v2)
        _, d4, _, _, _ = self._http(f"{base}/api/health")
        self.assertEqual(d4["status"], "DEGRADED")
        self.assertTrue(srv.service.wait_for_opengrep_probe(timeout=10.0))
        _, d5, _, _, _ = self._http(f"{base}/api/health")
        self.assertEqual(d5["status"], "OK", d5)
        self.assertEqual(d5["opengrep"]["rules_sha256"], sha_v2)

    def test_10_binary_and_wrapper_target_change_invalidates(self) -> None:
        w, target_script = _write_canary_wrapper(self.root / "bin_mut_og")
        srv, base = self._start_api(str(w))
        self.assertTrue(srv.service.wait_for_opengrep_probe(timeout=10.0))
        _, d1, _, _, _ = self._http(f"{base}/api/health")
        self.assertEqual(d1["status"], "OK")
        id_v1 = d1["opengrep"]["binary_identity_sha256"]

        # Modify ONLY the referenced Python bridge script without touching the .cmd wrapper!
        target_script.write_text(target_script.read_text(encoding="utf-8") + "\n# bridge modified\n", encoding="utf-8")
        _, d2, _, _, _ = self._http(f"{base}/api/health")
        self.assertEqual(d2["status"], "DEGRADED")
        self.assertFalse(d2["opengrep"]["available"])
        self.assertEqual(d2["opengrep"]["invalidation_reason"], "BINARY_IDENTITY_CHANGED")

        self.assertTrue(srv.service.wait_for_opengrep_probe(timeout=10.0))
        _, d3, _, _, _ = self._http(f"{base}/api/health")
        self.assertEqual(d3["status"], "OK")
        self.assertNotEqual(d3["opengrep"]["binary_identity_sha256"], id_v1)

        # Now modify the .cmd/.sh wrapper itself -> must also invalidate!
        w.write_text(w.read_text(encoding="utf-8") + ("\r\nrem wrapper updated\r\n" if os.name == "nt" else "\n# updated\n"), encoding="utf-8")
        _, d4, _, _, _ = self._http(f"{base}/api/health")
        self.assertEqual(d4["status"], "DEGRADED")
        self.assertEqual(d4["opengrep"]["invalidation_reason"], "BINARY_IDENTITY_CHANGED")
        self.assertTrue(srv.service.wait_for_opengrep_probe(timeout=10.0))
        _, d5, _, _, _ = self._http(f"{base}/api/health")
        self.assertEqual(d5["status"], "OK")

    def test_11_api_restart_starts_unverified_with_new_instance_id(self) -> None:
        shared_data = self.root / "restart_data"
        w_fast, _ = _write_canary_wrapper(self.root / "restart_og_fast")
        srv1, base1 = self._start_api(str(w_fast), data_dir=shared_data)
        self.assertTrue(srv1.service.wait_for_opengrep_probe(timeout=10.0))
        _, d1, _, _, _ = self._http(f"{base1}/api/health")
        self.assertEqual(d1["status"], "OK")
        inst1 = d1["opengrep"]["process_instance_id"]
        srv1.shutdown()
        srv1.server_close()

        # Restart a brand-new server instance on the SAME data_dir with a slow probe ->
        # MUST NOT inherit VERIFIED from dead instance 1!
        w_slow, _ = _write_canary_wrapper(self.root / "restart_og_slow", sleep_scan=1.2)
        srv2, base2 = self._start_api(str(w_slow), data_dir=shared_data)
        _, d2_before, _, elapsed, _ = self._http(f"{base2}/api/health")
        self.assertLess(elapsed, 0.6)
        self.assertEqual(d2_before["status"], "DEGRADED")
        self.assertIn("OPENGREP_NOT_VERIFIED", d2_before["degraded_reasons"])
        self.assertFalse(d2_before["opengrep"]["available"])
        self.assertEqual(d2_before["opengrep"]["probe_status"], "NOT_VERIFIED")
        self.assertNotEqual(d2_before["opengrep"]["process_instance_id"], inst1)

        # Once instance 2 completes its own real probe -> transitions to VERIFIED / OK
        self.assertTrue(srv2.service.wait_for_opengrep_probe(timeout=10.0))
        _, d2_after, _, _, _ = self._http(f"{base2}/api/health")
        self.assertEqual(d2_after["status"], "OK")
        self.assertEqual(d2_after["opengrep"]["probe_status"], "VERIFIED")
        self.assertEqual(d2_after["opengrep"]["process_instance_id"], d2_before["opengrep"]["process_instance_id"])

    def test_12_snapshot_ttl_expiry_fails_closed_and_refreshes(self) -> None:
        now_box = {"t": 1000.0}
        w, _ = _write_canary_wrapper(self.root / "ttl_og")
        cfg = ApiConfig(
            host="127.0.0.1",
            port=0,
            data_dir=self.root / "ttl_data",
            rules_path=self.rules_file,
            opengrep_binary=str(w),
            ollama_endpoint=self.ollama_url,
            api_token=TEST_TOKEN,
            opengrep_health_probe_ttl_seconds=60.0,
        )
        probe = OpenGrepHealthProbe(cfg, clock=lambda: now_box["t"])
        self.addCleanup(probe.shutdown)

        self.assertTrue(probe.start_background_probe())
        self.assertTrue(probe.wait_for_probe(timeout=10.0))
        st1 = probe.get_status()
        self.assertTrue(st1["available"])
        self.assertEqual(st1["probe_status"], "VERIFIED")
        self.assertEqual(probe.probe_run_count(), 1)

        # Advance fake clock past TTL -> MUST fail-closed immediately (EXPIRED, available=False) and trigger refresh
        now_box["t"] += 61.0
        st_exp = probe.get_status(trigger_refresh=True)
        self.assertFalse(st_exp["available"])
        self.assertFalse(st_exp["runtime_verified"])
        self.assertEqual(st_exp["probe_status"], "EXPIRED")
        self.assertEqual(st_exp["invalidation_reason"], "SNAPSHOT_EXPIRED")

        self.assertTrue(probe.wait_for_probe(timeout=10.0))
        st2 = probe.get_status()
        self.assertTrue(st2["available"])
        self.assertEqual(st2["probe_status"], "VERIFIED")
        self.assertEqual(probe.probe_run_count(), 2)

    def test_13_repeated_health_gets_never_reinvoke_opengrep(self) -> None:
        log_f = self.root / "repeat_og" / "inv.log"
        w, _ = _write_canary_wrapper(self.root / "repeat_og", log_file=log_f)
        srv, base = self._start_api(str(w))
        self.assertTrue(srv.service.wait_for_opengrep_probe(timeout=10.0))

        inv_before = len(log_f.read_text(encoding="utf-8").splitlines())
        self.assertEqual(inv_before, 2, "Initial probe runs exactly 1 --version + 1 canary scan")
        for _ in range(12):
            code, data, _, elapsed, _ = self._http(f"{base}/api/health")
            self.assertEqual(code, 200)
            self.assertLess(elapsed, 0.3)
            self.assertEqual(data["status"], "OK")
        inv_after = len(log_f.read_text(encoding="utf-8").splitlines())
        self.assertEqual(inv_after, inv_before, "Repeated GET /api/health must NEVER re-run OpenGrep!")
        self.assertEqual(srv.service._opengrep_probe.probe_run_count(), 1)

    def test_14_concurrent_health_gets_single_flight_no_duplicate_probes(self) -> None:
        log_f = self.root / "conc_og" / "inv.log"
        w, _ = _write_canary_wrapper(self.root / "conc_og", sleep_scan=1.0, log_file=log_f)
        srv, base = self._start_api(str(w))

        results = []
        lock = threading.Lock()
        barrier = threading.Barrier(10)

        def worker():
            barrier.wait(timeout=3.0)
            r = self._http(f"{base}/api/health")
            with lock:
                results.append(r)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)

        self.assertEqual(len(results), 10)
        for code, data, _, elapsed, _ in results:
            self.assertEqual(code, 200)
            self.assertLess(elapsed, 0.6)
            self.assertEqual(data["status"], "DEGRADED")
            self.assertEqual(data["opengrep"]["probe_status"], "NOT_VERIFIED")

        self.assertTrue(srv.service.wait_for_opengrep_probe(timeout=10.0))
        _, d_final, _, _, _ = self._http(f"{base}/api/health")
        self.assertEqual(d_final["status"], "OK")
        self.assertEqual(srv.service._opengrep_probe.probe_run_count(), 1)
        self.assertEqual(len(log_f.read_text(encoding="utf-8").splitlines()), 2)

    def test_15_unauthenticated_health_minimal_and_never_triggers_probe(self) -> None:
        log_f = self.root / "unauth_og" / "inv.log"
        w, _ = _write_canary_wrapper(self.root / "unauth_og", log_file=log_f)
        # Start with probe disabled or check direct TriageApiService without startup trigger
        cfg = ApiConfig(
            host="127.0.0.1",
            port=0,
            data_dir=self.root / "unauth_data",
            rules_path=self.rules_file,
            opengrep_binary=str(w),
            ollama_endpoint=self.ollama_url,
            api_token=TEST_TOKEN,
            read_auth_mode="required",
        )
        svc = TriageApiService(cfg)
        self.addCleanup(svc.shutdown_opengrep_probe)
        unauth = svc.health(authenticated=False)
        self.assertEqual(
            set(unauth.keys()),
            {
                "status",
                "api_ready",
                "service",
                "api_version",
                "contract_schema",
                "auth_required",
                "write_auth_required",
                "authenticated",
            },
        )
        self.assertEqual(unauth["status"], "AUTH_REQUIRED")
        self.assertFalse(unauth["authenticated"])
        self.assertFalse(log_f.exists(), "Unauthenticated /api/health must NEVER trigger OpenGrep probes!")

    def test_16_and_17_authenticated_contract_cors_bearer_and_frontend_parity(self) -> None:
        w, _ = _write_canary_wrapper(self.root / "contract_og")
        srv, base = self._start_api(str(w))
        self.assertTrue(srv.service.wait_for_opengrep_probe(timeout=10.0))

        # Forbidden CORS origin -> 403
        c_forb, d_forb, hdr_forb, _, _ = self._http(f"{base}/api/health", origin="https://evil.example")
        self.assertEqual(c_forb, 403)
        self.assertEqual(d_forb["error_code"], "CORS_ORIGIN_FORBIDDEN")
        self.assertNotIn("Access-Control-Allow-Origin", hdr_forb)

        # Wrong Bearer token -> AUTH_REQUIRED on /api/health, 401 on /api/scans
        c_bad, d_bad, _, _, _ = self._http(f"{base}/api/health", token="wrong-token-123456")
        self.assertEqual(c_bad, 200)
        self.assertEqual(d_bad["status"], "AUTH_REQUIRED")
        c_401, d_401, _, _, _ = self._http(f"{base}/api/scans", token="wrong-token-123456")
        self.assertEqual(c_401, 401)
        self.assertEqual(d_401["error_code"], "UNAUTHORIZED")

        # Valid token + allowed CORS origin -> full contract matching frontend AppShell/StatusPage/findingPresentation
        c_ok, data, hdr_ok, _, _ = self._http(f"{base}/api/health", origin="http://localhost:5173")
        self.assertEqual(c_ok, 200)
        self.assertEqual(hdr_ok.get("Access-Control-Allow-Origin"), "http://localhost:5173")
        required_top = {
            "status", "api_ready", "service", "api_version", "contract_schema",
            "triage_schema_version", "prompt_version", "prompt_contract", "architecture",
            "auth_required", "write_auth_required", "write_auth_configured", "authenticated",
            "degraded_reasons", "opengrep", "ollama", "git_available", "rules",
            "source_inventory_limits", "job_limits", "checked_at",
        }
        self.assertTrue(required_top.issubset(set(data.keys())))
        self.assertEqual(data["status"], "OK")
        self.assertEqual(data["service"], "ntk-thesis-api")
        self.assertEqual(data["api_version"], "1.0.0")
        self.assertEqual(data["contract_schema"], "ntk-thesis-web-api-1")
        self.assertEqual(data["degraded_reasons"], [])
        self.assertTrue(data["opengrep"]["available"])
        self.assertEqual(data["opengrep"]["version"], "1.25.0")
        self.assertNotIn("model_runtime_verified", data["ollama"])

    def test_18_failed_opengrep_or_other_degraded_never_reports_ok(self) -> None:
        w, _ = _write_canary_wrapper(self.root / "dep_og")

        # 1. OpenGrep VERIFIED + Ollama unreachable -> DEGRADED (OLLAMA_UNREACHABLE)
        srv1, base1 = self._start_api(str(w), ollama_endpoint="http://127.0.0.1:65532")
        self.assertTrue(srv1.service.wait_for_opengrep_probe(timeout=10.0))
        _, d1, _, _, _ = self._http(f"{base1}/api/health")
        self.assertEqual(d1["status"], "DEGRADED")
        self.assertTrue(d1["opengrep"]["available"])
        self.assertIn("OLLAMA_UNREACHABLE", d1["degraded_reasons"])
        self.assertNotIn("OPENGREP_NOT_VERIFIED", d1["degraded_reasons"])

        # 2. OpenGrep VERIFIED + api_token missing -> DEGRADED (WRITE_AUTH_TOKEN_NOT_CONFIGURED)
        srv2, base2 = self._start_api(str(w), api_token=None, read_auth_mode="write-only")
        self.assertTrue(srv2.service.wait_for_opengrep_probe(timeout=10.0))
        _, d2, _, _, _ = self._http(f"{base2}/api/health", token=None)
        self.assertEqual(d2["status"], "DEGRADED")
        self.assertTrue(d2["opengrep"]["available"])
        self.assertIn("WRITE_AUTH_TOKEN_NOT_CONFIGURED", d2["degraded_reasons"])

        # 3. OpenGrep VERIFIED + rules file deleted -> DEGRADED (RULES_UNAVAILABLE + OPENGREP_UNAVAILABLE)
        del_rules = self.root / "deletable_rules.yml"
        del_rules.write_text(VALID_MINIMAL_RULES_YAML, encoding="utf-8")
        srv3, base3 = self._start_api(str(w), rules_path=del_rules)
        self.assertTrue(srv3.service.wait_for_opengrep_probe(timeout=10.0))
        _, d3_ok, _, _, _ = self._http(f"{base3}/api/health")
        self.assertEqual(d3_ok["status"], "OK")
        del_rules.unlink()
        _, d3_del, _, _, _ = self._http(f"{base3}/api/health")
        self.assertEqual(d3_del["status"], "DEGRADED")
        self.assertFalse(d3_del["opengrep"]["available"])
        self.assertIn("RULES_UNAVAILABLE", d3_del["degraded_reasons"])
        self.assertIn("OPENGREP_UNAVAILABLE", d3_del["degraded_reasons"])

    def test_19_probe_does_not_interfere_with_scan_jobs_and_defers_during_stage2(self) -> None:
        w, _ = _write_canary_wrapper(self.root / "scan_job_og")
        srv, base = self._start_api(str(w))
        self.assertTrue(srv.service.wait_for_opengrep_probe(timeout=10.0))
        _, d_h, _, _, _ = self._http(f"{base}/api/health")
        self.assertEqual(d_h["status"], "OK")

        # Test Stage 2 deferral: when busy_check returns True and TTL expires, probe fails closed (EXPIRED)
        # and defers launching a new OpenGrep subprocess until Stage 2 finishes!
        busy = {"active": True}
        now_box = {"t": 100.0}
        probe = OpenGrepHealthProbe(srv.api_config, clock=lambda: now_box["t"], scan_busy_check=lambda: busy["active"])
        self.addCleanup(probe.shutdown)
        busy["active"] = False
        self.assertTrue(probe.start_background_probe())
        self.assertTrue(probe.wait_for_probe(timeout=10.0))
        self.assertEqual(probe.get_status()["probe_status"], "VERIFIED")
        busy["active"] = True
        now_box["t"] += 400.0
        st_def = probe.get_status(trigger_refresh=True)
        self.assertFalse(st_def["available"])
        self.assertEqual(st_def["probe_status"], "EXPIRED")
        self.assertTrue(st_def["deferred_by_active_scan"])
        self.assertEqual(probe.probe_run_count(), 1, "Must not spawn probe while Stage 2 scan is active!")
        busy["active"] = False
        probe.get_status(trigger_refresh=True)
        self.assertTrue(probe.wait_for_probe(timeout=10.0))
        self.assertEqual(probe.get_status()["probe_status"], "VERIFIED")
        self.assertEqual(probe.probe_run_count(), 2)

        # Submit a real ZIP scan job -> completes cleanly and preserves SQLite/findings
        ct, body = _make_multipart_zip("demo.zip", _make_java_zip())
        c_sub, j_sub, _, _, _ = self._http(f"{base}/api/scan-jobs", method="POST", body=body, content_type=ct)
        self.assertEqual(c_sub, 202)
        jid = j_sub["job_id"]
        j_cur = None
        for _ in range(80):
            _, j_cur, _, _, _ = self._http(f"{base}/api/scan-jobs/{jid}")
            if j_cur["state"] in ("COMPLETED", "FAILED"):
                break
            time.sleep(0.1)
        self.assertEqual(j_cur["state"], "COMPLETED", j_cur)
        _, findings, _, _, _ = self._http(f"{base}/api/scans/{j_cur['scan_id']}/findings")
        self.assertEqual(findings["total_count"], 1)

    def test_20_shutdown_cancels_inflight_probe_bounded_and_clean(self) -> None:
        pid_file = self.root / "shutdown_cancel" / "pids.txt"
        w, _ = _write_canary_wrapper(
            self.root / "shutdown_cancel",
            sleep_version=25.0,
            spawn_grandchild_pid_file=pid_file,
        )
        srv, base = self._start_api(str(w), probe_timeout=25.0)
        deadline = time.monotonic() + 5.0
        while not pid_file.is_file() and time.monotonic() < deadline:
            time.sleep(0.05)

        t0 = time.monotonic()
        srv.shutdown()
        srv.server_close()
        close_elapsed = time.monotonic() - t0
        self.assertLess(close_elapsed, 4.0, f"Shutdown hung waiting for in-flight probe ({close_elapsed:.2f}s)")

        if pid_file.is_file():
            pids = [int(x.strip()) for x in pid_file.read_text(encoding="utf-8").splitlines() if x.strip().isdigit()]
            for pid in pids:
                self.assertFalse(_is_os_pid_alive(pid), f"PID {pid} survived shutdown cancellation!")

        after = srv.service.probe_opengrep()
        self.assertFalse(after["available"])
        self.assertEqual(after["probe_status"], "SHUTTING_DOWN")
        self.assertEqual(intake._reconcile_lingering_git_jobs(0.2), 0)

    def test_21_wsl_identity_honors_full_step_timeout_and_distinguishes_timeout_vs_missing_and_recovers(self) -> None:
        """P2.1: WSL identity MUST NOT clamp timeout to 15s, MUST distinguish missing vs timeout vs not-verified,
        preserve post-TOCTOU timeout/cleanup priority, and recover via real canary re-probe after Stage 2."""
        from unittest.mock import patch

        # 1. Missing binary -> health_state=ENGINE_MISSING, binary_present=False, NO OPENGREP_PROBE_TIMEOUT
        srv_miss, base_miss = self._start_api("opengrep-p21-missing-xyz")
        self.assertTrue(srv_miss.service.wait_for_opengrep_probe(timeout=2.0))
        _, d_miss, _, _, _ = self._http(f"{base_miss}/api/health")
        self.assertEqual(d_miss["opengrep"]["health_state"], "ENGINE_MISSING")
        self.assertFalse(d_miss["opengrep"]["binary_present"])
        self.assertEqual(d_miss["degraded_reasons"], ["OPENGREP_UNAVAILABLE"])

        # 2. WSL wrapper configured with probe_timeout=42.0 -> every WSL step receives full 42.0s (not 15.0s cap!)
        wdir = self.root / "wsl_p21"
        wdir.mkdir(parents=True, exist_ok=True)
        bridge = wdir / "bridge.py"
        bridge.write_text(
            "import subprocess, sys\n"
            'cmd = ["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep", *sys.argv[1:]]\n'
            "subprocess.run(cmd, check=False)\n",
            encoding="utf-8",
        )
        wrapper = wdir / ("opengrep_wsl.cmd" if os.name == "nt" else "opengrep_wsl.sh")
        if os.name == "nt":
            wrapper.write_text(f'@echo off\r\n"{sys.executable}" "{bridge}" %*\r\n', encoding="utf-8")
        else:
            wrapper.write_text(f'#!/bin/sh\n"{sys.executable}" "{bridge}" "$@"\n', encoding="utf-8")
            wrapper.chmod(0o755)

        cfg = ApiConfig(
            host="127.0.0.1",
            port=0,
            data_dir=self.root / "wsl_p21_data",
            rules_path=self.rules_file,
            opengrep_binary=str(wrapper),
            ollama_endpoint=self.ollama_url,
            api_token=TEST_TOKEN,
            opengrep_health_probe_timeout_seconds=42.0,
        )
        seen_timeouts: list[tuple[str, float]] = []

        def timeout_on_realpath(step, args, **kw):
            seen_timeouts.append((step, float(kw.get("timeout_seconds", -1.0))))
            raise intake._GitStepTimeout(step, {"clean": True, "step": step}, stderr_bytes=0)

        probe = OpenGrepHealthProbe(cfg)
        self.addCleanup(probe.shutdown)
        with patch.object(intake, "_run_git_step", side_effect=timeout_on_realpath):
            snap_to, *_ = probe._execute_probe_once()
        self.assertEqual(seen_timeouts, [("opengrep-health-wsl-realpath", 42.0)])
        self.assertEqual(snap_to["probe_status"], "TIMEOUT")
        self.assertEqual(snap_to["health_state"], "PROBE_TIMEOUT")
        self.assertTrue(snap_to["binary_present"])
        self.assertEqual(snap_to["probe_stage_failed"], "wsl_binary_identity:realpath")
        self.assertEqual(snap_to["step_timeout_seconds"], 42.0)
        self.assertIn("42.0s", snap_to["error"])

        # 3. Real HTTP health on timeout surfaces OPENGREP_PROBE_TIMEOUT (distinct from missing binary)
        w_slow, _ = _write_canary_wrapper(self.root / "p21_timeout", sleep_scan=10.0)
        srv_to, base_to = self._start_api(str(w_slow), probe_timeout=0.9, failure_ttl=60.0)
        self.assertTrue(srv_to.service.wait_for_opengrep_probe(timeout=10.0))
        _, d_to, _, _, _ = self._http(f"{base_to}/api/health")
        self.assertEqual(d_to["status"], "DEGRADED")
        self.assertIn("OPENGREP_PROBE_TIMEOUT", d_to["degraded_reasons"])
        self.assertEqual(d_to["opengrep"]["probe_status"], "TIMEOUT")
        self.assertEqual(d_to["opengrep"]["health_state"], "PROBE_TIMEOUT")
        self.assertTrue(d_to["opengrep"]["binary_present"])
        self.assertEqual(d_to["opengrep"]["probe_stage_failed"], "canary_scan")

        # 4. notify_real_scan_completed NEVER fakes VERIFIED, only triggers real background canary re-probe
        w_rec, _ = _write_canary_wrapper(self.root / "p21_recover")
        srv_rec, base_rec = self._start_api(str(w_rec), probe_enabled=False)
        st_before = srv_rec.service.probe_opengrep(trigger_refresh=False)
        self.assertFalse(st_before["available"])
        self.assertEqual(st_before["health_state"], "NOT_VERIFIED")
        # Even after real scan completion, when probe is disabled, available MUST stay False!
        self.assertFalse(srv_rec.service.notify_real_opengrep_scan_completed(engine_version="1.25.0"))
        st_after_disabled = srv_rec.service.probe_opengrep(trigger_refresh=False)
        self.assertFalse(st_after_disabled["available"])
        self.assertEqual(st_after_disabled["probe_status"], "NOT_VERIFIED")
        self.assertEqual(st_after_disabled["last_real_scan_observed"]["engine_version"], "1.25.0")

        # When probe is enabled and stuck in TIMEOUT cooldown, notify_real_scan_completed triggers a REAL canary probe
        srv_rec2, base_rec2 = self._start_api(str(w_rec), probe_timeout=15.0, failure_ttl=120.0)
        self.assertTrue(srv_rec2.service.wait_for_opengrep_probe(timeout=10.0))
        # Simulate prior cold-start TIMEOUT snapshot with long cooldown
        with srv_rec2.service._opengrep_probe._lock:
            srv_rec2.service._opengrep_probe._snapshot["probe_status"] = "TIMEOUT"
            srv_rec2.service._opengrep_probe._snapshot["available"] = False
            srv_rec2.service._opengrep_probe._snapshot["runtime_verified"] = False
            srv_rec2.service._opengrep_probe._snapshot["health_state"] = "PROBE_TIMEOUT"
            srv_rec2.service._opengrep_probe._snapshot_expires_mono = time.monotonic() + 120.0
        runs_before = srv_rec2.service._opengrep_probe.probe_run_count()
        self.assertTrue(srv_rec2.service.notify_real_opengrep_scan_completed(engine_version="1.25.0"))
        self.assertTrue(srv_rec2.service.wait_for_opengrep_probe(timeout=10.0))
        _, d_rec, _, _, _ = self._http(f"{base_rec2}/api/health")
        self.assertEqual(d_rec["status"], "OK")
        self.assertTrue(d_rec["opengrep"]["available"])
        self.assertEqual(d_rec["opengrep"]["health_state"], "VERIFIED")
        self.assertEqual(srv_rec2.service._opengrep_probe.probe_run_count(), runs_before + 1)

        # 5. Post-scan WSL TOCTOU CLEANUP_FAILED MUST NOT be swallowed as INPUT_CHANGED_DURING_PROBE
        call_n = {"rl": 0}
        real_canary_w, _ = _write_canary_wrapper(self.root / "p21_post_src")
        def post_cleanup_fail(step, args, **kw):
            if step == "opengrep-health-wsl-realpath":
                call_n["rl"] += 1
                if call_n["rl"] == 2:
                    raise intake._GitStepCleanupFailed(
                        step, 0, {"clean": False, "step": step, "remaining_processes": 1}
                    )
                return subprocess.CompletedProcess(args, 0, b"/usr/local/bin/opengrep\n", b"")
            if step == "opengrep-health-wsl-sha256":
                return subprocess.CompletedProcess(args, 0, b"a" * 64 + b"  /usr/local/bin/opengrep\n", b"")
            if step == "opengrep-health-wsl-version":
                return subprocess.CompletedProcess(args, 0, b"1.25.0\n", b"")
            # Delegate wrapper --version and canary scan to real stub script
            rewritten = [str(real_canary_w), *args[1:]]
            return subprocess.run(rewritten, capture_output=True, timeout=10)

        probe_post = OpenGrepHealthProbe(cfg)
        self.addCleanup(probe_post.shutdown)
        with patch.object(intake, "_run_git_step", side_effect=post_cleanup_fail):
            snap_cf, *_ = probe_post._execute_probe_once()
        self.assertFalse(snap_cf["available"])
        self.assertEqual(snap_cf["probe_status"], "CLEANUP_FAILED", snap_cf)
        self.assertEqual(snap_cf["health_state"], "CLEANUP_FAILED")
        self.assertEqual(snap_cf["failure_code"], "PROBE_CLEANUP_FAILED")
        self.assertEqual(snap_cf["probe_stage_failed"], "wsl_binary_identity:post_realpath")


if __name__ == "__main__":
    unittest.main()
