"""Regression tests for Stage D & E fixes: Windows TCP RST, SARIF parity error code, 0-finding scan, JSONL SHA cache."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import zipfile

from v2.api.config import ApiConfig, DEFAULT_BACKEND_RULES
from v2.api.server import ThesisApiServer
from v2.api.service import ApiServiceError, TriageApiService
from v2.triage.evidence import digest


def _make_java_zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content.encode("utf-8"))
    return buf.getvalue()


def _create_fake_opengrep(root: Path, script_body: str, subdir: str = "bin") -> str:
    bin_dir = root / subdir
    bin_dir.mkdir(parents=True, exist_ok=True)
    py_file = bin_dir / "opengrep_stub.py"
    py_file.write_text(script_body, encoding="utf-8")
    if os.name == "nt":
        cmd = bin_dir / "opengrep.cmd"
        cmd.write_text(f'@echo off\r\n"{sys.executable}" "{py_file}" %*\r\n', encoding="utf-8")
        return str(cmd)
    sh = bin_dir / "opengrep"
    sh.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{py_file}" "$@"\n', encoding="utf-8")
    sh.chmod(0o755)
    return str(sh)


class ApiFixesAndPerformanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.rules = self.root / "rules.yml"
        self.rules.write_text("rules: []\n", encoding="utf-8")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_api_config_defaults_to_backend_rules_and_cache_opt_in(self) -> None:
        cfg = ApiConfig(data_dir=self.root / "data")
        self.assertEqual(cfg.rules_path, DEFAULT_BACKEND_RULES.resolve())
        self.assertEqual(cfg.rules_path.name, "java_cwe22_cwe89.yml")
        self.assertFalse(cfg.enable_qwen_cache)
        self.assertEqual(cfg.max_prompt_bytes, 32_000)

    def test_post_early_503_and_401_with_connection_close_no_tcp_rst(self) -> None:
        # Unconfigured token -> HTTP 503 with explicit Connection: close (reproduces WinError 10053)
        cfg_no_tok = ApiConfig(
            host="127.0.0.1",
            port=0,
            data_dir=self.root / "data_notok",
            api_token=None,
            read_auth_mode="write-only",
            rules_path=self.rules,
            runtime_origin="mock",
        )
        srv = ThesisApiServer(cfg_no_tok)
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        try:
            url = f"http://127.0.0.1:{srv.server_port}/api/scan-jobs"
            body = json.dumps({"repo_url": "https://github.com/org/repo"}).encode("utf-8")
            for _ in range(3):
                req = Request(
                    url,
                    data=body,
                    method="POST",
                    headers={"Content-Type": "application/json", "Connection": "close"},
                )
                with self.assertRaises(HTTPError) as ctx:
                    urlopen(req, timeout=5)
                self.assertEqual(ctx.exception.code, 503)
                doc = json.loads(ctx.exception.read().decode("utf-8"))
                self.assertEqual(doc["error_code"], "AUTH_TOKEN_NOT_CONFIGURED")
        finally:
            srv.shutdown()
            srv.server_close()

        # Configured token, wrong credentials -> HTTP 401 with Connection: close
        cfg_tok = ApiConfig(
            host="127.0.0.1",
            port=0,
            data_dir=self.root / "data_tok",
            api_token="secret-valid-token-1234",
            read_auth_mode="required",
            rules_path=self.rules,
            runtime_origin="mock",
        )
        srv2 = ThesisApiServer(cfg_tok)
        th2 = threading.Thread(target=srv2.serve_forever, daemon=True)
        th2.start()
        try:
            url = f"http://127.0.0.1:{srv2.server_port}/api/scan-jobs"
            body = json.dumps({"repo_url": "https://github.com/org/repo"}).encode("utf-8")
            req = Request(
                url,
                data=body,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer wrong-token",
                    "Connection": "close",
                },
            )
            with self.assertRaises(HTTPError) as ctx:
                urlopen(req, timeout=5)
            self.assertEqual(ctx.exception.code, 401)
            doc = json.loads(ctx.exception.read().decode("utf-8"))
            self.assertEqual(doc["error_code"], "UNAUTHORIZED")
        finally:
            srv2.shutdown()
            srv2.server_close()

    def test_json_sarif_parity_mismatch_reports_exact_error_code(self) -> None:
        fake_og = _create_fake_opengrep(
            self.root,
            """
import json, pathlib, sys
args = sys.argv[1:]
if "--version" in args:
    print("1.25.0")
    raise SystemExit(0)
target = pathlib.Path(args[-1])
java_file = sorted(target.rglob("*.java"))[0]
if "--sarif" in args:
    # Intentionally mismatched empty SARIF results vs 1 JSON finding!
    print(json.dumps({"version": "2.1.0", "runs": [{"results": []}]}))
    raise SystemExit(0)
print(json.dumps({
    "version": "1.25.0",
    "results": [{
        "check_id": "ntk.api.java.cwe89.sql-injection",
        "path": str(java_file),
        "start": {"line": 1, "col": 1},
        "end": {"line": 1, "col": 10},
        "extra": {"severity": "ERROR", "metadata": {"cwe": ["CWE-89"]}},
    }],
    "errors": [],
    "paths": {"scanned": [str(java_file)], "skipped": []},
}))
raise SystemExit(0)
""",
            subdir="og_mismatch",
        )
        cfg = ApiConfig(
            host="127.0.0.1",
            port=0,
            data_dir=self.root / "data_parity",
            api_token="parity-test-token-1234",
            opengrep_binary=fake_og,
            rules_path=self.rules,
            runtime_origin="mock",
        )
        srv = ThesisApiServer(cfg)
        try:
            zbytes = _make_java_zip({"A.java": "public class A {}\n"})
            job = srv.jobs.submit_zip_job("a.zip", zbytes, no_llm=True)
            deadline = time.monotonic() + 15.0
            while time.monotonic() < deadline:
                cur = srv.jobs.get_job(job["job_id"])
                if cur["state"] in ("COMPLETED", "FAILED"):
                    break
                time.sleep(0.05)
            cur = srv.jobs.get_job(job["job_id"])
            self.assertEqual(cur["state"], "FAILED")
            self.assertEqual(cur["error_code"], "JSON_SARIF_PARITY_MISMATCH")
        finally:
            srv.server_close()

    def test_zero_findings_scan_with_llm_enabled_completes_cleanly(self) -> None:
        fake_og = _create_fake_opengrep(
            self.root,
            """
import json, pathlib, sys
args = sys.argv[1:]
if "--version" in args:
    print("1.25.0")
    raise SystemExit(0)
target = pathlib.Path(args[-1])
java_files = [str(p) for p in sorted(target.rglob("*.java"))]
if "--sarif" in args:
    print(json.dumps({"version": "2.1.0", "runs": [{"results": []}]}))
    raise SystemExit(0)
print(json.dumps({"version": "1.25.0", "results": [], "errors": [], "paths": {"scanned": java_files, "skipped": []}}))
raise SystemExit(0)
""",
            subdir="og_zero",
        )
        cfg = ApiConfig(
            host="127.0.0.1",
            port=0,
            data_dir=self.root / "data_zero",
            api_token="zero-test-token-1234",
            opengrep_binary=fake_og,
            rules_path=self.rules,
            ollama_endpoint="http://127.0.0.1:1",  # unreachable ok when 0 findings; tags probe fails gracefully
            ollama_timeout_seconds=1.5,
            runtime_origin="mock",
        )
        srv = ThesisApiServer(cfg)
        try:
            zbytes = _make_java_zip({"Clean.java": "public class Clean { int ok() { return 1; } }\n"})
            job = srv.jobs.submit_zip_job("clean.zip", zbytes, no_llm=False)
            deadline = time.monotonic() + 20.0
            while time.monotonic() < deadline:
                cur = srv.jobs.get_job(job["job_id"])
                if cur["state"] in ("COMPLETED", "FAILED"):
                    break
                time.sleep(0.05)
            cur = srv.jobs.get_job(job["job_id"])
            self.assertEqual(cur["state"], "COMPLETED", cur)
            self.assertEqual(cur["stage_statuses"]["qwen_inference_status"], "NO_FINDINGS")
            self.assertEqual(cur["stage_statuses"]["http_capture_status"], "NO_FINDINGS")
            cap_file = (self.root / "data_zero" / "scans" / cur["job_id"] / "triage" / "http-capture-check.json")
            cap_doc = json.loads(cap_file.read_text(encoding="utf-8"))
            self.assertTrue(cap_doc["capture_integrity_ok"])
            self.assertEqual(cap_doc["capture_status"], "NO_FINDINGS")
            proto_file = (self.root / "data_zero" / "scans" / cur["job_id"] / "triage" / "live-protocol-check.json")
            proto_doc = json.loads(proto_file.read_text(encoding="utf-8"))
            self.assertEqual(proto_doc["protocol_status"], "PENDING")
            self.assertEqual(proto_doc["completed_reported_responses"], 0)
        finally:
            srv.server_close()

    def test_jsonl_sha256_cache_speeds_reads_and_detects_single_byte_tamper(self) -> None:
        cfg = ApiConfig(data_dir=self.root / "data_cache", rules_path=self.rules, runtime_origin="mock")
        svc = TriageApiService(cfg)
        jsonl_file = self.root / "assessments.jsonl"
        row = {
            "id": "a" * 64,
            "evidence": {"id": "a" * 64, "cwe": ["CWE-89"], "snippets": [], "issues": []},
            "assessment": {"status": "SUPPORTED", "runtime": {"origin": "unverified"}, "citations": []},
        }
        payload = "\n".join(json.dumps(row) for _ in range(150)) + "\n"
        jsonl_file.write_text(payload, encoding="utf-8")
        before_sha = digest(jsonl_file.read_bytes())

        t0 = time.monotonic()
        rows1, mock1 = svc._inspect_assessments_jsonl(jsonl_file, need_rows=False)
        cold_ms = (time.monotonic() - t0) * 1000.0
        self.assertEqual(rows1, [])
        self.assertFalse(mock1)

        t1 = time.monotonic()
        rows2, mock2 = svc._inspect_assessments_jsonl(jsonl_file, need_rows=False)
        warm_ms = (time.monotonic() - t1) * 1000.0
        self.assertEqual(rows2, [])
        self.assertFalse(mock2)
        self.assertEqual(digest(jsonl_file.read_bytes()), before_sha)
        # Warm hit avoids strict_json across all 150 rows
        self.assertLessEqual(warm_ms, cold_ms + 5.0)

        # Single-byte tamper (same exact file length AND same exact mtime!) MUST miss cache and raise 409 immediately!
        orig_stat = jsonl_file.stat()
        tampered = payload.replace('"SUPPORTED"', '"SUPPORTED', 1) + " "
        self.assertEqual(len(tampered.encode("utf-8")), len(payload.encode("utf-8")))
        jsonl_file.write_text(tampered, encoding="utf-8")
        os.utime(jsonl_file, ns=(orig_stat.st_atime_ns, orig_stat.st_mtime_ns))
        self.assertEqual(jsonl_file.stat().st_size, orig_stat.st_size)
        self.assertEqual(jsonl_file.stat().st_mtime_ns, orig_stat.st_mtime_ns)
        with self.assertRaises(ApiServiceError) as ctx:
            svc._inspect_assessments_jsonl(jsonl_file, need_rows=False)
        self.assertEqual(ctx.exception.http_status, 409)
        self.assertEqual(ctx.exception.error_code, "ARTIFACT_PROVENANCE_MISMATCH")

        # Valid-JSON single-byte tamper preserving exact size & mtime also misses SHA-256 cache (returns mutated row)!
        jsonl_file.write_text(payload, encoding="utf-8")
        os.utime(jsonl_file, ns=(orig_stat.st_atime_ns, orig_stat.st_mtime_ns))
        rows_clean, _ = svc._inspect_assessments_jsonl(jsonl_file, need_rows=True)
        self.assertEqual(rows_clean[0]["assessment"]["status"], "SUPPORTED")
        valid_tampered = payload.replace('"SUPPORTED"', '"SUPPORTEX"', 1)
        self.assertEqual(len(valid_tampered.encode("utf-8")), len(payload.encode("utf-8")))
        jsonl_file.write_text(valid_tampered, encoding="utf-8")
        os.utime(jsonl_file, ns=(orig_stat.st_atime_ns, orig_stat.st_mtime_ns))
        rows_after, _ = svc._inspect_assessments_jsonl(jsonl_file, need_rows=True)
        self.assertEqual(rows_after[0]["assessment"]["status"], "SUPPORTEX")

    def test_connection_close_with_incomplete_slow_trickle_post_body_respects_drain_deadline(self) -> None:
        cfg = ApiConfig(
            host="127.0.0.1",
            port=0,
            data_dir=self.root / "data_close_trickle",
            api_token="close-trickle-token-1234",
            read_auth_mode="required",
            rules_path=self.rules,
            runtime_origin="mock",
        )
        srv = ThesisApiServer(cfg)
        srv.drain_timeout_seconds = 0.2
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        try:
            host, port = srv.server_address[:2]
            with socket.create_connection((host, port), timeout=2.0) as sock:
                sock.settimeout(2.0)
                head = (
                    f"POST /api/scan-jobs HTTP/1.1\r\n"
                    f"Host: {host}:{port}\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: 100\r\n"
                    f"Authorization: Bearer wrong-token\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode("ascii")
                t0 = time.monotonic()
                sock.sendall(head + b'{"repo_url":')  # Incomplete body with Connection: close
                chunks = []
                while True:
                    d = sock.recv(4096)
                    if not d:
                        break
                    chunks.append(d)
                elapsed = time.monotonic() - t0
                raw = b"".join(chunks)
                self.assertIn(b"401", raw.split(b"\r\n", 1)[0])
                self.assertIn(b"UNAUTHORIZED", raw)
                self.assertLess(elapsed, 1.0)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_cached_triage_scan_never_reports_real_scan_and_concurrent_review_is_safe(self) -> None:
        # Build a realistic non-mock loopback stub Ollama + fake OpenGrep to test:
        # 1) enable_qwen_cache=True is explicitly refused (SAFELY_DISABLED)
        # 2) historical cached scan directory in reviewable_scan_dirs never reports REAL_SCAN
        # 3) concurrent GET reads + Human Review mutations + STALE_SOURCE drift + 1-byte tamper on live scan
        java_code = (
            "package demo;\n"
            "import java.sql.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class LiveCacheDemo {\n"
            "    public void run(HttpServletRequest req, Statement st) throws Exception {\n"
            "        String u = req.getParameter(\"u\");\n"
            "        st.executeQuery(\"SELECT * FROM t WHERE u='\" + u + \"'\");\n"
            "    }\n"
            "}\n"
        )
        zbytes = _make_java_zip({"src/LiveCacheDemo.java": java_code})
        file_sha = digest(java_code.encode("utf-8"))
        sink_line_txt = java_code.splitlines()[6]
        model_name = "qwen3.5:9b-q4_K_M"
        post_calls = {"count": 0}

        with self.assertRaises(ValueError):
            ApiConfig(data_dir=self.root / "data_cache_refused", rules_path=self.rules, enable_qwen_cache=True)

        fake_og = _create_fake_opengrep(
            self.root,
            """
import json, pathlib, sys
args = sys.argv[1:]
if "--version" in args:
    print("1.25.0")
    raise SystemExit(0)
target = pathlib.Path(args[-1])
jf = sorted(target.rglob("*.java"))[0]
lines = jf.read_text(encoding="utf-8").splitlines(keepends=True)
def loc(ln, s):
    raw = lines[ln - 1].rstrip("\\r\\n")
    c0 = raw.index(s)
    pref = sum(len(x.encode("utf-8")) for x in lines[:ln - 1])
    so = pref + len(raw[:c0].encode("utf-8"))
    return {"path": str(jf), "start": {"line": ln, "col": len(raw[:c0].encode("utf-8")) + 1, "offset": so}, "end": {"line": ln, "col": len(raw[:c0 + len(s)].encode("utf-8")) + 1, "offset": so + len(s.encode("utf-8"))}}
sl = loc(6, 'req.getParameter("u")')
kl = loc(7, 'st.executeQuery("SELECT * FROM t WHERE u=\\'" + u + "\\'")')
if "--sarif" in args:
    print(json.dumps({"version": "2.1.0", "runs": [{"results": [{"ruleId": "ntk.api.java.cwe89.sql-injection", "locations": [{"physicalLocation": {"artifactLocation": {"uri": str(jf)}, "region": {"startLine": 7, "endLine": 7, "startColumn": kl["start"]["col"], "endColumn": kl["end"]["col"]}}}]}]}]}))
    raise SystemExit(0)
print(json.dumps({"version": "1.25.0", "results": [{"check_id": "ntk.api.java.cwe89.sql-injection", "path": str(jf), "start": kl["start"], "end": kl["end"], "extra": {"message": "sqli", "severity": "ERROR", "metadata": {"cwe": ["CWE-89"]}, "dataflow_trace": {"taint_source": ["CliLoc", [sl, 'req.getParameter("u")']], "intermediate_vars": [], "taint_sink": ["CliLoc", [kl, 'st.executeQuery("SELECT * FROM t WHERE u=\\'" + u + "\\'")']]}}}], "errors": [], "paths": {"scanned": [str(jf)], "skipped": []}}))
raise SystemExit(0)
""",
            subdir="og_cache_live",
        )

        class _StubOllama(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                return

            def do_GET(self):
                if self.path == "/api/tags":
                    body = json.dumps({"models": [{"name": model_name, "digest": "c" * 64, "size": 100}]}).encode("utf-8")
                else:
                    body = json.dumps({"models": []}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                post_calls["count"] += 1
                n = int(self.headers.get("Content-Length", "0"))
                _ = self.rfile.read(n)
                ans = json.dumps({
                    "status": "SUPPORTED",
                    "explanation": "Direct string concat in SQL.",
                    "fix_suggestion": "Use PreparedStatement.",
                    "citations": [{"path": "src/LiveCacheDemo.java", "start_line": 7, "end_line": 7, "quote": sink_line_txt, "sha256": file_sha}],
                })
                body = json.dumps({
                    "model": model_name,
                    "done": True,
                    "done_reason": "stop",
                    "eval_count": 42,
                    "eval_duration": 1000000,
                    "message": {"role": "assistant", "content": ans},
                }).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        ol_srv = ThreadingHTTPServer(("127.0.0.1", 0), _StubOllama)
        ol_th = threading.Thread(target=ol_srv.serve_forever, daemon=True)
        ol_th.start()
        try:
            data_dir = self.root / "data_cached_origin"
            hist_cached_dir = self.root / "historical_cached_scan"
            token = "cache-origin-test-token-1234"
            cfg = ApiConfig(
                host="127.0.0.1",
                port=0,
                data_dir=data_dir,
                reviewable_scan_dirs=(hist_cached_dir,),
                api_token=token,
                read_auth_mode="required",
                opengrep_binary=fake_og,
                rules_path=self.rules,
                ollama_endpoint=f"http://127.0.0.1:{ol_srv.server_port}",
                ollama_model=model_name,
                enable_qwen_cache=False,
                runtime_origin="unverified",
            )
            srv = ThesisApiServer(cfg)
            th = threading.Thread(target=srv.serve_forever, daemon=True)
            th.start()
            try:
                base_url = f"http://127.0.0.1:{srv.server_port}"
                auth_hdr = {"Authorization": f"Bearer {token}"}

                def _wait_job(jid: str) -> dict:
                    dl = time.monotonic() + 20.0
                    while time.monotonic() < dl:
                        cur = srv.jobs.get_job(jid)
                        if cur["state"] in ("COMPLETED", "FAILED"):
                            return cur
                        time.sleep(0.05)
                    raise AssertionError("job timed out")

                # Job 1: live HTTP scan -> REAL_SCAN
                j1 = _wait_job(srv.jobs.submit_zip_job("p1.zip", zbytes, no_llm=False)["job_id"])
                self.assertEqual(j1["state"], "COMPLETED", j1)
                self.assertEqual(post_calls["count"], 1)
                s1 = j1["scan_id"]
                rep1 = srv.service.export_scan_report(s1)
                self.assertEqual(rep1["data_origin"], "REAL_SCAN")

                # Job 2: identical source also executes live HTTP because cache is SAFELY_DISABLED
                j2 = _wait_job(srv.jobs.submit_zip_job("p2.zip", zbytes, no_llm=False)["job_id"])
                self.assertEqual(j2["state"], "COMPLETED", j2)
                self.assertEqual(post_calls["count"], 2)

                # Historical cached scan artifact in reviewable_scan_dirs MUST report CACHED_TRIAGE_NO_LIVE_HTTP, never REAL_SCAN!
                import shutil
                from v2.triage.store import ReviewStore
                shutil.copytree(data_dir / "scans" / j1["job_id"], hist_cached_dir)
                (hist_cached_dir / "api-scan-meta.json").unlink()
                ev_h = json.loads((hist_cached_dir / "triage" / "evidence.json").read_text(encoding="utf-8"))
                rows_h = [json.loads(line) for line in (hist_cached_dir / "triage" / "assessments.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
                rows_h[0]["assessment"]["transport"] = "qwen-cache-verified"
                rows_h[0]["assessment"]["raw_response"] = None
                rows_h[0]["assessment"]["runtime"].update({
                    "origin": "cached_verified", "cache_hit": True, "request_attempted": False, "model_runtime_verified": False,
                })
                (hist_cached_dir / "triage" / "assessments.jsonl").write_text(json.dumps(rows_h[0]) + "\n", encoding="utf-8")
                (hist_cached_dir / "triage" / "review.sqlite").unlink()
                rs_h = ReviewStore(hist_cached_dir / "triage" / "review.sqlite")
                try:
                    rs_h.add(ev_h, [rows_h[0]["assessment"]])
                finally:
                    rs_h.close()

                all_scans = srv.service.list_scans()["scans"]
                hist_sum = next(sc for sc in all_scans if sc["data_origin"] == "CACHED_TRIAGE_NO_LIVE_HTTP")
                s_hist = hist_sum["scan_id"]
                f_hist = srv.service.list_findings(s_hist)["findings"][0]["id"]
                for ep in (
                    f"/api/scans/{s_hist}",
                    f"/api/scans/{s_hist}/findings",
                    f"/api/scans/{s_hist}/review-queue",
                    f"/api/scans/{s_hist}/findings/{f_hist}",
                    f"/api/scans/{s_hist}/report",
                ):
                    with urlopen(Request(base_url + ep, headers=auth_hdr), timeout=5) as resp:
                        doc = json.loads(resp.read().decode("utf-8"))
                    self.assertNotEqual(doc["data_origin"], "REAL_SCAN", f"{ep} falsely reported REAL_SCAN")
                    self.assertEqual(doc["data_origin"], "CACHED_TRIAGE_NO_LIVE_HTTP", ep)

                # Concurrent GET reads while executing Human Review mutations + STALE_SOURCE drift on Job 1
                fid1 = srv.service.list_findings(s1)["findings"][0]["id"]
                read_errors: list[str] = []
                stop_reads = threading.Event()

                def _reader(ep: str) -> None:
                    while not stop_reads.is_set():
                        try:
                            with urlopen(Request(base_url + ep, headers=auth_hdr), timeout=5) as r:
                                d = json.loads(r.read().decode("utf-8"))
                                if r.status != 200:
                                    read_errors.append(f"{ep} status={r.status}")
                                if "human_review_state" in d and "review_events" in d:
                                    evs = d["review_events"]
                                    exp_st = "OPEN"
                                    for ev in evs:
                                        exp_st = {"confirm-true": "CONFIRMED_TRUE", "confirm-false": "CONFIRMED_FALSE", "reopen": "OPEN"}[ev["action"]]
                                    if d["human_review_state"] != exp_st:
                                        read_errors.append(f"torn state {d['human_review_state']} vs {exp_st}")
                        except Exception as exc:
                            read_errors.append(f"{ep}: {exc}")

                readers = [
                    threading.Thread(target=_reader, args=(ep,), daemon=True)
                    for ep in (
                        f"/api/scans/{s1}/findings",
                        f"/api/scans/{s1}/findings/{fid1}",
                        f"/api/scans/{s1}/review-queue",
                        f"/api/scans/{s1}/report",
                    )
                ]
                for rt in readers:
                    rt.start()
                try:
                    for action, reason in (
                        ("confirm-true", "Concurrent confirm TP"),
                        ("reopen", "Concurrent reopen"),
                        ("confirm-false", "Concurrent confirm FP"),
                        ("reopen", "Reopen before drift"),
                    ):
                        req = Request(
                            f"{base_url}/api/scans/{s1}/findings/{fid1}/{action}",
                            data=json.dumps({"actor": "concurrent-reviewer", "reason": reason}).encode("utf-8"),
                            method="POST",
                            headers={**auth_hdr, "Content-Type": "application/json"},
                        )
                        with urlopen(req, timeout=5) as resp:
                            self.assertEqual(resp.status, 200)
                finally:
                    stop_reads.set()
                    for rt in readers:
                        rt.join(timeout=3.0)
                self.assertEqual(read_errors, [], f"concurrent read errors: {read_errors[:5]}")

                # Mutate source on disk -> confirm-false MUST fail 409 STALE_SOURCE without deleting warning or losing history
                ws_java = data_dir / "workspaces" / j1["job_id"] / "source" / "src" / "LiveCacheDemo.java"
                ws_java.write_text(java_code + "// drifted\n", encoding="utf-8")
                req_drift = Request(
                    f"{base_url}/api/scans/{s1}/findings/{fid1}/confirm-false",
                    data=json.dumps({"actor": "concurrent-reviewer", "reason": "Try after drift"}).encode("utf-8"),
                    method="POST",
                    headers={**auth_hdr, "Content-Type": "application/json"},
                )
                with self.assertRaises(HTTPError) as ctx_drift:
                    urlopen(req_drift, timeout=5)
                self.assertEqual(ctx_drift.exception.code, 409)
                drift_doc = json.loads(ctx_drift.exception.read().decode("utf-8"))
                self.assertEqual(drift_doc["error_code"], "STALE_SOURCE")
                self.assertEqual(drift_doc["human_review_state"], "OPEN")

                # Verify zero-mutation GETs & report exposes rejected_decisions
                db_p = data_dir / "scans" / j1["job_id"] / "triage" / "review.sqlite"
                sha_before = digest(db_p.read_bytes())
                final_rep = srv.service.export_scan_report(s1)
                self.assertEqual(final_rep["audit_trail"]["events_count"], 4)
                self.assertEqual(final_rep["audit_trail"]["rejected_decisions_count"], 1)
                self.assertEqual(len(final_rep["findings"]), 1)
                self.assertEqual(final_rep["findings"][0]["human_review_state"], "OPEN")
                self.assertEqual(digest(db_p.read_bytes()), sha_before)

                # HTTP-level 1-byte same-size same-mtime tamper on assessments.jsonl MUST fail closed with 409!
                jsonl_p = data_dir / "scans" / j1["job_id"] / "triage" / "assessments.jsonl"
                orig_jstat = jsonl_p.stat()
                orig_jtxt = jsonl_p.read_text(encoding="utf-8")
                bad_jtxt = orig_jtxt.replace('"SUPPORTED"', '"SUPPORTED', 1) + " "
                self.assertEqual(len(bad_jtxt.encode("utf-8")), len(orig_jtxt.encode("utf-8")))
                jsonl_p.write_text(bad_jtxt, encoding="utf-8")
                os.utime(jsonl_p, ns=(orig_jstat.st_atime_ns, orig_jstat.st_mtime_ns))
                with self.assertRaises(HTTPError) as ctx_tamper:
                    urlopen(Request(f"{base_url}/api/scans/{s1}/report", headers=auth_hdr), timeout=5)
                self.assertEqual(ctx_tamper.exception.code, 409)
                tamper_doc = json.loads(ctx_tamper.exception.read().decode("utf-8"))
                self.assertEqual(tamper_doc["error_code"], "ARTIFACT_PROVENANCE_MISMATCH")
            finally:
                srv.shutdown()
                srv.server_close()
        finally:
            ol_srv.shutdown()
            ol_srv.server_close()


if __name__ == "__main__":
    unittest.main()
