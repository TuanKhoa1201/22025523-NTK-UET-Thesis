"""End-to-end unit and integration tests for v2.api without touching sealed DBs or GPU."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
import io
import json
from pathlib import Path
import stat
import tempfile
import threading
import time
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import zipfile

from v2.api.config import ApiConfig, IntakeLimits
from v2.api.intake import IntakeError, validate_github_url
from v2.api.server import ThesisApiServer
from v2.triage import evidence, store


TEST_TOKEN = "test-operator-token-9876543210"

SAMPLE_JAVA = (
    "package demo;\n"
    "public class SqlDemo {\n"
    "    public void query(javax.servlet.http.HttpServletRequest req, java.sql.Statement st) throws Exception {\n"
    '        String id = req.getParameter("id");\n'
    '        st.executeQuery("SELECT * FROM users WHERE id=" + id);\n'
    "    }\n"
    "}\n"
)


def _make_multipart(field_name: str, filename: str, content: bytes, extra_fields: dict[str, str] | None = None) -> tuple[str, bytes]:
    boundary = "----NTKTestBoundary7MA4YWxkTrZu0gW"
    buf = io.BytesIO()
    for k, v in (extra_fields or {}).items():
        buf.write(f"--{boundary}\r\n".encode("utf-8"))
        buf.write(f'Content-Disposition: form-data; name="{k}"\r\n\r\n'.encode("utf-8"))
        buf.write(f"{v}\r\n".encode("utf-8"))
    buf.write(f"--{boundary}\r\n".encode("utf-8"))
    buf.write(f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'.encode("utf-8"))
    buf.write(b"Content-Type: application/zip\r\n\r\n")
    buf.write(content)
    buf.write(f"\r\n--{boundary}--\r\n".encode("utf-8"))
    return f"multipart/form-data; boundary={boundary}", buf.getvalue()


def _make_zip_bytes(entries: dict[str, bytes], *, symlink_name: str | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
        if symlink_name:
            info = zipfile.ZipInfo(symlink_name)
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, b"/etc/passwd")
    return buf.getvalue()


def _create_synthetic_real_scan_dir(base_dir: Path, *, mark_mock: bool = False) -> tuple[Path, Path, str, str]:
    """Create a self-contained triage scan directory in temp space for Flow A & Flow B tests."""
    src_dir = base_dir / "src_project"
    src_dir.mkdir(parents=True, exist_ok=True)
    java_file = src_dir / "SqlDemo.java"
    java_file.write_text(SAMPLE_JAVA, encoding="utf-8")
    lines = SAMPLE_JAVA.splitlines()

    def _loc(ln: int, needle: str) -> dict:
        col = lines[ln - 1].index(needle) + 1
        return {
            "path": "SqlDemo.java",
            "start": {"line": ln, "col": col},
            "end": {"line": ln, "col": col + len(needle)},
        }

    src_loc = _loc(4, 'req.getParameter("id")')
    sink_loc = _loc(5, 'st.executeQuery("SELECT * FROM users WHERE id=" + id)')
    trace = {
        "taint_source": ["CliLoc", [src_loc, 'req.getParameter("id")']],
        "taint_sink": ["CliLoc", [sink_loc, 'st.executeQuery("SELECT * FROM users WHERE id=" + id)']],
        "intermediate_vars": [],
    }
    finding = {
        "check_id": "v2.g1.java.cwe89.mock-fixture" if mark_mock else "v2.g1.java.cwe89.sql-injection",
        **sink_loc,
        "extra": {
            "severity": "ERROR",
            "message": "Potential SQL injection via string concatenation",
            "metadata": {"cwe": ["CWE-89: SQL Injection"]},
            "dataflow_trace": trace,
        },
    }
    raw_bytes = json.dumps({"results": [finding], "errors": []}).encode("utf-8")
    java_sha = evidence.digest(java_file.read_bytes())
    provenance = {
        "origin": "UNIT_TEST_MOCK_CAPTURE" if mark_mock else "recorded_capture_unsigned",
        "source_capture_verified": True,
        "exit_capture_verified": True,
        "recorded_engine_exit": 0,
        "source_hashes": {"SqlDemo.java": java_sha},
    }
    bundle = evidence.collect(raw_bytes, src_dir, engine_exit=0, scan_provenance=provenance)
    bundle["scan_provenance"] = provenance
    bundle["pre_scan_hashes"] = {"SqlDemo.java": java_sha}
    rec = bundle["records"][0]

    assessment = {
        "status": "REFUTED",
        "raw_model_status": "REFUTED",
        "validated_status": "REFUTED",
        "validator_downgraded": False,
        "failure_kind": None,
        "explanation": "Mô hình đề xuất bác bỏ để kiểm tra chốt không tự động ẩn cảnh báo.",
        "fix_suggestion": "Dùng PreparedStatement.",
        "citations": [
            {
                "path": "SqlDemo.java",
                "start_line": 5,
                "end_line": 5,
                "quote": lines[4],
                "sha256": java_sha,
            }
        ],
        "citation_check": "MATCHED",
        "requires_human_review": True,
        "security_conclusion_verified": False,
        "analyzed_at": evidence.now(),
        "runtime": {
            "origin": "mock" if mark_mock else "unverified",
            "request_attempted": True,
            "http_response_received": True,
            "http_status": 200,
            "response_complete": True,
            "model_identity_matched": True,
            "reported_eval_count": 42,
            "answer_validated": True,
            "model_runtime_verified": False,
        },
    }

    scan_dir = base_dir / ("mock_scan" if mark_mock else "verified_scan")
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "input.opengrep.json").write_bytes(raw_bytes)
    (scan_dir / "evidence.json").write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    jsonl_row = {
        "schema_version": bundle["schema_version"],
        "id": rec["id"],
        "alert_id": rec["id"],
        "scan_sha256": bundle["scan_sha256"],
        "finding_index": 0,
        "state": "OPEN",
        "evidence": rec,
        "assessment": assessment,
    }
    (scan_dir / "assessments.jsonl").write_text(json.dumps(jsonl_row) + "\n", encoding="utf-8")
    rs = store.ReviewStore(scan_dir / "review.sqlite")
    try:
        rs.add(bundle, [assessment])
    finally:
        rs.close()

    return scan_dir, java_file, bundle["scan_sha256"], rec["id"]


def _write_fake_opengrep_cmd(temp_root: Path) -> Path:
    """Create a local Windows batch/Python fake OpenGrep executable for job runner tests."""
    py_script = temp_root / "opengrep_fake_impl.py"
    py_script.write_text(
        "import json, pathlib, sys\n"
        "args = sys.argv[1:]\n"
        "if '--version' in args:\n"
        "    print('opengrep 1.25.0-test-stub')\n"
        "    sys.exit(0)\n"
        "target = pathlib.Path(args[-1]).resolve()\n"
        "java_files = sorted(target.rglob('*.java')) if target.is_dir() else [target]\n"
        "jf = java_files[0]\n"
        "rel = jf.relative_to(target).as_posix() if target.is_dir() else jf.name\n"
        "lines = jf.read_text(encoding='utf-8').splitlines()\n"
        "src_ln = next(i+1 for i, l in enumerate(lines) if 'getParameter' in l)\n"
        "sink_ln = next(i+1 for i, l in enumerate(lines) if 'executeQuery' in l)\n"
        "src_txt = 'req.getParameter(\"id\")'\n"
        "sink_txt = 'st.executeQuery(\"SELECT * FROM users WHERE id=\" + id)'\n"
        "sc = lines[src_ln-1].index(src_txt) + 1\n"
        "kc = lines[sink_ln-1].index(sink_txt) + 1\n"
        "if '--json' in args:\n"
        "    res1 = {\n"
        "        'check_id': 'v2.g1_integration.rules.ntk.g1.java.cwe89.sql-injection',\n"
        "        'path': str(jf),\n"
        "        'start': {'line': sink_ln, 'col': kc},\n"
        "        'end': {'line': sink_ln, 'col': kc + len(sink_txt)},\n"
        "        'extra': {\n"
        "            'severity': 'ERROR',\n"
        "            'message': 'SQLi sink',\n"
        "            'metadata': {'cwe': ['CWE-89: SQL Injection']},\n"
        "            'dataflow_trace': {\n"
        "                'taint_source': ['CliLoc', [{'path': str(jf), 'start': {'line': src_ln, 'col': sc}, 'end': {'line': src_ln, 'col': sc + len(src_txt)}}, src_txt]],\n"
        "                'taint_sink': ['CliLoc', [{'path': str(jf), 'start': {'line': sink_ln, 'col': kc}, 'end': {'line': sink_ln, 'col': kc + len(sink_txt)}}, sink_txt]],\n"
        "                'intermediate_vars': []\n"
        "            }\n"
        "        }\n"
        "    }\n"
        "    res2 = {\n"
        "        'check_id': 'v2.g1_integration.rules.ntk.g1.java.cwe22.path-traversal',\n"
        "        'path': str(jf),\n"
        "        'start': {'line': sink_ln, 'col': kc},\n"
        "        'end': {'line': sink_ln, 'col': kc + len(sink_txt)},\n"
        "        'extra': {\n"
        "            'severity': 'WARNING',\n"
        "            'message': 'Second alert for invalid citation test',\n"
        "            'metadata': {'cwe': ['CWE-22: Path Traversal']},\n"
        "            'dataflow_trace': res1['extra']['dataflow_trace']\n"
        "        }\n"
        "    }\n"
        "    print(json.dumps({'version': '1.25.0', 'results': [res1, res2], 'errors': []}))\n"
        "    sys.exit(0)\n"
        "if '--sarif' in args:\n"
        "    sarif = {'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'opengrep', 'rules': []}}, 'results': [\n"
        "        {'ruleId': 'v2.g1_integration.rules.ntk.g1.java.cwe89.sql-injection', 'message': {'text': 'SQLi sink'}, 'locations': [{'physicalLocation': {'artifactLocation': {'uri': str(jf)}, 'region': {'startLine': sink_ln, 'startColumn': kc, 'endLine': sink_ln, 'endColumn': kc + len(sink_txt)}}}]},\n"
        "        {'ruleId': 'v2.g1_integration.rules.ntk.g1.java.cwe22.path-traversal', 'message': {'text': 'Second alert'}, 'locations': [{'physicalLocation': {'artifactLocation': {'uri': str(jf)}, 'region': {'startLine': sink_ln, 'startColumn': kc, 'endLine': sink_ln, 'endColumn': kc + len(sink_txt)}}}]} \n"
        "    ]}]}\n"
        "    print(json.dumps(sarif))\n"
        "    sys.exit(0)\n"
        "sys.exit(2)\n",
        encoding="utf-8",
    )
    cmd_wrapper = temp_root / "opengrep_stub.cmd"
    cmd_wrapper.write_text(f'@"{Path(io.__file__).resolve().parents[1] / "python.exe"}" "{py_script}" %*\r\n', encoding="utf-8")
    if not (Path(io.__file__).resolve().parents[1] / "python.exe").is_file():
        import sys as _sys
        cmd_wrapper.write_text(f'@"{_sys.executable}" "{py_script}" %*\r\n', encoding="utf-8")
    return cmd_wrapper


class ApiAdapterTestSuite(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def _start_server(self, config: ApiConfig) -> tuple[ThesisApiServer, str]:
        srv = ThesisApiServer(config)
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()

        def _stop() -> None:
            srv.shutdown()
            thread.join(timeout=2.0)
            srv.server_close()

        self.addCleanup(_stop)
        host, port = srv.server_address[:2]
        return srv, f"http://{host}:{port}"

    def _http(
        self,
        url: str,
        *,
        method: str = "GET",
        token: str | None = TEST_TOKEN,
        body: bytes | dict | None = None,
        content_type: str = "application/json",
        origin: str | None = None,
    ) -> tuple[int, dict, dict]:
        headers: dict[str, str] = {"Connection": "close"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if origin:
            headers["Origin"] = origin
        payload_bytes = None
        if isinstance(body, dict):
            payload_bytes = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif isinstance(body, bytes):
            payload_bytes = body
            headers["Content-Type"] = content_type

        req = Request(url, data=payload_bytes, headers=headers, method=method)
        try:
            with urlopen(req, timeout=15) as resp:
                raw = resp.read().decode("utf-8")
                return resp.status, (json.loads(raw) if raw else {}), dict(resp.headers)
        except HTTPError as exc:
            raw = exc.read().decode("utf-8")
            return exc.code, (json.loads(raw) if raw else {}), dict(exc.headers)

    def test_security_boundaries_port_8765_public_bind_and_sealed_dirs(self) -> None:
        with self.assertRaises(ValueError):
            ApiConfig(port=8765, data_dir=self.root / "data")
        with self.assertRaises(ValueError):
            ApiConfig(host="0.0.0.0", port=0, data_dir=self.root / "data")
        with self.assertRaises(ValueError):
            ApiConfig(port=0, data_dir=Path(__file__).resolve().parents[2] / "triage" / "sub")
        with self.assertRaises(ValueError):
            ApiConfig(port=0, data_dir=self.root / "data", cors_origins=("*",))
        with self.assertRaises(ValueError):
            ApiConfig(port=0, data_dir=self.root / "data", ollama_endpoint="https://api.openai.com")
        # Tailscale CGNAT IP is accepted when explicitly configured
        cfg_ts = ApiConfig(host="100.101.102.103", port=8780, data_dir=self.root / "data", api_token=TEST_TOKEN)
        self.assertEqual(cfg_ts.host, "100.101.102.103")

    def test_malicious_github_urls_rejected(self) -> None:
        bad_urls = [
            "",
            "http://github.com/owner/repo",
            "https://evil.com/owner/repo",
            "https://user:secret@github.com/owner/repo",
            "https://github.com/--upload-pack=evil/repo",
            "https://github.com/owner/-badrepo",
            "https://github.com/owner/repo?cmd=whoami",
            "https://github.com/owner/../etc",
            "https://github.com/owner/repo/subpath/extra",
        ]
        for bad in bad_urls:
            with self.subTest(url=bad), self.assertRaises(IntakeError):
                validate_github_url(bad)
        with self.assertRaises(IntakeError):
            validate_github_url("https://github.com/owner/repo", commit_sha="--exec=evil")

        url, owner, repo, sha = validate_github_url("https://github.com/TuanKhoa1201/SampleJavaRepo.git", "de61f4b4")
        self.assertEqual((url, owner, repo, sha), ("https://github.com/TuanKhoa1201/SampleJavaRepo", "TuanKhoa1201", "SampleJavaRepo", "de61f4b4"))

    def test_auth_cors_and_flow_a_readonly_zero_mutation(self) -> None:
        ro_scan_dir, _, scan_sha, finding_id = _create_synthetic_real_scan_dir(self.root / "ro_area", mark_mock=False)
        before_hashes = {
            p.name: evidence.digest(p.read_bytes())
            for p in ro_scan_dir.iterdir()
            if p.is_file()
        }

        cfg = ApiConfig(
            host="127.0.0.1",
            port=0,
            data_dir=self.root / "api_data",
            readonly_scan_dirs=(ro_scan_dir,),
            api_token=TEST_TOKEN,
            read_auth_mode="required",
            cors_origins=("http://localhost:5173",),
            opengrep_binary="opengrep-nonexistent-test-bin",
            ollama_endpoint="http://127.0.0.1:65530",
        )
        _, base = self._start_server(cfg)

        # 1. Unauthenticated /api/health returns AUTH_REQUIRED without sensitive details
        code, h_unauth, _ = self._http(f"{base}/api/health", token=None, origin="http://localhost:5173")
        self.assertEqual(code, 200)
        self.assertEqual(h_unauth["status"], "AUTH_REQUIRED")
        self.assertFalse(h_unauth["authenticated"])

        # 2. Disallowed CORS origin is blocked with 403
        code, cors_err, hdrs = self._http(f"{base}/api/health", token=TEST_TOKEN, origin="https://evil.example")
        self.assertEqual(code, 403)
        self.assertEqual(cors_err["error_code"], "CORS_ORIGIN_FORBIDDEN")
        self.assertNotIn("Access-Control-Allow-Origin", hdrs)

        # 3. Unauthenticated /api/scans is blocked with 401
        code, unauth_err, _ = self._http(f"{base}/api/scans", token=None)
        self.assertEqual(code, 401)
        self.assertEqual(unauth_err["error_code"], "UNAUTHORIZED")

        # 4. Authenticated /api/health accurately reports DEGRADED when OpenGrep & Ollama are unavailable
        code, h_auth, hdrs = self._http(f"{base}/api/health", token=TEST_TOKEN, origin="http://localhost:5173")
        self.assertEqual(code, 200)
        self.assertEqual(h_auth["status"], "DEGRADED")
        self.assertFalse(h_auth["opengrep"]["available"])
        self.assertFalse(h_auth["ollama"]["reachable"])
        self.assertEqual(hdrs.get("Access-Control-Allow-Origin"), "http://localhost:5173")

        # 5. Flow A: Read scan list, summary, findings, detail, queue, report — zero byte change!
        code, scans_res, _ = self._http(f"{base}/api/scans")
        self.assertEqual(code, 200)
        self.assertEqual(scans_res["total_count"], 1)
        self.assertFalse(scans_res["scans"][0]["writable"])

        code, f_list, _ = self._http(f"{base}/api/scans/{scan_sha}/findings?cwe=CWE-89")
        self.assertEqual(code, 200)
        self.assertEqual(f_list["total_matching"], 1)
        self.assertEqual(f_list["findings"][0]["validated_status"], "REFUTED")
        self.assertEqual(f_list["findings"][0]["human_review_state"], "OPEN")

        code, f_det, _ = self._http(f"{base}/api/scans/{scan_sha}/findings/{finding_id}")
        self.assertEqual(code, 200)
        self.assertEqual(f_det["citation_check"], "MATCHED")
        self.assertEqual(len(f_det["evidence"]["snippets"]), 3)

        code, rep, _ = self._http(f"{base}/api/scans/{scan_sha}/report")
        self.assertEqual(code, 200)
        self.assertEqual(rep["data_origin"], "REAL_SCAN")
        self.assertIsNotNone(rep["paired_pilot_export"])

        # 6. Read-only scan refuses review mutation with 403 SCAN_READ_ONLY
        code, ro_err, _ = self._http(
            f"{base}/api/scans/{scan_sha}/findings/{finding_id}/confirm-true",
            method="POST",
            body={"actor": "reviewer-1", "reason": "Test RO guard"},
        )
        self.assertEqual(code, 403)
        self.assertEqual(ro_err["error_code"], "SCAN_READ_ONLY")

        after_hashes = {
            p.name: evidence.digest(p.read_bytes())
            for p in ro_scan_dir.iterdir()
            if p.is_file()
        }
        self.assertEqual(before_hashes, after_hashes)

    def test_flow_b_human_review_lifecycle_and_stale_source_guard(self) -> None:
        rw_scan_dir, java_file, scan_sha, finding_id = _create_synthetic_real_scan_dir(self.root / "rw_area", mark_mock=False)
        mock_scan_dir, _, mock_sha, _ = _create_synthetic_real_scan_dir(self.root / "mock_area", mark_mock=True)

        cfg = ApiConfig(
            host="127.0.0.1",
            port=0,
            data_dir=self.root / "api_data_b",
            reviewable_scan_dirs=(rw_scan_dir, mock_scan_dir),
            api_token=TEST_TOKEN,
        )
        _, base = self._start_server(cfg)

        # Mock scan is isolated in production mode (runtime_origin='unverified')
        code, scans_res, _ = self._http(f"{base}/api/scans")
        self.assertEqual([s["scan_sha256"] for s in scans_res["scans"]], [scan_sha])
        code, iso_err, _ = self._http(f"{base}/api/scans/{mock_sha}/report")
        self.assertEqual(code, 403)
        self.assertEqual(iso_err["error_code"], "TEST_DATA_ISOLATED")

        # Initial queue: Qwen proposed REFUTED, yet human_review_state is OPEN and stays in queue!
        code, q0, _ = self._http(f"{base}/api/scans/{scan_sha}/review-queue")
        self.assertEqual(code, 200)
        self.assertEqual(len(q0["warnings"]), 1)
        self.assertEqual(q0["warnings"][0]["human_review_state"], "OPEN")

        # Confirm-true -> CONFIRMED_TRUE, stays visible in default queue
        code, d1, _ = self._http(
            f"{base}/api/scans/{scan_sha}/findings/{finding_id}/confirm-true",
            method="POST",
            body={"actor": "nguyen-tuan-khoa", "reason": "Xác nhận luồng dữ liệu cộng chuỗi SQL trực tiếp"},
        )
        self.assertEqual(code, 200)
        self.assertEqual(d1["human_review_state"], "CONFIRMED_TRUE")

        # Confirm-false (unmodified source) -> CONFIRMED_FALSE, hidden from default queue, visible with include_all=true
        code, d2, _ = self._http(
            f"{base}/api/scans/{scan_sha}/findings/{finding_id}/confirm-false",
            method="POST",
            body={"actor": "nguyen-tuan-khoa", "reason": "Kiểm thử xác nhận giả khi mã nguồn chưa đổi"},
        )
        self.assertEqual(code, 200)
        self.assertEqual(d2["human_review_state"], "CONFIRMED_FALSE")

        _, q_default, _ = self._http(f"{base}/api/scans/{scan_sha}/review-queue")
        self.assertEqual(len(q_default["warnings"]), 0)
        _, q_all, _ = self._http(f"{base}/api/scans/{scan_sha}/review-queue?include_all=true")
        self.assertEqual(len(q_all["warnings"]), 1)

        # Reopen -> returns to OPEN
        code, d3, _ = self._http(
            f"{base}/api/scans/{scan_sha}/findings/{finding_id}/reopen",
            method="POST",
            body={"actor": "nguyen-tuan-khoa", "reason": "Mở lại để kiểm tra chốt STALE_SOURCE"},
        )
        self.assertEqual(code, 200)
        self.assertEqual(d3["human_review_state"], "OPEN")
        self.assertEqual(len(d3["review_events"]), 3)

        # Mutate Java file on disk -> confirm-false MUST fail with 409 STALE_SOURCE, state stays OPEN, rejected_decisions recorded!
        java_file.write_text(SAMPLE_JAVA + "// modified after scan\n", encoding="utf-8")
        code, stale_res, _ = self._http(
            f"{base}/api/scans/{scan_sha}/findings/{finding_id}/confirm-false",
            method="POST",
            body={"actor": "nguyen-tuan-khoa", "reason": "Cố xác nhận giả sau khi sửa mã nguồn"},
        )
        self.assertEqual(code, 409)
        self.assertEqual(stale_res["error_code"], "STALE_SOURCE")
        self.assertEqual(stale_res["human_review_state"], "OPEN")
        self.assertIn("SqlDemo.java", stale_res["stale_source"]["mismatched_paths"])
        self.assertEqual(len(stale_res["review_events"]), 3)  # No event added!
        self.assertEqual(len(stale_res["rejected_decisions"]), 1)
        self.assertEqual(stale_res["rejected_decisions"][0]["rejection_code"], "STALE_SOURCE")

    def test_malicious_zip_uploads_rejected_without_side_effects(self) -> None:
        cfg = ApiConfig(
            host="127.0.0.1",
            port=0,
            data_dir=self.root / "api_data_zip",
            api_token=TEST_TOKEN,
            limits=IntakeLimits(max_zip_upload_bytes=1024 * 1024, max_compression_ratio=20.0),
        )
        _, base = self._start_server(cfg)

        # 1. Path traversal
        z_trav = _make_zip_bytes({"../evil.java": SAMPLE_JAVA.encode("utf-8")})
        ct, body = _make_multipart("file", "trav.zip", z_trav)
        code, res, _ = self._http(f"{base}/api/scan-jobs", method="POST", body=body, content_type=ct)
        self.assertEqual(code, 400)
        self.assertEqual(res["error_code"], "ZIP_PATH_TRAVERSAL")

        # 2. Symlink inside ZIP
        z_sym = _make_zip_bytes({"SqlDemo.java": SAMPLE_JAVA.encode("utf-8")}, symlink_name="link.java")
        ct, body = _make_multipart("file", "sym.zip", z_sym)
        code, res, _ = self._http(f"{base}/api/scan-jobs", method="POST", body=body, content_type=ct)
        self.assertEqual(code, 400)
        self.assertEqual(res["error_code"], "ZIP_SYMLINK_FORBIDDEN")

        # 3. ZIP bomb (high compression ratio: 500 KB of zeros compresses > 200:1 > limit 20.0)
        z_bomb = _make_zip_bytes({"SqlDemo.java": b"A" * 300_000})
        ct, body = _make_multipart("file", "bomb.zip", z_bomb)
        code, res, _ = self._http(f"{base}/api/scan-jobs", method="POST", body=body, content_type=ct)
        self.assertEqual(code, 400)
        self.assertEqual(res["error_code"], "ZIP_BOMB_DETECTED")

        # 4. ZIP without Java files
        z_nojava = _make_zip_bytes({"README.md": b"# hello"})
        ct, body = _make_multipart("file", "readme.zip", z_nojava)
        code, res, _ = self._http(f"{base}/api/scan-jobs", method="POST", body=body, content_type=ct)
        self.assertEqual(code, 400)
        self.assertEqual(res["error_code"], "NO_JAVA_FILES_IN_ZIP")

    def test_flow_c_scan_job_missing_opengrep_and_mock_ollama_citation_downgrade(self) -> None:
        valid_zip = _make_zip_bytes({"src/SqlDemo.java": SAMPLE_JAVA.encode("utf-8")})

        # Case 1: OpenGrep binary missing -> Job fails cleanly at Stage 2 with OPENGREP_UNAVAILABLE
        cfg_missing_og = ApiConfig(
            host="127.0.0.1",
            port=0,
            data_dir=self.root / "api_missing_og",
            api_token=TEST_TOKEN,
            opengrep_binary="opengrep-missing-binary-xyz",
        )
        _, base1 = self._start_server(cfg_missing_og)
        ct, body = _make_multipart("file", "project.zip", valid_zip, extra_fields={"no_llm": "true"})
        code, job_sub, _ = self._http(f"{base1}/api/scan-jobs", method="POST", body=body, content_type=ct)
        self.assertEqual(code, 202)
        job_id = job_sub["job_id"]
        for _ in range(40):
            _, j_state, _ = self._http(f"{base1}/api/scan-jobs/{job_id}")
            if j_state["state"] in ("COMPLETED", "FAILED"):
                break
            time.sleep(0.1)
        self.assertEqual(j_state["state"], "FAILED")
        self.assertEqual(j_state["error_code"], "OPENGREP_UNAVAILABLE")

        # Case 2: OpenGrep stub + Mock Ollama loopback server
        # Finding 0 gets valid citation -> SUPPORTED; Finding 1 gets invalid quote -> downgraded to UNDETERMINED!
        og_cmd = _write_fake_opengrep_cmd(self.root)
        call_counter = {"chat": 0}

        class MockOllamaHandler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                return

            def do_GET(self):
                if self.path == "/api/tags":
                    out = json.dumps({"models": [{"name": "qwen3.5:9b-q4_K_M"}]}).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(out)))
                    self.end_headers()
                    self.wfile.write(out)
                    return
                self.send_response(404)
                self.end_headers()

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                req_doc = json.loads(self.rfile.read(length).decode("utf-8"))
                user_payload = json.loads(req_doc["messages"][1]["content"])
                snip = user_payload["snippets"][0]
                idx = call_counter["chat"]
                call_counter["chat"] += 1
                if idx == 0:
                    sink_line_obj = next(l for l in snip["lines"] if "executeQuery" in l["text"])
                    ans = {
                        "status": "SUPPORTED",
                        "explanation": "Dòng truy vấn nối chuỗi trực tiếp từ tham số đầu vào.",
                        "fix_suggestion": "Sử dụng PreparedStatement.",
                        "citations": [
                            {
                                "path": snip["path"],
                                "start_line": sink_line_obj["line"],
                                "end_line": sink_line_obj["line"],
                                "quote": sink_line_obj["text"],
                                "sha256": snip["sha256"],
                            }
                        ],
                    }
                else:
                    ans = {
                        "status": "SUPPORTED",
                        "explanation": "Trích dẫn sai nội dung để kiểm tra bộ validator hạ về UNDETERMINED.",
                        "fix_suggestion": "",
                        "citations": [
                            {
                                "path": snip["path"],
                                "start_line": 1,
                                "end_line": 1,
                                "quote": "NON_EXISTENT_INVENTED_CODE_LINE",
                                "sha256": snip["sha256"],
                            }
                        ],
                    }
                envelope = {
                    "model": "qwen3.5:9b-q4_K_M",
                    "done": True,
                    "eval_count": 35,
                    "eval_duration": 10_000_000,
                    "message": {"role": "assistant", "content": json.dumps(ans, ensure_ascii=False)},
                }
                raw_out = json.dumps(envelope).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw_out)))
                self.end_headers()
                self.wfile.write(raw_out)

        ollama_srv = HTTPServer(("127.0.0.1", 0), MockOllamaHandler)
        ollama_thread = threading.Thread(target=ollama_srv.serve_forever, daemon=True)
        ollama_thread.start()

        def _stop_ollama() -> None:
            ollama_srv.shutdown()
            ollama_thread.join(timeout=2.0)
            ollama_srv.server_close()

        self.addCleanup(_stop_ollama)
        ollama_port = ollama_srv.server_address[1]

        cfg_e2e = ApiConfig(
            host="127.0.0.1",
            port=0,
            data_dir=self.root / "api_e2e_mock",
            api_token=TEST_TOKEN,
            opengrep_binary=str(og_cmd),
            ollama_endpoint=f"http://127.0.0.1:{ollama_port}",
            runtime_origin="mock",
        )
        srv2, base2 = self._start_server(cfg_e2e)

        # Wait for the bounded active OpenGrep health probe to evaluate the mock stub:
        # _write_fake_opengrep_cmd emits CWE-22 on the SQLi line rather than the canary FileInputStream sink,
        # so the strict canary oracle MUST reject it and keep /api/health DEGRADED (fail-closed, never OK).
        self.assertTrue(srv2.service.wait_for_opengrep_probe(timeout=10.0))
        code, h_ok, _ = self._http(f"{base2}/api/health")
        self.assertEqual(code, 200)
        self.assertEqual(h_ok["status"], "DEGRADED")
        self.assertIn("OPENGREP_UNAVAILABLE", h_ok["degraded_reasons"])
        self.assertFalse(h_ok["opengrep"]["available"])
        self.assertFalse(h_ok["opengrep"]["runtime_verified"])
        self.assertEqual(h_ok["opengrep"]["probe_status"], "CANARY_FAILED")
        self.assertTrue(h_ok["ollama"]["reachable"])
        self.assertTrue(h_ok["ollama"]["model_installed"])

        ct2, body2 = _make_multipart("file", "java_app.zip", valid_zip)
        code, j2_sub, _ = self._http(f"{base2}/api/scan-jobs", method="POST", body=body2, content_type=ct2)
        self.assertEqual(code, 202)
        job2_id = j2_sub["job_id"]
        for _ in range(80):
            _, j2, _ = self._http(f"{base2}/api/scan-jobs/{job2_id}")
            if j2["state"] in ("COMPLETED", "FAILED"):
                break
            time.sleep(0.1)
        self.assertEqual(j2["state"], "COMPLETED", j2)
        scan_id = j2["scan_id"]
        self.assertTrue(scan_id)

        code, flist, _ = self._http(f"{base2}/api/scans/{scan_id}/findings")
        self.assertEqual(code, 200)
        self.assertEqual(flist["total_count"], 2)
        by_cwe = {row["cwe"]: row for row in flist["findings"]}

        # CWE-89 had valid citation -> SUPPORTED + MATCHED + OPEN
        self.assertEqual(by_cwe["CWE-89"]["validated_status"], "SUPPORTED")
        self.assertEqual(by_cwe["CWE-89"]["citation_check"], "MATCHED")
        self.assertEqual(by_cwe["CWE-89"]["human_review_state"], "OPEN")

        # CWE-22 had invalid citation quote -> downgraded to UNDETERMINED, preserving raw_model_status = SUPPORTED!
        self.assertEqual(by_cwe["CWE-22"]["raw_model_status"], "SUPPORTED")
        self.assertEqual(by_cwe["CWE-22"]["validated_status"], "UNDETERMINED")
        self.assertTrue(by_cwe["CWE-22"]["validator_downgraded"])
        self.assertEqual(by_cwe["CWE-22"]["failure_kind"], "INVALID_CITATION")
        self.assertEqual(by_cwe["CWE-22"]["human_review_state"], "OPEN")

    def test_unreachable_ollama_and_citation_hash_mismatch_stay_undetermined_and_open(self) -> None:
        valid_zip = _make_zip_bytes({"src/SqlDemo.java": SAMPLE_JAVA.encode("utf-8")})
        og_cmd = _write_fake_opengrep_cmd(self.root)

        # 1. Ollama unreachable -> findings still ingested into SQLite as UNDETERMINED + OPEN
        cfg_no_ollama = ApiConfig(
            host="127.0.0.1",
            port=0,
            data_dir=self.root / "api_no_ollama",
            api_token=TEST_TOKEN,
            opengrep_binary=str(og_cmd),
            ollama_endpoint="http://127.0.0.1:65531",
            ollama_timeout_seconds=1.5,
            runtime_origin="mock",
        )
        _, base_down = self._start_server(cfg_no_ollama)
        ct, body = _make_multipart("file", "offline_ollama.zip", valid_zip)
        code, j_sub, _ = self._http(f"{base_down}/api/scan-jobs", method="POST", body=body, content_type=ct)
        self.assertEqual(code, 202)
        for _ in range(80):
            _, j_cur, _ = self._http(f"{base_down}/api/scan-jobs/{j_sub['job_id']}")
            if j_cur["state"] in ("COMPLETED", "FAILED"):
                break
            time.sleep(0.1)
        self.assertEqual(j_cur["state"], "COMPLETED", j_cur)
        self.assertEqual(j_cur["stage_statuses"]["qwen_inference_status"], "PARTIAL_OR_FAILED")
        _, flist, _ = self._http(f"{base_down}/api/scans/{j_cur['scan_id']}/findings")
        self.assertEqual(flist["total_count"], 2)
        self.assertTrue(all(f["validated_status"] == "UNDETERMINED" for f in flist["findings"]))
        self.assertTrue(all(f["human_review_state"] == "OPEN" for f in flist["findings"]))

        # 2. Ollama returns mismatched citation sha256 -> downgraded to UNDETERMINED + OPEN
        class BadHashOllama(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                return

            def do_GET(self):
                out = json.dumps({"models": [{"name": "qwen3.5:9b-q4_K_M"}]}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                req_doc = json.loads(self.rfile.read(length).decode("utf-8"))
                snip = json.loads(req_doc["messages"][1]["content"])["snippets"][0]
                sink_line_obj = next(l for l in snip["lines"] if "executeQuery" in l["text"])
                ans = {
                    "status": "REFUTED",
                    "explanation": "Thử trả sha256 giả mạo để kiểm tra chốt băm mã nguồn.",
                    "fix_suggestion": "",
                    "citations": [
                        {
                            "path": snip["path"],
                            "start_line": sink_line_obj["line"],
                            "end_line": sink_line_obj["line"],
                            "quote": sink_line_obj["text"],
                            "sha256": "0" * 64,
                        }
                    ],
                }
                raw_out = json.dumps(
                    {
                        "model": "qwen3.5:9b-q4_K_M",
                        "done": True,
                        "eval_count": 20,
                        "message": {"role": "assistant", "content": json.dumps(ans)},
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw_out)))
                self.end_headers()
                self.wfile.write(raw_out)

        bad_srv = HTTPServer(("127.0.0.1", 0), BadHashOllama)
        bad_thread = threading.Thread(target=bad_srv.serve_forever, daemon=True)
        bad_thread.start()
        self.addCleanup(lambda: (bad_srv.shutdown(), bad_thread.join(timeout=2.0), bad_srv.server_close()))

        cfg_bad_hash = ApiConfig(
            host="127.0.0.1",
            port=0,
            data_dir=self.root / "api_bad_hash",
            api_token=TEST_TOKEN,
            opengrep_binary=str(og_cmd),
            ollama_endpoint=f"http://127.0.0.1:{bad_srv.server_address[1]}",
            runtime_origin="mock",
        )
        _, base_bh = self._start_server(cfg_bad_hash)
        code, j_bh_sub, _ = self._http(f"{base_bh}/api/scan-jobs", method="POST", body=body, content_type=ct)
        self.assertEqual(code, 202)
        for _ in range(80):
            _, j_bh, _ = self._http(f"{base_bh}/api/scan-jobs/{j_bh_sub['job_id']}")
            if j_bh["state"] in ("COMPLETED", "FAILED"):
                break
            time.sleep(0.1)
        self.assertEqual(j_bh["state"], "COMPLETED")
        _, bh_findings, _ = self._http(f"{base_bh}/api/scans/{j_bh['scan_id']}/findings")
        for f in bh_findings["findings"]:
            self.assertEqual(f["raw_model_status"], "REFUTED")
            self.assertEqual(f["validated_status"], "UNDETERMINED")
            self.assertTrue(f["validator_downgraded"])
            self.assertEqual(f["human_review_state"], "OPEN")

    def test_unconfigured_token_locks_all_write_operations(self) -> None:
        cfg_no_token = ApiConfig(
            host="127.0.0.1",
            port=0,
            data_dir=self.root / "api_no_tok",
            api_token=None,
            read_auth_mode="write-only",
        )
        _, base = self._start_server(cfg_no_token)
        code, h, _ = self._http(f"{base}/api/health", token=None)
        self.assertEqual(code, 200)
        self.assertFalse(h["write_auth_configured"])

        code, err, _ = self._http(
            f"{base}/api/scan-jobs",
            method="POST",
            token=None,
            body={"repo_url": "https://github.com/owner/repo"},
        )
        self.assertEqual(code, 503)
        self.assertEqual(err["error_code"], "AUTH_TOKEN_NOT_CONFIGURED")


if __name__ == "__main__":
    unittest.main()
