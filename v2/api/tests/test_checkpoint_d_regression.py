"""Checkpoint D regression tests: Windows/cross-host compatibility, CORS, mock isolation, limits, and report schema."""
from __future__ import annotations

from http.client import HTTPConnection
import json
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from v2.api.config import ApiConfig
from v2.api.server import ThesisApiServer
from v2.triage import evidence, store


TEST_TOKEN = "checkpoint-d-api-token-20261117"

SAMPLE_JAVA = (
    "package demo;\n"
    "public class FileController {\n"
    "    public java.io.File read(javax.servlet.http.HttpServletRequest req) {\n"
    '        String f = req.getParameter("f");\n'
    '        return new java.io.File("/srv/files", f);\n'
    "    }\n"
    "}\n"
)


def _make_scan(base_dir: Path, *, mark_mock: bool = False, tag: str = "real") -> tuple[Path, str, str]:
    src_dir = base_dir / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    java_file = src_dir / "FileController.java"
    code = SAMPLE_JAVA + f"// {tag}\n"
    java_file.write_text(code, encoding="utf-8")
    lines = code.splitlines()
    src_txt = 'req.getParameter("f")'
    sink_txt = 'new java.io.File("/srv/files", f)'
    cs = lines[3].index(src_txt) + 1
    ck = lines[4].index(sink_txt) + 1
    src_loc = {"path": "FileController.java", "start": {"line": 4, "col": cs}, "end": {"line": 4, "col": cs + len(src_txt)}}
    sink_loc = {"path": "FileController.java", "start": {"line": 5, "col": ck}, "end": {"line": 5, "col": ck + len(sink_txt)}}
    finding = {
        "check_id": "v2.g1.java.cwe22.path-traversal",
        **sink_loc,
        "extra": {
            "severity": "ERROR",
            "message": f"CWE-22 finding ({tag})",
            "metadata": {"cwe": ["CWE-22: Path Traversal"]},
            "dataflow_trace": {
                "taint_source": ["CliLoc", [src_loc, src_txt]],
                "taint_sink": ["CliLoc", [sink_loc, sink_txt]],
                "intermediate_vars": [],
            },
        },
    }
    raw_bytes = json.dumps({"results": [finding], "errors": []}).encode("utf-8")
    sha = evidence.digest(java_file.read_bytes())
    prov = {
        "origin": "UNIT_TEST_MOCK_CAPTURE" if mark_mock else "recorded_capture_unsigned",
        "source_capture_verified": True,
        "exit_capture_verified": True,
        "recorded_engine_exit": 0,
        "source_hashes": {"FileController.java": sha},
    }
    bundle = evidence.collect(raw_bytes, src_dir, engine_exit=0, scan_provenance=prov)
    bundle["scan_provenance"] = prov
    bundle["pre_scan_hashes"] = {"FileController.java": sha}
    ass = {
        "status": "REFUTED",
        "raw_model_status": "REFUTED",
        "validated_status": "REFUTED",
        "validator_downgraded": False,
        "failure_kind": None,
        "explanation": "Regression check",
        "fix_suggestion": "Canonical path check",
        "citations": [{"path": "FileController.java", "start_line": 5, "end_line": 5, "quote": lines[4], "sha256": sha}],
        "citation_check": "MATCHED",
        "requires_human_review": True,
        "security_conclusion_verified": False,
        "analyzed_at": evidence.now(),
        "runtime": {"origin": "mock" if mark_mock else "unverified", "model_runtime_verified": False},
    }
    scan_dir = base_dir / "scan"
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "input.opengrep.json").write_bytes(raw_bytes)
    (scan_dir / "evidence.json").write_text(json.dumps(bundle), encoding="utf-8")
    rs = store.ReviewStore(scan_dir / "review.sqlite")
    try:
        rs.add(bundle, [ass])
    finally:
        rs.close()
    return scan_dir, bundle["scan_sha256"], bundle["records"][0]["id"]


class CheckpointDRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def _start_server(self, config: ApiConfig) -> tuple[str, int]:
        srv = ThesisApiServer(config)
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: (srv.shutdown(), thread.join(timeout=2.0), srv.server_close()))
        host, port = srv.server_address[:2]
        return str(host), int(port)

    def _http(self, url: str, *, method: str = "GET", token: str | None = TEST_TOKEN, body: dict | None = None) -> tuple[int, dict, dict]:
        headers = {"Connection": "close"}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        raw = None
        if body is not None:
            raw = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = Request(url, data=raw, headers=headers, method=method)
        try:
            with urlopen(req, timeout=15) as resp:
                txt = resp.read().decode("utf-8")
                return resp.status, (json.loads(txt) if txt else {}), dict(resp.headers)
        except HTTPError as exc:
            txt = exc.read().decode("utf-8")
            return exc.code, (json.loads(txt) if txt else {}), dict(exc.headers)

    def test_keepalive_post_401_does_not_corrupt_next_request_on_same_socket(self) -> None:
        rw_dir, scan_id, finding_id = _make_scan(self.root / "ka", tag="ka")
        host, port = self._start_server(
            ApiConfig(
                host="127.0.0.1",
                port=0,
                data_dir=self.root / "data_ka",
                reviewable_scan_dirs=(rw_dir,),
                api_token=TEST_TOKEN,
            )
        )
        conn = HTTPConnection(host, port, timeout=10)
        self.addCleanup(conn.close)

        # 1. Unauthenticated POST with body -> 401 UNAUTHORIZED
        payload = json.dumps({"actor": "reviewer", "reason": "No auth"})
        conn.request(
            "POST",
            f"/api/scans/{scan_id}/findings/{finding_id}/confirm-true",
            body=payload,
            headers={"Content-Type": "application/json"},
        )
        r1 = conn.getresponse()
        r1.read()
        self.assertEqual(r1.status, 401)

        # 2. Reuse the SAME keep-alive connection for an authenticated GET -> must return 200, not 400!
        conn.request("GET", f"/api/scans/{scan_id}", headers={"Authorization": f"Bearer {TEST_TOKEN}"})
        r2 = conn.getresponse()
        body2 = json.loads(r2.read().decode("utf-8"))
        self.assertEqual(r2.status, 200)
        self.assertEqual(body2["scan_id"], scan_id)

    def test_cors_preflight_mock_history_isolation_and_report_contents(self) -> None:
        real_dir, real_scan, real_finding = _make_scan(self.root / "real", mark_mock=False, tag="real")
        mock_dir, mock_scan, mock_finding = _make_scan(self.root / "mock", mark_mock=True, tag="mock")
        host, port = self._start_server(
            ApiConfig(
                host="127.0.0.1",
                port=0,
                data_dir=self.root / "data_rep",
                reviewable_scan_dirs=(real_dir, mock_dir),
                api_token=TEST_TOKEN,
                cors_origins=("http://localhost:5173",),
            )
        )
        base = f"http://{host}:{port}"

        # CORS preflight
        req_opt = Request(
            f"{base}/api/scans",
            method="OPTIONS",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Authorization, Content-Type",
            },
        )
        with urlopen(req_opt, timeout=10) as resp:
            self.assertEqual(resp.status, 204)
            self.assertEqual(resp.headers.get("Access-Control-Allow-Origin"), "http://localhost:5173")
            self.assertIn("Authorization", resp.headers.get("Access-Control-Allow-Headers", ""))

        # Mock scan blocked on history & review-history
        for url in (
            f"{base}/api/scans/{mock_scan}/review-history",
            f"{base}/api/scans/{mock_scan}/findings/{mock_finding}/history",
            f"{base}/api/scans/{mock_scan}/report",
        ):
            code, err, _ = self._http(url)
            self.assertEqual(code, 403)
            self.assertEqual(err["error_code"], "TEST_DATA_ISOLATED")

        # Real scan report has all required fields and preserves REFUTED as OPEN
        code, rep, _ = self._http(f"{base}/api/scans/{real_scan}/report")
        self.assertEqual(code, 200)
        self.assertFalse(rep["contains_mock_or_test_data"])
        self.assertEqual(rep["scan_summary"]["by_cwe"], {"CWE-22": 1})
        self.assertEqual(rep["scan_summary"]["by_validated_status"]["REFUTED"], 1)
        self.assertEqual(rep["scan_summary"]["by_human_review_state"]["OPEN"], 1)
        self.assertEqual(rep["scan_summary"]["by_human_review_state"]["CONFIRMED_FALSE"], 0)
        self.assertTrue(len(rep["scan_summary"]["known_analysis_limits"]) > 0)
        self.assertEqual(len(rep["findings"]), 1)
        self.assertEqual(len(rep["findings"][0]["assessment"]["citations"]), 1)
        self.assertIn("FileController.java", rep["findings"][0]["evidence"]["snapshots"])

    def test_oversized_json_body_rejected_with_413_and_connection_close(self) -> None:
        rw_dir, scan_id, finding_id = _make_scan(self.root / "big", tag="big")
        host, port = self._start_server(
            ApiConfig(
                host="127.0.0.1",
                port=0,
                data_dir=self.root / "data_big",
                reviewable_scan_dirs=(rw_dir,),
                api_token=TEST_TOKEN,
            )
        )
        big_body = json.dumps({"actor": "reviewer", "reason": "x" * 70_000}).encode("utf-8")
        req = Request(
            f"http://{host}:{port}/api/scans/{scan_id}/findings/{finding_id}/confirm-true",
            data=big_body,
            headers={
                "Authorization": f"Bearer {TEST_TOKEN}",
                "Content-Type": "application/json",
                "Connection": "close",
            },
            method="POST",
        )
        try:
            urlopen(req, timeout=10)
            self.fail("Expected 413 PAYLOAD_TOO_LARGE")
        except HTTPError as exc:
            self.assertEqual(exc.code, 413)
            err = json.loads(exc.read().decode("utf-8"))
            self.assertEqual(err["error_code"], "PAYLOAD_TOO_LARGE")


if __name__ == "__main__":
    unittest.main()
