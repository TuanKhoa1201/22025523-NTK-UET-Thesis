"""Checkpoint C tests: Human Review queue, confirm-true/false, reopen, 409 STALE_SOURCE, auth & error guards."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
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


TEST_TOKEN = "checkpoint-c-test-token-20261117"

SAMPLE_JAVA = (
    "package demo;\n"
    "public class PathDemo {\n"
    "    public java.io.File openFile(javax.servlet.http.HttpServletRequest req) {\n"
    '        String name = req.getParameter("file");\n'
    '        return new java.io.File("/var/data", name);\n'
    "    }\n"
    "}\n"
)


def _create_isolated_scan(
    base_dir: Path,
    *,
    validated_status: str = "REFUTED",
    with_evidence_issue: bool = False,
    tag: str = "default",
) -> tuple[Path, Path, str, str]:
    src_dir = base_dir / "java_src"
    src_dir.mkdir(parents=True, exist_ok=True)
    java_file = src_dir / "PathDemo.java"
    java_code = SAMPLE_JAVA + f"// scan-tag: {tag}\n"
    java_file.write_text(java_code, encoding="utf-8")
    lines = java_code.splitlines()

    def _loc(ln: int, needle: str) -> dict:
        col = lines[ln - 1].index(needle) + 1
        return {
            "path": "PathDemo.java",
            "start": {"line": ln, "col": col},
            "end": {"line": ln, "col": col + len(needle)},
        }

    src_loc = _loc(4, 'req.getParameter("file")')
    sink_loc = _loc(5, 'new java.io.File("/var/data", name)')
    finding = {
        "check_id": "v2.g1.java.cwe22.path-traversal",
        **sink_loc,
        "extra": {
            "severity": "ERROR",
            "message": f"Potential CWE-22 Path Traversal ({tag})",
            "metadata": {"cwe": ["CWE-22: Path Traversal"]},
            "dataflow_trace": {
                "taint_source": ["CliLoc", [src_loc, 'req.getParameter("file")']],
                "taint_sink": ["CliLoc", [sink_loc, 'new java.io.File("/var/data", name)']],
                "intermediate_vars": [],
            },
        },
    }
    raw_bytes = json.dumps({"results": [finding], "errors": []}).encode("utf-8")
    java_sha = evidence.digest(java_file.read_bytes())
    provenance = {
        "origin": "recorded_capture_unsigned",
        "source_capture_verified": True,
        "exit_capture_verified": True,
        "recorded_engine_exit": 0,
        "source_hashes": {"PathDemo.java": java_sha},
    }
    bundle = evidence.collect(raw_bytes, src_dir, engine_exit=0, scan_provenance=provenance)
    bundle["scan_provenance"] = provenance
    bundle["pre_scan_hashes"] = {"PathDemo.java": java_sha}
    rec = bundle["records"][0]
    if with_evidence_issue:
        rec["issues"] = ["TEST_FORCED_INCOMPLETE_EVIDENCE"]

    assessment = {
        "status": validated_status,
        "raw_model_status": validated_status,
        "validated_status": validated_status,
        "validator_downgraded": False,
        "failure_kind": None,
        "explanation": "Kiểm thử tách biệt trạng thái mô hình và trạng thái Human Review.",
        "fix_suggestion": "Kiểm tra đường dẫn canonical.",
        "citations": [
            {
                "path": "PathDemo.java",
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
        "runtime": {"origin": "unverified", "model_runtime_verified": False},
    }

    scan_dir = base_dir / "scan_out"
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "input.opengrep.json").write_bytes(raw_bytes)
    (scan_dir / "evidence.json").write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    rs = store.ReviewStore(scan_dir / "review.sqlite")
    try:
        rs.add(bundle, [assessment])
    finally:
        rs.close()

    return scan_dir, java_file, bundle["scan_sha256"], rec["id"]


class HumanReviewCheckpointCTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def _start_server(self, config: ApiConfig) -> str:
        srv = ThesisApiServer(config)
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()

        def _stop() -> None:
            srv.shutdown()
            thread.join(timeout=2.0)
            srv.server_close()

        self.addCleanup(_stop)
        host, port = srv.server_address[:2]
        return f"http://{host}:{port}"

    def _http(
        self,
        url: str,
        *,
        method: str = "GET",
        token: str | None = TEST_TOKEN,
        body: dict | bytes | None = None,
    ) -> tuple[int, dict]:
        headers = {"Connection": "close"}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        raw_body = None
        if isinstance(body, dict):
            raw_body = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif isinstance(body, bytes):
            raw_body = body
            headers["Content-Type"] = "application/json"

        req = Request(url, data=raw_body, headers=headers, method=method)
        try:
            with urlopen(req, timeout=15) as resp:
                txt = resp.read().decode("utf-8")
                return resp.status, (json.loads(txt) if txt else {})
        except HTTPError as exc:
            txt = exc.read().decode("utf-8")
            return exc.code, (json.loads(txt) if txt else {})

    def test_refuted_remains_open_confirm_false_reopen_history_and_stale_source_409(self) -> None:
        scan_dir, java_file, scan_id, finding_id = _create_isolated_scan(self.root / "rw", validated_status="REFUTED")
        base = self._start_server(
            ApiConfig(
                host="127.0.0.1",
                port=0,
                data_dir=self.root / "data",
                reviewable_scan_dirs=(scan_dir,),
                api_token=TEST_TOKEN,
            )
        )

        # 1. REFUTED finding stays OPEN in review queue & scan summary distinguishes two axes
        code, summary_open = self._http(f"{base}/api/scans/{scan_id}")
        self.assertEqual(code, 200)
        self.assertEqual(summary_open["by_validated_status"]["REFUTED"], 1)
        self.assertEqual(summary_open["by_human_review_state"]["OPEN"], 1)
        self.assertEqual(summary_open["proposed_refuted_open_count"], 1)

        code, queue = self._http(f"{base}/api/scans/{scan_id}/review-queue")
        self.assertEqual(code, 200)
        self.assertEqual(queue["data_origin"], "REAL_SCAN")
        self.assertIs(queue["is_test_or_mock"], False)
        self.assertIs(queue["scan_provenance"]["source_capture_verified"], True)
        self.assertIs(queue["scan_provenance"]["exit_capture_verified"], True)
        self.assertEqual(queue["counts"]["open_count"], 1)
        self.assertEqual(queue["counts"]["proposed_refuted_open_count"], 1)
        self.assertEqual(queue["warnings"][0]["validated_status"], "REFUTED")
        self.assertEqual(queue["warnings"][0]["human_review_state"], "OPEN")

        code, detail = self._http(f"{base}/api/scans/{scan_id}/findings/{finding_id}")
        self.assertEqual(code, 200)
        self.assertEqual(detail["data_origin"], "REAL_SCAN")
        self.assertIs(detail["is_test_or_mock"], False)
        self.assertIs(detail["evidence"]["scan_provenance"]["source_capture_verified"], True)

        # 2. confirm-false succeeds when source is intact -> CONFIRMED_FALSE
        code, d_false = self._http(
            f"{base}/api/scans/{scan_id}/findings/{finding_id}/confirm-false",
            method="POST",
            body={"actor": "reviewer-uet", "reason": "Đã kiểm tra whitelist tên tệp trên server"},
        )
        self.assertEqual(code, 200)
        self.assertEqual(d_false["human_review_state"], "CONFIRMED_FALSE")
        self.assertEqual(len(d_false["review_events"]), 1)
        self.assertEqual(d_false["review_events"][0]["action"], "confirm-false")

        # Hidden in default queue, present when include_all=true; summary separates REFUTED total vs REFUTED+OPEN
        code, summary_closed = self._http(f"{base}/api/scans/{scan_id}")
        self.assertEqual(code, 200)
        self.assertEqual(summary_closed["by_validated_status"]["REFUTED"], 1)
        self.assertEqual(summary_closed["by_human_review_state"]["CONFIRMED_FALSE"], 1)
        self.assertEqual(summary_closed["proposed_refuted_open_count"], 0)

        _, q_default = self._http(f"{base}/api/scans/{scan_id}/review-queue?include_all=false")
        self.assertEqual(len(q_default["warnings"]), 0)
        _, q_all = self._http(f"{base}/api/scans/{scan_id}/review-queue?include_all=true")
        self.assertEqual(len(q_all["warnings"]), 1)
        self.assertEqual(q_all["warnings"][0]["human_review_state"], "CONFIRMED_FALSE")

        # 3. reopen -> returns to OPEN with 2 events
        code, d_reopen = self._http(
            f"{base}/api/scans/{scan_id}/findings/{finding_id}/reopen",
            method="POST",
            body={"actor": "reviewer-lead", "reason": "Cần kiểm tra lại luồng gọi từ controller"},
        )
        self.assertEqual(code, 200)
        self.assertEqual(d_reopen["human_review_state"], "OPEN")
        self.assertEqual([e["action"] for e in d_reopen["review_events"]], ["confirm-false", "reopen"])

        # 4. Mutate source on disk -> confirm-false returns 409 STALE_SOURCE and logs rejected_decisions
        java_file.write_text(SAMPLE_JAVA + "// drifted\n", encoding="utf-8")
        code, stale = self._http(
            f"{base}/api/scans/{scan_id}/findings/{finding_id}/confirm-false",
            method="POST",
            body={"actor": "reviewer-uet", "reason": "Thử xác nhận giả sau khi sửa tệp Java"},
        )
        self.assertEqual(code, 409)
        self.assertEqual(stale["error_code"], "STALE_SOURCE")
        self.assertEqual(stale["human_review_state"], "OPEN")
        self.assertIn("PathDemo.java", stale["stale_source"]["mismatched_paths"])
        self.assertEqual(len(stale["review_events"]), 2)
        self.assertEqual(len(stale["rejected_decisions"]), 1)
        self.assertEqual(stale["rejected_decisions"][0]["rejection_code"], "STALE_SOURCE")

        # 5. History endpoints expose both applied events and rejected_decisions
        code, f_hist = self._http(f"{base}/api/scans/{scan_id}/findings/{finding_id}/history?include_rejected=true")
        self.assertEqual(code, 200)
        self.assertEqual(f_hist["human_review_state"], "OPEN")
        self.assertEqual(len(f_hist["events"]), 2)
        self.assertEqual(len(f_hist["rejected_decisions"]), 1)

        code, s_hist = self._http(f"{base}/api/scans/{scan_id}/review-history")
        self.assertEqual(code, 200)
        self.assertEqual(len(s_hist["events"]), 2)
        self.assertEqual(len(s_hist["rejected_decisions"]), 1)

    def test_auth_permissions_validation_and_refused_operations(self) -> None:
        rw_scan, _, rw_id, rw_finding = _create_isolated_scan(self.root / "rw_err", validated_status="UNDETERMINED", tag="rw_err")
        ro_scan, _, ro_id, ro_finding = _create_isolated_scan(self.root / "ro_err", validated_status="SUPPORTED", tag="ro_err")
        inc_scan, _, inc_id, inc_finding = _create_isolated_scan(
            self.root / "inc_err",
            validated_status="REFUTED",
            with_evidence_issue=True,
            tag="inc_err",
        )

        base = self._start_server(
            ApiConfig(
                host="127.0.0.1",
                port=0,
                data_dir=self.root / "data_err",
                reviewable_scan_dirs=(rw_scan, inc_scan),
                readonly_scan_dirs=(ro_scan,),
                api_token=TEST_TOKEN,
            )
        )

        # Missing & wrong Bearer token -> 401 UNAUTHORIZED
        for bad_tok in (None, "wrong-token"):
            code, err = self._http(
                f"{base}/api/scans/{rw_id}/findings/{rw_finding}/confirm-true",
                method="POST",
                token=bad_tok,
                body={"actor": "reviewer", "reason": "No auth"},
            )
            self.assertEqual(code, 401)
            self.assertEqual(err["error_code"], "UNAUTHORIZED")

        # Read-only scan -> 403 SCAN_READ_ONLY
        code, err = self._http(
            f"{base}/api/scans/{ro_id}/findings/{ro_finding}/confirm-true",
            method="POST",
            body={"actor": "reviewer", "reason": "Try RO mutation"},
        )
        self.assertEqual(code, 403)
        self.assertEqual(err["error_code"], "SCAN_READ_ONLY")

        # Validation errors -> 400
        code, err = self._http(
            f"{base}/api/scans/{rw_id}/findings/{rw_finding}/confirm-true",
            method="POST",
            body={"actor": "   ", "reason": "Valid reason"},
        )
        self.assertEqual(code, 400)
        self.assertEqual(err["error_code"], "INVALID_REVIEW_ACTOR")

        code, err = self._http(
            f"{base}/api/scans/{rw_id}/findings/{rw_finding}/confirm-true",
            method="POST",
            body={"actor": "bad\nactor", "reason": "Valid reason"},
        )
        self.assertEqual(code, 400)
        self.assertEqual(err["error_code"], "INVALID_REVIEW_ACTOR")

        code, err = self._http(
            f"{base}/api/scans/{rw_id}/findings/{rw_finding}/confirm-true",
            method="POST",
            body={"actor": "reviewer", "reason": "   "},
        )
        self.assertEqual(code, 400)
        self.assertEqual(err["error_code"], "INVALID_REVIEW_REASON")

        code, err = self._http(
            f"{base}/api/scans/{rw_id}/findings/{rw_finding}/confirm-true",
            method="POST",
            body=b"not-json",
        )
        self.assertEqual(code, 400)
        self.assertEqual(err["error_code"], "INVALID_JSON_BODY")

        # Unknown finding -> 404
        code, err = self._http(
            f"{base}/api/scans/{rw_id}/findings/non-existent-finding/confirm-true",
            method="POST",
            body={"actor": "reviewer", "reason": "Missing finding"},
        )
        self.assertEqual(code, 404)
        self.assertEqual(err["error_code"], "FINDING_NOT_FOUND")

        # Incomplete evidence -> confirm-false refused with 409 CONFIRM_FALSE_REFUSED
        code, err = self._http(
            f"{base}/api/scans/{inc_id}/findings/{inc_finding}/confirm-false",
            method="POST",
            body={"actor": "reviewer", "reason": "Incomplete evidence guard"},
        )
        self.assertEqual(code, 409)
        self.assertEqual(err["error_code"], "CONFIRM_FALSE_REFUSED")
        self.assertEqual(err["human_review_state"], "OPEN")

        # Unconfigured server token -> 503 AUTH_TOKEN_NOT_CONFIGURED on review POST
        base_notok = self._start_server(
            ApiConfig(
                host="127.0.0.1",
                port=0,
                data_dir=self.root / "data_notok",
                reviewable_scan_dirs=(rw_scan,),
                api_token=None,
                read_auth_mode="write-only",
            )
        )
        code, err = self._http(
            f"{base_notok}/api/scans/{rw_id}/findings/{rw_finding}/confirm-true",
            method="POST",
            token=None,
            body={"actor": "reviewer", "reason": "Server token missing"},
        )
        self.assertEqual(code, 503)
        self.assertEqual(err["error_code"], "AUTH_TOKEN_NOT_CONFIGURED")

    def test_concurrent_review_decisions_serialized_without_sqlite_lock_error(self) -> None:
        scan_dir, _, scan_id, finding_id = _create_isolated_scan(self.root / "conc", validated_status="SUPPORTED")
        base = self._start_server(
            ApiConfig(
                host="127.0.0.1",
                port=0,
                data_dir=self.root / "data_conc",
                reviewable_scan_dirs=(scan_dir,),
                api_token=TEST_TOKEN,
            )
        )

        def _send(idx: int) -> int:
            action = "confirm-true" if idx % 2 == 0 else "reopen"
            code, _ = self._http(
                f"{base}/api/scans/{scan_id}/findings/{finding_id}/{action}",
                method="POST",
                body={"actor": f"reviewer-{idx}", "reason": f"Concurrent check #{idx}"},
            )
            return code

        with ThreadPoolExecutor(max_workers=6) as pool:
            statuses = list(pool.map(_send, range(10)))
        self.assertTrue(all(s == 200 for s in statuses), statuses)

        code, hist = self._http(f"{base}/api/scans/{scan_id}/findings/{finding_id}/history")
        self.assertEqual(code, 200)
        self.assertEqual(len(hist["events"]), 10)


if __name__ == "__main__":
    unittest.main()
