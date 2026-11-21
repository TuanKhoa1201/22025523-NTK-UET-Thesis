"""Counterexample & remediation tests for Audit Finding A3 (report provenance cross-check & mock leak in paired_pilot_export)."""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from v2.api.config import ApiConfig
from v2.api.server import ThesisApiServer
from v2.triage import evidence, store


TEST_TOKEN = "remediation-a3-token-20261117"

SAMPLE_JAVA = (
    "package demo;\n"
    "public class ReportAuditDemo {\n"
    "    public java.io.File open(javax.servlet.http.HttpServletRequest req) {\n"
    '        String f = req.getParameter("f");\n'
    '        return new java.io.File("/srv/data", f);\n'
    "    }\n"
    "}\n"
)


def _create_full_scan_dir(
    base_dir: Path,
    *,
    tag: str,
    sqlite_runtime_origin: str = "unverified",
    jsonl_runtime_origin: str | None = None,
    source_capture_verified: bool = True,
    exit_capture_verified: bool = True,
    recorded_engine_exit: int = 0,
    snippet_mock: bool = False,
) -> tuple[Path, str, str, dict]:
    src_dir = base_dir / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    java_file = src_dir / "ReportAuditDemo.java"
    code = SAMPLE_JAVA + f"// {tag}\n"
    java_file.write_text(code, encoding="utf-8")
    lines = code.splitlines()
    src_txt = 'req.getParameter("f")'
    sink_txt = 'new java.io.File("/srv/data", f)'
    cs = lines[3].index(src_txt) + 1
    ck = lines[4].index(sink_txt) + 1
    src_loc = {"path": "ReportAuditDemo.java", "start": {"line": 4, "col": cs}, "end": {"line": 4, "col": cs + len(src_txt)}}
    sink_loc = {"path": "ReportAuditDemo.java", "start": {"line": 5, "col": ck}, "end": {"line": 5, "col": ck + len(sink_txt)}}
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
        "origin": "recorded_capture_unsigned",
        "source_capture_verified": source_capture_verified,
        "exit_capture_verified": exit_capture_verified,
        "recorded_engine_exit": recorded_engine_exit,
        "source_hashes": {"ReportAuditDemo.java": sha},
    }
    bundle = evidence.collect(raw_bytes, src_dir, engine_exit=recorded_engine_exit, scan_provenance=prov)
    bundle["scan_provenance"] = prov
    bundle["pre_scan_hashes"] = {"ReportAuditDemo.java": sha}
    rec = bundle["records"][0]
    if snippet_mock and rec.get("snippets"):
        rec["snippets"][0]["metadata"] = {"mock": True}

    def _make_assessment(rt_origin: str) -> dict:
        return {
            "status": "REFUTED",
            "raw_model_status": "REFUTED",
            "validated_status": "REFUTED",
            "validator_downgraded": False,
            "failure_kind": None,
            "explanation": "Audit A3 test",
            "fix_suggestion": "Normalize path",
            "citations": [{"path": "ReportAuditDemo.java", "start_line": 5, "end_line": 5, "quote": lines[4], "sha256": sha}],
            "citation_check": "MATCHED",
            "requires_human_review": True,
            "security_conclusion_verified": False,
            "analyzed_at": evidence.now(),
            "runtime": {"origin": rt_origin, "model_runtime_verified": False},
        }

    sqlite_ass = _make_assessment(sqlite_runtime_origin)
    jsonl_ass = json.loads(json.dumps(sqlite_ass))
    if jsonl_runtime_origin is not None:
        jsonl_ass["runtime"]["origin"] = jsonl_runtime_origin

    scan_dir = base_dir / "scan"
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
        "assessment": jsonl_ass,
    }
    (scan_dir / "assessments.jsonl").write_text(json.dumps(jsonl_row) + "\n", encoding="utf-8")
    rs = store.ReviewStore(scan_dir / "review.sqlite")
    try:
        rs.add(bundle, [sqlite_ass])
    finally:
        rs.close()

    return scan_dir, bundle["scan_sha256"], rec["id"], jsonl_row


class AuditRemediationA3Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def _start_server(self, scan_dirs: tuple[Path, ...]) -> str:
        srv = ThesisApiServer(
            ApiConfig(
                host="127.0.0.1",
                port=0,
                data_dir=self.root / "api_data",
                reviewable_scan_dirs=scan_dirs,
                api_token=TEST_TOKEN,
            )
        )
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: (srv.shutdown(), thread.join(timeout=2.0), srv.server_close()))
        host, port = srv.server_address[:2]
        return f"http://{host}:{port}"

    def _get_report(self, base: str, scan_id: str) -> tuple[int, dict]:
        req = Request(
            f"{base}/api/scans/{scan_id}/report",
            headers={"Authorization": f"Bearer {TEST_TOKEN}", "Connection": "close"},
            method="GET",
        )
        try:
            with urlopen(req, timeout=15) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_valid_consistent_report_succeeds(self) -> None:
        scan_dir, scan_id, _, _ = _create_full_scan_dir(self.root / "ok", tag="ok")
        base = self._start_server((scan_dir,))
        code, rep = self._get_report(base, scan_id)
        self.assertEqual(code, 200)
        self.assertEqual(rep["data_origin"], "REAL_SCAN")
        self.assertFalse(rep["contains_mock_or_test_data"])
        self.assertIsNotNone(rep["paired_pilot_export"])
        self.assertEqual(len(rep["paired_pilot_export"]["triage"]["triage_results"]), 1)

    def test_a3_sqlite_real_but_jsonl_has_mock_runtime_must_block_export(self) -> None:
        # SQLite says unverified/real, while assessments.jsonl has runtime.origin == "mock"!
        scan_dir, scan_id, _, _ = _create_full_scan_dir(
            self.root / "mock_jsonl",
            tag="mock_jsonl",
            sqlite_runtime_origin="unverified",
            jsonl_runtime_origin="mock",
        )
        base = self._start_server((scan_dir,))
        code, payload = self._get_report(base, scan_id)
        self.assertEqual(code, 403, f"Expected 403 TEST_DATA_ISOLATED, got {code}: {payload}")
        self.assertEqual(payload["error_code"], "TEST_DATA_ISOLATED")

    def test_a3_inconsistent_or_corrupt_artifacts_fail_closed(self) -> None:
        # Case 1: raw input.opengrep.json tampered (SHA-256 mismatch with SQLite scan_sha256)
        dir_raw, scan_raw, _, _ = _create_full_scan_dir(self.root / "bad_raw", tag="bad_raw")
        (dir_raw / "input.opengrep.json").write_text('{"results": [], "errors": []}', encoding="utf-8")

        # Case 2: assessments.jsonl status disagrees with SQLite assessment
        dir_stat, scan_stat, _, row_stat = _create_full_scan_dir(self.root / "bad_stat", tag="bad_stat")
        row_stat["assessment"]["validated_status"] = "SUPPORTED"
        row_stat["assessment"]["status"] = "SUPPORTED"
        (dir_stat / "assessments.jsonl").write_text(json.dumps(row_stat) + "\n", encoding="utf-8")

        # Case 3: assessments.jsonl is malformed JSON
        dir_corrupt, scan_corrupt, _, _ = _create_full_scan_dir(self.root / "bad_json", tag="bad_json")
        (dir_corrupt / "assessments.jsonl").write_text("{not-valid-json\n", encoding="utf-8")

        # Case 4: evidence.json provenance differs from SQLite bundle
        dir_ev, scan_ev, _, _ = _create_full_scan_dir(self.root / "bad_ev", tag="bad_ev")
        ev_doc = json.loads((dir_ev / "evidence.json").read_text(encoding="utf-8"))
        ev_doc["scan_provenance"]["source_capture_verified"] = False
        (dir_ev / "evidence.json").write_text(json.dumps(ev_doc), encoding="utf-8")

        # Case 5: assessments.jsonl exists while raw input.opengrep.json is missing
        dir_miss_raw, scan_miss_raw, _, _ = _create_full_scan_dir(self.root / "miss_raw", tag="miss_raw")
        (dir_miss_raw / "input.opengrep.json").unlink()

        base = self._start_server((dir_raw, dir_stat, dir_corrupt, dir_ev, dir_miss_raw))
        for label, sid in (
            ("raw_sha_mismatch", scan_raw),
            ("jsonl_status_mismatch", scan_stat),
            ("jsonl_corrupt", scan_corrupt),
            ("evidence_provenance_mismatch", scan_ev),
            ("missing_raw_json_with_jsonl", scan_miss_raw),
        ):
            with self.subTest(case=label):
                code, payload = self._get_report(base, sid)
                self.assertEqual(code, 409, f"[{label}] Expected 409 fail-closed, got {code}: {payload}")
                self.assertEqual(payload["error_code"], "ARTIFACT_PROVENANCE_MISMATCH")

    def test_a3_missing_provenance_cannot_be_labeled_real_scan(self) -> None:
        # Unverified capture flags + missing raw_json_path: must NOT be REAL_SCAN
        scan_dir, scan_id, _, _ = _create_full_scan_dir(
            self.root / "unver",
            tag="unver",
            source_capture_verified=False,
            exit_capture_verified=False,
        )
        base = self._start_server((scan_dir,))
        code, rep = self._get_report(base, scan_id)
        self.assertEqual(code, 200)
        self.assertNotEqual(rep["data_origin"], "REAL_SCAN")
        self.assertEqual(rep["data_origin"], "IMPORTED_SCAN_UNVERIFIED_CAPTURE")

    def test_snippet_metadata_mock_and_nonzero_engine_exit_cannot_be_labeled_real_scan(self) -> None:
        # 1. evidence.snippets[0].metadata.mock = True -> classified MOCK_SYNTHETIC_TEST and isolated (403)
        scan_sm, sid_sm, _, _ = _create_full_scan_dir(self.root / "snip_mock", tag="snip_mock", snippet_mock=True)

        # 2. recorded_engine_exit = 1 even with both capture flags True -> UNVERIFIED (not REAL_SCAN and not mock)
        scan_ex1, sid_ex1, _, _ = _create_full_scan_dir(
            self.root / "exit_one",
            tag="exit_one",
            recorded_engine_exit=1,
        )

        base = self._start_server((scan_sm, scan_ex1))
        code_sm, payload_sm = self._get_report(base, sid_sm)
        self.assertEqual(code_sm, 403, f"Expected 403 TEST_DATA_ISOLATED for snippet metadata mock, got {code_sm}: {payload_sm}")
        self.assertEqual(payload_sm["error_code"], "TEST_DATA_ISOLATED")

        # Nonzero engine exit must not be labeled REAL_SCAN (and not treated as mock 403)
        req_sum = Request(f"{base}/api/scans/{sid_ex1}", headers={"Authorization": f"Bearer {TEST_TOKEN}", "Connection": "close"})
        with urlopen(req_sum, timeout=15) as resp:
            sum_ex1 = json.loads(resp.read().decode("utf-8"))
        self.assertNotEqual(sum_ex1["data_origin"], "REAL_SCAN")
        self.assertEqual(sum_ex1["is_test_or_mock"], False)

    def test_conflicting_component_data_origin_cannot_be_certified_real_scan(self) -> None:
        # 1. Valid bundle provenance, but finding evidence explicitly carries an unverified/imported data_origin
        scan_ev_imp, sid_ev_imp, _, _ = _create_full_scan_dir(self.root / "ev_imp", tag="ev_imp")
        conn = sqlite3.connect(str(scan_ev_imp / "review.sqlite"))
        try:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT id, evidence FROM warnings LIMIT 1").fetchone()
            ev_obj = json.loads(row["evidence"])
            ev_obj["data_origin"] = "IMPORTED_SCAN_UNVERIFIED_CAPTURE"
            conn.execute("UPDATE warnings SET evidence=? WHERE id=?", (json.dumps(ev_obj), row["id"]))
            conn.commit()
        finally:
            conn.close()
        ev_doc = json.loads((scan_ev_imp / "evidence.json").read_text(encoding="utf-8"))
        ev_doc["records"][0]["data_origin"] = "IMPORTED_SCAN_UNVERIFIED_CAPTURE"
        (scan_ev_imp / "evidence.json").write_text(json.dumps(ev_doc), encoding="utf-8")
        # Keep assessments.jsonl aligned with updated evidence row so artifact binding stays consistent
        jsonl_lines = [json.loads(line) for line in (scan_ev_imp / "assessments.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
        jsonl_lines[0]["evidence"]["data_origin"] = "IMPORTED_SCAN_UNVERIFIED_CAPTURE"
        (scan_ev_imp / "assessments.jsonl").write_text(json.dumps(jsonl_lines[0]) + "\n", encoding="utf-8")

        # 2. Arbitrary custom non-REAL_SCAN data_origin in api-scan-meta.json alongside valid bundle provenance
        scan_meta_conf, sid_meta_conf, _, _ = _create_full_scan_dir(self.root / "meta_conf", tag="meta_conf")
        (scan_meta_conf / "api-scan-meta.json").write_text(
            json.dumps({"data_origin": "CUSTOM_UNVERIFIED_FEED"}),
            encoding="utf-8",
        )

        base = self._start_server((scan_ev_imp, scan_meta_conf))
        for label, sid in (("evidence_unverified_origin", sid_ev_imp), ("meta_custom_origin", sid_meta_conf)):
            with self.subTest(case=label):
                code, rep = self._get_report(base, sid)
                self.assertEqual(code, 200)
                self.assertNotEqual(rep["data_origin"], "REAL_SCAN")
                self.assertEqual(rep["data_origin"], "IMPORTED_SCAN_UNVERIFIED_CAPTURE")
                self.assertFalse(rep["contains_mock_or_test_data"])
                self.assertEqual(len(rep["findings"]), 1)
                self.assertNotEqual(rep["findings"][0]["data_origin"], "REAL_SCAN")
                self.assertEqual(rep["findings"][0]["data_origin"], "IMPORTED_SCAN_UNVERIFIED_CAPTURE")
                self.assertFalse(rep["findings"][0]["is_test_or_mock"])


if __name__ == "__main__":
    unittest.main()
