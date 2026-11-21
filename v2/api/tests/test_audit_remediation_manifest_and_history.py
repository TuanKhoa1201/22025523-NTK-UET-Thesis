"""Counterexample & remediation tests for empty `{}` manifest and SQLite review history tampering."""
from __future__ import annotations

from contextlib import closing
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


TEST_TOKEN = "remediation-manifest-history-token-20261117"

SAMPLE_JAVA = (
    "package demo;\n"
    "public class HistoryIntegrityDemo {\n"
    "    public java.io.File open(javax.servlet.http.HttpServletRequest req) {\n"
    '        String f = req.getParameter("f");\n'
    '        return new java.io.File("/srv/data", f);\n'
    "    }\n"
    "}\n"
)


def _build_scan(
    base_dir: Path,
    *,
    tag: str,
    validated_status: str = "REFUTED",
    with_manifest: bool = True,
    source_capture_verified: bool = True,
    exit_capture_verified: bool = True,
) -> tuple[Path, Path, str, str, dict]:
    src_dir = base_dir / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    java_file = src_dir / "HistoryIntegrityDemo.java"
    code = SAMPLE_JAVA + f"// {tag}\n"
    java_file.write_text(code, encoding="utf-8")
    lines = code.splitlines()
    src_txt = 'req.getParameter("f")'
    sink_txt = 'new java.io.File("/srv/data", f)'
    cs = lines[3].index(src_txt) + 1
    ck = lines[4].index(sink_txt) + 1
    src_loc = {"path": "HistoryIntegrityDemo.java", "start": {"line": 4, "col": cs}, "end": {"line": 4, "col": cs + len(src_txt)}}
    sink_loc = {"path": "HistoryIntegrityDemo.java", "start": {"line": 5, "col": ck}, "end": {"line": 5, "col": ck + len(sink_txt)}}
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
    sarif_bytes = json.dumps({"version": "2.1.0", "runs": [{"results": []}]}).encode("utf-8")
    scan_manifest_bytes = json.dumps({"success": True, "runs": {"version": {"exit_code": 0}, "json": {"exit_code": 0}, "sarif": {"exit_code": 0}}}).encode("utf-8")
    cli_origin_bytes = json.dumps({"mode": "local-triage"}).encode("utf-8")
    sha = evidence.digest(java_file.read_bytes())
    prov = {
        "origin": "recorded_capture_unsigned",
        "source_capture_verified": source_capture_verified,
        "exit_capture_verified": exit_capture_verified,
        "recorded_engine_exit": 0,
        "source_hashes": {"HistoryIntegrityDemo.java": sha},
    }
    bundle = evidence.collect(raw_bytes, src_dir, engine_exit=0, scan_provenance=prov)
    bundle["scan_provenance"] = prov
    bundle["pre_scan_hashes"] = {"HistoryIntegrityDemo.java": sha}
    rec = bundle["records"][0]
    ass = {
        "status": validated_status,
        "raw_model_status": validated_status,
        "validated_status": validated_status,
        "validator_downgraded": False,
        "failure_kind": None,
        "explanation": "Manifest and review history integrity test",
        "fix_suggestion": "Normalize path",
        "citations": (
            [{"path": "HistoryIntegrityDemo.java", "start_line": 5, "end_line": 5, "quote": lines[4], "sha256": sha}]
            if validated_status != "UNDETERMINED"
            else []
        ),
        "citation_check": "MATCHED" if validated_status != "UNDETERMINED" else "NONE",
        "requires_human_review": True,
        "security_conclusion_verified": False,
        "analyzed_at": evidence.now(),
        "runtime": {"origin": "unverified", "model_runtime_verified": False},
    }

    scan_dir = base_dir / "scan"
    capture_dir = scan_dir / "capture"
    triage_dir = scan_dir / "triage"
    capture_dir.mkdir(parents=True, exist_ok=True)
    triage_dir.mkdir(parents=True, exist_ok=True)

    og_json = capture_dir / "opengrep.json"
    og_sarif = capture_dir / "opengrep.sarif"
    scan_manifest = capture_dir / "scan-manifest.json"
    cli_origin = capture_dir / "cli-origin.json"
    ev_path = triage_dir / "evidence.json"
    jsonl_path = triage_dir / "assessments.jsonl"
    db_path = triage_dir / "review.sqlite"
    http_check_path = triage_dir / "http-capture-check.json"

    og_json.write_bytes(raw_bytes)
    og_sarif.write_bytes(sarif_bytes)
    scan_manifest.write_bytes(scan_manifest_bytes)
    cli_origin.write_bytes(cli_origin_bytes)
    ev_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")

    jsonl_row = {
        "schema_version": bundle["schema_version"],
        "id": rec["id"],
        "alert_id": rec["id"],
        "scan_sha256": bundle["scan_sha256"],
        "finding_index": 0,
        "state": "OPEN",
        "evidence": rec,
        "assessment": ass,
    }
    jsonl_path.write_text(json.dumps(jsonl_row) + "\n", encoding="utf-8")

    rs = store.ReviewStore(db_path)
    try:
        rs.add(bundle, [ass])
    finally:
        rs.close()

    http_check_path.write_text(
        json.dumps({"capture_status": "VERIFIED_COMPLETE", "capture_integrity_ok": True}, indent=2) + "\n",
        encoding="utf-8",
    )

    artifact_paths = {
        "opengrep_json": og_json,
        "opengrep_sarif": og_sarif,
        "scan_manifest": scan_manifest,
        "cli_origin": cli_origin,
        "evidence_json": ev_path,
        "assessments_jsonl": jsonl_path,
        "review_sqlite": db_path,
        "http_capture_check": http_check_path,
    }
    g1_manifest = {
        "schema": "ntk-g1-run-manifest-1",
        "recorded_at": evidence.now(),
        "ollama": {
            "enabled": True,
            "endpoint": "http://127.0.0.1:11434",
            "requested_model": "qwen3.5:9b-q4_K_M",
            "runtime_origin": "unverified",
        },
        "findings_summary": {
            "total_findings": 1,
            "validated_statuses": [validated_status],
            "human_review_states": ["OPEN"],
        },
        "artifacts": {
            k: {"path": str(p), "sha256": evidence.digest(p.read_bytes())}
            for k, p in artifact_paths.items()
        },
    }
    if with_manifest:
        (scan_dir / "g1-run-manifest.json").write_text(json.dumps(g1_manifest, indent=2), encoding="utf-8")
    return scan_dir, java_file, bundle["scan_sha256"], rec["id"], g1_manifest


class AuditRemediationManifestAndHistoryTests(unittest.TestCase):
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

    def _http(self, url: str, *, method: str = "GET", body: dict | None = None) -> tuple[int, dict]:
        headers = {"Authorization": f"Bearer {TEST_TOKEN}", "Connection": "close"}
        raw = None
        if body is not None:
            raw = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = Request(url, data=raw, headers=headers, method=method)
        try:
            with urlopen(req, timeout=15) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_1_empty_object_manifest_with_missing_sarif_rejected_409_and_no_manifest_import_preserved(self) -> None:
        # 1a. Present manifest `{}` + missing capture/opengrep.sarif -> MUST return 409, never 200 REAL_SCAN
        d_empty, _, sid_empty, _, _ = _build_scan(self.root / "empty_manifest", tag="empty_manifest")
        (d_empty / "g1-run-manifest.json").write_text("{}", encoding="utf-8")
        (d_empty / "capture" / "opengrep.sarif").unlink()

        # 1b. No manifest file + unverified capture -> stays IMPORTED_SCAN_UNVERIFIED_CAPTURE
        d_imp, _, sid_imp, _, _ = _build_scan(
            self.root / "imported_no_manifest",
            tag="imported_no_manifest",
            with_manifest=False,
            source_capture_verified=False,
            exit_capture_verified=False,
        )

        base = self._start_server((d_empty, d_imp))

        code_empty, p_empty = self._http(f"{base}/api/scans/{sid_empty}/report")
        self.assertEqual(code_empty, 409, f"Empty {{}} manifest must return 409, got {code_empty}: {p_empty}")
        self.assertEqual(p_empty["error_code"], "ARTIFACT_PROVENANCE_MISMATCH")

        code_imp, p_imp = self._http(f"{base}/api/scans/{sid_imp}/report")
        self.assertEqual(code_imp, 200, p_imp)
        self.assertEqual(p_imp["data_origin"], "IMPORTED_SCAN_UNVERIFIED_CAPTURE")

    def test_2_3_4_forged_and_tampered_sqlite_events_and_rejected_decisions_rejected(self) -> None:
        # Case 2: Forged confirm-false event with empty actor/reason, invalid timestamp, empty snapshots, fake hash
        d_fake_ev, _, sid_fake_ev, fid_fake_ev, _ = _build_scan(self.root / "fake_ev", tag="fake_ev")
        with closing(sqlite3.connect(d_fake_ev / "triage" / "review.sqlite")) as conn:
            with conn:
                conn.execute(
                    "INSERT INTO events(warning_id,actor,timestamp,action,reason,source_version,observed_version,evidence_sha256) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (fid_fake_ev, "", "not-a-timestamp", "confirm-false", "", "{}", "{}", "0" * 64),
                )
                conn.execute("UPDATE warnings SET state='CONFIRMED_FALSE' WHERE id=?", (fid_fake_ev,))

        # Case 3a: Valid Human Review event created via API, then evidence_sha256 tampered
        d_tamper_sha, _, sid_tamper_sha, fid_tamper_sha, _ = _build_scan(self.root / "tamper_sha", tag="tamper_sha")
        # Case 3b: Valid Human Review event created via API, then actor/reason/observed_version metadata tampered
        d_tamper_meta, _, sid_tamper_meta, fid_tamper_meta, _ = _build_scan(self.root / "tamper_meta", tag="tamper_meta")

        # Case 4a: Fake rejected_decisions row with invalid action/code + tampered baseline hash
        d_fake_rej, _, sid_fake_rej, fid_fake_rej, m_fake_rej = _build_scan(self.root / "fake_rej", tag="fake_rej")
        m_fake_rej["artifacts"]["review_sqlite"]["sha256"] = "e" * 64
        (d_fake_rej / "g1-run-manifest.json").write_text(json.dumps(m_fake_rej, indent=2), encoding="utf-8")
        with closing(sqlite3.connect(d_fake_rej / "triage" / "review.sqlite")) as conn:
            with conn:
                conn.execute(
                    "INSERT INTO rejected_decisions(warning_id,actor,timestamp,attempted_action,reason,rejection_code,source_version,observed_version,detail) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (fid_fake_rej, "attacker", evidence.now(), "confirm-true", "forged rejection", "CUSTOM_FAKE", "{}", "{}", "{}"),
                )

        # Case 4b: Fake rejected_decisions row claiming STALE_SOURCE even though observed_version matches expected snapshots!
        d_fake_stale, _, sid_fake_stale, fid_fake_stale, _ = _build_scan(self.root / "fake_stale", tag="fake_stale")
        with closing(sqlite3.connect(d_fake_stale / "triage" / "review.sqlite")) as conn:
            ev_json = json.loads(conn.execute("SELECT evidence FROM warnings WHERE id=?", (fid_fake_stale,)).fetchone()[0])
            snaps = ev_json["snapshots"]
            exp_hashes = {p: v["sha256"] for p, v in snaps.items()}
            with conn:
                conn.execute(
                    "INSERT INTO rejected_decisions(warning_id,actor,timestamp,attempted_action,reason,rejection_code,source_version,observed_version,detail) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        fid_fake_stale,
                        "attacker",
                        evidence.now(),
                        "confirm-false",
                        "forged stale",
                        "STALE_SOURCE",
                        json.dumps(snaps, sort_keys=True),
                        json.dumps(exp_hashes, sort_keys=True),
                        json.dumps({"error_code": "STALE_SOURCE", "mismatched_paths": ["HistoryIntegrityDemo.java"], "expected_hashes": exp_hashes, "observed_hashes": exp_hashes}),
                    ),
                )

        base = self._start_server((d_fake_ev, d_tamper_sha, d_tamper_meta, d_fake_rej, d_fake_stale))

        # Seed genuine Human Review events via HTTP API before tampering them
        for sid, fid in ((sid_tamper_sha, fid_tamper_sha), (sid_tamper_meta, fid_tamper_meta)):
            code_ok, _ = self._http(
                f"{base}/api/scans/{sid}/findings/{fid}/confirm-true",
                method="POST",
                body={"actor": "legit-reviewer", "reason": "Genuine review before tampering"},
            )
            self.assertEqual(code_ok, 200)

        with closing(sqlite3.connect(d_tamper_sha / "triage" / "review.sqlite")) as conn:
            with conn:
                conn.execute("UPDATE events SET evidence_sha256=? WHERE warning_id=?", ("f" * 64, fid_tamper_sha))

        with closing(sqlite3.connect(d_tamper_meta / "triage" / "review.sqlite")) as conn:
            with conn:
                conn.execute("UPDATE events SET actor=' ', reason='', timestamp='bad-ts' WHERE warning_id=?", (fid_tamper_meta,))

        for label, sid in (
            ("fake_confirm_false_event", sid_fake_ev),
            ("tampered_valid_event_evidence_sha", sid_tamper_sha),
            ("tampered_valid_event_metadata", sid_tamper_meta),
            ("fake_rejected_decision_bypassing_baseline", sid_fake_rej),
            ("fake_rejected_decision_non_mismatched_hashes", sid_fake_stale),
        ):
            with self.subTest(case=label):
                code, payload = self._http(f"{base}/api/scans/{sid}/report")
                self.assertEqual(code, 409, f"[{label}] Expected 409 ARTIFACT_PROVENANCE_MISMATCH, got {code}: {payload}")
                self.assertEqual(payload["error_code"], "ARTIFACT_PROVENANCE_MISMATCH")

    def test_5_6_valid_reports_before_after_review_post_review_drift_and_open_defaults(self) -> None:
        # Scenario 5: Valid review lifecycle (confirm-false when source intact -> source modified later -> report still 200;
        # then reopen -> confirm-false triggers 409 STALE_SOURCE rejected_decisions -> report still 200!)
        d_ok, java_ok, sid_ok, fid_ok, _ = _build_scan(self.root / "valid_lifecycle", tag="valid_lifecycle", validated_status="REFUTED")
        # Scenario 6: REFUTED and UNDETERMINED stay OPEN until human reviewer decides
        d_undet, _, sid_undet, _, _ = _build_scan(self.root / "open_undet", tag="open_undet", validated_status="UNDETERMINED")

        base = self._start_server((d_ok, d_undet))

        # Before Human Review: both REFUTED and UNDETERMINED stay OPEN and reports return 200 REAL_SCAN
        for sid, expected_status in ((sid_ok, "REFUTED"), (sid_undet, "UNDETERMINED")):
            code_r, rep = self._http(f"{base}/api/scans/{sid}/report")
            self.assertEqual(code_r, 200, rep)
            self.assertEqual(rep["data_origin"], "REAL_SCAN")
            self.assertEqual(rep["findings"][0]["validated_status"], expected_status)
            self.assertEqual(rep["findings"][0]["human_review_state"], "OPEN")
            self.assertEqual(rep["scan_summary"]["by_human_review_state"]["OPEN"], 1)

        # Valid confirm-false while source is intact
        code_cf, d_cf = self._http(
            f"{base}/api/scans/{sid_ok}/findings/{fid_ok}/confirm-false",
            method="POST",
            body={"actor": "auditor", "reason": "Confirmed FP before later source edit"},
        )
        self.assertEqual(code_cf, 200, d_cf)
        self.assertEqual(d_cf["human_review_state"], "CONFIRMED_FALSE")

        # Edit Java source AFTER valid confirm-false review: old valid confirm-false report MUST STILL succeed (200)!
        java_ok.write_text(SAMPLE_JAVA + "// modified legitimately after review\n", encoding="utf-8")
        code_r_after_edit, rep_after_edit = self._http(f"{base}/api/scans/{sid_ok}/report")
        self.assertEqual(code_r_after_edit, 200, rep_after_edit)
        self.assertEqual(rep_after_edit["findings"][0]["human_review_state"], "CONFIRMED_FALSE")

        # Reopen -> attempt confirm-false -> 409 STALE_SOURCE creates genuine rejected_decisions row -> report STILL 200!
        code_re, _ = self._http(
            f"{base}/api/scans/{sid_ok}/findings/{fid_ok}/reopen",
            method="POST",
            body={"actor": "auditor", "reason": "Reopen for re-check"},
        )
        self.assertEqual(code_re, 200)
        code_stale, stale_err = self._http(
            f"{base}/api/scans/{sid_ok}/findings/{fid_ok}/confirm-false",
            method="POST",
            body={"actor": "auditor", "reason": "Should be rejected by STALE_SOURCE"},
        )
        self.assertEqual(code_stale, 409)
        self.assertEqual(stale_err["error_code"], "STALE_SOURCE")

        code_r_final, rep_final = self._http(f"{base}/api/scans/{sid_ok}/report")
        self.assertEqual(code_r_final, 200, rep_final)
        self.assertEqual(rep_final["data_origin"], "REAL_SCAN")
        self.assertEqual(rep_final["audit_trail"]["events_count"], 2)
        self.assertEqual(rep_final["audit_trail"]["rejected_decisions_count"], 1)
        self.assertEqual(rep_final["findings"][0]["human_review_state"], "OPEN")


if __name__ == "__main__":
    unittest.main()
