"""Counterexample & remediation tests for G1 manifest (`ntk-g1-run-manifest-1`) contract checks in A3."""
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


TEST_TOKEN = "remediation-a3-manifest-contract-20261117"

SAMPLE_JAVA = (
    "package demo;\n"
    "public class ManifestContractDemo {\n"
    "    public java.io.File open(javax.servlet.http.HttpServletRequest req) {\n"
    '        String f = req.getParameter("f");\n'
    '        return new java.io.File("/srv/data", f);\n'
    "    }\n"
    "}\n"
)


def _build_g1_producer_scan(
    base_dir: Path,
    *,
    tag: str,
    no_llm: bool = False,
) -> tuple[Path, Path, str, str, dict]:
    """Construct a scan directory matching `v2/g1_integration/bridge.py` output structure."""
    src_dir = base_dir / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    java_file = src_dir / "ManifestContractDemo.java"
    code = SAMPLE_JAVA + f"// {tag}\n"
    java_file.write_text(code, encoding="utf-8")
    lines = code.splitlines()
    src_txt = 'req.getParameter("f")'
    sink_txt = 'new java.io.File("/srv/data", f)'
    cs = lines[3].index(src_txt) + 1
    ck = lines[4].index(sink_txt) + 1
    src_loc = {"path": "ManifestContractDemo.java", "start": {"line": 4, "col": cs}, "end": {"line": 4, "col": cs + len(src_txt)}}
    sink_loc = {"path": "ManifestContractDemo.java", "start": {"line": 5, "col": ck}, "end": {"line": 5, "col": ck + len(sink_txt)}}
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
        "source_capture_verified": True,
        "exit_capture_verified": True,
        "recorded_engine_exit": 0,
        "source_hashes": {"ManifestContractDemo.java": sha},
    }
    bundle = evidence.collect(raw_bytes, src_dir, engine_exit=0, scan_provenance=prov)
    bundle["scan_provenance"] = prov
    bundle["pre_scan_hashes"] = {"ManifestContractDemo.java": sha}
    rec = bundle["records"][0]
    ass = {
        "status": "REFUTED",
        "raw_model_status": "REFUTED",
        "validated_status": "REFUTED",
        "validator_downgraded": False,
        "failure_kind": None,
        "explanation": "G1 producer manifest parity test",
        "fix_suggestion": "Normalize path",
        "citations": [{"path": "ManifestContractDemo.java", "start_line": 5, "end_line": 5, "quote": lines[4], "sha256": sha}],
        "citation_check": "MATCHED",
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

    if not no_llm:
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
            "enabled": not no_llm,
            "endpoint": "http://127.0.0.1:11434" if not no_llm else None,
            "requested_model": "qwen3.5:9b-q4_K_M" if not no_llm else None,
            "runtime_origin": "unverified" if not no_llm else "disabled",
        },
        "findings_summary": {
            "total_findings": 1,
            "validated_statuses": ["REFUTED"],
            "human_review_states": ["OPEN"],
        },
        "artifacts": {
            k: {"path": str(p), "sha256": evidence.digest(p.read_bytes()) if p.is_file() else None}
            for k, p in artifact_paths.items()
        },
    }
    (scan_dir / "g1-run-manifest.json").write_text(json.dumps(g1_manifest, indent=2), encoding="utf-8")
    return scan_dir, java_file, bundle["scan_sha256"], rec["id"], g1_manifest


class AuditRemediationA3ManifestTests(unittest.TestCase):
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

    def test_four_manifest_bypass_counterexamples_and_sqlite_tamper_rejected(self) -> None:
        # Counterexample 1: opengrep.sarif deleted and hash set to null
        d1, _, sid1, _, m1 = _build_g1_producer_scan(self.root / "ce1", tag="ce1")
        (d1 / "capture" / "opengrep.sarif").unlink()
        m1["artifacts"]["opengrep_sarif"]["sha256"] = None
        (d1 / "g1-run-manifest.json").write_text(json.dumps(m1, indent=2), encoding="utf-8")

        # Counterexample 2: assessments.jsonl deleted and sha256 field omitted
        d2, _, sid2, _, m2 = _build_g1_producer_scan(self.root / "ce2", tag="ce2")
        (d2 / "triage" / "assessments.jsonl").unlink()
        m2["artifacts"]["assessments_jsonl"].pop("sha256", None)
        (d2 / "g1-run-manifest.json").write_text(json.dumps(m2, indent=2), encoding="utf-8")

        # Counterexample 3: unsupported artifact key in artifacts with missing file
        d3, _, sid3, _, m3 = _build_g1_producer_scan(self.root / "ce3", tag="ce3")
        m3["artifacts"]["unsupported_custom_artifact"] = {
            "path": str(d3 / "capture" / "does-not-exist.json"),
            "sha256": "a" * 64,
        }
        (d3 / "g1-run-manifest.json").write_text(json.dumps(m3, indent=2), encoding="utf-8")

        # Counterexample 4: wrong schema version in manifest
        d4, _, sid4, _, m4 = _build_g1_producer_scan(self.root / "ce4", tag="ce4")
        m4["schema"] = "wrong-manifest-schema-v99"
        (d4 / "g1-run-manifest.json").write_text(json.dumps(m4, indent=2), encoding="utf-8")

        # Counterexample 5a: unreviewed review.sqlite tampered out-of-band (hash differs from manifest without events)
        d5a, _, sid5a, _, m5a = _build_g1_producer_scan(self.root / "ce5a", tag="ce5a")
        m5a["artifacts"]["review_sqlite"]["sha256"] = "b" * 64
        (d5a / "g1-run-manifest.json").write_text(json.dumps(m5a, indent=2), encoding="utf-8")

        # Counterexample 5b: review.sqlite state updated directly without Human Review event
        d5b, _, sid5b, fid5b, _ = _build_g1_producer_scan(self.root / "ce5b", tag="ce5b")
        with closing(sqlite3.connect(d5b / "triage" / "review.sqlite")) as conn:
            with conn:
                conn.execute("UPDATE warnings SET state='CONFIRMED_FALSE' WHERE id=?", (fid5b,))

        # Conditional case: ollama.enabled=True but http_capture_check.sha256 is null
        d_http, _, sid_http, _, m_http = _build_g1_producer_scan(self.root / "ce_http", tag="ce_http", no_llm=False)
        (d_http / "triage" / "http-capture-check.json").unlink()
        m_http["artifacts"]["http_capture_check"]["sha256"] = None
        (d_http / "g1-run-manifest.json").write_text(json.dumps(m_http, indent=2), encoding="utf-8")

        base = self._start_server((d1, d2, d3, d4, d5a, d5b, d_http))
        for label, sid in (
            ("ce1_sarif_deleted_null_hash", sid1),
            ("ce2_assessments_deleted_omitted_hash", sid2),
            ("ce3_unsupported_artifact_key", sid3),
            ("ce4_wrong_schema", sid4),
            ("ce5a_unreviewed_sqlite_hash_mismatch", sid5a),
            ("ce5b_sqlite_state_tampered_without_event", sid5b),
            ("http_capture_null_when_llm_enabled", sid_http),
        ):
            with self.subTest(case=label):
                code, payload = self._http(f"{base}/api/scans/{sid}/report")
                self.assertEqual(code, 409, f"[{label}] Expected 409 ARTIFACT_PROVENANCE_MISMATCH, got {code}: {payload}")
                self.assertEqual(payload["error_code"], "ARTIFACT_PROVENANCE_MISMATCH")

    def test_valid_manifest_with_and_without_llm_and_after_human_review(self) -> None:
        d_llm, java_llm, sid_llm, fid_llm, _ = _build_g1_producer_scan(self.root / "ok_llm", tag="ok_llm", no_llm=False)
        d_nollm, _, sid_nollm, fid_nollm, _ = _build_g1_producer_scan(self.root / "ok_nollm", tag="ok_nollm", no_llm=True)

        base = self._start_server((d_llm, d_nollm))

        # Before review: both LLM-enabled and no_llm=True manifests succeed
        code_0, rep_0 = self._http(f"{base}/api/scans/{sid_llm}/report")
        self.assertEqual(code_0, 200, rep_0)
        self.assertEqual(rep_0["data_origin"], "REAL_SCAN")

        code_no, rep_no = self._http(f"{base}/api/scans/{sid_nollm}/report")
        self.assertEqual(code_no, 200, rep_no)
        self.assertEqual(rep_no["data_origin"], "REAL_SCAN")

        # Perform Human Review actions on both scans (mutating review.sqlite legitimately)
        code_cf, _ = self._http(
            f"{base}/api/scans/{sid_llm}/findings/{fid_llm}/confirm-false",
            method="POST",
            body={"actor": "auditor", "reason": "Confirmed FP before reopen"},
        )
        self.assertEqual(code_cf, 200)
        code_re, _ = self._http(
            f"{base}/api/scans/{sid_llm}/findings/{fid_llm}/reopen",
            method="POST",
            body={"actor": "auditor", "reason": "Reopen to trigger stale source next"},
        )
        self.assertEqual(code_re, 200)

        # Also record a STALE_SOURCE rejected decision in SQLite
        java_llm.write_text(SAMPLE_JAVA + "// ok_llm modified\n", encoding="utf-8")
        code_stale, err_stale = self._http(
            f"{base}/api/scans/{sid_llm}/findings/{fid_llm}/confirm-false",
            method="POST",
            body={"actor": "auditor", "reason": "Try after source drift"},
        )
        self.assertEqual(code_stale, 409)
        self.assertEqual(err_stale["error_code"], "STALE_SOURCE")

        # After Human Review mutations (events + rejected_decisions), report MUST succeed & preserve full audit trail!
        code_1, rep_1 = self._http(f"{base}/api/scans/{sid_llm}/report")
        self.assertEqual(code_1, 200, rep_1)
        self.assertEqual(rep_1["data_origin"], "REAL_SCAN")
        self.assertEqual(rep_1["audit_trail"]["events_count"], 2)
        self.assertEqual(rep_1["audit_trail"]["rejected_decisions_count"], 1)
        self.assertEqual(rep_1["findings"][0]["human_review_state"], "OPEN")

        # Confirm-true on no_llm scan also preserves report 200
        code_ct, _ = self._http(
            f"{base}/api/scans/{sid_nollm}/findings/{fid_nollm}/confirm-true",
            method="POST",
            body={"actor": "auditor", "reason": "Confirm true on no_llm scan"},
        )
        self.assertEqual(code_ct, 200)
        code_no2, rep_no2 = self._http(f"{base}/api/scans/{sid_nollm}/report")
        self.assertEqual(code_no2, 200, rep_no2)
        self.assertEqual(rep_no2["scan_summary"]["by_human_review_state"]["CONFIRMED_TRUE"], 1)
        self.assertEqual(rep_no2["audit_trail"]["events_count"], 1)


if __name__ == "__main__":
    unittest.main()
