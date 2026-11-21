"""Counterexample & remediation tests for remaining A3 artifact, assessment, runtime, and G1 manifest inconsistencies."""
from __future__ import annotations

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


TEST_TOKEN = "remediation-a3-complete-token-20261117"

SAMPLE_JAVA = (
    "package demo;\n"
    "public class CompleteA3Demo {\n"
    "    public java.io.File open(javax.servlet.http.HttpServletRequest req) {\n"
    '        String f = req.getParameter("f");\n'
    '        return new java.io.File("/srv/data", f);\n'
    "    }\n"
    "}\n"
)


def _build_g1_style_scan(
    base_dir: Path,
    *,
    tag: str,
    with_manifest: bool = True,
    manifest_ollama_origin: str = "unverified",
    no_llm: bool = False,
) -> tuple[Path, str, str, dict, dict]:
    src_dir = base_dir / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    java_file = src_dir / "CompleteA3Demo.java"
    code = SAMPLE_JAVA + f"// {tag}\n"
    java_file.write_text(code, encoding="utf-8")
    lines = code.splitlines()
    src_txt = 'req.getParameter("f")'
    sink_txt = 'new java.io.File("/srv/data", f)'
    cs = lines[3].index(src_txt) + 1
    ck = lines[4].index(sink_txt) + 1
    src_loc = {"path": "CompleteA3Demo.java", "start": {"line": 4, "col": cs}, "end": {"line": 4, "col": cs + len(src_txt)}}
    sink_loc = {"path": "CompleteA3Demo.java", "start": {"line": 5, "col": ck}, "end": {"line": 5, "col": ck + len(sink_txt)}}
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
    manifest_bytes = json.dumps({"success": True, "runs": {}}).encode("utf-8")
    cli_origin_bytes = json.dumps({"mode": "local-triage"}).encode("utf-8")
    sha = evidence.digest(java_file.read_bytes())
    prov = {
        "origin": "recorded_capture_unsigned",
        "source_capture_verified": True,
        "exit_capture_verified": True,
        "recorded_engine_exit": 0,
        "source_hashes": {"CompleteA3Demo.java": sha},
    }
    bundle = evidence.collect(raw_bytes, src_dir, engine_exit=0, scan_provenance=prov)
    bundle["scan_provenance"] = prov
    bundle["pre_scan_hashes"] = {"CompleteA3Demo.java": sha}
    rec = bundle["records"][0]
    ass = {
        "status": "REFUTED",
        "raw_model_status": "REFUTED",
        "validated_status": "REFUTED",
        "validator_downgraded": False,
        "failure_kind": None,
        "explanation": "Complete A3 verification",
        "fix_suggestion": "Normalize path",
        "citations": [{"path": "CompleteA3Demo.java", "start_line": 5, "end_line": 5, "quote": lines[4], "sha256": sha}],
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

    og_json.write_bytes(raw_bytes)
    og_sarif.write_bytes(sarif_bytes)
    scan_manifest.write_bytes(manifest_bytes)
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

    g1_manifest = {
        "schema": "ntk-g1-run-manifest-1",
        "ollama": {
            "enabled": not no_llm,
            "endpoint": "http://127.0.0.1:11434" if not no_llm else None,
            "requested_model": "qwen3.5:9b-q4_K_M" if not no_llm else None,
            "runtime_origin": manifest_ollama_origin if not no_llm else "disabled",
        },
        "findings_summary": {
            "total_findings": 1,
            "validated_statuses": ["REFUTED"],
            "human_review_states": ["OPEN"],
        },
        "artifacts": {
            "opengrep_json": {"path": str(og_json), "sha256": evidence.digest(og_json.read_bytes())},
            "opengrep_sarif": {"path": str(og_sarif), "sha256": evidence.digest(og_sarif.read_bytes())},
            "scan_manifest": {"path": str(scan_manifest), "sha256": evidence.digest(scan_manifest.read_bytes())},
            "cli_origin": {"path": str(cli_origin), "sha256": evidence.digest(cli_origin.read_bytes())},
            "evidence_json": {"path": str(ev_path), "sha256": evidence.digest(ev_path.read_bytes())},
            "assessments_jsonl": {"path": str(jsonl_path), "sha256": evidence.digest(jsonl_path.read_bytes())},
            "review_sqlite": {"path": str(db_path), "sha256": evidence.digest(db_path.read_bytes())},
            "http_capture_check": {"path": str(triage_dir / "http-capture-check.json"), "sha256": None},
        },
    }
    if with_manifest:
        (scan_dir / "g1-run-manifest.json").write_text(json.dumps(g1_manifest, indent=2), encoding="utf-8")

    return scan_dir, bundle["scan_sha256"], rec["id"], jsonl_row, g1_manifest


def _refresh_manifest_hashes(scan_dir: Path, g1_manifest: dict) -> None:
    triage_dir = scan_dir / "triage"
    capture_dir = scan_dir / "capture"
    mapping = {
        "opengrep_json": capture_dir / "opengrep.json",
        "opengrep_sarif": capture_dir / "opengrep.sarif",
        "scan_manifest": capture_dir / "scan-manifest.json",
        "cli_origin": capture_dir / "cli-origin.json",
        "evidence_json": triage_dir / "evidence.json",
        "assessments_jsonl": triage_dir / "assessments.jsonl",
        "review_sqlite": triage_dir / "review.sqlite",
    }
    for k, p in mapping.items():
        if p.is_file():
            g1_manifest["artifacts"][k]["sha256"] = evidence.digest(p.read_bytes())
    (scan_dir / "g1-run-manifest.json").write_text(json.dumps(g1_manifest, indent=2), encoding="utf-8")


class AuditRemediationA3CompleteTests(unittest.TestCase):
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

    def test_case1_contradictory_assessment_status_in_jsonl_rejected(self) -> None:
        sdir, sid, _, row, g1 = _build_g1_style_scan(self.root / "c1", tag="c1")
        # SQLite has status=REFUTED & validated_status=REFUTED; JSONL keeps validated_status=REFUTED but status=SUPPORTED
        row["assessment"]["status"] = "SUPPORTED"
        (sdir / "triage" / "assessments.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
        _refresh_manifest_hashes(sdir, g1)

        base = self._start_server((sdir,))
        code, payload = self._http(f"{base}/api/scans/{sid}/report")
        self.assertEqual(code, 409, f"Expected 409 ARTIFACT_PROVENANCE_MISMATCH, got {code}: {payload}")
        self.assertEqual(payload["error_code"], "ARTIFACT_PROVENANCE_MISMATCH")

    def test_case2_contradictory_runtime_verification_in_jsonl_rejected(self) -> None:
        sdir, sid, _, row, g1 = _build_g1_style_scan(self.root / "c2", tag="c2")
        # SQLite has model_runtime_verified=False; JSONL claims model_runtime_verified=True
        row["assessment"]["runtime"]["model_runtime_verified"] = True
        (sdir / "triage" / "assessments.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
        _refresh_manifest_hashes(sdir, g1)

        base = self._start_server((sdir,))
        code, payload = self._http(f"{base}/api/scans/{sid}/report")
        self.assertEqual(code, 409, f"Expected 409 ARTIFACT_PROVENANCE_MISMATCH, got {code}: {payload}")
        self.assertEqual(payload["error_code"], "ARTIFACT_PROVENANCE_MISMATCH")

    def test_case3_evidence_rule_id_and_records_mismatch_rejected(self) -> None:
        # 3a. SQLite warnings.evidence.rule_id differs from original raw opengrep.json & evidence.json
        sdir_rule, sid_rule, fid_rule, _, g1_rule = _build_g1_style_scan(self.root / "c3a", tag="c3a")
        from contextlib import closing
        import sqlite3
        with closing(sqlite3.connect(sdir_rule / "triage" / "review.sqlite")) as conn:
            with conn:
                ev_json = json.loads(conn.execute("SELECT evidence FROM warnings WHERE id=?", (fid_rule,)).fetchone()[0])
                ev_json["rule_id"] = "tampered.rule.id"
                conn.execute("UPDATE warnings SET evidence=? WHERE id=?", (json.dumps(ev_json), fid_rule))
        _refresh_manifest_hashes(sdir_rule, g1_rule)

        # 3b. evidence.json has records=[] while SQLite has 1 finding
        sdir_rec, sid_rec, _, _, g1_rec = _build_g1_style_scan(self.root / "c3b", tag="c3b")
        ev_doc = json.loads((sdir_rec / "triage" / "evidence.json").read_text(encoding="utf-8"))
        ev_doc["records"] = []
        (sdir_rec / "triage" / "evidence.json").write_text(json.dumps(ev_doc), encoding="utf-8")
        _refresh_manifest_hashes(sdir_rec, g1_rec)

        base = self._start_server((sdir_rule, sdir_rec))
        for label, sid in (("rule_id_mismatch", sid_rule), ("empty_evidence_records", sid_rec)):
            with self.subTest(case=label):
                code, payload = self._http(f"{base}/api/scans/{sid}/report")
                self.assertEqual(code, 409, f"[{label}] Expected 409, got {code}: {payload}")
                self.assertEqual(payload["error_code"], "ARTIFACT_PROVENANCE_MISMATCH")

    def test_case4_5_6_g1_manifest_schema_hash_mock_and_missing_artifact(self) -> None:
        # 4. Wrong artifacts.opengrep_json.sha256
        sdir_hash, sid_hash, _, _, g1_hash = _build_g1_style_scan(self.root / "c4", tag="c4")
        g1_hash["artifacts"]["opengrep_json"]["sha256"] = "f" * 64
        (sdir_hash / "g1-run-manifest.json").write_text(json.dumps(g1_hash), encoding="utf-8")

        # 5. g1-run-manifest.json ollama.runtime_origin == "mock"
        sdir_mock, sid_mock, _, _, _ = _build_g1_style_scan(
            self.root / "c5",
            tag="c5",
            manifest_ollama_origin="mock",
        )

        # 6. g1-run-manifest.json declares assessments_jsonl.sha256, but assessments.jsonl deleted!
        sdir_miss, sid_miss, _, _, _ = _build_g1_style_scan(self.root / "c6", tag="c6")
        (sdir_miss / "triage" / "assessments.jsonl").unlink()

        base = self._start_server((sdir_hash, sdir_mock, sdir_miss))

        code_h, p_h = self._http(f"{base}/api/scans/{sid_hash}/report")
        self.assertEqual(code_h, 409, f"Expected 409 for bad manifest artifact hash, got {code_h}: {p_h}")
        self.assertEqual(p_h["error_code"], "ARTIFACT_PROVENANCE_MISMATCH")

        code_m, p_m = self._http(f"{base}/api/scans/{sid_mock}/report")
        self.assertEqual(code_m, 403, f"Expected 403 TEST_DATA_ISOLATED for ollama.runtime_origin=mock, got {code_m}: {p_m}")
        self.assertEqual(p_m["error_code"], "TEST_DATA_ISOLATED")

        code_x, p_x = self._http(f"{base}/api/scans/{sid_miss}/report")
        self.assertEqual(code_x, 409, f"Expected 409 when manifest-declared assessments_jsonl is missing, got {code_x}: {p_x}")
        self.assertEqual(p_x["error_code"], "ARTIFACT_PROVENANCE_MISMATCH")

    def test_case7_8_9_valid_report_and_human_review_does_not_break_immutable_artifact_check(self) -> None:
        # 7. Corrupt JSONL still blocked
        sdir_bad, sid_bad, _, _, g1_bad = _build_g1_style_scan(self.root / "c7", tag="c7")
        (sdir_bad / "triage" / "assessments.jsonl").write_text('{"assessment":[1],"evidence":{}}\n', encoding="utf-8")
        _refresh_manifest_hashes(sdir_bad, g1_bad)

        # 8 & 9. Valid G1 scan (including optional http_capture_check sha256=None when no_llm=True)
        # Perform Human Review mutations on review.sqlite AFTER g1-run-manifest.json was written,
        # so review.sqlite bytes & hash legitimately change while immutable scan artifacts stay intact!
        sdir_ok, sid_ok, fid_ok, _, _ = _build_g1_style_scan(self.root / "c89", tag="c89", no_llm=True)

        base = self._start_server((sdir_bad, sdir_ok))

        code_bad, p_bad = self._http(f"{base}/api/scans/{sid_bad}/report")
        self.assertEqual(code_bad, 409)
        self.assertEqual(p_bad["error_code"], "ARTIFACT_PROVENANCE_MISMATCH")

        # Initial valid report before review
        code_r0, rep0 = self._http(f"{base}/api/scans/{sid_ok}/report")
        self.assertEqual(code_r0, 200, rep0)
        self.assertEqual(rep0["data_origin"], "REAL_SCAN")
        self.assertEqual(rep0["scan_summary"]["by_human_review_state"]["OPEN"], 1)

        # Mutate review.sqlite legitimately via Human Review
        code_rev, d_rev = self._http(
            f"{base}/api/scans/{sid_ok}/findings/{fid_ok}/confirm-true",
            method="POST",
            body={"actor": "reviewer-a3", "reason": "Confirmed true after scan"},
        )
        self.assertEqual(code_rev, 200, d_rev)
        self.assertEqual(d_rev["human_review_state"], "CONFIRMED_TRUE")

        # Report MUST STILL SUCCEED after Human Review changed review.sqlite!
        code_r1, rep1 = self._http(f"{base}/api/scans/{sid_ok}/report")
        self.assertEqual(code_r1, 200, rep1)
        self.assertEqual(rep1["data_origin"], "REAL_SCAN")
        self.assertEqual(rep1["scan_summary"]["by_human_review_state"]["CONFIRMED_TRUE"], 1)
        self.assertEqual(rep1["audit_trail"]["events_count"], 1)
        self.assertEqual(rep1["findings"][0]["human_review_state"], "CONFIRMED_TRUE")


if __name__ == "__main__":
    unittest.main()
