"""Unit and negative regression tests for v2/evaluation/verify_evidence_audit.py.

All negative tests operate exclusively on temporary copies in tempfile.TemporaryDirectory()
and never mutate locked REPLAY fixtures or original LIVE server evidence.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest

import sys

EVAL_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = EVAL_DIR.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(EVAL_DIR) not in sys.path:
    sys.path.insert(0, str(EVAL_DIR))

import verify_evidence_audit as vea
from v2.triage.store import ReviewStore


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class VerifyEvidenceAuditRegressionTests(unittest.TestCase):
    """Comprehensive regression test suite covering all 15+ audit failure and pass modes."""

    def setUp(self) -> None:
        self.tmp_ctx = tempfile.TemporaryDirectory(prefix="ntk_test_vea_")
        self.tmp_dir = Path(self.tmp_ctx.name)

        self.orig_scan_sha = _sha256_file(vea.DEFAULT_HISTORICAL_SCAN)
        self.orig_ass_sha = _sha256_file(vea.DEFAULT_HISTORICAL_ASSESSMENTS)
        self.orig_src_sha = _sha256_file(vea.DEFAULT_SOURCE_ROOT / "SmokeVulnSample.java")

        # Create clean working copies inside self.tmp_dir
        self.scan_copy = self.tmp_dir / "opengrep.json"
        self.ass_copy = self.tmp_dir / "assessments.jsonl"
        self.src_dir = self.tmp_dir / "smoke_evidence"
        self.src_dir.mkdir(parents=True, exist_ok=True)
        self.java_copy = self.src_dir / "SmokeVulnSample.java"
        self.labels_copy = self.tmp_dir / "labels.json"

        shutil.copy2(vea.DEFAULT_HISTORICAL_SCAN, self.scan_copy)
        shutil.copy2(vea.DEFAULT_HISTORICAL_ASSESSMENTS, self.ass_copy)
        shutil.copy2(vea.DEFAULT_SOURCE_ROOT / "SmokeVulnSample.java", self.java_copy)
        shutil.copy2(vea.DEFAULT_HISTORICAL_LABELS, self.labels_copy)

    def tearDown(self) -> None:
        self.tmp_ctx.cleanup()
        # Verify original repository fixtures were never mutated
        self.assertEqual(_sha256_file(vea.DEFAULT_HISTORICAL_SCAN), self.orig_scan_sha)
        self.assertEqual(_sha256_file(vea.DEFAULT_HISTORICAL_ASSESSMENTS), self.orig_ass_sha)
        self.assertEqual(_sha256_file(vea.DEFAULT_SOURCE_ROOT / "SmokeVulnSample.java"), self.orig_src_sha)

    def _load_assessments(self) -> list[dict]:
        lines = [
            line.strip()
            for line in self.ass_copy.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        return [json.loads(line) for line in lines]

    def _write_assessments(self, records: list[dict]) -> None:
        text = "\n".join(json.dumps(r, ensure_ascii=False) for r in records) + "\n"
        self.ass_copy.write_text(text, encoding="utf-8")

    def _build_sqlite_from_copies(self, db_path: Path) -> None:
        records = self._load_assessments()
        scan_sha = (
            records[0].get("scan_sha256")
            or (records[0].get("evidence") or {}).get("scan_sha256")
            or _sha256_file(self.scan_copy)
        )
        bundle_records = []
        assessments_only = []
        for idx, r in enumerate(records):
            ev = copy.deepcopy(r.get("evidence") or {})
            ev["id"] = r["id"]
            ev["finding_index"] = idx
            ev["scan_sha256"] = scan_sha
            ev["root"] = str(self.src_dir)
            ev["issues"] = ev.get("issues", [])
            ev["scan_provenance"] = {
                "origin": "recorded_capture_unsigned",
                "source_capture_verified": True,
                "exit_capture_verified": True,
            }
            bundle_records.append(ev)
            assessments_only.append(copy.deepcopy(r.get("assessment") or {}))
        bundle = {
            "schema_version": "1.1",
            "scan_sha256": scan_sha,
            "root": str(self.src_dir),
            "records": bundle_records,
            "issues": [],
        }
        store = ReviewStore(db_path)
        try:
            store.add(bundle, assessments_only)
        finally:
            store.close()

    # ------------------------------------------------------------------
    # Positive Baseline Tests
    # ------------------------------------------------------------------

    def test_01_replay_mode_cli_passes_exit_0(self) -> None:
        out_json = self.tmp_dir / "replay_out.json"
        code = vea.main(["--mode", "replay", "--output-json", str(out_json)])
        self.assertEqual(code, 0)
        doc = json.loads(out_json.read_text(encoding="utf-8"))
        self.assertEqual(doc["audit_verdict"], "PASS")
        self.assertEqual(doc["total_findings"], 3)
        self.assertEqual(len(doc["issues"]), 0)
        self.assertEqual(doc["paired_comparison"]["labeled_tp"], 2)
        self.assertEqual(doc["paired_comparison"]["labeled_fp"], 1)

    def test_02_custom_mode_passes_on_valid_copies(self) -> None:
        code = vea.main([
            "--mode", "custom",
            "--opengrep", str(self.scan_copy),
            "--assessments", str(self.ass_copy),
            "--source-root", str(self.src_dir),
            "--labels", str(self.labels_copy),
        ])
        self.assertEqual(code, 0)

    # ------------------------------------------------------------------
    # Negative Regression Tests (15 Required Scenarios)
    # ------------------------------------------------------------------

    def test_03_missing_live_evidence_returns_awaiting_server_exit_2(self) -> None:
        missing_live = self.tmp_dir / "nonexistent_server_live_dir"
        out_json = self.tmp_dir / "awaiting.json"
        code = vea.main([
            "--mode", "live",
            "--live-dir", str(missing_live),
            "--output-json", str(out_json),
        ])
        self.assertEqual(code, 2)
        doc = json.loads(out_json.read_text(encoding="utf-8"))
        self.assertEqual(doc["audit_verdict"], "AWAITING_SERVER_EVIDENCE")

    def test_04_missing_required_files_rejected(self) -> None:
        # Missing opengrep scan
        res1 = vea.audit_scan_and_evidence(
            opengrep_path=self.tmp_dir / "missing_scan.json",
            assessments_path=self.ass_copy,
            source_root=self.src_dir,
        )
        self.assertEqual(res1["audit_verdict"], "FAIL")

        # Missing assessments.jsonl
        res2 = vea.audit_scan_and_evidence(
            opengrep_path=self.scan_copy,
            assessments_path=self.tmp_dir / "missing_assessments.jsonl",
            source_root=self.src_dir,
        )
        self.assertEqual(res2["audit_verdict"], "FAIL")

        # Missing required scan-manifest.json
        res3 = vea.audit_scan_and_evidence(
            opengrep_path=self.scan_copy,
            assessments_path=self.ass_copy,
            source_root=self.src_dir,
            scan_manifest_path=self.tmp_dir / "missing_manifest.json",
            require_scan_manifest=True,
        )
        self.assertEqual(res3["audit_verdict"], "FAIL")
        self.assertTrue(any("Missing required scan-manifest.json" in i for i in res3["issues"]))

        # Missing custom mode required args returns exit 2
        self.assertEqual(vea.main(["--mode", "custom"]), 2)

    def test_05_wrong_sha256_and_manifest_mismatch_rejected(self) -> None:
        # Wrong expected_scan_sha
        res = vea.audit_scan_and_evidence(
            opengrep_path=self.scan_copy,
            assessments_path=self.ass_copy,
            source_root=self.src_dir,
            expected_scan_sha="f" * 64,
        )
        self.assertEqual(res["audit_verdict"], "FAIL")
        self.assertTrue(any("Scan SHA-256 mismatch" in i for i in res["issues"]))

        # Manifest with mismatched opengrep.json hash and unverified flags
        bad_manifest = self.tmp_dir / "scan-manifest.json"
        bad_manifest.write_text(
            json.dumps({
                "schema": "ntk-scan-capture-1",
                "source_capture_verified": False,
                "exit_capture_verified": False,
                "artifacts": {"opengrep.json": "a" * 64},
            }),
            encoding="utf-8",
        )
        res_m = vea.audit_scan_and_evidence(
            opengrep_path=self.scan_copy,
            assessments_path=self.ass_copy,
            source_root=self.src_dir,
            scan_manifest_path=bad_manifest,
            require_scan_manifest=True,
        )
        self.assertEqual(res_m["audit_verdict"], "FAIL")
        self.assertTrue(any("Manifest recorded json sha256" in i for i in res_m["issues"]))
        self.assertTrue(any("Manifest source_capture_verified is not True" in i for i in res_m["issues"]))

    def test_06_mutated_raw_opengrep_json_rejected(self) -> None:
        # Append whitespace/comment or alter raw OpenGrep JSON bytes after triage
        raw_doc = json.loads(self.scan_copy.read_text(encoding="utf-8"))
        raw_doc["results"][0]["extra"]["message"] = "TAMPERED MESSAGE"
        self.scan_copy.write_text(json.dumps(raw_doc, indent=2), encoding="utf-8")

        res = vea.audit_scan_and_evidence(
            opengrep_path=self.scan_copy,
            assessments_path=self.ass_copy,
            source_root=self.src_dir,
        )
        self.assertEqual(res["audit_verdict"], "FAIL")
        self.assertTrue(
            any("alert_id mismatch" in i or "scan_sha256" in i for i in res["issues"])
        )

    def test_07_mutated_java_source_rejected(self) -> None:
        self.java_copy.write_text(
            self.java_copy.read_text(encoding="utf-8") + "\n// source drift\n",
            encoding="utf-8",
        )
        res = vea.audit_scan_and_evidence(
            opengrep_path=self.scan_copy,
            assessments_path=self.ass_copy,
            source_root=self.src_dir,
        )
        self.assertEqual(res["audit_verdict"], "FAIL")
        self.assertTrue(any("Source file SHA-256 drift" in i for i in res["issues"]))

    def test_08_wrong_finding_id_or_rule_id_or_location_rejected(self) -> None:
        records = self._load_assessments()
        records[0]["id"] = "0" * 64
        records[0]["alert_id"] = "0" * 64
        records[1]["evidence"]["rule_id"] = "v2.baseline.rules.ntk.java.wrong_rule"
        records[2]["evidence"]["start"]["line"] = 99
        self._write_assessments(records)

        res = vea.audit_scan_and_evidence(
            opengrep_path=self.scan_copy,
            assessments_path=self.ass_copy,
            source_root=self.src_dir,
        )
        self.assertEqual(res["audit_verdict"], "FAIL")
        self.assertTrue(any("alert_id mismatch" in i for i in res["issues"]))
        self.assertTrue(any("rule_id mismatch" in i for i in res["issues"]))
        self.assertTrue(any("start_line mismatch" in i for i in res["issues"]))

    def test_09_missing_dataflow_trace_rejected(self) -> None:
        records = self._load_assessments()
        records[0]["evidence"]["raw_trace"] = None
        records[0]["evidence"].pop("dataflow_trace", None)
        if "raw_finding" in records[0]["evidence"] and "extra" in records[0]["evidence"]["raw_finding"]:
            records[0]["evidence"]["raw_finding"]["extra"].pop("dataflow_trace", None)
        self._write_assessments(records)

        res = vea.audit_scan_and_evidence(
            opengrep_path=self.scan_copy,
            assessments_path=self.ass_copy,
            source_root=self.src_dir,
            require_trace=True,
        )
        self.assertEqual(res["audit_verdict"], "FAIL")
        self.assertTrue(any("missing or incomplete dataflow_trace" in i for i in res["issues"]))

    def test_10_nonexistent_or_blank_or_comment_citation_rejected(self) -> None:
        records = self._load_assessments()
        # Finding 0: nonexistent line 999
        records[0]["assessment"]["citations"] = [
            {"path": "SmokeVulnSample.java", "start_line": 999, "end_line": 999, "quote": "fake"}
        ]
        # Finding 1: comment line 15 (" * Isolated Java smoke-test fixture...")
        records[1]["assessment"]["citations"] = [
            {"path": "SmokeVulnSample.java", "start_line": 15, "end_line": 15, "quote": "* Isolated Java smoke-test fixture"}
        ]
        self._write_assessments(records)

        res = vea.audit_scan_and_evidence(
            opengrep_path=self.scan_copy,
            assessments_path=self.ass_copy,
            source_root=self.src_dir,
        )
        self.assertEqual(res["audit_verdict"], "FAIL")
        self.assertTrue(any("cited line 999 does not exist" in i for i in res["issues"]))
        self.assertTrue(any("cited line 15 is blank or comment-only" in i for i in res["issues"]))

    def test_11_wrong_citation_location_or_quote_mismatch_rejected(self) -> None:
        records = self._load_assessments()
        # Finding 0 (lines 25-28): cite unrelated safe method line 40
        records[0]["assessment"]["citations"] = [
            {
                "path": "SmokeVulnSample.java",
                "start_line": 40,
                "end_line": 40,
                "quote": "        ps.setString(1, userInput);",
                "sha256": vea.EXPECTED_SOURCE_SHA,
            }
        ]
        # Finding 1 (lines 32-33): wrong quote text for line 32
        records[1]["assessment"]["citations"] = [
            {
                "path": "SmokeVulnSample.java",
                "start_line": 32,
                "end_line": 32,
                "quote": "String completelyFabricatedCode = null;",
                "sha256": vea.EXPECTED_SOURCE_SHA,
            }
        ]
        self._write_assessments(records)

        res = vea.audit_scan_and_evidence(
            opengrep_path=self.scan_copy,
            assessments_path=self.ass_copy,
            source_root=self.src_dir,
        )
        self.assertEqual(res["audit_verdict"], "FAIL")
        self.assertTrue(any("outside finding/trace location window" in i for i in res["issues"]))
        self.assertTrue(any("citation quote at lines 32..32 does not match" in i for i in res["issues"]))

    def test_12_invalid_json_in_scan_or_assessments_or_raw_response_rejected(self) -> None:
        # Invalid JSON line in assessments.jsonl
        self.ass_copy.write_text(
            self.ass_copy.read_text(encoding="utf-8") + "{malformed json line\n",
            encoding="utf-8",
        )
        res1 = vea.audit_scan_and_evidence(
            opengrep_path=self.scan_copy,
            assessments_path=self.ass_copy,
            source_root=self.src_dir,
        )
        self.assertEqual(res1["audit_verdict"], "FAIL")
        self.assertTrue(any("malformed records" in i for i in res1["issues"]))

        # Invalid JSON in OpenGrep scan file
        bad_scan = self.tmp_dir / "bad_scan.json"
        bad_scan.write_text("{not valid json", encoding="utf-8")
        res2 = vea.audit_scan_and_evidence(
            opengrep_path=bad_scan,
            assessments_path=self.ass_copy,
            source_root=self.src_dir,
        )
        self.assertEqual(res2["audit_verdict"], "FAIL")

    def test_13_missing_or_wrong_model_and_missing_qwen_evidence_rejected(self) -> None:
        records = self._load_assessments()
        records[0]["assessment"]["model"] = "gpt-4o-cloud"
        records[1]["assessment"]["explanation"] = ""
        records[2]["assessment"].pop("raw_response", None)
        records[2]["assessment"]["runtime"] = {"http_response_received": False}
        self._write_assessments(records)

        res = vea.audit_scan_and_evidence(
            opengrep_path=self.scan_copy,
            assessments_path=self.ass_copy,
            source_root=self.src_dir,
            require_qwen_runtime=True,
        )
        self.assertEqual(res["audit_verdict"], "FAIL")
        self.assertTrue(any("model_id is not Qwen3.5" in i for i in res["issues"]))
        self.assertTrue(any("missing Qwen explanation" in i for i in res["issues"]))
        self.assertTrue(any("missing Qwen raw_response" in i for i in res["issues"]))
        self.assertTrue(any("incomplete Qwen LIVE runtime telemetry" in i for i in res["issues"]))

    def test_14_unconfirmed_closed_warning_and_unknown_overclaim_rejected(self) -> None:
        records = self._load_assessments()
        # Finding 0: closed without human confirmation / auto_dismissed
        records[0]["state"] = "CONFIRMED_FALSE"
        records[0]["auto_dismissed"] = True
        # Finding 1: raw model returned UNDETERMINED but assessment claims SUPPORTED
        records[1]["assessment"]["raw_response"] = {
            "model": "qwen3.5:9b-q4_K_M",
            "message": {"role": "assistant", "content": json.dumps({"status": "UNDETERMINED"})},
        }
        records[1]["assessment"]["status"] = "SUPPORTED"
        # Finding 2: UNDETERMINED status over-claimed as PROPOSED_FP and security_conclusion_verified=True
        records[2]["assessment"]["status"] = "UNDETERMINED"
        records[2]["verdict"] = "PROPOSED_FP"
        records[2]["assessment"]["security_conclusion_verified"] = True
        records[2]["assessment"]["requires_human_review"] = False
        self._write_assessments(records)

        res = vea.audit_scan_and_evidence(
            opengrep_path=self.scan_copy,
            assessments_path=self.ass_copy,
            source_root=self.src_dir,
        )
        self.assertEqual(res["audit_verdict"], "FAIL")
        self.assertTrue(any("safety violation: auto_dismissed=True, state='CONFIRMED_FALSE'" in i for i in res["issues"]))
        self.assertTrue(any("over-claimed status 'SUPPORTED' from raw model status 'UNDETERMINED'" in i for i in res["issues"]))
        self.assertTrue(any("UNKNOWN/UNDETERMINED status over-claimed as 'PROPOSED_FP'" in i for i in res["issues"]))
        self.assertTrue(any("security_conclusion_verified=True while state is OPEN" in i for i in res["issues"]))
        self.assertTrue(any("requires_human_review=False" in i for i in res["issues"]))

    def test_15_sqlite_inconsistency_and_unconfirmed_closure_and_lifecycle(self) -> None:
        db_path = self.tmp_dir / "review.sqlite"
        self._build_sqlite_from_copies(db_path)

        # 1. Valid SQLite with lifecycle verification passes and leaves original SQLite untouched
        res_ok = vea.audit_scan_and_evidence(
            opengrep_path=self.scan_copy,
            assessments_path=self.ass_copy,
            source_root=self.src_dir,
            sqlite_path=db_path,
            require_sqlite=True,
            verify_review_lifecycle=True,
        )
        self.assertEqual(res_ok["audit_verdict"], "PASS", msg=f"Issues: {res_ok.get('issues')}")
        self.assertEqual(res_ok["sqlite_audit"]["lifecycle_verification"]["status"], "PASS")
        self.assertTrue(res_ok["sqlite_audit"]["original_sqlite_unchanged"])

        # 2. Tamper with SQLite warning state to CONFIRMED_FALSE without any human review event
        conn = sqlite3.connect(db_path)
        try:
            conn.execute("UPDATE warnings SET state='CONFIRMED_FALSE'")
            conn.commit()
        finally:
            conn.close()

        res_bad = vea.audit_scan_and_evidence(
            opengrep_path=self.scan_copy,
            assessments_path=self.ass_copy,
            source_root=self.src_dir,
            sqlite_path=db_path,
            require_sqlite=True,
        )
        self.assertEqual(res_bad["audit_verdict"], "FAIL")
        self.assertTrue(
            any("state 'CONFIRMED_FALSE' with 0 human review events" in i for i in res_bad["issues"])
        )

    def test_16_codex_adapter_and_score_pilot_verify_start_end_line_quote_and_sha(self) -> None:
        """16. Regression test: codex_adapter + score_pilot must verify quote and sha256 when citation uses start_line/end_line."""
        import codex_adapter
        import score_pilot

        records = self._load_assessments()
        # Convert record #2 (FP in ground truth) to REFUTED with valid start_line/end_line citation
        records[2]["assessment"]["status"] = "REFUTED"
        norm_ok = codex_adapter.convert_single_codex_record(records[2], record_index=2)
        self.assertTrue(
            len(norm_ok["citation_quotes"]) >= 1,
            "codex_adapter must extract citation_quotes from start_line/end_line dicts",
        )

        # Now tamper with quote in start_line/end_line citation on REFUTED record
        tampered_quote_records = copy.deepcopy(records)
        tampered_quote_records[2]["assessment"]["status"] = "REFUTED"
        tampered_quote_records[2]["assessment"]["citations"][0]["quote"] = "String fabricatedSanitizer = sanitize(x);"
        self._write_assessments(tampered_quote_records)

        eval_bad_quote = score_pilot.evaluate_pilot(
            opengrep_data=json.loads(self.scan_copy.read_text(encoding="utf-8")),
            labels_data=json.loads(self.labels_copy.read_text(encoding="utf-8")),
            triage_data=tampered_quote_records,
            source_root=vea.DEFAULT_SOURCE_ROOT,
            expected_model_prefix="qwen3.5",
        )
        self.assertEqual(
            eval_bad_quote["summary"]["overall"]["counts"]["proposed_fp_on_true_fp"],
            0,
            "Tampered quote on start_line/end_line citation must block PROPOSED_FP in score_pilot",
        )
        self.assertTrue(
            len(eval_bad_quote["anomalies"]["ungrounded_fp_overrides"]) >= 1,
            "Expected ungrounded_fp_overrides anomaly when start_line/end_line quote is tampered",
        )

        # Also tamper with sha256 in start_line/end_line citation on REFUTED record
        tampered_sha_records = copy.deepcopy(records)
        tampered_sha_records[2]["assessment"]["status"] = "REFUTED"
        tampered_sha_records[2]["assessment"]["citations"][0]["sha256"] = "f" * 64
        self._write_assessments(tampered_sha_records)

        eval_bad_sha = score_pilot.evaluate_pilot(
            opengrep_data=json.loads(self.scan_copy.read_text(encoding="utf-8")),
            labels_data=json.loads(self.labels_copy.read_text(encoding="utf-8")),
            triage_data=tampered_sha_records,
            source_root=vea.DEFAULT_SOURCE_ROOT,
            expected_model_prefix="qwen3.5",
        )
        self.assertEqual(
            eval_bad_sha["summary"]["overall"]["counts"]["proposed_fp_on_true_fp"],
            0,
            "Tampered sha256 on start_line/end_line citation must block PROPOSED_FP in score_pilot",
        )
        self.assertTrue(
            len(eval_bad_sha["anomalies"]["ungrounded_fp_overrides"]) >= 1,
            "Expected ungrounded_fp_overrides anomaly when start_line/end_line sha256 is tampered",
        )


if __name__ == "__main__":
    unittest.main()
