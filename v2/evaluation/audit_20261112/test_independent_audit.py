"""Counterfactual and adversarial unit test suite for `independent_audit.py`.

Verifies that the standalone audit suite catches every mandatory sabotage class:
1. Tampered alert ground-truth label (vs OWASP v1.2, JSON vs CSV, label vs paired row)
2. Single-character edit in single-line or multi-line cited code quote
3. Modified source SHA-256
4. Swapped rule_id or CWE
5. Duplicate finding_index or alert_id
6. Shuffled row order (must succeed by key) vs missing/orphan row (must fail)
7. Conclusive verdict (`SUPPORTED` / `REFUTED`) without valid citation or citing comment/blank line
8. Mixed records from two different OpenGrep scans (`scan_sha256`)
9. Results produced by a different/unexpected LLM model ID
10. Citation referencing a file outside locked source snapshots or wrong file with matching line number
11. Missing raw server / full-corpus data returns `NOT_VERIFIED`, NEVER `PASS`
12. Distinct `drop_fp` vs `keep_tp_only` policy calculation
13. Rejection of LLM-derived ground-truth labels and auto-dismissed human review state
14. End-to-end server `assessments.jsonl` + `review.sqlite` verifier positive & negative checks
15. Direct code-level proof of `heuristics.py` -> `ollama.py` `recommended_status` steering and `.startsWith(` bug
"""
from __future__ import annotations

import copy
import csv
import json
from pathlib import Path
import random
import sqlite3
import sys
import tempfile
import unittest

AUDIT_DIR = Path(__file__).resolve().parent
REPO_ROOT = AUDIT_DIR.parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(AUDIT_DIR) not in sys.path:
    sys.path.insert(0, str(AUDIT_DIR))

import independent_audit as ia  # noqa: E402


class IndependentAuditCounterfactualTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        pr = ia.POST_REPORT_DIR
        cls.owasp_ref = json.loads(ia.DEFAULT_OWASP_REF.read_text(encoding="utf-8"))
        cls.dev_alerts = json.loads((pr / "dev_alerts.json").read_text(encoding="utf-8"))["alerts"]
        cls.dev_labels_json = json.loads((pr / "labels_development.json").read_text(encoding="utf-8"))["labels"]
        with (pr / "labels_development.csv").open(encoding="utf-8", newline="") as f:
            cls.dev_labels_csv = list(csv.DictReader(f))

        cls.ho_alerts = json.loads((pr / "heldout_alerts.json").read_text(encoding="utf-8"))["alerts"]
        cls.ho_labels_json = json.loads((pr / "labels_heldout.json").read_text(encoding="utf-8"))["labels"]
        with (pr / "labels_heldout.csv").open(encoding="utf-8", newline="") as f:
            cls.ho_labels_csv = list(csv.DictReader(f))

        with (pr / "PAIRED_EVALUATION.csv").open(encoding="utf-8", newline="") as f:
            cls.paired_rows = list(csv.DictReader(f))
        with (pr / "METRICS_BY_CWE.csv").open(encoding="utf-8", newline="") as f:
            cls.metrics_by_cwe_rows = list(csv.DictReader(f))

        cls.sample_lines = [
            "package demo;",
            "// Pure comment line that must never count as code evidence",
            "",
            "public class Sample {",
            "    public void run(String userPath, java.sql.Connection conn) throws Exception {",
            "        String safe = org.apache.commons.io.FilenameUtils.getName(userPath);",
            "        java.io.File target = new java.io.File(\"/srv/data\", safe);",
            "        java.sql.PreparedStatement ps = conn.prepareStatement(",
            "            \"SELECT id FROM users WHERE name = ?\"",
            "        );",
            "    }",
            "}",
        ]
        cls.sample_sha = ia.sha256_text("\n".join(cls.sample_lines) + "\n")
        cls.sample_scan_sha = "a" * 64
        cls.sample_snapshots = {
            "Sample.java": {
                "sha256": cls.sample_sha,
                "lines": cls.sample_lines,
            }
        }

    def test_00_baseline_recomputation_matches_reported_tables(self) -> None:
        recomp = ia.recompute_arm_metrics(self.ho_alerts, self.ho_labels_json, self.paired_rows)
        self.assertEqual(recomp["status"], "PASS")
        self.assertEqual(recomp["anomalies"], [])
        comp = ia.compare_against_reported_tables(recomp, self.metrics_by_cwe_rows)
        self.assertEqual(comp["status"], "PASS")
        self.assertEqual(comp["verdict_label_vi"], "số liệu tái tính khớp")
        self.assertEqual(comp["cell_mismatches"], [])

    def test_01_tampered_alert_label_is_detected(self) -> None:
        # Case A: Flip label in labels_heldout.json against OWASP Ground Truth
        bad_labels = copy.deepcopy(self.ho_labels_json)
        bad_csv = copy.deepcopy(self.ho_labels_csv)
        target_aid = bad_labels[0]["alert_id"]
        flipped = "FALSE_POSITIVE" if bad_labels[0]["ground_truth"] == "TRUE_POSITIVE" else "TRUE_POSITIVE"
        bad_labels[0]["ground_truth"] = flipped
        for crow in bad_csv:
            if crow["alert_id"] == target_aid:
                crow["expected_label"] = flipped

        res = ia.audit_owasp_labels(
            self.dev_alerts,
            self.dev_labels_json,
            self.dev_labels_csv,
            self.ho_alerts,
            bad_labels,
            bad_csv,
            self.owasp_ref,
        )
        self.assertEqual(res["status"], "FAIL")
        self.assertTrue(any(e["type"] == "owasp_ground_truth_mismatch" and e["alert_id"] == target_aid for e in res["errors"]))

        # Case B: Flip verified_ground_truth in PAIRED_EVALUATION.csv relative to locked label
        bad_paired = copy.deepcopy(self.paired_rows)
        bad_paired[3]["verified_ground_truth"] = (
            "FALSE_POSITIVE" if bad_paired[3]["verified_ground_truth"] == "TRUE_POSITIVE" else "TRUE_POSITIVE"
        )
        recomp = ia.recompute_arm_metrics(self.ho_alerts, self.ho_labels_json, bad_paired)
        self.assertEqual(recomp["status"], "FAIL")
        self.assertTrue(any(a["type"] == "ground_truth_mismatch_in_paired_table" for a in recomp["anomalies"]))

    def test_02_single_char_quote_modification_is_rejected(self) -> None:
        # Valid single-line and multi-line citations pass first
        valid_single = {
            "path": "Sample.java",
            "start_line": 6,
            "end_line": 6,
            "quote": self.sample_lines[5],
            "sha256": self.sample_sha,
        }
        ok1, iss1 = ia.verify_citation_strict(valid_single, self.sample_snapshots, self.sample_scan_sha, self.sample_scan_sha)
        self.assertTrue(ok1, iss1)

        valid_multi = {
            "path": "Sample.java",
            "start_line": 8,
            "end_line": 10,
            "quote": "\n".join(self.sample_lines[7:10]),
            "sha256": self.sample_sha,
        }
        ok2, iss2 = ia.verify_citation_strict(valid_multi, self.sample_snapshots, self.sample_scan_sha, self.sample_scan_sha)
        self.assertTrue(ok2, iss2)

        # Single-character mutation in single-line quote (e.g. changing `;` to `:`)
        tampered_single = {**valid_single, "quote": valid_single["quote"][:-1] + ":"}
        ok_bad1, iss_bad1 = ia.verify_citation_strict(
            tampered_single, self.sample_snapshots, self.sample_scan_sha, self.sample_scan_sha
        )
        self.assertFalse(ok_bad1)
        self.assertTrue(any("verbatim_quote_mismatch" in x for x in iss_bad1))

        # Single-character mutation inside middle line of multi-line quote (`?` -> `x`)
        tampered_multi = {**valid_multi, "quote": valid_multi["quote"].replace("?", "x", 1)}
        ok_bad2, iss_bad2 = ia.verify_citation_strict(
            tampered_multi, self.sample_snapshots, self.sample_scan_sha, self.sample_scan_sha
        )
        self.assertFalse(ok_bad2)
        self.assertTrue(any("verbatim_quote_mismatch" in x for x in iss_bad2))

    def test_03_modified_source_sha256_is_detected(self) -> None:
        bad_alerts = copy.deepcopy(self.ho_alerts)
        orig_sha = bad_alerts[5]["source_sha256"]
        bad_alerts[5]["source_sha256"] = ("0" if orig_sha[0] != "0" else "1") + orig_sha[1:]

        recomp = ia.recompute_arm_metrics(bad_alerts, self.ho_labels_json, self.paired_rows)
        self.assertEqual(recomp["status"], "FAIL")
        self.assertTrue(any(a["type"] == "source_sha256_mismatch" for a in recomp["anomalies"]))

        # Also check citation SHA-256 tamper
        bad_cite = {
            "path": "Sample.java",
            "start_line": 6,
            "end_line": 6,
            "quote": self.sample_lines[5],
            "sha256": "f" * 64,
        }
        ok, issues = ia.verify_citation_strict(bad_cite, self.sample_snapshots, self.sample_scan_sha, self.sample_scan_sha)
        self.assertFalse(ok)
        self.assertTrue(any("citation_source_sha256_mismatch" in i for i in issues))

    def test_04_swapped_rule_id_or_cwe_is_detected(self) -> None:
        bad_paired = copy.deepcopy(self.paired_rows)
        bad_paired[2]["cwe"] = "CWE-89" if bad_paired[2]["cwe"] == "CWE-22" else "CWE-22"
        bad_paired[7]["rule_id"] = "java.fake.swapped-rule"

        recomp = ia.recompute_arm_metrics(self.ho_alerts, self.ho_labels_json, bad_paired)
        self.assertEqual(recomp["status"], "FAIL")
        anom_types = {a["type"] for a in recomp["anomalies"]}
        self.assertIn("cwe_mismatch", anom_types)
        self.assertIn("rule_id_mismatch", anom_types)

    def test_05_duplicate_finding_or_alert_id_is_detected(self) -> None:
        dup_paired = copy.deepcopy(self.paired_rows)
        dup_paired[-1] = copy.deepcopy(dup_paired[0])

        recomp = ia.recompute_arm_metrics(self.ho_alerts, self.ho_labels_json, dup_paired)
        self.assertEqual(recomp["status"], "FAIL")
        anom_types = {a["type"] for a in recomp["anomalies"]}
        self.assertIn("duplicate_paired_alert_id", anom_types)
        self.assertIn("missing_paired_row_for_alert", anom_types)

    def test_06_reordered_rows_match_by_key_and_missing_row_fails(self) -> None:
        rng = random.Random(20261112)
        shuf_alerts = copy.deepcopy(self.ho_alerts)
        shuf_labels = copy.deepcopy(self.ho_labels_json)
        shuf_paired = copy.deepcopy(self.paired_rows)
        rng.shuffle(shuf_alerts)
        rng.shuffle(shuf_labels)
        rng.shuffle(shuf_paired)

        baseline = ia.recompute_arm_metrics(self.ho_alerts, self.ho_labels_json, self.paired_rows)
        shuffled = ia.recompute_arm_metrics(shuf_alerts, shuf_labels, shuf_paired)
        self.assertEqual(shuffled["status"], "PASS")
        self.assertEqual(shuffled["arms"], baseline["arms"])

        # Deleting one row must immediately fail
        missing_paired = shuf_paired[:-1]
        failed = ia.recompute_arm_metrics(shuf_alerts, shuf_labels, missing_paired)
        self.assertEqual(failed["status"], "FAIL")
        self.assertTrue(any(a["type"] == "missing_paired_row_for_alert" for a in failed["anomalies"]))

    def test_07_conclusive_verdict_without_valid_evidence_fails(self) -> None:
        # Case A: Conclusive REFUTED in paired table without MATCHED citation / cited_lines
        bad_paired = copy.deepcopy(self.paired_rows)
        ref_row = next(r for r in bad_paired if r["arm_c_qwen35_post_citation_status"] == "REFUTED")
        ref_row["arm_c_cited_lines"] = ""
        recomp = ia.recompute_arm_metrics(self.ho_alerts, self.ho_labels_json, bad_paired)
        self.assertEqual(recomp["status"], "FAIL")
        self.assertTrue(any(a["type"] == "ungrounded_conclusive_verdict" and a["arm"] == "Arm_C" for a in recomp["anomalies"]))

        # Case B: Citation pointing to comment-only or blank line is rejected
        comment_cite = {
            "path": "Sample.java",
            "start_line": 2,
            "end_line": 3,
            "quote": "\n".join(self.sample_lines[1:3]),
            "sha256": self.sample_sha,
        }
        ok, issues = ia.verify_citation_strict(comment_cite, self.sample_snapshots, self.sample_scan_sha, self.sample_scan_sha)
        self.assertFalse(ok)
        self.assertTrue(any("citation_blank_or_comment_only" in x for x in issues))

    def test_08_mixed_data_from_two_scans_is_detected(self) -> None:
        mixed_paired = copy.deepcopy(self.paired_rows)
        mixed_paired[10]["scan_sha256"] = ia.EXPECTED_SCAN_SHAS["dev_set_16"]

        recomp = ia.recompute_arm_metrics(self.ho_alerts, self.ho_labels_json, mixed_paired)
        self.assertEqual(recomp["status"], "FAIL")
        self.assertTrue(any(a["type"] == "mixed_or_wrong_scan_sha256" for a in recomp["anomalies"]))

    def test_09_wrong_model_id_is_detected(self) -> None:
        bad_paired = copy.deepcopy(self.paired_rows)
        bad_paired[0]["arm_c_model_id"] = "qwen2.5-coder:7b-instruct"

        recomp = ia.recompute_arm_metrics(self.ho_alerts, self.ho_labels_json, bad_paired)
        self.assertEqual(recomp["status"], "FAIL")
        self.assertTrue(any(a["type"] == "wrong_model_id" for a in recomp["anomalies"]))

    def test_10_citation_outside_locked_snapshot_or_wrong_file_is_rejected(self) -> None:
        # OtherFile.java has the exact same text at line 6, but is NOT Sample.java / not in locked snapshots
        wrong_file_cite = {
            "path": "OtherFile.java",
            "start_line": 6,
            "end_line": 6,
            "quote": self.sample_lines[5],
            "sha256": self.sample_sha,
        }
        ok, issues = ia.verify_citation_strict(
            wrong_file_cite, self.sample_snapshots, self.sample_scan_sha, self.sample_scan_sha
        )
        self.assertFalse(ok)
        self.assertTrue(any("citation_path_outside_locked_snapshots" in x for x in issues))

    def test_11_insufficient_or_missing_data_returns_not_verified_never_pass(self) -> None:
        # Missing server directory -> NOT_VERIFIED
        res_none = ia.audit_server_raw_evidence(None)
        self.assertEqual(res_none["status"], "NOT_VERIFIED")
        self.assertNotEqual(res_none["status"], "PASS")

        with tempfile.TemporaryDirectory() as tmp:
            empty_dir = Path(tmp) / "empty_server"
            empty_dir.mkdir()
            res_empty = ia.audit_server_raw_evidence(empty_dir)
            self.assertEqual(res_empty["status"], "NOT_VERIFIED")
            self.assertNotEqual(res_empty["status"], "PASS")

        # Full-corpus OWASP test-case TPR/FPR without 772-case scan -> NOT_VERIFIED
        recomp = ia.recompute_arm_metrics(self.ho_alerts, self.ho_labels_json, self.paired_rows)
        self.assertEqual(recomp["owasp_testcase_level_tpr_fpr"]["status"], "NOT_VERIFIED")

    def test_12_drop_fp_and_keep_tp_only_policies_are_distinct(self) -> None:
        recomp = ia.recompute_arm_metrics(self.ho_alerts, self.ho_labels_json, self.paired_rows)
        arm_b_pol = recomp["arms"]["Arm_B_Heuristic"]["ALL (CWE-22 + CWE-89)"]["policies_alert_level"]
        # Arm B has 24 UNDETERMINED (11 TP, 13 FP), 9 SUPPORTED (9 TP, 0 FP), 7 REFUTED (0 TP, 7 FP):
        # drop_fp keeps 9+24=33 alerts (20 TP / 33 = 60.61% precision, 20/20 = 100% recall)
        # keep_tp_only keeps 9 alerts (9 TP / 9 = 100.0% precision, 9/20 = 45.0% recall)
        self.assertEqual(arm_b_pol["drop_fp"]["retained_alerts"], 33)
        self.assertEqual(arm_b_pol["keep_tp_only"]["retained_alerts"], 9)
        self.assertNotEqual(arm_b_pol["drop_fp"]["precision"]["pct"], arm_b_pol["keep_tp_only"]["precision"]["pct"])
        self.assertNotEqual(
            arm_b_pol["drop_fp"]["tp_recall_alert_tpr"]["pct"],
            arm_b_pol["keep_tp_only"]["tp_recall_alert_tpr"]["pct"],
        )

    def test_13_llm_generated_labels_and_human_review_bypass_are_rejected(self) -> None:
        bad_labels = copy.deepcopy(self.ho_labels_json)
        bad_labels[0]["annotated_by"] = "qwen3.5:9b-q4_K_M-auto-labeler"
        recomp = ia.recompute_arm_metrics(self.ho_alerts, bad_labels, self.paired_rows)
        self.assertEqual(recomp["status"], "FAIL")
        self.assertTrue(any(a["type"] == "forbidden_llm_ground_truth" for a in recomp["anomalies"]))

        bad_paired = copy.deepcopy(self.paired_rows)
        bad_paired[0]["arm_c_human_review_state"] = "CONFIRMED_FALSE"
        recomp2 = ia.recompute_arm_metrics(self.ho_alerts, self.ho_labels_json, bad_paired)
        self.assertEqual(recomp2["status"], "FAIL")
        self.assertTrue(any(a["type"] == "human_review_state_not_open" for a in recomp2["anomalies"]))

    def test_14_server_raw_evidence_verifier_catches_tampering_and_auto_close(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = root / "run1"
            run_dir.mkdir()
            og_bytes = b'{"results":[{"check_id":"r1"}],"errors":[]}'
            scan_sha = ia.sha256_bytes(og_bytes)
            (run_dir / "input.opengrep.json").write_bytes(og_bytes)
            aid = ia.canonical_alert_id(scan_sha, 0)

            valid_row = {
                "schema_version": "1.1",
                "id": aid,
                "alert_id": aid,
                "scan_sha256": scan_sha,
                "finding_index": 0,
                "state": "OPEN",
                "evidence": {
                    "id": aid,
                    "scan_sha256": scan_sha,
                    "finding_index": 0,
                    "triage_mode": "evidence+llm",
                    "heuristic_signals": {"recommended_status": "REFUTED"},
                    "snapshots": self.sample_snapshots,
                },
                "assessment": {
                    "status": "REFUTED",
                    "transport": "ollama-http",
                    "model": ia.EXPECTED_MODEL_ID,
                    "citations": [{
                        "path": "Sample.java",
                        "start_line": 6,
                        "end_line": 6,
                        "quote": self.sample_lines[5],
                        "sha256": self.sample_sha,
                    }],
                    "runtime": {
                        "origin": "unverified",
                        "request_attempted": True,
                        "http_response_received": True,
                        "http_status": 200,
                    },
                    "raw_response": {"eval_count": 42, "done": True},
                },
            }
            a_file = run_dir / "assessments.jsonl"
            a_file.write_text(json.dumps(valid_row) + "\n", encoding="utf-8")

            # Valid 1-file server dir yields PARTIAL (1/10 files, 0 errors)
            res_ok = ia.audit_server_raw_evidence(root)
            self.assertEqual(res_ok["status"], "PARTIAL")
            self.assertEqual(res_ok["errors"], [])
            self.assertEqual(
                res_ok["assessment_receipts"][0]["rows_with_heuristic_recommended_status_in_prompt_context"],
                1,
            )

            # Create SQLite DB with illegal auto-dismissed warning (CONFIRMED_FALSE with 0 events)
            db_path = run_dir / "review.sqlite"
            conn = sqlite3.connect(db_path)
            conn.executescript(
                """
                CREATE TABLE warnings(id TEXT PRIMARY KEY, state TEXT NOT NULL);
                CREATE TABLE events(sequence INTEGER PRIMARY KEY, warning_id TEXT);
                INSERT INTO warnings VALUES ('w1', 'CONFIRMED_FALSE');
                """
            )
            conn.commit()
            conn.close()

            # Also tamper model ID in assessments.jsonl
            bad_row = copy.deepcopy(valid_row)
            bad_row["assessment"]["model"] = "llama3:8b"
            a_file.write_text(json.dumps(bad_row) + "\n", encoding="utf-8")

            res_bad = ia.audit_server_raw_evidence(root)
            self.assertEqual(res_bad["status"], "FAIL")
            err_types = {e["type"] for e in res_bad["errors"]}
            self.assertIn("wrong_model_id", err_types)
            self.assertIn("auto_dismissal_without_human_event", err_types)

    def test_15_proves_heuristic_steering_and_unsound_startswith_sanitizer_in_triage_code(self) -> None:
        from v2.triage.heuristics import extract_evidence_signals
        from v2.triage.ollama import request_payload

        # Construct a genuinely vulnerable CWE-22 snippet that calls normalize() WITHOUT checking path prefix,
        # while having an unrelated header.startsWith("Bearer ") on line 2!
        vuln_lines = [
            {"line": 1, "text": "String token = request.getHeader(\"Authorization\");"},
            {"line": 2, "text": "if (token != null && token.startsWith(\"Bearer \")) {"},
            {"line": 3, "text": "    String p = java.nio.file.Paths.get(request.getParameter(\"f\")).normalize().toString();"},
            {"line": 4, "text": "    new java.io.FileInputStream(\"/var/data/\" + p);"},
            {"line": 5, "text": "}"},
        ]
        record = {
            "id": "b" * 64,
            "rule_id": "java.lang.security.httpservlet-path-traversal.httpservlet-path-traversal",
            "cwe": ["CWE-22"],
            "severity": "ERROR",
            "message": "path traversal",
            "path": "Vuln.java",
            "start": {"line": 4},
            "end": {"line": 4},
            "snapshots": {"Vuln.java": {"sha256": "c" * 64}},
            "snippets": [{
                "role": "finding",
                "path": "Vuln.java",
                "sha256": "c" * 64,
                "start": {"line": 1},
                "end": {"line": 5},
                "lines": vuln_lines,
            }],
            "issues": [],
        }
        signals = extract_evidence_signals(record)
        record["heuristic_signals"] = signals

        # Unsound sanitizer bug: unrelated `token.startsWith("Bearer ")` causes heuristics.py
        # to classify `normalize()` as a valid CWE-22 sanitizer and steer Qwen to REFUTED!
        self.assertEqual(signals["recommended_status"], "REFUTED")
        self.assertTrue(any(s["name"] == "normalize_startsWith" for s in signals["sanitizers_found"]))

        # Verify ollama.py request_payload injects recommended_status + recommendation_reason + candidate_citations
        payload = request_payload(record, ia.EXPECTED_MODEL_ID)
        user_msg = json.loads(payload["messages"][1]["content"])
        injected_signals = user_msg["evidence_signals"]
        self.assertEqual(injected_signals["recommended_status"], "REFUTED")
        self.assertIn("làm sạch đúng ngữ cảnh CWE-22", injected_signals["recommendation_reason"])
        self.assertTrue(len(injected_signals["candidate_citations"]) >= 1)


if __name__ == "__main__":
    unittest.main()
