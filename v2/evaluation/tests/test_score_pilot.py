"""Unit tests for v2/evaluation/score_pilot.py.

ALL DATA IN THIS FILE IS A SYNTHETIC TEST FIXTURE ("TEST_FIXTURE_ONLY").
Do NOT treat any alerts, labels, or triage outputs here as real OpenGrep or Qwen runs.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import score_pilot  # noqa: E402

TEST_FIXTURE_BANNER = "TEST_FIXTURE_ONLY: Synthetic data for unit testing score_pilot.py"


class TestScorePilotEvaluation(unittest.TestCase):
    """Tests M4/M5 scoring logic and edge cases on synthetic TEST FIXTURE data."""

    def setUp(self) -> None:
        self.sample_sha = score_pilot.compute_sha256_text("// synthetic java source fixture")

    def test_standard_priority_and_secondary_cwe_scoring(self) -> None:
        """Verify TP/FP/REVIEW counts, coverage, and latency across CWE-22/89 and CWE-78/79."""
        opengrep_fixture = {
            "_fixture_notice": TEST_FIXTURE_BANNER,
            "results": [
                {
                    "alert_id": "FIXTURE-CWE22-TP-1",
                    "path": "src/FileController.java",
                    "start": {"line": 42},
                    "end": {"line": 45},
                    "check_id": "java.lang.security.audit.path-traversal",
                    "extra": {"metadata": {"cwe": ["CWE-22: Improper Limitation of a Pathname"]}},
                    "source_sha256": self.sample_sha,
                },
                {
                    "alert_id": "FIXTURE-CWE22-FP-1",
                    "path": "src/FileController.java",
                    "start": {"line": 80},
                    "end": {"line": 84},
                    "check_id": "java.lang.security.audit.path-traversal",
                    "extra": {"metadata": {"cwe": "CWE-22"}},
                    "source_sha256": self.sample_sha,
                },
                {
                    "alert_id": "FIXTURE-CWE89-TP-ERR-DROP",
                    "path": "src/UserDao.java",
                    "start": {"line": 19},
                    "end": {"line": 22},
                    "check_id": "java.sql.sqli",
                    "extra": {"metadata": {"cwe": "CWE-89"}},
                    "source_sha256": self.sample_sha,
                },
                {
                    "alert_id": "FIXTURE-CWE89-FP-1",
                    "path": "src/UserDao.java",
                    "start": {"line": 55},
                    "end": {"line": 58},
                    "check_id": "java.sql.sqli",
                    "extra": {"metadata": {"cwe": "CWE-89"}},
                    "source_sha256": self.sample_sha,
                },
                {
                    "alert_id": "FIXTURE-CWE78-AMB-1",
                    "path": "src/ExecRunner.java",
                    "start": {"line": 30},
                    "end": {"line": 33},
                    "check_id": "java.lang.cmdi",
                    "extra": {"metadata": {"cwe": "CWE-78"}},
                    "source_sha256": self.sample_sha,
                },
                {
                    "alert_id": "FIXTURE-CWE79-FP-REVIEW",
                    "path": "src/ViewServlet.java",
                    "start": {"line": 12},
                    "end": {"line": 15},
                    "check_id": "java.servlet.xss",
                    "extra": {"metadata": {"cwe": "CWE-79"}},
                    "source_sha256": self.sample_sha,
                },
            ],
        }

        labels_fixture = {
            "_fixture_notice": TEST_FIXTURE_BANNER,
            "labels": [
                {
                    "alert_id": "FIXTURE-CWE22-TP-1",
                    "file_path": "src/FileController.java",
                    "cwe": "CWE-22",
                    "ground_truth": "TRUE_POSITIVE",
                    "source_sha256": self.sample_sha,
                },
                {
                    "alert_id": "FIXTURE-CWE22-FP-1",
                    "file_path": "src/FileController.java",
                    "cwe": "CWE-22",
                    "ground_truth": "FALSE_POSITIVE",
                    "source_sha256": self.sample_sha,
                },
                {
                    "alert_id": "FIXTURE-CWE89-TP-ERR-DROP",
                    "file_path": "src/UserDao.java",
                    "cwe": "CWE-89",
                    "ground_truth": "TRUE_POSITIVE",
                    "source_sha256": self.sample_sha,
                },
                {
                    "alert_id": "FIXTURE-CWE89-FP-1",
                    "file_path": "src/UserDao.java",
                    "cwe": "CWE-89",
                    "ground_truth": "FALSE_POSITIVE",
                    "source_sha256": self.sample_sha,
                },
                {
                    "alert_id": "FIXTURE-CWE78-AMB-1",
                    "file_path": "src/ExecRunner.java",
                    "cwe": "CWE-78",
                    "ground_truth": "AMBIGUOUS",
                    "source_sha256": self.sample_sha,
                },
                {
                    "alert_id": "FIXTURE-CWE79-FP-REVIEW",
                    "file_path": "src/ViewServlet.java",
                    "cwe": "CWE-79",
                    "ground_truth": "FALSE_POSITIVE",
                    "source_sha256": self.sample_sha,
                },
            ],
        }

        triage_fixture = {
            "_fixture_notice": TEST_FIXTURE_BANNER,
            "triage_results": [
                {
                    "alert_id": "FIXTURE-CWE22-TP-1",
                    "cwe": "CWE-22",
                    "verdict": "TP",
                    "cited_lines": [42, 44],
                    "rationale": "User request param flows directly to FileInputStream sink.",
                    "source_sha256": self.sample_sha,
                    "latency_ms": 1200.0,
                },
                {
                    "alert_id": "FIXTURE-CWE22-FP-1",
                    "cwe": "CWE-22",
                    "verdict": "FP",
                    "cited_lines": [81, 82],
                    "context_start_line": 75,
                    "context_end_line": 90,
                    "rationale": "Path normalize + startsWith(BASE_DIR) enforces strict containment.",
                    "source_sha256": self.sample_sha,
                    "latency_ms": 1400.0,
                },
                {
                    "alert_id": "FIXTURE-CWE89-TP-ERR-DROP",
                    "cwe": "CWE-89",
                    "verdict": "FP",
                    "cited_lines": [20],
                    "context_start_line": 15,
                    "context_end_line": 25,
                    "rationale": "Model mistakenly claims input is integer-only when it is String.",
                    "source_sha256": self.sample_sha,
                    "latency_ms": 1600.0,
                },
                {
                    "alert_id": "FIXTURE-CWE89-FP-1",
                    "cwe": "CWE-89",
                    "verdict": "FP",
                    "cited_lines": [56, 57],
                    "context_start_line": 50,
                    "context_end_line": 62,
                    "rationale": "PreparedStatement with ? placeholder and setString binds parameter.",
                    "source_sha256": self.sample_sha,
                    "latency_ms": 1100.0,
                },
                {
                    "alert_id": "FIXTURE-CWE78-AMB-1",
                    "cwe": "CWE-78",
                    "verdict": "FP",
                    "cited_lines": [31],
                    "context_start_line": 25,
                    "context_end_line": 35,
                    "rationale": "Wrapper helper comes from external jar; cannot verify sanitizer.",
                    "source_sha256": self.sample_sha,
                    "latency_ms": 1800.0,
                },
                {
                    "alert_id": "FIXTURE-CWE79-FP-REVIEW",
                    "cwe": "CWE-79",
                    "verdict": "UNDETERMINED",
                    "cited_lines": [13],
                    "rationale": "Custom encoding method unknown.",
                    "source_sha256": self.sample_sha,
                    "latency_ms": 900.0,
                },
            ],
        }

        report = score_pilot.evaluate_pilot(opengrep_fixture, labels_fixture, triage_fixture)
        overall = report["summary"]["overall"]
        priority = report["summary"]["priority_tier_1"]
        secondary = report["summary"]["secondary_tier_2"]

        # Overall counts: 6 alerts (2 TP, 3 FP, 1 AMBIGUOUS)
        self.assertEqual(overall["counts"]["total_alerts"], 6)
        self.assertEqual(overall["counts"]["labeled_tp"], 2)
        self.assertEqual(overall["counts"]["labeled_fp"], 3)
        self.assertEqual(overall["counts"]["labeled_ambiguous"], 1)

        # Proposed FP on true FP: 2 out of 3 (CWE-22-FP-1 and CWE-89-FP-1)
        self.assertEqual(overall["rates"]["proposed_fp_removal"]["numerator"], 2)
        self.assertEqual(overall["rates"]["proposed_fp_removal"]["denominator"], 3)

        # Erroneously proposed TP removal: 1 out of 2 (FIXTURE-CWE89-TP-ERR-DROP)
        self.assertEqual(overall["rates"]["erroneous_tp_removal"]["numerator"], 1)
        self.assertEqual(overall["rates"]["erroneous_tp_removal"]["denominator"], 2)
        self.assertAlmostEqual(overall["rates"]["erroneous_tp_removal"]["rate"], 0.5)

        # Needs review: 2 (1 UNDETERMINED on CWE-79 + 1 AMBIGUOUS on CWE-78 routed to review)
        self.assertEqual(overall["counts"]["needs_review_total"], 2)
        self.assertEqual(overall["counts"]["needs_review_on_ambiguous"], 1)
        self.assertEqual(overall["counts"]["needs_review_on_fp"], 1)

        # Priority Tier 1 (CWE-22, CWE-89): 4 alerts (2 TP, 2 FP)
        self.assertEqual(priority["counts"]["total_alerts"], 4)
        self.assertEqual(priority["rates"]["proposed_fp_removal"]["numerator"], 2)
        self.assertEqual(priority["rates"]["proposed_fp_removal"]["denominator"], 2)
        self.assertEqual(priority["rates"]["erroneous_tp_removal"]["numerator"], 1)
        self.assertEqual(priority["rates"]["erroneous_tp_removal"]["denominator"], 2)

        # Secondary Tier 2 (CWE-78, CWE-79): 2 alerts
        self.assertEqual(secondary["counts"]["total_alerts"], 2)

        # Coverage & Latency
        self.assertEqual(overall["rates"]["triage_coverage"]["numerator"], 6)
        self.assertEqual(overall["rates"]["triage_coverage"]["denominator"], 6)
        self.assertEqual(overall["latency_ms"]["count"], 6)
        self.assertEqual(overall["latency_ms"]["total_ms"], 8000.0)
        self.assertEqual(overall["latency_ms"]["p50_ms"], 1300.0)

    def test_missing_labels_and_unlabeled_handling(self) -> None:
        """Verify alerts missing ground-truth labels are tracked and routed to REVIEW."""
        opengrep_fixture = [
            {"alert_id": "A-LABELED", "file_path": "src/A.java", "start_line": 10, "cwe": "CWE-22"},
            {"alert_id": "A-MISSING-LABEL", "file_path": "src/B.java", "start_line": 20, "cwe": "CWE-89"},
        ]
        labels_fixture = [
            {"alert_id": "A-LABELED", "file_path": "src/A.java", "cwe": "CWE-22", "ground_truth": "FALSE_POSITIVE"},
        ]
        triage_fixture = [
            {
                "alert_id": "A-LABELED",
                "cwe": "CWE-22",
                "verdict": "FP",
                "cited_lines": [10],
                "rationale": "Constant path lookup from static allowlist.",
            },
            {
                "alert_id": "A-MISSING-LABEL",
                "cwe": "CWE-89",
                "verdict": "FP",
                "cited_lines": [20],
                "rationale": "Parameterized query.",
            },
        ]

        report = score_pilot.evaluate_pilot(opengrep_fixture, labels_fixture, triage_fixture)
        self.assertEqual(report["anomalies"]["unlabeled_alert_ids"], ["A-MISSING-LABEL"])
        overall = report["summary"]["overall"]
        self.assertEqual(overall["counts"]["unlabeled_alerts"], 1)
        # Unlabeled alert with FP verdict must NOT inflate proposed_fp_on_true_fp
        self.assertEqual(overall["counts"]["proposed_fp_on_true_fp"], 1)
        self.assertEqual(overall["counts"]["needs_review_on_unlabeled"], 1)
        self.assertEqual(overall["rates"]["label_coverage"]["numerator"], 1)
        self.assertEqual(overall["rates"]["label_coverage"]["denominator"], 2)

    def test_wrong_cwe_join_detection(self) -> None:
        """Verify wrong-CWE joins between alert, label, and triage are rejected and flagged."""
        opengrep_fixture = [
            {"alert_id": "CWE-MISMATCH-LABEL", "file_path": "src/Dao.java", "start_line": 15, "cwe": "CWE-89"},
            {"alert_id": "CWE-MISMATCH-TRIAGE", "file_path": "src/Path.java", "start_line": 30, "cwe": "CWE-22"},
        ]
        labels_fixture = [
            # Label wrongly says CWE-22 on a CWE-89 alert
            {"alert_id": "CWE-MISMATCH-LABEL", "file_path": "src/Dao.java", "cwe": "CWE-22", "ground_truth": "FALSE_POSITIVE"},
            {"alert_id": "CWE-MISMATCH-TRIAGE", "file_path": "src/Path.java", "cwe": "CWE-22", "ground_truth": "FALSE_POSITIVE"},
        ]
        triage_fixture = [
            {
                "alert_id": "CWE-MISMATCH-LABEL",
                "cwe": "CWE-89",
                "verdict": "FP",
                "cited_lines": [15],
                "rationale": "Uses PreparedStatement safely.",
            },
            {
                # Triage model analyzed CWE-79 XSS instead of CWE-22 Path Traversal!
                "alert_id": "CWE-MISMATCH-TRIAGE",
                "cwe": "CWE-79",
                "verdict": "FP",
                "cited_lines": [30],
                "rationale": "HTML escaped via OWASP encoder (irrelevant to CWE-22 path traversal!).",
            },
        ]

        report = score_pilot.evaluate_pilot(opengrep_fixture, labels_fixture, triage_fixture)
        mismatches = report["anomalies"]["cwe_mismatches"]
        self.assertEqual(len(mismatches), 2)
        stages = {m["stage"] for m in mismatches}
        self.assertEqual(stages, {"alert_vs_label", "alert_vs_triage"})

        # Neither mismatched alert may count as a valid proposed FP removal
        overall = report["summary"]["overall"]
        self.assertEqual(overall["counts"]["proposed_fp_on_true_fp"], 0)
        self.assertEqual(overall["counts"]["needs_review_total"], 2)

    def test_duplicate_ids_detection_and_deduplication(self) -> None:
        """Verify duplicate IDs in OpenGrep alerts, labels, and triage outputs are caught."""
        opengrep_fixture = [
            {"alert_id": "DUP-1", "file_path": "src/App.java", "start_line": 10, "cwe": "CWE-22"},
            {"alert_id": "DUP-1", "file_path": "src/App.java", "start_line": 10, "cwe": "CWE-22"},
        ]
        labels_fixture = [
            {"alert_id": "DUP-1", "file_path": "src/App.java", "cwe": "CWE-22", "ground_truth": "TRUE_POSITIVE"},
            {"alert_id": "DUP-1", "file_path": "src/App.java", "cwe": "CWE-22", "ground_truth": "FALSE_POSITIVE"},
        ]
        triage_fixture = [
            {"alert_id": "DUP-1", "cwe": "CWE-22", "verdict": "TP", "latency_ms": 500},
            {"alert_id": "DUP-1", "cwe": "CWE-22", "verdict": "FP", "latency_ms": 600},
        ]

        report = score_pilot.evaluate_pilot(opengrep_fixture, labels_fixture, triage_fixture)
        self.assertEqual(report["anomalies"]["duplicate_alert_ids"], ["DUP-1"])
        self.assertEqual(report["anomalies"]["duplicate_label_ids"], ["DUP-1"])
        self.assertEqual(report["anomalies"]["duplicate_triage_ids"], ["DUP-1"])
        # Deduplicated to 1 unique alert
        self.assertEqual(report["summary"]["overall"]["counts"]["total_alerts"], 1)

    def test_zero_denominators_safe_division(self) -> None:
        """Verify zero denominators (0 alerts, 0 TP, 0 FP) return rate=None without ZeroDivisionError."""
        report = score_pilot.evaluate_pilot(opengrep_data=[], labels_data=[], triage_data=[])
        overall = report["summary"]["overall"]
        self.assertEqual(overall["counts"]["total_alerts"], 0)
        self.assertIsNone(overall["rates"]["proposed_fp_removal"]["rate"])
        self.assertEqual(overall["rates"]["proposed_fp_removal"]["display"], "0/0 (N/A)")
        self.assertIsNone(overall["rates"]["erroneous_tp_removal"]["rate"])
        self.assertEqual(overall["rates"]["erroneous_tp_removal"]["display"], "0/0 (N/A)")
        self.assertIsNone(overall["rates"]["triage_coverage"]["rate"])
        self.assertIsNone(overall["latency_ms"]["mean_ms"])

        # Also test non-empty alerts with 0 TPs (only FPs present)
        only_fp_alerts = [{"alert_id": "ONLY-FP", "file_path": "a.java", "start_line": 1, "cwe": "CWE-89"}]
        only_fp_labels = [{"alert_id": "ONLY-FP", "file_path": "a.java", "cwe": "CWE-89", "ground_truth": "FALSE_POSITIVE"}]
        only_fp_triage = [{
            "alert_id": "ONLY-FP",
            "cwe": "CWE-89",
            "verdict": "FP",
            "cited_lines": [1],
            "rationale": "Safe parameterized query via PreparedStatement.",
        }]
        report_no_tp = score_pilot.evaluate_pilot(only_fp_alerts, only_fp_labels, only_fp_triage)
        err_tp_rate = report_no_tp["summary"]["overall"]["rates"]["erroneous_tp_removal"]
        self.assertEqual(err_tp_rate["numerator"], 0)
        self.assertEqual(err_tp_rate["denominator"], 0)
        self.assertIsNone(err_tp_rate["rate"])
        self.assertEqual(err_tp_rate["display"], "0/0 (N/A)")

    def test_malformed_json_and_corrupted_llm_outputs_fallback_to_review(self) -> None:
        """Verify malformed JSONL lines, invalid raw_llm_json, and invalid verdicts fail safe to REVIEW."""
        opengrep_fixture = [
            {"alert_id": "MAL-1", "file_path": "src/A.java", "start_line": 10, "cwe": "CWE-22"},
            {"alert_id": "MAL-2", "file_path": "src/B.java", "start_line": 20, "cwe": "CWE-89"},
            {"alert_id": "MAL-3", "file_path": "src/C.java", "start_line": 30, "cwe": "CWE-89"},
        ]
        labels_fixture = [
            {"alert_id": "MAL-1", "file_path": "src/A.java", "cwe": "CWE-22", "ground_truth": "TRUE_POSITIVE"},
            {"alert_id": "MAL-2", "file_path": "src/B.java", "cwe": "CWE-89", "ground_truth": "FALSE_POSITIVE"},
            {"alert_id": "MAL-3", "file_path": "src/C.java", "cwe": "CWE-89", "ground_truth": "FALSE_POSITIVE"},
        ]
        # Raw JSONL string with:
        # Line 1: truncated/corrupted JSON for MAL-1
        # Line 2: valid outer JSON for MAL-2 but corrupted embedded raw_llm_json
        # Line 3: valid JSON for MAL-3 but hallucinated verdict "MAYBE_SAFE"
        raw_jsonl_triage = "\n".join([
            '{"alert_id": "MAL-1", "verdict": "FP", "rationale": "unterminated string...',
            json.dumps({"alert_id": "MAL-2", "raw_llm_json": "{not valid json"}),
            json.dumps({"alert_id": "MAL-3", "cwe": "CWE-89", "verdict": "MAYBE_SAFE"}),
        ])

        report = score_pilot.evaluate_pilot(opengrep_fixture, labels_fixture, raw_jsonl_triage)
        self.assertEqual(len(report["anomalies"]["malformed_triage_records"]), 3)
        overall = report["summary"]["overall"]
        # All 3 must fail-safe to REVIEW; 0 coverage; 0 proposed FP removals
        self.assertEqual(overall["counts"]["needs_review_total"], 3)
        self.assertEqual(overall["counts"]["triage_covered_alerts"], 0)
        self.assertEqual(overall["counts"]["proposed_fp_on_true_fp"], 0)
        self.assertEqual(overall["counts"]["erroneously_proposed_fp_on_tp"], 0)

    def test_security_review_guards_sha256_ungrounded_fp_and_human_approval(self) -> None:
        """Verify SHA-256 drift, ungrounded FP citations, and auto-dismiss bypass are caught."""
        opengrep_fixture = [
            {
                "alert_id": "SEC-SHA",
                "file_path": "src/S1.java",
                "start_line": 10,
                "cwe": "CWE-22",
                "source_sha256": "aaa111",
            },
            {
                "alert_id": "SEC-UNGROUNDED",
                "file_path": "src/S2.java",
                "start_line": 20,
                "cwe": "CWE-89",
                "source_sha256": "bbb222",
            },
            {
                "alert_id": "SEC-BYPASS",
                "file_path": "src/S3.java",
                "start_line": 30,
                "cwe": "CWE-89",
                "source_sha256": "ccc333",
            },
        ]
        labels_fixture = [
            {"alert_id": "SEC-SHA", "file_path": "src/S1.java", "cwe": "CWE-22", "ground_truth": "FALSE_POSITIVE", "source_sha256": "aaa111"},
            {"alert_id": "SEC-UNGROUNDED", "file_path": "src/S2.java", "cwe": "CWE-89", "ground_truth": "FALSE_POSITIVE", "source_sha256": "bbb222"},
            {"alert_id": "SEC-BYPASS", "file_path": "src/S3.java", "cwe": "CWE-89", "ground_truth": "FALSE_POSITIVE", "source_sha256": "ccc333"},
        ]
        triage_fixture = [
            {
                "alert_id": "SEC-SHA",
                "cwe": "CWE-22",
                "verdict": "FP",
                "cited_lines": [10],
                "rationale": "Canonical path validated against base directory.",
                "source_sha256": "different_sha_after_edit",
            },
            {
                "alert_id": "SEC-UNGROUNDED",
                "cwe": "CWE-89",
                "verdict": "FP",
                "cited_lines": [999],  # Out of context range [15, 25]
                "context_start_line": 15,
                "context_end_line": 25,
                "rationale": "Claiming line 999 sanitizes input.",
                "source_sha256": "bbb222",
            },
            {
                "alert_id": "SEC-BYPASS",
                "cwe": "CWE-89",
                "verdict": "FP",
                "cited_lines": [30],
                "rationale": "PreparedStatement binds parameter safely.",
                "source_sha256": "ccc333",
                "auto_dismissed": True,  # Forbidden by AGENTS.md Rule 4!
            },
        ]

        report = score_pilot.evaluate_pilot(opengrep_fixture, labels_fixture, triage_fixture)
        self.assertEqual(len(report["anomalies"]["sha256_mismatches"]), 1)
        self.assertEqual(len(report["anomalies"]["ungrounded_fp_overrides"]), 1)
        self.assertEqual(len(report["anomalies"]["human_approval_violations"]), 1)

        # All 3 must be overridden to REVIEW rather than accepted as FP removals
        overall = report["summary"]["overall"]
        self.assertEqual(overall["counts"]["proposed_fp_on_true_fp"], 0)
        self.assertEqual(overall["counts"]["needs_review_total"], 3)
        self.assertEqual(overall["counts"]["fail_safe_review_overrides"], 3)

    def test_cli_end_to_end_with_fixture_flag(self) -> None:
        """Verify CLI entry point writes JSON and Markdown files marked as TEST FIXTURE."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            og_path = tmp / "opengrep_fixture.json"
            lb_path = tmp / "labels_fixture.json"
            tr_path = tmp / "triage_fixture.json"
            out_json = tmp / "out_report.json"
            out_md = tmp / "out_report.md"

            og_path.write_text(
                json.dumps([{"alert_id": "CLI-1", "file_path": "A.java", "start_line": 5, "cwe": "CWE-22"}]),
                encoding="utf-8",
            )
            lb_path.write_text(
                json.dumps([{"alert_id": "CLI-1", "file_path": "A.java", "cwe": "CWE-22", "ground_truth": "FALSE_POSITIVE"}]),
                encoding="utf-8",
            )
            tr_path.write_text(
                json.dumps([{
                    "alert_id": "CLI-1",
                    "cwe": "CWE-22",
                    "verdict": "FP",
                    "cited_lines": [5],
                    "rationale": "Validated against strict allowlist before file access.",
                    "latency_ms": 750.0,
                }]),
                encoding="utf-8",
            )

            rc = score_pilot.main([
                "--opengrep", str(og_path),
                "--labels", str(lb_path),
                "--triage", str(tr_path),
                "--output-json", str(out_json),
                "--output-md", str(out_md),
                "--fixture",
            ])
            self.assertEqual(rc, 0)
            saved_json = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertIn("TEST FIXTURE ONLY", saved_json.get("fixture_notice", ""))
            saved_md = out_md.read_text(encoding="utf-8")
            self.assertIn("SYNTHETIC TEST FIXTURE OUTPUT", saved_md)


if __name__ == "__main__":
    unittest.main()
