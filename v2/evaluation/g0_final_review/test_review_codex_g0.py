"""Counter-tests for the Codex G0 resolution logic and checks of the proposed stricter acceptance rule.

The Codex directory is read-only input (env NTK_CODEX_CROSSCHECK). If it is not readable, the tests are
skipped with an explicit reason; a skip is NOT a pass and must be reported as NOT_VERIFIED.
"""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import review_codex_g0 as rv  # noqa: E402

CX = rv.DEFAULT_CODEX_DIR
AVAILABLE = (CX / "resolve_g0.py").is_file()
REQUIRED_CODEX = ("transfer_integrity", "scan_development", "scan_heldout", "scan_manual",
                  "owasp_labels_and_sources", "heldout_published_comparison", "immutability")


@unittest.skipUnless(AVAILABLE, f"Codex crosscheck directory not readable: {CX} -> NOT_VERIFIED")
class CodexAcceptanceCounterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = rv.load_codex_module(CX, "resolve_g0")
        cls.verdict = json.loads((CX / "G0_RAW_INDEPENDENT_VERDICT.json").read_text("utf-8"))
        cls.resolution = json.loads((CX / "G0_FINAL_RESOLUTION.json").read_text("utf-8"))

    def test_00_reviewed_artifacts_are_pinned(self):
        for name, expected in rv.REVIEWED_CODEX_SHA256.items():
            self.assertEqual(rv.sha256_file(CX / name), expected, name)

    def test_01_published_inputs_do_not_reproduce_conditional(self):
        """Fed the criteria+register that ARE published, Codex acceptance() returns BLOCKED, while the
        resolution declares CONDITIONAL (computed from the unpublished audit.private.json)."""
        got = self.r.acceptance({"criteria": self.verdict["criteria"], "register": self.verdict["register"]},
                                {"rows_columns_equal": True})
        self.assertEqual(got, "BLOCKED")
        self.assertEqual(self.resolution["G0_ACCEPTANCE"], "CONDITIONAL")
        fails = {(x["criterion"], x["field"]) for x in self.verdict["register"] if x["status"] == "FAIL"}
        self.assertIn(("annotation_rationale", "annotator_rationale / sanitizer_or_reason"), fails)

    def test_02_heldout_arm_runs_are_not_required(self):
        """acceptance() stays CONDITIONAL when the held-out Arm C run itself could not be re-derived."""
        criteria = dict.fromkeys(REQUIRED_CODEX, "PASS")
        criteria["run_stage4_heldout40_armC_evidence_llm"] = "INCOMPLETE"
        criteria["heldout_aggregate_comparison"] = "INCOMPLETE"
        register = [{"criterion": "run_stage4_heldout40_armC_evidence_llm", "status": "INCOMPLETE",
                     "field": "missing_evidence", "actual": "FileNotFoundError: assessments.jsonl"}]
        self.assertEqual(self.r.acceptance({"criteria": criteria, "register": register},
                                           {"rows_columns_equal": True}), "CONDITIONAL")

    def test_03_raw_exit_code_and_missing_list_are_ignored(self):
        criteria = dict.fromkeys(REQUIRED_CODEX, "PASS")
        audit = {"criteria": criteria, "register": [], "exit_code": 3, "missing": ["x"] * 50}
        self.assertEqual(self.r.acceptance(audit, {"rows_columns_equal": True}), "CONDITIONAL")

    def test_04_any_fail_is_labelled_errata_issued(self):
        """classify() maps a ground-truth label FAIL to ERRATA_ISSUED with no errata check."""
        row = {"status": "FAIL", "criterion": "owasp_labels_and_sources", "field": "label.ground_truth",
               "actual": "FALSE_POSITIVE"}
        self.assertEqual(self.r.classify(row)[0], "ERRATA_ISSUED")

    def test_05_completion_axes_and_conditions_are_literals(self):
        fields = rv.hardcoded_report_fields((CX / "resolve_g0.py").read_text("utf-8"))
        for key in ("G0_AUDIT_COMPLETED", "axes", "conditions", "additional_review_rows", "git"):
            self.assertTrue(fields[key], key)
        self.assertFalse(fields["G0_ACCEPTANCE"])

    def test_06_two_published_acceptance_statements_disagree(self):
        self.assertEqual(self.verdict["g0_acceptance"], "INCOMPLETE")
        self.assertNotEqual(self.verdict["g0_acceptance"], self.resolution["G0_ACCEPTANCE"])

    def test_07_resolution_metrics_match_public_per_alert_csv(self):
        self.assertEqual(rv.consistency_with_public(self.resolution), [])

    def test_08_publication_scan_finds_user_paths_and_no_secrets(self):
        scan = rv.publication_scan(CX)
        self.assertEqual(scan["files"], 24)
        self.assertEqual(len(scan["absolute_user_paths"]), 11)
        self.assertEqual(scan["secret_like"], [])


@unittest.skipUnless(AVAILABLE, f"Codex crosscheck directory not readable: {CX} -> NOT_VERIFIED")
class ProposedAcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.verdict = json.loads((CX / "G0_RAW_INDEPENDENT_VERDICT.json").read_text("utf-8"))

    def test_09_published_verdict_still_conditional_with_derived_conditions(self):
        verdict, open_c, reasons = rv.proposed_acceptance(self.verdict["criteria"], self.verdict["register"], True)
        self.assertEqual((verdict, reasons), ("CONDITIONAL", []))
        for c in ("historical_configuration", "human_review_history", "manual_ground_truth",
                  "run_stage2_dev16_baseline_v1_0"):
            self.assertIn(c, open_c)

    def test_10_counterexamples_are_blocked(self):
        base_c, base_r = self.verdict["criteria"], self.verdict["register"]
        c = dict(base_c, run_stage4_heldout40_armC_evidence_llm="INCOMPLETE")
        self.assertEqual(rv.proposed_acceptance(c, base_r, True)[0], "BLOCKED")
        r = base_r + [{"criterion": "owasp_labels_and_sources", "status": "FAIL", "field": "label.ground_truth"}]
        self.assertEqual(rv.proposed_acceptance(base_c, r, True)[0], "BLOCKED")
        r = base_r + [{"criterion": "heldout_aggregate_comparison", "status": "INCOMPLETE",
                       "field": "missing_evidence", "actual": "C/ALL: fp_correctly_proposed missing"}]
        self.assertEqual(rv.proposed_acceptance(base_c, r, True)[0], "BLOCKED")
        self.assertEqual(rv.proposed_acceptance(base_c, base_r, False)[0], "BLOCKED")
        c = copy.deepcopy(base_c); c.pop("immutability")
        self.assertEqual(rv.proposed_acceptance(c, base_r, True)[0], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
