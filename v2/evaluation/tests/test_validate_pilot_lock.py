"""Unit tests for v2/evaluation/validate_pilot_lock.py.

ALL DATA IN THIS FILE IS A SYNTHETIC TEST FIXTURE ("TEST_FIXTURE_ONLY").
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import score_pilot  # noqa: E402
import validate_pilot_lock  # noqa: E402


class TestValidatePilotLockAndGrounding(unittest.TestCase):
    """Tests M4 STRICT_LOCK vs SMOKE validation and M3 Java source grounding checks."""

    def test_smoke_mode_vs_strict_lock_on_small_fixture(self) -> None:
        """Verify small fixture passes in SMOKE mode (m4_acceptance_ready=False) but fails STRICT_LOCK."""
        fixtures_dir = Path(__file__).resolve().parents[1] / "fixtures"
        og_path = fixtures_dir / "opengrep_alerts.fixture.json"
        lb_path = fixtures_dir / "ground_truth_labels.fixture.json"

        og_data = json.loads(og_path.read_text(encoding="utf-8"))
        lb_data = json.loads(lb_path.read_text(encoding="utf-8"))

        # 1. Must FAIL in STRICT_LOCK (only 6 alerts < 30, priority share 66.7% < 70%, has fixture marker)
        strict_res = validate_pilot_lock.validate_pilot_dataset(
            og_data, lb_data, mode="STRICT_LOCK"
        )
        self.assertFalse(strict_res["valid_lock_candidate"])
        self.assertFalse(strict_res["m4_acceptance_ready"])
        self.assertGreaterEqual(len(strict_res["errors"]), 3)

        # 2. Must PASS in SMOKE mode with explicit bounds, but m4_acceptance_ready MUST remain False
        smoke_res = validate_pilot_lock.validate_pilot_dataset(
            og_data,
            lb_data,
            min_alerts=1,
            max_alerts=10,
            min_priority_share=0.5,
            mode="SMOKE",
        )
        self.assertTrue(smoke_res["valid_lock_candidate"])
        self.assertFalse(smoke_res["m4_acceptance_ready"])
        self.assertEqual(smoke_res["lock_mode"], "SMOKE")

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            og_copy = tmp / "opengrep.json"
            lb_copy = tmp / "labels.json"
            og_copy.write_bytes(og_path.read_bytes())
            lb_copy.write_bytes(lb_path.read_bytes())

            manifest = validate_pilot_lock.create_lock_manifest(
                og_copy, lb_copy, mode="SMOKE", m4_acceptance_ready=False
            )
            self.assertFalse(manifest["m4_acceptance_ready"])
            ok, errs = validate_pilot_lock.verify_lock_manifest(manifest, og_copy, lb_copy)
            self.assertTrue(ok)
            self.assertEqual(errs, [])

            # Smoke manifest must be rejected if someone tries to use it for M4 acceptance
            ok_m4, errs_m4 = validate_pilot_lock.verify_lock_manifest(
                manifest, og_copy, lb_copy, require_m4_acceptance=True
            )
            self.assertFalse(ok_m4)
            self.assertTrue(any("SMOKE/FIXTURE" in e for e in errs_m4))

            # Simulate post-lock tampering of labels.json (forbidden test-set tuning)
            lb_copy.write_text(lb_copy.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            ok_after, errs_after = validate_pilot_lock.verify_lock_manifest(manifest, og_copy, lb_copy)
            self.assertFalse(ok_after)
            self.assertGreaterEqual(len(errs_after), 2)

    def test_strict_lock_accepts_compliant_30_alert_dataset_and_rejects_under_minimum(self) -> None:
        """Verify STRICT_LOCK enforces 30-60 size, >=70% CWE-22/89 share, 64-hex SHA, and annotator."""
        valid_sha = "a" * 64
        alerts = []
        labels = []
        # Create 30 alerts: 24 CWE-22/89 (80% >= 70%) and 6 CWE-78/79 (20%)
        for i in range(30):
            cwe = "CWE-22" if i < 12 else ("CWE-89" if i < 24 else "CWE-78")
            aid = f"REAL-CANDIDATE-{i:02d}"
            fpath = f"src/main/java/app/Service{i:02d}.java"
            alerts.append({
                "alert_id": aid,
                "file_path": fpath,
                "start_line": 10 + i,
                "end_line": 12 + i,
                "rule_id": f"java.rule.{cwe.lower()}",
                "cwe": cwe,
                "source_sha256": valid_sha,
            })
            labels.append({
                "alert_id": aid,
                "file_path": fpath,
                "cwe": cwe,
                "ground_truth": "TRUE_POSITIVE" if i % 2 == 0 else "FALSE_POSITIVE",
                "annotator_rationale": "Verified taint flow from servlet parameter to sink at line 11.",
                "annotated_by": "student-independent-annotator",
                "source_sha256": valid_sha,
            })

        res_ok = validate_pilot_lock.validate_pilot_dataset(alerts, labels, mode="STRICT_LOCK")
        self.assertTrue(res_ok["valid_lock_candidate"], msg=f"Unexpected errors: {res_ok['errors']}")
        self.assertTrue(res_ok["m4_acceptance_ready"])
        self.assertEqual(res_ok["total_unique_alerts"], 30)
        self.assertAlmostEqual(res_ok["priority_cwe_share"], 0.80)

        # Now drop to 29 alerts -> must fail STRICT_LOCK minimum size check
        res_too_small = validate_pilot_lock.validate_pilot_dataset(
            alerts[:29], labels[:29], mode="STRICT_LOCK"
        )
        self.assertFalse(res_too_small["valid_lock_candidate"])
        self.assertFalse(res_too_small["m4_acceptance_ready"])
        self.assertTrue(
            any("outside required pilot window [30, 60]" in e for e in res_too_small["errors"])
        )

    def test_source_grounding_catches_comment_lines_and_sha_mismatch(self) -> None:
        """Verify M3 source grounding checks line bounds, comment-only lines, and SHA-256."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            java_file = root / "src" / "DemoDao.java"
            java_file.parent.mkdir(parents=True, exist_ok=True)
            java_source = "\n".join([
                "package demo;",
                "// Line 2 is a comment only",
                "public class DemoDao {",
                "    public void query(String id) {",
                "        PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM t WHERE id=?\");",
                "        ps.setString(1, id);",
                "    }",
                "}",
            ])
            java_file.write_text(java_source, encoding="utf-8")
            sha = score_pilot.compute_sha256_text(java_source)

            alerts = [
                {"alert_id": "G-OK", "file_path": "src/DemoDao.java", "start_line": 5, "cwe": "CWE-89", "source_sha256": sha},
                {"alert_id": "G-COMMENT", "file_path": "src/DemoDao.java", "start_line": 5, "cwe": "CWE-89", "source_sha256": sha},
                {"alert_id": "G-SHA", "file_path": "src/DemoDao.java", "start_line": 5, "cwe": "CWE-89", "source_sha256": sha},
            ]
            triage = [
                {"alert_id": "G-OK", "cited_lines": [5, 6], "source_sha256": sha},
                {"alert_id": "G-COMMENT", "cited_lines": [2], "source_sha256": sha},
                {"alert_id": "G-SHA", "cited_lines": [5], "source_sha256": "0" * 64},
            ]

            res = validate_pilot_lock.verify_source_grounding(root, alerts, triage)
            self.assertFalse(res["grounding_pass"])
            self.assertEqual(res["verified_grounded_records"], 1)
            v_types = {v["type"] for v in res["violations"]}
            self.assertEqual(v_types, {"cited_line_blank_or_comment", "source_sha256_mismatch"})


if __name__ == "__main__":
    unittest.main()
