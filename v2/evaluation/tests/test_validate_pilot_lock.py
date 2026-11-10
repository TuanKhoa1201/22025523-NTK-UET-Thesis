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
    """Tests M4 pilot lock validation and M3 Java source grounding checks."""

    def test_validate_fixture_files_and_lock_manifest_tamper_detection(self) -> None:
        """Verify lock manifest creation and detection of post-lock file modification."""
        fixtures_dir = Path(__file__).resolve().parents[1] / "fixtures"
        og_path = fixtures_dir / "opengrep_alerts.fixture.json"
        lb_path = fixtures_dir / "ground_truth_labels.fixture.json"

        og_data = json.loads(og_path.read_text(encoding="utf-8"))
        lb_data = json.loads(lb_path.read_text(encoding="utf-8"))

        # Validate with fixture size bounds [1, 10]
        res = validate_pilot_lock.validate_pilot_dataset(
            og_data, lb_data, min_alerts=1, max_alerts=10, min_priority_share=0.5
        )
        self.assertTrue(res["valid_lock_candidate"])
        self.assertEqual(res["total_unique_alerts"], 6)
        self.assertEqual(res["priority_cwe_alerts"], 4)
        self.assertEqual(res["secondary_cwe_alerts"], 2)

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            og_copy = tmp / "opengrep.json"
            lb_copy = tmp / "labels.json"
            og_copy.write_bytes(og_path.read_bytes())
            lb_copy.write_bytes(lb_path.read_bytes())

            manifest = validate_pilot_lock.create_lock_manifest(og_copy, lb_copy)
            ok, errs = validate_pilot_lock.verify_lock_manifest(manifest, og_copy, lb_copy)
            self.assertTrue(ok)
            self.assertEqual(errs, [])

            # Simulate post-lock tampering of labels.json (forbidden test-set tuning)
            lb_copy.write_text(lb_copy.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            ok_after, errs_after = validate_pilot_lock.verify_lock_manifest(manifest, og_copy, lb_copy)
            self.assertFalse(ok_after)
            self.assertGreaterEqual(len(errs_after), 2)

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
                {"alert_id": "G-SHA", "cited_lines": [5], "source_sha256": "wrong_sha_hash"},
            ]

            res = validate_pilot_lock.verify_source_grounding(root, alerts, triage)
            self.assertFalse(res["grounding_pass"])
            self.assertEqual(res["verified_grounded_records"], 1)
            v_types = {v["type"] for v in res["violations"]}
            self.assertEqual(v_types, {"cited_line_blank_or_comment", "source_sha256_mismatch"})


if __name__ == "__main__":
    unittest.main()
