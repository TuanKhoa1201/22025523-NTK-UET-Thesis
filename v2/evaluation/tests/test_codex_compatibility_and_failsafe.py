"""Unit tests for P0 & P1 Codex Schema Compatibility, Fail-Safe Grounding, and Lock Rules.

ALL DATA IN THIS FILE IS A SYNTHETIC TEST FIXTURE ("TEST_FIXTURE_ONLY").
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import codex_adapter  # noqa: E402
import score_pilot  # noqa: E402
import validate_pilot_lock  # noqa: E402


class TestCodexCompatibilityAndFailSafes(unittest.TestCase):
    """Covers all 9 required P1 test scenarios for Codex integration and fail-safe gates."""

    def setUp(self) -> None:
        self.java_code_cwe22 = "\n".join([
            "package com.example.web;",
            "import java.io.File;",
            "import java.nio.file.Path;",
            "public class FileService {",
            "    private static final Path BASE = Path.of(\"/var/app/data\");",
            "    public File getSafeFile(String userInput) {",
            "        Path resolved = BASE.resolve(userInput).normalize();",
            "        if (!resolved.startsWith(BASE)) {",
            "            throw new SecurityException(\"Path traversal blocked\");",
            "        }",
            "        return resolved.toFile();",
            "    }",
            "}",
        ])
        self.sha_cwe22 = score_pilot.compute_sha256_text(self.java_code_cwe22)

        self.java_code_cwe89 = "\n".join([
            "package com.example.dao;",
            "import java.sql.*;",
            "public class UserDao {",
            "    public ResultSet findUser(Connection conn, String username) throws SQLException {",
            "        String sql = \"SELECT * FROM users WHERE username = '\" + username + \"'\";",
            "        Statement stmt = conn.createStatement();",
            "        return stmt.executeQuery(sql);",
            "    }",
            "}",
        ])
        self.sha_cwe89 = score_pilot.compute_sha256_text(self.java_code_cwe89)

    def test_1_codex_nested_schema_conversion(self) -> None:
        """1. Chuyển đổi đúng schema Codex (SUPPORTED->KEEP_TP, REFUTED->PROPOSED_FP, UNDETERMINED->REVIEW)."""
        opengrep_scan = {
            "results": [
                {
                    "check_id": "java.path.traversal",
                    "path": "src/com/example/web/FileService.java",
                    "start": {"line": 7, "col": 9},
                    "end": {"line": 11, "col": 34},
                    "extra": {"metadata": {"cwe": ["CWE-22: Path Traversal"]}},
                    "source_sha256": self.sha_cwe22,
                },
                {
                    "check_id": "java.sql.sqli",
                    "path": "src/com/example/dao/UserDao.java",
                    "start": {"line": 5, "col": 9},
                    "end": {"line": 7, "col": 38},
                    "extra": {"metadata": {"cwe": ["CWE-89: SQL Injection"]}},
                    "source_sha256": self.sha_cwe89,
                },
                {
                    "check_id": "java.lang.cmdi",
                    "path": "src/com/example/cmd/Runner.java",
                    "start": {"line": 15, "col": 5},
                    "end": {"line": 16, "col": 20},
                    "extra": {"metadata": {"cwe": ["CWE-78: OS Command Injection"]}},
                    "source_sha256": "c" * 64,
                },
            ]
        }
        alerts = score_pilot._extract_opengrep_alerts(opengrep_scan)
        labels = [
            {
                "alert_id": alerts[0]["alert_id"],
                "file_path": "src/com/example/web/FileService.java",
                "cwe": "CWE-22",
                "ground_truth": "FALSE_POSITIVE",
                "annotator_rationale": "Normalized path checked with startsWith(BASE).",
                "annotated_by": "human-sec-reviewer",
                "source_sha256": self.sha_cwe22,
            },
            {
                "alert_id": alerts[1]["alert_id"],
                "file_path": "src/com/example/dao/UserDao.java",
                "cwe": "CWE-89",
                "ground_truth": "TRUE_POSITIVE",
                "annotator_rationale": "Direct string concatenation of username in SQL query.",
                "annotated_by": "human-sec-reviewer",
                "source_sha256": self.sha_cwe89,
            },
            {
                "alert_id": alerts[2]["alert_id"],
                "file_path": "src/com/example/cmd/Runner.java",
                "cwe": "CWE-78",
                "ground_truth": "TRUE_POSITIVE",
                "annotator_rationale": "Command execution with external argument.",
                "annotated_by": "human-sec-reviewer",
                "source_sha256": "c" * 64,
            },
        ]

        # Codex assessments.jsonl format with totally different `id` values
        codex_jsonl = "\n".join([
            json.dumps({
                "id": "codex-uuid-1001",
                "evidence": {
                    "raw_finding": opengrep_scan["results"][0],
                    "cwe": ["CWE-22: Improper Limitation of a Pathname"],
                    "snapshots": [{
                        "path": "src/com/example/web/FileService.java",
                        "sha256": self.sha_cwe22,
                        "content": self.java_code_cwe22,
                    }],
                    "snippets": [{"start_line": 6, "end_line": 12, "content": "\n".join(self.java_code_cwe22.splitlines()[5:12])}],
                },
                "assessment": {
                    "status": "REFUTED",
                    "citations": [{"path": "src/com/example/web/FileService.java", "line": 7}, {"line": 8}],
                    "explanation": "Path is normalized at line 7 and strictly checked with startsWith(BASE) at line 8.",
                    "latency_ms": 1350.0,
                },
            }),
            json.dumps({
                "id": "codex-uuid-1002",
                "evidence": {
                    "raw_finding": opengrep_scan["results"][1],
                    "cwe": ["CWE-89: SQL Injection"],
                    "snapshots": [{
                        "path": "src/com/example/dao/UserDao.java",
                        "sha256": self.sha_cwe89,
                        "content": self.java_code_cwe89,
                    }],
                },
                "assessment": {
                    "status": "SUPPORTED",
                    "citations": ["src/com/example/dao/UserDao.java:5", "L7"],
                    "explanation": "Unvalidated username is concatenated into SQL query at line 5 and executed at line 7.",
                    "latency_ms": 1120.0,
                },
            }),
            json.dumps({
                "id": "codex-uuid-1003",
                "evidence": {
                    "raw_finding": opengrep_scan["results"][2],
                    "cwe": ["CWE-78"],
                },
                "assessment": {
                    "status": "UNDETERMINED",
                    "citations": [],
                    "explanation": "Insufficient context to trace caller arguments.",
                    "latency_ms": 890.0,
                },
            }),
        ])

        report = score_pilot.evaluate_pilot(opengrep_scan, labels, codex_jsonl)
        overall = report["summary"]["overall"]
        self.assertEqual(overall["counts"]["total_alerts"], 3)
        self.assertEqual(overall["counts"]["proposed_fp_on_true_fp"], 1)
        self.assertEqual(overall["counts"]["kept_tp_on_true_tp"], 1)
        self.assertEqual(overall["counts"]["needs_review_total"], 1)
        self.assertEqual(overall["rates"]["erroneous_tp_removal"]["display"], "0/2 (0.0%)")

    def test_2_deterministic_id_matching_and_mismatch_rejection(self) -> None:
        """2. Ghép đúng/sai ID: không đoán mò khi không khớp hoặc khi trùng lặp mơ hồ."""
        opengrep_scan = {
            "results": [
                {
                    "check_id": "java.sql.sqli",
                    "path": "src/Dao.java",
                    "start": {"line": 10, "col": 5},
                    "end": {"line": 12, "col": 20},
                    "extra": {"metadata": {"cwe": "CWE-89"}},
                    "source_sha256": self.sha_cwe89,
                },
                # Identical location/rule/CWE without col difference to test ambiguity guard
                {
                    "check_id": "java.sql.sqli",
                    "path": "src/AmbiguousDao.java",
                    "start": {"line": 30, "col": 5},
                    "end": {"line": 32, "col": 20},
                    "extra": {"metadata": {"cwe": "CWE-89"}},
                    "source_sha256": self.sha_cwe89,
                },
                {
                    "check_id": "java.sql.sqli",
                    "path": "src/AmbiguousDao.java",
                    "start": {"line": 30, "col": 5},
                    "end": {"line": 32, "col": 20},
                    "extra": {"metadata": {"cwe": "CWE-89"}},
                    "source_sha256": self.sha_cwe89,
                },
            ]
        }

        codex_records = [
            # Unmatched file/line (does not exist in OpenGrep scan)
            {
                "id": "codex-unmatched",
                "evidence": {
                    "raw_finding": {
                        "check_id": "java.sql.sqli",
                        "path": "src/NonExistent.java",
                        "start": {"line": 99},
                        "end": {"line": 100},
                        "extra": {"metadata": {"cwe": "CWE-89"}},
                    }
                },
                "assessment": {"status": "SUPPORTED", "citations": [99], "explanation": "Unmatched finding."},
            },
            # Ambiguous finding without finding_index disambiguation
            {
                "id": "codex-ambiguous",
                "evidence": {
                    "raw_finding": {
                        "check_id": "java.sql.sqli",
                        "path": "src/AmbiguousDao.java",
                        "start": {"line": 30, "col": 5},
                        "end": {"line": 32, "col": 20},
                        "extra": {"metadata": {"cwe": "CWE-89"}},
                    }
                },
                "assessment": {"status": "REFUTED", "citations": [30], "explanation": "Ambiguous match must fail safe."},
            },
        ]

        report = score_pilot.evaluate_pilot(opengrep_scan, [], codex_records)
        unmatched = report["anomalies"]["unmatched_or_ambiguous_triage_records"]
        self.assertEqual(len(unmatched), 2)
        # All 3 OpenGrep alerts must fail-safe to REVIEW
        self.assertEqual(report["summary"]["overall"]["counts"]["needs_review_total"], 3)

    def test_3_wrong_or_missing_sha256_blocks_refuted_fp(self) -> None:
        """3. Hash sai hoặc thiếu: REFUTED bị chặn và chuyển về REVIEW."""
        opengrep_scan = [
            {"alert_id": "SHA-MISSING", "file_path": "src/FileService.java", "start_line": 7, "cwe": "CWE-22", "source_sha256": self.sha_cwe22},
            {"alert_id": "SHA-WRONG", "file_path": "src/FileService.java", "start_line": 8, "cwe": "CWE-22", "source_sha256": self.sha_cwe22},
        ]
        labels = [
            {"alert_id": "SHA-MISSING", "file_path": "src/FileService.java", "cwe": "CWE-22", "ground_truth": "FALSE_POSITIVE", "source_sha256": self.sha_cwe22},
            {"alert_id": "SHA-WRONG", "file_path": "src/FileService.java", "cwe": "CWE-22", "ground_truth": "FALSE_POSITIVE", "source_sha256": self.sha_cwe22},
        ]
        codex_records = [
            {
                "alert_id": "SHA-MISSING",
                "evidence": {
                    "file_path": "src/FileService.java",
                    "cwe": ["CWE-22"],
                    # No sha256 provided in evidence or snapshot!
                    "snippets": [{"start_line": 1, " lines": self.java_code_cwe22.splitlines()}],
                },
                "assessment": {
                    "status": "REFUTED",
                    "citations": [7, 8],
                    "explanation": "Path is normalized and checked with startsWith.",
                },
            },
            {
                "alert_id": "SHA-WRONG",
                "evidence": {
                    "file_path": "src/FileService.java",
                    "cwe": ["CWE-22"],
                    "snapshots": [{"path": "src/FileService.java", "sha256": "f" * 64, "content": "// modified file"}],
                },
                "assessment": {
                    "status": "REFUTED",
                    "citations": [7, 8],
                    "explanation": "Path is normalized and checked with startsWith.",
                },
            },
        ]

        report = score_pilot.evaluate_pilot(opengrep_scan, labels, codex_records)
        self.assertEqual(len(report["anomalies"]["sha256_mismatches"]), 2)
        self.assertEqual(report["summary"]["overall"]["counts"]["proposed_fp_on_true_fp"], 0)
        self.assertEqual(report["summary"]["overall"]["counts"]["needs_review_total"], 2)

    def test_4_refuted_with_nonexistent_or_comment_citation_overridden_to_review(self) -> None:
        """4. Qwen trả REFUTED nhưng trích dẫn không tồn tại trong file/snapshot thực tế -> REVIEW."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            java_path = root / "src" / "com" / "example" / "web" / "FileService.java"
            java_path.parent.mkdir(parents=True, exist_ok=True)
            java_path.write_text(self.java_code_cwe22, encoding="utf-8")

            opengrep_scan = [{
                "alert_id": "CITE-NONEXISTENT",
                "file_path": "src/com/example/web/FileService.java",
                "start_line": 7,
                "end_line": 11,
                "cwe": "CWE-22",
                "source_sha256": self.sha_cwe22,
            }]
            labels = [{
                "alert_id": "CITE-NONEXISTENT",
                "file_path": "src/com/example/web/FileService.java",
                "cwe": "CWE-22",
                "ground_truth": "FALSE_POSITIVE",
                "source_sha256": self.sha_cwe22,
            }]
            # FileService.java only has 13 lines, but LLM cites line 45 (and context_start/end is omitted!)
            codex_records = [{
                "alert_id": "CITE-NONEXISTENT",
                "evidence": {
                    "file_path": "src/com/example/web/FileService.java",
                    "cwe": ["CWE-22"],
                    "source_sha256": self.sha_cwe22,
                },
                "assessment": {
                    "status": "REFUTED",
                    "citations": [45],
                    "explanation": "Hallucinated sanitizer at line 45 that does not exist in FileService.java.",
                },
            }]

            report = score_pilot.evaluate_pilot(
                opengrep_scan, labels, codex_records, source_root=root
            )
            self.assertEqual(len(report["anomalies"]["missing_or_invalid_citations"]), 1)
            self.assertEqual(len(report["anomalies"]["ungrounded_fp_overrides"]), 1)
            self.assertEqual(report["summary"]["overall"]["counts"]["proposed_fp_on_true_fp"], 0)
            self.assertEqual(report["summary"]["overall"]["counts"]["needs_review_total"], 1)

    def test_5_model_concludes_wrong_cwe(self) -> None:
        """5. Mô hình kết luận sai CWE -> bị chặn và chuyển về REVIEW."""
        opengrep_scan = [{
            "alert_id": "WRONG-CWE-1",
            "file_path": "src/com/example/web/FileService.java",
            "start_line": 7,
            "cwe": "CWE-22",
            "source_sha256": self.sha_cwe22,
        }]
        labels = [{
            "alert_id": "WRONG-CWE-1",
            "file_path": "src/com/example/web/FileService.java",
            "cwe": "CWE-22",
            "ground_truth": "FALSE_POSITIVE",
            "source_sha256": self.sha_cwe22,
        }]
        codex_records = [{
            "alert_id": "WRONG-CWE-1",
            "evidence": {
                "file_path": "src/com/example/web/FileService.java",
                "cwe": ["CWE-89"],  # Wrong CWE in evidence/assessment!
                "snapshots": [{"path": "src/com/example/web/FileService.java", "sha256": self.sha_cwe22, "content": self.java_code_cwe22}],
            },
            "assessment": {
                "status": "REFUTED",
                "cwe": "CWE-89",
                "citations": [7, 8],
                "explanation": "Claims no SQL injection, ignoring that the alert is CWE-22 Path Traversal.",
            },
        }]

        report = score_pilot.evaluate_pilot(opengrep_scan, labels, codex_records)
        self.assertGreaterEqual(len(report["anomalies"]["cwe_mismatches"]), 1)
        self.assertEqual(report["summary"]["overall"]["counts"]["proposed_fp_on_true_fp"], 0)
        self.assertEqual(report["summary"]["overall"]["counts"]["needs_review_total"], 1)

    def test_6_no_ground_truth_and_reject_auto_generated_labels(self) -> None:
        """6. Không có ground truth (hoặc cố dùng output Qwen làm nhãn) -> tỷ lệ lọc = 0/0 (N/A), không tự nhận đúng."""
        opengrep_scan = [{
            "alert_id": "NO-GT-1",
            "file_path": "src/com/example/web/FileService.java",
            "start_line": 7,
            "cwe": "CWE-22",
            "source_sha256": self.sha_cwe22,
        }]
        codex_records = [{
            "alert_id": "NO-GT-1",
            "evidence": {
                "file_path": "src/com/example/web/FileService.java",
                "cwe": ["CWE-22"],
                "snapshots": [{"path": "src/com/example/web/FileService.java", "sha256": self.sha_cwe22, "content": self.java_code_cwe22}],
            },
            "assessment": {
                "status": "REFUTED",
                "citations": [7, 8],
                "explanation": "Path is normalized and checked with startsWith(BASE).",
            },
        }]

        # Attempt to pass Qwen/Codex output as ground truth labels -> must be rejected!
        fake_auto_labels = [{
            "alert_id": "NO-GT-1",
            "file_path": "src/com/example/web/FileService.java",
            "cwe": "CWE-22",
            "ground_truth": "FALSE_POSITIVE",
            "annotated_by": "qwen3.5:9b-q4_K_M",
        }]

        report = score_pilot.evaluate_pilot(opengrep_scan, fake_auto_labels, codex_records)
        self.assertEqual(len(report["anomalies"]["rejected_auto_generated_labels"]), 1)
        overall = report["summary"]["overall"]
        self.assertEqual(overall["counts"]["unlabeled_alerts"], 1)
        self.assertEqual(overall["counts"]["grounding_verified_fp_proposals"], 1)
        # Without valid independent ground truth, true_fp_correctly_proposed_for_removal MUST be 0/0 (N/A)
        self.assertEqual(overall["rates"]["proposed_fp_removal"]["display"], "0/0 (N/A)")
        self.assertIsNone(overall["rates"]["proposed_fp_removal"]["rate"])
        self.assertEqual(overall["rates"]["erroneous_tp_removal"]["display"], "0/0 (N/A)")

    def test_7_benchmark_below_minimum_size_rejected_by_strict_lock(self) -> None:
        """7. Tập benchmark thiếu số lượng tối thiểu (<30) hoặc thiếu tỷ trọng CWE ưu tiên (<70%) bị chặn ở STRICT_LOCK."""
        sha = "b" * 64
        small_alerts = [
            {"alert_id": f"A-{i}", "file_path": "src/A.java", "start_line": i + 1, "cwe": "CWE-22", "source_sha256": sha}
            for i in range(10)
        ]
        small_labels = [
            {
                "alert_id": f"A-{i}",
                "file_path": "src/A.java",
                "cwe": "CWE-22",
                "ground_truth": "TRUE_POSITIVE",
                "annotator_rationale": "Verified taint flow to file sink.",
                "annotated_by": "human-reviewer",
                "source_sha256": sha,
            }
            for i in range(10)
        ]
        res = validate_pilot_lock.validate_pilot_dataset(small_alerts, small_labels, mode="STRICT_LOCK")
        self.assertFalse(res["valid_lock_candidate"])
        self.assertFalse(res["m4_acceptance_ready"])
        self.assertTrue(any("outside required pilot window [30, 60]" in e for e in res["errors"]))

    def test_8_erroneously_proposed_tp_removal_tracked_with_numerator_denominator(self) -> None:
        """8. Một cảnh báo TP bị đề xuất lọc nhầm (REFUTED) luôn hiển thị rõ tử số và mẫu số."""
        opengrep_scan = [{
            "alert_id": "TP-DROPPED-1",
            "file_path": "src/com/example/dao/UserDao.java",
            "start_line": 5,
            "cwe": "CWE-89",
            "source_sha256": self.sha_cwe89,
        }]
        labels = [{
            "alert_id": "TP-DROPPED-1",
            "file_path": "src/com/example/dao/UserDao.java",
            "cwe": "CWE-89",
            "ground_truth": "TRUE_POSITIVE",
            "annotator_rationale": "Exploitable SQLi via string concatenation.",
            "annotated_by": "human-reviewer",
            "source_sha256": self.sha_cwe89,
        }]
        codex_records = [{
            "alert_id": "TP-DROPPED-1",
            "evidence": {
                "file_path": "src/com/example/dao/UserDao.java",
                "cwe": ["CWE-89"],
                "snapshots": [{"path": "src/com/example/dao/UserDao.java", "sha256": self.sha_cwe89, "content": self.java_code_cwe89}],
            },
            "assessment": {
                "status": "REFUTED",
                "citations": [5, 6],
                "explanation": "Model falsely claims statement is safe despite raw string concatenation.",
            },
        }]

        report = score_pilot.evaluate_pilot(opengrep_scan, labels, codex_records)
        err_tp = report["summary"]["overall"]["rates"]["erroneous_tp_removal"]
        self.assertEqual(err_tp["numerator"], 1)
        self.assertEqual(err_tp["denominator"], 1)
        self.assertEqual(err_tp["display"], "1/1 (100.0%)")

    def test_9_retain_all_alerts_for_human_confirmation_and_block_auto_dismiss(self) -> None:
        """9. Giữ mọi cảnh báo chờ con người xác nhận; auto_dismissed=True bị đánh dấu vi phạm."""
        opengrep_scan = [{
            "alert_id": "HUMAN-GATE-1",
            "file_path": "src/com/example/web/FileService.java",
            "start_line": 7,
            "cwe": "CWE-22",
            "source_sha256": self.sha_cwe22,
        }]
        labels = [{
            "alert_id": "HUMAN-GATE-1",
            "file_path": "src/com/example/web/FileService.java",
            "cwe": "CWE-22",
            "ground_truth": "FALSE_POSITIVE",
            "annotator_rationale": "Normalized path checked with startsWith.",
            "annotated_by": "human-reviewer",
            "source_sha256": self.sha_cwe22,
        }]
        codex_records = [{
            "alert_id": "HUMAN-GATE-1",
            "evidence": {
                "file_path": "src/com/example/web/FileService.java",
                "cwe": ["CWE-22"],
                "snapshots": [{"path": "src/com/example/web/FileService.java", "sha256": self.sha_cwe22, "content": self.java_code_cwe22}],
            },
            "assessment": {
                "status": "REFUTED",
                "citations": [7, 8],
                "explanation": "Normalized path checked with startsWith.",
            },
        }]

        report = score_pilot.evaluate_pilot(opengrep_scan, labels, codex_records)
        arm_b = report["arms"]["arm_b_opengrep_plus_qwen"]
        self.assertEqual(arm_b["auto_dismissed_alerts"], 0)
        self.assertEqual(arm_b["alerts_retained_pending_human_confirmation"], 1)
        decision = report["per_alert_decisions"][0]
        self.assertTrue(decision["proposal_only"])
        self.assertTrue(decision["requires_human_confirmation"])
        self.assertTrue(decision["retained_for_human_review"])


if __name__ == "__main__":
    unittest.main()
