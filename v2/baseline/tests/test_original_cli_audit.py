"""Negative audit fixtures; these are not model or engine runtime evidence."""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
from audit_original_cli import LABELS, audit, main, verify_commands
from prove_original_cli import sha
from verify_handoff import verify


class AuditTests(unittest.TestCase):
    def commands(self, root):
        commands = []
        for label in sorted(LABELS):
            command = {"label": label, "argv": ["UNIT"], "exit": 0, "timed_out": False}
            for stream in ("stdout", "stderr"):
                data = (label + stream).encode()
                (root / (label + "." + stream + ".txt")).write_bytes(data)
                command[stream + "_sha256"] = sha(data)
            commands.append(command)
        return commands

    def test_command_receipts_require_complete_successful_unmodified_logs(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            commands = self.commands(root)
            self.assertEqual(len(verify_commands(root, commands)), 4)
            for field, value in (("exit", 1), ("exit", False), ("timed_out", True),
                                 ("stdout_sha256", "wrong"), ("argv", "not argv")):
                wrong = copy.deepcopy(commands)
                wrong[0][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    verify_commands(root, wrong)
            for wrong in (None, commands[:-1], [commands[0]] * 4):
                with self.assertRaises(ValueError):
                    verify_commands(root, wrong)
            log = root / (commands[0]["label"] + ".stderr.txt")
            log.unlink()
            with self.assertRaises(OSError):
                verify_commands(root, commands)

    def test_missing_invalid_or_wrong_commit_proof_fails_without_rewriting(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            with self.assertRaises(OSError):
                audit(root)
            for content in (b"{", b"[]", json.dumps({"upstream_commit": "wrong"}).encode()):
                (root / "proof.json").write_bytes(content)
                with self.assertRaises(ValueError):
                    audit(root)
                self.assertEqual((root / "proof.json").read_bytes(), content)

    def test_cli_failure_has_nonzero_exit_and_output_cannot_overwrite_evidence(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            with patch.object(sys, "argv", ["audit", str(root)]), patch("builtins.print"):
                self.assertEqual(main(), 2)
            with patch.object(sys, "argv", ["audit", str(root), "--output", str(root / "proof.json")]), \
                 patch("audit_original_cli.audit") as runner, patch("builtins.print"):
                self.assertEqual(main(), 2)
                runner.assert_not_called()
            self.assertFalse((root / "proof.json").exists())

    def test_handoff_rejects_changed_identity_trace_and_source_provenance(self):
        # Minimal synthetic handoff; no scan is claimed for this fixture.
        finding = {"check_id": "unit.rule", "path": "Unit.java", "start": {"line": 1, "col": 1},
                   "end": {"line": 1, "col": 5}, "extra": {"dataflow_trace": {"UNIT": "trace"}}}
        raw = json.dumps({"results": [finding], "errors": []}).encode()
        scan_sha = sha(raw)
        sarif = {"runs": [{"results": [{"ruleId": "unit.rule", "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "Unit.java"},
            "region": {"startLine": 1, "startColumn": 1, "endLine": 1, "endColumn": 5}}}]}]}]}
        record = {"finding_index": 0, "id": sha((scan_sha + ":0").encode()), "raw_finding": finding,
                  "rule_id": "unit.rule", "raw_trace": finding["extra"]["dataflow_trace"], "issues": []}
        bundle = {"scan_sha256": scan_sha, "issues": [], "scan_provenance": {"source_capture_verified": True},
                  "records": [record]}
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            engine, triage = root / "engine", root / "triage"
            engine.mkdir()
            triage.mkdir()
            (engine / "opengrep.json").write_bytes(raw)
            (engine / "opengrep.sarif").write_text(json.dumps(sarif))
            (triage / "input.opengrep.json").write_bytes(raw)
            evidence = triage / "evidence.json"
            evidence.write_text(json.dumps(bundle))
            self.assertEqual(verify(engine, triage, write_report=False)["status"], "PASS")
            self.assertFalse((triage / "handoff-verification.json").exists())
            for field, value in (("id", "wrong"), ("finding_index", False), ("rule_id", "wrong"),
                                 ("raw_trace", None), ("issues", ["UNIT missing trace"])):
                changed = copy.deepcopy(bundle)
                changed["records"][0][field] = value
                evidence.write_text(json.dumps(changed))
                with self.subTest(field=field), self.assertRaises(ValueError):
                    verify(engine, triage, write_report=False)
            changed = copy.deepcopy(bundle)
            changed["scan_provenance"]["source_capture_verified"] = False
            evidence.write_text(json.dumps(changed))
            with self.assertRaises(ValueError):
                verify(engine, triage, write_report=False)
            evidence.write_text("{")
            with self.assertRaises(ValueError):
                verify(engine, triage, write_report=False)
