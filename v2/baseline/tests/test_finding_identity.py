"""Synthetic format checks, not new engine runtime evidence."""
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
from finding_identity import compare_findings
from prove_original_cli import run, validate_dependencies


class FindingIdentityTests(unittest.TestCase):
    def pair(self):
        raw = {"results": [{"check_id": "unit.cwe22", "path": "C:\\Code Space\\Demo.java",
                            "start": {"line": 7, "col": 9}, "end": {"line": 7, "col": 28}}]}
        sarif = {"runs": [{"results": [{"ruleId": "unit.cwe22", "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "file:///C:/Code%20Space/Demo.java"},
            "region": {"startLine": 7, "startColumn": 9, "endLine": 7, "endColumn": 28}}}]}]}]}
        return raw, sarif

    def test_same_rule_span_and_uri_path_match_without_mutation(self):
        raw, sarif = self.pair()
        original = copy.deepcopy((raw, sarif))
        self.assertTrue(compare_findings(raw, sarif)["rule_ids_and_locations_match"])
        self.assertEqual((raw, sarif), original)

    def test_equal_count_with_wrong_rule_is_rejected(self):
        raw, sarif = self.pair()
        sarif["runs"][0]["results"][0]["ruleId"] = "unit.other-rule"
        with self.assertRaises(ValueError):
            compare_findings(raw, sarif)

    def test_wrong_file_or_any_span_coordinate_is_rejected(self):
        for field, value in (("uri", "C:/Elsewhere/Demo.java"), ("startLine", 8), ("startColumn", 10),
                             ("endLine", 8), ("endColumn", 29)):
            raw, sarif = self.pair()
            physical = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
            if field == "uri":
                physical["artifactLocation"][field] = value
            else:
                physical["region"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                compare_findings(raw, sarif)

    def test_duplicate_multiplicity_cannot_hide_missing_finding(self):
        raw, sarif = self.pair()
        other = copy.deepcopy(raw["results"][0])
        other["check_id"] = "unit.second-rule"
        raw["results"].append(other)
        sarif["runs"][0]["results"] *= 2
        with self.assertRaises(ValueError):
            compare_findings(raw, sarif)

    def test_order_does_not_change_identity(self):
        raw, sarif = self.pair()
        raw["results"].append({**raw["results"][0], "check_id": "unit.other"})
        second = copy.deepcopy(sarif["runs"][0]["results"][0])
        second["ruleId"] = "unit.other"
        sarif["runs"][0]["results"].insert(0, second)
        self.assertEqual(compare_findings(raw, sarif)["findings"], 2)

    def test_missing_or_malformed_evidence_is_rejected(self):
        raw, sarif = self.pair()
        for wrong in ({}, {"runs": None}, {"runs": [{"results": [None]}]},
                      {"runs": [{"results": [{"ruleId": "unit.cwe22", "locations": []}]}]}):
            with self.assertRaises(ValueError):
                compare_findings(raw, wrong)
        region = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        region["startLine"] = True
        with self.assertRaises(ValueError):
            compare_findings(raw, sarif)


class DependencyGateTests(unittest.TestCase):
    def descriptor(self):
        return {"python": "3.12.3", "executable": "UNIT interpreter",
                "packages": {"typer": "0.17.5", "rich": "15.0.0", "PyYAML": "6.0.3"}}

    def test_observed_dependency_shape_is_supported(self):
        validate_dependencies(self.descriptor())

    def test_missing_packages_or_probe_fields_are_rejected(self):
        for name in ("typer", "rich", "PyYAML"):
            d = self.descriptor()
            d["packages"][name] = None
            with self.assertRaises(ValueError):
                validate_dependencies(d)
        with self.assertRaises(ValueError):
            validate_dependencies({})

    def test_failed_dependency_process_prevents_help_scan_and_handoff(self):
        with tempfile.TemporaryDirectory(dir=BASE / "evidence") as t:
            root = Path(t)
            def prepared(upstream, advisor, out):
                (out / "source").mkdir(parents=True)
                return {"prepared_files_sha256": {}}
            with patch("prove_original_cli.prepare", side_effect=prepared), \
                 patch("prove_original_cli.subprocess.run", return_value=subprocess.CompletedProcess([], 1, b"", b"UNIT dependency failure")) as process:
                result, code = run(root / "upstream", root / "private", root / "proof")
            self.assertEqual(code, 2)
            self.assertEqual(result["first_failure_stage"], "dependencies")
            self.assertEqual(result["cli"]["status"], "BLOCKED")
            self.assertEqual(process.call_count, 1)
