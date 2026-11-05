"""Javac class initializer callsites must never borrow a nearby method."""
import tempfile
import unittest
from pathlib import Path

import ntk_alert_verification as triage
import ntk_web_backend_service as service

JAVA = """package demo;
public class Example {
  static {
    System.out.println("static");
  }
  {
    System.out.println("instance");
  }
  public void realMethod() {
    System.out.println("method");
  }
}
"""


class InitializerProvenanceTests(unittest.TestCase):
    def test_ast_initializer_spans_and_nearest_method_guard(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "Example.java"
            path.write_text(JAVA)
            parsed = triage.parse_java_source_with_javac_ast(JAVA, str(path))
            self.assertIsNotNone(parsed)
            blocks = parsed["classes"][0]["initializers"]
            self.assertEqual(len(blocks), 2)
            self.assertTrue(any(b["is_static"] and b["start_line"] <= 4 <= b["end_line"] for b in blocks))
            self.assertTrue(any(not b["is_static"] and b["start_line"] <= 7 <= b["end_line"] for b in blocks))
            for line, expected in [(4, "staticInitializer"), (7, "instanceInitializer")]:
                res = triage.analyze_java_site_ast_and_taint(
                    JAVA, str(path), line, 79,
                    opengrep_matched_code=JAVA.splitlines()[line-1].strip())
                self.assertEqual(res.enclosing_method, expected)
                self.assertEqual(res.flow_proof_state, "UNKNOWN")
                self.assertIn("RC_CLASS_INITIALIZER_FLOW_UNPROVEN", res.extra_reason_codes)
            real = triage.analyze_java_site_ast_and_taint(
                JAVA, str(path), 10, 79,
                opengrep_matched_code=JAVA.splitlines()[9].strip())
            self.assertEqual(real.enclosing_method, "realMethod")

    def test_validator_rejects_fake_method_but_accepts_real_initializer_span(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "Example.java"
            path.write_text(JAVA)
            matched = JAVA.splitlines()[3].strip()
            finding = {
                "finding_id":"TEST-CWE079-staticInitializer-L4",
                "file_path":"Example.java", "line_number":4,
                "matched_code":matched, "enclosing_method":"staticInitializer",
                "scanner_rule_id":"test-cwe079", "cwe":"CWE-079", "cwe_id":79,
                "decision":"REVIEW", "triage_status":"NEEDS_REVIEW",
                "original_iris_evidence":[],
            }
            og = {"results":[{"path":str(path),"start":{"line":4},"check_id":"test-cwe079"}]}
            proof = service.verify_findings_against_source_tree([finding],og,Path(temp),"test-source")
            self.assertTrue(proof["verified"],proof["mismatches"])
            self.assertTrue(proof["per_finding_records"][0]["ast_initializer_verified"])
            fake = dict(finding,enclosing_method="realMethod")
            rejected = service.verify_findings_against_source_tree([fake],og,Path(temp),"test-source")
            self.assertFalse(rejected["verified"])
            self.assertIn("AST_ENCLOSING_METHOD_MISMATCH",str(rejected["mismatches"]))

if __name__ == "__main__": unittest.main()
