"""Unit tests use mocked processes only; real evidence is verified separately."""
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / "fork"))
from semgrepai.config import OpenGrepConfig
from semgrepai.scanner import SemgrepScanner, ScanError


def finding():
    return {"check_id": "fixture.rule", "path": str(BASE / "fixtures/java/Vulnerable.java"),
            "start": {"line": 7}, "end": {"line": 7},
            "extra": {"lines": "new File(forwarded);", "metadata": {}, "severity": "WARNING",
                      "dataflow_trace": {"taint_source": ["CliLoc", [{"start": {"line": 5}},
                                                                    "req.getParameter()"]],
                                         "intermediate_vars": [], "taint_sink": None}}}


class ConfigTests(unittest.TestCase):
    def test_default_local_rules_and_engine(self):
        cmd = OpenGrepConfig().command(BASE / "fixtures/java", "json")
        self.assertEqual(cmd[:2], ["opengrep", "scan"])
        self.assertIn("--dataflow-traces", cmd)
        self.assertIn("--no-git-ignore", cmd)
        self.assertIn("--disable-version-check", cmd)
        self.assertNotIn("--config=auto", cmd)
        self.assertIn("*.java", cmd)
        self.assertTrue(Path(cmd[cmd.index("--config")+1]).is_file())

    def test_remote_rules_rejected(self):
        for value in ("auto", "p/java", "https://example.com/rules.yml"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                OpenGrepConfig(rules=Path(value))

    def test_invalid_limits(self):
        for kwargs in ({"timeout": 0}, {"jobs": 0}, {"timeout": -1}):
            with self.assertRaises(ValueError):
                OpenGrepConfig(**kwargs)

    def test_invalid_format(self):
        with self.assertRaises(ValueError):
            OpenGrepConfig().command(BASE, "html")


class ProcessingTests(unittest.TestCase):
    def setUp(self):
        self.scanner = SemgrepScanner()

    def test_native_trace_preserved_without_fabricating_steps(self):
        item = finding()
        output = self.scanner._process_results({"json": {"results": [item]}})
        self.assertEqual(output[0]["dataflow"], item["extra"]["dataflow_trace"])
        self.assertEqual(output[0]["review_status"], "REVIEW")

    def test_extra_trace_precedence(self):
        item = finding()
        item["dataflow_trace"] = [{"content": "legacy"}]
        self.assertEqual(self.scanner._extract_dataflow(item), item["extra"]["dataflow_trace"])

    def test_missing_null_and_unknown_traces_not_invented(self):
        item = finding()
        for trace in (None, {"future_format": [1, 2]}, []):
            item["extra"]["dataflow_trace"] = trace
            self.assertEqual(self.scanner._extract_dataflow(item), trace)
        del item["extra"]["dataflow_trace"]
        self.assertEqual(self.scanner._extract_dataflow(item), [])

    def test_legacy_trace_preserved(self):
        item = finding()
        del item["extra"]["dataflow_trace"]
        item["dataflow_trace"] = [{"content": "fixture legacy"}]
        self.assertEqual(self.scanner._extract_dataflow(item), item["dataflow_trace"])

    def test_empty_success_has_no_findings(self):
        self.assertEqual(self.scanner._process_results({"json": {"results": [], "errors": []}}), [])

    def test_malformed_envelopes_and_partial_results_fail(self):
        for doc in (None, [], {}, {"results": {}}, {"results": [None]},
                    {"results": [], "errors": [{"message": "parse failure"}]}):
            with self.subTest(doc=doc), self.assertRaises(ScanError):
                self.scanner.validate_json(doc)

    def test_malformed_finding_fails(self):
        for key, value in (("extra", None), ("start", {"line": 0}), ("end", {}),
                           ("check_id", ""), ("path", "")):
            item = finding()
            item[key] = value
            with self.subTest(key=key), self.assertRaises(ScanError):
                self.scanner.validate_json({"results": [item]})

    def test_source_context_fallback(self):
        item = finding()
        item["extra"]["lines"] = "requires login"
        self.scanner.target_root = BASE / "fixtures/java"
        self.assertIn("7 |", self.scanner._extract_code(item))

    def test_outside_target_fallback_rejected(self):
        item = finding()
        item["extra"]["lines"] = ""
        item["path"] = str(BASE / "README.md")
        self.scanner.target_root = BASE / "fixtures/java"
        self.assertIn("REVIEW", self.scanner._extract_code(item))


class ExecutionTests(unittest.TestCase):
    def run_mock(self, root, outputs):
        scanner = SemgrepScanner(output_dir=Path(root)/"run")
        with patch("semgrepai.scanner.subprocess.run", side_effect=outputs) as mocked:
            result = scanner.scan(BASE / "fixtures/java")
        return scanner, result, mocked

    def test_mocked_success_captures_both_formats(self):
        outputs = [subprocess.CompletedProcess([], 0, "mock-version", ""),
                   subprocess.CompletedProcess([], 0, '{"results":[],"errors":[]}', ""),
                   subprocess.CompletedProcess([], 0, '{"runs":[]}', "")]
        with tempfile.TemporaryDirectory(dir=BASE / "evidence") as tmp:
            scanner, result, mocked = self.run_mock(tmp, outputs)
            self.assertEqual(result["json"]["results"], [])
            self.assertEqual(mocked.call_count, 3)
            self.assertTrue((scanner.output_dir / "json.command.json").is_file())
            env = mocked.call_args.kwargs["env"]
            self.assertEqual(env["OPENGREP_ENABLE_VERSION_CHECK"], "0")
            self.assertTrue(env["SEMGREP_LOG_FILE"].startswith(str(scanner.output_dir)))

    def test_engine_exit_not_clean(self):
        for code in (1, 2, 7):
            with tempfile.TemporaryDirectory(dir=BASE / "evidence") as tmp:
                with self.assertRaises(ScanError):
                    self.run_mock(tmp, [subprocess.CompletedProcess([], 0, "mock", ""),
                                       subprocess.CompletedProcess([], code, "", "fixture failure")])
                self.assertEqual((Path(tmp)/"run/json.exit.txt").read_text(), str(code))

    def test_missing_engine_or_timeout_fails(self):
        for exc in (FileNotFoundError("fixture"), subprocess.TimeoutExpired(["opengrep"], 90)):
            with tempfile.TemporaryDirectory(dir=BASE / "evidence") as tmp:
                with self.assertRaises(ScanError):
                    self.run_mock(tmp, [exc])
                self.assertTrue((Path(tmp)/"run/version.failure.txt").is_file())

    def test_invalid_json_fails_and_keeps_stdout(self):
        with tempfile.TemporaryDirectory(dir=BASE / "evidence") as tmp:
            with self.assertRaises(ScanError):
                self.run_mock(tmp, [subprocess.CompletedProcess([], 0, "mock", ""),
                                   subprocess.CompletedProcess([], 0, "not-json", "")])
            self.assertEqual((Path(tmp)/"run/opengrep.json").read_text(), "not-json")

    def test_partial_engine_results_fail(self):
        with tempfile.TemporaryDirectory(dir=BASE / "evidence") as tmp:
            with self.assertRaises(ScanError):
                self.run_mock(tmp, [subprocess.CompletedProcess([], 0, "mock", ""),
                                   subprocess.CompletedProcess([], 0, '{"results":[],"errors":[{}]}', ""),
                                   subprocess.CompletedProcess([], 0, '{"runs":[]}', "")])

    def test_invalid_sarif_fails(self):
        with tempfile.TemporaryDirectory(dir=BASE / "evidence") as tmp:
            with self.assertRaises(ScanError):
                self.run_mock(tmp, [subprocess.CompletedProcess([], 0, "mock", ""),
                                   subprocess.CompletedProcess([], 0, '{"results":[]}', ""),
                                   subprocess.CompletedProcess([], 0, '{}', "")])

    def test_argument_paths_are_not_shell_interpolated(self):
        command = OpenGrepConfig().command(Path("path with spaces;literal"), "json")
        self.assertTrue(command[-1].endswith("path with spaces;literal"))

    def test_existing_evidence_not_overwritten(self):
        with tempfile.TemporaryDirectory(dir=BASE / "evidence") as tmp:
            path = Path(tmp)/"keep.txt"
            path.write_text("keep")
            with self.assertRaises(ScanError):
                SemgrepScanner(output_dir=Path(tmp)).scan(BASE / "fixtures/java")
            self.assertEqual(path.read_text(), "keep")


class ProvenanceTests(unittest.TestCase):
    def test_upstream_snapshot_matches_git_blob_hashes(self):
        root = BASE / "upstream"
        for item in json.loads((root/"PROVENANCE.json").read_text())["files"]:
            raw = (root/item["path"]).read_bytes()
            digest = hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
            self.assertEqual(digest, item["git_blob_sha"], item["path"])


if __name__ == "__main__":
    unittest.main()
