"""UNIT fixtures are simulated. Only the opt-in server test executes the real upstream CLI."""
import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import types
import unittest
import uuid
import zipfile
from pathlib import Path
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
from prepare_upstream_local import PIN, validate_checkout_identity, apply_advisor_patch, prepared_hashes
from prove_original_cli import run, validate_cli_origin


class OriginalCLIProofTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=BASE / "evidence")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()

    def inventory(self):
        spec = json.loads((BASE / "pinned_upstream_tree.json").read_text())
        return spec, {f["path"]: {"mode": f["mode"], "git_blob_sha": f["git_blob_sha"]} for f in spec["files"]}

    def test_complete_public_inventory_matches_known_snapshot_blobs(self):
        spec, files = self.inventory()
        self.assertEqual(validate_checkout_identity(PIN, spec["tree_sha"], files), 96)
        pinned = json.loads((BASE / "upstream/PROVENANCE.json").read_text())
        for item in pinned["files"]:
            self.assertEqual(files[item["path"]]["git_blob_sha"], item["git_blob_sha"])

    def test_wrong_commit_wrong_tree_and_missing_source_refused(self):
        spec, files = self.inventory()
        for head, tree, candidate in (("0"*40, spec["tree_sha"], files), (PIN, "0"*40, files),
                                      (PIN, spec["tree_sha"], {k:v for k,v in files.items() if k != "semgrepai/cli.py"})):
            with self.assertRaises(ValueError):
                validate_checkout_identity(head, tree, candidate)

    def origin(self):
        source = self.root / "source"
        (source / "semgrepai").mkdir(parents=True)
        for name in ("cli.py", "scanner.py", "__main__.py"):
            (source / "semgrepai" / name).write_text("# UNIT fixture, not upstream runtime\n")
        hashes = prepared_hashes(source)
        origin = {"stage":"exit", "main_module":"semgrepai.__main__", "function":"semgrepai.cli.scan",
                  "producer":"inherited-cli-function-hook", "forbidden_imports":[],
                  "argv":[str(source / "semgrepai/__main__.py"),"scan","--scan-only"],
                  "cli_file":str(source / "semgrepai/cli.py"), "scanner_file":str(source / "semgrepai/scanner.py"),
                  "cli_sha256":hashes["semgrepai/cli.py"], "scanner_sha256":hashes["semgrepai/scanner.py"]}
        return source, hashes, origin

    def test_cli_identity_fields_and_code_hashes_are_bound(self):
        source, hashes, origin = self.origin()
        validate_cli_origin(source, origin, hashes)
        (source / "semgrepai/cli.py").write_text("# altered\n")
        with self.assertRaises(ValueError):
            validate_cli_origin(source, origin, hashes)

    def test_direct_scanner_hook_cannot_substitute_for_original_cli(self):
        source, hashes, origin = self.origin()
        for field, value in (("main_module", None), ("function", "SemgrepScanner.scan"),
                             ("stage", "enter"), ("forbidden_imports", ["semgrepai.rag"]),
                             ("scanner_file", str(self.root / "replacement/scanner.py"))):
            candidate = {**origin, field: value}
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_cli_origin(source, candidate, hashes)

    def test_missing_rules_blocks_before_preparation_and_execution(self):
        with patch("prove_original_cli.prepare") as prepare, patch("prove_original_cli.subprocess.run") as execute:
            result, code = run(self.root / "upstream", self.root / "private", self.root / "proof", rules=self.root / "missing.yml")
        self.assertEqual(code, 2)
        self.assertEqual(result["first_failure_stage"], "inputs")
        self.assertEqual(result["M1_ORIGINAL_CLI"], "SERVER_RUNTIME_PENDING")
        prepare.assert_not_called()
        execute.assert_not_called()

    def test_preparation_failure_never_falls_back_to_direct_scanner(self):
        with patch("prove_original_cli.prepare", side_effect=ValueError("UNIT wrong commit/patch")), \
             patch("prove_original_cli.subprocess.run") as execute:
            result, code = run(self.root / "upstream", self.root / "private", self.root / "proof")
        self.assertEqual(code, 2)
        self.assertEqual(result["cli"]["status"], "BLOCKED")
        execute.assert_not_called()

    def test_real_git_rejects_unit_wrong_patch(self):
        source, output, advisor = self.root / "tree", self.root / "output", self.root / "private"
        for p in (source, output, advisor):
            p.mkdir()
        with zipfile.ZipFile(advisor / "opengrep-triage.zip", "w") as z:
            z.writestr("opengrep-triage/patches/simple_semgrepAI_opengrep.patch", "UNIT invalid patch; not professor source\n")
        git = ["git", "-c", "safe.directory="+BASE.parents[1].as_posix(), "-c", "core.autocrlf=false"]
        with self.assertRaises(ValueError):
            apply_advisor_patch(source, output, advisor, git)
        results = json.loads((output / "patch-results.json").read_text())
        self.assertNotEqual(results[0]["exit"], 0)
        self.assertEqual(len(results), 1)

    def test_recorded_engine_error_cannot_finish_successfully(self):
        # Load recording support in an isolated test namespace, not a fake upstream CLI.
        name = "ntk_unit_recording_" + uuid.uuid4().hex
        package = types.ModuleType(name)
        package.__path__ = [str(BASE / "fork/semgrepai")]
        sys.modules[name] = package
        def clean():
            for n in list(sys.modules):
                if n == name or n.startswith(name + "."):
                    del sys.modules[n]
        self.addCleanup(clean)
        spec = importlib.util.spec_from_file_location(name + ".scan_recording", BASE / "upstream_local_support/scan_recording.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        java = self.root / "java"
        java.mkdir()
        (java / "Unit.java").write_text("class Unit {}")
        rules = self.root / "rules.yml"
        rules.write_text("# UNIT mock rules")
        capture = self.root / "capture"
        with patch.object(module.subprocess, "run", return_value=subprocess.CompletedProcess([],2,b"",b"MOCK engine failure")):
            with self.assertRaises(subprocess.CalledProcessError):
                with module.recording(java, rules, capture):
                    module.recorded_run(["MOCK_ENGINE", "--json", "--output", str(capture / "output.json")], check=True)
        manifest = json.loads((capture / "scan-manifest.json").read_text())
        self.assertFalse(manifest["success"])
        self.assertEqual(manifest["runs"]["json"]["exit_code"], 2)

        missing_binary = self.root / "missing-binary-capture"
        with patch.object(module.subprocess, "run", side_effect=FileNotFoundError("UNIT missing binary")):
            with self.assertRaises(FileNotFoundError):
                with module.recording(java, rules, missing_binary):
                    module.recorded_run(["UNIT_MISSING_BINARY", "--version"], check=True)
        missing = json.loads((missing_binary / "scan-manifest.json").read_text())
        self.assertFalse(missing["success"])
        self.assertNotIn("version", missing["runs"])

    def capture_fixture(self):
        from v2.baseline.fork.semgrepai.scan_manifest import ScanCapture
        java = self.root / "unit-java"
        java.mkdir()
        (java / "Unit.java").write_text("class Unit {}\n")
        rules = self.root / "unit-rules.yml"
        rules.write_text("# UNIT receipt only; no engine executed\n")
        output = self.root / "unit-capture"
        output.mkdir()
        capture = ScanCapture(java, rules, output, producer="UNIT_TEST_ONLY")
        raw = b'{"results":[],"errors":[]}'
        for label, data in (("version", b"MOCK VERSION"), ("json", raw), ("sarif", b'{"runs":[]}')):
            argv = ["UNIT_MOCK_ENGINE", label]
            capture.runs[label] = {"argv": argv, "exit_code": 0}
            (output / (label+".stdout.txt")).write_bytes(data)
            (output / (label+".stderr.txt")).write_bytes(b"")
            (output / (label+".exit.txt")).write_text("0")
            (output / (label+".command.json")).write_text(json.dumps(argv))
            if label != "version":
                (output / ("opengrep."+label)).write_bytes(data)
        capture.finish(True)
        return java, output, raw

    def test_changed_raw_output_is_not_accepted_as_engine_evidence(self):
        from v2.triage.scan_receipt import verify_receipt
        java, capture, raw = self.capture_fixture()
        self.assertEqual(verify_receipt(capture / "scan-manifest.json", raw, java)[1], [])
        (capture / "opengrep.json").write_bytes(raw + b" ")
        self.assertTrue(verify_receipt(capture / "scan-manifest.json", raw, java)[1])

    def test_changed_java_after_capture_is_not_accepted(self):
        from v2.triage.scan_receipt import verify_receipt
        java, capture, raw = self.capture_fixture()
        (java / "Unit.java").write_text("class Unit {} // source edited after capture\n")
        metadata, issues = verify_receipt(capture / "scan-manifest.json", raw, java)
        self.assertTrue(issues)
        self.assertFalse(metadata["source_capture_verified"])


class LiveOriginalCLI(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("NTK_M1_LIVE_UPSTREAM") and os.environ.get("NTK_M1_ADVISOR_DIR"),
                         "Opt-in live rerun not requested; recorded laptop proof is audited separately without rescanning")
    def test_real_package_entrypoint_scan_and_handoff(self):
        output = BASE / "evidence" / ("server-cli-test-" + uuid.uuid4().hex)
        result, code = run(Path(os.environ["NTK_M1_LIVE_UPSTREAM"]), Path(os.environ["NTK_M1_ADVISOR_DIR"]), output)
        self.assertEqual(code, 0, result)
        self.assertEqual(result["cli"]["status"], "PASS")
        self.assertEqual(result["scanner"]["status"], "PASS")
        self.assertEqual(result["handoff"]["status"], "PASS")
        self.assertEqual(result["demo_examples"], "PASS")
