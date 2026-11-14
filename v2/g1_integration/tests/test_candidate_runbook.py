"""Offline release contract: runbook targets, B2 runtime plan invariants, and candidate lineage."""
import importlib
import json
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from v2.triage.ollama import PROMPT_VERSION


class CandidateRunbookTests(unittest.TestCase):
    def test_test_instructions_and_new_runtime_modules_exist(self):
        candidate = json.loads((ROOT / "v2/g1_integration/CANDIDATE.json").read_text(encoding="utf-8"))
        commands = candidate["test_instructions"]
        self.assertGreater(len(commands), 0)
        for command in commands:
            with self.subTest(command=command):
                paths = re.findall(r"v2/[\w/]+(?:\.py)?", command)
                self.assertTrue(paths)
                for path in paths:
                    self.assertTrue((ROOT / path).exists(), path)
        self.assertTrue(any("run_checks.py" in c for c in commands))
        self.assertTrue(any("verify_test_receipt.py" in c for c in commands))

        # Verify all B1/B2 runtime verification & receipt modules are importable
        for mod_name in (
            "v2.triage.verify_http_capture",
            "v2.g1_integration.exec_receipt",
            "v2.g1_integration.evaluate_r01_r03",
        ):
            with self.subTest(module=mod_name):
                importlib.import_module(mod_name)

    def test_candidate_lineage_and_runtime_limit_are_explicit(self):
        cand_path = ROOT / "v2/g1_integration/CANDIDATE.json"
        raw_bytes = cand_path.read_bytes()
        self.assertNotIn(b"\r\n", raw_bytes, "CANDIDATE.json must use LF line endings")
        candidate = json.loads(raw_bytes.decode("utf-8"))
        self.assertEqual(candidate["candidate_id"], "G1-C4")
        self.assertEqual(candidate["previous_candidate_id"], "G1-C3")
        self.assertEqual(candidate["previous_candidate_commit"], "236439ead654d12448bb2cf711e534a243007afd")
        self.assertEqual(candidate["previous_candidate_runtime_status"], "RUNTIME_PLAN_REQUIRES_CORRECTION")
        self.assertEqual(candidate["historical_g1_c2_commit"], "6ebf3ec6668741a346199f860cf349332ad94eae")
        self.assertEqual(candidate["historical_g1_c2_runtime_status"], "G1_C2_RUNTIME_ACCEPTANCE_FAILED")
        self.assertEqual(candidate["qwen_server_runtime_status"], "NOT_TESTED")
        self.assertEqual(candidate["prompt_version"], PROMPT_VERSION)

        env_cmp = candidate["environment_reference_vs_admin_pc"]
        self.assertEqual(env_cmp["advisor_reference"]["opengrep"], "1.33.1")
        self.assertEqual(env_cmp["advisor_reference"]["ollama"], "0.40.16")
        self.assertEqual(env_cmp["admin_pc_actual"]["opengrep"], "1.25.0")
        self.assertEqual(env_cmp["admin_pc_actual"]["ollama"], "0.40.7")
        self.assertEqual(env_cmp["admin_pc_actual"]["model"], "qwen3.5:9b-q4_K_M")

    def test_runtime_acceptance_plan_resolves_b2_discrepancies(self):
        candidate = json.loads((ROOT / "v2/g1_integration/CANDIDATE.json").read_text(encoding="utf-8"))
        plan_path = ROOT / candidate["runtime_acceptance_plan"]
        self.assertTrue(plan_path.is_file())
        raw_bytes = plan_path.read_bytes()
        self.assertNotIn(b"\r\n", raw_bytes, "RUNTIME_ACCEPTANCE_PLAN.md must use LF line endings")
        text = raw_bytes.decode("utf-8")

        for required_token in (
            "1.33.1",
            "0.40.16",
            "1.25.0",
            "0.40.7",
            "qwen3.5:9b-q4_K_M",
            "3.11.9",
            "getCanonicalPath().startsWith(\"/srv/reports/\")",
            "ExternalPathPolicy.normalizeDocumentPath",
            "evidence.json",
            ".prompt.json",
            ".request.body.bin",
            ".response.body.bin",
            ".http-capture.json",
            "warnings[0].id",
            "--auxiliary-controls-only",
            "v2.g1_integration.exec_receipt",
            "v2.triage.verify_http_capture",
            "v2.g1_integration.evaluate_r01_r03",
            "G1_C2_RUNTIME_ACCEPTANCE_FAILED",
            "RUNTIME_PLAN_REQUIRES_CORRECTION",
        ):
            with self.subTest(required=required_token):
                self.assertIn(required_token, text)

        # Ensure forbidden PowerShell overwrite/re-encoding/stale-path tokens never appear in executable blocks
        ps_blocks = "\n".join(re.findall(r"```powershell\n(.*?)```", text, flags=re.DOTALL))
        self.assertTrue(ps_blocks, "Expected executable PowerShell code blocks in RUNTIME_ACCEPTANCE_PLAN.md")
        for forbidden_cmd_token in (
            "venv --clear",
            "New-Item -Force",
            "New-Item -ItemType Directory -Force",
            "Tee-Object",
            "*>",
            "evidence.jsonl",
            ".prompt.txt",
            ".warning_id",
        ):
            with self.subTest(forbidden=forbidden_cmd_token):
                self.assertNotIn(forbidden_cmd_token, ps_blocks)

    def test_runbook_preserves_failure_and_removes_missing_command(self):
        for name in ("README.md", "G1_FINAL_HANDOFF.md"):
            with self.subTest(name=name):
                text = (ROOT / "v2/g1_integration" / name).read_text(encoding="utf-8")
                self.assertIn("G1_C2_RUNTIME_ACCEPTANCE_FAILED", text)
                self.assertIn("RUNTIME_PLAN_REQUIRES_CORRECTION", text)
                self.assertIn(PROMPT_VERSION, text)
                self.assertNotIn("scripts/verify-repository.py", text)


if __name__ == "__main__":
    unittest.main()
