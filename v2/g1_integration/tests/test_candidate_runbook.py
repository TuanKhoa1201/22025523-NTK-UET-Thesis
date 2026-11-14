"""Offline release contract: runbook targets exist and candidate lineage is explicit."""
import json
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from v2.triage.ollama import PROMPT_VERSION


class CandidateRunbookTests(unittest.TestCase):
    def test_test_instructions_reference_existing_entrypoints(self):
        candidate = json.loads((ROOT/'v2/g1_integration/CANDIDATE.json').read_text(encoding='utf-8'))
        commands = candidate['test_instructions']
        self.assertGreater(len(commands), 0)
        for command in commands:
            with self.subTest(command=command):
                paths = re.findall(r'v2/[\w/]+(?:\.py)?', command)
                self.assertTrue(paths)
                for path in paths:
                    self.assertTrue((ROOT/path).exists(), path)
        self.assertTrue(any('run_checks.py' in c for c in commands))
        self.assertTrue(any('verify_test_receipt.py' in c for c in commands))

    def test_candidate_lineage_and_runtime_limit_are_explicit(self):
        candidate = json.loads((ROOT/'v2/g1_integration/CANDIDATE.json').read_text(encoding='utf-8'))
        self.assertEqual(candidate['candidate_id'], 'G1-C3')
        self.assertEqual(candidate['previous_candidate_id'], 'G1-C2')
        self.assertEqual(candidate['previous_candidate_commit'], '6ebf3ec6668741a346199f860cf349332ad94eae')
        self.assertEqual(candidate['previous_candidate_runtime_status'], 'G1_C2_RUNTIME_ACCEPTANCE_FAILED')
        self.assertEqual(candidate['qwen_server_runtime_status'], 'NOT_TESTED')
        self.assertEqual(candidate['prompt_version'], PROMPT_VERSION)

    def test_runbook_preserves_failure_and_removes_missing_command(self):
        for name in ('README.md', 'G1_FINAL_HANDOFF.md'):
            with self.subTest(name=name):
                text = (ROOT/'v2/g1_integration'/name).read_text(encoding='utf-8')
                self.assertIn('G1_C2_RUNTIME_ACCEPTANCE_FAILED', text)
                self.assertIn(PROMPT_VERSION, text)
                self.assertNotIn('scripts/verify-repository.py', text)


if __name__ == '__main__':
    unittest.main()
