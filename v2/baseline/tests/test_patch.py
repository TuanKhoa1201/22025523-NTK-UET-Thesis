import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
from make_patch import render_patch
from verify_patch import verify


class PatchTests(unittest.TestCase):
    def test_patch_generation_is_deterministic(self):
        self.assertEqual(render_patch().encode(), (BASE / "opengrep.patch").read_bytes())

    def test_actual_git_apply_roundtrip_and_provenance(self):
        result = verify()
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(all(not entry["stderr"] for entry in result["git_apply"]))
