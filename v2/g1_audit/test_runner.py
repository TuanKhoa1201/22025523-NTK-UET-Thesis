"""Exercise real unittest child processes, including discovery/import/subtest failures."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from run_checks import reconcile


class RunnerChecks(unittest.TestCase):
    def child(self, body):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); (root/'test_probe.py').write_text(body,encoding='utf-8')
            receipt=root/'receipt.json'
            cmd=[sys.executable,'-B',str(Path(__file__).with_name('unittest_probe.py')),
                 '--start',str(root),'--pattern','test_probe.py','--receipt',str(receipt)]
            p=subprocess.run(cmd,capture_output=True,timeout=15)
            return p,json.loads(receipt.read_text())

    def test_positive_success_and_skip(self):
        p,r=self.child('import unittest\nclass T(unittest.TestCase):\n def test_ok(self): pass\n @unittest.skip("synthetic")\n def test_skip(self): pass\n')
        self.assertTrue(reconcile(r,p.returncode,p.stderr.decode()))
        self.assertEqual(r['counts']['PASS'],1); self.assertEqual(r['counts']['SKIP'],1)

    def test_zero_discovery_rejected(self):
        p,r=self.child('import unittest\n')
        self.assertNotEqual(p.returncode,0)
        with self.assertRaises(ValueError): reconcile(r,p.returncode,p.stderr.decode())

    def test_import_error_is_failure(self):
        p,r=self.child('raise ImportError("synthetic import failure")\n')
        self.assertFalse(reconcile(r,p.returncode,p.stderr.decode()))
        self.assertEqual(r['import_errors'],1); self.assertEqual(r['counts']['ERROR'],1)

    def test_failing_subtests_count_as_one_failed_test(self):
        p,r=self.child('import unittest\nclass T(unittest.TestCase):\n def test_sub(self):\n  for i in range(2):\n   with self.subTest(i=i): self.fail("synthetic")\n')
        self.assertFalse(reconcile(r,p.returncode,p.stderr.decode()))
        self.assertEqual(r['run'],1); self.assertEqual(r['counts']['FAIL'],1)

    def test_exit_summary_disagreement_rejected(self):
        p,r=self.child('import unittest\nclass T(unittest.TestCase):\n def test_ok(self): pass\n')
        with self.assertRaises(ValueError): reconcile(r,2,p.stderr.decode())

    def test_log_count_disagreement_rejected(self):
        p,r=self.child('import unittest\nclass T(unittest.TestCase):\n def test_ok(self): pass\n')
        with self.assertRaises(ValueError): reconcile(r,p.returncode,p.stderr.decode().replace('Ran 1 test','Ran 2 test'))

    def test_structured_count_disagreement_rejected(self):
        p,r=self.child('import unittest\nclass T(unittest.TestCase):\n def test_ok(self): pass\n')
        r['counts']['PASS']=2
        with self.assertRaises(ValueError): reconcile(r,p.returncode,p.stderr.decode())


if __name__ == '__main__': unittest.main()
