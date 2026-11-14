"""Exercise real unittest child processes, including discovery/import/subtest failures."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from run_checks import reconcile
from run_checks import guard_checkout
from unittest.mock import patch
import os


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
        r['counts']['PASS']=1;r['run']=True
        with self.assertRaises(ValueError): reconcile(r,p.returncode,p.stderr.decode())

    def test_wrong_sha_stops_before_tests(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'not-created'
            cmd=[sys.executable,'-B',str(Path(__file__).with_name('run_checks.py')),'--checkout',os.environ['G1_CHECKOUT'],
                 '--expected-sha','0'*40,'--output',str(out)]
            p=subprocess.run(cmd,capture_output=True,timeout=15)
            self.assertEqual(p.returncode,2); self.assertFalse(out.exists())

    def test_mutated_checkout_or_branch_is_rejected(self):
        for replies in (['a'*40,'HEAD',' M tracked.py'], ['a'*40,'moving-branch']):
            with self.subTest(replies=replies), patch('run_checks.git',side_effect=replies):
                with self.assertRaises(ValueError): guard_checkout(Path('.'),'a'*40)

    def test_clean_detached_checkout_positive(self):
        guard_checkout(Path(os.environ['G1_CHECKOUT']),os.environ['G1_EXPECTED_SHA'])

    def test_receipt_log_hash_and_aggregate_corruption(self):
        from verify_test_receipt import verify
        from audit import sha
        p,r=self.child('import unittest\nclass T(unittest.TestCase):\n def test_ok(self): pass\n')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'0.stdout.txt').write_bytes(p.stdout);(root/'0.stderr.txt').write_bytes(p.stderr)
            path=root/'0.unittest.json';path.write_text(json.dumps(r),encoding='utf-8')
            command=dict(stdout_sha256=sha(p.stdout),stderr_sha256=sha(p.stderr),structured_sha256=sha(path.read_bytes()),
                         structured=r,counts=r['counts'],exit_code=p.returncode,reconciled=True)
            receipt=dict(commands=[command],counts=dict(r['counts']),tests_succeeded=True,checkout_guard_error=None)
            (root/'checks.json').write_text(json.dumps(receipt));self.assertTrue(verify(root)['receipts_consistent'])
            receipt['counts']['PASS']=2;(root/'checks.json').write_text(json.dumps(receipt))
            with self.assertRaises(ValueError):verify(root)
            receipt['counts']['PASS']=1;(root/'checks.json').write_text(json.dumps(receipt))
            (root/'0.stderr.txt').write_bytes(p.stderr+b'changed')
            with self.assertRaises(ValueError):verify(root)


if __name__ == '__main__': unittest.main()
