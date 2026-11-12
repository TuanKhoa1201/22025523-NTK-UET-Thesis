"""Synthetic marker/receipt joins do not establish a real candidate or real runtime."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from inspect_release import inspect, runtime_join
from inspect_cli import inspect as inspect_cli
import os


class ReleaseChecks(unittest.TestCase):
    def test_matching_receipt_stays_unattested(self):
        r=runtime_join(dict(candidate_id='SYNTHETIC-C1',tested_sha='a'*40),'SYNTHETIC-C1','a'*40)
        self.assertEqual(r['join'],'PASS');self.assertEqual(r['gate_verdict'],'INCOMPLETE')
        self.assertFalse(r['raw_artifacts_independently_checked']);self.assertFalse(r['runtime_observed'])

    def test_wrong_runtime_sha(self):
        with self.assertRaises(ValueError): runtime_join(dict(candidate_id='SYNTHETIC-C1',tested_sha='b'*40),'SYNTHETIC-C1','a'*40)

    def test_wrong_candidate_id(self):
        with self.assertRaises(ValueError): runtime_join(dict(candidate_id='SYNTHETIC-C2',tested_sha='a'*40),'SYNTHETIC-C1','a'*40)

    def test_missing_receipt_fields(self):
        with self.assertRaises(KeyError): runtime_join({'verdict':'PASS'},'SYNTHETIC-C1','a'*40)

    def test_missing_marker(self):
        with tempfile.TemporaryDirectory() as tmp, patch('inspect_release.git',side_effect=['a'*40,'']):
            r=inspect(tmp,'a'*40)
            self.assertEqual(r['reason'],'CANDIDATE_NOT_AVAILABLE');self.assertIsNone(r['candidate_sha'])

    def test_not_ready_marker(self):
        with tempfile.TemporaryDirectory() as tmp, patch('inspect_release.git',side_effect=['a'*40,'']):
            p=Path(tmp)/'v2/g1_integration';p.mkdir(parents=True)
            (p/'CANDIDATE.json').write_text(json.dumps({'status':'DRAFT','candidate_id':'SYNTHETIC-C1'}))
            r=inspect(tmp,'a'*40)
            self.assertEqual(r['reason'],'CANDIDATE_NOT_READY');self.assertIsNone(r['candidate_sha'])

    def test_ready_marker_uses_real_checkout_sha(self):
        with tempfile.TemporaryDirectory() as tmp, patch('inspect_release.git',side_effect=['a'*40,'','a'*40,'']):
            p=Path(tmp)/'v2/g1_integration';p.mkdir(parents=True)
            (p/'CANDIDATE.json').write_text(json.dumps({'status':'READY_FOR_INDEPENDENT_TEST','candidate_id':'SYNTHETIC-C1','claimed_sha':'b'*40}))
            r=inspect(tmp,'a'*40)
            self.assertEqual(r['candidate_sha'],'a'*40);self.assertEqual(r['verdict'],'INCOMPLETE')

    def test_static_cli_never_passes_runtime_gate(self):
        r=inspect_cli(os.environ['G1_CHECKOUT'],os.environ['G1_EXPECTED_SHA'])
        self.assertEqual(r['evidence_kind'],'STATIC_SOURCE_ONLY')
        self.assertEqual(r['gate_verdict'],'INCOMPLETE');self.assertTrue(r['files'])


if __name__=='__main__':unittest.main()
