"""Regression for 409 when scan index attaches provenance after CWSS archiving.

Local synthetic DTOs only; never runs Java repo code, Qwen, or external calls.
"""
import copy
import json
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

import ntk_cwss_automatic as automatic
import ntk_cwss_workflow as workflow
import ntk_web_backend_service as service
from test_ntk_cwss_workflow import SCAN, finding


class ProvenanceIndex:
    def __init__(self):
        self.findings = []

    def index_scan_record(self, scan_id, scan_record, **kwargs):
        prov = scan_record.get('source_provenance_verification', {})
        by_id = {item['finding_id']: item for item in prov.get('per_finding_records', [])}
        self.findings = []
        for row in scan_record['findings']:
            indexed = copy.deepcopy(row)
            if row['finding_id'] in by_id:
                indexed['source_provenance_record'] = copy.deepcopy(by_id[row['finding_id']])
            indexed.update(scan_id=scan_id, finding_seq=len(self.findings) + 1,
                           scoped_finding_id=scan_id + ':' + row['finding_id'])
            self.findings.append(indexed)
        return {'scan_id': scan_id}

    def get_all_finding_details(self, scan_id):
        return copy.deepcopy(self.findings) if scan_id == SCAN else []


class SourceProvenance409Tests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.index = ProvenanceIndex()
        self.state = SimpleNamespace(
            storage_dir=Path(self.work.name), _lock=threading.Lock(),
            findings_by_id={}, pipeline_traces_by_scan={}, raw_opengrep_by_scan={},
            scans={}, result_index=self.index)
        self.raw = finding()
        self.prov = {'finding_id': self.raw['finding_id'], 'verified': True,
                     'file_sha256': 'a' * 64, 'source': 'SYNTHETIC_INDEX_409_TEST'}
        self.snapshot = automatic.collect(None, [self.raw],
                                          {'per_finding_records': [self.prov]})
        self.payload = {'findings': [self.raw],
                        'cwss_automatic_collection': self.snapshot,
                        'source_provenance_verification': {'verified': True,
                            'per_finding_records': [self.prov]}}

    def test_index_and_all_three_immutable_auto_modes_agree_and_replay(self):
        untouched = copy.deepcopy(self.payload)
        saved = service.NtkBackendState.record_scan(self.state, SCAN, self.payload)
        self.assertEqual(self.payload, untouched)
        self.assertEqual(saved['findings'][0]['decision'], self.raw['decision'])
        indexed = self.index.get_all_finding_details(SCAN)[0]
        self.assertEqual(indexed['source_provenance_record'], self.prov)
        expected = workflow.evidence_hash(indexed)
        history_store = workflow.AssessmentStore(workflow.directory(self.state))
        complete_store = workflow.AssessmentStore(workflow.directory(self.state)/'complete')
        for mode in (*automatic.MODES, workflow.complete.MODE):
            storage = complete_store if mode == workflow.complete.MODE else history_store
            revision = [item for item in storage.history(SCAN, self.raw['finding_id'])
                        if item['profile']['mode'] == mode][-1]
            self.assertEqual(revision['assessment']['source_evidence_hash'], expected)
            self.assertEqual(revision['finding_snapshot']['source_provenance_record'], self.prov)
            self.assertTrue(storage.replay(SCAN, self.raw['finding_id'], revision['revision'])['replay_verified'])
            results = workflow.ranking([indexed], SCAN, history_store, mode)
            self.assertEqual(results[0]['source_evidence_hash'], expected)
            self.assertIsNotNone(results[0]['revision'])
        archived = json.loads((Path(self.work.name)/(SCAN+'.json')).read_text())
        self.assertEqual(archived['findings'][0]['source_provenance_record'], self.prov)

    def test_stale_collected_fingerprint_is_rejected_before_writing(self):
        invalid = copy.deepcopy(self.payload)
        invalid['cwss_automatic_collection']['finding_evidence_hashes'][self.raw['finding_id']] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'fingerprint changed'):
            service.NtkBackendState.record_scan(self.state, SCAN, invalid)
        self.assertFalse((Path(self.work.name)/(SCAN+'.json')).exists())
        self.assertEqual(self.index.findings, [])

    def test_conflicting_provenance_is_rejected(self):
        invalid = copy.deepcopy(self.payload)
        invalid['findings'][0]['source_provenance_record'] = {'source': 'CONFLICT'}
        with self.assertRaisesRegex(ValueError, 'source provenance disagrees'):
            service.NtkBackendState.record_scan(self.state, SCAN, invalid)
        self.assertEqual(self.index.findings, [])


if __name__ == '__main__':
    unittest.main()
