"""CWSS V2 fastpath preserves findings/metric evidence and legacy immutability.

Only synthetic Java DTOs; no scans, GPU, IRIS CodeQL or network.
"""
import copy
import hashlib
import tempfile
import unittest
from pathlib import Path

import ntk_cwss_workflow as w
import ntk_cwss_auto_v2 as v2
import ntk_cwss_automatic as v1
import ntk_cwss_complete as complete

SCAN = 'SCAN-CWSS-SCOPE-TEST'


def fixture():
    fid='FINDING-CWSS-SCOPE-001'
    finding={
        'finding_id':fid, 'cwe':'CWE-089', 'file_path':'Alpha.java',
        'line_number':1, 'scanner_rule_id':'test', 'matched_code':'class Alpha {}',
        'decision':'REVIEW', 'review_status':'NOT_REVIEWED',
        'iris_evidence':{'flow_proof_state':'UNKNOWN'},
        'llm_api_role':{'strict_json_valid':False,'predicted_role':'none'},
    }
    a='class Alpha {}'; b='class Other {'+'\n'.join('String unused%d="long";' % i for i in range(1000))+'}'
    h=lambda s: hashlib.sha256(s.encode()).hexdigest()
    files=[{'path':name,'text':source,'sha256':h(source),'content_sha256':h(source)}
           for name,source in [('Alpha.java',a),('Other.java',b)]]
    snapshot={
        'collector_version':v1.VERSION,'inference_version':v2.graph.VERSION,
        'files':files,'java_ast':{},'independent_local_proofs':{},
        'finding_source_paths':{fid:'Alpha.java','UNRELATED':'Other.java'},
        'analysis_source_bindings':{fid:h(a),'UNRELATED':h(b)},
        'finding_evidence_hashes':{fid:w.evidence_hash(finding),'UNRELATED':'0'*64},
        'limitations':[],'inventory_complete':True,'servlet_mappings':[],
    }
    return finding,snapshot


class CWSSFindingScopeFastpathTests(unittest.TestCase):
    def test_v2_projection_not_legacy_or_mutated(self):
        f,s=fixture();before=copy.deepcopy(s)
        p=w.scope_v2_snapshot(s,f)
        self.assertEqual(s,before)
        self.assertEqual([x['path'] for x in p['files']],['Alpha.java'])
        self.assertEqual(set(p['finding_evidence_hashes']),{f['finding_id']})
        self.assertEqual(set(p['analysis_source_bindings']),{f['finding_id']})
        self.assertLess(len(w.canonical(p)), len(w.canonical(s))/3)
        v1_snap=copy.deepcopy(s);v1_snap['inference_version']=v1.VERSION
        self.assertIs(w.scope_v2_snapshot(v1_snap,f),v1_snap)

    def test_three_modes_exact_metric_and_graph_equivalence(self):
        f,s=fixture();p=w.scope_v2_snapshot(s,f)
        for mode in (*v1.MODES,complete.MODE):
            _,full=v2.assess(f,SCAN,s,mode)
            _,small=v2.assess(f,SCAN,p,mode)
            for field in ('factor_codes','cwss_score','cwss_score_exact','metric_assessments',
                          'normalized_evidence','source_evidence_hash','triage_decision',
                          'assessment_status','reference_profile','unknown_metric_count'):
                self.assertEqual(full.get(field),small.get(field),(mode,field))
            self.assertFalse(small['fully_verified'])

    def test_compact_store_history_and_replay_and_tamper_guard(self):
        f,s=fixture();p=w.scope_v2_snapshot(s,f)
        with tempfile.TemporaryDirectory() as t:
            store=w.AssessmentStore(Path(t)/'auto')
            comp=w.AssessmentStore(Path(t)/'complete')
            store.publish_automatic(f,SCAN,p)
            comp.publish_complete(f,SCAN,p)
            self.assertEqual(len(store.history(SCAN,f['finding_id'])),2)
            self.assertEqual(len(comp.history(SCAN,f['finding_id'])),1)
            for db in (store,comp):
                for row in db.history(SCAN,f['finding_id']):
                    self.assertEqual(row['profile']['automatic_evidence']['cwss_snapshot_scope'],
                                     'CWSS_V2_EXACT_FINDING_SCOPE_V1')
                    self.assertTrue(db.replay(SCAN,f['finding_id'],row['revision'])['replay_verified'])
            before=store.history(SCAN,f['finding_id'])
            store.publish_automatic(f,SCAN,p)
            self.assertEqual(before,store.history(SCAN,f['finding_id']))
            with store.connect() as db:
                db.execute("UPDATE revisions SET envelope='{}' WHERE scan=?",(SCAN,))
            with self.assertRaisesRegex(ValueError,'checksum'):
                store.history(SCAN,f['finding_id'])

if __name__=='__main__':
    unittest.main()
