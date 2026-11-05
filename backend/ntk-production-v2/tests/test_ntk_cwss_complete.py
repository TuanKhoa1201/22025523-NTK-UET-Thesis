"""Scenario-conditional completion tests, not independent severity ground truth."""
import copy
import json
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import ntk_cwss_complete as c
import ntk_cwss_workflow as w
import ntk_cwss_automatic as a
import ntk_cwss_v101 as scoring
from test_ntk_cwss_automatic import example, FIXTURES, KINDS
from test_ntk_cwss_workflow import SCAN, Index, profile, metric


def high_context(f):
    """Explicit synthetic independent-review attestation test double."""
    p = profile(f)
    for m, code in {'AP':'A','AL':'A','FC':'T','BI':'C','EC':'N','DI':'H','EX':'H','SC':'A','RL':'A'}.items():
        p['metrics'][m] = metric(code)
    p['finding_verification'] = {'verdict':'CONFIRMED_TRUE_POSITIVE', 'attacker_reachability_verified':True,
        'evidence':'Synthetic independent review context ONLY; not a deployed system claim',
        'reference':'synthetic-high-context', 'reviewer':'alice','reviewed_at_utc':'2026-10-30T00:00:00Z'}
    return {'profile':p, 'reviewer':'alice'}


class CompleteTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.f=example();self.snap=a.collect(FIXTURES,[self.f])
        self.store=w.AssessmentStore(Path(self.tmp.name)/'store')

    def assess(self, reference='GENERAL_JAVA', attestation=None):
        return c.assess(self.f,SCAN,self.snap,reference,attestation)[1]

    def test_complete_all_sixteen_official_codes_weights(self):
        for cwe in KINDS:
            f=example(cwe)
            for reference in c.PROFILES:
                _,r=c.assess(f,SCAN,a.collect(FIXTURES,[f]),reference)
                self.assertEqual(set(r['factor_codes']),set(scoring.FACTOR_ORDER))
                self.assertFalse(set(r['factor_codes'].values()) & {'UK','U'})
                self.assertEqual(r['unknown_metric_count'],0)
                for m,row in r['metric_assessments'].items():
                    self.assertEqual(row['weight'],scoring.WEIGHTS[m][row['code']])
                self.assertEqual(r['cwss_score_exact'],scoring.score_codes(r['factor_codes'],fill_unknown=False)['cwss_score_exact'])

    def test_verified_evidence_precedes_every_lower_tier(self):
        r=self.assess('RESTRICTED_INTERNAL')
        self.assertEqual(r['factor_codes']['TI'],'H')
        self.assertEqual(r['metric_assessments']['TI']['classification'],'VERIFIED')
        att=high_context(self.f);att['profile']['metrics']['TI']=metric('N')
        self.assertEqual(self.assess(attestation=att)['factor_codes']['TI'],'H')

    def test_unknown_business_and_controls_use_standard_defaults(self):
        r=self.assess()
        for m in ('BI','EC','FC','AP'):
            row=r['metric_assessments'][m]
            self.assertEqual(row['code'],'D')
            self.assertEqual(row['classification'],'STANDARD_DEFAULT')
            self.assertFalse(row['evidence_sufficient'])
        self.assertEqual(r['factor_codes']['P'],'NA')
        self.assertFalse(r['fully_verified'])
        self.assertEqual(r['assessment_status'],'SCENARIO-CONDITIONAL')

    def test_profile_selection_never_automatically_critical(self):
        with patch.dict('os.environ',{},clear=True):self.assertEqual(c.selection(),'GENERAL_JAVA')
        with patch.dict('os.environ',{'NTK_CWSS_REFERENCE_PROFILE':'RESTRICTED_INTERNAL'}):
            self.assertEqual(c.selection(),'RESTRICTED_INTERNAL')
        with patch.dict('os.environ',{'NTK_CWSS_REFERENCE_PROFILE':'invalid'}):
            with self.assertRaises(ValueError):c.selection()

    def test_business_context_changes_only_declared_metric(self):
        ordinary=self.assess('INTERNET_WEB');critical=self.assess('BUSINESS_CRITICAL_WEB')
        self.assertGreater(critical['cwss_score'],ordinary['cwss_score'])
        self.assertEqual([m for m in ordinary['factor_codes'] if ordinary['factor_codes'][m]!=critical['factor_codes'][m]],['BI'])
        self.assertEqual(critical['metric_assessments']['BI']['classification'],'REFERENCE_ASSUMED')

    def test_high_risk_with_explicit_context_exceeds_fifty(self):
        r=self.assess('BUSINESS_CRITICAL_WEB',high_context(self.f))
        self.assertGreater(r['cwss_score'],50)
        self.assertEqual(r['metric_assessments']['FC']['classification'],'ANALYST_ATTESTED')
        self.assertEqual(r['cwss_score'],scoring.score_codes(r['factor_codes'])['cwss_score'])
        self.assertFalse(r['fully_verified'])

    def test_bad_fc_attestation_not_bypassed(self):
        att=high_context(self.f);att['profile']['finding_verification']['attacker_reachability_verified']=False
        with self.assertRaises(ValueError):self.assess(attestation=att)
        att=high_context(self.f);att['profile']['metrics']['FC']['classification']='MACHINE_SUGGESTED'
        self.assertEqual(self.assess(attestation=att)['factor_codes']['FC'],'D')

    def test_low_risk_reference_reduces_score(self):
        self.assertLess(self.assess('RESTRICTED_INTERNAL')['cwss_score'],self.assess('BUSINESS_CRITICAL_WEB')['cwss_score'])

    def test_no_source_no_context_not_high_by_construction(self):
        f=example();f.pop('iris_evidence');f.pop('llm_api_role')
        _,r=c.assess(f,SCAN,a.collect(None,[f]))
        expected={m:'D' for m in scoring.FACTOR_ORDER};expected['P']='NA'
        self.assertEqual(r['factor_codes'],expected)
        self.assertEqual(r['default_metric_count'],15)

    def test_strong_verified_control_zero_without_triage_change(self):
        f=example(22);f['iris_evidence'].update(flow_proof_state='PROVEN_SAFE',taint_reaches_sink=False,
            source_sink_trace_status='SAFE_SANITIZED_OR_GUARDED',explicit_ast_release_verified=True,
            sanitizer_status='VERIFIED_NORMALIZED_PATH_WITH_PREFIX_GUARD',
            ast_proof_node='SANITIZER_CALL:Path::normalize+STARTSWITH_PREFIX_GUARD:p.startsWith(base)')
        _,r=c.assess(f,SCAN,a.collect(FIXTURES,[f]),'BUSINESS_CRITICAL_WEB')
        self.assertEqual(r['factor_codes']['IC'],'C');self.assertEqual(r['cwss_score'],0)
        self.assertEqual(r['triage_decision'],f['decision'])

    def test_machine_estimate_never_becomes_attested_or_verified(self):
        r=self.assess()
        for m in ('IC','RP','AS','AV','AL'):
            self.assertIn(r['metric_assessments'][m]['classification'],('MACHINE_SUGGESTED','SCENARIO_ASSUMED'))
            self.assertFalse(r['metric_assessments'][m]['evidence_sufficient'])

    def test_counts_cover_sixteen_and_no_triage_mutation(self):
        original=copy.deepcopy(self.f);r=self.assess()
        self.assertEqual(sum(r[k] for k in ('verified_metric_count','attested_metric_count','estimated_metric_count','reference_metric_count','default_metric_count'))+1,16)
        self.assertEqual(self.f,original)
        self.assertEqual(r['triage_decision'],'REPORT')

    def test_reproducibility_hashes_and_versioned_snapshot(self):
        first=self.assess();second=self.assess()
        self.assertEqual(first,second)
        record=self.store.publish_complete(self.f,SCAN,self.snap)
        self.assertEqual(record,self.store.publish_complete(self.f,SCAN,self.snap))
        self.assertTrue(self.store.replay(SCAN,self.f['finding_id'],1)['replay_verified'])
        with patch.dict(c.PROFILES['GENERAL_JAVA']['codes'],{'BI':'C'}):
            with self.assertRaises(w.Conflict):self.store.replay(SCAN,self.f['finding_id'],1)

    def test_context_revisions_and_history(self):
        first=self.store.publish_complete(self.f,SCAN,self.snap)
        second=self.store.publish_complete(self.f,SCAN,self.snap,'INTERNET_WEB')
        self.assertEqual(second['revision'],2)
        self.assertNotEqual(first['assessment']['calculation_hash'],second['assessment']['calculation_hash'])
        self.assertTrue(self.store.replay(SCAN,self.f['finding_id'],1)['replay_verified'])

    def test_api_complete_ranking_report_history_and_replay(self):
        index=Index();index.findings=[self.f]
        state=SimpleNamespace(storage_dir=Path(self.tmp.name),result_index=index)
        complete_store=w.AssessmentStore(w.directory(state)/'complete')
        complete_store.publish_complete(self.f,SCAN,self.snap)
        base='/api/scans/'+SCAN+'/cwss/v1/'
        for endpoint in ('ranking','report'):
            code,body=w.handle(state,'GET',base+endpoint,{'mode':[c.MODE]})
            self.assertEqual(code,200);self.assertEqual(body['findings'][0]['score_mode'],c.MODE)
        path=base+'findings/'+self.f['finding_id']+'/'
        code,body=w.handle(state,'GET',path+'automatic',{})
        self.assertEqual(code,200);self.assertEqual(body['auto_complete']['unknown_metric_count'],0)
        code,body=w.handle(state,'GET',path+'history',{})
        self.assertEqual(len(body['complete_revisions']),1)
        code,body=w.handle(state,'GET',path+'replay',{'mode':[c.MODE],'revision':['1']})
        self.assertEqual(code,200);self.assertTrue(body['replay_verified'])

    def test_new_scan_persists_complete_with_no_manual_input(self):
        import ntk_web_backend_service as service
        class ResultIndex:
            def index_scan_record(self,**kwargs):return {'scan_id':kwargs['scan_id']}
        state=SimpleNamespace(storage_dir=Path(self.tmp.name),_lock=threading.Lock(),
            findings_by_id={},pipeline_traces_by_scan={},raw_opengrep_by_scan={},scans={},result_index=ResultIndex())
        data={'findings':[self.f],'cwss_automatic_collection':self.snap};original=copy.deepcopy(data)
        with patch.dict('os.environ',{'NTK_CWSS_REFERENCE_PROFILE':'GENERAL_JAVA'}):
            service.NtkBackendState.record_scan(state,SCAN,data)
        self.assertEqual(data,original)
        records=w.AssessmentStore(w.directory(state)/'complete').history(SCAN,self.f['finding_id'])
        self.assertEqual(len(records),1);self.assertEqual(records[0]['assessment']['unknown_metric_count'],0)

    def test_declared_repository_high_scenario_automated_without_attestation(self):
        declaration=json.loads((Path(__file__).parent/'fixtures/cwss_complete/high-reference.json').read_text())
        root=Path(self.tmp.name);(root/'ntk-cwss-reference-context.json').write_text(json.dumps(declaration))
        snap=copy.deepcopy(self.snap);snap['complete_reference_context']=c.collect_context(root)
        _,r=c.assess(self.f,SCAN,snap)
        self.assertGreater(r['cwss_score'],50)
        self.assertEqual(r['factor_codes']['FC'],'D')
        self.assertEqual(r['reference_selection'],'REPOSITORY_DECLARED_SCENARIO')
        self.assertEqual(r['attested_metric_count'],0)
        self.assertEqual(r['metric_assessments']['BI']['classification'],'REFERENCE_ASSUMED')
        self.assertFalse(r['fully_verified'])
        self.store.publish_complete(self.f,SCAN,snap)
        self.assertTrue(self.store.replay(SCAN,self.f['finding_id'],1)['replay_verified'])

    def test_invalid_context_and_fc_injection_fail_closed(self):
        root=Path(self.tmp.name);path=root/'ntk-cwss-reference-context.json'
        path.write_text('{bad json')
        snap=copy.deepcopy(self.snap);snap['complete_reference_context']=c.collect_context(root)
        _,r=c.assess(self.f,SCAN,snap)
        self.assertEqual(r['reference_profile'],'GENERAL_JAVA')
        self.assertTrue(r['reference_context_warning'])
        value=json.loads((Path(__file__).parent/'fixtures/cwss_complete/high-reference.json').read_text())
        value['metric_assumptions']['FC']={'code':'T','reason':'Do not trust a repository claim of confirmed exploitability.'}
        path.write_text(json.dumps(value))
        self.assertIn('error',c.collect_context(root))

    def test_user_cannot_submit_complete_as_verified_profile(self):
        p,_=c.assess(self.f,SCAN,self.snap)
        with self.assertRaises(ValueError):w.evaluate(self.f,SCAN,p,'alice')
