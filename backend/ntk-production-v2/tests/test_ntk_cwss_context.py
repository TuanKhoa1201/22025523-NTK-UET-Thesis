"""Stage 9 CWSS evidence/context tests -- fail-safe and backwards compatible."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from ntk_cwss_v101 import score_codes
from ntk_cwss_context import (template_for_scan, finding_anchor, evidence_leads, evaluate_with_context,
                              publish_profile_checked, read_published_profile)
from ntk_cwss_context_api import cwss_findings_page

SCAN = "SCAN-20261028180139-CC5400"


def finding(cwe="CWE-078", fid="FINDING-001-CWE078-executeCommand-L114", review_status="NOT_REVIEWED"):
    return {"finding_id":fid,"cwe":cwe, "file_path":"src/main/java/VulnerableController.java",
            "line_number":114,"scanner_rule_id":"test", "matched_code":"Runtime.exec(input)",
            "decision":"REPORT","review_status":review_status,"final_heuristic_score":0.85,
            "iris_evidence":{"ast_parser_engine":"OPENJDK17_JAVAC_TASK_AST", "source_sink_trace_status":"VERIFIED_TAINT_FLOW",
                             "taint_reaches_sink":True,"taint_trace_steps":["SOURCE_PARAM:cmd","Runtime.exec(cmd)"]},
            "llm_api_role":{"predicted_role":"sink","strict_json_valid":True}}


def attested(code, **kwargs):
    return dict(code=code,verified=True,source="MANUAL_REVIEW",reference="review-log-2026-0001",
                evidence="Detailed verified observation of target runtime and relevant attack path",
                reviewer="security_analyst",reviewed_at_utc="2026-10-29T08:00:00+07:00",**kwargs)


class TestStage9Context(unittest.TestCase):
    def test_unknown_original_36(self):
        r=evaluate_with_context(finding(),SCAN)
        self.assertEqual(r['cwss_score'],3.6)
        self.assertEqual(r['unknown_metric_count'],15)
        self.assertEqual(r['fc_recommendation_not_proof']['suggested_code'],'LT')
        self.assertEqual(r['factor_codes']['FC'],'UK')
        self.assertEqual(r['existing_ntk_triage_decision_unchanged'],'REPORT')

    def test_profile_does_not_promote_suggestions_automatically(self):
        f=finding();p=template_for_scan(SCAN,[f])
        e=p['findings'][f['finding_id']]
        e['metric_assessments']['TI']=dict(code='H', verified=False, source='', evidence='', reviewer='')
        r=evaluate_with_context(f,SCAN,p)
        self.assertEqual(r['factor_codes']['TI'],'UK')
        self.assertEqual(r['review_audit']['pending_metrics'],['TI'])

    def test_attested_metric_updates_official_score(self):
        f=finding();p=template_for_scan(SCAN,[f])
        p['findings'][f['finding_id']]['metric_assessments']['TI']=attested('H')
        p['findings'][f['finding_id']]['metric_assessments']['BI']=attested('M')
        r=evaluate_with_context(f,SCAN,p)
        self.assertEqual(r['factor_codes']['TI'],'H')
        self.assertEqual(r['factor_codes']['BI'],'M')
        self.assertEqual(r['unknown_metric_count'],13)
        self.assertEqual(r['cwss_score'],score_codes({'TI':'H','BI':'M'})['cwss_score'])

    def test_unreviewed_not_promoted_to_fc_proven(self):
        f=finding();p=template_for_scan(SCAN,[f]);e=p['findings'][f['finding_id']]
        e['metric_assessments']['FC']=attested('LT')
        with self.assertRaisesRegex(ValueError,'independently reviewed'):
            evaluate_with_context(f,SCAN,p)
        e['finding_verification']=dict(verdict='CONFIRMED_TRUE_POSITIVE', attacker_reachability_verified=False,
                                        evidence='Manually verified command injection, non-constant taint reaching exec',
                                        reference='review-log-2026-0002',reviewer='analyst',
                                        reviewed_at_utc='2026-10-29T08:00:00+07:00')
        r=evaluate_with_context(f,SCAN,p)
        self.assertEqual(r['factor_codes']['FC'],'LT')
        e['metric_assessments']['FC']=attested('T')
        with self.assertRaisesRegex(ValueError,'attacker reachability'):
            evaluate_with_context(f,SCAN,p)
        e['finding_verification']['attacker_reachability_verified']=True
        self.assertEqual(evaluate_with_context(f,SCAN,p)['factor_codes']['FC'],'T')

    def test_fc_false_requires_review(self):
        f=finding();p=template_for_scan(SCAN,[f]);e=p['findings'][f['finding_id']]
        e['metric_assessments']['FC']=attested('F')
        with self.assertRaises(ValueError):
            evaluate_with_context(f,SCAN,p)

    def test_mismatched_finding_fails_closed(self):
        f=finding();p=template_for_scan(SCAN,[f])
        f2={**f,'line_number':115}
        with self.assertRaisesRegex(ValueError,'anchor mismatch'):
            evaluate_with_context(f2,SCAN,p)
        with self.assertRaisesRegex(ValueError,'scan ID'):
            evaluate_with_context(f,'SCAN-20261029999999-BBBB',p)

    def test_bad_metric_value_refused(self):
        f=finding();p=template_for_scan(SCAN,[f]);e=p['findings'][f['finding_id']]
        e['metric_assessments']['TI']=attested('97%')
        with self.assertRaises(ValueError):
            evaluate_with_context(f,SCAN,p)

    def test_validated_profile_private_atomic_publish(self):
        f=finding();p=template_for_scan(SCAN,[f]);
        with tempfile.TemporaryDirectory() as tmp:
            src=Path(tmp)/'src.json'; src.write_text(json.dumps(p))
            target=publish_profile_checked(src,Path(tmp)/'private')
            self.assertEqual(read_published_profile(SCAN,Path(tmp)/'private')['scan_id'],SCAN)
            self.assertEqual(target.stat().st_mode & 0o777,0o600)

    def test_cwe_hints_no_auto_impact(self):
        for cwe in (22,78,79,89):
            f=finding(f'CWE-{cwe:03d}', f'FINDING-111-CWE{cwe:03d}-L114')
            r=evaluate_with_context(f,SCAN)
            self.assertEqual(r['factor_codes']['TI'],'UK')
            self.assertEqual(r['factor_codes']['BI'],'UK')
            self.assertEqual(r['factor_codes']['AV'],'U')

    def test_all_machine_leads_are_unverified(self):
        leads=evidence_leads(finding())
        self.assertGreater(len(leads),1)
        self.assertTrue(all(x['verified_factor'] is False for x in leads))

    def test_api_read_only_and_paginated(self):
        class Index:
            def query_findings_page(self, **kwargs):
                return 200, {'status':'OK','findings':[finding()],'page':1,'page_size':50,'total_matching':1}
        class Backend:
            result_index=Index()
        with patch('ntk_cwss_context_api.read_published_profile',return_value=None):
            status, payload=cwss_findings_page(Backend(),SCAN,'1','50')
        self.assertEqual(status,200)
        self.assertEqual(payload['assessments'][0]['cwss']['cwss_score'],3.6)
        self.assertTrue(payload['read_only'])

    def test_api_invalid_profile_is_not_silent(self):
        class Index:
            def query_findings_page(self, **kwargs):
                return 200, {'status':'OK','findings':[finding()]}
        class Backend:
            result_index=Index()
        bad=template_for_scan(SCAN,[finding()]);bad['findings'][finding()['finding_id']]['anchor_sha256']='bad'
        with patch('ntk_cwss_context_api.read_published_profile',return_value=bad):
            status,payload=cwss_findings_page(Backend(),SCAN)
        self.assertEqual(status,422)
        self.assertEqual(payload['error_code'],'CWSS_CONTEXT_VALIDATION_ERROR')

if __name__=='__main__':
    unittest.main()
