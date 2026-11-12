"""Synthetic counterexamples and published-receipt checks; no engine/model runs."""
import copy
import csv
import json
from pathlib import Path
import tempfile
import unittest
import audit_raw_bundle as b
import recompute as c
import resolve_g0 as r
import finalize_public as f


class GateTests(unittest.TestCase):
    def receipt(self):
        raw=f.load('G0_RAW_INDEPENDENT_VERDICT.json')
        return dict(raw,exit_code=raw['automated_audit_exit_code'],limitations_recorded=True)

    def test_reproduction(self):
        state=f.derive()
        report=f.load('G0_FINAL_RESOLUTION.json')
        for k,v in state.items(): self.assertEqual(report[k],v,k)

    def test_required_arm_c(self):
        a=self.receipt();del a['criteria']['run_stage4_heldout40_armC_evidence_llm']
        self.assertEqual(r.acceptance(a,{'rows_columns_equal':True}),'BLOCKED')
        self.assertFalse(r.execution_completed(a))

    def test_missing_receipt_never_complete(self):
        for key in ('register','checked_fields','checks','exit_code','limitations_recorded'):
            a=self.receipt();del a[key]
            self.assertFalse(r.execution_completed(a),key)

    def test_bad_exit(self):
        a=self.receipt();a['exit_code']=0
        self.assertEqual(r.acceptance(a,{'rows_columns_equal':True},f.load('G0_ERRATA_REGISTER.json')),'BLOCKED')

    def test_errata_binding_and_pending(self):
        a=self.receipt();e=f.load('G0_ERRATA_REGISTER.json')
        row=next(x for x in a['register'] if x['status']=='FAIL')
        self.assertEqual(r.classify(row,e)[0],'ERRATA_ISSUED')
        for key in ('expected','actual','source_sha256','alert_id','criterion'):
            x=dict(row);x[key]='unrelated'
            self.assertEqual(r.classify(x,e)[0],'UNRESOLVED_FAIL',key)
        self.assertTrue(all(x['approval']=='PENDING' for x in e))
        x=dict(row,criterion='owasp_labels_and_sources')
        self.assertFalse(r.valid_errata(x,[dict(x,check_id='X',errata_id='X',approval='APPROVED')]))

    def paired(self, mutation):
        labels={};records=[];rows=[]
        for i in range(2):
            aid=str(i);label=dict(scan_sha256='s',source_sha256='h',rule_id='r',cwe='CWE-89',finding_index=i,file_path=aid+'.java',ground_truth='TRUE_POSITIVE')
            labels[aid]=label
            rec=dict(id=aid,post='SUPPORTED' if i==0 else 'UNDETERMINED',raw='REFUTED' if i==0 else 'SUPPORTED',citation='MATCHED',human='PENDING',ms=str(i+1))
            records.append(rec)
            row=dict(alert_id=aid,**{k:label[k] for k in ('scan_sha256','source_sha256','rule_id','cwe')},finding_index=str(i),path=label['file_path'],verified_ground_truth=label['ground_truth'])
            row.update(arm_c_qwen35_decision=c.DECISION[rec['post']],arm_c_citation_check='MATCHED',arm_c_qwen35_raw_status=rec['raw'],arm_c_qwen35_post_citation_status=rec['post'],arm_c_human_review_state='PENDING',arm_c_latency_ms=rec['ms'])
            rows.append(row)
        mutation(rows)
        with tempfile.TemporaryDirectory() as t:
            path=Path(t)/'paired.csv'
            with path.open('w',newline='',encoding='utf8') as stream:
                w=csv.DictWriter(stream,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
            audit=b.Audit()
            b.compare_paired(path,{'findings':labels},labels,{'C':{'ALL':{'per_finding':records}}},audit)
            return audit.differences

    def test_status_swap(self):
        def mutate(rows):
            rows[0]['arm_c_qwen35_raw_status'],rows[1]['arm_c_qwen35_raw_status']=rows[1]['arm_c_qwen35_raw_status'],rows[0]['arm_c_qwen35_raw_status']
        self.assertTrue(self.paired(mutate))

    def test_compensating_latency(self):
        self.assertTrue(self.paired(lambda rows: (rows[0].update(arm_c_latency_ms='1.5'),rows[1].update(arm_c_latency_ms='1.5'))))

    def test_missing_and_duplicate(self):
        self.assertTrue(self.paired(lambda rows: rows.pop()))
        self.assertTrue(self.paired(lambda rows: rows.append(dict(rows[0]))))

    def test_raw_post_inversion(self):
        def mutate(rows):
            for row in rows:
                row['arm_c_qwen35_raw_status'],row['arm_c_qwen35_post_citation_status']=row['arm_c_qwen35_post_citation_status'],row['arm_c_qwen35_raw_status']
        self.assertTrue(self.paired(mutate))

    def test_ground_truth_and_identity(self):
        for key in ('verified_ground_truth','source_sha256','rule_id','cwe'):
            self.assertTrue(self.paired(lambda rows: rows[0].update({key:'CORRUPTED'})),key)

    def test_baseline_pair_matches(self):
        self.assertFalse(self.paired(lambda rows: None))
