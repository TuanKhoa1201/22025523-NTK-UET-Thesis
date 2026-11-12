"""Synthetic audit tests, never evidence of an engine/model run."""
import copy
import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
import recompute as r


class CounterTests(unittest.TestCase):
    def raw_fixture(self, root):
        # Fully synthetic protocol fixture; never described as runtime evidence.
        raw={'results':[{'check_id':'unit.rule','path':'A.java','start':{'line':2,'col':1},'end':{'line':2,'col':8},
                        'extra':{'metadata':{'cwe':['CWE-89']}}}], 'errors':[]}
        src=root/'src';src.mkdir();java=src/'A.java';java.write_bytes(b'class A {\n int x;\n}\n')
        scan=root/'opengrep.json';scan.write_text(json.dumps(raw));scan_hash=r.sha(scan.read_bytes());source_hash=r.sha(java.read_bytes())
        aid=r.sha((scan_hash+':0').encode())
        label={'alert_id':aid,'finding_index':0,'scan_sha256':scan_hash,'source_sha256':source_hash,
               'file_path':'A.java','start_line':2,'end_line':2,'rule_id':'unit.rule','cwe':'CWE-89','ground_truth':'TRUE_POSITIVE'}
        labels=root/'labels.json';labels.write_text(json.dumps({'labels':[label]}))
        artifacts={'opengrep.json':scan.read_bytes(),'rules.snapshot.yml':b'rules: []'};runs={}
        for n in ('version','json','sarif'):
            artifacts[n+'.exit.txt']=b'0';artifacts[n+'.command.json']=b'["UNIT"]';runs[n]={'exit_code':0,'argv':['UNIT']}
        for n,b in artifacts.items():(root/n).write_bytes(b)
        manifest=root/'manifest.json';manifest.write_text(json.dumps({'schema':'ntk-scan-capture-1','success':True,
            'artifacts':{n:r.sha(b) for n,b in artifacts.items()},'runs':runs,
            'sources_before':{'A.java':source_hash},'sources_after':{'A.java':source_hash},
            'rules_before_sha256':r.sha(artifacts['rules.snapshot.yml']),'rules_after_sha256':r.sha(artifacts['rules.snapshot.yml'])}))
        spec={'source_root':str(src),'scan':str(scan),'labels':str(labels),'scan_manifest':str(manifest),'arms':{}}
        quote={'path':'A.java','start_line':2,'end_line':2,'quote':' int x;','sha256':source_hash}
        for arm,mode in [('B','heuristic'),('C','evidence+llm'),('D','llm')]:
            ev={'id':aid,'finding_index':0,'scan_sha256':scan_hash,'rule_id':'unit.rule','cwe':['CWE-89'],
                'path':'A.java','start':raw['results'][0]['start'],'end':raw['results'][0]['end'],'raw_finding':raw['results'][0],
                'snapshots':{'A.java':{'sha256':source_hash}},'triage_mode':mode,'issues':[],
                'snippets':[{'role':'finding','path':'A.java','sha256':source_hash,'lines':[{'line':2,'text':' int x;'}]}]}
            ans={'status':'SUPPORTED','explanation':'UNIT','fix_suggestion':'','citations':[quote]}
            assessment={**ans,'transport':'heuristic-only' if arm=='B' else 'ollama-http','model':'qwen-unit',
                        'citation_check':'MATCHED','elapsed_seconds':.001,'runtime':{'origin':'unverified'},
                        'raw_response':None if arm=='B' else {'model':'qwen-unit','done':True,'message':{'content':json.dumps(ans)}}}
            path=root/(arm+'.jsonl');path.write_text(json.dumps({'id':aid,'evidence':ev,'assessment':assessment})+'\n')
            spec['arms'][arm]={'assessments':str(path)}
        return spec

    def test_raw_join_checks_detect_corruption_and_arm_swaps(self):
        with tempfile.TemporaryDirectory() as t:
            spec=self.raw_fixture(Path(t));a=r.Audit();m=r.raw_run(spec,a)
            self.assertEqual(a.status(),'INCOMPLETE')
            self.assertFalse(a.differences)
            self.assertEqual(m['C']['ALL']['n'],1)
            p=Path(spec['arms']['C']['assessments']);original=r.strict(p.read_bytes())
            for field,value in [('scan_sha256','f'*64),('rule_id','other'),('path','Wrong.java'),('cwe',['CWE-22']),('finding_index',3)]:
                changed=copy.deepcopy(original);changed['evidence'][field]=value;p.write_text(json.dumps(changed)+'\n')
                a=r.Audit();r.raw_run(spec,a);self.assertEqual(a.status(),'FAIL',field)
            p.write_text(json.dumps(original)+'\n')
            spec['arms']['C'],spec['arms']['D']=spec['arms']['D'],spec['arms']['C']
            a=r.Audit();r.raw_run(spec,a);self.assertEqual(a.status(),'FAIL')

    def test_raw_duplicate_missing_and_wrong_citation_are_detected(self):
        with tempfile.TemporaryDirectory() as t:
            spec=self.raw_fixture(Path(t));p=Path(spec['arms']['D']['assessments']);original=p.read_text()
            for text in ('',original+original):
                p.write_text(text);a=r.Audit();r.raw_run(spec,a);self.assertEqual(a.status(),'FAIL')
            row=r.strict(original);answer=r.strict(row['assessment']['raw_response']['message']['content'])
            answer['citations'][0]['quote']='wrong';row['assessment']['raw_response']['message']['content']=json.dumps(answer)
            p.write_text(json.dumps(row)+'\n');a=r.Audit();r.raw_run(spec,a)
            self.assertEqual(a.status(),'FAIL')
            self.assertTrue(any(d['field'].endswith('independent_post_replay') for d in a.differences))

    def rows(self):
        return [{'id': str(i), 'gt': gt, 'post': post, 'ms': ms, 'citation': 'MATCHED'}
                for i, (gt, post, ms) in enumerate([
                    ('TRUE_POSITIVE','SUPPORTED','1.1'),('TRUE_POSITIVE','REFUTED','2.2'),
                    ('TRUE_POSITIVE','UNDETERMINED',None),('FALSE_POSITIVE','REFUTED','3.3'),
                    ('FALSE_POSITIVE','SUPPORTED','4.4'),('FALSE_POSITIVE','UNDETERMINED','5.5')])]

    def test_all_six_cells_policy_denominators_and_distinct_tp_risks(self):
        m = r.metrics(self.rows())
        self.assertEqual(m['conclusive_coverage'], r.ratio(4,6))
        self.assertEqual(m['accuracy_all'], r.ratio(2,6))
        self.assertEqual(m['policies']['drop_fp']['precision'], r.ratio(2,4))
        self.assertEqual(m['policies']['drop_fp']['tp_excluded'], r.ratio(1,3))
        self.assertEqual(m['policies']['keep_tp_only']['tp_excluded'], r.ratio(2,3))
        self.assertFalse(m['latency']['complete'])
        self.assertIsNone(m['latency']['total_ms'])
        self.assertEqual(m['latency']['observed_total_ms'], '16.5')

    def test_zero_denominator_is_undefined(self):
        self.assertIsNone(r.metrics([])['selective_accuracy']['value'])

    def test_invalid_status_gt_and_latency_rejected(self):
        for k,v in [('post','FALSE_POSITIVE'),('gt','SUPPORTED'),('ms','NaN'),('ms','-1')]:
            rows=self.rows();rows[0][k]=v
            with self.subTest(k=k),self.assertRaises(ValueError):r.metrics(rows)

    def test_no_hardcoded_corpus_size(self):
        self.assertEqual(r.metrics(self.rows()*3)['n'],18)

    def test_raw_does_not_fall_back_to_post(self):
        self.assertEqual(r.metrics(self.rows())['raw_statuses'], {'None':6})

    def test_duplicate_and_changed_field_are_machine_readable(self):
        a=r.Audit();a.index([{'alert_id':'x'},{'alert_id':'x'}],__file__)
        a.compare('x','rule','one','two',__file__)
        self.assertEqual(a.status(),'FAIL')
        self.assertEqual(set(a.differences[0]),{'alert_id','field','expected','actual','source_file','source_sha256'})
        self.assertEqual(len(a.differences[0]['source_sha256']),64)

    def test_incomplete_is_not_pass(self):
        a=r.Audit();a.incomplete('raw absent');self.assertEqual(a.status(),'INCOMPLETE')

    def test_exit_codes_and_failure_precedence(self):
        a = r.Audit()
        a.compare('fixture', 'scoped_check', 1, 1, __file__)
        self.assertEqual((a.status(), a.exit_code()), ('PASS', 0))
        a.incomplete('runtime unavailable')
        self.assertEqual((a.status(), a.exit_code()), ('INCOMPLETE', 3))
        a.compare('fixture', 'hash', 'original', 'changed', __file__)
        self.assertEqual((a.status(), a.exit_code()), ('FAIL', 2))

    def test_complete_latency_and_raw_to_post_matrix(self):
        rows = self.rows()
        rows[2]['ms'] = '0.6'
        for row in rows:
            row['raw'] = 'SUPPORTED'
        m = r.metrics(rows)
        self.assertEqual(m['raw_to_post'], {'SUPPORTED->SUPPORTED': 2, 'SUPPORTED->REFUTED': 2,
                                          'SUPPORTED->UNDETERMINED': 2})
        self.assertEqual(m['raw_post_changes'], 4)
        self.assertEqual(m['latency']['total_ms'], '17.1')
        self.assertEqual(m['latency']['mean_ms'], '2.85')
        self.assertEqual(m['latency']['median_ms'], '2.75')
        self.assertEqual(m['latency']['p95_nearest_rank_ms'], '5.5')
        self.assertEqual(m['citation_matched_conclusive'], r.ratio(4, 4))
        self.assertEqual(m['citation_matched'], r.ratio(6, 6))

    def test_unobserved_measurement_is_not_zero(self):
        row = self.rows()[0]
        row.update(ms=None, citation=None, raw=None)
        m = r.metrics([row])
        self.assertIsNone(m['citation_matched']['value'])
        self.assertIsNone(m['latency']['total_ms'])
        self.assertEqual(m['raw_unavailable'], 1)
        self.assertEqual(m['raw_to_post'], {})

    def test_unknown_raw_status_or_cwe_rejected(self):
        row = self.rows()[0]
        row['raw'] = 'KEEP_TP'
        with self.assertRaises(ValueError):
            r.metrics([row])
        row.update(raw=None, cwe='CWE-79')
        with self.assertRaises(ValueError):
            r.by_group({'C': [row]})

    def public_fixture(self, folder):
        folder.mkdir()
        label = {'alert_id': 'synthetic', 'scan_sha256': 'a'*64, 'source_sha256': 'b'*64,
                 'finding_index': 0, 'file_path': 'Unit.java', 'start_line': 3, 'end_line': 4,
                 'cwe': 'CWE-89', 'rule_id': 'unit', 'ground_truth': 'FALSE_POSITIVE'}
        (folder/'labels_heldout.json').write_text(json.dumps({'labels': [label]}))
        row = {k: label[k] for k in ('alert_id', 'scan_sha256', 'source_sha256', 'finding_index', 'cwe', 'rule_id')}
        row.update(path='Unit.java', line='3-4', verified_ground_truth='FALSE_POSITIVE',
                   arm_a_opengrep_decision='KEEP', arm_b_heuristic_status='REFUTED',
                   arm_b_heuristic_decision='PROPOSED_FP', arm_b_citation_check='MATCHED',
                   arm_c_qwen35_raw_status='REFUTED', arm_c_qwen35_post_citation_status='REFUTED',
                   arm_c_qwen35_decision='PROPOSED_FP', arm_c_citation_check='MATCHED',
                   arm_c_latency_ms='1.25', arm_c_human_review_state='OPEN',
                   arm_d_llm_ablation_raw_status='SUPPORTED', arm_d_llm_ablation_decision='REVIEW',
                   arm_d_citation_check='NOT_VERIFIED', arm_d_latency_ms='2.75')
        self.write_csv(folder/'PAIRED_EVALUATION.csv', [row])
        return row

    def write_csv(self, path, rows):
        with path.open('w', encoding='utf-8', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader(); writer.writerows(rows)

    def run_cli(self, *args):
        return subprocess.run([sys.executable, '-X', 'utf8', '-B', str(Path(r.__file__)), *map(str, args)],
                              capture_output=True, text=True, timeout=20)

    def test_published_cli_incomplete_and_mutations_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp); data = base/'public'; row = self.public_fixture(data)
            result = self.run_cli('--published', data, '--output', base/'valid')
            self.assertEqual(result.returncode, 3, result.stderr)
            doc = r.strict((base/'valid/audit.json').read_bytes())
            self.assertFalse(doc['raw_runtime_verified'])
            self.assertEqual(doc['metrics']['B']['ALL']['fp_proposed'], 1)
            self.assertEqual(doc['metrics']['C']['ALL']['human_states'], {'OPEN': 1})
            self.assertEqual(doc['metrics']['D']['ALL']['raw_to_post'], {'SUPPORTED->UNDETERMINED': 1})
            with (base/'valid/published_per_alert.csv').open(newline='') as stream:
                self.assertEqual(len(list(csv.DictReader(stream))), 4)
            with (base/'valid/status_transitions.csv').open(newline='') as stream:
                transitions = list(csv.DictReader(stream))
            self.assertEqual([(x['arm'], x['raw'], x['post']) for x in transitions],
                             [('D', 'SUPPORTED', 'UNDETERMINED')])
            for i, (field, bad) in enumerate([('arm_b_heuristic_decision', 'KEEP_TP'),
                    ('arm_c_qwen35_decision', 'REVIEW'), ('arm_d_llm_ablation_raw_status', 'INVALID'),
                    ('arm_c_latency_ms', '-1'), ('line', '4-5'), ('rule_id', 'wrong')]):
                changed = dict(row); changed[field] = bad
                self.write_csv(data/'PAIRED_EVALUATION.csv', [changed])
                result = self.run_cli('--published', data, '--output', base/str(i))
                self.assertEqual(result.returncode, 2, (field, result.stdout, result.stderr))
                self.assertEqual(r.strict((base/str(i)/'audit.json').read_bytes())['status'], 'FAIL')

    def test_published_missing_raw_and_latency_remain_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp); data = base/'public'; row = self.public_fixture(data)
            row.update(arm_c_qwen35_raw_status='', arm_d_latency_ms='')
            self.write_csv(data/'PAIRED_EVALUATION.csv', [row])
            result = self.run_cli('--published', data, '--output', base/'out')
            self.assertEqual(result.returncode, 3, result.stderr)
            doc = r.strict((base/'out/audit.json').read_bytes())
            self.assertEqual(doc['metrics']['C']['ALL']['raw_unavailable'], 1)
            self.assertIsNone(doc['metrics']['D']['ALL']['latency']['total_ms'])

    def test_cli_missing_invalid_and_output_protection(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            result = self.run_cli('--spec', base/'missing.json', '--output', base/'missing')
            self.assertEqual(result.returncode, 3, result.stderr)
            spec = base/'invalid.json'; spec.write_text('{')
            result = self.run_cli('--spec', spec, '--output', base/'invalid')
            self.assertEqual(result.returncode, 2, result.stderr)
            result = self.run_cli('--spec', spec, '--output', base/'invalid')
            self.assertEqual(result.returncode, 2)
            data = base/'public'; self.public_fixture(data)
            result = self.run_cli('--published', data, '--output', data/'output')
            self.assertEqual(result.returncode, 2)
            self.assertFalse((data/'output').exists())

    def test_reported_aggregates_recomputed_and_tampering_fails(self):
        rows = [self.rows()[0], self.rows()[3]]  # TP supported, FP refuted, latency 1.1 + 3.3.
        calculated = {'C': {'ALL': r.metrics(rows)}}
        row = {'arm': 'Arm_C_Evidence_LLM', 'cwe_group': 'ALL (CWE-22 + CWE-89)',
               'total_alerts': '2', 'labeled_tp': '1', 'labeled_fp': '1',
               'tp_kept_supported': '1/1 (100.0%)', 'tp_retained_total_with_review': '1/1 (100.0%)',
               'fp_correctly_proposed_refuted': '1/1 (100.0%)', 'tp_erroneously_proposed_fp': '0/1 (0.0%)',
               'undetermined_review_rate': '0/2 (0.0%)', 'citation_verified_rate': '2/2 (100.0%)',
               'policy_drop_fp_precision': '1/1 (100.0%)', 'policy_drop_fp_tp_recall': '1/1 (100.0%)',
               'policy_keep_tp_only_precision': '1/1 (100.0%)', 'policy_keep_tp_only_tp_recall': '1/1 (100.0%)',
               'mean_latency_ms': '2.2', 'p50_latency_ms': '2.2', 'p95_latency_ms': '3.3'}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'aggregate.csv'; self.write_csv(path, [row]); audit = r.Audit()
            r.compare_reported_metrics(path, calculated, audit)
            self.assertEqual(audit.status(), 'PASS')  # Scoped arithmetic only, synthetic.
            for field, value in [('fp_correctly_proposed_refuted', '0/1 (0.0%)'),
                                 ('policy_drop_fp_precision', '1/1 (50.0%)'), ('mean_latency_ms', '0')]:
                changed = dict(row); changed[field] = value
                self.write_csv(path, [changed]); audit = r.Audit()
                r.compare_reported_metrics(path, calculated, audit)
                self.assertEqual(audit.status(), 'FAIL', field)
            self.write_csv(path, [row, row]); audit = r.Audit()
            r.compare_reported_metrics(path, calculated, audit)
            self.assertEqual(audit.status(), 'FAIL')

    def test_strict_json_rejects_duplicate_and_nonfinite(self):
        for s in ('{"x":1,"x":2}','{"x":NaN}','{'):
            with self.assertRaises(ValueError):r.strict(s)

    def test_paths_cannot_escape(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)/'project';root.mkdir();(Path(t)/'outside.java').write_text('private')
            with self.assertRaises(ValueError):r.safe_file(root,'../outside.java')

    def test_citation_wrong_quote_position_hash_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'A.java';p.write_bytes(b'class A {\n  int x;\n}\n')
            ev={'snippets':[{'path':'A.java','lines':[{'line':1,'text':'class A {'},{'line':2,'text':'  int x;'}]}]}
            ans={'status':'SUPPORTED','citations':[{'path':'A.java','start_line':2,'end_line':2,'quote':'  int x;','sha256':r.sha(p.read_bytes())}]}
            self.assertEqual(r.citations(ev,ans,t),'MATCHED')
            for k,v in [('quote','int x;'),('start_line',1),('sha256','0'*64),('end_line',999)]:
                changed=copy.deepcopy(ans);changed['citations'][0][k]=v
                self.assertEqual(r.citations(ev,changed,t),'NOT_VERIFIED')
            p.write_text('class Changed {}')
            self.assertEqual(r.citations(ev,ans,t),'NOT_VERIFIED')

    def test_manifest_raw_tampering_detected(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t);java=p/'A.java';java.write_bytes(b'class A {}')
            artifacts={'opengrep.json':b'{"results":[]}', 'rules.snapshot.yml':b'rules: []'}
            runs={}
            for name in ('version','json','sarif'):
                artifacts[name+'.exit.txt']=b'0';artifacts[name+'.command.json']=b'["SYNTHETIC"]'
                runs[name]={'argv':['SYNTHETIC'],'exit_code':0}
            for n,b in artifacts.items():(p/n).write_bytes(b)
            d={'schema':'ntk-scan-capture-1','success':True,'artifacts':{n:r.sha(b) for n,b in artifacts.items()},
               'runs':runs,'sources_before':{'A.java':r.sha(java.read_bytes())},'sources_after':{'A.java':r.sha(java.read_bytes())},
               'rules_before_sha256':r.sha(artifacts['rules.snapshot.yml']),'rules_after_sha256':r.sha(artifacts['rules.snapshot.yml'])}
            f=p/'manifest.json';f.write_text(json.dumps(d));a=r.Audit()
            r.check_manifest(f,artifacts['opengrep.json'],p,a);self.assertEqual(a.status(),'PASS')
            (p/'opengrep.json').write_bytes(b'{"results":["tampered"]}')
            a=r.Audit();r.check_manifest(f,artifacts['opengrep.json'],p,a);self.assertEqual(a.status(),'FAIL')
