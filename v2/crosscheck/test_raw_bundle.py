"""Portable synthetic counterexamples; no dependence on private evidence or services."""
import copy
from contextlib import closing
import csv
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest

import audit_raw_bundle as b
import recompute as c
import test_recompute as fixture_tests


class BundleTests(unittest.TestCase):
    def fixture(self, root):
        protocol=root/'protocol';protocol.mkdir()
        fixture_tests.CounterTests().raw_fixture(protocol)
        e=root/'evidence';scan_dir=e/'runs'/b.SCAN_DIRS['heldout'][0]
        scan_dir.mkdir(parents=True);source=e/'sources/heldout_set_40';source.mkdir(parents=True)
        shutil.copyfile(protocol/'src/A.java',source/'A.java')
        for f in protocol.iterdir():
            if f.is_file() and f.name not in {'labels.json','manifest.json'} and not f.name.endswith('.jsonl'):
                shutil.copyfile(f,scan_dir/f.name)
        sarif={'version':'2.1.0','runs':[{'tool':{'driver':{'rules':[{'id':'unit.rule','properties':{'tags':['CWE-89']}}]}},
            'results':[{'ruleId':'unit.rule','locations':[{'physicalLocation':{'artifactLocation':{'uri':'A.java'},
                'region':{'startLine':2,'endLine':2,'startColumn':1,'endColumn':8}}}]}]}]}
        (scan_dir/'opengrep.sarif').write_text(json.dumps(sarif))
        (scan_dir/'version.stdout.txt').write_text('UNIT_FIXTURE')
        manifest=c.strict((protocol/'manifest.json').read_bytes())
        manifest.update(source_root='C:/synthetic/source',issues=[])
        (scan_dir/'rules.snapshot.yml').write_bytes(b'rules:\n  - id: unit.rule\n')
        rule_hash=c.sha((scan_dir/'rules.snapshot.yml').read_bytes())
        manifest['rules_before_sha256']=manifest['rules_after_sha256']=rule_hash
        manifest['artifacts']['rules.snapshot.yml']=rule_hash
        manifest['artifacts']['opengrep.sarif']=c.sha((scan_dir/'opengrep.sarif').read_bytes())
        (scan_dir/'scan-manifest.json').write_text(json.dumps(manifest))
        a=b.Audit();scan=b.inspect_scan(e,'heldout',a)
        self.assertFalse(a.differences)  # Only trace is absent in this synthetic scan.
        aid=next(iter(scan['findings']))
        ev=c.strict((protocol/'C.jsonl').read_bytes())['evidence']
        ev.update(alert_id=aid,raw_trace=None,root=manifest['source_root'],path_mappings=[],
                  scan_provenance={'manifest_sha256':c.sha((scan_dir/'scan-manifest.json').read_bytes()),'recorded_engine_exit':0})
        ev['snapshots']['A.java']['size']=(source/'A.java').stat().st_size
        bundle={'scan_sha256':scan['hash'],'raw_document':scan['doc'],'records':[ev]}
        label=c.strict((protocol/'labels.json').read_bytes())['labels'][0]
        for arm in 'BCD':
            folder=e/'runs'/arm;folder.mkdir()
            row=c.strict((protocol/(arm+'.jsonl')).read_bytes());row['evidence'].update(copy.deepcopy(ev))
            row['evidence']['triage_mode']={'B':'heuristic','C':'evidence+llm','D':'llm'}[arm]
            row.update(alert_id=aid,scan_sha256=scan['hash'],finding_index=0,state='OPEN')
            ans=row['assessment'];ans.update(security_conclusion_verified=False,requires_human_review=True)
            if arm!='B':
                ans['runtime'].update(response_json_sha256=b.digest_json(ans['raw_response']),finding_id=aid,
                                      http_status=200,http_response_received=True)
            (folder/'assessments.jsonl').write_text(json.dumps(row)+'\n')
            (folder/'input.opengrep.json').write_bytes(scan['path'].read_bytes())
            local_bundle=copy.deepcopy(bundle);local_bundle['records']=[row['evidence']]
            (folder/'evidence.json').write_text(json.dumps(local_bundle))
            self.write_db(folder/'review.sqlite',row,local_bundle)
            cp=e/'checkpoints';cp.mkdir(exist_ok=True)
            if arm!='B': (cp/(arm+'.ckpt.jsonl')).write_text(json.dumps({'id':aid,'assessment':ans})+'\n')
        return e,scan,{aid:label}

    def write_db(self,path,row,bundle):
        with closing(sqlite3.connect(path)) as db, db:
            db.executescript('''CREATE TABLE scans(id TEXT PRIMARY KEY,bundle TEXT);
              CREATE TABLE warnings(id TEXT PRIMARY KEY,scan_id TEXT,evidence TEXT,assessment TEXT,state TEXT);
              CREATE TABLE events(sequence INTEGER PRIMARY KEY,warning_id TEXT,actor TEXT,timestamp TEXT,
                action TEXT,reason TEXT,source_version TEXT,observed_version TEXT,evidence_sha256 TEXT);''')
            db.execute('INSERT INTO scans VALUES (?,?)',(row['scan_sha256'],b.canonical(bundle)))
            db.execute('INSERT INTO warnings VALUES (?,?,?,?,?)',(row['id'],row['scan_sha256'],b.canonical(row['evidence']),b.canonical(row['assessment']),row['state']))

    def inspect(self,e,scan,labels,arm='C'):
        audit=b.Audit();result=b.inspect_run(e,arm,scan,arm,labels,audit)
        return audit,result

    def test_valid_scoped_run_and_heuristic_zero_not_measured(self):
        with tempfile.TemporaryDirectory() as t:
            e,scan,labels=self.fixture(Path(t));before=b.inventory(e)
            audit,result=self.inspect(e,scan,labels)
            self.assertEqual(audit.status(),'PASS',audit.differences)
            self.assertEqual(result['metrics']['ALL']['latency']['observed'],1)
            audit,result=self.inspect(e,scan,labels,'B')
            self.assertEqual(audit.status(),'PASS',audit.differences)
            self.assertIsNone(result['metrics']['ALL']['latency']['total_ms'])
            self.assertEqual(before,b.inventory(e))

    def test_reordered_sarif_equivalent_and_wrong_identity_rejected(self):
        manifest={'source_root':'C:/source','sources_before':{'A.java':'hash'}}
        f={'check_id':'one','path':'A.java','start':{'line':1,'col':1},'end':{'line':1,'col':2}}
        g=copy.deepcopy(f);g['check_id']='two'
        self.assertEqual(b.Counter(map(lambda x:b.finding_key(x,manifest),[f,g])),
                         b.Counter(map(lambda x:b.finding_key(x,manifest),[g,f])))
        with tempfile.TemporaryDirectory() as t:
            e,scan,labels=self.fixture(Path(t));p=scan['path'].with_suffix('.sarif')
            sarif=b.read_json(p);sarif['runs'][0]['results'][0]['ruleId']='other';p.write_text(json.dumps(sarif))
            audit=b.Audit();b.inspect_scan(e,'heldout',audit)
            self.assertEqual(audit.status(),'FAIL')
            self.assertTrue(any(d['field']=='sarif.finding_multiset' for d in audit.differences))
            # Counter keys in a discrepancy must still serialize, not crash the gate.
            json.dumps(b.jsonable(audit.register))

    def test_raw_scan_missing_modified_and_duplicate_finding(self):
        for change in ('missing','modified','duplicate'):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as t:
                e,scan,labels=self.fixture(Path(t));path=scan['path']
                if change=='missing': path.unlink()  # Synthetic temp file only.
                else:
                    doc=b.read_json(path)
                    if change=='modified':doc['results'][0]['check_id']='tampered'
                    else:doc['results'].append(copy.deepcopy(doc['results'][0]))
                    path.write_text(json.dumps(doc))
                audit=b.Audit();b.protected_call(audit,'scan',lambda:b.inspect_scan(e,'heldout',audit))
                self.assertNotEqual(audit.status(),'PASS')

    def test_reordered_assessment_ids_are_not_positional(self):
        a=b.Audit();rows=[{'id':'two','value':2},{'id':'one','value':1}]
        self.assertEqual(a.index(rows,__file__,'id'),a.index(list(reversed(rows)),__file__,'id'))
        self.assertEqual(a.status(),'PASS')

    def test_duplicate_missing_and_arm_swap_are_rejected(self):
        for change in ('duplicate','missing','arm_swap'):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as t:
                e,scan,labels=self.fixture(Path(t));p=e/'runs/C/assessments.jsonl';original=p.read_text()
                p.write_text(original+original if change=='duplicate' else '' if change=='missing' else (e/'runs/D/assessments.jsonl').read_text())
                audit,result=self.inspect(e,scan,labels)
                self.assertEqual(audit.status(),'FAIL')

    def test_raw_and_post_verdict_changes_rejected(self):
        for change in ('raw','post'):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as t:
                e,scan,labels=self.fixture(Path(t));p=e/'runs/C/assessments.jsonl';row=b.read_jsonl(p)[0]
                if change=='post':row['assessment']['status']='REFUTED'
                else:
                    content=c.strict(row['assessment']['raw_response']['message']['content']);content['status']='REFUTED'
                    row['assessment']['raw_response']['message']['content']=json.dumps(content)
                p.write_text(json.dumps(row)+'\n');audit,result=self.inspect(e,scan,labels)
                self.assertEqual(audit.status(),'FAIL')
                self.assertTrue(any(d['field']=='replay.post' for d in audit.differences))

    def test_wrong_citation_source_hash_and_modified_java_rejected(self):
        for change in ('path','sha256','source'):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as t:
                e,scan,labels=self.fixture(Path(t));p=e/'runs/C/assessments.jsonl';row=b.read_jsonl(p)[0]
                if change=='source':(scan['root']/'A.java').write_text('class Changed {}')
                else:
                    content=c.strict(row['assessment']['raw_response']['message']['content'])
                    content['citations'][0][change]='outside.java' if change=='path' else 'f'*64
                    row['assessment']['raw_response']['message']['content']=json.dumps(content)
                    p.write_text(json.dumps(row)+'\n')
                audit,result=self.inspect(e,scan,labels)
                self.assertEqual(audit.status(),'FAIL')

    def test_multiline_quote_and_fallback_citation_are_distinct(self):
        with tempfile.TemporaryDirectory() as t:
            e,scan,labels=self.fixture(Path(t));row=b.read_jsonl(e/'runs/D/assessments.jsonl')[0]
            ev=row['evidence'];ans=row['assessment']
            ev['snippets'][0]['lines']=[{'line':1,'text':'class A {'},{'line':2,'text':' int x;'}]
            answer=c.strict(ans['raw_response']['message']['content']);answer['citations'][0].update(start_line=1,end_line=2,quote='class A {\n int x;')
            ans['raw_response']['message']['content']=json.dumps(answer)
            self.assertEqual(b.replay_answer(ev,ans,scan['root'])[1:3],('SUPPORTED','MATCHED'))
            answer['citations'][0]['quote']='wrong';ans['raw_response']['message']['content']=json.dumps(answer)
            ans.update(status='UNDETERMINED',citations=[],citation_check='NOT_VERIFIED')
            self.assertEqual(c.citations(ev,ans,scan['root']),'NONE')
            self.assertEqual(b.replay_answer(ev,ans,scan['root'])[1:3],('UNDETERMINED','NOT_VERIFIED'))

    def test_swapped_latency_same_total_detected_per_alert(self):
        with tempfile.TemporaryDirectory() as t:
            e,scan,labels=self.fixture(Path(t));aid=next(iter(labels));other='other'
            labels[other]=dict(labels[aid],alert_id=other)
            fake_scan={'findings':{aid:None,other:None}}
            base={'gt':'TRUE_POSITIVE','cwe':'CWE-89','post':'SUPPORTED','raw':'SUPPORTED','citation':'MATCHED','human':'OPEN'}
            records=[dict(base,id=aid,ms='1000.000000001'),dict(base,id=other,ms='2000')]
            rows=[]
            for ident,ms in ((aid,'2000'),(other,'1000')):
                l=labels[ident]
                rows.append(dict(alert_id=ident,scan_sha256=l['scan_sha256'],source_sha256=l['source_sha256'],rule_id=l['rule_id'],cwe=l['cwe'],
                                 finding_index=str(l['finding_index']),path=l['file_path'],verified_ground_truth=l['ground_truth'],
                                 arm_c_qwen35_decision='KEEP_TP',arm_c_citation_check='MATCHED',arm_c_qwen35_raw_status='SUPPORTED',
                                 arm_c_qwen35_post_citation_status='SUPPORTED',arm_c_human_review_state='OPEN',arm_c_latency_ms=ms))
            p=Path(t)/'paired.csv'
            with p.open('w',newline='') as stream:
                w=csv.DictWriter(stream,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
            audit=b.Audit();b.compare_paired(p,fake_scan,labels,{'C':{'ALL':{'per_finding':records}}},audit)
            self.assertEqual(len([d for d in audit.differences if 'latency' in d['field']]),2)

    def test_sqlite_state_event_conflict_and_stale_false_are_rejected(self):
        for change in ('state_without_event','stale_false','wrong_event_evidence'):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as t:
                e,scan,labels=self.fixture(Path(t));folder=e/'runs/C';p=folder/'review.sqlite';row=b.read_jsonl(folder/'assessments.jsonl')[0]
                ev=row['evidence']
                with closing(sqlite3.connect(p)) as db, db:
                    if change=='state_without_event':db.execute("UPDATE warnings SET state='CONFIRMED_FALSE'")
                    else:
                        observed={k:v['sha256'] for k,v in ev['snapshots'].items()}
                        if change=='stale_false':observed['A.java']='f'*64
                        db.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)',(1,row['id'],'SCRIPTED-UNIT','2026-01-01T00:00:00Z','confirm-false','unit reason',b.canonical(ev['snapshots']),b.canonical(observed),b.digest_json(ev) if change=='stale_false' else '0'*64,))
                audit=b.Audit();b.verify_sqlite(p,{row['id']:row},audit)
                self.assertEqual(audit.status(),'FAIL')
                wanted={'state_without_event':'sqlite.event_state','stale_false':'sqlite.false_source_fresh',
                        'wrong_event_evidence':'sqlite.event_evidence_hash'}[change]
                self.assertTrue(any(d['field']==wanted for d in audit.differences))

    def test_path_mapping_requires_exact_captured_root(self):
        m={'source_root':'C:/captured','sources_before':{'A.java':'hash'}}
        self.assertEqual(b.source_path('C:\\captured\\A.java',m),'A.java')
        for path in ('C:/captured-other/A.java','/mnt/c/unrelated/A.java','../A.java'):
            with self.assertRaises(ValueError):b.source_path(path,m)

    def test_record_mapping_and_capture_hash_are_checked(self):
        for change in ('mapping.target','mapping.source','provenance.manifest_sha256'):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as t:
                e,scan,labels=self.fixture(Path(t));p=e/'runs/C/assessments.jsonl';row=b.read_jsonl(p)[0]
                ev=row['evidence'];ev['path_mappings']=[{'from':'/mnt/c/synthetic/source','to':'C:/synthetic/source'}]
                if change=='mapping.target':ev['path_mappings'][0]['to']='C:/wrong'
                elif change=='mapping.source':ev['path_mappings'][0]['from']='/mnt/c/wrong'
                else:ev['scan_provenance']['manifest_sha256']='f'*64
                p.write_text(json.dumps(row)+'\n');audit,result=self.inspect(e,scan,labels)
                self.assertTrue(any(d['field']==change for d in audit.differences))

    def test_missing_latency_is_incomplete_even_when_copies_agree(self):
        with tempfile.TemporaryDirectory() as t:
            e,scan,labels=self.fixture(Path(t));folder=e/'runs/C';p=folder/'assessments.jsonl';row=b.read_jsonl(p)[0]
            row['assessment'].pop('elapsed_seconds')
            p.write_text(json.dumps(row)+'\n')
            (e/'checkpoints/C.ckpt.jsonl').write_text(json.dumps({'id':row['id'],'assessment':row['assessment']})+'\n')
            with closing(sqlite3.connect(folder/'review.sqlite')) as db,db:
                db.execute('UPDATE warnings SET assessment=?',(b.canonical(row['assessment']),))
            audit,result=self.inspect(e,scan,labels)
            self.assertEqual(audit.status(),'INCOMPLETE',audit.differences)
            self.assertIsNone(result['metrics']['ALL']['latency']['total_ms'])

    def test_wrong_label_and_cwe_rejected_against_separate_catalog(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);e,scan,labels=self.fixture(root)
            official=root/'expected.csv';official.write_bytes(b'A,sqli,true,89\n')
            def blob(data):return b.hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
            reference=root/'reference.json'
            reference.write_text(json.dumps({'commit':'8b67a88d73b2594570fc21150705283de884620b',
                'files':[{'path':'A.java','sha':blob((scan['root']/'A.java').read_bytes())},
                         {'path':'expectedresults-1.2.csv','sha':blob(official.read_bytes())}]}))
            path=root/'labels.json'
            for field,value in [('ground_truth','FALSE_POSITIVE'),('cwe','CWE-22')]:
                row=copy.deepcopy(next(iter(labels.values())));row[field]=value
                path.write_text(json.dumps({'labels':[row]}));audit=b.Audit()
                b.verify_labels(path,scan,official,reference,audit)
                self.assertEqual(audit.status(),'FAIL',field)

    def test_missing_package_cannot_be_forced_pass_by_receipt(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);package=root/'package';package.mkdir()
            (package/'receipt.json').write_text('{"status":"PASS"}')
            proc=subprocess.run([sys.executable,'-X','utf8','-B',str(Path(b.__file__)),'--package',str(package),'--output',str(root/'out')],capture_output=True,text=True,timeout=20)
            self.assertEqual(proc.returncode,3,proc.stderr)
            result=b.read_json(root/'out/audit.private.json')
            self.assertEqual(result['status'],'INCOMPLETE')
            self.assertFalse(result['runtime_attested'])
