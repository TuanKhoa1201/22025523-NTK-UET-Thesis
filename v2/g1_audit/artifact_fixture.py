"""SYNTHETIC ONLY: internally consistent artifacts for auditor positive/negative controls.

No engine, HTTP or model runs. Version/executable strings are planted protocol data.
The aggregate audit must remain INCOMPLETE for these unsigned files.
"""
import copy
import json
from pathlib import Path
import sqlite3
from contextlib import closing
from audit import sha


class Fixture:
    def __init__(self, root, count=2):
        self.root = Path(root); self.source = self.root / 'source'; self.source.mkdir()
        self.engine = self.root / 'engine'; self.engine.mkdir()
        self.text = 'class Probe {\n void run(String q) {\n  stmt.executeQuery(q);\n }\n}\n'
        self.java = self.source / 'Probe.java'; self.java.write_bytes(self.text.encode())
        self.source_hash = sha(self.java.read_bytes())
        self.finding = dict(check_id='synthetic.full.rule.cwe89',path='Probe.java',
            start=dict(line=3,col=3),end=dict(line=3,col=23),extra=dict(severity='ERROR',metadata={'cwe':['CWE-89']},
                dataflow_trace={'synthetic':'trace preserved; no scan performed'}))
        self.doc = dict(version='1.25.0',results=[copy.deepcopy(self.finding) for _ in range(count)],errors=[])
        self.raw = json.dumps(self.doc).encode(); self.scan = sha(self.raw)
        self.records = []
        for i, finding in enumerate(self.doc['results']):
            ident = sha((self.scan+':'+str(i)).encode())
            rec = dict(schema_version='1.1',id=ident,alert_id=ident,finding_index=i,scan_sha256=self.scan,
                root=str(self.source),rule_id=finding['check_id'],path=finding['path'],start=finding['start'],end=finding['end'],
                cwe=['CWE-89'],severity='ERROR',raw_finding=finding,raw_trace=finding['extra']['dataflow_trace'],
                snapshots={'Probe.java':{'sha256':self.source_hash,'size':len(self.java.read_bytes())}},
                snippets=[dict(path='Probe.java',role='finding',start=finding['start'],end=finding['end'],
                    sha256=self.source_hash,matched=self.text.splitlines()[2][2:22],
                    lines=[{'line':i+1,'text':line} for i,line in enumerate(self.text.splitlines())])],
                issues=[],scan_provenance={'source_capture_verified':True})
            self.records.append(rec)
        self.bundle = dict(schema_version='1.1',scan_sha256=self.scan,root=str(self.source),raw_document=self.doc,
                           issues=[],records=self.records)
        self.rows = [dict(schema_version='1.1',id=r['id'],alert_id=r['id'],scan_sha256=self.scan,finding_index=i,
            state='OPEN',evidence=r,assessment=dict(status='UNDETERMINED',explanation='SYNTHETIC fixture; no model run',
                fix_suggestion='',citations=[],requires_human_review=True,security_conclusion_verified=False,
                runtime=dict(origin='mock',request_attempted=False,http_response_received=False,answer_validated=False)))
            for i,r in enumerate(self.records)]
        self.sarif = dict(version='2.1.0',runs=[dict(invocations=[{'executionSuccessful':True}],
            tool={'driver':{'name':'SYNTHETIC FIXTURE','semanticVersion':'1.25.0','rules':[
                dict(id=self.finding['check_id'],defaultConfiguration={'level':'error'},properties={'tags':['CWE-89']})]}},
            results=[dict(ruleId=self.finding['check_id'],ruleIndex=0,locations=[dict(physicalLocation=dict(
                artifactLocation={'uri':'Probe.java','uriBaseId':'%SRCROOT%'},
                region={'startLine':3,'endLine':3,'startColumn':3,'endColumn':23}))]) for _ in range(count)])])
        self.write('input.opengrep.json', self.raw); self.write('engine/opengrep.json', self.raw)
        self.write('evidence.json', self.bundle); self.write('assessments.jsonl', b''.join(json.dumps(r).encode()+b'\n' for r in self.rows))
        self.write('engine/opengrep.sarif', self.sarif)
        self.write('engine/rules.snapshot.yml', b'# SYNTHETIC ONLY\nrules: []\n')
        rules = str(self.engine / 'rules.snapshot.yml')
        runs = {}
        for label in ('version','json','sarif'):
            argv = ['opengrep','--version'] if label == 'version' else ['opengrep','scan','--config',rules,'--'+label,str(self.source)]
            runs[label] = dict(argv=argv,exit_code=0)
            self.write('engine/'+label+'.command.json', argv)
            self.write('engine/'+label+'.exit.txt', b'0')
            body = b'1.25.0\n' if label == 'version' else (self.engine/('opengrep.'+label)).read_bytes()
            self.write('engine/'+label+'.stdout.txt', body); self.write('engine/'+label+'.stderr.txt', b'')
        inventory = {'Probe.java':self.source_hash}
        self.manifest = dict(schema='ntk-scan-capture-1',producer='SYNTHETIC_AUDITOR_FIXTURE_NO_RUNTIME',
            source_root=str(self.source),target_kind='directory',sources_before=inventory,sources_after=copy.deepcopy(inventory),
            rules_before_sha256=sha((self.engine/'rules.snapshot.yml').read_bytes()),
            rules_after_sha256=sha((self.engine/'rules.snapshot.yml').read_bytes()),runs=runs,artifacts={},success=True,issues=[],
            started_at='2026-11-01T00:00:00+00:00',finished_at='2026-11-01T00:00:01+00:00')
        self.rehash(); self.database()

    def write(self, name, value):
        p = self.root/name
        p.write_bytes(value if isinstance(value, bytes) else json.dumps(value, ensure_ascii=False).encode())

    def rehash(self):
        self.manifest['artifacts'] = {p.name:sha(p.read_bytes()) for p in self.engine.iterdir() if p.name != 'scan-manifest.json'}
        self.write('engine/scan-manifest.json',self.manifest)

    def database(self):
        with closing(sqlite3.connect(self.root/'review.sqlite')) as db, db:
            db.executescript('''CREATE TABLE scans(id TEXT PRIMARY KEY,bundle TEXT NOT NULL);
                CREATE TABLE warnings(id TEXT PRIMARY KEY,scan_id TEXT REFERENCES scans(id),evidence TEXT,assessment TEXT,state TEXT);
                CREATE TABLE events(sequence INTEGER PRIMARY KEY,warning_id TEXT REFERENCES warnings(id),actor TEXT,timestamp TEXT,
                action TEXT,reason TEXT,source_version TEXT,observed_version TEXT,evidence_sha256 TEXT);''')
            db.execute('INSERT INTO scans VALUES (?,?)',(self.scan,json.dumps(self.bundle)))
            for r,row in zip(self.records,self.rows):
                db.execute('INSERT INTO warnings VALUES (?,?,?,?,?)',(r['id'],self.scan,json.dumps(r),json.dumps(row['assessment']),'OPEN'))

    def event(self, action='confirm-false', when='2026-11-01T00:01:00+00:00'):
        r=self.records[0]; versions=r['snapshots']
        with closing(sqlite3.connect(self.root/'review.sqlite')) as db, db:
            db.execute('INSERT INTO events(warning_id,actor,timestamp,action,reason,source_version,observed_version,evidence_sha256) VALUES (?,?,?,?,?,?,?,?)',
                (r['id'],'SCRIPTED-SYNTHETIC',when,action,'positive control',json.dumps(versions),
                 json.dumps({k:v['sha256'] for k,v in versions.items()}),sha(json.dumps(r,ensure_ascii=False,sort_keys=True).encode())))
            db.execute('UPDATE warnings SET state=? WHERE id=?',
                ({'confirm-false':'CONFIRMED_FALSE','confirm-true':'CONFIRMED_TRUE','reopen':'OPEN'}[action],r['id']))
