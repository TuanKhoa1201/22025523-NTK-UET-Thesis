"""SYNTHETIC artifact corruption tests with complete positive controls."""
import copy
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from contextlib import closing
from artifact_fixture import Fixture
from audit import Audit, load
from contracts import compare_sarif, strict, validate_rows


class DeepArtifactChecks(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name); self.f=Fixture(self.root); self.audit=Audit(self.root,self.root)

    def reject(self, method):
        self.audit.check(method,getattr(self.audit,method))
        self.assertEqual(self.audit.checks[-1]['status'],'FAIL', self.audit.checks[-1])

    def sql(self, statement, args=()):
        with closing(sqlite3.connect(self.root/'review.sqlite')) as db, db: db.execute(statement,args)

    def test_complete_unsigned_bundle_positive(self):
        for name in ('manifest','identity','sarif','sources','database','runtime'):
            with self.subTest(check=name): self.audit.check(name,getattr(self.audit,name)); self.assertEqual(self.audit.checks[-1]['status'],'PASS',self.audit.checks[-1])

    def test_explicit_capture_layout_positive(self):
        capture=self.root/'separate-cli-capture';self.f.engine.rename(capture)
        # File-output paths are not involved: the original stdout capture remains byte-identical.
        audit=Audit(self.root,self.root,capture=capture)
        audit.manifest();audit.identity();audit.sarif()

    def test_empty_results_positive(self):
        d=copy.deepcopy(self.f.doc); d['results']=[]
        s=copy.deepcopy(self.f.sarif); s['runs'][0]['results']=[]
        self.assertEqual(compare_sarif(d,s)['findings'],0)

    def test_optional_sarif_fields_are_not_invented(self):
        s=copy.deepcopy(self.f.sarif); s['runs'][0].pop('tool')
        for r in s['runs'][0]['results']:
            r.pop('ruleIndex'); rg=r['locations'][0]['physicalLocation']['region']; rg.pop('startColumn'); rg.pop('endColumn')
        result=compare_sarif(self.f.doc,s)
        self.assertEqual(result['optional_fields_compared']['startColumn'],0)
        self.assertEqual(result['findings'],2)

    def test_sarif_inconsistencies(self):
        mutations = [lambda s:s['runs'][0].update(results=[]),
            lambda s:s['runs'][0]['results'].append(copy.deepcopy(s['runs'][0]['results'][0])),
            lambda s:s['runs'][0]['results'][0].update(ruleId='wrong'),
            lambda s:s['runs'][0]['results'][0]['locations'][0]['physicalLocation']['region'].update(startLine=2),
            lambda s:s['runs'][0]['results'][0]['locations'][0]['physicalLocation']['region'].update(startColumn=4),
            lambda s:s['runs'][0]['results'][0]['locations'][0]['physicalLocation']['region'].update(endColumn=24),
            lambda s:s['runs'][0]['tool']['driver']['rules'][0]['defaultConfiguration'].update(level='note'),
            lambda s:s['runs'][0]['tool']['driver']['rules'][0]['properties'].update(tags=['CWE-22']),
            lambda s:s['runs'][0]['results'][0].pop('locations'),
            lambda s:s['runs'][0]['results'][0].update(ruleIndex=True),
            lambda s:s['runs'][0]['invocations'][0].update(executionSuccessful=False)]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                s=copy.deepcopy(self.f.sarif); mutate(s)
                with self.assertRaises((ValueError,KeyError)): compare_sarif(self.f.doc,s)

    def test_sarif_extra_when_json_empty(self):
        doc=copy.deepcopy(self.f.doc); doc['results']=[]
        with self.assertRaises(ValueError): compare_sarif(doc,self.f.sarif)

    def test_uri_percent_and_file_positive(self):
        doc=copy.deepcopy(self.f.doc); s=copy.deepcopy(self.f.sarif)
        for r in doc['results']: r['path']='C:/source/A B.java'
        for r in s['runs'][0]['results']:
            r['locations'][0]['physicalLocation']['artifactLocation']={'uri':'file:///C:/source/A%20B.java'}
        self.assertEqual(compare_sarif(doc,s)['findings'],2)

    def test_unsafe_uri_paths_rejected(self):
        for uri in ('../Probe.java','%2e%2e/Probe.java','https://example.com/Probe.java','file://remote/Probe.java','Probe.java?x=1','Probe%ZZ.java'):
            with self.subTest(uri=uri):
                s=copy.deepcopy(self.f.sarif)
                s['runs'][0]['results'][0]['locations'][0]['physicalLocation']['artifactLocation']['uri']=uri
                with self.assertRaises(ValueError): compare_sarif(self.f.doc,s)

    def test_strict_json_and_jsonl(self):
        for raw in ('{"a":1,"a":2}','{"a":NaN}','{"a":Infinity}','{"a":1e999}', '{'):
            with self.subTest(raw=raw), self.assertRaises(ValueError): strict(raw)
        self.f.write('assessments.jsonl', b'{"id":1,"id":2}\n'); self.reject('database')

    def test_jsonl_joins_and_schema(self):
        mutations = [lambda r:r.pop(), lambda r:r.append(copy.deepcopy(r[0])), lambda r:r.reverse(),
            lambda r:r[0].update(alert_id='0'*64),lambda r:r[0].update(scan_sha256='0'*64),
            lambda r:r[0].update(finding_index=1),lambda r:r[0].update(schema_version='2.0'),
            lambda r:r[0].pop('assessment'),lambda r:r[0]['assessment'].update(status='CONFIRMED_FALSE'),
            lambda r:r[0].update(id=r[1]['id']), lambda r:r[0]['evidence']['raw_trace'].update(changed=True)]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                rows=copy.deepcopy(self.f.rows); mutate(rows)
                with self.assertRaises((ValueError,KeyError)): validate_rows(rows,self.f.bundle)

    def test_raw_trace_change(self):
        bundle=copy.deepcopy(self.f.bundle); bundle['records'][0]['raw_trace']={'changed':True}
        self.f.write('evidence.json',bundle); self.reject('identity')

    def test_reordered_records(self):
        self.f.bundle['records'].reverse(); self.f.write('evidence.json',self.f.bundle); self.reject('identity')

    def test_hash_corruption(self):
        self.f.write('engine/json.stderr.txt',b'tampered'); self.reject('manifest')

    def test_manifest_contract_corruption(self):
        mutations=[lambda m:m.update(success='true'),lambda m:m.update(issues=['partial']),
            lambda m:m.update(rules_after_sha256='0'*64),lambda m:m.update(sources_after={}),
            lambda m:m['runs']['json'].update(exit_code=2),lambda m:m.update(schema='wrong'),
            lambda m:m.update(finished_at='2026-10-01T00:00:00Z'),lambda m:m['artifacts'].pop('json.stderr.txt')]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                original=copy.deepcopy(self.f.manifest); mutate(self.f.manifest)
                self.f.write('engine/scan-manifest.json',self.f.manifest); self.reject('manifest'); self.f.manifest=original

    def test_rules_argv_mismatch(self):
        run=self.f.manifest['runs']['sarif']; run['argv'][3]='auto'
        self.f.write('engine/sarif.command.json',run['argv']); self.f.rehash(); self.reject('manifest')

    def test_inherited_file_output_argv_positive(self):
        for label in ('json','sarif'):
            run=self.f.manifest['runs'][label]
            output=str(self.f.engine/('legacy.'+label))
            run.update(argv=['opengrep','scan','--config',str(self.f.engine/'rules.snapshot.yml'),
                             str(self.f.source),'--'+label,'--output',output],
                       output_mode='file',engine_output_path=output)
            self.f.write('engine/'+label+'.command.json',run['argv'])
        self.f.rehash(); self.audit.manifest()

    def test_engine_file_output_outside_capture(self):
        run=self.f.manifest['runs']['json']; output=str(self.root/'outside.json')
        run.update(argv=['opengrep','scan','--config',str(self.f.engine/'rules.snapshot.yml'),
                         str(self.f.source),'--json','--output',output],output_mode='file',engine_output_path=output)
        self.f.write('engine/json.command.json',run['argv']); self.f.rehash(); self.reject('manifest')

    def test_success_exit_missing_output_is_incomplete(self):
        (self.root/'engine/opengrep.json').unlink()
        self.audit.check('manifest',self.audit.manifest)
        self.assertEqual(self.audit.checks[-1]['status'],'INCOMPLETE')

    def test_changed_source(self):
        self.f.java.write_bytes(self.f.java.read_bytes()+b'//change'); self.reject('sources')

    def test_deleted_source(self):
        self.f.java.unlink(); self.reject('sources')

    def test_new_source_inventory(self):
        (self.f.source/'Extra.java').write_text('class Extra {}'); self.reject('sources')

    def test_snapshot_wrong_hash(self):
        self.f.bundle['records'][0]['snapshots']['Probe.java']['sha256']='0'*64
        self.f.write('evidence.json',self.f.bundle); self.reject('sources')

    def test_snippet_forgery(self):
        for changes in ({'matched':'invented'}, {'start':{'line':999,'col':1}}, {'end':{'line':3,'col':999}},
                        {'sha256':'0'*64}, {'lines':[{'line':3,'text':'invented'}]}):
            with self.subTest(changes=changes):
                bundle=copy.deepcopy(self.f.bundle); bundle['records'][0]['snippets'][0].update(changes)
                self.f.write('evidence.json',bundle); self.reject('sources')

    def test_absolute_finding_outside_root(self):
        bundle=copy.deepcopy(self.f.bundle)
        bundle['records'][0]['snippets'][0]['raw_path']='/outside/Probe.java'
        self.f.write('evidence.json',bundle); self.reject('sources')

    def test_explicit_source_mapping_positive(self):
        bundle=copy.deepcopy(self.f.bundle)
        for rec in bundle['records']:
            rec['snippets'][0]['raw_path']='/synthetic/source/Probe.java'
            rec['path_mappings']=[{'from':'/synthetic/source','to':str(self.f.source)}]
        self.f.write('evidence.json',bundle); self.audit.sources()

    def test_sqlite_backdated_event(self):
        self.f.event(); self.f.event('reopen','2026-10-01T00:00:00Z'); self.reject('database')

    def test_sqlite_unknown_warning_event(self):
        self.f.event(); self.sql("UPDATE events SET warning_id='unknown'"); self.reject('database')

    def test_sqlite_duplicate_import_and_rejected_action_control(self):
        self.f.event(); before=(self.root/'review.sqlite').read_bytes()
        with self.assertRaises(sqlite3.IntegrityError):
            self.sql('INSERT INTO scans VALUES (?,?)',(self.f.scan,json.dumps(self.f.bundle)))
        self.audit.database();self.assertEqual((self.root/'review.sqlite').read_bytes(),before)

    def test_false_confirmation_positive_and_reopen(self):
        self.f.event(); self.audit.database()
        self.f.event('reopen','2026-11-01T00:02:00Z'); self.audit.database()

    def test_true_confirmation_positive(self):
        self.f.event('confirm-true'); self.audit.database()

    def test_sqlite_evidence_digest(self):
        self.f.event(); self.sql('UPDATE events SET evidence_sha256=?',('0'*64,)); self.reject('database')

    def test_sqlite_event_forged_source_and_observed(self):
        self.f.event(); fake={'Probe.java':{'sha256':'0'*64,'size':len(self.f.text)}}
        self.sql('UPDATE events SET source_version=?,observed_version=?',(json.dumps(fake),json.dumps({'Probe.java':'0'*64}))); self.reject('database')

    def test_sqlite_stale_observed(self):
        self.f.event(); self.sql('UPDATE events SET observed_version=?',(json.dumps({'Probe.java':'0'*64}),)); self.reject('database')

    def test_sqlite_missing_warning(self):
        self.sql('DELETE FROM warnings WHERE id=?',(self.f.records[0]['id'],)); self.reject('database')

    def test_sqlite_state_without_events(self):
        self.sql("UPDATE warnings SET state='CONFIRMED_FALSE'"); self.reject('database')

    def test_sqlite_wrong_scan_join(self):
        self.sql("UPDATE warnings SET scan_id='wrong'"); self.reject('database')

    def test_sqlite_event_metadata(self):
        self.f.event()
        for statement in ("UPDATE events SET actor=''", "UPDATE events SET reason=''", "UPDATE events SET timestamp='yesterday'"):
            with self.subTest(sql=statement):
                self.sql(statement); self.reject('database')
                self.sql("UPDATE events SET actor='SCRIPTED',reason='synthetic',timestamp='2026-11-01T00:01:00Z'")

    def test_wal_is_not_checkpointed(self):
        wal=self.root/'review.sqlite-wal'; wal.write_bytes(b'synthetic nonempty WAL')
        before=wal.read_bytes(); self.audit.check('database',self.audit.database)
        self.assertEqual(self.audit.checks[-1]['status'],'INCOMPLETE'); self.assertEqual(wal.read_bytes(),before)

    def test_database_bytes_unchanged(self):
        before=(self.root/'review.sqlite').read_bytes(); self.audit.database()
        self.assertEqual((self.root/'review.sqlite').read_bytes(),before)

    def test_historical_real_format_pair_read_only(self):
        root=Path(os.environ['G1_CHECKOUT'])/'v2/demo'
        doc=load(root/'smoke_v2_taint_raw.opengrep.json'); sarif=load(root/'smoke_v2_taint_raw.opengrep.sarif')
        result=compare_sarif(doc,sarif)
        self.assertGreater(result['findings'],0)
        self.assertEqual(result['optional_fields_compared']['severity'],result['findings'])


if __name__ == '__main__': unittest.main()
