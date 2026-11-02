"""Cache/source and mining-budget regressions; synthetic data is not E2E proof."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
import sys
import os
import csv
from types import SimpleNamespace
from unittest.mock import patch

import ntk_engine_cache as cache
import ntk_iris_full_mining as mining
from ntk_original_iris_worker import codeql_launcher
from ntk_original_iris_adapter import reusable_execution,attach_standard_flow_context


class CodeqlLauncherTests(unittest.TestCase):
    def test_resource_flags_are_not_duplicated(self):
        for flags in [[],['--threads=1','--ram=2048'],['--threads','1','--ram','2048']]:
            with patch.object(sys,'argv',['wrapper','query','run','proof.ql',*flags]),patch('os.execv') as run:
                exec(compile(codeql_launcher('/safe/codeql',True),'<launcher>','exec'),{})
            argv=run.call_args.args[1]
            self.assertEqual(sum(x=='--threads' or x.startswith('--threads=') for x in argv),1)
            self.assertEqual(sum(x=='--ram' or x.startswith('--ram=') for x in argv),1)

    def test_only_opt_in_reuses_query_evaluation(self):
        for full in [False,True]:
            with patch.object(sys,'argv',['wrapper','database','analyze','db','--rerun']),patch('os.execv') as run:
                exec(compile(codeql_launcher('/safe/codeql',full),'<launcher>','exec'),{})
            self.assertEqual('--rerun' in run.call_args.args[1],not full)


class PortableProcessTelemetryTests(unittest.TestCase):
    def test_missing_io_counters_is_unavailable_not_fake_zero_or_process_failure(self):
        class ProcessWithoutIo:
            def __init__(self,pid):pass
            def children(self,recursive=False):return []
            def memory_info(self):return SimpleNamespace(rss=1024)
            def cpu_times(self):return SimpleNamespace(user=0.0,system=0.0)
        with tempfile.TemporaryDirectory() as tmp,patch('psutil.Process',ProcessWithoutIo):
            receipt=cache.run_process([sys.executable,'-c','import time; time.sleep(.3)'],
                Path(tmp)/'process.log',dict(os.environ),timeout_sec=3)
        self.assertEqual(receipt['exit_code'],0)
        self.assertFalse(receipt['disk_io_measurement_available'])
        self.assertIsNone(receipt['sampled_read_bytes_lower_bound'])


class SourceArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.db=self.root/'db';self.db.mkdir()
        (self.db/'db-java').mkdir();(self.db/'codeql-database.yml').write_text('test metadata')
        self.source=self.root/'source';self.source.mkdir()
        self.data=b'class Example {}'
        self.manifest={'Example.java':{'sha256':hashlib.sha256(self.data).hexdigest()}}

    def archive(self,data):
        with zipfile.ZipFile(self.db/'src.zip','w') as archive:
            archive.writestr(self.source.as_posix().lstrip('/')+'/Example.java',data)

    def test_exact_archive_bytes_required_and_changed_source_invalidates(self):
        self.archive(self.data)
        result=cache.verify_source_archive(self.db,self.source,self.manifest)
        self.assertEqual(result['java_files_archived_and_verified'],1)
        changed={'Example.java':{'sha256':hashlib.sha256(b'class Changed {}').hexdigest()}}
        with self.assertRaisesRegex(ValueError,'ARCHIVE_MISMATCH'):
            cache.verify_source_archive(self.db,self.source,changed)

    def test_modified_archive_not_accepted(self):
        self.archive(b'class Different {}')
        with self.assertRaisesRegex(ValueError,'ARCHIVE_MISMATCH'):
            cache.verify_source_archive(self.db,self.source,self.manifest)

    def test_source_query_and_model_changes_invalidate_content_key(self):
        original={'source':'one','query':'two','model':'three','policy':'four'}
        for field in original:
            self.assertNotEqual(cache.key(original),cache.key({**original,field:'changed'}))
        self.assertEqual(cache.key(original),cache.key(dict(reversed(list(original.items())))))

    def test_corroboration_requires_exact_endpoints_and_current_source_bytes(self):
        source=self.source/'Example.java';source.write_text('class Example {\n void f() {}\n}\n')
        manifest={'Example.java':{'sha256':cache.file_hash(source)}}
        proof=self.root/'proof.csv'
        with proof.open('w',newline='') as stream:
            writer=csv.writer(stream);writer.writerow(['source_file','source_line','source_column','sink_file','sink_line','sink_column'])
            writer.writerow([str(source),1,1,str(source),2,2])
        path={'source_location':{'file_path':'Example.java','line':1,'column':1},
              'sink_location':{'file_path':'Example.java','line':2,'column':2},'cwe_context_verified':False}
        other={**path,'source_location':{**path['source_location'],'column':2}}
        attach_standard_flow_context([path,other],proof,self.source,manifest)
        self.assertTrue(path['cwe_context_verified']);self.assertFalse(other['cwe_context_verified'])
        source.write_text('class Changed {}\n')
        with self.assertRaisesRegex(ValueError,'SOURCE_SHA_MISMATCH'):
            attach_standard_flow_context([path],proof,self.source,manifest)


class MiningSafetyTests(unittest.TestCase):
    def test_partial_cache_keeps_contract_limits_but_never_caches_failed_or_unexamined_execution(self):
        worker={'pipelines':[{'analysis_status':'COMPLETED'}],'analysis_status':'IRIS_PARTIAL'}
        self.assertTrue(reusable_execution(worker,['API_ROLE_CONTRACT_UNSUPPORTED'],True))
        self.assertEqual(worker['analysis_status'],'IRIS_PARTIAL')
        for reason in ['MODEL_GENERATION_BATCH_BUDGET_EXCEEDED','IRIS_SARIF_SOURCE_SHA_MISMATCH','UPSTREAM_PIPELINE_INCOMPLETE']:
            self.assertFalse(reusable_execution(worker,[reason],True))
        self.assertFalse(reusable_execution({'pipelines':[{'analysis_status':'FAILED'}]},['API_ROLE_CONTRACT_UNSUPPORTED'],True))

    def test_exhausted_budget_does_not_generate(self):
        session=object.__new__(mining.MiningSession)
        session.batches=2;session.request={'max_model_calls':2}
        with patch.object(mining,'generate') as generate:
            self.assertEqual(session._generate([(78,{})]),(None,None))
            generate.assert_not_called()

    def test_invalid_role_cannot_become_native_spec(self):
        identity={'package':'java.lang','class':'Runtime','method':'exec','signature':'Process exec(String p0)'}
        invalid={**identity,'type':'sink','sink_args':['p99']}
        with self.assertRaisesRegex(ValueError,'UNVALIDATED_MODEL_SPECIFICATION'):
            mining.MiningSession.specification(json.dumps(invalid),78,identity)


class InventoryScopeTests(unittest.TestCase):
    def test_full_java_inventory_does_not_imply_original_engine_or_semantic_coverage(self):
        import ntk_web_backend_service as service
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'Example.java').write_text('class Example {}')
            cfg=service.NtkWebBackendConfig(original_iris_mode='NTK_JAVAC_AST_FALLBACK',
                javac_bin='/usr/lib/jvm/java-17-openjdk-amd64/bin/javac')
            with patch.object(service,'run_llm_inference_for_identities',side_effect=AssertionError('Zero candidates must not infer')):
                result=service.scan_java_sources_and_triage(root,config=cfg,compile_check=False)
            contract=result['engine_coverage_contract']
            self.assertEqual(contract['full_java_source_inventory'],'PASS')
            self.assertEqual(contract['full_ntk_engine_execution'],'PARTIAL')
            self.assertEqual(contract['complete_semantic_dataflow_coverage'],'NOT_PROVEN')

    def test_wrapper_source_inclusion_is_explicit_and_no_script_is_executed(self):
        import ntk_web_backend_service as service
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);wrapper=root/'.mvn/wrapper';wrapper.mkdir(parents=True)
            (root/'App.java').write_text('class App {}')
            (wrapper/'Downloader.java').write_text('class Downloader {}')
            def inventory(include):
                return service.discover_and_verify_java_source_inventory(root,root,
                    service.NtkWebBackendConfig(include_java_build_wrappers=include),'LOCAL_JAVA_DIRECTORY')
            baseline=inventory(False);full=inventory(True)
            self.assertEqual(baseline['status'],'OK');self.assertEqual(full['status'],'OK')
            self.assertEqual(len(full['java_files']),len(baseline['java_files'])+1)


if __name__=='__main__':unittest.main()
