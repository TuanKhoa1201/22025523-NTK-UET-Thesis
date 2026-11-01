"""Real parser/scanner regressions; never execute uploaded code or call Qwen."""
import io
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
import ntk_web_backend_service as service
import ntk_cwss_reference_scenario_api as scenario
from types import SimpleNamespace


def archive(files):
    out=io.BytesIO()
    with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
        for name,text in files.items(): z.writestr(name,text)
    return out.getvalue()


class InputValidationTests(unittest.TestCase):
    def setUp(self):
        self.config=service.NtkWebBackendConfig(javac_bin='/usr/lib/jvm/java-17-openjdk-amd64/bin/javac')

    def scan(self, files):
        with patch.object(service,'run_llm_inference_for_identities',side_effect=AssertionError('Unnecessary Qwen inference')):
            return service.scan_java_zip_and_triage(archive(files),config=self.config,compile_check=False)

    def test_non_java_languages_empty_and_readme_are_not_successful_scans(self):
        for files in [{'main.py':'print(1)'},{'app.ts':'const x=1'},{'main.cpp':'int main(){}'},
                      {'main.go':'package main'}, {'README.md':'text'}, {}]:
            result=self.scan(files)
            self.assertEqual(result['status'],'ERROR')
            self.assertEqual(result['error_code'],'NO_JAVA_FILES_IN_ZIP')
            self.assertEqual(result['coverage_diagnostics']['java_files_discovered'],0)
            self.assertFalse(all(s['state']=='COMPLETED' for s in result['pipeline_trace']['stages']))

    def test_plain_and_mixed_java_zero_candidates_skip_llm(self):
        for extras in [{},{'app.py':'raise RuntimeError("NEVER EXECUTE")','app.js':'throw Error("NEVER EXECUTE")'}]:
            result=self.scan({'nested/Plain.java':'class Plain { int add(int a,int b){return a+b;} }',**extras})
            self.assertEqual(result['status'],'OK')
            self.assertEqual(result['findings'],[])
            self.assertEqual(result['actual_gpu_inference_calls'],0)
            self.assertEqual(result['pipeline_trace']['stages'][5]['state'],'SKIPPED')
            self.assertEqual(result['summary']['total_scanner_candidates'],0)
            self.assertEqual(result['coverage_diagnostics']['coverage_scope'],'JAVA_SOURCE_ONLY_SUPPORTED_CWES_NOT_WHOLE_REPOSITORY_SECURITY')

    def test_fake_java_and_java_syntax_errors_fail_before_scanner_or_qwen(self):
        for source in ['print("python")','class Broken { void run( { }']:
            result=self.scan({'Fake.java':source})
            self.assertEqual(result['status'],'ERROR')
            self.assertEqual(result['error_code'],'JAVA_SYNTAX_ERROR')
            self.assertEqual(result['findings'],[])
            self.assertTrue(result['coverage_diagnostics']['java_parse_failures'])

    def test_filtered_scope_is_distinct_from_no_java_repository(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'Plain.java').write_text('class Plain {}');(root/'docs').mkdir()
            result=service.discover_and_verify_java_source_inventory(workspace_root=root,scan_root=root/'docs',cfg=self.config,
                source_mode='GITHUB_GIT_CLONE',repository_url='https://github.com/example/repo',target_subpath='docs')
            self.assertEqual(result['error_code'],'NO_JAVA_FILES_MATCHED_FILTERS')

    def test_local_directory_mode_preserves_sources_and_never_executes_other_languages(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'app.py').write_text('raise RuntimeError("never execute")')
            with patch.object(service,'run_llm_inference_for_identities',side_effect=AssertionError('Unnecessary Qwen')):
                result=service.scan_java_sources_and_triage(root,config=self.config,compile_check=False)
                self.assertEqual(result['error_code'],'NO_JAVA_FILES_FOUND')
                (root/'Plain.java').write_text('class Plain { String value(){return "plain";} }')
                (root/'link.java').symlink_to(root/'Plain.java')
                result=service.scan_java_sources_and_triage(root,config=self.config,compile_check=False)
                self.assertEqual(result['status'],'OK');self.assertEqual(result['findings'],[])
                self.assertTrue((root/'link.java').is_symlink())

    def test_invalid_zip_traversal_symlink_and_limits_are_rejected(self):
        for data,code in [(b'not a ZIP','INVALID_ZIP_MAGIC_HEADER_REJECTED'),(b'PK\x03\x04broken','MALFORMED_ZIP_ARCHIVE_REJECTED'),
                          (archive({'../Bad.java':'class Bad {}'}),'ZIP_SLIP_PATH_TRAVERSAL_REJECTED')]:
            result=service.scan_java_zip_and_triage(data,config=self.config,compile_check=False)
            self.assertEqual(result['error_code'],code)
        out=io.BytesIO()
        with zipfile.ZipFile(out,'w') as z:
            info=zipfile.ZipInfo('Link.java');info.create_system=3;info.external_attr=(0o120777<<16);z.writestr(info,'/etc/passwd')
        self.assertEqual(service.scan_java_zip_and_triage(out.getvalue(),config=self.config)['error_code'],'ZIP_SYMLINK_ENTRY_REJECTED')
        config=service.NtkWebBackendConfig(max_zip_upload_bytes=8)
        self.assertEqual(service.scan_java_zip_and_triage(archive({'A.java':'class A {}'}),config=config)['error_code'],'MAX_ZIP_UPLOAD_BYTES_EXCEEDED')

    def test_empty_scenario_requires_no_database_and_synthesizes_no_metric(self):
        class Index:
            def query_findings_page(self,**kwargs):return 200,{'findings':[],'total_matching':0}
        with tempfile.TemporaryDirectory() as temp:
            state=SimpleNamespace(storage_dir=Path(temp),result_index=Index())
            status,body=scenario.handle(state,'/api/scans/SCAN-ZERO/cwss/v2/scenario',{})
            self.assertEqual(status,200);self.assertEqual(body['assessments'],[])
            self.assertFalse(list(Path(temp).rglob('*.sqlite3')))

    def test_zip_resource_limits_with_small_controlled_fixtures(self):
        cases = [
            ({'A.java':'class A {}','B.java':'class B {}'},
             {'max_zip_entries':1}, 'ZIP_TOO_MANY_ENTRIES_REJECTED'),
            ({'A.java':'class A {}'}, {'max_file_bytes':8}, 'MAX_FILE_BYTES_EXCEEDED'),
            ({'A.java':'class A {}'}, {'max_repo_total_bytes_ceiling':8}, 'MAX_REPO_BYTES_EXCEEDED'),
            ({'A.java':'/*'+'a'*70000+'*/ class A {}'}, {}, 'ZIP_BOMB_COMPRESSION_RATIO_REJECTED'),
        ]
        for files, limits, expected in cases:
            with self.subTest(expected=expected):
                cfg=service.NtkWebBackendConfig(**limits)
                result=service.scan_java_zip_and_triage(archive(files),config=cfg,compile_check=False)
                self.assertEqual(result['error_code'],expected)
