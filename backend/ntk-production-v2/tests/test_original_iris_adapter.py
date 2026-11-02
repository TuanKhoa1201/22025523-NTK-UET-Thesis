"""Evidence-policy/parser regressions, not substitutes for live IRIS acceptance."""
import copy
import csv
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import ntk_original_iris_adapter as iris
from ntk_original_iris_worker import mining_frontier_order
import ntk_pipeline_telemetry_and_datasets as telemetry
import ntk_web_backend_service as service


class OriginalIrisEvidenceTests(unittest.TestCase):
    def test_bounded_mining_prioritizes_framework_but_never_removes_apis(self):
        candidates=[('java.util','HashMap','put','Object put(Object p0, Object p1)'),
                    ('javax.servlet.http','HttpServletRequest','getParameter','String getParameter(String p0)'),
                    ('java.lang','Runtime','exec','Process exec(String p0)')]
        ordered=sorted(candidates,key=mining_frontier_order)
        self.assertCountEqual(ordered,candidates)
        self.assertEqual(ordered[0],candidates[1])
        self.assertEqual(ordered,sorted(reversed(candidates),key=mining_frontier_order))

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.file = self.root / 'Example.java'
        self.file.write_text('class Example {\n  void run() {}\n}\n')
        self.manifest = {'Example.java': {'sha256': iris.digest(self.file.read_bytes())}}

    def location(self, line):
        return {'physicalLocation': {'artifactLocation': {'uri': 'Example.java'},
                                     'region': {'startLine': line, 'startColumn': 1}}}

    def sarif(self):
        # Deliberately synthetic parser input; never registered as a real scan.
        return {'runs': [{'results': [{'ruleId': 'parser-fixture', 'locations': [self.location(2)],
                  'codeFlows': [{'threadFlows': [{'locations': [
                      {'location': self.location(1)}, {'location': self.location(2)}]}]}]}]}]}

    def bound(self):
        paths, rejected = iris.bind_sarif(self.sarif(), self.root, self.manifest, 78, {})
        self.assertFalse(rejected)
        self.assertEqual(len(paths), 1)
        return paths[0]

    def test_thread_flow_binds_every_step_to_source_bytes(self):
        path = self.bound()
        self.assertEqual(len(path['taint_path_steps']), 2)
        self.assertEqual(path['source_location']['source_sha256'], self.manifest['Example.java']['sha256'])
        self.assertEqual(path['verification_status'], 'SOURCE_BOUND_CODEQL_PATH')
        self.assertIn('NOT_EXPERT_TP', path['semantic_limit'])

    def test_modified_source_invalidates_path(self):
        self.file.write_text('class Changed {}\n')
        paths, rejected = iris.bind_sarif(self.sarif(), self.root, self.manifest, 78, {})
        self.assertEqual(paths, [])
        self.assertIn('IRIS_SARIF_SOURCE_SHA_MISMATCH', rejected)

    def test_path_escape_is_rejected(self):
        sarif = self.sarif()
        loc = sarif['runs'][0]['results'][0]['codeFlows'][0]['threadFlows'][0]['locations'][0]['location']
        loc['physicalLocation']['artifactLocation']['uri'] = '../outside.java'
        paths, rejected = iris.bind_sarif(sarif, self.root, self.manifest, 78, {})
        self.assertEqual(paths, [])
        self.assertIn('IRIS_SARIF_SOURCE_ESCAPE', rejected)

    def test_remote_file_uri_cannot_bind_as_local_source(self):
        loc=self.location(1)
        loc['physicalLocation']['artifactLocation']['uri']='file://remote-host'+str(self.file)
        with self.assertRaisesRegex(ValueError,'REMOTE_FILE_AUTHORITY'):
            iris._location(loc,self.root,self.manifest)

    def api_context(self, source_class, sink_package, sink_class, method, signature):
        path=self.bound()
        path['source_location']['column']=1;path['sink_location']['column']=1
        target=self.root/'apis.csv'
        with target.open('w') as stream:
            writer=csv.DictWriter(stream,fieldnames=['location','package','clazz','func','full_signature'])
            writer.writeheader()
            writer.writerow(dict(location=self.file.as_uri()+':1:1:1:30',package='javax.servlet.http',
                clazz=source_class,func='getHeader' if source_class=='HttpServletRequest' else 'getWriter',full_signature='String method()'))
            writer.writerow(dict(location=self.file.as_uri()+':2:1:2:30',package=sink_package,
                clazz=sink_class,func=method,full_signature=signature))
        iris.attach_api_context([path],target,self.root)
        return path['cwe_context_verified']

    def test_response_api_cannot_be_promoted_to_untrusted_request_source(self):
        self.assertFalse(self.api_context('HttpServletResponse','java.lang','Runtime','exec','Process exec(String p0)'))

    def test_cross_cwe_sql_sink_is_not_command_proof(self):
        self.assertFalse(self.api_context('HttpServletRequest','java.sql','Statement','executeQuery','ResultSet executeQuery(String p0)'))

    def test_runtime_environment_slot_requires_additional_proof(self):
        self.assertFalse(self.api_context('HttpServletRequest','java.lang','Runtime','exec','Process exec(String[] p0, String[] p1)'))

    def test_unambiguous_typed_command_context_is_recognized(self):
        self.assertTrue(self.api_context('HttpServletRequest','java.lang','Runtime','exec','Process exec(String p0)'))

    def test_failed_query_cannot_emit_proof(self):
        sarif = self.sarif()
        sarif['runs'][0]['invocations'] = [{'executionSuccessful': False}]
        self.assertEqual(iris.bind_sarif(sarif, self.root, self.manifest, 78, {})[0], [])

    def test_single_node_match_is_not_taint_path(self):
        sarif = self.sarif()
        sarif['runs'][0]['results'][0]['codeFlows'][0]['threadFlows'][0]['locations'].pop()
        self.assertEqual(iris.bind_sarif(sarif, self.root, self.manifest, 78, {})[0], [])

    def test_union_keeps_iris_only_discovery_and_raw_opengrep_unchanged(self):
        path = self.bound()
        hits = [{'path': str(self.file), 'start': {'line': 1},
                 'extra': {'metadata': {'cwe': 89}}}]
        original = copy.deepcopy(hits)
        merged = iris.merge_callsite_evidence(hits, [path, path], self.root)
        self.assertEqual(hits, original)
        self.assertEqual(len(merged), 2)
        self.assertEqual(merged[1]['engines'], ['IRIS_ORIGINAL_CODEQL'])
        self.assertEqual(len(merged[1]['iris_paths']), 1)

    def test_union_overlap_preserves_both_origins(self):
        hits = [{'path': str(self.file), 'start': {'line': 2}, 'extra': {'metadata': {'cwe': 78}}}]
        merged = iris.merge_callsite_evidence(hits, [self.bound()], self.root)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]['engines'], ['OPENGREP', 'IRIS_ORIGINAL_CODEQL'])

    def test_no_path_does_not_establish_safety_or_truth(self):
        self.assertEqual(iris.fuse_decision('REVIEW', False, []), ('REVIEW', []))

    def test_bound_path_without_cwe_context_does_not_auto_report(self):
        decision, reasons = iris.fuse_decision('REVIEW', False, [self.bound()])
        self.assertEqual(decision, 'REVIEW')
        self.assertIn('ORIGINAL_IRIS_MINED_MODEL_CWE_CONTEXT_UNCONFIRMED', reasons)

    def test_safe_conflict_requires_review_even_with_positive_path(self):
        path = {**self.bound(), 'cwe_context_verified': True}
        decision, reasons = iris.fuse_decision('SUPPRESS', True, [path])
        self.assertEqual(decision, 'REVIEW')
        self.assertIn('IRIS_PATH_CONFLICTS_WITH_LOCAL_SAFE_PROOF', reasons)

    def test_valid_contextual_path_can_add_report_without_opengrep_agreement(self):
        path = {**self.bound(), 'cwe_context_verified': True}
        self.assertEqual(iris.fuse_decision('REVIEW', False, [path])[0], 'REPORT')
        path['verification_status'] = 'UNVERIFIED'
        self.assertEqual(iris.fuse_decision('REVIEW', False, [path])[0], 'REVIEW')

    def test_license_gate_is_bound_to_exact_identity(self):
        att = self.root / 'attestation.json'
        att.write_text(json.dumps({'purpose': 'ACADEMIC_RESEARCH', 'sources': [{
            'source_identity': 'a'*40, 'license_id': 'MIT',
            'upstream_url': 'https://github.com/example/public', 'license_sha256': 'b'*64}]}))
        self.assertTrue(iris.verify_license_attestation(att, 'a'*40))
        self.assertFalse(iris.verify_license_attestation(att, 'c'*40))

    def test_fallback_and_unavailable_are_not_original_engine_success(self):
        default = iris.run(self.root, [self.file], '', config=iris.IrisConfig())
        self.assertEqual(default['engine_mode'], 'NTK_JAVAC_AST_FALLBACK')
        self.assertEqual(default['actual_gpu_inference_calls'], 0)
        missing = iris.run(self.root, [self.file], '', config=iris.IrisConfig(mode='ORIGINAL_IRIS_CODEQL_STRICT'))
        self.assertEqual(missing['analysis_status'], 'IRIS_UNAVAILABLE')

    def test_stage_engine_labels_do_not_modify_restored_trace(self):
        tracker = telemetry.PipelineStageTracker()
        historical = tracker.to_pipeline_trace_dict()
        tracker.describe_stage_engine(5, 'Explicit engine', 'NTK_JAVAC_AST_FALLBACK', 'parser')
        updated = tracker.to_pipeline_trace_dict()
        self.assertNotEqual(historical['stages'][4]['name'], updated['stages'][4]['name'])
        self.assertEqual(updated['stages'][4]['engine_id'], 'NTK_JAVAC_AST_FALLBACK')

    def test_strict_mode_fails_before_llm_and_no_fake_completed_scan(self):
        cfg = service.NtkWebBackendConfig(javac_bin='/usr/lib/jvm/java-17-openjdk-amd64/bin/javac',
                                         original_iris_mode='ORIGINAL_IRIS_CODEQL_STRICT')
        with patch.dict('os.environ', {'NTK_ORIGINAL_IRIS_LICENSE_ATTESTATION': ''}), \
             patch.object(service, 'run_llm_inference_for_identities', side_effect=AssertionError('Unexpected inference')):
            result = service.scan_java_sources_and_triage(self.root, config=cfg, compile_check=False)
        self.assertEqual(result['error_code'], 'ORIGINAL_IRIS_STRICT_REQUIREMENT_NOT_MET')
        self.assertEqual(result['findings'], [])
        self.assertEqual(result['pipeline_trace']['stages'][4]['state'], 'FAILED')
        self.assertNotEqual(result['pipeline_trace']['state'], 'COMPLETED')
