"""Synthetic fixtures and deterministic pipeline DTOs; no deployment/TP labels.

The source + DTO tests isolate CWSS rules. A separate real local AST test checks
compatibility; API-role predictions there are explicit test doubles, not Qwen.
"""
import copy
import hashlib
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import ntk_cwss_automatic as a
import ntk_cwss_workflow as w
import ntk_cwss_v101 as scorer
from test_ntk_cwss_workflow import finding, Index, SCAN, TOKEN

FIXTURES = Path(__file__).parent/'fixtures'/'cwss_auto'
KINDS = {78: ('Command', 'java.lang', 'Runtime', 'exec', 'Process exec(String[] cmdarray)'),
         89: ('Sql', 'java.sql', 'Statement', 'executeQuery', 'ResultSet executeQuery(String sql)'),
         79: ('Xss', 'java.io', 'PrintWriter', 'println', 'void println(String x)'),
         22: ('Path', 'java.nio.file', 'Files', 'readAllBytes', 'byte[] readAllBytes(Path path)')}


def example(cwe=78):
    f = finding(cwe)
    name, package, cls, method, signature = KINDS[cwe]
    f.update(file_path=name+'Controller.java', line_number=9)
    f['matched_code'] = (FIXTURES/f['file_path']).read_text().splitlines()[8]
    f['iris_evidence'].update(enclosing_method='run', flow_proof_state='PROVEN_TAINT',
        covered_sink_args=['arg0'], explicit_ast_release_verified=False, sanitizer_status='NONE_DETECTED',
        ast_overloaded_signature=signature,
        target_callee_identity={'package': package, 'class': cls, 'method': method, 'signature': signature})
    f['source_provenance_record'] = {'verified': True, 'file_sha256': hashlib.sha256((FIXTURES/f['file_path']).read_bytes()).hexdigest(), 'source': 'SYNTHETIC_TEST_DOUBLE'}
    f['llm_api_role']['canonical_sink_args'] = ['arg0']
    return f


class AutomaticTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)/'repo'; self.root.mkdir()
        for path in FIXTURES.iterdir():
            (self.root/path.name).write_bytes(path.read_bytes())
        self.store = w.AssessmentStore(Path(self.tmp.name)/'store')
        self.f = example()

    def score(self, f=None, mode=a.MODES[0]):
        f = f or self.f
        return a.assess(f, SCAN, a.collect(self.root, [f]), mode)[1]

    def test_all_sixteen_records_weights_and_formula(self):
        for cwe in KINDS:
            for mode in a.MODES:
                r = self.score(example(cwe), mode)
                self.assertEqual(len(r['metric_assessments']), 16)
                expected = scorer.score_codes(r['factor_codes'], fill_unknown=False)
                for key in ('cwss_score', 'cwss_score_exact', 'subscores_exact', 'vector'):
                    self.assertEqual(r[key], expected[key])
                for m, row in r['metric_assessments'].items():
                    self.assertEqual(row['weight'], scorer.WEIGHTS[m][row['code']])
                    self.assertIn('provenance', row)
                    self.assertIn('reason', row)

    def test_tainted_shell_local_impact_and_interaction_proofs(self):
        r = self.score()
        self.assertEqual(r['factor_codes']['TI'], 'H')
        self.assertEqual(r['factor_codes']['IN'], 'A')
        self.assertGreater(r['cwss_score'], 3.6)
        self.assertEqual(r['metric_assessments']['TI']['classification'], 'VERIFIED')
        self.assertFalse(r['fully_verified'])

    def test_other_sinks_not_claimed_verified_high_impact(self):
        for cwe in (22, 79, 89):
            r = self.score(example(cwe))
            self.assertEqual(r['factor_codes']['TI'], 'UK')
            self.assertTrue(any(s['metric'] == 'TI' and s['code'] == 'H' for s in r['machine_suggestions']))

    def test_estimates_never_promoted_to_evidence_or_attestation(self):
        e, s = self.score(), self.score(mode=a.MODES[1])
        for m in ('IC', 'RP', 'AS', 'AV'):
            self.assertIn(e['factor_codes'][m], ('UK', 'U'))
            self.assertNotIn(s['factor_codes'][m], ('UK', 'U'))
            self.assertFalse(s['metric_assessments'][m]['evidence_sufficient'])
            self.assertNotEqual(s['metric_assessments'][m]['classification'], 'VERIFIED')
        self.assertGreater(s['cwss_score'], e['cwss_score'])
        self.assertIn('NOT_VERIFIED', s['risk_interpretation'])

    def test_fc_business_environment_and_privileges_remain_unknown(self):
        for mode in a.MODES:
            r = self.score(mode=mode)
            for m in ('FC', 'BI', 'EC', 'AP', 'AL', 'RL', 'DI', 'EX', 'SC'):
                self.assertEqual(r['factor_codes'][m], 'UK')
            self.assertEqual(r['factor_codes']['P'], 'NA')

    def test_unknown_flow_never_uses_effect_rules(self):
        for change in ({'flow_proof_state': 'UNKNOWN'}, {'covered_sink_args': []},
                       {'taint_reaches_sink': False}, {'explicit_ast_release_verified': True},
                       {'ast_parser_engine': 'REGEX'}, {'source_sink_trace_status': 'UNKNOWN'}):
            f = example(); f['iris_evidence'].update(change)
            r = self.score(f)
            self.assertEqual(r['factor_codes']['TI'], 'UK')
            self.assertEqual(r['factor_codes']['IN'], 'UK')

    def test_resolved_owner_signature_and_coverage_required(self):
        for change in ({'package': 'custom'}, {'signature': 'Process exec(Object command)'},
                       {'method': 'execute'}, {'class': 'CustomRuntime'}):
            f = example(); f['iris_evidence']['target_callee_identity'].update(change)
            self.assertEqual(self.score(f)['factor_codes']['TI'], 'UK')
        f = example(); f['llm_api_role']['canonical_sink_args'] = ['arg1']
        self.assertEqual(self.score(f)['factor_codes']['TI'], 'UK')

    def test_sql_no_argument_overload_not_applied(self):
        f = example(89)
        f['iris_evidence']['ast_overloaded_signature'] = 'ResultSet executeQuery()'
        self.assertEqual(self.score(f, a.MODES[1])['factor_codes']['TI'], 'UK')

    def test_model_or_cwe_alone_not_evidence(self):
        f = example(); f.pop('iris_evidence')
        self.assertEqual(self.score(f)['cwss_score'], 3.6)
        f = example(); f['llm_api_role']['strict_json_valid'] = False
        self.assertEqual(self.score(f)['factor_codes']['TI'], 'UK')

    def test_context_removal_reduces_only_estimate_by_official_formula(self):
        high = self.score(mode=a.MODES[1])
        (self.root/'ingress.yaml').unlink()
        low = self.score(mode=a.MODES[1])
        self.assertEqual(high['factor_codes']['AV'], 'I')
        self.assertEqual(low['factor_codes']['AV'], 'U')
        self.assertGreater(high['cwss_score'], low['cwss_score'])
        self.assertEqual({m for m in high['factor_codes'] if high['factor_codes'][m] != low['factor_codes'][m]}, {'AV'})

    def test_ambiguous_security_never_infers_no_authentication(self):
        path = self.root/'SecurityConfig.java'
        original = path.read_text()
        for text in (original.replace('permitAll()', 'authenticated()'), original+'\nclass Other {}',
                     original.replace('anyRequest()', 'requestMatchers("/other")'),
                     original.replace('.build()', '.addFilter(custom).build()')):
            path.write_text(text)
            r = self.score(mode=a.MODES[1])
            self.assertEqual(r['factor_codes']['RP'], 'UK')
            self.assertEqual(r['factor_codes']['AS'], 'UK')
        path.write_text(original)
        (self.root/'SecondSecurity.java').write_text('class SecondSecurity { SecurityFilterChain chain; }')
        self.assertEqual(self.score(mode=a.MODES[1])['factor_codes']['AS'], 'UK')

    def test_guarded_or_wrong_method_route_fails_closed(self):
        path = self.root/'CommandController.java'; original = path.read_text()
        for text in (original.replace('@GetMapping', '@PreAuthorize("role")\n @GetMapping'),
                     original.replace('public void run', 'public void other'),
                     original.replace('@GetMapping("/example")', '@PostMapping("/example")')):
            path.write_text(text)
            self.assertEqual(self.score()['factor_codes']['IN'], 'UK')
        path.write_text(original)
        f = example(); f['line_number'] = 1
        self.assertEqual(self.score(f)['factor_codes']['TI'], 'UK')

    def test_comments_cannot_manufacture_route_proof(self):
        path = self.root/'CommandController.java'
        path.write_text('/*\n'+path.read_text()+'*/\nclass Empty {}')
        self.assertEqual(self.score()['factor_codes']['IN'], 'UK')

    def test_repository_unavailable_preserves_unknown(self):
        r = a.assess(self.f, SCAN, a.collect(None, [self.f]), a.MODES[0])[1]
        self.assertEqual(r['cwss_score'], 3.6)
        self.assertIn('SOURCE_REPOSITORY_UNAVAILABLE', r['collection_limitations'])

    def test_bounded_inventory_disables_configuration_assumptions(self):
        with patch.object(a, 'MAX_FILES', 1):
            snap = a.collect(self.root, [self.f])
        self.assertFalse(snap['inventory_complete'])
        r = a.assess(self.f, SCAN, snap, a.MODES[1])[1]
        self.assertEqual(r['factor_codes']['AS'], 'UK')

    def test_symlinks_and_traversal_never_read(self):
        (self.root/'outside.yaml').symlink_to('/etc/passwd')
        f = example(); f['file_path'] = '../escape.java'
        snap = a.collect(self.root, [f])
        self.assertNotIn(f['finding_id'], snap['finding_source_paths'])
        self.assertFalse(snap['inventory_complete'])
        self.assertFalse(any(r['path'] == 'outside.yaml' for r in snap['files']))

    def test_deployment_secrets_not_saved(self):
        (self.root/'secret.yaml').write_text('password: do-not-archive-this\nkind: Secret\ndata:\n  token: secret-value\n')
        snap = a.collect(self.root, [self.f])
        self.assertNotIn('do-not-archive', json.dumps(snap))
        self.assertNotIn('secret-value', json.dumps(snap))

    def test_input_order_and_replays_are_deterministic(self):
        snap = a.collect(self.root, [self.f]); other = copy.deepcopy(snap)
        one = a.assess(self.f, SCAN, snap, a.MODES[0])
        self.assertEqual(one, a.assess(copy.deepcopy(self.f), SCAN, other, a.MODES[0]))
        records = self.store.publish_automatic(self.f, SCAN, snap)
        self.assertEqual(len(records), 2)
        self.assertEqual(records, self.store.publish_automatic(self.f, SCAN, snap))
        for r in records:
            self.assertTrue(self.store.replay(SCAN, self.f['finding_id'], r['revision'])['replay_verified'])

    def test_atomic_idempotent_concurrent_revisions(self):
        snap = a.collect(self.root, [self.f])
        with ThreadPoolExecutor(4) as pool:
            list(pool.map(lambda _: self.store.publish_automatic(self.f, SCAN, snap), range(4)))
        self.assertEqual(len(self.store.history(SCAN, self.f['finding_id'])), 2)

    def test_atomic_pair_rolls_back_if_second_insert_fails(self):
        import sqlite3
        with self.store.connect() as db:
            db.execute("CREATE TRIGGER reject_second BEFORE INSERT ON revisions WHEN NEW.revision=2 BEGIN SELECT RAISE(ABORT, 'test rollback'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.publish_automatic(self.f, SCAN, a.collect(self.root, [self.f]))
        self.assertEqual(self.store.history(SCAN, self.f['finding_id']), [])

    def test_modified_source_creates_new_versioned_pair(self):
        self.store.publish_automatic(self.f, SCAN, a.collect(self.root, [self.f]))
        (self.root/'ingress.yaml').unlink()
        records = self.store.publish_automatic(self.f, SCAN, a.collect(self.root, [self.f]))
        self.assertEqual([r['revision'] for r in records], [3, 4])
        self.assertTrue(self.store.replay(SCAN, self.f['finding_id'], 2)['replay_verified'])
        self.assertNotEqual(records[1]['assessment']['profile_hash'], self.store.history(SCAN, self.f['finding_id'])[1]['assessment']['profile_hash'])

    def test_snapshot_tampering_rejected(self):
        snap = a.collect(self.root, [self.f]); snap['files'][0]['text'] += ' changed'
        with self.assertRaises(ValueError): a.assess(self.f, SCAN, snap, a.MODES[0])
        snap = a.collect(self.root, [self.f]); f = copy.deepcopy(self.f); f['line_number'] += 1
        with self.assertRaises(ValueError): a.assess(f, SCAN, snap, a.MODES[0])

    def test_auto_modes_cannot_be_posted_as_attestations(self):
        profile, _ = a.assess(self.f, SCAN, a.collect(self.root, [self.f]), a.MODES[0])
        with self.assertRaises(ValueError): w.evaluate(self.f, SCAN, profile, 'alice')
        with self.assertRaises(ValueError): self.store.publish(self.f, SCAN, profile, 'alice', 0)

    def test_api_read_report_ranking_and_no_write_route(self):
        index = Index(); index.findings = [self.f]
        state = SimpleNamespace(result_index=index, storage_dir=Path(self.tmp.name))
        self.store = w.AssessmentStore(w.directory(state))
        self.store.publish_automatic(self.f, SCAN, a.collect(self.root, [self.f]))
        root = '/api/scans/'+SCAN+'/cwss/v1/'
        code, body = w.handle(state, 'GET', root+'findings/'+self.f['finding_id']+'/automatic', {})
        self.assertEqual(code, 200)
        self.assertEqual(set(body['automatic_scores']), set(a.MODES))
        for endpoint in ('report', 'ranking'):
            code, body = w.handle(state, 'GET', root+endpoint, {'mode': [a.MODES[1]]})
            self.assertEqual(code, 200)
            self.assertEqual(body['findings'][0]['mode'], a.MODES[1])
        code, _ = w.handle(state, 'POST', root+'findings/'+self.f['finding_id']+'/automatic', {}, {})
        self.assertEqual(code, 401)
        with patch.dict('os.environ', {'NTK_CWSS_REVIEWER_TOKENS': json.dumps({'alice': TOKEN})}):
            code, _ = w.handle(state, 'POST', root+'findings/'+self.f['finding_id']+'/automatic', {}, {}, 'Bearer '+TOKEN)
        self.assertEqual(code, 405)

    def test_ranking_fallback_explicit_mode_and_no_archived_mutation(self):
        original = copy.deepcopy(self.f)
        rows = w.ranking([self.f], SCAN, self.store, a.MODES[0])
        self.assertEqual(rows[0]['mode'], a.MODES[0])
        self.assertIsNone(rows[0]['revision'])
        self.assertEqual(self.f, original)
        self.assertEqual(self.store.history(SCAN, self.f['finding_id']), [])

    def test_fc_attestation_gate_still_required(self):
        from test_ntk_cwss_workflow import profile, metric
        p = profile(self.f); p['metrics']['FC'] = metric('T')
        with self.assertRaises(ValueError): w.evaluate(self.f, SCAN, p, 'alice')


    def test_missing_or_stale_source_hash_cannot_verify(self):
        f = example(); f.pop('source_provenance_record')
        self.assertEqual(self.score(f)['factor_codes']['IN'], 'UK')
        path = self.root/'CommandController.java'
        path.write_text(path.read_text().replace('String input', 'String other'))
        self.assertEqual(self.score()['factor_codes']['TI'], 'UK')

    def test_complete_internal_guard_proof_only_exact_source_and_slots(self):
        f = example(22)
        f['iris_evidence'].update(flow_proof_state='PROVEN_SAFE', taint_reaches_sink=False,
            source_sink_trace_status='SAFE_SANITIZED_OR_GUARDED', explicit_ast_release_verified=True,
            sanitizer_status='VERIFIED_NORMALIZED_PATH_WITH_PREFIX_GUARD',
            ast_proof_node='SANITIZER_CALL:java.nio.file.Path::normalize+STARTSWITH_PREFIX_GUARD:p.startsWith(base)')
        r = self.score(f)
        self.assertEqual(r['factor_codes']['IC'], 'C')
        self.assertEqual(r['cwss_score'], 0)
        self.assertEqual(r['triage_decision'], 'REPORT')  # scoring never overwrites triage
        self.assertEqual(r['factor_codes']['FC'], 'UK')
        for change in ({'covered_sink_args': []}, {'ast_proof_node': 'LITERAL:fixed'},
                       {'flow_proof_state': 'UNKNOWN'}, {'sanitizer_status': 'UNVERIFIED_CUSTOM_SANITIZER'}):
            bad = copy.deepcopy(f); bad['iris_evidence'].update(change)
            self.assertEqual(self.score(bad)['factor_codes']['IC'], 'UK')

    def test_changed_source_line_cannot_reuse_local_proof(self):
        path = self.root/'CommandController.java'
        path.write_text(path.read_text().replace('"-c"', '"-n"'))
        self.assertEqual(self.score()['factor_codes']['TI'], 'UK')

    def test_ingress_ambiguity_or_unrelated_route_not_exposure(self):
        path = self.root/'ingress.yaml'; original = path.read_text()
        path.write_text(original.replace('/example', '/other'))
        self.assertEqual(self.score(mode=a.MODES[1])['factor_codes']['AV'], 'U')
        path.write_text(original)
        (self.root/'another.yaml').write_text(original)
        self.assertEqual(self.score(mode=a.MODES[1])['factor_codes']['AV'], 'U')

    def test_new_scan_publishes_sidecar_pair_without_archiving_snapshot(self):
        import threading
        import ntk_web_backend_service as service
        class ResultIndex:
            def index_scan_record(self, **kwargs): return {'scan_id': kwargs['scan_id']}
        state = SimpleNamespace(storage_dir=Path(self.tmp.name), _lock=threading.Lock(),
            findings_by_id={}, pipeline_traces_by_scan={}, raw_opengrep_by_scan={}, scans={}, result_index=ResultIndex())
        payload = {'findings': [self.f], 'cwss_automatic_collection': a.collect(self.root, [self.f])}
        before = copy.deepcopy(payload)
        record = service.NtkBackendState.record_scan(state, SCAN, payload)
        self.assertEqual(payload, before)
        self.assertNotIn('cwss_automatic_collection', record)
        self.assertEqual(record['findings'][0]['decision'], 'REPORT')
        store = w.AssessmentStore(w.directory(state))
        self.assertEqual(len(store.history(SCAN, self.f['finding_id'])), 2)
        archived = json.loads((Path(self.tmp.name)/(SCAN+'.json')).read_text())
        self.assertNotIn('cwss_automatic_collection', archived)
        self.assertNotIn('automatic_evidence', json.dumps(archived))


class LocalAstAutomaticTests(unittest.TestCase):
    from test_ast_false_suppression import FalseSuppressionTests as _baseline
    setUpClass = classmethod(_baseline.setUpClass.__func__)

    def analyze(self, cwe, replacement=None, source_override=None):
        from dataclasses import asdict
        import ntk_alert_verification as av
        import ntk_iris_shared as shared
        f = example(cwe)
        source = source_override or (FIXTURES/f['file_path']).read_text()
        f['line_number'] = next(i for i, line in enumerate(source.splitlines(), 1) if '// SINK' in line)
        if replacement:
            source = source.replace('request.getParameter("value")', replacement)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); path = root/f['file_path']; path.write_text(source)
            analysis = av.analyze_java_site_ast_and_taint(source, str(path), f['line_number'], cwe)
            # Test double for existing local Qwen role output; no model call.
            prediction = shared.parse_and_validate_callee_json(json.dumps({
                **analysis.target_callee_identity, 'type': 'sink', 'sink_args': ['arg0']}),
                expected_identity=analysis.target_callee_identity, cwe=cwe)
            result = av.verify_and_triage_finding('synthetic', cwe, f['file_path'], f['line_number'],
                'synthetic', 'ERROR', .7, analysis, prediction)
            f = asdict(result)
            f['source_provenance_record'] = {'verified': True, 'file_sha256': hashlib.sha256(source.encode()).hexdigest(), 'source': 'LOCAL_AST_TEST_SOURCE_HASH'}
            snapshot = a.collect(root, [f])
            return analysis, a.assess(f, SCAN, snapshot, a.MODES[0])[1]

    def test_real_local_ast_four_synthetic_sources(self):
        for cwe in KINDS:
            analysis, r = self.analyze(cwe)
            self.assertEqual(analysis.flow_proof_state, 'PROVEN_TAINT')
            self.assertEqual(r['factor_codes']['FC'], 'UK')
            self.assertEqual(r['factor_codes']['TI'], 'H' if cwe == 78 else 'UK')
            self.assertEqual(r['factor_codes']['IN'], 'UK' if cwe == 79 else 'A')

    def test_real_local_ast_unproven_guard_stays_unknown(self):
        source = (FIXTURES/'PathController.java').read_text().replace(
            'String input = request.getParameter("value");',
            'java.nio.file.Path base = java.nio.file.Paths.get("/srv/data").toAbsolutePath().normalize();\n'
            '  java.nio.file.Path target = java.nio.file.Paths.get(request.getParameter("value")).normalize();\n'
            '  if (!target.startsWith(base)) { throw new SecurityException(); }').replace(
            'java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(input));',
            'java.nio.file.Files.readAllBytes(target);')
        analysis, result = self.analyze(22, source_override=source)
        self.assertEqual(analysis.flow_proof_state, 'UNKNOWN')
        self.assertEqual(result['factor_codes']['IC'], 'UK')
        self.assertEqual(result['cwss_score'], 3.6)
        self.assertEqual(result['factor_codes']['FC'], 'UK')

    def test_real_local_ast_constant_and_unknown_helper_no_promotion(self):
        for expression, state in [('"echo fixed"', 'PROVEN_SAFE'), ('External.value(request)', 'UNKNOWN')]:
            analysis, r = self.analyze(78, expression)
            self.assertEqual(analysis.flow_proof_state, state)
            self.assertEqual(r['factor_codes']['TI'], 'UK')
            self.assertEqual(r['factor_codes']['IN'], 'UK')


if __name__ == '__main__':
    unittest.main()
