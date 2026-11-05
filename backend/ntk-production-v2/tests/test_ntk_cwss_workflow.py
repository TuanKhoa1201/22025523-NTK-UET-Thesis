"""CWSS workflow regression: synthetic context only, no model/deployment claims."""
import copy
import http.client
import json
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import ntk_cwss_v101 as scoring
import ntk_cwss_workflow as w
import ntk_cwss_context_api as old_api
import ntk_web_backend_service as service

SCAN = 'SCAN-CWSS-REGRESSION'
TOKEN = 'test-only-token-' + 'x' * 40


def finding(cwe=78, seq=1):
    identities = {22: ('Files', 'readAllBytes'), 78: ('Runtime', 'exec'),
                  79: ('PrintWriter', 'println'), 89: ('Statement', 'executeQuery')}
    cls, method = identities[cwe]
    return {'finding_id': 'FINDING-%03d-CWE%d' % (seq, cwe), 'cwe': 'CWE-%03d' % cwe,
            'file_path': 'Synthetic.java', 'line_number': seq, 'scanner_rule_id': 'synthetic',
            'matched_code': cls + '.' + method + '(input)', 'decision': 'REPORT',
            'review_status': 'NOT_REVIEWED', 'final_heuristic_score': .85,
            'iris_evidence': {'source_sink_trace_status': 'VERIFIED_TAINT_FLOW', 'taint_reaches_sink': True,
                              'ast_parser_engine': 'OPENJDK17_JAVAC_TASK_AST', 'taint_trace_steps': ['source', 'sink'],
                              'target_callee_identity': {'class': cls, 'method': method}},
            'llm_api_role': {'strict_json_valid': True, 'predicted_role': 'sink'}}


def profile(f=None, mode='ASSESSED'):
    p = w.template(f or finding(), SCAN)
    p.update(mode=mode, context={'deployment_name': 'SYNTHETIC TEST ONLY',
                                'deployment_version_or_commit': 'test-version', 'assessment_scope': 'test scope'})
    if mode == 'SCENARIO':
        p['scenario_name'] = 'explicit synthetic scenario'
    return p


def metric(code='H', mode='ASSESSED'):
    return {'code': code, 'classification': 'ANALYST_ATTESTED' if mode == 'ASSESSED' else 'SCENARIO_ASSUMED',
            'verified': mode == 'ASSESSED', 'reason': 'Synthetic test evidence of impact; not a deployed application claim',
            'source': 'TEST_ONLY', 'reference': 'synthetic-reference', 'reviewer': 'alice',
            'reviewed_at_utc': '2026-10-30T00:00:00+00:00'}


class Index:
    def __init__(self):
        self.findings = [finding()]
    def get_all_finding_details(self, scan):
        return copy.deepcopy(self.findings) if scan == SCAN else []
    def get_scan_summary(self, scan):
        return {'scan_id': scan} if scan == SCAN else None
    def query_findings_page(self, **kwargs):
        return 200, {'findings': copy.deepcopy(self.findings), 'page': 1, 'page_size': 50}


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = w.AssessmentStore(Path(self.tmp.name)/'assessments')

    def test_exact_sixteen_metric_catalog(self):
        rows = '''TI C:1 H:.9 M:.6 L:.3 N:0 D:.6
AP A:1 P:.9 RU:.7 L:.6 N:.1 D:.7
AL A:1 S:.9 N:.7 E:1 D:.9
IC N:1 L:.9 M:.7 I:.5 B:.3 C:0 D:.6
FC T:1 LT:.8 F:0 D:.8
RP N:1 L:.9 RU:.7 P:.6 A:.1 D:.7
RL A:1 S:.9 N:.7 E:1 D:.9
AV I:1 R:.8 V:.8 A:.7 L:.5 P:.2 D:.75
AS S:.7 M:.8 W:.9 N:1 D:.85
IN A:1 T:.9 M:.8 O:.3 H:.1 NI:0 D:.55
SC A:1 M:.9 R:.5 P:.1 D:.7
BI C:1 H:.9 M:.6 L:.3 N:0 D:.6
DI H:1 M:.6 L:.2 D:.6
EX H:1 M:.6 L:.2 N:0 D:.6
EC N:1 L:.9 M:.7 I:.5 B:.3 C:.1 D:.6
P W:1 H:.9 C:.8 L:.7 D:.85'''
        expected = {}
        for row in rows.splitlines():
            name, *values = row.split()
            expected[name] = {k: float(v) for k, v in (s.split(':') for s in values)}
            expected[name].update({'U' if name == 'AV' else 'UK': .5, 'NA': 1})
        self.assertEqual(scoring.WEIGHTS, expected)
        self.assertEqual(len(w.catalog()['metrics']), 16)
        with self.assertRaises(ValueError):
            scoring.score_codes({'TI': 'Q'})

    def test_decimal_half_up_boundary(self):
        codes = dict(zip(scoring.FACTOR_ORDER, 'D NA NA N LT NA N NA NA M D C UK UK I NA'.split()))
        r = scoring.score_codes(codes, fill_unknown=False)
        self.assertEqual(r['cwss_score'], 28.1)
        from decimal import Decimal
        self.assertEqual(Decimal(r['cwss_score_exact']), Decimal('28.05'))

    def test_preliminary_incomplete_not_low_risk(self):
        r = w.evaluate(finding(), SCAN)
        self.assertEqual(r['cwss_score'], 3.6)
        self.assertEqual(r['unknown_metric_count'], 15)
        self.assertEqual(r['assessment_status'], 'INCOMPLETE')
        self.assertFalse(r['fully_verified'])
        self.assertEqual(r['metric_assessments']['P']['classification'], 'NOT_APPLICABLE')
        self.assertTrue(all(r['factor_codes'][m] in ('U', 'UK') for m in scoring.FACTOR_ORDER if m != 'P'))

    def test_scenario_increases_and_decreases_using_same_engine(self):
        p = profile(mode='SCENARIO')
        p['metrics']['BI'] = metric('C', 'SCENARIO')
        high = w.evaluate(finding(), SCAN, p)
        self.assertGreater(high['cwss_score'], 3.6)
        self.assertFalse(high['fully_verified'])
        p['metrics']['BI']['code'] = 'N'
        self.assertEqual(w.evaluate(finding(), SCAN, p)['cwss_score'], 0)

    def test_machine_suggestions_never_become_attestation(self):
        p = profile()
        p['metrics']['TI'] = {'classification': 'MACHINE_SUGGESTED', 'code': 'H', 'verified': True}
        r = w.evaluate(finding(), SCAN, p)
        self.assertEqual(r['cwss_score'], 3.6)
        self.assertEqual(r['factor_codes']['TI'], 'UK')
        self.assertFalse(r['metric_assessments']['TI']['evidence_sufficient'])

    def test_cwe_alone_never_suggests_confirmed_impact(self):
        f = finding(); f.pop('iris_evidence'); f.pop('llm_api_role')
        ti = next(s for s in w.suggestions(f) if s['metric'] == 'TI')
        self.assertEqual(ti['code'], 'UK')
        self.assertEqual(w.evaluate(f, SCAN)['factor_codes']['TI'], 'UK')

    def test_four_cwe_leads_remain_only_suggestions(self):
        for cwe in (22, 78, 79, 89):
            r = w.evaluate(finding(cwe), SCAN)
            self.assertEqual(r['cwss_score'], 3.6)
            self.assertEqual(next(s for s in r['machine_suggestions'] if s['metric'] == 'TI')['code'], 'H')
            self.assertTrue(all(not s['applied_to_score'] for s in r['machine_suggestions']))

    def test_no_proven_true_from_taint(self):
        p = profile(); p['metrics']['FC'] = metric('T')
        with self.assertRaisesRegex(ValueError, 'independently reviewed'):
            w.evaluate(finding(), SCAN, p, 'alice')
        p['finding_verification'] = {'verdict': 'CONFIRMED_TRUE_POSITIVE', 'attacker_reachability_verified': False,
            'evidence': 'Synthetic independent local review evidence', 'reference': 'test-ref',
            'reviewer': 'alice', 'reviewed_at_utc': '2026-10-30T00:00:00Z'}
        with self.assertRaisesRegex(ValueError, 'reachability'):
            w.evaluate(finding(), SCAN, p, 'alice')
        p['finding_verification']['attacker_reachability_verified'] = True
        self.assertEqual(w.evaluate(finding(), SCAN, p, 'alice')['factor_codes']['FC'], 'T')

    def test_attestation_identity_evidence_and_context_gates(self):
        p = profile(); p['metrics']['BI'] = metric()
        for change in ({'reviewer': 'mallory'}, {'verified': False}, {'reason': 'short'}, {'reviewed_at_utc': 'bad'}, {'classification': 'VERIFIED'}):
            bad = copy.deepcopy(p); bad['metrics']['BI'].update(change)
            with self.assertRaises(ValueError): w.evaluate(finding(), SCAN, bad, 'alice')
        bad = copy.deepcopy(p); bad['context']['deployment_version_or_commit'] = ''
        with self.assertRaises(ValueError): w.evaluate(finding(), SCAN, bad, 'alice')

    def test_targeted_na_and_unknown_not_substituted(self):
        p = profile(); p['metrics']['P'] = metric('NA')
        with self.assertRaises(ValueError): w.evaluate(finding(), SCAN, p, 'alice')
        p = profile(); p['metrics']['BI'] = {'classification': 'UNKNOWN', 'code': 'C'}
        with self.assertRaises(ValueError): w.evaluate(finding(), SCAN, p, 'alice')

    def test_draft_preview_publish_replay_and_conflict(self):
        p = profile(); p['metrics']['BI'] = metric()
        a = self.store.save_draft(finding(), SCAN, p, 'alice')
        self.assertEqual(self.store.draft(SCAN, finding()['finding_id'], 'alice'), p)
        self.assertIsNone(self.store.draft(SCAN, finding()['finding_id'], 'bob'))
        self.assertEqual(self.store.history(SCAN, finding()['finding_id']), [])
        rev = self.store.publish(finding(), SCAN, p, 'alice', 0)
        self.assertEqual(rev['assessment'], a)
        self.assertTrue(self.store.replay(SCAN, finding()['finding_id'], 1)['replay_verified'])
        with self.assertRaises(w.Conflict): self.store.publish(finding(), SCAN, p, 'alice', 0)
        self.assertEqual(len(self.store.history(SCAN, finding()['finding_id'])), 1)

    def test_revision_hash_and_profile_hash_change_with_context(self):
        p = profile(); a = self.store.publish(finding(), SCAN, p, 'alice', 0)
        p['context']['deployment_version_or_commit'] = 'new-version'
        b = self.store.publish(finding(), SCAN, p, 'alice', 1)
        self.assertNotEqual(a['assessment']['profile_hash'], b['assessment']['profile_hash'])
        self.assertNotEqual(a['revision_hash'], b['revision_hash'])
        self.assertEqual(a['assessment']['cwss_score'], b['assessment']['cwss_score'])
        self.assertEqual(self.store.replay(SCAN, finding()['finding_id'], 1)['assessment'], a['assessment'])

    def test_invalid_publish_does_not_poison_history(self):
        p = profile(); self.store.publish(finding(), SCAN, p, 'alice', 0)
        p['metrics']['BI'] = metric('fake')
        with self.assertRaises(ValueError): self.store.publish(finding(), SCAN, p, 'alice', 1)
        self.assertEqual(len(self.store.history(SCAN, finding()['finding_id'])), 1)

    def test_atomic_concurrent_publish(self):
        def publish(_):
            try: self.store.publish(finding(), SCAN, profile(), 'alice', 0); return 'ok'
            except w.Conflict: return 'conflict'
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertCountEqual(list(pool.map(publish, range(2))), ['ok', 'conflict'])

    def test_revision_corruption_detected(self):
        self.store.publish(finding(), SCAN, profile(), 'alice', 0)
        with self.store.connect() as db:
            db.execute("UPDATE revisions SET envelope='{}'")
        with self.assertRaisesRegex(ValueError, 'checksum'):
            self.store.history(SCAN, finding()['finding_id'])

    def test_ranking_by_cwss_not_heuristic_or_page(self):
        a, b = finding(seq=1), finding(seq=2)
        a['final_heuristic_score'], b['final_heuristic_score'] = .99, .55
        p = profile(b); p['metrics']['BI'] = metric('C')
        self.store.publish(b, SCAN, p, 'alice', 0)
        rows = w.ranking([a, b], SCAN, self.store)
        self.assertEqual(rows[0]['finding_id'], b['finding_id'])
        self.assertEqual(rows[1]['mode'], 'PRELIMINARY')
        self.assertEqual(rows[0]['triage_decision'], 'REPORT')

    def test_scenarios_never_become_assessed_ranking(self):
        p = profile(mode='SCENARIO'); p['metrics']['BI'] = metric('C', 'SCENARIO')
        self.store.publish(finding(), SCAN, p, 'alice', 0)
        self.assertEqual(w.ranking([finding()], SCAN, self.store)[0]['mode'], 'PRELIMINARY')
        self.assertEqual(w.ranking([finding()], SCAN, self.store, 'SCENARIO', p['scenario_name'])[0]['mode'], 'SCENARIO')

    def test_no_mutation_and_determinism(self):
        f, p = finding(), profile(); before = copy.deepcopy((f, p))
        a = w.evaluate(f, SCAN, p, 'alice')
        self.assertEqual(a, w.evaluate(f, SCAN, p, 'alice'))
        self.assertEqual((f, p), before)

    def test_live_http_authorization_validation_publish_and_overlay(self):
        class Config:
            cors_allowed_origins = ('http://localhost:5173',)
        class State:
            config = Config()
            result_index = Index()
        state = State(); state.storage_dir = Path(self.tmp.name)/'http'
        env = {'NTK_CWSS_REVIEWER_TOKENS': json.dumps({'alice': TOKEN}),
               'NTK_CWSS_ASSESSMENT_DIR': str(state.storage_dir/'cwss-assessments')}
        with patch.dict('os.environ', env):
            server = service.create_ntk_http_server(port=0, state=state)
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            try:
                base = '/api/scans/'+SCAN+'/cwss/v1/findings/'+finding()['finding_id']
                def req(method, url, body=None, token='', origin=None):
                    conn = http.client.HTTPConnection('127.0.0.1', server.server_port)
                    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer '+token}
                    if origin: headers['Origin'] = origin
                    conn.request(method, url, json.dumps(body) if body is not None else None, headers)
                    response = conn.getresponse(); result = (response.status, json.loads(response.read())); conn.close()
                    return result
                p = profile(); p['metrics']['BI'] = metric('C')
                body = {'profile': p, 'expected_revision': 0}
                self.assertEqual(req('POST', base+'/publish', body)[0], 401)
                self.assertEqual(req('POST', base+'/publish', body, TOKEN, 'https://untrusted.example')[0], 403)
                self.assertEqual(req('POST', base+'/preview', body, TOKEN)[0], 200)
                self.assertEqual(req('POST', base+'/draft', body, TOKEN)[0], 200)
                self.assertEqual(req('GET', base+'/draft', token=TOKEN)[1]['profile'], p)
                self.assertEqual(req('POST', base+'/publish', body, TOKEN)[0], 201)
                self.assertEqual(req('POST', base+'/publish', body, TOKEN)[0], 409)
                self.assertTrue(req('GET', base+'/replay?revision=1')[1]['replay_verified'])
                self.assertEqual(req('GET', '/api/scans/'+SCAN+'/cwss/v1/ranking')[0], 200)
                exported = req('GET', '/api/scans/'+SCAN+'/cwss/v1/report')[1]
                self.assertTrue(exported['archive_unchanged'])
                self.assertEqual(exported['findings'][0]['revision'], 1)
                status, old = old_api.cwss_findings_page(state, SCAN)
                self.assertEqual(status, 200)
                self.assertEqual(old['assessments'][0]['cwss']['revision'], 1)
                self.assertEqual(state.result_index.findings[0], finding())
            finally:
                server.shutdown(); thread.join(); server.server_close()

    def test_changed_source_evidence_rejected_even_at_same_sink_line(self):
        p = profile()
        changed = finding(); changed['iris_evidence']['taint_trace_steps'].append('changed helper return')
        with self.assertRaisesRegex(ValueError, 'anchor mismatch'):
            w.evaluate(changed, SCAN, p, 'alice')
        self.store.publish(finding(), SCAN, p, 'alice', 0)
        with self.assertRaises(w.Conflict): w.ranking([changed], SCAN, self.store)

    def test_defaults_and_na_are_not_fully_verified_risk(self):
        f = finding(); f['review_status'] = 'CONFIRMED_TRUE_POSITIVE'
        p = profile(f)
        for m in scoring.FACTOR_ORDER:
            if m != 'P': p['metrics'][m] = metric('D')
        r = w.evaluate(f, SCAN, p, 'alice')
        self.assertEqual(r['unknown_metric_count'], 0)
        self.assertFalse(r['fully_verified'])
        self.assertIn('BI', r['verification_scope_limited_metrics'])

    def test_complete_attested_profile_uses_official_example_engine(self):
        f = finding()
        p = profile(f)
        values = 'H A A N T L A I N T A C H H N NA'.split()
        for m, code in zip(scoring.FACTOR_ORDER, values):
            if m != 'P': p['metrics'][m] = metric(code)
        p['finding_verification'] = {'verdict': 'CONFIRMED_TRUE_POSITIVE', 'attacker_reachability_verified': True,
            'evidence': 'Synthetic review for the MITRE example only', 'reference': 'test-ref',
            'reviewer': 'alice', 'reviewed_at_utc': '2026-10-30T00:00:00Z'}
        r = w.evaluate(f, SCAN, p, 'alice')
        self.assertEqual(r['cwss_score'], 92.6)
        self.assertTrue(r['fully_verified'])
        self.assertEqual(r['assessment_status'], 'COMPLETE')

    def test_incomplete_assessed_revision_remains_explicit(self):
        p = profile(); p['metrics']['BI'] = metric('H')
        a = self.store.publish(finding(), SCAN, p, 'alice', 0)['assessment']
        self.assertEqual(a['unknown_metric_count'], 14)
        self.assertEqual(a['assessment_completeness']['unknown_ratio'], 14/16)
        self.assertFalse(a['fully_verified'])

    def test_no_authorization_config_fails_closed(self):
        with patch.dict('os.environ', {'NTK_CWSS_REVIEWER_TOKENS': '{}'}):
            with self.assertRaises(PermissionError): w.authorize('Bearer '+TOKEN)
        with patch.dict('os.environ', {'NTK_CWSS_REVIEWER_TOKENS': '{"alice":"weak"}'}):
            with self.assertRaises(PermissionError): w.authorize('Bearer weak')

    def test_legacy_profile_validates_before_replace(self):
        import ntk_cwss_context as legacy
        p = legacy.template_for_scan(SCAN, [finding()])
        src = Path(self.tmp.name)/'profile.json'; src.write_text(json.dumps(p))
        published = legacy.publish_profile_checked(src, Path(self.tmp.name)/'legacy')
        before = published.read_bytes()
        p['findings'][finding()['finding_id']]['metric_assessments']['BI'] = {
            'code': 'bad', 'verified': True}
        src.write_text(json.dumps(p))
        with self.assertRaises(ValueError): legacy.publish_profile_checked(src, published.parent)
        self.assertEqual(published.read_bytes(), before)

    def test_new_scan_persists_preliminary_without_mutating_input(self):
        from types import SimpleNamespace
        class ResultIndex:
            def index_scan_record(self, **kwargs): return {'scan_id': kwargs['scan_id']}
        state = SimpleNamespace(storage_dir=Path(self.tmp.name), _lock=threading.Lock(),
            findings_by_id={}, pipeline_traces_by_scan={}, raw_opengrep_by_scan={}, scans={}, result_index=ResultIndex())
        payload = {'findings': [finding()]}; original = copy.deepcopy(payload)
        record = service.NtkBackendState.record_scan(state, SCAN, payload)
        self.assertEqual(payload, original)
        self.assertEqual(record['findings'][0]['cwss']['cwss_score'], 3.6)
        self.assertEqual(record['findings'][0]['decision'], 'REPORT')
        self.assertEqual(json.loads((Path(self.tmp.name)/(SCAN+'.json')).read_text())['sast_priority_policy'],
                         'CWSS_0_100_WITH_ASSESSMENT_STATE')

    def test_preview_does_not_create_published_revision(self):
        p = profile(); p['metrics']['BI'] = metric()
        w.evaluate(finding(), SCAN, p, 'alice')
        self.assertEqual(self.store.history(SCAN, finding()['finding_id']), [])

    def test_decimal_context_is_isolated_from_callers(self):
        from decimal import localcontext
        expected = scoring.score_codes({})
        with localcontext() as ctx:
            ctx.prec = 2
            self.assertEqual(scoring.score_codes({}), expected)

    def test_catalog_names_and_value_labels_cover_all_discrete_codes(self):
        for row in w.catalog()['metrics']:
            self.assertTrue(row['name'])
            self.assertEqual(set(row['values']), set(row['value_labels']))
        r = w.evaluate(finding(), SCAN)
        self.assertTrue(all(row['value_meaning'] for row in r['metric_assessments'].values()))

    def test_archived_html_report_separates_priority_triage_and_internal_score(self):
        f = finding(); f['cwss'] = w.evaluate(f, SCAN)
        html = service.render_scan_html_report({'scan_id': SCAN, 'findings': [f]})
        self.assertIn('CWSS 1.0.1', html)
        self.assertIn('INCOMPLETE', html)
        self.assertIn('not probability', html)
        self.assertIn('REPORT', html)
        self.assertIn('metric_assessments', html)


if __name__ == '__main__':
    unittest.main()
