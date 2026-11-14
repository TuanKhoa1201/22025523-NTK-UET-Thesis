"""Synthetic marker/receipt joins do not establish a real candidate or real runtime."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from inspect_release import inspect, runtime_join
from inspect_cli import inspect as inspect_cli
import os
import copy
from review_javis import review
from audit import sha


class ReleaseChecks(unittest.TestCase):
    def test_matching_receipt_stays_unattested(self):
        r=runtime_join(dict(candidate_id='SYNTHETIC-C1',tested_sha='a'*40),'SYNTHETIC-C1','a'*40)
        self.assertEqual(r['join'],'PASS');self.assertEqual(r['gate_verdict'],'INCOMPLETE')
        self.assertFalse(r['raw_artifacts_independently_checked']);self.assertFalse(r['runtime_observed'])

    def test_wrong_runtime_sha(self):
        with self.assertRaises(ValueError): runtime_join(dict(candidate_id='SYNTHETIC-C1',tested_sha='b'*40),'SYNTHETIC-C1','a'*40)

    def test_wrong_candidate_id(self):
        with self.assertRaises(ValueError): runtime_join(dict(candidate_id='SYNTHETIC-C2',tested_sha='a'*40),'SYNTHETIC-C1','a'*40)

    def test_missing_receipt_fields(self):
        with self.assertRaises(KeyError): runtime_join({'verdict':'PASS'},'SYNTHETIC-C1','a'*40)

    def test_missing_marker(self):
        with tempfile.TemporaryDirectory() as tmp, patch('inspect_release.git',side_effect=['a'*40,'']):
            r=inspect(tmp,'a'*40)
            self.assertEqual(r['reason'],'CANDIDATE_NOT_AVAILABLE');self.assertIsNone(r['candidate_sha'])

    def test_not_ready_marker(self):
        with tempfile.TemporaryDirectory() as tmp, patch('inspect_release.git',side_effect=['a'*40,'']):
            p=Path(tmp)/'v2/g1_integration';p.mkdir(parents=True)
            (p/'CANDIDATE.json').write_text(json.dumps({'status':'DRAFT','candidate_id':'SYNTHETIC-C1'}))
            r=inspect(tmp,'a'*40)
            self.assertEqual(r['reason'],'CANDIDATE_NOT_READY');self.assertIsNone(r['candidate_sha'])

    def test_ready_marker_uses_real_checkout_sha(self):
        with tempfile.TemporaryDirectory() as tmp, patch('inspect_release.git',side_effect=['a'*40,'','a'*40,'']):
            p=Path(tmp)/'v2/g1_integration';p.mkdir(parents=True)
            (p/'CANDIDATE.json').write_text(json.dumps({'status':'READY_FOR_INDEPENDENT_TEST','candidate_id':'SYNTHETIC-C1','claimed_sha':'b'*40}))
            r=inspect(tmp,'a'*40)
            self.assertEqual(r['candidate_sha'],'a'*40);self.assertEqual(r['verdict'],'INCOMPLETE')

    def test_static_cli_never_passes_runtime_gate(self):
        r=inspect_cli(os.environ['G1_CHECKOUT'],os.environ['G1_EXPECTED_SHA'])
        self.assertEqual(r['evidence_kind'],'STATIC_SOURCE_ONLY')
        self.assertEqual(r['gate_verdict'],'INCOMPLETE');self.assertTrue(r['files'])

    def public_receipt(self):
        scan='b'*64;ident=sha((scan+':0').encode())
        return dict(schema='ntk-g1-javis-runtime-verdict-1',candidate_id='G1-C1',reference_pre_g1_sha='a'*40,
            candidate_available=False,tested_sha=None,reference_is_candidate=False,verdict='INCOMPLETE',reason='CANDIDATE_NOT_AVAILABLE',
            host_environment=dict(ollama_endpoint='http://127.0.0.1:11434',model_name='qwen-synthetic',model_digest='c'*64,opengrep_version='1.25.0'),
            provenance=dict(model_tag='qwen-synthetic',model_digest='c'*64,prompt_contract_schema_sha256='d'*64,rules_sha256='e'*64,
                            engine_version='1.25.0',prompt_version='synthetic'),
            runtime_pipeline_execution=dict(findings_total=1,real_qwen_calls=1,findings_with_trace=1,valid_qwen_responses=1,invalid_qwen_responses=0,
                warnings_by_validated_status={'SUPPORTED':1},fork_cli_has_triage_bridge_at_inspected_sha=False,opengrep_invocations_during_triage_bridge=0,
                per_finding_records=[dict(alert_id=ident,trace_roles=['source','sink'],validated_status='SUPPORTED',raw_model_status='SUPPORTED',
                    answer_validated=True,review_state='OPEN',http_status=200,elapsed_seconds=1,
                    request_payload_sha256='f'*64,response_body_sha256='0'*64,response_json_sha256='1'*64)]),
            artifact_hashes={'fork_cli_scan/opengrep.json':scan},
            timings=dict(session_started_at_utc='2026-11-01T00:00:00Z',session_finished_at_utc='2026-11-01T00:00:02Z',session_wall_clock_ms=2000,total_qwen_inference_seconds=1),
            commands_executed=[],demos=dict(demo_1_real_warnings_cwe22_cwe89={'findings_count':1},
                demo_4_stale_source_refusal={'confirm_false_exit_code':2,'no_new_event_appended':True,'warning_state_preserved':True},
                demo_2_false_positive_review_scripted={'actor_is_simulated_not_independent_human':True},
                demo_5_qwen_fault_injection={'not_claimed_as_real_qwen_failure':True}))

    def test_public_readiness_positive_stays_incomplete(self):
        r=review(self.public_receipt(),'a'*40)
        self.assertEqual(r['public_consistency'],'PASS');self.assertEqual(r['g1_verdict'],'INCOMPLETE')
        self.assertFalse(r['runtime_observed_by_codex']);self.assertFalse(r['raw_artifacts_independently_checked'])

    def test_public_receipt_counts_hash_and_identity_corruption(self):
        mutations=[lambda v:v['runtime_pipeline_execution'].update(findings_total=2),
            lambda v:v['artifact_hashes'].update({'fork_cli_scan/opengrep.json':'x'}),
            lambda v:v['host_environment'].update(model_digest='0'*64),
            lambda v:v['runtime_pipeline_execution']['per_finding_records'][0].update(alert_id='0'*64),
            lambda v:v.update(tested_sha='a'*40)]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                v=self.public_receipt();mutate(v);self.assertEqual(review(v,'a'*40)['public_consistency'],'FAIL')


if __name__=='__main__':unittest.main()
