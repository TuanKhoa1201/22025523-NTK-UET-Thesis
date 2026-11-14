"""Inspect public JavisOS receipt consistency only; never claim raw/runtime observation."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
from urllib.parse import urlsplit
from audit import load, sha
from contracts import require, hexhash, timestamp, STATUSES


def review(receipt, reference_sha):
    checks=[]
    def check(name,fn):
        try: detail=fn();status='PASS'
        except (ValueError,KeyError,TypeError,IndexError,AttributeError) as exc:detail=str(exc);status='FAIL'
        checks.append(dict(check=name,status=status,detail=detail))
    def identity():
        require(receipt['schema']=='ntk-g1-javis-runtime-verdict-1','unknown runtime receipt schema')
        require(receipt['candidate_id']=='G1-C1' and receipt['reference_pre_g1_sha']==reference_sha,'reference/candidate mismatch')
        require(receipt['candidate_available'] is False,'this readiness-review adapter requires pre-candidate receipt; use inspect_release for a real candidate')
        if receipt['candidate_available'] is False:
            require(receipt['tested_sha'] is None and receipt['reference_is_candidate'] is False
                    and receipt['verdict']=='INCOMPLETE' and receipt['reason']=='CANDIDATE_NOT_AVAILABLE','pre-candidate claims contradict verdict')
        return 'reference receipt identity only; no ready candidate joined'
    def model():
        host=receipt['host_environment'];prov=receipt['provenance']
        require(urlsplit(host['ollama_endpoint']).hostname in ('localhost','127.0.0.1','::1'),'nonlocal endpoint')
        require(host['model_name']==prov['model_tag'] and host['model_digest']==prov['model_digest'],'model metadata differs')
        hexhash(host['model_digest']);hexhash(prov['prompt_contract_schema_sha256']);hexhash(prov['rules_sha256'])
        require(host['opengrep_version']==prov['engine_version'],'engine version differs')
        return dict(engine=prov['engine_version'],model=prov['model_tag'],prompt_version=prov['prompt_version'],
                    limitation='model/digest and prompt schema hash are unverified public claims; prompt bytes absent')
    def finding_counts():
        p=receipt['runtime_pipeline_execution'];rows=p['per_finding_records']
        require(p['findings_total']==p['real_qwen_calls']==len(rows),'finding/request counts differ')
        require(len({r['alert_id'] for r in rows})==len(rows),'duplicate public alert ID')
        require(p['findings_with_trace']==sum('source' in r['trace_roles'] and 'sink' in r['trace_roles'] for r in rows),'trace count differs')
        require(p['warnings_by_validated_status']==dict(Counter(r['validated_status'] for r in rows)),'validator status counts differ')
        require(p['valid_qwen_responses']==sum(r['answer_validated'] is True for r in rows),'validated response count differs')
        require(p['valid_qwen_responses']+p['invalid_qwen_responses']==len(rows),'response counts differ')
        for r in rows:
            hexhash(r['alert_id']);require(r['raw_model_status'] in STATUSES and r['validated_status'] in STATUSES,'invalid model enum')
            require(r['review_state']=='OPEN' and r['http_status']==200,'public initial review/HTTP state differs')
            for key in ('request_payload_sha256','response_body_sha256','response_json_sha256'):hexhash(r[key])
        return dict(findings=len(rows),responses_claimed=len(rows),validated_claimed=p['valid_qwen_responses'])
    def artifact_hashes():
        for name,value in receipt['artifact_hashes'].items():hexhash(value)
        return dict(entries=len(receipt['artifact_hashes']),raw_hashes_recomputed=False)
    def scan_join():
        scan=receipt['artifact_hashes']['fork_cli_scan/opengrep.json']
        n=receipt['demos']['demo_1_real_warnings_cwe22_cwe89']['findings_count']
        rows=receipt['runtime_pipeline_execution']['per_finding_records'][:n]
        require(len(rows)==n and all(r['alert_id']==sha((scan+':'+str(i)).encode()) for i,r in enumerate(rows)),
                'reported demo1 scan hash/index does not derive reported alert IDs')
        return dict(public_hash_id_joins=n,limitation='demo2 raw scan hash not listed; private raw bytes unavailable for both demos')
    def timing():
        t=receipt['timings'];elapsed=(timestamp(t['session_finished_at_utc'])-timestamp(t['session_started_at_utc'])).total_seconds()*1000
        require(abs(elapsed-t['session_wall_clock_ms'])<10,'session duration differs')
        require(abs(sum(r['elapsed_seconds'] for r in receipt['runtime_pipeline_execution']['per_finding_records'])-t['total_qwen_inference_seconds'])<0.01,'per-warning elapsed sum differs')
        for command in receipt['commands_executed']:
            require(type(command['exit_code']) is int,'invalid command exit')
            require(timestamp(command['finished_at_utc'])>=timestamp(command['started_at_utc']),'reversed command timestamp')
            hexhash(command['stdout_sha256']);hexhash(command['stderr_sha256'])
        return dict(commands=len(receipt['commands_executed']),wall_clock_ms=t['session_wall_clock_ms'])
    def demo():
        d=receipt['demos'];stale=d['demo_4_stale_source_refusal']
        require(stale['confirm_false_exit_code']==2 and stale['no_new_event_appended'] is True
                and stale['warning_state_preserved'] is True,'stale refusal claims differ')
        require(d['demo_2_false_positive_review_scripted']['actor_is_simulated_not_independent_human'] is True,'demo actor misclassified')
        require(d['demo_5_qwen_fault_injection']['not_claimed_as_real_qwen_failure'] is True,'mock fault misclassified')
        p=receipt['runtime_pipeline_execution']
        require(p['fork_cli_has_triage_bridge_at_inspected_sha'] is False and p['opengrep_invocations_during_triage_bridge']==0,'pre-G1 route claims differ')
        return 'Scripted review/mock fault/readiness scope kept separate; SQLite and invocation log unavailable to Codex'
    for name,fn in (('identity',identity),('model',model),('findings',finding_counts),('artifact_hashes',artifact_hashes),
                    ('public_scan_id_join',scan_join),('timing',timing),('demo_scope',demo)):check(name,fn)
    return dict(schema='ntk-g1-public-runtime-review-1',reviewed_at=datetime.now(timezone.utc).isoformat(),
        reference_sha=reference_sha,candidate_sha=None,javis_tested_sha=receipt.get('tested_sha'),
        evidence_level='PUBLIC_RECEIPT_ONLY',checks=checks,
        public_consistency='FAIL' if any(c['status']=='FAIL' for c in checks) else 'PASS',
        g1_verdict='INCOMPLETE',reason='CANDIDATE_NOT_AVAILABLE',raw_artifacts_independently_checked=False,runtime_observed_by_codex=False,
        limitations=['No private raw JSON/SARIF, prompt/request/response bytes, DB, source or daemon logs accessed.',
            'Public counter/digest/hash consistency is not execution attestation or G1 candidate acceptance.'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--receipt',required=True);p.add_argument('--reference-sha',required=True);p.add_argument('--output',required=True)
    a=p.parse_args();result=review(load(a.receipt),a.reference_sha);result['public_receipt_sha256']=sha(Path(a.receipt).read_bytes())
    with Path(a.output).open('x',encoding='utf-8') as stream:stream.write(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({c['check']:c['status'] for c in result['checks']}));raise SystemExit(1 if result['public_consistency']=='FAIL' else 2)
