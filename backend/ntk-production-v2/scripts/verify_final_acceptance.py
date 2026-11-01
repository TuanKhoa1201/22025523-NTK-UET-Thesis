"""Verify a real persisted scan via HTTP; never submit scans or modify history."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
from urllib.request import Request, urlopen


def verify(base, scan, original_storage, output):
    output.mkdir(parents=True, exist_ok=True)
    checks = []

    def get(label, path, is_json=True):
        with urlopen(Request(base + path, headers={'Origin': 'http://localhost:5173'}), timeout=60) as response:
            raw = response.read()
            assert response.status == 200, (label, response.status)
            assert response.headers.get('Access-Control-Allow-Origin') == 'http://localhost:5173'
        (output / (label + ('.json' if is_json else '.html'))).write_bytes(raw)
        checks.append(label)
        return json.loads(raw) if is_json else raw.decode()

    health = get('health', '/api/health')
    assert health['status'] == 'OK' and health['torch_cuda_available']
    model = get('model', '/api/model')
    assert model['local_files_only'] and model['cloud_calls_enabled'] is False
    assert model['actual_model_device'] == 'cuda:0'
    assert model['lora_adapter_param_devices'] == ['cuda:0']
    summary = get('summary', f'/api/scans/{scan}/summary')
    full = get('full', f'/api/scans/{scan}?full=true')
    trace = get('trace', f'/api/scans/{scan}/pipeline-trace')
    assert len(trace['stages']) == 10 and all(s['state'] == 'COMPLETED' for s in trace['stages'])
    assert trace['state'] == 'COMPLETED' and full['actual_gpu_inference_calls'] > 0
    get('history', '/api/scans')
    get('jobs', '/api/scan-jobs')
    get('datasets', '/api/datasets/manifest')
    page = get('findings', f'/api/scans/{scan}/findings/page?page=1&page_size=50')
    rank = get('ranking', f'/api/scans/{scan}/cwss/v1/ranking?mode=CWSS_AUTO_COMPLETE')
    scenario = get('scenario', f'/api/scans/{scan}/cwss/v2/scenario?page=1&page_size=50')
    assert scenario['hypothetical'] is True and scenario['verified_deployment'] is False
    prior_paths = sorted(original_storage.glob('SCAN-*.json'))
    prior_path = next(p for p in prior_paths if not p.name.endswith('.pipeline_trace.json'))
    prior_bytes = prior_path.read_bytes()
    prior = json.loads(prior_bytes)
    assert full['resolved_commit'] == prior['resolved_commit']
    assert full['repository_provenance']['file_sha256_map'] == prior['repository_provenance']['file_sha256_map']
    previous = {f['finding_id']: f for f in prior['findings']}
    old_rank = get('original-ranking', f"/api/scans/{prior['scan_id']}/cwss/v1/ranking?mode=CWSS_AUTO_COMPLETE")
    old_scenario = get('original-scenario', f"/api/scans/{prior['scan_id']}/cwss/v2/scenario")
    old_scores = {r['finding_id']: r['cwss_score'] for r in old_rank['findings']}
    old_conditional = {r['finding_id']: r['cwss']['cwss_score'] for r in old_scenario['assessments']}
    ranking = {r['finding_id']: r for r in rank['findings']}
    contexts = {r['finding_id']: r['cwss'] for r in scenario['assessments']}
    assert len(page['findings']) == len(previous) == len(ranking) == len(contexts)
    rows, metrics = [], []
    for f in full['findings']:
        fid = f['finding_id']
        assert f['decision'] == previous[fid]['decision']
        assert f['iris_evidence']['flow_proof_state'] == previous[fid]['iris_evidence']['flow_proof_state']
        assert f['review_status'] == 'NOT_REVIEWED'
        assert f['confidence_score'] is None and f['final_heuristic_score'] is None
        assert f['fusion_score_breakdown']['numeric_score_used_for_decision'] is False
        result, conditional = ranking[fid], contexts[fid]
        graph = result['normalized_evidence']
        assert graph['source_bound'] and graph['ast_callsite'] or graph['iris_proof'] == 'UNKNOWN'
        assert graph['source_bound'], fid
        assert result['factor_codes']['FC'] != 'T' and conditional['factor_codes']['FC'] != 'T'
        proof = f['iris_evidence']['flow_proof_state']
        if proof == 'PROVEN_SAFE':
            assert graph['local_safe_proven'] and result['factor_codes']['TI'] == 'N', fid
        elif proof == 'PROVEN_TAINT':
            assert graph['local_taint_proven'] and graph['slot_binding_verified'], fid
        else:
            assert not graph['local_taint_proven'] and not graph['local_safe_proven'], fid
        for mode, assessment in [('GENERAL_JAVA', result), ('REFERENCE_SCENARIO', conditional)]:
            assert assessment['inference_version'] == 'NTK_CWSS_INFERENCE_V2'
            assert len(assessment['metric_assessments']) == 16
            for metric, value in assessment['metric_assessments'].items():
                assert all(k in value for k in ['code', 'weight', 'classification', 'rule_id', 'evidence', 'provenance'])
                metrics.append({'finding_id': fid, 'mode': mode, 'metric': metric, **value})
        detail = get('detail-' + fid, f'/api/scans/{scan}/findings/{fid}')
        get('automatic-' + fid, f'/api/scans/{scan}/cwss/v1/findings/{fid}/automatic')
        rows.append({'finding_id': fid, 'iris_proof': proof, 'triage': f['decision'],
                     'source_hash': graph['source_hash'], 'source_bound': graph['source_bound'],
                     'local_taint_proven': graph['local_taint_proven'], 'local_safe_proven': graph['local_safe_proven'],
                     'sink_slot': graph['sink_slot'], 'blocked_rules': graph['blocked_rules'],
                     'general_before': old_scores[fid], 'scenario_before': old_conditional[fid],
                     'general_after': result['cwss_score'], 'scenario_after': conditional['cwss_score']})
    for decision in ['REPORT', 'REVIEW', 'SUPPRESS']:
        filtered = get('filter-' + decision, f'/api/scans/{scan}/findings/page?decision={decision}&page_size=50')
        assert all(f['decision'] == decision for f in filtered['findings'])
    report = get('report', f'/api/scans/{scan}/report?format=html', False)
    assert 'Internal heuristic' not in report and 'metric_assessments' in report
    assert 'NTK_CWSS_INFERENCE_V2' in report
    result = {'status': 'PASS', 'scan_id': scan, 'original_scan_id': prior['scan_id'],
              'original_archive_sha256': hashlib.sha256(prior_bytes).hexdigest(),
              'resolved_commit': full['resolved_commit'], 'coverage': full['coverage_status'],
              'api_checks_passed': len(checks), 'pipeline_stages': len(trace['stages']),
              'actual_gpu_inference_calls': full['actual_gpu_inference_calls'],
              'duration_ms': full['total_e2e_duration_ms'], 'findings': rows}
    (output/'metric-provenance.json').write_text(json.dumps(metrics, indent=2))
    (output/'acceptance.json').write_text(json.dumps(result, indent=2))
    with (output/'metrics.csv').open('w', newline='') as handle:
        fields = ['finding_id','mode','metric','code','weight','classification','rule_id','evidence','provenance']
        writer=csv.DictWriter(handle,fieldnames=fields);writer.writeheader()
        for row in metrics:
            writer.writerow({k: json.dumps(row[k]) if isinstance(row[k],(dict,list)) else row[k] for k in fields})
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', default='http://127.0.0.1:8765')
    parser.add_argument('--scan-id', required=True)
    parser.add_argument('--original-storage', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args()
    verify(args.base_url.rstrip('/'), args.scan_id, args.original_storage, args.output_dir)
