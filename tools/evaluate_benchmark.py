"""Frozen test-case/CWE evaluation; ground truth is never sent to the scanner."""
import argparse
import base64
import collections
import csv
import functools
import hashlib
import json
import os
from pathlib import Path
import sys
import time
from run_multiproject_acceptance import OUT, ROOT, run_job, save, zip_bytes
TAG=os.environ.get('NTK_EVAL_RUN_TAG','')


def run(group):
    selection=json.loads((OUT/'ground-truth-selection.json').read_text())
    cases=selection['regression6' if group=='six' else 'expanded40']
    source=OUT/'benchmark-eval-git';files={}
    for case in cases:
        relative='src/main/java/org/owasp/benchmark/testcode/'+case['case']+'.java'
        files[relative]=(source/relative).read_bytes()
    # Only source bytes go into the ZIP. CSV/labels/selection metadata stay here.
    data=zip_bytes(files);(OUT/('benchmark-'+group+TAG+'.zip')).write_bytes(data)
    result=run_job('benchmark-'+group+TAG,{'zip_base64':base64.b64encode(data).decode(),
        'archive_filename':'benchmark-'+group+'.zip','max_files_limit':50,'force_new_job':True})
    save('benchmark-'+group+TAG+'-result.json',result)


def metrics(truth,predictions):
    def confusion(review_positive=None):
        tp=fp=tn=fn=0
        for actual,pred in zip(truth,predictions):
            if pred=='REVIEW' and review_positive is None:continue
            positive=pred=='POSITIVE' or pred=='REVIEW' and review_positive
            if actual and positive:tp+=1
            elif actual:fn+=1
            elif positive:fp+=1
            else:tn+=1
        ratio=lambda a,b: a/b if b else None
        return {'TP':tp,'FP':fp,'TN':tn,'FN':fn,'precision':ratio(tp,tp+fp),'recall':ratio(tp,tp+fn),
                'FPR':ratio(fp,fp+tn),'F1':ratio(2*tp,2*tp+fp+fn)}
    return {'review_rate':predictions.count('REVIEW')/len(predictions),
            'automatic_decision_coverage':1-predictions.count('REVIEW')/len(predictions),
            'selective_decided_only':confusion(),
            'report_only_review_as_negative':confusion(False),
            'retain_review_as_positive':confusion(True)}


def score():
    sys.path.insert(0,str(ROOT/'backend/ntk-production-v2/scripts'))
    import ntk_alert_verification as av
    av.parse_java_source_with_javac_ast=functools.partial(av.parse_java_source_with_javac_ast,
        java_bin='/usr/lib/jvm/java-17-openjdk-amd64/bin/java',javac_bin='/usr/lib/jvm/java-17-openjdk-amd64/bin/javac')
    selection=json.loads((OUT/'ground-truth-selection.json').read_text());summaries={};all_cases=[];calls=[]
    for group,key in [('six','regression6'),('forty','expanded40')]:
        p=OUT/('benchmark-'+group+TAG+'-result.json')
        if not p.exists():continue
        result=json.loads(p.read_text());assert result['state']=='COMPLETED'
        record=result['full'];rows=[];fresh_ast_started=time.perf_counter()
        for item in selection[key]:
            found=[f for f in record['findings'] if Path(f['file_path']).stem==item['case']]
            target=[f for f in found if int(f['cwe_id'])==item['cwe']]
            proofs=[]
            for finding in found:
                path=OUT/'benchmark-eval-git'/finding['file_path'];source=path.read_text()
                # Independently rerun AST with scanner CWE, never the CSV target label.
                analysis=av.analyze_java_site_ast_and_taint(source,str(path),finding['line_number'],finding['cwe_id'])
                if finding in target:proofs.append(analysis.flow_proof_state)
                calls.append({'group':group,'case':item['case'],'target_cwe':item['cwe'],'ground_truth':item['vulnerable'],
                    'finding_id':finding['finding_id'],'finding_cwe':finding['cwe_id'],
                    'off_target_cwe':finding['cwe_id']!=item['cwe'],'line':finding['line_number'],
                    'decision':finding['decision'],'iris_proof':finding['iris_evidence']['flow_proof_state'],
                    'fresh_ast_proof':analysis.flow_proof_state,
                    'qwen_prediction':finding.get('llm_prediction',{}).get('predicted_role'),
                    'fusion_reason_codes':';'.join(finding.get('reason_codes',[])),
                    'scan_id':result['scan_id']})
            a='POSITIVE' if target else 'NEGATIVE'
            b='POSITIVE' if 'PROVEN_TAINT' in proofs else 'REVIEW' if 'UNKNOWN' in proofs else 'NEGATIVE'
            decisions=[f['decision'] for f in target]
            c='POSITIVE' if 'REPORT' in decisions else 'REVIEW' if 'REVIEW' in decisions else 'NEGATIVE'
            relative='src/main/java/org/owasp/benchmark/testcode/'+item['case']+'.java'
            rows.append({'group':group,**item,'source_sha256':hashlib.sha256((OUT/'benchmark-eval-git'/relative).read_bytes()).hexdigest(),
                'target_candidates':len(target),'off_target_candidates':len(found)-len(target),
                'iris_taint':proofs.count('PROVEN_TAINT'),'iris_safe':proofs.count('PROVEN_SAFE'),'iris_unknown':proofs.count('UNKNOWN'),
                'REPORT':decisions.count('REPORT'),'REVIEW':decisions.count('REVIEW'),'SUPPRESS':decisions.count('SUPPRESS'),
                'A_opengrep':a,'B_fresh_ast':b,'C_full_triage':c,'scan_id':result['scan_id']})
        truth=[r['vulnerable'] for r in rows]
        summaries[group]={'cases':len(rows),'scan_id':result['scan_id'],'source_commit':selection['commit'],
            'ast_analysis_version':av.AST_ANALYSIS_VERSION,'evaluation_run_tag':TAG,
            'fresh_ast_observation_duration_ms':round((time.perf_counter()-fresh_ast_started)*1000,3),
            'duration_ms':record['total_e2e_duration_ms'],'gpu_inference_calls':record['actual_gpu_inference_calls'],
            'cache_statistics':record['cache_statistics'],
            'A_opengrep':metrics(truth,[r['A_opengrep'] for r in rows]),
            'B_fresh_ast':metrics(truth,[r['B_fresh_ast'] for r in rows]),
            'C_full_triage':metrics(truth,[r['C_full_triage'] for r in rows])}
        all_cases.extend(rows)
    save('ground-truth-metrics'+TAG+'.json',summaries)
    for filename,rows in [('ground-truth-cases'+TAG+'.csv',all_cases),('ground-truth-findings'+TAG+'.csv',calls)]:
        with (OUT/filename).open('w',newline='') as h:
            writer=csv.DictWriter(h,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    print(json.dumps({g:{'cases':v['cases'],'scan':v['scan_id'],'full':v['C_full_triage']} for g,v in summaries.items()},indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('phase',choices=['six','forty','score']);a=p.parse_args()
    score() if a.phase=='score' else run(a.phase)
