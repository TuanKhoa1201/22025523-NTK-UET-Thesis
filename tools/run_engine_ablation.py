"""Run independent A/B/C/D executions; never ingest ground-truth labels.

B requires local Qwen for original IRIS mining. C additionally attempts its
native posthoc contract, retained as advisory because negative model output is
not a safe proof. Only D applies NTK triage/CWSS. Candidate discovery and final
triage are different estimands; this runner does not invent accuracy metrics.
"""
import argparse
from dataclasses import replace
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root',type=Path,required=True)
    parser.add_argument('--source-identity',required=True)
    parser.add_argument('--cwes',default='22,78,79,89')
    parser.add_argument('--output-dir',type=Path,required=True)
    parser.add_argument('--arms',default='A,B,C,D',help='Explicit subset is recorded; it is never called full ablation.')
    args=parser.parse_args()
    arms=args.arms.split(',')
    if not arms or len(set(arms))!=len(arms) or set(arms)-set('ABCD'):
        parser.error('Arms must be a unique comma-separated subset of A,B,C,D.')
    output=args.output_dir.resolve()
    if not output.is_relative_to(ROOT/'work') or output.exists():
        parser.error('Use a NEW directory within work/; existing artifacts are never overwritten.')
    source=args.source_root.resolve()
    files=sorted(source.rglob('*.java'))
    if not files or len(files)>500 or any(f.is_symlink() or not f.resolve().is_relative_to(source) for f in files):
        parser.error('Use a bounded canonical Java source scope (1..500 files).')
    manifest={f.relative_to(source).as_posix():sha(f.read_bytes()) for f in files}
    if sum(f.stat().st_size for f in files)>32*1024*1024:
        parser.error('Java source exceeds the 32 MiB acceptance bound.')
    output.mkdir(parents=True)
    os.environ.update(NTK_STORAGE_DIR=str(output/'storage'),NTK_EXT4_CACHE_DIR=str(output/'cache'),
                      HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1')
    scripts=ROOT/'backend/ntk-production-v2/scripts';sys.path.insert(0,str(scripts))
    import ntk_original_iris_adapter as iris
    import ntk_web_backend_service as service
    cwes=tuple(int(c) for c in args.cwes.split(','))
    config=replace(iris.IrisConfig.from_env(),mode='ORIGINAL_IRIS_CODEQL')
    if not iris.verify_license_attestation(config.licensed_source_attestation,args.source_identity):
        parser.error('Exact public-source identity/license attestation is required.')
    ntk=replace(service.NtkWebBackendConfig(),original_iris_mode='ORIGINAL_IRIS_CODEQL_STRICT',original_iris_cwes=cwes)
    model={'NTK_BASE_MODEL_PATH':ntk.base_model_path,'NTK_BEST_ADAPTER_PATH':ntk.best_adapter_path,
           'NTK_INFERENCE_DEVICE':ntk.device,'JAVA_HOME':config.java_home,'NTK_JAVAC_BIN':ntk.javac_bin}
    freeze={'source_identity':args.source_identity,'java_manifest':manifest,'cwes':cwes,
            'requested_arms':arms,'full_configuration_ablation':arms==['A','B','C','D'],
            'implementation_hashes':{p.name:sha(p.read_bytes()) for p in scripts.glob('*.py')},
            'ground_truth_received':False,'cache_policy':'force fresh engine/model mining; global CodeQL compiler caches may remain warm',
            'configurations':{'A':'OpenGrep candidate detection','B':'OpenGrep + native IRIS; local Qwen mining, no posthoc',
                              'C':'B + local native posthoc advisory, never a safe proof',
                              'D':'Full NTK strict mode, evidence fusion/triage/CWSS collection'}}
    (output/'freeze.json').write_text(json.dumps(freeze,indent=2))
    rules=output/'rules.yml';rules.write_text(service.DEFAULT_OPENGREP_RULES_YAML)

    def scan_opengrep():
        hits=[]
        for start in range(0,len(files),128):
            batch=files[start:start+128]
            p=subprocess.run([ntk.opengrep_bin,'scan','--json','--config',str(rules),'--no-git-ignore',
                              *map(str,batch)],capture_output=True,text=True,timeout=ntk.subprocess_timeout_sec)
            if p.returncode not in [0,1]:raise RuntimeError('OPENGREP_PROCESS_FAILED:'+str(p.returncode))
            data=json.loads(p.stdout)
            if {p.resolve() for p in batch}-{Path(p).resolve() for p in data.get('paths',{}).get('scanned',[])}:
                raise RuntimeError('OPENGREP_INVENTORY_INCOMPLETE')
            if data.get('errors'):raise RuntimeError('OPENGREP_DIAGNOSTICS_REQUIRE_REVIEW')
            hits.extend(h for h in data.get('results',[]) if service._infer_cwe_from_rule(h) in cwes)
        return hits

    results={}
    for arm in arms:
        if {f.relative_to(source).as_posix():sha(f.read_bytes()) for f in files}!=manifest:
            raise RuntimeError('SOURCE_CHANGED_AFTER_FREEZE')
        started=time.monotonic()
        if arm=='D':
            sid='SCAN-'+datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')+'-'+uuid.uuid4().hex[:6].upper()
            tracker=service.telemetry_mod.PipelineStageTracker(scan_id=sid)
            provenance={'source_mode':'ATTESTED_ABLATION_SOURCE',
                'archive_sha256' if len(args.source_identity)==64 else 'resolved_commit_sha':args.source_identity}
            result=service.scan_java_sources_and_triage(source,config=ntk,compile_check=False,force_fresh_scan=True,
                stage_tracker=tracker,repo_provenance=provenance,
                readiness_status='STRICT_ORIGINAL_IRIS_ABLATION')
            if result.get('status')=='OK':
                result=service.NtkBackendState(storage_dir=output/'storage').record_scan(sid,result)
        else:
            hits=scan_opengrep();result={'opengrep_hits':hits,'actual_gpu_inference_calls':0}
            if arm!='A':
                original=iris.run(source,files,args.source_identity,model_environment=model,cwes=cwes,
                    config=replace(config,skip_posthoc=arm=='B'),force_fresh=True)
                result.update(original_iris=original,actual_gpu_inference_calls=original['actual_gpu_inference_calls'],
                    union=iris.merge_callsite_evidence(hits,original['paths'],source))
        result['ablation_wallclock_sec']=time.monotonic()-started
        (output/(arm+'.json')).write_text(json.dumps(result,indent=2))
        results[arm]={'seconds':result['ablation_wallclock_sec'],'gpu_calls':result.get('actual_gpu_inference_calls'),
                      'status':result.get('status') or result.get('original_iris',{}).get('analysis_status','OPENGREP_EXECUTED')}
        (output/'execution-summary.json').write_text(json.dumps(results,indent=2))
    return 0


if __name__=='__main__':
    sys.exit(main())
