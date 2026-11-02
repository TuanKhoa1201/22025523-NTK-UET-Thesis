"""Real production pipeline on a byte-verified public Git checkout.

IRIS DB/API caches are intentionally primed by engineering checks. These runs
are INITIAL_PRIMED and WARM_REPEAT, not a claim of an all-layer cold benchmark.
"""
import os,sys,json,time,threading,urllib.request,uuid
from datetime import datetime,timezone
from pathlib import Path

from argparse import ArgumentParser
parser=ArgumentParser(description=__doc__)
parser.add_argument('--execute',action='store_true',help='Run the real pipeline twice; may take substantial time.')
if not parser.parse_args().execute:
    parser.print_help();raise SystemExit(0)
repo=Path(__file__).resolve().parents[1]
audit=repo/'work/full-engine-completion-20261102'
root=Path('/home/tuankhoa/ntk-full-engine-20261102')
runtime=root/'production-e2e-v1'
env=json.loads((repo/'work/acceptance/runtime/launch-env.json').read_text())
env.update(NTK_STORAGE_DIR=str(runtime/'storage'),NTK_EXT4_CACHE_DIR=str(runtime/'cache'),
 NTK_CWSS_ASSESSMENT_DIR=str(runtime/'storage/cwss-assessments'),
 NTK_ORIGINAL_IRIS_MODE='ORIGINAL_IRIS_CODEQL',NTK_ORIGINAL_IRIS_FULL_SOURCE_MODE='1',
 NTK_INCLUDE_JAVA_BUILD_WRAPPERS='1',NTK_ORIGINAL_IRIS_SKIP_POSTHOC='1',
 NTK_ORIGINAL_IRIS_DIR='/home/tuankhoa/ntk-original-iris-research-20261102/upstream-iris-v2-3a12f457',
 NTK_ORIGINAL_IRIS_COMMIT='3a12f45750f58135bcc58c7fdf4c20786b600e31',
 NTK_ORIGINAL_IRIS_CODEQL='/home/tuankhoa/iris/codeql/codeql',
 NTK_ORIGINAL_IRIS_RUNTIME=str(root/'resumed-full-iris-v1'),
 NTK_ORIGINAL_IRIS_LICENSE_ATTESTATION=str(root/'resumed-full-iris-v1/reviewed-public-license.json'),
 NTK_ORIGINAL_IRIS_JAVA_ALL_PACK='/home/tuankhoa/.codeql/packages/codeql/java-all/9.1.2',
 NTK_ORIGINAL_IRIS_REUSED_DATABASE=str(root/'webgoat-full-db-v1'),
 NTK_ORIGINAL_IRIS_REUSED_SOURCE_ROOT=str(root/'webgoat-all-java-v1'),
 NTK_ORIGINAL_IRIS_TIMEOUT_SEC='7200',NTK_ORIGINAL_IRIS_MAX_MODEL_CALLS='2048')
os.environ.update(env);sys.path.insert(0,str(repo/'backend/ntk-production-v2/scripts'))
import ntk_web_backend_service as service
cfg=service.NtkWebBackendConfig(max_new_tokens=160,subprocess_timeout_sec=120)
state=service.NtkBackendState(config=cfg,storage_dir=runtime/'storage',allow_local_dir=False)
server=service.create_ntk_http_server(port=8782,state=state)
thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
manifest=json.loads((audit/'webgoat-source-manifest.json').read_text());source=Path(manifest['source'])
rows=[];semantics=[]
try:
 for label in ['INITIAL_PRIMED','WARM_REPEAT']:
  sid='SCAN-'+datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')+'-'+uuid.uuid4().hex[:6].upper()
  tracker=service.telemetry_mod.PipelineStageTracker(scan_id=sid,source_mode='VERIFIED_PUBLIC_GIT_CHECKOUT')
  raw={};started=time.monotonic()
  payload=service.scan_java_sources_and_triage(source,config=cfg,compile_check=False,
   repo_provenance={'source_mode':'VERIFIED_PUBLIC_GIT_CHECKOUT','canonical_repo_url':'https://github.com/WebGoat/WebGoat',
     'resolved_commit_sha':manifest['commit'],'resolved_commit':manifest['commit']},
   raw_opengrep_sink=raw,stage_tracker=tracker,scan_scope_policy='FULL_REPOSITORY_BATCHED_SCAN')
  (runtime/(sid+'-before-persistence.json')).write_text(json.dumps(payload,indent=2))
  if payload.get('status')!='OK':
   rows.append({'label':label,'scan_id':sid,'status':payload.get('status'),'error':payload.get('error_code'),'seconds':time.monotonic()-started})
   (audit/'production-webgoat-runs.json').write_text(json.dumps(rows,indent=2));break
  record=state.record_scan(sid,payload,raw)
  urls=['/api/scans/'+sid+'/summary','/api/scans/'+sid+'/report?format=json',
    '/api/scans/'+sid+'/report?format=html','/api/scans/'+sid+'/pipeline-trace',
    '/api/scans/'+sid+'/findings?page=1&page_size=25','/api/scans/'+sid+'/cwss/v2/scenario?page_size=100']
  api=[]
  for index,url in enumerate(urls):
   try:
    with urllib.request.urlopen('http://127.0.0.1:8782'+url,timeout=120) as response:
     body=response.read();(runtime/(sid+'-http-'+str(index)+'.response')).write_bytes(body)
     api.append({'url':url,'status':response.status,'bytes':len(body)})
   except Exception as error:api.append({'url':url,'error':str(error)})
  findings=record['findings']
  stable=sorted((f['file_path'],f['line_number'],f['cwe_id'],f['decision'],(f.get('cwss') or {}).get('cwss_score')) for f in findings)
  semantics.append(stable)
  rows.append({'label':label,'scan_id':sid,'seconds':time.monotonic()-started,'status':record['status'],
    'engine_coverage_contract':record.get('engine_coverage_contract'),'summary':record.get('summary'),
    'full_scan_aggregates':record.get('full_scan_aggregates'),'original_iris_mode':record['original_iris']['engine_mode'],
    'iris_cache_hit':record['original_iris']['cache_hit'],'api':api,'findings':len(findings)})
  (audit/'production-webgoat-runs.json').write_text(json.dumps(rows,indent=2));print(json.dumps(rows[-1]),flush=True)
 (audit/'production-webgoat-equivalence.json').write_text(json.dumps({'runs':len(rows),
  'findings_decision_cwss_equal':len(semantics)==2 and semantics[0]==semantics[1],
  'initial_state':'DATABASE_AND_API_CACHES_PRIMED_NOT_ALL_LAYER_COLD'},indent=2))
finally:
 server.shutdown();server.server_close()
