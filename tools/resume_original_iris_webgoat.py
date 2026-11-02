import hashlib,json,os,sys,time
from pathlib import Path
from argparse import ArgumentParser
parser=ArgumentParser(description='Resume real IRIS on preserved WebGoat database and API caches.')
parser.add_argument('--execute',action='store_true')
parser.add_argument('--cwes',default='79,89',help='CWE scope to execute; default resumes uncompleted queries.')
args=parser.parse_args()
if not args.execute:
    parser.print_help();raise SystemExit(0)
repo=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(repo/'backend/ntk-production-v2/scripts'))
import ntk_original_iris_adapter as adapter
root=Path('/home/tuankhoa/ntk-full-engine-20261102')
audit=repo/'work/full-engine-completion-20261102'
manifest=json.loads((audit/'webgoat-source-manifest.json').read_text())
source=Path(manifest['source']);commit=manifest['commit']
env=json.loads((repo/'work/acceptance/runtime/launch-env.json').read_text())
model_env={k:v for k,v in env.items() if k in ['NTK_BASE_MODEL_PATH','NTK_BEST_ADAPTER_PATH','NTK_INFERENCE_DEVICE','JAVA_HOME','NTK_JAVAC_BIN']}
runtime=root/'resumed-full-iris-v1';runtime.mkdir(exist_ok=True)
license_file=runtime/'reviewed-public-license.json'
license_file.write_text(json.dumps({'purpose':'ACADEMIC_RESEARCH','sources':[{
 'source_identity':commit,'resolved_commit':commit,'public_checkout_path':str(source),
 'upstream_url':'https://github.com/WebGoat/WebGoat','license_id':'GPL-2.0-only',
 'license_file':'LICENSE.txt','license_sha256':hashlib.sha256((source/'LICENSE.txt').read_bytes()).hexdigest()}]},indent=2))
cfg=adapter.IrisConfig(mode='ORIGINAL_IRIS_CODEQL_STRICT',
 upstream_dir='/home/tuankhoa/ntk-original-iris-research-20261102/upstream-iris-v2-3a12f457',
 upstream_commit='3a12f45750f58135bcc58c7fdf4c20786b600e31',
 codeql_bin='/home/tuankhoa/iris/codeql/codeql',runtime_root=str(runtime),
 timeout_sec=7200,max_runtime_bytes=4*1024**3,max_model_calls=2048,
 licensed_source_attestation=str(license_file),skip_posthoc=True,full_source_mode=True,
 java_all_pack='/home/tuankhoa/.codeql/packages/codeql/java-all/9.1.2',
 reused_database=str(root/'webgoat-full-db-v1'),reused_source_root=manifest['staged'])
started=time.monotonic()
result=adapter.run(source,[source/p for p in manifest['java_files']],commit,model_env,cfg,cwes=tuple(int(c) for c in args.cwes.split(',')))
(audit/'resumed-full-iris-result.json').write_text(json.dumps(result,indent=2))
print(json.dumps({k:v for k,v in result.items() if k not in ['paths','model_telemetry']},indent=2),flush=True)
