"""Independent upstream IRIS/CodeQL execution, evidence binding and union policy.

The default is an explicitly named Javac fallback. Original/strict modes require
an administrator's licensed-source attestation and a pinned, pristine upstream.
Absence of a CodeQL path is never a safe proof.
"""
from dataclasses import asdict,dataclass
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
from urllib.parse import unquote,urlparse

ADAPTER_VERSION='NTK_ORIGINAL_IRIS_ADAPTER_V1'
MODES={'NTK_JAVAC_AST_FALLBACK','ORIGINAL_IRIS_CODEQL','ORIGINAL_IRIS_CODEQL_STRICT'}
WORKER=Path(__file__).with_name('ntk_original_iris_worker.py')


def digest(data):
    return hashlib.sha256(data if isinstance(data,bytes) else json.dumps(data,sort_keys=True,separators=(',',':')).encode()).hexdigest()


@dataclass(frozen=True)
class IrisConfig:
    mode:str='NTK_JAVAC_AST_FALLBACK'
    upstream_dir:str=''
    upstream_commit:str=''
    codeql_bin:str=''
    runtime_root:str=''
    python_bin:str=sys.executable
    java_home:str='/usr/lib/jvm/java-17-openjdk-amd64'
    timeout_sec:float=600
    max_java_files:int=500
    max_source_bytes:int=32*1024*1024
    max_runtime_bytes:int=1024*1024*1024
    max_rss_bytes:int=6*1024*1024*1024
    max_model_calls:int=64
    licensed_source_attestation:str=''
    skip_posthoc:bool=False
    full_source_mode:bool=False
    java_all_pack:str=''
    reused_database:str=''
    reused_source_root:str=''
    @classmethod
    def from_env(cls):
        return cls(mode=os.environ.get('NTK_ORIGINAL_IRIS_MODE','NTK_JAVAC_AST_FALLBACK'),
            upstream_dir=os.environ.get('NTK_ORIGINAL_IRIS_DIR',''),upstream_commit=os.environ.get('NTK_ORIGINAL_IRIS_COMMIT',''),
            codeql_bin=os.environ.get('NTK_ORIGINAL_IRIS_CODEQL',''),runtime_root=os.environ.get('NTK_ORIGINAL_IRIS_RUNTIME',''),
            licensed_source_attestation=os.environ.get('NTK_ORIGINAL_IRIS_LICENSE_ATTESTATION',''),
            skip_posthoc=os.environ.get('NTK_ORIGINAL_IRIS_SKIP_POSTHOC','0')=='1',
            full_source_mode=os.environ.get('NTK_ORIGINAL_IRIS_FULL_SOURCE_MODE','0')=='1',
            java_all_pack=os.environ.get('NTK_ORIGINAL_IRIS_JAVA_ALL_PACK',''),
            reused_database=os.environ.get('NTK_ORIGINAL_IRIS_REUSED_DATABASE',''),
            reused_source_root=os.environ.get('NTK_ORIGINAL_IRIS_REUSED_SOURCE_ROOT',''),
            timeout_sec=float(os.environ.get('NTK_ORIGINAL_IRIS_TIMEOUT_SEC','600')),
            max_model_calls=int(os.environ.get('NTK_ORIGINAL_IRIS_MAX_MODEL_CALLS','64')))


def failure(code,mode='IRIS_UNAVAILABLE',detail=''):
    return {'engine_id':mode,'engine_mode':mode,'analysis_status':mode,'verification_status':'NOT_VERIFIED',
        'paths':[],'reason_codes':[code],'detail':detail,'cloud_calls_enabled':False,'cache_hit':False,
        'actual_gpu_inference_calls':0,'duration_ms':0}


def verify_license_attestation(filename,source_identity):
    """Administrator records verified public OSI source identities explicitly.
    This is a legal-scope gate, never a detection label or ground truth input.
    """
    try:record=json.loads(Path(filename).read_text())
    except (OSError,ValueError):return False
    if not isinstance(record,dict) or not isinstance(record.get('sources'),list):return False
    return record.get('purpose')=='ACADEMIC_RESEARCH' and any(
        entry.get('source_identity')==source_identity and
        entry.get('license_id') in ['MIT','Apache-2.0','GPL-2.0-only','GPL-2.0-or-later','GPL-3.0-only','BSD-2-Clause','BSD-3-Clause','EPL-2.0'] and
        str(entry.get('upstream_url','')).startswith('https://github.com/') and
        re.fullmatch(r'[0-9a-f]{64}',str(entry.get('license_sha256','')))
        for entry in record.get('sources',[]) if isinstance(entry,dict))


def snapshot_sources(source_root,java_files,java_home='/usr/lib/jvm/java-17-openjdk-amd64'):
    root=Path(source_root).resolve();manifest={};packages=set();total=0
    java_files=list(java_files)
    for file in java_files:
        path=Path(file)
        if path.is_symlink():raise ValueError('IRIS_SOURCE_SYMLINK_REJECTED')
        if not path.resolve().is_relative_to(root) or path.suffix!='.java':
            raise ValueError('IRIS_SOURCE_SCOPE_ESCAPE')
    import ntk_alert_verification as verification
    verification.prewarm_javac_ast_cache([Path(p) for p in java_files],
        java_bin=str(Path(java_home)/'bin/java'),javac_bin=str(Path(java_home)/'bin/javac'))
    for file in java_files:
        path=Path(file)
        if path.is_symlink():raise ValueError('IRIS_SOURCE_SYMLINK_REJECTED')
        real=path.resolve()
        if not real.is_relative_to(root) or real.suffix!='.java':raise ValueError('IRIS_SOURCE_SCOPE_ESCAPE')
        data=real.read_bytes();relative=real.relative_to(root).as_posix();total+=len(data)
        manifest[relative]={'sha256':digest(data),'bytes':len(data)}
        import ntk_alert_verification as verification
        ast=verification.parse_java_source_with_javac_ast(data.decode('utf-8',errors='replace'),str(real),
            java_bin=str(Path(java_home)/'bin/java'),javac_bin=str(Path(java_home)/'bin/javac'))
        if not ast or ast.get('parse_success') is not True:raise ValueError('IRIS_SOURCE_PARSE_NOT_VERIFIED')
        if ast.get('package_name'):packages.add(ast['package_name'])
    return manifest,sorted(packages),total


def verify_public_source_binding(filename,source_identity,source_root,manifest):
    """Verify reviewed license bytes and source bytes against a pinned Git tree.

    This proves the attested input binding, not a legal opinion or that an
    arbitrary GitHub URL makes a private source public.
    """
    entries=json.loads(Path(filename).read_text())['sources']
    entry=next(e for e in entries if e.get('source_identity')==source_identity)
    checkout=Path(entry['public_checkout_path']).resolve();commit=entry['resolved_commit']
    if not re.fullmatch('[0-9a-f]{40}',commit):raise ValueError('LICENSE_COMMIT_REQUIRED')
    def git(*args):
        return subprocess.run(['git','-C',str(checkout),*args],capture_output=True,timeout=30,check=True).stdout
    remote=git('remote','get-url','origin').decode().strip().removesuffix('.git')
    if remote!=entry['upstream_url'].removesuffix('.git'):raise ValueError('LICENSE_REMOTE_MISMATCH')
    license_bytes=git('show',commit+':'+entry['license_file'])
    if digest(license_bytes)!=entry['license_sha256']:raise ValueError('LICENSE_BYTES_MISMATCH')
    tree={}
    for line in git('ls-tree','-r','-z',commit).split(b'\0'):
        if not line:continue
        meta,name=line.split(b'\t',1);mode,kind,sha=meta.split()
        if kind==b'blob' and mode!=b'120000':tree[name.decode()]=sha.decode()
    for relative,meta in manifest.items():
        data=(Path(source_root)/relative).read_bytes()
        blob=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
        if digest(data)!=meta['sha256'] or tree.get(relative)!=blob:raise ValueError('LICENSE_SOURCE_GIT_BLOB_MISMATCH')
    return {'resolved_commit':commit,'license_sha256':digest(license_bytes),'java_git_blobs_verified':len(manifest)}


def _location(location,source_root,manifest):
    physical=location.get('physicalLocation',{})
    uri=physical.get('artifactLocation',{}).get('uri','');parsed=urlparse(uri)
    if parsed.scheme not in ['','file']:raise ValueError('IRIS_NON_FILE_LOCATION')
    if parsed.netloc:raise ValueError('IRIS_REMOTE_FILE_AUTHORITY_REJECTED')
    raw=unquote(parsed.path if parsed.scheme=='file' else uri)
    path=Path(raw)
    root=Path(source_root).resolve();resolved=(path if path.is_absolute() else root/path).resolve()
    if not resolved.is_relative_to(root):raise ValueError('IRIS_SARIF_SOURCE_ESCAPE')
    relative=resolved.relative_to(root).as_posix()
    if relative not in manifest:raise ValueError('IRIS_SARIF_FILE_NOT_IN_SNAPSHOT')
    data=resolved.read_bytes()
    if digest(data)!=manifest[relative]['sha256']:raise ValueError('IRIS_SARIF_SOURCE_SHA_MISMATCH')
    region=physical.get('region',{});line=int(region.get('startLine',0))
    if not 1<=line<=len(data.splitlines()):raise ValueError('IRIS_SARIF_LINE_OUT_OF_RANGE')
    return {'file_path':relative,'line':line,'column':region.get('startColumn'),
        'source_sha256':manifest[relative]['sha256'],'message':location.get('message',{}).get('text','')}


def bind_sarif(sarif,source_root,manifest,cwe,provenance):
    """Bind actual CodeQL thread-flow locations. Never infer a path from hits."""
    paths=[];rejected=[]
    for run in sarif.get('runs',[]):
        if any(i.get('executionSuccessful') is False for i in run.get('invocations',[])):
            rejected.append('IRIS_CODEQL_INVOCATION_FAILED');continue
        for result in run.get('results',[]):
            for flow in result.get('codeFlows',[]):
                for thread in flow.get('threadFlows',[]):
                    try:
                        steps=[_location(step['location'],source_root,manifest) for step in thread.get('locations',[])]
                        if len(steps)<2:raise ValueError('IRIS_INCOMPLETE_TAINT_PATH')
                        primary=_location(result['locations'][0],source_root,manifest) if result.get('locations') else steps[-1]
                        path={**provenance,'engine_id':'IRIS_ORIGINAL_CODEQL','engine_mode':'ORIGINAL_IRIS_CODEQL',
                            'query_id':result.get('ruleId',provenance.get('query_id')),'cwe_id':int(cwe),
                            'source_location':steps[0],'source_symbol':steps[0]['message'],
                            'sink_location':steps[-1],'sink_symbol':steps[-1]['message'],'callsite_location':primary,
                            'taint_path_steps':steps,'analysis_status':'PATH_FOUND','verification_status':'SOURCE_BOUND_CODEQL_PATH',
                            'reason_codes':['CODEQL_THREAD_FLOW_SOURCE_BYTES_VERIFIED'],
                            'semantic_limit':'FLOW_IS_CONDITIONAL_ON_PINNED_MINED_SOURCE_SINK_MODELS_NOT_EXPERT_TP'}
                        path['path_id']=digest(path);paths.append(path)
                    except (ValueError,KeyError,TypeError,OSError) as error:rejected.append(str(error))
    return paths,rejected


def merge_callsite_evidence(opengrep_hits,iris_paths,source_root):
    """Union by source/CWE/callsite; preserve all independent path IDs."""
    root=Path(source_root).resolve();by_site={}
    for hit in opengrep_hits:
        path=Path(hit['path']).resolve();relative=path.relative_to(root).as_posix()
        cwe=int(hit.get('extra',{}).get('metadata',{}).get('cwe',0))
        key=(relative,cwe,int(hit['start']['line']))
        by_site[key]={'hit':hit,'engines':['OPENGREP'],'iris_paths':[]}
    for path in iris_paths:
        loc=path['callsite_location'];key=(loc['file_path'],int(path['cwe_id']),int(loc['line']))
        if key not in by_site:
            file=root/loc['file_path'];line=loc['line'];text=file.read_text(encoding='utf-8',errors='replace').splitlines()[line-1]
            # An IRIS candidate has its own origin; this is never added to raw
            # OpenGrep output or described as an OpenGrep rule match.
            by_site[key]={'hit':{'path':str(file),'start':{'line':line},'check_id':'original-iris/'+str(path['query_id']),
                'extra':{'metadata':{'cwe':path['cwe_id']},'lines':text,'severity':'ERROR','candidate_origin':'IRIS_ORIGINAL_CODEQL'}},
                'engines':[],'iris_paths':[]}
        entry=by_site[key]
        if 'IRIS_ORIGINAL_CODEQL' not in entry['engines']:entry['engines'].append('IRIS_ORIGINAL_CODEQL')
        if not any(p['path_id']==path['path_id'] for p in entry['iris_paths']):entry['iris_paths'].append(path)
    return list(by_site.values())


def fuse_decision(ast_decision,ast_safe,iris_paths):
    verified=[p for p in iris_paths if p.get('verification_status')=='SOURCE_BOUND_CODEQL_PATH']
    if verified and ast_safe:return 'REVIEW',['IRIS_PATH_CONFLICTS_WITH_LOCAL_SAFE_PROOF']
    if any(p.get('cwe_context_verified') for p in verified):return 'REPORT',['VALIDATED_ORIGINAL_IRIS_CODEQL_PATH','MODEL_SPEC_DEPENDENT_FLOW']
    if verified:return ast_decision,['ORIGINAL_IRIS_MINED_MODEL_CWE_CONTEXT_UNCONFIRMED']
    return ast_decision,[] # No path / unavailable engine is never a safe proof.


def attach_api_context(paths,api_csv,source_root):
    """Use actual upstream CodeQL call identities, not model labels, to reject
    cross-CWE paths. Novel/ambiguous sinks stay REVIEW, not auto-REPORT.
    This deliberately small policy does not claim full framework coverage.
    """
    with open(api_csv) as handle:rows=list(csv.DictReader(handle))
    def lookup(location):
        matches=[]
        for row in rows:
            match=re.match(r'^(file://.*):(\d+):(\d+):(\d+):(\d+)$',row.get('location',''))
            if not match:continue
            file=Path(unquote(urlparse(match[1]).path))
            if file.resolve()!= (Path(source_root)/location['file_path']).resolve():continue
            start,col,end,endcol=map(int,match.groups()[1:])
            line=location['line'];column=location.get('column') or 0
            if start<=line<=end and (line!=start or column>=col) and (line!=end or column<=endcol):
                identity={'package':row['package'],'class':row['clazz'],'method':row['func'],'signature':row['full_signature']}
                if identity not in matches:matches.append(identity)
        return matches[0] if len(matches)==1 else None
    for path in paths:
        source=lookup(path['source_location']);sink=lookup(path['sink_location']);path['codeql_source_api']=source;path['codeql_sink_api']=sink
        remote=bool(source and (source['package'] in ['javax.servlet','javax.servlet.http','jakarta.servlet','jakarta.servlet.http']
            and source['class'] in ['ServletRequest','HttpServletRequest']
            and source['method'] in ['getParameter','getParameterValues','getParameterMap','getHeader','getHeaders','getQueryString','getPathInfo','getRequestURI','getInputStream','getReader'] or
            source['package']=='java.lang' and source['class']=='System' and source['method']=='getenv'))
        supported=False
        if sink:
            package=sink['package'];clazz=sink['class'];method=sink['method'];cwe=path['cwe_id']
            if cwe==22:supported=(package=='java.io' and clazz in ['FileInputStream','FileOutputStream','FileReader','FileWriter','RandomAccessFile']
                or package=='java.nio.file' and clazz=='Files' and method in ['newInputStream','newOutputStream','readAllBytes','readString','write','newBufferedReader','newBufferedWriter'])
            elif cwe==78:
                params=sink['signature'].split('(',1)[-1].rsplit(')',1)[0]
                supported=package=='java.lang' and (clazz=='ProcessBuilder' and method=='start' or clazz=='Runtime' and method=='exec' and ',' not in params)
            elif cwe==89:supported=package=='java.sql' and clazz=='Statement' and method in ['execute','executeQuery','executeUpdate','executeLargeUpdate','addBatch'] and ',' not in sink['signature'].split('(',1)[-1]
            # XSS requires an HTTP output-context proof, not merely PrintWriter.
        path['cwe_context_verified']=remote and supported
        path['cwe_context_policy']='CODEQL_TYPED_STANDARD_API_CONTEXT_V1_CONSERVATIVE'


def _stop(process):
    if process.poll() is None:
        os.killpg(process.pid,signal.SIGTERM)
        try:process.wait(timeout=3)
        except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=3)


def attach_standard_flow_context(paths,proof_csv,source_root,manifest):
    """Require both endpoints of an independently executed stock CWE flow.

    No result is not a safe proof. This only corroborates existing upstream
    thread flows; it cannot manufacture a new path or a suppression.
    """
    proof=Path(proof_csv);pairs=set()
    def location(row,prefix):
        file=Path(row[prefix+'_file']).resolve()
        return _location({'physicalLocation':{'artifactLocation':{'uri':file.as_uri()},
            'region':{'startLine':int(row[prefix+'_line']),'startColumn':int(row[prefix+'_column'])}}},source_root,manifest)
    def endpoint(loc):return (loc['file_path'],loc['line'],loc['column'])
    with proof.open() as handle:
        for row in csv.DictReader(handle):pairs.add((endpoint(location(row,'source')),endpoint(location(row,'sink'))))
    for path in paths:
        if (endpoint(path['source_location']),endpoint(path['sink_location'])) in pairs:
            path.update(cwe_context_verified=True,cwe_context_policy='INDEPENDENT_STOCK_CODEQL_CWE_FLOW_V1',
                contextual_proof_artifact=str(proof),contextual_proof_sha256=digest(proof.read_bytes()))


def reusable_execution(worker,reasons,full_source_mode):
    if not reasons:return True
    # Reuse a completed, content-bound query execution with the SAME explicit
    # contract limitations. This never promotes PARTIAL to COMPLETED. Budget,
    # extraction, query, binding and cancellation failures are not reusable.
    allowed={'API_ROLE_CONTRACT_UNSUPPORTED','NATIVE_PARAMETER_CONTRACT_UNSUPPORTED'}
    return (full_source_mode and bool(worker.get('pipelines')) and set(reasons)<=allowed
        and all(p.get('analysis_status')=='COMPLETED' for p in worker['pipelines']))


def run(source_root,java_files,source_identity,model_environment=None,config=None,cwes=(22,78,79,89),cancel_event=None,force_fresh=False):
    cfg=config or IrisConfig.from_env();started=time.monotonic()
    if cfg.mode not in MODES:return failure('INVALID_IRIS_ENGINE_MODE','IRIS_FAILED')
    if cfg.mode=='NTK_JAVAC_AST_FALLBACK':return failure('ORIGINAL_IRIS_NOT_ENABLED','NTK_JAVAC_AST_FALLBACK')
    if not cwes or any(c not in [22,78,79,89] for c in cwes):return failure('IRIS_UNSUPPORTED_CWE_SCOPE','IRIS_FAILED')
    if not cfg.licensed_source_attestation:return failure('CODEQL_LICENSE_SOURCE_SCOPE_NOT_ATTESTED')
    if not verify_license_attestation(cfg.licensed_source_attestation,source_identity):return failure('CODEQL_SOURCE_LICENSE_NOT_VERIFIED_FOR_IDENTITY')
    if not all([cfg.runtime_root,cfg.upstream_dir,cfg.upstream_commit,cfg.codeql_bin]):return failure('ORIGINAL_IRIS_CONFIGURATION_MISSING')
    try:
        upstream=Path(cfg.upstream_dir).resolve();runtime=Path(cfg.runtime_root).resolve()
        if runtime==Path(source_root).resolve() or 'work/acceptance/runtime' in runtime.as_posix():raise ValueError('IRIS_RUNTIME_MUST_BE_ISOLATED')
        head=subprocess.run(['git','-C',str(upstream),'rev-parse','HEAD'],capture_output=True,text=True,timeout=15,check=True).stdout.strip()
        if head!=cfg.upstream_commit:raise ValueError('IRIS_UPSTREAM_COMMIT_MISMATCH')
        dirty=subprocess.run(['git','-C',str(upstream),'status','--porcelain','--untracked-files=no'],capture_output=True,text=True,timeout=15,check=True).stdout
        if dirty:raise ValueError('IRIS_UPSTREAM_TRACKED_SOURCE_MODIFIED')
        cli_version=json.loads(subprocess.run([cfg.codeql_bin,'version','--format=json'],capture_output=True,text=True,timeout=15,check=True).stdout)
        manifest,packages,total=snapshot_sources(source_root,java_files,cfg.java_home)
        if not manifest:raise ValueError('IRIS_NO_JAVA_SOURCE')
        if len(manifest)>cfg.max_java_files or total>cfg.max_source_bytes:raise ValueError('IRIS_SOURCE_RESOURCE_LIMIT')
        license_binding=None
        if cfg.full_source_mode:
            license_binding=verify_public_source_binding(cfg.licensed_source_attestation,source_identity,source_root,manifest)
        env_model=model_environment or {}
        model_files={}
        for key,filename in [('NTK_BEST_ADAPTER_PATH','adapter_model.safetensors'),('NTK_BASE_MODEL_PATH','config.json')]:
            if env_model.get(key):
                directory=Path(env_model[key]);files=[directory/filename]
                if key=='NTK_BASE_MODEL_PATH':files+=sorted(directory.glob('*.safetensors'))
                from ntk_engine_cache import file_hash
                model_files[key]=digest({f.name:file_hash(f) for f in files})
        templates={str(p.relative_to(upstream)):digest(p.read_bytes()) for p in (upstream/'src').rglob('*') if p.suffix in ['.py','.ql','.qll']}
        identity={'adapter_version':ADAPTER_VERSION,'source_identity':source_identity,'source_manifest':manifest,'upstream_commit':head,
            'codeql_version':cli_version['version'],'codeql_build':cli_version.get('sha'),'upstream_templates':digest(templates),
            'model_files':model_files,'model_identity':env_model.get('NTK_BASE_MODEL_PATH'),'cwes':list(cwes),
            'worker_hash':digest(WORKER.read_bytes()),'adapter_hash':digest(Path(__file__).read_bytes()),
            'prompt_code_hash':digest(Path(__file__).with_name('ntk_iris_shared.py').read_bytes()),
            'build_mode':'NONE_JAVA_ONLY_NO_BUILD_SCRIPTS','policy':asdict(cfg)}
        if cfg.full_source_mode:
            from ntk_engine_cache import file_hash
            from ntk_codeql_models import LibraryModels
            identity['extension_hashes']={name:file_hash(Path(__file__).with_name(name+'.py')) for name in
                ['ntk_engine_cache','ntk_codeql_models','ntk_iris_codegen_extension','ntk_iris_full_mining','ntk_local_role_batch']}
            identity['library_models_hash']=LibraryModels(cfg.java_all_pack).hash
            identity['java_all_pack_content_hash']=digest({p.relative_to(cfg.java_all_pack).as_posix():file_hash(p)
                for p in Path(cfg.java_all_pack).rglob('*') if p.is_file() and p.suffix in ['.ql','.qll','.yml']})
            identity['codeql_executable_hash']=file_hash(cfg.codeql_bin)
        key=digest(identity);runtime.mkdir(parents=True,exist_ok=True)
        cache=runtime/'bound-cache'/key/'result.json'
        if not force_fresh and cache.exists():
            entry=json.loads(cache.read_text());result=entry['result']
            if entry['identity']!=identity or digest(result)!=entry['result_sha256']:raise ValueError('IRIS_CACHE_IDENTITY_OR_PAYLOAD_MISMATCH')
            artifacts={}
            for path in result.get('paths',[]):
                artifacts[path['raw_artifact_reference']]=path['raw_artifact_sha256']
                if path.get('contextual_proof_artifact'):
                    artifacts[path['contextual_proof_artifact']]=path['contextual_proof_sha256']
            for filename,expected_sha in artifacts.items():
                if digest(Path(filename).read_bytes())!=expected_sha:raise ValueError('IRIS_CACHE_PROOF_ARTIFACT_CHANGED')
            if cfg.full_source_mode and cfg.reused_database:
                from ntk_engine_cache import verify_source_archive
                if verify_source_archive(cfg.reused_database,cfg.reused_source_root,manifest)!=result['database_receipt']['archive_verification']:
                    raise ValueError('IRIS_CACHE_DATABASE_ARCHIVE_CHANGED')
            if cfg.full_source_mode:
                result={**result,'execution_origin':'VALIDATED_CACHE_REUSE','cached_execution_duration_ms':result['duration_ms'],
                    'model_telemetry_from_cached_execution':True,'commands_from_cached_execution':True,
                    'current_cwe_query_pipeline_invocations':0}
            result={**result,'cache_hit':True,'actual_gpu_inference_calls':0,'duration_ms':round((time.monotonic()-started)*1000,3)}
            return result
        work=runtime/'runs'/(key[:16]+'-'+str(time.time_ns()));work.mkdir(parents=True)
        staged=work/'java-source';database_path=work/'database';database_receipt=None
        env=dict(os.environ,HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1',JAVA_HOME=cfg.java_home,
            LGTM_INDEX_XML_MODE='none',LGTM_INDEX_PROPERTIES_FILES='false',PYTHONDONTWRITEBYTECODE='1')
        env['PATH']=cfg.java_home+'/bin:/usr/bin:/bin'
        if cfg.full_source_mode:
            from ntk_engine_cache import database,verify_source_archive
            if cfg.reused_database:
                import yaml
                database_path=Path(cfg.reused_database).resolve();staged=Path(cfg.reused_source_root).resolve()
                metadata=yaml.safe_load((database_path/'codeql-database.yml').read_text())
                if str(metadata.get('creationMetadata',{}).get('cliVersion'))!=cli_version['version']:
                    raise ValueError('REUSED_DATABASE_CODEQL_VERSION_MISMATCH')
                if (metadata.get('primaryLanguage')!='java' or metadata.get('finalised') is not True
                    or metadata.get('buildMode')!='none' or Path(metadata.get('sourceLocationPrefix','')).resolve()!=staged):
                    raise ValueError('REUSED_DATABASE_EXTRACTION_METADATA_MISMATCH')
                verified=verify_source_archive(database_path,staged,manifest)
                for relative,meta in manifest.items():
                    if digest((staged/relative).read_bytes())!=meta['sha256']:raise ValueError('REUSED_DATABASE_STAGED_SOURCE_CHANGED')
                database_receipt={'database_id':digest(verified),'archive_verification':verified,'cache_hit':True,
                    'actual_creation_duration_ms':0,'reuse_mode':'EXPLICIT_VERIFIED_PREEXISTING_DATABASE_NOT_COLD_EXTRACTION'}
            else:
                database_path,staged,database_receipt=database(runtime/'persistent-cache',source_root,manifest,identity,
                    cfg.codeql_bin,cfg.java_home,env,cfg.timeout_sec,cfg.max_rss_bytes,cancel_event)
        else:
            staged.mkdir()
            for relative,meta in manifest.items():
                target=staged/relative;target.parent.mkdir(parents=True,exist_ok=True);data=(Path(source_root)/relative).read_bytes()
                if digest(data)!=meta['sha256']:raise ValueError('IRIS_SOURCE_CHANGED_DURING_SNAPSHOT')
                target.write_bytes(data)
        request={'workspace':str(work/'upstream-execution'),'source_root':str(staged),'source_hash':digest(manifest),
            'upstream_dir':str(upstream),'upstream_commit':head,'database':str(database_path),'packages':packages,
            'codeql_bin':cfg.codeql_bin,'java_home':cfg.java_home,'cwes':list(cwes),'model_environment':env_model,
            'result_file':str(work/'worker-result.json'),'max_model_calls':cfg.max_model_calls,'skip_posthoc':cfg.skip_posthoc}
        if cfg.full_source_mode:
            request.update(full_source_mode=True,persistent_cache_root=str(runtime/'persistent-cache'),
                java_all_pack=cfg.java_all_pack,model_identity=model_files)
        (work/'request.json').write_text(json.dumps(request,indent=2))
        env=dict(os.environ,HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1',JAVA_HOME=cfg.java_home,
            LGTM_INDEX_XML_MODE='none',LGTM_INDEX_PROPERTIES_FILES='false',PYTHONDONTWRITEBYTECODE='1')
        env['PATH']=cfg.java_home+'/bin:/usr/bin:/bin'
        db_cmd=[cfg.codeql_bin,'database','create',request['database'],'--language=java','--build-mode=none',
            '--source-root='+str(staged),'--search-path='+str(Path(cfg.codeql_bin).parent/'java'),'--threads=1','--ram=2048']
        commands=[('database',db_cmd),('iris',[cfg.python_bin,'-B',str(WORKER),str(work/'request.json')])]
        if cfg.full_source_mode:commands=commands[1:]
        peak_rss=0;receipts=[];last_disk_check=0
        import psutil
        for label,argv in commands:
            t=time.monotonic()
            with (work/(label+'.log')).open('w') as log:
                process=subprocess.Popen(argv,env=env,cwd=work,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
                try:
                    while process.poll() is None:
                        if time.monotonic()-started>cfg.timeout_sec:raise TimeoutError('IRIS_WALLCLOCK_TIMEOUT')
                        if cancel_event is not None and cancel_event.is_set():raise RuntimeError('IRIS_CANCELLED')
                        if time.monotonic()-last_disk_check>3:
                            size=sum(f.stat().st_size for f in work.rglob('*') if f.is_file() and not f.is_symlink())
                            if size>cfg.max_runtime_bytes:raise RuntimeError('IRIS_RUNTIME_DISK_LIMIT')
                            last_disk_check=time.monotonic()
                        try:
                            parent=psutil.Process(process.pid);rss=sum(p.memory_info().rss for p in [parent,*parent.children(recursive=True)] if p.is_running());peak_rss=max(peak_rss,rss)
                            if rss>cfg.max_rss_bytes:raise RuntimeError('IRIS_PROCESS_TREE_RSS_LIMIT')
                        except (psutil.NoSuchProcess,psutil.AccessDenied):pass
                        time.sleep(.2)
                except BaseException:_stop(process);raise
            receipts.append({'phase':label,'argv':argv,'exit_code':process.returncode,'duration_ms':round((time.monotonic()-t)*1000,3)})
            if process.returncode:raise RuntimeError('IRIS_'+label.upper()+'_PROCESS_FAILED:'+str(process.returncode))
        worker=json.loads(Path(request['result_file']).read_text());paths=[];reasons=list(worker['reason_codes'])
        database_id=database_receipt['database_id'] if database_receipt else digest({'identity':identity,'metadata':digest((database_path/'codeql-database.yml').read_bytes())})
        sarif_count=0
        for pipeline in worker['pipelines']:
            sarif=Path(pipeline['sarif'])
            if not sarif.exists():reasons.append('IRIS_QUERY_OUTPUT_MISSING');continue
            sarif_count+=1
            generated=Path(request['workspace'])/'output'
            query_hash=digest({str(f.relative_to(generated)):digest(f.read_bytes()) for f in generated.rglob('*') if f.suffix in ['.ql','.qll','.yml']})
            provenance={'iris_upstream_commit':head,'codeql_version':cli_version['version'],'codeql_database_id':database_id,
                'source_commit_or_archive_sha':source_identity,'query_id':pipeline['query_id'],'query_hash':query_hash,
                'model_identity':model_files,'duration_ms':pipeline['duration_ms'],'raw_artifact_reference':str(sarif),
                'raw_artifact_sha256':digest(sarif.read_bytes())}
            bound,rejected=bind_sarif(json.loads(sarif.read_text()),staged,manifest,pipeline['cwe_id'],provenance)
            api_csv=next((Path(request['workspace'])/'output').rglob('fetch_external_apis/results.csv'),None)
            if api_csv:attach_api_context(bound,api_csv,staged)
            if cfg.full_source_mode and pipeline.get('standard_proof_csv'):
                attach_standard_flow_context(bound,pipeline['standard_proof_csv'],staged,manifest)
            paths.extend(bound);reasons.extend(rejected)
        if not sarif_count:raise RuntimeError('UPSTREAM_CODEQL_TAINT_QUERY_NOT_EXECUTED')
        if any(p['analysis_status']!='COMPLETED' for p in worker['pipelines']):reasons.append('UPSTREAM_PIPELINE_INCOMPLETE')
        result={'engine_id':'IRIS_ORIGINAL_CODEQL','engine_mode':'IRIS_PARTIAL' if reasons else 'ORIGINAL_IRIS_CODEQL',
            'analysis_status':'IRIS_PARTIAL' if reasons else 'COMPLETED','verification_status':'SOURCE_BOUND_CODEQL_PATH' if paths else 'NO_PATH_FOUND_NOT_SAFE_PROOF',
            'paths':paths,'reason_codes':sorted(set(reasons)),'cache_hit':False,'iris_upstream_commit':head,'codeql_version':cli_version['version'],
            'codeql_database_id':database_id,'source_commit_or_archive_sha':source_identity,'cloud_calls_enabled':False,
            'actual_gpu_inference_calls':worker.get('actual_gpu_generation_batches',len(worker['model_calls'])),'model_telemetry':worker['model_telemetry'],'source_files':len(manifest),
            'cwe_scope':list(cwes),
            'source_coverage':'JAVA_ONLY_WITHOUT_BUILD_OR_RESOURCE_MODELS','duration_ms':round((time.monotonic()-started)*1000,3),
            'peak_process_tree_rss_bytes':peak_rss,'commands':receipts,'raw_artifact_reference':str(work)}
        if cfg.full_source_mode:
            result.update(database_receipt=database_receipt,mining_coverage=worker.get('mining_coverage',{}),
                stages=worker.get('stages',[]),input_tokens=worker.get('input_tokens'),generated_tokens=worker.get('generated_tokens'),
                optional_posthoc_status=worker.get('optional_posthoc_status'),semantic_dataflow_coverage='NOT_PROVEN',license_source_binding=license_binding,
                cwe_executions=worker['pipelines'],execution_origin='UPSTREAM_PROCESS_WITH_EXPLICIT_LAYER_CACHES',
                current_cwe_query_pipeline_invocations=len(worker['pipelines']),model_telemetry_from_cached_execution=False,
                commands_from_cached_execution=False)
        if reusable_execution(worker,reasons,cfg.full_source_mode):
            cache.parent.mkdir(parents=True,exist_ok=True);cache.write_text(json.dumps({'identity':identity,'result':result,'result_sha256':digest(result)},indent=2))
        (work/'adapter-result.json').write_text(json.dumps(result,indent=2));return result
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as error:
        result=failure(type(error).__name__+':'+str(error),'IRIS_FAILED');result['duration_ms']=round((time.monotonic()-started)*1000,3)
        if 'work' in locals():
            result['raw_artifact_reference']=str(work)
            calls=work/'upstream-execution/model-calls.jsonl'
            if calls.exists():result['actual_gpu_inference_calls']=len(calls.read_text().splitlines())
        return result
