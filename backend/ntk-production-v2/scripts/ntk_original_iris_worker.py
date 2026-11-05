"""Local-only bridge to a verified, unmodified upstream IRIS v2 SAPipeline.

Upstream owns API discovery, model generation, CodeQL queries and path analysis.
NTK supplies isolated paths, pinned QL dependencies and a validated local model
protocol adapter. No benchmark labels or project-specific source/sink answers.
"""
import argparse
import csv
import functools
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time
import traceback


class ContractError(RuntimeError):
    pass


def codeql_launcher(real_cli,full_source_mode=False):
    launcher='#!'+sys.executable+'\nimport os,sys\na=sys.argv[1:]\n'
    if full_source_mode:launcher+='a=[x for x in a if x != "--rerun"]\n'
    launcher+="if a[:2] in [['query','run'],['database','analyze'],['database','create']]:\n"
    launcher+=" i=a.index('--') if '--' in a else len(a)\n a[i:i]=[v for v in ['--threads=1','--ram=2048'] if not any(x==v.split('=')[0] or x.startswith(v.split('=')[0]+'=') for x in a[:i])]\n"
    return launcher+'os.execv('+repr(real_cli)+',['+repr(real_cli)+']+a)\n'


def mining_frontier_order(identity):
    """Spend bounded mining on framework boundaries before general utilities.

    This changes scheduling only: every API remains an input candidate and
    only a validated local model response can assign its taint role. It never
    inspects a repository name, case ID, CVE, expected label or CWSS score.
    """
    package,clazz,method,signature=identity
    if package.startswith(('javax.servlet','jakarta.servlet')):priority=0
    elif package in ['java.io','java.nio.file','java.net','java.sql']:priority=1
    elif package=='java.lang' and clazz in ['Runtime','ProcessBuilder','System']:priority=2
    else:priority=3
    return (priority,package,clazz,method,signature)


def main(request_file):
    request=json.loads(Path(request_file).read_text())
    workspace=Path(request['workspace']).resolve();workspace.mkdir(parents=True,exist_ok=True)
    upstream=Path(request['upstream_dir']).resolve()
    commit=subprocess.run(['git','-C',str(upstream),'rev-parse','HEAD'],capture_output=True,text=True,check=True).stdout.strip()
    if commit!=request['upstream_commit']:raise ValueError('IRIS_UPSTREAM_COMMIT_MISMATCH')
    dirty=subprocess.run(['git','-C',str(upstream),'status','--porcelain','--untracked-files=no'],capture_output=True,text=True,check=True).stdout
    if dirty:raise ValueError('IRIS_UPSTREAM_TRACKED_SOURCE_MODIFIED')
    os.environ.update(HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1',HF_HUB_DISABLE_TELEMETRY='1',
        TOKENIZERS_PARALLELISM='false',OMP_NUM_THREADS='2',MKL_NUM_THREADS='2')
    for key in list(os.environ):
        if key.endswith('_API_KEY') or key in ['OPENAI_BASE_URL','ANTHROPIC_AUTH_TOKEN']:os.environ.pop(key,None)
    # The Java-only staging directory contains no Maven/Gradle descriptors,
    # executable scripts, XML or properties. Resource extraction is explicitly
    # excluded; the existing CodeQL bundle's XML discovery is not modified.
    os.environ.update(LGTM_INDEX_XML_MODE='none',LGTM_INDEX_PROPERTIES_FILES='false')
    for key,value in request.get('model_environment',{}).items():
        if key in ['NTK_BASE_MODEL_PATH','NTK_BEST_ADAPTER_PATH','NTK_INFERENCE_DEVICE','JAVA_HOME','NTK_JAVAC_BIN']:os.environ[key]=str(value)
    os.environ['PATH']=request['java_home']+'/bin:/usr/bin:/bin'
    import requests
    def no_network(*args,**kwargs):raise RuntimeError('EXTERNAL_HTTP_DISABLED_IN_IRIS_WORKER')
    requests.sessions.Session.request=no_network
    original_connect=socket.socket.connect
    def local_connect(sock,address):
        if sock.family in [socket.AF_INET,socket.AF_INET6]:raise RuntimeError('PYTHON_NETWORK_DISABLED_IN_LOCAL_IRIS')
        return original_connect(sock,address)
    socket.socket.connect=local_connect
    sys.path[:0]=[str(upstream),str(upstream/'src')]
    import src.config as config
    project='ntk__source_'+request['source_hash'][:16]
    sources=workspace/'sources';sources.mkdir(exist_ok=True)
    if not (sources/project).exists():(sources/project).symlink_to(request['source_root'],target_is_directory=True)
    databases=workspace/'databases';databases.mkdir(exist_ok=True)
    if not (databases/project).exists():(databases/project).symlink_to(request['database'],target_is_directory=True)
    packages=workspace/'packages';packages.mkdir(exist_ok=True)
    (packages/(project+'.txt')).write_text('\n'.join(request['packages'])+'\n')
    metadata=workspace/'empty-evaluation-metadata.csv'
    metadata.write_text('project_slug,file,class,method,name\n')
    wrapper=workspace/'codeql-tools';wrapper.mkdir(exist_ok=True);(wrapper/'qlpacks').mkdir(exist_ok=True)
    real_cli=request['codeql_bin']
    launcher=codeql_launcher(real_cli,request.get('full_source_mode',False))
    (wrapper/'codeql').write_text(launcher);(wrapper/'codeql').chmod(0o755)
    config.CODEQL_DIR=str(wrapper);config.CODEQL_DB_PATH=str(databases)
    config.PROJECT_SOURCE_CODE_DIR=str(sources);config.PACKAGE_MODULES_PATH=str(packages)
    config.OUTPUT_DIR=str(workspace/'output');config.ALL_METHOD_INFO_DIR=str(metadata)
    config.CVES_MAPPED_W_COMMITS_DIR=str(workspace/'unused-cve-metadata.csv')
    config.CODEQL_QUERY_VERSION='1.11.4'
    iris=importlib.import_module('src.iris');iris.IRIS_ROOT_DIR=str(workspace)
    import ntk_web_backend_service as service
    import ntk_iris_shared as shared
    from ntk_local_gpu_lock import gpu_inference_lock
    cfg=service.NtkWebBackendConfig(device='cuda',max_new_tokens=160,llm_inference_timeout_sec=30)
    stages=[];model_calls=[];blocked=[];pipeline_results=[]
    def record_call(value):
        model_calls.append(value)
        with (workspace/'model-calls.jsonl').open('a') as handle:handle.write(json.dumps(value)+'\n')
    mining=None
    if request.get('full_source_mode'):
        from ntk_iris_full_mining import MiningSession
        mining=MiningSession(request,cfg,record_call)
    class LocalModel:
        cwe=0
        api_rows={}
        function_rows={}
        def raw(self,prompt):
            import torch
            if len(model_calls)>=request.get('max_model_calls',64):raise ContractError('LOCAL_MODEL_CALL_BUDGET_EXCEEDED')
            torch.set_num_threads(2)
            with gpu_inference_lock():
                tokenizer,model,device=service._get_or_load_model_bundle(cfg)
                enc=tokenizer(tokenizer.apply_chat_template(prompt,tokenize=False,add_generation_prompt=True),return_tensors='pt').to(device)
                if enc['input_ids'].shape[1]>2048:raise ContractError('LOCAL_CONTEXT_BUDGET_EXCEEDED')
                with torch.inference_mode():
                    generated=model.generate(**enc,max_new_tokens=256,do_sample=False,pad_token_id=tokenizer.eos_token_id)
                assert str(enc['input_ids'].device)==str(generated.device)=='cuda:0'
                raw=tokenizer.decode(generated[0][enc['input_ids'].shape[1]:],skip_special_tokens=True).strip()
            record_call({'task':'UPSTREAM_CONTEXTUAL_CONTRACT','raw_output':raw,'input_device':str(enc['input_ids'].device),'output_device':str(generated.device)})
            return raw
        def one(self,prompt):
            system=prompt[0]['content'];user=prompt[1]['content']
            if '"tainted_input"' in system:
                if len(model_calls)>=request.get('max_model_calls',64):
                    blocked.append('LOCAL_MODEL_CALL_BUDGET_EXCEEDED')
                    return '[]' # Zero validated specs, with explicit PARTIAL coverage.
                raw=self.raw(prompt)
                try:
                    result=json.loads(raw)
                    if not isinstance(result,list):raise ValueError('Expected function-source list')
                    for entry in result:
                        if not isinstance(entry,dict) or not isinstance(entry.get('tainted_input'),list):raise ValueError('Function-source schema')
                        identity=tuple(entry.get(k) for k in ['package','class','method','signature'])
                        if identity not in self.function_rows:raise ValueError('Unknown function identity')
                        signature=entry['signature']
                        if ','.join([entry['package'],entry['class'],signature])+',' not in user:raise ValueError('Function absent from this prompt')
                        params={name for _,name in shared.extract_formal_params_from_signature(signature) if name}
                        if any(not isinstance(v,str) or v not in params for v in entry['tainted_input']):raise ValueError('Unbound function parameter')
                    return json.dumps(result)
                except (ValueError,TypeError):
                    blocked.append('FUNC_PARAM_MODEL_CONTRACT_REJECTED')
                    return '[]' # Projection of zero validated specs; stage is PARTIAL, never a safe verdict.
            if '"is_vulnerable"' in system:
                raw=self.raw(prompt)
                try:
                    result=json.loads(raw)
                    if not isinstance(result,dict) or not isinstance(result.get('explanation'),str):raise ValueError('Posthoc explanation schema')
                    if any(type(result.get(k)) is not bool for k in ['is_vulnerable','source_is_false_positive','sink_is_false_positive']):raise ValueError('Posthoc boolean schema')
                    return raw
                except (ValueError,TypeError):
                    blocked.append('POSTHOC_MODEL_CONTRACT_REJECTED');raise ContractError('Posthoc output rejected; preserve unfiltered paths')
            if 'Package,Class,Method,Signature' not in user:raise ContractError('Unknown upstream model task')
            specs=[]
            for line in user.rsplit('Package,Class,Method,Signature',1)[1].splitlines():
                if not line.strip():continue
                # IRIS's prompt table is not quoted CSV. Generic constructors
                # contain commas, so bind to the real CodeQL CSV row rather
                # than splitting the prompt into a different API identity.
                ident=self.api_rows.get(line)
                if ident is None:raise ContractError('Unbound API mining input')
                ident=dict(ident)
                if '<' in ident['method'] and ident['method'].split('<',1)[0]==ident['class'].split('<',1)[0]:
                    ident['method']=ident['method'].split('<',1)[0]
                if len(model_calls)>=request.get('max_model_calls',64):
                    blocked.append('LOCAL_MODEL_CALL_BUDGET_EXCEEDED')
                    continue # No fabricated spec; run real query with explicitly partial mining.
                raw,latency=service.run_llm_inference_for_identities([(self.cwe,ident)],config=cfg)[0]
                pred=shared.parse_and_validate_callee_json(raw,expected_identity=ident,cwe=self.cwe)
                telemetry=service._LAST_INFERENCE_TELEMETRY
                record_call({'task':'API_ROLE_CANONICAL_IRIS_2MSG_PROMPT_V1','cwe':self.cwe,'identity':ident,'raw_output':raw,
                    'strict_valid':pred.strict_valid,'reason':pred.abstain_reason,'duration_ms':latency,
                    'input_device':telemetry.get('input_tensor_device'),'output_device':telemetry.get('output_tensor_device')})
                if not pred.strict_valid:blocked.append('API_ROLE_MODEL_CONTRACT_REJECTED');continue
                data=json.loads(raw)
                if data.get('type') not in ['source','sink','taint-propagator']:continue
                # Upstream QLL generation expects CodeQL's pN parameter names.
                args=[]
                for arg in data.get('sink_args',[]):
                    if arg=='this':args.append(arg)
                    elif re.fullmatch(r'(?:p|arg)?[0-9]+',str(arg)):args.append('p'+re.search(r'[0-9]+',str(arg))[0])
                    else:args.append(arg)
                declared=set(re.findall(r'\b(p[0-9]+)\b',ident['signature']))
                if data.get('type')=='sink' and (not args or any(arg!='this' and arg not in declared for arg in args)):
                    blocked.append('SINK_SLOT_NOT_BOUND_TO_CODEQL_SIGNATURE');continue
                data['sink_args']=args;specs.append(data)
            return json.dumps(specs)
        def predict(self,prompts,batch_size=0,**kwargs):
            if mining is not None and batch_size and prompts:
                system=prompts[0][0]['content']
                if '"tainted_input"' in system:return mining.parameters(prompts,self.function_rows,self.cwe)
                if '"is_vulnerable"' not in system:return mining.api(prompts,self.cwe,self.api_rows)
            return [self.one(p) for p in prompts] if batch_size else self.one(prompts)
    model=LocalModel();iris.LLM.get_llm=staticmethod(lambda **kwargs:model)
    for cwe in request['cwes']:
        model.cwe=int(cwe);query='cwe-'+str(cwe).zfill(3)+'wLLM';started=time.monotonic()
        try:
            pipeline=iris.SAPipeline(project,query,run_id='fresh',llm='ntk-local-eo06',label_api_batch_size=1,
                label_func_param_batch_size=1,num_threads=1,use_exhaustive_qll=True,skip_evaluation=True,
                skip_posthoc_filter=request.get('skip_posthoc',False),overwrite=False)
            pack=Path(pipeline.custom_codeql_root)
            (pack/'qlpack.yml').write_text('name: iris\nversion: 1.0.0\ndependencies:\n  codeql/java-all: 9.1.2\n  codeql/java-queries: 1.11.4\n')
            pipeline.fetch_project_description_from_readme=lambda:''
            native_filter=pipeline.filter_to_query_apis_with_cache
            pipeline.filter_to_query_apis_with_cache=lambda candidates,_native=native_filter: sorted(_native(candidates),key=mining_frontier_order)
            for name in ['collect_invoked_external_apis','collect_internal_function_parameters','query_gpt_for_api_src_tp_sink_batched',
                         'query_gpt_for_func_param_src','build_project_specific_query','find_vulnerability','post_process_cwe_query_result',
                         'query_gpt_for_posthoc_filtering','evaluate_result']:
                original=getattr(pipeline,name)
                def timed(*args,_fn=original,_name=name,**kwargs):
                    t=time.monotonic();status='COMPLETED'
                    try:
                        if _name=='query_gpt_for_api_src_tp_sink_batched':
                            with open(pipeline.candidate_apis_csv_path) as handle:
                                rows=list(csv.DictReader(handle))
                            model.api_rows={','.join(row[k] for k in ['package','clazz','func','full_signature']):
                                dict(zip(['package','class','method','signature'],[row[k] for k in ['package','clazz','func','full_signature']])) for row in rows}
                            if mining is not None:mining.prepare(pipeline,cwe,rows)
                        if _name=='query_gpt_for_func_param_src':
                            with open(pipeline.source_func_param_candidates_path) as handle:
                                model.function_rows={tuple(row[k] for k in ['package','clazz','func','full_signature']):row for row in csv.DictReader(handle)}
                        value=_fn(*args,**kwargs)
                        if mining is not None and _name=='build_project_specific_query':
                            from ntk_iris_codegen_extension import extend_generated_pack
                            pipeline.ntk_standard_proof_query=extend_generated_pack(pipeline,int(cwe),upstream)
                        if mining is not None and _name=='find_vulnerability' and Path(pipeline.query_output_result_sarif_path).exists():
                            proof=pipeline.ntk_standard_proof_query;out=proof.with_suffix('.bqrs')
                            subprocess.run([str(wrapper/'codeql'),'query','run',str(proof),'--database='+request['database'],
                                '--output='+str(out)],check=True)
                            subprocess.run([real_cli,'bqrs','decode',str(out),'--format=csv','--output='+str(proof.with_suffix('.csv'))],check=True)
                        return value
                    except BaseException:
                        status='FAILED';raise
                    finally:stages.append({'cwe':cwe,'stage':_name,'state':status,'duration_ms':round((time.monotonic()-t)*1000,3)})
                setattr(pipeline,name,timed)
            pipeline.run()
            state='COMPLETED'
        except BaseException as error:
            state='PARTIAL';blocked.append(type(error).__name__+':'+str(error));traceback.print_exc()
        sarif=Path(getattr(locals().get('pipeline'),'query_output_result_sarif_path',workspace/'missing'))
        pipeline_results.append({'cwe_id':cwe,'query_id':query,'analysis_status':state if sarif.is_file() else 'FAILED',
            'sarif':str(sarif),'duration_ms':round((time.monotonic()-started)*1000,3)})
        proof=getattr(locals().get('pipeline'),'ntk_standard_proof_query',None)
        if proof and proof.with_suffix('.csv').is_file():pipeline_results[-1]['standard_proof_csv']=str(proof.with_suffix('.csv'))
    if mining is not None:blocked.extend(mining.issues)
    telemetry={**service._LAST_INFERENCE_TELEMETRY,**service.get_model_runtime_telemetry(cfg)}
    result={'engine_id':'IRIS_ORIGINAL_CODEQL','iris_upstream_commit':commit,'pipelines':pipeline_results,
        'stages':stages,'model_calls':model_calls,'model_telemetry':telemetry,'reason_codes':sorted(set(blocked)),
        'cloud_calls_enabled':False,'upstream_source_modified':False,'evaluation_labels_used':False,
        'compatibility_extensions':['isolated_paths','pinned_existing_ql_packs','canonical_api_role_protocol','strict_contextual_validation','bounded_framework_frontier_scheduling'],
        'analysis_status':'IRIS_PARTIAL' if blocked or any(p['analysis_status']!='COMPLETED' for p in pipeline_results) else 'COMPLETED',
        'worker_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    if mining is not None:
        result.update(actual_gpu_generation_batches=mining.batches,mining_coverage=mining.stats,
            input_tokens=mining.total_input_tokens,generated_tokens=mining.total_output_tokens,
            library_models_hash=mining.models.hash,optional_posthoc_status='DISABLED_UNVALIDATED_TASK' if request.get('skip_posthoc') else 'ATTEMPTED')
    Path(request['result_file']).write_text(json.dumps(result,indent=2)+'\n')


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('request_file');args=parser.parse_args();main(args.request_file)
