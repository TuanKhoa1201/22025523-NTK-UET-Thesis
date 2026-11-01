"""Sequential real-API acceptance. Private/source artifacts stay under ignored work/."""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import zipfile

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'work/e2e-multiproject-acceptance'
BASE=os.environ.get('NTK_E2E_API','http://127.0.0.1:8766')

def save(name,data):
    p=OUT/name;p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(json.dumps(data,indent=2,ensure_ascii=True)+'\n')

def api(path, body=None, raw=None, headers=None):
    payload=json.dumps(body).encode() if body is not None else raw
    req=Request(BASE+path,data=payload,headers=headers or ({'Content-Type':'application/json'} if body is not None else {}))
    try:
        with urlopen(req,timeout=180) as response: data=response.read();status=response.status
    except HTTPError as error:status=error.code;data=error.read()
    try:return status,json.loads(data)
    except ValueError:return status,data.decode(errors='replace')

def zip_bytes(files):
    result=io.BytesIO()
    with zipfile.ZipFile(result,'w',zipfile.ZIP_DEFLATED) as z:
        for name,data in sorted(files.items()):z.writestr(name,data)
    return result.getvalue()

def run_job(label, body=None, raw=None, headers=None, resume=False):
    previous=OUT/f'responses/{label}-submitted.json'
    if resume and previous.exists():
        saved=json.loads(previous.read_text());status,submitted=saved['http'],saved['body']
    else:
        status,submitted=api('/api/scan-jobs',body,raw,headers)
        save(f'responses/{label}-submitted.json',{'http':status,'body':submitted})
    if status not in (200,202):return {'label':label,'http':status,'state':'REJECTED','error':submitted}
    job_id=submitted['job_id'];deadline=time.monotonic()+600;last=0
    while time.monotonic()<deadline:
        status,job=api('/api/scan-jobs/'+job_id)
        if status!=200:raise RuntimeError((label,status,job))
        if job.get('state') in ('COMPLETED','FAILED'):break
        if time.monotonic()-last>20:print('RUNNING',label,'stage',job.get('active_stage'),flush=True);last=time.monotonic()
        time.sleep(.5)
    else:raise TimeoutError(label+' job did not finish; no new GPU scan will be submitted')
    save(f'responses/{label}-job.json',job)
    result={'label':label,'http':status,'state':job['state'],'scan_id':job['scan_id'],'job_id':job_id,
            'error_code':job.get('error_code'),'error_message':job.get('error_message'),'stages':job.get('stages')}
    if result['state']=='COMPLETED':
        sid=job['scan_id']
        for key,suffix in [('full','?full=true'),('summary','/summary'),('trace','/pipeline-trace'),
                           ('ranking','/cwss/v1/ranking?mode=CWSS_AUTO_COMPLETE&page_size=200'),
                           ('scenario','/cwss/v2/scenario?page_size=100'),('report','/report?format=json')]:
            code,data=api('/api/scans/'+sid+suffix);save(f'responses/{label}-{key}.json',{'http':code,'body':data})
            if code!=200:raise AssertionError((label,key,code,data))
            result[key]=data
        record=result['full'];findings=record.get('findings',[])
        assert record['actual_gpu_inference_calls']==0 if not findings else True
        assert len(result['ranking']['findings'])==len(findings)
        for assessment in result['ranking']['findings']:
            assert len(assessment['metric_assessments'])==16
            assert assessment['factor_codes']['FC']!='T'
        assert len(result['trace']['stages'])==10
    print('FINISHED',label,result['state'],result.get('error_code'),flush=True)
    return result

def projects():
    sources=json.loads((OUT/'sources.json').read_text());results=[]
    for source in sources:
        label=source['project'];folder=Path(source['path']);files={f['path']:(folder/f['path']).read_bytes() for f in source['files']}
        own=(folder/'.git').exists();source['source_kind']='GIT_SOURCE_TREE' if own else 'LOCAL_RESEARCH_FIXTURE'
        if own:
            tree=subprocess.run(['git','-C',str(folder),'ls-tree','-r','HEAD','-z'],capture_output=True,check=True).stdout
            ids={entry.split(b'\t',1)[1].decode():entry.split(b'\t',1)[0].split()[-1].decode() for entry in tree.split(b'\0') if entry}
            source['java_bytes_match_commit']=all(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==ids.get(name) for name,data in files.items())
        else:source['java_bytes_match_commit']=None
        archive=OUT/'archives'/(label+'.zip');archive.parent.mkdir(exist_ok=True)
        if archive.exists():
            data=archive.read_bytes()
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                assert set(z.namelist())==set(files) and all(z.read(n)==v for n,v in files.items())
        else:
            data=zip_bytes(files);archive.write_bytes(data)
        source['archive_sha256']=hashlib.sha256(data).hexdigest()
        configuration={'max_files_limit':200,'scan_scope_policy':'BOUNDED_PARTIAL_SCAN'}
        if source['java_count']>300:
            if 'owasp_benchmark' in label:
                selected=sorted(n for n in files if '/testcode/BenchmarkTest' in n)[:16]
            else:
                preferred=sorted(n for n in files if '/main/' in n and any(s in n.lower() for s in ['sqlinjection','pathtraversal','xss']))
                selected=preferred[:16] or sorted(n for n in files if '/main/' in n)[:16]
            configuration.update(file_allowlist=selected,max_files_limit=16)
        source['selection']=configuration
        body={'zip_base64':base64.b64encode(data).decode(),'archive_filename':archive.name,'force_new_job':True,**configuration}
        tag=os.environ.get('NTK_E2E_RUN_TAG','')
        result=run_job(label+tag,body,resume=True)
        result['source']=source;results.append(result);save('projects-results.json',results);save('source-manifest.json',sources)
    return results

def inputs():
    fixture=OUT/'input-fixtures';fixture.mkdir(exist_ok=True)
    plain='class Plain { String value(){return "ordinary";} }'
    cases={
      'python-only':{'main.py':'print("not executed")'},'javascript-only':{'app.js':'console.log(1)'},
      'typescript-only':{'app.ts':'const value:number=1'},'cpp-only':{'main.cpp':'int main() {return 0;}'},
      'go-only':{'main.go':'package main\nfunc main() {}'},'readme-only':{'README.md':'no Java'},'empty':{},
      'mixed':{'Plain.java':plain,'main.py':'raise Exception("never executed")','app.js':'throw Error("never executed")'},
      'nested-java':{'nested/src/Plain.java':plain},'zero-java':{'Plain.java':plain},
      'fake-java':{'Fake.java':'print("not Java")'},'syntax-error':{'Broken.java':'class Broken { void run( { }'},
      'traversal':{'../Escape.java':plain},'bytecode':{'Evil.class':'not bytecode','Plain.java':plain},
    }
    tests=[]
    for name,files in cases.items():
        data=zip_bytes(files);(fixture/(name+'.zip')).write_bytes(data)
        result=run_job('input-'+name,raw=data,headers={'Content-Type':'application/zip','X-Archive-Filename':name+'.zip'})
        expected='COMPLETED' if name in ['mixed','nested-java','zero-java'] else 'FAILED'
        result['expected']=expected;result['pass']=result['state']==expected
        if result['state']=='COMPLETED':
            result['pass'] &= not result['full']['findings'] and result['full']['actual_gpu_inference_calls']==0
            result['pass'] &= result['trace']['stages'][5]['state']=='SKIPPED' and not result['scenario']['assessments']
        tests.append(result);save('input-results.json',tests)
    for name,data in [('corrupt',b'PK\x03\x04bad'),('renamed-zip',b'not ZIP bytes')]:
        (fixture/(name+'.zip')).write_bytes(data)
        result=run_job('input-'+name,raw=data,headers={'Content-Type':'application/zip'})
        result['expected']='REJECTED_OR_FAILED';result['pass']=result['state'] in ['FAILED','REJECTED'];tests.append(result)
    # A real parser/scanner and model handle safe and unknown candidates.
    for name,fixture_name in [('verified-safe','ConstantServlet.java'),('prepared-safe','ParameterizedServlet.java'),
                              ('path-safe','GuardedPathServlet.java'),('encoded-safe','EncodedServlet.java'),('unknown','UnknownServlet.java')]:
        source=(ROOT/'backend/ntk-production-v2/tests/fixtures/cwss_v2'/fixture_name).read_bytes();data=zip_bytes({fixture_name:source});(fixture/(name+'.zip')).write_bytes(data)
        result=run_job('input-'+name,raw=data,headers={'Content-Type':'application/zip','X-Archive-Filename':name+'.zip'})
        result['expected']='COMPLETED';result['pass']=result['state']=='COMPLETED';tests.append(result);save('input-results.json',tests)
    save('input-results.json',tests)
    return tests

def git_inputs():
    tests=[]
    cases=[
      ('python',{'repo_url':'https://github.com/pypa/sampleproject'},'FAILED'),
      ('javascript',{'repo_url':'https://github.com/jonschlinkert/is-number'},'FAILED'),
      ('c',{'repo_url':'https://github.com/jserv/mini-arm-os'},'FAILED'),
      ('go',{'repo_url':'https://github.com/golang/example'},'FAILED'),
      ('readme',{'repo_url':'https://github.com/octocat/Hello-World'},'FAILED'),
      ('mixed',{'repo_url':'https://github.com/TuanKhoa1201/22025523-NTK-UET-Thesis','max_files_limit':2,'scan_scope_policy':'BOUNDED_PARTIAL_SCAN'},'COMPLETED'),
      ('invalid-url',{'repo_url':'https://example.com/not-github'},'REJECTED'),
      ('nonexistent',{'repo_url':'https://github.com/ntk-nonexistent-test-20261102/no-such-repo-1201'},'FAILED'),
      ('invalid-branch',{'repo_url':'https://github.com/pypa/sampleproject','branch':'ntk-no-such-branch-20261102'},'FAILED'),
      ('invalid-commit',{'repo_url':'https://github.com/pypa/sampleproject','commit_sha':'0000000000000000000000000000000000000000'},'FAILED'),
      ('no-java-subpath',{'repo_url':'https://github.com/TuanKhoa1201/22025523-NTK-UET-Thesis','target_subpath':'docs'},'FAILED'),
    ]
    for name,body,expected in cases:
        result=run_job('git-input-'+name,{'force_new_job':True,**body});result.update(expected=expected,pass_=result['state']==expected,request=body)
        tests.append(result);save('git-input-results.json',tests)
    return tests

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('phase',choices=['projects','inputs','git-inputs']);args=parser.parse_args()
    {'projects':projects,'inputs':inputs,'git-inputs':git_inputs}[args.phase]()
