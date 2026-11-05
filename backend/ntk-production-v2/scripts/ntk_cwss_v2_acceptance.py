"""Local CPU export/optional append for persisted scans; never calls Qwen.

Reads immutable source snapshots, invokes only NTK's existing bounded Javac
parser on temporary source data. No repository build, script or code execution.
"""
import argparse
import copy
import csv
import hashlib
import json
import re
import tempfile
from pathlib import Path
import ntk_cwss_auto_v2 as v
import ntk_cwss_workflow as w


def hydrate(snapshot):
    import ntk_alert_verification as av
    import time
    result=copy.deepcopy(snapshot);result['inference_version']=v.graph.VERSION
    result['java_ast']={}
    deadline=time.monotonic()+15
    for row in result.get('files',[]):
        if row['path'] not in result.get('finding_source_paths',{}).values():continue
        if len(result['java_ast'])>=64 or time.monotonic()>deadline:
            result['limitations'].append('CWSS_AST_BUDGET_EXCEEDED');break
        relative=Path(row['path'])
        if relative.is_absolute() or '..' in relative.parts or not str(relative).endswith('.java'):
            raise ValueError('Unsafe snapshot path')
        data=row['text'].encode()
        if len(data)>v.old.MAX_FILE or hashlib.sha256(data).hexdigest()!=row['sha256']:
            raise ValueError('Source snapshot checksum mismatch')
        # No source is written to the repository or any scan archive.
        ast=av.parse_java_source_with_javac_ast(row['text'],timeout_sec=5)
        if ast:
            ast=copy.deepcopy(ast);ast['file_path']=row['path']
            result['java_ast'][row['path']]={'sha256':row['sha256'],'ast':ast}
        else:result['limitations'].append('CWSS_AST_UNAVAILABLE:'+row['path'])
    return result


def export(storage,scan,context=None,append=False):
    if not re.fullmatch(r'SCAN-[A-Za-z0-9_-]{1,96}',scan):raise ValueError('Invalid scan ID')
    record=json.loads((Path(storage)/(scan+'.json')).read_text())
    findings=record['findings'];directory=Path(storage)/'cwss-assessments'
    import sqlite3
    def history(folder,fid):
        path=folder/'cwss-assessments.sqlite3'
        if not path.is_file():return []
        with sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True) as db:
            rows=db.execute('SELECT envelope,checksum FROM revisions WHERE scan=? AND finding=? ORDER BY revision',(scan,fid)).fetchall()
        result=[]
        for raw,checksum in rows:
            value=json.loads(raw)
            if w.digest(value)!=checksum:raise ValueError('Assessment checksum mismatch')
            result.append(value)
        return result
    store=w.AssessmentStore(directory) if append else None
    complete=w.AssessmentStore(directory/'complete') if append else None
    rows=[];hydrated={}
    provenance={r['finding_id']:r for r in (record.get('source_provenance_verification') or {}).get('per_finding_records',[])}
    for archived in findings:
        f=copy.deepcopy(archived)
        if f['finding_id'] in provenance:
            expected_record=provenance[f['finding_id']]
            if f.get('source_provenance_record') is not None and f['source_provenance_record']!=expected_record:
                raise ValueError('Archive/provenance conflict')
            f['source_provenance_record']=copy.deepcopy(expected_record)
        revisions=history(directory,f['finding_id'])+history(directory/'complete',f['finding_id'])
        matches=[r for r in revisions if r['profile'].get('automatic_evidence') and v.matches(f,r)]
        if not matches:raise ValueError('Matching immutable automatic snapshot unavailable: '+f['finding_id'])
        selected=matches[-1];prior=selected['finding_snapshot'];snapshot=selected['profile']['automatic_evidence']
        original=copy.deepcopy(f)
        old_fingerprint=snapshot['finding_evidence_hashes'].get(f['finding_id'])
        if old_fingerprint not in (w.evidence_hash(prior),w.evidence_hash(original)):
            raise ValueError('Stored snapshot fingerprint differs')
        key=w.digest(snapshot)
        if key not in hydrated:hydrated[key]=hydrate(snapshot)
        s=copy.deepcopy(hydrated[key])
        s['finding_evidence_hashes'][original['finding_id']]=w.evidence_hash(original)
        if context:s['declared_context_v2']=v.validate_context(context)
        outputs={mode:v.assess(original,scan,s,mode)[1] for mode in v.MODES}
        default=copy.deepcopy(s);default.pop('declared_context_v2',None)
        ordinary=v.assess(original,scan,default,v.completion.MODE)[1]
        before={r['profile']['mode']:r['assessment']['cwss_score'] for r in revisions}
        current=outputs[v.completion.MODE];g=current['normalized_evidence']
        rows.append({'finding_id':f['finding_id'],'cwe':f['cwe'],'triage':f.get('decision'),
            'iris_proof':g['iris_proof'],'normalized_sink':g['declaring_type']+'.'+g['identity'].get('method','') if g['resolved_method_identity'] else 'UNRESOLVED:'+str(g['observed_callsite'].get('method_name',g['observed_callsite'].get('class_type',''))) ,
            'preliminary':w.evaluate(original,scan)['cwss_score'],'before':before,
            'evidence':outputs[v.old.MODES[0]]['cwss_score'],'estimate':outputs[v.old.MODES[1]]['cwss_score'],
            'complete':ordinary['cwss_score'],'contextual':current['cwss_score'] if context else None,
            'counts':current['assessment_completeness'],'blocked_rules':g['blocked_rules'],'conflicts':g['conflicts'],
            'evidence_hash':g['evidence_hash'],'explanation':current['explanation'],'results':outputs})
        if append:
            store.publish_automatic(original,scan,s)
            complete.publish_complete(original,scan,s)
    return {'scan_id':scan,'row_count':len(rows),'actual_scan_data':True,'inference_version':v.VERSION,
            'archive_unchanged':True,'append_requested':append,'findings':rows}


def export_bundle(directory,context=None):
    """Read the exact six-file private diagnostic bundle; no database access."""
    p=Path(directory)
    for line in (p/'SHA256SUMS').read_text().splitlines():
        sha,name=line.split(maxsplit=1);relative=Path(name.lstrip('* '))
        if relative.is_absolute() or '..' in relative.parts:raise ValueError('Unsafe checksum path')
        if hashlib.sha256((p/relative).read_bytes()).hexdigest()!=sha:raise ValueError('DTO bundle checksum mismatch')
    raw=json.loads((p/'01_ARCHIVED_FINDINGS_25.json').read_text())
    indexed=json.loads((p/'02_INDEXED_FINDINGS_25.json').read_text())
    old_report=json.loads((p/'03_CWSS_AUTO_COMPLETE_25.json').read_text())
    before={r['finding_id']:r['cwss_score'] for r in old_report['findings']}
    snapshot=hydrate(json.loads((p/'04_CWSS_COLLECTION_SNAPSHOT.json').read_text()))
    if len(raw)!=len(indexed):raise ValueError('DTO counts differ')
    raw_by_id={r['finding_id']:r for r in raw}
    for f in indexed:
        original=raw_by_id[f['finding_id']]
        if snapshot['finding_evidence_hashes'].get(f['finding_id']) not in (w.evidence_hash(original),w.evidence_hash(f)):
            raise ValueError('DTO/source fingerprint mismatch')
        if not v.matches(f,{'finding_snapshot':original,'profile':{'automatic_evidence':snapshot}}):
            raise ValueError('Unproven index enrichment')
        snapshot['finding_evidence_hashes'][f['finding_id']]=w.evidence_hash(f)
    rows=[]
    for f in indexed:
        results={mode:v.assess(f,old_report['scan_id'],snapshot,mode)[1] for mode in v.MODES}
        high_snapshot=copy.deepcopy(snapshot)
        if context:high_snapshot['declared_context_v2']=v.validate_context(context)
        high=v.assess(f,old_report['scan_id'],high_snapshot,v.completion.MODE)[1] if context else None
        r=results[v.completion.MODE];g=r['normalized_evidence']
        rows.append({'finding_id':f['finding_id'],'cwe':f['cwe'],'triage':f['decision'],'iris_proof':g['iris_proof'],
            'normalized_sink':g['declaring_type']+'.'+g['identity'].get('method','') if g['resolved_method_identity'] else 'UNRESOLVED:'+str(g['observed_callsite'].get('method_name',g['observed_callsite'].get('class_type',''))) ,
            'preliminary':w.evaluate(f,old_report['scan_id'])['cwss_score'],'before':before[f['finding_id']],
            'evidence':results[v.old.MODES[0]]['cwss_score'],'estimate':results[v.old.MODES[1]]['cwss_score'],
            'complete':r['cwss_score'],'contextual':high['cwss_score'] if high else None,
            'counts':r['assessment_completeness'],'blocked_rules':g['blocked_rules'],'conflicts':g['conflicts'],
            'evidence_hash':g['evidence_hash'],'explanation':r['explanation'],'results':results})
    return {'scan_id':old_report['scan_id'],'row_count':len(rows),'actual_scan_data':True,
            'inference_version':v.VERSION,'archive_unchanged':True,'append_requested':False,'findings':rows}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--storage-dir',type=Path);p.add_argument('--scan-id')
    p.add_argument('--dto-dir',type=Path,help='Read-only supplied diagnostic bundle')
    p.add_argument('--context',type=Path);p.add_argument('--output',required=True,type=Path)
    p.add_argument('--append',action='store_true',help='Append immutable V2 revisions; archives unchanged')
    args=p.parse_args()
    ctx=json.loads(args.context.read_text()) if args.context else None
    if args.dto_dir:
        if args.append:p.error('--dto-dir is read-only')
        result=export_bundle(args.dto_dir,ctx)
    else:
        if not args.storage_dir or not args.scan_id:p.error('--storage-dir and --scan-id required without --dto-dir')
        result=export(args.storage_dir,args.scan_id,ctx,args.append)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n')
    with args.output.with_suffix('.csv').open('w',newline='') as fp:
        columns=['finding_id','cwe','triage','iris_proof','normalized_sink','preliminary','before','evidence','estimate','complete','contextual','counts','blocked_rules','conflicts','evidence_hash','explanation']
        writer=csv.DictWriter(fp,fieldnames=columns);writer.writeheader()
        for row in result['findings']:writer.writerow({k:json.dumps(row[k]) if isinstance(row[k],(dict,list)) else row[k] for k in columns})
    print('Exported',result['row_count'],'actual persisted findings; append=',args.append)


if __name__=='__main__':main()
