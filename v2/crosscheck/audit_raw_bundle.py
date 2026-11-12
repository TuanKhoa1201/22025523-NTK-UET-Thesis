"""Read-only independent bundle audit. No scanner, model, scorer or server-auditor imports.

Exit contract is recompute.EXIT_CODES: 0 PASS, 2 FAIL, 3 INCOMPLETE.
Detailed output is private and must be outside the transferred bundle/repository.
"""
import argparse
import copy
from collections import Counter
from contextlib import closing
import csv
from decimal import Decimal, InvalidOperation
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from urllib.parse import unquote

import recompute as core

SCAN_DIRS = {'development': ('stage1_dev_set_16_scan', 'dev_set_16'),
             'heldout': ('stage1_heldout_set_40_scan', 'heldout_set_40'),
             'manual': ('stage5_real_projects_scan', 'real_projects')}
RUNS = {
    'stage2_dev16_baseline_v1_0': ('development', 'C'),
    'stage3_dev16_armB_heuristic': ('development', 'B'),
    'stage3_dev16_armC_evidence_llm': ('development', 'C'),
    'stage3_dev16_armC_v2_1_evidence_llm': ('development', 'C'),
    'stage3_dev16_armD_llm_ablation': ('development', 'D'),
    'stage4_heldout40_armB_heuristic': ('heldout', 'B'),
    'stage4_heldout40_armC_evidence_llm': ('heldout', 'C'),
    'stage4_heldout40_armD_llm_ablation': ('heldout', 'D'),
    'stage5_real_projects_armB_heuristic': ('manual', 'B'),
    'stage5_real_projects_armC_evidence_llm': ('manual', 'C')}


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)


def digest_json(value):
    return core.sha(canonical(value).encode('utf-8'))


def read_json(path):
    return core.strict(Path(path).read_bytes())


def read_jsonl(path):
    return [core.strict(line) for line in Path(path).read_text(encoding='utf-8').splitlines() if line.strip()]


def normalized(path):
    return re.sub('/+', '/', str(path).replace('\\', '/'))


def source_path(raw_path, manifest):
    """Only normalize separators or strip the exact captured source-root prefix."""
    path = normalized(raw_path)
    prefix = normalized(manifest['source_root']).rstrip('/') + '/'
    if path.startswith(prefix):
        path = path[len(prefix):]
    if path.startswith('/') or re.match(r'^[A-Za-z]:', path) or '..' in path.split('/'):
        raise ValueError('unmapped or escaping source path: ' + path)
    if path not in {normalized(p) for p in manifest['sources_before']}:
        raise ValueError('source path not captured by manifest: ' + path)
    return path


class Audit(core.Audit):
    def __init__(self):
        super().__init__()
        self.section = 'input'
        self.register = []
        self.section_counts = Counter()

    def compare(self, aid, field, expected, actual, source):
        self.section_counts[self.section] += 1
        old = len(self.differences)
        super().compare(aid, field, expected, actual, source)
        if len(self.differences) != old:
            self.register.append(dict(self.differences[-1], criterion=self.section, status='FAIL',
                                      impact='Cần đối chiếu; có thể ảnh hưởng tính toàn vẹn hoặc kết luận',
                                      reproduce='Run audit_raw_bundle.py with the same inputs; field=' + field))

    def incomplete(self, message, source=None, field='missing_evidence'):
        super().incomplete(self.section + ': ' + message)
        self.register.append({'criterion': self.section, 'status': 'INCOMPLETE', 'alert_id': '*',
                              'field': field, 'expected': 'verifiable historical input', 'actual': message,
                              'source_file': str(source) if source else '',
                              'source_sha256': core.sha(Path(source).read_bytes()) if source and Path(source).is_file() else None,
                              'impact': 'Chưa đủ căn cứ nghiệm thu tiêu chí này',
                              'reproduce': 'Provide the named historical input; do not reconstruct a past run'})

    def statuses(self):
        out = {name: 'PASS' for name in self.section_counts}
        for row in self.register:
            name = row['criterion']
            if row['status'] == 'FAIL' or out.get(name) != 'FAIL':
                out[name] = row['status']
        return out


def inventory(root):
    return {p.relative_to(root).as_posix(): core.sha(p.read_bytes())
            for p in sorted(root.rglob('*')) if p.is_file()}


def verify_transfer(package, archive_sha, audit):
    audit.section = 'transfer_integrity'
    extracted = package / 'extracted'
    before = inventory(extracted)
    manifest = package / 'files.sha256.csv'
    with manifest.open(encoding='utf-8-sig', newline='') as stream:
        entries = list(csv.DictReader(stream))
    indexed = audit.index(entries, manifest, 'RelativePath')
    audit.compare('*', 'transfer.path_set', sorted(indexed), sorted(before), manifest)
    for rel, entry in indexed.items():
        try:
            path = core.safe_file(extracted, rel)
        except FileNotFoundError:
            audit.incomplete('Transferred file missing: ' + rel, manifest)
            continue
        audit.compare(rel, 'transfer.sha256', entry['SHA256'].lower(), core.sha(path.read_bytes()), path)
        audit.compare(rel, 'transfer.bytes', int(entry['Bytes']), path.stat().st_size, path)
    archive = package / 'NTK-G0-raw-evidence.tar.gz'
    actual_archive = core.sha(archive.read_bytes())
    if archive_sha:
        audit.compare('*', 'archive.sha256', archive_sha.lower(), actual_archive, archive)
    else:
        audit.incomplete('Externally provided archive SHA absent', archive)
    return before, {'files': len(before), 'manifest_entries': len(entries), 'archive_sha256': actual_archive,
                    'transfer_manifest_sha256': core.sha(manifest.read_bytes())}


def point(loc):
    return (loc['line'], loc['col'])


def finding_key(finding, manifest):
    return (finding['check_id'], source_path(finding['path'], manifest),
            *point(finding['start']), *point(finding['end']))


def trace_locations(node):
    """Walk actual CliLoc/CliCall locations without inventing edges or endpoints."""
    if isinstance(node, list):
        if len(node) == 2 and isinstance(node[0], dict) and {'path', 'start', 'end'} <= node[0].keys() and isinstance(node[1], str):
            yield node[0], node[1]
        else:
            for item in node:
                yield from trace_locations(item)
    elif isinstance(node, dict):
        if isinstance(node.get('location'), dict) and {'path', 'start', 'end'} <= node['location'].keys():
            yield node['location'], node.get('content')
        else:
            for item in node.values():
                yield from trace_locations(item)


def check_location(loc, text, root, manifest, audit, aid):
    path = core.safe_file(root, source_path(loc['path'], manifest))
    data = path.read_bytes(); lines = data.splitlines(keepends=True)
    offsets = []
    for edge in ('start', 'end'):
        pos = loc[edge]; line, col = point(pos)
        valid = type(line) is int and type(col) is int and 1 <= line <= len(lines) and 1 <= col <= len(lines[line-1].rstrip(b'\r\n')) + 1
        audit.compare(aid, 'location.' + edge + '.range', True, valid, path)
        if not valid:
            return
        offset = sum(map(len, lines[:line-1])) + col - 1
        if 'offset' in pos:
            audit.compare(aid, 'location.' + edge + '.offset', offset, pos['offset'], path)
        offsets.append(offset)
    audit.compare(aid, 'location.ordered', True, offsets[0] <= offsets[1], path)
    if text is not None:
        actual = data[offsets[0]:offsets[1]].decode('utf-8').replace('\r\n', '\n')
        audit.compare(aid, 'location.content_sha256', core.sha(text.encode()), core.sha(actual.encode()), path)


def inspect_scan(evidence, group, audit):
    audit.section = 'scan_' + group
    scan_dir, source_dir = SCAN_DIRS[group]
    folder = evidence / 'runs' / scan_dir; root = evidence / 'sources' / source_dir
    path = folder / 'opengrep.json'; raw = path.read_bytes(); doc = core.strict(raw)
    manifest = core.check_manifest(folder/'scan-manifest.json', raw, root, audit)
    rule_ids=[v.strip('"\'') for v in re.findall(r'^\s*-\s*id:\s*(\S+)',(folder/'rules.snapshot.yml').read_text(encoding='utf-8'),re.M)]
    audit.compare('*','rules.unique_ids',len(rule_ids),len(set(rule_ids)),folder/'rules.snapshot.yml')
    audit.compare('*', 'engine.errors', [], doc['errors'], path)
    audit.compare('*', 'manifest.issues', [], manifest['issues'], folder/'scan-manifest.json')
    sarif_file = folder/'opengrep.sarif'; sarif = read_json(sarif_file)
    audit.compare('*', 'sarif.version', '2.1.0', sarif['version'], sarif_file)
    sresults, srules = [], {}
    for run in sarif['runs']:
        srules.update({r['id']: r for r in run['tool']['driver']['rules']})
        sresults.extend(run['results'])
    sindex = {}
    for result in sresults:
        physical = result['locations'][0]['physicalLocation']; region = physical['region']
        key = (result['ruleId'], source_path(unquote(physical['artifactLocation']['uri']), manifest),
               region['startLine'], region['startColumn'], region['endLine'], region['endColumn'])
        sindex.setdefault(key, []).append(result)
    keys = [finding_key(f, manifest) for f in doc['results']]
    audit.compare('*', 'sarif.finding_multiset', Counter(keys), Counter({k: len(v) for k,v in sindex.items()}), sarif_file)
    audit.compare('*', 'raw.duplicate_identity', 0, len(keys)-len(set(keys)), path)
    scan_sha = core.sha(raw); findings = {}; method_groups=set()
    for i, finding in enumerate(doc['results']):
        aid = core.sha((scan_sha + ':' + str(i)).encode())
        findings[aid] = (i, finding)
        audit.compare(aid,'rules.finding_id_match',1,sum(finding['check_id']==rule or finding['check_id'].endswith('.'+rule) for rule in rule_ids),path)
        key = keys[i]
        if group=='manual':
            lines=core.safe_file(root,key[1]).read_text(encoding='utf-8').splitlines()
            declarations=[(n,m.group(1)) for n,line in enumerate(lines[:finding['start']['line']],1)
                          if (m:=re.search(r'^\s*(?:public|private|protected)\s+(?:static\s+)?[\w<>?\[\].]+\s+(\w+)\s*\(',line))]
            if declarations: method_groups.add((key[1],*declarations[-1]))
        check_location(finding, None, root, manifest, audit, aid)
        raw_trace = finding['extra'].get('dataflow_trace')
        if raw_trace is None:
            audit.incomplete('Trace not supplied for ' + aid, path, 'trace_absent')
        trace = list(trace_locations(raw_trace))
        for loc, content in trace:
            check_location(loc, content, root, manifest, audit, aid)
        if len(sindex.get(key, [])) != 1:
            continue
        sresult = sindex[key][0]
        raw_cwes = finding['extra']['metadata']['cwe']
        if isinstance(raw_cwes, str): raw_cwes = [raw_cwes]
        cwes = sorted(core.norm_cwe(c) for c in raw_cwes)
        audit.compare(aid, 'cwe.scope', True, set(cwes) <= {'CWE-22','CWE-89'}, path)
        audit.compare(aid, 'sarif.cwe', cwes, sorted(core.norm_cwe(t) for t in srules[finding['check_id']]['properties']['tags'] if t.startswith('CWE-')), sarif_file)
        st = []
        for flow in sresult.get('codeFlows', []):
            for thread in flow['threadFlows']:
                for step in thread['locations']:
                    loc = step['location']['physicalLocation']; reg = loc['region']
                    st.append((source_path(unquote(loc['artifactLocation']['uri']), manifest), reg['startLine'], reg['startColumn'], reg['endLine'], reg['endColumn'], reg.get('snippet', {}).get('text')))
        jt = [(source_path(loc['path'], manifest), *point(loc['start']), *point(loc['end']), content) for loc, content in trace]
        audit.compare(aid, 'sarif.trace_multiset', Counter(jt), Counter(st), sarif_file)
    return {'doc': doc, 'manifest': manifest, 'root': root, 'path': path, 'hash': scan_sha,
            'findings': findings, 'summary': {'findings': len(findings), 'sarif_findings': len(sresults),
            'sources': len(manifest['sources_before']), 'scan_sha256': scan_sha,
            'rules_sha256': manifest['rules_before_sha256'], 'engine_version': (folder/'version.stdout.txt').read_text().strip(),
            'rules_count':len(rule_ids),
            'unique_start_lines': len({(k[1], k[2]) for k in keys}),
            'declaration_groups':sorted(method_groups),
            'declaration_grouping_note':'Nearest preceding method declaration, manually checked on these 8 files; not distinct vulnerability identity',
            'unique_ranges_without_rule': len({k[1:] for k in keys})}}


def verify_labels(label_file, scan, expected_csv, reference_file, audit):
    audit.section = 'owasp_labels_and_sources'
    official = {r[0]: r for r in csv.reader(expected_csv.read_text(encoding='utf-8').splitlines()) if r and not r[0].startswith('#')}
    reference = read_json(reference_file)
    blobs = {Path(x['path']).name: x['sha'] for x in reference['files']}
    def blob(data):
        return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
    audit.compare('*', 'reference.commit', '8b67a88d73b2594570fc21150705283de884620b', reference['commit'], reference_file)
    audit.compare('*', 'official.csv_git_blob', blobs['expectedresults-1.2.csv'], blob(expected_csv.read_bytes()), expected_csv)
    labels = audit.index(read_json(label_file)['labels'], label_file)
    audit.compare('*', 'labels.id_set', sorted(scan['findings']), sorted(labels), label_file)
    for aid, label in labels.items():
        if aid not in scan['findings']: continue
        i, finding = scan['findings'][aid]
        path = source_path(finding['path'], scan['manifest']); src = core.safe_file(scan['root'], path)
        row = official[Path(path).stem]
        for field, expected in [('finding_index', i), ('scan_sha256', scan['hash']), ('rule_id', finding['check_id']),
                ('file_path', path), ('start_line', finding['start']['line']), ('end_line', finding['end']['line']),
                ('source_sha256', core.sha(src.read_bytes())), ('cwe','CWE-'+row[3]),
                ('ground_truth', 'TRUE_POSITIVE' if row[2]=='true' else 'FALSE_POSITIVE')]:
            audit.compare(aid, 'label.'+field, expected, label.get(field), label_file)
        raw_cwe = finding['extra']['metadata']['cwe']
        audit.compare(aid, 'label.raw_cwe', label['cwe'], core.norm_cwe(raw_cwe if isinstance(raw_cwe,str) else raw_cwe[0]), label_file)
        audit.compare(aid, 'source.pinned_git_blob', blobs[Path(path).name], blob(src.read_bytes()), src)
    return labels


def replay_answer(evidence, assessment, root):
    """Independent schema/text replay, not a proof of security semantics or prompt membership."""
    response = assessment.get('raw_response')
    raw = None; reason = 'no raw response'
    if not isinstance(response, dict): return raw, 'UNDETERMINED', 'NOT_VERIFIED', reason
    try:
        answer = core.strict(response['message']['content']); raw = answer.get('status')
        shape = (set(answer) == {'status','explanation','citations','fix_suggestion'} and raw in core.STATES
                 and isinstance(answer['explanation'],str) and bool(answer['explanation'].strip())
                 and isinstance(answer['fix_suggestion'],str) and isinstance(answer['citations'],list))
        if not shape: return raw, 'UNDETERMINED','NOT_VERIFIED','invalid answer schema'
        for cite in answer['citations']:
            if not isinstance(cite,dict) or set(cite) != {'path','start_line','end_line','quote','sha256'}:
                return raw,'UNDETERMINED','NOT_VERIFIED','invalid citation schema'
            if not all(isinstance(cite[k],str) for k in ('path','quote','sha256')):
                return raw,'UNDETERMINED','NOT_VERIFIED','invalid citation string type'
            sl,el=cite['start_line'],cite['end_line']
            if type(sl) is not int or type(el) is not int or el-sl>150:
                return raw,'UNDETERMINED','NOT_VERIFIED','invalid citation range'
            if evidence['snapshots'].get(cite['path'],{}).get('sha256') != cite['sha256']:
                return raw,'UNDETERMINED','NOT_VERIFIED','citation hash absent from snapshot'
        citation = core.citations(evidence, answer, root)
        if citation == 'NOT_VERIFIED': return raw,'UNDETERMINED',citation,'citation does not match source/snapshot'
        if evidence.get('issues'): return raw,'UNDETERMINED','NOT_VERIFIED','evidence issues'
        if response.get('done') is not True or response.get('done_reason') not in (None,'stop'):
            return raw,'UNDETERMINED','NOT_VERIFIED','incomplete model response'
        if response.get('model') != assessment.get('model'):
            return raw,'UNDETERMINED','NOT_VERIFIED','model identity mismatch'
        return raw, raw, citation, 'schema and exact source text match'
    except (ValueError, TypeError, KeyError, AttributeError, OSError):
        return raw,'UNDETERMINED','NOT_VERIFIED','malformed JSON/citation or unavailable source'


def verify_sqlite(path, rows, audit, expected_bundle=None):
    if any(Path(str(path)+suffix).exists() for suffix in ('-wal','-shm')):
        audit.incomplete('SQLite has WAL/SHM; consistent snapshot required', path)
        return {}
    before = core.sha(path.read_bytes())
    with closing(sqlite3.connect(path.resolve().as_uri()+'?mode=ro&immutable=1',uri=True)) as db:
        db.row_factory=sqlite3.Row
        audit.compare('*','sqlite.integrity',['ok'],[r[0] for r in db.execute('PRAGMA integrity_check')],path)
        audit.compare('*','sqlite.foreign_keys',[],list(db.execute('PRAGMA foreign_key_check')),path)
        warnings={r['id']:dict(r) for r in db.execute('SELECT * FROM warnings')}
        audit.compare('*','sqlite.id_set',sorted(rows),sorted(warnings),path)
        bundles={r['id']:core.strict(r['bundle']) for r in db.execute('SELECT * FROM scans')}
        if expected_bundle is not None:
            audit.compare('*','sqlite.full_scan_bundle',expected_bundle,bundles.get(expected_bundle['scan_sha256']),path)
        states={aid:'OPEN' for aid in warnings}
        events=[dict(r) for r in db.execute('SELECT * FROM events ORDER BY sequence')]
        for aid,w in warnings.items():
            if aid not in rows: continue
            row=rows[aid]
            audit.compare(aid,'sqlite.evidence',row['evidence'],core.strict(w['evidence']),path)
            audit.compare(aid,'sqlite.assessment',row['assessment'],core.strict(w['assessment']),path)
            audit.compare(aid,'sqlite.scan_id',row['scan_sha256'],w['scan_id'],path)
            audit.compare(aid,'sqlite.scan_exists',True,w['scan_id'] in bundles,path)
            if w['scan_id'] in bundles:
                audit.compare(aid,'sqlite.bundle_scan',w['scan_id'],bundles[w['scan_id']]['scan_sha256'],path)
        for event in events:
            aid=event['warning_id'];action=event['action']
            audit.compare(aid,'sqlite.event_target',True,aid in warnings,path)
            audit.compare(aid,'sqlite.actor_reason',True,bool(event['actor'].strip()) and bool(event['reason'].strip()),path)
            audit.compare(aid,'sqlite.action_valid',True,action in {'confirm-true','confirm-false','reopen'},path)
            if aid not in warnings: continue
            ev=core.strict(warnings[aid]['evidence'])
            audit.compare(aid,'sqlite.event_evidence_hash',digest_json(ev),event['evidence_sha256'],path)
            version=core.strict(event['source_version']); observed=core.strict(event['observed_version'])
            audit.compare(aid,'sqlite.event_source',ev['snapshots'],version,path)
            if action=='confirm-false':
                audit.compare(aid,'sqlite.false_source_fresh',{p:v['sha256'] for p,v in version.items()},observed,path)
            if action in {'confirm-true','confirm-false','reopen'}:
                states[aid]={'confirm-true':'CONFIRMED_TRUE','confirm-false':'CONFIRMED_FALSE','reopen':'OPEN'}[action]
        for aid,w in warnings.items():
            audit.compare(aid,'sqlite.event_state',states[aid],w['state'],path)
            if aid in rows: audit.compare(aid,'sqlite.export_state',w['state'],rows[aid]['state'],path)
    audit.compare('*','sqlite.unchanged',before,core.sha(path.read_bytes()),path)
    return {'warnings':len(warnings),'events':len(events),'states':dict(Counter(w['state'] for w in warnings.values())),
            'event_actions':[e['action'] for e in events], 'actors':sorted({e['actor'] for e in events})}


def inspect_run(evidence, name, scan, arm, labels, audit):
    audit.section='run_'+name
    folder=evidence/'runs'/name; path=folder/'assessments.jsonl'
    rows=audit.index(read_jsonl(path),path,'id')
    audit.compare('*','run.id_set',sorted(scan['findings']),sorted(rows),path)
    audit.compare('*','run.input_hash',scan['hash'],core.sha((folder/'input.opengrep.json').read_bytes()),folder/'input.opengrep.json')
    bundle=read_json(folder/'evidence.json')
    audit.compare('*','bundle.raw_document',scan['doc'],bundle['raw_document'],folder/'evidence.json')
    audit.compare('*','bundle.scan_hash',scan['hash'],bundle['scan_sha256'],folder/'evidence.json')
    bindex=audit.index(bundle['records'],folder/'evidence.json','id')
    audit.compare('*','bundle.id_set',sorted(scan['findings']),sorted(bindex),folder/'evidence.json')
    observations=[]; transitions=[]; statuses=Counter(); raw_statuses=Counter(); concordance=[0,0]
    responses=0; raw_latencies=[]
    for aid,row in rows.items():
        if aid not in scan['findings']: continue
        i,finding=scan['findings'][aid]; ev=row['evidence'];ans=row['assessment']
        captured_root=normalized(scan['manifest']['source_root'])
        audit.compare(aid,'evidence.captured_root',captured_root,normalized(ev.get('root','')),path)
        provenance=ev.get('scan_provenance',{})
        audit.compare(aid,'provenance.manifest_sha256',core.sha((scan['path'].parent/'scan-manifest.json').read_bytes()),provenance.get('manifest_sha256'),path)
        audit.compare(aid,'provenance.recorded_exit',scan['manifest']['runs']['json']['exit_code'],provenance.get('recorded_engine_exit'),path)
        for mapping in ev.get('path_mappings',[]):
            audit.compare(aid,'mapping.target',captured_root,normalized(mapping['to']),path)
            windows=re.fullmatch(r'([A-Za-z]):/(.*)',captured_root)
            allowed={captured_root}
            if windows:allowed.add('/mnt/'+windows[1].lower()+'/'+windows[2])
            audit.compare(aid,'mapping.source',True,normalized(mapping['from']) in allowed,path)
        for field,expected in [('id',aid),('alert_id',aid),('scan_sha256',scan['hash']),('finding_index',i)]:
            audit.compare(aid,'row.'+field,expected,row.get(field),path)
            audit.compare(aid,'evidence.'+field,expected,ev.get(field),path)
        for field,expected in [('rule_id',finding['check_id']),('path',finding['path']),('start',finding['start']),('end',finding['end']),
                               ('raw_finding',finding),('raw_trace',finding['extra'].get('dataflow_trace')),
                               ('cwe',finding['extra']['metadata']['cwe'])]:
            audit.compare(aid,'evidence.'+field,expected,ev.get(field),path)
            if aid in bindex: audit.compare(aid,'bundle.'+field,expected,bindex[aid].get(field),folder/'evidence.json')
        relative=source_path(finding['path'],scan['manifest'])
        audit.compare(aid,'snapshot.finding_exists',True,relative in ev['snapshots'],path)
        for rel,snapshot in ev['snapshots'].items():
            src=core.safe_file(scan['root'],source_path(rel,scan['manifest'])); data=src.read_bytes()
            audit.compare(aid,'snapshot.sha256',core.sha(data),snapshot['sha256'],src)
            audit.compare(aid,'snapshot.bytes',len(data),snapshot['size'],src)
        for snip in ev['snippets']:
            src=core.safe_file(scan['root'],source_path(snip['path'],scan['manifest'])); data=src.read_bytes();lines=data.decode('utf-8').splitlines()
            audit.compare(aid,'snippet.sha256',core.sha(data),snip['sha256'],src)
            for line in snip['lines']:
                n=line['line']; valid=type(n) is int and 1<=n<=len(lines)
                audit.compare(aid,'snippet.line_range',True,valid,src)
                if valid: audit.compare(aid,'snippet.text_sha256',core.sha(lines[n-1].encode()),core.sha(line['text'].encode()),src)
        post=ans['status']; statuses[post]+=1
        audit.compare(aid,'post.valid',True,post in core.STATES,path)
        audit.compare(aid,'security.not_certified',False,ans.get('security_conclusion_verified'),path)
        audit.compare(aid,'human.review_required',True,ans.get('requires_human_review'),path)
        audit.compare(aid,'run.transport','heuristic-only' if arm=='B' else 'ollama-http',ans.get('transport'),path)
        audit.compare(aid,'run.mode',{'B':'heuristic','C':'evidence+llm','D':'llm'}[arm],ev.get('triage_mode','evidence+llm'),path)
        raw_status=None
        if arm!='B':
            raw_status,replay,citation,reason=replay_answer(ev,ans,scan['root'])
            audit.compare(aid,'replay.post',replay,post,path)
            audit.compare(aid,'replay.citation',citation,ans.get('citation_check'),path)
            response=ans.get('raw_response');rt=ans.get('runtime',{})
            if isinstance(response,dict):
                responses+=1
                audit.compare(aid,'response.json_sha256',digest_json(response),rt.get('response_json_sha256'),path)
                audit.compare(aid,'response.finding_id',aid,rt.get('finding_id'),path)
                audit.compare(aid,'response.http_status',200,rt.get('http_status'),path)
                audit.compare(aid,'response.received',True,rt.get('http_response_received'),path)
                audit.compare(aid,'response.mock',False,bool(response.get('mock_test_fixture')) or rt.get('origin')=='mock',path)
            raw_statuses[str(raw_status)]+=1
            recommended=ev.get('heuristic_signals',{}).get('recommended_status')
            if raw_status in core.STATES and recommended in core.STATES:
                concordance[1]+=1;concordance[0]+=raw_status==recommended
            if raw_status!=post:
                transitions.append({'alert_id':aid,'path':relative,'raw':raw_status,'post':post,'reason':reason,
                                    'raw_citation_count':len(core.strict(response['message']['content']).get('citations',[])) if raw_status in core.STATES else None})
        else:
            audit.compare(aid,'heuristic.raw_model_response',None,ans.get('raw_response'),path)
            audit.compare(aid,'heuristic.no_http_request',False,ans.get('runtime',{}).get('request_attempted') is True,path)
            if post!='UNDETERMINED':audit.compare(aid,'heuristic.citation','MATCHED',core.citations(ev,ans,scan['root']),path)
        seconds=ans.get('elapsed_seconds');ms=None
        if type(seconds) in (int,float):
            value=Decimal(str(seconds))*1000
            if not value.is_finite() or value<0: raise ValueError('invalid raw latency')
            # The historical heuristic implementation assigns elapsed_seconds=0.0;
            # this is a placeholder, not a stopwatch measurement. Keep it in raw input.
            if arm!='B':
                ms=str(value);raw_latencies.append(value)
        elif seconds is not None:
            raise ValueError('invalid latency type')
        elif arm!='B':
            audit.incomplete('Missing elapsed_seconds for '+aid,path,'latency_absent')
        if labels is not None and aid in labels:
            observations.append({'id':aid,'path':relative,'gt':labels[aid]['ground_truth'],'cwe':labels[aid]['cwe'],
                                 'post':post,'raw':raw_status if raw_status in core.STATES else None,'citation':ans.get('citation_check'),
                                 'ms':ms,'human':row['state']})
    checkpoint=evidence/'checkpoints'/(name+'.ckpt.jsonl')
    checkpoint_count=None
    if checkpoint.is_file():
        checkpoints=audit.index(read_jsonl(checkpoint),checkpoint,'id');checkpoint_count=len(checkpoints)
        audit.compare('*','checkpoint.id_set',sorted(rows),sorted(checkpoints),checkpoint)
        for aid,row in rows.items():
            if aid in checkpoints: audit.compare(aid,'checkpoint.assessment',row['assessment'],checkpoints[aid]['assessment'],checkpoint)
    elif arm!='B': audit.incomplete('Historical checkpoint absent for '+name,path,'checkpoint_absent')
    sql=verify_sqlite(folder/'review.sqlite',rows,audit,bundle)
    return {'records':len(rows),'post':dict(statuses),'raw':dict(raw_statuses),'response_records':responses,
            'ground_truth_basis':'AUTHOR_ASSIGNED_UNVERIFIED' if labels and any('number' in v for v in labels.values()) else 'OWASP_CASE_LABELS_AND_SOURCE_BLOBS' if labels else 'NOT_AVAILABLE',
            'heuristic_raw_agreement':core.ratio(*concordance),'checkpoint_records':checkpoint_count,
            'sql':sql,'transitions':transitions,'metrics':core.by_group({arm:observations})[arm] if labels is not None else None,
            'latency_observed':len(raw_latencies),'latency_total_ms':str(sum(raw_latencies)) if raw_latencies else None,
            'latency_mean_ms':str(sum(raw_latencies)/len(raw_latencies)) if raw_latencies else None}


def inspect_review_demo(evidence, audit):
    audit.section='human_review_history'
    folder=evidence/'runs/stage6_human_review_demo'
    transcript_file=folder/'cli_lifecycle_transcript.json'; transcript=read_json(transcript_file)
    expected_rows=audit.index(read_jsonl(evidence/'runs/stage3_dev16_armB_heuristic/assessments.jsonl'),transcript_file,'id')
    final_queue=transcript['12_queue_after_confirm_true']['stdout']['warnings']
    states=audit.index(final_queue,transcript_file,'id')
    audit.compare('*','demo.final_queue_ids',sorted(expected_rows),sorted(states),transcript_file)
    for aid,row in expected_rows.items():
        if aid in states: row['state']=states[aid]['state']
    result=verify_sqlite(folder/'review_demo.sqlite',expected_rows,audit)
    for step,record in transcript.items():
        negative='negative_' in step
        audit.compare(step,'demo.exit_success',not negative,record['exit_code']==0,transcript_file)
    default=transcript['06_queue_after_confirm_false']['stdout']['warnings']
    all_rows=transcript['07_queue_all_after_confirm_false']['stdout']['warnings']
    audit.compare('*','demo.hidden_only_confirmed_false',sorted(w['id'] for w in all_rows if w['state']!='CONFIRMED_FALSE'),sorted(w['id'] for w in default),transcript_file)
    audit.compare('*','demo.all_preserved',sorted(expected_rows),sorted(w['id'] for w in all_rows),transcript_file)
    audit.compare('*','demo.lifecycle_actions',['confirm-false','reopen','confirm-true'],result.get('event_actions'),transcript_file)
    # Lifecycle demo is scripted evidence; actor strings are not authenticated identities.
    result['actor_identity_attested']=False
    audit.incomplete('No stale-source attempt appears in the received 13-step lifecycle transcript; unit-test logs are not that historical CLI attempt',transcript_file,'historical_stale_source_demo')
    return result


def manual_labels(evidence, scan, audit):
    audit.section='manual_label_catalog'
    path=evidence/'cases/REAL_PROJECT_EVALUATION.md';text=path.read_text(encoding='utf-8')
    labels={}
    for line in text.splitlines():
        if not re.match(r'^\| `\d+`',line): continue
        cells=[c.strip() for c in line.strip('|').split('|')]
        number,filename,span,cwe,rule=[c.strip('`') for c in cells[:5]]
        match=re.search(r'`(TRUE_POSITIVE|FALSE_POSITIVE)`',cells[5])
        if not match: raise ValueError('invalid manual table label')
        matches=[]
        for aid,(i,f) in scan['findings'].items():
            start,end=f['start']['line'],f['end']['line']
            actual_span=str(start) if start==end else f'{start}-{end}'
            if source_path(f['path'],scan['manifest'])==filename and span==actual_span and f['check_id'].endswith(rule):
                matches.append(aid)
        audit.compare(number,'manual.unique_finding_match',1,len(matches),path)
        if len(matches)!=1: continue
        aid=matches[0];audit.compare(aid,'manual.duplicate_label',False,aid in labels,path)
        f=scan['findings'][aid][1];src=core.safe_file(scan['root'],filename)
        raw_cwe=f['extra']['metadata']['cwe']
        audit.compare(aid,'manual.cwe',core.norm_cwe(raw_cwe if isinstance(raw_cwe,str) else raw_cwe[0]),cwe,path)
        labels[aid]={'number':number,'file_path':filename,'ground_truth':match[1],'cwe':cwe,
                     'source_sha256':core.sha(src.read_bytes()),'rule_id':f['check_id'],
                     'independently_verified':False}
    audit.compare('*','manual.label_id_set',sorted(scan['findings']),sorted(labels),path)
    return labels


def check_manual_latency_document(evidence, run, audit):
    audit.section='document_consistency'
    path=evidence/'cases/REAL_PROJECT_EVALUATION.md';text=path.read_text(encoding='utf-8')
    found=re.search(r'thời gian chạy tổng cộng `([0-9.]+)s`, trung bình `([0-9.]+)s',text)
    if found and run['latency_total_ms'] is not None:
        for field,expected,actual in [('manual.total_seconds',Decimal(run['latency_total_ms'])/1000,Decimal(found[1])),
                                     ('manual.mean_seconds',Decimal(run['latency_mean_ms'])/1000,Decimal(found[2]))]:
            audit.compare('*',field,expected.quantize(Decimal('.01')),actual,path)
        for row in audit.register:
            if row['criterion']=='document_consistency': row['impact']='Tài liệu: số thời gian không khớp raw; không thay đổi phân loại'


def compare_public_lock(evidence, public, audit):
    audit.section='public_lock_raw_lf'
    path=public/'heldout_strict_lock_manifest.json';lock=read_json(path)
    result={}
    for name in ('labels_development.json','labels_heldout.json','dev_alerts.json','heldout_alerts.json'):
        source=evidence/'labels'/name;raw=source.read_bytes();published=(public/name).read_bytes()
        result[name]={'raw_sha256':core.sha(raw),'lf_sha256':core.sha(raw.replace(b'\r\n',b'\n')),'public_sha256':core.sha(published)}
        audit.compare(name,'public.semantic_json',core.strict(published),core.strict(raw),source)
        audit.compare(name,'public.lf_bytes_hash',core.sha(published),result[name]['lf_sha256'],source)
    og=core.sha((evidence/'labels'/lock['opengrep_file']).read_bytes())
    lb=core.sha((evidence/'labels'/lock['labels_file']).read_bytes())
    audit.compare('*','lock.opengrep_sha256',lock['opengrep_sha256'],og,path)
    audit.compare('*','lock.labels_sha256',lock['labels_sha256'],lb,path)
    text=f"mode:{lock['lock_mode'].strip().upper()}|opengrep:{og}|labels:{lb}|config:{lock['config_sha256'] or 'none'}"
    audit.compare('*','lock.combined_sha256',lock['combined_lock_sha256'],core.sha(text.encode()),path)
    result['combined_lock_sha256']=core.sha(text.encode())
    result['config_sha256']=lock.get('config_sha256')
    audit.section='historical_configuration'
    if lock.get('config_sha256') is None:
        audit.incomplete('Public lock hashes match delivered CRLF inputs, but config_file/config_sha256 are null; this is not a full historical configuration lock',path,'lock_config_null')
    audit.incomplete('Git-published lock/prompt manifest is available as a reference, not proof that the split/configuration was frozen before execution',path,'pre_run_lock_time')
    return result


def jsonable(value):
    if isinstance(value,dict): return {str(k):jsonable(v) for k,v in value.items()}
    if isinstance(value,(list,tuple)): return [jsonable(v) for v in value]
    if isinstance(value,Decimal): return str(value)
    return value


def compare_paired(path, scan, labels, arms, audit):
    audit.section='heldout_published_comparison'
    with path.open(encoding='utf-8',newline='') as stream: rows=audit.index(list(csv.DictReader(stream)),path)
    audit.compare('*','paired.id_set',sorted(scan['findings']),sorted(rows),path)
    for arm, result in arms.items():
        for rec in result['ALL']['per_finding']:
            aid=rec['id']
            if aid not in rows: continue
            row=rows[aid]; label=labels[aid]
            for key in ('scan_sha256','source_sha256','rule_id','cwe'):
                audit.compare(aid,'csv.'+key,label[key],row[key],path)
            for key,expected in [('finding_index',str(label['finding_index'])),('path',label['file_path']),('verified_ground_truth',label['ground_truth'])]:
                audit.compare(aid,'csv.'+key,expected,row[key],path)
            prefix={'B':'arm_b_heuristic','C':'arm_c_qwen35','D':'arm_d_llm_ablation'}[arm]
            audit.compare(aid,arm+'.csv.decision',core.DECISION[rec['post']],row[prefix+'_decision'],path)
            audit.compare(aid,arm+'.csv.citation',rec['citation'],row['arm_'+arm.lower()+'_citation_check'],path)
            if arm=='B': audit.compare(aid,'B.csv.post',rec['post'],row[prefix+'_status'],path)
            else:
                audit.compare(aid,arm+'.csv.raw',rec['raw'],row[prefix+'_raw_status'],path)
                if arm=='C':
                    audit.compare(aid,'C.csv.post',rec['post'],row[prefix+'_post_citation_status'],path)
                    audit.compare(aid,'C.csv.human',rec['human'],row['arm_c_human_review_state'],path)
                observed=Decimal(rec['ms']).quantize(Decimal('.001')) if rec['ms'] is not None else None
                audit.compare(aid,arm+'.csv.latency_ms_3dp',observed,Decimal(row['arm_'+arm.lower()+'_latency_ms']),path)


def protected_call(audit, section, fn):
    audit.section=section
    try: return fn()
    except OSError as exc: audit.incomplete(type(exc).__name__+': '+str(exc))
    except (ValueError,TypeError,KeyError,IndexError,AttributeError,InvalidOperation,sqlite3.DatabaseError) as exc:
        audit.compare('*','input_contract','valid complete schema',type(exc).__name__+': '+str(exc),Path(__file__))
    return None


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package',required=True,type=Path)
    parser.add_argument('--archive-sha256')
    parser.add_argument('--owasp-reference',type=Path,default=Path(__file__).with_name('owasp_reference_blobs.json'))
    parser.add_argument('--public-post-report',type=Path,help='Read-only files exported from pinned experiment commit; not server raw')
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args(argv)
    if args.output.exists() or args.output.resolve().is_relative_to(args.package.resolve()) or args.output.resolve().is_relative_to(Path(__file__).resolve().parents[2]):
        parser.error('choose a new private output directory outside package and repository')
    args.output.mkdir(parents=True)
    audit=Audit();result={'schema':'ntk-independent-raw-audit-1','runtime_attested':False,
                         'metric_source':'raw assessments; public CSV compared only afterwards'}
    transfer=protected_call(audit,'transfer_integrity',lambda:verify_transfer(args.package,args.archive_sha256,audit))
    e=args.package/'extracted/evidence/post_report_cwe22_cwe89_20261112'
    scans={};labels={};runs={}
    if transfer: result['transfer']=transfer[1]
    for group in SCAN_DIRS:
        scan=protected_call(audit,'scan_'+group,lambda g=group:inspect_scan(e,g,audit))
        if scan: scans[group]=scan
    result['scans']={g:s['summary'] for g,s in scans.items()}
    for group in ('development','heldout'):
        if group in scans:
            label_file=e/'labels'/('labels_'+group+'.json')
            value=protected_call(audit,'owasp_labels_and_sources',lambda g=group,p=label_file:verify_labels(p,scans[g],e/'sources/expectedresults-1.2.csv',args.owasp_reference,audit))
            if value is not None: labels[group]=value
    if len(labels)==2:
        audit.section='owasp_labels_and_sources'
        for field in ('file_path','source_sha256'):
            sets=[{r[field] for r in labels[g].values()} for g in ('development','heldout')]
            audit.compare('*','split.'+field,[],sorted(sets[0]&sets[1]),e/'labels/labels_heldout.json')
        result['ground_truth']={g:dict(Counter((r['cwe']+':'+r['ground_truth']) for r in rows.values())) for g,rows in labels.items()}
    if 'manual' in scans:
        value=protected_call(audit,'manual_label_catalog',lambda:manual_labels(e,scans['manual'],audit))
        if value is not None:
            labels['manual']=value;result['manual_author_labels']=value
    for name,(group,arm) in RUNS.items():
        if group not in scans: continue
        value=protected_call(audit,'run_'+name,lambda n=name,g=group,a=arm:inspect_run(e,n,scans[g],a,labels.get(g),audit))
        if value is not None: runs[name]=value
    result['runs']=runs
    if 'stage5_real_projects_armC_evidence_llm' in runs:
        protected_call(audit,'document_consistency',lambda:check_manual_latency_document(e,runs['stage5_real_projects_armC_evidence_llm'],audit))
    result['review_demo']=protected_call(audit,'human_review_history',lambda:inspect_review_demo(e,audit))
    heldout={a:runs[n]['metrics'] for n,(g,a) in RUNS.items() if g=='heldout' and n in runs and runs[n]['metrics'] is not None}
    if 'heldout' in labels:
        baseline=[{'id':aid,'path':r['file_path'],'gt':r['ground_truth'],'cwe':r['cwe'],'post':'SUPPORTED','raw':None,'ms':None,'citation':None,'human':'NOT_APPLICABLE'} for aid,r in labels['heldout'].items()]
        heldout['A']=core.by_group({'A':baseline})['A']
        protected_call(audit,'heldout_published_comparison',lambda:compare_paired(e/'metrics/PAIRED_EVALUATION.csv',scans['heldout'],labels['heldout'],{a:m for a,m in heldout.items() if a!='A'},audit))
        rounded=copy.deepcopy(heldout)
        for groups in rounded.values():
            for m in groups.values():
                for field in ('mean_ms','median_ms','p95_nearest_rank_ms'):
                    if m['latency'][field] is not None:
                        m['latency'][field]=str(Decimal(m['latency'][field]).quantize(Decimal('.001')))
        protected_call(audit,'heldout_aggregate_comparison',lambda:core.compare_reported_metrics(e/'metrics/METRICS_BY_CWE.csv',rounded,audit))
    result['heldout_metrics']=heldout
    result['reference']=protected_call(audit,'external_reference',lambda:{'commit':read_json(args.owasp_reference)['commit'],
                         'file_sha256':core.sha(args.owasp_reference.read_bytes())})
    selected=('stage3_dev16_armC_v2_1_evidence_llm','stage4_heldout40_armC_evidence_llm','stage5_real_projects_armC_evidence_llm')
    result['guided_pipeline_agreement']=core.ratio(sum(runs[n]['heuristic_raw_agreement']['numerator'] for n in selected if n in runs),
                                                 sum(runs[n]['heuristic_raw_agreement']['denominator'] for n in selected if n in runs))
    if args.public_post_report:
        result['public_lock']=protected_call(audit,'public_lock_raw_lf',lambda:compare_public_lock(e,args.public_post_report,audit))
    # No server receipt conclusions are used as answers for any check above.
    audit.section='historical_configuration'
    for filename in ('heldout_strict_lock_manifest.json','PROMPT_VERSION_MANIFEST.json'):
        matches=list(e.rglob(filename))
        if not matches: audit.incomplete('Not present in transferred experimental inputs: '+filename,field=filename)
    audit.incomplete('Original request payload/body files and full historical model/options/code lock are not supplied; client JSON receipt is not independent runtime attestation')
    audit.section='manual_ground_truth'
    audit.incomplete('20 project/demo alerts have author labels, not independently proven case ground truth; see #08/#09/#10/#15 review',e/'cases/REAL_PROJECT_EVALUATION.md')
    audit.section='latency_measurements'
    audit.incomplete('Arm B records a hard-coded 0.0 placeholder; no per-alert stopwatch. Arm A has scan-capture timestamps, not equivalent per-alert triage timings')
    audit.section='immutability'
    if transfer: audit.compare('*','all_input_hashes_unchanged',transfer[0],inventory(args.package/'extracted'),args.package/'files.sha256.csv')
    result.update(status=audit.status(),exit_code=audit.exit_code(),criteria=audit.statuses(),
                  checked_fields=dict(audit.checked_fields),section_counts=dict(audit.section_counts),
                  register=audit.register,missing=audit.missing)
    (args.output/'audit.private.json').write_text(json.dumps(jsonable(result),ensure_ascii=False,indent=2,default=str),encoding='utf-8')
    print(json.dumps({'status':audit.status(),'exit_code':audit.exit_code(),'checks':sum(audit.checked_fields.values()),
                      'failures':len(audit.differences),'incomplete':len(audit.missing),'output':str(args.output)},ensure_ascii=False))
    return audit.exit_code()


if __name__=='__main__':
    raise SystemExit(main())
