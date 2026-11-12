"""Independent G1 data checks. No producer imports; no evidence writes."""
from collections import Counter, defaultdict
from datetime import datetime
import hashlib
import json
import math
import re
from urllib.parse import unquote, urlsplit

STATUSES = {'SUPPORTED', 'REFUTED', 'UNDETERMINED'}
STATES = {'OPEN', 'CONFIRMED_TRUE', 'CONFIRMED_FALSE'}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def strict(text):
    def pairs(items):
        result = {}
        for k, v in items:
            require(k not in result, 'duplicate JSON key: ' + k)
            result[k] = v
        return result
    def number(value):
        result = float(value)
        require(math.isfinite(result), 'nonfinite JSON number')
        return result
    def constant(value):
        raise ValueError('invalid JSON constant: ' + value)
    return json.loads(text, object_pairs_hook=pairs, parse_float=number, parse_constant=constant)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def hexhash(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None, 'invalid SHA-256')
    return value


def version(obj):
    value = obj.get('schema_version', '1.0')
    require(isinstance(value, str) and re.fullmatch(r'1\.\d+', value) is not None, 'incompatible schema_version')


def timestamp(value):
    require(isinstance(value, str), 'missing timestamp')
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(result.tzinfo is not None and result.utcoffset() is not None, 'timestamp must include timezone')
    return result


def path_key(value, uri=False):
    require(isinstance(value, str) and bool(value) and not any(ord(c) < 32 for c in value), 'invalid path')
    if uri:
        require(not re.search(r'%(?![0-9a-fA-F]{2})', value), 'invalid URI escape')
        if value.lower().startswith('file:'):
            parsed = urlsplit(value)
            require(parsed.netloc.lower() in ('', 'localhost') and not parsed.query and not parsed.fragment,
                    'remote or ambiguous file URI')
            value = unquote(parsed.path, errors='strict')
            if re.match(r'^/[a-zA-Z]:/', value): value = value[1:]
        else:
            require(not urlsplit(value).scheme or re.match(r'^[a-zA-Z]:[/\\]', value), 'unsupported URI scheme')
            require('?' not in value and '#' not in value, 'ambiguous relative URI')
            value = unquote(value, errors='strict')
    value = value.replace('\\', '/')
    require(not value.startswith('//') and '..' not in value.split('/') and '\x00' not in value,
            'path traversal/UNC is forbidden')
    require(':' not in value[2:] and (':' not in value or re.match(r'^[a-zA-Z]:/', value)), 'invalid path colon')
    value = '/'.join(p for p in value.split('/') if p != '.')
    if re.match(r'^[a-zA-Z]:/', value): value = value[0].lower() + value[1:]
    return value.rstrip('/')


def relative_java(value):
    key = path_key(value)
    require(not key.startswith('/') and not re.match(r'^[a-zA-Z]:', key) and key == value and key.endswith('.java'),
            'source key must be canonical relative Java path')
    return key


def position(value):
    require(isinstance(value, dict), 'missing position')
    for key in ('line', 'col'):
        require(type(value.get(key)) is int and value[key] > 0, 'invalid line/column')
    return value['line'], value['col']


def raw_results(doc):
    require(isinstance(doc, dict) and isinstance(doc.get('results'), list) and isinstance(doc.get('errors'), list),
            'raw scan requires results/errors arrays')
    require(not doc['errors'], 'scanner reported errors/partial scan')
    skipped = doc.get('paths', {}).get('skipped', [])
    # OpenGrep can report non-Java files skipped by design. Java skips cannot pass completeness.
    require(not any(isinstance(p, dict) and str(p.get('path', '')).lower().endswith('.java') for p in skipped),
            'Java files skipped; scan completeness unproven')
    for finding in doc['results']:
        require(isinstance(finding.get('check_id'), str) and bool(finding['check_id']), 'missing full rule ID')
        path_key(finding['path'])
        require(finding['path'].lower().endswith('.java'), 'non-Java finding')
        require(position(finding['end']) >= position(finding['start']), 'reversed finding span')
        require(finding['extra']['severity'] in ('ERROR', 'WARNING', 'INFO', 'INVENTORY', 'EXPERIMENT'), 'invalid severity')
        require(isinstance(finding['extra'].get('metadata'), dict), 'missing metadata')
    return doc['results']


def validate_bundle(raw, doc, bundle):
    version(bundle)
    findings = raw_results(doc)
    require(bundle['scan_sha256'] == digest(raw) and bundle['raw_document'] == doc and bundle['issues'] == [], 'bundle/raw mismatch')
    require(isinstance(bundle['records'], list) and len(bundle['records']) == len(findings), 'record count mismatch')
    ids = set()
    for index, (finding, rec) in enumerate(zip(findings, bundle['records'])):
        version(rec)
        expected = digest((digest(raw) + ':' + str(index)).encode())
        require(rec['id'] == rec['alert_id'] == expected and rec['scan_sha256'] == digest(raw)
                and type(rec['finding_index']) is int and rec['finding_index'] == index and expected not in ids,
                'finding ID/index/order mismatch')
        ids.add(expected)
        require(rec['raw_finding'] == finding and rec['raw_trace'] == finding['extra'].get('dataflow_trace'), 'raw finding/trace changed')
        require(rec['rule_id'] == finding['check_id'] and rec['severity'] == finding['extra']['severity']
                and rec['cwe'] == finding['extra']['metadata'].get('cwe', []), 'rule/severity/CWE changed')
        for key in ('path', 'start', 'end'):
            require(rec[key] == finding[key], 'finding location changed')
        require(rec['root'] == bundle['root'], 'record source root changed')
    return bundle['records']


def assessment(a):
    require(isinstance(a, dict) and a['status'] in STATUSES, 'invalid model status')
    require(a['requires_human_review'] is True and a['security_conclusion_verified'] is False, 'model/human separation violated')
    require(isinstance(a['explanation'], str) and bool(a['explanation'].strip()) and isinstance(a['fix_suggestion'], str)
            and isinstance(a['citations'], list), 'invalid assessment fields')


def validate_rows(rows, bundle):
    require(len(rows) == len(bundle['records']), 'JSONL count mismatch')
    ids, indices = set(), set()
    for row, rec in zip(rows, bundle['records']):
        version(row)
        require(type(row['finding_index']) is int and row['finding_index'] not in indices and row['id'] not in ids,
                'duplicate/invalid JSONL ID or index')
        require(row['id'] == row['alert_id'] == rec['id'] and row['scan_sha256'] == rec['scan_sha256']
                and row['finding_index'] == rec['finding_index'] and row['evidence'] == rec, 'JSONL join/order mismatch')
        require(row['state'] == 'OPEN', 'JSONL ingestion state must be OPEN; current human state is in SQLite')
        assessment(row['assessment'])
        ids.add(row['id']); indices.add(row['finding_index'])
    return rows


def cwes(value):
    if isinstance(value, str): value = [value]
    require(isinstance(value, list) and all(isinstance(x, str) for x in value), 'invalid CWE metadata')
    return sorted(set(re.findall(r'\bCWE-\d+\b', ' '.join(value))))


def compare_sarif(doc, sarif):
    findings = raw_results(doc)
    require(sarif.get('version', '2.1.0') == '2.1.0' and isinstance(sarif.get('runs'), list) and bool(sarif['runs']), 'invalid SARIF runs/version')
    raw_by_key, sarif_by_key = defaultdict(list), defaultdict(list)
    coverage = Counter()
    for r in findings:
        raw_by_key[(r['check_id'], path_key(r['path']), r['start']['line'], r['end']['line'])].append(r)
    for run in sarif['runs']:
        require(isinstance(run['results'], list), 'missing SARIF results')
        for invocation in run.get('invocations', []):
            require(invocation.get('executionSuccessful') is not False, 'SARIF execution unsuccessful')
            require(not any(n.get('level') == 'error' for n in invocation.get('toolExecutionNotifications', [])), 'SARIF engine notification error')
        driver = run.get('tool', {}).get('driver', {})
        rules = driver.get('rules', [])
        rule_map = {r['id']:r for r in rules}
        require(len(rule_map) == len(rules), 'duplicate SARIF rule descriptor')
        for r in run['results']:
            require(isinstance(r['ruleId'], str) and bool(r['ruleId']), 'missing SARIF rule ID')
            if 'ruleIndex' in r:
                i = r['ruleIndex']; require(type(i) is int and 0 <= i < len(rules) and rules[i]['id'] == r['ruleId'], 'SARIF ruleIndex mismatch')
            require(len(r['locations']) == 1, 'ambiguous primary SARIF location')
            p = r['locations'][0]['physicalLocation']; region = p['region']; artifact = p['artifactLocation']
            value = artifact['uri']
            # %SRCROOT% is commonly present without a definition in OpenGrep output.
            # Use exact relative path in that case; never guess an absolute base.
            if 'uriBaseId' in artifact and artifact['uriBaseId'] in run.get('originalUriBaseIds', {}):
                base = run['originalUriBaseIds'][artifact['uriBaseId']]['uri']
                require(not urlsplit(value).scheme and not value.startswith('/'), 'absolute path with uriBaseId')
                value = base.rstrip('/') + '/' + value
            key = (r['ruleId'], path_key(value, uri=True), region['startLine'], region.get('endLine', region['startLine']))
            require(type(key[2]) is int and type(key[3]) is int and 1 <= key[2] <= key[3], 'invalid SARIF lines')
            descriptor = rule_map.get(r['ruleId'], {})
            level = r.get('level', descriptor.get('defaultConfiguration', {}).get('level'))
            tags = descriptor.get('properties', {}).get('tags')
            metadata = r.get('properties', {}).get('metadata', {})
            observed_cwes = cwes(metadata['cwe']) if 'cwe' in metadata else cwes(tags) if tags is not None else None
            sarif_by_key[key].append(dict(region=region, level=level, cwes=observed_cwes))
    require(set(raw_by_key) == set(sarif_by_key), 'JSON/SARIF full rule/path/line sets differ')
    for key, left in raw_by_key.items():
        right = sarif_by_key[key]
        require(len(left) == len(right), 'JSON/SARIF finding multiplicity differs')
        def compatible(raw, sr):
            rg = sr['region']
            for sk, jk, side in (('startColumn', 'col', 'start'), ('endColumn', 'col', 'end')):
                if sk in rg and (type(rg[sk]) is not int or rg[sk] <= 0 or rg[sk] != raw[side][jk]): return False
            if sr['level'] is not None:
                expected = {'ERROR':'error', 'WARNING':'warning', 'INFO':'note', 'INVENTORY':'note', 'EXPERIMENT':'note'}[raw['extra']['severity']]
                if sr['level'] != expected: return False
            if sr['cwes'] is not None and sr['cwes'] != cwes(raw['extra']['metadata'].get('cwe', [])): return False
            return True
        # Bipartite matching handles duplicate locations with optional SARIF fields.
        matches = {}
        def assign(i, seen):
            for j, sr in enumerate(right):
                if j in seen or not compatible(left[i], sr): continue
                seen.add(j)
                if j not in matches or assign(matches[j], seen):
                    matches[j] = i; return True
            return False
        require(all(assign(i, set()) for i in range(len(left))), 'JSON/SARIF columns/severity/CWE differ')
        for sr in right:
            for field in ('startColumn','endColumn'): coverage[field] += field in sr['region']
            coverage['severity'] += sr['level'] is not None
            coverage['cwe'] += sr['cwes'] is not None
    return dict(findings=len(findings), optional_fields_compared=dict(coverage),
                limitation='Missing optional SARIF metadata is disclosed, not invented. JSON trace checked separately.')
