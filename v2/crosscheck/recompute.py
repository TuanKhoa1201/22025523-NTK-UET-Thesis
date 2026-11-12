"""Independent, stdlib-only audit. Never invokes scanner, LLM or production scorer.

Exit 0: complete checks; 2: contradiction; 3: incomplete evidence.
Published mode cannot establish raw-runtime acceptance and always exits 3 or 2.
"""
import argparse
import csv
import hashlib
import json
import math
import re
from collections import Counter
from decimal import Decimal, InvalidOperation
from pathlib import Path

STATES = {'SUPPORTED', 'REFUTED', 'UNDETERMINED'}
DECISION = {'SUPPORTED': 'KEEP_TP', 'REFUTED': 'PROPOSED_FP', 'UNDETERMINED': 'REVIEW'}
EXIT_CODES = {'PASS': 0, 'FAIL': 2, 'INCOMPLETE': 3}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def strict(data):
    def pairs(items):
        d = {}
        for k, v in items:
            if k in d:
                raise ValueError('duplicate JSON key: ' + k)
            d[k] = v
        return d
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))


def ratio(a, b):
    return {'numerator': a, 'denominator': b, 'value': a / b if b else None}


def norm_cwe(c):
    return str(c).split(':')[0].strip().upper()


def safe_file(root, path):
    p = (Path(root) / path).resolve(strict=True)
    if not p.is_relative_to(Path(root).resolve()) or not p.is_file():
        raise ValueError('path outside source root: ' + str(path))
    return p


class Audit:
    def __init__(self):
        self.differences = []
        self.missing = []
        self.checked_fields = Counter()

    def compare(self, aid, field, expected, actual, source):
        source = Path(source)
        self.checked_fields[field] += 1
        if expected != actual:
            self.differences.append({'alert_id': aid, 'field': field, 'expected': expected,
                                     'actual': actual, 'source_file': str(source),
                                     'source_sha256': sha(source.read_bytes()) if source.is_file() else None})

    def incomplete(self, message):
        self.missing.append(message)

    def index(self, records, source, key='alert_id'):
        result = {}
        for r in records:
            k = r[key]
            self.compare(k, 'duplicate_id', False, k in result, source)
            result[k] = r
        return result

    def status(self):
        return 'FAIL' if self.differences else 'INCOMPLETE' if self.missing else 'PASS'

    def exit_code(self):
        return EXIT_CODES[self.status()]


def metrics(rows):
    """Rows are observations, not answers fixed to any corpus size."""
    c = Counter((r['gt'], r['post']) for r in rows)
    if any(r['post'] not in STATES or r['gt'] not in {'TRUE_POSITIVE', 'FALSE_POSITIVE'} for r in rows):
        raise ValueError('unknown post status or ground truth')
    if any(r.get('raw') is not None and r['raw'] not in STATES for r in rows):
        raise ValueError('unknown raw status')
    n = len(rows)
    tp = sum(r['gt'] == 'TRUE_POSITIVE' for r in rows)
    fp = sum(r['gt'] == 'FALSE_POSITIVE' for r in rows)
    ts, tr, tu = [c['TRUE_POSITIVE', s] for s in ('SUPPORTED', 'REFUTED', 'UNDETERMINED')]
    fs, fr, fu = [c['FALSE_POSITIVE', s] for s in ('SUPPORTED', 'REFUTED', 'UNDETERMINED')]
    try:
        samples = [Decimal(str(r['ms'])) for r in rows if r.get('ms') is not None]
    except InvalidOperation as exc:
        raise ValueError('non-numeric latency') from exc
    if any(not x.is_finite() or x < 0 for x in samples):
        raise ValueError('invalid latency')
    complete = bool(rows) and len(samples) == n
    ordered = sorted(samples)
    total = sum(samples, Decimal(0))
    mean = total / len(samples) if samples else None
    median = ((ordered[(len(samples)-1)//2] + ordered[len(samples)//2]) / 2) if samples else None
    p95 = ordered[math.ceil(Decimal('.95') * len(samples))-1] if samples else None
    conclusive = ts + tr + fs + fr
    cited = sum(r.get('citation') == 'MATCHED' for r in rows)
    citation_observed = sum(r.get('citation') is not None for r in rows)
    transitions = Counter((r['raw'], r['post']) for r in rows if r.get('raw') in STATES)
    policies = {}
    for name, keep in [('baseline', STATES), ('drop_fp', {'SUPPORTED', 'UNDETERMINED'}),
                       ('keep_tp_only', {'SUPPORTED'})]:
        kt = sum(r['gt'] == 'TRUE_POSITIVE' and r['post'] in keep for r in rows)
        kf = sum(r['gt'] == 'FALSE_POSITIVE' and r['post'] in keep for r in rows)
        policies[name] = {'precision': ratio(kt, kt + kf), 'tp_retention_recall': ratio(kt, tp),
                          'tp_retained': kt, 'fp_retained': kf,
                          'tp_excluded': ratio(tp - kt, tp), 'fp_excluded': ratio(fp - kf, fp)}
    return {'n': n, 'tp': tp, 'fp': fp, 'tp_supported': ts, 'fp_proposed': fr,
            'post_gt_matrix': {'TRUE_POSITIVE': dict(zip(('SUPPORTED', 'REFUTED', 'UNDETERMINED'), (ts, tr, tu))),
                               'FALSE_POSITIVE': dict(zip(('SUPPORTED', 'REFUTED', 'UNDETERMINED'), (fs, fr, fu)))},
            'fp_correctly_proposed_rate': ratio(fr, fp), 'tp_erroneously_proposed_rate': ratio(tr, tp),
            'supported_precision': ratio(ts, ts + fs), 'supported_tp_recall': ratio(ts, tp),
            'raw_statuses': dict(Counter(str(r.get('raw')) for r in rows)),
            'raw_unavailable': sum(r.get('raw') is None for r in rows),
            'raw_to_post': {raw + '->' + post: count for (raw, post), count in sorted(transitions.items())},
            'raw_post_changes': sum(count for (raw, post), count in transitions.items() if raw != post),
            'raw_gt_matrix': {gt: dict(Counter(str(r.get('raw')) for r in rows if r['gt'] == gt))
                              for gt in ('TRUE_POSITIVE', 'FALSE_POSITIVE')},
            'tp_erroneously_proposed': tr, 'fp_supported': fs, 'undetermined': tu + fu,
            'citation_observed': citation_observed,
            'citation_matched': ratio(cited, n) if citation_observed else ratio(0, 0),
            'citation_matched_conclusive': ratio(sum(r.get('citation') == 'MATCHED' and r['post'] != 'UNDETERMINED' for r in rows), conclusive) if citation_observed else ratio(0, 0),
            'conclusive_coverage': ratio(conclusive, n),
            'accuracy_all': ratio(ts + fr, n), 'selective_accuracy': ratio(ts + fr, conclusive),
            'human_states': dict(Counter(r.get('human', 'NOT_CHECKED') for r in rows)),
            'policies': policies, 'latency': {'observed': len(samples), 'expected': n,
            'observed_total_ms': str(total) if samples else None,
            'observed_mean_ms': str(mean) if samples else None,
            'total_ms': str(total) if complete else None,
            'mean_ms': str(mean) if complete else None,
            'median_ms': str(median) if complete else None,
            'p95_nearest_rank_ms': str(p95) if complete else None,
            'complete': complete, 'meaning': 'sum/mean of per-alert observations; not wall-clock duration'},
            'per_finding': rows}


def by_group(arms):
    if any(r['cwe'] not in {'CWE-22', 'CWE-89'} for rows in arms.values() for r in rows):
        raise ValueError('CWE outside audit scope')
    result = {arm: {group: metrics([r for r in rows if group == 'ALL' or r['cwe'] == group])
                  for group in ('ALL', 'CWE-22', 'CWE-89')} for arm, rows in arms.items()}
    for arm, groups in result.items():
        for item in groups.values():
            item['status_basis'] = {'A': 'baseline_keep_placeholder_not_model', 'B': 'heuristic_post',
                                    'C': 'model_post_validator', 'D': 'model_post_validator'}[arm]
    return result


def ground_truth(data, expected, sources, audit):
    official = {r[0]: r for r in csv.reader(Path(expected).read_text(encoding='utf-8').splitlines())
                if r and not r[0].startswith('#')}
    out, splits = [], []
    for name in ('development', 'heldout'):
        f = Path(data) / ('labels_' + name + '.json')
        labels = strict(f.read_bytes())['labels']
        audit.index(labels, f)
        paths = set()
        for l in labels:
            aid = l['alert_id']; path = l['file_path']; case = Path(path).stem
            paths.add(path)
            o = official[case]
            audit.compare(aid, 'official_cwe', 'CWE-' + o[3], l['cwe'], f)
            audit.compare(aid, 'official_label', 'TRUE_POSITIVE' if o[2] == 'true' else 'FALSE_POSITIVE', l['ground_truth'], f)
            audit.compare(aid, 'contract_id', sha((l['scan_sha256'] + ':' + str(l['finding_index'])).encode()), aid, f)
            src = safe_file(sources, path); b = src.read_bytes(); lines = b.decode('utf-8').splitlines()
            audit.compare(aid, 'source_hash', l['source_sha256'], sha(b), src)
            sl, el = l['start_line'], l['end_line']
            audit.compare(aid, 'sink_range_exists', True, type(sl) is int and type(el) is int and 1 <= sl <= el <= len(lines), f)
            out.append({'split': name, 'alert_id': aid, 'case': case, 'cwe': l['cwe'], 'gt': l['ground_truth'],
                        'sink_line': sl, 'sink_text': '\n'.join(lines[sl-1:el]), 'source_sha256': sha(b),
                        'flow_semantics': 'MANUAL_REVIEW_REQUIRED', 'label_source': 'OWASP case; not model'})
        splits.append(paths)
    audit.compare('*', 'split_overlap', [], sorted(splits[0] & splits[1]), Path(data) / 'labels_heldout.json')
    return out


def published(data, audit):
    f = Path(data) / 'PAIRED_EVALUATION.csv'
    rows = list(csv.DictReader(f.open(encoding='utf-8', newline='')))
    audit.index(rows, f)
    label_file = Path(data) / 'labels_heldout.json'
    labels = audit.index(strict(label_file.read_bytes())['labels'], label_file)
    audit.compare('*', 'csv_id_set', sorted(labels), sorted(r['alert_id'] for r in rows), f)
    arms = {a: [] for a in 'ABCD'}
    for r in rows:
        aid = r['alert_id']
        if aid not in labels:
            continue  # ID-set mismatch is already recorded; retain a per-field report.
        l = labels[aid]
        for k in ('scan_sha256', 'source_sha256', 'cwe', 'rule_id'):
            audit.compare(aid, k, l[k], r[k], f)
        for k, v in [('finding_index', str(l['finding_index'])), ('path', l['file_path']), ('verified_ground_truth', l['ground_truth'])]:
            audit.compare(aid, k, v, r[k], f)
        span = str(l['start_line']) if l['start_line'] == l['end_line'] else str(l['start_line']) + '-' + str(l['end_line'])
        audit.compare(aid, 'sink_line_range', span, r['line'], f)
        audit.compare(aid, 'A.decision', 'KEEP', r['arm_a_opengrep_decision'], f)
        for a, post, cit, latency in [('A', 'SUPPORTED', None, None),
                ('B', r['arm_b_heuristic_status'], r['arm_b_citation_check'], None),
                ('C', r['arm_c_qwen35_post_citation_status'], r['arm_c_citation_check'], r['arm_c_latency_ms']),
                ('D', {'KEEP_TP': 'SUPPORTED', 'PROPOSED_FP': 'REFUTED', 'REVIEW': 'UNDETERMINED'}[r['arm_d_llm_ablation_decision']], r['arm_d_citation_check'], r['arm_d_latency_ms'])]:
            audit.compare(aid, a + '.valid_post_status', True, post in STATES, f)
            if a in 'BC':
                audit.compare(aid, a + '.decision', DECISION[post], r['arm_b_heuristic_decision' if a == 'B' else 'arm_c_qwen35_decision'], f)
            raw = r.get('arm_c_qwen35_raw_status') if a == 'C' else r.get('arm_d_llm_ablation_raw_status') if a == 'D' else None
            if a in 'CD':
                if not raw:
                    raw = None
                    audit.incomplete(a + '/' + aid + ': raw status missing in published CSV')
                elif raw not in STATES:
                    raise ValueError('invalid published raw status: ' + raw)
                if not latency:
                    latency = None
                    audit.incomplete(a + '/' + aid + ': latency missing in published CSV')
            if a != 'A':
                audit.compare(aid, a + '.valid_citation_state', True, cit in {'MATCHED', 'NOT_VERIFIED', 'NONE'}, f)
            arms[a].append({'id': aid, 'path': l['file_path'], 'gt': l['ground_truth'], 'cwe': l['cwe'], 'post': post, 'ms': latency,
                            'citation': cit, 'raw': raw,
                            'human': r.get('arm_c_human_review_state') if a == 'C' else 'NOT_CHECKED'})
    audit.incomplete('Published CSV only: no independent raw assessments/scan/manifest/runtime verification')
    return by_group(arms)


def compare_reported_metrics(path, calculated, audit):
    """Check the public aggregate table against per-alert computation, not vice versa."""
    path = Path(path)
    with path.open(encoding='utf-8', newline='') as stream:
        rows = list(csv.DictReader(stream))
    expected = {(a, group) for a, groups in calculated.items() for group in groups}
    seen = set()
    for row in rows:
        match = re.fullmatch(r'Arm_([ABCD])_.+', row['arm'])
        if not match:
            raise ValueError('unknown aggregate arm: ' + row['arm'])
        arm = match[1]
        group = 'ALL' if row['cwe_group'] == 'ALL (CWE-22 + CWE-89)' else row['cwe_group']
        key = (arm, group); aid = arm + '/' + group
        audit.compare(aid, 'aggregate.duplicate', False, key in seen, path)
        seen.add(key)
        if key not in expected:
            audit.compare(aid, 'aggregate.known_group', True, False, path)
            continue
        m = calculated[arm][group]
        for col, field in [('total_alerts', 'n'), ('labeled_tp', 'tp'), ('labeled_fp', 'fp')]:
            audit.compare(aid, 'aggregate.' + col, m[field], int(row[col]), path)
        ratios = {
            'tp_kept_supported': ratio(m['tp_supported'], m['tp']),
            'tp_retained_total_with_review': m['policies']['drop_fp']['tp_retention_recall'],
            'fp_correctly_proposed_refuted': m['fp_correctly_proposed_rate'],
            'tp_erroneously_proposed_fp': m['tp_erroneously_proposed_rate'],
            'undetermined_review_rate': ratio(m['undetermined'], m['n']),
            'citation_verified_rate': m['citation_matched'],
            'policy_drop_fp_precision': m['policies']['drop_fp']['precision'],
            'policy_drop_fp_tp_recall': m['policies']['drop_fp']['tp_retention_recall'],
            'policy_keep_tp_only_precision': m['policies']['keep_tp_only']['precision'],
            'policy_keep_tp_only_tp_recall': m['policies']['keep_tp_only']['tp_retention_recall']}
        for col, value in ratios.items():
            if value['denominator'] == 0:
                audit.compare(aid, 'aggregate.' + col, 'N/A', row[col], path)
                continue
            parsed = re.fullmatch(r'(\d+)/(\d+) \((\d+(?:\.\d+)?)%\)', row[col])
            if not parsed:
                raise ValueError('invalid ratio ' + col + ': ' + row[col])
            audit.compare(aid, 'aggregate.' + col + '.fraction',
                          [value['numerator'], value['denominator']], [int(parsed[1]), int(parsed[2])], path)
            pct = (Decimal(value['numerator']) * 100 / value['denominator']).quantize(Decimal('.1'))
            audit.compare(aid, 'aggregate.' + col + '.percent', pct, Decimal(parsed[3]), path)
        for col, field in [('mean_latency_ms', 'mean_ms'), ('p50_latency_ms', 'median_ms'), ('p95_latency_ms', 'p95_nearest_rank_ms')]:
            if m['latency'][field] is None:
                audit.incomplete(aid + ': ' + col + ' not verifiable; aggregate value is not a per-alert measurement')
            else:
                audit.compare(aid, 'aggregate.' + col, Decimal(m['latency'][field]), Decimal(row[col]), path)
    audit.compare('*', 'aggregate.group_set', sorted(expected), sorted(seen), path)


def check_manifest(path, raw, source_root, audit):
    path = Path(path); doc = strict(path.read_bytes())
    audit.compare('*', 'manifest.schema', 'ntk-scan-capture-1', doc.get('schema'), path)
    audit.compare('*', 'manifest.success', True, doc.get('success'), path)
    for name, expected in doc['artifacts'].items():
        artifact = safe_file(path.parent, name)
        audit.compare('*', 'artifact.' + name, expected, sha(artifact.read_bytes()), artifact)
    audit.compare('*', 'scan.raw_hash', sha(raw), sha(safe_file(path.parent, 'opengrep.json').read_bytes()), path)
    audit.compare('*', 'sources.before_after', doc['sources_before'], doc['sources_after'], path)
    audit.compare('*', 'rules.before_after', doc['rules_before_sha256'], doc['rules_after_sha256'], path)
    audit.compare('*', 'rules.snapshot', doc['rules_before_sha256'], sha(safe_file(path.parent, 'rules.snapshot.yml').read_bytes()), path)
    for label in ('version', 'json', 'sarif'):
        run = doc['runs'][label]
        audit.compare('*', label + '.exit_integer', True, type(run['exit_code']) is int, path)
        audit.compare('*', label + '.exit', 0, run['exit_code'], path)
        audit.compare('*', label + '.exit_artifact', str(run['exit_code']), safe_file(path.parent, label + '.exit.txt').read_text().strip(), path)
        audit.compare('*', label + '.argv', run['argv'], strict(safe_file(path.parent, label + '.command.json').read_bytes()), path)
    for src, expected in doc['sources_before'].items():
        p = safe_file(source_root, src)
        audit.compare('*', 'captured_source.' + src, expected, sha(p.read_bytes()), p)
    return doc


def citations(record, answer, sources):
    if answer.get('status') == 'UNDETERMINED' and answer.get('citations') == []:
        return 'NONE'
    cites = answer.get('citations')
    if not isinstance(cites, list) or not cites:
        return 'NOT_VERIFIED'
    available = {(s['path'], l['line']): l['text'] for s in record['snippets'] for l in s['lines']}
    for c in cites:
        p = safe_file(sources, c['path']); b = p.read_bytes(); lines = b.decode('utf-8').splitlines()
        sl, el = c['start_line'], c['end_line']
        if type(sl) is not int or type(el) is not int or not 1 <= sl <= el <= len(lines):
            return 'NOT_VERIFIED'
        text = '\n'.join(lines[sl-1:el])
        if not text.strip() or text != c['quote'] or sha(b) != c['sha256']:
            return 'NOT_VERIFIED'
        if any(available.get((c['path'], i)) != lines[i-1] for i in range(sl, el+1)):
            return 'NOT_VERIFIED'
    # Historical snapshots are checked here. Actual prompt membership is a separate requirement.
    return 'MATCHED'


def raw_run(spec, audit):
    root = Path(spec['source_root']); scan = Path(spec['scan']); raw = scan.read_bytes()
    doc = strict(raw); scan_hash = sha(raw)
    audit.compare('*', 'engine_errors', [], doc.get('errors', []), scan)
    check_manifest(spec['scan_manifest'], raw, root, audit)
    lf = Path(spec['labels']); labels = audit.index(strict(lf.read_bytes())['labels'], lf)
    expected = {sha((scan_hash + ':' + str(i)).encode()): (i, f) for i, f in enumerate(doc['results'])}
    audit.compare('*', 'raw_labels_id_set', sorted(expected), sorted(labels), lf)
    arms = {'A': []}
    for aid, (i, f) in expected.items():
        l = labels[aid]
        for k, v in [('finding_index', i), ('scan_sha256', scan_hash), ('rule_id', f['check_id']), ('start_line', f['start']['line']), ('end_line', f['end']['line'])]:
            audit.compare(aid, 'label.' + k, v, l[k], lf)
        audit.compare(aid, 'raw_cwe', l['cwe'], norm_cwe((f['extra']['metadata']['cwe'] if isinstance(f['extra']['metadata']['cwe'], str) else f['extra']['metadata']['cwe'][0])), scan)
        p = safe_file(root, l['file_path'])
        audit.compare(aid, 'label.source_hash', l['source_sha256'], sha(p.read_bytes()), p)
        arms['A'].append({'id': aid, 'gt': l['ground_truth'], 'cwe': l['cwe'], 'post': 'SUPPORTED', 'raw': None, 'citation': None, 'ms': None})
    for arm in 'BCD':
        cfg = spec['arms'].get(arm)
        if not cfg:
            audit.incomplete('Missing arm ' + arm); continue
        p = Path(cfg['assessments']); records = [strict(l) for l in p.read_text(encoding='utf-8').splitlines() if l.strip()]
        ix = audit.index(records, p, 'id')
        audit.compare('*', arm + '.id_set', sorted(expected), sorted(ix), p)
        arms[arm] = []
        for aid, (i, f) in expected.items():
            if aid not in ix: continue
            row = ix[aid]; ev = row['evidence']; ans = row['assessment']; l = labels[aid]
            for k, v in [('id', aid), ('finding_index', i), ('scan_sha256', scan_hash), ('rule_id', f['check_id']), ('raw_finding', f)]:
                audit.compare(aid, arm + '.evidence.' + k, v, ev.get(k), p)
            audit.compare(aid, arm + '.evidence.cwe', l['cwe'], norm_cwe(ev.get('cwe', ['UNKNOWN'])[0]), p)
            audit.compare(aid, arm + '.evidence.path', f['path'], ev.get('path'), p)
            for point in ('start', 'end'):
                audit.compare(aid, arm + '.evidence.' + point, f[point], ev.get(point), p)
            finding = next((s for s in ev['snippets'] if s.get('role') == 'finding'), {})
            audit.compare(aid, arm + '.source_path', l['file_path'], finding.get('path'), p)
            audit.compare(aid, arm + '.source_hash', l['source_sha256'], finding.get('sha256'), p)
            for path, snap in ev['snapshots'].items():
                src = safe_file(root, path)
                audit.compare(aid, arm + '.snapshot.' + path, snap['sha256'], sha(src.read_bytes()), src)
            audit.compare(aid, arm + '.transport', 'heuristic-only' if arm == 'B' else 'ollama-http', ans.get('transport'), p)
            audit.compare(aid, arm + '.mode', {'B': 'heuristic', 'C': 'evidence+llm', 'D': 'llm'}[arm], ev.get('triage_mode', 'evidence+llm'), p)
            post = ans.get('status'); audit.compare(aid, arm + '.post_valid', True, post in STATES, p)
            inner = None
            if arm != 'B':
                response = ans.get('raw_response')
                if response and isinstance(response.get('message'), dict):
                    try: inner = strict(response['message']['content']).get('status')
                    except (ValueError, TypeError): pass
                if inner not in STATES: audit.incomplete(arm + '/' + aid + ': raw model status unavailable')
                if inner in STATES:
                    raw_answer = strict(response['message']['content'])
                    shape = (set(raw_answer) == {'status','explanation','citations','fix_suggestion'}
                             and isinstance(raw_answer['explanation'], str) and bool(raw_answer['explanation'].strip())
                             and isinstance(raw_answer['fix_suggestion'], str) and isinstance(raw_answer['citations'], list))
                    grounded = citations(ev, raw_answer, root) if shape else 'NOT_VERIFIED'
                    replay = inner if (shape and not ev.get('issues') and response.get('done') is True
                                      and response.get('done_reason') in (None,'stop')
                                      and response.get('model') == ans.get('model')
                                      and (inner == 'UNDETERMINED' or grounded == 'MATCHED')) else 'UNDETERMINED'
                    audit.compare(aid, arm + '.independent_post_replay', replay, post, p)
                rt = ans.get('runtime', {})
                audit.compare(aid, arm + '.not_mock', False, rt.get('origin') == 'mock' or bool((response or {}).get('mock_test_fixture')), p)
                if not rt.get('response_body_sha256'): audit.incomplete(arm + '/' + aid + ': HTTP body receipt missing')
                audit.incomplete(arm + '/' + aid + ': historical prompt membership/runtime attestation requires original request receipt')
            checked_citation = citations(ev, ans, root)
            if post != 'UNDETERMINED': audit.compare(aid, arm + '.citation', checked_citation, ans.get('citation_check'), p)
            # A rejected raw quote is removed from the fallback answer. NONE from
            # the empty fallback is not the historical NOT_VERIFIED result.
            cit = ans.get('citation_check')
            seconds = ans.get('elapsed_seconds')
            ms = str(Decimal(str(seconds)) * 1000) if type(seconds) in (int, float) else None
            if ms is None: audit.incomplete(arm + '/' + aid + ': latency unavailable')
            arms[arm].append({'id': aid, 'gt': l['ground_truth'], 'cwe': l['cwe'], 'post': post,
                              'raw': inner, 'citation': cit, 'ms': ms, 'human': row.get('state', 'NOT_RECORDED')})
    if spec.get('paired_csv'):
        p = Path(spec['paired_csv']); rows = audit.index(list(csv.DictReader(p.open(encoding='utf-8'))), p)
        audit.compare('*', 'csv.raw_id_set', sorted(expected), sorted(rows), p)
        for arm, records in arms.items():
            for rec in records:
                if rec['id'] not in rows: continue
                r = rows[rec['id']]; aid = rec['id']; l = labels[aid]
                for k in ('rule_id', 'cwe', 'scan_sha256', 'source_sha256'):
                    audit.compare(aid, 'csv.' + k, l[k], r[k], p)
                audit.compare(aid, 'csv.path', l['file_path'], r['path'], p)
                audit.compare(aid, 'csv.gt', rec['gt'], r['verified_ground_truth'], p)
                keys = {'B': [('post', 'arm_b_heuristic_status')], 'C': [('post', 'arm_c_qwen35_post_citation_status'), ('raw', 'arm_c_qwen35_raw_status'), ('citation', 'arm_c_citation_check')], 'D': [('raw', 'arm_d_llm_ablation_raw_status'), ('citation', 'arm_d_citation_check')]}.get(arm, [])
                for k, col in keys: audit.compare(aid, arm + '.csv.' + k, rec[k], r[col], p)
                if arm in 'CD':
                    audit.compare(aid, arm + '.csv.decision', DECISION[rec['post']], r['arm_c_qwen35_decision' if arm == 'C' else 'arm_d_llm_ablation_decision'], p)
                    # codex_adapter at the experiment commit exports round(seconds*1000, 3).
                    # Preserve unrounded ms in metrics; compare CSV at its declared precision.
                    audit.compare(aid, arm + '.csv.latency', Decimal(rec['ms']).quantize(Decimal('.001')) if rec['ms'] else None, Decimal(r['arm_c_latency_ms' if arm == 'C' else 'arm_d_latency_ms']), p)
    return by_group(arms)


def write_public_tables(output, result):
    """Small reproducible public-derived artifacts; never called for raw input mode."""
    summary = {k: v for k, v in result.items() if k not in {'metrics', 'ground_truth'}}
    summary['metrics'] = {arm: {group: {k: v for k, v in m.items() if k != 'per_finding'}
                               for group, m in groups.items()} for arm, groups in result['metrics'].items()}
    (output / 'published_metrics.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2, default=str) + '\n', encoding='utf-8')
    per_alert = [dict(arm=arm, **row) for arm, groups in result['metrics'].items() for row in groups['ALL']['per_finding']]
    transitions = [row for row in per_alert if row.get('raw') in STATES and row['raw'] != row['post']]
    tables = [('published_per_alert.csv', per_alert, ['arm', 'id', 'path', 'gt', 'cwe', 'post', 'ms', 'citation', 'raw', 'human']),
              ('status_transitions.csv', transitions, ['arm', 'id', 'path', 'gt', 'cwe', 'post', 'ms', 'citation', 'raw', 'human'])]
    if 'ground_truth' in result:
        tables.append(('ground_truth_56.csv', result['ground_truth'],
                       ['split', 'alert_id', 'case', 'cwe', 'gt', 'sink_line', 'sink_text', 'source_sha256', 'flow_semantics', 'label_source']))
    for name, rows, fields in tables:
        with (output / name).open('w', encoding='utf-8', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader(); writer.writerows(rows)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--spec', type=Path)
    p.add_argument('--published', type=Path)
    p.add_argument('--expectedresults', type=Path)
    p.add_argument('--owasp-sources', type=Path)
    p.add_argument('--reference-commit', help='Caller-declared public source commit; hashes are recorded independently')
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args(argv); a = Audit(); result = {}
    if bool(args.spec) == bool(args.published): p.error('choose --spec or --published')
    if args.published and args.output.resolve().is_relative_to(args.published.resolve()):
        p.error('output must be outside input dataset')
    if args.spec:
        try:
            config = strict(args.spec.read_bytes())
            for parent in (Path(config['source_root']), Path(config['scan']).parent):
                if args.output.resolve().is_relative_to(parent.resolve()):
                    p.error('output must be outside source and scan capture directories')
        except (OSError, ValueError, TypeError, KeyError):
            pass  # Main audit below records missing/invalid inputs without silently passing.
    if args.output.exists():
        p.error('output already exists; choose a new directory')
    args.output.mkdir(parents=True, exist_ok=False)
    try:
        result['metrics'] = raw_run(strict(args.spec.read_bytes()), a) if args.spec else published(args.published, a)
        if args.published:
            metric_table = args.published / 'METRICS_BY_CWE.csv'
            if metric_table.is_file():
                compare_reported_metrics(metric_table, result['metrics'], a)
            else:
                a.incomplete('METRICS_BY_CWE.csv unavailable; reported aggregates not checked')
            result['public_input_hashes'] = {name: sha((args.published / name).read_bytes())
                                           for name in ('PAIRED_EVALUATION.csv', 'METRICS_BY_CWE.csv',
                                                        'labels_heldout.json', 'labels_development.json')
                                           if (args.published / name).is_file()}
        if args.published and args.expectedresults and args.owasp_sources:
            result['ground_truth'] = ground_truth(args.published, args.expectedresults, args.owasp_sources, a)
            result['official_csv_sha256'] = sha(args.expectedresults.read_bytes())
        else: a.incomplete('Official OWASP case/source audit not included in this invocation')
    except OSError as exc:
        a.incomplete(type(exc).__name__ + ': ' + str(exc))
    except (ValueError, TypeError, KeyError, IndexError, AttributeError, InvalidOperation) as exc:
        a.compare('*', 'input_contract', 'valid data structure', type(exc).__name__ + ': ' + str(exc), args.spec or args.published)
    result.update(status=a.status(), missing=a.missing, checked_fields=dict(a.checked_fields),
                  discrepancies=a.differences, schema_version='ntk-crosscheck-2',
                  evidence_class='PUBLIC_DERIVED' if args.published else 'RAW_INPUT_AUDIT',
                  raw_runtime_verified=False,
                  reference_commit=args.reference_commit,
                  scope='No inference execution; no inferred human confirmations; runtime attestation unsupported')
    (args.output / 'audit.json').write_text(json.dumps(result, ensure_ascii=False, indent=2, default=str), encoding='utf-8')
    with (args.output / 'discrepancies.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['alert_id','field','expected','actual','source_file','source_sha256']); w.writeheader(); w.writerows(a.differences)
    if args.published and 'metrics' in result:
        write_public_tables(args.output, result)
    print(json.dumps({'status': a.status(), 'discrepancies': len(a.differences), 'missing': len(a.missing), 'checked': sum(a.checked_fields.values())}))
    return a.exit_code()


if __name__ == '__main__':
    raise SystemExit(main())
