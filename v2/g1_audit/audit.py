"""Read-only G1 artifact audit. Standard library; never imports producer checks."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import re
from contextlib import closing
from contracts import (strict, require, version, hexhash, timestamp, path_key, relative_java,
                       validate_bundle, validate_rows, compare_sarif, assessment)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load(path):
    return strict(Path(path).read_text(encoding='utf-8'))


def inside(root, name):
    require(isinstance(name, str) and bool(name) and not Path(name).is_absolute()
            and '..' not in name.replace('\\', '/').split('/') and ':' not in name,
            'unsafe relative artifact path')
    path = (root / name).resolve(strict=True)
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError('artifact escapes root or is not a file: ' + str(name))
    return path


def git(root, *args):
    p = subprocess.run(['git', '-c', 'safe.directory=' + root.as_posix(), '-C', str(root), *args],
                       capture_output=True, text=True)
    if p.returncode:
        raise ValueError(p.stderr.strip())
    return p.stdout.strip()


class Audit:
    def __init__(self, checkout, evidence, capture=None):
        self.checkout, self.root = Path(checkout).resolve(), Path(evidence).resolve()
        self.capture = Path(capture).resolve() if capture else self.root / 'engine'
        self.checks, self.artifacts = [], {}

    def path(self, name):
        return inside(self.capture, name[len('engine/'):]) if name.startswith('engine/') else inside(self.root,name)

    def read(self, name):
        p = self.path(name)
        self.artifacts[str(name)] = sha(p.read_bytes())
        return load(p)

    def check(self, name, fn):
        try:
            detail = fn()
            status = 'PASS'
        except FileNotFoundError as exc:
            status, detail = 'INCOMPLETE', str(exc)
        except (ValueError, KeyError, TypeError, IndexError, AttributeError, OSError, sqlite3.Error) as exc:
            status, detail = 'FAIL', str(exc)
        self.checks.append(dict(check=name, status=status, detail=detail))

    def manifest(self):
        m = self.read('engine/scan-manifest.json')
        if m['schema'] != 'ntk-scan-capture-1':
            raise ValueError('unsupported manifest schema')
        require(timestamp(m['finished_at']) >= timestamp(m['started_at']), 'reversed scan timestamps')
        require(isinstance(m['source_root'], str) and bool(m['source_root']), 'missing scan source root')
        require(m['target_kind'] in ('file', 'directory'), 'invalid target kind')
        require(isinstance(m['sources_before'], dict), 'invalid source inventory')
        for name, expected in m['sources_before'].items():
            relative_java(name); hexhash(expected)
        require(m['target_kind'] != 'file' or len(m['sources_before']) == 1, 'file target needs one source')
        required = {'opengrep.json', 'opengrep.sarif', 'rules.snapshot.yml'}
        required.update(label + suffix for label in ('version', 'json', 'sarif')
                        for suffix in ('.command.json', '.exit.txt', '.stdout.txt', '.stderr.txt'))
        if not required <= set(m['artifacts']):
            raise ValueError('manifest does not hash all required process artifacts')
        for name, expected in m['artifacts'].items():
            require('/' not in name and '\\' not in name, 'manifest artifacts must be basenames')
            hexhash(expected)
            p = inside(self.capture, name)
            actual = sha(p.read_bytes())
            self.artifacts['engine/' + name] = actual
            if actual != expected:
                raise ValueError('artifact hash mismatch: ' + name)
        executables, targets, rules = set(), set(), set()
        for label in ('version', 'json', 'sarif'):
            run = m['runs'][label]
            argv = self.read('engine/' + label + '.command.json')
            if argv != run['argv'] or not argv or not all(isinstance(x, str) and x for x in argv):
                raise ValueError('command mismatch: ' + label)
            executable = argv[0].replace('\\', '/').split('/')[-1].lower()
            if executable not in ('opengrep', 'opengrep.exe'):
                raise ValueError('engine executable requires review: ' + executable)
            executables.add(path_key(argv[0]))
            require(argv.count('--' + label) == 1, 'recorded command format mismatch')
            code = int(self.path('engine/' + label + '.exit.txt').read_text())
            if type(run['exit_code']) is not int or code != run['exit_code'] or code != 0:
                raise ValueError('recorded engine failure: ' + label)
            if label != 'version':
                selected = []
                for i, token in enumerate(argv):
                    if token in ('--config', '-c'):
                        require(i + 1 < len(argv), 'missing rules argument'); selected.append(argv[i + 1])
                    elif token.startswith('--config='): selected.append(token.split('=', 1)[1])
                require(len(selected) == 1 and selected[0] != 'auto' and '://' not in selected[0]
                        and not selected[0].startswith(('p/', 'r/')), 'one explicit local rules file required')
                rules.add(path_key(selected[0]))
                # Inherited CLI places target BEFORE --json/--sarif/--output.
                # Scanner-only CLI places it last. Parse value-taking flags rather than argv[-1].
                value_flags = {'--config','-c','--output','-o','--timeout','--jobs','-j','--include','--exclude',
                               '--max-target-bytes','--max-memory','--timeout-threshold'}
                positional, i = [], 1
                while i < len(argv):
                    token = argv[i]
                    if token in value_flags:
                        require(i+1 < len(argv), 'option missing argument'); i += 2; continue
                    if token == 'scan' and i == 1 or token.startswith('-'):
                        i += 1; continue
                    positional.append(path_key(token)); i += 1
                require(len(positional)==1,'ambiguous or missing scanner target; review argv')
                target = positional[0]; targets.add(target)
                expected_target = path_key(m['source_root'])
                if m['target_kind'] == 'file': expected_target += '/' + next(iter(m['sources_before']))
                require(target == expected_target, 'scan target differs from manifest source root')
                if run.get('output_mode', 'stdout') == 'stdout':
                    if self.path('engine/' + label + '.stdout.txt').read_bytes() != self.path('engine/opengrep.' + label).read_bytes():
                        raise ValueError('stdout mismatch')
                elif run['output_mode'] == 'file':
                    if argv.count('--output') != 1 or argv[argv.index('--output') + 1] != run['engine_output_path'] or '--' + label not in argv:
                        raise ValueError('file output argv mismatch')
                    output = path_key(run['engine_output_path'])
                    capture = path_key(str(self.capture.resolve()))
                    require(output.startswith(capture + '/'), 'engine file output outside capture; explicit original-path mapping required')
                else:
                    raise ValueError('unsupported output mode')
        require(len(executables) == len(targets) == len(rules) == 1, 'engine/rules/target changed across scan formats')
        engine_version = self.path('engine/version.stdout.txt').read_text().strip()
        require(re.fullmatch(r'(?:opengrep\s+)?\d+\.\d+\.\d+(?:[-+][\w.-]+)?', engine_version, re.I) is not None,
                'unrecognized engine version; review original version stdout')
        if m['success'] is not True or m['issues'] != [] or m['sources_before'] != m['sources_after'] or m['rules_before_sha256'] != m['rules_after_sha256']:
            raise ValueError('unsuccessful capture or changed inputs')
        if sha(self.path('engine/rules.snapshot.yml').read_bytes()) != m['rules_before_sha256']:
            raise ValueError('rule hash mismatch')
        for fmt in ('json', 'sarif'):
            doc = self.read('engine/opengrep.' + fmt)
            if fmt == 'json':
                from contracts import raw_results
                raw_results(doc)
                if 'version' in doc: require(doc['version'] == engine_version, 'JSON engine version differs')
            else:
                require(isinstance(doc.get('runs'), list) and bool(doc['runs']), 'missing SARIF run')
                for run in doc['runs']:
                    driver = run.get('tool', {}).get('driver', {})
                    if 'semanticVersion' in driver: require(driver['semanticVersion'] == engine_version, 'SARIF engine version differs')
        return dict(version=engine_version, rules_path=next(iter(rules)), runs=list(m['runs']),
                    limitation='unsigned process capture; executable basename/version are not binary attestation')

    def identity(self):
        raw = inside(self.root, 'input.opengrep.json').read_bytes()
        if raw != self.path('engine/opengrep.json').read_bytes():
            raise ValueError('handoff changed raw bytes')
        doc, bundle = self.read('input.opengrep.json'), self.read('evidence.json')
        records = validate_bundle(raw, doc, bundle)
        return str(len(records)) + ' identities preserved; not security labels'

    def sarif(self):
        doc, sarif = self.read('input.opengrep.json'), self.read('engine/opengrep.sarif')
        return compare_sarif(doc, sarif)

    def sources(self):
        m, bundle = self.read('engine/scan-manifest.json'), self.read('evidence.json')
        root = Path(bundle['root']).resolve(strict=True)
        require(path_key(bundle['root']) == path_key(m['source_root']), 'bundle/manifest source root differs')
        for name, expected in m['sources_before'].items():
            relative_java(name)
            try: actual = sha(inside(root, name).read_bytes())
            except FileNotFoundError as exc: raise ValueError('STALE_SOURCE missing: ' + name) from exc
            if actual != expected:
                raise ValueError('STALE_SOURCE: ' + name)
        if m['target_kind'] == 'directory':
            require({p.relative_to(root).as_posix() for p in root.rglob('*.java')} == set(m['sources_before']), 'source inventory changed')
        for rec in bundle['records']:
            for name, snapshot in rec['snapshots'].items():
                if snapshot['sha256'] != m['sources_before'].get(name):
                    raise ValueError('snapshot not bound to scan')
                require(snapshot['size'] == inside(root, name).stat().st_size, 'snapshot byte size differs')
            require(isinstance(rec['issues'], list), 'invalid record issues')
            if not rec['snapshots'] or rec['issues']:
                raise FileNotFoundError('complete Java evidence unavailable; warning retained for review')
            for snippet in rec['snippets']:
                name = relative_java(snippet['path'])
                raw_path = snippet.get('raw_path', rec['path'] if snippet['role'] == 'finding' else name)
                resolved_raw = path_key(raw_path)
                root_key = path_key(str(root))
                for mapping in sorted(rec.get('path_mappings', []), key=lambda m:len(m['from']), reverse=True):
                    prefix, destination = path_key(mapping['from']), path_key(mapping['to'])
                    require(destination == root_key or destination.startswith(root_key+'/'), 'path-map destination escapes source root')
                    if resolved_raw == prefix or resolved_raw.startswith(prefix+'/'):
                        resolved_raw = destination + resolved_raw[len(prefix):]; break
                if not resolved_raw.startswith('/') and not re.match(r'^[a-zA-Z]:/',resolved_raw):
                    resolved_raw = root_key + '/' + resolved_raw
                require(resolved_raw.startswith(root_key+'/'), 'raw finding/trace path outside source root')
                if resolved_raw != root_key + '/' + name:
                    raise FileNotFoundError('explicit path_base mapping missing; auditor will not guess source prefix')
                data = inside(root, name).read_bytes()
                require(snippet['sha256'] == sha(data) == rec['snapshots'][name]['sha256'], 'snippet source hash differs')
                lines = data.decode('utf-8').splitlines(keepends=True)
                offsets = []
                for point in (snippet['start'], snippet['end']):
                    line, col = point['line'], point['col']
                    require(type(line) is int and type(col) is int and 1 <= line <= len(lines)
                            and 1 <= col <= len(lines[line-1].rstrip('\r\n').encode('utf-8'))+1, 'snippet line/column out of range')
                    offset = sum(len(x.encode('utf-8')) for x in lines[:line-1])+col-1
                    require('offset' not in point or type(point['offset']) is int and point['offset'] == offset, 'snippet byte offset differs')
                    offsets.append(offset)
                require(offsets[0] < offsets[1], 'empty/reversed snippet span')
                matched = data[offsets[0]:offsets[1]].decode('utf-8')
                require(snippet['matched'] == matched, 'snippet matched bytes differ')
                seen_lines = set()
                for line in snippet['lines']:
                    i = line['line']
                    require(type(i) is int and 1 <= i <= len(lines) and i not in seen_lines, 'invalid/duplicate snippet line')
                    require(line['text'] == lines[i-1].rstrip('\r\n'), 'snippet quote differs from Java source')
                    seen_lines.add(i)
        return 'current source matches captured hashes'

    def rows(self):
        path = inside(self.root, 'assessments.jsonl')
        self.artifacts['assessments.jsonl'] = sha(path.read_bytes())
        rows = [strict(line) for line in path.read_text(encoding='utf-8').splitlines()]
        return validate_rows(rows, self.read('evidence.json'))

    def database(self):
        path = inside(self.root, 'review.sqlite')
        if Path(str(path) + '-wal').exists() and Path(str(path) + '-wal').stat().st_size:
            raise FileNotFoundError('checkpointed SQLite snapshot required; audit never checkpoints evidence')
        self.artifacts['review.sqlite'] = sha(path.read_bytes())
        rows, bundle = self.rows(), self.read('evidence.json')
        if len(rows) != len(bundle['records']):
            raise ValueError('assessment count mismatch')
        with closing(sqlite3.connect(path.as_uri() + '?mode=ro&immutable=1', uri=True)) as db:
            db.row_factory = sqlite3.Row
            require(db.execute('PRAGMA quick_check').fetchone()[0] == 'ok', 'SQLite integrity check failed')
            require(not list(db.execute('PRAGMA foreign_key_check')), 'SQLite foreign keys broken')
            scans = list(db.execute('SELECT * FROM scans'))
            require(len(scans) == 1 and scans[0]['id'] == bundle['scan_sha256']
                    and strict(scans[0]['bundle']) == bundle, 'SQLite scan/bundle mismatch (one-run bundle required)')
            warnings = {r['id']: r for r in db.execute('SELECT * FROM warnings')}
            if set(warnings) != {r['id'] for r in bundle['records']}:
                raise ValueError('SQLite warning set mismatch')
            for row, rec in zip(rows, bundle['records']):
                w = warnings[rec['id']]
                if w['scan_id'] != bundle['scan_sha256'] or row['id'] != rec['id'] or row['evidence'] != rec or strict(w['evidence']) != rec or strict(w['assessment']) != row['assessment']:
                    raise ValueError('SQLite/JSONL join mismatch')
                a = row['assessment']
                if a['status'] not in ('SUPPORTED', 'REFUTED', 'UNDETERMINED') or a['requires_human_review'] is not True or a['security_conclusion_verified'] is not False:
                    raise ValueError('model/human separation violated')
                events = list(db.execute('SELECT * FROM events WHERE warning_id=? ORDER BY sequence', (rec['id'],)))
                state = 'OPEN'
                previous_time, previous_seq = None, 0
                for event in events:
                    require(type(event['sequence']) is int and event['sequence'] > previous_seq, 'invalid event sequence')
                    at = timestamp(event['timestamp'])
                    require(previous_time is None or at >= previous_time, 'event timestamps reversed')
                    if 'collected_at' in rec:
                        require(at >= timestamp(rec['collected_at']), 'event predates evidence collection')
                    previous_time, previous_seq = at, event['sequence']
                    state = {'confirm-true': 'CONFIRMED_TRUE', 'confirm-false': 'CONFIRMED_FALSE', 'reopen': 'OPEN'}[event['action']]
                    if not event['actor'].strip() or not event['reason'].strip():
                        raise ValueError('event lacks actor/reason')
                    expected_version = strict(event['source_version'])
                    observed_version = strict(event['observed_version'])
                    require(expected_version == rec['snapshots'], 'event source version differs from warning snapshot')
                    require(set(observed_version) == set(expected_version), 'event observed version has missing/extra files')
                    for name, value in expected_version.items():
                        relative_java(name); hexhash(value['sha256'])
                        if observed_version[name] != 'MISSING_OR_UNREADABLE': hexhash(observed_version[name])
                    encoded = json.dumps(rec, ensure_ascii=False, sort_keys=True).encode('utf-8')
                    require(event['evidence_sha256'] == sha(encoded), 'event evidence digest differs')
                    if event['action'] == 'confirm-false':
                        require(not rec['issues'] and bool(expected_version), 'false confirmation with incomplete evidence')
                        require(rec['scan_provenance']['source_capture_verified'] is True, 'false confirmation lacks captured source identity')
                        require(observed_version == {k:v['sha256'] for k,v in expected_version.items()}, 'false confirmation with stale source')
                        manifest = self.read('engine/scan-manifest.json')
                        require(at >= timestamp(manifest['finished_at']), 'false-confirm event predates captured scan')
                        require(all(manifest['sources_before'].get(k) == v['sha256'] for k,v in expected_version.items()),
                                'event snapshot differs from scan-time inventory')
                if w['state'] != state:
                    raise ValueError('state not justified by human events')
            all_events = list(db.execute('SELECT * FROM events ORDER BY sequence'))
            require(all(e['warning_id'] in warnings for e in all_events), 'event refers to unknown warning')
        return 'read-only SQLite state/event replay matches; actors are unauthenticated'

    def runtime(self):
        counts = Counter()
        for row in self.rows():
            a = row['assessment']; r = a.get('runtime', {})
            assessment(a)
            require(isinstance(r, dict), 'invalid runtime metadata')
            for field in ('request_attempted', 'http_response_received', 'answer_validated'):
                require(type(r.get(field)) is bool, 'missing/nonboolean runtime observation: ' + field)
                counts[field] += r.get(field) is True
            counts['mock'] += r.get('origin') == 'mock'
            if a.get('endpoint'):
                from urllib.parse import urlsplit
                url = urlsplit(a['endpoint'])
                if (url.scheme != 'http' or url.hostname not in ('127.0.0.1', 'localhost', '::1')
                        or url.username or url.password or url.query or url.fragment or url.path not in ('','/')):
                    raise ValueError('nonlocal model endpoint')
            if a['status'] != 'UNDETERMINED' and (not r.get('answer_validated') or a.get('citation_check') != 'MATCHED'):
                raise ValueError('conclusive status without validator success')
            if r['http_response_received']:
                require(r['request_attempted'] and type(r['http_status']) is int, 'response without HTTP request/status')
            if r['answer_validated']:
                response = a['raw_response']
                require(response['model'] == a['model'] and response['done'] is True
                        and response.get('done_reason') in (None, 'stop'), 'validated response truncated or model identity differs')
                answer = strict(response['message']['content'])
                require(answer['status'] == a['status'] and answer['citations'] == a['citations'], 'raw model/validator answer differs')
            if a['status'] != 'UNDETERMINED':
                rec = row['evidence']
                require(not rec['issues'] and bool(a['citations']), 'conclusive status with insufficient evidence')
                require(isinstance(rec['raw_trace'], dict) and rec['raw_trace'].get('taint_source')
                        and rec['raw_trace'].get('taint_sink'), 'conclusive taint verdict lacks source/sink trace')
                available = {(s['path'], line['line']):line['text'] for s in rec['snippets'] for line in s['lines']}
                for cite in a['citations']:
                    relative_java(cite['path']); start, end = cite['start_line'], cite['end_line']
                    require(type(start) is int and type(end) is int and 1 <= start <= end <= start+150, 'invalid citation range')
                    require(cite['sha256'] == rec['snapshots'][cite['path']]['sha256'], 'citation hash mismatch')
                    require(cite['quote'] == '\n'.join(available[(cite['path'], i)] for i in range(start, end+1)), 'citation not supplied in evidence')
        return dict(counts)

    def run(self):
        for name in ('manifest', 'identity', 'sarif', 'sources', 'database', 'runtime'):
            self.check(name, getattr(self, name))
        # Unsigned producer artifacts alone cannot establish these acceptance conditions.
        for name in ('fork_cli_runtime_and_handoff_no_rescan', 'qwen_digest_prompt_request_response_provenance',
                     'independent_C1_C8_tests_at_candidate_sha', 'demo_commands_and_runtime_observer'):
            self.checks.append(dict(check=name, status='INCOMPLETE', detail='independent candidate-specific observation required; summary.json is not evidence'))
        statuses = [c['status'] for c in self.checks]
        return dict(schema='ntk-g1-independent-audit-1', timestamp=datetime.now(timezone.utc).isoformat(),
                    tested_sha=git(self.checkout, 'rev-parse', 'HEAD'), checks=self.checks,
                    evidence_layout=dict(triage=str(self.root),capture=str(self.capture)),
                    counts=dict(Counter(statuses)), artifacts=self.artifacts,
                    verdict='FAIL' if 'FAIL' in statuses else 'INCOMPLETE' if 'INCOMPLETE' in statuses else 'PASS')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--checkout', required=True); p.add_argument('--evidence', required=True)
    p.add_argument('--capture',help='explicit separate original CLI capture directory; default <evidence>/engine')
    p.add_argument('--output', required=True, help='new directory outside checkout/evidence')
    a = p.parse_args(); out = Path(a.output).resolve()
    checkout, evidence = Path(a.checkout).resolve(), Path(a.evidence).resolve()
    if out.is_relative_to(evidence) or out.is_relative_to(checkout) or a.capture and out.is_relative_to(Path(a.capture).resolve()):
        p.error('output must be outside inspected checkout and evidence')
    result = Audit(checkout, evidence, a.capture).run()
    out.mkdir(parents=True, exist_ok=False)
    (out / 'audit.json').write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding='utf-8')
    (out / 'audit.md').write_text('# G1 artifact audit: ' + result['verdict'] + '\n\n' +
        '\n'.join('- ' + c['check'] + ': ' + c['status'] + ' — ' + str(c['detail']) for c in result['checks']), encoding='utf-8')
    print(result['verdict'])
    return {'PASS': 0, 'FAIL': 1, 'INCOMPLETE': 2}[result['verdict']]


if __name__ == '__main__':
    raise SystemExit(main())
