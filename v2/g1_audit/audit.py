"""Read-only G1 artifact audit. Standard library; never imports producer checks."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load(path):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON key: ' + key)
            result[key] = value
        return result
    return json.loads(Path(path).read_text(encoding='utf-8'), object_pairs_hook=pairs,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))


def inside(root, name):
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
    def __init__(self, checkout, evidence):
        self.checkout, self.root = Path(checkout).resolve(), Path(evidence).resolve()
        self.checks, self.artifacts = [], {}

    def read(self, name):
        p = inside(self.root, name)
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
        required = {'opengrep.json', 'opengrep.sarif', 'rules.snapshot.yml'}
        required.update(label + suffix for label in ('version', 'json', 'sarif')
                        for suffix in ('.command.json', '.exit.txt', '.stdout.txt', '.stderr.txt'))
        if not required <= set(m['artifacts']):
            raise ValueError('manifest does not hash all required process artifacts')
        for name, expected in m['artifacts'].items():
            p = inside(self.root / 'engine', name)
            actual = sha(p.read_bytes())
            self.artifacts['engine/' + name] = actual
            if actual != expected:
                raise ValueError('artifact hash mismatch: ' + name)
        for label in ('version', 'json', 'sarif'):
            run = m['runs'][label]
            argv = self.read('engine/' + label + '.command.json')
            if argv != run['argv'] or not argv:
                raise ValueError('command mismatch: ' + label)
            executable = Path(argv[0]).name.lower()
            if executable not in ('opengrep', 'opengrep.exe'):
                raise ValueError('engine executable requires review: ' + executable)
            code = int(inside(self.root, 'engine/' + label + '.exit.txt').read_text())
            if type(run['exit_code']) is not int or code != run['exit_code'] or code != 0:
                raise ValueError('recorded engine failure: ' + label)
            if label != 'version':
                if run.get('output_mode', 'stdout') == 'stdout':
                    if inside(self.root, 'engine/' + label + '.stdout.txt').read_bytes() != inside(self.root, 'engine/opengrep.' + label).read_bytes():
                        raise ValueError('stdout mismatch')
                elif run['output_mode'] == 'file':
                    if argv.count('--output') != 1 or argv[argv.index('--output') + 1] != run['engine_output_path'] or '--' + label not in argv:
                        raise ValueError('file output argv mismatch')
                else:
                    raise ValueError('unsupported output mode')
        if not inside(self.root, 'engine/version.stdout.txt').read_text().strip():
            raise ValueError('empty engine version')
        if not m['success'] or m['issues'] or m['sources_before'] != m['sources_after'] or m['rules_before_sha256'] != m['rules_after_sha256']:
            raise ValueError('unsuccessful capture or changed inputs')
        if sha(inside(self.root, 'engine/rules.snapshot.yml').read_bytes()) != m['rules_before_sha256']:
            raise ValueError('rule hash mismatch')
        return 'unsigned command/hash consistency; engine authenticity needs runtime observation'

    def identity(self):
        raw = inside(self.root, 'input.opengrep.json').read_bytes()
        if raw != inside(self.root, 'engine/opengrep.json').read_bytes():
            raise ValueError('handoff changed raw bytes')
        doc, bundle = self.read('input.opengrep.json'), self.read('evidence.json')
        records = bundle['records']
        if doc.get('errors') or bundle['issues']:
            raise ValueError('scan errors retained: no successful scan acceptance')
        if bundle['scan_sha256'] != sha(raw) or bundle['raw_document'] != doc or len(records) != len(doc['results']):
            raise ValueError('bundle/raw mismatch')
        for index, (finding, record) in enumerate(zip(doc['results'], records)):
            expected = sha((sha(raw) + ':' + str(index)).encode())
            if record['id'] != expected or record['alert_id'] != expected or record['finding_index'] != index or record['scan_sha256'] != sha(raw):
                raise ValueError('finding identity mismatch')
            if record['raw_finding'] != finding or record['raw_trace'] != finding['extra'].get('dataflow_trace'):
                raise ValueError('raw finding/trace lost')
            if record['rule_id'] != finding['check_id'] or record['severity'] != finding['extra']['severity'] or record['cwe'] != finding['extra']['metadata']['cwe']:
                raise ValueError('rule/severity/CWE mismatch')
        return str(len(records)) + ' identities preserved; not security labels'

    def sarif(self):
        doc, sarif = self.read('input.opengrep.json'), self.read('engine/opengrep.sarif')
        left = Counter((r['check_id'], r['path'], r['start']['line'], r['end']['line']) for r in doc['results'])
        right = Counter()
        for run in sarif['runs']:
            for r in run['results']:
                p = r['locations'][0]['physicalLocation']
                right[(r['ruleId'], p['artifactLocation']['uri'], p['region']['startLine'], p['region'].get('endLine', p['region']['startLine']))] += 1
        if left != right:
            raise ValueError('JSON/SARIF finding multiset differs (full rule/path/line)')
        return 'exact multiset; column/severity/CWE SARIF adapter still requires candidate review'

    def sources(self):
        m, bundle = self.read('engine/scan-manifest.json'), self.read('evidence.json')
        root = Path(bundle['root']).resolve(strict=True)
        for name, expected in m['sources_before'].items():
            if sha(inside(root, name).read_bytes()) != expected:
                raise ValueError('STALE_SOURCE: ' + name)
        for rec in bundle['records']:
            for name, snapshot in rec['snapshots'].items():
                if snapshot['sha256'] != m['sources_before'].get(name):
                    raise ValueError('snapshot not bound to scan')
        return 'current source matches captured hashes'

    def rows(self):
        path = inside(self.root, 'assessments.jsonl')
        self.artifacts['assessments.jsonl'] = sha(path.read_bytes())
        return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]

    def database(self):
        path = inside(self.root, 'review.sqlite')
        if Path(str(path) + '-wal').exists() and Path(str(path) + '-wal').stat().st_size:
            raise FileNotFoundError('checkpointed SQLite snapshot required; audit never checkpoints evidence')
        self.artifacts['review.sqlite'] = sha(path.read_bytes())
        rows, bundle = self.rows(), self.read('evidence.json')
        if len(rows) != len(bundle['records']):
            raise ValueError('assessment count mismatch')
        with sqlite3.connect(path.as_uri() + '?mode=ro&immutable=1', uri=True) as db:
            db.row_factory = sqlite3.Row
            warnings = {r['id']: r for r in db.execute('SELECT * FROM warnings')}
            if set(warnings) != {r['id'] for r in bundle['records']}:
                raise ValueError('SQLite warning set mismatch')
            for row, rec in zip(rows, bundle['records']):
                w = warnings[rec['id']]
                if row['id'] != rec['id'] or row['evidence'] != rec or json.loads(w['evidence']) != rec or json.loads(w['assessment']) != row['assessment']:
                    raise ValueError('SQLite/JSONL join mismatch')
                a = row['assessment']
                if a['status'] not in ('SUPPORTED', 'REFUTED', 'UNDETERMINED') or a['requires_human_review'] is not True or a['security_conclusion_verified'] is not False:
                    raise ValueError('model/human separation violated')
                events = list(db.execute('SELECT * FROM events WHERE warning_id=? ORDER BY sequence', (rec['id'],)))
                state = 'OPEN'
                for event in events:
                    state = {'confirm-true': 'CONFIRMED_TRUE', 'confirm-false': 'CONFIRMED_FALSE', 'reopen': 'OPEN'}[event['action']]
                    if not event['actor'].strip() or not event['reason'].strip():
                        raise ValueError('event lacks actor/reason')
                    if event['action'] == 'confirm-false' and json.loads(event['source_version']) != json.loads(event['observed_version']):
                        raise ValueError('false confirmation with stale source')
                if w['state'] != state:
                    raise ValueError('state not justified by human events')
        return 'read-only SQLite state/event replay matches; actors are unauthenticated'

    def runtime(self):
        counts = Counter()
        for row in self.rows():
            a = row['assessment']; r = a.get('runtime', {})
            for field in ('request_attempted', 'http_response_received', 'answer_validated'):
                counts[field] += r.get(field) is True
            counts['mock'] += r.get('origin') == 'mock'
            if a.get('endpoint'):
                from urllib.parse import urlsplit
                url = urlsplit(a['endpoint'])
                if url.scheme != 'http' or url.hostname not in ('127.0.0.1', 'localhost', '::1'):
                    raise ValueError('nonlocal model endpoint')
            if a['status'] != 'UNDETERMINED' and (not r.get('answer_validated') or a.get('citation_check') != 'MATCHED'):
                raise ValueError('conclusive status without validator success')
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
                    counts=dict(Counter(statuses)), artifacts=self.artifacts,
                    verdict='FAIL' if 'FAIL' in statuses else 'INCOMPLETE' if 'INCOMPLETE' in statuses else 'PASS')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--checkout', required=True); p.add_argument('--evidence', required=True)
    p.add_argument('--output', required=True, help='new directory outside checkout/evidence')
    a = p.parse_args(); out = Path(a.output).resolve()
    checkout, evidence = Path(a.checkout).resolve(), Path(a.evidence).resolve()
    if out.is_relative_to(evidence) or out.is_relative_to(checkout):
        p.error('output must be outside inspected checkout and evidence')
    result = Audit(checkout, evidence).run()
    out.mkdir(parents=True, exist_ok=False)
    (out / 'audit.json').write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding='utf-8')
    (out / 'audit.md').write_text('# G1 artifact audit: ' + result['verdict'] + '\n\n' +
        '\n'.join('- ' + c['check'] + ': ' + c['status'] + ' — ' + str(c['detail']) for c in result['checks']), encoding='utf-8')
    print(result['verdict'])
    return {'PASS': 0, 'FAIL': 1, 'INCOMPLETE': 2}[result['verdict']]


if __name__ == '__main__':
    raise SystemExit(main())
