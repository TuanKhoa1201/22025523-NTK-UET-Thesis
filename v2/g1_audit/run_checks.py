"""Run bounded synthetic tests at a pinned G1 checkout; preserve exact process receipts."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import time
from audit import git, sha, load
from contracts import require


def now(): return datetime.now(timezone.utc).isoformat()


def guard_checkout(root, expected_sha):
    require(git(root, 'rev-parse', 'HEAD') == expected_sha, 'checkout SHA differs')
    require(git(root, 'rev-parse', '--abbrev-ref', 'HEAD') == 'HEAD', 'detached checkout required')
    require(not git(root, 'status', '--porcelain', '--untracked-files=no'), 'tracked checkout files changed')


def reconcile(receipt, code, log):
    require(receipt['schema'] == 'ntk-unittest-receipt-1', 'invalid unittest receipt schema')
    require(type(receipt['run']) is int and type(receipt['import_errors']) is int and receipt['import_errors'] >= 0
            and type(receipt['successful']) is bool and isinstance(receipt['outcomes'],dict), 'invalid structured test receipt types')
    counts = receipt['counts']
    require(set(counts) == {'PASS','FAIL','ERROR','SKIP','XFAIL','XPASS'} and
            all(type(v) is int and v >= 0 for v in counts.values()), 'invalid test counts')
    require(type(receipt['discovered']) is int and receipt['discovered'] > 0, 'zero tests discovered')
    require(receipt['run'] == receipt['discovered'] == sum(counts.values()) == len(receipt['outcomes']), 'discovered/run/outcome count mismatch')
    require(all(list(receipt['outcomes'].values()).count(k) == v for k,v in counts.items()), 'outcome/summary mismatch')
    announced = re.findall(r'^Ran (\d+) tests? in ', log, re.M)
    require(len(announced) == 1 and int(announced[0]) == receipt['run'], 'log/structured test count mismatch')
    successful = code == 0 and receipt['import_errors'] == 0 and not any(counts[k] for k in ('FAIL','ERROR','XPASS'))
    require(receipt['successful'] is successful, 'exit/summary success mismatch')
    return successful


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--checkout', required=True); p.add_argument('--expected-sha', required=True)
    p.add_argument('--output', required=True)
    args = p.parse_args()
    root, out = Path(args.checkout).resolve(strict=True), Path(args.output).resolve()
    if out.is_relative_to(root): p.error('output must be outside tested checkout')
    try: guard_checkout(root,args.expected_sha)
    except ValueError as exc: p.error(str(exc))
    out.mkdir(parents=True, exist_ok=False)
    started = now(); receipts = []
    env = dict(os.environ, G1_CHECKOUT=str(root), G1_EXPECTED_SHA=args.expected_sha, PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1')
    audit_root = Path(__file__).resolve().parent
    specs = [(audit_root, 'test_candidate.py'), (audit_root, 'test_auditor.py'),
             (audit_root, 'test_deep_audit.py'), (audit_root, 'test_runner.py'),
             (audit_root, 'test_release.py'),
             (root / 'v2/triage/tests', 'test_g0_v22_payload_contract.py'),
             (root / 'v2/triage/tests', 'test_human_review_negative_suite.py')]
    for index, (folder, pattern) in enumerate(specs):
        structured_path = out / f'{index}.unittest.json'
        cmd = [sys.executable, '-X', 'utf8', '-B', str(audit_root / 'unittest_probe.py'),
               '--start', str(folder), '--pattern', pattern, '--receipt', str(structured_path)]
        tick = time.monotonic()
        try:
            proc = subprocess.run(cmd, cwd=root, env=env, capture_output=True, timeout=90)
            code, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as exc:
            code, stdout, stderr = 124, exc.stdout or b'', exc.stderr or b''
        text = stderr.decode('utf-8', errors='replace')
        structured, valid, error = None, False, None
        try:
            structured = load(structured_path)
            valid = reconcile(structured, code, text)
        except (OSError, ValueError, TypeError, KeyError) as exc:
            error = str(exc)
        counts = structured['counts'] if structured else {k:0 for k in ('PASS','FAIL','ERROR','SKIP','XFAIL','XPASS')}
        (out / f'{index}.stdout.txt').write_bytes(stdout); (out / f'{index}.stderr.txt').write_bytes(stderr)
        receipts.append(dict(argv=cmd, cwd=str(root), exit_code=code, counts=counts,
                             structured=structured, reconciled=valid, receipt_error=error,
                             structured_sha256=sha(structured_path.read_bytes()) if structured_path.exists() else None,
                             elapsed_seconds=time.monotonic()-tick, stdout_sha256=sha(stdout), stderr_sha256=sha(stderr),
                             test_file_sha256=sha((folder / pattern).read_bytes())))
    checkout_error = None
    try: guard_checkout(root,args.expected_sha)
    except ValueError as exc: checkout_error = str(exc)
    result = dict(started_at=started, finished_at=now(), tested_sha=args.expected_sha,
                  environment=dict(python=platform.python_version(), platform=platform.platform()),
                  evidence_kind='SYNTHETIC_ONLY_NO_SCANNER_NO_REAL_QWEN', commands=receipts,
                  counts={k:sum(r['counts'][k] for r in receipts) for k in ('PASS','FAIL','ERROR','SKIP','XFAIL','XPASS')},
                  tests_succeeded=checkout_error is None and all(r['reconciled'] for r in receipts),
                  checkout_guard_error=checkout_error,
                  harness_sha256=sha((audit_root / 'unittest_probe.py').read_bytes()),
                  g1_acceptance='INCOMPLETE')
    (out / 'checks.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result['counts'])); return 0 if result['tests_succeeded'] else 1


if __name__ == '__main__': raise SystemExit(main())
