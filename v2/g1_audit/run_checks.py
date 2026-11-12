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
from audit import git, sha


def now(): return datetime.now(timezone.utc).isoformat()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--checkout', required=True); p.add_argument('--expected-sha', required=True)
    p.add_argument('--output', required=True)
    args = p.parse_args()
    root, out = Path(args.checkout).resolve(strict=True), Path(args.output).resolve()
    if out.is_relative_to(root): p.error('output must be outside tested checkout')
    if git(root, 'rev-parse', 'HEAD') != args.expected_sha: p.error('checkout SHA differs')
    if git(root, 'status', '--porcelain', '--untracked-files=no'): p.error('tracked checkout files changed')
    out.mkdir(parents=True, exist_ok=False)
    started = now(); receipts = []
    env = dict(os.environ, G1_CHECKOUT=str(root), PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1')
    audit_root = Path(__file__).resolve().parent
    specs = [(audit_root, 'test_candidate.py'), (audit_root, 'test_auditor.py'),
             (root / 'v2/triage/tests', 'test_g0_v22_payload_contract.py'),
             (root / 'v2/triage/tests', 'test_human_review_negative_suite.py')]
    for index, (folder, pattern) in enumerate(specs):
        cmd = [sys.executable, '-X', 'utf8', '-B', '-m', 'unittest', 'discover', '-s', str(folder), '-p', pattern, '-v']
        tick = time.monotonic()
        try:
            proc = subprocess.run(cmd, cwd=root, env=env, capture_output=True, timeout=90)
            code, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as exc:
            code, stdout, stderr = 124, exc.stdout or b'', exc.stderr or b''
        text = stderr.decode('utf-8', errors='replace')
        counts = dict(PASS=len(re.findall(r'\.\.\. ok\s*$', text, re.M)),
                      FAIL=len(re.findall(r'\.\.\. (?:FAIL|ERROR)\s*$', text, re.M)),
                      SKIP=len(re.findall(r'\.\.\. skipped', text)))
        (out / f'{index}.stdout.txt').write_bytes(stdout); (out / f'{index}.stderr.txt').write_bytes(stderr)
        receipts.append(dict(argv=cmd, cwd=str(root), exit_code=code, counts=counts,
                             elapsed_seconds=time.monotonic()-tick, stdout_sha256=sha(stdout), stderr_sha256=sha(stderr),
                             test_file_sha256=sha((folder / pattern).read_bytes())))
    if git(root, 'rev-parse', 'HEAD') != args.expected_sha or git(root, 'status', '--porcelain', '--untracked-files=no'):
        raise RuntimeError('checkout changed during tests')
    result = dict(started_at=started, finished_at=now(), tested_sha=args.expected_sha,
                  environment=dict(python=platform.python_version(), platform=platform.platform()),
                  evidence_kind='SYNTHETIC_ONLY_NO_SCANNER_NO_REAL_QWEN', commands=receipts,
                  counts={k:sum(r['counts'][k] for r in receipts) for k in ('PASS','FAIL','SKIP')},
                  tests_succeeded=all(r['exit_code']==0 and sum(r['counts'].values())>0 for r in receipts),
                  g1_acceptance='INCOMPLETE')
    (out / 'checks.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result['counts'])); return 0 if result['tests_succeeded'] else 1


if __name__ == '__main__': raise SystemExit(main())
