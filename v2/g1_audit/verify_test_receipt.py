"""Recompute test receipt/log consistency without running producer code."""
import argparse
import json
from pathlib import Path
from audit import load, sha
from contracts import require
from run_checks import reconcile


def verify(directory):
    directory=Path(directory).resolve(strict=True); receipt=load(directory/'checks.json')
    totals={k:0 for k in ('PASS','FAIL','ERROR','SKIP','XFAIL','XPASS')}; successes=[]
    require(bool(receipt['commands']), 'empty command receipts')
    for i,command in enumerate(receipt['commands']):
        stdout=(directory/f'{i}.stdout.txt').read_bytes(); stderr=(directory/f'{i}.stderr.txt').read_bytes()
        structured_path=directory/f'{i}.unittest.json'; structured=load(structured_path)
        require(sha(stdout)==command['stdout_sha256'] and sha(stderr)==command['stderr_sha256'], 'test log hash mismatch')
        require(sha(structured_path.read_bytes())==command['structured_sha256'] and structured==command['structured'], 'structured receipt changed')
        require(command['counts']==structured['counts'], 'command/structured counts differ')
        ok=reconcile(structured,command['exit_code'],stderr.decode('utf-8',errors='replace'))
        require(ok is command['reconciled'], 'command success differs')
        successes.append(ok)
        for k in totals: totals[k]+=command['counts'][k]
    require(totals==receipt['counts'], 'aggregate test counts differ')
    expected=receipt.get('checkout_guard_error') is None and all(successes)
    require(receipt['tests_succeeded'] is expected, 'aggregate test success differs')
    return dict(receipts_consistent=True,counts=totals,tests_succeeded=expected,
                limitation='Unsigned local process evidence; synthetic tests do not attest G1 runtime')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('directory');a=p.parse_args()
    try: print(json.dumps(verify(a.directory)));code=0
    except (OSError,ValueError,TypeError,KeyError) as exc:print('FAIL: '+str(exc));code=1
    raise SystemExit(code)
