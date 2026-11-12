"""Read-only marker/runtime receipt join. Public claims never become raw/runtime attestation."""
import argparse
from datetime import datetime, timezone
import json
import re
from pathlib import Path
from audit import git, load, sha
from contracts import hexhash, require


def runtime_join(receipt, candidate_id, candidate_sha):
    require(isinstance(receipt,dict), 'invalid runtime receipt')
    require(re.fullmatch('[0-9a-f]{40}',candidate_sha) is not None,'invalid candidate SHA')
    require(receipt['candidate_id'] == candidate_id, 'JavisOS candidate_id differs')
    require(receipt['tested_sha'] == candidate_sha, 'JavisOS tested_sha differs from pinned candidate')
    # These fields are a requested delivery checklist, not a guessed producer schema.
    return dict(join='PASS',evidence_level='PUBLIC_RECEIPT_ONLY',javis_tested_sha=receipt['tested_sha'],
        disclosed_keys=sorted(receipt),raw_artifacts_independently_checked=False,runtime_observed=False,
        gate_verdict='INCOMPLETE',limitation='A matching public receipt cannot prove raw artifact integrity or physical inference')


def inspect(checkout, expected_sha, runtime_receipt=None):
    root=Path(checkout).resolve(strict=True)
    actual=git(root,'rev-parse','HEAD')
    require(actual==expected_sha,'checkout SHA differs from expected')
    require(not git(root,'status','--porcelain','--untracked-files=no'),'checkout has tracked changes')
    path=root/'v2/g1_integration/CANDIDATE.json'
    result=dict(schema='ntk-g1-release-inspection-1',timestamp=datetime.now(timezone.utc).isoformat(),
        reference_sha=actual,candidate_sha=None,candidate_id=None,javis_tested_sha=None,
        verdict='INCOMPLETE',reason='CANDIDATE_NOT_AVAILABLE')
    if not path.exists(): return result
    marker=load(path)
    result['marker_sha256']=sha(path.read_bytes()); result['marker_status']=marker['status']
    if marker['status']!='READY_FOR_INDEPENDENT_TEST':
        result['reason']='CANDIDATE_NOT_READY'; return result
    require(isinstance(marker['candidate_id'],str) and bool(marker['candidate_id']),'missing candidate ID')
    result.update(candidate_id=marker['candidate_id'],candidate_sha=actual,reason='CANDIDATE_REQUIRES_GATE_AUDIT')
    if runtime_receipt is not None:
        result['runtime_receipt_sha256']=sha(Path(runtime_receipt).read_bytes())
        result['runtime_join']=runtime_join(load(runtime_receipt),marker['candidate_id'],actual)
        result['javis_tested_sha']=actual
    require(git(root,'rev-parse','HEAD')==actual and not git(root,'status','--porcelain','--untracked-files=no'), 'checkout changed during inspection')
    return result


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--checkout',required=True);p.add_argument('--expected-sha',required=True)
    p.add_argument('--runtime-receipt');p.add_argument('--output',required=True)
    a=p.parse_args()
    output=Path(a.output).resolve()
    if output.is_relative_to(Path(a.checkout).resolve()): p.error('output inside inspected checkout')
    try:
        result=inspect(a.checkout,a.expected_sha,a.runtime_receipt);code=2
    except (ValueError,KeyError,TypeError,OSError) as exc:
        result=dict(verdict='FAIL',reason='INVALID_RELEASE_OR_RUNTIME_RECEIPT',detail=str(exc));code=1
    with output.open('x',encoding='utf-8') as stream: stream.write(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(result['reason']);raise SystemExit(code)
