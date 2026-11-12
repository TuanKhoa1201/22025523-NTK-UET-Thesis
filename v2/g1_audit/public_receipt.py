"""Publish safe derived test receipts, excluding captured stdout/stderr bodies."""
import argparse
import json
from pathlib import Path
import sys
from audit import load, sha


def publish(source, target, repo):
    source, target, repo = Path(source).resolve(), Path(target).resolve(), Path(repo).resolve()
    value = load(source)
    # Only allow the known runner schema fields; never copy arbitrary source payloads.
    result = {k:value[k] for k in ('started_at','finished_at','tested_sha','environment','evidence_kind',
                                  'counts','tests_succeeded','g1_acceptance','harness_sha256')}
    result['private_receipt_sha256'] = sha(source.read_bytes())
    result['commands'] = []
    for command in value['commands']:
        item = {k:command[k] for k in ('exit_code','counts','elapsed_seconds','stdout_sha256','stderr_sha256',
                                      'test_file_sha256','structured_sha256','reconciled')}
        item['argv'] = ['<python>' if x == sys.executable else x.replace(str(repo),'<audit-repo>').replace(repo.as_posix(),'<audit-repo>') for x in command['argv']]
        item['cwd'] = '<pinned-checkout>'
        receipt = command['structured']
        item['discovered'], item['run'], item['import_errors'] = receipt['discovered'],receipt['run'],receipt['import_errors']
        result['commands'].append(item)
    require_parent = target.parent.resolve()
    require_parent.mkdir(exist_ok=True, parents=True)
    with target.open('x',encoding='utf-8',newline='\n') as stream:
        stream.write(json.dumps(result,ensure_ascii=False,indent=2)+'\n')


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',required=True); p.add_argument('--output',required=True); p.add_argument('--repo',required=True)
    a=p.parse_args(); publish(a.source,a.output,a.repo)
