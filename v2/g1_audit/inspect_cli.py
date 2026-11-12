"""Static inventory of the inherited CLI route; never substitutes for a runtime receipt."""
import argparse
import ast
from datetime import datetime, timezone
import json
from pathlib import Path
from audit import git, sha
from contracts import require


def inspect(checkout, expected_sha):
    root=Path(checkout).resolve(strict=True)
    require(git(root,'rev-parse','HEAD')==expected_sha,'checkout SHA differs')
    paths=['v2/baseline/upstream/PROVENANCE.json','v2/baseline/upstream/pyproject.toml',
        'v2/baseline/upstream/semgrepai/cli.py','v2/baseline/upstream/semgrepai/scanner.py',
        'v2/baseline/fork/semgrepai/__main__.py','v2/baseline/fork/semgrepai/cli.py',
        'v2/baseline/fork/semgrepai/config.py','v2/baseline/fork/semgrepai/scan_manifest.py',
        'v2/baseline/prepare_upstream_local.py','v2/baseline/upstream_local_support/scan_recording.py',
        'v2/baseline/upstream_local_support/scanner_config.py','v2/triage/cli.py']
    if (root/'v2/g1_integration').is_dir():
        paths.extend(p.relative_to(root).as_posix() for p in (root/'v2/g1_integration').rglob('*.py'))
    files=[]
    for name in paths:
        path=root/name
        if not path.exists():
            files.append(dict(path=name,status='MISSING'));continue
        text=path.read_text(encoding='utf-8-sig')
        item=dict(path=name,sha256=sha(path.read_bytes()),status='READ')
        if path.suffix=='.py':
            parsed=ast.parse(text)
            item['imports']=[dict(line=n.lineno,module=n.module) for n in ast.walk(parsed) if isinstance(n,ast.ImportFrom)]
            item['calls']=[dict(line=n.lineno,call=ast.unparse(n.func)) for n in ast.walk(parsed) if isinstance(n,ast.Call)
                           and any(key in ast.unparse(n.func).lower() for key in ('scanner','triage','subprocess','record','prepare','collect'))]
        files.append(item)
    require(git(root,'rev-parse','HEAD')==expected_sha,'checkout changed')
    return dict(schema='ntk-g1-static-cli-1',timestamp=datetime.now(timezone.utc).isoformat(),reference_sha=expected_sha,
        candidate_sha=None,evidence_kind='STATIC_SOURCE_ONLY',gate_verdict='INCOMPLETE',files=files,
        limitation='Names, imports and call AST do not prove a call executed. Inspect prepared CLI/runtime argv/modules/hash/handoff at candidate SHA.')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--checkout',required=True);p.add_argument('--expected-sha',required=True);p.add_argument('--output',required=True)
    a=p.parse_args();out=Path(a.output).resolve()
    if out.is_relative_to(Path(a.checkout).resolve()):p.error('output inside inspected checkout')
    r=inspect(a.checkout,a.expected_sha)
    with out.open('x',encoding='utf-8') as stream:stream.write(json.dumps(r,ensure_ascii=False,indent=2)+'\n')
    print(r['gate_verdict'])
