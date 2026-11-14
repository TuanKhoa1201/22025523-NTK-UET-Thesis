"""Read pinned Git attributes and reproduce BOM parsing in disposable synthetic repos."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import tempfile
from audit import git, sha


def inspect(checkout, output):
    root, out = Path(checkout).resolve(strict=True), Path(output).resolve()
    if out.is_relative_to(root): raise ValueError('output must be outside inspected checkout')
    out.mkdir(parents=True, exist_ok=False)
    events = []
    def run(folder, *args):
        cmd=['git','-c','safe.directory='+folder.as_posix(),'-C',str(folder),*args]
        p=subprocess.run(cmd,capture_output=True)
        events.append(dict(argv=['git','-C','<pinned-checkout>' if folder==root else '<temporary-synthetic-repo>',*args],
            exit_code=p.returncode,stdout=p.stdout.decode('utf-8',errors='replace').strip(),
            stderr=p.stderr.decode('utf-8',errors='replace').strip()))
        return p
    attr='v2/demo/.gitattributes'; raw='v2/demo/smoke_m1_rules_raw.opengrep.json'
    blob=run(root,'show','HEAD:'+attr).stdout
    # The blob body is public metadata; do not include a raw code/scan payload in output.
    events[-1].pop('stdout')
    working=(root/attr).read_bytes()
    commands=[]
    for cached in (False,True):
        p=run(root,'check-attr',*(['--cached'] if cached else []),'-a','--',raw)
        commands.append(dict(cached=cached,exit_code=p.returncode,warning_reproduced=b'is not a valid attribute name' in p.stderr))
    original=run(root,'show','HEAD:'+raw).stdout; events[-1].pop('stdout')
    current=(root/raw).read_bytes()
    controls=[]
    with tempfile.TemporaryDirectory(dir=out, prefix='synthetic-') as tmp:
        temp=Path(tmp).resolve(); assert temp.is_relative_to(out)
        run(temp,'init','--quiet')
        (temp/'probe.json').write_bytes(b'{"synthetic":true}\n')
        comment=b'# synthetic comment (SHA-256: not-a-real-digest)\nprobe.json -text\n'
        for name,data in (('bom',b'\xef\xbb\xbf'+comment),('no_bom',comment)):
            (temp/'.gitattributes').write_bytes(data)
            run(temp,'-c','core.autocrlf=false','add','--','.gitattributes','probe.json')
            p=run(temp,'check-attr','--cached','-a','--','probe.json')
            controls.append(dict(variant=name,warning=b'is not a valid attribute name' in p.stderr,
                                 text_unset=b'text: unset' in p.stdout,exit_code=p.returncode))
    result=dict(schema='ntk-g1-git-attributes-1',timestamp=datetime.now(timezone.utc).isoformat(),
        reference_sha=git(root,'rev-parse','HEAD'),git_version=git(root,'--version'),
        attribute_blob_sha256=sha(blob),attribute_working_sha256=sha(working),
        blob_has_utf8_bom=blob.startswith(b'\xef\xbb\xbf'),working_has_utf8_bom=working.startswith(b'\xef\xbb\xbf'),
        pinned_raw_sha256=sha(original),working_raw_sha256=sha(current),raw_bytes_equal=current==original,
        commands=commands,synthetic_controls=controls,processes=events,
        finding='MINOR: cached Git attribute parser treats BOM-prefixed comment as pattern; -text rule still applied',
        limitation='Observed on this Git version; no production files modified, no proof of unrelated historical transformations')
    (out/'attributes.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    return result


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--checkout',required=True);p.add_argument('--output',required=True)
    a=p.parse_args(); r=inspect(a.checkout,a.output)
    print(json.dumps({k:r[k] for k in ('reference_sha','raw_bytes_equal','synthetic_controls')}))
