"""Verify upstream bytes, deterministic patch and actual git-apply round trip."""
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from make_patch import BASE, render_patch


def verify():
    provenance = json.loads((BASE / "upstream/PROVENANCE.json").read_text())
    for entry in provenance["files"]:
        raw = (BASE / "upstream" / entry["path"]).read_bytes()
        assert hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == entry["git_blob_sha"], entry["path"]
    patch = BASE / "opengrep.patch"
    assert patch.read_bytes() == render_patch().encode("utf-8"), "regenerate patch; bytes differ"
    commands = []
    # Outside the repository so git apply operates on a plain source snapshot.
    with tempfile.TemporaryDirectory(prefix="ntk-m1-patch-") as temporary:
        target = Path(temporary)
        shutil.copytree(BASE / "upstream/semgrepai", target / "semgrepai")
        for flags in (("--check",), ()):
            command = ["git", "-c", "safe.directory=" + BASE.parents[1].as_posix(),
                       "-c", "core.autocrlf=false", "apply", *flags, str(patch)]
            result = subprocess.run(command, cwd=target, capture_output=True, text=True)
            commands.append({"command": command, "exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
            assert result.returncode == 0, result.stderr
        for name in ("scanner.py", "config.py", "cli.py"):
            actual = (target / "semgrepai" / name).read_bytes()
            expected = (BASE / "fork/semgrepai" / name).read_bytes().replace(b"\r\n", b"\n")
            assert actual == expected, "applied patch differs from fork: " + name
    return {"status": "PASS", "upstream_files_verified": len(provenance["files"]),
            "patch_sha256": hashlib.sha256(patch.read_bytes()).hexdigest(), "git_apply": commands}


if __name__ == "__main__":
    result = verify()
    (BASE / "evidence/patch-verification.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print("PASS: 6 upstream blobs; deterministic patch; git apply --check/apply matches 3 fork files")
