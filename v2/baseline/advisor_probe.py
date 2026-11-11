"""Private advisor patch comparison; never vendors the ZIP or its patch into public source."""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

BASE = Path(__file__).resolve().parent
PIN = "2c79a58a16d11e9dea3723e30d2a7faffba7bdc9"


def run(advisor_dir, output, upstream=None, cli_timeout=45):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    workspace = BASE.parents[1]
    git = ["git", "-c", "safe.directory=" + workspace.as_posix(), "-c", "core.autocrlf=false"]
    commands = []
    def execute(label, argv, cwd, env=None, timeout=45):
        try:
            r = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, timeout=timeout)
            code, stdout, stderr = r.returncode, r.stdout, r.stderr
        except (OSError, subprocess.TimeoutExpired) as exc:
            code, stdout, stderr = None, b"", str(exc).encode()
        (output / (label + ".stdout.txt")).write_bytes(stdout)
        (output / (label + ".stderr.txt")).write_bytes(stderr)
        commands.append({"label": label, "argv": [str(x) for x in argv], "cwd": str(cwd), "exit": code})
        return code, stdout
    tree = output / "source"
    if upstream:
        source = Path(upstream).resolve()
        code, sha = execute("upstream-head", git + ["rev-parse", "HEAD"], source)
        code2, status = execute("upstream-clean", git + ["status", "--porcelain"], source)
        if code != 0 or sha.decode().strip() != PIN or code2 != 0 or status.strip():
            raise RuntimeError("supplied upstream must be clean at pinned commit")
        shutil.copytree(source, tree, ignore=shutil.ignore_patterns(".git", ".venv", "node_modules"))
        kind = "copy of clean pinned upstream checkout; caller supplies clone evidence"
    else:
        shutil.copytree(BASE / "upstream", tree)
        entrypoints = BASE / "evidence/pinned-entrypoints"
        if not entrypoints.is_dir():
            raise RuntimeError("supply --upstream clean clone; local pinned entrypoints unavailable")
        for name in ("semgrepai/__init__.py", "semgrepai/__main__.py", "main.py"):
            shutil.copyfile(entrypoints / name, tree / name)
        for provenance_root in (BASE / "upstream", entrypoints):
            manifest = json.loads((provenance_root / "PROVENANCE.json").read_text())
            for item in manifest["files"]:
                data = (provenance_root / item["path"]).read_bytes()
                assert hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() == item["git_blob_sha"]
        kind = "OFFLINE targeted pinned snapshot, NOT a full upstream clone"
    archive = Path(advisor_dir) / "opengrep-triage.zip"
    with zipfile.ZipFile(archive) as z:
        patch = z.read("opengrep-triage/patches/simple_semgrepAI_opengrep.patch")
    patch_path = output / "advisor-private.patch"
    patch_path.write_bytes(patch)
    assert execute("git-init", git + ["init", "--initial-branch=v2/codex-core"], tree)[0] == 0
    assert execute("snapshot-index", git + ["add", "--", "."], tree)[0] == 0
    check, _ = execute("patch-check", git + ["apply", "--check", str(patch_path)], tree)
    applied = None
    if check == 0:
        applied, _ = execute("patch-apply", git + ["apply", str(patch_path)], tree)
    execute("patch-diff-stat", git + ["diff", "--stat"], tree)
    if check != 0 or applied != 0:
        (output / "probe.json").write_text(json.dumps({"source_kind": kind, "upstream_pin": PIN,
            "patch_check_exit": check, "patch_apply_exit": applied,
            "original_cli_help_exit": None, "original_cli_scan_exit": None,
            "refusal": "Never run the original cloud-capable CLI when the local-provider patch failed",
            "commands": commands}, indent=2), encoding="utf-8")
        raise RuntimeError("advisor patch failed; original CLI execution refused")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(tree)
    env["SEMGREP_LOG_FILE"] = str(output / "opengrep.log")
    env["SEMGREP_SETTINGS_FILE"] = str(output / "settings.yml")
    for key in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY"):
        env.pop(key, None)
    help_exit, _ = execute("original-cli-help", [sys.executable, "-m", "semgrepai", "--help"], tree, env, cli_timeout)
    scan_exit, _ = execute("original-cli-scan", [sys.executable, "-m", "semgrepai", "scan",
                          str(BASE / "fixtures/java"), "--rules-path", str(BASE / "rules/java.yml"),
                          "--config-path", str(tree / "semgrepai.yml"), "--output-dir", str(output / "cli-report")], tree, env, cli_timeout)
    # Separate binary compatibility probe, not a successful original-CLI scan.
    engine = []
    for fmt in ("json", "sarif"):
        argv = ["opengrep", "scan", "--timeout", "60", "--jobs", "1", "--dataflow-traces", "--taint-intrafile",
                "--config", str(BASE / "rules/java.yml"), "--disable-version-check", "--no-git-ignore",
                "--" + fmt, "--output", str(output / ("flag-probe." + fmt)), str(BASE / "fixtures/java")]
        engine.append(execute("teacher-flags-" + fmt, argv, tree, env)[0])
    result = {"source_kind": kind, "upstream_pin": PIN, "advisor_zip_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
              "advisor_patch_sha256": hashlib.sha256(patch).hexdigest(), "patch_check_exit": check,
              "patch_apply_exit": applied, "original_cli_help_exit": help_exit, "original_cli_scan_exit": scan_exit,
              "separate_teacher_flag_probe_exits": engine, "commands": commands}
    (output / "probe.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--advisor-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--upstream", type=Path, help="clean full clone at pinned HEAD; otherwise use local offline snapshot")
    parser.add_argument("--cli-timeout", type=float, default=45, help="bound original CLI calls; increase explicitly for a server model")
    args = parser.parse_args()
    r = run(args.advisor_dir, args.output_dir, args.upstream, args.cli_timeout)
    print(json.dumps({k: v for k, v in r.items() if k != "commands"}, indent=2))
