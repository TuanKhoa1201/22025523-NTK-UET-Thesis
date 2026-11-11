"""Prepare a verified full upstream tree + private teacher patch + bounded local overlay.

Does not install or run RAG/cloud/LLM. Full application acceptance is not implied.
"""
import argparse
import ast
import difflib
import hashlib
import json
import subprocess
import zipfile
from pathlib import Path

BASE = Path(__file__).resolve().parent
PIN = "2c79a58a16d11e9dea3723e30d2a7faffba7bdc9"


def overlay_cli(original):
    result = original
    for module, name in (("validator", "AIValidator"), ("reporter", "HTMLReporter"), ("rag", "RAGStore"), ("config", "ConfigManager")):
        line = f"from .{module} import {name}\n"
        if result.count(line) != 1:
            raise ValueError("unexpected pinned CLI imports: " + module)
        result = result.replace(line, "")
    needle = '    """Run Semgrep scan with optional custom rules and generate reports."""\n'
    if result.count(needle) != 1:
        raise ValueError("unexpected pinned scan function")
    signature = '    config_path: Optional[Path] = typer.Option(None, help="Path to configuration file"),\n'
    result = result.replace(signature, signature + '    scan_only: bool = typer.Option(False, "--scan-only", help="Local engine only; no RAG or LLM"),\n')
    result = result.replace(needle, needle + '''    if not scan_only or rules_path is None or not rules_path.is_file():
        raise typer.BadParameter("Verification overlay requires --scan-only and an existing local --rules-path")
''')
    result = result.replace("scanner = SemgrepScanner()", "scanner = SemgrepScanner(config_path=str(config_path) if config_path else None)")
    call = "        results = scanner.scan(target_path, rules_path)\n"
    if result.count(call) != 1:
        raise ValueError("unexpected original scanner call")
    result = result.replace(call, call + '''        console.print("NTK local verification: original scanner completed; no RAG/LLM invoked")
        return
''')
    result = result.replace("from .scanner import SemgrepScanner\n", "from .scanner import SemgrepScanner\nfrom .scan_recording import recording\n")
    block = "        scanner = SemgrepScanner(config_path=str(config_path) if config_path else None)\n" + call
    wrapped = "        with recording(target_path, rules_path, output_dir):\n" + "".join("    " + line for line in block.splitlines(keepends=True))
    if result.count(block) != 1:
        raise ValueError("unexpected upstream scan initialization")
    result = result.replace(block, wrapped)
    # Keep the original implementation for comparison, but make unrelated commands unreachable.
    parsed = ast.parse(result)
    lines = result.splitlines(keepends=True)
    edits = []
    for node in parsed.body:
        if isinstance(node, ast.FunctionDef) and node.name in ("search", "serve", "init_db", "config"):
            body = node.body[1:] if isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant) else node.body
            edits.append((body[0].lineno - 1, '    raise typer.BadParameter("Disabled in local verification overlay; no RAG/cloud/web allowed")\n'))
    for index, line in sorted(edits, reverse=True):
        lines.insert(index, line)
    result = "".join(lines)
    ast.parse(result)
    return result


def prepare(upstream, advisor, output):
    upstream, output = Path(upstream).resolve(), Path(output).resolve()
    workspace = BASE.parents[1].as_posix()
    git = ["git", "-c", "safe.directory=" + workspace, "-c", "core.autocrlf=false"]
    def read_git(*args):
        return subprocess.run(git + list(args), cwd=upstream, check=True, capture_output=True).stdout
    if read_git("rev-parse", "HEAD").decode().strip() != PIN or read_git("status", "--porcelain").strip():
        raise ValueError("full upstream must be clean at exact pinned commit")
    tracked = [p.decode("utf-8") for p in read_git("ls-files", "-z").split(b"\0") if p]
    required = {"main.py", "semgrepai/__init__.py", "semgrepai/__main__.py", "semgrepai/cli.py", "semgrepai/scanner.py", "semgrepai/validator.py", "semgrepai/rag.py"}
    if not required.issubset(tracked):
        raise ValueError("not a full pinned upstream checkout")
    output.mkdir(parents=True, exist_ok=False)
    source = output / "source"
    source.mkdir()
    for relative in tracked:
        src = (upstream / relative).resolve(strict=True)
        if not src.is_relative_to(upstream) or not src.is_file():
            raise ValueError("unsafe tracked upstream source")
        dst = source / relative
        dst.parent.mkdir(parents=True, exist_ok=True)
        # Object bytes avoid Windows checkout CRLF conversion changing patch context.
        dst.write_bytes(read_git("show", "HEAD:" + relative))
    with zipfile.ZipFile(Path(advisor) / "opengrep-triage.zip") as z:
        patch = z.read("opengrep-triage/patches/simple_semgrepAI_opengrep.patch")
    patchfile = output / "advisor-private.patch"
    patchfile.write_bytes(patch)
    commands = []
    for flags in (("--check",), ()):
        command = git + ["apply", *flags, str(patchfile)]
        # Disable repository discovery above the plain copied tree.
        import os
        env = os.environ.copy()
        env["GIT_CEILING_DIRECTORIES"] = str(source.parent)
        result = subprocess.run(command, cwd=source, env=env, capture_output=True)
        commands.append({"argv": command, "exit": result.returncode,
                         "stdout": result.stdout.decode("utf-8", "replace"), "stderr": result.stderr.decode("utf-8", "replace")})
        (output / "patch-results.json").write_text(json.dumps(commands, indent=2), encoding="utf-8")
        if result.returncode:
            raise ValueError("advisor patch failed; do not run upstream")
    overlay_sha = apply_local_overlay(source, output)
    manifest = {"upstream_commit": PIN, "full_checkout_verified": True,
                "advisor_patch_sha256": hashlib.sha256(patch).hexdigest(),
                "scope": "upstream Typer scan function and advisor-patched scanner; --scan-only only; not full RAG/LLM acceptance",
                "overlay_sha256": overlay_sha}
    (output / "preparation.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def apply_local_overlay(source, output):
    """Apply NTK code only. This function does NOT verify a checkout or claim full source."""
    source, output = Path(source), Path(output)
    changes = []
    def write(relative, new):
        path = source / relative
        old = path.read_text(encoding="utf-8") if path.exists() else ""
        changes.extend(difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True),
            fromfile="a/" + relative if path.exists() else "/dev/null", tofile="b/" + relative))
        path.write_text(new, encoding="utf-8", newline="\n")
    write("semgrepai/cli.py", overlay_cli((source / "semgrepai/cli.py").read_text(encoding="utf-8")))
    scanner = (source / "semgrepai/scanner.py").read_text(encoding="utf-8")
    if scanner.count("from .config import ConfigManager") != 1:
        raise ValueError("expected advisor-patched scanner config import")
    scanner = scanner.replace("from .config import ConfigManager", "from .scanner_config import ConfigManager\nfrom .scan_recording import recorded_run, capture_output_dir")
    if scanner.count("subprocess.run(") != 3 or scanner.count('reports_dir = Path("reports")') != 1:
        raise ValueError("unexpected advisor scanner subprocess/output shape")
    scanner = scanner.replace("subprocess.run(", "recorded_run(").replace('reports_dir = Path("reports")', "reports_dir = capture_output_dir()")
    write("semgrepai/scanner.py", scanner)
    write("semgrepai/scanner_config.py", (BASE / "upstream_local_support/scanner_config.py").read_text(encoding="utf-8"))
    write("semgrepai/scan_recording.py", (BASE / "upstream_local_support/scan_recording.py").read_text(encoding="utf-8"))
    write("semgrepai/scan_manifest.py", (BASE / "fork/semgrepai/scan_manifest.py").read_text(encoding="utf-8"))
    write("semgrepai/__init__.py", '''"""NTK local verification overlay; upstream implementation remains in this tree."""
__version__ = "0.1.0"
def __getattr__(name):
    if name == "app":
        from .cli import app
        return app
    raise AttributeError(name)
''')
    (output / "ntk-local-overlay.patch").write_text("".join(changes), encoding="utf-8", newline="\n")
    return hashlib.sha256((output / "ntk-local-overlay.patch").read_bytes()).hexdigest()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--advisor-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    a = parser.parse_args()
    print(json.dumps(prepare(a.upstream, a.advisor_dir, a.output_dir), indent=2))
