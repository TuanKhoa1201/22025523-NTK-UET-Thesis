"""Reproducible G1 fork builder for pinned hardw00t/simple_semgrepAI (0.2.0 @ 2c79a58a).

Builds a verified 96-file upstream tree + OpenGrep scanner adaptation + bounded G1 CLI bridge
in a fresh output directory outside Git, without touching M1 locked artifacts or upstream cloud/RAG modules.
"""
from __future__ import annotations

import argparse
import ast
import difflib
import hashlib
import json
import os
from pathlib import Path
import subprocess
import zipfile

from v2.g1_integration import UPSTREAM_COMMIT, UPSTREAM_REPO, UPSTREAM_TREE_SHA, UPSTREAM_VERSION

BASE = Path(__file__).resolve().parent
REPO_ROOT = BASE.parents[1]
PIN = UPSTREAM_COMMIT


def validate_checkout_identity(head: str, tree: str, files: dict[str, dict[str, str]], expected: dict | None = None) -> int:
    expected = expected or json.loads((BASE / "pinned_upstream_tree.json").read_text(encoding="utf-8"))
    wanted = {x["path"]: {"mode": x["mode"], "git_blob_sha": x["git_blob_sha"]} for x in expected["files"]}
    if head != PIN or head != expected["upstream_commit"]:
        raise ValueError(f"wrong upstream commit: expected {PIN}, got {head}")
    if tree != expected["tree_sha"] or files != wanted:
        raise ValueError("upstream tree is incomplete or differs from pinned 96-file public inventory")
    return len(wanted)


def prepared_hashes(source: Path) -> dict[str, str]:
    source = Path(source).resolve()
    hashes: dict[str, str] = {}
    for p in sorted(source.rglob("*")):
        if "__pycache__" in p.parts or p.suffix == ".pyc" or not p.is_file():
            continue
        if p.is_symlink() or not p.resolve(strict=True).is_relative_to(source):
            raise ValueError("prepared source escapes source directory")
        hashes[p.relative_to(source).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
    return hashes


def _read_advisor_patch_bytes(advisor_dir: Path | None, advisor_patch: Path | None) -> bytes:
    if advisor_patch is not None:
        p = Path(advisor_patch).resolve(strict=True)
        if p.suffix.lower() == ".zip":
            with zipfile.ZipFile(p) as zf:
                return zf.read("opengrep-triage/patches/simple_semgrepAI_opengrep.patch")
        return p.read_bytes()
    if advisor_dir is None:
        raise ValueError("must provide --advisor-dir or --advisor-patch when scanner_layer='advisor-patch'")
    base = Path(advisor_dir).resolve(strict=True)
    zip_candidate = base / "opengrep-triage.zip"
    if zip_candidate.is_file():
        with zipfile.ZipFile(zip_candidate) as zf:
            return zf.read("opengrep-triage/patches/simple_semgrepAI_opengrep.patch")
    for rel in ("simple_semgrepAI_opengrep.patch", "patches/simple_semgrepAI_opengrep.patch"):
        cand = base / rel
        if cand.is_file():
            return cand.read_bytes()
    raise FileNotFoundError(f"could not locate opengrep-triage.zip or simple_semgrepAI_opengrep.patch in {base}")


def apply_advisor_patch(source: Path, output: Path, advisor_dir: Path | None, advisor_patch: Path | None, git: list[str]) -> bytes:
    """Verify and apply the reference OpenGrep patch onto the clean 96-file upstream copy."""
    patch_bytes = _read_advisor_patch_bytes(advisor_dir, advisor_patch)
    patchfile = output / "advisor-private.patch"
    patchfile.write_bytes(patch_bytes)
    commands = []
    env = os.environ.copy()
    env["GIT_CEILING_DIRECTORIES"] = str(source.parent)
    for flags in (("--check",), ()):
        command = git + ["apply", *flags, str(patchfile)]
        result = subprocess.run(command, cwd=source, env=env, capture_output=True)
        commands.append({
            "argv": command,
            "exit": result.returncode,
            "stdout": result.stdout.decode("utf-8", "replace"),
            "stderr": result.stderr.decode("utf-8", "replace"),
        })
        (output / "patch-results.json").write_text(json.dumps(commands, indent=2), encoding="utf-8")
        if result.returncode != 0:
            raise ValueError("advisor patch failed to apply cleanly onto pinned upstream")
    return patch_bytes


def apply_ntk_cleanroom_scanner_layer(source: Path) -> str:
    """Explicitly labeled fallback for clean servers lacking the private advisor ZIP.

    Adapts pinned upstream MIT `semgrepai/scanner.py` to invoke local OpenGrep with
    `--dataflow-traces` and `--taint-intrafile` so `apply_g1_overlay` can instrument it.
    Never claims `advisor_patch` provenance.
    """
    scanner_path = source / "semgrepai/scanner.py"
    orig = scanner_path.read_text(encoding="utf-8")
    if "def verify_semgrep_installation(self):" not in orig or 'cmd = ["semgrep", "scan"]' not in orig:
        raise ValueError("unexpected pinned upstream scanner.py")
    adapted = orig.replace(
        "import json\n",
        "import json\nimport shutil\nfrom .config import ConfigManager\n",
        1,
    ).replace(
        "    def __init__(self):\n        self.verify_semgrep_installation()\n",
        "    def __init__(self, binary: Optional[str] = None, config_path: Optional[str] = None):\n"
        "        cfg = ConfigManager(config_path).config.semgrep\n"
        "        self.binary = binary or cfg.binary\n"
        "        self.default_rules = list(cfg.default_rules or [])\n"
        "        self.timeout = cfg.timeout\n"
        "        self.jobs = cfg.jobs\n"
        "        self.dataflow_traces = cfg.dataflow_traces\n"
        "        self.taint_intrafile = cfg.taint_intrafile\n"
        "        self.verify_semgrep_installation()\n\n"
        "    @property\n"
        "    def is_opengrep(self) -> bool:\n"
        "        return Path(self.binary).name.lower().startswith('opengrep')\n",
        1,
    ).replace(
        '            result = subprocess.run(["semgrep", "--version"], capture_output=True, text=True, check=True)\n'
        '            console.print(f"[green]✓[/green] Semgrep version: {result.stdout.strip()}")\n',
        '            if not shutil.which(self.binary):\n'
        '                raise RuntimeError(f"{self.binary} is not installed or not in PATH")\n'
        '            result = subprocess.run([self.binary, "--version"], capture_output=True, text=True, check=True)\n'
        '            console.print(f"[green]✓[/green] {self.binary} version: {(result.stdout or result.stderr).strip()}")\n',
        1,
    ).replace(
        '            # Build base command\n'
        '            cmd = ["semgrep", "scan"]\n'
        '            \n'
        '            if rules_path:\n'
        '                cmd.extend(["--config", str(rules_path)])\n'
        '            else:\n'
        '                cmd.append("--config=auto")\n',
        '            cmd = [self.binary, "scan", "--timeout", str(self.timeout)]\n'
        '            if self.jobs:\n'
        '                cmd.extend(["--jobs", str(self.jobs)])\n'
        '            if self.dataflow_traces:\n'
        '                cmd.append("--dataflow-traces")\n'
        '            if self.taint_intrafile and self.is_opengrep:\n'
        '                cmd.append("--taint-intrafile")\n'
        '            if rules_path:\n'
        '                cmd.extend(["--config", str(rules_path)])\n'
        '            else:\n'
        '                raise RuntimeError("Local OpenGrep requires explicit --rules-path")\n',
        1,
    )
    diff = "".join(
        difflib.unified_diff(
            orig.splitlines(keepends=True),
            adapted.splitlines(keepends=True),
            fromfile="a/semgrepai/scanner.py",
            tofile="b/semgrepai/scanner.py",
        )
    )
    scanner_path.write_text(adapted, encoding="utf-8", newline="\n")
    return hashlib.sha256(diff.encode("utf-8")).hexdigest()


G1_BRIDGE_LOADER_SNIPPET = '''import json as _g1_json
import os as _g1_os
import sys as _g1_sys


def _load_g1_bridge():
    env_root = _g1_os.environ.get("NTK_G1_REPO_ROOT")
    if env_root:
        candidate = Path(env_root).resolve()
        if str(candidate) not in _g1_sys.path:
            _g1_sys.path.insert(0, str(candidate))
    else:
        binding = Path(__file__).resolve().parents[2] / "g1_repo_binding.json"
        if binding.is_file():
            doc = _g1_json.loads(binding.read_text(encoding="utf-8"))
            repo_root = doc.get("repo_root")
            if repo_root and str(repo_root) not in _g1_sys.path:
                _g1_sys.path.insert(0, str(repo_root))
    from v2.g1_integration import bridge as _g1_bridge
    return _g1_bridge
'''

G1_REVIEW_COMMANDS_SNIPPET = '''

@app.command(name="queue")
def review_queue(
    db: Path = typer.Option(..., "--db", help="Path to SQLite review database"),
    include_all: bool = typer.Option(False, "--all", help="Include human-confirmed false warnings"),
):
    """List open/confirmed warnings in the local G1 SQLite review queue."""
    argv = ["queue", "--db", str(db)]
    if include_all:
        argv.append("--all")
    raise typer.Exit(_load_g1_bridge().run_review_command_from_cli(argv))


@app.command(name="show")
def review_show(
    warning_id: str = typer.Argument(..., help="Warning/alert SHA-256 identifier"),
    db: Path = typer.Option(..., "--db", help="Path to SQLite review database"),
):
    """Show full evidence, raw/validated Qwen status, and human review state for one warning."""
    raise typer.Exit(_load_g1_bridge().run_review_command_from_cli(["show", "--db", str(db), warning_id]))


@app.command(name="confirm-true")
def review_confirm_true(
    warning_id: str = typer.Argument(..., help="Warning/alert SHA-256 identifier"),
    db: Path = typer.Option(..., "--db", help="Path to SQLite review database"),
    actor: str = typer.Option(..., "--actor", help="Operator identifier recorded in audit log"),
    reason: str = typer.Option(..., "--reason", help="Human review justification"),
):
    """Confirm a warning as a true positive (CONFIRMED_TRUE) in the SQLite queue."""
    raise typer.Exit(
        _load_g1_bridge().run_review_command_from_cli(
            ["confirm-true", "--db", str(db), warning_id, "--actor", actor, "--reason", reason]
        )
    )


@app.command(name="confirm-false")
def review_confirm_false(
    warning_id: str = typer.Argument(..., help="Warning/alert SHA-256 identifier"),
    db: Path = typer.Option(..., "--db", help="Path to SQLite review database"),
    actor: str = typer.Option(..., "--actor", help="Operator identifier recorded in audit log"),
    reason: str = typer.Option(..., "--reason", help="Human review justification"),
):
    """Confirm a warning as a false positive (CONFIRMED_FALSE) after fresh Java SHA-256 check."""
    raise typer.Exit(
        _load_g1_bridge().run_review_command_from_cli(
            ["confirm-false", "--db", str(db), warning_id, "--actor", actor, "--reason", reason]
        )
    )


@app.command(name="reopen")
def review_reopen(
    warning_id: str = typer.Argument(..., help="Warning/alert SHA-256 identifier"),
    db: Path = typer.Option(..., "--db", help="Path to SQLite review database"),
    actor: str = typer.Option(..., "--actor", help="Operator identifier recorded in audit log"),
    reason: str = typer.Option(..., "--reason", help="Reason for reopening warning"),
):
    """Reopen a previously reviewed warning back to OPEN while preserving full event history."""
    raise typer.Exit(
        _load_g1_bridge().run_review_command_from_cli(
            ["reopen", "--db", str(db), warning_id, "--actor", actor, "--reason", reason]
        )
    )


@app.command(name="history")
def review_history(
    warning_id: str = typer.Argument(..., help="Warning/alert SHA-256 identifier"),
    db: Path = typer.Option(..., "--db", help="Path to SQLite review database"),
    include_rejected: bool = typer.Option(False, "--include-rejected", help="Include rejected STALE_SOURCE attempts"),
):
    """Show append-only human decision history for one warning."""
    argv = ["history", "--db", str(db), warning_id]
    if include_rejected:
        argv.append("--include-rejected")
    raise typer.Exit(_load_g1_bridge().run_review_command_from_cli(argv))


@app.command(name="decide")
def review_decide(
    warning_id: str = typer.Argument(..., help="Warning/alert SHA-256 identifier"),
    action: str = typer.Argument(..., help="Decision action: confirm-true, confirm-false, or reopen"),
    db: Path = typer.Option(..., "--db", help="Path to SQLite review database"),
    actor: str = typer.Option(..., "--actor", help="Operator identifier recorded in audit log"),
    reason: str = typer.Option(..., "--reason", help="Human review justification"),
):
    """Compatibility human decision subcommand (confirm-true | confirm-false | reopen)."""
    raise typer.Exit(
        _load_g1_bridge().run_review_command_from_cli(
            ["decide", "--db", str(db), warning_id, action, "--actor", actor, "--reason", reason]
        )
    )
'''


def overlay_cli_g1(original: str) -> str:
    result = original
    for module, name in (
        ("validator", "AIValidator"),
        ("reporter", "HTMLReporter"),
        ("rag", "RAGStore"),
        ("config", "ConfigManager"),
    ):
        line = f"from .{module} import {name}\n"
        if result.count(line) != 1:
            raise ValueError("unexpected pinned CLI imports: " + module)
        result = result.replace(line, "")

    if result.count("from typing import Optional\n") != 1:
        raise ValueError("unexpected pinned CLI typing import")
    result = result.replace("from typing import Optional\n", "from typing import List, Optional\n", 1)

    if result.count("from .scanner import SemgrepScanner\n") != 1:
        raise ValueError("unexpected pinned SemgrepScanner import")
    result = result.replace(
        "from .scanner import SemgrepScanner\n",
        "from .scanner import SemgrepScanner\n"
        "from .scan_recording import recording, record_cli_origin, get_subprocess_invocations, reset_subprocess_invocations\n"
        + G1_BRIDGE_LOADER_SNIPPET,
    )

    signature = '    config_path: Optional[Path] = typer.Option(None, help="Path to configuration file"),\n'
    if result.count(signature) != 1:
        raise ValueError("unexpected pinned scan signature")
    extra_options = (
        '    scan_only: bool = typer.Option(False, "--scan-only", help="M1 mode: local OpenGrep engine only; no RAG or LLM"),\n'
        '    local_triage: bool = typer.Option(False, "--local-triage", help="G1 mode: OpenGrep -> raw JSON/SARIF -> local Qwen -> validator -> SQLite queue"),\n'
        '    executable: Optional[str] = typer.Option(None, "--executable", help="OpenGrep executable name or path"),\n'
        '    endpoint: str = typer.Option("http://127.0.0.1:11434", "--endpoint", help="Loopback HTTP Ollama endpoint"),\n'
        '    model: str = typer.Option("qwen3.5:9b-q4_K_M", "--model", help="Local Qwen model tag in Ollama"),\n'
        '    prompt_contract: str = typer.Option("blind", "--prompt-contract", help="LLM input contract: blind (G1 default) or neutral_hints"),\n'
        '    timeout: float = typer.Option(120.0, "--timeout", help="Per-finding Ollama HTTP timeout in seconds"),\n'
        '    no_llm: bool = typer.Option(False, "--no-llm", help="Skip Ollama calls and record UNDETERMINED in SQLite queue"),\n'
        '    runtime_origin: str = typer.Option("unverified", "--runtime-origin", help="Runtime origin label: unverified or mock"),\n'
        '    path_map: Optional[List[str]] = typer.Option(None, "--path-map", help="Optional explicit POSIX/WSL prefix mapping PREFIX=LOCAL_DIR inside source root"),\n'
    )
    result = result.replace(signature, signature + extra_options)

    needle = '    """Run Semgrep scan with optional custom rules and generate reports."""\n'
    if result.count(needle) != 1:
        raise ValueError("unexpected pinned scan docstring")
    dispatch_guard = '''    if scan_only and local_triage:
        raise typer.BadParameter("Choose either --scan-only or --local-triage, not both")
    if not scan_only and not local_triage:
        raise typer.BadParameter("Local G1 fork requires --scan-only (M1) or --local-triage (G1); upstream RAG/cloud pipeline is disabled")
    if local_triage:
        try:
            _exit_code, _ = _load_g1_bridge().run_local_triage_from_cli(
                cli_file=__file__,
                scanner_cls=SemgrepScanner,
                recording_fn=recording,
                record_cli_origin_fn=record_cli_origin,
                get_invocations_fn=get_subprocess_invocations,
                reset_invocations_fn=reset_subprocess_invocations,
                target_path=target_path,
                rules_path=rules_path,
                output_dir=output_dir,
                config_path=config_path,
                executable=executable,
                endpoint=endpoint,
                model=model,
                prompt_contract=prompt_contract,
                timeout=timeout,
                no_llm=no_llm,
                runtime_origin=runtime_origin,
                path_map=list(path_map or []),
                argv=list(_g1_sys.argv),
            )
        except Exception as _exc:
            console.print(f"[red]G1 local-triage error:[/red] {_exc}")
            raise typer.Exit(2)
        raise typer.Exit(_exit_code)
    if rules_path is None or not rules_path.is_file():
        raise typer.BadParameter("Verification --scan-only mode requires an existing local --rules-path")
'''
    result = result.replace(needle, needle + dispatch_guard)

    orig_block = (
        "        scanner = SemgrepScanner()\n"
        "        results = scanner.scan(target_path, rules_path)\n"
    )
    if result.count(orig_block) != 1:
        raise ValueError("unexpected pinned scanner invocation block")
    scan_only_wrapped = (
        "        target_path = Path(target_path).resolve(strict=True)\n"
        "        rules_path = Path(rules_path).resolve(strict=True)\n"
        "        output_dir = Path(output_dir).resolve()\n"
        '        with recording(target_path, rules_path, output_dir, cli_mode="scan-only"):\n'
        '            record_cli_origin(__file__, SemgrepScanner, "enter", mode="scan-only")\n'
        "            scanner = SemgrepScanner(binary=executable, config_path=str(config_path) if config_path else None)\n"
        "            results = scanner.scan(target_path, rules_path)\n"
        '            record_cli_origin(__file__, SemgrepScanner, "exit", mode="scan-only")\n'
        '            console.print("NTK local verification: original scanner completed; no RAG/LLM invoked")\n'
        "            return\n"
    )
    result = result.replace(orig_block, scan_only_wrapped)

    err_anchor = "\n    except Exception as e:\n"
    if result.count(err_anchor) < 1:
        raise ValueError("unexpected scan exception handler")
    result = result.replace(
        err_anchor,
        "\n    except (typer.Exit, typer.BadParameter):\n        raise\n    except Exception as e:\n",
        1,
    )

    # Disable unrelated upstream cloud/RAG/web commands while keeping original AST intact below raise.
    parsed = ast.parse(result)
    lines = result.splitlines(keepends=True)
    edits = []
    for node in parsed.body:
        if isinstance(node, ast.FunctionDef) and node.name in ("search", "serve", "init_db", "config"):
            body = (
                node.body[1:]
                if isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant)
                else node.body
            )
            edits.append((
                body[0].lineno - 1,
                '    raise typer.BadParameter("Disabled in local G1 fork; no RAG/cloud/web allowed")\n',
            ))
    for index, line in sorted(edits, reverse=True):
        lines.insert(index, line)
    result = "".join(lines)

    main_tail = '\nif __name__ == "__main__":\n    app()\n'
    if not result.endswith('if __name__ == "__main__":\n    app()\n'):
        raise ValueError("unexpected CLI main guard")
    result = result[: -len('if __name__ == "__main__":\n    app()\n')] + G1_REVIEW_COMMANDS_SNIPPET + main_tail
    ast.parse(result)
    return result


def apply_g1_overlay(source: Path, output: Path) -> str:
    """Apply G1 CLI & recording overlay onto the OpenGrep-patched upstream source tree."""
    source, output = Path(source), Path(output)
    changes: list[str] = []

    def write(relative: str, new_text: str) -> None:
        path = source / relative
        old_text = path.read_text(encoding="utf-8") if path.exists() else ""
        changes.extend(
            difflib.unified_diff(
                old_text.splitlines(keepends=True),
                new_text.splitlines(keepends=True),
                fromfile="a/" + relative if path.exists() else "/dev/null",
                tofile="b/" + relative,
            )
        )
        path.write_text(new_text, encoding="utf-8", newline="\n")

    write("semgrepai/cli.py", overlay_cli_g1((source / "semgrepai/cli.py").read_text(encoding="utf-8")))

    scanner = (source / "semgrepai/scanner.py").read_text(encoding="utf-8")
    if scanner.count("from .config import ConfigManager") != 1:
        raise ValueError("expected OpenGrep-patched scanner config import")
    scanner = scanner.replace(
        "from .config import ConfigManager",
        "from .scanner_config import ConfigManager\nfrom .scan_recording import recorded_run, capture_output_dir",
    )
    if scanner.count("subprocess.run(") != 3 or scanner.count('reports_dir = Path("reports")') != 1:
        raise ValueError("unexpected scanner subprocess/output shape")
    scanner = (
        scanner.replace("subprocess.run(", "recorded_run(")
        .replace('reports_dir = Path("reports")', "reports_dir = capture_output_dir()")
        .replace("with open(json_output_file) as f:", 'with open(json_output_file, encoding="utf-8") as f:')
        .replace("with open(sarif_output_file) as f:", 'with open(sarif_output_file, encoding="utf-8") as f:')
    )
    write("semgrepai/scanner.py", scanner)
    write(
        "semgrepai/scanner_config.py",
        (BASE / "fork_support/scanner_config.py").read_text(encoding="utf-8"),
    )
    write(
        "semgrepai/scan_recording.py",
        (BASE / "fork_support/scan_recording.py").read_text(encoding="utf-8"),
    )
    write(
        "semgrepai/scan_manifest.py",
        (BASE / "fork_support/scan_manifest.py").read_text(encoding="utf-8"),
    )
    write(
        "semgrepai/__init__.py",
        '"""NTK G1 integrated fork overlay; upstream package layout preserved."""\n'
        '__version__ = "0.2.0+ntk.g1"\n'
        "def __getattr__(name):\n"
        '    if name == "app":\n'
        "        from .cli import app\n"
        "        return app\n"
        "    raise AttributeError(name)\n",
    )
    overlay_patch_path = output / "g1-integration-overlay.patch"
    overlay_patch_path.write_text("".join(changes), encoding="utf-8", newline="\n")
    return hashlib.sha256(overlay_patch_path.read_bytes()).hexdigest()


def prepare(
    upstream: Path,
    output: Path,
    *,
    advisor_dir: Path | None = None,
    advisor_patch: Path | None = None,
    scanner_layer: str = "advisor-patch",
) -> dict:
    upstream, output = Path(upstream).resolve(), Path(output).resolve()
    if scanner_layer not in ("advisor-patch", "ntk-cleanroom"):
        raise ValueError(f"unsupported scanner_layer: {scanner_layer!r}")
    if not upstream.is_dir():
        raise ValueError(f"full upstream checkout directory is unavailable: {upstream}")

    git = ["git", "-c", "safe.directory=" + upstream.as_posix(), "-c", "core.autocrlf=false"]

    def read_git(*args: str) -> bytes:
        return subprocess.run(git + list(args), cwd=upstream, check=True, capture_output=True).stdout

    head = read_git("rev-parse", "HEAD").decode("utf-8").strip()
    if head != PIN or read_git("status", "--porcelain").strip():
        raise ValueError("full upstream must be clean at exact pinned commit " + PIN)
    tree_sha = read_git("rev-parse", "HEAD^{tree}").decode("utf-8").strip()
    files: dict[str, dict[str, str]] = {}
    for entry in read_git("ls-tree", "-r", "-z", "HEAD").split(b"\0"):
        if not entry:
            continue
        header, name = entry.split(b"\t", 1)
        mode, kind, blob = header.decode("utf-8").split()
        if kind != "blob":
            raise ValueError("unsupported upstream tree entry")
        files[name.decode("utf-8")] = {"mode": mode, "git_blob_sha": blob}

    file_count = validate_checkout_identity(head, tree_sha, files)
    tracked = [p.decode("utf-8") for p in read_git("ls-files", "-z").split(b"\0") if p]
    if set(tracked) != set(files):
        raise ValueError("index does not contain the complete 96-file pinned tree")
    required = {
        "main.py",
        "semgrepai/__init__.py",
        "semgrepai/__main__.py",
        "semgrepai/cli.py",
        "semgrepai/scanner.py",
        "semgrepai/validator.py",
        "semgrepai/rag.py",
    }
    if not required.issubset(tracked):
        raise ValueError("not a full pinned upstream checkout")

    output.mkdir(parents=True, exist_ok=False)
    source = output / "source"
    source.mkdir()
    for relative in tracked:
        src = (upstream / relative).resolve(strict=True)
        if not src.is_relative_to(upstream) or not src.is_file():
            raise ValueError("unsafe tracked upstream source: " + relative)
        dst = source / relative
        dst.parent.mkdir(parents=True, exist_ok=True)
        raw = read_git("show", "HEAD:" + relative)
        if hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() != files[relative]["git_blob_sha"]:
            raise ValueError("upstream blob mismatch: " + relative)
        dst.write_bytes(raw)

    advisor_patch_sha = None
    cleanroom_diff_sha = None
    if scanner_layer == "advisor-patch":
        patch_bytes = apply_advisor_patch(source, output, advisor_dir, advisor_patch, git)
        advisor_patch_sha = hashlib.sha256(patch_bytes).hexdigest()
    else:
        cleanroom_diff_sha = apply_ntk_cleanroom_scanner_layer(source)

    overlay_sha = apply_g1_overlay(source, output)

    # Bind prepared copy outside `source/` so `source/` hashes remain 100% machine-independent!
    (output / "g1_repo_binding.json").write_text(
        json.dumps({"repo_root": str(REPO_ROOT)}, indent=2),
        encoding="utf-8",
    )

    manifest = {
        "schema": "ntk-g1-fork-preparation-1",
        "upstream_repo": UPSTREAM_REPO,
        "upstream_version": UPSTREAM_VERSION,
        "upstream_commit": PIN,
        "upstream_tree_sha": UPSTREAM_TREE_SHA,
        "full_checkout_verified": True,
        "upstream_files_verified": file_count,
        "scanner_layer": scanner_layer,
        "advisor_patch_sha256": advisor_patch_sha,
        "ntk_cleanroom_scanner_diff_sha256": cleanroom_diff_sha,
        "g1_overlay_patch_sha256": overlay_sha,
        "prepared_source_dir": str(source),
        "prepared_files_sha256": prepared_hashes(source),
        "provenance_layers": [
            {"layer": 1, "origin": f"{UPSTREAM_REPO}@{PIN}", "files": 96},
            {
                "layer": 2,
                "origin": (
                    "advisor reference patch simple_semgrepAI_opengrep.patch (private)"
                    if scanner_layer == "advisor-patch"
                    else "NTK cleanroom OpenGrep scanner adaptation (fallback)"
                ),
                "touched_files": (
                    ["pyproject.toml", "semgrepai.yml", "semgrepai/config.py", "semgrepai/scanner.py"]
                    if scanner_layer == "advisor-patch"
                    else ["semgrepai/scanner.py"]
                ),
            },
            {
                "layer": 3,
                "origin": "NTK G1 CLI & local-triage bridge overlay (v2/g1_integration)",
                "touched_files": [
                    "semgrepai/__init__.py",
                    "semgrepai/cli.py",
                    "semgrepai/scanner.py",
                    "semgrepai/scanner_config.py",
                    "semgrepai/scan_recording.py",
                    "semgrepai/scan_manifest.py",
                ],
            },
        ],
    }
    (output / "preparation.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prepare verified G1 simple_semgrepAI fork with OpenGrep + v2.triage bridge")
    parser.add_argument("--upstream", type=Path, required=True, help="Clean clone of hardw00t/simple_semgrepAI at 2c79a58a")
    parser.add_argument("--advisor-dir", type=Path, help="Private directory containing opengrep-triage.zip or patch")
    parser.add_argument("--advisor-patch", type=Path, help="Explicit path to simple_semgrepAI_opengrep.patch or zip")
    parser.add_argument(
        "--scanner-layer",
        choices=("advisor-patch", "ntk-cleanroom"),
        default="advisor-patch",
        help="Scanner patch layer: advisor-patch (default when private pack available) or ntk-cleanroom (fallback)",
    )
    parser.add_argument("--output-dir", type=Path, required=True, help="Fresh private directory to populate")
    args = parser.parse_args(argv)
    manifest = prepare(
        args.upstream,
        args.output_dir,
        advisor_dir=args.advisor_dir,
        advisor_patch=args.advisor_patch,
        scanner_layer=args.scanner_layer,
    )
    print(json.dumps({
        "schema": manifest["schema"],
        "upstream_commit": manifest["upstream_commit"],
        "upstream_files_verified": manifest["upstream_files_verified"],
        "scanner_layer": manifest["scanner_layer"],
        "advisor_patch_sha256": manifest["advisor_patch_sha256"],
        "g1_overlay_patch_sha256": manifest["g1_overlay_patch_sha256"],
        "prepared_source_dir": manifest["prepared_source_dir"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
