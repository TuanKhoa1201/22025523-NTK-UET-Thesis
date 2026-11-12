"""Instrument real upstream scanner subprocesses for M1 (--scan-only) and G1 (--local-triage); never synthesize engine outcomes."""
from contextlib import contextmanager
from contextvars import ContextVar
import inspect
import json
from pathlib import Path
import subprocess
import sys
from .scan_manifest import ScanCapture, sha
from .scanner_config import validate_opengrep_binary

_active = ContextVar("ntk_upstream_scan_capture", default=None)
_cli_mode = ContextVar("ntk_upstream_cli_mode", default="scan-only")
_subprocess_invocations = []

FORBIDDEN_UPSTREAM_IMPORTS = (
    "semgrepai.rag",
    "semgrepai.validator",
    "semgrepai.reporter",
    "semgrepai.llm.providers",
    "chromadb",
    "langchain",
    "openai",
    "anthropic",
)


def get_subprocess_invocations():
    return list(_subprocess_invocations)


def reset_subprocess_invocations():
    _subprocess_invocations.clear()


@contextmanager
def recording(target, rules, output, *, cli_mode="scan-only"):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    cap = ScanCapture(target, rules, output, producer="ntk-instrumented-upstream-scanner")
    token = _active.set(cap)
    mode_token = _cli_mode.set(cli_mode)
    try:
        yield cap
    except Exception:
        cap.finish(False)
        raise
    else:
        result = cap.finish(True)
        if not result["success"]:
            raise RuntimeError("source/rules changed during upstream scan; rescan required")
    finally:
        _cli_mode.reset(mode_token)
        _active.reset(token)


def capture_output_dir():
    cap = _active.get()
    if cap is None:
        raise RuntimeError("scanner must run inside local recording context")
    return cap.output / "legacy_reports"


def check_no_forbidden_imports():
    loaded = sorted(
        n for n in sys.modules
        if any(n == b or n.startswith(b + ".") for b in FORBIDDEN_UPSTREAM_IMPORTS)
    )
    if loaded:
        raise RuntimeError("forbidden RAG/cloud/provider import in local CLI: " + ", ".join(loaded))
    return loaded


def record_cli_origin(cli_file, scanner_class, stage, mode=None):
    """Executed inside the inherited CLI scan path, never by standalone triage."""
    cap = _active.get()
    if cap is None:
        raise RuntimeError("CLI origin requires active capture")
    loaded = check_no_forbidden_imports()
    cli = Path(cli_file).resolve()
    scanner = Path(inspect.getsourcefile(scanner_class)).resolve()
    if scanner.parent != cli.parent or cli.name != "cli.py":
        raise RuntimeError("scanner does not belong to this upstream CLI package")
    spec = getattr(sys.modules.get("__main__"), "__spec__", None)
    active_mode = mode or _cli_mode.get()
    (cap.output / "cli-origin.json").write_text(
        json.dumps(
            {
                "stage": stage,
                "cli_mode": active_mode,
                "main_module": getattr(spec, "name", None),
                "argv": list(sys.argv),
                "cli_file": str(cli),
                "scanner_file": str(scanner),
                "cli_sha256": sha(cli.read_bytes()),
                "scanner_sha256": sha(scanner.read_bytes()),
                "function": "semgrepai.cli.scan",
                "forbidden_imports": loaded,
                "producer": "inherited-cli-function-hook",
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def recorded_run(command, **kwargs):
    cap = _active.get()
    if cap is None:
        raise RuntimeError("unrecorded upstream engine execution refused")
    if not isinstance(command, list) or not command:
        raise RuntimeError("invalid engine command list")
    validate_opengrep_binary(command[0])
    label = next((x for x in ("version", "json", "sarif") if "--" + x in command), None)
    if label is None:
        raise RuntimeError("unexpected upstream engine invocation")
    if label in cap.runs:
        raise RuntimeError(f"duplicate OpenGrep {label} invocation within single scan pass refused")
    requested_check = kwargs.pop("check", False)
    result = subprocess.run(command, check=False, **kwargs)
    _subprocess_invocations.append(
        {"label": label, "argv": list(command), "exit_code": result.returncode}
    )
    cap.runs[label] = {"argv": command, "exit_code": result.returncode, "output_mode": "stdout"}
    for name, value in (("stdout", result.stdout or b""), ("stderr", result.stderr or b"")):
        data = value if isinstance(value, bytes) else value.encode("utf-8")
        (cap.output / (label + "." + name + ".txt")).write_bytes(data)
    (cap.output / (label + ".command.json")).write_text(json.dumps(command), encoding="utf-8")
    (cap.output / (label + ".exit.txt")).write_text(str(result.returncode), encoding="utf-8")
    if label in ("json", "sarif") and "--output" in command:
        engine_output = command[command.index("--output") + 1]
        cap.runs[label].update(output_mode="file", engine_output_path=engine_output)
        path = Path(engine_output).resolve()
        if not path.is_relative_to(cap.output):
            raise RuntimeError("engine output outside new capture directory")
        if path.is_file():
            (cap.output / ("opengrep." + label)).write_bytes(path.read_bytes())
    if requested_check:
        result.check_returncode()
    return result
