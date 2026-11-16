"""Binary-preserving subprocess receipt runner for runtime acceptance steps.

Executes a single child command without shell interpolation (`shell=False`), persists exact
raw `stdout` and `stderr` byte streams (`*.stdout.bin`, `*.stderr.bin`) and a structured
JSON receipt (`*.receipt.json`) using exclusive (`xb`) file creation so previous logs can
never be silently overwritten, and enforces fail-fast exit-code expectations.
"""
from __future__ import annotations

import argparse
from collections.abc import Sequence
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from typing import Any

MAX_HASHABLE_BINARY_BYTES = 250 * 1024 * 1024
_STEP_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file_bounded(path: Path) -> str | None:
    try:
        if not path.is_file() or path.stat().st_size > MAX_HASHABLE_BINARY_BYTES:
            return None
        h = hashlib.sha256()
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _write_xb(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(payload)


def _resolve_executable(cmd0: str, cwd: Path, env: dict[str, str]) -> Path | None:
    cand = Path(cmd0)
    if cand.is_absolute() and cand.exists():
        return cand.resolve()
    rel_cand = (cwd / cand)
    if (os.sep in cmd0 or (os.altsep and os.altsep in cmd0)) and rel_cand.exists():
        return rel_cand.resolve()
    found = shutil.which(cmd0, path=env.get("PATH"))
    return Path(found).resolve() if found else None


def execute_with_receipt(
    cmd_argv: Sequence[str],
    *,
    receipt_dir: Path,
    step: str,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    expected_exits: Sequence[int] | None = (0,),
) -> dict[str, Any]:
    if not cmd_argv:
        raise ValueError("cmd_argv must contain at least the executable")
    if not _STEP_NAME_RE.fullmatch(step):
        raise ValueError(f"invalid step identifier: {step!r}")

    receipt_dir = Path(receipt_dir).resolve()
    work_cwd = Path(cwd).resolve(strict=True) if cwd is not None else Path.cwd().resolve(strict=True)
    active_env = dict(os.environ if env is None else env)

    stdout_path = receipt_dir / f"{step}.stdout.bin"
    stderr_path = receipt_dir / f"{step}.stderr.bin"
    receipt_path = receipt_dir / f"{step}.receipt.json"
    for target in (stdout_path, stderr_path, receipt_path):
        if target.exists():
            raise FileExistsError(f"refusing to overwrite existing step artifact: {target}")

    argv_list = [str(x) for x in cmd_argv]
    resolved_exe = _resolve_executable(argv_list[0], work_cwd, active_env)
    exe_sha = _sha256_file_bounded(resolved_exe) if resolved_exe is not None else None

    started_utc = _utc_now()
    t0 = time.monotonic()
    proc = subprocess.run(
        argv_list,
        cwd=str(work_cwd),
        env=active_env,
        shell=False,
        capture_output=True,
        text=False,
    )
    elapsed = time.monotonic() - t0
    finished_utc = _utc_now()

    stdout_bytes = bytes(proc.stdout or b"")
    stderr_bytes = bytes(proc.stderr or b"")
    _write_xb(stdout_path, stdout_bytes)
    _write_xb(stderr_path, stderr_bytes)

    allowed = list(expected_exits) if expected_exits is not None else None
    matched = True if allowed is None else (proc.returncode in allowed)

    receipt_doc: dict[str, Any] = {
        "schema": "ntk-process-exec-receipt-1",
        "step": step,
        "argv": argv_list,
        "cwd": str(work_cwd),
        "resolved_executable": str(resolved_exe) if resolved_exe is not None else None,
        "executable_sha256": exe_sha,
        "pythonpath": active_env.get("PYTHONPATH"),
        "started_at_utc": started_utc,
        "finished_at_utc": finished_utc,
        "elapsed_seconds": round(elapsed, 6),
        "exit_code": proc.returncode,
        "expected_exit_codes": allowed,
        "exit_matched_expectation": matched,
        "stdout_raw_file": stdout_path.name,
        "stdout_path": str(stdout_path),
        "stdout_bytes": len(stdout_bytes),
        "stdout_sha256": _sha256_bytes(stdout_bytes),
        "stderr_raw_file": stderr_path.name,
        "stderr_path": str(stderr_path),
        "stderr_bytes": len(stderr_bytes),
        "stderr_sha256": _sha256_bytes(stderr_bytes),
    }
    _write_xb(receipt_path, (json.dumps(receipt_doc, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
    return receipt_doc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Execute a command without shell interpolation and write binary stdout/stderr + JSON receipt"
    )
    parser.add_argument("--receipt-dir", type=Path, required=True, help="Directory for <step>.{stdout.bin,stderr.bin,receipt.json}")
    parser.add_argument("--step", required=True, help="Unique step stem (refuses overwrite if already used)")
    parser.add_argument("--cwd", type=Path, default=None, help="Working directory for child command")
    parser.add_argument(
        "--expect-exit",
        type=int,
        action="append",
        default=None,
        help="Allowed exit code (repeatable; defaults to 0 unless --allow-any-exit is set)",
    )
    parser.add_argument("--allow-any-exit", action="store_true", help="Record child exit code without failing on non-zero")
    parser.add_argument("cmd", nargs=argparse.REMAINDER, help="Command and arguments (precede with '--')")
    args = parser.parse_args(argv)

    cmd_argv = list(args.cmd)
    if cmd_argv and cmd_argv[0] == "--":
        cmd_argv = cmd_argv[1:]
    if not cmd_argv:
        parser.error("missing child command after '--'")

    expected = None if args.allow_any_exit else (args.expect_exit if args.expect_exit else [0])
    receipt = execute_with_receipt(
        cmd_argv,
        receipt_dir=args.receipt_dir,
        step=args.step,
        cwd=args.cwd,
        expected_exits=expected,
    )
    print(json.dumps(receipt, indent=2, ensure_ascii=True))
    if not receipt["exit_matched_expectation"]:
        return receipt["exit_code"] if receipt["exit_code"] != 0 else 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
