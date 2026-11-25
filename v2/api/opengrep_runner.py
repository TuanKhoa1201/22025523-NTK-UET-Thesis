"""Bounded OpenGrep execution for v2.api scan jobs (Windows/WSL2-safe).

The sealed baseline scanner (`v2/baseline/fork/semgrepai/scanner.py`, pinned by `verify_patch.py`)
runs each engine command with `subprocess.run(capture_output=True, timeout=config.timeout + 30)`.
On Windows that call only kills the direct child on timeout and then performs an unbounded
`communicate()`, so a wrapper chain such as `opengrep.cmd -> python.exe -> wsl.exe` whose descendants
inherit stdout/stderr can keep the scan job blocked long after the timeout (observed in Windows wrapper
environments where a 90 s timeout surfaced only after several minutes in stage 2).

This module does not modify the sealed scanner. It subclasses it at runtime and replaces only the
process execution inside `_run`, reusing the audited process-tree runner from `v2.api.intake`
(suspended start + KILL_ON_JOB_CLOSE Job Object before any code runs, output to temporary files,
verified termination, fail-closed pending registry). Timeout bound, capture files
(`<label>.command.json`, `.stdout.txt`, `.stderr.txt`, `.exit.txt`, `.failure.txt`), `capture.runs`,
exit-code handling and UTF-8 decoding are kept identical to the baseline.
"""
from __future__ import annotations

import ast
from collections.abc import Callable
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import struct
import sys
import tempfile
import threading
import time
from typing import Any
import uuid
import yaml

from v2.api import intake
from v2.g1_integration.fork_support.scanner_config import validate_opengrep_binary
from v2.triage.evidence import EvidenceError, digest, now, strict_json

# Cap for each captured OpenGrep stream; exceeding it fails the step instead of truncating JSON/SARIF.
MAX_OPENGREP_OUTPUT_BYTES = 256 * 1024 * 1024
MAX_HEALTH_PROBE_VERSION_OUTPUT_BYTES = 64 * 1024
MAX_HEALTH_PROBE_SCAN_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_HEALTH_PROBE_WSL_ID_OUTPUT_BYTES = 16 * 1024
_MAX_WRAPPER_INSPECT_BYTES = 256 * 1024
_MAX_CHAIN_DEPTH = 4
_MAX_CHAIN_FILES = 64
_WRAPPER_SUFFIXES = frozenset({".cmd", ".bat", ".sh", ".ps1", ".py"})
_WRAPPER_SCRIPT_SUFFIXES = (".py", ".sh", ".cmd", ".bat", ".ps1")
_INTERPRETER_SUFFIXES = (".exe",)

_OPENGREP_VERSION_RE = re.compile(
    r"^(?:opengrep\s+)?(\d+)\.(\d+)\.(\d+)(?:[-+][A-Za-z0-9._-]+)?$",
    re.IGNORECASE,
)
_CWE_CODE_RE = re.compile(r"CWE[-_]?0*(\d+)", re.IGNORECASE)
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_CANARY_CWES: tuple[str, ...] = ("CWE-22", "CWE-89")
_PRIORITY_CWES = frozenset(REQUIRED_CANARY_CWES)

HEALTH_CANARY_FILENAME = "OpenGrepHealthCanary.java"
HEALTH_CANARY_SQL_SOURCE_LINE = 9
HEALTH_CANARY_SQL_LINE = 10
HEALTH_CANARY_PATH_SOURCE_LINE = 14
HEALTH_CANARY_PATH_LINE = 15
HEALTH_CANARY_SAFE_SQL_LINES = frozenset({18, 19, 20})
HEALTH_CANARY_SAFE_PATH_LINES = frozenset({22, 23, 24})
HEALTH_CANARY_SAFE_LINES = HEALTH_CANARY_SAFE_SQL_LINES | HEALTH_CANARY_SAFE_PATH_LINES
HEALTH_CANARY_SOURCE = (
    "package ntk.health;\n"
    "\n"
    "import java.io.FileInputStream;\n"
    "import java.sql.Statement;\n"
    "import javax.servlet.http.HttpServletRequest;\n"
    "\n"
    "public class OpenGrepHealthCanary {\n"
    "    public void sqlProbe(HttpServletRequest req, Statement st) throws Exception {\n"
    '        String id = req.getParameter("id");\n'
    '        st.executeQuery("SELECT * FROM users WHERE id=" + id);\n'
    "    }\n"
    "\n"
    "    public void pathProbe(HttpServletRequest req) throws Exception {\n"
    '        String name = req.getParameter("file");\n'
    '        new FileInputStream("/srv/data/" + name);\n'
    "    }\n"
    "\n"
    "    public void safeProbe(Statement st) throws Exception {\n"
    '        st.executeQuery("SELECT 1");\n'
    "    }\n"
    "\n"
    "    public void safePathProbe() throws Exception {\n"
    '        new FileInputStream("/srv/data/static-template.txt");\n'
    "    }\n"
    "}\n"
)
HEALTH_CANARY_SHA256 = hashlib.sha256(HEALTH_CANARY_SOURCE.encode("utf-8")).hexdigest()


_PE_SUPPORTED_MACHINES = frozenset({0x014C, 0x8664, 0xAA64, 0x01C4})
_MACHO_MAGICS = frozenset({
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
})
_PYINSTALLER_COOKIE = b"MEI\x0c\x0b\x0a\x0b\x0e"


def _is_verified_native_executable_file(resolved_path: Path) -> bool:
    """Positively verify that `resolved_path` is a native compiled executable binary, not a script or launcher shim.

    This checks platform binary headers and rejects:
    - Shebang scripts (`#!`), text/batch/PowerShell/Python wrappers, and dummy/corrupt `.exe` files.
    - DLLs or truncated/malformed PE/ELF/Mach-O headers.
    - Windows `distlib`/`pip`/`setuptools` console-script launcher shims (PE with `#!`/ZIP overlay)
      and PyInstaller single-file wrapper bundles.
    """
    try:
        if not resolved_path.is_file():
            return False
        file_size = resolved_path.stat().st_size
        if file_size < 64:
            return False
        with resolved_path.open("rb") as fh:
            head = fh.read(64)
            if len(head) < 64 or head.startswith(b"#!"):
                return False

            if os.name == "nt":
                if resolved_path.suffix.lower() != ".exe":
                    return False
                if head[:2] != b"MZ":
                    return False
                e_lfanew = struct.unpack_from("<I", head, 60)[0]
                if e_lfanew < 64 or e_lfanew + 24 > file_size:
                    return False
                fh.seek(e_lfanew)
                pe_hdr = fh.read(24)
                if len(pe_hdr) < 24 or pe_hdr[:4] != b"PE\x00\x00":
                    return False
                machine, num_sections, _ts, _sym, _nsym, opt_size, chars = struct.unpack_from("<HHIIIHH", pe_hdr, 4)
                if machine not in _PE_SUPPORTED_MACHINES or num_sections < 1 or opt_size < 2:
                    return False
                # Must be an executable image (0x0002) and NOT a DLL (0x2000).
                if not (chars & 0x0002) or (chars & 0x2000):
                    return False
                opt_off = e_lfanew + 24
                sec_table_off = opt_off + opt_size
                if sec_table_off + num_sections * 40 > file_size:
                    return False
                opt = fh.read(opt_size)
                if len(opt) < opt_size:
                    return False
                opt_magic = struct.unpack_from("<H", opt, 0)[0]
                if opt_magic == 0x010B:
                    num_rva_off, dd_off = 92, 96
                elif opt_magic == 0x020B:
                    num_rva_off, dd_off = 108, 112
                else:
                    return False
                cert_off = 0
                cert_size = 0
                if opt_size >= dd_off + 5 * 8:
                    num_rva = struct.unpack_from("<I", opt, num_rva_off)[0]
                    if num_rva > 4:
                        cert_off, cert_size = struct.unpack_from("<II", opt, dd_off + 4 * 8)

                max_raw_end = 0
                has_exec_code_section = False
                for _ in range(num_sections):
                    sh = fh.read(40)
                    if len(sh) < 40:
                        return False
                    raw_size, raw_ptr = struct.unpack_from("<II", sh, 16)
                    sec_chars = struct.unpack_from("<I", sh, 36)[0]
                    if raw_size > 0:
                        sec_end = raw_ptr + raw_size
                        if sec_end > file_size:
                            return False
                        if sec_end > max_raw_end:
                            max_raw_end = sec_end
                        if sec_chars & 0x20000000:
                            has_exec_code_section = True
                if not has_exec_code_section or max_raw_end == 0 or max_raw_end > file_size:
                    return False

                overlay_size = file_size - max_raw_end
                if overlay_size > 0:
                    fh.seek(max_raw_end)
                    overlay_head = fh.read(min(64, overlay_size))
                    if overlay_head.startswith(b"#!") or overlay_head.startswith(b"PK\x03\x04"):
                        return False
                    aligned_end = (max_raw_end + 7) & ~7
                    if not (
                        cert_size > 0
                        and max_raw_end <= cert_off <= aligned_end
                        and cert_off + cert_size == file_size
                    ):
                        return False
                    if cert_off > max_raw_end and any(b != 0 for b in overlay_head[: cert_off - max_raw_end]):
                        return False

                tail_len = min(file_size, 65560)
                fh.seek(file_size - tail_len)
                tail = fh.read(tail_len)
                if _PYINSTALLER_COOKIE in tail:
                    return False
                return True

            if sys.platform.startswith("linux"):
                if head[:4] != b"\x7fELF" or head[4] not in (1, 2) or head[5] not in (1, 2):
                    return False
                endian = "<" if head[5] == 1 else ">"
                e_type = struct.unpack_from(f"{endian}H", head, 16)[0]
                if e_type not in (2, 3):  # ET_EXEC or ET_DYN
                    return False
                tail_len = min(file_size, 65560)
                fh.seek(file_size - tail_len)
                tail = fh.read(tail_len)
                if _PYINSTALLER_COOKIE in tail or b"PK\x05\x06" in tail:
                    return False
                return True

            if sys.platform == "darwin":
                if head[:4] not in _MACHO_MAGICS:
                    return False
                tail_len = min(file_size, 65560)
                fh.seek(file_size - tail_len)
                tail = fh.read(tail_len)
                if _PYINSTALLER_COOKIE in tail or b"PK\x05\x06" in tail:
                    return False
                return True

            return False
    except (OSError, struct.error):
        return False


def make_bounded_scanner_class(base_scanner_cls: type, scan_error_cls: type) -> type:
    """Build a SemgrepScanner subclass whose engine subprocesses are time-bounded as a process tree."""

    class OpenGrepRunError(scan_error_cls):  # type: ignore[misc, valid-type]
        def __init__(self, error_code: str, message: str, details: dict[str, Any] | None = None):
            super().__init__(message)
            self.error_code = error_code
            self.details = dict(details or {})

    class BoundedOpenGrepScanner(base_scanner_cls):  # type: ignore[misc, valid-type]
        RunError = OpenGrepRunError

        def __init__(
            self,
            config=None,
            output_dir="reports",
            *,
            deadline_mono: float | None = None,
            enable_single_pass_dual_output: bool = True,
            wsl_single_pass_verified: bool = False,
        ):
            super().__init__(config, output_dir)
            self.deadline_mono = deadline_mono
            self.enable_single_pass_dual_output = bool(enable_single_pass_dual_output)
            self.wsl_single_pass_verified = bool(wsl_single_pass_verified)
            self.last_timing: dict[str, Any] = {}

        def _process_timeout(self) -> float:
            # Same bound as the sealed baseline scanner; deliberately not increased.
            return self.config.timeout + 30

        def _write_failure(self, label: str, payload: dict[str, Any]) -> None:
            (self.output_dir / (label + ".failure.txt")).write_text(
                json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
            )

        def _check_deadline_before_step(self, label: str) -> None:
            if self.deadline_mono is not None and time.monotonic() >= self.deadline_mono:
                details = {"engine_step": label, "reason": "job_deadline_exceeded"}
                message = f"{label}: vượt quá giới hạn thời gian tổng của job (JOB_TIMEOUT) trước khi chạy OpenGrep."
                self._write_failure(label, {"error_code": "JOB_TIMEOUT", "message": message, **details})
                raise OpenGrepRunError("JOB_TIMEOUT", message, details)

        def _evaluate_single_pass_capability(self, executable: str) -> tuple[bool, str]:
            """Allow single-pass `--sarif-output` only on positively verified native binaries or verified WSL bridges.

            Executable identity verification (`found=True`) does NOT prove native single-pass capability:
            - Fingerprinted wrappers (bridge scripts, wrapper interpreters, script suffixes, or non-native/shim
              binaries) and unresolved execution chains default conservatively to two-pass stdout
              (`WRAPPER_SINGLE_PASS_CAPABILITY_NOT_VERIFIED`).
            - WSL2 bridges require both a complete verified WSL identity AND explicit
              `wsl_single_pass_verified=True` (default `False` -> `WSL_SINGLE_PASS_CAPABILITY_NOT_VERIFIED`).
            """
            if not self.enable_single_pass_dual_output:
                return False, "DISABLED_BY_CALLER"
            ident = inspect_opengrep_binary_identity(str(executable))
            wsl_target = ident.get("wsl_target") if isinstance(ident.get("wsl_target"), dict) else {}
            failure_code = str(ident.get("failure_code") or "")
            is_wsl_bridge = bool(wsl_target.get("detected")) or failure_code.startswith("WSL_")
            if is_wsl_bridge:
                if (
                    self.wsl_single_pass_verified
                    and ident.get("found") is True
                    and ident.get("identity_complete") is True
                    and bool(wsl_target.get("detected"))
                    and not ident.get("chain_issues")
                ):
                    return True, "WSL_SINGLE_PASS_VERIFIED"
                return False, "WSL_SINGLE_PASS_CAPABILITY_NOT_VERIFIED"

            if (
                ident.get("found") is not True
                or ident.get("binary_exists") is not True
                or ident.get("identity_complete") is not True
                or bool(ident.get("chain_issues"))
                or bool(failure_code)
            ):
                return False, "WRAPPER_SINGLE_PASS_CAPABILITY_NOT_VERIFIED"

            if ident.get("wrapper_targets") or ident.get("wrapper_interpreters"):
                return False, "WRAPPER_SINGLE_PASS_CAPABILITY_NOT_VERIFIED"

            resolved_raw = ident.get("resolved_path")
            if not isinstance(resolved_raw, str) or not resolved_raw.strip():
                return False, "WRAPPER_SINGLE_PASS_CAPABILITY_NOT_VERIFIED"
            resolved_path = Path(resolved_raw)
            if resolved_path.suffix.lower() in _WRAPPER_SUFFIXES:
                return False, "WRAPPER_SINGLE_PASS_CAPABILITY_NOT_VERIFIED"

            if not _is_verified_native_executable_file(resolved_path):
                return False, "WRAPPER_SINGLE_PASS_CAPABILITY_NOT_VERIFIED"

            return True, "NATIVE_SINGLE_PASS_ELIGIBLE"

        @staticmethod
        def _build_dual_output_command(json_cmd: list[str], sarif_out_path: Path) -> list[str]:
            """Insert `--sarif-output <path>` as two tokens right after `--json`, keeping target as args[-1]."""
            cmd = list(json_cmd)
            try:
                idx = cmd.index("--json") + 1
            except ValueError:
                idx = max(1, len(cmd) - 1)
            cmd[idx:idx] = ["--sarif-output", str(sarif_out_path)]
            return cmd

        @staticmethod
        def _stderr_rejects_sarif_output(stderr_bytes: bytes) -> bool:
            low = stderr_bytes.decode("utf-8", errors="replace").lower()
            return "sarif-output" in low and any(
                tok in low for tok in ("unknown", "unrecognized", "invalid", "unexpected", "no such option")
            )

        def _scan_outputs(self, target_path, config):
            t_total0 = time.monotonic()
            self._check_deadline_before_step("version")
            t_ver0 = time.monotonic()
            version = self.verify_semgrep_installation()
            version_ms = round((time.monotonic() - t_ver0) * 1000.0, 2)

            use_single_pass, sp_capability = self._evaluate_single_pass_capability(config.executable)
            results: dict[str, Any] = {}
            single_pass_used = False
            fallback_to_two_pass = False
            json_ms: float | None = None
            sarif_ms: float | None = None

            base_json_cmd = list(config.command(target_path, "json"))
            out_dir_resolved = self.output_dir.resolve()
            sarif_stage_path = out_dir_resolved / ".opengrep.singlepass.sarif.tmp"
            if sarif_stage_path.exists() or sarif_stage_path.is_symlink():
                try:
                    sarif_stage_path.unlink()
                except OSError:
                    pass

            try:
                self._check_deadline_before_step("json")
                if use_single_pass:
                    dual_cmd = self._build_dual_output_command(base_json_cmd, sarif_stage_path)
                    t_j0 = time.monotonic()
                    try:
                        raw_json = self._run("json", dual_cmd)
                    except OpenGrepRunError:
                        # Never fallback on timeout, cancellation, cleanup failure, output limit, or process isolation error.
                        raise
                    except scan_error_cls:
                        stderr_p = self.output_dir / "json.stderr.txt"
                        stderr_b = stderr_p.read_bytes() if stderr_p.is_file() else b""
                        if not self._stderr_rejects_sarif_output(stderr_b):
                            raise
                        self._check_deadline_before_step("json")
                        fallback_to_two_pass = True
                        raw_json = self._run("json", base_json_cmd)
                    json_ms = round((time.monotonic() - t_j0) * 1000.0, 2)
                else:
                    t_j0 = time.monotonic()
                    raw_json = self._run("json", base_json_cmd)
                    json_ms = round((time.monotonic() - t_j0) * 1000.0, 2)

                (self.output_dir / "opengrep.json").write_bytes(raw_json.encode("utf-8"))
                try:
                    results["json"] = json.loads(raw_json)
                except (ValueError, TypeError) as exc:
                    raise scan_error_cls("invalid json; REVIEW required") from exc

                # If single-pass mode was executed and the engine created the staged `--sarif-output` file,
                # validate it fail-closed (never fall back to hide empty/corrupt/symlink/oversized SARIF output).
                stage_touched = use_single_pass and not fallback_to_two_pass and (
                    sarif_stage_path.is_symlink() or sarif_stage_path.exists()
                )
                if stage_touched:
                    if sarif_stage_path.is_symlink():
                        raise scan_error_cls("sarif-output stage file must not be a symlink; REVIEW required")
                    resolved_stage = sarif_stage_path.resolve(strict=True)
                    if (
                        resolved_stage.is_symlink()
                        or not resolved_stage.is_relative_to(out_dir_resolved)
                        or not resolved_stage.is_file()
                    ):
                        raise scan_error_cls("sarif-output stage file escaped output directory; REVIEW required")
                    sarif_size = resolved_stage.stat().st_size
                    if sarif_size > MAX_OPENGREP_OUTPUT_BYTES:
                        details = {
                            "engine_step": "sarif",
                            "output_stream": "sarif_output_file",
                            "output_bytes": sarif_size,
                            "limit_bytes": MAX_OPENGREP_OUTPUT_BYTES,
                        }
                        msg = (
                            f"sarif: đầu ra OpenGrep (--sarif-output) vượt giới hạn {MAX_OPENGREP_OUTPUT_BYTES} byte; "
                            "không ghi kết quả bị cắt."
                        )
                        self._write_failure("sarif", {"error_code": "OPENGREP_OUTPUT_LIMIT_EXCEEDED", "message": msg, **details})
                        raise OpenGrepRunError("OPENGREP_OUTPUT_LIMIT_EXCEEDED", msg, details)
                    if sarif_size == 0:
                        raise scan_error_cls("empty sarif-output file; REVIEW required")
                    sarif_bytes = resolved_stage.read_bytes()
                    try:
                        raw_sarif = sarif_bytes.decode("utf-8")
                    except UnicodeError as exc:
                        raise scan_error_cls("engine SARIF output is not UTF-8; raw bytes retained") from exc
                    (self.output_dir / "opengrep.sarif").write_bytes(sarif_bytes)
                    (self.output_dir / "sarif.command.json").write_text(
                        json.dumps(dual_cmd, indent=2), encoding="utf-8"
                    )
                    (self.output_dir / "sarif.stdout.txt").write_bytes(sarif_bytes)
                    json_stderr_path = self.output_dir / "json.stderr.txt"
                    (self.output_dir / "sarif.stderr.txt").write_bytes(
                        json_stderr_path.read_bytes() if json_stderr_path.is_file() else b""
                    )
                    (self.output_dir / "sarif.exit.txt").write_text("0", encoding="utf-8")
                    if self.capture is not None:
                        self.capture.runs["json"] = {
                            "argv": dual_cmd,
                            "exit_code": 0,
                            "output_mode": "stdout",
                            "single_pass_dual_output": True,
                        }
                        self.capture.runs["sarif"] = {
                            "argv": dual_cmd,
                            "exit_code": 0,
                            "output_mode": "stdout",
                            "single_pass_dual_output": True,
                            "capture_origin": "engine_sarif_output_file",
                            "engine_sarif_output_path": str(sarif_stage_path),
                        }
                    try:
                        results["sarif"] = json.loads(raw_sarif)
                    except (ValueError, TypeError) as exc:
                        raise scan_error_cls("invalid sarif; REVIEW required") from exc
                    single_pass_used = True
                    sarif_ms = 0.0

                if not single_pass_used:
                    if use_single_pass:
                        fallback_to_two_pass = True
                    self._check_deadline_before_step("sarif")
                    t_s0 = time.monotonic()
                    raw_sarif = self._run("sarif", config.command(target_path, "sarif"))
                    sarif_ms = round((time.monotonic() - t_s0) * 1000.0, 2)
                    (self.output_dir / "opengrep.sarif").write_bytes(raw_sarif.encode("utf-8"))
                    try:
                        results["sarif"] = json.loads(raw_sarif)
                    except (ValueError, TypeError) as exc:
                        raise scan_error_cls("invalid sarif; REVIEW required") from exc
            finally:
                try:
                    if sarif_stage_path.exists() or sarif_stage_path.is_symlink():
                        sarif_stage_path.unlink()
                except OSError:
                    pass

            self.validate_json(results["json"])
            sarif = results["sarif"]
            if not isinstance(sarif, dict) or not isinstance(sarif.get("runs"), list):
                raise scan_error_cls("invalid SARIF envelope; REVIEW required")
            results["engine_version"] = version
            self.last_timing = {
                "version_ms": version_ms,
                "json_ms": json_ms,
                "sarif_ms": sarif_ms,
                "total_scan_outputs_ms": round((time.monotonic() - t_total0) * 1000.0, 2),
                "single_pass_dual_output": single_pass_used,
                "single_pass_capability": sp_capability,
                "fallback_to_two_pass": fallback_to_two_pass,
                "jobs": int(config.jobs),
            }
            return results

        def _run(self, label, command):
            env = os.environ.copy()
            env["SEMGREP_LOG_FILE"] = str(self.output_dir / "opengrep.log")
            env["SEMGREP_SETTINGS_FILE"] = str(self.output_dir / "settings.yml")
            env["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
            env["OPENGREP_ENABLE_VERSION_CHECK"] = "0"
            env["SEMGREP_SEND_METRICS"] = "off"
            (self.output_dir / (label + ".command.json")).write_text(
                json.dumps(command, indent=2), encoding="utf-8")
            base_bound = self._process_timeout()
            job_budget_capped = False
            if self.deadline_mono is not None:
                rem = self.deadline_mono - time.monotonic()
                if rem <= 0.0:
                    details = {"engine_step": label, "reason": "job_deadline_exceeded"}
                    message = f"{label}: vượt quá giới hạn thời gian tổng của job (JOB_TIMEOUT) trước khi chạy OpenGrep."
                    self._write_failure(label, {"error_code": "JOB_TIMEOUT", "message": message, **details})
                    raise OpenGrepRunError("JOB_TIMEOUT", message, details)
                if rem < base_bound:
                    bound = max(0.05, rem)
                    job_budget_capped = True
                else:
                    bound = base_bound
            else:
                bound = base_bound
            engine_step = f"opengrep-{label}"
            try:
                result = intake._run_git_step(
                    engine_step, command, timeout_seconds=bound, env=env,
                    max_output_bytes=MAX_OPENGREP_OUTPUT_BYTES,
                )
            except intake._GitStepCleanupFailed as exc:
                details = {"engine_step": label, "cleanup_status": "CLEANUP_FAILED",
                           "process_cleanup": exc.cleanup}
                message = (f"{label}: OpenGrep đã kết thúc (exit {exc.returncode}) nhưng không xác nhận được việc "
                           "dừng toàn bộ tiến trình con (CLEANUP_FAILED).")
                self._write_failure(label, {"error_code": "OPENGREP_CLEANUP_FAILED", "message": message, **details})
                raise OpenGrepRunError("OPENGREP_CLEANUP_FAILED", message, details) from None
            except intake._GitStepOutputLimit as exc:
                details = {"engine_step": label, "output_stream": exc.stream, "output_bytes": exc.size,
                           "limit_bytes": exc.limit, "process_cleanup": exc.cleanup}
                if not exc.cleanup.get("clean"):
                    details["cleanup_status"] = "CLEANUP_FAILED"
                if exc.verified:
                    code = "OPENGREP_OUTPUT_LIMIT_EXCEEDED"
                    message = f"{label}: đầu ra OpenGrep ({exc.stream}) vượt giới hạn {exc.limit} byte; không ghi kết quả bị cắt."
                else:
                    code = "OPENGREP_OUTPUT_UNVERIFIED"
                    message = f"{label}: không xác minh được kích thước đầu ra OpenGrep ({exc.stream}); không ghi kết quả."
                self._write_failure(label, {"error_code": code, "message": message, **details})
                raise OpenGrepRunError(code, message, details) from None
            except intake._GitStepInternalError as exc:
                details = {"engine_step": label, "primary_error": exc.error_type, "process_cleanup": exc.cleanup}
                if not exc.cleanup.get("clean"):
                    details["cleanup_status"] = "CLEANUP_FAILED"
                message = f"{label}: lỗi nội bộ khi quản lý tiến trình OpenGrep ({exc.error_type}); đã chạy bước dọn dẹp."
                self._write_failure(label, {"error_code": "OPENGREP_PROCESS_ERROR", "message": message, **details})
                raise OpenGrepRunError("OPENGREP_PROCESS_ERROR", message, details) from None
            except intake._GitStepTimeout as exc:
                cleanup = exc.cleanup
                hit_job_deadline = job_budget_capped or (
                    self.deadline_mono is not None and time.monotonic() >= self.deadline_mono
                )
                timeout_code = "JOB_TIMEOUT" if hit_job_deadline else "OPENGREP_TIMEOUT"
                details: dict[str, Any] = {
                    "engine_step": label,
                    "timeout_seconds": bound,
                    "process_cleanup": cleanup,
                    "stderr_bytes": exc.stderr_bytes,
                }
                message = (
                    f"{label}: vượt quá giới hạn thời gian tổng của job ({bound:.2f} giây); đã dừng cây tiến trình OpenGrep."
                    if hit_job_deadline
                    else f"{label}: OpenGrep vượt giới hạn {bound} giây; đã dừng cây tiến trình."
                )
                if not cleanup.get("clean"):
                    details["cleanup_status"] = "CLEANUP_FAILED"
                    message = (
                        f"{label}: OpenGrep vượt giới hạn {bound} giây; không xác nhận được việc dừng "
                        "toàn bộ tiến trình con (CLEANUP_FAILED)."
                    )
                self._write_failure(label, {"error_code": timeout_code, "message": message, **details})
                raise OpenGrepRunError(timeout_code, message, details) from None
            except intake.IntakeError as exc:
                if exc.error_code == "GITHUB_GIT_CLEANUP_PENDING":
                    code = "OPENGREP_CLEANUP_PENDING"
                    message = (
                        "Cây tiến trình ngoài (Git/OpenGrep) của lượt trước chưa được xác nhận đã dừng; "
                        "từ chối chạy OpenGrep."
                    )
                elif exc.error_code == "GIT_PROCESS_ISOLATION_FAILED":
                    code = "OPENGREP_PROCESS_ISOLATION_FAILED"
                    message = "Không thiết lập được quyền quản lý tiến trình OpenGrep trước khi chạy; từ chối chạy."
                else:
                    raise
                details = {"engine_step": label, **{k: v for k, v in exc.details.items() if k != "git_step"}}
                self._write_failure(label, {"error_code": code, "message": message, **details})
                raise OpenGrepRunError(code, message, details) from None
            except OSError as exc:
                (self.output_dir / (label + ".failure.txt")).write_text(str(exc), encoding="utf-8")
                raise scan_error_cls(str(exc)) from exc

            for name, value in (("stdout", result.stdout), ("stderr", result.stderr)):
                data = value if isinstance(value, bytes) else value.encode("utf-8")
                (self.output_dir / (label + "." + name + ".txt")).write_bytes(data)
            (self.output_dir / (label + ".exit.txt")).write_text(str(result.returncode), encoding="utf-8")
            if self.capture is not None:
                self.capture.runs[label] = {"argv": command, "exit_code": result.returncode}
            if result.returncode != 0:
                raise scan_error_cls(f"{label} exited {result.returncode}; see captured stderr")
            try:
                return result.stdout.decode("utf-8") if isinstance(result.stdout, bytes) else result.stdout
            except UnicodeError as exc:
                raise scan_error_cls("engine output is not UTF-8; raw bytes retained") from exc

    return BoundedOpenGrepScanner


def _sha256_file_stream(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65_536), b""):
            h.update(chunk)
    return h.hexdigest()


def _parse_semver_tuple(ver_str: str) -> tuple[int, int, int] | None:
    parts = ver_str.strip().split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        return None
    return int(parts[0]), int(parts[1]), int(parts[2])


def parse_and_check_opengrep_version(
    raw_output: str,
    *,
    min_version: str = "1.25.0",
    max_major: int = 1,
) -> tuple[bool, str | None, tuple[int, int, int] | None, str | None, str | None]:
    """Strictly parse `--version` output and enforce OpenGrep version policy (fail-closed)."""
    if not isinstance(raw_output, str):
        return False, None, None, "INVALID_VERSION_OUTPUT", "Đầu ra --version của OpenGrep không phải chuỗi văn bản."
    cleaned = raw_output.strip()
    if not cleaned or "\n" in cleaned or "\r" in cleaned:
        return (
            False,
            None,
            None,
            "INVALID_VERSION_OUTPUT",
            "Đầu ra --version của OpenGrep rỗng hoặc chứa nhiều dòng không hợp lệ.",
        )
    m = _OPENGREP_VERSION_RE.fullmatch(cleaned)
    if not m:
        return (
            False,
            None,
            None,
            "INVALID_VERSION_OUTPUT",
            f"Không thể phân tích phiên bản OpenGrep hợp lệ từ đầu ra: {cleaned[:80]!r}.",
        )
    parsed = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    min_tuple = _parse_semver_tuple(min_version) or (1, 25, 0)
    if parsed < min_tuple or parsed[0] > max_major:
        return (
            False,
            cleaned,
            parsed,
            "VERSION_POLICY_REJECTED",
            f"Phiên bản OpenGrep {cleaned!r} không nằm trong chính sách hỗ trợ (>={min_version}, major<={max_major}).",
        )
    return True, cleaned, parsed, None, None


def _is_windows_system_path(path: Path) -> bool:
    if os.name != "nt":
        return False
    low = str(path).lower()
    sys_root = os.environ.get("SystemRoot", r"C:\Windows").lower().rstrip("\\")
    return low.startswith(sys_root + "\\")


def _stat_sig(path: Path) -> tuple[int, int, int, int] | None:
    try:
        st = path.stat()
        return (int(st.st_dev), int(st.st_ino), int(st.st_size), int(st.st_mtime_ns))
    except OSError:
        return None


_WSL_SHELL_BINARIES = frozenset({"sh", "bash", "dash", "zsh", "ash", "ksh", "csh", "tcsh", "fish", "env"})


def _is_wsl_executable_token(tok: str) -> bool:
    base = tok.strip().strip("\"'").replace("\\", "/").rsplit("/", 1)[-1].lower()
    return base in ("wsl", "wsl.exe")


def _is_safe_wsl_linux_path(tok: str) -> bool:
    if not tok.startswith("/") or len(tok) <= 1 or tok.startswith("//"):
        return False
    if not re.fullmatch(r"/[A-Za-z0-9_./+-]+", tok):
        return False
    if ".." in tok.split("/"):
        return False
    return True


def _extract_wsl_target_from_tokens(tokens: list[str]) -> dict[str, Any] | None:
    """Detect `wsl(.exe) -d <distro> [--] </linux/path>` inside a wrapper/bridge command token list."""
    wsl_idx = None
    for idx, tok in enumerate(tokens):
        if _is_wsl_executable_token(tok):
            wsl_idx = idx
            break
    if wsl_idx is None:
        return None
    distro: str | None = None
    linux_path: str | None = None
    i = wsl_idx + 1
    after_sep = False
    while i < len(tokens):
        tok = tokens[i].strip().strip("\"'")
        if not tok:
            i += 1
            continue
        if not after_sep and tok in ("-d", "--distribution") and i + 1 < len(tokens):
            cand = tokens[i + 1].strip().strip("\"'")
            if cand and not cand.startswith("-"):
                distro = cand
            i += 2
            continue
        if not after_sep and tok.startswith("--distribution="):
            cand = tok.split("=", 1)[1].strip().strip("\"'")
            if cand:
                distro = cand
            i += 1
            continue
        if not after_sep and tok == "--":
            after_sep = True
            i += 1
            continue
        if not after_sep and tok in ("-e", "--exec"):
            after_sep = True
            i += 1
            continue
        if not after_sep and tok in ("-u", "--user", "--cd", "--shell-type") and i + 1 < len(tokens):
            i += 2
            continue
        if tok.startswith("/") and len(tok) > 1 and not tok.startswith("//"):
            base = tok.rsplit("/", 1)[-1].lower()
            if base in _WSL_SHELL_BINARIES:
                return None
            if after_sep or linux_path is None:
                linux_path = tok
                if after_sep:
                    break
        i += 1
    if linux_path:
        return {
            "detected": True,
            "distro": distro,
            "linux_binary_path": linux_path,
        }
    return None


def _inspect_wsl_seq_nodes(nodes: list[ast.AST]) -> tuple[str, dict[str, Any] | None, str | None]:
    """Analyze an AST element list for a `wsl(.exe)` command.

    Returns `(status, target_or_none, reason_or_none)` where `status` is one of:
    - `"none"`: no `wsl` / `wsl.exe` executable token in `nodes`
    - `"ok"`: unique static `(distro, absolute_linux_binary_path)` fixed before any trailing `*args`
    - `"unresolvable"`: dynamic/unbounded distro or executable, shell wrapper, or missing path
    """
    wsl_idx = None
    for idx, elt in enumerate(nodes):
        if isinstance(elt, ast.Constant) and isinstance(elt.value, str) and _is_wsl_executable_token(elt.value):
            wsl_idx = idx
            break
    if wsl_idx is None:
        return "none", None, None

    distro: str | None = None
    after_sep = False
    i = wsl_idx + 1
    while i < len(nodes):
        elt = nodes[i]
        if isinstance(elt, ast.Starred):
            return (
                "unresolvable",
                None,
                "Phần tử mở rộng động (*args) xuất hiện trước khi cố định đường dẫn binary WSL.",
            )
        if not (isinstance(elt, ast.Constant) and isinstance(elt.value, str)):
            return (
                "unresolvable",
                None,
                "Tham số động xuất hiện trước khi cố định đường dẫn binary WSL.",
            )
        tok = elt.value.strip().strip("\"'")
        if not tok:
            i += 1
            continue
        if not after_sep and tok in ("-d", "--distribution"):
            if i + 1 >= len(nodes):
                return "unresolvable", None, "Thiếu tên distro WSL sau cờ -d/--distribution."
            nxt = nodes[i + 1]
            if not (isinstance(nxt, ast.Constant) and isinstance(nxt.value, str)):
                return "unresolvable", None, "Tên distro WSL là giá trị động không thể xác minh tĩnh."
            cand = nxt.value.strip().strip("\"'")
            if not cand or cand.startswith("-"):
                return "unresolvable", None, f"Tên distro WSL không hợp lệ: {cand!r}."
            distro = cand
            i += 2
            continue
        if not after_sep and tok.startswith("--distribution="):
            cand = tok.split("=", 1)[1].strip().strip("\"'")
            if not cand:
                return "unresolvable", None, "Giá trị --distribution bị rỗng."
            distro = cand
            i += 1
            continue
        if not after_sep and tok == "--":
            after_sep = True
            i += 1
            continue
        if not after_sep and tok in ("-e", "--exec"):
            after_sep = True
            i += 1
            continue
        if not after_sep and tok in ("-u", "--user", "--cd", "--shell-type"):
            if i + 1 >= len(nodes) or not (isinstance(nodes[i + 1], ast.Constant) and isinstance(nodes[i + 1].value, str)):
                return "unresolvable", None, f"Tham số sau cờ WSL {tok!r} không phải hằng chuỗi tĩnh."
            i += 2
            continue
        if not after_sep and tok.startswith("-"):
            i += 1
            continue
        # Positional binary token reached
        base = tok.rsplit("/", 1)[-1].lower()
        if base in _WSL_SHELL_BINARIES:
            return "unresolvable", None, f"Lệnh WSL bọc qua shell ({tok!r}) che khuất binary đích."
        if _is_safe_wsl_linux_path(tok):
            # Binary path & distro are now uniquely determined; trailing `*translated_args` are safe.
            return (
                "ok",
                {
                    "detected": True,
                    "distro": distro,
                    "linux_binary_path": tok,
                },
                None,
            )
        return "unresolvable", None, f"Đường dẫn binary WSL không phải đường dẫn tuyệt đối tĩnh hợp lệ: {tok!r}."

    return "unresolvable", None, "Tìm thấy lời gọi wsl.exe nhưng không xác định được đường dẫn binary Linux."


def _node_mentions_wsl(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str) and ("wsl" in sub.value.lower()):
            if _is_wsl_executable_token(sub.value) or any(_is_wsl_executable_token(t) for t in sub.value.split()):
                return True
    return False


_SUBPROCESS_LAUNCH_FUNCS = frozenset({"run", "Popen", "call", "check_call", "check_output"})
_OS_LAUNCH_FUNCS = frozenset(
    {"system", "popen", "execv", "execve", "execvp", "execvpe", "spawnv", "spawnve", "spawnvp", "spawnvpe"}
)
_ASYNCIO_LAUNCH_FUNCS = frozenset({"create_subprocess_exec", "create_subprocess_shell"})


def _eval_static_branch_truth(test: ast.AST, *, is_main_module: bool) -> bool | None:
    """Return statically provable truth value (`True`/`False`) of a branch test, or `None` if runtime-dependent."""
    if isinstance(test, ast.Constant):
        return bool(test.value)
    if isinstance(test, (ast.List, ast.Tuple, ast.Set)):
        if not test.elts:
            return False
        if not any(isinstance(e, ast.Starred) for e in test.elts):
            return True
        return None
    if isinstance(test, ast.Dict):
        if not test.keys:
            return False
        if not any(k is None for k in test.keys):
            return True
        return None
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        inner = _eval_static_branch_truth(test.operand, is_main_module=is_main_module)
        return (not inner) if inner is not None else None
    if isinstance(test, ast.IfExp):
        cond = _eval_static_branch_truth(test.test, is_main_module=is_main_module)
        if cond is True:
            return _eval_static_branch_truth(test.body, is_main_module=is_main_module)
        if cond is False:
            return _eval_static_branch_truth(test.orelse, is_main_module=is_main_module)
        body_truth = _eval_static_branch_truth(test.body, is_main_module=is_main_module)
        if body_truth is None:
            return None
        orelse_truth = _eval_static_branch_truth(test.orelse, is_main_module=is_main_module)
        if body_truth is orelse_truth:
            return body_truth
        return None
    if isinstance(test, ast.BoolOp):
        if isinstance(test.op, ast.And):
            all_true = True
            for v in test.values:
                tv = _eval_static_branch_truth(v, is_main_module=is_main_module)
                if tv is False:
                    return False
                if tv is not True:
                    all_true = False
            return True if all_true else None
        if isinstance(test.op, ast.Or):
            all_false = True
            for v in test.values:
                tv = _eval_static_branch_truth(v, is_main_module=is_main_module)
                if tv is True:
                    return True
                if tv is not False:
                    all_false = False
            return False if all_false else None
    if isinstance(test, ast.Compare) and len(test.ops) == 1 and len(test.comparators) == 1:
        op = test.ops[0]
        left, right = test.left, test.comparators[0]
        is_name_main_cmp = (
            (isinstance(left, ast.Name) and left.id == "__name__" and isinstance(right, ast.Constant) and right.value == "__main__")
            or (isinstance(right, ast.Name) and right.id == "__name__" and isinstance(left, ast.Constant) and left.value == "__main__")
        )
        if is_name_main_cmp:
            if isinstance(op, ast.Eq):
                return is_main_module
            if isinstance(op, ast.NotEq):
                return not is_main_module
        if isinstance(left, ast.Constant) and isinstance(right, ast.Constant):
            lv, rv = left.value, right.value
            try:
                if isinstance(op, ast.Eq):
                    return bool(lv == rv)
                if isinstance(op, ast.NotEq):
                    return bool(lv != rv)
                if isinstance(op, ast.Lt):
                    return bool(lv < rv)
                if isinstance(op, ast.LtE):
                    return bool(lv <= rv)
                if isinstance(op, ast.Gt):
                    return bool(lv > rv)
                if isinstance(op, ast.GtE):
                    return bool(lv >= rv)
                if isinstance(op, ast.Is):
                    return bool(lv is rv)
                if isinstance(op, ast.IsNot):
                    return bool(lv is not rv)
            except TypeError:
                return None
    return None


def _dotted_attr_chain(node: ast.AST) -> tuple[str, ...] | None:
    parts: list[str] = []
    cur: ast.AST = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        parts.reverse()
        return tuple(parts)
    return None


def _collect_wsl_candidates_from_py_ast(
    tree: ast.AST,
    *,
    nodes: list[ast.AST] | None = None,
    is_entry_script: bool = True,
    imported_entry_names: set[str] | None = None,
    out_reachable_refs: dict[str, set[Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Collect static WSL targets ONLY from reachable process-launch call sites and fail closed on ambiguity/dynamics.

    Reachability starts from supported entry points:
    - Entry script (`is_entry_script=True`): module top-level statements, `if __name__ == "__main__":`,
      transitively called local functions (`main()`, `sys.exit(main())`, helpers, helpers returning commands).
    - Imported local dependency (`is_entry_script=False`): module top-level statements (excluding `__main__`)
      plus top-level functions referenced by the importing script (`imported_entry_names`).
    Statically false branches (`if False:`, `if 0:`, `while False:`, `else` of `if True:`) and uncalled
    functions are excluded. Unreferenced documentation tuples/lists never produce false candidates or conflicts.
    Dynamic/unverifiable call dispatch in reachable code fails closed with `WSL_TARGET_UNRESOLVABLE`.
    """
    walk_nodes = nodes if nodes is not None else list(ast.walk(tree))
    has_any_wsl_str = any(
        isinstance(n, ast.Constant)
        and isinstance(n.value, str)
        and ("wsl" in n.value.lower())
        and (_is_wsl_executable_token(n.value) or any(_is_wsl_executable_token(t) for t in n.value.split()))
        for n in walk_nodes
    )
    if not has_any_wsl_str and out_reachable_refs is None:
        return [], []

    scope_assigns: dict[int, dict[str, list[ast.AST]]] = {}
    scope_subscript_mutated: dict[int, set[str]] = {}
    func_defs_by_scope: dict[int, dict[str, tuple[ast.FunctionDef | ast.AsyncFunctionDef, tuple[int, ...]]]] = {}
    class_defs_by_scope: dict[int, dict[str, ast.ClassDef]] = {}
    reachable_func_returns: dict[int, list[ast.AST]] = {}
    func_call_arg_bindings: dict[int, dict[str, list[tuple[ast.AST, tuple[int, ...]]]]] = {}

    subprocess_mods: set[str] = {"subprocess"}
    os_mods: set[str] = {"os"}
    asyncio_mods: set[str] = {"asyncio"}
    direct_launch_aliases: dict[str, str] = {}
    var_launch_aliases: dict[int, dict[str, str]] = {}
    var_func_aliases: dict[int, dict[str, str]] = {}
    var_dynamic_callables: dict[int, dict[str, str]] = {}

    launch_calls: list[tuple[ast.Call, tuple[int, ...], str]] = []
    pending_calls: list[tuple[str, tuple[int, ...], ast.Call]] = []
    visited_func_sids: set[int] = set()
    reachable_loaded_names: set[str] = set()
    has_dynamic_reachable_dispatch = False
    has_suspicious_subscript_or_indirect_call = False
    has_reachable_wsl_or_launcher_value = False

    def _lookup_launch_alias(name: str, scope_chain: tuple[int, ...]) -> str | None:
        for sid in scope_chain:
            hit = var_launch_aliases.get(sid, {}).get(name)
            if hit is not None:
                return hit
        return direct_launch_aliases.get(name)

    def _lookup_dynamic_callable_kind(name: str, scope_chain: tuple[int, ...]) -> str | None:
        for sid in scope_chain:
            hit = var_dynamic_callables.get(sid, {}).get(name)
            if hit is not None:
                return hit
        return None

    def _classify_dynamic_callable_rhs(expr: ast.AST) -> str | None:
        if isinstance(expr, ast.Subscript):
            if (
                isinstance(expr.value, ast.Call)
                and isinstance(expr.value.func, ast.Name)
                and expr.value.func.id in ("globals", "locals", "vars")
            ):
                return "getattr"
            return "subscript"
        if isinstance(expr, ast.Call):
            if isinstance(expr.func, ast.Name) and expr.func.id in ("getattr", "eval", "exec"):
                return "getattr"
            if isinstance(expr.func, ast.Attribute) and expr.func.attr == "get":
                return "subscript"
        return None

    def _lookup_func_alias(name: str, scope_chain: tuple[int, ...]) -> str:
        cur = name
        seen: set[str] = set()
        while cur not in seen:
            seen.add(cur)
            nxt: str | None = None
            for sid in scope_chain:
                if cur in var_func_aliases.get(sid, {}):
                    nxt = var_func_aliases[sid][cur]
                    break
            if nxt is None:
                break
            cur = nxt
        return cur

    def _expr_launch_kind(expr: ast.AST, scope_chain: tuple[int, ...]) -> str | None:
        if isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name):
            mod, attr = expr.value.id, expr.attr
            if mod in subprocess_mods and attr in _SUBPROCESS_LAUNCH_FUNCS:
                return f"subprocess.{attr}"
            if mod in os_mods and attr in _OS_LAUNCH_FUNCS:
                return f"os.{attr}"
            if mod in asyncio_mods and attr in _ASYNCIO_LAUNCH_FUNCS:
                return f"asyncio.{attr}"
        elif isinstance(expr, ast.Name):
            return _lookup_launch_alias(expr.id, scope_chain)
        return None

    def _record_target_mutation(tgt: ast.AST, sid: int) -> None:
        if isinstance(tgt, ast.Subscript) and isinstance(tgt.value, ast.Name):
            scope_subscript_mutated.setdefault(sid, set()).add(tgt.value.id)
        elif isinstance(tgt, (ast.Tuple, ast.List)):
            for el in tgt.elts:
                _record_target_mutation(el, sid)

    def _visit_expr(expr: ast.AST, scope_chain: tuple[int, ...]) -> None:
        nonlocal has_dynamic_reachable_dispatch, has_suspicious_subscript_or_indirect_call, has_reachable_wsl_or_launcher_value
        if isinstance(expr, ast.IfExp):
            truth = _eval_static_branch_truth(expr.test, is_main_module=is_entry_script)
            _visit_expr(expr.test, scope_chain)
            if truth is True:
                _visit_expr(expr.body, scope_chain)
            elif truth is False:
                _visit_expr(expr.orelse, scope_chain)
            else:
                _visit_expr(expr.body, scope_chain)
                _visit_expr(expr.orelse, scope_chain)
            return
        if isinstance(expr, ast.BoolOp):
            is_and = isinstance(expr.op, ast.And)
            is_or = isinstance(expr.op, ast.Or)
            for val in expr.values:
                _visit_expr(val, scope_chain)
                truth = _eval_static_branch_truth(val, is_main_module=is_entry_script)
                if (is_and and truth is False) or (is_or and truth is True):
                    break
            return
        if isinstance(expr, ast.Attribute):
            if out_reachable_refs is not None:
                chain = _dotted_attr_chain(expr)
                if chain is not None:
                    out_reachable_refs["dotted_attrs"].add(chain)
            if _expr_launch_kind(expr, scope_chain) is not None:
                has_reachable_wsl_or_launcher_value = True
            _visit_expr(expr.value, scope_chain)
            return
        if isinstance(expr, ast.Name) and isinstance(expr.ctx, ast.Load):
            reachable_loaded_names.add(expr.id)
            if out_reachable_refs is not None:
                out_reachable_refs["called_or_loaded"].add(expr.id)
            if _lookup_launch_alias(expr.id, scope_chain) is not None:
                has_reachable_wsl_or_launcher_value = True
            return
        if isinstance(expr, ast.Call):
            fn = expr.func
            # Detect dynamic/unverifiable invocation or dynamic attribute lookup on process launchers
            if isinstance(fn, ast.Name) and fn.id in ("eval", "exec"):
                has_dynamic_reachable_dispatch = True
            elif isinstance(fn, ast.Name) and fn.id == "getattr":
                if expr.args and isinstance(expr.args[0], ast.Name):
                    if out_reachable_refs is not None:
                        out_reachable_refs["getattr_targets"].add(expr.args[0].id)
                    if (
                        expr.args[0].id in subprocess_mods
                        or expr.args[0].id in os_mods
                        or expr.args[0].id in asyncio_mods
                    ):
                        has_dynamic_reachable_dispatch = True
            elif isinstance(fn, ast.Subscript):
                if _node_mentions_wsl(expr) or (
                    isinstance(fn.value, ast.Call)
                    and isinstance(fn.value.func, ast.Name)
                    and fn.value.func.id in ("globals", "locals", "vars")
                ):
                    has_dynamic_reachable_dispatch = True
                else:
                    has_suspicious_subscript_or_indirect_call = True
            elif isinstance(fn, ast.Call) and isinstance(fn.func, ast.Name) and fn.func.id in ("getattr", "eval", "exec"):
                has_dynamic_reachable_dispatch = True
            elif isinstance(fn, ast.Call) and isinstance(fn.func, ast.Attribute) and fn.func.attr == "get":
                if _node_mentions_wsl(expr):
                    has_dynamic_reachable_dispatch = True
                else:
                    has_suspicious_subscript_or_indirect_call = True

            kind = _expr_launch_kind(fn, scope_chain)
            if kind is not None:
                launch_calls.append((expr, scope_chain, kind))
            elif isinstance(fn, ast.Name):
                if out_reachable_refs is not None:
                    out_reachable_refs["called_or_loaded"].add(fn.id)
                dyn_kind = _lookup_dynamic_callable_kind(fn.id, scope_chain)
                if dyn_kind == "getattr":
                    has_dynamic_reachable_dispatch = True
                elif dyn_kind == "subscript":
                    if _node_mentions_wsl(expr):
                        has_dynamic_reachable_dispatch = True
                    else:
                        has_suspicious_subscript_or_indirect_call = True
                resolved_fn_name = _lookup_func_alias(fn.id, scope_chain)
                if out_reachable_refs is not None:
                    out_reachable_refs["called_or_loaded"].add(resolved_fn_name)
                pending_calls.append((resolved_fn_name, scope_chain, expr))

            # Visit call arguments & callee expression (note: direct callee Name doesn't count as indirect callback ref)
            if not isinstance(fn, ast.Name):
                _visit_expr(fn, scope_chain)
            for arg in expr.args:
                _visit_expr(arg, scope_chain)
            for kw in expr.keywords:
                _visit_expr(kw.value, scope_chain)
            return
        if isinstance(expr, ast.Lambda):
            _visit_expr(expr.body, scope_chain)
            return
        for child in ast.iter_child_nodes(expr):
            _visit_expr(child, scope_chain)

    def _visit_stmts(stmts: list[ast.stmt], scope_chain: tuple[int, ...]) -> None:
        cur_sid = scope_chain[0]
        # Register local FunctionDef / ClassDef names before resolving calls within the same block
        for stmt in stmts:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn_sid = id(stmt)
                func_defs_by_scope.setdefault(cur_sid, {})[stmt.name] = (stmt, (fn_sid, *scope_chain))
            elif isinstance(stmt, ast.ClassDef):
                class_defs_by_scope.setdefault(cur_sid, {})[stmt.name] = stmt

        for stmt in stmts:
            if isinstance(stmt, ast.Import):
                for alias in stmt.names:
                    bound = alias.asname or alias.name
                    if alias.name == "subprocess":
                        subprocess_mods.add(bound)
                    elif alias.name == "os":
                        os_mods.add(bound)
                    elif alias.name == "asyncio":
                        asyncio_mods.add(bound)
            elif isinstance(stmt, ast.ImportFrom) and stmt.level == 0 and stmt.module in ("subprocess", "os", "asyncio"):
                allowed = (
                    _SUBPROCESS_LAUNCH_FUNCS
                    if stmt.module == "subprocess"
                    else (_OS_LAUNCH_FUNCS if stmt.module == "os" else _ASYNCIO_LAUNCH_FUNCS)
                )
                for alias in stmt.names:
                    if alias.name in allowed:
                        direct_launch_aliases[alias.asname or alias.name] = f"{stmt.module}.{alias.name}"
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Decorators and default argument expressions execute at definition time; body waits until called
                for dec in stmt.decorator_list:
                    _visit_expr(dec, scope_chain)
                for df in stmt.args.defaults:
                    _visit_expr(df, scope_chain)
                for df in stmt.args.kw_defaults:
                    if df is not None:
                        _visit_expr(df, scope_chain)
            elif isinstance(stmt, ast.ClassDef):
                for dec in stmt.decorator_list:
                    _visit_expr(dec, scope_chain)
                for base in stmt.bases:
                    _visit_expr(base, scope_chain)
            elif isinstance(stmt, ast.If):
                truth = _eval_static_branch_truth(stmt.test, is_main_module=is_entry_script)
                _visit_expr(stmt.test, scope_chain)
                if truth is True:
                    _visit_stmts(stmt.body, scope_chain)
                elif truth is False:
                    _visit_stmts(stmt.orelse, scope_chain)
                else:
                    _visit_stmts(stmt.body, scope_chain)
                    _visit_stmts(stmt.orelse, scope_chain)
            elif isinstance(stmt, ast.While):
                truth = _eval_static_branch_truth(stmt.test, is_main_module=is_entry_script)
                _visit_expr(stmt.test, scope_chain)
                if truth is False:
                    _visit_stmts(stmt.orelse, scope_chain)
                else:
                    _visit_stmts(stmt.body, scope_chain)
                    _visit_stmts(stmt.orelse, scope_chain)
            elif isinstance(stmt, (ast.For, ast.AsyncFor)):
                _visit_expr(stmt.iter, scope_chain)
                _visit_stmts(stmt.body, scope_chain)
                _visit_stmts(stmt.orelse, scope_chain)
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                for item in stmt.items:
                    _visit_expr(item.context_expr, scope_chain)
                _visit_stmts(stmt.body, scope_chain)
            elif isinstance(stmt, ast.Try):
                _visit_stmts(stmt.body, scope_chain)
                for h in stmt.handlers:
                    if h.type is not None:
                        _visit_expr(h.type, scope_chain)
                    _visit_stmts(h.body, scope_chain)
                _visit_stmts(stmt.orelse, scope_chain)
                _visit_stmts(stmt.finalbody, scope_chain)
            elif hasattr(ast, "TryStar") and isinstance(stmt, ast.TryStar):
                _visit_stmts(stmt.body, scope_chain)
                for h in stmt.handlers:
                    if h.type is not None:
                        _visit_expr(h.type, scope_chain)
                    _visit_stmts(h.body, scope_chain)
                _visit_stmts(stmt.orelse, scope_chain)
                _visit_stmts(stmt.finalbody, scope_chain)
            elif hasattr(ast, "Match") and isinstance(stmt, ast.Match):
                _visit_expr(stmt.subject, scope_chain)
                for case in stmt.cases:
                    if case.guard is not None:
                        _visit_expr(case.guard, scope_chain)
                    _visit_stmts(case.body, scope_chain)
            elif isinstance(stmt, ast.Assign):
                rhs_launch = _expr_launch_kind(stmt.value, scope_chain)
                rhs_fn_name = stmt.value.id if isinstance(stmt.value, ast.Name) else None
                rhs_dyn_kind = _classify_dynamic_callable_rhs(stmt.value)
                for tgt in stmt.targets:
                    if isinstance(tgt, ast.Name):
                        scope_assigns.setdefault(cur_sid, {}).setdefault(tgt.id, []).append(stmt.value)
                        if rhs_launch is not None:
                            var_launch_aliases.setdefault(cur_sid, {})[tgt.id] = rhs_launch
                        if rhs_fn_name is not None:
                            var_func_aliases.setdefault(cur_sid, {})[tgt.id] = rhs_fn_name
                        if rhs_dyn_kind is not None:
                            var_dynamic_callables.setdefault(cur_sid, {})[tgt.id] = rhs_dyn_kind
                    else:
                        _record_target_mutation(tgt, cur_sid)
                _visit_expr(stmt.value, scope_chain)
            elif isinstance(stmt, ast.AnnAssign):
                if isinstance(stmt.target, ast.Name) and stmt.value is not None:
                    scope_assigns.setdefault(cur_sid, {}).setdefault(stmt.target.id, []).append(stmt.value)
                    rhs_launch = _expr_launch_kind(stmt.value, scope_chain)
                    if rhs_launch is not None:
                        var_launch_aliases.setdefault(cur_sid, {})[stmt.target.id] = rhs_launch
                    rhs_dyn_kind = _classify_dynamic_callable_rhs(stmt.value)
                    if rhs_dyn_kind is not None:
                        var_dynamic_callables.setdefault(cur_sid, {})[stmt.target.id] = rhs_dyn_kind
                else:
                    _record_target_mutation(stmt.target, cur_sid)
                if stmt.value is not None:
                    _visit_expr(stmt.value, scope_chain)
            elif isinstance(stmt, ast.AugAssign):
                _record_target_mutation(stmt.target, cur_sid)
                _visit_expr(stmt.value, scope_chain)
            elif isinstance(stmt, ast.Delete):
                for tgt in stmt.targets:
                    _record_target_mutation(tgt, cur_sid)
            elif isinstance(stmt, ast.Return):
                if stmt.value is not None:
                    reachable_func_returns.setdefault(cur_sid, []).append(stmt.value)
                    _visit_expr(stmt.value, scope_chain)
            elif isinstance(stmt, ast.Expr):
                _visit_expr(stmt.value, scope_chain)
            elif isinstance(stmt, ast.Raise):
                if stmt.exc is not None:
                    _visit_expr(stmt.exc, scope_chain)
                if stmt.cause is not None:
                    _visit_expr(stmt.cause, scope_chain)
            elif isinstance(stmt, ast.Assert):
                _visit_expr(stmt.test, scope_chain)
                if stmt.msg is not None:
                    _visit_expr(stmt.msg, scope_chain)

    def _lookup_func(fn_name: str, scope_chain: tuple[int, ...]) -> tuple[ast.FunctionDef | ast.AsyncFunctionDef, tuple[int, ...]] | None:
        for sid in scope_chain:
            hit = func_defs_by_scope.get(sid, {}).get(fn_name)
            if hit is not None:
                return hit
        return None

    def _bind_call_args(
        fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
        call_expr: ast.Call,
        caller_chain: tuple[int, ...],
    ) -> None:
        fn_sid = id(fn_node)
        pos_params = [a.arg for a in fn_node.args.posonlyargs] + [a.arg for a in fn_node.args.args]
        for idx, arg_expr in enumerate(call_expr.args):
            if idx < len(pos_params) and not isinstance(arg_expr, ast.Starred):
                func_call_arg_bindings.setdefault(fn_sid, {}).setdefault(pos_params[idx], []).append(
                    (arg_expr, caller_chain)
                )
        for kw in call_expr.keywords:
            if kw.arg is not None:
                func_call_arg_bindings.setdefault(fn_sid, {}).setdefault(kw.arg, []).append(
                    (kw.value, caller_chain)
                )

    # 1. Traverse supported entry statements
    root_sid = id(tree)
    if isinstance(tree, ast.Module):
        _visit_stmts(tree.body, (root_sid,))

    # 2. For imported local helper modules, seed functions referenced by the parent script
    if not is_entry_script:
        top_defs = func_defs_by_scope.get(root_sid, {})
        for fn_name, (fn_node, fn_chain) in top_defs.items():
            if imported_entry_names is None or "*" in imported_entry_names or fn_name in imported_entry_names:
                fn_sid = id(fn_node)
                if fn_sid not in visited_func_sids:
                    visited_func_sids.add(fn_sid)
                    _visit_stmts(fn_node.body, fn_chain)

    # 3. Drain transitively called local functions (bounded by total defined functions -> O(N))
    while pending_calls:
        fn_name, caller_chain, call_expr = pending_calls.pop(0)
        hit = _lookup_func(fn_name, caller_chain)
        if hit is None:
            continue
        fn_node, fn_chain = hit
        _bind_call_args(fn_node, call_expr, caller_chain)
        fn_sid = id(fn_node)
        if fn_sid not in visited_func_sids:
            visited_func_sids.add(fn_sid)
            _visit_stmts(fn_node.body, fn_chain)

    if not has_any_wsl_str:
        return [], []

    candidates: dict[tuple[str | None, str], dict[str, Any]] = {}
    issues: list[dict[str, str]] = []
    inspected_seq_ids: set[int] = set()

    # Fail-closed on dynamic/unverifiable call dispatch in reachable code when script mentions WSL
    if has_dynamic_reachable_dispatch or (
        has_suspicious_subscript_or_indirect_call and has_reachable_wsl_or_launcher_value
    ):
        issues.append(
            {
                "code": "WSL_TARGET_UNRESOLVABLE",
                "detail": "Phát hiện lời gọi động (eval/exec/getattr/subscript dispatch) trong đường thực thi có chứa lệnh WSL.",
            }
        )

    # Fail-closed if an unvisited local function or class containing a WSL mention IS referenced as a value
    # (e.g., callback / dispatch table / instantiation) from reachable code
    for sid_map in func_defs_by_scope.values():
        for fn_name, (fn_node, _fn_chain) in sid_map.items():
            if id(fn_node) not in visited_func_sids and fn_name in reachable_loaded_names:
                if _node_mentions_wsl(fn_node):
                    issues.append(
                        {
                            "code": "WSL_TARGET_UNRESOLVABLE",
                            "detail": f"Hàm {fn_name!r} chứa tham chiếu WSL được truyền/tham chiếu gián tiếp; không thể xác minh tĩnh đường gọi.",
                        }
                    )
    for cls_map in class_defs_by_scope.values():
        for cls_name, cls_node in cls_map.items():
            if cls_name in reachable_loaded_names and _node_mentions_wsl(cls_node):
                issues.append(
                    {
                        "code": "WSL_TARGET_UNRESOLVABLE",
                        "detail": f"Lớp {cls_name!r} chứa tham chiếu WSL được khởi tạo/tham chiếu; không thể xác minh tĩnh phương thức gọi.",
                    }
                )

    if not launch_calls:
        return list(candidates.values()), issues

    def _record_seq(elts: list[ast.AST], node_id: int) -> bool:
        """Return True if this sequence is a WSL sequence (either valid candidate or unresolvable)."""
        if node_id in inspected_seq_ids:
            return False
        inspected_seq_ids.add(node_id)
        status, target, reason = _inspect_wsl_seq_nodes(elts)
        if status == "ok" and target is not None:
            key = (target.get("distro"), str(target["linux_binary_path"]))
            candidates[key] = target
            return True
        if status == "unresolvable":
            issues.append(
                {
                    "code": "WSL_TARGET_UNRESOLVABLE",
                    "detail": reason or "Không thể xác minh tĩnh đích binary WSL.",
                }
            )
            return True
        return False

    def _lookup_var_binding(var_name: str, scope_chain: tuple[int, ...]) -> tuple[int | None, list[ast.AST]]:
        for sid in scope_chain:
            vals = scope_assigns.get(sid, {}).get(var_name)
            if vals:
                return sid, vals
        return None, []

    def _inspect_cmd_expr(
        expr: ast.AST,
        scope_chain: tuple[int, ...],
        *,
        depth: int = 0,
        visited: frozenset[tuple[str, int, str]] = frozenset(),
    ) -> bool:
        """Inspect command expression tied to a reachable launch call site. Return True if WSL-related."""
        if depth > 8:
            if _node_mentions_wsl(expr):
                issues.append(
                    {
                        "code": "WSL_TARGET_UNRESOLVABLE",
                        "detail": "Độ sâu suy diễn biểu thức lệnh WSL vượt giới hạn tĩnh.",
                    }
                )
                return True
            return False

        if isinstance(expr, ast.IfExp):
            truth = _eval_static_branch_truth(expr.test, is_main_module=is_entry_script)
            if truth is True:
                return _inspect_cmd_expr(expr.body, scope_chain, depth=depth + 1, visited=visited)
            if truth is False:
                return _inspect_cmd_expr(expr.orelse, scope_chain, depth=depth + 1, visited=visited)
            b1 = _inspect_cmd_expr(expr.body, scope_chain, depth=depth + 1, visited=visited)
            b2 = _inspect_cmd_expr(expr.orelse, scope_chain, depth=depth + 1, visited=visited)
            return b1 or b2

        if isinstance(expr, (ast.List, ast.Tuple)):
            return _record_seq(expr.elts, id(expr))

        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            if _node_mentions_wsl(expr):
                if isinstance(expr.left, (ast.List, ast.Tuple)):
                    status, target, reason = _inspect_wsl_seq_nodes(expr.left.elts)
                    inspected_seq_ids.add(id(expr.left))
                    if status == "ok" and target is not None:
                        key = (target.get("distro"), str(target["linux_binary_path"]))
                        candidates[key] = target
                        return True
                    issues.append(
                        {
                            "code": "WSL_TARGET_UNRESOLVABLE",
                            "detail": reason or "Danh sách lệnh WSL ghép nối (+) trước khi cố định binary.",
                        }
                    )
                    return True
                issues.append(
                    {
                        "code": "WSL_TARGET_UNRESOLVABLE",
                        "detail": "Biểu thức ghép lệnh WSL động không thể xác minh tĩnh.",
                    }
                )
                return True
            return False

        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            toks = expr.value.split()
            if any(_is_wsl_executable_token(t) for t in toks):
                hit = _extract_wsl_target_from_tokens(toks)
                if hit is None:
                    issues.append(
                        {
                            "code": "WSL_TARGET_UNRESOLVABLE",
                            "detail": "Chuỗi lệnh WSL không phân giải được binary Linux tuyệt đối tĩnh.",
                        }
                    )
                else:
                    key = (hit.get("distro"), str(hit["linux_binary_path"]))
                    candidates[key] = hit
                return True
            return False

        if isinstance(expr, ast.Name):
            bind_sid, vals = _lookup_var_binding(expr.id, scope_chain)
            if bind_sid is not None:
                visit_key = ("var", bind_sid, expr.id)
                if visit_key in visited:
                    return False
                next_visited = visited | {visit_key}
                bind_idx = scope_chain.index(bind_sid) if bind_sid in scope_chain else 0
                bind_chain = scope_chain[bind_idx:]
                var_is_wsl = False
                for val_node in vals:
                    if _inspect_cmd_expr(val_node, bind_chain, depth=depth + 1, visited=next_visited):
                        var_is_wsl = True
                if var_is_wsl and expr.id in scope_subscript_mutated.get(bind_sid, ()):
                    issues.append(
                        {
                            "code": "WSL_TARGET_UNRESOLVABLE",
                            "detail": f"Biến lệnh WSL {expr.id!r} bị thay đổi phần tử động qua subscript trước khi thực thi.",
                        }
                    )
                return var_is_wsl

            # Check parameter bindings passed from reachable call sites of enclosing helper function
            for sid in scope_chain:
                param_vals = func_call_arg_bindings.get(sid, {}).get(expr.id)
                if param_vals:
                    visit_key = ("param", sid, expr.id)
                    if visit_key in visited:
                        return False
                    next_visited = visited | {visit_key}
                    param_is_wsl = False
                    for arg_expr, caller_chain in param_vals:
                        if _inspect_cmd_expr(arg_expr, caller_chain, depth=depth + 1, visited=next_visited):
                            param_is_wsl = True
                    return param_is_wsl
            return False

        if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name):
            resolved_fn_name = _lookup_func_alias(expr.func.id, scope_chain)
            fn_hit = _lookup_func(resolved_fn_name, scope_chain)
            if fn_hit is not None:
                fn_node, fn_chain = fn_hit
                fn_sid = id(fn_node)
                visit_key = ("fn", fn_sid, resolved_fn_name)
                if visit_key not in visited:
                    next_visited = visited | {visit_key}
                    fn_is_wsl = False
                    for ret_expr in reachable_func_returns.get(fn_sid, []):
                        if _inspect_cmd_expr(ret_expr, fn_chain, depth=depth + 1, visited=next_visited):
                            fn_is_wsl = True
                    return fn_is_wsl
                return False

        if _node_mentions_wsl(expr):
            issues.append(
                {
                    "code": "WSL_TARGET_UNRESOLVABLE",
                    "detail": "Cấu trúc lệnh WSL động không thể xác minh tĩnh.",
                }
            )
            return True
        return False

    for call_node, scope_chain, kind in launch_calls:
        shell_true = False
        exec_kw_wsl = False
        for kw in call_node.keywords:
            if kw.arg == "shell":
                if not (isinstance(kw.value, ast.Constant) and kw.value.value is False):
                    shell_true = True
            elif kw.arg == "executable" and _node_mentions_wsl(kw.value):
                exec_kw_wsl = True

        cmd_arg: ast.AST | None = None
        if kind == "asyncio.create_subprocess_exec":
            cmd_arg = ast.List(elts=list(call_node.args), ctx=ast.Load())
        elif kind.startswith("os.execv"):
            cmd_arg = call_node.args[1] if len(call_node.args) >= 2 else (call_node.args[0] if call_node.args else None)
        elif kind.startswith("os.spawnv"):
            cmd_arg = call_node.args[2] if len(call_node.args) >= 3 else (call_node.args[1] if len(call_node.args) >= 2 else None)
        else:
            cmd_arg = (
                call_node.args[0]
                if call_node.args
                else next((kw.value for kw in call_node.keywords if kw.arg == "args"), None)
            )

        call_is_wsl = False
        if exec_kw_wsl:
            call_is_wsl = True
            issues.append(
                {
                    "code": "WSL_TARGET_UNRESOLVABLE",
                    "detail": "Lời gọi subprocess chỉ định executable WSL động không thể xác minh tĩnh.",
                }
            )
        if cmd_arg is not None:
            if _inspect_cmd_expr(cmd_arg, scope_chain):
                call_is_wsl = True
        if shell_true and (call_is_wsl or (cmd_arg is not None and _node_mentions_wsl(cmd_arg))):
            issues.append(
                {
                    "code": "WSL_TARGET_UNRESOLVABLE",
                    "detail": "Lời gọi subprocess dùng shell=True với WSL không cho phép xác minh tĩnh đích binary.",
                }
            )

    return list(candidates.values()), issues


def _extract_wsl_target_from_py_ast(tree: ast.AST) -> dict[str, Any] | None:
    """Backward-compatible helper returning a unique WSL target only if unambiguous and resolvable."""
    cands, issues = _collect_wsl_candidates_from_py_ast(tree)
    if issues or len(cands) != 1:
        return None
    return cands[0]


def _resolve_local_python_module_files(
    mod_name: str,
    *,
    search_roots: list[Path],
    imported_names: list[str] | None = None,
) -> list[Path]:
    """Resolve a Python module name ONLY within trusted local wrapper/bridge directories (never stdlib/site-packages)."""
    parts = [p for p in mod_name.split(".") if p]
    if not parts:
        return []
    found: list[Path] = []
    seen_p: set[Path] = set()

    def _add(p: Path) -> None:
        try:
            if p.is_file():
                rp = p.resolve(strict=True)
                if rp not in seen_p:
                    seen_p.add(rp)
                    found.append(rp)
        except OSError:
            return

    for root in search_roots:
        if not root.is_dir():
            continue
        # Intermediate package __init__.py files
        cur = root
        for seg in parts[:-1]:
            cur = cur / seg
            _add(cur / "__init__.py")
        leaf_base = root.joinpath(*parts)
        _add(leaf_base.with_suffix(".py"))
        pkg_init = leaf_base / "__init__.py"
        _add(pkg_init)
        if imported_names and leaf_base.is_dir():
            for nm in imported_names:
                if nm == "*" or not nm:
                    continue
                _add((leaf_base / nm).with_suffix(".py"))
                _add(leaf_base / nm / "__init__.py")
    return found


def _inspect_python_script_static(
    py_path: Path,
    *,
    wrapper_root: Path,
    is_entry_script: bool = True,
    imported_entry_names: set[str] | None = None,
) -> tuple[list[Path], list[Path], list[dict[str, Any]], list[dict[str, str]], dict[Path, set[str]]]:
    """Parse a local Python bridge/dependency statically via `ast` (never executes code).

    Returns `(local_py_deps, referenced_scripts, wsl_candidates, issues, dep_entry_names)`.
    Trust boundary: resolves imports strictly inside `[py_path.parent, wrapper_root]` and any static
    local `sys.path` subdirectories under `wrapper_root` (excludes Python stdlib & site-packages).
    """
    issues: list[dict[str, str]] = []
    try:
        st_size = py_path.stat().st_size
        if st_size > _MAX_WRAPPER_INSPECT_BYTES:
            issues.append(
                {
                    "code": "WRAPPER_INSPECTION_FAILED",
                    "detail": f"Tệp Python vượt giới hạn kích thước phân tích ({st_size} > {_MAX_WRAPPER_INSPECT_BYTES}): {py_path}",
                }
            )
            return [], [], [], issues, {}
        text = py_path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(text, filename=str(py_path))
    except (OSError, SyntaxError, ValueError) as exc:
        issues.append(
            {
                "code": "WRAPPER_INSPECTION_FAILED",
                "detail": f"Không thể phân tích cú pháp/đọc tệp Python trong chuỗi thực thi ({py_path}): {type(exc).__name__}",
            }
        )
        return [], [], [], issues, {}

    nodes = list(ast.walk(tree))
    wrapper_root_resolved = wrapper_root.resolve()
    py_parent_resolved = py_path.parent.resolve()

    search_roots: list[Path] = []
    for cand_dir in (py_parent_resolved, wrapper_root_resolved):
        if cand_dir not in search_roots:
            search_roots.append(cand_dir)

    # Detect static local sys.path.insert/append(<path>) pointing inside wrapper_root
    for node in nodes:
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ("insert", "append") and isinstance(node.func.value, ast.Attribute):
                if (
                    node.func.value.attr == "path"
                    and isinstance(node.func.value.value, ast.Name)
                    and node.func.value.value.id == "sys"
                ):
                    for arg in node.args:
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value.strip():
                            try:
                                p = Path(arg.value)
                                if not p.is_absolute():
                                    p = (py_parent_resolved / p).resolve()
                                else:
                                    p = p.resolve()
                                if p.is_dir() and p.is_relative_to(wrapper_root_resolved) and p not in search_roots:
                                    search_roots.append(p)
                            except OSError:
                                pass

    local_deps: list[Path] = []
    seen_deps: set[Path] = set()
    ref_scripts: list[Path] = []
    seen_scripts: set[Path] = set()
    mod_attr_bindings: list[tuple[tuple[str, ...], list[Path]]] = []
    from_symbol_bindings: list[tuple[str, str, list[Path]]] = []
    wildcard_deps: set[Path] = set()

    def _collect(paths: list[Path]) -> None:
        for p in paths:
            if p not in seen_deps:
                seen_deps.add(p)
                local_deps.append(p)

    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name:
                    hits = _resolve_local_python_module_files(alias.name, search_roots=search_roots)
                    _collect(hits)
                    if hits:
                        prefix = (alias.asname,) if alias.asname else tuple(p for p in alias.name.split(".") if p)
                        if prefix:
                            mod_attr_bindings.append((prefix, hits))
        elif isinstance(node, ast.ImportFrom):
            names = [a.name for a in node.names if a.name]
            if node.level and node.level > 0:
                base_dir = py_parent_resolved
                for _ in range(node.level - 1):
                    base_dir = base_dir.parent
                rel_roots = [base_dir]
                if node.module:
                    hits = _resolve_local_python_module_files(node.module, search_roots=rel_roots, imported_names=names)
                else:
                    hits = []
                    for nm in names:
                        if nm != "*":
                            hits.extend(_resolve_local_python_module_files(nm, search_roots=rel_roots))
                if not hits:
                    issues.append(
                        {
                            "code": "WRAPPER_TARGET_UNRESOLVED",
                            "detail": f"Không phân giải được relative import trong {py_path.name}: level={node.level} module={node.module!r}",
                        }
                    )
                _collect(hits)
                if hits:
                    for alias in node.names:
                        if alias.name == "*":
                            wildcard_deps.update(hits)
                        elif alias.name:
                            bound = alias.asname or alias.name
                            sub_hits = [p for p in hits if p.stem == alias.name or (p.name == "__init__.py" and p.parent.name == alias.name)]
                            if sub_hits:
                                mod_attr_bindings.append(((bound,), sub_hits))
                            other_hits = [p for p in hits if p not in sub_hits]
                            if other_hits:
                                from_symbol_bindings.append((bound, alias.name, other_hits))
            elif node.module:
                hits = _resolve_local_python_module_files(node.module, search_roots=search_roots, imported_names=names)
                if not hits:
                    top_pkg = node.module.split(".", 1)[0]
                    if any((sr / top_pkg).is_dir() for sr in search_roots):
                        issues.append(
                            {
                                "code": "WRAPPER_TARGET_UNRESOLVED",
                                "detail": f"Không phân giải được module cục bộ {node.module!r} trong {py_path.name}.",
                            }
                        )
                _collect(hits)
                if hits:
                    for alias in node.names:
                        if alias.name == "*":
                            wildcard_deps.update(hits)
                        elif alias.name:
                            bound = alias.asname or alias.name
                            sub_hits = [p for p in hits if p.stem == alias.name or (p.name == "__init__.py" and p.parent.name == alias.name)]
                            if sub_hits:
                                mod_attr_bindings.append(((bound,), sub_hits))
                            other_hits = [p for p in hits if p not in sub_hits]
                            if other_hits:
                                from_symbol_bindings.append((bound, alias.name, other_hits))
        elif isinstance(node, ast.Call):
            # Static `importlib.import_module("mod")` or `__import__("mod")`
            is_dyn_import = False
            if isinstance(node.func, ast.Name) and node.func.id == "__import__":
                is_dyn_import = True
            elif isinstance(node.func, ast.Attribute) and node.func.attr == "import_module":
                is_dyn_import = True
            if is_dyn_import:
                if not node.args or not (isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str) and node.args[0].value.strip()):
                    issues.append(
                        {
                            "code": "WRAPPER_DYNAMIC_DEPENDENCY_UNVERIFIABLE",
                            "detail": f"Phát hiện import động không thể xác minh tĩnh trong {py_path.name}.",
                        }
                    )
                else:
                    mod_arg = node.args[0].value.strip()
                    hits = _resolve_local_python_module_files(mod_arg, search_roots=search_roots)
                    if not hits and (mod_arg.startswith(".") or any((sr / mod_arg.split(".", 1)[0]).is_dir() for sr in search_roots)):
                        issues.append(
                            {
                                "code": "WRAPPER_TARGET_UNRESOLVED",
                                "detail": f"Không phân giải được import động cục bộ {mod_arg!r} trong {py_path.name}.",
                            }
                        )
                    _collect(hits)
                    wildcard_deps.update(hits)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            val = node.value.strip()
            if val and val.lower().endswith(_WRAPPER_SCRIPT_SUFFIXES) and "\n" not in val and len(val) <= 260:
                try:
                    p = Path(val)
                    if not p.is_absolute():
                        p = py_parent_resolved / p
                    if p.is_file():
                        rp = p.resolve(strict=True)
                        if rp.is_relative_to(wrapper_root_resolved) and rp not in seen_scripts:
                            seen_scripts.add(rp)
                            ref_scripts.append(rp)
                except OSError:
                    pass

    reachable_refs: dict[str, set[Any]] | None = (
        {"dotted_attrs": set(), "called_or_loaded": set(), "getattr_targets": set()}
        if local_deps
        else None
    )
    wsl_cands, wsl_issues = _collect_wsl_candidates_from_py_ast(
        tree,
        nodes=nodes,
        is_entry_script=is_entry_script,
        imported_entry_names=imported_entry_names,
        out_reachable_refs=reachable_refs,
    )
    issues.extend(wsl_issues)

    dep_entry_names: dict[Path, set[str]] = {}
    for p in wildcard_deps:
        dep_entry_names.setdefault(p, set()).add("*")
    if reachable_refs is not None:
        dotted_attrs: set[tuple[str, ...]] = reachable_refs["dotted_attrs"]
        called_or_loaded: set[str] = reachable_refs["called_or_loaded"]
        getattr_targets: set[str] = reachable_refs["getattr_targets"]
        for prefix, paths in mod_attr_bindings:
            plen = len(prefix)
            if plen == 1 and prefix[0] in getattr_targets:
                for p in paths:
                    dep_entry_names.setdefault(p, set()).add("*")
            for chain in dotted_attrs:
                if len(chain) > plen and chain[:plen] == prefix:
                    for p in paths:
                        dep_entry_names.setdefault(p, set()).add(chain[plen])
        for bound_name, orig_name, paths in from_symbol_bindings:
            if bound_name in called_or_loaded or any(ch[0] == bound_name for ch in dotted_attrs):
                for p in paths:
                    dep_entry_names.setdefault(p, set()).add(orig_name)

    return local_deps, ref_scripts, wsl_cands, issues, dep_entry_names


def _tokenize_wrapper_line(line: str, base_dir: Path) -> list[str]:
    expanded = re.sub(
        r"%~dp0[\\/]?",
        lambda _m: str(base_dir) + os.sep,
        line,
        flags=re.IGNORECASE,
    )
    tokens: list[str] = []
    for m in re.finditer(r'"([^"]*)"|\'([^\']*)\'|([^\s"\']+)', expanded):
        tok = (m.group(1) if m.group(1) is not None else (m.group(2) if m.group(2) is not None else m.group(3)) or "").strip()
        if tok:
            tokens.append(tok)
    return tokens


def _resolve_wrapper_exe_token(token: str, base_dir: Path) -> tuple[bool, Path | None]:
    """Resolve an `.exe` token referenced by a shell/batch/ps1 wrapper; fails closed if missing or unexpanded."""
    cand = token.strip()
    if not cand:
        return True, None
    # Expand known Windows system env vars (`%SystemRoot%`, `%WINDIR%`), fail closed on unknown `%VAR%`/`$VAR`.
    if "%" in cand:
        for var_name in ("SystemRoot", "WINDIR"):
            val = os.environ.get(var_name)
            if val:
                cand = re.sub(rf"%{var_name}%", lambda _m: val, cand, flags=re.IGNORECASE)
        if re.search(r"%[^%]+%", cand):
            return False, None
    if cand.startswith("$") or "${" in cand:
        return False, None
    try:
        p = Path(cand)
        if p.is_absolute() or (os.name == "nt" and len(cand) >= 2 and cand[1] == ":"):
            if p.is_file():
                return True, p.resolve(strict=True)
            return False, None
        rel = base_dir / p
        if rel.is_file():
            return True, rel.resolve(strict=True)
        found = shutil.which(cand)
        if found and Path(found).is_file():
            return True, Path(found).resolve(strict=True)
    except OSError:
        return False, None
    return False, None


_ISSUE_CODE_PRIORITY = {
    "WSL_TARGET_AMBIGUOUS": 1,
    "WSL_TARGET_UNRESOLVABLE": 2,
    "WRAPPER_TARGET_UNRESOLVED": 3,
    "WRAPPER_DYNAMIC_DEPENDENCY_UNVERIFIABLE": 4,
    "WRAPPER_INSPECTION_FAILED": 5,
    "CHAIN_DEPTH_EXCEEDED": 6,
    "CHAIN_FILE_LIMIT_EXCEEDED": 7,
}


def _inspect_execution_chain(
    wrapper_path: Path,
) -> tuple[list[dict[str, str]], list[dict[str, str]], dict[str, Any], list[dict[str, str]]]:
    """Bounded static inspection of wrapper -> bridge script -> local Python dependency closure + WSL target.

    Returns `(wrapper_targets, wrapper_interpreters, wsl_target, chain_issues)`.
    Fail-closed contract:
    - Exceeding `_MAX_CHAIN_DEPTH` or `_MAX_CHAIN_FILES`, encountering unresolved interpreters/scripts/imports,
      unreadable/unparseable bridge scripts, or multiple/dynamic WSL targets records explicit `chain_issues`
      instead of silently truncating or guessing.
    - Explicitly excludes Python stdlib, site-packages, and OS system binaries (`C:\\Windows\\...`) and
      never hashes unreferenced sibling files in the same directory or audit-log env vars.
    """
    no_wsl = {"detected": False, "distro": None, "linux_binary_path": None}
    if wrapper_path.suffix.lower() not in _WRAPPER_SUFFIXES:
        return [], [], no_wsl, []

    self_resolved = wrapper_path.resolve()
    wrapper_root = self_resolved.parent
    targets_by_path: dict[str, dict[str, str]] = {}
    interpreters_by_path: dict[str, dict[str, str]] = {}
    wsl_candidates: dict[tuple[str | None, str], dict[str, Any]] = {}
    issues: list[dict[str, str]] = []
    seen_issue_keys: set[tuple[str, str]] = set()

    def _append_issues(new_issues: list[dict[str, str]]) -> None:
        for iss in new_issues:
            ik = (str(iss.get("code", "")), str(iss.get("detail", "")))
            if ik not in seen_issue_keys:
                seen_issue_keys.add(ik)
                issues.append(iss)

    queue: list[tuple[Path, int]] = [(self_resolved, 0)]
    visited: set[Path] = {self_resolved}
    dep_is_entry: dict[Path, bool] = {self_resolved: True}
    dep_depth: dict[Path, int] = {self_resolved: 0}
    dep_entry_names_by_path: dict[Path, set[str]] = {}
    inspected_entry_names: dict[Path, set[str]] = {}
    inspected_as_entry: set[Path] = set()

    def _add_target(dep_p: Path, role: str, next_depth: int, *, entry_names: set[str] | None = None) -> None:
        if dep_p == self_resolved:
            return
        as_entry = role != "local_python_dependency"
        if as_entry:
            dep_is_entry[dep_p] = True
        else:
            dep_is_entry.setdefault(dep_p, False)
        if entry_names:
            dep_entry_names_by_path.setdefault(dep_p, set()).update(entry_names)

        key = str(dep_p)
        is_new = key not in targets_by_path
        if is_new and len(targets_by_path) >= _MAX_CHAIN_FILES:
            _append_issues(
                [
                    {
                        "code": "CHAIN_FILE_LIMIT_EXCEEDED",
                        "detail": f"Số tệp phụ thuộc trong chuỗi thực thi vượt giới hạn {_MAX_CHAIN_FILES} ({dep_p.name}).",
                    }
                ]
            )
            return
        if is_new:
            try:
                targets_by_path[key] = {
                    "path": key,
                    "sha256": _sha256_file_stream(dep_p),
                    "role": role,
                }
            except OSError as exc:
                _append_issues(
                    [
                        {
                            "code": "WRAPPER_INSPECTION_FAILED",
                            "detail": f"Không thể đọc hoặc tính SHA-256 của tệp phụ thuộc {dep_p}: {exc}",
                        }
                    ]
                )
                return
        if dep_p not in visited:
            if next_depth > _MAX_CHAIN_DEPTH:
                _append_issues(
                    [
                        {
                            "code": "CHAIN_DEPTH_EXCEEDED",
                            "detail": f"Độ sâu chuỗi phụ thuộc vượt giới hạn {_MAX_CHAIN_DEPTH} tại {dep_p.name}.",
                        }
                    ]
                )
                return
            visited.add(dep_p)
            dep_depth[dep_p] = next_depth
            queue.append((dep_p, next_depth))
        elif dep_p.suffix.lower() == ".py" and all(q_p != dep_p for q_p, _ in queue):
            if as_entry and dep_p not in inspected_as_entry:
                queue.append((dep_p, dep_depth.get(dep_p, next_depth)))
            elif not dep_is_entry.get(dep_p, False) and entry_names:
                already = inspected_entry_names.get(dep_p, set())
                if "*" not in already and (entry_names - already):
                    queue.append((dep_p, dep_depth.get(dep_p, next_depth)))

    while queue:
        cur_path, depth = queue.pop(0)
        suffix = cur_path.suffix.lower()
        if suffix == ".py":
            is_entry = dep_is_entry.get(cur_path, True)
            cur_entry_names = None if is_entry else set(dep_entry_names_by_path.get(cur_path, set()))
            if is_entry:
                inspected_as_entry.add(cur_path)
            else:
                inspected_entry_names.setdefault(cur_path, set()).update(cur_entry_names or set())
            local_deps, ref_scripts, py_wsl_cands, py_issues, py_dep_entry_names = _inspect_python_script_static(
                cur_path,
                wrapper_root=wrapper_root,
                is_entry_script=is_entry,
                imported_entry_names=cur_entry_names,
            )
            _append_issues(py_issues)
            for wc in py_wsl_cands:
                wkey = (wc.get("distro"), str(wc["linux_binary_path"]))
                wsl_candidates[wkey] = wc
            for dep_p in local_deps:
                _add_target(
                    dep_p,
                    "local_python_dependency",
                    depth + 1,
                    entry_names=py_dep_entry_names.get(dep_p),
                )
            for sc_p in ref_scripts:
                _add_target(sc_p, "referenced_script", depth + 1)
            continue

        # Shell / Batch / PowerShell wrapper text inspection (supports LF and CRLF)
        try:
            st_size = cur_path.stat().st_size
            if st_size > _MAX_WRAPPER_INSPECT_BYTES:
                issues.append(
                    {
                        "code": "WRAPPER_INSPECTION_FAILED",
                        "detail": f"Tệp wrapper vượt giới hạn kích thước ({st_size} > {_MAX_WRAPPER_INSPECT_BYTES}): {cur_path}",
                    }
                )
                continue
            text = cur_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            issues.append(
                {
                    "code": "WRAPPER_INSPECTION_FAILED",
                    "detail": f"Không thể đọc tệp wrapper {cur_path}: {exc}",
                }
            )
            continue

        for raw_line in text.splitlines():
            stripped = raw_line.strip()
            if not stripped:
                continue
            low_line = stripped.lower()
            if suffix in (".cmd", ".bat"):
                if low_line.startswith("@"):
                    stripped = stripped[1:].strip()
                    low_line = stripped.lower()
                if low_line == "echo off" or low_line == "echo on":
                    continue
                if low_line.startswith("rem ") or low_line == "rem" or stripped.startswith("::"):
                    continue
                # Environment variable assignment (e.g. `set NTK_G1_OPENGREP_AUDIT_LOG=...`): never treat as executable
                if re.match(r"^set\s+[A-Za-z_][A-Za-z0-9_]*=", stripped, re.IGNORECASE):
                    continue
            else:
                if stripped.startswith("#"):
                    continue
                if re.match(r"^(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*=", stripped):
                    continue

            line_tokens = _tokenize_wrapper_line(stripped, cur_path.parent)
            if not line_tokens:
                continue

            if any(_is_wsl_executable_token(t) for t in line_tokens):
                line_wsl = _extract_wsl_target_from_tokens(line_tokens)
                if line_wsl is None:
                    issues.append(
                        {
                            "code": "WSL_TARGET_UNRESOLVABLE",
                            "detail": f"Tìm thấy lệnh WSL trong {cur_path.name} nhưng không cố định được binary Linux.",
                        }
                    )
                else:
                    wkey = (line_wsl.get("distro"), str(line_wsl["linux_binary_path"]))
                    wsl_candidates[wkey] = line_wsl

            for token in line_tokens:
                if token in ("%*", "$@", "$*") or re.fullmatch(r"%[0-9]|\$[0-9]", token):
                    continue
                low_tok = token.lower()
                if low_tok.endswith(_WRAPPER_SCRIPT_SUFFIXES):
                    if "%" in token or "$" in token:
                        issues.append(
                            {
                                "code": "WRAPPER_TARGET_UNRESOLVED",
                                "detail": f"Đường dẫn script chứa biến môi trường chưa mở rộng: {token!r}",
                            }
                        )
                        continue
                    try:
                        p = Path(token)
                        if not p.is_absolute():
                            p = cur_path.parent / p
                        if not p.is_file():
                            issues.append(
                                {
                                    "code": "WRAPPER_TARGET_UNRESOLVED",
                                    "detail": f"Không tìm thấy script đích trong wrapper {cur_path.name}: {token!r}",
                                }
                            )
                            continue
                        rp = p.resolve(strict=True)
                    except OSError as exc:
                        issues.append(
                            {
                                "code": "WRAPPER_TARGET_UNRESOLVED",
                                "detail": f"Không phân giải được script đích {token!r} trong {cur_path.name}: {exc}",
                            }
                        )
                        continue
                    _add_target(rp, "bridge_script" if depth == 0 else "referenced_script", depth + 1)
                elif low_tok.endswith(_INTERPRETER_SUFFIXES):
                    ok_exe, rp_exe = _resolve_wrapper_exe_token(token, cur_path.parent)
                    if not ok_exe or rp_exe is None:
                        issues.append(
                            {
                                "code": "WRAPPER_TARGET_UNRESOLVED",
                                "detail": f"Không tìm thấy executable/interpreter trong wrapper {cur_path.name}: {token!r}",
                            }
                        )
                        continue
                    if rp_exe != self_resolved and not _is_windows_system_path(rp_exe):
                        key = str(rp_exe)
                        if key not in interpreters_by_path:
                            try:
                                interpreters_by_path[key] = {
                                    "path": key,
                                    "sha256": _sha256_file_stream(rp_exe),
                                    "role": "wrapper_interpreter",
                                }
                            except OSError as exc:
                                issues.append(
                                    {
                                        "code": "WRAPPER_INSPECTION_FAILED",
                                        "detail": f"Không thể tính SHA-256 interpreter {rp_exe}: {exc}",
                                    }
                                )

    if len(wsl_candidates) > 1:
        issues.append(
            {
                "code": "WSL_TARGET_AMBIGUOUS",
                "detail": f"Phát hiện nhiều đích WSL khác nhau trong chuỗi thực thi ({len(wsl_candidates)} ứng viên).",
            }
        )
        wsl_target = dict(no_wsl)
    elif len(wsl_candidates) == 1 and not any(iss["code"] == "WSL_TARGET_UNRESOLVABLE" for iss in issues):
        wsl_target = next(iter(wsl_candidates.values()))
    else:
        wsl_target = dict(no_wsl)

    targets_list = [targets_by_path[k] for k in sorted(targets_by_path)]
    interps_list = [interpreters_by_path[k] for k in sorted(interpreters_by_path)]
    return targets_list, interps_list, wsl_target, issues


def _extract_wrapper_targets(wrapper_path: Path) -> list[dict[str, str]]:
    """Backward-compatible wrapper returning direct & transitive script/local-module targets."""
    targets, _interps, _wsl, _issues = _inspect_execution_chain(wrapper_path)
    return targets


def inspect_opengrep_binary_identity(binary: str) -> dict[str, Any]:
    """Validate OpenGrep binary name, resolve local path, and fingerprint full local execution chain + WSL target."""
    empty_wsl = {"detected": False, "distro": None, "linux_binary_path": None}
    try:
        validate_opengrep_binary(binary)
    except ValueError as exc:
        return {
            "found": False,
            "binary_exists": False,
            "identity_complete": False,
            "executable": binary,
            "resolved_path": None,
            "executable_sha256": None,
            "wrapper_targets": [],
            "wrapper_interpreters": [],
            "wsl_target": dict(empty_wsl),
            "binary_identity_sha256": None,
            "chain_issues": [],
            "failure_code": "BINARY_INVALID",
            "error": str(exc),
        }

    resolved_raw = binary if Path(binary).is_file() else shutil.which(binary)
    if not resolved_raw:
        return {
            "found": False,
            "binary_exists": False,
            "identity_complete": False,
            "executable": binary,
            "resolved_path": None,
            "executable_sha256": None,
            "wrapper_targets": [],
            "wrapper_interpreters": [],
            "wsl_target": dict(empty_wsl),
            "binary_identity_sha256": None,
            "chain_issues": [],
            "failure_code": "BINARY_NOT_FOUND",
            "error": f"Không tìm thấy binary OpenGrep ({binary!r}) trên đĩa hoặc trong PATH.",
        }

    try:
        resolved_path = Path(resolved_raw).resolve(strict=True)
        if not resolved_path.is_file():
            raise OSError("not a regular file")
        exec_sha = _sha256_file_stream(resolved_path)
        targets, interpreters, wsl_target, chain_issues = _inspect_execution_chain(resolved_path)
    except OSError as exc:
        return {
            "found": False,
            "binary_exists": False,
            "identity_complete": False,
            "executable": binary,
            "resolved_path": str(resolved_raw),
            "executable_sha256": None,
            "wrapper_targets": [],
            "wrapper_interpreters": [],
            "wsl_target": dict(empty_wsl),
            "binary_identity_sha256": None,
            "chain_issues": [],
            "failure_code": "BINARY_UNREADABLE",
            "error": f"Không thể đọc hoặc tính SHA-256 của binary OpenGrep ({resolved_raw}): {exc}",
        }

    if chain_issues:
        ordered = sorted(
            chain_issues,
            key=lambda iss: _ISSUE_CODE_PRIORITY.get(str(iss.get("code") or ""), 99),
        )
        primary_issue = ordered[0]
        return {
            "found": False,
            "binary_exists": True,
            "identity_complete": False,
            "executable": binary,
            "resolved_path": str(resolved_path),
            "executable_sha256": exec_sha,
            "wrapper_targets": targets,
            "wrapper_interpreters": interpreters,
            "wsl_target": wsl_target,
            "binary_identity_sha256": None,
            "chain_issues": ordered,
            "failure_code": primary_issue["code"],
            "error": primary_issue["detail"],
        }

    identity_doc = {
        "resolved_path": str(resolved_path),
        "executable_sha256": exec_sha,
        "wrapper_targets": targets,
        "wrapper_interpreters": interpreters,
        "wsl_target": wsl_target,
    }
    identity_sha = digest(json.dumps(identity_doc, sort_keys=True, ensure_ascii=False).encode("utf-8"))
    return {
        "found": True,
        "binary_exists": True,
        "identity_complete": True,
        "executable": binary,
        "resolved_path": str(resolved_path),
        "executable_sha256": exec_sha,
        "wrapper_targets": targets,
        "wrapper_interpreters": interpreters,
        "wsl_target": wsl_target,
        "binary_identity_sha256": identity_sha,
        "chain_issues": [],
        "failure_code": None,
        "error": None,
    }


def _extract_cwe_codes(raw_cwe: Any) -> set[str]:
    values = raw_cwe if isinstance(raw_cwe, list) else [raw_cwe]
    out: set[str] = set()
    for val in values:
        if val is None:
            continue
        for m in _CWE_CODE_RE.finditer(str(val)):
            out.add(f"CWE-{int(m.group(1))}")
    return out


def inspect_rules_for_canary(rules_path: Path) -> dict[str, Any]:
    """Read rules_path once, compute SHA-256, validate YAML schema, and enforce fixed CWE-22 + CWE-89 scope."""
    fixed_expected = list(REQUIRED_CANARY_CWES)
    try:
        raw_bytes = Path(rules_path).read_bytes()
    except OSError as exc:
        return {
            "ok": False,
            "rules_sha256": None,
            "_raw_bytes": None,
            "expected_cwes": fixed_expected,
            "missing_required_cwes": list(fixed_expected),
            "cwe_rule_ids": {},
            "cwe_taint_only": {},
            "failure_code": "RULES_UNREADABLE",
            "error": f"Không thể đọc tệp tập luật OpenGrep ({rules_path}): {exc}",
        }

    rules_sha = digest(raw_bytes)
    try:
        parsed = yaml.safe_load(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        return {
            "ok": False,
            "rules_sha256": rules_sha,
            "_raw_bytes": raw_bytes,
            "expected_cwes": fixed_expected,
            "missing_required_cwes": list(fixed_expected),
            "cwe_rule_ids": {},
            "cwe_taint_only": {},
            "failure_code": "RULES_INVALID",
            "error": f"Tệp tập luật OpenGrep không phải YAML UTF-8 hợp lệ: {exc}",
        }

    if not isinstance(parsed, dict) or not isinstance(parsed.get("rules"), list) or not parsed["rules"]:
        return {
            "ok": False,
            "rules_sha256": rules_sha,
            "_raw_bytes": raw_bytes,
            "expected_cwes": fixed_expected,
            "missing_required_cwes": list(fixed_expected),
            "cwe_rule_ids": {},
            "cwe_taint_only": {},
            "failure_code": "RULES_INVALID",
            "error": "Tệp tập luật OpenGrep không chứa danh sách rules hợp lệ hoặc danh sách rỗng.",
        }

    cwe_rule_ids: dict[str, list[str]] = {}
    cwe_modes: dict[str, set[str]] = {}
    rule_modes: dict[str, str] = {}
    for rule in parsed["rules"]:
        if not isinstance(rule, dict):
            return {
                "ok": False,
                "rules_sha256": rules_sha,
                "_raw_bytes": raw_bytes,
                "expected_cwes": fixed_expected,
                "missing_required_cwes": list(fixed_expected),
                "cwe_rule_ids": {},
                "cwe_taint_only": {},
                "cwe_has_taint": {},
                "rule_modes": {},
                "failure_code": "RULES_INVALID",
                "error": "Tệp tập luật OpenGrep chứa phần tử rule không hợp lệ.",
            }
        rid = rule.get("id")
        if not isinstance(rid, str) or not rid.strip():
            return {
                "ok": False,
                "rules_sha256": rules_sha,
                "_raw_bytes": raw_bytes,
                "expected_cwes": fixed_expected,
                "missing_required_cwes": list(fixed_expected),
                "cwe_rule_ids": {},
                "cwe_taint_only": {},
                "cwe_has_taint": {},
                "rule_modes": {},
                "failure_code": "RULES_INVALID",
                "error": "Tệp tập luật OpenGrep chứa rule thiếu trường id hợp lệ.",
            }
        langs_raw = rule.get("languages")
        langs = {str(x).strip().lower() for x in langs_raw} if isinstance(langs_raw, list) else set()
        if "java" not in langs:
            continue
        meta = rule.get("metadata")
        cwes = _extract_cwe_codes(meta.get("cwe") if isinstance(meta, dict) else None)
        mode = str(rule.get("mode") or "search").strip().lower()
        rid_clean = rid.strip()
        for cwe in cwes & _PRIORITY_CWES:
            cwe_rule_ids.setdefault(cwe, []).append(rid_clean)
            cwe_modes.setdefault(cwe, set()).add(mode)
            rule_modes[rid_clean] = mode

    missing_required = [cwe for cwe in REQUIRED_CANARY_CWES if not cwe_rule_ids.get(cwe)]
    if missing_required:
        return {
            "ok": False,
            "rules_sha256": rules_sha,
            "_raw_bytes": raw_bytes,
            "expected_cwes": fixed_expected,
            "missing_required_cwes": missing_required,
            "cwe_rule_ids": cwe_rule_ids,
            "cwe_taint_only": {cwe: (cwe_modes.get(cwe) == {"taint"}) for cwe in cwe_rule_ids},
            "cwe_has_taint": {cwe: ("taint" in cwe_modes.get(cwe, set())) for cwe in cwe_rule_ids},
            "rule_modes": rule_modes,
            "failure_code": "RULES_MISSING_REQUIRED_CWE",
            "error": (
                "Tệp tập luật OpenGrep thiếu quy tắc Java bắt buộc theo phạm vi CWE-22 và CWE-89: "
                f"{', '.join(missing_required)}."
            ),
        }

    cwe_taint_only = {cwe: (cwe_modes.get(cwe) == {"taint"}) for cwe in fixed_expected}
    cwe_has_taint = {cwe: ("taint" in cwe_modes.get(cwe, set())) for cwe in fixed_expected}
    return {
        "ok": True,
        "rules_sha256": rules_sha,
        "_raw_bytes": raw_bytes,
        "expected_cwes": fixed_expected,
        "missing_required_cwes": [],
        "cwe_rule_ids": cwe_rule_ids,
        "cwe_taint_only": cwe_taint_only,
        "cwe_has_taint": cwe_has_taint,
        "rule_modes": rule_modes,
        "failure_code": None,
        "error": None,
    }


def _canonicalize_canary_path(raw_path: Any) -> str | None:
    """Normalize a canary path across Windows (`C:\\...`), slash (`C:/...`), and WSL (`/mnt/c/...`) formats.

    Preserves directory structure (never collapses to basename) and rejects traversal (`..`) or non-canary files.
    """
    if not isinstance(raw_path, str):
        return None
    cleaned = raw_path.strip()
    if not cleaned or "\x00" in cleaned:
        return None
    norm = cleaned.replace("\\", "/")
    if ".." in norm.split("/"):
        return None
    m_mnt = re.match(r"^/mnt/([A-Za-z])(/.*)?$", norm)
    if m_mnt:
        drive = m_mnt.group(1).lower()
        rest = m_mnt.group(2) or "/"
        norm = f"{drive}:{rest}"
    elif re.match(r"^[A-Za-z]:/", norm):
        norm = norm[0].lower() + norm[1:]
    elif re.match(r"^[A-Za-z]:\\", cleaned):
        norm = norm[0].lower() + norm[1:]
    if norm.startswith("/"):
        norm_p = PurePosixPath(norm)
        parts = [p for p in norm_p.parts if p not in ("", "/")]
        canonical = "/" + "/".join(parts)
    elif re.match(r"^[a-z]:/", norm):
        drv = norm[:2]
        rest = norm[2:]
        parts = [p for p in rest.split("/") if p]
        canonical = drv + "/" + "/".join(parts)
    else:
        parts = [p for p in norm.split("/") if p and p != "."]
        canonical = "/".join(parts)
    if not canonical:
        return None
    base = canonical.rsplit("/", 1)[-1]
    if base != HEALTH_CANARY_FILENAME:
        return None
    if os.name == "nt" and re.match(r"^[a-z]:/", canonical):
        return canonical.lower()
    return canonical


def _path_is_canary_fixture(raw_path: Any) -> bool:
    return _canonicalize_canary_path(raw_path) is not None


def _build_canary_offset_table(source_bytes: bytes) -> dict[str, Any]:
    text = source_bytes.decode("utf-8")
    lines_with_eol = source_bytes.splitlines(keepends=True)
    lines_no_eol = text.splitlines()
    line_byte_starts: list[int] = [0]
    acc = 0
    for chunk in lines_with_eol:
        acc += len(chunk)
        line_byte_starts.append(acc)
    return {
        "bytes": source_bytes,
        "lines": lines_no_eol,
        "line_byte_starts": line_byte_starts,
    }


_CANARY_TABLE_LF = _build_canary_offset_table(HEALTH_CANARY_SOURCE.encode("utf-8"))
_CANARY_TABLE_CRLF = _build_canary_offset_table(HEALTH_CANARY_SOURCE.replace("\n", "\r\n").encode("utf-8"))


def _slice_canary_loc(
    loc: Any,
    *,
    require_offset: bool = False,
    expected_bytes_table: dict[str, Any] | None = None,
    mode_box: dict[str, str | None] | None = None,
) -> str | None:
    """Validate `(start, end)` `line`/`col`/`offset` coordinates against `HEALTH_CANARY_SOURCE` and return exact text slice."""
    if not isinstance(loc, dict):
        return None
    st = loc.get("start")
    en = loc.get("end")
    if not isinstance(st, dict) or not isinstance(en, dict):
        return None
    sl, sc = st.get("line"), st.get("col")
    el, ec = en.get("line"), en.get("col")
    if (
        type(sl) is not int
        or type(el) is not int
        or type(sc) is not int
        or type(ec) is not int
        or sl < 1
        or sc < 1
        or el < sl
        or ec < 1
    ):
        return None
    lines = _CANARY_TABLE_LF["lines"]
    if el > len(lines):
        return None
    if sl == el:
        line_txt = lines[sl - 1]
        if sc > len(line_txt) + 1 or ec > len(line_txt) + 1 or ec <= sc:
            return None
        sliced = line_txt[sc - 1 : ec - 1]
    else:
        first_line = lines[sl - 1]
        last_line = lines[el - 1]
        if sc > len(first_line) + 1 or ec > len(last_line) + 1:
            return None
        parts = [first_line[sc - 1 :]]
        for ln_idx in range(sl + 1, el):
            parts.append(lines[ln_idx - 1])
        parts.append(last_line[: ec - 1])
        sliced = "\n".join(parts)
    if not sliced.strip():
        return None

    has_st_off = "offset" in st
    has_en_off = "offset" in en
    if has_st_off != has_en_off:
        return None
    if require_offset and not has_st_off:
        return None
    if has_st_off:
        so = st.get("offset")
        eo = en.get("offset")
        if type(so) is not int or type(eo) is not int or so < 0 or eo <= so:
            return None
        if expected_bytes_table is not None:
            cand_tables = [("EXACT", expected_bytes_table)]
        else:
            cand_tables = [("LF", _CANARY_TABLE_LF), ("CRLF", _CANARY_TABLE_CRLF)]
        matched_mode: str | None = None
        locked_mode = mode_box.get("mode") if mode_box is not None else None
        for mname, tbl in cand_tables:
            if locked_mode is not None and mname != locked_mode:
                continue
            lstarts = tbl["line_byte_starts"]
            if sl - 1 >= len(lstarts) or el - 1 >= len(lstarts):
                continue
            exp_so = lstarts[sl - 1] + (sc - 1)
            exp_eo = lstarts[el - 1] + (ec - 1)
            if so == exp_so and eo == exp_eo:
                raw_b = tbl["bytes"]
                if eo <= len(raw_b):
                    byte_slice = raw_b[so:eo].decode("utf-8", errors="replace").replace("\r\n", "\n")
                    if byte_slice == sliced:
                        matched_mode = mname
                        break
        if matched_mode is None:
            return None
        if mode_box is not None and mode_box.get("mode") is None:
            mode_box["mode"] = matched_mode
    return sliced


def _extract_trace_node_loc(
    node: Any,
    *,
    role: str,
    canonical_fixture_path: str,
    require_offset: bool = False,
    expected_bytes_table: dict[str, Any] | None = None,
    mode_box: dict[str, str | None] | None = None,
    depth: int = 0,
) -> tuple[str, int, int, str] | None:
    """Parse & strictly verify an OpenGrep 1.25.0 `CliLoc` / `CliCall` node against `HEALTH_CANARY_SOURCE`."""
    if depth > 12 or not isinstance(node, list) or len(node) != 2:
        return None
    kind, payload = node[0], node[1]
    if kind == "CliLoc":
        if not isinstance(payload, list) or len(payload) != 2:
            return None
        loc, content = payload[0], payload[1]
        if not isinstance(loc, dict) or not isinstance(content, str) or not content.strip():
            return None
        canon_p = _canonicalize_canary_path(loc.get("path"))
        if canon_p is None or canon_p != canonical_fixture_path:
            return None
        sliced = _slice_canary_loc(
            loc,
            require_offset=require_offset,
            expected_bytes_table=expected_bytes_table,
            mode_box=mode_box,
        )
        if sliced is None or sliced != content:
            return None
        st = loc["start"]
        en = loc["end"]
        return canon_p, st["line"], en["line"], content
    if kind == "CliCall":
        if not isinstance(payload, list) or len(payload) != 3:
            return None
        call_site, call_steps, inner = payload
        if (
            not isinstance(call_site, list)
            or len(call_site) != 2
            or not isinstance(call_site[0], dict)
            or not isinstance(call_site[1], str)
            or not isinstance(call_steps, list)
        ):
            return None
        cs_loc, cs_txt = call_site
        cs_canon = _canonicalize_canary_path(cs_loc.get("path"))
        if cs_canon is None or cs_canon != canonical_fixture_path:
            return None
        cs_slice = _slice_canary_loc(
            cs_loc,
            require_offset=require_offset,
            expected_bytes_table=expected_bytes_table,
            mode_box=mode_box,
        )
        if cs_slice is None or cs_slice != cs_txt:
            return None
        return _extract_trace_node_loc(
            inner,
            role=role,
            canonical_fixture_path=canonical_fixture_path,
            require_offset=require_offset,
            expected_bytes_table=expected_bytes_table,
            mode_box=mode_box,
            depth=depth + 1,
        )
    return None


def _validate_canary_dataflow_trace(
    trace: Any,
    *,
    expected_source_line: int,
    expected_sink_line: int,
    expected_cwe: str,
    canonical_fixture_path: str,
    require_offset: bool = False,
    expected_bytes_table: dict[str, Any] | None = None,
    mode_box: dict[str, str | None] | None = None,
) -> bool:
    """Strictly verify OpenGrep 1.25.0 `dataflow_trace` paths, spans, byte offsets, and exact source/sink content."""
    if not isinstance(trace, dict):
        return False
    src_parsed = _extract_trace_node_loc(
        trace.get("taint_source"),
        role="source",
        canonical_fixture_path=canonical_fixture_path,
        require_offset=require_offset,
        expected_bytes_table=expected_bytes_table,
        mode_box=mode_box,
    )
    sink_parsed = _extract_trace_node_loc(
        trace.get("taint_sink"),
        role="sink",
        canonical_fixture_path=canonical_fixture_path,
        require_offset=require_offset,
        expected_bytes_table=expected_bytes_table,
        mode_box=mode_box,
    )
    if src_parsed is None or sink_parsed is None:
        return False
    src_path, src_sl, src_el, src_txt = src_parsed
    sink_path, sink_sl, sink_el, sink_txt = sink_parsed
    if src_path != canonical_fixture_path or sink_path != canonical_fixture_path:
        return False
    if src_sl != expected_source_line or src_el != expected_source_line:
        return False
    if sink_sl != expected_sink_line or sink_el != expected_sink_line:
        return False
    if src_sl >= sink_sl:
        return False

    if expected_cwe == "CWE-89":
        if 'req.getParameter("id")' not in src_txt:
            return False
        if '"SELECT * FROM users WHERE id=" + id' not in sink_txt and "st.executeQuery(" not in sink_txt:
            return False
    elif expected_cwe == "CWE-22":
        if 'req.getParameter("file")' not in src_txt:
            return False
        if '"/srv/data/" + name' not in sink_txt and "new FileInputStream(" not in sink_txt:
            return False

    inter = trace.get("intermediate_vars")
    if inter is not None:
        if not isinstance(inter, list):
            return False
        for step in inter:
            if not isinstance(step, dict):
                return False
            loc = step.get("location")
            content = step.get("content")
            if not isinstance(loc, dict) or not isinstance(content, str) or not content.strip():
                return False
            if _canonicalize_canary_path(loc.get("path")) != canonical_fixture_path:
                return False
            sliced = _slice_canary_loc(
                loc,
                require_offset=require_offset,
                expected_bytes_table=expected_bytes_table,
                mode_box=mode_box,
            )
            if sliced is None or sliced != content:
                return False
            st_ln = loc["start"]["line"]
            if st_ln < expected_source_line or st_ln > expected_sink_line:
                return False
    return True


def verify_canary_scan_output(
    raw_stdout: bytes,
    *,
    expected_version_tuple: tuple[int, int, int],
    rules_info: dict[str, Any],
    expected_canary_path: str | Path | None = None,
    expected_canary_bytes: bytes | None = None,
    require_offset: bool | None = None,
) -> tuple[bool, bool, dict[str, Any], str | None, str | None]:
    """Validate OpenGrep canary JSON envelope and fixed CWE-22 + CWE-89 oracle assertions.

    Returns `(scan_executed, scan_verified, canary_summary, failure_code, error_message)`.
    `scan_executed=True` means OpenGrep produced valid strict JSON with 0 errors and valid finding schema;
    `scan_verified=True` additionally requires the canary findings to match the exact CWE/line/col/offset/
    content/canonical-path/per-rule-trace/safe-control oracle.
    """
    fixed_expected_cwes = list(REQUIRED_CANARY_CWES)
    base_summary: dict[str, Any] = {
        "fixture": HEALTH_CANARY_FILENAME,
        "fixture_sha256": HEALTH_CANARY_SHA256,
        "expected_cwes": fixed_expected_cwes,
        "observed_cwes": [],
        "findings_count": None,
        "errors_count": None,
        "safe_control_clean": None,
        "oracle_matched": False,
    }
    try:
        text = raw_stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        return False, False, base_summary, "INVALID_JSON_ENCODING", f"Đầu ra JSON của OpenGrep không phải UTF-8: {exc}"

    try:
        doc = strict_json(text)
    except EvidenceError as exc:
        return False, False, base_summary, "INVALID_JSON", f"Đầu ra JSON của OpenGrep không hợp lệ: {exc}"

    if not isinstance(doc, dict) or not isinstance(doc.get("results"), list):
        return (
            False,
            False,
            base_summary,
            "INVALID_JSON_ENVELOPE",
            "Đầu ra OpenGrep thiếu cấu trúc JSON {results: [...]} hợp lệ.",
        )

    if "errors" not in doc or not isinstance(doc.get("errors"), list):
        return (
            False,
            False,
            base_summary,
            "INVALID_JSON_ENVELOPE",
            "Đầu ra OpenGrep thiếu trường errors dạng danh sách hợp lệ.",
        )
    errors_list = doc["errors"]
    base_summary["errors_count"] = len(errors_list)
    if errors_list:
        return (
            False,
            False,
            base_summary,
            "OPENGREP_SCAN_ERRORS",
            f"OpenGrep báo {len(errors_list)} lỗi khi quét canary fixture.",
        )

    results = doc["results"]
    base_summary["findings_count"] = len(results)
    for item in results:
        if not isinstance(item, dict):
            return False, False, base_summary, "INVALID_JSON_ENVELOPE", "Phần tử finding trong JSON OpenGrep không hợp lệ."
        extra = item.get("extra")
        if not isinstance(extra, dict) or not isinstance(extra.get("metadata"), dict):
            return False, False, base_summary, "INVALID_JSON_ENVELOPE", "Finding thiếu extra/metadata hợp lệ."
        if not isinstance(extra.get("message"), str) or not extra["message"].strip():
            return False, False, base_summary, "INVALID_JSON_ENVELOPE", "Finding thiếu extra.message hợp lệ."
        if not isinstance(extra.get("severity"), str) or not extra["severity"].strip():
            return False, False, base_summary, "INVALID_JSON_ENVELOPE", "Finding thiếu extra.severity hợp lệ."
        if not isinstance(item.get("path"), str) or not item["path"].strip():
            return False, False, base_summary, "INVALID_JSON_ENVELOPE", "Finding thiếu đường dẫn path hợp lệ."
        if not isinstance(item.get("check_id"), str) or not item["check_id"].strip():
            return False, False, base_summary, "INVALID_JSON_ENVELOPE", "Finding thiếu check_id hợp lệ."
        start_loc = item.get("start")
        end_loc = item.get("end")
        if (
            not isinstance(start_loc, dict)
            or not isinstance(end_loc, dict)
            or type(start_loc.get("line")) is not int
            or type(end_loc.get("line")) is not int
            or start_loc["line"] < 1
            or end_loc["line"] < start_loc["line"]
        ):
            return False, False, base_summary, "INVALID_JSON_ENVELOPE", "Finding thiếu tọa độ dòng start/end hợp lệ."

    # Envelope is valid strict OpenGrep JSON with 0 errors -> SCAN_EXECUTED reached!
    json_version = doc.get("version")
    if not isinstance(json_version, str) or not json_version.strip():
        return (
            True,
            False,
            base_summary,
            "CANARY_VERSION_MISSING",
            "Đầu ra JSON của OpenGrep thiếu trường version bắt buộc.",
        )
    v_ok, _, v_tuple, _, _ = parse_and_check_opengrep_version(
        json_version, min_version="0.0.0", max_major=999
    )
    if not v_ok or v_tuple != expected_version_tuple:
        return (
            True,
            False,
            base_summary,
            "CANARY_VERSION_MISMATCH",
            f"Phiên bản trong JSON ({json_version!r}) không khớp --version ({expected_version_tuple}).",
        )

    paths_doc = doc.get("paths")
    if not isinstance(paths_doc, dict) or not isinstance(paths_doc.get("scanned"), list) or not paths_doc["scanned"]:
        return (
            True,
            False,
            base_summary,
            "CANARY_FILE_NOT_SCANNED",
            "Đầu ra JSON của OpenGrep thiếu danh sách paths.scanned hợp lệ.",
        )

    scanned_canary_paths = {
        cp for cp in (_canonicalize_canary_path(p) for p in paths_doc["scanned"]) if cp is not None
    }
    if len(scanned_canary_paths) != 1:
        return (
            True,
            False,
            base_summary,
            "CANARY_FILE_NOT_SCANNED",
            f"OpenGrep không ghi nhận đúng một đường dẫn canary {HEALTH_CANARY_FILENAME} trong paths.scanned.",
        )
    canon_fixture_path = next(iter(scanned_canary_paths))
    if expected_canary_path is not None:
        exp_canon = _canonicalize_canary_path(str(expected_canary_path))
        if exp_canon is None or canon_fixture_path != exp_canon:
            return (
                True,
                False,
                base_summary,
                "CANARY_FILE_NOT_SCANNED",
                f"Đường dẫn canary trong paths.scanned ({canon_fixture_path!r}) không khớp tệp thực tế ({exp_canon!r}).",
            )

    expected_bytes_table = (
        _build_canary_offset_table(expected_canary_bytes) if expected_canary_bytes is not None else None
    )
    require_offset = (expected_canary_bytes is not None) if require_offset is None else bool(require_offset)
    mode_box: dict[str, str | None] = {"mode": None}

    cwe_rule_ids: dict[str, list[str]] = dict(rules_info.get("cwe_rule_ids") or {})
    cwe_taint_only: dict[str, bool] = dict(rules_info.get("cwe_taint_only") or {})
    cwe_has_taint: dict[str, bool] = dict(rules_info.get("cwe_has_taint") or {})
    rule_modes: dict[str, str] = dict(rules_info.get("rule_modes") or {})

    observed_cwes: set[str] = set()
    matched_oracle_cwes: set[str] = set()
    matched_taint_cwes: set[str] = set()
    safe_control_clean = True

    expected_coords = {
        "CWE-89": (HEALTH_CANARY_SQL_SOURCE_LINE, HEALTH_CANARY_SQL_LINE),
        "CWE-22": (HEALTH_CANARY_PATH_SOURCE_LINE, HEALTH_CANARY_PATH_LINE),
    }

    for item in results:
        if _canonicalize_canary_path(item["path"]) != canon_fixture_path:
            base_summary["observed_cwes"] = sorted(observed_cwes)
            base_summary["safe_control_clean"] = safe_control_clean
            return (
                True,
                False,
                base_summary,
                "CANARY_ORACLE_MISMATCH",
                f"Finding canary trỏ tới tệp không khớp canonical fixture ({item['path']!r} != {canon_fixture_path!r}).",
            )
        start_line = int(item["start"]["line"])
        end_line = int(item["end"]["line"])
        if any(ln in HEALTH_CANARY_SAFE_LINES for ln in range(start_line, end_line + 1)):
            safe_control_clean = False

        extra = item["extra"]
        meta = extra.get("metadata") or {}
        finding_cwes = _extract_cwe_codes(meta.get("cwe"))
        observed_cwes.update(finding_cwes)
        check_id = str(item["check_id"]).strip()
        raw_trace = extra.get("dataflow_trace") if "dataflow_trace" in extra else item.get("dataflow_trace")

        for exp_cwe in fixed_expected_cwes:
            if exp_cwe not in finding_cwes:
                continue
            exp_src_line, exp_sink_line = expected_coords[exp_cwe]
            if start_line != exp_sink_line or end_line != exp_sink_line:
                continue
            declared_ids = cwe_rule_ids.get(exp_cwe) or []
            matched_rid = next(
                (rid for rid in declared_ids if check_id == rid or check_id.endswith("." + rid)),
                None,
            )
            if matched_rid is None:
                continue

            finding_slice = _slice_canary_loc(
                item,
                require_offset=require_offset,
                expected_bytes_table=expected_bytes_table,
                mode_box=mode_box,
            )
            if finding_slice is None:
                continue
            if exp_cwe == "CWE-89" and (
                '"SELECT * FROM users WHERE id=" + id' not in finding_slice and "st.executeQuery(" not in finding_slice
            ):
                continue
            if exp_cwe == "CWE-22" and (
                '"/srv/data/" + name' not in finding_slice and "new FileInputStream(" not in finding_slice
            ):
                continue

            # Determine per-rule taint requirement (never weakened by unrelated search rules in same CWE!).
            if matched_rid in rule_modes:
                rule_mode = rule_modes[matched_rid]
            elif exp_cwe in cwe_taint_only:
                rule_mode = "taint" if cwe_taint_only[exp_cwe] else "taint"
            else:
                rule_mode = "taint"

            require_trace = (rule_mode == "taint") or bool(cwe_taint_only.get(exp_cwe, False))
            if require_trace or raw_trace is not None:
                if not _validate_canary_dataflow_trace(
                    raw_trace,
                    expected_source_line=exp_src_line,
                    expected_sink_line=exp_sink_line,
                    expected_cwe=exp_cwe,
                    canonical_fixture_path=canon_fixture_path,
                    require_offset=require_offset,
                    expected_bytes_table=expected_bytes_table,
                    mode_box=mode_box,
                ):
                    continue
            matched_oracle_cwes.add(exp_cwe)
            if rule_mode == "taint":
                matched_taint_cwes.add(exp_cwe)

    base_summary["observed_cwes"] = sorted(observed_cwes)
    base_summary["safe_control_clean"] = safe_control_clean

    if not safe_control_clean:
        return (
            True,
            False,
            base_summary,
            "CANARY_SAFE_CONTROL_VIOLATED",
            "Canary scan báo nhầm cảnh báo trên hàm đối chứng an toàn (safeProbe SQL hoặc safePathProbe Path).",
        )

    missing_cwes = [
        cwe
        for cwe in fixed_expected_cwes
        if cwe not in matched_oracle_cwes
        or (cwe_has_taint.get(cwe, False) and cwe not in matched_taint_cwes)
    ]
    if missing_cwes:
        return (
            True,
            False,
            base_summary,
            "CANARY_ORACLE_MISMATCH",
            f"Canary scan không khớp oracle cho các CWE bắt buộc: {', '.join(missing_cwes)}.",
        )

    base_summary["oracle_matched"] = True
    return True, True, base_summary, None, None


def _verification_stages_dict(level: str) -> dict[str, bool]:
    order = {
        "NONE": 0,
        "BINARY_FOUND": 1,
        "VERSION_IDENTIFIED": 2,
        "SCAN_EXECUTED": 3,
        "SCAN_VERIFIED": 4,
    }
    rank = order.get(level, 0)
    return {
        "binary_found": rank >= 1,
        "version_identified": rank >= 2,
        "scan_executed": rank >= 3,
        "scan_verified": rank >= 4,
    }


def _classify_health_state(
    probe_status: str,
    *,
    is_verified: bool,
    binary_exists: bool,
) -> str:
    if is_verified:
        return "VERIFIED"
    if probe_status == "UNAVAILABLE":
        return "ENGINE_MISSING" if not binary_exists else "PROBE_FAILED"
    if probe_status == "TIMEOUT":
        return "PROBE_TIMEOUT"
    if probe_status in ("NOT_VERIFIED", "EXPIRED"):
        return "NOT_VERIFIED"
    if probe_status in ("CLEANUP_FAILED", "SHUTTING_DOWN", "RULES_INVALID", "CANARY_FAILED"):
        return probe_status
    return "PROBE_FAILED"


def _iso_after_seconds(seconds: float) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=max(0.0, float(seconds)))).isoformat()


class OpenGrepHealthProbe:
    """Bounded, single-flight, snapshot-driven active health probe for OpenGrep.

    Invariants:
    - Never blocks GET /api/health waiting on subprocess execution.
    - Runs at most ONE bounded OpenGrep probe at a time (single-flight).
    - Uses `intake._run_git_step` (Windows Job Object KILL_ON_JOB_CLOSE + temp-file output + verified cleanup).
    - Separates BINARY_FOUND, VERSION_IDENTIFIED, SCAN_EXECUTED, and SCAN_VERIFIED strictly.
    - Keeps all snapshots strictly in-memory per process instance; server restart starts unverified.
    - Immediately invalidates VERIFIED snapshots on rules SHA-256 change, execution-chain identity change,
      config change, or TTL expiry at one atomic linearization point (`evaluate_readiness_snapshot`).
    - Preserves `CLEANUP_FAILED` with highest priority over `CANCELLED`, `TIMEOUT`, and `SHUTTING_DOWN`.
    """

    PROBE_TYPE = "active_version_and_java_canary"

    def __init__(
        self,
        config: Any,
        *,
        clock: Callable[[], float] | None = None,
        scan_busy_check: Callable[[], bool] | None = None,
    ):
        self.config = config
        self._clock: Callable[[], float] = clock or time.monotonic
        self._scan_busy_check: Callable[[], bool] | None = scan_busy_check
        self.process_instance_id = uuid.uuid4().hex

        self._lock = threading.Lock()
        self._snapshot: dict[str, Any] | None = None
        self._snapshot_expires_mono: float = 0.0
        self._snapshot_rules_sha256: str | None = None
        self._snapshot_binary_identity_sha256: str | None = None
        self._snapshot_config_fingerprint: str | None = None
        self._in_flight: bool = False
        self._worker_thread: threading.Thread | None = None
        self._done_event = threading.Event()
        self._done_event.set()
        self._cancel_event = threading.Event()
        self._shutting_down: bool = False
        self._next_generation: int = 0
        self._active_worker_generation: int | None = None
        self._invalidation_epoch: int = 0
        self._probe_run_count: int = 0
        self._cleanup_failed: bool = False
        self._last_step_cleanup: dict[str, Any] | None = None
        self._shutdown_result: dict[str, Any] | None = None
        self._last_real_scan_observed: dict[str, Any] | None = None

    def set_scan_busy_check(self, fn: Callable[[], bool] | None) -> None:
        with self._lock:
            self._scan_busy_check = fn

    def _is_scan_busy(self) -> bool:
        fn = self._scan_busy_check
        if fn is None:
            return False
        try:
            return bool(fn())
        except Exception:
            return False

    def _capture_config_snapshot(self) -> tuple[str, str, Path, str, int, float]:
        og_bin = str(self.config.opengrep_binary)
        rules_p = Path(self.config.rules_path)
        min_ver = str(getattr(self.config, "opengrep_min_version", "1.25.0"))
        max_major = int(getattr(self.config, "opengrep_max_major", 1))
        step_timeout = float(getattr(self.config, "opengrep_health_probe_timeout_seconds", 30.0))
        payload = {
            "opengrep_binary": og_bin,
            "rules_path": str(rules_p),
            "opengrep_min_version": min_ver,
            "opengrep_max_major": max_major,
            "opengrep_health_probe_timeout_seconds": step_timeout,
        }
        fp = digest(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8"))
        return fp, og_bin, rules_p, min_ver, max_major, step_timeout

    def _config_fingerprint(self) -> str:
        return self._capture_config_snapshot()[0]

    def _read_live_inputs_once(self, *, reverse: bool = False) -> dict[str, Any]:
        """Read local execution-chain identity, rules bytes/SHA-256, and config fingerprint in one pass."""
        def _read_rules(rules_p: Path) -> dict[str, Any]:
            st_sig = _stat_sig(rules_p)
            try:
                raw = rules_p.read_bytes()
                return {
                    "available": True,
                    "sha256": digest(raw),
                    "name": rules_p.name,
                    "stat_sig": st_sig,
                }
            except OSError:
                return {
                    "available": False,
                    "sha256": None,
                    "name": rules_p.name,
                    "stat_sig": None,
                }

        def _chain_sigs(binfo: dict[str, Any]) -> dict[str, tuple[int, int, int, int] | None]:
            sigs: dict[str, tuple[int, int, int, int] | None] = {}
            rp = binfo.get("resolved_path")
            if isinstance(rp, str) and rp:
                sigs[rp] = _stat_sig(Path(rp))
            for item in binfo.get("wrapper_targets") or []:
                p = item.get("path") if isinstance(item, dict) else None
                if isinstance(p, str) and p:
                    sigs[p] = _stat_sig(Path(p))
            for item in binfo.get("wrapper_interpreters") or []:
                p = item.get("path") if isinstance(item, dict) else None
                if isinstance(p, str) and p:
                    sigs[p] = _stat_sig(Path(p))
            return sigs

        if not reverse:
            cfg_fp, og_bin, rules_p, _min_v, _max_m, _t = self._capture_config_snapshot()
            bin_info = inspect_opengrep_binary_identity(og_bin)
            rules_eval = _read_rules(rules_p)
            chain_sigs = _chain_sigs(bin_info)
        else:
            cfg_fp_pre, og_bin_pre, rules_p_pre, _min_v, _max_m, _t = self._capture_config_snapshot()
            rules_eval = _read_rules(rules_p_pre)
            bin_info = inspect_opengrep_binary_identity(og_bin_pre)
            cfg_fp, _og_bin2, _rules_p2, _min_v2, _max_m2, _t2 = self._capture_config_snapshot()
            if cfg_fp != cfg_fp_pre:
                # Signal config mutation during reverse read by leaving mismatch visible against P1
                cfg_fp = f"{cfg_fp_pre}->{cfg_fp}"
            chain_sigs = _chain_sigs(bin_info)

        return {
            "cfg_fp": cfg_fp,
            "bin_info": bin_info,
            "rules_eval": rules_eval,
            "chain_sigs": chain_sigs,
        }

    @staticmethod
    def _inputs_consistent(p1: dict[str, Any], p2: dict[str, Any]) -> tuple[bool, str | None]:
        """Verify two read phases (`P1` forward, `P2` reverse) agree on every identity input."""
        if p1["cfg_fp"] != p2["cfg_fp"]:
            return False, "CONFIG_CHANGED"

        b1, b2 = p1["bin_info"], p2["bin_info"]
        if (
            bool(b1.get("found")) != bool(b2.get("found"))
            or bool(b1.get("binary_exists")) != bool(b2.get("binary_exists"))
            or b1.get("failure_code") != b2.get("failure_code")
            or b1.get("binary_identity_sha256") != b2.get("binary_identity_sha256")
            or b1.get("resolved_path") != b2.get("resolved_path")
        ):
            return False, "BINARY_IDENTITY_CHANGED"

        s1, s2 = p1.get("chain_sigs") or {}, p2.get("chain_sigs") or {}
        if set(s1.keys()) != set(s2.keys()):
            return False, "BINARY_IDENTITY_CHANGED"
        for k, sig1 in s1.items():
            sig2 = s2.get(k)
            if sig1 is not None and sig2 is not None and sig1 != sig2:
                return False, "BINARY_IDENTITY_CHANGED"

        r1, r2 = p1["rules_eval"], p2["rules_eval"]
        if (
            bool(r1.get("available")) != bool(r2.get("available"))
            or r1.get("sha256") != r2.get("sha256")
            or r1.get("name") != r2.get("name")
        ):
            return False, "RULES_SHA256_CHANGED"
        rs1, rs2 = r1.get("stat_sig"), r2.get("stat_sig")
        if rs1 is not None and rs2 is not None and rs1 != rs2:
            return False, "RULES_SHA256_CHANGED"

        return True, None

    def _identity_scope_doc(self) -> dict[str, Any]:
        ttl = float(getattr(self.config, "opengrep_health_probe_ttl_seconds", 300.0))
        return {
            "checked_on_every_health_get": [
                "wrapper_or_executable_sha256",
                "wrapper_targets_and_local_python_dependencies_sha256",
                "wrapper_interpreters_sha256",
                "declared_wsl_distro_and_path_in_wrapper",
                "rules_file_sha256",
                "config_fingerprint",
                "snapshot_ttl_and_process_instance_id",
            ],
            "verified_at_last_probe_only": [
                "wsl_linux_binary_sha256",
                "opengrep_version_execution",
                "java_canary_scan_execution_on_immutable_rules_snapshot",
            ],
            "max_staleness_seconds": ttl,
            "realtime_wsl_binary_mutation_detection": False,
            "trust_boundary_note": (
                "Local wrapper, bridge scripts, transitive local Python imports, non-OS wrapper interpreter, "
                "declared WSL target, and rules SHA-256 are checked on every GET /api/health without spawning "
                "subprocesses. Mutations inside WSL2 Linux binaries without modifying host wrapper files are "
                "detected upon TTL expiry, API restart, or forced re-probe."
            ),
        }

    def _base_payload(
        self,
        *,
        available: bool,
        probe_status: str,
        verification_level: str,
        bin_info: dict[str, Any],
        rules_sha256: str | None,
        version: str | None = None,
        error: str | None = None,
        failure_code: str | None = None,
        invalidation_reason: str | None = None,
        probed_at: str | None = None,
        expires_at: str | None = None,
        version_exit_code: int | None = None,
        canary_exit_code: int | None = None,
        canary_duration_ms: float | None = None,
        canary_summary: dict[str, Any] | None = None,
        probe_in_progress: bool = False,
        deferred_by_active_scan: bool = False,
        wsl_binary_identity: dict[str, Any] | None = None,
        probe_execution_identity_sha256: str | None = None,
        process_cleanup: dict[str, Any] | None = None,
        probe_stage_failed: str | None = None,
        step_timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        is_verified = bool(
            available and probe_status == "VERIFIED" and verification_level == "SCAN_VERIFIED"
        )
        binary_present = bool(bin_info.get("binary_exists") or bin_info.get("found"))
        health_state = _classify_health_state(
            probe_status,
            is_verified=is_verified,
            binary_exists=binary_present,
        )
        payload: dict[str, Any] = {
            "available": is_verified,
            "executable": str(bin_info.get("executable") or self.config.opengrep_binary),
            "resolved_path": bin_info.get("resolved_path"),
            "version": version,
            "probe_status": probe_status,
            "health_state": health_state,
            "binary_present": binary_present,
            "runtime_verified": is_verified,
            "error": None if is_verified else error,
            "verification_level": verification_level,
            "verification_stages": _verification_stages_dict(verification_level),
            "probe_type": self.PROBE_TYPE,
            "probe_in_progress": bool(probe_in_progress),
            "deferred_by_active_scan": bool(deferred_by_active_scan),
            "probed_at": probed_at,
            "expires_at": expires_at,
            "ttl_seconds": float(getattr(self.config, "opengrep_health_probe_ttl_seconds", 300.0)),
            "executable_sha256": bin_info.get("executable_sha256"),
            "wrapper_targets": copy.deepcopy(bin_info.get("wrapper_targets") or []),
            "wrapper_interpreters": copy.deepcopy(bin_info.get("wrapper_interpreters") or []),
            "wsl_target": copy.deepcopy(bin_info.get("wsl_target") or {"detected": False, "distro": None, "linux_binary_path": None}),
            "wsl_binary_identity": copy.deepcopy(wsl_binary_identity) if wsl_binary_identity is not None else None,
            "binary_identity_sha256": bin_info.get("binary_identity_sha256"),
            "probe_execution_identity_sha256": probe_execution_identity_sha256,
            "identity_verification_scope": self._identity_scope_doc(),
            "rules_sha256": rules_sha256,
            "version_exit_code": version_exit_code,
            "canary_exit_code": canary_exit_code,
            "canary_duration_ms": canary_duration_ms,
            "canary_summary": copy.deepcopy(canary_summary) if canary_summary is not None else None,
            "failure_code": None if is_verified else failure_code,
            "probe_stage_failed": None if is_verified else probe_stage_failed,
            "step_timeout_seconds": None if is_verified else step_timeout_seconds,
            "invalidation_reason": invalidation_reason,
            "process_instance_id": self.process_instance_id,
        }
        if self._last_real_scan_observed is not None:
            payload["last_real_scan_observed"] = copy.deepcopy(self._last_real_scan_observed)
        if process_cleanup is not None:
            payload["process_cleanup"] = copy.deepcopy(process_cleanup)
            if not process_cleanup.get("clean"):
                payload["cleanup_status"] = "CLEANUP_FAILED"
        elif probe_status == "CLEANUP_FAILED":
            payload["cleanup_status"] = "CLEANUP_FAILED"
        return payload

    def start_background_probe(self, *, force: bool = False) -> bool:
        """Start a single-flight background probe if enabled, binary exists, and not shutting down."""
        if not bool(getattr(self.config, "opengrep_health_probe_enabled", True)):
            return False
        bin_info = inspect_opengrep_binary_identity(self.config.opengrep_binary)
        if not bin_info["found"]:
            return False
        with self._lock:
            if self._shutting_down or self._in_flight:
                return False
            reg = intake.inspect_lingering_registry_state(step_prefix="opengrep-health-")
            if reg["blocking_count"] > 0 or reg["non_closed_count"] > 0 or reg["registry_fault"]:
                self._cleanup_failed = True
                return False
            if self._cleanup_failed:
                return False
            if self._is_scan_busy() and not force:
                return False
            return self._spawn_worker_locked()

    def _spawn_worker_locked(self) -> bool:
        """Caller MUST hold `self._lock` and have checked `not self._shutting_down and not self._in_flight`."""
        self._next_generation += 1
        gen = self._next_generation
        epoch = self._invalidation_epoch
        self._active_worker_generation = gen
        self._in_flight = True
        self._done_event.clear()
        th = threading.Thread(
            target=self._worker_entry,
            args=(gen, epoch),
            name="ntk-opengrep-health-probe",
            daemon=True,
        )
        try:
            th.start()
        except Exception as exc:
            self._in_flight = False
            self._active_worker_generation = None
            self._worker_thread = None
            self._done_event.set()
            now_mono = self._clock()
            fail_ttl = float(getattr(self.config, "opengrep_health_probe_failure_ttl_seconds", 30.0))
            bin_info = inspect_opengrep_binary_identity(self.config.opengrep_binary)
            rules_sha = None
            try:
                rules_sha = digest(Path(self.config.rules_path).read_bytes())
            except OSError:
                pass
            self._snapshot = self._base_payload(
                available=False,
                probe_status="FAILED",
                verification_level="BINARY_FOUND" if bin_info["found"] else "NONE",
                bin_info=bin_info,
                rules_sha256=rules_sha,
                error=f"Không thể khởi tạo luồng kiểm chứng OpenGrep: {type(exc).__name__}",
                failure_code="THREAD_START_FAILED",
                probed_at=now(),
                expires_at=_iso_after_seconds(fail_ttl),
            )
            self._snapshot_expires_mono = now_mono + fail_ttl
            self._snapshot_rules_sha256 = rules_sha
            self._snapshot_binary_identity_sha256 = bin_info.get("binary_identity_sha256")
            self._snapshot_config_fingerprint = self._config_fingerprint()
            return False
        self._worker_thread = th
        return True

    def _worker_entry(self, generation: int, epoch: int) -> None:
        try:
            snap, ttl_sec, r_sha, b_sha, cfg_fp, step_cleanup = self._execute_probe_once()
            is_cleanup_fail = (
                snap.get("probe_status") == "CLEANUP_FAILED"
                or (isinstance(step_cleanup, dict) and step_cleanup.get("clean") is False)
            )
            with self._lock:
                if isinstance(step_cleanup, dict):
                    self._last_step_cleanup = copy.deepcopy(step_cleanup)
                if is_cleanup_fail:
                    # CLEANUP_FAILED has highest priority: NEVER drop or mask under shutdown or epoch bump!
                    self._cleanup_failed = True
                    self._snapshot = snap
                    self._snapshot_expires_mono = self._clock() + ttl_sec
                    self._snapshot_rules_sha256 = r_sha
                    self._snapshot_binary_identity_sha256 = b_sha
                    self._snapshot_config_fingerprint = cfg_fp
                elif (
                    not self._shutting_down
                    and epoch == self._invalidation_epoch
                    and generation == self._active_worker_generation
                ):
                    self._cleanup_failed = False
                    self._snapshot = snap
                    self._snapshot_expires_mono = self._clock() + ttl_sec
                    self._snapshot_rules_sha256 = r_sha
                    self._snapshot_binary_identity_sha256 = b_sha
                    self._snapshot_config_fingerprint = cfg_fp
        except BaseException as exc:
            reg_after = intake.inspect_lingering_registry_state(step_prefix="opengrep-health-")
            reg_leaked = (
                reg_after["blocking_count"] > 0
                or reg_after["non_closed_count"] > 0
                or bool(reg_after["registry_fault"])
            )
            exc_cleanup = getattr(exc, "cleanup", None)
            if not isinstance(exc_cleanup, dict):
                d = getattr(exc, "details", None)
                exc_cleanup = d.get("process_cleanup") if isinstance(d, dict) else None
            exc_clean_failed = isinstance(exc_cleanup, dict) and exc_cleanup.get("clean") is False
            with self._lock:
                if isinstance(exc_cleanup, dict):
                    self._last_step_cleanup = copy.deepcopy(exc_cleanup)
                if reg_leaked or exc_clean_failed:
                    self._cleanup_failed = True
                    self._snapshot = self._base_payload(
                        available=False,
                        probe_status="CLEANUP_FAILED",
                        verification_level="BINARY_FOUND",
                        bin_info=inspect_opengrep_binary_identity(self.config.opengrep_binary),
                        rules_sha256=None,
                        error=(
                            f"Luồng kiểm chứng OpenGrep bị ngắt ({type(exc).__name__}) và không xác nhận được việc dừng sạch tiến trình "
                            f"(state={reg_after['registry_state']})."
                        ),
                        failure_code="PROBE_CLEANUP_FAILED",
                        probed_at=now(),
                        expires_at=_iso_after_seconds(
                            float(getattr(self.config, "opengrep_health_probe_failure_ttl_seconds", 30.0))
                        ),
                        process_cleanup=self._last_step_cleanup,
                    )
                    self._snapshot_expires_mono = self._clock() + float(
                        getattr(self.config, "opengrep_health_probe_failure_ttl_seconds", 30.0)
                    )
                elif (
                    isinstance(exc, Exception)
                    and not self._shutting_down
                    and epoch == self._invalidation_epoch
                    and generation == self._active_worker_generation
                ):
                    fail_ttl = float(getattr(self.config, "opengrep_health_probe_failure_ttl_seconds", 30.0))
                    bin_info = inspect_opengrep_binary_identity(self.config.opengrep_binary)
                    self._snapshot = self._base_payload(
                        available=False,
                        probe_status="FAILED",
                        verification_level="BINARY_FOUND" if bin_info.get("binary_exists") or bin_info["found"] else "NONE",
                        bin_info=bin_info,
                        rules_sha256=None,
                        error=f"Lỗi nội bộ khi kiểm chứng OpenGrep: {type(exc).__name__}",
                        failure_code="PROBE_INTERNAL_ERROR",
                        probed_at=now(),
                        expires_at=_iso_after_seconds(fail_ttl),
                    )
                    self._snapshot_expires_mono = self._clock() + fail_ttl
                    self._snapshot_rules_sha256 = None
                    self._snapshot_binary_identity_sha256 = bin_info.get("binary_identity_sha256")
                    self._snapshot_config_fingerprint = self._config_fingerprint()
            if not isinstance(exc, Exception):
                raise
        finally:
            with self._lock:
                if self._active_worker_generation == generation:
                    self._in_flight = False
                    self._active_worker_generation = None
                self._done_event.set()

    def _execute_probe_once(
        self,
    ) -> tuple[dict[str, Any], float, str | None, str | None, str, dict[str, Any] | None]:
        with self._lock:
            self._probe_run_count += 1

        p_start = self._read_live_inputs_once(reverse=False)
        cfg_fp, _og_bin_cfg, rules_path_cfg, min_ver, max_major, step_timeout = self._capture_config_snapshot()
        cfg_fp = p_start["cfg_fp"]
        ok_ttl = float(getattr(self.config, "opengrep_health_probe_ttl_seconds", 300.0))
        fail_ttl = float(getattr(self.config, "opengrep_health_probe_failure_ttl_seconds", 30.0))

        # Stage 1: Binary/wrapper/local-dependency existence & identity
        bin_info = p_start["bin_info"]
        if not bin_info["found"]:
            bin_exists = bool(bin_info.get("binary_exists"))
            snap = self._base_payload(
                available=False,
                probe_status="FAILED" if bin_exists else "UNAVAILABLE",
                verification_level="BINARY_FOUND" if bin_exists else "NONE",
                bin_info=bin_info,
                rules_sha256=p_start["rules_eval"].get("sha256"),
                error=bin_info["error"],
                failure_code=bin_info["failure_code"],
                probed_at=now(),
                expires_at=_iso_after_seconds(fail_ttl),
            )
            return snap, fail_ttl, None, None, cfg_fp, None

        b_sha = bin_info["binary_identity_sha256"]
        resolved_bin = str(bin_info["resolved_path"])

        # Validate rules file + SHA-256 + fixed CWE-22 & CWE-89 contract before spawning OpenGrep
        rules_info = inspect_rules_for_canary(rules_path_cfg)
        r_sha = rules_info.get("rules_sha256")
        rules_raw_bytes = rules_info.get("_raw_bytes")
        if not rules_info["ok"] or not isinstance(rules_raw_bytes, (bytes, bytearray)):
            snap = self._base_payload(
                available=False,
                probe_status="RULES_INVALID",
                verification_level="BINARY_FOUND",
                bin_info=bin_info,
                rules_sha256=r_sha,
                error=rules_info["error"],
                failure_code=rules_info["failure_code"],
                probed_at=now(),
                expires_at=_iso_after_seconds(fail_ttl),
            )
            return snap, fail_ttl, r_sha, b_sha, cfg_fp, None

        if self._cancel_event.is_set():
            snap = self._base_payload(
                available=False,
                probe_status="SHUTTING_DOWN",
                verification_level="BINARY_FOUND",
                bin_info=bin_info,
                rules_sha256=r_sha,
                error="Tiến trình kiểm chứng OpenGrep đã bị hủy do máy chủ đang dừng.",
                failure_code="PROBE_CANCELLED",
                probed_at=now(),
                expires_at=_iso_after_seconds(fail_ttl),
            )
            return snap, fail_ttl, r_sha, b_sha, cfg_fp, None

        with tempfile.TemporaryDirectory(prefix="ntk_og_health_") as tmp_s:
            tmp_dir = Path(tmp_s)
            canary_dir = tmp_dir / "src"
            canary_dir.mkdir(parents=True, exist_ok=True)
            canary_bytes = HEALTH_CANARY_SOURCE.encode("utf-8")
            canary_file = (canary_dir / HEALTH_CANARY_FILENAME).resolve()
            canary_file.write_bytes(canary_bytes)

            # Immutable rules snapshot bound to `r_sha` so OpenGrep scans exact verified bytes (eliminates TOCTOU)
            snapshot_rules_path = tmp_dir / "rules.snapshot.yml"
            snapshot_rules_path.write_bytes(bytes(rules_raw_bytes))
            if digest(snapshot_rules_path.read_bytes()) != r_sha:
                snap = self._base_payload(
                    available=False,
                    probe_status="RULES_INVALID",
                    verification_level="BINARY_FOUND",
                    bin_info=bin_info,
                    rules_sha256=r_sha,
                    error="Không xác minh được SHA-256 của bản sao rules bất biến trước khi chạy canary.",
                    failure_code="RULES_SNAPSHOT_INTEGRITY_FAILED",
                    probed_at=now(),
                    expires_at=_iso_after_seconds(fail_ttl),
                )
                return snap, fail_ttl, r_sha, b_sha, cfg_fp, None

            env = os.environ.copy()
            env["SEMGREP_LOG_FILE"] = str(tmp_dir / "opengrep.log")
            env["SEMGREP_SETTINGS_FILE"] = str(tmp_dir / "settings.yml")
            env["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
            env["OPENGREP_ENABLE_VERSION_CHECK"] = "0"
            env["SEMGREP_SEND_METRICS"] = "off"

            wsl_binary_identity: dict[str, Any] | None = None
            wsl_ver_tuple: tuple[int, ...] | None = None
            wsl_prefix_used: list[str] | None = None
            wsl_resolved_linux: str | None = None

            def _extract_exc_cleanup(exc: Exception) -> dict[str, Any] | None:
                c = getattr(exc, "cleanup", None)
                if isinstance(c, dict):
                    return c
                if isinstance(exc, intake.IntakeError):
                    pc = exc.details.get("process_cleanup")
                    if isinstance(pc, dict):
                        return pc
                return None

            def _map_step_error(
                exc: Exception,
                *,
                stage_label: str,
                reached_level: str,
                ver_str: str | None = None,
                ver_exit: int | None = None,
                actual_timeout: float | None = None,
            ) -> tuple[dict[str, Any], float, str | None, str | None, str, dict[str, Any] | None]:
                cleanup_info = _extract_exc_cleanup(exc)
                cleanup_failed = isinstance(cleanup_info, dict) and not bool(cleanup_info.get("clean"))
                effective_timeout = float(step_timeout if actual_timeout is None else actual_timeout)

                # Strict priority: CLEANUP_FAILED MUST NEVER be overwritten by CANCELLED, TIMEOUT, or SHUTTING_DOWN!
                if isinstance(exc, intake._GitStepCleanupFailed) or cleanup_failed:
                    p_status, f_code = "CLEANUP_FAILED", "PROBE_CLEANUP_FAILED"
                    primary_out = getattr(exc, "primary_outcome", None)
                    reason_hint = f" (nguyên nhân trước đó: {primary_out})" if primary_out else ""
                    msg = (
                        f"Bước kiểm chứng OpenGrep ({stage_label}) không xác nhận được việc dừng toàn bộ "
                        f"cây tiến trình con (CLEANUP_FAILED){reason_hint}."
                    )
                elif isinstance(exc, intake._GitStepCancelled):
                    p_status, f_code = "SHUTTING_DOWN", "PROBE_CANCELLED"
                    msg = f"Bước kiểm chứng OpenGrep ({stage_label}) đã bị hủy an toàn khi dừng máy chủ."
                elif isinstance(exc, intake._GitStepTimeout):
                    p_status, f_code = "TIMEOUT", "PROBE_TIMEOUT"
                    msg = f"OpenGrep vượt thời gian chờ ({effective_timeout:.1f}s) ở bước {stage_label}; đã dừng cây tiến trình."
                elif isinstance(exc, intake._GitStepOutputLimit):
                    p_status, f_code = "FAILED", "PROBE_OUTPUT_LIMIT_EXCEEDED"
                    msg = f"Đầu ra OpenGrep ({exc.stream}) ở bước {stage_label} vượt giới hạn {exc.limit} byte."
                elif isinstance(exc, intake.IntakeError):
                    p_status = "CLEANUP_FAILED" if exc.error_code == "GITHUB_GIT_CLEANUP_PENDING" else "FAILED"
                    f_code = exc.error_code
                    msg = str(exc)
                elif isinstance(exc, intake._GitStepInternalError):
                    p_status, f_code = "FAILED", "PROBE_PROCESS_ERROR"
                    msg = f"Lỗi quản lý tiến trình OpenGrep ở bước {stage_label} ({exc.error_type})."
                else:
                    p_status, f_code = "UNAVAILABLE", "PROBE_LAUNCH_FAILED"
                    msg = f"Không thể khởi chạy OpenGrep ở bước {stage_label}: {type(exc).__name__}"
                snap_err = self._base_payload(
                    available=False,
                    probe_status=p_status,
                    verification_level=reached_level,
                    bin_info=bin_info,
                    rules_sha256=r_sha,
                    version=ver_str,
                    error=msg,
                    failure_code=f_code,
                    probed_at=now(),
                    expires_at=_iso_after_seconds(fail_ttl),
                    version_exit_code=ver_exit,
                    wsl_binary_identity=wsl_binary_identity,
                    process_cleanup=cleanup_info,
                    probe_stage_failed=stage_label,
                    step_timeout_seconds=effective_timeout if p_status == "TIMEOUT" else None,
                )
                return snap_err, fail_ttl, r_sha, b_sha, cfg_fp, cleanup_info

            # Stage 1b: If wrapper/bridge targets a WSL2 Linux binary, verify its real path and SHA-256 at probe time
            # Invoke readlink and sha256sum directly (never via `/bin/sh -c`) to avoid shell/quote issues on Windows.
            wsl_target = bin_info.get("wsl_target") or {}
            if wsl_target.get("detected"):
                wsl_distro = wsl_target.get("distro")
                wsl_linux_path = str(wsl_target.get("linux_binary_path") or "").strip()
                if not re.fullmatch(r"/[A-Za-z0-9_./+-]+", wsl_linux_path) or ".." in wsl_linux_path.split("/"):
                    snap = self._base_payload(
                        available=False,
                        probe_status="FAILED",
                        verification_level="BINARY_FOUND",
                        bin_info=bin_info,
                        rules_sha256=r_sha,
                        error=f"Đường dẫn binary WSL không hợp lệ: {wsl_linux_path!r}.",
                        failure_code="WSL_BINARY_IDENTITY_FAILED",
                        probed_at=now(),
                        expires_at=_iso_after_seconds(fail_ttl),
                    )
                    return snap, fail_ttl, r_sha, b_sha, cfg_fp, None

                wsl_prefix = ["wsl.exe"]
                if isinstance(wsl_distro, str) and wsl_distro.strip():
                    wsl_prefix.extend(["-d", wsl_distro.strip()])
                wsl_prefix.append("--")

                wsl_step_timeout = float(step_timeout)
                try:
                    rl_proc = intake._run_git_step(
                        "opengrep-health-wsl-realpath",
                        [*wsl_prefix, "readlink", "-f", "--", wsl_linux_path],
                        timeout_seconds=wsl_step_timeout,
                        env=env,
                        max_output_bytes=MAX_HEALTH_PROBE_WSL_ID_OUTPUT_BYTES,
                        cancel_event=self._cancel_event,
                    )
                except Exception as exc:
                    return _map_step_error(
                        exc,
                        stage_label="wsl_binary_identity:realpath",
                        reached_level="BINARY_FOUND",
                        actual_timeout=wsl_step_timeout,
                    )

                resolved_linux = rl_proc.stdout.decode("utf-8", errors="replace").strip() if rl_proc.returncode == 0 else ""
                if rl_proc.returncode != 0 or not resolved_linux.startswith("/") or "\n" in resolved_linux:
                    stderr_hint = rl_proc.stderr.decode("utf-8", errors="replace").strip()[:200]
                    snap = self._base_payload(
                        available=False,
                        probe_status="FAILED",
                        verification_level="BINARY_FOUND",
                        bin_info=bin_info,
                        rules_sha256=r_sha,
                        error=(
                            f"Không thể phân giải đường dẫn binary OpenGrep trong WSL "
                            f"({wsl_distro or 'default'}:{wsl_linux_path}, exit {rl_proc.returncode})"
                            + (f": {stderr_hint}" if stderr_hint else ".")
                        ),
                        failure_code="WSL_BINARY_IDENTITY_FAILED",
                        probed_at=now(),
                        expires_at=_iso_after_seconds(fail_ttl),
                    )
                    return snap, fail_ttl, r_sha, b_sha, cfg_fp, None

                try:
                    sha_proc = intake._run_git_step(
                        "opengrep-health-wsl-sha256",
                        [*wsl_prefix, "sha256sum", "--", resolved_linux],
                        timeout_seconds=wsl_step_timeout,
                        env=env,
                        max_output_bytes=MAX_HEALTH_PROBE_WSL_ID_OUTPUT_BYTES,
                        cancel_event=self._cancel_event,
                    )
                except Exception as exc:
                    return _map_step_error(
                        exc,
                        stage_label="wsl_binary_identity:sha256",
                        reached_level="BINARY_FOUND",
                        actual_timeout=wsl_step_timeout,
                    )

                wsl_sha = None
                if sha_proc.returncode == 0:
                    first_line = sha_proc.stdout.decode("utf-8", errors="replace").strip().splitlines()
                    if first_line:
                        toks = first_line[0].split()
                        cand_sha = toks[0].lower() if toks else ""
                        if _SHA256_HEX_RE.fullmatch(cand_sha):
                            wsl_sha = cand_sha
                if not wsl_sha:
                    stderr_hint = sha_proc.stderr.decode("utf-8", errors="replace").strip()[:200]
                    snap = self._base_payload(
                        available=False,
                        probe_status="FAILED",
                        verification_level="BINARY_FOUND",
                        bin_info=bin_info,
                        rules_sha256=r_sha,
                        error=(
                            f"Không thể xác minh SHA-256 của binary OpenGrep trong WSL "
                            f"({wsl_distro or 'default'}:{resolved_linux}, exit {sha_proc.returncode})"
                            + (f": {stderr_hint}" if stderr_hint else ".")
                        ),
                        failure_code="WSL_BINARY_IDENTITY_FAILED",
                        probed_at=now(),
                        expires_at=_iso_after_seconds(fail_ttl),
                    )
                    return snap, fail_ttl, r_sha, b_sha, cfg_fp, None

                try:
                    wsl_ver_proc = intake._run_git_step(
                        "opengrep-health-wsl-version",
                        [*wsl_prefix, resolved_linux, "--version"],
                        timeout_seconds=wsl_step_timeout,
                        env=env,
                        max_output_bytes=MAX_HEALTH_PROBE_VERSION_OUTPUT_BYTES,
                        cancel_event=self._cancel_event,
                    )
                except Exception as exc:
                    return _map_step_error(
                        exc,
                        stage_label="wsl_binary_identity:version",
                        reached_level="BINARY_FOUND",
                        actual_timeout=wsl_step_timeout,
                    )

                if wsl_ver_proc.returncode != 0:
                    stderr_hint = wsl_ver_proc.stderr.decode("utf-8", errors="replace").strip()[:200]
                    snap = self._base_payload(
                        available=False,
                        probe_status="FAILED",
                        verification_level="BINARY_FOUND",
                        bin_info=bin_info,
                        rules_sha256=r_sha,
                        error=(
                            f"Không thể xác minh phiên bản binary OpenGrep trong WSL "
                            f"({wsl_distro or 'default'}:{resolved_linux}, exit {wsl_ver_proc.returncode})"
                            + (f": {stderr_hint}" if stderr_hint else ".")
                        ),
                        failure_code="WSL_BINARY_IDENTITY_FAILED",
                        probed_at=now(),
                        expires_at=_iso_after_seconds(fail_ttl),
                        version_exit_code=int(wsl_ver_proc.returncode),
                    )
                    return snap, fail_ttl, r_sha, b_sha, cfg_fp, None

                try:
                    wsl_ver_stdout = wsl_ver_proc.stdout.decode("utf-8")
                except UnicodeDecodeError:
                    snap = self._base_payload(
                        available=False,
                        probe_status="FAILED",
                        verification_level="BINARY_FOUND",
                        bin_info=bin_info,
                        rules_sha256=r_sha,
                        error="Đầu ra --version từ binary WSL không phải UTF-8 hợp lệ.",
                        failure_code="WSL_BINARY_IDENTITY_FAILED",
                        probed_at=now(),
                        expires_at=_iso_after_seconds(fail_ttl),
                        version_exit_code=int(wsl_ver_proc.returncode),
                    )
                    return snap, fail_ttl, r_sha, b_sha, cfg_fp, None

                w_ver_ok, w_ver_display, w_ver_tuple, w_ver_fcode, w_ver_err = parse_and_check_opengrep_version(
                    wsl_ver_stdout, min_version=min_ver, max_major=max_major
                )
                if not w_ver_ok or w_ver_tuple is None:
                    p_st = "VERSION_POLICY_REJECTED" if w_ver_fcode == "VERSION_POLICY_REJECTED" else "FAILED"
                    f_cd = w_ver_fcode if w_ver_fcode == "VERSION_POLICY_REJECTED" else "WSL_BINARY_IDENTITY_FAILED"
                    snap = self._base_payload(
                        available=False,
                        probe_status=p_st,
                        verification_level="BINARY_FOUND",
                        bin_info=bin_info,
                        rules_sha256=r_sha,
                        version=w_ver_display,
                        error=w_ver_err,
                        failure_code=f_cd,
                        probed_at=now(),
                        expires_at=_iso_after_seconds(fail_ttl),
                        version_exit_code=int(wsl_ver_proc.returncode),
                    )
                    return snap, fail_ttl, r_sha, b_sha, cfg_fp, None

                wsl_ver_tuple = w_ver_tuple
                wsl_prefix_used = list(wsl_prefix)
                wsl_resolved_linux = resolved_linux
                wsl_binary_identity = {
                    "distro": wsl_distro,
                    "configured_path": wsl_linux_path,
                    "resolved_path": resolved_linux,
                    "sha256": wsl_sha,
                    "version": w_ver_display,
                    "verified_at_probe": True,
                }

            # Stage 2: Version check (`--version`)
            try:
                ver_proc = intake._run_git_step(
                    "opengrep-health-version",
                    [resolved_bin, "--version"],
                    timeout_seconds=step_timeout,
                    env=env,
                    max_output_bytes=MAX_HEALTH_PROBE_VERSION_OUTPUT_BYTES,
                    cancel_event=self._cancel_event,
                )
            except Exception as exc:
                return _map_step_error(exc, stage_label="version", reached_level="BINARY_FOUND")

            if ver_proc.returncode != 0:
                stderr_hint = ver_proc.stderr.decode("utf-8", errors="replace").strip()[:200]
                snap = self._base_payload(
                    available=False,
                    probe_status="FAILED",
                    verification_level="BINARY_FOUND",
                    bin_info=bin_info,
                    rules_sha256=r_sha,
                    error=(
                        f"OpenGrep --version thất bại (exit {ver_proc.returncode})"
                        + (f": {stderr_hint}" if stderr_hint else ".")
                    ),
                    failure_code="VERSION_EXIT_NONZERO",
                    probed_at=now(),
                    expires_at=_iso_after_seconds(fail_ttl),
                    version_exit_code=int(ver_proc.returncode),
                    wsl_binary_identity=wsl_binary_identity,
                )
                return snap, fail_ttl, r_sha, b_sha, cfg_fp, None

            try:
                ver_stdout = ver_proc.stdout.decode("utf-8")
            except UnicodeDecodeError:
                snap = self._base_payload(
                    available=False,
                    probe_status="FAILED",
                    verification_level="BINARY_FOUND",
                    bin_info=bin_info,
                    rules_sha256=r_sha,
                    error="Đầu ra --version của OpenGrep không phải UTF-8 hợp lệ.",
                    failure_code="INVALID_VERSION_OUTPUT",
                    probed_at=now(),
                    expires_at=_iso_after_seconds(fail_ttl),
                    version_exit_code=int(ver_proc.returncode),
                    wsl_binary_identity=wsl_binary_identity,
                )
                return snap, fail_ttl, r_sha, b_sha, cfg_fp, None

            ver_ok, ver_display, ver_tuple, ver_fcode, ver_err = parse_and_check_opengrep_version(
                ver_stdout, min_version=min_ver, max_major=max_major
            )
            if not ver_ok or ver_tuple is None:
                p_st = "VERSION_POLICY_REJECTED" if ver_fcode == "VERSION_POLICY_REJECTED" else "FAILED"
                snap = self._base_payload(
                    available=False,
                    probe_status=p_st,
                    verification_level="BINARY_FOUND",
                    bin_info=bin_info,
                    rules_sha256=r_sha,
                    version=ver_display,
                    error=ver_err,
                    failure_code=ver_fcode,
                    probed_at=now(),
                    expires_at=_iso_after_seconds(fail_ttl),
                    version_exit_code=int(ver_proc.returncode),
                    wsl_binary_identity=wsl_binary_identity,
                )
                return snap, fail_ttl, r_sha, b_sha, cfg_fp, None

            if wsl_ver_tuple is not None and wsl_ver_tuple != ver_tuple:
                snap = self._base_payload(
                    available=False,
                    probe_status="FAILED",
                    verification_level="BINARY_FOUND",
                    bin_info=bin_info,
                    rules_sha256=r_sha,
                    version=ver_display,
                    error=(
                        f"Phiên bản wrapper ({ver_display}) không khớp binary OpenGrep trong WSL "
                        f"({wsl_binary_identity.get('version') if wsl_binary_identity else 'unknown'})."
                    ),
                    failure_code="WSL_BINARY_IDENTITY_FAILED",
                    probed_at=now(),
                    expires_at=_iso_after_seconds(fail_ttl),
                    version_exit_code=int(ver_proc.returncode),
                    wsl_binary_identity=wsl_binary_identity,
                )
                return snap, fail_ttl, r_sha, b_sha, cfg_fp, None

            # Stage 3 & 4: Real Java canary scan using IMMUTABLE snapshot rules + strict oracle check
            scan_timeout_arg = max(1, int(min(step_timeout, float(self.config.opengrep_timeout_seconds))))
            scan_cmd = [
                resolved_bin,
                "scan",
                "--config",
                str(snapshot_rules_path.resolve()),
                "--json",
                "--dataflow-traces",
                "--no-git-ignore",
                "--disable-version-check",
                "--jobs",
                "1",
                "--timeout",
                str(scan_timeout_arg),
                "--include",
                "*.java",
                str(canary_dir.resolve()),
            ]
            t_scan0 = time.monotonic()
            try:
                scan_proc = intake._run_git_step(
                    "opengrep-health-canary",
                    scan_cmd,
                    timeout_seconds=step_timeout,
                    env=env,
                    max_output_bytes=MAX_HEALTH_PROBE_SCAN_OUTPUT_BYTES,
                    cancel_event=self._cancel_event,
                )
            except Exception as exc:
                return _map_step_error(
                    exc,
                    stage_label="canary_scan",
                    reached_level="VERSION_IDENTIFIED",
                    ver_str=ver_display,
                    ver_exit=int(ver_proc.returncode),
                )
            canary_ms = round((time.monotonic() - t_scan0) * 1000.0, 2)

            if scan_proc.returncode != 0:
                stderr_hint = scan_proc.stderr.decode("utf-8", errors="replace").strip()[:200]
                snap = self._base_payload(
                    available=False,
                    probe_status="CANARY_FAILED",
                    verification_level="VERSION_IDENTIFIED",
                    bin_info=bin_info,
                    rules_sha256=r_sha,
                    version=ver_display,
                    error=(
                        f"OpenGrep canary scan thất bại (exit {scan_proc.returncode})"
                        + (f": {stderr_hint}" if stderr_hint else ".")
                    ),
                    failure_code="SCAN_EXIT_NONZERO",
                    probed_at=now(),
                    expires_at=_iso_after_seconds(fail_ttl),
                    version_exit_code=int(ver_proc.returncode),
                    canary_exit_code=int(scan_proc.returncode),
                    canary_duration_ms=canary_ms,
                    wsl_binary_identity=wsl_binary_identity,
                )
                return snap, fail_ttl, r_sha, b_sha, cfg_fp, None

            scan_exec_ok, scan_ver_ok, canary_summary, c_fcode, c_err = verify_canary_scan_output(
                scan_proc.stdout,
                expected_version_tuple=ver_tuple,
                rules_info=rules_info,
                expected_canary_path=canary_file,
                require_offset=True,
            )
            if not scan_ver_ok:
                reached = "SCAN_EXECUTED" if scan_exec_ok else "VERSION_IDENTIFIED"
                snap = self._base_payload(
                    available=False,
                    probe_status="CANARY_FAILED",
                    verification_level=reached,
                    bin_info=bin_info,
                    rules_sha256=r_sha,
                    version=ver_display,
                    error=c_err,
                    failure_code=c_fcode,
                    probed_at=now(),
                    expires_at=_iso_after_seconds(fail_ttl),
                    version_exit_code=int(ver_proc.returncode),
                    canary_exit_code=int(scan_proc.returncode),
                    canary_duration_ms=canary_ms,
                    canary_summary=canary_summary,
                    wsl_binary_identity=wsl_binary_identity,
                )
                return snap, fail_ttl, r_sha, b_sha, cfg_fp, None

            # Post-scan TOCTOU re-check: refuse VERIFIED if rules, execution chain, config, or WSL binary mutated during probe!
            wsl_changed = False
            if wsl_binary_identity is not None and wsl_prefix_used is not None and wsl_resolved_linux is not None:
                post_wsl_timeout = float(step_timeout)
                try:
                    post_rl = intake._run_git_step(
                        "opengrep-health-wsl-realpath",
                        [*wsl_prefix_used, "readlink", "-f", "--", wsl_linux_path],
                        timeout_seconds=post_wsl_timeout,
                        env=env,
                        max_output_bytes=MAX_HEALTH_PROBE_WSL_ID_OUTPUT_BYTES,
                        cancel_event=self._cancel_event,
                    )
                except Exception as exc:
                    return _map_step_error(
                        exc,
                        stage_label="wsl_binary_identity:post_realpath",
                        reached_level="SCAN_EXECUTED",
                        ver_str=ver_display,
                        ver_exit=int(ver_proc.returncode),
                        actual_timeout=post_wsl_timeout,
                    )
                post_rl_path = post_rl.stdout.decode("utf-8", errors="replace").strip() if post_rl.returncode == 0 else ""
                if post_rl.returncode != 0 or post_rl_path != wsl_resolved_linux:
                    wsl_changed = True
                else:
                    try:
                        post_sha_p = intake._run_git_step(
                            "opengrep-health-wsl-sha256",
                            [*wsl_prefix_used, "sha256sum", "--", post_rl_path],
                            timeout_seconds=post_wsl_timeout,
                            env=env,
                            max_output_bytes=MAX_HEALTH_PROBE_WSL_ID_OUTPUT_BYTES,
                            cancel_event=self._cancel_event,
                        )
                    except Exception as exc:
                        return _map_step_error(
                            exc,
                            stage_label="wsl_binary_identity:post_sha256",
                            reached_level="SCAN_EXECUTED",
                            ver_str=ver_display,
                            ver_exit=int(ver_proc.returncode),
                            actual_timeout=post_wsl_timeout,
                        )
                    post_wsl_sha = None
                    if post_sha_p.returncode == 0:
                        lines = post_sha_p.stdout.decode("utf-8", errors="replace").strip().splitlines()
                        if lines:
                            toks = lines[0].split()
                            cand = toks[0].lower() if toks else ""
                            if _SHA256_HEX_RE.fullmatch(cand):
                                post_wsl_sha = cand
                    if post_wsl_sha != wsl_binary_identity.get("sha256"):
                        wsl_changed = True

            post_p1 = self._read_live_inputs_once(reverse=False)
            post_p2 = self._read_live_inputs_once(reverse=True)
            post_consistent, _ = self._inputs_consistent(post_p1, post_p2)
            post_bin = post_p2["bin_info"]
            post_rules_sha = post_p2["rules_eval"].get("sha256")
            post_cfg_fp = post_p2["cfg_fp"]
            if (
                not post_consistent
                or not post_bin["found"]
                or post_bin.get("binary_identity_sha256") != b_sha
                or post_rules_sha != r_sha
                or p_start["rules_eval"].get("sha256") != r_sha
                or post_cfg_fp != cfg_fp
                or wsl_changed
                or self._cancel_event.is_set()
            ):
                snap = self._base_payload(
                    available=False,
                    probe_status="NOT_VERIFIED",
                    verification_level="SCAN_EXECUTED",
                    bin_info=post_bin if post_bin["found"] else bin_info,
                    rules_sha256=post_rules_sha,
                    version=ver_display,
                    error="Binary, dependency, binary WSL hoặc tập luật OpenGrep đã thay đổi trong lúc chạy probe; cần tái xác minh.",
                    failure_code="INPUT_CHANGED_DURING_PROBE",
                    invalidation_reason="INPUT_CHANGED_DURING_PROBE",
                    probed_at=now(),
                    expires_at=_iso_after_seconds(fail_ttl),
                    version_exit_code=int(ver_proc.returncode),
                    canary_exit_code=int(scan_proc.returncode),
                    canary_duration_ms=canary_ms,
                    canary_summary=canary_summary,
                    wsl_binary_identity=wsl_binary_identity,
                )
                return snap, fail_ttl, post_rules_sha, post_bin.get("binary_identity_sha256"), post_cfg_fp, None

            exec_id_doc = {
                "binary_identity_sha256": b_sha,
                "wsl_binary_identity": wsl_binary_identity,
                "rules_sha256": r_sha,
                "version": ver_display,
                "config_fingerprint": cfg_fp,
            }
            probe_exec_id = digest(json.dumps(exec_id_doc, sort_keys=True, ensure_ascii=False).encode("utf-8"))
            verified_snap = self._base_payload(
                available=True,
                probe_status="VERIFIED",
                verification_level="SCAN_VERIFIED",
                bin_info=bin_info,
                rules_sha256=r_sha,
                version=ver_display,
                error=None,
                failure_code=None,
                probed_at=now(),
                expires_at=_iso_after_seconds(ok_ttl),
                version_exit_code=int(ver_proc.returncode),
                canary_exit_code=int(scan_proc.returncode),
                canary_duration_ms=canary_ms,
                canary_summary=canary_summary,
                wsl_binary_identity=wsl_binary_identity,
                probe_execution_identity_sha256=probe_exec_id,
            )
            return verified_snap, ok_ttl, r_sha, b_sha, cfg_fp, {"clean": True, "step": "opengrep-health-canary"}

    def evaluate_readiness_snapshot(
        self,
        *,
        trigger_refresh: bool = True,
        force: bool = False,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Atomic two-phase linearization point returning `(opengrep_status, rules_eval)`.

        Uses forward read P1 `[config -> binary -> rules]` before acquiring `self._lock` and reverse read P2
        `[rules -> binary -> config]` outside `self._lock` when validating a cached `VERIFIED` snapshot,
        preventing torn health outputs when inputs mutate concurrently.
        """
        def _public_rules_eval(rev: dict[str, Any]) -> dict[str, Any]:
            return {
                "available": bool(rev.get("available")),
                "sha256": rev.get("sha256"),
                "name": rev.get("name"),
            }

        p1 = self._read_live_inputs_once(reverse=False)
        bin_info = p1["bin_info"]
        rules_eval = _public_rules_eval(p1["rules_eval"])
        live_rules_sha: str | None = rules_eval["sha256"]
        rules_readable = bool(rules_eval["available"])
        enabled = bool(getattr(self.config, "opengrep_health_probe_enabled", True))
        cfg_fp = p1["cfg_fp"]
        live_b_sha = bin_info.get("binary_identity_sha256")

        while True:
            with self._lock:
                # --- LINEARIZATION POINT (T_decision) ---
                now_mono = self._clock()
                snap = self._snapshot
                deferred = False

                reg = intake.inspect_lingering_registry_state(step_prefix="opengrep-health-")
                orphaned_or_shutdown_active = (self._shutting_down or not self._in_flight) and (
                    reg["non_closed_count"] > 0 or reg["live_process_count"] > 0
                )
                if orphaned_or_shutdown_active or reg["blocking_count"] > 0 or reg["registry_fault"]:
                    self._cleanup_failed = True

                # 1. Highest priority: CLEANUP_FAILED (never masked by SHUTTING_DOWN!)
                if self._cleanup_failed or (self._shutdown_result is not None and not self._shutdown_result.get("clean")):
                    still_blocked = (
                        self._shutting_down
                        or reg["blocking_count"] > 0
                        or orphaned_or_shutdown_active
                        or bool(reg["registry_fault"])
                        or now_mono < self._snapshot_expires_mono
                    )
                    if still_blocked:
                        return (
                            self._base_payload(
                                available=False,
                                probe_status="CLEANUP_FAILED",
                                verification_level=str((snap or {}).get("verification_level") or "NONE"),
                                bin_info=bin_info,
                                rules_sha256=live_rules_sha,
                                error=(
                                    (snap or {}).get("error")
                                    or "Không xác nhận được việc dừng sạch cây tiến trình OpenGrep health probe (CLEANUP_FAILED)."
                                ),
                                failure_code="PROBE_CLEANUP_FAILED",
                                probed_at=(snap or {}).get("probed_at"),
                                expires_at=(snap or {}).get("expires_at"),
                                probe_in_progress=self._in_flight,
                                process_cleanup=self._last_step_cleanup,
                            ),
                            rules_eval,
                        )
                    # Server is still running, fail cooldown elapsed, and registry is now clean -> allow recovery probe
                    self._cleanup_failed = False
                    self._snapshot = None
                    self._snapshot_expires_mono = 0.0
                    snap = None

                # 2. Clean shutdown state
                if self._shutting_down:
                    return (
                        self._base_payload(
                            available=False,
                            probe_status="SHUTTING_DOWN",
                            verification_level="NONE",
                            bin_info={"executable": self.config.opengrep_binary, "resolved_path": None, "wrapper_targets": []},
                            rules_sha256=live_rules_sha,
                            error="Máy chủ API đang dừng; từ chối chạy kiểm chứng OpenGrep mới.",
                            failure_code="SHUTTING_DOWN",
                        ),
                        rules_eval,
                    )

                # 3. Missing/unreadable binary or broken execution chain
                if not bin_info["found"]:
                    self._snapshot = None
                    self._snapshot_expires_mono = 0.0
                    self._invalidation_epoch += 1
                    bin_exists = bool(bin_info.get("binary_exists"))
                    return (
                        self._base_payload(
                            available=False,
                            probe_status="FAILED" if bin_exists else "UNAVAILABLE",
                            verification_level="BINARY_FOUND" if bin_exists else "NONE",
                            bin_info=bin_info,
                            rules_sha256=live_rules_sha,
                            error=bin_info["error"],
                            failure_code=bin_info["failure_code"],
                            probe_in_progress=self._in_flight,
                        ),
                        rules_eval,
                    )

                if not rules_readable:
                    self._snapshot = None
                    self._snapshot_expires_mono = 0.0
                    self._invalidation_epoch += 1
                    return (
                        self._base_payload(
                            available=False,
                            probe_status="RULES_INVALID",
                            verification_level="BINARY_FOUND",
                            bin_info=bin_info,
                            rules_sha256=None,
                            error=f"Tệp tập luật OpenGrep ({self.config.rules_path}) không tồn tại hoặc không thể đọc.",
                            failure_code="RULES_UNREADABLE",
                            probe_in_progress=self._in_flight,
                        ),
                        rules_eval,
                    )

                def _maybe_trigger_locked() -> None:
                    nonlocal deferred
                    if not enabled or not trigger_refresh or self._shutting_down or self._in_flight:
                        return
                    if self._is_scan_busy() and not force:
                        deferred = True
                        return
                    self._spawn_worker_locked()

                err_map = {
                    "SNAPSHOT_EXPIRED": "Snapshot xác minh OpenGrep đã hết hiệu lực TTL; đang chờ tái xác minh.",
                    "RULES_SHA256_CHANGED": "Tập luật OpenGrep (rules SHA-256) đã thay đổi; đã hủy hiệu lực snapshot và cần tái xác minh.",
                    "BINARY_IDENTITY_CHANGED": "Binary, wrapper hoặc dependency OpenGrep đã thay đổi; đã hủy hiệu lực snapshot và cần tái xác minh.",
                    "CONFIG_CHANGED": "Cấu hình OpenGrep đã thay đổi; đã hủy hiệu lực snapshot và cần tái xác minh.",
                    "INSTANCE_MISMATCH": "Snapshot không khớp phiên bản tiến trình hiện hành; đã hủy hiệu lực.",
                }

                # 4. Evaluate VERIFIED snapshot against ALL live inputs + TTL at T_decision
                if snap is not None and snap.get("probe_status") == "VERIFIED" and not force:
                    invalidation: str | None = None
                    if snap.get("process_instance_id") != self.process_instance_id:
                        invalidation = "INSTANCE_MISMATCH"
                    elif live_rules_sha != self._snapshot_rules_sha256 or snap.get("rules_sha256") != live_rules_sha:
                        invalidation = "RULES_SHA256_CHANGED"
                    elif live_b_sha != self._snapshot_binary_identity_sha256 or snap.get("binary_identity_sha256") != live_b_sha:
                        invalidation = "BINARY_IDENTITY_CHANGED"
                    elif cfg_fp != self._snapshot_config_fingerprint:
                        invalidation = "CONFIG_CHANGED"
                    elif now_mono >= self._snapshot_expires_mono:
                        invalidation = "SNAPSHOT_EXPIRED"

                    if invalidation is not None:
                        # Fail-closed invalidation: clear cached VERIFIED snapshot immediately & bump epoch on input change.
                        self._snapshot = None
                        self._snapshot_expires_mono = 0.0
                        if invalidation != "SNAPSHOT_EXPIRED":
                            self._invalidation_epoch += 1
                        _maybe_trigger_locked()
                        p_status = "EXPIRED" if invalidation == "SNAPSHOT_EXPIRED" else "NOT_VERIFIED"
                        return (
                            self._base_payload(
                                available=False,
                                probe_status=p_status,
                                verification_level="BINARY_FOUND",
                                bin_info=bin_info,
                                rules_sha256=live_rules_sha,
                                version=None,
                                error=err_map[invalidation],
                                failure_code=invalidation,
                                invalidation_reason=invalidation,
                                probed_at=snap.get("probed_at"),
                                expires_at=snap.get("expires_at"),
                                probe_in_progress=self._in_flight,
                                deferred_by_active_scan=deferred,
                            ),
                            rules_eval,
                        )

                    snap_ref = snap
                    epoch_ref = self._invalidation_epoch
                else:
                    snap_ref = None
                    epoch_ref = -1

            if snap_ref is None:
                break

            # Reverse stabilization read P2 outside `self._lock` (`[rules -> binary -> config]`)
            p2 = self._read_live_inputs_once(reverse=True)
            consistent, mismatch_code = self._inputs_consistent(p1, p2)
            p2_bin = p2["bin_info"]
            p2_rules = _public_rules_eval(p2["rules_eval"])
            p2_rules_sha = p2_rules["sha256"]
            p2_b_sha = p2_bin.get("binary_identity_sha256")
            p2_cfg = p2["cfg_fp"]

            with self._lock:
                now_mono2 = self._clock()
                reg2 = intake.inspect_lingering_registry_state(step_prefix="opengrep-health-")
                orphaned2 = (self._shutting_down or not self._in_flight) and (
                    reg2["non_closed_count"] > 0 or reg2["live_process_count"] > 0
                )
                if orphaned2 or reg2["blocking_count"] > 0 or reg2["registry_fault"]:
                    self._cleanup_failed = True
                if self._cleanup_failed or (self._shutdown_result is not None and not self._shutdown_result.get("clean")):
                    return (
                        self._base_payload(
                            available=False,
                            probe_status="CLEANUP_FAILED",
                            verification_level=str(snap_ref.get("verification_level") or "NONE"),
                            bin_info=p2_bin,
                            rules_sha256=p2_rules_sha,
                            error="Không xác nhận được việc dừng sạch cây tiến trình OpenGrep health probe (CLEANUP_FAILED).",
                            failure_code="PROBE_CLEANUP_FAILED",
                            probed_at=snap_ref.get("probed_at"),
                            expires_at=snap_ref.get("expires_at"),
                            probe_in_progress=self._in_flight,
                            process_cleanup=self._last_step_cleanup,
                        ),
                        p2_rules,
                    )
                if self._shutting_down:
                    return (
                        self._base_payload(
                            available=False,
                            probe_status="SHUTTING_DOWN",
                            verification_level="NONE",
                            bin_info={"executable": self.config.opengrep_binary, "resolved_path": None, "wrapper_targets": []},
                            rules_sha256=p2_rules_sha,
                            error="Máy chủ API đang dừng; từ chối chạy kiểm chứng OpenGrep mới.",
                            failure_code="SHUTTING_DOWN",
                        ),
                        p2_rules,
                    )
                if not p2_bin["found"]:
                    self._snapshot = None
                    self._snapshot_expires_mono = 0.0
                    self._invalidation_epoch += 1
                    bin_exists2 = bool(p2_bin.get("binary_exists"))
                    return (
                        self._base_payload(
                            available=False,
                            probe_status="FAILED" if bin_exists2 else "UNAVAILABLE",
                            verification_level="BINARY_FOUND" if bin_exists2 else "NONE",
                            bin_info=p2_bin,
                            rules_sha256=p2_rules_sha,
                            error=p2_bin["error"],
                            failure_code=p2_bin["failure_code"],
                            probe_in_progress=self._in_flight,
                        ),
                        p2_rules,
                    )
                if not p2_rules["available"]:
                    self._snapshot = None
                    self._snapshot_expires_mono = 0.0
                    self._invalidation_epoch += 1
                    return (
                        self._base_payload(
                            available=False,
                            probe_status="RULES_INVALID",
                            verification_level="BINARY_FOUND",
                            bin_info=p2_bin,
                            rules_sha256=None,
                            error=f"Tệp tập luật OpenGrep ({self.config.rules_path}) không tồn tại hoặc không thể đọc.",
                            failure_code="RULES_UNREADABLE",
                            probe_in_progress=self._in_flight,
                        ),
                        p2_rules,
                    )

                invalidation2: str | None = None
                if not consistent:
                    invalidation2 = mismatch_code or "RULES_SHA256_CHANGED"
                elif self._snapshot is not snap_ref or self._invalidation_epoch != epoch_ref:
                    # Refresh P1 and re-evaluate cleanly if a concurrent worker replaced the snapshot
                    p1 = p2
                    bin_info = p2_bin
                    rules_eval = p2_rules
                    live_rules_sha = p2_rules_sha
                    rules_readable = bool(p2_rules["available"])
                    cfg_fp = p2_cfg
                    live_b_sha = p2_b_sha
                    continue
                elif p2_rules_sha != self._snapshot_rules_sha256 or snap_ref.get("rules_sha256") != p2_rules_sha:
                    invalidation2 = "RULES_SHA256_CHANGED"
                elif p2_b_sha != self._snapshot_binary_identity_sha256 or snap_ref.get("binary_identity_sha256") != p2_b_sha:
                    invalidation2 = "BINARY_IDENTITY_CHANGED"
                elif p2_cfg != self._snapshot_config_fingerprint:
                    invalidation2 = "CONFIG_CHANGED"
                elif now_mono2 >= self._snapshot_expires_mono:
                    invalidation2 = "SNAPSHOT_EXPIRED"

                if invalidation2 is None:
                    out = copy.deepcopy(snap_ref)
                    out["probe_in_progress"] = self._in_flight
                    if self._last_real_scan_observed is not None:
                        out["last_real_scan_observed"] = copy.deepcopy(self._last_real_scan_observed)
                    return out, p2_rules

                self._snapshot = None
                self._snapshot_expires_mono = 0.0
                if invalidation2 != "SNAPSHOT_EXPIRED":
                    self._invalidation_epoch += 1
                if enabled and trigger_refresh and not self._shutting_down and not self._in_flight:
                    if not (self._is_scan_busy() and not force):
                        self._spawn_worker_locked()
                    else:
                        deferred = True
                p_status2 = "EXPIRED" if invalidation2 == "SNAPSHOT_EXPIRED" else "NOT_VERIFIED"
                return (
                    self._base_payload(
                        available=False,
                        probe_status=p_status2,
                        verification_level="BINARY_FOUND",
                        bin_info=p2_bin,
                        rules_sha256=p2_rules_sha,
                        version=None,
                        error=err_map.get(invalidation2, err_map["RULES_SHA256_CHANGED"]),
                        failure_code=invalidation2,
                        invalidation_reason=invalidation2,
                        probed_at=snap_ref.get("probed_at"),
                        expires_at=snap_ref.get("expires_at"),
                        probe_in_progress=self._in_flight,
                        deferred_by_active_scan=deferred,
                    ),
                    p2_rules,
                )

        # Non-VERIFIED or pending paths evaluated under single lock hold with consistent P1
        with self._lock:
            now_mono = self._clock()
            snap = self._snapshot
            deferred = False

            def _maybe_trigger_locked2() -> None:
                nonlocal deferred
                if not enabled or not trigger_refresh or self._shutting_down or self._in_flight:
                    return
                if self._is_scan_busy() and not force:
                    deferred = True
                    return
                self._spawn_worker_locked()

            # 5. Evaluate existing non-VERIFIED snapshot
            if snap is not None and not force:
                invalidation_reason: str | None = None
                if live_rules_sha != self._snapshot_rules_sha256:
                    invalidation_reason = "RULES_SHA256_CHANGED"
                elif live_b_sha != self._snapshot_binary_identity_sha256:
                    invalidation_reason = "BINARY_IDENTITY_CHANGED"
                elif cfg_fp != self._snapshot_config_fingerprint:
                    invalidation_reason = "CONFIG_CHANGED"

                if invalidation_reason is not None:
                    self._snapshot = None
                    self._snapshot_expires_mono = 0.0
                    self._invalidation_epoch += 1
                    _maybe_trigger_locked2()
                    return (
                        self._base_payload(
                            available=False,
                            probe_status="NOT_VERIFIED",
                            verification_level="BINARY_FOUND",
                            bin_info=bin_info,
                            rules_sha256=live_rules_sha,
                            version=None,
                            error="Đầu vào OpenGrep (binary/wrapper/dependency/rules/config) đã thay đổi; đang chờ tái xác minh.",
                            failure_code=invalidation_reason,
                            invalidation_reason=invalidation_reason,
                            probed_at=snap.get("probed_at"),
                            expires_at=snap.get("expires_at"),
                            probe_in_progress=self._in_flight,
                            deferred_by_active_scan=deferred,
                        ),
                        rules_eval,
                    )

                cooldown_expired = now_mono >= self._snapshot_expires_mono
                if cooldown_expired:
                    _maybe_trigger_locked2()
                out = copy.deepcopy(snap)
                out["rules_sha256"] = live_rules_sha
                out["probe_in_progress"] = self._in_flight
                out["deferred_by_active_scan"] = deferred
                if self._last_real_scan_observed is not None:
                    out["last_real_scan_observed"] = copy.deepcopy(self._last_real_scan_observed)
                return out, rules_eval

            # 6. Force invalidation or initial pending state
            if force:
                self._snapshot = None
                self._snapshot_expires_mono = 0.0
                self._invalidation_epoch += 1
            _maybe_trigger_locked2()
            return (
                self._base_payload(
                    available=False,
                    probe_status="NOT_VERIFIED",
                    verification_level="BINARY_FOUND",
                    bin_info=bin_info,
                    rules_sha256=live_rules_sha,
                    version=None,
                    error=(
                        "Đang chạy kiểm chứng thực thi OpenGrep (version + Java canary); chưa thể công bố VERIFIED."
                        if enabled
                        else "Cơ chế active probe OpenGrep trên /api/health đang tắt theo cấu hình."
                    ),
                    failure_code="PROBE_PENDING" if enabled else "PROBE_DISABLED",
                    probe_in_progress=self._in_flight,
                    deferred_by_active_scan=deferred,
                ),
                rules_eval,
            )

    def get_status(self, *, trigger_refresh: bool = True, force: bool = False) -> dict[str, Any]:
        """Return current OpenGrep probe status immediately without blocking on subprocesses."""
        og, _rules_eval = self.evaluate_readiness_snapshot(trigger_refresh=trigger_refresh, force=force)
        return og

    def notify_real_scan_completed(self, *, engine_version: str | None = None) -> bool:
        """Record a completed real Stage 2 OpenGrep scan and trigger a non-blocking canary re-probe if stale/timed out.

        Security invariant: NEVER sets `available=True`, `runtime_verified=True`, or `probe_status="VERIFIED"`.
        Only clears failure cooldown (or an expired VERIFIED snapshot) and schedules one single-flight active
        canary probe when the probe was previously stuck in `TIMEOUT`, `EXPIRED`, `NOT_VERIFIED`, or held a
        `VERIFIED` snapshot whose TTL has already elapsed.
        """
        with self._lock:
            self._last_real_scan_observed = {
                "observed_at": now(),
                "engine_version": engine_version,
                "process_instance_id": self.process_instance_id,
            }
            if (
                not bool(getattr(self.config, "opengrep_health_probe_enabled", True))
                or self._shutting_down
                or self._cleanup_failed
                or self._in_flight
            ):
                return False
            now_mono = self._clock()
            snap = self._snapshot
            expired_verified = False
            if snap is not None and snap.get("probe_status") == "VERIFIED":
                if now_mono < self._snapshot_expires_mono:
                    return False
                expired_verified = True
            elif snap is not None and snap.get("probe_status") not in ("TIMEOUT", "EXPIRED", "NOT_VERIFIED"):
                return False
            reg = intake.inspect_lingering_registry_state(step_prefix="opengrep-health-")
            if reg["blocking_count"] > 0 or reg["non_closed_count"] > 0 or reg["registry_fault"]:
                self._cleanup_failed = True
                return False
            if self._is_scan_busy():
                return False
            if expired_verified:
                self._snapshot = None
            self._snapshot_expires_mono = 0.0
            return self._spawn_worker_locked()

    def wait_for_probe(self, timeout: float = 35.0) -> bool:
        """Wait bounded time for the current in-flight probe (if any) to complete."""
        return self._done_event.wait(timeout=max(0.0, float(timeout)))

    def probe_run_count(self) -> int:
        with self._lock:
            return self._probe_run_count

    def shutdown(self, *, wait_seconds: float = 3.0) -> dict[str, Any]:
        """Cancel any active probe, verify true process/job/registry cleanup, and preserve CLEANUP_FAILED."""
        with self._lock:
            self._shutting_down = True
            self._cancel_event.set()
            worker = self._worker_thread
        if worker is not None and worker.is_alive():
            worker.join(timeout=max(0.0, float(wait_seconds)))
        still_alive = bool(worker is not None and worker.is_alive())
        reg = intake.inspect_lingering_registry_state(step_prefix="opengrep-health-")
        reg_has_blocking = reg["blocking_count"] > 0
        reg_has_non_closed = reg["non_closed_count"] > 0 or reg["live_process_count"] > 0
        reg_has_fault = bool(reg["registry_fault"])
        reg_unclean = reg_has_blocking or reg_has_non_closed or reg_has_fault
        with self._lock:
            step_cleanup = copy.deepcopy(self._last_step_cleanup)
            worker_reported_cleanup_fail = self._cleanup_failed
            root_exited = (
                bool(step_cleanup.get("root_exited"))
                if isinstance(step_cleanup, dict) and "root_exited" in step_cleanup
                else (not still_alive)
            ) and (not still_alive) and (reg["live_process_count"] == 0)
            children_exited = (
                (
                    bool(step_cleanup.get("children_exited", step_cleanup.get("remaining_processes") == 0))
                    if isinstance(step_cleanup, dict) and ("children_exited" in step_cleanup or "remaining_processes" in step_cleanup)
                    else (not still_alive)
                )
                and (not still_alive)
                and (not reg_unclean)
            )
            job_closed = (
                (
                    bool(step_cleanup.get("job_closed", step_cleanup.get("handle_closed")))
                    if isinstance(step_cleanup, dict) and ("job_closed" in step_cleanup or "handle_closed" in step_cleanup)
                    else (not still_alive)
                )
                and (not still_alive)
                and (not reg_unclean)
            )
            step_clean_ok = (
                bool(step_cleanup.get("clean"))
                if isinstance(step_cleanup, dict)
                else True
            )
            cleanup_clean = bool(
                (not still_alive)
                and (not worker_reported_cleanup_fail)
                and step_clean_ok
                and (not reg_unclean)
            )
            if not cleanup_clean:
                self._cleanup_failed = True
                if still_alive:
                    f_code = "PROBE_WORKER_STILL_ALIVE"
                elif worker_reported_cleanup_fail or not step_clean_ok:
                    f_code = "PROBE_CLEANUP_FAILED"
                elif reg_has_fault:
                    f_code = "PROBE_REGISTRY_FAULT"
                elif reg_has_blocking:
                    f_code = "PROBE_REGISTRY_PENDING"
                else:
                    f_code = "PROBE_REGISTRY_ACTIVE"
            else:
                f_code = None

            result = {
                "clean": cleanup_clean,
                "status": "SHUTTING_DOWN" if cleanup_clean else "CLEANUP_FAILED",
                "failure_code": f_code,
                "worker_stopped": not still_alive,
                "worker_alive": still_alive,
                "root_exited": root_exited,
                "children_exited": children_exited,
                "job_closed": job_closed,
                "registry_state": reg["registry_state"],
                "registry_safe": reg["registry_safe"],
                "process_cleanup": step_cleanup,
            }
            self._shutdown_result = result
            return copy.deepcopy(result)
