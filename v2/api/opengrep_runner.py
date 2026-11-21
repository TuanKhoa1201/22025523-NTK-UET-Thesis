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

import json
import os
from typing import Any

from v2.api import intake

# Cap for each captured OpenGrep stream; exceeding it fails the step instead of truncating JSON/SARIF.
MAX_OPENGREP_OUTPUT_BYTES = 256 * 1024 * 1024


def make_bounded_scanner_class(base_scanner_cls: type, scan_error_cls: type) -> type:
    """Build a SemgrepScanner subclass whose engine subprocesses are time-bounded as a process tree."""

    class OpenGrepRunError(scan_error_cls):  # type: ignore[misc, valid-type]
        def __init__(self, error_code: str, message: str, details: dict[str, Any] | None = None):
            super().__init__(message)
            self.error_code = error_code
            self.details = dict(details or {})

    class BoundedOpenGrepScanner(base_scanner_cls):  # type: ignore[misc, valid-type]
        RunError = OpenGrepRunError

        def _process_timeout(self) -> float:
            # Same bound as the sealed baseline scanner; deliberately not increased.
            return self.config.timeout + 30

        def _write_failure(self, label: str, payload: dict[str, Any]) -> None:
            (self.output_dir / (label + ".failure.txt")).write_text(
                json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
            )

        def _run(self, label, command):
            env = os.environ.copy()
            env["SEMGREP_LOG_FILE"] = str(self.output_dir / "opengrep.log")
            env["SEMGREP_SETTINGS_FILE"] = str(self.output_dir / "settings.yml")
            env["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
            env["OPENGREP_ENABLE_VERSION_CHECK"] = "0"
            env["SEMGREP_SEND_METRICS"] = "off"
            (self.output_dir / (label + ".command.json")).write_text(
                json.dumps(command, indent=2), encoding="utf-8")
            bound = self._process_timeout()
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
                details: dict[str, Any] = {
                    "engine_step": label,
                    "timeout_seconds": bound,
                    "process_cleanup": cleanup,
                    "stderr_bytes": exc.stderr_bytes,
                }
                message = f"{label}: OpenGrep vượt giới hạn {bound} giây; đã dừng cây tiến trình."
                if not cleanup.get("clean"):
                    details["cleanup_status"] = "CLEANUP_FAILED"
                    message = (
                        f"{label}: OpenGrep vượt giới hạn {bound} giây; không xác nhận được việc dừng "
                        "toàn bộ tiến trình con (CLEANUP_FAILED)."
                    )
                self._write_failure(label, {"error_code": "OPENGREP_TIMEOUT", "message": message, **details})
                raise OpenGrepRunError("OPENGREP_TIMEOUT", message, details) from None
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
