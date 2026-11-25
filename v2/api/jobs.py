"""Asynchronous, bounded scan job runner orchestrating OpenGrep -> Evidence -> Qwen -> ReviewStore.

Preserves 100% of sealed `v2.triage` and `v2.g1_integration` contracts:
- Runs OpenGrep ONCE via `v2.baseline.fork.semgrepai.scanner.SemgrepScanner` (recording `scan-manifest.json`).
- Verifies JSON/SARIF parity via `v2.g1_integration.finding_identity.compare_findings`.
- Hands off raw `opengrep.json` + `scan-manifest.json` + `derive_trusted_path_maps` to `v2.triage.cli.run`
  under `_forbid_implicit_scanner_rescan()`.
- Tracks live finding-by-finding progress via `v2.triage.cli.run`'s `--checkpoint` JSONL stream without
  fabricated stages or artificial timers.
"""
from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
import copy
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
from typing import Any
import uuid

from v2.api.config import ApiConfig, REPO_ROOT
from v2.api.intake import IntakeError, clone_github_repo, extract_safe_zip, validate_github_url
from v2.api.opengrep_runner import make_bounded_scanner_class
from v2.api.qwen_triage import StorageCommitError, run_bounded_triage
from v2.api.service import (
    ApiServiceError,
    MANAGED_COMMIT_SCHEMA,
    MANAGED_META_SCHEMA,
    acquire_publication_lock,
    collect_managed_artifact_sha256s,
    inspect_managed_job_dir_committed,
)
from v2.g1_integration.bridge import _forbid_implicit_scanner_rescan, derive_trusted_path_maps
from v2.g1_integration.finding_identity import compare_findings
from v2.g1_integration.fork_support.scanner_config import validate_opengrep_binary
from v2.triage import live_check, verify_http_capture
from v2.triage.evidence import EvidenceError, digest, now, strict_json

PIPELINE_STAGE_SPECS = (
    (1, "INTAKE_VALIDATION", "Tiếp nhận & kiểm tra an toàn mã nguồn Java"),
    (2, "OPENGREP_SCAN", "Phân tích tĩnh OpenGrep & ghi biên nhận băm nguồn"),
    (3, "EVIDENCE_COLLECTION", "Trích xuất bằng chứng & ngữ cảnh phương thức Java"),
    (4, "QWEN_INFERENCE", "Suy luận Qwen3.5-9B cục bộ qua Ollama (hợp đồng blind)"),
    (5, "CITATION_VALIDATION", "Kiểm chứng trích dẫn dòng mã thật & SHA-256"),
    (6, "REVIEW_STORE_COMMIT", "Khởi tạo hàng đợi Human Review trên SQLite"),
)


_SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_SAFE_DETAIL_TOKENS = ("git_step", "engine_step", "cleanup_status", "reason", "git_failure_kind", "output_stream",
                       "primary_error")
_SAFE_DETAIL_SCALARS = ("timeout_seconds", "root_exited", "stderr_bytes", "git_exit_code", "output_bytes", "limit_bytes")
_SAFE_CLEANUP_TOKENS = ("step", "ownership", "cleanup_error")
_SAFE_CLEANUP_SCALARS = ("terminate_ok", "root_exited", "remaining_processes", "handle_closed", "clean")


def _safe_scalar(value: Any) -> bool:
    return value is None or isinstance(value, (bool, int, float))


class _JobDeadlineTimeoutError(RuntimeError):
    """Internal control-flow signal raised when job_timeout_seconds expires during finalization."""


def _atomic_write_text(
    target: Path,
    text: str,
    *,
    before_replace: Callable[[], None] | None = None,
) -> None:
    tmp = target.parent / f".{target.name}.{os.getpid()}.{threading.get_ident()}.{uuid.uuid4().hex[:8]}.tmp"
    replaced = False
    try:
        tmp.write_text(text, encoding="utf-8")
        # On Windows NTFS, transient sharing violations (WinError 5/32) can occur briefly if another
        # reader holds a file handle; retry a few short ticks while still enforcing `before_replace`.
        max_attempts = 8 if os.name == "nt" else 1
        for attempt in range(max_attempts):
            if before_replace is not None:
                before_replace()
            try:
                tmp.replace(target)
                replaced = True
                break
            except PermissionError as exc:
                if os.name == "nt" and getattr(exc, "winerror", None) in (5, 32) and attempt + 1 < max_attempts:
                    time.sleep(0.005 * (attempt + 1))
                    continue
                raise
    finally:
        if not replaced:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass


def _mark_scan_meta_failed_best_effort(scan_out_root: Path, job_id: str, error_code: str) -> None:
    """Update any staged/FINALIZING api-scan-meta.json to explicit FAILED/unpublishable without deleting evidence."""
    meta_file = scan_out_root / "api-scan-meta.json"
    if not meta_file.is_file():
        return
    try:
        raw = json.loads(meta_file.read_text(encoding="utf-8"))
        doc = dict(raw) if isinstance(raw, dict) else {}
    except (OSError, ValueError):
        doc = {}
    doc.update(
        {
            "job_id": job_id,
            "scan_id": None,
            "job_state": "FAILED",
            "publishable": False,
            "error_code": error_code,
        }
    )
    try:
        _atomic_write_text(meta_file, json.dumps(doc, indent=2, ensure_ascii=False))
    except OSError:
        pass


def _finalize_failed_stages(doc: dict[str, Any], *, finished_ts: str, error_code: str, message: str) -> None:
    if not isinstance(doc.get("stages"), list):
        return
    for st in doc["stages"]:
        if not isinstance(st, dict):
            continue
        if st.get("state") == "RUNNING":
            st["state"] = "FAILED"
            st["finished_at"] = finished_ts
            if not st.get("error"):
                st["error"] = f"[{error_code}] {message}"
        elif st.get("state") == "PENDING":
            st["state"] = "SKIPPED"


def _write_failure_marker(
    scan_out_root: Path,
    job_id: str,
    error_code: str,
    message: str,
    *,
    extra: dict[str, Any] | None = None,
) -> None:
    if not scan_out_root.is_dir():
        return
    try:
        doc: dict[str, Any] = {
            "schema": "ntk-api-scan-failure-1",
            "job_id": job_id,
            "state": "FAILED",
            "publishable": False,
            "error_code": error_code,
            "error_message": message,
            "recorded_at": now(),
        }
        if extra:
            doc.update(extra)
        _atomic_write_text(
            scan_out_root / "api-scan-failure.json",
            json.dumps(doc, indent=2, ensure_ascii=False) + "\n",
        )
    except OSError:
        pass


def _collect_artifact_sha256s(scan_out_root: Path, *, no_llm: bool = True) -> dict[str, str]:
    """Compatibility wrapper over single authoritative `collect_managed_artifact_sha256s`."""
    hashes, _ = collect_managed_artifact_sha256s(scan_out_root, no_llm=no_llm)
    return hashes


def _verify_mixed_http_captures(triage_dir: Path, assessments_rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Verify live HTTP captures in a mixed cache+live run using an isolated temp staging directory.

    Live finding rows are verified strictly against real `llm_io/` byte captures without modifying
    real scan artifacts or classifying a mixed run as `live_chat_verified=True`.
    """
    cache_hits = 0
    live_calls = 0
    staged_rows: list[dict[str, Any]] = []
    for raw_row in assessments_rows:
        row = json.loads(json.dumps(raw_row))
        ass = row.get("assessment") if isinstance(row.get("assessment"), dict) else {}
        rt = ass.get("runtime") if isinstance(ass.get("runtime"), dict) else {}
        if rt.get("origin") == "cached_verified" or rt.get("cache_hit") is True or ass.get("transport") == "qwen-cache-verified":
            cache_hits += 1
            ass["transport"] = "disabled"
            ass["status"] = "UNDETERMINED"
            ass["validated_status"] = "UNDETERMINED"
            ass["runtime"] = {"origin": "disabled", "request_attempted": False}
            row["assessment"] = ass
        elif rt.get("request_attempted") is True:
            live_calls += 1
        staged_rows.append(row)

    with tempfile.TemporaryDirectory(prefix="ntk_mixed_cap_") as tmp_s:
        tmp_dir = Path(tmp_s)
        ev_src = triage_dir / "evidence.json"
        if ev_src.is_file():
            shutil.copy2(ev_src, tmp_dir / "evidence.json")
        io_src = triage_dir / "llm_io"
        if io_src.is_dir():
            shutil.copytree(io_src, tmp_dir / "llm_io")
        (tmp_dir / "assessments.jsonl").write_text(
            "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in staged_rows),
            encoding="utf-8",
        )
        res = verify_http_capture.verify_run_http_captures(tmp_dir, require_live_chat=False)

    cap_ok = bool(res.get("capture_integrity_ok"))
    return {
        "schema": "ntk-http-capture-verification-1",
        "capture_scope": "mixed_cache_and_live_http",
        "capture_status": "MIXED_CACHE_AND_LIVE_HTTP_VERIFIED" if cap_ok else "MIXED_CACHE_AND_LIVE_HTTP_FAILED",
        "capture_integrity_ok": cap_ok,
        "live_chat_verified": False,
        "total_findings": len(assessments_rows),
        "cache_hits": cache_hits,
        "live_calls": live_calls,
        "finding_checks": res.get("finding_checks"),
        "errors": res.get("errors"),
        "note": (
            "Phiên quét hỗn hợp (cache hit + live HTTP): các bản ghi gọi Qwen trực tiếp đã được đối chiếu "
            "raw HTTP byte-for-byte trong thư mục kiểm định cô lập; phiên hỗn hợp không được đánh dấu REAL_SCAN hay live_chat_verified."
        ),
    }


def _safe_error_details(details: dict[str, Any]) -> dict[str, Any]:
    """Allowlist structured, content-free diagnostics for job records and HTTP responses.

    Free-text fields (e.g. raw tool stderr) are dropped so credentials can never be persisted or served.
    """
    out: dict[str, Any] = {}
    for key in _SAFE_DETAIL_TOKENS:
        val = details.get(key)
        if isinstance(val, str) and _SAFE_TOKEN_RE.fullmatch(val):
            out[key] = val
    for key in _SAFE_DETAIL_SCALARS:
        if key in details and _safe_scalar(details[key]):
            out[key] = details[key]
    cleanup = details.get("process_cleanup")
    if isinstance(cleanup, dict):
        safe_c: dict[str, Any] = {}
        for key in _SAFE_CLEANUP_TOKENS:
            val = cleanup.get(key)
            if isinstance(val, str) and _SAFE_TOKEN_RE.fullmatch(val):
                safe_c[key] = val
        for key in _SAFE_CLEANUP_SCALARS:
            if key in cleanup and _safe_scalar(cleanup[key]):
                safe_c[key] = cleanup[key]
        out["process_cleanup"] = safe_c
    return out


def _initial_stages() -> list[dict[str, Any]]:
    return [
        {
            "stage_number": num,
            "stage_key": key,
            "stage_name": name,
            "state": "PENDING",
            "started_at": None,
            "finished_at": None,
            "duration_ms": None,
            "summary_metadata": None,
            "error": None,
        }
        for num, key, name in PIPELINE_STAGE_SPECS
    ]


def _load_baseline_scanner():
    fork_dir = str((REPO_ROOT / "v2" / "baseline" / "fork").resolve())
    if fork_dir not in sys.path:
        sys.path.insert(0, fork_dir)
    from semgrepai.config import OpenGrepConfig
    from semgrepai.scanner import ScanError, SemgrepScanner
    return OpenGrepConfig, SemgrepScanner, ScanError


class ScanJobManager:
    def __init__(self, config: ApiConfig):
        self.config = config
        self._lock = threading.Lock()
        self._jobs: dict[str, dict[str, Any]] = {}
        self._on_opengrep_scan_succeeded: Callable[..., Any] | None = None
        self._executor = ThreadPoolExecutor(
            max_workers=config.max_concurrent_scans,
            thread_name_prefix="ntk-scan-worker",
        )
        self._load_persisted_jobs()

    def set_on_opengrep_scan_succeeded(self, fn: Callable[..., Any] | None) -> None:
        with self._lock:
            self._on_opengrep_scan_succeeded = fn

    @property
    def jobs_dir(self) -> Path:
        return self.config.data_dir / "jobs"

    @property
    def workspaces_dir(self) -> Path:
        return self.config.data_dir / "workspaces"

    @property
    def scans_dir(self) -> Path:
        return self.config.data_dir / "scans"

    def _ensure_dirs(self) -> None:
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        self.workspaces_dir.mkdir(parents=True, exist_ok=True)
        self.scans_dir.mkdir(parents=True, exist_ok=True)

    def _load_persisted_jobs(self) -> None:
        if not self.jobs_dir.is_dir():
            return
        with acquire_publication_lock(self.config.data_dir):
            for jf in sorted(self.jobs_dir.glob("*.json")):
                try:
                    doc = json.loads(jf.read_text(encoding="utf-8"))
                    if not (isinstance(doc, dict) and isinstance(doc.get("job_id"), str)):
                        continue
                    jid = doc["job_id"]
                    scan_dir = self.scans_dir / jid
                    needs_persist = False
                    if doc.get("state") in ("QUEUED", "RUNNING"):
                        restarted_ts = now()
                        err_msg = "Tiến trình API khởi động lại khi job chưa hoàn tất; vui lòng chạy lại."
                        doc["state"] = "FAILED"
                        doc["scan_id"] = None
                        doc["error_code"] = "SERVER_RESTARTED_DURING_JOB"
                        doc["error_message"] = err_msg
                        doc["finished_at"] = restarted_ts
                        _finalize_failed_stages(
                            doc,
                            finished_ts=restarted_ts,
                            error_code="SERVER_RESTARTED_DURING_JOB",
                            message=err_msg,
                        )
                        needs_persist = True
                        if scan_dir.is_dir():
                            _mark_scan_meta_failed_best_effort(scan_dir, jid, "SERVER_RESTARTED_DURING_JOB")
                            _write_failure_marker(scan_dir, jid, "SERVER_RESTARTED_DURING_JOB", err_msg)
                    elif doc.get("state") == "COMPLETED":
                        # Apply the EXACT same commit & artifact-contract rule used by TriageApiService discovery.
                        has_scan_dir = scan_dir.is_dir()
                        must_verify = has_scan_dir or ("commit" in doc)
                        if must_verify:
                            chk = inspect_managed_job_dir_committed(
                                scan_dir=scan_dir,
                                owner_job_id=jid,
                                owner_job_doc=doc,
                                jobs_dir=self.jobs_dir,
                            )
                            if not chk.ok:
                                restarted_ts = now()
                                if chk.status == "ARTIFACT_INTEGRITY_FAILED":
                                    err_code = "COMMITTED_ARTIFACT_TAMPERED_OR_MISSING"
                                    err_msg = (
                                        f"Phát hiện artifact đã niêm phong bị thiếu hoặc thay đổi sau commit ({chk.reason}); "
                                        "thu hồi công bố scan và giữ nguyên bằng chứng còn lại để kiểm toán."
                                    )
                                    orig_sid = doc.get("scan_id")
                                    revoked = doc.pop("commit", None)
                                    if isinstance(revoked, dict):
                                        doc["revoked_commit"] = revoked
                                    revoked_sid = (
                                        revoked.get("scan_id")
                                        if isinstance(revoked, dict) and isinstance(revoked.get("scan_id"), str)
                                        else orig_sid
                                    )
                                    if isinstance(revoked_sid, str) and revoked_sid.strip():
                                        doc["revoked_scan_id"] = revoked_sid.strip()
                                    doc["integrity_failure"] = {
                                        "status": chk.status,
                                        "reason": chk.reason,
                                        "missing_artifacts": list(chk.missing_artifacts),
                                        "mismatched_artifacts": list(chk.mismatched_artifacts),
                                    }
                                else:
                                    err_code = "INCOMPLETE_COMMIT_ON_RESTART"
                                    err_msg = (
                                        f"Bản ghi job COMPLETED trên đĩa không khớp điểm commit hợp lệ sau khởi động lại "
                                        f"({chk.reason}); không công bố scan."
                                    )
                                    doc.pop("commit", None)
                                doc["state"] = "FAILED"
                                doc["scan_id"] = None
                                doc["error_code"] = err_code
                                doc["error_message"] = err_msg
                                doc["finished_at"] = restarted_ts
                                _finalize_failed_stages(
                                    doc,
                                    finished_ts=restarted_ts,
                                    error_code=err_code,
                                    message=err_msg,
                                )
                                needs_persist = True
                                if has_scan_dir:
                                    if chk.status != "ARTIFACT_INTEGRITY_FAILED":
                                        # Never overwrite original sealed api-scan-meta.json when post-commit
                                        # artifacts were tampered/missing, so forensic hashes remain intact!
                                        _mark_scan_meta_failed_best_effort(scan_dir, jid, err_code)
                                    _write_failure_marker(
                                        scan_dir,
                                        jid,
                                        err_code,
                                        err_msg,
                                        extra={
                                            "failure_classification": chk.status,
                                            "failure_reason": chk.reason,
                                            "revoked_scan_id": doc.get("revoked_scan_id"),
                                            "scan_sha256": doc.get("scan_sha256"),
                                            "missing_artifacts": list(chk.missing_artifacts),
                                            "mismatched_artifacts": list(chk.mismatched_artifacts),
                                        },
                                    )
                    if needs_persist:
                        try:
                            _atomic_write_text(jf, json.dumps(doc, indent=2, ensure_ascii=False))
                        except OSError:
                            pass
                    self._jobs[jid] = doc
                except (OSError, ValueError):
                    continue

    def _has_existing_scan_sha(self, scan_sha: str, *, exclude_dir: Path) -> bool:
        """Fast O(1)-per-scan check for duplicate scan_sha256 across scans/ and committed/revoked jobs/."""
        exclude_job_id = exclude_dir.name
        if self.jobs_dir.is_dir():
            for jf in self.jobs_dir.glob("*.json"):
                if jf.stem == exclude_job_id:
                    continue
                try:
                    jdoc = json.loads(jf.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                if not isinstance(jdoc, dict) or jdoc.get("job_id") == exclude_job_id:
                    continue
                if jdoc.get("scan_sha256") == scan_sha:
                    return True
                for ck in ("commit", "revoked_commit"):
                    cobj = jdoc.get(ck)
                    if isinstance(cobj, dict) and cobj.get("scan_sha256") == scan_sha:
                        return True
        if not self.scans_dir.is_dir():
            return False
        for p in self.scans_dir.iterdir():
            if not p.is_dir() or p == exclude_dir:
                continue
            meta_file = p / "api-scan-meta.json"
            if meta_file.is_file():
                try:
                    meta = json.loads(meta_file.read_text(encoding="utf-8"))
                    if isinstance(meta, dict) and meta.get("scan_sha256") == scan_sha:
                        return True
                    continue
                except (OSError, ValueError):
                    pass
            db_file = p / "triage" / "review.sqlite"
            if db_file.is_file():
                try:
                    uri = db_file.resolve(strict=True).as_uri() + "?mode=ro"
                    conn = sqlite3.connect(uri, uri=True, timeout=2.0, isolation_level=None)
                    try:
                        if conn.execute("SELECT 1 FROM scans WHERE id=? LIMIT 1", (scan_sha,)).fetchone() is not None:
                            return True
                    finally:
                        conn.close()
                except (OSError, sqlite3.Error):
                    continue
        return False

    def _persist_job_locked(self, job: dict[str, Any]) -> None:
        self._ensure_dirs()
        target = self.jobs_dir / f"{job['job_id']}.json"
        tmp = self.jobs_dir / f".{job['job_id']}.tmp"
        tmp.write_text(json.dumps(job, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(target)

    def _check_capacity_locked(self) -> None:
        active = sum(1 for j in self._jobs.values() if j.get("state") in ("QUEUED", "RUNNING"))
        max_total = self.config.max_concurrent_scans + self.config.max_queued_jobs
        if active >= max_total:
            raise ApiServiceError(
                "TOO_MANY_CONCURRENT_SCANS",
                f"Hệ thống đang xử lý tối đa {max_total} phiên quét đồng thời/xếp hàng. Vui lòng thử lại sau.",
                http_status=429,
            )

    def submit_zip_job(self, file_name: str, zip_bytes: bytes, *, no_llm: bool = False) -> dict[str, Any]:
        safe_name = Path(str(file_name or "project.zip")).name[:120]
        if not safe_name.lower().endswith(".zip"):
            raise IntakeError("INVALID_ZIP_FILENAME", "Chỉ chấp nhận tệp nén có phần mở rộng .zip.")

        job_id = f"job-{uuid.uuid4().hex[:16]}"
        self._ensure_dirs()
        source_dir = self.workspaces_dir / job_id / "source"

        t0 = time.monotonic()
        intake_started = now()
        # Validate and safely extract synchronously BEFORE queueing so malicious/empty ZIPs fail immediately!
        inventory = extract_safe_zip(zip_bytes, source_dir, self.config.limits)
        intake_ms = round((time.monotonic() - t0) * 1000.0, 3)
        intake_finished = now()

        stages = _initial_stages()
        stages[0].update(
            state="COMPLETED",
            started_at=intake_started,
            finished_at=intake_finished,
            duration_ms=intake_ms,
            summary_metadata={
                "input_mode": "ZIP",
                "file_name": safe_name,
                "archive_bytes": inventory["archive_bytes"],
                "java_files_count": inventory["java_files_count"],
                "non_java_files_count": inventory["non_java_files_count"],
                "total_bytes": inventory["total_bytes"],
            },
        )

        with acquire_publication_lock(self.config.data_dir), self._lock:
            try:
                self._check_capacity_locked()
            except Exception:
                import shutil
                shutil.rmtree(self.workspaces_dir / job_id, ignore_errors=True)
                raise

            job = {
                "job_id": job_id,
                "scan_id": None,
                "scan_sha256": None,
                "state": "QUEUED",
                "input_mode": "ZIP",
                "file_name": safe_name,
                "repo_url": None,
                "requested_commit": None,
                "resolved_commit": None,
                "no_llm": bool(no_llm),
                "active_stage": 2,
                "created_at": intake_started,
                "started_at": intake_started,
                "finished_at": None,
                "total_e2e_duration_ms": None,
                "progress": {"processed_findings": 0, "total_findings": None},
                "stages": stages,
                "stage_statuses": None,
                "error_code": None,
                "error_message": None,
            }
            self._jobs[job_id] = job
            self._persist_job_locked(job)

        self._executor.submit(self._run_job_worker, job_id, source_dir, inventory, t0)
        return self.get_job(job_id)

    def submit_github_job(self, repo_url: str, commit_sha: str | None = None, *, no_llm: bool = False) -> dict[str, Any]:
        canonical_url, owner, repo, validated_sha = validate_github_url(repo_url, commit_sha)
        job_id = f"job-{uuid.uuid4().hex[:16]}"
        self._ensure_dirs()
        created = now()

        with acquire_publication_lock(self.config.data_dir), self._lock:
            self._check_capacity_locked()
            job = {
                "job_id": job_id,
                "scan_id": None,
                "scan_sha256": None,
                "state": "QUEUED",
                "input_mode": "GITHUB",
                "file_name": None,
                "repo_url": canonical_url,
                "owner": owner,
                "repo": repo,
                "requested_commit": validated_sha,
                "resolved_commit": None,
                "no_llm": bool(no_llm),
                "active_stage": 1,
                "created_at": created,
                "started_at": None,
                "finished_at": None,
                "total_e2e_duration_ms": None,
                "progress": {"processed_findings": 0, "total_findings": None},
                "stages": _initial_stages(),
                "stage_statuses": None,
                "error_code": None,
                "error_message": None,
            }
            self._jobs[job_id] = job
            self._persist_job_locked(job)

        source_dir = self.workspaces_dir / job_id / "source"
        self._executor.submit(self._run_job_worker, job_id, source_dir, None, None)
        return self.get_job(job_id)

    def _update_job(self, job_id: str, mutator) -> None:
        with acquire_publication_lock(self.config.data_dir), self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            mutator(job)
            self._persist_job_locked(job)

    def _fail_job(
        self,
        job_id: str,
        stage_idx: int,
        error_code: str,
        message: str,
        started_mono: float,
        details: dict[str, Any] | None = None,
    ) -> None:
        finished_ts = now()
        total_ms = round((time.monotonic() - started_mono) * 1000.0, 3)

        def _mut(job: dict[str, Any]) -> None:
            job["state"] = "FAILED"
            job["scan_id"] = None
            job["finished_at"] = finished_ts
            job["total_e2e_duration_ms"] = total_ms
            job["error_code"] = error_code
            job["error_message"] = message
            job.pop("commit", None)
            if details:
                safe = _safe_error_details(details)
                if safe:
                    job["error_details"] = safe
            if 0 <= stage_idx < len(job["stages"]):
                st = job["stages"][stage_idx]
                st["state"] = "FAILED"
                st["finished_at"] = finished_ts
                st["error"] = f"[{error_code}] {message}"
            for idx_s, s_item in enumerate(job["stages"]):
                if idx_s == stage_idx:
                    continue
                if s_item["state"] == "RUNNING":
                    s_item["state"] = "FAILED" if error_code == "JOB_TIMEOUT" else "SKIPPED"
                    s_item["finished_at"] = finished_ts
                    if error_code == "JOB_TIMEOUT" and not s_item.get("error"):
                        s_item["error"] = f"[{error_code}] {message}"
                elif s_item["state"] == "PENDING":
                    s_item["state"] = "SKIPPED"

        with acquire_publication_lock(self.config.data_dir), self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            _mut(job)
            try:
                self._persist_job_locked(job)
            except OSError:
                # Even if disk persistence fails during failure recording, keep FAILED state in memory
                # and never let an exception escape failure cleanup.
                pass

    def _run_job_worker(
        self,
        job_id: str,
        source_dir: Path,
        pre_inventory: dict[str, Any] | None,
        intake_mono_start: float | None,
    ) -> None:
        e2e_mono = intake_mono_start if intake_mono_start is not None else time.monotonic()
        deadline_mono = e2e_mono + float(self.config.job_timeout_seconds)
        run_started_iso = now()

        def _mark_running(job: dict[str, Any]) -> None:
            job["state"] = "RUNNING"
            if not job["started_at"]:
                job["started_at"] = run_started_iso

        self._update_job(job_id, _mark_running)

        def _abort_job_timeout(
            stage_idx: int,
            scan_root: Path | None,
            *,
            scan_sha_val: str | None = None,
            engine_ver: str | None = None,
            verified_rules: str | None = None,
            stage_statuses_doc: dict[str, Any] | None = None,
            triage_tel: dict[str, Any] | None = None,
            completed_ts: str | None = None,
            data_origin: str | None = None,
            inv: dict[str, Any] | None = None,
            timeout_aborts_count: int = 0,
            details: dict[str, Any] | None = None,
        ) -> None:
            timeout_msg = (
                f"Vượt quá thời gian xử lý tối đa của phiên quét (job_timeout_seconds={self.config.job_timeout_seconds}s; "
                f"timeout_aborts={timeout_aborts_count}). Bằng chứng bán phần đã được giữ lại và không công bố."
            )
            e2e_now_ms = round((time.monotonic() - e2e_mono) * 1000.0, 3)
            with acquire_publication_lock(self.config.data_dir):
                if scan_root is not None and scan_root.is_dir():
                    try:
                        with self._lock:
                            cur_job = self._jobs[job_id]
                            fail_meta: dict[str, Any] = {
                                "scan_id": None,
                                "scan_sha256": scan_sha_val,
                                "job_id": job_id,
                                "job_state": "FAILED",
                                "publishable": False,
                                "error_code": "JOB_TIMEOUT",
                                "data_origin": data_origin or ("MOCK_TEST" if self.config.runtime_origin == "mock" else "REAL_SCAN"),
                                "input_mode": cur_job["input_mode"],
                                "file_name": cur_job.get("file_name"),
                                "repo_url": cur_job.get("repo_url"),
                                "resolved_commit": cur_job.get("resolved_commit"),
                                "started_at": cur_job["started_at"],
                                "completed_at": completed_ts or now(),
                                "total_e2e_duration_ms": e2e_now_ms,
                                "java_files_count": inv["java_files_count"] if isinstance(inv, dict) else None,
                                "java_sha256": inv["java_sha256"] if isinstance(inv, dict) else None,
                                "opengrep_version": engine_ver,
                                "rules_name": self.config.rules_path.name,
                                "rules_sha256": verified_rules,
                                "stage_statuses": stage_statuses_doc,
                                "triage_telemetry": triage_tel,
                            }
                        _atomic_write_text(
                            scan_root / "api-scan-meta.json",
                            json.dumps(fail_meta, indent=2, ensure_ascii=False),
                        )
                    except OSError:
                        pass
                    _write_failure_marker(scan_root, job_id, "JOB_TIMEOUT", timeout_msg)
                self._fail_job(job_id, stage_idx, "JOB_TIMEOUT", timeout_msg, e2e_mono, details=details)

        try:
            # Stage 1: GitHub intake if not already extracted from ZIP
            inventory = pre_inventory
            if inventory is None:
                rem_s1 = deadline_mono - time.monotonic()
                if rem_s1 <= 0.0:
                    _abort_job_timeout(0, None)
                    return
                s1_mono = time.monotonic()
                s1_start = now()
                self._update_job(
                    job_id,
                    lambda j: (
                        j.update(active_stage=1),
                        j["stages"][0].update(state="RUNNING", started_at=s1_start),
                    ),
                )
                with self._lock:
                    repo_url = self._jobs[job_id]["repo_url"]
                    req_commit = self._jobs[job_id]["requested_commit"]
                try:
                    inventory = clone_github_repo(
                        repo_url,
                        req_commit,
                        source_dir,
                        self.config.limits,
                        timeout_seconds=min(float(self.config.git_clone_timeout_seconds), max(0.1, rem_s1)),
                    )
                except IntakeError as exc:
                    if time.monotonic() >= deadline_mono and exc.error_code.endswith("_TIMEOUT"):
                        _abort_job_timeout(0, None, details=exc.details)
                        return
                    self._fail_job(job_id, 0, exc.error_code, str(exc), e2e_mono, details=exc.details)
                    return

                s1_ms = round((time.monotonic() - s1_mono) * 1000.0, 3)
                s1_end = now()
                self._update_job(
                    job_id,
                    lambda j: (
                        j.update(resolved_commit=inventory.get("resolved_commit"), active_stage=2),
                        j["stages"][0].update(
                            state="COMPLETED",
                            finished_at=s1_end,
                            duration_ms=s1_ms,
                            summary_metadata={
                                "input_mode": "GITHUB",
                                "repo_url": inventory.get("repo_url"),
                                "resolved_commit": inventory.get("resolved_commit"),
                                "java_files_count": inventory["java_files_count"],
                                "total_bytes": inventory["total_bytes"],
                            },
                        ),
                    ),
                )

            if time.monotonic() >= deadline_mono:
                _abort_job_timeout(1, None, inv=inventory)
                return

            # Stage 2: OpenGrep Static Scan
            s2_mono = time.monotonic()
            s2_start = now()
            self._update_job(
                job_id,
                lambda j: (
                    j.update(active_stage=2),
                    j["stages"][1].update(state="RUNNING", started_at=s2_start),
                ),
            )

            try:
                validate_opengrep_binary(self.config.opengrep_binary)
            except ValueError as exc:
                self._fail_job(job_id, 1, "OPENGREP_INVALID_BINARY", str(exc), e2e_mono)
                return

            OpenGrepConfig, SemgrepScanner, ScanError = _load_baseline_scanner()
            scan_out_root: Path | None = None
            scan_out_root = self.scans_dir / job_id
            capture_dir = scan_out_root / "capture"
            triage_dir = scan_out_root / "triage"
            scan_out_root.mkdir(parents=True, exist_ok=False)

            if time.monotonic() >= deadline_mono:
                _abort_job_timeout(1, scan_out_root, inv=inventory)
                return

            try:
                resolved_og = (
                    self.config.opengrep_binary
                    if Path(self.config.opengrep_binary).is_file()
                    else (shutil.which(self.config.opengrep_binary) or self.config.opengrep_binary)
                )
                og_cfg = OpenGrepConfig(
                    executable=resolved_og,
                    rules=self.config.rules_path,
                    timeout=self.config.opengrep_timeout_seconds,
                    jobs=self.config.opengrep_jobs,
                )
                # Bounded subclass: same capture/exit semantics, but timeouts terminate the whole
                # process tree and stay capped by overall job `deadline_mono` (see v2/api/opengrep_runner.py).
                scanner = make_bounded_scanner_class(SemgrepScanner, ScanError)(
                    og_cfg, capture_dir, deadline_mono=deadline_mono
                )
                scan_results = scanner.scan(source_dir, self.config.rules_path)
                scanner_timing = dict(getattr(scanner, "last_timing", None) or {})
            except ScanError as exc:
                err_txt = str(exc)
                code = getattr(exc, "error_code", None) or (
                    "OPENGREP_UNAVAILABLE"
                    if ("WinError 2" in err_txt or "No such file" in err_txt or "not found" in err_txt.lower())
                    else "OPENGREP_SCAN_FAILED"
                )
                if code == "JOB_TIMEOUT" or (time.monotonic() >= deadline_mono and code == "OPENGREP_TIMEOUT"):
                    _abort_job_timeout(1, scan_out_root, inv=inventory, details=getattr(exc, "details", None))
                    return
                _write_failure_marker(scan_out_root, job_id, code, err_txt)
                self._fail_job(
                    job_id, 1, code, f"OpenGrep không thể hoàn tất phân tích: {err_txt}", e2e_mono,
                    details=getattr(exc, "details", None),
                )
                return

            if time.monotonic() >= deadline_mono:
                _abort_job_timeout(1, scan_out_root, inv=inventory, engine_ver=scan_results.get("engine_version"))
                return

            raw_json_path = capture_dir / "opengrep.json"
            raw_sarif_path = capture_dir / "opengrep.sarif"
            manifest_path = capture_dir / "scan-manifest.json"
            raw_json_bytes = raw_json_path.read_bytes()
            scan_sha = digest(raw_json_bytes)
            j_doc = strict_json(raw_json_bytes.decode("utf-8"))
            s_doc = strict_json(raw_sarif_path.read_bytes().decode("utf-8"))
            try:
                parity = compare_findings(j_doc, s_doc)
            except ValueError as exc:
                self._fail_job(
                    job_id,
                    1,
                    "JSON_SARIF_PARITY_MISMATCH",
                    f"Kết quả JSON và SARIF của OpenGrep không khớp: {exc}",
                    e2e_mono,
                )
                return
            if not parity.get("rule_ids_and_locations_match"):
                self._fail_job(job_id, 1, "JSON_SARIF_PARITY_MISMATCH", "Kết quả JSON và SARIF của OpenGrep không khớp.", e2e_mono)
                return

            raw_count = len(j_doc.get("results") or [])
            engine_version = scan_results.get("engine_version")
            s2_ms = round((time.monotonic() - s2_mono) * 1000.0, 3)
            s2_end = now()
            self._update_job(
                job_id,
                lambda j: (
                    j.update(
                        scan_sha256=scan_sha,
                        active_stage=3,
                        progress={"processed_findings": 0, "total_findings": raw_count},
                    ),
                    j["stages"][1].update(
                        state="COMPLETED",
                        finished_at=s2_end,
                        duration_ms=s2_ms,
                        summary_metadata={
                            "opengrep_version": engine_version,
                            "raw_findings_count": raw_count,
                            "scan_sha256": scan_sha,
                            "json_sarif_parity": "MATCHED",
                            "opengrep_jobs": self.config.opengrep_jobs,
                            "single_pass_dual_output": bool(scanner_timing.get("single_pass_dual_output")),
                            "opengrep_timing": scanner_timing or None,
                        },
                    ),
                ),
            )
            cb = self._on_opengrep_scan_succeeded
            if cb is not None:
                try:
                    cb(engine_version=engine_version)
                except Exception:
                    pass

            if time.monotonic() >= deadline_mono:
                _abort_job_timeout(2, scan_out_root, scan_sha_val=scan_sha, engine_ver=engine_version, inv=inventory)
                return

            # Stages 3–6: Run bounded triage under no-rescan guard using sealed v2.triage primitives.
            with self._lock:
                no_llm = bool(self._jobs[job_id]["no_llm"])
            trusted_maps = derive_trusted_path_maps(source_dir)
            ckpt_file = scan_out_root / "triage-checkpoint.jsonl"

            def _summarize_triage_outcome(
                ass_list: list[dict[str, Any]],
                *,
                c_hits: int,
                l_calls: int,
            ) -> tuple[str, str, str, str]:
                if no_llm:
                    return "DISABLED", "NOT_APPLICABLE", "SKIPPED", "SKIPPED"
                if not ass_list:
                    return "NO_FINDINGS", "NOT_APPLICABLE", "COMPLETED", "COMPLETED"
                http_ok_cnt = sum(
                    1
                    for a in ass_list
                    if (
                        a.get("runtime", {}).get("http_response_received") is True
                        and a.get("runtime", {}).get("http_status") == 200
                        and a.get("runtime", {}).get("response_complete") is True
                        and a.get("runtime", {}).get("model_identity_matched") is True
                    )
                    or (
                        a.get("runtime", {}).get("origin") == "cached_verified"
                        and a.get("runtime", {}).get("cache_hit") is True
                    )
                )
                val_ok_cnt = sum(1 for a in ass_list if a.get("runtime", {}).get("answer_validated") is True)
                if c_hits > 0 and l_calls > 0:
                    q_st = "MIXED_CACHE_AND_LIVE_HTTP"
                elif c_hits > 0 and http_ok_cnt == len(ass_list):
                    q_st = "ALL_COMPLETED_WITH_VERIFIED_CACHE"
                else:
                    q_st = "ALL_HTTP_COMPLETED" if http_ok_cnt == len(ass_list) else "PARTIAL_OR_FAILED"
                v_st = "ALL_VALIDATED" if val_ok_cnt == len(ass_list) else "DOWNGRADED_TO_UNDETERMINED"
                st4 = "COMPLETED" if http_ok_cnt == len(ass_list) else "DEGRADED"
                st5 = "COMPLETED" if v_st == "ALL_VALIDATED" else "DEGRADED"
                return q_st, v_st, st4, st5

            s3_mono = time.monotonic()
            s3_start = now()
            self._update_job(
                job_id,
                lambda j: (
                    j.update(active_stage=3),
                    j["stages"][2].update(state="RUNNING", started_at=s3_start),
                ),
            )

            def _on_evidence_ready(total_rec: int, ctx_stats: dict[str, Any]) -> None:
                ts = now()
                el_ms = round((time.monotonic() - s3_mono) * 1000.0, 3)

                def _apply(j: dict[str, Any]) -> None:
                    j.update(
                        active_stage=6 if no_llm else 4,
                        progress={"processed_findings": 0, "total_findings": total_rec},
                    )
                    j["stages"][2].update(
                        state="COMPLETED",
                        finished_at=ts,
                        duration_ms=el_ms,
                        summary_metadata={
                            "records_processed": total_rec,
                            "context_version": ctx_stats.get("context_version"),
                            "spring_methods_recovered": ctx_stats.get("spring_methods_recovered"),
                            "helpers_attached": ctx_stats.get("helpers_attached"),
                            "compacted_snippets": ctx_stats.get("compacted_snippets"),
                            "before_prompt_bytes_avg": ctx_stats.get("before_prompt_bytes_avg"),
                            "after_prompt_bytes_avg": ctx_stats.get("after_prompt_bytes_avg"),
                        },
                    )
                    if no_llm:
                        j["stages"][3].update(state="SKIPPED", started_at=None, finished_at=None)
                        j["stages"][4].update(state="SKIPPED", started_at=None, finished_at=None)
                        j["stages"][5].update(state="RUNNING", started_at=ts)
                    else:
                        j["stages"][3].update(state="RUNNING", started_at=ts)

                self._update_job(job_id, _apply)

            last_progress = {"done": -1}

            def _on_finding_progress(done_count: int, total_rec: int) -> None:
                if no_llm or done_count == last_progress["done"]:
                    return
                last_progress["done"] = done_count
                self._update_job(
                    job_id,
                    lambda j, p=done_count, tot=total_rec: j.update(
                        progress={"processed_findings": p, "total_findings": tot}
                    ),
                )

            def _on_triage_finished(info: dict[str, Any]) -> None:
                ts = now()
                ass_list = info.get("assessments_list") or []
                c_hits = int(info.get("cache_hits") or 0)
                l_calls = int(info.get("live_calls") or 0)
                q_st, v_st, st4, st5 = _summarize_triage_outcome(ass_list, c_hits=c_hits, l_calls=l_calls)

                def _apply(j: dict[str, Any]) -> None:
                    j["active_stage"] = 6
                    if j["stages"][2]["state"] != "COMPLETED":
                        j["stages"][2].update(state="COMPLETED", finished_at=ts)
                    j["stages"][3].update(
                        state=st4,
                        started_at=j["stages"][3]["started_at"] or (None if no_llm else s3_start),
                        finished_at=None if no_llm else ts,
                        duration_ms=None if no_llm else info.get("qwen_total_ms"),
                        summary_metadata={
                            "qwen_inference_status": q_st,
                            "model": None if no_llm else self.config.ollama_model,
                            "live_calls": l_calls,
                            "cache_hits": c_hits,
                            "timeout_aborts": int(info.get("timeout_aborts") or 0),
                            "resource_blocks": int(info.get("resource_blocks") or 0),
                        },
                    )
                    j["stages"][4].update(
                        state=st5,
                        started_at=None if no_llm else (j["stages"][3]["started_at"] or s3_start),
                        finished_at=None if no_llm else ts,
                        summary_metadata={"validator_status": v_st},
                    )
                    j["stages"][5].update(state="RUNNING", started_at=j["stages"][5]["started_at"] or ts)

                self._update_job(job_id, _apply)

            deadline_mono = e2e_mono + float(self.config.job_timeout_seconds)
            try:
                with _forbid_implicit_scanner_rescan():
                    triage_res = run_bounded_triage(
                        source_root=source_dir,
                        triage_dir=triage_dir,
                        raw_json_path=raw_json_path,
                        manifest_path=manifest_path,
                        path_maps=list(trusted_maps),
                        rules_path=self.config.rules_path,
                        no_llm=no_llm,
                        prompt_contract=self.config.prompt_contract,
                        ollama_endpoint=self.config.ollama_endpoint,
                        ollama_model=self.config.ollama_model,
                        ollama_timeout_seconds=float(self.config.ollama_timeout_seconds),
                        runtime_origin=self.config.runtime_origin,
                        deadline_mono=deadline_mono,
                        checkpoint_path=ckpt_file,
                        max_prompt_bytes=self.config.max_prompt_bytes,
                        enable_qwen_cache=self.config.enable_qwen_cache,
                        qwen_cache_dir=self.config.data_dir / "qwen-cache",
                        on_evidence_ready=_on_evidence_ready,
                        on_finding_progress=_on_finding_progress,
                        on_triage_finished=_on_triage_finished,
                    )
            except StorageCommitError as exc:
                _write_failure_marker(scan_out_root, job_id, "STORAGE_COMMIT_FAILED", str(exc))
                self._fail_job(job_id, 5, "STORAGE_COMMIT_FAILED", str(exc), e2e_mono)
                return

            triage_exit = triage_res["triage_exit"]
            triage_telemetry = triage_res["telemetry"]
            cache_hits = int(triage_res["cache_hits"])
            live_calls = int(triage_res["live_calls"])
            timeout_aborts = int(triage_res["timeout_aborts"])
            deadline_exceeded = bool(triage_res.get("deadline_exceeded"))
            triage_finished = now()

            assessments_rows = triage_res["assessments_rows"]
            assessments_list = triage_res["assessments_list"]

            verified_rules_sha = triage_res.get("rules_sha256")
            if not verified_rules_sha and (capture_dir / "rules.snapshot.yml").is_file():
                verified_rules_sha = digest((capture_dir / "rules.snapshot.yml").read_bytes())

            qwen_status, validator_status, s4_state, s5_state = _summarize_triage_outcome(
                assessments_list,
                c_hits=cache_hits,
                l_calls=live_calls,
            )

            if self.config.runtime_origin == "mock":
                job_data_origin = "MOCK_TEST"
            elif cache_hits > 0 and live_calls > 0:
                job_data_origin = "MIXED_CACHE_AND_LIVE_HTTP"
            elif cache_hits > 0:
                job_data_origin = "CACHED_TRIAGE_NO_LIVE_HTTP"
            else:
                job_data_origin = "REAL_SCAN"

            def _partial_stage_statuses(http_cap_chk: dict[str, Any] | None) -> dict[str, Any]:
                return {
                    "scanner_status": "OK",
                    "source_integrity_status": "VERIFIED" if triage_exit == 0 else "DEGRADED",
                    "json_sarif_parity_status": "MATCHED",
                    "qwen_inference_status": qwen_status,
                    "validator_status": validator_status,
                    "http_capture_status": (
                        "DISABLED"
                        if no_llm
                        else (http_cap_chk["capture_status"] if http_cap_chk else "NO_FINDINGS")
                    ),
                    "queue_status": "OPEN_READY",
                }

            timeout_stage_idx = 3 if (not no_llm and timeout_aborts > 0) else 5

            # Fail closed immediately whenever overall job deadline expired or findings were aborted by JOB_TIMEOUT.
            if timeout_aborts > 0 or deadline_exceeded or time.monotonic() >= deadline_mono:
                _abort_job_timeout(
                    timeout_stage_idx,
                    scan_out_root,
                    scan_sha_val=scan_sha,
                    engine_ver=engine_version,
                    verified_rules=verified_rules_sha,
                    stage_statuses_doc=_partial_stage_statuses(None),
                    triage_tel=triage_telemetry,
                    completed_ts=triage_finished,
                    data_origin=job_data_origin,
                    inv=inventory,
                    timeout_aborts_count=timeout_aborts,
                )
                return

            protocol_check = None
            http_capture_check = None
            try:
                if not no_llm:
                    protocol_check = live_check.inspect(
                        assessments_rows,
                        minimum=max(1, len(assessments_rows)),
                    )
                    (triage_dir / "live-protocol-check.json").write_text(
                        json.dumps(protocol_check, indent=2), encoding="utf-8"
                    )
                    if time.monotonic() >= deadline_mono:
                        _abort_job_timeout(
                            5,
                            scan_out_root,
                            scan_sha_val=scan_sha,
                            engine_ver=engine_version,
                            verified_rules=verified_rules_sha,
                            stage_statuses_doc=_partial_stage_statuses(None),
                            triage_tel=triage_telemetry,
                            completed_ts=triage_finished,
                            data_origin=job_data_origin,
                            inv=inventory,
                            timeout_aborts_count=timeout_aborts,
                        )
                        return
                    if cache_hits > 0 and live_calls > 0:
                        http_capture_check = _verify_mixed_http_captures(triage_dir, assessments_rows)
                    elif cache_hits > 0:
                        http_capture_check = {
                            "schema": "ntk-http-capture-verification-1",
                            "capture_scope": "cache_reused_opt_in_no_live_http",
                            "capture_status": "CACHE_REUSED_NO_LIVE_HTTP",
                            "capture_integrity_ok": False,
                            "live_chat_verified": False,
                            "total_findings": len(assessments_rows),
                            "cache_hits": cache_hits,
                            "live_calls": live_calls,
                            "note": (
                                "Phiên quét bật tùy chọn bộ nhớ đệm có ràng buộc provenance (enable_qwen_cache=True); "
                                "các bản ghi trúng cache không phát sinh raw HTTP live và không được coi là live_chat_verified."
                            ),
                        }
                    else:
                        http_capture_check = verify_http_capture.verify_run_http_captures(
                            triage_dir, require_live_chat=False
                        )
                    (triage_dir / "http-capture-check.json").write_text(
                        json.dumps(http_capture_check, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8",
                    )
            except (OSError, EvidenceError, ValueError, RuntimeError) as exc:
                _write_failure_marker(scan_out_root, job_id, "STORAGE_COMMIT_FAILED", str(exc))
                self._fail_job(job_id, 5, "STORAGE_COMMIT_FAILED", f"Không thể ghi chứng từ kiểm định lưu trữ: {exc}", e2e_mono)
                return

            stage_statuses = _partial_stage_statuses(http_capture_check)
            e2e_ms = round((time.monotonic() - e2e_mono) * 1000.0, 3)

            if time.monotonic() >= deadline_mono:
                _abort_job_timeout(
                    5,
                    scan_out_root,
                    scan_sha_val=scan_sha,
                    engine_ver=engine_version,
                    verified_rules=verified_rules_sha,
                    stage_statuses_doc=stage_statuses,
                    triage_tel=triage_telemetry,
                    completed_ts=triage_finished,
                    data_origin=job_data_origin,
                    inv=inventory,
                    timeout_aborts_count=timeout_aborts,
                )
                return

            # Decide unique scan_id using O(1)-per-scan metadata/SQLite lookup instead of reading full evidence.json.
            existing_same_sha = self._has_existing_scan_sha(scan_sha, exclude_dir=scan_out_root)
            final_scan_id = f"{scan_sha[:16]}-{job_id[-8:]}" if existing_same_sha else scan_sha

            def _complete(job: dict[str, Any]) -> None:
                job["state"] = "COMPLETED"
                job["scan_id"] = final_scan_id
                job["scan_sha256"] = scan_sha
                job["active_stage"] = 6
                job["finished_at"] = triage_finished
                job["total_e2e_duration_ms"] = e2e_ms
                job["progress"] = {"processed_findings": len(assessments_list), "total_findings": raw_count}
                job["stage_statuses"] = stage_statuses
                if job["stages"][2]["state"] != "COMPLETED":
                    job["stages"][2].update(
                        state="COMPLETED",
                        finished_at=triage_finished,
                        duration_ms=triage_telemetry["evidence_ms"],
                    )
                job["stages"][3].update(
                    state=s4_state,
                    started_at=job["stages"][3]["started_at"] or (None if no_llm else s3_start),
                    finished_at=None if no_llm else triage_finished,
                    duration_ms=None if no_llm else triage_telemetry["qwen_total_ms"],
                    summary_metadata={
                        "qwen_inference_status": qwen_status,
                        "model": None if no_llm else self.config.ollama_model,
                        "live_calls": triage_telemetry["live_calls"],
                        "cache_hits": triage_telemetry["cache_hits"],
                        "timeout_aborts": triage_telemetry["timeout_aborts"],
                        "resource_blocks": triage_telemetry["resource_blocks"],
                    },
                )
                job["stages"][4].update(
                    state=s5_state,
                    started_at=None if no_llm else (job["stages"][3]["started_at"] or s3_start),
                    finished_at=None if no_llm else triage_finished,
                    summary_metadata={"validator_status": validator_status},
                )
                job["stages"][5].update(
                    state="COMPLETED",
                    started_at=job["stages"][5]["started_at"] or s3_start,
                    finished_at=triage_finished,
                    duration_ms=triage_telemetry["store_commit_ms"],
                    summary_metadata={"queue_status": "OPEN_READY", "warnings_committed": len(assessments_list)},
                )

            def _check_deadline() -> None:
                if time.monotonic() >= deadline_mono:
                    raise _JobDeadlineTimeoutError("job deadline expired during finalization")

            def _build_staged_meta_doc(
                cur_job_snap: dict[str, Any],
                *,
                hashes: dict[str, str],
            ) -> dict[str, Any]:
                # Staged immutable metadata written BEFORE the single authoritative commit point.
                # Deliberately carries `commit_authority="job_record"` and NEVER claims publishable=True
                # or job_state=COMPLETED independently; scan discovery requires the owning job's commit record.
                return {
                    "schema": MANAGED_META_SCHEMA,
                    "commit_authority": "job_record",
                    "scan_id": final_scan_id,
                    "scan_sha256": scan_sha,
                    "job_id": job_id,
                    "no_llm": bool(no_llm),
                    "data_origin": job_data_origin,
                    "input_mode": cur_job_snap["input_mode"],
                    "file_name": cur_job_snap.get("file_name"),
                    "repo_url": cur_job_snap.get("repo_url"),
                    "resolved_commit": cur_job_snap.get("resolved_commit"),
                    "started_at": cur_job_snap["started_at"],
                    "completed_at": triage_finished,
                    "total_e2e_duration_ms": e2e_ms,
                    "java_files_count": inventory["java_files_count"],
                    "java_sha256": inventory["java_sha256"],
                    "opengrep_version": engine_version,
                    "rules_name": self.config.rules_path.name,
                    "rules_sha256": verified_rules_sha,
                    "artifact_sha256s": hashes,
                    "stage_statuses": stage_statuses,
                    "triage_telemetry": triage_telemetry,
                }

            try:
                _check_deadline()
                # Verify all mode-required artifacts exist AND compute sealed SHA-256 digests using the
                # SINGLE authoritative contract shared with TriageApiService discovery & restart recovery.
                artifact_sha256s, missing_artifacts = collect_managed_artifact_sha256s(
                    scan_out_root,
                    no_llm=no_llm,
                )
                if missing_artifacts:
                    raise StorageCommitError(f"Thiếu artifact bắt buộc trước khi commit: {missing_artifacts}")
                _check_deadline()
                with self._lock:
                    cur_job_snap = copy.deepcopy(self._jobs[job_id])

                # Step 1 (Pre-commit staging): write immutable metadata sealed by SHA-256.
                # While jobs/<job_id>.json is still RUNNING, TriageApiService will NEVER publish this scan.
                staged_meta = _build_staged_meta_doc(cur_job_snap, hashes=artifact_sha256s)
                meta_path = scan_out_root / "api-scan-meta.json"
                _atomic_write_text(
                    meta_path,
                    json.dumps(staged_meta, indent=2, ensure_ascii=False),
                    before_replace=_check_deadline,
                )
                meta_sha256 = digest(meta_path.read_bytes())
                _check_deadline()

                # Step 2 (Single Authoritative Commit Point):
                # Prepare complete job record binding `meta_sha256` + `artifact_sha256s` + `no_llm`, then atomically
                # replace `jobs/<job_id>.json` inside `acquire_publication_lock` + `self._lock` with the final deadline
                # check right before `replace()`. Once `replace()` succeeds, commit is irreversible — NO post-commit
                # deadline check or failure transition may ever occur.
                completed_job_doc = copy.deepcopy(cur_job_snap)
                _complete(completed_job_doc)
                completed_job_doc["commit"] = {
                    "schema": MANAGED_COMMIT_SCHEMA,
                    "job_id": job_id,
                    "scan_id": final_scan_id,
                    "scan_sha256": scan_sha,
                    "scan_dir": job_id,
                    "no_llm": bool(no_llm),
                    "meta_sha256": meta_sha256,
                    "artifact_sha256s": artifact_sha256s,
                    "committed_at": triage_finished,
                }
                completed_job_text = json.dumps(completed_job_doc, indent=2, ensure_ascii=False)
                self._ensure_dirs()
                job_file = self.jobs_dir / f"{job_id}.json"
                with acquire_publication_lock(self.config.data_dir), self._lock:
                    _check_deadline()
                    _atomic_write_text(
                        job_file,
                        completed_job_text,
                        before_replace=_check_deadline,
                    )
                    # Commit succeeded on disk — immediately publish matching COMPLETED state in memory.
                    self._jobs[job_id] = completed_job_doc

            except _JobDeadlineTimeoutError:
                _abort_job_timeout(
                    5,
                    scan_out_root,
                    scan_sha_val=scan_sha,
                    engine_ver=engine_version,
                    verified_rules=verified_rules_sha,
                    stage_statuses_doc=stage_statuses,
                    triage_tel=triage_telemetry,
                    completed_ts=triage_finished,
                    data_origin=job_data_origin,
                    inv=inventory,
                    timeout_aborts_count=timeout_aborts,
                )
                return
            except (OSError, sqlite3.Error, EvidenceError, ValueError, RuntimeError) as exc:
                with acquire_publication_lock(self.config.data_dir):
                    _mark_scan_meta_failed_best_effort(scan_out_root, job_id, "STORAGE_COMMIT_FAILED")
                    _write_failure_marker(scan_out_root, job_id, "STORAGE_COMMIT_FAILED", str(exc))
                    self._fail_job(job_id, 5, "STORAGE_COMMIT_FAILED", f"Không thể hoàn tất ghi metadata phiên quét: {exc}", e2e_mono)
                return

        except (StorageCommitError, sqlite3.Error, EvidenceError, OSError, ValueError, RuntimeError) as exc:
            err_code = getattr(exc, "error_code", None) or (
                "STORAGE_COMMIT_FAILED" if isinstance(exc, sqlite3.Error) else "PIPELINE_EXECUTION_ERROR"
            )
            if locals().get("scan_out_root") is not None:
                _write_failure_marker(scan_out_root, job_id, err_code, str(exc))
            with self._lock:
                active_idx = max(0, int(self._jobs.get(job_id, {}).get("active_stage") or 1) - 1)
            self._fail_job(job_id, active_idx, err_code, str(exc), e2e_mono)

    def _reconcile_job_view(self, job: dict[str, Any]) -> dict[str, Any]:
        """Return a read-only job snapshot verified against the SAME commit & artifact contract as TriageApiService.

        Never mutates original on-disk job/meta/evidence files while serving GET /api/scan-jobs or /api/scan-jobs/{id}.
        """
        view = copy.deepcopy(job)
        if view.get("state") != "COMPLETED":
            return view
        jid = view.get("job_id")
        if not isinstance(jid, str) or not jid:
            return view
        scan_dir = self.scans_dir / jid
        if not (scan_dir.is_dir() or ("commit" in view)):
            return view
        chk = inspect_managed_job_dir_committed(
            scan_dir=scan_dir,
            owner_job_id=jid,
            owner_job_doc=view,
            jobs_dir=self.jobs_dir,
        )
        if chk.ok:
            return view
        orig_sid = view.get("scan_id")
        if chk.status == "ARTIFACT_INTEGRITY_FAILED":
            err_code = "COMMITTED_ARTIFACT_TAMPERED_OR_MISSING"
            err_msg = (
                f"Phát hiện artifact đã niêm phong bị thiếu hoặc thay đổi sau commit ({chk.reason}); "
                "không tiếp tục công bố job COMPLETED và giữ nguyên dữ liệu gốc để kiểm toán."
            )
            revoked = view.pop("commit", None)
            if isinstance(revoked, dict):
                view["revoked_commit"] = revoked
            revoked_sid = (
                revoked.get("scan_id")
                if isinstance(revoked, dict) and isinstance(revoked.get("scan_id"), str)
                else orig_sid
            )
            if isinstance(revoked_sid, str) and revoked_sid.strip():
                view["revoked_scan_id"] = revoked_sid.strip()
            view["integrity_failure"] = {
                "status": chk.status,
                "reason": chk.reason,
                "missing_artifacts": list(chk.missing_artifacts),
                "mismatched_artifacts": list(chk.mismatched_artifacts),
            }
        else:
            err_code = "INCOMPLETE_COMMIT_ON_RESTART"
            err_msg = (
                f"Bản ghi job COMPLETED không khớp điểm commit hợp lệ ({chk.reason}); không công bố scan."
            )
            view.pop("commit", None)
        view["state"] = "FAILED"
        view["scan_id"] = None
        view["error_code"] = err_code
        view["error_message"] = err_msg
        _finalize_failed_stages(
            view,
            finished_ts=str(view.get("finished_at") or now()),
            error_code=err_code,
            message=err_msg,
        )
        return view

    def get_job(self, job_id: str) -> dict[str, Any]:
        with acquire_publication_lock(self.config.data_dir):
            with self._lock:
                job = self._jobs.get(job_id)
                if job is None:
                    raise ApiServiceError("JOB_NOT_FOUND", f"Không tìm thấy tác vụ quét {job_id!r}.", http_status=404)
                snap = copy.deepcopy(job)
            return self._reconcile_job_view(snap)

    def list_jobs(self) -> dict[str, Any]:
        with acquire_publication_lock(self.config.data_dir):
            with self._lock:
                snaps = [copy.deepcopy(j) for j in self._jobs.values()]
            items = [self._reconcile_job_view(j) for j in snaps]
        items.sort(key=lambda j: str(j.get("created_at") or ""), reverse=True)
        return {"total_count": len(items), "jobs": items}

    def has_active_opengrep_stage(self) -> bool:
        """Return True iff any scan job is currently executing Stage 2 (OPENGREP_SCAN)."""
        with self._lock:
            for job in self._jobs.values():
                if job.get("state") != "RUNNING":
                    continue
                stages = job.get("stages")
                if isinstance(stages, list) and len(stages) >= 2 and stages[1].get("state") == "RUNNING":
                    return True
            return False

    def shutdown(self, *, wait: bool = False) -> None:
        self._executor.shutdown(wait=wait, cancel_futures=True)
