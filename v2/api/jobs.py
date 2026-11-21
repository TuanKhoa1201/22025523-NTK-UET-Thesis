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

from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import re
import shutil
import sys
import threading
import time
from types import SimpleNamespace
from typing import Any
import uuid

from v2.api.config import ApiConfig, REPO_ROOT
from v2.api.intake import IntakeError, clone_github_repo, extract_safe_zip, validate_github_url
from v2.api.opengrep_runner import make_bounded_scanner_class
from v2.api.service import ApiServiceError
from v2.g1_integration.bridge import _forbid_implicit_scanner_rescan, derive_trusted_path_maps
from v2.g1_integration.finding_identity import compare_findings
from v2.g1_integration.fork_support.scanner_config import validate_opengrep_binary
from v2.triage import cli as triage_cli
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
        self._executor = ThreadPoolExecutor(
            max_workers=config.max_concurrent_scans,
            thread_name_prefix="ntk-scan-worker",
        )
        self._load_persisted_jobs()

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
        for jf in sorted(self.jobs_dir.glob("*.json")):
            try:
                doc = json.loads(jf.read_text(encoding="utf-8"))
                if isinstance(doc, dict) and isinstance(doc.get("job_id"), str):
                    if doc.get("state") in ("QUEUED", "RUNNING"):
                        doc["state"] = "FAILED"
                        doc["error_code"] = "SERVER_RESTARTED_DURING_JOB"
                        doc["error_message"] = "Tiến trình API khởi động lại khi job chưa hoàn tất; vui lòng chạy lại."
                        doc["finished_at"] = now()
                    self._jobs[doc["job_id"]] = doc
            except (OSError, ValueError):
                continue

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

        with self._lock:
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

        with self._lock:
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
        with self._lock:
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
            job["finished_at"] = finished_ts
            job["total_e2e_duration_ms"] = total_ms
            job["error_code"] = error_code
            job["error_message"] = message
            if details:
                safe = _safe_error_details(details)
                if safe:
                    job["error_details"] = safe
            if 0 <= stage_idx < len(job["stages"]):
                st = job["stages"][stage_idx]
                st["state"] = "FAILED"
                st["finished_at"] = finished_ts
                st["error"] = f"[{error_code}] {message}"
            for later in job["stages"][stage_idx + 1 :]:
                if later["state"] == "PENDING":
                    later["state"] = "SKIPPED"

        self._update_job(job_id, _mut)

    def _run_job_worker(
        self,
        job_id: str,
        source_dir: Path,
        pre_inventory: dict[str, Any] | None,
        intake_mono_start: float | None,
    ) -> None:
        e2e_mono = intake_mono_start if intake_mono_start is not None else time.monotonic()
        run_started_iso = now()

        def _mark_running(job: dict[str, Any]) -> None:
            job["state"] = "RUNNING"
            if not job["started_at"]:
                job["started_at"] = run_started_iso

        self._update_job(job_id, _mark_running)

        try:
            # Stage 1: GitHub intake if not already extracted from ZIP
            inventory = pre_inventory
            if inventory is None:
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
                        timeout_seconds=self.config.git_clone_timeout_seconds,
                    )
                except IntakeError as exc:
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

            if (time.monotonic() - e2e_mono) > self.config.job_timeout_seconds:
                self._fail_job(job_id, 1, "JOB_TIMEOUT", "Quá thời gian xử lý tối đa của phiên quét.", e2e_mono)
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
            scan_out_root = self.scans_dir / job_id
            capture_dir = scan_out_root / "capture"
            triage_dir = scan_out_root / "triage"
            scan_out_root.mkdir(parents=True, exist_ok=False)

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
                    jobs=1,
                )
                # Bounded subclass: same capture/exit semantics, but timeouts terminate the whole
                # process tree instead of blocking on inherited pipes (see v2/api/opengrep_runner.py).
                scanner = make_bounded_scanner_class(SemgrepScanner, ScanError)(og_cfg, capture_dir)
                scan_results = scanner.scan(source_dir, self.config.rules_path)
            except ScanError as exc:
                err_txt = str(exc)
                code = getattr(exc, "error_code", None) or (
                    "OPENGREP_UNAVAILABLE"
                    if ("WinError 2" in err_txt or "No such file" in err_txt or "not found" in err_txt.lower())
                    else "OPENGREP_SCAN_FAILED"
                )
                self._fail_job(
                    job_id, 1, code, f"OpenGrep không thể hoàn tất phân tích: {err_txt}", e2e_mono,
                    details=getattr(exc, "details", None),
                )
                return

            raw_json_path = capture_dir / "opengrep.json"
            raw_sarif_path = capture_dir / "opengrep.sarif"
            manifest_path = capture_dir / "scan-manifest.json"
            raw_json_bytes = raw_json_path.read_bytes()
            scan_sha = digest(raw_json_bytes)
            j_doc = strict_json(raw_json_bytes.decode("utf-8"))
            s_doc = strict_json(raw_sarif_path.read_bytes().decode("utf-8"))
            parity = compare_findings(j_doc, s_doc)
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
                        },
                    ),
                ),
            )

            # Stages 3–6: Delegate strictly to v2.triage.cli.run under no-rescan guard, watching checkpoint.jsonl
            with self._lock:
                no_llm = bool(self._jobs[job_id]["no_llm"])
            trusted_maps = derive_trusted_path_maps(source_dir)
            ckpt_file = scan_out_root / "triage-checkpoint.jsonl"

            s3_mono = time.monotonic()
            s3_start = now()
            self._update_job(
                job_id,
                lambda j: (
                    j.update(active_stage=3),
                    j["stages"][2].update(state="RUNNING", started_at=s3_start),
                ),
            )

            stop_watch = threading.Event()

            def _watch_triage_progress() -> None:
                moved_to_qwen = False
                while not stop_watch.wait(0.25):
                    evidence_ready = (triage_dir / "evidence.json").is_file()
                    processed = 0
                    if ckpt_file.is_file():
                        try:
                            processed = sum(1 for ln in ckpt_file.read_text(encoding="utf-8").splitlines() if ln.strip())
                        except OSError:
                            processed = 0
                    if evidence_ready and not moved_to_qwen:
                        moved_to_qwen = True
                        ts = now()
                        el_ms = round((time.monotonic() - s3_mono) * 1000.0, 3)
                        self._update_job(
                            job_id,
                            lambda j, ts=ts, el_ms=el_ms: (
                                j.update(active_stage=6 if no_llm else 4),
                                j["stages"][2].update(state="COMPLETED", finished_at=ts, duration_ms=el_ms),
                                j["stages"][3].update(
                                    state="SKIPPED" if no_llm else "RUNNING",
                                    started_at=None if no_llm else ts,
                                ),
                            ),
                        )
                    if moved_to_qwen and not no_llm:
                        self._update_job(
                            job_id,
                            lambda j, p=processed: j.update(
                                progress={"processed_findings": p, "total_findings": raw_count}
                            ),
                        )

            watcher = threading.Thread(target=_watch_triage_progress, daemon=True)
            watcher.start()
            triage_stdout = io.StringIO()
            try:
                remaining_sec = max(5.0, self.config.job_timeout_seconds - (time.monotonic() - e2e_mono))
                per_finding_timeout = min(self.config.ollama_timeout_seconds, remaining_sec)
                triage_args = SimpleNamespace(
                    source_root=str(source_dir),
                    output_dir=str(triage_dir),
                    json=str(raw_json_path),
                    scan_manifest=manifest_path,
                    path_base=None,
                    path_map=list(trusted_maps),
                    engine_exit=None,
                    rules=str(self.config.rules_path),
                    executable=self.config.opengrep_binary,
                    no_llm=no_llm,
                    mode="evidence+llm",
                    prompt_contract=self.config.prompt_contract,
                    checkpoint=str(ckpt_file),
                    endpoint=self.config.ollama_endpoint,
                    model=self.config.ollama_model,
                    timeout=float(per_finding_timeout),
                    runtime_origin=self.config.runtime_origin,
                )
                with _forbid_implicit_scanner_rescan(), redirect_stdout(triage_stdout):
                    triage_exit = triage_cli.run(triage_args)
            finally:
                stop_watch.set()
                watcher.join(timeout=2.0)

            triage_finished = now()
            triage_total_ms = round((time.monotonic() - s3_mono) * 1000.0, 3)

            assessments_rows = [
                strict_json(line)
                for line in (triage_dir / "assessments.jsonl").read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            assessments_list = [r["assessment"] for r in assessments_rows]

            protocol_check = None
            http_capture_check = None
            if not no_llm:
                protocol_check = live_check.inspect(assessments_rows, minimum=max(1, len(assessments_rows)))
                (triage_dir / "live-protocol-check.json").write_text(
                    json.dumps(protocol_check, indent=2), encoding="utf-8"
                )
                http_capture_check = verify_http_capture.verify_run_http_captures(
                    triage_dir, require_live_chat=False
                )
                (triage_dir / "http-capture-check.json").write_text(
                    json.dumps(http_capture_check, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8",
                )

            if no_llm:
                qwen_status = "DISABLED"
                validator_status = "NOT_APPLICABLE"
                s4_state, s5_state = "SKIPPED", "SKIPPED"
            elif not assessments_list:
                qwen_status = "NO_FINDINGS"
                validator_status = "NOT_APPLICABLE"
                s4_state, s5_state = "COMPLETED", "COMPLETED"
            else:
                http_ok = sum(
                    1
                    for a in assessments_list
                    if a.get("runtime", {}).get("http_response_received") is True
                    and a.get("runtime", {}).get("http_status") == 200
                    and a.get("runtime", {}).get("response_complete") is True
                    and a.get("runtime", {}).get("model_identity_matched") is True
                )
                val_ok = sum(1 for a in assessments_list if a.get("runtime", {}).get("answer_validated") is True)
                qwen_status = "ALL_HTTP_COMPLETED" if http_ok == len(assessments_list) else "PARTIAL_OR_FAILED"
                validator_status = "ALL_VALIDATED" if val_ok == len(assessments_list) else "DOWNGRADED_TO_UNDETERMINED"
                s4_state = "COMPLETED" if qwen_status == "ALL_HTTP_COMPLETED" else "DEGRADED"
                s5_state = "COMPLETED" if validator_status == "ALL_VALIDATED" else "DEGRADED"

            stage_statuses = {
                "scanner_status": "OK",
                "source_integrity_status": "VERIFIED" if triage_exit == 0 else "DEGRADED",
                "json_sarif_parity_status": "MATCHED",
                "qwen_inference_status": qwen_status,
                "validator_status": validator_status,
                "http_capture_status": (
                    "DISABLED"
                    if no_llm
                    else (http_capture_check["capture_status"] if http_capture_check else "NO_FINDINGS")
                ),
                "queue_status": "OPEN_READY",
            }

            # Decide unique scan_id (prefer canonical scan_sha256 if unique, else disambiguated)
            existing_same_sha = any(
                p != scan_out_root
                and (p / "triage" / "evidence.json").is_file()
                and scan_sha in (p / "triage" / "evidence.json").read_text(encoding="utf-8")
                for p in self.scans_dir.iterdir()
                if p.is_dir()
            )
            final_scan_id = f"{scan_sha[:16]}-{job_id[-8:]}" if existing_same_sha else scan_sha

            e2e_ms = round((time.monotonic() - e2e_mono) * 1000.0, 3)
            with self._lock:
                cur_job = self._jobs[job_id]
                meta_doc = {
                    "scan_id": final_scan_id,
                    "scan_sha256": scan_sha,
                    "job_id": job_id,
                    "data_origin": "MOCK_TEST" if self.config.runtime_origin == "mock" else "REAL_SCAN",
                    "input_mode": cur_job["input_mode"],
                    "file_name": cur_job.get("file_name"),
                    "repo_url": cur_job.get("repo_url"),
                    "resolved_commit": cur_job.get("resolved_commit"),
                    "started_at": cur_job["started_at"],
                    "completed_at": triage_finished,
                    "total_e2e_duration_ms": e2e_ms,
                    "java_files_count": inventory["java_files_count"],
                    "java_sha256": inventory["java_sha256"],
                    "opengrep_version": engine_version,
                    "rules_sha256": digest(self.config.rules_path.read_bytes()),
                    "stage_statuses": stage_statuses,
                }
            (scan_out_root / "api-scan-meta.json").write_text(
                json.dumps(meta_doc, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

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
                    job["stages"][2].update(state="COMPLETED", finished_at=triage_finished, duration_ms=triage_total_ms)
                job["stages"][3].update(
                    state=s4_state,
                    started_at=job["stages"][3]["started_at"] or (None if no_llm else s3_start),
                    finished_at=None if no_llm else triage_finished,
                    duration_ms=None if no_llm else triage_total_ms,
                    summary_metadata={"qwen_inference_status": qwen_status, "model": None if no_llm else self.config.ollama_model},
                )
                job["stages"][4].update(
                    state=s5_state,
                    started_at=None if no_llm else s3_start,
                    finished_at=None if no_llm else triage_finished,
                    summary_metadata={"validator_status": validator_status},
                )
                job["stages"][5].update(
                    state="COMPLETED",
                    started_at=s3_start,
                    finished_at=triage_finished,
                    summary_metadata={"queue_status": "OPEN_READY", "warnings_committed": len(assessments_list)},
                )

            self._update_job(job_id, _complete)

        except (EvidenceError, OSError, ValueError, RuntimeError) as exc:
            with self._lock:
                active_idx = max(0, int(self._jobs.get(job_id, {}).get("active_stage") or 1) - 1)
            self._fail_job(job_id, active_idx, "PIPELINE_EXECUTION_ERROR", str(exc), e2e_mono)

    def get_job(self, job_id: str) -> dict[str, Any]:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise ApiServiceError("JOB_NOT_FOUND", f"Không tìm thấy tác vụ quét {job_id!r}.", http_status=404)
            return json.loads(json.dumps(job))

    def list_jobs(self) -> dict[str, Any]:
        with self._lock:
            items = [json.loads(json.dumps(j)) for j in self._jobs.values()]
        items.sort(key=lambda j: str(j.get("created_at") or ""), reverse=True)
        return {"total_count": len(items), "jobs": items}

    def shutdown(self, *, wait: bool = False) -> None:
        self._executor.shutdown(wait=wait, cancel_futures=True)
