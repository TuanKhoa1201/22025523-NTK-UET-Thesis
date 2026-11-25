"""Bounded local triage pipeline for v2.api (Stages 3-6) using sealed v2.triage primitives.

Preserves 100% compatibility with:
- sealed `v2.triage.scan_receipt.verify_receipt`
- sealed `v2.triage.evidence.collect`
- sealed `v2.triage.ollama.OllamaClient` (exact same-call raw HTTP bytes & SHA-256 receipts)
- sealed `v2.triage.verify_http_capture.verify_run_http_captures`
- sealed `v2.triage.store.ReviewStore`

Adds inside v2/api:
- Balanced-paren Java context enrichment, distant same-file helper snippets, duplicate snippet compaction
  and strict 32 KB prompt budget enforcement (`java_context_v2`).
- Strict `apply_integration_gate` enforcement (`triage_gate`) on both live and cached verdicts.
- Hard `deadline_mono` gate before `/api/tags`, `/api/ps`, and `/api/chat` (remaining findings fail-closed).
- Snapshot-verified `rules.snapshot.yml` SHA-256 & repo-inventory-bound opt-in cache (`enable_qwen_cache=False`).
- Atomic fail-closed Stage 6 SQLite / `assessments.jsonl` commits (`StorageCommitError`).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import time
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
import uuid

from v2.api.java_context_v2 import (
    DEFAULT_MAX_PROMPT_BYTES,
    effective_prompt_byte_length,
    enrich_bundle_context,
)
from v2.api.qwen_cache import ProvenanceQwenCache, compute_source_inventory_sha256
from v2.api.triage_gate import apply_integration_gate
from v2.triage.evidence import EvidenceError, collect, digest, strict_json
from v2.triage.ollama import (
    DEFAULT_PROMPT_CONTRACT,
    PROMPT_CONTRACTS,
    OllamaClient,
    undecided,
)
from v2.triage.runtime import SCHEMA_VERSION, execution, summary as runtime_summary
from v2.triage.scan_receipt import verify_receipt
from v2.triage.store import ReviewStore

FOREIGN_MODEL_VRAM_BLOCK_BYTES = 12 * 1024 * 1024 * 1024  # 12 GiB on 16 GiB GPU


class StorageCommitError(EvidenceError):
    error_code = "STORAGE_COMMIT_FAILED"


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise EvidenceError("Ollama redirects are forbidden")


def _extract_verified_rules_sha256(manifest_path: Path, receipt: dict[str, Any]) -> str | None:
    """Resolve rules SHA-256 strictly from the captured `rules.snapshot.yml` verified against `scan-manifest.json`.

    Never re-reads mutable `rules_path` from disk after scan capture.
    """
    if receipt.get("rules_capture_verified") is False:
        return None
    try:
        mpath = Path(manifest_path)
        snap_path = mpath.parent / "rules.snapshot.yml"
        if not mpath.is_file() or not snap_path.is_file():
            return None
        man = strict_json(mpath.read_text(encoding="utf-8"))
        if not isinstance(man, dict):
            return None
        snap_sha = digest(snap_path.read_bytes())
        artifacts = man.get("artifacts") if isinstance(man.get("artifacts"), dict) else {}
        if (
            man.get("rules_before_sha256") != snap_sha
            or man.get("rules_after_sha256") != snap_sha
            or artifacts.get("rules.snapshot.yml") != snap_sha
        ):
            return None
        return snap_sha
    except (OSError, UnicodeDecodeError, EvidenceError, ValueError):
        return None


def probe_ollama_ps(endpoint: str, *, requested_model: str, timeout: float = 2.0) -> dict[str, Any]:
    """Read-only GET /api/ps precheck to detect foreign heavy models occupying GPU VRAM."""
    url = endpoint.rstrip("/") + "/api/ps"
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    req = Request(url, headers={"Connection": "close"})
    try:
        with opener.open(req, timeout=max(0.5, min(timeout, 3.0))) as resp:
            raw = resp.read(256 * 1024)
            doc = strict_json(raw.decode("utf-8"))
    except (HTTPError, URLError, OSError, TimeoutError, UnicodeDecodeError, EvidenceError) as exc:
        return {
            "checked": False,
            "reachable": False,
            "blocked": False,
            "reason": None,
            "loaded_models": [],
            "error": str(exc),
        }

    models = doc.get("models") if isinstance(doc, dict) and isinstance(doc.get("models"), list) else []
    loaded: list[dict[str, Any]] = []
    foreign_vram_bytes = 0
    for item in models:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("model") or "")
        size_vram = int(item.get("size_vram") or 0) if type(item.get("size_vram")) is int else 0
        loaded.append({"name": name, "size_vram": size_vram})
        if name and name != requested_model:
            foreign_vram_bytes += size_vram

    blocked = foreign_vram_bytes > FOREIGN_MODEL_VRAM_BLOCK_BYTES
    reason = (
        f"GPU VRAM đang bị chiếm bởi mô hình khác ({foreign_vram_bytes} bytes > ngưỡng an toàn); "
        "tạm dừng suy luận Qwen an toàn (RESOURCE_BLOCKED)."
        if blocked
        else None
    )
    return {
        "checked": True,
        "reachable": True,
        "blocked": blocked,
        "reason": reason,
        "foreign_vram_bytes": foreign_vram_bytes,
        "loaded_models": loaded,
        "error": None,
    }


def _fail_closed_precheck_assessment(
    record: dict[str, Any],
    *,
    reason: str,
    failure_kind: str,
    model: str,
    endpoint: str,
    runtime_origin: str,
) -> dict[str, Any]:
    rt = execution(runtime_origin)
    rt.update(
        {
            "finding_id": record.get("id"),
            "request_attempted": False,
            "http_response_received": False,
            "answer_validated": False,
            "model_runtime_verified": False,
            "failure_kind": failure_kind,
            "http_capture_completeness": "precheck_not_attempted",
            "http_capture_complete": False,
        }
    )
    return undecided(
        reason,
        failure_kind=failure_kind,
        transport="ollama-http",
        model=model,
        endpoint=endpoint,
        raw_response=None,
        runtime=rt,
        prompt_contract=record.get("prompt_contract", DEFAULT_PROMPT_CONTRACT),
        prompt_sha256=None,
        elapsed_seconds=0.0,
        latency_ms=0.0,
    )


def run_bounded_triage(
    *,
    source_root: Path,
    triage_dir: Path,
    raw_json_path: Path,
    manifest_path: Path,
    path_maps: list[str],
    rules_path: Path,
    no_llm: bool,
    prompt_contract: str,
    ollama_endpoint: str,
    ollama_model: str,
    ollama_timeout_seconds: float,
    runtime_origin: str,
    deadline_mono: float,
    checkpoint_path: Path | None = None,
    max_prompt_bytes: int = DEFAULT_MAX_PROMPT_BYTES,
    enable_qwen_cache: bool = False,
    qwen_cache_dir: Path | None = None,
    on_evidence_ready: Callable[[int, dict[str, Any]], None] | None = None,
    on_finding_progress: Callable[[int, int], None] | None = None,
    on_triage_finished: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Execute Stages 3-6 cleanly inside `triage_dir` and return full telemetry + artifacts."""
    root = Path(source_root).resolve(strict=True)
    output = Path(triage_dir)
    if prompt_contract not in PROMPT_CONTRACTS:
        raise EvidenceError("unknown prompt contract: " + repr(prompt_contract))

    effective_max_prompt_bytes = min(int(max_prompt_bytes), DEFAULT_MAX_PROMPT_BYTES)
    if enable_qwen_cache:
        raise EvidenceError(
            "QWEN_CACHE_DISABLED: Qwen verdict caching is safely disabled; direct live HTTP analysis is required."
        )
    use_llm = not no_llm
    client = (
        OllamaClient(
            ollama_endpoint,
            ollama_model,
            ollama_timeout_seconds,
            runtime_origin,
            io_log_dir=output / "llm_io",
            capture_root=output,
        )
        if use_llm
        else None
    )
    output.mkdir(parents=True, exist_ok=False)

    # Stage 3: Evidence Collection + Java Context V2 Enrichment
    t_ev0 = time.monotonic()
    deadline_exceeded = t_ev0 >= deadline_mono
    raw = Path(raw_json_path).read_bytes()
    receipt, receipt_issues = verify_receipt(manifest_path, raw, root, None)
    issues = list(receipt_issues)
    exit_code = receipt["recorded_engine_exit"] if receipt["exit_capture_verified"] else None
    (output / "input.opengrep.json").write_bytes(raw)

    bundle = collect(
        raw,
        root,
        None,
        exit_code,
        issues,
        path_maps=path_maps,
        scan_provenance=receipt,
    )
    bundle["scan_provenance"] = receipt
    bundle["prompt_contract"] = prompt_contract
    source_inventory = (
        receipt.get("source_hashes")
        if receipt.get("source_capture_verified") is True and isinstance(receipt.get("source_hashes"), dict)
        else None
    )
    source_inventory_sha256 = compute_source_inventory_sha256(source_inventory)
    for record in bundle["records"]:
        record["prompt_contract"] = prompt_contract
        if receipt["source_capture_verified"]:
            for path_key, snapshot in record["snapshots"].items():
                if receipt["source_hashes"].get(path_key) != snapshot["sha256"]:
                    record["issues"].append("finding/trace source not bound to captured scan: " + path_key)

    t_ctx0 = time.monotonic()
    context_stats = enrich_bundle_context(
        bundle,
        root,
        path_maps=path_maps,
        max_prompt_bytes=effective_max_prompt_bytes,
    )
    context_enrich_ms = round((time.monotonic() - t_ctx0) * 1000.0, 3)

    (output / "evidence.json").write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    evidence_ms = round((time.monotonic() - t_ev0) * 1000.0, 3)
    if time.monotonic() >= deadline_mono:
        deadline_exceeded = True

    total_records = len(bundle["records"])
    if on_evidence_ready is not None:
        on_evidence_ready(total_records, context_stats)

    # Stage 4 & 5: Deadline-bounded Model Inventory + Resource Precheck + Inference + Validation
    t_qwen0 = time.monotonic()
    model_inventory: dict[str, Any] | None = None
    ps_snapshot: dict[str, Any] | None = None

    if use_llm:
        rem_tags = deadline_mono - time.monotonic()
        if deadline_exceeded or rem_tags <= 0.0:
            deadline_exceeded = True
        else:
            assert client is not None
            client.timeout = float(min(ollama_timeout_seconds, max(0.5, rem_tags)))
            model_inventory = client.verify_model_installed()
            (output / "ollama-tags-check.json").write_text(
                json.dumps(model_inventory, indent=2), encoding="utf-8"
            )
            rem_ps = deadline_mono - time.monotonic()
            if rem_ps <= 0.0:
                deadline_exceeded = True
            elif total_records > 0 and runtime_origin != "mock":
                ps_snapshot = probe_ollama_ps(
                    ollama_endpoint,
                    requested_model=ollama_model,
                    timeout=min(2.0, ollama_timeout_seconds, max(0.5, rem_ps)),
                )

    rules_sha256 = _extract_verified_rules_sha256(manifest_path, receipt)
    model_digest = model_inventory.get("model_digest") if isinstance(model_inventory, dict) else None
    cache = None
    if time.monotonic() >= deadline_mono:
        deadline_exceeded = True

    assessments: list[dict[str, Any]] = []
    per_finding_ms: list[float] = []
    cache_hits = 0
    live_calls = 0
    timeout_aborts = 0
    resource_blocks = 0

    if no_llm:
        assessments = [undecided("inference explicitly disabled", transport="disabled") for _ in bundle["records"]]
        if time.monotonic() >= deadline_mono:
            deadline_exceeded = True
    else:
        ckpt_path = Path(checkpoint_path) if checkpoint_path else None
        if ckpt_path:
            ckpt_path.parent.mkdir(parents=True, exist_ok=True)

        for idx, record in enumerate(bundle["records"], start=1):
            t_f0 = time.monotonic()
            remaining_sec = deadline_mono - time.monotonic()
            if deadline_exceeded or remaining_sec < 2.0:
                deadline_exceeded = True
                timeout_aborts += 1
                assessment = _fail_closed_precheck_assessment(
                    record,
                    reason="Vượt quá thời gian xử lý tối đa của phiên quét (job_timeout_seconds); chuyển UNDETERMINED an toàn.",
                    failure_kind="JOB_TIMEOUT",
                    model=ollama_model,
                    endpoint=ollama_endpoint,
                    runtime_origin=runtime_origin,
                )
            elif ps_snapshot is not None and ps_snapshot.get("blocked") is True:
                resource_blocks += 1
                assessment = _fail_closed_precheck_assessment(
                    record,
                    reason=str(ps_snapshot.get("reason") or "Tài nguyên GPU không an toàn để chạy Qwen."),
                    failure_kind="RESOURCE_BLOCKED",
                    model=ollama_model,
                    endpoint=ollama_endpoint,
                    runtime_origin=runtime_origin,
                )
            else:
                # Fail closed BEFORE HTTP /api/chat if prompt > 32 KB or issues exist
                prompt_bytes_now: int | None = None
                try:
                    prompt_bytes_now = effective_prompt_byte_length(record)
                except Exception:
                    prompt_bytes_now = None
                if prompt_bytes_now is not None and prompt_bytes_now > effective_max_prompt_bytes:
                    oversize_msg = (
                        f"prompt byte budget exceeded ({prompt_bytes_now} > {effective_max_prompt_bytes} bytes); "
                        "inference aborted fail-closed"
                    )
                    if oversize_msg not in record["issues"]:
                        record["issues"].append(oversize_msg)
                if record.get("issues"):
                    is_oversize = (
                        prompt_bytes_now is not None and prompt_bytes_now > effective_max_prompt_bytes
                    ) or any("budget exceeded" in str(x).lower() for x in record["issues"])
                    assessment = _fail_closed_precheck_assessment(
                        record,
                        reason="insufficient evidence: " + "; ".join(str(x) for x in record["issues"]),
                        failure_kind="PROMPT_TOO_LARGE" if is_oversize else "EVIDENCE_PRECHECK_FAILED",
                        model=ollama_model,
                        endpoint=ollama_endpoint,
                        runtime_origin=runtime_origin,
                    )
                else:
                    rem_before_chat = deadline_mono - time.monotonic()
                    if rem_before_chat < 2.0:
                        deadline_exceeded = True
                        timeout_aborts += 1
                        assessment = _fail_closed_precheck_assessment(
                            record,
                            reason="Vượt quá thời gian xử lý tối đa của phiên quét (job_timeout_seconds); chuyển UNDETERMINED an toàn.",
                            failure_kind="JOB_TIMEOUT",
                            model=ollama_model,
                            endpoint=ollama_endpoint,
                            runtime_origin=runtime_origin,
                        )
                    else:
                        assert client is not None
                        client.timeout = float(min(ollama_timeout_seconds, rem_before_chat))
                        raw_assessment = client.analyze(record)
                        if (raw_assessment.get("runtime") or {}).get("request_attempted") is True:
                            live_calls += 1
                        assessment = apply_integration_gate(record, raw_assessment)
                        if time.monotonic() >= deadline_mono:
                            deadline_exceeded = True

            assessments.append(assessment)
            per_finding_ms.append(round((time.monotonic() - t_f0) * 1000.0, 3))

            if ckpt_path:
                with ckpt_path.open("a", encoding="utf-8") as ckpt_stream:
                    ckpt_stream.write(json.dumps({"id": record["id"], "assessment": assessment}, ensure_ascii=False) + "\n")
            if on_finding_progress is not None:
                on_finding_progress(idx, total_records)

        if time.monotonic() >= deadline_mono:
            deadline_exceeded = True

    qwen_total_ms = round((time.monotonic() - t_qwen0) * 1000.0, 3)
    if on_triage_finished is not None:
        on_triage_finished(
            {
                "assessments_list": assessments,
                "qwen_total_ms": qwen_total_ms,
                "live_calls": live_calls,
                "cache_hits": cache_hits,
                "timeout_aborts": timeout_aborts,
                "resource_blocks": resource_blocks,
                "deadline_exceeded": deadline_exceeded or time.monotonic() >= deadline_mono,
            }
        )

    # Stage 6: SQLite ReviewStore Commit & Atomic assessments.jsonl
    t_store0 = time.monotonic()
    if t_store0 >= deadline_mono:
        deadline_exceeded = True
    assessments_rows: list[dict[str, Any]] = []
    tmp_jsonl = output / f".assessments.{os.getpid()}.{uuid.uuid4().hex[:8]}.jsonl.tmp"
    try:
        store = ReviewStore(output / "review.sqlite")
        try:
            store.add(bundle, assessments)
        finally:
            store.close()

        with tmp_jsonl.open("w", encoding="utf-8") as stream:
            for record, assessment in zip(bundle["records"], assessments):
                row = {
                    "schema_version": SCHEMA_VERSION,
                    "id": record["id"],
                    "alert_id": record["id"],
                    "scan_sha256": record["scan_sha256"],
                    "finding_index": record["finding_index"],
                    "state": "OPEN",
                    "human_review_state": "OPEN",
                    "raw_model_status": assessment.get("raw_model_status"),
                    "validated_status": assessment.get("validated_status", assessment.get("status")),
                    "evidence": record,
                    "assessment": assessment,
                }
                assessments_rows.append(row)
                stream.write(json.dumps(row, ensure_ascii=False) + "\n")
        tmp_jsonl.replace(output / "assessments.jsonl")
    except (sqlite3.Error, EvidenceError, OSError, ValueError, TypeError) as exc:
        raise StorageCommitError(f"Failed to commit triage SQLite/JSONL storage: {exc}") from exc
    finally:
        tmp_jsonl.unlink(missing_ok=True)

    store_commit_ms = round((time.monotonic() - t_store0) * 1000.0, 3)
    if time.monotonic() >= deadline_mono:
        deadline_exceeded = True
    triage_exit = 2 if bundle["issues"] or any(r["issues"] for r in bundle["records"]) else 0

    return {
        "triage_exit": triage_exit,
        "bundle": bundle,
        "assessments_rows": assessments_rows,
        "assessments_list": assessments,
        "model_inventory": model_inventory,
        "ps_snapshot": ps_snapshot,
        "runtime_summary": runtime_summary(assessments),
        "rules_sha256": rules_sha256,
        "source_inventory_sha256": source_inventory_sha256,
        "deadline_exceeded": deadline_exceeded,
        "cache_hits": cache_hits,
        "live_calls": live_calls,
        "timeout_aborts": timeout_aborts,
        "resource_blocks": resource_blocks,
        "telemetry": {
            "evidence_ms": evidence_ms,
            "context_enrich_ms": context_enrich_ms,
            "qwen_total_ms": qwen_total_ms,
            "qwen_per_finding_ms": per_finding_ms,
            "store_commit_ms": store_commit_ms,
            "context_stats": context_stats,
            "rules_sha256": rules_sha256,
            "source_inventory_sha256": source_inventory_sha256,
            "deadline_exceeded": deadline_exceeded,
            "cache_enabled": False,
            "cache_policy": "SAFELY_DISABLED",
            "cache_hits": cache_hits,
            "live_calls": live_calls,
            "timeout_aborts": timeout_aborts,
            "resource_blocks": resource_blocks,
        },
    }
