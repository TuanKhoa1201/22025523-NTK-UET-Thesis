"""Qwen verdict cache — SAFELY DISABLED at the v2.api boundary.

Disabled unconditionally (`CACHE_ENABLED = False`, `QWEN_CACHE_STATUS = "SAFELY_DISABLED"`):
- `ProvenanceQwenCache.lookup()` and `ProvenanceQwenCache.store()` are permanently locked
  and never persist or reuse Qwen verdicts.
- Direct local HTTP calls to Ollama (`OllamaClient`) remain the sole verdict execution path so
  every analyzed finding has same-call raw HTTP request/response byte evidence.
- Preserves module symbols (`compute_source_inventory_sha256`, `compute_prompt_sha256`,
  `compute_cache_key`, `_verify_source_inventory_on_disk`) for backwards-compatible imports.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from v2.api.java_context_v2 import CONTEXT_V2_VERSION
from v2.triage.evidence import digest
from v2.triage.ollama import (
    DEFAULT_PROMPT_CONTRACT,
    PROMPT_VERSION,
    prompt as build_ollama_prompt,
)

CACHE_ENABLED = False
QWEN_CACHE_STATUS = "SAFELY_DISABLED"
CACHE_SCHEMA = "ntk-qwen-cache-entry-disabled"


def _is_sha256_hex(val: Any) -> bool:
    return isinstance(val, str) and len(val) == 64 and all(c in "0123456789abcdef" for c in val.lower())


def compute_source_inventory_sha256(source_inventory: dict[str, str] | None) -> str | None:
    """Compute a deterministic SHA-256 over the verified repo-wide `{rel_path: sha256}` inventory."""
    if not isinstance(source_inventory, dict) or not source_inventory:
        return None
    normalized: dict[str, str] = {}
    for rel, fsha in sorted(source_inventory.items()):
        if not isinstance(rel, str) or not rel or not _is_sha256_hex(fsha):
            return None
        normalized[rel] = fsha.lower()
    return digest(json.dumps(normalized, sort_keys=True, ensure_ascii=False).encode("utf-8"))


def compute_prompt_sha256(record: dict[str, Any]) -> str:
    messages = build_ollama_prompt(record)
    return digest(json.dumps(messages, ensure_ascii=False).encode("utf-8"))


def compute_cache_key(
    record: dict[str, Any],
    *,
    rules_sha256: str,
    ollama_model: str,
    model_digest: str,
    prompt_sha256: str,
    source_inventory_sha256: str,
) -> str:
    snapshots = record.get("snapshots") if isinstance(record.get("snapshots"), dict) else {}
    snap_hashes = {
        str(k): str(v.get("sha256") or "")
        for k, v in sorted(snapshots.items())
        if isinstance(v, dict)
    }
    snippets = record.get("snippets") if isinstance(record.get("snippets"), list) else []
    canonical_trace = [
        {
            "role": s.get("role"),
            "path": s.get("path"),
            "start": s.get("start"),
            "end": s.get("end"),
            "sha256": s.get("sha256"),
            "matched": s.get("matched"),
        }
        for s in snippets
        if isinstance(s, dict)
    ]
    finding_path = (
        canonical_trace[0]["path"]
        if canonical_trace and isinstance(canonical_trace[0].get("path"), str)
        else record.get("path")
    )
    trace_sha = digest(json.dumps(canonical_trace, sort_keys=True, ensure_ascii=False).encode("utf-8"))
    key_material = {
        "schema": "ntk-qwen-cache-key-3",
        "source_inventory_sha256": source_inventory_sha256,
        "snapshots": snap_hashes,
        "finding_path": finding_path,
        "rule_id": record.get("rule_id"),
        "start": record.get("start"),
        "end": record.get("end"),
        "canonical_trace_sha256": trace_sha,
        "rules_sha256": rules_sha256,
        "ollama_model": ollama_model,
        "model_digest": model_digest,
        "prompt_version": PROMPT_VERSION,
        "prompt_contract": record.get("prompt_contract", DEFAULT_PROMPT_CONTRACT),
        "prompt_sha256": prompt_sha256,
        "context_version": CONTEXT_V2_VERSION,
    }
    return digest(json.dumps(key_material, sort_keys=True, ensure_ascii=False).encode("utf-8"))


def _verify_source_inventory_on_disk(source_root: Path, source_inventory: dict[str, str]) -> bool:
    """Defense-in-depth whole-tree inventory verifier detecting added, removed, or modified `.java` files."""
    root = Path(source_root).resolve()
    if not isinstance(source_inventory, dict) or not source_inventory:
        return False
    try:
        actual_java_paths = {
            p.resolve().relative_to(root).as_posix()
            for p in root.rglob("*.java")
            if p.is_file()
        }
    except (OSError, ValueError):
        return False
    if actual_java_paths != set(source_inventory.keys()):
        return False
    for rel, expected_sha in source_inventory.items():
        if not isinstance(rel, str) or not rel or Path(rel).is_absolute() or not _is_sha256_hex(expected_sha):
            return False
        target = (root / rel).resolve()
        try:
            target.relative_to(root)
        except ValueError:
            return False
        if not target.is_file():
            return False
        try:
            if digest(target.read_bytes()) != expected_sha.lower():
                return False
        except OSError:
            return False
    return True


class ProvenanceQwenCache:
    """Locked no-op cache stub (`SAFELY_DISABLED`): never stores or replays Qwen verdicts."""

    def __init__(self, cache_dir: Path):
        self.cache_dir = Path(cache_dir).resolve()

    @staticmethod
    def is_enabled() -> bool:
        return False

    def lookup(self, *args: Any, **kwargs: Any) -> None:
        return None

    def store(self, *args: Any, **kwargs: Any) -> None:
        return None
