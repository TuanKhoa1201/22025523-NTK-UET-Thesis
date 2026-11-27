"""Core read, health, human-review, and provenance-preserving report service for v2.api.

All read endpoints query SQLite strictly via read-only URI (`?mode=ro`) so inspecting
existing scans (Flow A) never mutates `review.sqlite` or creates journal files.
All human review mutations (Flow B) delegate directly to `v2.triage.store.ReviewStore`.
"""
from __future__ import annotations

from contextlib import closing, contextmanager
import copy
from dataclasses import dataclass
from datetime import datetime
import json
import os
from pathlib import Path
import shutil
import sqlite3
import threading
import time
from typing import Any

if os.name == "nt":
    import msvcrt
else:
    import fcntl

from v2.api import API_CONTRACT_SCHEMA, API_SERVICE_NAME, API_VERSION, REPORT_SCHEMA
from v2.api.config import ApiConfig
from v2.api.opengrep_runner import (
    OpenGrepHealthProbe,
    compute_opengrep_coverage_telemetry,
    reconcile_cached_and_raw_coverage_telemetry,
    validate_coverage_telemetry_payload,
)
from v2.api.triage_gate import UNSUPPORTED_REFUTATION_PROOF_LIMITS
from v2.g1_integration.bridge import KNOWN_ANALYSIS_LIMITS
from v2.g1_integration.fork_support.scanner_config import validate_opengrep_binary
from v2.triage import export_pilot
from v2.triage.evidence import EvidenceError, StaleSourceError, digest, now, strict_json
from v2.triage.ollama import PROMPT_VERSION, OllamaClient, is_reparse_link
from v2.triage.runtime import SCHEMA_VERSION, summary as runtime_summary_fn
from v2.triage.store import ReviewStore


class ApiServiceError(Exception):
    def __init__(
        self,
        error_code: str,
        message: str,
        *,
        http_status: int = 400,
        extra: dict[str, Any] | None = None,
    ):
        super().__init__(message)
        self.error_code = error_code
        self.http_status = http_status
        self.extra = dict(extra or {})

    def to_dict(self) -> dict[str, Any]:
        return {
            "error_code": self.error_code,
            "error_message": str(self),
            **self.extra,
        }


MANAGED_META_SCHEMA = "ntk-api-scan-meta-2"
MANAGED_COMMIT_SCHEMA = "ntk-scan-commit-1"
_MANAGED_META_KEYS = ("job_id", "job_state", "publishable", "error_code", "commit_authority")

# Single authoritative managed artifact contract shared by ScanJobManager (commit & recovery)
# and TriageApiService (discovery, publication, revalidation, read/write provenance).
MANAGED_COMMON_SEALED_ARTIFACTS: tuple[str, ...] = (
    "capture/opengrep.json",
    "capture/opengrep.sarif",
    "capture/scan-manifest.json",
    "triage/evidence.json",
    "triage/input.opengrep.json",
    "triage/assessments.jsonl",
)
MANAGED_LLM_SEALED_ARTIFACTS: tuple[str, ...] = (
    "triage/live-protocol-check.json",
    "triage/http-capture-check.json",
)
MANAGED_OPTIONAL_SEALED_ARTIFACTS: tuple[str, ...] = (
    "capture/rules.snapshot.yml",
    "triage/ollama-tags-check.json",
)
MANAGED_REQUIRED_MUTABLE_ARTIFACTS: tuple[str, ...] = (
    "triage/review.sqlite",
)


def managed_required_sealed_artifacts(*, no_llm: bool) -> tuple[str, ...]:
    """Return the exact immutable artifacts that MUST exist and be SHA-256 sealed for a managed job mode."""
    if no_llm:
        return MANAGED_COMMON_SEALED_ARTIFACTS
    return MANAGED_COMMON_SEALED_ARTIFACTS + MANAGED_LLM_SEALED_ARTIFACTS


def managed_optional_sealed_artifacts(*, no_llm: bool) -> tuple[str, ...]:
    """Return optional immutable artifacts that, if present at commit time, are sealed and verified thereafter."""
    if no_llm:
        return ("capture/rules.snapshot.yml",)
    return MANAGED_OPTIONAL_SEALED_ARTIFACTS


def managed_required_runtime_artifacts(*, no_llm: bool) -> tuple[str, ...]:
    """Return all artifacts (immutable sealed + mutable review.sqlite) that MUST exist before commit."""
    return managed_required_sealed_artifacts(no_llm=no_llm) + MANAGED_REQUIRED_MUTABLE_ARTIFACTS


def collect_managed_artifact_sha256s(scan_out_root: Path, *, no_llm: bool) -> tuple[dict[str, str], list[str]]:
    """Verify presence of all mode-required artifacts and compute SHA-256 digests for all sealed artifacts.

    Single source of truth used by `ScanJobManager` pre-commit staging/commit and aligned with
    `inspect_managed_job_commit` in `TriageApiService`.
    """
    missing: list[str] = []
    for rel in managed_required_runtime_artifacts(no_llm=no_llm):
        if not (scan_out_root / rel).is_file():
            missing.append(rel)

    hashes: dict[str, str] = {}
    for rel in managed_required_sealed_artifacts(no_llm=no_llm) + managed_optional_sealed_artifacts(no_llm=no_llm):
        fp = scan_out_root / rel
        if fp.is_file():
            hashes[rel] = digest(fp.read_bytes())
    return hashes, missing


@dataclass(frozen=True)
class ManagedCommitCheck:
    """Structured result distinguishing never-completed/invalid commits from post-commit missing/tampered artifacts."""

    ok: bool
    status: str  # "VALID" | "INCOMPLETE_COMMIT" | "ARTIFACT_INTEGRITY_FAILED"
    reason: str
    missing_artifacts: tuple[str, ...] = ()
    mismatched_artifacts: tuple[str, ...] = ()


# Shared data_dir-scoped publication & review synchronization lock (used by BOTH ScanJobManager and TriageApiService).
# Combines a re-entrant in-process RLock with a cross-process OS lockfile (`<data_dir>/.ntk-publication.lock`)
# so owner publication/revocation transitions and Human Review writes serialize across instances & processes.
_PUB_LOCKS_GUARD = threading.Lock()
_PUB_LOCKS: dict[str, threading.RLock] = {}
_PUB_LOCK_LOCAL = threading.local()


def _pub_lock_key(data_dir: Path) -> str:
    try:
        norm = str(Path(data_dir).resolve())
    except OSError:
        norm = os.path.abspath(os.fspath(data_dir))
    return norm.lower() if os.name == "nt" else norm


def _get_pub_rlock(key: str) -> threading.RLock:
    with _PUB_LOCKS_GUARD:
        lock = _PUB_LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _PUB_LOCKS[key] = lock
        return lock


@contextmanager
def acquire_publication_lock(data_dir: Path, *, timeout_seconds: float = 30.0):
    """Acquire the authoritative data_dir publication/review lock (in-process RLock + cross-process OS lockfile)."""
    key = _pub_lock_key(data_dir)
    rlock = _get_pub_rlock(key)
    depths: dict[str, int] = getattr(_PUB_LOCK_LOCAL, "depths", None)  # type: ignore[assignment]
    if depths is None:
        depths = {}
        _PUB_LOCK_LOCAL.depths = depths

    rlock.acquire()
    cur_depth = depths.get(key, 0)
    depths[key] = cur_depth + 1
    fd: int | None = None
    os_locked = False
    try:
        if cur_depth == 0:
            data_path = Path(data_dir)
            if data_path.is_dir():
                lock_path = data_path / ".ntk-publication.lock"
                fd = os.open(os.fspath(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
                if os.fstat(fd).st_size == 0:
                    os.write(fd, b"0")
                deadline = time.monotonic() + max(0.5, float(timeout_seconds))
                while True:
                    try:
                        if os.name == "nt":
                            os.lseek(fd, 0, os.SEEK_SET)
                            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                        else:
                            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        os_locked = True
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise ApiServiceError(
                                "PUBLICATION_LOCK_TIMEOUT",
                                "Không thể lấy khóa đồng bộ công bố/kiểm duyệt trong thời gian cho phép.",
                                http_status=503,
                            )
                        time.sleep(0.01)
        yield
    finally:
        if os_locked and fd is not None:
            try:
                if os.name == "nt":
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        new_depth = depths.get(key, 1) - 1
        if new_depth <= 0:
            depths.pop(key, None)
        else:
            depths[key] = new_depth
        rlock.release()


@dataclass(frozen=True)
class DiscoveredScan:
    scan_id: str
    scan_sha256: str
    base_dir: Path
    triage_dir: Path
    db_path: Path
    evidence_path: Path
    assessments_path: Path | None
    raw_json_path: Path | None
    g1_manifest_path: Path | None
    meta_path: Path | None
    writable: bool
    candidate_dir: Path | None = None
    is_managed: bool = False
    owner_job_id: str | None = None
    integrity_error: str | None = None


def _norm_cwe(raw_cwe: Any) -> str:
    if isinstance(raw_cwe, list):
        first = raw_cwe[0] if raw_cwe else ""
    else:
        first = str(raw_cwe or "")
    head = str(first).split(":", 1)[0].strip().upper()
    if head.startswith("CWE-"):
        suffix = head[4:].lstrip("0") or "0"
        return f"CWE-{suffix}" if suffix.isdigit() else head
    return head or "UNKNOWN_CWE"


def _parse_json_maybe(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return value


def _open_ro_sqlite(db_path: Path):
    resolved = Path(db_path).resolve(strict=True)
    uri = resolved.as_uri() + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=5.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    return closing(conn)


def _has_table(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


def _is_valid_iso_tz(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    norm = value.strip()
    if norm.endswith("Z"):
        norm = norm[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(norm)
    except ValueError:
        return False
    return dt.tzinfo is not None


def _count_nonempty_jsonl_lines(path: Path) -> int | None:
    try:
        raw_text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    return sum(1 for ln in raw_text.splitlines() if ln.strip())


def _lexical_abs_path(path: Path) -> Path:
    """Return absolute lexical path without dereferencing Windows NTFS junctions or symlinks."""
    return Path(os.path.abspath(os.fspath(path)))


def _candidate_path_variants(candidate: Path, triage_dir: Path | None = None) -> tuple[list[Path], bool]:
    """Collect lexical (junction/symlink-preserving) and resolved paths for candidate AND parent when accessing `triage/`."""
    variants: list[Path] = []
    seen: set[Path] = set()
    resolve_failed = False

    def _add(p: Path) -> None:
        if p not in seen:
            seen.add(p)
            variants.append(p)

    lex_cand = _lexical_abs_path(candidate)
    _add(lex_cand)
    res_cand: Path | None = None
    try:
        res_cand = candidate.resolve()
        _add(res_cand)
    except OSError:
        resolve_failed = True

    t_dir = triage_dir if triage_dir is not None else ((candidate / "triage") if (candidate / "triage").exists() else None)
    if t_dir is not None:
        lex_t = _lexical_abs_path(t_dir)
        _add(lex_t.parent)
        try:
            res_t = t_dir.resolve()
            _add(res_t.parent)
        except OSError:
            resolve_failed = True
        if t_dir == candidate:
            # Direct access to `triage/` (or junction pointing to `triage/`): preserve parent scan relationship!
            _add(lex_cand.parent)
            if res_cand is not None:
                _add(res_cand.parent)

    return variants, resolve_failed


def _managed_root_variants(managed_scans_root: Path | None) -> tuple[list[Path], bool]:
    if managed_scans_root is None:
        return [], False
    variants: list[Path] = [_lexical_abs_path(managed_scans_root)]
    resolve_failed = False
    try:
        res = managed_scans_root.resolve()
        if res not in variants:
            variants.append(res)
    except OSError:
        resolve_failed = True
    return variants, resolve_failed


def _collect_managed_scan_aliases(managed_scans_root: Path | None) -> dict[Path, list[str]]:
    """Map resolved target scan directories AND their `triage/` subdirectories back to managed child job names."""
    aliases: dict[Path, list[str]] = {}
    if managed_scans_root is None or not managed_scans_root.is_dir():
        return aliases
    try:
        children = list(managed_scans_root.iterdir())
    except OSError:
        return aliases
    for child in children:
        try:
            res = child.resolve()
        except OSError:
            continue
        aliases.setdefault(res, [])
        if child.name not in aliases[res]:
            aliases[res].append(child.name)
        triage_child = child / "triage"
        if triage_child.exists():
            try:
                res_t = triage_child.resolve()
                aliases.setdefault(res_t, [])
                if child.name not in aliases[res_t]:
                    aliases[res_t].append(child.name)
            except OSError:
                pass
            res_sub = res / "triage"
            aliases.setdefault(res_sub, [])
            if child.name not in aliases[res_sub]:
                aliases[res_sub].append(child.name)
    return aliases


def _is_within_managed_scans_root(cand_variants: list[Path], root_variants: list[Path]) -> bool:
    for c_var in cand_variants:
        for r_var in root_variants:
            if c_var != r_var and c_var.is_relative_to(r_var):
                return True
    return False


def _meta_has_managed_markers(parsed_meta: dict[str, Any] | None) -> bool:
    if not isinstance(parsed_meta, dict):
        return False
    if parsed_meta.get("schema") == MANAGED_META_SCHEMA:
        return True
    return any(k in parsed_meta for k in _MANAGED_META_KEYS)


def _find_parent_managed_scan_dir(
    candidate: Path,
    *,
    managed_scans_root: Path | None,
    jobs_dir: Path | None,
    managed_aliases: dict[Path, list[str]] | None,
) -> Path | None:
    """When `candidate` points directly at a `triage/` subdir (or junction to it), detect its managed parent scan dir."""
    root_variants, root_err = _managed_root_variants(managed_scans_root)
    if root_err:
        return _lexical_abs_path(candidate).parent

    parent_cands: list[Path] = []
    lex_parent = _lexical_abs_path(candidate).parent
    parent_cands.append(lex_parent)
    try:
        res_cand = candidate.resolve()
        res_parent = res_cand.parent
        if res_parent not in parent_cands:
            parent_cands.append(res_parent)
    except OSError:
        return lex_parent

    for p in parent_cands:
        if any(p != r and p.is_relative_to(r) for r in root_variants):
            return p
        if managed_aliases and p in managed_aliases:
            return p
        if (p / "api-scan-failure.json").is_file():
            return p
        pm = p / "api-scan-meta.json"
        if pm.is_file():
            try:
                raw_m = strict_json(pm.read_text(encoding="utf-8"))
                if _meta_has_managed_markers(raw_m):
                    return p
            except (OSError, UnicodeDecodeError, EvidenceError):
                # Unreadable meta on a parent with `capture/` or matching job file is treated conservatively
                if (p / "capture").is_dir() or (jobs_dir is not None and (jobs_dir / f"{p.name}.json").is_file()):
                    return p
        if jobs_dir is not None and jobs_dir.is_dir() and p.name and (jobs_dir / f"{p.name}.json").is_file():
            return p

    # Also check if `candidate` itself is mapped as a `triage/` alias of a managed scan
    if managed_aliases:
        try:
            res_c = candidate.resolve()
            if res_c in managed_aliases:
                return res_c.parent
        except OSError:
            return lex_parent
    return None


def _collect_dir_owner_job_ids(
    cand_variants: list[Path],
    root_variants: list[Path],
    jobs_dir: Path | None,
    *,
    managed_aliases: dict[Path, list[str]] | None = None,
) -> set[str]:
    """Collect authoritative directory/junction-derived job IDs for a managed scan candidate."""
    owners: set[str] = set()
    for c_var in cand_variants:
        for r_var in root_variants:
            if c_var != r_var and c_var.is_relative_to(r_var):
                rel = c_var.relative_to(r_var)
                if rel.parts and rel.parts[0]:
                    owners.add(rel.parts[0])
        if managed_aliases and c_var in managed_aliases:
            for alias_name in managed_aliases[c_var]:
                if alias_name:
                    owners.add(alias_name)
        if jobs_dir is not None and jobs_dir.is_dir() and c_var.name:
            if (jobs_dir / f"{c_var.name}.json").is_file():
                owners.add(c_var.name)
    return owners


def _has_conflicting_job_owner(
    jobs_dir: Path | None,
    *,
    owner_job_id: str,
    scan_id: str,
    scan_dir_name: str | None = None,
) -> bool:
    """Return True if any DIFFERENT job record claims ownership of the same `scan_id` or `scan_dir`."""
    if jobs_dir is None or not jobs_dir.is_dir():
        return False
    try:
        for jf in sorted(jobs_dir.glob("*.json")):
            stem = jf.stem
            try:
                jdoc = strict_json(jf.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, EvidenceError):
                continue
            if not isinstance(jdoc, dict):
                continue
            jid = jdoc.get("job_id") if isinstance(jdoc.get("job_id"), str) and jdoc["job_id"].strip() else stem
            if jid == owner_job_id:
                continue
            if jdoc.get("scan_id") == scan_id or jdoc.get("revoked_scan_id") == scan_id:
                return True
            for commit_key in ("commit", "revoked_commit"):
                commit_obj = jdoc.get(commit_key)
                if isinstance(commit_obj, dict):
                    if commit_obj.get("scan_id") == scan_id:
                        return True
                    if scan_dir_name and commit_obj.get("scan_dir") == scan_dir_name:
                        return True
    except OSError:
        return True
    return False


def _validate_sealed_v2_commit_structure(
    commit_obj: Any,
    *,
    owner_job_id: str,
    owner_job_doc: dict[str, Any],
    is_revoked: bool = False,
) -> tuple[dict[str, Any] | None, str | None]:
    """Validate that a v2 `commit` (or recovery `revoked_commit`) object itself represents a genuine sealed commit."""
    if not isinstance(commit_obj, dict):
        return None, "missing commit object on job record"
    if commit_obj.get("schema") != MANAGED_COMMIT_SCHEMA:
        return None, "invalid commit schema"
    if commit_obj.get("job_id") != owner_job_id:
        return None, "commit job_id mismatch"
    c_scan_dir = commit_obj.get("scan_dir")
    if c_scan_dir is not None and (not isinstance(c_scan_dir, str) or c_scan_dir != owner_job_id):
        return None, "commit scan_dir mismatch"
    c_sid = commit_obj.get("scan_id")
    if not isinstance(c_sid, str) or not c_sid.strip():
        return None, "commit scan_id missing"
    c_sha = commit_obj.get("scan_sha256")
    if not TriageApiService._is_sha256_hex(c_sha):
        return None, "commit scan_sha256 invalid"
    if not is_revoked:
        if owner_job_doc.get("scan_id") != c_sid:
            return None, "commit scan_id mismatch"
        if owner_job_doc.get("scan_sha256") != c_sha:
            return None, "commit scan_sha256 mismatch"
    elif owner_job_doc.get("scan_sha256") is not None and owner_job_doc.get("scan_sha256") != c_sha:
        return None, "revoked_commit scan_sha256 mismatch"
    expected_meta_sha = commit_obj.get("meta_sha256")
    if not TriageApiService._is_sha256_hex(expected_meta_sha):
        return None, "commit meta_sha256 invalid"
    c_no_llm = commit_obj.get("no_llm")
    if "no_llm" in commit_obj:
        if type(c_no_llm) is not bool:
            return None, "commit.no_llm is not a boolean"
        if "no_llm" in owner_job_doc and owner_job_doc.get("no_llm") != c_no_llm:
            return None, "conflicting no_llm flags across job and commit"
    else:
        j_no_llm = owner_job_doc.get("no_llm")
        if type(j_no_llm) is bool:
            c_no_llm = j_no_llm
        else:
            st = owner_job_doc.get("stage_statuses") if isinstance(owner_job_doc.get("stage_statuses"), dict) else None
            qst = str(st.get("qwen_inference_status") or "").strip().upper() if isinstance(st, dict) else ""
            if qst == "DISABLED":
                c_no_llm = True
            elif qst:
                c_no_llm = False
            else:
                return None, "unable to determine no_llm job mode"
    commit_hashes = commit_obj.get("artifact_sha256s")
    if not isinstance(commit_hashes, dict) or not commit_hashes:
        return None, "commit artifact_sha256s missing"
    required_sealed = managed_required_sealed_artifacts(no_llm=c_no_llm)
    missing_in_manifest = [rel for rel in required_sealed if not TriageApiService._is_sha256_hex(commit_hashes.get(rel))]
    if missing_in_manifest:
        return None, f"sealed commit manifest omits required artifacts for no_llm={c_no_llm}: {missing_in_manifest}"
    if commit_hashes.get("capture/opengrep.json") != c_sha or commit_hashes.get("triage/input.opengrep.json") != c_sha:
        return None, "sealed opengrep.json hash disagrees with scan_sha256"
    return commit_obj, None


def _extract_sealed_v2_commit(
    owner_job_doc: Any,
    owner_job_id: str,
) -> tuple[dict[str, Any] | None, bool, str | None]:
    """Extract an active or post-commit-revoked sealed v2 commit record from `owner_job_doc`.

    Returns `(commit_obj, is_revoked_integrity_failure, invalid_reason)`.
    Only jobs that truly reached the v2 single commit point return a non-None `commit_obj`.
    """
    if not isinstance(owner_job_doc, dict) or owner_job_doc.get("job_id") != owner_job_id:
        return None, False, "invalid owner job object or job_id mismatch"
    if (
        owner_job_doc.get("state") == "COMPLETED"
        and owner_job_doc.get("finalizing") is not True
        and not owner_job_doc.get("error_code")
        and "commit" in owner_job_doc
    ):
        c_obj, err = _validate_sealed_v2_commit_structure(
            owner_job_doc.get("commit"),
            owner_job_id=owner_job_id,
            owner_job_doc=owner_job_doc,
            is_revoked=False,
        )
        return c_obj, False, err
    if (
        owner_job_doc.get("state") == "FAILED"
        and owner_job_doc.get("error_code") == "COMMITTED_ARTIFACT_TAMPERED_OR_MISSING"
        and isinstance(owner_job_doc.get("revoked_commit"), dict)
    ):
        c_obj, err = _validate_sealed_v2_commit_structure(
            owner_job_doc.get("revoked_commit"),
            owner_job_id=owner_job_id,
            owner_job_doc=owner_job_doc,
            is_revoked=True,
        )
        if c_obj is not None:
            return c_obj, True, None
        return None, False, err
    return None, False, "job has no active or post-commit-revoked sealed v2 commit"


def _inspect_failure_marker(scan_dir: Path) -> tuple[bool, bool, str | None]:
    """Inspect `api-scan-failure.json`.

    Returns `(marker_exists, is_post_commit_integrity_failure, detail_reason)`.
    """
    fp = scan_dir / "api-scan-failure.json"
    if not fp.exists() and not fp.is_symlink():
        return False, False, None
    if not fp.is_file():
        return True, False, "non-file api-scan-failure.json present"
    try:
        doc = strict_json(fp.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, EvidenceError):
        return True, False, "unreadable or malformed api-scan-failure.json"
    if not isinstance(doc, dict):
        return True, False, "non-object api-scan-failure.json"
    is_post_commit = (
        doc.get("failure_classification") == "ARTIFACT_INTEGRITY_FAILED"
        or doc.get("error_code") == "COMMITTED_ARTIFACT_TAMPERED_OR_MISSING"
    )
    reason = doc.get("failure_reason") if isinstance(doc.get("failure_reason"), str) else doc.get("error_message")
    if not isinstance(reason, str) or not reason.strip():
        parts = []
        if doc.get("failure_classification") is not None:
            parts.append(f"failure_classification={doc.get('failure_classification')!r}")
        if doc.get("error_code") is not None:
            parts.append(f"error_code={doc.get('error_code')!r}")
        reason = ", ".join(parts) if parts else "unspecified failure marker payload"
    return True, is_post_commit, reason


def _revoked_integrity_check_from_job_doc(owner_job_doc: dict[str, Any]) -> ManagedCommitCheck:
    """Reconstruct a structured `ARTIFACT_INTEGRITY_FAILED` check from a recovery-revoked job record."""
    inf = owner_job_doc.get("integrity_failure") if isinstance(owner_job_doc.get("integrity_failure"), dict) else {}
    reason = (
        str(inf.get("reason"))
        if isinstance(inf.get("reason"), str) and inf.get("reason")
        else "sealed artifacts missing or tampered after commit (recorded during recovery)"
    )
    missing = tuple(str(x) for x in (inf.get("missing_artifacts") or []) if isinstance(x, str))
    mismatched = tuple(str(x) for x in (inf.get("mismatched_artifacts") or []) if isinstance(x, str))
    return ManagedCommitCheck(
        False,
        "ARTIFACT_INTEGRITY_FAILED",
        reason,
        missing_artifacts=missing,
        mismatched_artifacts=mismatched,
    )


def _resolve_managed_no_llm_mode(
    owner_job_doc: dict[str, Any],
    parsed_meta: dict[str, Any],
    commit_obj: dict[str, Any] | None,
) -> tuple[bool | None, str | None]:
    """Resolve `no_llm` mode consistently across job record, metadata, and commit record."""
    explicit_vals: list[bool] = []
    for src_name, src in (("job", owner_job_doc), ("meta", parsed_meta), ("commit", commit_obj or {})):
        if isinstance(src, dict) and "no_llm" in src:
            val = src.get("no_llm")
            if type(val) is not bool:
                return None, f"{src_name}.no_llm is not a boolean"
            explicit_vals.append(val)
    if explicit_vals:
        if len(set(explicit_vals)) != 1:
            return None, "conflicting no_llm flags across job, metadata, and commit"
        return explicit_vals[0], None
    # Backward compatibility for pre-existing v2 records created before `no_llm` was mirrored into meta/commit
    st = parsed_meta.get("stage_statuses") if isinstance(parsed_meta.get("stage_statuses"), dict) else None
    if not isinstance(st, dict):
        st = owner_job_doc.get("stage_statuses") if isinstance(owner_job_doc.get("stage_statuses"), dict) else None
    if isinstance(st, dict):
        qst = str(st.get("qwen_inference_status") or "").strip().upper()
        if qst == "DISABLED":
            return True, None
        if qst:
            return False, None
    return None, "unable to determine no_llm job mode"


def _verify_sealed_artifact_hashes_on_disk(
    scan_dir: Path,
    hashes: dict[str, str],
) -> tuple[list[str], list[str]]:
    """Verify every `(rel, expected_sha)` entry inside `scan_dir` exists, stays within `scan_dir`, and matches SHA-256."""
    missing: list[str] = []
    mismatched: list[str] = []
    try:
        base_resolved = scan_dir.resolve(strict=True)
    except OSError:
        return list(hashes.keys()), []
    for rel, expected_sha in hashes.items():
        if not isinstance(rel, str) or not rel or not TriageApiService._is_sha256_hex(expected_sha):
            mismatched.append(str(rel))
            continue
        try:
            target = (base_resolved / rel).resolve()
            target.relative_to(base_resolved)
        except (OSError, ValueError):
            mismatched.append(rel)
            continue
        if not target.is_file():
            missing.append(rel)
            continue
        try:
            actual_sha = digest(target.read_bytes())
        except OSError:
            mismatched.append(rel)
            continue
        if actual_sha != expected_sha:
            mismatched.append(rel)
    return missing, mismatched


def _meta_marks_unpublishable(parsed_meta: dict[str, Any]) -> bool:
    """Return True if metadata explicitly declares an unpublishable or non-COMPLETED job state."""
    return (
        parsed_meta.get("publishable") is False
        or str(parsed_meta.get("job_state") or "").strip().upper() in ("FAILED", "RUNNING", "QUEUED", "ERROR", "FINALIZING")
        or bool(parsed_meta.get("error_code"))
    )


def _check_sealed_commit_meta_binding(
    *,
    owner_job_id: str,
    owner_job_doc: dict[str, Any],
    sealed_commit: dict[str, Any],
    parsed_meta: dict[str, Any],
) -> tuple[bool | None, ManagedCommitCheck | None]:
    """Validate that a metadata document whose SHA-256 matches `sealed_commit.meta_sha256` actually sealed
    a valid publishable completed scan for `owner_job_id` (rejecting forged commits that seal unpublishable
    or mismatched pre-commit metadata as `INCOMPLETE_COMMIT`)."""
    if _meta_marks_unpublishable(parsed_meta):
        return None, ManagedCommitCheck(False, "INCOMPLETE_COMMIT", "metadata marks scan unpublishable or non-COMPLETED")
    raw_meta_jid = parsed_meta.get("job_id")
    if not isinstance(raw_meta_jid, str) or raw_meta_jid.strip() != owner_job_id:
        return None, ManagedCommitCheck(False, "INCOMPLETE_COMMIT", "metadata job_id mismatch")
    commit_scan_id = str(sealed_commit["scan_id"]).strip()
    raw_sid = parsed_meta.get("scan_id")
    if not isinstance(raw_sid, str) or raw_sid.strip() != commit_scan_id:
        return None, ManagedCommitCheck(False, "INCOMPLETE_COMMIT", "metadata scan_id mismatch")
    if parsed_meta.get("scan_sha256") != sealed_commit["scan_sha256"]:
        return None, ManagedCommitCheck(False, "INCOMPLETE_COMMIT", "metadata scan_sha256 mismatch")
    no_llm, mode_err = _resolve_managed_no_llm_mode(owner_job_doc, parsed_meta, sealed_commit)
    if no_llm is None:
        return None, ManagedCommitCheck(False, "INCOMPLETE_COMMIT", mode_err or "invalid no_llm mode")
    return no_llm, None


def _post_commit_failure_marker_check(scan_dir: Path) -> ManagedCommitCheck | None:
    """After a sealed v2 commit and its sealed artifacts have been authenticated, any `api-scan-failure.json`
    on disk is a post-commit integrity anomaly and MUST NEVER negate the sealed commit into `INCOMPLETE_COMMIT`."""
    marker_exists, marker_is_post_commit, marker_reason = _inspect_failure_marker(scan_dir)
    if not marker_exists:
        return None
    if marker_is_post_commit:
        return ManagedCommitCheck(
            False,
            "ARTIFACT_INTEGRITY_FAILED",
            marker_reason or "post-commit artifact integrity failure marker present",
            mismatched_artifacts=("api-scan-failure.json",),
        )
    return ManagedCommitCheck(
        False,
        "ARTIFACT_INTEGRITY_FAILED",
        f"unexpected failure marker api-scan-failure.json present on sealed committed scan ({marker_reason or 'untrusted marker'})",
        mismatched_artifacts=("api-scan-failure.json",),
    )


def inspect_managed_job_commit(
    *,
    scan_dir: Path,
    triage_dir: Path,
    parsed_meta: dict[str, Any],
    meta_raw_bytes: bytes,
    owner_job_id: str,
    owner_job_doc: dict[str, Any],
    scan_sha: str,
    warning_count: int,
    assessments_path: Path | None,
    jobs_dir: Path | None,
    in_managed_root: bool = True,
) -> ManagedCommitCheck:
    """Single authoritative commit & artifact-contract verifier shared by ScanJobManager and TriageApiService."""
    sealed_commit, is_revoked_integrity, _ = _extract_sealed_v2_commit(owner_job_doc, owner_job_id)
    if sealed_commit is not None:
        c_sid = str(sealed_commit["scan_id"]).strip()
        c_dir = str(sealed_commit.get("scan_dir") or owner_job_id).strip()
        if _has_conflicting_job_owner(
            jobs_dir,
            owner_job_id=owner_job_id,
            scan_id=c_sid,
            scan_dir_name=c_dir if in_managed_root else None,
        ):
            return ManagedCommitCheck(False, "INCOMPLETE_COMMIT", "conflicting job owner for scan_id or scan_dir")
    if is_revoked_integrity and sealed_commit is not None:
        return _revoked_integrity_check_from_job_doc(owner_job_doc)

    has_sealed_commit = sealed_commit is not None
    # Only pre-commit / legacy jobs lacking a verified sealed v2 commit may be immediately classified as
    # `INCOMPLETE_COMMIT` from a mutable on-disk `api-scan-failure.json` marker.
    if not has_sealed_commit:
        marker_exists, _, _ = _inspect_failure_marker(scan_dir)
        if marker_exists:
            return ManagedCommitCheck(False, "INCOMPLETE_COMMIT", "failure marker present")

    if not isinstance(owner_job_doc, dict) or not isinstance(parsed_meta, dict):
        return ManagedCommitCheck(False, "INCOMPLETE_COMMIT", "invalid job or metadata object")
    if owner_job_doc.get("job_id") != owner_job_id:
        return ManagedCommitCheck(False, "INCOMPLETE_COMMIT", "owner job_id mismatch")
    if owner_job_doc.get("state") != "COMPLETED" or owner_job_doc.get("finalizing") is True:
        return ManagedCommitCheck(False, "INCOMPLETE_COMMIT", "owner job is not COMPLETED")
    if owner_job_doc.get("error_code"):
        return ManagedCommitCheck(False, "INCOMPLETE_COMMIT", "owner job carries error_code")

    # Branch 1: v2 single-commit-point contract (`commit_authority="job_record"` or `commit` object on job record)
    is_v2_commit = (
        parsed_meta.get("commit_authority") == "job_record"
        or parsed_meta.get("schema") == MANAGED_META_SCHEMA
        or "commit" in owner_job_doc
    )
    if is_v2_commit:
        commit_obj, commit_err = _validate_sealed_v2_commit_structure(
            owner_job_doc.get("commit"),
            owner_job_id=owner_job_id,
            owner_job_doc=owner_job_doc,
            is_revoked=False,
        )
        if commit_obj is None:
            return ManagedCommitCheck(False, "INCOMPLETE_COMMIT", commit_err or "invalid commit object")

        commit_scan_id = str(commit_obj["scan_id"]).strip()
        commit_scan_sha = str(commit_obj["scan_sha256"])
        if _has_conflicting_job_owner(
            jobs_dir,
            owner_job_id=owner_job_id,
            scan_id=commit_scan_id,
            scan_dir_name=owner_job_id if in_managed_root else None,
        ):
            return ManagedCommitCheck(False, "INCOMPLETE_COMMIT", "conflicting job owner for scan_id or scan_dir")

        # Once `commit_obj` itself is verified structurally sealed and non-conflicting, verify the
        # sealed metadata SHA-256 FIRST before inspecting mutable fields inside `parsed_meta`.
        # Tampering `api-scan-meta.json` (e.g. setting `"publishable": false` or `"job_state": "FINALIZING"`)
        # MUST NEVER allow on-disk metadata to negate an existing sealed commit!
        expected_meta_sha = commit_obj["meta_sha256"]
        if digest(meta_raw_bytes) != expected_meta_sha:
            return ManagedCommitCheck(
                False,
                "ARTIFACT_INTEGRITY_FAILED",
                "api-scan-meta.json hash does not match commit.meta_sha256",
                mismatched_artifacts=("api-scan-meta.json",),
            )
        # If the sealed bytes themselves match `meta_sha256` yet mark the scan unpublishable/non-COMPLETED
        # or mismatch owner identity, the commit record itself never sealed a valid completed scan -> INCOMPLETE_COMMIT.
        no_llm, meta_bind_err = _check_sealed_commit_meta_binding(
            owner_job_id=owner_job_id,
            owner_job_doc=owner_job_doc,
            sealed_commit=commit_obj,
            parsed_meta=parsed_meta,
        )
        if meta_bind_err is not None or no_llm is None:
            return meta_bind_err or ManagedCommitCheck(False, "INCOMPLETE_COMMIT", "invalid sealed metadata binding")
        if scan_sha != commit_scan_sha:
            return ManagedCommitCheck(
                False,
                "ARTIFACT_INTEGRITY_FAILED",
                "review.sqlite scan_sha256 does not match sealed commit.scan_sha256",
                mismatched_artifacts=("triage/review.sqlite",),
            )

        commit_hashes = commit_obj["artifact_sha256s"]
        meta_hashes = parsed_meta.get("artifact_sha256s")
        if not isinstance(meta_hashes, dict) or commit_hashes != meta_hashes:
            return ManagedCommitCheck(
                False,
                "ARTIFACT_INTEGRITY_FAILED",
                "artifact_sha256s mismatched between commit and metadata",
                mismatched_artifacts=("api-scan-meta.json",),
            )

        # Verify all sealed artifacts on disk + mutable review.sqlite
        missing_disk, mismatched_disk = _verify_sealed_artifact_hashes_on_disk(scan_dir, commit_hashes)
        if not (triage_dir / "review.sqlite").is_file():
            missing_disk.append("triage/review.sqlite")
        if missing_disk or mismatched_disk:
            return ManagedCommitCheck(
                False,
                "ARTIFACT_INTEGRITY_FAILED",
                f"sealed artifacts missing={missing_disk} mismatched={mismatched_disk}",
                missing_artifacts=tuple(sorted(set(missing_disk))),
                mismatched_artifacts=tuple(sorted(set(mismatched_disk))),
            )

        if assessments_path is None or not assessments_path.is_file():
            return ManagedCommitCheck(
                False,
                "ARTIFACT_INTEGRITY_FAILED",
                "triage/assessments.jsonl missing",
                missing_artifacts=("triage/assessments.jsonl",),
            )
        row_cnt = _count_nonempty_jsonl_lines(assessments_path)
        if row_cnt is None or row_cnt != warning_count:
            return ManagedCommitCheck(
                False,
                "ARTIFACT_INTEGRITY_FAILED",
                "triage/assessments.jsonl line count mismatches SQLite warning count",
                mismatched_artifacts=("triage/assessments.jsonl",),
            )

        # Structural sanity of sealed JSON artifacts (evidence, scan-manifest, and LLM protocol/http checks)
        try:
            ev_doc = strict_json((triage_dir / "evidence.json").read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, EvidenceError):
            return ManagedCommitCheck(False, "ARTIFACT_INTEGRITY_FAILED", "corrupt triage/evidence.json", mismatched_artifacts=("triage/evidence.json",))
        if (
            not isinstance(ev_doc, dict)
            or ev_doc.get("scan_sha256") != scan_sha
            or not isinstance(ev_doc.get("records"), list)
            or len(ev_doc["records"]) != warning_count
        ):
            return ManagedCommitCheck(False, "ARTIFACT_INTEGRITY_FAILED", "triage/evidence.json identity/count mismatch", mismatched_artifacts=("triage/evidence.json",))

        try:
            man_doc = strict_json((scan_dir / "capture" / "scan-manifest.json").read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, EvidenceError):
            return ManagedCommitCheck(False, "ARTIFACT_INTEGRITY_FAILED", "corrupt capture/scan-manifest.json", mismatched_artifacts=("capture/scan-manifest.json",))
        if not isinstance(man_doc, dict) or man_doc.get("success") is not True:
            return ManagedCommitCheck(False, "ARTIFACT_INTEGRITY_FAILED", "capture/scan-manifest.json success!=True", mismatched_artifacts=("capture/scan-manifest.json",))

        if not no_llm:
            for llm_rel in MANAGED_LLM_SEALED_ARTIFACTS:
                try:
                    llm_doc = strict_json((scan_dir / llm_rel).read_text(encoding="utf-8"))
                except (OSError, UnicodeDecodeError, EvidenceError):
                    return ManagedCommitCheck(False, "ARTIFACT_INTEGRITY_FAILED", f"corrupt {llm_rel}", mismatched_artifacts=(llm_rel,))
                if not isinstance(llm_doc, dict):
                    return ManagedCommitCheck(False, "ARTIFACT_INTEGRITY_FAILED", f"non-object {llm_rel}", mismatched_artifacts=(llm_rel,))

        # A valid committed scan never carries `api-scan-failure.json` at commit time. If a failure marker
        # appears on disk post-commit (regardless of its mutable classification or syntax), fail closed as
        # `ARTIFACT_INTEGRITY_FAILED` so sealed commit identity and provenance are preserved.
        marker_chk = _post_commit_failure_marker_check(scan_dir)
        if marker_chk is not None:
            return marker_chk

        return ManagedCommitCheck(True, "VALID", "ok")

    if _meta_marks_unpublishable(parsed_meta):
        return ManagedCommitCheck(False, "INCOMPLETE_COMMIT", "metadata marks scan unpublishable or non-COMPLETED")

    raw_meta_jid = parsed_meta.get("job_id")
    if not isinstance(raw_meta_jid, str) or raw_meta_jid.strip() != owner_job_id:
        return ManagedCommitCheck(False, "INCOMPLETE_COMMIT", "metadata job_id mismatch")
    raw_sid = parsed_meta.get("scan_id")
    if not isinstance(raw_sid, str) or not raw_sid.strip():
        return ManagedCommitCheck(False, "INCOMPLETE_COMMIT", "missing metadata scan_id")
    meta_scan_id = raw_sid.strip()
    if not TriageApiService._is_sha256_hex(parsed_meta.get("scan_sha256")) or parsed_meta["scan_sha256"] != scan_sha:
        return ManagedCommitCheck(False, "INCOMPLETE_COMMIT", "metadata scan_sha256 mismatch")

    job_sid = owner_job_doc.get("scan_id")
    if job_sid is not None and job_sid != meta_scan_id:
        return ManagedCommitCheck(False, "INCOMPLETE_COMMIT", "job scan_id mismatch")
    job_sha = owner_job_doc.get("scan_sha256")
    if job_sha is not None and job_sha != scan_sha:
        return ManagedCommitCheck(False, "INCOMPLETE_COMMIT", "job scan_sha256 mismatch")

    if _has_conflicting_job_owner(
        jobs_dir,
        owner_job_id=owner_job_id,
        scan_id=meta_scan_id,
        scan_dir_name=owner_job_id if in_managed_root else None,
    ):
        return ManagedCommitCheck(False, "INCOMPLETE_COMMIT", "conflicting job owner for scan_id or scan_dir")

    # Branch 2: v1 `publishable` metadata schema (explicit backward-compatibility policy for pre-v2 scans)
    if "publishable" in parsed_meta:
        if parsed_meta.get("publishable") is not True:
            return ManagedCommitCheck(False, "INCOMPLETE_COMMIT", "v1 metadata publishable!=True")
        raw_js = parsed_meta.get("job_state")
        if not isinstance(raw_js, str) or raw_js.strip().upper() != "COMPLETED":
            return ManagedCommitCheck(False, "INCOMPLETE_COMMIT", "v1 metadata job_state!=COMPLETED")
        if assessments_path is None or not assessments_path.is_file():
            return ManagedCommitCheck(False, "ARTIFACT_INTEGRITY_FAILED", "v1 assessments.jsonl missing", missing_artifacts=("triage/assessments.jsonl",))
        row_cnt = _count_nonempty_jsonl_lines(assessments_path)
        if row_cnt is None or row_cnt != warning_count:
            return ManagedCommitCheck(False, "ARTIFACT_INTEGRITY_FAILED", "v1 assessments.jsonl row count mismatch", mismatched_artifacts=("triage/assessments.jsonl",))
        if isinstance(parsed_meta.get("artifact_sha256s"), dict):
            miss_v1, mis_v1 = _verify_sealed_artifact_hashes_on_disk(scan_dir, parsed_meta["artifact_sha256s"])
            if miss_v1 or mis_v1:
                return ManagedCommitCheck(
                    False,
                    "ARTIFACT_INTEGRITY_FAILED",
                    f"v1 sealed artifacts missing={miss_v1} mismatched={mis_v1}",
                    missing_artifacts=tuple(miss_v1),
                    mismatched_artifacts=tuple(mis_v1),
                )
        return ManagedCommitCheck(True, "VALID", "ok_v1_legacy")

    # Branch 3: Legacy baseline schema (lacking `publishable` and `commit_authority`)
    ok_legacy = _verify_legacy_completed_meta(
        scan_dir,
        triage_dir,
        parsed_meta,
        scan_sha,
        warning_count,
        assessments_path,
        jobs_dir,
    )
    if not ok_legacy:
        return ManagedCommitCheck(False, "INCOMPLETE_COMMIT", "legacy metadata verification failed")
    if isinstance(parsed_meta.get("artifact_sha256s"), dict):
        miss_lg, mis_lg = _verify_sealed_artifact_hashes_on_disk(scan_dir, parsed_meta["artifact_sha256s"])
        if miss_lg or mis_lg:
            return ManagedCommitCheck(
                False,
                "ARTIFACT_INTEGRITY_FAILED",
                f"legacy sealed artifacts missing={miss_lg} mismatched={mis_lg}",
                missing_artifacts=tuple(miss_lg),
                mismatched_artifacts=tuple(mis_lg),
            )
    return ManagedCommitCheck(True, "VALID", "ok_legacy")


def verify_managed_job_commit(
    *,
    scan_dir: Path,
    triage_dir: Path,
    parsed_meta: dict[str, Any],
    meta_raw_bytes: bytes,
    owner_job_id: str,
    owner_job_doc: dict[str, Any],
    scan_sha: str,
    warning_count: int,
    assessments_path: Path | None,
    jobs_dir: Path | None,
    in_managed_root: bool = True,
) -> bool:
    """Boolean wrapper over single authoritative `inspect_managed_job_commit`."""
    return inspect_managed_job_commit(
        scan_dir=scan_dir,
        triage_dir=triage_dir,
        parsed_meta=parsed_meta,
        meta_raw_bytes=meta_raw_bytes,
        owner_job_id=owner_job_id,
        owner_job_doc=owner_job_doc,
        scan_sha=scan_sha,
        warning_count=warning_count,
        assessments_path=assessments_path,
        jobs_dir=jobs_dir,
        in_managed_root=in_managed_root,
    ).ok


def inspect_managed_job_dir_committed(
    *,
    scan_dir: Path,
    owner_job_id: str,
    owner_job_doc: dict[str, Any],
    jobs_dir: Path | None,
) -> ManagedCommitCheck:
    """Authoritative on-disk commit & artifact integrity check shared by ScanJobManager (live + recovery) and TriageApiService."""
    sealed_commit, is_revoked_integrity, _ = _extract_sealed_v2_commit(owner_job_doc, owner_job_id)
    if sealed_commit is not None:
        c_sid = str(sealed_commit["scan_id"]).strip()
        c_dir = str(sealed_commit.get("scan_dir") or owner_job_id).strip()
        if _has_conflicting_job_owner(
            jobs_dir,
            owner_job_id=owner_job_id,
            scan_id=c_sid,
            scan_dir_name=c_dir,
        ):
            return ManagedCommitCheck(False, "INCOMPLETE_COMMIT", "conflicting job owner for scan_id or scan_dir")
    if is_revoked_integrity and sealed_commit is not None:
        return _revoked_integrity_check_from_job_doc(owner_job_doc)

    has_sealed_commit = sealed_commit is not None
    if not scan_dir.is_dir():
        return ManagedCommitCheck(
            False,
            "ARTIFACT_INTEGRITY_FAILED" if has_sealed_commit else "INCOMPLETE_COMMIT",
            "scan directory missing on disk",
            missing_artifacts=("scan_dir",),
        )
    # Only pre-commit / legacy jobs lacking a verified sealed v2 commit may be short-circuited by
    # a mutable on-disk `api-scan-failure.json` marker. Sealed committed scans MUST verify sealed
    # metadata and artifacts FIRST so a forged/unexpected failure marker can never negate commit history.
    if not has_sealed_commit:
        marker_exists, _, _ = _inspect_failure_marker(scan_dir)
        if marker_exists:
            return ManagedCommitCheck(False, "INCOMPLETE_COMMIT", "failure marker present")

    triage_dir = scan_dir / "triage"
    db_path = triage_dir / "review.sqlite"
    ev_path = triage_dir / "evidence.json"
    meta_path = scan_dir / "api-scan-meta.json"
    assessments_path = triage_dir / "assessments.jsonl"

    if not meta_path.is_file():
        return ManagedCommitCheck(
            False,
            "ARTIFACT_INTEGRITY_FAILED" if has_sealed_commit else "INCOMPLETE_COMMIT",
            "api-scan-meta.json missing",
            missing_artifacts=("api-scan-meta.json",),
        )
    try:
        meta_raw_bytes = meta_path.read_bytes()
        parsed_meta = strict_json(meta_raw_bytes.decode("utf-8"))
    except (OSError, UnicodeDecodeError, EvidenceError):
        return ManagedCommitCheck(
            False,
            "ARTIFACT_INTEGRITY_FAILED" if has_sealed_commit else "INCOMPLETE_COMMIT",
            "api-scan-meta.json unreadable or corrupt",
            mismatched_artifacts=("api-scan-meta.json",),
        )
    if not isinstance(parsed_meta, dict):
        return ManagedCommitCheck(
            False,
            "ARTIFACT_INTEGRITY_FAILED" if has_sealed_commit else "INCOMPLETE_COMMIT",
            "api-scan-meta.json must be JSON object",
            mismatched_artifacts=("api-scan-meta.json",),
        )

    # Verify sealed commit's `meta_sha256` FIRST before trusting any mutable field inside `parsed_meta`.
    # Tampering `api-scan-meta.json` (including `"publishable": false`, `"job_state": "FINALIZING"`, or
    # `"error_code"`) MUST be classified as `ARTIFACT_INTEGRITY_FAILED`, never `INCOMPLETE_COMMIT`.
    if has_sealed_commit and sealed_commit is not None:
        if digest(meta_raw_bytes) != sealed_commit.get("meta_sha256"):
            return ManagedCommitCheck(
                False,
                "ARTIFACT_INTEGRITY_FAILED",
                "api-scan-meta.json hash does not match commit.meta_sha256",
                mismatched_artifacts=("api-scan-meta.json",),
            )
        # If the sealed bytes match `meta_sha256` yet seal an unpublishable/mismatched metadata document
        # (e.g., forged commit over a pre-commit failure), classify as `INCOMPLETE_COMMIT`.
        _, meta_bind_err = _check_sealed_commit_meta_binding(
            owner_job_id=owner_job_id,
            owner_job_doc=owner_job_doc,
            sealed_commit=sealed_commit,
            parsed_meta=parsed_meta,
        )
        if meta_bind_err is not None:
            return meta_bind_err
    elif _meta_marks_unpublishable(parsed_meta):
        return ManagedCommitCheck(False, "INCOMPLETE_COMMIT", "metadata marks scan unpublishable or non-COMPLETED")

    missing_core = [
        rel
        for rel, fp in (
            ("triage/review.sqlite", db_path),
            ("triage/evidence.json", ev_path),
            ("triage/assessments.jsonl", assessments_path),
        )
        if not fp.is_file()
    ]
    if missing_core:
        return ManagedCommitCheck(
            False,
            "ARTIFACT_INTEGRITY_FAILED" if has_sealed_commit else "INCOMPLETE_COMMIT",
            f"missing core triage artifacts: {missing_core}",
            missing_artifacts=tuple(missing_core),
        )

    expected_sha = sealed_commit["scan_sha256"] if (has_sealed_commit and sealed_commit is not None) else owner_job_doc.get("scan_sha256")
    if not TriageApiService._is_sha256_hex(expected_sha):
        expected_sha = parsed_meta.get("scan_sha256")
    if not TriageApiService._is_sha256_hex(expected_sha):
        return ManagedCommitCheck(False, "INCOMPLETE_COMMIT", "missing valid scan_sha256")
    try:
        with _open_ro_sqlite(db_path) as conn:
            row = conn.execute("SELECT id FROM scans WHERE id=?", (expected_sha,)).fetchone()
            if row is None or not row["id"]:
                return ManagedCommitCheck(
                    False,
                    "ARTIFACT_INTEGRITY_FAILED" if has_sealed_commit else "INCOMPLETE_COMMIT",
                    "expected scan_sha256 missing in review.sqlite",
                    mismatched_artifacts=("triage/review.sqlite",),
                )
            scan_sha = str(row["id"])
            cnt_row = conn.execute("SELECT COUNT(*) FROM warnings WHERE scan_id=?", (scan_sha,)).fetchone()
            warning_count = int(cnt_row[0]) if cnt_row is not None else 0
    except (OSError, sqlite3.Error):
        return ManagedCommitCheck(
            False,
            "ARTIFACT_INTEGRITY_FAILED" if has_sealed_commit else "INCOMPLETE_COMMIT",
            "review.sqlite unreadable or corrupt",
            mismatched_artifacts=("triage/review.sqlite",),
        )
    return inspect_managed_job_commit(
        scan_dir=scan_dir,
        triage_dir=triage_dir,
        parsed_meta=parsed_meta,
        meta_raw_bytes=meta_raw_bytes,
        owner_job_id=owner_job_id,
        owner_job_doc=owner_job_doc,
        scan_sha=scan_sha,
        warning_count=warning_count,
        assessments_path=assessments_path,
        jobs_dir=jobs_dir,
        in_managed_root=True,
    )


def verify_managed_job_dir_committed(
    *,
    scan_dir: Path,
    owner_job_id: str,
    owner_job_doc: dict[str, Any],
    jobs_dir: Path | None,
) -> bool:
    """Boolean wrapper over `inspect_managed_job_dir_committed`."""
    return inspect_managed_job_dir_committed(
        scan_dir=scan_dir,
        owner_job_id=owner_job_id,
        owner_job_doc=owner_job_doc,
        jobs_dir=jobs_dir,
    ).ok


def _classify_candidate_is_managed(
    candidate: Path,
    parsed_meta: dict[str, Any] | None,
    managed_scans_root: Path | None,
    jobs_dir: Path | None,
    *,
    triage_dir: Path | None = None,
    managed_aliases: dict[Path, list[str]] | None = None,
) -> tuple[bool, bool]:
    """Identify API-managed scan directories via lexical/resolved paths, junctions, `triage/` parent, job records, and metadata.

    Returns `(is_managed, is_inside_managed_root)`.
    """
    cand_variants, cand_err = _candidate_path_variants(candidate, triage_dir=triage_dir)
    root_variants, root_err = _managed_root_variants(managed_scans_root)
    if cand_err or root_err:
        return True, True

    in_managed_root = _is_within_managed_scans_root(cand_variants, root_variants)
    if in_managed_root:
        return True, True

    if managed_aliases:
        for c_var in cand_variants:
            if c_var in managed_aliases:
                return True, True

    if jobs_dir is not None and jobs_dir.is_dir():
        for c_var in cand_variants:
            if c_var.name and (jobs_dir / f"{c_var.name}.json").is_file():
                return True, False

    if (candidate / "triage").is_dir() and (candidate / "api-scan-failure.json").is_file():
        return True, False
    if triage_dir == candidate:
        if (_lexical_abs_path(candidate).parent / "api-scan-failure.json").is_file():
            return True, False
        try:
            if (candidate.resolve().parent / "api-scan-failure.json").is_file():
                return True, False
        except OSError:
            return True, True

    if _meta_has_managed_markers(parsed_meta):
        return True, False
    return False, False


def _verify_legacy_completed_meta(
    candidate: Path,
    triage_dir: Path,
    parsed_meta: dict[str, Any],
    scan_sha: str,
    warning_count: int,
    assessments_path: Path | None,
    jobs_dir: Path | None,
) -> bool:
    """Verify baseline-commit `api-scan-meta.json` (lacking `publishable`) via completion & artifact integrity proof."""
    if not isinstance(parsed_meta, dict):
        return False
    if str(parsed_meta.get("job_state") or "").upper() in ("FAILED", "RUNNING", "QUEUED", "ERROR"):
        return False
    if parsed_meta.get("error_code"):
        return False
    scan_id_val = parsed_meta.get("scan_id")
    job_id_val = parsed_meta.get("job_id")
    if not isinstance(scan_id_val, str) or not scan_id_val.strip():
        return False
    if not isinstance(job_id_val, str) or not job_id_val.strip():
        return False
    if not TriageApiService._is_sha256_hex(parsed_meta.get("scan_sha256")) or parsed_meta["scan_sha256"] != scan_sha:
        return False
    if not _is_valid_iso_tz(parsed_meta.get("completed_at")):
        return False
    st = parsed_meta.get("stage_statuses")
    if not isinstance(st, dict):
        return False
    if (
        st.get("scanner_status") != "OK"
        or st.get("json_sarif_parity_status") != "MATCHED"
        or st.get("queue_status") != "OPEN_READY"
    ):
        return False

    if jobs_dir is not None:
        job_file = jobs_dir / f"{job_id_val}.json"
        if jobs_dir.is_dir() and not job_file.is_file():
            return False
        if job_file.is_file():
            try:
                job_doc = json.loads(job_file.read_text(encoding="utf-8"))
                if not isinstance(job_doc, dict) or job_doc.get("state") != "COMPLETED":
                    return False
            except (OSError, ValueError):
                return False

    if assessments_path is None or not assessments_path.is_file():
        return False
    row_cnt = _count_nonempty_jsonl_lines(assessments_path)
    if row_cnt is None or row_cnt != warning_count:
        return False

    ev_path = triage_dir / "evidence.json"
    try:
        ev_doc = strict_json(ev_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, EvidenceError):
        return False
    if (
        not isinstance(ev_doc, dict)
        or ev_doc.get("scan_sha256") != scan_sha
        or not isinstance(ev_doc.get("records"), list)
        or len(ev_doc["records"]) != warning_count
    ):
        return False

    og_capture_json = candidate / "capture" / "opengrep.json"
    og_triage_json = triage_dir / "input.opengrep.json"
    raw_og_path = og_capture_json if og_capture_json.is_file() else (og_triage_json if og_triage_json.is_file() else None)
    if raw_og_path is None:
        return False
    try:
        if digest(raw_og_path.read_bytes()) != scan_sha:
            return False
    except OSError:
        return False

    og_manifest = candidate / "capture" / "scan-manifest.json"
    if og_manifest.is_file():
        try:
            man_doc = strict_json(og_manifest.read_text(encoding="utf-8"))
            if not isinstance(man_doc, dict) or man_doc.get("success") is not True:
                return False
        except (OSError, UnicodeDecodeError, EvidenceError):
            return False

    return True


def _inspect_candidate_dir(
    candidate: Path,
    *,
    writable: bool,
    managed_scans_root: Path | None = None,
    jobs_dir: Path | None = None,
    managed_aliases: dict[Path, list[str]] | None = None,
    include_integrity_failed: bool = False,
) -> DiscoveredScan | None:
    if not candidate.is_dir():
        return None
    if managed_aliases is None:
        managed_aliases = _collect_managed_scan_aliases(managed_scans_root)

    effective_base = candidate
    if (candidate / "triage" / "review.sqlite").is_file() and (candidate / "triage" / "evidence.json").is_file():
        triage_dir = candidate / "triage"
    elif (candidate / "review.sqlite").is_file() and (candidate / "evidence.json").is_file():
        triage_dir = candidate
        # If `candidate` directly accesses a managed scan's `triage/` directory (or a junction to it),
        # preserve the parent scan's managed status rather than treating it as an unmanaged external scan!
        parent_managed = _find_parent_managed_scan_dir(
            candidate,
            managed_scans_root=managed_scans_root,
            jobs_dir=jobs_dir,
            managed_aliases=managed_aliases,
        )
        if parent_managed is not None:
            effective_base = parent_managed
    else:
        return None

    meta_path = effective_base / "api-scan-meta.json"
    explicit_id = None
    parsed_meta: dict[str, Any] | None = None
    meta_raw_bytes: bytes | None = None
    meta_unreadable_or_nondict = False
    if meta_path.is_file():
        try:
            meta_raw_bytes = meta_path.read_bytes()
            meta = strict_json(meta_raw_bytes.decode("utf-8"))
        except (OSError, UnicodeDecodeError, EvidenceError):
            meta = None
            meta_unreadable_or_nondict = True
        if isinstance(meta, dict):
            parsed_meta = meta
            if isinstance(meta.get("scan_id"), str) and meta["scan_id"].strip():
                explicit_id = meta["scan_id"].strip()
        else:
            meta_unreadable_or_nondict = True

    is_managed, in_managed_root = _classify_candidate_is_managed(
        effective_base,
        parsed_meta,
        managed_scans_root,
        jobs_dir,
        triage_dir=triage_dir,
        managed_aliases=managed_aliases,
    )
    if effective_base != candidate:
        # Also verify lexical candidate path variants so junctions from/into managed root stay managed
        c_managed, c_in_root = _classify_candidate_is_managed(
            candidate,
            parsed_meta,
            managed_scans_root,
            jobs_dir,
            triage_dir=triage_dir,
            managed_aliases=managed_aliases,
        )
        is_managed = is_managed or c_managed
        in_managed_root = in_managed_root or c_in_root

    if not is_managed:
        if (
            (candidate / "api-scan-failure.json").exists()
            or (candidate / "api-scan-failure.json").is_symlink()
            or (effective_base / "api-scan-failure.json").exists()
            or (effective_base / "api-scan-failure.json").is_symlink()
        ):
            return None
        if triage_dir == candidate:
            lex_p_fail = _lexical_abs_path(candidate).parent / "api-scan-failure.json"
            if lex_p_fail.exists() or lex_p_fail.is_symlink():
                return None
            try:
                res_p_fail = candidate.resolve().parent / "api-scan-failure.json"
                if res_p_fail.exists() or res_p_fail.is_symlink():
                    return None
            except OSError:
                return None
        if isinstance(parsed_meta, dict) and _meta_marks_unpublishable(parsed_meta):
            return None

    assessments_path = triage_dir / "assessments.jsonl"
    if not assessments_path.is_file():
        assessments_path = None

    if is_managed:
        if meta_unreadable_or_nondict or not isinstance(parsed_meta, dict) or meta_raw_bytes is None:
            return None

    db_path = triage_dir / "review.sqlite"
    evidence_path = triage_dir / "evidence.json"
    try:
        with _open_ro_sqlite(db_path) as conn:
            row = conn.execute("SELECT id FROM scans ORDER BY rowid DESC LIMIT 1").fetchone()
            if row is None or not row["id"]:
                return None
            scan_sha = str(row["id"])
            cnt_row = conn.execute("SELECT COUNT(*) FROM warnings WHERE scan_id=?", (scan_sha,)).fetchone()
            warning_count = int(cnt_row[0]) if cnt_row is not None else 0
    except (OSError, sqlite3.Error):
        return None

    owner_job_id: str | None = None
    integrity_error: str | None = None
    if is_managed:
        assert parsed_meta is not None and meta_raw_bytes is not None
        cand_variants, cand_err = _candidate_path_variants(effective_base, triage_dir=triage_dir)
        if effective_base != candidate:
            extra_vars, extra_err = _candidate_path_variants(candidate, triage_dir=triage_dir)
            cand_err = cand_err or extra_err
            for ev in extra_vars:
                if ev not in cand_variants:
                    cand_variants.append(ev)
        root_variants, root_err = _managed_root_variants(managed_scans_root)
        if cand_err or root_err:
            return None

        raw_meta_jid = parsed_meta.get("job_id")
        if not isinstance(raw_meta_jid, str) or not raw_meta_jid.strip():
            return None
        meta_job_id = raw_meta_jid.strip()

        dir_owners = _collect_dir_owner_job_ids(
            cand_variants,
            root_variants,
            jobs_dir,
            managed_aliases=managed_aliases,
        )
        # Single authoritative owner invariant: directory/junction identity MUST NOT conflict with `meta.job_id`!
        if dir_owners and dir_owners != {meta_job_id}:
            return None
        owner_job_id = meta_job_id

        # Require the exact owning job record file `jobs/<owner_job_id>.json` to exist and prove valid commit!
        if jobs_dir is None or not jobs_dir.is_dir():
            return None
        owner_job_file = jobs_dir / f"{owner_job_id}.json"
        if not owner_job_file.is_file():
            return None
        try:
            owner_job_doc = strict_json(owner_job_file.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, EvidenceError):
            return None
        if not isinstance(owner_job_doc, dict):
            return None

        commit_chk = inspect_managed_job_commit(
            scan_dir=effective_base,
            triage_dir=triage_dir,
            parsed_meta=parsed_meta,
            meta_raw_bytes=meta_raw_bytes,
            owner_job_id=owner_job_id,
            owner_job_doc=owner_job_doc,
            scan_sha=scan_sha,
            warning_count=warning_count,
            assessments_path=assessments_path,
            jobs_dir=jobs_dir,
            in_managed_root=in_managed_root,
        )
        if commit_chk.ok and effective_base != candidate:
            extra_marker_dirs: list[Path] = [candidate]
            if triage_dir == candidate:
                lex_parent = _lexical_abs_path(candidate).parent
                if lex_parent != effective_base:
                    extra_marker_dirs.append(lex_parent)
            for mdir in extra_marker_dirs:
                extra_exists, _, extra_reason = _inspect_failure_marker(mdir)
                if extra_exists:
                    sealed_extra, _, _ = _extract_sealed_v2_commit(owner_job_doc, owner_job_id)
                    if sealed_extra is not None:
                        commit_chk = ManagedCommitCheck(
                            False,
                            "ARTIFACT_INTEGRITY_FAILED",
                            f"unexpected failure marker api-scan-failure.json present alongside scan path ({extra_reason or 'untrusted marker'})",
                            mismatched_artifacts=("api-scan-failure.json",),
                        )
                    else:
                        commit_chk = ManagedCommitCheck(False, "INCOMPLETE_COMMIT", "failure marker present")
                    break
        if not commit_chk.ok:
            if include_integrity_failed and commit_chk.status == "ARTIFACT_INTEGRITY_FAILED":
                sealed_for_id, _, _ = _extract_sealed_v2_commit(owner_job_doc, owner_job_id)
                if sealed_for_id is not None:
                    explicit_id = str(sealed_for_id["scan_id"]).strip()
                integrity_error = (
                    f"Artifact đã niêm phong của phiên quét {explicit_id or scan_sha!r} bị thiếu hoặc đã bị thay đổi "
                    f"sau commit ({commit_chk.reason})."
                )
            else:
                return None

    raw_json_path = triage_dir / "input.opengrep.json"
    if not raw_json_path.is_file():
        alt = effective_base / "capture" / "opengrep.json"
        raw_json_path = alt if alt.is_file() else None

    g1_manifest = effective_base / "g1-run-manifest.json"
    if not g1_manifest.is_file():
        g1_manifest = None

    return DiscoveredScan(
        scan_id=explicit_id or scan_sha,
        scan_sha256=scan_sha,
        base_dir=effective_base.resolve(),
        triage_dir=triage_dir.resolve(),
        db_path=db_path.resolve(),
        evidence_path=evidence_path.resolve(),
        assessments_path=assessments_path.resolve() if assessments_path else None,
        raw_json_path=raw_json_path.resolve() if raw_json_path else None,
        g1_manifest_path=g1_manifest.resolve() if g1_manifest else None,
        meta_path=meta_path.resolve() if meta_path.is_file() else None,
        writable=writable,
        candidate_dir=_lexical_abs_path(candidate),
        is_managed=is_managed,
        owner_job_id=owner_job_id,
        integrity_error=integrity_error,
    )


class TriageApiService:
    _JSONL_CACHE_MAX_ENTRIES = 32

    def __init__(self, config: ApiConfig):
        self.config = config
        self._review_lock = threading.RLock()
        self._jsonl_cache_lock = threading.Lock()
        self._jsonl_cache: dict[tuple[str, str], tuple[list[dict[str, Any]], bool]] = {}
        self._evidence_cache: dict[tuple[str, str], dict[str, Any]] = {}
        self._opengrep_probe = OpenGrepHealthProbe(config)

    def set_scan_busy_check(self, fn) -> None:
        self._opengrep_probe.set_scan_busy_check(fn)

    def start_opengrep_probe(self, *, force: bool = False) -> bool:
        return self._opengrep_probe.start_background_probe(force=force)

    def wait_for_opengrep_probe(self, timeout: float = 35.0) -> bool:
        return self._opengrep_probe.wait_for_probe(timeout=timeout)

    def shutdown_opengrep_probe(self, *, wait_seconds: float = 3.0) -> dict[str, Any]:
        return self._opengrep_probe.shutdown(wait_seconds=wait_seconds)

    def probe_opengrep(self, *, force: bool = False, trigger_refresh: bool = True) -> dict[str, Any]:
        """Return bounded active OpenGrep probe snapshot without blocking HTTP handlers on subprocesses."""
        return self._opengrep_probe.get_status(trigger_refresh=trigger_refresh, force=force)

    def notify_real_opengrep_scan_completed(self, *, engine_version: str | None = None) -> bool:
        """Inform health probe that a real Stage 2 OpenGrep scan completed cleanly (never fakes VERIFIED)."""
        return self._opengrep_probe.notify_real_scan_completed(engine_version=engine_version)

    def probe_ollama(self) -> dict[str, Any]:
        client = OllamaClient(
            endpoint=self.config.ollama_endpoint,
            model=self.config.ollama_model,
            timeout=min(2.5, self.config.ollama_timeout_seconds),
            runtime_origin=self.config.runtime_origin,
        )
        inv = client.verify_model_installed()
        reachable = bool(inv.get("reachable"))
        installed_list = inv.get("installed_models") or []
        return {
            "endpoint": self.config.ollama_endpoint,
            "requested_model": self.config.ollama_model,
            "runtime_origin": self.config.runtime_origin,
            "reachable": reachable,
            "model_installed": bool(inv.get("model_found")),
            "model_digest": inv.get("model_digest"),
            "installed_models_count": len(installed_list) if reachable else None,
            "error": inv.get("error"),
        }

    def health(self, *, authenticated: bool) -> dict[str, Any]:
        auth_required = bool(self.config.api_token and self.config.read_auth_mode == "required")
        if auth_required and not authenticated:
            return {
                "status": "AUTH_REQUIRED",
                "api_ready": True,
                "service": API_SERVICE_NAME,
                "api_version": API_VERSION,
                "contract_schema": API_CONTRACT_SCHEMA,
                "auth_required": True,
                "write_auth_required": True,
                "authenticated": False,
            }

        # Run non-locked external/OS checks FIRST so OpenGrepHealthProbe._lock is never held across
        # potentially slow Ollama HTTP calls, then commit the OpenGrep + rules readiness decision at
        # one atomic linearization point (`evaluate_readiness_snapshot`).
        ol = self.probe_ollama()
        git_path = shutil.which("git")
        og, rules_eval = self._opengrep_probe.evaluate_readiness_snapshot(trigger_refresh=True)
        rules_ok = bool(rules_eval.get("available"))
        rules_sha = rules_eval.get("sha256")

        # Defense-in-depth invariant guard: never emit OK or available=True if og/rules disagree.
        if og.get("available"):
            if (
                not rules_ok
                or not rules_sha
                or og.get("rules_sha256") != rules_sha
                or og.get("probe_status") != "VERIFIED"
                or not og.get("runtime_verified")
            ):
                og = dict(og)
                og["available"] = False
                og["runtime_verified"] = False
                og["probe_status"] = "NOT_VERIFIED"
                og["health_state"] = "NOT_VERIFIED"
                og["failure_code"] = "HEALTH_CONSISTENCY_GUARD"
                og["error"] = "Không thể xác nhận tính nhất quán giữa snapshot OpenGrep và tập luật tại thời điểm quyết định."

        degraded: list[str] = []
        if not og["available"]:
            p_stat = og.get("probe_status")
            if p_stat in ("NOT_VERIFIED", "EXPIRED"):
                degraded.append("OPENGREP_NOT_VERIFIED")
            elif p_stat == "TIMEOUT":
                degraded.append("OPENGREP_PROBE_TIMEOUT")
                degraded.append("OPENGREP_UNAVAILABLE")
            else:
                degraded.append("OPENGREP_UNAVAILABLE")
        if not rules_ok:
            degraded.append("RULES_UNAVAILABLE")
        if not ol["reachable"]:
            degraded.append("OLLAMA_UNREACHABLE")
        elif not ol["model_installed"]:
            degraded.append("QWEN_MODEL_NOT_INSTALLED")
        if not self.config.api_token:
            degraded.append("WRITE_AUTH_TOKEN_NOT_CONFIGURED")

        overall = "OK" if not degraded else "DEGRADED"
        return {
            "status": overall,
            "api_ready": True,
            "service": API_SERVICE_NAME,
            "api_version": API_VERSION,
            "contract_schema": API_CONTRACT_SCHEMA,
            "triage_schema_version": SCHEMA_VERSION,
            "prompt_version": PROMPT_VERSION,
            "prompt_contract": self.config.prompt_contract,
            "architecture": {
                "static_engine": "OpenGrep",
                "llm_engine": "Qwen3.5-9B via Local Ollama",
                "priority_cwes": ["CWE-22", "CWE-89"],
                "human_review_required": True,
                "stale_source_guard_enabled": True,
                "cloud_llm_enabled": False,
            },
            "auth_required": auth_required,
            "write_auth_required": True,
            "write_auth_configured": bool(self.config.api_token),
            "authenticated": authenticated,
            "degraded_reasons": degraded,
            "opengrep": og,
            "ollama": ol,
            "git_available": git_path is not None,
            "rules": {
                "available": rules_ok,
                "name": str(rules_eval.get("name") or self.config.rules_path.name),
                "sha256": rules_sha,
                "priority_cwes": ["CWE-22", "CWE-89"],
            },
            "source_inventory_limits": self.config.limits.to_dict(),
            "job_limits": {
                "max_concurrent_scans": self.config.max_concurrent_scans,
                "max_queued_jobs": self.config.max_queued_jobs,
                "job_timeout_seconds": self.config.job_timeout_seconds,
            },
            "checked_at": now(),
        }

    def _collect_committed_managed_integrity_tombstones(
        self,
        managed_scans_root: Path,
        jobs_dir: Path,
    ) -> list[DiscoveredScan]:
        """Collect reserved identities for managed jobs that reached a valid sealed v2 commit
        (whether still marked COMPLETED or revoked during restart recovery) whose artifacts are now
        missing or tampered.

        Reserving these identities BEFORE scanning other directories guarantees:
        - F2: No other scan with the same `scan_sha256` can hijack a committed `scan_id`, even when
          `assessments.jsonl`, `evidence.json`, `review.sqlite`, `api-scan-meta.json`, or the scan
          directory itself was deleted or altered.
        - F3: After restart recovery records `COMMITTED_ARTIFACT_TAMPERED_OR_MISSING` + `revoked_commit`,
          direct lookup of the committed `scan_id` continues to return `409 ARTIFACT_PROVENANCE_MISMATCH`
          instead of collapsing into `404 SCAN_NOT_FOUND`.
        """
        tombstones: list[DiscoveredScan] = []
        if not jobs_dir.is_dir():
            return tombstones
        try:
            job_files = sorted(jobs_dir.glob("*.json"))
        except OSError:
            return tombstones
        for jf in job_files:
            try:
                jdoc = strict_json(jf.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, EvidenceError):
                continue
            if not isinstance(jdoc, dict):
                continue
            jid = jdoc.get("job_id") if isinstance(jdoc.get("job_id"), str) and jdoc["job_id"].strip() else jf.stem
            commit_rec, _is_revoked, _ = _extract_sealed_v2_commit(jdoc, jid)
            if commit_rec is None:
                continue
            scan_dir_name = commit_rec.get("scan_dir") if isinstance(commit_rec.get("scan_dir"), str) and commit_rec["scan_dir"].strip() else jid
            scan_dir = managed_scans_root / scan_dir_name
            chk = inspect_managed_job_dir_committed(
                scan_dir=scan_dir,
                owner_job_id=jid,
                owner_job_doc=jdoc,
                jobs_dir=jobs_dir,
            )
            if chk.ok or chk.status != "ARTIFACT_INTEGRITY_FAILED":
                continue
            committed_sid = str(commit_rec["scan_id"]).strip()
            committed_sha = str(commit_rec["scan_sha256"])
            try:
                base_dir = scan_dir.resolve() if scan_dir.exists() else _lexical_abs_path(scan_dir)
            except OSError:
                base_dir = _lexical_abs_path(scan_dir)
            triage_dir = base_dir / "triage"
            meta_p = base_dir / "api-scan-meta.json"
            ass_p = triage_dir / "assessments.jsonl"
            tombstones.append(
                DiscoveredScan(
                    scan_id=committed_sid,
                    scan_sha256=committed_sha,
                    base_dir=base_dir,
                    triage_dir=triage_dir,
                    db_path=triage_dir / "review.sqlite",
                    evidence_path=triage_dir / "evidence.json",
                    assessments_path=ass_p if ass_p.is_file() else None,
                    raw_json_path=None,
                    g1_manifest_path=None,
                    meta_path=meta_p if meta_p.is_file() else None,
                    writable=True,
                    candidate_dir=_lexical_abs_path(scan_dir),
                    is_managed=True,
                    owner_job_id=jid,
                    integrity_error=(
                        f"Artifact đã niêm phong của phiên quét {committed_sid!r} (job {jid!r}) "
                        f"bị thiếu hoặc đã bị thay đổi sau commit ({chk.reason})."
                    ),
                )
            )
        return tombstones

    def discover_scans(self, *, include_integrity_failed: bool = False) -> list[DiscoveredScan]:
        found: dict[str, DiscoveredScan] = {}
        seen_dirs: set[Path] = set()
        managed_scans_root = self.config.data_dir / "scans"
        jobs_dir = self.config.data_dir / "jobs"
        managed_aliases = _collect_managed_scan_aliases(managed_scans_root)

        def _register(inspected: DiscoveredScan | None, child_name: str | None = None) -> None:
            if inspected is None or inspected.base_dir in seen_dirs:
                return
            seen_dirs.add(inspected.base_dir)
            if inspected.scan_id in found and inspected.base_dir != found[inspected.scan_id].base_dir:
                suffix = child_name or inspected.base_dir.name
                disambiguated = f"{inspected.scan_sha256[:16]}-{suffix}"
                inspected = DiscoveredScan(
                    **{**inspected.__dict__, "scan_id": disambiguated}
                )
            found.setdefault(inspected.scan_id, inspected)

        # Reserve committed managed identities whose post-commit artifacts failed integrity FIRST so
        # no other directory/import with identical scan_sha256 can ever hijack their scan_id.
        # Synchronize reading `jobs/*.json` under `acquire_publication_lock` (re-entrant RLock + OS lock)
        # so concurrent Windows readers never clash with `ScanJobManager`'s atomic `jobs/<id>.json` replace.
        with acquire_publication_lock(self.config.data_dir):
            tombstones = self._collect_committed_managed_integrity_tombstones(managed_scans_root, jobs_dir)
        for tomb in tombstones:
            _register(tomb, child_name=tomb.owner_job_id)

        def _looks_like_scan_dir(path: Path) -> bool:
            return (
                (path / "triage" / "review.sqlite").is_file()
                or (path / "review.sqlite").is_file()
                or (path / "api-scan-failure.json").is_file()
                or (path / "api-scan-meta.json").is_file()
            )

        def _scan_root(root: Path, *, writable: bool) -> None:
            if not root.exists() or not root.is_dir():
                return
            if _looks_like_scan_dir(root):
                direct = _inspect_candidate_dir(
                    root,
                    writable=writable,
                    managed_scans_root=managed_scans_root,
                    jobs_dir=jobs_dir,
                    managed_aliases=managed_aliases,
                    include_integrity_failed=True,
                )
                _register(direct)
                return
            try:
                children = sorted(root.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
            except OSError:
                return
            for child in children:
                if not child.is_dir():
                    continue
                inspected = _inspect_candidate_dir(
                    child,
                    writable=writable,
                    managed_scans_root=managed_scans_root,
                    jobs_dir=jobs_dir,
                    managed_aliases=managed_aliases,
                    include_integrity_failed=True,
                )
                _register(inspected, child_name=child.name)

        _scan_root(managed_scans_root, writable=True)
        for rw_dir in self.config.reviewable_scan_dirs:
            _scan_root(rw_dir, writable=True)
        for ro_dir in self.config.readonly_scan_dirs:
            _scan_root(ro_dir, writable=False)

        entries = list(found.values())
        if include_integrity_failed:
            return entries
        return [e for e in entries if e.integrity_error is None]

    def resolve_scan(self, scan_id: str) -> DiscoveredScan:
        if not isinstance(scan_id, str) or not scan_id.strip():
            raise ApiServiceError("INVALID_SCAN_ID", "Mã phiên quét không hợp lệ.", http_status=400)
        wanted = scan_id.strip()
        # Inspect once including post-commit integrity-failed committed scans so:
        # 1) A tampered committed scan still reserves its committed scan_id and cannot be hijacked by another
        #    directory/copy with the same scan_sha256.
        # 2) Direct resolution of an exact scan_id whose sealed artifacts were tampered/deleted fails closed
        #    with 409 ARTIFACT_PROVENANCE_MISMATCH instead of silently falling back to another scan by scan_sha256.
        all_scans = self.discover_scans(include_integrity_failed=True)
        for entry in all_scans:
            if entry.scan_id == wanted:
                if entry.integrity_error:
                    raise ApiServiceError("ARTIFACT_PROVENANCE_MISMATCH", entry.integrity_error, http_status=409)
                return entry
        integrity_match: DiscoveredScan | None = None
        for entry in all_scans:
            if entry.scan_sha256 == wanted:
                if entry.integrity_error is None:
                    return entry
                if integrity_match is None:
                    integrity_match = entry
        if integrity_match is not None and integrity_match.integrity_error:
            raise ApiServiceError("ARTIFACT_PROVENANCE_MISMATCH", integrity_match.integrity_error, http_status=409)
        raise ApiServiceError("SCAN_NOT_FOUND", f"Không tìm thấy phiên quét {wanted!r}.", http_status=404)

    def _query_audit_on_conn(
        self,
        conn: sqlite3.Connection,
        *,
        finding_id: str | None = None,
        descending: bool = False,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        order = "DESC" if descending else "ASC"
        if finding_id is not None:
            events_raw = [
                dict(r)
                for r in conn.execute(
                    f"SELECT * FROM events WHERE warning_id=? ORDER BY sequence {order}",
                    (finding_id,),
                ).fetchall()
            ]
            rejected_raw = (
                [
                    dict(r)
                    for r in conn.execute(
                        f"SELECT * FROM rejected_decisions WHERE warning_id=? ORDER BY sequence {order}",
                        (finding_id,),
                    ).fetchall()
                ]
                if _has_table(conn, "rejected_decisions")
                else []
            )
        else:
            events_raw = [
                dict(r)
                for r in conn.execute(f"SELECT * FROM events ORDER BY sequence {order}").fetchall()
            ]
            rejected_raw = (
                [
                    dict(r)
                    for r in conn.execute(f"SELECT * FROM rejected_decisions ORDER BY sequence {order}").fetchall()
                ]
                if _has_table(conn, "rejected_decisions")
                else []
            )

        events = [
            {
                **ev,
                "source_version_parsed": _parse_json_maybe(ev.get("source_version")),
                "observed_version_parsed": _parse_json_maybe(ev.get("observed_version")),
            }
            for ev in events_raw
        ]
        rejected = [
            {
                **rj,
                "source_version_parsed": _parse_json_maybe(rj.get("source_version")),
                "observed_version_parsed": _parse_json_maybe(rj.get("observed_version")),
                "detail_parsed": _parse_json_maybe(rj.get("detail")),
            }
            for rj in rejected_raw
        ]
        return events, rejected

    def _read_json_object_artifact(self, path: Path | None, label: str) -> dict[str, Any]:
        """Read an optional manifest/metadata JSON artifact strictly as a JSON object; fail closed with 409."""
        if not path or not path.is_file():
            return {}
        try:
            parsed = strict_json(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, EvidenceError) as exc:
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                f"Tệp {label} bị hỏng hoặc không đọc được: {exc}",
                http_status=409,
            ) from exc
        if not isinstance(parsed, dict):
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                f"Tệp {label} phải là đối tượng JSON hợp lệ.",
                http_status=409,
            )
        return parsed

    @staticmethod
    def _verify_meta_artifact_hashes(entry: DiscoveredScan, meta_doc: dict[str, Any]) -> None:
        hashes = meta_doc.get("artifact_sha256s")
        if not isinstance(hashes, dict):
            return
        base_resolved = entry.base_dir.resolve()
        for rel, expected_sha in hashes.items():
            if not isinstance(rel, str) or not rel or not isinstance(expected_sha, str) or not expected_sha:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    "Trường artifact_sha256s trong api-scan-meta.json không hợp lệ.",
                    http_status=409,
                )
            target = (base_resolved / rel).resolve()
            try:
                target.relative_to(base_resolved)
            except ValueError as exc:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Đường dẫn artifact {rel!r} trong api-scan-meta.json vượt phạm vi phiên quét.",
                    http_status=409,
                ) from exc
            if not target.is_file():
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Thiếu tệp chứng từ {rel!r} đã niêm phong trong api-scan-meta.json.",
                    http_status=409,
                )
            try:
                actual_sha = digest(target.read_bytes())
            except OSError as exc:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Không thể đọc tệp chứng từ {rel!r}: {exc}",
                    http_status=409,
                ) from exc
            if actual_sha != expected_sha:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Mã băm SHA-256 của tệp {rel!r} đã bị thay đổi so với api-scan-meta.json.",
                    http_status=409,
                )

    def _inspect_assessments_jsonl(
        self,
        assessments_path: Path,
        *,
        need_rows: bool = True,
    ) -> tuple[list[dict[str, Any]], bool]:
        """Strictly parse and type-check assessments.jsonl; fail-closed with 409 on corrupt or malformed rows.

        `_jsonl_cache` is ONLY a read-optimization cache keyed by `(resolved_path, file_bytes_sha256)` to avoid
        redundant JSONL parsing across repeated read endpoints; it does NOT serve as an authenticity/tamper
        check. Authoritative tamper detection happens against SQLite rows and `api-scan-meta.json` `artifact_sha256s`.
        """
        try:
            resolved_str = str(assessments_path.resolve(strict=True))
            raw_bytes = assessments_path.read_bytes()
        except OSError as exc:
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                f"Tệp assessments.jsonl không hợp lệ hoặc bị hỏng: {exc}",
                http_status=409,
            ) from exc

        cache_key = (resolved_str, digest(raw_bytes))
        with self._jsonl_cache_lock:
            cached = self._jsonl_cache.get(cache_key)
        if cached is not None:
            cached_rows, cached_mock = cached
            return (copy.deepcopy(cached_rows) if need_rows else []), cached_mock

        try:
            jsonl_text = raw_bytes.decode("utf-8")
            jsonl_rows = [strict_json(line) for line in jsonl_text.splitlines() if line.strip()]
        except (UnicodeDecodeError, EvidenceError) as exc:
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                f"Tệp assessments.jsonl không hợp lệ hoặc bị hỏng: {exc}",
                http_status=409,
            ) from exc

        has_mock_jsonl = False
        parsed_rows: list[dict[str, Any]] = []
        for idx, row in enumerate(jsonl_rows):
            if not isinstance(row, dict):
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Dòng #{idx + 1} trong assessments.jsonl phải là đối tượng JSON (object).",
                    http_status=409,
                )
            row_ass = row.get("assessment")
            row_ev = row.get("evidence")
            if not isinstance(row_ass, dict) or not isinstance(row_ev, dict):
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Dòng #{idx + 1} trong assessments.jsonl thiếu cấu trúc object hợp lệ cho evidence/assessment.",
                    http_status=409,
                )
            row_rt = row_ass.get("runtime")
            if row_rt is not None and not isinstance(row_rt, dict):
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Trường assessment.runtime ở dòng #{idx + 1} trong assessments.jsonl phải là object hoặc null.",
                    http_status=409,
                )
            row_cp = row_ass.get("citation_provenance")
            if row_cp is not None and not isinstance(row_cp, dict):
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Trường assessment.citation_provenance ở dòng #{idx + 1} trong assessments.jsonl phải là object hoặc null.",
                    http_status=409,
                )
            if "citations" in row_ass:
                row_cites = row_ass["citations"]
                if not isinstance(row_cites, list):
                    raise ApiServiceError(
                        "ARTIFACT_PROVENANCE_MISMATCH",
                        f"Trường assessment.citations ở dòng #{idx + 1} trong assessments.jsonl phải là danh sách (list).",
                        http_status=409,
                    )
                for c_idx, cite in enumerate(row_cites):
                    if not isinstance(cite, dict):
                        raise ApiServiceError(
                            "ARTIFACT_PROVENANCE_MISMATCH",
                            f"Phần tử citations[{c_idx}] ở dòng #{idx + 1} trong assessments.jsonl phải là object.",
                            http_status=409,
                        )
                    c_path = cite.get("path")
                    s_line = cite.get("start_line")
                    e_line = cite.get("end_line")
                    if (
                        not isinstance(c_path, str)
                        or not c_path.strip()
                        or type(s_line) is not int
                        or type(e_line) is not int
                        or s_line < 1
                        or e_line < s_line
                        or not isinstance(cite.get("quote"), str)
                        or not isinstance(cite.get("sha256"), str)
                    ):
                        raise ApiServiceError(
                            "ARTIFACT_PROVENANCE_MISMATCH",
                            f"Phần tử citations[{c_idx}] ở dòng #{idx + 1} trong assessments.jsonl sai kiểu hoặc thiếu trường bắt buộc.",
                            http_status=409,
                        )

            row_sp = row_ev.get("scan_provenance")
            if row_sp is not None and not isinstance(row_sp, dict):
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Trường evidence.scan_provenance ở dòng #{idx + 1} trong assessments.jsonl phải là object hoặc null.",
                    http_status=409,
                )
            row_cwe = row_ev.get("cwe")
            if row_cwe is not None and (not isinstance(row_cwe, list) or any(not isinstance(c, str) for c in row_cwe)):
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Trường evidence.cwe ở dòng #{idx + 1} trong assessments.jsonl phải là danh sách chuỗi.",
                    http_status=409,
                )
            row_snippets = row_ev.get("snippets")
            if row_snippets is not None:
                if not isinstance(row_snippets, list):
                    raise ApiServiceError(
                        "ARTIFACT_PROVENANCE_MISMATCH",
                        f"Trường evidence.snippets ở dòng #{idx + 1} trong assessments.jsonl phải là danh sách.",
                        http_status=409,
                    )
                for snip in row_snippets:
                    if not isinstance(snip, dict):
                        raise ApiServiceError(
                            "ARTIFACT_PROVENANCE_MISMATCH",
                            f"Phần tử evidence.snippets ở dòng #{idx + 1} trong assessments.jsonl phải là object.",
                            http_status=409,
                        )
                    snip_lines = snip.get("lines")
                    if snip_lines is not None and (
                        not isinstance(snip_lines, list) or any(not isinstance(ln, dict) for ln in snip_lines)
                    ):
                        raise ApiServiceError(
                            "ARTIFACT_PROVENANCE_MISMATCH",
                            f"Trường evidence.snippets[].lines ở dòng #{idx + 1} trong assessments.jsonl phải là danh sách object.",
                            http_status=409,
                        )
            for dict_key in ("snapshots", "raw_finding", "raw_trace", "start", "end", "java_context"):
                ev_val = row_ev.get(dict_key)
                if ev_val is not None and not isinstance(ev_val, dict):
                    raise ApiServiceError(
                        "ARTIFACT_PROVENANCE_MISMATCH",
                        f"Trường evidence.{dict_key} ở dòng #{idx + 1} trong assessments.jsonl phải là object hoặc null.",
                        http_status=409,
                    )
            row_issues = row_ev.get("issues")
            if row_issues is not None and not isinstance(row_issues, list):
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Trường evidence.issues ở dòng #{idx + 1} trong assessments.jsonl phải là danh sách.",
                    http_status=409,
                )

            if (row_rt or {}).get("origin") == "mock" or (row_sp or {}).get("origin") == "UNIT_TEST_MOCK_CAPTURE":
                has_mock_jsonl = True
            parsed_rows.append(row)

        with self._jsonl_cache_lock:
            if len(self._jsonl_cache) >= self._JSONL_CACHE_MAX_ENTRIES:
                self._jsonl_cache.pop(next(iter(self._jsonl_cache)))
            self._jsonl_cache[cache_key] = (parsed_rows, has_mock_jsonl)
        return (copy.deepcopy(parsed_rows) if need_rows else []), has_mock_jsonl

    def _revalidate_entry(self, entry: DiscoveredScan) -> DiscoveredScan:
        """Re-inspect entry on disk and return a fresh DiscoveredScan; reject stale/mutated identity."""
        managed_scans_root = self.config.data_dir / "scans"
        jobs_dir = self.config.data_dir / "jobs"
        managed_aliases = _collect_managed_scan_aliases(managed_scans_root)
        target_dir = entry.candidate_dir or entry.base_dir
        rechecked = _inspect_candidate_dir(
            target_dir,
            writable=entry.writable,
            managed_scans_root=managed_scans_root,
            jobs_dir=jobs_dir,
            managed_aliases=managed_aliases,
            include_integrity_failed=True,
        )
        if rechecked is None:
            if entry.is_managed and entry.owner_job_id and jobs_dir.is_dir():
                owner_jf = jobs_dir / f"{entry.owner_job_id}.json"
                if owner_jf.is_file():
                    try:
                        owner_jdoc = strict_json(owner_jf.read_text(encoding="utf-8"))
                    except (OSError, UnicodeDecodeError, EvidenceError):
                        owner_jdoc = None
                    c_rec, _, _ = _extract_sealed_v2_commit(owner_jdoc, entry.owner_job_id)
                    if c_rec is not None and isinstance(owner_jdoc, dict):
                        chk = inspect_managed_job_dir_committed(
                            scan_dir=entry.base_dir,
                            owner_job_id=entry.owner_job_id,
                            owner_job_doc=owner_jdoc,
                            jobs_dir=jobs_dir,
                        )
                        if not chk.ok and chk.status == "ARTIFACT_INTEGRITY_FAILED":
                            raise ApiServiceError(
                                "ARTIFACT_PROVENANCE_MISMATCH",
                                (
                                    f"Artifact đã niêm phong của phiên quét {entry.scan_id!r} (job {entry.owner_job_id!r}) "
                                    f"bị thiếu hoặc đã bị thay đổi sau commit ({chk.reason})."
                                ),
                                http_status=409,
                            )
            raise ApiServiceError(
                "SCAN_NOT_FOUND",
                f"Phiên quét {entry.scan_id!r} chưa được công bố, đã bị thu hồi hoặc không còn tồn tại.",
                http_status=404,
            )
        if rechecked.integrity_error:
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                rechecked.integrity_error,
                http_status=409,
            )
        if (
            rechecked.base_dir != entry.base_dir
            or rechecked.triage_dir != entry.triage_dir
            or rechecked.db_path != entry.db_path
            or rechecked.is_managed != entry.is_managed
            or rechecked.owner_job_id != entry.owner_job_id
        ):
            raise ApiServiceError(
                "SCAN_NOT_FOUND",
                f"Danh tính hoặc quyền sở hữu phiên quét {entry.scan_id!r} đã thay đổi sau bước kiểm tra.",
                http_status=404,
            )
        if rechecked.scan_sha256 != entry.scan_sha256:
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                f"Mã băm scan_sha256 của phiên quét {entry.scan_id!r} đã thay đổi sau bước kiểm tra.",
                http_status=409,
            )
        disambiguated_external = (
            rechecked.meta_path is None
            and not rechecked.is_managed
            and entry.scan_id.startswith(f"{entry.scan_sha256[:16]}-")
        )
        if rechecked.scan_id != entry.scan_id and not disambiguated_external:
            raise ApiServiceError(
                "SCAN_NOT_FOUND",
                f"Mã scan_id của phiên quét {entry.scan_id!r} đã thay đổi sau bước kiểm tra.",
                http_status=404,
            )
        if rechecked.scan_id != entry.scan_id:
            return DiscoveredScan(**{**rechecked.__dict__, "scan_id": entry.scan_id})
        return rechecked

    def _assert_entry_still_publishable(self, entry: DiscoveredScan) -> DiscoveredScan:
        return self._revalidate_entry(entry)

    def _read_scan_snapshot(
        self,
        entry: DiscoveredScan,
        *,
        finding_id: str | None = None,
        include_audit: bool = False,
        events_desc: bool = False,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any], dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
        """Read scan bundle, warnings, and optional audit rows from one atomic SQLite read transaction."""
        live_entry = self._revalidate_entry(entry)
        g1_doc = self._read_json_object_artifact(live_entry.g1_manifest_path, "g1-run-manifest.json")
        if live_entry.g1_manifest_path and live_entry.g1_manifest_path.is_file() and not g1_doc:
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                "Tệp g1-run-manifest.json rỗng hoặc thiếu schema ntk-g1-run-manifest-1.",
                http_status=409,
            )
        ollama_obj = g1_doc.get("ollama")
        if ollama_obj is not None and not isinstance(ollama_obj, dict):
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                "Trường ollama trong g1-run-manifest.json phải là đối tượng JSON hợp lệ.",
                http_status=409,
            )
        meta_doc = self._read_json_object_artifact(live_entry.meta_path, "api-scan-meta.json")
        self._verify_meta_artifact_hashes(live_entry, meta_doc)

        events: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []
        with _open_ro_sqlite(live_entry.db_path) as conn:
            conn.execute("BEGIN")
            try:
                scan_row = conn.execute("SELECT id, bundle FROM scans WHERE id=?", (live_entry.scan_sha256,)).fetchone()
                if scan_row is None:
                    raise ApiServiceError(
                        "ARTIFACT_PROVENANCE_MISMATCH",
                        "Bản ghi scan với mã băm SHA-256 mong đợi không còn tồn tại trong review.sqlite.",
                        http_status=409,
                    )
                bundle = json.loads(scan_row["bundle"])
                warning_rows = conn.execute(
                    "SELECT id, scan_id, evidence, assessment, state FROM warnings WHERE scan_id=? ORDER BY rowid",
                    (scan_row["id"],),
                ).fetchall()
                items = [
                    {
                        "id": str(r["id"]),
                        "scan_id": str(r["scan_id"]),
                        "state": str(r["state"]),
                        "evidence": json.loads(r["evidence"]),
                        "assessment": json.loads(r["assessment"]),
                    }
                    for r in warning_rows
                ]
                if include_audit:
                    events, rejected = self._query_audit_on_conn(
                        conn,
                        finding_id=finding_id,
                        descending=events_desc,
                    )
            finally:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass

        has_mock_jsonl = False
        jsonl_rows: list[dict[str, Any]] | None = None
        if live_entry.assessments_path and live_entry.assessments_path.is_file():
            jsonl_rows, has_mock_jsonl = self._inspect_assessments_jsonl(live_entry.assessments_path, need_rows=True)

        if self.config.runtime_origin != "mock":
            # Prevent test/mock runs from masquerading as production data unless server is in mock test mode.
            is_mock_meta = meta_doc.get("data_origin") == "MOCK_TEST"
            has_mock_runtime = any(
                isinstance(w.get("assessment"), dict)
                and isinstance(w["assessment"].get("runtime"), dict)
                and w["assessment"]["runtime"].get("origin") == "mock"
                for w in items
            )
            has_mock_g1 = (
                g1_doc.get("runtime_origin") == "mock"
                or (isinstance(g1_doc.get("ollama"), dict) and g1_doc["ollama"].get("runtime_origin") == "mock")
            )
            if is_mock_meta or has_mock_runtime or has_mock_g1 or has_mock_jsonl:
                meta_doc = {**meta_doc, "_contains_mock_runtime": True}

        # Authoritative immutable provenance verification on EVERY read/write path (not just /report):
        # Cross-check immutable SQLite `scans.bundle`, `warnings.evidence`, and `warnings.assessment` against
        # the sealed `assessments.jsonl` and `evidence.json` artifacts while preserving mutable Human Review
        # (`warnings.state`, `events`, `rejected_decisions`). Skip mismatch check ONLY when mock isolation
        # has already marked the scan for 403 TEST_DATA_ISOLATED / list hiding so isolation takes precedence.
        if not (meta_doc.get("_contains_mock_runtime") and self.config.runtime_origin != "mock"):
            self._verify_sqlite_immutable_provenance(
                live_entry,
                bundle,
                items,
                jsonl_rows=jsonl_rows,
                strict_report=False,
            )

        return bundle, items, g1_doc, meta_doc, events, rejected

    def _read_cached_evidence_json(self, evidence_path: Path) -> dict[str, Any]:
        """Strictly parse evidence.json with a read-only cache keyed by `(resolved_path, raw_bytes_sha256)`."""
        try:
            resolved_str = str(evidence_path.resolve(strict=True))
            raw_bytes = evidence_path.read_bytes()
        except OSError as exc:
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                f"Tệp evidence.json không đọc được hoặc bị thiếu: {exc}",
                http_status=409,
            ) from exc
        cache_key = (resolved_str, digest(raw_bytes))
        with self._jsonl_cache_lock:
            cached = self._evidence_cache.get(cache_key)
        if cached is not None:
            return cached
        try:
            ev_doc = strict_json(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, EvidenceError) as exc:
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                f"Tệp evidence.json bị hỏng hoặc không hợp lệ: {exc}",
                http_status=409,
            ) from exc
        if not isinstance(ev_doc, dict):
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                "Tệp evidence.json phải là đối tượng JSON hợp lệ.",
                http_status=409,
            )
        with self._jsonl_cache_lock:
            if len(self._evidence_cache) >= self._JSONL_CACHE_MAX_ENTRIES:
                self._evidence_cache.pop(next(iter(self._evidence_cache)))
            self._evidence_cache[cache_key] = ev_doc
        return ev_doc

    def _verify_sqlite_immutable_provenance(
        self,
        entry: DiscoveredScan,
        bundle: dict[str, Any],
        items: list[dict[str, Any]],
        *,
        jsonl_rows: list[dict[str, Any]] | None = None,
        strict_report: bool = False,
    ) -> None:
        """Verify immutable SQLite scan bundle, warning evidence, and warning assessments against sealed source files."""
        # 1. Cross-check immutable `scans.bundle` & `warnings.evidence` against `evidence.json`
        if entry.evidence_path and entry.evidence_path.is_file():
            ev_doc = self._read_cached_evidence_json(entry.evidence_path)
            if ev_doc.get("scan_sha256") != entry.scan_sha256 or bundle.get("scan_sha256") != entry.scan_sha256:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    "Mã băm scan_sha256 giữa evidence.json và SQLite không khớp.",
                    http_status=409,
                )
            if ev_doc.get("scan_provenance") != bundle.get("scan_provenance"):
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    "Thông tin scan_provenance giữa evidence.json và SQLite không khớp.",
                    http_status=409,
                )
            self._verify_evidence_and_raw_consistency(entry, ev_doc, None, items)
        elif entry.is_managed:
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                "Thiếu tệp evidence.json để đối chiếu bằng chứng bất biến của phiên quét managed.",
                http_status=409,
            )

        # 2. Cross-check immutable `warnings.assessment` & `warnings.evidence` against `assessments.jsonl`
        if jsonl_rows is None and entry.assessments_path and entry.assessments_path.is_file():
            jsonl_rows, _ = self._inspect_assessments_jsonl(entry.assessments_path, need_rows=True)
        if jsonl_rows is None:
            if entry.is_managed:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    "Thiếu tệp assessments.jsonl đã niêm phong để đối chiếu assessment trong SQLite.",
                    http_status=409,
                )
            return

        if len(jsonl_rows) != len(items):
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                "Số lượng bản ghi trong assessments.jsonl không khớp với bảng warnings trong SQLite.",
                http_status=409,
            )
        items_by_id = {w["id"]: w for w in items}
        seen_ids: set[str] = set()
        for row in jsonl_rows:
            row_id = row.get("id")
            row_ev = row["evidence"]
            if not isinstance(row_id, str) or row_id in seen_ids or row_id not in items_by_id:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    "Danh sách cảnh báo trong assessments.jsonl không khớp với SQLite.",
                    http_status=409,
                )
            seen_ids.add(row_id)
            if row.get("scan_sha256") != entry.scan_sha256 or row_ev.get("scan_sha256") != entry.scan_sha256:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    "Mã băm scan_sha256 trong assessments.jsonl không khớp với SQLite.",
                    http_status=409,
                )
            self._verify_jsonl_row_matches_sqlite(
                row,
                items_by_id[row_id],
                strict_exact_assessment=entry.is_managed,
                allow_omitted_runtime=(not entry.is_managed and not strict_report),
            )

    def _read_scan_rows(self, entry: DiscoveredScan) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
        bundle, items, g1_doc, meta_doc, _, _ = self._read_scan_snapshot(entry)
        return bundle, items, g1_doc, meta_doc

    @staticmethod
    def _has_mock_provenance_marker(obj: Any) -> bool:
        if not isinstance(obj, dict):
            return False
        if any(obj.get(k) is True for k in ("is_test_or_mock", "contains_mock_or_test_data", "mock", "is_mock", "synthetic", "is_synthetic")):
            return True
        for key in ("data_origin", "origin"):
            val = str(obj.get(key) or "").strip().upper()
            if val in ("MOCK_TEST", "MOCK_SYNTHETIC_TEST", "MOCK", "SYNTHETIC", "UNIT_TEST_MOCK_CAPTURE"):
                return True
        return False

    @classmethod
    def _is_unverified_provenance_origin(cls, raw_origin: Any) -> bool:
        val = str(raw_origin or "").strip().upper()
        if not val:
            return True
        return any(tok in val for tok in ("COLLECTION_ONLY", "DECLARED_ONLY", "IMPORTED", "UNVERIFIED", "UNKNOWN", "MANUAL_IMPORT"))

    @staticmethod
    def _has_cached_triage_marker(obj: Any) -> bool:
        if not isinstance(obj, dict):
            return False
        if obj.get("cache_hit") is True or obj.get("_contains_cached_triage") is True:
            return True
        for key in ("data_origin", "origin", "transport", "http_capture_status", "capture_status"):
            val = str(obj.get(key) or "").strip().upper()
            if val in (
                "CACHED_VERIFIED",
                "QWEN-CACHE-VERIFIED",
                "CACHED_TRIAGE_NO_LIVE_HTTP",
                "CACHE_REUSED_NO_LIVE_HTTP",
            ):
                return True
        telem = obj.get("triage_telemetry")
        if isinstance(telem, dict) and type(telem.get("cache_hits")) is int and telem["cache_hits"] > 0:
            return True
        st = obj.get("stage_statuses")
        if isinstance(st, dict) and str(st.get("http_capture_status") or "").strip().upper() == "CACHE_REUSED_NO_LIVE_HTTP":
            return True
        return False

    @staticmethod
    def _has_explicit_non_real_origin(obj: Any) -> bool:
        if not isinstance(obj, dict) or "data_origin" not in obj or obj["data_origin"] is None:
            return False
        raw = obj["data_origin"]
        if not isinstance(raw, str):
            return True
        val = raw.strip().upper()
        return bool(val) and val != "REAL_SCAN"

    def _classify_data_origin(self, bundle: dict[str, Any], items: list[dict[str, Any]], meta_doc: dict[str, Any]) -> str:
        if meta_doc.get("_contains_mock_runtime"):
            return "MOCK_SYNTHETIC_TEST"
        prov = bundle.get("scan_provenance") if isinstance(bundle.get("scan_provenance"), dict) else {}
        for top in (bundle, bundle.get("metadata"), meta_doc, prov, prov.get("metadata")):
            if self._has_mock_provenance_marker(top):
                return "MOCK_SYNTHETIC_TEST"

        for w in items:
            ass = w.get("assessment") if isinstance(w.get("assessment"), dict) else {}
            ev = w.get("evidence") if isinstance(w.get("evidence"), dict) else {}
            rt = ass.get("runtime") if isinstance(ass.get("runtime"), dict) else {}
            w_prov = w.get("scan_provenance") if isinstance(w.get("scan_provenance"), dict) else {}
            item_prov = ev.get("scan_provenance") if isinstance(ev.get("scan_provenance"), dict) else {}
            candidates: list[Any] = [
                w,
                w.get("metadata"),
                w_prov,
                w_prov.get("metadata"),
                ass,
                ass.get("metadata"),
                rt,
                rt.get("metadata"),
                ev,
                ev.get("metadata"),
                item_prov,
                item_prov.get("metadata"),
            ]
            for snip in (ev.get("snippets") or []):
                if isinstance(snip, dict):
                    candidates.append(snip)
                    candidates.append(snip.get("metadata"))
            for cit in (ass.get("citations") or []):
                if isinstance(cit, dict):
                    candidates.append(cit)
                    candidates.append(cit.get("metadata"))
            if any(self._has_mock_provenance_marker(c) for c in candidates):
                return "MOCK_SYNTHETIC_TEST"

        cached_items = 0
        live_items = 0
        for w in items:
            ass = w.get("assessment") if isinstance(w.get("assessment"), dict) else {}
            rt = ass.get("runtime") if isinstance(ass.get("runtime"), dict) else {}
            if self._has_cached_triage_marker(ass) or self._has_cached_triage_marker(rt):
                cached_items += 1
            elif rt.get("request_attempted") is True:
                live_items += 1

        telem = meta_doc.get("triage_telemetry") if isinstance(meta_doc.get("triage_telemetry"), dict) else {}
        telem_live = type(telem.get("live_calls")) is int and telem["live_calls"] > 0
        telem_cached = type(telem.get("cache_hits")) is int and telem["cache_hits"] > 0
        has_cached = cached_items > 0 or telem_cached or any(
            self._has_cached_triage_marker(top)
            for top in (bundle, bundle.get("metadata"), meta_doc, meta_doc.get("metadata"))
        )
        has_live = live_items > 0 or telem_live
        if has_cached and has_live:
            return "MIXED_CACHE_AND_LIVE_HTTP"
        if has_cached:
            return "CACHED_TRIAGE_NO_LIVE_HTTP"

        if meta_doc.get("_contains_non_real_origin") or any(
            self._has_explicit_non_real_origin(top)
            for top in (bundle, bundle.get("metadata"), bundle.get("scan_summary"), meta_doc, meta_doc.get("metadata"))
        ):
            return "IMPORTED_SCAN_UNVERIFIED_CAPTURE"

        # Distinguish three conditions for REAL_SCAN:
        # 1) source_capture_verified is True, 2) exit_capture_verified is True, 3) recorded_engine_exit == 0.
        if (
            not self._is_unverified_provenance_origin(prov.get("origin"))
            and prov.get("source_capture_verified") is True
            and prov.get("exit_capture_verified") is True
            and type(prov.get("recorded_engine_exit")) is int
            and prov.get("recorded_engine_exit") == 0
        ):
            for w in items:
                ass = w.get("assessment") if isinstance(w.get("assessment"), dict) else {}
                ev = w.get("evidence") if isinstance(w.get("evidence"), dict) else {}
                if any(
                    self._has_explicit_non_real_origin(comp)
                    for comp in (
                        w,
                        w.get("metadata"),
                        w.get("scan_summary"),
                        ev,
                        ev.get("metadata"),
                        ass,
                        ass.get("metadata"),
                    )
                ):
                    return "IMPORTED_SCAN_UNVERIFIED_CAPTURE"
                for item_prov in (w.get("scan_provenance"), ev.get("scan_provenance")):
                    if isinstance(item_prov, dict):
                        if (
                            self._is_unverified_provenance_origin(item_prov.get("origin"))
                            or item_prov.get("source_capture_verified") is not True
                            or item_prov.get("exit_capture_verified") is not True
                            or type(item_prov.get("recorded_engine_exit")) is not int
                            or item_prov.get("recorded_engine_exit") != 0
                        ):
                            return "IMPORTED_SCAN_UNVERIFIED_CAPTURE"
            return "REAL_SCAN"
        return "IMPORTED_SCAN_UNVERIFIED_CAPTURE"

    @classmethod
    def _classify_finding_triage_provenance(cls, item: dict[str, Any]) -> str:
        ass = item.get("assessment") if isinstance(item.get("assessment"), dict) else {}
        rt = ass.get("runtime") if isinstance(ass.get("runtime"), dict) else {}
        if cls._has_mock_provenance_marker(ass) or cls._has_mock_provenance_marker(rt):
            return "MOCK_SYNTHETIC_TEST"
        if (
            rt.get("origin") == "cached_verified"
            or rt.get("cache_hit") is True
            or str(ass.get("transport") or "").lower() == "qwen-cache-verified"
        ):
            return "CACHED_TRIAGE_NO_LIVE_HTTP"
        if str(ass.get("transport") or "").lower() == "disabled" and str(rt.get("origin") or "").lower() == "disabled":
            return "DISABLED"
        if (
            rt.get("request_attempted") is True
            and rt.get("http_response_received") is True
            and rt.get("http_status") == 200
            and rt.get("response_complete") is True
        ):
            return "LIVE_HTTP_CAPTURED"
        return "PRECHECK_OR_ERROR"

    def _project_finding_summary(self, scan_id: str, item: dict[str, Any]) -> dict[str, Any]:
        ev = item["evidence"]
        ass = item["assessment"]
        finding_snip = next((s for s in (ev.get("snippets") or []) if s.get("role") == "finding"), None)
        rel_path = (
            finding_snip.get("path")
            if isinstance(finding_snip, dict) and finding_snip.get("path")
            else str(ev.get("path") or "").replace("\\", "/")
        )
        start = ev.get("start") or {}
        end = ev.get("end") or {}
        cwes = ev.get("cwe") or []
        primary_cwe = _norm_cwe(cwes)
        raw_finding = ev.get("raw_finding") if isinstance(ev.get("raw_finding"), dict) else {}
        extra = raw_finding.get("extra") if isinstance(raw_finding.get("extra"), dict) else {}
        validated_status = ass.get("validated_status", ass.get("status", "UNDETERMINED"))
        raw_model_status = ass.get("raw_model_status")
        citations = ass.get("citations") if isinstance(ass.get("citations"), list) else []
        triage_provenance = self._classify_finding_triage_provenance(item)

        return {
            "id": item["id"],
            "finding_id": item["id"],
            "alert_id": ev.get("alert_id", item["id"]),
            "scan_id": scan_id,
            "scan_sha256": ev.get("scan_sha256"),
            "finding_index": ev.get("finding_index"),
            "rule_id": ev.get("rule_id"),
            "cwe": primary_cwe,
            "cwe_list": list(cwes),
            "severity": ev.get("severity") or extra.get("severity") or "WARNING",
            "message": extra.get("message") or ev.get("rule_id") or "",
            "file_path": rel_path,
            "raw_path": ev.get("path"),
            "start_line": start.get("line"),
            "end_line": end.get("line"),
            "start_col": start.get("col"),
            "end_col": end.get("col"),
            "has_dataflow_trace": bool(isinstance(ev.get("raw_trace"), dict) and ev.get("raw_trace")),
            "evidence_issues_count": len(ev.get("issues") or []),
            "evidence_issues": list(ev.get("issues") or []),
            "raw_model_status": raw_model_status,
            "validated_status": validated_status,
            "validator_downgraded": bool(ass.get("validator_downgraded")),
            "failure_kind": ass.get("failure_kind"),
            "citation_check": ass.get("citation_check", "NOT_VERIFIED"),
            "citations_count": len(citations),
            "explanation_preview": str(ass.get("explanation") or "")[:240],
            "human_review_state": item["state"],
            "requires_human_review": bool(ass.get("requires_human_review", True)),
            "security_conclusion_verified": bool(ass.get("security_conclusion_verified", False)),
            "triage_provenance": triage_provenance,
            "detail_url": f"/api/scans/{scan_id}/findings/{item['id']}",
        }

    def _build_scan_summary_from_snapshot(
        self,
        entry: DiscoveredScan,
        bundle: dict[str, Any],
        items: list[dict[str, Any]],
        g1_doc: dict[str, Any],
        meta_doc: dict[str, Any],
    ) -> dict[str, Any]:
        data_origin = self._classify_data_origin(bundle, items, meta_doc)

        by_validated = {"SUPPORTED": 0, "REFUTED": 0, "UNDETERMINED": 0}
        by_raw_model: dict[str, int] = {"SUPPORTED": 0, "REFUTED": 0, "UNDETERMINED": 0, "NONE": 0}
        by_human = {"OPEN": 0, "CONFIRMED_TRUE": 0, "CONFIRMED_FALSE": 0}
        by_cwe: dict[str, int] = {}
        by_triage_prov: dict[str, int] = {}
        with_trace = 0
        downgraded = 0
        matched_citations = 0
        proposed_refuted_open = 0

        assessments = []
        for w in items:
            ev = w["evidence"]
            ass = w["assessment"]
            assessments.append(ass)
            prov_tag = self._classify_finding_triage_provenance(w)
            by_triage_prov[prov_tag] = by_triage_prov.get(prov_tag, 0) + 1
            v_state = ass.get("validated_status", ass.get("status", "UNDETERMINED"))
            by_validated[v_state] = by_validated.get(v_state, 0) + 1
            r_state = ass.get("raw_model_status")
            r_key = r_state if isinstance(r_state, str) and r_state else "NONE"
            by_raw_model[r_key] = by_raw_model.get(r_key, 0) + 1
            h_state = w["state"]
            by_human[h_state] = by_human.get(h_state, 0) + 1
            if h_state == "OPEN" and v_state == "REFUTED":
                proposed_refuted_open += 1
            cwe_key = _norm_cwe(ev.get("cwe"))
            by_cwe[cwe_key] = by_cwe.get(cwe_key, 0) + 1
            if isinstance(ev.get("raw_trace"), dict) and ev.get("raw_trace"):
                with_trace += 1
            if ass.get("validator_downgraded"):
                downgraded += 1
            if ass.get("citation_check") == "MATCHED":
                matched_citations += 1

        rt_counts = runtime_summary_fn(assessments)
        prov = bundle.get("scan_provenance") or {}
        inventory_malformed = False
        bundle_pre_raw = bundle.get("pre_scan_hashes")
        g1_pre_raw = g1_doc.get("pre_scan_sources_sha256")
        meta_pre_raw = meta_doc.get("java_sha256")
        for cand_raw in (bundle_pre_raw, g1_pre_raw, meta_pre_raw):
            if cand_raw is not None and not isinstance(cand_raw, dict):
                inventory_malformed = True

        # Prefer cryptographically verified capture/scan-manifest.json inventory over unverified meta_doc cache
        manifest_hashes: dict[str, Any] | None = None
        if bundle_pre_raw is None and g1_pre_raw is None:
            manifest_sha_expected = prov.get("manifest_sha256")
            if (
                isinstance(manifest_sha_expected, str)
                and len(manifest_sha_expected) == 64
                and all(ch in "0123456789abcdef" for ch in manifest_sha_expected)
            ):
                manifest_path = entry.base_dir / "capture" / "scan-manifest.json"
                if manifest_path.is_file() and not is_reparse_link(manifest_path):
                    try:
                        m_raw = manifest_path.read_bytes()
                        if digest(m_raw) == manifest_sha_expected:
                            m_doc = strict_json(m_raw.decode("utf-8"))
                            if isinstance(m_doc, dict) and isinstance(m_doc.get("sources_before"), dict):
                                sb = m_doc["sources_before"]
                                sa = m_doc.get("sources_after")
                                if sa is None or (isinstance(sa, dict) and sa == sb):
                                    manifest_hashes = sb
                                else:
                                    inventory_malformed = True
                    except (OSError, UnicodeDecodeError, EvidenceError, ValueError):
                        inventory_malformed = True

        pre_hashes: dict[str, Any] | None = None
        if isinstance(bundle_pre_raw, dict):
            pre_hashes = bundle_pre_raw
        elif isinstance(g1_pre_raw, dict):
            pre_hashes = g1_pre_raw
        elif manifest_hashes is not None:
            pre_hashes = manifest_hashes
            if isinstance(meta_pre_raw, dict):
                m_java_keys = {
                    k.replace("\\", "/") for k in manifest_hashes.keys() if isinstance(k, str) and k.replace("\\", "/").lower().endswith(".java")
                }
                c_java_keys = {
                    k.replace("\\", "/") for k in meta_pre_raw.keys() if isinstance(k, str) and k.replace("\\", "/").lower().endswith(".java")
                }
                if c_java_keys != m_java_keys:
                    inventory_malformed = True
        elif isinstance(meta_pre_raw, dict):
            pre_hashes = meta_pre_raw

        raw_meta_count = meta_doc.get("java_files_count")
        if raw_meta_count is not None and not (type(raw_meta_count) is int and raw_meta_count >= 0):
            inventory_malformed = True
            valid_meta_count = None
        else:
            valid_meta_count = raw_meta_count

        if pre_hashes is not None:
            pre_java_count = sum(
                1 for k in pre_hashes.keys() if isinstance(k, str) and k.replace("\\", "/").lower().endswith(".java")
            )
            legacy_java_scanned = len(pre_hashes) if pre_hashes else valid_meta_count
            expected_inventory_int: int | None = pre_java_count
        else:
            legacy_java_scanned = valid_meta_count
            expected_inventory_int = valid_meta_count

        inv_paths_arg = pre_hashes.keys() if pre_hashes is not None else None
        bundle_root_raw = bundle.get("root")
        source_root_arg = (
            Path(bundle_root_raw)
            if isinstance(bundle_root_raw, str) and bundle_root_raw.strip()
            else None
        )
        og_path = entry.raw_json_path or (entry.base_dir / "capture" / "opengrep.json")
        has_valid_sha = (
            isinstance(entry.scan_sha256, str)
            and len(entry.scan_sha256) == 64
            and all(ch in "0123456789abcdef" for ch in entry.scan_sha256)
        )
        raw_file_present = False
        if inventory_malformed:
            raw_coverage_tel = {
                "java_files_inventory": None,
                "java_files_opengrep_scanned": None,
                "java_files_opengrep_ignored": None,
                "opengrep_paths_telemetry_status": "INCONSISTENT_TELEMETRY",
            }
        elif not entry.scan_sha256:
            raw_coverage_tel = {
                "java_files_inventory": expected_inventory_int,
                "java_files_opengrep_scanned": None,
                "java_files_opengrep_ignored": None,
                "opengrep_paths_telemetry_status": "MISSING_PATHS_TELEMETRY",
            }
        elif not has_valid_sha:
            raw_coverage_tel = {
                "java_files_inventory": expected_inventory_int,
                "java_files_opengrep_scanned": None,
                "java_files_opengrep_ignored": None,
                "opengrep_paths_telemetry_status": "INCONSISTENT_TELEMETRY",
            }
        elif og_path is not None and og_path.is_file():
            raw_file_present = True
            try:
                if is_reparse_link(og_path):
                    raise EvidenceError("symlink/reparse opengrep.json forbidden")
                raw_og = og_path.read_bytes()
                if digest(raw_og) != entry.scan_sha256:
                    raw_coverage_tel = {
                        "java_files_inventory": expected_inventory_int,
                        "java_files_opengrep_scanned": None,
                        "java_files_opengrep_ignored": None,
                        "opengrep_paths_telemetry_status": "INCONSISTENT_TELEMETRY",
                    }
                else:
                    og_doc = strict_json(raw_og.decode("utf-8"))
                    raw_coverage_tel = compute_opengrep_coverage_telemetry(
                        inv_paths_arg,
                        og_doc if isinstance(og_doc, dict) else og_doc,
                        inventory_count_fallback=expected_inventory_int,
                        source_root=source_root_arg,
                    )
            except (OSError, UnicodeDecodeError, EvidenceError, ValueError):
                raw_coverage_tel = {
                    "java_files_inventory": expected_inventory_int,
                    "java_files_opengrep_scanned": None,
                    "java_files_opengrep_ignored": None,
                    "opengrep_paths_telemetry_status": "INCONSISTENT_TELEMETRY",
                }
        else:
            raw_coverage_tel = {
                "java_files_inventory": expected_inventory_int,
                "java_files_opengrep_scanned": None,
                "java_files_opengrep_ignored": None,
                "opengrep_paths_telemetry_status": "MISSING_PATHS_TELEMETRY",
            }

        coverage_tel = reconcile_cached_and_raw_coverage_telemetry(
            meta_doc,
            raw_coverage_tel,
            expected_inventory=expected_inventory_int,
            scan_sha256=entry.scan_sha256,
            raw_file_present=raw_file_present,
        )

        return {
            "scan_id": entry.scan_id,
            "scan_sha256": entry.scan_sha256,
            "schema_version": bundle.get("schema_version", SCHEMA_VERSION),
            "data_origin": data_origin,
            "is_test_or_mock": data_origin == "MOCK_SYNTHETIC_TEST",
            "writable": entry.writable,
            "collected_at": bundle.get("collected_at") or g1_doc.get("recorded_at") or meta_doc.get("completed_at"),
            "started_at": meta_doc.get("started_at") or prov.get("started_at"),
            "completed_at": meta_doc.get("completed_at") or g1_doc.get("recorded_at") or bundle.get("collected_at"),
            "total_e2e_duration_ms": meta_doc.get("total_e2e_duration_ms"),
            "input_mode": meta_doc.get("input_mode") or ("DIRECTORY" if not meta_doc else None),
            "repo_url": meta_doc.get("repo_url"),
            "resolved_commit": meta_doc.get("resolved_commit"),
            "file_name": meta_doc.get("file_name"),
            "job_id": meta_doc.get("job_id"),
            "java_files_scanned": legacy_java_scanned,
            "java_files_inventory": coverage_tel["java_files_inventory"],
            "java_files_opengrep_scanned": coverage_tel["java_files_opengrep_scanned"],
            "java_files_opengrep_ignored": coverage_tel["java_files_opengrep_ignored"],
            "opengrep_paths_telemetry_status": coverage_tel["opengrep_paths_telemetry_status"],
            "prompt_contract": bundle.get("prompt_contract") or g1_doc.get("prompt_contract") or "blind",
            "prompt_version": g1_doc.get("prompt_version") or PROMPT_VERSION,
            "opengrep_version": g1_doc.get("opengrep_version") or meta_doc.get("opengrep_version"),
            "rules_sha256": g1_doc.get("rules_sha256") or meta_doc.get("rules_sha256"),
            "scan_issues": list(bundle.get("issues") or []),
            "scan_provenance": {
                "origin": prov.get("origin"),
                "source_capture_verified": bool(prov.get("source_capture_verified")),
                "exit_capture_verified": bool(prov.get("exit_capture_verified")),
                "recorded_engine_exit": prov.get("recorded_engine_exit"),
                "manifest_sha256": prov.get("manifest_sha256"),
            },
            "stage_statuses": g1_doc.get("stage_statuses") or meta_doc.get("stage_statuses"),
            "total_findings": len(items),
            "findings_with_trace": with_trace,
            "validator_downgraded_count": downgraded,
            "matched_citation_count": matched_citations,
            "by_validated_status": by_validated,
            "by_raw_model_status": by_raw_model,
            "by_human_review_state": by_human,
            "triage_provenance_summary": by_triage_prov,
            "proposed_refuted_open_count": proposed_refuted_open,
            "by_cwe": dict(sorted(by_cwe.items())),
            "runtime_summary": rt_counts,
            "qwen_runtime_verified": bool(items) and rt_counts["verified_model_runtime_count"] == len(items),
            "known_analysis_limits": [*KNOWN_ANALYSIS_LIMITS, *UNSUPPORTED_REFUTATION_PROOF_LIMITS],
        }

    def build_scan_summary(self, entry: DiscoveredScan) -> dict[str, Any]:
        live_entry = self._revalidate_entry(entry)
        bundle, items, g1_doc, meta_doc = self._read_scan_rows(live_entry)
        return self._build_scan_summary_from_snapshot(live_entry, bundle, items, g1_doc, meta_doc)

    def list_scans(self, *, include_mock: bool = False) -> dict[str, Any]:
        summaries = []
        for entry in self.discover_scans():
            try:
                summary = self.build_scan_summary(entry)
            except ApiServiceError:
                continue
            if summary["is_test_or_mock"] and not include_mock and self.config.runtime_origin != "mock":
                continue
            summaries.append(summary)
        summaries.sort(key=lambda s: str(s.get("completed_at") or s.get("collected_at") or ""), reverse=True)
        return {
            "contract_schema": API_CONTRACT_SCHEMA,
            "total_count": len(summaries),
            "scans": summaries,
        }

    def list_findings(
        self,
        scan_id: str,
        *,
        page: int = 1,
        page_size: int = 50,
        cwe: str | None = None,
        query: str | None = None,
        file_filter: str | None = None,
        validated_status: str | None = None,
        human_review_state: str | None = None,
        include_confirmed_false: bool = True,
    ) -> dict[str, Any]:
        entry = self.resolve_scan(scan_id)
        bundle, items, _, meta_doc = self._read_scan_rows(entry)
        data_origin = self._classify_data_origin(bundle, items, meta_doc)
        if data_origin == "MOCK_SYNTHETIC_TEST" and self.config.runtime_origin != "mock":
            raise ApiServiceError(
                "TEST_DATA_ISOLATED",
                "Dữ liệu kiểm thử mô phỏng (mock) bị cách ly khỏi chế độ vận hành thực.",
                http_status=403,
            )

        page = max(1, int(page))
        page_size = max(1, min(200, int(page_size)))
        projected = [self._project_finding_summary(entry.scan_id, w) for w in items]

        cwe_norm = _norm_cwe(cwe) if cwe and cwe.strip() else None
        q_norm = query.strip().lower() if query and query.strip() else None
        f_norm = file_filter.strip().lower() if file_filter and file_filter.strip() else None
        v_norm = validated_status.strip().upper() if validated_status and validated_status.strip() else None
        h_norm = human_review_state.strip().upper() if human_review_state and human_review_state.strip() else None

        filtered = []
        for row in projected:
            if not include_confirmed_false and row["human_review_state"] == "CONFIRMED_FALSE":
                continue
            if cwe_norm and row["cwe"] != cwe_norm:
                continue
            if v_norm and row["validated_status"] != v_norm:
                continue
            if h_norm and row["human_review_state"] != h_norm:
                continue
            if f_norm and f_norm not in str(row["file_path"] or "").lower():
                continue
            if q_norm:
                haystack = f"{row['id']} {row['rule_id']} {row['cwe']} {row['file_path']} {row['message']}".lower()
                if q_norm not in haystack:
                    continue
            filtered.append(row)

        total_matching = len(filtered)
        total_pages = max(1, (total_matching + page_size - 1) // page_size)
        slice_start = (page - 1) * page_size
        page_items = filtered[slice_start : slice_start + page_size]

        return {
            "scan_id": entry.scan_id,
            "scan_sha256": entry.scan_sha256,
            "data_origin": data_origin,
            "writable": entry.writable,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "total_count": len(projected),
            "total_matching": total_matching,
            "findings": page_items,
        }

    def get_review_queue(self, scan_id: str, *, include_all: bool = False) -> dict[str, Any]:
        entry = self.resolve_scan(scan_id)
        bundle, items, _, meta_doc = self._read_scan_rows(entry)
        data_origin = self._classify_data_origin(bundle, items, meta_doc)
        if data_origin == "MOCK_SYNTHETIC_TEST" and self.config.runtime_origin != "mock":
            raise ApiServiceError(
                "TEST_DATA_ISOLATED",
                "Dữ liệu kiểm thử mô phỏng (mock) bị cách ly khỏi chế độ vận hành thực.",
                http_status=403,
            )

        visible_items = items if include_all else [w for w in items if w["state"] != "CONFIRMED_FALSE"]
        rows = [self._project_finding_summary(entry.scan_id, w) for w in visible_items]
        counts = {
            "total_in_scan": len(items),
            "visible_in_queue": len(rows),
            "open_count": sum(1 for w in items if w["state"] == "OPEN"),
            "confirmed_true_count": sum(1 for w in items if w["state"] == "CONFIRMED_TRUE"),
            "confirmed_false_count": sum(1 for w in items if w["state"] == "CONFIRMED_FALSE"),
            "proposed_refuted_open_count": sum(
                1
                for w in items
                if w["state"] == "OPEN"
                and w["assessment"].get("validated_status", w["assessment"].get("status")) == "REFUTED"
            ),
            "undetermined_open_count": sum(
                1
                for w in items
                if w["state"] == "OPEN"
                and w["assessment"].get("validated_status", w["assessment"].get("status")) == "UNDETERMINED"
            ),
        }
        prov = bundle.get("scan_provenance") or {}
        return {
            "scan_id": entry.scan_id,
            "scan_sha256": entry.scan_sha256,
            "data_origin": data_origin,
            "is_test_or_mock": data_origin == "MOCK_SYNTHETIC_TEST",
            "scan_provenance": {
                "origin": prov.get("origin"),
                "source_capture_verified": bool(prov.get("source_capture_verified")),
                "exit_capture_verified": bool(prov.get("exit_capture_verified")),
                "recorded_engine_exit": prov.get("recorded_engine_exit"),
                "manifest_sha256": prov.get("manifest_sha256"),
            },
            "writable": entry.writable,
            "include_all": include_all,
            "scan_issues": list(bundle.get("issues") or []),
            "counts": counts,
            "warnings": rows,
        }

    def _build_finding_detail_from_snapshot(
        self,
        entry: DiscoveredScan,
        data_origin: str,
        target: dict[str, Any],
        events: list[dict[str, Any]],
        rejected: list[dict[str, Any]],
    ) -> dict[str, Any]:
        summary_fields = self._project_finding_summary(entry.scan_id, target)
        ev = target["evidence"]
        ass = target["assessment"]
        rt = ass.get("runtime") or {}

        # Redact machine-local filesystem root from evidence payload returned over HTTP while keeping relative paths & hashes intact.
        safe_evidence = {
            "schema_version": ev.get("schema_version"),
            "id": ev.get("id"),
            "alert_id": ev.get("alert_id"),
            "finding_index": ev.get("finding_index"),
            "scan_sha256": ev.get("scan_sha256"),
            "rule_id": ev.get("rule_id"),
            "cwe": ev.get("cwe"),
            "severity": ev.get("severity"),
            "path": summary_fields["file_path"],
            "raw_path": ev.get("path"),
            "start": ev.get("start"),
            "end": ev.get("end"),
            "snapshots": ev.get("snapshots"),
            "snippets": ev.get("snippets"),
            "raw_trace": ev.get("raw_trace"),
            "java_context": ev.get("java_context"),
            "issues": ev.get("issues"),
            "scan_provenance": ev.get("scan_provenance"),
            "collected_at": ev.get("collected_at"),
        }
        safe_assessment = {
            "status": ass.get("status"),
            "raw_model_status": ass.get("raw_model_status"),
            "validated_status": ass.get("validated_status", ass.get("status")),
            "validator_downgraded": bool(ass.get("validator_downgraded")),
            "downgrade_reason": ass.get("downgrade_reason"),
            "failure_kind": ass.get("failure_kind"),
            "explanation": ass.get("explanation"),
            "fix_suggestion": ass.get("fix_suggestion") or "",
            "fix_suggestion_display_only": True,
            "citations": ass.get("citations") or [],
            "citation_check": ass.get("citation_check", "NOT_VERIFIED"),
            "citation_provenance": ass.get("citation_provenance"),
            "raw_response": ass.get("raw_response"),
            "prompt_version": ass.get("prompt_version"),
            "requires_human_review": bool(ass.get("requires_human_review", True)),
            "security_conclusion_verified": bool(ass.get("security_conclusion_verified", False)),
            "supports_security_claim_verified": bool(ass.get("supports_security_claim_verified", False)),
            "independent_refutation_proof": ass.get("independent_refutation_proof"),
            "analyzed_at": ass.get("analyzed_at"),
            "elapsed_seconds": ass.get("elapsed_seconds"),
            "model": ass.get("model"),
            "transport": ass.get("transport"),
            "runtime": {
                "origin": rt.get("origin"),
                "request_attempted": rt.get("request_attempted"),
                "http_response_received": rt.get("http_response_received"),
                "http_status": rt.get("http_status"),
                "response_complete": rt.get("response_complete"),
                "model_identity_matched": rt.get("model_identity_matched"),
                "reported_eval_count": rt.get("reported_eval_count"),
                "answer_validated": rt.get("answer_validated"),
                "model_runtime_verified": rt.get("model_runtime_verified", False),
                "request_payload_sha256": rt.get("request_payload_sha256"),
                "response_body_sha256": rt.get("response_body_sha256"),
            },
        }

        return {
            **summary_fields,
            "data_origin": data_origin,
            "is_test_or_mock": data_origin == "MOCK_SYNTHETIC_TEST",
            "writable": entry.writable,
            "evidence": safe_evidence,
            "assessment": safe_assessment,
            "review_events": events,
            "rejected_decisions": rejected,
        }

    def get_finding_detail(self, scan_id: str, finding_id: str) -> dict[str, Any]:
        entry = self.resolve_scan(scan_id)
        bundle, items, _, meta_doc, events, rejected = self._read_scan_snapshot(
            entry,
            finding_id=finding_id,
            include_audit=True,
            events_desc=False,
        )
        data_origin = self._classify_data_origin(bundle, items, meta_doc)
        if data_origin == "MOCK_SYNTHETIC_TEST" and self.config.runtime_origin != "mock":
            raise ApiServiceError(
                "TEST_DATA_ISOLATED",
                "Dữ liệu kiểm thử mô phỏng (mock) bị cách ly khỏi chế độ vận hành thực.",
                http_status=403,
            )

        target = next((w for w in items if w["id"] == finding_id), None)
        if target is None:
            raise ApiServiceError("FINDING_NOT_FOUND", f"Không tìm thấy cảnh báo {finding_id!r} trong phiên quét này.", http_status=404)

        return self._build_finding_detail_from_snapshot(entry, data_origin, target, events, rejected)

    def get_finding_history(self, scan_id: str, finding_id: str, *, include_rejected: bool = True) -> dict[str, Any]:
        entry = self.resolve_scan(scan_id)
        bundle, items, _, meta_doc, events, rejected = self._read_scan_snapshot(
            entry,
            finding_id=finding_id,
            include_audit=True,
            events_desc=False,
        )
        if self._classify_data_origin(bundle, items, meta_doc) == "MOCK_SYNTHETIC_TEST" and self.config.runtime_origin != "mock":
            raise ApiServiceError(
                "TEST_DATA_ISOLATED",
                "Dữ liệu kiểm thử mô phỏng (mock) bị cách ly khỏi chế độ vận hành thực.",
                http_status=403,
            )
        target = next((w for w in items if w["id"] == finding_id), None)
        if target is None:
            raise ApiServiceError("FINDING_NOT_FOUND", f"Không tìm thấy cảnh báo {finding_id!r}.", http_status=404)
        payload: dict[str, Any] = {
            "scan_id": entry.scan_id,
            "finding_id": finding_id,
            "human_review_state": target["state"],
            "events": events,
        }
        if include_rejected:
            payload["rejected_decisions"] = rejected
        return payload

    def get_scan_review_history(self, scan_id: str) -> dict[str, Any]:
        entry = self.resolve_scan(scan_id)
        bundle, items, _, meta_doc, events, rejected = self._read_scan_snapshot(
            entry,
            finding_id=None,
            include_audit=True,
            events_desc=True,
        )
        if self._classify_data_origin(bundle, items, meta_doc) == "MOCK_SYNTHETIC_TEST" and self.config.runtime_origin != "mock":
            raise ApiServiceError(
                "TEST_DATA_ISOLATED",
                "Dữ liệu kiểm thử mô phỏng (mock) bị cách ly khỏi chế độ vận hành thực.",
                http_status=403,
            )
        return {
            "scan_id": entry.scan_id,
            "scan_sha256": entry.scan_sha256,
            "events": events,
            "rejected_decisions": rejected,
        }

    def decide_finding(self, scan_id: str, finding_id: str, action: str, actor: str, reason: str) -> dict[str, Any]:
        if action not in ("confirm-true", "confirm-false", "reopen"):
            raise ApiServiceError("INVALID_REVIEW_ACTION", f"Hành động kiểm duyệt không hợp lệ: {action!r}.", http_status=400)
        if not isinstance(actor, str) or not actor.strip() or len(actor.strip()) > 120 or any(ord(c) < 32 for c in actor):
            raise ApiServiceError("INVALID_REVIEW_ACTOR", "Tên người kiểm duyệt (actor) bắt buộc từ 1–120 ký tự hợp lệ.", http_status=400)
        if not isinstance(reason, str) or not reason.strip() or len(reason.strip()) > 2000:
            raise ApiServiceError("INVALID_REVIEW_REASON", "Lý do kiểm duyệt (reason) bắt buộc không được để trống (tối đa 2000 ký tự).", http_status=400)

        with acquire_publication_lock(self.config.data_dir), self._review_lock:
            entry = self.resolve_scan(scan_id)
            if not entry.writable:
                raise ApiServiceError(
                    "SCAN_READ_ONLY",
                    "Phiên quét này thuộc vùng dữ liệu chỉ đọc; không cho phép thay đổi trạng thái kiểm duyệt.",
                    http_status=403,
                )

            # Verify scan identity, ownership, artifact hashes, immutable SQLite assessments, and non-mock isolation.
            bundle, items, _, meta_doc = self._read_scan_rows(entry)
            data_origin = self._classify_data_origin(bundle, items, meta_doc)
            if data_origin == "MOCK_SYNTHETIC_TEST" and self.config.runtime_origin != "mock":
                raise ApiServiceError(
                    "TEST_DATA_ISOLATED",
                    "Không cho phép thay đổi trạng thái kiểm duyệt trên dữ liệu kiểm thử mô phỏng (mock).",
                    http_status=403,
                )
            existing = next((w for w in items if w["id"] == finding_id), None)
            if existing is None:
                raise ApiServiceError(
                    "FINDING_NOT_FOUND",
                    f"Không tìm thấy cảnh báo {finding_id!r} trong phiên quét {scan_id!r}.",
                    http_status=404,
                )

            # Authoritative revalidation immediately before opening writable ReviewStore.
            live_entry = self._revalidate_entry(entry)
            if not live_entry.writable:
                raise ApiServiceError(
                    "SCAN_READ_ONLY",
                    "Phiên quét này thuộc vùng dữ liệu chỉ đọc; không cho phép thay đổi trạng thái kiểm duyệt.",
                    http_status=403,
                )

            store = ReviewStore(live_entry.db_path)
            revoked_error: list[ApiServiceError | None] = [None]

            def _assert_owner_valid_in_tx() -> int:
                """In-transaction owner & publication guard invoked by SQLite TEMP triggers before every write."""
                try:
                    rechecked = self._revalidate_entry(live_entry)
                    if not rechecked.writable:
                        revoked_error[0] = ApiServiceError(
                            "SCAN_READ_ONLY",
                            "Phiên quét này thuộc vùng dữ liệu chỉ đọc; không cho phép thay đổi trạng thái kiểm duyệt.",
                            http_status=403,
                        )
                        return 0
                    return 1
                except ApiServiceError as exc:
                    revoked_error[0] = exc
                    return 0
                except Exception as exc:
                    revoked_error[0] = ApiServiceError(
                        "SCAN_NOT_FOUND",
                        f"Quyền sở hữu phiên quét không còn hợp lệ tại điểm commit kiểm duyệt: {exc}",
                        http_status=404,
                    )
                    return 0

            try:
                # Attach connection-local TEMP triggers (never persisted to review.sqlite schema) so ANY owner
                # revocation occurring before INSERT INTO events / UPDATE warnings / INSERT INTO rejected_decisions
                # aborts inside ReviewStore.decide()'s BEGIN IMMEDIATE transaction and rolls back cleanly!
                store.db.create_function("_ntk_assert_owner_valid", 0, _assert_owner_valid_in_tx)
                store.db.executescript(
                    """
                    CREATE TEMP TRIGGER _ntk_guard_events_insert
                    BEFORE INSERT ON main.events
                    BEGIN
                        SELECT CASE WHEN _ntk_assert_owner_valid() = 0
                             THEN RAISE(ABORT, 'NTK_OWNER_REVOKED') END;
                    END;
                    CREATE TEMP TRIGGER _ntk_guard_warnings_update
                    BEFORE UPDATE ON main.warnings
                    BEGIN
                        SELECT CASE WHEN _ntk_assert_owner_valid() = 0
                             THEN RAISE(ABORT, 'NTK_OWNER_REVOKED') END;
                    END;
                    CREATE TEMP TRIGGER _ntk_guard_rejected_insert
                    BEFORE INSERT ON main.rejected_decisions
                    BEGIN
                        SELECT CASE WHEN _ntk_assert_owner_valid() = 0
                             THEN RAISE(ABORT, 'NTK_OWNER_REVOKED') END;
                    END;
                    """
                )
                store.decide(finding_id, action, actor.strip(), reason.strip())
            except sqlite3.IntegrityError as exc:
                if revoked_error[0] is not None:
                    raise revoked_error[0] from exc
                raise
            except StaleSourceError as exc:
                _, items_after, _, _, events_after, rejected_after = self._read_scan_snapshot(
                    live_entry,
                    finding_id=finding_id,
                    include_audit=True,
                    events_desc=False,
                )
                cur_row = next((w for w in items_after if w["id"] == finding_id), None)
                cur_state = cur_row["state"] if cur_row else existing["state"]
                raise ApiServiceError(
                    "STALE_SOURCE",
                    "Mã nguồn Java đã thay đổi hoặc bị thiếu so với thời điểm quét (STALE_SOURCE). Từ chối xác nhận cảnh báo giả; cảnh báo được giữ nguyên để quét lại.",
                    http_status=409,
                    extra={
                        "finding_id": finding_id,
                        "scan_id": live_entry.scan_id,
                        "human_review_state": cur_state,
                        "stale_source": exc.to_dict(),
                        "review_events": events_after,
                        "rejected_decisions": rejected_after,
                    },
                ) from exc
            except EvidenceError as exc:
                msg = str(exc)
                status_code = 409 if action == "confirm-false" else 400
                err_code = "CONFIRM_FALSE_REFUSED" if action == "confirm-false" else "REVIEW_DECISION_REFUSED"
                _, items_after, _, _ = self._read_scan_rows(live_entry)
                cur_row = next((w for w in items_after if w["id"] == finding_id), None)
                cur_state = cur_row["state"] if cur_row else existing["state"]
                raise ApiServiceError(
                    err_code,
                    f"Từ chối thao tác kiểm duyệt ({action}): {msg}",
                    http_status=status_code,
                    extra={
                        "finding_id": finding_id,
                        "scan_id": live_entry.scan_id,
                        "human_review_state": cur_state,
                    },
                ) from exc
            finally:
                store.close()

            committed_scan_id = live_entry.scan_id
            return self.get_finding_detail(committed_scan_id, finding_id)

    @staticmethod
    def _is_sha256_hex(value: Any) -> bool:
        return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)

    @staticmethod
    def _parse_iso_tz_timestamp(value: Any, label: str) -> datetime:
        if not isinstance(value, str) or not value.strip():
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                f"Trường timestamp của {label} bị thiếu hoặc sai kiểu.",
                http_status=409,
            )
        normalized = value.strip()
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(normalized)
        except ValueError as exc:
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                f"Định dạng timestamp của {label} không hợp lệ: {exc}",
                http_status=409,
            ) from exc
        if dt.tzinfo is None:
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                f"Timestamp của {label} thiếu múi giờ ISO-8601.",
                http_status=409,
            )
        return dt

    @classmethod
    def _verify_sqlite_audit_history(
        cls,
        bundle: dict[str, Any],
        items: list[dict[str, Any]],
        events_asc: list[dict[str, Any]],
        rejected_asc: list[dict[str, Any]],
    ) -> None:
        """Verify SQLite events and rejected_decisions against the exact ReviewStore write contract."""
        items_by_id = {w["id"]: w for w in items}
        sim_states: dict[str, str] = {wid: "OPEN" for wid in items_by_id}
        action_to_state = {
            "confirm-true": "CONFIRMED_TRUE",
            "confirm-false": "CONFIRMED_FALSE",
            "reopen": "OPEN",
        }

        bundle_collected_dt: datetime | None = None
        if isinstance(bundle.get("collected_at"), str) and bundle["collected_at"].strip():
            try:
                bundle_collected_dt = cls._parse_iso_tz_timestamp(bundle["collected_at"], "bundle.collected_at")
            except ApiServiceError:
                bundle_collected_dt = None

        prev_ev_ts: datetime | None = None
        for idx, ev in enumerate(events_asc):
            if ev.get("sequence") != idx + 1:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Thứ tự sequence của event #{idx + 1} trong review.sqlite không hợp lệ.",
                    http_status=409,
                )
            wid = ev.get("warning_id")
            act = ev.get("action")
            if not isinstance(wid, str) or wid not in items_by_id or act not in action_to_state:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Event #{idx + 1} trong review.sqlite có warning_id hoặc action không hợp lệ.",
                    http_status=409,
                )
            actor = ev.get("actor")
            reason = ev.get("reason")
            if (
                not isinstance(actor, str)
                or not actor.strip()
                or actor != actor.strip()
                or not isinstance(reason, str)
                or not reason.strip()
                or reason != reason.strip()
            ):
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Event #{idx + 1} trong review.sqlite thiếu actor hoặc reason hợp lệ.",
                    http_status=409,
                )

            ev_ts = cls._parse_iso_tz_timestamp(ev.get("timestamp"), f"events[{idx}]")
            if prev_ev_ts is not None and ev_ts < prev_ev_ts:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Timestamp của event #{idx + 1} lùi ngược trước event liền trước.",
                    http_status=409,
                )
            if bundle_collected_dt is not None and ev_ts < bundle_collected_dt:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Timestamp của event #{idx + 1} xảy ra trước thời điểm thu thập bằng chứng scan.",
                    http_status=409,
                )
            prev_ev_ts = ev_ts

            rec = items_by_id[wid]["evidence"]
            expected_snapshots = rec.get("snapshots") if isinstance(rec.get("snapshots"), dict) else {}
            expected_hashes = {
                p: snap.get("sha256")
                for p, snap in expected_snapshots.items()
                if isinstance(snap, dict)
            }
            canonical_rec = json.dumps(rec, ensure_ascii=False, sort_keys=True)
            expected_ev_sha = digest(canonical_rec.encode("utf-8"))
            if ev.get("evidence_sha256") != expected_ev_sha:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Mã băm evidence_sha256 của event #{idx + 1} không khớp bằng chứng trong SQLite.",
                    http_status=409,
                )

            canonical_sv = json.dumps(expected_snapshots, ensure_ascii=False, sort_keys=True)
            raw_sv = ev.get("source_version")
            raw_ov = ev.get("observed_version")
            try:
                sv_doc = strict_json(raw_sv) if isinstance(raw_sv, str) else None
                ov_doc = strict_json(raw_ov) if isinstance(raw_ov, str) else None
            except EvidenceError as exc:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"JSON source_version/observed_version của event #{idx + 1} bị hỏng: {exc}",
                    http_status=409,
                ) from exc

            if sv_doc != expected_snapshots or raw_sv != canonical_sv:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Trường source_version của event #{idx + 1} không khớp snapshot của cảnh báo.",
                    http_status=409,
                )
            if (
                not isinstance(ov_doc, dict)
                or set(ov_doc.keys()) != set(expected_snapshots.keys())
                or raw_ov != json.dumps(ov_doc, ensure_ascii=False, sort_keys=True)
                or any(
                    v != "MISSING_OR_UNREADABLE" and not cls._is_sha256_hex(v)
                    for v in ov_doc.values()
                )
            ):
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Trường observed_version của event #{idx + 1} không hợp lệ theo hợp đồng ReviewStore.",
                    http_status=409,
                )

            if act == "confirm-false":
                prov = rec.get("scan_provenance") if isinstance(rec.get("scan_provenance"), dict) else {}
                if (
                    rec.get("issues")
                    or not expected_snapshots
                    or prov.get("source_capture_verified") is not True
                    or ov_doc != expected_hashes
                ):
                    raise ApiServiceError(
                        "ARTIFACT_PROVENANCE_MISMATCH",
                        f"Event confirm-false #{idx + 1} vi phạm điều kiện toàn vẹn snapshot tại thời điểm kiểm duyệt.",
                        http_status=409,
                    )

            sim_states[wid] = action_to_state[act]

        for w in items:
            if w.get("state") != sim_states.get(w["id"]):
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Trạng thái Human Review của cảnh báo {w['id']!r} trong review.sqlite không khớp lịch sử events.",
                    http_status=409,
                )

        prev_rej_ts: datetime | None = None
        for idx, rj in enumerate(rejected_asc):
            if rj.get("sequence") != idx + 1:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Thứ tự sequence của rejected_decisions #{idx + 1} trong review.sqlite không hợp lệ.",
                    http_status=409,
                )
            wid = rj.get("warning_id")
            if not isinstance(wid, str) or wid not in items_by_id:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Bản ghi rejected_decisions #{idx + 1} tham chiếu warning_id không tồn tại.",
                    http_status=409,
                )
            actor = rj.get("actor")
            reason = rj.get("reason")
            if (
                not isinstance(actor, str)
                or not actor.strip()
                or actor != actor.strip()
                or not isinstance(reason, str)
                or not reason.strip()
                or reason != reason.strip()
            ):
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Bản ghi rejected_decisions #{idx + 1} thiếu actor hoặc reason hợp lệ.",
                    http_status=409,
                )
            if rj.get("attempted_action") != "confirm-false" or rj.get("rejection_code") != "STALE_SOURCE":
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Bản ghi rejected_decisions #{idx + 1} có attempted_action/rejection_code không hợp lệ.",
                    http_status=409,
                )

            rj_ts = cls._parse_iso_tz_timestamp(rj.get("timestamp"), f"rejected_decisions[{idx}]")
            if prev_rej_ts is not None and rj_ts < prev_rej_ts:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Timestamp của rejected_decisions #{idx + 1} lùi ngược trước bản ghi liền trước.",
                    http_status=409,
                )
            if bundle_collected_dt is not None and rj_ts < bundle_collected_dt:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Timestamp của rejected_decisions #{idx + 1} xảy ra trước thời điểm thu thập scan.",
                    http_status=409,
                )
            prev_rej_ts = rj_ts

            rec = items_by_id[wid]["evidence"]
            prov = rec.get("scan_provenance") if isinstance(rec.get("scan_provenance"), dict) else {}
            expected_snapshots = rec.get("snapshots") if isinstance(rec.get("snapshots"), dict) else {}
            expected_hashes = {
                p: snap.get("sha256")
                for p, snap in expected_snapshots.items()
                if isinstance(snap, dict)
            }
            if rec.get("issues") or not expected_snapshots or prov.get("source_capture_verified") is not True:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Bản ghi rejected_decisions #{idx + 1} không phù hợp điều kiện từ chối STALE_SOURCE của cảnh báo.",
                    http_status=409,
                )

            raw_sv = rj.get("source_version")
            raw_ov = rj.get("observed_version")
            raw_det = rj.get("detail")
            try:
                sv_doc = strict_json(raw_sv) if isinstance(raw_sv, str) else None
                ov_doc = strict_json(raw_ov) if isinstance(raw_ov, str) else None
                det_doc = strict_json(raw_det) if isinstance(raw_det, str) else None
            except EvidenceError as exc:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"JSON trong rejected_decisions #{idx + 1} bị hỏng: {exc}",
                    http_status=409,
                ) from exc

            canonical_sv = json.dumps(expected_snapshots, ensure_ascii=False, sort_keys=True)
            if sv_doc != expected_snapshots or raw_sv != canonical_sv:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Trường source_version của rejected_decisions #{idx + 1} không khớp snapshot của cảnh báo.",
                    http_status=409,
                )
            if (
                not isinstance(ov_doc, dict)
                or set(ov_doc.keys()) != set(expected_snapshots.keys())
                or raw_ov != json.dumps(ov_doc, ensure_ascii=False, sort_keys=True)
                or any(
                    v != "MISSING_OR_UNREADABLE" and not cls._is_sha256_hex(v)
                    for v in ov_doc.values()
                )
                or ov_doc == expected_hashes
            ):
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Trường observed_version của rejected_decisions #{idx + 1} không chứng minh được sai khác mã nguồn.",
                    http_status=409,
                )

            actual_mismatched = {p for p, exp in expected_hashes.items() if ov_doc.get(p) != exp}
            if (
                not isinstance(det_doc, dict)
                or det_doc.get("error_code") != "STALE_SOURCE"
                or not isinstance(det_doc.get("message"), str)
                or not det_doc["message"].strip()
                or not isinstance(det_doc.get("mismatched_paths"), list)
                or not det_doc["mismatched_paths"]
                or set(det_doc["mismatched_paths"]) != actual_mismatched
                or det_doc.get("expected_hashes") != expected_hashes
                or det_doc.get("observed_hashes") != ov_doc
            ):
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Trường detail của rejected_decisions #{idx + 1} không khớp cấu trúc StaleSourceError.",
                    http_status=409,
                )

    @classmethod
    def _verify_review_sqlite_consistency(
        cls,
        entry: DiscoveredScan,
        expected_sha: str,
        bundle: dict[str, Any],
        ev_doc: dict[str, Any],
        items: list[dict[str, Any]],
        events_asc: list[dict[str, Any]],
        rejected_asc: list[dict[str, Any]],
    ) -> None:
        """Distinguish untouched review.sqlite (must match manifest SHA-256) from structurally verified Human Review updates."""
        if not entry.db_path.is_file():
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                "Thiếu tệp review.sqlite được khai báo trong g1-run-manifest.json.",
                http_status=409,
            )

        if bundle != ev_doc:
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                "Dữ liệu bundle bất biến trong review.sqlite không khớp với evidence.json.",
                http_status=409,
            )

        cls._verify_sqlite_audit_history(bundle, items, events_asc, rejected_asc)

        # Only exempt the pre-review whole-file SHA-256 baseline check after every event & rejected decision is verified consistent.
        if not events_asc and not rejected_asc:
            try:
                actual_sha = digest(entry.db_path.read_bytes())
            except OSError as exc:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Không thể đọc review.sqlite để đối chiếu mã băm: {exc}",
                    http_status=409,
                ) from exc
            if actual_sha != expected_sha:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    "Mã băm review.sqlite không khớp g1-run-manifest.json dù chưa có thao tác Human Review hợp lệ nào.",
                    http_status=409,
                )

    def _verify_g1_manifest(
        self,
        entry: DiscoveredScan,
        g1_doc: dict[str, Any],
        bundle: dict[str, Any],
        ev_doc: dict[str, Any],
        items: list[dict[str, Any]],
        events_asc: list[dict[str, Any]],
        rejected_asc: list[dict[str, Any]],
    ) -> bool:
        """Validate g1-run-manifest.json strictly against the G1 producer contract (`ntk-g1-run-manifest-1`)."""
        if not (entry.g1_manifest_path and entry.g1_manifest_path.is_file()):
            return False

        if g1_doc.get("schema") != "ntk-g1-run-manifest-1":
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                f"Schema của g1-run-manifest.json không hợp lệ: {g1_doc.get('schema')!r}.",
                http_status=409,
            )

        ollama_obj = g1_doc.get("ollama")
        if not isinstance(ollama_obj, dict):
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                "Trường ollama trong g1-run-manifest.json bắt buộc phải là đối tượng JSON hợp lệ.",
                http_status=409,
            )
        llm_enabled = ollama_obj.get("enabled")
        ollama_origin = ollama_obj.get("runtime_origin")
        if (
            type(llm_enabled) is not bool
            or not isinstance(ollama_origin, str)
            or not ollama_origin.strip()
            or (not llm_enabled and ollama_origin != "disabled")
            or (llm_enabled and ollama_origin == "disabled")
        ):
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                "Trường ollama.enabled/runtime_origin trong g1-run-manifest.json không nhất quán.",
                http_status=409,
            )

        has_mock_g1 = bool(g1_doc.get("runtime_origin") == "mock" or ollama_origin == "mock")
        if has_mock_g1 and self.config.runtime_origin != "mock":
            raise ApiServiceError(
                "TEST_DATA_ISOLATED",
                "Phát hiện runtime_origin='mock' trong g1-run-manifest.json; từ chối xuất báo cáo.",
                http_status=403,
            )

        for sha_key in ("scan_sha256", "raw_opengrep_json_sha256"):
            if g1_doc.get(sha_key) and g1_doc.get(sha_key) != entry.scan_sha256:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Mã băm {sha_key} trong g1-run-manifest.json không khớp với SQLite.",
                    http_status=409,
                )

        artifacts = g1_doc.get("artifacts")
        if not isinstance(artifacts, dict):
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                "Trường artifacts trong g1-run-manifest.json bắt buộc phải là đối tượng JSON hợp lệ.",
                http_status=409,
            )

        artifact_file_map = {
            "opengrep_json": entry.raw_json_path or (entry.base_dir / "capture" / "opengrep.json"),
            "opengrep_sarif": entry.base_dir / "capture" / "opengrep.sarif",
            "scan_manifest": entry.base_dir / "capture" / "scan-manifest.json",
            "cli_origin": entry.base_dir / "capture" / "cli-origin.json",
            "evidence_json": entry.evidence_path,
            "assessments_jsonl": entry.assessments_path or (entry.triage_dir / "assessments.jsonl"),
            "review_sqlite": entry.db_path,
            "http_capture_check": entry.triage_dir / "http-capture-check.json",
        }
        unknown_keys = sorted(set(artifacts.keys()) - set(artifact_file_map.keys()))
        if unknown_keys:
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                f"g1-run-manifest.json khai báo artifact không được hỗ trợ: {unknown_keys}.",
                http_status=409,
            )
        missing_keys = [k for k in artifact_file_map if k not in artifacts]
        if missing_keys:
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                f"g1-run-manifest.json thiếu khai báo artifact bắt buộc: {missing_keys}.",
                http_status=409,
            )

        for key, target_path in artifact_file_map.items():
            meta_entry = artifacts[key]
            if not isinstance(meta_entry, dict):
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Mục artifacts.{key} trong g1-run-manifest.json phải là đối tượng JSON hợp lệ.",
                    http_status=409,
                )
            declared_path = meta_entry.get("path")
            if not isinstance(declared_path, str) or not declared_path.strip() or target_path is None:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Mục artifacts.{key}.path trong g1-run-manifest.json không hợp lệ.",
                    http_status=409,
                )
            if Path(declared_path.replace("\\", "/")).name != target_path.name:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Tên tệp khai báo ở artifacts.{key}.path không khớp {target_path.name!r}.",
                    http_status=409,
                )
            if "sha256" not in meta_entry:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Thiếu trường sha256 ở artifacts.{key} trong g1-run-manifest.json.",
                    http_status=409,
                )
            expected_sha = meta_entry["sha256"]

            # Only http_capture_check may legitimately omit SHA-256 (`null`), strictly when LLM is disabled (--no-llm).
            if key == "http_capture_check" and not llm_enabled and expected_sha is None:
                if target_path.is_file():
                    raise ApiServiceError(
                        "ARTIFACT_PROVENANCE_MISMATCH",
                        "Tệp http-capture-check.json tồn tại trên đĩa dù manifest khai báo sha256=null (--no-llm).",
                        http_status=409,
                    )
                continue

            if not self._is_sha256_hex(expected_sha):
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Mã băm artifacts.{key}.sha256 trong g1-run-manifest.json thiếu hoặc không hợp lệ.",
                    http_status=409,
                )

            if key == "review_sqlite":
                self._verify_review_sqlite_consistency(
                    entry,
                    expected_sha,
                    bundle,
                    ev_doc,
                    items,
                    events_asc,
                    rejected_asc,
                )
                continue

            if not target_path.is_file():
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Thiếu artifact bắt buộc {key!r} được khai báo trong g1-run-manifest.json.",
                    http_status=409,
                )
            try:
                actual_sha = digest(target_path.read_bytes())
            except OSError as exc:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Không thể đọc artifact {key!r} được khai báo trong g1-run-manifest.json: {exc}",
                    http_status=409,
                ) from exc
            if actual_sha != expected_sha:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Mã băm SHA-256 của artifact {key!r} không khớp với g1-run-manifest.json.",
                    http_status=409,
                )
            if key == "opengrep_json" and expected_sha != entry.scan_sha256:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    "Mã băm artifacts.opengrep_json.sha256 không khớp với scan_sha256 trong SQLite.",
                    http_status=409,
                )

        findings_summary = g1_doc.get("findings_summary")
        if not isinstance(findings_summary, dict):
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                "Trường findings_summary trong g1-run-manifest.json bắt buộc phải là đối tượng JSON hợp lệ.",
                http_status=409,
            )
        if findings_summary.get("total_findings") != len(items):
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                "Số lượng cảnh báo trong findings_summary của g1-run-manifest.json không khớp với SQLite.",
                http_status=409,
            )
        expected_statuses = [
            w["assessment"].get("validated_status", w["assessment"].get("status"))
            for w in items
        ]
        if findings_summary.get("validated_statuses") != expected_statuses:
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                "Danh sách validated_statuses trong g1-run-manifest.json không khớp với SQLite.",
                http_status=409,
            )
        return has_mock_g1

    def _verify_evidence_and_raw_consistency(
        self,
        entry: DiscoveredScan,
        ev_doc: dict[str, Any],
        raw_json_bytes: bytes | None,
        items: list[dict[str, Any]],
    ) -> None:
        ev_records = ev_doc.get("records")
        if not isinstance(ev_records, list) or len(ev_records) != len(items):
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                "Danh sách records trong evidence.json không khớp với số cảnh báo trong SQLite.",
                http_status=409,
            )

        ev_by_id: dict[str, dict[str, Any]] = {}
        for rec in ev_records:
            if not isinstance(rec, dict) or not isinstance(rec.get("id"), str) or rec["id"] in ev_by_id:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    "Bản ghi trong evidence.json không hợp lệ hoặc bị trùng ID.",
                    http_status=409,
                )
            ev_by_id[rec["id"]] = rec

        raw_results: list[Any] | None = None
        if raw_json_bytes is not None:
            try:
                raw_doc = strict_json(raw_json_bytes.decode("utf-8"))
            except (UnicodeDecodeError, EvidenceError) as exc:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Tệp OpenGrep JSON gốc không hợp lệ: {exc}",
                    http_status=409,
                ) from exc
            if not isinstance(raw_doc, dict) or not isinstance(raw_doc.get("results"), list):
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    "Tệp OpenGrep JSON gốc thiếu danh sách results[].",
                    http_status=409,
                )
            raw_results = raw_doc["results"]
            if len(raw_results) != len(items):
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    "Số lượng kết quả trong OpenGrep JSON gốc không khớp với SQLite.",
                    http_status=409,
                )

        immutable_ev_fields = (
            "id",
            "alert_id",
            "finding_index",
            "scan_sha256", "root",
            "rule_id",
            "cwe",
            "severity",
            "path",
            "start",
            "end",
            "snapshots",
            "snippets",
            "raw_finding",
            "raw_trace",
            "issues",
            "scan_provenance",
        )
        for sql_item in items:
            fid = sql_item["id"]
            sql_ev = sql_item.get("evidence")
            if not isinstance(sql_ev, dict) or fid not in ev_by_id:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Thiếu hoặc sai cấu trúc evidence cho cảnh báo {fid!r} giữa SQLite và evidence.json.",
                    http_status=409,
                )
            ev_rec = ev_by_id[fid]
            for field_name in immutable_ev_fields:
                if ev_rec.get(field_name) != sql_ev.get(field_name):
                    raise ApiServiceError(
                        "ARTIFACT_PROVENANCE_MISMATCH",
                        f"Trường evidence.{field_name} của cảnh báo {fid!r} không khớp giữa SQLite và evidence.json.",
                        http_status=409,
                    )
            if raw_results is not None:
                f_idx = sql_ev.get("finding_index")
                if (
                    type(f_idx) is not int
                    or not (0 <= f_idx < len(raw_results))
                    or digest(f"{entry.scan_sha256}:{f_idx}".encode("utf-8")) != fid
                    or not isinstance(raw_results[f_idx], dict)
                    or raw_results[f_idx].get("check_id") != sql_ev.get("rule_id")
                    or raw_results[f_idx] != sql_ev.get("raw_finding")
                ):
                    raise ApiServiceError(
                        "ARTIFACT_PROVENANCE_MISMATCH",
                        f"Evidence cảnh báo {fid!r} trong SQLite không khớp với kết quả OpenGrep JSON gốc.",
                        http_status=409,
                    )

    @staticmethod
    def _verify_jsonl_row_matches_sqlite(
        row: dict[str, Any],
        sql_item: dict[str, Any],
        *,
        strict_exact_assessment: bool = False,
        allow_omitted_runtime: bool = False,
    ) -> None:
        fid = sql_item["id"]
        row_ev = row["evidence"]
        sql_ev = sql_item["evidence"]
        immutable_ev_fields = (
            "id",
            "alert_id",
            "finding_index",
            "scan_sha256", "root",
            "rule_id",
            "cwe",
            "severity",
            "path",
            "start",
            "end",
            "snapshots",
            "snippets",
            "raw_finding",
            "raw_trace",
            "java_context",
            "heuristic_signals",
            "prompt_contract",
            "issues",
            "scan_provenance",
        )
        for field_name in immutable_ev_fields:
            if row_ev.get(field_name) != sql_ev.get(field_name):
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Trường evidence.{field_name} của cảnh báo {fid!r} trong assessments.jsonl không khớp với SQLite.",
                    http_status=409,
                )

        row_ass = row["assessment"]
        sql_ass = sql_item["assessment"]
        if (
            row.get("alert_id") is not None and row.get("alert_id") != sql_ev.get("alert_id", fid)
        ) or (
            row.get("finding_index") is not None and row.get("finding_index") != sql_ev.get("finding_index")
        ) or (
            row.get("raw_model_status") != sql_ass.get("raw_model_status")
            and "raw_model_status" in row
        ) or (
            row.get("validated_status") is not None
            and row.get("validated_status") != sql_ass.get("validated_status", sql_ass.get("status"))
        ):
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                f"Trường định danh hoặc trạng thái cấp dòng của cảnh báo {fid!r} trong assessments.jsonl không khớp với SQLite.",
                http_status=409,
            )
        if strict_exact_assessment and row_ass != sql_ass:
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                f"Dữ liệu assessment bất biến của cảnh báo {fid!r} trong SQLite đã bị thay đổi so với assessments.jsonl đã niêm phong.",
                http_status=409,
            )
        if (
            row_ass.get("status") != sql_ass.get("status")
            or row_ass.get("validated_status", row_ass.get("status")) != sql_ass.get("validated_status", sql_ass.get("status"))
            or row_ass.get("raw_model_status") != sql_ass.get("raw_model_status")
            or bool(row_ass.get("validator_downgraded")) != bool(sql_ass.get("validator_downgraded"))
            or row_ass.get("downgrade_reason") != sql_ass.get("downgrade_reason")
            or row_ass.get("failure_kind") != sql_ass.get("failure_kind")
            or row_ass.get("citation_check") != sql_ass.get("citation_check")
            or row_ass.get("citation_provenance") != sql_ass.get("citation_provenance")
            or (row_ass.get("citations") or []) != (sql_ass.get("citations") or [])
            or row_ass.get("raw_model_citations") != sql_ass.get("raw_model_citations")
            or row_ass.get("explanation") != sql_ass.get("explanation")
            or (row_ass.get("fix_suggestion") or "") != (sql_ass.get("fix_suggestion") or "")
            or bool(row_ass.get("requires_human_review", True)) != bool(sql_ass.get("requires_human_review", True))
            or bool(row_ass.get("security_conclusion_verified", False)) != bool(sql_ass.get("security_conclusion_verified", False))
            or bool(row_ass.get("supports_security_claim_verified", False)) != bool(sql_ass.get("supports_security_claim_verified", False))
            or row_ass.get("independent_refutation_proof") != sql_ass.get("independent_refutation_proof")
            or row_ass.get("prompt_version") != sql_ass.get("prompt_version")
            or row_ass.get("prompt_contract") != sql_ass.get("prompt_contract")
            or row_ass.get("prompt_sha256") != sql_ass.get("prompt_sha256")
            or row_ass.get("model") != sql_ass.get("model")
            or row_ass.get("transport") != sql_ass.get("transport")
            or row_ass.get("endpoint") != sql_ass.get("endpoint")
            or row_ass.get("raw_response") != sql_ass.get("raw_response")
            or row_ass.get("analyzed_at") != sql_ass.get("analyzed_at")
            or row_ass.get("elapsed_seconds") != sql_ass.get("elapsed_seconds")
            or row_ass.get("latency_ms") != sql_ass.get("latency_ms")
        ):
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                f"Trường assessment của cảnh báo {fid!r} trong assessments.jsonl không khớp với SQLite.",
                http_status=409,
            )

        if allow_omitted_runtime and "runtime" not in row_ass:
            return

        row_rt = row_ass.get("runtime") if isinstance(row_ass.get("runtime"), dict) else {}
        sql_rt = sql_ass.get("runtime") if isinstance(sql_ass.get("runtime"), dict) else {}
        if bool(row_rt.get("model_runtime_verified", False)) != bool(sql_rt.get("model_runtime_verified", False)):
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                f"Trạng thái model_runtime_verified của cảnh báo {fid!r} trong assessments.jsonl không khớp với SQLite.",
                http_status=409,
            )
        for rt_key in set(row_rt.keys()) | set(sql_rt.keys()):
            if row_rt.get(rt_key) != sql_rt.get(rt_key):
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Thông tin runtime.{rt_key} của cảnh báo {fid!r} trong assessments.jsonl không khớp với SQLite.",
                    http_status=409,
                )

    def _verify_report_artifacts(
        self,
        entry: DiscoveredScan,
        bundle: dict[str, Any],
        items: list[dict[str, Any]],
        events_asc: list[dict[str, Any]],
        rejected_asc: list[dict[str, Any]],
    ) -> tuple[str, dict[str, Any] | None]:
        """Cross-check provenance and immutable content across SQLite, evidence.json, raw JSON, G1 manifest, and assessments.jsonl."""
        # 1. Verify optional manifest/meta files are readable valid JSON objects if present and match scan_sha256.
        meta_doc = self._read_json_object_artifact(entry.meta_path, "api-scan-meta.json")
        self._verify_meta_artifact_hashes(entry, meta_doc)
        if meta_doc.get("scan_sha256") and meta_doc.get("scan_sha256") != entry.scan_sha256:
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                "Mã băm scan_sha256 trong api-scan-meta.json không khớp với SQLite.",
                http_status=409,
            )

        g1_doc = self._read_json_object_artifact(entry.g1_manifest_path, "g1-run-manifest.json")

        # 2. Cross-check evidence.json against SQLite bundle.
        if not entry.evidence_path or not entry.evidence_path.is_file():
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                "Thiếu tệp evidence.json để đối chiếu provenance trước khi xuất báo cáo.",
                http_status=409,
            )
        try:
            ev_doc = strict_json(entry.evidence_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, EvidenceError) as exc:
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                f"Tệp evidence.json bị hỏng hoặc không đọc được: {exc}",
                http_status=409,
            ) from exc
        if not isinstance(ev_doc, dict):
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                "Tệp evidence.json phải là đối tượng JSON hợp lệ.",
                http_status=409,
            )
        if ev_doc.get("scan_sha256") != entry.scan_sha256 or bundle.get("scan_sha256") != entry.scan_sha256:
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                "Mã băm scan_sha256 giữa evidence.json và SQLite không khớp.",
                http_status=409,
            )
        if ev_doc.get("scan_provenance") != bundle.get("scan_provenance"):
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                "Thông tin scan_provenance giữa evidence.json và SQLite không khớp.",
                http_status=409,
            )

        # 3. Verify raw OpenGrep JSON hash if present, then cross-check G1 manifest + evidence records + raw findings.
        raw_json_bytes: bytes | None = None
        if entry.raw_json_path and entry.raw_json_path.is_file():
            try:
                raw_json_bytes = entry.raw_json_path.read_bytes()
            except OSError as exc:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Không đọc được tệp raw OpenGrep JSON: {exc}",
                    http_status=409,
                ) from exc
            if digest(raw_json_bytes) != entry.scan_sha256:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    "Mã băm SHA-256 của tệp OpenGrep JSON gốc không khớp với scan_sha256 trong SQLite.",
                    http_status=409,
                )

        has_mock_g1 = self._verify_g1_manifest(entry, g1_doc, bundle, ev_doc, items, events_asc, rejected_asc)
        if not has_mock_g1 and not (entry.g1_manifest_path and entry.g1_manifest_path.is_file()):
            # Even when no g1-run-manifest.json exists, audit history tables in SQLite must obey ReviewStore contracts.
            self._verify_sqlite_audit_history(bundle, items, events_asc, rejected_asc)
        self._verify_evidence_and_raw_consistency(entry, ev_doc, raw_json_bytes, items)

        # 4. Cross-check assessments.jsonl when present and validate paired_pilot_export fail-closed.
        has_mock_jsonl = False
        has_cached_jsonl = False
        paired_export: dict[str, Any] | None = None
        if entry.assessments_path and entry.assessments_path.is_file():
            if raw_json_bytes is None:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    "Tồn tại assessments.jsonl nhưng thiếu tệp OpenGrep JSON gốc để đối chiếu.",
                    http_status=409,
                )
            jsonl_rows, has_mock_jsonl = self._inspect_assessments_jsonl(entry.assessments_path)
            has_cached_jsonl = any(
                self._has_cached_triage_marker(r.get("assessment"))
                or self._has_cached_triage_marker((r.get("assessment") or {}).get("runtime"))
                for r in jsonl_rows
                if isinstance(r, dict)
            )
            if has_mock_jsonl and self.config.runtime_origin != "mock":
                raise ApiServiceError(
                    "TEST_DATA_ISOLATED",
                    "Phát hiện dữ liệu runtime mock trong assessments.jsonl; từ chối xuất báo cáo.",
                    http_status=403,
                )

            if len(jsonl_rows) != len(items):
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    "Số lượng bản ghi trong assessments.jsonl không khớp với bảng warnings trong SQLite.",
                    http_status=409,
                )

            items_by_id = {w["id"]: w for w in items}
            seen_ids: set[str] = set()
            for row in jsonl_rows:
                row_id = row.get("id")
                row_ev = row["evidence"]
                if not isinstance(row_id, str) or row_id in seen_ids or row_id not in items_by_id:
                    raise ApiServiceError(
                        "ARTIFACT_PROVENANCE_MISMATCH",
                        "Danh sách cảnh báo trong assessments.jsonl không khớp với SQLite.",
                        http_status=409,
                    )
                seen_ids.add(row_id)
                if row.get("scan_sha256") != entry.scan_sha256 or row_ev.get("scan_sha256") != entry.scan_sha256:
                    raise ApiServiceError(
                        "ARTIFACT_PROVENANCE_MISMATCH",
                        "Mã băm scan_sha256 trong assessments.jsonl không khớp với SQLite.",
                        http_status=409,
                    )
                self._verify_jsonl_row_matches_sqlite(
                    row,
                    items_by_id[row_id],
                    strict_exact_assessment=entry.is_managed,
                    allow_omitted_runtime=False,
                )

            try:
                alerts_doc, triage_doc = export_pilot.adapt(jsonl_rows, raw_json_bytes)
            except Exception as exc:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    f"Không thể đối chiếu paired_pilot_export từ assessments.jsonl và raw JSON: {exc}",
                    http_status=409,
                ) from exc

            triage_results = triage_doc.get("triage_results", [])
            for tr in triage_results:
                if not isinstance(tr, dict):
                    raise ApiServiceError(
                        "ARTIFACT_PROVENANCE_MISMATCH",
                        "Bản ghi paired_pilot_export không hợp lệ.",
                        http_status=409,
                    )
                tr_rt = tr.get("runtime") if isinstance(tr.get("runtime"), dict) else {}
                if self.config.runtime_origin != "mock" and tr_rt.get("origin") == "mock":
                    raise ApiServiceError(
                        "TEST_DATA_ISOLATED",
                        "Kết quả paired_pilot_export chứa runtime mock; từ chối xuất báo cáo.",
                        http_status=403,
                    )
                sql_item = items_by_id.get(str(tr.get("alert_id")))
                if sql_item is None:
                    raise ApiServiceError(
                        "ARTIFACT_PROVENANCE_MISMATCH",
                        "Kết quả paired_pilot_export không khớp alert_id trong SQLite.",
                        http_status=409,
                    )
                sql_ass = sql_item["assessment"]
                sql_rt = sql_ass.get("runtime") if isinstance(sql_ass.get("runtime"), dict) else {}
                if (
                    tr.get("model_status") != sql_ass.get("status")
                    or bool(tr_rt.get("model_runtime_verified", False)) != bool(sql_rt.get("model_runtime_verified", False))
                ):
                    raise ApiServiceError(
                        "ARTIFACT_PROVENANCE_MISMATCH",
                        "Kết quả paired_pilot_export mâu thuẫn trạng thái hoặc xác minh runtime với SQLite.",
                        http_status=409,
                    )
            paired_export = {"alerts": alerts_doc, "triage": triage_doc}

        # 5. Final origin classification across all verified artifacts.
        effective_meta = dict(meta_doc)
        if (
            has_mock_jsonl
            or has_mock_g1
            or self._has_mock_provenance_marker(ev_doc)
            or self._has_mock_provenance_marker(ev_doc.get("metadata"))
            or any(
                self._has_mock_provenance_marker(r) or self._has_mock_provenance_marker(r.get("metadata"))
                for r in (ev_doc.get("records") or [])
                if isinstance(r, dict)
            )
            or (ev_doc.get("scan_provenance") or {}).get("origin") == "UNIT_TEST_MOCK_CAPTURE"
        ):
            effective_meta["_contains_mock_runtime"] = True
        if has_cached_jsonl:
            effective_meta["_contains_cached_triage"] = True
        if (
            self._has_explicit_non_real_origin(ev_doc)
            or self._has_explicit_non_real_origin(ev_doc.get("metadata"))
            or any(
                self._has_explicit_non_real_origin(r) or self._has_explicit_non_real_origin(r.get("metadata"))
                for r in (ev_doc.get("records") or [])
                if isinstance(r, dict)
            )
        ):
            effective_meta["_contains_non_real_origin"] = True
        data_origin = self._classify_data_origin(bundle, items, effective_meta)
        if data_origin == "MOCK_SYNTHETIC_TEST" and self.config.runtime_origin != "mock":
            raise ApiServiceError(
                "TEST_DATA_ISOLATED",
                "Không cho phép xuất dữ liệu kiểm thử mô phỏng (mock) thành báo cáo thực.",
                http_status=403,
            )
        if data_origin == "REAL_SCAN" and raw_json_bytes is None:
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                "Thiếu tệp kết quả OpenGrep gốc để xác minh báo cáo REAL_SCAN.",
                http_status=409,
            )
        return data_origin, paired_export

    def export_scan_report(self, scan_id: str) -> dict[str, Any]:
        entry = self.resolve_scan(scan_id)
        live_entry = self._revalidate_entry(entry)
        bundle, items, g1_doc, meta_doc, events_desc, rejected_desc = self._read_scan_snapshot(
            live_entry,
            finding_id=None,
            include_audit=True,
            events_desc=True,
        )
        early_origin = self._classify_data_origin(bundle, items, meta_doc)
        if early_origin == "MOCK_SYNTHETIC_TEST" and self.config.runtime_origin != "mock":
            raise ApiServiceError(
                "TEST_DATA_ISOLATED",
                "Không cho phép xuất dữ liệu kiểm thử mô phỏng (mock) thành báo cáo thực.",
                http_status=403,
            )

        events_asc = list(reversed(events_desc))
        rejected_asc = list(reversed(rejected_desc))
        live_entry = self._revalidate_entry(live_entry)
        data_origin, paired_export = self._verify_report_artifacts(live_entry, bundle, items, events_asc, rejected_asc)
        summary = self._build_scan_summary_from_snapshot(live_entry, bundle, items, g1_doc, meta_doc)
        events_by_wid: dict[str, list[dict[str, Any]]] = {}
        for ev in events_asc:
            events_by_wid.setdefault(str(ev.get("warning_id")), []).append(ev)
        rejected_by_wid: dict[str, list[dict[str, Any]]] = {}
        for rj in rejected_asc:
            rejected_by_wid.setdefault(str(rj.get("warning_id")), []).append(rj)

        detailed_findings = [
            self._build_finding_detail_from_snapshot(
                live_entry,
                data_origin,
                w,
                events_by_wid.get(w["id"], []),
                rejected_by_wid.get(w["id"], []),
            )
            for w in items
        ]

        return {
            "report_schema": REPORT_SCHEMA,
            "contract_schema": API_CONTRACT_SCHEMA,
            "generated_at": now(),
            "data_origin": data_origin,
            "contains_mock_or_test_data": data_origin == "MOCK_SYNTHETIC_TEST",
            "scan_summary": summary,
            "audit_trail": {
                "events_count": len(events_desc),
                "rejected_decisions_count": len(rejected_desc),
                "events": events_desc,
                "rejected_decisions": rejected_desc,
            },
            "paired_pilot_export": paired_export,
            "paired_pilot_export_error": None,
            "findings": detailed_findings,
        }
