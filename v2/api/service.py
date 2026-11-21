"""Core read, health, human-review, and provenance-preserving report service for v2.api.

All read endpoints query SQLite strictly via read-only URI (`?mode=ro`) so inspecting
existing scans (Flow A) never mutates `review.sqlite` or creates journal files.
All human review mutations (Flow B) delegate directly to `v2.triage.store.ReviewStore`.
"""
from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path
import shutil
import sqlite3
import threading
from typing import Any

from v2.api import API_CONTRACT_SCHEMA, API_SERVICE_NAME, API_VERSION, REPORT_SCHEMA
from v2.api.config import ApiConfig
from v2.g1_integration.bridge import KNOWN_ANALYSIS_LIMITS
from v2.g1_integration.fork_support.scanner_config import validate_opengrep_binary
from v2.triage import export_pilot
from v2.triage.evidence import EvidenceError, StaleSourceError, digest, now, strict_json
from v2.triage.ollama import PROMPT_VERSION, OllamaClient
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


def _inspect_candidate_dir(candidate: Path, *, writable: bool) -> DiscoveredScan | None:
    if not candidate.is_dir():
        return None
    if (candidate / "triage" / "review.sqlite").is_file() and (candidate / "triage" / "evidence.json").is_file():
        triage_dir = candidate / "triage"
    elif (candidate / "review.sqlite").is_file() and (candidate / "evidence.json").is_file():
        triage_dir = candidate
    else:
        return None

    db_path = triage_dir / "review.sqlite"
    evidence_path = triage_dir / "evidence.json"
    try:
        with _open_ro_sqlite(db_path) as conn:
            row = conn.execute("SELECT id FROM scans ORDER BY rowid DESC LIMIT 1").fetchone()
            if row is None or not row["id"]:
                return None
            scan_sha = str(row["id"])
    except (OSError, sqlite3.Error):
        return None

    meta_path = candidate / "api-scan-meta.json"
    explicit_id = None
    if meta_path.is_file():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            if isinstance(meta, dict) and isinstance(meta.get("scan_id"), str) and meta["scan_id"].strip():
                explicit_id = meta["scan_id"].strip()
        except (OSError, ValueError):
            explicit_id = None

    raw_json_path = triage_dir / "input.opengrep.json"
    if not raw_json_path.is_file():
        alt = candidate / "capture" / "opengrep.json"
        raw_json_path = alt if alt.is_file() else None

    assessments_path = triage_dir / "assessments.jsonl"
    if not assessments_path.is_file():
        assessments_path = None

    g1_manifest = candidate / "g1-run-manifest.json"
    if not g1_manifest.is_file():
        g1_manifest = None

    return DiscoveredScan(
        scan_id=explicit_id or scan_sha,
        scan_sha256=scan_sha,
        base_dir=candidate.resolve(),
        triage_dir=triage_dir.resolve(),
        db_path=db_path.resolve(),
        evidence_path=evidence_path.resolve(),
        assessments_path=assessments_path.resolve() if assessments_path else None,
        raw_json_path=raw_json_path.resolve() if raw_json_path else None,
        g1_manifest_path=g1_manifest.resolve() if g1_manifest else None,
        meta_path=meta_path.resolve() if meta_path.is_file() else None,
        writable=writable,
    )


class TriageApiService:
    def __init__(self, config: ApiConfig):
        self.config = config
        self._review_lock = threading.Lock()

    def probe_opengrep(self, *, force: bool = False) -> dict[str, Any]:  # noqa: ARG002
        """Inspect configured OpenGrep binary path without spawning subprocesses, WSL2, or probe threads."""
        binary = self.config.opengrep_binary
        try:
            validate_opengrep_binary(binary)
        except ValueError as exc:
            return {
                "available": False,
                "executable": binary,
                "resolved_path": None,
                "version": None,
                "probe_status": "UNAVAILABLE",
                "runtime_verified": False,
                "error": str(exc),
            }

        resolved = binary if Path(binary).is_file() else shutil.which(binary)
        if not resolved:
            return {
                "available": False,
                "executable": binary,
                "resolved_path": None,
                "version": None,
                "probe_status": "UNAVAILABLE",
                "runtime_verified": False,
                "error": f"Không tìm thấy binary OpenGrep ({binary!r}) trong PATH.",
            }

        return {
            "available": False,
            "executable": binary,
            "resolved_path": str(resolved),
            "version": None,
            "probe_status": "NOT_VERIFIED",
            "runtime_verified": False,
            "error": "Không chạy kiểm tra OpenGrep trên /api/health; phiên bản chỉ được xác minh khi thực thi scan job.",
        }

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

        og = self.probe_opengrep()
        ol = self.probe_ollama()
        git_path = shutil.which("git")
        rules_ok = self.config.rules_path.is_file()
        rules_sha = digest(self.config.rules_path.read_bytes()) if rules_ok else None

        degraded: list[str] = []
        if not og["available"]:
            degraded.append(
                "OPENGREP_NOT_VERIFIED" if og.get("probe_status") == "NOT_VERIFIED" else "OPENGREP_UNAVAILABLE"
            )
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
                "name": self.config.rules_path.name,
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

    def discover_scans(self) -> list[DiscoveredScan]:
        found: dict[str, DiscoveredScan] = {}

        def _scan_root(root: Path, *, writable: bool) -> None:
            if not root.exists() or not root.is_dir():
                return
            direct = _inspect_candidate_dir(root, writable=writable)
            if direct is not None:
                found.setdefault(direct.scan_id, direct)
                return
            try:
                children = sorted(root.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
            except OSError:
                return
            for child in children:
                if not child.is_dir():
                    continue
                inspected = _inspect_candidate_dir(child, writable=writable)
                if inspected is not None:
                    if inspected.scan_id in found and inspected.base_dir != found[inspected.scan_id].base_dir:
                        disambiguated = f"{inspected.scan_sha256[:16]}-{child.name}"
                        inspected = DiscoveredScan(
                            **{**inspected.__dict__, "scan_id": disambiguated}
                        )
                    found.setdefault(inspected.scan_id, inspected)

        _scan_root(self.config.data_dir / "scans", writable=True)
        for rw_dir in self.config.reviewable_scan_dirs:
            _scan_root(rw_dir, writable=True)
        for ro_dir in self.config.readonly_scan_dirs:
            _scan_root(ro_dir, writable=False)

        return list(found.values())

    def resolve_scan(self, scan_id: str) -> DiscoveredScan:
        if not isinstance(scan_id, str) or not scan_id.strip():
            raise ApiServiceError("INVALID_SCAN_ID", "Mã phiên quét không hợp lệ.", http_status=400)
        wanted = scan_id.strip()
        scans = self.discover_scans()
        for entry in scans:
            if entry.scan_id == wanted:
                return entry
        for entry in scans:
            if entry.scan_sha256 == wanted:
                return entry
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

    def _inspect_assessments_jsonl(self, assessments_path: Path) -> tuple[list[dict[str, Any]], bool]:
        """Strictly parse and type-check assessments.jsonl; fail-closed with 409 on corrupt or malformed rows."""
        try:
            jsonl_text = assessments_path.read_text(encoding="utf-8")
            jsonl_rows = [strict_json(line) for line in jsonl_text.splitlines() if line.strip()]
        except (OSError, UnicodeDecodeError, EvidenceError) as exc:
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
        return parsed_rows, has_mock_jsonl

    def _read_scan_snapshot(
        self,
        entry: DiscoveredScan,
        *,
        finding_id: str | None = None,
        include_audit: bool = False,
        events_desc: bool = False,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any], dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
        """Read scan bundle, warnings, and optional audit rows from one atomic SQLite read transaction."""
        g1_doc = self._read_json_object_artifact(entry.g1_manifest_path, "g1-run-manifest.json")
        if entry.g1_manifest_path and entry.g1_manifest_path.is_file() and not g1_doc:
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
        meta_doc = self._read_json_object_artifact(entry.meta_path, "api-scan-meta.json")

        events: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []
        with _open_ro_sqlite(entry.db_path) as conn:
            conn.execute("BEGIN")
            try:
                scan_row = conn.execute("SELECT id, bundle FROM scans WHERE id=?", (entry.scan_sha256,)).fetchone()
                if scan_row is None:
                    scan_row = conn.execute("SELECT id, bundle FROM scans ORDER BY rowid DESC LIMIT 1").fetchone()
                if scan_row is None:
                    raise ApiServiceError("CORRUPT_SCAN_DB", "Cơ sở dữ liệu phiên quét không chứa bản ghi scan.", http_status=500)
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
        if entry.assessments_path and entry.assessments_path.is_file():
            _, has_mock_jsonl = self._inspect_assessments_jsonl(entry.assessments_path)

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

        return bundle, items, g1_doc, meta_doc, events, rejected

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
        with_trace = 0
        downgraded = 0
        matched_citations = 0
        proposed_refuted_open = 0

        assessments = []
        for w in items:
            ev = w["evidence"]
            ass = w["assessment"]
            assessments.append(ass)
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
        pre_hashes = bundle.get("pre_scan_hashes") or g1_doc.get("pre_scan_sources_sha256") or meta_doc.get("java_sha256") or {}

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
            "java_files_scanned": len(pre_hashes) if isinstance(pre_hashes, dict) and pre_hashes else meta_doc.get("java_files_count"),
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
            "proposed_refuted_open_count": proposed_refuted_open,
            "by_cwe": dict(sorted(by_cwe.items())),
            "runtime_summary": rt_counts,
            "qwen_runtime_verified": bool(items) and rt_counts["verified_model_runtime_count"] == len(items),
            "known_analysis_limits": KNOWN_ANALYSIS_LIMITS,
        }

    def build_scan_summary(self, entry: DiscoveredScan) -> dict[str, Any]:
        bundle, items, g1_doc, meta_doc = self._read_scan_rows(entry)
        return self._build_scan_summary_from_snapshot(entry, bundle, items, g1_doc, meta_doc)

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
            "failure_kind": ass.get("failure_kind"),
            "explanation": ass.get("explanation"),
            "fix_suggestion": ass.get("fix_suggestion") or "",
            "fix_suggestion_display_only": True,
            "citations": ass.get("citations") or [],
            "citation_check": ass.get("citation_check", "NOT_VERIFIED"),
            "citation_provenance": ass.get("citation_provenance"),
            "prompt_version": ass.get("prompt_version"),
            "requires_human_review": bool(ass.get("requires_human_review", True)),
            "security_conclusion_verified": bool(ass.get("security_conclusion_verified", False)),
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

        entry = self.resolve_scan(scan_id)
        if not entry.writable:
            raise ApiServiceError(
                "SCAN_READ_ONLY",
                "Phiên quét này thuộc vùng dữ liệu chỉ đọc; không cho phép thay đổi trạng thái kiểm duyệt.",
                http_status=403,
            )

        # Verify finding belongs to this exact scan and block mock data before opening writable ReviewStore.
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
            raise ApiServiceError("FINDING_NOT_FOUND", f"Không tìm thấy cảnh báo {finding_id!r} trong phiên quét {scan_id!r}.", http_status=404)

        with self._review_lock:
            store = ReviewStore(entry.db_path)
            try:
                store.decide(finding_id, action, actor.strip(), reason.strip())
            except StaleSourceError as exc:
                _, items_after, _, _, events_after, rejected_after = self._read_scan_snapshot(
                    entry,
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
                        "scan_id": entry.scan_id,
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
                _, items_after, _, _ = self._read_scan_rows(entry)
                cur_row = next((w for w in items_after if w["id"] == finding_id), None)
                cur_state = cur_row["state"] if cur_row else existing["state"]
                raise ApiServiceError(
                    err_code,
                    f"Từ chối thao tác kiểm duyệt ({action}): {msg}",
                    http_status=status_code,
                    extra={
                        "finding_id": finding_id,
                        "scan_id": entry.scan_id,
                        "human_review_state": cur_state,
                    },
                ) from exc
            finally:
                store.close()

        return self.get_finding_detail(entry.scan_id, finding_id)

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
            "scan_sha256",
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
    def _verify_jsonl_row_matches_sqlite(row: dict[str, Any], sql_item: dict[str, Any]) -> None:
        fid = sql_item["id"]
        row_ev = row["evidence"]
        sql_ev = sql_item["evidence"]
        immutable_ev_fields = (
            "id",
            "alert_id",
            "finding_index",
            "scan_sha256",
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
            row_ass.get("status") != sql_ass.get("status")
            or row_ass.get("validated_status", row_ass.get("status")) != sql_ass.get("validated_status", sql_ass.get("status"))
            or row_ass.get("raw_model_status") != sql_ass.get("raw_model_status")
            or bool(row_ass.get("validator_downgraded")) != bool(sql_ass.get("validator_downgraded"))
            or row_ass.get("failure_kind") != sql_ass.get("failure_kind")
            or row_ass.get("citation_check") != sql_ass.get("citation_check")
            or (row_ass.get("citations") or []) != (sql_ass.get("citations") or [])
            or row_ass.get("explanation") != sql_ass.get("explanation")
            or (row_ass.get("fix_suggestion") or "") != (sql_ass.get("fix_suggestion") or "")
            or bool(row_ass.get("requires_human_review", True)) != bool(sql_ass.get("requires_human_review", True))
            or bool(row_ass.get("security_conclusion_verified", False)) != bool(sql_ass.get("security_conclusion_verified", False))
            or row_ass.get("prompt_version") != sql_ass.get("prompt_version")
            or row_ass.get("analyzed_at") != sql_ass.get("analyzed_at")
            or row_ass.get("elapsed_seconds") != sql_ass.get("elapsed_seconds")
        ):
            raise ApiServiceError(
                "ARTIFACT_PROVENANCE_MISMATCH",
                f"Trường assessment của cảnh báo {fid!r} trong assessments.jsonl không khớp với SQLite.",
                http_status=409,
            )

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
        paired_export: dict[str, Any] | None = None
        if entry.assessments_path and entry.assessments_path.is_file():
            if raw_json_bytes is None:
                raise ApiServiceError(
                    "ARTIFACT_PROVENANCE_MISMATCH",
                    "Tồn tại assessments.jsonl nhưng thiếu tệp OpenGrep JSON gốc để đối chiếu.",
                    http_status=409,
                )
            jsonl_rows, has_mock_jsonl = self._inspect_assessments_jsonl(entry.assessments_path)
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
                self._verify_jsonl_row_matches_sqlite(row, items_by_id[row_id])

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
        bundle, items, g1_doc, meta_doc, events_desc, rejected_desc = self._read_scan_snapshot(
            entry,
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
        data_origin, paired_export = self._verify_report_artifacts(entry, bundle, items, events_asc, rejected_asc)
        summary = self._build_scan_summary_from_snapshot(entry, bundle, items, g1_doc, meta_doc)
        events_by_wid: dict[str, list[dict[str, Any]]] = {}
        for ev in events_asc:
            events_by_wid.setdefault(str(ev.get("warning_id")), []).append(ev)
        rejected_by_wid: dict[str, list[dict[str, Any]]] = {}
        for rj in rejected_asc:
            rejected_by_wid.setdefault(str(rj.get("warning_id")), []).append(rj)

        detailed_findings = [
            self._build_finding_detail_from_snapshot(
                entry,
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
