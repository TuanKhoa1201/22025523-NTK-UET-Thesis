"""Read-only R01-R03 runtime acceptance evaluator for G1.

Evaluates fresh run directories against `G1_C3_REGRESSION_CRITERIA.md` (R01, R02, R03)
and `G1_C3_R01_R03_CHECKLIST.json` without mutating any scenario directory or opening
SQLite in read-write mode (`?mode=ro` URI only; never instantiates `ReviewStore`).

Never infers R01 PASS from CLI exit code `0`, HTTP `200`, `ALL_HTTP_COMPLETED`, or
`OLLAMA_REPORTED_UNATTESTED` alone.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import stat
from typing import Any

from v2.g1_audit import contracts
from v2.triage import live_check
from v2.triage.evidence import EvidenceError, SourceTree, StaleSourceError, check_current, digest, strict_json
from v2.triage.ollama import (
    PROMPT_CONTRACT_BLIND,
    PROMPT_VERSION,
    CaptureWriteError,
    _validate_lexical_dir_path,
    assert_prompt_contract,
    inspect_citations_provenance,
    is_reparse_link,
    validate_answer,
    verify_safe_directory_chain,
)
from v2.triage.scan_receipt import verify_receipt
from v2.triage.verify_http_capture import _safe_id, verify_run_http_captures

REQUIRED_SCANNER_CAPTURE_FILES = frozenset({
    "opengrep.json",
    "opengrep.sarif",
    "rules.snapshot.yml",
    "version.command.json",
    "version.exit.txt",
    "version.stdout.txt",
    "version.stderr.txt",
    "json.command.json",
    "json.exit.txt",
    "json.stdout.txt",
    "json.stderr.txt",
    "sarif.command.json",
    "sarif.exit.txt",
    "sarif.stdout.txt",
    "sarif.stderr.txt",
})


def _encode_canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _has_parent_traversal(path: Path) -> bool:
    try:
        _validate_lexical_dir_path(path, label="path")
    except CaptureWriteError:
        return True
    return ".." in Path(path).parts


def _is_missing_clean_path(path: Path) -> bool:
    """Return True only when path is lexically clean, traverses no symlink/junction ancestors,
    and does not exist yet because a clean non-reparse directory segment is absent.
    """
    try:
        raw_p = _validate_lexical_dir_path(path, label="scenario directory")
    except CaptureWriteError:
        return False
    abs_p = Path(os.path.abspath(raw_p))
    if not abs_p.anchor or abs_p == Path(abs_p.anchor):
        return False
    anchor = Path(abs_p.anchor)
    try:
        anchor_st = os.lstat(anchor)
        if not stat.S_ISDIR(anchor_st.st_mode):
            return False
        prev_resolved = anchor.resolve(strict=True)
        if os.name == "nt" and prev_resolved.drive.upper() != anchor.drive.upper():
            return False
        if prev_resolved != Path(os.path.abspath(prev_resolved)) or prev_resolved.parent != prev_resolved:
            return False
    except (OSError, RuntimeError):
        return False
    cur = anchor
    for part in abs_p.relative_to(anchor).parts:
        cur = cur / part
        try:
            st = os.lstat(cur)
        except FileNotFoundError:
            return True
        except OSError:
            return False
        try:
            if is_reparse_link(cur) or not stat.S_ISDIR(st.st_mode):
                return False
            resolved_cur = cur.resolve(strict=True)
            res_st = os.lstat(resolved_cur)
        except (OSError, CaptureWriteError, RuntimeError):
            return False
        if resolved_cur.parent != prev_resolved or not os.path.samestat(st, res_st):
            return False
        prev_resolved = resolved_cur
    return False


def _is_safe_dir(path: Path) -> bool:
    try:
        verify_safe_directory_chain(Path(path), boundary_root=Path(path), create=False)
    except (CaptureWriteError, OSError, RuntimeError, ValueError, TypeError):
        return False
    return True


def _is_safe_regular_file(path: Path) -> bool:
    try:
        raw_p = _validate_lexical_dir_path(path, label="artifact file")
        abs_p = Path(os.path.abspath(raw_p))
        if abs_p.parent == abs_p:
            return False
        resolved_parent = verify_safe_directory_chain(abs_p.parent, boundary_root=abs_p.parent, create=False)
        if not os.path.lexists(abs_p) or is_reparse_link(abs_p):
            return False
        st = os.lstat(abs_p)
        if not stat.S_ISREG(st.st_mode):
            return False
        resolved = abs_p.resolve(strict=True)
        res_st = os.lstat(resolved)
        if resolved.parent != resolved_parent or not os.path.samestat(st, res_st):
            return False
    except (CaptureWriteError, OSError, RuntimeError, ValueError, TypeError):
        return False
    return True


def _parse_utc_timestamp(value: Any) -> datetime:
    """Parse timezone-aware ISO-8601 timestamp and normalize to UTC."""
    return contracts.timestamp(value).astimezone(timezone.utc)


def _verify_manifest_artifact_hash(
    label: str,
    artifacts_meta: Any,
    key: str,
    file_path: Path,
    *,
    expected_basename: str | None = None,
) -> tuple[str | None, list[str]]:
    if not isinstance(artifacts_meta, dict):
        return None, [f"{label}: g1-run-manifest missing artifacts dictionary for {key}"]
    entry = artifacts_meta.get(key)
    if not isinstance(entry, dict):
        return None, [f"{label}: g1-run-manifest missing mandatory artifacts.{key} entry"]
    raw_decl_path = entry.get("path")
    target_basename = expected_basename or file_path.name
    if not isinstance(raw_decl_path, str) or not raw_decl_path.strip() or Path(raw_decl_path).name != target_basename:
        return None, [
            f"{label}: artifacts.{key}.path must name {target_basename!r}, got {raw_decl_path!r}"
        ]
    raw_sha = entry.get("sha256")
    try:
        expected_sha = contracts.hexhash(raw_sha)
    except (ValueError, TypeError) as exc:
        return None, [f"{label}: missing or invalid mandatory artifacts.{key}.sha256 ({raw_sha!r}): {exc}"]
    if not _is_safe_regular_file(file_path):
        return expected_sha, [f"{label}: missing or unsafe artifact file for artifacts.{key}: {file_path.name}"]
    actual_sha = digest(file_path.read_bytes())
    if actual_sha != expected_sha:
        return expected_sha, [
            f"{label}: artifacts.{key}.sha256 mismatch for {file_path.name} (expected {expected_sha}, got {actual_sha})"
        ]
    return expected_sha, []


def _open_sqlite_ro(db_path: Path) -> sqlite3.Connection:
    resolved = Path(db_path).resolve(strict=True)
    uri = f"{resolved.as_uri()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _read_sqlite_state_ro(db_path: Path) -> dict[str, Any]:
    raw_path = Path(db_path)
    if not _is_safe_regular_file(raw_path):
        raise EvidenceError(f"missing or unsafe SQLite database: {db_path}")
    for side_ext in ("-wal", "-shm"):
        side_path = Path(str(raw_path) + side_ext)
        if os.path.lexists(side_path):
            if is_reparse_link(side_path):
                raise EvidenceError(f"SQLite sidecar {side_path.name} is a symlink/junction")
            try:
                st = os.lstat(side_path)
            except OSError as exc:
                raise EvidenceError(f"cannot lstat SQLite sidecar {side_path.name}: {exc}") from exc
            if not stat.S_ISREG(st.st_mode):
                raise EvidenceError(f"SQLite sidecar {side_path.name} is not a regular file")
            if side_ext == "-wal" and st.st_size > 0:
                raise EvidenceError(f"uncheckpointed non-empty SQLite WAL present: {side_path.name}")

    resolved = raw_path.resolve(strict=True)
    conn = _open_sqlite_ro(resolved)
    try:
        qc = conn.execute("PRAGMA quick_check").fetchall()
        if [tuple(r) for r in qc] != [("ok",)]:
            raise EvidenceError(f"SQLite quick_check failed for {raw_path.name}: {qc}")
        fk = conn.execute("PRAGMA foreign_key_check").fetchall()
        if fk:
            raise EvidenceError(f"SQLite foreign_key_check failed for {raw_path.name}: {len(fk)} violation(s)")

        scans = []
        for r in conn.execute("SELECT id, bundle FROM scans ORDER BY rowid"):
            scans.append({
                "id": r["id"],
                "bundle": strict_json(r["bundle"]),
            })
        warnings = []
        for r in conn.execute("SELECT id, scan_id, evidence, assessment, state FROM warnings ORDER BY rowid"):
            warnings.append({
                "id": r["id"],
                "scan_id": r["scan_id"],
                "state": r["state"],
                "evidence": strict_json(r["evidence"]),
                "assessment": strict_json(r["assessment"]),
            })
        events = [
            dict(r)
            for r in conn.execute(
                "SELECT sequence, warning_id, actor, timestamp, action, reason, source_version, observed_version, evidence_sha256 "
                "FROM events ORDER BY sequence, rowid"
            )
        ]
        rejected = [
            dict(r)
            for r in conn.execute(
                "SELECT sequence, warning_id, actor, timestamp, attempted_action, reason, rejection_code, source_version, observed_version, detail "
                "FROM rejected_decisions ORDER BY sequence, rowid"
            )
        ]
        return {
            "db_sha256": digest(resolved.read_bytes()),
            "scans_count": len(scans),
            "scan_ids": [s["id"] for s in scans],
            "scans": scans,
            "warnings": warnings,
            "events": events,
            "rejected_decisions": rejected,
        }
    finally:
        conn.close()


_NON_HUMAN_ACTOR_TOKENS = frozenset({
    "scripted",
    "mock",
    "synthetic",
    "replay",
    "bot",
    "fake",
    "dummy",
    "fixture",
})
_NON_HUMAN_REVIEW_PATTERNS = (
    re.compile(r"scripted[_\-\s]*test(?:[_\-\s]*only)?", re.IGNORECASE),
    re.compile(r"synthetic[_\-\s]*mock(?:[_\-\s]*http)?", re.IGNORECASE),
    re.compile(r"mock[_\-\s]*(?:http|test[_\-\s]*fixture)", re.IGNORECASE),
    re.compile(r"replay[_\-\s]*(?:only|test|event|decision)", re.IGNORECASE),
    re.compile(r"not\s+(?:an?\s+|an\s+approved\s+)?human\s+(?:decision|review)", re.IGNORECASE),
    re.compile(r"not[_\-\s]+human[_\-\s]+(?:decision|review)", re.IGNORECASE),
    re.compile(r"automated[_\-\s]*test(?:[_\-\s]*only)?", re.IGNORECASE),
    re.compile(r"dry[_\-\s]*run[_\-\s]*only", re.IGNORECASE),
    re.compile(r"ntk-demo-operator", re.IGNORECASE),
)
_NON_HUMAN_REASON_PREFIX = re.compile(
    r"^\s*(?:\[?\s*(?:scripted|mock|synthetic|replay|dry[-_\s]?run)\b[^a-z0-9]*(?:\]|:|-|\s))",
    re.IGNORECASE,
)
_NON_HUMAN_UPPER_TAG_RE = re.compile(
    r"\b(?:SCRIPTED_TEST_ONLY|MOCK_HTTP|MOCK_ONLY|SYNTHETIC_MOCK|REPLAY_ONLY|REPLAY_EVENT|TEST_HARNESS)\b"
)


def _find_non_human_review_marker(actor: Any, reason: Any) -> str | None:
    """Return a match description when actor/reason indicates scripted, mock, or replay test activity."""
    actor_str = actor if isinstance(actor, str) else ""
    reason_str = reason if isinstance(reason, str) else ""
    for pat in _NON_HUMAN_REVIEW_PATTERNS:
        if pat.search(actor_str) or pat.search(reason_str):
            return pat.pattern
    if _NON_HUMAN_UPPER_TAG_RE.search(actor_str) or _NON_HUMAN_UPPER_TAG_RE.search(reason_str):
        return "explicit non-human test tag"
    actor_tokens = [tok for tok in re.split(r"[^a-z0-9]+", actor_str.lower()) if tok]
    for tok in actor_tokens:
        if tok in _NON_HUMAN_ACTOR_TOKENS:
            return f"actor token {tok!r}"
    if _NON_HUMAN_REASON_PREFIX.search(reason_str):
        return "reason non-human prefix"
    return None


def _verify_sqlite_against_triage(
    label: str,
    db_state: dict[str, Any],
    evidence_bundle: dict[str, Any],
    rows: list[dict[str, Any]],
    *,
    scan_manifest: dict[str, Any] | None = None,
    run_manifest: dict[str, Any] | None = None,
    require_scan_manifest: bool = True,
    require_run_manifest: bool = True,
    require_zero_rejected: bool = True,
    allow_scripted_events: bool = False,
) -> list[str]:
    errors: list[str] = []
    scan_sha = evidence_bundle.get("scan_sha256")
    records = evidence_bundle.get("records") or []

    scan_started_ts: datetime | None = None
    scan_finished_ts: datetime | None = None
    scan_sources_before: dict[str, Any] | None = None
    if require_scan_manifest and not isinstance(scan_manifest, dict):
        errors.append(f"{label}: missing valid scan-manifest.json anchor for SQLite chronology verification")
    elif isinstance(scan_manifest, dict):
        try:
            scan_started_ts = _parse_utc_timestamp(scan_manifest.get("started_at"))
            scan_finished_ts = _parse_utc_timestamp(scan_manifest.get("finished_at"))
            if scan_finished_ts < scan_started_ts:
                errors.append(f"{label}: scan-manifest finished_at precedes started_at")
        except (ValueError, TypeError) as exc:
            errors.append(f"{label}: invalid scan-manifest timestamps for chronology verification: {exc}")
        if isinstance(scan_manifest.get("sources_before"), dict):
            scan_sources_before = scan_manifest["sources_before"]

    bundle_collected_ts: datetime | None = None
    try:
        bundle_collected_ts = _parse_utc_timestamp(evidence_bundle.get("collected_at"))
        if scan_finished_ts is not None and bundle_collected_ts < scan_finished_ts:
            errors.append(f"{label}: evidence.json collected_at precedes scan-manifest finished_at")
    except (ValueError, TypeError) as exc:
        errors.append(f"{label}: invalid or missing evidence.json collected_at: {exc}")

    run_recorded_ts: datetime | None = None
    if require_run_manifest and not isinstance(run_manifest, dict):
        errors.append(f"{label}: missing valid g1-run-manifest.json anchor for SQLite chronology verification")
    elif isinstance(run_manifest, dict):
        try:
            run_recorded_ts = _parse_utc_timestamp(run_manifest.get("recorded_at"))
            if bundle_collected_ts is not None and run_recorded_ts < bundle_collected_ts:
                errors.append(f"{label}: g1-run-manifest recorded_at precedes evidence.json collected_at")
        except (ValueError, TypeError) as exc:
            errors.append(f"{label}: invalid or missing g1-run-manifest recorded_at: {exc}")

    if db_state["scans_count"] != 1:
        errors.append(f"{label}: expected 1 scans row, got {db_state['scans_count']}")
    elif db_state["scan_ids"] != [scan_sha]:
        errors.append(f"{label}: scans.id {db_state['scan_ids']!r} != [{scan_sha!r}]")
    elif db_state["scans"][0]["bundle"] != evidence_bundle:
        errors.append(f"{label}: SQLite scans.bundle differs from triage/evidence.json")

    warnings = db_state["warnings"]
    if len(warnings) != len(records) or len(warnings) != len(rows):
        errors.append(
            f"{label}: SQLite warnings count ({len(warnings)}) != evidence ({len(records)}) / assessments ({len(rows)})"
        )
        return errors

    rec_ids = [rec.get("id") for rec in records]
    warn_ids = [w.get("id") for w in warnings]
    if warn_ids != rec_ids:
        errors.append(f"{label}: SQLite warning IDs do not match evidence records")
        return errors

    rec_by_id: dict[str, dict[str, Any]] = {}
    rec_collected_by_id: dict[str, datetime | None] = {}
    analyzed_ts_by_id: dict[str, datetime | None] = {}
    for idx, (w, rec, row) in enumerate(zip(warnings, records, rows)):
        wid = rec["id"]
        rec_by_id[wid] = rec
        if w.get("scan_id") != scan_sha:
            errors.append(f"{label}: warning[{idx}] scan_id {w.get('scan_id')!r} != {scan_sha!r}")
        if w.get("state") not in ("OPEN", "CONFIRMED_TRUE", "CONFIRMED_FALSE"):
            errors.append(f"{label}: warning[{idx}] invalid SQLite state {w.get('state')!r}")
        if w.get("evidence") != rec:
            errors.append(f"{label}: warning[{idx}] SQLite evidence differs from evidence.json")
        if w.get("assessment") != row.get("assessment"):
            errors.append(f"{label}: warning[{idx}] SQLite assessment differs from assessments.jsonl")

        try:
            rec_ts = _parse_utc_timestamp(rec.get("collected_at"))
            if scan_finished_ts is not None and rec_ts < scan_finished_ts:
                errors.append(f"{label}: warning[{idx}] evidence collected_at precedes scan finished_at")
            if bundle_collected_ts is not None and rec_ts > bundle_collected_ts:
                errors.append(f"{label}: warning[{idx}] evidence collected_at exceeds bundle collected_at")
        except (ValueError, TypeError) as exc:
            rec_ts = None
            errors.append(f"{label}: warning[{idx}] invalid evidence collected_at: {exc}")
        rec_collected_by_id[wid] = rec_ts

        assessment_obj = row.get("assessment") if isinstance(row.get("assessment"), dict) else {}
        try:
            an_ts = _parse_utc_timestamp(assessment_obj.get("analyzed_at"))
            if rec_ts is not None and an_ts < rec_ts:
                errors.append(f"{label}: warning[{idx}] assessment analyzed_at precedes finding collected_at")
            if bundle_collected_ts is not None and an_ts < bundle_collected_ts:
                errors.append(f"{label}: warning[{idx}] assessment analyzed_at precedes bundle collected_at")
            if run_recorded_ts is not None and an_ts > run_recorded_ts:
                errors.append(f"{label}: warning[{idx}] assessment analyzed_at exceeds g1-run-manifest recorded_at")
        except (ValueError, TypeError) as exc:
            an_ts = None
            errors.append(f"{label}: warning[{idx}] invalid assessment analyzed_at: {exc}")
        analyzed_ts_by_id[wid] = an_ts

        if scan_sources_before is not None:
            snaps = rec.get("snapshots") if isinstance(rec.get("snapshots"), dict) else {}
            for sp, snap in snaps.items():
                if not isinstance(snap, dict) or scan_sources_before.get(sp) != snap.get("sha256"):
                    errors.append(
                        f"{label}: warning[{idx}] snapshot hash for {sp!r} does not match scan-manifest sources_before"
                    )

    events = db_state["events"]
    expected_seqs = list(range(1, len(events) + 1))
    if [ev.get("sequence") for ev in events] != expected_seqs:
        errors.append(f"{label}: SQLite events sequence numbers are non-sequential")

    sim_states = {wid: "OPEN" for wid in rec_by_id}
    prev_ts: datetime | None = None
    for idx, ev in enumerate(events):
        wid = ev.get("warning_id")
        if wid not in rec_by_id:
            errors.append(f"{label}: event[{idx}] references unknown warning_id {wid!r}")
            continue
        rec = rec_by_id[wid]
        try:
            ts = _parse_utc_timestamp(ev.get("timestamp"))
        except (ValueError, TypeError) as exc:
            errors.append(f"{label}: event[{idx}] invalid timestamp {ev.get('timestamp')!r}: {exc}")
            ts = None
        if ts is not None:
            if scan_started_ts is not None and ts < scan_started_ts:
                errors.append(
                    f"{label}: event[{idx}] timestamp ({ts.isoformat()}) precedes scan started_at ({scan_started_ts.isoformat()})"
                )
            if scan_finished_ts is not None and ts < scan_finished_ts:
                errors.append(
                    f"{label}: event[{idx}] timestamp ({ts.isoformat()}) precedes scan finished_at ({scan_finished_ts.isoformat()})"
                )
            rec_ts = rec_collected_by_id.get(wid)
            if rec_ts is not None and ts < rec_ts:
                errors.append(
                    f"{label}: event[{idx}] timestamp ({ts.isoformat()}) precedes finding collected_at ({rec_ts.isoformat()})"
                )
            if bundle_collected_ts is not None and ts < bundle_collected_ts:
                errors.append(
                    f"{label}: event[{idx}] timestamp ({ts.isoformat()}) precedes evidence bundle collected_at ({bundle_collected_ts.isoformat()})"
                )
            an_ts = analyzed_ts_by_id.get(wid)
            if an_ts is not None and ts < an_ts:
                errors.append(
                    f"{label}: event[{idx}] timestamp ({ts.isoformat()}) precedes triage analyzed_at ({an_ts.isoformat()})"
                )
            if run_recorded_ts is not None and ts < run_recorded_ts:
                errors.append(
                    f"{label}: event[{idx}] timestamp ({ts.isoformat()}) precedes ingestion manifest recorded_at ({run_recorded_ts.isoformat()})"
                )
            if prev_ts is not None and ts < prev_ts:
                errors.append(f"{label}: event[{idx}] timestamp regressed before prior event")
            prev_ts = ts

        actor = ev.get("actor")
        reason = ev.get("reason")
        if not isinstance(actor, str) or not actor.strip() or actor != actor.strip():
            errors.append(f"{label}: event[{idx}] invalid or unstripped actor {actor!r}")
        if not isinstance(reason, str) or not reason.strip() or reason != reason.strip():
            errors.append(f"{label}: event[{idx}] invalid or unstripped reason")
        non_human_marker = _find_non_human_review_marker(actor, reason)
        if non_human_marker is not None and not allow_scripted_events:
            errors.append(
                f"{label}: event[{idx}] carries non-human/scripted/mock/replay marker ({non_human_marker}); "
                "cannot count as approved human review in official evaluation"
            )

        expected_snapshots = rec.get("snapshots") or {}
        expected_obs = {
            p: snap.get("sha256")
            for p, snap in expected_snapshots.items()
            if isinstance(snap, dict)
        }

        action = ev.get("action")
        if action == "confirm-true":
            if sim_states[wid] != "OPEN":
                errors.append(f"{label}: event[{idx}] invalid confirm-true from state {sim_states[wid]!r}")
            sim_states[wid] = "CONFIRMED_TRUE"
        elif action == "confirm-false":
            if sim_states[wid] != "OPEN":
                errors.append(f"{label}: event[{idx}] invalid confirm-false from state {sim_states[wid]!r}")
            if rec.get("issues"):
                errors.append(f"{label}: event[{idx}] confirm-false accepted despite evidence issues {rec.get('issues')!r}")
            if not isinstance(expected_snapshots, dict) or not expected_snapshots:
                errors.append(f"{label}: event[{idx}] confirm-false accepted without verified source snapshots")
            if rec.get("scan_provenance", {}).get("source_capture_verified") is not True:
                errors.append(f"{label}: event[{idx}] confirm-false accepted without source_capture_verified=True")
            sim_states[wid] = "CONFIRMED_FALSE"
        elif action == "reopen":
            if sim_states[wid] not in ("CONFIRMED_TRUE", "CONFIRMED_FALSE"):
                errors.append(f"{label}: event[{idx}] invalid reopen from state {sim_states[wid]!r}")
            sim_states[wid] = "OPEN"
        else:
            errors.append(f"{label}: event[{idx}] unknown action {action!r}")

        try:
            ev_sv = strict_json(ev.get("source_version"))
        except (EvidenceError, TypeError):
            ev_sv = None
        try:
            ev_ov = strict_json(ev.get("observed_version"))
        except (EvidenceError, TypeError):
            ev_ov = None
        if ev_sv != expected_snapshots or ev.get("source_version") != _encode_canonical(expected_snapshots):
            errors.append(f"{label}: event[{idx}] source_version does not match finding snapshots")
        if ev_ov != expected_obs or ev.get("observed_version") != _encode_canonical(expected_obs):
            errors.append(f"{label}: event[{idx}] observed_version does not match finding snapshot hashes")

        expected_ev_sha = digest(_encode_canonical(rec).encode("utf-8"))
        if ev.get("evidence_sha256") != expected_ev_sha:
            errors.append(f"{label}: event[{idx}] evidence_sha256 mismatch")

    actual_states = {w["id"]: w["state"] for w in warnings}
    if actual_states != sim_states:
        errors.append(f"{label}: SQLite warning states {actual_states!r} do not match event replay {sim_states!r}")

    rejected_rows = db_state["rejected_decisions"]
    if require_zero_rejected and rejected_rows:
        errors.append(f"{label}: unexpectedly contains {len(rejected_rows)} rejected_decisions row(s)")
    elif rejected_rows:
        expected_rej_seqs = list(range(1, len(rejected_rows) + 1))
        if [rj.get("sequence") for rj in rejected_rows] != expected_rej_seqs:
            errors.append(f"{label}: SQLite rejected_decisions sequence numbers are non-sequential")
        prev_rej_ts: datetime | None = None
        for idx, rj in enumerate(rejected_rows):
            r_wid = rj.get("warning_id")
            if r_wid not in rec_by_id:
                errors.append(f"{label}: rejected_decisions[{idx}] references unknown warning_id {r_wid!r}")
                continue
            try:
                rj_ts = _parse_utc_timestamp(rj.get("timestamp"))
            except (ValueError, TypeError) as exc:
                errors.append(f"{label}: rejected_decisions[{idx}] invalid timestamp {rj.get('timestamp')!r}: {exc}")
                rj_ts = None
            if rj_ts is not None:
                if scan_started_ts is not None and rj_ts < scan_started_ts:
                    errors.append(
                        f"{label}: rejected_decisions[{idx}] timestamp ({rj_ts.isoformat()}) precedes scan started_at ({scan_started_ts.isoformat()})"
                    )
                if scan_finished_ts is not None and rj_ts < scan_finished_ts:
                    errors.append(
                        f"{label}: rejected_decisions[{idx}] timestamp ({rj_ts.isoformat()}) precedes scan finished_at ({scan_finished_ts.isoformat()})"
                    )
                rec_ts = rec_collected_by_id.get(r_wid)
                if rec_ts is not None and rj_ts < rec_ts:
                    errors.append(
                        f"{label}: rejected_decisions[{idx}] timestamp ({rj_ts.isoformat()}) precedes finding collected_at ({rec_ts.isoformat()})"
                    )
                if bundle_collected_ts is not None and rj_ts < bundle_collected_ts:
                    errors.append(
                        f"{label}: rejected_decisions[{idx}] timestamp ({rj_ts.isoformat()}) precedes evidence bundle collected_at ({bundle_collected_ts.isoformat()})"
                    )
                an_ts = analyzed_ts_by_id.get(r_wid)
                if an_ts is not None and rj_ts < an_ts:
                    errors.append(
                        f"{label}: rejected_decisions[{idx}] timestamp ({rj_ts.isoformat()}) precedes triage analyzed_at ({an_ts.isoformat()})"
                    )
                if run_recorded_ts is not None and rj_ts < run_recorded_ts:
                    errors.append(
                        f"{label}: rejected_decisions[{idx}] timestamp ({rj_ts.isoformat()}) precedes ingestion manifest recorded_at ({run_recorded_ts.isoformat()})"
                    )
                if prev_rej_ts is not None and rj_ts < prev_rej_ts:
                    errors.append(f"{label}: rejected_decisions[{idx}] timestamp regressed before prior rejected decision")
                prev_rej_ts = rj_ts

    return errors


def _roots_overlap_or_nest(path_a: Path, path_b: Path) -> bool:
    """Return True when two resolved directories are identical or nested inside one another."""
    return path_a == path_b or path_a.is_relative_to(path_b) or path_b.is_relative_to(path_a)


def _collect_safe_rel_files(
    root: Path,
    *,
    prefix: str,
    allow_subdirs: bool = True,
    excluded_top_dirs: frozenset[str] = frozenset(),
) -> tuple[dict[str, Path] | None, list[str]]:
    """Walk root safely without following symlinks/junctions and return relative-POSIX file map."""
    if not _is_safe_dir(root):
        return None, [f"{prefix}: unsafe, missing, or reparse-linked directory: {root}"]
    root_resolved = root.resolve(strict=True)
    rel_files: dict[str, Path] = {}
    errors: list[str] = []
    stack: list[Path] = [root_resolved]
    while stack:
        cur = stack.pop()
        try:
            entries = sorted(cur.iterdir(), key=lambda p: p.name)
        except OSError as exc:
            errors.append(f"{prefix}: cannot list directory {cur}: {exc}")
            continue
        for entry in entries:
            rel_posix = entry.relative_to(root_resolved).as_posix()
            if is_reparse_link(entry):
                errors.append(f"{prefix}: forbidden symlink/junction entry: {rel_posix}")
                continue
            try:
                st = os.lstat(entry)
            except OSError as exc:
                errors.append(f"{prefix}: cannot lstat entry {rel_posix}: {exc}")
                continue
            if stat.S_ISDIR(st.st_mode):
                if cur == root_resolved and entry.name in excluded_top_dirs:
                    continue
                if not allow_subdirs:
                    errors.append(f"{prefix}: unexpected subdirectory {rel_posix}")
                    continue
                if not _is_safe_dir(entry):
                    errors.append(f"{prefix}: unsafe subdirectory {rel_posix}")
                    continue
                stack.append(entry)
            elif stat.S_ISREG(st.st_mode):
                if not _is_safe_regular_file(entry):
                    errors.append(f"{prefix}: unsafe regular file {rel_posix}")
                    continue
                rel_files[rel_posix] = entry
            else:
                errors.append(f"{prefix}: unsupported non-regular entry {rel_posix}")
    return rel_files, errors


def _compare_safe_file_maps(
    prefix: str,
    label: str,
    *,
    orig_files: dict[str, Path],
    review_files: dict[str, Path],
) -> list[str]:
    """Compare relative file keys, raw bytes, and SHA-256 digests between original and review copy."""
    errors: list[str] = []
    orig_keys = set(orig_files)
    rev_keys = set(review_files)
    missing_in_rev = sorted(orig_keys - rev_keys)
    extra_in_rev = sorted(rev_keys - orig_keys)
    if missing_in_rev:
        errors.append(f"{prefix}: {label} missing in relocated review copy: {missing_in_rev}")
    if extra_in_rev:
        errors.append(f"{prefix}: {label} unexpected extra file(s) in relocated review copy: {extra_in_rev}")
    for rel_key in sorted(orig_keys & rev_keys):
        orig_bytes = orig_files[rel_key].read_bytes()
        rev_bytes = review_files[rel_key].read_bytes()
        if rev_bytes != orig_bytes or digest(rev_bytes) != digest(orig_bytes):
            errors.append(f"{prefix}: relocated {label} {rel_key!r} diverges from pinned original")
    return errors


def _verify_relocated_capture_parity(
    prefix: str,
    *,
    review_capture_dir: Path,
    original_capture_dir: Path,
    review_manifest: dict[str, Any] | None,
) -> list[str]:
    """Verify full file-inventory and byte-for-byte parity between relocated capture and pinned original capture."""
    errors: list[str] = []
    orig_top, orig_top_errs = _collect_safe_rel_files(
        original_capture_dir,
        prefix=f"{prefix} original capture",
        allow_subdirs=False,
        excluded_top_dirs=frozenset({"legacy_reports"}),
    )
    rev_top, rev_top_errs = _collect_safe_rel_files(
        review_capture_dir,
        prefix=f"{prefix} review capture",
        allow_subdirs=False,
        excluded_top_dirs=frozenset({"legacy_reports"}),
    )
    errors.extend(orig_top_errs)
    errors.extend(rev_top_errs)
    if orig_top is not None and rev_top is not None:
        for fixed_name in ("cli-origin.json", "scan-manifest.json"):
            if fixed_name not in orig_top or fixed_name not in rev_top:
                errors.append(
                    f"{prefix}: missing or unsafe {fixed_name} during relocated capture parity check"
                )
        errors.extend(
            _compare_safe_file_maps(
                prefix,
                "capture file",
                orig_files=orig_top,
                review_files=rev_top,
            )
        )

    orig_legacy = original_capture_dir / "legacy_reports"
    rev_legacy = review_capture_dir / "legacy_reports"
    orig_legacy_exists = os.path.lexists(orig_legacy)
    rev_legacy_exists = os.path.lexists(rev_legacy)
    orig_leg_files: dict[str, Path] | None = None
    if orig_legacy_exists:
        orig_leg_files, orig_leg_errs = _collect_safe_rel_files(
            orig_legacy, prefix=f"{prefix} original capture/legacy_reports", allow_subdirs=True
        )
        errors.extend(orig_leg_errs)
    if rev_legacy_exists:
        rev_leg_files, rev_leg_errs = _collect_safe_rel_files(
            rev_legacy, prefix=f"{prefix} review capture/legacy_reports", allow_subdirs=True
        )
        errors.extend(rev_leg_errs)
        if not orig_legacy_exists:
            errors.append(
                f"{prefix}: relocated review copy contains legacy_reports/ absent from pinned original capture"
            )
        elif orig_leg_files is not None and rev_leg_files is not None:
            errors.extend(
                _compare_safe_file_maps(
                    prefix,
                    "capture/legacy_reports file",
                    orig_files=orig_leg_files,
                    review_files=rev_leg_files,
                )
            )

    if isinstance(review_manifest, dict) and isinstance(review_manifest.get("artifacts"), dict):
        for art_name in sorted(review_manifest["artifacts"]):
            if (
                not isinstance(art_name, str)
                or Path(art_name).name != art_name
                or "/" in art_name
                or "\\" in art_name
                or ":" in art_name
                or art_name in (".", "..")
            ):
                continue
            rev_art = review_capture_dir / art_name
            orig_art = original_capture_dir / art_name
            if not _is_safe_regular_file(rev_art) or not _is_safe_regular_file(orig_art):
                errors.append(
                    f"{prefix}: missing or unsafe relocated artifact {art_name!r} in review copy or pinned original capture"
                )
            elif rev_art.read_bytes() != orig_art.read_bytes():
                errors.append(
                    f"{prefix}: relocated review artifact {art_name!r} bytes differ from pinned original capture"
                )
    return errors


_TRIAGE_IMMUTABLE_CORE = frozenset({
    "evidence.json",
    "assessments.jsonl",
    "input.opengrep.json",
    "review.post_ingestion.sqlite",
})
_TRIAGE_IMMUTABLE_LLM_OPTIONAL = frozenset({
    "live-protocol-check.json",
    "ollama-tags-check.json",
})


def _collect_safe_triage_top_entries(
    triage_dir: Path,
    *,
    prefix: str,
    expect_llm: bool,
    allow_after_confirm_false: bool,
) -> tuple[dict[str, Path] | None, list[str]]:
    """Inspect direct entries of triage/ for symlink safety, expected files, and zero rogue extras."""
    if not _is_safe_dir(triage_dir):
        return None, [f"{prefix}: unsafe, missing, or reparse-linked triage dir: {triage_dir}"]
    errors: list[str] = []
    immutable_files: dict[str, Path] = {}
    required_immutable = set(_TRIAGE_IMMUTABLE_CORE)
    if expect_llm:
        required_immutable.add("http-capture-check.json")
    allowed_immutable = set(required_immutable)
    if expect_llm:
        allowed_immutable.update(_TRIAGE_IMMUTABLE_LLM_OPTIONAL)

    allowed_sqlite_mutable = {
        "review.sqlite",
        "review.sqlite-wal",
        "review.sqlite-shm",
    }
    if allow_after_confirm_false:
        allowed_sqlite_mutable.update({
            "review.after_confirm_false.sqlite",
            "review.after_confirm_false.sqlite-wal",
            "review.after_confirm_false.sqlite-shm",
        })

    saw_llm_io = False
    try:
        entries = sorted(triage_dir.iterdir(), key=lambda p: p.name)
    except OSError as exc:
        return None, [f"{prefix}: cannot list triage dir {triage_dir}: {exc}"]

    for entry in entries:
        name = entry.name
        if is_reparse_link(entry):
            errors.append(f"{prefix}: triage contains symlink/junction entry: {name}")
            continue
        try:
            st = os.lstat(entry)
        except OSError as exc:
            errors.append(f"{prefix}: cannot lstat triage entry {name}: {exc}")
            continue
        if stat.S_ISDIR(st.st_mode):
            if name == "llm_io" and expect_llm:
                saw_llm_io = True
                if not _is_safe_dir(entry):
                    errors.append(f"{prefix}: unsafe triage/llm_io directory")
            else:
                errors.append(f"{prefix}: unexpected triage subdirectory {name!r}")
        elif stat.S_ISREG(st.st_mode):
            if not _is_safe_regular_file(entry):
                errors.append(f"{prefix}: unsafe triage regular file {name}")
                continue
            if name in ("review.post_ingestion.sqlite-wal", "review.post_ingestion.sqlite-shm"):
                errors.append(f"{prefix}: forbidden ingestion snapshot SQLite sidecar in triage/: {name!r}")
            elif name in allowed_immutable:
                immutable_files[name] = entry
            elif name in allowed_sqlite_mutable:
                if name.endswith("-wal") and st.st_size > 0:
                    errors.append(f"{prefix}: non-empty uncheckpointed SQLite WAL present: {name}")
            else:
                errors.append(f"{prefix}: unexpected extra file in triage/: {name!r}")
        else:
            errors.append(f"{prefix}: non-regular entry in triage/: {name!r}")

    missing_req = sorted(required_immutable - set(immutable_files))
    if missing_req:
        errors.append(f"{prefix}: missing mandatory triage file(s): {missing_req}")
    if expect_llm and not saw_llm_io:
        errors.append(f"{prefix}: missing mandatory triage/llm_io directory")
    return immutable_files, errors


def _verify_relocated_scenario_provenance(
    prefix: str,
    *,
    review_scenario_dir: Path,
    review_capture_dir: Path,
    trusted_original_scenario_dir: Path | None,
    trusted_original_capture_dir: Path | None,
    expect_llm: bool,
    expect_live_source_current: bool,
    require_after_confirm_false: bool,
) -> tuple[list[str], list[str], Path | None]:
    """Verify full original scenario vs relocated review copy provenance, inventory, and pre-review byte parity."""
    if trusted_original_scenario_dir is None and trusted_original_capture_dir is None:
        return [], [], None
    if trusted_original_scenario_dir is None or trusted_original_capture_dir is None:
        msg = (
            f"{prefix}: relocation pinning requires BOTH trusted_original_scenario_dir and "
            "trusted_original_capture_dir to be provided together"
        )
        return [msg], [msg], None

    capture_errors: list[str] = []
    triage_manifest_errors: list[str] = []

    raw_orig_scen = Path(trusted_original_scenario_dir)
    raw_orig_cap = Path(trusted_original_capture_dir)
    if _has_parent_traversal(raw_orig_scen) or not _is_safe_dir(raw_orig_scen):
        capture_errors.append(
            f"{prefix}: unsafe, missing, or reparse-linked trusted_original_scenario_dir: {raw_orig_scen}"
        )
    if _has_parent_traversal(raw_orig_cap) or not _is_safe_dir(raw_orig_cap):
        capture_errors.append(
            f"{prefix}: unsafe, missing, or reparse-linked trusted_original_capture_dir: {raw_orig_cap}"
        )
    if capture_errors:
        return capture_errors, list(capture_errors), None

    orig_scen = raw_orig_scen.resolve(strict=True)
    orig_cap = raw_orig_cap.resolve(strict=True)
    rev_scen = review_scenario_dir.resolve(strict=True)
    rev_cap = review_capture_dir.resolve(strict=True)

    if _roots_overlap_or_nest(orig_scen, rev_scen):
        msg = (
            f"{prefix}: trusted_original_scenario_dir ({orig_scen}) cannot equal or nest with "
            f"review scenario_dir ({rev_scen}) (self-pinning rejected)"
        )
        capture_errors.append(msg)
        triage_manifest_errors.append(msg)
    if _roots_overlap_or_nest(orig_cap, rev_cap):
        msg = (
            f"{prefix}: trusted_original_capture_dir ({orig_cap}) cannot equal or nest with "
            f"review capture_dir ({rev_cap}) (self-pinning rejected)"
        )
        capture_errors.append(msg)
        triage_manifest_errors.append(msg)

    expected_orig_cap_path = orig_scen / "capture"
    if os.path.lexists(expected_orig_cap_path) and is_reparse_link(expected_orig_cap_path):
        msg = f"{prefix}: original scenario capture/ is a symlink/junction: {expected_orig_cap_path}"
        capture_errors.append(msg)
        triage_manifest_errors.append(msg)
    elif not _is_safe_dir(expected_orig_cap_path) or orig_cap != expected_orig_cap_path.resolve(strict=True):
        msg = (
            f"{prefix}: trusted_original_capture_dir ({orig_cap}) is not bound to "
            f"trusted_original_scenario_dir/capture ({expected_orig_cap_path})"
        )
        capture_errors.append(msg)
        triage_manifest_errors.append(msg)

    # Top-level scenario inventory & manifest byte parity
    allowed_top = {"capture", "triage", "g1-run-manifest.json", "g1-cli-summary.json"}
    try:
        orig_top_entries = {p.name: p for p in orig_scen.iterdir()}
        rev_top_entries = {p.name: p for p in rev_scen.iterdir()}
    except OSError as exc:
        msg = f"{prefix}: cannot inspect top-level scenario entries during relocation check: {exc}"
        return capture_errors + [msg], triage_manifest_errors + [msg], orig_cap

    for side_label, entries in (("original scenario", orig_top_entries), ("relocated review copy", rev_top_entries)):
        for name, entry in sorted(entries.items()):
            if is_reparse_link(entry):
                triage_manifest_errors.append(f"{prefix}: {side_label} top-level entry is symlink/junction: {name}")
            if name not in allowed_top:
                triage_manifest_errors.append(f"{prefix}: {side_label} contains unexpected top-level entry: {name!r}")

    if set(orig_top_entries) != set(rev_top_entries):
        triage_manifest_errors.append(
            f"{prefix}: top-level scenario inventory differs between pinned original "
            f"({sorted(orig_top_entries)}) and review copy ({sorted(rev_top_entries)})"
        )
    for top_json_name in ("g1-run-manifest.json", "g1-cli-summary.json"):
        orig_in = top_json_name in orig_top_entries
        rev_in = top_json_name in rev_top_entries
        if not orig_in and not rev_in:
            if top_json_name == "g1-run-manifest.json":
                triage_manifest_errors.append(f"{prefix}: missing mandatory g1-run-manifest.json")
            continue
        orig_f = orig_scen / top_json_name
        rev_f = rev_scen / top_json_name
        if not _is_safe_regular_file(orig_f) or not _is_safe_regular_file(rev_f):
            triage_manifest_errors.append(f"{prefix}: missing or unsafe {top_json_name} during relocation parity check")
        else:
            ob = orig_f.read_bytes()
            rb = rev_f.read_bytes()
            if ob != rb or digest(ob) != digest(rb):
                triage_manifest_errors.append(
                    f"{prefix}: relocated {top_json_name} diverges from pinned original scenario"
                )

    # Independent verification of original scenario pre-review triage integrity
    orig_triage = orig_scen / "triage"
    rev_triage = rev_scen / "triage"
    orig_man_path = orig_scen / "g1-run-manifest.json"
    orig_man: dict[str, Any] | None = None
    if _is_safe_regular_file(orig_man_path):
        try:
            parsed_om = strict_json(orig_man_path.read_text(encoding="utf-8"))
            if isinstance(parsed_om, dict) and parsed_om.get("schema") == "ntk-g1-run-manifest-1":
                orig_man = parsed_om
            else:
                triage_manifest_errors.append(f"{prefix}: original g1-run-manifest schema invalid")
        except (OSError, UnicodeError, EvidenceError) as exc:
            triage_manifest_errors.append(f"{prefix}: original g1-run-manifest invalid JSON: {exc}")

    if isinstance(orig_man, dict):
        orig_artifacts = orig_man.get("artifacts")
        expected_pairs: list[tuple[str, Path, str | None]] = [
            ("opengrep_json", orig_cap / "opengrep.json", None),
            ("opengrep_sarif", orig_cap / "opengrep.sarif", None),
            ("scan_manifest", orig_cap / "scan-manifest.json", None),
            ("cli_origin", orig_cap / "cli-origin.json", None),
            ("evidence_json", orig_triage / "evidence.json", None),
            ("assessments_jsonl", orig_triage / "assessments.jsonl", None),
            ("review_sqlite", orig_triage / "review.post_ingestion.sqlite", "review.sqlite"),
        ]
        if expect_llm:
            expected_pairs.append(("http_capture_check", orig_triage / "http-capture-check.json", None))
        for akey, apath, exp_base in expected_pairs:
            _, art_errs = _verify_manifest_artifact_hash(
                f"{prefix} original",
                orig_artifacts,
                akey,
                apath,
                expected_basename=exp_base,
            )
            triage_manifest_errors.extend(art_errs)
        if expect_llm:
            orig_http = verify_run_http_captures(orig_triage, require_live_chat=False, minimum_findings=1)
            if not orig_http["capture_integrity_ok"]:
                triage_manifest_errors.append(
                    f"{prefix}: original triage raw HTTP capture integrity failed: {orig_http['errors']}"
                )
        else:
            http_entry = orig_artifacts.get("http_capture_check") if isinstance(orig_artifacts, dict) else None
            if not isinstance(http_entry, dict) or http_entry.get("sha256") is not None:
                triage_manifest_errors.append(
                    f"{prefix}: original --no-llm artifacts.http_capture_check must have sha256=null"
                )
        if _is_safe_regular_file(orig_cap / "opengrep.json") and _is_safe_regular_file(orig_triage / "input.opengrep.json"):
            if (orig_cap / "opengrep.json").read_bytes() != (orig_triage / "input.opengrep.json").read_bytes():
                triage_manifest_errors.append(
                    f"{prefix}: original triage/input.opengrep.json differs from original capture/opengrep.json"
                )

    # Strict triage/ inventory and raw-byte parity (only post-review review.sqlite / after_confirm_false may diverge)
    orig_imm, orig_triage_errs = _collect_safe_triage_top_entries(
        orig_triage,
        prefix=f"{prefix} original triage",
        expect_llm=expect_llm,
        allow_after_confirm_false=require_after_confirm_false,
    )
    rev_imm, rev_triage_errs = _collect_safe_triage_top_entries(
        rev_triage,
        prefix=f"{prefix} review triage",
        expect_llm=expect_llm,
        allow_after_confirm_false=require_after_confirm_false,
    )
    triage_manifest_errors.extend(orig_triage_errs)
    triage_manifest_errors.extend(rev_triage_errs)
    if orig_imm is not None and rev_imm is not None:
        triage_manifest_errors.extend(
            _compare_safe_file_maps(
                prefix,
                "triage pre-review artifact",
                orig_files=orig_imm,
                review_files=rev_imm,
            )
        )

    if expect_llm:
        orig_llm_files, orig_llm_errs = _collect_safe_rel_files(
            orig_triage / "llm_io", prefix=f"{prefix} original triage/llm_io", allow_subdirs=True
        )
        rev_llm_files, rev_llm_errs = _collect_safe_rel_files(
            rev_triage / "llm_io", prefix=f"{prefix} review triage/llm_io", allow_subdirs=True
        )
        triage_manifest_errors.extend(orig_llm_errs)
        triage_manifest_errors.extend(rev_llm_errs)
        if orig_llm_files is not None and rev_llm_files is not None:
            if not orig_llm_files:
                triage_manifest_errors.append(f"{prefix}: original triage/llm_io contains zero captured files")
            else:
                triage_manifest_errors.extend(
                    _compare_safe_file_maps(
                        prefix,
                        "triage/llm_io raw capture file",
                        orig_files=orig_llm_files,
                        review_files=rev_llm_files,
                    )
                )

    # Also ensure capture verification uses original capture directory when expect_live_source_current varies cleanly
    _ = expect_live_source_current
    return capture_errors, triage_manifest_errors, orig_cap


def _verify_capture_dir_integrity(
    prefix: str,
    capture_dir: Path,
    *,
    expected_cli_mode: str,
    expect_live_source_current: bool,
    trusted_original_capture_dir: Path | None = None,
) -> tuple[list[str], dict[str, Any] | None]:
    errors: list[str] = []
    if not _is_safe_dir(capture_dir):
        return [f"{prefix}: unsafe, missing, or reparse-linked capture dir: {capture_dir}"], None

    try:
        entries = list(capture_dir.iterdir())
    except OSError as exc:
        return [f"{prefix}: cannot list capture dir: {exc}"], None
    for entry in entries:
        if is_reparse_link(entry):
            errors.append(f"{prefix}: capture contains symlink/junction entry: {entry.name}")
    legacy_copy_dir = capture_dir / "legacy_reports"
    if os.path.lexists(legacy_copy_dir) and not _is_safe_dir(legacy_copy_dir):
        errors.append(f"{prefix}: unsafe or reparse-linked legacy_reports directory in capture dir: {legacy_copy_dir}")

    orig_capture_resolved: Path | None = None
    if trusted_original_capture_dir is not None:
        raw_orig = Path(trusted_original_capture_dir)
        cap_resolved = capture_dir.resolve(strict=True)
        if _has_parent_traversal(raw_orig) or not _is_safe_dir(raw_orig):
            errors.append(
                f"{prefix}: unsafe, missing, or reparse-linked trusted_original_capture_dir: {raw_orig}"
            )
        else:
            orig_cap = raw_orig.resolve(strict=True)
            orig_capture_resolved = orig_cap
            if _roots_overlap_or_nest(orig_cap, cap_resolved):
                errors.append(
                    f"{prefix}: trusted_original_capture_dir ({orig_cap}) cannot equal or nest with "
                    f"review capture_dir ({cap_resolved}) (self-pinning rejected)"
                )
            else:
                orig_errors, _ = _verify_capture_dir_integrity(
                    f"{prefix} original capture",
                    orig_cap,
                    expected_cli_mode=expected_cli_mode,
                    expect_live_source_current=expect_live_source_current,
                    trusted_original_capture_dir=None,
                )
                errors.extend(orig_errors)

    origin_path = capture_dir / "cli-origin.json"
    if not _is_safe_regular_file(origin_path):
        errors.append(f"{prefix}: missing or unsafe cli-origin.json")
    else:
        try:
            origin_doc = strict_json(origin_path.read_text(encoding="utf-8"))
            if not isinstance(origin_doc, dict):
                raise EvidenceError("cli-origin.json must be JSON object")
            if origin_doc.get("stage") != "exit":
                errors.append(f"{prefix}: cli-origin.json stage={origin_doc.get('stage')!r} != 'exit'")
            if origin_doc.get("cli_mode") != expected_cli_mode:
                errors.append(
                    f"{prefix}: cli-origin.json cli_mode={origin_doc.get('cli_mode')!r} != {expected_cli_mode!r}"
                )
            if origin_doc.get("forbidden_imports") != []:
                errors.append(f"{prefix}: cli-origin.json forbidden_imports non-empty: {origin_doc.get('forbidden_imports')}")
        except (OSError, UnicodeError, EvidenceError) as exc:
            errors.append(f"{prefix}: invalid cli-origin.json: {exc}")

    manifest_path = capture_dir / "scan-manifest.json"
    if not _is_safe_regular_file(manifest_path):
        errors.append(f"{prefix}: missing or unsafe scan-manifest.json")
        return errors, None

    try:
        s_man = strict_json(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, EvidenceError) as exc:
        errors.append(f"{prefix}: invalid scan-manifest.json: {exc}")
        return errors, None

    if not isinstance(s_man, dict) or s_man.get("schema") != "ntk-scan-capture-1":
        errors.append(f"{prefix}: invalid scan-manifest schema: {s_man.get('schema') if isinstance(s_man, dict) else None!r}")
        return errors, None

    try:
        t_start = contracts.timestamp(s_man.get("started_at"))
        t_end = contracts.timestamp(s_man.get("finished_at"))
        if t_end < t_start:
            errors.append(f"{prefix}: scan-manifest finished_at earlier than started_at")
    except (ValueError, TypeError) as exc:
        errors.append(f"{prefix}: invalid scan-manifest timestamps: {exc}")

    if s_man.get("success") is not True or s_man.get("issues"):
        errors.append(f"{prefix}: scan-manifest did not succeed cleanly (success={s_man.get('success')!r}, issues={s_man.get('issues')!r})")

    src_before = s_man.get("sources_before")
    src_after = s_man.get("sources_after")
    if not isinstance(src_before, dict) or not src_before or src_before != src_after:
        errors.append(f"{prefix}: scan-manifest sources_before/sources_after invalid or mismatched")
    else:
        for sp, sv in src_before.items():
            try:
                contracts.relative_java(sp)
                contracts.hexhash(sv)
            except ValueError as exc:
                errors.append(f"{prefix}: invalid source inventory entry {sp!r}: {exc}")

    rules_before = s_man.get("rules_before_sha256")
    rules_after = s_man.get("rules_after_sha256")
    try:
        contracts.hexhash(rules_before)
        if rules_before != rules_after:
            errors.append(f"{prefix}: scan-manifest rules_before_sha256 != rules_after_sha256")
    except ValueError as exc:
        errors.append(f"{prefix}: invalid scan-manifest rules hash: {exc}")

    artifacts = s_man.get("artifacts")
    if not isinstance(artifacts, dict):
        errors.append(f"{prefix}: scan-manifest missing artifacts dict")
        artifacts = {}
    else:
        missing_art = sorted(REQUIRED_SCANNER_CAPTURE_FILES - set(artifacts))
        if missing_art:
            errors.append(f"{prefix}: scan-manifest missing required artifacts: {missing_art}")
        for art_name, art_sha in artifacts.items():
            if not isinstance(art_name, str) or Path(art_name).name != art_name or "/" in art_name or "\\" in art_name or ":" in art_name or art_name in (".", ".."):
                errors.append(f"{prefix}: unsafe capture artifact name {art_name!r}")
                continue
            art_file = capture_dir / art_name
            if not _is_safe_regular_file(art_file):
                errors.append(f"{prefix}: missing or unsafe capture artifact {art_name}")
                continue
            if digest(art_file.read_bytes()) != art_sha:
                errors.append(f"{prefix}: capture artifact SHA-256 mismatch: {art_name}")

    rules_snap = capture_dir / "rules.snapshot.yml"
    if _is_safe_regular_file(rules_snap) and isinstance(rules_before, str):
        if digest(rules_snap.read_bytes()) != rules_before:
            errors.append(f"{prefix}: rules.snapshot.yml SHA-256 differs from rules_before_sha256")

    if orig_capture_resolved is not None and orig_capture_resolved != capture_dir.resolve(strict=True):
        errors.extend(
            _verify_relocated_capture_parity(
                prefix,
                review_capture_dir=capture_dir,
                original_capture_dir=orig_capture_resolved,
                review_manifest=s_man,
            )
        )

    runs = s_man.get("runs")
    if not isinstance(runs, dict):
        errors.append(f"{prefix}: scan-manifest missing runs dict")
        runs = {}
    exe_names: set[str] = set()
    for label in ("version", "json", "sarif"):
        r_meta = runs.get(label)
        if not isinstance(r_meta, dict):
            errors.append(f"{prefix}: scan-manifest missing run record {label}")
            continue
        argv = r_meta.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(x, str) and x for x in argv):
            errors.append(f"{prefix}: invalid {label} argv in scan-manifest")
            continue
        exe_names.add(argv[0])
        if type(r_meta.get("exit_code")) is not int or r_meta.get("exit_code") != 0:
            errors.append(f"{prefix}: child run {label} exit_code={r_meta.get('exit_code')!r} != 0")

        exit_file = capture_dir / f"{label}.exit.txt"
        if not _is_safe_regular_file(exit_file):
            errors.append(f"{prefix}: missing or unsafe {label}.exit.txt")
        else:
            try:
                exit_val = int(exit_file.read_text(encoding="utf-8").strip())
                if exit_val != 0 or exit_val != r_meta.get("exit_code"):
                    errors.append(f"{prefix}: {label}.exit.txt={exit_val!r} does not match exit_code 0")
            except (OSError, UnicodeError, ValueError) as exc:
                errors.append(f"{prefix}: unreadable {label}.exit.txt: {exc}")

        cmd_file = capture_dir / f"{label}.command.json"
        if not _is_safe_regular_file(cmd_file):
            errors.append(f"{prefix}: missing or unsafe {label}.command.json")
        else:
            try:
                if strict_json(cmd_file.read_text(encoding="utf-8")) != argv:
                    errors.append(f"{prefix}: {label}.command.json disagrees with scan-manifest runs.{label}.argv")
            except (OSError, UnicodeError, EvidenceError) as exc:
                errors.append(f"{prefix}: invalid {label}.command.json: {exc}")

        if label in ("json", "sarif"):
            cap_file = capture_dir / f"opengrep.{label}"
            if not _is_safe_regular_file(cap_file):
                errors.append(f"{prefix}: missing or unsafe opengrep.{label}")
                continue
            cap_bytes = cap_file.read_bytes()
            mode = r_meta.get("output_mode", "stdout")
            if mode == "file":
                if (
                    argv.count("--output") != 1
                    or argv.index("--output") + 1 >= len(argv)
                    or f"--{label}" not in argv
                    or argv[argv.index("--output") + 1] != r_meta.get("engine_output_path")
                ):
                    errors.append(f"{prefix}: invalid file output flags for {label}")
                else:
                    legacy_path = Path(str(r_meta.get("engine_output_path", "")))
                    containment_root = (
                        orig_capture_resolved if orig_capture_resolved is not None else capture_dir.resolve()
                    )
                    if _has_parent_traversal(legacy_path) or not _is_safe_regular_file(legacy_path):
                        errors.append(f"{prefix}: missing or unsafe engine_output_path for {label}")
                    elif not legacy_path.resolve().is_relative_to(containment_root):
                        if orig_capture_resolved is None:
                            errors.append(f"{prefix}: engine_output_path escapes capture dir for {label}")
                        else:
                            errors.append(f"{prefix}: engine_output_path escapes pinned original capture dir for {label}")
                    elif legacy_path.read_bytes() != cap_bytes:
                        errors.append(f"{prefix}: legacy output bytes != opengrep.{label} bytes")
            elif mode == "stdout":
                stdout_file = capture_dir / f"{label}.stdout.txt"
                if not _is_safe_regular_file(stdout_file) or stdout_file.read_bytes() != cap_bytes:
                    errors.append(f"{prefix}: {label}.stdout.txt bytes != opengrep.{label} bytes")
            else:
                errors.append(f"{prefix}: unsupported capture output_mode {mode!r} for {label}")

    if len(exe_names) > 1:
        errors.append(f"{prefix}: inconsistent scanner executable across version/json/sarif runs")

    if expect_live_source_current:
        src_root_raw = s_man.get("source_root")
        raw_json_file = capture_dir / "opengrep.json"
        if not isinstance(src_root_raw, str) or not src_root_raw or not _is_safe_dir(Path(src_root_raw)):
            errors.append(f"{prefix}: scan-manifest source_root missing or unsafe: {src_root_raw!r}")
        elif _is_safe_regular_file(raw_json_file):
            if isinstance(src_before, dict):
                for rel_java in src_before:
                    java_path = Path(src_root_raw) / Path(*rel_java.split("/"))
                    if not _is_safe_regular_file(java_path):
                        errors.append(f"{prefix}: source file missing or symlink/junction on disk: {rel_java}")
            receipt_meta, receipt_issues = verify_receipt(
                manifest_path,
                raw_json_file.read_bytes(),
                src_root_raw,
                declared_exit=0,
            )
            if (
                receipt_issues
                or receipt_meta.get("source_capture_verified") is not True
                or receipt_meta.get("exit_capture_verified") is not True
            ):
                errors.append(f"{prefix}: scan receipt verification failed: {receipt_issues}")

    return errors, s_man


def _has_raw_path_metadata_key(prompt_evidence: dict[str, Any]) -> bool:
    for snip in prompt_evidence.get("snippets") or []:
        if isinstance(snip, dict) and "raw_path" in snip:
            return True
    for step in prompt_evidence.get("trace_steps") or []:
        if isinstance(step, dict) and "raw_path" in step:
            return True
    return "raw_path" in prompt_evidence


def _inspect_primary_scenario(
    scenario_name: str,
    scenario_dir: Path,
    *,
    expected_findings: int,
    expected_polarity: str,
    allow_mock_primary: bool,
    require_after_confirm_false: bool = False,
    trusted_original_scenario_dir: Path | None = None,
    trusted_original_capture_dir: Path | None = None,
) -> dict[str, Any]:
    raw_scenario_dir = Path(scenario_dir)
    failures: list[str] = []
    blockers: list[str] = []
    r02_errors: list[str] = []
    r03_errors: list[str] = []

    if not _is_safe_dir(raw_scenario_dir):
        if _is_missing_clean_path(raw_scenario_dir):
            return {
                "scenario": scenario_name,
                "status": "BLOCKED",
                "findings_count": 0,
                "r02_errors": [],
                "r03_errors": [],
                "blockers": [f"missing scenario directory: {raw_scenario_dir}"],
                "failures": [],
            }
        msg = f"{scenario_name}: scenario directory is unsafe or traverses a symlink/junction: {raw_scenario_dir}"
        return {
            "scenario": scenario_name,
            "status": "FAIL",
            "findings_count": 0,
            "r02_errors": [msg],
            "r03_errors": [msg],
            "blockers": [],
            "failures": [msg],
        }

    scenario_dir = raw_scenario_dir.resolve()
    manifest_path = scenario_dir / "g1-run-manifest.json"
    capture_dir = scenario_dir / "capture"
    triage_dir = scenario_dir / "triage"
    if (
        (os.path.lexists(capture_dir) and is_reparse_link(capture_dir))
        or (os.path.lexists(triage_dir) and is_reparse_link(triage_dir))
        or (os.path.lexists(manifest_path) and is_reparse_link(manifest_path))
    ):
        msg = f"{scenario_name}: capture, triage, or g1-run-manifest.json is a symlink/junction"
        return {
            "scenario": scenario_name,
            "status": "FAIL",
            "findings_count": 0,
            "r02_errors": [msg],
            "r03_errors": [msg],
            "blockers": [],
            "failures": [msg],
        }
    if not _is_safe_regular_file(manifest_path) or not _is_safe_dir(capture_dir) or not _is_safe_dir(triage_dir):
        return {
            "scenario": scenario_name,
            "status": "BLOCKED",
            "findings_count": 0,
            "r02_errors": [],
            "r03_errors": [],
            "blockers": [f"{scenario_name}: missing g1-run-manifest.json, capture/, or triage/"],
            "failures": [],
        }

    evidence_path = triage_dir / "evidence.json"
    assessments_path = triage_dir / "assessments.jsonl"
    if not _is_safe_regular_file(evidence_path) or not _is_safe_regular_file(assessments_path):
        msg = f"{scenario_name}: missing or unsafe triage/evidence.json or triage/assessments.jsonl"
        return {
            "scenario": scenario_name,
            "status": "FAIL",
            "findings_count": 0,
            "r02_errors": [msg],
            "r03_errors": [msg],
            "blockers": [],
            "failures": [msg],
        }

    try:
        manifest = strict_json(manifest_path.read_text(encoding="utf-8"))
        evidence_bundle = strict_json(evidence_path.read_text(encoding="utf-8"))
        rows = [
            strict_json(line)
            for line in assessments_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, UnicodeError, EvidenceError) as exc:
        msg = f"{scenario_name}: invalid g1-run-manifest/evidence/assessments JSON: {exc}"
        return {
            "scenario": scenario_name,
            "status": "FAIL",
            "findings_count": 0,
            "r02_errors": [msg],
            "r03_errors": [msg],
            "blockers": [],
            "failures": [msg],
        }

    if not isinstance(manifest, dict) or manifest.get("schema") != "ntk-g1-run-manifest-1":
        schema_val = manifest.get("schema") if isinstance(manifest, dict) else None
        msg_schema = f"{scenario_name}: invalid g1-run-manifest schema={schema_val!r} != 'ntk-g1-run-manifest-1'"
        r02_errors.append(msg_schema)
        r03_errors.append(msg_schema)
        if not isinstance(manifest, dict):
            manifest = {}

    if len(rows) != expected_findings:
        failures.append(f"{scenario_name}: expected {expected_findings} finding(s), observed {len(rows)}")

    if manifest.get("prompt_contract") != PROMPT_CONTRACT_BLIND:
        failures.append(f"{scenario_name}: manifest prompt_contract={manifest.get('prompt_contract')!r} != 'blind'")
    if manifest.get("prompt_version") != PROMPT_VERSION:
        failures.append(f"{scenario_name}: manifest prompt_version={manifest.get('prompt_version')!r} != {PROMPT_VERSION!r}")

    # B1 HTTP capture check
    http_check = verify_run_http_captures(
        triage_dir,
        require_live_chat=not allow_mock_primary,
        minimum_findings=expected_findings,
    )
    if not http_check["capture_integrity_ok"]:
        if any("used in-memory mocked request()" in e or "is marked mock" in e for e in http_check["errors"]):
            blockers.append(f"{scenario_name}: HTTP capture is mock/non-live: {http_check['errors']}")
        else:
            blockers.append(f"{scenario_name}: raw HTTP capture verification failed: {http_check['errors']}")

    # Live protocol check (exact finding count minimum, never minimum=1 for 2-finding Demo1!)
    proto = live_check.inspect(rows, minimum=expected_findings)
    if not allow_mock_primary and proto.get("protocol_status") != "OLLAMA_REPORTED_UNATTESTED":
        blockers.append(
            f"{scenario_name}: live_check protocol_status={proto.get('protocol_status')} "
            f"(completed={proto.get('completed_reported_responses')}/{expected_findings})"
        )

    # R02 checks on this scenario
    if manifest.get("triage_subprocess_invocations") != 0:
        r02_errors.append(f"{scenario_name}: triage_subprocess_invocations={manifest.get('triage_subprocess_invocations')} != 0")
    st = manifest.get("stage_statuses") or {}
    for key, expected_val in (
        ("scanner_status", "OK"),
        ("source_integrity_status", "VERIFIED"),
        ("json_sarif_parity_status", "MATCHED"),
        ("handoff_status", "VERIFIED"),
        ("queue_status", "OPEN_READY"),
    ):
        if st.get(key) != expected_val:
            r02_errors.append(f"{scenario_name}: stage_statuses.{key}={st.get(key)!r} != {expected_val!r}")
    if manifest.get("pre_scan_sources_sha256") != manifest.get("post_triage_sources_sha256") or not manifest.get("pre_scan_sources_sha256"):
        r02_errors.append(f"{scenario_name}: pre/post source SHA-256 mismatch or empty")

    raw_json_path = capture_dir / "opengrep.json"
    raw_sarif_path = capture_dir / "opengrep.sarif"
    triage_input_path = triage_dir / "input.opengrep.json"
    if not _is_safe_regular_file(raw_json_path) or not _is_safe_regular_file(raw_sarif_path):
        r02_errors.append(f"{scenario_name}: missing or unsafe capture/opengrep.json or opengrep.sarif")
    else:
        raw_bytes = raw_json_path.read_bytes()
        if not _is_safe_regular_file(triage_input_path):
            r02_errors.append(f"{scenario_name}: missing or unsafe mandatory triage/input.opengrep.json")
        elif triage_input_path.read_bytes() != raw_bytes:
            r02_errors.append(f"{scenario_name}: triage/input.opengrep.json differs from capture/opengrep.json")
        try:
            raw_doc = contracts.strict(raw_bytes.decode("utf-8"))
            sarif_doc = contracts.strict(raw_sarif_path.read_bytes().decode("utf-8"))
            contracts.validate_bundle(raw_bytes, raw_doc, evidence_bundle)
            contracts.validate_rows(rows, evidence_bundle)
            contracts.compare_sarif(raw_doc, sarif_doc)
        except (ValueError, KeyError, TypeError, UnicodeError) as exc:
            r02_errors.append(f"{scenario_name}: independent contract/SARIF validation failed: {exc}")

    cap_errors, s_man = _verify_capture_dir_integrity(
        scenario_name,
        capture_dir,
        expected_cli_mode="local-triage",
        expect_live_source_current=True,
        trusted_original_capture_dir=trusted_original_capture_dir,
    )
    r02_errors.extend(cap_errors)

    scen_cap_errs, scen_triage_errs, _ = _verify_relocated_scenario_provenance(
        scenario_name,
        review_scenario_dir=scenario_dir,
        review_capture_dir=capture_dir,
        trusted_original_scenario_dir=trusted_original_scenario_dir,
        trusted_original_capture_dir=trusted_original_capture_dir,
        expect_llm=True,
        expect_live_source_current=True,
        require_after_confirm_false=require_after_confirm_false,
    )
    if scen_cap_errs:
        r02_errors.extend(scen_cap_errs)
    if scen_triage_errs:
        failures.extend(scen_triage_errs)
        r02_errors.extend(scen_triage_errs)
        r03_errors.extend(scen_triage_errs)

    if s_man is not None:
        if manifest.get("pre_scan_sources_sha256") != s_man.get("sources_before"):
            r02_errors.append(f"{scenario_name}: g1-run-manifest pre_scan_sources_sha256 differs from scan-manifest sources_before")
        if manifest.get("rules_sha256") != s_man.get("rules_before_sha256"):
            r02_errors.append(f"{scenario_name}: g1-run-manifest rules_sha256 differs from scan-manifest rules_before_sha256")

    artifacts_meta = manifest.get("artifacts")
    if not isinstance(artifacts_meta, dict):
        r02_errors.append(f"{scenario_name}: g1-run-manifest missing artifacts")
    else:
        for akey, apath in (
            ("opengrep_json", capture_dir / "opengrep.json"),
            ("opengrep_sarif", capture_dir / "opengrep.sarif"),
            ("scan_manifest", capture_dir / "scan-manifest.json"),
            ("cli_origin", capture_dir / "cli-origin.json"),
            ("evidence_json", triage_dir / "evidence.json"),
            ("assessments_jsonl", triage_dir / "assessments.jsonl"),
            ("http_capture_check", triage_dir / "http-capture-check.json"),
        ):
            _, art_errs = _verify_manifest_artifact_hash(scenario_name, artifacts_meta, akey, apath)
            r02_errors.extend(art_errs)

    # Live source drift check against finding evidence snapshots (R02 STALE_SOURCE failure)
    records = evidence_bundle.get("records") or []
    for idx, rec in enumerate(records):
        try:
            check_current(rec)
        except (StaleSourceError, EvidenceError, OSError, ValueError, RuntimeError) as exc:
            r02_errors.append(f"{scenario_name}[{idx}]: live source drift / integrity error: {exc}")

    # Per-finding R01 prompt, raw body replay, validator & canonical citation checks
    per_finding_details: list[dict[str, Any]] = []
    for idx, (rec, row) in enumerate(zip(records, rows)):
        rec_id = rec["id"]
        safe_id = _safe_id(rec_id)
        assessment = row["assessment"]
        runtime = assessment.get("runtime") or {}
        f_errors: list[str] = []

        if row.get("state") != "OPEN":
            f_errors.append(f"assessments.jsonl state={row.get('state')!r} != 'OPEN'")
        if assessment.get("prompt_version") != PROMPT_VERSION:
            f_errors.append(f"assessment.prompt_version={assessment.get('prompt_version')!r} != {PROMPT_VERSION!r}")
        if assessment.get("prompt_contract") != PROMPT_CONTRACT_BLIND:
            f_errors.append(f"assessment.prompt_contract={assessment.get('prompt_contract')!r} != 'blind'")
        if rec.get("triage_mode") not in (None, "evidence+llm"):
            f_errors.append(f"unexpected triage_mode={rec.get('triage_mode')!r}")
        if assessment.get("requires_human_review") is not True or assessment.get("security_conclusion_verified") is not False:
            f_errors.append("human-review separation flags violated")

        prompt_file = triage_dir / "llm_io" / f"{safe_id}.prompt.json"
        if not _is_safe_regular_file(prompt_file):
            f_errors.append(f"missing or unsafe {safe_id}.prompt.json")
        else:
            p_doc = strict_json(prompt_file.read_text(encoding="utf-8"))
            if p_doc.get("prompt_contract") != PROMPT_CONTRACT_BLIND or p_doc.get("prompt_version") != PROMPT_VERSION:
                f_errors.append(f"{safe_id}.prompt.json contract/version mismatch")
            msgs = p_doc.get("messages") or []
            if len(msgs) != 2 or not isinstance(msgs[1], dict) or not isinstance(msgs[1].get("content"), str):
                f_errors.append(f"{safe_id}.prompt.json missing 2-message structure")
            else:
                user_ev = strict_json(msgs[1]["content"])
                if _has_raw_path_metadata_key(user_ev):
                    f_errors.append(f"{safe_id}.prompt.json leaked raw_path metadata key")
                try:
                    assert_prompt_contract(user_ev, PROMPT_CONTRACT_BLIND)
                except EvidenceError as exc:
                    f_errors.append(f"{safe_id}.prompt.json violated blind contract: {exc}")

        # Replay raw HTTP response body -> validate_answer
        resp_bin = triage_dir / "llm_io" / f"{safe_id}.response.body.bin"
        if _is_safe_regular_file(resp_bin):
            replayed_answer = None
            try:
                env_doc = strict_json(resp_bin.read_bytes().decode("utf-8"))
                msg_content = env_doc.get("message", {}).get("content") if isinstance(env_doc, dict) and isinstance(env_doc.get("message"), dict) else None
                if isinstance(msg_content, str):
                    replayed_answer = validate_answer(msg_content, rec)
                else:
                    f_errors.append(f"{safe_id}.response.body.bin missing assistant message.content string")
            except (UnicodeError, ValueError, EvidenceError) as exc:
                f_errors.append(f"unchanged validator rejected {safe_id}.response.body.bin: {exc}")
        else:
            replayed_answer = None
            blockers.append(f"{scenario_name}[{idx}]: missing or unsafe {safe_id}.response.body.bin")

        raw_status = assessment.get("raw_model_status")
        val_status = assessment.get("validated_status", assessment.get("status"))
        fail_kind = assessment.get("failure_kind")
        downgraded = assessment.get("validator_downgraded")

        if expected_polarity in ("SUPPORTED", "REFUTED"):
            # Demo1 and Demo2 require conclusive verdicts passing unchanged validator with canonical citations
            if val_status != expected_polarity:
                f_errors.append(
                    f"expected conclusive validated_status={expected_polarity!r}, observed {val_status!r} "
                    f"(raw_model_status={raw_status!r}, failure_kind={fail_kind!r})"
                )
            if downgraded is not False or fail_kind != "NONE" or runtime.get("answer_validated") is not True:
                f_errors.append(
                    f"validator did not accept answer cleanly (downgraded={downgraded}, failure_kind={fail_kind}, "
                    f"answer_validated={runtime.get('answer_validated')})"
                )
            cites = assessment.get("citations") or []
            if not cites or assessment.get("citation_check") != "MATCHED":
                f_errors.append("conclusive verdict missing MATCHED canonical citations")
            else:
                prov = inspect_citations_provenance(cites, rec)
                if not (
                    prov["citation_in_source"] is True
                    and prov["citation_in_prompt"] is True
                    and prov["citation_posthoc_only"] is False
                    and prov["all_executable_code"] is True
                    and prov["any_dead_branch"] is False
                    and prov["any_in_relevant_scope"] is True
                    and prov["supports_security_claim_verified"] is False
                ):
                    f_errors.append(f"citation provenance check failed: {prov}")
            if replayed_answer is None or replayed_answer.get("validated_status") != expected_polarity:
                f_errors.append("independent validator replay from raw HTTP body did not reproduce expected conclusive status")
        elif expected_polarity == "UNDETERMINED_ABSTAIN":
            # Demo3a requires genuine model abstention (not SUPPORTED, not REFUTED, and not crash/invalid-citation fallback)
            if val_status != "UNDETERMINED":
                f_errors.append(f"Demo3a missing-helper must be UNDETERMINED, observed validated_status={val_status!r}")
            if raw_status != "UNDETERMINED":
                f_errors.append(
                    f"Demo3a requires genuine model abstention (raw_model_status='UNDETERMINED'), observed raw_model_status={raw_status!r}"
                )
            if downgraded is not False or fail_kind != "NONE" or runtime.get("answer_validated") is not True:
                f_errors.append(
                    f"Demo3a UNDETERMINED resulted from validator/transport failure rather than valid abstention "
                    f"(downgraded={downgraded}, failure_kind={fail_kind}, answer_validated={runtime.get('answer_validated')})"
                )
            if replayed_answer is None or replayed_answer.get("validated_status") != "UNDETERMINED":
                f_errors.append("independent validator replay from raw HTTP body did not reproduce valid UNDETERMINED abstention")
        elif expected_polarity == "OBSERVED_VALID_TRIAGE":
            # Supplementary control preserves observed Qwen verdict (REFUTED / SUPPORTED / UNDETERMINED) without coercion
            if val_status not in ("SUPPORTED", "REFUTED", "UNDETERMINED"):
                f_errors.append(
                    f"invalid validated_status={val_status!r} (expected SUPPORTED, REFUTED, or UNDETERMINED)"
                )
            if raw_status not in ("SUPPORTED", "REFUTED", "UNDETERMINED"):
                f_errors.append(
                    f"missing or non-enum raw_model_status={raw_status!r} (failure_kind={fail_kind!r})"
                )
            if downgraded is not False or fail_kind != "NONE" or runtime.get("answer_validated") is not True:
                f_errors.append(
                    f"validator did not accept answer cleanly (downgraded={downgraded}, failure_kind={fail_kind}, "
                    f"answer_validated={runtime.get('answer_validated')})"
                )
            cites = assessment.get("citations") or []
            if val_status in ("SUPPORTED", "REFUTED") or cites:
                if not cites or assessment.get("citation_check") != "MATCHED":
                    f_errors.append("supplementary control verdict missing MATCHED canonical citations")
                else:
                    prov = inspect_citations_provenance(cites, rec)
                    if not (
                        prov["citation_in_source"] is True
                        and prov["citation_in_prompt"] is True
                        and prov["citation_posthoc_only"] is False
                        and prov["all_executable_code"] is True
                        and prov["any_dead_branch"] is False
                        and prov["any_in_relevant_scope"] is True
                        and prov["supports_security_claim_verified"] is False
                    ):
                        f_errors.append(f"citation provenance check failed: {prov}")
            if replayed_answer is None or replayed_answer.get("validated_status") != val_status:
                f_errors.append("independent validator replay from raw HTTP body did not reproduce observed validated_status")

        failures.extend(f"{scenario_name}[{idx}]: {e}" for e in f_errors)
        per_finding_details.append({
            "finding_index": idx,
            "id": rec_id,
            "rule_id": rec.get("rule_id"),
            "cwe": rec.get("cwe"),
            "raw_model_status": raw_status,
            "validated_status": val_status,
            "validator_downgraded": downgraded,
            "failure_kind": fail_kind,
            "answer_validated": runtime.get("answer_validated"),
            "citations_count": len(assessment.get("citations") or []),
            "citation_check": assessment.get("citation_check"),
            "passed": len(f_errors) == 0,
            "errors": f_errors,
        })

    # Mandatory pre-lifecycle SQLite snapshot check & mandatory SHA-256 anchor (F06/F07)
    pre_db = triage_dir / "review.post_ingestion.sqlite"
    expected_rev_sha, rev_anchor_errs = _verify_manifest_artifact_hash(
        scenario_name,
        artifacts_meta,
        "review_sqlite",
        pre_db,
        expected_basename="review.sqlite",
    )
    r03_errors.extend(rev_anchor_errs)

    ing_db_state = None
    if not _is_safe_regular_file(pre_db):
        r03_errors.append(f"{scenario_name}: missing or unsafe mandatory review.post_ingestion.sqlite")
    else:
        try:
            ing_db_state = _read_sqlite_state_ro(pre_db)
            r03_errors.extend(
                _verify_sqlite_against_triage(
                    f"{scenario_name} post_ingestion",
                    ing_db_state,
                    evidence_bundle,
                    rows,
                    scan_manifest=s_man,
                    run_manifest=manifest,
                    require_zero_rejected=True,
                    allow_scripted_events=allow_mock_primary,
                )
            )
            if len(ing_db_state["warnings"]) != expected_findings or any(w["state"] != "OPEN" for w in ing_db_state["warnings"]):
                r03_errors.append(f"{scenario_name}: review.post_ingestion.sqlite does not hold {expected_findings} OPEN warning(s)")
            if ing_db_state["events"]:
                r03_errors.append(f"{scenario_name}: review.post_ingestion.sqlite unexpectedly has pre-existing events")
            if expected_rev_sha is None or ing_db_state["db_sha256"] != expected_rev_sha:
                r03_errors.append(
                    f"{scenario_name}: review.post_ingestion.sqlite SHA-256 missing mandatory anchor or differs from manifest artifacts.review_sqlite.sha256"
                )
        except (OSError, sqlite3.Error, EvidenceError, ValueError, KeyError, TypeError) as exc:
            r03_errors.append(f"{scenario_name}: invalid review.post_ingestion.sqlite: {exc}")

    current_db_state = None
    try:
        current_db_state = _read_sqlite_state_ro(triage_dir / "review.sqlite")
        r03_errors.extend(
            _verify_sqlite_against_triage(
                f"{scenario_name} review.sqlite",
                current_db_state,
                evidence_bundle,
                rows,
                scan_manifest=s_man,
                run_manifest=manifest,
                require_zero_rejected=True,
                allow_scripted_events=allow_mock_primary,
            )
        )
        if ing_db_state is not None:
            if current_db_state["events"] or current_db_state["rejected_decisions"]:
                if current_db_state["db_sha256"] == ing_db_state["db_sha256"]:
                    r03_errors.append(
                        f"{scenario_name}: review.sqlite SHA-256 equals review.post_ingestion.sqlite despite recorded lifecycle events"
                    )
            else:
                if current_db_state["db_sha256"] != ing_db_state["db_sha256"]:
                    r03_errors.append(
                        f"{scenario_name}: review.sqlite SHA-256 differs from review.post_ingestion.sqlite despite zero lifecycle events"
                    )
    except (OSError, sqlite3.Error, EvidenceError, ValueError, KeyError, TypeError) as exc:
        r03_errors.append(f"{scenario_name}: invalid review.sqlite: {exc}")

    af_db_state = None
    if require_after_confirm_false:
        after_false_snap = triage_dir / "review.after_confirm_false.sqlite"
        if not _is_safe_regular_file(after_false_snap):
            r03_errors.append(f"{scenario_name}: missing or unsafe mandatory review.after_confirm_false.sqlite")
        else:
            try:
                af_db_state = _read_sqlite_state_ro(after_false_snap)
                r03_errors.extend(
                    _verify_sqlite_against_triage(
                        f"{scenario_name} after_confirm_false",
                        af_db_state,
                        evidence_bundle,
                        rows,
                        scan_manifest=s_man,
                        run_manifest=manifest,
                        require_zero_rejected=True,
                        allow_scripted_events=allow_mock_primary,
                    )
                )
                if [w["state"] for w in af_db_state["warnings"]] != ["CONFIRMED_FALSE"]:
                    r03_errors.append(f"{scenario_name}: review.after_confirm_false.sqlite does not show ['CONFIRMED_FALSE']")
                if [ev["action"] for ev in af_db_state["events"]] != ["confirm-false"]:
                    r03_errors.append(f"{scenario_name}: review.after_confirm_false.sqlite events != ['confirm-false']")
                elif current_db_state is not None and (
                    not current_db_state["events"] or af_db_state["events"][0] != current_db_state["events"][0]
                ):
                    r03_errors.append(f"{scenario_name}: review.after_confirm_false.sqlite event differs from current review.sqlite events[0]")
                if ing_db_state is not None and af_db_state["db_sha256"] == ing_db_state["db_sha256"]:
                    r03_errors.append(
                        f"{scenario_name}: review.after_confirm_false.sqlite SHA-256 unexpectedly equals review.post_ingestion.sqlite"
                    )
                if (
                    current_db_state is not None
                    and len(current_db_state["events"]) > 1
                    and af_db_state["db_sha256"] == current_db_state["db_sha256"]
                ):
                    r03_errors.append(
                        f"{scenario_name}: review.after_confirm_false.sqlite SHA-256 unexpectedly equals post-reopen review.sqlite"
                    )
            except (OSError, sqlite3.Error, EvidenceError, ValueError, KeyError, TypeError) as exc:
                r03_errors.append(f"{scenario_name}: invalid review.after_confirm_false.sqlite: {exc}")

    current_sqlite_info = None
    if current_db_state is not None:
        current_sqlite_info = {
            "db_sha256": current_db_state["db_sha256"],
            "states": [w["state"] for w in current_db_state["warnings"]],
            "events_count": len(current_db_state["events"]),
            "rejected_count": len(current_db_state["rejected_decisions"]),
            "events": current_db_state["events"],
            "rejected_decisions": current_db_state["rejected_decisions"],
        }

    result_obj: dict[str, Any] = {
        "scenario": scenario_name,
        "findings_count": len(rows),
        "http_capture": http_check,
        "live_protocol": proto,
        "capture_relocation": {
            "relocated_mode": (
                trusted_original_capture_dir is not None or trusted_original_scenario_dir is not None
            ),
            "pinned_original_scenario_dir": (
                str(trusted_original_scenario_dir) if trusted_original_scenario_dir is not None else None
            ),
            "pinned_original_capture_dir": (
                str(trusted_original_capture_dir) if trusted_original_capture_dir is not None else None
            ),
        },
        "r02_errors": r02_errors,
        "r03_errors": r03_errors,
        "findings": per_finding_details,
        "run_provenance": {
            "scenario_dir_name": Path(scenario_dir).name,
            "recorded_at": manifest.get("recorded_at"),
            "model": manifest.get("model"),
            "prompt_contract": manifest.get("prompt_contract"),
            "prompt_version": manifest.get("prompt_version"),
            "rules_sha256": manifest.get("rules_sha256"),
            "pre_scan_sources_sha256": manifest.get("pre_scan_sources_sha256"),
            "post_triage_sources_sha256": manifest.get("post_triage_sources_sha256"),
            "opengrep_version": s_man.get("opengrep_version") if isinstance(s_man, dict) else None,
            "source_hashes": {
                str(rec.get("path")): {
                    p: snap.get("sha256")
                    for p, snap in (rec.get("snapshots") or {}).items()
                    if isinstance(snap, dict)
                }
                for rec in records
                if isinstance(rec, dict)
            },
        },
        "post_ingestion_sqlite": {
            "present": ing_db_state is not None,
            "db_sha256": ing_db_state["db_sha256"] if ing_db_state else None,
            "states": [w["state"] for w in ing_db_state["warnings"]] if ing_db_state else None,
        },
        "current_sqlite": current_sqlite_info,
        "blockers": blockers,
        "failures": failures,
    }
    if require_after_confirm_false:
        result_obj["after_confirm_false_sqlite"] = {
            "present": af_db_state is not None,
            "db_sha256": af_db_state["db_sha256"] if af_db_state else None,
            "states": [w["state"] for w in af_db_state["warnings"]] if af_db_state else None,
        }
    return result_obj


def _verify_relocated_m1_provenance(
    *,
    review_m1_dir: Path,
    review_cap_dir: Path,
    trusted_original_scenario_dir: Path | None,
    trusted_original_capture_dir: Path | None,
) -> list[str]:
    """Verify M1 scan-only relocated review copy against operator-pinned original scenario and capture dirs."""
    if trusted_original_scenario_dir is None and trusted_original_capture_dir is None:
        return []
    if trusted_original_scenario_dir is None or trusted_original_capture_dir is None:
        return [
            "M1: relocation pinning requires BOTH trusted_original_scenario_dir and "
            "trusted_original_capture_dir to be provided together"
        ]
    errors: list[str] = []
    raw_orig_m1 = Path(trusted_original_scenario_dir)
    raw_orig_cap = Path(trusted_original_capture_dir)
    if _has_parent_traversal(raw_orig_m1) or not _is_safe_dir(raw_orig_m1):
        errors.append(f"M1: unsafe, missing, or reparse-linked trusted_original_scenario_dir: {raw_orig_m1}")
    if _has_parent_traversal(raw_orig_cap) or not _is_safe_dir(raw_orig_cap):
        errors.append(f"M1: unsafe, missing, or reparse-linked trusted_original_capture_dir: {raw_orig_cap}")
    if errors:
        return errors

    orig_m1 = raw_orig_m1.resolve(strict=True)
    orig_cap = raw_orig_cap.resolve(strict=True)
    rev_m1 = review_m1_dir.resolve(strict=True)
    rev_cap = review_cap_dir.resolve(strict=True)
    if _roots_overlap_or_nest(orig_m1, rev_m1):
        errors.append(
            f"M1: trusted_original_scenario_dir ({orig_m1}) cannot equal or nest with review dir ({rev_m1})"
        )
    if _roots_overlap_or_nest(orig_cap, rev_cap):
        errors.append(
            f"M1: trusted_original_capture_dir ({orig_cap}) cannot equal or nest with review capture dir ({rev_cap})"
        )

    for forbidden_rel in ("triage", "g1-run-manifest.json", "llm_io", "assessments.jsonl", "review.sqlite"):
        if os.path.lexists(orig_m1 / forbidden_rel):
            errors.append(f"M1 original scenario unexpectedly contains {forbidden_rel}")

    if os.path.lexists(orig_m1 / "scan-manifest.json"):
        if orig_cap != orig_m1:
            errors.append(
                f"M1: trusted_original_capture_dir ({orig_cap}) must equal original flat scenario dir ({orig_m1})"
            )
    else:
        orig_cap_child = orig_m1 / "capture"
        if os.path.lexists(orig_cap_child) and is_reparse_link(orig_cap_child):
            errors.append(f"M1: original scenario capture/ is a symlink/junction: {orig_cap_child}")
        elif not _is_safe_dir(orig_cap_child) or orig_cap != orig_cap_child.resolve(strict=True):
            errors.append(
                f"M1: trusted_original_capture_dir ({orig_cap}) is not bound to original scenario/capture ({orig_cap_child})"
            )
        try:
            orig_top = {p.name for p in orig_m1.iterdir()}
            if orig_top != {"capture"}:
                errors.append(f"M1: unexpected top-level entries in original scenario dir: {sorted(orig_top)}")
        except OSError as exc:
            errors.append(f"M1: cannot list original scenario dir: {exc}")
    if rev_cap != rev_m1:
        try:
            rev_top = {p.name for p in rev_m1.iterdir()}
            if rev_top != {"capture"}:
                errors.append(f"M1: unexpected top-level entries in relocated review dir: {sorted(rev_top)}")
        except OSError as exc:
            errors.append(f"M1: cannot list relocated review dir: {exc}")
    return errors


def _inspect_m1_scan_only(
    m1_dir: Path,
    *,
    trusted_original_scenario_dir: Path | None = None,
    trusted_original_capture_dir: Path | None = None,
) -> dict[str, Any]:
    raw_m1 = Path(m1_dir)
    errors: list[str] = []
    blockers: list[str] = []
    if not _is_safe_dir(raw_m1):
        if _is_missing_clean_path(raw_m1):
            return {"present": False, "blockers": [f"missing M1 scan-only directory: {raw_m1}"], "errors": []}
        return {
            "present": True,
            "blockers": [],
            "errors": [f"M1 directory is unsafe or traverses a symlink/junction: {raw_m1}"],
        }

    m1_dir = raw_m1.resolve()
    cap_dir = m1_dir if os.path.lexists(m1_dir / "scan-manifest.json") else (m1_dir / "capture")
    if os.path.lexists(cap_dir) and is_reparse_link(cap_dir):
        return {"present": True, "blockers": [], "errors": [f"M1 capture directory is a symlink/junction: {cap_dir}"]}
    if not os.path.lexists(cap_dir / "scan-manifest.json"):
        return {"present": True, "blockers": [f"missing scan-manifest.json in {m1_dir}"], "errors": []}

    for forbidden_rel in ("triage", "g1-run-manifest.json", "llm_io", "assessments.jsonl", "review.sqlite"):
        if os.path.lexists(m1_dir / forbidden_rel):
            errors.append(f"M1 --scan-only unexpectedly produced {forbidden_rel}")

    errors.extend(
        _verify_relocated_m1_provenance(
            review_m1_dir=m1_dir,
            review_cap_dir=cap_dir,
            trusted_original_scenario_dir=trusted_original_scenario_dir,
            trusted_original_capture_dir=trusted_original_capture_dir,
        )
    )

    cap_errors, _ = _verify_capture_dir_integrity(
        "M1",
        cap_dir,
        expected_cli_mode="scan-only",
        expect_live_source_current=True,
        trusted_original_capture_dir=trusted_original_capture_dir,
    )
    errors.extend(cap_errors)

    j_path = cap_dir / "opengrep.json"
    s_path = cap_dir / "opengrep.sarif"
    parity = None
    if _is_safe_regular_file(j_path) and _is_safe_regular_file(s_path):
        try:
            j_doc = contracts.strict(j_path.read_bytes().decode("utf-8"))
            s_doc = contracts.strict(s_path.read_bytes().decode("utf-8"))
            parity = contracts.compare_sarif(j_doc, s_doc)
        except (OSError, UnicodeError, ValueError, KeyError, TypeError) as exc:
            parity = None
            errors.append(f"M1 multiset JSON/SARIF parity failed: {exc}")
    else:
        errors.append("M1 missing or unsafe opengrep.json / opengrep.sarif for parity")

    return {
        "present": True,
        "capture_dir": str(cap_dir),
        "parity": parity,
        "blockers": blockers,
        "errors": errors,
    }


def _inspect_demo3b_mock_control(
    demo3b_dir: Path | None,
    *,
    trusted_original_scenario_dir: Path | None = None,
    trusted_original_capture_dir: Path | None = None,
) -> dict[str, Any]:
    if demo3b_dir is None:
        return {"present": False, "excluded_from_real_denominator": True, "errors": []}
    raw_d3b = Path(demo3b_dir)
    if not _is_safe_dir(raw_d3b):
        return {
            "present": not _is_missing_clean_path(raw_d3b),
            "excluded_from_real_denominator": True,
            "errors": [f"missing or unsafe demo3b dir: {raw_d3b}"],
        }

    demo3b_dir = raw_d3b.resolve()
    errors: list[str] = []
    capture_dir = demo3b_dir / "capture"
    triage_dir = demo3b_dir / "triage"
    manifest_path = demo3b_dir / "g1-run-manifest.json"
    if not _is_safe_dir(capture_dir) or not _is_safe_dir(triage_dir) or not _is_safe_regular_file(manifest_path):
        errors.append(f"Demo3b missing or unsafe capture/, triage/, or g1-run-manifest.json in {demo3b_dir}")
        return {
            "present": True,
            "evidence_kind": "SYNTHETIC_MOCK_HTTP",
            "excluded_from_real_denominator": True,
            "http_capture_status": None,
            "errors": errors,
        }

    d3b_manifest: dict[str, Any] | None = None
    try:
        parsed_d3b = strict_json(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(parsed_d3b, dict) or parsed_d3b.get("schema") != "ntk-g1-run-manifest-1":
            errors.append(
                f"Demo3b invalid g1-run-manifest schema: {parsed_d3b.get('schema') if isinstance(parsed_d3b, dict) else None!r}"
            )
        else:
            d3b_manifest = parsed_d3b
    except (OSError, UnicodeError, EvidenceError) as exc:
        errors.append(f"Demo3b invalid g1-run-manifest.json: {exc}")

    http_check = verify_run_http_captures(triage_dir, require_live_chat=False, minimum_findings=1)
    if not http_check["capture_integrity_ok"]:
        errors.append(f"Demo3b mock HTTP raw capture check failed: {http_check['errors']}")

    cap_errors, d3b_s_man = _verify_capture_dir_integrity(
        "Demo3b",
        capture_dir,
        expected_cli_mode="local-triage",
        expect_live_source_current=True,
        trusted_original_capture_dir=trusted_original_capture_dir,
    )
    errors.extend(cap_errors)

    d3b_scen_cap_errs, d3b_scen_triage_errs, _ = _verify_relocated_scenario_provenance(
        "Demo3b",
        review_scenario_dir=demo3b_dir,
        review_capture_dir=capture_dir,
        trusted_original_scenario_dir=trusted_original_scenario_dir,
        trusted_original_capture_dir=trusted_original_capture_dir,
        expect_llm=True,
        expect_live_source_current=True,
        require_after_confirm_false=False,
    )
    errors.extend(d3b_scen_cap_errs)
    errors.extend(d3b_scen_triage_errs)

    d3b_artifacts = d3b_manifest.get("artifacts") if isinstance(d3b_manifest, dict) else None
    for akey, apath in (
        ("opengrep_json", capture_dir / "opengrep.json"),
        ("opengrep_sarif", capture_dir / "opengrep.sarif"),
        ("scan_manifest", capture_dir / "scan-manifest.json"),
        ("cli_origin", capture_dir / "cli-origin.json"),
        ("evidence_json", triage_dir / "evidence.json"),
        ("assessments_jsonl", triage_dir / "assessments.jsonl"),
        ("http_capture_check", triage_dir / "http-capture-check.json"),
    ):
        _, art_errs = _verify_manifest_artifact_hash("Demo3b", d3b_artifacts, akey, apath)
        errors.extend(art_errs)

    ev_path = triage_dir / "evidence.json"
    assess_path = triage_dir / "assessments.jsonl"
    raw_json_path = capture_dir / "opengrep.json"
    raw_sarif_path = capture_dir / "opengrep.sarif"
    triage_input_path = triage_dir / "input.opengrep.json"

    evidence_bundle = None
    rows: list[dict[str, Any]] = []
    if not _is_safe_regular_file(ev_path) or not _is_safe_regular_file(assess_path):
        errors.append("Demo3b missing or unsafe evidence.json or assessments.jsonl")
    else:
        try:
            evidence_bundle = strict_json(ev_path.read_text(encoding="utf-8"))
            rows = [
                strict_json(line)
                for line in assess_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        except (OSError, UnicodeError, EvidenceError) as exc:
            errors.append(f"Demo3b invalid evidence.json or assessments.jsonl: {exc}")

    if evidence_bundle is not None and _is_safe_regular_file(raw_json_path) and _is_safe_regular_file(raw_sarif_path):
        raw_bytes = raw_json_path.read_bytes()
        if not _is_safe_regular_file(triage_input_path):
            errors.append("Demo3b missing or unsafe mandatory triage/input.opengrep.json")
        elif triage_input_path.read_bytes() != raw_bytes:
            errors.append("Demo3b triage/input.opengrep.json differs from capture/opengrep.json")
        try:
            raw_doc = contracts.strict(raw_bytes.decode("utf-8"))
            sarif_doc = contracts.strict(raw_sarif_path.read_bytes().decode("utf-8"))
            contracts.validate_bundle(raw_bytes, raw_doc, evidence_bundle)
            contracts.validate_rows(rows, evidence_bundle)
            contracts.compare_sarif(raw_doc, sarif_doc)
        except (OSError, ValueError, KeyError, TypeError, UnicodeError) as exc:
            errors.append(f"Demo3b contract/SARIF validation failed: {exc}")

    if len(rows) != 1:
        errors.append(f"Demo3b expected 1 finding, got {len(rows)}")
    else:
        a = rows[0]["assessment"]
        rt = a.get("runtime") or {}
        if rt.get("origin") != "mock":
            errors.append(f"Demo3b must have runtime.origin='mock', got {rt.get('origin')!r}")
        if a.get("validated_status") != "UNDETERMINED" or a.get("failure_kind") != "MALFORMED_JSON":
            errors.append(
                f"Demo3b expected UNDETERMINED + MALFORMED_JSON, got {a.get('validated_status')!r} / {a.get('failure_kind')!r}"
            )

    if evidence_bundle is not None:
        for idx, rec in enumerate(evidence_bundle.get("records") or []):
            try:
                check_current(rec)
            except (StaleSourceError, EvidenceError, OSError, ValueError, RuntimeError) as exc:
                errors.append(f"Demo3b[{idx}] live source drift / integrity error: {exc}")

    db_state = None
    try:
        db_state = _read_sqlite_state_ro(triage_dir / "review.sqlite")
        if evidence_bundle is not None:
            errors.extend(
                _verify_sqlite_against_triage(
                    "Demo3b review.sqlite",
                    db_state,
                    evidence_bundle,
                    rows,
                    scan_manifest=d3b_s_man,
                    run_manifest=d3b_manifest,
                    require_zero_rejected=True,
                )
            )
        if [w["state"] for w in db_state["warnings"]] != ["OPEN"]:
            errors.append(f"Demo3b SQLite warning state must remain OPEN, got {[w['state'] for w in db_state['warnings']]}")
        if db_state["events"]:
            errors.append("Demo3b unexpectedly has SQLite events")
    except (OSError, sqlite3.Error, EvidenceError, ValueError, KeyError, TypeError) as exc:
        errors.append(f"Demo3b invalid review.sqlite: {exc}")

    d3b_pre = triage_dir / "review.post_ingestion.sqlite"
    d3b_expected_rev_sha, d3b_rev_errs = _verify_manifest_artifact_hash(
        "Demo3b",
        d3b_artifacts,
        "review_sqlite",
        d3b_pre,
        expected_basename="review.sqlite",
    )
    errors.extend(d3b_rev_errs)
    if not _is_safe_regular_file(d3b_pre):
        errors.append("Demo3b missing or unsafe mandatory review.post_ingestion.sqlite")
    else:
        try:
            d3b_pre_state = _read_sqlite_state_ro(d3b_pre)
            if evidence_bundle is not None:
                errors.extend(
                    _verify_sqlite_against_triage(
                        "Demo3b post_ingestion",
                        d3b_pre_state,
                        evidence_bundle,
                        rows,
                        scan_manifest=d3b_s_man,
                        run_manifest=d3b_manifest,
                        require_zero_rejected=True,
                    )
                )
            if [w["state"] for w in d3b_pre_state["warnings"]] != ["OPEN"] or d3b_pre_state["events"]:
                errors.append("Demo3b review.post_ingestion.sqlite must hold 1 OPEN warning and 0 events")
            if d3b_expected_rev_sha is None or d3b_pre_state["db_sha256"] != d3b_expected_rev_sha:
                errors.append("Demo3b review.post_ingestion.sqlite SHA-256 missing anchor or differs from manifest")
            if db_state is not None and db_state["db_sha256"] != d3b_pre_state["db_sha256"]:
                errors.append("Demo3b review.sqlite SHA-256 differs from review.post_ingestion.sqlite despite zero events")
        except (OSError, sqlite3.Error, EvidenceError, ValueError, KeyError, TypeError) as exc:
            errors.append(f"Demo3b invalid review.post_ingestion.sqlite: {exc}")

    return {
        "present": True,
        "evidence_kind": "SYNTHETIC_MOCK_HTTP",
        "excluded_from_real_denominator": True,
        "http_capture_status": http_check["capture_status"],
        "errors": errors,
    }


def _inspect_demo4_stale_control(
    demo4_dir: Path,
    *,
    trusted_original_scenario_dir: Path | None = None,
    trusted_original_capture_dir: Path | None = None,
) -> dict[str, Any]:
    raw_d4 = Path(demo4_dir)
    if not _is_safe_dir(raw_d4):
        if _is_missing_clean_path(raw_d4):
            return {"present": False, "blockers": [f"missing Demo4 stale-source directory: {raw_d4}"], "errors": []}
        return {
            "present": True,
            "excluded_from_real_denominator": True,
            "blockers": [],
            "errors": [f"Demo4 directory is unsafe or traverses a symlink/junction: {raw_d4}"],
        }

    demo4_dir = raw_d4.resolve()
    errors: list[str] = []
    capture_dir = demo4_dir / "capture"
    triage_dir = demo4_dir / "triage"
    manifest_path = demo4_dir / "g1-run-manifest.json"
    if not _is_safe_dir(capture_dir) or not _is_safe_dir(triage_dir) or not _is_safe_regular_file(manifest_path):
        errors.append(f"Demo4 missing or unsafe capture/, triage/, or g1-run-manifest.json in {demo4_dir}")
        return {
            "present": True,
            "evidence_kind": "REAL_OPENGREP_SCAN_AND_SQLITE_GUARD",
            "excluded_from_real_denominator": True,
            "db_sha256": None,
            "blockers": [],
            "errors": errors,
        }

    manifest: dict[str, Any] | None = None
    try:
        parsed_d4 = strict_json(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(parsed_d4, dict) or parsed_d4.get("schema") != "ntk-g1-run-manifest-1":
            errors.append(
                f"Demo4 invalid g1-run-manifest schema: {parsed_d4.get('schema') if isinstance(parsed_d4, dict) else None!r}"
            )
        else:
            manifest = parsed_d4
    except (OSError, UnicodeError, EvidenceError) as exc:
        errors.append(f"Demo4 invalid g1-run-manifest.json: {exc}")

    if not isinstance(manifest, dict) or manifest.get("ollama", {}).get("enabled") is not False:
        errors.append("Demo4 stale-source control must run with --no-llm (excluded from Qwen calls)")

    cap_errors, d4_s_man = _verify_capture_dir_integrity(
        "Demo4",
        capture_dir,
        expected_cli_mode="local-triage",
        expect_live_source_current=False,
        trusted_original_capture_dir=trusted_original_capture_dir,
    )
    errors.extend(cap_errors)

    d4_scen_cap_errs, d4_scen_triage_errs, _ = _verify_relocated_scenario_provenance(
        "Demo4",
        review_scenario_dir=demo4_dir,
        review_capture_dir=capture_dir,
        trusted_original_scenario_dir=trusted_original_scenario_dir,
        trusted_original_capture_dir=trusted_original_capture_dir,
        expect_llm=False,
        expect_live_source_current=False,
        require_after_confirm_false=False,
    )
    errors.extend(d4_scen_cap_errs)
    errors.extend(d4_scen_triage_errs)

    ev_path = triage_dir / "evidence.json"
    assess_path = triage_dir / "assessments.jsonl"
    raw_json_path = capture_dir / "opengrep.json"
    raw_sarif_path = capture_dir / "opengrep.sarif"
    triage_input_path = triage_dir / "input.opengrep.json"

    evidence_bundle = None
    rows: list[dict[str, Any]] = []
    if not _is_safe_regular_file(ev_path) or not _is_safe_regular_file(assess_path):
        errors.append("Demo4 missing or unsafe triage/evidence.json or triage/assessments.jsonl")
    else:
        try:
            evidence_bundle = strict_json(ev_path.read_text(encoding="utf-8"))
            rows = [
                strict_json(line)
                for line in assess_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        except (OSError, UnicodeError, EvidenceError) as exc:
            errors.append(f"Demo4 invalid evidence.json or assessments.jsonl: {exc}")

    if evidence_bundle is not None and _is_safe_regular_file(raw_json_path) and _is_safe_regular_file(raw_sarif_path):
        raw_bytes = raw_json_path.read_bytes()
        if not _is_safe_regular_file(triage_input_path):
            errors.append("Demo4 missing or unsafe mandatory triage/input.opengrep.json")
        elif triage_input_path.read_bytes() != raw_bytes:
            errors.append("Demo4 triage/input.opengrep.json differs from capture/opengrep.json")
        try:
            raw_doc = contracts.strict(raw_bytes.decode("utf-8"))
            sarif_doc = contracts.strict(raw_sarif_path.read_bytes().decode("utf-8"))
            contracts.validate_bundle(raw_bytes, raw_doc, evidence_bundle)
            contracts.validate_rows(rows, evidence_bundle)
            contracts.compare_sarif(raw_doc, sarif_doc)
        except (OSError, ValueError, KeyError, TypeError, UnicodeError) as exc:
            errors.append(f"Demo4 contract/SARIF validation failed: {exc}")

    artifacts_meta = manifest.get("artifacts") if isinstance(manifest, dict) else None
    for akey, apath in (
        ("opengrep_json", capture_dir / "opengrep.json"),
        ("opengrep_sarif", capture_dir / "opengrep.sarif"),
        ("scan_manifest", capture_dir / "scan-manifest.json"),
        ("cli_origin", capture_dir / "cli-origin.json"),
        ("evidence_json", triage_dir / "evidence.json"),
        ("assessments_jsonl", triage_dir / "assessments.jsonl"),
    ):
        _, art_errs = _verify_manifest_artifact_hash("Demo4", artifacts_meta, akey, apath)
        errors.extend(art_errs)
    http_art = artifacts_meta.get("http_capture_check") if isinstance(artifacts_meta, dict) else None
    if not isinstance(http_art, dict) or http_art.get("sha256") is not None:
        errors.append("Demo4 --no-llm artifacts.http_capture_check must exist with sha256=null")
    if os.path.lexists(triage_dir / "http-capture-check.json"):
        errors.append("Demo4 --no-llm unexpectedly contains triage/http-capture-check.json")

    pre_db = triage_dir / "review.post_ingestion.sqlite"
    d4_expected_rev_sha, d4_rev_errs = _verify_manifest_artifact_hash(
        "Demo4",
        artifacts_meta,
        "review_sqlite",
        pre_db,
        expected_basename="review.sqlite",
    )
    errors.extend(d4_rev_errs)

    ing_state = None
    if not _is_safe_regular_file(pre_db):
        errors.append("Demo4 missing or unsafe mandatory review.post_ingestion.sqlite")
    else:
        try:
            ing_state = _read_sqlite_state_ro(pre_db)
            if evidence_bundle is not None:
                errors.extend(
                    _verify_sqlite_against_triage(
                        "Demo4 post_ingestion",
                        ing_state,
                        evidence_bundle,
                        rows,
                        scan_manifest=d4_s_man,
                        run_manifest=manifest,
                        require_zero_rejected=True,
                    )
                )
            if [w["state"] for w in ing_state["warnings"]] != ["OPEN"] or ing_state["events"]:
                errors.append("Demo4 review.post_ingestion.sqlite must hold 1 OPEN warning and 0 events")
            if d4_expected_rev_sha is None or ing_state["db_sha256"] != d4_expected_rev_sha:
                errors.append(
                    "Demo4 review.post_ingestion.sqlite SHA-256 missing mandatory anchor or differs from manifest artifacts.review_sqlite.sha256"
                )
        except (OSError, sqlite3.Error, EvidenceError, ValueError, KeyError, TypeError) as exc:
            errors.append(f"Demo4 invalid review.post_ingestion.sqlite: {exc}")

    db_sha = None
    try:
        db_state = _read_sqlite_state_ro(triage_dir / "review.sqlite")
        db_sha = db_state["db_sha256"]
        if evidence_bundle is not None:
            errors.extend(
                _verify_sqlite_against_triage(
                    "Demo4 review.sqlite",
                    db_state,
                    evidence_bundle,
                    rows,
                    scan_manifest=d4_s_man,
                    run_manifest=manifest,
                    require_zero_rejected=False,
                )
            )
        if ing_state is not None and db_state["db_sha256"] == ing_state["db_sha256"]:
            errors.append("Demo4 review.sqlite SHA-256 equals review.post_ingestion.sqlite despite recorded rejected decision")
        if len(db_state["warnings"]) != 1 or db_state["warnings"][0]["state"] != "OPEN":
            errors.append(f"Demo4 warning must remain OPEN, got {[w['state'] for w in db_state['warnings']]}")
        if len(db_state["events"]) != 0:
            errors.append(f"Demo4 must have 0 accepted events, got {len(db_state['events'])}")
        if len(db_state["rejected_decisions"]) != 1:
            errors.append(f"Demo4 must have 1 rejected_decisions row, got {len(db_state['rejected_decisions'])}")
        else:
            rej = db_state["rejected_decisions"][0]
            if rej.get("sequence") != 1:
                errors.append(f"Demo4 rejected_decisions sequence={rej.get('sequence')!r} != 1")
            try:
                contracts.timestamp(rej.get("timestamp"))
            except (ValueError, TypeError) as exc:
                errors.append(f"Demo4 rejected_decisions invalid timestamp: {exc}")
            if rej.get("attempted_action") != "confirm-false" or rej.get("rejection_code") != "STALE_SOURCE":
                errors.append(f"Demo4 unexpected rejection record: {rej}")
            actor = rej.get("actor")
            reason = rej.get("reason")
            if not isinstance(actor, str) or not actor.strip() or actor != actor.strip():
                errors.append(f"Demo4 rejection record invalid actor: {actor!r}")
            if not isinstance(reason, str) or not reason.strip() or reason != reason.strip():
                errors.append("Demo4 rejection record invalid reason")

            records = (evidence_bundle or {}).get("records") or []
            if len(records) == 1:
                rec = records[0]
                if rej.get("warning_id") != rec["id"]:
                    errors.append(f"Demo4 rejected warning_id {rej.get('warning_id')!r} != {rec['id']!r}")
                expected_snapshots = rec.get("snapshots") or {}
                expected_hashes = {
                    p: snap.get("sha256")
                    for p, snap in expected_snapshots.items()
                    if isinstance(snap, dict)
                }
                try:
                    sv_doc = strict_json(rej.get("source_version"))
                    ov_doc = strict_json(rej.get("observed_version"))
                    det_doc = strict_json(rej.get("detail"))
                except (EvidenceError, TypeError) as exc:
                    sv_doc = ov_doc = det_doc = None
                    errors.append(f"Demo4 invalid JSON in rejected_decisions: {exc}")
                if sv_doc is not None:
                    if sv_doc != expected_snapshots or rej.get("source_version") != _encode_canonical(expected_snapshots):
                        errors.append("Demo4 rejected source_version does not match finding snapshots")
                    if not isinstance(ov_doc, dict) or set(ov_doc) != set(expected_hashes):
                        errors.append("Demo4 rejected observed_version keys do not match finding snapshots")
                    elif ov_doc == expected_hashes:
                        errors.append("Demo4 rejected observed_version equals source snapshot hashes")
                    elif rej.get("observed_version") != _encode_canonical(ov_doc):
                        errors.append("Demo4 rejected observed_version is not canonical JSON")
                    else:
                        live_stale_err = None
                        try:
                            check_current(rec)
                        except StaleSourceError as stale_exc:
                            live_stale_err = stale_exc
                        except (EvidenceError, OSError, ValueError, RuntimeError) as exc:
                            errors.append(f"Demo4 live source state check failed: {exc}")
                        if live_stale_err is None:
                            errors.append("Demo4 mutable source copy on disk did not actually diverge from scan snapshot")
                        elif ov_doc != live_stale_err.observed_hashes:
                            errors.append(
                                f"Demo4 rejected observed_version {ov_doc!r} disagrees with live mutated source hashes {live_stale_err.observed_hashes!r}"
                            )
                        if not isinstance(det_doc, dict):
                            errors.append("Demo4 rejected detail must be JSON object")
                        else:
                            expected_mismatched = {p for p in expected_hashes if ov_doc.get(p) != expected_hashes[p]}
                            if det_doc.get("error_code") != "STALE_SOURCE":
                                errors.append(f"Demo4 rejected detail error_code={det_doc.get('error_code')!r} != 'STALE_SOURCE'")
                            if det_doc.get("expected_hashes") != expected_hashes:
                                errors.append("Demo4 rejected detail.expected_hashes mismatch")
                            if det_doc.get("observed_hashes") != ov_doc:
                                errors.append("Demo4 rejected detail.observed_hashes mismatch")
                            if set(det_doc.get("mismatched_paths") or []) != expected_mismatched:
                                errors.append("Demo4 rejected detail.mismatched_paths mismatch")
    except (OSError, sqlite3.Error, EvidenceError, ValueError, KeyError, TypeError) as exc:
        errors.append(f"Demo4 invalid review.sqlite: {exc}")

    return {
        "present": True,
        "evidence_kind": "REAL_OPENGREP_SCAN_AND_SQLITE_GUARD",
        "excluded_from_real_denominator": True,
        "db_sha256": db_sha,
        "blockers": [],
        "errors": errors,
    }


_EXACT_CWE89_RE = re.compile(r"^CWE-89(?::\s*\S[^\r\n]*)?\Z")


def _is_exact_cwe89_identifier(value: Any) -> bool:
    """Return True iff value is exact 'CWE-89' or 'CWE-89: <description>' without other CWE IDs."""
    if not isinstance(value, str) or _EXACT_CWE89_RE.match(value) is None:
        return False
    if value.startswith("CWE-89:") and re.search(r"\bCWE-\d+\b", value[len("CWE-89:"):], re.IGNORECASE):
        return False
    return True


def _extract_allowlisted_path_mappings(ev: dict[str, Any], rec: dict[str, Any]) -> list[Any]:
    """Extract and structurally validate path_mappings from evidence bundle / record without synthesizing guesses."""
    has_rec_maps = "path_mappings" in rec
    has_ev_maps = "path_mappings" in ev
    if has_rec_maps and has_ev_maps and rec.get("path_mappings") != ev.get("path_mappings"):
        raise EvidenceError("record path_mappings disagrees with evidence bundle path_mappings")
    raw_maps = rec.get("path_mappings") if has_rec_maps else ev.get("path_mappings")
    if raw_maps is None:
        return []
    if not isinstance(raw_maps, list):
        raise EvidenceError(f"path_mappings must be a JSON array, got {type(raw_maps).__name__}")
    for entry in raw_maps:
        if isinstance(entry, dict):
            if set(entry) != {"from", "to"} or not isinstance(entry["from"], str) or not isinstance(entry["to"], str):
                raise EvidenceError("path_mappings entries must be {from, to} string objects")
        elif isinstance(entry, str):
            if "=" not in entry:
                raise EvidenceError("string path_mappings entry must be FROM=TO")
        else:
            raise EvidenceError(f"unsupported path_mappings entry type {type(entry).__name__}")
    return list(raw_maps)


def _verify_allowlisted_fp_scenario_identity(
    scenario_dir: Path, *, trusted_source_root: Path | None = None,
) -> list[str]:
    """Verify AllowlistedQuery against an operator-pinned root, never an evidence-declared root alone."""
    approved_fixture = Path(__file__).resolve().parent / "demo_fixtures" / "AllowlistedQuery.java"
    if not _is_safe_regular_file(approved_fixture):
        return [f"allowlisted_query_fp_control: missing or unsafe approved repo fixture: {approved_fixture}"]
    expected_bytes = approved_fixture.read_bytes()
    expected_sha = digest(expected_bytes)
    expected_size = len(expected_bytes)

    # A root claimed by evidence.json or g1-run-manifest.json is NOT an authority.
    # The caller must pin the original scan root independently (CLI/operator input).
    if trusted_source_root is None:
        return ["allowlisted_query_fp_control: missing independent trusted_source_root; fail closed"]
    try:
        trusted_root_path = Path(trusted_source_root)
        if not _is_safe_dir(trusted_root_path):
            raise EvidenceError("trusted_source_root missing, unsafe or reparse-linked")
        pinned_root = trusted_root_path.resolve(strict=True)
    except (OSError, ValueError, RuntimeError, EvidenceError, TypeError) as exc:
        return [f"allowlisted_query_fp_control: invalid independent trusted_source_root: {exc}"]

    errors: list[str] = []
    scenario_resolved = Path(scenario_dir).resolve()
    ev_path = scenario_resolved / "triage" / "evidence.json"
    if not _is_safe_regular_file(ev_path):
        return [f"allowlisted_query_fp_control: missing or unsafe triage/evidence.json: {ev_path}"]
    try:
        ev = strict_json(ev_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, EvidenceError) as exc:
        return [f"allowlisted_query_fp_control: invalid triage/evidence.json: {exc}"]
    records = ev.get("records") if isinstance(ev, dict) else None
    if not isinstance(records, list) or len(records) != 1:
        return [f"allowlisted_query_fp_control: expected 1 evidence record, got {len(records) if isinstance(records, list) else None}"]
    rec = records[0]
    if not isinstance(rec, dict):
        return ["allowlisted_query_fp_control: evidence record[0] is not a JSON object"]

    raw_rec_path = rec.get("path")
    norm_rec_path = raw_rec_path.replace("\\", "/") if isinstance(raw_rec_path, str) else ""
    lexical_path_ok = (
        isinstance(raw_rec_path, str)
        and bool(raw_rec_path.strip())
        and raw_rec_path == raw_rec_path.strip()
        and "\x00" not in raw_rec_path
        and not any(ord(ch) < 32 for ch in raw_rec_path)
        and not raw_rec_path.lower().startswith("file:")
        and not norm_rec_path.startswith("//")
        and not (raw_rec_path.startswith("/") and "\\" in raw_rec_path)
        and not (":" in norm_rec_path and not re.match(r"^[A-Za-z]:/", norm_rec_path))
        and ".." not in PurePosixPath(norm_rec_path).parts
        and ".." not in Path(raw_rec_path).parts
        and PurePosixPath(norm_rec_path).name == "AllowlistedQuery.java"
    )
    if not lexical_path_ok:
        errors.append(
            f"allowlisted_query_fp_control: expected path naming exact 'AllowlistedQuery.java' without traversal, got {raw_rec_path!r}"
        )

    raw_root = rec.get("root")
    is_posix_rec_path = isinstance(raw_rec_path, str) and norm_rec_path.startswith("/")
    try:
        validated_maps = _extract_allowlisted_path_mappings(ev, rec)
    except EvidenceError as exc:
        validated_maps = []
        errors.append(f"allowlisted_query_fp_control: invalid path_mappings: {exc}")

    expected_snap_key: str | None = None
    tree: SourceTree | None = None
    if not isinstance(raw_root, str) or not raw_root.strip() or "\x00" in raw_root:
        errors.append(f"allowlisted_query_fp_control: missing or invalid declared source root {raw_root!r}")
    elif not _is_safe_dir(Path(raw_root)):
        errors.append(f"allowlisted_query_fp_control: declared source root is missing or unsafe/reparse-linked: {raw_root!r}")
    elif Path(raw_root).resolve(strict=True) != pinned_root:
        errors.append(
            "allowlisted_query_fp_control: declared source root disagrees with independently pinned "
            f"trusted_source_root (declared={raw_root!r}, pinned={str(pinned_root)!r})"
        )
    elif lexical_path_ok:
        try:
            if is_posix_rec_path and os.name == "nt":
                if not validated_maps:
                    raise EvidenceError("POSIX/WSL source path requires explicit path_mappings")
                # JSON maps (including manifest copies) are evidence, not an authority.
                # Re-derive the Windows/WSL2 mount mapping from the on-disk root,
                # with no caller-supplied extra path maps, then require exact equality.
                from v2.g1_integration.bridge import derive_trusted_path_maps

                os_derived_maps = derive_trusted_path_maps(pinned_root)
                if not os_derived_maps:
                    raise EvidenceError("cannot independently derive a WSL mapping from this host source root")
                canonical_tree = SourceTree(pinned_root, path_maps=os_derived_maps)
                evidence_tree = SourceTree(pinned_root, path_maps=validated_maps)
                if evidence_tree.path_maps != canonical_tree.path_maps:
                    raise EvidenceError("untrusted path_mappings: do not match OS-derived source-root mapping")
                tree = canonical_tree
            elif os.name != "nt" and validated_maps:
                # On Linux/POSIX there is no independent OS drive-mount mapping authority
                # (derive_trusted_path_maps returns []); fail closed on any non-empty
                # evidence/manifest path_mappings instead of trusting self-declared maps.
                raise EvidenceError("untrusted path_mappings: POSIX/Linux host has no independent mapping authority")
            else:
                tree = SourceTree(pinned_root)
            resolved_source = tree.resolve(raw_rec_path)
            if not _is_safe_regular_file(resolved_source):
                raise EvidenceError(f"resolved source traverses unsafe symlink/junction: {resolved_source}")
            rel_key, disk_bytes, _ = tree.read(raw_rec_path)
            if digest(disk_bytes) != expected_sha or len(disk_bytes) != expected_size:
                errors.append(
                    "allowlisted_query_fp_control: source drift or disk fixture mismatch "
                    f"(expected sha256={expected_sha} size={expected_size}, got sha256={digest(disk_bytes)} size={len(disk_bytes)})"
                )
            if (
                not rel_key.strip()
                or rel_key.startswith("/")
                or (len(rel_key) >= 2 and rel_key[1] == ":")
                or ".." in PurePosixPath(rel_key).parts
                or PurePosixPath(rel_key).name != "AllowlistedQuery.java"
            ):
                errors.append(
                    f"allowlisted_query_fp_control: invalid relative snapshot key {rel_key!r} (expected 'AllowlistedQuery.java' relative path)"
                )
            else:
                expected_snap_key = rel_key
        except (EvidenceError, OSError, UnicodeError, ValueError, RuntimeError) as exc:
            errors.append(f"allowlisted_query_fp_control: source root/mapping verification failed for {norm_rec_path!r}: {exc}")

    manifest_path = scenario_resolved / "g1-run-manifest.json"
    if os.path.lexists(manifest_path):
        if not _is_safe_regular_file(manifest_path):
            errors.append("allowlisted_query_fp_control: unsafe g1-run-manifest.json")
        else:
            try:
                run_manifest = strict_json(manifest_path.read_text(encoding="utf-8"))
                if isinstance(run_manifest, dict):
                    man_root = run_manifest.get("source_root")
                    if isinstance(man_root, str) and man_root.strip() and isinstance(raw_root, str) and raw_root.strip():
                        if _is_safe_dir(Path(man_root)) and _is_safe_dir(Path(raw_root)):
                            if Path(man_root).resolve() != pinned_root:
                                errors.append(
                                    "allowlisted_query_fp_control: g1-run-manifest source_root "
                                    f"{man_root!r} disagrees with independently pinned trusted_source_root {str(pinned_root)!r}"
                                )
                        else:
                            errors.append(
                                f"allowlisted_query_fp_control: g1-run-manifest source_root {man_root!r} missing or unsafe"
                            )
                    if is_posix_rec_path and tree is not None and "trusted_path_maps" in run_manifest:
                        man_maps = run_manifest.get("trusted_path_maps")
                        if not isinstance(man_maps, list):
                            errors.append("allowlisted_query_fp_control: g1-run-manifest trusted_path_maps must be a list")
                        else:
                            man_tree = SourceTree(pinned_root, path_maps=man_maps)
                            if man_tree.path_maps != tree.path_maps:
                                errors.append(
                                    "allowlisted_query_fp_control: evidence path_mappings disagrees with g1-run-manifest trusted_path_maps"
                                )
            except (OSError, UnicodeError, EvidenceError, ValueError, RuntimeError) as exc:
                errors.append(f"allowlisted_query_fp_control: invalid g1-run-manifest root/path_mappings check: {exc}")

    rule_id = str(rec.get("rule_id") or "")
    if not rule_id.endswith("ntk.g1.java.cwe89.sql-injection"):
        errors.append(
            f"allowlisted_query_fp_control: expected rule_id ending with 'ntk.g1.java.cwe89.sql-injection', got {rule_id!r}"
        )

    raw_cwe = rec.get("cwe")
    if (
        not isinstance(raw_cwe, list)
        or not raw_cwe
        or not all(isinstance(c, str) and c == c.strip() and _is_exact_cwe89_identifier(c) for c in raw_cwe)
    ):
        errors.append(f"allowlisted_query_fp_control: expected exact CWE-89 finding, got cwe={raw_cwe!r}")

    snapshots = rec.get("snapshots")
    if not isinstance(snapshots, dict) or not snapshots:
        errors.append("allowlisted_query_fp_control: missing verified snapshots map bound to AllowlistedQuery.java")
    else:
        if len(snapshots) != 1:
            errors.append(
                f"allowlisted_query_fp_control: expected single-file snapshot map for AllowlistedQuery.java, got {sorted(snapshots)!r}"
            )
        if expected_snap_key is None:
            errors.append(
                "allowlisted_query_fp_control: cannot bind snapshots to unverified target path "
                f"(present={sorted(snapshots)!r})"
            )
        else:
            snap = snapshots.get(expected_snap_key)
            if not isinstance(snap, dict):
                errors.append(
                    f"allowlisted_query_fp_control: snapshots missing exact target entry {expected_snap_key!r} "
                    f"(present={sorted(snapshots)!r})"
                )
            else:
                if snap.get("sha256") != expected_sha or snap.get("size") != expected_size:
                    errors.append(
                        "allowlisted_query_fp_control: snapshot hash/size mismatch against approved repo AllowlistedQuery.java "
                        f"(expected sha256={expected_sha} size={expected_size}, got sha256={snap.get('sha256')!r} size={snap.get('size')!r})"
                    )

    snippets = rec.get("snippets")
    if not isinstance(snippets, list) or not snippets:
        errors.append("allowlisted_query_fp_control: missing snippet evidence for AllowlistedQuery")
        return errors

    ordered_lines: dict[int, str] = {}
    for snip in snippets:
        if not isinstance(snip, dict):
            continue
        snip_path = str(snip.get("path") or "").replace("\\", "/")
        if (
            (expected_snap_key is not None and snip_path != expected_snap_key)
            or PurePosixPath(snip_path).name != "AllowlistedQuery.java"
            or snip.get("sha256") != expected_sha
        ):
            errors.append(
                f"allowlisted_query_fp_control: snippet path/sha256 mismatch (path={snip_path!r}, expected_key={expected_snap_key!r}, sha256={snip.get('sha256')!r})"
            )
        for ln in (snip.get("lines") or []):
            if not isinstance(ln, dict):
                continue
            ln_no = ln.get("line")
            if isinstance(ln_no, int):
                ordered_lines[ln_no] = str(ln.get("text") or "").strip()

    sorted_items = sorted(ordered_lines.items())
    source_lines = [ln for ln, txt in sorted_items if txt == 'String query = req.getParameter("q");']
    guard_lines = [ln for ln, txt in sorted_items if txt == 'if (!"SELECT 1".equals(query)) {']
    sink_lines = [ln for ln, txt in sorted_items if txt == "stmt.executeQuery(query);"]
    matched_guard_block = False
    if source_lines and guard_lines and sink_lines:
        src_ln = source_lines[0]
        for g_ln in guard_lines:
            if (
                g_ln > src_ln
                and ordered_lines.get(g_ln + 1) == 'throw new IllegalArgumentException("Only SELECT 1 is allowed");'
                and ordered_lines.get(g_ln + 2) == "}"
                and any(s_ln > g_ln + 2 for s_ln in sink_lines)
            ):
                s_ln = next(s for s in sink_lines if s > g_ln + 2)
                between = [txt for ln, txt in sorted_items if g_ln + 2 < ln < s_ln]
                if not any(re.search(r"\bquery\s*=", b) for b in between):
                    matched_guard_block = True
                    break
    if not matched_guard_block:
        errors.append(
            "allowlisted_query_fp_control: snippet evidence missing ordered throwing exact-literal guard "
            '(!SELECT-1.equals(query) -> throw IllegalArgumentException -> } -> stmt.executeQuery(query)) without bypass'
        )
    return errors


def _validate_capture_relocation_args(
    *,
    capture_relocation_mode: str,
    r03_fp_mode: str,
    demo3b_dir: Path | None,
    scenario_roots: dict[str, Path | None],
    capture_roots: dict[str, Path | None],
) -> tuple[dict[str, Path], dict[str, Path]]:
    if capture_relocation_mode not in ("strict-in-place", "pinned-original-capture"):
        raise ValueError(f"unsupported capture_relocation_mode={capture_relocation_mode!r}")
    provided_scenarios = {key: val for key, val in scenario_roots.items() if val is not None}
    provided_captures = {key: val for key, val in capture_roots.items() if val is not None}
    if capture_relocation_mode == "strict-in-place" and (provided_scenarios or provided_captures):
        raise ValueError(
            "trusted scenario/capture root arguments require capture_relocation_mode='pinned-original-capture'"
        )
    if capture_relocation_mode == "pinned-original-capture":
        if not provided_scenarios and not provided_captures:
            raise ValueError(
                "operator-pinned trusted scenario and capture roots are required in capture_relocation_mode='pinned-original-capture'"
            )
        all_keys = sorted(set(scenario_roots) | set(capture_roots))
        for key in all_keys:
            has_scen = key in provided_scenarios
            has_cap = key in provided_captures
            if has_scen != has_cap:
                raise ValueError(
                    f"relocated scenario {key!r} requires BOTH {key}_trusted_scenario_root and {key}_trusted_capture_root"
                )
    if r03_fp_mode == "locked-demo2" and (
        scenario_roots.get("allowlisted") is not None or capture_roots.get("allowlisted") is not None
    ):
        raise ValueError(
            "allowlisted_trusted_scenario_root and allowlisted_trusted_capture_root are only valid in proposed-allowlisted-fp mode"
        )
    if demo3b_dir is None and (
        scenario_roots.get("demo3b") is not None or capture_roots.get("demo3b") is not None
    ):
        raise ValueError("demo3b_trusted_scenario_root and demo3b_trusted_capture_root require demo3b_dir")
    return provided_scenarios, provided_captures


def evaluate_acceptance(
    *,
    demo1_dir: Path,
    demo2_dir: Path,
    demo3a_dir: Path,
    m1_dir: Path,
    demo4_dir: Path,
    demo3b_dir: Path | None = None,
    allowlisted_fp_dir: Path | None = None,
    allowlisted_trusted_source_root: Path | None = None,
    r03_fp_mode: str = "locked-demo2",
    capture_relocation_mode: str = "strict-in-place",
    demo1_trusted_scenario_root: Path | None = None,
    demo2_trusted_scenario_root: Path | None = None,
    demo3a_trusted_scenario_root: Path | None = None,
    m1_trusted_scenario_root: Path | None = None,
    demo4_trusted_scenario_root: Path | None = None,
    demo3b_trusted_scenario_root: Path | None = None,
    allowlisted_trusted_scenario_root: Path | None = None,
    demo1_trusted_capture_root: Path | None = None,
    demo2_trusted_capture_root: Path | None = None,
    demo3a_trusted_capture_root: Path | None = None,
    m1_trusted_capture_root: Path | None = None,
    demo4_trusted_capture_root: Path | None = None,
    demo3b_trusted_capture_root: Path | None = None,
    allowlisted_trusted_capture_root: Path | None = None,
    allow_mock_primary: bool = False,
) -> dict[str, Any]:
    if r03_fp_mode not in ("locked-demo2", "proposed-allowlisted-fp"):
        raise ValueError(f"unsupported r03_fp_mode={r03_fp_mode!r}")
    if r03_fp_mode == "locked-demo2" and allowlisted_fp_dir is not None:
        raise ValueError("allowlisted_fp_dir requires r03_fp_mode='proposed-allowlisted-fp'")
    if r03_fp_mode == "proposed-allowlisted-fp" and allowlisted_fp_dir is None:
        raise ValueError("allowlisted_fp_dir is required when r03_fp_mode='proposed-allowlisted-fp'")
    if r03_fp_mode == "locked-demo2" and allowlisted_trusted_source_root is not None:
        raise ValueError("allowlisted_trusted_source_root is only valid in proposed-allowlisted-fp mode")
    if r03_fp_mode == "proposed-allowlisted-fp" and allowlisted_trusted_source_root is None:
        raise ValueError("operator-pinned allowlisted_trusted_source_root is required in proposed-allowlisted-fp mode")

    scenario_roots_map: dict[str, Path | None] = {
        "demo1": demo1_trusted_scenario_root,
        "demo2": demo2_trusted_scenario_root,
        "demo3a": demo3a_trusted_scenario_root,
        "m1": m1_trusted_scenario_root,
        "demo4": demo4_trusted_scenario_root,
        "demo3b": demo3b_trusted_scenario_root,
        "allowlisted": allowlisted_trusted_scenario_root,
    }
    capture_roots_map: dict[str, Path | None] = {
        "demo1": demo1_trusted_capture_root,
        "demo2": demo2_trusted_capture_root,
        "demo3a": demo3a_trusted_capture_root,
        "m1": m1_trusted_capture_root,
        "demo4": demo4_trusted_capture_root,
        "demo3b": demo3b_trusted_capture_root,
        "allowlisted": allowlisted_trusted_capture_root,
    }
    provided_scenario_roots, provided_capture_roots = _validate_capture_relocation_args(
        capture_relocation_mode=capture_relocation_mode,
        r03_fp_mode=r03_fp_mode,
        demo3b_dir=demo3b_dir,
        scenario_roots=scenario_roots_map,
        capture_roots=capture_roots_map,
    )

    use_proposed_fp = r03_fp_mode == "proposed-allowlisted-fp"

    d1 = _inspect_primary_scenario(
        "demo1_true_positive",
        demo1_dir,
        expected_findings=2,
        expected_polarity="SUPPORTED",
        allow_mock_primary=allow_mock_primary,
        trusted_original_scenario_dir=demo1_trusted_scenario_root,
        trusted_original_capture_dir=demo1_trusted_capture_root,
    )
    d2 = _inspect_primary_scenario(
        "demo2_protected_false_positive",
        demo2_dir,
        expected_findings=1,
        expected_polarity="REFUTED",
        allow_mock_primary=allow_mock_primary,
        require_after_confirm_false=not use_proposed_fp,
        trusted_original_scenario_dir=demo2_trusted_scenario_root,
        trusted_original_capture_dir=demo2_trusted_capture_root,
    )
    d_fp: dict[str, Any] | None = None
    id_errs: list[str] = []
    if use_proposed_fp:
        assert allowlisted_fp_dir is not None
        d_fp = _inspect_primary_scenario(
            "allowlisted_query_fp_control",
            allowlisted_fp_dir,
            expected_findings=1,
            expected_polarity="OBSERVED_VALID_TRIAGE",
            allow_mock_primary=allow_mock_primary,
            require_after_confirm_false=True,
            trusted_original_scenario_dir=allowlisted_trusted_scenario_root,
            trusted_original_capture_dir=allowlisted_trusted_capture_root,
        )
        id_errs = _verify_allowlisted_fp_scenario_identity(
            allowlisted_fp_dir, trusted_source_root=allowlisted_trusted_source_root,
        )
        if allowlisted_trusted_source_root is not None and _is_safe_dir(Path(allowlisted_trusted_source_root)):
            src_resolved = Path(allowlisted_trusted_source_root).resolve(strict=True)
            for label_check, cand_dir in (
                ("allowlisted_fp_dir", allowlisted_fp_dir),
                ("allowlisted_trusted_scenario_root", allowlisted_trusted_scenario_root),
                ("allowlisted_trusted_capture_root", allowlisted_trusted_capture_root),
            ):
                if cand_dir is not None and _is_safe_dir(Path(cand_dir)):
                    if _roots_overlap_or_nest(src_resolved, Path(cand_dir).resolve(strict=True)):
                        id_errs.append(
                            f"allowlisted_query_fp_control: allowlisted_trusted_source_root ({src_resolved}) "
                            f"cannot equal or nest with {label_check}"
                        )
        if allowlisted_trusted_scenario_root is not None and _is_safe_dir(Path(allowlisted_trusted_scenario_root)):
            id_errs.extend(
                _verify_allowlisted_fp_scenario_identity(
                    Path(allowlisted_trusted_scenario_root),
                    trusted_source_root=allowlisted_trusted_source_root,
                )
            )
        if id_errs:
            d_fp.setdefault("r03_errors", []).extend(id_errs)
    d3a = _inspect_primary_scenario(
        "demo3a_missing_helper",
        demo3a_dir,
        expected_findings=1,
        expected_polarity="UNDETERMINED_ABSTAIN",
        allow_mock_primary=allow_mock_primary,
        trusted_original_scenario_dir=demo3a_trusted_scenario_root,
        trusted_original_capture_dir=demo3a_trusted_capture_root,
    )
    m1 = _inspect_m1_scan_only(
        m1_dir,
        trusted_original_scenario_dir=m1_trusted_scenario_root,
        trusted_original_capture_dir=m1_trusted_capture_root,
    )
    d3b = _inspect_demo3b_mock_control(
        demo3b_dir,
        trusted_original_scenario_dir=demo3b_trusted_scenario_root,
        trusted_original_capture_dir=demo3b_trusted_capture_root,
    )
    d4 = _inspect_demo4_stale_control(
        demo4_dir,
        trusted_original_scenario_dir=demo4_trusted_scenario_root,
        trusted_original_capture_dir=demo4_trusted_capture_root,
    )

    # R01 decision: strictly evaluates the 4 historical G1-C5 inferences (Demo1=2, Demo2=1, Demo3a=1) + Demo3b control.
    # Supplementary R03 control runs never alter the historical R01 denominator or pass/fail outcome.
    historical_primary_items = [d1, d2, d3a]
    r01_failures = [
        *d1.get("failures", []),
        *d2.get("failures", []),
        *d3a.get("failures", []),
        *d3b.get("errors", []),
    ]
    r01_blockers = [e for item in historical_primary_items for e in item.get("blockers", [])]
    expected_real_total = 4
    real_findings_total = sum(x.get("findings_count", 0) for x in historical_primary_items)
    if real_findings_total != expected_real_total and not r01_blockers:
        r01_failures.append(
            f"R01 real-Qwen denominator must equal {expected_real_total}, observed {real_findings_total}"
        )
    r01_status = "FAIL" if r01_failures else ("BLOCKED" if r01_blockers else "PASS")

    # R02 decision (historical M1 + Demo1/Demo2/Demo3a pipeline parity)
    r02_failures = [
        *m1.get("errors", []),
        *[e for item in historical_primary_items for e in item.get("r02_errors", [])],
    ]
    r02_blockers = [*m1.get("blockers", []), *r01_blockers]
    r02_status = "FAIL" if r02_failures else ("BLOCKED" if r02_blockers else "PASS")

    # R03 decision (Demo1 confirm-true + FP control confirm-false -> reopen + Demo3a untouched OPEN + Demo4 STALE_SOURCE)
    r03_failures: list[str] = [
        *d4.get("errors", []),
        *[e for item in historical_primary_items for e in item.get("r03_errors", [])],
    ]
    r03_blockers: list[str] = [
        *d4.get("blockers", []),
        *r01_blockers,
    ]
    if d_fp is not None:
        r03_failures.extend(d_fp.get("failures", []))
        r03_failures.extend(d_fp.get("r02_errors", []))
        r03_failures.extend(d_fp.get("r03_errors", []))
        r03_blockers.extend(d_fp.get("blockers", []))

    d1_sql = d1.get("current_sqlite")
    if d1_sql is not None:
        if "CONFIRMED_TRUE" not in d1_sql["states"] or "OPEN" not in d1_sql["states"]:
            r03_failures.append(f"Demo1 expected one CONFIRMED_TRUE and one OPEN warning, got {d1_sql['states']}")
        d1_events = d1_sql["events"]
        if len(d1_events) != 1 or d1_events[0]["action"] != "confirm-true" or not str(d1_events[0].get("actor", "")).strip() or not str(d1_events[0].get("reason", "")).strip():
            r03_failures.append(f"Demo1 expected 1 confirm-true event with actor/reason, got {d1_events}")
        elif not allow_mock_primary:
            marker = _find_non_human_review_marker(d1_events[0].get("actor"), d1_events[0].get("reason"))
            if marker is not None:
                r03_failures.append(
                    f"Demo1 event carries non-human/scripted/mock/replay marker ({marker}); rejected under official human-review evaluation"
                )

    d2_sql = d2.get("current_sqlite")
    if d2_sql is not None:
        if use_proposed_fp:
            if d2_sql["states"] != ["OPEN"] or d2_sql["events"] or d2_sql["rejected_count"] != 0:
                r03_failures.append(
                    "Demo2 (retained for security-limit analysis under proposed-allowlisted-fp) must remain untouched OPEN "
                    f"with 0 events/rejections, got states={d2_sql['states']} events={d2_sql['events']} rejected={d2_sql['rejected_count']}"
                )
        else:
            if d2_sql["states"] != ["OPEN"]:
                r03_failures.append(f"Demo2 expected final state ['OPEN'] after reopen, got {d2_sql['states']}")
            d2_actions = [e["action"] for e in d2_sql["events"]]
            if d2_actions != ["confirm-false", "reopen"]:
                r03_failures.append(f"Demo2 expected events ['confirm-false', 'reopen'], got {d2_actions}")
            for ev in d2_sql["events"]:
                if not str(ev.get("actor", "")).strip() or not str(ev.get("reason", "")).strip():
                    r03_failures.append(f"Demo2 event missing actor or reason: {ev}")
                elif not allow_mock_primary:
                    marker = _find_non_human_review_marker(ev.get("actor"), ev.get("reason"))
                    if marker is not None:
                        r03_failures.append(
                            f"Demo2 event carries non-human/scripted/mock/replay marker ({marker}); rejected under official human-review evaluation"
                        )

    if d_fp is not None:
        d_fp_sql = d_fp.get("current_sqlite")
        if d_fp_sql is not None:
            if d_fp_sql["states"] != ["OPEN"]:
                r03_failures.append(
                    f"AllowlistedQuery expected final state ['OPEN'] after reopen, got {d_fp_sql['states']}"
                )
            d_fp_actions = [e["action"] for e in d_fp_sql["events"]]
            if d_fp_actions != ["confirm-false", "reopen"]:
                r03_failures.append(
                    f"AllowlistedQuery expected events ['confirm-false', 'reopen'], got {d_fp_actions}"
                )
            for ev in d_fp_sql["events"]:
                if not str(ev.get("actor", "")).strip() or not str(ev.get("reason", "")).strip():
                    r03_failures.append(f"AllowlistedQuery event missing actor or reason: {ev}")
                elif not allow_mock_primary:
                    marker = _find_non_human_review_marker(ev.get("actor"), ev.get("reason"))
                    if marker is not None:
                        r03_failures.append(
                            f"AllowlistedQuery event carries non-human/scripted/mock/replay marker ({marker}); rejected under official human-review evaluation"
                        )

    d3a_sql = d3a.get("current_sqlite")
    if d3a_sql is not None:
        if d3a_sql["states"] != ["OPEN"]:
            r03_failures.append(f"Demo3a expected warning state ['OPEN'], got {d3a_sql['states']}")
        if d3a_sql["events"]:
            r03_failures.append(f"Demo3a expected 0 SQLite events, got {d3a_sql['events']}")

    r03_status = "FAIL" if r03_failures else ("BLOCKED" if r03_blockers else "PASS")

    overall = (
        "FAIL"
        if "FAIL" in (r01_status, r02_status, r03_status)
        else ("BLOCKED" if "BLOCKED" in (r01_status, r02_status, r03_status) else "PASS")
    )

    breakdown: dict[str, int] = {
        "demo1_true_positive": d1.get("findings_count", 0),
        "demo2_protected_false_positive": d2.get("findings_count", 0),
        "demo3a_missing_helper": d3a.get("findings_count", 0),
    }
    excluded_aux = ["m1_scan_only", "demo3b_malformed_json_mock", "demo4_stale_source"]
    scenarios_out: dict[str, Any] = {
        "m1_scan_only": m1,
        "demo1_true_positive": d1,
        "demo2_protected_false_positive": d2,
    }
    supplementary_r03_control: dict[str, Any] | None = None
    if d_fp is not None:
        excluded_aux.append("allowlisted_query_fp_control")
        scenarios_out["allowlisted_query_fp_control"] = d_fp
        fp_findings = d_fp.get("findings") or []
        fp_f0 = fp_findings[0] if fp_findings and isinstance(fp_findings[0], dict) else {}
        fp_raw_status = fp_f0.get("raw_model_status")
        fp_val_status = fp_f0.get("validated_status")
        fp_integrity_ok = (
            d_fp.get("findings_count") == 1
            and not d_fp.get("failures")
            and not d_fp.get("r02_errors")
            and not id_errs
            and fp_f0.get("passed", True) is True
        )
        if not fp_integrity_ok or fp_val_status not in ("SUPPORTED", "REFUTED", "UNDETERMINED"):
            fp_concurrence = "EVIDENCE_OR_CONTRACT_FAILURE"
            fp_impact = (
                "Supplementary AllowlistedQuery triage/identity failed evidence or contract validation; "
                "historical R01 (4 inferences) and R02 remain unaffected, while R03 fails closed."
            )
        elif fp_val_status == "REFUTED":
            fp_concurrence = "CONCURRED_REFUTED"
            fp_impact = (
                "Supplementary AllowlistedQuery run validly produced REFUTED concurring with human FP review; "
                "kept separate from historical 4-call R01/R02 session."
            )
        elif fp_val_status == "SUPPORTED":
            fp_concurrence = "DISAGREED_SUPPORTED"
            fp_impact = (
                "Model validly judged AllowlistedQuery as SUPPORTED (preserved without coercing to REFUTED); "
                "historical R01 (4 inferences) and R02 remain unaffected and R03 human lifecycle is evaluated independently, "
                "but acceptance documentation must report that Qwen did not concur on FP and confirm human-override policy."
            )
        else:
            fp_concurrence = "ABSTAINED_UNDETERMINED"
            fp_impact = (
                "Model validly abstained as UNDETERMINED on AllowlistedQuery (preserved without coercing to REFUTED); "
                "historical R01 (4 inferences) and R02 remain unaffected and R03 human lifecycle is evaluated independently, "
                "but acceptance documentation must report Qwen abstention on the FP control and confirm human-override policy."
            )
        supplementary_r03_control = {
            "scenario": "allowlisted_query_fp_control",
            "run_separation": "SEPARATE_SUPPLEMENTARY_RUN_NOT_MERGED_WITH_G1_C5_PRIMARY_4",
            "merged_with_g1_c5_session": False,
            "expected_findings": 1,
            "observed_findings": d_fp.get("findings_count", 0),
            "triage_policy": "OBSERVED_VALID_TRIAGE",
            "raw_model_status": fp_raw_status,
            "validated_status": fp_val_status,
            "model_fp_concurrence": fp_concurrence,
            "qwen_concurred_fp": fp_val_status == "REFUTED" and fp_integrity_ok,
            "acceptance_impact": fp_impact,
            "run_provenance": d_fp.get("run_provenance"),
        }
    scenarios_out.update({
        "demo3a_missing_helper": d3a,
        "demo3b_malformed_json_mock": d3b,
        "demo4_stale_source": d4,
    })

    caveats = [
        "Read-only SQLite URI (?mode=ro) inspection only; writable ReviewStore was not used.",
        "Human actor actions in R03 test operational lifecycle, not Ground Truth labels.",
        "SQLite --actor strings are local unauthenticated operational identifiers (not cryptographic identity attestation); official mode rejects scripted/mock/replay markers.",
        "HTTP 200 and raw HTTP body hashes prove client-observed transport bytes, not cryptographic model weight attestation.",
    ]
    if use_proposed_fp:
        caveats.append(
            "PROPOSED R03 FP REPLACEMENT MODE (requires operator/advisor approval to supersede locked G1-C5 Demo2 R03 contract): "
            "Historical R01/R02 (4 G1-C5 inferences including Demo2 REFUTED) remain strictly unchanged and separate; supplementary R03 confirm-false/reopen runs on AllowlistedQuery.java without coercing Qwen to REFUTED."
        )
    if capture_relocation_mode == "pinned-original-capture":
        caveats.append(
            "PINNED SCENARIO/CAPTURE RELOCATION MODE: Relocated review copies are verified against operator-pinned original "
            "scenario and capture directories (independent original scenario & capture integrity, legacy_reports containment inside "
            "original capture, full pre-review byte parity of g1-run-manifest, capture/, triage/evidence.json, assessments.jsonl, "
            "input.opengrep.json, http-capture-check.json, recursive llm_io/, and review.post_ingestion.sqlite); "
            "only post-review SQLite review.sqlite / review.after_confirm_false.sqlite may diverge, and manifest paths are never self-authenticating."
        )

    out_doc: dict[str, Any] = {
        "schema": "ntk-g1-r01-r03-evaluation-1",
        "r03_fp_mode": r03_fp_mode,
        "capture_relocation_mode": capture_relocation_mode,
        "pinned_original_scenario_roots": {k: str(v) for k, v in provided_scenario_roots.items()},
        "pinned_original_capture_roots": {k: str(v) for k, v in provided_capture_roots.items()},
        "allow_mock_primary_test_mode": allow_mock_primary,
        "actor_identity_model": {
            "mechanism": "LOCAL_UNAUTHENTICATED_OPERATOR_IDENTIFIER",
            "cryptographic_identity_verified": False,
            "scripted_mock_replay_markers_rejected_in_official_mode": not allow_mock_primary,
            "enforced_when_official": [
                "non-empty stripped actor and reason required",
                "scripted/mock/synthetic/replay actor tokens and tags rejected when allow_mock_primary=False",
                "live Ollama HTTP capture and unmodified source hashes required when allow_mock_primary=False",
            ],
        },
        "overall_status": overall,
        "real_qwen_denominator": {
            "expected": expected_real_total,
            "observed": real_findings_total,
            "breakdown": breakdown,
            "excluded_auxiliary_controls": excluded_aux,
        },
        "criteria": {
            "R01": {"status": r01_status, "failures": r01_failures, "blockers": r01_blockers},
            "R02": {"status": r02_status, "failures": r02_failures, "blockers": r02_blockers},
            "R03": {"status": r03_status, "failures": r03_failures, "blockers": r03_blockers},
        },
        "scenarios": scenarios_out,
        "caveats": caveats,
    }
    if use_proposed_fp:
        out_doc["real_qwen_denominator"]["historical_g1_c5_expected"] = 4
        out_doc["supplementary_r03_control"] = supplementary_r03_control
        out_doc["proposed_contract_status"] = "PROPOSED_AWAITING_OPERATOR_APPROVAL"
    return out_doc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only R01-R03 runtime acceptance evaluator")
    parser.add_argument("--demo1-dir", type=Path, required=True)
    parser.add_argument("--demo2-dir", type=Path, required=True)
    parser.add_argument("--demo3a-dir", type=Path, required=True)
    parser.add_argument("--m1-dir", type=Path, required=True)
    parser.add_argument("--demo4-dir", type=Path, required=True)
    parser.add_argument("--demo3b-dir", type=Path, default=None)
    parser.add_argument(
        "--r03-fp-mode",
        choices=("locked-demo2", "proposed-allowlisted-fp"),
        default="locked-demo2",
        help="locked-demo2 preserves G1-C5 Demo2 R03 lifecycle; proposed-allowlisted-fp shifts R03 FP confirm-false/reopen to AllowlistedQuery.java",
    )
    parser.add_argument(
        "--allowlisted-fp-dir",
        type=Path,
        default=None,
        help="Scenario directory for AllowlistedQuery.java (required with --r03-fp-mode proposed-allowlisted-fp)",
    )
    parser.add_argument(
        "--allowlisted-trusted-source-root", type=Path, default=None,
        help="Original AllowlistedQuery scan source root pinned by the operator, independent of evidence JSON/manifest",
    )
    parser.add_argument(
        "--capture-relocation-mode",
        choices=("strict-in-place", "pinned-original-capture"),
        default="strict-in-place",
        help="strict-in-place requires legacy_reports inside scenario capture dir; pinned-original-capture pairs relocated review copies with operator-pinned original scenario and capture dirs",
    )
    parser.add_argument("--demo1-trusted-scenario-root", type=Path, default=None, help="Original Demo1 scenario root (containing g1-run-manifest.json, capture/, triage/) pinned by the operator")
    parser.add_argument("--demo2-trusted-scenario-root", type=Path, default=None, help="Original Demo2 scenario root pinned by the operator")
    parser.add_argument("--demo3a-trusted-scenario-root", type=Path, default=None, help="Original Demo3a scenario root pinned by the operator")
    parser.add_argument("--m1-trusted-scenario-root", type=Path, default=None, help="Original M1 scan-only scenario root pinned by the operator")
    parser.add_argument("--demo4-trusted-scenario-root", type=Path, default=None, help="Original Demo4 scenario root pinned by the operator")
    parser.add_argument("--demo3b-trusted-scenario-root", type=Path, default=None, help="Original Demo3b scenario root pinned by the operator")
    parser.add_argument("--allowlisted-trusted-scenario-root", type=Path, default=None, help="Original AllowlistedQuery scenario root pinned by the operator")
    parser.add_argument("--demo1-trusted-capture-root", type=Path, default=None, help="Original Demo1 capture dir (containing scan-manifest.json and legacy_reports/) pinned by the operator")
    parser.add_argument("--demo2-trusted-capture-root", type=Path, default=None, help="Original Demo2 capture dir pinned by the operator")
    parser.add_argument("--demo3a-trusted-capture-root", type=Path, default=None, help="Original Demo3a capture dir pinned by the operator")
    parser.add_argument("--m1-trusted-capture-root", type=Path, default=None, help="Original M1 capture dir pinned by the operator")
    parser.add_argument("--demo4-trusted-capture-root", type=Path, default=None, help="Original Demo4 capture dir pinned by the operator")
    parser.add_argument("--demo3b-trusted-capture-root", type=Path, default=None, help="Original Demo3b capture dir pinned by the operator")
    parser.add_argument("--allowlisted-trusted-capture-root", type=Path, default=None, help="Original AllowlistedQuery capture dir pinned by the operator")
    parser.add_argument("--output", type=Path, required=True, help="Output JSON file (must lie outside scenario directories)")
    parser.add_argument("--allow-mock-primary", action="store_true", help="Offline unit-test flag only; never set in real acceptance")
    args = parser.parse_args(argv)

    if args.r03_fp_mode == "locked-demo2" and args.allowlisted_fp_dir is not None:
        parser.error("--allowlisted-fp-dir requires --r03-fp-mode proposed-allowlisted-fp")
    if args.r03_fp_mode == "proposed-allowlisted-fp" and args.allowlisted_fp_dir is None:
        parser.error("--r03-fp-mode proposed-allowlisted-fp requires --allowlisted-fp-dir")
    if args.r03_fp_mode == "proposed-allowlisted-fp" and args.allowlisted_trusted_source_root is None:
        parser.error("--r03-fp-mode proposed-allowlisted-fp requires --allowlisted-trusted-source-root")
    if args.r03_fp_mode == "locked-demo2" and args.allowlisted_trusted_source_root is not None:
        parser.error("--allowlisted-trusted-source-root requires --r03-fp-mode proposed-allowlisted-fp")

    cli_scenario_roots: dict[str, Path | None] = {
        "demo1": args.demo1_trusted_scenario_root,
        "demo2": args.demo2_trusted_scenario_root,
        "demo3a": args.demo3a_trusted_scenario_root,
        "m1": args.m1_trusted_scenario_root,
        "demo4": args.demo4_trusted_scenario_root,
        "demo3b": args.demo3b_trusted_scenario_root,
        "allowlisted": args.allowlisted_trusted_scenario_root,
    }
    cli_capture_roots: dict[str, Path | None] = {
        "demo1": args.demo1_trusted_capture_root,
        "demo2": args.demo2_trusted_capture_root,
        "demo3a": args.demo3a_trusted_capture_root,
        "m1": args.m1_trusted_capture_root,
        "demo4": args.demo4_trusted_capture_root,
        "demo3b": args.demo3b_trusted_capture_root,
        "allowlisted": args.allowlisted_trusted_capture_root,
    }
    try:
        provided_cli_scenarios, provided_cli_captures = _validate_capture_relocation_args(
            capture_relocation_mode=args.capture_relocation_mode,
            r03_fp_mode=args.r03_fp_mode,
            demo3b_dir=args.demo3b_dir,
            scenario_roots=cli_scenario_roots,
            capture_roots=cli_capture_roots,
        )
    except ValueError as exc:
        parser.error(str(exc))

    try:
        raw_out = _validate_lexical_dir_path(args.output, label="--output")
    except CaptureWriteError as exc:
        parser.error(f"invalid --output path {args.output}: {exc}")
    abs_out = Path(os.path.abspath(raw_out))
    if abs_out.parent == abs_out or Path(abs_out.name).name != abs_out.name or abs_out.name in ("", ".", ".."):
        parser.error(f"invalid --output filename: {args.output}")
    if os.path.lexists(abs_out):
        parser.error(f"refusing to overwrite existing evaluation report: {args.output}")
    if not _is_missing_clean_path(abs_out):
        parser.error(f"refusing unsafe or symlink/junction-linked --output path: {args.output}")
    protected_dirs = [args.demo1_dir, args.demo2_dir, args.demo3a_dir, args.m1_dir, args.demo4_dir]
    if args.demo3b_dir is not None:
        protected_dirs.append(args.demo3b_dir)
    if args.allowlisted_fp_dir is not None:
        protected_dirs.append(args.allowlisted_fp_dir)
    if args.allowlisted_trusted_source_root is not None:
        protected_dirs.append(args.allowlisted_trusted_source_root)
    protected_dirs.extend(provided_cli_scenarios.values())
    protected_dirs.extend(provided_cli_captures.values())
    for p_dir in protected_dirs:
        if os.path.lexists(p_dir):
            abs_p = Path(os.path.abspath(p_dir))
            if abs_out.is_relative_to(abs_p):
                parser.error(f"--output must lie outside scenario directory {p_dir}")
            try:
                res_p = p_dir.resolve(strict=True)
                if abs_out.is_relative_to(res_p):
                    parser.error(f"--output must lie outside scenario directory {p_dir}")
            except (OSError, RuntimeError):
                pass

    report = evaluate_acceptance(
        demo1_dir=args.demo1_dir,
        demo2_dir=args.demo2_dir,
        demo3a_dir=args.demo3a_dir,
        m1_dir=args.m1_dir,
        demo4_dir=args.demo4_dir,
        demo3b_dir=args.demo3b_dir,
        allowlisted_fp_dir=args.allowlisted_fp_dir,
        allowlisted_trusted_source_root=args.allowlisted_trusted_source_root,
        r03_fp_mode=args.r03_fp_mode,
        capture_relocation_mode=args.capture_relocation_mode,
        demo1_trusted_scenario_root=args.demo1_trusted_scenario_root,
        demo2_trusted_scenario_root=args.demo2_trusted_scenario_root,
        demo3a_trusted_scenario_root=args.demo3a_trusted_scenario_root,
        m1_trusted_scenario_root=args.m1_trusted_scenario_root,
        demo4_trusted_scenario_root=args.demo4_trusted_scenario_root,
        demo3b_trusted_scenario_root=args.demo3b_trusted_scenario_root,
        allowlisted_trusted_scenario_root=args.allowlisted_trusted_scenario_root,
        demo1_trusted_capture_root=args.demo1_trusted_capture_root,
        demo2_trusted_capture_root=args.demo2_trusted_capture_root,
        demo3a_trusted_capture_root=args.demo3a_trusted_capture_root,
        m1_trusted_capture_root=args.m1_trusted_capture_root,
        demo4_trusted_capture_root=args.demo4_trusted_capture_root,
        demo3b_trusted_capture_root=args.demo3b_trusted_capture_root,
        allowlisted_trusted_capture_root=args.allowlisted_trusted_capture_root,
        allow_mock_primary=args.allow_mock_primary,
    )
    try:
        safe_out_parent = verify_safe_directory_chain(abs_out.parent, boundary_root=abs_out.parent, create=True)
        out_resolved = safe_out_parent / abs_out.name
    except CaptureWriteError as exc:
        parser.error(f"refusing unsafe --output directory {abs_out.parent}: {exc}")
    rendered = json.dumps(report, indent=2, ensure_ascii=False)
    with out_resolved.open("xb") as handle:
        handle.write((rendered + "\n").encode("utf-8"))
    print(rendered)
    return 0 if report["overall_status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
