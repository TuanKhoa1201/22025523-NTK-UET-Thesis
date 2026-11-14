"""Read-only R01-R03 runtime acceptance evaluator for G1.

Evaluates fresh run directories against `G1_C3_REGRESSION_CRITERIA.md` (R01, R02, R03)
and `G1_C3_R01_R03_CHECKLIST.json` without mutating any scenario directory or opening
SQLite in read-write mode (`?mode=ro` URI only; never instantiates `ReviewStore`).

Never infers R01 PASS from CLI exit code `0`, HTTP `200`, `ALL_HTTP_COMPLETED`, or
`OLLAMA_REPORTED_UNATTESTED` alone.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import sqlite3
import stat
from typing import Any

from v2.g1_audit import contracts
from v2.triage import live_check
from v2.triage.evidence import EvidenceError, SourceTree, StaleSourceError, check_current, digest, strict_json
from v2.triage.ollama import (
    PROMPT_CONTRACT_BLIND,
    PROMPT_VERSION,
    assert_prompt_contract,
    inspect_citations_provenance,
    is_reparse_link,
    validate_answer,
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
    return ".." in Path(path).parts


def _is_safe_dir(path: Path) -> bool:
    p = Path(path)
    if _has_parent_traversal(p) or not os.path.lexists(p):
        return False
    if is_reparse_link(p):
        return False
    try:
        st = os.lstat(p)
    except OSError:
        return False
    if not stat.S_ISDIR(st.st_mode):
        return False
    parent = p.parent
    if parent != p and os.path.lexists(parent) and is_reparse_link(parent):
        return False
    return True


def _is_safe_regular_file(path: Path) -> bool:
    p = Path(path)
    if _has_parent_traversal(p) or not os.path.lexists(p):
        return False
    if is_reparse_link(p):
        return False
    try:
        st = os.lstat(p)
    except OSError:
        return False
    if not stat.S_ISREG(st.st_mode):
        return False
    parent = p.parent
    if parent != p and os.path.lexists(parent) and is_reparse_link(parent):
        return False
    return True


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


def _verify_sqlite_against_triage(
    label: str,
    db_state: dict[str, Any],
    evidence_bundle: dict[str, Any],
    rows: list[dict[str, Any]],
    *,
    require_zero_rejected: bool = True,
) -> list[str]:
    errors: list[str] = []
    scan_sha = evidence_bundle.get("scan_sha256")
    records = evidence_bundle.get("records") or []

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
            ts = contracts.timestamp(ev.get("timestamp"))
        except (ValueError, TypeError) as exc:
            errors.append(f"{label}: event[{idx}] invalid timestamp {ev.get('timestamp')!r}: {exc}")
            ts = None
        if ts is not None:
            if prev_ts is not None and ts < prev_ts:
                errors.append(f"{label}: event[{idx}] timestamp regressed before prior event")
            prev_ts = ts

        actor = ev.get("actor")
        reason = ev.get("reason")
        if not isinstance(actor, str) or not actor.strip() or actor != actor.strip():
            errors.append(f"{label}: event[{idx}] invalid or unstripped actor {actor!r}")
        if not isinstance(reason, str) or not reason.strip() or reason != reason.strip():
            errors.append(f"{label}: event[{idx}] invalid or unstripped reason")

        action = ev.get("action")
        if action == "confirm-true":
            if sim_states[wid] != "OPEN":
                errors.append(f"{label}: event[{idx}] invalid confirm-true from state {sim_states[wid]!r}")
            sim_states[wid] = "CONFIRMED_TRUE"
        elif action == "confirm-false":
            if sim_states[wid] != "OPEN":
                errors.append(f"{label}: event[{idx}] invalid confirm-false from state {sim_states[wid]!r}")
            sim_states[wid] = "CONFIRMED_FALSE"
        elif action == "reopen":
            if sim_states[wid] not in ("CONFIRMED_TRUE", "CONFIRMED_FALSE"):
                errors.append(f"{label}: event[{idx}] invalid reopen from state {sim_states[wid]!r}")
            sim_states[wid] = "OPEN"
        else:
            errors.append(f"{label}: event[{idx}] unknown action {action!r}")

        expected_snapshots = rec.get("snapshots") or {}
        expected_obs = {
            p: snap.get("sha256")
            for p, snap in expected_snapshots.items()
            if isinstance(snap, dict)
        }
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

    if require_zero_rejected and db_state["rejected_decisions"]:
        errors.append(f"{label}: unexpectedly contains {len(db_state['rejected_decisions'])} rejected_decisions row(s)")

    return errors


def _verify_capture_dir_integrity(
    prefix: str,
    capture_dir: Path,
    *,
    expected_cli_mode: str,
    expect_live_source_current: bool,
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
                    if _has_parent_traversal(legacy_path) or not _is_safe_regular_file(legacy_path):
                        errors.append(f"{prefix}: missing or unsafe engine_output_path for {label}")
                    elif not legacy_path.resolve().is_relative_to(capture_dir.resolve()):
                        errors.append(f"{prefix}: engine_output_path escapes capture dir for {label}")
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
) -> dict[str, Any]:
    raw_scenario_dir = Path(scenario_dir)
    failures: list[str] = []
    blockers: list[str] = []
    r02_errors: list[str] = []
    r03_errors: list[str] = []

    if os.path.lexists(raw_scenario_dir) and is_reparse_link(raw_scenario_dir):
        msg = f"{scenario_name}: scenario directory is a symlink/junction: {raw_scenario_dir}"
        return {
            "scenario": scenario_name,
            "status": "FAIL",
            "findings_count": 0,
            "r02_errors": [msg],
            "r03_errors": [msg],
            "blockers": [],
            "failures": [msg],
        }
    if not _is_safe_dir(raw_scenario_dir):
        return {
            "scenario": scenario_name,
            "status": "BLOCKED",
            "findings_count": 0,
            "r02_errors": [],
            "r03_errors": [],
            "blockers": [f"missing scenario directory: {raw_scenario_dir}"],
            "failures": [],
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
    )
    r02_errors.extend(cap_errors)

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
        ):
            entry = artifacts_meta.get(akey)
            expected_sha = entry.get("sha256") if isinstance(entry, dict) else None
            if not _is_safe_regular_file(apath) or digest(apath.read_bytes()) != expected_sha:
                r02_errors.append(f"{scenario_name}: artifacts.{akey}.sha256 mismatch or missing file")

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

    # Mandatory pre-lifecycle SQLite snapshot check (F06/F07)
    pre_db = triage_dir / "review.post_ingestion.sqlite"
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
                    require_zero_rejected=True,
                )
            )
            if len(ing_db_state["warnings"]) != expected_findings or any(w["state"] != "OPEN" for w in ing_db_state["warnings"]):
                r03_errors.append(f"{scenario_name}: review.post_ingestion.sqlite does not hold {expected_findings} OPEN warning(s)")
            if ing_db_state["events"]:
                r03_errors.append(f"{scenario_name}: review.post_ingestion.sqlite unexpectedly has pre-existing events")
            review_art = artifacts_meta.get("review_sqlite") if isinstance(artifacts_meta, dict) else None
            expected_rev_sha = review_art.get("sha256") if isinstance(review_art, dict) else None
            if expected_rev_sha and ing_db_state["db_sha256"] != expected_rev_sha:
                r03_errors.append(f"{scenario_name}: review.post_ingestion.sqlite SHA-256 differs from manifest artifacts.review_sqlite.sha256")
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
                require_zero_rejected=True,
            )
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
                        require_zero_rejected=True,
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
        "r02_errors": r02_errors,
        "r03_errors": r03_errors,
        "findings": per_finding_details,
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


def _inspect_m1_scan_only(m1_dir: Path) -> dict[str, Any]:
    raw_m1 = Path(m1_dir)
    errors: list[str] = []
    blockers: list[str] = []
    if os.path.lexists(raw_m1) and is_reparse_link(raw_m1):
        return {"present": True, "blockers": [], "errors": [f"M1 directory is a symlink/junction: {raw_m1}"]}
    if not _is_safe_dir(raw_m1):
        return {"present": False, "blockers": [f"missing M1 scan-only directory: {raw_m1}"], "errors": []}

    m1_dir = raw_m1.resolve()
    cap_dir = m1_dir if os.path.lexists(m1_dir / "scan-manifest.json") else (m1_dir / "capture")
    if os.path.lexists(cap_dir) and is_reparse_link(cap_dir):
        return {"present": True, "blockers": [], "errors": [f"M1 capture directory is a symlink/junction: {cap_dir}"]}
    if not os.path.lexists(cap_dir / "scan-manifest.json"):
        return {"present": True, "blockers": [f"missing scan-manifest.json in {m1_dir}"], "errors": []}

    for forbidden_rel in ("triage", "g1-run-manifest.json", "llm_io", "assessments.jsonl", "review.sqlite"):
        if os.path.lexists(m1_dir / forbidden_rel):
            errors.append(f"M1 --scan-only unexpectedly produced {forbidden_rel}")

    cap_errors, _ = _verify_capture_dir_integrity(
        "M1",
        cap_dir,
        expected_cli_mode="scan-only",
        expect_live_source_current=True,
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


def _inspect_demo3b_mock_control(demo3b_dir: Path | None) -> dict[str, Any]:
    if demo3b_dir is None:
        return {"present": False, "excluded_from_real_denominator": True, "errors": []}
    raw_d3b = Path(demo3b_dir)
    if os.path.lexists(raw_d3b) and is_reparse_link(raw_d3b):
        return {
            "present": True,
            "excluded_from_real_denominator": True,
            "errors": [f"Demo3b directory is a symlink/junction: {raw_d3b}"],
        }
    if not _is_safe_dir(raw_d3b):
        return {"present": False, "excluded_from_real_denominator": True, "errors": [f"missing demo3b dir: {raw_d3b}"]}

    demo3b_dir = raw_d3b.resolve()
    errors: list[str] = []
    capture_dir = demo3b_dir / "capture"
    triage_dir = demo3b_dir / "triage"
    if not _is_safe_dir(capture_dir) or not _is_safe_dir(triage_dir):
        errors.append(f"Demo3b missing or unsafe capture/ or triage/ in {demo3b_dir}")
        return {
            "present": True,
            "evidence_kind": "SYNTHETIC_MOCK_HTTP",
            "excluded_from_real_denominator": True,
            "http_capture_status": None,
            "errors": errors,
        }

    http_check = verify_run_http_captures(triage_dir, require_live_chat=False, minimum_findings=1)
    if not http_check["capture_integrity_ok"]:
        errors.append(f"Demo3b mock HTTP raw capture check failed: {http_check['errors']}")

    cap_errors, _ = _verify_capture_dir_integrity(
        "Demo3b",
        capture_dir,
        expected_cli_mode="local-triage",
        expect_live_source_current=True,
    )
    errors.extend(cap_errors)

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

    try:
        db_state = _read_sqlite_state_ro(triage_dir / "review.sqlite")
        if evidence_bundle is not None:
            errors.extend(
                _verify_sqlite_against_triage(
                    "Demo3b review.sqlite",
                    db_state,
                    evidence_bundle,
                    rows,
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
    if os.path.lexists(d3b_pre):
        try:
            d3b_pre_state = _read_sqlite_state_ro(d3b_pre)
            if evidence_bundle is not None:
                errors.extend(
                    _verify_sqlite_against_triage(
                        "Demo3b post_ingestion",
                        d3b_pre_state,
                        evidence_bundle,
                        rows,
                        require_zero_rejected=True,
                    )
                )
            if [w["state"] for w in d3b_pre_state["warnings"]] != ["OPEN"] or d3b_pre_state["events"]:
                errors.append("Demo3b review.post_ingestion.sqlite must hold 1 OPEN warning and 0 events")
        except (OSError, sqlite3.Error, EvidenceError, ValueError, KeyError, TypeError) as exc:
            errors.append(f"Demo3b invalid review.post_ingestion.sqlite: {exc}")

    return {
        "present": True,
        "evidence_kind": "SYNTHETIC_MOCK_HTTP",
        "excluded_from_real_denominator": True,
        "http_capture_status": http_check["capture_status"],
        "errors": errors,
    }


def _inspect_demo4_stale_control(demo4_dir: Path) -> dict[str, Any]:
    raw_d4 = Path(demo4_dir)
    if os.path.lexists(raw_d4) and is_reparse_link(raw_d4):
        return {
            "present": True,
            "excluded_from_real_denominator": True,
            "blockers": [],
            "errors": [f"Demo4 directory is a symlink/junction: {raw_d4}"],
        }
    if not _is_safe_dir(raw_d4):
        return {"present": False, "blockers": [f"missing Demo4 stale-source directory: {raw_d4}"], "errors": []}

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

    try:
        manifest = strict_json(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, EvidenceError) as exc:
        manifest = {}
        errors.append(f"Demo4 invalid g1-run-manifest.json: {exc}")

    if manifest.get("ollama", {}).get("enabled") is not False:
        errors.append("Demo4 stale-source control must run with --no-llm (excluded from Qwen calls)")

    cap_errors, _ = _verify_capture_dir_integrity(
        "Demo4",
        capture_dir,
        expected_cli_mode="local-triage",
        expect_live_source_current=False,
    )
    errors.extend(cap_errors)

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
    pre_db = triage_dir / "review.post_ingestion.sqlite"
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
                        require_zero_rejected=True,
                    )
                )
            if [w["state"] for w in ing_state["warnings"]] != ["OPEN"] or ing_state["events"]:
                errors.append("Demo4 review.post_ingestion.sqlite must hold 1 OPEN warning and 0 events")
            d4_rev_art = artifacts_meta.get("review_sqlite") if isinstance(artifacts_meta, dict) else None
            d4_expected_rev_sha = d4_rev_art.get("sha256") if isinstance(d4_rev_art, dict) else None
            if d4_expected_rev_sha and ing_state["db_sha256"] != d4_expected_rev_sha:
                errors.append("Demo4 review.post_ingestion.sqlite SHA-256 differs from manifest artifacts.review_sqlite.sha256")
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
                    require_zero_rejected=False,
                )
            )
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


def evaluate_acceptance(
    *,
    demo1_dir: Path,
    demo2_dir: Path,
    demo3a_dir: Path,
    m1_dir: Path,
    demo4_dir: Path,
    demo3b_dir: Path | None = None,
    allow_mock_primary: bool = False,
) -> dict[str, Any]:
    d1 = _inspect_primary_scenario(
        "demo1_true_positive",
        demo1_dir,
        expected_findings=2,
        expected_polarity="SUPPORTED",
        allow_mock_primary=allow_mock_primary,
    )
    d2 = _inspect_primary_scenario(
        "demo2_protected_false_positive",
        demo2_dir,
        expected_findings=1,
        expected_polarity="REFUTED",
        allow_mock_primary=allow_mock_primary,
        require_after_confirm_false=True,
    )
    d3a = _inspect_primary_scenario(
        "demo3a_missing_helper",
        demo3a_dir,
        expected_findings=1,
        expected_polarity="UNDETERMINED_ABSTAIN",
        allow_mock_primary=allow_mock_primary,
    )
    m1 = _inspect_m1_scan_only(m1_dir)
    d3b = _inspect_demo3b_mock_control(demo3b_dir)
    d4 = _inspect_demo4_stale_control(demo4_dir)

    # R01 decision: record observed FAIL even if another check is BLOCKED (per checklist false_pass_guards!)
    r01_failures = [*d1.get("failures", []), *d2.get("failures", []), *d3a.get("failures", []), *d3b.get("errors", [])]
    r01_blockers = [*d1.get("blockers", []), *d2.get("blockers", []), *d3a.get("blockers", [])]
    real_findings_total = sum(x.get("findings_count", 0) for x in (d1, d2, d3a))
    if real_findings_total != 4 and not r01_blockers:
        r01_failures.append(f"R01 real-Qwen denominator must equal 4 (2+1+1), observed {real_findings_total}")
    r01_status = "FAIL" if r01_failures else ("BLOCKED" if r01_blockers else "PASS")

    # R02 decision
    r02_failures = [
        *m1.get("errors", []),
        *d1.get("r02_errors", []),
        *d2.get("r02_errors", []),
        *d3a.get("r02_errors", []),
    ]
    r02_blockers = [*m1.get("blockers", []), *d1.get("blockers", []), *d2.get("blockers", []), *d3a.get("blockers", [])]
    r02_status = "FAIL" if r02_failures else ("BLOCKED" if r02_blockers else "PASS")

    # R03 decision (Demo1 confirm-true + Demo2 confirm-false -> reopen + Demo3a untouched OPEN + Demo4 STALE_SOURCE)
    r03_failures: list[str] = [
        *d4.get("errors", []),
        *d1.get("r03_errors", []),
        *d2.get("r03_errors", []),
        *d3a.get("r03_errors", []),
    ]
    r03_blockers: list[str] = [
        *d4.get("blockers", []),
        *d1.get("blockers", []),
        *d2.get("blockers", []),
        *d3a.get("blockers", []),
    ]

    d1_sql = d1.get("current_sqlite")
    if d1_sql is not None:
        if "CONFIRMED_TRUE" not in d1_sql["states"] or "OPEN" not in d1_sql["states"]:
            r03_failures.append(f"Demo1 expected one CONFIRMED_TRUE and one OPEN warning, got {d1_sql['states']}")
        d1_events = d1_sql["events"]
        if len(d1_events) != 1 or d1_events[0]["action"] != "confirm-true" or not d1_events[0]["actor"].strip() or not d1_events[0]["reason"].strip():
            r03_failures.append(f"Demo1 expected 1 confirm-true event with actor/reason, got {d1_events}")

    d2_sql = d2.get("current_sqlite")
    if d2_sql is not None:
        if d2_sql["states"] != ["OPEN"]:
            r03_failures.append(f"Demo2 expected final state ['OPEN'] after reopen, got {d2_sql['states']}")
        d2_actions = [e["action"] for e in d2_sql["events"]]
        if d2_actions != ["confirm-false", "reopen"]:
            r03_failures.append(f"Demo2 expected events ['confirm-false', 'reopen'], got {d2_actions}")
        for ev in d2_sql["events"]:
            if not str(ev.get("actor", "")).strip() or not str(ev.get("reason", "")).strip():
                r03_failures.append(f"Demo2 event missing actor or reason: {ev}")

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

    return {
        "schema": "ntk-g1-r01-r03-evaluation-1",
        "allow_mock_primary_test_mode": allow_mock_primary,
        "overall_status": overall,
        "real_qwen_denominator": {
            "expected": 4,
            "observed": real_findings_total,
            "breakdown": {
                "demo1_true_positive": d1.get("findings_count", 0),
                "demo2_protected_false_positive": d2.get("findings_count", 0),
                "demo3a_missing_helper": d3a.get("findings_count", 0),
            },
            "excluded_auxiliary_controls": ["m1_scan_only", "demo3b_malformed_json_mock", "demo4_stale_source"],
        },
        "criteria": {
            "R01": {"status": r01_status, "failures": r01_failures, "blockers": r01_blockers},
            "R02": {"status": r02_status, "failures": r02_failures, "blockers": r02_blockers},
            "R03": {"status": r03_status, "failures": r03_failures, "blockers": r03_blockers},
        },
        "scenarios": {
            "m1_scan_only": m1,
            "demo1_true_positive": d1,
            "demo2_protected_false_positive": d2,
            "demo3a_missing_helper": d3a,
            "demo3b_malformed_json_mock": d3b,
            "demo4_stale_source": d4,
        },
        "caveats": [
            "Read-only SQLite URI (?mode=ro) inspection only; writable ReviewStore was not used.",
            "Human actor actions in R03 test operational lifecycle, not Ground Truth labels.",
            "HTTP 200 and raw HTTP body hashes prove client-observed transport bytes, not cryptographic model weight attestation.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only R01-R03 runtime acceptance evaluator")
    parser.add_argument("--demo1-dir", type=Path, required=True)
    parser.add_argument("--demo2-dir", type=Path, required=True)
    parser.add_argument("--demo3a-dir", type=Path, required=True)
    parser.add_argument("--m1-dir", type=Path, required=True)
    parser.add_argument("--demo4-dir", type=Path, required=True)
    parser.add_argument("--demo3b-dir", type=Path, default=None)
    parser.add_argument("--output", type=Path, required=True, help="Output JSON file (must lie outside scenario directories)")
    parser.add_argument("--allow-mock-primary", action="store_true", help="Offline unit-test flag only; never set in real acceptance")
    args = parser.parse_args(argv)

    if _has_parent_traversal(args.output):
        parser.error(f"refusing '..' in --output path: {args.output}")
    for anc in (args.output, *args.output.parents):
        if os.path.lexists(anc) and is_reparse_link(anc):
            parser.error(f"refusing to write --output through symlink/junction: {anc}")
    if os.path.lexists(args.output):
        parser.error(f"refusing to overwrite existing evaluation report: {args.output}")
    out_resolved = args.output.resolve()
    protected_dirs = [args.demo1_dir, args.demo2_dir, args.demo3a_dir, args.m1_dir, args.demo4_dir]
    if args.demo3b_dir is not None:
        protected_dirs.append(args.demo3b_dir)
    for p_dir in protected_dirs:
        if p_dir.exists() and out_resolved.is_relative_to(p_dir.resolve()):
            parser.error(f"--output must lie outside scenario directory {p_dir}")

    report = evaluate_acceptance(
        demo1_dir=args.demo1_dir,
        demo2_dir=args.demo2_dir,
        demo3a_dir=args.demo3a_dir,
        m1_dir=args.m1_dir,
        demo4_dir=args.demo4_dir,
        demo3b_dir=args.demo3b_dir,
        allow_mock_primary=args.allow_mock_primary,
    )
    rendered = json.dumps(report, indent=2, ensure_ascii=False)
    out_resolved.parent.mkdir(parents=True, exist_ok=True)
    with out_resolved.open("xb") as handle:
        handle.write((rendered + "\n").encode("utf-8"))
    print(rendered)
    return 0 if report["overall_status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
