"""Read-only forensic helper utilities for auditing server OpenGrep, Ollama, SQLite, and Ground-Truth artifacts.

Strictly read-only on historical evidence directories:
- Never modifies, touches, or opens historical SQLite files in place (copies SQLite to TemporaryDirectory first).
- Executes isolated temp-copy lifecycle checks (`confirm-true`, `confirm-false`, `reopen`, invalid states,
  and `STALE_SOURCE` blocking `confirm-false` after source mutation) while verifying zero mutation on originals.
- Separates raw LLM HTTP responses from post-validator assessments and human review states.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import shutil
import sqlite3
import tempfile
import zipfile
from collections import Counter
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from statistics import median
from typing import Any


ACTION_TO_STATE = {
    "confirm-true": "CONFIRMED_TRUE",
    "confirm-false": "CONFIRMED_FALSE",
    "reopen": "OPEN",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_lf_text(data: bytes) -> str | None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    normalized = "\n".join(line.rstrip("\r") for line in text.splitlines())
    return sha256_bytes(normalized.encode("utf-8"))


def compute_contract_alert_id(scan_sha256: str, finding_index: int) -> str:
    token = f"{scan_sha256.strip().lower()}:{finding_index}".encode("utf-8")
    return hashlib.sha256(token).hexdigest()


def normalize_cwe(raw_cwe: Any) -> str:
    if isinstance(raw_cwe, list):
        raw_cwe = raw_cwe[0] if raw_cwe else ""
    text = str(raw_cwe or "").strip().upper()
    if "CWE-22" in text or "CWE-022" in text or text == "22":
        return "CWE-22"
    if "CWE-89" in text or "CWE-089" in text or text == "89":
        return "CWE-89"
    if ":" in text:
        text = text.split(":", 1)[0].strip()
    return text or "UNKNOWN_CWE"


def status_to_decision(status: str) -> str:
    if status == "SUPPORTED":
        return "KEEP_TP"
    if status == "REFUTED":
        return "PROPOSED_FP"
    return "REVIEW"


def format_cited_lines(citations: list[dict[str, Any]] | None) -> str:
    if not citations:
        return ""
    parts: list[str] = []
    for c in citations:
        sl = c.get("start_line")
        el = c.get("end_line")
        if sl == el:
            parts.append(str(sl))
        else:
            parts.append(f"{sl}-{el}")
    return ",".join(parts)


def verify_sarif_against_opengrep_json(
    og_doc: dict[str, Any],
    sarif_doc: dict[str, Any],
) -> dict[str, Any]:
    """Cross-check raw SARIF results against raw opengrep.json results (order-independent multiset check)."""
    j_res = og_doc.get("results") if isinstance(og_doc.get("results"), list) else []
    runs = sarif_doc.get("runs") if isinstance(sarif_doc.get("runs"), list) else []
    if not runs or not isinstance(runs[0], dict):
        return {
            "passed": False,
            "order_preserved": False,
            "json_results_count": len(j_res),
            "sarif_results_count": 0,
            "mismatches": ["SARIF missing runs[0] object"],
        }
    s_res = runs[0].get("results") if isinstance(runs[0].get("results"), list) else []
    mismatches: list[str] = []
    if len(j_res) != len(s_res):
        mismatches.append(f"Result count mismatch: opengrep.json={len(j_res)} vs opengrep.sarif={len(s_res)}")

    j_keys: list[tuple[str, str, Any, Any]] = []
    for jr in j_res:
        j_sl = (jr.get("start") or {}).get("line")
        j_el = (jr.get("end") or {}).get("line", j_sl)
        j_keys.append(
            (
                str(jr.get("check_id") or ""),
                str(jr.get("path") or "").replace("\\", "/"),
                j_sl,
                j_el,
            )
        )

    s_keys: list[tuple[str, str, Any, Any]] = []
    for idx, sr in enumerate(s_res):
        locs = sr.get("locations") if isinstance(sr.get("locations"), list) else []
        if not locs or not isinstance(locs[0], dict):
            mismatches.append(f"SARIF result[{idx}] missing locations[0]")
            continue
        phys = locs[0].get("physicalLocation") or {}
        uri = str((phys.get("artifactLocation") or {}).get("uri") or "").replace("\\", "/")
        reg = phys.get("region") or {}
        s_sl = reg.get("startLine")
        s_el = reg.get("endLine", s_sl)
        s_keys.append((str(sr.get("ruleId") or ""), uri, s_sl, s_el))

    j_counter = Counter(j_keys)
    s_counter = Counter(s_keys)
    if j_counter != s_counter:
        for (rule_id, path, sl, el), cnt in sorted((j_counter - s_counter).items()):
            mismatches.append(
                f"Missing in SARIF (x{cnt}): check_id='{rule_id}', path='{path}', lines={sl}-{el}"
            )
        for (rule_id, uri, sl, el), cnt in sorted((s_counter - j_counter).items()):
            mismatches.append(
                f"Unexpected in SARIF (x{cnt}): ruleId='{rule_id}', uri='{uri}', lines={sl}-{el}"
            )

    return {
        "passed": len(mismatches) == 0,
        "order_preserved": j_keys == s_keys,
        "json_results_count": len(j_res),
        "sarif_results_count": len(s_res),
        "mismatches": mismatches,
    }


def percentile_nearest_rank(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, int((pct / 100.0) * len(ordered) + 0.999999))
    idx = min(len(ordered) - 1, rank - 1)
    return round(ordered[idx], 2)


def summarize_latencies_ms(values_ms: list[float]) -> dict[str, float | int | None]:
    if not values_ms:
        return {
            "count": 0,
            "total_ms": 0.0,
            "total_s": 0.0,
            "mean_ms": None,
            "p50_ms": None,
            "p95_ms": None,
            "min_ms": None,
            "max_ms": None,
        }
    total_ms = sum(values_ms)
    return {
        "count": len(values_ms),
        "total_ms": round(total_ms, 2),
        "total_s": round(total_ms / 1000.0, 2),
        "mean_ms": round(total_ms / len(values_ms), 2),
        "p50_ms": round(float(median(values_ms)), 2),
        "p95_ms": percentile_nearest_rank(values_ms, 95.0),
        "min_ms": round(min(values_ms), 2),
        "max_ms": round(max(values_ms), 2),
    }


def inspect_sqlite_readonly_copy(
    sqlite_path: Path,
    source_root: Path | None = None,
    expected_scan_sha256: str | None = None,
    expected_records_by_id: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Copy a SQLite DB to a temporary directory before reading and audit per-alert state & events."""
    if not sqlite_path.is_file():
        return {"present": False, "path": str(sqlite_path), "valid": False, "issues": ["sqlite file missing"]}

    before_sha = sha256_file(sqlite_path)
    before_mtime_ns = sqlite_path.stat().st_mtime_ns
    size_bytes = sqlite_path.stat().st_size
    issues: list[str] = []
    event_state_mismatches: list[dict[str, Any]] = []
    source_hash_mismatches: list[dict[str, Any]] = []
    alert_audit_rows: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="ntk_ro_sqlite_") as tmpdir:
        tmp_db = Path(tmpdir) / sqlite_path.name
        shutil.copy2(sqlite_path, tmp_db)
        conn = sqlite3.connect(str(tmp_db))
        try:
            integrity = str(conn.execute("PRAGMA integrity_check").fetchone()[0])
            if integrity.lower() != "ok":
                issues.append(f"SQLite integrity_check failed: {integrity}")
            fk_violations = conn.execute("PRAGMA foreign_key_check").fetchall()
            if fk_violations:
                issues.append(f"SQLite foreign_key_check violations: {len(fk_violations)}")

            tables = [
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                ).fetchall()
            ]
            for req_tbl in ("scans", "warnings", "events"):
                if req_tbl not in tables:
                    issues.append(f"Missing required SQLite table '{req_tbl}'")

            table_counts: dict[str, int] = {}
            for tbl in tables:
                table_counts[tbl] = int(conn.execute(f"SELECT COUNT(*) FROM [{tbl}]").fetchone()[0])

            scan_table_ids: list[str] = []
            if "scans" in tables:
                scan_table_ids = [
                    str(r[0]) for r in conn.execute("SELECT id FROM scans ORDER BY rowid").fetchall()
                ]
                if expected_scan_sha256 and scan_table_ids != [expected_scan_sha256]:
                    issues.append(
                        f"scans.id {scan_table_ids} != expected [{expected_scan_sha256}]"
                    )

            events_rows: list[dict[str, Any]] = []
            events_by_warning: dict[str, list[dict[str, Any]]] = {}
            if "events" in tables:
                cols = [c[1] for c in conn.execute("PRAGMA table_info(events)").fetchall()]
                for row in conn.execute("SELECT * FROM events ORDER BY sequence").fetchall():
                    ev_dict = dict(zip(cols, row))
                    events_rows.append(ev_dict)
                    wid = str(ev_dict.get("warning_id") or "")
                    events_by_warning.setdefault(wid, []).append(ev_dict)
                    act = str(ev_dict.get("action") or "")
                    if act not in ACTION_TO_STATE:
                        issues.append(f"Invalid action '{act}' in events sequence={ev_dict.get('sequence')}")
                    if "actor" in ev_dict and not str(ev_dict.get("actor") or "").strip():
                        issues.append(f"Empty actor in events sequence={ev_dict.get('sequence')}")
                    if "reason" in ev_dict and not str(ev_dict.get("reason") or "").strip():
                        issues.append(f"Empty reason in events sequence={ev_dict.get('sequence')}")
                    if "timestamp" in ev_dict and not str(ev_dict.get("timestamp") or "").strip():
                        issues.append(f"Empty timestamp in events sequence={ev_dict.get('sequence')}")

            states: dict[str, int] = {}
            scan_ids: list[str] = []
            warning_ids_seen: set[str] = set()
            if "warnings" in tables:
                w_cols = [c[1] for c in conn.execute("PRAGMA table_info(warnings)").fetchall()]
                for row in conn.execute("SELECT * FROM warnings ORDER BY rowid").fetchall():
                    w = dict(zip(w_cols, row))
                    wid = str(w.get("id") or "")
                    warning_ids_seen.add(wid)
                    w_scan = str(w.get("scan_id") or "")
                    w_state = str(w.get("state") or "")
                    states[w_state] = states.get(w_state, 0) + 1
                    if w_scan not in scan_ids:
                        scan_ids.append(w_scan)

                    if w_state not in ("OPEN", "CONFIRMED_TRUE", "CONFIRMED_FALSE"):
                        issues.append(f"Warning {wid}: invalid state '{w_state}'")
                    if expected_scan_sha256 and w_scan != expected_scan_sha256:
                        issues.append(f"Warning {wid}: scan_id {w_scan} != expected {expected_scan_sha256}")

                    w_ev_list = events_by_warning.get(wid, [])
                    expected_state = "OPEN" if not w_ev_list else ACTION_TO_STATE.get(str(w_ev_list[-1].get("action")), "INVALID")
                    if w_state != expected_state:
                        mismatch_obj = {
                            "warning_id": wid,
                            "actual_state": w_state,
                            "expected_state_from_events": expected_state,
                            "events_count": len(w_ev_list),
                            "last_event_action": w_ev_list[-1].get("action") if w_ev_list else None,
                        }
                        event_state_mismatches.append(mismatch_obj)
                        issues.append(
                            f"Warning {wid}: state='{w_state}' contradicts event history expected='{expected_state}'"
                        )

                    ev_json: dict[str, Any] = {}
                    ass_json: dict[str, Any] = {}
                    if "evidence" in w and isinstance(w["evidence"], str):
                        try:
                            ev_json = json.loads(w["evidence"])
                        except Exception as exc:
                            issues.append(f"Warning {wid}: malformed evidence JSON ({exc})")
                    if "assessment" in w and isinstance(w["assessment"], str):
                        try:
                            ass_json = json.loads(w["assessment"])
                        except Exception as exc:
                            issues.append(f"Warning {wid}: malformed assessment JSON ({exc})")

                    snaps = ev_json.get("snapshots") if isinstance(ev_json.get("snapshots"), dict) else {}
                    primary_path = str(ev_json.get("path") or "")
                    primary_source_sha = (snaps.get(primary_path) or {}).get("sha256")
                    if source_root is not None and snaps:
                        for rel_p, snap_meta in snaps.items():
                            disk_p = source_root / str(rel_p)
                            rec_sha = (snap_meta or {}).get("sha256")
                            if not disk_p.is_file():
                                source_hash_mismatches.append(
                                    {"warning_id": wid, "path": rel_p, "recorded_sha256": rec_sha, "disk_sha256": "MISSING"}
                                )
                                issues.append(f"Warning {wid}: missing disk source '{rel_p}'")
                            else:
                                d_sha = sha256_file(disk_p)
                                if d_sha != rec_sha:
                                    source_hash_mismatches.append(
                                        {"warning_id": wid, "path": rel_p, "recorded_sha256": rec_sha, "disk_sha256": d_sha}
                                    )
                                    issues.append(f"Warning {wid}: source_sha256 mismatch on '{rel_p}'")

                    if expected_records_by_id is not None:
                        exp_rec = expected_records_by_id.get(wid)
                        if exp_rec is None:
                            issues.append(f"Warning {wid}: present in SQLite but missing from assessments.jsonl")
                        else:
                            exp_status = (exp_rec.get("assessment") or {}).get("status")
                            if ass_json.get("status") != exp_status:
                                issues.append(
                                    f"Warning {wid}: SQLite assessment.status='{ass_json.get('status')}' != JSONL '{exp_status}'"
                                )

                    last_ev = w_ev_list[-1] if w_ev_list else None
                    alert_audit_rows.append(
                        {
                            "alert_id": wid,
                            "scan_sha256": w_scan,
                            "path": primary_path,
                            "source_sha256": primary_source_sha,
                            "queue_state": w_state,
                            "in_active_queue": w_state != "CONFIRMED_FALSE",
                            "model_proposed_status": ass_json.get("status"),
                            "human_events_count": len(w_ev_list),
                            "human_decision_action": last_ev.get("action") if last_ev else None,
                            "human_decision_actor": last_ev.get("actor") if last_ev else None,
                            "human_decision_timestamp": last_ev.get("timestamp") if last_ev else None,
                            "human_decision_reason": last_ev.get("reason") if last_ev else None,
                        }
                    )

                if expected_records_by_id is not None:
                    missing_in_db = sorted(set(expected_records_by_id) - warning_ids_seen)
                    if missing_in_db:
                        issues.append(f"Warnings missing from SQLite ({len(missing_in_db)}): {missing_in_db[:3]}")

                orphan_event_wids = sorted(set(events_by_warning) - warning_ids_seen)
                if orphan_event_wids:
                    issues.append(f"Orphaned warning_ids in events table: {orphan_event_wids}")
        finally:
            conn.close()

    after_sha = sha256_file(sqlite_path)
    after_mtime_ns = sqlite_path.stat().st_mtime_ns
    original_untouched = (before_sha == after_sha) and (before_mtime_ns == after_mtime_ns)
    if not original_untouched:
        issues.append("Historical SQLite file bytes or mtime changed during read-only inspection!")

    return {
        "present": True,
        "valid": len(issues) == 0,
        "path": str(sqlite_path),
        "size_bytes": size_bytes,
        "sha256": before_sha,
        "original_untouched": original_untouched,
        "integrity_check": integrity,
        "table_counts": table_counts,
        "warning_states": states,
        "distinct_scan_ids": scan_ids,
        "human_events_count": len(events_rows),
        "event_state_mismatches": event_state_mismatches,
        "source_hash_mismatches": source_hash_mismatches,
        "events": events_rows,
        "per_alert_summary": alert_audit_rows,
        "issues": issues,
    }


def verify_sqlite_review_lifecycle_on_temp_copy(
    sqlite_path: Path,
    source_root: Path,
) -> dict[str, Any]:
    """Execute isolated temp-copy tests for confirm-true, confirm-false, reopen, invalid state, and STALE_SOURCE."""
    from v2.triage.cli import main as triage_cli_main
    from v2.triage.evidence import EvidenceError
    from v2.triage.store import ReviewStore

    if not sqlite_path.is_file() or not source_root.is_dir():
        return {
            "passed": False,
            "issues": ["Missing sqlite_path or source_root for temp lifecycle verification"],
        }

    orig_db_sha = sha256_file(sqlite_path)
    orig_db_mtime = sqlite_path.stat().st_mtime_ns
    orig_src_shas = {
        p.relative_to(source_root).as_posix(): sha256_file(p)
        for p in sorted(source_root.rglob("*.java"))
    }

    issues: list[str] = []
    steps_detail: dict[str, Any] = {}

    def _run_cli(argv: list[str]) -> tuple[int, str, str]:
        out_buf, err_buf = io.StringIO(), io.StringIO()
        with redirect_stdout(out_buf), redirect_stderr(err_buf):
            code = triage_cli_main(argv)
        return code, out_buf.getvalue(), err_buf.getvalue()

    with tempfile.TemporaryDirectory(prefix="ntk_lifecycle_proof_") as tmpdir:
        tmp = Path(tmpdir)
        tmp_src = tmp / "sources"
        shutil.copytree(source_root, tmp_src)
        tmp_db = tmp / "review_copy.sqlite"
        shutil.copy2(sqlite_path, tmp_db)

        # Rewrite evidence.root ONLY inside tmp_db so ReviewStore checks tmp_src instead of historical sources
        conn = sqlite3.connect(str(tmp_db))
        try:
            rows = conn.execute("SELECT id, evidence FROM warnings ORDER BY rowid").fetchall()
            if not rows:
                return {"passed": False, "issues": ["No warnings in sqlite_path to test lifecycle"]}
            target_id = None
            target_rel_path = None
            for row_id, raw_ev in rows:
                ev_doc = json.loads(raw_ev)
                ev_doc["root"] = str(tmp_src)
                if target_id is None and not ev_doc.get("issues") and ev_doc.get("snapshots"):
                    prov = ev_doc.get("scan_provenance") or {}
                    if prov.get("source_capture_verified") is True:
                        target_id = str(row_id)
                        target_rel_path = next(iter(ev_doc["snapshots"].keys()))
                conn.execute(
                    "UPDATE warnings SET evidence=?, state='OPEN' WHERE id=?",
                    (json.dumps(ev_doc, ensure_ascii=False, sort_keys=True), row_id),
                )
            conn.execute("DELETE FROM events")
            conn.commit()
        finally:
            conn.close()

        if target_id is None or target_rel_path is None:
            return {
                "passed": False,
                "issues": ["No warning with verified scan_provenance and clean evidence found for confirm-false test"],
            }

        # 1. confirm-true
        c1, out1, err1 = _run_cli(
            [
                "decide",
                "--db",
                str(tmp_db),
                target_id,
                "confirm-true",
                "--actor",
                "forensic-auditor",
                "--reason",
                "Temp-copy verification of confirm-true transition",
            ]
        )
        d1 = json.loads(out1) if c1 == 0 and out1.strip() else {}
        c1_ok = c1 == 0 and d1.get("state") == "CONFIRMED_TRUE"
        steps_detail["confirm_true"] = {"exit_code": c1, "state": d1.get("state"), "passed": c1_ok}
        if not c1_ok:
            issues.append(f"confirm-true failed: exit={c1}, err={err1}")

        # 2. confirm-false on unmodified source
        c2, out2, err2 = _run_cli(
            [
                "decide",
                "--db",
                str(tmp_db),
                target_id,
                "confirm-false",
                "--actor",
                "forensic-auditor",
                "--reason",
                "Temp-copy verification of confirm-false on unchanged source",
            ]
        )
        d2 = json.loads(out2) if c2 == 0 and out2.strip() else {}
        _, q_default_out, _ = _run_cli(["queue", "--db", str(tmp_db)])
        _, q_all_out, _ = _run_cli(["queue", "--db", str(tmp_db), "--all"])
        q_default_ids = [w["id"] for w in json.loads(q_default_out)["warnings"]]
        q_all_ids = [w["id"] for w in json.loads(q_all_out)["warnings"]]
        c2_ok = (
            c2 == 0
            and d2.get("state") == "CONFIRMED_FALSE"
            and (target_id not in q_default_ids)
            and (target_id in q_all_ids)
        )
        steps_detail["confirm_false_unchanged_source"] = {
            "exit_code": c2,
            "state": d2.get("state"),
            "hidden_from_active_queue": target_id not in q_default_ids,
            "retained_in_audit_queue_all": target_id in q_all_ids,
            "passed": c2_ok,
        }
        if not c2_ok:
            issues.append(f"confirm-false failed: exit={c2}, err={err2}")

        # 3. reopen
        c3, out3, err3 = _run_cli(
            [
                "decide",
                "--db",
                str(tmp_db),
                target_id,
                "reopen",
                "--actor",
                "forensic-auditor",
                "--reason",
                "Temp-copy verification of reopen transition",
            ]
        )
        d3 = json.loads(out3) if c3 == 0 and out3.strip() else {}
        _, q_reopen_out, _ = _run_cli(["queue", "--db", str(tmp_db)])
        q_reopen_ids = [w["id"] for w in json.loads(q_reopen_out)["warnings"]]
        c3_ok = c3 == 0 and d3.get("state") == "OPEN" and (target_id in q_reopen_ids)
        steps_detail["reopen"] = {
            "exit_code": c3,
            "state": d3.get("state"),
            "restored_to_active_queue": target_id in q_reopen_ids,
            "passed": c3_ok,
        }
        if not c3_ok:
            issues.append(f"reopen failed: exit={c3}, err={err3}")

        # 4. Reject invalid state action & empty actor/reason
        store = ReviewStore(tmp_db)
        try:
            invalid_action_rejected = False
            try:
                store.decide(target_id, "invalid-state-transition", "forensic-auditor", "Should fail")
            except EvidenceError:
                invalid_action_rejected = True
        finally:
            store.close()
        c4_empty_actor, _, _ = _run_cli(
            ["decide", "--db", str(tmp_db), target_id, "confirm-false", "--actor", "   ", "--reason", "valid"]
        )
        c4_empty_reason, _, _ = _run_cli(
            ["decide", "--db", str(tmp_db), target_id, "confirm-false", "--actor", "auditor", "--reason", "   "]
        )
        c4_ok = invalid_action_rejected and c4_empty_actor == 2 and c4_empty_reason == 2
        steps_detail["invalid_state_and_actor_rejected"] = {
            "invalid_action_raised_evidence_error": invalid_action_rejected,
            "empty_actor_cli_exit_code": c4_empty_actor,
            "empty_reason_cli_exit_code": c4_empty_reason,
            "passed": c4_ok,
        }
        if not c4_ok:
            issues.append("Invalid action or empty actor/reason was not properly rejected")

        # 5. STALE_SOURCE check: mutate temporary Java source file, prove confirm-false is strictly blocked
        target_java = tmp_src / target_rel_path
        target_java.write_text(
            target_java.read_text(encoding="utf-8") + "\n// STALE_SOURCE mutation test in temp dir\n",
            encoding="utf-8",
        )
        c5_stale_cli, _, err5_stale = _run_cli(
            [
                "decide",
                "--db",
                str(tmp_db),
                target_id,
                "confirm-false",
                "--actor",
                "forensic-auditor",
                "--reason",
                "Attempt confirm-false after source mutation",
            ]
        )
        store = ReviewStore(tmp_db)
        try:
            stale_store_error = None
            try:
                store.decide(target_id, "confirm-false", "forensic-auditor", "Attempt confirm-false via API")
            except EvidenceError as exc:
                stale_store_error = str(exc)
            post_stale_state = store.get(target_id)["state"]
            full_history = store.history(target_id)
        finally:
            store.close()

        stale_ok = (
            c5_stale_cli == 2
            and ("rescan required" in err5_stale or "source hash mismatch" in err5_stale)
            and stale_store_error is not None
            and "rescan required" in stale_store_error
            and post_stale_state == "OPEN"
            and len(full_history) == 3
        )
        steps_detail["stale_source_blocks_confirm_false"] = {
            "diagnostic_status": "STALE_SOURCE",
            "mutated_temp_file": target_rel_path,
            "cli_exit_code": c5_stale_cli,
            "cli_stderr": err5_stale.strip(),
            "store_exception": stale_store_error,
            "state_after_blocked_confirm_false": post_stale_state,
            "events_recorded_before_block": len(full_history),
            "passed": stale_ok,
        }
        if not stale_ok:
            issues.append(
                f"STALE_SOURCE did not block confirm-false properly: cli_exit={c5_stale_cli}, state={post_stale_state}"
            )

    # Verify zero mutation on historical SQLite and historical Java sources
    after_db_sha = sha256_file(sqlite_path)
    after_db_mtime = sqlite_path.stat().st_mtime_ns
    after_src_shas = {
        p.relative_to(source_root).as_posix(): sha256_file(p)
        for p in sorted(source_root.rglob("*.java"))
    }
    originals_unchanged = (
        orig_db_sha == after_db_sha
        and orig_db_mtime == after_db_mtime
        and orig_src_shas == after_src_shas
    )
    if not originals_unchanged:
        issues.append("Original SQLite or Java source files changed during temp-copy lifecycle test!")

    return {
        "passed": len(issues) == 0,
        "tested_alert_id": target_id,
        "tested_source_rel_path": target_rel_path,
        "originals_unchanged_verified": originals_unchanged,
        "steps": steps_detail,
        "issues": issues,
    }


def scan_json_for_forbidden_label_keys(obj: Any, path_prefix: str = "") -> list[str]:
    """Recursively scan an evidence/prompt dict to verify ground_truth labels were never leaked."""
    forbidden_keys = {
        "ground_truth",
        "expected_label",
        "verified_ground_truth",
        "real_vulnerability",
        "expectedresults",
        "annotator_rationale",
        "annotated_by",
    }
    hits: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            key_lower = str(k).strip().lower()
            cur = f"{path_prefix}.{k}" if path_prefix else str(k)
            if key_lower in forbidden_keys:
                hits.append(cur)
            hits.extend(scan_json_for_forbidden_label_keys(v, cur))
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            hits.extend(scan_json_for_forbidden_label_keys(item, f"{path_prefix}[{idx}]"))
    return hits


def read_zip_member_sha256(zip_path: Path, member_suffix: str) -> dict[str, Any]:
    if not zip_path.is_file():
        return {"present": False}
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            if info.filename.replace("\\", "/").endswith(member_suffix):
                raw = zf.read(info.filename)
                return {
                    "present": True,
                    "member": info.filename,
                    "size_bytes": len(raw),
                    "sha256": sha256_bytes(raw),
                    "lf_sha256": sha256_lf_text(raw),
                }
    return {"present": False, "member_suffix": member_suffix}


def load_owasp_expected_csv(csv_path: Path) -> dict[str, dict[str, Any]]:
    """Parse OWASP Benchmark v1.2 expectedresults-1.2.csv keyed by testcase name."""
    mapping: dict[str, dict[str, Any]] = {}
    with csv_path.open("r", encoding="utf-8", newline="") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            row = next(csv.reader([line]))
            if len(row) < 4:
                continue
            name, category, real_vuln, cwe_num = (
                row[0].strip(),
                row[1].strip(),
                row[2].strip().lower(),
                row[3].strip(),
            )
            if name.lower().startswith("test name"):
                continue
            mapping[name] = {
                "test_name": name,
                "category": category,
                "real_vulnerability": real_vuln == "true",
                "expected_label": "TRUE_POSITIVE" if real_vuln == "true" else "FALSE_POSITIVE",
                "cwe": f"CWE-{int(cwe_num)}" if cwe_num.isdigit() else normalize_cwe(cwe_num),
            }
    return mapping
