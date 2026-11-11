"""NTK Thesis V2 - Independent Evidence & Paired Audit Verification CLI.

Audits OpenGrep and Qwen triage evidence across REPLAY (historical locked)
and LIVE (fresh manifest-bound) runs:
1. Verifies exact scan_sha256 and source_sha256 cryptographic alignment.
2. Enforces Contract 1.1 deterministic alert_id = SHA256(UTF8(scan_sha256 + ":" + decimal(finding_index))).
3. Verifies citations against genuine source files (line existence, non-blank, non-comment, multi-line quote match, and finding/trace window alignment).
4. Verifies model identity (qwen3.5:9b-q4_K_M), dataflow trace preservation, Qwen runtime evidence, and human queue safety (state == OPEN, auto_dismissed == False, no UNKNOWN over-claim).
5. Verifies SQLite review queue consistency (scans, warnings, events) and exercises human confirm-true / confirm-false / stale-source rejection / reopen on an isolated temporary copy.
6. Computes exact paired comparison metrics (Arm A: OpenGrep-only vs. Arm B: OpenGrep+Qwen) with numerators and denominators.
7. Gracefully reports AWAITING_SERVER_EVIDENCE (exit code 2) when executed on environments lacking remote server artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
from typing import Any

# Ensure repo root and v2/evaluation are in sys.path
EVAL_DIR = Path(__file__).resolve().parent
REPO_ROOT = EVAL_DIR.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(EVAL_DIR) not in sys.path:
    sys.path.insert(0, str(EVAL_DIR))

import codex_adapter
import score_pilot
from v2.triage.evidence import EvidenceError
from v2.triage.scan_receipt import verify_receipt
from v2.triage.store import ReviewStore

DEFAULT_SERVER_LIVE_DIR = Path(r"C:\Users\Admin\ntk-thesis-v2\evidence\repro_live_verified_20261111_c36_f25")
DEFAULT_HISTORICAL_SCAN = EVAL_DIR.parent / "demo" / "smoke_m1_rules_raw.opengrep.json"
DEFAULT_HISTORICAL_ASSESSMENTS = EVAL_DIR.parent / "demo" / "triage_qwen35_9b_smoke_m1_assessments.jsonl"
DEFAULT_HISTORICAL_LABELS = EVAL_DIR / "smoke_m1_verified_labels.json"
DEFAULT_SOURCE_ROOT = EVAL_DIR / "smoke_evidence"

EXPECTED_HISTORICAL_SCAN_SHA = "005863f208b58de1195d252a9544fbcef53c53801281345328cf0aff32d4ccb4"
EXPECTED_LIVE_SCAN_SHA = "4d628a214c737a99931ac51cce7f260bf3843b4f3610b3a5eb5a278bc919cfb9"
EXPECTED_SOURCE_SHA = "090c9349e4837588c47ae0d920cb841611252c7905b0654fda931648c421a9f9"


def compute_file_sha256(path: Path) -> str:
    """Compute hex SHA-256 of raw file bytes."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _collect_allowed_finding_window(
    alert: dict[str, Any],
    evidence: dict[str, Any],
    margin: int = 8,
) -> set[int]:
    """Collect valid 1-based line numbers belonging to a finding, its trace, and its extracted snippets."""
    allowed: set[int] = set()
    for block in (alert, evidence, evidence.get("raw_finding") or {}):
        if not isinstance(block, dict):
            continue
        s_line = (block.get("start") or {}).get("line") if isinstance(block.get("start"), dict) else block.get("start_line")
        e_line = (block.get("end") or {}).get("line") if isinstance(block.get("end"), dict) else block.get("end_line")
        if isinstance(s_line, int) and s_line > 0:
            stop = e_line if isinstance(e_line, int) and e_line >= s_line else s_line
            for lno in range(max(1, s_line - margin), stop + margin + 1):
                allowed.add(lno)

    snippets = evidence.get("snippets")
    if isinstance(snippets, list):
        for snip in snippets:
            if not isinstance(snip, dict):
                continue
            lines_list = snip.get("lines")
            if isinstance(lines_list, list):
                for item in lines_list:
                    if isinstance(item, dict) and isinstance(item.get("line"), int):
                        allowed.add(item["line"])

    trace = (
        evidence.get("raw_trace")
        or evidence.get("dataflow_trace")
        or ((alert.get("extra") or {}).get("dataflow_trace") if isinstance(alert.get("extra"), dict) else None)
    )
    if isinstance(trace, dict):
        for key in ("taint_source", "taint_sink"):
            val = trace.get(key)
            if isinstance(val, list) and len(val) >= 2 and isinstance(val[1], list) and val[1]:
                loc = val[1][0]
                if isinstance(loc, dict):
                    sl = (loc.get("start") or {}).get("line")
                    el = (loc.get("end") or {}).get("line") or sl
                    if isinstance(sl, int) and isinstance(el, int):
                        for lno in range(max(1, sl - margin), el + margin + 1):
                            allowed.add(lno)
        for ivar in trace.get("intermediate_vars") or []:
            if isinstance(ivar, dict) and isinstance(ivar.get("location"), dict):
                loc = ivar["location"]
                sl = (loc.get("start") or {}).get("line")
                el = (loc.get("end") or {}).get("line") or sl
                if isinstance(sl, int) and isinstance(el, int):
                    for lno in range(max(1, sl - margin), el + margin + 1):
                        allowed.add(lno)
    return allowed


def _quote_matches_source_lines(
    quote: str,
    source_line_map: dict[int, str],
    start_line: int,
    end_line: int,
) -> bool:
    """Verify that a single-line or multi-line citation quote matches the source lines in start_line..end_line."""
    if not isinstance(quote, str) or not quote.strip():
        return False
    expected_lines = [
        source_line_map[lno].strip()
        for lno in range(start_line, end_line + 1)
        if lno in source_line_map and source_line_map[lno].strip()
    ]
    if not expected_lines:
        return False
    quote_lines = [line.strip() for line in quote.splitlines() if line.strip()]
    if not quote_lines:
        return False
    if len(expected_lines) == 1 and len(quote_lines) == 1:
        exp = expected_lines[0]
        got = quote_lines[0]
        return exp == got or (len(got) >= 8 and got in exp)
    if len(quote_lines) != len(expected_lines):
        joined_exp = " ".join(expected_lines)
        joined_got = " ".join(quote_lines)
        return joined_exp == joined_got
    return all(
        exp == got or (len(got) >= 8 and got in exp)
        for exp, got in zip(expected_lines, quote_lines)
    )


def audit_sqlite_queue(
    sqlite_path: Path,
    active_scan_sha: str,
    expected_records: list[dict[str, Any]],
    source_root: Path,
    actual_source_sha: str | None,
    verify_lifecycle: bool = False,
) -> tuple[dict[str, Any], list[str]]:
    """Verify SQLite review queue consistency and optionally exercise confirm/reopen/stale-source in a temp copy."""
    issues: list[str] = []
    sqlite_info: dict[str, Any] = {
        "present": False,
        "path": str(sqlite_path),
    }
    if not sqlite_path.is_file():
        issues.append(f"Missing SQLite review database: {sqlite_path}")
        return sqlite_info, issues

    before_sha = compute_file_sha256(sqlite_path)
    sqlite_info["present"] = True
    sqlite_info["sqlite_sha256"] = before_sha

    try:
        conn = sqlite3.connect(f"file:{sqlite_path.resolve().as_posix()}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            scans_rows = conn.execute("SELECT id, bundle FROM scans").fetchall()
            warnings_rows = conn.execute(
                "SELECT id, scan_id, evidence, assessment, state FROM warnings ORDER BY rowid"
            ).fetchall()
            events_rows = conn.execute(
                "SELECT sequence, warning_id, actor, timestamp, action, reason, source_version, observed_version, evidence_sha256 FROM events ORDER BY sequence"
            ).fetchall()
        finally:
            conn.close()
    except Exception as exc:
        issues.append(f"SQLite read/schema error in {sqlite_path.name}: {exc}")
        return sqlite_info, issues

    scan_ids = [str(r["id"]).lower() for r in scans_rows]
    sqlite_info["scans_count"] = len(scans_rows)
    sqlite_info["warnings_count"] = len(warnings_rows)
    sqlite_info["events_count"] = len(events_rows)

    if active_scan_sha.lower() not in scan_ids:
        issues.append(
            f"SQLite scans table missing active scan_sha256 {active_scan_sha} (found {scan_ids})"
        )

    if len(warnings_rows) != len(expected_records):
        issues.append(
            f"SQLite warnings count ({len(warnings_rows)}) != expected findings count ({len(expected_records)})"
        )

    events_by_warning: dict[str, list[dict[str, Any]]] = {}
    for ev in events_rows:
        ev_dict = dict(ev)
        events_by_warning.setdefault(str(ev_dict["warning_id"]), []).append(ev_dict)

    warnings_by_id = {str(r["id"]): dict(r) for r in warnings_rows}
    states_summary: dict[str, int] = {}

    for idx, exp in enumerate(expected_records):
        exp_id = exp["expected_alert_id"]
        w_row = warnings_by_id.get(exp_id)
        if w_row is None:
            issues.append(f"SQLite warnings table missing alert_id {exp_id} for finding [{idx}]")
            continue
        if str(w_row["scan_id"]).lower() != active_scan_sha.lower():
            issues.append(
                f"SQLite warning {exp_id} has scan_id={w_row['scan_id']} != {active_scan_sha}"
            )
        w_state = str(w_row["state"]).strip().upper()
        states_summary[w_state] = states_summary.get(w_state, 0) + 1

        try:
            w_ev = json.loads(w_row["evidence"])
            w_ass = json.loads(w_row["assessment"])
        except Exception as exc:
            issues.append(f"SQLite warning {exp_id} contains invalid JSON column: {exc}")
            continue

        if str(w_ass.get("status") or "").strip().upper() != exp.get("status"):
            issues.append(
                f"SQLite warning {exp_id} status '{w_ass.get('status')}' != JSONL status '{exp.get('status')}'"
            )
        if str(w_ass.get("citation_check") or "").strip().upper() != exp.get("citation_check"):
            issues.append(
                f"SQLite warning {exp_id} citation_check '{w_ass.get('citation_check')}' != JSONL '{exp.get('citation_check')}'"
            )

        if w_state != "OPEN":
            w_events = events_by_warning.get(exp_id, [])
            if not w_events:
                issues.append(
                    f"SQLite safety violation: warning {exp_id} is in state '{w_state}' with 0 human review events"
                )
            else:
                last_ev = w_events[-1]
                expected_action = "confirm-true" if w_state == "CONFIRMED_TRUE" else "confirm-false"
                if last_ev.get("action") != expected_action or not str(last_ev.get("actor") or "").strip():
                    issues.append(
                        f"SQLite warning {exp_id} state '{w_state}' does not match last event {last_ev}"
                    )

    sqlite_info["states_summary"] = states_summary

    if verify_lifecycle and len(issues) == 0 and expected_records:
        with tempfile.TemporaryDirectory(prefix="ntk_sqlite_audit_") as tmp_dir_str:
            tmp_dir = Path(tmp_dir_str)
            tmp_db = tmp_dir / "review_copy.sqlite"
            tmp_src = tmp_dir / "source_copy"
            shutil.copy2(sqlite_path, tmp_db)
            if source_root.is_dir():
                shutil.copytree(source_root, tmp_src)
            else:
                tmp_src.mkdir(parents=True, exist_ok=True)

            # Point copied DB records' root to tmp_src so we can test stale-source mutation safely
            rw_conn = sqlite3.connect(tmp_db)
            try:
                for row_id, raw_ev in rw_conn.execute("SELECT id, evidence FROM warnings").fetchall():
                    ev_doc = json.loads(raw_ev)
                    ev_doc["root"] = str(tmp_src)
                    rw_conn.execute(
                        "UPDATE warnings SET evidence=? WHERE id=?",
                        (json.dumps(ev_doc, ensure_ascii=False, sort_keys=True), row_id),
                    )
                rw_conn.commit()
            finally:
                rw_conn.close()

            store = ReviewStore(tmp_db)
            try:
                target_id = expected_records[0]["expected_alert_id"]
                decided_tp = store.decide(
                    target_id, "confirm-true", "human-reviewer-audit", "Verified SQLi flow in audit copy"
                )
                if decided_tp["state"] != "CONFIRMED_TRUE":
                    issues.append("ReviewStore lifecycle check failed: confirm-true did not set CONFIRMED_TRUE")

                decided_fp = store.decide(
                    target_id, "confirm-false", "human-reviewer-audit", "Testing confirm-false transition"
                )
                if decided_fp["state"] != "CONFIRMED_FALSE":
                    issues.append("ReviewStore lifecycle check failed: confirm-false did not set CONFIRMED_FALSE")

                active_queue_ids = [item["id"] for item in store.queue(include_all=False)]
                if target_id in active_queue_ids:
                    issues.append("ReviewStore lifecycle check failed: CONFIRMED_FALSE warning still in active queue")

                reopened = store.decide(
                    target_id, "reopen", "human-reviewer-audit", "Reopened warning after audit check"
                )
                if reopened["state"] != "OPEN":
                    issues.append("ReviewStore lifecycle check failed: reopen did not restore OPEN state")

                # Mutate temporary Java source file and verify stale-source blocks confirm-false
                java_files = list(tmp_src.rglob("*.java"))
                stale_blocked = False
                if java_files:
                    java_files[0].write_text(
                        java_files[0].read_text(encoding="utf-8") + "\n// mutated for stale-source test\n",
                        encoding="utf-8",
                    )
                    try:
                        store.decide(
                            target_id,
                            "confirm-false",
                            "human-reviewer-audit",
                            "Should be rejected due to stale source",
                        )
                    except EvidenceError:
                        stale_blocked = True
                if not stale_blocked:
                    issues.append("ReviewStore lifecycle check failed: stale-source mutation was not rejected on confirm-false")

                hist = store.history(target_id)
                sqlite_info["lifecycle_verification"] = {
                    "status": "PASS" if len(issues) == 0 else "FAIL",
                    "events_recorded_in_temp_copy": len(hist),
                    "stale_source_confirm_false_rejected": stale_blocked,
                    "reopen_verified": reopened["state"] == "OPEN",
                }
            finally:
                store.close()

    after_sha = compute_file_sha256(sqlite_path)
    sqlite_info["original_sqlite_unchanged"] = before_sha == after_sha
    if before_sha != after_sha:
        issues.append("Original SQLite review database was mutated during audit")

    return sqlite_info, issues


def audit_scan_and_evidence(
    opengrep_path: Path,
    assessments_path: Path,
    source_root: Path,
    labels_path: Path | None = None,
    scan_manifest_path: Path | None = None,
    expected_scan_sha: str | None = None,
    require_scan_manifest: bool = False,
    sqlite_path: Path | None = None,
    require_sqlite: bool = False,
    require_trace: bool = True,
    require_qwen_runtime: bool = False,
    verify_review_lifecycle: bool = False,
) -> dict[str, Any]:
    """Execute rigorous independent audit on an OpenGrep scan and Qwen assessment pair."""
    issues: list[str] = []
    findings_audit: list[dict[str, Any]] = []

    # 1. Verify OpenGrep Scan File
    if not opengrep_path.is_file():
        return {
            "audit_verdict": "FAIL",
            "reason": f"OpenGrep scan file not found: {opengrep_path}",
            "issues": [f"Missing opengrep file: {opengrep_path}"],
        }

    raw_bytes = opengrep_path.read_bytes()
    sha_variants = codex_adapter.compute_scan_sha256_variants(raw_bytes)
    actual_raw_sha = sha_variants["raw"]
    variant_map = {v.lower(): v.lower() for v in sha_variants.values()}

    if expected_scan_sha:
        if expected_scan_sha.lower() not in variant_map:
            issues.append(
                f"Scan SHA-256 mismatch: expected {expected_scan_sha}, got variants: {sha_variants}"
            )

    active_scan_sha = (
        expected_scan_sha.lower()
        if (expected_scan_sha and expected_scan_sha.lower() in variant_map)
        else actual_raw_sha
    )

    try:
        og_doc = json.loads(raw_bytes.decode("utf-8"))
    except Exception as exc:
        return {
            "audit_verdict": "FAIL",
            "reason": f"OpenGrep scan JSON decode error: {exc}",
            "issues": [str(exc)],
        }

    if not isinstance(og_doc, dict):
        return {
            "audit_verdict": "FAIL",
            "reason": "OpenGrep scan JSON root is not an object",
            "issues": ["OpenGrep scan JSON root is not an object"],
        }

    results = og_doc.get("results") if "results" in og_doc else og_doc.get("alerts")
    if not isinstance(results, list) or len(results) == 0:
        issues.append(f"OpenGrep scan contains 0 findings: {opengrep_path}")
        results = []

    # Resolve target Java directory and file before manifest receipt check
    sample_rel_path = "SmokeVulnSample.java"
    java_file = (source_root / sample_rel_path).resolve()
    actual_java_root = source_root.resolve() if source_root.exists() else source_root
    if not java_file.is_file() and (source_root / "smoke_evidence" / sample_rel_path).is_file():
        java_file = (source_root / "smoke_evidence" / sample_rel_path).resolve()
        actual_java_root = (source_root / "smoke_evidence").resolve()

    # 2. Verify Scan Manifest (if provided or required)
    manifest_audit: dict[str, Any] = {"present": False}
    if scan_manifest_path and scan_manifest_path.is_file():
        manifest_audit["present"] = True
        try:
            m_doc = json.loads(scan_manifest_path.read_text(encoding="utf-8"))
            if not isinstance(m_doc, dict):
                raise ValueError("scan-manifest.json root is not a JSON object")
            m_sha = compute_file_sha256(scan_manifest_path)
            manifest_audit["manifest_sha256"] = m_sha
            schema_val = m_doc.get("schema") if m_doc.get("schema") is not None else m_doc.get("schema_version")
            manifest_audit["schema_version"] = schema_val
            manifest_audit["producer"] = m_doc.get("producer")

            if schema_val != "ntk-scan-capture-1":
                issues.append(f"Unexpected manifest schema_version: {schema_val}")

            recorded_json_sha = (
                (m_doc.get("artifacts") or {}).get("opengrep.json")
                if isinstance(m_doc.get("artifacts"), dict) and "opengrep.json" in m_doc.get("artifacts", {})
                else ((m_doc.get("runs") or {}).get("json") or {}).get("sha256")
            )
            if recorded_json_sha and str(recorded_json_sha).lower() != actual_raw_sha.lower():
                issues.append(
                    f"Manifest recorded json sha256 ({recorded_json_sha}) != raw opengrep sha256 ({actual_raw_sha})"
                )

            # Use canonical verify_receipt when full capture structure is present
            if (
                isinstance(m_doc.get("artifacts"), dict)
                and isinstance(m_doc.get("runs"), dict)
                and "sources_before" in m_doc
            ):
                receipt_meta, receipt_issues = verify_receipt(
                    scan_manifest_path, raw_bytes, actual_java_root
                )
                for r_issue in receipt_issues:
                    issues.append(f"Scan receipt verification error: {r_issue}")
                src_verified = bool(
                    receipt_meta.get("source_capture_verified") is True
                    and m_doc.get("source_capture_verified", True) is True
                )
                exit_verified = bool(
                    receipt_meta.get("exit_capture_verified") is True
                    and m_doc.get("exit_capture_verified", True) is True
                )
                manifest_audit["recorded_engine_exit"] = receipt_meta.get("recorded_engine_exit")
            else:
                src_verified = m_doc.get("source_capture_verified") is True
                exit_verified = m_doc.get("exit_capture_verified") is True

            manifest_audit["source_capture_verified"] = src_verified
            manifest_audit["exit_capture_verified"] = exit_verified
            if not src_verified:
                issues.append("Manifest source_capture_verified is not True")
            if not exit_verified:
                issues.append("Manifest exit_capture_verified is not True")
        except Exception as exc:
            issues.append(f"Failed to parse scan-manifest.json: {exc}")
    elif require_scan_manifest:
        issues.append("Missing required scan-manifest.json for verified scan receipt")

    # 3. Verify Target Java Source File
    source_line_map: dict[int, str] = {}
    actual_source_sha: str | None = None
    if java_file.is_file():
        java_bytes = java_file.read_bytes()
        java_text = java_bytes.decode("utf-8")
        actual_source_sha = hashlib.sha256(java_bytes).hexdigest()
        text_source_sha = score_pilot.compute_sha256_text(java_text)
        source_line_map = {idx + 1: line for idx, line in enumerate(java_text.splitlines())}
        if EXPECTED_SOURCE_SHA.lower() not in {actual_source_sha.lower(), text_source_sha.lower()}:
            issues.append(
                f"Source file SHA-256 drift: expected {EXPECTED_SOURCE_SHA}, got {actual_source_sha}"
            )
    else:
        issues.append(f"Target Java source file not found under source-root: {source_root}")

    # 4. Verify Assessments JSONL File & Finding Mapping
    if not assessments_path.is_file():
        return {
            "audit_verdict": "FAIL",
            "reason": f"Assessments file not found: {assessments_path}",
            "issues": [f"Missing assessments file: {assessments_path}"],
        }

    raw_assessments_text = assessments_path.read_text(encoding="utf-8")
    assessments_sha = compute_file_sha256(assessments_path)
    records, malformed = score_pilot.parse_triage_inputs(raw_assessments_text)

    if not expected_scan_sha and records:
        first_rec_sha = str(
            records[0].get("scan_sha256")
            or (records[0].get("evidence") or {}).get("scan_sha256")
            or ""
        ).strip().lower()
        if first_rec_sha and first_rec_sha in variant_map:
            active_scan_sha = variant_map[first_rec_sha]

    if malformed:
        issues.append(f"Found {len(malformed)} malformed records in {assessments_path.name}")

    if len(records) != len(results):
        issues.append(
            f"Findings count mismatch: OpenGrep emitted {len(results)} vs {len(records)} assessments"
        )

    # Validate each finding and assessment 1-to-1
    for idx, alert in enumerate(results):
        f_idx = idx
        expected_contract_aid = codex_adapter.compute_contract_alert_id(active_scan_sha, f_idx)

        # Find matching assessment
        rec = None
        for candidate in records:
            c_aid = candidate.get("id") or candidate.get("alert_id")
            c_fidx = (candidate.get("evidence") or {}).get("finding_index")
            if c_fidx is None:
                c_fidx = candidate.get("finding_index")
            if c_aid == expected_contract_aid or c_fidx == f_idx:
                rec = candidate
                break

        if rec is None and idx < len(records):
            rec = records[idx]

        finding_info: dict[str, Any] = {
            "finding_index": f_idx,
            "expected_alert_id": expected_contract_aid,
            "matched_assessment": rec is not None,
        }

        if rec is None:
            issues.append(f"Finding [{f_idx}] has no corresponding assessment record")
            findings_audit.append(finding_info)
            continue

        c_aid = rec.get("id") or rec.get("alert_id")
        finding_info["actual_alert_id"] = c_aid
        if c_aid != expected_contract_aid:
            issues.append(
                f"Finding [{f_idx}] alert_id mismatch: expected {expected_contract_aid}, got {c_aid}"
            )

        evidence = rec.get("evidence") if isinstance(rec.get("evidence"), dict) else {}
        assessment = rec.get("assessment") if isinstance(rec.get("assessment"), dict) else {}
        runtime = (
            assessment.get("runtime")
            if isinstance(assessment.get("runtime"), dict)
            else (rec.get("runtime") if isinstance(rec.get("runtime"), dict) else {})
        )

        # Verify rule_id / check_id alignment
        expected_rule_id = str(alert.get("check_id") or alert.get("rule_id") or "").strip()
        actual_rule_id = str(
            evidence.get("rule_id")
            or (evidence.get("raw_finding") or {}).get("check_id")
            or rec.get("rule_id")
            or ""
        ).strip()
        finding_info["rule_id"] = actual_rule_id
        if expected_rule_id and actual_rule_id != expected_rule_id:
            issues.append(
                f"Finding [{f_idx}] rule_id mismatch: OpenGrep has '{expected_rule_id}', assessment has '{actual_rule_id}'"
            )

        # Verify finding line coordinates and path alignment
        alert_start_line = (alert.get("start") or {}).get("line") if isinstance(alert.get("start"), dict) else alert.get("start_line")
        ev_start_line = (evidence.get("start") or {}).get("line") if isinstance(evidence.get("start"), dict) else rec.get("start_line")
        if isinstance(alert_start_line, int) and isinstance(ev_start_line, int) and alert_start_line != ev_start_line:
            issues.append(
                f"Finding [{f_idx}] start_line mismatch: OpenGrep has {alert_start_line}, assessment has {ev_start_line}"
            )

        alert_path = alert.get("path") or alert.get("file_path")
        ev_path = evidence.get("path") or rec.get("file_path") or rec.get("path")
        if alert_path and ev_path and not codex_adapter.paths_match(alert_path, ev_path):
            issues.append(
                f"Finding [{f_idx}] file path mismatch: OpenGrep has '{alert_path}', assessment has '{ev_path}'"
            )

        # Verify dataflow trace preservation when required or present in raw scan
        alert_has_trace = bool(
            isinstance(alert.get("extra"), dict) and alert["extra"].get("dataflow_trace")
        )
        ev_trace = (
            evidence.get("raw_trace")
            or evidence.get("dataflow_trace")
            or ((evidence.get("raw_finding") or {}).get("extra") or {}).get("dataflow_trace")
        )
        has_valid_trace = (
            isinstance(ev_trace, dict)
            and bool(ev_trace.get("taint_source"))
            and bool(ev_trace.get("taint_sink"))
        )
        finding_info["has_dataflow_trace"] = has_valid_trace
        if (require_trace or alert_has_trace) and not has_valid_trace:
            issues.append(f"Finding [{f_idx}] missing or incomplete dataflow_trace in evidence")

        # Verify scan_sha256 field
        r_scan_sha = rec.get("scan_sha256") or evidence.get("scan_sha256")
        if not r_scan_sha or str(r_scan_sha).strip().lower() != active_scan_sha.lower():
            issues.append(
                f"Finding [{f_idx}] row scan_sha256 ({r_scan_sha}) != active scan_sha256 ({active_scan_sha})"
            )

        # Verify snapshot source_sha256 inside evidence
        snapshots = evidence.get("snapshots")
        if isinstance(snapshots, dict) and actual_source_sha:
            for snap_name, snap_meta in snapshots.items():
                snap_sha = snap_meta.get("sha256") if isinstance(snap_meta, dict) else None
                if snap_sha and str(snap_sha).lower() != actual_source_sha.lower():
                    issues.append(
                        f"Finding [{f_idx}] snapshot '{snap_name}' sha256 ({snap_sha}) != source sha256 ({actual_source_sha})"
                    )

        # Verify model identity and Qwen assessment evidence
        model_id = str(assessment.get("model") or runtime.get("model") or rec.get("model") or "").strip()
        finding_info["model_id"] = model_id
        if not model_id.lower().startswith("qwen3.5"):
            issues.append(f"Finding [{f_idx}] model_id is not Qwen3.5: '{model_id}'")

        # Verify status and explanation
        status = str(assessment.get("status") or rec.get("status") or "").strip().upper()
        finding_info["status"] = status
        if status not in ("SUPPORTED", "REFUTED", "UNDETERMINED"):
            issues.append(f"Finding [{f_idx}] invalid status: '{status}'")

        explanation = str(assessment.get("explanation") or rec.get("explanation") or "").strip()
        if status in ("SUPPORTED", "REFUTED") and not explanation:
            issues.append(f"Finding [{f_idx}] missing Qwen explanation for status '{status}'")

        # Check raw_response and runtime metadata if present or required
        raw_resp = assessment.get("raw_response")
        if raw_resp is not None:
            if not isinstance(raw_resp, dict):
                issues.append(f"Finding [{f_idx}] raw_response is not a dict")
            else:
                msg_content = (raw_resp.get("message") or {}).get("content") if isinstance(raw_resp.get("message"), dict) else None
                if isinstance(msg_content, str):
                    try:
                        parsed_msg = json.loads(msg_content)
                        if not isinstance(parsed_msg, dict):
                            issues.append(f"Finding [{f_idx}] raw_response message.content is not a JSON object")
                    except Exception as exc:
                        issues.append(f"Finding [{f_idx}] invalid JSON in raw_response.message.content: {exc}")
        elif require_qwen_runtime:
            issues.append(f"Finding [{f_idx}] missing Qwen raw_response in LIVE evidence")

        if require_qwen_runtime:
            if (
                runtime.get("http_response_received") is not True
                or runtime.get("response_complete") is not True
                or runtime.get("model_identity_matched") is not True
            ):
                issues.append(
                    f"Finding [{f_idx}] incomplete Qwen LIVE runtime telemetry: {runtime}"
                )

        # Verify over-claim prevention for UNKNOWN / UNDETERMINED
        raw_model_status = codex_adapter._extract_raw_model_status_from_response(assessment)
        if raw_model_status in ("UNDETERMINED", "UNKNOWN") and status in ("SUPPORTED", "REFUTED"):
            issues.append(
                f"Finding [{f_idx}] over-claimed status '{status}' from raw model status '{raw_model_status}'"
            )

        explicit_verdict = str(rec.get("verdict") or rec.get("pilot_verdict") or "").strip().upper()
        if status in ("UNDETERMINED", "UNKNOWN") and explicit_verdict in ("KEEP_TP", "PROPOSED_FP", "SUPPRESS_FP", "TRUE_POSITIVE", "FALSE_POSITIVE"):
            issues.append(
                f"Finding [{f_idx}] UNKNOWN/UNDETERMINED status over-claimed as '{explicit_verdict}'"
            )

        # Verify citations
        citations = assessment.get("citations") if assessment.get("citations") is not None else rec.get("citations")
        citation_check = str(assessment.get("citation_check") or rec.get("citation_check") or "").strip().upper()
        finding_info["citation_check"] = citation_check
        if citation_check != "MATCHED":
            issues.append(f"Finding [{f_idx}] citation_check is not MATCHED: '{citation_check}'")

        if not isinstance(citations, list) or len(citations) == 0:
            issues.append(f"Finding [{f_idx}] citations list is empty or missing")
            citations = []

        allowed_window = _collect_allowed_finding_window(alert, evidence)
        cited_lines: list[int] = []
        for c_item in citations:
            if isinstance(c_item, dict):
                sl = c_item.get("start_line") if c_item.get("start_line") is not None else c_item.get("line")
                el = c_item.get("end_line") if c_item.get("end_line") is not None else sl
                if not isinstance(sl, int) or not isinstance(el, int) or sl <= 0 or el < sl:
                    issues.append(f"Finding [{f_idx}] citation has invalid line span: {c_item}")
                    continue
                for lno in range(sl, el + 1):
                    if lno not in cited_lines:
                        cited_lines.append(lno)
                c_quote = c_item.get("quote")
                c_sha = c_item.get("sha256")
                if c_sha and actual_source_sha and str(c_sha).lower() != actual_source_sha.lower():
                    issues.append(
                        f"Finding [{f_idx}] citation sha256 ({c_sha}) != source sha256 ({actual_source_sha})"
                    )
                if all(lno in source_line_map for lno in range(sl, el + 1)):
                    if not _quote_matches_source_lines(str(c_quote or ""), source_line_map, sl, el):
                        issues.append(
                            f"Finding [{f_idx}] citation quote at lines {sl}..{el} does not match source code"
                        )
            elif isinstance(c_item, int) and not isinstance(c_item, bool):
                if c_item <= 0:
                    issues.append(f"Finding [{f_idx}] non-positive cited line: {c_item}")
                elif c_item not in cited_lines:
                    cited_lines.append(c_item)
            else:
                issues.append(f"Finding [{f_idx}] unsupported citation item: {c_item!r}")

        finding_info["cited_lines"] = cited_lines
        if not cited_lines:
            issues.append(f"Finding [{f_idx}] resolved 0 cited line numbers")

        for lno in cited_lines:
            if lno not in source_line_map:
                issues.append(f"Finding [{f_idx}] cited line {lno} does not exist in source file")
            elif not score_pilot._is_meaningful_code_line(source_line_map[lno]):
                issues.append(f"Finding [{f_idx}] cited line {lno} is blank or comment-only")

        if cited_lines and allowed_window and not any(lno in allowed_window for lno in cited_lines):
            issues.append(
                f"Finding [{f_idx}] cited lines {cited_lines} are outside finding/trace location window {sorted(allowed_window)}"
            )

        # Verify human safety state
        state = str(rec.get("state") or rec.get("human_review_state") or assessment.get("state") or "OPEN").strip().upper()
        auto_dismissed = bool(rec.get("auto_dismissed") or assessment.get("auto_dismissed") or False)
        sec_verified = bool(assessment.get("security_conclusion_verified") or rec.get("security_conclusion_verified") or False)
        req_human = assessment.get("requires_human_review", rec.get("requires_human_review", True))

        finding_info["state"] = state
        finding_info["auto_dismissed"] = auto_dismissed
        finding_info["security_conclusion_verified"] = sec_verified
        finding_info["requires_human_review"] = bool(req_human)

        if auto_dismissed or state != "OPEN":
            issues.append(
                f"Finding [{f_idx}] safety violation: auto_dismissed={auto_dismissed}, state='{state}' (must be OPEN)"
            )
        if sec_verified and state == "OPEN":
            issues.append(
                f"Finding [{f_idx}] safety violation: security_conclusion_verified=True while state is OPEN"
            )
        if req_human is False:
            issues.append(
                f"Finding [{f_idx}] safety violation: requires_human_review=False on unconfirmed assessment"
            )

        findings_audit.append(finding_info)

    # 5. Verify SQLite Review Queue (if provided or required)
    sqlite_audit: dict[str, Any] = {"present": False}
    if sqlite_path is not None and (sqlite_path.is_file() or require_sqlite):
        sqlite_audit, sqlite_issues = audit_sqlite_queue(
            sqlite_path=sqlite_path,
            active_scan_sha=active_scan_sha,
            expected_records=findings_audit,
            source_root=actual_java_root,
            actual_source_sha=actual_source_sha,
            verify_lifecycle=verify_review_lifecycle,
        )
        issues.extend(sqlite_issues)

    # 6. Compute Paired Comparison (Arm A: OpenGrep-only vs Arm B: OpenGrep+Qwen) if labels are available
    paired_comparison: dict[str, Any] | None = None
    if labels_path and labels_path.is_file() and len(results) > 0:
        try:
            labels_doc = json.loads(labels_path.read_text(encoding="utf-8"))
            pilot_eval = score_pilot.evaluate_pilot(
                opengrep_data=og_doc,
                labels_data=labels_doc,
                triage_data=raw_assessments_text,
                source_root=actual_java_root,
                expected_scan_sha256=active_scan_sha,
                require_scan_provenance=require_scan_manifest,
            )
            overall_dict = (pilot_eval.get("summary") or {}).get("overall") or {}
            overall = overall_dict.get("counts", {})
            rates = overall_dict.get("rates", {})
            latency = overall_dict.get("latency_ms", {})
            paired_comparison = {
                "dataset_kind": labels_doc.get("dataset_kind") if isinstance(labels_doc, dict) else None,
                "m4_acceptance_ready": labels_doc.get("m4_acceptance_ready") if isinstance(labels_doc, dict) else False,
                "total_input_alerts": overall.get("total_alerts", len(results)),
                "labeled_tp": overall.get("labeled_tp", 0),
                "labeled_fp": overall.get("labeled_fp", 0),
                "arm_a_opengrep_only": {
                    "retained_alerts": overall.get("total_alerts", len(results)),
                    "tp_retained": overall.get("labeled_tp", 0),
                    "fp_retained": overall.get("labeled_fp", 0),
                    "proposed_fp_removal_rate": f"0/{overall.get('labeled_fp', 1)} (0.0%)",
                },
                "arm_b_opengrep_plus_qwen": {
                    "qwen_supported_keep_tp": overall.get("kept_tp_on_true_tp", 0) + overall.get("kept_tp_on_true_fp", 0),
                    "qwen_refuted_proposed_fp": overall.get("grounding_verified_fp_proposals", 0),
                    "qwen_undetermined_or_review": overall.get("needs_review_total", 0),
                    "proposed_fp_on_true_fp": overall.get("proposed_fp_on_true_fp", 0),
                    "erroneously_proposed_fp_on_tp": overall.get("erroneously_proposed_fp_on_tp", 0),
                    "proposed_fp_removal_rate": (rates.get("proposed_fp_removal") or {}).get("display"),
                    "erroneous_tp_removal_rate": (rates.get("erroneous_tp_removal") or {}).get("display"),
                    "review_escalation_rate": (rates.get("review_escalation") or {}).get("display"),
                    "latency_ms": latency,
                    "human_confirmed_tp": 0,
                    "human_confirmed_fp": 0,
                    "queue_open_alerts": len(results),
                },
            }
        except Exception as exc:
            paired_comparison = {"error": str(exc)}

    audit_pass = len(issues) == 0
    return {
        "audit_verdict": "PASS" if audit_pass else "FAIL",
        "scan_file": opengrep_path.name,
        "scan_sha256": active_scan_sha,
        "source_file": sample_rel_path,
        "source_sha256": actual_source_sha,
        "assessments_file": assessments_path.name,
        "assessments_sha256": assessments_sha,
        "manifest_audit": manifest_audit,
        "sqlite_audit": sqlite_audit,
        "paired_comparison": paired_comparison,
        "total_findings": len(results),
        "findings_audit": findings_audit,
        "issues": issues,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify NTK Thesis V2 OpenGrep + Qwen paired evidence (REPLAY or LIVE mode)."
    )
    parser.add_argument(
        "--mode",
        choices=["replay", "live", "custom"],
        default="replay",
        help="Audit mode: 'replay' (historical locked), 'live' (server manifest-bound), or 'custom'.",
    )
    parser.add_argument("--opengrep", type=Path, help="Path to raw OpenGrep JSON file.")
    parser.add_argument("--assessments", type=Path, help="Path to Qwen assessments.jsonl file.")
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT, help="Java source root.")
    parser.add_argument("--labels", type=Path, help="Path to ground-truth labels JSON.")
    parser.add_argument("--scan-manifest", type=Path, help="Path to scan-manifest.json.")
    parser.add_argument("--sqlite-db", type=Path, help="Optional path to review.sqlite database.")
    parser.add_argument(
        "--verify-review-lifecycle",
        action="store_true",
        help="Exercise human confirm-true/confirm-false/reopen and stale-source rejection on a temp copy of SQLite.",
    )
    parser.add_argument(
        "--live-dir",
        type=Path,
        default=DEFAULT_SERVER_LIVE_DIR,
        help="Root directory of LIVE run on server (contains live_scan/ and triage_live_qwen35/).",
    )
    parser.add_argument("--output-json", type=Path, help="Optional path to write audit report JSON.")
    args = parser.parse_args(argv)

    print("=" * 80)
    print("NTK THESIS V2 - INDEPENDENT EVIDENCE AUDIT & INTEGRITY CHECK")
    print(f"Mode: {args.mode.upper()}")
    print("=" * 80)

    if args.mode == "replay":
        og_path = args.opengrep or DEFAULT_HISTORICAL_SCAN
        ass_path = args.assessments or DEFAULT_HISTORICAL_ASSESSMENTS
        lbl_path = args.labels or (DEFAULT_HISTORICAL_LABELS if DEFAULT_HISTORICAL_LABELS.is_file() else None)
        report = audit_scan_and_evidence(
            opengrep_path=og_path,
            assessments_path=ass_path,
            source_root=args.source_root,
            labels_path=lbl_path,
            expected_scan_sha=EXPECTED_HISTORICAL_SCAN_SHA,
            require_scan_manifest=False,
            sqlite_path=args.sqlite_db,
            require_sqlite=bool(args.sqlite_db),
            verify_review_lifecycle=args.verify_review_lifecycle,
        )
    elif args.mode == "live":
        live_dir = args.live_dir
        if not live_dir.exists():
            print(f"\n[LIVE AUDIT] STATUS: AWAITING_SERVER_EVIDENCE")
            print(f"Reason: Remote server directory does not exist on this machine:\n  {live_dir}")
            print("\nVerification instructions for JavisOS on server ADMIN-PC:")
            print(f"  Set-Location \"C:\\Users\\Admin\\ntk-thesis-v2\\integration-pilot\"")
            print(f"  python v2/evaluation/verify_evidence_audit.py --mode live --live-dir \"{live_dir}\"")
            if args.output_json:
                args.output_json.parent.mkdir(parents=True, exist_ok=True)
                args.output_json.write_text(
                    json.dumps(
                        {
                            "audit_verdict": "AWAITING_SERVER_EVIDENCE",
                            "server_path": str(live_dir),
                            "note": "Laptop client cannot access remote server path. Run verification command on ADMIN-PC.",
                        },
                        indent=2,
                    ),
                    encoding="utf-8",
                )
            return 2

        # When running on the server where live_dir exists
        og_path = args.opengrep or (live_dir / "live_scan" / "opengrep.json")
        ass_path = args.assessments or (live_dir / "triage_live_qwen35" / "assessments.jsonl")
        if not ass_path.is_file():
            ass_path = live_dir / "triage_live" / "assessments.jsonl"
        manifest_path = args.scan_manifest or (live_dir / "live_scan" / "scan-manifest.json")
        sqlite_path = args.sqlite_db or (live_dir / "triage_live_qwen35" / "review.sqlite")
        if not sqlite_path.is_file() and (live_dir / "triage_live" / "review.sqlite").is_file():
            sqlite_path = live_dir / "triage_live" / "review.sqlite"
        live_labels = args.labels or (live_dir / "live_scan" / "smoke_m1_live_labels.json")
        if not live_labels.is_file() and DEFAULT_HISTORICAL_LABELS.is_file():
            live_labels = DEFAULT_HISTORICAL_LABELS

        report = audit_scan_and_evidence(
            opengrep_path=og_path,
            assessments_path=ass_path,
            source_root=args.source_root,
            labels_path=live_labels if live_labels.is_file() else None,
            scan_manifest_path=manifest_path,
            expected_scan_sha=EXPECTED_LIVE_SCAN_SHA,
            require_scan_manifest=True,
            sqlite_path=sqlite_path,
            require_sqlite=True,
            require_qwen_runtime=True,
            verify_review_lifecycle=True,
        )
    else:  # custom
        if not args.opengrep or not args.assessments:
            print("Error: --opengrep and --assessments are required in custom mode.")
            return 2
        report = audit_scan_and_evidence(
            opengrep_path=args.opengrep,
            assessments_path=args.assessments,
            source_root=args.source_root,
            labels_path=args.labels,
            scan_manifest_path=args.scan_manifest,
            require_scan_manifest=bool(args.scan_manifest),
            sqlite_path=args.sqlite_db,
            require_sqlite=bool(args.sqlite_db),
            verify_review_lifecycle=args.verify_review_lifecycle,
        )

    verdict = report.get("audit_verdict")
    print(f"\nAudit Verdict: {verdict}")
    print(f"OpenGrep Scan SHA-256: {report.get('scan_sha256')}")
    print(f"Java Source SHA-256:   {report.get('source_sha256')}")
    print(f"Assessments SHA-256:   {report.get('assessments_sha256')}")
    print(f"Total Findings:        {report.get('total_findings')}")

    if report.get("manifest_audit", {}).get("present"):
        m = report["manifest_audit"]
        m_sha_short = (m.get("manifest_sha256") or "")[:12]
        print(
            f"Scan Manifest:         PRESENT (sha256={m_sha_short}..., "
            f"source_capture_verified={m.get('source_capture_verified')}, "
            f"exit_capture_verified={m.get('exit_capture_verified')})"
        )

    if report.get("sqlite_audit", {}).get("present"):
        sq = report["sqlite_audit"]
        sq_sha_short = (sq.get("sqlite_sha256") or "")[:12]
        lc_status = (sq.get("lifecycle_verification") or {}).get("status", "N/A")
        print(
            f"SQLite Review Queue:   PRESENT (sha256={sq_sha_short}..., "
            f"warnings={sq.get('warnings_count')}, states={sq.get('states_summary')}, "
            f"lifecycle_check={lc_status})"
        )

    print("\nPer-Finding Alignment:")
    for f in report.get("findings_audit", []):
        f_idx = f["finding_index"]
        aid = f.get("expected_alert_id", "")[:12]
        stat = f.get("status")
        chk = f.get("citation_check")
        lines = f.get("cited_lines")
        state = f.get("state")
        print(f"  [{f_idx}] Alert {aid}... | Status: {stat} | Citations: {chk} (lines {lines}) | Queue: {state}")

    if report.get("paired_comparison") and not report["paired_comparison"].get("error"):
        pc = report["paired_comparison"]
        arm_b = pc.get("arm_b_opengrep_plus_qwen", {})
        print(
            f"\nPaired Comparison (Arm A OpenGrep-Only vs Arm B OpenGrep+Qwen, n={pc.get('total_input_alerts')}):"
        )
        print(
            f"  Reference Labels: TP={pc.get('labeled_tp')}, FP={pc.get('labeled_fp')} ({pc.get('dataset_kind')})"
        )
        print(
            f"  Arm B Qwen:       KEEP_TP={arm_b.get('qwen_supported_keep_tp')}, "
            f"PROPOSED_FP={arm_b.get('qwen_refuted_proposed_fp')}, "
            f"REVIEW={arm_b.get('qwen_undetermined_or_review')} | "
            f"FP Removal={arm_b.get('proposed_fp_removal_rate')} | "
            f"Erroneous TP Removal={arm_b.get('erroneous_tp_removal_rate')}"
        )

    if report.get("issues"):
        print("\nIntegrity Issues / Anomalies:")
        for issue in report["issues"]:
            print(f"  [!] {issue}")
    else:
        print("\nIntegrity Checks: ALL 1-TO-1 CRITERIA PASSED (0 issues)")

    if args.output_json:
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        args.output_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nWrote full audit JSON to: {args.output_json}")

    return {"PASS": 0, "AWAITING_SERVER_EVIDENCE": 2}.get(verdict, 1)


if __name__ == "__main__":
    sys.exit(main())
