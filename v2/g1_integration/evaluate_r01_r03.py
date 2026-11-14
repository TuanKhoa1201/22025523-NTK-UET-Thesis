"""Read-only R01-R03 runtime acceptance evaluator for G1.

Evaluates fresh run directories against `G1_C3_REGRESSION_CRITERIA.md` (R01, R02, R03)
and `G1_C3_R01_R03_CHECKLIST.json` without mutating any scenario directory or opening
SQLite in read-write mode (`?mode=ro` URI only; never instantiates `ReviewStore`).

Never infers R01 PASS from CLI exit code `0`, HTTP `200`, `ALL_HTTP_COMPLETED`, or
`OLLAMA_REPORTED_UNATTESTED` alone.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sqlite3
from typing import Any

from v2.g1_audit import contracts
from v2.triage import live_check
from v2.triage.evidence import EvidenceError, digest, strict_json
from v2.triage.ollama import (
    PROMPT_CONTRACT_BLIND,
    PROMPT_VERSION,
    assert_prompt_contract,
    inspect_citations_provenance,
    validate_answer,
)
from v2.triage.verify_http_capture import _safe_id, verify_run_http_captures


def _open_sqlite_ro(db_path: Path) -> sqlite3.Connection:
    resolved = Path(db_path).resolve(strict=True)
    uri = f"{resolved.as_uri()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _read_sqlite_state_ro(db_path: Path) -> dict[str, Any]:
    conn = _open_sqlite_ro(db_path)
    try:
        scans = [dict(r) for r in conn.execute("SELECT id, bundle FROM scans ORDER BY rowid")]
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
                "FROM events ORDER BY sequence"
            )
        ]
        rejected = [
            dict(r)
            for r in conn.execute(
                "SELECT sequence, warning_id, actor, timestamp, attempted_action, reason, rejection_code, source_version, observed_version, detail "
                "FROM rejected_decisions ORDER BY sequence"
            )
        ]
        return {
            "db_sha256": digest(Path(db_path).read_bytes()),
            "scans_count": len(scans),
            "scan_ids": [s["id"] for s in scans],
            "warnings": warnings,
            "events": events,
            "rejected_decisions": rejected,
        }
    finally:
        conn.close()


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
) -> dict[str, Any]:
    scenario_dir = Path(scenario_dir).resolve()
    failures: list[str] = []
    blockers: list[str] = []

    if not scenario_dir.is_dir():
        return {
            "scenario": scenario_name,
            "status": "BLOCKED",
            "blockers": [f"missing scenario directory: {scenario_dir}"],
            "failures": [],
        }

    manifest_path = scenario_dir / "g1-run-manifest.json"
    capture_dir = scenario_dir / "capture"
    triage_dir = scenario_dir / "triage"
    if not manifest_path.is_file() or not capture_dir.is_dir() or not triage_dir.is_dir():
        return {
            "scenario": scenario_name,
            "status": "BLOCKED",
            "blockers": [f"{scenario_name}: missing g1-run-manifest.json, capture/, or triage/"],
            "failures": [],
        }

    manifest = strict_json(manifest_path.read_text(encoding="utf-8"))
    evidence_bundle = strict_json((triage_dir / "evidence.json").read_text(encoding="utf-8"))
    rows = [
        strict_json(line)
        for line in (triage_dir / "assessments.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

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
    r02_errors: list[str] = []
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
    if not raw_json_path.is_file() or not raw_sarif_path.is_file():
        r02_errors.append(f"{scenario_name}: missing capture/opengrep.json or opengrep.sarif")
    else:
        raw_bytes = raw_json_path.read_bytes()
        if triage_input_path.is_file() and triage_input_path.read_bytes() != raw_bytes:
            r02_errors.append(f"{scenario_name}: triage/input.opengrep.json differs from capture/opengrep.json")
        try:
            raw_doc = contracts.strict(raw_bytes.decode("utf-8"))
            sarif_doc = contracts.strict(raw_sarif_path.read_bytes().decode("utf-8"))
            contracts.validate_bundle(raw_bytes, raw_doc, evidence_bundle)
            contracts.validate_rows(rows, evidence_bundle)
            contracts.compare_sarif(raw_doc, sarif_doc)
        except (ValueError, KeyError, TypeError, UnicodeError) as exc:
            r02_errors.append(f"{scenario_name}: independent contract/SARIF validation failed: {exc}")

    for child_label in ("version", "json", "sarif"):
        for ext in (".command.json", ".exit.txt", ".stdout.txt", ".stderr.txt"):
            if not (capture_dir / f"{child_label}{ext}").is_file():
                r02_errors.append(f"{scenario_name}: missing scanner child artifact {child_label}{ext}")

    # Per-finding R01 prompt, raw body replay, validator & canonical citation checks
    per_finding_details: list[dict[str, Any]] = []
    records = evidence_bundle.get("records") or []
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
        if not prompt_file.is_file():
            f_errors.append(f"missing {safe_id}.prompt.json")
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
        replayed_answer = None
        if resp_bin.is_file():
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
            blockers.append(f"{scenario_name}[{idx}]: missing {safe_id}.response.body.bin")

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

    # Pre-lifecycle SQLite snapshot check (if present)
    pre_db = triage_dir / "review.post_ingestion.sqlite"
    ing_db_state = None
    if pre_db.is_file():
        ing_db_state = _read_sqlite_state_ro(pre_db)
        if len(ing_db_state["warnings"]) != expected_findings or any(w["state"] != "OPEN" for w in ing_db_state["warnings"]):
            failures.append(f"{scenario_name}: review.post_ingestion.sqlite does not hold {expected_findings} OPEN warning(s)")
        if ing_db_state["events"]:
            failures.append(f"{scenario_name}: review.post_ingestion.sqlite unexpectedly has pre-existing events")

    current_db_state = _read_sqlite_state_ro(triage_dir / "review.sqlite")

    return {
        "scenario": scenario_name,
        "findings_count": len(rows),
        "http_capture": http_check,
        "live_protocol": proto,
        "r02_errors": r02_errors,
        "findings": per_finding_details,
        "post_ingestion_sqlite": {
            "present": pre_db.is_file(),
            "db_sha256": ing_db_state["db_sha256"] if ing_db_state else None,
            "states": [w["state"] for w in ing_db_state["warnings"]] if ing_db_state else None,
        },
        "current_sqlite": {
            "db_sha256": current_db_state["db_sha256"],
            "states": [w["state"] for w in current_db_state["warnings"]],
            "events_count": len(current_db_state["events"]),
            "rejected_count": len(current_db_state["rejected_decisions"]),
            "events": current_db_state["events"],
            "rejected_decisions": current_db_state["rejected_decisions"],
        },
        "blockers": blockers,
        "failures": failures,
    }


def _inspect_m1_scan_only(m1_dir: Path) -> dict[str, Any]:
    m1_dir = Path(m1_dir).resolve()
    errors: list[str] = []
    blockers: list[str] = []
    if not m1_dir.is_dir():
        return {"present": False, "blockers": [f"missing M1 scan-only directory: {m1_dir}"], "errors": []}

    cap_dir = m1_dir if (m1_dir / "scan-manifest.json").is_file() else (m1_dir / "capture")
    if not (cap_dir / "scan-manifest.json").is_file():
        return {"present": True, "blockers": [f"missing scan-manifest.json in {m1_dir}"], "errors": []}

    for forbidden_rel in ("triage", "g1-run-manifest.json", "llm_io", "assessments.jsonl", "review.sqlite"):
        if (m1_dir / forbidden_rel).exists():
            errors.append(f"M1 --scan-only unexpectedly produced {forbidden_rel}")

    s_man = strict_json((cap_dir / "scan-manifest.json").read_text(encoding="utf-8"))
    if s_man.get("success") is not True:
        errors.append("M1 scan-manifest.json success != True")

    origin_file = cap_dir / "cli-origin.json"
    if not origin_file.is_file():
        errors.append("M1 missing cli-origin.json")
    else:
        origin_doc = strict_json(origin_file.read_text(encoding="utf-8"))
        if origin_doc.get("cli_mode") != "scan-only":
            errors.append(f"M1 cli-origin.json cli_mode={origin_doc.get('cli_mode')!r} != 'scan-only'")
        if origin_doc.get("forbidden_imports"):
            errors.append(f"M1 forbidden_imports non-empty: {origin_doc.get('forbidden_imports')}")

    runs = s_man.get("runs") or {}
    for label in ("version", "json", "sarif"):
        r_meta = runs.get(label)
        if not isinstance(r_meta, dict) or r_meta.get("exit_code") != 0:
            errors.append(f"M1 child run {label} missing or non-zero exit")
            continue
        if label in ("json", "sarif"):
            cap_file = cap_dir / f"opengrep.{label}"
            if not cap_file.is_file():
                errors.append(f"M1 missing opengrep.{label}")
                continue
            if r_meta.get("output_mode") == "file":
                legacy_path = Path(str(r_meta.get("engine_output_path", "")))
                if not legacy_path.is_file() or legacy_path.read_bytes() != cap_file.read_bytes():
                    errors.append(f"M1 legacy file bytes != capture opengrep.{label} bytes")
            else:
                stdout_file = cap_dir / f"{label}.stdout.txt"
                if not stdout_file.is_file() or stdout_file.read_bytes() != cap_file.read_bytes():
                    errors.append(f"M1 {label}.stdout.txt bytes != capture opengrep.{label} bytes")

    try:
        j_doc = contracts.strict((cap_dir / "opengrep.json").read_bytes().decode("utf-8"))
        s_doc = contracts.strict((cap_dir / "opengrep.sarif").read_bytes().decode("utf-8"))
        parity = contracts.compare_sarif(j_doc, s_doc)
    except (OSError, UnicodeError, ValueError, KeyError, TypeError) as exc:
        parity = None
        errors.append(f"M1 multiset JSON/SARIF parity failed: {exc}")

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
    demo3b_dir = Path(demo3b_dir).resolve()
    if not demo3b_dir.is_dir():
        return {"present": False, "excluded_from_real_denominator": True, "errors": [f"missing demo3b dir: {demo3b_dir}"]}

    errors: list[str] = []
    triage_dir = demo3b_dir / "triage"
    http_check = verify_run_http_captures(triage_dir, require_live_chat=False)
    if not http_check["capture_integrity_ok"]:
        errors.append(f"Demo3b mock HTTP raw capture check failed: {http_check['errors']}")
    rows = [
        strict_json(line)
        for line in (triage_dir / "assessments.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
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
    db_state = _read_sqlite_state_ro(triage_dir / "review.sqlite")
    if [w["state"] for w in db_state["warnings"]] != ["OPEN"]:
        errors.append(f"Demo3b SQLite warning state must remain OPEN, got {[w['state'] for w in db_state['warnings']]}")

    return {
        "present": True,
        "evidence_kind": "SYNTHETIC_MOCK_HTTP",
        "excluded_from_real_denominator": True,
        "http_capture_status": http_check["capture_status"],
        "errors": errors,
    }


def _inspect_demo4_stale_control(demo4_dir: Path) -> dict[str, Any]:
    demo4_dir = Path(demo4_dir).resolve()
    if not demo4_dir.is_dir():
        return {"present": False, "blockers": [f"missing Demo4 stale-source directory: {demo4_dir}"], "errors": []}

    errors: list[str] = []
    triage_dir = demo4_dir / "triage"
    manifest = strict_json((demo4_dir / "g1-run-manifest.json").read_text(encoding="utf-8"))
    if manifest.get("ollama", {}).get("enabled") is not False:
        errors.append("Demo4 stale-source control must run with --no-llm (excluded from Qwen calls)")

    db_state = _read_sqlite_state_ro(triage_dir / "review.sqlite")
    if len(db_state["warnings"]) != 1 or db_state["warnings"][0]["state"] != "OPEN":
        errors.append(f"Demo4 warning must remain OPEN, got {[w['state'] for w in db_state['warnings']]}")
    if len(db_state["events"]) != 0:
        errors.append(f"Demo4 must have 0 accepted events, got {len(db_state['events'])}")
    if len(db_state["rejected_decisions"]) != 1:
        errors.append(f"Demo4 must have 1 rejected_decisions row, got {len(db_state['rejected_decisions'])}")
    else:
        rej = db_state["rejected_decisions"][0]
        if rej.get("attempted_action") != "confirm-false" or rej.get("rejection_code") != "STALE_SOURCE":
            errors.append(f"Demo4 unexpected rejection record: {rej}")
        if not str(rej.get("actor", "")).strip() or not str(rej.get("reason", "")).strip():
            errors.append("Demo4 rejection record missing actor or reason")
        if rej.get("source_version") == rej.get("observed_version"):
            errors.append("Demo4 rejection source_version unexpectedly equals observed_version")

    return {
        "present": True,
        "evidence_kind": "REAL_OPENGREP_SCAN_AND_SQLITE_GUARD",
        "excluded_from_real_denominator": True,
        "db_sha256": db_state["db_sha256"],
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

    # R03 decision (Demo1 confirm-true + Demo2 confirm-false -> reopen + Demo4 STALE_SOURCE + initial OPEN)
    r03_failures: list[str] = [*d4.get("errors", [])]
    r03_blockers: list[str] = [*d4.get("blockers", []), *d1.get("blockers", []), *d2.get("blockers", [])]

    if not r03_blockers:
        d1_sql = d1["current_sqlite"]
        if "CONFIRMED_TRUE" not in d1_sql["states"] or "OPEN" not in d1_sql["states"]:
            r03_failures.append(f"Demo1 expected one CONFIRMED_TRUE and one OPEN warning, got {d1_sql['states']}")
        d1_events = d1_sql["events"]
        if len(d1_events) != 1 or d1_events[0]["action"] != "confirm-true" or not d1_events[0]["actor"].strip() or not d1_events[0]["reason"].strip():
            r03_failures.append(f"Demo1 expected 1 confirm-true event with actor/reason, got {d1_events}")

        d2_sql = d2["current_sqlite"]
        if d2_sql["states"] != ["OPEN"]:
            r03_failures.append(f"Demo2 expected final state ['OPEN'] after reopen, got {d2_sql['states']}")
        d2_actions = [e["action"] for e in d2_sql["events"]]
        if d2_actions != ["confirm-false", "reopen"]:
            r03_failures.append(f"Demo2 expected events ['confirm-false', 'reopen'], got {d2_actions}")
        for ev in d2_sql["events"]:
            if not str(ev.get("actor", "")).strip() or not str(ev.get("reason", "")).strip():
                r03_failures.append(f"Demo2 event missing actor or reason: {ev}")

        # Optional intermediate snapshot after confirm-false (if captured by manual CLI runbook)
        after_false_snap = Path(demo2_dir).resolve() / "triage" / "review.after_confirm_false.sqlite"
        if after_false_snap.is_file():
            af_state = _read_sqlite_state_ro(after_false_snap)
            if [w["state"] for w in af_state["warnings"]] != ["CONFIRMED_FALSE"]:
                r03_failures.append("Demo2 review.after_confirm_false.sqlite does not show CONFIRMED_FALSE")

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

    out_resolved = args.output.resolve()
    if out_resolved.exists():
        parser.error(f"refusing to overwrite existing evaluation report: {out_resolved}")
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
