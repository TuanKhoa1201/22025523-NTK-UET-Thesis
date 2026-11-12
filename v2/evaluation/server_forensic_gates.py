"""Fail-closed acceptance gates, per-alert PAIRED_EVALUATION audit, and guided-LLM confounder verifier.

Exit code contract (Section VI):
- 0 (PASS): Every mandatory acceptance criterion is verified and passed.
- 1 (FAIL): False, tampered, or contradictory evidence detected.
- 2 (INCOMPLETE): Mandatory evidence missing or cannot be verified; never coerced to PASS.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from v2.evaluation.server_forensic_helpers import (
    compute_contract_alert_id,
    format_cited_lines,
    load_owasp_expected_csv,
    normalize_cwe,
    scan_json_for_forbidden_label_keys,
    sha256_file,
    status_to_decision,
)
from v2.triage import ollama as triage_ollama

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_INCOMPLETE = 2

MANDATORY_CRITERIA_IDS: tuple[str, ...] = (
    "C01_historical_immutability",
    "C02_opengrep_three_scans_and_9_rules",
    "C03_ollama_10_assessments_and_6_checkpoints",
    "C04_citations_and_post_validator_integrity",
    "C05_paired_evaluation_per_alert_table",
    "C06_ground_truth_56_owasp_and_20_real_projects",
    "C07_sqlite_readonly_and_stale_source_lifecycle",
    "C08_guided_llm_confounder_and_zero_label_leakage",
    "C09_metrics_recomputation_alignment",
)


def _add_discrepancy(
    discrepancies: list[dict[str, Any]],
    alert_id: str,
    field: str,
    expected: Any,
    actual: Any,
    source_file: str,
    severity: str = "CRITICAL",
) -> None:
    discrepancies.append(
        {
            "alert_id": str(alert_id),
            "field": str(field),
            "expected": str(expected),
            "actual": str(actual),
            "source_file": str(source_file),
            "severity": str(severity),
        }
    )


def audit_paired_evaluation_table(
    evidence_root: Path,
    worktree_root: Path,
    expected_heldout_scan_sha: str,
    sqlite_arm_c_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Exhaustive per-alert, per-column verification of PAIRED_EVALUATION.csv against raw evidence."""
    post_dir = worktree_root / "v2" / "evaluation" / "post_report"
    csv_path = post_dir / "PAIRED_EVALUATION.csv"
    og_path = evidence_root / "runs" / "stage1_heldout_set_40_scan" / "opengrep.json"
    lbl_path = post_dir / "labels_heldout.json"
    owasp_csv_path = evidence_root / "sources" / "expectedresults-1.2.csv"
    src_dir = evidence_root / "sources" / "heldout_set_40"

    arm_b_path = evidence_root / "runs" / "stage4_heldout40_armB_heuristic" / "assessments.jsonl"
    arm_c_path = evidence_root / "runs" / "stage4_heldout40_armC_evidence_llm" / "assessments.jsonl"
    arm_d_path = evidence_root / "runs" / "stage4_heldout40_armD_llm_ablation" / "assessments.jsonl"

    required_paths = [csv_path, og_path, lbl_path, owasp_csv_path, arm_b_path, arm_c_path, arm_d_path]
    missing_paths = [str(p) for p in required_paths if not p.is_file()]
    if missing_paths or not src_dir.is_dir():
        return {
            "status": "INCOMPLETE",
            "missing_inputs": missing_paths + ([str(src_dir)] if not src_dir.is_dir() else []),
            "discrepancies": [],
            "per_alert_verified_rows": [],
        }

    with csv_path.open("r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        fieldnames = list(reader.fieldnames or [])
        csv_rows = list(reader)

    required_columns = [
        "alert_id",
        "finding_index",
        "scan_sha256",
        "source_sha256",
        "cwe",
        "rule_id",
        "path",
        "line",
        "verified_ground_truth",
        "label_type",
        "arm_a_opengrep_decision",
        "arm_b_heuristic_status",
        "arm_b_heuristic_decision",
        "arm_b_citation_check",
        "arm_c_qwen35_raw_status",
        "arm_c_qwen35_post_citation_status",
        "arm_c_qwen35_decision",
        "arm_c_citation_check",
        "arm_c_cited_lines",
        "arm_c_latency_ms",
        "arm_c_model_id",
        "arm_c_human_review_state",
        "arm_d_llm_ablation_raw_status",
        "arm_d_llm_ablation_decision",
        "arm_d_citation_check",
        "arm_d_latency_ms",
        "arm_c_explanation",
    ]

    discrepancies: list[dict[str, Any]] = []
    for col in required_columns:
        if col not in fieldnames:
            _add_discrepancy(discrepancies, "TABLE_HEADER", "missing_column", col, "MISSING", str(csv_path))

    og_results = json.loads(og_path.read_text(encoding="utf-8")).get("results", [])
    actual_scan_sha = sha256_file(og_path)
    if actual_scan_sha != expected_heldout_scan_sha:
        _add_discrepancy(
            discrepancies,
            "SCAN_ROOT",
            "scan_sha256",
            expected_heldout_scan_sha,
            actual_scan_sha,
            str(og_path),
        )

    owasp_map = load_owasp_expected_csv(owasp_csv_path)
    lbl_items = json.loads(lbl_path.read_text(encoding="utf-8")).get("labels", [])
    lbl_by_id: dict[str, dict[str, Any]] = {}
    for item in lbl_items:
        aid = str(item.get("alert_id") or "")
        if aid in lbl_by_id:
            _add_discrepancy(discrepancies, aid, "duplicate_alert_id", "unique", "duplicate", str(lbl_path))
        lbl_by_id[aid] = item

    def _load_jsonl_map(path: Path, label: str) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for line_no, raw_ln in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not raw_ln.strip():
                continue
            rec = json.loads(raw_ln)
            aid = str(rec.get("alert_id") or rec.get("id") or "")
            if aid in out:
                _add_discrepancy(
                    discrepancies, aid, f"{label}.duplicate_alert_id", "unique", f"duplicate_line_{line_no}", str(path)
                )
            out[aid] = rec
        return out

    arm_b_map = _load_jsonl_map(arm_b_path, "arm_b")
    arm_c_map = _load_jsonl_map(arm_c_path, "arm_c")
    arm_d_map = _load_jsonl_map(arm_d_path, "arm_d")

    sqlite_state_by_id: dict[str, str] = {}
    if sqlite_arm_c_summary and isinstance(sqlite_arm_c_summary.get("per_alert_summary"), list):
        for srow in sqlite_arm_c_summary["per_alert_summary"]:
            sqlite_state_by_id[str(srow.get("alert_id"))] = str(srow.get("queue_state"))

    expected_alert_ids = [compute_contract_alert_id(actual_scan_sha, idx) for idx in range(len(og_results))]
    expected_set = set(expected_alert_ids)

    csv_by_id: dict[str, dict[str, str]] = {}
    for row_idx, cr in enumerate(csv_rows):
        aid = str(cr.get("alert_id") or "")
        if aid in csv_by_id:
            _add_discrepancy(
                discrepancies,
                aid,
                "duplicate_alert_id",
                "1_occurrence",
                f"duplicate_at_csv_row_{row_idx}",
                str(csv_path),
            )
        else:
            csv_by_id[aid] = cr
        if aid not in expected_set:
            _add_discrepancy(
                discrepancies,
                aid,
                "extra_alert_id",
                "in_stage1_heldout_set_40_scan",
                "EXTRA_UNKNOWN_ALERT_ID",
                str(csv_path),
            )

    for idx, exp_aid in enumerate(expected_alert_ids):
        if exp_aid not in csv_by_id:
            _add_discrepancy(
                discrepancies,
                exp_aid,
                "missing_alert_id_in_csv",
                f"present_at_index_{idx}",
                "MISSING",
                str(csv_path),
            )
        if exp_aid not in arm_b_map:
            _add_discrepancy(discrepancies, exp_aid, "missing_alert_in_arm_b", "present", "MISSING", str(arm_b_path))
        if exp_aid not in arm_c_map:
            _add_discrepancy(discrepancies, exp_aid, "missing_alert_in_arm_c", "present", "MISSING", str(arm_c_path))
        if exp_aid not in arm_d_map:
            _add_discrepancy(discrepancies, exp_aid, "missing_alert_in_arm_d", "present", "MISSING", str(arm_d_path))
        if exp_aid not in lbl_by_id:
            _add_discrepancy(discrepancies, exp_aid, "missing_alert_in_labels", "present", "MISSING", str(lbl_path))

    def _raw_llm_status(rec: dict[str, Any]) -> str:
        raw_resp = (rec.get("assessment") or {}).get("raw_response")
        if not isinstance(raw_resp, dict):
            return "NO_LLM_CALL"
        content = (raw_resp.get("message") or {}).get("content")
        if not isinstance(content, str) or not content.strip():
            return "EMPTY_RAW_CONTENT"
        try:
            return str(json.loads(content).get("status") or "MISSING_STATUS")
        except Exception:
            return "RAW_JSON_PARSE_ERROR"

    per_alert_verified_rows: list[dict[str, Any]] = []
    for idx, exp_aid in enumerate(expected_alert_ids):
        cr = csv_by_id.get(exp_aid)
        rb = arm_b_map.get(exp_aid)
        rc = arm_c_map.get(exp_aid)
        rd = arm_d_map.get(exp_aid)
        lbl = lbl_by_id.get(exp_aid)
        if not (cr and rb and rc and rd and lbl):
            continue

        r_og = og_results[idx]
        fname = Path(str(r_og.get("path") or "")).name
        test_name = fname[:-5] if fname.endswith(".java") else fname
        owasp_ref = owasp_map.get(test_name)
        disk_java = src_dir / fname
        if not disk_java.is_file():
            _add_discrepancy(discrepancies, exp_aid, "disk_java_source", str(disk_java), "MISSING", str(src_dir))
            continue
        disk_sha = sha256_file(disk_java)

        sl = int((r_og.get("start") or {}).get("line") or 0)
        el = int((r_og.get("end") or {}).get("line") or sl)
        exp_line_str = str(sl) if sl == el else f"{sl}-{el}"
        exp_cwe = normalize_cwe(((r_og.get("extra") or {}).get("metadata") or {}).get("cwe"))
        exp_rule_id = str(r_og.get("check_id") or "")

        exp_gt = owasp_ref["expected_label"] if owasp_ref else str(lbl.get("ground_truth") or "")
        if owasp_ref and lbl.get("ground_truth") != owasp_ref["expected_label"]:
            _add_discrepancy(
                discrepancies,
                exp_aid,
                "labels_heldout.ground_truth",
                owasp_ref["expected_label"],
                lbl.get("ground_truth"),
                str(lbl_path),
            )
        if owasp_ref and normalize_cwe(lbl.get("cwe")) != owasp_ref["cwe"]:
            _add_discrepancy(
                discrepancies,
                exp_aid,
                "labels_heldout.cwe",
                owasp_ref["cwe"],
                lbl.get("cwe"),
                str(lbl_path),
            )
        if lbl.get("source_sha256") != disk_sha:
            _add_discrepancy(
                discrepancies,
                exp_aid,
                "labels_heldout.source_sha256",
                disk_sha,
                lbl.get("source_sha256"),
                str(lbl_path),
            )

        ass_b = rb.get("assessment") or {}
        ass_c = rc.get("assessment") or {}
        ass_d = rd.get("assessment") or {}

        exp_b_status = str(ass_b.get("status") or "")
        exp_b_dec = status_to_decision(exp_b_status)
        exp_b_cc = str(ass_b.get("citation_check") or "")

        exp_c_raw = _raw_llm_status(rc)
        exp_c_post = str(ass_c.get("status") or "")
        exp_c_dec = status_to_decision(exp_c_post)
        exp_c_cc = str(ass_c.get("citation_check") or "")
        exp_c_cites = format_cited_lines(ass_c.get("citations"))
        exp_c_lat_ms = round(float(ass_c.get("elapsed_seconds") or 0.0) * 1000.0, 3)
        exp_c_model = str(ass_c.get("model") or "")
        exp_c_state = sqlite_state_by_id.get(exp_aid, str(rc.get("state") or "OPEN"))
        exp_c_expl = str(ass_c.get("explanation") or "")

        exp_d_raw = _raw_llm_status(rd)
        exp_d_post = str(ass_d.get("status") or "")
        exp_d_dec = status_to_decision(exp_d_post)
        exp_d_cc = str(ass_d.get("citation_check") or "")
        exp_d_lat_ms = round(float(ass_d.get("elapsed_seconds") or 0.0) * 1000.0, 3)

        exact_checks = [
            ("finding_index", str(idx), cr.get("finding_index")),
            ("scan_sha256", actual_scan_sha, cr.get("scan_sha256")),
            ("source_sha256", disk_sha, cr.get("source_sha256")),
            ("cwe", exp_cwe, normalize_cwe(cr.get("cwe"))),
            ("rule_id", exp_rule_id, cr.get("rule_id")),
            ("path", fname, Path(str(cr.get("path") or "")).name),
            ("line", exp_line_str, cr.get("line")),
            ("verified_ground_truth", exp_gt, cr.get("verified_ground_truth")),
            ("label_type", str(lbl.get("label_type") or "INDEPENDENT_GROUND_TRUTH"), cr.get("label_type")),
            ("arm_a_opengrep_decision", "KEEP", cr.get("arm_a_opengrep_decision")),
            ("arm_b_heuristic_status", exp_b_status, cr.get("arm_b_heuristic_status")),
            ("arm_b_heuristic_decision", exp_b_dec, cr.get("arm_b_heuristic_decision")),
            ("arm_b_citation_check", exp_b_cc, cr.get("arm_b_citation_check")),
            ("arm_c_qwen35_raw_status", exp_c_raw, cr.get("arm_c_qwen35_raw_status")),
            ("arm_c_qwen35_post_citation_status", exp_c_post, cr.get("arm_c_qwen35_post_citation_status")),
            ("arm_c_qwen35_decision", exp_c_dec, cr.get("arm_c_qwen35_decision")),
            ("arm_c_citation_check", exp_c_cc, cr.get("arm_c_citation_check")),
            ("arm_c_cited_lines", exp_c_cites, cr.get("arm_c_cited_lines")),
            ("arm_c_model_id", exp_c_model, cr.get("arm_c_model_id")),
            ("arm_c_human_review_state", exp_c_state, cr.get("arm_c_human_review_state")),
            ("arm_d_llm_ablation_raw_status", exp_d_raw, cr.get("arm_d_llm_ablation_raw_status")),
            ("arm_d_llm_ablation_decision", exp_d_dec, cr.get("arm_d_llm_ablation_decision")),
            ("arm_d_citation_check", exp_d_cc, cr.get("arm_d_citation_check")),
            ("arm_c_explanation", exp_c_expl, cr.get("arm_c_explanation")),
        ]
        for fname_col, exp_val, act_val in exact_checks:
            if str(act_val) != str(exp_val):
                _add_discrepancy(discrepancies, exp_aid, fname_col, exp_val, act_val, str(csv_path))

        # Per-alert latency verification (catches compensating +/- swaps where total stays equal)
        for lat_col, exp_ms in (("arm_c_latency_ms", exp_c_lat_ms), ("arm_d_latency_ms", exp_d_lat_ms)):
            raw_lat = cr.get(lat_col)
            try:
                act_ms = float(raw_lat) if raw_lat is not None else -1.0
                if abs(act_ms - exp_ms) > 0.05:
                    _add_discrepancy(discrepancies, exp_aid, lat_col, exp_ms, raw_lat, str(csv_path))
            except (TypeError, ValueError):
                _add_discrepancy(discrepancies, exp_aid, lat_col, exp_ms, raw_lat, str(csv_path))

        per_alert_verified_rows.append(
            {
                "finding_index": idx,
                "alert_id": exp_aid,
                "path": fname,
                "line": exp_line_str,
                "cwe": exp_cwe,
                "verified_ground_truth": exp_gt,
                "scan_sha256": actual_scan_sha,
                "source_sha256": disk_sha,
                "arm_a_status": "SUPPORTED",
                "arm_b_status": exp_b_status,
                "arm_c_raw_status": exp_c_raw,
                "arm_c_post_status": exp_c_post,
                "arm_c_citation_check": exp_c_cc,
                "arm_c_cited_lines": exp_c_cites,
                "arm_c_latency_ms": exp_c_lat_ms,
                "arm_d_raw_status": exp_d_raw,
                "arm_d_post_status": exp_d_post,
                "arm_d_decision": exp_d_dec,
                "arm_d_citation_check": exp_d_cc,
                "arm_d_latency_ms": exp_d_lat_ms,
                "human_review_state": exp_c_state,
            }
        )

    return {
        "status": "PASS" if len(discrepancies) == 0 else "FAIL",
        "csv_path": str(csv_path),
        "csv_sha256": sha256_file(csv_path),
        "csv_row_count": len(csv_rows),
        "expected_alert_count": len(expected_alert_ids),
        "columns_verified_count": len(required_columns),
        "columns_verified": required_columns,
        "discrepancy_count": len(discrepancies),
        "discrepancies": discrepancies,
        "per_alert_verified_rows": per_alert_verified_rows,
    }


def audit_guided_llm_confounder(evidence_root: Path) -> dict[str, Any]:
    """Verify exact heuristic_signals injected into Arm C prompts, 76/76 concordance, and 0 label leakage."""
    v2_1_arm_c_runs = [
        ("stage3_dev16_armC_v2_1_evidence_llm", 16),
        ("stage4_heldout40_armC_evidence_llm", 40),
        ("stage5_real_projects_armC_evidence_llm", 20),
    ]
    per_run: list[dict[str, Any]] = []
    observed_signal_keys: set[str] = set()
    prompt_leak_hits: list[str] = []
    total_checked = 0
    total_concordant = 0
    missing_runs: list[str] = []

    for run_name, expected_n in v2_1_arm_c_runs:
        aj_path = evidence_root / "runs" / run_name / "assessments.jsonl"
        if not aj_path.is_file():
            missing_runs.append(run_name)
            continue
        rows = [json.loads(ln) for ln in aj_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        concordant = 0
        rec_status_present = 0
        rec_reason_present = 0
        cand_cites_present = 0
        for idx, rec in enumerate(rows):
            ev = rec.get("evidence") or {}
            ass = rec.get("assessment") or {}
            hs = ev.get("heuristic_signals")
            if isinstance(hs, dict):
                observed_signal_keys.update(hs.keys())
                if "recommended_status" in hs:
                    rec_status_present += 1
                if "recommendation_reason" in hs:
                    rec_reason_present += 1
                if "candidate_citations" in hs:
                    cand_cites_present += 1
            model_name = str(ass.get("model") or "qwen3.5:9b-q4_K_M")
            payload = triage_ollama.request_payload(ev, model_name)
            leaks = scan_json_for_forbidden_label_keys(payload)
            if leaks:
                prompt_leak_hits.extend(f"{run_name}[{idx}]:{k}" for k in leaks)

            raw_resp = ass.get("raw_response") or {}
            msg_txt = (raw_resp.get("message") or {}).get("content") or "{}"
            try:
                raw_status = json.loads(msg_txt).get("status")
            except Exception:
                raw_status = None
            if isinstance(hs, dict) and raw_status == hs.get("recommended_status"):
                concordant += 1
            total_checked += 1

        total_concordant += concordant
        per_run.append(
            {
                "run_name": run_name,
                "expected_records": expected_n,
                "actual_records": len(rows),
                "recommended_status_injected_count": rec_status_present,
                "recommendation_reason_injected_count": rec_reason_present,
                "candidate_citations_injected_count": cand_cites_present,
                "raw_qwen_matches_recommended_status_count": concordant,
                "concordance_ratio": f"{concordant}/{len(rows)}",
            }
        )

    if missing_runs:
        return {"status": "INCOMPLETE", "missing_runs": missing_runs}

    status = "PASS" if len(prompt_leak_hits) == 0 and total_checked == 76 else "FAIL"
    return {
        "status": status,
        "prompt_evidence_field_name": "evidence_signals",
        "injected_heuristic_signals_keys": sorted(observed_signal_keys),
        "critical_guiding_fields": [
            "heuristic_signals.recommended_status",
            "heuristic_signals.recommendation_reason",
            "heuristic_signals.candidate_citations",
        ],
        "frozen_v2_1_arm_c_total_records": total_checked,
        "raw_qwen_concordant_with_heuristic_count": total_concordant,
        "concordance_display": f"{total_concordant}/{total_checked}",
        "forbidden_ground_truth_keys_in_rebuilt_prompts": prompt_leak_hits,
        "scientific_attribution_rule": (
            "PIPELINE_COMBINED_RESULT_ONLY: Do NOT attribute 40/40 on heldout_set_40 to standalone Qwen "
            "reasoning; extract_evidence_signals() deterministically pre-computed 40/40 recommended_status "
            "values on OWASP Benchmark patterns and passed them into Qwen's prompt."
        ),
        "runs_breakdown": per_run,
    }


def evaluate_acceptance_gates(
    criteria_map: dict[str, dict[str, Any]],
    attempt_force_pass: bool = False,
) -> dict[str, Any]:
    """Fail-closed gate evaluator: FAIL -> exit 1; INCOMPLETE -> exit 2; PASS -> exit 0.

    Explicitly rejects any attempt (`attempt_force_pass=True`) to coerce FAIL or INCOMPLETE into PASS.
    """
    ordered_results: list[dict[str, Any]] = []
    failed_ids: list[str] = []
    incomplete_ids: list[str] = []
    passed_ids: list[str] = []

    for cid in MANDATORY_CRITERIA_IDS:
        entry = criteria_map.get(cid)
        if not isinstance(entry, dict):
            incomplete_ids.append(cid)
            ordered_results.append(
                {
                    "criterion_id": cid,
                    "status": "INCOMPLETE",
                    "issues": [f"Mandatory criterion '{cid}' was not evaluated"],
                    "evidence": {},
                }
            )
            continue

        st = str(entry.get("status") or "INCOMPLETE").upper()
        if st not in ("PASS", "FAIL", "INCOMPLETE"):
            st = "INCOMPLETE"
        if st == "PASS" and not entry.get("evidence"):
            st = "INCOMPLETE"
            entry = {
                **entry,
                "status": "INCOMPLETE",
                "issues": list(entry.get("issues") or []) + [f"Criterion '{cid}' claimed PASS without evidence"],
            }

        if st == "FAIL":
            failed_ids.append(cid)
        elif st == "INCOMPLETE":
            incomplete_ids.append(cid)
        else:
            passed_ids.append(cid)

        ordered_results.append(
            {
                "criterion_id": cid,
                "status": st,
                "issues": list(entry.get("issues") or []),
                "evidence": entry.get("evidence") or {},
            }
        )

    coercion_blocked = False
    if failed_ids:
        overall_verdict = "FAIL"
        exit_code = EXIT_FAIL
        if attempt_force_pass:
            coercion_blocked = True
    elif incomplete_ids:
        overall_verdict = "INCOMPLETE"
        exit_code = EXIT_INCOMPLETE
        if attempt_force_pass:
            coercion_blocked = True
    else:
        overall_verdict = "PASS"
        exit_code = EXIT_PASS

    return {
        "schema": "ntk.server_forensic_failclosed_verdict.v2",
        "overall_verdict": overall_verdict,
        "exit_code": exit_code,
        "force_pass_attempt_blocked": coercion_blocked,
        "mandatory_criteria_total": len(MANDATORY_CRITERIA_IDS),
        "passed_count": len(passed_ids),
        "failed_count": len(failed_ids),
        "incomplete_count": len(incomplete_ids),
        "passed_criteria": passed_ids,
        "failed_criteria": failed_ids,
        "incomplete_criteria": incomplete_ids,
        "criteria": ordered_results,
    }
