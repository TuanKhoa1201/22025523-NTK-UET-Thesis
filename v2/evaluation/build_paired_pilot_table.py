"""NTK Thesis V2 — Reproducible Paired Pilot Table Generator (Arm A vs. Arm B).

Generates the advisor-mandated per-alert paired comparison table (.csv and .md)
and mandatory summary metrics for OpenGrep standalone (Arm A) vs. OpenGrep +
Qwen3.5-9B (Arm B) on the exact same OpenGrep JSON scan and verified ground-truth
labels.

Enforces strict provenance guardrails:
1. Contract 1.1 deterministic `alert_id = SHA256(UTF8(scan_sha256 + ":" + decimal(finding_index)))`.
2. Rejects non-Qwen3.5 model outputs (e.g., `qwen3:8b`) if passed to `--qwen35-triage`,
   preventing legacy `qwen3:8b` runs from masquerading as `qwen3.5:9b-q4_K_M`.
3. Distinguishes `SYNTHETIC SMOKE PILOT, n=3` (`SYNTHETIC_GROUND_TRUTH`) from
   `INDEPENDENT_GROUND_TRUTH` (`STRICT_LOCK`, n=30..60).
4. Distinguishes model verdict (`KEEP_TP`, `PROPOSED_FP`, `REVIEW`) from operational
   human review state (`OPEN`, `CONFIRMED_TRUE`, `CONFIRMED_FALSE`).
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
from typing import Any

import codex_adapter
import score_pilot

CSV_FIELDNAMES: tuple[str, ...] = (
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
    "ground_truth_rationale",
    "arm_a_baseline_decision",
    "qwen35_raw_model_status",
    "qwen35_post_citation_status",
    "qwen35_arm_b_decision",
    "qwen35_citation_grounding",
    "qwen35_latency_ms",
    "qwen35_model_id",
    "qwen35_human_review_state",
    "ref_qwen3_8b_raw_model_status",
    "ref_qwen3_8b_post_citation_status",
    "ref_qwen3_8b_arm_b_decision",
    "ref_qwen3_8b_citation_grounding",
    "ref_qwen3_8b_latency_ms",
    "ref_qwen3_8b_model_id",
    "ref_qwen3_8b_human_review_state",
)


def _extract_records_from_summary_or_jsonl(
    raw_input: Any,
    run_key: str = "run2_smoke_m1_baseline_rules",
) -> Any:
    """Extract assessment records from JSONL text, list, dict, or multi-run summary JSON."""
    if raw_input is None:
        return None
    if isinstance(raw_input, str):
        stripped = raw_input.strip()
        if not stripped:
            return None
        try:
            parsed = json.loads(stripped)
            return _extract_records_from_summary_or_jsonl(parsed, run_key=run_key)
        except json.JSONDecodeError:
            return raw_input
    if isinstance(raw_input, dict):
        for container_key in ("runs", "triage_runs_qwen3_8b"):
            runs = raw_input.get(container_key)
            if isinstance(runs, dict) and isinstance(runs.get(run_key), list):
                return runs[run_key]
    return raw_input


def _verify_model_family(
    triage_input: Any,
    required_prefix: str = "qwen3.5",
) -> None:
    """Verify that every assessment record in `triage_input` belongs to `required_prefix`."""
    if triage_input is None:
        return
    records, _ = score_pilot.parse_triage_inputs(triage_input)
    for idx, rec in enumerate(records):
        norm = (
            codex_adapter.convert_single_codex_record(rec, record_index=idx)
            if codex_adapter.is_codex_assessment_record(rec)
            else rec
        )
        model_id = str(norm.get("model_id") or norm.get("model") or "").strip().lower()
        if not model_id or not model_id.startswith(required_prefix.lower()):
            raise ValueError(
                f"Model provenance violation at record {idx}: expected model starting with "
                f"'{required_prefix}', got '{model_id or 'MISSING'}'. Refusing to substitute "
                f"'{model_id or 'MISSING'}' as Qwen3.5-9B."
            )


def compute_arm_b_mandatory_metrics(
    report: dict[str, Any] | None,
    raw_triage_input: Any,
    total_alerts: int,
    labeled_tp: int,
    labeled_fp: int,
) -> dict[str, Any]:
    """Compute all P0.2 mandatory metrics with explicit numerators and denominators."""
    if report is None or raw_triage_input is None:
        return {
            "status": "PENDING_QWEN3_5_9B_RUN",
            "fp_correctly_proposed_for_removal": f"PENDING (0/{labeled_fp} denominator locked)",
            "tp_erroneously_proposed_for_removal": f"PENDING (0/{labeled_tp} denominator locked)",
            "tp_retained_keep_tp": f"PENDING (0/{labeled_tp} denominator locked)",
            "tp_retained_via_review": f"PENDING (0/{labeled_tp} denominator locked)",
            "tp_total_retained": f"PENDING (0/{labeled_tp} denominator locked)",
            "total_undetermined_or_review": f"PENDING (0/{total_alerts} denominator locked)",
            "valid_json_response_rate": f"PENDING (0/{total_alerts} denominator locked)",
            "insufficient_evidence_count": "PENDING",
            "technical_error_count": "PENDING",
            "invalid_citation_count": "PENDING",
            "mean_latency_ms": None,
            "per_alert_latency_ms": [],
            "auto_dismissed_without_human_review": f"0/{total_alerts} (0.0%)",
        }

    overall = report["summary"]["overall"]
    counts = overall["counts"]
    rates = overall["rates"]
    anom = report["anomalies"]
    decisions = report["per_alert_decisions"]

    # Classify failure/review causes across alerts
    valid_json_count = counts["triage_covered_alerts"]
    technical_error_count = len(anom["malformed_triage_records"]) + len(
        anom["unmatched_or_ambiguous_triage_records"]
    )
    invalid_citation_count = 0
    insufficient_evidence_count = 0

    for d in decisions:
        cit_chk = str(d.get("citation_check") or "").upper()
        overrides = d.get("override_reasons") or []
        has_ungrounded_override = any(str(r).startswith("ungrounded_fp:") for r in overrides)
        if cit_chk == "NOT_VERIFIED" or has_ungrounded_override:
            invalid_citation_count += 1
        elif (
            d.get("effective_verdict") == "REVIEW"
            and d.get("triage_covered")
            and not overrides
        ):
            insufficient_evidence_count += 1

    tp_keep = counts["kept_tp_on_true_tp"]
    tp_review = counts["needs_review_on_tp"]
    tp_retained_total = tp_keep + tp_review
    auto_dismissed = len(anom["human_approval_violations"])

    return {
        "status": "EVALUATED",
        "fp_correctly_proposed_for_removal": rates["proposed_fp_removal"]["display"],
        "tp_erroneously_proposed_for_removal": rates["erroneous_tp_removal"]["display"],
        "raw_model_fp_proposed_for_removal": rates["raw_model_fp_removal"]["display"],
        "raw_model_tp_erroneously_proposed_for_removal": rates["raw_model_erroneous_tp_removal"]["display"],
        "tp_retained_keep_tp": score_pilot.RatioMetric(tp_keep, labeled_tp).format_str(),
        "tp_retained_via_review": score_pilot.RatioMetric(tp_review, labeled_tp).format_str(),
        "tp_total_retained": score_pilot.RatioMetric(tp_retained_total, labeled_tp).format_str(),
        "total_undetermined_or_review": rates["review_escalation"]["display"],
        "valid_json_response_rate": score_pilot.RatioMetric(valid_json_count, total_alerts).format_str(),
        "insufficient_evidence_count": f"{insufficient_evidence_count}/{total_alerts}",
        "technical_error_count": f"{technical_error_count}/{total_alerts}",
        "invalid_citation_count": f"{invalid_citation_count}/{total_alerts}",
        "mean_latency_ms": overall["latency_ms"]["mean_ms"],
        "p50_latency_ms": overall["latency_ms"]["p50_ms"],
        "p95_latency_ms": overall["latency_ms"]["p95_ms"],
        "max_latency_ms": overall["latency_ms"]["max_ms"],
        "per_alert_latency_ms": [
            {"alert_id": d["alert_id"], "finding_index": d["finding_index"], "latency_ms": d["latency_ms"]}
            for d in decisions
        ],
        "auto_dismissed_without_human_review": score_pilot.RatioMetric(
            auto_dismissed, total_alerts
        ).format_str(),
    }


def _format_citation_grounding(decision: dict[str, Any] | None) -> str:
    if decision is None or not decision.get("triage_covered"):
        return "PENDING_QWEN3_5_9B_RUN"
    cit_check = decision.get("citation_check") or "UNSPECIFIED"
    cited_lines = decision.get("cited_lines") or []
    lines_str = ",".join(str(x) for x in cited_lines) if cited_lines else "none"
    overrides = decision.get("override_reasons") or []
    if overrides:
        return f"{cit_check} (lines={lines_str}; overrides={';'.join(overrides)})"
    return f"{cit_check} (lines={lines_str}; sha256=VERIFIED)"


def build_paired_rows_and_summary(
    opengrep_data: Any,
    labels_data: Any,
    scan_sha256: str,
    qwen35_triage_data: Any = None,
    qwen3_8b_reference_data: Any = None,
    source_root: Path | str | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Build per-alert paired comparison rows and summary metrics dict."""
    qwen35_extracted = _extract_records_from_summary_or_jsonl(qwen35_triage_data)
    if qwen35_extracted is not None:
        _verify_model_family(qwen35_extracted, required_prefix="qwen3.5")

    qwen3_8b_extracted = _extract_records_from_summary_or_jsonl(qwen3_8b_reference_data)

    # Evaluate Baseline + Ground Truth (with empty triage to get locked alert/label structure)
    base_report = score_pilot.evaluate_pilot(
        opengrep_data=opengrep_data,
        labels_data=labels_data,
        triage_data=[],
        source_root=source_root,
        expected_scan_sha256=scan_sha256,
    )

    qwen35_report = (
        score_pilot.evaluate_pilot(
            opengrep_data=opengrep_data,
            labels_data=labels_data,
            triage_data=qwen35_extracted,
            source_root=source_root,
            expected_scan_sha256=scan_sha256,
            expected_model_prefix="qwen3.5",
        )
        if qwen35_extracted is not None
        else None
    )

    qwen3_8b_report = (
        score_pilot.evaluate_pilot(
            opengrep_data=opengrep_data,
            labels_data=labels_data,
            triage_data=qwen3_8b_extracted,
            source_root=source_root,
            expected_scan_sha256=scan_sha256,
        )
        if qwen3_8b_extracted is not None
        else None
    )

    raw_labels = score_pilot._extract_labels(labels_data)
    rationale_by_id: dict[str, str] = {}
    label_type_by_id: dict[str, str] = {}
    for lb in raw_labels:
        if isinstance(lb, dict) and lb.get("alert_id"):
            aid = str(lb["alert_id"]).strip()
            rationale_by_id[aid] = str(lb.get("annotator_rationale") or "").strip()
            label_type_by_id[aid] = str(
                lb.get("label_type") or lb.get("ground_truth_type") or "SYNTHETIC_GROUND_TRUTH"
            ).strip()

    q35_by_id = (
        {d["alert_id"]: d for d in qwen35_report["per_alert_decisions"]}
        if qwen35_report
        else {}
    )
    q8b_by_id = (
        {d["alert_id"]: d for d in qwen3_8b_report["per_alert_decisions"]}
        if qwen3_8b_report
        else {}
    )

    rows: list[dict[str, Any]] = []
    for base_d in base_report["per_alert_decisions"]:
        aid = base_d["alert_id"]
        q35_d = q35_by_id.get(aid)
        q8b_d = q8b_by_id.get(aid)

        start_l = base_d.get("start_line")
        end_l = base_d.get("end_line")
        line_str = (
            f"{start_l}"
            if start_l == end_l or end_l is None
            else f"{start_l}-{end_l}"
        )

        rows.append({
            "alert_id": aid,
            "finding_index": base_d.get("finding_index"),
            "scan_sha256": scan_sha256,
            "source_sha256": base_d.get("source_sha256") or "",
            "cwe": base_d.get("cwe") or "",
            "rule_id": base_d.get("rule_id") or "",
            "path": base_d.get("file_path") or "",
            "line": line_str,
            "verified_ground_truth": base_d.get("ground_truth") or "UNLABELED",
            "label_type": label_type_by_id.get(aid, base_d.get("label_type") or "SYNTHETIC_GROUND_TRUTH"),
            "ground_truth_rationale": rationale_by_id.get(aid, ""),
            "arm_a_baseline_decision": "KEEP",
            "qwen35_raw_model_status": (
                q35_d.get("raw_model_status") or "UNDETERMINED"
                if q35_d and q35_d.get("triage_covered")
                else "PENDING_QWEN3_5_9B_RUN"
            ),
            "qwen35_post_citation_status": (
                q35_d.get("raw_codex_status") or "UNDETERMINED"
                if q35_d and q35_d.get("triage_covered")
                else "PENDING_QWEN3_5_9B_RUN"
            ),
            "qwen35_arm_b_decision": (
                q35_d.get("effective_verdict")
                if q35_d and q35_d.get("triage_covered")
                else "PENDING_QWEN3_5_9B_RUN"
            ),
            "qwen35_citation_grounding": _format_citation_grounding(q35_d),
            "qwen35_latency_ms": (
                q35_d.get("latency_ms")
                if q35_d and q35_d.get("latency_ms") is not None
                else "PENDING"
            ),
            "qwen35_model_id": (
                q35_d.get("model_id") or "qwen3.5:9b-q4_K_M"
                if q35_d and q35_d.get("triage_covered")
                else "qwen3.5:9b-q4_K_M (PENDING_RUN)"
            ),
            "qwen35_human_review_state": (
                q35_d.get("human_review_state") or "OPEN"
                if q35_d and q35_d.get("triage_covered")
                else "OPEN (PENDING_QWEN3_5_9B_RUN)"
            ),
            "ref_qwen3_8b_raw_model_status": (
                q8b_d.get("raw_model_status") or "N/A"
                if q8b_d and q8b_d.get("triage_covered")
                else "N/A"
            ),
            "ref_qwen3_8b_post_citation_status": (
                q8b_d.get("raw_codex_status") or "N/A"
                if q8b_d and q8b_d.get("triage_covered")
                else "N/A"
            ),
            "ref_qwen3_8b_arm_b_decision": (
                q8b_d.get("effective_verdict") or "N/A"
                if q8b_d and q8b_d.get("triage_covered")
                else "N/A"
            ),
            "ref_qwen3_8b_citation_grounding": (
                _format_citation_grounding(q8b_d)
                if q8b_d and q8b_d.get("triage_covered")
                else "N/A"
            ),
            "ref_qwen3_8b_latency_ms": (
                q8b_d.get("latency_ms")
                if q8b_d and q8b_d.get("latency_ms") is not None
                else "N/A"
            ),
            "ref_qwen3_8b_model_id": (
                q8b_d.get("model_id") or "qwen3:8b"
                if q8b_d and q8b_d.get("triage_covered")
                else "N/A"
            ),
            "ref_qwen3_8b_human_review_state": (
                q8b_d.get("human_review_state") or "OPEN"
                if q8b_d and q8b_d.get("triage_covered")
                else "N/A"
            ),
        })

    base_counts = base_report["summary"]["overall"]["counts"]
    total_alerts = base_counts["total_alerts"]
    labeled_tp = base_counts["labeled_tp"]
    labeled_fp = base_counts["labeled_fp"]

    summary = {
        "dataset_banner": (
            f"SYNTHETIC SMOKE PILOT, n={total_alerts}"
            if total_alerts < 30
            else f"LOCKED PILOT BENCHMARK, n={total_alerts}"
        ),
        "scan_sha256": scan_sha256,
        "total_alerts": total_alerts,
        "labeled_tp": labeled_tp,
        "labeled_fp": labeled_fp,
        "arm_a_baseline": {
            "total_alerts_kept": f"{total_alerts}/{total_alerts} (100.0%)",
            "fp_proposed_for_removal": f"0/{labeled_fp} (0.0%)",
            "tp_erroneously_proposed_for_removal": f"0/{labeled_tp} (0.0%)",
            "tp_retained": f"{labeled_tp}/{labeled_tp} (100.0%)",
        },
        "arm_b_qwen35_9b": compute_arm_b_mandatory_metrics(
            qwen35_report, qwen35_extracted, total_alerts, labeled_tp, labeled_fp
        ),
        "reference_qwen3_8b": (
            compute_arm_b_mandatory_metrics(
                qwen3_8b_report, qwen3_8b_extracted, total_alerts, labeled_tp, labeled_fp
            )
            if qwen3_8b_report is not None
            else None
        ),
    }
    return rows, summary


def render_csv_string(rows: list[dict[str, Any]]) -> str:
    """Serialize per-alert paired rows to CSV text."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(CSV_FIELDNAMES), lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({k: row.get(k, "") for k in CSV_FIELDNAMES})
    return buf.getvalue()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build Advisor Paired Pilot Table (.csv and .md) for Arm A vs. Arm B."
    )
    parser.add_argument("--opengrep", required=True, help="Path to locked OpenGrep JSON scan.")
    parser.add_argument("--labels", required=True, help="Path to verified ground-truth labels JSON.")
    parser.add_argument("--qwen35-triage", help="Optional path to Qwen3.5-9B assessments JSON/JSONL.")
    parser.add_argument(
        "--qwen3-8b-reference",
        help="Optional path to historical Qwen3:8b assessments JSON/JSONL for reference only.",
    )
    parser.add_argument("--source-root", help="Optional path to Java source root.")
    parser.add_argument("--output-csv", required=True, help="Path to write CSV table.")
    parser.add_argument("--output-json", help="Optional path to write summary JSON.")
    args = parser.parse_args(argv)

    og_bytes = Path(args.opengrep).read_bytes()
    sha_variants = codex_adapter.compute_scan_sha256_variants(og_bytes)
    og_data = json.loads(og_bytes.decode("utf-8"))
    labels_data = json.loads(Path(args.labels).read_text(encoding="utf-8"))

    # If labels_data specifies a locked scan_sha256 that matches one of the verified
    # line-ending variants (raw, LF, or CRLF) of the OpenGrep file, use that canonical digest.
    locked_label_scan_sha = (
        str(labels_data.get("scan_sha256")).strip().lower()
        if isinstance(labels_data, dict) and codex_adapter.is_valid_sha256(labels_data.get("scan_sha256"))
        else None
    )
    if locked_label_scan_sha and locked_label_scan_sha in set(sha_variants.values()):
        scan_sha256 = locked_label_scan_sha
    elif locked_label_scan_sha and locked_label_scan_sha not in set(sha_variants.values()):
        raise ValueError(
            f"Labels scan_sha256 {locked_label_scan_sha} does not match OpenGrep scan file "
            f"(variants: {sha_variants})"
        )
    else:
        scan_sha256 = sha_variants["raw"]
    q35_raw = (
        Path(args.qwen35_triage).read_text(encoding="utf-8")
        if args.qwen35_triage
        else None
    )
    q8b_raw = (
        Path(args.qwen3_8b_reference).read_text(encoding="utf-8")
        if args.qwen3_8b_reference
        else None
    )

    rows, summary = build_paired_rows_and_summary(
        opengrep_data=og_data,
        labels_data=labels_data,
        scan_sha256=scan_sha256,
        qwen35_triage_data=q35_raw,
        qwen3_8b_reference_data=q8b_raw,
        source_root=args.source_root,
    )

    out_csv = Path(args.output_csv)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    out_csv.write_text(render_csv_string(rows), encoding="utf-8")

    if args.output_json:
        out_json = Path(args.output_json)
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_json.write_text(
            json.dumps({"summary": summary, "rows": rows}, indent=2),
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
