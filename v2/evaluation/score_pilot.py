"""NTK Thesis V2 - M4/M5 Evaluation Scoring & Fail-Safe Integrity Script.

Compares Arm A (OpenGrep standalone) vs. Arm B (OpenGrep + local Qwen triage)
on the exact same OpenGrep scan output and locked independent ground-truth alert labels.

Supports both normalized triage JSON/JSONL and Codex nested `assessment.jsonl` /
`assessments.jsonl` (`SUPPORTED`, `REFUTED`, `UNDETERMINED`) via `codex_adapter.py`.
Prioritizes CWE-22 and CWE-89 while supporting separate reporting for CWE-78 and CWE-79.
Uses only the Python standard library.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import hashlib
import json
import math
from pathlib import Path
import statistics
from typing import Any

import codex_adapter

PRIORITY_CWES: tuple[str, ...] = ("CWE-22", "CWE-89")
SECONDARY_CWES: tuple[str, ...] = ("CWE-78", "CWE-79")
ALL_SUPPORTED_CWES: tuple[str, ...] = PRIORITY_CWES + SECONDARY_CWES

VALID_GROUND_TRUTH: frozenset[str] = frozenset({
    "TRUE_POSITIVE",
    "FALSE_POSITIVE",
    "AMBIGUOUS",
})

FORBIDDEN_AUTO_LABEL_SOURCES: frozenset[str] = frozenset({
    "qwen",
    "ollama",
    "llm",
    "codex",
    "auto",
    "model",
    "opengrep-triage",
})

# Markers that cannot masquerade as INDEPENDENT_GROUND_TRUTH (only SYNTHETIC_GROUND_TRUTH is allowed for agent/fixture verification)
FORBIDDEN_INDEPENDENT_LABEL_ANNOTATORS: frozenset[str] = frozenset({
    "antigravity",
    "agent",
    "javis",
    "synthetic",
    "fixture",
    "ai",
})

# Normalized triage decisions:
# - PROPOSED_FP: model proposes alert is a false positive (REFUTED -> candidate only, requires human confirmation)
# - KEEP_TP: model supports/keeps alert as a likely true positive (SUPPORTED -> KEEP_TP)
# - REVIEW: model returns UNDETERMINED / REVIEW or fail-safe override triggers
VALID_MODEL_VERDICTS: dict[str, str] = {
    "REFUTED": "PROPOSED_FP",
    "FP": "PROPOSED_FP",
    "FALSE_POSITIVE": "PROPOSED_FP",
    "PROPOSED_FP": "PROPOSED_FP",
    "SUPPORTED": "KEEP_TP",
    "TP": "KEEP_TP",
    "TRUE_POSITIVE": "KEEP_TP",
    "KEEP_TP": "KEEP_TP",
    "UNDETERMINED": "REVIEW",
    "REVIEW": "REVIEW",
    "NEEDS_REVIEW": "REVIEW",
}


def normalize_cwe(raw_cwe: Any) -> str:
    """Normalize a CWE identifier such as 'CWE-89: SQL Injection' or ['CWE-22'] to 'CWE-89'."""
    return codex_adapter.normalize_cwe_value(raw_cwe)


def compute_sha256_text(content: str) -> str:
    """Compute hex SHA-256 of normalized UTF-8 text."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class RatioMetric:
    """Represents a ratio metric with explicit numerator, denominator, and safe division."""

    numerator: int
    denominator: int

    @property
    def rate(self) -> float | None:
        if self.denominator <= 0:
            return None
        return self.numerator / self.denominator

    def format_str(self) -> str:
        if self.denominator <= 0:
            return f"{self.numerator}/0 (N/A)"
        pct = (self.numerator / self.denominator) * 100.0
        return f"{self.numerator}/{self.denominator} ({pct:.1f}%)"

    def to_dict(self) -> dict[str, Any]:
        return {
            "numerator": self.numerator,
            "denominator": self.denominator,
            "rate": round(self.rate, 6) if self.rate is not None else None,
            "display": self.format_str(),
        }


@dataclass
class LatencySummary:
    """Summary statistics for per-alert processing time in milliseconds."""

    count: int = 0
    total_ms: float = 0.0
    mean_ms: float | None = None
    p50_ms: float | None = None
    p95_ms: float | None = None
    max_ms: float | None = None

    @classmethod
    def from_samples(cls, samples_ms: list[float]) -> LatencySummary:
        clean = [
            float(x)
            for x in samples_ms
            if isinstance(x, (int, float))
            and not isinstance(x, bool)
            and not math.isnan(float(x))
            and float(x) >= 0.0
        ]
        if not clean:
            return cls()
        clean.sort()
        count = len(clean)
        total_ms = sum(clean)
        mean_ms = statistics.fmean(clean)
        p50_ms = statistics.median(clean)
        p95_idx = min(count - 1, max(0, math.ceil(0.95 * count) - 1))
        p95_ms = clean[p95_idx]
        max_ms = clean[-1]
        return cls(
            count=count,
            total_ms=round(total_ms, 3),
            mean_ms=round(mean_ms, 3),
            p50_ms=round(p50_ms, 3),
            p95_ms=round(p95_ms, 3),
            max_ms=round(max_ms, 3),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "count": self.count,
            "total_ms": self.total_ms,
            "mean_ms": self.mean_ms,
            "p50_ms": self.p50_ms,
            "p95_ms": self.p95_ms,
            "max_ms": self.max_ms,
        }


@dataclass
class CweBucketMetrics:
    """Aggregated evaluation metrics for a single CWE or group of CWEs."""

    cwe: str
    tier: str
    total_alerts: int = 0
    labeled_tp: int = 0
    labeled_fp: int = 0
    labeled_ambiguous: int = 0
    unlabeled_alerts: int = 0
    triage_covered_alerts: int = 0
    grounding_verified_fp_proposals: int = 0
    proposed_fp_on_true_fp: int = 0
    erroneously_proposed_fp_on_tp: int = 0
    kept_tp_on_true_tp: int = 0
    kept_tp_on_true_fp: int = 0
    needs_review_total: int = 0
    needs_review_on_tp: int = 0
    needs_review_on_fp: int = 0
    needs_review_on_ambiguous: int = 0
    needs_review_on_unlabeled: int = 0
    fail_safe_review_overrides: int = 0
    raw_model_refuted_on_tp: int = 0
    raw_model_refuted_on_fp: int = 0
    raw_model_supported_on_tp: int = 0
    raw_model_supported_on_fp: int = 0
    fail_safe_blocked_tp_refutations: int = 0
    latency_samples_ms: list[float] = field(default_factory=list)

    @property
    def proposed_fp_removal_rate(self) -> RatioMetric:
        """True FP alerts proposed as FP by triage (requires independent FP label)."""
        return RatioMetric(self.proposed_fp_on_true_fp, self.labeled_fp)

    @property
    def erroneous_tp_removal_rate(self) -> RatioMetric:
        """True TP alerts wrongly proposed for removal as FP (always shows num/den)."""
        return RatioMetric(self.erroneously_proposed_fp_on_tp, self.labeled_tp)

    @property
    def raw_model_erroneous_tp_removal_rate(self) -> RatioMetric:
        """Layer 2: True TP alerts where raw LLM output returned REFUTED (before fail-safe gate)."""
        return RatioMetric(self.raw_model_refuted_on_tp, self.labeled_tp)

    @property
    def raw_model_fp_removal_rate(self) -> RatioMetric:
        """Layer 2: True FP alerts where raw LLM output returned REFUTED (before fail-safe gate)."""
        return RatioMetric(self.raw_model_refuted_on_fp, self.labeled_fp)

    @property
    def review_escalation_rate(self) -> RatioMetric:
        """Fraction of total alerts routed to human REVIEW/UNDETERMINED."""
        return RatioMetric(self.needs_review_total, self.total_alerts)

    @property
    def triage_coverage_rate(self) -> RatioMetric:
        """Fraction of alerts with a valid, non-malformed triage output."""
        return RatioMetric(self.triage_covered_alerts, self.total_alerts)

    @property
    def label_coverage_rate(self) -> RatioMetric:
        """Fraction of alerts with a valid independent ground-truth label."""
        labeled_count = self.labeled_tp + self.labeled_fp + self.labeled_ambiguous
        return RatioMetric(labeled_count, self.total_alerts)

    @property
    def latency(self) -> LatencySummary:
        return LatencySummary.from_samples(self.latency_samples_ms)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cwe": self.cwe,
            "tier": self.tier,
            "counts": {
                "total_alerts": self.total_alerts,
                "labeled_tp": self.labeled_tp,
                "labeled_fp": self.labeled_fp,
                "labeled_ambiguous": self.labeled_ambiguous,
                "unlabeled_alerts": self.unlabeled_alerts,
                "triage_covered_alerts": self.triage_covered_alerts,
                "grounding_verified_fp_proposals": self.grounding_verified_fp_proposals,
                "proposed_fp_on_true_fp": self.proposed_fp_on_true_fp,
                "erroneously_proposed_fp_on_tp": self.erroneously_proposed_fp_on_tp,
                "kept_tp_on_true_tp": self.kept_tp_on_true_tp,
                "kept_tp_on_true_fp": self.kept_tp_on_true_fp,
                "needs_review_total": self.needs_review_total,
                "needs_review_on_tp": self.needs_review_on_tp,
                "needs_review_on_fp": self.needs_review_on_fp,
                "needs_review_on_ambiguous": self.needs_review_on_ambiguous,
                "needs_review_on_unlabeled": self.needs_review_on_unlabeled,
                "fail_safe_review_overrides": self.fail_safe_review_overrides,
                "raw_model_refuted_on_tp": self.raw_model_refuted_on_tp,
                "raw_model_refuted_on_fp": self.raw_model_refuted_on_fp,
                "raw_model_supported_on_tp": self.raw_model_supported_on_tp,
                "raw_model_supported_on_fp": self.raw_model_supported_on_fp,
                "fail_safe_blocked_tp_refutations": self.fail_safe_blocked_tp_refutations,
            },
            "rates": {
                "proposed_fp_removal": self.proposed_fp_removal_rate.to_dict(),
                "erroneous_tp_removal": self.erroneous_tp_removal_rate.to_dict(),
                "raw_model_erroneous_tp_removal": self.raw_model_erroneous_tp_removal_rate.to_dict(),
                "raw_model_fp_removal": self.raw_model_fp_removal_rate.to_dict(),
                "review_escalation": self.review_escalation_rate.to_dict(),
                "triage_coverage": self.triage_coverage_rate.to_dict(),
                "label_coverage": self.label_coverage_rate.to_dict(),
            },
            "latency_ms": self.latency.to_dict(),
        }


@dataclass
class IntegrityAnomalies:
    """Tracks data, protocol, and fail-safe security-review integrity violations."""

    duplicate_alert_ids: list[str] = field(default_factory=list)
    duplicate_label_ids: list[str] = field(default_factory=list)
    duplicate_triage_ids: list[str] = field(default_factory=list)
    unlabeled_alert_ids: list[str] = field(default_factory=list)
    missing_triage_alert_ids: list[str] = field(default_factory=list)
    orphan_triage_ids: list[str] = field(default_factory=list)
    unmatched_or_ambiguous_triage_records: list[dict[str, Any]] = field(default_factory=list)
    cwe_mismatches: list[dict[str, Any]] = field(default_factory=list)
    location_mismatches: list[dict[str, Any]] = field(default_factory=list)
    sha256_mismatches: list[dict[str, Any]] = field(default_factory=list)
    missing_trace_alerts: list[str] = field(default_factory=list)
    missing_or_invalid_citations: list[dict[str, Any]] = field(default_factory=list)
    unverified_source_alerts: list[dict[str, Any]] = field(default_factory=list)
    malformed_triage_records: list[dict[str, Any]] = field(default_factory=list)
    ungrounded_fp_overrides: list[dict[str, Any]] = field(default_factory=list)
    human_approval_violations: list[dict[str, Any]] = field(default_factory=list)
    invalid_ground_truth_labels: list[dict[str, Any]] = field(default_factory=list)
    rejected_auto_generated_labels: list[dict[str, Any]] = field(default_factory=list)
    model_mismatches: list[dict[str, Any]] = field(default_factory=list)
    unverified_scan_provenance: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "duplicate_alert_ids": self.duplicate_alert_ids,
            "duplicate_label_ids": self.duplicate_label_ids,
            "duplicate_triage_ids": self.duplicate_triage_ids,
            "unlabeled_alert_ids": self.unlabeled_alert_ids,
            "missing_triage_alert_ids": self.missing_triage_alert_ids,
            "orphan_triage_ids": self.orphan_triage_ids,
            "unmatched_or_ambiguous_triage_records": self.unmatched_or_ambiguous_triage_records,
            "cwe_mismatches": self.cwe_mismatches,
            "location_mismatches": self.location_mismatches,
            "sha256_mismatches": self.sha256_mismatches,
            "missing_trace_alerts": self.missing_trace_alerts,
            "missing_or_invalid_citations": self.missing_or_invalid_citations,
            "unverified_source_alerts": self.unverified_source_alerts,
            "malformed_triage_records": self.malformed_triage_records,
            "ungrounded_fp_overrides": self.ungrounded_fp_overrides,
            "human_approval_violations": self.human_approval_violations,
            "invalid_ground_truth_labels": self.invalid_ground_truth_labels,
            "rejected_auto_generated_labels": self.rejected_auto_generated_labels,
            "model_mismatches": self.model_mismatches,
            "unverified_scan_provenance": self.unverified_scan_provenance,
        }


def _extract_opengrep_alerts(
    raw_data: Any,
    scan_sha256: str | None = None,
) -> list[dict[str, Any]]:
    """Extract normalized alert records from OpenGrep JSON or normalized alert list."""
    effective_scan_sha = scan_sha256
    if isinstance(raw_data, dict):
        if not effective_scan_sha and codex_adapter.is_valid_sha256(raw_data.get("scan_sha256")):
            effective_scan_sha = str(raw_data["scan_sha256"]).strip().lower()
        if "alerts" in raw_data and isinstance(raw_data["alerts"], list):
            items = raw_data["alerts"]
        elif "results" in raw_data and isinstance(raw_data["results"], list):
            items = raw_data["results"]
        else:
            raise ValueError("OpenGrep data dict must contain 'alerts' or 'results' list.")
    elif isinstance(raw_data, list):
        items = raw_data
    else:
        raise ValueError("OpenGrep input must be a JSON object or list.")

    if effective_scan_sha and not codex_adapter.is_valid_sha256(effective_scan_sha):
        effective_scan_sha = None

    normalized: list[dict[str, Any]] = []
    for idx, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        explicit_id = item.get("alert_id") or item.get("id")
        file_path = codex_adapter.normalize_path(item.get("file_path") or item.get("path") or "")
        start_line = item.get("start_line")
        end_line = item.get("end_line")
        start_col = item.get("start_col")
        end_col = item.get("end_col")
        if isinstance(item.get("start"), dict):
            if start_line is None:
                start_line = item["start"].get("line")
            if start_col is None:
                start_col = item["start"].get("col")
        if isinstance(item.get("end"), dict):
            if end_line is None:
                end_line = item["end"].get("line")
            if end_col is None:
                end_col = item["end"].get("col")
        if end_line is None:
            end_line = start_line

        rule_id = str(item.get("rule_id") or item.get("check_id") or "unknown_rule").strip()
        raw_cwe = item.get("cwe")
        has_trace = bool(item.get("trace") or item.get("dataflow_trace"))
        if isinstance(item.get("extra"), dict):
            metadata = item["extra"].get("metadata", {})
            if raw_cwe is None and isinstance(metadata, dict):
                raw_cwe = metadata.get("cwe")
            if item["extra"].get("dataflow_trace"):
                has_trace = True
        cwe = normalize_cwe(raw_cwe)

        legacy_alert_id = f"{file_path}:{start_line}:{end_line}:{cwe}:{rule_id}:{idx}"
        contract_alert_id = (
            codex_adapter.compute_contract_alert_id(effective_scan_sha, idx)
            if effective_scan_sha
            else None
        )
        alert_id = str(explicit_id or contract_alert_id or legacy_alert_id)

        normalized.append({
            "alert_id": alert_id,
            "contract_alert_id": contract_alert_id,
            "legacy_alert_id": legacy_alert_id,
            "scan_sha256": effective_scan_sha or item.get("scan_sha256"),
            "finding_index": idx,
            "file_path": file_path,
            "start_line": int(start_line) if isinstance(start_line, int) else None,
            "end_line": int(end_line) if isinstance(end_line, int) else None,
            "start_col": int(start_col) if isinstance(start_col, int) else None,
            "end_col": int(end_col) if isinstance(end_col, int) else None,
            "rule_id": rule_id,
            "cwe": cwe,
            "source_sha256": item.get("source_sha256"),
            "has_trace": has_trace,
        })
    return normalized


def _extract_labels(raw_labels: Any) -> list[dict[str, Any]]:
    """Extract ground-truth label list from JSON object or list."""
    if raw_labels is None:
        return []
    if isinstance(raw_labels, dict):
        if "labels" in raw_labels and isinstance(raw_labels["labels"], list):
            return raw_labels["labels"]
        raise ValueError("Labels dict must contain a 'labels' list.")
    if isinstance(raw_labels, list):
        return raw_labels
    raise ValueError("Labels input must be a JSON object, list, or None.")


def parse_triage_inputs(raw_triage: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Parse triage records from a JSON object, list, or raw JSON/JSONL string."""
    valid_records: list[dict[str, Any]] = []
    malformed_records: list[dict[str, Any]] = []

    if isinstance(raw_triage, str):
        text = raw_triage.strip()
        if not text:
            return [], []
        try:
            parsed = json.loads(text)
            return parse_triage_inputs(parsed)
        except json.JSONDecodeError:
            for line_no, line in enumerate(text.splitlines(), start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    obj = json.loads(stripped)
                    if isinstance(obj, dict):
                        valid_records.append(obj)
                    else:
                        malformed_records.append({
                            "line": line_no,
                            "reason": "JSON line is not an object",
                            "raw": stripped[:200],
                        })
                except json.JSONDecodeError as exc:
                    malformed_records.append({
                        "line": line_no,
                        "reason": f"JSONDecodeError: {exc.msg}",
                        "raw": stripped[:200],
                    })
            return valid_records, malformed_records

    if isinstance(raw_triage, dict):
        if "triage_results" in raw_triage and isinstance(raw_triage["triage_results"], list):
            items = raw_triage["triage_results"]
        elif "assessments" in raw_triage and isinstance(raw_triage["assessments"], list):
            items = raw_triage["assessments"]
        elif "results" in raw_triage and isinstance(raw_triage["results"], list):
            items = raw_triage["results"]
        else:
            malformed_records.append({
                "index": 0,
                "reason": "Triage dict missing 'triage_results', 'assessments', or 'results' list",
            })
            return [], malformed_records
    elif isinstance(raw_triage, list):
        items = raw_triage
    else:
        malformed_records.append({
            "index": 0,
            "reason": f"Unsupported triage container type: {type(raw_triage).__name__}",
        })
        return [], malformed_records

    for idx, entry in enumerate(items):
        if isinstance(entry, str):
            try:
                parsed_entry = json.loads(entry)
                if isinstance(parsed_entry, dict):
                    valid_records.append(parsed_entry)
                else:
                    malformed_records.append({
                        "index": idx,
                        "reason": "Embedded JSON string did not decode to an object",
                        "raw": entry[:200],
                    })
            except json.JSONDecodeError as exc:
                malformed_records.append({
                    "index": idx,
                    "reason": f"Malformed JSON string in triage list: {exc.msg}",
                    "raw": entry[:200],
                })
        elif isinstance(entry, dict):
            if "raw_llm_json" in entry and isinstance(entry["raw_llm_json"], str):
                try:
                    llm_payload = json.loads(entry["raw_llm_json"])
                    if not isinstance(llm_payload, dict):
                        raise ValueError("raw_llm_json did not decode to dict")
                    merged = dict(llm_payload)
                    for k, v in entry.items():
                        if k != "raw_llm_json":
                            merged[k] = v
                    valid_records.append(merged)
                except (json.JSONDecodeError, ValueError) as exc:
                    malformed_records.append({
                        "index": idx,
                        "alert_id": entry.get("alert_id") or entry.get("id"),
                        "reason": f"Malformed raw_llm_json: {exc}",
                        "raw": str(entry.get("raw_llm_json"))[:200],
                    })
            else:
                valid_records.append(entry)
        else:
            malformed_records.append({
                "index": idx,
                "reason": f"Triage entry must be dict or JSON string, got {type(entry).__name__}",
            })

    return valid_records, malformed_records


def _load_source_file_lines_and_sha(
    source_root: Path | None,
    rel_file_path: str,
) -> tuple[str | None, dict[int, str], str | None]:
    """Load real Java source file from source_root and compute `(sha256, line_map, error)`."""
    if source_root is None or not rel_file_path:
        return None, {}, None
    root_resolved = source_root.resolve()
    candidate = (root_resolved / rel_file_path).resolve()
    try:
        candidate.relative_to(root_resolved)
    except ValueError:
        return None, {}, f"Alert file_path '{rel_file_path}' escapes source_root"
    if not candidate.is_file():
        # If source_root is already the leaf directory (e.g. v2/evaluation/smoke_evidence)
        # and rel_file_path is v2/evaluation/smoke_evidence/SmokeVulnSample.java, check basename
        fallback = (root_resolved / Path(rel_file_path).name).resolve()
        if (
            fallback.is_file()
            and codex_adapter.paths_match(rel_file_path, fallback.as_posix())
        ):
            candidate = fallback
        else:
            return None, {}, f"Source file not found under source_root: '{rel_file_path}'"
    text = candidate.read_text(encoding="utf-8")
    sha = compute_sha256_text(text)
    line_map = {idx + 1: line for idx, line in enumerate(text.splitlines())}
    return sha, line_map, None


def _is_meaningful_code_line(line_text: str) -> bool:
    """Return True if a source line is non-empty and not a pure comment line."""
    stripped = line_text.strip()
    if not stripped:
        return False
    if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
        return False
    return True


def _validate_evidence_grounding(
    alert: dict[str, Any],
    triage_record: dict[str, Any],
    verified_line_map: dict[int, str],
    require_verified_lines: bool,
    expected_sha: str | None = None,
) -> tuple[bool, str | None]:
    """Verify that a PROPOSED_FP (REFUTED) verdict has grounded citations in verified source."""
    if str(triage_record.get("citation_check") or "").strip().upper() == "NOT_VERIFIED":
        return False, "Codex citation_check is NOT_VERIFIED; cannot accept PROPOSED_FP"

    rationale = triage_record.get("rationale") or triage_record.get("explanation") or ""
    if not isinstance(rationale, str) or len(rationale.strip()) < 10:
        return False, "Missing or insufficient security rationale for FP proposal"

    if triage_record.get("citation_parse_errors"):
        return (
            False,
            f"Invalid citation format: {'; '.join(triage_record['citation_parse_errors'])}",
        )

    cited_paths = triage_record.get("cited_paths") or []
    alert_path = codex_adapter.normalize_path(alert.get("file_path") or "")
    if cited_paths and alert_path:
        for c_path in cited_paths:
            if not codex_adapter.paths_match(c_path, alert_path):
                return (
                    False,
                    f"Citation path '{c_path}' does not match alert file '{alert_path}'",
                )

    cited_lines = triage_record.get("cited_lines") or triage_record.get("evidence_lines")
    if not isinstance(cited_lines, list) or not cited_lines:
        return False, "Missing cited_lines/citations for FP proposal"

    if not all(isinstance(line, int) and not isinstance(line, bool) and line > 0 for line in cited_lines):
        return False, "cited_lines must contain positive integer line numbers"

    context_start = triage_record.get("context_start_line")
    context_end = triage_record.get("context_end_line")
    if isinstance(context_start, int) and isinstance(context_end, int):
        for line in cited_lines:
            if line < context_start or line > context_end:
                return (
                    False,
                    f"Cited line {line} outside extracted context [{context_start}, {context_end}]",
                )

    # Check actual line existence in verified source snapshot or file
    if verified_line_map:
        for line in cited_lines:
            if line not in verified_line_map:
                return (
                    False,
                    f"Cited line {line} does not exist in verified source/snapshot lines",
                )
            if not _is_meaningful_code_line(verified_line_map[line]):
                return (
                    False,
                    f"Cited line {line} is blank or comment-only in verified source/snapshot",
                )
    elif require_verified_lines:
        return (
            False,
            "No verified Java source file or snapshot lines available to confirm cited_lines",
        )

    # Verify per-citation quote text and sha256 if present
    citation_quotes = triage_record.get("citation_quotes") or []
    if isinstance(citation_quotes, list):
        for cq in citation_quotes:
            if not isinstance(cq, dict):
                continue
            c_line = cq.get("line")
            c_start = (
                cq.get("start_line")
                if isinstance(cq.get("start_line"), int) and not isinstance(cq.get("start_line"), bool)
                else (c_line if isinstance(c_line, int) and not isinstance(c_line, bool) else None)
            )
            c_end = (
                cq.get("end_line")
                if isinstance(cq.get("end_line"), int) and not isinstance(cq.get("end_line"), bool)
                else c_start
            )
            c_quote = cq.get("quote")
            c_sha = cq.get("sha256")
            if c_sha and expected_sha and str(c_sha).strip().lower() != str(expected_sha).strip().lower():
                return (
                    False,
                    f"Citation sha256 '{c_sha}' at line {c_start} does not match expected source_sha256 '{expected_sha}'",
                )
            if c_quote is not None and isinstance(c_start, int) and isinstance(c_end, int) and verified_line_map:
                if c_start == c_end and c_start in verified_line_map:
                    actual_line_str = verified_line_map[c_start].strip()
                    quote_str = str(c_quote).strip()
                    if not quote_str or (quote_str != actual_line_str and quote_str not in actual_line_str):
                        return (
                            False,
                            f"Citation quote at line {c_start} ('{quote_str}') does not match verified source line ('{actual_line_str}')",
                        )
                elif c_end > c_start and all(lno in verified_line_map for lno in range(c_start, c_end + 1)):
                    span_lines = [verified_line_map[lno] for lno in range(c_start, c_end + 1)]
                    actual_block = "\n".join(span_lines)
                    actual_norm = "\n".join(line.strip() for line in span_lines).strip()
                    quote_norm = "\n".join(line.strip() for line in str(c_quote).splitlines()).strip()
                    if not quote_norm or (quote_norm != actual_norm and quote_norm not in actual_block):
                        return (
                            False,
                            f"Citation quote at lines {c_start}-{c_end} ('{quote_norm}') does not match verified source lines ('{actual_norm}')",
                        )

    return True, None


def _get_tier_for_cwe(cwe: str) -> str:
    if cwe in PRIORITY_CWES:
        return "PRIORITY_TIER_1"
    if cwe in SECONDARY_CWES:
        return "SECONDARY_TIER_2"
    return "OTHER_CWE"


def evaluate_pilot(
    opengrep_data: Any,
    labels_data: Any,
    triage_data: Any,
    opengrep_scan_time_ms: float | None = None,
    source_root: Path | str | None = None,
    expected_scan_sha256: str | None = None,
    expected_model_prefix: str | None = None,
    require_scan_provenance: bool = False,
) -> dict[str, Any]:
    """Evaluate OpenGrep standalone vs. OpenGrep + Qwen triage on locked alerts and labels."""
    anomalies = IntegrityAnomalies()
    source_root_path = Path(source_root) if source_root else None

    # 1. Deduplicate and index OpenGrep alerts
    inferred_scan_sha = expected_scan_sha256
    if not inferred_scan_sha and isinstance(labels_data, dict):
        cand_sha = labels_data.get("scan_sha256")
        if codex_adapter.is_valid_sha256(cand_sha):
            inferred_scan_sha = str(cand_sha).strip().lower()
    raw_alerts = _extract_opengrep_alerts(opengrep_data, scan_sha256=inferred_scan_sha)
    alerts_by_id: dict[str, dict[str, Any]] = {}
    alias_to_canonical_id: dict[str, str] = {}
    unique_alerts_ordered: list[dict[str, Any]] = []
    for alert in raw_alerts:
        aid = alert["alert_id"]
        if aid in alerts_by_id:
            anomalies.duplicate_alert_ids.append(aid)
            continue
        alerts_by_id[aid] = alert
        alias_to_canonical_id[aid] = aid
        if alert.get("contract_alert_id"):
            alias_to_canonical_id[str(alert["contract_alert_id"])] = aid
        if alert.get("legacy_alert_id"):
            alias_to_canonical_id[str(alert["legacy_alert_id"])] = aid
        unique_alerts_ordered.append(alert)

    # 2. Deduplicate and index Ground-Truth Labels (rejecting LLM auto-generated labels)
    raw_labels = _extract_labels(labels_data)
    labels_by_id: dict[str, dict[str, Any]] = {}
    for idx, label in enumerate(raw_labels):
        if not isinstance(label, dict):
            anomalies.invalid_ground_truth_labels.append({
                "index": idx,
                "reason": "Label entry is not a dict",
            })
            continue
        raw_aid = str(label.get("alert_id") or label.get("id") or "").strip()
        if not raw_aid:
            anomalies.invalid_ground_truth_labels.append({
                "index": idx,
                "reason": "Missing alert_id in label",
            })
            continue
        aid = alias_to_canonical_id.get(raw_aid, raw_aid)

        # Detect forbidden auto-generated labels from Qwen/Codex outputs
        annotator = str(
            label.get("annotated_by")
            or label.get("label_source")
            or label.get("generated_by")
            or ""
        ).strip().lower()
        has_codex_assessment = isinstance(label.get("assessment"), dict) or (
            "ground_truth" not in label and ("verdict" in label or "status" in label)
        )
        if has_codex_assessment or any(tok in annotator for tok in FORBIDDEN_AUTO_LABEL_SOURCES):
            anomalies.rejected_auto_generated_labels.append({
                "alert_id": aid,
                "annotated_by": annotator or "model_output",
                "reason": "Ground-truth labels must be independent; auto-generated LLM verdicts are forbidden",
            })
            continue

        # Validate label provenance when label_type / ground_truth_type is claimed
        lbl_type = str(label.get("label_type") or label.get("ground_truth_type") or "").strip().upper()
        rationale_txt = str(label.get("annotator_rationale") or label.get("rationale") or "").strip()
        if lbl_type == "INDEPENDENT_GROUND_TRUTH":
            if not annotator or any(tok in annotator for tok in FORBIDDEN_INDEPENDENT_LABEL_ANNOTATORS):
                anomalies.invalid_ground_truth_labels.append({
                    "alert_id": aid,
                    "annotated_by": annotator or "MISSING",
                    "label_type": lbl_type,
                    "reason": (
                        "Label claims INDEPENDENT_GROUND_TRUTH but is missing human annotated_by "
                        f"or uses agent/synthetic annotator '{annotator or 'MISSING'}'"
                    ),
                })
                continue
            if len(rationale_txt) < 10:
                anomalies.invalid_ground_truth_labels.append({
                    "alert_id": aid,
                    "label_type": lbl_type,
                    "reason": "Label claims INDEPENDENT_GROUND_TRUTH without substantive annotator_rationale (>=10 chars)",
                })
                continue
        elif lbl_type and not annotator:
            anomalies.invalid_ground_truth_labels.append({
                "alert_id": aid,
                "label_type": lbl_type,
                "reason": "Label with explicit label_type is missing annotated_by attribution",
            })
            continue

        if aid in labels_by_id:
            anomalies.duplicate_label_ids.append(aid)
            continue

        gt = str(label.get("ground_truth") or "").strip().upper()
        if gt not in VALID_GROUND_TRUTH:
            anomalies.invalid_ground_truth_labels.append({
                "alert_id": aid,
                "ground_truth": gt,
                "reason": f"Invalid ground_truth '{gt}'; expected one of {sorted(VALID_GROUND_TRUTH)}",
            })
            continue
        labels_by_id[aid] = {
            **label,
            "alert_id": aid,
            "ground_truth": gt,
            "cwe": normalize_cwe(label.get("cwe")),
        }

    # 3. Parse, convert (Codex nested -> normalized), and deduplicate Triage records
    parsed_triage_raw, malformed_triage = parse_triage_inputs(triage_data)
    anomalies.malformed_triage_records.extend(malformed_triage)

    converted_triage, mapping_errors = codex_adapter.match_and_convert_codex_records(
        parsed_triage_raw,
        unique_alerts_ordered,
        expected_scan_sha256=expected_scan_sha256,
    )
    anomalies.unmatched_or_ambiguous_triage_records.extend(mapping_errors)

    malformed_alert_ids: set[str] = {
        str(m["alert_id"])
        for m in malformed_triage
        if isinstance(m, dict) and m.get("alert_id")
    }

    triage_by_id: dict[str, dict[str, Any]] = {}
    for idx, rec in enumerate(converted_triage):
        aid = str(rec.get("alert_id") or "").strip()
        if not aid:
            anomalies.malformed_triage_records.append({
                "index": idx,
                "reason": "Triage record missing alert_id after mapping",
            })
            continue
        if aid in triage_by_id:
            anomalies.duplicate_triage_ids.append(aid)
            continue
        triage_by_id[aid] = rec

    for aid in triage_by_id:
        if aid not in alerts_by_id:
            anomalies.orphan_triage_ids.append(aid)

    # 4. Initialize buckets: overall, priority tier, secondary tier, and per-CWE
    overall_bucket = CweBucketMetrics(cwe="ALL", tier="OVERALL")
    priority_bucket = CweBucketMetrics(cwe="PRIORITY (CWE-22, CWE-89)", tier="PRIORITY_TIER_1")
    secondary_bucket = CweBucketMetrics(cwe="SECONDARY (CWE-78, CWE-79)", tier="SECONDARY_TIER_2")
    per_cwe_buckets: dict[str, CweBucketMetrics] = {
        cwe: CweBucketMetrics(cwe=cwe, tier=_get_tier_for_cwe(cwe))
        for cwe in ALL_SUPPORTED_CWES
    }

    per_alert_decisions: list[dict[str, Any]] = []
    provenance_counts: dict[str, int] = {
        "VERIFIED_CAPTURE": 0,
        "UNVERIFIED_CAPTURE": 0,
        "HISTORICAL_UNBUNDLED": 0,
    }

    # 5. Evaluate each alert in the locked OpenGrep scan
    for aid, alert in alerts_by_id.items():
        alert_cwe = alert["cwe"]
        if alert_cwe not in per_cwe_buckets:
            per_cwe_buckets[alert_cwe] = CweBucketMetrics(
                cwe=alert_cwe,
                tier=_get_tier_for_cwe(alert_cwe),
            )
        cwe_bucket = per_cwe_buckets[alert_cwe]

        target_buckets = [overall_bucket, cwe_bucket]
        if alert_cwe in PRIORITY_CWES:
            target_buckets.append(priority_bucket)
        elif alert_cwe in SECONDARY_CWES:
            target_buckets.append(secondary_bucket)

        for b in target_buckets:
            b.total_alerts += 1

        # Match ground-truth label
        label = labels_by_id.get(aid)
        label_cwe_mismatch = False
        duplicate_label_conflict = aid in anomalies.duplicate_label_ids
        if duplicate_label_conflict:
            gt_status = "UNLABELED"
            if aid not in anomalies.unlabeled_alert_ids:
                anomalies.unlabeled_alert_ids.append(aid)
        elif label is None:
            anomalies.unlabeled_alert_ids.append(aid)
            gt_status = "UNLABELED"
        else:
            lbl_line = label.get("start_line") if label.get("start_line") is not None else label.get("line")
            lbl_fidx = label.get("finding_index")
            if label["cwe"] != "UNKNOWN_CWE" and label["cwe"] != alert_cwe:
                anomalies.cwe_mismatches.append({
                    "alert_id": aid,
                    "stage": "alert_vs_label",
                    "alert_cwe": alert_cwe,
                    "label_cwe": label["cwe"],
                })
                label_cwe_mismatch = True
                gt_status = "UNLABELED"
                anomalies.unlabeled_alert_ids.append(aid)
            elif (
                label.get("file_path")
                and alert.get("file_path")
                and not codex_adapter.paths_match(label["file_path"], alert["file_path"])
            ):
                anomalies.location_mismatches.append({
                    "alert_id": aid,
                    "alert_file_path": alert["file_path"],
                    "label_file_path": codex_adapter.normalize_path(label["file_path"]),
                })
                gt_status = "UNLABELED"
                anomalies.unlabeled_alert_ids.append(aid)
            elif (
                isinstance(lbl_line, int)
                and not isinstance(lbl_line, bool)
                and alert.get("start_line") is not None
                and int(lbl_line) != int(alert["start_line"])
            ):
                anomalies.location_mismatches.append({
                    "alert_id": aid,
                    "stage": "alert_vs_label_line",
                    "alert_start_line": alert["start_line"],
                    "label_start_line": lbl_line,
                })
                gt_status = "UNLABELED"
                anomalies.unlabeled_alert_ids.append(aid)
            elif (
                isinstance(lbl_fidx, int)
                and not isinstance(lbl_fidx, bool)
                and isinstance(alert.get("finding_index"), int)
                and int(lbl_fidx) != int(alert["finding_index"])
            ):
                anomalies.location_mismatches.append({
                    "alert_id": aid,
                    "stage": "alert_vs_label_finding_index",
                    "alert_finding_index": alert["finding_index"],
                    "label_finding_index": lbl_fidx,
                })
                gt_status = "UNLABELED"
                anomalies.unlabeled_alert_ids.append(aid)
            else:
                gt_status = label["ground_truth"]

        for b in target_buckets:
            if gt_status == "TRUE_POSITIVE":
                b.labeled_tp += 1
            elif gt_status == "FALSE_POSITIVE":
                b.labeled_fp += 1
            elif gt_status == "AMBIGUOUS":
                b.labeled_ambiguous += 1
            else:
                b.unlabeled_alerts += 1

        # Load real Java file from source_root if provided
        disk_sha, disk_lines, disk_err = _load_source_file_lines_and_sha(
            source_root_path, alert.get("file_path") or ""
        )

        # Match and validate Qwen / Codex triage output
        triage = triage_by_id.get(aid)
        override_reasons: list[str] = []
        triage_covered = False
        latency_val: float | None = None

        if label_cwe_mismatch:
            override_reasons.append("label_cwe_mismatch")
        if duplicate_label_conflict:
            override_reasons.append("duplicate_label_id")

        raw_model_mapped: str | None = None
        prov_status: str | None = None
        if triage is None:
            if aid not in malformed_alert_ids:
                anomalies.missing_triage_alert_ids.append(aid)
            effective_verdict = "REVIEW"
            override_reasons.append("missing_or_unmatched_triage_output")
        else:
            if not alert.get("has_trace") and not triage.get("has_trace"):
                anomalies.missing_trace_alerts.append(aid)

            raw_verdict = str(triage.get("verdict") or triage.get("status") or "").strip().upper()
            raw_m_stat = str(
                triage.get("raw_model_status")
                or triage.get("raw_codex_status")
                or raw_verdict
            ).strip().upper()
            if raw_m_stat in VALID_MODEL_VERDICTS:
                raw_model_mapped = VALID_MODEL_VERDICTS[raw_m_stat]

            if triage.get("has_error"):
                anomalies.malformed_triage_records.append({
                    "alert_id": aid,
                    "reason": "Codex assessment reported runtime/model error",
                })
                effective_verdict = "REVIEW"
                override_reasons.append("triage_runtime_error")
            elif raw_verdict not in VALID_MODEL_VERDICTS:
                anomalies.malformed_triage_records.append({
                    "alert_id": aid,
                    "reason": f"Invalid model verdict '{raw_verdict}'",
                })
                effective_verdict = "REVIEW"
                override_reasons.append("invalid_model_verdict")
            else:
                triage_covered = True
                effective_verdict = VALID_MODEL_VERDICTS[raw_verdict]

            if aid in anomalies.duplicate_triage_ids:
                effective_verdict = "REVIEW"
                override_reasons.append("duplicate_triage_id")

            # Check scan_provenance and evidence_issues from Codex c36bc12
            prov_obj = triage.get("scan_provenance")
            prov_status = triage.get("scan_provenance_status")
            if not prov_status:
                if isinstance(prov_obj, dict):
                    prov_status = (
                        "VERIFIED_CAPTURE"
                        if prov_obj.get("source_capture_verified") is True
                        else "UNVERIFIED_CAPTURE"
                    )
                else:
                    prov_status = "HISTORICAL_UNBUNDLED"
            if prov_status in provenance_counts:
                provenance_counts[prov_status] += 1

            ev_issues = triage.get("evidence_issues") or []
            if prov_status == "UNVERIFIED_CAPTURE" or bool(ev_issues):
                anomalies.unverified_scan_provenance.append({
                    "alert_id": aid,
                    "scan_provenance_status": prov_status,
                    "origin": prov_obj.get("origin") if isinstance(prov_obj, dict) else None,
                    "evidence_issues": ev_issues,
                    "reason": "Scan provenance explicitly unverified or evidence issues present",
                })
                effective_verdict = "REVIEW"
                override_reasons.append("unverified_scan_provenance")
            elif require_scan_provenance and prov_status != "VERIFIED_CAPTURE":
                anomalies.unverified_scan_provenance.append({
                    "alert_id": aid,
                    "scan_provenance_status": prov_status,
                    "reason": "Strict provenance mode requires scan_provenance.source_capture_verified == True",
                })
                effective_verdict = "REVIEW"
                override_reasons.append("missing_verified_scan_provenance")

            # Verify model family/prefix if expected_model_prefix is specified
            triage_model = str(triage.get("model_id") or triage.get("model") or "").strip()
            if expected_model_prefix:
                if not triage_model or not triage_model.lower().startswith(expected_model_prefix.strip().lower()):
                    anomalies.model_mismatches.append({
                        "alert_id": aid,
                        "expected_model_prefix": expected_model_prefix,
                        "actual_model_id": triage_model or "MISSING",
                    })
                    effective_verdict = "REVIEW"
                    override_reasons.append(f"model_mismatch:{triage_model or 'MISSING'}")

            # Check intra-file location / line / finding_index consistency on triage record
            t_line = triage.get("start_line")
            t_fidx = triage.get("finding_index")
            if (
                triage.get("file_path")
                and alert.get("file_path")
                and not codex_adapter.paths_match(triage["file_path"], alert["file_path"])
            ):
                anomalies.location_mismatches.append({
                    "alert_id": aid,
                    "stage": "alert_vs_triage_path",
                    "alert_file_path": alert["file_path"],
                    "triage_file_path": codex_adapter.normalize_path(triage["file_path"]),
                })
                effective_verdict = "REVIEW"
                override_reasons.append("triage_file_path_mismatch")
            elif (
                isinstance(t_line, int)
                and not isinstance(t_line, bool)
                and alert.get("start_line") is not None
                and int(t_line) != int(alert["start_line"])
            ):
                anomalies.location_mismatches.append({
                    "alert_id": aid,
                    "stage": "alert_vs_triage_line",
                    "alert_start_line": alert["start_line"],
                    "triage_start_line": t_line,
                })
                effective_verdict = "REVIEW"
                override_reasons.append("triage_line_mismatch")
            elif (
                isinstance(t_fidx, int)
                and not isinstance(t_fidx, bool)
                and isinstance(alert.get("finding_index"), int)
                and int(t_fidx) != int(alert["finding_index"])
            ):
                anomalies.location_mismatches.append({
                    "alert_id": aid,
                    "stage": "alert_vs_triage_finding_index",
                    "alert_finding_index": alert["finding_index"],
                    "triage_finding_index": t_fidx,
                })
                effective_verdict = "REVIEW"
                override_reasons.append("triage_finding_index_mismatch")

            # Record latency if valid
            raw_latency = triage.get("latency_ms")
            if isinstance(raw_latency, (int, float)) and not isinstance(raw_latency, bool):
                if float(raw_latency) >= 0.0 and not math.isnan(float(raw_latency)):
                    latency_val = float(raw_latency)

            # Check CWE consistency between OpenGrep alert and Triage record
            if triage.get("cwe") is not None:
                triage_cwe = normalize_cwe(triage.get("cwe"))
                if triage_cwe != alert_cwe:
                    anomalies.cwe_mismatches.append({
                        "alert_id": aid,
                        "stage": "alert_vs_triage",
                        "alert_cwe": alert_cwe,
                        "triage_cwe": triage_cwe,
                    })
                    effective_verdict = "REVIEW"
                    override_reasons.append("triage_cwe_mismatch")
            if isinstance(triage.get("evidence_cwes"), list):
                ev_cwes = [normalize_cwe(c) for c in triage["evidence_cwes"] if c]
                if ev_cwes and ev_cwes != ["UNKNOWN_CWE"] and alert_cwe not in ev_cwes:
                    anomalies.cwe_mismatches.append({
                        "alert_id": aid,
                        "stage": "alert_vs_evidence_cwe",
                        "alert_cwe": alert_cwe,
                        "evidence_cwes": ev_cwes,
                    })
                    effective_verdict = "REVIEW"
                    override_reasons.append("evidence_cwe_mismatch")

            # Check human approval bypass (never auto-dismiss without human confirmation)
            if bool(triage.get("auto_dismissed", False)):
                anomalies.human_approval_violations.append({
                    "alert_id": aid,
                    "reason": "auto_dismissed=True is forbidden; human confirmation is required",
                })
                effective_verdict = "REVIEW"
                override_reasons.append("human_approval_bypass")
            elif bool(triage.get("human_confirmed", False)) and not str(
                triage.get("human_reviewer") or ""
            ).strip():
                anomalies.human_approval_violations.append({
                    "alert_id": aid,
                    "reason": "human_confirmed=True without human_reviewer identifier",
                })
                effective_verdict = "REVIEW"
                override_reasons.append("missing_human_reviewer_id")

            # Check SHA-256 integrity across alert, label, triage snapshot, and disk file
            expected_sha = (
                (label.get("source_sha256") if label else None)
                or alert.get("source_sha256")
                or disk_sha
            )
            triage_sha = triage.get("source_sha256")

            if disk_err and effective_verdict == "PROPOSED_FP":
                anomalies.unverified_source_alerts.append({
                    "alert_id": aid,
                    "reason": disk_err,
                })
                effective_verdict = "REVIEW"
                override_reasons.append(f"unverified_source:{disk_err}")

            if disk_sha and expected_sha and str(disk_sha).lower() != str(expected_sha).lower():
                anomalies.sha256_mismatches.append({
                    "alert_id": aid,
                    "stage": "disk_vs_expected",
                    "disk_sha256": disk_sha,
                    "expected_sha256": expected_sha,
                })
                effective_verdict = "REVIEW"
                override_reasons.append("disk_source_sha256_mismatch")

            if expected_sha and triage_sha and str(expected_sha).lower() != str(triage_sha).lower():
                anomalies.sha256_mismatches.append({
                    "alert_id": aid,
                    "stage": "expected_vs_triage",
                    "expected_sha256": expected_sha,
                    "triage_sha256": triage_sha,
                })
                effective_verdict = "REVIEW"
                override_reasons.append("source_sha256_mismatch")
            elif effective_verdict == "PROPOSED_FP":
                # P0 Rule 1: SHA-256 is mandatory when accepting a REFUTED / PROPOSED_FP proposal
                is_codex_record = "raw_codex_status" in triage
                if is_codex_record or source_root_path is not None or expected_sha is not None:
                    if not expected_sha or not triage_sha:
                        anomalies.sha256_mismatches.append({
                            "alert_id": aid,
                            "stage": "missing_sha256_on_proposed_fp",
                            "expected_sha256": expected_sha,
                            "triage_sha256": triage_sha,
                        })
                        effective_verdict = "REVIEW"
                        override_reasons.append("missing_mandatory_sha256_for_fp_proposal")

            # Build verified source line map from disk file or SHA-verified snapshot/snippet
            verified_line_map: dict[int, str] = {}
            if disk_lines:
                verified_line_map.update(disk_lines)
            elif isinstance(triage.get("verified_source_lines"), dict):
                verified_line_map.update(triage["verified_source_lines"])
            elif triage.get("source_lines") is not None:
                verified_line_map.update(
                    codex_adapter._extract_lines_from_text_or_list(triage["source_lines"])
                )

            require_verified_lines = (
                "raw_codex_status" in triage
                or source_root_path is not None
                or bool(verified_line_map)
            )

            # Check evidence grounding if model proposes FP dismissal
            if effective_verdict == "PROPOSED_FP":
                grounded, ungrounded_reason = _validate_evidence_grounding(
                    alert,
                    triage,
                    verified_line_map=verified_line_map,
                    require_verified_lines=require_verified_lines,
                    expected_sha=expected_sha or triage_sha,
                )
                if not grounded:
                    anomalies.missing_or_invalid_citations.append({
                        "alert_id": aid,
                        "reason": ungrounded_reason,
                    })
                    anomalies.ungrounded_fp_overrides.append({
                        "alert_id": aid,
                        "reason": ungrounded_reason,
                    })
                    effective_verdict = "REVIEW"
                    override_reasons.append(f"ungrounded_fp:{ungrounded_reason}")

        # Update bucket counters
        for b in target_buckets:
            if triage_covered:
                b.triage_covered_alerts += 1
            if latency_val is not None:
                b.latency_samples_ms.append(latency_val)
            if override_reasons:
                b.fail_safe_review_overrides += 1

            # Layer 2: Raw model TP/FP classification before citation/fail-safe overrides
            if raw_model_mapped == "PROPOSED_FP":
                if gt_status == "TRUE_POSITIVE":
                    b.raw_model_refuted_on_tp += 1
                    if effective_verdict != "PROPOSED_FP":
                        b.fail_safe_blocked_tp_refutations += 1
                elif gt_status == "FALSE_POSITIVE":
                    b.raw_model_refuted_on_fp += 1
            elif raw_model_mapped == "KEEP_TP":
                if gt_status == "TRUE_POSITIVE":
                    b.raw_model_supported_on_tp += 1
                elif gt_status == "FALSE_POSITIVE":
                    b.raw_model_supported_on_fp += 1

            if effective_verdict == "PROPOSED_FP":
                b.grounding_verified_fp_proposals += 1
                if gt_status == "FALSE_POSITIVE":
                    b.proposed_fp_on_true_fp += 1
                elif gt_status == "TRUE_POSITIVE":
                    b.erroneously_proposed_fp_on_tp += 1
                else:
                    # Ambiguous or unlabeled alerts cannot be counted as confirmed FP removals;
                    # route them to human review in scoring
                    b.needs_review_total += 1
                    if gt_status == "AMBIGUOUS":
                        b.needs_review_on_ambiguous += 1
                    else:
                        b.needs_review_on_unlabeled += 1
            elif effective_verdict == "KEEP_TP":
                if gt_status == "TRUE_POSITIVE":
                    b.kept_tp_on_true_tp += 1
                elif gt_status == "FALSE_POSITIVE":
                    b.kept_tp_on_true_fp += 1
                else:
                    b.needs_review_total += 1
                    if gt_status == "AMBIGUOUS":
                        b.needs_review_on_ambiguous += 1
                    else:
                        b.needs_review_on_unlabeled += 1
            else:
                # REVIEW / UNDETERMINED
                b.needs_review_total += 1
                if gt_status == "TRUE_POSITIVE":
                    b.needs_review_on_tp += 1
                elif gt_status == "FALSE_POSITIVE":
                    b.needs_review_on_fp += 1
                elif gt_status == "AMBIGUOUS":
                    b.needs_review_on_ambiguous += 1
                else:
                    b.needs_review_on_unlabeled += 1

        effective_source_sha = (
            (label.get("source_sha256") if label else None)
            or alert.get("source_sha256")
            or (triage.get("source_sha256") if triage else None)
            or disk_sha
        )
        per_alert_decisions.append({
            "alert_id": aid,
            "contract_alert_id": alert.get("contract_alert_id"),
            "finding_index": alert.get("finding_index"),
            "scan_sha256": expected_scan_sha256 or alert.get("scan_sha256") or (triage.get("scan_sha256") if triage else None),
            "source_sha256": effective_source_sha,
            "cwe": alert_cwe,
            "rule_id": alert.get("rule_id"),
            "file_path": alert["file_path"],
            "start_line": alert["start_line"],
            "end_line": alert.get("end_line"),
            "ground_truth": gt_status,
            "label_type": (
                (label.get("label_type") or label.get("ground_truth_type"))
                if label
                else None
            ),
            "arm_a_baseline": "KEEP",
            "raw_model_status": triage.get("raw_model_status") if triage else None,
            "raw_codex_status": triage.get("raw_codex_status") if triage else None,
            "scan_provenance_status": prov_status,
            "citation_check": triage.get("citation_check") if triage else None,
            "cited_lines": triage.get("cited_lines") if triage else None,
            "model_id": triage.get("model_id") if triage else None,
            "human_review_state": (
                (triage.get("human_review_state") or "OPEN")
                if triage
                else "OPEN"
            ),
            "effective_verdict": (
                "REVIEW"
                if gt_status in ("AMBIGUOUS", "UNLABELED")
                else effective_verdict
            ),
            "proposal_only": True,
            "requires_human_confirmation": True,
            "retained_for_human_review": True,
            "triage_covered": triage_covered,
            "override_reasons": override_reasons,
            "latency_ms": latency_val,
        })

    arm_a_analyst_workload = overall_bucket.total_alerts
    arm_b_proposed_fp_candidates = (
        overall_bucket.proposed_fp_on_true_fp + overall_bucket.erroneously_proposed_fp_on_tp
    )

    return {
        "schema_version": "ntk-v2-m4-m5-eval-1.1",
        "arms": {
            "arm_a_opengrep_standalone": {
                "total_alerts_emitted": overall_bucket.total_alerts,
                "true_positives_present": overall_bucket.labeled_tp,
                "false_positives_present": overall_bucket.labeled_fp,
                "ambiguous_present": overall_bucket.labeled_ambiguous,
                "unlabeled_present": overall_bucket.unlabeled_alerts,
                "analyst_mandatory_review_count": arm_a_analyst_workload,
                "erroneously_dropped_tp": RatioMetric(0, overall_bucket.labeled_tp).to_dict(),
                "scan_time_ms": opengrep_scan_time_ms,
            },
            "arm_b_opengrep_plus_qwen": {
                "total_alerts_evaluated": overall_bucket.total_alerts,
                "auto_dismissed_alerts": 0,
                "alerts_retained_pending_human_confirmation": overall_bucket.total_alerts,
                "grounding_verified_fp_proposals": overall_bucket.grounding_verified_fp_proposals,
                "proposed_fp_for_human_confirmation": arm_b_proposed_fp_candidates,
                "true_fp_correctly_proposed_for_removal": (
                    overall_bucket.proposed_fp_removal_rate.to_dict()
                ),
                "true_tp_erroneously_proposed_for_removal": (
                    overall_bucket.erroneous_tp_removal_rate.to_dict()
                ),
                "needs_further_review": overall_bucket.review_escalation_rate.to_dict(),
                "triage_coverage": overall_bucket.triage_coverage_rate.to_dict(),
                "triage_latency_ms": overall_bucket.latency.to_dict(),
                "grounding_disclaimer": (
                    "Formal citation and SHA-256 verification only gates whether a REFUTED "
                    "output may be surfaced as a PROPOSED_FP candidate; it does NOT prove "
                    "the security conclusion is correct without independent human labels."
                ),
            },
        },
        "summary": {
            "overall": overall_bucket.to_dict(),
            "priority_tier_1": priority_bucket.to_dict(),
            "secondary_tier_2": secondary_bucket.to_dict(),
            "by_cwe": {cwe: bucket.to_dict() for cwe, bucket in per_cwe_buckets.items()},
        },
        "anomalies": anomalies.to_dict(),
        "scan_provenance_summary": {
            "require_scan_provenance": require_scan_provenance,
            **provenance_counts,
        },
        "per_alert_decisions": per_alert_decisions,
    }


def render_markdown_report(report: dict[str, Any], is_fixture: bool = False) -> str:
    """Render a concise Markdown table summary of the evaluation report."""
    banner = (
        "> [!WARNING]\n"
        "> **SYNTHETIC TEST FIXTURE OUTPUT** — Do not cite as real benchmark evidence.\n\n"
        if is_fixture
        else ""
    )
    lines: list[str] = [
        "# NTK Thesis V2 — M4/M5 Evaluation Summary",
        "",
    ]
    if banner:
        lines.append(banner)

    lines.extend([
        "## Per-CWE & Tier Triage Breakdown (OpenGrep + Local Qwen vs. Ground Truth)",
        "",
        "| Scope / CWE | Tier | Total Alerts | Labeled TP | Labeled FP | Proposed FP Removal (True FP) | Erroneously Proposed TP Removal | Needs Review (`REVIEW`) | Triage Coverage | Mean / P95 Latency (ms) |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ])

    summary = report["summary"]
    rows_to_render = [
        summary["overall"],
        summary["priority_tier_1"],
        summary["secondary_tier_2"],
        *[summary["by_cwe"][cwe] for cwe in summary["by_cwe"]],
    ]

    for row in rows_to_render:
        counts = row["counts"]
        rates = row["rates"]
        lat = row["latency_ms"]
        lat_str = (
            f"{lat['mean_ms']} / {lat['p95_ms']}"
            if lat["mean_ms"] is not None
            else "N/A"
        )
        lines.append(
            f"| `{row['cwe']}` | {row['tier']} | {counts['total_alerts']} | "
            f"{counts['labeled_tp']} | {counts['labeled_fp']} | "
            f"{rates['proposed_fp_removal']['display']} | "
            f"{rates['erroneous_tp_removal']['display']} | "
            f"{rates['review_escalation']['display']} | "
            f"{rates['triage_coverage']['display']} | {lat_str} |"
        )

    anom = report["anomalies"]
    lines.extend([
        "",
        "## Integrity & Fail-Safe Security Review Checks",
        "",
        f"- **Duplicate Alert IDs**: {len(anom['duplicate_alert_ids'])}",
        f"- **Duplicate Label IDs**: {len(anom['duplicate_label_ids'])}",
        f"- **Duplicate Triage IDs**: {len(anom['duplicate_triage_ids'])}",
        f"- **Unlabeled Alerts**: {len(anom['unlabeled_alert_ids'])}",
        f"- **Unmatched / Ambiguous Triage Mappings**: {len(anom['unmatched_or_ambiguous_triage_records'])}",
        f"- **CWE Join Mismatches**: {len(anom['cwe_mismatches'])}",
        f"- **Source SHA-256 Mismatches / Missing**: {len(anom['sha256_mismatches'])}",
        f"- **Missing / Invalid Source Citations**: {len(anom['missing_or_invalid_citations'])}",
        f"- **Malformed Triage JSON Records**: {len(anom['malformed_triage_records'])}",
        f"- **Ungrounded FP Overridden to REVIEW**: {len(anom['ungrounded_fp_overrides'])}",
        f"- **Human Approval Violations**: {len(anom['human_approval_violations'])}",
        f"- **Rejected Auto-Generated Labels**: {len(anom['rejected_auto_generated_labels'])}",
        "",
    ])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Score NTK Thesis V2 M4/M5 OpenGrep vs. OpenGrep+Qwen pilot evaluation."
    )
    parser.add_argument("--opengrep", required=True, help="Path to locked OpenGrep JSON file.")
    parser.add_argument("--labels", help="Optional path to locked ground-truth labels JSON.")
    parser.add_argument("--triage", required=True, help="Path to Qwen/Codex triage JSON or JSONL.")
    parser.add_argument("--source-root", help="Optional root directory of Java source files.")
    parser.add_argument("--scan-time-ms", type=float, default=None, help="OpenGrep scan time (ms).")
    parser.add_argument("--output-json", help="Optional path to write full evaluation JSON.")
    parser.add_argument("--output-md", help="Optional path to write Markdown report.")
    parser.add_argument(
        "--fixture",
        action="store_true",
        help="Mark output as synthetic TEST FIXTURE.",
    )
    parser.add_argument(
        "--require-scan-provenance",
        action="store_true",
        help="Require scan_provenance.source_capture_verified == True on every triage record.",
    )
    args = parser.parse_args(argv)

    opengrep_raw = json.loads(Path(args.opengrep).read_text(encoding="utf-8"))
    labels_raw = (
        json.loads(Path(args.labels).read_text(encoding="utf-8"))
        if args.labels
        else []
    )
    triage_raw_text = Path(args.triage).read_text(encoding="utf-8")

    report = evaluate_pilot(
        opengrep_data=opengrep_raw,
        labels_data=labels_raw,
        triage_data=triage_raw_text,
        opengrep_scan_time_ms=args.scan_time_ms,
        source_root=args.source_root,
        require_scan_provenance=args.require_scan_provenance,
    )
    if args.fixture:
        report["fixture_notice"] = (
            "TEST FIXTURE ONLY - Synthetic test data, not real OpenGrep or Qwen benchmark output."
        )

    if args.output_json:
        out_json_path = Path(args.output_json)
        out_json_path.parent.mkdir(parents=True, exist_ok=True)
        out_json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    md_text = render_markdown_report(report, is_fixture=args.fixture)
    if args.output_md:
        out_md_path = Path(args.output_md)
        out_md_path.parent.mkdir(parents=True, exist_ok=True)
        out_md_path.write_text(md_text, encoding="utf-8")
    else:
        print(md_text)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
