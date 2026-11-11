"""NTK Thesis V2 — Codex Assessment Adapter & Deterministic Alert Matcher.

Bridges Codex's `assessment.jsonl` / `assessments.jsonl` output format
(`v2/triage/cli.py`, `evidence.py`, `ollama.py`) to `v2/evaluation/score_pilot.py`.

Key responsibilities:
1. Convert Codex statuses (`SUPPORTED`, `REFUTED`, `UNDETERMINED`) to scoring statuses
   (`KEEP_TP`, `PROPOSED_FP`, `REVIEW`).
2. Extract nested `id`, `evidence` (`raw_finding`, `cwe`, `snapshots`, `snippets`, `trace`),
   and `assessment` (`status`, `citations`, `explanation`).
3. Perform a reproducible, deterministic 1-to-1 mapping between original OpenGrep JSON
   findings (`scan_sha256`, finding order, canonical location/rule/CWE/fingerprint) and
   Codex assessment records without assuming Codex `id` equals `score_pilot` `alert_id`.
4. Extract verified source lines from SHA-256-matched snapshots/snippets or `source_root`
   so `REFUTED -> PROPOSED_FP` is only accepted when cited lines truly exist in the verified
   Java file snapshot.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any

CODEX_STATUS_MAP: dict[str, str] = {
    "SUPPORTED": "KEEP_TP",
    "REFUTED": "PROPOSED_FP",
    "UNDETERMINED": "REVIEW",
}

HEX_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def is_valid_sha256(value: Any) -> bool:
    """Return True if value is a valid 64-character hex SHA-256 string."""
    return isinstance(value, str) and bool(HEX_SHA256_RE.match(value.strip()))


def normalize_path(raw_path: Any) -> str:
    """Normalize a file path to forward slashes without leading './'."""
    if not isinstance(raw_path, str):
        return ""
    cleaned = raw_path.strip().replace("\\", "/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return cleaned


def normalize_cwe_value(raw_cwe: Any) -> str:
    """Normalize a string or list of CWE strings to a canonical 'CWE-<num>' string."""
    if isinstance(raw_cwe, list):
        for item in raw_cwe:
            norm = normalize_cwe_value(item)
            if norm != "UNKNOWN_CWE":
                return norm
        return "UNKNOWN_CWE"
    if not isinstance(raw_cwe, str):
        return "UNKNOWN_CWE"
    token = raw_cwe.strip().upper()
    if not token:
        return "UNKNOWN_CWE"
    if ":" in token:
        token = token.split(":", 1)[0].strip()
    if " " in token:
        token = token.split(" ", 1)[0].strip()
    if token.isdigit():
        return f"CWE-{token}"
    if token.startswith("CWE-") and token[4:].isdigit():
        return f"CWE-{int(token[4:])}"
    return token


def normalize_cwe_list(raw_cwe: Any) -> list[str]:
    """Return all normalized CWEs from a string or list."""
    if isinstance(raw_cwe, list):
        result: list[str] = []
        for item in raw_cwe:
            norm = normalize_cwe_value(item)
            if norm != "UNKNOWN_CWE" and norm not in result:
                result.append(norm)
        return result or ["UNKNOWN_CWE"]
    norm = normalize_cwe_value(raw_cwe)
    return [norm]


def canonical_finding_signature(finding: dict[str, Any]) -> tuple[str, int | None, int | None, int | None, int | None, str, str]:
    """Build a deterministic canonical tuple from an OpenGrep raw_finding or alert dict."""
    file_path = normalize_path(finding.get("file_path") or finding.get("path") or "")

    start_line = finding.get("start_line")
    start_col = finding.get("start_col")
    if isinstance(finding.get("start"), dict):
        if start_line is None:
            start_line = finding["start"].get("line")
        if start_col is None:
            start_col = finding["start"].get("col")

    end_line = finding.get("end_line")
    end_col = finding.get("end_col")
    if isinstance(finding.get("end"), dict):
        if end_line is None:
            end_line = finding["end"].get("line")
        if end_col is None:
            end_col = finding["end"].get("col")
    if end_line is None:
        end_line = start_line

    rule_id = str(finding.get("rule_id") or finding.get("check_id") or "unknown_rule").strip()

    raw_cwe = finding.get("cwe")
    if raw_cwe is None and isinstance(finding.get("extra"), dict):
        metadata = finding["extra"].get("metadata", {})
        if isinstance(metadata, dict):
            raw_cwe = metadata.get("cwe")
    cwe = normalize_cwe_value(raw_cwe)

    return (
        file_path,
        int(start_line) if isinstance(start_line, int) else None,
        int(end_line) if isinstance(end_line, int) else None,
        int(start_col) if isinstance(start_col, int) else None,
        int(end_col) if isinstance(end_col, int) else None,
        rule_id,
        cwe,
    )


def _extract_lines_from_text_or_list(
    content: Any,
    start_line: int = 1,
) -> dict[int, str]:
    """Convert a string or list of lines/dicts into a 1-based `{line_number: line_text}` map."""
    line_map: dict[int, str] = {}
    if isinstance(content, str):
        for offset, text in enumerate(content.splitlines()):
            line_map[start_line + offset] = text
    elif isinstance(content, list):
        for offset, item in enumerate(content):
            if isinstance(item, str):
                line_map[start_line + offset] = item
            elif isinstance(item, dict):
                lno = item.get("line") or item.get("line_number") or item.get("lineno")
                txt = item.get("content") if item.get("content") is not None else item.get("text")
                if isinstance(lno, int) and isinstance(txt, str):
                    line_map[lno] = txt
    elif isinstance(content, dict):
        for k, v in content.items():
            if str(k).isdigit() and isinstance(v, str):
                line_map[int(k)] = v
    return line_map


def extract_snapshot_and_lines(
    evidence: dict[str, Any],
    target_path: str,
) -> tuple[str | None, dict[int, str], bool]:
    """Extract `(source_sha256, verified_line_map, has_trace)` from Codex `evidence` dict."""
    norm_target = normalize_path(target_path)
    found_sha: str | None = None
    verified_lines: dict[int, str] = {}

    # Check direct source_sha256 on evidence or raw_finding
    for candidate_key in ("source_sha256", "sha256", "file_sha256"):
        val = evidence.get(candidate_key)
        if is_valid_sha256(val):
            found_sha = str(val).strip().lower()
            break
    if not found_sha and isinstance(evidence.get("raw_finding"), dict):
        rf = evidence["raw_finding"]
        for candidate_key in ("source_sha256", "sha256", "file_sha256"):
            val = rf.get(candidate_key)
            if is_valid_sha256(val):
                found_sha = str(val).strip().lower()
                break

    # Extract from snapshots (can be dict keyed by path, single snapshot dict, or list of dicts)
    snapshots = evidence.get("snapshots")
    snapshot_list: list[dict[str, Any]] = []
    if isinstance(snapshots, dict):
        if any(k in snapshots for k in ("content", "lines", "sha256", "source_sha256", "path", "file_path")):
            snapshot_list.append(snapshots)
        else:
            for k_path, snap_val in snapshots.items():
                if isinstance(snap_val, dict):
                    snapshot_list.append({"path": k_path, **snap_val})
                elif isinstance(snap_val, str):
                    snapshot_list.append({"path": k_path, "content": snap_val})
    elif isinstance(snapshots, list):
        snapshot_list.extend(s for s in snapshots if isinstance(s, dict))

    for snap in snapshot_list:
        snap_path = normalize_path(snap.get("path") or snap.get("file_path") or norm_target)
        if norm_target and snap_path and snap_path != norm_target:
            continue
        snap_sha = snap.get("sha256") or snap.get("source_sha256")
        content = snap.get("content") if snap.get("content") is not None else snap.get("text")
        if isinstance(content, str) and not is_valid_sha256(snap_sha):
            snap_sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if is_valid_sha256(snap_sha) and not found_sha:
            found_sha = str(snap_sha).strip().lower()

        start_l = snap.get("start_line") if isinstance(snap.get("start_line"), int) else 1
        if content is not None:
            verified_lines.update(_extract_lines_from_text_or_list(content, start_line=start_l))
        if snap.get("lines") is not None:
            verified_lines.update(_extract_lines_from_text_or_list(snap["lines"], start_line=start_l))

    # Extract from snippets (list or dict)
    snippets = evidence.get("snippets")
    snippet_list: list[dict[str, Any]] = []
    if isinstance(snippets, list):
        snippet_list.extend(s for s in snippets if isinstance(s, dict))
    elif isinstance(snippets, dict):
        snippet_list.append(snippets)

    for snip in snippet_list:
        snip_path = normalize_path(snip.get("path") or snip.get("file_path") or norm_target)
        if norm_target and snip_path and snip_path != norm_target:
            continue
        snip_sha = snip.get("sha256") or snip.get("source_sha256")
        if is_valid_sha256(snip_sha) and not found_sha:
            found_sha = str(snip_sha).strip().lower()
        start_l = snip.get("start_line") if isinstance(snip.get("start_line"), int) else 1
        for field_name in ("lines", "content", "snippet", "code", "text"):
            if snip.get(field_name) is not None:
                verified_lines.update(
                    _extract_lines_from_text_or_list(snip[field_name], start_line=start_l)
                )

    # Check whether trace / dataflow evidence is present
    has_trace = False
    if evidence.get("trace") or evidence.get("dataflow_trace"):
        has_trace = True
    elif isinstance(evidence.get("raw_finding"), dict):
        rf_extra = evidence["raw_finding"].get("extra")
        if isinstance(rf_extra, dict) and rf_extra.get("dataflow_trace"):
            has_trace = True

    return found_sha, verified_lines, has_trace


def parse_codex_citations(
    raw_citations: Any,
    default_path: str = "",
) -> tuple[list[int], list[str], list[str]]:
    """Parse Codex `assessment.citations` into `(cited_lines, cited_paths, citation_errors)`.

    Supports:
    - integers: `[42, 43]`
    - dicts: `[{"path": "A.java", "line": 42}, {"start_line": 42, "end_line": 44}]`
    - strings: `["src/A.java:42", "L42-L44", "42"]`
    """
    cited_lines: list[int] = []
    cited_paths: list[str] = []
    errors: list[str] = []

    if not isinstance(raw_citations, list):
        return [], [], ["citations field is missing or not a list"]

    for idx, item in enumerate(raw_citations):
        if isinstance(item, int) and not isinstance(item, bool):
            if item > 0:
                if item not in cited_lines:
                    cited_lines.append(item)
            else:
                errors.append(f"Citation at index {idx} has non-positive line number: {item}")
        elif isinstance(item, dict):
            c_path = normalize_path(item.get("path") or item.get("file_path") or default_path)
            if c_path and c_path not in cited_paths:
                cited_paths.append(c_path)
            line_single = item.get("line") if item.get("line") is not None else item.get("line_number")
            start_l = item.get("start_line")
            end_l = item.get("end_line")
            if isinstance(line_single, int) and not isinstance(line_single, bool) and line_single > 0:
                if line_single not in cited_lines:
                    cited_lines.append(line_single)
            elif isinstance(start_l, int) and start_l > 0:
                stop_l = end_l if isinstance(end_l, int) and end_l >= start_l else start_l
                for lno in range(start_l, min(stop_l, start_l + 50) + 1):
                    if lno not in cited_lines:
                        cited_lines.append(lno)
            else:
                errors.append(f"Citation dict at index {idx} has no valid line/start_line")
        elif isinstance(item, str):
            token = item.strip()
            if not token:
                errors.append(f"Empty citation string at index {idx}")
                continue
            # Match optional path:line or L<start>-L<end>
            m_path_line = re.match(r"^(?:(.+?):)?L?(\d+)(?:\s*-\s*L?(\d+))?$", token)
            if m_path_line:
                c_path = normalize_path(m_path_line.group(1) or default_path)
                if c_path and c_path not in cited_paths:
                    cited_paths.append(c_path)
                s_l = int(m_path_line.group(2))
                e_l = int(m_path_line.group(3)) if m_path_line.group(3) else s_l
                if s_l > 0 and e_l >= s_l:
                    for lno in range(s_l, min(e_l, s_l + 50) + 1):
                        if lno not in cited_lines:
                            cited_lines.append(lno)
                else:
                    errors.append(f"Invalid line range in citation '{token}'")
            else:
                errors.append(f"Unparseable citation string '{token}'")
        else:
            errors.append(f"Unsupported citation item type at index {idx}: {type(item).__name__}")

    return cited_lines, cited_paths, errors


def is_codex_assessment_record(record: dict[str, Any]) -> bool:
    """Return True if a dict looks like a Codex `assessments.jsonl` record."""
    if not isinstance(record, dict):
        return False
    if isinstance(record.get("assessment"), dict) or isinstance(record.get("evidence"), dict):
        return True
    if str(record.get("status") or "").strip().upper() in CODEX_STATUS_MAP:
        return True
    if str(record.get("verdict") or "").strip().upper() in CODEX_STATUS_MAP:
        return True
    return False


def convert_single_codex_record(
    record: dict[str, Any],
    record_index: int = 0,
) -> dict[str, Any]:
    """Normalize a single Codex record (nested or flat) into an intermediate assessment dict."""
    codex_id = str(record.get("id") or record.get("finding_id") or f"codex-{record_index}").strip()
    explicit_alert_id = str(record.get("alert_id") or "").strip() or None

    evidence = record.get("evidence") if isinstance(record.get("evidence"), dict) else {}
    assessment = record.get("assessment") if isinstance(record.get("assessment"), dict) else {}

    raw_finding = (
        evidence.get("raw_finding")
        if isinstance(evidence.get("raw_finding"), dict)
        else (record.get("raw_finding") if isinstance(record.get("raw_finding"), dict) else {})
    )

    # Extract target path, lines, rule_id, CWE from evidence / raw_finding / record
    merged_finding_view: dict[str, Any] = {
        **raw_finding,
        **{k: v for k, v in evidence.items() if k not in ("raw_finding", "snapshots", "snippets") and v is not None},
        **{k: v for k, v in record.items() if k in ("file_path", "path", "start_line", "end_line", "rule_id", "check_id") and v is not None},
    }
    sig = canonical_finding_signature(merged_finding_view)
    file_path, start_line, end_line, start_col, end_col, rule_id, evidence_cwe = sig

    evidence_cwes = normalize_cwe_list(
        evidence.get("cwe") if evidence.get("cwe") is not None else raw_finding.get("cwe")
    )
    if evidence_cwes == ["UNKNOWN_CWE"] and evidence_cwe != "UNKNOWN_CWE":
        evidence_cwes = [evidence_cwe]

    # Check if assessment overrides or states its own CWE conclusion
    assessment_cwe_raw = assessment.get("cwe") or record.get("cwe")
    assessment_cwe = (
        normalize_cwe_value(assessment_cwe_raw)
        if assessment_cwe_raw is not None
        else evidence_cwes[0]
    )

    # Status conversion
    raw_status = str(
        assessment.get("status")
        or assessment.get("verdict")
        or record.get("status")
        or record.get("verdict")
        or ""
    ).strip().upper()

    has_error = bool(assessment.get("error") or record.get("error"))
    if has_error:
        mapped_verdict = "REVIEW"
    elif raw_status in CODEX_STATUS_MAP:
        mapped_verdict = CODEX_STATUS_MAP[raw_status]
    else:
        mapped_verdict = raw_status  # Let score_pilot flag invalid model verdict if unknown

    # Citations & explanation
    raw_citations = (
        assessment.get("citations")
        if assessment.get("citations") is not None
        else (
            record.get("cited_lines")
            if record.get("cited_lines") is not None
            else record.get("evidence_lines")
        )
    )
    cited_lines, cited_paths, citation_parse_errors = parse_codex_citations(
        raw_citations, default_path=file_path
    )

    explanation = str(
        assessment.get("explanation")
        or assessment.get("rationale")
        or record.get("rationale")
        or record.get("explanation")
        or ""
    ).strip()

    # Extract snapshots, snippets, and source_sha256
    snap_sha, verified_lines, has_trace = extract_snapshot_and_lines(evidence, file_path)
    top_sha = record.get("source_sha256") or assessment.get("source_sha256")
    source_sha256 = (
        str(top_sha).strip().lower()
        if is_valid_sha256(top_sha)
        else snap_sha
    )

    # Extract latency if available
    latency_ms = (
        assessment.get("latency_ms")
        or assessment.get("duration_ms")
        or record.get("latency_ms")
        or record.get("duration_ms")
    )

    # Extract auto_dismissed / human confirmation flags from either level
    auto_dismissed = bool(
        record.get("auto_dismissed", False) or assessment.get("auto_dismissed", False)
    )
    human_confirmed = bool(
        record.get("human_confirmed", False) or assessment.get("human_confirmed", False)
    )
    human_reviewer = (
        record.get("human_reviewer") or assessment.get("human_reviewer")
    )

    finding_index = (
        evidence.get("finding_index")
        if isinstance(evidence.get("finding_index"), int)
        else (record.get("finding_index") if isinstance(record.get("finding_index"), int) else None)
    )
    scan_sha256 = (
        evidence.get("scan_sha256")
        or record.get("scan_sha256")
    )

    return {
        "codex_id": codex_id,
        "alert_id": explicit_alert_id,
        "finding_index": finding_index,
        "scan_sha256": scan_sha256,
        "canonical_signature": sig,
        "file_path": file_path,
        "start_line": start_line,
        "end_line": end_line,
        "rule_id": rule_id,
        "cwe": assessment_cwe,
        "evidence_cwes": evidence_cwes,
        "raw_codex_status": raw_status,
        "verdict": mapped_verdict,
        "cited_lines": cited_lines,
        "cited_paths": cited_paths,
        "citation_parse_errors": citation_parse_errors,
        "rationale": explanation,
        "source_sha256": source_sha256,
        "verified_source_lines": verified_lines,
        "has_trace": has_trace,
        "has_error": has_error,
        "latency_ms": latency_ms,
        "auto_dismissed": auto_dismissed,
        "human_confirmed": human_confirmed,
        "human_reviewer": human_reviewer,
    }


def match_and_convert_codex_records(
    raw_records: list[dict[str, Any]],
    opengrep_alerts: list[dict[str, Any]],
    expected_scan_sha256: str | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Deterministically map Codex assessment records 1-to-1 onto OpenGrep alerts.

    Never guesses:
    - If `scan_sha256` conflicts, rejects mapping.
    - Matches by verified `alert_id`, verified `finding_index` + signature, or unique
      canonical signature `(file_path, start_line, end_line, start_col, end_col, rule_id, cwe)`.
    - If multiple identical OpenGrep alerts share the exact signature and cannot be
      disambiguated by `finding_index`, marks them as ambiguous and routes to REVIEW.
    """
    converted_list: list[dict[str, Any]] = []
    mapping_errors: list[dict[str, Any]] = []

    alerts_by_id: dict[str, dict[str, Any]] = {a["alert_id"]: a for a in opengrep_alerts}
    alerts_by_index: dict[int, dict[str, Any]] = {
        idx: a for idx, a in enumerate(opengrep_alerts)
    }

    # Index OpenGrep alerts by canonical signature and by relaxed location+rule signature
    sig_to_alert_ids: dict[tuple[Any, ...], list[str]] = {}
    loc_rule_to_alert_ids: dict[tuple[Any, ...], list[str]] = {}
    for a in opengrep_alerts:
        sig = canonical_finding_signature(a)
        sig_to_alert_ids.setdefault(sig, []).append(a["alert_id"])
        loc_rule = (sig[0], sig[1], sig[2], sig[5])  # (file_path, start_line, end_line, rule_id)
        loc_rule_to_alert_ids.setdefault(loc_rule, []).append(a["alert_id"])

    claimed_alert_ids: set[str] = set()

    for idx, rec in enumerate(raw_records):
        if not is_codex_assessment_record(rec):
            # Already a flat score_pilot record; pass through while normalizing status if needed
            converted_list.append(rec)
            continue

        norm = convert_single_codex_record(rec, record_index=idx)

        # 1. Verify scan_sha256 if both sides provide it
        if (
            expected_scan_sha256
            and norm.get("scan_sha256")
            and str(norm["scan_sha256"]).strip().lower() != expected_scan_sha256.strip().lower()
        ):
            mapping_errors.append({
                "codex_id": norm["codex_id"],
                "reason": (
                    f"scan_sha256 mismatch: expected {expected_scan_sha256}, "
                    f"got {norm['scan_sha256']}"
                ),
            })
            continue

        matched_aid: str | None = None
        sig = norm["canonical_signature"]
        loc_rule = (sig[0], sig[1], sig[2], sig[5])

        # 2. Try explicit alert_id if it exists in alerts_by_id and does not conflict on location
        if norm["alert_id"] and norm["alert_id"] in alerts_by_id:
            candidate_alert = alerts_by_id[norm["alert_id"]]
            if (
                norm["file_path"]
                and candidate_alert["file_path"]
                and norm["file_path"] != candidate_alert["file_path"]
            ):
                mapping_errors.append({
                    "codex_id": norm["codex_id"],
                    "alert_id": norm["alert_id"],
                    "reason": (
                        f"Explicit alert_id {norm['alert_id']} location conflict: "
                        f"{norm['file_path']} vs {candidate_alert['file_path']}"
                    ),
                })
                continue
            matched_aid = norm["alert_id"]

        # 3. Try explicit finding_index if provided and signature matches
        if matched_aid is None and isinstance(norm["finding_index"], int):
            idx_alert = alerts_by_index.get(norm["finding_index"])
            if idx_alert is not None:
                idx_sig = canonical_finding_signature(idx_alert)
                if (idx_sig[0], idx_sig[1], idx_sig[2], idx_sig[5]) == loc_rule:
                    matched_aid = idx_alert["alert_id"]
                else:
                    mapping_errors.append({
                        "codex_id": norm["codex_id"],
                        "finding_index": norm["finding_index"],
                        "reason": "finding_index signature does not match OpenGrep alert at that index",
                    })
                    continue

        # 4. Try unique canonical signature match
        if matched_aid is None:
            exact_candidates = sig_to_alert_ids.get(sig, [])
            if len(exact_candidates) == 1:
                matched_aid = exact_candidates[0]
            elif len(exact_candidates) > 1:
                mapping_errors.append({
                    "codex_id": norm["codex_id"],
                    "candidates": exact_candidates,
                    "reason": (
                        "Ambiguous mapping: multiple OpenGrep alerts share identical canonical "
                        "signature without finding_index disambiguation"
                    ),
                })
                continue
            else:
                # Check if location+rule matches uniquely (e.g., when model concluded a different CWE)
                loc_candidates = loc_rule_to_alert_ids.get(loc_rule, [])
                if len(loc_candidates) == 1:
                    matched_aid = loc_candidates[0]
                elif len(loc_candidates) > 1:
                    mapping_errors.append({
                        "codex_id": norm["codex_id"],
                        "candidates": loc_candidates,
                        "reason": "Ambiguous location+rule match across multiple alerts",
                    })
                    continue

        # 5. Last check: did Codex use `id` equal to an OpenGrep `alert_id` when no raw_finding was embedded?
        if matched_aid is None and norm["codex_id"] in alerts_by_id and not norm["file_path"]:
            matched_aid = norm["codex_id"]

        if matched_aid is None:
            mapping_errors.append({
                "codex_id": norm["codex_id"],
                "file_path": norm["file_path"],
                "start_line": norm["start_line"],
                "rule_id": norm["rule_id"],
                "reason": "Could not deterministically match Codex record to any OpenGrep alert",
            })
            continue

        if matched_aid in claimed_alert_ids:
            # Allow score_pilot duplicate_triage_ids tracker to also see the duplicate alert_id
            mapping_errors.append({
                "codex_id": norm["codex_id"],
                "alert_id": matched_aid,
                "reason": f"Duplicate Codex assessment mapping to already-claimed alert {matched_aid}",
            })

        claimed_alert_ids.add(matched_aid)
        norm["alert_id"] = matched_aid
        converted_list.append(norm)

    return converted_list, mapping_errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Convert Codex assessments.jsonl to score_pilot schema with 1-to-1 verification."
    )
    parser.add_argument("--opengrep", required=True, help="Path to locked OpenGrep JSON file.")
    parser.add_argument("--assessments", required=True, help="Path to Codex assessments.jsonl.")
    parser.add_argument("--output", required=True, help="Path to write converted JSON.")
    args = parser.parse_args(argv)

    import score_pilot

    og_raw = json.loads(Path(args.opengrep).read_text(encoding="utf-8"))
    og_alerts = score_pilot._extract_opengrep_alerts(og_raw)
    triage_raw_text = Path(args.assessments).read_text(encoding="utf-8")
    parsed_records, malformed = score_pilot.parse_triage_inputs(triage_raw_text)

    converted, mapping_errors = match_and_convert_codex_records(parsed_records, og_alerts)
    payload = {
        "schema_version": "ntk-v2-codex-converted-1.0",
        "converted_count": len(converted),
        "malformed_records": malformed,
        "mapping_errors": mapping_errors,
        "triage_results": converted,
    }
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return 0 if not malformed and not mapping_errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
