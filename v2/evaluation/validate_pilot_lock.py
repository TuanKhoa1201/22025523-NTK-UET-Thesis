"""NTK Thesis V2 — M3/M4 Locked Evaluation & Source Grounding Validator.

Provides two core verification capabilities using only the Python standard library:
1. M4 Pilot Lock Verification: Validates that the OpenGrep scan output and independent
   ground-truth labels meet pilot protocol constraints (e.g., 30-60 alerts, CWE-22/89
   priority coverage, 1-to-1 ID/CWE/path alignment, non-empty annotator rationale) and
   computes/verifies a cryptographic SHA-256 lock manifest to prevent test-set tuning.
2. M3 Source & Line Grounding Verification: Verifies that `source_sha256` matches actual
   Java source files on disk and that LLM `cited_lines` point to real, non-empty,
   non-comment-only code lines within the target file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

import score_pilot


def compute_file_sha256(path: Path) -> str:
    """Compute hex SHA-256 of raw file bytes."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_pilot_dataset(
    opengrep_data: Any,
    labels_data: Any,
    min_alerts: int = 30,
    max_alerts: int = 60,
    min_priority_share: float = 0.5,
) -> dict[str, Any]:
    """Validate M4 locked pilot dataset readiness and alignment between alerts and labels."""
    alerts = score_pilot._extract_opengrep_alerts(opengrep_data)
    labels = score_pilot._extract_labels(labels_data)

    errors: list[str] = []
    warnings: list[str] = []

    alert_ids: dict[str, dict[str, Any]] = {}
    for alert in alerts:
        aid = alert["alert_id"]
        if aid in alert_ids:
            errors.append(f"Duplicate alert_id in OpenGrep input: {aid}")
        else:
            alert_ids[aid] = alert

    label_ids: dict[str, dict[str, Any]] = {}
    for idx, label in enumerate(labels):
        if not isinstance(label, dict):
            errors.append(f"Label at index {idx} is not a JSON object")
            continue
        aid = str(label.get("alert_id") or "").strip()
        if not aid:
            errors.append(f"Label at index {idx} is missing alert_id")
            continue
        if aid in label_ids:
            errors.append(f"Duplicate alert_id in labels input: {aid}")
            continue
        label_ids[aid] = label

        gt = str(label.get("ground_truth") or "").strip().upper()
        if gt not in score_pilot.VALID_GROUND_TRUTH:
            errors.append(f"Label {aid} has invalid ground_truth: '{gt}'")

        rationale = str(label.get("annotator_rationale") or label.get("rationale") or "").strip()
        if len(rationale) < 10:
            errors.append(f"Label {aid} is missing a substantive annotator_rationale (>=10 chars)")

        if not str(label.get("source_sha256") or "").strip():
            warnings.append(f"Label {aid} is missing source_sha256")

    # Check 1-to-1 coverage and CWE/path match
    for aid, alert in alert_ids.items():
        if aid not in label_ids:
            errors.append(f"OpenGrep alert {aid} is missing a ground-truth label")
            continue
        lbl = label_ids[aid]
        lbl_cwe = score_pilot.normalize_cwe(lbl.get("cwe"))
        if lbl_cwe != alert["cwe"]:
            errors.append(
                f"CWE mismatch on {aid}: OpenGrep has {alert['cwe']} vs label {lbl_cwe}"
            )
        lbl_path = str(lbl.get("file_path") or "").replace("\\", "/")
        if lbl_path and alert["file_path"] and lbl_path != alert["file_path"]:
            errors.append(
                f"File path mismatch on {aid}: OpenGrep has {alert['file_path']} vs label {lbl_path}"
            )

    for aid in label_ids:
        if aid not in alert_ids:
            warnings.append(f"Orphan ground-truth label {aid} not present in OpenGrep alerts")

    total_unique = len(alert_ids)
    if total_unique < min_alerts or total_unique > max_alerts:
        warnings.append(
            f"Total unique alerts ({total_unique}) outside target pilot window [{min_alerts}, {max_alerts}]"
        )

    priority_count = sum(
        1 for a in alert_ids.values() if a["cwe"] in score_pilot.PRIORITY_CWES
    )
    secondary_count = sum(
        1 for a in alert_ids.values() if a["cwe"] in score_pilot.SECONDARY_CWES
    )
    priority_share = (priority_count / total_unique) if total_unique > 0 else 0.0
    if total_unique > 0 and priority_share < min_priority_share:
        warnings.append(
            f"Priority CWE-22/CWE-89 share ({priority_share:.1%}) is below target {min_priority_share:.1%}"
        )

    return {
        "valid_lock_candidate": len(errors) == 0,
        "total_unique_alerts": total_unique,
        "total_unique_labels": len(label_ids),
        "priority_cwe_alerts": priority_count,
        "secondary_cwe_alerts": secondary_count,
        "priority_cwe_share": round(priority_share, 4),
        "errors": errors,
        "warnings": warnings,
    }


def verify_source_grounding(
    source_root: Path,
    alerts_data: Any,
    triage_data: Any,
) -> dict[str, Any]:
    """Verify source_sha256 and cited_lines against real Java source files under source_root."""
    alerts = score_pilot._extract_opengrep_alerts(alerts_data)
    alerts_by_id = {a["alert_id"]: a for a in alerts}
    triage_records, malformed = score_pilot.parse_triage_inputs(triage_data)

    violations: list[dict[str, Any]] = []
    verified_count = 0

    for rec in triage_records:
        aid = str(rec.get("alert_id") or "")
        alert = alerts_by_id.get(aid)
        if alert is None:
            violations.append({
                "alert_id": aid,
                "type": "unknown_alert_id",
                "detail": "Triage alert_id not found in OpenGrep alerts",
            })
            continue

        rel_path = alert["file_path"]
        file_path = (source_root / rel_path).resolve()
        try:
            file_path.relative_to(source_root.resolve())
        except ValueError:
            violations.append({
                "alert_id": aid,
                "type": "path_traversal_outside_root",
                "detail": f"Alert path {rel_path} resolves outside source_root",
            })
            continue

        if not file_path.is_file():
            violations.append({
                "alert_id": aid,
                "type": "missing_source_file",
                "detail": f"Source file not found: {rel_path}",
            })
            continue

        source_text = file_path.read_text(encoding="utf-8")
        actual_text_sha = score_pilot.compute_sha256_text(source_text)
        actual_bytes_sha = compute_file_sha256(file_path)

        expected_sha = rec.get("source_sha256") or alert.get("source_sha256")
        if expected_sha and expected_sha not in (actual_text_sha, actual_bytes_sha):
            violations.append({
                "alert_id": aid,
                "type": "source_sha256_mismatch",
                "detail": f"Expected {expected_sha}, got {actual_text_sha}",
            })
            continue

        lines = source_text.splitlines()
        cited_lines = rec.get("cited_lines") or rec.get("evidence_lines") or []
        if not isinstance(cited_lines, list) or not cited_lines:
            violations.append({
                "alert_id": aid,
                "type": "missing_cited_lines",
                "detail": "No cited_lines provided",
            })
            continue

        line_error = False
        for line_no in cited_lines:
            if not isinstance(line_no, int) or line_no < 1 or line_no > len(lines):
                violations.append({
                    "alert_id": aid,
                    "type": "cited_line_out_of_bounds",
                    "detail": f"Cited line {line_no} outside file line count 1..{len(lines)}",
                })
                line_error = True
                break
            code_line = lines[line_no - 1].strip()
            if not code_line or code_line.startswith("//") or code_line.startswith("/*") or code_line.startswith("*"):
                violations.append({
                    "alert_id": aid,
                    "type": "cited_line_blank_or_comment",
                    "detail": f"Cited line {line_no} is blank or comment-only: '{code_line}'",
                })
                line_error = True
                break

        if not line_error:
            verified_count += 1

    return {
        "total_triage_records": len(triage_records),
        "malformed_triage_records": len(malformed),
        "verified_grounded_records": verified_count,
        "grounding_pass": len(violations) == 0 and len(malformed) == 0,
        "violations": violations,
    }


def create_lock_manifest(
    opengrep_path: Path,
    labels_path: Path,
    config_path: Path | None = None,
) -> dict[str, Any]:
    """Create a deterministic M4 lock manifest with SHA-256 digests of evaluation inputs."""
    og_sha = compute_file_sha256(opengrep_path)
    lb_sha = compute_file_sha256(labels_path)
    cfg_sha = compute_file_sha256(config_path) if config_path and config_path.is_file() else None

    combined = f"opengrep:{og_sha}|labels:{lb_sha}|config:{cfg_sha or 'none'}"
    lock_digest = score_pilot.compute_sha256_text(combined)

    return {
        "schema_version": "ntk-v2-m4-lock-1.0",
        "opengrep_file": opengrep_path.name,
        "opengrep_sha256": og_sha,
        "labels_file": labels_path.name,
        "labels_sha256": lb_sha,
        "config_file": config_path.name if config_path else None,
        "config_sha256": cfg_sha,
        "combined_lock_sha256": lock_digest,
    }


def verify_lock_manifest(
    manifest: dict[str, Any],
    opengrep_path: Path,
    labels_path: Path,
    config_path: Path | None = None,
) -> tuple[bool, list[str]]:
    """Verify current files on disk match a previously recorded M4 lock manifest."""
    current = create_lock_manifest(opengrep_path, labels_path, config_path)
    mismatches: list[str] = []
    for key in ("opengrep_sha256", "labels_sha256", "config_sha256", "combined_lock_sha256"):
        if manifest.get(key) != current.get(key):
            mismatches.append(
                f"Lock mismatch for {key}: expected {manifest.get(key)}, got {current.get(key)}"
            )
    return len(mismatches) == 0, mismatches


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate M4 locked pilot dataset and M3 source grounding."
    )
    parser.add_argument("--opengrep", required=True, help="Path to OpenGrep JSON file.")
    parser.add_argument("--labels", required=True, help="Path to ground-truth labels JSON file.")
    parser.add_argument("--min-alerts", type=int, default=30, help="Minimum pilot alerts.")
    parser.add_argument("--max-alerts", type=int, default=60, help="Maximum pilot alerts.")
    parser.add_argument("--write-lock", help="Optional path to write M4 lock manifest JSON.")
    parser.add_argument("--verify-lock", help="Optional path to verify existing M4 lock manifest.")
    args = parser.parse_args(argv)

    og_path = Path(args.opengrep)
    lb_path = Path(args.labels)
    og_data = json.loads(og_path.read_text(encoding="utf-8"))
    lb_data = json.loads(lb_path.read_text(encoding="utf-8"))

    validation = validate_pilot_dataset(
        og_data,
        lb_data,
        min_alerts=args.min_alerts,
        max_alerts=args.max_alerts,
    )

    if args.write_lock:
        manifest = create_lock_manifest(og_path, lb_path)
        Path(args.write_lock).write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        validation["lock_manifest"] = manifest

    if args.verify_lock:
        saved_manifest = json.loads(Path(args.verify_lock).read_text(encoding="utf-8"))
        ok, lock_errors = verify_lock_manifest(saved_manifest, og_path, lb_path)
        validation["lock_verified"] = ok
        validation["errors"].extend(lock_errors)
        validation["valid_lock_candidate"] = len(validation["errors"]) == 0

    print(json.dumps(validation, indent=2))
    return 0 if validation["valid_lock_candidate"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
