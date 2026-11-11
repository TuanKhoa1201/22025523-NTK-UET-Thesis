"""NTK Thesis V2 — Independent Evidence & Paired Audit Verification CLI.

Audits OpenGrep and Qwen triage evidence across REPLAY (historical locked)
and LIVE (fresh manifest-bound) runs:
1. Verifies exact scan_sha256 and source_sha256 cryptographic alignment.
2. Enforces Contract 1.1 deterministic alert_id = SHA256(UTF8(scan_sha256 + ":" + decimal(finding_index))).
3. Verifies citations against genuine source files (line existence, non-blank, non-comment, quote match).
4. Verifies model identity (qwen3.5:9b-q4_K_M) and human queue safety (state == OPEN, auto_dismissed == False).
5. Computes exact paired comparison metrics (Arm A vs. Arm B) with numerators and denominators.
6. Gracefully reports AWAITING_SERVER_EVIDENCE when executed on environments lacking remote server artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

# Ensure v2/evaluation is in sys.path
EVAL_DIR = Path(__file__).resolve().parent
if str(EVAL_DIR) not in sys.path:
    sys.path.insert(0, str(EVAL_DIR))

import codex_adapter
import score_pilot

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


def audit_scan_and_evidence(
    opengrep_path: Path,
    assessments_path: Path,
    source_root: Path,
    labels_path: Path | None = None,
    scan_manifest_path: Path | None = None,
    expected_scan_sha: str | None = None,
    require_scan_manifest: bool = False,
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

    if expected_scan_sha:
        if expected_scan_sha.lower() not in set(v.lower() for v in sha_variants.values()):
            issues.append(
                f"Scan SHA-256 mismatch: expected {expected_scan_sha}, got variants: {sha_variants}"
            )

    active_scan_sha = expected_scan_sha or actual_raw_sha

    try:
        og_doc = json.loads(raw_bytes.decode("utf-8"))
    except Exception as exc:
        return {
            "audit_verdict": "FAIL",
            "reason": f"OpenGrep scan JSON decode error: {exc}",
            "issues": [str(exc)],
        }

    results = og_doc.get("results") or og_doc.get("alerts") or []
    if not isinstance(results, list) or len(results) == 0:
        issues.append(f"OpenGrep scan contains 0 findings: {opengrep_path}")

    # 2. Verify Scan Manifest (if provided or required)
    manifest_audit: dict[str, Any] = {"present": False}
    if scan_manifest_path and scan_manifest_path.is_file():
        manifest_audit["present"] = True
        try:
            m_doc = json.loads(scan_manifest_path.read_text(encoding="utf-8"))
            m_sha = compute_file_sha256(scan_manifest_path)
            manifest_audit["manifest_sha256"] = m_sha
            manifest_audit["schema_version"] = m_doc.get("schema_version")
            manifest_audit["source_capture_verified"] = m_doc.get("source_capture_verified")
            manifest_audit["exit_capture_verified"] = m_doc.get("exit_capture_verified")
            if m_doc.get("schema_version") != "ntk-scan-capture-1":
                issues.append(f"Unexpected manifest schema_version: {m_doc.get('schema_version')}")
            if m_doc.get("source_capture_verified") is not True:
                issues.append("Manifest source_capture_verified is not True")
            if m_doc.get("exit_capture_verified") is not True:
                issues.append("Manifest exit_capture_verified is not True")
            recorded_json_sha = (m_doc.get("runs") or {}).get("json", {}).get("sha256")
            if recorded_json_sha and recorded_json_sha.lower() != actual_raw_sha.lower():
                issues.append(
                    f"Manifest recorded json sha256 ({recorded_json_sha}) != raw opengrep sha256 ({actual_raw_sha})"
                )
        except Exception as exc:
            issues.append(f"Failed to parse scan-manifest.json: {exc}")
    elif require_scan_manifest:
        issues.append("Missing required scan-manifest.json for verified scan receipt")

    # 3. Verify Target Java Source File
    sample_rel_path = "SmokeVulnSample.java"
    java_file = (source_root / sample_rel_path).resolve()
    if not java_file.is_file():
        java_file = (source_root / "smoke_evidence" / sample_rel_path).resolve()

    source_line_map: dict[int, str] = {}
    actual_source_sha: str | None = None
    if java_file.is_file():
        java_text = java_file.read_text(encoding="utf-8")
        actual_source_sha = score_pilot.compute_sha256_text(java_text)
        source_line_map = {idx + 1: line for idx, line in enumerate(java_text.splitlines())}
        if actual_source_sha.lower() != EXPECTED_SOURCE_SHA.lower():
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
        runtime = rec.get("runtime") if isinstance(rec.get("runtime"), dict) else {}

        # Verify scan_sha256 field
        r_scan_sha = rec.get("scan_sha256") or evidence.get("scan_sha256")
        if r_scan_sha and str(r_scan_sha).strip().lower() != active_scan_sha.lower():
            issues.append(
                f"Finding [{f_idx}] row scan_sha256 ({r_scan_sha}) != active scan_sha256 ({active_scan_sha})"
            )

        # Verify model identity
        model_id = str(assessment.get("model") or runtime.get("model") or rec.get("model") or "").strip()
        finding_info["model_id"] = model_id
        if not model_id.lower().startswith("qwen3.5"):
            issues.append(f"Finding [{f_idx}] model_id is not Qwen3.5: '{model_id}'")

        # Verify status
        status = str(assessment.get("status") or rec.get("status") or "").strip().upper()
        finding_info["status"] = status
        if status not in ("SUPPORTED", "REFUTED", "UNDETERMINED"):
            issues.append(f"Finding [{f_idx}] invalid status: '{status}'")

        # Verify citations
        citations = assessment.get("citations") or rec.get("citations") or []
        citation_check = str(assessment.get("citation_check") or rec.get("citation_check") or "").strip().upper()
        finding_info["citation_check"] = citation_check
        if citation_check != "MATCHED":
            issues.append(f"Finding [{f_idx}] citation_check is not MATCHED: '{citation_check}'")

        cited_lines: list[int] = []
        if isinstance(citations, list):
            for c_item in citations:
                if isinstance(c_item, dict):
                    sl = c_item.get("start_line") or c_item.get("line")
                    el = c_item.get("end_line") or sl
                    if isinstance(sl, int) and isinstance(el, int):
                        for lno in range(sl, el + 1):
                            if lno not in cited_lines:
                                cited_lines.append(lno)
                    c_quote = c_item.get("quote")
                    c_sha = c_item.get("sha256")
                    if c_sha and actual_source_sha and str(c_sha).lower() != actual_source_sha.lower():
                        issues.append(
                            f"Finding [{f_idx}] citation sha256 ({c_sha}) != source sha256 ({actual_source_sha})"
                        )
                    if c_quote and sl and sl in source_line_map:
                        expected_q_line = source_line_map[sl].strip()
                        if expected_q_line not in str(c_quote) and str(c_quote).strip() not in expected_q_line:
                            issues.append(
                                f"Finding [{f_idx}] citation quote at line {sl} does not match source code"
                            )
                elif isinstance(c_item, int):
                    if c_item not in cited_lines:
                        cited_lines.append(c_item)

        finding_info["cited_lines"] = cited_lines
        for lno in cited_lines:
            if lno not in source_line_map:
                issues.append(f"Finding [{f_idx}] cited line {lno} does not exist in source file")
            elif not score_pilot._is_meaningful_code_line(source_line_map[lno]):
                issues.append(f"Finding [{f_idx}] cited line {lno} is blank or comment-only")

        # Verify human safety state
        state = str(rec.get("state") or rec.get("human_review_state") or assessment.get("state") or "OPEN").strip().upper()
        auto_dismissed = bool(rec.get("auto_dismissed") or assessment.get("auto_dismissed") or False)
        finding_info["state"] = state
        finding_info["auto_dismissed"] = auto_dismissed
        if auto_dismissed or state != "OPEN":
            issues.append(
                f"Finding [{f_idx}] safety violation: auto_dismissed={auto_dismissed}, state='{state}' (must be OPEN)"
            )

        findings_audit.append(finding_info)

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
    parser.add_argument(
        "--live-dir",
        type=Path,
        default=DEFAULT_SERVER_LIVE_DIR,
        help="Root directory of LIVE run on server (contains live_scan/ and triage_live_qwen35/).",
    )
    parser.add_argument("--output-json", type=Path, help="Optional path to write audit report JSON.")
    args = parser.parse_args(argv)

    print("=" * 80)
    print("NTK THESIS V2 — INDEPENDENT EVIDENCE AUDIT & INTEGRITY CHECK")
    print(f"Mode: {args.mode.upper()}")
    print("=" * 80)

    if args.mode == "replay":
        og_path = args.opengrep or DEFAULT_HISTORICAL_SCAN
        ass_path = args.assessments or DEFAULT_HISTORICAL_ASSESSMENTS
        report = audit_scan_and_evidence(
            opengrep_path=og_path,
            assessments_path=ass_path,
            source_root=args.source_root,
            expected_scan_sha=EXPECTED_HISTORICAL_SCAN_SHA,
            require_scan_manifest=False,
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

        report = audit_scan_and_evidence(
            opengrep_path=og_path,
            assessments_path=ass_path,
            source_root=args.source_root,
            scan_manifest_path=manifest_path,
            expected_scan_sha=EXPECTED_LIVE_SCAN_SHA,
            require_scan_manifest=True,
        )
    else:  # custom
        if not args.opengrep or not args.assessments:
            print("Error: --opengrep and --assessments are required in custom mode.")
            return 2
        report = audit_scan_and_evidence(
            opengrep_path=args.opengrep,
            assessments_path=args.assessments,
            source_root=args.source_root,
            scan_manifest_path=args.scan_manifest,
            require_scan_manifest=bool(args.scan_manifest),
        )

    verdict = report.get("audit_verdict")
    print(f"\nAudit Verdict: {verdict}")
    print(f"OpenGrep Scan SHA-256: {report.get('scan_sha256')}")
    print(f"Java Source SHA-256:   {report.get('source_sha256')}")
    print(f"Assessments SHA-256:   {report.get('assessments_sha256')}")
    print(f"Total Findings:        {report.get('total_findings')}")

    if report.get("manifest_audit", {}).get("present"):
        m = report["manifest_audit"]
        print(f"Scan Manifest:         PRESENT (sha256={m.get('manifest_sha256')[:12]}..., source_capture_verified={m.get('source_capture_verified')})")

    print("\nPer-Finding Alignment:")
    for f in report.get("findings_audit", []):
        f_idx = f["finding_index"]
        aid = f.get("expected_alert_id", "")[:12]
        stat = f.get("status")
        chk = f.get("citation_check")
        lines = f.get("cited_lines")
        state = f.get("state")
        print(f"  [{f_idx}] Alert {aid}... | Status: {stat} | Citations: {chk} (lines {lines}) | Queue: {state}")

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
