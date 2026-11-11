#!/usr/bin/env python3
"""Contract verifier for NTK Thesis V2 reproduction script (REPLAY vs LIVE modes).

Enforces:
1. Exact scan_sha256 identity across raw OpenGrep JSON, assessments.jsonl, and labels JSON.
   Refuses to pair a new raw scan with old assessments if scan_sha256 values differ (exit code 3).
2. Canonical alert_id = SHA256(UTF8(scan_sha256 + ":" + decimal(finding_index))) on every row.
3. In LIVE mode, strict model runtime checks on every assessment row (exit code 4 on failure):
   - transport == "ollama-http"
   - model == expected_model
   - runtime.origin == "unverified" (never "mock" or "disabled")
   - runtime.request_attempted is True
   - runtime.http_response_received is True and runtime.http_status == 200
   - runtime.response_complete is True
   - runtime.model_identity_matched is True
   - runtime.reported_eval_count > 0
   - runtime.answer_validated is True
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from v2.triage import live_check, scan_receipt


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_alert_id(scan_sha256: str, finding_index: int) -> str:
    return hashlib.sha256(f"{scan_sha256}:{finding_index}".encode("utf-8")).hexdigest()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise ValueError(f"JSONL file does not exist: {path}")
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines:
        raise ValueError(f"JSONL file is empty: {path}")
    rows: list[dict[str, Any]] = []
    for idx, line in enumerate(lines, start=1):
        if not line.strip():
            raise ValueError(f"Blank line at {path}:{idx}")
        obj = json.loads(line)
        if not isinstance(obj, dict):
            raise ValueError(f"Row at {path}:{idx} is not a JSON object")
        rows.append(obj)
    return rows


def verify_scan_and_triage_alignment(
    opengrep_path: Path,
    triage_path: Path,
) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]]]:
    if not opengrep_path.is_file():
        raise ValueError(f"OpenGrep JSON file does not exist: {opengrep_path}")
    raw_bytes = opengrep_path.read_bytes()
    if not raw_bytes:
        raise ValueError(f"OpenGrep JSON file is empty: {opengrep_path}")
    scan_sha256 = sha256_bytes(raw_bytes)
    raw_doc = json.loads(raw_bytes.decode("utf-8"))
    results = raw_doc.get("results")
    if not isinstance(results, list) or not results:
        raise ValueError(f"OpenGrep JSON has no results[] list: {opengrep_path}")

    rows = load_jsonl(triage_path)
    if len(rows) != len(results):
        raise ValueError(
            f"SCAN_HASH_MISMATCH: OpenGrep results count ({len(results)}) != "
            f"assessments row count ({len(rows)})"
        )

    seen_indices: set[int] = set()
    for row_num, row in enumerate(rows, start=1):
        row_scan_sha = str(row.get("scan_sha256") or "").strip().lower()
        ev = row.get("evidence")
        ev_scan_sha = str(ev.get("scan_sha256") if isinstance(ev, dict) else "").strip().lower()
        if row_scan_sha != scan_sha256 or (ev_scan_sha and ev_scan_sha != scan_sha256):
            raise ValueError(
                f"SCAN_HASH_MISMATCH at row {row_num}: raw scan sha256 ({scan_sha256}) != "
                f"assessments scan_sha256 ({row_scan_sha or ev_scan_sha})"
            )
        f_idx = row.get("finding_index")
        if not isinstance(f_idx, int) or isinstance(f_idx, bool) or f_idx < 0 or f_idx >= len(results):
            raise ValueError(f"Invalid finding_index at row {row_num}: {f_idx!r}")
        if f_idx in seen_indices:
            raise ValueError(f"Duplicate finding_index at row {row_num}: {f_idx}")
        seen_indices.add(f_idx)

        expected_id = canonical_alert_id(scan_sha256, f_idx)
        row_id = str(row.get("id") or "").strip().lower()
        alert_id = str(row.get("alert_id") or "").strip().lower()
        if row_id != expected_id or alert_id != expected_id:
            raise ValueError(
                f"SCAN_HASH_MISMATCH at row {row_num}: expected canonical alert_id {expected_id} "
                f"for scan {scan_sha256}:{f_idx}, got id={row_id}, alert_id={alert_id}"
            )

    return scan_sha256, results, rows


def verify_labels_alignment(
    scan_sha256: str,
    results: list[dict[str, Any]],
    labels_path: Path,
) -> dict[str, Any]:
    if not labels_path.is_file():
        raise ValueError(f"Labels JSON file does not exist: {labels_path}")
    labels_doc = json.loads(labels_path.read_text(encoding="utf-8"))
    if not isinstance(labels_doc, dict):
        raise ValueError(f"Labels JSON must be an object: {labels_path}")

    doc_scan_sha = str(labels_doc.get("scan_sha256") or "").strip().lower()
    if doc_scan_sha and doc_scan_sha != scan_sha256:
        raise ValueError(
            f"SCAN_HASH_MISMATCH: raw scan sha256 ({scan_sha256}) != "
            f"labels scan_sha256 ({doc_scan_sha})"
        )

    labels = labels_doc.get("labels")
    if not isinstance(labels, list) or len(labels) != len(results):
        raise ValueError("Labels list missing or length mismatch with scan results")

    for idx, lbl in enumerate(labels):
        if not isinstance(lbl, dict):
            raise ValueError(f"Label at index {idx} is not an object")
        lbl_scan = str(lbl.get("scan_sha256") or "").strip().lower()
        if lbl_scan and lbl_scan != scan_sha256:
            raise ValueError(
                f"SCAN_HASH_MISMATCH on label {idx}: raw scan sha256 ({scan_sha256}) != "
                f"label scan_sha256 ({lbl_scan})"
            )
        f_idx = lbl.get("finding_index", idx)
        expected_id = canonical_alert_id(scan_sha256, int(f_idx))
        if str(lbl.get("alert_id") or "").strip().lower() != expected_id:
            raise ValueError(
                f"SCAN_HASH_MISMATCH on label {idx}: expected alert_id {expected_id}, "
                f"got {lbl.get('alert_id')}"
            )
    return labels_doc


def verify_live_runtime_rows(rows: list[dict[str, Any]], expected_model: str) -> list[str]:
    errors: list[str] = []
    for idx, row in enumerate(rows):
        aid = str(row.get("alert_id") or row.get("id") or f"row-{idx}")
        assessment = row.get("assessment")
        if not isinstance(assessment, dict):
            errors.append(f"{aid}: missing assessment object")
            continue
        if assessment.get("transport") != "ollama-http":
            errors.append(f"{aid}: expected transport='ollama-http', got {assessment.get('transport')!r}")
        if assessment.get("model") != expected_model:
            errors.append(f"{aid}: expected model={expected_model!r}, got {assessment.get('model')!r}")
        runtime = assessment.get("runtime")
        if not isinstance(runtime, dict):
            errors.append(f"{aid}: missing assessment.runtime object")
            continue
        if runtime.get("origin") != "unverified":
            errors.append(f"{aid}: runtime.origin must be 'unverified' (not mock/disabled), got {runtime.get('origin')!r}")
        if runtime.get("request_attempted") is not True:
            errors.append(f"{aid}: runtime.request_attempted is not True")
        if runtime.get("http_response_received") is not True or runtime.get("http_status") != 200:
            errors.append(
                f"{aid}: HTTP response not received or non-200 status "
                f"(received={runtime.get('http_response_received')!r}, status={runtime.get('http_status')!r})"
            )
        if runtime.get("response_complete") is not True:
            errors.append(f"{aid}: runtime.response_complete is not True")
        if runtime.get("model_identity_matched") is not True:
            errors.append(f"{aid}: runtime.model_identity_matched is not True")
        eval_count = runtime.get("reported_eval_count")
        if not isinstance(eval_count, int) or isinstance(eval_count, bool) or eval_count <= 0:
            errors.append(f"{aid}: runtime.reported_eval_count must be positive int, got {eval_count!r}")
        if runtime.get("answer_validated") is not True:
            errors.append(f"{aid}: runtime.answer_validated is not True (status={assessment.get('status')!r})")
    return errors


def verify_scan_manifest_contract(
    manifest_path: Path | None,
    opengrep_path: Path,
    source_root: Path,
    rows: list[dict[str, Any]],
    disallow_mock_producer: bool = True,
) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    if manifest_path is None:
        return {}, ["--scan-manifest is required for manifest-bound verification"]
    if not opengrep_path.is_file():
        return {}, [f"OpenGrep JSON file does not exist: {opengrep_path}"]

    raw_bytes = opengrep_path.read_bytes()
    receipt, issues = scan_receipt.verify_receipt(
        manifest_path,
        raw_bytes,
        source_root,
        declared_exit=0,
    )
    for issue in issues:
        errors.append(issue)
    if receipt.get("source_capture_verified") is not True:
        errors.append("scan receipt source_capture_verified is not True")
    if receipt.get("exit_capture_verified") is not True or receipt.get("recorded_engine_exit") != 0:
        errors.append(
            f"scan receipt exit_capture_verified={receipt.get('exit_capture_verified')!r}, "
            f"recorded_engine_exit={receipt.get('recorded_engine_exit')!r}"
        )
    if disallow_mock_producer and receipt.get("producer") == "UNIT_TEST_MOCK_CAPTURE":
        errors.append("mock producer UNIT_TEST_MOCK_CAPTURE is forbidden in LIVE mode")

    expected_manifest_sha = receipt.get("manifest_sha256")
    for idx, row in enumerate(rows):
        aid = str(row.get("alert_id") or row.get("id") or f"row-{idx}")
        ev = row.get("evidence")
        if not isinstance(ev, dict):
            errors.append(f"{aid}: missing evidence object")
            continue
        prov = ev.get("scan_provenance")
        if not isinstance(prov, dict):
            errors.append(f"{aid}: missing evidence.scan_provenance object")
            continue
        if prov.get("source_capture_verified") is not True:
            errors.append(f"{aid}: evidence.scan_provenance.source_capture_verified is not True")
        if prov.get("exit_capture_verified") is not True or prov.get("recorded_engine_exit") != 0:
            errors.append(
                f"{aid}: evidence.scan_provenance exit_capture_verified={prov.get('exit_capture_verified')!r}, "
                f"recorded_engine_exit={prov.get('recorded_engine_exit')!r}"
            )
        if expected_manifest_sha and prov.get("manifest_sha256") != expected_manifest_sha:
            errors.append(
                f"{aid}: row manifest_sha256 ({prov.get('manifest_sha256')!r}) != "
                f"receipt manifest_sha256 ({expected_manifest_sha!r})"
            )
        ev_issues = ev.get("issues")
        if isinstance(ev_issues, list) and ev_issues:
            errors.append(f"{aid}: evidence.issues is non-empty: {ev_issues}")

    return receipt, errors


def _paths_align(res_path: str, lbl_path: str) -> bool:
    r = res_path.replace("\\", "/").strip("/")
    l = lbl_path.replace("\\", "/").strip("/")
    return r == l or r.endswith("/" + l) or l.endswith("/" + r)


def project_labels_to_live_scan(
    scan_sha256: str,
    results: list[dict[str, Any]],
    template_labels_path: Path,
    output_labels_path: Path,
) -> dict[str, Any]:
    template_doc = json.loads(template_labels_path.read_text(encoding="utf-8"))
    template_labels = template_doc.get("labels")
    if not isinstance(template_labels, list) or len(template_labels) != len(results):
        raise ValueError("Template labels count does not match live scan results count")

    projected = copy.deepcopy(template_doc)
    projected["scan_sha256"] = scan_sha256
    for idx, (res, lbl) in enumerate(zip(results, projected["labels"])):
        res_path = str(res.get("path") or "").replace("\\", "/")
        lbl_path = str(lbl.get("file_path") or "").replace("\\", "/")
        res_line = res.get("start", {}).get("line")
        lbl_line = lbl.get("start_line")
        res_rule = str(res.get("check_id") or "")
        lbl_rule = str(lbl.get("rule_id") or "")
        if not _paths_align(res_path, lbl_path) or res_line != lbl_line or res_rule != lbl_rule:
            raise ValueError(
                f"Live scan finding[{idx}] ({res_path}:{res_line} {res_rule}) does not match "
                f"template label ({lbl_path}:{lbl_line} {lbl_rule})"
            )
        lbl["finding_index"] = idx
        lbl["scan_sha256"] = scan_sha256
        lbl["alert_id"] = canonical_alert_id(scan_sha256, idx)

    output_labels_path.parent.mkdir(parents=True, exist_ok=True)
    output_labels_path.write_text(json.dumps(projected, indent=2), encoding="utf-8")
    return projected


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)

    p_replay = sub.add_parser("replay", help="Verify locked REPLAY scan/triage/labels contract")
    p_replay.add_argument("--opengrep", type=Path, required=True)
    p_replay.add_argument("--triage", type=Path, required=True)
    p_replay.add_argument("--labels", type=Path, required=True)
    p_replay.add_argument("--scan-manifest", type=Path, default=None)
    p_replay.add_argument("--source-root", type=Path, default=REPO_ROOT / "v2" / "evaluation" / "smoke_evidence")
    p_replay.add_argument("--output-report", type=Path)

    p_live = sub.add_parser("live", help="Verify fresh LIVE scan/triage/runtime contract")
    p_live.add_argument("--opengrep", type=Path, required=True)
    p_live.add_argument("--triage", type=Path, required=True)
    p_live.add_argument("--template-labels", type=Path, required=True)
    p_live.add_argument("--expected-model", required=True)
    p_live.add_argument("--output-labels", type=Path, required=True)
    p_live.add_argument("--scan-manifest", type=Path, default=None)
    p_live.add_argument("--source-root", type=Path, default=REPO_ROOT / "v2" / "evaluation" / "smoke_evidence")
    p_live.add_argument("--output-report", type=Path)

    args = parser.parse_args(argv)
    try:
        scan_sha256, results, rows = verify_scan_and_triage_alignment(args.opengrep, args.triage)
        if args.mode == "replay":
            verify_labels_alignment(scan_sha256, results, args.labels)
            if args.scan_manifest is not None:
                receipt, manifest_errors = verify_scan_manifest_contract(
                    args.scan_manifest,
                    args.opengrep,
                    args.source_root,
                    rows,
                    disallow_mock_producer=False,
                )
                if manifest_errors:
                    for err in manifest_errors:
                        print(f"SCAN_MANIFEST_INVALID: {err}", file=sys.stderr)
                    return 5
                provenance_classification = "MANIFEST_BOUND_REPLAY"
                source_capture_verified = True
                manifest_sha256 = receipt.get("manifest_sha256")
            else:
                for idx, row in enumerate(rows):
                    ev = row.get("evidence")
                    prov = ev.get("scan_provenance") if isinstance(ev, dict) else None
                    if isinstance(prov, dict) and prov.get("source_capture_verified") is True:
                        raise ValueError(
                            f"UNBUNDLED_REPLAY_PROVENANCE_ESCALATION at row {idx + 1}: "
                            "row claims source_capture_verified=True without --scan-manifest"
                        )
                provenance_classification = "HISTORICAL_UNBUNDLED_REPLAY"
                source_capture_verified = False
                manifest_sha256 = None

            report = {
                "mode": "REPLAY",
                "status": "PASS",
                "provenance_classification": provenance_classification,
                "source_capture_verified": source_capture_verified,
                "manifest_sha256": manifest_sha256,
                "scan_sha256": scan_sha256,
                "findings_count": len(rows),
                "opengrep_path": str(args.opengrep),
                "triage_path": str(args.triage),
                "labels_path": str(args.labels),
            }
            if args.output_report:
                args.output_report.parent.mkdir(parents=True, exist_ok=True)
                args.output_report.write_text(json.dumps(report, indent=2), encoding="utf-8")
            print(
                f"PASS: REPLAY contract verified (scan_sha256={scan_sha256}, "
                f"provenance={provenance_classification}, findings={len(rows)})"
            )
            return 0

        receipt, manifest_errors = verify_scan_manifest_contract(
            args.scan_manifest,
            args.opengrep,
            args.source_root,
            rows,
            disallow_mock_producer=True,
        )
        if manifest_errors:
            for err in manifest_errors:
                print(f"SCAN_MANIFEST_INVALID: {err}", file=sys.stderr)
            return 5

        runtime_errors = verify_live_runtime_rows(rows, args.expected_model)
        live_protocol = live_check.inspect(rows, minimum=len(rows))
        if (
            live_protocol.get("protocol_status") != "OLLAMA_REPORTED_UNATTESTED"
            or live_protocol.get("completed_reported_responses") != len(rows)
        ):
            runtime_errors.append(
                f"live_check protocol_status={live_protocol.get('protocol_status')!r} "
                f"(completed={live_protocol.get('completed_reported_responses')}/{len(rows)})"
            )
        if runtime_errors:
            for err in runtime_errors:
                print(f"LIVE_RUNTIME_VERIFICATION_FAILED: {err}", file=sys.stderr)
            return 4

        project_labels_to_live_scan(scan_sha256, results, args.template_labels, args.output_labels)
        report = {
            "mode": "LIVE",
            "status": "PASS",
            "provenance_classification": "LIVE_MANIFEST_VERIFIED",
            "source_capture_verified": True,
            "manifest_sha256": receipt.get("manifest_sha256"),
            "live_protocol_status": live_protocol.get("protocol_status"),
            "scan_sha256": scan_sha256,
            "expected_model": args.expected_model,
            "findings_count": len(rows),
            "opengrep_path": str(args.opengrep),
            "scan_manifest_path": str(args.scan_manifest),
            "triage_path": str(args.triage),
            "output_labels_path": str(args.output_labels),
        }
        if args.output_report:
            args.output_report.parent.mkdir(parents=True, exist_ok=True)
            args.output_report.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(
            f"PASS: LIVE contract, scan-manifest, and model runtime verified "
            f"(scan_sha256={scan_sha256}, manifest_sha256={receipt.get('manifest_sha256')}, "
            f"model={args.expected_model}, findings={len(rows)})"
        )
        return 0
    except Exception as exc:
        print(f"CONTRACT_VERIFICATION_FAILED: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
