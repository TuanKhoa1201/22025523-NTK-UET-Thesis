"""Independent raw HTTP capture verifier for v2.triage Ollama runs.

Verifies that same-call raw HTTP request/response body artifacts (`*.request.body.bin`,
`*.response.body.bin` or `*.response.incomplete.bin`) and per-call receipts
(`*.http-capture.json`) match `evidence.json` and `assessments.jsonl` byte-for-byte
and SHA-256-for-SHA-256 without mutating run artifacts when `--output` or `--no-write` is used.

Scope note:
- Verifies client-sent HTTP payload bytes and client-received HTTP body bytes from the same
  `urllib` call prior to UTF-8/JSON decoding.
- Does NOT claim raw TCP/chunked wire framing capture or server-side model weight attestation.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any

from .evidence import EvidenceError, digest, strict_json
from .ollama import MAX_HTTP_BODY_BYTES, request_payload


def _safe_id(finding_id: Any) -> str:
    return re.sub(r"[^0-9a-fA-F_-]", "_", str(finding_id or "unknown"))[:80]


def _verify_tags_captures(tags_dir: Path, seen_call_ids: set[str], errors: list[str]) -> list[dict[str, Any]]:
    probes: list[dict[str, Any]] = []
    if not tags_dir.exists():
        return probes
    if not tags_dir.is_dir():
        errors.append(f"llm_io/_tags is not a directory: {tags_dir}")
        return probes

    receipt_files = sorted(tags_dir.glob("*.http-capture.json"))
    expected_files: set[str] = set()
    for r_file in receipt_files:
        expected_files.add(r_file.name)
        try:
            doc = strict_json(r_file.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError, EvidenceError) as exc:
            errors.append(f"unreadable tags receipt {r_file.name}: {exc}")
            continue
        if not isinstance(doc, dict) or doc.get("schema") != "ntk-ollama-http-capture-1":
            errors.append(f"invalid schema in tags receipt {r_file.name}")
            continue
        call_id = doc.get("call_id")
        if not isinstance(call_id, str) or not call_id:
            errors.append(f"missing call_id in tags receipt {r_file.name}")
        elif call_id in seen_call_ids:
            errors.append(f"duplicate call_id across HTTP receipts: {call_id}")
        else:
            seen_call_ids.add(call_id)

        if doc.get("call_kind") != "tags_probe" or doc.get("method") != "GET" or doc.get("path") != "/api/tags":
            errors.append(f"tags receipt {r_file.name} has unexpected call_kind/method/path")
        if doc.get("finding_id") is not None:
            errors.append(f"tags receipt {r_file.name} must not bind a finding_id")
        if doc.get("request_raw_file") is not None:
            errors.append(f"GET tags receipt {r_file.name} unexpectedly declares request_raw_file")

        completeness = doc.get("completeness")
        resp_name = doc.get("response_raw_file")
        inc_name = doc.get("response_incomplete_raw_file")
        probe_ok = True
        if completeness in ("complete", "complete_http_error_body"):
            if not isinstance(resp_name, str) or not resp_name:
                errors.append(f"tags receipt {r_file.name} missing response_raw_file")
                probe_ok = False
            else:
                expected_files.add(resp_name)
                resp_path = tags_dir / resp_name
                if not resp_path.is_file():
                    errors.append(f"missing tags raw response body file: {resp_name}")
                    probe_ok = False
                else:
                    raw = resp_path.read_bytes()
                    if len(raw) > MAX_HTTP_BODY_BYTES:
                        errors.append(f"tags raw response {resp_name} exceeds MAX_HTTP_BODY_BYTES")
                        probe_ok = False
                    if len(raw) != doc.get("response_byte_length"):
                        errors.append(f"tags raw response {resp_name} byte length mismatch")
                        probe_ok = False
                    if digest(raw) != doc.get("response_body_sha256"):
                        errors.append(f"tags raw response {resp_name} SHA-256 mismatch")
                        probe_ok = False
        elif inc_name is not None:
            if not isinstance(inc_name, str) or not inc_name:
                errors.append(f"tags receipt {r_file.name} has invalid response_incomplete_raw_file")
                probe_ok = False
            else:
                expected_files.add(inc_name)
                inc_path = tags_dir / inc_name
                if not inc_path.is_file():
                    errors.append(f"missing tags incomplete body file: {inc_name}")
                    probe_ok = False
                else:
                    inc_bytes = inc_path.read_bytes()
                    if len(inc_bytes) != doc.get("response_incomplete_byte_length") or digest(inc_bytes) != doc.get("response_incomplete_sha256"):
                        errors.append(f"tags incomplete body {inc_name} length/SHA-256 mismatch")
                        probe_ok = False

        probes.append({
            "receipt": f"llm_io/_tags/{r_file.name}",
            "call_id": call_id,
            "http_status": doc.get("http_status"),
            "completeness": completeness,
            "complete": doc.get("complete") is True,
            "response_body_sha256": doc.get("response_body_sha256"),
            "verified": probe_ok,
        })

    for actual in sorted(p.name for p in tags_dir.iterdir() if p.is_file()):
        if actual not in expected_files:
            errors.append(f"orphan file in llm_io/_tags not referenced by any tags receipt: {actual}")

    return probes


def verify_run_http_captures(
    triage_dir: Path,
    *,
    require_live_chat: bool = False,
    minimum_findings: int = 0,
) -> dict[str, Any]:
    triage_dir = Path(triage_dir).resolve()
    errors: list[str] = []
    finding_checks: list[dict[str, Any]] = []
    seen_call_ids: set[str] = set()

    evidence_path = triage_dir / "evidence.json"
    assessments_path = triage_dir / "assessments.jsonl"
    io_dir = triage_dir / "llm_io"

    if not evidence_path.is_file():
        return {
            "schema": "ntk-http-capture-verification-1",
            "capture_status": "FAILED",
            "capture_integrity_ok": False,
            "live_chat_verified": False,
            "errors": [f"missing evidence.json: {evidence_path}"],
            "findings": [],
            "tags_probes": [],
        }
    if not assessments_path.is_file():
        return {
            "schema": "ntk-http-capture-verification-1",
            "capture_status": "FAILED",
            "capture_integrity_ok": False,
            "live_chat_verified": False,
            "errors": [f"missing assessments.jsonl: {assessments_path}"],
            "findings": [],
            "tags_probes": [],
        }

    try:
        bundle = strict_json(evidence_path.read_text(encoding="utf-8"))
        rows = [
            strict_json(line)
            for line in assessments_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, UnicodeError, ValueError, EvidenceError) as exc:
        return {
            "schema": "ntk-http-capture-verification-1",
            "capture_status": "FAILED",
            "capture_integrity_ok": False,
            "live_chat_verified": False,
            "errors": [f"failed to parse evidence/assessments: {exc}"],
            "findings": [],
            "tags_probes": [],
        }

    records = bundle.get("records") if isinstance(bundle, dict) else None
    scan_sha = bundle.get("scan_sha256") if isinstance(bundle, dict) else None
    if not isinstance(records, list) or not isinstance(scan_sha, str):
        errors.append("evidence.json missing records list or scan_sha256")
        records = []

    if len(rows) != len(records):
        errors.append(f"finding count mismatch: evidence={len(records)} vs assessments={len(rows)}")

    tags_probes = _verify_tags_captures(io_dir / "_tags", seen_call_ids, errors) if io_dir.is_dir() else []
    expected_chat_files: set[str] = set()

    disabled_count = 0
    mock_method_count = 0
    complete_chat_count = 0
    live_non_mock_complete_count = 0
    partial_or_error_count = 0

    for idx, (rec, row) in enumerate(zip(records, rows)):
        rec_id = rec.get("id") if isinstance(rec, dict) else None
        expected_id = digest(f"{scan_sha}:{idx}".encode("utf-8")) if isinstance(scan_sha, str) else None
        assessment = row.get("assessment") if isinstance(row, dict) and isinstance(row.get("assessment"), dict) else {}
        runtime = assessment.get("runtime") if isinstance(assessment.get("runtime"), dict) else {}
        safe_id = _safe_id(rec_id)
        item_errors: list[str] = []

        if (
            not isinstance(rec_id, str)
            or rec_id != expected_id
            or row.get("id") != rec_id
            or runtime.get("finding_id") not in (rec_id, None)
        ):
            item_errors.append(f"finding[{idx}] ID join mismatch across evidence/assessments/runtime")

        origin = runtime.get("origin")
        raw_resp_obj = assessment.get("raw_response")
        is_mock = origin == "mock" or (isinstance(raw_resp_obj, dict) and raw_resp_obj.get("mock_test_fixture") is True)
        req_attempted = runtime.get("request_attempted") is True
        cap_completeness = runtime.get("http_capture_completeness")
        failure_kind = assessment.get("failure_kind")

        if failure_kind == "EVIDENCE_CAPTURE_WRITE_FAILED" or cap_completeness == "capture_write_failed":
            item_errors.append(
                f"finding[{idx}] ({rec_id}) failed raw evidence capture write: {runtime.get('http_capture_error') or assessment.get('explanation')}"
            )

        if origin == "disabled" and assessment.get("transport") == "disabled":
            disabled_count += 1
            if req_attempted:
                item_errors.append(f"finding[{idx}] disabled transport unexpectedly attempted HTTP request")
            for suffix in (".request.body.bin", ".response.body.bin", ".response.incomplete.bin", ".http-capture.json"):
                if (io_dir / f"{safe_id}{suffix}").exists():
                    item_errors.append(f"finding[{idx}] disabled run unexpectedly has {safe_id}{suffix}")
            finding_checks.append({
                "finding_index": idx,
                "id": rec_id,
                "mode": "disabled",
                "mock": False,
                "verified": len(item_errors) == 0,
                "errors": item_errors,
            })
            errors.extend(item_errors)
            continue

        if not req_attempted and cap_completeness == "request_method_mocked":
            mock_method_count += 1
            # Compatibility JSON sidecars may exist when io_log_dir was passed under mocked request()
            for suffix in (".prompt.json", ".request.json", ".response.json"):
                cand = io_dir / f"{safe_id}{suffix}"
                if cand.is_file():
                    expected_chat_files.add(cand.name)
            if require_live_chat:
                item_errors.append(f"finding[{idx}] ({rec_id}) used in-memory mocked request() without HTTP transport capture")
            finding_checks.append({
                "finding_index": idx,
                "id": rec_id,
                "mode": "request_method_mocked",
                "mock": True,
                "verified": len(item_errors) == 0,
                "errors": item_errors,
            })
            errors.extend(item_errors)
            continue

        if not req_attempted:
            # Precheck failure prior to transport (e.g. insufficient evidence or oversized prompt)
            partial_or_error_count += 1
            for suffix in (".prompt.json", ".request.json", ".response.json"):
                cand = io_dir / f"{safe_id}{suffix}"
                if cand.is_file():
                    expected_chat_files.add(cand.name)
            for suffix in (".request.body.bin", ".response.body.bin", ".response.incomplete.bin", ".http-capture.json"):
                if (io_dir / f"{safe_id}{suffix}").exists():
                    item_errors.append(f"finding[{idx}] precheck-aborted finding unexpectedly has {safe_id}{suffix}")
            if runtime.get("answer_validated") is True or assessment.get("validated_status") != "UNDETERMINED":
                item_errors.append(f"finding[{idx}] precheck-aborted finding must be unvalidated UNDETERMINED")
            if require_live_chat:
                item_errors.append(f"finding[{idx}] ({rec_id}) did not execute live HTTP chat")
            finding_checks.append({
                "finding_index": idx,
                "id": rec_id,
                "mode": "precheck_not_attempted",
                "mock": is_mock,
                "verified": len(item_errors) == 0,
                "errors": item_errors,
            })
            errors.extend(item_errors)
            continue

        # Real HTTP transport was attempted -> raw capture files and receipt are mandatory!
        if not io_dir.is_dir():
            item_errors.append(f"finding[{idx}] missing llm_io directory: {io_dir}")
            finding_checks.append({
                "finding_index": idx,
                "id": rec_id,
                "mode": "http_transport",
                "mock": is_mock,
                "verified": False,
                "errors": item_errors,
            })
            errors.extend(item_errors)
            continue

        receipt_name = f"{safe_id}.http-capture.json"
        req_bin_name = f"{safe_id}.request.body.bin"
        resp_bin_name = f"{safe_id}.response.body.bin"
        inc_bin_name = f"{safe_id}.response.incomplete.bin"
        prompt_json_name = f"{safe_id}.prompt.json"
        req_json_name = f"{safe_id}.request.json"
        resp_json_name = f"{safe_id}.response.json"

        receipt_path = io_dir / receipt_name
        req_bin_path = io_dir / req_bin_name
        resp_bin_path = io_dir / resp_bin_name
        inc_bin_path = io_dir / inc_bin_name

        for sidecar_name in (receipt_name, req_bin_name, prompt_json_name, req_json_name, resp_json_name):
            expected_chat_files.add(sidecar_name)

        receipt_doc: dict[str, Any] = {}
        if not receipt_path.is_file():
            item_errors.append(f"finding[{idx}] missing HTTP capture receipt: {receipt_name}")
        else:
            try:
                loaded = strict_json(receipt_path.read_text(encoding="utf-8"))
                if not isinstance(loaded, dict):
                    item_errors.append(f"finding[{idx}] receipt {receipt_name} is not a JSON object")
                else:
                    receipt_doc = loaded
            except (OSError, UnicodeError, ValueError, EvidenceError) as exc:
                item_errors.append(f"finding[{idx}] unreadable receipt {receipt_name}: {exc}")

        if receipt_doc:
            if receipt_doc.get("schema") != "ntk-ollama-http-capture-1":
                item_errors.append(f"finding[{idx}] unexpected receipt schema: {receipt_doc.get('schema')!r}")
            if receipt_doc.get("capture_scope") != "http_body_and_client_metadata_not_tcp_wire":
                item_errors.append(f"finding[{idx}] unexpected capture_scope: {receipt_doc.get('capture_scope')!r}")
            call_id = receipt_doc.get("call_id")
            if not isinstance(call_id, str) or not call_id:
                item_errors.append(f"finding[{idx}] missing call_id in {receipt_name}")
            elif call_id in seen_call_ids:
                item_errors.append(f"finding[{idx}] duplicate call_id {call_id}")
            else:
                seen_call_ids.add(call_id)

            if receipt_doc.get("call_kind") != "chat_analyze" or receipt_doc.get("method") != "POST" or receipt_doc.get("path") != "/api/chat":
                item_errors.append(f"finding[{idx}] receipt call_kind/method/path mismatch")
            if (
                receipt_doc.get("finding_id") != rec_id
                or receipt_doc.get("alert_id") != rec.get("alert_id")
                or receipt_doc.get("scan_sha256") != rec.get("scan_sha256")
                or receipt_doc.get("finding_index") != idx
                or receipt_doc.get("rule_id") != rec.get("rule_id")
            ):
                item_errors.append(f"finding[{idx}] receipt finding metadata does not match evidence record")
            if receipt_doc.get("requested_model") != assessment.get("model") or receipt_doc.get("endpoint") != assessment.get("endpoint"):
                item_errors.append(f"finding[{idx}] receipt model/endpoint does not match assessment")
            if runtime.get("http_capture_receipt") != f"llm_io/{receipt_name}":
                item_errors.append(f"finding[{idx}] runtime.http_capture_receipt mismatch")

        # Verify raw request payload bytes
        req_sha_verified = None
        req_len_verified = None
        if not req_bin_path.is_file():
            item_errors.append(f"finding[{idx}] missing raw request body file: {req_bin_name}")
        else:
            req_bytes = req_bin_path.read_bytes()
            req_len_verified = len(req_bytes)
            req_sha_verified = digest(req_bytes)
            if req_sha_verified != runtime.get("request_payload_sha256"):
                item_errors.append(f"finding[{idx}] {req_bin_name} SHA-256 != runtime.request_payload_sha256")
            if req_len_verified != runtime.get("request_payload_bytes"):
                item_errors.append(f"finding[{idx}] {req_bin_name} byte length != runtime.request_payload_bytes")
            if receipt_doc:
                if req_sha_verified != receipt_doc.get("request_payload_sha256"):
                    item_errors.append(f"finding[{idx}] {req_bin_name} SHA-256 != receipt.request_payload_sha256")
                if req_len_verified != receipt_doc.get("request_byte_length"):
                    item_errors.append(f"finding[{idx}] {req_bin_name} byte length != receipt.request_byte_length")
            try:
                expected_req_bytes = json.dumps(request_payload(rec, assessment.get("model"))).encode("utf-8")
                if req_bytes != expected_req_bytes:
                    item_errors.append(f"finding[{idx}] {req_bin_name} bytes differ from canonical serialized request_payload")
            except (EvidenceError, KeyError, TypeError, ValueError) as exc:
                item_errors.append(f"finding[{idx}] could not reconstruct request_payload from evidence: {exc}")

        # Verify compatibility JSON sidecars
        for json_sidecar in (prompt_json_name, req_json_name, resp_json_name):
            sidecar_path = io_dir / json_sidecar
            if not sidecar_path.is_file():
                item_errors.append(f"finding[{idx}] missing compatibility JSON artifact: {json_sidecar}")
            else:
                try:
                    s_doc = strict_json(sidecar_path.read_text(encoding="utf-8"))
                    if json_sidecar == prompt_json_name:
                        if s_doc.get("finding_id") != rec_id or s_doc.get("prompt_sha256") != assessment.get("prompt_sha256"):
                            item_errors.append(f"finding[{idx}] {prompt_json_name} finding_id/prompt_sha256 mismatch")
                    elif json_sidecar == resp_json_name:
                        if s_doc.get("finding_id") != rec_id or s_doc.get("raw_response") != assessment.get("raw_response"):
                            item_errors.append(f"finding[{idx}] {resp_json_name} finding_id/raw_response mismatch")
                except (OSError, UnicodeError, ValueError, EvidenceError) as exc:
                    item_errors.append(f"finding[{idx}] unreadable compatibility artifact {json_sidecar}: {exc}")

        # Verify raw response body bytes according to completeness state
        completeness = receipt_doc.get("completeness") if receipt_doc else None
        resp_sha_verified = None
        resp_len_verified = None
        if completeness in ("complete", "complete_http_error_body"):
            expected_chat_files.add(resp_bin_name)
            if receipt_doc.get("complete") is not True:
                item_errors.append(f"finding[{idx}] receipt completeness={completeness} must set complete=True")
            if inc_bin_path.exists():
                item_errors.append(f"finding[{idx}] unexpected {inc_bin_name} alongside complete response")
            if not resp_bin_path.is_file():
                item_errors.append(f"finding[{idx}] missing raw response body file: {resp_bin_name}")
            else:
                resp_bytes = resp_bin_path.read_bytes()
                resp_len_verified = len(resp_bytes)
                resp_sha_verified = digest(resp_bytes)
                if resp_len_verified > MAX_HTTP_BODY_BYTES:
                    item_errors.append(f"finding[{idx}] {resp_bin_name} exceeds MAX_HTTP_BODY_BYTES")
                if resp_sha_verified != runtime.get("response_body_sha256"):
                    item_errors.append(f"finding[{idx}] {resp_bin_name} SHA-256 != runtime.response_body_sha256")
                if resp_len_verified != runtime.get("response_body_bytes"):
                    item_errors.append(f"finding[{idx}] {resp_bin_name} byte length != runtime.response_body_bytes")
                if resp_sha_verified != receipt_doc.get("response_body_sha256"):
                    item_errors.append(f"finding[{idx}] {resp_bin_name} SHA-256 != receipt.response_body_sha256")
                if resp_len_verified != receipt_doc.get("response_byte_length"):
                    item_errors.append(f"finding[{idx}] {resp_bin_name} byte length != receipt.response_byte_length")
                if receipt_doc.get("http_status") != runtime.get("http_status") or not isinstance(receipt_doc.get("response_headers"), list):
                    item_errors.append(f"finding[{idx}] receipt http_status/response_headers mismatch")

                if completeness == "complete":
                    complete_chat_count += 1
                    if receipt_doc.get("http_status") != 200:
                        item_errors.append(f"finding[{idx}] completeness='complete' requires http_status 200")
                    if receipt_doc.get("response_json_parse_succeeded") is True:
                        try:
                            parsed_raw = strict_json(resp_bytes.decode("utf-8"))
                            if parsed_raw != assessment.get("raw_response"):
                                item_errors.append(f"finding[{idx}] parsed {resp_bin_name} != assessment.raw_response")
                            canon_sha = digest(
                                json.dumps(parsed_raw, sort_keys=True, ensure_ascii=False, allow_nan=False).encode("utf-8")
                            )
                            if canon_sha != runtime.get("response_json_sha256") or canon_sha != receipt_doc.get("response_json_sha256"):
                                item_errors.append(f"finding[{idx}] canonical response_json_sha256 mismatch")
                            if not is_mock:
                                live_non_mock_complete_count += 1
                        except (UnicodeError, ValueError, EvidenceError) as exc:
                            item_errors.append(f"finding[{idx}] receipt claimed JSON parse succeeded but {resp_bin_name} failed strict_json: {exc}")
                    else:
                        # Malformed JSON or invalid UTF-8 on HTTP 200: raw bytes preserved, must not validate!
                        if assessment.get("raw_response") is not None:
                            item_errors.append(f"finding[{idx}] unparseable HTTP 200 body must have raw_response=None")
                        if runtime.get("answer_validated") is True or assessment.get("validated_status") != "UNDETERMINED":
                            item_errors.append(f"finding[{idx}] unparseable HTTP 200 body must fail closed to UNDETERMINED")
                        if require_live_chat:
                            item_errors.append(f"finding[{idx}] HTTP 200 response failed strict JSON parsing")
                else:
                    # complete_http_error_body (e.g. HTTP 404/500)
                    partial_or_error_count += 1
                    if runtime.get("answer_validated") is True or assessment.get("validated_status") != "UNDETERMINED":
                        item_errors.append(f"finding[{idx}] HTTP error response must fail closed to UNDETERMINED")
                    if require_live_chat:
                        item_errors.append(f"finding[{idx}] HTTP error status {receipt_doc.get('http_status')}")
        elif completeness in ("partial_read_error", "exceeded_max_bytes_prefix_only"):
            partial_or_error_count += 1
            if receipt_doc.get("complete") is not False or runtime.get("http_capture_complete") is not False:
                item_errors.append(f"finding[{idx}] incomplete response must have complete=False")
            if runtime.get("response_body_sha256") is not None or receipt_doc.get("response_body_sha256") is not None:
                item_errors.append(f"finding[{idx}] incomplete response must not fabricate response_body_sha256")
            if resp_bin_path.exists():
                item_errors.append(f"finding[{idx}] incomplete response must not write {resp_bin_name}")
            if receipt_doc.get("response_incomplete_raw_file") is not None:
                expected_chat_files.add(inc_bin_name)
                if not inc_bin_path.is_file():
                    item_errors.append(f"finding[{idx}] missing declared {inc_bin_name}")
                else:
                    inc_bytes = inc_bin_path.read_bytes()
                    if len(inc_bytes) > MAX_HTTP_BODY_BYTES:
                        item_errors.append(f"finding[{idx}] {inc_bin_name} exceeds MAX_HTTP_BODY_BYTES")
                    if len(inc_bytes) != receipt_doc.get("response_incomplete_byte_length"):
                        item_errors.append(f"finding[{idx}] {inc_bin_name} byte length mismatch")
                    if digest(inc_bytes) != receipt_doc.get("response_incomplete_sha256"):
                        item_errors.append(f"finding[{idx}] {inc_bin_name} SHA-256 mismatch")
            if runtime.get("answer_validated") is True or assessment.get("validated_status") != "UNDETERMINED":
                item_errors.append(f"finding[{idx}] incomplete response must fail closed to UNDETERMINED")
            if require_live_chat:
                item_errors.append(f"finding[{idx}] incomplete HTTP response ({completeness})")
        elif completeness in ("no_body_received", "read_error_after_headers"):
            partial_or_error_count += 1
            if receipt_doc.get("complete") is not False or runtime.get("http_capture_complete") is not False:
                item_errors.append(f"finding[{idx}] no-body transport failure must have complete=False")
            if runtime.get("response_body_sha256") is not None or receipt_doc.get("response_body_sha256") is not None:
                item_errors.append(f"finding[{idx}] no-body transport failure must not set response_body_sha256")
            if resp_bin_path.exists() or inc_bin_path.exists():
                item_errors.append(f"finding[{idx}] no-body transport failure must not fabricate response binary files")
            if runtime.get("answer_validated") is True or assessment.get("validated_status") != "UNDETERMINED":
                item_errors.append(f"finding[{idx}] no-body transport failure must fail closed to UNDETERMINED")
            if require_live_chat:
                item_errors.append(f"finding[{idx}] HTTP transport failed before complete body ({completeness})")
        else:
            item_errors.append(f"finding[{idx}] unrecognized or missing receipt completeness: {completeness!r}")

        if require_live_chat and is_mock:
            item_errors.append(f"finding[{idx}] ({rec_id}) is marked mock, not real live Qwen HTTP")

        finding_checks.append({
            "finding_index": idx,
            "id": rec_id,
            "call_id": receipt_doc.get("call_id") if receipt_doc else None,
            "mode": "http_transport",
            "mock": is_mock,
            "http_status": receipt_doc.get("http_status") if receipt_doc else runtime.get("http_status"),
            "completeness": completeness,
            "request_byte_length": req_len_verified,
            "request_payload_sha256": req_sha_verified,
            "response_byte_length": resp_len_verified,
            "response_body_sha256": resp_sha_verified,
            "response_json_sha256": runtime.get("response_json_sha256"),
            "verified": len(item_errors) == 0,
            "errors": item_errors,
        })
        errors.extend(item_errors)

    if io_dir.is_dir():
        for entry in sorted(io_dir.iterdir(), key=lambda p: p.name):
            if entry.name == "_tags" and entry.is_dir():
                continue
            if entry.is_file() and entry.name not in expected_chat_files:
                errors.append(f"orphan file in llm_io not bound to any finding in assessments.jsonl: {entry.name}")
            elif entry.is_dir():
                errors.append(f"unexpected subdirectory in llm_io: {entry.name}")

    if require_live_chat and len(rows) < max(1, minimum_findings):
        errors.append(f"live chat requires at least {max(1, minimum_findings)} finding(s), found {len(rows)}")
    if require_live_chat and live_non_mock_complete_count < max(1, minimum_findings, len(rows)):
        errors.append(
            f"live chat requires {max(1, minimum_findings, len(rows))} non-mock complete HTTP 200 chat capture(s), found {live_non_mock_complete_count}"
        )

    integrity_ok = len(errors) == 0
    if not integrity_ok:
        status = "FAILED"
    elif len(rows) == 0:
        status = "NO_FINDINGS"
    elif disabled_count == len(rows):
        status = "DISABLED"
    elif mock_method_count == len(rows):
        status = "MOCKED_REQUEST_METHOD"
    elif complete_chat_count == len(rows):
        status = "VERIFIED_COMPLETE"
    else:
        status = "VERIFIED_ERROR_OR_PARTIAL_CAPTURED"

    live_chat_ok = bool(
        integrity_ok
        and len(rows) >= max(1, minimum_findings)
        and live_non_mock_complete_count == len(rows)
    )

    return {
        "schema": "ntk-http-capture-verification-1",
        "capture_scope": "http_body_and_client_metadata_not_tcp_wire",
        "capture_status": status,
        "capture_integrity_ok": integrity_ok,
        "live_chat_verified": live_chat_ok,
        "total_findings": len(rows),
        "complete_http_200_captures": complete_chat_count,
        "live_non_mock_complete_captures": live_non_mock_complete_count,
        "partial_or_error_captures": partial_or_error_count,
        "tags_probes": tags_probes,
        "findings": finding_checks,
        "errors": errors,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify raw same-call HTTP request/response captures in a triage directory")
    parser.add_argument("run", type=Path, help="Path to <run>/triage directory")
    parser.add_argument("--require-live-chat", action="store_true", help="Require non-mock complete HTTP 200 chat captures")
    parser.add_argument("--minimum-findings", type=int, default=0, help="Minimum expected finding count")
    parser.add_argument("--output", type=Path, default=None, help="Write JSON report to this path instead of <run>/http-capture-check.json")
    parser.add_argument("--no-write", action="store_true", help="Print JSON report to stdout only without writing any file")
    args = parser.parse_args(argv)
    if args.minimum_findings < 0:
        parser.error("--minimum-findings must be >= 0")

    result = verify_run_http_captures(
        args.run,
        require_live_chat=args.require_live_chat,
        minimum_findings=args.minimum_findings,
    )
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    if not args.no_write:
        target = args.output if args.output is not None else (Path(args.run) / "http-capture-check.json")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    if args.require_live_chat:
        return 0 if result["live_chat_verified"] else 2
    return 0 if result["capture_integrity_ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
