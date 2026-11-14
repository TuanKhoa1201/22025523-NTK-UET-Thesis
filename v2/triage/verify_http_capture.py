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
import os
from pathlib import Path
import re
import stat
from typing import Any

from .evidence import EvidenceError, digest, strict_json
from .ollama import MAX_HTTP_BODY_BYTES, CaptureWriteError, is_reparse_link, request_payload

MAX_METADATA_JSON_BYTES = 16 * 1024 * 1024


def _safe_id(finding_id: Any) -> str:
    return re.sub(r"[^0-9a-fA-F_-]", "_", str(finding_id or "unknown"))[:80]


def _is_strict_basename(name: Any) -> bool:
    if not isinstance(name, str) or not name or name in (".", ".."):
        return False
    if "/" in name or "\\" in name or ":" in name or "\x00" in name:
        return False
    p = Path(name)
    if p.is_absolute() or bool(p.drive) or p.name != name:
        return False
    return True


def _safe_regular_child_file(
    parent_dir: Path,
    resolved_parent: Path,
    filename: Any,
    *,
    max_bytes: int | None,
    label: str,
    errors: list[str],
) -> Path | None:
    if not _is_strict_basename(filename):
        errors.append(f"{label} uses unsafe non-basename artifact path: {filename!r}")
        return None
    candidate = parent_dir / filename
    if not os.path.lexists(candidate):
        errors.append(f"missing {label}: {filename}")
        return None
    try:
        if is_reparse_link(candidate):
            errors.append(f"{label} {filename} must not be a symlink or junction")
            return None
        st = os.lstat(candidate)
        if not stat.S_ISREG(st.st_mode):
            errors.append(f"{label} {filename} is not a regular file")
            return None
        resolved = candidate.resolve(strict=True)
        if resolved.parent != resolved_parent or resolved.name != filename:
            errors.append(f"{label} {filename} resolves outside allowed capture directory: {resolved}")
            return None
        if max_bytes is not None and st.st_size > max_bytes:
            errors.append(f"{label} {filename} exceeds byte bound ({st.st_size} > {max_bytes})")
            return None
    except (OSError, CaptureWriteError, RuntimeError) as exc:
        errors.append(f"cannot verify {label} {filename}: {exc}")
        return None
    return candidate


_TAGS_RECEIPT_RE = re.compile(r"tags-\d{4}\.http-capture\.json")


def _failed_report(errors: list[str]) -> dict[str, Any]:
    return {
        "schema": "ntk-http-capture-verification-1",
        "capture_scope": "http_body_and_client_metadata_not_tcp_wire",
        "capture_status": "FAILED",
        "capture_integrity_ok": False,
        "live_chat_verified": False,
        "errors": errors,
        "findings": [],
        "tags_probes": [],
    }


def _verify_tags_captures(tags_dir: Path, seen_call_ids: set[str], errors: list[str]) -> list[dict[str, Any]]:
    probes: list[dict[str, Any]] = []
    raw_tags = Path(tags_dir)
    if ".." in raw_tags.parts:
        errors.append(f"llm_io/_tags path must not contain '..': {tags_dir}")
        return probes
    abs_tags = Path(os.path.abspath(raw_tags))
    if abs_tags.parent != abs_tags and abs_tags.parent != Path(abs_tags.anchor):
        if os.path.lexists(abs_tags.parent):
            try:
                if is_reparse_link(abs_tags.parent):
                    errors.append(f"llm_io parent directory is a symlink or junction: {abs_tags.parent}")
                    return probes
            except CaptureWriteError as exc:
                errors.append(str(exc))
                return probes
    if not os.path.lexists(abs_tags):
        return probes
    try:
        if is_reparse_link(abs_tags):
            errors.append(f"llm_io/_tags must not be a symlink or junction: {abs_tags}")
            return probes
        st = os.lstat(abs_tags)
        if not stat.S_ISDIR(st.st_mode):
            errors.append(f"llm_io/_tags is not a directory: {abs_tags}")
            return probes
        resolved_tags = abs_tags.resolve(strict=True)
        if os.path.lexists(abs_tags.parent) and resolved_tags.parent != abs_tags.parent.resolve(strict=True):
            errors.append(f"llm_io/_tags resolves outside parent llm_io directory: {resolved_tags}")
            return probes
        dir_entries = sorted(abs_tags.iterdir(), key=lambda p: p.name)
    except (OSError, CaptureWriteError, RuntimeError) as exc:
        errors.append(f"cannot inspect llm_io/_tags {abs_tags}: {exc}")
        return probes

    receipt_files: list[Path] = []
    regular_names: list[str] = []
    for entry in dir_entries:
        try:
            if is_reparse_link(entry):
                errors.append(f"symlink or junction forbidden in llm_io/_tags: {entry.name}")
                continue
            est = os.lstat(entry)
            if stat.S_ISDIR(est.st_mode):
                errors.append(f"unexpected directory inside llm_io/_tags: {entry.name}")
                continue
            if not stat.S_ISREG(est.st_mode):
                errors.append(f"non-regular file inside llm_io/_tags: {entry.name}")
                continue
        except (OSError, CaptureWriteError) as exc:
            errors.append(f"cannot inspect llm_io/_tags entry {entry.name}: {exc}")
            continue
        regular_names.append(entry.name)
        if entry.name.endswith(".http-capture.json"):
            if not _TAGS_RECEIPT_RE.fullmatch(entry.name):
                errors.append(f"unexpected tags receipt filename format: {entry.name}")
                continue
            receipt_files.append(entry)

    expected_files: set[str] = set()
    for r_file in receipt_files:
        expected_files.add(r_file.name)
        prefix = r_file.name[: -len(".http-capture.json")]
        safe_r = _safe_regular_child_file(
            abs_tags,
            resolved_tags,
            r_file.name,
            max_bytes=1024 * 1024,
            label="tags receipt",
            errors=errors,
        )
        if safe_r is None:
            continue
        try:
            doc = strict_json(safe_r.read_text(encoding="utf-8"))
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
        expected_resp_name = f"{prefix}.response.body.bin"
        expected_inc_name = f"{prefix}.response.incomplete.bin"
        probe_ok = True
        if completeness in ("complete", "complete_http_error_body"):
            if resp_name != expected_resp_name:
                errors.append(
                    f"tags receipt {r_file.name} response_raw_file must be exact basename {expected_resp_name!r}, got {resp_name!r}"
                )
                probe_ok = False
            else:
                expected_files.add(resp_name)
                resp_path = _safe_regular_child_file(
                    abs_tags,
                    resolved_tags,
                    resp_name,
                    max_bytes=MAX_HTTP_BODY_BYTES,
                    label="tags raw response body",
                    errors=errors,
                )
                if resp_path is None:
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
            if inc_name != expected_inc_name:
                errors.append(
                    f"tags receipt {r_file.name} response_incomplete_raw_file must be {expected_inc_name!r}, got {inc_name!r}"
                )
                probe_ok = False
            else:
                expected_files.add(inc_name)
                inc_path = _safe_regular_child_file(
                    abs_tags,
                    resolved_tags,
                    inc_name,
                    max_bytes=MAX_HTTP_BODY_BYTES + 1024,
                    label="tags incomplete body",
                    errors=errors,
                )
                if inc_path is None:
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

    for actual in regular_names:
        if actual not in expected_files:
            errors.append(f"orphan file in llm_io/_tags not referenced by any tags receipt: {actual}")

    return probes


def verify_run_http_captures(
    triage_dir: Path,
    *,
    require_live_chat: bool = False,
    minimum_findings: int = 0,
) -> dict[str, Any]:
    raw_triage = Path(triage_dir)
    if ".." in raw_triage.parts:
        return _failed_report([f"triage_dir must not contain '..': {triage_dir}"])
    abs_triage = Path(os.path.abspath(raw_triage))
    errors: list[str] = []
    if not os.path.lexists(abs_triage):
        return _failed_report([f"missing triage directory: {abs_triage}"])
    try:
        if abs_triage.parent != abs_triage and abs_triage.parent != Path(abs_triage.anchor):
            if os.path.lexists(abs_triage.parent) and is_reparse_link(abs_triage.parent):
                return _failed_report([f"triage parent directory is a symlink or junction: {abs_triage.parent}"])
        if is_reparse_link(abs_triage):
            return _failed_report([f"triage directory must not be a symlink or junction: {abs_triage}"])
        if not stat.S_ISDIR(os.lstat(abs_triage).st_mode):
            return _failed_report([f"triage path is not a directory: {abs_triage}"])
        resolved_triage = abs_triage.resolve(strict=True)
        if abs_triage.parent != abs_triage and os.path.lexists(abs_triage.parent):
            if resolved_triage.parent != abs_triage.parent.resolve(strict=True):
                return _failed_report([f"triage directory resolves outside parent directory: {resolved_triage}"])
    except (OSError, CaptureWriteError, RuntimeError) as exc:
        return _failed_report([f"cannot verify triage directory {abs_triage}: {exc}"])

    finding_checks: list[dict[str, Any]] = []
    seen_call_ids: set[str] = set()

    parse_errors: list[str] = []
    evidence_path = _safe_regular_child_file(
        abs_triage,
        resolved_triage,
        "evidence.json",
        max_bytes=64 * 1024 * 1024,
        label="evidence.json",
        errors=parse_errors,
    )
    assessments_path = _safe_regular_child_file(
        abs_triage,
        resolved_triage,
        "assessments.jsonl",
        max_bytes=64 * 1024 * 1024,
        label="assessments.jsonl",
        errors=parse_errors,
    )
    if evidence_path is None or assessments_path is None:
        return _failed_report(parse_errors)

    try:
        bundle = strict_json(evidence_path.read_text(encoding="utf-8"))
        rows = [
            strict_json(line)
            for line in assessments_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, UnicodeError, ValueError, EvidenceError) as exc:
        return _failed_report([f"failed to parse evidence/assessments: {exc}"])

    records = bundle.get("records") if isinstance(bundle, dict) else None
    scan_sha = bundle.get("scan_sha256") if isinstance(bundle, dict) else None
    if not isinstance(records, list) or not isinstance(scan_sha, str):
        errors.append("evidence.json missing records list or scan_sha256")
        records = []

    if len(rows) != len(records):
        errors.append(f"finding count mismatch: evidence={len(records)} vs assessments={len(rows)}")

    io_dir = abs_triage / "llm_io"
    io_dir_exists = os.path.lexists(io_dir)
    io_dir_safe = False
    resolved_io_dir: Path | None = None
    io_regular_files: list[str] = []
    if io_dir_exists:
        try:
            if is_reparse_link(io_dir):
                errors.append(f"llm_io must not be a symlink or junction: {io_dir}")
            elif not stat.S_ISDIR(os.lstat(io_dir).st_mode):
                errors.append(f"llm_io is not a directory: {io_dir}")
            else:
                cand_resolved_io = io_dir.resolve(strict=True)
                if cand_resolved_io != resolved_triage / "llm_io":
                    errors.append(f"llm_io resolves outside triage directory: {cand_resolved_io}")
                else:
                    io_dir_safe = True
                    resolved_io_dir = cand_resolved_io
                    for entry in sorted(io_dir.iterdir(), key=lambda p: p.name):
                        if is_reparse_link(entry):
                            errors.append(f"symlink or junction forbidden inside llm_io: {entry.name}")
                            continue
                        est = os.lstat(entry)
                        if entry.name == "_tags" and stat.S_ISDIR(est.st_mode):
                            continue
                        if stat.S_ISDIR(est.st_mode):
                            errors.append(f"unexpected subdirectory in llm_io: {entry.name}")
                        elif stat.S_ISREG(est.st_mode):
                            io_regular_files.append(entry.name)
                        else:
                            errors.append(f"non-regular entry in llm_io: {entry.name}")
        except (OSError, CaptureWriteError, RuntimeError) as exc:
            errors.append(f"cannot inspect llm_io directory {io_dir}: {exc}")

    tags_probes = _verify_tags_captures(io_dir / "_tags", seen_call_ids, errors) if io_dir_safe else []
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

        if io_dir_exists and not io_dir_safe:
            item_errors.append(f"finding[{idx}] unsafe or escaped llm_io directory rejected")

        sidecar_stem_raw = runtime.get("sidecar_artifact_stem")
        sidecar_stem = safe_id
        if sidecar_stem_raw is not None:
            if re.fullmatch(rf"{re.escape(safe_id)}(?:\.attempt-\d{{4}})?", str(sidecar_stem_raw)):
                sidecar_stem = str(sidecar_stem_raw)
            else:
                item_errors.append(f"finding[{idx}] invalid sidecar_artifact_stem: {sidecar_stem_raw!r}")

        if origin == "disabled" and assessment.get("transport") == "disabled":
            disabled_count += 1
            if req_attempted:
                item_errors.append(f"finding[{idx}] disabled transport unexpectedly attempted HTTP request")
            if io_dir_safe:
                for suffix in (".request.body.bin", ".response.body.bin", ".response.incomplete.bin", ".http-capture.json"):
                    if os.path.lexists(io_dir / f"{safe_id}{suffix}"):
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
            if io_dir_safe and resolved_io_dir is not None:
                for suffix in (".prompt.json", ".request.json", ".response.json"):
                    sname = f"{sidecar_stem}{suffix}"
                    if os.path.lexists(io_dir / sname):
                        cand = _safe_regular_child_file(
                            io_dir, resolved_io_dir, sname, max_bytes=MAX_METADATA_JSON_BYTES, label=f"finding[{idx}] sidecar", errors=item_errors
                        )
                        if cand is not None:
                            expected_chat_files.add(sname)
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
            if io_dir_safe and resolved_io_dir is not None:
                for suffix in (".prompt.json", ".request.json", ".response.json"):
                    sname = f"{sidecar_stem}{suffix}"
                    if os.path.lexists(io_dir / sname):
                        cand = _safe_regular_child_file(
                            io_dir, resolved_io_dir, sname, max_bytes=MAX_METADATA_JSON_BYTES, label=f"finding[{idx}] sidecar", errors=item_errors
                        )
                        if cand is not None:
                            expected_chat_files.add(sname)
                for suffix in (".request.body.bin", ".response.body.bin", ".response.incomplete.bin", ".http-capture.json"):
                    if os.path.lexists(io_dir / f"{sidecar_stem}{suffix}"):
                        item_errors.append(f"finding[{idx}] precheck-aborted finding unexpectedly has {sidecar_stem}{suffix}")
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
        if not io_dir_safe or resolved_io_dir is None:
            item_errors.append(f"finding[{idx}] missing or unsafe llm_io directory: {io_dir}")
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

        receipt_path = _safe_regular_child_file(
            io_dir, resolved_io_dir, receipt_name, max_bytes=MAX_METADATA_JSON_BYTES, label=f"finding[{idx}] HTTP capture receipt", errors=item_errors
        )
        req_bin_path = _safe_regular_child_file(
            io_dir, resolved_io_dir, req_bin_name, max_bytes=MAX_METADATA_JSON_BYTES, label=f"finding[{idx}] raw request body", errors=item_errors
        )
        resp_bin_path = io_dir / resp_bin_name
        inc_bin_path = io_dir / inc_bin_name

        for sidecar_name in (receipt_name, req_bin_name, prompt_json_name, req_json_name, resp_json_name):
            expected_chat_files.add(sidecar_name)

        receipt_doc: dict[str, Any] = {}
        if receipt_path is not None:
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
            if receipt_doc.get("request_raw_file") != req_bin_name:
                item_errors.append(
                    f"finding[{idx}] receipt request_raw_file must be {req_bin_name!r}, got {receipt_doc.get('request_raw_file')!r}"
                )
            if runtime.get("request_raw_artifact") != f"llm_io/{req_bin_name}":
                item_errors.append(f"finding[{idx}] runtime.request_raw_artifact mismatch")

        # Verify raw request payload bytes
        req_sha_verified = None
        req_len_verified = None
        if req_bin_path is not None:
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
            sidecar_path = _safe_regular_child_file(
                io_dir,
                resolved_io_dir,
                json_sidecar,
                max_bytes=MAX_METADATA_JSON_BYTES,
                label=f"finding[{idx}] compatibility artifact",
                errors=item_errors,
            )
            if sidecar_path is not None:
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
            if receipt_doc.get("response_raw_file") != resp_bin_name:
                item_errors.append(
                    f"finding[{idx}] receipt response_raw_file must be {resp_bin_name!r}, got {receipt_doc.get('response_raw_file')!r}"
                )
            if runtime.get("response_raw_artifact") != f"llm_io/{resp_bin_name}":
                item_errors.append(f"finding[{idx}] runtime.response_raw_artifact mismatch")
            if os.path.lexists(inc_bin_path):
                item_errors.append(f"finding[{idx}] unexpected {inc_bin_name} alongside complete response")
            safe_resp_path = _safe_regular_child_file(
                io_dir,
                resolved_io_dir,
                resp_bin_name,
                max_bytes=MAX_HTTP_BODY_BYTES,
                label=f"finding[{idx}] raw response body",
                errors=item_errors,
            )
            if safe_resp_path is not None:
                resp_bytes = safe_resp_path.read_bytes()
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
            if os.path.lexists(resp_bin_path):
                item_errors.append(f"finding[{idx}] incomplete response must not write {resp_bin_name}")
            if receipt_doc.get("response_incomplete_raw_file") is not None:
                if receipt_doc.get("response_incomplete_raw_file") != inc_bin_name:
                    item_errors.append(
                        f"finding[{idx}] receipt response_incomplete_raw_file must be {inc_bin_name!r}, got {receipt_doc.get('response_incomplete_raw_file')!r}"
                    )
                else:
                    expected_chat_files.add(inc_bin_name)
                    safe_inc_path = _safe_regular_child_file(
                        io_dir,
                        resolved_io_dir,
                        inc_bin_name,
                        max_bytes=MAX_HTTP_BODY_BYTES + 1024,
                        label=f"finding[{idx}] incomplete body",
                        errors=item_errors,
                    )
                    if safe_inc_path is not None:
                        inc_bytes = safe_inc_path.read_bytes()
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
            if os.path.lexists(resp_bin_path) or os.path.lexists(inc_bin_path):
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

    if io_dir_safe:
        for fname in io_regular_files:
            if fname not in expected_chat_files:
                errors.append(f"orphan file in llm_io not bound to any finding in assessments.jsonl: {fname}")

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
        unsafe_reason = None
        if args.output is None:
            run_path = Path(args.run)
            if ".." in run_path.parts or not os.path.lexists(run_path) or is_reparse_link(run_path) or not run_path.is_dir():
                unsafe_reason = f"refusing to write http-capture-check.json into unsafe or link triage dir: {args.run}"
            elif os.path.lexists(target) and is_reparse_link(target):
                unsafe_reason = f"refusing to write through reparse/symlink target: {target}"
        else:
            if ".." in target.parts:
                unsafe_reason = f"refusing '..' in verifier --output path: {target}"
            else:
                for anc in (target, *target.parents):
                    if os.path.lexists(anc) and is_reparse_link(anc):
                        unsafe_reason = f"refusing to write --output through reparse/symlink ancestor: {anc}"
                        break
        if unsafe_reason is not None:
            if unsafe_reason not in result["errors"]:
                result["errors"].append(unsafe_reason)
            result["capture_integrity_ok"] = False
            result["live_chat_verified"] = False
            result["capture_status"] = "FAILED"
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 2
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    if args.require_live_chat:
        return 0 if result["live_chat_verified"] else 2
    return 0 if result["capture_integrity_ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
