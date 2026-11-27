"""Check recorded live HTTP protocol independently of triage exit/verdict; no model attestation."""
import argparse
import json
from pathlib import Path
from .evidence import digest, strict_json
from .ollama import (
    DEFAULT_PROMPT_CONTRACT,
    LEGACY_STEERED_PROMPT_VERSION,
    PROMPT_CONTRACTS,
    request_payload,
    request_payload_for_version,
)

# Strict contract boundary for legacy M2 minimal protocol unit-test rows (no runtime capture or prompt metadata).
# Any row carrying runtime capture artifacts, transport/endpoint fields, validation provenance, or prompt metadata
# MUST pass full cryptographic prompt-metadata verification and can NEVER fall back to the M2 minimal branch.
_M2_MINIMAL_ASSESSMENT_KEYS = frozenset({"status", "model", "runtime", "raw_response"})
_M2_MINIMAL_RUNTIME_KEYS = frozenset(
    {
        "origin",
        "request_attempted",
        "http_response_received",
        "http_status",
        "finding_id",
        "request_payload_sha256",
        "response_json_sha256",
        "answer_validated",
    }
)


def _is_minimal_m2_protocol_row(evidence: dict, assessment: dict, runtime: dict) -> bool:
    if "prompt_contract" in evidence:
        return False
    if set(assessment.keys()) != _M2_MINIMAL_ASSESSMENT_KEYS:
        return False
    if not (set(runtime.keys()) <= _M2_MINIMAL_RUNTIME_KEYS):
        return False
    if runtime.get("origin") != "unverified":
        return False
    return True


def inspect(rows, minimum=1, *, require_prompt_metadata=False):
    details = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("assessment"), dict) or not isinstance(row.get("evidence"), dict):
            details.append({"id": None, "ollama_reported_completed_inference": False, "error": "malformed row"})
            continue
        evidence = row.get("evidence", {})
        assessment = row["assessment"]
        raw_r, response = assessment.get("runtime"), assessment.get("raw_response")
        r = raw_r if isinstance(raw_r, dict) else {}
        origin = r.get("origin")
        mock = origin == "mock" or (isinstance(response, dict) and response.get("mock_test_fixture") is True)
        origin_live_valid = origin == "unverified" and not mock
        index = evidence.get("finding_index")
        provenance = evidence.get("scan_provenance")
        join = (type(index) is int and index >= 0 and isinstance(evidence.get("scan_sha256"), str)
                and evidence.get("id") == row.get("id") == r.get("finding_id")
                and row.get("id") == digest((evidence["scan_sha256"] + ":" + str(index)).encode())
                and isinstance(provenance, dict) and provenance.get("source_capture_verified") is True)
        protocol_metadata_mode = "FAILED"
        model_name = assessment.get("model")
        model_str_ok = isinstance(model_name, str) and bool(model_name.strip())
        attestation_flags_safe = (
            assessment.get("security_conclusion_verified") is not True
            and r.get("model_runtime_verified") is not True
            and assessment.get("requires_human_review") is not False
            and ("state" not in row or row.get("state") == "OPEN")
            and ("human_review_state" not in row or row.get("human_review_state") == "OPEN")
        )
        try:
            if not isinstance(raw_r, dict) or not model_str_ok or not attestation_flags_safe:
                payload_bound = False
            elif not require_prompt_metadata and _is_minimal_m2_protocol_row(evidence, assessment, r):
                # Strict M2 minimal protocol row (contains ONLY M2 protocol fields, zero capture/prompt metadata):
                # binds exact canonical current request_payload_sha256 while labeling mode explicitly.
                expected_payload = request_payload(evidence, model_name)
                payload_bound = r.get("request_payload_sha256") == digest(
                    json.dumps(expected_payload).encode("utf-8")
                )
                if payload_bound:
                    protocol_metadata_mode = "MINIMAL_M2_PROTOCOL_NO_PROMPT_METADATA"
            else:
                rec_pv = assessment.get("prompt_version")
                expected_payload, ser_meta = request_payload_for_version(
                    evidence, model_name, prompt_version=rec_pv
                )
                if expected_payload is None:
                    payload_bound = False
                else:
                    is_hist = bool(ser_meta.get("historical"))
                    expected_req_sha = digest(json.dumps(expected_payload).encode("utf-8"))
                    expected_prompt_sha = digest(
                        json.dumps(expected_payload.get("messages"), ensure_ascii=False).encode("utf-8")
                    )
                    expected_fp = ser_meta.get("serializer_fingerprint")
                    rec_contract = evidence.get("prompt_contract", DEFAULT_PROMPT_CONTRACT)
                    ass_contract = assessment.get("prompt_contract")
                    rt_contract_ok = (
                        ("prompt_contract" in r and r.get("prompt_contract") == rec_contract)
                        if not is_hist
                        else ("prompt_contract" not in r or r.get("prompt_contract") == rec_contract)
                    )
                    contract_ok = (
                        rec_contract in PROMPT_CONTRACTS
                        and (
                            ass_contract == rec_contract
                            if ass_contract is not None
                            else rec_pv == LEGACY_STEERED_PROMPT_VERSION
                        )
                        and rt_contract_ok
                    )
                    prompt_sha_ok = (
                        assessment.get("prompt_sha256") == expected_prompt_sha
                        and r.get("prompt_sha256") == expected_prompt_sha
                    )
                    fp_ok = True
                    if "serializer_fingerprint" in assessment:
                        fp_ok = fp_ok and (assessment.get("serializer_fingerprint") == expected_fp)
                    elif not is_hist:
                        fp_ok = False
                    if "serializer_fingerprint" in r:
                        fp_ok = fp_ok and (r.get("serializer_fingerprint") == expected_fp)
                    elif not is_hist:
                        fp_ok = False
                    if "prompt_version" in r:
                        fp_ok = fp_ok and (r.get("prompt_version") == rec_pv)
                    elif not is_hist:
                        fp_ok = False
                    payload_bound = (
                        r.get("request_payload_sha256") == expected_req_sha
                        and prompt_sha_ok
                        and contract_ok
                        and fp_ok
                    )
                    if payload_bound:
                        protocol_metadata_mode = (
                            "HISTORICAL_PROMPT_METADATA_BOUND" if is_hist else "EXPLICIT_PROMPT_METADATA_BOUND"
                        )
        except (KeyError, TypeError, ValueError):
            payload_bound = False
        rt_capture_consistent = (
            ("http_capture_complete" not in r or r.get("http_capture_complete") is True)
            and ("http_capture_completeness" not in r or r.get("http_capture_completeness") == "complete")
            and ("response_complete" not in r or r.get("response_complete") is True)
            and ("model_identity_matched" not in r or r.get("model_identity_matched") is True)
            and ("answer_validated" not in r or isinstance(r.get("answer_validated"), bool))
            and (
                "failure_kind" not in assessment
                or "failure_kind" not in r
                or assessment.get("failure_kind") == r.get("failure_kind")
            )
            and (
                "validated_status" not in row
                or row.get("validated_status") == assessment.get("validated_status", assessment.get("status"))
            )
            and (
                "raw_model_status" not in row
                or row.get("raw_model_status") == assessment.get("raw_model_status")
            )
        )
        observed = (
            join
            and payload_bound
            and origin_live_valid
            and attestation_flags_safe
            and rt_capture_consistent
            and r.get("request_attempted") is True
            and r.get("http_response_received") is True
            and type(r.get("http_status")) is int
            and r.get("http_status") == 200
            and isinstance(response, dict)
        )
        canonical = json.dumps(response, sort_keys=True, ensure_ascii=False, allow_nan=False).encode("utf-8") if isinstance(response, dict) else b""
        bound = observed and r.get("response_json_sha256") == digest(canonical)
        verdict_consistent = True
        if bound and r.get("answer_validated") is True:
            msg_content = response.get("message", {}).get("content") if isinstance(response.get("message"), dict) else None
            if isinstance(msg_content, str):
                try:
                    parsed_ans = strict_json(msg_content)
                except (ValueError, TypeError):
                    parsed_ans = None
                ans_st = parsed_ans.get("status") if isinstance(parsed_ans, dict) else None
                if (
                    ans_st not in ("SUPPORTED", "REFUTED", "UNDETERMINED")
                    or assessment.get("status") != ans_st
                    or assessment.get("validated_status", assessment.get("status")) != ans_st
                    or ("raw_model_status" in assessment and assessment.get("raw_model_status") != ans_st)
                    or assessment.get("validator_downgraded") is True
                    or ("failure_kind" in assessment and assessment.get("failure_kind") != "NONE")
                ):
                    verdict_consistent = False
            else:
                verdict_consistent = False
        elif bound and r.get("answer_validated") is False:
            if (
                assessment.get("status") != "UNDETERMINED"
                or assessment.get("validated_status", assessment.get("status")) != "UNDETERMINED"
            ):
                verdict_consistent = False
        counters = (
            bound
            and verdict_consistent
            and response.get("done") is True
            and response.get("done_reason") in (None, "stop")
            and model_str_ok
            and response.get("model") == model_name
            and type(response.get("eval_count")) is int
            and response["eval_count"] > 0
            and type(response.get("eval_duration")) is int
            and response["eval_duration"] > 0
            and ("reported_eval_count" not in r or (type(r.get("reported_eval_count")) is int and r["reported_eval_count"] == response["eval_count"]))
            and ("reported_eval_duration_ns" not in r or (type(r.get("reported_eval_duration_ns")) is int and r["reported_eval_duration_ns"] == response["eval_duration"]))
        )
        details.append({"id": row.get("id"), "mock": mock, "finding_join_valid": bool(join), "request_payload_bound": payload_bound,
                        "protocol_metadata_mode": protocol_metadata_mode,
                        "bound_http_response": bool(bound),
                        "ollama_reported_completed_inference": bool(counters),
                        "model_status": assessment.get("status"), "answer_validated": r.get("answer_validated") is True})
    count = sum(d["ollama_reported_completed_inference"] for d in details)
    return {
        "protocol_status": "OLLAMA_REPORTED_UNATTESTED" if count >= minimum else "PENDING",
        "verification_scope": "assessment_rows_protocol_only_no_sidecar_or_live_origin_attestation",
        "completed_reported_responses": count,
        "minimum_required": minimum,
        "warnings": details,
        "live_origin_verified": False,
        "independently_verified_model_runtime": False,
        "security_conclusion_verified": False,
        "note": (
            "Unsigned self-reported assessment rows only; does not inspect receipt/sidecar files "
            "or verify live Ollama origin; requires operator-collected external runtime evidence "
            "and server model identity/run logs for independent M2/runtime acceptance"
        ),
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("run", type=Path)
    p.add_argument("--minimum-responses", type=int, default=1)
    a = p.parse_args()
    if a.minimum_responses < 1:
        p.error("minimum must be positive")
    try:
        rows = [strict_json(line) for line in (a.run / "assessments.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
        result = inspect(rows, a.minimum_responses, require_prompt_metadata=(a.run / "llm_io").is_dir())
    except (OSError, ValueError, TypeError, UnicodeError) as exc:
        result = {
            "protocol_status": "PENDING",
            "verification_scope": "assessment_rows_protocol_only_no_sidecar_or_live_origin_attestation",
            "error": str(exc),
            "live_origin_verified": False,
            "independently_verified_model_runtime": False,
            "security_conclusion_verified": False,
        }
    (a.run / "live-protocol-check.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if result["protocol_status"] == "OLLAMA_REPORTED_UNATTESTED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
