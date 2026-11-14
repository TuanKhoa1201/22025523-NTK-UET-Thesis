"""Check recorded live HTTP protocol independently of triage exit/verdict; no model attestation."""
import argparse
import json
from pathlib import Path
from .evidence import digest, strict_json
from .ollama import request_payload


def inspect(rows, minimum=1):
    details = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("assessment"), dict) or not isinstance(row.get("evidence"), dict):
            details.append({"id": None, "ollama_reported_completed_inference": False, "error": "malformed row"})
            continue
        evidence = row.get("evidence", {})
        assessment = row["assessment"]
        r, response = assessment.get("runtime", {}), assessment.get("raw_response")
        if not isinstance(r, dict):
            r = {}
        mock = r.get("origin") == "mock" or (isinstance(response, dict) and response.get("mock_test_fixture") is True)
        index = evidence.get("finding_index")
        provenance = evidence.get("scan_provenance")
        join = (type(index) is int and index >= 0 and isinstance(evidence.get("scan_sha256"), str)
                and evidence.get("id") == row.get("id") == r.get("finding_id")
                and row.get("id") == digest((evidence["scan_sha256"] + ":" + str(index)).encode())
                and isinstance(provenance, dict) and provenance.get("source_capture_verified") is True)
        try:
            payload_bound = r.get("request_payload_sha256") == digest(json.dumps(request_payload(evidence, assessment.get("model"))).encode("utf-8"))
        except (KeyError, TypeError, ValueError):
            payload_bound = False
        observed = (join and payload_bound and not mock and r.get("request_attempted") is True and r.get("http_response_received") is True
                    and r.get("http_status") == 200 and isinstance(response, dict))
        canonical = json.dumps(response, sort_keys=True, ensure_ascii=False, allow_nan=False).encode("utf-8")
        bound = observed and r.get("response_json_sha256") == digest(canonical)
        counters = (bound and response.get("done") is True and response.get("done_reason") in (None, "stop")
                    and response.get("model") == assessment.get("model")
                    and type(response.get("eval_count")) is int and response["eval_count"] > 0
                    and type(response.get("eval_duration")) is int and response["eval_duration"] > 0)
        details.append({"id": row.get("id"), "mock": mock, "finding_join_valid": bool(join), "request_payload_bound": payload_bound,
                        "bound_http_response": bool(bound),
                        "ollama_reported_completed_inference": bool(counters),
                        "model_status": assessment.get("status"), "answer_validated": r.get("answer_validated") is True})
    count = sum(d["ollama_reported_completed_inference"] for d in details)
    return {"protocol_status": "OLLAMA_REPORTED_UNATTESTED" if count >= minimum else "PENDING",
            "completed_reported_responses": count, "minimum_required": minimum, "warnings": details,
            "independently_verified_model_runtime": False,
            "note": "Unsigned local evidence; requires server model identity/run logs for independent M2 acceptance"}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("run", type=Path)
    p.add_argument("--minimum-responses", type=int, default=1)
    a = p.parse_args()
    if a.minimum_responses < 1:
        p.error("minimum must be positive")
    try:
        rows = [strict_json(line) for line in (a.run / "assessments.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
        result = inspect(rows, a.minimum_responses)
    except (OSError, ValueError, TypeError, UnicodeError) as exc:
        result = {"protocol_status": "PENDING", "error": str(exc), "independently_verified_model_runtime": False}
    (a.run / "live-protocol-check.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if result["protocol_status"] == "OLLAMA_REPORTED_UNATTESTED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
