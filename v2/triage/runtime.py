"""Separate received HTTP, validated answers and externally attested model execution."""
SCHEMA_VERSION = "1.1"


def execution(origin="unverified"):
    return {"origin": origin, "request_attempted": False, "http_response_received": False,
            "http_status": None, "response_body_sha256": None,
            "response_json_sha256": None,
            "request_payload_sha256": None, "finding_id": None,
            "response_complete": False, "model_identity_matched": False,
            "reported_eval_count": None, "reported_eval_duration_ns": None,
            "answer_validated": False, "model_runtime_verified": False}


def summary(assessments):
    runs = [a.get("runtime", execution()) for a in assessments]
    return {"warnings": len(runs),
            "http_responses_received": sum(r.get("http_response_received") is True for r in runs),
            "validated_answers": sum(r.get("answer_validated") is True for r in runs),
            "mock_records": sum(r.get("origin") == "mock" for r in runs),
            "ollama_reported_inference": sum(r.get("origin") != "mock" and r.get("http_response_received") is True
                                            and r.get("response_complete") is True and r.get("model_identity_matched") is True
                                            and type(r.get("reported_eval_count")) is int and r["reported_eval_count"] > 0
                                            for r in runs),
            "verified_model_runtime_count": sum(r.get("model_runtime_verified") is True for r in runs)}
