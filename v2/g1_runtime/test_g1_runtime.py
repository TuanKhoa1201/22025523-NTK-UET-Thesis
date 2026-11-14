"""
Unit and contract verification tests for G1 Runtime Receipt (v2/g1_runtime/G1-C1).
Ensures strict adherence to Phases A-H, sanitization of private paths, separation of
6 attestation levels, and fail-closed honesty when CANDIDATE.json is absent.
"""
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
VERDICT_PATH = REPO_ROOT / "v2" / "g1_runtime" / "G1-C1" / "VERDICT.json"
REPORT_PATH = REPO_ROOT / "v2" / "g1_runtime" / "G1-C1" / "RUNTIME_REPORT.md"


def load_verdict() -> dict:
    assert VERDICT_PATH.is_file(), f"Missing {VERDICT_PATH}"
    return json.loads(VERDICT_PATH.read_text(encoding="utf-8"))


def test_verdict_and_report_exist_and_sanitized():
    v_text = VERDICT_PATH.read_text(encoding="utf-8")
    r_text = REPORT_PATH.read_text(encoding="utf-8")
    assert "\u2014" not in v_text, "Em-dash forbidden in VERDICT.json"
    assert "\u2014" not in r_text, "Em-dash forbidden in RUNTIME_REPORT.md"
    for forbidden in ("C:\\NTK-G1-Private", "C:/NTK-G1-Private", "C:\\NTK-G1\\candidates"):
        assert forbidden not in v_text, f"Unsanitized private path {forbidden} in VERDICT.json"
        assert forbidden not in r_text, f"Unsanitized private path {forbidden} in RUNTIME_REPORT.md"


def test_phase_a_and_b_preflight_recorded():
    v = load_verdict()
    env = v["host_environment"]
    assert env["hostname"] == "ADMIN-PC"
    assert env["opengrep_version"] == "1.25.0"
    assert env["ollama_version"] == "0.40.7"
    assert env["ollama_endpoint"] == "http://127.0.0.1:11434"
    assert env["model_name"] == "qwen3.5:9b-q4_K_M"
    assert env["model_digest"] == "56671c2ab9385f9cfcb404638e32cd62d88e3501d44822208363c010179a3c90"

    pf = v["preflight_summary"]
    assert pf["status"] == "PASS"
    assert pf["used_as_g1_acceptance"] is False
    assert pf["opengrep_findings"] == 4
    assert pf["opengrep_traces"] == 4
    assert pf["opengrep_sarif_codeflows"] == 4
    assert pf["qwen_http_status"] == 200
    assert pf["qwen_eval_count"] > 0


def test_candidate_availability_honesty_and_no_fake_pass():
    v = load_verdict()
    if not v["candidate_available"]:
        assert v["tested_sha"] is None
        assert v["verdict"] == "INCOMPLETE"
        assert v["reason"] == "CANDIDATE_NOT_AVAILABLE"
        assert v["reference_pre_g1_sha"] == "457183f9e17892fe284da04b57ef6c5c24b008e0"
        assert v["reference_is_candidate"] is False
        assert len(v["runtime_errors"]) >= 1
    else:
        assert isinstance(v["tested_sha"], str) and len(v["tested_sha"]) == 40


def test_no_redundant_opengrep_rescan_and_real_qwen_calls():
    v = load_verdict()
    pipe = v["runtime_pipeline_execution"]
    assert pipe["opengrep_invocations_during_fork_scan"] == 6  # 3 for Demo 1 + 3 for Demo 2
    assert pipe["opengrep_invocations_during_triage_bridge"] == 0
    assert pipe["no_redundant_rescan_verified"] is True
    assert pipe["findings_total"] == 5
    assert pipe["findings_with_trace"] == 5
    assert pipe["real_qwen_calls"] == 5
    assert pipe["valid_qwen_responses"] >= 1
    for rec in pipe["per_finding_records"]:
        assert rec["http_status"] == 200
        assert isinstance(rec["request_payload_sha256"], str) and len(rec["request_payload_sha256"]) == 64
        assert isinstance(rec["response_body_sha256"], str) and len(rec["response_body_sha256"]) == 64
        assert rec["eval_count"] > 0


def test_five_g1_demos_verified():
    v = load_verdict()
    demos = v["demos"]

    d1 = demos["demo_1_real_warnings_cwe22_cwe89"]
    assert d1["status"] == "PASS"
    assert d1["findings_count"] == 4
    assert "CWE-22" in d1["cwes_observed"] and "CWE-89" in d1["cwes_observed"]
    assert d1["all_have_source_and_sink_trace"] is True
    assert d1["all_in_default_queue_as_open"] is True

    d2 = demos["demo_2_false_positive_review_scripted"]
    assert d2["status"] == "PASS"
    assert d2["actor"] == "SCRIPTED-DEMO"
    assert d2["actor_is_simulated_not_independent_human"] is True
    assert d2["confirm_false_exit_code"] == 0
    assert d2["default_queue_count_after_confirm_false"] == 0
    assert d2["all_queue_count_after_confirm_false"] == 1

    d3 = demos["demo_3_reopen_warning"]
    assert d3["status"] == "PASS"
    assert d3["reopen_exit_code"] == 0
    assert d3["default_queue_count_after_reopen"] == 1
    assert d3["event_actions"] == ["confirm-false", "reopen"]
    assert d3["opengrep_and_model_records_preserved"] is True

    d4 = demos["demo_4_stale_source_refusal"]
    assert d4["status"] == "PASS"
    assert d4["sha256_changed"] is True
    assert d4["confirm_false_exit_code"] == 2
    assert d4["decision_refused"] is True
    assert d4["rescan_message_present"] is True
    assert d4["no_new_event_appended"] is True
    assert d4["warning_state_preserved"] is True
    assert d4["g0_fixtures_unchanged"] is True

    d5 = demos["demo_5_qwen_fault_injection"]
    assert d5["status"] == "PASS"
    assert d5["not_claimed_as_real_qwen_failure"] is True
    assert d5["warnings_preserved_in_queue"] == 4
    assert d5["all_warnings_state_open"] is True
    assert d5["all_model_statuses_undetermined"] is True


def test_phase_g_six_attestation_levels_separated():
    v = load_verdict()
    levels = v["attestation_levels_phase_g"]
    assert set(levels.keys()) == {
        "level_1_mock_or_synthetic_test",
        "level_2_real_scanner_executed",
        "level_3_ollama_http_request_received",
        "level_4_ollama_response_recorded",
        "level_5_local_model_runtime_observed_by_host_logs",
        "level_6_independent_ground_truth_security_correctness",
    }
    assert levels["level_5_local_model_runtime_observed_by_host_logs"]["observed"] is True
    assert levels["level_5_local_model_runtime_observed_by_host_logs"]["externally_cryptographically_attested"] is False
    assert levels["level_6_independent_ground_truth_security_correctness"]["observed"] is False
