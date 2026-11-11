"""Unit and integration tests for NTK Thesis V2 P0 Quality Gate Repair (P0.1 - P0.3)."""
from __future__ import annotations

import copy
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
VERIFY_REPO_SCRIPT = REPO_ROOT / "scripts" / "verify-repository.py"
VERIFY_CONTRACT_SCRIPT = REPO_ROOT / "v2" / "demo" / "verify_repro_contract.py"
RUN_GATE_SCRIPT = REPO_ROOT / "v2" / "scripts" / "run_v2_quality_gate.py"
REPRO_PS1_SCRIPT = REPO_ROOT / "v2" / "demo" / "reproduce_integration_pilot.ps1"
WORKFLOW_YML = REPO_ROOT / "v2" / "workflows" / "v2-quality-gate.yml"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


verify_repo_mod = _load_module("verify_repository", VERIFY_REPO_SCRIPT)
verify_contract_mod = _load_module("verify_repro_contract", VERIFY_CONTRACT_SCRIPT)


def _find_powershell() -> str:
    for candidate in ("powershell.exe", "pwsh", "powershell"):
        found = shutil.which(candidate)
        if found:
            return found
    pytest.skip("No PowerShell executable found on PATH")


class TestRepositoryPolicyGate:
    """P0.1 positive and negative tests for scripts/verify-repository.py."""

    def test_approved_three_jsonl_files_pass_validation(self):
        expected_paths = {
            "v2/demo/triage_qwen35_9b_smoke_m1_assessments.jsonl",
            "v2/evaluation/fixtures/codex_assessments.fixture.jsonl",
            "v2/evaluation/fixtures/qwen_triage_outputs.fixture.jsonl",
        }
        assert set(verify_repo_mod.APPROVED_JSONL_POLICIES.keys()) == expected_paths

        for rel_path in expected_paths:
            full_path = REPO_ROOT / rel_path
            errors = verify_repo_mod.validate_approved_jsonl(full_path, rel_path)
            assert errors == [], f"Expected {rel_path} to pass validation, got: {errors}"

        violations = verify_repo_mod.evaluate_tracked_paths(sorted(expected_paths), root=REPO_ROOT)
        assert violations == []

    def test_verify_repository_cli_passes_on_clean_repo(self):
        proc = subprocess.run(
            [sys.executable, str(VERIFY_REPO_SCRIPT)],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, f"verify-repository.py failed: {proc.stderr}\n{proc.stdout}"
        assert "PASS:" in proc.stdout

    @pytest.mark.parametrize(
        "unapproved_path",
        [
            "v2/demo/unapproved_dump.jsonl",
            "v2/triage/assessments.jsonl",
            "v2/evaluation/fixtures/extra_unreviewed.jsonl",
            "data/train_samples.jsonl",
            "dataset_vnext_3_1/v2/demo/triage_qwen35_9b_smoke_m1_assessments.jsonl",
            "_advisor_sources/opengrep-triage.zip",
            "v2/triage/review.sqlite",
            "v2/triage/review.sqlite3",
            "v2/triage/state.db",
            "checkpoints/adapter_model.safetensors",
            "models/qwen.gguf",
            "secrets/private.key",
            "secrets/cert.pem",
            "config/ntk_backend.env",
        ],
    )
    def test_unapproved_jsonl_and_forbidden_paths_are_rejected(self, unapproved_path: str):
        violations = verify_repo_mod.evaluate_tracked_paths([unapproved_path], root=REPO_ROOT)
        assert violations != [], f"Expected {unapproved_path} to be rejected by repository policy"

    def test_malformed_and_tampered_jsonl_files_are_rejected(self, tmp_path: Path):
        rel = "v2/evaluation/fixtures/codex_assessments.fixture.jsonl"
        policy = verify_repo_mod.APPROVED_JSONL_POLICIES[rel]
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)

        # 1. Empty file
        target.write_bytes(b"")
        assert any("empty" in e for e in verify_repo_mod.validate_approved_jsonl(target, rel, policy))

        # 2. UTF-8 BOM
        target.write_bytes(b"\xef\xbb\xbf{}")
        assert any("BOM" in e for e in verify_repo_mod.validate_approved_jsonl(target, rel, policy))

        # 3. Invalid JSON syntax
        target.write_text('{"_fixture_notice": "TEST_FIXTURE_ONLY"\n', encoding="utf-8")
        assert any("invalid JSONL row" in e for e in verify_repo_mod.validate_approved_jsonl(target, rel, policy))

        # 4. Non-object JSON row
        target.write_text('[1, 2, 3]\n', encoding="utf-8")
        assert any("must be a JSON object" in e for e in verify_repo_mod.validate_approved_jsonl(target, rel, policy))

        # 5. Duplicate JSON keys
        target.write_text(
            '{"_fixture_notice": "TEST_FIXTURE_ONLY", "id": "a", "id": "b", "evidence": {}, "assessment": {"status": "SUPPORTED"}}\n',
            encoding="utf-8",
        )
        assert any("duplicate JSON key" in e for e in verify_repo_mod.validate_approved_jsonl(target, rel, policy))

        # 6. Missing _fixture_notice
        target.write_text(
            '{"id": "a", "evidence": {}, "assessment": {"status": "SUPPORTED"}}\n',
            encoding="utf-8",
        )
        assert any("_fixture_notice" in e for e in verify_repo_mod.validate_approved_jsonl(target, rel, policy))

        # 7. Oversized file
        small_policy = {**policy, "max_bytes": 32}
        target.write_text(
            '{"_fixture_notice": "TEST_FIXTURE_ONLY", "id": "a", "evidence": {}, "assessment": {"status": "SUPPORTED"}}\n',
            encoding="utf-8",
        )
        assert any("exceeds limit" in e for e in verify_repo_mod.validate_approved_jsonl(target, rel, small_policy))

    def test_tampered_replay_safety_flags_are_rejected(self, tmp_path: Path):
        rel = "v2/demo/triage_qwen35_9b_smoke_m1_assessments.jsonl"
        policy = verify_repo_mod.APPROVED_JSONL_POLICIES[rel]
        orig_lines = (REPO_ROOT / rel).read_text(encoding="utf-8").splitlines()
        row0 = json.loads(orig_lines[0])

        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)

        # Tamper requires_human_review -> False
        bad_row = copy.deepcopy(row0)
        bad_row["assessment"]["requires_human_review"] = False
        target.write_text(json.dumps(bad_row) + "\n", encoding="utf-8")
        errs = verify_repo_mod.validate_approved_jsonl(target, rel, policy)
        assert any("requires_human_review must be True" in e for e in errs)

        # Tamper security_conclusion_verified -> True
        bad_row2 = copy.deepcopy(row0)
        bad_row2["assessment"]["security_conclusion_verified"] = True
        target.write_text(json.dumps(bad_row2) + "\n", encoding="utf-8")
        errs2 = verify_repo_mod.validate_approved_jsonl(target, rel, policy)
        assert any("security_conclusion_verified must be False" in e for e in errs2)

        # Tamper scan_sha256
        bad_row3 = copy.deepcopy(row0)
        bad_row3["scan_sha256"] = "f" * 64
        target.write_text(json.dumps(bad_row3) + "\n", encoding="utf-8")
        errs3 = verify_repo_mod.validate_approved_jsonl(target, rel, policy)
        assert any("scan_sha256 does not match" in e for e in errs3)

    @pytest.mark.parametrize(
        "unsafe_payload",
        [
            "ghp_1234567890abcdefghijklmnopqrstuv",
            "github_pat_1234567890abcdefghijklmnopqrstuv",
            "sk-proj1234567890abcdefghijklmnop",
            "-----BEGIN RSA PRIVATE KEY-----",
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "01_TRAIN_VNEXT_3_1_TRACK_A",
            "opengrep-triage.zip",
        ],
    )
    def test_sensitive_content_in_approved_jsonl_is_rejected(self, tmp_path: Path, unsafe_payload: str):
        rel = "v2/evaluation/fixtures/codex_assessments.fixture.jsonl"
        policy = verify_repo_mod.APPROVED_JSONL_POLICIES[rel]
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        row = {
            "_fixture_notice": "TEST_FIXTURE_ONLY",
            "id": "codex-unsafe-test",
            "evidence": {},
            "assessment": {"status": "SUPPORTED", "explanation": unsafe_payload},
        }
        target.write_text(json.dumps(row) + "\n", encoding="utf-8")
        errs = verify_repo_mod.validate_approved_jsonl(target, rel, policy)
        assert any("sensitive or forbidden content" in e for e in errs), f"Expected rejection for {unsafe_payload}"

    def test_credential_field_in_approved_jsonl_is_rejected(self, tmp_path: Path):
        rel = "v2/evaluation/fixtures/codex_assessments.fixture.jsonl"
        policy = verify_repo_mod.APPROVED_JSONL_POLICIES[rel]
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        row = {
            "_fixture_notice": "TEST_FIXTURE_ONLY",
            "id": "codex-cred-test",
            "api_key": "not-allowed",
            "evidence": {},
            "assessment": {"status": "SUPPORTED"},
        }
        target.write_text(json.dumps(row) + "\n", encoding="utf-8")
        errs = verify_repo_mod.validate_approved_jsonl(target, rel, policy)
        assert any("credential_field" in e for e in errs)


class TestGitHubActionsWorkflowGate:
    """P0.2 tests for v2/workflows/v2-quality-gate.yml and v2/scripts/run_v2_quality_gate.py."""

    def test_v2_workflow_exists_and_checks_required_gates(self, tmp_path: Path):
        assert WORKFLOW_YML.is_file(), "Missing v2/workflows/v2-quality-gate.yml"
        content = WORKFLOW_YML.read_text(encoding="utf-8")
        assert "'v2/**'" in content or '"v2/**"' in content
        assert "python3 scripts/verify-repository.py" in content
        assert "python3 v2/baseline/verify_patch.py" in content
        assert "pytest v2/baseline/tests v2/triage/tests v2/evaluation/tests v2/demo/tests" in content
        assert "v2/scripts/run_v2_quality_gate.py" in content

        report_path = tmp_path / "gate_report.json"
        proc = subprocess.run(
            [
                sys.executable,
                str(RUN_GATE_SCRIPT),
                "--skip-pytest",
                "--output-report",
                str(report_path),
            ],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, f"run_v2_quality_gate.py failed: {proc.stderr}\n{proc.stdout}"
        assert report_path.is_file()
        report = json.loads(report_path.read_text(encoding="utf-8"))
        assert report["status"] == "PASS"
        assert report["total_steps"] >= 9


class TestReproductionContractAndFailClosedScript:
    """P0.3 tests for verify_repro_contract.py and reproduce_integration_pilot.ps1."""

    def test_replay_contract_passes_on_locked_artifacts_and_rejects_mismatched_scan_hash(self, tmp_path: Path):
        og_path = REPO_ROOT / "v2" / "demo" / "smoke_m1_rules_raw.opengrep.json"
        tr_path = REPO_ROOT / "v2" / "demo" / "triage_qwen35_9b_smoke_m1_assessments.jsonl"
        lb_path = REPO_ROOT / "v2" / "evaluation" / "smoke_m1_verified_labels.json"

        code_ok = verify_contract_mod.main(
            [
                "replay",
                "--opengrep",
                str(og_path),
                "--triage",
                str(tr_path),
                "--labels",
                str(lb_path),
                "--output-report",
                str(tmp_path / "ok_report.json"),
            ]
        )
        assert code_ok == 0
        assert (tmp_path / "ok_report.json").is_file()

        # Simulate a newly generated raw scan whose byte hash differs from locked assessments
        mismatched_scan = tmp_path / "fresh_raw_scan.opengrep.json"
        mismatched_scan.write_bytes(og_path.read_bytes().replace(b"\r\n", b"\n") + b"\n")
        code_bad = verify_contract_mod.main(
            [
                "replay",
                "--opengrep",
                str(mismatched_scan),
                "--triage",
                str(tr_path),
                "--labels",
                str(lb_path),
            ]
        )
        assert code_bad == 3

    def test_live_contract_verifies_runtime_and_rejects_mock_or_incomplete_runtime(self, tmp_path: Path):
        og_path = REPO_ROOT / "v2" / "demo" / "smoke_m1_rules_raw.opengrep.json"
        tr_path = REPO_ROOT / "v2" / "demo" / "triage_qwen35_9b_smoke_m1_assessments.jsonl"
        lb_path = REPO_ROOT / "v2" / "evaluation" / "smoke_m1_verified_labels.json"
        out_labels = tmp_path / "live_labels.json"

        # Valid live runtime rows should pass
        code_ok = verify_contract_mod.main(
            [
                "live",
                "--opengrep",
                str(og_path),
                "--triage",
                str(tr_path),
                "--template-labels",
                str(lb_path),
                "--expected-model",
                "qwen3.5:9b-q4_K_M",
                "--output-labels",
                str(out_labels),
            ]
        )
        assert code_ok == 0
        assert out_labels.is_file()

        # Tamper runtime to mock/unverified failure -> must exit with code 4
        rows = [json.loads(line) for line in tr_path.read_text(encoding="utf-8").splitlines()]
        rows[0]["assessment"]["runtime"]["origin"] = "mock"
        rows[0]["assessment"]["runtime"]["http_response_received"] = False
        bad_triage = tmp_path / "bad_live_assessments.jsonl"
        bad_triage.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")

        code_bad_rt = verify_contract_mod.main(
            [
                "live",
                "--opengrep",
                str(og_path),
                "--triage",
                str(bad_triage),
                "--template-labels",
                str(lb_path),
                "--expected-model",
                "qwen3.5:9b-q4_K_M",
                "--output-labels",
                str(tmp_path / "bad_labels.json"),
            ]
        )
        assert code_bad_rt == 4

    def test_reproduce_script_negative_fault_injection_does_not_print_complete(self, tmp_path: Path):
        ps_exe = _find_powershell()
        ev_dir = tmp_path / "ev_fault_injection"
        env = {**os.environ, "NTK_V2_IN_QUALITY_GATE_TEST": "1"}
        proc = subprocess.run(
            [
                ps_exe,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(REPRO_PS1_SCRIPT),
                "-Mode",
                "REPLAY",
                "-SkipHeavyDemos",
                "-InjectFailureStep",
                "build_paired_pilot_table",
                "-EvidenceRoot",
                str(ev_dir),
            ],
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 99, f"Expected exit code 99, got {proc.returncode}: {proc.stderr}"
        assert "=== COMPLETE:" not in proc.stdout
        assert "[FAIL-CLOSED]" in proc.stderr

    def test_reproduce_script_negative_scan_hash_mismatch_fails_closed(self, tmp_path: Path):
        ps_exe = _find_powershell()
        og_path = REPO_ROOT / "v2" / "demo" / "smoke_m1_rules_raw.opengrep.json"
        mismatched_scan = tmp_path / "mismatched_raw.opengrep.json"
        mismatched_scan.write_bytes(og_path.read_bytes() + b"\n")

        ev_dir = tmp_path / "ev_hash_mismatch"
        env = {**os.environ, "NTK_V2_IN_QUALITY_GATE_TEST": "1"}
        proc = subprocess.run(
            [
                ps_exe,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(REPRO_PS1_SCRIPT),
                "-Mode",
                "REPLAY",
                "-SkipHeavyDemos",
                "-ReplayOpenGrepJson",
                str(mismatched_scan),
                "-EvidenceRoot",
                str(ev_dir),
            ],
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 3, f"Expected exit code 3, got {proc.returncode}: {proc.stderr}"
        assert "SCAN_HASH_MISMATCH" in proc.stderr
        assert "=== COMPLETE:" not in proc.stdout

    def test_reproduce_script_refuses_existing_directory_or_in_repo_path(self, tmp_path: Path):
        ps_exe = _find_powershell()
        existing_dir = tmp_path / "already_exists"
        existing_dir.mkdir(parents=True, exist_ok=True)
        env = {**os.environ, "NTK_V2_IN_QUALITY_GATE_TEST": "1"}

        proc_existing = subprocess.run(
            [
                ps_exe,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(REPRO_PS1_SCRIPT),
                "-Mode",
                "REPLAY",
                "-SkipHeavyDemos",
                "-EvidenceRoot",
                str(existing_dir),
            ],
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc_existing.returncode == 2
        assert "=== COMPLETE:" not in proc_existing.stdout

        in_repo_dir = REPO_ROOT / "v2" / "demo" / "forbidden_in_repo_output"
        proc_in_repo = subprocess.run(
            [
                ps_exe,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(REPRO_PS1_SCRIPT),
                "-Mode",
                "REPLAY",
                "-SkipHeavyDemos",
                "-EvidenceRoot",
                str(in_repo_dir),
            ],
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc_in_repo.returncode == 2
        assert "=== COMPLETE:" not in proc_in_repo.stdout
        assert not in_repo_dir.exists()

    def test_reproduce_script_replay_fast_path_succeeds(self, tmp_path: Path):
        ps_exe = _find_powershell()
        ev_dir = tmp_path / "ev_replay_ok"
        env = {**os.environ, "NTK_V2_IN_QUALITY_GATE_TEST": "1"}
        proc = subprocess.run(
            [
                ps_exe,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(REPRO_PS1_SCRIPT),
                "-Mode",
                "REPLAY",
                "-SkipHeavyDemos",
                "-EvidenceRoot",
                str(ev_dir),
            ],
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, f"Expected exit 0, got {proc.returncode}: {proc.stderr}\n{proc.stdout}"
        assert "=== COMPLETE: [MODE=REPLAY]" in proc.stdout
        assert (ev_dir / "contract_verification_receipt.json").is_file()
        assert (ev_dir / "ADVISOR_PAIRED_PILOT_20261111.csv").is_file()
        assert (ev_dir / "paired_pilot_summary.json").is_file()
        assert (ev_dir / "score_pilot_verified.json").is_file()
        assert (ev_dir / "score_pilot_verified.md").is_file()
