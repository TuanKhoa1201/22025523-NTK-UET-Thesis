"""Offline integration & counterexample tests for IR-P1-HTTP-02 & IR-P2-HTTP-03 caller compatibility.

Pure Python standard library (does not require typer or OpenGrep) so it executes deterministically
on both ADMIN-PC and independent audit hosts without touching live services or GPU.
"""
from __future__ import annotations

import contextlib
import copy
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from v2.g1_integration import evaluate_r01_r03 as evaluator
from v2.g1_integration import exec_receipt
from v2.triage import ollama, verify_http_capture
from v2.triage.tests.test_fa_p1_http_01_metadata_binding import _build_real_loopback_v226_run


def _run_verifier_cli_capture(argv: list[str]) -> tuple[int, dict]:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = verify_http_capture.main(argv)
    return rc, json.loads(buf.getvalue())


def _wrap_scenario_dir(scenario_dir: Path, triage_src: Path, *, prompt_contract: str = "blind") -> Path:
    triage_dir = scenario_dir / "triage"
    shutil.copytree(triage_src, triage_dir)
    (scenario_dir / "capture").mkdir(parents=True, exist_ok=True)
    (scenario_dir / "g1-run-manifest.json").write_text(
        json.dumps(
            {
                "schema": "ntk-g1-run-manifest-1",
                "prompt_contract": prompt_contract,
                "prompt_version": ollama.PROMPT_VERSION,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return triage_dir


class CallerCompatibilityIrP1Http02Tests(unittest.TestCase):
    def test_01_step26_via_exec_receipt_and_evaluator_separate_artifact_from_live_origin(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ntk_ir_p1_http02_") as td:
            root = Path(td)
            triage_src, rec, _row = _build_real_loopback_v226_run(
                root / "writer_live_shape",
                runtime_origin="unverified",
            )
            scenario = root / "demo2_scenario"
            triage = _wrap_scenario_dir(scenario, triage_src, prompt_contract="blind")
            receipt_dir = root / "receipts"
            out_report = root / "audit" / "demo2-http-capture-audit.json"

            # Gate A (normal mode) via exec_receipt expecting exit 0 succeeds cleanly
            rc_gate_a = exec_receipt.main([
                "--receipt-dir", str(receipt_dir),
                "--step", "26_http_capture_demo2",
                "--cwd", str(REPO_ROOT),
                "--expect-exit", "0",
                "--",
                sys.executable, "-B", "-m", "v2.triage.verify_http_capture",
                str(triage), "--minimum-findings", "1", "--output", str(out_report),
            ])
            self.assertEqual(rc_gate_a, 0)
            rep_doc = json.loads(out_report.read_text(encoding="utf-8"))
            self.assertEqual(rep_doc["capture_status"], "VERIFIED_COMPLETE")
            self.assertTrue(rep_doc["capture_integrity_ok"])
            self.assertTrue(rep_doc["artifact_integrity_ok"])
            self.assertTrue(rep_doc["endpoint_reported_protocol_ok"])
            self.assertFalse(rep_doc["live_origin_verified"])
            self.assertFalse(rep_doc["live_chat_verified"])
            self.assertFalse(rep_doc["independently_verified_model_runtime"])
            self.assertFalse(rep_doc["security_conclusion_verified"])
            self.assertEqual(rep_doc["errors"], [])

            # Strict fail-closed control via exec_receipt expecting exit 2 also passes its expectation
            rc_strict_ctrl = exec_receipt.main([
                "--receipt-dir", str(receipt_dir),
                "--step", "26b_http_capture_demo2_strict_control",
                "--cwd", str(REPO_ROOT),
                "--expect-exit", "2",
                "--",
                sys.executable, "-B", "-m", "v2.triage.verify_http_capture",
                str(triage), "--require-live-chat", "--minimum-findings", "1", "--no-write",
            ])
            self.assertEqual(rc_strict_ctrl, 0)
            strict_doc = json.loads((receipt_dir / "26b_http_capture_demo2_strict_control.stdout.bin").read_text(encoding="utf-8"))
            self.assertEqual(strict_doc["capture_status"], "FAILED")
            self.assertFalse(strict_doc["capture_integrity_ok"])
            self.assertTrue(strict_doc["artifact_integrity_ok"])
            self.assertTrue(strict_doc["endpoint_reported_protocol_ok"])
            self.assertFalse(strict_doc["live_origin_verified"])
            self.assertTrue(any("UNVERIFIED_LIVE_RUNTIME_ORIGIN" in e for e in strict_doc["errors"]))

            # Official evaluator (_inspect_primary_scenario, allow_mock_primary=False) no longer mislabels
            # unverified live origin as "raw HTTP capture verification failed", yet still records live origin unverified.
            ev_res = evaluator._inspect_primary_scenario(
                "http_contract_only",
                scenario,
                expected_findings=1,
                expected_polarity="OBSERVED_VALID_TRIAGE",
                allow_mock_primary=False,
            )
            self.assertEqual(ev_res["blockers"], [], ev_res["blockers"])
            self.assertFalse(any("raw HTTP capture verification failed" in b for b in ev_res["blockers"]))
            hv = ev_res["http_verification"]
            self.assertEqual(hv["classification"], "ARTIFACT_AND_PROTOCOL_VERIFIED_LIVE_ORIGIN_UNVERIFIED_OFFLINE")
            self.assertTrue(hv["artifact_integrity_ok"])
            self.assertTrue(hv["endpoint_reported_protocol_ok"])
            self.assertFalse(hv["live_origin_verified"])
            self.assertFalse(hv["independently_verified_model_runtime"])
            self.assertFalse(hv["security_conclusion_verified"])
            self.assertEqual(hv["live_origin_status"], "UNVERIFIED_OFFLINE_REQUIRES_OPERATOR_EXTERNAL_EVIDENCE")
            self.assertTrue(any("UNVERIFIED_LIVE_RUNTIME_ORIGIN" in r for r in ev_res["live_origin_requirements"]))

            # Existing output report must refuse overwrite while preserving artifact_integrity_ok=True
            orig_bytes = out_report.read_bytes()
            rc_exist_norm, doc_exist_norm = _run_verifier_cli_capture([
                str(triage), "--minimum-findings", "1", "--output", str(out_report),
            ])
            self.assertEqual(rc_exist_norm, 2)
            self.assertEqual(out_report.read_bytes(), orig_bytes)
            self.assertTrue(doc_exist_norm["verification_executed"])
            self.assertTrue(doc_exist_norm["artifact_integrity_ok"])
            self.assertTrue(doc_exist_norm["endpoint_reported_protocol_ok"])
            self.assertEqual(doc_exist_norm["capture_status"], "VERIFIED_COMPLETE")
            self.assertFalse(doc_exist_norm["report_write_ok"])
            self.assertEqual(doc_exist_norm["report_write_status"], "REFUSED_EXISTING_OUTPUT")
            self.assertIn("OUTPUT_WRITE_REFUSED_EXISTING_FILE", doc_exist_norm["report_write_error"])

            rc_exist_strict, doc_exist_strict = _run_verifier_cli_capture([
                str(triage), "--minimum-findings", "1", "--require-live-chat", "--output", str(out_report),
            ])
            self.assertEqual(rc_exist_strict, 2)
            self.assertEqual(out_report.read_bytes(), orig_bytes)
            self.assertTrue(doc_exist_strict["verification_executed"])
            self.assertTrue(doc_exist_strict["artifact_integrity_ok"])
            self.assertTrue(doc_exist_strict["endpoint_reported_protocol_ok"])
            self.assertEqual(doc_exist_strict["capture_status"], "FAILED")
            self.assertFalse(doc_exist_strict["report_write_ok"])
            self.assertEqual(doc_exist_strict["report_write_status"], "REFUSED_EXISTING_OUTPUT")

    def test_02_counterexample_matrix_tamper_mock_incomplete_protocol_and_type_errors(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ntk_ir_p1_http02_mat_") as td:
            root = Path(td)
            triage_src, rec, _row = _build_real_loopback_v226_run(
                root / "base_run",
                runtime_origin="unverified",
            )
            fid = rec["id"]

            # 1. Tampered raw response body -> ARTIFACT_INTEGRITY_FAILED in failures (never PASS)
            sc_body = root / "sc_tamper_body"
            t_body = _wrap_scenario_dir(sc_body, triage_src)
            resp_bin = t_body / "llm_io" / f"{fid}.response.body.bin"
            resp_bin.write_bytes(resp_bin.read_bytes() + b" ")
            ev_body = evaluator._inspect_primary_scenario(
                "tamper_body", sc_body, expected_findings=1, expected_polarity="OBSERVED_VALID_TRIAGE", allow_mock_primary=False
            )
            self.assertEqual(ev_body["http_verification"]["classification"], "ARTIFACT_INTEGRITY_FAILED")
            self.assertFalse(ev_body["http_verification"]["artifact_integrity_ok"])
            self.assertTrue(any("HTTP_ARTIFACT_INTEGRITY_FAILED" in f for f in ev_body["failures"]), ev_body["failures"])

            # 2. Tampered receipt SHA-256 -> ARTIFACT_INTEGRITY_FAILED
            sc_rcpt = root / "sc_tamper_receipt"
            t_rcpt = _wrap_scenario_dir(sc_rcpt, triage_src)
            rcpt_p = t_rcpt / "llm_io" / f"{fid}.http-capture.json"
            rcpt_doc = json.loads(rcpt_p.read_text(encoding="utf-8"))
            rcpt_doc["response_body_sha256"] = "0" * 64
            rcpt_p.write_text(json.dumps(rcpt_doc, indent=2) + "\n", encoding="utf-8")
            ev_rcpt = evaluator._inspect_primary_scenario(
                "tamper_rcpt", sc_rcpt, expected_findings=1, expected_polarity="OBSERVED_VALID_TRIAGE", allow_mock_primary=False
            )
            self.assertEqual(ev_rcpt["http_verification"]["classification"], "ARTIFACT_INTEGRITY_FAILED")
            self.assertFalse(ev_rcpt["http_verification"]["artifact_integrity_ok"])
            self.assertTrue(any("HTTP_ARTIFACT_INTEGRITY_FAILED" in f for f in ev_rcpt["failures"]))

            # 3. Contradictory metadata sidecar -> ARTIFACT_INTEGRITY_FAILED
            sc_meta = root / "sc_tamper_meta"
            t_meta = _wrap_scenario_dir(sc_meta, triage_src)
            side_p = t_meta / "llm_io" / f"{fid}.response.json"
            side_doc = json.loads(side_p.read_text(encoding="utf-8"))
            side_doc["runtime"]["prompt_contract"] = "neutral_hints"
            side_p.write_text(json.dumps(side_doc, indent=2) + "\n", encoding="utf-8")
            ev_meta = evaluator._inspect_primary_scenario(
                "tamper_meta", sc_meta, expected_findings=1, expected_polarity="OBSERVED_VALID_TRIAGE", allow_mock_primary=False
            )
            self.assertEqual(ev_meta["http_verification"]["classification"], "ARTIFACT_INTEGRITY_FAILED")
            self.assertFalse(ev_meta["http_verification"]["artifact_integrity_ok"])

            # 4. Incomplete endpoint protocol (missing ollama-tags-check.json) -> ENDPOINT_PROTOCOL_INCOMPLETE blocker
            sc_proto = root / "sc_incomplete_proto"
            t_proto = _wrap_scenario_dir(sc_proto, triage_src)
            (t_proto / "ollama-tags-check.json").unlink()
            ev_proto = evaluator._inspect_primary_scenario(
                "incomplete_proto", sc_proto, expected_findings=1, expected_polarity="OBSERVED_VALID_TRIAGE", allow_mock_primary=False
            )
            self.assertEqual(ev_proto["http_verification"]["classification"], "ENDPOINT_PROTOCOL_INCOMPLETE")
            self.assertTrue(ev_proto["http_verification"]["artifact_integrity_ok"])
            self.assertFalse(ev_proto["http_verification"]["endpoint_reported_protocol_ok"])
            self.assertTrue(any("HTTP_ENDPOINT_PROTOCOL_INCOMPLETE" in b for b in ev_proto["blockers"]), ev_proto["blockers"])

            # 5. Mock simulating Ollama protocol -> MOCK_OR_NON_LIVE_DECLARED blocker in official mode
            triage_mock, _, _ = _build_real_loopback_v226_run(
                root / "mock_run", runtime_origin="mock"
            )
            sc_mock = root / "sc_mock"
            _wrap_scenario_dir(sc_mock, triage_mock)
            ev_mock = evaluator._inspect_primary_scenario(
                "mock_run", sc_mock, expected_findings=1, expected_polarity="OBSERVED_VALID_TRIAGE", allow_mock_primary=False
            )
            self.assertEqual(ev_mock["http_verification"]["classification"], "MOCK_OR_NON_LIVE_DECLARED")
            self.assertTrue(ev_mock["http_verification"]["artifact_integrity_ok"])
            self.assertFalse(ev_mock["http_verification"]["endpoint_reported_protocol_ok"])
            self.assertTrue(any("HTTP_MOCK_OR_NON_LIVE" in b for b in ev_mock["blockers"]), ev_mock["blockers"])

            # 6. Missing / wrong-typed / forged-true verifier fields -> INVALID_VERIFIER_RESULT fail-closed
            bad_payloads = [
                ("not_dict", "broken"),
                ("missing_fields", {"artifact_integrity_ok": True}),
                ("string_bool", {
                    "artifact_integrity_ok": "true",
                    "capture_integrity_ok": True,
                    "endpoint_reported_protocol_ok": True,
                    "live_origin_verified": False,
                    "live_chat_verified": False,
                    "independently_verified_model_runtime": False,
                    "security_conclusion_verified": False,
                    "capture_status": "VERIFIED_COMPLETE",
                    "live_origin_trust_status": "UNVERIFIED_OFFLINE_NO_TRUSTED_EXTERNAL_PROVENANCE",
                    "errors": [],
                    "endpoint_reported_protocol_errors": [],
                    "findings": [],
                }),
                ("forged_live_true", {
                    "artifact_integrity_ok": True,
                    "capture_integrity_ok": True,
                    "endpoint_reported_protocol_ok": True,
                    "live_origin_verified": True,
                    "live_chat_verified": False,
                    "independently_verified_model_runtime": False,
                    "security_conclusion_verified": False,
                    "capture_status": "VERIFIED_COMPLETE",
                    "live_origin_trust_status": "UNVERIFIED_OFFLINE_NO_TRUSTED_EXTERNAL_PROVENANCE",
                    "errors": [],
                    "endpoint_reported_protocol_errors": [],
                    "findings": [],
                }),
            ]
            for label, payload in bad_payloads:
                with self.subTest(bad_verifier_payload=label):
                    hv, fails, blks, reqs = evaluator._classify_http_capture_verification(
                        label, payload, allow_mock_primary=False
                    )
                    self.assertEqual(hv["classification"], "INVALID_VERIFIER_RESULT")
                    self.assertFalse(hv["artifact_integrity_ok"])
                    self.assertFalse(hv["live_origin_verified"])
                    self.assertTrue(any("HTTP_VERIFIER_CONTRACT_ERROR" in f for f in fails), fails)
                    self.assertEqual(reqs, [])

            # 7. CLI write error to unwritable path (parent is a regular file) preserves artifact_integrity_ok=True
            blocker_file = root / "not_a_dir"
            blocker_file.write_text("file", encoding="utf-8")
            rc_io, doc_io = _run_verifier_cli_capture([
                str(triage_src), "--minimum-findings", "1", "--output", str(blocker_file / "report.json"),
            ])
            self.assertEqual(rc_io, 2)
            self.assertTrue(doc_io["verification_executed"])
            self.assertTrue(doc_io["artifact_integrity_ok"])
            self.assertTrue(doc_io["endpoint_reported_protocol_ok"])
            self.assertFalse(doc_io["report_write_ok"])
            self.assertIn(doc_io["report_write_status"], ("REFUSED_UNSAFE_OUTPUT_TARGET", "OUTPUT_WRITE_IO_ERROR"))

    def test_03_evaluate_acceptance_never_claims_live_pass_offline_and_exits_3_pending_operator(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ntk_ir_p1_http02_eval_") as td:
            root = Path(td)
            dummy_dirs = {}
            for name in ("d1", "d2", "d3a", "m1", "d3b", "d4"):
                p = root / name
                p.mkdir()
                dummy_dirs[name] = p

            def _fake_primary(scenario_name, _dir, *, expected_findings, expected_polarity, allow_mock_primary, **_kw):
                return {
                    "scenario": scenario_name,
                    "findings_count": expected_findings,
                    "http_capture": {"capture_status": "VERIFIED_COMPLETE", "artifact_integrity_ok": True, "endpoint_reported_protocol_ok": True, "live_origin_verified": False},
                    "http_verification": {
                        "classification": "MOCK_TEST_MODE_ARTIFACT_VERIFIED" if allow_mock_primary else "ARTIFACT_AND_PROTOCOL_VERIFIED_LIVE_ORIGIN_UNVERIFIED_OFFLINE",
                        "artifact_integrity_ok": True,
                        "endpoint_reported_protocol_ok": not allow_mock_primary,
                        "live_origin_verified": False,
                        "independently_verified_model_runtime": False,
                        "security_conclusion_verified": False,
                    },
                    "live_origin_requirements": [] if allow_mock_primary else [f"{scenario_name}: UNVERIFIED_LIVE_RUNTIME_ORIGIN"],
                    "r02_errors": [],
                    "r03_errors": [],
                    "findings": [],
                    "current_sqlite": (
                        {"states": ["CONFIRMED_TRUE", "OPEN"], "events": [{"action": "confirm-true", "actor": "operator-real", "reason": "Verified trace"}], "rejected_count": 0}
                        if scenario_name == "demo1_true_positive"
                        else (
                            {"states": ["OPEN"], "events": [{"action": "confirm-false", "actor": "operator-real", "reason": "Verified guard"}, {"action": "reopen", "actor": "lead-real", "reason": "Recheck"}], "rejected_count": 0}
                            if scenario_name == "demo2_protected_false_positive"
                            else {"states": ["OPEN"], "events": [], "rejected_count": 0}
                        )
                    ),
                    "blockers": [],
                    "failures": [],
                }

            with (
                patch.object(evaluator, "_inspect_primary_scenario", side_effect=_fake_primary),
                patch.object(evaluator, "_inspect_m1_scan_only", return_value={"present": True, "blockers": [], "errors": []}),
                patch.object(evaluator, "_inspect_demo3b_mock_control", return_value={"present": True, "errors": []}),
                patch.object(evaluator, "_inspect_demo4_stale_control", return_value={"present": True, "blockers": [], "errors": []}),
            ):
                # Official mode (allow_mock_primary=False) -> exit 3, OFFLINE_VERIFIED_PENDING_OPERATOR_LIVE_ORIGIN (never PASS!)
                out_official = root / "eval_official.json"
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    rc_off = evaluator.main([
                        "--demo1-dir", str(dummy_dirs["d1"]),
                        "--demo2-dir", str(dummy_dirs["d2"]),
                        "--demo3a-dir", str(dummy_dirs["d3a"]),
                        "--m1-dir", str(dummy_dirs["m1"]),
                        "--demo3b-dir", str(dummy_dirs["d3b"]),
                        "--demo4-dir", str(dummy_dirs["d4"]),
                        "--output", str(out_official),
                    ])
                self.assertEqual(rc_off, 3)
                rep_off = json.loads(out_official.read_text(encoding="utf-8"))
                self.assertEqual(rep_off["overall_status"], "OFFLINE_VERIFIED_PENDING_OPERATOR_LIVE_ORIGIN")
                self.assertEqual(rep_off["offline_artifact_status"], "PASS")
                self.assertFalse(rep_off["live_origin_verified"])
                self.assertEqual(rep_off["live_runtime_acceptance_status"], "PENDING_OPERATOR_EXTERNAL_RUNTIME_EVIDENCE")
                self.assertFalse(rep_off["independently_verified_model_runtime"])
                self.assertFalse(rep_off["security_conclusion_verified"])
                self.assertEqual(rep_off["criteria"]["R01"]["status"], "OFFLINE_VERIFIED_PENDING_OPERATOR_LIVE_ORIGIN")
                self.assertEqual(rep_off["criteria"]["R01"]["offline_artifact_status"], "PASS")
                self.assertEqual(rep_off["criteria"]["R02"]["status"], "PASS")
                self.assertEqual(rep_off["criteria"]["R03"]["status"], "PASS")
                self.assertGreaterEqual(len(rep_off["live_origin_requirements"]), 3)

                # Existing evaluator output path refuses overwrite cleanly
                orig_off_bytes = out_official.read_bytes()
                with self.assertRaises(SystemExit) as cm:
                    with contextlib.redirect_stderr(io.StringIO()):
                        evaluator.main([
                            "--demo1-dir", str(dummy_dirs["d1"]),
                            "--demo2-dir", str(dummy_dirs["d2"]),
                            "--demo3a-dir", str(dummy_dirs["d3a"]),
                            "--m1-dir", str(dummy_dirs["m1"]),
                            "--demo3b-dir", str(dummy_dirs["d3b"]),
                            "--demo4-dir", str(dummy_dirs["d4"]),
                            "--output", str(out_official),
                        ])
                self.assertEqual(cm.exception.code, 2)
                self.assertEqual(out_official.read_bytes(), orig_off_bytes)

                # Offline mock test mode (--allow-mock-primary) retains exit 0 / PASS compatibility
                out_mock = root / "eval_mock.json"
                with contextlib.redirect_stdout(io.StringIO()):
                    rc_mock = evaluator.main([
                        "--demo1-dir", str(dummy_dirs["d1"]),
                        "--demo2-dir", str(dummy_dirs["d2"]),
                        "--demo3a-dir", str(dummy_dirs["d3a"]),
                        "--m1-dir", str(dummy_dirs["m1"]),
                        "--demo3b-dir", str(dummy_dirs["d3b"]),
                        "--demo4-dir", str(dummy_dirs["d4"]),
                        "--output", str(out_mock),
                        "--allow-mock-primary",
                    ])
                self.assertEqual(rc_mock, 0)
                rep_mock = json.loads(out_mock.read_text(encoding="utf-8"))
                self.assertEqual(rep_mock["overall_status"], "PASS")
                self.assertFalse(rep_mock["live_origin_verified"])
                self.assertEqual(rep_mock["live_runtime_acceptance_status"], "NOT_APPLICABLE_MOCK_TEST_MODE")

    def test_04_runbook_three_gate_and_p11_invariants(self) -> None:
        plan_text = (REPO_ROOT / "v2" / "g1_integration" / "RUNTIME_ACCEPTANCE_PLAN.md").read_text(encoding="utf-8")
        # Steps 25-27 & P2 use normal verifier mode (no --require-live-chat in exit-0 steps)
        for step in ("25_http_capture_demo1", "26_http_capture_demo2", "27_http_capture_demo3a", "P2_allowq_verify_http"):
            m = re.search(rf'Invoke-ReceiptStep -Step "{step}"[^\n]*', plan_text)
            self.assertIsNotNone(m, f"Missing runbook step {step}")
            assert m is not None
            self.assertNotIn("--require-live-chat", m.group(0), f"Step {step} must not expect exit 0 with --require-live-chat")
        # Strict controls explicitly expect exit 2
        for ctrl in ("25b_http_capture_demo1_strict_control", "26b_http_capture_demo2_strict_control", "27b_http_capture_demo3a_strict_control", "P2b_allowq_verify_http_strict_control"):
            self.assertIn(f'Invoke-ReceiptStep -Step "{ctrl}" -ExpectedExit @(2)', plan_text)
        # Step 42 and P11 expect exit 3 (OFFLINE_VERIFIED_PENDING_OPERATOR_LIVE_ORIGIN)
        self.assertIn('Invoke-ReceiptStep -Step "42_evaluate_r01_r03" -ExpectedExit @(3)', plan_text)
        self.assertIn("OFFLINE_VERIFIED_PENDING_OPERATOR_LIVE_ORIGIN", plan_text)
        self.assertIn("06b_operator_ollama_process_pre", plan_text)
        self.assertIn("27c_operator_ollama_process_post", plan_text)
        self.assertIn("independently_verified_model_runtime=false", plan_text)
        self.assertIn("security_conclusion_verified=false", plan_text)

        # Verify P11 block variable hygiene and isolation
        sec_start = plan_text.index("### 12.3.")
        next_sec = plan_text.index("\n### 12.4.", sec_start)
        p11_section = plan_text[sec_start:next_sec]
        m_ps = re.search(r"```powershell\r?\n(.*?)```", p11_section, flags=re.DOTALL)
        self.assertIsNotNone(m_ps)
        assert m_ps is not None
        p11_ps = m_ps.group(1)
        self.assertIn("--expect-exit 3", p11_ps)
        for forbidden_call in ("11434", "/api/chat", "/api/tags", "run_g1_demo", "ollama"):
            self.assertNotIn(forbidden_call, p11_ps.lower())
        defined_vars = set(re.findall(r"\$([A-Za-z_][A-Za-z0-9_]*)\s*=", p11_ps))
        defined_vars.update(re.findall(r"\[[^\]]+\]\$([A-Za-z_][A-Za-z0-9_]*)", p11_ps))
        defined_vars.update(re.findall(r"foreach\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\s+in\b", p11_ps))
        builtin_vars = {"LASTEXITCODE", "ErrorActionPreference", "null", "true", "false", "env"}
        used_vars = set(re.findall(r"\$([A-Za-z_][A-Za-z0-9_]*)\b", p11_ps)) - builtin_vars
        self.assertEqual(sorted(used_vars - defined_vars), [])

    def test_05_evaluator_rejects_contradictory_or_empty_findings_and_runbook_strictmode_hygiene(self) -> None:
        # 1. Evaluator rejects contradictory per-finding flags and empty findings when top-level claims True
        contradictory = {
            "artifact_integrity_ok": True,
            "capture_integrity_ok": True,
            "endpoint_reported_protocol_ok": True,
            "live_origin_verified": False,
            "live_chat_verified": False,
            "independently_verified_model_runtime": False,
            "security_conclusion_verified": False,
            "capture_status": "VERIFIED_COMPLETE",
            "live_origin_trust_status": "UNVERIFIED_OFFLINE_NO_TRUSTED_EXTERNAL_PROVENANCE",
            "total_findings": 1,
            "errors": [],
            "endpoint_reported_protocol_errors": [],
            "findings": [{"artifact_integrity_ok": False, "endpoint_reported_protocol_ok": False, "live_provenance_ok": False}],
        }
        hv_c, f_c, b_c, r_c = evaluator._classify_http_capture_verification(
            "contra", contradictory, allow_mock_primary=False, expected_findings=1
        )
        self.assertEqual(hv_c["classification"], "INVALID_VERIFIER_RESULT")
        self.assertTrue(any("HTTP_VERIFIER_CONTRACT_ERROR" in x for x in f_c), f_c)
        self.assertEqual(r_c, [])

        empty_findings = dict(contradictory, total_findings=0, findings=[])
        hv_e, f_e, _, r_e = evaluator._classify_http_capture_verification(
            "empty", empty_findings, allow_mock_primary=False, expected_findings=1
        )
        self.assertEqual(hv_e["classification"], "INVALID_VERIFIER_RESULT")
        self.assertTrue(any("HTTP_VERIFIER_CONTRACT_ERROR" in x for x in f_e), f_e)
        self.assertEqual(r_e, [])

        mismatched_total = dict(
            contradictory,
            total_findings=2,
            findings=[{"artifact_integrity_ok": True, "endpoint_reported_protocol_ok": True, "live_provenance_ok": False}],
        )
        hv_m, f_m, _, _ = evaluator._classify_http_capture_verification(
            "mismatch_total", mismatched_total, allow_mock_primary=False, expected_findings=2
        )
        self.assertEqual(hv_m["classification"], "INVALID_VERIFIER_RESULT")
        self.assertTrue(any("total_findings" in x for x in f_m), f_m)

        # 2. Runbook PowerShell checks: no double-quoted $c expansion under StrictMode, P3 reads stdout.bin,
        #    and strict controls verify UNVERIFIED_LIVE_RUNTIME_ORIGIN (not bare exit 2)
        plan_text = (REPO_ROOT / "v2" / "g1_integration" / "RUNTIME_ACCEPTANCE_PLAN.md").read_text(encoding="utf-8")
        self.assertIn("$GateBPreScript = @'", plan_text)
        self.assertIn("$GateBPostScript = @'", plan_text)
        self.assertIn("FAIL-FAST [GATE_A_STRICT_CONTROL]", plan_text)
        self.assertIn("FAIL-FAST [GATE_B_CONTINUITY]", plan_text)
        self.assertIn("FAIL-FAST [P2B_STRICT_CONTROL]", plan_text)
        self.assertIn("P3_allowq_queue_initial.stdout.bin", plan_text)
        self.assertNotIn("$AllowQQueueRaw.stdout", plan_text)
        self.assertIn("--expected-prompt-version $P11ExpectedPromptVersion", plan_text)
        self.assertIn('$P11ExpectedPromptVersion = "v2.2.2-cwe22-cwe89-canonical-citations"', plan_text)

    def test_06_evaluator_rejects_p1_content_tamper_and_supports_explicit_historical_prompt_replay(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ntk_ir_p1_p11_") as td:
            root = Path(td)
            triage_src, rec, _row = _build_real_loopback_v226_run(root / "base_v226", runtime_origin="unverified")
            src_lines = {ln["line"]: ln["text"] for ln in rec["snippets"][0]["lines"]}
            snap_sha = rec["snapshots"]["DemoSql.java"]["sha256"]

            # 1. Every P1 assessment content tamper must be classified ARTIFACT_INTEGRITY_FAILED in evaluator
            tamper_cases = {
                "quote": lambda r: r["assessment"]["citations"][0].__setitem__("quote", "not in Java source"),
                "empty_cites": lambda r: r["assessment"].__setitem__("citations", []),
                "cc_none": lambda r: r["assessment"].__setitem__("citation_check", "NONE"),
                "explanation": lambda r: r["assessment"].__setitem__("explanation", "Text not returned by endpoint"),
                "fix_suggestion": lambda r: r["assessment"].__setitem__("fix_suggestion", "Different suggestion"),
                "del_raw_ms": lambda r: (r.pop("raw_model_status", None), r["assessment"].pop("raw_model_status", None)),
                "sub_real_line": lambda r: r["assessment"].__setitem__(
                    "citations",
                    [{"path": "DemoSql.java", "start_line": 3, "end_line": 3, "quote": src_lines[3], "sha256": snap_sha}],
                ),
            }
            for label, mut in tamper_cases.items():
                with self.subTest(p1_evaluator_case=label):
                    sc = root / f"sc_{label}"
                    tdir = _wrap_scenario_dir(sc, triage_src)
                    aj = tdir / "assessments.jsonl"
                    row = json.loads(aj.read_text(encoding="utf-8").strip())
                    mut(row)
                    aj.write_text(json.dumps(row, ensure_ascii=False) + "\n", encoding="utf-8")
                    ev = evaluator._inspect_primary_scenario(
                        f"p1_{label}",
                        sc,
                        expected_findings=1,
                        expected_polarity="OBSERVED_VALID_TRIAGE",
                        allow_mock_primary=False,
                    )
                    self.assertEqual(ev["http_verification"]["classification"], "ARTIFACT_INTEGRITY_FAILED", ev)
                    self.assertFalse(ev["http_verification"]["artifact_integrity_ok"])
                    self.assertTrue(any("HTTP_ARTIFACT_INTEGRITY_FAILED" in f for f in ev["failures"]), ev["failures"])

            # 2. Explicit expected_prompt_version resolution fails closed on arbitrary/steered versions
            self.assertEqual(evaluator._resolve_expected_prompt_version(None), ollama.PROMPT_VERSION)
            self.assertEqual(
                evaluator._resolve_expected_prompt_version(ollama.PREVIOUS_CANONICAL_PROMPT_VERSION),
                ollama.PREVIOUS_CANONICAL_PROMPT_VERSION,
            )
            for bad_pv in ("", "  ", "v99-unknown", ollama.LEGACY_STEERED_PROMPT_VERSION):
                with self.subTest(bad_prompt_version=bad_pv):
                    with self.assertRaises(ValueError):
                        evaluator._resolve_expected_prompt_version(bad_pv)

            # 3. Historical v2.2.2 capture with valid multi-line citation is rejected by default (v2.2.6)
            #    and accepted ONLY when expected_prompt_version=v2.2.2 is explicitly selected
            v222_ver = ollama.PREVIOUS_CANONICAL_PROMPT_VERSION
            v222_sc = root / "sc_hist_v222"
            v222_tdir = _wrap_scenario_dir(v222_sc, triage_src)
            fid = rec["id"]
            req_v222, ser_meta = ollama.request_payload_for_version(rec, "qwen3.5:9b-q4_K_M", prompt_version=v222_ver)
            assert req_v222 is not None
            req_bytes = json.dumps(req_v222).encode("utf-8")
            req_sha = ollama.digest(req_bytes)
            prompt_sha = ollama.digest(json.dumps(req_v222["messages"], ensure_ascii=False).encode("utf-8"))
            multi_cite = {
                "path": "DemoSql.java",
                "start_line": 3,
                "end_line": 4,
                "quote": f"{src_lines[3]}\n{src_lines[4]}",
                "sha256": snap_sha,
            }
            v222_ans = {
                "status": "SUPPORTED",
                "explanation": "Multi-line historical v2.2.2 citation.",
                "fix_suggestion": "Use PreparedStatement.",
                "citations": [multi_cite],
            }
            resp_obj = {
                "model": "qwen3.5:9b-q4_K_M",
                "created_at": "2026-11-15T04:00:00Z",
                "message": {"role": "assistant", "content": json.dumps(v222_ans, ensure_ascii=False)},
                "done": True,
                "done_reason": "stop",
                "eval_count": 20,
                "eval_duration": 100000000,
            }
            resp_bytes = json.dumps(resp_obj, ensure_ascii=False).encode("utf-8")
            resp_body_sha = ollama.digest(resp_bytes)
            resp_json_sha = ollama.digest(json.dumps(resp_obj, sort_keys=True, ensure_ascii=False, allow_nan=False).encode("utf-8"))

            man_p = v222_sc / "g1-run-manifest.json"
            man_doc = json.loads(man_p.read_text(encoding="utf-8"))
            man_doc["prompt_version"] = v222_ver
            man_p.write_text(json.dumps(man_doc, indent=2) + "\n", encoding="utf-8")

            io_dir = v222_tdir / "llm_io"
            (io_dir / f"{fid}.request.body.bin").write_bytes(req_bytes)
            (io_dir / f"{fid}.response.body.bin").write_bytes(resp_bytes)
            (io_dir / f"{fid}.request.json").write_text(json.dumps(req_v222, indent=2), encoding="utf-8")
            (io_dir / f"{fid}.prompt.json").write_text(
                json.dumps({
                    "finding_id": fid,
                    "prompt_version": v222_ver,
                    "prompt_contract": "blind",
                    "prompt_sha256": prompt_sha,
                    "serializer_fingerprint": ser_meta["serializer_fingerprint"],
                    "messages": req_v222["messages"],
                }, indent=2),
                encoding="utf-8",
            )
            rcp_p = io_dir / f"{fid}.http-capture.json"
            rcp_doc = json.loads(rcp_p.read_text(encoding="utf-8"))
            rcp_doc.update({
                "prompt_version": v222_ver,
                "prompt_sha256": prompt_sha,
                "serializer_fingerprint": ser_meta["serializer_fingerprint"],
                "request_byte_length": len(req_bytes),
                "request_payload_sha256": req_sha,
                "response_byte_length": len(resp_bytes),
                "response_body_sha256": resp_body_sha,
                "response_json_sha256": resp_json_sha,
            })
            rcp_p.write_text(json.dumps(rcp_doc, indent=2) + "\n", encoding="utf-8")

            aj_p = v222_tdir / "assessments.jsonl"
            row_v = json.loads(aj_p.read_text(encoding="utf-8").strip())
            row_v["assessment"].update({
                "status": "SUPPORTED",
                "raw_model_status": "SUPPORTED",
                "validated_status": "SUPPORTED",
                "explanation": v222_ans["explanation"],
                "fix_suggestion": v222_ans["fix_suggestion"],
                "citations": [multi_cite],
                "citation_check": "MATCHED",
                "prompt_version": v222_ver,
                "prompt_sha256": prompt_sha,
                "serializer_fingerprint": ser_meta["serializer_fingerprint"],
                "raw_response": resp_obj,
            })
            row_v["assessment"]["runtime"].update({
                "prompt_version": v222_ver,
                "prompt_sha256": prompt_sha,
                "serializer_fingerprint": ser_meta["serializer_fingerprint"],
                "request_payload_sha256": req_sha,
                "request_payload_bytes": len(req_bytes),
                "response_body_sha256": resp_body_sha,
                "response_body_bytes": len(resp_bytes),
                "response_json_sha256": resp_json_sha,
                "reported_eval_count": 20,
                "reported_eval_duration_ns": 100000000,
            })
            aj_p.write_text(json.dumps(row_v, ensure_ascii=False) + "\n", encoding="utf-8")

            s_p = io_dir / f"{fid}.response.json"
            s_doc = json.loads(s_p.read_text(encoding="utf-8"))
            s_doc["raw_response"] = resp_obj
            s_doc["runtime"] = dict(row_v["assessment"]["runtime"])
            s_p.write_text(json.dumps(s_doc, indent=2) + "\n", encoding="utf-8")

            # Default evaluator (v2.2.6) MUST fail on v2.2.2 capture
            ev_default = evaluator._inspect_primary_scenario(
                "v222_default_reject",
                v222_sc,
                expected_findings=1,
                expected_polarity="OBSERVED_VALID_TRIAGE",
                allow_mock_primary=False,
            )
            self.assertTrue(any("prompt_version" in f for f in ev_default["failures"]), ev_default["failures"])
            self.assertTrue(any("single executable line" in f for f in ev_default["failures"]), ev_default["failures"])

            # Explicit historical replay (v2.2.2) accepts v2.2.2 multi-line citation & version cleanly
            ev_hist = evaluator._inspect_primary_scenario(
                "v222_explicit_replay",
                v222_sc,
                expected_findings=1,
                expected_polarity="OBSERVED_VALID_TRIAGE",
                allow_mock_primary=False,
                expected_prompt_version=v222_ver,
            )
            self.assertEqual(ev_hist["failures"], [], ev_hist["failures"])
            self.assertEqual(ev_hist["blockers"], [], ev_hist["blockers"])
            self.assertEqual(
                ev_hist["http_verification"]["classification"],
                "ARTIFACT_AND_PROTOCOL_VERIFIED_LIVE_ORIGIN_UNVERIFIED_OFFLINE",
            )

    def test_07_fsync_and_atomic_publish_fault_injection_exec_receipt_and_evaluator(self) -> None:
        """Simulated fault injection on exec_receipt._write_xb and evaluate_r01_r03.main output publishing."""
        import errno

        with tempfile.TemporaryDirectory(prefix="ntk_fsync_g1_") as td:
            root = Path(td)
            foreign_tmp = root / ".foreign.999999.deadbeef.tmp"
            foreign_tmp.write_bytes(b"foreign-process-temp")

            # 1. exec_receipt._write_xb: EIO, ENOSPC, PermissionError on fsync; EOPNOTSUPP/EXDEV/PermissionError on link; FileExistsError
            for label, target_fn, exc_obj in (
                ("er_fsync_eio", "v2.g1_integration.exec_receipt.os.fsync", OSError(errno.EIO, "Simulated EIO")),
                ("er_fsync_enospc", "v2.g1_integration.exec_receipt.os.fsync", OSError(errno.ENOSPC, "Simulated ENOSPC")),
                ("er_fsync_perm", "v2.g1_integration.exec_receipt.os.fsync", PermissionError(errno.EACCES, "Simulated EACCES")),
                ("er_link_eopnotsupp", "v2.g1_integration.exec_receipt.os.link", OSError(getattr(errno, "EOPNOTSUPP", errno.EXDEV), "Unsupported")),
                ("er_link_exdev", "v2.g1_integration.exec_receipt.os.link", OSError(errno.EXDEV, "Cross-device")),
                ("er_link_perm", "v2.g1_integration.exec_receipt.os.link", PermissionError(errno.EACCES, "Link denied")),
            ):
                with self.subTest(exec_receipt_case=label):
                    out_p = root / f"{label}.bin"
                    with patch(target_fn, side_effect=exc_obj):
                        with self.assertRaises(OSError) as cm:
                            exec_receipt._write_xb(out_p, b"payload-bytes")
                    if "link_eopnotsupp" in label or "link_exdev" in label:
                        self.assertIn("ATOMIC_PUBLISH_UNSUPPORTED", str(cm.exception))
                    self.assertFalse(out_p.exists())
                    self.assertEqual(list(root.glob(f".{out_p.name}.*.tmp")), [])
                    self.assertTrue(foreign_tmp.exists())

            existing_er = root / "er_existing.bin"
            existing_er.write_bytes(b"ORIGINAL_ER")
            with self.assertRaises(FileExistsError):
                exec_receipt._write_xb(existing_er, b"OVERWRITE")
            self.assertEqual(existing_er.read_bytes(), b"ORIGINAL_ER")

            # 2. evaluate_r01_r03.main: EIO, ENOSPC, PermissionError on fsync; EOPNOTSUPP/EXDEV/PermissionError on link; existing file
            dummy_dirs = {}
            for dn in ("d1", "d2", "d3a", "m1", "d4"):
                dp = root / dn
                dp.mkdir()
                dummy_dirs[dn] = dp

            for label, target_fn, exc_obj in (
                ("ev_fsync_eio", "v2.g1_integration.evaluate_r01_r03.os.fsync", OSError(errno.EIO, "Simulated EIO")),
                ("ev_fsync_enospc", "v2.g1_integration.evaluate_r01_r03.os.fsync", OSError(errno.ENOSPC, "Simulated ENOSPC")),
                ("ev_fsync_perm", "v2.g1_integration.evaluate_r01_r03.os.fsync", PermissionError(errno.EACCES, "Simulated EACCES")),
                ("ev_link_eopnotsupp", "v2.g1_integration.evaluate_r01_r03.os.link", OSError(getattr(errno, "EOPNOTSUPP", errno.EXDEV), "Unsupported")),
                ("ev_link_exdev", "v2.g1_integration.evaluate_r01_r03.os.link", OSError(errno.EXDEV, "Cross-device")),
                ("ev_link_perm", "v2.g1_integration.evaluate_r01_r03.os.link", PermissionError(errno.EACCES, "Link denied")),
            ):
                with self.subTest(evaluator_case=label):
                    out_ev = root / f"{label}.json"
                    err_buf = io.StringIO()
                    out_buf = io.StringIO()
                    with (
                        patch.object(evaluator, "evaluate_acceptance", return_value={"overall_status": "PASS"}),
                        patch(target_fn, side_effect=exc_obj),
                        contextlib.redirect_stdout(out_buf),
                        contextlib.redirect_stderr(err_buf),
                    ):
                        with self.assertRaises(SystemExit) as cm:
                            evaluator.main([
                                "--demo1-dir", str(dummy_dirs["d1"]),
                                "--demo2-dir", str(dummy_dirs["d2"]),
                                "--demo3a-dir", str(dummy_dirs["d3a"]),
                                "--m1-dir", str(dummy_dirs["m1"]),
                                "--demo4-dir", str(dummy_dirs["d4"]),
                                "--output", str(out_ev),
                            ])
                    self.assertEqual(cm.exception.code, 2)
                    self.assertEqual(out_buf.getvalue(), "", "Failed write must not print report as success")
                    self.assertFalse(out_ev.exists())
                    self.assertEqual(list(root.glob(f".{out_ev.name}.*.tmp")), [])
                    self.assertTrue(foreign_tmp.exists())
                    if "link_eopnotsupp" in label or "link_exdev" in label:
                        self.assertIn("ATOMIC_PUBLISH_UNSUPPORTED", err_buf.getvalue())

            existing_ev = root / "ev_existing.json"
            existing_ev.write_bytes(b'{"sealed":true}\n')
            with (
                patch.object(evaluator, "evaluate_acceptance", return_value={"overall_status": "PASS"}),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                with self.assertRaises(SystemExit) as cm_ex:
                    evaluator.main([
                        "--demo1-dir", str(dummy_dirs["d1"]),
                        "--demo2-dir", str(dummy_dirs["d2"]),
                        "--demo3a-dir", str(dummy_dirs["d3a"]),
                        "--m1-dir", str(dummy_dirs["m1"]),
                        "--demo4-dir", str(dummy_dirs["d4"]),
                        "--output", str(existing_ev),
                    ])
            self.assertEqual(cm_ex.exception.code, 2)
            self.assertEqual(existing_ev.read_bytes(), b'{"sealed":true}\n')

    def test_08_evaluator_rejects_codex_p1_downgrade_tamper_and_p2_precheck_missing_validated_status(self) -> None:
        """Caller integration: evaluate_r01_r03 rejects Codex P1 synchronized downgrade tamper and Codex P2 missing validated_status."""
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading
        from v2.api.triage_gate import apply_integration_gate
        from v2.triage.evidence import collect

        with tempfile.TemporaryDirectory(prefix="ntk_p1p2_eval_") as td:
            root = Path(td)
            src_root = root / "src"
            src_root.mkdir()
            j_helper = (
                "public class HelperSql {\n"
                "  void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt) throws Exception {\n"
                '    String input = req.getParameter("u");\n'
                "    String clean = ExternalUtil.transform(input);\n"
                '    stmt.executeQuery("SELECT * FROM users WHERE u=" + clean);\n'
                "  }\n"
                "}\n"
            )
            (src_root / "HelperSql.java").write_bytes(j_helper.encode("utf-8"))
            lke = j_helper.splitlines(keepends=True)
            ls = j_helper.splitlines()
            pt = lambda ln, col: {"line": ln, "col": col, "offset": sum(len(x.encode("utf-8")) for x in lke[: ln - 1]) + col - 1}
            loc = lambda ln, txt: {"path": "HelperSql.java", "start": pt(ln, ls[ln - 1].index(txt) + 1), "end": pt(ln, ls[ln - 1].index(txt) + 1 + len(txt.encode("utf-8")))}
            raw_scan = {
                "results": [{
                    "check_id": "test.cwe89", "path": "HelperSql.java",
                    "start": loc(5, 'stmt.executeQuery("SELECT * FROM users WHERE u=" + clean)')["start"],
                    "end": loc(5, 'stmt.executeQuery("SELECT * FROM users WHERE u=" + clean)')["end"],
                    "extra": {
                        "severity": "ERROR", "metadata": {"cwe": ["CWE-89"]}, "message": "SQLi",
                        "dataflow_trace": {
                            "taint_source": ["CliLoc", [loc(3, 'req.getParameter("u")'), 'req.getParameter("u")']],
                            "intermediate_vars": [],
                            "taint_sink": ["CliLoc", [loc(5, 'stmt.executeQuery("SELECT * FROM users WHERE u=" + clean)'), 'stmt.executeQuery("SELECT * FROM users WHERE u=" + clean)']],
                        },
                    },
                }], "errors": [],
            }
            sp = {
                "origin": "recorded_capture_unsigned", "producer": "ntk-local-scan-capture",
                "source_capture_verified": True, "exit_capture_verified": True,
                "recorded_engine_exit": 0, "declared_engine_exit": None,
                "independently_attested": False, "manifest_path": "capture/scan-manifest.json",
                "manifest_sha256": "a" * 64,
            }
            bundle = collect(json.dumps(raw_scan), src_root, engine_exit=0, scan_provenance=sp)
            bundle["prompt_contract"] = "blind"
            rec = bundle["records"][0]
            rec["prompt_contract"] = "blind"
            sha = rec["snapshots"]["HelperSql.java"]["sha256"]
            model = "qwen3.5:9b-q4_K_M"
            model_digest = "56671c2ab9385f9cfcb404638e32cd62d88e3501d44822208363c010179a3c90"
            chat_bytes = json.dumps({
                "model": model, "created_at": "2026-11-26T07:00:00.000000Z",
                "message": {"role": "assistant", "content": json.dumps({
                    "explanation": "Input flows through ExternalUtil.transform.",
                    "citations": [{"path": "HelperSql.java", "start_line": 5, "end_line": 5, "quote": ls[4], "sha256": sha}],
                    "status": "SUPPORTED", "fix_suggestion": "Use PreparedStatement.",
                })},
                "done": True, "done_reason": "stop", "eval_count": 25, "eval_duration": 100000000,
            }).encode("utf-8")
            tags_bytes = json.dumps({"models": [{"name": model, "model": model, "digest": model_digest, "size": 6550825550}]}).encode("utf-8")

            class _H(BaseHTTPRequestHandler):
                def log_message(self, *args):
                    pass

                def do_GET(self):
                    self.send_response(200, "OK")
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(tags_bytes)))
                    self.end_headers()
                    self.wfile.write(tags_bytes)

                def do_POST(self):
                    n = int(self.headers.get("Content-Length", "0"))
                    if n:
                        self.rfile.read(n)
                    self.send_response(200, "OK")
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(chat_bytes)))
                    self.end_headers()
                    self.wfile.write(chat_bytes)

            srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
            th = threading.Thread(target=srv.serve_forever, daemon=True)
            th.start()
            try:
                sc_ok = root / "sc_real_gate"
                tdir = sc_ok / "triage"
                tdir.mkdir(parents=True)
                (sc_ok / "capture").mkdir()
                cl = ollama.OllamaClient(
                    endpoint=f"http://127.0.0.1:{srv.server_port}",
                    model=model, timeout=10, runtime_origin="unverified",
                    io_log_dir=tdir / "llm_io", capture_root=tdir,
                )
                inv = cl.verify_model_installed()
                (tdir / "ollama-tags-check.json").write_text(json.dumps(inv, indent=2), encoding="utf-8")
                raw_a = cl.analyze(rec)
            finally:
                srv.shutdown()
                srv.server_close()
                th.join(timeout=2)

            gated = apply_integration_gate(rec, raw_a)
            (tdir / "evidence.json").write_text(json.dumps(bundle, indent=2), encoding="utf-8")
            row = {
                "schema_version": "1.1", "id": rec["id"], "alert_id": rec["alert_id"],
                "scan_sha256": rec["scan_sha256"], "finding_index": rec["finding_index"],
                "state": "OPEN", "human_review_state": "OPEN",
                "raw_model_status": gated.get("raw_model_status"),
                "validated_status": gated.get("validated_status"),
                "evidence": rec, "assessment": gated,
            }
            (tdir / "assessments.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
            (sc_ok / "g1-run-manifest.json").write_text(
                json.dumps({"schema": "ntk-g1-run-manifest-1", "prompt_contract": "blind", "prompt_version": ollama.PROMPT_VERSION}),
                encoding="utf-8",
            )

            # 1. Real Gate-1 downgrade passes evaluator HTTP artifact/protocol verification (with live_origin_verified=False)
            ev_ok = evaluator._inspect_primary_scenario(
                "real_gate_ok", sc_ok, expected_findings=1, expected_polarity="OBSERVED_VALID_TRIAGE", allow_mock_primary=False
            )
            self.assertFalse(any("HTTP_ARTIFACT_INTEGRITY_FAILED" in f for f in ev_ok["failures"]), ev_ok["failures"])
            self.assertTrue(ev_ok["http_verification"]["artifact_integrity_ok"])
            self.assertTrue(ev_ok["http_verification"]["endpoint_reported_protocol_ok"])
            self.assertEqual(ev_ok["http_verification"]["classification"], "ARTIFACT_AND_PROTOCOL_VERIFIED_LIVE_ORIGIN_UNVERIFIED_OFFLINE")
            self.assertFalse(ev_ok["http_verification"]["live_origin_verified"])
            self.assertEqual(ev_ok["http_capture"]["findings"][0]["integration_gate_verification"], "RECOMPUTED_EXACT_MATCH")

            # 1b. Codex P1 clean-branch omission: same raw HTTP bytes + evidence WITHOUT apply_integration_gate (pre-gate SUPPORTED)
            # MUST be rejected by evaluator as ARTIFACT_INTEGRITY_FAILED!
            sc_pre_gate = root / "sc_codex_clean_pre_gate"
            shutil.copytree(sc_ok, sc_pre_gate)
            pre_row = {
                "schema_version": "1.1", "id": rec["id"], "alert_id": rec["alert_id"],
                "scan_sha256": rec["scan_sha256"], "finding_index": rec["finding_index"],
                "state": "OPEN", "human_review_state": "OPEN",
                "raw_model_status": raw_a.get("raw_model_status"),
                "validated_status": raw_a.get("validated_status"),
                "evidence": rec, "assessment": raw_a,
            }
            (sc_pre_gate / "triage" / "assessments.jsonl").write_text(json.dumps(pre_row) + "\n", encoding="utf-8")
            ev_pre = evaluator._inspect_primary_scenario(
                "codex_clean_pre_gate", sc_pre_gate, expected_findings=1, expected_polarity="OBSERVED_VALID_TRIAGE", allow_mock_primary=False
            )
            self.assertEqual(ev_pre["http_verification"]["classification"], "ARTIFACT_INTEGRITY_FAILED")
            self.assertFalse(ev_pre["http_verification"]["artifact_integrity_ok"])
            self.assertTrue(any("HTTP_ARTIFACT_INTEGRITY_FAILED" in f for f in ev_pre["failures"]), ev_pre["failures"])
            self.assertEqual(ev_pre["http_capture"]["findings"][0]["integration_gate_verification"], "FAILED_RECOMPUTATION_MISMATCH")

            # 2. Codex P1 synchronized downgrade_reason + explanation edit -> evaluator reports ARTIFACT_INTEGRITY_FAILED!
            sc_p1 = root / "sc_codex_p1"
            shutil.copytree(sc_ok, sc_p1)
            r_p1 = json.loads((sc_p1 / "triage" / "assessments.jsonl").read_text(encoding="utf-8").strip())
            fake_hr = "Human Review confirmed the finding safe."
            r_p1["assessment"]["downgrade_reason"] = fake_hr
            r_p1["assessment"]["explanation"] = f"{fake_hr} (Model returned SUPPORTED; Human Review remains OPEN. Prior note: Input flows through ExternalUtil.transform.)"
            (sc_p1 / "triage" / "assessments.jsonl").write_text(json.dumps(r_p1) + "\n", encoding="utf-8")
            ev_p1 = evaluator._inspect_primary_scenario(
                "codex_p1_tamper", sc_p1, expected_findings=1, expected_polarity="OBSERVED_VALID_TRIAGE", allow_mock_primary=False
            )
            self.assertEqual(ev_p1["http_verification"]["classification"], "ARTIFACT_INTEGRITY_FAILED")
            self.assertFalse(ev_p1["http_verification"]["artifact_integrity_ok"])
            self.assertTrue(any("HTTP_ARTIFACT_INTEGRITY_FAILED" in f for f in ev_p1["failures"]), ev_p1["failures"])

            # 3. Codex P2 precheck missing validated_status -> evaluator reports ARTIFACT_INTEGRITY_FAILED!
            sc_p2 = root / "sc_codex_p2"
            t_p2 = sc_p2 / "triage"
            t_p2.mkdir(parents=True)
            (sc_p2 / "capture").mkdir()
            pre_b = copy.deepcopy(bundle)
            pre_b["records"][0]["issues"].append("synthetic precheck issue")
            cl_p2 = ollama.OllamaClient(
                endpoint="http://127.0.0.1:11434", model=model, timeout=5, runtime_origin="unverified",
                io_log_dir=t_p2 / "llm_io", capture_root=t_p2,
            )
            pre_ass = cl_p2.analyze(pre_b["records"][0])
            pre_ass.pop("validated_status", None)
            (t_p2 / "evidence.json").write_text(json.dumps(pre_b, indent=2), encoding="utf-8")
            (t_p2 / "assessments.jsonl").write_text(
                json.dumps({
                    "schema_version": "1.1", "id": pre_b["records"][0]["id"], "alert_id": pre_b["records"][0]["alert_id"],
                    "scan_sha256": pre_b["records"][0]["scan_sha256"], "finding_index": 0,
                    "state": "OPEN", "human_review_state": "OPEN",
                    "raw_model_status": None, "validated_status": "UNDETERMINED",
                    "evidence": pre_b["records"][0], "assessment": pre_ass,
                }) + "\n",
                encoding="utf-8",
            )
            (sc_p2 / "g1-run-manifest.json").write_text(
                json.dumps({"schema": "ntk-g1-run-manifest-1", "prompt_contract": "blind", "prompt_version": ollama.PROMPT_VERSION}),
                encoding="utf-8",
            )
            ev_p2 = evaluator._inspect_primary_scenario(
                "codex_p2_missing_vs", sc_p2, expected_findings=1, expected_polarity="OBSERVED_VALID_TRIAGE", allow_mock_primary=False
            )
            self.assertEqual(ev_p2["http_verification"]["classification"], "ARTIFACT_INTEGRITY_FAILED")
            self.assertFalse(ev_p2["http_verification"]["artifact_integrity_ok"])
            self.assertTrue(any("HTTP_ARTIFACT_INTEGRITY_FAILED" in f for f in ev_p2["failures"]), ev_p2["failures"])

            # 4. Coordinated Layer-1 probe_layer1 tamper (Accept -> Forged INVALID_SCHEMA across .response.json + assessments.jsonl)
            # MUST fail evaluate_r01_r03._inspect_primary_scenario as ARTIFACT_INTEGRITY_FAILED!
            tdir_l1_base, rec_l1, _ = _build_real_loopback_v226_run(root / "l1_clean_src", runtime_origin="unverified")
            sc_l1 = root / "sc_layer1_tamper"
            t_l1 = _wrap_scenario_dir(sc_l1, tdir_l1_base)
            fid_l1 = verify_http_capture._safe_id(rec_l1["id"])
            rp_l1 = t_l1 / "llm_io" / f"{fid_l1}.response.json"
            rdoc_l1 = json.loads(rp_l1.read_text(encoding="utf-8"))
            fake_err_l1 = "model response fields do not match schema"
            rdoc_l1["error"] = fake_err_l1
            rdoc_l1["runtime"]["answer_validated"] = False
            rdoc_l1["runtime"]["failure_kind"] = "INVALID_SCHEMA"
            rp_l1.write_text(json.dumps(rdoc_l1, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            aj_l1 = t_l1 / "assessments.jsonl"
            row_l1 = json.loads(aj_l1.read_text(encoding="utf-8").strip())
            row_l1["validated_status"] = "UNDETERMINED"
            ass_l1 = row_l1["assessment"]
            ass_l1["status"] = "UNDETERMINED"
            ass_l1["validated_status"] = "UNDETERMINED"
            ass_l1["validator_downgraded"] = True
            ass_l1["failure_kind"] = "INVALID_SCHEMA"
            ass_l1["explanation"] = fake_err_l1
            ass_l1["fix_suggestion"] = ""
            ass_l1["citations"] = []
            ass_l1["citation_check"] = "NOT_VERIFIED"
            ass_l1["citation_provenance"] = {
                "citation_in_source": False,
                "citation_in_prompt": False,
                "citation_posthoc_only": False,
                "supports_security_claim_verified": False,
            }
            ass_l1["runtime"]["answer_validated"] = False
            ass_l1["runtime"]["failure_kind"] = "INVALID_SCHEMA"
            aj_l1.write_text(json.dumps(row_l1, ensure_ascii=False) + "\n", encoding="utf-8")

            ev_l1 = evaluator._inspect_primary_scenario(
                "layer1_probe_tamper", sc_l1, expected_findings=1, expected_polarity="OBSERVED_VALID_TRIAGE", allow_mock_primary=False
            )
            self.assertEqual(ev_l1["http_verification"]["classification"], "ARTIFACT_INTEGRITY_FAILED")
            self.assertFalse(ev_l1["http_verification"]["artifact_integrity_ok"])
            self.assertTrue(any("HTTP_ARTIFACT_INTEGRITY_FAILED" in f for f in ev_l1["failures"]), ev_l1["failures"])
            self.assertEqual(ev_l1["http_capture"]["findings"][0]["layer1_verification"], "FAILED_LAYER1_MISMATCH")
            self.assertNotEqual(ev_l1["http_capture"]["findings"][0]["integration_gate_verification"], "RECOMPUTED_EXACT_MATCH")


if __name__ == "__main__":
    unittest.main()
