"""Integration tests for B1/B2 runtime controls:
- `exec_receipt.py` binary stream preservation, fail-fast exit checks, and overwrite refusal
- Inherited `semgrepai scan --local-triage` end-to-end raw HTTP capture & `http-capture-check.json`
- `run_g1_demo --auxiliary-controls-only` zero-real-Qwen control execution
- `evaluate_r01_r03.py` read-only SQLite inspection, R01-R03 verification, and false-PASS guards

All HTTP servers in this suite are explicit local loopback MOCK fixtures; real Qwen is never called.
"""
from __future__ import annotations

import contextlib
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from v2.g1_integration.evaluate_r01_r03 import evaluate_acceptance, main as evaluate_main
from v2.g1_integration.exec_receipt import execute_with_receipt, main as exec_receipt_main
from v2.g1_integration.run_g1_demo import run_demo_suite
from v2.g1_integration.tests.test_g1_integration import (
    _build_synthetic_prepared_fork,
    _find_opengrep_binary,
    _run_prepared_cli,
)
from v2.triage.evidence import digest, strict_json


def _dir_inventory(root: Path) -> dict[str, str]:
    inv: dict[str, str] = {}
    for p in sorted(root.rglob("*")):
        if p.is_file():
            inv[p.relative_to(root).as_posix()] = digest(p.read_bytes())
    return inv


class ExecReceiptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tmp_root = Path(self.tmp.name).resolve()

    def test_binary_stdout_stderr_preservation_fail_fast_and_overwrite_refusal(self):
        rdir = self.tmp_root / "receipts"
        script = (
            "import sys; "
            "sys.stdout.buffer.write(b'OUT\\x00\\xff\\r\\nLINE2'); "
            "sys.stderr.buffer.write(b'ERR\\xfe\\x80\\n'); "
            "raise SystemExit(0)"
        )
        rc = exec_receipt_main([
            "--receipt-dir", str(rdir),
            "--step", "01_bin_check",
            "--expect-exit", "0",
            "--",
            sys.executable, "-c", script,
        ])
        self.assertEqual(rc, 0)
        self.assertEqual((rdir / "01_bin_check.stdout.bin").read_bytes(), b"OUT\x00\xff\r\nLINE2")
        self.assertEqual((rdir / "01_bin_check.stderr.bin").read_bytes(), b"ERR\xfe\x80\n")
        doc = strict_json((rdir / "01_bin_check.receipt.json").read_text(encoding="utf-8"))
        self.assertEqual(doc["exit_code"], 0)
        self.assertTrue(doc["exit_matched_expectation"])
        self.assertEqual(doc["stdout_sha256"], digest(b"OUT\x00\xff\r\nLINE2"))
        self.assertEqual(doc["stderr_sha256"], digest(b"ERR\xfe\x80\n"))

        # Reusing the same step stem must refuse to overwrite
        with self.assertRaises(FileExistsError):
            execute_with_receipt(
                [sys.executable, "-c", "print('x')"],
                receipt_dir=rdir,
                step="01_bin_check",
            )

        # Unexpected exit code fails fast (non-zero return) while still saving binary streams + receipt
        rc_fail = exec_receipt_main([
            "--receipt-dir", str(rdir),
            "--step", "02_expected_fail_fast",
            "--expect-exit", "0",
            "--",
            sys.executable, "-c", "import sys; sys.stderr.buffer.write(b'boom'); raise SystemExit(3)",
        ])
        self.assertEqual(rc_fail, 3)
        self.assertEqual((rdir / "02_expected_fail_fast.stderr.bin").read_bytes(), b"boom")
        doc_fail = strict_json((rdir / "02_expected_fail_fast.receipt.json").read_text(encoding="utf-8"))
        self.assertEqual(doc_fail["exit_code"], 3)
        self.assertFalse(doc_fail["exit_matched_expectation"])


class B1B2EndToEndAcceptanceControlsTests(unittest.TestCase):
    def setUp(self):
        self.opengrep = _find_opengrep_binary()
        if not self.opengrep:
            self.skipTest("OpenGrep binary not available on test host")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tmp_root = Path(self.tmp.name).resolve()
        self.prepared_source = _build_synthetic_prepared_fork(self.tmp_root / "prepared_fork")
        self.rules = REPO_ROOT / "v2" / "g1_integration" / "rules" / "java_g1_cwe22_cwe89.yml"
        self.fixtures = REPO_ROOT / "v2" / "g1_integration" / "demo_fixtures"

    def _start_mock_qwen_server(self, *, mode: str = "valid_all"):
        """Start loopback mock HTTP server responding to Demo1, Demo2, and Demo3a prompts."""
        post_counter = {"count": 0}

        class _MockQwenHandler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                if self.path == "/api/tags":
                    raw = b'{\r\n  "models": [{"name": "qwen3.5:9b-q4_K_M", "digest": "mockdigest", "size": 100}]\r\n}\r\n'
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                else:
                    self.send_error(404)

            def do_POST(self):
                post_counter["count"] += 1
                length = int(self.headers.get("Content-Length", "0"))
                req_bytes = self.rfile.read(length)
                req_doc = json.loads(req_bytes.decode("utf-8"))
                user_ev = json.loads(req_doc["messages"][1]["content"])
                snip = user_ev["snippets"][0]
                rel_path = snip["path"]
                snap_sha = snip["sha256"]
                line_map = {ln["line"]: ln["text"] for ln in snip["lines"]}
                sink_ln = user_ev["start"]["line"]

                if "Demo1TruePositive.java" in rel_path:
                    ans = {
                        "status": "SUPPORTED",
                        "explanation": "MOCK: Tham số đầu vào đi thẳng tới sink nhạy cảm không qua kiểm tra.",
                        "citations": [{
                            "path": rel_path,
                            "start_line": sink_ln,
                            "end_line": sink_ln,
                            "quote": line_map[sink_ln],
                            "sha256": snap_sha,
                        }],
                        "fix_suggestion": "MOCK: Ràng buộc tham số đầu vào trước khi truy cập tài nguyên.",
                    }
                elif "Demo2ProtectedFalsePositive.java" in rel_path:
                    if mode == "demo2_invalid_citation":
                        ans = {
                            "status": "REFUTED",
                            "explanation": "MOCK: Sai trích dẫn để kiểm tra bộ chặn false-PASS.",
                            "citations": [{
                                "path": "/mnt/c/forged/" + rel_path,
                                "start_line": sink_ln,
                                "end_line": sink_ln,
                                "quote": line_map[sink_ln],
                                "sha256": snap_sha,
                            }],
                            "fix_suggestion": "",
                        }
                    else:
                        # Canonical multiline citation covering lines 16-18 (getCanonicalPath + startsWith('/srv/reports/'))
                        guard_lines = [ln for ln in sorted(line_map) if "getCanonicalPath" in line_map[ln] or "startsWith(\"/srv/reports/\")" in line_map[ln]]
                        g_start, g_end = min(guard_lines), max(guard_lines)
                        quote = "\n".join(line_map[i] for i in range(g_start, g_end + 1))
                        ans = {
                            "status": "REFUTED",
                            "explanation": "MOCK: Đường dẫn đã được chuẩn hóa bằng getCanonicalPath và kiểm tra tiền tố /srv/reports/.",
                            "citations": [{
                                "path": rel_path,
                                "start_line": g_start,
                                "end_line": g_end,
                                "quote": quote,
                                "sha256": snap_sha,
                            }],
                            "fix_suggestion": "",
                        }
                else:
                    # Demo3a missing external helper
                    if mode == "demo3a_supported_violation":
                        ans = {
                            "status": "SUPPORTED",
                            "explanation": "MOCK: Giả lập lỗi kết luận SUPPORTED dù thiếu mã nguồn helper.",
                            "citations": [{
                                "path": rel_path,
                                "start_line": sink_ln,
                                "end_line": sink_ln,
                                "quote": line_map[sink_ln],
                                "sha256": snap_sha,
                            }],
                            "fix_suggestion": "MOCK",
                        }
                    else:
                        ans = {
                            "status": "UNDETERMINED",
                            "explanation": "MOCK: Không có mã nguồn ExternalPathPolicy.normalizeDocumentPath trong bằng chứng.",
                            "citations": [{
                                "path": rel_path,
                                "start_line": sink_ln,
                                "end_line": sink_ln,
                                "quote": line_map[sink_ln],
                                "sha256": snap_sha,
                            }],
                            "fix_suggestion": "MOCK: Kiểm tra thủ công lớp helper bên ngoài.",
                        }

                # Irregular formatting + CRLF to prove raw byte preservation through inherited CLI
                envelope_str = (
                    "{\r\n"
                    '  "mock_test_fixture": true,\r\n'
                    '  "done": true,\r\n'
                    '  "done_reason": "stop",\r\n'
                    '  "model": "qwen3.5:9b-q4_K_M",\r\n'
                    '  "eval_count": 33,\r\n'
                    '  "eval_duration": 123456,\r\n'
                    f'  "message": {{ "role": "assistant", "content": {json.dumps(json.dumps(ans, ensure_ascii=False), ensure_ascii=False)} }}\r\n'
                    "}\r\n"
                )
                body = envelope_str.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _MockQwenHandler)
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        self.addCleanup(lambda: (srv.shutdown(), srv.server_close(), th.join(timeout=2)))
        return srv, post_counter

    def _run_primary_set_and_lifecycle(self, run_root: Path, endpoint: str) -> tuple[Path, Path, Path, Path]:
        m1_dir = run_root / "m1_scan_only"
        r_m1 = _run_prepared_cli(self.prepared_source, [
            "scan", str(self.fixtures / "Demo1TruePositive.java"),
            "--rules-path", str(self.rules),
            "--output-dir", str(m1_dir),
            "--executable", self.opengrep,
            "--scan-only",
        ])
        self.assertEqual(r_m1.returncode, 0, r_m1.stderr)

        d1_dir = run_root / "demo1_true_positive"
        d2_dir = run_root / "demo2_protected_fp"
        d3a_dir = run_root / "demo3a_missing_helper"
        for target_java, out_d in (
            (self.fixtures / "Demo1TruePositive.java", d1_dir),
            (self.fixtures / "Demo2ProtectedFalsePositive.java", d2_dir),
            (self.fixtures / "Demo3ExternalHelperUndetermined.java", d3a_dir),
        ):
            r = _run_prepared_cli(self.prepared_source, [
                "scan", str(target_java),
                "--rules-path", str(self.rules),
                "--output-dir", str(out_d),
                "--executable", self.opengrep,
                "--local-triage",
                "--endpoint", endpoint,
                "--model", "qwen3.5:9b-q4_K_M",
                "--prompt-contract", "blind",
                "--runtime-origin", "mock",
            ])
            self.assertEqual(r.returncode, 0, r.stderr)
            shutil.copy2(out_d / "triage" / "review.sqlite", out_d / "triage" / "review.post_ingestion.sqlite")

        # Manual CLI lifecycle on Demo1 (confirm-true using .warnings[0].id)
        d1_db = str(d1_dir / "triage" / "review.sqlite")
        d1_q = json.loads(_run_prepared_cli(self.prepared_source, ["queue", "--db", d1_db]).stdout)
        d1_wid = d1_q["warnings"][0]["id"]
        self.assertEqual(
            _run_prepared_cli(self.prepared_source, [
                "confirm-true", d1_wid, "--db", d1_db, "--actor", "test-operator",
                "--reason", "Confirmed unsanitized taint trace on Demo1",
            ]).returncode,
            0,
        )

        # Manual CLI lifecycle on Demo2 (confirm-false -> queue -> queue --all -> reopen -> queue)
        d2_db = str(d2_dir / "triage" / "review.sqlite")
        d2_q = json.loads(_run_prepared_cli(self.prepared_source, ["queue", "--db", d2_db]).stdout)
        d2_wid = d2_q["warnings"][0]["id"]
        self.assertEqual(
            _run_prepared_cli(self.prepared_source, [
                "confirm-false", d2_wid, "--db", d2_db, "--actor", "test-operator",
                "--reason", "Verified getCanonicalPath().startsWith('/srv/reports/') guard before FileInputStream",
            ]).returncode,
            0,
        )
        shutil.copy2(d2_dir / "triage" / "review.sqlite", d2_dir / "triage" / "review.after_confirm_false.sqlite")
        self.assertEqual(json.loads(_run_prepared_cli(self.prepared_source, ["queue", "--db", d2_db]).stdout)["warnings"], [])
        self.assertEqual(
            json.loads(_run_prepared_cli(self.prepared_source, ["queue", "--db", d2_db, "--all"]).stdout)["warnings"][0]["state"],
            "CONFIRMED_FALSE",
        )
        self.assertEqual(
            _run_prepared_cli(self.prepared_source, [
                "reopen", d2_wid, "--db", d2_db, "--actor", "test-lead",
                "--reason", "Reopened to verify mount symlink policy",
            ]).returncode,
            0,
        )
        return m1_dir, d1_dir, d2_dir, d3a_dir

    def test_01_full_single_set_r01_r03_evaluation_auxiliary_controls_and_readonly_sqlite(self):
        srv, post_counter = self._start_mock_qwen_server(mode="valid_all")
        endpoint = f"http://127.0.0.1:{srv.server_port}"
        run_root = self.tmp_root / "acceptance_valid"

        m1_dir, d1_dir, d2_dir, d3a_dir = self._run_primary_set_and_lifecycle(run_root, endpoint)
        # Exactly 4 chat POST calls in the primary set (2 + 1 + 1), never 8!
        self.assertEqual(post_counter["count"], 4)

        # Auxiliary controls (--auxiliary-controls-only) must make ZERO calls to endpoint!
        aux_dir = run_root / "aux_controls"
        aux_summary = run_demo_suite(
            prepared_source=self.prepared_source,
            output_dir=aux_dir,
            executable=self.opengrep,
            endpoint=endpoint,
            auxiliary_controls_only=True,
        )
        self.assertEqual(post_counter["count"], 4, "--auxiliary-controls-only must issue 0 calls to primary endpoint")
        self.assertEqual(set(aux_summary["scenarios"]), {"demo3b_malformed_json_mock", "demo4_stale_source"})
        self.assertTrue((aux_dir / "child_receipts" / "01_demo3b_mock_scan.receipt.json").is_file())
        d3b_dir = aux_dir / "demo3b_malformed_llm_synthetic_mock"
        d4_dir = aux_dir / "demo4_stale_source"

        # Verify raw HTTP capture check file generated by bridge.py
        d1_http_check = strict_json((d1_dir / "triage" / "http-capture-check.json").read_text(encoding="utf-8"))
        self.assertEqual(d1_http_check["capture_status"], "VERIFIED_COMPLETE")
        self.assertTrue(d1_http_check["capture_integrity_ok"])

        # Without --allow-mock-primary, evaluator MUST block mock runs (never report real runtime PASS!)
        blocked_report = evaluate_acceptance(
            demo1_dir=d1_dir, demo2_dir=d2_dir, demo3a_dir=d3a_dir,
            m1_dir=m1_dir, demo4_dir=d4_dir, demo3b_dir=d3b_dir,
            allow_mock_primary=False,
        )
        self.assertEqual(blocked_report["overall_status"], "BLOCKED")
        self.assertEqual(blocked_report["criteria"]["R01"]["status"], "BLOCKED")

        # Snapshot scenario directory hashes BEFORE evaluate_main to prove strict read-only audit
        before_inv = {
            name: _dir_inventory(p)
            for name, p in (("m1", m1_dir), ("d1", d1_dir), ("d2", d2_dir), ("d3a", d3a_dir), ("d3b", d3b_dir), ("d4", d4_dir))
        }
        eval_out = run_root / "audit" / "r01_r03_eval.json"
        rc = evaluate_main([
            "--demo1-dir", str(d1_dir),
            "--demo2-dir", str(d2_dir),
            "--demo3a-dir", str(d3a_dir),
            "--m1-dir", str(m1_dir),
            "--demo3b-dir", str(d3b_dir),
            "--demo4-dir", str(d4_dir),
            "--output", str(eval_out),
            "--allow-mock-primary",
        ])
        self.assertEqual(rc, 0)
        after_inv = {
            name: _dir_inventory(p)
            for name, p in (("m1", m1_dir), ("d1", d1_dir), ("d2", d2_dir), ("d3a", d3a_dir), ("d3b", d3b_dir), ("d4", d4_dir))
        }
        self.assertEqual(before_inv, after_inv, "evaluate_r01_r03 must be 100% read-only on all scenario directories")

        eval_doc = strict_json(eval_out.read_text(encoding="utf-8"))
        self.assertEqual(eval_doc["overall_status"], "PASS")
        self.assertEqual(eval_doc["real_qwen_denominator"]["observed"], 4)
        for cid in ("R01", "R02", "R03"):
            self.assertEqual(eval_doc["criteria"][cid]["status"], "PASS", eval_doc["criteria"][cid])

    def test_02_false_pass_guards_reject_cli_exit_zero_when_citation_invalid_or_demo3a_not_abstaining(self):
        aux_dir = self.tmp_root / "shared_aux"
        run_demo_suite(
            prepared_source=self.prepared_source,
            output_dir=aux_dir,
            executable=self.opengrep,
            auxiliary_controls_only=True,
        )
        d3b_dir = aux_dir / "demo3b_malformed_llm_synthetic_mock"
        d4_dir = aux_dir / "demo4_stale_source"

        # Case A: Demo2 CLI exited 0 & HTTP 200, but citation used forged raw path -> INVALID_CITATION -> R01 MUST FAIL
        srv_bad_cite, _ = self._start_mock_qwen_server(mode="demo2_invalid_citation")
        m1_a, d1_a, d2_a, d3a_a = self._run_primary_set_and_lifecycle(
            self.tmp_root / "run_bad_cite", f"http://127.0.0.1:{srv_bad_cite.server_port}"
        )
        rep_a = evaluate_acceptance(
            demo1_dir=d1_a, demo2_dir=d2_a, demo3a_dir=d3a_a,
            m1_dir=m1_a, demo4_dir=d4_dir, demo3b_dir=d3b_dir,
            allow_mock_primary=True,
        )
        self.assertEqual(rep_a["criteria"]["R01"]["status"], "FAIL")
        self.assertEqual(rep_a["overall_status"], "FAIL")

        # Case B: Demo3a missing helper returned SUPPORTED (even with valid citation & CLI exit 0!) -> R01 MUST FAIL
        srv_no_abstain, _ = self._start_mock_qwen_server(mode="demo3a_supported_violation")
        m1_b, d1_b, d2_b, d3a_b = self._run_primary_set_and_lifecycle(
            self.tmp_root / "run_no_abstain", f"http://127.0.0.1:{srv_no_abstain.server_port}"
        )
        rep_b = evaluate_acceptance(
            demo1_dir=d1_b, demo2_dir=d2_b, demo3a_dir=d3a_b,
            m1_dir=m1_b, demo4_dir=d4_dir, demo3b_dir=d3b_dir,
            allow_mock_primary=True,
        )
        self.assertEqual(rep_b["criteria"]["R01"]["status"], "FAIL")
        self.assertEqual(rep_b["overall_status"], "FAIL")

    def test_03_f05_f06_f07_evaluator_fail_closed_counterexamples(self):
        srv, _ = self._start_mock_qwen_server(mode="valid_all")
        endpoint = f"http://127.0.0.1:{srv.server_port}"
        run_root = self.tmp_root / "f05_f07_run"
        m1_dir, d1_dir, d2_dir, d3a_dir = self._run_primary_set_and_lifecycle(run_root, endpoint)

        aux_dir = self.tmp_root / "f05_f07_aux"
        run_demo_suite(
            prepared_source=self.prepared_source,
            output_dir=aux_dir,
            executable=self.opengrep,
            auxiliary_controls_only=True,
        )
        d3b_dir = aux_dir / "demo3b_malformed_llm_synthetic_mock"
        d4_dir = aux_dir / "demo4_stale_source"

        def _eval(override_d1: Path | None = None):
            return evaluate_acceptance(
                demo1_dir=override_d1 or d1_dir,
                demo2_dir=d2_dir,
                demo3a_dir=d3a_dir,
                m1_dir=m1_dir,
                demo4_dir=d4_dir,
                demo3b_dir=d3b_dir,
                allow_mock_primary=True,
            )

        self.assertEqual(_eval()["overall_status"], "PASS")

        def _assert_tampered_file(path: Path, mutator, expected_criterion: str):
            orig = path.read_bytes()
            try:
                mutator(path)
                rep = _eval()
                self.assertEqual(rep["overall_status"], "FAIL", f"{path.name}: {rep['criteria']}")
                self.assertEqual(rep["criteria"][expected_criterion]["status"], "FAIL", rep["criteria"][expected_criterion])
            finally:
                path.write_bytes(orig)

        # F05a: Missing triage/input.opengrep.json -> R02 FAIL
        _assert_tampered_file(d1_dir / "triage" / "input.opengrep.json", lambda p: p.unlink(), "R02")

        # F05b: Consistent scanner child non-zero exit (json.exit.txt=7 + scan-manifest.json updated) -> R02 FAIL
        exit_file = d1_dir / "capture" / "json.exit.txt"
        man_file = d1_dir / "capture" / "scan-manifest.json"
        orig_exit = exit_file.read_bytes()
        orig_man = man_file.read_bytes()
        try:
            exit_file.write_text("7", encoding="utf-8")
            mdoc = json.loads(orig_man.decode("utf-8"))
            mdoc["runs"]["json"]["exit_code"] = 7
            mdoc["artifacts"]["json.exit.txt"] = digest(b"7")
            man_file.write_text(json.dumps(mdoc, indent=2), encoding="utf-8")
            rep_exit = _eval()
            self.assertEqual(rep_exit["overall_status"], "FAIL")
            self.assertEqual(rep_exit["criteria"]["R02"]["status"], "FAIL")
        finally:
            exit_file.write_bytes(orig_exit)
            man_file.write_bytes(orig_man)

        # F06a: Missing Demo1/triage/review.post_ingestion.sqlite -> R03 FAIL
        _assert_tampered_file(d1_dir / "triage" / "review.post_ingestion.sqlite", lambda p: p.unlink(), "R03")

        # F06b: Missing Demo2/triage/review.after_confirm_false.sqlite -> R03 FAIL
        _assert_tampered_file(d2_dir / "triage" / "review.after_confirm_false.sqlite", lambda p: p.unlink(), "R03")

        # F07a: Corrupted SQLite bytes -> clean R03 FAIL (no unhandled DatabaseError crash)
        _assert_tampered_file(
            d1_dir / "triage" / "review.sqlite",
            lambda p: p.write_bytes(b"not a valid sqlite database"),
            "R03",
        )

        # F07b: Mutate Demo1 warnings.state without event -> event-replay mismatch -> R03 FAIL
        def _tamper_warning_state(db_p: Path):
            with contextlib.closing(sqlite3.connect(str(db_p))) as conn:
                conn.execute("UPDATE warnings SET state='CONFIRMED_TRUE' WHERE state='OPEN'")
                conn.commit()

        _assert_tampered_file(d1_dir / "triage" / "review.sqlite", _tamper_warning_state, "R03")

        # F07c: Mutate Demo2 event evidence_sha256 & invalid timestamp -> R03 FAIL
        def _tamper_event_row(db_p: Path):
            with contextlib.closing(sqlite3.connect(str(db_p))) as conn:
                conn.execute("UPDATE events SET evidence_sha256='badsha', timestamp='not-iso' WHERE sequence=1")
                conn.commit()

        _assert_tampered_file(d2_dir / "triage" / "review.sqlite", _tamper_event_row, "R03")

        # F06c (A2 in-place without relocation): mandatory review.post_ingestion.sqlite SHA-256 anchor in g1-run-manifest.json
        def _drop_review_sha(p: Path):
            doc = json.loads(p.read_text(encoding="utf-8"))
            doc["artifacts"]["review_sqlite"].pop("sha256", None)
            p.write_text(json.dumps(doc, indent=2), encoding="utf-8")

        def _null_review_sha(p: Path):
            doc = json.loads(p.read_text(encoding="utf-8"))
            doc["artifacts"]["review_sqlite"]["sha256"] = None
            p.write_text(json.dumps(doc, indent=2), encoding="utf-8")

        def _bad_hex_review_sha(p: Path):
            doc = json.loads(p.read_text(encoding="utf-8"))
            doc["artifacts"]["review_sqlite"]["sha256"] = "not-a-valid-sha256"
            p.write_text(json.dumps(doc, indent=2), encoding="utf-8")

        def _wrong_review_sha(p: Path):
            doc = json.loads(p.read_text(encoding="utf-8"))
            doc["artifacts"]["review_sqlite"]["sha256"] = "0" * 64
            p.write_text(json.dumps(doc, indent=2), encoding="utf-8")

        def _drop_review_entry(p: Path):
            doc = json.loads(p.read_text(encoding="utf-8"))
            doc["artifacts"].pop("review_sqlite", None)
            p.write_text(json.dumps(doc, indent=2), encoding="utf-8")

        for mut in (_drop_review_sha, _null_review_sha, _bad_hex_review_sha, _wrong_review_sha, _drop_review_entry):
            _assert_tampered_file(d1_dir / "g1-run-manifest.json", mut, "R03")
        _assert_tampered_file(d4_dir / "g1-run-manifest.json", _drop_review_sha, "R03")

        def _mutate_post_ingestion_db(db_p: Path):
            with contextlib.closing(sqlite3.connect(str(db_p))) as conn:
                conn.execute("UPDATE warnings SET assessment='{}'")
                conn.commit()

        _assert_tampered_file(d1_dir / "triage" / "review.post_ingestion.sqlite", _mutate_post_ingestion_db, "R03")

        # F07d (A3 in-place without relocation): review event / rejected_decisions predating scan must FAIL;
        # valid post-ingestion non-UTC timezone offset (+07:00) must PASS; evaluator stays strictly read-only.
        d1_db_file = d1_dir / "triage" / "review.sqlite"
        orig_d1_db_bytes = d1_db_file.read_bytes()
        try:
            with contextlib.closing(sqlite3.connect(str(d1_db_file))) as conn:
                conn.execute("UPDATE events SET timestamp='2000-01-01T00:00:00+00:00'")
                conn.commit()
            d1_triage_inv_before = _dir_inventory(d1_dir / "triage")
            rep_predate = _eval()
            self.assertEqual(rep_predate["overall_status"], "FAIL")
            self.assertEqual(rep_predate["criteria"]["R03"]["status"], "FAIL")
            self.assertTrue(
                any("precedes scan" in msg or "precedes" in msg for msg in rep_predate["criteria"]["R03"]["failures"]),
                rep_predate["criteria"]["R03"]["failures"],
            )
            self.assertEqual(_dir_inventory(d1_dir / "triage"), d1_triage_inv_before)

            # Naive timestamp without timezone offset -> R03 FAIL
            with contextlib.closing(sqlite3.connect(str(d1_db_file))) as conn:
                conn.execute("UPDATE events SET timestamp='2026-11-15T12:00:00'")
                conn.commit()
            rep_naive = _eval()
            self.assertEqual(rep_naive["overall_status"], "FAIL")
            self.assertEqual(rep_naive["criteria"]["R03"]["status"], "FAIL")

            # Positive timezone-offset control (+07:00 strictly after g1-run-manifest recorded_at) -> PASS
            d1_manifest_doc = json.loads((d1_dir / "g1-run-manifest.json").read_text(encoding="utf-8"))
            rec_dt = datetime.fromisoformat(d1_manifest_doc["recorded_at"].replace("Z", "+00:00"))
            tz_vn = timezone(timedelta(hours=7))
            valid_plus7_ts = (rec_dt + timedelta(seconds=5)).astimezone(tz_vn).isoformat()
            with contextlib.closing(sqlite3.connect(str(d1_db_file))) as conn:
                conn.execute("UPDATE events SET timestamp=?", (valid_plus7_ts,))
                conn.commit()
            rep_plus7 = _eval()
            self.assertEqual(rep_plus7["overall_status"], "PASS", rep_plus7["criteria"])
            self.assertEqual(rep_plus7["criteria"]["R03"]["status"], "PASS")
        finally:
            d1_db_file.write_bytes(orig_d1_db_bytes)
        self.assertEqual(_eval()["overall_status"], "PASS")

        # Demo4 rejected_decisions predating scan -> R03 FAIL
        def _predate_d4_rejected(db_p: Path):
            with contextlib.closing(sqlite3.connect(str(db_p))) as conn:
                conn.execute("UPDATE rejected_decisions SET timestamp='2000-01-01T00:00:00+00:00'")
                conn.commit()

        _assert_tampered_file(d4_dir / "triage" / "review.sqlite", _predate_d4_rejected, "R03")

        # A1 deep ancestor junction on scenario directory -> evaluator rejects with FAIL
        junc_holder = self.tmp_root / "eval_deep_junc_holder"
        junc_holder.mkdir()
        junc_outside = self.tmp_root / "eval_deep_junc_outside"
        (junc_outside / "a" / "b").mkdir(parents=True)
        shutil.copytree(d1_dir, junc_outside / "a" / "b" / "d1")
        eval_link = junc_holder / "link"
        linked_ok = False
        if os.name == "nt":
            proc = subprocess.run(
                ["cmd.exe", "/c", "mklink", "/J", str(eval_link), str(junc_outside)],
                capture_output=True,
                text=True,
            )
            linked_ok = proc.returncode == 0
        else:
            try:
                os.symlink(str(junc_outside), str(eval_link), target_is_directory=True)
                linked_ok = True
            except (OSError, NotImplementedError):
                linked_ok = False
        if linked_ok:
            try:
                rep_junc = _eval(override_d1=eval_link / "a" / "b" / "d1")
                self.assertEqual(rep_junc["overall_status"], "FAIL")
                self.assertEqual(rep_junc["criteria"]["R02"]["status"], "FAIL")
                self.assertEqual(rep_junc["criteria"]["R03"]["status"], "FAIL")
            finally:
                if os.name == "nt":
                    subprocess.run(["cmd.exe", "/c", "rmdir", str(eval_link)], capture_output=True, text=True)
                elif eval_link.is_symlink():
                    eval_link.unlink()

        # F05c: Live Java fixture drift on disk after scan -> R02 FAIL without mutating triage/
        live_src_dir = self.tmp_root / "mutable_d1_live_src"
        live_src_dir.mkdir()
        live_java = live_src_dir / "Demo1TruePositive.java"
        shutil.copy2(self.fixtures / "Demo1TruePositive.java", live_java)
        d1_live = self.tmp_root / "d1_live_drift_run"
        r_live = _run_prepared_cli(self.prepared_source, [
            "scan", str(live_java),
            "--rules-path", str(self.rules),
            "--output-dir", str(d1_live),
            "--executable", self.opengrep,
            "--local-triage",
            "--endpoint", endpoint,
            "--model", "qwen3.5:9b-q4_K_M",
            "--prompt-contract", "blind",
            "--runtime-origin", "mock",
        ])
        self.assertEqual(r_live.returncode, 0, r_live.stderr)
        shutil.copy2(d1_live / "triage" / "review.sqlite", d1_live / "triage" / "review.post_ingestion.sqlite")
        d1_live_db = str(d1_live / "triage" / "review.sqlite")
        live_wid = json.loads(_run_prepared_cli(self.prepared_source, ["queue", "--db", d1_live_db]).stdout)["warnings"][0]["id"]
        self.assertEqual(
            _run_prepared_cli(self.prepared_source, [
                "confirm-true", live_wid, "--db", d1_live_db, "--actor", "test-operator",
                "--reason", "Confirmed live fixture before post-scan drift check",
            ]).returncode,
            0,
        )
        self.assertEqual(_eval(override_d1=d1_live)["overall_status"], "PASS")

        triage_inv_before = _dir_inventory(d1_live / "triage")
        live_java.write_text(live_java.read_text(encoding="utf-8") + "\n// post-scan live drift\n", encoding="utf-8")
        rep_drift = _eval(override_d1=d1_live)
        self.assertEqual(rep_drift["overall_status"], "FAIL")
        self.assertEqual(rep_drift["criteria"]["R02"]["status"], "FAIL")
        self.assertEqual(_dir_inventory(d1_live / "triage"), triage_inv_before)


if __name__ == "__main__":
    unittest.main()
