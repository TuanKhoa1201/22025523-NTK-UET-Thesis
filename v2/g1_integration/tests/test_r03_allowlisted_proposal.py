"""Offline regression and counterexample tests for the PROPOSED AllowlistedQuery R03 FP replacement.

All loopback HTTP Qwen responses and SQLite lifecycle tests in this file are explicitly
mocked (`SCRIPTED_TEST_ONLY` / `mock` runtime origin) and use real OpenGrep subprocess execution
without mutating any committed G1 fixture or external G1-C5 evidence directory.
"""
from __future__ import annotations

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

from v2.g1_integration.evaluate_r01_r03 import (
    _read_sqlite_state_ro,
    _verify_allowlisted_fp_scenario_identity,
    _verify_sqlite_against_triage,
    evaluate_acceptance,
    main as evaluate_main,
)
from v2.g1_integration.prepare_g1_fork import apply_g1_overlay, apply_ntk_cleanroom_scanner_layer
from v2.g1_integration.run_g1_demo import run_demo_suite
from v2.triage import demo_queue
from v2.triage.evidence import digest, strict_json


def _find_opengrep_binary() -> str | None:
    env_bin = os.environ.get("OPENGREP_BINARY")
    if env_bin and shutil.which(env_bin):
        return env_bin
    found = shutil.which("opengrep")
    if found:
        return found
    cli_root = Path.home() / ".opengrep" / "cli"
    if cli_root.is_dir():
        for exe_name in ("opengrep.exe", "opengrep"):
            matches = sorted(cli_root.glob(f"*/{exe_name}"), reverse=True)
            if matches:
                return str(matches[0])
    return None


def _build_prepared_fork(dest_dir: Path) -> Path:
    source = dest_dir / "source"
    (source / "semgrepai").mkdir(parents=True, exist_ok=True)
    upstream_base = REPO_ROOT / "v2" / "baseline" / "upstream"
    for name in ("LICENSE", "pyproject.toml", "semgrepai.yml"):
        shutil.copy2(upstream_base / name, source / name)
    for mod in ("cli.py", "config.py", "scanner.py"):
        shutil.copy2(upstream_base / "semgrepai" / mod, source / "semgrepai" / mod)
    (source / "semgrepai" / "__main__.py").write_text(
        "from .cli import app\nif __name__ == '__main__':\n    app()\n",
        encoding="utf-8",
    )
    apply_ntk_cleanroom_scanner_layer(source)
    apply_g1_overlay(source, dest_dir)
    (dest_dir / "g1_repo_binding.json").write_text(
        json.dumps({"repo_root": str(REPO_ROOT)}, indent=2),
        encoding="utf-8",
    )
    return source


def _run_cli(prepared_source: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join([str(prepared_source), str(REPO_ROOT)])
    env["NTK_G1_REPO_ROOT"] = str(REPO_ROOT)
    env["PYTHONUTF8"] = "1"
    return subprocess.run(
        [sys.executable, "-X", "utf8", "-B", "-m", "semgrepai", *args],
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def _dir_inventory(root: Path) -> dict[str, tuple[int, str]]:
    inv: dict[str, tuple[int, str]] = {}
    for cur, _, files in os.walk(root):
        cur_p = Path(cur)
        for fn in sorted(files):
            fp = cur_p / fn
            raw = fp.read_bytes()
            inv[fp.relative_to(root).as_posix()] = (len(raw), digest(raw))
    return inv


class R03AllowlistedProposalTests(unittest.TestCase):
    def setUp(self):
        self.opengrep = _find_opengrep_binary()
        if not self.opengrep:
            self.skipTest("OpenGrep binary not available on test host")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tmp_root = Path(self.tmp.name).resolve()
        self.prepared_source = _build_prepared_fork(self.tmp_root / "prepared_fork")
        self.rules = REPO_ROOT / "v2" / "g1_integration" / "rules" / "java_g1_cwe22_cwe89.yml"
        self.fixtures = REPO_ROOT / "v2" / "g1_integration" / "demo_fixtures"
        self.allowq = self.fixtures / "AllowlistedQuery.java"

    def _start_mock_server(self, *, allowq_mode: str = "valid_refuted"):
        """Start loopback HTTP mock Ollama (`SCRIPTED_TEST_ONLY`)."""

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                if self.path == "/api/tags":
                    raw = b'{"models":[{"name":"qwen3.5:9b-q4_K_M","digest":"mockdigest","size":100}]}'
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                else:
                    self.send_error(404)

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                req_doc = json.loads(self.rfile.read(length).decode("utf-8"))
                user_ev = json.loads(req_doc["messages"][1]["content"])
                snip = user_ev["snippets"][0]
                rel_path = snip["path"]
                snap_sha = snip["sha256"]
                line_map = {ln["line"]: ln["text"] for ln in snip["lines"]}
                sink_ln = user_ev["start"]["line"]

                if "Demo1TruePositive.java" in rel_path:
                    ans = {
                        "status": "SUPPORTED",
                        "explanation": "SCRIPTED_TEST_ONLY: untrusted parameter reaches sink.",
                        "citations": [{
                            "path": rel_path,
                            "start_line": sink_ln,
                            "end_line": sink_ln,
                            "quote": line_map[sink_ln],
                            "sha256": snap_sha,
                        }],
                        "fix_suggestion": "SCRIPTED_TEST_ONLY: parameterize or validate input.",
                    }
                elif "Demo2ProtectedFalsePositive.java" in rel_path:
                    g_lines = [
                        ln for ln in sorted(line_map)
                        if "getCanonicalPath" in line_map[ln] or 'startsWith("/srv/reports/")' in line_map[ln]
                    ]
                    ans = {
                        "status": "REFUTED",
                        "explanation": "SCRIPTED_TEST_ONLY: historical Demo2 canonical path check.",
                        "citations": [{
                            "path": rel_path,
                            "start_line": min(g_lines),
                            "end_line": max(g_lines),
                            "quote": "\n".join(line_map[i] for i in range(min(g_lines), max(g_lines) + 1)),
                            "sha256": snap_sha,
                        }],
                        "fix_suggestion": "",
                    }
                elif "AllowlistedQuery.java" in rel_path:
                    if allowq_mode == "bad_citation":
                        ans = {
                            "status": "REFUTED",
                            "explanation": "SCRIPTED_TEST_ONLY: bad path citation.",
                            "citations": [{
                                "path": "/forged/" + rel_path,
                                "start_line": sink_ln,
                                "end_line": sink_ln,
                                "quote": line_map[sink_ln],
                                "sha256": snap_sha,
                            }],
                            "fix_suggestion": "",
                        }
                    elif allowq_mode == "supported_wrong":
                        ans = {
                            "status": "SUPPORTED",
                            "explanation": "SCRIPTED_TEST_ONLY: wrong status polarity.",
                            "citations": [{
                                "path": rel_path,
                                "start_line": sink_ln,
                                "end_line": sink_ln,
                                "quote": line_map[sink_ln],
                                "sha256": snap_sha,
                            }],
                            "fix_suggestion": "",
                        }
                    elif allowq_mode == "valid_undetermined":
                        ans = {
                            "status": "UNDETERMINED",
                            "explanation": "SCRIPTED_TEST_ONLY: valid model abstention without coercion.",
                            "citations": [],
                            "fix_suggestion": "SCRIPTED_TEST_ONLY: review helper or allowlist boundary.",
                        }
                    elif allowq_mode == "malformed":
                        body = b'{"done":true,"model":"qwen3.5:9b-q4_K_M","message":{"role":"assistant","content":"{truncated"}}'
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                        return
                    else:
                        guard_ln = next(ln for ln, txt in sorted(line_map.items()) if "SELECT 1" in txt)
                        throw_ln = guard_ln + 1
                        ans = {
                            "status": "REFUTED",
                            "explanation": "SCRIPTED_TEST_ONLY: only exact literal SELECT 1 passes before executeQuery.",
                            "citations": [{
                                "path": rel_path,
                                "start_line": guard_ln,
                                "end_line": throw_ln,
                                "quote": f"{line_map[guard_ln]}\n{line_map[throw_ln]}",
                                "sha256": snap_sha,
                            }],
                            "fix_suggestion": "",
                        }
                else:
                    ans = {
                        "status": "UNDETERMINED",
                        "explanation": "SCRIPTED_TEST_ONLY: external helper missing.",
                        "citations": [{
                            "path": rel_path,
                            "start_line": sink_ln,
                            "end_line": sink_ln,
                            "quote": line_map[sink_ln],
                            "sha256": snap_sha,
                        }],
                        "fix_suggestion": "SCRIPTED_TEST_ONLY: inspect external helper.",
                    }

                body = json.dumps({
                    "mock_test_fixture": True,
                    "done": True,
                    "done_reason": "stop",
                    "model": "qwen3.5:9b-q4_K_M",
                    "message": {"role": "assistant", "content": json.dumps(ans, ensure_ascii=False)},
                }, ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        self.addCleanup(lambda: (srv.shutdown(), srv.server_close(), th.join(timeout=2)))
        return f"http://127.0.0.1:{srv.server_port}"

    def test_01_fixture_reuses_demo_queue_triggers_opengrep_and_no_llm_stays_open(self):
        src = self.allowq.read_text(encoding="utf-8")
        for expected_line in (
            'String query = req.getParameter("q");',
            'if (!"SELECT 1".equals(query)) {',
            'throw new IllegalArgumentException("Only SELECT 1 is allowed");',
            "stmt.executeQuery(query);",
        ):
            self.assertIn(expected_line, demo_queue.SAFE_JAVA)
            self.assertIn(expected_line, src)

        out_dir = self.tmp_root / "allowq_no_llm"
        res = _run_cli(self.prepared_source, [
            "scan", str(self.allowq),
            "--rules-path", str(self.rules),
            "--output-dir", str(out_dir),
            "--executable", self.opengrep,
            "--local-triage",
            "--no-llm",
        ])
        self.assertEqual(res.returncode, 0, res.stderr)
        ev = strict_json((out_dir / "triage" / "evidence.json").read_text(encoding="utf-8"))
        self.assertEqual(len(ev["records"]), 1)
        rec = ev["records"][0]
        self.assertTrue(any("CWE-89" in str(c) for c in rec["cwe"]))
        self.assertEqual(rec["rule_id"].endswith("ntk.g1.java.cwe89.sql-injection"), True)

        rows = [strict_json(ln) for ln in (out_dir / "triage" / "assessments.jsonl").read_text(encoding="utf-8").splitlines() if ln.strip()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["assessment"]["status"], "UNDETERMINED")
        self.assertEqual(rows[0]["state"], "OPEN")

        db_path = str(out_dir / "triage" / "review.sqlite")
        q_init = json.loads(_run_cli(self.prepared_source, ["queue", "--db", db_path]).stdout)
        self.assertEqual(len(q_init["warnings"]), 1)
        self.assertEqual(q_init["warnings"][0]["state"], "OPEN")

    def test_02_allowlisted_query_refuted_never_auto_dismisses_and_lifecycle_plus_stale_source(self):
        # 1) Valid mock REFUTED stays OPEN before human decision; queue hide/restore/history works
        endpoint = self._start_mock_server(allowq_mode="valid_refuted")
        out_dir = self.tmp_root / "allowq_mock_valid"
        res = _run_cli(self.prepared_source, [
            "scan", str(self.allowq),
            "--rules-path", str(self.rules),
            "--output-dir", str(out_dir),
            "--executable", self.opengrep,
            "--local-triage",
            "--endpoint", endpoint,
            "--model", "qwen3.5:9b-q4_K_M",
            "--prompt-contract", "blind",
            "--runtime-origin", "mock",
        ])
        self.assertEqual(res.returncode, 0, res.stderr)
        rows = [strict_json(ln) for ln in (out_dir / "triage" / "assessments.jsonl").read_text(encoding="utf-8").splitlines() if ln.strip()]
        asmt = rows[0]["assessment"]
        self.assertEqual(asmt["status"], "REFUTED")
        self.assertEqual(asmt["validated_status"], "REFUTED")
        self.assertFalse(asmt["validator_downgraded"])
        self.assertEqual(asmt["failure_kind"], "NONE")
        self.assertEqual(asmt["citation_check"], "MATCHED")
        self.assertEqual(rows[0]["state"], "OPEN")

        db_path = str(out_dir / "triage" / "review.sqlite")
        q0 = json.loads(_run_cli(self.prepared_source, ["queue", "--db", db_path]).stdout)
        wid = q0["warnings"][0]["id"]
        self.assertEqual(q0["warnings"][0]["state"], "OPEN")

        self.assertEqual(_run_cli(self.prepared_source, [
            "confirm-false", wid, "--db", db_path,
            "--actor", "SCRIPTED_TEST_ONLY-reviewer",
            "--reason", "SCRIPTED_TEST_ONLY: verified in-memory SELECT 1 allowlist",
        ]).returncode, 0)
        q_hidden = json.loads(_run_cli(self.prepared_source, ["queue", "--db", db_path]).stdout)
        q_all = json.loads(_run_cli(self.prepared_source, ["queue", "--db", db_path, "--all"]).stdout)
        self.assertEqual(q_hidden["warnings"], [])
        self.assertEqual(len(q_all["warnings"]), 1)
        self.assertEqual(q_all["warnings"][0]["state"], "CONFIRMED_FALSE")

        self.assertEqual(_run_cli(self.prepared_source, [
            "reopen", wid, "--db", db_path,
            "--actor", "SCRIPTED_TEST_ONLY-lead",
            "--reason", "SCRIPTED_TEST_ONLY: verify reopen restores OPEN queue visibility",
        ]).returncode, 0)
        q_reopened = json.loads(_run_cli(self.prepared_source, ["queue", "--db", db_path]).stdout)
        self.assertEqual([w["state"] for w in q_reopened["warnings"]], ["OPEN"])
        hist = json.loads(_run_cli(self.prepared_source, ["history", wid, "--db", db_path]).stdout)
        self.assertEqual([h["action"] for h in hist], ["confirm-false", "reopen"])
        self.assertTrue(all(h["actor"].startswith("SCRIPTED_TEST_ONLY-") and h["reason"] and h["timestamp"] for h in hist))

        # 2) Malformed/missing LLM evidence degrades cleanly to UNDETERMINED + OPEN
        bad_endpoint = self._start_mock_server(allowq_mode="malformed")
        bad_dir = self.tmp_root / "allowq_malformed"
        res_bad = _run_cli(self.prepared_source, [
            "scan", str(self.allowq),
            "--rules-path", str(self.rules),
            "--output-dir", str(bad_dir),
            "--executable", self.opengrep,
            "--local-triage",
            "--endpoint", bad_endpoint,
            "--model", "qwen3.5:9b-q4_K_M",
            "--prompt-contract", "blind",
            "--runtime-origin", "mock",
        ])
        self.assertEqual(res_bad.returncode, 0, res_bad.stderr)
        bad_rows = [strict_json(ln) for ln in (bad_dir / "triage" / "assessments.jsonl").read_text(encoding="utf-8").splitlines() if ln.strip()]
        self.assertEqual(bad_rows[0]["assessment"]["validated_status"], "UNDETERMINED")
        self.assertEqual(bad_rows[0]["state"], "OPEN")

        # 3) Mutable copy source drift triggers STALE_SOURCE exit 2 & preserves OPEN state
        mut_dir = self.tmp_root / "allowq_stale_src"
        mut_dir.mkdir()
        mut_java = mut_dir / "AllowlistedQuery.java"
        shutil.copy2(self.allowq, mut_java)
        stale_out = self.tmp_root / "allowq_stale_out"
        self.assertEqual(_run_cli(self.prepared_source, [
            "scan", str(mut_java),
            "--rules-path", str(self.rules),
            "--output-dir", str(stale_out),
            "--executable", self.opengrep,
            "--local-triage", "--no-llm",
        ]).returncode, 0)
        stale_db = str(stale_out / "triage" / "review.sqlite")
        stale_id = json.loads(_run_cli(self.prepared_source, ["queue", "--db", stale_db]).stdout)["warnings"][0]["id"]
        mut_java.write_text(mut_java.read_text(encoding="utf-8") + "\n// STALE_SOURCE drift test\n", encoding="utf-8")
        refused = _run_cli(self.prepared_source, [
            "confirm-false", stale_id, "--db", stale_db,
            "--actor", "SCRIPTED_TEST_ONLY-reviewer",
            "--reason", "SCRIPTED_TEST_ONLY: should fail with STALE_SOURCE",
        ])
        self.assertEqual(refused.returncode, 2)
        self.assertIn("STALE_SOURCE", refused.stderr)
        hist_rej = json.loads(_run_cli(self.prepared_source, [
            "history", stale_id, "--db", stale_db, "--include-rejected",
        ]).stdout)
        self.assertEqual(hist_rej["events"], [])
        self.assertEqual(len(hist_rej["rejected_decisions"]), 1)
        self.assertEqual(hist_rej["rejected_decisions"][0]["rejection_code"], "STALE_SOURCE")

    def _build_full_proposed_run(
        self,
        run_root: Path,
        endpoint: str,
        *,
        dismiss_demo2: bool = False,
        op_actor: str = "SCRIPTED_TEST_ONLY-op",
        lead_actor: str = "SCRIPTED_TEST_ONLY-lead",
        reason_prefix: str = "SCRIPTED_TEST_ONLY",
    ):
        m1_dir = run_root / "m1_scan_only"
        self.assertEqual(_run_cli(self.prepared_source, [
            "scan", str(self.fixtures / "Demo1TruePositive.java"),
            "--rules-path", str(self.rules),
            "--output-dir", str(m1_dir),
            "--executable", self.opengrep,
            "--scan-only",
        ]).returncode, 0)

        d1_dir = run_root / "demo1_true_positive"
        d2_dir = run_root / "demo2_protected_fp"
        d3a_dir = run_root / "demo3a_missing_helper"
        allowq_dir = run_root / "allowlisted_query_fp"
        for src_java, out_d in (
            (self.fixtures / "Demo1TruePositive.java", d1_dir),
            (self.fixtures / "Demo2ProtectedFalsePositive.java", d2_dir),
            (self.fixtures / "Demo3ExternalHelperUndetermined.java", d3a_dir),
            (self.allowq, allowq_dir),
        ):
            r = _run_cli(self.prepared_source, [
                "scan", str(src_java),
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

        # Demo1: confirm-true one warning, second stays OPEN
        d1_db = str(d1_dir / "triage" / "review.sqlite")
        d1_id = json.loads(_run_cli(self.prepared_source, ["queue", "--db", d1_db]).stdout)["warnings"][0]["id"]
        self.assertEqual(_run_cli(self.prepared_source, [
            "confirm-true", d1_id, "--db", d1_db,
            "--actor", op_actor,
            "--reason", f"{reason_prefix}: confirmed TP",
        ]).returncode, 0)

        # Optional negative condition: accidentally confirming Demo2
        if dismiss_demo2:
            d2_db = str(d2_dir / "triage" / "review.sqlite")
            d2_id = json.loads(_run_cli(self.prepared_source, ["queue", "--db", d2_db]).stdout)["warnings"][0]["id"]
            self.assertEqual(_run_cli(self.prepared_source, [
                "confirm-false", d2_id, "--db", d2_db,
                "--actor", op_actor,
                "--reason", f"{reason_prefix}: negative violation",
            ]).returncode, 0)

        # AllowlistedQuery: confirm-false -> snapshot -> reopen -> OPEN
        aq_db = str(allowq_dir / "triage" / "review.sqlite")
        aq_id = json.loads(_run_cli(self.prepared_source, ["queue", "--db", aq_db]).stdout)["warnings"][0]["id"]
        self.assertEqual(_run_cli(self.prepared_source, [
            "confirm-false", aq_id, "--db", aq_db,
            "--actor", op_actor,
            "--reason", f"{reason_prefix}: verified literal SELECT 1 allowlist",
        ]).returncode, 0)
        shutil.copy2(allowq_dir / "triage" / "review.sqlite", allowq_dir / "triage" / "review.after_confirm_false.sqlite")
        self.assertEqual(_run_cli(self.prepared_source, [
            "reopen", aq_id, "--db", aq_db,
            "--actor", lead_actor,
            "--reason", f"{reason_prefix}: verified reopen lifecycle",
        ]).returncode, 0)

        aux_dir = run_root / "aux_controls"
        run_demo_suite(
            prepared_source=self.prepared_source,
            output_dir=aux_dir,
            executable=self.opengrep,
            auxiliary_controls_only=True,
        )
        return m1_dir, d1_dir, d2_dir, allowq_dir, d3a_dir, aux_dir / "demo3b_malformed_llm_synthetic_mock", aux_dir / "demo4_stale_source"

    def test_03_evaluator_proposed_allowlisted_fp_mode_and_counterexamples(self):
        endpoint = self._start_mock_server(allowq_mode="valid_refuted")
        run_root = self.tmp_root / "proposed_valid"
        m1_dir, d1_dir, d2_dir, aq_dir, d3a_dir, d3b_dir, d4_dir = self._build_full_proposed_run(run_root, endpoint)

        # Default locked-demo2 remains untouched & rejects untouched Demo2
        locked_rep = evaluate_acceptance(
            demo1_dir=d1_dir, demo2_dir=d2_dir, demo3a_dir=d3a_dir,
            m1_dir=m1_dir, demo4_dir=d4_dir, demo3b_dir=d3b_dir,
            allow_mock_primary=True,
        )
        self.assertEqual(locked_rep["r03_fp_mode"], "locked-demo2")
        self.assertEqual(locked_rep["criteria"]["R03"]["status"], "FAIL")

        # Without allow_mock_primary=True, non-scripted operator actors on mock HTTP stay BLOCKED (not FAIL or PASS)
        clean_mock_root = self.tmp_root / "proposed_clean_mock_blocked"
        m1_b, d1_b, d2_b, aq_b, d3a_b, d3b_b, d4_b = self._build_full_proposed_run(
            clean_mock_root,
            endpoint,
            op_actor="acceptance-operator",
            lead_actor="acceptance-reviewer",
            reason_prefix="Acceptance operator review",
        )
        blocked_rep = evaluate_acceptance(
            demo1_dir=d1_b, demo2_dir=d2_b, demo3a_dir=d3a_b,
            m1_dir=m1_b, demo4_dir=d4_b, demo3b_dir=d3b_b,
            allowlisted_fp_dir=aq_b,
            allowlisted_trusted_source_root=self.fixtures,
            r03_fp_mode="proposed-allowlisted-fp",
            allow_mock_primary=False,
        )
        self.assertEqual(blocked_rep["overall_status"], "BLOCKED")
        self.assertEqual(blocked_rep["criteria"]["R01"]["status"], "BLOCKED")
        self.assertEqual(blocked_rep["criteria"]["R03"]["status"], "BLOCKED")

        # Without allow_mock_primary=True, SCRIPTED_TEST_ONLY events MUST trigger R03 FAIL (never PASS)
        scripted_official_rep = evaluate_acceptance(
            demo1_dir=d1_dir, demo2_dir=d2_dir, demo3a_dir=d3a_dir,
            m1_dir=m1_dir, demo4_dir=d4_dir, demo3b_dir=d3b_dir,
            allowlisted_fp_dir=aq_dir,
            allowlisted_trusted_source_root=self.fixtures,
            r03_fp_mode="proposed-allowlisted-fp",
            allow_mock_primary=False,
        )
        self.assertEqual(scripted_official_rep["criteria"]["R03"]["status"], "FAIL")
        self.assertEqual(scripted_official_rep["overall_status"], "FAIL")

        before_inv = {
            name: _dir_inventory(p)
            for name, p in (("m1", m1_dir), ("d1", d1_dir), ("d2", d2_dir), ("aq", aq_dir), ("d3a", d3a_dir), ("d3b", d3b_dir), ("d4", d4_dir))
        }
        eval_out = run_root / "audit" / "proposed_eval.json"
        rc = evaluate_main([
            "--demo1-dir", str(d1_dir),
            "--demo2-dir", str(d2_dir),
            "--demo3a-dir", str(d3a_dir),
            "--m1-dir", str(m1_dir),
            "--demo3b-dir", str(d3b_dir),
            "--demo4-dir", str(d4_dir),
            "--r03-fp-mode", "proposed-allowlisted-fp",
            "--allowlisted-fp-dir", str(aq_dir),
            "--allowlisted-trusted-source-root", str(self.fixtures),
            "--output", str(eval_out),
            "--allow-mock-primary",
        ])
        self.assertEqual(rc, 0)
        after_inv = {
            name: _dir_inventory(p)
            for name, p in (("m1", m1_dir), ("d1", d1_dir), ("d2", d2_dir), ("aq", aq_dir), ("d3a", d3a_dir), ("d3b", d3b_dir), ("d4", d4_dir))
        }
        self.assertEqual(before_inv, after_inv, "proposed evaluator mode must remain 100% read-only")
        rep = strict_json(eval_out.read_text(encoding="utf-8"))
        self.assertEqual(rep["overall_status"], "PASS")
        self.assertEqual(rep["r03_fp_mode"], "proposed-allowlisted-fp")
        self.assertEqual(rep["proposed_contract_status"], "PROPOSED_AWAITING_OPERATOR_APPROVAL")
        self.assertEqual(rep["real_qwen_denominator"]["expected"], 4)
        self.assertEqual(rep["real_qwen_denominator"]["observed"], 4)
        self.assertEqual(rep["real_qwen_denominator"]["historical_g1_c5_expected"], 4)
        self.assertNotIn("allowlisted_query_fp_control", rep["real_qwen_denominator"]["breakdown"])
        self.assertIn("allowlisted_query_fp_control", rep["real_qwen_denominator"]["excluded_auxiliary_controls"])
        supp = rep["supplementary_r03_control"]
        self.assertEqual(supp["run_separation"], "SEPARATE_SUPPLEMENTARY_RUN_NOT_MERGED_WITH_G1_C5_PRIMARY_4")
        self.assertFalse(supp["merged_with_g1_c5_session"])
        self.assertEqual(supp["raw_model_status"], "REFUTED")
        self.assertEqual(supp["validated_status"], "REFUTED")
        self.assertEqual(supp["model_fp_concurrence"], "CONCURRED_REFUTED")
        self.assertTrue(supp["qwen_concurred_fp"])
        self.assertEqual(supp["run_provenance"]["scenario_dir_name"], "allowlisted_query_fp")
        self.assertEqual(rep["actor_identity_model"]["mechanism"], "LOCAL_UNAUTHENTICATED_OPERATOR_IDENTIFIER")
        self.assertFalse(rep["actor_identity_model"]["cryptographic_identity_verified"])

        # Counterexample 1: Wrong fixture (Demo2) passed to --allowlisted-fp-dir -> R01 stays PASS, R03 FAIL
        wrong_fix_rep = evaluate_acceptance(
            demo1_dir=d1_dir, demo2_dir=d2_dir, demo3a_dir=d3a_dir,
            m1_dir=m1_dir, demo4_dir=d4_dir, demo3b_dir=d3b_dir,
            allowlisted_fp_dir=d2_dir,
            allowlisted_trusted_source_root=self.fixtures,
            r03_fp_mode="proposed-allowlisted-fp",
            allow_mock_primary=True,
        )
        self.assertEqual(wrong_fix_rep["criteria"]["R01"]["status"], "PASS")
        self.assertEqual(wrong_fix_rep["criteria"]["R03"]["status"], "FAIL")
        self.assertEqual(wrong_fix_rep["overall_status"], "FAIL")

        # Counterexample 2: Missing review.after_confirm_false.sqlite -> R03 FAIL (R01 PASS)
        af_path = aq_dir / "triage" / "review.after_confirm_false.sqlite"
        af_bytes = af_path.read_bytes()
        try:
            af_path.unlink()
            no_af_rep = evaluate_acceptance(
                demo1_dir=d1_dir, demo2_dir=d2_dir, demo3a_dir=d3a_dir,
                m1_dir=m1_dir, demo4_dir=d4_dir, demo3b_dir=d3b_dir,
                allowlisted_fp_dir=aq_dir,
                allowlisted_trusted_source_root=self.fixtures,
                r03_fp_mode="proposed-allowlisted-fp",
                allow_mock_primary=True,
            )
            self.assertEqual(no_af_rep["criteria"]["R01"]["status"], "PASS")
            self.assertEqual(no_af_rep["criteria"]["R03"]["status"], "FAIL")
        finally:
            af_path.write_bytes(af_bytes)

        # Counterexample 3: Demo2 dismissed under proposed mode -> R03 FAIL
        dismiss_root = self.tmp_root / "neg_demo2_dismissed"
        m1_d, d1_d, d2_d, aq_d, d3a_d, d3b_d, d4_d = self._build_full_proposed_run(dismiss_root, endpoint, dismiss_demo2=True)
        d2_dismissed_rep = evaluate_acceptance(
            demo1_dir=d1_d, demo2_dir=d2_d, demo3a_dir=d3a_d,
            m1_dir=m1_d, demo4_dir=d4_d, demo3b_dir=d3b_d,
            allowlisted_fp_dir=aq_d,
            allowlisted_trusted_source_root=self.fixtures,
            r03_fp_mode="proposed-allowlisted-fp",
            allow_mock_primary=True,
        )
        self.assertEqual(d2_dismissed_rep["criteria"]["R03"]["status"], "FAIL")

        # Counterexample 4: AllowlistedQuery returned bad citation -> R01 & R02 remain PASS, R03 & overall FAIL
        bad_cite_ep = self._start_mock_server(allowq_mode="bad_citation")
        bad_cite_root = self.tmp_root / "neg_bad_citation"
        m1_c, d1_c, d2_c, aq_c, d3a_c, d3b_c, d4_c = self._build_full_proposed_run(bad_cite_root, bad_cite_ep)
        bad_cite_rep = evaluate_acceptance(
            demo1_dir=d1_c, demo2_dir=d2_c, demo3a_dir=d3a_c,
            m1_dir=m1_c, demo4_dir=d4_c, demo3b_dir=d3b_c,
            allowlisted_fp_dir=aq_c,
            allowlisted_trusted_source_root=self.fixtures,
            r03_fp_mode="proposed-allowlisted-fp",
            allow_mock_primary=True,
        )
        self.assertEqual(bad_cite_rep["criteria"]["R01"]["status"], "PASS")
        self.assertEqual(bad_cite_rep["criteria"]["R02"]["status"], "PASS")
        self.assertEqual(bad_cite_rep["criteria"]["R03"]["status"], "FAIL")
        self.assertEqual(bad_cite_rep["overall_status"], "FAIL")
        self.assertEqual(bad_cite_rep["supplementary_r03_control"]["model_fp_concurrence"], "EVIDENCE_OR_CONTRACT_FAILURE")

        # Counterexample 5: CLI rejects invalid flag combinations
        with self.assertRaises(SystemExit) as cm1:
            evaluate_main([
                "--demo1-dir", str(d1_dir), "--demo2-dir", str(d2_dir), "--demo3a-dir", str(d3a_dir),
                "--m1-dir", str(m1_dir), "--demo4-dir", str(d4_dir),
                "--r03-fp-mode", "proposed-allowlisted-fp",
                "--output", str(run_root / "audit" / "cli_err1.json"),
            ])
        self.assertEqual(cm1.exception.code, 2)
        with self.assertRaises(SystemExit) as cm2:
            evaluate_main([
                "--demo1-dir", str(d1_dir), "--demo2-dir", str(d2_dir), "--demo3a-dir", str(d3a_dir),
                "--m1-dir", str(m1_dir), "--demo4-dir", str(d4_dir),
                "--allowlisted-fp-dir", str(aq_dir),
                "--output", str(run_root / "audit" / "cli_err2.json"),
            ])
        self.assertEqual(cm2.exception.code, 2)

    def test_04_supplementary_supported_and_undetermined_preserve_r01_without_coercion(self):
        cases = (
            ("supported_wrong", "SUPPORTED", "DISAGREED_SUPPORTED"),
            ("valid_undetermined", "UNDETERMINED", "ABSTAINED_UNDETERMINED"),
        )
        for mode_name, expected_status, expected_concurrence in cases:
            with self.subTest(allowq_mode=mode_name):
                ep = self._start_mock_server(allowq_mode=mode_name)
                root = self.tmp_root / f"non_refuted_{mode_name}"
                m1_d, d1_d, d2_d, aq_d, d3a_d, d3b_d, d4_d = self._build_full_proposed_run(root, ep)
                rep = evaluate_acceptance(
                    demo1_dir=d1_d, demo2_dir=d2_d, demo3a_dir=d3a_d,
                    m1_dir=m1_d, demo4_dir=d4_d, demo3b_dir=d3b_d,
                    allowlisted_fp_dir=aq_d,
                    allowlisted_trusted_source_root=self.fixtures,
                    r03_fp_mode="proposed-allowlisted-fp",
                    allow_mock_primary=True,
                )
                self.assertEqual(rep["criteria"]["R01"]["status"], "PASS")
                self.assertEqual(rep["criteria"]["R02"]["status"], "PASS")
                self.assertEqual(rep["criteria"]["R03"]["status"], "PASS")
                self.assertEqual(rep["overall_status"], "PASS")
                self.assertEqual(rep["real_qwen_denominator"]["expected"], 4)
                self.assertEqual(rep["real_qwen_denominator"]["observed"], 4)
                supp = rep["supplementary_r03_control"]
                self.assertEqual(supp["raw_model_status"], expected_status)
                self.assertEqual(supp["validated_status"], expected_status)
                self.assertEqual(supp["model_fp_concurrence"], expected_concurrence)
                self.assertFalse(supp["qwen_concurred_fp"])
                self.assertIn("did not concur" if expected_status == "SUPPORTED" else "abstained", supp["acceptance_impact"])

        # Malformed LLM JSON on supplementary run still fails closed in R03 while keeping R01/R02 PASS
        mal_ep = self._start_mock_server(allowq_mode="malformed")
        mal_root = self.tmp_root / "malformed_supp"
        m1_m, d1_m, d2_m, aq_m, d3a_m, d3b_m, d4_m = self._build_full_proposed_run(mal_root, mal_ep)
        mal_rep = evaluate_acceptance(
            demo1_dir=d1_m, demo2_dir=d2_m, demo3a_dir=d3a_m,
            m1_dir=m1_m, demo4_dir=d4_m, demo3b_dir=d3b_m,
            allowlisted_fp_dir=aq_m,
            allowlisted_trusted_source_root=self.fixtures,
            r03_fp_mode="proposed-allowlisted-fp",
            allow_mock_primary=True,
        )
        self.assertEqual(mal_rep["criteria"]["R01"]["status"], "PASS")
        self.assertEqual(mal_rep["criteria"]["R02"]["status"], "PASS")
        self.assertEqual(mal_rep["criteria"]["R03"]["status"], "FAIL")
        self.assertEqual(mal_rep["overall_status"], "FAIL")

    def test_05_scripted_mock_replay_rejected_when_official_allowed_when_test_mode(self):
        endpoint = self._start_mock_server(allowq_mode="valid_refuted")
        root = self.tmp_root / "scripted_vs_official"
        m1_d, d1_d, d2_d, aq_d, d3a_d, d3b_d, d4_d = self._build_full_proposed_run(root, endpoint)

        bundle = strict_json((aq_d / "triage" / "evidence.json").read_text(encoding="utf-8"))
        rows = [strict_json(ln) for ln in (aq_d / "triage" / "assessments.jsonl").read_text(encoding="utf-8").splitlines() if ln.strip()]
        s_man = strict_json((aq_d / "capture" / "scan-manifest.json").read_text(encoding="utf-8"))
        r_man = strict_json((aq_d / "g1-run-manifest.json").read_text(encoding="utf-8"))
        db_state = _read_sqlite_state_ro(aq_d / "triage" / "review.sqlite")

        self.assertEqual(
            _verify_sqlite_against_triage(
                "scripted_allowed",
                db_state,
                bundle,
                rows,
                scan_manifest=s_man,
                run_manifest=r_man,
                allow_scripted_events=True,
            ),
            [],
        )
        default_errs = _verify_sqlite_against_triage(
            "official_rejects_scripted",
            db_state,
            bundle,
            rows,
            scan_manifest=s_man,
            run_manifest=r_man,
        )
        self.assertTrue(any("scripted/mock/replay" in e for e in default_errs), default_errs)

        # Normal baseline test-operator / test-lead or real operator remains valid; mock/replay markers fail
        clean_state = json.loads(json.dumps(db_state))
        for idx, ev in enumerate(clean_state["events"]):
            ev["actor"] = "test-operator" if idx == 0 else "test-lead"
            ev["reason"] = "Verified in-memory allowlist guard cleanly."
        self.assertEqual(
            _verify_sqlite_against_triage(
                "clean_baseline",
                clean_state,
                bundle,
                rows,
                scan_manifest=s_man,
                run_manifest=r_man,
            ),
            [],
        )
        for bad_actor, bad_reason in (
            ("mock-reviewer", "looks safe"),
            ("operator-1", "REPLAY: copied prior verdict"),
            ("SCRIPTED_TEST_ONLY", "SCRIPTED_TEST_ONLY: not an approved human decision"),
        ):
            mut_state = json.loads(json.dumps(clean_state))
            mut_state["events"][0]["actor"] = bad_actor
            mut_state["events"][0]["reason"] = bad_reason
            errs = _verify_sqlite_against_triage(
                "bad_marker",
                mut_state,
                bundle,
                rows,
                scan_manifest=s_man,
                run_manifest=r_man,
            )
            self.assertTrue(errs, f"expected rejection for actor={bad_actor!r}, reason={bad_reason!r}")

        # Official locked-demo2 also rejects SCRIPTED_TEST_ONLY events on Demo1 when allow_mock_primary=False
        locked_scripted_rep = evaluate_acceptance(
            demo1_dir=d1_d, demo2_dir=d2_d, demo3a_dir=d3a_d,
            m1_dir=m1_d, demo4_dir=d4_d, demo3b_dir=d3b_d,
            r03_fp_mode="locked-demo2",
            allow_mock_primary=False,
        )
        self.assertEqual(locked_scripted_rep["criteria"]["R03"]["status"], "FAIL")
        self.assertTrue(
            any("non-human/scripted/mock/replay" in e for e in locked_scripted_rep["criteria"]["R03"]["failures"]),
            locked_scripted_rep["criteria"]["R03"]["failures"],
        )

    def test_06_allowlisted_identity_hardening_counterexamples(self):
        endpoint = self._start_mock_server(allowq_mode="valid_refuted")
        root = self.tmp_root / "identity_hardening"
        _, _, _, aq_d, _, _, _ = self._build_full_proposed_run(root, endpoint)
        self.assertEqual(_verify_allowlisted_fp_scenario_identity(aq_d, trusted_source_root=self.fixtures), [])

        base_ev = strict_json((aq_d / "triage" / "evidence.json").read_text(encoding="utf-8"))

        # 1) Filename suffix spoof + log-only branch + missing snapshots (Codex test_05 payload)
        ce1 = self.tmp_root / "id_ce_suffix"
        (ce1 / "triage").mkdir(parents=True, exist_ok=True)
        (ce1 / "triage" / "evidence.json").write_text(json.dumps({
            "records": [{
                "path": "C:/fake/NotAllowlistedQuery.java",
                "cwe": ["CWE-89: SQL Injection"],
                "snippets": [{
                    "lines": [
                        {"line": 1, "text": 'if (!"SELECT 1".equals(query)) { System.out.println("rejected"); }'},
                        {"line": 2, "text": "stmt.executeQuery(query);"},
                    ],
                }],
            }],
        }), encoding="utf-8")
        self.assertTrue(_verify_allowlisted_fp_scenario_identity(ce1, trusted_source_root=self.fixtures))

        # 2) Same basename AllowlistedQuery.java, forged snapshot SHA-256
        ce2 = self.tmp_root / "id_ce_hash"
        (ce2 / "triage").mkdir(parents=True, exist_ok=True)
        ev2 = json.loads(json.dumps(base_ev))
        snap_key = next(iter(ev2["records"][0]["snapshots"]))
        ev2["records"][0]["snapshots"][snap_key]["sha256"] = "0" * 64
        (ce2 / "triage" / "evidence.json").write_text(json.dumps(ev2), encoding="utf-8")
        self.assertTrue(_verify_allowlisted_fp_scenario_identity(ce2, trusted_source_root=self.fixtures))

        # 3) Same basename AllowlistedQuery.java + valid CWE-89, log-only branch instead of throwing guard
        ce3 = self.tmp_root / "id_ce_log_only"
        (ce3 / "triage").mkdir(parents=True, exist_ok=True)
        ev3 = json.loads(json.dumps(base_ev))
        for snip in ev3["records"][0]["snippets"]:
            for ln in snip["lines"]:
                if "throw new IllegalArgumentException" in ln["text"]:
                    ln["text"] = 'System.out.println("rejected");'
        (ce3 / "triage" / "evidence.json").write_text(json.dumps(ev3), encoding="utf-8")
        self.assertTrue(_verify_allowlisted_fp_scenario_identity(ce3, trusted_source_root=self.fixtures))

        # 4) Wrong rule_id even with AllowlistedQuery path
        ce4 = self.tmp_root / "id_ce_rule"
        (ce4 / "triage").mkdir(parents=True, exist_ok=True)
        ev4 = json.loads(json.dumps(base_ev))
        ev4["records"][0]["rule_id"] = "java.custom.wrong-rule"
        (ce4 / "triage" / "evidence.json").write_text(json.dumps(ev4), encoding="utf-8")
        self.assertTrue(_verify_allowlisted_fp_scenario_identity(ce4, trusted_source_root=self.fixtures))

        # 5) Reassigned query bypass between guard closing brace and sink
        ce5 = self.tmp_root / "id_ce_reassign"
        (ce5 / "triage").mkdir(parents=True, exist_ok=True)
        ev5 = json.loads(json.dumps(base_ev))
        for snip in ev5["records"][0]["snippets"]:
            for ln in snip["lines"]:
                if "stmt.executeQuery(query);" in ln["text"]:
                    ln["line"] += 1
            snip["lines"].append({"line": 22, "text": '        query = req.getParameter("q");'})
        (ce5 / "triage" / "evidence.json").write_text(json.dumps(ev5), encoding="utf-8")
        errs5 = _verify_allowlisted_fp_scenario_identity(ce5, trusted_source_root=self.fixtures)
        self.assertTrue(any("without bypass" in e for e in errs5), errs5)

        # 6) Positive & negative CWE-89 exact identifier controls (reject CWE-890/891/189/forged/bad-type)
        for valid_cwe in (
            ["CWE-89"],
            ["CWE-89: SQL Injection"],
            ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"],
        ):
            ce_pos = self.tmp_root / "id_cwe_pos"
            (ce_pos / "triage").mkdir(parents=True, exist_ok=True)
            ev_pos = json.loads(json.dumps(base_ev))
            ev_pos["records"][0]["cwe"] = valid_cwe
            (ce_pos / "triage" / "evidence.json").write_text(json.dumps(ev_pos), encoding="utf-8")
            self.assertEqual(_verify_allowlisted_fp_scenario_identity(ce_pos, trusted_source_root=self.fixtures), [], f"valid cwe={valid_cwe!r} failed")

        for idx_cwe, bad_cwe in enumerate((
            ["CWE-890"],
            ["CWE-891"],
            ["CWE-189"],
            ["CWE-22"],
            ["CWE-890: Similar CWE"],
            ["fake CWE-89"],
            ["CWE-89-bypass"],
            ["CWE-89:"],
            ["CWE-89:   "],
            ["CWE-89: alias CWE-22"],
            ["CWE-89\n"],
            [" CWE-89"],
            ["CWE-89", "CWE-890"],
            [],
            None,
            "CWE-89",
            [89],
            {"cwe": "CWE-89"},
        )):
            with self.subTest(bad_cwe=bad_cwe):
                ce_neg = self.tmp_root / f"id_cwe_neg_{idx_cwe}"
                (ce_neg / "triage").mkdir(parents=True, exist_ok=True)
                ev_neg = json.loads(json.dumps(base_ev))
                if bad_cwe is None:
                    ev_neg["records"][0].pop("cwe", None)
                else:
                    ev_neg["records"][0]["cwe"] = bad_cwe
                (ce_neg / "triage" / "evidence.json").write_text(json.dumps(ev_neg), encoding="utf-8")
                cwe_errs = _verify_allowlisted_fp_scenario_identity(ce_neg, trusted_source_root=self.fixtures)
                self.assertTrue(
                    any("expected exact CWE-89 finding" in e for e in cwe_errs),
                    f"expected CWE-89 rejection for cwe={bad_cwe!r}, got {cwe_errs!r}",
                )

    def test_07_wsl2_path_mapping_and_security_controls(self):
        allow_bytes = self.allowq.read_bytes()
        allow_sha = digest(allow_bytes)

        def _make_wsl_forwarding_wrapper(src_java: Path, wsl_file: str) -> Path:
            bin_dir = self.tmp_root / f"wsl_wrap_{abs(hash((str(src_java), wsl_file)))}"
            bin_dir.mkdir(parents=True, exist_ok=True)
            helper_py = bin_dir / "rewrite_opengrep.py"
            helper_code = "\n".join([
                "import json, pathlib, subprocess, sys",
                f"REAL = {self.opengrep!r}",
                f"TARGET = pathlib.Path({str(src_java)!r}).resolve()",
                f"WSL_FILE = {wsl_file!r}",
                "WSL_URI = 'file://' + WSL_FILE",
                "TARGETS_LOWER = {str(TARGET).lower(), TARGET.as_posix().lower()}",
                "TARGET_URIS_LOWER = {TARGET.as_uri().lower(), 'file://' + TARGET.as_posix().lower()}",
                "def _rewrite(val):",
                "    if isinstance(val, dict):",
                "        return {k: _rewrite(v) for k, v in val.items()}",
                "    if isinstance(val, list):",
                "        return [_rewrite(v) for v in val]",
                "    if isinstance(val, str):",
                "        lo = val.lower()",
                "        if lo in TARGETS_LOWER:",
                "            return WSL_FILE",
                "        if lo in TARGET_URIS_LOWER:",
                "            return WSL_URI",
                "        if val.endswith('AllowlistedQuery.java'):",
                "            norm = val.replace('\\\\', '/')",
                "            if norm.lower().endswith('/allowlistedquery.java') and TARGET.name == 'AllowlistedQuery.java':",
                "                if '://' in norm:",
                "                    return WSL_URI",
                "    return val",
                "args = sys.argv[1:]",
                "proc = subprocess.run([REAL, *args], capture_output=True, text=True, encoding='utf-8')",
                "out_file = None",
                "for idx, tok in enumerate(args):",
                "    if tok in ('-o', '--output') and idx + 1 < len(args):",
                "        out_file = pathlib.Path(args[idx + 1])",
                "    elif tok.startswith('--output='):",
                "        out_file = pathlib.Path(tok.split('=', 1)[1])",
                "if out_file and out_file.is_file():",
                "    txt = out_file.read_text(encoding='utf-8')",
                "    if txt.lstrip().startswith('{'):",
                "        out_file.write_text(json.dumps(_rewrite(json.loads(txt))), encoding='utf-8')",
                "stdout = proc.stdout",
                "if stdout.lstrip().startswith('{'):",
                "    stdout = json.dumps(_rewrite(json.loads(stdout)))",
                "sys.stdout.write(stdout)",
                "sys.stderr.write(proc.stderr)",
                "raise SystemExit(proc.returncode)",
            ])
            helper_py.write_text(helper_code + "\n", encoding="utf-8")
            if os.name == "nt":
                wrapper = bin_dir / "opengrep_wsl_allowq.cmd"
                wrapper.write_text(
                    f'@echo off\r\n"{sys.executable}" "{helper_py}" %*\r\n',
                    encoding="utf-8",
                )
            else:
                wrapper = bin_dir / "opengrep_wsl_allowq"
                wrapper.write_text(
                    f'#!/usr/bin/env sh\nexec "{sys.executable}" "{helper_py}" "$@"\n',
                    encoding="utf-8",
                )
                os.chmod(wrapper, 0o755)
            return wrapper

        def _to_wsl(p: Path) -> str:
            res = p.resolve()
            if res.drive:
                drv = res.drive[0].lower()
                rel_p = res.relative_to(res.anchor).as_posix().strip("/")
                return f"/mnt/{drv}/{rel_p}"
            return f"/mnt/host/{res.as_posix().strip('/')}"

        # Case 1 + Case 8 first: real CLI scan producing genuine OpenGrep evidence + WSL2 E2E SUPPORTED evaluation
        ep = self._start_mock_server(allowq_mode="supported_wrong")
        e2e_root = self.tmp_root / "wsl2_e2e_supported"
        m1_d, d1_d, d2_d, native_aq_d, d3a_d, d3b_d, d4_d = self._build_full_proposed_run(e2e_root, ep)

        wsl_cand_root = self.tmp_root / "candidates" / "g1-r03-wsl-acceptance"
        wsl_fix_dir = wsl_cand_root / "v2" / "g1_integration" / "demo_fixtures"
        wsl_fix_dir.mkdir(parents=True, exist_ok=True)
        wsl_target = wsl_fix_dir / "AllowlistedQuery.java"
        wsl_target.write_bytes(allow_bytes)

        wsl_fix_prefix = _to_wsl(wsl_fix_dir)
        wsl_file_path = f"{wsl_fix_prefix}/AllowlistedQuery.java"
        wrapper = _make_wsl_forwarding_wrapper(wsl_target, wsl_file_path)

        wsl_aq_d = e2e_root / "allowlisted_query_wsl_fp"
        scan_args = [
            "scan", str(wsl_target),
            "--rules-path", str(self.rules),
            "--output-dir", str(wsl_aq_d),
            "--executable", str(wrapper),
            "--local-triage",
            "--endpoint", ep,
            "--model", "qwen3.5:9b-q4_K_M",
            "--prompt-contract", "blind",
            "--runtime-origin", "mock",
        ]
        if os.name != "nt":
            scan_args.extend(["--path-map", f"{wsl_fix_prefix}={wsl_fix_dir}"])
        scan_res = _run_cli(self.prepared_source, scan_args)
        self.assertEqual(scan_res.returncode, 0, scan_res.stderr)
        shutil.copy2(wsl_aq_d / "triage" / "review.sqlite", wsl_aq_d / "triage" / "review.post_ingestion.sqlite")

        aq_db = str(wsl_aq_d / "triage" / "review.sqlite")
        aq_id = json.loads(_run_cli(self.prepared_source, ["queue", "--db", aq_db]).stdout)["warnings"][0]["id"]
        self.assertEqual(_run_cli(self.prepared_source, [
            "confirm-false", aq_id, "--db", aq_db,
            "--actor", "SCRIPTED_TEST_ONLY-op",
            "--reason", "SCRIPTED_TEST_ONLY: WSL2 allowlist check",
        ]).returncode, 0)
        shutil.copy2(wsl_aq_d / "triage" / "review.sqlite", wsl_aq_d / "triage" / "review.after_confirm_false.sqlite")
        self.assertEqual(_run_cli(self.prepared_source, [
            "reopen", aq_id, "--db", aq_db,
            "--actor", "SCRIPTED_TEST_ONLY-lead",
            "--reason", "SCRIPTED_TEST_ONLY: WSL2 reopen check",
        ]).returncode, 0)

        wsl_aq_ev = json.loads((wsl_aq_d / "triage" / "evidence.json").read_text(encoding="utf-8"))
        self.assertEqual(wsl_aq_ev["records"][0]["path"], wsl_file_path)
        self.assertEqual(_verify_allowlisted_fp_scenario_identity(wsl_aq_d, trusted_source_root=wsl_fix_dir), [])

        rep = evaluate_acceptance(
            demo1_dir=d1_d, demo2_dir=d2_d, demo3a_dir=d3a_d,
            m1_dir=m1_d, demo4_dir=d4_d, demo3b_dir=d3b_d,
            allowlisted_fp_dir=wsl_aq_d,
            allowlisted_trusted_source_root=wsl_fix_dir,
            r03_fp_mode="proposed-allowlisted-fp",
            allow_mock_primary=True,
        )
        self.assertEqual(rep["criteria"]["R01"]["status"], "PASS")
        self.assertEqual(rep["criteria"]["R02"]["status"], "PASS")
        self.assertEqual(rep["criteria"]["R03"]["status"], "PASS")
        self.assertEqual(rep["overall_status"], "PASS")
        self.assertEqual(rep["real_qwen_denominator"]["expected"], 4)
        self.assertEqual(rep["real_qwen_denominator"]["observed"], 4)
        supp = rep["supplementary_r03_control"]
        self.assertEqual(supp["raw_model_status"], "SUPPORTED")
        self.assertEqual(supp["validated_status"], "SUPPORTED")
        self.assertEqual(supp["model_fp_concurrence"], "DISAGREED_SUPPORTED")
        self.assertFalse(supp["qwen_concurred_fp"])

        base_ev = json.loads((native_aq_d / "triage" / "evidence.json").read_text(encoding="utf-8"))

        def _check_bundle(case_name: str, ev_mutator, *, manifest_doc=None, before_check=None, trusted_root=None) -> list[str]:
            cdir = self.tmp_root / f"wsl_case_{case_name}"
            (cdir / "triage").mkdir(parents=True, exist_ok=True)
            ev_doc = json.loads(json.dumps(base_ev))
            ev_mutator(ev_doc)
            (cdir / "triage" / "evidence.json").write_text(json.dumps(ev_doc), encoding="utf-8")
            if manifest_doc is not None:
                (cdir / "g1-run-manifest.json").write_text(json.dumps(manifest_doc), encoding="utf-8")
            if before_check is not None:
                before_check(cdir)
            return _verify_allowlisted_fp_scenario_identity(
                cdir, trusted_source_root=wsl_fix_dir if trusted_root is None else trusted_root,
            )

        # Case 2: Valid Windows absolute path, relative path, and repo-root WSL2 mapped path
        def _win_abs(d):
            d["root"] = str(wsl_fix_dir)
            d.pop("path_mappings", None)
            r = d["records"][0]
            r["root"] = str(wsl_fix_dir)
            r.pop("path_mappings", None)
            r["path"] = str(wsl_target)
            for s in r["snippets"]:
                s["path"] = "AllowlistedQuery.java"
                s["raw_path"] = str(wsl_target)

        self.assertEqual(_check_bundle("valid_win_abs", _win_abs), [])

        def _rel_path(d):
            _win_abs(d)
            d["records"][0]["path"] = "AllowlistedQuery.java"
            for s in d["records"][0]["snippets"]:
                s["raw_path"] = "AllowlistedQuery.java"

        self.assertEqual(_check_bundle("valid_rel", _rel_path), [])

        repo_rel_key = "v2/g1_integration/demo_fixtures/AllowlistedQuery.java"
        wsl_cand_prefix = _to_wsl(wsl_cand_root)
        wsl_repo_file = f"{wsl_cand_prefix}/{repo_rel_key}"

        def _wsl_repo_root(d):
            d["root"] = str(wsl_cand_root)
            d["path_mappings"] = [{"from": wsl_cand_prefix, "to": str(wsl_cand_root)}]
            r = d["records"][0]
            r["root"] = str(wsl_cand_root)
            r["path_mappings"] = [{"from": wsl_cand_prefix, "to": str(wsl_cand_root)}]
            r["path"] = wsl_repo_file
            r["snapshots"] = {repo_rel_key: dict(r["snapshots"]["AllowlistedQuery.java"])}
            for s in r["snippets"]:
                s["path"] = repo_rel_key
                s["raw_path"] = wsl_repo_file

        self.assertEqual(_check_bundle("valid_wsl_repo_root", _wsl_repo_root, trusted_root=wsl_cand_root), [])

        # Case 3 & 4: Missing/invalid/disagreeing/outside-root/sibling-prefix path_mappings & manifest mismatches
        outside_dir = self.tmp_root / "outside_allowq"
        outside_dir.mkdir(parents=True, exist_ok=True)
        outside_file = outside_dir / "AllowlistedQuery.java"
        outside_file.write_bytes(allow_bytes)

        sibling_dir = self.tmp_root / "candidates" / "g1-r03-wsl-acceptance-evil" / "v2" / "g1_integration" / "demo_fixtures"
        sibling_dir.mkdir(parents=True, exist_ok=True)
        (sibling_dir / "AllowlistedQuery.java").write_bytes(allow_bytes)

        def _wsl_base(d):
            d["root"] = str(wsl_fix_dir)
            d["path_mappings"] = [{"from": wsl_fix_prefix, "to": str(wsl_fix_dir)}]
            r = d["records"][0]
            r["root"] = str(wsl_fix_dir)
            r["path_mappings"] = [{"from": wsl_fix_prefix, "to": str(wsl_fix_dir)}]
            r["path"] = wsl_file_path
            for s in r["snippets"]:
                s["path"] = "AllowlistedQuery.java"
                s["raw_path"] = wsl_file_path

        mapping_rejects = []
        mapping_rejects.append(("missing_maps", lambda d: (_wsl_base(d), d.pop("path_mappings"), d["records"][0].pop("path_mappings")), None))
        mapping_rejects.append(("empty_maps", lambda d: (_wsl_base(d), d.__setitem__("path_mappings", []), d["records"][0].__setitem__("path_mappings", [])), None))
        mapping_rejects.append(("wrong_from_key", lambda d: (_wsl_base(d), d.__setitem__("path_mappings", [{"from": "/mnt/c/unmatched", "to": str(wsl_fix_dir)}]), d["records"][0].__setitem__("path_mappings", [{"from": "/mnt/c/unmatched", "to": str(wsl_fix_dir)}])), None))
        mapping_rejects.append(("outside_to_root", lambda d: (_wsl_base(d), d.__setitem__("path_mappings", [{"from": wsl_fix_prefix, "to": str(outside_dir)}]), d["records"][0].__setitem__("path_mappings", [{"from": wsl_fix_prefix, "to": str(outside_dir)}])), None))
        mapping_rejects.append(("sibling_prefix", lambda d: (_wsl_base(d), d["records"][0].__setitem__("path", f"{wsl_fix_prefix}-evil/AllowlistedQuery.java")), None))
        mapping_rejects.append(("ev_rec_map_disagree", lambda d: (_wsl_base(d), d["records"][0].__setitem__("path_mappings", [{"from": "/mnt/c/other", "to": str(wsl_fix_dir)}])), None))
        mapping_rejects.append(("manifest_maps_disagree", _wsl_base, {"source_root": str(wsl_fix_dir), "trusted_path_maps": [f"/mnt/c/other={wsl_fix_dir}"]}))
        mapping_rejects.append(("manifest_root_disagree", _wsl_base, {"source_root": str(outside_dir), "trusted_path_maps": [f"{wsl_fix_prefix}={wsl_fix_dir}"]}))
        for cname, mut, man in mapping_rejects:
            with self.subTest(mapping_case=cname):
                errs = _check_bundle(cname, mut, manifest_doc=man)
                self.assertTrue(errs, f"expected rejection for {cname}")

        # Codex trust-boundary counterexample: two mutually consistent JSON maps
        # must not rebind a WSL path outside the checkout to approved fixture bytes.
        forged_prefix = _to_wsl(outside_dir)
        forged_maps = [{"from": forged_prefix, "to": str(wsl_fix_dir)}]

        def _forged_consistent_maps(d):
            _wsl_base(d)
            d["path_mappings"] = list(forged_maps)
            r = d["records"][0]
            r["path_mappings"] = list(forged_maps)
            r["path"] = f"{forged_prefix}/AllowlistedQuery.java"
            for s in r["snippets"]:
                s["raw_path"] = r["path"]

        forged_manifest = {
            "source_root": str(wsl_fix_dir),
            "trusted_path_maps": [f"{forged_prefix}={wsl_fix_dir}"],
        }
        forged_errors = _check_bundle(
            "forged_consistent_maps", _forged_consistent_maps,
            manifest_doc=forged_manifest,
        )
        self.assertTrue(
            any("untrusted path_mappings" in error for error in forged_errors),
            f"matching forged JSON mappings must fail closed: {forged_errors!r}",
        )

        # Independent root authority: two JSONs can agree on a copied source,
        # but an operator-pinned scan root remains immutable for this evaluation.
        copied_root = self.tmp_root / "forged_copy_of_scan_root"
        copied_root.mkdir()
        (copied_root / "AllowlistedQuery.java").write_bytes(allow_bytes)
        copied_prefix = _to_wsl(copied_root)
        copied_maps = [{"from": copied_prefix, "to": str(copied_root)}]

        def _forge_declared_root(d):
            _wsl_base(d)
            d["root"] = str(copied_root)
            d["path_mappings"] = list(copied_maps)
            d["records"][0]["root"] = str(copied_root)
            d["records"][0]["path_mappings"] = list(copied_maps)
            d["records"][0]["path"] = f"{copied_prefix}/AllowlistedQuery.java"

        copied_manifest = {
            "source_root": str(copied_root),
            "trusted_path_maps": [f"{copied_prefix}={copied_root}"],
        }
        root_errors = _check_bundle(
            "forged_consistent_root", _forge_declared_root, manifest_doc=copied_manifest,
            trusted_root=wsl_fix_dir,
        )
        self.assertTrue(
            any("disagrees with independently pinned" in e for e in root_errors),
            f"forged evidence+manifest source root must be rejected: {root_errors!r}",
        )

        # Case 5: Traversal, spoofed basenames, outside paths, and junction/symlink escape
        path_rejects = [
            ("rel_traversal", "../outside_allowq/AllowlistedQuery.java"),
            ("wsl_traversal", f"{wsl_fix_prefix}/../outside_allowq/AllowlistedQuery.java"),
            ("outside_win", str(outside_file)),
            ("outside_wsl", f"{_to_wsl(outside_dir)}/AllowlistedQuery.java"),
            ("wrong_basename", f"{wsl_fix_prefix}/NotAllowlistedQuery.java"),
            ("file_uri", f"file://{wsl_file_path}"),
            ("unc_prefix", f"//{wsl_fix_prefix.lstrip('/')}/AllowlistedQuery.java"),
            ("mixed_slash", f"{wsl_fix_prefix}\\AllowlistedQuery.java"),
        ]
        for cname, bad_path in path_rejects:
            with self.subTest(path_case=cname):
                errs = _check_bundle(cname, lambda d, bp=bad_path: (_wsl_base(d), d["records"][0].__setitem__("path", bp)))
                self.assertTrue(errs, f"expected rejection for path {bad_path!r}")

        esc_dir = wsl_fix_dir / "esc_link"
        link_created = False
        try:
            if os.name == "nt":
                import _winapi
                _winapi.CreateJunction(str(outside_dir), str(esc_dir))
                link_created = True
            else:
                os.symlink(outside_dir, esc_dir, target_is_directory=True)
                link_created = True
        except OSError:
            link_created = False
        if link_created:
            try:
                for lname, lp in (
                    ("junction_rel", "esc_link/AllowlistedQuery.java"),
                    ("junction_wsl", f"{wsl_fix_prefix}/esc_link/AllowlistedQuery.java"),
                ):
                    with self.subTest(link_case=lname):
                        errs = _check_bundle(lname, lambda d, p=lp: (
                            _wsl_base(d),
                            d["records"][0].__setitem__("path", p),
                            d["records"][0].__setitem__("snapshots", {"esc_link/AllowlistedQuery.java": {"sha256": allow_sha, "size": len(allow_bytes)}}),
                        ))
                        self.assertTrue(errs, f"expected symlink/junction escape rejection for {lp!r}")
            finally:
                if esc_dir.is_symlink() or os.path.lexists(esc_dir):
                    try:
                        esc_dir.rmdir()
                    except OSError:
                        esc_dir.unlink(missing_ok=True)

        # Case 6: Wrong hash, CWE-890, wrong rule_id
        with self.subTest(meta="wrong_sha"):
            errs = _check_bundle("wrong_sha", lambda d: (_wsl_base(d), d["records"][0]["snapshots"]["AllowlistedQuery.java"].__setitem__("sha256", "0" * 64)))
            self.assertTrue(any("snapshot hash/size mismatch" in e for e in errs), errs)
        with self.subTest(meta="cwe890"):
            errs = _check_bundle("cwe890", lambda d: (_wsl_base(d), d["records"][0].__setitem__("cwe", ["CWE-890"])))
            self.assertTrue(any("expected exact CWE-89 finding" in e for e in errs), errs)
        with self.subTest(meta="wrong_rule"):
            errs = _check_bundle("wrong_rule", lambda d: (_wsl_base(d), d["records"][0].__setitem__("rule_id", "java.lang.security.sql-injection")))
            self.assertTrue(any("rule_id" in e for e in errs), errs)

        # Case 7: Source drift on disk fails closed
        drift_dir = self.tmp_root / "drift_fixtures"
        drift_dir.mkdir(parents=True, exist_ok=True)
        drift_file = drift_dir / "AllowlistedQuery.java"
        drift_file.write_bytes(allow_bytes + b"\n// post-scan drift\n")
        drift_wsl = _to_wsl(drift_dir)
        errs = _check_bundle(
            "source_drift",
            lambda d: (
                _wsl_base(d),
                d.__setitem__("root", str(drift_dir)),
                d.__setitem__("path_mappings", [{"from": drift_wsl, "to": str(drift_dir)}]),
                d["records"][0].__setitem__("root", str(drift_dir)),
                d["records"][0].__setitem__("path_mappings", [{"from": drift_wsl, "to": str(drift_dir)}]),
                d["records"][0].__setitem__("path", f"{drift_wsl}/AllowlistedQuery.java"),
            ),
            trusted_root=drift_dir,
        )
        self.assertTrue(any("source drift or disk fixture mismatch" in e for e in errs), errs)


if __name__ == "__main__":
    unittest.main()
