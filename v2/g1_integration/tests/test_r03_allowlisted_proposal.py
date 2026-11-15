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
        self.assertEqual(_verify_allowlisted_fp_scenario_identity(aq_d), [])

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
        self.assertTrue(_verify_allowlisted_fp_scenario_identity(ce1))

        # 2) Same basename AllowlistedQuery.java, forged snapshot SHA-256
        ce2 = self.tmp_root / "id_ce_hash"
        (ce2 / "triage").mkdir(parents=True, exist_ok=True)
        ev2 = json.loads(json.dumps(base_ev))
        snap_key = next(iter(ev2["records"][0]["snapshots"]))
        ev2["records"][0]["snapshots"][snap_key]["sha256"] = "0" * 64
        (ce2 / "triage" / "evidence.json").write_text(json.dumps(ev2), encoding="utf-8")
        self.assertTrue(_verify_allowlisted_fp_scenario_identity(ce2))

        # 3) Same basename AllowlistedQuery.java + valid CWE-89, log-only branch instead of throwing guard
        ce3 = self.tmp_root / "id_ce_log_only"
        (ce3 / "triage").mkdir(parents=True, exist_ok=True)
        ev3 = json.loads(json.dumps(base_ev))
        for snip in ev3["records"][0]["snippets"]:
            for ln in snip["lines"]:
                if "throw new IllegalArgumentException" in ln["text"]:
                    ln["text"] = 'System.out.println("rejected");'
        (ce3 / "triage" / "evidence.json").write_text(json.dumps(ev3), encoding="utf-8")
        self.assertTrue(_verify_allowlisted_fp_scenario_identity(ce3))

        # 4) Wrong rule_id even with AllowlistedQuery path
        ce4 = self.tmp_root / "id_ce_rule"
        (ce4 / "triage").mkdir(parents=True, exist_ok=True)
        ev4 = json.loads(json.dumps(base_ev))
        ev4["records"][0]["rule_id"] = "java.custom.wrong-rule"
        (ce4 / "triage" / "evidence.json").write_text(json.dumps(ev4), encoding="utf-8")
        self.assertTrue(_verify_allowlisted_fp_scenario_identity(ce4))

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
        errs5 = _verify_allowlisted_fp_scenario_identity(ce5)
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
            self.assertEqual(_verify_allowlisted_fp_scenario_identity(ce_pos), [], f"valid cwe={valid_cwe!r} failed")

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
                cwe_errs = _verify_allowlisted_fp_scenario_identity(ce_neg)
                self.assertTrue(
                    any("expected exact CWE-89 finding" in e for e in cwe_errs),
                    f"expected CWE-89 rejection for cwe={bad_cwe!r}, got {cwe_errs!r}",
                )


if __name__ == "__main__":
    unittest.main()
