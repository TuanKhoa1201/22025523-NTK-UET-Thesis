"""Focused G1 end-to-end integration and regression suite (Section 8: CLI/engine, Qwen/validator, Human review).

Distinguishes REAL OpenGrep subprocess execution from explicitly labeled MOCK HTTP Ollama fixtures.
Zero personal paths, zero cloud calls, and all temporary artifacts are cleaned up outside Git.
"""
from __future__ import annotations

import ast
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from v2.g1_integration import bridge
from v2.g1_integration.finding_identity import compare_findings
from v2.g1_integration.fork_support import scan_recording, scanner_config
from v2.g1_integration.prepare_g1_fork import apply_g1_overlay, apply_ntk_cleanroom_scanner_layer, overlay_cli_g1
from v2.triage.evidence import EvidenceError, StaleSourceError, collect, digest
from v2.triage.ollama import (
    DEFAULT_PROMPT_CONTRACT,
    GROUND_TRUTH_FORBIDDEN_KEYS,
    PROMPT_CONTRACT_BLIND,
    PROMPT_CONTRACT_NEUTRAL_HINTS,
    STEERING_SIGNAL_KEYS,
    OllamaClient,
    assert_prompt_contract,
    request_payload,
    validate_answer,
)
from v2.triage.store import ReviewStore


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


def _build_synthetic_prepared_fork(dest_dir: Path) -> Path:
    """Build an executable prepared fork tree from committed upstream baseline files + G1 overlay."""
    source = dest_dir / "source"
    (source / "semgrepai").mkdir(parents=True, exist_ok=True)
    upstream_base = REPO_ROOT / "v2" / "baseline" / "upstream"
    shutil.copy2(upstream_base / "LICENSE", source / "LICENSE")
    shutil.copy2(upstream_base / "pyproject.toml", source / "pyproject.toml")
    shutil.copy2(upstream_base / "semgrepai.yml", source / "semgrepai.yml")
    shutil.copy2(upstream_base / "semgrepai" / "cli.py", source / "semgrepai" / "cli.py")
    shutil.copy2(upstream_base / "semgrepai" / "config.py", source / "semgrepai" / "config.py")
    shutil.copy2(upstream_base / "semgrepai" / "scanner.py", source / "semgrepai" / "scanner.py")
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


def _run_prepared_cli(prepared_source: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join([str(prepared_source), str(REPO_ROOT)])
    env["NTK_G1_REPO_ROOT"] = str(REPO_ROOT)
    env["PYTHONUTF8"] = "1"
    return subprocess.run(
        [sys.executable, "-B", "-m", "semgrepai", *args],
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


class G1CliAndEngineIntegrationTests(unittest.TestCase):
    """Section 8 Group 1: CLI & OpenGrep engine integration invariants."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tmp_path = Path(self.tmp.name)
        self.prepared_source = _build_synthetic_prepared_fork(self.tmp_path / "prepared_fork")
        self.rules = REPO_ROOT / "v2" / "g1_integration" / "rules" / "java_g1_cwe22_cwe89.yml"
        self.demo1 = REPO_ROOT / "v2" / "g1_integration" / "demo_fixtures" / "Demo1TruePositive.java"
        self.demo2 = REPO_ROOT / "v2" / "g1_integration" / "demo_fixtures" / "Demo2ProtectedFalsePositive.java"

    def test_01_overlay_cli_preserves_scan_only_adds_local_triage_and_blocks_cloud_commands(self):
        orig = (REPO_ROOT / "v2" / "baseline" / "upstream" / "semgrepai" / "cli.py").read_text(encoding="utf-8")
        patched = overlay_cli_g1(orig)
        tree = ast.parse(patched)
        imports = [n.module for n in tree.body if isinstance(n, ast.ImportFrom)]
        for forbidden in ("rag", "validator", "reporter", "config"):
            self.assertNotIn(forbidden, imports)
        fn_names = {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}
        for expected_fn in (
            "scan", "review_queue", "review_show", "review_confirm_true",
            "review_confirm_false", "review_reopen", "review_history", "review_decide",
        ):
            self.assertIn(expected_fn, fn_names)

        # Unspecified mode (neither --scan-only nor --local-triage) is refused
        res_no_mode = _run_prepared_cli(self.prepared_source, ["scan", str(self.demo1)])
        self.assertNotEqual(res_no_mode.returncode, 0)

        # Disabled RAG/web commands fail closed
        for disabled_cmd in (["search", "sqli"], ["init-db"], ["config", "--show"]):
            res_dis = _run_prepared_cli(self.prepared_source, disabled_cmd)
            self.assertNotEqual(res_dis.returncode, 0)

    def test_02_semgrep_binary_is_strictly_rejected(self):
        for bad_bin in ("semgrep", "semgrep.exe", "/usr/bin/semgrep", "python"):
            with self.assertRaises(ValueError):
                scanner_config.validate_opengrep_binary(bad_bin)
        out_dir = self.tmp_path / "reject_semgrep"
        res = _run_prepared_cli(
            self.prepared_source,
            [
                "scan", str(self.demo1),
                "--rules-path", str(self.rules),
                "--output-dir", str(out_dir),
                "--local-triage",
                "--executable", "semgrep",
                "--no-llm",
            ],
        )
        self.assertEqual(res.returncode, 2)
        self.assertFalse((out_dir / "triage" / "review.sqlite").exists())

    def test_03_no_implicit_rescan_guard_blocks_second_scanner_call(self):
        with bridge._forbid_implicit_scanner_rescan():
            with self.assertRaisesRegex(RuntimeError, "implicit scanner rescan forbidden"):
                subprocess.run(["opengrep", "scan", "."], check=False)
            with self.assertRaisesRegex(RuntimeError, "implicit scanner rescan forbidden"):
                subprocess.run(["semgrep", "scan", "."], check=False)

    def test_04_real_opengrep_inherited_cli_handoff_parity_trace_and_single_scan(self):
        opengrep_bin = _find_opengrep_binary()
        if not opengrep_bin:
            self.skipTest("OpenGrep binary not installed on host")

        # 4a. M1 --scan-only still works on the G1 prepared fork
        m1_out = self.tmp_path / "m1_scan_only"
        res_m1 = _run_prepared_cli(
            self.prepared_source,
            [
                "scan", str(self.demo1),
                "--rules-path", str(self.rules),
                "--output-dir", str(m1_out),
                "--executable", opengrep_bin,
                "--scan-only",
            ],
        )
        self.assertEqual(res_m1.returncode, 0, res_m1.stderr)
        self.assertTrue((m1_out / "scan-manifest.json").is_file())
        self.assertTrue((m1_out / "cli-origin.json").is_file())

        # 4b. G1 --local-triage runs OpenGrep ONCE, preserves JSON/SARIF & trace, populates SQLite OPEN
        g1_out = self.tmp_path / "g1_local_triage"
        res_g1 = _run_prepared_cli(
            self.prepared_source,
            [
                "scan", str(self.demo1),
                "--rules-path", str(self.rules),
                "--output-dir", str(g1_out),
                "--executable", opengrep_bin,
                "--local-triage",
                "--no-llm",
            ],
        )
        self.assertEqual(res_g1.returncode, 0, res_g1.stderr)
        manifest = json.loads((g1_out / "g1-run-manifest.json").read_text(encoding="utf-8"))
        self.assertEqual([x["label"] for x in manifest["scanner_subprocess_invocations"]], ["version", "json", "sarif"])
        for inv in manifest["scanner_subprocess_invocations"]:
            self.assertTrue(Path(inv["argv"][0]).name.lower().startswith("opengrep"))
        self.assertEqual(manifest["triage_subprocess_invocations"], 0)
        self.assertEqual(manifest["stage_statuses"]["scanner_status"], "OK")
        self.assertEqual(manifest["stage_statuses"]["source_integrity_status"], "VERIFIED")
        self.assertEqual(manifest["stage_statuses"]["json_sarif_parity_status"], "MATCHED")
        self.assertEqual(manifest["stage_statuses"]["handoff_status"], "VERIFIED")
        self.assertEqual(manifest["findings_summary"]["total_findings"], 2)
        self.assertEqual(manifest["findings_summary"]["findings_with_trace"], 2)

        cli_origin = json.loads((g1_out / "capture" / "cli-origin.json").read_text(encoding="utf-8"))
        self.assertEqual(cli_origin["producer"], "inherited-cli-function-hook")
        self.assertEqual(cli_origin["cli_mode"], "local-triage")
        self.assertEqual(cli_origin["forbidden_imports"], [])

        # Refuses overwriting existing output_dir
        res_dup = _run_prepared_cli(
            self.prepared_source,
            [
                "scan", str(self.demo1),
                "--rules-path", str(self.rules),
                "--output-dir", str(g1_out),
                "--executable", opengrep_bin,
                "--local-triage",
                "--no-llm",
            ],
        )
        self.assertEqual(res_dup.returncode, 2)

    def test_05_failed_or_partial_scanner_and_divergent_sarif_never_counted_as_success(self):
        # Simulate a scanner that writes 1 partial finding to opengrep.json + mismatched empty SARIF and raises RuntimeError
        java_dir = self.tmp_path / "src"
        java_dir.mkdir()
        java_file = java_dir / "Partial.java"
        java_text = (
            "class Partial {\n"
            "  void f(javax.servlet.http.HttpServletRequest r, java.sql.Statement s) throws Exception {\n"
            '    String x = r.getParameter("q");\n'
            '    s.executeQuery("SELECT " + x);\n'
            "  }\n"
            "}\n"
        )
        java_file.write_text(java_text, encoding="utf-8")

        class BrokenScanner:
            def __init__(self, binary=None, config_path=None):
                pass

            def scan(self_scanner, target_path, rules_path=None):
                cap_out = scan_recording.capture_output_dir().parent
                partial_doc = {
                    "results": [{
                        "check_id": "ntk.g1.java.cwe89.sql-injection",
                        "path": "Partial.java",
                        "start": {"line": 4, "col": 5},
                        "end": {"line": 4, "col": 34},
                        "extra": {"severity": "ERROR", "metadata": {"cwe": ["CWE-89"]}, "errors": ["partial"]},
                    }],
                    "errors": [{"message": "engine partial failure"}],
                }
                (cap_out / "opengrep.json").write_text(json.dumps(partial_doc), encoding="utf-8")
                (cap_out / "opengrep.sarif").write_text(json.dumps({"runs": [{"results": []}]}), encoding="utf-8")
                raise RuntimeError("MOCK OpenGrep engine crash mid-scan")

        fake_cli_dir = self.tmp_path / "fake_pkg"
        fake_cli_dir.mkdir()
        fake_cli = fake_cli_dir / "cli.py"
        fake_cli.write_text("# mock cli\n", encoding="utf-8")

        out_dir = self.tmp_path / "broken_scan_out"
        exit_code, manifest = bridge.run_local_triage_from_cli(
            cli_file=str(fake_cli),
            scanner_cls=BrokenScanner,
            recording_fn=scan_recording.recording,
            record_cli_origin_fn=lambda *a, **kw: None,
            get_invocations_fn=scan_recording.get_subprocess_invocations,
            reset_invocations_fn=scan_recording.reset_subprocess_invocations,
            target_path=java_file,
            rules_path=self.rules,
            output_dir=out_dir,
            no_llm=True,
        )
        self.assertEqual(exit_code, 2)
        self.assertEqual(manifest["stage_statuses"]["scanner_status"], "FAILED")
        self.assertEqual(manifest["stage_statuses"]["json_sarif_parity_status"], "MISMATCH")
        self.assertFalse(manifest["stage_statuses"]["all_stages_succeeded"])

        # Partial finding is still retained in SQLite with state OPEN and UNDETERMINED
        store = ReviewStore(out_dir / "triage" / "review.sqlite")
        try:
            rows = store.queue()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["state"], "OPEN")
            self.assertEqual(rows[0]["assessment"]["status"], "UNDETERMINED")
        finally:
            store.close()


class G1QwenContractAndValidatorTests(unittest.TestCase):
    """Section 8 Group 2: Blind prompt contract, nested key guard, validator & failure resilience."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "src"
        self.root.mkdir()
        self.java_file = self.root / "Case.java"
        self.code = (
            "import java.io.*;\n"
            "import javax.servlet.http.*;\n"
            "class Case {\n"
            "  FileInputStream badEncoder(HttpServletRequest req) throws Exception {\n"
            '    String p = req.getParameter("f");\n'
            "    String html = org.owasp.esapi.ESAPI.encoder().encodeForHTML(p);\n"
            "    return new FileInputStream(html);\n"
            "  }\n"
            "}\n"
        )
        self.java_file.write_bytes(self.code.encode("utf-8"))
        lines = self.code.splitlines(keepends=True)

        def pt(ln, col):
            return {"line": ln, "col": col, "offset": sum(len(x.encode("utf-8")) for x in lines[: ln - 1]) + col - 1}

        def tag(ln, text):
            c = self.code.splitlines()[ln - 1].index(text) + 1
            return ["CliLoc", [{"path": "Case.java", "start": pt(ln, c), "end": pt(ln, c + len(text.encode("utf-8")))}, text]]

        self.raw_doc = {
            "results": [{
                "check_id": "ntk.g1.java.cwe22.path-traversal",
                "path": "Case.java",
                "start": pt(7, 12),
                "end": pt(7, 37),
                "extra": {
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-22"]},
                    "dataflow_trace": {
                        "taint_source": tag(5, 'req.getParameter("f")'),
                        "intermediate_vars": [],
                        "taint_sink": tag(7, "new FileInputStream(html)"),
                    },
                },
            }],
            "errors": [],
        }
        self.bundle = collect(
            json.dumps(self.raw_doc),
            self.root,
            engine_exit=0,
            scan_provenance={"origin": "UNIT_TEST_MOCK_CAPTURE", "source_capture_verified": True},
        )
        self.record = self.bundle["records"][0]
        self.sha = self.record["snapshots"]["Case.java"]["sha256"]

    def _cite(self, line_no: int) -> dict:
        line_txt = self.code.splitlines()[line_no - 1]
        return {
            "path": "Case.java",
            "start_line": line_no,
            "end_line": line_no,
            "quote": line_txt,
            "sha256": self.sha,
        }

    def test_06_blind_is_default_and_blocks_ground_truth_and_nested_keys(self):
        self.assertEqual(DEFAULT_PROMPT_CONTRACT, PROMPT_CONTRACT_BLIND)
        req = request_payload(self.record, "qwen3.5:9b-q4_K_M")
        user_payload = json.loads(req["messages"][1]["content"])
        self.assertNotIn("evidence_signals", user_payload)
        for k in STEERING_SIGNAL_KEYS | GROUND_TRUTH_FORBIDDEN_KEYS:
            self.assertNotIn(k, json.dumps(user_payload))

        # Planted invalid nested keys inside snippets, lines, start, trace_steps, cwe, or ground truth are rejected
        bad_payloads = [
            {**user_payload, "ground_truth": "TP"},
            {**user_payload, "cwe": [{"nested": "CWE-22"}]},
            {**user_payload, "start": {"line": 7, "col": 12, "extra_key": 1}},
            {**user_payload, "snippets": [{"path": "Case.java", "unexpected_key": 1, "lines": []}]},
            {**user_payload, "snippets": [{"path": "Case.java", "lines": [{"line": 1, "text": "x", "leak": "TP"}]}]},
            {**user_payload, "trace_steps": [{"role": "sink", "path": "Case.java", "start_line": 7, "end_line": 7, "extra": 1}]},
        ]
        for bad in bad_payloads:
            with self.assertRaises(EvidenceError):
                assert_prompt_contract(bad, PROMPT_CONTRACT_BLIND)

        # Controlled neutral_hints option works without leaking verdicts
        rec_hints = copy.deepcopy(self.record)
        rec_hints["prompt_contract"] = PROMPT_CONTRACT_NEUTRAL_HINTS
        req_hints = request_payload(rec_hints, "qwen3.5:9b-q4_K_M")
        hints_payload = json.loads(req_hints["messages"][1]["content"])
        self.assertIn("evidence_signals", hints_payload)
        self.assertNotIn("recommended_status", hints_payload["evidence_signals"])

    def test_07_malformed_json_bad_citations_and_unverified_refuted_preserve_raw_status_and_downgrade(self):
        io_dir = Path(self.tmp.name) / "llm_io"
        client = OllamaClient(model="qwen3.5:9b-q4_K_M", runtime_origin="mock", io_log_dir=io_dir)

        # Case A: REFUTED citing wrong-context HTML encoder (encodeForHTML on CWE-22) -> downgraded!
        bad_refuted_content = json.dumps({
            "status": "REFUTED",
            "explanation": "Đã mã hóa HTML.",
            "fix_suggestion": "",
            "citations": [self._cite(6)],
        })
        mock_resp = {
            "done": True,
            "done_reason": "stop",
            "model": "qwen3.5:9b-q4_K_M",
            "mock_test_fixture": True,
            "message": {"content": bad_refuted_content},
        }
        with patch.object(client, "request", return_value=mock_resp):
            out = client.analyze(self.record)
        # Raw model output is preserved as REFUTED, while validated_status is UNDETERMINED!
        self.assertEqual(out["raw_model_status"], "REFUTED")
        self.assertEqual(out["validated_status"], "UNDETERMINED")
        self.assertEqual(out["status"], "UNDETERMINED")
        self.assertTrue(out["validator_downgraded"])
        self.assertEqual(out["failure_kind"], "UNVERIFIED_REFUTATION")

        # Verbatim prompt/request/response artifacts saved in private io_log_dir
        self.assertTrue((io_dir / f"{self.record['id']}.prompt.json").is_file())
        self.assertTrue((io_dir / f"{self.record['id']}.request.json").is_file())
        self.assertTrue((io_dir / f"{self.record['id']}.response.json").is_file())

        # Case B: Wrong citation SHA-256 -> INVALID_CITATION
        bad_sha_content = json.dumps({
            "status": "SUPPORTED",
            "explanation": "Lỗ hổng.",
            "fix_suggestion": "",
            "citations": [{**self._cite(7), "sha256": "0" * 64}],
        })
        with patch.object(client, "request", return_value={**mock_resp, "message": {"content": bad_sha_content}}):
            out_sha = client.analyze(self.record)
        self.assertEqual(out_sha["raw_model_status"], "SUPPORTED")
        self.assertEqual(out_sha["validated_status"], "UNDETERMINED")
        self.assertEqual(out_sha["failure_kind"], "INVALID_CITATION")

        # Case C: Malformed JSON -> MALFORMED_JSON
        with patch.object(client, "request", return_value={**mock_resp, "message": {"content": "{not json"}}):
            out_mal = client.analyze(self.record)
        self.assertIsNone(out_mal["raw_model_status"])
        self.assertEqual(out_mal["validated_status"], "UNDETERMINED")
        self.assertEqual(out_mal["failure_kind"], "MALFORMED_JSON")

    def test_08_ollama_http_404_model_unavailable_and_timeout_retain_open_alerts(self):
        class MissingModelHandler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                if length:
                    self.rfile.read(length)
                body = b'{"error":"model \'qwen3.5:9b-q4_K_M\' not found"}'
                self.send_response(404)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = ThreadingHTTPServer(("127.0.0.1", 0), MissingModelHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = OllamaClient(f"http://127.0.0.1:{server.server_port}", model="qwen3.5:9b-q4_K_M", runtime_origin="mock")
            assessment = client.analyze(self.record)
            self.assertEqual(assessment["validated_status"], "UNDETERMINED")
            self.assertEqual(assessment["failure_kind"], "MODEL_UNAVAILABLE")

            store = ReviewStore(Path(self.tmp.name) / "missing_model.sqlite")
            try:
                store.add(self.bundle, [assessment])
                q = store.queue()
                self.assertEqual(len(q), 1)
                self.assertEqual(q[0]["state"], "OPEN")
            finally:
                store.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


class G1HumanReviewAndStaleSourceTests(unittest.TestCase):
    """Section 8 Group 3: Human review lifecycle & STALE_SOURCE structured refusal via prepared CLI."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tmp_path = Path(self.tmp.name)
        self.prepared_source = _build_synthetic_prepared_fork(self.tmp_path / "prepared_fork")

        self.src_dir = self.tmp_path / "java_src"
        self.src_dir.mkdir()
        self.java_file = self.src_dir / "Guarded.java"
        self.java_text = (
            "import java.io.*;\n"
            "import javax.servlet.http.*;\n"
            "class Guarded {\n"
            "  FileInputStream read(HttpServletRequest req) throws Exception {\n"
            '    String f = req.getParameter("f");\n'
            '    File c = new File("/srv/reports/", f);\n'
            "    String canon = c.getCanonicalPath();\n"
            '    if (!canon.startsWith("/srv/reports/")) throw new SecurityException("bad");\n'
            "    return new FileInputStream(c);\n"
            "  }\n"
            "}\n"
        )
        self.java_file.write_bytes(self.java_text.encode("utf-8"))
        lines = self.java_text.splitlines(keepends=True)

        def pt(ln, col):
            return {"line": ln, "col": col, "offset": sum(len(x.encode("utf-8")) for x in lines[: ln - 1]) + col - 1}

        def tag(ln, text):
            c = self.java_text.splitlines()[ln - 1].index(text) + 1
            return ["CliLoc", [{"path": "Guarded.java", "start": pt(ln, c), "end": pt(ln, c + len(text.encode("utf-8")))}, text]]

        raw_doc = {
            "results": [{
                "check_id": "ntk.g1.java.cwe22.path-traversal",
                "path": "Guarded.java",
                "start": pt(9, 12),
                "end": pt(9, 33),
                "extra": {
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-22"]},
                    "dataflow_trace": {
                        "taint_source": tag(5, 'req.getParameter("f")'),
                        "intermediate_vars": [],
                        "taint_sink": tag(9, "new FileInputStream(c)"),
                    },
                },
            }],
            "errors": [],
        }
        bundle = collect(
            json.dumps(raw_doc),
            self.src_dir,
            engine_exit=0,
            scan_provenance={"origin": "UNIT_TEST_MOCK_CAPTURE", "source_capture_verified": True},
        )
        self.record = bundle["records"][0]
        sha = self.record["snapshots"]["Guarded.java"]["sha256"]
        refuted_ans = validate_answer(
            json.dumps({
                "status": "REFUTED",
                "explanation": "Đã kiểm tra đường dẫn chính tắc.",
                "fix_suggestion": "",
                "citations": [{
                    "path": "Guarded.java",
                    "start_line": 8,
                    "end_line": 8,
                    "quote": self.java_text.splitlines()[7],
                    "sha256": sha,
                }],
            }),
            self.record,
        )
        self.db_path = self.tmp_path / "review.sqlite"
        store = ReviewStore(self.db_path)
        try:
            store.add(bundle, [refuted_ans])
        finally:
            store.close()

    def test_09_refuted_remains_open_and_confirm_true_confirm_false_reopen_history_work_via_fork_cli(self):
        wid = self.record["id"]
        db = str(self.db_path)

        # Unconfirmed REFUTED alert MUST appear in default queue as OPEN
        q0 = json.loads(_run_prepared_cli(self.prepared_source, ["queue", "--db", db]).stdout)
        self.assertEqual(len(q0["warnings"]), 1)
        self.assertEqual(q0["warnings"][0]["state"], "OPEN")
        self.assertEqual(q0["warnings"][0]["validated_status"], "REFUTED")

        # confirm-false hides from default queue, visible in --all
        cf = _run_prepared_cli(
            self.prepared_source,
            ["confirm-false", wid, "--db", db, "--actor", "reviewer-1", "--reason", "Canonical guard verified"],
        )
        self.assertEqual(cf.returncode, 0, cf.stderr)
        self.assertEqual(json.loads(_run_prepared_cli(self.prepared_source, ["queue", "--db", db]).stdout)["warnings"], [])
        q_all = json.loads(_run_prepared_cli(self.prepared_source, ["queue", "--db", db, "--all"]).stdout)
        self.assertEqual(q_all["warnings"][0]["state"], "CONFIRMED_FALSE")

        # reopen restores to default queue and preserves history
        ro = _run_prepared_cli(
            self.prepared_source,
            ["reopen", wid, "--db", db, "--actor", "reviewer-2", "--reason", "Re-checking symlink behavior"],
        )
        self.assertEqual(ro.returncode, 0, ro.stderr)
        q_reopened = json.loads(_run_prepared_cli(self.prepared_source, ["queue", "--db", db]).stdout)
        self.assertEqual(len(q_reopened["warnings"]), 1)
        self.assertEqual(q_reopened["warnings"][0]["state"], "OPEN")

        # confirm-true keeps visible in default queue
        ct = _run_prepared_cli(
            self.prepared_source,
            ["confirm-true", wid, "--db", db, "--actor", "reviewer-2", "--reason", "Confirmed issue on Windows"],
        )
        self.assertEqual(ct.returncode, 0, ct.stderr)
        hist = json.loads(_run_prepared_cli(self.prepared_source, ["history", wid, "--db", db]).stdout)
        self.assertEqual([h["action"] for h in hist], ["confirm-false", "reopen", "confirm-true"])

    def test_10_stale_source_refuses_confirm_false_and_records_structured_rejection_without_false_event(self):
        wid = self.record["id"]
        db = str(self.db_path)

        # Modify Java file after scan
        self.java_file.write_text(self.java_text + "// mutated after scan\n", encoding="utf-8")

        res = _run_prepared_cli(
            self.prepared_source,
            ["confirm-false", wid, "--db", db, "--actor", "reviewer-1", "--reason", "Attempt on stale source"],
        )
        self.assertEqual(res.returncode, 2)
        self.assertIn("STALE_SOURCE", res.stderr)
        stderr_lines = [ln for ln in res.stderr.strip().splitlines() if ln.startswith("{")]
        self.assertEqual(len(stderr_lines), 1)
        err_obj = json.loads(stderr_lines[0])
        self.assertEqual(err_obj["error_code"], "STALE_SOURCE")
        self.assertIn("Guarded.java", err_obj["mismatched_paths"])

        # Warning remains OPEN, 0 accepted events, 1 rejected_decisions record
        q = json.loads(_run_prepared_cli(self.prepared_source, ["queue", "--db", db]).stdout)
        self.assertEqual(q["warnings"][0]["state"], "OPEN")
        hist_full = json.loads(
            _run_prepared_cli(self.prepared_source, ["history", wid, "--db", db, "--include-rejected"]).stdout
        )
        self.assertEqual(hist_full["events"], [])
        self.assertEqual(len(hist_full["rejected_decisions"]), 1)
        self.assertEqual(hist_full["rejected_decisions"][0]["rejection_code"], "STALE_SOURCE")


class G1Wsl2PathMappingIntegrationTests(unittest.TestCase):
    """Section 8 Group 4 (G1-C2): End-to-end WSL2 OpenGrep -> Windows source_root bridge & security boundaries."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tmp_path = Path(self.tmp.name).resolve(strict=True)
        self.prepared_source = _build_synthetic_prepared_fork(self.tmp_path / "prepared_fork")
        self.rules = REPO_ROOT / "v2" / "g1_integration" / "rules" / "java_g1_cwe22_cwe89.yml"

        self.src_dir = self.tmp_path / "wsl_target_src"
        self.src_dir.mkdir()
        self.demo1_src = REPO_ROOT / "v2" / "g1_integration" / "demo_fixtures" / "Demo1TruePositive.java"
        self.target_java = self.src_dir / "Demo1TruePositive.java"
        shutil.copy2(self.demo1_src, self.target_java)

    def _wsl_path_for_file(self, file_path: Path) -> str:
        resolved = file_path.resolve(strict=True)
        if os.name == "nt" and resolved.drive:
            drv = resolved.drive[0].lower()
            rel = resolved.relative_to(resolved.anchor).as_posix().strip("/")
            return str(PurePosixPath(f"/mnt/{drv}/{rel}"))
        return str(PurePosixPath(f"/mnt/c/ntk_wsl_sim/{resolved.name}"))

    def _make_wsl_opengrep_wrapper(self, emitted_wsl_path: str) -> tuple[Path, bytes, bytes]:
        """Build a local wrapper named `opengrep_wsl_sim(.cmd)` that emits 2 findings and 11 WSL2 locations."""
        code_bytes = self.target_java.read_bytes()
        code_text = code_bytes.decode("utf-8")
        lines_ke = code_text.splitlines(keepends=True)
        lines = code_text.splitlines()

        def pt(ln: int, col: int) -> dict[str, int]:
            return {
                "line": ln,
                "col": col,
                "offset": sum(len(x.encode("utf-8")) for x in lines_ke[: ln - 1]) + col - 1,
            }

        def loc_dict(ln: int, snippet_txt: str) -> dict:
            c = lines[ln - 1].index(snippet_txt) + 1
            return {
                "path": emitted_wsl_path,
                "start": pt(ln, c),
                "end": pt(ln, c + len(snippet_txt.encode("utf-8"))),
            }

        def cli_loc(ln: int, snippet_txt: str) -> list:
            return ["CliLoc", [loc_dict(ln, snippet_txt), snippet_txt]]

        # Find actual line numbers in Demo1TruePositive.java dynamically (6 + 5 = 11 WSL2 locations, matching ADMIN-PC!)
        sqli_src_ln = next(i + 1 for i, l in enumerate(lines) if 'req.getParameter("role")' in l)
        sqli_norm_ln = next(i + 1 for i, l in enumerate(lines) if "String normalizedRole =" in l)
        sqli_var_ln = next(i + 1 for i, l in enumerate(lines) if "String sql =" in l)
        sqli_sink_ln = next(i + 1 for i, l in enumerate(lines) if "stmt.executeQuery(sql)" in l)

        pt_src_ln = next(i + 1 for i, l in enumerate(lines) if 'req.getParameter("file")' in l)
        pt_var_ln = next(i + 1 for i, l in enumerate(lines) if "String targetPath =" in l)
        pt_sink_ln = next(i + 1 for i, l in enumerate(lines) if "new FileInputStream(targetPath)" in l)

        sqli_sink_loc = loc_dict(sqli_sink_ln, "stmt.executeQuery(sql)")
        pt_sink_loc = loc_dict(pt_sink_ln, "new FileInputStream(targetPath)")

        raw_json_obj = {
            "version": "1.25.0",
            "results": [
                {
                    "check_id": "v2.g1_integration.rules.ntk.g1.java.cwe89.sql-injection",
                    "path": emitted_wsl_path,
                    "start": sqli_sink_loc["start"],
                    "end": sqli_sink_loc["end"],
                    "extra": {
                        "severity": "ERROR",
                        "message": "SQLi",
                        "metadata": {"cwe": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command"]},
                        "dataflow_trace": {
                            "taint_source": cli_loc(sqli_src_ln, 'req.getParameter("role")'),
                            "intermediate_vars": [
                                {"location": loc_dict(sqli_src_ln, "role"), "content": "role"},
                                {"location": loc_dict(sqli_norm_ln, "normalizedRole"), "content": "normalizedRole"},
                                {"location": loc_dict(sqli_var_ln, "sql"), "content": "sql"},
                            ],
                            "taint_sink": cli_loc(sqli_sink_ln, "stmt.executeQuery(sql)"),
                        },
                    },
                },
                {
                    "check_id": "v2.g1_integration.rules.ntk.g1.java.cwe22.path-traversal",
                    "path": emitted_wsl_path,
                    "start": pt_sink_loc["start"],
                    "end": pt_sink_loc["end"],
                    "extra": {
                        "severity": "ERROR",
                        "message": "Path traversal",
                        "metadata": {"cwe": ["CWE-22: Improper Limitation of a Pathname to a Restricted Directory"]},
                        "dataflow_trace": {
                            "taint_source": cli_loc(pt_src_ln, 'req.getParameter("file")'),
                            "intermediate_vars": [
                                {"location": loc_dict(pt_src_ln, "invoiceName"), "content": "invoiceName"},
                                {"location": loc_dict(pt_var_ln, "targetPath"), "content": "targetPath"},
                            ],
                            "taint_sink": cli_loc(pt_sink_ln, "new FileInputStream(targetPath)"),
                        },
                    },
                },
            ],
            "errors": [],
            "paths": {"scanned": [emitted_wsl_path], "skipped": []},
        }
        sarif_uri = "file://" + emitted_wsl_path
        raw_sarif_obj = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "opengrep", "semanticVersion": "1.25.0", "rules": []}},
                    "results": [
                        {
                            "ruleId": "v2.g1_integration.rules.ntk.g1.java.cwe89.sql-injection",
                            "locations": [{
                                "physicalLocation": {
                                    "artifactLocation": {"uri": sarif_uri},
                                    "region": {
                                        "startLine": sqli_sink_loc["start"]["line"],
                                        "startColumn": sqli_sink_loc["start"]["col"],
                                        "endLine": sqli_sink_loc["end"]["line"],
                                        "endColumn": sqli_sink_loc["end"]["col"],
                                    },
                                }
                            }],
                        },
                        {
                            "ruleId": "v2.g1_integration.rules.ntk.g1.java.cwe22.path-traversal",
                            "locations": [{
                                "physicalLocation": {
                                    "artifactLocation": {"uri": sarif_uri},
                                    "region": {
                                        "startLine": pt_sink_loc["start"]["line"],
                                        "startColumn": pt_sink_loc["start"]["col"],
                                        "endLine": pt_sink_loc["end"]["line"],
                                        "endColumn": pt_sink_loc["end"]["col"],
                                    },
                                }
                            }],
                        },
                    ],
                }
            ],
        }

        payload_dir = self.tmp_path / f"wsl_payload_{abs(hash(emitted_wsl_path))}"
        payload_dir.mkdir(parents=True, exist_ok=True)
        raw_json_bytes = (json.dumps(raw_json_obj, indent=2) + "\n").encode("utf-8")
        raw_sarif_bytes = (json.dumps(raw_sarif_obj, indent=2) + "\n").encode("utf-8")
        (payload_dir / "payload.json").write_bytes(raw_json_bytes)
        (payload_dir / "payload.sarif").write_bytes(raw_sarif_bytes)

        helper_py = payload_dir / "emit_scan.py"
        helper_py.write_text(
            "import pathlib, shutil, sys\n"
            "args = sys.argv[1:]\n"
            "base = pathlib.Path(__file__).resolve().parent\n"
            "if '--version' in args:\n"
            "    print('1.25.0')\n"
            "    raise SystemExit(0)\n"
            "src = base / ('payload.sarif' if '--sarif' in args else 'payload.json')\n"
            "if '--output' in args:\n"
            "    out = pathlib.Path(args[args.index('--output') + 1])\n"
            "    shutil.copyfile(src, out)\n"
            "else:\n"
            "    sys.stdout.buffer.write(src.read_bytes())\n",
            encoding="utf-8",
        )

        bin_dir = payload_dir / "bin"
        bin_dir.mkdir(exist_ok=True)
        if os.name == "nt":
            wrapper = bin_dir / "opengrep_wsl_sim.cmd"
            wrapper.write_text(f'@echo off\r\n"{sys.executable}" -B "{helper_py}" %*\r\n', encoding="utf-8")
        else:
            wrapper = bin_dir / "opengrep_wsl_sim"
            wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" -B "{helper_py}" "$@"\n', encoding="utf-8")
            wrapper.chmod(0o755)
        return wrapper, raw_json_bytes, raw_sarif_bytes

    def test_11_wsl2_opengrep_e2e_via_inherited_cli_preserves_raw_capture_and_invokes_qwen(self):
        wsl_path = self._wsl_path_for_file(self.target_java)
        wrapper, expected_json_bytes, expected_sarif_bytes = self._make_wsl_opengrep_wrapper(wsl_path)

        chat_requests: list[dict] = []

        class MockQwenHandler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                if self.path == "/api/tags":
                    body = json.dumps({
                        "models": [{"name": "qwen3.5:9b-q4_K_M", "digest": "mock-wsl-test", "size": 1}]
                    }).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_error(404)

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                req_doc = json.loads(self.rfile.read(length).decode("utf-8"))
                chat_requests.append(req_doc)
                user_ev = json.loads(req_doc["messages"][1]["content"])
                snip = user_ev["snippets"][0]
                sink_ln = user_ev["start"]["line"]
                line_obj = next(ln for ln in snip["lines"] if ln["line"] == sink_ln)
                ans = {
                    "status": "SUPPORTED",
                    "explanation": "Tham số HTTP đi thẳng tới sink nhạy cảm không qua bước làm sạch.",
                    "fix_suggestion": "Sử dụng PreparedStatement hoặc kiểm tra đường dẫn chính tắc.",
                    "citations": [{
                        "path": snip["path"],
                        "start_line": sink_ln,
                        "end_line": sink_ln,
                        "quote": line_obj["text"],
                        "sha256": snip["sha256"],
                    }],
                }
                resp = {
                    "done": True,
                    "done_reason": "stop",
                    "model": "qwen3.5:9b-q4_K_M",
                    "mock_test_fixture": True,
                    "eval_count": 64,
                    "eval_duration": 1000000,
                    "message": {"role": "assistant", "content": json.dumps(ans, ensure_ascii=False)},
                }
                body = json.dumps(resp, ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = ThreadingHTTPServer(("127.0.0.1", 0), MockQwenHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            out_dir = self.tmp_path / "wsl_g1_e2e_out"
            extra_flags = [] if os.name == "nt" else ["--path-map", f"/mnt/c/ntk_wsl_sim={self.src_dir}"]
            res = _run_prepared_cli(
                self.prepared_source,
                [
                    "scan", str(self.target_java),
                    "--rules-path", str(self.rules),
                    "--output-dir", str(out_dir),
                    "--executable", str(wrapper),
                    "--local-triage",
                    "--endpoint", f"http://127.0.0.1:{server.server_port}",
                    "--model", "qwen3.5:9b-q4_K_M",
                    "--runtime-origin", "mock",
                    *extra_flags,
                ],
            )
            self.assertEqual(res.returncode, 0, f"STDERR:\n{res.stderr}\nSTDOUT:\n{res.stdout}")

            # 1. Raw OpenGrep JSON and SARIF are preserved byte-for-byte lossless (no path rewriting!)
            self.assertEqual((out_dir / "capture" / "opengrep.json").read_bytes(), expected_json_bytes)
            self.assertEqual((out_dir / "capture" / "opengrep.sarif").read_bytes(), expected_sarif_bytes)

            # 2. All stages succeeded, 0 rescans, Qwen actually invoked twice (once per finding)
            manifest = json.loads((out_dir / "g1-run-manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["triage_subprocess_invocations"], 0)
            self.assertEqual(manifest["stage_statuses"]["scanner_status"], "OK")
            self.assertEqual(manifest["stage_statuses"]["source_integrity_status"], "VERIFIED")
            self.assertEqual(manifest["stage_statuses"]["json_sarif_parity_status"], "MATCHED")
            self.assertEqual(manifest["stage_statuses"]["handoff_status"], "VERIFIED")
            self.assertEqual(manifest["stage_statuses"]["qwen_inference_status"], "ALL_HTTP_COMPLETED")
            self.assertEqual(manifest["stage_statuses"]["validator_status"], "ALL_VALIDATED")
            self.assertEqual(manifest["stage_statuses"]["queue_status"], "OPEN_READY")
            self.assertTrue(manifest["stage_statuses"]["all_stages_succeeded"])
            self.assertEqual(len(chat_requests), 2)

            # 3. Evidence bundle has 0 issues, preserves raw `/mnt/...` provenance, and binds canonical relative snapshot
            ev_bundle = json.loads((out_dir / "triage" / "evidence.json").read_text(encoding="utf-8"))
            self.assertEqual(ev_bundle["issues"], [])
            for rec in ev_bundle["records"]:
                self.assertEqual(rec["issues"], [])
                self.assertEqual(rec["path"], wsl_path)
                self.assertIn("Demo1TruePositive.java", rec["snapshots"])
                self.assertEqual(rec["snippets"][0]["path"], "Demo1TruePositive.java")
                self.assertEqual(rec["snippets"][0]["raw_path"], wsl_path)

            # 4. Human queue holds both findings as OPEN with validated SUPPORTED status
            q_doc = json.loads(
                _run_prepared_cli(self.prepared_source, ["queue", "--db", str(out_dir / "triage" / "review.sqlite")]).stdout
            )
            self.assertEqual(len(q_doc["warnings"]), 2)
            self.assertTrue(all(w["state"] == "OPEN" for w in q_doc["warnings"]))
            self.assertEqual([w["validated_status"] for w in q_doc["warnings"]], ["SUPPORTED", "SUPPORTED"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_12_untrusted_posix_cross_drive_sibling_traversal_and_symlink_escape_fail_closed_in_cli(self):
        outside_dir = self.tmp_path / "outside_secret"
        outside_dir.mkdir()
        shutil.copy2(self.demo1_src, outside_dir / "Demo1TruePositive.java")

        sibling_dir = self.tmp_path / "wsl_target_src-evil"
        sibling_dir.mkdir()
        shutil.copy2(self.demo1_src, sibling_dir / "Demo1TruePositive.java")

        escape_link = self.src_dir / "escape_sub"
        if os.name == "nt":
            import _winapi
            _winapi.CreateJunction(str(outside_dir), str(escape_link))
        else:
            os.symlink(str(outside_dir), str(escape_link), target_is_directory=True)

        valid_wsl_file = self._wsl_path_for_file(self.target_java)
        valid_wsl_dir = valid_wsl_file.rsplit("/", 1)[0]

        attack_paths = [
            ("/etc/Demo1TruePositive.java", None),
            ("/mnt/z/cross_drive/Demo1TruePositive.java", None),
            (f"{valid_wsl_dir}-evil/Demo1TruePositive.java", None),
            (f"{valid_wsl_dir}/../outside_secret/Demo1TruePositive.java", "invalid mapped path suffix"),
            (f"{valid_wsl_dir}/escape_sub/Demo1TruePositive.java", "outside configured root"),
        ]
        try:
            # Directory-target inventory also rejects a junction/symlink escaping source_root before scanning
            with self.assertRaisesRegex(EvidenceError, "outside configured root"):
                bridge._source_inventory(self.src_dir)

            for idx, (bad_wsl_path, expected_issue_substr) in enumerate(attack_paths):
                with self.subTest(bad_wsl_path=bad_wsl_path):
                    wrapper, _, _ = self._make_wsl_opengrep_wrapper(bad_wsl_path)
                    out_dir = self.tmp_path / f"attack_out_{idx}"
                    extra_flags = [] if os.name == "nt" else ["--path-map", f"/mnt/c/ntk_wsl_sim={self.src_dir}"]
                    res = _run_prepared_cli(
                        self.prepared_source,
                        [
                            "scan", str(self.target_java),
                            "--rules-path", str(self.rules),
                            "--output-dir", str(out_dir),
                            "--executable", str(wrapper),
                            "--local-triage",
                            "--no-llm",
                            *extra_flags,
                        ],
                    )
                    # Wrapper must exit 2 (degraded/failed evidence) and retain both alerts OPEN + UNDETERMINED
                    self.assertEqual(res.returncode, 2)
                    ev_bundle = json.loads((out_dir / "triage" / "evidence.json").read_text(encoding="utf-8"))
                    for rec in ev_bundle["records"]:
                        self.assertTrue(rec["issues"])
                        if expected_issue_substr:
                            self.assertTrue(
                                any(expected_issue_substr in iss for iss in rec["issues"]),
                                f"Expected {expected_issue_substr!r} in {rec['issues']}",
                            )
                        self.assertEqual(rec["snapshots"], {})
                    q_doc = json.loads(
                        _run_prepared_cli(self.prepared_source, ["queue", "--db", str(out_dir / "triage" / "review.sqlite")]).stdout
                    )
                    self.assertEqual(len(q_doc["warnings"]), 2)
                    self.assertTrue(all(w["state"] == "OPEN" for w in q_doc["warnings"]))
                    self.assertTrue(all(w["validated_status"] == "UNDETERMINED" for w in q_doc["warnings"]))
        finally:
            if escape_link.exists() or escape_link.is_symlink():
                if os.name == "nt":
                    os.rmdir(escape_link)
                else:
                    escape_link.unlink()

        # Also verify explicit --path-map outside source_root via CLI fails closed with exit code 2 before scanning
        bad_map_out = self.tmp_path / "bad_cli_map_out"
        res_bad_map = _run_prepared_cli(
            self.prepared_source,
            [
                "scan", str(self.target_java),
                "--rules-path", str(self.rules),
                "--output-dir", str(bad_map_out),
                "--local-triage",
                "--no-llm",
                "--path-map", f"/mnt/x/outside={outside_dir}",
            ],
        )
        self.assertEqual(res_bad_map.returncode, 2)
        self.assertFalse((bad_map_out / "triage" / "review.sqlite").exists())


if __name__ == "__main__":
    unittest.main()
