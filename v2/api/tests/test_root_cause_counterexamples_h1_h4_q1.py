"""Root-cause counterexample regression suite for independent audit findings H-01, Q-01, H-02, H-03, H-04.

Locked BEFORE fixes (expected RED on pre-fix code) and verified AFTER fixes (expected GREEN):
- Group A (H-01): Health readiness linearization consistency (CE-01 rules mutated during Ollama,
  CE-02 TTL expired during Ollama, rules/config mutated before decision, stale probe generation
  discarded, concurrent GETs without holding lock across Ollama HTTP).
- Group B (Q-01): Java helper gate type-evidence fail-closed contract (CE-08 custom receiver full
  vs truncated snippet, all conventional undeclared names, verified servlet/library receiver,
  two classes same method name, shadowing, System shadowing, overload, unknown/var type) tested
  end-to-end through `analyze_flow_dependencies()` -> `apply_integration_gate()`.
- Group C (H-02): Cancellation & cleanup failure propagation (CE-03 `clean=False` under cancellation
  must preserve `CLEANUP_FAILED` across `intake._run_git_step`, `OpenGrepHealthProbe`, `shutdown()`,
  `get_status()`, and `ThesisApiServer.server_close()`; timeout cleanup failure; clean cancel/timeout;
  registry fail-closed; unrelated sibling process untouched).
- Group D (H-03): Fixed-scope CWE-22 + CWE-89 canary oracle (CE-06 CWE-89-only & CWE-22-only rules
  rejected, malformed/truthy/wrong-line/wrong-file `dataflow_trace` rejected, missing required
  envelope fields `version`/`errors`/`paths.scanned` rejected, safe SQL + safe Path violations
  rejected, genuine OpenGrep 1.25.0 passes).
- Group E (H-04): Full execution-chain identity & immutable canary rules snapshot (CE-07 indirect
  Python dependency imported by bridge changes identity and invalidates health immediately,
  wrapper/bridge change, immutable rules snapshot scanned by OpenGrep + mid-probe mutation rejected,
  WSL distro/path detection + probe-time WSL binary SHA-256 verification + honest TTL scope
  disclosure + fail-closed when WSL identity check fails, restart/TTL isolation).
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.request import Request, urlopen

from v2.api import intake
from v2.api.config import ApiConfig, DEFAULT_BACKEND_RULES
from v2.api.java_context_v2 import analyze_flow_dependencies
from v2.api.opengrep_runner import (
    HEALTH_CANARY_FILENAME,
    HEALTH_CANARY_PATH_LINE,
    HEALTH_CANARY_SQL_LINE,
    OpenGrepHealthProbe,
    inspect_opengrep_binary_identity,
    inspect_rules_for_canary,
    verify_canary_scan_output,
)
from v2.api.server import ThesisApiServer
from v2.api.service import TriageApiService
from v2.api.tests.test_backend_quality_repairs import _make_record, _supported_assessment
from v2.api.tests.test_health_opengrep_active_probe import (
    TEST_TOKEN,
    VALID_MINIMAL_RULES_YAML,
    _is_os_pid_alive,
    _make_mock_ollama_server,
    _resolve_real_opengrep_binary,
    _write_canary_wrapper,
)
from v2.api.triage_gate import apply_integration_gate
from v2.triage.evidence import digest


RULES_ONLY_CWE89_YAML = (
    "rules:\n"
    "  - id: ntk.test.java.cwe89.sql-injection\n"
    "    mode: taint\n"
    "    languages: [java]\n"
    "    severity: ERROR\n"
    "    message: test cwe89 only\n"
    "    metadata:\n"
    "      cwe:\n"
    "        - 'CWE-89: SQL Injection'\n"
)

RULES_ONLY_CWE22_YAML = (
    "rules:\n"
    "  - id: ntk.test.java.cwe22.path-traversal\n"
    "    mode: taint\n"
    "    languages: [java]\n"
    "    severity: ERROR\n"
    "    message: test cwe22 only\n"
    "    metadata:\n"
    "      cwe:\n"
    "        - 'CWE-22: Path Traversal'\n"
)


def _http_get_json(url: str, token: str = TEST_TOKEN) -> tuple[int, dict, bytes]:
    req = Request(url, headers={"Authorization": f"Bearer {token}", "Connection": "close"}, method="GET")
    with urlopen(req, timeout=15) as resp:
        raw = resp.read()
        return resp.status, json.loads(raw.decode("utf-8")), raw


class GroupAHealthConsistencyTests(unittest.TestCase):
    """H-01: Linearization point consistency between OpenGrep snapshot, rules SHA-256, TTL, and HTTP response."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ntk_rc_h01_")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.rules_file = self.root / "rules.yml"
        self.rules_file.write_text(VALID_MINIMAL_RULES_YAML, encoding="utf-8")
        self.ol_srv, self.ol_th, self.ollama_url = _make_mock_ollama_server(installed=True)
        self.addCleanup(lambda: (self.ol_srv.shutdown(), self.ol_th.join(timeout=2.0), self.ol_srv.server_close()))

    def _make_config(self, og_bin: str, *, ttl: float = 300.0, ollama_url: str | None = None) -> ApiConfig:
        return ApiConfig(
            host="127.0.0.1",
            port=0,
            data_dir=self.root / f"data_{time.monotonic_ns()}",
            rules_path=self.rules_file,
            opengrep_binary=og_bin,
            ollama_endpoint=ollama_url or self.ollama_url,
            ollama_model="qwen3.5:9b-q4_K_M",
            api_token=TEST_TOKEN,
            read_auth_mode="required",
            opengrep_health_probe_ttl_seconds=ttl,
        )

    def test_ce01_rules_mutated_during_ollama_inventory_returns_degraded_and_consistent_sha(self) -> None:
        """CE-01: If rules.yml mutates while probe_ollama() is running, health() MUST return DEGRADED, never OK."""
        w, _ = _write_canary_wrapper(self.root / "ce01_og")
        cfg = self._make_config(str(w))
        svc = TriageApiService(cfg)
        self.addCleanup(svc.shutdown_opengrep_probe)

        self.assertTrue(svc.start_opengrep_probe())
        self.assertTrue(svc.wait_for_opengrep_probe(timeout=10.0))
        sha_v1 = digest(self.rules_file.read_bytes())
        h_before = svc.health(authenticated=True)
        self.assertEqual(h_before["status"], "OK")
        self.assertEqual(h_before["opengrep"]["rules_sha256"], sha_v1)
        self.assertEqual(h_before["rules"]["sha256"], sha_v1)

        orig_probe_ollama = svc.probe_ollama
        sha_v2_box: dict[str, str] = {}

        def mutate_during_ollama() -> dict:
            res = orig_probe_ollama()
            self.rules_file.write_text(VALID_MINIMAL_RULES_YAML + "# mutated during ollama call\n", encoding="utf-8")
            sha_v2_box["sha"] = digest(self.rules_file.read_bytes())
            return res

        with patch.object(svc, "probe_ollama", side_effect=mutate_during_ollama):
            h_after = svc.health(authenticated=True)

        sha_v2 = sha_v2_box["sha"]
        self.assertNotEqual(sha_v1, sha_v2)
        self.assertEqual(h_after["status"], "DEGRADED", f"CE-01 REPRODUCED: health returned OK after rules changed! {h_after}")
        self.assertFalse(h_after["opengrep"]["available"])
        self.assertFalse(h_after["opengrep"]["runtime_verified"])
        self.assertEqual(h_after["opengrep"]["rules_sha256"], sha_v2)
        self.assertEqual(h_after["rules"]["sha256"], sha_v2)
        self.assertEqual(h_after["opengrep"]["invalidation_reason"], "RULES_SHA256_CHANGED")

    def test_ce02_ttl_expires_during_ollama_inventory_returns_degraded_expired(self) -> None:
        """CE-02: If snapshot TTL expires while probe_ollama() runs, health() MUST return DEGRADED/EXPIRED."""
        clock_box = {"t": 5000.0}
        w, _ = _write_canary_wrapper(self.root / "ce02_og")
        cfg = self._make_config(str(w), ttl=60.0)
        svc = TriageApiService(cfg)
        svc._opengrep_probe = OpenGrepHealthProbe(cfg, clock=lambda: clock_box["t"])
        self.addCleanup(svc.shutdown_opengrep_probe)

        self.assertTrue(svc.start_opengrep_probe())
        self.assertTrue(svc.wait_for_opengrep_probe(timeout=10.0))
        self.assertEqual(svc.health(authenticated=True)["status"], "OK")

        orig_probe_ollama = svc.probe_ollama

        def expire_during_ollama() -> dict:
            res = orig_probe_ollama()
            clock_box["t"] += 61.0  # TTL expires mid-request!
            return res

        with patch.object(svc, "probe_ollama", side_effect=expire_during_ollama):
            h_exp = svc.health(authenticated=True)

        self.assertEqual(h_exp["status"], "DEGRADED", f"CE-02 REPRODUCED: expired snapshot returned OK! {h_exp}")
        self.assertFalse(h_exp["opengrep"]["available"])
        self.assertFalse(h_exp["opengrep"]["runtime_verified"])
        self.assertEqual(h_exp["opengrep"]["probe_status"], "EXPIRED")
        self.assertEqual(h_exp["opengrep"]["invalidation_reason"], "SNAPSHOT_EXPIRED")
        self.assertIn("OPENGREP_NOT_VERIFIED", h_exp["degraded_reasons"])

    def test_h01_rules_deleted_or_wrapper_mutated_before_decision_returns_degraded(self) -> None:
        w, script = _write_canary_wrapper(self.root / "h01_del_og")
        cfg = self._make_config(str(w))
        svc = TriageApiService(cfg)
        self.addCleanup(svc.shutdown_opengrep_probe)
        self.assertTrue(svc.start_opengrep_probe())
        self.assertTrue(svc.wait_for_opengrep_probe(timeout=10.0))
        self.assertEqual(svc.health(authenticated=True)["status"], "OK")

        orig_ol = svc.probe_ollama

        def mutate_wrapper_during_ollama() -> dict:
            res = orig_ol()
            script.write_text(script.read_text(encoding="utf-8") + "\n# changed mid-health\n", encoding="utf-8")
            return res

        with patch.object(svc, "probe_ollama", side_effect=mutate_wrapper_during_ollama):
            h_bin = svc.health(authenticated=True)
        self.assertEqual(h_bin["status"], "DEGRADED")
        self.assertFalse(h_bin["opengrep"]["available"])
        self.assertEqual(h_bin["opengrep"]["invalidation_reason"], "BINARY_IDENTITY_CHANGED")

        self.assertTrue(svc.wait_for_opengrep_probe(timeout=10.0))
        self.assertEqual(svc.health(authenticated=True)["status"], "OK")

        def delete_rules_during_ollama() -> dict:
            res = orig_ol()
            self.rules_file.unlink()
            return res

        with patch.object(svc, "probe_ollama", side_effect=delete_rules_during_ollama):
            h_del = svc.health(authenticated=True)
        self.assertEqual(h_del["status"], "DEGRADED")
        self.assertFalse(h_del["opengrep"]["available"])
        self.assertFalse(h_del["rules"]["available"])
        self.assertIsNone(h_del["rules"]["sha256"])
        self.assertIsNone(h_del["opengrep"]["rules_sha256"])
        self.assertIn("RULES_UNAVAILABLE", h_del["degraded_reasons"])

    def test_h01_stale_probe_worker_after_invalidation_generation_discarded_and_not_stuck(self) -> None:
        """Old worker completing after rules/force invalidation must NOT commit stale VERIFIED or stick _in_flight."""
        entered = threading.Event()
        release = threading.Event()
        w, _ = _write_canary_wrapper(self.root / "h01_gen_og")
        cfg = self._make_config(str(w))
        probe = OpenGrepHealthProbe(cfg)
        self.addCleanup(probe.shutdown)

        real_exec = probe._execute_probe_once
        call_num = {"n": 0}

        def gated_exec():
            call_num["n"] += 1
            my_call = call_num["n"]
            res = real_exec()
            if my_call == 1:
                entered.set()
                release.wait(timeout=5.0)
            return res

        with patch.object(probe, "_execute_probe_once", side_effect=gated_exec):
            self.assertTrue(probe.start_background_probe())
            self.assertTrue(entered.wait(timeout=5.0))
            # Force invalidation (epoch bump) while worker 1 is still finishing with old rules
            st_mid = probe.get_status(trigger_refresh=False, force=True)
            self.assertFalse(st_mid["available"])
            release.set()
            self.assertTrue(probe.wait_for_probe(timeout=5.0))

            # Stale worker 1 MUST have been discarded AND _in_flight cleared so new probe can run!
            st_after_stale = probe.get_status(trigger_refresh=False)
            self.assertFalse(
                st_after_stale["available"],
                f"Stale probe from invalidated generation must NEVER commit VERIFIED: {st_after_stale}",
            )
            self.assertFalse(st_after_stale["probe_in_progress"])

            # Fresh probe runs cleanly and reaches VERIFIED
            self.assertTrue(probe.start_background_probe())
            self.assertTrue(probe.wait_for_probe(timeout=5.0))
            st_fresh = probe.get_status(trigger_refresh=False)
            self.assertTrue(st_fresh["available"])
            self.assertEqual(st_fresh["probe_status"], "VERIFIED")

    def test_h01_concurrent_get_does_not_hold_probe_lock_across_slow_ollama_and_stays_consistent(self) -> None:
        """Slow Ollama HTTP must not hold OpenGrepHealthProbe._lock; concurrent GETs must run concurrently and never lie."""
        slow_delay = 0.35

        class SlowOllamaHandler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                return

            def do_GET(self):
                time.sleep(slow_delay)
                raw = json.dumps({"models": [{"name": "qwen3.5:9b-q4_K_M", "digest": "sha256:slow"}]}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        slow_ol = ThreadingHTTPServer(("127.0.0.1", 0), SlowOllamaHandler)
        slow_th = threading.Thread(target=slow_ol.serve_forever, daemon=True)
        slow_th.start()
        self.addCleanup(lambda: (slow_ol.shutdown(), slow_th.join(timeout=2.0), slow_ol.server_close()))
        slow_url = f"http://127.0.0.1:{slow_ol.server_address[1]}"

        w, _ = _write_canary_wrapper(self.root / "h01_conc_og")
        srv = ThesisApiServer(self._make_config(str(w), ollama_url=slow_url))
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        self.addCleanup(lambda: (srv.shutdown(), th.join(timeout=3.0), srv.server_close()))
        base = f"http://127.0.0.1:{srv.server_address[1]}"

        self.assertTrue(srv.service.wait_for_opengrep_probe(timeout=10.0))

        # Launch 5 concurrent GETs; mutate rules midway while Ollama sleeps.
        barrier = threading.Barrier(5)
        responses: list[dict] = []
        rlock = threading.Lock()

        def worker():
            barrier.wait(timeout=3.0)
            _, doc, _ = _http_get_json(f"{base}/api/health")
            with rlock:
                responses.append(doc)

        t0 = time.monotonic()
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        time.sleep(0.12)
        self.rules_file.write_text(VALID_MINIMAL_RULES_YAML + "# concurrent mutation\n", encoding="utf-8")
        new_sha = digest(self.rules_file.read_bytes())
        for t in threads:
            t.join(timeout=10.0)
        elapsed = time.monotonic() - t0

        self.assertEqual(len(responses), 5)
        # If lock were held during slow_delay=0.35s, 5 serialized calls would take >= 1.75s.
        self.assertLess(elapsed, 1.4, f"Ollama calls appeared serialized under lock ({elapsed:.2f}s)")
        for doc in responses:
            # Every single response MUST be internally consistent: never OK with mismatched SHA!
            if doc["status"] == "OK":
                self.assertTrue(doc["opengrep"]["available"])
                self.assertEqual(doc["opengrep"]["rules_sha256"], doc["rules"]["sha256"])
            else:
                self.assertEqual(doc["opengrep"]["rules_sha256"], doc["rules"]["sha256"])
        # Because rules mutated at 0.12s while Ollama took 0.35s, all 5 decisions happened AFTER mutation -> all DEGRADED!
        for doc in responses:
            self.assertEqual(doc["status"], "DEGRADED", f"Concurrent GET after rules mutation returned OK: {doc}")
            self.assertEqual(doc["rules"]["sha256"], new_sha)
            self.assertEqual(doc["opengrep"]["rules_sha256"], new_sha)


class GroupBJavaTypeEvidenceTests(unittest.TestCase):
    """Q-01: Receiver variable name must NEVER prove stdlib/library contract when type evidence is missing."""

    def _run_gate_on_code(self, code: str, *, rel_path: str = "Demo.java", sink_line: int, source_line: int,
                          extra_files: dict[str, str] | None = None,
                          strip_type_evidence: bool = False) -> tuple[dict, dict]:
        with tempfile.TemporaryDirectory(prefix="ntk_rc_q01_") as td:
            rec = _make_record(
                Path(td),
                rel_path,
                code,
                sink_line=sink_line,
                source_line=source_line,
                extra_files=extra_files,
            )
            if strip_type_evidence:
                # Simulate truncated snippet where parameter/local/field type declaration & disk root are absent
                rec["root"] = str(Path(td) / "nonexistent_root_for_truncation")
                primary = rec["snippets"][0]
                primary["lines"] = [
                    ln for ln in primary["lines"]
                    if ln["line"] >= source_line
                ]
                jctx = dict(rec.get("java_context") or {})
                enc = dict(jctx.get("enclosing_method") or {})
                enc["parameters"] = []
                enc["header_line"] = source_line - 1
                jctx["enclosing_method"] = enc
                jctx.pop("enclosing_class_field_types", None)
                rec["java_context"] = jctx
            dep = analyze_flow_dependencies(rec)
            gated = apply_integration_gate(rec, _supported_assessment(rec, sink_line))
            return dep, gated

    def test_ce08_custom_receiver_full_vs_truncated_both_fail_closed(self) -> None:
        """CE-08: Removing CustomReq declaration from snippet MUST NOT upgrade UNDETERMINED to SUPPORTED."""
        code = (
            "import java.io.*;\n"
            "public class CustomReqApp {\n"
            "    void handle(CustomReq req) throws Exception {\n"
            '        String f = req.getParameter("f");\n'
            '        new FileInputStream("/tmp/" + f);\n'
            "    }\n"
            "}\n"
        )
        dep_full, gated_full = self._run_gate_on_code(code, sink_line=5, source_line=4, strip_type_evidence=False)
        self.assertTrue(dep_full["has_unverified_helper_dependency"], dep_full)
        self.assertEqual(gated_full["validated_status"], "UNDETERMINED")
        self.assertEqual(gated_full["failure_kind"], "UNVERIFIED_HELPER_FLOW")

        dep_trunc, gated_trunc = self._run_gate_on_code(code, sink_line=5, source_line=4, strip_type_evidence=True)
        self.assertTrue(
            dep_trunc["has_unverified_helper_dependency"],
            f"CE-08 REPRODUCED: truncated CustomReq `req` bypassed helper gate! dep={dep_trunc}",
        )
        self.assertEqual(gated_trunc["validated_status"], "UNDETERMINED")
        self.assertEqual(gated_trunc["failure_kind"], "UNVERIFIED_HELPER_FLOW")

    def test_q01_all_conventional_undeclared_receivers_and_chains_fail_closed(self) -> None:
        """None of req/request/resp/stmt/ps/conn/jdbc/log/out/sb may bypass helper verification without type evidence."""
        cases = [
            ("undeclared_request", 'String f = request.getParameter("f");', 'new FileInputStream("/tmp/" + f);'),
            ("undeclared_chained_req", 'Object o = req.getSession().getAttribute("k");', 'new FileInputStream("/tmp/" + o);'),
            ("undeclared_stmt", 'Object rs = stmt.executeQuery("SELECT 1");', 'new FileInputStream("/tmp/" + rs);'),
            ("undeclared_resp", 'Object w = resp.getWriter();', 'new FileInputStream("/tmp/" + w);'),
            ("undeclared_conn", 'Object ps = conn.prepareStatement("SELECT 1");', 'new FileInputStream("/tmp/" + ps);'),
            ("undeclared_sb", 'Object s = sb.append("x");', 'new FileInputStream("/tmp/" + s);'),
        ]
        for label, line4, line5 in cases:
            with self.subTest(case=label):
                code = (
                    "import java.io.*;\n"
                    "import javax.servlet.http.*;\n"
                    "import java.sql.*;\n"
                    "public class TruncApp {\n"
                    "    void handle(CustomHolder req, CustomHolder request, CustomHolder stmt, CustomHolder resp, CustomHolder conn, CustomHolder sb) throws Exception {\n"
                    f"        {line4}\n"
                    f"        {line5}\n"
                    "    }\n"
                    "}\n"
                )
                dep, gated = self._run_gate_on_code(code, sink_line=7, source_line=6, strip_type_evidence=True)
                self.assertTrue(
                    dep["has_unverified_helper_dependency"],
                    f"Undeclared receiver `{label}` bypassed helper gate! dep={dep}",
                )
                self.assertEqual(gated["validated_status"], "UNDETERMINED")
                self.assertEqual(gated["failure_kind"], "UNVERIFIED_HELPER_FLOW")

    def test_q01_verified_servlet_receiver_remains_supported(self) -> None:
        """Proven HttpServletRequest receiver with real declaration + import MUST remain SUPPORTED."""
        code = (
            "import java.io.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class ValidServletApp {\n"
            "    void handle(HttpServletRequest req) throws Exception {\n"
            '        String f = req.getParameter("f");\n'
            '        new FileInputStream("/tmp/" + f);\n'
            "    }\n"
            "}\n"
        )
        dep, gated = self._run_gate_on_code(code, sink_line=6, source_line=5, strip_type_evidence=False)
        self.assertFalse(dep["has_unverified_helper_dependency"], f"Valid servlet falsely downgraded: {dep}")
        self.assertEqual(gated["validated_status"], "SUPPORTED")

    def test_q01_two_classes_same_method_name_shadowing_overload_and_unknown_type(self) -> None:
        # 1. Two classes with same method name `getParameter`: CustomRequest vs HttpServletRequest
        code_two_cls = (
            "package app;\n"
            "import java.io.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class TwoClassApp {\n"
            "    void handle(CustomRequest req, HttpServletRequest httpReq) throws Exception {\n"
            '        String a = httpReq.getParameter("a");\n'
            '        String b = req.getParameter(a);\n'
            '        new FileInputStream("/tmp/" + b);\n'
            "    }\n"
            "}\n"
        )
        dep1, gated1 = self._run_gate_on_code(code_two_cls, rel_path="app/TwoClassApp.java", sink_line=8, source_line=6)
        self.assertTrue(dep1["has_unverified_helper_dependency"], dep1)
        self.assertEqual(gated1["validated_status"], "UNDETERMINED")

        # 2. Field shadowing: class field is HttpServletRequest `req`, local param shadows `req` with CustomReq
        code_shadow = (
            "import java.io.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class ShadowFieldApp {\n"
            "    private HttpServletRequest req;\n"
            "    void handle(CustomReq req) throws Exception {\n"
            '        String f = req.getParameter("f");\n'
            '        new FileInputStream("/tmp/" + f);\n'
            "    }\n"
            "}\n"
        )
        dep2, gated2 = self._run_gate_on_code(code_shadow, sink_line=7, source_line=6)
        self.assertTrue(dep2["has_unverified_helper_dependency"], dep2)
        self.assertEqual(gated2["validated_status"], "UNDETERMINED")

        # 3. `System` variable shadowing `java.lang.System`: `System.out.println(...)` must NOT resolve as stdlib!
        code_sys_shadow = (
            "import java.io.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class ShadowSystemApp {\n"
            "    void handle(HttpServletRequest req, CustomSystem System) throws Exception {\n"
            '        String f = req.getParameter("f");\n'
            "        String res = System.out.format(f);\n"
            '        new FileInputStream("/tmp/" + res);\n'
            "    }\n"
            "}\n"
        )
        dep3, gated3 = self._run_gate_on_code(code_sys_shadow, sink_line=7, source_line=5)
        self.assertTrue(dep3["has_unverified_helper_dependency"], dep3)
        self.assertEqual(gated3["validated_status"], "UNDETERMINED")

        # 4. Same-arity overload ambiguity in helper class
        code_overload = (
            "import java.io.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class OverloadApp {\n"
            "    private String clean(String x) { return x; }\n"
            "    private String clean(Object x) { return String.valueOf(x); }\n"
            "    void handle(HttpServletRequest req) throws Exception {\n"
            '        String f = clean(req.getParameter("f"));\n'
            '        new FileInputStream("/tmp/" + f);\n'
            "    }\n"
            "}\n"
        )
        dep4, gated4 = self._run_gate_on_code(code_overload, sink_line=8, source_line=7)
        self.assertTrue(dep4["has_unverified_helper_dependency"], dep4)
        self.assertEqual(gated4["validated_status"], "UNDETERMINED")

        # 5. Unknown / `var` receiver type
        code_var = (
            "import java.io.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class VarApp {\n"
            "    void handle(HttpServletRequest raw) throws Exception {\n"
            "        var req = raw;\n"
            '        String f = req.getParameter("f");\n'
            '        new FileInputStream("/tmp/" + f);\n'
            "    }\n"
            "}\n"
        )
        dep5, gated5 = self._run_gate_on_code(code_var, sink_line=7, source_line=6)
        self.assertTrue(dep5["has_unverified_helper_dependency"], dep5)
        self.assertEqual(gated5["validated_status"], "UNDETERMINED")


class GroupCCancellationAndCleanupTests(unittest.TestCase):
    """H-02: CLEANUP_FAILED priority over CANCELLED / TIMEOUT / SHUTTING_DOWN across launcher, probe, and server."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ntk_rc_h02_")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.rules_file = self.root / "rules.yml"
        self.rules_file.write_text(VALID_MINIMAL_RULES_YAML, encoding="utf-8")
        self.ol_srv, self.ol_th, self.ollama_url = _make_mock_ollama_server(installed=True)
        self.addCleanup(lambda: (self.ol_srv.shutdown(), self.ol_th.join(timeout=2.0), self.ol_srv.server_close()))
        self.addCleanup(self._cleanup_intake_state)

    def _cleanup_intake_state(self) -> None:
        intake._reconcile_lingering_git_jobs(2.0)
        with intake._LINGERING_LOCK:
            intake._REGISTRY_FAULT = False
            intake._LINGERING_GIT_TREES[:] = [
                e for e in intake._LINGERING_GIT_TREES if e.get("state") != intake._STATE_CLOSED
            ]

    def test_ce03_cancellation_with_clean_false_preserves_cleanup_failed_end_to_end(self) -> None:
        """CE-03: Fault injection clean=False during cancellation MUST report CLEANUP_FAILED across all 3 layers."""
        # Spawn an unrelated control process to prove cancellation/cleanup NEVER kills unrelated processes!
        control_proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        self.addCleanup(lambda: (control_proc.kill() if control_proc.poll() is None else None, control_proc.wait(timeout=3)))

        pid_file = self.root / "ce03_og" / "pids.txt"
        w, _ = _write_canary_wrapper(
            self.root / "ce03_og",
            sleep_version=25.0,
            spawn_grandchild_pid_file=pid_file,
        )

        # Layer 1 direct check on intake._run_git_step with cancel_event + clean=False fault injection
        real_finalize = intake._finalize_tree_safe
        fault_active = {"on": True}
        retained_entries: list[dict] = []

        def inject_cleanup_fail(entry, step, deadline):
            if fault_active["on"] and step.startswith("opengrep-health-"):
                # Keep entry PENDING in registry (fail-closed) without closing/confirming clean!
                intake._transition(entry, intake._STATE_PENDING, terminal=True)
                retained_entries.append(entry)
                return {
                    "step": step,
                    "ownership": "JOB_OBJECT_BEFORE_RESUME" if entry["kind"] == "job" else "PROCESS_GROUP",
                    "terminate_ok": False,
                    "root_exited": False,
                    "children_exited": False,
                    "remaining_processes": 1,
                    "handle_closed": False,
                    "job_closed": False,
                    "registry_state": intake._STATE_PENDING,
                    "registry_safe": True,
                    "clean": False,
                    "cleanup_error": "InjectedCleanupFailure",
                }
            return real_finalize(entry, step, deadline)

        srv = ThesisApiServer(
            ApiConfig(
                host="127.0.0.1",
                port=0,
                data_dir=self.root / "ce03_data",
                rules_path=self.rules_file,
                opengrep_binary=str(w),
                ollama_endpoint=self.ollama_url,
                api_token=TEST_TOKEN,
                opengrep_health_probe_timeout_seconds=25.0,
            )
        )
        # Replace startup probe cleanly before starting our fault-injected scenario
        srv.service.shutdown_opengrep_probe(wait_seconds=3.0)
        srv.service._opengrep_probe = OpenGrepHealthProbe(srv.api_config)

        try:
            with patch.object(intake, "_finalize_tree_safe", side_effect=inject_cleanup_fail):
                self.assertTrue(srv.service.start_opengrep_probe())
                deadline = time.monotonic() + 5.0
                while not pid_file.is_file() and time.monotonic() < deadline:
                    time.sleep(0.05)

                # Close server while probe is running -> triggers cancel_event + injected clean=False!
                srv.server_close()

                # Layer 3: server_close() MUST record structured CLEANUP_FAILED, NOT drop it silently!
                sd_report = getattr(srv, "last_probe_shutdown_status", None)
                self.assertIsInstance(sd_report, dict, "server_close() must record last_probe_shutdown_status")
                self.assertFalse(sd_report["clean"], f"CE-03 REPRODUCED: shutdown claimed clean=True! {sd_report}")
                self.assertEqual(sd_report.get("status"), "CLEANUP_FAILED", sd_report)
                self.assertFalse(sd_report.get("job_closed", True))
                self.assertEqual(sd_report.get("registry_state"), intake._STATE_PENDING)

                # Layer 2: probe.get_status() after shutdown MUST report CLEANUP_FAILED, NOT mask as SHUTTING_DOWN!
                post_status = srv.service.probe_opengrep(trigger_refresh=False)
                self.assertFalse(post_status["available"])
                self.assertEqual(
                    post_status["probe_status"],
                    "CLEANUP_FAILED",
                    f"CE-03 REPRODUCED: probe_status masked cleanup failure as {post_status['probe_status']}!",
                )
                self.assertEqual(post_status["failure_code"], "PROBE_CLEANUP_FAILED")

                # Registry MUST remain fail-closed blocking new launches while PENDING!
                with intake._LINGERING_LOCK:
                    self.assertTrue(intake._launch_blocked_locked(), "Registry must stay fail-closed while PENDING!")

                # Control process MUST NOT be killed!
                self.assertIsNone(control_proc.poll(), "Control sibling process was wrongly terminated!")
        finally:
            fault_active["on"] = False
            # Now reconcile cleanly so no real test subprocess leaks
            self.assertEqual(intake._reconcile_lingering_git_jobs(3.0), 0)

    def test_h02_intake_direct_cancel_with_clean_false_raises_cleanup_failed(self) -> None:
        """Direct launcher contract: cancel_event + clean=False MUST raise _GitStepCleanupFailed, not _GitStepCancelled."""
        cancel_ev = threading.Event()
        real_finalize = intake._finalize_tree_safe

        def fail_once(entry, step, deadline):
            intake._transition(entry, intake._STATE_PENDING, terminal=True)
            return {"step": step, "clean": False, "root_exited": False, "remaining_processes": 1, "handle_closed": False}

        def trigger_cancel():
            time.sleep(0.2)
            cancel_ev.set()

        th = threading.Thread(target=trigger_cancel, daemon=True)
        th.start()
        try:
            with patch.object(intake, "_finalize_tree_safe", side_effect=fail_once):
                with self.assertRaises(intake._GitStepCleanupFailed) as ctx:
                    intake._run_git_step(
                        "opengrep-health-cancel-ce03",
                        [sys.executable, "-c", "import time; time.sleep(20)"],
                        timeout_seconds=15.0,
                        env=os.environ.copy(),
                        cancel_event=cancel_ev,
                    )
                self.assertFalse(ctx.exception.cleanup["clean"])
                self.assertEqual(getattr(ctx.exception, "primary_outcome", None), "cancelled")
        finally:
            self.assertEqual(intake._reconcile_lingering_git_jobs(3.0), 0)

    def test_h02_clean_cancellation_and_timeout_cleanup_failure_distinguished(self) -> None:
        """Clean cancellation reports clean=True/SHUTTING_DOWN; timeout with clean=False reports CLEANUP_FAILED."""
        # 1. Clean cancellation
        w_slow, _ = _write_canary_wrapper(self.root / "h02_clean_cancel", sleep_version=20.0)
        cfg = ApiConfig(
            host="127.0.0.1",
            port=0,
            data_dir=self.root / "h02_clean_data",
            rules_path=self.rules_file,
            opengrep_binary=str(w_slow),
            ollama_endpoint=self.ollama_url,
            api_token=TEST_TOKEN,
            opengrep_health_probe_timeout_seconds=20.0,
        )
        probe = OpenGrepHealthProbe(cfg)
        self.assertTrue(probe.start_background_probe())
        time.sleep(0.25)
        sd = probe.shutdown(wait_seconds=4.0)
        self.assertTrue(sd["clean"], sd)
        self.assertTrue(sd["worker_stopped"], sd)
        self.assertEqual(sd["status"], "SHUTTING_DOWN")
        self.assertEqual(probe.get_status(trigger_refresh=False)["probe_status"], "SHUTTING_DOWN")

        # 2. Timeout with cleanup failure -> CLEANUP_FAILED (not TIMEOUT)
        w_to, _ = _write_canary_wrapper(self.root / "h02_to_fail", sleep_scan=20.0)
        cfg_to = ApiConfig(
            host="127.0.0.1",
            port=0,
            data_dir=self.root / "h02_to_data",
            rules_path=self.rules_file,
            opengrep_binary=str(w_to),
            ollama_endpoint=self.ollama_url,
            api_token=TEST_TOKEN,
            opengrep_health_probe_timeout_seconds=0.8,
        )
        probe_to = OpenGrepHealthProbe(cfg_to)
        real_fin = intake._finalize_tree_safe

        def fail_canary_cleanup(entry, step, deadline):
            if step == "opengrep-health-canary":
                intake._transition(entry, intake._STATE_PENDING, terminal=True)
                return {"step": step, "clean": False, "root_exited": False, "remaining_processes": 1, "handle_closed": False}
            return real_fin(entry, step, deadline)

        try:
            with patch.object(intake, "_finalize_tree_safe", side_effect=fail_canary_cleanup):
                self.assertTrue(probe_to.start_background_probe())
                self.assertTrue(probe_to.wait_for_probe(timeout=10.0))
                st = probe_to.get_status(trigger_refresh=False)
                self.assertFalse(st["available"])
                self.assertEqual(st["probe_status"], "CLEANUP_FAILED")
                self.assertEqual(st["failure_code"], "PROBE_CLEANUP_FAILED")
        finally:
            self.assertEqual(intake._reconcile_lingering_git_jobs(3.0), 0)
            probe_to.shutdown(wait_seconds=2.0)


class GroupDCanaryOracleTests(unittest.TestCase):
    """H-03: Fixed CWE-22 + CWE-89 canary scope, structured OpenGrep dataflow_trace, envelope, and dual safe controls."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ntk_rc_h03_")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.ol_srv, self.ol_th, self.ollama_url = _make_mock_ollama_server(installed=True)
        self.addCleanup(lambda: (self.ol_srv.shutdown(), self.ol_th.join(timeout=2.0), self.ol_srv.server_close()))

    def _valid_canary_doc(self) -> dict:
        jf = f"C:/tmp/{HEALTH_CANARY_FILENAME}"
        return {
            "version": "1.25.0",
            "errors": [],
            "paths": {"scanned": [jf]},
            "results": [
                {
                    "check_id": "ntk.test.java.cwe89.sql-injection",
                    "path": jf,
                    "start": {"line": HEALTH_CANARY_SQL_LINE, "col": 9, "offset": 297},
                    "end": {"line": HEALTH_CANARY_SQL_LINE, "col": 62, "offset": 350},
                    "extra": {
                        "message": "CWE-89 finding",
                        "severity": "ERROR",
                        "metadata": {"cwe": ["CWE-89: SQL Injection"]},
                        "dataflow_trace": {
                            "taint_source": [
                                "CliLoc",
                                [
                                    {
                                        "path": jf,
                                        "start": {"line": 9, "col": 21, "offset": 265},
                                        "end": {"line": 9, "col": 43, "offset": 287},
                                    },
                                    'req.getParameter("id")',
                                ],
                            ],
                            "intermediate_vars": [],
                            "taint_sink": [
                                "CliLoc",
                                [
                                    {
                                        "path": jf,
                                        "start": {"line": 10, "col": 25, "offset": 313},
                                        "end": {"line": 10, "col": 61, "offset": 349},
                                    },
                                    '"SELECT * FROM users WHERE id=" + id',
                                ],
                            ],
                        },
                    },
                },
                {
                    "check_id": "ntk.test.java.cwe22.path-traversal",
                    "path": jf,
                    "start": {"line": HEALTH_CANARY_PATH_LINE, "col": 9, "offset": 484},
                    "end": {"line": HEALTH_CANARY_PATH_LINE, "col": 49, "offset": 524},
                    "extra": {
                        "message": "CWE-22 finding",
                        "severity": "ERROR",
                        "metadata": {"cwe": ["CWE-22: Path Traversal"]},
                        "dataflow_trace": {
                            "taint_source": [
                                "CliLoc",
                                [
                                    {
                                        "path": jf,
                                        "start": {"line": 14, "col": 23, "offset": 450},
                                        "end": {"line": 14, "col": 47, "offset": 474},
                                    },
                                    'req.getParameter("file")',
                                ],
                            ],
                            "intermediate_vars": [],
                            "taint_sink": [
                                "CliLoc",
                                [
                                    {
                                        "path": jf,
                                        "start": {"line": 15, "col": 9, "offset": 484},
                                        "end": {"line": 15, "col": 49, "offset": 524},
                                    },
                                    'new FileInputStream("/srv/data/" + name)',
                                ],
                            ],
                        },
                    },
                },
            ],
        }

    def test_ce06_rules_missing_cwe22_or_cwe89_rejected_in_inventory_and_api(self) -> None:
        """CE-06: Single-CWE rulesets (CWE-89 only or CWE-22 only) MUST be rejected, never VERIFIED."""
        for label, yaml_text in (("only_cwe89", RULES_ONLY_CWE89_YAML), ("only_cwe22", RULES_ONLY_CWE22_YAML)):
            with self.subTest(case=label):
                rf = self.root / f"{label}.yml"
                rf.write_text(yaml_text, encoding="utf-8")
                info = inspect_rules_for_canary(rf)
                self.assertFalse(info["ok"], f"CE-06 REPRODUCED: {label} accepted by inspect_rules_for_canary! {info}")
                self.assertEqual(info["failure_code"], "RULES_MISSING_REQUIRED_CWE")
                self.assertEqual(info["expected_cwes"], ["CWE-22", "CWE-89"])

                w, _ = _write_canary_wrapper(self.root / f"og_{label}")
                svc = TriageApiService(
                    ApiConfig(
                        host="127.0.0.1",
                        port=0,
                        data_dir=self.root / f"data_{label}",
                        rules_path=rf,
                        opengrep_binary=str(w),
                        ollama_endpoint=self.ollama_url,
                        api_token=TEST_TOKEN,
                    )
                )
                self.addCleanup(svc.shutdown_opengrep_probe)
                self.assertTrue(svc.start_opengrep_probe())
                self.assertTrue(svc.wait_for_opengrep_probe(timeout=10.0))
                h = svc.health(authenticated=True)
                self.assertEqual(h["status"], "DEGRADED")
                self.assertFalse(h["opengrep"]["available"])
                self.assertEqual(h["opengrep"]["probe_status"], "RULES_INVALID")
                self.assertEqual(h["opengrep"]["failure_code"], "RULES_MISSING_REQUIRED_CWE")

        # Defense-in-depth: even if caller passes weakened expected_cwes=["CWE-89"], verify_canary_scan_output enforces both!
        doc_only89 = self._valid_canary_doc()
        doc_only89["results"] = [doc_only89["results"][0]]
        _, scan_ver, _, fcode, _ = verify_canary_scan_output(
            json.dumps(doc_only89).encode("utf-8"),
            expected_version_tuple=(1, 25, 0),
            rules_info={
                "expected_cwes": ["CWE-89"],
                "cwe_rule_ids": {"CWE-89": ["ntk.test.java.cwe89.sql-injection"]},
                "cwe_taint_only": {"CWE-89": True},
            },
        )
        self.assertFalse(scan_ver)
        self.assertEqual(fcode, "CANARY_ORACLE_MISMATCH")

    def test_h03_malformed_truthy_or_misaligned_dataflow_trace_and_envelope_rejected(self) -> None:
        rf = self.root / "valid_rules.yml"
        rf.write_text(VALID_MINIMAL_RULES_YAML, encoding="utf-8")
        rinfo = inspect_rules_for_canary(rf)
        self.assertTrue(rinfo["ok"], rinfo)

        # Baseline valid doc MUST pass
        exec_ok, ver_ok, summary, fcode, err = verify_canary_scan_output(
            json.dumps(self._valid_canary_doc()).encode("utf-8"),
            expected_version_tuple=(1, 25, 0),
            rules_info=rinfo,
        )
        self.assertTrue(exec_ok and ver_ok, f"Baseline valid doc failed: {fcode} {err}")

        def check_rejected(mutator, label: str, *, expected_code: str | None = None) -> None:
            doc = self._valid_canary_doc()
            mutator(doc)
            _, v_ok, _, fc, _ = verify_canary_scan_output(
                json.dumps(doc).encode("utf-8"),
                expected_version_tuple=(1, 25, 0),
                rules_info=rinfo,
            )
            self.assertFalse(v_ok, f"Counterexample `{label}` unexpectedly passed canary oracle!")
            if expected_code:
                self.assertEqual(fc, expected_code, f"{label}: got {fc}")

        # 1. Truthy garbage dataflow_trace
        check_rejected(lambda d: d["results"][0]["extra"].update({"dataflow_trace": {"fake": 1}}), "truthy_dict_trace")
        check_rejected(lambda d: d["results"][0]["extra"].update({"dataflow_trace": True}), "truthy_bool_trace")
        # 2. Missing taint_source or taint_sink
        check_rejected(lambda d: d["results"][0]["extra"]["dataflow_trace"].pop("taint_source"), "missing_taint_source")
        check_rejected(lambda d: d["results"][1]["extra"]["dataflow_trace"].pop("taint_sink"), "missing_taint_sink")
        # 3. Wrong source line (line 8 instead of 9 for CWE-89; line 13 instead of 14 for CWE-22)
        check_rejected(
            lambda d: d["results"][0]["extra"]["dataflow_trace"]["taint_source"][1][0]["start"].update({"line": 8}),
            "wrong_source_line_cwe89",
        )
        check_rejected(
            lambda d: d["results"][1]["extra"]["dataflow_trace"]["taint_source"][1][0]["start"].update({"line": 13}),
            "wrong_source_line_cwe22",
        )
        # 4. Wrong sink line or wrong file in trace
        check_rejected(
            lambda d: d["results"][0]["extra"]["dataflow_trace"]["taint_sink"][1][0]["start"].update({"line": 11}),
            "wrong_sink_line_in_trace",
        )
        check_rejected(
            lambda d: d["results"][0]["extra"]["dataflow_trace"]["taint_source"][1][0].update({"path": "C:/tmp/Other.java"}),
            "wrong_file_in_trace",
        )
        # 5. Missing required envelope fields: version, errors, paths/scanned
        check_rejected(lambda d: d.pop("version"), "missing_version")
        check_rejected(lambda d: d.pop("errors"), "missing_errors")
        check_rejected(lambda d: d.pop("paths"), "missing_paths")
        check_rejected(lambda d: d["paths"].update({"scanned": []}), "empty_paths_scanned")
        # 6. Safe SQL (line 19) and Safe Path (line 23) violations both rejected
        def add_safe_finding(d: dict, line: int, cwe: str, rid: str) -> None:
            jf = f"C:/tmp/{HEALTH_CANARY_FILENAME}"
            d["results"].append({
                "check_id": rid,
                "path": jf,
                "start": {"line": line, "col": 9},
                "end": {"line": line, "col": 35},
                "extra": {"message": "fp", "severity": "ERROR", "metadata": {"cwe": [cwe]}},
            })

        check_rejected(
            lambda d: add_safe_finding(d, 19, "CWE-89", "ntk.test.java.cwe89.sql-injection"),
            "safe_sql_flagged",
            expected_code="CANARY_SAFE_CONTROL_VIOLATED",
        )
        check_rejected(
            lambda d: add_safe_finding(d, 23, "CWE-22", "ntk.test.java.cwe22.path-traversal"),
            "safe_path_flagged",
            expected_code="CANARY_SAFE_CONTROL_VIOLATED",
        )

    def test_h03_real_opengrep_1_25_0_passes_strict_oracle(self) -> None:
        real_og = _resolve_real_opengrep_binary()
        if not real_og:
            self.skipTest("Real OpenGrep binary not present")
        svc = TriageApiService(
            ApiConfig(
                host="127.0.0.1",
                port=0,
                data_dir=self.root / "real_og_data",
                rules_path=DEFAULT_BACKEND_RULES.resolve(),
                opengrep_binary=real_og,
                ollama_endpoint=self.ollama_url,
                api_token=TEST_TOKEN,
                opengrep_health_probe_timeout_seconds=30.0,
            )
        )
        self.addCleanup(svc.shutdown_opengrep_probe)
        self.assertTrue(svc.start_opengrep_probe())
        self.assertTrue(svc.wait_for_opengrep_probe(timeout=35.0))
        h = svc.health(authenticated=True)
        self.assertEqual(h["status"], "OK", h)
        self.assertEqual(h["opengrep"]["verification_level"], "SCAN_VERIFIED")
        self.assertTrue(h["opengrep"]["canary_summary"]["oracle_matched"])
        self.assertTrue(h["opengrep"]["canary_summary"]["safe_control_clean"])


class GroupEExecutionChainIdentityTests(unittest.TestCase):
    """H-04: Indirect bridge dependencies (CE-07), immutable rules snapshot, and WSL binary identity."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ntk_rc_h04_")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.rules_file = self.root / "rules.yml"
        self.rules_file.write_text(VALID_MINIMAL_RULES_YAML, encoding="utf-8")
        self.ol_srv, self.ol_th, self.ollama_url = _make_mock_ollama_server(installed=True)
        self.addCleanup(lambda: (self.ol_srv.shutdown(), self.ol_th.join(timeout=2.0), self.ol_srv.server_close()))

    def test_ce07_indirect_bridge_python_dependency_mutation_invalidates_identity_and_health(self) -> None:
        """CE-07: Mutating a local module imported by the bridge script MUST change identity and invalidate VERIFIED."""
        bdir = self.root / "ce07_chain"
        bdir.mkdir(parents=True, exist_ok=True)
        sub_mod = bdir / "bridge_sub_helper.py"
        sub_mod.write_text("VER = '1.25.0'\n", encoding="utf-8")
        helper_mod = bdir / "bridge_helper.py"
        helper_mod.write_text("import bridge_sub_helper\ndef get_ver():\n    return bridge_sub_helper.VER\n", encoding="utf-8")
        wrapper, bridge_script = _write_canary_wrapper(bdir, name="opengrep_ce07")
        # Prepend import of local helper module into bridge script
        bridge_script.write_text(
            "import bridge_helper\n_ = bridge_helper.get_ver()\n" + bridge_script.read_text(encoding="utf-8"),
            encoding="utf-8",
        )

        id1 = inspect_opengrep_binary_identity(str(wrapper))
        self.assertTrue(id1["found"])
        target_paths = {Path(t["path"]).resolve() for t in id1["wrapper_targets"]}
        self.assertIn(helper_mod.resolve(), target_paths, f"CE-07 REPRODUCED: bridge_helper.py missing from identity! {id1}")
        self.assertIn(sub_mod.resolve(), target_paths, f"CE-07 REPRODUCED: transitive bridge_sub_helper.py missing! {id1}")

        svc = TriageApiService(
            ApiConfig(
                host="127.0.0.1",
                port=0,
                data_dir=self.root / "ce07_data",
                rules_path=self.rules_file,
                opengrep_binary=str(wrapper),
                ollama_endpoint=self.ollama_url,
                api_token=TEST_TOKEN,
            )
        )
        self.addCleanup(svc.shutdown_opengrep_probe)
        self.assertTrue(svc.start_opengrep_probe())
        self.assertTrue(svc.wait_for_opengrep_probe(timeout=10.0))
        h1 = svc.health(authenticated=True)
        self.assertEqual(h1["status"], "OK")
        sha1 = h1["opengrep"]["binary_identity_sha256"]

        # Mutate ONLY the indirect transitive dependency `bridge_sub_helper.py` without touching wrapper or bridge!
        sub_mod.write_text("VER = '1.25.0'\n# indirect mutation\n", encoding="utf-8")
        id2 = inspect_opengrep_binary_identity(str(wrapper))
        self.assertNotEqual(id1["binary_identity_sha256"], id2["binary_identity_sha256"])

        h2 = svc.health(authenticated=True)
        self.assertEqual(h2["status"], "DEGRADED", f"CE-07 REPRODUCED: health stayed OK after indirect dep changed! {h2}")
        self.assertFalse(h2["opengrep"]["available"])
        self.assertEqual(h2["opengrep"]["invalidation_reason"], "BINARY_IDENTITY_CHANGED")
        self.assertNotEqual(h2["opengrep"]["binary_identity_sha256"], sha1)

    def test_h04_immutable_rules_snapshot_scanned_and_midprobe_mutation_rejected(self) -> None:
        """Canary scan MUST receive an immutable snapshot rules file (not live config.rules_path) and reject mid-probe mutation."""
        log_f = self.root / "snap_og" / "argv.log"
        w, _ = _write_canary_wrapper(self.root / "snap_og", log_file=log_f)
        svc = TriageApiService(
            ApiConfig(
                host="127.0.0.1",
                port=0,
                data_dir=self.root / "snap_data",
                rules_path=self.rules_file,
                opengrep_binary=str(w),
                ollama_endpoint=self.ollama_url,
                api_token=TEST_TOKEN,
            )
        )
        self.addCleanup(svc.shutdown_opengrep_probe)
        self.assertTrue(svc.start_opengrep_probe())
        self.assertTrue(svc.wait_for_opengrep_probe(timeout=10.0))
        h = svc.health(authenticated=True)
        self.assertEqual(h["status"], "OK", h)
        lines = log_f.read_text(encoding="utf-8").splitlines()
        scan_line = next(ln for ln in lines if "scan " in ln)
        # Scanner MUST NOT point directly at live mutable `self.rules_file`!
        self.assertNotIn(str(self.rules_file.resolve()), scan_line, f"Canary scanned live mutable rules_path: {scan_line}")
        self.assertIn("rules.snapshot.yml", scan_line)

        # Mid-probe rules mutation MUST be rejected (never VERIFIED)
        w_slow, _ = _write_canary_wrapper(self.root / "snap_slow_og", sleep_scan=0.8)
        svc2 = TriageApiService(
            ApiConfig(
                host="127.0.0.1",
                port=0,
                data_dir=self.root / "snap_data2",
                rules_path=self.rules_file,
                opengrep_binary=str(w_slow),
                ollama_endpoint=self.ollama_url,
                api_token=TEST_TOKEN,
            )
        )
        self.addCleanup(svc2.shutdown_opengrep_probe)
        self.assertTrue(svc2.start_opengrep_probe())
        time.sleep(0.25)
        self.rules_file.write_text(VALID_MINIMAL_RULES_YAML + "# mid-probe edit\n", encoding="utf-8")
        self.assertTrue(svc2.wait_for_opengrep_probe(timeout=10.0))
        st = svc2.probe_opengrep(trigger_refresh=False)
        self.assertFalse(st["available"], f"Mid-probe rules mutation produced VERIFIED! {st}")

    def test_h04_wsl_target_identity_verified_at_probe_and_fails_closed_if_unverifiable(self) -> None:
        real_og = _resolve_real_opengrep_binary()
        if not real_og:
            self.skipTest("Real ADMIN-PC OpenGrep wrapper not present")

        # 1. Static inspection detects WSL distro/path from opengrep_counted.py without running WSL
        binfo = inspect_opengrep_binary_identity(real_og)
        self.assertTrue(binfo["found"])
        wsl_target = binfo.get("wsl_target")
        self.assertIsInstance(wsl_target, dict, binfo)
        self.assertTrue(wsl_target.get("detected"), binfo)
        self.assertEqual(wsl_target.get("distro"), "Ubuntu-IRIS")
        self.assertEqual(wsl_target.get("linux_binary_path"), "/usr/local/bin/opengrep")

        # 2. Real probe verifies WSL binary SHA-256 and discloses honest TTL scope
        svc = TriageApiService(
            ApiConfig(
                host="127.0.0.1",
                port=0,
                data_dir=self.root / "wsl_real_data",
                rules_path=DEFAULT_BACKEND_RULES.resolve(),
                opengrep_binary=real_og,
                ollama_endpoint=self.ollama_url,
                api_token=TEST_TOKEN,
                opengrep_health_probe_timeout_seconds=30.0,
            )
        )
        self.addCleanup(svc.shutdown_opengrep_probe)
        self.assertTrue(svc.start_opengrep_probe())
        self.assertTrue(svc.wait_for_opengrep_probe(timeout=35.0))
        h = svc.health(authenticated=True)
        self.assertEqual(h["status"], "OK", h)
        og = h["opengrep"]
        wsl_id = og.get("wsl_binary_identity")
        self.assertIsInstance(wsl_id, dict, og)
        self.assertTrue(wsl_id.get("verified_at_probe"))
        self.assertEqual(wsl_id.get("distro"), "Ubuntu-IRIS")
        self.assertEqual(len(str(wsl_id.get("sha256") or "")), 64)
        scope = og.get("identity_verification_scope")
        self.assertIsInstance(scope, dict, og)
        self.assertFalse(scope.get("realtime_wsl_binary_mutation_detection"))
        self.assertEqual(scope.get("max_staleness_seconds"), 300.0)

        # 3. Fail-closed when WSL binary identity verification fails
        bdir = self.root / "fake_wsl_fail"
        w, bscript = _write_canary_wrapper(bdir, name="opengrep_wsl_fail")
        # Embed a real WSL subprocess call site targeting a bogus distro so WSL identity verification MUST run and fail closed!
        bscript.write_text(
            'import os as _wsl_os, subprocess as _wsl_sp\n'
            'if _wsl_os.environ.get("NTK_FORCE_BOGUS_WSL"):\n'
            '    _wsl_sp.run(["wsl.exe", "-d", "NonExistentDistroXYZ", "--", "/usr/local/bin/opengrep"], check=False)\n'
            + bscript.read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        svc_fail = TriageApiService(
            ApiConfig(
                host="127.0.0.1",
                port=0,
                data_dir=self.root / "wsl_fail_data",
                rules_path=self.rules_file,
                opengrep_binary=str(w),
                ollama_endpoint=self.ollama_url,
                api_token=TEST_TOKEN,
                opengrep_health_probe_timeout_seconds=10.0,
            )
        )
        self.addCleanup(svc_fail.shutdown_opengrep_probe)
        self.assertTrue(svc_fail.start_opengrep_probe())
        self.assertTrue(svc_fail.wait_for_opengrep_probe(timeout=15.0))
        h_fail = svc_fail.health(authenticated=True)
        self.assertEqual(h_fail["status"], "DEGRADED", h_fail)
        self.assertFalse(h_fail["opengrep"]["available"])
        self.assertEqual(h_fail["opengrep"]["failure_code"], "WSL_BINARY_IDENTITY_FAILED")


if __name__ == "__main__":
    unittest.main()
