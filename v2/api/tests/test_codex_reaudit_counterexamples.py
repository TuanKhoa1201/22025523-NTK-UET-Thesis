"""Counterexample suite reproducing the 3 High and 5 Medium integration blockers from independent audit.

Run BEFORE fixes to confirm reproduction (FAIL), and AFTER fixes to verify root-cause remediation (PASS).
Covers:
- P0-III: Validator / integration gate rejecting unsubstantiated REFUTED against active taint.
- P0-IV: Blocking conclusive verdicts when flow-deciding helper implementation is absent or mismatched.
- P0-V: CWE-22 ruleset (removing unconditional FilenameUtils.getName / Path.getFileName sanitizers) & gate handling.
- P0-VI: Provenance-bound Qwen cache (whole-repo inventory, snapshot rules_sha256, concurrent writers, default off).
- P0-VII: Strict UTF-8 prompt budget enforcement and balanced/string-aware Java method & annotation parsing.
- P1-VIII: Job deadline enforcement, no COMPLETED on timeout, storage/sqlite3.OperationalError fail-closed, no partial scan publish.
- P1-IX: CWE-89 untyped receiver FP narrowing (jdbcHealth, index) & NamedParameterJdbcOperations.batchUpdate TP recovery.
- P1-X: Mixed cache+live provenance separation & valid-JSON tampering detection on assessments.jsonl.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import zipfile

from v2.api.config import ApiConfig, DEFAULT_BACKEND_RULES
from v2.api.java_context_v2 import (
    DEFAULT_MAX_PROMPT_BYTES,
    analyze_flow_dependencies,
    enrich_bundle_context,
    parse_java_structure_v2,
)
from v2.api.triage_gate import (
    SUPPORTED_REFUTATION_PROOF_CLASSES,
    UNSUPPORTED_REFUTATION_PROOF_LIMITS,
    apply_integration_gate,
)
from v2.triage.heuristics import extract_evidence_signals
from v2.triage.store import ReviewStore
from v2.api.jobs import ScanJobManager
from v2.api.qwen_cache import ProvenanceQwenCache
from v2.api.qwen_triage import run_bounded_triage
from v2.api.server import ThesisApiServer
from v2.api.service import ApiServiceError, TriageApiService
from v2.api.tests.test_java_context_and_qwen_triage import _make_manifest_and_opengrep
from v2.triage.evidence import collect, digest
from v2.triage.ollama import prompt as build_prompt


def _make_java_zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content.encode("utf-8"))
    return buf.getvalue()


def _resolve_opengrep_binary() -> str | None:
    env_bin = os.environ.get("OPENGREP_BINARY") or os.environ.get("NTK_TEST_OPENGREP_BINARY")
    if env_bin and Path(env_bin).is_file():
        return env_bin
    for candidate in (
        r"C:\NTK-G1-Private\G1-Runtime\bin\opengrep.cmd",
        shutil.which("opengrep"),
    ):
        if candidate and Path(candidate).is_file():
            return str(candidate)
    return None


def _create_fake_opengrep_from_fixtures(root: Path, *, subdir: str = "fake_og", sleep_sec: float = 0.0) -> str:
    """Create a deterministic fake OpenGrep producing JSON+SARIF for every .java file with getParameter/readString."""
    bin_dir = root / subdir
    bin_dir.mkdir(parents=True, exist_ok=True)
    py_file = bin_dir / "og_stub.py"
    py_file.write_text(
        f"""
import json, pathlib, sys, time
args = sys.argv[1:]
if "--version" in args:
    print("1.25.0")
    raise SystemExit(0)
if {sleep_sec!r} > 0 and "--json" in args:
    time.sleep({sleep_sec!r})
target = pathlib.Path(args[-1])
java_files = sorted(target.rglob("*.java"))
results = []
sarif_results = []
for jf in java_files:
    raw = jf.read_text(encoding="utf-8")
    lines = raw.splitlines(keepends=True)
    def _loc(ln_idx, needle):
        lraw = lines[ln_idx - 1].rstrip("\\r\\n")
        col0 = lraw.index(needle)
        pref = sum(len(x.encode("utf-8")) for x in lines[:ln_idx - 1])
        so = pref + len(lraw[:col0].encode("utf-8"))
        return {{
            "path": str(jf),
            "start": {{"line": ln_idx, "col": len(lraw[:col0].encode("utf-8")) + 1, "offset": so}},
            "end": {{"line": ln_idx, "col": len(lraw[:col0 + len(needle)].encode("utf-8")) + 1, "offset": so + len(needle.encode("utf-8"))}},
        }}
    src_ln = next((i + 1 for i, l in enumerate(lines) if "getParameter(" in l), None)
    if src_ln is None:
        continue
    src_needle = 'getParameter('
    # Extract full call like req.getParameter("x")
    src_raw = lines[src_ln - 1].rstrip("\\r\\n")
    s_pos = src_raw.find("req.getParameter(")
    if s_pos == -1:
        continue
    e_pos = src_raw.find(")", s_pos) + 1
    src_txt = src_raw[s_pos:e_pos]
    for idx_l, l in enumerate(lines, 1):
        for marker, rule_id, cwe in (
            ("stmt.executeQuery(", "ntk.api.java.cwe89.sql-injection", "CWE-89"),
            ("st.executeQuery(", "ntk.api.java.cwe89.sql-injection", "CWE-89"),
            ("Files.readString(", "ntk.api.java.cwe22.path-traversal", "CWE-22"),
            ("new FileInputStream(", "ntk.api.java.cwe22.path-traversal", "CWE-22"),
        ):
            if marker in l:
                lraw = l.rstrip("\\r\\n")
                m_start = lraw.index(marker)
                # capture call up to ';' or ')'
                if lraw.endswith(";"):
                    snk_txt = lraw[m_start:-1].strip()
                else:
                    snk_txt = lraw[m_start:].strip()
                sl = _loc(src_ln, src_txt)
                kl = _loc(idx_l, snk_txt)
                results.append({{
                    "check_id": rule_id,
                    "path": str(jf),
                    "start": kl["start"],
                    "end": kl["end"],
                    "extra": {{
                        "message": f"[{{cwe}}] finding",
                        "severity": "ERROR",
                        "metadata": {{"cwe": [cwe]}},
                        "dataflow_trace": {{
                            "taint_source": ["CliLoc", [sl, src_txt]],
                            "intermediate_vars": [],
                            "taint_sink": ["CliLoc", [kl, snk_txt]],
                        }},
                    }},
                }})
                sarif_results.append({{
                    "ruleId": rule_id,
                    "locations": [{{
                        "physicalLocation": {{
                            "artifactLocation": {{"uri": str(jf)}},
                            "region": {{
                                "startLine": kl["start"]["line"],
                                "endLine": kl["end"]["line"],
                                "startColumn": kl["start"]["col"],
                                "endColumn": kl["end"]["col"],
                            }},
                        }}
                    }}],
                }})
if "--sarif" in args:
    print(json.dumps({{"version": "2.1.0", "runs": [{{"results": sarif_results}}]}}))
    raise SystemExit(0)
print(json.dumps({{
    "version": "1.25.0",
    "results": results,
    "errors": [],
    "paths": {{"scanned": [str(jf) for jf in java_files], "skipped": []}},
}}))
""",
        encoding="utf-8",
    )
    if os.name == "nt":
        cmd = bin_dir / "opengrep.cmd"
        cmd.write_text(f'@echo off\r\n"{sys.executable}" "{py_file}" %*\r\n', encoding="utf-8")
        return str(cmd)
    sh = bin_dir / "opengrep"
    sh.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{py_file}" "$@"\n', encoding="utf-8")
    sh.chmod(0o755)
    return str(sh)


class _ScriptedOllamaServer:
    """Loopback stub Ollama returning caller-supplied verdict content per finding prompt."""

    def __init__(self, responder):
        self.responder = responder
        self.post_count = 0
        self.tags_count = 0
        self.model_digest = "d" * 64
        self.post_prompts: list[dict] = []
        outer = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                return

            def do_GET(self):
                if self.path == "/api/tags":
                    outer.tags_count += 1
                    body = json.dumps({
                        "models": [{"name": "qwen3.5:9b-q4_K_M", "digest": outer.model_digest, "size": 100}]
                    }).encode("utf-8")
                else:
                    body = json.dumps({"models": []}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                outer.post_count += 1
                n = int(self.headers.get("Content-Length", "0"))
                req_doc = json.loads(self.rfile.read(n).decode("utf-8"))
                outer.post_prompts.append(req_doc)
                resp_obj = outer.responder(req_doc, outer.post_count)
                if isinstance(resp_obj, tuple):
                    delay, content_dict = resp_obj
                    time.sleep(delay)
                else:
                    content_dict = resp_obj
                body = json.dumps({
                    "model": "qwen3.5:9b-q4_K_M",
                    "done": True,
                    "done_reason": "stop",
                    "eval_count": 30,
                    "eval_duration": 1_000_000,
                    "message": {"role": "assistant", "content": json.dumps(content_dict, ensure_ascii=False)},
                }).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._th = threading.Thread(target=self._srv.serve_forever, daemon=True)

    @property
    def endpoint(self) -> str:
        return f"http://127.0.0.1:{self._srv.server_port}"

    def __enter__(self):
        self._th.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self._srv.shutdown()
        self._srv.server_close()


class CodexReauditCounterexampleTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.rules = self.root / "rules.yml"
        self.rules.write_text("rules: []\n", encoding="utf-8")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    # ------------------------------------------------------------------
    # P0-III: Validator must NOT accept REFUTED on active taint without flow-verified guard
    # ------------------------------------------------------------------
    def test_p0_3_refuted_rejected_on_demo1_tp_and_weak_guard_citing_sink_for_live_and_cache(self) -> None:
        from v2.api.triage_gate import apply_integration_gate

        # 1. Direct semantic-gate counterexamples (even with SUPPORTED heuristic + valid citation):
        #    (a) Guard checks another variable; (b) normalize().startsWith() ignored; (c) canonical without exit/dominance
        for ce_name, ce_line in (
            ("other_var_guard", 'if (!"SELECT 1".equals(otherVar)) { throw new SecurityException(); }'),
            ("normalize_ignored", "target.normalize().startsWith(baseDir);"),
            ("canonical_no_exit", 'if (!target.getCanonicalPath().startsWith(baseCanon + File.separator)) { log.warn("bad"); }'),
        ):
            ce_rec = {
                "id": "1" * 64,
                "cwe": ["CWE-22"],
                "snapshots": {"Ce.java": {"sha256": "a" * 64}},
                "snippets": [
                    {
                        "role": "finding",
                        "path": "Ce.java",
                        "sha256": "a" * 64,
                        "start": {"line": 5, "col": 1},
                        "end": {"line": 5, "col": 30},
                        "lines": [
                            {"line": 4, "text": ce_line},
                            {"line": 5, "text": "return new FileInputStream(target);"},
                        ],
                    }
                ],
                "java_context": {"enclosing_method": {"header_line": 3, "start_line": 3, "end_line": 6}},
                "heuristic_signals": {"recommended_status": "SUPPORTED", "sink_line": 5, "unresolved_calls": []},
            }
            ce_ass = {
                "status": "REFUTED",
                "validated_status": "REFUTED",
                "raw_response": {"model": "qwen3.5:9b-q4_K_M", "done": True},
                "citations": [
                    {"path": "Ce.java", "start_line": 4, "end_line": 4, "quote": ce_line, "sha256": "a" * 64}
                ],
            }
            gated = apply_integration_gate(ce_rec, ce_ass)
            self.assertEqual(gated["validated_status"], "UNDETERMINED", f"{ce_name} bypassed gate!")
            self.assertEqual(gated["raw_model_status"], "REFUTED")
            self.assertTrue(gated["validator_downgraded"])
            self.assertEqual(gated["raw_response"], ce_ass["raw_response"])
            self.assertEqual(len(gated["citations"]), 1)
            self.assertTrue(gated.get("downgrade_reason"))

        # 2. End-to-end live scan on SQLi TP, Path Traversal TP, and WeakPrefix CWE-22 -> REFUTED downgraded, TP SUPPORTED kept
        demo1_code = (
            "package ntk.g1.demo;\n"
            "import java.io.FileInputStream;\n"
            "import java.io.IOException;\n"
            "import java.sql.ResultSet;\n"
            "import java.sql.SQLException;\n"
            "import java.sql.Statement;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class Demo1TruePositive {\n"
            "    public ResultSet lookupUserByRole(HttpServletRequest req, Statement stmt) throws SQLException {\n"
            '        String role = req.getParameter("role");\n'
            "        String normalizedRole = role.trim();\n"
            '        String sql = "SELECT id, username FROM users WHERE role = \'" + normalizedRole + "\'";\n'
            "        return stmt.executeQuery(sql);\n"
            "    }\n"
            "    public FileInputStream downloadInvoiceFile(HttpServletRequest req) throws IOException {\n"
            '        String invoiceName = req.getParameter("file");\n'
            '        String targetPath = "/srv/invoices/" + invoiceName;\n'
            "        return new FileInputStream(targetPath);\n"
            "    }\n"
            "}\n"
        )
        weak_prefix_code = (
            "package demo;\n"
            "import java.io.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class WeakPrefix {\n"
            "    public FileInputStream open(HttpServletRequest req) throws Exception {\n"
            '        String report = req.getParameter("report");\n'
            '        File target = new File("/reports", report);\n'
            '        if (!target.getCanonicalPath().startsWith("/reports")) { return null; }\n'
            "        return new FileInputStream(target);\n"
            "    }\n"
            "}\n"
        )
        fake_og = _create_fake_opengrep_from_fixtures(self.root, subdir="og_p0_3")

        def _respond_refuted_at_sink(req_doc, _n):
            ev_user = json.loads(req_doc["messages"][1]["content"])
            snip = ev_user["snippets"][0]
            sink_line_no = ev_user["start"]["line"]
            line_obj = next(l for l in snip["lines"] if l["line"] == sink_line_no)
            return {
                "status": "REFUTED",
                "explanation": "Cho rang da duoc xu ly an toan tai dong sink.",
                "fix_suggestion": "",
                "citations": [{
                    "path": snip["path"],
                    "start_line": sink_line_no,
                    "end_line": sink_line_no,
                    "quote": line_obj["text"],
                    "sha256": snip["sha256"],
                }],
            }

        with _ScriptedOllamaServer(_respond_refuted_at_sink) as ol:
            cfg = ApiConfig(
                host="127.0.0.1",
                port=0,
                data_dir=self.root / "data_p0_3",
                api_token="p03-token-123456",
                opengrep_binary=fake_og,
                rules_path=self.rules,
                ollama_endpoint=ol.endpoint,
                enable_qwen_cache=False,
                runtime_origin="unverified",
            )
            mgr = ScanJobManager(cfg)
            try:
                zbytes = _make_java_zip({
                    "Demo1TruePositive.java": demo1_code,
                    "WeakPrefix.java": weak_prefix_code,
                })
                j1 = mgr.submit_zip_job("p03_1.zip", zbytes)
                dl = time.monotonic() + 20.0
                while time.monotonic() < dl:
                    cur = mgr.get_job(j1["job_id"])
                    if cur["state"] in ("COMPLETED", "FAILED"):
                        break
                    time.sleep(0.05)
                j1 = mgr.get_job(j1["job_id"])
                self.assertEqual(j1["state"], "COMPLETED", j1)
                svc = TriageApiService(cfg)
                findings = svc.list_findings(j1["scan_id"])["findings"]
                self.assertEqual(len(findings), 3)
                for f in findings:
                    self.assertEqual(f["raw_model_status"], "REFUTED")
                    self.assertEqual(
                        f["validated_status"],
                        "UNDETERMINED",
                        f"Active taint {f['file_path']} must downgrade unverified REFUTED to UNDETERMINED, got {f}",
                    )
                    self.assertTrue(f["validator_downgraded"])
                    self.assertEqual(f["human_review_state"], "OPEN")
                    det = svc.get_finding_detail(j1["scan_id"], f["id"])
                    self.assertEqual(det["assessment"]["raw_model_status"], "REFUTED")
                    self.assertTrue(det["assessment"]["citations"])
                    self.assertTrue(det["assessment"]["raw_response"])
                    self.assertTrue(det["assessment"]["downgrade_reason"])
            finally:
                mgr.shutdown(wait=True)

        # 3. Positive guard control (SafeCanonicalSpring: getCanonicalPath + File.separator + throw + checked canonical path at sink -> REFUTED)
        #    vs RawPathAfterCanonicalGuard (checks targetCanon but passes raw `target` to sink -> UNDETERMINED)
        #    vs AllowlistedQuery (unmodeled by heuristics -> UNDETERMINED)
        #    vs BasenameOnly citing FilenameUtils.getName line (P0-V -> UNDETERMINED)
        #    vs SQLi TP & Path Traversal TP (SUPPORTED)
        safe_canon_java = (
            "package demo;\nimport java.io.*;\nimport javax.servlet.http.HttpServletRequest;\n"
            "public class SafeCanonicalSpring {\n"
            "    public FileInputStream open(HttpServletRequest req) throws IOException {\n"
            '        String r = req.getParameter("r");\n'
            '        File base = new File("/srv/reports");\n'
            "        File target = new File(base, r);\n"
            "        String baseCanon = base.getCanonicalPath();\n"
            "        String targetCanon = target.getCanonicalPath();\n"
            "        if (!targetCanon.startsWith(baseCanon + File.separator)) {\n"
            '            throw new SecurityException("outside");\n'
            "        }\n"
            "        return new FileInputStream(targetCanon);\n"
            "    }\n}\n"
        )
        raw_after_canon_java = safe_canon_java.replace(
            "public class SafeCanonicalSpring", "public class RawPathAfterCanonicalGuard"
        ).replace(
            "return new FileInputStream(targetCanon);", "return new FileInputStream(target);"
        )
        allow_java = (
            "package ntk.g1.demo;\nimport java.sql.*;\nimport javax.servlet.http.HttpServletRequest;\n"
            "public class AllowlistedQuery {\n"
            "    public void run(HttpServletRequest req, Statement stmt) throws SQLException {\n"
            '        String query = req.getParameter("q");\n'
            '        if (!"SELECT 1".equals(query)) {\n'
            '            throw new IllegalArgumentException("Only SELECT 1 is allowed");\n'
            "        }\n"
            "        stmt.executeQuery(query);\n"
            "    }\n}\n"
        )
        basename_only_java = (
            "package demo;\nimport java.io.*;\nimport javax.servlet.http.HttpServletRequest;\nimport org.apache.commons.io.FilenameUtils;\n"
            "public class BasenameOnly {\n"
            "    public FileInputStream open(HttpServletRequest req) throws Exception {\n"
            '        String f = FilenameUtils.getName(req.getParameter("f"));\n'
            '        return new FileInputStream(new File("/srv/files", f));\n'
            "    }\n}\n"
        )

        def _respond_ctrl(req_doc, _n):
            ev_user = json.loads(req_doc["messages"][1]["content"])
            snip = ev_user["snippets"][0]
            fp = snip["path"]
            if "SafeCanonicalSpring" in fp or "RawPathAfterCanonicalGuard" in fp:
                target_ln = 11  # if (!targetCanon.startsWith(baseCanon + File.separator)) {
                status = "REFUTED"
            elif "AllowlistedQuery" in fp:
                target_ln = 7
                status = "REFUTED"
            elif "BasenameOnly" in fp:
                target_ln = 7  # String f = FilenameUtils.getName(...)
                status = "REFUTED"
            else:
                target_ln = ev_user["start"]["line"]
                status = "SUPPORTED"
            line_obj = next(l for l in snip["lines"] if l["line"] == target_ln)
            return {
                "status": status,
                "explanation": "Controlled verdict check.",
                "fix_suggestion": "",
                "citations": [{
                    "path": fp,
                    "start_line": target_ln,
                    "end_line": target_ln,
                    "quote": line_obj["text"],
                    "sha256": snip["sha256"],
                }],
            }

        with _ScriptedOllamaServer(_respond_ctrl) as ol_ctrl:
            cfg_c = ApiConfig(
                host="127.0.0.1", port=0, data_dir=self.root / "data_p0_3_ctrl", api_token="p03c-token-1234",
                opengrep_binary=fake_og, rules_path=self.rules, ollama_endpoint=ol_ctrl.endpoint, runtime_origin="unverified",
            )
            mgr_c = ScanJobManager(cfg_c)
            try:
                jc = mgr_c.submit_zip_job("ctrl.zip", _make_java_zip({
                    "SafeCanonicalSpring.java": safe_canon_java,
                    "RawPathAfterCanonicalGuard.java": raw_after_canon_java,
                    "AllowlistedQuery.java": allow_java,
                    "BasenameOnly.java": basename_only_java,
                    "Demo1TruePositive.java": demo1_code,
                }))
                while mgr_c.get_job(jc["job_id"])["state"] not in ("COMPLETED", "FAILED"):
                    time.sleep(0.05)
                jc = mgr_c.get_job(jc["job_id"])
                self.assertEqual(jc["state"], "COMPLETED", jc)
                svc_c = TriageApiService(cfg_c)
                findings_c = svc_c.list_findings(jc["scan_id"])["findings"]
                by_fp = {f["file_path"]: f for f in findings_c}
                self.assertEqual(by_fp["SafeCanonicalSpring.java"]["validated_status"], "REFUTED")
                self.assertEqual(by_fp["RawPathAfterCanonicalGuard.java"]["validated_status"], "UNDETERMINED")
                self.assertEqual(by_fp["AllowlistedQuery.java"]["validated_status"], "UNDETERMINED")
                self.assertEqual(by_fp["BasenameOnly.java"]["validated_status"], "UNDETERMINED")
                tp_statuses = [f["validated_status"] for f in findings_c if f["file_path"] == "Demo1TruePositive.java"]
                self.assertEqual(tp_statuses, ["SUPPORTED", "SUPPORTED"])
            finally:
                mgr_c.shutdown(wait=True)

    # ------------------------------------------------------------------
    # P0-IV: Block conclusive verdicts when flow-deciding helper is absent / mismatched
    # ------------------------------------------------------------------
    def test_p0_4_missing_or_mismatched_helper_blocks_supported_while_non_decisive_allowed(self) -> None:
        ext_helper_java = (
            "package demo;\n"
            "import java.nio.file.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class ExtHelperCtrl {\n"
            "    public String read(HttpServletRequest req) throws Exception {\n"
            '        String input = req.getParameter("p");\n'
            "        Path p = Elsewhere.adjust(input);\n"
            "        return Files.readString(p);\n"
            "    }\n"
            "}\n"
        )
        non_decisive_java = (
            "package demo;\n"
            "import java.nio.file.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class NonDecisiveCtrl {\n"
            "    public String read(HttpServletRequest req) throws Exception {\n"
            '        String input = req.getParameter("p");\n'
            '        AuditLogger.record("read_attempt");\n'
            '        return Files.readString(Path.of("/srv/files", input));\n'
            "    }\n"
            "}\n"
        )
        same_file_java = (
            "package demo;\n"
            "import java.nio.file.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class SameFileHelperCtrl {\n"
            "    public String read(HttpServletRequest req) throws Exception {\n"
            '        String input = req.getParameter("p");\n'
            "        Path p = adjustLocal(input);\n"
            "        return Files.readString(p);\n"
            "    }\n"
            "    private Path adjustLocal(String raw) {\n"
            '        return Paths.get("/srv/files", raw);\n'
            "    }\n"
            "}\n"
        )
        src_dir = self.root / "src_p0_4"
        src_dir.mkdir()
        (src_dir / "ExtHelperCtrl.java").write_text(ext_helper_java, encoding="utf-8")
        (src_dir / "NonDecisiveCtrl.java").write_text(non_decisive_java, encoding="utf-8")
        (src_dir / "SameFileHelperCtrl.java").write_text(same_file_java, encoding="utf-8")

        fake_og = _create_fake_opengrep_from_fixtures(self.root, subdir="og_p0_4")

        def _respond_supported_at_sink(req_doc, _n):
            ev_user = json.loads(req_doc["messages"][1]["content"])
            snip = ev_user["snippets"][0]
            sink_ln = ev_user["start"]["line"]
            line_obj = next(l for l in snip["lines"] if l["line"] == sink_ln)
            return {
                "status": "SUPPORTED",
                "explanation": "Ket luan SUPPORTED chi dua tren dong sink.",
                "fix_suggestion": "Kiem tra duong dan.",
                "citations": [{
                    "path": snip["path"],
                    "start_line": sink_ln,
                    "end_line": sink_ln,
                    "quote": line_obj["text"],
                    "sha256": snip["sha256"],
                }],
            }

        with _ScriptedOllamaServer(_respond_supported_at_sink) as ol:
            cfg = ApiConfig(
                host="127.0.0.1",
                port=0,
                data_dir=self.root / "data_p0_4",
                api_token="p04-token-123456",
                opengrep_binary=fake_og,
                rules_path=self.rules,
                ollama_endpoint=ol.endpoint,
                runtime_origin="unverified",
            )
            mgr = ScanJobManager(cfg)
            try:
                zbytes = _make_java_zip({
                    "ExtHelperCtrl.java": ext_helper_java,
                    "NonDecisiveCtrl.java": non_decisive_java,
                    "SameFileHelperCtrl.java": same_file_java,
                })
                j = mgr.submit_zip_job("p04.zip", zbytes)
                dl = time.monotonic() + 20.0
                while time.monotonic() < dl:
                    cur = mgr.get_job(j["job_id"])
                    if cur["state"] in ("COMPLETED", "FAILED"):
                        break
                    time.sleep(0.05)
                j = mgr.get_job(j["job_id"])
                self.assertEqual(j["state"], "COMPLETED", j)
                svc = TriageApiService(cfg)
                by_file = {f["file_path"]: f for f in svc.list_findings(j["scan_id"])["findings"]}
                # 1. Missing external helper -> MUST fail closed to UNDETERMINED!
                self.assertEqual(by_file["ExtHelperCtrl.java"]["raw_model_status"], "SUPPORTED")
                self.assertEqual(
                    by_file["ExtHelperCtrl.java"]["validated_status"],
                    "UNDETERMINED",
                    "Missing Elsewhere.adjust() implementation must downgrade SUPPORTED to UNDETERMINED",
                )
                self.assertTrue(by_file["ExtHelperCtrl.java"]["validator_downgraded"])
                # 2. Non-decisive logging call -> SUPPORTED remains accepted!
                self.assertEqual(by_file["NonDecisiveCtrl.java"]["validated_status"], "SUPPORTED")
                # 3. Same-file helper present in prompt -> SUPPORTED remains accepted!
                self.assertEqual(by_file["SameFileHelperCtrl.java"]["validated_status"], "SUPPORTED")
            finally:
                mgr.shutdown(wait=True)

        # 4. Cross-file helper snippet with mismatched source hash MUST fail closed to UNDETERMINED!
        helper_src = self.root / "src_p0_4_hash"
        helper_src.mkdir()
        (helper_src / "Ctrl.java").write_text(ext_helper_java, encoding="utf-8", newline="\n")
        elsewhere_java = "package demo;\nimport java.nio.file.*;\npublic class Elsewhere {\n    public static Path adjust(String s) { return Paths.get(\"/srv\", s); }\n}\n"
        (helper_src / "Elsewhere.java").write_text(elsewhere_java, encoding="utf-8", newline="\n")
        og_h, man_h = _make_manifest_and_opengrep(
            helper_src,
            "Ctrl.java",
            rule_id="ntk.api.java.cwe22.path-traversal",
            cwe="CWE-22",
            source_line=6,
            source_text='req.getParameter("p")',
            sink_line=8,
            sink_text="Files.readString(p)",
            rules_path=self.rules,
        )
        b_h = collect(
            og_h.read_bytes(),
            helper_src,
            engine_exit=0,
            scan_provenance={"origin": "unit", "source_capture_verified": True, "exit_capture_verified": True, "recorded_engine_exit": 0},
        )
        enrich_bundle_context(b_h, helper_src)
        rec_h = b_h["records"][0]
        rec_h["snapshots"]["Elsewhere.java"] = {"sha256": digest(elsewhere_java.encode("utf-8")), "size": len(elsewhere_java)}
        rec_h["snippets"].append({
            "role": "helper",
            "path": "Elsewhere.java",
            "start": {"line": 3, "col": 1},
            "end": {"line": 5, "col": 2},
            "sha256": "f" * 64,  # Mismatched hash!
            "lines": [{"line": i + 1, "text": l} for i, l in enumerate(elsewhere_java.splitlines())],
        })
        # Save modified evidence? Better test through run_bounded_triage or check helper hash mismatch via direct record validation
        # Here verify that even if helper snippet is attached with wrong hash, our gate blocks it.
        from v2.triage.ollama import validate_answer as raw_validate
        ans_h = json.dumps({
            "status": "SUPPORTED",
            "explanation": "Helper mismatched hash",
            "fix_suggestion": "Fix",
            "citations": [{
                "path": "Ctrl.java",
                "start_line": 8,
                "end_line": 8,
                "quote": ext_helper_java.splitlines()[7],
                "sha256": rec_h["snapshots"]["Ctrl.java"]["sha256"],
            }],
        })
        # Check through triage gate if present (pre-fix: validate_answer returns SUPPORTED!)
        val_raw = raw_validate(ans_h, rec_h)
        from v2.api.triage_gate import apply_integration_gate
        gated = apply_integration_gate(rec_h, val_raw)
        self.assertEqual(gated["validated_status"], "UNDETERMINED")

        # 5. Same-file helper cut out by prompt budget MUST fail closed to UNDETERMINED!
        big_pad = "\n".join(f'        String pad{i} = "' + ("B" * 260) + '";' for i in range(140))
        same_budget_java = (
            "package demo;\nimport java.nio.file.*;\nimport javax.servlet.http.HttpServletRequest;\n"
            "public class SameHelperCutByBudget {\n"
            "    public String read(HttpServletRequest req) throws Exception {\n"
            '        String input = req.getParameter("p");\n'
            "        Path p = adjustLocal(input);\n"
            "        return Files.readString(p);\n"
            "    }\n"
            + big_pad + "\n"
            "    private Path adjustLocal(String raw) {\n"
            '        return Paths.get("/srv/files", raw);\n'
            "    }\n"
            "}\n"
        )
        src_sb = self.root / "src_p0_4_budget"
        src_sb.mkdir()
        (src_sb / "SameHelperCutByBudget.java").write_text(same_budget_java, encoding="utf-8")
        og_sb, _ = _make_manifest_and_opengrep(
            src_sb, "SameHelperCutByBudget.java",
            rule_id="ntk.api.java.cwe22.path-traversal", cwe="CWE-22",
            source_line=6, source_text='req.getParameter("p")',
            sink_line=8, sink_text="Files.readString(p)",
            rules_path=self.rules,
        )
        b_sb = collect(
            og_sb.read_bytes(), src_sb, engine_exit=0,
            scan_provenance={"origin": "unit", "source_capture_verified": True, "exit_capture_verified": True, "recorded_engine_exit": 0},
        )
        enrich_bundle_context(b_sb, src_sb, max_prompt_bytes=32_000)
        rec_sb = b_sb["records"][0]
        rec_sb["snippets"] = [s for s in rec_sb["snippets"] if s.get("role") != "helper"]
        ans_sb = json.dumps({
            "status": "SUPPORTED", "explanation": "Same-file helper cut from prompt", "fix_suggestion": "Fix",
            "citations": [{"path": "SameHelperCutByBudget.java", "start_line": 8, "end_line": 8, "quote": same_budget_java.splitlines()[7], "sha256": rec_sb["snapshots"]["SameHelperCutByBudget.java"]["sha256"]}],
        })
        self.assertEqual(apply_integration_gate(rec_sb, raw_validate(ans_sb, rec_sb))["validated_status"], "UNDETERMINED")

        # 6. Helper owner/class-declaration/overload/hash matrix (Section D)
        _case_seq = 0

        def _run_helper_snippet_case(helper_rel: str, helper_code: str, *, override_sha: str | None = None) -> str:
            nonlocal _case_seq
            _case_seq += 1
            case_src = self.root / f"src_p0_4_case_{_case_seq}"
            case_src.mkdir(parents=True, exist_ok=True)
            (case_src / "Ctrl.java").write_text(ext_helper_java, encoding="utf-8", newline="\n")
            helper_file = case_src / helper_rel
            helper_file.parent.mkdir(parents=True, exist_ok=True)
            helper_file.write_text(helper_code, encoding="utf-8", newline="\n")

            rec_x = json.loads(json.dumps(rec_h))
            rec_x["root"] = str(case_src)
            real_sha = digest(helper_code.encode("utf-8"))
            rec_x["snapshots"] = {
                "Ctrl.java": rec_h["snapshots"]["Ctrl.java"],
                helper_rel: {"sha256": real_sha, "size": len(helper_code.encode("utf-8"))},
            }
            rec_x["snippets"] = [s for s in rec_x["snippets"] if s.get("role") != "helper"]
            rec_x["snippets"].append({
                "role": "helper",
                "path": helper_rel,
                "start": {"line": 1, "col": 1},
                "end": {"line": len(helper_code.splitlines()), "col": 2},
                "sha256": override_sha or real_sha,
                "lines": [{"line": i + 1, "text": ln} for i, ln in enumerate(helper_code.splitlines())],
            })
            val_x = raw_validate(ans_h, rec_x)
            return apply_integration_gate(rec_x, val_x)["validated_status"]

        # 6a. Exact owner class `Elsewhere` + exact matching signature + matching hash -> SUPPORTED
        self.assertEqual(
            _run_helper_snippet_case(
                "Elsewhere.java",
                'package demo;\nimport java.nio.file.*;\npublic class Elsewhere {\n    public static Path adjust(String s) { return Paths.get("/srv", s); }\n}\n',
            ),
            "SUPPORTED",
        )
        # 6b. Wrong owner class `OtherHelper` defining `adjust(String)` -> MUST stay unresolved -> UNDETERMINED
        self.assertEqual(
            _run_helper_snippet_case(
                "OtherHelper.java",
                'package demo;\nimport java.nio.file.*;\npublic class OtherHelper {\n    public static Path adjust(String s) { return Paths.get("/srv", s); }\n}\n',
            ),
            "UNDETERMINED",
        )
        # 6c. Snippet without class declaration (only method body) -> MUST stay unresolved -> UNDETERMINED
        self.assertEqual(
            _run_helper_snippet_case(
                "Elsewhere.java",
                '    public static Path adjust(String s) { return Paths.get("/srv", s); }\n',
            ),
            "UNDETERMINED",
        )
        # 6d. Same-arity overload ambiguity in `Elsewhere` -> MUST stay unresolved -> UNDETERMINED
        self.assertEqual(
            _run_helper_snippet_case(
                "Elsewhere.java",
                'package demo;\nimport java.nio.file.*;\npublic class Elsewhere {\n    public static Path adjust(String s) { return Paths.get("/srv", s); }\n    public static Path adjust(Object o) { return Paths.get("/srv"); }\n}\n',
            ),
            "UNDETERMINED",
        )
        # 6e. Wrong-arity overload `adjust(String, int)` for 1-arg call -> MUST stay unresolved -> UNDETERMINED
        self.assertEqual(
            _run_helper_snippet_case(
                "Elsewhere.java",
                'package demo;\nimport java.nio.file.*;\npublic class Elsewhere {\n    public static Path adjust(String s, int flags) { return Paths.get("/srv", s); }\n}\n',
            ),
            "UNDETERMINED",
        )
        # 6f. Valid owner/signature but wrong SHA-256 -> MUST fail closed -> UNDETERMINED
        self.assertEqual(
            _run_helper_snippet_case(
                "Elsewhere.java",
                'package demo;\nimport java.nio.file.*;\npublic class Elsewhere {\n    public static Path adjust(String s) { return Paths.get("/srv", s); }\n}\n',
                override_sha="e" * 64,
            ),
            "UNDETERMINED",
        )

    # ------------------------------------------------------------------
    # P0-V & P1-IX: Real OpenGrep 1.25.0 CWE-22 & CWE-89 counterexamples
    # ------------------------------------------------------------------
    def test_p0_5_and_p1_9_real_opengrep_cwe22_and_cwe89_counterexamples(self) -> None:
        og_bin = _resolve_opengrep_binary()
        if not og_bin:
            self.skipTest("ENV_BLOCKED: no local OpenGrep binary found")
        cases = {
            # CWE-22 positives (MUST HIT)
            "PosCwe22FilenameUtilsResolveNewInputStream.java": (
                "import java.nio.file.*;\nimport javax.servlet.http.HttpServletRequest;\nimport org.apache.commons.io.FilenameUtils;\n"
                "public class PosCwe22FilenameUtilsResolveNewInputStream {\n"
                "    public void run(HttpServletRequest req, Path base) throws Exception {\n"
                '        String leaf = FilenameUtils.getName(req.getParameter("f"));\n'
                "        Files.newInputStream(base.resolve(leaf));\n"
                "    }\n}\n"
            ),
            "PosCwe22PathGetFileNameFilesList.java": (
                "import java.nio.file.*;\nimport javax.servlet.http.HttpServletRequest;\n"
                "public class PosCwe22PathGetFileNameFilesList {\n"
                "    public void run(HttpServletRequest req, Path base) throws Exception {\n"
                '        Path leaf = Paths.get(req.getParameter("p")).getFileName();\n'
                "        Files.list(base.resolve(leaf));\n"
                "    }\n}\n"
            ),
            "PosCwe22ResolveNormalizeNoBoundaryReadString.java": (
                "import java.nio.file.*;\nimport javax.servlet.http.HttpServletRequest;\n"
                "public class PosCwe22ResolveNormalizeNoBoundaryReadString {\n"
                "    public String run(HttpServletRequest req, Path base) throws Exception {\n"
                '        Path target = base.resolve(req.getParameter("f")).normalize();\n'
                "        return Files.readString(target);\n"
                "    }\n}\n"
            ),
            "PosCwe22SiblingPrefixBypass.java": (
                "import java.io.*;\nimport javax.servlet.http.HttpServletRequest;\n"
                "public class PosCwe22SiblingPrefixBypass {\n"
                "    public FileInputStream run(HttpServletRequest req) throws Exception {\n"
                '        File f = new File("/srv/reports", req.getParameter("r"));\n'
                '        if (!f.getCanonicalPath().startsWith("/srv/reports")) { throw new SecurityException(); }\n'
                "        return new FileInputStream(f);\n"
                "    }\n}\n"
            ),
            # CWE-22 negatives (0 finding)
            "NegCwe22ParseIntPath.java": (
                "import java.nio.file.*;\nimport javax.servlet.http.HttpServletRequest;\n"
                "public class NegCwe22ParseIntPath {\n"
                "    public String run(HttpServletRequest req, Path base) throws Exception {\n"
                '        int id = Integer.parseInt(req.getParameter("id"));\n'
                '        return Files.readString(base.resolve(id + ".txt"));\n'
                "    }\n}\n"
            ),
            # CWE-89 positive (MUST HIT)
            "PosCwe89NamedParameterJdbcOperationsBatch.java": (
                "import java.util.Map;\nimport javax.servlet.http.HttpServletRequest;\n"
                "import org.springframework.jdbc.core.namedparam.NamedParameterJdbcOperations;\n"
                "public class PosCwe89NamedParameterJdbcOperationsBatch {\n"
                "    public void run(HttpServletRequest req, NamedParameterJdbcOperations ops, Map<String, ?>[] binds) {\n"
                '        String dyn = req.getParameter("tbl");\n'
                '        ops.batchUpdate("DELETE FROM " + dyn, binds);\n'
                "    }\n}\n"
            ),
            # CWE-89 negatives (MUST BE 0 FINDING)
            "NegCwe89JdbcHealthUpdate.java": (
                "import javax.servlet.http.HttpServletRequest;\n"
                "public class NegCwe89JdbcHealthUpdate {\n"
                "    static class HealthCheck { void update(String s) {} }\n"
                "    public void run(HttpServletRequest req, HealthCheck jdbcHealth) {\n"
                '        jdbcHealth.update(req.getParameter("s"));\n'
                "    }\n}\n"
            ),
            "NegCwe89IndexQueryForList.java": (
                "import javax.servlet.http.HttpServletRequest;\n"
                "public class NegCwe89IndexQueryForList {\n"
                "    static class SearchIndex { void queryForList(String q) {} }\n"
                "    public void run(HttpServletRequest req, SearchIndex index) {\n"
                '        index.queryForList(req.getParameter("q"));\n'
                "    }\n}\n"
            ),
        }
        stage = self.root / "og_rules_stage"
        stage.mkdir()
        for fn, code in cases.items():
            (stage / fn).write_text(code, encoding="utf-8")
        cp = subprocess.run(
            [og_bin, "scan", "--config", str(DEFAULT_BACKEND_RULES.resolve()), "--json", "--no-git-ignore", str(stage)],
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)
        doc = json.loads(cp.stdout)
        self.assertEqual(doc.get("errors"), [])
        by_file: dict[str, set[str]] = {}
        for r in doc.get("results") or []:
            by_file.setdefault(Path(r["path"]).name, set()).add(r["check_id"])

        for pos_fn in (
            "PosCwe22FilenameUtilsResolveNewInputStream.java",
            "PosCwe22PathGetFileNameFilesList.java",
            "PosCwe22ResolveNormalizeNoBoundaryReadString.java",
            "PosCwe22SiblingPrefixBypass.java",
            "PosCwe89NamedParameterJdbcOperationsBatch.java",
        ):
            self.assertIn(pos_fn, by_file, f"Missing expected finding on {pos_fn}")

        for neg_fn in (
            "NegCwe22ParseIntPath.java",
            "NegCwe89JdbcHealthUpdate.java",
            "NegCwe89IndexQueryForList.java",
        ):
            self.assertNotIn(neg_fn, by_file, f"Unexpected false positive on {neg_fn}: {by_file.get(neg_fn)}")

    # ------------------------------------------------------------------
    # P0-VI: Qwen cache SAFELY_DISABLED lock & whole-tree inventory verification
    # ------------------------------------------------------------------
    def test_p0_6_cache_repo_isolation_snapshot_rules_hash_and_concurrent_writers(self) -> None:
        from v2.api.qwen_cache import _verify_source_inventory_on_disk
        from v2.triage.evidence import EvidenceError

        ctrl_java = (
            "package demo;\n"
            "import java.nio.file.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class RepoCtrl {\n"
            "    public String run(HttpServletRequest req) throws Exception {\n"
            '        String p = req.getParameter("p");\n'
            '        return Files.readString(Path.of("/srv/files", p));\n'
            "    }\n"
            "}\n"
        )
        fake_og = _create_fake_opengrep_from_fixtures(self.root, subdir="og_p0_6")

        def _respond_supported(req_doc, _n):
            ev_user = json.loads(req_doc["messages"][1]["content"])
            snip = ev_user["snippets"][0]
            sink_ln = ev_user["start"]["line"]
            line_obj = next(l for l in snip["lines"] if l["line"] == sink_ln)
            return {
                "status": "SUPPORTED",
                "explanation": "Direct Path.of sink.",
                "fix_suggestion": "Normalize and verify boundary.",
                "citations": [{
                    "path": snip["path"],
                    "start_line": sink_ln,
                    "end_line": sink_ln,
                    "quote": line_obj["text"],
                    "sha256": snip["sha256"],
                }],
            }

        # 1. Default off & explicit opt-in via config/env MUST be rejected clearly
        default_cfg = ApiConfig(data_dir=self.root / "data_p0_6_def", rules_path=self.rules, runtime_origin="mock")
        self.assertFalse(default_cfg.enable_qwen_cache)
        with self.assertRaises(ValueError):
            ApiConfig(data_dir=self.root / "data_p0_6_on", rules_path=self.rules, enable_qwen_cache=True, runtime_origin="mock")
        with patch.dict(os.environ, {"NTK_ENABLE_QWEN_CACHE": "1"}):
            with self.assertRaises(ValueError):
                ApiConfig.from_env({"data_dir": self.root / "data_p0_6_env", "rules_path": self.rules, "runtime_origin": "mock"})

        # 2. Locked ProvenanceQwenCache never stores or replays; direct live HTTP always executes
        locked_cache = ProvenanceQwenCache(self.root / "locked_cache")
        self.assertFalse(locked_cache.is_enabled())
        self.assertIsNone(locked_cache.store({}, {}))
        self.assertIsNone(locked_cache.lookup({}))

        # 3. Defense-in-depth inventory verifier detects added, deleted, and modified .java files
        src_inv = self.root / "src_inv_chk"
        src_inv.mkdir()
        jf1 = src_inv / "RepoCtrl.java"
        jf1.write_text(ctrl_java, encoding="utf-8")
        inv_map = {"RepoCtrl.java": digest(jf1.read_bytes())}
        self.assertTrue(_verify_source_inventory_on_disk(src_inv, inv_map))
        (src_inv / "NewHelper.java").write_text("package demo; class NewHelper {}\n", encoding="utf-8")
        self.assertFalse(_verify_source_inventory_on_disk(src_inv, inv_map))
        (src_inv / "NewHelper.java").unlink()
        self.assertTrue(_verify_source_inventory_on_disk(src_inv, inv_map))

        with _ScriptedOllamaServer(_respond_supported) as ol:
            # 4. Calling run_bounded_triage(..., enable_qwen_cache=True) MUST fail closed
            og_c, man_c = _make_manifest_and_opengrep(
                src_inv, "RepoCtrl.java",
                rule_id="ntk.api.java.cwe22.path-traversal", cwe="CWE-22",
                source_line=6, source_text='req.getParameter("p")',
                sink_line=7, sink_text='Files.readString(Path.of("/srv/files", p))',
                rules_path=self.rules,
            )
            with self.assertRaises(EvidenceError):
                run_bounded_triage(
                    source_root=src_inv,
                    triage_dir=self.root / "triage_cache_blocked",
                    raw_json_path=og_c,
                    manifest_path=man_c,
                    path_maps=[],
                    rules_path=self.rules,
                    no_llm=False,
                    prompt_contract="blind",
                    ollama_endpoint=ol.endpoint,
                    ollama_model="qwen3.5:9b-q4_K_M",
                    ollama_timeout_seconds=10.0,
                    runtime_origin="unverified",
                    deadline_mono=time.monotonic() + 20.0,
                    enable_qwen_cache=True,
                )

            # 5. Two identical jobs always invoke live HTTP Qwen directly (cache_hits == 0, post_count == 2)
            cfg = ApiConfig(
                host="127.0.0.1", port=0, data_dir=self.root / "data_p0_6", api_token="p06-token-123456",
                opengrep_binary=fake_og, rules_path=self.rules, ollama_endpoint=ol.endpoint,
                enable_qwen_cache=False, runtime_origin="unverified",
            )
            mgr = ScanJobManager(cfg)
            try:
                z_a = _make_java_zip({"RepoCtrl.java": ctrl_java})
                for name in ("repo_1.zip", "repo_2.zip"):
                    j = mgr.submit_zip_job(name, z_a)
                    while mgr.get_job(j["job_id"])["state"] not in ("COMPLETED", "FAILED"):
                        time.sleep(0.05)
                    j = mgr.get_job(j["job_id"])
                    self.assertEqual(j["state"], "COMPLETED", j)
                self.assertEqual(ol.post_count, 2)
            finally:
                mgr.shutdown(wait=True)

    # ------------------------------------------------------------------
    # P0-VII: Prompt > 32KB aborted fail-closed & inline/string-paren Spring parser
    # ------------------------------------------------------------------
    def test_p0_7_oversized_single_line_never_exceeds_32kb_or_sent_and_parser_handles_inline_parens(self) -> None:
        java_ann = (
            "package demo;\n"
            "import org.springframework.web.bind.annotation.*;\n"
            "public class AnnParserDemo {\n"
            '    @GetMapping("/x(1)") public String handle(@RequestParam(defaultValue = "(") String p, String q) {\n'
            '        return p + q;\n'
            "    }\n"
            "}\n"
        )
        parsed = parse_java_structure_v2(java_ann)
        self.assertEqual([m["name"] for m in parsed["methods"]], ["handle"])
        m0 = parsed["methods"][0]
        self.assertTrue(m0["is_entrypoint"])
        self.assertIn("GetMapping", m0["annotations"])
        self.assertEqual(len(m0["parameters"]), 2, f"Expected 2 params, got {m0['parameters']}")

        # Very long single Java line right in mandatory window -> prompt > 32KB -> MUST fail closed and NOT call Ollama!
        huge_line = '        String hugePad = "' + ("X" * 35_000) + '";'
        java_huge = (
            "package demo;\n"
            "import java.sql.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class HugeSingleLine {\n"
            "    public void run(HttpServletRequest req, Statement stmt) throws Exception {\n"
            '        String u = req.getParameter("u");\n'
            + huge_line + "\n"
            '        stmt.executeQuery("SELECT * FROM t WHERE u=\'" + u + "\'");\n'
            "    }\n"
            "}\n"
        )
        src_h = self.root / "src_huge_line"
        src_h.mkdir()
        (src_h / "HugeSingleLine.java").write_text(java_huge, encoding="utf-8")
        og_h, man_h = _make_manifest_and_opengrep(
            src_h, "HugeSingleLine.java",
            rule_id="ntk.api.java.cwe89.sql-injection", cwe="CWE-89",
            source_line=6, source_text='req.getParameter("u")',
            sink_line=8, sink_text='stmt.executeQuery("SELECT * FROM t WHERE u=\'" + u + "\'")',
            rules_path=self.rules,
        )
        b_h = collect(
            og_h.read_bytes(), src_h, engine_exit=0,
            scan_provenance={"origin": "unit", "source_capture_verified": True, "exit_capture_verified": True, "recorded_engine_exit": 0},
        )
        enrich_bundle_context(b_h, src_h, max_prompt_bytes=DEFAULT_MAX_PROMPT_BYTES)
        rec_h = b_h["records"][0]
        final_bytes = len(json.dumps(build_prompt(rec_h), ensure_ascii=False).encode("utf-8"))
        # Either compacted safely <= 32KB without dropping source/sink/guard, OR issues non-empty!
        if final_bytes > DEFAULT_MAX_PROMPT_BYTES:
            self.assertTrue(rec_h["issues"], "Oversized prompt (>32KB) MUST record fail-closed issue!")

        with _ScriptedOllamaServer(lambda _r, _n: {}) as ol:
            res_h = run_bounded_triage(
                source_root=src_h,
                triage_dir=self.root / "triage_huge_line",
                raw_json_path=og_h,
                manifest_path=man_h,
                path_maps=[],
                rules_path=self.rules,
                no_llm=False,
                prompt_contract="blind",
                ollama_endpoint=ol.endpoint,
                ollama_model="qwen3.5:9b-q4_K_M",
                ollama_timeout_seconds=10.0,
                runtime_origin="unverified",
                deadline_mono=time.monotonic() + 20.0,
                max_prompt_bytes=DEFAULT_MAX_PROMPT_BYTES,
            )
            self.assertEqual(ol.post_count, 0, "Oversized uncompacted prompt MUST NEVER be sent to Ollama!")
            self.assertEqual(res_h["assessments_list"][0]["validated_status"], "UNDETERMINED")

    # ------------------------------------------------------------------
    # P1-VIII: Job deadline -> FAILED JOB_TIMEOUT, no post-deadline calls, storage error not published
    # ------------------------------------------------------------------
    def test_p1_8_job_timeout_fails_job_and_storage_failure_not_published(self) -> None:
        multi_java = (
            "package demo;\n"
            "import java.sql.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class MultiTo {\n"
            "    public void run(HttpServletRequest req, Statement st) throws Exception {\n"
            '        String u = req.getParameter("u");\n'
            '        st.executeQuery("SELECT 1 FROM a WHERE u=\'" + u + "\'");\n'
            '        st.executeQuery("SELECT 2 FROM b WHERE u=\'" + u + "\'");\n'
            '        st.executeQuery("SELECT 3 FROM c WHERE u=\'" + u + "\'");\n'
            "    }\n"
            "}\n"
        )
        fake_og = _create_fake_opengrep_from_fixtures(self.root, subdir="og_p1_8")
        # 1. Expired deadline -> job MUST end FAILED with JOB_TIMEOUT, never COMPLETED; evidence kept!
        with _ScriptedOllamaServer(lambda _r, _n: (1.2, {
            "status": "SUPPORTED", "explanation": "SQLi", "fix_suggestion": "PS", "citations": []
        })) as ol:
            cfg_to = ApiConfig(
                host="127.0.0.1", port=0,
                data_dir=self.root / "data_p1_8_to",
                api_token="p18-token-123456",
                opengrep_binary=fake_og, rules_path=self.rules,
                ollama_endpoint=ol.endpoint,
                job_timeout_seconds=1.5,
                ollama_timeout_seconds=10.0,
                runtime_origin="unverified",
            )
            mgr_to = ScanJobManager(cfg_to)
            try:
                zbytes = _make_java_zip({"MultiTo.java": multi_java})
                j_to = mgr_to.submit_zip_job("to.zip", zbytes)
                dl = time.monotonic() + 20.0
                while time.monotonic() < dl:
                    cur = mgr_to.get_job(j_to["job_id"])
                    if cur["state"] in ("COMPLETED", "FAILED"):
                        break
                    time.sleep(0.05)
                cur = mgr_to.get_job(j_to["job_id"])
                self.assertEqual(cur["state"], "FAILED", f"Timed out job must NOT report COMPLETED: {cur}")
                self.assertEqual(cur["error_code"], "JOB_TIMEOUT")
                # Failed evidence preserved on disk
                triage_dir = cfg_to.data_dir / "scans" / cur["job_id"] / "triage"
                self.assertTrue((triage_dir / "evidence.json").is_file())
                self.assertTrue((triage_dir / "review.sqlite").is_file())
            finally:
                mgr_to.shutdown(wait=True)

        # 1b. Deadline already expired after OpenGrep -> NO /api/tags, NO /api/ps, NO /api/chat calls!
        slow_og = _create_fake_opengrep_from_fixtures(self.root, subdir="og_p1_8_slow", sleep_sec=1.6)
        with _ScriptedOllamaServer(lambda _r, _n: {
            "status": "SUPPORTED", "explanation": "SQLi", "fix_suggestion": "PS", "citations": []
        }) as ol_post_dl:
            cfg_dl = ApiConfig(
                host="127.0.0.1", port=0,
                data_dir=self.root / "data_p1_8_dl",
                api_token="p18dl-token-1234",
                opengrep_binary=slow_og, rules_path=self.rules,
                ollama_endpoint=ol_post_dl.endpoint,
                job_timeout_seconds=1.2,
                ollama_timeout_seconds=10.0,
                runtime_origin="unverified",
            )
            mgr_dl = ScanJobManager(cfg_dl)
            try:
                j_dl = mgr_dl.submit_zip_job("dl.zip", _make_java_zip({"MultiTo.java": multi_java}))
                dl = time.monotonic() + 20.0
                while time.monotonic() < dl:
                    cur_dl = mgr_dl.get_job(j_dl["job_id"])
                    if cur_dl["state"] in ("COMPLETED", "FAILED"):
                        break
                    time.sleep(0.05)
                cur_dl = mgr_dl.get_job(j_dl["job_id"])
                self.assertEqual(cur_dl["state"], "FAILED", cur_dl)
                self.assertEqual(cur_dl["error_code"], "JOB_TIMEOUT")
                self.assertEqual(ol_post_dl.tags_count, 0, "Must NOT probe /api/tags after job deadline!")
                self.assertEqual(ol_post_dl.post_count, 0, "Must NOT call /api/chat after job deadline!")
                self.assertIsNone(cur_dl["scan_id"])
                self.assertEqual(TriageApiService(cfg_dl).list_scans()["total_count"], 0)
            finally:
                mgr_dl.shutdown(wait=True)

        # 1c. no_llm=True with slow scanner exceeding job_timeout_seconds -> MUST fail JOB_TIMEOUT and NOT publish!
        cfg_nollm_to = ApiConfig(
            host="127.0.0.1", port=0,
            data_dir=self.root / "data_p1_8_nollm_to",
            api_token="p18no-token-1234",
            opengrep_binary=slow_og, rules_path=self.rules,
            job_timeout_seconds=1.0,
            runtime_origin="mock",
        )
        mgr_nollm_to = ScanJobManager(cfg_nollm_to)
        try:
            j_no = mgr_nollm_to.submit_zip_job("nollm_to.zip", _make_java_zip({"MultiTo.java": multi_java}), no_llm=True)
            dl = time.monotonic() + 20.0
            while time.monotonic() < dl:
                cur_no = mgr_nollm_to.get_job(j_no["job_id"])
                if cur_no["state"] in ("COMPLETED", "FAILED"):
                    break
                time.sleep(0.05)
            cur_no = mgr_nollm_to.get_job(j_no["job_id"])
            self.assertEqual(cur_no["state"], "FAILED", cur_no)
            self.assertEqual(cur_no["error_code"], "JOB_TIMEOUT")
            self.assertIsNone(cur_no["scan_id"])
            self.assertEqual(TriageApiService(cfg_nollm_to).list_scans()["total_count"], 0)
        finally:
            mgr_nollm_to.shutdown(wait=True)

        # 1d. Last Qwen /api/chat call finishes AFTER deadline_mono -> MUST fail JOB_TIMEOUT and NOT publish!
        single_java = (
            "package demo;\nimport java.sql.*;\nimport javax.servlet.http.HttpServletRequest;\n"
            "public class SingleTo {\n    public void run(HttpServletRequest req, Statement st) throws Exception {\n"
            '        String u = req.getParameter("u");\n        st.executeQuery("SELECT * FROM a WHERE u=\'" + u + "\'");\n'
            "    }\n}\n"
        )
        with _ScriptedOllamaServer(lambda req_doc, _n: (1.5, {
            "status": "SUPPORTED", "explanation": "SQLi", "fix_suggestion": "PS",
            "citations": [{
                "path": "SingleTo.java", "start_line": 7, "end_line": 7,
                "quote": single_java.splitlines()[6],
                "sha256": json.loads(req_doc["messages"][1]["content"])["snippets"][0]["sha256"],
            }],
        })) as ol_last:
            cfg_last = ApiConfig(
                host="127.0.0.1", port=0,
                data_dir=self.root / "data_p1_8_last",
                api_token="p18last-token-123",
                opengrep_binary=fake_og, rules_path=self.rules,
                ollama_endpoint=ol_last.endpoint,
                job_timeout_seconds=1.1,
                ollama_timeout_seconds=10.0,
                runtime_origin="unverified",
            )
            mgr_last = ScanJobManager(cfg_last)
            try:
                j_last = mgr_last.submit_zip_job("last.zip", _make_java_zip({"SingleTo.java": single_java}))
                dl = time.monotonic() + 20.0
                while time.monotonic() < dl:
                    cur_last = mgr_last.get_job(j_last["job_id"])
                    if cur_last["state"] in ("COMPLETED", "FAILED"):
                        break
                    time.sleep(0.05)
                cur_last = mgr_last.get_job(j_last["job_id"])
                self.assertEqual(cur_last["state"], "FAILED", cur_last)
                self.assertEqual(cur_last["error_code"], "JOB_TIMEOUT")
                self.assertIsNone(cur_last["scan_id"])
                self.assertEqual(TriageApiService(cfg_last).list_scans()["total_count"], 0)
            finally:
                mgr_last.shutdown(wait=True)

        # 2. Storage failure (sqlite3.OperationalError & post-commit JSONL/meta failure) -> FAILED + NOT published in /api/scans!
        with _ScriptedOllamaServer(lambda req_doc, _n: (
            lambda snip, ln: {
                "status": "SUPPORTED", "explanation": "SQLi", "fix_suggestion": "PS",
                "citations": [{"path": snip["path"], "start_line": ln, "end_line": ln, "quote": next(l["text"] for l in snip["lines"] if l["line"] == ln), "sha256": snip["sha256"]}],
            }
        )(json.loads(req_doc["messages"][1]["content"])["snippets"][0], json.loads(req_doc["messages"][1]["content"])["start"]["line"])) as ol2:
            cfg_st = ApiConfig(
                host="127.0.0.1", port=0,
                data_dir=self.root / "data_p1_8_st",
                api_token="p18-st-token-1234",
                opengrep_binary=fake_og, rules_path=self.rules,
                ollama_endpoint=ol2.endpoint,
                runtime_origin="unverified",
            )
            mgr_st = ScanJobManager(cfg_st)
            try:
                with patch("v2.api.qwen_triage.ReviewStore.add", side_effect=sqlite3.OperationalError("simulated disk full")):
                    j_sql_err = mgr_st.submit_zip_job("sqlerr.zip", _make_java_zip({"MultiTo.java": multi_java}))
                    dl = time.monotonic() + 15.0
                    while time.monotonic() < dl:
                        cur = mgr_st.get_job(j_sql_err["job_id"])
                        if cur["state"] in ("COMPLETED", "FAILED"):
                            break
                        time.sleep(0.05)
                    cur = mgr_st.get_job(j_sql_err["job_id"])
                    self.assertEqual(cur["state"], "FAILED", f"sqlite3.OperationalError must mark job FAILED: {cur}")
                    self.assertIn("STORAGE", str(cur.get("error_code") or ""))

                # Post-SQLite commit failure writing assessments.jsonl -> partial scan MUST NOT be published!
                real_open = Path.open

                def _fail_jsonl_open(self_p: Path, mode: str = "r", *args, **kwargs):
                    if "assessments" in self_p.name and ("w" in mode or "x" in mode):
                        raise OSError("simulated jsonl write error after sqlite commit")
                    return real_open(self_p, mode, *args, **kwargs)

                with patch.object(Path, "open", _fail_jsonl_open):
                    j_jerr = mgr_st.submit_zip_job("jerr.zip", _make_java_zip({"MultiTo.java": multi_java}))
                    dl = time.monotonic() + 15.0
                    while time.monotonic() < dl:
                        cur2 = mgr_st.get_job(j_jerr["job_id"])
                        if cur2["state"] in ("COMPLETED", "FAILED"):
                            break
                        time.sleep(0.05)
                    cur2 = mgr_st.get_job(j_jerr["job_id"])
                    self.assertEqual(cur2["state"], "FAILED", cur2)
                    # Evidence preserved on disk, but NOT published in TriageApiService.list_scans()!
                    self.assertTrue((cfg_st.data_dir / "scans" / cur2["job_id"] / "triage" / "review.sqlite").is_file())
                    svc_st = TriageApiService(cfg_st)
                    self.assertEqual(svc_st.list_scans()["total_count"], 0, "Partial failed scan MUST NOT be published!")

                # Failure writing api-scan-meta.json after SQLite+JSONL commit -> FAILED + NOT published!
                real_write_text = Path.write_text

                def _fail_meta_write(self_p: Path, data: str, *args, **kwargs):
                    if "api-scan-meta" in self_p.name:
                        raise OSError("simulated meta write error after sqlite+jsonl commit")
                    return real_write_text(self_p, data, *args, **kwargs)

                with patch.object(Path, "write_text", _fail_meta_write):
                    j_merr = mgr_st.submit_zip_job("merr.zip", _make_java_zip({"MultiTo.java": multi_java}))
                    dl = time.monotonic() + 15.0
                    while time.monotonic() < dl:
                        cur3 = mgr_st.get_job(j_merr["job_id"])
                        if cur3["state"] in ("COMPLETED", "FAILED"):
                            break
                        time.sleep(0.05)
                    cur3 = mgr_st.get_job(j_merr["job_id"])
                    self.assertEqual(cur3["state"], "FAILED", cur3)
                    self.assertIn("STORAGE", str(cur3.get("error_code") or ""))
                    self.assertTrue((cfg_st.data_dir / "scans" / cur3["job_id"] / "triage" / "assessments.jsonl").is_file())
                    self.assertEqual(TriageApiService(cfg_st).list_scans()["total_count"], 0)
            finally:
                mgr_st.shutdown(wait=True)

    # ------------------------------------------------------------------
    # P1-X: Historical mixed cache+live provenance & valid-JSON tampering on assessments.jsonl
    # ------------------------------------------------------------------
    def test_p1_10_mixed_cache_live_provenance_and_valid_json_tamper(self) -> None:
        from v2.triage.store import ReviewStore

        f1_java = (
            "package demo;\nimport java.sql.*;\nimport javax.servlet.http.HttpServletRequest;\n"
            "public class CachedOne {\n"
            "    public void run(HttpServletRequest req, Statement st) throws Exception {\n"
            '        String u = req.getParameter("u");\n'
            '        st.executeQuery("SELECT * FROM a WHERE u=\'" + u + "\'");\n'
            "    }\n}\n"
        )
        f2_java = (
            "package demo;\nimport java.sql.*;\nimport javax.servlet.http.HttpServletRequest;\n"
            "public class LiveTwo {\n"
            "    public void run(HttpServletRequest req, Statement st) throws Exception {\n"
            '        String v = req.getParameter("v");\n'
            '        st.executeQuery("SELECT * FROM b WHERE v=\'" + v + "\'");\n'
            "    }\n}\n"
        )
        fake_og = _create_fake_opengrep_from_fixtures(self.root, subdir="og_p1_10")

        def _respond_sqli(req_doc, _n):
            ev_user = json.loads(req_doc["messages"][1]["content"])
            snip = ev_user["snippets"][0]
            ln = ev_user["start"]["line"]
            return {
                "status": "SUPPORTED", "explanation": "SQL concat", "fix_suggestion": "Use PreparedStatement",
                "citations": [{"path": snip["path"], "start_line": ln, "end_line": ln, "quote": next(l["text"] for l in snip["lines"] if l["line"] == ln), "sha256": snip["sha256"]}],
            }

        default_cfg = ApiConfig(data_dir=self.root / "data_p1_10_def", rules_path=self.rules, runtime_origin="mock")
        self.assertFalse(default_cfg.enable_qwen_cache)

        with _ScriptedOllamaServer(_respond_sqli) as ol_live:
            hist_mixed = self.root / "hist_mixed_scan"
            cfg_m = ApiConfig(
                host="127.0.0.1", port=0,
                data_dir=self.root / "data_p1_10_mix",
                reviewable_scan_dirs=(hist_mixed,),
                api_token="p110m-token-1234",
                opengrep_binary=fake_og, rules_path=self.rules,
                ollama_endpoint=ol_live.endpoint,
                enable_qwen_cache=False,
                runtime_origin="unverified",
            )
            mgr_m = ScanJobManager(cfg_m)
            svc_m = TriageApiService(cfg_m)
            try:
                z_mix = _make_java_zip({"CachedOne.java": f1_java, "LiveTwo.java": f2_java})
                j_live = mgr_m.submit_zip_job("m1.zip", z_mix)
                while mgr_m.get_job(j_live["job_id"])["state"] not in ("COMPLETED", "FAILED"):
                    time.sleep(0.05)
                j_live = mgr_m.get_job(j_live["job_id"])
                self.assertEqual(j_live["state"], "COMPLETED", j_live)

                # Valid-JSON same-size same-mtime tamper on assessments.jsonl (mutating raw_response) MUST fail 409!
                rep_live = svc_m.export_scan_report(j_live["scan_id"])
                self.assertEqual(rep_live["data_origin"], "REAL_SCAN")
                jsonl_p = cfg_m.data_dir / "scans" / j_live["job_id"] / "triage" / "assessments.jsonl"
                orig_stat = jsonl_p.stat()
                orig_txt = jsonl_p.read_text(encoding="utf-8")
                self.assertIn("SQL concat", orig_txt)
                tampered_txt = orig_txt.replace("SQL concat", "SQL concaX", 1)
                self.assertEqual(len(tampered_txt.encode("utf-8")), len(orig_txt.encode("utf-8")))
                jsonl_p.write_text(tampered_txt, encoding="utf-8")
                os.utime(jsonl_p, ns=(orig_stat.st_atime_ns, orig_stat.st_mtime_ns))
                with self.assertRaises(ApiServiceError) as ctx_t:
                    svc_m.export_scan_report(j_live["scan_id"])
                self.assertEqual(ctx_t.exception.http_status, 409)
                self.assertEqual(ctx_t.exception.error_code, "ARTIFACT_PROVENANCE_MISMATCH")

                # Historical mixed cached+live scan artifact in reviewable_scan_dirs preserves per-finding triage_provenance
                jsonl_p.write_text(orig_txt, encoding="utf-8")
                shutil.copytree(cfg_m.data_dir / "scans" / j_live["job_id"], hist_mixed)
                (hist_mixed / "api-scan-meta.json").unlink()
                ev_h = json.loads((hist_mixed / "triage" / "evidence.json").read_text(encoding="utf-8"))
                rows_h = [json.loads(ln) for ln in (hist_mixed / "triage" / "assessments.jsonl").read_text(encoding="utf-8").splitlines() if ln.strip()]
                for r_h in rows_h:
                    if "CachedOne" in r_h["evidence"]["path"]:
                        r_h["assessment"]["transport"] = "qwen-cache-verified"
                        r_h["assessment"]["raw_response"] = None
                        r_h["assessment"]["runtime"].update({
                            "origin": "cached_verified", "cache_hit": True, "request_attempted": False, "model_runtime_verified": False,
                        })
                (hist_mixed / "triage" / "assessments.jsonl").write_text(
                    "".join(json.dumps(r) + "\n" for r in rows_h), encoding="utf-8"
                )
                (hist_mixed / "triage" / "review.sqlite").unlink()
                rs_h = ReviewStore(hist_mixed / "triage" / "review.sqlite")
                try:
                    rs_h.add(ev_h, [r["assessment"] for r in rows_h])
                finally:
                    rs_h.close()

                mix_summary = next(sc for sc in svc_m.list_scans()["scans"] if sc["data_origin"] == "MIXED_CACHE_AND_LIVE_HTTP")
                rep_mix = svc_m.export_scan_report(mix_summary["scan_id"])
                self.assertFalse(rep_mix["scan_summary"]["qwen_runtime_verified"])
                self.assertEqual(rep_mix["data_origin"], "MIXED_CACHE_AND_LIVE_HTTP")
                by_fp = {f["file_path"]: f for f in rep_mix["findings"]}
                self.assertEqual(by_fp["CachedOne.java"].get("triage_provenance"), "CACHED_TRIAGE_NO_LIVE_HTTP")
                self.assertEqual(by_fp["LiveTwo.java"].get("triage_provenance"), "LIVE_HTTP_CAPTURED")
            finally:
                mgr_m.shutdown(wait=True)

    # ------------------------------------------------------------------
    # Section G: Consistent scan publication across managed & reviewable paths + legacy schema compatibility
    # ------------------------------------------------------------------
    def test_section_g_consistent_scan_publication_and_legacy_schema_compatibility(self) -> None:
        from v2.triage.store import ReviewStore

        data_dir = self.root / "data_sec_g"
        scans_dir = data_dir / "scans"
        jobs_dir = data_dir / "jobs"
        scans_dir.mkdir(parents=True)
        jobs_dir.mkdir(parents=True)

        def _seed_base_scan(scan_dir: Path, scan_sha: str) -> None:
            (scan_dir / "capture").mkdir(parents=True, exist_ok=True)
            (scan_dir / "triage").mkdir(parents=True, exist_ok=True)
            og_bytes = json.dumps({"version": "1.25.0", "results": [], "errors": []}).encode("utf-8")
            # Ensure actual sha matches scan_sha for legacy check by returning digest
            (scan_dir / "capture" / "opengrep.json").write_bytes(og_bytes)
            (scan_dir / "capture" / "scan-manifest.json").write_text(json.dumps({"success": True}), encoding="utf-8")
            (scan_dir / "triage" / "input.opengrep.json").write_bytes(og_bytes)
            actual_sha = digest(og_bytes)
            b_doc = {
                "schema_version": "1.1",
                "scan_sha256": actual_sha,
                "collected_at": "2026-11-22T01:00:00+00:00",
                "scan_provenance": {"origin": "recorded_capture_unsigned", "source_capture_verified": True, "exit_capture_verified": True, "recorded_engine_exit": 0},
                "records": [],
            }
            (scan_dir / "triage" / "evidence.json").write_text(json.dumps(b_doc), encoding="utf-8")
            rs = ReviewStore(scan_dir / "triage" / "review.sqlite")
            try:
                rs.add(b_doc, [])
            finally:
                rs.close()
            return actual_sha

        # 1. In-progress managed scan (no api-scan-meta.json, no assessments.jsonl) MUST be hidden on BOTH default & overlapping reviewable/readonly!
        inprog_dir = scans_dir / "job-inprog-1"
        _seed_base_scan(inprog_dir, "")
        (jobs_dir / "job-inprog-1.json").write_text(json.dumps({"job_id": "job-inprog-1", "state": "RUNNING"}), encoding="utf-8")

        # 2. Failed managed scan (publishable=False / api-scan-failure.json) MUST be hidden on ALL discovery paths
        failed_dir = scans_dir / "job-failed-1"
        f_sha = _seed_base_scan(failed_dir, "")
        (failed_dir / "triage" / "assessments.jsonl").write_text("", encoding="utf-8")
        (failed_dir / "api-scan-meta.json").write_text(json.dumps({"scan_id": None, "scan_sha256": f_sha, "job_id": "job-failed-1", "job_state": "FAILED", "publishable": False}), encoding="utf-8")
        (failed_dir / "api-scan-failure.json").write_text(json.dumps({"job_id": "job-failed-1", "state": "FAILED", "publishable": False}), encoding="utf-8")

        for extra_rw in ((), (scans_dir,), (inprog_dir,), (data_dir,)):
            svc_check = TriageApiService(
                ApiConfig(data_dir=data_dir, reviewable_scan_dirs=extra_rw, readonly_scan_dirs=extra_rw, rules_path=self.rules, runtime_origin="mock")
            )
            self.assertEqual(svc_check.list_scans()["total_count"], 0, f"In-progress/failed scan leaked via reviewable_scan_dirs={extra_rw}")

        # 3. Completed legacy baseline-commit scan (lacking `publishable` and `job_state`) MUST remain visible & readable!
        legacy_dir = scans_dir / "job-legacy-ok"
        leg_sha = _seed_base_scan(legacy_dir, "")
        (legacy_dir / "triage" / "assessments.jsonl").write_text("", encoding="utf-8")
        (jobs_dir / "job-legacy-ok.json").write_text(json.dumps({"job_id": "job-legacy-ok", "state": "COMPLETED"}), encoding="utf-8")
        (legacy_dir / "api-scan-meta.json").write_text(
            json.dumps({
                "scan_id": leg_sha,
                "scan_sha256": leg_sha,
                "job_id": "job-legacy-ok",
                "data_origin": "REAL_SCAN",
                "input_mode": "ZIP",
                "started_at": "2026-11-22T00:59:00+00:00",
                "completed_at": "2026-11-22T01:00:00+00:00",
                "stage_statuses": {
                    "scanner_status": "OK",
                    "json_sarif_parity_status": "MATCHED",
                    "queue_status": "OPEN_READY",
                },
            }),
            encoding="utf-8",
        )
        svc_leg = TriageApiService(
            ApiConfig(data_dir=data_dir, reviewable_scan_dirs=(scans_dir,), rules_path=self.rules, runtime_origin="mock")
        )
        listed = svc_leg.list_scans()
        self.assertEqual(listed["total_count"], 1, f"Legacy completed scan hidden or leaked! {listed}")
        self.assertEqual(listed["scans"][0]["scan_id"], leg_sha)
        self.assertEqual(svc_leg.list_findings(leg_sha)["scan_id"], leg_sha)
        self.assertEqual(svc_leg.export_scan_report(leg_sha)["scan_summary"]["scan_id"], leg_sha)

        # 4. Legacy-like meta missing assessments.jsonl or completed_at MUST still be rejected
        bad_legacy_dir = scans_dir / "job-legacy-incomplete"
        bad_sha = _seed_base_scan(bad_legacy_dir, "")
        (bad_legacy_dir / "api-scan-meta.json").write_text(
            json.dumps({
                "scan_id": bad_sha,
                "scan_sha256": bad_sha,
                "job_id": "job-legacy-incomplete",
                "completed_at": "2026-11-22T01:00:00+00:00",
                "stage_statuses": {"scanner_status": "OK", "json_sarif_parity_status": "MATCHED", "queue_status": "OPEN_READY"},
            }),
            encoding="utf-8",
        )
        self.assertEqual(svc_leg.list_scans()["total_count"], 1)

    # ------------------------------------------------------------------
    # Blocker C Adversarial: Java overflow, non-constant guards, try/catch,
    # non-dominance, and valid structural refutation controls
    # ------------------------------------------------------------------
    def test_blocker_c_adversarial_refutation_proof_and_preserving_raw_evidence(self) -> None:
        int_overflow_sql = (
            "package demo;\n"
            "import java.sql.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class IntOverflowCtrl {\n"
            "    public void run(HttpServletRequest req, Statement st) throws Exception {\n"
            "        int num = 2147483647;\n"
            '        String u = req.getParameter("u");\n'
            "        String q;\n"
            "        if ((2 * 2) + num > 0) {\n"
            '            q = "SELECT 1";\n'
            "        } else {\n"
            '            q = "SELECT * FROM users WHERE u=\'" + u + "\'";\n'
            "        }\n"
            "        st.executeQuery(q);\n"
            "    }\n"
            "}\n"
        )
        overflow_path = (
            "package demo;\n"
            "import java.io.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class OverflowPathCtrl {\n"
            "    public FileInputStream open(HttpServletRequest req) throws IOException {\n"
            '        String p = req.getParameter("p");\n'
            "        int num = 2147483647;\n"
            "        if ((2 * 2) + num > 0) {\n"
            '            p = "safe.txt";\n'
            "        }\n"
            '        return new FileInputStream(new File("/srv/files", p));\n'
            "    }\n"
            "}\n"
        )
        long_overflow_sql = (
            "package demo;\n"
            "import java.sql.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class LongOverflowCtrl {\n"
            "    public void run(HttpServletRequest req, Statement st) throws Exception {\n"
            "        long num = 9223372036854775807L;\n"
            '        String u = req.getParameter("u");\n'
            "        String q;\n"
            "        if (num + 1L > 0L) {\n"
            '            q = "SELECT 1";\n'
            "        } else {\n"
            '            q = "SELECT * FROM users WHERE u=\'" + u + "\'";\n'
            "        }\n"
            "        st.executeQuery(q);\n"
            "    }\n"
            "}\n"
        )
        wrong_var_guard = (
            "package demo;\n"
            "import java.io.*;\n"
            "import java.nio.file.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class WrongVarGuardCtrl {\n"
            "    public String read(HttpServletRequest req) throws Exception {\n"
            '        String raw = req.getParameter("p");\n'
            '        File base = new File("/srv/safe");\n'
            "        String baseCanon = base.getCanonicalPath();\n"
            '        File decoy = new File(base, "safe.txt");\n'
            "        String decoyCanon = decoy.getCanonicalPath();\n"
            "        File realTarget = new File(base, raw);\n"
            "        String realCanon = realTarget.getCanonicalPath();\n"
            "        if (!decoyCanon.startsWith(baseCanon + File.separator)) {\n"
            '            throw new SecurityException("bad");\n'
            "        }\n"
            "        return Files.readString(Paths.get(realCanon));\n"
            "    }\n"
            "}\n"
        )
        swallowed_try_guard = (
            "package demo;\n"
            "import java.io.*;\n"
            "import java.nio.file.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class SwallowedTryGuardCtrl {\n"
            "    public String read(HttpServletRequest req) throws Exception {\n"
            '        String raw = req.getParameter("p");\n'
            '        File base = new File("/srv/safe");\n'
            "        String baseCanon = base.getCanonicalPath();\n"
            "        File target = new File(base, raw);\n"
            "        String targetCanon = target.getCanonicalPath();\n"
            "        try {\n"
            "            if (!targetCanon.startsWith(baseCanon + File.separator)) {\n"
            '                throw new SecurityException("bad");\n'
            "            }\n"
            "        } catch (SecurityException ignored) {\n"
            "        }\n"
            "        return Files.readString(Paths.get(targetCanon));\n"
            "    }\n"
            "}\n"
        )
        tainted_base_guard = (
            "package demo;\n"
            "import java.io.*;\n"
            "import java.nio.file.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class TaintedBaseGuardCtrl {\n"
            "    public String read(HttpServletRequest req) throws Exception {\n"
            '        String raw = req.getParameter("p");\n'
            '        File base = new File(req.getParameter("base"));\n'
            "        String baseCanon = base.getCanonicalPath();\n"
            "        File target = new File(base, raw);\n"
            "        String targetCanon = target.getCanonicalPath();\n"
            "        if (!targetCanon.startsWith(baseCanon + File.separator)) {\n"
            '            throw new SecurityException("bad");\n'
            "        }\n"
            "        return Files.readString(Paths.get(targetCanon));\n"
            "    }\n"
            "}\n"
        )
        safe_canon_guard = (
            "package demo;\n"
            "import java.io.*;\n"
            "import java.nio.file.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class SafeCanonGuardCtrl {\n"
            "    public String read(HttpServletRequest req) throws Exception {\n"
            '        String raw = req.getParameter("p");\n'
            '        File base = new File("/srv/safe");\n'
            "        String baseCanon = base.getCanonicalPath();\n"
            "        File target = new File(base, raw);\n"
            "        String targetCanon = target.getCanonicalPath();\n"
            "        if (!targetCanon.startsWith(baseCanon + File.separator)) {\n"
            '            throw new SecurityException("bad");\n'
            "        }\n"
            "        return Files.readString(Paths.get(targetCanon));\n"
            "    }\n"
            "}\n"
        )
        safe_const_sql = (
            "package demo;\n"
            "import java.sql.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class SafeConstSqlCtrl {\n"
            "    public void run(HttpServletRequest req, Statement st) throws Exception {\n"
            '        String ignored = req.getParameter("u");\n'
            '        String q = "SELECT id FROM users";\n'
            "        st.executeQuery(q);\n"
            "    }\n"
            "}\n"
        )
        safe_scalar_sql = (
            "package demo;\n"
            "import java.sql.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class SafeScalarSqlCtrl {\n"
            "    public void run(HttpServletRequest req, Statement st) throws Exception {\n"
            '        String raw = req.getParameter("id");\n'
            "        int safeId = Integer.parseInt(raw);\n"
            '        st.executeQuery("SELECT * FROM users WHERE id=" + safeId);\n'
            "    }\n"
            "}\n"
        )

        # Confirm sealed heuristics emits deceptive REFUTED on OverflowPathCtrl (root cause of Blocker C)
        self.assertEqual(
            extract_evidence_signals({
                "rule_id": "ntk.api.java.cwe22.path-traversal",
                "cwe": ["CWE-22"],
                "start": {"line": 11, "col": 9},
                "raw_trace": {
                    "taint_source": ["CliLoc", [{"line": 6, "col": 20}, 'req.getParameter("p")']],
                    "intermediate_vars": [],
                    "taint_sink": ["CliLoc", [{"line": 11, "col": 16}, 'new FileInputStream(new File("/srv/files", p))']],
                },
                "java_context": {"enclosing_method": {"name": "open", "header_line": 5, "end_line": 12}},
                "snapshots": {"OverflowPathCtrl.java": {"sha256": "h"}},
                "snippets": [{"role": "finding", "path": "OverflowPathCtrl.java", "sha256": "h",
                              "start": {"line": 11}, "end": {"line": 11},
                              "lines": [{"line": i + 1, "text": l} for i, l in enumerate(overflow_path.splitlines())]}],
            }).get("recommended_status"),
            "REFUTED",
        )

        fake_og = _create_fake_opengrep_from_fixtures(self.root, subdir="og_blocker_c")

        def _respond_refuted_full_method(req_doc, _n):
            ev_user = json.loads(req_doc["messages"][1]["content"])
            snip = ev_user["snippets"][0]
            lines = snip["lines"]
            return {
                "status": "REFUTED",
                "explanation": "Cho rang nhanh an toan hoac da duoc kiem soat.",
                "fix_suggestion": "Khong can sua.",
                "citations": [{
                    "path": snip["path"],
                    "start_line": lines[0]["line"],
                    "end_line": lines[-1]["line"],
                    "quote": "\n".join(l["text"] for l in lines),
                    "sha256": snip["sha256"],
                }],
            }

        with _ScriptedOllamaServer(_respond_refuted_full_method) as ol:
            cfg = ApiConfig(
                host="127.0.0.1",
                port=0,
                data_dir=self.root / "data_blocker_c",
                api_token="blk-c-token-1234",
                opengrep_binary=fake_og,
                rules_path=self.rules,
                ollama_endpoint=ol.endpoint,
                runtime_origin="unverified",
            )
            mgr = ScanJobManager(cfg)
            try:
                j = mgr.submit_zip_job(
                    "blocker_c.zip",
                    _make_java_zip({
                        "OverflowPathCtrl.java": overflow_path,
                        "IntOverflowCtrl.java": int_overflow_sql,
                        "LongOverflowCtrl.java": long_overflow_sql,
                        "WrongVarGuardCtrl.java": wrong_var_guard,
                        "SwallowedTryGuardCtrl.java": swallowed_try_guard,
                        "TaintedBaseGuardCtrl.java": tainted_base_guard,
                        "SafeCanonGuardCtrl.java": safe_canon_guard,
                        "SafeConstSqlCtrl.java": safe_const_sql,
                        "SafeScalarSqlCtrl.java": safe_scalar_sql,
                    }),
                )
                dl = time.monotonic() + 30.0
                while time.monotonic() < dl:
                    cur = mgr.get_job(j["job_id"])
                    if cur["state"] in ("COMPLETED", "FAILED"):
                        break
                    time.sleep(0.05)
                cur = mgr.get_job(j["job_id"])
                self.assertEqual(cur["state"], "COMPLETED", cur)
                svc = TriageApiService(cfg)
                summary = svc.build_scan_summary(svc.resolve_scan(cur["scan_id"]))
                for limit_text in UNSUPPORTED_REFUTATION_PROOF_LIMITS:
                    self.assertIn(limit_text, summary["known_analysis_limits"])
                by_file = {f["file_path"]: f for f in svc.list_findings(cur["scan_id"])["findings"]}

                for unsafe_tp in (
                    "OverflowPathCtrl.java",
                    "IntOverflowCtrl.java",
                    "LongOverflowCtrl.java",
                    "WrongVarGuardCtrl.java",
                    "SwallowedTryGuardCtrl.java",
                    "TaintedBaseGuardCtrl.java",
                ):
                    row = by_file[unsafe_tp]
                    self.assertEqual(row["raw_model_status"], "REFUTED", unsafe_tp)
                    self.assertEqual(row["validated_status"], "UNDETERMINED", f"{unsafe_tp} leaked REFUTED! {row}")
                    self.assertTrue(row["validator_downgraded"], unsafe_tp)
                    self.assertEqual(row["human_review_state"], "OPEN", unsafe_tp)
                    detail = svc.get_finding_detail(cur["scan_id"], row["id"])
                    self.assertFalse(detail["assessment"].get("supports_security_claim_verified"), unsafe_tp)
                    self.assertTrue(detail["assessment"].get("raw_response"), unsafe_tp)
                    self.assertTrue(detail["assessment"].get("citations"), unsafe_tp)
                    self.assertTrue(detail["assessment"].get("downgrade_reason"), unsafe_tp)

                for safe_ctrl in (
                    "SafeCanonGuardCtrl.java",
                    "SafeConstSqlCtrl.java",
                    "SafeScalarSqlCtrl.java",
                ):
                    row = by_file[safe_ctrl]
                    self.assertEqual(row["validated_status"], "REFUTED", f"Valid control {safe_ctrl} failed: {row}")
                    self.assertFalse(row["validator_downgraded"], safe_ctrl)
                    detail = svc.get_finding_detail(cur["scan_id"], row["id"])
                    self.assertIn(detail["assessment"].get("independent_refutation_proof"), SUPPORTED_REFUTATION_PROOF_CLASSES)
            finally:
                mgr.shutdown(wait=True)

    # ------------------------------------------------------------------
    # Blocker D Adversarial: package qualification, static vs instance,
    # dynamic dispatch, overload ambiguity, concrete local vs virtual `this`
    # ------------------------------------------------------------------
    def test_blocker_d_call_resolution_package_dispatch_and_overloads(self) -> None:
        caller_pkg_p = (
            "package demo;\n"
            "import app.Tools;\n"
            "import java.nio.file.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class Caller {\n"
            "    public String go(HttpServletRequest req) throws Exception {\n"
            '        String x = req.getParameter("x");\n'
            "        String y = p.Tools.adjust(x);\n"
            '        return Files.readString(Path.of("/srv", y));\n'
            "    }\n"
            "}\n"
        )
        app_tools_inst = 'package app;\npublic class Tools {\n    public String adjust(String s) { return "safe"; }\n}\n'
        p_tools_inst = "package p;\npublic class Tools {\n    public String adjust(String s) { return s; }\n}\n"
        p_tools_static = "package p;\npublic class Tools {\n    public static String adjust(String s) { return s; }\n}\n"
        caller_param_dyn = (
            "package demo;\n"
            "import app.Tools;\n"
            "import java.nio.file.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class CallerDyn {\n"
            "    public String go(HttpServletRequest req, Tools t) throws Exception {\n"
            '        String x = req.getParameter("x");\n'
            "        String y = t.adjust(x);\n"
            '        return Files.readString(Path.of("/srv", y));\n'
            "    }\n"
            "}\n"
        )
        caller_concrete_local = (
            "package demo;\n"
            "import app.Tools;\n"
            "import java.nio.file.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class CallerConcrete {\n"
            "    public String go(HttpServletRequest req) throws Exception {\n"
            '        String x = req.getParameter("x");\n'
            "        Tools t = new Tools();\n"
            "        String y = t.adjust(x);\n"
            '        return Files.readString(Path.of("/srv", y));\n'
            "    }\n"
            "}\n"
        )
        caller_virtual_this = (
            "package demo;\n"
            "import java.nio.file.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class CallerVirtualThis {\n"
            "    public String go(HttpServletRequest req) throws Exception {\n"
            '        String x = req.getParameter("x");\n'
            "        String y = this.adjust(x);\n"
            '        return Files.readString(Path.of("/srv", y));\n'
            "    }\n"
            "    protected String adjust(String s) { return s; }\n"
            "}\n"
        )
        overload_helper = (
            "package p;\n"
            "public class Tools {\n"
            "    public static String adjust(String s) { return s; }\n"
            '    public static String adjust(CharSequence s) { return "x"; }\n'
            "}\n"
        )

        def _check_flow(
            cname: str,
            ctxt: str,
            htxt: str | None,
            hname: str | None,
            params: list[str],
            qual: str | None,
            call_line: int,
            sink_line: int,
        ) -> dict:
            snips = [{
                "role": "finding",
                "path": cname,
                "sha256": "hc",
                "lines": [{"line": i + 1, "text": l} for i, l in enumerate(ctxt.splitlines())],
            }]
            snaps = {cname: {"sha256": "hc"}}
            if htxt is not None and hname is not None:
                snips.append({
                    "role": "helper",
                    "path": hname,
                    "sha256": "hh",
                    "lines": [{"line": i + 1, "text": l} for i, l in enumerate(htxt.splitlines())],
                })
                snaps[hname] = {"sha256": "hh"}
            rec = {
                "snippets": snips,
                "snapshots": snaps,
                "java_context": {
                    "enclosing_class": cname[:-5],
                    "enclosing_method": {
                        "name": "go",
                        "header_line": 6 if htxt is not None or cname != "CallerVirtualThis.java" else 5,
                        "end_line": sink_line + 1,
                        "parameters": params,
                    },
                },
                "heuristic_signals": {
                    "sink_line": sink_line,
                    "unresolved_calls": [{"qualifier": qual, "method": "adjust", "line": call_line}],
                },
            }
            fd = analyze_flow_dependencies(rec)
            # Also verify triage_gate decision with valid citation when all methods exist
            rec_gate = {
                **rec,
                "cwe": ["CWE-22"],
                "start": {"line": sink_line, "col": 1},
                "end": {"line": sink_line, "col": 40},
            }
            line_txt = ctxt.splitlines()[sink_line - 1]
            gated = apply_integration_gate(
                rec_gate,
                {
                    "status": "SUPPORTED",
                    "explanation": "Exploit path",
                    "fix_suggestion": "Fix",
                    "citations": [{"path": cname, "start_line": sink_line, "end_line": sink_line, "quote": line_txt, "sha256": "hc"}],
                    "runtime": {"origin": "unit-test", "http_response_received": True, "http_status": 200, "response_complete": True, "model_identity_matched": True},
                },
            )
            return {"flow": fd, "gated": gated}

        # 1. p.Tools.adjust(x) when only app.Tools is present -> MUST block (UNDETERMINED)
        r1 = _check_flow("Caller.java", caller_pkg_p, app_tools_inst, "app/Tools.java", ["HttpServletRequest req"], "p.Tools", 8, 9)
        self.assertTrue(r1["flow"]["has_unverified_helper_dependency"])
        self.assertEqual(r1["gated"].get("validated_status") or r1["gated"].get("status"), "UNDETERMINED")

        # 2. p.Tools.adjust(x) static call matched against non-static p.Tools.adjust -> MUST block (UNDETERMINED)
        r2 = _check_flow("Caller.java", caller_pkg_p, p_tools_inst, "p/Tools.java", ["HttpServletRequest req"], "p.Tools", 8, 9)
        self.assertTrue(r2["flow"]["has_unverified_helper_dependency"])
        self.assertEqual(r2["gated"].get("validated_status") or r2["gated"].get("status"), "UNDETERMINED")

        # 3. p.Tools.adjust(x) static call with verified p.Tools static helper -> ALLOWED (SUPPORTED)
        r3 = _check_flow("Caller.java", caller_pkg_p, p_tools_static, "p/Tools.java", ["HttpServletRequest req"], "p.Tools", 8, 9)
        self.assertFalse(r3["flow"]["has_unverified_helper_dependency"], r3["flow"])
        self.assertEqual(r3["gated"].get("validated_status") or r3["gated"].get("status"), "SUPPORTED")

        # 4. Dynamic dispatch on parameter `Tools t` -> MUST block (UNDETERMINED)
        r4 = _check_flow("CallerDyn.java", caller_param_dyn, app_tools_inst, "app/Tools.java", ["HttpServletRequest req", "Tools t"], "t", 8, 9)
        self.assertTrue(r4["flow"]["has_unverified_helper_dependency"])
        self.assertEqual(r4["gated"].get("validated_status") or r4["gated"].get("status"), "UNDETERMINED")

        # 5. Concrete local `Tools t = new Tools(); t.adjust(x);` with non-static app.Tools.adjust -> ALLOWED (SUPPORTED)
        r5 = _check_flow("CallerConcrete.java", caller_concrete_local, app_tools_inst, "app/Tools.java", ["HttpServletRequest req"], "t", 9, 10)
        self.assertFalse(r5["flow"]["has_unverified_helper_dependency"], r5["flow"])
        self.assertEqual(r5["gated"].get("validated_status") or r5["gated"].get("status"), "SUPPORTED")

        # 6. Non-private/non-final virtual `this.adjust(x)` -> MUST block (UNDETERMINED)
        r6 = _check_flow("CallerVirtualThis.java", caller_virtual_this, None, None, ["HttpServletRequest req"], "this", 7, 8)
        self.assertTrue(r6["flow"]["has_unverified_helper_dependency"])
        self.assertEqual(r6["gated"].get("validated_status") or r6["gated"].get("status"), "UNDETERMINED")

        # 7. Same-arity overload ambiguity in p.Tools -> MUST block (UNDETERMINED)
        r7 = _check_flow("Caller.java", caller_pkg_p, overload_helper, "p/Tools.java", ["HttpServletRequest req"], "p.Tools", 8, 9)
        self.assertTrue(r7["flow"]["has_unverified_helper_dependency"])
        self.assertEqual(r7["gated"].get("validated_status") or r7["gated"].get("status"), "UNDETERMINED")

    # ------------------------------------------------------------------
    # Blocker F Adversarial: NaN/Inf/bool validation + deadline expiry across
    # every finalization boundary (both no_llm=True and no_llm=False) + no PENDING stage
    # ------------------------------------------------------------------
    def test_blocker_f_nan_inf_config_and_finalization_deadline_boundaries(self) -> None:
        for kw, val in (
            ("job_timeout_seconds", float("nan")),
            ("job_timeout_seconds", float("inf")),
            ("job_timeout_seconds", float("-inf")),
            ("job_timeout_seconds", True),
            ("ollama_timeout_seconds", float("nan")),
            ("ollama_timeout_seconds", float("inf")),
            ("opengrep_timeout_seconds", True),
            ("git_clone_timeout_seconds", 0),
        ):
            with self.assertRaises(ValueError, msg=f"Invalid {kw}={val!r} must raise ValueError"):
                ApiConfig(data_dir=self.root / f"cfg_bad_{kw}", rules_path=self.rules, runtime_origin="mock", **{kw: val})

        sqli_java = (
            "package demo;\nimport java.sql.*;\nimport javax.servlet.http.HttpServletRequest;\n"
            "public class FinTo {\n    public void run(HttpServletRequest req, Statement st) throws Exception {\n"
            '        String u = req.getParameter("u");\n        st.executeQuery("SELECT * FROM a WHERE u=\'" + u + "\'");\n'
            "    }\n}\n"
        )
        fake_og = _create_fake_opengrep_from_fixtures(self.root, subdir="og_blocker_f")
        from v2.api import jobs as jobs_mod
        real_atomic = jobs_mod._atomic_write_text
        real_monotonic = time.monotonic

        for no_llm_flag in (True, False):
            for expire_phase in ("after_staged_meta", "before_job_commit_replace"):
                clock = {"now": 100.0}
                mid_write_scans: list[int] = []
                mid_write_job_states: list[str] = []
                with patch("v2.api.jobs.time.monotonic", side_effect=lambda: clock["now"]), patch(
                    "v2.api.qwen_triage.time.monotonic", side_effect=lambda: clock["now"]
                ):
                    data_dir = self.root / f"data_f_{no_llm_flag}_{expire_phase}"
                    cfg = ApiConfig(
                        host="127.0.0.1",
                        port=0,
                        data_dir=data_dir,
                        api_token="f-token-123456",
                        opengrep_binary=fake_og,
                        rules_path=self.rules,
                        job_timeout_seconds=10.0,
                        ollama_timeout_seconds=5.0,
                        runtime_origin="mock",
                    )

                    def _ok_ollama(req_doc, _n):
                        ev_u = json.loads(req_doc["messages"][1]["content"])
                        sn = ev_u["snippets"][0]
                        ln = ev_u["start"]["line"]
                        txt = next(x["text"] for x in sn["lines"] if x["line"] == ln)
                        return {
                            "status": "SUPPORTED",
                            "explanation": "SQLi",
                            "fix_suggestion": "PreparedStatement",
                            "citations": [{"path": sn["path"], "start_line": ln, "end_line": ln, "quote": txt, "sha256": sn["sha256"]}],
                        }

                    with _ScriptedOllamaServer(_ok_ollama) as ol:
                        cfg_run = ApiConfig(
                            host="127.0.0.1",
                            port=0,
                            data_dir=data_dir,
                            api_token="f-token-123456",
                            opengrep_binary=fake_og,
                            rules_path=self.rules,
                            ollama_endpoint=ol.endpoint,
                            job_timeout_seconds=10.0,
                            ollama_timeout_seconds=5.0,
                            runtime_origin="unverified",
                        ) if not no_llm_flag else cfg
                        svc_probe = TriageApiService(cfg_run)
                        mgr = ScanJobManager(cfg_run)

                        def _hooked_atomic(target: Path, text: str, *, before_replace=None, _ep=expire_phase, _svc=svc_probe):
                            if _ep == "after_staged_meta" and target.name == "api-scan-meta.json" and '"commit_authority"' in text:
                                real_atomic(target, text, before_replace=before_replace)
                                # Inspect scan discovery RIGHT BETWEEN staged metadata write and job commit!
                                mid_write_scans.append(_svc.list_scans(include_mock=True)["total_count"])
                                clock["now"] = 500.0
                                return
                            if _ep == "before_job_commit_replace" and target.parent.name == "jobs" and target.suffix == ".json" and '"COMPLETED"' in text:
                                mid_write_scans.append(_svc.list_scans(include_mock=True)["total_count"])
                                clock["now"] = 500.0
                                real_atomic(target, text, before_replace=before_replace)
                                return
                            real_atomic(target, text, before_replace=before_replace)

                        try:
                            with patch("v2.api.jobs._atomic_write_text", side_effect=_hooked_atomic):
                                sub = mgr.submit_zip_job("fin.zip", _make_java_zip({"FinTo.java": sqli_java}), no_llm=no_llm_flag)
                                dl = real_monotonic() + 20.0
                                while real_monotonic() < dl:
                                    cur = mgr.get_job(sub["job_id"])
                                    if cur["state"] in ("COMPLETED", "FAILED"):
                                        break
                                    time.sleep(0.02)
                            cur = mgr.get_job(sub["job_id"])
                            self.assertEqual(cur["state"], "FAILED", f"no_llm={no_llm_flag} phase={expire_phase}: {cur}")
                            self.assertEqual(cur["error_code"], "JOB_TIMEOUT")
                            self.assertIsNone(cur["scan_id"])
                            self.assertTrue(mid_write_scans, f"Hook did not fire for {expire_phase}")
                            self.assertEqual(mid_write_scans, [0], f"Ghost publication observed mid-finalization: {mid_write_scans}")
                            open_stages = [(s["stage_key"], s["state"]) for s in cur["stages"] if s["state"] in ("PENDING", "RUNNING")]
                            self.assertEqual(open_stages, [], f"Zero stages may stay PENDING/RUNNING after fail: {cur['stages']}")
                            meta_on_disk = json.loads((data_dir / "scans" / cur["job_id"] / "api-scan-meta.json").read_text(encoding="utf-8"))
                            self.assertFalse(meta_on_disk.get("publishable"))
                            self.assertEqual(meta_on_disk.get("job_state"), "FAILED")
                            self.assertEqual(svc_probe.list_scans(include_mock=True)["total_count"], 0)
                        finally:
                            mgr.shutdown(wait=True)

    # ------------------------------------------------------------------
    # Blocker G Adversarial (Windows): junctions, missing job_id with active job,
    # FINALIZING state, and endpoint-wide 404 consistency
    # ------------------------------------------------------------------
    def test_blocker_g_junctions_and_missing_job_id_never_leak(self) -> None:
        data_dir = self.root / "data_blk_g"
        scans_dir = data_dir / "scans"
        jobs_dir = data_dir / "jobs"
        ext_dir = self.root / "ext_blk_g"
        alias_dir = self.root / "alias_blk_g"
        scans_dir.mkdir(parents=True)
        jobs_dir.mkdir(parents=True)
        ext_dir.mkdir(parents=True)
        alias_dir.mkdir(parents=True)

        def _make_scan_tree(dest: Path, meta: dict | None) -> str:
            (dest / "capture").mkdir(parents=True, exist_ok=True)
            (dest / "triage").mkdir(parents=True, exist_ok=True)
            og = json.dumps({"version": "1.25.0", "results": [], "errors": []}).encode("utf-8")
            sha = digest(og)
            (dest / "capture" / "opengrep.json").write_bytes(og)
            (dest / "capture" / "scan-manifest.json").write_text(json.dumps({"success": True}), encoding="utf-8")
            ev = {
                "schema_version": "ntk-evidence-1",
                "scan_sha256": sha,
                "collected_at": "2026-11-22T01:00:00+00:00",
                "prompt_contract": "blind",
                "records": [],
            }
            (dest / "triage" / "evidence.json").write_text(json.dumps(ev), encoding="utf-8")
            (dest / "triage" / "assessments.jsonl").write_text("", encoding="utf-8")
            rs = ReviewStore(dest / "triage" / "review.sqlite")
            try:
                rs.add(ev, [])
            finally:
                rs.close()
            if meta is not None:
                m_doc = {**meta}
                if m_doc.get("scan_sha256") == "<SHA>":
                    m_doc["scan_sha256"] = sha
                (dest / "api-scan-meta.json").write_text(json.dumps(m_doc), encoding="utf-8")
            return sha

        # Case 1: scans/job-g-1 -> ext_blk_g/renamed_dir with forged publishable=True WITHOUT job_id while RUNNING!
        ext_target = ext_dir / "renamed_dir"
        sha1 = _make_scan_tree(ext_target, {"scan_id": "leak-junc-1", "scan_sha256": "<SHA>", "publishable": True})
        (jobs_dir / "job-g-1.json").write_text(json.dumps({"job_id": "job-g-1", "state": "RUNNING", "scan_id": "leak-junc-1"}), encoding="utf-8")

        # Case 2: scans/job-g-2 in-progress (no api-scan-meta.json) aliased via alias_blk_g/other_name -> scans/job-g-2
        real_inprog = scans_dir / "job-g-2"
        sha2 = _make_scan_tree(real_inprog, None)
        (jobs_dir / "job-g-2.json").write_text(json.dumps({"job_id": "job-g-2", "state": "RUNNING"}), encoding="utf-8")

        # Case 3: FINALIZING metadata in scans/job-g-3 -> MUST stay hidden across every route
        fin_dir = scans_dir / "job-g-3"
        sha3 = _make_scan_tree(fin_dir, {
            "scan_id": "leak-fin-3",
            "scan_sha256": "<SHA>",
            "job_id": "job-g-3",
            "job_state": "FINALIZING",
            "publishable": False,
        })
        (jobs_dir / "job-g-3.json").write_text(json.dumps({"job_id": "job-g-3", "state": "COMPLETED"}), encoding="utf-8")

        created_junctions: list[Path] = []
        try:
            if os.name == "nt":
                j1 = scans_dir / "job-g-1"
                j2 = alias_dir / "other_alias"
                subprocess.run(["cmd", "/c", "mklink", "/J", str(j1), str(ext_target)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                created_junctions.append(j1)
                subprocess.run(["cmd", "/c", "mklink", "/J", str(j2), str(real_inprog)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                created_junctions.append(j2)
            else:
                j1 = scans_dir / "job-g-1"
                j2 = alias_dir / "other_alias"
                j1.symlink_to(ext_target, target_is_directory=True)
                created_junctions.append(j1)
                j2.symlink_to(real_inprog, target_is_directory=True)
                created_junctions.append(j2)

            svc = TriageApiService(
                ApiConfig(
                    data_dir=data_dir,
                    reviewable_scan_dirs=(ext_dir, alias_dir, scans_dir),
                    readonly_scan_dirs=(ext_dir,),
                    rules_path=self.rules,
                    runtime_origin="mock",
                )
            )
            self.assertEqual(svc.list_scans()["total_count"], 0, svc.list_scans())
            for leaked_id in ("leak-junc-1", "leak-fin-3", sha1, sha2, sha3, "job-g-1", "job-g-2", "job-g-3"):
                with self.assertRaises(ApiServiceError) as ctx:
                    svc.resolve_scan(leaked_id)
                self.assertEqual(ctx.exception.http_status, 404)
                for fn in (
                    lambda sid=leaked_id: svc.build_scan_summary(svc.resolve_scan(sid)),
                    lambda sid=leaked_id: svc.list_findings(sid),
                    lambda sid=leaked_id: svc.get_review_queue(sid),
                    lambda sid=leaked_id: svc.get_scan_review_history(sid),
                    lambda sid=leaked_id: svc.export_scan_report(sid),
                    lambda sid=leaked_id: svc.decide_finding(sid, "f0", "confirm-true", actor="r", reason="x"),
                ):
                    with self.assertRaises(ApiServiceError) as rctx:
                        fn()
                    self.assertEqual(rctx.exception.http_status, 404)
        finally:
            for jp in created_junctions:
                if jp.exists():
                    jp.rmdir()

    # ------------------------------------------------------------------
    # Codex Re-Audit Root-Cause Counterexamples (C / D / F / G)
    # ------------------------------------------------------------------
    def test_root_cause_c_parser_unknown_stmts_and_canonical_boundary_strictness(self) -> None:
        def _gate_case(fname: str, code: str, cwe: str, header_ln: int, sink_ln: int, cite_ln: int) -> dict:
            lines = code.splitlines()
            sha = digest(code.encode("utf-8"))
            rec = {
                "id": "c" * 64,
                "cwe": [cwe],
                "start": {"line": sink_ln, "col": 1},
                "end": {"line": sink_ln, "col": len(lines[sink_ln - 1])},
                "issues": [],
                "snapshots": {fname: {"sha256": sha, "size": len(code.encode("utf-8"))}},
                "snippets": [{
                    "role": "finding",
                    "path": fname,
                    "sha256": sha,
                    "start": {"line": sink_ln, "col": 1},
                    "end": {"line": sink_ln, "col": len(lines[sink_ln - 1])},
                    "lines": [{"line": i + 1, "text": t} for i, t in enumerate(lines)],
                }],
                "java_context": {
                    "enclosing_class": fname[:-5],
                    "enclosing_method": {"name": "run", "header_line": header_ln, "start_line": header_ln, "end_line": len(lines) - 1},
                },
                "heuristic_signals": {"recommended_status": "REFUTED", "sink_line": sink_ln, "unresolved_calls": [], "sanitizers_found": []},
            }
            ass = {
                "status": "REFUTED",
                "validated_status": "REFUTED",
                "raw_response": {"model": "qwen3.5:9b-q4_K_M", "done": True},
                "citations": [{"path": fname, "start_line": cite_ln, "end_line": cite_ln, "quote": lines[cite_ln - 1], "sha256": sha}],
                "runtime": {"origin": "unit-test", "http_response_received": True, "http_status": 200, "response_complete": True, "model_identity_matched": True},
            }
            return apply_integration_gate(rec, ass)

        unsafe_cases = [
            # 1. Braceless if reassignment & nested/else-if braceless chains
            ("BracelessIf.java", "CWE-89", 5, 10, 7, (
                "package demo;\nimport java.sql.*;\nimport javax.servlet.http.HttpServletRequest;\npublic class BracelessIf {\n"
                "    public void run(HttpServletRequest req, Statement st, boolean flag) throws Exception {\n"
                '        String u = req.getParameter("u");\n        String q = "SELECT 1";\n'
                '        if (flag)\n            q = "SELECT * FROM t WHERE u=\'" + u + "\'";\n'
                "        st.executeQuery(q);\n    }\n}\n"
            )),
            # 2. Single-line if/else where `then` modifies another var and `else` taints `q`
            ("OneLineIfElse.java", "CWE-89", 5, 10, 7, (
                "package demo;\nimport java.sql.*;\nimport javax.servlet.http.HttpServletRequest;\npublic class OneLineIfElse {\n"
                "    public void run(HttpServletRequest req, Statement st, boolean flag) throws Exception {\n"
                '        String u = req.getParameter("u");\n        String q = "SELECT 1";\n        int x = 0;\n'
                '        if (flag) x = 1; else q = "SELECT * FROM t WHERE u=\'" + u + "\'";\n'
                "        st.executeQuery(q);\n    }\n}\n"
            )),
            # 3. Braceless for / while / do loops
            ("BracelessFor.java", "CWE-89", 5, 10, 7, (
                "package demo;\nimport java.sql.*;\nimport javax.servlet.http.HttpServletRequest;\npublic class BracelessFor {\n"
                "    public void run(HttpServletRequest req, Statement st) throws Exception {\n"
                '        String u = req.getParameter("u");\n        String q = "SELECT 1";\n'
                '        for (int i = 0; i < 1; i++)\n            q = "SELECT * FROM t WHERE u=\'" + u + "\'";\n'
                "        st.executeQuery(q);\n    }\n}\n"
            )),
            ("BracelessWhile.java", "CWE-89", 5, 10, 7, (
                "package demo;\nimport java.sql.*;\nimport javax.servlet.http.HttpServletRequest;\npublic class BracelessWhile {\n"
                "    public void run(HttpServletRequest req, Statement st, boolean flag) throws Exception {\n"
                '        String u = req.getParameter("u");\n        String q = "SELECT 1";\n'
                '        while (flag)\n            q = "SELECT * FROM t WHERE u=\'" + u + "\'";\n'
                "        st.executeQuery(q);\n    }\n}\n"
            )),
            # 4. Unknown statements, same-line multi-statements, condition side-effects, undeclared class field, same-line sink mutation
            ("MultiStmt.java", "CWE-89", 5, 9, 7, (
                "package demo;\nimport java.sql.*;\nimport javax.servlet.http.HttpServletRequest;\npublic class MultiStmt {\n"
                "    public void run(HttpServletRequest req, Statement st) throws Exception {\n"
                '        String u = req.getParameter("u");\n        String q = "SELECT 1";\n'
                '        int x = 1; q = "SELECT * FROM t WHERE u=\'" + u + "\'";\n'
                "        st.executeQuery(q);\n    }\n}\n"
            )),
            ("SameLineSinkMut.java", "CWE-89", 5, 8, 7, (
                "package demo;\nimport java.sql.*;\nimport javax.servlet.http.HttpServletRequest;\npublic class SameLineSinkMut {\n"
                "    public void run(HttpServletRequest req, Statement st) throws Exception {\n"
                '        String u = req.getParameter("u");\n        String q = "SELECT 1";\n'
                '        q = "SELECT * FROM t WHERE u=\'" + u + "\'"; st.executeQuery(q);\n'
                "    }\n}\n"
            )),
            ("SameLineIfMutBeforeSink.java", "CWE-89", 5, 8, 7, (
                "package demo;\nimport java.sql.*;\nimport javax.servlet.http.HttpServletRequest;\npublic class SameLineIfMutBeforeSink {\n"
                "    public void run(HttpServletRequest req, Statement st, boolean flag) throws Exception {\n"
                '        String u = req.getParameter("u");\n        String q = "SELECT 1";\n'
                '        if (flag) q = "SELECT * FROM t WHERE u=\'" + u + "\'"; st.executeQuery(q);\n'
                "    }\n}\n"
            )),
            ("SameLineTrailingAssignAfterSink.java", "CWE-89", 5, 8, 7, (
                "package demo;\nimport java.sql.*;\nimport javax.servlet.http.HttpServletRequest;\npublic class SameLineTrailingAssignAfterSink {\n"
                "    public void run(HttpServletRequest req, Statement st) throws Exception {\n"
                '        String u = req.getParameter("u");\n        String q = "SELECT 1";\n'
                '        st.executeQuery("SELECT * FROM t WHERE u=\'" + u + "\'"); int x = 1;\n'
                "    }\n}\n"
            )),
            ("SameLineIfElseAtSink.java", "CWE-89", 5, 9, 7, (
                "package demo;\nimport java.sql.*;\nimport javax.servlet.http.HttpServletRequest;\npublic class SameLineIfElseAtSink {\n"
                "    public void run(HttpServletRequest req, Statement st, boolean flag) throws Exception {\n"
                '        String u = req.getParameter("u");\n        String q = "SELECT 1";\n        int x = 0;\n'
                '        if (flag) st.executeQuery("SELECT * FROM t WHERE u=\'" + u + "\'"); else x = 1;\n'
                "    }\n}\n"
            )),
            ("CondSideEff.java", "CWE-89", 5, 9, 7, (
                "package demo;\nimport java.sql.*;\nimport javax.servlet.http.HttpServletRequest;\npublic class CondSideEff {\n"
                "    public void run(HttpServletRequest req, Statement st) throws Exception {\n"
                '        String u = req.getParameter("u");\n        String q = "SELECT 1";\n'
                "        if ((q = u) != null) {}\n        st.executeQuery(q);\n    }\n}\n"
            )),
            ("FieldAssignRace.java", "CWE-89", 6, 9, 7, (
                "package demo;\nimport java.sql.*;\nimport javax.servlet.http.HttpServletRequest;\npublic class FieldAssignRace {\n"
                "    private String q;\n"
                "    public void run(HttpServletRequest req, Statement st) throws Exception {\n"
                '        q = "SELECT 1";\n        int x = 1;\n        st.executeQuery(q);\n    }\n}\n'
            )),
            ("UnknownMethodStmt.java", "CWE-89", 5, 9, 7, (
                "package demo;\nimport java.sql.*;\nimport javax.servlet.http.HttpServletRequest;\npublic class UnknownMethodStmt {\n"
                "    public void run(HttpServletRequest req, Statement st) throws Exception {\n"
                '        String u = req.getParameter("u");\n        String q = "SELECT 1";\n'
                "        this.q = u;\n        st.executeQuery(q);\n    }\n}\n"
            )),
            ("ForHeaderCall.java", "CWE-89", 5, 9, 7, (
                "package demo;\nimport java.sql.*;\nimport javax.servlet.http.HttpServletRequest;\npublic class ForHeaderCall {\n"
                "    public void run(HttpServletRequest req, Statement st) throws Exception {\n"
                '        String u = req.getParameter("u");\n        String q = "SELECT 1";\n'
                "        for (int i = 0; mutate(u); i++) ;\n        st.executeQuery(q);\n    }\n}\n"
            )),
            # 5. Canonical guard weak prefix boundaries (`baseCanon + "/sub"`, `"/"`, uncanonicalized `"/srv/safe/"`, `baseCanon + File.separator + "sub"`)
            ("PrefixNoTrailSlash.java", "CWE-22", 6, 15, 12, (
                "package demo;\nimport java.io.*;\nimport java.nio.file.*;\nimport javax.servlet.http.HttpServletRequest;\n"
                "public class PrefixNoTrailSlash {\n    public String run(HttpServletRequest req) throws Exception {\n"
                '        String raw = req.getParameter("p");\n        File base = new File("/srv/safe");\n'
                "        String baseCanon = base.getCanonicalPath();\n        File target = new File(base, raw);\n"
                "        String targetCanon = target.getCanonicalPath();\n"
                '        if (!targetCanon.startsWith(baseCanon + "/sub")) {\n            throw new SecurityException("bad");\n        }\n'
                "        return Files.readString(Paths.get(targetCanon));\n    }\n}\n"
            )),
            ("PrefixRootOnly.java", "CWE-22", 6, 14, 11, (
                "package demo;\nimport java.io.*;\nimport java.nio.file.*;\nimport javax.servlet.http.HttpServletRequest;\n"
                "public class PrefixRootOnly {\n    public String run(HttpServletRequest req) throws Exception {\n"
                '        String raw = req.getParameter("p");\n        File base = new File("/srv/safe");\n'
                "        File target = new File(base, raw);\n        String targetCanon = target.getCanonicalPath();\n"
                '        if (!targetCanon.startsWith("/")) {\n            throw new SecurityException("bad");\n        }\n'
                "        return Files.readString(Paths.get(targetCanon));\n    }\n}\n"
            )),
            ("PrefixLiteralOnly.java", "CWE-22", 6, 14, 11, (
                "package demo;\nimport java.io.*;\nimport java.nio.file.*;\nimport javax.servlet.http.HttpServletRequest;\n"
                "public class PrefixLiteralOnly {\n    public String run(HttpServletRequest req) throws Exception {\n"
                '        String raw = req.getParameter("p");\n        File base = new File("/srv/safe");\n'
                "        File target = new File(base, raw);\n        String targetCanon = target.getCanonicalPath();\n"
                '        if (!targetCanon.startsWith("/srv/safe/")) {\n            throw new SecurityException("bad");\n        }\n'
                "        return Files.readString(Paths.get(targetCanon));\n    }\n}\n"
            )),
            # 6. Sink uses raw path or re-resolves canonical path (TOCTOU) instead of checked value
            ("RawSinkAfterCanon.java", "CWE-22", 5, 14, 11, (
                "package demo;\nimport java.io.*;\nimport javax.servlet.http.HttpServletRequest;\n"
                "public class RawSinkAfterCanon {\n    public FileInputStream run(HttpServletRequest req) throws Exception {\n"
                '        String raw = req.getParameter("p");\n        File base = new File("/srv/safe");\n'
                "        String baseCanon = base.getCanonicalPath();\n        File target = new File(base, raw);\n"
                "        String targetCanon = target.getCanonicalPath();\n"
                "        if (!targetCanon.startsWith(baseCanon + File.separator)) {\n            throw new SecurityException(\"bad\");\n        }\n"
                "        return new FileInputStream(target);\n    }\n}\n"
            )),
            ("LexicalNormalizeGuard.java", "CWE-22", 5, 12, 9, (
                "package demo;\nimport java.nio.file.*;\nimport javax.servlet.http.HttpServletRequest;\n"
                "public class LexicalNormalizeGuard {\n    public String run(HttpServletRequest req) throws Exception {\n"
                '        String raw = req.getParameter("p");\n        Path base = Paths.get("/srv/safe").toAbsolutePath().normalize();\n'
                "        Path target = base.resolve(raw).toAbsolutePath().normalize();\n"
                '        if (!target.startsWith(base)) {\n            throw new SecurityException("bad");\n        }\n'
                "        return Files.readString(target);\n    }\n}\n"
            )),
        ]
        for fname, cwe, hl, sl, cl, code in unsafe_cases:
            with self.subTest(unsafe_case=fname):
                out = _gate_case(fname, code, cwe, hl, sl, cl)
                self.assertEqual(out["validated_status"], "UNDETERMINED", f"{fname} must fail closed: {out}")
                self.assertEqual(out["raw_model_status"], "REFUTED")
                self.assertTrue(out["validator_downgraded"])
                self.assertTrue(out.get("raw_response"))
                self.assertTrue(out.get("citations"))
                self.assertTrue(out.get("downgrade_reason"))
                self.assertTrue(out.get("requires_human_review"))

        # Valid safe controls MUST still pass REFUTED (proving we did NOT disable REFUTED globally!)
        safe_controls = [
            ("SafeConst.java", "CWE-89", 5, 8, 7, "UNCONDITIONAL_CONSTANT_SINK_FLOW", (
                "package demo;\nimport java.sql.*;\nimport javax.servlet.http.HttpServletRequest;\npublic class SafeConst {\n"
                "    public void run(HttpServletRequest req, Statement st) throws Exception {\n"
                '        String ignored = req.getParameter("u");\n        String q = "SELECT id FROM users";\n'
                "        st.executeQuery(q);\n    }\n}\n"
            )),
            ("SafeRealPath.java", "CWE-22", 5, 12, 9, "CWE22_CANONICAL_CONTAINMENT_GUARD", (
                "package demo;\nimport java.nio.file.*;\nimport javax.servlet.http.HttpServletRequest;\npublic class SafeRealPath {\n"
                "    public String run(HttpServletRequest req) throws Exception {\n"
                '        String raw = req.getParameter("p");\n        Path baseReal = Paths.get("/srv/safe").toRealPath();\n'
                "        Path targetReal = baseReal.resolve(raw).toRealPath();\n"
                '        if (!targetReal.startsWith(baseReal)) {\n            throw new SecurityException("bad");\n        }\n'
                "        return Files.readString(targetReal);\n    }\n}\n"
            )),
            ("SafePrepared.java", "CWE-89", 5, 9, 7, "CWE89_CONSTANT_PREPARED_STATEMENT", (
                "package demo;\nimport java.sql.*;\nimport javax.servlet.http.HttpServletRequest;\npublic class SafePrepared {\n"
                "    public void run(HttpServletRequest req, Connection conn) throws Exception {\n"
                '        String u = req.getParameter("u");\n'
                '        PreparedStatement ps = conn.prepareStatement("SELECT id FROM users WHERE u = ?");\n'
                "        ps.setString(1, u);\n        ps.executeQuery();\n    }\n}\n"
            )),
        ]
        for fname, cwe, hl, sl, cl, exp_proof, code in safe_controls:
            with self.subTest(safe_control=fname):
                out = _gate_case(fname, code, cwe, hl, sl, cl)
                self.assertEqual(out["validated_status"], "REFUTED", f"{fname} control failed: {out}")
                self.assertEqual(out.get("independent_refutation_proof"), exp_proof)

    def test_root_cause_d_package_preserving_receiver_and_shadowing_and_inheritance(self) -> None:
        app_tools = 'package app;\npublic class Tools {\n    public String adjust(String s) { return "safe"; }\n}\n'
        p_tools = "package p;\npublic class Tools {\n    public String adjust(String s) { return s; }\n}\n"
        p_tools_sub = "package p;\npublic class Tools extends BaseTools {\n    public String adjust(String s) { return s; }\n}\n"

        def _eval(cname: str, ccode: str, helpers: list[tuple[str, str]], call_ln: int, sink_ln: int, qual: str | None, meth: str, *, include_unresolved: bool = True, params: list[str] | None = None) -> tuple[bool, str]:
            csha = digest(ccode.encode("utf-8"))
            snips = [{"role": "finding", "path": cname, "sha256": csha, "lines": [{"line": i + 1, "text": l} for i, l in enumerate(ccode.splitlines())]}]
            snaps = {cname: {"sha256": csha}}
            for hp, hc in helpers:
                hs = digest(hc.encode("utf-8"))
                snips.append({"role": "helper", "path": hp, "sha256": hs, "lines": [{"line": i + 1, "text": l} for i, l in enumerate(hc.splitlines())]})
                snaps[hp] = {"sha256": hs}
            hl = next(i + 1 for i, l in enumerate(ccode.splitlines()) if "public String go(" in l)
            rec = {
                "cwe": ["CWE-22"],
                "start": {"line": sink_ln, "col": 1},
                "end": {"line": sink_ln, "col": 40},
                "snippets": snips,
                "snapshots": snaps,
                "java_context": {"enclosing_class": cname[:-5], "enclosing_method": {"name": "go", "header_line": hl, "end_line": sink_ln + 1, "parameters": params or ["HttpServletRequest req"]}},
                "heuristic_signals": {"sink_line": sink_ln, "unresolved_calls": [{"qualifier": qual, "method": meth, "line": call_ln}] if include_unresolved else []},
            }
            dep = analyze_flow_dependencies(rec)
            gated = apply_integration_gate(rec, {
                "status": "SUPPORTED", "explanation": "TP", "fix_suggestion": "Fix",
                "citations": [{"path": cname, "start_line": sink_ln, "end_line": sink_ln, "quote": ccode.splitlines()[sink_ln - 1], "sha256": csha}],
                "runtime": {"origin": "unit-test", "http_response_received": True, "http_status": 200, "response_complete": True, "model_identity_matched": True},
            })
            return bool(dep["has_unverified_helper_dependency"]), str(gated.get("validated_status") or gated.get("status"))

        fqn_caller = (
            "package demo;\nimport app.Tools;\nimport java.nio.file.*;\nimport javax.servlet.http.HttpServletRequest;\n"
            "public class CallerFqn {\n    public String go(HttpServletRequest req) throws Exception {\n"
            '        String x = req.getParameter("x");\n        p.Tools t = new p.Tools();\n'
            '        String y = t.adjust(x);\n        return Files.readString(Path.of("/srv", y));\n    }\n}\n'
        )
        # 1. `p.Tools t = new p.Tools()` with only `app/Tools.java` (despite `import app.Tools;`) -> MUST reject!
        self.assertEqual(_eval("CallerFqn.java", fqn_caller, [("app/Tools.java", app_tools)], 9, 10, "t", "adjust"), (True, "UNDETERMINED"))
        # 2. `p.Tools t = new p.Tools()` with `p/Tools.java` ONLY (despite `import app.Tools;`) -> MUST resolve `p.Tools`!
        self.assertEqual(_eval("CallerFqn.java", fqn_caller, [("p/Tools.java", p_tools)], 9, 10, "t", "adjust"), (False, "SUPPORTED"))
        # 3. `p.Tools t = new p.Tools()` when BOTH `app/Tools.java` and `p/Tools.java` exist -> MUST select `p.Tools` cleanly!
        self.assertEqual(_eval("CallerFqn.java", fqn_caller, [("app/Tools.java", app_tools), ("p/Tools.java", p_tools)], 9, 10, "t", "adjust"), (False, "SUPPORTED"))
        # 4. `Tools t = new p.Tools()` with `import app.Tools;` -> mismatched decl vs ctor package -> MUST reject!
        mixed_caller = fqn_caller.replace("CallerFqn", "CallerMix").replace("p.Tools t = new p.Tools();", "Tools t = new p.Tools();")
        self.assertEqual(_eval("CallerMix.java", mixed_caller, [("app/Tools.java", app_tools), ("p/Tools.java", p_tools)], 9, 10, "t", "adjust"), (True, "UNDETERMINED"))
        # 5. Custom class `com.evil.String` shadowing `java.lang.String` -> MUST NOT bypass via stdlib!
        evil_str_caller = (
            "package demo;\nimport java.nio.file.*;\nimport javax.servlet.http.HttpServletRequest;\n"
            "public class CallerShadow {\n    public String go(HttpServletRequest req) throws Exception {\n"
            '        String x = req.getParameter("x");\n        com.evil.String s = new com.evil.String(x);\n'
            '        String y = s.trim();\n        return Files.readString(Path.of("/srv", y));\n    }\n}\n'
        )
        self.assertEqual(_eval("CallerShadow.java", evil_str_caller, [], 8, 9, "s", "trim", include_unresolved=False), (True, "UNDETERMINED"))
        # 6. `var` local receiver calling a stdlib-named method (`t.resolve(x)`) -> MUST NOT bypass via stdlib!
        var_caller = (
            "package demo;\nimport java.nio.file.*;\nimport javax.servlet.http.HttpServletRequest;\n"
            "public class CallerVar {\n    public String go(HttpServletRequest req) throws Exception {\n"
            '        String x = req.getParameter("x");\n        var t = new p.Tools();\n'
            '        String y = t.resolve(x);\n        return Files.readString(Path.of("/srv", y));\n    }\n}\n'
        )
        self.assertEqual(_eval("CallerVar.java", var_caller, [], 8, 9, "t", "resolve", include_unresolved=False), (True, "UNDETERMINED"))
        # 7. Inline reassignment `if (flag) t = other;` -> MUST reject!
        inline_reasgn = (
            "package demo;\nimport app.Tools;\nimport java.nio.file.*;\nimport javax.servlet.http.HttpServletRequest;\n"
            "public class CallerInlineReasgn {\n    public String go(HttpServletRequest req, Tools other, boolean flag) throws Exception {\n"
            '        String x = req.getParameter("x");\n        Tools t = new Tools();\n        if (flag) t = other;\n'
            '        String y = t.adjust(x);\n        return Files.readString(Path.of("/srv", y));\n    }\n}\n'
        )
        self.assertEqual(
            _eval("CallerInlineReasgn.java", inline_reasgn, [("app/Tools.java", app_tools)], 10, 11, "t", "adjust", params=["HttpServletRequest req", "Tools other", "boolean flag"]),
            (True, "UNDETERMINED"),
        )
        # 8. Helper with unresolved superclass inheritance (`extends BaseTools`) -> MUST stay unresolved!
        self.assertEqual(_eval("CallerFqn.java", fqn_caller, [("p/Tools.java", p_tools_sub)], 9, 10, "t", "adjust"), (True, "UNDETERMINED"))
        # 9. Valid `new p.Tools().adjust(x)` with `p/Tools.java` -> SUPPORTED; with only `app/Tools.java` -> UNDETERMINED!
        new_chain = fqn_caller.replace("CallerFqn", "CallerNewChain").replace("        p.Tools t = new p.Tools();\n        String y = t.adjust(x);", "        String y = new p.Tools().adjust(x);")
        self.assertEqual(_eval("CallerNewChain.java", new_chain, [("app/Tools.java", app_tools)], 8, 9, "p.Tools", "adjust", include_unresolved=False), (True, "UNDETERMINED"))
        self.assertEqual(_eval("CallerNewChain.java", new_chain, [("p/Tools.java", p_tools)], 8, 9, "p.Tools", "adjust", include_unresolved=False), (False, "SUPPORTED"))

    def test_root_cause_f_single_commit_crash_recovery_errors_and_concurrency(self) -> None:
        sqli_java = (
            "package demo;\nimport java.sql.*;\nimport javax.servlet.http.HttpServletRequest;\n"
            "public class SingleCommitF {\n    public void run(HttpServletRequest req, Statement st) throws Exception {\n"
            '        String u = req.getParameter("u");\n        st.executeQuery("SELECT * FROM a WHERE u=\'" + u + "\'");\n'
            "    }\n}\n"
        )
        fake_og = _create_fake_opengrep_from_fixtures(self.root, subdir="og_root_f")
        from v2.api import jobs as jobs_mod
        real_atomic = jobs_mod._atomic_write_text

        # 1. Normal completion + concurrent readers polling job status & scan discovery simultaneously
        data_ok = self.root / "data_rf_ok"
        cfg_ok = ApiConfig(
            host="127.0.0.1", port=0, data_dir=data_ok, api_token="rf-ok-token-1234",
            opengrep_binary=fake_og, rules_path=self.rules, runtime_origin="mock",
        )
        svc_ok = TriageApiService(cfg_ok)
        mgr_ok = ScanJobManager(cfg_ok)
        inconsistencies: list[str] = []
        stop_ev = threading.Event()
        try:
            sub = mgr_ok.submit_zip_job("ok.zip", _make_java_zip({"SingleCommitF.java": sqli_java}), no_llm=True)
            jid = sub["job_id"]

            def _poll_concurrent():
                while not stop_ev.is_set():
                    jdoc = mgr_ok.get_job(jid)
                    scans = svc_ok.list_scans(include_mock=True)["scans"]
                    if jdoc["state"] == "COMPLETED":
                        # Once job API reports COMPLETED, scan discovery MUST immediately see the scan!
                        if not any(sc["scan_id"] == jdoc["scan_id"] for sc in scans):
                            inconsistencies.append(f"job COMPLETED ({jdoc['scan_id']}) but scan missing from list_scans")
                    elif jdoc["state"] == "FAILED":
                        if scans:
                            inconsistencies.append(f"job FAILED but scans visible: {scans}")

            threads = [threading.Thread(target=_poll_concurrent, daemon=True) for _ in range(2)]
            for th in threads:
                th.start()
            dl = time.monotonic() + 20.0
            while time.monotonic() < dl:
                cur = mgr_ok.get_job(jid)
                if cur["state"] in ("COMPLETED", "FAILED"):
                    break
                time.sleep(0.02)
            stop_ev.set()
            for th in threads:
                th.join(timeout=3.0)
            cur = mgr_ok.get_job(jid)
            self.assertEqual(cur["state"], "COMPLETED", cur)
            self.assertEqual(inconsistencies, [])
            self.assertEqual(svc_ok.list_scans(include_mock=True)["total_count"], 1)
            # 2. Crash AFTER commit -> new ScanJobManager instance recovers COMPLETED deterministically!
            mgr_after_commit = ScanJobManager(cfg_ok)
            try:
                rec_job = mgr_after_commit.get_job(jid)
                self.assertEqual(rec_job["state"], "COMPLETED")
                self.assertEqual(rec_job["scan_id"], cur["scan_id"])
                self.assertEqual(svc_ok.list_scans(include_mock=True)["total_count"], 1)
            finally:
                mgr_after_commit.shutdown(wait=True)
        finally:
            mgr_ok.shutdown(wait=True)

        # 3. Crash BEFORE commit (staged api-scan-meta.json present, jobs/<id>.json still RUNNING) -> hidden & restarts FAILED!
        data_pre = self.root / "data_rf_pre"
        shutil.copytree(data_ok, data_pre)
        jfile_pre = next((data_pre / "jobs").glob("*.json"))
        jdoc_pre = json.loads(jfile_pre.read_text(encoding="utf-8"))
        jdoc_pre["state"] = "RUNNING"
        jdoc_pre["scan_id"] = None
        jdoc_pre.pop("commit", None)
        jfile_pre.write_text(json.dumps(jdoc_pre), encoding="utf-8")
        cfg_pre = ApiConfig(data_dir=data_pre, rules_path=self.rules, runtime_origin="mock")
        self.assertEqual(TriageApiService(cfg_pre).list_scans(include_mock=True)["total_count"], 0)
        mgr_pre = ScanJobManager(cfg_pre)
        try:
            rj_pre = mgr_pre.get_job(jdoc_pre["job_id"])
            self.assertEqual(rj_pre["state"], "FAILED")
            self.assertEqual(rj_pre["error_code"], "SERVER_RESTARTED_DURING_JOB")
            self.assertEqual(json.loads(jfile_pre.read_text(encoding="utf-8"))["state"], "FAILED")
            self.assertEqual(TriageApiService(cfg_pre).list_scans(include_mock=True)["total_count"], 0)
        finally:
            mgr_pre.shutdown(wait=True)

        # 4. Restart with legacy FINALIZING metadata + COMPLETED job (no v2 sealed commit) -> reconciled to FAILED & 0 scans!
        data_fin = self.root / "data_rf_fin"
        shutil.copytree(data_ok, data_fin)
        jfile_fin = next((data_fin / "jobs").glob("*.json"))
        jdoc_fin = json.loads(jfile_fin.read_text(encoding="utf-8"))
        jdoc_fin.pop("commit", None)
        jfile_fin.write_text(json.dumps(jdoc_fin), encoding="utf-8")
        mfile_fin = data_fin / "scans" / jdoc_fin["job_id"] / "api-scan-meta.json"
        mdoc_fin = json.loads(mfile_fin.read_text(encoding="utf-8"))
        mdoc_fin.pop("commit_authority", None)
        mdoc_fin.pop("schema", None)
        mdoc_fin.update({"job_state": "FINALIZING", "publishable": False})
        mfile_fin.write_text(json.dumps(mdoc_fin), encoding="utf-8")
        cfg_fin = ApiConfig(data_dir=data_fin, rules_path=self.rules, runtime_origin="mock")
        self.assertEqual(TriageApiService(cfg_fin).list_scans(include_mock=True)["total_count"], 0)
        mgr_fin = ScanJobManager(cfg_fin)
        try:
            rj_fin = mgr_fin.get_job(jdoc_fin["job_id"])
            self.assertEqual(rj_fin["state"], "FAILED")
            self.assertEqual(rj_fin["error_code"], "INCOMPLETE_COMMIT_ON_RESTART")
            self.assertIsNone(rj_fin["scan_id"])
            self.assertEqual(TriageApiService(cfg_fin).list_scans(include_mock=True)["total_count"], 0)
        finally:
            mgr_fin.shutdown(wait=True)

        # 5. Error writing job commit record -> job FAILED (STORAGE_COMMIT_FAILED), evidence kept, 0 scans!
        data_jerr = self.root / "data_rf_jerr"
        cfg_jerr = ApiConfig(
            host="127.0.0.1", port=0, data_dir=data_jerr, api_token="rf-jerr-token-123",
            opengrep_binary=fake_og, rules_path=self.rules, runtime_origin="mock",
        )
        mgr_jerr = ScanJobManager(cfg_jerr)
        try:
            def _fail_commit_write(target: Path, text: str, *, before_replace=None):
                if target.parent.name == "jobs" and target.suffix == ".json" and '"COMPLETED"' in text:
                    raise OSError("simulated job commit write failure")
                return real_atomic(target, text, before_replace=before_replace)

            with patch("v2.api.jobs._atomic_write_text", side_effect=_fail_commit_write):
                sub_e = mgr_jerr.submit_zip_job("jerr.zip", _make_java_zip({"SingleCommitF.java": sqli_java}), no_llm=True)
                dl = time.monotonic() + 20.0
                while time.monotonic() < dl:
                    cur_e = mgr_jerr.get_job(sub_e["job_id"])
                    if cur_e["state"] in ("COMPLETED", "FAILED"):
                        break
                    time.sleep(0.02)
            cur_e = mgr_jerr.get_job(sub_e["job_id"])
            self.assertEqual(cur_e["state"], "FAILED")
            self.assertEqual(cur_e["error_code"], "STORAGE_COMMIT_FAILED")
            self.assertTrue((data_jerr / "scans" / cur_e["job_id"] / "triage" / "review.sqlite").is_file())
            self.assertEqual(TriageApiService(cfg_jerr).list_scans(include_mock=True)["total_count"], 0)
        finally:
            mgr_jerr.shutdown(wait=True)

    def test_root_cause_g_exact_owner_triage_isolation_no_fallback_and_locked_decide(self) -> None:
        data_dir = self.root / "data_rg"
        scans_dir = data_dir / "scans"
        jobs_dir = data_dir / "jobs"
        ext_root = self.root / "ext_rg"
        alias_root = self.root / "alias_rg"
        for d in (scans_dir, jobs_dir, ext_root, alias_root):
            d.mkdir(parents=True)

        src_java = self.root / "GTest.java"
        src_java.write_text("class GTest {}\n", encoding="utf-8")

        def _seed_one_finding(dest: Path, tag: str, meta: dict | None) -> tuple[str, str]:
            (dest / "capture").mkdir(parents=True, exist_ok=True)
            (dest / "triage").mkdir(parents=True, exist_ok=True)
            og = json.dumps({"version": "1.25.0", "results": [{"check_id": f"r-{tag}"}], "errors": [], "tag": tag}).encode("utf-8")
            sha = digest(og)
            wid = digest(f"{sha}:0".encode("utf-8"))
            rec = {
                "id": wid, "alert_id": wid, "finding_index": 0, "scan_sha256": sha,
                "root": str(self.root), "rule_id": f"r-{tag}", "cwe": ["CWE-89"], "severity": "ERROR",
                "path": "GTest.java", "start": {"line": 1, "col": 1}, "end": {"line": 1, "col": 5},
                "snapshots": {"GTest.java": {"sha256": digest(src_java.read_bytes()), "size": len(src_java.read_bytes())}},
                "snippets": [], "raw_finding": {"check_id": f"r-{tag}"}, "issues": [],
                "scan_provenance": {"origin": "recorded_capture_unsigned", "source_capture_verified": True, "exit_capture_verified": True, "recorded_engine_exit": 0},
            }
            ass = {"status": "UNDETERMINED", "validated_status": "UNDETERMINED", "citations": [], "runtime": {"origin": "unverified"}}
            ev = {
                "schema_version": "1.1", "scan_sha256": sha, "collected_at": "2026-11-22T01:00:00+00:00",
                "prompt_contract": "blind", "root": str(self.root), "scan_provenance": rec["scan_provenance"], "records": [rec],
            }
            (dest / "capture" / "opengrep.json").write_bytes(og)
            (dest / "capture" / "scan-manifest.json").write_text(json.dumps({"success": True}), encoding="utf-8")
            (dest / "triage" / "input.opengrep.json").write_bytes(og)
            (dest / "triage" / "evidence.json").write_text(json.dumps(ev), encoding="utf-8")
            (dest / "triage" / "assessments.jsonl").write_text(json.dumps({"id": wid, "scan_sha256": sha, "evidence": rec, "assessment": ass}) + "\n", encoding="utf-8")
            rs = ReviewStore(dest / "triage" / "review.sqlite")
            try:
                rs.add(ev, [ass])
            finally:
                rs.close()
            if meta is not None:
                m = {**meta}
                if m.get("scan_sha256") == "<SHA>":
                    m["scan_sha256"] = sha
                if m.get("scan_id") == "<SHA>":
                    m["scan_id"] = sha
                (dest / "api-scan-meta.json").write_text(json.dumps(m), encoding="utf-8")
            return sha, wid

        # Case 1: Owner job MISSING while another job COMPLETED shares `scan_id`
        s1_sha, _ = _seed_one_finding(scans_dir / "job-owner-missing", "c1", {
            "scan_id": "sid-missing-owner", "scan_sha256": "<SHA>", "job_id": "job-owner-missing",
            "job_state": "COMPLETED", "publishable": True,
        })
        (jobs_dir / "job-other-ok-1.json").write_text(json.dumps({
            "job_id": "job-other-ok-1", "state": "COMPLETED", "scan_id": "sid-missing-owner", "scan_sha256": s1_sha,
        }), encoding="utf-8")

        # Case 2: Owner job FAILED while another job COMPLETED shares `scan_id`
        s2_sha, _ = _seed_one_finding(scans_dir / "job-owner-failed", "c2", {
            "scan_id": "sid-failed-owner", "scan_sha256": "<SHA>", "job_id": "job-owner-failed",
            "job_state": "COMPLETED", "publishable": True,
        })
        (jobs_dir / "job-owner-failed.json").write_text(json.dumps({"job_id": "job-owner-failed", "state": "FAILED"}), encoding="utf-8")
        (jobs_dir / "job-other-ok-2.json").write_text(json.dumps({
            "job_id": "job-other-ok-2", "state": "COMPLETED", "scan_id": "sid-failed-owner", "scan_sha256": s2_sha,
        }), encoding="utf-8")

        # Case 3: Scan meta `job_id` mismatches directory owner & job record `scan_id`
        _seed_one_finding(scans_dir / "job-dir-mismatch", "c3", {
            "scan_id": "sid-mismatch", "scan_sha256": "<SHA>", "job_id": "job-other-ok-3",
            "job_state": "COMPLETED", "publishable": True,
        })
        (jobs_dir / "job-other-ok-3.json").write_text(json.dumps({
            "job_id": "job-other-ok-3", "state": "COMPLETED", "scan_id": "sid-other-scan", "scan_sha256": "0" * 64,
        }), encoding="utf-8")

        # Case 4: Running managed scan accessed via direct `triage/` & junction to `triage/`
        ext_run = ext_root / "run_target"
        _seed_one_finding(ext_run, "c4", None)
        (jobs_dir / "job-run-tri.json").write_text(json.dumps({"job_id": "job-run-tri", "state": "RUNNING"}), encoding="utf-8")

        # Case 5: Valid external scan + External scan with corrupt meta (`"[]"`)
        ext_valid = ext_root / "ext_valid"
        ext_valid_sha, ext_valid_wid = _seed_one_finding(ext_valid, "ext_ok", None)
        ext_corrupt = ext_root / "ext_corrupt"
        ext_corrupt_sha, _ = _seed_one_finding(ext_corrupt, "ext_bad", None)
        (ext_corrupt / "api-scan-meta.json").write_text("[]", encoding="utf-8")

        # Case 6: Valid completed managed scan for post-inspect mutation, SHA disappearance, and decide_finding TOCTOU tests
        ok_dir = scans_dir / "job-valid-managed"
        ok_sha, ok_wid = _seed_one_finding(ok_dir, "managed_ok", {
            "scan_id": "sid-valid-managed", "scan_sha256": "<SHA>", "job_id": "job-valid-managed",
            "job_state": "COMPLETED", "publishable": True,
        })
        (jobs_dir / "job-valid-managed.json").write_text(json.dumps({
            "job_id": "job-valid-managed", "state": "COMPLETED", "scan_id": "sid-valid-managed", "scan_sha256": ok_sha,
        }), encoding="utf-8")

        created_j: list[Path] = []
        try:
            j_scan = scans_dir / "job-run-tri"
            j_tri = alias_root / "triage_alias"
            if os.name == "nt":
                subprocess.run(["cmd", "/c", "mklink", "/J", str(j_scan), str(ext_run)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                created_j.append(j_scan)
                subprocess.run(["cmd", "/c", "mklink", "/J", str(j_tri), str(ext_run / "triage")], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                created_j.append(j_tri)
            else:
                j_scan.symlink_to(ext_run, target_is_directory=True)
                created_j.append(j_scan)
                j_tri.symlink_to(ext_run / "triage", target_is_directory=True)
                created_j.append(j_tri)

            svc = TriageApiService(ApiConfig(
                data_dir=data_dir,
                reviewable_scan_dirs=(ext_run / "triage", j_tri, ext_valid, ext_corrupt),
                rules_path=self.rules,
                runtime_origin="mock",
            ))

            # Only `ext_valid` and `sid-valid-managed` may appear in list_scans (ext_corrupt fails 409 in build_scan_summary and is skipped in list)
            listed_ids = {s["scan_id"] for s in svc.list_scans(include_mock=True)["scans"]}
            self.assertEqual(listed_ids, {ext_valid_sha, "sid-valid-managed"})

            # All invalid managed scans return 404 across list/detail/findings/queue/history/report/confirm-false
            for bad_id in ("sid-missing-owner", "sid-failed-owner", "sid-mismatch", s1_sha, s2_sha):
                for fn in (
                    lambda sid=bad_id: svc.resolve_scan(sid),
                    lambda sid=bad_id: svc.list_findings(sid),
                    lambda sid=bad_id: svc.get_review_queue(sid),
                    lambda sid=bad_id: svc.get_scan_review_history(sid),
                    lambda sid=bad_id: svc.export_scan_report(sid),
                    lambda sid=bad_id: svc.decide_finding(sid, "f0", "confirm-false", "r", "x"),
                ):
                    with self.assertRaises(ApiServiceError) as ctx:
                        fn()
                    self.assertEqual(ctx.exception.http_status, 404)

            # Corrupt external metadata MUST preserve 409 ARTIFACT_PROVENANCE_MISMATCH
            with self.assertRaises(ApiServiceError) as ctx_bad:
                svc.build_scan_summary(svc.resolve_scan(ext_corrupt_sha))
            self.assertEqual(ctx_bad.exception.http_status, 409)
            self.assertEqual(ctx_bad.exception.error_code, "ARTIFACT_PROVENANCE_MISMATCH")

            # Valid external scan works across read endpoints
            self.assertEqual(svc.list_findings(ext_valid_sha)["total_count"], 1)
            self.assertEqual(svc.get_finding_detail(ext_valid_sha, ext_valid_wid)["id"], ext_valid_wid)

            # Missing expected SHA in SQLite MUST NOT fallback to another scan row!
            ext_entry = svc.resolve_scan(ext_valid_sha)
            conn_e = sqlite3.connect(str(ext_valid / "triage" / "review.sqlite"))
            try:
                conn_e.execute("UPDATE scans SET id=? WHERE id=?", ("d" * 64, ext_valid_sha))
                conn_e.commit()
            finally:
                conn_e.close()
            with self.assertRaises(ApiServiceError) as ctx_nf:
                svc._read_scan_rows(ext_entry)
            self.assertEqual(ctx_nf.exception.http_status, 409)
            self.assertEqual(ctx_nf.exception.error_code, "ARTIFACT_PROVENANCE_MISMATCH")

            # Post-inspect mutation on managed scan rejects stale DiscoveredScan (no stale reuse!)
            managed_entry = svc.resolve_scan("sid-valid-managed")
            orig_read = svc._read_scan_rows
            revoked = {"done": False}

            def _revoke_mid_decide(e):
                out = orig_read(e)
                if not revoked["done"]:
                    revoked["done"] = True
                    (jobs_dir / "job-valid-managed.json").write_text(json.dumps({
                        "job_id": "job-valid-managed", "state": "FAILED", "scan_id": None,
                    }), encoding="utf-8")
                return out

            with patch.object(svc, "_read_scan_rows", side_effect=_revoke_mid_decide):
                with self.assertRaises(ApiServiceError) as ctx_toc:
                    svc.decide_finding("sid-valid-managed", ok_wid, "confirm-false", "reviewer", "toctou check")
                self.assertEqual(ctx_toc.exception.http_status, 404)
            # Zero review events written to SQLite!
            conn_m = sqlite3.connect(str(ok_dir / "triage" / "review.sqlite"))
            try:
                self.assertEqual(conn_m.execute("SELECT COUNT(*) FROM events").fetchone()[0], 0)
            finally:
                conn_m.close()
            # And stale `managed_entry` is rejected immediately on read!
            with self.assertRaises(ApiServiceError) as ctx_stale:
                svc.build_scan_summary(managed_entry)
            self.assertEqual(ctx_stale.exception.http_status, 404)
        finally:
            for jp in created_j:
                if jp.exists():
                    jp.rmdir()

    # ------------------------------------------------------------------
    # Six Codex Independent Re-Audit Counterexamples (C1, C2, D, F, G1, G2)
    # ------------------------------------------------------------------
    def test_six_codex_reaudit_counterexamples_c1_c2_d_f_g1_g2(self) -> None:
        from contextlib import closing
        from v2.triage.store import ReviewStore

        def _gate_ref(fname: str, code: str, cwe: str, hl: int, sl: int, cl: int, *, helpers=(), root_dir=None, src_hashes=None) -> dict:
            lines = code.splitlines()
            sha = digest(code.encode("utf-8"))
            snips = [{
                "role": "finding",
                "path": fname,
                "sha256": sha,
                "start": {"line": sl, "col": 1},
                "end": {"line": sl, "col": len(lines[sl - 1])},
                "lines": [{"line": i + 1, "text": t} for i, t in enumerate(lines)],
            }]
            snaps = {fname: {"sha256": sha, "size": len(code.encode("utf-8"))}}
            for hp, hc in helpers:
                hsha = digest(hc.encode("utf-8"))
                snips.append({"role": "helper", "path": hp, "sha256": hsha, "lines": [{"line": i + 1, "text": t} for i, t in enumerate(hc.splitlines())]})
                snaps[hp] = {"sha256": hsha, "size": len(hc.encode("utf-8"))}
            rec = {
                "id": "e" * 64,
                "cwe": [cwe],
                "start": {"line": sl, "col": 1},
                "end": {"line": sl, "col": len(lines[sl - 1])},
                "issues": [],
                "snapshots": snaps,
                "snippets": snips,
                "java_context": {
                    "enclosing_class": Path(fname).stem,
                    "enclosing_method": {"name": "run", "header_line": hl, "start_line": hl, "end_line": len(lines) - 1},
                },
                "heuristic_signals": {"recommended_status": "REFUTED", "sink_line": sl, "unresolved_calls": [], "sanitizers_found": []},
            }
            if root_dir is not None:
                rec["root"] = str(root_dir)
            if src_hashes is not None:
                rec["scan_provenance"] = {"source_capture_verified": True, "source_hashes": src_hashes}
            ass = {
                "status": "REFUTED",
                "validated_status": "REFUTED",
                "raw_response": {"model": "qwen3.5:9b-q4_K_M", "done": True},
                "citations": [{"path": fname, "start_line": cl, "end_line": cl, "quote": lines[cl - 1], "sha256": sha}],
                "runtime": {"origin": "unit-test", "http_response_received": True, "http_status": 200, "response_complete": True, "model_identity_matched": True},
            }
            return apply_integration_gate(rec, ass)

        # === C1: Immediate separator boundary after canonical base ===
        c1_tpl = (
            "package demo;\nimport java.io.*;\nimport java.nio.file.*;\nimport javax.servlet.http.HttpServletRequest;\n"
            "public class C1Boundary {{\n    public String run(HttpServletRequest req) throws Exception {{\n"
            '        String raw = req.getParameter("p");\n        File base = new File("/srv/safe");\n'
            "        String baseCanon = base.getCanonicalPath();\n        File target = new File(base, raw);\n"
            "        String targetCanon = target.getCanonicalPath();\n"
            "        if (!targetCanon.startsWith({pref})) {{\n            throw new SecurityException(\"bad\");\n        }}\n"
            "        return {sink};\n    }}\n}}\n"
        )
        for bad_pref, bad_sink in (
            ('baseCanon + "archive/"', "Files.readString(Paths.get(targetCanon))"),
            ('baseCanon + "archive" + File.separator', "Files.readString(Paths.get(targetCanon))"),
            ('baseCanon + "" + "archive/"', "Files.readString(Paths.get(targetCanon))"),
            ('baseCanon + File.separator + "archive/"', "Files.readString(Paths.get(targetCanon))"),
            ('baseCanon + "/archive\\\\"', "Files.readString(Paths.get(targetCanon))"),
            ("baseCanon + File.separator", 'new File(targetCanon, "child").toString()'),
        ):
            out_c1 = _gate_ref("C1Boundary.java", c1_tpl.format(pref=bad_pref, sink=bad_sink), "CWE-22", 6, 15, 12)
            self.assertEqual(out_c1["validated_status"], "UNDETERMINED", f"C1 unsafe prefix/sink must fail closed: {bad_pref} / {bad_sink}")
        for ok_pref in (
            "baseCanon + File.separator",
            'baseCanon + File.separator + "archive" + File.separator',
            'baseCanon + "/archive/"',
            'baseCanon + "\\\\archive\\\\"',
        ):
            out_c1_ok = _gate_ref("C1Boundary.java", c1_tpl.format(pref=ok_pref, sink="Files.readString(Paths.get(targetCanon))"), "CWE-22", 6, 15, 12)
            self.assertEqual(out_c1_ok["validated_status"], "REFUTED", f"C1 valid guard should pass: {ok_pref} -> {out_c1_ok}")
            self.assertEqual(out_c1_ok.get("independent_refutation_proof"), "CWE22_CANONICAL_CONTAINMENT_GUARD")

        # === C2: Loop-carried mutation AFTER sink in loop ===
        for label, code, hl, sl, cl, cwe in (
            ("for_after_sink", (
                "package demo;\nimport java.sql.*;\nimport javax.servlet.http.HttpServletRequest;\npublic class LoopForMut {\n"
                "    public void run(HttpServletRequest req, Statement st) throws Exception {\n"
                '        String u = req.getParameter("u");\n        String q = "SELECT 1";\n'
                "        for (int i = 0; i < 2; i++) {\n            st.executeQuery(q);\n"
                '            q = "SELECT * FROM t WHERE u=\'" + u + "\'";\n        }\n    }\n}\n'
            ), 5, 9, 7, "CWE-89"),
            ("two_step_chain", (
                "package demo;\nimport java.sql.*;\nimport javax.servlet.http.HttpServletRequest;\npublic class LoopChain {\n"
                "    public void run(HttpServletRequest req, Statement st) throws Exception {\n"
                '        String u = req.getParameter("u");\n        String a = "SELECT 1";\n        String b = "SELECT 2";\n'
                "        for (int i = 0; i < 3; i++) {\n            st.executeQuery(a);\n"
                "            a = b;\n            b = u;\n        }\n    }\n}\n"
            ), 5, 10, 7, "CWE-89"),
            ("nested_outer_mut", (
                "package demo;\nimport java.sql.*;\nimport javax.servlet.http.HttpServletRequest;\npublic class LoopNested {\n"
                "    public void run(HttpServletRequest req, Statement st) throws Exception {\n"
                '        String u = req.getParameter("u");\n        String q = "SELECT 1";\n'
                "        for (int i = 0; i < 2; i++) {\n            for (int j = 0; j < 2; j++) {\n"
                "                st.executeQuery(q);\n            }\n"
                '            q = "SELECT * FROM t WHERE u=\'" + u + "\'";\n        }\n    }\n}\n'
            ), 5, 10, 7, "CWE-89"),
            ("cwe22_guarded_mut_after_sink", (
                "package demo;\nimport java.io.*;\nimport java.nio.file.*;\nimport javax.servlet.http.HttpServletRequest;\n"
                "public class LoopCwe22 {\n    public void run(HttpServletRequest req) throws Exception {\n"
                '        String raw = req.getParameter("p");\n        File base = new File("/srv/safe");\n'
                "        String baseCanon = base.getCanonicalPath();\n        File target = new File(base, raw);\n"
                "        String targetCanon = target.getCanonicalPath();\n"
                "        if (!targetCanon.startsWith(baseCanon + File.separator)) {\n            throw new SecurityException(\"bad\");\n        }\n"
                "        for (int i = 0; i < 2; i++) {\n            Files.readString(Paths.get(targetCanon));\n"
                "            targetCanon = raw;\n        }\n    }\n}\n"
            ), 6, 16, 12, "CWE-22"),
        ):
            out_c2 = _gate_ref(f"{label}.java", code, cwe, hl, sl, cl)
            self.assertEqual(out_c2["validated_status"], "UNDETERMINED", f"C2 {label} must fail closed: {out_c2}")

        c2_pos = (
            "package demo;\nimport java.sql.*;\nimport javax.servlet.http.HttpServletRequest;\npublic class LoopSafeConst {\n"
            "    public void run(HttpServletRequest req, Statement st) throws Exception {\n"
            '        String u = req.getParameter("u");\n        String q = "SELECT id FROM users";\n'
            "        for (int i = 0; i < 3; i++) {\n            st.executeQuery(q);\n        }\n    }\n}\n"
        )
        out_c2_pos = _gate_ref("LoopSafeConst.java", c2_pos, "CWE-89", 5, 9, 7)
        self.assertEqual(out_c2_pos["validated_status"], "REFUTED")
        self.assertEqual(out_c2_pos.get("independent_refutation_proof"), "UNCONDITIONAL_CONSTANT_SINK_FLOW")

        # === D: Same-package class shadowing java.lang.Integer & JLS §6.5.5.1 precedence ===
        d_root = self.root / "d_shadow_repo"
        (d_root / "audit").mkdir(parents=True)
        d_caller = (
            "package audit;\nimport java.sql.*;\nimport javax.servlet.http.HttpServletRequest;\n"
            "public class Caller {\n"
            "    public void run(HttpServletRequest req, Statement st) throws Exception {\n"
            '        String raw = req.getParameter("id");\n'
            "        int id = Integer.parseInt(raw);\n"
            '        st.executeQuery("SELECT * FROM users WHERE id=" + id);\n'
            "    }\n}\n"
        )
        d_shadow = "package audit;\npublic class Integer {\n    public static int parseInt(String s) { return Helper.decode(s); }\n}\n"
        (d_root / "audit" / "Caller.java").write_text(d_caller, encoding="utf-8")
        (d_root / "audit" / "Integer.java").write_text(d_shadow, encoding="utf-8")
        c_sha = digest(d_caller.encode("utf-8"))
        i_sha = digest(d_shadow.encode("utf-8"))

        def _eval_d_sup(cname, ccode, *, helpers=(), root_dir=None, src_hashes=None):
            cs = digest(ccode.encode("utf-8"))
            snips = [{"role": "finding", "path": cname, "sha256": cs, "lines": [{"line": i + 1, "text": t} for i, t in enumerate(ccode.splitlines())]}]
            snaps = {cname: {"sha256": cs}}
            for hp, hc in helpers:
                hs = digest(hc.encode("utf-8"))
                snips.append({"role": "helper", "path": hp, "sha256": hs, "lines": [{"line": i + 1, "text": t} for i, t in enumerate(hc.splitlines())]})
                snaps[hp] = {"sha256": hs}
            lns = ccode.splitlines()
            hl = next(i + 1 for i, l in enumerate(lns) if "public void run(" in l)
            sl = next(i + 1 for i, l in enumerate(lns) if "executeQuery(" in l)
            rec = {
                "id": "d" * 64, "cwe": ["CWE-89"], "start": {"line": sl, "col": 1}, "end": {"line": sl, "col": len(lns[sl - 1])},
                "issues": [], "snippets": snips, "snapshots": snaps,
                "java_context": {"enclosing_class": Path(cname).stem, "enclosing_method": {"name": "run", "header_line": hl, "end_line": len(lns) - 1, "parameters": ["HttpServletRequest req", "Statement st"]}},
                "heuristic_signals": {"sink_line": sl, "unresolved_calls": []},
            }
            if root_dir is not None:
                rec["root"] = str(root_dir)
            if src_hashes is not None:
                rec["scan_provenance"] = {"source_capture_verified": True, "source_hashes": src_hashes}
            dep = analyze_flow_dependencies(rec)
            gated = apply_integration_gate(rec, {
                "status": "SUPPORTED", "validated_status": "SUPPORTED", "explanation": "TP", "fix_suggestion": "PS",
                "citations": [{"path": cname, "start_line": sl, "end_line": sl, "quote": lns[sl - 1], "sha256": cs}],
                "runtime": {"origin": "unit-test", "http_response_received": True, "http_status": 200, "response_complete": True, "model_identity_matched": True},
            })
            return dep["has_unverified_helper_dependency"], gated["validated_status"]

        # Same-package audit.Integer on disk (not attached) -> UNDETERMINED
        self.assertEqual(_eval_d_sup("audit/Caller.java", d_caller, root_dir=d_root, src_hashes={"audit/Caller.java": c_sha, "audit/Integer.java": i_sha}), (True, "UNDETERMINED"))
        # Same-package audit.Integer attached calling unverified Helper.decode -> UNDETERMINED
        self.assertEqual(_eval_d_sup("audit/Caller.java", d_caller, helpers=[("audit/Integer.java", d_shadow)]), (True, "UNDETERMINED"))
        # Same-package audit.Integer blocks false REFUTED scalar parse even when complete!
        d_shadow_clean = "package audit;\npublic class Integer {\n    public static int parseInt(String s) { return 0; }\n}\n"
        self.assertEqual(_gate_ref("audit/Caller.java", d_caller, "CWE-89", 5, 8, 7, helpers=[("audit/Integer.java", d_shadow_clean)])["validated_status"], "UNDETERMINED")
        # Unimported non-java.lang StringUtils.trim -> UNDETERMINED
        d_unimp = d_caller.replace("int id = Integer.parseInt(raw);", "String id = StringUtils.trim(raw);")
        self.assertEqual(_eval_d_sup("audit/Caller.java", d_unimp), (True, "UNDETERMINED"))
        # Positive controls: explicit java.lang.Integer.parseInt & explicit `import java.lang.Integer;` beat same-package audit.Integer!
        d_fqn = d_caller.replace("Integer.parseInt(raw)", "java.lang.Integer.parseInt(raw)")
        self.assertEqual(_eval_d_sup("audit/Caller.java", d_fqn, root_dir=d_root, src_hashes={"audit/Caller.java": digest(d_fqn.encode()), "audit/Integer.java": i_sha}), (False, "SUPPORTED"))
        self.assertEqual(_gate_ref("audit/Caller.java", d_fqn, "CWE-89", 5, 8, 7, root_dir=d_root, src_hashes={"audit/Caller.java": digest(d_fqn.encode()), "audit/Integer.java": i_sha})["validated_status"], "REFUTED")
        d_imp_jl = d_caller.replace("import java.sql.*;", "import java.lang.Integer;\nimport java.sql.*;")
        self.assertEqual(_eval_d_sup("audit/Caller.java", d_imp_jl, root_dir=d_root, src_hashes={"audit/Caller.java": digest(d_imp_jl.encode()), "audit/Integer.java": i_sha}), (False, "SUPPORTED"))

        # === F, G1, G2: Full ScanJobManager + TriageApiService production pipeline ===
        sqli_java = (
            "package demo;\nimport java.sql.*;\nimport javax.servlet.http.HttpServletRequest;\n"
            "public class ReauditFG {\n    public void run(HttpServletRequest req, Statement st) throws Exception {\n"
            '        String u = req.getParameter("u");\n        st.executeQuery("SELECT * FROM a WHERE u=\'" + u + "\'");\n'
            "    }\n}\n"
        )
        fake_og = _create_fake_opengrep_from_fixtures(self.root, subdir="og_six_reaudit")

        def _ok_ol(req_doc, _n):
            ev_u = json.loads(req_doc["messages"][1]["content"])
            sn = ev_u["snippets"][0]
            ln = ev_u["start"]["line"]
            txt = next(x["text"] for x in sn["lines"] if x["line"] == ln)
            return {
                "status": "SUPPORTED", "explanation": "SQL concat", "fix_suggestion": "Use PreparedStatement",
                "citations": [{"path": sn["path"], "start_line": ln, "end_line": ln, "quote": txt, "sha256": sn["sha256"]}],
            }

        with _ScriptedOllamaServer(_ok_ol) as ol:
            def _run_job(tag: str, *, no_llm: bool):
                cfg = ApiConfig(
                    host="127.0.0.1", port=0, data_dir=self.root / f"data_six_{tag}", api_token="six-reaudit-token-123",
                    opengrep_binary=fake_og, rules_path=self.rules, ollama_endpoint=ol.endpoint, runtime_origin="unverified",
                )
                mgr = ScanJobManager(cfg)
                try:
                    sub = mgr.submit_zip_job(f"{tag}.zip", _make_java_zip({"src/ReauditFG.java": sqli_java}), no_llm=no_llm)
                    dl = time.monotonic() + 25.0
                    while time.monotonic() < dl:
                        cur = mgr.get_job(sub["job_id"])
                        if cur["state"] in ("COMPLETED", "FAILED"):
                            break
                        time.sleep(0.03)
                finally:
                    mgr.shutdown(wait=True)
                self.assertEqual(cur["state"], "COMPLETED", cur)
                return cfg, cur

            # F1: LLM job missing live-protocol-check.json -> NOT published (list_scans=0, direct 409) & recovery FAILED(COMMITTED_ARTIFACT_TAMPERED_OR_MISSING)!
            cfg_f1, j_f1 = _run_job("f1_llm", no_llm=False)
            meta_f1_path = cfg_f1.data_dir / "scans" / j_f1["job_id"] / "api-scan-meta.json"
            orig_meta_f1 = meta_f1_path.read_bytes()
            (cfg_f1.data_dir / "scans" / j_f1["job_id"] / "triage" / "live-protocol-check.json").unlink()
            svc_f1 = TriageApiService(cfg_f1)
            self.assertEqual(svc_f1.list_scans()["total_count"], 0)
            with self.assertRaises(ApiServiceError) as ctx_f1:
                svc_f1.resolve_scan(j_f1["scan_id"])
            self.assertEqual(ctx_f1.exception.http_status, 409)
            self.assertEqual(ctx_f1.exception.error_code, "ARTIFACT_PROVENANCE_MISMATCH")
            mgr_f1_rec = ScanJobManager(cfg_f1)
            try:
                rj_f1 = mgr_f1_rec.get_job(j_f1["job_id"])
            finally:
                mgr_f1_rec.shutdown(wait=True)
            self.assertEqual(rj_f1["state"], "FAILED")
            self.assertEqual(rj_f1["error_code"], "COMMITTED_ARTIFACT_TAMPERED_OR_MISSING")
            self.assertIsNone(rj_f1["scan_id"])
            self.assertIn("revoked_commit", rj_f1)
            # Original sealed api-scan-meta.json bytes preserved intact for forensics!
            self.assertEqual(meta_f1_path.read_bytes(), orig_meta_f1)

            # F2: no_llm job missing capture/opengrep.sarif -> NOT published AND recovery FAILED(COMMITTED_ARTIFACT_TAMPERED_OR_MISSING)!
            cfg_f2, j_f2 = _run_job("f2_nollm", no_llm=True)
            (cfg_f2.data_dir / "scans" / j_f2["job_id"] / "capture" / "opengrep.sarif").unlink()
            self.assertEqual(TriageApiService(cfg_f2).list_scans()["total_count"], 0)
            mgr_f2_rec = ScanJobManager(cfg_f2)
            try:
                rj_f2 = mgr_f2_rec.get_job(j_f2["job_id"])
            finally:
                mgr_f2_rec.shutdown(wait=True)
            self.assertEqual(rj_f2["state"], "FAILED")
            self.assertEqual(rj_f2["error_code"], "COMMITTED_ARTIFACT_TAMPERED_OR_MISSING")
            self.assertIsNone(rj_f2["scan_id"])

            # G1: SQLite warnings.assessment mutated after sealing -> ALL read & write endpoints reject 409!
            cfg_g1, j_g1 = _run_job("g1_tamper", no_llm=False)
            svc_g1 = TriageApiService(cfg_g1)
            sid_g1 = j_g1["scan_id"]
            fid_g1 = svc_g1.list_findings(sid_g1)["findings"][0]["id"]
            # Intact positive control first: valid Human Review succeeds!
            rev_ok = svc_g1.decide_finding(sid_g1, fid_g1, "confirm-true", "auditor", "valid review before tamper")
            self.assertEqual(rev_ok["human_review_state"], "CONFIRMED_TRUE")
            self.assertEqual(rev_ok["validated_status"], "SUPPORTED")
            # Now tamper immutable `warnings.assessment` in SQLite without touching any hashed file or scan SHA!
            db_g1 = cfg_g1.data_dir / "scans" / j_g1["job_id"] / "triage" / "review.sqlite"
            with closing(sqlite3.connect(str(db_g1))) as conn:
                ass_obj = json.loads(conn.execute("SELECT assessment FROM warnings WHERE id=?", (fid_g1,)).fetchone()[0])
                ass_obj["status"] = "REFUTED"
                ass_obj["validated_status"] = "REFUTED"
                ass_obj["explanation"] = "FORGED_IN_SQLITE"
                with conn:
                    conn.execute("UPDATE warnings SET assessment=? WHERE id=?", (json.dumps(ass_obj), fid_g1))
            self.assertEqual(svc_g1.list_scans()["total_count"], 0)
            for fn in (
                lambda: svc_g1.get_finding_detail(sid_g1, fid_g1),
                lambda: svc_g1.list_findings(sid_g1),
                lambda: svc_g1.get_review_queue(sid_g1),
                lambda: svc_g1.get_finding_history(sid_g1, fid_g1),
                lambda: svc_g1.get_scan_review_history(sid_g1),
                lambda: svc_g1.decide_finding(sid_g1, fid_g1, "reopen", "auditor", "must fail on tampered assessment"),
                lambda: svc_g1.export_scan_report(sid_g1),
            ):
                with self.assertRaises(ApiServiceError) as ctx_g1:
                    fn()
                self.assertEqual(ctx_g1.exception.http_status, 409)
                self.assertEqual(ctx_g1.exception.error_code, "ARTIFACT_PROVENANCE_MISMATCH")

            # G2: Owner revoked AFTER last _revalidate_entry and BEFORE ReviewStore.decide commits -> rollback, 0 events, 404!
            cfg_g2, j_g2 = _run_job("g2_race", no_llm=False)
            svc_g2 = TriageApiService(cfg_g2)
            sid_g2 = j_g2["scan_id"]
            fid_g2 = svc_g2.list_findings(sid_g2)["findings"][0]["id"]
            jfile_g2 = cfg_g2.data_dir / "jobs" / f"{j_g2['job_id']}.json"
            db_g2 = cfg_g2.data_dir / "scans" / j_g2["job_id"] / "triage" / "review.sqlite"
            orig_decide = ReviewStore.decide
            revoked_flag = {"done": False}

            def _revoke_inside_decide(store_self, *args, **kwargs):
                if not revoked_flag["done"]:
                    revoked_flag["done"] = True
                    jd = json.loads(jfile_g2.read_text(encoding="utf-8"))
                    jd["state"] = "FAILED"
                    jd["scan_id"] = None
                    jd["error_code"] = "REVOKED_BEFORE_COMMIT"
                    jd.pop("commit", None)
                    jfile_g2.write_text(json.dumps(jd, indent=2), encoding="utf-8")
                return orig_decide(store_self, *args, **kwargs)

            with patch.object(ReviewStore, "decide", _revoke_inside_decide):
                with self.assertRaises(ApiServiceError) as ctx_g2:
                    svc_g2.decide_finding(sid_g2, fid_g2, "confirm-true", "auditor", "race revoke")
            self.assertEqual(ctx_g2.exception.http_status, 404)
            with closing(sqlite3.connect(str(db_g2))) as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], 0)
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM rejected_decisions").fetchone()[0], 0)
                self.assertEqual(conn.execute("SELECT state FROM warnings WHERE id=?", (fid_g2,)).fetchone()[0], "OPEN")
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='trigger'").fetchone()[0], 0)

            # G2 concurrent production lock check: ScanJobManager._fail_job vs TriageApiService.decide_finding
            cfg_g2c, j_g2c = _run_job("g2_conc", no_llm=False)
            svc_g2c = TriageApiService(cfg_g2c)
            mgr_g2c = ScanJobManager(cfg_g2c)
            try:
                sid_c = j_g2c["scan_id"]
                fid_c = svc_g2c.list_findings(sid_c)["findings"][0]["id"]
                db_c = cfg_g2c.data_dir / "scans" / j_g2c["job_id"] / "triage" / "review.sqlite"
                barrier = threading.Barrier(2)
                decide_outcome: list[str] = []

                def _do_decide():
                    barrier.wait()
                    try:
                        res = svc_g2c.decide_finding(sid_c, fid_c, "confirm-false", "auditor", "concurrent test")
                        decide_outcome.append(f"OK:{res['human_review_state']}")
                    except ApiServiceError as exc:
                        decide_outcome.append(f"ERR:{exc.http_status}:{exc.error_code}")

                def _do_revoke():
                    barrier.wait()
                    mgr_g2c._fail_job(j_g2c["job_id"], 5, "CONCURRENT_REVOKE", "revoked", time.monotonic())

                t1 = threading.Thread(target=_do_decide)
                t2 = threading.Thread(target=_do_revoke)
                t1.start(); t2.start()
                t1.join(timeout=10.0); t2.join(timeout=10.0)
                with closing(sqlite3.connect(str(db_c))) as conn:
                    ev_c = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                self.assertEqual(len(decide_outcome), 1)
                if decide_outcome[0].startswith("OK:"):
                    self.assertEqual(ev_c, 1)
                else:
                    self.assertEqual(ev_c, 0, f"API returned {decide_outcome[0]} yet SQLite committed {ev_c} events!")
            finally:
                mgr_g2c.shutdown(wait=True)

    # ------------------------------------------------------------------
    # Root-Cause Remediation Suite: F1/F2/F3, C1 File.separator Shadowing,
    # D Single-Static-Import Nested Type, G1 SQLite root, and C2 continue/break
    # ------------------------------------------------------------------
    def test_codex_blockers_f1_f2_f3_c1_separator_shadow_d_static_import_and_g1_c2(self) -> None:
        from contextlib import closing
        from urllib.error import HTTPError
        from urllib.request import Request, urlopen

        def _gate(fname: str, code: str, cwe: str, hl: int, sl: int, cl: int, *, status="REFUTED", helpers=(), params=None) -> dict:
            lines = code.splitlines()
            sha = digest(code.encode("utf-8"))
            snips = [{
                "role": "finding",
                "path": fname,
                "sha256": sha,
                "start": {"line": sl, "col": 1},
                "end": {"line": sl, "col": max(1, len(lines[sl - 1]))},
                "lines": [{"line": i + 1, "text": t} for i, t in enumerate(lines)],
            }]
            snaps = {fname: {"sha256": sha, "size": len(code.encode("utf-8"))}}
            for hp, hc in helpers:
                hsha = digest(hc.encode("utf-8"))
                snips.append({"role": "helper", "path": hp, "sha256": hsha, "lines": [{"line": i + 1, "text": t} for i, t in enumerate(hc.splitlines())]})
                snaps[hp] = {"sha256": hsha, "size": len(hc.encode("utf-8"))}
            enc = {"name": "run", "header_line": hl, "start_line": hl, "end_line": len(lines) - 1}
            if params is not None:
                enc["parameters"] = params
            rec = {
                "id": "f" * 64,
                "cwe": [cwe],
                "start": {"line": sl, "col": 1},
                "end": {"line": sl, "col": max(1, len(lines[sl - 1]))},
                "issues": [],
                "snapshots": snaps,
                "snippets": snips,
                "java_context": {"enclosing_class": Path(fname).stem, "enclosing_method": enc},
                "heuristic_signals": {"recommended_status": status, "sink_line": sl, "unresolved_calls": [], "sanitizers_found": []},
            }
            ass = {
                "status": status,
                "validated_status": status,
                "raw_response": {"model": "qwen3.5:9b-q4_K_M", "done": True},
                "citations": [{"path": fname, "start_line": cl, "end_line": cl, "quote": lines[cl - 1], "sha256": sha}],
                "runtime": {"origin": "unit-test", "http_response_received": True, "http_status": 200, "response_complete": True, "model_identity_matched": True},
            }
            return apply_integration_gate(rec, ass)

        # === C1: File.separator shadowing (param, local, field, annotated field, static import, java var) ===
        for label, code, hl, sl, cl, exp in (
            ("param_shadow", (
                "package demo;\nimport java.io.File;\nimport java.nio.file.*;\nimport javax.servlet.http.HttpServletRequest;\n"
                "public class C1Param {\n    static class Holder { public String separator = \"\"; }\n"
                "    public String run(HttpServletRequest req, Holder File) throws Exception {\n"
                '        String raw = req.getParameter("p");\n        File base = new File("/srv/safe");\n'
                "        String baseCanon = base.getCanonicalPath();\n        File target = new File(base, raw);\n"
                "        String targetCanon = target.getCanonicalPath();\n"
                "        if (!targetCanon.startsWith(baseCanon + File.separator)) {\n            throw new SecurityException(\"bad\");\n        }\n"
                "        return Files.readString(Paths.get(targetCanon));\n    }\n}\n"
            ), 7, 16, 13, "UNDETERMINED"),
            ("local_shadow", (
                "package demo;\nimport java.io.File;\nimport java.nio.file.*;\nimport javax.servlet.http.HttpServletRequest;\n"
                "public class C1Local {\n    static class Holder { public String separator = \"\"; }\n"
                "    public String run(HttpServletRequest req) throws Exception {\n"
                '        String raw = req.getParameter("p");\n        Holder File = new Holder();\n'
                '        File base = new File("/srv/safe");\n        String baseCanon = base.getCanonicalPath();\n'
                "        File target = new File(base, raw);\n        String targetCanon = target.getCanonicalPath();\n"
                "        if (!targetCanon.startsWith(baseCanon + File.separator)) {\n            throw new SecurityException(\"bad\");\n        }\n"
                "        return Files.readString(Paths.get(targetCanon));\n    }\n}\n"
            ), 7, 17, 14, "UNDETERMINED"),
            ("annotated_field_shadow", (
                "package demo;\nimport java.io.File;\nimport java.nio.file.*;\nimport javax.servlet.http.HttpServletRequest;\n"
                "public class C1AnnField {\n    static class Holder { public String separator = \"\"; }\n"
                "    @SuppressWarnings(\"unused\") private Holder File = new Holder();\n"
                "    public String run(HttpServletRequest req) throws Exception {\n"
                '        String raw = req.getParameter("p");\n        File base = new File("/srv/safe");\n'
                "        String baseCanon = base.getCanonicalPath();\n        File target = new File(base, raw);\n"
                "        String targetCanon = target.getCanonicalPath();\n"
                "        if (!targetCanon.startsWith(baseCanon + File.separator)) {\n            throw new SecurityException(\"bad\");\n        }\n"
                "        return Files.readString(Paths.get(targetCanon));\n    }\n}\n"
            ), 8, 17, 14, "UNDETERMINED"),
            ("java_param_shadow_fqn", (
                "package demo;\nimport java.io.File;\nimport java.nio.file.*;\nimport javax.servlet.http.HttpServletRequest;\n"
                "public class C1JavaParam {\n    static class J { public Io io = new Io(); }\n    static class Io { public F File = new F(); }\n    static class F { public String separator = \"\"; }\n"
                "    public String run(HttpServletRequest req, J java) throws Exception {\n"
                '        String raw = req.getParameter("p");\n        File base = new File("/srv/safe");\n'
                "        String baseCanon = base.getCanonicalPath();\n        File target = new File(base, raw);\n"
                "        String targetCanon = target.getCanonicalPath();\n"
                "        if (!targetCanon.startsWith(baseCanon + java.io.File.separator)) {\n            throw new SecurityException(\"bad\");\n        }\n"
                "        return Files.readString(Paths.get(targetCanon));\n    }\n}\n"
            ), 9, 18, 15, "UNDETERMINED"),
            ("valid_fqn_with_param_file", (
                "package demo;\nimport java.io.File;\nimport java.nio.file.*;\nimport javax.servlet.http.HttpServletRequest;\n"
                "public class C1ValidFqn {\n    static class Holder { public String separator = \"\"; }\n"
                "    public String run(HttpServletRequest req, Holder File) throws Exception {\n"
                '        String raw = req.getParameter("p");\n        File base = new File("/srv/safe");\n'
                "        String baseCanon = base.getCanonicalPath();\n        File target = new File(base, raw);\n"
                "        String targetCanon = target.getCanonicalPath();\n"
                "        if (!targetCanon.startsWith(baseCanon + java.io.File.separator)) {\n            throw new SecurityException(\"bad\");\n        }\n"
                "        return Files.readString(Paths.get(targetCanon));\n    }\n}\n"
            ), 7, 16, 13, "REFUTED"),
        ):
            out = _gate(f"{label}.java", code, "CWE-22", hl, sl, cl)
            self.assertEqual(out["validated_status"], exp, f"C1 {label}: {out}")

        # === D: Single static import nested type, non-static nested import, static wildcard, multi-import line ===
        d_base = (
            "package audit;\n{imp}\nimport java.sql.*;\nimport javax.servlet.http.HttpServletRequest;\n"
            "public class DStaticCase {{\n"
            "    public void run(HttpServletRequest req, Statement st) throws Exception {{\n"
            '        String raw = req.getParameter("id");\n'
            "        int id = {call};\n"
            '        st.executeQuery("SELECT * FROM users WHERE id=" + id);\n'
            "    }}\n}}\n"
        )
        for label, imp, call, st_in, exp in (
            ("single_static_supported", "import static evil.Holder.Integer;", "Integer.parseInt(raw)", "SUPPORTED", "UNDETERMINED"),
            ("single_static_refuted", "import static evil.Holder.Integer;", "Integer.parseInt(raw)", "REFUTED", "UNDETERMINED"),
            ("single_line_multi_static", "import java.util.List; import static evil.Holder.Integer;", "Integer.parseInt(raw)", "SUPPORTED", "UNDETERMINED"),
            ("nonstatic_nested_refuted", "import evil.Holder.Integer;", "Integer.parseInt(raw)", "REFUTED", "UNDETERMINED"),
            ("static_wildcard_supported", "import static evil.Holder.*;", "Integer.parseInt(raw)", "SUPPORTED", "UNDETERMINED"),
            ("explicit_fqn_supported", "import static evil.Holder.Integer;", "java.lang.Integer.parseInt(raw)", "SUPPORTED", "SUPPORTED"),
            ("explicit_fqn_refuted", "import static evil.Holder.Integer;", "java.lang.Integer.parseInt(raw)", "REFUTED", "REFUTED"),
            ("clean_stdlib_refuted", "import java.util.List;", "Integer.parseInt(raw)", "REFUTED", "REFUTED"),
        ):
            cl = 8 if st_in == "REFUTED" else 9
            out = _gate(
                f"audit/{label}.java",
                d_base.format(imp=imp, call=call),
                "CWE-89", 6, 9, cl, status=st_in, params=["HttpServletRequest req", "Statement st"],
            )
            self.assertEqual(out["validated_status"], exp, f"D {label}: {out}")

        # === C2: continue AND break early exit skipping constant reset ===
        c2_cont = (
            "package demo;\nimport java.sql.*;\nimport javax.servlet.http.HttpServletRequest;\npublic class C2Cont {\n"
            "    public void run(HttpServletRequest req, Statement st, boolean flag) throws Exception {\n"
            '        String u = req.getParameter("u");\n        String q = "SELECT 1";\n'
            "        for (int i = 0; i < 2; i++) {\n            st.executeQuery(q);\n"
            "            if (flag) {\n                q = \"SELECT * FROM t WHERE u='\" + u + \"'\";\n                continue;\n            }\n"
            '            q = "SELECT 1";\n        }\n    }\n}\n'
        )
        c2_brk = (
            "package demo;\nimport java.sql.*;\nimport javax.servlet.http.HttpServletRequest;\npublic class C2Brk {\n"
            "    public void run(HttpServletRequest req, Statement st, boolean flag) throws Exception {\n"
            '        String u = req.getParameter("u");\n        String q = "SELECT 1";\n'
            "        for (int i = 0; i < 2; i++) {\n            if (flag) {\n                q = \"SELECT * FROM t WHERE u='\" + u + \"'\";\n                break;\n            }\n"
            '            q = "SELECT 1";\n        }\n        st.executeQuery(q);\n    }\n}\n'
        )
        self.assertEqual(_gate("C2Cont.java", c2_cont, "CWE-89", 5, 9, 7)["validated_status"], "UNDETERMINED")
        self.assertEqual(_gate("C2Brk.java", c2_brk, "CWE-89", 5, 15, 7)["validated_status"], "UNDETERMINED")

        # === F1/F2/F3 + G1 root tampering through live HTTP ThesisApiServer & Restart Recovery ===
        sqli_java = (
            "package demo;\nimport java.sql.*;\nimport javax.servlet.http.HttpServletRequest;\n"
            "public class ProdF123G1 {\n    public void run(HttpServletRequest req, Statement st) throws Exception {\n"
            '        String u = req.getParameter("u");\n        st.executeQuery("SELECT * FROM a WHERE u=\'" + u + "\'");\n'
            "    }\n}\n"
        )
        fake_og = _create_fake_opengrep_from_fixtures(self.root, subdir="og_f123_g1")

        def _ok_ol(req_doc, _n):
            ev_u = json.loads(req_doc["messages"][1]["content"])
            sn = ev_u["snippets"][0]
            ln = ev_u["start"]["line"]
            txt = next(x["text"] for x in sn["lines"] if x["line"] == ln)
            return {
                "status": "SUPPORTED", "explanation": "SQL concat", "fix_suggestion": "Use PreparedStatement",
                "citations": [{"path": sn["path"], "start_line": ln, "end_line": ln, "quote": txt, "sha256": sn["sha256"]}],
            }

        with _ScriptedOllamaServer(_ok_ol) as ol:
            # F1 + F3 standalone (no external scan) over live HTTP ThesisApiServer and after restart
            data_f13 = self.root / "data_http_f13"
            tok = "f13-http-token-20261122"
            cfg_f13 = ApiConfig(
                host="127.0.0.1", port=0, data_dir=data_f13, api_token=tok,
                opengrep_binary=fake_og, rules_path=self.rules, ollama_endpoint=ol.endpoint, runtime_origin="unverified",
            )
            srv = ThesisApiServer(cfg_f13)
            th = threading.Thread(target=srv.serve_forever, daemon=True)
            th.start()
            try:
                base = f"http://127.0.0.1:{srv.server_port}"
                hdrs = {"Authorization": f"Bearer {tok}", "Connection": "close"}
                sub = srv.jobs.submit_zip_job("f13.zip", _make_java_zip({"src/ProdF123G1.java": sqli_java}), no_llm=False)
                dl = time.monotonic() + 25.0
                while time.monotonic() < dl:
                    cur = srv.jobs.get_job(sub["job_id"])
                    if cur["state"] in ("COMPLETED", "FAILED"):
                        break
                    time.sleep(0.03)
                self.assertEqual(cur["state"], "COMPLETED", cur)
                jid, sid = cur["job_id"], cur["scan_id"]
                jfile_sha0 = digest((data_f13 / "jobs" / f"{jid}.json").read_bytes())

                # Delete triage/http-capture-check.json while server is running
                (data_f13 / "scans" / jid / "triage" / "http-capture-check.json").unlink()

                # HTTP GET /api/scan-jobs/{jid} & /api/scan-jobs MUST NOT report COMPLETED and MUST NOT mutate disk
                with urlopen(Request(f"{base}/api/scan-jobs/{jid}", headers=hdrs), timeout=5) as r:
                    j_http = json.loads(r.read().decode("utf-8"))
                self.assertEqual(j_http["state"], "FAILED")
                self.assertEqual(j_http["error_code"], "COMMITTED_ARTIFACT_TAMPERED_OR_MISSING")
                self.assertIsNone(j_http["scan_id"])
                with urlopen(Request(f"{base}/api/scan-jobs", headers=hdrs), timeout=5) as r:
                    jl_http = json.loads(r.read().decode("utf-8"))
                self.assertEqual(jl_http["jobs"][0]["state"], "FAILED")
                self.assertEqual(digest((data_f13 / "jobs" / f"{jid}.json").read_bytes()), jfile_sha0)

                # HTTP GET /api/scans/{sid} -> 409 ARTIFACT_PROVENANCE_MISMATCH
                with self.assertRaises(HTTPError) as ctx_s1:
                    urlopen(Request(f"{base}/api/scans/{sid}", headers=hdrs), timeout=5)
                self.assertEqual(ctx_s1.exception.code, 409)
                self.assertEqual(json.loads(ctx_s1.exception.read().decode("utf-8"))["error_code"], "ARTIFACT_PROVENANCE_MISMATCH")
            finally:
                srv.shutdown()
                th.join(timeout=2.0)
                srv.server_close()

            # F3 standalone restart recovery (no external scan): /api/scans/{sid} MUST still be 409, NOT 404!
            srv2 = ThesisApiServer(cfg_f13)
            th2 = threading.Thread(target=srv2.serve_forever, daemon=True)
            th2.start()
            try:
                base2 = f"http://127.0.0.1:{srv2.server_port}"
                hdrs2 = {"Authorization": f"Bearer {tok}", "Connection": "close"}
                with self.assertRaises(HTTPError) as ctx_s2:
                    urlopen(Request(f"{base2}/api/scans/{sid}", headers=hdrs2), timeout=5)
                self.assertEqual(ctx_s2.exception.code, 409)
                self.assertEqual(json.loads(ctx_s2.exception.read().decode("utf-8"))["error_code"], "ARTIFACT_PROVENANCE_MISMATCH")
                self.assertEqual(srv2.service.list_scans()["total_count"], 0)
            finally:
                srv2.shutdown()
                th2.join(timeout=2.0)
                srv2.server_close()

            # F2: External scan with identical scan_sha256 MUST NOT hijack committed scan_id when assessments.jsonl is deleted
            data_f2 = self.root / "data_f2_hijack"
            ext_f2 = self.root / "ext_f2_same_sha"
            cfg_f2 = ApiConfig(
                host="127.0.0.1", port=0, data_dir=data_f2, readonly_scan_dirs=(ext_f2,), api_token=tok,
                opengrep_binary=fake_og, rules_path=self.rules, ollama_endpoint=ol.endpoint, runtime_origin="unverified",
            )
            mgr_f2 = ScanJobManager(cfg_f2)
            try:
                sub2 = mgr_f2.submit_zip_job("f2.zip", _make_java_zip({"src/ProdF123G1.java": sqli_java}), no_llm=False)
                dl = time.monotonic() + 25.0
                while time.monotonic() < dl:
                    c2 = mgr_f2.get_job(sub2["job_id"])
                    if c2["state"] in ("COMPLETED", "FAILED"):
                        break
                    time.sleep(0.03)
                self.assertEqual(c2["state"], "COMPLETED")
                shutil.copytree(data_f2 / "scans" / c2["job_id"], ext_f2)
                (ext_f2 / "api-scan-meta.json").unlink()
                (data_f2 / "scans" / c2["job_id"] / "triage" / "assessments.jsonl").unlink()
                svc_f2 = TriageApiService(cfg_f2)
                with self.assertRaises(ApiServiceError) as ctx_f2:
                    svc_f2.resolve_scan(c2["scan_id"])
                self.assertEqual(ctx_f2.exception.http_status, 409)
                self.assertEqual(ctx_f2.exception.error_code, "ARTIFACT_PROVENANCE_MISMATCH")
                self.assertNotIn(c2["scan_id"], [x["scan_id"] for x in svc_f2.list_scans()["scans"]])
            finally:
                mgr_f2.shutdown(wait=True)

            # G1: SQLite warnings.evidence.root tampering rejected 409 on detail & review with 0 events
            data_g1 = self.root / "data_g1_root"
            cfg_g1 = ApiConfig(
                host="127.0.0.1", port=0, data_dir=data_g1, api_token=tok,
                opengrep_binary=fake_og, rules_path=self.rules, ollama_endpoint=ol.endpoint, runtime_origin="unverified",
            )
            mgr_g1 = ScanJobManager(cfg_g1)
            try:
                sub_g = mgr_g1.submit_zip_job("g1.zip", _make_java_zip({"src/ProdF123G1.java": sqli_java}), no_llm=False)
                dl = time.monotonic() + 25.0
                while time.monotonic() < dl:
                    cg = mgr_g1.get_job(sub_g["job_id"])
                    if cg["state"] in ("COMPLETED", "FAILED"):
                        break
                    time.sleep(0.03)
                self.assertEqual(cg["state"], "COMPLETED")
                svc_g1 = TriageApiService(cfg_g1)
                sid_g = cg["scan_id"]
                fid_g = svc_g1.list_findings(sid_g)["findings"][0]["id"]
                self.assertEqual(svc_g1.get_finding_detail(sid_g, fid_g)["id"], fid_g)
                db_g = data_g1 / "scans" / cg["job_id"] / "triage" / "review.sqlite"
                with closing(sqlite3.connect(str(db_g))) as conn:
                    ev = json.loads(conn.execute("SELECT evidence FROM warnings WHERE id=?", (fid_g,)).fetchone()[0])
                    ev["root"] = str(self.root / "forged_root")
                    with conn:
                        conn.execute("UPDATE warnings SET evidence=? WHERE id=?", (json.dumps(ev, sort_keys=True), fid_g))
                for fn in (
                    lambda: svc_g1.get_finding_detail(sid_g, fid_g),
                    lambda: svc_g1.decide_finding(sid_g, fid_g, "confirm-false", "auditor", "forged root"),
                ):
                    with self.assertRaises(ApiServiceError) as ctx_g:
                        fn()
                    self.assertEqual(ctx_g.exception.http_status, 409)
                    self.assertEqual(ctx_g.exception.error_code, "ARTIFACT_PROVENANCE_MISMATCH")
                with closing(sqlite3.connect(str(db_g))) as conn:
                    self.assertEqual(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], 0)
            finally:
                mgr_g1.shutdown(wait=True)

    # ------------------------------------------------------------------
    # Blocker F Final: Sealed commit identity & provenance preserved when
    # api-scan-meta.json is tampered with `publishable=false` (or FINALIZING/error_code)
    # ------------------------------------------------------------------
    def test_blocker_f_sealed_commit_preserved_on_publishable_false_metadata_tamper(self) -> None:
        sqli_java = (
            "package demo;\nimport java.sql.*;\nimport javax.servlet.http.HttpServletRequest;\n"
            "public class PubFalseBlockerF {\n    public void run(HttpServletRequest req, Statement st) throws Exception {\n"
            '        String u = req.getParameter("u");\n        st.executeQuery("SELECT * FROM users WHERE u=\'" + u + "\'");\n'
            "    }\n}\n"
        )
        fake_og = _create_fake_opengrep_from_fixtures(self.root, subdir="og_f_pub_false")

        def _ok_ol(req_doc, _n):
            ev_u = json.loads(req_doc["messages"][1]["content"])
            sn = ev_u["snippets"][0]
            ln = ev_u["start"]["line"]
            txt = next(x["text"] for x in sn["lines"] if x["line"] == ln)
            return {
                "status": "SUPPORTED", "explanation": "SQL concat", "fix_suggestion": "Use PreparedStatement",
                "citations": [{"path": sn["path"], "start_line": ln, "end_line": ln, "quote": txt, "sha256": sn["sha256"]}],
            }

        def _make_committed(tag: str, *, readonly_dirs: tuple[Path, ...] = (), no_llm: bool = False, ol_ep: str = "http://127.0.0.1:11434"):
            ddir = self.root / f"data_pubf_{tag}"
            cfg = ApiConfig(
                host="127.0.0.1", port=0, data_dir=ddir, readonly_scan_dirs=readonly_dirs,
                api_token=f"pubf-tok-{tag}-1234", opengrep_binary=fake_og, rules_path=self.rules,
                ollama_endpoint=ol_ep, runtime_origin="unverified",
            )
            mgr = ScanJobManager(cfg)
            sub = mgr.submit_zip_job(f"{tag}.zip", _make_java_zip({"src/PubFalseBlockerF.java": sqli_java}), no_llm=no_llm)
            dl = time.monotonic() + 25.0
            cur = sub
            while time.monotonic() < dl:
                cur = mgr.get_job(sub["job_id"])
                if cur["state"] in ("COMPLETED", "FAILED"):
                    break
                time.sleep(0.03)
            self.assertEqual(cur["state"], "COMPLETED", cur)
            return cfg, mgr, cur

        with _ScriptedOllamaServer(_ok_ol) as ol:
            # 1. Exact Codex counterexample: committed scan -> tamper ONLY `api-scan-meta.json` with `publishable=false`
            #    (also check `operator_note`, `job_state=FINALIZING`, `error_code` controls)
            for tag, patch_fields in (
                ("pub_false", {"publishable": False}),
                ("op_note", {"operator_note": "tampered"}),
                ("fin_pub_false", {"job_state": "FINALIZING", "publishable": False}),
                ("spoof_err", {"error_code": "SPOOFED_ERROR"}),
            ):
                ext_same = self.root / f"ext_pubf_{tag}"
                cfg, mgr, job = _make_committed(tag, readonly_dirs=(ext_same,), ol_ep=ol.endpoint)
                jid, sid = job["job_id"], job["scan_id"]
                jfile = cfg.data_dir / "jobs" / f"{jid}.json"
                mfile = cfg.data_dir / "scans" / jid / "api-scan-meta.json"
                orig_job_sha = digest(jfile.read_bytes())
                orig_meta_sha = digest(mfile.read_bytes())
                try:
                    # Copy intact scan as external read-only import with identical scan_sha256
                    shutil.copytree(cfg.data_dir / "scans" / jid, ext_same)
                    (ext_same / "api-scan-meta.json").unlink()

                    # Pre-tamper check: valid committed scan resolves to managed dir
                    svc = TriageApiService(cfg)
                    self.assertEqual(svc.resolve_scan(sid).owner_job_id, jid)

                    # Tamper ONLY api-scan-meta.json
                    mdoc = json.loads(mfile.read_text(encoding="utf-8"))
                    mdoc.update(patch_fields)
                    mfile.write_text(json.dumps(mdoc, indent=2, ensure_ascii=False), encoding="utf-8")
                    tampered_meta_sha = digest(mfile.read_bytes())

                    # Live get_job / list_jobs -> FAILED / COMMITTED_ARTIFACT_TAMPERED_OR_MISSING, revoked_commit present, disk untouched
                    j_live = mgr.get_job(jid)
                    jl_live = mgr.list_jobs()["jobs"][0]
                    for view in (j_live, jl_live):
                        self.assertEqual(view["state"], "FAILED", f"{tag}: {view}")
                        self.assertEqual(view["error_code"], "COMMITTED_ARTIFACT_TAMPERED_OR_MISSING", f"{tag}: {view}")
                        self.assertIsNone(view["scan_id"])
                        self.assertIsInstance(view.get("revoked_commit"), dict)
                        self.assertEqual(view["revoked_commit"]["meta_sha256"], orig_meta_sha)
                        self.assertEqual(view.get("revoked_scan_id"), sid)
                    self.assertEqual(digest(jfile.read_bytes()), orig_job_sha)

                    # resolve_scan(sid) -> 409 ARTIFACT_PROVENANCE_MISMATCH; external same-SHA scan NEVER hijacks sid
                    with self.assertRaises(ApiServiceError) as ctx_live:
                        svc.resolve_scan(sid)
                    self.assertEqual(ctx_live.exception.http_status, 409, tag)
                    self.assertEqual(ctx_live.exception.error_code, "ARTIFACT_PROVENANCE_MISMATCH", tag)
                    self.assertNotIn(sid, [x["scan_id"] for x in svc.list_scans()["scans"]])
                finally:
                    mgr.shutdown(wait=True)

                # Restart recovery (1st and 2nd restart) preserves revoked_commit, tampered meta bytes, and HTTP 409
                for restart_idx in (1, 2):
                    mgr_r = ScanJobManager(cfg)
                    try:
                        j_r = mgr_r.get_job(jid)
                        j_r_disk = json.loads(jfile.read_text(encoding="utf-8"))
                        self.assertEqual(j_r["state"], "FAILED", f"{tag}/r{restart_idx}")
                        self.assertEqual(j_r["error_code"], "COMMITTED_ARTIFACT_TAMPERED_OR_MISSING", f"{tag}/r{restart_idx}")
                        self.assertIsNone(j_r["scan_id"])
                        self.assertEqual(j_r_disk["error_code"], "COMMITTED_ARTIFACT_TAMPERED_OR_MISSING")
                        self.assertEqual(j_r_disk["revoked_commit"]["meta_sha256"], orig_meta_sha)
                        self.assertEqual(j_r_disk["revoked_scan_id"], sid)
                        self.assertEqual(digest(mfile.read_bytes()), tampered_meta_sha)
                        svc_r = TriageApiService(cfg)
                        with self.assertRaises(ApiServiceError) as ctx_r:
                            svc_r.resolve_scan(sid)
                        self.assertEqual(ctx_r.exception.http_status, 409, f"{tag}/r{restart_idx}")
                        self.assertEqual(ctx_r.exception.error_code, "ARTIFACT_PROVENANCE_MISMATCH", f"{tag}/r{restart_idx}")
                        self.assertNotIn(sid, [x["scan_id"] for x in svc_r.list_scans()["scans"]])
                    finally:
                        mgr_r.shutdown(wait=True)

            # 2. Never-committed legacy scan with publishable=false -> INCOMPLETE_COMMIT_ON_RESTART, no revoked_commit, 404
            cfg_leg, mgr_leg, job_leg = _make_committed("legacy_unpub", no_llm=True, ol_ep=ol.endpoint)
            mgr_leg.shutdown(wait=True)
            jid_l, sid_l = job_leg["job_id"], job_leg["scan_id"]
            jf_l = cfg_leg.data_dir / "jobs" / f"{jid_l}.json"
            jd_l = json.loads(jf_l.read_text(encoding="utf-8"))
            jd_l.pop("commit", None)
            jf_l.write_text(json.dumps(jd_l, indent=2), encoding="utf-8")
            mf_l = cfg_leg.data_dir / "scans" / jid_l / "api-scan-meta.json"
            md_l = json.loads(mf_l.read_text(encoding="utf-8"))
            md_l.pop("commit_authority", None)
            md_l.pop("schema", None)
            md_l.update({"job_state": "FINALIZING", "publishable": False})
            mf_l.write_text(json.dumps(md_l, indent=2), encoding="utf-8")
            with self.assertRaises(ApiServiceError) as ctx_l1:
                TriageApiService(cfg_leg).resolve_scan(sid_l)
            self.assertEqual(ctx_l1.exception.http_status, 404)
            mgr_leg_r = ScanJobManager(cfg_leg)
            try:
                j_lr = mgr_leg_r.get_job(jid_l)
                self.assertEqual(j_lr["error_code"], "INCOMPLETE_COMMIT_ON_RESTART")
                self.assertNotIn("revoked_commit", j_lr)
                with self.assertRaises(ApiServiceError) as ctx_l2:
                    TriageApiService(cfg_leg).resolve_scan(sid_l)
                self.assertEqual(ctx_l2.exception.http_status, 404)
            finally:
                mgr_leg_r.shutdown(wait=True)

            # 3. Forged commit whose meta_sha256 MATCHES an unpublishable meta -> INCOMPLETE_COMMIT_ON_RESTART, 404
            cfg_fm, mgr_fm, job_fm = _make_committed("forged_match", no_llm=True, ol_ep=ol.endpoint)
            mgr_fm.shutdown(wait=True)
            jid_fm, sid_fm = job_fm["job_id"], job_fm["scan_id"]
            mf_fm = cfg_fm.data_dir / "scans" / jid_fm / "api-scan-meta.json"
            md_fm = json.loads(mf_fm.read_text(encoding="utf-8"))
            md_fm["publishable"] = False
            mf_fm.write_text(json.dumps(md_fm, indent=2), encoding="utf-8")
            jf_fm = cfg_fm.data_dir / "jobs" / f"{jid_fm}.json"
            jd_fm = json.loads(jf_fm.read_text(encoding="utf-8"))
            jd_fm["commit"]["meta_sha256"] = digest(mf_fm.read_bytes())
            jf_fm.write_text(json.dumps(jd_fm, indent=2), encoding="utf-8")
            with self.assertRaises(ApiServiceError) as ctx_fm:
                TriageApiService(cfg_fm).resolve_scan(sid_fm)
            self.assertEqual(ctx_fm.exception.http_status, 404)
            mgr_fm_r = ScanJobManager(cfg_fm)
            try:
                j_fmr = mgr_fm_r.get_job(jid_fm)
                self.assertEqual(j_fmr["error_code"], "INCOMPLETE_COMMIT_ON_RESTART")
                self.assertNotIn("revoked_commit", j_fmr)
            finally:
                mgr_fm_r.shutdown(wait=True)

            # 4. Forged job record claiming another valid scan's scan_id MUST NOT create tombstone or revoked_commit
            cfg_cf, mgr_cf, job_cf = _make_committed("forged_conflict", no_llm=True, ol_ep=ol.endpoint)
            mgr_cf.shutdown(wait=True)
            jid_cf, sid_cf = job_cf["job_id"], job_cf["scan_id"]
            forged_jid = "job-0000000000000000"
            forged_doc = json.loads((cfg_cf.data_dir / "jobs" / f"{jid_cf}.json").read_text(encoding="utf-8"))
            forged_doc["job_id"] = forged_jid
            forged_doc["commit"]["job_id"] = forged_jid
            forged_doc["commit"]["scan_dir"] = forged_jid
            forged_doc["commit"]["meta_sha256"] = "0" * 64
            (cfg_cf.data_dir / "jobs" / f"{forged_jid}.json").write_text(json.dumps(forged_doc, indent=2), encoding="utf-8")
            with self.assertRaises(ApiServiceError) as ctx_cf:
                TriageApiService(cfg_cf).resolve_scan(sid_cf)
            self.assertEqual(ctx_cf.exception.http_status, 404)
            mgr_cf_r = ScanJobManager(cfg_cf)
            try:
                j_forged_r = mgr_cf_r.get_job(forged_jid)
                self.assertEqual(j_forged_r["error_code"], "INCOMPLETE_COMMIT_ON_RESTART")
                self.assertNotIn("revoked_commit", j_forged_r)
            finally:
                mgr_cf_r.shutdown(wait=True)

            # 5. Existing integrity invariants preserved: missing assessments.jsonl and missing evidence.json -> 409 + revoked_commit
            for missing_tag, rel_del in (
                ("miss_ass", Path("triage") / "assessments.jsonl"),
                ("miss_ev", Path("triage") / "evidence.json"),
            ):
                cfg_m, mgr_m, job_m = _make_committed(missing_tag, ol_ep=ol.endpoint)
                jid_m, sid_m = job_m["job_id"], job_m["scan_id"]
                try:
                    (cfg_m.data_dir / "scans" / jid_m / rel_del).unlink()
                    self.assertEqual(mgr_m.get_job(jid_m)["error_code"], "COMMITTED_ARTIFACT_TAMPERED_OR_MISSING")
                    with self.assertRaises(ApiServiceError) as ctx_m1:
                        TriageApiService(cfg_m).resolve_scan(sid_m)
                    self.assertEqual(ctx_m1.exception.http_status, 409)
                finally:
                    mgr_m.shutdown(wait=True)
                mgr_mr = ScanJobManager(cfg_m)
                try:
                    j_mr = mgr_mr.get_job(jid_m)
                    self.assertEqual(j_mr["error_code"], "COMMITTED_ARTIFACT_TAMPERED_OR_MISSING")
                    self.assertIsInstance(j_mr.get("revoked_commit"), dict)
                    with self.assertRaises(ApiServiceError) as ctx_m2:
                        TriageApiService(cfg_m).resolve_scan(sid_m)
                    self.assertEqual(ctx_m2.exception.http_status, 409)
                finally:
                    mgr_mr.shutdown(wait=True)

    # ------------------------------------------------------------------
    # Blocker F Failure Marker: Untrusted/forged `api-scan-failure.json`
    # MUST NEVER negate an authenticated sealed v2 commit into 404/INCOMPLETE_COMMIT
    # ------------------------------------------------------------------
    def test_blocker_f_failure_marker_cannot_negate_sealed_commit(self) -> None:
        sqli_java = (
            "package demo;\nimport java.sql.*;\nimport javax.servlet.http.HttpServletRequest;\n"
            "public class MarkerBlockerF {\n    public void run(HttpServletRequest req, Statement st) throws Exception {\n"
            '        String u = req.getParameter("u");\n        st.executeQuery("SELECT * FROM users WHERE u=\'" + u + "\'");\n'
            "    }\n}\n"
        )
        fake_og = _create_fake_opengrep_from_fixtures(self.root, subdir="og_f_marker")

        def _ok_ol(req_doc, _n):
            ev_u = json.loads(req_doc["messages"][1]["content"])
            sn = ev_u["snippets"][0]
            ln = ev_u["start"]["line"]
            txt = next(x["text"] for x in sn["lines"] if x["line"] == ln)
            return {
                "status": "SUPPORTED", "explanation": "SQL concat", "fix_suggestion": "Use PreparedStatement",
                "citations": [{"path": sn["path"], "start_line": ln, "end_line": ln, "quote": txt, "sha256": sn["sha256"]}],
            }

        def _make_committed(tag: str, *, readonly_dirs: tuple[Path, ...] = (), no_llm: bool = False, ol_ep: str = "http://127.0.0.1:11434"):
            ddir = self.root / f"data_fmk_{tag}"
            cfg = ApiConfig(
                host="127.0.0.1", port=0, data_dir=ddir, readonly_scan_dirs=readonly_dirs,
                api_token=f"fmk-tok-{tag}-1234", opengrep_binary=fake_og, rules_path=self.rules,
                ollama_endpoint=ol_ep, runtime_origin="unverified",
            )
            mgr = ScanJobManager(cfg)
            sub = mgr.submit_zip_job(f"{tag}.zip", _make_java_zip({"src/MarkerBlockerF.java": sqli_java}), no_llm=no_llm)
            dl = time.monotonic() + 25.0
            cur = sub
            while time.monotonic() < dl:
                cur = mgr.get_job(sub["job_id"])
                if cur["state"] in ("COMPLETED", "FAILED"):
                    break
                time.sleep(0.03)
            self.assertEqual(cur["state"], "COMPLETED", cur)
            return cfg, mgr, cur

        with _ScriptedOllamaServer(_ok_ol) as ol:
            # 1. Exact Codex counterexample + varied classifications + malformed/non-object markers,
            #    with external same-SHA import and across 2 restarts
            marker_variants: tuple[tuple[str, str], ...] = (
                ("codex_incomplete", json.dumps({"failure_classification": "INCOMPLETE_COMMIT", "error_code": "INCOMPLETE_COMMIT_ON_RESTART"}, indent=2)),
                ("job_timeout", json.dumps({"error_code": "JOB_TIMEOUT", "state": "FAILED", "publishable": False})),
                ("empty_obj", "{}"),
                ("malformed_json", "{not-valid-json"),
                ("non_object_list", '["tampered"]'),
            )
            for tag, raw_marker in marker_variants:
                ext_same = self.root / f"ext_fmk_{tag}"
                cfg, mgr, job = _make_committed(tag, readonly_dirs=(ext_same,), ol_ep=ol.endpoint)
                jid, sid = job["job_id"], job["scan_id"]
                sdir = cfg.data_dir / "scans" / jid
                jfile = cfg.data_dir / "jobs" / f"{jid}.json"
                mfile = sdir / "api-scan-meta.json"
                orig_job_sha = digest(jfile.read_bytes())
                orig_meta_sha = digest(mfile.read_bytes())
                try:
                    shutil.copytree(sdir, ext_same)
                    (ext_same / "api-scan-meta.json").unlink()
                    svc = TriageApiService(cfg)
                    stale_entry = svc.resolve_scan(sid)
                    self.assertEqual(stale_entry.owner_job_id, jid)

                    # Drop ONLY `api-scan-failure.json` onto intact sealed committed scan
                    (sdir / "api-scan-failure.json").write_text(raw_marker, encoding="utf-8")

                    for view in (mgr.get_job(jid), mgr.list_jobs()["jobs"][0]):
                        self.assertEqual(view["state"], "FAILED", f"{tag}: {view}")
                        self.assertEqual(view["error_code"], "COMMITTED_ARTIFACT_TAMPERED_OR_MISSING", f"{tag}: {view}")
                        self.assertIsNone(view["scan_id"])
                        self.assertIsInstance(view.get("revoked_commit"), dict)
                        self.assertEqual(view["revoked_commit"]["meta_sha256"], orig_meta_sha)
                        self.assertEqual(view.get("revoked_scan_id"), sid)
                    self.assertEqual(digest(jfile.read_bytes()), orig_job_sha)

                    with self.assertRaises(ApiServiceError) as ctx_live:
                        svc.resolve_scan(sid)
                    self.assertEqual(ctx_live.exception.http_status, 409, tag)
                    self.assertEqual(ctx_live.exception.error_code, "ARTIFACT_PROVENANCE_MISMATCH", tag)
                    with self.assertRaises(ApiServiceError) as ctx_reval:
                        svc.build_scan_summary(stale_entry)
                    self.assertEqual(ctx_reval.exception.http_status, 409, tag)
                    listed_live = [x["scan_id"] for x in svc.list_scans()["scans"]]
                    self.assertNotIn(sid, listed_live)
                    self.assertTrue(any(x.startswith(f"{sid[:16]}-ext_fmk_{tag}") for x in listed_live))
                finally:
                    mgr.shutdown(wait=True)

                for r_idx in (1, 2):
                    mgr_r = ScanJobManager(cfg)
                    try:
                        j_r = mgr_r.get_job(jid)
                        j_disk = json.loads(jfile.read_text(encoding="utf-8"))
                        self.assertEqual(j_r["error_code"], "COMMITTED_ARTIFACT_TAMPERED_OR_MISSING", f"{tag}/r{r_idx}")
                        self.assertEqual(j_disk["error_code"], "COMMITTED_ARTIFACT_TAMPERED_OR_MISSING", f"{tag}/r{r_idx}")
                        self.assertEqual(j_disk["revoked_commit"]["meta_sha256"], orig_meta_sha)
                        self.assertEqual(j_disk["revoked_scan_id"], sid)
                        self.assertEqual(digest(mfile.read_bytes()), orig_meta_sha)
                        svc_r = TriageApiService(cfg)
                        with self.assertRaises(ApiServiceError) as ctx_r:
                            svc_r.resolve_scan(sid)
                        self.assertEqual(ctx_r.exception.http_status, 409, f"{tag}/r{r_idx}")
                        self.assertEqual(ctx_r.exception.error_code, "ARTIFACT_PROVENANCE_MISMATCH", f"{tag}/r{r_idx}")
                        self.assertNotIn(sid, [x["scan_id"] for x in svc_r.list_scans()["scans"]])
                    finally:
                        mgr_r.shutdown(wait=True)

            # 2. Pre-commit & legacy jobs with failure marker MUST remain 404 / non-revoked
            cfg_pre, mgr_pre, job_pre = _make_committed("precommit_mk", no_llm=True, ol_ep=ol.endpoint)
            mgr_pre.shutdown(wait=True)
            jid_p, sid_p = job_pre["job_id"], job_pre["scan_id"]
            jf_p = cfg_pre.data_dir / "jobs" / f"{jid_p}.json"
            jd_p = json.loads(jf_p.read_text(encoding="utf-8"))
            jd_p.pop("commit", None)
            jf_p.write_text(json.dumps(jd_p, indent=2), encoding="utf-8")
            mf_p = cfg_pre.data_dir / "scans" / jid_p / "api-scan-meta.json"
            md_p = json.loads(mf_p.read_text(encoding="utf-8"))
            md_p.pop("commit_authority", None)
            md_p.pop("schema", None)
            md_p.update({"job_state": "COMPLETED", "publishable": True})
            mf_p.write_text(json.dumps(md_p, indent=2), encoding="utf-8")
            (cfg_pre.data_dir / "scans" / jid_p / "api-scan-failure.json").write_text(
                json.dumps({"failure_classification": "ARTIFACT_INTEGRITY_FAILED", "error_code": "COMMITTED_ARTIFACT_TAMPERED_OR_MISSING"}),
                encoding="utf-8",
            )
            with self.assertRaises(ApiServiceError) as ctx_p1:
                TriageApiService(cfg_pre).resolve_scan(sid_p)
            self.assertEqual(ctx_p1.exception.http_status, 404)
            mgr_pr = ScanJobManager(cfg_pre)
            try:
                j_pr = mgr_pr.get_job(jid_p)
                self.assertEqual(j_pr["error_code"], "INCOMPLETE_COMMIT_ON_RESTART")
                self.assertNotIn("revoked_commit", j_pr)
            finally:
                mgr_pr.shutdown(wait=True)

            # 3. Forged commit sealing unpublishable metadata + failure marker -> INCOMPLETE_COMMIT_ON_RESTART, 404
            cfg_fg, mgr_fg, job_fg = _make_committed("forged_unpub_mk", no_llm=True, ol_ep=ol.endpoint)
            mgr_fg.shutdown(wait=True)
            jid_f, sid_f = job_fg["job_id"], job_fg["scan_id"]
            mf_f = cfg_fg.data_dir / "scans" / jid_f / "api-scan-meta.json"
            md_f = json.loads(mf_f.read_text(encoding="utf-8"))
            md_f.update({"publishable": False, "job_state": "FAILED", "error_code": "JOB_TIMEOUT"})
            mf_f.write_text(json.dumps(md_f, indent=2), encoding="utf-8")
            jf_f = cfg_fg.data_dir / "jobs" / f"{jid_f}.json"
            jd_f = json.loads(jf_f.read_text(encoding="utf-8"))
            jd_f["commit"]["meta_sha256"] = digest(mf_f.read_bytes())
            jf_f.write_text(json.dumps(jd_f, indent=2), encoding="utf-8")
            (cfg_fg.data_dir / "scans" / jid_f / "api-scan-failure.json").write_text(
                json.dumps({"error_code": "JOB_TIMEOUT", "state": "FAILED"}), encoding="utf-8"
            )
            with self.assertRaises(ApiServiceError) as ctx_f1:
                TriageApiService(cfg_fg).resolve_scan(sid_f)
            self.assertEqual(ctx_f1.exception.http_status, 404)
            mgr_fr = ScanJobManager(cfg_fg)
            try:
                j_fr = mgr_fr.get_job(jid_f)
                self.assertEqual(j_fr["error_code"], "INCOMPLETE_COMMIT_ON_RESTART")
                self.assertNotIn("revoked_commit", j_fr)
            finally:
                mgr_fr.shutdown(wait=True)

            # 4. Missing sealed artifact + fake INCOMPLETE_COMMIT marker still records missing_artifacts & 409
            cfg_ma, mgr_ma, job_ma = _make_committed("miss_ev_mk", ol_ep=ol.endpoint)
            jid_ma, sid_ma = job_ma["job_id"], job_ma["scan_id"]
            try:
                (cfg_ma.data_dir / "scans" / jid_ma / "triage" / "evidence.json").unlink()
                (cfg_ma.data_dir / "scans" / jid_ma / "api-scan-failure.json").write_text(
                    json.dumps({"failure_classification": "INCOMPLETE_COMMIT", "error_code": "INCOMPLETE_COMMIT_ON_RESTART"}),
                    encoding="utf-8",
                )
                j_ma_live = mgr_ma.get_job(jid_ma)
                self.assertEqual(j_ma_live["error_code"], "COMMITTED_ARTIFACT_TAMPERED_OR_MISSING")
                self.assertIn("triage/evidence.json", (j_ma_live.get("integrity_failure") or {}).get("missing_artifacts") or [])
                with self.assertRaises(ApiServiceError) as ctx_ma:
                    TriageApiService(cfg_ma).resolve_scan(sid_ma)
                self.assertEqual(ctx_ma.exception.http_status, 409)
            finally:
                mgr_ma.shutdown(wait=True)


if __name__ == "__main__":
    unittest.main()
