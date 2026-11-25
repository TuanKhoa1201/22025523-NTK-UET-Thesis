"""Regression & counterexample suite for Java flow-dependency slicing and citation status decoupling.

Covers four mandatory verification groups without fixture-name hardcoding:
- Group A (No false downgrade): independent DB connection helpers, disjoint helpers, and
  JavaVulnerableLab-equivalent CWE-89 & CWE-22 patterns remain SUPPORTED + MATCHED.
- Group B (Must stay fail-closed): unverified helpers returning sink/guard values, sanitizing/
  transforming or receiving tainted arguments, mutating nonlocal flow state, running post-sink
  inside enclosing loops, and `Demo3ExternalHelperUndetermined.java` fail closed to UNDETERMINED.
- Group C (Citation integrity): valid citations stay MATCHED even when Gate 1 / Gate 2 downgrades
  validated_status to UNDETERMINED; wrong line, wrong quote (including irregular whitespace),
  wrong SHA-256, empty citations, and forged MATCHED flags all fail closed with INVALID_CITATION.
- Group D (System contracts): no auto-deletion of warnings, SQLite/JSONL/API consistency,
  Human Review & source drift (`STALE_SOURCE` 409) preserved, raw HTTP capture verified complete,
  and finding ID / source hash mappings unchanged.
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest

from v2.api.config import ApiConfig
from v2.api.java_context_v2 import analyze_flow_dependencies, enrich_bundle_context
from v2.api.qwen_triage import run_bounded_triage
from v2.api.service import ApiServiceError, TriageApiService
from v2.api.triage_gate import apply_integration_gate
from v2.triage import verify_http_capture
from v2.triage.evidence import EvidenceError, collect, digest
from v2.triage.ollama import DEFAULT_PROMPT_CONTRACT, prompt as build_prompt, validate_answer


REPO_ROOT = Path(__file__).resolve().parents[3]
DEMO3_FIXTURE_PATH = REPO_ROOT / "v2" / "g1_integration" / "demo_fixtures" / "Demo3ExternalHelperUndetermined.java"


def _build_record(
    tmp_root: Path,
    files: dict[str, str],
    *,
    primary_rel: str,
    cwe: str,
    sink_needle: str,
    source_needle: str | None = None,
    rule_id: str | None = None,
) -> tuple[dict, Path]:
    """Write Java file(s) to disk, collect evidence via sealed `collect()`, and enrich with `java_context_v2`."""
    src_root = tmp_root / "src"
    src_root.mkdir(parents=True, exist_ok=True)
    for rel, content in files.items():
        dst = src_root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(content, encoding="utf-8", newline="\n")

    primary_file = src_root / primary_rel
    raw_text = primary_file.read_text(encoding="utf-8")
    lines = raw_text.splitlines(keepends=True)

    def _find_loc(needle: str) -> dict:
        for idx, raw_ln in enumerate(lines, start=1):
            stripped = raw_ln.rstrip("\r\n")
            if needle in stripped:
                col0 = stripped.index(needle)
                prefix_bytes = sum(len(x.encode("utf-8")) for x in lines[: idx - 1])
                start_off = prefix_bytes + len(stripped[:col0].encode("utf-8"))
                end_off = start_off + len(needle.encode("utf-8"))
                return {
                    "path": primary_rel,
                    "start": {"line": idx, "col": len(stripped[:col0].encode("utf-8")) + 1, "offset": start_off},
                    "end": {"line": idx, "col": len(stripped[: col0 + len(needle)].encode("utf-8")) + 1, "offset": end_off},
                }
        raise AssertionError(f"Needle {needle!r} not found in {primary_rel}")

    sink_loc = _find_loc(sink_needle)
    extra: dict = {
        "severity": "ERROR",
        "message": f"[{cwe}] synthetic regression finding",
        "metadata": {"cwe": [cwe]},
    }
    if source_needle is not None:
        src_loc = _find_loc(source_needle)
        extra["dataflow_trace"] = {
            "taint_source": ["CliLoc", [src_loc, source_needle]],
            "intermediate_vars": [],
            "taint_sink": ["CliLoc", [sink_loc, sink_needle]],
        }

    og_doc = {
        "version": "1.25.0",
        "results": [
            {
                "check_id": rule_id or f"test.{cwe.lower()}",
                "path": primary_rel,
                "start": sink_loc["start"],
                "end": sink_loc["end"],
                "extra": extra,
            }
        ],
        "errors": [],
        "paths": {"scanned": list(files.keys()), "skipped": []},
    }
    source_hashes = {
        rel: digest((src_root / rel).read_bytes())
        for rel in files
    }
    provenance = {
        "origin": "unit_test_local_capture",
        "source_capture_verified": True,
        "exit_capture_verified": True,
        "recorded_engine_exit": 0,
        "source_hashes": source_hashes,
    }
    bundle = collect(json.dumps(og_doc), src_root, engine_exit=0, scan_provenance=provenance)
    enrich_bundle_context(bundle, src_root)
    return bundle["records"][0], src_root


def _validated_model_answer(
    record: dict,
    *,
    status: str = "SUPPORTED",
    cite_lines: list[int] | None = None,
    explanation: str = "Dữ liệu đầu vào đi tới sink mà không có bộ lọc hợp lệ.",
    fix_suggestion: str = "Sử dụng truy vấn tham số hóa hoặc kiểm tra đường dẫn canonical.",
) -> dict:
    """Build a realistic JSON response and pass it through sealed `validate_answer()`."""
    primary = record["snippets"][0]
    p_path = primary["path"]
    p_sha = primary["sha256"]
    lmap = {ln["line"]: ln["text"] for ln in primary["lines"]}
    target_lines = cite_lines or [record["start"]["line"]]
    cites = [
        {
            "path": p_path,
            "start_line": ln,
            "end_line": ln,
            "quote": lmap[ln],
            "sha256": p_sha,
        }
        for ln in target_lines
    ]
    payload = json.dumps(
        {
            "status": status,
            "explanation": explanation,
            "fix_suggestion": fix_suggestion,
            "citations": cites,
        },
        ensure_ascii=False,
    )
    return validate_answer(payload, record)


class _LoopbackOllamaStub:
    """Minimal real loopback HTTP server simulating Ollama /api/tags and /api/chat."""

    def __init__(self, responder):
        self.responder = responder
        self.model = "qwen3.5:9b-q4_K_M"
        self.chat_calls = 0
        outer = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                return

            def do_GET(self):
                if self.path == "/api/tags":
                    body = json.dumps(
                        {"models": [{"name": outer.model, "digest": "a" * 64, "size": 1024}]}
                    ).encode("utf-8")
                else:
                    body = json.dumps({"models": []}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                outer.chat_calls += 1
                length = int(self.headers.get("Content-Length", "0"))
                req_doc = json.loads(self.rfile.read(length).decode("utf-8"))
                content_obj = outer.responder(req_doc, outer.chat_calls)
                content_str = (
                    content_obj if isinstance(content_obj, str) else json.dumps(content_obj, ensure_ascii=False)
                )
                resp_doc = {
                    "model": outer.model,
                    "done": True,
                    "done_reason": "stop",
                    "eval_count": 42,
                    "eval_duration": 10_000_000,
                    "message": {"role": "assistant", "content": content_str},
                }
                body = json.dumps(resp_doc, ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)

    @property
    def endpoint(self) -> str:
        host, port = self._srv.server_address[:2]
        return f"http://{host}:{port}"

    def __enter__(self) -> "_LoopbackOllamaStub":
        self._thread.start()
        return self

    def __exit__(self, *_exc) -> None:
        self._srv.shutdown()
        self._thread.join(timeout=2.0)
        self._srv.server_close()


class GroupANoFalseDowngradeTests(unittest.TestCase):
    """Nhóm A: Independent helpers & JavaVulnerableLab-equivalent flows MUST NOT be falsely downgraded."""

    def test_independent_db_connection_factory_chained_and_two_step_stay_supported(self) -> None:
        chained_java = (
            "package app.web;\n"
            "import java.io.IOException;\n"
            "import java.sql.Connection;\n"
            "import java.sql.ResultSet;\n"
            "import java.sql.Statement;\n"
            "import javax.servlet.http.HttpServlet;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "import javax.servlet.http.HttpServletResponse;\n"
            "import app.infra.PoolProvider;\n"
            "public class AccountLookupServlet extends HttpServlet {\n"
            "    protected void processRequest(HttpServletRequest request, HttpServletResponse response) throws IOException {\n"
            "        try {\n"
            '            Connection con = new PoolProvider().open(getServletContext().getRealPath("/WEB-INF/db.cfg"));\n'
            '            String mail = request.getParameter("mail").trim();\n'
            "            if (con != null && !con.isClosed()) {\n"
            "                Statement stmt = con.createStatement();\n"
            '                ResultSet rs = stmt.executeQuery("SELECT * FROM accounts WHERE mail=\'" + mail + "\'");\n'
            "                if (rs.next()) { response.getWriter().print(rs.getString(1)); }\n"
            "            }\n"
            "        } catch (Exception ex) {\n"
            "            response.getWriter().print(ex.getMessage());\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        two_step_java = chained_java.replace(
            'Connection con = new PoolProvider().open(getServletContext().getRealPath("/WEB-INF/db.cfg"));',
            'PoolProvider pf = new PoolProvider();\n            Connection con = pf.open("/etc/db.cfg");',
        )
        for label, src in (("chained", chained_java), ("two_step", two_step_java)):
            with self.subTest(variant=label), tempfile.TemporaryDirectory() as td:
                rec, _ = _build_record(
                    Path(td),
                    {"AccountLookupServlet.java": src},
                    primary_rel="AccountLookupServlet.java",
                    cwe="CWE-89",
                    source_needle='request.getParameter("mail")',
                    sink_needle='stmt.executeQuery("SELECT * FROM accounts WHERE mail=\'" + mail + "\'")',
                )
                dep = analyze_flow_dependencies(rec)
                self.assertFalse(dep["has_unverified_helper_dependency"], dep)
                self.assertEqual(dep["unverified_decisive_calls"], [])
                self.assertTrue(
                    any(c["method"] == "open" and c["reason"] == "disjoint_from_sink_and_taint_flow" for c in dep["non_decisive_unresolved_calls"]),
                    dep["non_decisive_unresolved_calls"],
                )
                ans = _validated_model_answer(rec, status="SUPPORTED")
                gated = apply_integration_gate(rec, ans)
                self.assertEqual(gated["validated_status"], "SUPPORTED", gated)
                self.assertFalse(gated["validator_downgraded"])
                self.assertEqual(gated["citation_check"], "MATCHED")

    def test_helper_disjoint_from_taint_and_post_sink_non_loop_call_stay_supported(self) -> None:
        java = (
            "package app.web;\n"
            "import java.sql.Connection;\n"
            "import java.sql.DriverManager;\n"
            "import java.sql.ResultSet;\n"
            "import java.sql.Statement;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "import app.telemetry.Metrics;\n"
            "import app.telemetry.TraceIds;\n"
            "import app.auth.TokenSigner;\n"
            "public class DisjointHelpersCtrl {\n"
            "    public String lookup(HttpServletRequest req) throws Exception {\n"
            '        Metrics.tick("lookup_start");\n'
            "        String traceId = TraceIds.nextId();\n"
            '        String user = req.getParameter("user").trim();\n'
            '        Connection con = DriverManager.getConnection("jdbc:h2:mem:test");\n'
            "        Statement stmt = con.createStatement();\n"
            '        ResultSet rs = stmt.executeQuery("SELECT id FROM users WHERE name=\'" + user + "\'");\n'
            "        if (rs != null && rs.next()) {\n"
            "            return TokenSigner.sign(user, traceId);\n"
            "        }\n"
            '        return "";\n'
            "    }\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as td:
            rec, _ = _build_record(
                Path(td),
                {"DisjointHelpersCtrl.java": java},
                primary_rel="DisjointHelpersCtrl.java",
                cwe="CWE-89",
                source_needle='req.getParameter("user")',
                sink_needle='stmt.executeQuery("SELECT id FROM users WHERE name=\'" + user + "\'")',
            )
            dep = analyze_flow_dependencies(rec)
            self.assertFalse(dep["has_unverified_helper_dependency"], dep)
            non_dec = {(c["method"], c["reason"]) for c in dep["non_decisive_unresolved_calls"]}
            self.assertIn(("tick", "disjoint_from_sink_and_taint_flow"), non_dec)
            self.assertIn(("nextId", "disjoint_from_sink_and_taint_flow"), non_dec)
            self.assertIn(("sign", "post_sink_non_loop"), non_dec)
            gated = apply_integration_gate(rec, _validated_model_answer(rec, status="SUPPORTED"))
            self.assertEqual(gated["validated_status"], "SUPPORTED")
            self.assertEqual(gated["citation_check"], "MATCHED")

    def test_independent_db_connection_with_prepared_statement_has_no_false_dependency(self) -> None:
        java = (
            "package app.web;\n"
            "import java.sql.Connection;\n"
            "import java.sql.PreparedStatement;\n"
            "import java.sql.ResultSet;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "import app.infra.PoolProvider;\n"
            "public class SafePreparedCtrl {\n"
            "    public boolean exists(HttpServletRequest req) throws Exception {\n"
            '        Connection con = new PoolProvider().open("/etc/db.cfg");\n'
            '        String email = req.getParameter("email");\n'
            "        if (con != null && !con.isClosed()) {\n"
            '            PreparedStatement ps = con.prepareStatement("SELECT 1 FROM users WHERE email = ?");\n'
            "            ps.setString(1, email);\n"
            "            ResultSet rs = ps.executeQuery();\n"
            "            return rs.next();\n"
            "        }\n"
            "        return false;\n"
            "    }\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as td:
            rec, _ = _build_record(
                Path(td),
                {"SafePreparedCtrl.java": java},
                primary_rel="SafePreparedCtrl.java",
                cwe="CWE-89",
                source_needle='req.getParameter("email")',
                sink_needle="ps.executeQuery()",
            )
            dep = analyze_flow_dependencies(rec)
            self.assertFalse(dep["has_unverified_helper_dependency"], dep)

    def test_javavulnerablelab_equivalent_sqli_and_cwe22_patterns_pass_gate(self) -> None:
        # 1. EmailCheck / UsernameCheck pattern (JSONObject + Connection factory + liveness guard + post-sink json.put)
        check_java = (
            "package sample.ctrl;\n"
            "import java.io.IOException;\n"
            "import java.io.PrintWriter;\n"
            "import java.sql.Connection;\n"
            "import java.sql.ResultSet;\n"
            "import java.sql.Statement;\n"
            "import javax.servlet.http.HttpServlet;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "import javax.servlet.http.HttpServletResponse;\n"
            "import org.json.JSONObject;\n"
            "import sample.model.ConnHelper;\n"
            "public class MailCheckCtrl extends HttpServlet {\n"
            "    protected void processRequest(HttpServletRequest request, HttpServletResponse response) throws IOException {\n"
            "        PrintWriter out = response.getWriter();\n"
            "        try {\n"
            '            Connection con = new ConnHelper().connect(getServletContext().getRealPath("/WEB-INF/config.properties"));\n'
            '            String email = request.getParameter("email").trim();\n'
            "            JSONObject json = new JSONObject();\n"
            "            if (con != null && !con.isClosed()) {\n"
            "                Statement stmt = con.createStatement();\n"
            '                ResultSet rs = stmt.executeQuery("select * from users where email=\'" + email + "\'");\n'
            "                if (rs.next()) {\n"
            '                    json.put("available", "1");\n'
            "                } else {\n"
            '                    json.put("available", "0");\n'
            "                }\n"
            "            }\n"
            "            out.print(json);\n"
            "        } catch (Exception e) {\n"
            "            out.print(e);\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        # 2. Register dual-sink pattern (executeUpdate x2)
        register_java = (
            "package sample.ctrl;\n"
            "import java.io.IOException;\n"
            "import java.sql.Connection;\n"
            "import java.sql.Statement;\n"
            "import javax.servlet.http.HttpServlet;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "import javax.servlet.http.HttpServletResponse;\n"
            "import sample.model.ConnHelper;\n"
            "public class SignupCtrl extends HttpServlet {\n"
            "    protected void processRequest(HttpServletRequest request, HttpServletResponse response) throws IOException {\n"
            "        try {\n"
            '            Connection con = new ConnHelper().connect(getServletContext().getRealPath("/WEB-INF/config.properties"));\n'
            '            String user = request.getParameter("username");\n'
            '            String email = request.getParameter("email");\n'
            "            if (con != null && !con.isClosed()) {\n"
            "                Statement stmt = con.createStatement();\n"
            '                stmt.executeUpdate("INSERT INTO users(username, email) VALUES (\'" + user + "\',\'" + email + "\')");\n'
            '                stmt.executeUpdate("INSERT INTO audit(username) VALUES (\'" + user + "\')");\n'
            "            }\n"
            "        } catch (Exception ex) {\n"
            "            response.getWriter().print(ex);\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        # 3. AddPage CWE-22 pattern (f.delete(), f.createNewFile(), new BufferedWriter(new FileWriter(f.getAbsoluteFile())))
        addpage_java = (
            "package sample.ctrl;\n"
            "import java.io.BufferedWriter;\n"
            "import java.io.File;\n"
            "import java.io.FileWriter;\n"
            "import java.io.IOException;\n"
            "import javax.servlet.http.HttpServlet;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "import javax.servlet.http.HttpServletResponse;\n"
            "public class PageWriterCtrl extends HttpServlet {\n"
            "    protected void processRequest(HttpServletRequest request, HttpServletResponse response) throws IOException {\n"
            '        String fileName = request.getParameter("filename");\n'
            '        String content = request.getParameter("content");\n'
            '        File f = new File(getServletContext().getRealPath("/pages") + "/" + fileName);\n'
            "        if (f.exists()) {\n"
            "            f.delete();\n"
            "        }\n"
            "        if (f.createNewFile()) {\n"
            "            BufferedWriter bw = new BufferedWriter(new FileWriter(f.getAbsoluteFile()));\n"
            "            bw.write(content);\n"
            "            bw.close();\n"
            "        }\n"
            "    }\n"
            "}\n"
        )

        cases = [
            ("MailCheckCtrl.java", check_java, "CWE-89", 'request.getParameter("email")', 'stmt.executeQuery("select * from users where email=\'" + email + "\'")'),
            ("SignupCtrl.java", register_java, "CWE-89", 'request.getParameter("username")', 'stmt.executeUpdate("INSERT INTO users(username, email) VALUES (\'" + user + "\',\'" + email + "\')")'),
            ("SignupCtrl.java", register_java, "CWE-89", 'request.getParameter("username")', 'stmt.executeUpdate("INSERT INTO audit(username) VALUES (\'" + user + "\')")'),
            ("PageWriterCtrl.java", addpage_java, "CWE-22", 'request.getParameter("filename")', "f.delete();"),
            ("PageWriterCtrl.java", addpage_java, "CWE-22", 'request.getParameter("filename")', "if (f.createNewFile())"),
            ("PageWriterCtrl.java", addpage_java, "CWE-22", 'request.getParameter("filename")', "BufferedWriter bw = new BufferedWriter(new FileWriter(f.getAbsoluteFile()));"),
        ]
        for fname, src, cwe, s_src, s_sink in cases:
            with self.subTest(file=fname, sink=s_sink), tempfile.TemporaryDirectory() as td:
                rec, _ = _build_record(
                    Path(td),
                    {fname: src},
                    primary_rel=fname,
                    cwe=cwe,
                    source_needle=s_src,
                    sink_needle=s_sink,
                )
                dep = analyze_flow_dependencies(rec)
                self.assertFalse(dep["has_unverified_helper_dependency"], dep)
                gated = apply_integration_gate(rec, _validated_model_answer(rec, status="SUPPORTED"))
                self.assertEqual(gated["validated_status"], "SUPPORTED", gated)
                self.assertEqual(gated["citation_check"], "MATCHED")


class GroupBMustFailClosedTests(unittest.TestCase):
    """Nhóm B: Any unverified helper that can alter, sanitize, forward, or guard the flow MUST fail closed."""

    def _assert_fails_closed_with_matched_citation(
        self,
        files: dict[str, str],
        *,
        primary_rel: str,
        cwe: str,
        sink_needle: str,
        source_needle: str | None = None,
    ) -> dict:
        with tempfile.TemporaryDirectory() as td:
            rec, _ = _build_record(
                Path(td),
                files,
                primary_rel=primary_rel,
                cwe=cwe,
                source_needle=source_needle,
                sink_needle=sink_needle,
            )
            dep = analyze_flow_dependencies(rec)
            self.assertTrue(dep["has_unverified_helper_dependency"], f"Expected fail-closed, got: {dep}")
            ans = _validated_model_answer(rec, status="SUPPORTED")
            gated = apply_integration_gate(rec, ans)
            self.assertEqual(gated["validated_status"], "UNDETERMINED", gated)
            self.assertEqual(gated["failure_kind"], "UNVERIFIED_HELPER_FLOW")
            self.assertTrue(gated["validator_downgraded"])
            self.assertEqual(gated["raw_model_status"], "SUPPORTED")
            # Lỗi B invariant: verified verbatim citation MUST remain MATCHED on UNVERIFIED_HELPER_FLOW downgrade
            self.assertEqual(gated["citation_check"], "MATCHED")
            self.assertTrue(gated["citation_provenance"]["citation_in_source"])
            self.assertFalse(gated["security_conclusion_verified"])
            self.assertTrue(gated["requires_human_review"])
            return gated

    def test_unverified_helper_returning_value_used_in_sink_fails_closed(self) -> None:
        # Both static helper returning sink component AND 0-arg custom constructor returning query object
        java_helper = (
            "package app;\n"
            "import java.sql.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "import app.ext.ConfigRepo;\n"
            "public class DynamicTableCtrl {\n"
            "    public void run(HttpServletRequest req, Connection con) throws Exception {\n"
            '        String id = req.getParameter("id");\n'
            "        String table = ConfigRepo.resolveTable();\n"
            "        Statement stmt = con.createStatement();\n"
            '        stmt.executeQuery("SELECT * FROM " + table + " WHERE id=\'" + id + "\'");\n'
            "    }\n"
            "}\n"
        )
        self._assert_fails_closed_with_matched_citation(
            {"DynamicTableCtrl.java": java_helper},
            primary_rel="DynamicTableCtrl.java",
            cwe="CWE-89",
            source_needle='req.getParameter("id")',
            sink_needle='stmt.executeQuery("SELECT * FROM " + table + " WHERE id=\'" + id + "\'")',
        )

        java_ctor = (
            "package app;\n"
            "import java.sql.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "import app.ext.CustomQuery;\n"
            "public class CustomCtorCtrl {\n"
            "    public void run(HttpServletRequest req, Connection con) throws Exception {\n"
            '        String id = req.getParameter("id");\n'
            "        CustomQuery q = new CustomQuery();\n"
            "        Statement stmt = con.createStatement();\n"
            "        stmt.executeQuery(q.toString() + id);\n"
            "    }\n"
            "}\n"
        )
        self._assert_fails_closed_with_matched_citation(
            {"CustomCtorCtrl.java": java_ctor},
            primary_rel="CustomCtorCtrl.java",
            cwe="CWE-89",
            source_needle='req.getParameter("id")',
            sink_needle="stmt.executeQuery(q.toString() + id)",
        )

    def test_unverified_sanitizer_transformer_void_validator_and_ctor_fail_closed(self) -> None:
        variants = {
            "returning_sanitizer": (
                "package app;\n"
                "import java.sql.*;\n"
                "import javax.servlet.http.HttpServletRequest;\n"
                "import app.sec.InputPolicy;\n"
                "public class CleanReturnCtrl {\n"
                "    public void run(HttpServletRequest req, Connection con) throws Exception {\n"
                '        String email = req.getParameter("email");\n'
                "        String safe = InputPolicy.clean(email);\n"
                "        Statement stmt = con.createStatement();\n"
                '        stmt.executeQuery("SELECT * FROM u WHERE e=\'" + safe + "\'");\n'
                "    }\n"
                "}\n",
                'stmt.executeQuery("SELECT * FROM u WHERE e=\'" + safe + "\'")',
            ),
            "void_throw_validator": (
                "package app;\n"
                "import java.sql.*;\n"
                "import javax.servlet.http.HttpServletRequest;\n"
                "import app.sec.InputPolicy;\n"
                "public class VoidValidatorCtrl {\n"
                "    public void run(HttpServletRequest req, Connection con) throws Exception {\n"
                '        String email = req.getParameter("email");\n'
                "        InputPolicy.assertSafe(email);\n"
                "        Statement stmt = con.createStatement();\n"
                '        stmt.executeQuery("SELECT * FROM u WHERE e=\'" + email + "\'");\n'
                "    }\n"
                "}\n",
                'stmt.executeQuery("SELECT * FROM u WHERE e=\'" + email + "\'")',
            ),
            "taint_receiving_ctor": (
                "package app;\n"
                "import java.sql.*;\n"
                "import javax.servlet.http.HttpServletRequest;\n"
                "import app.sec.InputPolicy;\n"
                "public class CtorValidatorCtrl {\n"
                "    public void run(HttpServletRequest req, Connection con) throws Exception {\n"
                '        String email = req.getParameter("email");\n'
                "        new InputPolicy(email);\n"
                "        Statement stmt = con.createStatement();\n"
                '        stmt.executeQuery("SELECT * FROM u WHERE e=\'" + email + "\'");\n'
                "    }\n"
                "}\n",
                'stmt.executeQuery("SELECT * FROM u WHERE e=\'" + email + "\'")',
            ),
        }
        for label, (src, sink) in variants.items():
            with self.subTest(variant=label):
                self._assert_fails_closed_with_matched_citation(
                    {"TestCtrl.java": src},
                    primary_rel="TestCtrl.java",
                    cwe="CWE-89",
                    source_needle='req.getParameter("email")',
                    sink_needle=sink,
                )

    def test_helper_forwarding_tainted_arg_or_request_or_non_jdbc_conn_fails_closed(self) -> None:
        base = (
            "package app;\n"
            "import java.sql.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "import app.infra.PoolProvider;\n"
            "public class ConnForwardCtrl {\n"
            "    public void run(HttpServletRequest req) throws Exception {\n"
            '        String email = req.getParameter("email");\n'
            "        {CONN_LINE}\n"
            "        if (con != null) {\n"
            "            Statement stmt = con.createStatement();\n"
            '            stmt.executeQuery("SELECT * FROM u WHERE e=\'" + email + "\'");\n'
            "        }\n"
            "    }\n"
            "}\n"
        )
        variants = {
            "arg_tainted_var": "Connection con = new PoolProvider().open(email);",
            "ctor_tainted_var": 'Connection con = new PoolProvider(email).open("/cfg");',
            "arg_http_request": "Connection con = new PoolProvider().openForRequest(req);",
            "custom_non_stdlib_conn": 'CustomSqlConn con = new PoolProvider().open("/cfg");',
        }
        for label, conn_line in variants.items():
            with self.subTest(variant=label):
                self._assert_fails_closed_with_matched_citation(
                    {"ConnForwardCtrl.java": base.replace("{CONN_LINE}", conn_line)},
                    primary_rel="ConnForwardCtrl.java",
                    cwe="CWE-89",
                    source_needle='req.getParameter("email")',
                    sink_needle='stmt.executeQuery("SELECT * FROM u WHERE e=\'" + email + "\'")',
                )

    def test_governing_guard_mutable_nonlocal_and_loop_carried_helper_fail_closed(self) -> None:
        guard_java = (
            "package app;\n"
            "import java.sql.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "import app.sec.PolicyGate;\n"
            "public class GuardedCtrl {\n"
            "    public void run(HttpServletRequest req, Connection con) throws Exception {\n"
            '        String email = req.getParameter("email");\n'
            "        boolean ok = PolicyGate.allow();\n"
            "        if (!ok) { return; }\n"
            "        Statement stmt = con.createStatement();\n"
            '        stmt.executeQuery("SELECT * FROM u WHERE e=\'" + email + "\'");\n'
            "    }\n"
            "}\n"
        )
        compound_guard_java = (
            "package app;\n"
            "import java.sql.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "import app.sec.PolicyGate;\n"
            "public class CompoundGuardCtrl {\n"
            "    public void run(HttpServletRequest req, Connection con) throws Exception {\n"
            '        String email = req.getParameter("email");\n'
            "        if (con != null && PolicyGate.allow()) {\n"
            "            Statement stmt = con.createStatement();\n"
            '            stmt.executeQuery("SELECT * FROM u WHERE e=\'" + email + "\'");\n'
            "        }\n"
            "    }\n"
            "}\n"
        )
        mutable_field_java = (
            "package app;\n"
            "import java.sql.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "import app.sec.ExternalCleaner;\n"
            "public class MutableFieldCtrl {\n"
            "    private String curEmail;\n"
            "    public void run(HttpServletRequest req, Connection con) throws Exception {\n"
            '        this.curEmail = req.getParameter("email");\n'
            "        ExternalCleaner.reset();\n"
            "        Statement stmt = con.createStatement();\n"
            '        stmt.executeQuery("SELECT * FROM u WHERE e=\'" + this.curEmail + "\'");\n'
            "    }\n"
            "}\n"
        )
        loop_post_sink_java = (
            "package app;\n"
            "import java.sql.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "import app.sec.ExternalStep;\n"
            "public class LoopCarriedCtrl {\n"
            "    public void run(HttpServletRequest req, Connection con) throws Exception {\n"
            '        String email = req.getParameter("email");\n'
            "        Statement stmt = con.createStatement();\n"
            "        for (int i = 0; i < 3; i++) {\n"
            '            stmt.executeQuery("SELECT * FROM u WHERE e=\'" + email + "\'");\n'
            "            email = ExternalStep.next(email);\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        for label, fname, src, sink in (
            ("governing_guard_var", "GuardedCtrl.java", guard_java, 'stmt.executeQuery("SELECT * FROM u WHERE e=\'" + email + "\'")'),
            ("compound_guard_call", "CompoundGuardCtrl.java", compound_guard_java, 'stmt.executeQuery("SELECT * FROM u WHERE e=\'" + email + "\'")'),
            ("mutable_nonlocal_field", "MutableFieldCtrl.java", mutable_field_java, 'stmt.executeQuery("SELECT * FROM u WHERE e=\'" + this.curEmail + "\'")'),
            ("loop_carried_post_sink", "LoopCarriedCtrl.java", loop_post_sink_java, 'stmt.executeQuery("SELECT * FROM u WHERE e=\'" + email + "\'")'),
        ):
            with self.subTest(variant=label):
                self._assert_fails_closed_with_matched_citation(
                    {fname: src},
                    primary_rel=fname,
                    cwe="CWE-89",
                    source_needle='req.getParameter("email")',
                    sink_needle=sink,
                )

    def test_demo3_external_helper_fixture_remains_undetermined_and_preserves_matched_citation(self) -> None:
        self.assertTrue(DEMO3_FIXTURE_PATH.is_file(), f"Missing fixture: {DEMO3_FIXTURE_PATH}")
        demo3_text = DEMO3_FIXTURE_PATH.read_text(encoding="utf-8")
        gated = self._assert_fails_closed_with_matched_citation(
            {"Demo3ExternalHelperUndetermined.java": demo3_text},
            primary_rel="Demo3ExternalHelperUndetermined.java",
            cwe="CWE-22",
            source_needle='req.getParameter("docId")',
            sink_needle="return new FileInputStream(delegatedPath);",
        )
        self.assertEqual(len(gated["citations"]), 1)
        self.assertEqual(gated["citations"][0]["path"], "Demo3ExternalHelperUndetermined.java")
        self.assertEqual(gated["citation_check"], "MATCHED")


class GroupCCitationIntegrityTests(unittest.TestCase):
    """Nhóm C: Strict citation verification and separation from helper/refutation downgrades."""

    def _make_sample_record(self, tmp_root: Path, *, with_external_helper: bool = False) -> dict:
        helper_line = "        String clean = ExternalSanitizer.clean(fileName);\n" if with_external_helper else ""
        target_var = "clean" if with_external_helper else "fileName"
        # Intentionally include irregular leading spaces (11 / 12 / 16 spaces) like AddPage.java
        java = (
            "package sample.web;\n"
            "import java.io.File;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class IrregularIndentCtrl {\n"
            "    public void write(HttpServletRequest request) throws Exception {\n"
            '           String fileName = request.getParameter("filename");\n'
            f"{helper_line}"
            '            File f = new File("/var/pages/" + ' + target_var + ");\n"
            "            if (f.exists()) {\n"
            "                f.delete();\n"
            "            }\n"
            "    }\n"
            "}\n"
        )
        rec, _ = _build_record(
            tmp_root,
            {"IrregularIndentCtrl.java": java},
            primary_rel="IrregularIndentCtrl.java",
            cwe="CWE-22",
            source_needle='request.getParameter("filename")',
            sink_needle="f.delete();",
        )
        return rec

    def test_valid_citation_stays_matched_on_supported_and_on_gate1_and_gate2_downgrades(self) -> None:
        # 1. SUPPORTED passes Gate 0 & Gate 1 -> MATCHED
        with tempfile.TemporaryDirectory() as td:
            rec = self._make_sample_record(Path(td), with_external_helper=False)
            ans_sup = _validated_model_answer(rec, status="SUPPORTED")
            gated_sup = apply_integration_gate(rec, ans_sup)
            self.assertEqual(gated_sup["validated_status"], "SUPPORTED")
            self.assertEqual(gated_sup["citation_check"], "MATCHED")

            # 2. REFUTED fails Gate 2 (no real sanitizer) -> UNDETERMINED + UNVERIFIED_REFUTATION, citation_check stays MATCHED!
            ref_java = (
                "package sample.web;\n"
                "import java.io.File;\n"
                "import java.io.FileInputStream;\n"
                "import javax.servlet.http.HttpServletRequest;\n"
                "public class UnsanitizedPathCtrl {\n"
                "    public FileInputStream open(HttpServletRequest request) throws Exception {\n"
                '        String fileName = request.getParameter("filename");\n'
                '        return new FileInputStream(new File("/var/pages", fileName));\n'
                "    }\n"
                "}\n"
            )
            with tempfile.TemporaryDirectory() as td_ref:
                rec_ref, _ = _build_record(
                    Path(td_ref),
                    {"UnsanitizedPathCtrl.java": ref_java},
                    primary_rel="UnsanitizedPathCtrl.java",
                    cwe="CWE-22",
                    source_needle='request.getParameter("filename")',
                    sink_needle='return new FileInputStream(new File("/var/pages", fileName));',
                )
                ans_ref = _validated_model_answer(rec_ref, status="REFUTED")
                gated_ref = apply_integration_gate(rec_ref, ans_ref)
                self.assertEqual(gated_ref["validated_status"], "UNDETERMINED")
                self.assertEqual(gated_ref["failure_kind"], "UNVERIFIED_REFUTATION")
                self.assertEqual(gated_ref["citation_check"], "MATCHED")
                self.assertEqual(len(gated_ref["citations"]), 1)
                self.assertFalse(gated_ref["security_conclusion_verified"])
                self.assertFalse(gated_ref["citation_provenance"]["supports_security_claim_verified"])

        # 3. SUPPORTED fails Gate 1 (external helper) -> UNDETERMINED + UNVERIFIED_HELPER_FLOW, citation_check stays MATCHED!
        with tempfile.TemporaryDirectory() as td:
            rec_h = self._make_sample_record(Path(td), with_external_helper=True)
            ans_h = _validated_model_answer(rec_h, status="SUPPORTED")
            gated_h = apply_integration_gate(rec_h, ans_h)
            self.assertEqual(gated_h["validated_status"], "UNDETERMINED")
            self.assertEqual(gated_h["failure_kind"], "UNVERIFIED_HELPER_FLOW")
            self.assertEqual(gated_h["citation_check"], "MATCHED")
            self.assertEqual(len(gated_h["citations"]), 1)

    def test_wrong_line_wrong_quote_irregular_whitespace_wrong_sha_and_empty_citations_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            rec = self._make_sample_record(Path(td), with_external_helper=False)
            primary = rec["snippets"][0]
            p_path = primary["path"]
            p_sha = primary["sha256"]
            sink_ln = rec["start"]["line"]
            lmap = {ln["line"]: ln["text"] for ln in primary["lines"]}
            exact_sink_quote = lmap[sink_ln]
            self.assertTrue(exact_sink_quote.startswith(" " * 16), repr(exact_sink_quote))

            bad_cases = {
                "wrong_line_number": [
                    {"path": p_path, "start_line": sink_ln - 1, "end_line": sink_ln - 1, "quote": exact_sink_quote, "sha256": p_sha}
                ],
                "wrong_quote_text": [
                    {"path": p_path, "start_line": sink_ln, "end_line": sink_ln, "quote": "                f.createNewFile();", "sha256": p_sha}
                ],
                "wrong_leading_whitespace_12_vs_16_spaces": [
                    {"path": p_path, "start_line": sink_ln, "end_line": sink_ln, "quote": "            f.delete();", "sha256": p_sha}
                ],
                "stripped_whitespace_quote": [
                    {"path": p_path, "start_line": sink_ln, "end_line": sink_ln, "quote": exact_sink_quote.strip(), "sha256": p_sha}
                ],
                "wrong_source_sha256": [
                    {"path": p_path, "start_line": sink_ln, "end_line": sink_ln, "quote": exact_sink_quote, "sha256": "0" * 64}
                ],
                "empty_citations_on_conclusive_verdict": [],
            }

            for label, bad_cites in bad_cases.items():
                with self.subTest(case=label):
                    raw_payload = json.dumps(
                        {
                            "status": "SUPPORTED",
                            "explanation": "Kết luận dứt khoát với trích dẫn sai/thiếu.",
                            "fix_suggestion": "Kiểm tra đường dẫn canonical.",
                            "citations": bad_cites,
                        },
                        ensure_ascii=False,
                    )
                    # 1. Sealed validate_answer MUST strictly reject (no whitespace relaxation)
                    with self.assertRaises(EvidenceError):
                        validate_answer(raw_payload, rec)

                    # 2. Direct apply_integration_gate (even with forged citation_check="MATCHED") MUST reject
                    forged = {
                        "status": "SUPPORTED",
                        "validated_status": "SUPPORTED",
                        "raw_model_status": "SUPPORTED",
                        "citation_check": "MATCHED",
                        "explanation": "Forged matched citation.",
                        "fix_suggestion": "Fix.",
                        "citations": bad_cites,
                    }
                    gated = apply_integration_gate(rec, forged)
                    self.assertEqual(gated["validated_status"], "UNDETERMINED", gated)
                    self.assertEqual(gated["failure_kind"], "INVALID_CITATION", gated)
                    self.assertEqual(gated["citation_check"], "NOT_VERIFIED", gated)
                    self.assertEqual(gated["citations"], [])
                    self.assertTrue(gated["validator_downgraded"])


class GroupDSystemContractsTests(unittest.TestCase):
    """Nhóm D: End-to-end contracts (no auto-delete, Human Review, source drift, raw HTTP capture, ID/hash mapping)."""

    def test_end_to_end_pipeline_preserves_contracts_human_review_drift_and_http_capture(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src_root = root / "repo"
            src_root.mkdir()
            rules_path = root / "rules.yml"
            rules_path.write_text("rules: []\n", encoding="utf-8")

            # Finding 1: Independent DB connection SQLi -> SUPPORTED + MATCHED
            f1_src = (
                "package demo;\n"
                "import java.sql.*;\n"
                "import javax.servlet.http.HttpServletRequest;\n"
                "import demo.db.PoolFactory;\n"
                "public class CleanSqliCtrl {\n"
                "    public void run(HttpServletRequest req) throws Exception {\n"
                '        Connection con = new PoolFactory().open("/cfg/db.properties");\n'
                '        String email = req.getParameter("email").trim();\n'
                "        if (con != null && !con.isClosed()) {\n"
                "            Statement stmt = con.createStatement();\n"
                '            stmt.executeQuery("SELECT * FROM users WHERE email=\'" + email + "\'");\n'
                "        }\n"
                "    }\n"
                "}\n"
            )
            # Finding 2: External decisive helper -> UNDETERMINED (UNVERIFIED_HELPER_FLOW) + MATCHED (Lỗi B!)
            f2_src = DEMO3_FIXTURE_PATH.read_text(encoding="utf-8")
            # Finding 3: Irregular whitespace CWE-22 -> model strips leading spaces -> UNDETERMINED (INVALID_CITATION) + NOT_VERIFIED
            f3_src = (
                "package demo;\n"
                "import java.io.File;\n"
                "import javax.servlet.http.HttpServletRequest;\n"
                "public class BadQuoteCtrl {\n"
                "    public void remove(HttpServletRequest req) {\n"
                '           String fname = req.getParameter("fname");\n'
                '            File f = new File("/srv/pages/" + fname);\n'
                "            if (f.exists()) {\n"
                "                f.delete();\n"
                "            }\n"
                "    }\n"
                "}\n"
            )

            file_map = {
                "CleanSqliCtrl.java": f1_src,
                "Demo3ExternalHelperUndetermined.java": f2_src,
                "BadQuoteCtrl.java": f3_src,
            }
            source_hashes: dict[str, str] = {}
            for rel, txt in file_map.items():
                p = src_root / rel
                p.write_text(txt, encoding="utf-8", newline="\n")
                source_hashes[rel] = digest(p.read_bytes())

            def _mk_result(rel: str, cwe: str, src_needle: str, sink_needle: str) -> dict:
                raw_lines = (src_root / rel).read_text(encoding="utf-8").splitlines(keepends=True)

                def _loc(needle: str) -> dict:
                    for idx, raw_ln in enumerate(raw_lines, start=1):
                        s = raw_ln.rstrip("\r\n")
                        if needle in s:
                            c0 = s.index(needle)
                            pb = sum(len(x.encode("utf-8")) for x in raw_lines[: idx - 1])
                            so = pb + len(s[:c0].encode("utf-8"))
                            eo = so + len(needle.encode("utf-8"))
                            return {
                                "path": rel,
                                "start": {"line": idx, "col": len(s[:c0].encode("utf-8")) + 1, "offset": so},
                                "end": {"line": idx, "col": len(s[: c0 + len(needle)].encode("utf-8")) + 1, "offset": eo},
                            }
                    raise AssertionError(needle)

                sloc = _loc(src_needle)
                kloc = _loc(sink_needle)
                return {
                    "check_id": f"test.{cwe.lower()}",
                    "path": rel,
                    "start": kloc["start"],
                    "end": kloc["end"],
                    "extra": {
                        "severity": "ERROR",
                        "message": f"[{cwe}] synthetic finding",
                        "metadata": {"cwe": [cwe]},
                        "dataflow_trace": {
                            "taint_source": ["CliLoc", [sloc, src_needle]],
                            "intermediate_vars": [],
                            "taint_sink": ["CliLoc", [kloc, sink_needle]],
                        },
                    },
                }

            og_doc = {
                "version": "1.25.0",
                "results": [
                    _mk_result(
                        "CleanSqliCtrl.java",
                        "CWE-89",
                        'req.getParameter("email")',
                        'stmt.executeQuery("SELECT * FROM users WHERE email=\'" + email + "\'")',
                    ),
                    _mk_result(
                        "Demo3ExternalHelperUndetermined.java",
                        "CWE-22",
                        'req.getParameter("docId")',
                        "return new FileInputStream(delegatedPath);",
                    ),
                    _mk_result(
                        "BadQuoteCtrl.java",
                        "CWE-22",
                        'req.getParameter("fname")',
                        "f.delete();",
                    ),
                ],
                "errors": [],
                "paths": {"scanned": list(file_map.keys()), "skipped": []},
            }

            scan_root = root / "scans"
            scan_dir = scan_root / "scan_01"
            cap_dir = scan_dir / "capture"
            triage_dir = scan_dir / "triage"
            cap_dir.mkdir(parents=True)

            og_bytes = json.dumps(og_doc, indent=2).encode("utf-8")
            sarif_doc = {
                "version": "2.1.0",
                "runs": [
                    {
                        "results": [
                            {
                                "ruleId": r["check_id"],
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": r["path"]},
                                            "region": {
                                                "startLine": r["start"]["line"],
                                                "endLine": r["end"]["line"],
                                                "startColumn": r["start"]["col"],
                                                "endColumn": r["end"]["col"],
                                            },
                                        }
                                    }
                                ],
                            }
                            for r in og_doc["results"]
                        ]
                    }
                ],
            }
            sarif_bytes = json.dumps(sarif_doc, indent=2).encode("utf-8")
            rules_bytes = rules_path.read_bytes()
            ver_cmd = ["opengrep", "--version"]
            json_cmd = ["opengrep", "scan", "--json", str(src_root)]
            sarif_cmd = ["opengrep", "scan", "--sarif", str(src_root)]
            extra_files = {
                "opengrep.json": og_bytes,
                "opengrep.sarif": sarif_bytes,
                "rules.snapshot.yml": rules_bytes,
                "version.exit.txt": b"0",
                "version.command.json": json.dumps(ver_cmd).encode("utf-8"),
                "json.exit.txt": b"0",
                "json.command.json": json.dumps(json_cmd).encode("utf-8"),
                "json.stdout.txt": og_bytes,
                "sarif.exit.txt": b"0",
                "sarif.command.json": json.dumps(sarif_cmd).encode("utf-8"),
                "sarif.stdout.txt": sarif_bytes,
            }
            artifacts: dict[str, str] = {}
            for fn, fb in extra_files.items():
                (cap_dir / fn).write_bytes(fb)
                artifacts[fn] = digest(fb)
            manifest_path = cap_dir / "scan-manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "schema": "ntk-scan-capture-1",
                        "producer": "unit_test_local_capture",
                        "success": True,
                        "issues": [],
                        "target_kind": "directory",
                        "sources_before": source_hashes,
                        "sources_after": source_hashes,
                        "rules_before_sha256": digest(rules_bytes),
                        "rules_after_sha256": digest(rules_bytes),
                        "artifacts": artifacts,
                        "runs": {
                            "version": {"argv": ver_cmd, "exit_code": 0},
                            "json": {"argv": json_cmd, "exit_code": 0, "output_mode": "stdout"},
                            "sarif": {"argv": sarif_cmd, "exit_code": 0, "output_mode": "stdout"},
                        },
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

            def _stub_qwen(req_doc: dict, _n: int) -> dict:
                ev = json.loads(req_doc["messages"][1]["content"])
                snip = ev["snippets"][0]
                sink_ln = ev["start"]["line"]
                quote = next(l["text"] for l in snip["lines"] if l["line"] == sink_ln)
                if snip["path"] == "BadQuoteCtrl.java":
                    # Simulate model stripping leading whitespace (like AddPage.java regression)
                    quote = quote.lstrip()
                return {
                    "status": "SUPPORTED",
                    "explanation": "Kiểm thử tích hợp luồng và trích dẫn.",
                    "fix_suggestion": "Áp dụng bộ lọc an toàn.",
                    "citations": [
                        {
                            "path": snip["path"],
                            "start_line": sink_ln,
                            "end_line": sink_ln,
                            "quote": quote,
                            "sha256": snip["sha256"],
                        }
                    ],
                }

            with _LoopbackOllamaStub(_stub_qwen) as stub:
                res = run_bounded_triage(
                    source_root=src_root,
                    triage_dir=triage_dir,
                    raw_json_path=cap_dir / "opengrep.json",
                    manifest_path=manifest_path,
                    path_maps=[],
                    rules_path=rules_path,
                    no_llm=False,
                    prompt_contract=DEFAULT_PROMPT_CONTRACT,
                    ollama_endpoint=stub.endpoint,
                    ollama_model=stub.model,
                    ollama_timeout_seconds=10.0,
                    runtime_origin="mock",
                    deadline_mono=time.monotonic() + 30.0,
                    enable_qwen_cache=False,
                )

            # 1. Verify finding IDs and source hashes are unchanged from sealed `collect()`
            expected_scan_sha = digest(og_bytes)
            self.assertEqual(res["bundle"]["scan_sha256"], expected_scan_sha)
            self.assertEqual(len(res["bundle"]["records"]), 3)
            expected_ids = [digest(f"{expected_scan_sha}:{i}".encode("utf-8")) for i in range(3)]

            # 2. Verify raw HTTP capture completeness & exact request/response byte integrity
            cap_report = verify_http_capture.verify_run_http_captures(triage_dir)
            self.assertTrue(cap_report["capture_integrity_ok"], cap_report)
            self.assertEqual(cap_report["errors"], [])

            # 3. Verify TriageApiService API parity (SQLite <-> assessments.jsonl <-> HTTP payloads)
            cfg = ApiConfig(
                data_dir=root / "api_data",
                reviewable_scan_dirs=(triage_dir,),
                rules_path=rules_path,
                runtime_origin="mock",
                opengrep_health_probe_enabled=False,
            )
            svc = TriageApiService(cfg)
            scan_summary = svc.build_scan_summary(svc.resolve_scan(expected_scan_sha))
            self.assertEqual(scan_summary["total_findings"], 3)
            self.assertEqual(scan_summary["by_human_review_state"]["OPEN"], 3)  # No auto-deletion!
            self.assertEqual(scan_summary["matched_citation_count"], 2)  # CleanSqli + Demo3!
            self.assertEqual(scan_summary["validator_downgraded_count"], 2)  # Demo3 + BadQuote!

            findings_list = svc.list_findings(expected_scan_sha)["findings"]
            self.assertEqual([f["finding_id"] for f in findings_list], expected_ids)
            by_file = {f["file_path"]: f for f in findings_list}

            # Finding 1: SUPPORTED + MATCHED + OPEN
            f1 = by_file["CleanSqliCtrl.java"]
            self.assertEqual(f1["validated_status"], "SUPPORTED")
            self.assertEqual(f1["citation_check"], "MATCHED")
            self.assertFalse(f1["validator_downgraded"])
            self.assertEqual(f1["human_review_state"], "OPEN")

            # Finding 2 (Demo3): UNDETERMINED + UNVERIFIED_HELPER_FLOW + MATCHED + OPEN
            f2 = by_file["Demo3ExternalHelperUndetermined.java"]
            self.assertEqual(f2["validated_status"], "UNDETERMINED")
            self.assertEqual(f2["raw_model_status"], "SUPPORTED")
            self.assertEqual(f2["failure_kind"], "UNVERIFIED_HELPER_FLOW")
            self.assertTrue(f2["validator_downgraded"])
            self.assertEqual(f2["citation_check"], "MATCHED")
            self.assertEqual(f2["human_review_state"], "OPEN")
            f2_detail = svc.get_finding_detail(expected_scan_sha, f2["finding_id"])
            self.assertEqual(f2_detail["citation_check"], "MATCHED")
            self.assertEqual(f2_detail["assessment"]["citation_check"], "MATCHED")
            self.assertEqual(len(f2_detail["assessment"]["citations"]), 1)
            self.assertTrue(f2_detail["assessment"]["citation_provenance"]["citation_in_source"])
            self.assertFalse(f2_detail["assessment"]["security_conclusion_verified"])
            self.assertFalse(f2_detail["assessment"]["supports_security_claim_verified"])
            self.assertEqual(
                f2_detail["evidence"]["snapshots"]["Demo3ExternalHelperUndetermined.java"]["sha256"],
                source_hashes["Demo3ExternalHelperUndetermined.java"],
            )

            # Finding 3 (BadQuote): UNDETERMINED + INVALID_CITATION + NOT_VERIFIED + OPEN
            f3 = by_file["BadQuoteCtrl.java"]
            self.assertEqual(f3["validated_status"], "UNDETERMINED")
            self.assertEqual(f3["failure_kind"], "INVALID_CITATION")
            self.assertEqual(f3["citation_check"], "NOT_VERIFIED")
            self.assertEqual(f3["human_review_state"], "OPEN")

            # 4. Human Review decisions work unchanged (`confirm-true`, `confirm-false`, `reopen`)
            d1 = svc.decide_finding(
                expected_scan_sha,
                f1["finding_id"],
                "confirm-true",
                "auditor",
                "Verified real SQLi.",
            )
            self.assertEqual(d1["human_review_state"], "CONFIRMED_TRUE")

            d2 = svc.decide_finding(
                expected_scan_sha,
                f2["finding_id"],
                "confirm-false",
                "auditor",
                "Confirmed external policy handles sanitization out-of-band.",
            )
            self.assertEqual(d2["human_review_state"], "CONFIRMED_FALSE")

            d2_reopen = svc.decide_finding(
                expected_scan_sha,
                f2["finding_id"],
                "reopen",
                "auditor",
                "Reopen for second review.",
            )
            self.assertEqual(d2_reopen["human_review_state"], "OPEN")

            # 5. Source drift triggers STALE_SOURCE (HTTP 409) and records rejected_decisions without mutating state
            (src_root / "BadQuoteCtrl.java").write_text(f3_src + "// drifted\n", encoding="utf-8", newline="\n")
            with self.assertRaises(ApiServiceError) as ctx:
                svc.decide_finding(
                    expected_scan_sha,
                    f3["finding_id"],
                    "confirm-false",
                    "auditor",
                    "Attempt on modified source.",
                )
            self.assertEqual(ctx.exception.http_status, 409)
            self.assertEqual(ctx.exception.error_code, "STALE_SOURCE")
            self.assertEqual(svc.get_finding_detail(expected_scan_sha, f3["finding_id"])["human_review_state"], "OPEN")

            conn = sqlite3.connect(str(triage_dir / "review.sqlite"))
            try:
                rej_count = conn.execute(
                    "SELECT COUNT(*) FROM rejected_decisions WHERE warning_id = ?",
                    (f3["finding_id"],),
                ).fetchone()[0]
            finally:
                conn.close()
            self.assertGreaterEqual(rej_count, 1)

            # 6. Report endpoint remains consistent with SQLite & assessments.jsonl
            report = svc.export_scan_report(expected_scan_sha)
            self.assertEqual(report["scan_summary"]["matched_citation_count"], 2)
            self.assertEqual(report["scan_summary"]["total_findings"], 3)


class GroupEExceptionControlFlowCounterexamples(unittest.TestCase):
    """Blocker #1 counterexamples (Cases E1-E6): exception-driven control dependency must fail closed."""

    def _run_case(
        self,
        body: str,
        *,
        extra_methods: str = "",
        extra_imports: str = "",
        expect_blocked: bool = True,
    ) -> tuple[dict, dict]:
        java = (
            "import java.io.IOException;\n"
            "import java.sql.Connection;\n"
            "import java.sql.Statement;\n"
            "import example.ExternalProbe;\n"
            f"{extra_imports}"
            "public class ExceptionFlowCtrl {\n"
            "    public void run(Statement stmt, Connection con) throws Exception {\n"
            '        String value = "1";\n'
            f"{body}"
            "    }\n"
            f"{extra_methods}"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as td:
            rec, _ = _build_record(
                Path(td),
                {"ExceptionFlowCtrl.java": java},
                primary_rel="ExceptionFlowCtrl.java",
                cwe="CWE-89",
                source_needle='String value = "1"',
                sink_needle='stmt.executeQuery("SELECT " + value)',
            )
            dep = analyze_flow_dependencies(rec)
            gated = apply_integration_gate(rec, _validated_model_answer(rec, status="SUPPORTED"))
        if expect_blocked:
            self.assertTrue(dep["has_unverified_helper_dependency"], dep)
            self.assertEqual(
                (gated["validated_status"], gated["failure_kind"], gated["citation_check"]),
                ("UNDETERMINED", "UNVERIFIED_HELPER_FLOW", "MATCHED"),
                gated,
            )
            self.assertTrue(gated["requires_human_review"])
            self.assertFalse(gated["security_conclusion_verified"])
        else:
            self.assertFalse(dep["has_unverified_helper_dependency"], dep)
            self.assertEqual(
                (gated["validated_status"], gated["failure_kind"], gated["citation_check"]),
                ("SUPPORTED", "NONE", "MATCHED"),
                gated,
            )
        return dep, gated

    def test_e1_e2_catch_sink_explicit_guard_multi_call_and_indirect_throw_fail_closed(self) -> None:
        cases = {
            "e1_codex_catch_sink": (
                "        try {\n"
                "            ExternalProbe.check();\n"
                "        } catch (IllegalStateException ex) {\n"
                '            stmt.executeQuery("SELECT " + value);\n'
                "        }\n",
                "",
            ),
            "e1_explicit_branch_control": (
                "        if (ExternalProbe.ready()) {\n"
                '            stmt.executeQuery("SELECT " + value);\n'
                "        }\n",
                "",
            ),
            "e1_try_with_resources_opener": (
                "        try (AutoCloseable r = ExternalProbe.open()) {\n"
                '            String tmp = "ok".trim();\n'
                "        } catch (Exception ex) {\n"
                '            stmt.executeQuery("SELECT " + value);\n'
                "        }\n",
                "",
            ),
            "e1_helper_outside_try_feeds_stdlib_thrower": (
                "        String raw = ExternalProbe.readToken();\n"
                "        try {\n"
                "            Integer.parseInt(raw);\n"
                "        } catch (NumberFormatException ex) {\n"
                '            stmt.executeQuery("SELECT " + value);\n'
                "        }\n",
                "",
            ),
            "e1_same_file_helper_in_try_calls_unverified": (
                "        try {\n"
                "            runLocalCheck();\n"
                "        } catch (IllegalStateException ex) {\n"
                '            stmt.executeQuery("SELECT " + value);\n'
                "        }\n",
                "    private void runLocalCheck() {\n"
                "        ExternalProbe.check();\n"
                "    }\n",
            ),
            "e2_multiple_calls_in_try_with_one_unverified": (
                "        try {\n"
                '            int n = Integer.parseInt("42");\n'
                "            ExternalProbe.check();\n"
                '            String s = String.valueOf(n).trim();\n'
                "        } catch (IllegalStateException ex) {\n"
                '            stmt.executeQuery("SELECT " + value);\n'
                "        }\n",
                "",
            ),
        }
        for label, (body, extra_m) in cases.items():
            with self.subTest(case=label):
                self._run_case(body, extra_methods=extra_m, expect_blocked=True)

    def test_e3_multi_catch_multiple_handlers_and_nested_try_catch_fail_closed(self) -> None:
        cases = {
            "e3_multi_catch_union": (
                "        try {\n"
                "            ExternalProbe.check();\n"
                "        } catch (IOException | IllegalStateException ex) {\n"
                '            stmt.executeQuery("SELECT " + value);\n'
                "        }\n"
            ),
            "e3_second_catch_handler": (
                "        try {\n"
                "            ExternalProbe.check();\n"
                "        } catch (IOException ioEx) {\n"
                "            return;\n"
                "        } catch (RuntimeException rtEx) {\n"
                '            stmt.executeQuery("SELECT " + value);\n'
                "        }\n"
            ),
            "e3_nested_try_sink_in_outer_catch": (
                "        try {\n"
                "            try {\n"
                "                ExternalProbe.check();\n"
                "            } catch (IOException inner) {\n"
                '                String ignored = inner.getMessage();\n'
                "            }\n"
                "        } catch (IllegalStateException outer) {\n"
                '            stmt.executeQuery("SELECT " + value);\n'
                "        }\n"
            ),
            "e3_nested_try_sink_in_inner_catch": (
                "        try {\n"
                "            try {\n"
                "                ExternalProbe.check();\n"
                "            } catch (IllegalStateException inner) {\n"
                '                stmt.executeQuery("SELECT " + value);\n'
                "            }\n"
                "        } catch (Exception outer) {\n"
                "            return;\n"
                "        }\n"
            ),
        }
        for label, body in cases.items():
            with self.subTest(case=label):
                self._run_case(body, expect_blocked=True)

    def test_e4_finally_and_preceding_try_catch_exception_paths_fail_closed(self) -> None:
        cases = {
            "e4_sink_in_finally_after_unverified_try": (
                "        try {\n"
                "            ExternalProbe.check();\n"
                "        } finally {\n"
                '            stmt.executeQuery("SELECT " + value);\n'
                "        }\n"
            ),
            "e4_sink_in_finally_with_unverified_catch": (
                "        try {\n"
                '            Integer.parseInt("x");\n'
                "        } catch (NumberFormatException ex) {\n"
                "            ExternalProbe.check();\n"
                "        } finally {\n"
                '            stmt.executeQuery("SELECT " + value);\n'
                "        }\n"
            ),
            "e4_preceding_try_catch_with_early_return": (
                "        try {\n"
                "            ExternalProbe.check();\n"
                "        } catch (IllegalStateException ex) {\n"
                "            return;\n"
                "        }\n"
                '        stmt.executeQuery("SELECT " + value);\n'
            ),
            "e4_preceding_try_skips_overwrite_on_throw": (
                "        try {\n"
                "            ExternalProbe.check();\n"
                '            value = "safe";\n'
                "        } catch (IllegalStateException ex) {\n"
                "        }\n"
                '        stmt.executeQuery("SELECT " + value);\n'
            ),
            "e4_preceding_catch_overwrites_sink_var": (
                "        try {\n"
                "            ExternalProbe.check();\n"
                "        } catch (IllegalStateException ex) {\n"
                '            value = "safe";\n'
                "        }\n"
                '        stmt.executeQuery("SELECT " + value);\n'
            ),
        }
        for label, body in cases.items():
            with self.subTest(case=label):
                self._run_case(body, expect_blocked=True)

    def test_e5_e6_non_exception_controls_pass_while_demo3_remains_undetermined_matched(self) -> None:
        # E5: Sink inside try body with independent JDBC factory & post-sink non-loop helper stays SUPPORTED
        dep, _ = self._run_case(
            "        try {\n"
            '            Connection c2 = new PoolProvider().open("/WEB-INF/db.cfg");\n'
            "            if (c2 != null && !c2.isClosed()) {\n"
            "                Statement s2 = c2.createStatement();\n"
            '                stmt.executeQuery("SELECT " + value);\n'
            "                ExternalProbe.postAudit();\n"
            "            }\n"
            "        } catch (Exception ex) {\n"
            "            ex.getMessage();\n"
            "        }\n",
            extra_imports="import example.PoolProvider;\n",
            expect_blocked=False,
        )
        self.assertEqual(dep["flow_slice_summary"]["exception_control_lines"], [])

        # E6: Demo3ExternalHelperUndetermined.java stays UNDETERMINED + UNVERIFIED_HELPER_FLOW + MATCHED
        demo3_text = DEMO3_FIXTURE_PATH.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as td:
            rec, _ = _build_record(
                Path(td),
                {"Demo3ExternalHelperUndetermined.java": demo3_text},
                primary_rel="Demo3ExternalHelperUndetermined.java",
                cwe="CWE-22",
                source_needle='req.getParameter("docId")',
                sink_needle="return new FileInputStream(delegatedPath);",
            )
            gated = apply_integration_gate(rec, _validated_model_answer(rec, status="SUPPORTED"))
            self.assertEqual(
                (gated["validated_status"], gated["failure_kind"], gated["citation_check"]),
                ("UNDETERMINED", "UNVERIFIED_HELPER_FLOW", "MATCHED"),
            )


class GroupFCitationBoundaryCounterexamples(unittest.TestCase):
    """Blocker #2 counterexamples (Cases C1-C6): Gate 0 trust boundary across UNDETERMINED, SUPPORTED, REFUTED."""

    def _make_record(self, td: str, *, with_external_helper: bool = False) -> tuple[dict, str, str, int, str]:
        helper_stmt = "        String q = ExternalHelper.clean(raw);\n" if with_external_helper else "        String q = raw;\n"
        java = (
            "package demo;\n"
            "import java.sql.Statement;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class GateBoundaryCtrl {\n"
            "    // non-executable comment line\n"
            "    public void run(HttpServletRequest req, Statement stmt) throws Exception {\n"
            '        String raw = req.getParameter("q");\n'
            f"{helper_stmt}"
            '        stmt.executeQuery("SELECT * FROM items WHERE k=\'" + q + "\'");\n'
            "    }\n"
            "}\n"
        )
        rec, _ = _build_record(
            Path(td),
            {"GateBoundaryCtrl.java": java},
            primary_rel="GateBoundaryCtrl.java",
            cwe="CWE-89",
            source_needle='req.getParameter("q")',
            sink_needle='stmt.executeQuery("SELECT * FROM items WHERE k=\'" + q + "\'")',
        )
        primary = rec["snippets"][0]
        sink_ln = rec["start"]["line"]
        lmap = {ln["line"]: ln["text"] for ln in primary["lines"]}
        return rec, primary["path"], primary["sha256"], sink_ln, lmap[sink_ln]

    def test_c1_undetermined_with_forged_matched_or_provenance_cannot_survive_gate0(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            rec, p_path, p_sha, sink_ln, exact_quote = self._make_record(td)
            forged_prov = {
                "citation_in_source": True,
                "citation_in_prompt": True,
                "citation_posthoc_only": False,
                "supports_security_claim_verified": True,
            }
            forged_cases = {
                "empty_cites_forged_matched": {
                    "status": "UNDETERMINED",
                    "validated_status": "UNDETERMINED",
                    "citation_check": "MATCHED",
                    "citation_provenance": forged_prov,
                    "citations": [],
                },
                "empty_cites_forged_provenance_only": {
                    "status": "UNDETERMINED",
                    "validated_status": "UNDETERMINED",
                    "citation_check": "NONE",
                    "citation_provenance": forged_prov,
                    "citations": [],
                },
                "missing_sha256_forged_matched": {
                    "status": "UNDETERMINED",
                    "validated_status": "UNDETERMINED",
                    "citation_check": "MATCHED",
                    "citation_provenance": forged_prov,
                    "citations": [{"path": p_path, "start_line": sink_ln, "end_line": sink_ln, "quote": exact_quote}],
                },
                "wrong_sha256_forged_matched": {
                    "status": "UNDETERMINED",
                    "validated_status": "UNDETERMINED",
                    "citation_check": "MATCHED",
                    "citation_provenance": forged_prov,
                    "citations": [
                        {"path": p_path, "start_line": sink_ln, "end_line": sink_ln, "quote": exact_quote, "sha256": "0" * 64}
                    ],
                },
                "wrong_quote_forged_matched": {
                    "status": "UNDETERMINED",
                    "validated_status": "UNDETERMINED",
                    "citation_check": "MATCHED",
                    "citation_provenance": forged_prov,
                    "citations": [
                        {"path": p_path, "start_line": sink_ln, "end_line": sink_ln, "quote": exact_quote.lstrip(), "sha256": p_sha}
                    ],
                },
                "comment_line_forged_matched": {
                    "status": "UNDETERMINED",
                    "validated_status": "UNDETERMINED",
                    "citation_check": "MATCHED",
                    "citation_provenance": forged_prov,
                    "citations": [
                        {"path": p_path, "start_line": 5, "end_line": 5, "quote": "    // non-executable comment line", "sha256": p_sha}
                    ],
                },
                "mismatched_status_and_validated_status": {
                    "status": "SUPPORTED",
                    "validated_status": "UNDETERMINED",
                    "citation_check": "MATCHED",
                    "citation_provenance": forged_prov,
                    "citations": [
                        {"path": p_path, "start_line": sink_ln, "end_line": sink_ln, "quote": "WRONG", "sha256": p_sha}
                    ],
                },
            }
            for label, payload in forged_cases.items():
                with self.subTest(case=label):
                    gated = apply_integration_gate(rec, payload)
                    self.assertEqual(gated["status"], "UNDETERMINED", gated)
                    self.assertEqual(gated["validated_status"], "UNDETERMINED", gated)
                    self.assertEqual(gated["citation_check"], "NOT_VERIFIED", gated)
                    self.assertEqual(gated["failure_kind"], "INVALID_CITATION", gated)
                    self.assertEqual(gated["citations"], [], gated)
                    self.assertFalse(gated["citation_provenance"]["citation_in_source"])
                    self.assertFalse(gated["citation_provenance"]["citation_in_prompt"])
                    self.assertFalse(gated["citation_provenance"]["supports_security_claim_verified"])
                    self.assertFalse(gated["security_conclusion_verified"])
                    self.assertTrue(gated["requires_human_review"])
                    if payload["citations"]:
                        self.assertEqual(gated["raw_model_citations"], payload["citations"])

    def test_c2_undetermined_with_real_verified_citation_keeps_matched_and_human_review(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            rec, p_path, p_sha, sink_ln, exact_quote = self._make_record(td)
            valid_und = {
                "status": "UNDETERMINED",
                "validated_status": "UNDETERMINED",
                "raw_model_status": "UNDETERMINED",
                "citation_check": "NOT_VERIFIED",  # Even if caller didn't pre-label, Gate 0 verifies independently
                "explanation": "Chưa đủ ngữ cảnh để kết luận dứt khoát.",
                "fix_suggestion": "Kiểm tra thủ công.",
                "citations": [
                    {"path": p_path, "start_line": sink_ln, "end_line": sink_ln, "quote": exact_quote, "sha256": p_sha}
                ],
            }
            gated = apply_integration_gate(rec, valid_und)
            self.assertEqual(gated["status"], "UNDETERMINED")
            self.assertEqual(gated["validated_status"], "UNDETERMINED")
            self.assertEqual(gated["citation_check"], "MATCHED")
            self.assertEqual(len(gated["citations"]), 1)
            self.assertTrue(gated["citation_provenance"]["citation_in_source"])
            self.assertTrue(gated["citation_provenance"]["citation_in_prompt"])
            self.assertFalse(gated["citation_provenance"]["supports_security_claim_verified"])
            self.assertFalse(gated["security_conclusion_verified"])
            self.assertTrue(gated["requires_human_review"])

            # Clean UNDETERMINED with empty citations preserves NONE; TIMEOUT preserves TIMEOUT + NOT_VERIFIED
            clean_none = apply_integration_gate(
                rec,
                {"status": "UNDETERMINED", "validated_status": "UNDETERMINED", "citations": [], "citation_check": "NONE", "failure_kind": "NONE"},
            )
            self.assertEqual(clean_none["citation_check"], "NONE")
            self.assertEqual(clean_none["validated_status"], "UNDETERMINED")

            timeout_und = apply_integration_gate(
                rec,
                {"status": "UNDETERMINED", "validated_status": "UNDETERMINED", "citations": [], "citation_check": "NOT_VERIFIED", "failure_kind": "TIMEOUT"},
            )
            self.assertEqual(timeout_und["citation_check"], "NOT_VERIFIED")
            self.assertEqual(timeout_und["failure_kind"], "TIMEOUT")

    def test_c3_c4_supported_and_refuted_missing_or_wrong_sha256_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            rec, p_path, _p_sha, sink_ln, exact_quote = self._make_record(td)
            bad_cite_variants = {
                "missing_sha256_key": [{"path": p_path, "start_line": sink_ln, "end_line": sink_ln, "quote": exact_quote}],
                "empty_sha256_str": [{"path": p_path, "start_line": sink_ln, "end_line": sink_ln, "quote": exact_quote, "sha256": ""}],
                "wrong_sha256_hex": [{"path": p_path, "start_line": sink_ln, "end_line": sink_ln, "quote": exact_quote, "sha256": "f" * 64}],
            }
            for status in ("SUPPORTED", "REFUTED"):
                for label, cites in bad_cite_variants.items():
                    with self.subTest(status=status, variant=label):
                        gated = apply_integration_gate(
                            rec,
                            {
                                "status": status,
                                "validated_status": status,
                                "raw_model_status": status,
                                "explanation": "Conclusive verdict with missing/wrong SHA-256.",
                                "fix_suggestion": "Use PreparedStatement.",
                                "citations": cites,
                            },
                        )
                        self.assertEqual(gated["validated_status"], "UNDETERMINED", gated)
                        self.assertEqual(gated["failure_kind"], "INVALID_CITATION", gated)
                        self.assertEqual(gated["citation_check"], "NOT_VERIFIED", gated)
                        self.assertEqual(gated["citations"], [], gated)
                        self.assertEqual(gated["raw_model_citations"], cites)
                        self.assertTrue(gated["validator_downgraded"])
                        self.assertTrue(gated["requires_human_review"])
                        self.assertFalse(gated["security_conclusion_verified"])

    def test_c5_c6_valid_citation_preserved_under_helper_downgrade_and_wrong_path_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            rec, p_path, p_sha, sink_ln, exact_quote = self._make_record(td, with_external_helper=True)
            for status in ("SUPPORTED", "REFUTED"):
                with self.subTest(status=status):
                    gated = apply_integration_gate(
                        rec,
                        {
                            "status": status,
                            "validated_status": status,
                            "raw_model_status": status,
                            "explanation": "Verdict with verified citation on unverified helper flow.",
                            "fix_suggestion": "Verify helper.",
                            "citations": [
                                {"path": p_path, "start_line": sink_ln, "end_line": sink_ln, "quote": exact_quote, "sha256": p_sha}
                            ],
                        },
                    )
                    self.assertEqual(gated["validated_status"], "UNDETERMINED")
                    self.assertEqual(gated["failure_kind"], "UNVERIFIED_HELPER_FLOW")
                    self.assertEqual(gated["citation_check"], "MATCHED")
                    self.assertEqual(len(gated["citations"]), 1)

            # C6: Wrong path must be strictly rejected
            wrong_path_gated = apply_integration_gate(
                rec,
                {
                    "status": "SUPPORTED",
                    "validated_status": "SUPPORTED",
                    "citation_check": "MATCHED",
                    "citations": [
                        {"path": "OtherFile.java", "start_line": sink_ln, "end_line": sink_ln, "quote": exact_quote, "sha256": p_sha}
                    ],
                },
            )
            self.assertEqual(wrong_path_gated["validated_status"], "UNDETERMINED")
            self.assertEqual(wrong_path_gated["failure_kind"], "INVALID_CITATION")
            self.assertEqual(wrong_path_gated["citation_check"], "NOT_VERIFIED")


class GroupGCrossAuditCE1ToCE5Counterexamples(unittest.TestCase):
    """Cross-audit security counterexamples CE1-CE5 and positive stdlib controls."""

    def test_ce1_branch_inside_try_without_throw_propagates_condition_to_guard_slice(self) -> None:
        if_java = (
            "package sample.ce1;\n"
            "import java.io.IOException;\n"
            "import java.nio.file.Files;\n"
            "import java.nio.file.Paths;\n"
            "import java.sql.Connection;\n"
            "import java.sql.Statement;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public final class TryIfCtrl {\n"
            "    public void handle(HttpServletRequest req, Connection conn) throws Exception {\n"
            '        String id = req.getParameter("id");\n'
            "        boolean strict = PolicyConfig.isStrict();\n"
            "        try {\n"
            "            if (strict) {\n"
            '                Files.readString(Paths.get("/nonexistent"));\n'
            "            }\n"
            "        } catch (IOException ex) {\n"
            "            Statement st = conn.createStatement();\n"
            '            st.executeQuery("SELECT * FROM users WHERE id=" + id);\n'
            "        }\n"
            "    }\n"
            "}\n"
        )
        switch_java = if_java.replace("boolean strict = PolicyConfig.isStrict();", "int mode = PolicyConfig.mode();").replace(
            'if (strict) {\n                Files.readString(Paths.get("/nonexistent"));\n            }',
            'switch (mode) { case 1: Files.readString(Paths.get("/nonexistent")); break; default: break; }',
        )
        for label, src in (("if_in_try", if_java), ("switch_in_try", switch_java)):
            with self.subTest(variant=label), tempfile.TemporaryDirectory() as td:
                rec, _ = _build_record(
                    Path(td),
                    {"TryIfCtrl.java": src},
                    primary_rel="TryIfCtrl.java",
                    cwe="CWE-89",
                    source_needle='req.getParameter("id")',
                    sink_needle='st.executeQuery("SELECT * FROM users WHERE id=" + id)',
                )
                dep = analyze_flow_dependencies(rec)
                self.assertTrue(dep["has_unverified_helper_dependency"], dep)
                gated = apply_integration_gate(rec, _validated_model_answer(rec, status="SUPPORTED"))
                self.assertEqual(
                    (gated["validated_status"], gated["failure_kind"], gated["citation_check"]),
                    ("UNDETERMINED", "UNVERIFIED_HELPER_FLOW", "MATCHED"),
                )

    def test_ce2_void_helper_mutating_mutable_arg_promotes_enclosing_guard(self) -> None:
        java = (
            "package sample.ce2;\n"
            "import java.sql.Connection;\n"
            "import java.sql.Statement;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public final class MutableArgCtrl {\n"
            "    private static void appendSql(StringBuilder target, String val) {\n"
            "        target.append(val);\n"
            "    }\n"
            "    public void handle(HttpServletRequest req, Connection conn) throws Exception {\n"
            '        String id = req.getParameter("id");\n'
            '        StringBuilder sql = new StringBuilder("SELECT * FROM users WHERE id="); \n'
            "        if (FeatureGate.allowTaint()) {\n"
            "            appendSql(sql, id);\n"
            "        }\n"
            "        Statement st = conn.createStatement();\n"
            "        st.executeQuery(sql.toString());\n"
            "    }\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as td:
            rec, _ = _build_record(
                Path(td),
                {"MutableArgCtrl.java": java},
                primary_rel="MutableArgCtrl.java",
                cwe="CWE-89",
                source_needle='req.getParameter("id")',
                sink_needle="st.executeQuery(sql.toString())",
            )
            dep = analyze_flow_dependencies(rec)
            self.assertTrue(dep["has_unverified_helper_dependency"], dep)
            gated = apply_integration_gate(rec, _validated_model_answer(rec, status="SUPPORTED"))
            self.assertEqual(
                (gated["validated_status"], gated["failure_kind"], gated["citation_check"]),
                ("UNDETERMINED", "UNVERIFIED_HELPER_FLOW", "MATCHED"),
            )

    def test_ce3a_ce3b_method_references_and_multiline_constructors(self) -> None:
        ref_unverified = (
            "package sample.ce3;\n"
            "import java.util.Optional;\n"
            "import java.sql.Connection;\n"
            "import java.sql.Statement;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public final class RefCtrl {\n"
            "    public void handle(HttpServletRequest req, Connection conn) throws Exception {\n"
            '        String id = req.getParameter("id");\n'
            '        String safe = Optional.ofNullable(id).map(CustomCleaner::clean).orElse("0");\n'
            "        Statement st = conn.createStatement();\n"
            '        st.executeQuery("SELECT * FROM users WHERE id=" + safe);\n'
            "    }\n"
            "}\n"
        )
        ref_ctor_unverified = ref_unverified.replace("CustomCleaner::clean", "CustomWrapper::new").replace(
            'orElse("0")', "orElse(null)"
        ).replace("String safe =", "Object safe =")
        ref_stdlib_positive = ref_unverified.replace("CustomCleaner::clean", "String::trim")

        multiline_ctor_unverified = (
            "package sample.ce3;\n"
            "import java.sql.Connection;\n"
            "import java.sql.Statement;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public final class MultilineCtorCtrl {\n"
            "    public void handle(HttpServletRequest req, Connection conn) throws Exception {\n"
            '        String id = req.getParameter("id");\n'
            "        try {\n"
            "            new CustomValidator(\n"
            "                id\n"
            "            );\n"
            "        } catch (RuntimeException ex) {\n"
            "            Statement st = conn.createStatement();\n"
            '            st.executeQuery("SELECT * FROM users WHERE id=" + id);\n'
            "        }\n"
            "    }\n"
            "}\n"
        )
        multiline_stdlib_ctor_positive = (
            "package sample.ce3;\n"
            "import java.io.BufferedWriter;\n"
            "import java.io.File;\n"
            "import java.io.FileWriter;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public final class MultilineStdlibCtorCtrl {\n"
            "    public void write(HttpServletRequest req) throws Exception {\n"
            '        String name = req.getParameter("name");\n'
            '        File f = new File("/srv/pages/" + name);\n'
            "        BufferedWriter bw = new BufferedWriter(\n"
            "            new FileWriter(\n"
            "                f\n"
            "            )\n"
            "        );\n"
            "        bw.close();\n"
            "    }\n"
            "}\n"
        )

        for label, fname, src, cwe, s_src, s_sink, expect_unv in (
            ("ce3a_method_ref", "RefCtrl.java", ref_unverified, "CWE-89", 'req.getParameter("id")', 'st.executeQuery("SELECT * FROM users WHERE id=" + safe)', True),
            ("ce3a_ctor_ref", "RefCtrl.java", ref_ctor_unverified, "CWE-89", 'req.getParameter("id")', 'st.executeQuery("SELECT * FROM users WHERE id=" + safe)', True),
            ("ce3a_stdlib_method_ref_ok", "RefCtrl.java", ref_stdlib_positive, "CWE-89", 'req.getParameter("id")', 'st.executeQuery("SELECT * FROM users WHERE id=" + safe)', False),
            ("ce3b_multiline_unverified_ctor", "MultilineCtorCtrl.java", multiline_ctor_unverified, "CWE-89", 'req.getParameter("id")', 'st.executeQuery("SELECT * FROM users WHERE id=" + id)', True),
            ("ce3b_multiline_stdlib_filewriter_ok", "MultilineStdlibCtorCtrl.java", multiline_stdlib_ctor_positive, "CWE-22", 'req.getParameter("name")', "new FileWriter(", False),
        ):
            with self.subTest(case=label), tempfile.TemporaryDirectory() as td:
                rec, _ = _build_record(
                    Path(td),
                    {fname: src},
                    primary_rel=fname,
                    cwe=cwe,
                    source_needle=s_src,
                    sink_needle=s_sink,
                )
                dep = analyze_flow_dependencies(rec)
                self.assertEqual(dep["has_unverified_helper_dependency"], expect_unv, dep)

    def test_ce4_ce5_contradictory_statuses_and_refuted_output_normalization(self) -> None:
        java = (
            "package sample.ce45;\n"
            "import java.sql.Connection;\n"
            "import java.sql.PreparedStatement;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public final class SafePreparedGateCtrl {\n"
            "    public void handle(HttpServletRequest req, Connection conn) throws Exception {\n"
            '        String id = req.getParameter("id");\n'
            '        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");\n'
            "        ps.setString(1, id);\n"
            "        ps.executeQuery();\n"
            "    }\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as td:
            rec, _ = _build_record(
                Path(td),
                {"SafePreparedGateCtrl.java": java},
                primary_rel="SafePreparedGateCtrl.java",
                cwe="CWE-89",
                source_needle='req.getParameter("id")',
                sink_needle="ps.executeQuery();",
            )
            primary = rec["snippets"][0]
            p_path, p_sha = primary["path"], primary["sha256"]
            lmap = {ln["line"]: ln["text"] for ln in primary["lines"]}
            c8 = {"path": p_path, "start_line": 8, "end_line": 8, "quote": lmap[8], "sha256": p_sha}
            c10 = {"path": p_path, "start_line": 10, "end_line": 10, "quote": lmap[10], "sha256": p_sha}

            # CE4: Contradictory upgrades and conclusive flips MUST fail closed to UNDETERMINED while keeping MATCHED citation
            contradictions = {
                "undetermined_to_supported": {"status": "UNDETERMINED", "validated_status": "SUPPORTED", "citations": [c10]},
                "undetermined_to_refuted": {"status": "UNDETERMINED", "validated_status": "REFUTED", "citations": [c8, c10]},
                "raw_undetermined_to_supported": {"raw_model_status": "UNDETERMINED", "status": "SUPPORTED", "validated_status": "SUPPORTED", "citations": [c10]},
                "supported_to_refuted_flip": {"status": "SUPPORTED", "validated_status": "REFUTED", "citations": [c8, c10]},
            }
            for label, payload in contradictions.items():
                with self.subTest(case=label):
                    out = apply_integration_gate(rec, {**payload, "explanation": "x", "fix_suggestion": ""})
                    self.assertEqual(out["status"], "UNDETERMINED", out)
                    self.assertEqual(out["validated_status"], "UNDETERMINED", out)
                    self.assertEqual(out["citation_check"], "MATCHED", out)
                    self.assertEqual(out["failure_kind"], "INVALID_SCHEMA", out)
                    self.assertFalse(out["supports_security_claim_verified"])
                    self.assertFalse(out["security_conclusion_verified"])
                    self.assertTrue(out["requires_human_review"])

            # Valid prior downgrade (status=SUPPORTED -> validated_status=UNDETERMINED) preserves UNDETERMINED + MATCHED cleanly
            valid_downgrade = apply_integration_gate(
                rec,
                {"status": "SUPPORTED", "validated_status": "UNDETERMINED", "explanation": "Prior downgrade.", "citations": [c10]},
            )
            self.assertEqual(valid_downgrade["status"], "UNDETERMINED")
            self.assertEqual(valid_downgrade["validated_status"], "UNDETERMINED")
            self.assertEqual(valid_downgrade["citation_check"], "MATCHED")
            self.assertEqual(valid_downgrade["raw_model_status"], "SUPPORTED")

            # CE5: Valid REFUTED with caller-forged security flags & omitted validated_status MUST normalize all outputs
            forged_ref = {
                "status": "REFUTED",
                "explanation": "PreparedStatement with ? placeholder.",
                "fix_suggestion": "",
                "citations": [c8, c10],
                "supports_security_claim_verified": True,
                "security_conclusion_verified": True,
                "requires_human_review": False,
            }
            out_ref = apply_integration_gate(rec, forged_ref)
            self.assertEqual(out_ref["status"], "REFUTED", out_ref)
            self.assertEqual(out_ref["validated_status"], "REFUTED", out_ref)
            self.assertEqual(out_ref["citation_check"], "MATCHED", out_ref)
            self.assertFalse(out_ref["supports_security_claim_verified"], out_ref)
            self.assertFalse(out_ref["security_conclusion_verified"], out_ref)
            self.assertFalse(out_ref["citation_provenance"]["supports_security_claim_verified"])
            self.assertTrue(out_ref["requires_human_review"], out_ref)


class GroupHFinalCrossAuditCoverageAndStatusMatrix(unittest.TestCase):
    """General fail-closed coverage for FIN-01/FIN-02 unresolved constructs and FIN-03 status transition matrix."""

    def test_fin01_fin02_general_unresolved_constructs_nested_generics_and_text_blocks(self) -> None:
        base_template = (
            "package sample.fin012;\n"
            "import java.util.List;\n"
            "import java.util.Map;\n"
            "import java.util.Optional;\n"
            "import java.sql.Connection;\n"
            "import java.sql.Statement;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public final class CoverageCtrl {\n"
            "    public void handle(HttpServletRequest req, Connection conn, Object sanitizer, Object[] sanitizers, Object[] boxes) throws Exception {\n"
            '        String id = req.getParameter("id");\n'
            "__BODY__"
            "        Statement st = conn.createStatement();\n"
            '        st.executeQuery("SELECT * FROM users WHERE id=" + safe);\n'
            "    }\n"
            "}\n"
        )
        fail_closed_bodies = {
            "array_element_method_ref": '        String safe = Optional.ofNullable(id).map(sanitizers[0]::clean).orElse("0");\n',
            "cast_receiver_method_ref": '        String safe = Optional.ofNullable(id).map(((ExternalSanitizer) sanitizer)::clean).orElse("0");\n',
            "new_instance_method_ref": '        String safe = Optional.ofNullable(id).map(new LocalBox()::clean).orElse("0");\n',
            "chained_expr_method_ref": '        String safe = Optional.ofNullable(id).map(boxes[0].box::clean).orElse("0");\n',
            "nested_generic_ctor": (
                "        String safe = id;\n"
                "        try {\n"
                "            new ExternalValidator<Map<String, List<String>>>(id);\n"
                "        } catch (RuntimeException ex) {\n"
                '            safe = id;\n'
                "        }\n"
            ),
            "nested_generic_method_ref": '        String safe = Optional.ofNullable(id).map(ExternalSanitizer<Map<String, List<String>>>::clean).orElse("0");\n',
            "anonymous_class_ctor": (
                "        String safe = id;\n"
                "        Runnable r = new Runnable() { public void run() { ExternalHook.audit(id); } };\n"
                "        r.run();\n"
            ),
            "explicit_type_witness_call": '        String safe = sanitizer.<List<String>>clean(id);\n',
            "overridable_stdlib_method_ref": '        String safe = Optional.ofNullable(id).map(Object::toString).orElse("0");\n',
        }
        for label, body in fail_closed_bodies.items():
            with self.subTest(fail_closed=label), tempfile.TemporaryDirectory() as td:
                src = base_template.replace("__BODY__", body)
                rec, _ = _build_record(
                    Path(td),
                    {"CoverageCtrl.java": src},
                    primary_rel="CoverageCtrl.java",
                    cwe="CWE-89",
                    source_needle='req.getParameter("id")',
                    sink_needle='st.executeQuery("SELECT * FROM users WHERE id=" + safe)',
                )
                dep = analyze_flow_dependencies(rec)
                self.assertTrue(dep["has_unverified_helper_dependency"], f"{label}: {dep}")
                gated = apply_integration_gate(rec, _validated_model_answer(rec, status="SUPPORTED"))
                self.assertEqual(
                    (gated["validated_status"], gated["failure_kind"], gated["citation_check"]),
                    ("UNDETERMINED", "UNVERIFIED_HELPER_FLOW", "MATCHED"),
                    f"{label}: {gated}",
                )

        # Positive controls: final stdlib method ref, Java 15+ text block containing fake ::/new, and post-sink helper
        positive_bodies = {
            "final_stdlib_string_trim_ref": '        String safe = Optional.ofNullable(id).map(String::trim).orElse("0");\n',
            "java15_text_block_non_executable_ignored": (
                '        String doc = """\n'
                "            sanitizers[0]::clean\n"
                "            new ExternalValidator<List<String>>(id)\n"
                '        """;\n'
                "        String safe = id;\n"
            ),
            "jdbc_conn_and_post_sink_non_loop": (
                "        String safe = id;\n"
                '        Connection c2 = new DBConnect().connect("/WEB-INF/config");\n'
                "        Statement st2 = c2.createStatement();\n"
            ),
        }
        for label, body in positive_bodies.items():
            with self.subTest(positive=label), tempfile.TemporaryDirectory() as td:
                src = base_template.replace("__BODY__", body)
                if label == "jdbc_conn_and_post_sink_non_loop":
                    src = src.replace(
                        'st.executeQuery("SELECT * FROM users WHERE id=" + safe);',
                        'st2.executeQuery("SELECT * FROM users WHERE id=" + safe);\n        ExternalLogger.auditDone();',
                    )
                    sink_n = 'st2.executeQuery("SELECT * FROM users WHERE id=" + safe)'
                else:
                    sink_n = 'st.executeQuery("SELECT * FROM users WHERE id=" + safe)'
                rec, _ = _build_record(
                    Path(td),
                    {"CoverageCtrl.java": src},
                    primary_rel="CoverageCtrl.java",
                    cwe="CWE-89",
                    source_needle='req.getParameter("id")',
                    sink_needle=sink_n,
                )
                dep = analyze_flow_dependencies(rec)
                self.assertFalse(dep["has_unverified_helper_dependency"], f"{label}: {dep}")
                gated = apply_integration_gate(rec, _validated_model_answer(rec, status="SUPPORTED"))
                self.assertEqual(
                    (gated["validated_status"], gated["failure_kind"], gated["citation_check"]),
                    ("SUPPORTED", "NONE", "MATCHED"),
                    f"{label}: {gated}",
                )

    def test_fin03_table_driven_status_transition_matrix(self) -> None:
        java = (
            "package sample.fin03;\n"
            "import java.sql.Connection;\n"
            "import java.sql.PreparedStatement;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public final class StatusMatrixCtrl {\n"
            "    public void handle(HttpServletRequest req, Connection conn) throws Exception {\n"
            '        String id = req.getParameter("id");\n'
            '        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");\n'
            "        ps.setString(1, id);\n"
            "        ps.executeQuery();\n"
            "    }\n"
            "}\n"
        )
        _OMIT = object()
        with tempfile.TemporaryDirectory() as td:
            rec, _ = _build_record(
                Path(td),
                {"StatusMatrixCtrl.java": java},
                primary_rel="StatusMatrixCtrl.java",
                cwe="CWE-89",
                source_needle='req.getParameter("id")',
                sink_needle="ps.executeQuery();",
            )
            primary = rec["snippets"][0]
            p_path, p_sha = primary["path"], primary["sha256"]
            lmap = {ln["line"]: ln["text"] for ln in primary["lines"]}
            c8 = {"path": p_path, "start_line": 8, "end_line": 8, "quote": lmap[8], "sha256": p_sha}
            c10 = {"path": p_path, "start_line": 10, "end_line": 10, "quote": lmap[10], "sha256": p_sha}

            # (label, raw_model_status, status, validated_status, cites, extra, expect_val, expect_fk, expect_cc, expect_raw)
            matrix = [
                # FIN-03 flips: raw_model_status <-> status / validated_status
                ("flip_raw_sup_to_ref", "SUPPORTED", "REFUTED", "REFUTED", [c8, c10], {}, "UNDETERMINED", "INVALID_SCHEMA", "MATCHED", "SUPPORTED"),
                ("flip_raw_ref_to_sup", "REFUTED", "SUPPORTED", "SUPPORTED", [c10], {}, "UNDETERMINED", "INVALID_SCHEMA", "MATCHED", "REFUTED"),
                ("flip_raw_sup_st_ref_val_und", "SUPPORTED", "REFUTED", "UNDETERMINED", [c8, c10], {}, "UNDETERMINED", "INVALID_SCHEMA", "MATCHED", "SUPPORTED"),
                ("flip_raw_ref_st_sup_val_und", "REFUTED", "SUPPORTED", "UNDETERMINED", [c10], {}, "UNDETERMINED", "INVALID_SCHEMA", "MATCHED", "REFUTED"),
                ("flip_st_sup_to_val_ref", _OMIT, "SUPPORTED", "REFUTED", [c8, c10], {}, "UNDETERMINED", "INVALID_SCHEMA", "MATCHED", "SUPPORTED"),
                ("flip_st_ref_to_val_sup", _OMIT, "REFUTED", "SUPPORTED", [c10], {}, "UNDETERMINED", "INVALID_SCHEMA", "MATCHED", "REFUTED"),
                # Upgrades from UNDETERMINED
                ("upgrade_raw_und_to_sup", "UNDETERMINED", "SUPPORTED", "SUPPORTED", [c10], {}, "UNDETERMINED", "INVALID_SCHEMA", "MATCHED", "UNDETERMINED"),
                ("upgrade_raw_und_to_ref", "UNDETERMINED", "REFUTED", "REFUTED", [c8, c10], {}, "UNDETERMINED", "INVALID_SCHEMA", "MATCHED", "UNDETERMINED"),
                ("upgrade_raw_und_st_und_val_sup", "UNDETERMINED", "UNDETERMINED", "SUPPORTED", [c10], {}, "UNDETERMINED", "INVALID_SCHEMA", "MATCHED", "UNDETERMINED"),
                ("upgrade_st_und_to_val_ref", _OMIT, "UNDETERMINED", "REFUTED", [c8, c10], {}, "UNDETERMINED", "INVALID_SCHEMA", "MATCHED", "UNDETERMINED"),
                # Missing status or explicit raw_model_status=None with conclusive verdict
                ("missing_status_with_val_sup", _OMIT, _OMIT, "SUPPORTED", [c10], {}, "UNDETERMINED", "INVALID_SCHEMA", "MATCHED", None),
                ("missing_status_with_raw_sup", "SUPPORTED", _OMIT, "SUPPORTED", [c10], {}, "UNDETERMINED", "INVALID_SCHEMA", "MATCHED", "SUPPORTED"),
                ("explicit_none_raw_with_sup", None, "SUPPORTED", "SUPPORTED", [c10], {}, "UNDETERMINED", "INVALID_SCHEMA", "MATCHED", None),
                ("explicit_none_raw_with_ref", None, "REFUTED", "REFUTED", [c8, c10], {}, "UNDETERMINED", "INVALID_SCHEMA", "MATCHED", None),
                # Unrecognized status value
                ("unknown_status_token", "PARTIAL", "SUPPORTED", "SUPPORTED", [c10], {}, "UNDETERMINED", "INVALID_SCHEMA", "MATCHED", "PARTIAL"),
                # Valid monotonic paths
                ("valid_supported", "SUPPORTED", "SUPPORTED", "SUPPORTED", [c10], {}, "SUPPORTED", "NONE", "MATCHED", "SUPPORTED"),
                ("valid_refuted", "REFUTED", "REFUTED", "REFUTED", [c8, c10], {}, "REFUTED", "NONE", "MATCHED", "REFUTED"),
                ("valid_downgrade_raw_sup_to_und", "SUPPORTED", "UNDETERMINED", "UNDETERMINED", [c10], {}, "UNDETERMINED", "NONE", "MATCHED", "SUPPORTED"),
                ("valid_downgrade_raw_ref_to_und", "REFUTED", "UNDETERMINED", "UNDETERMINED", [c8, c10], {}, "UNDETERMINED", "NONE", "MATCHED", "REFUTED"),
                ("valid_downgrade_st_sup_to_val_und", "SUPPORTED", "SUPPORTED", "UNDETERMINED", [c10], {}, "UNDETERMINED", "NONE", "MATCHED", "SUPPORTED"),
                ("valid_downgrade_st_ref_to_val_und", "REFUTED", "REFUTED", "UNDETERMINED", [c8, c10], {}, "UNDETERMINED", "NONE", "MATCHED", "REFUTED"),
                ("valid_technical_error_timeout", None, "UNDETERMINED", "UNDETERMINED", [], {"failure_kind": "TIMEOUT", "citation_check": "NOT_VERIFIED"}, "UNDETERMINED", "TIMEOUT", "NOT_VERIFIED", None),
            ]

            for label, raw_s, st_s, val_s, cites, extra, exp_val, exp_fk, exp_cc, exp_raw in matrix:
                with self.subTest(case=label):
                    payload = {"explanation": f"Matrix case {label}.", "fix_suggestion": "", "citations": cites, **extra}
                    if raw_s is not _OMIT:
                        payload["raw_model_status"] = raw_s
                    if st_s is not _OMIT:
                        payload["status"] = st_s
                    if val_s is not _OMIT:
                        payload["validated_status"] = val_s
                    out = apply_integration_gate(rec, payload)
                    self.assertEqual(out["status"], exp_val, f"{label}: {out}")
                    self.assertEqual(out["validated_status"], exp_val, f"{label}: {out}")
                    self.assertEqual(out.get("failure_kind", "NONE"), exp_fk, f"{label}: {out}")
                    self.assertEqual(out["citation_check"], exp_cc, f"{label}: {out}")
                    self.assertEqual(out["raw_model_status"], exp_raw, f"{label}: {out}")
                    self.assertFalse(out["security_conclusion_verified"], f"{label}: {out}")
                    self.assertFalse(out["supports_security_claim_verified"], f"{label}: {out}")
                    self.assertTrue(out["requires_human_review"], f"{label}: {out}")


if __name__ == "__main__":
    unittest.main()
