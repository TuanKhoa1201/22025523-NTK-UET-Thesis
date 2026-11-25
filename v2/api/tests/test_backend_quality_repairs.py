"""Targeted regression & counterexample tests for NTK V2 backend quality repairs.

Covers all 4 repair areas with both positive detections and strict fail-closed negative counterexamples:
1. Java CWE-89 Swing/AWT typed sources + JDBC sinks + ResultSet numeric getter sanitization.
2. Per-FQN stdlib API verification (NO global method-name whitelist), inherited HttpServlet methods,
   try-with-resources declarations, sibling-method scoping isolation, and verified chain return types.
3. Strict citation contract non-relaxation (omitted blank line & lstrip quotes still fail closed) plus
   focused caller/callee context extraction without sibling-handler bloat.
4. CWE-22 metadata pre-check (`File.exists()`) exclusion while preserving real I/O, mutation, and Zip-Slip sinks.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from v2.api.config import DEFAULT_BACKEND_RULES
from v2.api.java_context_v2 import (
    _compact_redundant_snippets,
    analyze_flow_dependencies,
    enrich_bundle_context,
    extract_java_context_v2,
)
from v2.api.triage_gate import apply_integration_gate
from v2.triage.evidence import EvidenceError, collect, digest
from v2.triage.ollama import validate_answer


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


def _run_opengrep(binary: str, target: Path) -> dict:
    cmd = [
        binary,
        "scan",
        "--config",
        str(DEFAULT_BACKEND_RULES.resolve()),
        "--json",
        "--no-git-ignore",
        str(target),
    ]
    cp = subprocess.run(cmd, capture_output=True, text=True, timeout=90, check=False)
    if cp.returncode != 0:
        raise AssertionError(f"OpenGrep exited {cp.returncode}: {cp.stderr[:500]}")
    return json.loads(cp.stdout)


def _make_record(
    root: Path,
    rel_path: str,
    code: str,
    *,
    sink_line: int,
    source_line: int,
    rule_id: str = "ntk.api.java.cwe22.path-traversal",
    cwe: list[str] | None = None,
    unresolved_calls: list[dict] | None = None,
    extra_files: dict[str, str] | None = None,
) -> dict:
    src_root = root / "src"
    src_root.mkdir(parents=True, exist_ok=True)
    fp = src_root / rel_path
    fp.parent.mkdir(parents=True, exist_ok=True)
    raw_bytes = code.encode("utf-8")
    fp.write_bytes(raw_bytes)
    lines = raw_bytes.decode("utf-8").splitlines(keepends=True)

    sources_map = {rel_path: digest(raw_bytes)}
    if extra_files:
        for e_rel, e_code in extra_files.items():
            efp = src_root / e_rel
            efp.parent.mkdir(parents=True, exist_ok=True)
            e_bytes = e_code.encode("utf-8")
            efp.write_bytes(e_bytes)
            sources_map[e_rel] = digest(e_bytes)

    def _loc(ln: int) -> tuple[dict, str]:
        line_raw = lines[ln - 1].rstrip("\r\n")
        snippet = line_raw.strip() or line_raw
        col0 = line_raw.index(snippet) if snippet else 0
        prefix_bytes = sum(len(x.encode("utf-8")) for x in lines[: ln - 1])
        start_off = prefix_bytes + len(line_raw[:col0].encode("utf-8"))
        end_off = start_off + len(snippet.encode("utf-8"))
        return (
            {
                "path": rel_path,
                "start": {"line": ln, "col": len(line_raw[:col0].encode("utf-8")) + 1, "offset": start_off},
                "end": {"line": ln, "col": len(line_raw[: col0 + len(snippet)].encode("utf-8")) + 1, "offset": end_off},
            },
            snippet,
        )

    src_loc, src_txt = _loc(source_line)
    snk_loc, snk_txt = _loc(sink_line)
    cwe_list = cwe or ["CWE-22"]
    og_doc = {
        "version": "1.25.0",
        "results": [
            {
                "check_id": rule_id,
                "path": rel_path,
                "start": snk_loc["start"],
                "end": snk_loc["end"],
                "extra": {
                    "message": f"[{cwe_list[0]}] synthetic test finding",
                    "severity": "ERROR",
                    "metadata": {"cwe": cwe_list},
                    "dataflow_trace": {
                        "taint_source": ["CliLoc", [src_loc, src_txt]],
                        "intermediate_vars": [],
                        "taint_sink": ["CliLoc", [snk_loc, snk_txt]],
                    },
                },
            }
        ],
        "errors": [],
        "paths": {"scanned": list(sources_map.keys()), "skipped": []},
    }
    cap_dir = root / "capture"
    cap_dir.mkdir(parents=True, exist_ok=True)
    og_path = cap_dir / "opengrep.json"
    og_bytes = json.dumps(og_doc, indent=2).encode("utf-8")
    og_path.write_bytes(og_bytes)
    sarif_doc = {
        "version": "2.1.0",
        "runs": [
            {
                "results": [
                    {
                        "ruleId": rule_id,
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": rel_path},
                                    "region": {"startLine": sink_line},
                                }
                            }
                        ],
                    }
                ]
            }
        ],
    }
    sarif_bytes = json.dumps(sarif_doc, indent=2).encode("utf-8")
    rules_bytes = b"rules: []\n"
    ver_cmd = ["opengrep", "--version"]
    json_cmd = ["opengrep", "scan", "--json", str(src_root)]
    sarif_cmd = ["opengrep", "scan", "--sarif", str(src_root)]
    art_blobs = {
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
    for fname, fbytes in art_blobs.items():
        (cap_dir / fname).write_bytes(fbytes)
        artifacts[fname] = digest(fbytes)
    manifest = {
        "schema": "ntk-scan-capture-1",
        "producer": "unit_test_local_capture",
        "success": True,
        "issues": [],
        "target_kind": "directory",
        "sources_before": sources_map,
        "sources_after": sources_map,
        "rules_before_sha256": digest(rules_bytes),
        "rules_after_sha256": digest(rules_bytes),
        "artifacts": artifacts,
        "runs": {
            "version": {"argv": ver_cmd, "exit_code": 0},
            "json": {"argv": json_cmd, "exit_code": 0, "output_mode": "stdout"},
            "sarif": {"argv": sarif_cmd, "exit_code": 0, "output_mode": "stdout"},
        },
    }
    manifest_path = cap_dir / "scan-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    bundle = collect(
        og_bytes,
        src_root,
        engine_exit=0,
        scan_provenance={
            "origin": "unit",
            "source_capture_verified": True,
            "exit_capture_verified": True,
            "recorded_engine_exit": 0,
            "source_hashes": sources_map,
        },
    )
    enrich_bundle_context(bundle, src_root)
    rec = bundle["records"][0]
    if unresolved_calls is not None:
        sig = dict(rec.get("heuristic_signals") or {})
        sig["unresolved_calls"] = unresolved_calls
        rec["heuristic_signals"] = sig
    return rec


def _supported_assessment(rec: dict, cite_line: int) -> dict:
    primary = rec["snippets"][0]
    p_path = primary["path"]
    lmap = {ln["line"]: ln["text"] for ln in primary["lines"]}
    quote = lmap[cite_line]
    return {
        "status": "SUPPORTED",
        "validated_status": "SUPPORTED",
        "raw_model_status": "SUPPORTED",
        "citations": [
            {
                "path": p_path,
                "start_line": cite_line,
                "end_line": cite_line,
                "quote": quote,
                "sha256": primary["sha256"],
            }
        ],
    }


class JavaRulesSwingCwe89AndCwe22Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.og_bin = _resolve_opengrep_binary()
        if not cls.og_bin:
            raise unittest.SkipTest("ENV_BLOCKED: no local OpenGrep binary found")

    def test_cwe89_swing_8_mandatory_cases_and_resultset_sanitization(self) -> None:
        cases = {
            # 1. JTextField.getText() -> stmt.executeQuery(...)
            "Pos1SwingTextFieldExecuteQuery.java": (
                "import javax.swing.*;\n"
                "import java.sql.*;\n"
                "public class Pos1SwingTextFieldExecuteQuery {\n"
                "    JTextField userField;\n"
                "    void login(Statement stmt) throws Exception {\n"
                "        String user = userField.getText();\n"
                "        stmt.executeQuery(\"SELECT * FROM users WHERE username = '\" + user + \"'\");\n"
                "    }\n"
                "}\n"
            ),
            # 2. JPasswordField.getPassword() -> SQL concat
            "Pos2SwingPasswordFieldSql.java": (
                "import javax.swing.*;\n"
                "import java.sql.*;\n"
                "public class Pos2SwingPasswordFieldSql {\n"
                "    JPasswordField passField;\n"
                "    void login(Statement stmt) throws Exception {\n"
                "        String pwd = new String(passField.getPassword());\n"
                "        stmt.executeQuery(\"SELECT * FROM users WHERE password = '\" + pwd + \"'\");\n"
                "    }\n"
                "}\n"
            ),
            # 3. Swing -> stmt.executeUpdate(...)
            "Pos3SwingExecuteUpdate.java": (
                "import javax.swing.*;\n"
                "import java.sql.*;\n"
                "public class Pos3SwingExecuteUpdate {\n"
                "    JTextField userField;\n"
                "    void touch(Statement stmt) throws Exception {\n"
                "        String u = userField.getText();\n"
                "        stmt.executeUpdate(\"UPDATE users SET active = 1 WHERE name = '\" + u + \"'\");\n"
                "    }\n"
                "}\n"
            ),
            # 4. Swing -> conn.prepareStatement(concatenated SQL)
            "Pos4SwingPreparedConcat.java": (
                "import javax.swing.*;\n"
                "import java.sql.*;\n"
                "public class Pos4SwingPreparedConcat {\n"
                "    JTextField userField;\n"
                "    void find(Connection conn) throws Exception {\n"
                "        String u = userField.getText();\n"
                "        PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE name = '\" + u + \"'\");\n"
                "        ps.executeQuery();\n"
                "    }\n"
                "}\n"
            ),
            # 5. Safe parameterized PreparedStatement with `?` + setString (NEGATIVE)
            "Neg5SwingPreparedSafeBind.java": (
                "import javax.swing.*;\n"
                "import java.sql.*;\n"
                "public class Neg5SwingPreparedSafeBind {\n"
                "    JTextField userField;\n"
                "    void find(Connection conn) throws Exception {\n"
                "        String u = userField.getText();\n"
                "        PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE name = ?\");\n"
                "        ps.setString(1, u);\n"
                "        ps.executeQuery();\n"
                "    }\n"
                "}\n"
            ),
            # 6. Constant SQL query even when Swing fields exist (NEGATIVE)
            "Neg6SwingConstantSql.java": (
                "import javax.swing.*;\n"
                "import java.sql.*;\n"
                "public class Neg6SwingConstantSql {\n"
                "    JTextField userField;\n"
                "    void load(Statement stmt) throws Exception {\n"
                "        String ignored = userField.getText();\n"
                "        stmt.executeQuery(\"SELECT id, name FROM roles WHERE enabled = 1\");\n"
                "    }\n"
                "}\n"
            ),
            # 7. Custom app class defining getText() MUST NOT trigger (NEGATIVE)
            "Neg7CustomAppGetText.java": (
                "import java.sql.*;\n"
                "public class Neg7CustomAppGetText {\n"
                "    static class CustomLabel { String getText() { return \"fixed\"; } }\n"
                "    CustomLabel lbl = new CustomLabel();\n"
                "    void run(Statement stmt) throws Exception {\n"
                "        String s = lbl.getText();\n"
                "        stmt.executeQuery(\"SELECT * FROM t WHERE k = '\" + s + \"'\");\n"
                "    }\n"
                "}\n"
            ),
            # 8. Non-regression on Servlet & Spring sources
            "Pos8ServletAndSpring.java": (
                "import java.sql.*;\n"
                "import javax.servlet.http.HttpServletRequest;\n"
                "import org.springframework.web.bind.annotation.*;\n"
                "public class Pos8ServletAndSpring {\n"
                "    void servlet(HttpServletRequest req, Statement stmt) throws Exception {\n"
                "        stmt.executeQuery(\"SELECT * FROM t WHERE a = '\" + req.getParameter(\"a\") + \"'\");\n"
                "    }\n"
                "    @GetMapping(\"/s\")\n"
                "    public void spring(@RequestParam(\"b\") String b, Statement stmt) throws Exception {\n"
                "        stmt.executeUpdate(\"DELETE FROM t WHERE b = '\" + b + \"'\");\n"
                "    }\n"
                "}\n"
            ),
            # 9. Second-order ResultSet.getString stays tainted, ResultSet.getInt is sanitized
            "Pos9SecondOrderStringVsSafeInt.java": (
                "import javax.swing.*;\n"
                "import java.sql.*;\n"
                "public class Pos9SecondOrderStringVsSafeInt {\n"
                "    JTextField userField;\n"
                "    void flow(Connection conn) throws Exception {\n"
                "        Statement stmt = conn.createStatement();\n"
                "        ResultSet rs = stmt.executeQuery(\"SELECT id FROM users WHERE u = '\" + userField.getText() + \"'\");\n"
                "        if (rs.next()) {\n"
                "            stmt.executeUpdate(\"UPDATE audit SET uid = \" + rs.getString(\"id\"));\n"
                "            PreparedStatement safeIntPs = conn.prepareStatement(\"SELECT * FROM p WHERE uid = \" + rs.getInt(\"id\"));\n"
                "            safeIntPs.executeQuery();\n"
                "        }\n"
                "    }\n"
                "}\n"
            ),
        }
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for fn, code in cases.items():
                (root / fn).write_text(code, encoding="utf-8")
            doc = _run_opengrep(self.og_bin, root)
            self.assertEqual(doc.get("errors"), [])
            by_file_lines: dict[str, list[int]] = {}
            for r in doc.get("results") or []:
                fn = Path(r["path"]).name
                by_file_lines.setdefault(fn, []).append(int(r["start"]["line"]))
                self.assertIn("cwe89", r["check_id"])

            self.assertIn("Pos1SwingTextFieldExecuteQuery.java", by_file_lines)
            self.assertIn("Pos2SwingPasswordFieldSql.java", by_file_lines)
            self.assertIn("Pos3SwingExecuteUpdate.java", by_file_lines)
            self.assertIn("Pos4SwingPreparedConcat.java", by_file_lines)
            self.assertEqual(len(by_file_lines.get("Pos8ServletAndSpring.java", [])), 2)
            # Pos9: L7 (executeQuery) + L9 (executeUpdate with rs.getString), NOT L10 (rs.getInt)
            self.assertEqual(sorted(by_file_lines.get("Pos9SecondOrderStringVsSafeInt.java", [])), [7, 9])

            for neg in ("Neg5SwingPreparedSafeBind.java", "Neg6SwingConstantSql.java", "Neg7CustomAppGetText.java"):
                self.assertNotIn(neg, by_file_lines, f"Unexpected CWE-89 FP on {neg}: {by_file_lines.get(neg)}")

    def test_cwe22_exists_precheck_excluded_and_real_sinks_preserved(self) -> None:
        cases = {
            "NegExistsOnly.java": (
                "import java.io.*;\n"
                "import javax.servlet.http.HttpServletRequest;\n"
                "public class NegExistsOnly {\n"
                "    boolean check(HttpServletRequest req) {\n"
                "        File f = new File(\"/tmp/base/\" + req.getParameter(\"f\"));\n"
                "        return f.exists() && f.isFile();\n"
                "    }\n"
                "}\n"
            ),
            "PosRealSinks.java": (
                "import java.io.*;\n"
                "import javax.servlet.http.HttpServletRequest;\n"
                "public class PosRealSinks {\n"
                "    void ops(HttpServletRequest req) throws Exception {\n"
                "        String name = req.getParameter(\"f\");\n"
                "        File f = new File(\"/tmp/base/\" + name);\n"
                "        if (f.exists()) {\n"
                "            new FileInputStream(f).close();\n"
                "            new FileOutputStream(f).close();\n"
                "            new FileReader(f).close();\n"
                "            new FileWriter(f).close();\n"
                "            f.delete();\n"
                "            f.mkdirs();\n"
                "        }\n"
                "    }\n"
                "}\n"
            ),
        }
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for fn, code in cases.items():
                (root / fn).write_text(code, encoding="utf-8")
            doc = _run_opengrep(self.og_bin, root)
            self.assertEqual(doc.get("errors"), [])
            by_file_lines: dict[str, list[int]] = {}
            for r in doc.get("results") or []:
                fn = Path(r["path"]).name
                by_file_lines.setdefault(fn, []).append(int(r["start"]["line"]))
            self.assertNotIn("NegExistsOnly.java", by_file_lines)
            # Lines 8..13 (FIS, FOS, FR, FW, delete, mkdirs), NOT line 7 (f.exists())
            self.assertEqual(sorted(by_file_lines.get("PosRealSinks.java", [])), [8, 9, 10, 11, 12, 13])


class HelperFlowPerFqnVerificationTests(unittest.TestCase):
    """Positive JDK/Servlet/Zip/SQL/Swing cases + strict negative app-defined counterexamples."""

    def test_positive_servlet_doget_try_with_resources_and_inherited_get_servlet_context(self) -> None:
        code = (
            "import java.io.*;\n"
            "import javax.servlet.*;\n"
            "import javax.servlet.http.*;\n"
            "public class FileServlet extends HttpServlet {\n"
            "    private static final String BASE_DIR = \"/tmp/userfiles/\";\n"
            "    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {\n"
            "        String fileName = request.getParameter(\"file\");\n"
            "        File file = new File(BASE_DIR + fileName);\n"
            "        if (file.exists() && file.isFile()) {\n"
            "            String contentType = getServletContext().getMimeType(file.getName());\n"
            "            try (FileInputStream in = new FileInputStream(file);\n"
            "                 OutputStream out = response.getOutputStream()) {\n"
            "                byte[] buf = new byte[1024];\n"
            "                int n;\n"
            "                while ((n = in.read(buf)) != -1) {\n"
            "                    out.write(buf, 0, n);\n"
            "                }\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as td:
            rec = _make_record(
                Path(td),
                "FileServlet.java",
                code,
                sink_line=11,
                source_line=7,
                unresolved_calls=[
                    {"method": "isFile", "line": 9},
                    {"qualifier": "FileServlet", "method": "getServletContext", "line": 10, "reason": "missing_helper_implementation"},
                ],
            )
            dep = analyze_flow_dependencies(rec)
            self.assertFalse(dep["has_unverified_helper_dependency"], f"Unexpected helper block: {dep}")
            gated = apply_integration_gate(rec, _supported_assessment(rec, 11))
            self.assertEqual(gated["validated_status"], "SUPPORTED")

    def test_positive_sibling_method_file_var_no_collision_and_zip_and_ois(self) -> None:
        code = (
            "import java.io.*;\n"
            "import java.util.zip.*;\n"
            "import javax.servlet.*;\n"
            "import javax.servlet.http.*;\n"
            "public class FileOpsServlet extends HttpServlet {\n"
            "    private static final String BASE = \"/tmp/\";\n"
            "    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {\n"
            "        String a = req.getParameter(\"a\");\n"
            "        String p = req.getParameter(\"p\");\n"
            "        if (\"del\".equals(a)) { deleteFile(resp, p); }\n"
            "        else if (\"zip\".equals(a)) { extractZip(resp, p); }\n"
            "        else { readSer(p); }\n"
            "    }\n"
            "    private void readFile(HttpServletResponse resp, String p) throws Exception {\n"
            "        File file = new File(BASE, p);\n"
            "        if (file.exists() && file.isFile()) {\n"
            "            try (BufferedReader reader = new BufferedReader(new FileReader(file));\n"
            "                 PrintWriter writer = resp.getWriter()) {\n"
            "                String line;\n"
            "                while ((line = reader.readLine()) != null) { writer.println(line); }\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "    private void deleteFile(HttpServletResponse resp, String p) throws Exception {\n"
            "        File file = new File(BASE + p);\n"
            "        if (file.exists()) {\n"
            "            if (file.delete()) { resp.getWriter().println(\"ok\"); }\n"
            "        }\n"
            "    }\n"
            "    private void extractZip(HttpServletResponse resp, String p) throws Exception {\n"
            "        File zf = new File(BASE, p);\n"
            "        try (ZipInputStream zipIn = new ZipInputStream(new FileInputStream(zf))) {\n"
            "            ZipEntry entry;\n"
            "            while ((entry = zipIn.getNextEntry()) != null) {\n"
            "                String name = entry.getName();\n"
            "                File outF = new File(\"/tmp/out/\", name);\n"
            "                if (entry.isDirectory()) { outF.mkdirs(); }\n"
            "                else {\n"
            "                    outF.getParentFile().mkdirs();\n"
            "                    try (FileOutputStream out = new FileOutputStream(outF)) {\n"
            "                        byte[] b = new byte[1024];\n"
            "                        int n;\n"
            "                        while ((n = zipIn.read(b)) != -1) { out.write(b, 0, n); }\n"
            "                    }\n"
            "                }\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "    private Object readSer(String id) throws Exception {\n"
            "        File file = new File(BASE + id);\n"
            "        if (file.exists()) {\n"
            "            FileInputStream fis = new FileInputStream(file);\n"
            "            ObjectInputStream ois = new ObjectInputStream(fis);\n"
            "            Object obj = ois.readObject();\n"
            "            return obj;\n"
            "        }\n"
            "        return null;\n"
            "    }\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for sink_ln, ucalls in [
                (17, [{"method": "isFile", "line": 16}]),
                (27, []),
                (37, [{"qualifier": "outF", "method": "mkdirs", "line": 37, "reason": "missing_helper_implementation"}]),
                (40, []),
                (52, []),
            ]:
                rec = _make_record(root, "FileOpsServlet.java", code, sink_line=sink_ln, source_line=9, unresolved_calls=ucalls)
                dep = analyze_flow_dependencies(rec)
                self.assertFalse(dep["has_unverified_helper_dependency"], f"Line {sink_ln} unexpectedly blocked: {dep}")

    def test_positive_swing_login_midfile_class_fields_and_chained_trim_equals(self) -> None:
        padding = "\n".join(f"    // pad {i}" for i in range(1, 55))
        code = (
            "import javax.swing.*;\n"
            "import java.awt.event.*;\n"
            "import java.sql.*;\n"
            "public class Login extends JFrame implements ActionListener {\n"
            "    JTextField userName_text;\n"
            "    JPasswordField password_text;\n"
            f"{padding}\n"
            "    public void actionPerformed(ActionEvent ae) {\n"
            "        String user = userName_text.getText();\n"
            "        String password = new String(password_text.getPassword());\n"
            "        try {\n"
            "            Connection conn = DriverManager.getConnection(\"jdbc:h2:mem:x\", \"a\", \"b\");\n"
            "            Statement stmt = conn.createStatement();\n"
            "            ResultSet rs = stmt.executeQuery(\"SELECT * FROM u WHERE n='\" + user + \"' AND p='\" + password + \"'\");\n"
            "            if (rs.next()) {\n"
            "                String uid = rs.getString(\"id\");\n"
            "                stmt.executeUpdate(\"UPDATE u SET x=1 WHERE id=\" + uid);\n"
            "            }\n"
            "        } catch (Exception e) {\n"
            "            if (user.trim().equals(\"admin\")) { System.err.println(e.getMessage()); }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        lines = code.splitlines()
        src_ln = next(i for i, l in enumerate(lines, 1) if "userName_text.getText()" in l)
        sink_ln = next(i for i, l in enumerate(lines, 1) if "stmt.executeQuery(" in l)
        with tempfile.TemporaryDirectory() as td:
            rec = _make_record(
                Path(td),
                "Login.java",
                code,
                sink_line=sink_ln,
                source_line=src_ln,
                rule_id="ntk.api.java.cwe89.sql-injection",
                cwe=["CWE-89"],
            )
            dep = analyze_flow_dependencies(rec)
            self.assertFalse(dep["has_unverified_helper_dependency"], f"Swing Login unexpectedly blocked: {dep}")
            gated = apply_integration_gate(rec, _supported_assessment(rec, sink_ln))
            self.assertEqual(gated["validated_status"], "SUPPORTED")

    def test_negative_app_defined_methods_with_stdlib_names_must_fail_closed(self) -> None:
        """Counterexamples: custom app classes defining exists(), read(), getName(), delete(), mkdirs() MUST fail closed."""
        counterexamples = [
            (
                "custom_exists",
                "import java.io.*;\n"
                "import javax.servlet.http.*;\n"
                "public class AppExists {\n"
                "    void handle(HttpServletRequest req, CustomStore store) throws Exception {\n"
                "        String f = req.getParameter(\"f\");\n"
                "        if (store.exists(f)) {\n"
                "            new FileInputStream(new File(\"/tmp/\" + f));\n"
                "        }\n"
                "    }\n"
                "}\n",
                7,
                5,
                None,
            ),
            (
                "custom_read",
                "import java.io.*;\n"
                "import javax.servlet.http.*;\n"
                "public class AppRead {\n"
                "    void handle(HttpServletRequest req, CustomReader cr) throws Exception {\n"
                "        String f = cr.read(req.getParameter(\"f\"));\n"
                "        new FileInputStream(new File(\"/tmp/\" + f));\n"
                "    }\n"
                "}\n",
                6,
                5,
                None,
            ),
            (
                "custom_getName",
                "import java.io.*;\n"
                "import javax.servlet.http.*;\n"
                "public class AppGetName {\n"
                "    void handle(HttpServletRequest req, CustomEntry ce) throws Exception {\n"
                "        String f = ce.getName(req.getParameter(\"f\"));\n"
                "        new FileInputStream(new File(\"/tmp/\" + f));\n"
                "    }\n"
                "}\n",
                6,
                5,
                None,
            ),
            (
                "chained_evil_factory_getName",
                "import java.io.*;\n"
                "import javax.servlet.http.*;\n"
                "public class AppChainedEvil {\n"
                "    void handle(HttpServletRequest req) throws Exception {\n"
                "        String f = evilFactory(req.getParameter(\"f\")).getName();\n"
                "        new FileInputStream(new File(\"/tmp/\" + f));\n"
                "    }\n"
                "}\n",
                6,
                5,
                None,
            ),
            (
                "custom_base_getServletContext",
                "import java.io.*;\n"
                "import javax.servlet.http.*;\n"
                "public class AppCustomBase extends CustomBaseServlet {\n"
                "    void handle(HttpServletRequest req) throws Exception {\n"
                "        String f = req.getParameter(\"f\");\n"
                "        String m = getServletContext().getMimeType(f);\n"
                "        new FileInputStream(new File(\"/tmp/\" + f));\n"
                "    }\n"
                "}\n",
                7,
                5,
                None,
            ),
            (
                "overridden_getServletContext_in_http_servlet",
                "import java.io.*;\n"
                "import javax.servlet.*;\n"
                "import javax.servlet.http.*;\n"
                "public class AppOverrideServlet extends HttpServlet {\n"
                "    public ServletContext getServletContext() { return null; }\n"
                "    void handle(HttpServletRequest req) throws Exception {\n"
                "        String f = req.getParameter(\"f\");\n"
                "        String m = getServletContext().getMimeType(f);\n"
                "        new FileInputStream(new File(\"/tmp/\" + f));\n"
                "    }\n"
                "}\n",
                9,
                7,
                None,
            ),
            (
                "same_package_shadowed_File",
                "package evil;\n"
                "import java.io.FileInputStream;\n"
                "import javax.servlet.http.*;\n"
                "public class AppShadowFile {\n"
                "    void handle(HttpServletRequest req) throws Exception {\n"
                "        String p = req.getParameter(\"f\");\n"
                "        File f = new File(p);\n"
                "        if (f.exists()) {\n"
                "            new FileInputStream(p);\n"
                "        }\n"
                "    }\n"
                "}\n",
                9,
                6,
                {"evil/File.java": "package evil;\npublic class File { public File(String p){} public boolean exists(){ return true; } }\n"},
            ),
            (
                "mixed_stdlib_and_custom_unresolved_on_same_line",
                "import java.io.*;\n"
                "import javax.servlet.http.*;\n"
                "public class AppMixedLine {\n"
                "    void handle(HttpServletRequest req, CustomStore store) throws Exception {\n"
                "        String p = req.getParameter(\"f\");\n"
                "        File file = new File(\"/tmp/\" + p);\n"
                "        if (file.exists() && store.exists()) {\n"
                "            new FileInputStream(file);\n"
                "        }\n"
                "    }\n"
                "}\n",
                8,
                5,
                None,
            ),
        ]
        for label, code, sink_ln, src_ln, extra_files in counterexamples:
            with self.subTest(case=label):
                with tempfile.TemporaryDirectory() as td:
                    rec = _make_record(
                        Path(td),
                        f"{label}.java" if not extra_files else "evil/AppShadowFile.java",
                        code,
                        sink_line=sink_ln,
                        source_line=src_ln,
                        extra_files=extra_files,
                    )
                    dep = analyze_flow_dependencies(rec)
                    self.assertTrue(
                        dep["has_unverified_helper_dependency"],
                        f"SECURITY REGRESSION: counterexample {label} was NOT blocked! dep={dep}",
                    )
                    gated = apply_integration_gate(rec, _supported_assessment(rec, sink_ln))
                    self.assertEqual(gated["validated_status"], "UNDETERMINED")
                    self.assertEqual(gated["failure_kind"], "UNVERIFIED_HELPER_FLOW")


class CitationIntegrityAndFocusedContextTests(unittest.TestCase):
    """Ensure citation validator stays strictly fail-closed and caller context avoids sibling bloat."""

    def test_citation_validator_still_rejects_lstrip_and_omitted_blank_line(self) -> None:
        code = (
            "import java.io.*;\n"
            "import javax.servlet.http.*;\n"
            "public class CiteCheck {\n"
            "    void handle(HttpServletRequest req) throws Exception {\n"
            "        String f = req.getParameter(\"f\");\n"
            "        File file = new File(\"/tmp/\" + f);\n"
            "            \n"
            "        new FileInputStream(file);\n"
            "    }\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            rec = _make_record(root, "CiteCheck.java", code, sink_line=8, source_line=5)
            fsha = rec["snapshots"]["CiteCheck.java"]["sha256"]
            # 1. Leading whitespace stripped on single line (reproduces FileServlet:187 & SerializationServlet:176)
            ans_lstrip = {
                "status": "SUPPORTED",
                "explanation": "user input flows to FileInputStream",
                "fix_suggestion": "validate canonical path",
                "citations": [
                    {
                        "path": "CiteCheck.java",
                        "start_line": 8,
                        "end_line": 8,
                        "quote": "new FileInputStream(file);",  # missing 8 leading spaces!
                        "sha256": fsha,
                    }
                ],
            }
            with self.assertRaises(EvidenceError):
                validate_answer(json.dumps(ans_lstrip), rec)

            # 2. Multiline quote omitting blank whitespace-only line 7 (reproduces FileServlet:35)
            ans_omitted = {
                "status": "SUPPORTED",
                "explanation": "user input flows to FileInputStream",
                "fix_suggestion": "validate canonical path",
                "citations": [
                    {
                        "path": "CiteCheck.java",
                        "start_line": 6,
                        "end_line": 8,
                        "quote": "        File file = new File(\"/tmp/\" + f);\n        new FileInputStream(file);",
                        "sha256": fsha,
                    }
                ],
            }
            with self.assertRaises(EvidenceError):
                validate_answer(json.dumps(ans_omitted), rec)

            # 3. Wrong sha256 hash MUST be rejected
            ans_bad_hash = {
                "status": "SUPPORTED",
                "explanation": "user input flows to FileInputStream",
                "fix_suggestion": "validate canonical path",
                "citations": [
                    {
                        "path": "CiteCheck.java",
                        "start_line": 8,
                        "end_line": 8,
                        "quote": "        new FileInputStream(file);",
                        "sha256": "0" * 64,
                    }
                ],
            }
            with self.assertRaises(EvidenceError):
                validate_answer(json.dumps(ans_bad_hash), rec)

            # 4. Verbatim exact quote with leading spaces and blank line -> SUPPORTED
            exact_quote = (
                "        File file = new File(\"/tmp/\" + f);\n"
                "            \n"
                "        new FileInputStream(file);"
            )
            ans_exact = {
                "status": "SUPPORTED",
                "explanation": "user input flows to FileInputStream",
                "fix_suggestion": "validate canonical path",
                "citations": [
                    {
                        "path": "CiteCheck.java",
                        "start_line": 6,
                        "end_line": 8,
                        "quote": exact_quote,
                        "sha256": fsha,
                    }
                ],
            }
            v_exact = validate_answer(json.dumps(ans_exact), rec)
            self.assertEqual(v_exact["status"], "SUPPORTED")

    def test_focused_caller_context_does_not_expand_unrelated_siblings_and_compacts_helper_overlap(self) -> None:
        pad = "\n".join(f"        // spacer {i}" for i in range(1, 35))
        code = (
            "import java.io.*;\n"
            "import javax.servlet.http.*;\n"
            "public class DispatchServlet extends HttpServlet {\n"
            "    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {\n"
            "        String a = req.getParameter(\"a\");\n"
            "        String p = req.getParameter(\"p\");\n"
            "        if (\"r\".equals(a)) { readFile(p); }\n"
            "        else if (\"w\".equals(a)) { writeFile(p); }\n"
            "        else { extractZip(p); }\n"
            "    }\n"
            "    private void readFile(String p) throws Exception {\n"
            f"{pad}\n"
            "        new FileReader(p);\n"
            "    }\n"
            "    private void writeFile(String p) throws Exception {\n"
            f"{pad}\n"
            "        new FileWriter(p);\n"
            "    }\n"
            "    private void extractZip(String p) throws Exception {\n"
            f"{pad}\n"
            "        new FileInputStream(p);\n"
            "    }\n"
            "}\n"
        )
        lines = code.splitlines()
        src_ln = next(i for i, l in enumerate(lines, 1) if 'req.getParameter("p")' in l)
        sink_ln = next(i for i, l in enumerate(lines, 1) if "new FileInputStream(p)" in l)
        jctx, _distant, _enc = extract_java_context_v2(code, sink_ln, sink_ln, trace_lines=[src_ln, sink_ln])
        callee_names = [c["name"] for c in jctx["same_file_callees"]]
        self.assertEqual(callee_names, ["doPost"])
        self.assertNotIn("readFile", callee_names)
        self.assertNotIn("writeFile", callee_names)

        with tempfile.TemporaryDirectory() as td:
            rec = _make_record(Path(td), "DispatchServlet.java", code, sink_line=sink_ln, source_line=src_ln)
            src_snips = [s for s in rec["snippets"] if s.get("role") == "source"]
            self.assertTrue(src_snips)
            # Source line is covered by attached `doPost` helper snippet, so compacted to exact 1-line span
            self.assertEqual(len(src_snips[0]["lines"]), 1)
            self.assertEqual(src_snips[0]["lines"][0]["line"], src_ln)


if __name__ == "__main__":
    unittest.main()
