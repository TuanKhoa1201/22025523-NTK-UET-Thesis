"""Real OpenGrep positive/negative test suite for v2/api/rules/java_cwe22_cwe89.yml.

Covers Java CWE-22 (Path Traversal) and CWE-89 (SQL Injection) positive cases, safe negative
controls (parameterized PreparedStatement/JdbcTemplate, non-SQL .execute(), numeric parseInt,
FilenameUtils.getName), and counterexamples CE01..CE09. Skips explicitly with ENV_BLOCKED
when no local OpenGrep binary is available in the test environment.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from v2.api.config import DEFAULT_BACKEND_RULES, REPO_ROOT


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


class JavaRulesCwe22Cwe89Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.og_bin = _resolve_opengrep_binary()
        if not cls.og_bin:
            raise unittest.SkipTest("ENV_BLOCKED: no local OpenGrep binary found for ruleset integration test")

    def test_positive_and_negative_java_cwe22_cwe89_matrix(self) -> None:
        cases = {
            # --- CWE-89 POSITIVES ---
            "PosSqliStatement.java": (
                "package cases;\n"
                "import java.sql.*;\n"
                "import javax.servlet.http.HttpServletRequest;\n"
                "public class PosSqliStatement {\n"
                "    public void run(HttpServletRequest req, Statement st) throws Exception {\n"
                "        String u = req.getParameter(\"user\");\n"
                "        st.executeQuery(\"SELECT * FROM users WHERE name='\" + u + \"'\");\n"
                "    }\n"
                "}\n"
            ),
            "PosSqliPreparedConcat.java": (
                "package cases;\n"
                "import java.sql.*;\n"
                "import org.springframework.web.bind.annotation.*;\n"
                "public class PosSqliPreparedConcat {\n"
                "    @GetMapping(\"/find\")\n"
                "    public void find(@RequestParam(\"u\") String u, Connection c) throws Exception {\n"
                "        PreparedStatement ps = c.prepareStatement(\"SELECT * FROM users WHERE u='\" + u + \"'\");\n"
                "        ps.executeQuery();\n"
                "    }\n"
                "}\n"
            ),
            "PosSqliJdbcTemplateConcat.java": (
                "package cases;\n"
                "import org.springframework.jdbc.core.JdbcTemplate;\n"
                "import org.springframework.web.bind.annotation.*;\n"
                "public class PosSqliJdbcTemplateConcat {\n"
                "    @GetMapping(\"/jt\")\n"
                "    public void find(@PathVariable(\"id\") String id, JdbcTemplate jt) {\n"
                "        jt.queryForList(\"SELECT * FROM items WHERE id=\" + id);\n"
                "    }\n"
                "}\n"
            ),
            "PosSqliEntityManagerNative.java": (
                "package cases;\n"
                "import javax.persistence.EntityManager;\n"
                "import org.springframework.web.bind.annotation.*;\n"
                "public class PosSqliEntityManagerNative {\n"
                "    @PostMapping(\"/em\")\n"
                "    public void find(@RequestBody String q, EntityManager em) {\n"
                "        em.createNativeQuery(\"SELECT * FROM logs WHERE tag='\" + q + \"'\").getResultList();\n"
                "    }\n"
                "}\n"
            ),
            "PosSqliIntrafileHelper.java": (
                "package cases;\n"
                "import java.sql.*;\n"
                "import org.springframework.web.bind.annotation.*;\n"
                "public class PosSqliIntrafileHelper {\n"
                "    @PostMapping(\"/helper\")\n"
                "    public void entry(@RequestParam String acct, Connection conn) throws Exception {\n"
                "        runQuery(conn, acct);\n"
                "    }\n"
                "    private void runQuery(Connection conn, String a) throws Exception {\n"
                "        Statement s = conn.createStatement();\n"
                "        s.execute(\"SELECT * FROM acct WHERE name='\" + a + \"'\");\n"
                "    }\n"
                "}\n"
            ),
            "PosSqliStaticJdbcHolder.java": (
                "package cases;\n"
                "import javax.servlet.http.HttpServletRequest;\n"
                "public class PosSqliStaticJdbcHolder {\n"
                "    public void run(HttpServletRequest req) {\n"
                "        String name = req.getParameter(\"name\");\n"
                "        AppDbHolder.jdbcTemplate.update(\"DELETE FROM sessions WHERE owner='\" + name + \"'\");\n"
                "    }\n"
                "}\n"
            ),
            # --- CWE-89 NEGATIVES (MUST BE 0 FINDINGS) ---
            "NegSqliEntityManagerSafeBind.java": (
                "package cases;\n"
                "import javax.persistence.EntityManager;\n"
                "import org.springframework.web.bind.annotation.*;\n"
                "public class NegSqliEntityManagerSafeBind {\n"
                "    @PostMapping(\"/emsafe\")\n"
                "    public void find(@RequestBody String q, EntityManager em) {\n"
                "        em.createNativeQuery(\"SELECT * FROM logs WHERE tag = :tag\").setParameter(\"tag\", q).getResultList();\n"
                "    }\n"
                "}\n"
            ),
            "NegSqliPreparedSafeBind.java": (
                "package cases;\n"
                "import java.sql.*;\n"
                "import org.springframework.web.bind.annotation.*;\n"
                "public class NegSqliPreparedSafeBind {\n"
                "    @GetMapping(\"/safe\")\n"
                "    public void find(@RequestParam(\"u\") String u, Connection c) throws Exception {\n"
                "        PreparedStatement ps = c.prepareStatement(\"SELECT * FROM users WHERE u = ?\");\n"
                "        ps.setString(1, u);\n"
                "        ps.executeQuery();\n"
                "    }\n"
                "}\n"
            ),
            "NegSqliJdbcTemplateSafeBind.java": (
                "package cases;\n"
                "import org.springframework.jdbc.core.JdbcTemplate;\n"
                "import org.springframework.web.bind.annotation.*;\n"
                "public class NegSqliJdbcTemplateSafeBind {\n"
                "    @GetMapping(\"/safejt\")\n"
                "    public void find(@RequestParam(\"u\") String u, JdbcTemplate jt) {\n"
                "        jt.queryForList(\"SELECT * FROM users WHERE u = ?\", u);\n"
                "    }\n"
                "}\n"
            ),
            "NegNonSqlRouterExecute.java": (
                "package cases;\n"
                "import javax.servlet.http.HttpServletRequest;\n"
                "public class NegNonSqlRouterExecute {\n"
                "    static class Router { void execute(String ctx) {} }\n"
                "    public void filter(HttpServletRequest req, Router r) {\n"
                "        String path = req.getHeader(\"X-Path\");\n"
                "        r.execute(path);\n"
                "    }\n"
                "}\n"
            ),
            "NegSqliParseIntSafe.java": (
                "package cases;\n"
                "import java.sql.*;\n"
                "import javax.servlet.http.HttpServletRequest;\n"
                "public class NegSqliParseIntSafe {\n"
                "    public void run(HttpServletRequest req, Statement st) throws Exception {\n"
                "        int id = Integer.parseInt(req.getParameter(\"id\"));\n"
                "        st.executeQuery(\"SELECT * FROM users WHERE id=\" + id);\n"
                "    }\n"
                "}\n"
            ),
            # --- CWE-22 POSITIVES ---
            "PosCwe22FilesRead.java": (
                "package cases;\n"
                "import java.nio.file.*;\n"
                "import org.springframework.web.bind.annotation.*;\n"
                "public class PosCwe22FilesRead {\n"
                "    @GetMapping(\"/dl/{name}\")\n"
                "    public byte[] dl(@PathVariable(\"name\") String name) throws Exception {\n"
                "        return Files.readAllBytes(Paths.get(\"/srv/files\", name));\n"
                "    }\n"
                "}\n"
            ),
            "PosCwe22FileWriter.java": (
                "package cases;\n"
                "import java.io.*;\n"
                "import javax.servlet.http.HttpServletRequest;\n"
                "public class PosCwe22FileWriter {\n"
                "    public void save(HttpServletRequest req) throws Exception {\n"
                "        String[] vals = req.getParameterValues(\"target\");\n"
                "        FileWriter fw = new FileWriter(new File(\"/srv/out\", vals[0]));\n"
                "        fw.write(\"ok\");\n"
                "    }\n"
                "}\n"
            ),
            "PosCwe22SpringIntrafileHelper.java": (
                "package cases;\n"
                "import java.io.IOException;\n"
                "import java.nio.file.*;\n"
                "import org.springframework.web.bind.annotation.*;\n"
                "public class PosCwe22SpringIntrafileHelper {\n"
                "    @GetMapping(\"/img\")\n"
                "    public byte[] img(@RequestParam(\"filepath\") String filepath) throws IOException {\n"
                "        return load(filepath);\n"
                "    }\n"
                "    private byte[] load(String f) throws IOException {\n"
                "        return Files.readAllBytes(Paths.get(f));\n"
                "    }\n"
                "}\n"
            ),
            # --- Bare FilenameUtils.getName without '..'/boundary check MUST NOT be suppressed (P0-V) ---
            "PosCwe22FilenameUtilsOnly.java": (
                "package cases;\n"
                "import java.io.*;\n"
                "import javax.servlet.http.HttpServletRequest;\n"
                "import org.apache.commons.io.FilenameUtils;\n"
                "public class PosCwe22FilenameUtilsOnly {\n"
                "    public FileInputStream open(HttpServletRequest req) throws Exception {\n"
                "        String safe = FilenameUtils.getName(req.getParameter(\"f\"));\n"
                "        return new FileInputStream(new File(\"/srv/files\", safe));\n"
                "    }\n"
                "}\n"
            ),
            # --- CWE-22 NEGATIVES (MUST BE 0 FINDINGS) ---
            "NegCwe22ParseIntPath.java": (
                "package cases;\n"
                "import java.nio.file.*;\n"
                "import javax.servlet.http.HttpServletRequest;\n"
                "public class NegCwe22ParseIntPath {\n"
                "    public byte[] readById(HttpServletRequest req) throws Exception {\n"
                "        int docId = Integer.parseInt(req.getParameter(\"id\"));\n"
                "        return Files.readAllBytes(Paths.get(\"/srv/files/\" + docId + \".bin\"));\n"
                "    }\n"
                "}\n"
            ),
            "NegCwe22WriteContentToFixedPath.java": (
                "package cases;\n"
                "import java.nio.file.*;\n"
                "import javax.servlet.http.HttpServletRequest;\n"
                "public class NegCwe22WriteContentToFixedPath {\n"
                "    public void log(HttpServletRequest req) throws Exception {\n"
                "        String body = req.getParameter(\"note\");\n"
                "        Files.writeString(Paths.get(\"/srv/logs/audit.txt\"), body);\n"
                "    }\n"
                "}\n"
            ),
        }
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for fname, code in cases.items():
                (root / fname).write_text(code, encoding="utf-8")
            doc = _run_opengrep(self.og_bin, root)
            self.assertEqual(doc.get("errors"), [])
            by_file: dict[str, set[str]] = {}
            for r in doc.get("results") or []:
                fn = Path(r["path"]).name
                by_file.setdefault(fn, set()).add(r["check_id"])
                self.assertTrue(r.get("extra", {}).get("dataflow_trace"), f"missing dataflow_trace for {fn}")

            expected_pos = {
                "PosSqliStatement.java": "ntk.api.java.cwe89.sql-injection",
                "PosSqliPreparedConcat.java": "ntk.api.java.cwe89.sql-injection",
                "PosSqliJdbcTemplateConcat.java": "ntk.api.java.cwe89.sql-injection",
                "PosSqliEntityManagerNative.java": "ntk.api.java.cwe89.sql-injection",
                "PosSqliIntrafileHelper.java": "ntk.api.java.cwe89.sql-injection",
                "PosSqliStaticJdbcHolder.java": "ntk.api.java.cwe89.sql-injection",
                "PosCwe22FilesRead.java": "ntk.api.java.cwe22.path-traversal",
                "PosCwe22FileWriter.java": "ntk.api.java.cwe22.path-traversal",
                "PosCwe22SpringIntrafileHelper.java": "ntk.api.java.cwe22.path-traversal",
                "PosCwe22FilenameUtilsOnly.java": "ntk.api.java.cwe22.path-traversal",
            }
            for fn, rule_id in expected_pos.items():
                got = by_file.get(fn, set())
                self.assertTrue(
                    any(cid == rule_id or cid.endswith("." + rule_id) for cid in got),
                    f"expected {rule_id} on {fn}, got {got}",
                )

            expected_neg = [
                "NegSqliEntityManagerSafeBind.java",
                "NegSqliPreparedSafeBind.java",
                "NegSqliJdbcTemplateSafeBind.java",
                "NegNonSqlRouterExecute.java",
                "NegSqliParseIntSafe.java",
                "NegCwe22ParseIntPath.java",
                "NegCwe22WriteContentToFixedPath.java",
            ]
            for fn in expected_neg:
                self.assertNotIn(fn, by_file, f"unexpected false positive on {fn}: {by_file.get(fn)}")

    def test_demo_fixtures_and_counterexamples_preserved(self) -> None:
        demo_dir = REPO_ROOT / "v2" / "g1_integration" / "demo_fixtures"
        doc = _run_opengrep(self.og_bin, demo_dir)
        self.assertEqual(doc.get("errors"), [])
        self.assertEqual(len(doc.get("results") or []), 5)

        ce_dir = REPO_ROOT / "v2" / "triage" / "tests" / "fixtures" / "counterexamples"
        # Copy CE01..CE09 into a non-'tests' directory so OpenGrep default ignore does not skip them
        with tempfile.TemporaryDirectory() as td:
            stage = Path(td) / "ce_stage"
            stage.mkdir()
            for jf in sorted(ce_dir.glob("CE0[1-9]_*.java")):
                shutil.copy2(jf, stage / jf.name)
            ce_doc = _run_opengrep(self.og_bin, stage)
            self.assertEqual(ce_doc.get("errors"), [])
            hit_files = {Path(r["path"]).name for r in ce_doc.get("results") or []}
            for i in range(1, 10):
                prefix = f"CE0{i}_"
                self.assertTrue(
                    any(fn.startswith(prefix) for fn in hit_files),
                    f"counterexample {prefix}* was not detected: {sorted(hit_files)}",
                )


    def test_ruleset_has_no_benchmark_specific_hardcoding(self) -> None:
        raw_yml = DEFAULT_BACKEND_RULES.read_text(encoding="utf-8").lower()
        self.assertNotIn("owasp.benchmark", raw_yml)
        self.assertNotIn("databasehelper", raw_yml)


if __name__ == "__main__":
    unittest.main()
