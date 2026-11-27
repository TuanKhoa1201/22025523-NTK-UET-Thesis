"""Targeted unit & adversarial counterexample tests for backend G3 quality improvements (Areas B, C, D2, E).

Self-contained: uses only temporary directories and synthetic Java fixtures (zero private paths or external assets).
"""
from __future__ import annotations

import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from v2.api.config import ApiConfig
from v2.api.java_context_v2 import (
    analyze_flow_dependencies,
    enrich_bundle_context,
)
from v2.api.opengrep_runner import compute_opengrep_coverage_telemetry
from v2.api.service import TriageApiService
from v2.api.triage_gate import (
    SUPPORTED_REFUTATION_PROOF_CLASSES,
    apply_integration_gate,
)
from v2.triage import evidence, ollama
from v2.triage.store import ReviewStore


def _make_record(
    tmp_root: Path,
    rel_path: str,
    java_code: str,
    *,
    sink_line: int,
    cwe: str = "CWE-89",
    rule_id: str = "java.lang.security.audit.sqli.tainted-sql-string",
    extra_files: dict[str, str] | None = None,
    use_manifest_file: bool = False,
    tamper_manifest: bool = False,
    tamper_extra_after_hash: str | None = None,
) -> tuple[dict, str]:
    """Create a realistic SHA-256-verified evidence record enriched via `enrich_bundle_context`."""
    target = tmp_root / rel_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(java_code.encode("utf-8"))

    hashes: dict[str, str] = {rel_path.replace("\\", "/"): evidence.digest(target.read_bytes())}
    for extra_rel, extra_src in (extra_files or {}).items():
        ef = tmp_root / extra_rel
        ef.parent.mkdir(parents=True, exist_ok=True)
        ef.write_bytes(extra_src.encode("utf-8"))
        hashes[extra_rel.replace("\\", "/")] = evidence.digest(ef.read_bytes())

    prov: dict = {
        "origin": "real_scan",
        "source_capture_verified": True,
        "exit_capture_verified": True,
        "recorded_engine_exit": 0,
    }
    if use_manifest_file:
        manifest_dir = tmp_root.parent / "_capture"
        manifest_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = manifest_dir / "scan-manifest.json"
        man_doc = {
            "sources_before": dict(hashes),
            "sources_after": dict(hashes),
        }
        man_bytes = json.dumps(man_doc).encode("utf-8")
        manifest_path.write_bytes(man_bytes)
        prov["manifest_path"] = str(manifest_path)
        prov["manifest_sha256"] = ("0" * 64) if tamper_manifest else evidence.digest(man_bytes)
    else:
        prov["source_hashes"] = dict(hashes)

    if tamper_extra_after_hash:
        tf = tmp_root / tamper_extra_after_hash
        tf.write_text(tf.read_text(encoding="utf-8") + "\n// tampered\n", encoding="utf-8")

    lines_ke = java_code.splitlines(keepends=True)
    row = lines_ke[sink_line - 1].rstrip("\r\n")
    stripped = row.lstrip()
    col0 = len(row) - len(stripped)
    off = sum(len(x.encode("utf-8")) for x in lines_ke[: sink_line - 1]) + len(row[:col0].encode("utf-8"))
    tok_bytes = stripped.encode("utf-8")
    snk_loc = {
        "path": rel_path.replace("\\", "/"),
        "start": {"line": sink_line, "col": len(row[:col0].encode("utf-8")) + 1, "offset": off},
        "end": {"line": sink_line, "col": len(row[:col0].encode("utf-8")) + len(tok_bytes) + 1, "offset": off + len(tok_bytes)},
    }
    raw_og = {
        "version": "1.25.0",
        "results": [
            {
                "check_id": rule_id,
                **snk_loc,
                "extra": {
                    "message": f"Synthetic finding for {cwe}",
                    "severity": "WARNING",
                    "metadata": {"cwe": [f"{cwe}: Synthetic"]},
                    "lines": row,
                    "dataflow_trace": {
                        "taint_source": ["CliLoc", [snk_loc, stripped]],
                        "intermediate_vars": [],
                        "taint_sink": ["CliLoc", [snk_loc, stripped]],
                    },
                },
            }
        ],
        "paths": {"scanned": [rel_path.replace("\\", "/")]},
    }
    raw_bytes = json.dumps(raw_og).encode("utf-8")
    bundle = evidence.collect(raw_bytes, tmp_root, None, 0, [], scan_provenance=prov)
    bundle["scan_provenance"] = prov
    enrich_bundle_context(bundle, tmp_root)
    rec = bundle["records"][0]
    rec["scan_provenance"] = prov
    return rec, hashes[rel_path.replace("\\", "/")]


def _mock_model_assessment(rec: dict, status: str, cite_lines: list[int] | None = None) -> dict:
    snip = rec["snippets"][0]
    by_line = {ln["line"]: ln["text"] for ln in snip["lines"]}
    chosen = cite_lines
    if chosen is None:
        sink_ln = (rec.get("heuristic_signals") or {}).get("sink_line") or (rec.get("start") or {}).get("line")
        exec_lines = [
            ln
            for ln, txt in sorted(by_line.items())
            if txt.strip() and not txt.strip().startswith(("/", "*", "@", "package ", "import ", "{", "}"))
        ]
        chosen = []
        if isinstance(sink_ln, int) and sink_ln in by_line:
            chosen.append(sink_ln)
        for ln in exec_lines:
            if ln not in chosen:
                chosen.append(ln)
            if len(chosen) >= 3:
                break
        chosen.sort()
    cites = [
        {
            "path": snip["path"],
            "start_line": ln,
            "end_line": ln,
            "quote": by_line[ln],
            "sha256": snip["sha256"],
        }
        for ln in chosen
        if ln in by_line
    ]
    return {
        "status": status,
        "raw_model_status": status,
        "validated_status": status,
        "validator_downgraded": False,
        "failure_kind": None,
        "explanation": "Phân tích luồng dữ liệu mã nguồn tổng hợp.",
        "fix_suggestion": "Giữ nguyên xác minh đầu vào.",
        "citations": cites,
        "citation_check": "MATCHED",
        "citation_provenance": {
            "citation_in_source": True,
            "citation_in_prompt": True,
            "citation_posthoc_only": False,
            "supports_security_claim_verified": False,
        },
        "prompt_version": ollama.PROMPT_VERSION,
        "security_conclusion_verified": False,
        "requires_human_review": True,
        "runtime": {
            "origin": "mock",
            "request_attempted": True,
            "http_response_received": True,
            "http_status": 200,
            "response_complete": True,
            "answer_validated": True,
            "model_identity_matched": True,
            "model_runtime_verified": False,
        },
    }


class AreaBJavaContextTests(unittest.TestCase):
    def test_b1_multiline_try_and_classic_for_and_primitive_sink_decl(self) -> None:
        code = (
            "package demo;\n"
            "import java.sql.Connection;\n"
            "import java.sql.Statement;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class DemoMulti {\n"
            "    public void handle(HttpServletRequest request) throws Exception {\n"
            "        String[] vals = request.getParameterValues(\"k\");\n"
            "        String bar = \"\";\n"
            "        if (vals != null) {\n"
            "            for (int i = 0; i < vals.length; i++) {\n"
            "                bar = vals[i];\n"
            "            }\n"
            "        }\n"
            "        String sql = \"UPDATE users SET a='\" + bar + \"'\";\n"
            "        try (\n"
            "            Connection conn =\n"
            "                HelperDb.getConn();\n"
            "            Statement stmt =\n"
            "                conn.createStatement()\n"
            "        ) {\n"
            "            int count = stmt.executeUpdate(sql, new String[] {\"ID\"});\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as td:
            rec, _ = _make_record(Path(td) / "src", "demo/DemoMulti.java", code, sink_line=21)
            dep = analyze_flow_dependencies(rec)
            self.assertFalse(dep["has_unverified_helper_dependency"], dep)
            self.assertFalse(dep["flow_slice_summary"]["has_mutable_nonlocal"])
            self.assertNotIn("stmt", dep["flow_slice_summary"]["sink_backward_vars"])
            self.assertIn("sql", dep["flow_slice_summary"]["sink_backward_vars"])

    def test_b1_var_stdlib_call_resolves_while_bare_alias_and_custom_ctor_fail_closed(self) -> None:
        stdlib_var_code = (
            "package demo;\n"
            "import java.io.File;\n"
            "import java.nio.file.Files;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class DemoVarStdlib {\n"
            "    public void run(HttpServletRequest req) throws Exception {\n"
            "        String name = req.getParameter(\"f\");\n"
            "        var baseDir = Files.createTempDirectory(\"app-\");\n"
            "        var target = baseDir.resolve(name);\n"
            "        Files.deleteIfExists(target);\n"
            "    }\n"
            "}\n"
        )
        bare_alias_code = (
            "package demo;\n"
            "import java.sql.Statement;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class DemoVarAlias {\n"
            "    public void run(HttpServletRequest raw, Statement stmt) throws Exception {\n"
            "        var req = raw;\n"
            "        String u = req.getParameter(\"u\");\n"
            "        stmt.executeQuery(\"SELECT * FROM t WHERE a='\" + u + \"'\");\n"
            "    }\n"
            "}\n"
        )
        custom_ctor_code = (
            "package demo;\n"
            "import java.sql.Statement;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class DemoVarCustom {\n"
            "    public void run(HttpServletRequest req, Statement stmt) throws Exception {\n"
            "        var tool = new custom.Tools();\n"
            "        String u = tool.clean(req.getParameter(\"u\"));\n"
            "        stmt.executeQuery(\"SELECT * FROM t WHERE a='\" + u + \"'\");\n"
            "    }\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as td:
            r1, _ = _make_record(Path(td) / "s1", "demo/DemoVarStdlib.java", stdlib_var_code, sink_line=10, cwe="CWE-22")
            self.assertFalse(analyze_flow_dependencies(r1)["has_unverified_helper_dependency"])

            r2, _ = _make_record(Path(td) / "s2", "demo/DemoVarAlias.java", bare_alias_code, sink_line=8)
            self.assertTrue(analyze_flow_dependencies(r2)["has_unverified_helper_dependency"])

            r3, _ = _make_record(Path(td) / "s3", "demo/DemoVarCustom.java", custom_ctor_code, sink_line=8)
            self.assertTrue(analyze_flow_dependencies(r3)["has_unverified_helper_dependency"])

    def test_b2_verified_static_stdlib_field_via_manifest_and_tamper_counterexamples(self) -> None:
        caller_code = (
            "package demo;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class DemoJdbcField {\n"
            "    public void run(HttpServletRequest req) {\n"
            "        String p = req.getParameter(\"p\");\n"
            "        String sql = \"SELECT * FROM t WHERE a='\" + p + \"'\";\n"
            "        DbHolder.JDBC.queryForList(sql);\n"
            "    }\n"
            "}\n"
        )
        good_helper = (
            "package demo;\n"
            "import org.springframework.jdbc.core.JdbcTemplate;\n"
            "public class DbHolder {\n"
            "    public static JdbcTemplate JDBC;\n"
            "}\n"
        )
        non_stdlib_helper = (
            "package demo;\n"
            "public class DbHolder {\n"
            "    public static CustomExecutor JDBC;\n"
            "}\n"
        )
        non_static_helper = (
            "package demo;\n"
            "import org.springframework.jdbc.core.JdbcTemplate;\n"
            "public class DbHolder {\n"
            "    public JdbcTemplate JDBC;\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as td:
            # 1. Valid double-SHA-256 chain via scan-manifest.json
            r_ok, _ = _make_record(
                Path(td) / "ok" / "src",
                "demo/DemoJdbcField.java",
                caller_code,
                sink_line=7,
                extra_files={"demo/DbHolder.java": good_helper},
                use_manifest_file=True,
            )
            self.assertFalse(analyze_flow_dependencies(r_ok)["has_unverified_helper_dependency"])

            # 2. Tampered DbHolder.java on disk -> fails closed
            r_tamper_file, _ = _make_record(
                Path(td) / "tf" / "src",
                "demo/DemoJdbcField.java",
                caller_code,
                sink_line=7,
                extra_files={"demo/DbHolder.java": good_helper},
                use_manifest_file=True,
                tamper_extra_after_hash="demo/DbHolder.java",
            )
            self.assertTrue(analyze_flow_dependencies(r_tamper_file)["has_unverified_helper_dependency"])

            # 3. Tampered scan-manifest.json sha256 -> fails closed
            r_tamper_man, _ = _make_record(
                Path(td) / "tm" / "src",
                "demo/DemoJdbcField.java",
                caller_code,
                sink_line=7,
                extra_files={"demo/DbHolder.java": good_helper},
                use_manifest_file=True,
                tamper_manifest=True,
            )
            self.assertTrue(analyze_flow_dependencies(r_tamper_man)["has_unverified_helper_dependency"])

            # 4. Non-stdlib static field -> fails closed
            r_custom, _ = _make_record(
                Path(td) / "nc" / "src",
                "demo/DemoJdbcField.java",
                caller_code,
                sink_line=7,
                extra_files={"demo/DbHolder.java": non_stdlib_helper},
                use_manifest_file=True,
            )
            self.assertTrue(analyze_flow_dependencies(r_custom)["has_unverified_helper_dependency"])

            # 5. Non-static instance field -> fails closed
            r_nonstatic, _ = _make_record(
                Path(td) / "ns" / "src",
                "demo/DemoJdbcField.java",
                caller_code,
                sink_line=7,
                extra_files={"demo/DbHolder.java": non_static_helper},
                use_manifest_file=True,
            )
            self.assertTrue(analyze_flow_dependencies(r_nonstatic)["has_unverified_helper_dependency"])


class AreaCCitationAndPromptTests(unittest.TestCase):
    def test_c_v225_schema_property_order_blind_contract_and_strict_validator(self) -> None:
        self.assertEqual(ollama.PROMPT_VERSION, "v2.2.6-cwe22-cwe89-strict-singleline-max3-citations")
        self.assertEqual(
            ollama.PREVIOUS_V225_PROMPT_VERSION,
            "v2.2.5-cwe22-cwe89-exec-citations-and-flow-rebuttal",
        )
        self.assertEqual(
            ollama.PREVIOUS_MINIMAL_SINGLELINE_PROMPT_VERSION,
            "v2.2.4-cwe22-cwe89-minimal-singleline-citations",
        )
        self.assertEqual(
            list(ollama.SCHEMA["properties"].keys()),
            ["explanation", "citations", "status", "fix_suggestion"],
        )
        self.assertEqual(
            ollama.SCHEMA["required"],
            ["explanation", "citations", "status", "fix_suggestion"],
        )
        self.assertEqual(ollama.SCHEMA["properties"]["citations"].get("maxItems"), 3)

        code = (
            "package demo;\n"
            "import java.sql.Statement;\n"
            "public class DemoAnnot {\n"
            "    public void login(\n"
            "        @RequestParam(\"user\") String user,\n"
            "        Statement stmt\n"
            "    ) throws Exception {\n"
            "        String sql = \"SELECT * FROM u WHERE name='\" + user + \"'\";\n"
            "        stmt.executeQuery(sql);\n"
            "    }\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as td:
            rec, sha = _make_record(Path(td) / "src", "demo/DemoAnnot.java", code, sink_line=9)
            req = ollama.request_payload(rec, "qwen3.5:9b-q4_K_M")
            self.assertFalse(req["think"])
            sys_txt = req["messages"][0]["content"]
            self.assertIn("@RequestParam", sys_txt)
            self.assertIn("PreparedStatement sanitizes CWE-89 ONLY", sys_txt)
            self.assertIn("DISTINCT SINGLE-LINE citations", sys_txt)
            self.assertIn("start_line == end_line", sys_txt)
            self.assertNotIn("(end_line - start_line + 1)", sys_txt)
            for banned in ("WebGoat", "BenchmarkTest", "AddPage", "ground_truth", "recommended_status"):
                self.assertNotIn(banned, sys_txt)

            # Legacy v2.1 forensic schema order MUST remain preserved
            leg = ollama.legacy_v2_1_request_payload(rec, "qwen3.5:9b-q4_K_M")
            self.assertEqual(leg["format"]["required"], ["status", "explanation", "citations", "fix_suggestion"])

            # Strict citation validator MUST still reject annotation-only citation fail-closed
            client = ollama.OllamaClient(runtime_origin="mock")
            bad_answer = {
                "explanation": "Lỗ hổng SQLi từ tham số user.",
                "citations": [
                    {
                        "path": "demo/DemoAnnot.java",
                        "start_line": 5,
                        "end_line": 5,
                        "quote": '        @RequestParam("user") String user,',
                        "sha256": sha,
                    }
                ],
                "status": "SUPPORTED",
                "fix_suggestion": "Dùng PreparedStatement.",
            }
            resp = {"model": client.model, "done": True, "mock_test_fixture": True, "message": {"content": json.dumps(bad_answer)}}
            with patch.object(client, "request", return_value=resp):
                out = client.analyze(rec)
            self.assertEqual(out["status"], "UNDETERMINED")
            self.assertEqual(out["failure_kind"], "INVALID_CITATION")
            self.assertTrue(out["validator_downgraded"])

            # Single-line executable body citations pass cleanly
            good_answer = copy.deepcopy(bad_answer)
            good_answer["citations"] = [
                {
                    "path": "demo/DemoAnnot.java",
                    "start_line": 8,
                    "end_line": 8,
                    "quote": '        String sql = "SELECT * FROM u WHERE name=\'" + user + "\'";',
                    "sha256": sha,
                },
                {
                    "path": "demo/DemoAnnot.java",
                    "start_line": 9,
                    "end_line": 9,
                    "quote": "        stmt.executeQuery(sql);",
                    "sha256": sha,
                },
            ]
            resp2 = {"model": client.model, "done": True, "mock_test_fixture": True, "message": {"content": json.dumps(good_answer)}}
            with patch.object(client, "request", return_value=resp2):
                out2 = client.analyze(rec)
            self.assertEqual(out2["status"], "SUPPORTED")
            self.assertEqual(out2["citation_check"], "MATCHED")


class AreaD2RefutationProofAndCounterexampleTests(unittest.TestCase):
    def _gate_refuted(self, java_code: str, sink_line: int, *, cwe: str = "CWE-89", extra_files: dict[str, str] | None = None, use_manifest: bool = False) -> dict:
        with tempfile.TemporaryDirectory() as td:
            rec, _ = _make_record(
                Path(td) / "src",
                "demo/Case.java",
                java_code,
                sink_line=sink_line,
                cwe=cwe,
                extra_files=extra_files,
                use_manifest_file=use_manifest,
            )
            ass = _mock_model_assessment(rec, "REFUTED")
            return apply_integration_gate(rec, ass)

    def test_d2_supported_proof_classes_declared(self) -> None:
        for cls_name in (
            "DETERMINISTIC_CONSTANT_SWITCH",
            "LOCAL_ARRAYLIST_CONSTANT_FLOW",
            "LOCAL_HASHMAP_CONSTANT_FLOW",
            "SAME_FILE_HELPER_CONSTANT_FLOW",
        ):
            self.assertIn(cls_name, SUPPORTED_REFUTATION_PROOF_CLASSES)

    def test_d2_switch_safe_vs_fallthrough_dynamic_and_int_arithmetic(self) -> None:
        safe_switch = (
            "package demo;\n"
            "import java.sql.Statement;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class Case {\n"
            "    public void run(HttpServletRequest req, Statement stmt) throws Exception {\n"
            "        String param = req.getParameter(\"p\");\n"
            "        String bar;\n"
            "        String guess = \"ABC\";\n"
            "        char target = guess.charAt(1);\n"
            "        switch (target) {\n"
            "            case 'A': bar = param; break;\n"
            "            case 'B': bar = \"safe_const\"; break;\n"
            "            default: bar = \"other\"; break;\n"
            "        }\n"
            "        String sql = \"SELECT * FROM u WHERE x='\" + bar + \"'\";\n"
            "        stmt.executeQuery(sql);\n"
            "    }\n"
            "}\n"
        )
        out_ok = self._gate_refuted(safe_switch, sink_line=16)
        self.assertEqual(out_ok["status"], "REFUTED", out_ok)

        # Counterexample 1: fallthrough without break from 'B' into 'C' assigning tainted param
        fallthrough_tp = safe_switch.replace(
            '            case \'B\': bar = "safe_const"; break;\n',
            '            case \'B\': bar = "safe_const";\n            case \'C\': bar = param; break;\n',
        )
        out_ft = self._gate_refuted(fallthrough_tp, sink_line=17)
        self.assertEqual(out_ft["status"], "UNDETERMINED")

        # Counterexample 2: dynamic switch target from user input
        dyn_switch = safe_switch.replace('        char target = guess.charAt(1);\n', '        char target = param.charAt(0);\n')
        out_dyn = self._gate_refuted(dyn_switch, sink_line=16)
        self.assertEqual(out_dyn["status"], "UNDETERMINED")

        # Counterexample 3: int arithmetic branch MUST NOT be pruned (stays UNDETERMINED)
        int_arith = (
            "package demo;\n"
            "import java.sql.Statement;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class Case {\n"
            "    public void run(HttpServletRequest req, Statement stmt) throws Exception {\n"
            "        String param = req.getParameter(\"p\");\n"
            "        int n = 106;\n"
            "        String bar = (200 - n > 86) ? \"safe\" : param;\n"
            "        String sql = \"SELECT * FROM u WHERE x='\" + bar + \"'\";\n"
            "        stmt.executeQuery(sql);\n"
            "    }\n"
            "}\n"
        )
        out_arith = self._gate_refuted(int_arith, sink_line=10)
        self.assertEqual(out_arith["status"], "UNDETERMINED")

    def test_d2_arraylist_safe_vs_tainted_slot_and_alias_escape(self) -> None:
        safe_list = (
            "package demo;\n"
            "import java.sql.Statement;\n"
            "import java.util.ArrayList;\n"
            "import java.util.List;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class Case {\n"
            "    public void run(HttpServletRequest req, Statement stmt) throws Exception {\n"
            "        String param = req.getParameter(\"p\");\n"
            "        List<String> values = new ArrayList<String>();\n"
            "        values.add(\"safe\");\n"
            "        values.add(param);\n"
            "        values.add(\"moresafe\");\n"
            "        values.remove(0);\n"
            "        String bar = values.get(1);\n"
            "        String sql = \"SELECT * FROM u WHERE x='\" + bar + \"'\";\n"
            "        stmt.executeQuery(sql);\n"
            "    }\n"
            "}\n"
        )
        self.assertEqual(self._gate_refuted(safe_list, sink_line=16)["status"], "REFUTED")

        # Counterexample 1: get(0) now returns tainted `param`!
        tainted_slot = safe_list.replace("values.get(1)", "values.get(0)")
        self.assertEqual(self._gate_refuted(tainted_slot, sink_line=16)["status"], "UNDETERMINED")

        # Counterexample 2: aliasing / escaping list mutates index 1
        aliased_list = safe_list.replace(
            "        String bar = values.get(1);\n",
            "        List<String> alias = values;\n        alias.set(1, param);\n        String bar = values.get(1);\n",
        )
        self.assertEqual(self._gate_refuted(aliased_list, sink_line=18)["status"], "UNDETERMINED")

    def test_d2_hashmap_safe_vs_tainted_key_overwrite_and_dynamic_key(self) -> None:
        safe_map = (
            "package demo;\n"
            "import java.sql.Statement;\n"
            "import java.util.HashMap;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class Case {\n"
            "    public void run(HttpServletRequest req, Statement stmt) throws Exception {\n"
            "        String param = req.getParameter(\"p\");\n"
            "        HashMap<String, Object> map = new HashMap<String, Object>();\n"
            "        map.put(\"keyA\", \"safe_val\");\n"
            "        map.put(\"keyB\", param);\n"
            "        String bar = (String) map.get(\"keyA\");\n"
            "        String sql = \"SELECT * FROM u WHERE x='\" + bar + \"'\";\n"
            "        stmt.executeQuery(sql);\n"
            "    }\n"
            "}\n"
        )
        self.assertEqual(self._gate_refuted(safe_map, sink_line=13)["status"], "REFUTED")

        # Counterexample 1: reading tainted keyB
        tainted_key = safe_map.replace('map.get("keyA")', 'map.get("keyB")')
        self.assertEqual(self._gate_refuted(tainted_key, sink_line=13)["status"], "UNDETERMINED")

        # Counterexample 2: overwriting keyA with param
        overwrite_key = safe_map.replace(
            '        String bar = (String) map.get("keyA");\n',
            '        map.put("keyA", param);\n        String bar = (String) map.get("keyA");\n',
        )
        self.assertEqual(self._gate_refuted(overwrite_key, sink_line=14)["status"], "UNDETERMINED")

        # Counterexample 3: dynamic key put invalidates map
        dyn_key = safe_map.replace('map.put("keyB", param);', 'map.put(param, param);')
        self.assertEqual(self._gate_refuted(dyn_key, sink_line=13)["status"], "UNDETERMINED")

    def test_d2_same_file_helper_safe_vs_tainted_branch_and_cross_file(self) -> None:
        safe_helper = (
            "package demo;\n"
            "import java.sql.Statement;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class Case {\n"
            "    public void run(HttpServletRequest req, Statement stmt) throws Exception {\n"
            "        String param = req.getParameter(\"p\");\n"
            "        String bar = new Inner().doSomething(param);\n"
            "        String sql = \"SELECT * FROM u WHERE x='\" + bar + \"'\";\n"
            "        stmt.executeQuery(sql);\n"
            "    }\n"
            "    private class Inner {\n"
            "        public String doSomething(String input) {\n"
            "            String out = \"always_const\";\n"
            "            return out;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        self.assertEqual(self._gate_refuted(safe_helper, sink_line=9)["status"], "REFUTED")

        # Counterexample 1: helper returns parameter on reachable branch
        tainted_helper = safe_helper.replace(
            '            String out = "always_const";\n',
            '            String out = input;\n',
        )
        self.assertEqual(self._gate_refuted(tainted_helper, sink_line=9)["status"], "UNDETERMINED")

        # Counterexample 2: cross-file helper cannot be proven safe
        cross_file = (
            "package demo;\n"
            "import java.sql.Statement;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class Case {\n"
            "    public void run(HttpServletRequest req, Statement stmt) throws Exception {\n"
            "        String param = req.getParameter(\"p\");\n"
            "        String bar = ExternalHelper.clean(param);\n"
            "        String sql = \"SELECT * FROM u WHERE x='\" + bar + \"'\";\n"
            "        stmt.executeQuery(sql);\n"
            "    }\n"
            "}\n"
        )
        self.assertEqual(self._gate_refuted(cross_file, sink_line=9)["status"], "UNDETERMINED")

    def test_d2_verified_static_final_const_and_prepared_statement_concat_tp_counterexample(self) -> None:
        cwe22_safe = (
            "package demo;\n"
            "import java.nio.file.Files;\n"
            "import java.nio.file.Paths;\n"
            "import java.nio.file.StandardOpenOption;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class Case {\n"
            "    public void run(HttpServletRequest req) throws Exception {\n"
            "        String param = req.getParameter(\"f\");\n"
            "        String bar = \"fixed.txt\";\n"
            "        String fileName = PathsUtil.SAFE_DIR + bar;\n"
            "        Files.newOutputStream(Paths.get(fileName), StandardOpenOption.CREATE);\n"
            "    }\n"
            "}\n"
        )
        good_const = (
            "package demo;\n"
            "import java.io.File;\n"
            "public class PathsUtil {\n"
            "    public static final String SAFE_DIR = \"app\" + File.separator + \"data\" + File.separator;\n"
            "}\n"
        )
        mutable_sysprop_const = (
            "package demo;\n"
            "import java.io.File;\n"
            "public class PathsUtil {\n"
            "    public static final String SAFE_DIR = System.getProperty(\"user.dir\") + File.separator + \"data\" + File.separator;\n"
            "}\n"
        )
        split_parent_const = (
            "package demo;\n"
            "public class PathsUtil {\n"
            "    public static final String SAFE_DIR = \".\" + \".\" + \"/data/\";\n"
            "}\n"
        )
        non_final_const = good_const.replace("static final String", "static String")
        dotdot_const = good_const.replace('"data"', '"../etc"')

        self.assertEqual(
            self._gate_refuted(
                cwe22_safe, sink_line=11, cwe="CWE-22", extra_files={"demo/PathsUtil.java": good_const}, use_manifest=True
            )["status"],
            "REFUTED",
        )
        self.assertEqual(
            self._gate_refuted(
                cwe22_safe, sink_line=11, cwe="CWE-22", extra_files={"demo/PathsUtil.java": mutable_sysprop_const}, use_manifest=True
            )["status"],
            "UNDETERMINED",
        )
        self.assertEqual(
            self._gate_refuted(
                cwe22_safe, sink_line=11, cwe="CWE-22", extra_files={"demo/PathsUtil.java": split_parent_const}, use_manifest=True
            )["status"],
            "UNDETERMINED",
        )
        self.assertEqual(
            self._gate_refuted(
                cwe22_safe, sink_line=11, cwe="CWE-22", extra_files={"demo/PathsUtil.java": non_final_const}, use_manifest=True
            )["status"],
            "UNDETERMINED",
        )
        self.assertEqual(
            self._gate_refuted(
                cwe22_safe, sink_line=11, cwe="CWE-22", extra_files={"demo/PathsUtil.java": dotdot_const}, use_manifest=True
            )["status"],
            "UNDETERMINED",
        )

        # Lesson5b-like counterexample: PreparedStatement with concatenated SQL MUST NOT be REFUTED!
        lesson5b_like = (
            "package demo;\n"
            "import java.sql.Connection;\n"
            "import java.sql.PreparedStatement;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class Case {\n"
            "    public void run(HttpServletRequest req, Connection conn) throws Exception {\n"
            "        String user = req.getParameter(\"u\");\n"
            "        String pass = req.getParameter(\"p\");\n"
            "        String query = \"SELECT * FROM users WHERE name = '\" + user + \"' AND pass = ?\";\n"
            "        PreparedStatement ps = conn.prepareStatement(query);\n"
            "        ps.setString(1, pass);\n"
            "        ps.executeQuery();\n"
            "    }\n"
            "}\n"
        )
        self.assertEqual(self._gate_refuted(lesson5b_like, sink_line=10)["status"], "UNDETERMINED")


class AreaETelemetryAndLegacyCompatTests(unittest.TestCase):
    def test_e_opengrep_coverage_telemetry_all_states(self) -> None:
        inv = [f"src/main/java/A{i}.java" for i in range(5)] + ["src/test/java/T1.java", "src/test/java/T2.java"]

        # Full coverage (with verified source_root for absolute paths)
        t_full = compute_opengrep_coverage_telemetry(
            inv,
            {"paths": {"scanned": [f"/proj/{p}" for p in inv]}, "results": []},
            source_root=Path("/proj"),
        )
        self.assertEqual(t_full["java_files_inventory"], 7)
        self.assertEqual(t_full["java_files_opengrep_scanned"], 7)
        self.assertEqual(t_full["java_files_opengrep_ignored"], 0)
        self.assertEqual(t_full["opengrep_paths_telemetry_status"], "VERIFIED")

        # Ignored test files (zero findings still valid!) with verified Windows source_root
        t_ign = compute_opengrep_coverage_telemetry(
            inv,
            {"paths": {"scanned": [f"C:\\work\\repo\\src\\main\\java\\A{i}.java" for i in range(5)]}, "results": []},
            source_root=Path("C:/work/repo"),
        )
        self.assertEqual(t_ign["java_files_inventory"], 7)
        self.assertEqual(t_ign["java_files_opengrep_scanned"], 5)
        self.assertEqual(t_ign["java_files_opengrep_ignored"], 2)
        self.assertEqual(t_ign["opengrep_paths_telemetry_status"], "VERIFIED")

        # Foreign / unrooted absolute paths MUST fail closed to INCONSISTENT_TELEMETRY
        t_foreign = compute_opengrep_coverage_telemetry(
            inv,
            {"paths": {"scanned": ["C:\\unrelated\\src\\main\\java\\A0.java"]}, "results": []},
            source_root=Path("C:/work/repo"),
        )
        self.assertEqual(t_foreign["opengrep_paths_telemetry_status"], "INCONSISTENT_TELEMETRY")
        self.assertIsNone(t_foreign["java_files_opengrep_scanned"])
        self.assertIsNone(t_foreign["java_files_opengrep_ignored"])

        # Missing paths.scanned
        t_miss = compute_opengrep_coverage_telemetry(inv, {"results": []})
        self.assertEqual(t_miss["opengrep_paths_telemetry_status"], "MISSING_PATHS_TELEMETRY")
        self.assertIsNone(t_miss["java_files_opengrep_scanned"])
        self.assertIsNone(t_miss["java_files_opengrep_ignored"])

        # Inconsistent: scanned > inventory
        t_over = compute_opengrep_coverage_telemetry(
            inv[:2], {"paths": {"scanned": [f"src/main/java/A{i}.java" for i in range(5)]}}
        )
        self.assertEqual(t_over["opengrep_paths_telemetry_status"], "INCONSISTENT_TELEMETRY")
        self.assertIsNone(t_over["java_files_opengrep_ignored"])

        # Inconsistent: malformed non-string entry in paths.scanned
        t_bad = compute_opengrep_coverage_telemetry(inv, {"paths": {"scanned": ["src/main/java/A0.java", 123]}})
        self.assertEqual(t_bad["opengrep_paths_telemetry_status"], "INCONSISTENT_TELEMETRY")

    def test_e_service_legacy_scan_readonly_coverage_and_tamper_detection(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            data_dir = base / "data"
            scan_dir = base / "legacy-scan-1"
            cap_dir = scan_dir / "capture"
            tri_dir = scan_dir / "triage"
            src_dir = base / "src"
            cap_dir.mkdir(parents=True, exist_ok=True)
            tri_dir.mkdir(parents=True, exist_ok=True)
            (src_dir / "src" / "main" / "java").mkdir(parents=True, exist_ok=True)
            (src_dir / "src" / "test" / "java").mkdir(parents=True, exist_ok=True)

            f1 = src_dir / "src" / "main" / "java" / "App.java"
            f2 = src_dir / "src" / "test" / "java" / "AppTest.java"
            f1.write_text("public class App {}\n", encoding="utf-8")
            f2.write_text("public class AppTest {}\n", encoding="utf-8")
            pre_hashes = {
                "src/main/java/App.java": evidence.digest(f1.read_bytes()),
                "src/test/java/AppTest.java": evidence.digest(f2.read_bytes()),
            }
            og_doc = {"version": "1.25.0", "results": [], "paths": {"scanned": [str(f1)]}}
            og_bytes = json.dumps(og_doc).encode("utf-8")
            og_path = cap_dir / "opengrep.json"
            og_path.write_bytes(og_bytes)
            scan_sha = evidence.digest(og_bytes)

            bundle = {
                "schema_version": 2,
                "scan_sha256": scan_sha,
                "root": str(src_dir),
                "collected_at": evidence.now(),
                "pre_scan_hashes": pre_hashes,
                "issues": [],
                "records": [],
                "scan_provenance": {"origin": "mock", "source_capture_verified": True, "exit_capture_verified": True, "recorded_engine_exit": 0},
            }
            (tri_dir / "evidence.json").write_text(json.dumps(bundle), encoding="utf-8")
            (tri_dir / "assessments.jsonl").write_text("", encoding="utf-8")
            store = ReviewStore(tri_dir / "review.sqlite")
            store.add(bundle, [])
            store.close()

            before_files = sorted(str(p.relative_to(scan_dir)) for p in scan_dir.rglob("*"))
            cfg = ApiConfig(data_dir=data_dir, runtime_origin="mock", readonly_scan_dirs=(scan_dir,))
            svc = TriageApiService(cfg)
            scans = svc.list_scans(include_mock=True)["scans"]
            self.assertEqual(len(scans), 1)
            s = scans[0]
            # Legacy field preserved!
            self.assertEqual(s["java_files_scanned"], 2)
            # Additive fields verified read-only!
            self.assertEqual(s["java_files_inventory"], 2)
            self.assertEqual(s["java_files_opengrep_scanned"], 1)
            self.assertEqual(s["java_files_opengrep_ignored"], 1)
            self.assertEqual(s["opengrep_paths_telemetry_status"], "VERIFIED")
            after_files = sorted(str(p.relative_to(scan_dir)) for p in scan_dir.rglob("*"))
            self.assertEqual(before_files, after_files)

            # Tamper opengrep.json -> scan_sha256 mismatch -> INCONSISTENT_TELEMETRY
            og_path.write_bytes(og_bytes + b" ")
            s2 = svc.list_scans(include_mock=True)["scans"][0]
            self.assertEqual(s2["opengrep_paths_telemetry_status"], "INCONSISTENT_TELEMETRY")
            self.assertIsNone(s2["java_files_opengrep_scanned"])


if __name__ == "__main__":
    unittest.main()
