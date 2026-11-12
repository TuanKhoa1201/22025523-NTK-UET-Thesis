"""Unit and regression tests for Stage 2 (Java context, CliCall, citation checking)
and Stage 3 (CWE-22 / CWE-89 heuristics and prompt modes).
"""
from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from test_triage import Fixture
from v2.triage.evidence import EvidenceError, collect, digest
from v2.triage.heuristics import extract_evidence_signals, heuristic_analyze
from v2.triage.java_context import extract_java_context, parse_java_structure
from v2.triage.ollama import PROMPT_VERSION, prompt, validate_answer


class Stage2JavaContextAndCliCallTests(Fixture):
    def test_java_context_extracts_enclosing_method_and_inner_callee(self):
        java_code = (
            "package org.example;\n"
            "import java.io.File;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class FileServlet {\n"
            "    @Override\n"
            "    public void doPost(HttpServletRequest request) {\n"
            "        String param = request.getHeader(\"x\");\n"
            "        String bar = new Helper().doSomething(param);\n"
            "        File f = new File(bar);\n"
            "    }\n"
            "    private class Helper {\n"
            "        public String doSomething(String param) {\n"
            "            String bar = \"safe_constant.txt\";\n"
            "            return bar;\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        struct = parse_java_structure(java_code)
        self.assertEqual(struct["package_name"], "org.example")
        self.assertIn("java.io.File", struct["imports"])
        method_names = [m["name"] for m in struct["methods"]]
        self.assertIn("doPost", method_names)
        self.assertIn("doSomething", method_names)

        ctx = extract_java_context(java_code, finding_start_line=9, finding_end_line=9, trace_lines=[7, 8, 13])
        self.assertIsNotNone(ctx["enclosing_method"])
        self.assertEqual(ctx["enclosing_method"]["name"], "doPost")
        self.assertTrue(ctx["enclosing_method"]["is_entrypoint"])
        callee_names = [c["name"] for c in ctx["same_file_callees"]]
        self.assertIn("doSomething", callee_names)
        self.assertLessEqual(ctx["context_start_line"], 6)
        self.assertGreaterEqual(ctx["context_end_line"], 15)

    def test_clicall_in_source_and_sink_is_flattened_and_verified(self):
        java_code = (
            "class CliCallDemo {\n"
            " void doPost(Request req) {\n"
            "  String p = req.getHeader(\"h\");\n"
            "  String b = helper(p);\n"
            "  java.io.File f = new java.io.File(b);\n"
            " }\n"
            " String helper(String x) {\n"
            "  return x;\n"
            " }\n"
            "}\n"
        )
        self.text = java_code
        self.source.write_bytes(self.text.encode("utf-8"))
        doc = {
            "results": [
                {
                    "check_id": "test.cwe22.clicall",
                    "path": "Demo.java",
                    "start": self.point(5, 20),
                    "end": self.point(5, 39),
                    "extra": {
                        "severity": "WARNING",
                        "metadata": {"cwe": ["CWE-22"]},
                        "message": "CWE-22 CliCall finding",
                        "dataflow_trace": {
                            "taint_source": [
                                "CliCall",
                                [
                                    [self.loc(3, 'req.getHeader("h")'), 'req.getHeader("h")'],
                                    [{"location": self.loc(3, "p"), "content": "p"}],
                                    self.tag(3, 'req.getHeader("h")'),
                                ],
                            ],
                            "intermediate_vars": [{"location": self.loc(4, "b"), "content": "b"}],
                            "taint_sink": [
                                "CliCall",
                                [
                                    [self.loc(4, "helper(p)"), "helper(p)"],
                                    [{"location": self.loc(8, "x"), "content": "x"}],
                                    self.tag(5, "new java.io.File(b)"),
                                ],
                            ],
                        },
                    },
                }
            ],
            "errors": [],
        }
        bundle = self.collect(doc)
        rec = bundle["records"][0]
        self.assertEqual(rec["issues"], [])
        roles = [s["role"] for s in rec["snippets"]]
        self.assertEqual(roles[0], "finding")
        self.assertIn("source", roles)
        self.assertIn("sink", roles)
        # Ensure expanded finding snippet includes helper line 8
        finding_lines = {ln["line"] for ln in rec["snippets"][0]["lines"]}
        self.assertIn(8, finding_lines)


class Stage3HeuristicsAndPromptTests(Fixture):
    def _make_java_record(self, java_code: str, cwe: str, source_line: int, source_str: str, sink_line: int, sink_str: str):
        self.text = java_code
        self.source.write_bytes(self.text.encode("utf-8"))
        doc = {
            "results": [
                {
                    "check_id": f"test.{cwe.lower()}",
                    "path": "Demo.java",
                    "start": self.point(sink_line, self.text.splitlines()[sink_line - 1].index(sink_str) + 1),
                    "end": self.point(
                        sink_line,
                        self.text.splitlines()[sink_line - 1].index(sink_str) + 1 + len(sink_str.encode("utf-8")),
                    ),
                    "extra": {
                        "severity": "WARNING",
                        "metadata": {"cwe": [cwe]},
                        "message": f"test {cwe}",
                        "dataflow_trace": {
                            "taint_source": self.tag(source_line, source_str),
                            "intermediate_vars": [],
                            "taint_sink": self.tag(sink_line, sink_str),
                        },
                    },
                }
            ],
            "errors": [],
        }
        return self.collect(doc)["records"][0]

    def test_cwe22_filename_utils_sanitizer_and_safe_source(self):
        code_san = (
            "class A {\n"
            " void run(Request request) {\n"
            "  String p = request.getParameter(\"f\");\n"
            "  String clean = FilenameUtils.getName(p);\n"
            "  new java.io.File(clean);\n"
            " }\n"
            "}\n"
        )
        rec = self._make_java_record(code_san, "CWE-22", 3, 'request.getParameter("f")', 5, "new java.io.File(clean)")
        sig = extract_evidence_signals(rec)
        self.assertEqual(sig["recommended_status"], "REFUTED")
        self.assertTrue(sig["sanitizers_found"])
        arm_b = heuristic_analyze(rec)
        self.assertEqual(arm_b["status"], "REFUTED")
        self.assertEqual(arm_b["citation_check"], "MATCHED")

        code_safe_src = (
            "class B {\n"
            " void run(SeparateClassRequest scr) {\n"
            "  String p = scr.getTheValue(\"x\");\n"
            "  new java.io.File(p);\n"
            " }\n"
            "}\n"
        )
        rec2 = self._make_java_record(code_safe_src, "CWE-22", 3, 'scr.getTheValue("x")', 4, "new java.io.File(p)")
        # SeparateClassRequest is absent from snapshots: must degrade to UNDETERMINED, never infer REFUTED from name
        self.assertEqual(extract_evidence_signals(rec2)["recommended_status"], "UNDETERMINED")
        self.assertEqual(heuristic_analyze(rec2)["status"], "UNDETERMINED")

    def test_switch_arithmetic_list_and_map_flows(self):
        # 1. Switch constant 'B' -> safe literal
        code_sw = (
            "class Sw {\n"
            " void run(Request req) {\n"
            "  String param = req.getHeader(\"x\");\n"
            "  String bar;\n"
            "  String guess = \"ABC\";\n"
            "  char switchTarget = guess.charAt(1);\n"
            "  switch (switchTarget) {\n"
            "   case 'A':\n"
            "    bar = param;\n"
            "    break;\n"
            "   case 'B':\n"
            "    bar = \"bob\";\n"
            "    break;\n"
            "   default:\n"
            "    bar = \"safe\";\n"
            "    break;\n"
            "  }\n"
            "  stmt.executeQuery(\"SELECT \" + bar);\n"
            " }\n"
            "}\n"
        )
        rec_sw = self._make_java_record(code_sw, "CWE-89", 3, 'req.getHeader("x")', 18, 'stmt.executeQuery("SELECT " + bar)')
        sig_sw = extract_evidence_signals(rec_sw)
        self.assertEqual(sig_sw["recommended_status"], "REFUTED")
        self.assertEqual(heuristic_analyze(rec_sw)["status"], "REFUTED")

        # 2. Inner helper list remove(0) + get(1) -> REFUTED in evidence_signals, UNDETERMINED in Arm B heuristic
        code_list = (
            "class Lst {\n"
            " void doPost(Request request) {\n"
            "  String param = request.getHeader(\"x\");\n"
            "  String bar = new Test().doSomething(request, param);\n"
            "  stmt.executeQuery(\"SELECT \" + bar);\n"
            " }\n"
            " private class Test {\n"
            "  public String doSomething(Request request, String param) {\n"
            "   java.util.List<String> valuesList = new java.util.ArrayList<String>();\n"
            "   valuesList.add(\"safe\");\n"
            "   valuesList.add(param);\n"
            "   valuesList.add(\"moresafe\");\n"
            "   valuesList.remove(0);\n"
            "   String bar = valuesList.get(1);\n"
            "   return bar;\n"
            "  }\n"
            " }\n"
            "}\n"
        )
        rec_lst = self._make_java_record(code_list, "CWE-89", 3, 'request.getHeader("x")', 5, 'stmt.executeQuery("SELECT " + bar)')
        sig_lst = extract_evidence_signals(rec_lst)
        self.assertEqual(sig_lst["recommended_status"], "REFUTED")
        self.assertEqual(heuristic_analyze(rec_lst)["status"], "UNDETERMINED")

    def test_prompt_modes_evidence_llm_vs_ablation_llm(self):
        self.assertTrue(PROMPT_VERSION.startswith("v2."))
        msgs_full = prompt(self.record)
        user_full = json.loads(msgs_full[1]["content"])
        self.assertIn("evidence_signals", user_full)
        self.assertNotIn("recommended_status", user_full["evidence_signals"])
        self.assertNotIn("recommendation_reason", user_full["evidence_signals"])
        self.assertNotIn("candidate_citations", user_full["evidence_signals"])
        self.assertIn("trace_steps", user_full)

        rec_ablation = copy.deepcopy(self.record)
        rec_ablation["triage_mode"] = "llm"
        msgs_abl = prompt(rec_ablation)
        user_abl = json.loads(msgs_abl[1]["content"])
        self.assertNotIn("evidence_signals", user_abl)
        self.assertNotIn("java_context_summary", user_abl)


if __name__ == "__main__":
    unittest.main()
