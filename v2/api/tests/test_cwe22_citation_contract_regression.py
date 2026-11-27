"""Regression tests for Stage C: CWE-22 multiline citation truncation root cause and single-line prompt contract.

Preserves exact BEFORE failing raw citation patterns from the 2026-11-24 JavaVulnerableLab AddPage.java run
as deterministic fail-closed controls (never auto-repaired, never relaxed), while validating the updated
v2.2.3 single-line-first citation prompt contract.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from v2.triage import evidence, ollama


ADDPAGE_LIKE_JAVA = (
    "package org.example.jvl;\n"                                                          # 1
    "import java.io.*;\n"                                                                 # 2
    "import javax.servlet.*;\n"                                                           # 3
    "import javax.servlet.http.*;\n"                                                      # 4
    "public class PageController extends HttpServlet {\n"                                 # 5
    "    protected void processRequest(HttpServletRequest request, HttpServletResponse response)\n"  # 6
    "            throws ServletException, IOException {\n"                                # 7
    "        try {\n"                                                                     # 8
    '           String fileName=request.getParameter("filename");\n'                      # 9  (mirrors L39)
    '           String content=request.getParameter("content");\n'                        # 10 (mirrors L40)
    "           if(fileName!=null && content!=null)\n"                                    # 11 (mirrors L41)
    "           {\n"                                                                      # 12 (mirrors L42)
    '            String pagesDir=getServletContext().getRealPath("/pages");\n'            # 13 (mirrors L43)
    '            String filePath=pagesDir+"/"+fileName;\n'                                # 14 (mirrors L44)
    "            File f=new File(filePath);\n"                                            # 15 (mirrors L45)
    "            if(f.exists())\n"                                                        # 16 (mirrors L46)
    "            {\n"                                                                     # 17 (mirrors L47)
    "                f.delete();\n"                                                       # 18 (mirrors L48)
    "            }\n"                                                                     # 19 (mirrors L49)
    "                if(f.createNewFile())\n"                                             # 20 (mirrors L50)
    "                {\n"                                                                 # 21 (mirrors L51)
    "                    BufferedWriter bw=new BufferedWriter(new FileWriter(f.getAbsoluteFile()));\n"  # 22 (mirrors L52)
    "                    bw.write(content);\n"                                            # 23 (mirrors L53)
    "                    bw.close();\n"                                                   # 24 (mirrors L54)
    "                }\n"                                                                 # 25 (mirrors L55)
    "           }\n"                                                                      # 26
    "        } catch (Exception e) { }\n"                                                 # 27
    "    }\n"                                                                             # 28
    "    private void unrelatedMethod() {\n"                                              # 29
    "        int x = 1;\n"                                                                # 30
    "    }\n"                                                                             # 31
    "}\n"                                                                                 # 32
)


class Cwe22CitationContractRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.rel = "src/main/java/org/example/jvl/PageController.java"
        src_file = self.root / self.rel
        src_file.parent.mkdir(parents=True, exist_ok=True)
        raw_src = ADDPAGE_LIKE_JAVA.encode("utf-8")
        src_file.write_bytes(raw_src)
        self.lines = ADDPAGE_LIKE_JAVA.splitlines()
        self.sha = evidence.digest(raw_src)

        def _loc(ln: int, needle: str) -> dict:
            lines_ke = ADDPAGE_LIKE_JAVA.splitlines(keepends=True)
            row = lines_ke[ln - 1].rstrip("\r\n")
            col0 = row.index(needle)
            off = sum(len(x.encode("utf-8")) for x in lines_ke[: ln - 1]) + len(row[:col0].encode("utf-8"))
            return {
                "path": self.rel,
                "start": {"line": ln, "col": len(row[:col0].encode("utf-8")) + 1, "offset": off},
                "end": {"line": ln, "col": len(row[: col0 + len(needle)].encode("utf-8")) + 1, "offset": off + len(needle.encode("utf-8"))},
            }

        src_loc = _loc(9, 'request.getParameter("filename")')
        i1 = _loc(14, 'filePath')
        i2 = _loc(15, 'f')
        snk_loc = _loc(18, 'f.delete()')
        og_doc = {
            "results": [
                {
                    "check_id": "v2.api.rules.ntk.api.java.cwe22.path-traversal",
                    **snk_loc,
                    "extra": {
                        "severity": "ERROR",
                        "message": "CWE-22 path traversal regression fixture",
                        "metadata": {"cwe": ["CWE-22: Path Traversal"]},
                        "dataflow_trace": {
                            "taint_source": ["CliLoc", [src_loc, 'request.getParameter("filename")']],
                            "intermediate_vars": [
                                {"location": i1, "content": "filePath"},
                                {"location": i2, "content": "f"},
                            ],
                            "taint_sink": ["CliLoc", [snk_loc, "f.delete()"]],
                        },
                    },
                }
            ],
            "errors": [],
        }
        prov = {
            "origin": "UNIT_TEST_MOCK_CAPTURE",
            "source_capture_verified": True,
            "exit_capture_verified": True,
            "source_hashes": {self.rel: self.sha},
        }
        self.bundle = evidence.collect(
            json.dumps(og_doc).encode("utf-8"),
            self.root,
            engine_exit=0,
            scan_provenance=prov,
        )
        self.record = self.bundle["records"][0]
        self.assertEqual(self.record["issues"], [])

    def _run_mock(self, answer: dict, record: dict | None = None) -> dict:
        rec = self.record if record is None else record
        client = ollama.OllamaClient(runtime_origin="mock")
        resp = {"model": client.model, "done": True, "mock_test_fixture": True, "message": {"content": json.dumps(answer)}}
        with patch.object(client, "request", return_value=resp):
            return client.analyze(rec)

    def test_prompt_contract_v223_prefers_single_line_and_stays_blind(self) -> None:
        self.assertEqual(ollama.PROMPT_VERSION, "v2.2.6-cwe22-cwe89-strict-singleline-max3-citations")
        self.assertEqual(
            ollama.PREVIOUS_V225_PROMPT_VERSION,
            "v2.2.5-cwe22-cwe89-exec-citations-and-flow-rebuttal",
        )
        self.assertEqual(
            ollama.PREVIOUS_MINIMAL_SINGLELINE_PROMPT_VERSION,
            "v2.2.4-cwe22-cwe89-minimal-singleline-citations",
        )
        self.assertEqual(ollama.PREVIOUS_CANONICAL_PROMPT_VERSION, "v2.2.2-cwe22-cwe89-canonical-citations")
        for contract in ("blind", "neutral_hints"):
            rec = copy.deepcopy(self.record)
            rec["prompt_contract"] = contract
            msgs = ollama.prompt(rec)
            sys_txt = msgs[0]["content"]
            user_doc = json.loads(msgs[1]["content"])
            ollama.assert_prompt_contract(user_doc, contract)
            self.assertIn("DISTINCT SINGLE-LINE citations", sys_txt)
            self.assertIn("start_line == end_line", sys_txt)
            self.assertNotIn("(end_line - start_line + 1)", sys_txt)
            self.assertNotIn("AddPage", sys_txt)
            self.assertLess(len(json.dumps(msgs).encode("utf-8")), 32_000)

    def test_before_failing_cwe22_truncated_multiline_citations_still_rejected_fail_closed(self) -> None:
        """Exact BEFORE failure patterns (missing final 1-2 lines) MUST remain rejected as INVALID_CITATION."""
        before_cases = [
            # Pattern 1 (AddPage:48): declared 9..18 (10 lines), quote only contains 9..16 (8 lines)
            ("missing_last_2_lines_39_48", 9, 18, "\n".join(self.lines[8:16])),
            # Pattern 2 (AddPage:50 & :52 cite 1): declared 9..14 (6 lines), quote only contains 9..13 (5 lines)
            ("missing_last_1_line_39_44", 9, 14, "\n".join(self.lines[8:13])),
            # Pattern 3 (AddPage:52 cite 2): declared 14..15 (2 lines), quote only contains line 14 (1 line)
            ("missing_last_1_line_44_45", 14, 15, self.lines[13]),
        ]
        for label, sl, el, bad_quote in before_cases:
            with self.subTest(case=label):
                answer = {
                    "status": "SUPPORTED",
                    "explanation": "BEFORE truncated multiline citation control",
                    "fix_suggestion": "Validate canonical path",
                    "citations": [{"path": self.rel, "start_line": sl, "end_line": el, "quote": bad_quote, "sha256": self.sha}],
                }
                before_copy = copy.deepcopy(answer)
                out = self._run_mock(answer)
                self.assertEqual(answer, before_copy, "validator must never mutate raw citation")
                self.assertEqual(out["raw_model_status"], "SUPPORTED")
                self.assertEqual(out["validated_status"], "UNDETERMINED")
                self.assertTrue(out["validator_downgraded"])
                self.assertEqual(out["failure_kind"], "INVALID_CITATION")
                self.assertEqual(out["citation_check"], "NOT_VERIFIED")
                self.assertFalse(out["security_conclusion_verified"])

    def test_separate_single_line_citations_for_source_intermediate_sink_accepted(self) -> None:
        answer = {
            "status": "SUPPORTED",
            "explanation": "Biến filename từ request đi qua nối chuỗi filePath và File tới f.delete() không kiểm tra canonical path.",
            "fix_suggestion": "Dùng getCanonicalFile() và kiểm tra prefix kèm File.separator.",
            "citations": [
                {"path": self.rel, "start_line": 9, "end_line": 9, "quote": self.lines[8], "sha256": self.sha},
                {"path": self.rel, "start_line": 14, "end_line": 14, "quote": self.lines[13], "sha256": self.sha},
                {"path": self.rel, "start_line": 18, "end_line": 18, "quote": self.lines[17], "sha256": self.sha},
            ],
        }
        out = self._run_mock(answer)
        self.assertEqual(out["validated_status"], "SUPPORTED")
        self.assertEqual(out["citation_check"], "MATCHED")
        self.assertEqual(len(out["citations"]), 3)
        self.assertTrue(out["citation_provenance"]["citation_in_source"])
        self.assertTrue(out["citation_provenance"]["citation_in_prompt"])
        # Citation MATCHED never implies automated security conclusion proof
        self.assertFalse(out["citation_provenance"]["supports_security_claim_verified"])
        self.assertFalse(out["security_conclusion_verified"])

        # Current v2.2.6 contract rejects >3 citations while preserving v2.2.4 historical replay
        four_cites_answer = copy.deepcopy(answer)
        four_cites_answer["citations"].insert(
            2, {"path": self.rel, "start_line": 15, "end_line": 15, "quote": self.lines[14], "sha256": self.sha}
        )
        out_four = self._run_mock(four_cites_answer)
        self.assertEqual(out_four["validated_status"], "UNDETERMINED")
        self.assertEqual(out_four["failure_kind"], "INVALID_CITATION")
        hist_four = ollama.validate_answer(
            json.dumps(four_cites_answer),
            self.record,
            prompt_version=ollama.PREVIOUS_MINIMAL_SINGLELINE_PROMPT_VERSION,
        )
        self.assertEqual(hist_four["validated_status"], "SUPPORTED")
        self.assertEqual(len(hist_four["citations"]), 4)

    def test_exact_inclusive_multiline_citation_still_supported(self) -> None:
        answer = {
            "status": "SUPPORTED",
            "explanation": "Exact inclusive 2-line quote allowed only under historical replay, rejected on v2.2.6.",
            "fix_suggestion": "Validate canonical path",
            "citations": [
                {"path": self.rel, "start_line": 14, "end_line": 15, "quote": "\n".join(self.lines[13:15]), "sha256": self.sha},
            ],
        }
        # Strict v2.2.6 rejects multi-line spans
        out_cur = self._run_mock(answer)
        self.assertEqual(out_cur["validated_status"], "UNDETERMINED")
        self.assertEqual(out_cur["failure_kind"], "INVALID_CITATION")
        # Historical replay under v2.2.2/v2.2.4 preserves exact inclusive multi-line semantics
        out_hist = ollama.validate_answer(
            json.dumps(answer),
            self.record,
            prompt_version=ollama.PREVIOUS_CANONICAL_PROMPT_VERSION,
        )
        self.assertEqual(out_hist["validated_status"], "SUPPORTED")
        self.assertEqual(out_hist["citation_check"], "MATCHED")
        self.assertFalse(out_hist["security_conclusion_verified"])

    def test_wrong_line_trimmed_quote_wrong_sha_wrong_file_and_out_of_prompt_rejected(self) -> None:
        bad_cites = [
            ("wrong_line_number", {"path": self.rel, "start_line": 15, "end_line": 15, "quote": self.lines[13], "sha256": self.sha}),
            ("trimmed_leading_spaces", {"path": self.rel, "start_line": 14, "end_line": 14, "quote": self.lines[13].strip(), "sha256": self.sha}),
            ("wrong_sha256", {"path": self.rel, "start_line": 14, "end_line": 14, "quote": self.lines[13], "sha256": "f" * 64}),
            ("wrong_file_path", {"path": "Other.java", "start_line": 14, "end_line": 14, "quote": self.lines[13], "sha256": self.sha}),
            ("brace_only_non_executable", {"path": self.rel, "start_line": 17, "end_line": 17, "quote": self.lines[16], "sha256": self.sha}),
        ]
        for label, cite in bad_cites:
            with self.subTest(case=label):
                out = self._run_mock({
                    "status": "SUPPORTED",
                    "explanation": "Negative citation check",
                    "fix_suggestion": "",
                    "citations": [cite],
                })
                self.assertEqual(out["validated_status"], "UNDETERMINED")
                self.assertEqual(out["failure_kind"], "INVALID_CITATION")

        # Line present in source snapshot but absent from compacted prompt window (llm mode) -> posthoc_only rejected
        rec_short = copy.deepcopy(self.record)
        rec_short["triage_mode"] = "llm"
        rec_short["snapshots"][self.rel]["lines"] = list(self.lines)
        out_posthoc = self._run_mock(
            {
                "status": "SUPPORTED",
                "explanation": "Out-of-prompt line check",
                "fix_suggestion": "",
                "citations": [{"path": self.rel, "start_line": 30, "end_line": 30, "quote": self.lines[29], "sha256": self.sha}],
            },
            record=rec_short,
        )
        self.assertEqual(out_posthoc["validated_status"], "UNDETERMINED")
        self.assertEqual(out_posthoc["failure_kind"], "INVALID_CITATION")


if __name__ == "__main__":
    unittest.main()
