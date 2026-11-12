"""Adversarial regression suite for G0 source-analysis, citation-provenance, and prompt-neutrality blind spots.

Tag legend in test docstrings:
- [REPRODUCES_OLD_BUG_NOW_FIXED]: Reproduces an actual v2.1 blind spot verified in code audit and confirms the v2.2 fix.
- [HARDENED_INVARIANT]: Verifies fail-closed security/evidence invariants against adversarial inputs.
"""
from __future__ import annotations

import copy
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from v2.triage.evidence import EvidenceError, collect, digest
from v2.triage.heuristics import extract_evidence_signals, heuristic_analyze
from v2.triage.ollama import (
    LEGACY_STEERED_PROMPT_VERSION,
    PROMPT_VERSION,
    OllamaClient,
    inspect_citations_provenance,
    legacy_v2_1_request_payload,
    prompt,
    request_payload,
    validate_answer,
)
from v2.triage.store import ReviewStore

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "counterexamples"


def _build_fixture_record(
    fixture_name: str,
    cwe: str,
    source_sub: str,
    sink_sub: str,
    method_hint: str | None = None,
) -> dict:
    src_file = FIXTURES_DIR / fixture_name
    text = src_file.read_text(encoding="utf-8")
    lines = text.splitlines()
    keepends = text.splitlines(keepends=True)

    start_idx = 0
    if method_hint:
        for idx, ln in enumerate(lines):
            if method_hint in ln:
                start_idx = idx
                break

    src_ln = next(i + 1 for i in range(start_idx, len(lines)) if source_sub in lines[i])
    sink_ln = next(i + 1 for i in range(start_idx, len(lines)) if sink_sub in lines[i])

    def _pt(line_no: int, col_no: int) -> dict:
        return {
            "line": line_no,
            "col": col_no,
            "offset": sum(len(x.encode("utf-8")) for x in keepends[: line_no - 1]) + col_no - 1,
        }

    def _loc(line_no: int, sub: str) -> dict:
        col = lines[line_no - 1].index(sub) + 1
        return {
            "path": fixture_name,
            "start": _pt(line_no, col),
            "end": _pt(line_no, col + len(sub.encode("utf-8"))),
        }

    sink_loc = _loc(sink_ln, sink_sub)
    doc = {
        "results": [
            {
                "check_id": f"audit.{cwe.lower().replace('-', '_')}",
                "path": fixture_name,
                "start": sink_loc["start"],
                "end": sink_loc["end"],
                "extra": {
                    "severity": "ERROR",
                    "message": "adversarial counterexample finding",
                    "metadata": {"cwe": [cwe]},
                    "dataflow_trace": {
                        "taint_source": ["CliLoc", [_loc(src_ln, source_sub), source_sub]],
                        "intermediate_vars": [],
                        "taint_sink": ["CliLoc", [sink_loc, sink_sub]],
                    },
                },
            }
        ],
        "errors": [],
        "paths": {"skipped": []},
    }
    bundle = collect(
        json.dumps(doc),
        root=FIXTURES_DIR,
        engine_exit=0,
        scan_provenance={"origin": "COUNTEREXAMPLE_UNIT_TEST", "source_capture_verified": True},
    )
    assert not bundle["issues"], bundle["issues"]
    return bundle["records"][0]


class CounterexampleHeuristicRegressions(unittest.TestCase):
    """Covers mandatory Section VI Java fixtures (1..10) and Section XII items (1..6)."""

    def test_ce01_unrelated_integer_parseint_does_not_refute_sqli(self):
        """[REPRODUCES_OLD_BUG_NOW_FIXED] XII.1 / VI.1: Integer.parseInt("7") on safeNumber must not refute SQLi on name."""
        rec = _build_fixture_record(
            "CE01_UnrelatedSanitizerSQLi.java",
            "CWE-89",
            'request.getParameter("name")',
            "stmt.executeQuery(",
        )
        sig = extract_evidence_signals(rec)
        arm_b = heuristic_analyze(rec)
        self.assertEqual(sig["recommended_status"], "SUPPORTED")
        self.assertEqual(arm_b["status"], "SUPPORTED")

    def test_ce02_sanitizer_after_sink_does_not_refute_path_traversal(self):
        """[HARDENED_INVARIANT] XII.2 / VI.2: FilenameUtils.getName appearing after sink line must never refute CWE-22."""
        rec = _build_fixture_record(
            "CE02_SanitizerAfterSinkPathTraversal.java",
            "CWE-22",
            'request.getParameter("file")',
            "new FileInputStream(",
        )
        sig = extract_evidence_signals(rec)
        arm_b = heuristic_analyze(rec)
        self.assertEqual(sig["recommended_status"], "SUPPORTED")
        self.assertEqual(arm_b["status"], "SUPPORTED")

    def test_ce03_safe_constant_in_only_one_if_branch_stays_supported(self):
        """[REPRODUCES_OLD_BUG_NOW_FIXED] XII.3 / VI.3: Constant assignment in single `if` branch leaves else path tainted."""
        rec = _build_fixture_record(
            "CE03_OneBranchOnlySafeAssignment.java",
            "CWE-89",
            'request.getParameter("user")',
            "stmt.executeQuery(",
        )
        sig = extract_evidence_signals(rec)
        arm_b = heuristic_analyze(rec)
        self.assertEqual(sig["recommended_status"], "SUPPORTED")
        self.assertEqual(arm_b["status"], "SUPPORTED")

    def test_ce04_startswith_without_directory_separator_is_rejected_as_containment(self):
        """[REPRODUCES_OLD_BUG_NOW_FIXED] XII.4 / VI.4: startsWith('/reports') allows '/reports-private/...' bypass."""
        rec = _build_fixture_record(
            "CE04_UnsafeStartsWithPrefixBypass.java",
            "CWE-22",
            'request.getParameter("report")',
            "new FileInputStream(target)",
        )
        sig = extract_evidence_signals(rec)
        arm_b = heuristic_analyze(rec)
        self.assertNotEqual(sig["recommended_status"], "REFUTED")
        self.assertEqual(sig["recommended_status"], "SUPPORTED")
        self.assertEqual(arm_b["status"], "SUPPORTED")

    def test_ce05_canonical_path_on_different_file_object_does_not_protect_sink(self):
        """[REPRODUCES_OLD_BUG_NOW_FIXED] XII.5 / VI.5: Checking safeFile.getCanonicalPath() does not sanitize userFile."""
        rec = _build_fixture_record(
            "CE05_CanonicalPathOnDifferentObject.java",
            "CWE-22",
            'request.getParameter("doc")',
            "new FileInputStream(userFile)",
        )
        sig = extract_evidence_signals(rec)
        arm_b = heuristic_analyze(rec)
        self.assertEqual(sig["recommended_status"], "SUPPORTED")
        self.assertEqual(arm_b["status"], "SUPPORTED")

    def test_ce06_unused_filename_utils_clean_name_does_not_sanitize_raw_sink_var(self):
        """[REPRODUCES_OLD_BUG_NOW_FIXED] VI.6: Unused cleanName = FilenameUtils.getName(rawPath) leaves rawPath tainted."""
        rec = _build_fixture_record(
            "CE06_UnusedFilenameUtilsResult.java",
            "CWE-22",
            'request.getParameter("file")',
            "new FileInputStream(",
        )
        sig = extract_evidence_signals(rec)
        arm_b = heuristic_analyze(rec)
        self.assertEqual(sig["recommended_status"], "SUPPORTED")
        self.assertEqual(arm_b["status"], "SUPPORTED")

    def test_ce07_same_method_name_in_different_class_never_cross_contaminates(self):
        """[REPRODUCES_OLD_BUG_NOW_FIXED] VI.7: UnusedSafeHelper.doSomething must not match ExternalUnprovidedHelper or UnsafeHelper."""
        rec_ext = _build_fixture_record(
            "CE07_SameMethodNameDifferentClass.java",
            "CWE-89",
            'request.getParameter("q")',
            "stmt.executeQuery(",
            method_hint="handleExternal",
        )
        sig_ext = extract_evidence_signals(rec_ext)
        self.assertEqual(sig_ext["recommended_status"], "UNDETERMINED")
        self.assertEqual(heuristic_analyze(rec_ext)["status"], "UNDETERMINED")

        rec_inner = _build_fixture_record(
            "CE07_SameMethodNameDifferentClass.java",
            "CWE-89",
            'request.getParameter("q")',
            "stmt.executeQuery(",
            method_hint="handleInnerDispatch",
        )
        sig_inner = extract_evidence_signals(rec_inner)
        self.assertEqual(sig_inner["recommended_status"], "SUPPORTED")

    def test_ce08_multi_hop_indirect_calls_propagate_taint_and_bound_depth(self):
        """[REPRODUCES_OLD_BUG_NOW_FIXED] VI.8: 2-hop passthrough stays SUPPORTED; >3 hops degrades to UNDETERMINED."""
        rec_two_hop = _build_fixture_record(
            "CE08_MultiHopIndirectHelperChain.java",
            "CWE-89",
            'request.getParameter("filter")',
            "stmt.executeQuery(",
            method_hint="handleTwoHopTainted",
        )
        self.assertEqual(extract_evidence_signals(rec_two_hop)["recommended_status"], "SUPPORTED")

        rec_deep = _build_fixture_record(
            "CE08_MultiHopIndirectHelperChain.java",
            "CWE-89",
            'request.getParameter("filter")',
            "stmt.executeQuery(",
            method_hint="handleDeepUnboundedChain",
        )
        self.assertEqual(extract_evidence_signals(rec_deep)["recommended_status"], "UNDETERMINED")

    def test_ce09_sanitized_variable_overwritten_by_tainted_input_stays_supported(self):
        """[REPRODUCES_OLD_BUG_NOW_FIXED] VI.9: Reassigning path = request.getParameter('override') invalidates prior sanitizer."""
        rec = _build_fixture_record(
            "CE09_SanitizedThenOverwrittenByTainted.java",
            "CWE-22",
            'request.getParameter("initial")',
            "new FileInputStream(",
        )
        sig = extract_evidence_signals(rec)
        arm_b = heuristic_analyze(rec)
        self.assertEqual(sig["recommended_status"], "SUPPORTED")
        self.assertEqual(arm_b["status"], "SUPPORTED")

    def test_ce10_missing_helper_implementation_degrades_to_undetermined(self):
        """[REPRODUCES_OLD_BUG_NOW_FIXED] XII.6 / VI.10: Unprovided SeparateClassRequest / MissingSanitizerHelper -> UNDETERMINED."""
        rec = _build_fixture_record(
            "CE10_MissingHelperImplementation.java",
            "CWE-22",
            'scr.getTheValue("id")',
            "new FileInputStream(",
        )
        sig = extract_evidence_signals(rec)
        arm_b = heuristic_analyze(rec)
        self.assertEqual(sig["recommended_status"], "UNDETERMINED")
        self.assertEqual(arm_b["status"], "UNDETERMINED")
        self.assertTrue(any(u.get("reason") == "missing_helper_implementation" for u in sig["unresolved_calls"]))


class CitationProvenanceAndPromptNeutralityRegressions(unittest.TestCase):
    """Covers Section VII, Section VIII, and Section XII items (7..14, 17)."""

    def setUp(self):
        self.rec = _build_fixture_record(
            "CE04_UnsafeStartsWithPrefixBypass.java",
            "CWE-22",
            'request.getParameter("report")',
            "new FileInputStream(target)",
        )
        self.path = self.rec["path"]
        self.sha = self.rec["snapshots"][self.path]["sha256"]
        self.lines_by_no = {
            ln["line"]: ln["text"]
            for s in self.rec["snippets"]
            for ln in s["lines"]
        }

    def _make_payload(self, status: str, start_ln: int, end_ln: int | None = None, quote: str | None = None, sha: str | None = None):
        el = start_ln if end_ln is None else end_ln
        q = "\n".join(self.lines_by_no[i] for i in range(start_ln, el + 1)) if quote is None else quote
        return {
            "status": status,
            "explanation": "Phân tích kiểm thử trích dẫn nguồn.",
            "citations": [
                {
                    "path": self.path,
                    "start_line": start_ln,
                    "end_line": el,
                    "quote": q,
                    "sha256": self.sha if sha is None else sha,
                }
            ],
            "fix_suggestion": "Kiểm tra biên thư mục có dấu phân cách.",
        }

    def test_07_citation_wrong_source_hash_rejected(self):
        """[HARDENED_INVARIANT] XII.7: Citation with wrong source SHA-256 must raise EvidenceError."""
        bad = self._make_payload("SUPPORTED", 15, sha="f" * 64)
        with self.assertRaisesRegex(EvidenceError, "hash"):
            validate_answer(json.dumps(bad), self.rec)

    def test_08_citation_invalid_or_reversed_line_range_rejected(self):
        """[HARDENED_INVARIANT] XII.8: Reversed (start > end) or out-of-snapshot line range must raise EvidenceError."""
        bad_rev = self._make_payload("SUPPORTED", 15, end_ln=15)
        bad_rev["citations"][0]["start_line"] = 16
        bad_rev["citations"][0]["end_line"] = 15
        with self.assertRaisesRegex(EvidenceError, "range"):
            validate_answer(json.dumps(bad_rev), self.rec)

        bad_oob = self._make_payload("SUPPORTED", 15, end_ln=15)
        bad_oob["citations"][0]["start_line"] = 999
        bad_oob["citations"][0]["end_line"] = 999
        with self.assertRaisesRegex(EvidenceError, "not supplied"):
            validate_answer(json.dumps(bad_oob), self.rec)

    def test_09_multiline_citation_missing_middle_or_last_line_rejected(self):
        """[HARDENED_INVARIANT] XII.9: Multi-line citation omitting one of the lines in start_line..end_line is rejected."""
        only_first_line = self.lines_by_no[10]
        bad_multi = self._make_payload("SUPPORTED", 10, end_ln=11, quote=only_first_line)
        with self.assertRaisesRegex(EvidenceError, "disagrees"):
            validate_answer(json.dumps(bad_multi), self.rec)

    def test_10_citation_in_source_but_omitted_from_compacted_prompt_is_flagged_and_rejected(self):
        """[REPRODUCES_OLD_BUG_NOW_FIXED] XII.10 / VII: Line in uncompacted snapshot but outside Arm D prompt window
        must record citation_in_source=True, citation_in_prompt=False, citation_posthoc_only=True and reject in validate_answer.
        """
        # Build a method long enough that line 8 is >3 lines away from source (line 10) and sink (line 15) in `llm` mode
        rec_abl = copy.deepcopy(self.rec)
        rec_abl["triage_mode"] = "llm"
        # Line 7 (`public class CE04_UnsafeStartsWithPrefixBypass {` or line 16 `fis.close();`? Sink is 15, so 15+3=18;
        # source is 10, so 10-3=7. Let's check CE08 which has lines 27..41 outside [sl-3, el+3]!)
        rec_long = _build_fixture_record(
            "CE08_MultiHopIndirectHelperChain.java",
            "CWE-89",
            'request.getParameter("filter")',
            "stmt.executeQuery(",
            method_hint="handleTwoHopTainted",
        )
        rec_long["triage_mode"] = "llm"
        long_lines = {ln["line"]: ln["text"] for s in rec_long["snippets"] for ln in s["lines"]}
        long_sha = rec_long["snapshots"][rec_long["path"]]["sha256"]
        # Line 23 (`return b;` inside `stepTwo`) is in `record["snippets"][0]` (same-file callee),
        # but outside `[8-3..10+3] = [5..13]` in `triage_mode="llm"`!
        self.assertIn(23, long_lines)
        cite_outside_prompt = [
            {
                "path": rec_long["path"],
                "start_line": 23,
                "end_line": 23,
                "quote": long_lines[23],
                "sha256": long_sha,
            }
        ]
        prov = inspect_citations_provenance(cite_outside_prompt, rec_long)
        self.assertTrue(prov["citation_in_source"])
        self.assertFalse(prov["citation_in_prompt"])
        self.assertTrue(prov["citation_posthoc_only"])
        self.assertFalse(prov["supports_security_claim_verified"])

        payload = {
            "status": "SUPPORTED",
            "explanation": "Trích dẫn dòng không nằm trong prompt rút gọn.",
            "citations": cite_outside_prompt,
            "fix_suggestion": "Sử dụng PreparedStatement.",
        }
        with self.assertRaisesRegex(EvidenceError, "not supplied in model prompt"):
            validate_answer(json.dumps(payload), rec_long)

    def test_11_comment_only_and_whitespace_only_citations_rejected(self):
        """[REPRODUCES_OLD_BUG_NOW_FIXED] XII.11 / VII: Comment-only and whitespace/brace-only lines cannot ground verdicts."""
        # Line 9 in CE04 is a `// ...` comment line; line 17 is `    }` brace-only
        self.assertTrue(self.lines_by_no[9].strip().startswith("//"))
        comment_payload = self._make_payload("SUPPORTED", 9)
        with self.assertRaisesRegex(EvidenceError, "executable Java code"):
            validate_answer(json.dumps(comment_payload), self.rec)

        brace_payload = self._make_payload("SUPPORTED", 17)
        with self.assertRaisesRegex(EvidenceError, "executable Java code"):
            validate_answer(json.dumps(brace_payload), self.rec)

        # Inject a non-empty whitespace line into snippet and snapshot to test pure-whitespace rejection
        ws_text = "class W {\n void f(HttpServletRequest r) {\n    \n  new java.io.File(r.getParameter(\"p\"));\n }\n}\n"
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "W.java"
            p.write_bytes(ws_text.encode("utf-8"))
            keep = ws_text.splitlines(keepends=True)
            off4 = sum(len(x.encode("utf-8")) for x in keep[:3]) + 2
            sub = 'new java.io.File(r.getParameter("p"))'
            loc4 = {
                "path": "W.java",
                "start": {"line": 4, "col": 3, "offset": off4},
                "end": {"line": 4, "col": 3 + len(sub), "offset": off4 + len(sub)},
            }
            doc = {
                "results": [{
                    "check_id": "audit.cwe22",
                    "path": "W.java",
                    "start": loc4["start"],
                    "end": loc4["end"],
                    "extra": {
                        "severity": "ERROR",
                        "metadata": {"cwe": ["CWE-22"]},
                        "dataflow_trace": {
                            "taint_source": ["CliLoc", [loc4, sub]],
                            "intermediate_vars": [],
                            "taint_sink": ["CliLoc", [loc4, sub]],
                        },
                    },
                }],
                "errors": [],
            }
            w_rec = collect(
                json.dumps(doc),
                root=Path(tmp),
                engine_exit=0,
                scan_provenance={"origin": "TEST", "source_capture_verified": True},
            )["records"][0]
            w_sha = w_rec["snapshots"]["W.java"]["sha256"]
            ws_payload = {
                "status": "SUPPORTED",
                "explanation": "Dòng khoảng trắng.",
                "citations": [{"path": "W.java", "start_line": 3, "end_line": 3, "quote": "    ", "sha256": w_sha}],
                "fix_suggestion": "Fix.",
            }
            with self.assertRaisesRegex(EvidenceError, "executable Java code"):
                validate_answer(json.dumps(ws_payload), w_rec)

    def test_12_supported_without_valid_scoped_evidence_is_rejected(self):
        """[REPRODUCES_OLD_BUG_NOW_FIXED] XII.12: SUPPORTED with empty citations or out-of-method citation is rejected."""
        empty_sup = {
            "status": "SUPPORTED",
            "explanation": "Thiếu trích dẫn.",
            "citations": [],
            "fix_suggestion": "Fix.",
        }
        with self.assertRaisesRegex(EvidenceError, "requires citations"):
            validate_answer(json.dumps(empty_sup), self.rec)

        # Cite UnusedSafeHelper line in CE07 (outside handleInnerDispatch and its callee UnsafeHelper)
        rec_ce07 = _build_fixture_record(
            "CE07_SameMethodNameDifferentClass.java",
            "CWE-89",
            'request.getParameter("q")',
            "stmt.executeQuery(",
            method_hint="handleInnerDispatch",
        )
        # Artificially append UnusedSafeHelper line 21 into snippet + prompt to verify scope rejection
        full_lines = (FIXTURES_DIR / "CE07_SameMethodNameDifferentClass.java").read_text(encoding="utf-8").splitlines()
        rec_ce07["snippets"][0]["lines"].append({"line": 21, "text": full_lines[20]})
        sha07 = rec_ce07["snapshots"][rec_ce07["path"]]["sha256"]
        wrong_scope_sup = {
            "status": "SUPPORTED",
            "explanation": "Trích dẫn nhầm lớp không được gọi.",
            "citations": [{
                "path": rec_ce07["path"],
                "start_line": 21,
                "end_line": 21,
                "quote": full_lines[20],
                "sha256": sha07,
            }],
            "fix_suggestion": "Fix.",
        }
        with self.assertRaisesRegex(EvidenceError, "outside enclosing method"):
            validate_answer(json.dumps(wrong_scope_sup), rec_ce07)

    def test_13_refuted_with_missing_helper_or_dead_branch_citation_is_rejected(self):
        """[REPRODUCES_OLD_BUG_NOW_FIXED] XII.13: REFUTED cannot pass when flow relies on missing helper or dead branch."""
        rec_missing = _build_fixture_record(
            "CE10_MissingHelperImplementation.java",
            "CWE-22",
            'scr.getTheValue("id")',
            "new FileInputStream(",
        )
        m_lines = {ln["line"]: ln["text"] for s in rec_missing["snippets"] for ln in s["lines"]}
        m_sha = rec_missing["snapshots"][rec_missing["path"]]["sha256"]
        refuted_missing_helper = {
            "status": "REFUTED",
            "explanation": "Suy đoán sai scr.getTheValue an toàn dù không có mã nguồn SeparateClassRequest.",
            "citations": [{
                "path": rec_missing["path"],
                "start_line": 8,
                "end_line": 8,
                "quote": m_lines[8],
                "sha256": m_sha,
            }],
            "fix_suggestion": "",
        }
        with self.assertRaisesRegex(EvidenceError, "external helper absent"):
            validate_answer(json.dumps(refuted_missing_helper), rec_missing)

    def test_14_truncated_ollama_json_or_incomplete_done_reason_becomes_undetermined(self):
        """[HARDENED_INVARIANT] XII.14: Truncated JSON or done_reason='length' must degrade cleanly to UNDETERMINED."""
        client = OllamaClient(model="qwen3.5:9b-q4_K_M", runtime_origin="mock")
        truncated_resp = {
            "model": "qwen3.5:9b-q4_K_M",
            "done": True,
            "done_reason": "stop",
            "eval_count": 42,
            "eval_duration": 1000,
            "mock_test_fixture": True,
            "message": {"role": "assistant", "content": '{"status":"REFUTED","explanation":"cut off...'},
        }
        with patch.object(client, "request", return_value=truncated_resp):
            out = client.analyze(self.rec)
        self.assertEqual(out["status"], "UNDETERMINED")
        self.assertEqual(out["citation_check"], "NOT_VERIFIED")
        self.assertTrue(out["requires_human_review"])

        length_cutoff_resp = {
            **truncated_resp,
            "done_reason": "length",
            "message": {"role": "assistant", "content": json.dumps(self._make_payload("SUPPORTED", 15))},
        }
        with patch.object(client, "request", return_value=length_cutoff_resp):
            out2 = client.analyze(self.rec)
        self.assertEqual(out2["status"], "UNDETERMINED")

    def test_section_viii_neutral_prompt_excludes_heuristic_verdict_and_citations(self):
        """[REPRODUCES_OLD_BUG_NOW_FIXED] VIII: Active v2.2 request_payload strips recommended_status,
        recommendation_reason, candidate_citations, and OWASP SeparateClassRequest hints while preserving
        forensic replay via legacy_v2_1_request_payload.
        """
        self.assertEqual(PROMPT_VERSION, "v2.2.1-cwe22-cwe89-whitelist")
        self.assertEqual(LEGACY_STEERED_PROMPT_VERSION, "v2.1-cwe22-cwe89-grounded")

        active_req = request_payload(self.rec, "qwen3.5:9b-q4_K_M")
        sys_txt = active_req["messages"][0]["content"]
        usr_obj = json.loads(active_req["messages"][1]["content"])
        ev_sig = usr_obj["evidence_signals"]

        for forbidden_key in (
            "recommended_status",
            "recommendation_reason",
            "candidate_citations",
            "intra_method_flow",
            "callee_method_flow",
            "sanitizers_found",
        ):
            self.assertNotIn(forbidden_key, ev_sig)
        self.assertNotIn("candidate_citations", sys_txt)
        self.assertNotIn("SeparateClassRequest.getTheValue", sys_txt)

        # Legacy v2.1 replay helper explicitly reproduces historical steered structure for hash forensics
        legacy_req = legacy_v2_1_request_payload(self.rec, "qwen3.5:9b-q4_K_M")
        legacy_usr = json.loads(legacy_req["messages"][1]["content"])
        self.assertIn("recommended_status", legacy_usr["evidence_signals"])
        self.assertIn("candidate_citations", legacy_usr["evidence_signals"])
        self.assertNotEqual(
            digest(json.dumps(active_req).encode("utf-8")),
            digest(json.dumps(legacy_req).encode("utf-8")),
        )


if __name__ == "__main__":
    unittest.main()
