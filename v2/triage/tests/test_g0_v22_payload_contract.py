"""G0 audit of the v2.2 prompt payload contract and the REFUTED evidence-completeness gate.

These are static/synthetic tests. They verify what is sent to Ollama and what the verifier accepts;
they say nothing about Qwen accuracy on real data.

Tag legend:
- [REPRODUCES_V22_GAP_NOW_FIXED]: reproduces a gap present at commit 03cd872 and checks the fix.
- [HARDENED_INVARIANT]: fail-closed invariant against planted/adversarial input.
- [NO_OVERBLOCK_CONTROL]: positive control showing the gate does not reject a provable case.
"""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from test_blind_spot_regressions import _build_fixture_record  # noqa: E402
from v2.triage.evidence import EvidenceError  # noqa: E402
from v2.triage import ollama  # noqa: E402
from v2.triage.ollama import (  # noqa: E402
    NEUTRAL_HINT_WHITELIST,
    PROMPT_CONTRACT_BLIND,
    PROMPT_CONTRACT_NEUTRAL_HINTS,
    STEERING_SIGNAL_KEYS,
    OllamaClient,
    assert_prompt_contract,
    neutralize_evidence_signals,
    request_payload,
    validate_answer,
)

MODEL = "qwen3.5:9b-q4_K_M"
VERDICT_TOKENS = ("SUPPORTED", "REFUTED", "UNDETERMINED", "SAFE_CONST", "TAINTED", "SANITIZED_CWE")


def _v22_blacklist(signals):
    """Exact reproduction of neutralize_evidence_signals() at commit 03cd872 (blacklist), for before/after."""
    return {k: v for k, v in signals.items() if k not in STEERING_SIGNAL_KEYS}


def _pl01():
    return _build_fixture_record(
        "PL01_ConstantSwitchPayloadProbe.java", "CWE-89", 'request.getParameter("q")', "stmt.executeQuery("
    )


def _user_payload(record):
    return json.loads(request_payload(record, MODEL)["messages"][1]["content"])


def _non_source_strings(node, parent=None, out=None):
    """Collect strings that are not verbatim source text (snippet line text / matched / source-derived names)."""
    out = [] if out is None else out
    if isinstance(node, dict):
        for key, value in node.items():
            _non_source_strings(value, key, out)
    elif isinstance(node, list):
        for value in node:
            _non_source_strings(value, parent, out)
    elif isinstance(node, str) and parent not in ollama._PROMPT_SOURCE_TEXT_KEYS:
        out.append(node)
    return out


def _all_keys(node, out=None):
    out = set() if out is None else out
    if isinstance(node, dict):
        for key, value in node.items():
            out.add(key)
            _all_keys(value, out)
    elif isinstance(node, list):
        for value in node:
            _all_keys(value, out)
    return out


def _refuted_on_line(record, line_no, status="REFUTED"):
    lines = {ln["line"]: ln["text"] for s in record["snippets"] for ln in s["lines"]}
    return json.dumps({
        "status": status,
        "explanation": "Kiểm thử cổng xác minh.",
        "fix_suggestion": "",
        "citations": [{
            "path": record["path"],
            "start_line": line_no,
            "end_line": line_no,
            "quote": lines[line_no],
            "sha256": record["snapshots"][record["path"]]["sha256"],
        }],
    })


class PayloadContractAudit(unittest.TestCase):
    def test_01_v22_blacklist_leaked_dead_branch_result_now_whitelisted(self):
        """[REPRODUCES_V22_GAP_NOW_FIXED] Constant switch: dead_branch_lines pointed at the tainted branch."""
        rec = _pl01()
        rec["prompt_contract"] = PROMPT_CONTRACT_NEUTRAL_HINTS
        sig = rec["heuristic_signals"]
        self.assertEqual(sig["recommended_status"], "REFUTED")
        self.assertTrue(sig["dead_branch_lines"], "fixture must exercise the dead-branch analysis")
        before = _v22_blacklist(sig)
        self.assertIn("dead_branch_lines", before)  # leak present in 03cd872 payload
        after = _user_payload(rec)["evidence_signals"]
        self.assertTrue(set(after) <= set(NEUTRAL_HINT_WHITELIST))
        for key in ("dead_branch_lines", "non_sanitizers_found", "uses_inner_helper", "uses_thing_factory",
                    "unresolved_calls", "heuristic_version", "primary_cwe"):
            self.assertNotIn(key, after)

    def test_02_nested_and_unknown_fields_cannot_pass_through(self):
        """[REPRODUCES_V22_GAP_NOW_FIXED] Nested verdict text inside an allowed list and unknown keys are dropped."""
        rec = _pl01()
        rec["prompt_contract"] = PROMPT_CONTRACT_NEUTRAL_HINTS
        planted = copy.deepcopy(rec["heuristic_signals"])
        planted["verdict_hint"] = "REFUTED"
        planted["extra"] = {"recommended_status": "REFUTED", "recommendation_reason": "safe constant"}
        planted["unresolved_calls"] = [
            {"qualifier": "helper", "method": "clean", "line": 9, "reason": "missing_helper_implementation",
             "recommended_status": "REFUTED", "note": "REFUTED because constant"},
            {"method": "wrap", "line": 10},  # taint-conditioned entry (no reason) must not be sent
            {"qualifier": "x", "method": "deep", "line": 11, "reason": "max_hop_depth_exceeded"},
            {"method": "bad name; REFUTED", "line": 12, "reason": "missing_helper_implementation"},
        ]
        before = json.dumps(_v22_blacklist(planted))
        self.assertIn("REFUTED", before)  # old blacklist forwarded nested verdict text
        rec["heuristic_signals"] = planted
        user = _user_payload(rec)
        sig = user["evidence_signals"]
        self.assertEqual(sig["unresolved_external_calls"], [{"method": "clean", "line": 9, "qualifier": "helper"}])
        self.assertTrue(set(sig) <= set(NEUTRAL_HINT_WHITELIST))
        for text in _non_source_strings(user):
            for token in VERDICT_TOKENS:
                self.assertNotIn(token, text)
        self.assertFalse(_all_keys(user) & (STEERING_SIGNAL_KEYS | {"verdict_hint", "extra", "note", "reason"}))

    def test_03_blind_contract_is_g1_default_and_sends_no_heuristic_signals(self):
        """[HARDENED_INVARIANT] G1 default is blind: code, location, trace and structural Java context only."""
        self.assertEqual(ollama.DEFAULT_PROMPT_CONTRACT, PROMPT_CONTRACT_BLIND)
        for explicit in (None, PROMPT_CONTRACT_BLIND):
            rec = _pl01()
            if explicit is not None:
                rec["prompt_contract"] = explicit
            user = _user_payload(rec)
            self.assertNotIn("evidence_signals", user)
            self.assertEqual(set(user), {"rule_id", "cwe", "severity", "start", "end", "snippets", "trace_steps",
                                         "java_context_summary"})
            self.assertFalse(_all_keys(user) & ollama._FORBIDDEN_PROMPT_KEYS)

    def test_04_java_context_summary_is_projected_not_copied(self):
        """[HARDENED_INVARIANT] Extra fields planted in java_context never reach the model."""
        rec = _pl01()
        rec["java_context"] = copy.deepcopy(rec["java_context"])
        rec["java_context"]["enclosing_method"]["recommended_status"] = "REFUTED"
        rec["java_context"]["enclosing_method"]["dead_branch_lines"] = [13]
        for contract in (PROMPT_CONTRACT_BLIND, PROMPT_CONTRACT_NEUTRAL_HINTS):
            rec["prompt_contract"] = contract
            user = _user_payload(rec)
            enc = user["java_context_summary"]["enclosing_method"]
            self.assertNotIn("recommended_status", enc)
            self.assertNotIn("dead_branch_lines", enc)
            self.assertEqual(enc["name"], "handle")

    def test_05_contract_guard_rejects_planted_payloads(self):
        """[HARDENED_INVARIANT] The final guard detects forbidden keys/tokens even if a builder regresses."""
        base = {"rule_id": "r", "cwe": ["CWE-89"], "severity": "ERROR", "snippets": [], "trace_steps": []}
        self.assertTrue(assert_prompt_contract(dict(base), PROMPT_CONTRACT_BLIND))
        bad_cases = [
            (PROMPT_CONTRACT_BLIND, {**base, "evidence_signals": {"source_line": 1}}),
            (PROMPT_CONTRACT_NEUTRAL_HINTS, {**base, "evidence_signals": {"dead_branch_lines": [3]}}),
            (PROMPT_CONTRACT_NEUTRAL_HINTS, {**base, "trace_steps": [{"role": "sink", "x": {"candidate_citations": []}}]}),
            (PROMPT_CONTRACT_NEUTRAL_HINTS, {**base, "severity": "ERROR (heuristic: REFUTED)"}),
            ("C_full_with_verdict", dict(base)),
        ]
        for contract, payload in bad_cases:
            with self.assertRaises(EvidenceError):
                assert_prompt_contract(payload, contract)
        # Source code text that happens to contain a verdict word is not a heuristic leak.
        src = {**base, "snippets": [{"path": "A.java", "lines": [{"line": 1, "text": "// SUPPORTED by docs"}]}]}
        self.assertTrue(assert_prompt_contract(src, PROMPT_CONTRACT_BLIND))

    def test_06_final_payload_captured_at_ollama_boundary(self):
        """[HARDENED_INVARIANT] Trace to the JSON body actually handed to the HTTP layer by analyze()."""
        rec = _pl01()
        captured = []

        def fake_request(self_client, path, payload=None):
            captured.append(json.loads(json.dumps(payload)))
            return {"done": True, "done_reason": "stop", "model": MODEL,
                    "message": {"content": _refuted_on_line(rec, 23, status="SUPPORTED")}}

        for contract in (PROMPT_CONTRACT_BLIND, PROMPT_CONTRACT_NEUTRAL_HINTS):
            rec["prompt_contract"] = contract
            captured.clear()
            with patch.object(OllamaClient, "request", fake_request):
                out = OllamaClient().analyze(rec)
            self.assertEqual(len(captured), 1)
            body = captured[0]
            user = json.loads(body["messages"][1]["content"])
            self.assertFalse(_all_keys(user) & ollama._FORBIDDEN_PROMPT_KEYS)
            self.assertNotIn("candidate_citations", body["messages"][0]["content"])
            self.assertEqual(out["prompt_contract"], contract)
            self.assertTrue(out["requires_human_review"])

    def test_07_unknown_contract_fails_closed(self):
        """[HARDENED_INVARIANT] An unknown contract name yields UNDETERMINED, never a request."""
        rec = _pl01()
        rec["prompt_contract"] = "C_full_with_verdict"
        with patch.object(OllamaClient, "request", side_effect=AssertionError("must not be called")):
            out = OllamaClient().analyze(rec)
        self.assertEqual(out["status"], "UNDETERMINED")
        self.assertIn("unknown prompt contract", out["explanation"])

    def test_08_whitelist_function_rejects_non_dict(self):
        self.assertIsNone(neutralize_evidence_signals(None))
        self.assertIsNone(neutralize_evidence_signals(["REFUTED"]))
        self.assertEqual(neutralize_evidence_signals({"source_line": "7", "source_kind": "REFUTED"}), {})


class RefutedEvidenceCompletenessGate(unittest.TestCase):
    def test_09_refuted_on_call_chain_beyond_hop_depth_is_rejected(self):
        """[REPRODUCES_V22_GAP_NOW_FIXED] 03cd872 accepted REFUTED when unresolved reason was max_hop_depth_exceeded."""
        rec = _build_fixture_record(
            "CE08_MultiHopIndirectHelperChain.java", "CWE-89", 'request.getParameter("filter")',
            "stmt.executeQuery(", method_hint="handleDeepUnboundedChain",
        )
        sig = rec["heuristic_signals"]
        self.assertEqual(sig["recommended_status"], "UNDETERMINED")
        self.assertTrue(any(u.get("reason") == "max_hop_depth_exceeded" for u in sig["unresolved_calls"]))
        with self.assertRaisesRegex(EvidenceError, "call path is unresolved"):
            validate_answer(_refuted_on_line(rec, rec["start"]["line"]), rec)
        # A SUPPORTED answer keeps the alert and is not blocked by this gate.
        self.assertEqual(validate_answer(_refuted_on_line(rec, rec["start"]["line"], "SUPPORTED"), rec)["status"],
                         "SUPPORTED")

    def test_10_refuted_without_completeness_analysis_is_rejected(self):
        """[REPRODUCES_V22_GAP_NOW_FIXED] heuristic_signals=None (extraction failure) skipped the gate in 03cd872."""
        for fixture, src, sink, hint in (
            ("CE10_MissingHelperImplementation.java", 'scr.getTheValue("id")', "new FileInputStream(", None),
            ("CE07_SameMethodNameDifferentClass.java", 'request.getParameter("q")', "stmt.executeQuery(", "handleExternal"),
        ):
            cwe = "CWE-22" if "CE10" in fixture else "CWE-89"
            rec = _build_fixture_record(fixture, cwe, src, sink, method_hint=hint)
            rec["heuristic_signals"] = None
            with self.assertRaisesRegex(EvidenceError, "flow-completeness analysis"):
                validate_answer(_refuted_on_line(rec, rec["start"]["line"]), rec)

    def test_11_missing_helper_still_rejected(self):
        """[HARDENED_INVARIANT] Regression guard for the existing missing-helper rule."""
        rec = _build_fixture_record(
            "CE10_MissingHelperImplementation.java", "CWE-22", 'scr.getTheValue("id")', "new FileInputStream("
        )
        with self.assertRaisesRegex(EvidenceError, "external helper absent"):
            validate_answer(_refuted_on_line(rec, rec["start"]["line"]), rec)

    def test_12_provable_constant_branch_refuted_is_not_overblocked(self):
        """[NO_OVERBLOCK_CONTROL] All-in-file constant switch: REFUTED with a valid sink citation is accepted
        (still OPEN / requires_human_review)."""
        rec = _pl01()
        out = validate_answer(_refuted_on_line(rec, 23), rec)
        self.assertEqual(out["status"], "REFUTED")
        self.assertTrue(out["requires_human_review"])
        self.assertFalse(out["security_conclusion_verified"])

    def test_13_refuted_citing_dead_tainted_branch_is_rejected(self):
        """[HARDENED_INVARIANT] Citing only the dead `bar = param;` line cannot support a conclusion."""
        rec = _pl01()
        with self.assertRaisesRegex(EvidenceError, "dead-branch"):
            validate_answer(_refuted_on_line(rec, 13), rec)


class JsonSarifConsistencyGate(unittest.TestCase):
    """Receipt must not report a verified capture when the JSON and SARIF of the same scan disagree."""

    def setUp(self):
        import tempfile
        from capture_fixture import make_capture
        from v2.triage.scan_receipt import json_sarif_disagreement, verify_receipt
        self.make_capture, self.verify_receipt, self.disagree = make_capture, verify_receipt, json_sarif_disagreement
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = TESTS_DIR / "fixtures" / "counterexamples"
        self.doc = {"results": [{
            "check_id": "audit.cwe_89", "path": "CE01_UnrelatedSanitizerSQLi.java",
            "start": {"line": 10, "col": 9, "offset": 0}, "end": {"line": 10, "col": 20, "offset": 0},
            "extra": {"metadata": {"cwe": ["CWE-89"]}}}], "errors": [], "paths": {"skipped": []}}
        self.raw = json.dumps(self.doc).encode("utf-8")

    def _sarif(self, results):
        return json.dumps({"runs": [{"tool": {"driver": {"name": "t"}}, "results": results}]}).encode("utf-8")

    def _res(self, rule, uri, line):
        return {"ruleId": rule, "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri},
                                                                   "region": {"startLine": line}}}]}

    def test_14_real_opengrep_json_sarif_pair_agrees(self):
        """[NO_OVERBLOCK_CONTROL] Real OpenGrep OSS 1.25.0 JSON/SARIF pair committed under v2/demo agrees."""
        demo = REPO_ROOT / "v2" / "demo"
        j = json.loads((demo / "smoke_v2_taint_raw.opengrep.json").read_text(encoding="utf-8"))
        s = json.loads((demo / "smoke_v2_taint_raw.opengrep.sarif").read_text(encoding="utf-8"))
        self.assertIsNone(self.disagree(j, s))

    def test_15_planted_sarif_divergence_is_detected(self):
        """[REPRODUCES_V22_GAP_NOW_FIXED] 03cd872 accepted any structurally valid SARIF (even with zero results)."""
        ok = self._res("audit.cwe_89", "CE01_UnrelatedSanitizerSQLi.java", 10)
        self.assertIsNone(self.disagree(self.doc, json.loads(self._sarif([ok]))))
        enc = self._res("audit.cwe_89", "./CE01_UnrelatedSanitizerSQLi%2Ejava", 10)
        self.assertIsNone(self.disagree(self.doc, json.loads(self._sarif([enc]))))
        planted = [
            [],                                                                   # finding dropped
            [ok, ok],                                                             # finding duplicated
            [self._res("audit.cwe_89", "CE01_UnrelatedSanitizerSQLi.java", 11)],  # line shifted
            [self._res("audit.cwe_22", "CE01_UnrelatedSanitizerSQLi.java", 10)],  # rule swapped
            [self._res("audit.cwe_89", "Other.java", 10)],                         # file swapped
            [{"ruleId": "audit.cwe_89"}],                                         # malformed location
        ]
        for results in planted:
            self.assertIsNotNone(self.disagree(self.doc, json.loads(self._sarif(results))))

    def test_16_receipt_with_divergent_sarif_is_not_source_verified(self):
        """[HARDENED_INVARIANT] End-to-end receipt: divergent SARIF -> issue + source_capture_verified False."""
        good = self.make_capture(self.root, self.raw, Path(self.tmp.name) / "good")
        meta, issues = self.verify_receipt(good, self.raw, self.root, 0)
        self.assertEqual(issues, [])
        self.assertTrue(meta["source_capture_verified"])
        bad = self.make_capture(self.root, self.raw, Path(self.tmp.name) / "bad", sarif=self._sarif([]))
        meta, issues = self.verify_receipt(bad, self.raw, self.root, 0)
        self.assertFalse(meta["source_capture_verified"])
        self.assertTrue(any("JSON and SARIF findings disagree" in i for i in issues))


if __name__ == "__main__":
    unittest.main()
