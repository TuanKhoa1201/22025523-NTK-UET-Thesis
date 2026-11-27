"""Adversarial counterexample & near-miss control tests for backend G3 repair (G3-J01..J05, G3-C01..C02, G3-A01..A03).

Self-contained: uses only temporary directories and synthetic Java fixtures (zero private paths or external assets).
"""
from __future__ import annotations

import ast
from hashlib import sha256
import json
import math
from pathlib import Path
import tempfile
import unittest

from v2.api.config import ApiConfig
from v2.api.opengrep_runner import (
    compute_opengrep_coverage_telemetry,
    validate_coverage_telemetry_payload,
)
from v2.api.qwen_triage import run_bounded_triage
from v2.api.service import DiscoveredScan, TriageApiService
from v2.api.tests.test_backend_g3_quality_improvements import (
    _make_record,
    _mock_model_assessment,
)
from v2.api.triage_gate import apply_integration_gate
from v2.triage import evidence, live_check, ollama
from v2.triage.verify_http_capture import verify_run_http_captures


def _run_both_layers(rec: dict, status: str = "REFUTED", cite_lines: list[int] | None = None) -> dict:
    ass = _mock_model_assessment(rec, status, cite_lines=cite_lines)
    direct = apply_integration_gate(rec, ass)
    raw_keys = ("status", "explanation", "fix_suggestion", "citations")
    try:
        validated = ollama.validate_answer(json.dumps({k: ass[k] for k in raw_keys}), rec)
        gated = apply_integration_gate(rec, dict(ass, **validated))
        through = {
            "accepted_by_validator": True,
            "status": gated["status"],
            "failure_kind": gated.get("failure_kind"),
            "proof": gated.get("independent_refutation_proof"),
        }
    except Exception as exc:
        through = {"accepted_by_validator": False, "error": str(exc)}
    return {
        "direct_status": direct["status"],
        "direct_failure_kind": direct.get("failure_kind"),
        "direct_proof": direct.get("independent_refutation_proof"),
        "security_conclusion_verified": direct.get("security_conclusion_verified"),
        "requires_human_review": direct.get("requires_human_review"),
        "through": through,
    }


def _wrap_sqli_case(body: str, members: str = "", imports: str = "") -> tuple[str, int]:
    src = (
        "package demo;\n"
        "import java.sql.Statement;\n"
        "import javax.servlet.http.HttpServletRequest;\n"
        + imports
        + "class Case {\n"
        "    void run(HttpServletRequest req, Statement stmt) throws Exception {\n"
        "        String input = req.getParameter(\"p\");\n"
        + body
        + "\n        stmt.executeQuery(sql);\n"
        "    }\n"
        + members
        + "}\n"
    )
    line = next(i for i, t in enumerate(src.splitlines(), 1) if "stmt.executeQuery(sql)" in t)
    return src, line


class TriageSafetyRepairCounterexampleTests(unittest.TestCase):
    """Covers Codex G3-J01, G3-J02, G3-J03, G3-J04, G3-J05 and near-miss safe/unsafe variants."""

    def test_j01_hashmap_octal_unicode_and_safe_two_key_controls(self) -> None:
        # Counterexample G3-J01: octal "\101" == "A" overwrites key "A" with tainted input
        octal_overwrite = (
            "        java.util.Map<String,String> m = new java.util.HashMap<String,String>();\n"
            '        m.put("A", "fixed");\n'
            '        m.put("\\101", input);\n'
            '        String value = m.get("A");\n'
            '        String sql = "query " + value;'
        )
        # Near-miss variant 1: 2-digit octal "\40" == " " overwrites " "
        octal_space = (
            "        java.util.Map<String,String> m = new java.util.HashMap<String,String>();\n"
            '        m.put(" ", "fixed");\n'
            '        m.put("\\40", input);\n'
            '        String value = m.get(" ");\n'
            '        String sql = "query " + value;'
        )
        # Near-miss variant 2: JLS §3.3 Unicode escape "\u0041" == "A"
        unicode_overwrite = (
            "        java.util.Map<String,String> m = new java.util.HashMap<String,String>();\n"
            '        m.put("A", "fixed");\n'
            '        m.put("\\u0041", input);\n'
            '        String value = m.get("A");\n'
            '        String sql = "query " + value;'
        )
        # Near-miss variant 3: JLS §3.3 Unicode escape inside comment (newline breakout)
        unicode_comment_breakout = (
            '        String value = "fixed";\n'
            "        // \\u000a value = input;\n"
            '        String sql = "query " + value;'
        )
        # Safe control: distinct keys "A" and "\102" ("B"), reading "A" stays constant
        safe_distinct_octal = (
            "        java.util.Map<String,String> m = new java.util.HashMap<String,String>();\n"
            '        m.put("A", "fixed");\n'
            '        m.put("\\102", input);\n'
            '        String value = m.get("A");\n'
            '        String sql = "query " + value;'
        )
        with tempfile.TemporaryDirectory() as td:
            for name, body in (
                ("octal_overwrite", octal_overwrite),
                ("octal_space", octal_space),
                ("unicode_overwrite", unicode_overwrite),
                ("unicode_comment_breakout", unicode_comment_breakout),
            ):
                src, line = _wrap_sqli_case(body)
                rec, _ = _make_record(Path(td) / name, "demo/Case.java", src, sink_line=line)
                res = _run_both_layers(rec, "REFUTED", cite_lines=[line])
                self.assertEqual(res["direct_status"], "UNDETERMINED", f"{name}: {res}")
                self.assertFalse(res["security_conclusion_verified"])
                self.assertTrue(res["requires_human_review"])
                if res["through"]["accepted_by_validator"]:
                    self.assertEqual(res["through"]["status"], "UNDETERMINED", f"{name}: {res}")

            # Safe control preserves LOCAL_HASHMAP_CONSTANT_FLOW
            src_ok, line_ok = _wrap_sqli_case(safe_distinct_octal)
            rec_ok, _ = _make_record(Path(td) / "safe_distinct_octal", "demo/Case.java", src_ok, sink_line=line_ok)
            res_ok = _run_both_layers(rec_ok, "REFUTED", cite_lines=[line_ok])
            self.assertEqual(res_ok["direct_status"], "REFUTED", res_ok)
            self.assertEqual(res_ok["direct_proof"], "LOCAL_HASHMAP_CONSTANT_FLOW")
            self.assertEqual(res_ok["through"]["status"], "REFUTED", res_ok)

    def test_j02_j03_switch_octal_char_and_utf16_surrogate_controls(self) -> None:
        # G3-J02: switch ("\101") takes case "A" (tainted), NOT case "101"
        sw_octal_str = (
            "        String value;\n"
            '        switch ("\\101") {\n'
            '            case "101": value = "fixed"; break;\n'
            '            case "A": value = input; break;\n'
            "            default: value = input; break;\n"
            "        }\n"
            '        String sql = "query " + value;'
        )
        # Near-miss G3-J02 char octal: switch ('\101') takes case 'A' (tainted)
        sw_octal_char = (
            "        String value;\n"
            "        switch ('\\101') {\n"
            "            case 'B': value = \"fixed\"; break;\n"
            "            case 'A': value = input; break;\n"
            "            default: value = input; break;\n"
            "        }\n"
            '        String sql = "query " + value;'
        )
        # G3-J03: "😀A".charAt(1) is low surrogate 0xDE00 on JDK -> default (tainted), NOT 'A'
        sw_utf16_surrogate = (
            '        String seed = "\U0001f600A";\n'
            "        char selector = seed.charAt(1);\n"
            "        String value;\n"
            "        switch (selector) {\n"
            "            case 'A': value = \"fixed\"; break;\n"
            "            default: value = input; break;\n"
            "        }\n"
            '        String sql = "query " + value;'
        )
        # Near-miss G3-J03: even default="fixed" on non-BMP string fails closed conservatively
        sw_utf16_non_bmp_default_safe = (
            '        String seed = "\U0001f600A";\n'
            "        char selector = seed.charAt(1);\n"
            "        String value;\n"
            "        switch (selector) {\n"
            "            case 'A': value = input; break;\n"
            "            default: value = \"fixed\"; break;\n"
            "        }\n"
            '        String sql = "query " + value;'
        )
        # Safe BMP control: "ÁB".charAt(1) == 'B' (both BMP code points, 1-to-1 UTF-16)
        sw_bmp_safe = (
            '        String seed = "\\u00c1B";\n'  # note: tested below with literal BMP 'ÁB' (not \u)
            "        char selector = seed.charAt(1);\n"
            "        String value;\n"
            "        switch (selector) {\n"
            "            case 'B': value = \"fixed\"; break;\n"
            "            default: value = input; break;\n"
            "        }\n"
            '        String sql = "query " + value;'
        ).replace("\\u00c1B", "\u00c1B")

        with tempfile.TemporaryDirectory() as td:
            for name, body in (
                ("sw_octal_str", sw_octal_str),
                ("sw_octal_char", sw_octal_char),
                ("sw_utf16_surrogate", sw_utf16_surrogate),
                ("sw_utf16_non_bmp_default_safe", sw_utf16_non_bmp_default_safe),
            ):
                src, line = _wrap_sqli_case(body)
                rec, _ = _make_record(Path(td) / name, "demo/Case.java", src, sink_line=line)
                res = _run_both_layers(rec, "REFUTED", cite_lines=[line])
                self.assertEqual(res["direct_status"], "UNDETERMINED", f"{name}: {res}")

            # Safe BMP control proves DETERMINISTIC_CONSTANT_SWITCH
            src_bmp, line_bmp = _wrap_sqli_case(sw_bmp_safe)
            rec_bmp, _ = _make_record(Path(td) / "sw_bmp_safe", "demo/Case.java", src_bmp, sink_line=line_bmp)
            res_bmp = _run_both_layers(rec_bmp, "REFUTED", cite_lines=[line_bmp])
            self.assertEqual(res_bmp["direct_status"], "REFUTED", res_bmp)
            self.assertEqual(res_bmp["direct_proof"], "DETERMINISTIC_CONSTANT_SWITCH")

    def test_j04_j05_cwe22_split_parent_octal_dotdot_and_mutable_sysprops(self) -> None:
        caller_static = (
            "package demo;\n"
            "import java.nio.file.Files;\n"
            "import java.nio.file.Paths;\n"
            "import java.nio.file.StandardOpenOption;\n"
            "class Case {\n"
            "    void run() throws Exception {\n"
            '        String name = "fixed.txt";\n'
            "        String path = PathsUtil.BASE + name;\n"
            "        Files.newOutputStream(Paths.get(path), StandardOpenOption.CREATE);\n"
            "    }\n"
            "}\n"
        )
        sink_static = 9
        unsafe_static_variants = {
            "g3_j04_split_parent": '"." + "." + "/fixtures/"',
            "g3_j04_octal_dotdot": '"\\56\\56/fixtures/"',
            "g3_j05_user_dir": 'System.getProperty("user.dir") + "/fixtures/"',
            "g3_j05_tmpdir": 'System.getProperty("java.io.tmpdir") + "/fixtures/"',
            "g3_j05_file_sep_prop": '"fixtures" + System.getProperty("file.separator")',
            "g3_j05_getenv": 'System.getenv("BASE_DIR") + "/fixtures/"',
            "g3_j05_unicode_escape": '"\\u002e\\u002e/fixtures/"',
        }
        with tempfile.TemporaryDirectory() as td:
            for name, rhs in unsafe_static_variants.items():
                extra = {
                    "demo/PathsUtil.java": f"package demo;\npublic class PathsUtil {{\n    public static final String BASE = {rhs};\n}}\n"
                }
                rec, _ = _make_record(
                    Path(td) / name / "src",
                    "demo/Case.java",
                    caller_static,
                    sink_line=sink_static,
                    cwe="CWE-22",
                    extra_files=extra,
                    use_manifest_file=True,
                )
                res = _run_both_layers(rec, "REFUTED", cite_lines=[sink_static])
                self.assertEqual(res["direct_status"], "UNDETERMINED", f"{name}: {res}")

            # Cross-file seam dot traversal: PathsUtil.BASE = "fixtures/." combined with "./fixed.txt",
            # "/fixed.txt", or used directly as a standalone "." segment must all fail closed.
            seam_extra = {
                "demo/PathsUtil.java": 'package demo;\npublic class PathsUtil {\n    public static final String BASE = "fixtures/.";\n}\n'
            }
            for seam_name, expr_line in (
                ("g3_j04_seam_dotdot", '        String path = PathsUtil.BASE + "./fixed.txt";\n'),
                ("g3_j04_seam_curdir", '        String path = PathsUtil.BASE + "/fixed.txt";\n'),
                ("g3_j04_seam_standalone", "        String path = PathsUtil.BASE;\n"),
            ):
                caller_seam = (
                    "package demo;\n"
                    "import java.nio.file.Files;\n"
                    "import java.nio.file.Paths;\n"
                    "import java.nio.file.StandardOpenOption;\n"
                    "class Case {\n"
                    "    void run() throws Exception {\n"
                    + expr_line
                    + "        Files.newOutputStream(Paths.get(path), StandardOpenOption.CREATE);\n"
                    "    }\n"
                    "}\n"
                )
                sl_seam = next(i for i, t in enumerate(caller_seam.splitlines(), 1) if "newOutputStream" in t)
                rec_seam, _ = _make_record(
                    Path(td) / seam_name / "src",
                    "demo/Case.java",
                    caller_seam,
                    sink_line=sl_seam,
                    cwe="CWE-22",
                    extra_files=seam_extra,
                    use_manifest_file=True,
                )
                res_seam = _run_both_layers(rec_seam, "REFUTED", cite_lines=[sl_seam])
                self.assertEqual(res_seam["direct_status"], "UNDETERMINED", f"{seam_name}: {res_seam}")

            # Safe compile-time static final String with File.separator -> REFUTED
            safe_extra = {
                "demo/PathsUtil.java": (
                    "package demo;\n"
                    "import java.io.File;\n"
                    "public class PathsUtil {\n"
                    '    public static final String BASE = "app" + File.separator + "fixtures" + File.separator;\n'
                    "}\n"
                )
            }
            rec_ok, _ = _make_record(
                Path(td) / "safe_static" / "src",
                "demo/Case.java",
                caller_static,
                sink_line=sink_static,
                cwe="CWE-22",
                extra_files=safe_extra,
                use_manifest_file=True,
            )
            res_ok = _run_both_layers(rec_ok, "REFUTED", cite_lines=[sink_static])
            self.assertEqual(res_ok["direct_status"], "REFUTED", res_ok)

            # Local split traversal variants (without static final class)
            local_split_cases = {
                "local_split_vars": '        String a = ".";\n        String b = ".";\n        String path = a + b + "/etc/passwd";\n',
                "local_seam_dot": '        String a = "fixtures/.";\n        String b = "./secret.txt";\n        String path = a + b;\n',
                "local_plus_eq": '        String path = ".";\n        path += ".";\n        path += "/secret.txt";\n',
                "local_octal_dotdot": '        String path = "\\56\\56/secret.txt";\n',
            }
            for name, setup in local_split_cases.items():
                src = (
                    "package demo;\n"
                    "import java.nio.file.Files;\n"
                    "import java.nio.file.Paths;\n"
                    "import java.nio.file.StandardOpenOption;\n"
                    "class Case {\n"
                    "    void run() throws Exception {\n"
                    + setup
                    + "        Files.newOutputStream(Paths.get(path), StandardOpenOption.CREATE);\n"
                    "    }\n"
                    "}\n"
                )
                sl = next(i for i, t in enumerate(src.splitlines(), 1) if "newOutputStream" in t)
                rec, _ = _make_record(Path(td) / name / "src", "demo/Case.java", src, sink_line=sl, cwe="CWE-22")
                res = _run_both_layers(rec, "REFUTED", cite_lines=[sl])
                self.assertEqual(res["direct_status"], "UNDETERMINED", f"{name}: {res}")

            # Safe local split filename extension ("safe" + ".txt" -> "fixtures/safe.txt") -> REFUTED
            safe_ext_src = (
                "package demo;\n"
                "import java.nio.file.Files;\n"
                "import java.nio.file.Paths;\n"
                "import java.nio.file.StandardOpenOption;\n"
                "class Case {\n"
                "    void run() throws Exception {\n"
                '        String a = "safe";\n'
                '        String b = ".txt";\n'
                '        String path = "fixtures/" + a + b;\n'
                "        Files.newOutputStream(Paths.get(path), StandardOpenOption.CREATE);\n"
                "    }\n"
                "}\n"
            )
            sl_ok = next(i for i, t in enumerate(safe_ext_src.splitlines(), 1) if "newOutputStream" in t)
            rec_ext, _ = _make_record(Path(td) / "safe_ext" / "src", "demo/Case.java", safe_ext_src, sink_line=sl_ok, cwe="CWE-22")
            res_ext = _run_both_layers(rec_ext, "REFUTED", cite_lines=[sl_ok])
            self.assertEqual(res_ext["direct_status"], "REFUTED", res_ext)


class CitationAndHistoricalReplayRepairTests(unittest.TestCase):
    """Covers Codex G3-C01 and G3-C02."""

    def test_c01_strict_max3_unique_singleline_and_historical_replay(self) -> None:
        self.assertEqual(ollama.SCHEMA["properties"]["citations"].get("maxItems"), 3)
        raw = (
            "package demo;\n"
            "import java.sql.Statement;\n"
            "class Case {\n"
            "    void run(Statement stmt) throws Exception {\n"
            '        String a = "1";\n'
            '        String b = "2";\n'
            '        String sql = "fixed" + a + b;\n'
            "        stmt.executeQuery(sql);\n"
            "    }\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as td:
            rec, sha = _make_record(Path(td) / "src", "demo/Case.java", raw, sink_line=8)
            lines = raw.splitlines()
            mk = lambda ln: {"path": "demo/Case.java", "start_line": ln, "end_line": ln, "quote": lines[ln - 1], "sha256": sha}
            multi = {"path": "demo/Case.java", "start_line": 7, "end_line": 8, "quote": "\n".join(lines[6:8]), "sha256": sha}

            # 1..3 distinct single-line citations pass
            ok3 = ollama.validate_answer(
                json.dumps({"status": "SUPPORTED", "explanation": "ok", "fix_suggestion": "", "citations": [mk(5), mk(7), mk(8)]}),
                rec,
            )
            self.assertEqual(ok3["citation_check"], "MATCHED")

            # 2 duplicates rejected
            with self.assertRaisesRegex(evidence.EvidenceError, "duplicate"):
                ollama.validate_answer(
                    json.dumps({"status": "SUPPORTED", "explanation": "dup", "fix_suggestion": "", "citations": [mk(8), mk(8)]}),
                    rec,
                )
            # 4 duplicates rejected
            with self.assertRaisesRegex(evidence.EvidenceError, "maximum 3"):
                ollama.validate_answer(
                    json.dumps({"status": "SUPPORTED", "explanation": "4dup", "fix_suggestion": "", "citations": [mk(8)] * 4}),
                    rec,
                )
            # 4 distinct rejected on current v2.2.6
            with self.assertRaisesRegex(evidence.EvidenceError, "maximum 3"):
                ollama.validate_answer(
                    json.dumps({"status": "SUPPORTED", "explanation": "4diff", "fix_suggestion": "", "citations": [mk(5), mk(6), mk(7), mk(8)]}),
                    rec,
                )
            # Multi-line rejected on current v2.2.6 (both validate_answer AND apply_integration_gate Gate 0!)
            with self.assertRaisesRegex(evidence.EvidenceError, "single executable line"):
                ollama.validate_answer(
                    json.dumps({"status": "SUPPORTED", "explanation": "multi", "fix_suggestion": "", "citations": [multi]}),
                    rec,
                )
            gated_multi = apply_integration_gate(
                rec,
                {
                    "status": "SUPPORTED",
                    "raw_model_status": "SUPPORTED",
                    "validated_status": "SUPPORTED",
                    "explanation": "multi",
                    "fix_suggestion": "",
                    "citations": [multi],
                    "prompt_version": ollama.PROMPT_VERSION,
                },
            )
            self.assertEqual(gated_multi["status"], "UNDETERMINED")
            self.assertEqual(gated_multi["failure_kind"], "INVALID_CITATION")
            self.assertEqual(gated_multi["citation_check"], "NOT_VERIFIED")

            # Historical replay (v2.2.4 / v2.2.2) preserves multi-line & 4-citation acceptance
            hist_multi = ollama.validate_answer(
                json.dumps({"status": "SUPPORTED", "explanation": "hist", "fix_suggestion": "", "citations": [multi]}),
                rec,
                prompt_version=ollama.PREVIOUS_MINIMAL_SINGLELINE_PROMPT_VERSION,
            )
            self.assertEqual(hist_multi["citation_check"], "MATCHED")

    def test_c02_historical_serializer_dispatch_and_unknown_version_fail_closed(self) -> None:
        raw = (
            "package demo;\n"
            "import java.sql.Statement;\n"
            "class Case {\n"
            "    void run(Statement stmt) throws Exception {\n"
            '        String sql = "fixed";\n'
            "        stmt.executeQuery(sql);\n"
            "    }\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as td:
            rec, _ = _make_record(Path(td) / "src", "demo/Case.java", raw, sink_line=6)
            fps = set()
            for pv in (
                ollama.PROMPT_VERSION,
                ollama.PREVIOUS_V225_PROMPT_VERSION,
                ollama.PREVIOUS_MINIMAL_SINGLELINE_PROMPT_VERSION,
                ollama.PREVIOUS_CANONICAL_PROMPT_VERSION,
                ollama.LEGACY_STEERED_PROMPT_VERSION,
            ):
                payload, meta = ollama.request_payload_for_version(rec, "qwen3.5:9b-q4_K_M", prompt_version=pv)
                self.assertIsNotNone(payload, pv)
                self.assertTrue(meta["serializer_available"], pv)
                self.assertTrue(meta["serializer_fingerprint"], pv)
                fps.add(meta["serializer_fingerprint"])
            self.assertEqual(len(fps), 5)

            # Unknown prompt version fails closed cleanly (never silently substitutes current serializer)
            unk_payload, unk_meta = ollama.request_payload_for_version(
                rec, "qwen3.5:9b-q4_K_M", prompt_version="v2.99.0-unpreserved-experiment"
            )
            self.assertIsNone(unk_payload)
            self.assertFalse(unk_meta["serializer_available"])


class TelemetryAndStage5RepairTests(unittest.TestCase):
    """Covers Codex G3-A01, G3-A02, G3-A03 and near-miss edge cases."""

    def test_a01_coverage_telemetry_strict_membership_duplicates_and_wsl_mapping(self) -> None:
        # Duplicate scanned Java paths fail closed to INCONSISTENT_TELEMETRY
        dup = compute_opengrep_coverage_telemetry(
            ["src/A.java", "src/B.java"],
            {"paths": {"scanned": ["src/A.java", "src/A.java"]}},
        )
        self.assertEqual(dup["opengrep_paths_telemetry_status"], "INCONSISTENT_TELEMETRY")
        self.assertIsNone(dup["java_files_opengrep_scanned"])
        self.assertIsNone(dup["java_files_opengrep_ignored"])

        # WSL /mnt/<drive> mapping verified against Windows source_root
        wsl_ok = compute_opengrep_coverage_telemetry(
            ["src/A.java", "src/B.java"],
            {"paths": {"scanned": ["/mnt/c/work/repo/src/A.java"]}},
            source_root=Path("C:/work/repo"),
        )
        self.assertEqual(wsl_ok["opengrep_paths_telemetry_status"], "VERIFIED")
        self.assertEqual(wsl_ok["java_files_inventory"], 2)
        self.assertEqual(wsl_ok["java_files_opengrep_scanned"], 1)
        self.assertEqual(wsl_ok["java_files_opengrep_ignored"], 1)

        # Foreign root with matching suffix fails closed
        wsl_foreign = compute_opengrep_coverage_telemetry(
            ["src/A.java"],
            {"paths": {"scanned": ["/mnt/c/other/repo/src/A.java"]}},
            source_root=Path("C:/work/repo"),
        )
        self.assertEqual(wsl_foreign["opengrep_paths_telemetry_status"], "INCONSISTENT_TELEMETRY")
        self.assertIsNone(wsl_foreign["java_files_opengrep_scanned"])

        # Non-iterable, bool fallback, negative fallback, malformed inventory elements -> INCONSISTENT_TELEMETRY
        for bad_inv in (True, 42, "src/A.java", [None], ["../A.java"], ["/abs/A.java"]):
            out = compute_opengrep_coverage_telemetry(bad_inv, {"paths": {"scanned": []}})
            self.assertEqual(out["opengrep_paths_telemetry_status"], "INCONSISTENT_TELEMETRY", repr(bad_inv))
        for bad_fb in (True, -1, "2"):
            out = compute_opengrep_coverage_telemetry(["src/A.java"], {"paths": {"scanned": ["src/A.java"]}}, inventory_count_fallback=bad_fb)
            self.assertEqual(out["opengrep_paths_telemetry_status"], "INCONSISTENT_TELEMETRY", repr(bad_fb))

    def test_a02_summary_validator_blocks_forged_cached_and_missing_hash_legacy(self) -> None:
        good_sha = "a" * 64
        # Valid cached payload passes
        ok = validate_coverage_telemetry_payload(
            {
                "java_files_inventory": 498,
                "java_files_opengrep_scanned": 389,
                "java_files_opengrep_ignored": 109,
                "opengrep_paths_telemetry_status": "VERIFIED",
            },
            expected_inventory=498,
            scan_sha256=good_sha,
        )
        self.assertEqual(ok["opengrep_paths_telemetry_status"], "VERIFIED")
        self.assertEqual(ok["java_files_opengrep_ignored"], 109)

        # Mismatched expected inventory downgrades cached VERIFIED to INCONSISTENT_TELEMETRY
        mismatch = validate_coverage_telemetry_payload(
            {
                "java_files_inventory": 19,
                "java_files_opengrep_scanned": 19,
                "java_files_opengrep_ignored": 0,
                "opengrep_paths_telemetry_status": "VERIFIED",
            },
            expected_inventory=20,
            scan_sha256=good_sha,
        )
        self.assertEqual(mismatch["opengrep_paths_telemetry_status"], "INCONSISTENT_TELEMETRY")
        self.assertIsNone(mismatch["java_files_opengrep_scanned"])

        # Missing or invalid scan_sha256 downgrades cached VERIFIED
        no_sha = validate_coverage_telemetry_payload(
            {
                "java_files_inventory": 1,
                "java_files_opengrep_scanned": 1,
                "java_files_opengrep_ignored": 0,
                "opengrep_paths_telemetry_status": "VERIFIED",
            },
            expected_inventory=1,
            scan_sha256="",
        )
        self.assertEqual(no_sha["opengrep_paths_telemetry_status"], "INCONSISTENT_TELEMETRY")

    def test_a03_stage5_projection_and_zero_call_null_distinction(self) -> None:
        jobs_path = Path(__file__).resolve().parents[1] / "jobs.py"
        jobs_ast = ast.parse(jobs_path.read_text(encoding="utf-8"))
        exprs = []
        for obj in ast.walk(jobs_ast):
            if not isinstance(obj, ast.Dict):
                continue
            for key, val in zip(obj.keys, obj.values):
                if isinstance(key, ast.Constant) and key.value == "non_overlapping_integration_gate_ms":
                    exprs.append(compile(ast.Expression(val), "<stage5>", "eval"))
        self.assertEqual(len(exprs), 2)
        for expr in exprs:
            for meta, no_llm, expected in (
                ({}, False, None),
                ({"integration_gate_ms": None, "integration_gate_calls": 1}, False, None),
                ({"integration_gate_ms": 0}, False, None),  # missing calls -> fail closed
                ({"integration_gate_ms": 0, "integration_gate_calls": 0}, False, None),  # zero calls -> fail closed
                ({"integration_gate_ms": 0, "integration_gate_calls": 1}, False, 0.0),
                ({"integration_gate_ms": 249.0, "integration_gate_calls": 1, "qwen_total_ms": 162360.0}, False, 249.0),
                ({"integration_gate_ms": 249.0, "integration_gate_calls": 1, "qwen_total_ms": 100.0}, False, None),  # exceeds Stage 4!
                ({"integration_gate_ms": 9.0005, "integration_gate_calls": 1, "qwen_total_ms": 9}, False, None),  # rounding excess!
                ({"integration_gate_ms": 10**400, "integration_gate_calls": 1}, False, None),  # huge int safe!
                ({"integration_gate_ms": 249.0, "integration_gate_calls": 1}, True, None),
                ({"integration_gate_ms": True, "integration_gate_calls": 1}, False, None),
                ({"integration_gate_ms": "9", "integration_gate_calls": 1}, False, None),
                ({"integration_gate_ms": [], "integration_gate_calls": 1}, False, None),
                ({"integration_gate_ms": -1, "integration_gate_calls": 1}, False, None),
                ({"integration_gate_ms": "x", "integration_gate_calls": 1}, False, None),
                ({"integration_gate_ms": float("nan"), "integration_gate_calls": 1}, False, None),
                ({"integration_gate_ms": float("inf"), "integration_gate_calls": 1}, False, None),
            ):
                actual = eval(
                    expr,
                    {"__builtins__": {"round": round, "float": float}},
                    {"info": meta, "triage_telemetry": meta, "no_llm": no_llm},
                )
                self.assertEqual(actual, expected, f"meta={meta} no_llm={no_llm}")

        # Zero-finding run with LLM enabled (apply_integration_gate never called) -> integration_gate_ms is None
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src_dir = root / "src"
            cap_dir = root / "cap"
            tri_dir = root / "tri"
            src_dir.mkdir()
            cap_dir.mkdir()
            jf = src_dir / "App.java"
            jf.write_text("public class App {}\n", encoding="utf-8")
            jsha = evidence.digest(jf.read_bytes())
            og_json = cap_dir / "opengrep.json"
            og_json.write_text(json.dumps({"version": "1.25.0", "results": [], "paths": {"scanned": [str(jf)]}}), encoding="utf-8")
            rules_f = cap_dir / "rules.yml"
            rules_f.write_text("rules: []\n", encoding="utf-8")
            rsha = evidence.digest(rules_f.read_bytes())
            man = cap_dir / "scan-manifest.json"
            man.write_text(
                json.dumps(
                    {
                        "sources_before": {"App.java": jsha},
                        "sources_after": {"App.java": jsha},
                        "rules_before_sha256": rsha,
                        "rules_after_sha256": rsha,
                    }
                ),
                encoding="utf-8",
            )
            # Local ephemeral loopback mock server for /api/tags (never contacts real Ollama 11434)
            from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
            import threading
            import time

            class _TagsOnlyHandler(BaseHTTPRequestHandler):
                def log_message(self, *args):
                    pass

                def do_GET(self):
                    if self.path == "/api/tags":
                        body = b'{"models":[{"name":"qwen3.5:9b-q4_K_M","digest":"mockdigest","size":100}]}'
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                    else:
                        self.send_error(404)

            srv = ThreadingHTTPServer(("127.0.0.1", 0), _TagsOnlyHandler)
            thr = threading.Thread(target=srv.serve_forever, daemon=True)
            thr.start()
            try:
                res = run_bounded_triage(
                    source_root=src_dir,
                    triage_dir=tri_dir,
                    raw_json_path=og_json,
                    manifest_path=man,
                    path_maps=[],
                    rules_path=rules_f,
                    no_llm=False,
                    prompt_contract="blind",
                    ollama_endpoint=f"http://127.0.0.1:{srv.server_port}",
                    ollama_model="qwen3.5:9b-q4_K_M",
                    ollama_timeout_seconds=5.0,
                    runtime_origin="mock",
                    deadline_mono=time.monotonic() + 30.0,
                )
            finally:
                srv.shutdown()
                srv.server_close()
            self.assertIsNone(res["telemetry"]["integration_gate_ms"])
            self.assertEqual(res["telemetry"]["integration_gate_calls"], 0)


if __name__ == "__main__":
    unittest.main()
