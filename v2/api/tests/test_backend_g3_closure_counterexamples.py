"""Closure counterexample & adversarial regression tests for backend G3 P0/P1 blockers (G3-J06, G3-A04, G3-A05, G3-C03).

Self-contained: uses only temporary directories, local ephemeral loopback servers, and synthetic Java fixtures.
Zero private paths, zero external assets, and zero real Ollama/OpenGrep calls.
"""
from __future__ import annotations

import ast
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import tempfile
import threading
import unittest

from v2.api.config import ApiConfig
from v2.api.opengrep_runner import (
    compute_opengrep_coverage_telemetry,
    reconcile_cached_and_raw_coverage_telemetry,
)
from v2.api.service import DiscoveredScan, TriageApiService
from v2.api.tests.test_backend_g3_quality_improvements import (
    _make_record,
    _mock_model_assessment,
)
from v2.api.tests.test_backend_g3_repair_counterexamples import (
    _run_both_layers,
    _wrap_sqli_case,
)
from v2.api.triage_gate import _eval_exact_char_expr
from v2.triage import evidence, live_check, ollama
from v2.triage.heuristics import parse_java_nonneg_decimal_int_literal
from v2.triage.runtime import SCHEMA_VERSION
from v2.triage.verify_http_capture import verify_run_http_captures


class P0JavaLiteralSemanticsClosureTests(unittest.TestCase):
    """Covers Codex P0 G3-J06 and full JLS §3.10.1 / §3.3 literal matrix across both validator and Gate 2."""

    def test_shared_java_nonneg_decimal_int_literal_parser_matrix(self) -> None:
        # Valid strict ASCII decimal Java int literals
        for raw, expected in (
            ("0", 0),
            (" 0 ", 0),
            ("1", 1),
            ("8", 8),
            ("10", 10),
            ("2147483647", 2147483647),
        ):
            self.assertEqual(parse_java_nonneg_decimal_int_literal(raw), expected, repr(raw))

        # Must fail closed (None) on octal, leading zero, hex, binary, underscore, sign, suffix, overflow, Unicode, expr
        for bad in (
            "00",
            "07",
            "010",
            "08",
            "09",
            "0x8",
            "0x0A",
            "0X10",
            "0b1000",
            "0B1010",
            "1_0",
            "0_10",
            "10_000",
            "+8",
            "+0",
            "-0",
            "-1",
            "-8",
            "10L",
            "10l",
            "2147483648",
            "99999999999999999999",
            "",
            "   ",
            "idx",
            "8 + 2",
            "'a'",
            r"\u0038",
            "\u0661\u0660",  # Arabic-Indic digits
            "\uff11\uff10",  # Fullwidth digits
            "\u00b2",  # Superscript 2 (str.isdigit() is True in Python!)
            None,
            10,
            True,
        ):
            self.assertIsNone(parse_java_nonneg_decimal_int_literal(bad), repr(bad))

    def test_arraylist_get_octal_hex_binary_underscore_sign_suffix_overflow_and_opposite_controls(self) -> None:
        # Element 8 is untrusted `input`; elements 0..7 and 9..10 are `"fixed"`.
        tainted_at_8_prefix = (
            "        java.util.List<String> values = new java.util.ArrayList<String>();\n"
            + "".join("        values.add(input);\n" if i == 8 else '        values.add("fixed");\n' for i in range(11))
        )
        # Opposite polarity control: element 8 is `"fixed"`, element 10 is untrusted `input`.
        fixed_at_8_tainted_at_10_prefix = (
            "        java.util.List<String> values = new java.util.ArrayList<String>();\n"
            + "".join("        values.add(input);\n" if i == 10 else '        values.add("fixed");\n' for i in range(11))
        )

        with tempfile.TemporaryDirectory() as td:
            # 1. Exact Codex P0 counterexample: values.get(010) -> Java index 8 (tainted!) -> MUST be UNDETERMINED on BOTH layers
            for label, idx_tok in (
                ("octal_010", "010"),
                ("octal_00", "00"),
                ("hex_0x08", "0x08"),
                ("hex_0x0a", "0x0a"),
                ("bin_0b1000", "0b1000"),
                ("bin_0b1010", "0b1010"),
                ("underscore_1_0", "1_0"),
                ("plus_10", "+10"),
                ("neg_1", "-1"),
                ("long_suffix_10L", "10L"),
                ("overflow_int", "2147483648"),
                ("oob_99", "99"),
                ("expr_8_plus_2", "8 + 2"),
                ("unicode_escape_idx", r"\u0031\u0030"),
            ):
                body = tainted_at_8_prefix + f'        String value = values.get({idx_tok});\n        String sql = "query " + value;'
                src, line = _wrap_sqli_case(body)
                rec, _ = _make_record(Path(td) / f"t8_{label}", "demo/Case.java", src, sink_line=line)
                res = _run_both_layers(rec, "REFUTED", cite_lines=[line])
                self.assertEqual(res["direct_status"], "UNDETERMINED", f"t8_{label}: {res}")
                if res["through"]["accepted_by_validator"]:
                    self.assertEqual(res["through"]["status"], "UNDETERMINED", f"t8_{label}: {res}")

            # 2. Opposite polarity: even when Java index 8 is `"fixed"` (and 10 is tainted), non-decimal `010` fails closed to UNDETERMINED,
            #    while valid decimal `8` -> REFUTED and valid decimal `10` (tainted) -> UNDETERMINED!
            for label, idx_tok, expected in (
                ("opp_octal_010_fail_closed", "010", "UNDETERMINED"),
                ("opp_decimal_8_safe", "8", "REFUTED"),
                ("opp_decimal_10_tainted", "10", "UNDETERMINED"),
            ):
                body = fixed_at_8_tainted_at_10_prefix + f'        String value = values.get({idx_tok});\n        String sql = "query " + value;'
                src, line = _wrap_sqli_case(body)
                rec, _ = _make_record(Path(td) / label, "demo/Case.java", src, sink_line=line)
                res = _run_both_layers(rec, "REFUTED", cite_lines=[line])
                self.assertEqual(res["direct_status"], expected, f"{label}: {res}")
                if expected == "REFUTED":
                    self.assertEqual(res["direct_proof"], "LOCAL_ARRAYLIST_CONSTANT_FLOW")
                    self.assertEqual(res["through"]["status"], "REFUTED", res)
                elif res["through"]["accepted_by_validator"]:
                    self.assertEqual(res["through"]["status"], "UNDETERMINED", f"{label}: {res}")

            # 3. Positive decimal control on original fixture: decimal 10 -> REFUTED, decimal 8 -> UNDETERMINED
            for label, idx_tok, expected in (("orig_dec_10", "10", "REFUTED"), ("orig_dec_8", "8", "UNDETERMINED")):
                body = tainted_at_8_prefix + f'        String value = values.get({idx_tok});\n        String sql = "query " + value;'
                src, line = _wrap_sqli_case(body)
                rec, _ = _make_record(Path(td) / label, "demo/Case.java", src, sink_line=line)
                res = _run_both_layers(rec, "REFUTED", cite_lines=[line])
                self.assertEqual(res["direct_status"], expected, f"{label}: {res}")

            # 4. Octal/non-decimal mutations (`set(010, input)`, `add(010, input)`, `remove(010)`) MUST invalidate list tracking!
            mut_base = (
                "        java.util.List<String> values = new java.util.ArrayList<String>();\n"
                + "".join('        values.add("fixed");\n' for _ in range(11))
            )
            for label, mut_stmt, read_idx in (
                ("set_octal_010_taint_at_8", "        values.set(010, input);\n", "8"),
                ("add_octal_010_shift_at_8", "        values.add(010, input);\n", "8"),
                ("remove_octal_010_shift", "        values.set(9, input);\n        values.remove(010);\n", "8"),
                ("set_hex_0x08_taint_at_8", "        values.set(0x08, input);\n", "8"),
                ("set_dynamic_idx", "        int idx = 8;\n        values.set(idx, input);\n", "8"),
            ):
                body = mut_base + mut_stmt + f'        String value = values.get({read_idx});\n        String sql = "query " + value;'
                src, line = _wrap_sqli_case(body)
                rec, _ = _make_record(Path(td) / label, "demo/Case.java", src, sink_line=line)
                res = _run_both_layers(rec, "REFUTED", cite_lines=[line])
                self.assertEqual(res["direct_status"], "UNDETERMINED", f"{label}: {res}")
                if res["through"]["accepted_by_validator"]:
                    self.assertEqual(res["through"]["status"], "UNDETERMINED", f"{label}: {res}")

    def test_charat_and_switch_octal_non_decimal_and_heuristics_guess_parity(self) -> None:
        seed = "aaaaaaaabac"
        self.assertEqual(_eval_exact_char_expr("seed.charAt(8)", {"seed": seed}, {}, {})[0], "b")
        self.assertEqual(_eval_exact_char_expr("seed.charAt(10)", {"seed": seed}, {}, {})[0], "c")
        for bad_tok in ("010", "00", "0x0a", "0b1010", "1_0", "+10", "-1", "10L", "99", "idx", "8+2"):
            self.assertIsNone(_eval_exact_char_expr(f"seed.charAt({bad_tok})", {"seed": seed}, {}, {})[0], bad_tok)

        with tempfile.TemporaryDirectory() as td:
            # Both `seed/selector` (Gate 2) and `guess/switchTarget` (heuristics + Gate 2) fail closed on `010`!
            for prefix_name, var_s, var_c in (("seed_selector", "seed", "selector"), ("guess_switchTarget", "guess", "switchTarget")):
                for tok, expected in (("10", "REFUTED"), ("010", "UNDETERMINED"), ("8", "UNDETERMINED"), ("0x0a", "UNDETERMINED")):
                    body = (
                        f'        String {var_s} = "aaaaaaaabac";\n'
                        f"        char {var_c} = {var_s}.charAt({tok});\n"
                        "        String value;\n"
                        f"        switch ({var_c}) {{\n"
                        "            case 'c': value = \"fixed\"; break;\n"
                        "            default: value = input; break;\n"
                        "        }\n"
                        '        String sql = "query " + value;'
                    )
                    src, line = _wrap_sqli_case(body)
                    rec, _ = _make_record(Path(td) / f"{prefix_name}_{tok}", "demo/Case.java", src, sink_line=line)
                    res = _run_both_layers(rec, "REFUTED", cite_lines=[line])
                    self.assertEqual(res["direct_status"], expected, f"{prefix_name}_{tok}: {res}")
                    if expected == "UNDETERMINED" and res["through"]["accepted_by_validator"]:
                        self.assertEqual(res["through"]["status"], "UNDETERMINED", f"{prefix_name}_{tok}: {res}")


class P1ACoverageAndCacheClosureTests(unittest.TestCase):
    """Covers Codex P1-A G3-A04 (cache cannot bypass raw SHA/membership + duplicate inventory rejected)."""

    def test_cached_verified_cannot_bypass_raw_alien_membership_missing_raw_or_count_mismatch(self) -> None:
        keys = (
            "java_files_inventory",
            "java_files_opengrep_scanned",
            "java_files_opengrep_ignored",
            "opengrep_paths_telemetry_status",
        )
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            scan = d / "opengrep.json"
            scan.write_bytes(b'{"paths":{"scanned":["B.java"]}}')
            scan_hash = sha256(scan.read_bytes()).hexdigest()
            svc = TriageApiService(ApiConfig(data_dir=d / "api", runtime_origin="mock"))
            bundle = {"pre_scan_hashes": {"A.java": "a"}}

            # 1. Exact Codex P1-A counterexample: cache claims 1/1/0 VERIFIED, raw scanned B.java outside inventory A.java
            entry = DiscoveredScan("audit", scan_hash, d, d, d / "r.sqlite", d / "evidence.json", None, scan, None, None, False)
            out_alien = svc._build_scan_summary_from_snapshot(
                entry, bundle, [], {}, dict(zip(keys, (1, 1, 0, "VERIFIED")))
            )
            self.assertEqual(out_alien["opengrep_paths_telemetry_status"], "INCONSISTENT_TELEMETRY")
            self.assertIsNone(out_alien["java_files_opengrep_scanned"])
            self.assertIsNone(out_alien["java_files_opengrep_ignored"])
            self.assertEqual(out_alien["java_files_inventory"], 1)
            self.assertEqual(out_alien["java_files_scanned"], 1)

            # 2. Missing raw file on disk while cache claims VERIFIED -> MISSING_PATHS_TELEMETRY (never VERIFIED!)
            missing_entry = DiscoveredScan("audit-miss", scan_hash, d, d, d / "r.sqlite", d / "evidence.json", None, d / "missing.json", None, None, False)
            out_miss = svc._build_scan_summary_from_snapshot(
                missing_entry, bundle, [], {}, dict(zip(keys, (1, 1, 0, "VERIFIED")))
            )
            self.assertEqual(out_miss["opengrep_paths_telemetry_status"], "MISSING_PATHS_TELEMETRY")
            self.assertIsNone(out_miss["java_files_opengrep_scanned"])
            self.assertIsNone(out_miss["java_files_opengrep_ignored"])

            # 3. Present raw file lacking `paths` while cache claims VERIFIED -> INCONSISTENT_TELEMETRY
            no_paths_scan = d / "opengrep_nopaths.json"
            no_paths_scan.write_bytes(b'{"results":[]}')
            np_hash = sha256(no_paths_scan.read_bytes()).hexdigest()
            np_entry = DiscoveredScan("audit-np", np_hash, d, d, d / "r.sqlite", d / "evidence.json", None, no_paths_scan, None, None, False)
            out_np = svc._build_scan_summary_from_snapshot(
                np_entry, bundle, [], {}, dict(zip(keys, (1, 1, 0, "VERIFIED")))
            )
            self.assertEqual(out_np["opengrep_paths_telemetry_status"], "INCONSISTENT_TELEMETRY")
            self.assertIsNone(out_np["java_files_opengrep_scanned"])

            # 4. Valid raw (2/1/1) vs contradictory cache (2/2/0) -> INCONSISTENT_TELEMETRY
            good_scan = d / "opengrep_good.json"
            good_scan.write_bytes(b'{"paths":{"scanned":["A.java"]}}')
            g_hash = sha256(good_scan.read_bytes()).hexdigest()
            g_entry = DiscoveredScan("audit-good", g_hash, d, d, d / "r.sqlite", d / "evidence.json", None, good_scan, None, None, False)
            bundle2 = {"pre_scan_hashes": {"A.java": "a", "B.java": "b"}}
            out_diff = svc._build_scan_summary_from_snapshot(
                g_entry, bundle2, [], {}, dict(zip(keys, (2, 2, 0, "VERIFIED")))
            )
            self.assertEqual(out_diff["opengrep_paths_telemetry_status"], "INCONSISTENT_TELEMETRY")
            self.assertIsNone(out_diff["java_files_opengrep_scanned"])

            # 5. Valid raw (2/1/1) + matching cache (2/1/1) -> VERIFIED
            out_ok = svc._build_scan_summary_from_snapshot(
                g_entry, bundle2, [], {}, dict(zip(keys, (2, 1, 1, "VERIFIED")))
            )
            self.assertEqual(out_ok["opengrep_paths_telemetry_status"], "VERIFIED")
            self.assertEqual(out_ok["java_files_inventory"], 2)
            self.assertEqual(out_ok["java_files_opengrep_scanned"], 1)
            self.assertEqual(out_ok["java_files_opengrep_ignored"], 1)

    def test_duplicate_inventory_paths_rejected_fail_closed(self) -> None:
        for dup_inv in (
            ["A.java", "A.java"],
            ["src/A.java", "./src/A.java"],
            ["src/A.java", r"src\A.java"],
        ):
            out = compute_opengrep_coverage_telemetry(dup_inv, {"paths": {"scanned": ["A.java"]}})
            self.assertEqual(out["opengrep_paths_telemetry_status"], "INCONSISTENT_TELEMETRY", dup_inv)
            self.assertIsNone(out["java_files_inventory"])
            self.assertIsNone(out["java_files_opengrep_scanned"])
            self.assertIsNone(out["java_files_opengrep_ignored"])


class P1BStage5TimingClosureTests(unittest.TestCase):
    """Covers Codex P1-B G3-A05 (zero/missing calls, rounding excess, huge int OverflowError)."""

    def test_stage5_projection_strict_calls_and_rounding_and_overflow_invariants(self) -> None:
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
        cases = (
            ({"integration_gate_ms": 9, "integration_gate_calls": 0}, False, None),
            ({"integration_gate_ms": 9}, False, None),
            ({"integration_gate_ms": 9, "integration_gate_calls": None}, False, None),
            ({"integration_gate_ms": 9, "integration_gate_calls": True}, False, None),
            ({"integration_gate_ms": 9, "integration_gate_calls": -1}, False, None),
            ({"integration_gate_ms": 9, "integration_gate_calls": 1.0}, False, None),
            ({"integration_gate_ms": 9, "integration_gate_calls": "1"}, False, None),
            ({"integration_gate_ms": 0, "integration_gate_calls": 1}, False, 0.0),
            ({"integration_gate_ms": -0.0, "integration_gate_calls": 1}, False, 0.0),
            ({"integration_gate_ms": 9.0005, "integration_gate_calls": 1, "qwen_total_ms": 9}, False, None),
            ({"integration_gate_ms": 9.0, "integration_gate_calls": 1, "qwen_total_ms": 9}, False, 9.0),
            ({"integration_gate_ms": 8.9996, "integration_gate_calls": 1, "qwen_total_ms": 8.9998}, False, 9.0),
            ({"integration_gate_ms": 10**400, "integration_gate_calls": 1}, False, None),
            ({"integration_gate_ms": 5.0, "integration_gate_calls": 1, "qwen_total_ms": 10**400}, False, None),
            ({"integration_gate_ms": 5.0, "integration_gate_calls": 10**400}, False, None),
            ({"integration_gate_ms": 5.0, "integration_gate_calls": 1, "qwen_total_ms": float("nan")}, False, None),
            ({"integration_gate_ms": 5.0, "integration_gate_calls": 1, "qwen_total_ms": True}, False, None),
        )
        for expr in exprs:
            for data, no_llm, expected in cases:
                actual = eval(
                    expr,
                    {"__builtins__": {"round": round, "float": float}},
                    {"info": data, "triage_telemetry": data, "no_llm": no_llm},
                )
                self.assertEqual(actual, expected, f"data={data} no_llm={no_llm}")
                if actual == 0.0:
                    self.assertFalse(str(actual).startswith("-"))


class P1CHttpCaptureMetadataBindingClosureTests(unittest.TestCase):
    """Covers Codex P1-C G3-C03 (prompt_version, prompt_sha256, prompt_contract, serializer_fingerprint binding)."""

    def _build_capture_run(self, root: Path) -> tuple[Path, dict, dict]:
        src_dir = root / "src"
        src_dir.mkdir(parents=True, exist_ok=True)
        java_code = (
            "package demo;\n"
            "import java.sql.Statement;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "class Case {\n"
            "    void run(HttpServletRequest req, Statement stmt) throws Exception {\n"
            '        String input = req.getParameter("p");\n'
            '        String sql = "SELECT " + input;\n'
            "        stmt.executeQuery(sql);\n"
            "    }\n"
            "}\n"
        )
        rec, sha = _make_record(src_dir, "demo/Case.java", java_code, sink_line=8)
        rec["prompt_contract"] = ollama.DEFAULT_PROMPT_CONTRACT
        bundle = {
            "schema_version": SCHEMA_VERSION,
            "scan_sha256": rec["scan_sha256"],
            "root": str(src_dir),
            "records": [rec],
            "issues": [],
        }
        quote = java_code.splitlines()[7]
        model_content = json.dumps(
            {
                "explanation": "Dữ liệu đầu vào nối trực tiếp vào câu lệnh SQL.",
                "citations": [{"path": "demo/Case.java", "start_line": 8, "end_line": 8, "quote": quote, "sha256": sha}],
                "status": "SUPPORTED",
                "fix_suggestion": "Dùng PreparedStatement.",
            },
            ensure_ascii=False,
        )
        raw_resp = json.dumps(
            {
                "mock_test_fixture": True,
                "done": True,
                "done_reason": "stop",
                "model": "qwen3.5:9b-q4_K_M",
                "eval_count": 20,
                "eval_duration": 123456,
                "message": {"role": "assistant", "content": model_content},
            },
            ensure_ascii=False,
        ).encode("utf-8")

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length", "0"))
                if n:
                    self.rfile.read(n)
                self.send_response(200)
                self.send_header("Content-Length", str(len(raw_resp)))
                self.end_headers()
                self.wfile.write(raw_resp)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        try:
            triage_dir = root / "triage"
            triage_dir.mkdir(parents=True, exist_ok=True)
            client = ollama.OllamaClient(
                endpoint=f"http://127.0.0.1:{srv.server_port}",
                model="qwen3.5:9b-q4_K_M",
                timeout=10,
                runtime_origin="mock",
                io_log_dir=triage_dir / "llm_io",
                capture_root=triage_dir,
            )
            assessment = client.analyze(rec)
        finally:
            srv.shutdown()
            srv.server_close()
            th.join(timeout=2)

        (triage_dir / "evidence.json").write_text(json.dumps(bundle, indent=2), encoding="utf-8")
        row = {
            "schema_version": SCHEMA_VERSION,
            "id": rec["id"],
            "alert_id": rec["alert_id"],
            "scan_sha256": rec["scan_sha256"],
            "finding_index": rec["finding_index"],
            "state": "OPEN",
            "evidence": rec,
            "assessment": assessment,
        }
        (triage_dir / "assessments.jsonl").write_text(json.dumps(row, ensure_ascii=False) + "\n", encoding="utf-8")
        return triage_dir, rec, row

    def test_request_payload_for_version_fails_closed_on_missing_blank_and_non_string_version(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            src, line = _wrap_sqli_case('        String sql = "fixed";')
            rec, _ = _make_record(Path(td) / "src", "demo/Case.java", src, sink_line=line)
            for bad_ver in (None, "", "   ", 123, f" {ollama.PROMPT_VERSION} ", "v99-unknown"):
                payload, meta = ollama.request_payload_for_version(rec, "qwen3.5:9b-q4_K_M", prompt_version=bad_ver)
                self.assertIsNone(payload, repr(bad_ver))
                self.assertFalse(meta["serializer_available"], repr(bad_ver))
                self.assertIsNone(meta["serializer_fingerprint"], repr(bad_ver))

    def test_metadata_tampering_caught_while_raw_http_body_remains_intact(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            clean_dir, rec, orig_row = self._build_capture_run(base / "orig")
            fid = rec["id"]

            # Clean control on current v2.2.6 -> VERIFIED_COMPLETE + VERIFIED_EXPLICIT
            clean_rep = verify_run_http_captures(clean_dir, require_live_chat=False)
            self.assertEqual(clean_rep["capture_status"], "VERIFIED_COMPLETE", clean_rep["errors"])
            self.assertTrue(clean_rep["capture_integrity_ok"])
            self.assertEqual(clean_rep["findings"][0]["prompt_metadata_binding"], "VERIFIED_EXPLICIT")
            self.assertFalse(orig_row["assessment"]["security_conclusion_verified"])
            self.assertFalse(orig_row["assessment"]["runtime"]["model_runtime_verified"])

            def _run_mutation(name: str, mutator):
                copy_dir = base / f"mut_{name}"
                shutil.copytree(clean_dir, copy_dir)
                rows = [json.loads(ln) for ln in (copy_dir / "assessments.jsonl").read_text(encoding="utf-8").splitlines() if ln.strip()]
                mutator(copy_dir, rows[0])
                (copy_dir / "assessments.jsonl").write_text(json.dumps(rows[0], ensure_ascii=False) + "\n", encoding="utf-8")
                return verify_run_http_captures(copy_dir, require_live_chat=False), live_check.inspect(rows, minimum=1)

            def _mut_fake_fp(_d, row):
                row["assessment"]["serializer_fingerprint"] = "0" * 64

            def _mut_missing_fp_current(_d, row):
                row["assessment"].pop("serializer_fingerprint", None)

            def _mut_fake_prompt_sha_both(d, row):
                row["assessment"]["prompt_sha256"] = "0" * 64
                p = d / "llm_io" / f"{fid}.prompt.json"
                doc = json.loads(p.read_text(encoding="utf-8"))
                doc["prompt_sha256"] = "0" * 64
                p.write_text(json.dumps(doc), encoding="utf-8")

            def _mut_fake_prompt_sha_all_three(d, row):
                _mut_fake_prompt_sha_both(d, row)
                row["assessment"]["runtime"]["prompt_sha256"] = "0" * 64

            def _mut_blank_version(_d, row):
                row["assessment"]["prompt_version"] = ""

            def _mut_missing_version(_d, row):
                row["assessment"].pop("prompt_version", None)

            def _mut_swapped_version(d, row):
                row["assessment"]["prompt_version"] = ollama.PREVIOUS_V225_PROMPT_VERSION
                p = d / "llm_io" / f"{fid}.prompt.json"
                doc = json.loads(p.read_text(encoding="utf-8"))
                doc["prompt_version"] = ollama.PREVIOUS_V225_PROMPT_VERSION
                p.write_text(json.dumps(doc), encoding="utf-8")

            def _mut_swapped_contract(d, row):
                row["assessment"]["prompt_contract"] = "neutral_hints"
                p = d / "llm_io" / f"{fid}.prompt.json"
                doc = json.loads(p.read_text(encoding="utf-8"))
                doc["prompt_contract"] = "neutral_hints"
                p.write_text(json.dumps(doc), encoding="utf-8")

            def _mut_forged_prompt_messages(d, _row):
                p = d / "llm_io" / f"{fid}.prompt.json"
                doc = json.loads(p.read_text(encoding="utf-8"))
                doc["messages"][0]["content"] = "forged system prompt"
                p.write_text(json.dumps(doc), encoding="utf-8")

            def _mut_forged_request_json(d, _row):
                p = d / "llm_io" / f"{fid}.request.json"
                doc = json.loads(p.read_text(encoding="utf-8"))
                doc["options"]["temperature"] = 0.9
                p.write_text(json.dumps(doc), encoding="utf-8")

            for name, fn in (
                ("fake_fingerprint", _mut_fake_fp),
                ("missing_fp_current", _mut_missing_fp_current),
                ("fake_prompt_sha_both", _mut_fake_prompt_sha_both),
                ("fake_prompt_sha_all_three", _mut_fake_prompt_sha_all_three),
                ("blank_version", _mut_blank_version),
                ("missing_version", _mut_missing_version),
                ("swapped_version", _mut_swapped_version),
                ("swapped_contract", _mut_swapped_contract),
                ("forged_prompt_messages", _mut_forged_prompt_messages),
                ("forged_request_json", _mut_forged_request_json),
            ):
                rep, lc = _run_mutation(name, fn)
                self.assertEqual(rep["capture_status"], "FAILED", f"{name}: {rep}")
                self.assertFalse(rep["capture_integrity_ok"], name)
                self.assertFalse(rep["findings"][0]["verified"], name)
                self.assertEqual(rep["findings"][0]["prompt_metadata_binding"], "FAILED", name)
                if name in ("fake_fingerprint", "missing_fp_current", "fake_prompt_sha_all_three", "blank_version", "missing_version", "swapped_version", "swapped_contract"):
                    self.assertFalse(lc["warnings"][0]["request_payload_bound"], f"live_check {name}: {lc}")
                self.assertFalse(lc["independently_verified_model_runtime"])


if __name__ == "__main__":
    unittest.main()
