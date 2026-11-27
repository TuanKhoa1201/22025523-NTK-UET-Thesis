"""Adversarial self-audit regression suite for G3 backend closure candidate.

Covers all 12 reproducible blind-spot classes discovered during pre-handover self-audit:
- SB-P0-01: JLS §15.18.1 left-to-right char+char+String numeric promotion in Gate 2
- SB-P0-02: Braced/nested break inside Java switch (both Layer 1 heuristics & Gate 2)
- SB-P0-03: CWE-22 tainted receiver on `.resolve(...)`, post-guard 1-arg `.resolve(...)`, multi-resource try
- SB-P0-04: Forged heuristic_signals.sink_line, forged enclosing_method.header_line, implements static final shadow
- SB-P1-01: Layer 1 heuristics Java semantics (int32 overflow, default-before-case, same-line case,
            untyped reassignment, branch/loop collection mutation, sibling/root path prefix, partial sanitizer search)
- SB-P1-02..08: live_check & verify_http_capture prompt metadata, response sidecar, finding_id, and receipt tampering
- SB-P1-09..11: Coverage telemetry duplicate-inventory resurrection, malformed types, manifest vs cache precedence
- SB-P1-12: Stage-4 `stages[3].duration_ms` (`qwen_total_ms`) sanitization & Stage-5 bounds
"""
from __future__ import annotations

import ast
import copy
import hashlib
import json
import math
from pathlib import Path
import shutil
import tempfile
import unittest

from v2.api import config, jobs, service
from v2.api.opengrep_runner import (
    compute_opengrep_coverage_telemetry,
    reconcile_cached_and_raw_coverage_telemetry,
)
from v2.api.triage_gate import apply_integration_gate
from v2.triage import heuristics, live_check, ollama, verify_http_capture
from v2.triage.evidence import digest
from v2.triage.ollama import PROMPT_VERSION


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _make_record(
    java_src: str,
    *,
    path: str = "Sample.java",
    cwe: str = "CWE-89",
    source_line: int,
    sink_line: int,
    header_line: int,
    end_line: int,
    method_name: str = "handle",
) -> dict:
    sha = _sha256_text(java_src)
    lines = [{"line": idx + 1, "text": txt} for idx, txt in enumerate(java_src.splitlines())]
    rec: dict = {
        "id": _sha256_text(f"{path}:{sink_line}:{cwe}"),
        "rule_id": f"ntk.api.java.{cwe.lower().replace('-', '')}.test",
        "cwe": [cwe],
        "path": path,
        "start": {"line": sink_line, "col": 1},
        "end": {"line": sink_line, "col": 40},
        "prompt_contract": "blind",
        "snapshots": {path: {"sha256": sha}},
        "snippets": [
            {
                "role": "finding",
                "path": path,
                "sha256": sha,
                "start": {"line": sink_line, "col": 1},
                "end": {"line": sink_line, "col": 40},
                "lines": lines,
            }
        ],
        "java_context": {
            "enclosing_method": {
                "name": method_name,
                "header_line": header_line,
                "end_line": end_line,
            },
            "source_line": source_line,
        },
        "raw_trace": {
            "taint_source": ["CliLoc", [{"line": source_line, "col": 1}, lines[source_line - 1]["text"]]],
            "intermediate_vars": [],
            "taint_sink": ["CliLoc", [{"line": sink_line, "col": 1}, lines[sink_line - 1]["text"]]],
        },
    }
    rec["heuristic_signals"] = heuristics.extract_evidence_signals(rec)
    return rec


def _make_refuted_assessment(rec: dict, cite_lines: list[int]) -> dict:
    path = rec["path"]
    sha = rec["snapshots"][path]["sha256"]
    line_map = {ln["line"]: ln["text"] for ln in rec["snippets"][0]["lines"]}
    cites = [
        {
            "path": path,
            "start_line": ln,
            "end_line": ln,
            "quote": line_map[ln],
            "sha256": sha,
        }
        for ln in cite_lines[:3]
    ]
    return {
        "status": "REFUTED",
        "explanation": "Claims flow is safe.",
        "fix_suggestion": "",
        "citations": cites,
        "citation_check": "MATCHED",
        "security_conclusion_verified": False,
        "raw_response": json.dumps({"status": "REFUTED", "citations": cites}),
    }


def _build_valid_v226_capture_dir(triage_dir: Path) -> tuple[Path, dict, dict]:
    """Create a self-consistent v2.2.6 capture fixture using real canonical serializer."""
    triage_dir.mkdir(parents=True, exist_ok=True)
    llm_dir = triage_dir / "llm_io"
    llm_dir.mkdir(parents=True, exist_ok=True)
    java_src = (
        "public class Demo {\n"
        "  void f(javax.servlet.http.HttpServletRequest req, java.sql.Statement st) throws Exception {\n"
        '    String u = req.getParameter("u");\n'
        '    st.executeQuery("SELECT * FROM t WHERE u=" + u);\n'
        "  }\n"
        "}\n"
    )
    src_dir = triage_dir.parent / f"{triage_dir.name}_src"
    src_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / "Demo.java").write_bytes(java_src.encode("utf-8"))
    rec = _make_record(java_src, path="Demo.java", cwe="CWE-89", source_line=3, sink_line=4, header_line=2, end_line=5, method_name="f")
    scan_sha = "1" * 64
    fid = digest(f"{scan_sha}:0".encode("utf-8"))
    rec["id"] = fid
    rec["alert_id"] = fid
    rec["scan_sha256"] = scan_sha
    rec["finding_index"] = 0
    rec["root"] = str(src_dir)
    rec["issues"] = []
    rec["scan_provenance"] = {"source_capture_verified": True}
    model = "qwen3.5:9b-q4_K_M"
    endpoint = "http://127.0.0.1:11434"
    req_payload = ollama.request_payload(rec, model)
    req_bytes = json.dumps(req_payload).encode("utf-8")
    req_sha = digest(req_bytes)
    prompt_sha = digest(json.dumps(req_payload["messages"], ensure_ascii=False).encode("utf-8"))
    ser_fp = ollama.PROMPT_SERIALIZER_FINGERPRINTS[PROMPT_VERSION]
    model_json = json.dumps(
        {
            "status": "SUPPORTED",
            "explanation": "Untrusted input concatenated into SQL.",
            "fix_suggestion": "Use PreparedStatement.",
            "citations": [
                {
                    "path": "Demo.java",
                    "start_line": 4,
                    "end_line": 4,
                    "quote": '    st.executeQuery("SELECT * FROM t WHERE u=" + u);',
                    "sha256": rec["snapshots"]["Demo.java"]["sha256"],
                }
            ],
        },
        ensure_ascii=False,
    )
    resp_obj = {
        "model": model,
        "message": {"role": "assistant", "content": model_json},
        "done": True,
        "done_reason": "stop",
        "eval_count": 10,
        "eval_duration": 1000,
    }
    resp_bytes = json.dumps(resp_obj, ensure_ascii=False).encode("utf-8")
    resp_body_sha = digest(resp_bytes)
    resp_json_sha = digest(json.dumps(resp_obj, sort_keys=True, ensure_ascii=False, allow_nan=False).encode("utf-8"))
    call_id = f"chat_analyze:{fid}:abcdef123456"

    runtime_doc = {
        "origin": "unverified",
        "finding_id": fid,
        "request_attempted": True,
        "http_response_received": True,
        "http_status": 200,
        "request_payload_sha256": req_sha,
        "request_payload_bytes": len(req_bytes),
        "request_raw_artifact": f"llm_io/{fid}.request.body.bin",
        "response_body_sha256": resp_body_sha,
        "response_body_bytes": len(resp_bytes),
        "response_raw_artifact": f"llm_io/{fid}.response.body.bin",
        "response_json_sha256": resp_json_sha,
        "http_capture_receipt": f"llm_io/{fid}.http-capture.json",
        "http_capture_completeness": "complete",
        "http_capture_complete": True,
        "prompt_version": PROMPT_VERSION,
        "prompt_contract": "blind",
        "prompt_sha256": prompt_sha,
        "serializer_fingerprint": ser_fp,
        "answer_validated": True,
        "failure_kind": "NONE",
    }
    row = {
        "id": fid,
        "evidence": rec,
        "assessment": {
            "status": "SUPPORTED",
            "raw_model_status": "SUPPORTED",
            "validated_status": "SUPPORTED",
            "validator_downgraded": False,
            "failure_kind": "NONE",
            "explanation": "Untrusted input concatenated into SQL.",
            "fix_suggestion": "Use PreparedStatement.",
            "citations": json.loads(model_json)["citations"],
            "citation_check": "MATCHED",
            "security_conclusion_verified": False,
            "requires_human_review": True,
            "transport": "ollama-http",
            "model": model,
            "endpoint": endpoint,
            "raw_response": resp_obj,
            "prompt_version": PROMPT_VERSION,
            "prompt_contract": "blind",
            "prompt_sha256": prompt_sha,
            "serializer_fingerprint": ser_fp,
            "runtime": copy.deepcopy(runtime_doc),
        },
    }
    (triage_dir / "evidence.json").write_text(
        json.dumps({"scan_sha256": scan_sha, "records": [rec]}, indent=2), encoding="utf-8"
    )
    (triage_dir / "assessments.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")

    (llm_dir / f"{fid}.request.body.bin").write_bytes(req_bytes)
    (llm_dir / f"{fid}.response.body.bin").write_bytes(resp_bytes)
    (llm_dir / f"{fid}.request.json").write_text(json.dumps(req_payload, indent=2), encoding="utf-8")
    (llm_dir / f"{fid}.prompt.json").write_text(
        json.dumps(
            {
                "finding_id": fid,
                "prompt_version": PROMPT_VERSION,
                "prompt_contract": "blind",
                "prompt_sha256": prompt_sha,
                "serializer_fingerprint": ser_fp,
                "messages": req_payload["messages"],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (llm_dir / f"{fid}.response.json").write_text(
        json.dumps(
            {
                "finding_id": fid,
                "model": model,
                "endpoint": endpoint,
                "runtime": copy.deepcopy(runtime_doc),
                "raw_response": resp_obj,
                "error": None,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (llm_dir / f"{fid}.http-capture.json").write_text(
        json.dumps(
            {
                "schema": "ntk-ollama-http-capture-1",
                "capture_scope": "http_body_and_client_metadata_not_tcp_wire",
                "call_id": call_id,
                "call_kind": "chat_analyze",
                "runtime_origin": "unverified",
                "finding_id": fid,
                "alert_id": fid,
                "scan_sha256": scan_sha,
                "finding_index": 0,
                "rule_id": rec["rule_id"],
                "endpoint": endpoint,
                "method": "POST",
                "path": "/api/chat",
                "requested_model": model,
                "prompt_version": PROMPT_VERSION,
                "prompt_contract": "blind",
                "prompt_sha256": prompt_sha,
                "serializer_fingerprint": ser_fp,
                "request_raw_file": f"{fid}.request.body.bin",
                "request_byte_length": len(req_bytes),
                "request_payload_sha256": req_sha,
                "http_status": 200,
                "response_headers": [["Content-Type", "application/json"]],
                "completeness": "complete",
                "complete": True,
                "response_raw_file": f"{fid}.response.body.bin",
                "response_byte_length": len(resp_bytes),
                "response_body_sha256": resp_body_sha,
                "response_json_parse_succeeded": True,
                "response_json_sha256": resp_json_sha,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return triage_dir, rec, row


class JavaSemanticsAndGate2SelfAuditTests(unittest.TestCase):
    def test_sb_p0_01_jls_char_plus_char_numeric_promotion_fails_closed(self) -> None:
        # 'A' + 'B' + "" evaluates to "131" in Java (JLS §15.18.1), NOT "AB"
        src1 = (
            "import java.sql.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class CharPromo1 {\n"
            "  void handle(HttpServletRequest req, Statement st) throws Exception {\n"
            '    String input = req.getParameter("x");\n'
            '    String key = \'A\' + \'B\' + "";\n'
            "    String bar;\n"
            "    switch (key) {\n"
            '      case "AB": bar = "safe"; break;\n'
            "      default: bar = input; break;\n"
            "    }\n"
            '    st.executeQuery("SELECT * FROM t WHERE c=" + bar);\n'
            "  }\n"
            "}\n"
        )
        rec1 = _make_record(src1, path="CharPromo1.java", source_line=5, sink_line=12, header_line=4, end_line=13)
        self.assertNotEqual(rec1["heuristic_signals"]["recommended_status"], "REFUTED")
        gated1 = apply_integration_gate(rec1, _make_refuted_assessment(rec1, [6, 9, 12]))
        self.assertEqual(gated1["status"], "UNDETERMINED")

        # char c = 'A'; String key = c + 'B' + ""; -> "131" in Java
        src2 = (
            "import java.sql.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class CharPromo2 {\n"
            "  void handle(HttpServletRequest req, Statement st) throws Exception {\n"
            '    String input = req.getParameter("x");\n'
            "    char c = 'A';\n"
            '    String key = c + \'B\' + "";\n'
            "    String bar;\n"
            "    switch (key) {\n"
            '      case "AB": bar = "safe"; break;\n'
            "      default: bar = input; break;\n"
            "    }\n"
            '    st.executeQuery("SELECT * FROM t WHERE c=" + bar);\n'
            "  }\n"
            "}\n"
        )
        rec2 = _make_record(src2, path="CharPromo2.java", source_line=5, sink_line=13, header_line=4, end_line=14)
        gated2 = apply_integration_gate(rec2, _make_refuted_assessment(rec2, [6, 7, 13]))
        self.assertEqual(gated2["status"], "UNDETERMINED")

        # '0' + '1' + "2" -> "972", charAt(0) == '9', NOT '0'
        src3 = (
            "import java.sql.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class CharPromo3 {\n"
            "  void handle(HttpServletRequest req, Statement st) throws Exception {\n"
            '    String input = req.getParameter("x");\n'
            '    String s = \'0\' + \'1\' + "2";\n'
            "    char ch = s.charAt(0);\n"
            "    String bar;\n"
            "    switch (ch) {\n"
            '      case \'0\': bar = "safe"; break;\n'
            "      default: bar = input; break;\n"
            "    }\n"
            '    st.executeQuery("SELECT * FROM t WHERE c=" + bar);\n'
            "  }\n"
            "}\n"
        )
        rec3 = _make_record(src3, path="CharPromo3.java", source_line=5, sink_line=13, header_line=4, end_line=14)
        gated3 = apply_integration_gate(rec3, _make_refuted_assessment(rec3, [6, 7, 13]))
        self.assertEqual(gated3["status"], "UNDETERMINED")

        # Positive control: "A" + 'B' + "C" IS "ABC" in Java -> Gate 2 proves DETERMINISTIC_CONSTANT_SWITCH
        src_pos = (
            "import java.sql.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class StrPlusCharPos {\n"
            "  void handle(HttpServletRequest req, Statement st) throws Exception {\n"
            '    String input = req.getParameter("x");\n'
            '    String key = "A" + \'B\' + "C";\n'
            "    String bar;\n"
            "    switch (key) {\n"
            '      case "ABC": bar = "safe"; break;\n'
            "      default: bar = input; break;\n"
            "    }\n"
            '    st.executeQuery("SELECT * FROM t WHERE c=" + bar);\n'
            "  }\n"
            "}\n"
        )
        rec_pos = _make_record(src_pos, path="StrPlusCharPos.java", source_line=5, sink_line=12, header_line=4, end_line=13)
        gated_pos = apply_integration_gate(rec_pos, _make_refuted_assessment(rec_pos, [6, 9, 12]))
        self.assertEqual(gated_pos["status"], "REFUTED")
        self.assertEqual(gated_pos["independent_refutation_proof"], "DETERMINISTIC_CONSTANT_SWITCH")

    def test_sb_p0_02_switch_braced_break_rejected_in_both_layers(self) -> None:
        for body_line in ("        break;", "        if (flag) break;"):
            src = (
                "import java.sql.*;\n"
                "import javax.servlet.http.HttpServletRequest;\n"
                "public class SwitchBlk {\n"
                "  void handle(HttpServletRequest req, Statement st, boolean flag) throws Exception {\n"
                '    String input = req.getParameter("x");\n'
                "    String bar;\n"
                '    switch ("A") {\n'
                '      case "A": {\n'
                "        bar = input;\n"
                f"{body_line}\n"
                "      }\n"
                '      case "B":\n'
                '        bar = "fixed";\n'
                "        break;\n"
                "    }\n"
                '    st.executeQuery("SELECT * FROM t WHERE c=" + bar);\n'
                "  }\n"
                "}\n"
            )
            rec = _make_record(src, path="SwitchBlk.java", source_line=5, sink_line=16, header_line=4, end_line=17)
            self.assertEqual(rec["heuristic_signals"]["recommended_status"], "SUPPORTED")
            gated = apply_integration_gate(rec, _make_refuted_assessment(rec, [7, 13, 16]))
            self.assertEqual(gated["status"], "UNDETERMINED")

    def test_sb_p0_03_cwe22_tainted_receiver_resolve_and_multi_resource_try(self) -> None:
        # Tainted Path receiver resolved with constant child
        src_recv = (
            "import java.nio.file.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class TaintedRecv {\n"
            "  Path handle(HttpServletRequest req) {\n"
            '    String input = req.getParameter("dir");\n'
            "    Path base = Paths.get(input);\n"
            '    return base.resolve("report.txt");\n'
            "  }\n"
            "}\n"
        )
        rec_r = _make_record(src_recv, path="TaintedRecv.java", cwe="CWE-22", source_line=5, sink_line=7, header_line=4, end_line=8)
        self.assertEqual(rec_r["heuristic_signals"]["recommended_status"], "SUPPORTED")
        gated_r = apply_integration_gate(rec_r, _make_refuted_assessment(rec_r, [6, 7]))
        self.assertEqual(gated_r["status"], "UNDETERMINED")

        # Post-guard 1-arg resolve with untrusted base receiver
        src_post = (
            "import java.io.*;\n"
            "import java.nio.file.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class PostGuardResolve {\n"
            "  Path handle(HttpServletRequest req, Path untrustedBase) throws Exception {\n"
            '    String raw = req.getParameter("f");\n'
            '    Path base = Paths.get("/srv/safe").toRealPath();\n'
            "    Path targetReal = base.resolve(raw).toRealPath();\n"
            "    if (!targetReal.startsWith(base)) {\n"
            '      throw new SecurityException("bad");\n'
            "    }\n"
            "    return untrustedBase.resolve(targetReal);\n"
            "  }\n"
            "}\n"
        )
        rec_p = _make_record(src_post, path="PostGuardResolve.java", cwe="CWE-22", source_line=6, sink_line=12, header_line=5, end_line=13)
        gated_p = apply_integration_gate(rec_p, _make_refuted_assessment(rec_p, [8, 9, 12]))
        self.assertEqual(gated_p["status"], "UNDETERMINED")

        # Multi-resource try-with-resources: first resource tainted, second constant
        src_try = (
            "import java.io.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class TwoResTry {\n"
            "  void handle(HttpServletRequest req) throws Exception {\n"
            '    String input = req.getParameter("p");\n'
            '    try (FileInputStream a = new FileInputStream(input); FileInputStream b = new FileInputStream("safe.txt")) {\n'
            "      a.read();\n"
            "    }\n"
            "  }\n"
            "}\n"
        )
        rec_t = _make_record(src_try, path="TwoResTry.java", cwe="CWE-22", source_line=5, sink_line=6, header_line=4, end_line=9)
        self.assertEqual(rec_t["heuristic_signals"]["recommended_status"], "SUPPORTED")
        gated_t = apply_integration_gate(rec_t, _make_refuted_assessment(rec_t, [5, 6]))
        self.assertEqual(gated_t["status"], "UNDETERMINED")

    def test_sb_p0_04_forged_sink_line_header_line_and_implements_shadow(self) -> None:
        # Forged heuristic_signals.sink_line pointing at safe line
        src_sql = (
            "import java.sql.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class ForgedSink {\n"
            "  void handle(HttpServletRequest req, Statement st) throws Exception {\n"
            '    String input = req.getParameter("u");\n'
            '    String safe = "SELECT 1";\n'
            "    st.executeQuery(safe);\n"
            '    st.executeQuery("SELECT * FROM users WHERE u=" + input);\n'
            "  }\n"
            "}\n"
        )
        rec_s = _make_record(src_sql, path="ForgedSink.java", source_line=5, sink_line=8, header_line=4, end_line=9)
        rec_s["heuristic_signals"]["sink_line"] = 7
        gated_s = apply_integration_gate(rec_s, _make_refuted_assessment(rec_s, [6, 7, 8]))
        self.assertEqual(gated_s["status"], "UNDETERMINED")
        self.assertIn("disagrees with verified OpenGrep", gated_s["downgrade_reason"])

        # Forged enclosing_method.header_line inside an if block
        src_hdr = (
            "import java.sql.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class ForgedHdr {\n"
            "  void handle(HttpServletRequest req, Statement st, boolean flag) throws Exception {\n"
            '    String q = "SELECT 1";\n'
            "    if (flag) {\n"
            '      q = "SELECT * FROM users WHERE u=" + req.getParameter("u");\n'
            "    }\n"
            "    st.executeQuery(q);\n"
            "  }\n"
            "}\n"
        )
        rec_h = _make_record(src_hdr, path="ForgedHdr.java", source_line=7, sink_line=9, header_line=8, end_line=10)
        gated_h = apply_integration_gate(rec_h, _make_refuted_assessment(rec_h, [5, 9]))
        self.assertEqual(gated_h["status"], "UNDETERMINED")

        # static final class implementing interface with shadowed constant must fail closed
        src_impl = (
            "import java.sql.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            'interface BaseConst { String KEY = "B"; }\n'
            'class Holder implements BaseConst { static final String OTHER = "A"; }\n'
            "public class ImplShadow {\n"
            "  void handle(HttpServletRequest req, Statement st) throws Exception {\n"
            '    String input = req.getParameter("u");\n'
            "    String bar;\n"
            "    switch (Holder.KEY) {\n"
            '      case "A": bar = "safe"; break;\n'
            "      default: bar = input; break;\n"
            "    }\n"
            '    st.executeQuery("SELECT * FROM t WHERE c=" + bar);\n'
            "  }\n"
            "}\n"
        )
        rec_i = _make_record(src_impl, path="ImplShadow.java", source_line=7, sink_line=13, header_line=6, end_line=14)
        gated_i = apply_integration_gate(rec_i, _make_refuted_assessment(rec_i, [4, 10, 13]))
        self.assertEqual(gated_i["status"], "UNDETERMINED")

    def test_sb_p1_01_heuristics_layer1_semantics_fixes(self) -> None:
        # 1. Java 32-bit int overflow in ternary
        src_ovf = (
            "import java.sql.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class OvfTern {\n"
            "  void handle(HttpServletRequest req, Statement st) throws Exception {\n"
            '    String input = req.getParameter("u");\n'
            "    int num = 100;\n"
            '    String bar = (100000 * 30000) - num > 200 ? "safe" : input;\n'
            '    st.executeQuery("SELECT * FROM t WHERE c=" + bar);\n'
            "  }\n"
            "}\n"
        )
        rec_ovf = _make_record(src_ovf, path="OvfTern.java", source_line=5, sink_line=8, header_line=4, end_line=9)
        self.assertEqual(rec_ovf["heuristic_signals"]["recommended_status"], "SUPPORTED")

        # 2. Switch default before case 'A'
        src_def = (
            "import java.sql.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class DefFirst {\n"
            "  void handle(HttpServletRequest req, Statement st) throws Exception {\n"
            '    String input = req.getParameter("u");\n'
            '    String guess = "ABC";\n'
            "    char switchTarget = guess.charAt(0);\n"
            "    String bar;\n"
            "    switch (switchTarget) {\n"
            "      default:\n"
            '        bar = "safe";\n'
            "        break;\n"
            "      case 'A':\n"
            "        bar = input;\n"
            "        break;\n"
            "    }\n"
            '    st.executeQuery("SELECT * FROM t WHERE c=" + bar);\n'
            "  }\n"
            "}\n"
        )
        rec_def = _make_record(src_def, path="DefFirst.java", source_line=5, sink_line=17, header_line=4, end_line=18)
        self.assertEqual(rec_def["heuristic_signals"]["recommended_status"], "SUPPORTED")

        # 3. Same-line case 'A': bar = input; break;
        src_sl = (
            "import java.sql.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class SameLineCase {\n"
            "  void handle(HttpServletRequest req, Statement st) throws Exception {\n"
            '    String input = req.getParameter("u");\n'
            '    String guess = "ABC";\n'
            "    char switchTarget = guess.charAt(0);\n"
            '    String bar = "safe";\n'
            "    switch (switchTarget) {\n"
            "      case 'A': bar = input; break;\n"
            '      default: bar = "safe"; break;\n'
            "    }\n"
            '    st.executeQuery("SELECT * FROM t WHERE c=" + bar);\n'
            "  }\n"
            "}\n"
        )
        rec_sl = _make_record(src_sl, path="SameLineCase.java", source_line=5, sink_line=13, header_line=4, end_line=14)
        self.assertEqual(rec_sl["heuristic_signals"]["recommended_status"], "SUPPORTED")

        # 4. Untyped reassignment invalidates tracked `num`
        src_num = (
            "import java.sql.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class NumReassign {\n"
            "  void handle(HttpServletRequest req, Statement st) throws Exception {\n"
            '    String input = req.getParameter("u");\n'
            "    int num = 10;\n"
            "    num = 500;\n"
            '    String bar = (7 * 42) - num > 200 ? "safe" : input;\n'
            '    st.executeQuery("SELECT * FROM t WHERE c=" + bar);\n'
            "  }\n"
            "}\n"
        )
        rec_num = _make_record(src_num, path="NumReassign.java", source_line=5, sink_line=9, header_line=4, end_line=10)
        self.assertEqual(rec_num["heuristic_signals"]["recommended_status"], "SUPPORTED")

        # 5. Collection mutated inside `if` branch invalidates tracked list
        src_lst = (
            "import java.sql.*;\n"
            "import java.util.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class ListMutIf {\n"
            "  void handle(HttpServletRequest req, Statement st, boolean flag) throws Exception {\n"
            '    String input = req.getParameter("u");\n'
            "    List<String> values = new ArrayList<>();\n"
            '    values.add("safe");\n'
            "    if (flag) {\n"
            "      values.set(0, input);\n"
            "    }\n"
            "    String bar = values.get(0);\n"
            '    st.executeQuery("SELECT * FROM t WHERE c=" + bar);\n'
            "  }\n"
            "}\n"
        )
        rec_lst = _make_record(src_lst, path="ListMutIf.java", source_line=6, sink_line=13, header_line=5, end_line=14)
        self.assertNotEqual(rec_lst["heuristic_signals"]["recommended_status"], "REFUTED")

        # 6. Sibling prefix `baseDir + "/reports"` and bare root `"/"` / `"C:/"` must NOT be SAFE_BOUNDARY
        self.assertNotEqual(heuristics._is_safe_path_prefix_expr('baseDir + "/reports"'), "SAFE_BOUNDARY")
        self.assertNotEqual(heuristics._is_safe_path_prefix_expr('"/"'), "SAFE_BOUNDARY")
        self.assertNotEqual(heuristics._is_safe_path_prefix_expr('"C:/"'), "SAFE_BOUNDARY")
        self.assertEqual(heuristics._is_safe_path_prefix_expr('"/app/reports/"'), "SAFE_BOUNDARY")
        self.assertEqual(heuristics._is_safe_path_prefix_expr("baseDir + File.separator"), "SAFE_BOUNDARY")

        # 7. Partial sub-call sanitizer match rejected (`String.format(..., Integer.parseInt("1"), input)` and `Paths.get(input, FilenameUtils.getName(safe))`)
        src_fmt = (
            "import java.sql.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class PartialScalar {\n"
            "  void handle(HttpServletRequest req, Statement st) throws Exception {\n"
            '    String input = req.getParameter("u");\n'
            '    String sql = String.format("SELECT * FROM t WHERE id=%d AND name=\'%s\'", Integer.parseInt("1"), input);\n'
            "    st.executeQuery(sql);\n"
            "  }\n"
            "}\n"
        )
        rec_fmt = _make_record(src_fmt, path="PartialScalar.java", source_line=5, sink_line=7, header_line=4, end_line=8)
        self.assertEqual(rec_fmt["heuristic_signals"]["recommended_status"], "SUPPORTED")

        src_p22 = (
            "import java.nio.file.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class PartialBasename {\n"
            "  Path handle(HttpServletRequest req) {\n"
            '    String input = req.getParameter("dir");\n'
            '    return Paths.get(input, FilenameUtils.getName("ok.txt"));\n'
            "  }\n"
            "}\n"
        )
        rec_p22 = _make_record(src_p22, path="PartialBasename.java", cwe="CWE-22", source_line=5, sink_line=6, header_line=4, end_line=7)
        self.assertEqual(rec_p22["heuristic_signals"]["recommended_status"], "SUPPORTED")


class HttpCaptureAndLiveCheckSelfAuditTests(unittest.TestCase):
    def test_sb_p1_02_to_08_tamper_cases_fail_closed_and_controls_pass(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            base_dir, rec, _ = _build_valid_v226_capture_dir(root / "base")
            fid = rec["id"]

            def _run_case(name: str, mutator):
                cdir = root / f"case_{name}"
                shutil.copytree(base_dir, cdir)
                rows = [json.loads((cdir / "assessments.jsonl").read_text(encoding="utf-8").strip())]
                mutator(cdir, rows[0])
                (cdir / "assessments.jsonl").write_text(json.dumps(rows[0]) + "\n", encoding="utf-8")
                vh = verify_http_capture.verify_run_http_captures(cdir, require_live_chat=False)
                lc = live_check.inspect(rows, minimum=1)
                return vh, lc

            # C0: clean v2.2.6 control passes both verifiers
            vh0, lc0 = _run_case("c0", lambda d, r: None)
            self.assertEqual(vh0["capture_status"], "VERIFIED_COMPLETE", vh0["errors"])
            self.assertEqual(vh0["findings"][0]["prompt_metadata_binding"], "VERIFIED_EXPLICIT")
            self.assertEqual(lc0["protocol_status"], "OLLAMA_REPORTED_UNATTESTED")
            self.assertTrue(lc0["warnings"][0]["request_payload_bound"])

            # C1: stripping all 4 prompt metadata keys from real v2.2.6 fails BOTH verifiers
            def _m_c1(d, r):
                for k in ("prompt_version", "prompt_contract", "prompt_sha256", "serializer_fingerprint"):
                    r["assessment"].pop(k, None)
                    r["assessment"]["runtime"].pop(k, None)
            vh1, lc1 = _run_case("c1", _m_c1)
            self.assertEqual(vh1["capture_status"], "FAILED")
            self.assertEqual(lc1["protocol_status"], "PENDING")
            self.assertFalse(lc1["warnings"][0]["request_payload_bound"])

            # C2: stripping runtime.prompt_version on v2.2.6 fails BOTH verifiers
            vh2, lc2 = _run_case("c2", lambda d, r: r["assessment"]["runtime"].pop("prompt_version", None))
            self.assertEqual(vh2["capture_status"], "FAILED")
            self.assertEqual(lc2["protocol_status"], "PENDING")
            self.assertFalse(lc2["warnings"][0]["request_payload_bound"])

            # C3: forged runtime.prompt_contract fails BOTH verifiers
            vh3, lc3 = _run_case("c3", lambda d, r: r["assessment"]["runtime"].__setitem__("prompt_contract", "neutral_hints"))
            self.assertEqual(vh3["capture_status"], "FAILED")
            self.assertEqual(lc3["protocol_status"], "PENDING")
            self.assertFalse(lc3["warnings"][0]["request_payload_bound"])

            # C4: historical v2.2.5 capture with stripped assessment.prompt_contract fails live_check
            def _m_c4(d, r):
                r["assessment"]["prompt_version"] = "v2.2.5-cwe22-cwe89-exec-citations-and-flow-rebuttal"
                r["assessment"].pop("prompt_contract", None)
                r["assessment"]["runtime"].pop("prompt_contract", None)
            _, lc4 = _run_case("c4", _m_c4)
            self.assertEqual(lc4["protocol_status"], "PENDING")
            self.assertFalse(lc4["warnings"][0]["request_payload_bound"])

            # C5: missing request.body.bin fails verify_http_capture and never reports VERIFIED_* binding
            def _m_c5(d, r):
                (d / "llm_io" / f"{fid}.request.body.bin").unlink()
                r["assessment"]["serializer_fingerprint"] = None
                r["assessment"]["runtime"]["serializer_fingerprint"] = None
            vh5, _ = _run_case("c5", _m_c5)
            self.assertEqual(vh5["capture_status"], "FAILED")
            self.assertEqual(vh5["findings"][0]["prompt_metadata_binding"], "FAILED")

            # C8: swapped .response.json sidecar (model/endpoint/runtime) fails verify_http_capture
            def _m_c8(d, r):
                rp = d / "llm_io" / f"{fid}.response.json"
                rdoc = json.loads(rp.read_text(encoding="utf-8"))
                rdoc["model"] = "other-model:7b"
                rdoc["endpoint"] = "http://127.0.0.1:9999"
                rdoc["runtime"]["request_payload_sha256"] = "0" * 64
                rp.write_text(json.dumps(rdoc, indent=2), encoding="utf-8")
            vh8, _ = _run_case("c8", _m_c8)
            self.assertEqual(vh8["capture_status"], "FAILED")
            self.assertEqual(vh8["findings"][0]["prompt_metadata_binding"], "FAILED")

            # C9: stripped runtime.finding_id fails verify_http_capture
            vh9, _ = _run_case("c9", lambda d, r: r["assessment"]["runtime"].pop("finding_id", None))
            self.assertEqual(vh9["capture_status"], "FAILED")

            # C10: forged receipt prompt_version / prompt_sha256 fails verify_http_capture
            def _m_c10(d, r):
                rcp = d / "llm_io" / f"{fid}.http-capture.json"
                rc = json.loads(rcp.read_text(encoding="utf-8"))
                rc["prompt_version"] = "v99-forged"
                rc["prompt_sha256"] = "0" * 64
                rcp.write_text(json.dumps(rc, indent=2), encoding="utf-8")
            vh10, _ = _run_case("c10", _m_c10)
            self.assertEqual(vh10["capture_status"], "FAILED")

            # C11: minimal M2 protocol fixture (without prompt metadata) stays compatible
            m2_ev = {k: v for k, v in rec.items() if k != "prompt_contract"}
            m2_req_sha = digest(json.dumps(ollama.request_payload(m2_ev, "qwen3.5:9b-q4_K_M")).encode("utf-8"))
            resp_obj = {
                "model": "qwen3.5:9b-q4_K_M",
                "done": True,
                "done_reason": "stop",
                "eval_count": 10,
                "eval_duration": 1000,
                "message": {"role": "assistant", "content": "{}"},
            }
            m2_row = {
                "id": fid,
                "evidence": m2_ev,
                "assessment": {
                    "status": "UNDETERMINED",
                    "model": "qwen3.5:9b-q4_K_M",
                    "runtime": {
                        "origin": "unverified",
                        "request_attempted": True,
                        "http_response_received": True,
                        "http_status": 200,
                        "finding_id": fid,
                        "request_payload_sha256": m2_req_sha,
                        "response_json_sha256": digest(
                            json.dumps(resp_obj, sort_keys=True, ensure_ascii=False, allow_nan=False).encode("utf-8")
                        ),
                    },
                    "raw_response": resp_obj,
                },
            }
            lc11 = live_check.inspect([m2_row], minimum=1)
            self.assertEqual(lc11["protocol_status"], "OLLAMA_REPORTED_UNATTESTED")
            self.assertTrue(lc11["warnings"][0]["request_payload_bound"])


class CoverageAndTimingSelfAuditTests(unittest.TestCase):
    def test_sb_p1_09_duplicate_inventory_does_not_resurrect_from_cache(self) -> None:
        raw_og = {"paths": {"scanned": ["A.java"]}}
        raw_tel = compute_opengrep_coverage_telemetry(["A.java", "./A.java"], raw_og)
        self.assertEqual(raw_tel["opengrep_paths_telemetry_status"], "INCONSISTENT_TELEMETRY")
        self.assertIsNone(raw_tel["java_files_inventory"])
        cached = {
            "java_files_inventory": 2,
            "java_files_opengrep_scanned": 1,
            "java_files_opengrep_ignored": 1,
            "opengrep_paths_telemetry_status": "VERIFIED",
        }
        rec = reconcile_cached_and_raw_coverage_telemetry(
            cached,
            raw_tel,
            expected_inventory=2,
            scan_sha256="a" * 64,
        )
        self.assertEqual(rec["opengrep_paths_telemetry_status"], "INCONSISTENT_TELEMETRY")
        self.assertIsNone(rec["java_files_inventory"])
        self.assertIsNone(rec["java_files_opengrep_scanned"])
        self.assertIsNone(rec["java_files_opengrep_ignored"])

    def test_sb_p1_10_and_11_service_malformed_types_and_manifest_precedence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = config.ApiConfig(data_dir=root / "data", runtime_origin="mock")
            svc = service.TriageApiService(cfg)
            base_dir = root / "scan_s1"
            (base_dir / "capture").mkdir(parents=True)
            og_bytes = json.dumps({"results": [], "paths": {"scanned": ["Alien.java"]}}).encode("utf-8")
            (base_dir / "capture" / "opengrep.json").write_bytes(og_bytes)
            scan_sha = digest(og_bytes)
            manifest_bytes = json.dumps(
                {"sources_before": {"A.java": "a" * 64}, "sources_after": {"A.java": "a" * 64}}
            ).encode("utf-8")
            (base_dir / "capture" / "scan-manifest.json").write_bytes(manifest_bytes)
            entry = service.DiscoveredScan(
                scan_id=scan_sha,
                scan_sha256=scan_sha,
                base_dir=base_dir,
                triage_dir=base_dir / "triage",
                db_path=base_dir / "triage" / "review.sqlite",
                evidence_path=base_dir / "triage" / "evidence.json",
                assessments_path=base_dir / "triage" / "assessments.jsonl",
                raw_json_path=base_dir / "capture" / "opengrep.json",
                g1_manifest_path=None,
                meta_path=None,
                writable=False,
                is_managed=False,
            )
            prov = {
                "origin": "recorded_capture_unsigned",
                "source_capture_verified": True,
                "exit_capture_verified": True,
                "recorded_engine_exit": 0,
                "manifest_sha256": digest(manifest_bytes),
            }
            # D5: unverified meta_doc["java_sha256"] cannot override verified scan-manifest.json
            s_d5 = svc._build_scan_summary_from_snapshot(
                entry,
                {"scan_sha256": scan_sha, "root": str(root / "src"), "scan_provenance": prov},
                [],
                {},
                {"java_sha256": {"Alien.java": "x" * 64}},
            )
            self.assertEqual(s_d5["opengrep_paths_telemetry_status"], "INCONSISTENT_TELEMETRY")
            self.assertIsNone(s_d5["java_files_opengrep_scanned"])

            # D2: malformed pre_scan_hashes type (list instead of dict) -> INCONSISTENT_TELEMETRY
            s_d2 = svc._build_scan_summary_from_snapshot(
                entry,
                {"scan_sha256": scan_sha, "root": str(root / "src"), "pre_scan_hashes": ["A.java"], "scan_provenance": prov},
                [],
                {},
                {},
            )
            self.assertEqual(s_d2["opengrep_paths_telemetry_status"], "INCONSISTENT_TELEMETRY")

            # D3: malformed meta_doc.java_files_count ("498") without inventory -> INCONSISTENT_TELEMETRY
            (base_dir / "capture" / "scan-manifest.json").unlink()
            s_d3 = svc._build_scan_summary_from_snapshot(
                entry,
                {"scan_sha256": scan_sha, "root": str(root / "src"), "scan_provenance": {k: v for k, v in prov.items() if k != "manifest_sha256"}},
                [],
                {},
                {"java_files_count": "498"},
            )
            self.assertEqual(s_d3["opengrep_paths_telemetry_status"], "INCONSISTENT_TELEMETRY")

    def test_unicode_case_expansion_root_prefix_control(self) -> None:
        cov = compute_opengrep_coverage_telemetry(
            ["A.java"],
            {"paths": {"scanned": ["C:/r\u0130/A.java"]}},
            source_root=Path("C:/r\u0130"),
        )
        self.assertEqual(cov["opengrep_paths_telemetry_status"], "VERIFIED")
        self.assertEqual(cov["java_files_inventory"], 1)
        self.assertEqual(cov["java_files_opengrep_scanned"], 1)
        self.assertEqual(cov["java_files_opengrep_ignored"], 0)

    def test_sb_p1_12_stage4_and_stage5_projection_expressions_sanitized(self) -> None:
        tree = ast.parse(Path(jobs.__file__).read_text(encoding="utf-8"))
        stage4_exprs = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "duration_ms" and "qwen_total_ms" in ast.unparse(kw.value):
                        stage4_exprs.append((node.lineno, ast.Expression(body=kw.value)))
        self.assertEqual(len(stage4_exprs), 2, "Expected both Stage-4 duration_ms projection sites in jobs.py")
        for lno, expr_ast in stage4_exprs:
            code_obj = compile(expr_ast, f"jobs.py:{lno}", "eval")
            for bad in (float("nan"), float("inf"), float("-inf"), -5.0, True, False, "9", 10**400, None):
                payload = {"qwen_total_ms": bad}
                val = eval(code_obj, {"__builtins__": {"round": round, "float": float}}, {"no_llm": False, "info": payload, "triage_telemetry": payload})
                self.assertIsNone(val, f"jobs.py:{lno} failed to reject {bad!r}: got {val!r}")
            neg_zero_val = eval(code_obj, {"__builtins__": {"round": round, "float": float}}, {"no_llm": False, "info": {"qwen_total_ms": -0.0}, "triage_telemetry": {"qwen_total_ms": -0.0}})
            self.assertEqual(neg_zero_val, 0.0)
            self.assertFalse(math.copysign(1.0, neg_zero_val) < 0)
            ok_val = eval(code_obj, {"__builtins__": {"round": round, "float": float}}, {"no_llm": False, "info": {"qwen_total_ms": 12.3454}, "triage_telemetry": {"qwen_total_ms": 12.3454}})
            self.assertEqual(ok_val, 12.345)

    def test_preflight_real_gate_downgrade_and_oversize_writer_verifier_parity(self) -> None:
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading
        import time as _time
        from v2.api.qwen_triage import run_bounded_triage
        from v2.triage.evidence import collect

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src_dir = root / "src"
            src_dir.mkdir()
            pad = "\n".join(f"    int v{i} = {i}; // oversize padding {i:04d} abcdefghijklmnopqrstuvwxyz" for i in range(60))
            java_src = (
                "public class OversizeSql {\n"
                "  void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt) throws Exception {\n"
                '    String input = req.getParameter("u");\n'
                + pad
                + "\n"
                '    stmt.executeQuery("SELECT * FROM users WHERE u=" + input);\n'
                "  }\n"
                "}\n"
            )
            (src_dir / "OversizeSql.java").write_bytes(java_src.encode("utf-8"))
            lines_ke = java_src.splitlines(keepends=True)
            lines = java_src.splitlines()

            def _pt(ln: int, col: int) -> dict[str, int]:
                return {"line": ln, "col": col, "offset": sum(len(x.encode("utf-8")) for x in lines_ke[: ln - 1]) + col - 1}

            def _loc(ln: int, txt: str) -> dict:
                c = lines[ln - 1].index(txt) + 1
                return {"path": "OversizeSql.java", "start": _pt(ln, c), "end": _pt(ln, c + len(txt.encode("utf-8")))}

            raw_scan = {
                "results": [
                    {
                        "check_id": "test.cwe89",
                        "path": "OversizeSql.java",
                        "start": _loc(64, 'stmt.executeQuery("SELECT * FROM users WHERE u=" + input)')["start"],
                        "end": _loc(64, 'stmt.executeQuery("SELECT * FROM users WHERE u=" + input)')["end"],
                        "extra": {
                            "severity": "ERROR",
                            "metadata": {"cwe": ["CWE-89"]},
                            "message": "SQLi",
                            "dataflow_trace": {
                                "taint_source": ["CliLoc", [_loc(3, 'req.getParameter("u")'), 'req.getParameter("u")']],
                                "intermediate_vars": [],
                                "taint_sink": ["CliLoc", [_loc(64, 'stmt.executeQuery("SELECT * FROM users WHERE u=" + input)'), 'stmt.executeQuery("SELECT * FROM users WHERE u=" + input)']],
                            },
                        },
                    }
                ],
                "errors": [],
            }
            eng = root / "engine"
            eng.mkdir()
            raw_p = eng / "opengrep.json"
            raw_p.write_text(json.dumps(raw_scan), encoding="utf-8")
            rules_p = eng / "rules.snapshot.yml"
            rules_p.write_text("rules: []\n", encoding="utf-8")
            man_p = eng / "scan-manifest.json"
            f_sha = digest((src_dir / "OversizeSql.java").read_bytes())
            r_sha = digest(rules_p.read_bytes())
            j_sha = digest(raw_p.read_bytes())
            man_p.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "recorded_engine_exit": 0,
                        "engine_exit": 0,
                        "opengrep_json_sha256": j_sha,
                        "rules_before_sha256": r_sha,
                        "rules_after_sha256": r_sha,
                        "source_hashes": {"OversizeSql.java": f_sha},
                        "artifacts": {"rules.snapshot.yml": r_sha, "opengrep.json": j_sha},
                    }
                ),
                encoding="utf-8",
            )
            tags_raw = json.dumps({"models": [{"name": "qwen3.5:9b-q4_K_M", "digest": "a" * 64, "size": 1}]}).encode("utf-8")

            class _TagsOnlyHandler(BaseHTTPRequestHandler):
                def log_message(self, *args):
                    pass

                def do_GET(self):
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(tags_raw)))
                    self.end_headers()
                    self.wfile.write(tags_raw)

            srv = ThreadingHTTPServer(("127.0.0.1", 0), _TagsOnlyHandler)
            th = threading.Thread(target=srv.serve_forever, daemon=True)
            th.start()
            try:
                tdir = root / "triage"
                out = run_bounded_triage(
                    source_root=src_dir,
                    triage_dir=tdir,
                    raw_json_path=raw_p,
                    manifest_path=man_p,
                    path_maps=[],
                    rules_path=rules_p,
                    no_llm=False,
                    prompt_contract="blind",
                    ollama_endpoint=f"http://127.0.0.1:{srv.server_port}",
                    ollama_model="qwen3.5:9b-q4_K_M",
                    ollama_timeout_seconds=5.0,
                    runtime_origin="mock",
                    deadline_mono=_time.monotonic() + 30.0,
                    max_prompt_bytes=500,
                )
            finally:
                srv.shutdown()
                srv.server_close()
                th.join(timeout=2)

            self.assertEqual(out["assessments_list"][0]["failure_kind"], "PROMPT_TOO_LARGE")
            vf = verify_http_capture.verify_run_http_captures(tdir, require_live_chat=False)
            self.assertEqual(vf["capture_status"], "VERIFIED_ERROR_OR_PARTIAL_CAPTURED", vf["errors"])
            self.assertTrue(vf["capture_integrity_ok"], vf["errors"])
            self.assertFalse(vf["live_chat_verified"])
            vt = verify_http_capture.verify_run_http_captures(tdir, require_live_chat=True)
            self.assertEqual(vt["capture_status"], "FAILED")
            self.assertFalse(vt["live_chat_verified"])

            # Also verify real OllamaClient -> real apply_integration_gate Gate-1 downgrade passes verifier
            h_src_dir = root / "h_src"
            h_src_dir.mkdir()
            h_java = (
                "public class HelperSql {\n"
                "  void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt) throws Exception {\n"
                '    String input = req.getParameter("u");\n'
                "    String clean = ExternalUtil.transform(input);\n"
                '    stmt.executeQuery("SELECT * FROM users WHERE u=" + clean);\n'
                "  }\n"
                "}\n"
            )
            (h_src_dir / "HelperSql.java").write_bytes(h_java.encode("utf-8"))
            hl_ke = h_java.splitlines(keepends=True)
            hl = h_java.splitlines()

            def _hpt(ln: int, col: int) -> dict[str, int]:
                return {"line": ln, "col": col, "offset": sum(len(x.encode("utf-8")) for x in hl_ke[: ln - 1]) + col - 1}

            def _hloc(ln: int, txt: str) -> dict:
                c = hl[ln - 1].index(txt) + 1
                return {"path": "HelperSql.java", "start": _hpt(ln, c), "end": _hpt(ln, c + len(txt.encode("utf-8")))}

            h_scan = {
                "results": [
                    {
                        "check_id": "test.cwe89",
                        "path": "HelperSql.java",
                        "start": _hloc(5, 'stmt.executeQuery("SELECT * FROM users WHERE u=" + clean)')["start"],
                        "end": _hloc(5, 'stmt.executeQuery("SELECT * FROM users WHERE u=" + clean)')["end"],
                        "extra": {
                            "severity": "ERROR",
                            "metadata": {"cwe": ["CWE-89"]},
                            "message": "SQLi",
                            "dataflow_trace": {
                                "taint_source": ["CliLoc", [_hloc(3, 'req.getParameter("u")'), 'req.getParameter("u")']],
                                "intermediate_vars": [],
                                "taint_sink": ["CliLoc", [_hloc(5, 'stmt.executeQuery("SELECT * FROM users WHERE u=" + clean)'), 'stmt.executeQuery("SELECT * FROM users WHERE u=" + clean)']],
                            },
                        },
                    }
                ],
                "errors": [],
            }
            h_bundle = collect(
                json.dumps(h_scan),
                h_src_dir,
                engine_exit=0,
                scan_provenance={"origin": "UNIT_TEST_MOCK_CAPTURE", "producer": "UNIT_TEST_MOCK_CAPTURE", "source_capture_verified": True},
            )
            h_bundle["prompt_contract"] = "blind"
            h_rec = h_bundle["records"][0]
            h_rec["prompt_contract"] = "blind"
            h_sha = h_rec["snapshots"]["HelperSql.java"]["sha256"]
            chat_body = json.dumps(
                {
                    "model": "qwen3.5:9b-q4_K_M",
                    "mock_test_fixture": True,
                    "done": True,
                    "done_reason": "stop",
                    "eval_count": 20,
                    "eval_duration": 100000,
                    "message": {
                        "role": "assistant",
                        "content": json.dumps(
                            {
                                "explanation": "Sink receives variable from external helper.",
                                "citations": [{"path": "HelperSql.java", "start_line": 5, "end_line": 5, "quote": hl[4], "sha256": h_sha}],
                                "status": "SUPPORTED",
                                "fix_suggestion": "Use PreparedStatement.",
                            }
                        ),
                    },
                }
            ).encode("utf-8")

            class _ChatHandler(BaseHTTPRequestHandler):
                def log_message(self, *args):
                    pass

                def do_POST(self):
                    n = int(self.headers.get("Content-Length", "0"))
                    if n:
                        self.rfile.read(n)
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(chat_body)))
                    self.end_headers()
                    self.wfile.write(chat_body)

            srv2 = ThreadingHTTPServer(("127.0.0.1", 0), _ChatHandler)
            th2 = threading.Thread(target=srv2.serve_forever, daemon=True)
            th2.start()
            try:
                htdir = root / "h_triage"
                htdir.mkdir()
                cl2 = ollama.OllamaClient(
                    endpoint=f"http://127.0.0.1:{srv2.server_port}",
                    model="qwen3.5:9b-q4_K_M",
                    timeout=5,
                    runtime_origin="mock",
                    io_log_dir=htdir / "llm_io",
                    capture_root=htdir,
                )
                raw_a = cl2.analyze(h_rec)
            finally:
                srv2.shutdown()
                srv2.server_close()
                th2.join(timeout=2)

            gated = apply_integration_gate(h_rec, raw_a)
            self.assertEqual(gated["validated_status"], "UNDETERMINED")
            self.assertEqual(gated["failure_kind"], "UNVERIFIED_HELPER_FLOW")
            self.assertTrue(gated.get("downgrade_reason"))
            self.assertEqual(len(gated["citations"]), 1)
            (htdir / "evidence.json").write_text(json.dumps(h_bundle, indent=2), encoding="utf-8")
            (htdir / "assessments.jsonl").write_text(
                json.dumps(
                    {
                        "id": h_rec["id"],
                        "state": "OPEN",
                        "human_review_state": "OPEN",
                        "raw_model_status": gated.get("raw_model_status"),
                        "validated_status": gated.get("validated_status"),
                        "evidence": h_rec,
                        "assessment": gated,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            hv = verify_http_capture.verify_run_http_captures(htdir, require_live_chat=False)
            self.assertEqual(hv["capture_status"], "VERIFIED_COMPLETE", hv["errors"])
            self.assertTrue(hv["capture_integrity_ok"], hv["errors"])
            self.assertFalse(hv["live_chat_verified"])

    def test_p1_six_chatgpt_counterexamples_and_jobs_integration_gate_binding(self) -> None:
        """Verify all 6 ChatGPT P1 counterexamples, citation substitution, jobs.py propagation, and real gate paths."""
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading
        from v2.triage.evidence import collect

        with tempfile.TemporaryDirectory(prefix="ntk_p1_sa_") as td:
            root = Path(td)
            clean_dir, rec, _row = _build_valid_v226_capture_dir(root / "clean")
            src_lines = {ln["line"]: ln["text"] for ln in rec["snippets"][0]["lines"]}
            snap_sha = rec["snapshots"]["Demo.java"]["sha256"]

            # Clean fixture stays VERIFIED_COMPLETE in normal mode with live flags False
            rep_clean = verify_http_capture.verify_run_http_captures(clean_dir, require_live_chat=False)
            self.assertEqual(rep_clean["capture_status"], "VERIFIED_COMPLETE", rep_clean["errors"])
            self.assertTrue(rep_clean["artifact_integrity_ok"])
            self.assertFalse(rep_clean["live_origin_verified"])
            self.assertFalse(rep_clean["live_chat_verified"])

            cases = {
                "ce1_quote": lambda r: r["assessment"]["citations"][0].__setitem__("quote", "not in Java source"),
                "ce2_empty_cites": lambda r: r["assessment"].__setitem__("citations", []),
                "ce3_cc_none": lambda r: r["assessment"].__setitem__("citation_check", "NONE"),
                "ce4_explanation": lambda r: r["assessment"].__setitem__("explanation", "Text not returned by endpoint"),
                "ce5_fix_suggestion": lambda r: r["assessment"].__setitem__("fix_suggestion", "Different suggestion"),
                "ce6_del_raw_ms": lambda r: r["assessment"].pop("raw_model_status", None),
                "ce7_sub_real_source_cite": lambda r: r["assessment"].__setitem__(
                    "citations",
                    [{"path": "Demo.java", "start_line": 3, "end_line": 3, "quote": src_lines[3], "sha256": snap_sha}],
                ),
            }
            for name, mut in cases.items():
                with self.subTest(counterexample=name):
                    cdir = root / name
                    shutil.copytree(clean_dir, cdir)
                    aj = cdir / "assessments.jsonl"
                    row = json.loads(aj.read_text(encoding="utf-8").strip())
                    mut(row)
                    aj.write_text(json.dumps(row, ensure_ascii=False) + "\n", encoding="utf-8")
                    rn = verify_http_capture.verify_run_http_captures(cdir, require_live_chat=False)
                    rs = verify_http_capture.verify_run_http_captures(cdir, require_live_chat=True)
                    self.assertEqual(rn["capture_status"], "FAILED", f"{name} normal passed: {rn}")
                    self.assertFalse(rn["artifact_integrity_ok"], name)
                    self.assertEqual(rs["capture_status"], "FAILED", name)
                    self.assertFalse(rs["artifact_integrity_ok"], name)
                    self.assertFalse(rs["live_origin_verified"], name)
                    self.assertFalse(rs["live_chat_verified"], name)

                    # jobs._verify_mixed_http_captures must also propagate new P1 integrity failures as FAILED
                    mixed_res = jobs._verify_mixed_http_captures(cdir, [row])
                    self.assertEqual(mixed_res["capture_status"], "MIXED_CACHE_AND_LIVE_HTTP_FAILED")
                    self.assertFalse(mixed_res["capture_integrity_ok"])
                    self.assertFalse(mixed_res["live_chat_verified"])

            # Real loopback writer + Layer-1 UNVERIFIED_REFUTATION citation preservation through apply_integration_gate
            src_dir = root / "l1_ref_src"
            src_dir.mkdir()
            java_src = (
                "public class BadSan {\n"
                "  void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement st) throws Exception {\n"
                '    String input = req.getParameter("u");\n'
                "    String encoded = org.owasp.esapi.ESAPI.encoder().encodeForHTML(input);\n"
                '    st.executeQuery("SELECT * FROM t WHERE u=" + encoded);\n'
                "  }\n"
                "}\n"
            )
            (src_dir / "BadSan.java").write_bytes(java_src.encode("utf-8"))
            lke = java_src.splitlines(keepends=True)
            ls = java_src.splitlines()

            def _pt(ln: int, col: int) -> dict[str, int]:
                return {"line": ln, "col": col, "offset": sum(len(x.encode("utf-8")) for x in lke[: ln - 1]) + col - 1}

            def _loc(ln: int, txt: str) -> dict:
                c = ls[ln - 1].index(txt) + 1
                return {"path": "BadSan.java", "start": _pt(ln, c), "end": _pt(ln, c + len(txt.encode("utf-8")))}

            raw_scan = {
                "results": [
                    {
                        "check_id": "test.cwe89",
                        "path": "BadSan.java",
                        "start": _pt(5, 5),
                        "end": _pt(5, 59),
                        "extra": {
                            "severity": "ERROR",
                            "metadata": {"cwe": ["CWE-89"]},
                            "message": "SQLi",
                            "dataflow_trace": {
                                "taint_source": ["CliLoc", [_loc(3, 'req.getParameter("u")'), 'req.getParameter("u")']],
                                "intermediate_vars": [],
                                "taint_sink": ["CliLoc", [_loc(5, 'st.executeQuery("SELECT * FROM t WHERE u=" + encoded)'), 'st.executeQuery("SELECT * FROM t WHERE u=" + encoded)']],
                            },
                        },
                    }
                ],
                "errors": [],
            }
            b = collect(
                json.dumps(raw_scan),
                src_dir,
                engine_exit=0,
                scan_provenance={"origin": "UNIT_TEST_MOCK_CAPTURE", "producer": "UNIT_TEST_MOCK_CAPTURE", "source_capture_verified": True},
            )
            b["prompt_contract"] = "blind"
            r0 = b["records"][0]
            r0["prompt_contract"] = "blind"
            r0_sha = r0["snapshots"]["BadSan.java"]["sha256"]
            body = json.dumps(
                {
                    "model": "qwen3.5:9b-q4_K_M",
                    "mock_test_fixture": True,
                    "done": True,
                    "done_reason": "stop",
                    "eval_count": 15,
                    "eval_duration": 100000,
                    "message": {
                        "role": "assistant",
                        "content": json.dumps(
                            {
                                "status": "REFUTED",
                                "explanation": "encodeForHTML neutralizes input.",
                                "fix_suggestion": "",
                                "citations": [
                                    {"path": "BadSan.java", "start_line": 4, "end_line": 4, "quote": ls[3], "sha256": r0_sha}
                                ],
                            }
                        ),
                    },
                }
            ).encode("utf-8")

            class _RefH(BaseHTTPRequestHandler):
                def log_message(self, *args):
                    pass

                def do_POST(self):
                    n = int(self.headers.get("Content-Length", "0"))
                    if n:
                        self.rfile.read(n)
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

            srv = ThreadingHTTPServer(("127.0.0.1", 0), _RefH)
            th = threading.Thread(target=srv.serve_forever, daemon=True)
            th.start()
            try:
                tdir_l1 = root / "l1_unref_triage"
                tdir_l1.mkdir()
                cl = ollama.OllamaClient(
                    endpoint=f"http://127.0.0.1:{srv.server_port}",
                    model="qwen3.5:9b-q4_K_M",
                    timeout=5,
                    runtime_origin="mock",
                    io_log_dir=tdir_l1 / "llm_io",
                    capture_root=tdir_l1,
                )
                raw_ass = cl.analyze(r0)
            finally:
                srv.shutdown()
                srv.server_close()
                th.join(timeout=2)

            self.assertEqual(raw_ass["failure_kind"], "UNVERIFIED_REFUTATION")
            self.assertEqual(raw_ass["citations"], [])
            gated_l1 = apply_integration_gate(r0, raw_ass)
            self.assertEqual(gated_l1["validated_status"], "UNDETERMINED")
            self.assertEqual(gated_l1["failure_kind"], "UNVERIFIED_REFUTATION")
            self.assertEqual(len(gated_l1["citations"]), 1)
            self.assertEqual(gated_l1["citation_check"], "MATCHED")
            (tdir_l1 / "evidence.json").write_text(json.dumps(b, indent=2), encoding="utf-8")
            l1_row = {
                "id": r0["id"],
                "state": "OPEN",
                "human_review_state": "OPEN",
                "raw_model_status": gated_l1.get("raw_model_status"),
                "validated_status": gated_l1.get("validated_status"),
                "evidence": r0,
                "assessment": gated_l1,
            }
            (tdir_l1 / "assessments.jsonl").write_text(json.dumps(l1_row) + "\n", encoding="utf-8")
            l1_rep = verify_http_capture.verify_run_http_captures(tdir_l1, require_live_chat=False)
            self.assertEqual(l1_rep["capture_status"], "VERIFIED_COMPLETE", l1_rep["errors"])
            self.assertTrue(l1_rep["artifact_integrity_ok"])

            # Codex P1 & P2 caller propagation via jobs._verify_mixed_http_captures:
            # 1) Tampering downgrade_reason on Layer-1 UNVERIFIED_REFUTATION must fail both verifier and jobs.py!
            tdir_l1_bad = root / "l1_unref_bad_dr"
            shutil.copytree(tdir_l1, tdir_l1_bad)
            bad_l1_row = copy.deepcopy(l1_row)
            bad_l1_row["assessment"]["downgrade_reason"] = "Human Review confirmed the finding safe."
            (tdir_l1_bad / "assessments.jsonl").write_text(json.dumps(bad_l1_row) + "\n", encoding="utf-8")
            self.assertEqual(verify_http_capture.verify_run_http_captures(tdir_l1_bad, require_live_chat=False)["capture_status"], "FAILED")
            bad_l1_mixed = jobs._verify_mixed_http_captures(tdir_l1_bad, [bad_l1_row])
            self.assertEqual(bad_l1_mixed["capture_status"], "MIXED_CACHE_AND_LIVE_HTTP_FAILED")
            self.assertFalse(bad_l1_mixed["capture_integrity_ok"])

            # 2) Precheck missing nested validated_status (Codex P2) must fail both verifier and jobs.py!
            pre_b = copy.deepcopy(b)
            pre_b["records"][0]["issues"].append("synthetic precheck issue")
            tdir_pre = root / "p2_precheck_jobs"
            tdir_pre.mkdir()
            cl_p2 = ollama.OllamaClient(
                endpoint="http://127.0.0.1:11434",
                model="qwen3.5:9b-q4_K_M",
                timeout=5,
                runtime_origin="mock",
                io_log_dir=tdir_pre / "llm_io",
                capture_root=tdir_pre,
            )
            p2_ass = cl_p2.analyze(pre_b["records"][0])
            (tdir_pre / "evidence.json").write_text(json.dumps(pre_b, indent=2), encoding="utf-8")
            p2_row = {
                "id": pre_b["records"][0]["id"],
                "state": "OPEN",
                "human_review_state": "OPEN",
                "raw_model_status": p2_ass.get("raw_model_status"),
                "validated_status": p2_ass.get("validated_status"),
                "evidence": pre_b["records"][0],
                "assessment": copy.deepcopy(p2_ass),
            }
            (tdir_pre / "assessments.jsonl").write_text(json.dumps(p2_row) + "\n", encoding="utf-8")
            self.assertTrue(verify_http_capture.verify_run_http_captures(tdir_pre, require_live_chat=False)["artifact_integrity_ok"])

            p2_row_missing = copy.deepcopy(p2_row)
            p2_row_missing["assessment"].pop("validated_status", None)
            (tdir_pre / "assessments.jsonl").write_text(json.dumps(p2_row_missing) + "\n", encoding="utf-8")
            p2_rep = verify_http_capture.verify_run_http_captures(tdir_pre, require_live_chat=False)
            self.assertEqual(p2_rep["capture_status"], "FAILED")
            self.assertFalse(p2_rep["artifact_integrity_ok"])
            p2_mixed = jobs._verify_mixed_http_captures(tdir_pre, [p2_row_missing])
            self.assertEqual(p2_mixed["capture_status"], "MIXED_CACHE_AND_LIVE_HTTP_FAILED")
            self.assertFalse(p2_mixed["capture_integrity_ok"])

            # 3) Unified Integration Gate enforcement: pre-gate SUPPORTED on ExternalUtil.transform MUST fail both verifier and jobs.py,
            # while gate-applied UNDETERMINED on the exact same raw HTTP response passes both!
            j_helper = (
                "public class HelperSql {\n"
                "  void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement st) throws Exception {\n"
                '    String input = req.getParameter("u");\n'
                "    String clean = ExternalUtil.transform(input);\n"
                '    st.executeQuery("SELECT * FROM t WHERE u=" + clean);\n'
                "  }\n"
                "}\n"
            )
            h_src_dir = root / "unified_gate_jobs_src"
            h_src_dir.mkdir()
            (h_src_dir / "HelperSql.java").write_bytes(j_helper.encode("utf-8"))
            h_lke = j_helper.splitlines(keepends=True)
            h_ls = j_helper.splitlines()
            h_pt = lambda ln, col: {"line": ln, "col": col, "offset": sum(len(x.encode("utf-8")) for x in h_lke[: ln - 1]) + col - 1}
            h_loc = lambda ln, txt: {"path": "HelperSql.java", "start": h_pt(ln, h_ls[ln - 1].index(txt) + 1), "end": h_pt(ln, h_ls[ln - 1].index(txt) + 1 + len(txt.encode("utf-8")))}
            h_sink = 'st.executeQuery("SELECT * FROM t WHERE u=" + clean)'
            h_raw_scan = {
                "results": [{
                    "check_id": "test.cwe89", "path": "HelperSql.java",
                    "start": h_loc(5, h_sink)["start"], "end": h_loc(5, h_sink)["end"],
                    "extra": {
                        "severity": "ERROR", "metadata": {"cwe": ["CWE-89"]}, "message": "SQLi",
                        "dataflow_trace": {
                            "taint_source": ["CliLoc", [h_loc(3, 'req.getParameter("u")'), 'req.getParameter("u")']],
                            "intermediate_vars": [],
                            "taint_sink": ["CliLoc", [h_loc(5, h_sink), h_sink]],
                        },
                    },
                }], "errors": [],
            }
            hb = collect(
                json.dumps(h_raw_scan),
                h_src_dir,
                engine_exit=0,
                scan_provenance={"origin": "UNIT_TEST_MOCK_CAPTURE", "producer": "UNIT_TEST_MOCK_CAPTURE", "source_capture_verified": True},
            )
            hb["prompt_contract"] = "blind"
            hrec = hb["records"][0]
            hrec["prompt_contract"] = "blind"
            hsha = hrec["snapshots"]["HelperSql.java"]["sha256"]
            hbody = json.dumps({
                "model": "qwen3.5:9b-q4_K_M",
                "mock_test_fixture": True,
                "done": True, "done_reason": "stop", "eval_count": 18, "eval_duration": 100000,
                "message": {"role": "assistant", "content": json.dumps({
                    "status": "SUPPORTED",
                    "explanation": "Input passes through ExternalUtil.transform.",
                    "fix_suggestion": "Use PreparedStatement.",
                    "citations": [{"path": "HelperSql.java", "start_line": 5, "end_line": 5, "quote": h_ls[4], "sha256": hsha}],
                })},
            }).encode("utf-8")

            class _SupH(BaseHTTPRequestHandler):
                def log_message(self, *args):
                    pass

                def do_POST(self):
                    n = int(self.headers.get("Content-Length", "0"))
                    if n:
                        self.rfile.read(n)
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(hbody)))
                    self.end_headers()
                    self.wfile.write(hbody)

            srv_h = ThreadingHTTPServer(("127.0.0.1", 0), _SupH)
            th_h = threading.Thread(target=srv_h.serve_forever, daemon=True)
            th_h.start()
            try:
                tdir_pre_gate = root / "unified_jobs_pre_gate"
                tdir_pre_gate.mkdir()
                cl_h = ollama.OllamaClient(
                    endpoint=f"http://127.0.0.1:{srv_h.server_port}",
                    model="qwen3.5:9b-q4_K_M", timeout=5, runtime_origin="mock",
                    io_log_dir=tdir_pre_gate / "llm_io", capture_root=tdir_pre_gate,
                )
                raw_sup = cl_h.analyze(hrec)
            finally:
                srv_h.shutdown()
                srv_h.server_close()
                th_h.join(timeout=2)

            self.assertEqual(raw_sup["validated_status"], "SUPPORTED")
            gated_sup = apply_integration_gate(hrec, raw_sup)
            self.assertEqual(gated_sup["validated_status"], "UNDETERMINED")
            self.assertEqual(gated_sup["failure_kind"], "UNVERIFIED_HELPER_FLOW")

            (tdir_pre_gate / "evidence.json").write_text(json.dumps(hb, indent=2), encoding="utf-8")
            pre_gate_row = {
                "id": hrec["id"], "state": "OPEN", "human_review_state": "OPEN",
                "raw_model_status": raw_sup.get("raw_model_status"),
                "validated_status": raw_sup.get("validated_status"),
                "evidence": hrec, "assessment": raw_sup,
            }
            (tdir_pre_gate / "assessments.jsonl").write_text(json.dumps(pre_gate_row) + "\n", encoding="utf-8")
            pre_ver = verify_http_capture.verify_run_http_captures(tdir_pre_gate, require_live_chat=False)
            self.assertEqual(pre_ver["capture_status"], "FAILED")
            self.assertFalse(pre_ver["artifact_integrity_ok"])
            self.assertEqual(pre_ver["findings"][0]["integration_gate_verification"], "FAILED_RECOMPUTATION_MISMATCH")
            pre_mixed = jobs._verify_mixed_http_captures(tdir_pre_gate, [pre_gate_row])
            self.assertEqual(pre_mixed["capture_status"], "MIXED_CACHE_AND_LIVE_HTTP_FAILED")
            self.assertFalse(pre_mixed["capture_integrity_ok"])

            tdir_post_gate = root / "unified_jobs_post_gate"
            shutil.copytree(tdir_pre_gate, tdir_post_gate)
            post_gate_row = {
                "id": hrec["id"], "state": "OPEN", "human_review_state": "OPEN",
                "raw_model_status": gated_sup.get("raw_model_status"),
                "validated_status": gated_sup.get("validated_status"),
                "evidence": hrec, "assessment": gated_sup,
            }
            (tdir_post_gate / "assessments.jsonl").write_text(json.dumps(post_gate_row) + "\n", encoding="utf-8")
            post_ver = verify_http_capture.verify_run_http_captures(tdir_post_gate, require_live_chat=False)
            self.assertEqual(post_ver["capture_status"], "VERIFIED_COMPLETE", post_ver["errors"])
            self.assertTrue(post_ver["artifact_integrity_ok"])
            self.assertEqual(post_ver["findings"][0]["integration_gate_verification"], "RECOMPUTED_EXACT_MATCH")
            post_mixed = jobs._verify_mixed_http_captures(tdir_post_gate, [post_gate_row])
            self.assertEqual(post_mixed["capture_status"], "MIXED_CACHE_AND_LIVE_HTTP_VERIFIED")
            self.assertTrue(post_mixed["capture_integrity_ok"])

            # Coordinated Layer-1 probe_layer1 tamper (Accept -> Forged INVALID_SCHEMA across .response.json + assessments.jsonl)
            # MUST fail verify_http_capture AND propagate through jobs._verify_mixed_http_captures.
            tdir_l1_tamper = root / "layer1_forged_reject_jobs"
            shutil.copytree(clean_dir, tdir_l1_tamper)
            fid_c = rec["id"]
            rp_c = tdir_l1_tamper / "llm_io" / f"{fid_c}.response.json"
            rdoc_c = json.loads(rp_c.read_text(encoding="utf-8"))
            fake_l1_err = "model response fields do not match schema"
            rdoc_c["error"] = fake_l1_err
            rdoc_c["runtime"]["answer_validated"] = False
            rdoc_c["runtime"]["failure_kind"] = "INVALID_SCHEMA"
            rp_c.write_text(json.dumps(rdoc_c, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            aj_c = tdir_l1_tamper / "assessments.jsonl"
            row_c = json.loads(aj_c.read_text(encoding="utf-8").strip())
            row_c["validated_status"] = "UNDETERMINED"
            ass_c = row_c["assessment"]
            ass_c["status"] = "UNDETERMINED"
            ass_c["validated_status"] = "UNDETERMINED"
            ass_c["validator_downgraded"] = True
            ass_c["failure_kind"] = "INVALID_SCHEMA"
            ass_c["explanation"] = fake_l1_err
            ass_c["fix_suggestion"] = ""
            ass_c["citations"] = []
            ass_c["citation_check"] = "NOT_VERIFIED"
            ass_c["runtime"]["answer_validated"] = False
            ass_c["runtime"]["failure_kind"] = "INVALID_SCHEMA"
            aj_c.write_text(json.dumps(row_c, ensure_ascii=False) + "\n", encoding="utf-8")

            l1_ver = verify_http_capture.verify_run_http_captures(tdir_l1_tamper, require_live_chat=False)
            self.assertEqual(l1_ver["capture_status"], "FAILED")
            self.assertFalse(l1_ver["artifact_integrity_ok"])
            self.assertEqual(l1_ver["findings"][0]["layer1_verification"], "FAILED_LAYER1_MISMATCH")
            self.assertNotEqual(l1_ver["findings"][0]["integration_gate_verification"], "RECOMPUTED_EXACT_MATCH")
            l1_mixed = jobs._verify_mixed_http_captures(tdir_l1_tamper, [row_c])
            self.assertEqual(l1_mixed["capture_status"], "MIXED_CACHE_AND_LIVE_HTTP_FAILED")
            self.assertFalse(l1_mixed["capture_integrity_ok"])
            self.assertFalse(l1_mixed["live_chat_verified"])


if __name__ == "__main__":
    unittest.main()
