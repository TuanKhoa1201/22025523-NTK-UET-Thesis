"""Adversarial regression suite for FA-P1-HTTP-01: HTTP capture metadata binding & live-chat provenance.

All tests are strictly offline (zero real Ollama/Qwen calls, zero OpenGrep subprocesses).
Covers the 12 mandatory counterexample categories plus sibling root-cause invariants:
1. Tampering prompt_contract in .response.json.runtime / assessment.runtime / receipt / prompt.json.
2. Tampering http_status in .response.json.runtime / receipt / bool-vs-int type confusion.
3. Tampering origin in .response.json.runtime / assessment.runtime / receipt / mock_test_fixture contradiction.
4. Tampering .response.json error & http_error_body fields (and illegal post-gate upgrade vs legal downgrade).
5. Missing required v2.2.6 metadata fields across assessment, assessment.runtime, receipt, prompt.json, response.json.
6. Null, empty, wrong-type, nested-bad-type, and duplicate-key metadata across all JSON artifacts.
7. Cross-artifact contradictions (assessment vs sidecar vs receipt vs evidence.json vs row.evidence).
8. Offline synthetic fixture with require_live_chat=True (must never receive live_chat_verified=True).
9. Live-shaped capture missing individual required live provenance elements (tags probe, ollama-tags-check, digest,
   scan_provenance, transport_entered, timestamps, eval counters, created_at).
10. Attempts to bypass v2.2.6 strictness via historical prompt_version spoofing or M2 minimal branch.
11. Valid positive controls: offline mock OllamaClient capture, full live-provenance v2.2.6 capture, and M2 minimal row.
12. Academic boundary guards: independently_verified_model_runtime and security_conclusion_verified never elevated.
"""
from __future__ import annotations

import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import tempfile
import threading
import unittest
from unittest.mock import patch

from v2.triage import live_check, ollama, verify_http_capture
from v2.triage.evidence import collect, digest
from v2.triage.ollama import OllamaClient, PROMPT_SERIALIZER_FINGERPRINTS, PROMPT_VERSION
from v2.triage.runtime import SCHEMA_VERSION


def _build_real_loopback_v226_run(
    root: Path,
    *,
    runtime_origin: str = "unverified",
    include_live_scan_provenance: bool = True,
    include_tags_probe: bool = True,
    include_ollama_created_at: bool = True,
    mock_fixture_flag: bool = False,
) -> tuple[Path, dict, dict]:
    """Run real OllamaClient against an in-process loopback HTTP server to emit genuine v2.2.6 artifacts."""
    src_root = root / "src"
    src_root.mkdir(parents=True, exist_ok=True)
    java_text = (
        "public class DemoSql {\n"
        "  void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt) throws Exception {\n"
        '    String input = req.getParameter("u");\n'
        '    stmt.executeQuery("SELECT * FROM users WHERE u=" + input);\n'
        "  }\n"
        "}\n"
    )
    java_path = src_root / "DemoSql.java"
    java_path.write_bytes(java_text.encode("utf-8"))
    lines_ke = java_text.splitlines(keepends=True)
    lines = java_text.splitlines()

    def pt(ln: int, col: int) -> dict[str, int]:
        return {"line": ln, "col": col, "offset": sum(len(x.encode("utf-8")) for x in lines_ke[: ln - 1]) + col - 1}

    def loc(ln: int, txt: str) -> dict:
        c = lines[ln - 1].index(txt) + 1
        return {"path": "DemoSql.java", "start": pt(ln, c), "end": pt(ln, c + len(txt.encode("utf-8")))}

    raw_scan = {
        "results": [
            {
                "check_id": "test.cwe89",
                "path": "DemoSql.java",
                "start": pt(4, 5),
                "end": pt(4, 63),
                "extra": {
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-89"]},
                    "message": "SQLi",
                    "dataflow_trace": {
                        "taint_source": ["CliLoc", [loc(3, 'req.getParameter("u")'), 'req.getParameter("u")']],
                        "intermediate_vars": [],
                        "taint_sink": ["CliLoc", [loc(4, 'stmt.executeQuery("SELECT * FROM users WHERE u=" + input)'), 'stmt.executeQuery("SELECT * FROM users WHERE u=" + input)']],
                    },
                },
            }
        ],
        "errors": [],
    }
    if include_live_scan_provenance:
        scan_prov = {
            "origin": "recorded_capture_unsigned",
            "producer": "ntk-local-scan-capture",
            "source_capture_verified": True,
            "exit_capture_verified": True,
            "recorded_engine_exit": 0,
            "declared_engine_exit": None,
            "independently_attested": False,
            "manifest_path": "capture/scan-manifest.json",
            "manifest_sha256": "a" * 64,
        }
    else:
        scan_prov = {"origin": "UNIT_TEST_MOCK_CAPTURE", "producer": "UNIT_TEST_MOCK_CAPTURE", "source_capture_verified": True}

    bundle = collect(json.dumps(raw_scan), src_root, engine_exit=0, scan_provenance=scan_prov)
    bundle["prompt_contract"] = "blind"
    rec = bundle["records"][0]
    rec["prompt_contract"] = "blind"
    snap_sha = rec["snapshots"]["DemoSql.java"]["sha256"]
    model = "qwen3.5:9b-q4_K_M"
    model_digest = "56671c2ab9385f9cfcb404638e32cd62d88e3501d44822208363c010179a3c90"

    model_answer = json.dumps(
        {
            "explanation": "Biến input lấy từ request.getParameter và nối trực tiếp vào câu lệnh SQL.",
            "citations": [
                {
                    "path": "DemoSql.java",
                    "start_line": 4,
                    "end_line": 4,
                    "quote": lines[3],
                    "sha256": snap_sha,
                }
            ],
            "status": "SUPPORTED",
            "fix_suggestion": "Sử dụng PreparedStatement với tham số ?.",
        },
        ensure_ascii=False,
    )
    chat_resp_obj: dict = {
        "model": model,
        "message": {"role": "assistant", "content": model_answer},
        "done": True,
        "done_reason": "stop",
        "eval_count": 32,
        "eval_duration": 150000000,
    }
    if include_ollama_created_at:
        chat_resp_obj["created_at"] = "2026-11-25T14:00:00.123456Z"
    if mock_fixture_flag:
        chat_resp_obj["mock_test_fixture"] = True

    chat_bytes = json.dumps(chat_resp_obj, ensure_ascii=False).encode("utf-8")
    tags_bytes = json.dumps(
        {"models": [{"name": model, "model": model, "digest": model_digest, "size": 6550825550}]},
        ensure_ascii=False,
    ).encode("utf-8")

    class _LoopbackHandler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            self.send_response(200, "OK")
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(tags_bytes)))
            self.end_headers()
            self.wfile.write(tags_bytes)

        def do_POST(self):
            n = int(self.headers.get("Content-Length", "0"))
            if n:
                self.rfile.read(n)
            self.send_response(200, "OK")
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(chat_bytes)))
            self.end_headers()
            self.wfile.write(chat_bytes)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _LoopbackHandler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        triage_dir = root / "triage"
        triage_dir.mkdir(parents=True, exist_ok=True)
        client = OllamaClient(
            endpoint=f"http://127.0.0.1:{srv.server_port}",
            model=model,
            timeout=10,
            runtime_origin=runtime_origin,
            io_log_dir=triage_dir / "llm_io",
            capture_root=triage_dir,
        )
        if include_tags_probe:
            inv = client.verify_model_installed()
            (triage_dir / "ollama-tags-check.json").write_text(json.dumps(inv, indent=2), encoding="utf-8")
        assessment = client.analyze(rec)
    finally:
        srv.shutdown()
        srv.server_close()
        th.join(timeout=2)

    (triage_dir / "evidence.json").write_text(json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8")
    row = {
        "schema_version": SCHEMA_VERSION,
        "id": rec["id"],
        "alert_id": rec["alert_id"],
        "scan_sha256": rec["scan_sha256"],
        "finding_index": rec["finding_index"],
        "state": "OPEN",
        "human_review_state": "OPEN",
        "raw_model_status": assessment.get("raw_model_status"),
        "validated_status": assessment.get("validated_status"),
        "evidence": rec,
        "assessment": assessment,
    }
    (triage_dir / "assessments.jsonl").write_text(json.dumps(row, ensure_ascii=False) + "\n", encoding="utf-8")
    return triage_dir, rec, row


class FaP1Http01MetadataBindingTests(unittest.TestCase):
    def test_01_valid_v226_live_shape_control_and_writer_metadata_emission(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            triage_dir, rec, row = _build_real_loopback_v226_run(Path(td) / "live_ok", runtime_origin="unverified")
            fid = rec["id"]
            # Confirm OllamaClient writer emits prompt_contract in runtime AND 5 binding keys in receipt
            self.assertEqual(row["assessment"]["runtime"]["prompt_contract"], "blind")
            rcp = json.loads((triage_dir / "llm_io" / f"{fid}.http-capture.json").read_text(encoding="utf-8"))
            self.assertEqual(rcp["runtime_origin"], "unverified")
            self.assertEqual(rcp["prompt_version"], PROMPT_VERSION)
            self.assertEqual(rcp["prompt_contract"], "blind")
            self.assertEqual(rcp["prompt_sha256"], row["assessment"]["prompt_sha256"])
            self.assertEqual(rcp["serializer_fingerprint"], PROMPT_SERIALIZER_FINGERPRINTS[PROMPT_VERSION])

            # Normal capture-integrity mode: valid capture bytes/metadata & endpoint-reported protocol shape,
            # but offline inspection MUST NEVER grant live_chat_verified=True / live_origin_verified=True!
            rep_f = verify_http_capture.verify_run_http_captures(triage_dir, require_live_chat=False)
            self.assertEqual(rep_f["capture_status"], "VERIFIED_COMPLETE", rep_f["errors"])
            self.assertTrue(rep_f["capture_integrity_ok"], rep_f["errors"])
            self.assertTrue(rep_f["artifact_integrity_ok"], rep_f["errors"])
            self.assertTrue(rep_f["endpoint_reported_protocol_ok"], rep_f)
            self.assertFalse(rep_f["live_chat_verified"], rep_f)
            self.assertFalse(rep_f["live_origin_verified"], rep_f)
            self.assertEqual(rep_f["live_origin_trust_status"], "UNVERIFIED_OFFLINE_NO_TRUSTED_EXTERNAL_PROVENANCE")
            self.assertEqual(rep_f["live_non_mock_complete_captures"], 0)
            self.assertEqual(rep_f["endpoint_reported_non_mock_complete_captures"], 1)
            self.assertFalse(rep_f["independently_verified_model_runtime"])
            self.assertFalse(rep_f["security_conclusion_verified"])
            self.assertEqual(rep_f["findings"][0]["prompt_metadata_binding"], "VERIFIED_EXPLICIT")
            self.assertTrue(rep_f["findings"][0]["artifact_integrity_ok"])
            self.assertTrue(rep_f["findings"][0]["endpoint_reported_protocol_ok"])
            self.assertFalse(rep_f["findings"][0]["live_provenance_ok"])

            # Strict live mode: MUST fail closed for loopback fixture lacking trusted external runtime provenance
            rep_t = verify_http_capture.verify_run_http_captures(triage_dir, require_live_chat=True)
            self.assertEqual(rep_t["capture_status"], "FAILED", rep_t)
            self.assertFalse(rep_t["capture_integrity_ok"], rep_t)
            self.assertTrue(rep_t["artifact_integrity_ok"], rep_t)
            self.assertTrue(rep_t["endpoint_reported_protocol_ok"], rep_t)
            self.assertFalse(rep_t["live_chat_verified"], rep_t)
            self.assertFalse(rep_t["live_origin_verified"], rep_t)
            self.assertFalse(rep_t["independently_verified_model_runtime"])
            self.assertFalse(rep_t["security_conclusion_verified"])
            self.assertTrue(any("UNVERIFIED_LIVE_RUNTIME_ORIGIN" in e for e in rep_t["errors"]), rep_t["errors"])

            lc = live_check.inspect([row], minimum=1, require_prompt_metadata=True)
            self.assertEqual(lc["protocol_status"], "OLLAMA_REPORTED_UNATTESTED")
            self.assertEqual(lc["warnings"][0]["protocol_metadata_mode"], "EXPLICIT_PROMPT_METADATA_BOUND")
            self.assertFalse(lc["live_origin_verified"])
            self.assertFalse(lc["independently_verified_model_runtime"])
            self.assertFalse(lc["security_conclusion_verified"])

    def test_02_original_fa_p1_http_01_and_sibling_tamper_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            base_dir, rec, _ = _build_real_loopback_v226_run(root / "base", runtime_origin="unverified")
            fid = rec["id"]

            def _raw_hashes(d: Path) -> dict[str, str]:
                return {p.name: digest(p.read_bytes()) for p in sorted((d / "llm_io").glob("*.bin"))}

            orig_raw = _raw_hashes(base_dir)

            def _mutate_and_verify(label: str, fn):
                out = root / f"case_{label}"
                shutil.copytree(base_dir, out)
                fn(out)
                # Raw HTTP body bytes remain untouched in every metadata tamper test!
                self.assertEqual(_raw_hashes(out), orig_raw, label)
                rep_f = verify_http_capture.verify_run_http_captures(out, require_live_chat=False)
                rep_t = verify_http_capture.verify_run_http_captures(out, require_live_chat=True)
                self.assertEqual(rep_f["capture_status"], "FAILED", f"{label} non-strict unexpectedly passed: {rep_f}")
                self.assertFalse(rep_f["capture_integrity_ok"], label)
                self.assertFalse(rep_f["live_chat_verified"], label)
                self.assertFalse(rep_f["findings"][0]["verified"], label)
                self.assertEqual(rep_t["capture_status"], "FAILED", label)
                self.assertFalse(rep_t["live_chat_verified"], label)
                self.assertFalse(rep_t["independently_verified_model_runtime"], label)
                self.assertFalse(rep_t["security_conclusion_verified"], label)
                return rep_f

            def _edit_json(path: Path, fn):
                doc = json.loads(path.read_text(encoding="utf-8"))
                fn(doc)
                path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

            def _edit_row(d: Path, fn):
                p = d / "assessments.jsonl"
                row = json.loads(p.read_text(encoding="utf-8").strip())
                fn(row)
                p.write_text(json.dumps(row, ensure_ascii=False) + "\n", encoding="utf-8")

            # 1-4: Exact FA-P1-HTTP-01 cases on .response.json
            r1 = _mutate_and_verify("resp_rt_contract", lambda d: _edit_json(d / "llm_io" / f"{fid}.response.json", lambda x: x["runtime"].__setitem__("prompt_contract", "neutral_hints")))
            self.assertEqual(r1["findings"][0]["prompt_metadata_binding"], "FAILED")
            r2 = _mutate_and_verify("resp_rt_http_status", lambda d: _edit_json(d / "llm_io" / f"{fid}.response.json", lambda x: x["runtime"].__setitem__("http_status", 503)))
            self.assertEqual(r2["findings"][0]["prompt_metadata_binding"], "FAILED")
            r3 = _mutate_and_verify("resp_rt_origin", lambda d: _edit_json(d / "llm_io" / f"{fid}.response.json", lambda x: x["runtime"].__setitem__("origin", "forged")))
            self.assertEqual(r3["findings"][0]["prompt_metadata_binding"], "FAILED")
            r4 = _mutate_and_verify("resp_error_forged", lambda d: _edit_json(d / "llm_io" / f"{fid}.response.json", lambda x: x.__setitem__("error", "forged")))
            self.assertEqual(r4["findings"][0]["prompt_metadata_binding"], "FAILED")

            # 5: Missing assessment.runtime.prompt_contract (and also missing in BOTH assessment.runtime & response.json.runtime!)
            _mutate_and_verify("ass_rt_contract_missing", lambda d: _edit_row(d, lambda r: r["assessment"]["runtime"].pop("prompt_contract", None)))
            def _strip_both_rt_contract(d: Path):
                _edit_row(d, lambda r: r["assessment"]["runtime"].pop("prompt_contract", None))
                _edit_json(d / "llm_io" / f"{fid}.response.json", lambda x: x["runtime"].pop("prompt_contract", None))
            _mutate_and_verify("both_rt_contract_missing", _strip_both_rt_contract)

            # 6: Receipt tampering (path, requested_model, missing required v2.2.6 receipt keys, tampered runtime_origin)
            rp_path = _mutate_and_verify("receipt_path", lambda d: _edit_json(d / "llm_io" / f"{fid}.http-capture.json", lambda x: x.__setitem__("path", "/api/not-chat")))
            self.assertEqual(rp_path["findings"][0]["prompt_metadata_binding"], "FAILED")
            rp_mdl = _mutate_and_verify("receipt_model", lambda d: _edit_json(d / "llm_io" / f"{fid}.http-capture.json", lambda x: x.__setitem__("requested_model", "other:9b")))
            self.assertEqual(rp_mdl["findings"][0]["prompt_metadata_binding"], "FAILED")
            for req_key in ("runtime_origin", "prompt_version", "prompt_contract", "prompt_sha256", "serializer_fingerprint"):
                _mutate_and_verify(f"receipt_missing_{req_key}", lambda d, k=req_key: _edit_json(d / "llm_io" / f"{fid}.http-capture.json", lambda x: x.pop(k, None)))
            _mutate_and_verify("receipt_origin_mock", lambda d: _edit_json(d / "llm_io" / f"{fid}.http-capture.json", lambda x: x.__setitem__("runtime_origin", "mock")))

            # 7: Sibling .response.json tampering (missing model/endpoint/runtime/error, extra runtime key, http_error_body on HTTP 200, wrong type)
            for req_skey in ("model", "endpoint", "runtime", "error", "raw_response"):
                _mutate_and_verify(f"resp_missing_{req_skey}", lambda d, k=req_skey: _edit_json(d / "llm_io" / f"{fid}.response.json", lambda x: x.pop(k, None)))
            _mutate_and_verify("resp_http_error_body_on_200", lambda d: _edit_json(d / "llm_io" / f"{fid}.response.json", lambda x: x.__setitem__("http_error_body", "err")))
            _mutate_and_verify("resp_rt_extra_key", lambda d: _edit_json(d / "llm_io" / f"{fid}.response.json", lambda x: x["runtime"].__setitem__("injected", True)))
            _mutate_and_verify("resp_rt_del_bytes", lambda d: _edit_json(d / "llm_io" / f"{fid}.response.json", lambda x: x["runtime"].pop("response_body_bytes", None)))
            _mutate_and_verify("resp_error_empty_str", lambda d: _edit_json(d / "llm_io" / f"{fid}.response.json", lambda x: x.__setitem__("error", "")))
            _mutate_and_verify("resp_error_list", lambda d: _edit_json(d / "llm_io" / f"{fid}.response.json", lambda x: x.__setitem__("error", ["err"])))

            # 8: Forged origin simultaneously across assessment, sidecar, and receipt -> STILL FAILS (not in allowed enum)
            def _forged_origin_everywhere(d: Path):
                _edit_row(d, lambda r: r["assessment"]["runtime"].__setitem__("origin", "forged"))
                _edit_json(d / "llm_io" / f"{fid}.response.json", lambda x: x["runtime"].__setitem__("origin", "forged"))
                _edit_json(d / "llm_io" / f"{fid}.http-capture.json", lambda x: x.__setitem__("runtime_origin", "forged"))
            _mutate_and_verify("origin_forged_everywhere", _forged_origin_everywhere)

            # 9: Bool-vs-int type confusion (http_status=True, finding_index=False) and null/wrong-type metadata
            def _bool_http_status(d: Path):
                _edit_row(d, lambda r: r["assessment"]["runtime"].__setitem__("http_status", True))
                _edit_json(d / "llm_io" / f"{fid}.response.json", lambda x: x["runtime"].__setitem__("http_status", True))
                _edit_json(d / "llm_io" / f"{fid}.http-capture.json", lambda x: x.__setitem__("http_status", True))
            _mutate_and_verify("bool_http_status", _bool_http_status)
            _mutate_and_verify("bool_finding_index", lambda d: _edit_json(d / "llm_io" / f"{fid}.http-capture.json", lambda x: x.__setitem__("finding_index", False)))
            _mutate_and_verify("null_runtime_contract", lambda d: _edit_row(d, lambda r: r["assessment"]["runtime"].__setitem__("prompt_contract", None)))

            # 10: Duplicate JSON key in .response.json and .http-capture.json
            def _dup_key_resp(d: Path):
                p = d / "llm_io" / f"{fid}.response.json"
                raw = p.read_text(encoding="utf-8")
                p.write_text(raw.replace('"error": null', '"error": null, "error": null', 1), encoding="utf-8")
            _mutate_and_verify("dup_key_response_json", _dup_key_resp)

            # 11: Academic boundary flag tampering (security_conclusion_verified=True or model_runtime_verified=True)
            _mutate_and_verify("security_verified_true", lambda d: _edit_row(d, lambda r: r["assessment"].__setitem__("security_conclusion_verified", True)))
            def _model_rt_verified_true(d: Path):
                _edit_row(d, lambda r: r["assessment"]["runtime"].__setitem__("model_runtime_verified", True))
                _edit_json(d / "llm_io" / f"{fid}.response.json", lambda x: x["runtime"].__setitem__("model_runtime_verified", True))
            _mutate_and_verify("model_runtime_verified_true", _model_rt_verified_true)

            # 12: Split row.evidence vs evidence.json
            _mutate_and_verify("split_row_evidence", lambda d: _edit_row(d, lambda r: r["evidence"].__setitem__("prompt_contract", "neutral_hints")))

            # 13: Illegal post-gate UPGRADE (sidecar answer_validated=False -> assessment answer_validated=True)
            _mutate_and_verify("illegal_post_gate_upgrade", lambda d: _edit_json(d / "llm_io" / f"{fid}.response.json", lambda x: x["runtime"].__setitem__("answer_validated", False)))

            # 14: Spoofing historical prompt_version to bypass v2.2.6 required fields
            def _spoof_v225(d: Path):
                _edit_row(d, lambda r: (
                    r["assessment"].__setitem__("prompt_version", ollama.PREVIOUS_V225_PROMPT_VERSION),
                    r["assessment"].pop("serializer_fingerprint", None),
                    r["assessment"]["runtime"].pop("prompt_version", None),
                    r["assessment"]["runtime"].pop("prompt_contract", None),
                    r["assessment"]["runtime"].pop("serializer_fingerprint", None),
                ))
                _edit_json(d / "llm_io" / f"{fid}.prompt.json", lambda x: (
                    x.__setitem__("prompt_version", ollama.PREVIOUS_V225_PROMPT_VERSION),
                    x.pop("serializer_fingerprint", None),
                ))
                _edit_json(d / "llm_io" / f"{fid}.response.json", lambda x: (
                    x["runtime"].pop("prompt_version", None),
                    x["runtime"].pop("prompt_contract", None),
                    x["runtime"].pop("serializer_fingerprint", None),
                ))
                _edit_json(d / "llm_io" / f"{fid}.http-capture.json", lambda x: (
                    x.pop("prompt_version", None),
                    x.pop("prompt_contract", None),
                    x.pop("prompt_sha256", None),
                    x.pop("serializer_fingerprint", None),
                    x.pop("runtime_origin", None),
                ))
            _mutate_and_verify("spoof_v225_bypass", _spoof_v225)

    def test_03_legal_post_gate_downgrade_remains_verified(self) -> None:
        from v2.api.triage_gate import apply_integration_gate

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            # 1. Legitimate apply_integration_gate Gate-1 downgrade on Java source with unverified external helper
            src_root = root / "helper_run" / "src"
            src_root.mkdir(parents=True, exist_ok=True)
            java_text = (
                "public class HelperSql {\n"
                "  void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt) throws Exception {\n"
                '    String input = req.getParameter("u");\n'
                "    String clean = ExternalUtil.transform(input);\n"
                '    stmt.executeQuery("SELECT * FROM users WHERE u=" + clean);\n'
                "  }\n"
                "}\n"
            )
            (src_root / "HelperSql.java").write_bytes(java_text.encode("utf-8"))
            lke = java_text.splitlines(keepends=True)
            ls = java_text.splitlines()
            pt = lambda ln, col: {"line": ln, "col": col, "offset": sum(len(x.encode("utf-8")) for x in lke[: ln - 1]) + col - 1}
            loc = lambda ln, txt: {"path": "HelperSql.java", "start": pt(ln, ls[ln - 1].index(txt) + 1), "end": pt(ln, ls[ln - 1].index(txt) + 1 + len(txt.encode("utf-8")))}
            raw_scan = {
                "results": [
                    {
                        "check_id": "test.cwe89",
                        "path": "HelperSql.java",
                        "start": loc(5, 'stmt.executeQuery("SELECT * FROM users WHERE u=" + clean)')["start"],
                        "end": loc(5, 'stmt.executeQuery("SELECT * FROM users WHERE u=" + clean)')["end"],
                        "extra": {
                            "severity": "ERROR",
                            "metadata": {"cwe": ["CWE-89"]},
                            "message": "SQLi",
                            "dataflow_trace": {
                                "taint_source": ["CliLoc", [loc(3, 'req.getParameter("u")'), 'req.getParameter("u")']],
                                "intermediate_vars": [],
                                "taint_sink": ["CliLoc", [loc(5, 'stmt.executeQuery("SELECT * FROM users WHERE u=" + clean)'), 'stmt.executeQuery("SELECT * FROM users WHERE u=" + clean)']],
                            },
                        },
                    }
                ],
                "errors": [],
            }
            scan_prov = {
                "origin": "recorded_capture_unsigned",
                "producer": "ntk-local-scan-capture",
                "source_capture_verified": True,
                "exit_capture_verified": True,
                "recorded_engine_exit": 0,
                "declared_engine_exit": None,
                "independently_attested": False,
                "manifest_path": "capture/scan-manifest.json",
                "manifest_sha256": "a" * 64,
            }
            bundle = collect(json.dumps(raw_scan), src_root, engine_exit=0, scan_provenance=scan_prov)
            bundle["prompt_contract"] = "blind"
            rec = bundle["records"][0]
            rec["prompt_contract"] = "blind"
            snap_sha = rec["snapshots"]["HelperSql.java"]["sha256"]
            model = "qwen3.5:9b-q4_K_M"
            model_digest = "56671c2ab9385f9cfcb404638e32cd62d88e3501d44822208363c010179a3c90"
            chat_bytes = json.dumps(
                {
                    "model": model,
                    "created_at": "2026-11-26T05:00:00.000000Z",
                    "message": {
                        "role": "assistant",
                        "content": json.dumps(
                            {
                                "explanation": "Input flows through ExternalUtil.transform into SQL query.",
                                "citations": [{"path": "HelperSql.java", "start_line": 5, "end_line": 5, "quote": ls[4], "sha256": snap_sha}],
                                "status": "SUPPORTED",
                                "fix_suggestion": "Use PreparedStatement.",
                            },
                            ensure_ascii=False,
                        ),
                    },
                    "done": True,
                    "done_reason": "stop",
                    "eval_count": 30,
                    "eval_duration": 140000000,
                },
                ensure_ascii=False,
            ).encode("utf-8")
            tags_bytes = json.dumps({"models": [{"name": model, "model": model, "digest": model_digest, "size": 6550825550}]}).encode("utf-8")

            class _H(BaseHTTPRequestHandler):
                def log_message(self, *args):
                    pass

                def do_GET(self):
                    self.send_response(200, "OK")
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(tags_bytes)))
                    self.end_headers()
                    self.wfile.write(tags_bytes)

                def do_POST(self):
                    n = int(self.headers.get("Content-Length", "0"))
                    if n:
                        self.rfile.read(n)
                    self.send_response(200, "OK")
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(chat_bytes)))
                    self.end_headers()
                    self.wfile.write(chat_bytes)

            srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
            th = threading.Thread(target=srv.serve_forever, daemon=True)
            th.start()
            try:
                triage_dir = root / "helper_run" / "triage"
                triage_dir.mkdir(parents=True, exist_ok=True)
                client = OllamaClient(
                    endpoint=f"http://127.0.0.1:{srv.server_port}",
                    model=model,
                    timeout=10,
                    runtime_origin="unverified",
                    io_log_dir=triage_dir / "llm_io",
                    capture_root=triage_dir,
                )
                inv = client.verify_model_installed()
                (triage_dir / "ollama-tags-check.json").write_text(json.dumps(inv, indent=2), encoding="utf-8")
                raw_ass = client.analyze(rec)
            finally:
                srv.shutdown()
                srv.server_close()
                th.join(timeout=2)

            gated = apply_integration_gate(rec, raw_ass)
            self.assertEqual(gated["validated_status"], "UNDETERMINED")
            self.assertEqual(gated["failure_kind"], "UNVERIFIED_HELPER_FLOW")
            (triage_dir / "evidence.json").write_text(json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8")
            row = {
                "schema_version": SCHEMA_VERSION,
                "id": rec["id"],
                "alert_id": rec["alert_id"],
                "scan_sha256": rec["scan_sha256"],
                "finding_index": rec["finding_index"],
                "state": "OPEN",
                "human_review_state": "OPEN",
                "raw_model_status": gated.get("raw_model_status"),
                "validated_status": gated.get("validated_status"),
                "evidence": rec,
                "assessment": gated,
            }
            (triage_dir / "assessments.jsonl").write_text(json.dumps(row, ensure_ascii=False) + "\n", encoding="utf-8")

            rep_f = verify_http_capture.verify_run_http_captures(triage_dir, require_live_chat=False)
            self.assertEqual(rep_f["capture_status"], "VERIFIED_COMPLETE", rep_f["errors"])
            self.assertTrue(rep_f["capture_integrity_ok"], rep_f["errors"])
            self.assertTrue(rep_f["artifact_integrity_ok"], rep_f["errors"])
            self.assertTrue(rep_f["endpoint_reported_protocol_ok"], rep_f)
            self.assertEqual(rep_f["findings"][0]["post_gate_downgrade_verification"], "RECOMPUTED_EXACT_MATCH")
            self.assertFalse(rep_f["live_chat_verified"], rep_f)
            self.assertFalse(rep_f["live_origin_verified"], rep_f)

            rep_t = verify_http_capture.verify_run_http_captures(triage_dir, require_live_chat=True)
            self.assertEqual(rep_t["capture_status"], "FAILED", rep_t)
            self.assertTrue(rep_t["artifact_integrity_ok"], rep_t)
            self.assertFalse(rep_t["live_chat_verified"], rep_t)
            self.assertTrue(any("UNVERIFIED_LIVE_RUNTIME_ORIGIN" in e for e in rep_t["errors"]), rep_t["errors"])

            # 2. Ungrounded hand-patched downgrade on clean DemoSql (where Gate does NOT downgrade) MUST FAIL CLOSED!
            fake_dir, _, _ = _build_real_loopback_v226_run(root / "fake_gate_down", runtime_origin="unverified")
            fp = fake_dir / "assessments.jsonl"
            frow = json.loads(fp.read_text(encoding="utf-8").strip())
            frow["validated_status"] = "UNDETERMINED"
            frow["assessment"]["status"] = "UNDETERMINED"
            frow["assessment"]["validated_status"] = "UNDETERMINED"
            frow["assessment"]["validator_downgraded"] = True
            frow["assessment"]["failure_kind"] = "UNVERIFIED_HELPER_FLOW"
            frow["assessment"]["downgrade_reason"] = "Blocked conclusive verdict due to unverified helper flow."
            frow["assessment"]["runtime"]["answer_validated"] = False
            frow["assessment"]["runtime"]["failure_kind"] = "UNVERIFIED_HELPER_FLOW"
            frow["assessment"]["runtime"]["validator_downgraded"] = True
            fp.write_text(json.dumps(frow, ensure_ascii=False) + "\n", encoding="utf-8")
            fake_rep = verify_http_capture.verify_run_http_captures(fake_dir, require_live_chat=False)
            self.assertEqual(fake_rep["capture_status"], "FAILED")
            self.assertFalse(fake_rep["artifact_integrity_ok"])

    def test_04_live_chat_provenance_rejects_offline_mock_and_incomplete_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            # 4a) Mock origin client -> non-strict passes integrity (live_chat_verified=False), strict fails!
            mock_dir, _, _ = _build_real_loopback_v226_run(root / "mock_origin", runtime_origin="mock", mock_fixture_flag=True)
            rep_m_f = verify_http_capture.verify_run_http_captures(mock_dir, require_live_chat=False)
            self.assertEqual(rep_m_f["capture_status"], "VERIFIED_COMPLETE", rep_m_f["errors"])
            self.assertFalse(rep_m_f["live_chat_verified"])
            rep_m_t = verify_http_capture.verify_run_http_captures(mock_dir, require_live_chat=True)
            self.assertEqual(rep_m_t["capture_status"], "FAILED")
            self.assertFalse(rep_m_t["live_chat_verified"])

            # 4b) Missing /api/tags probe -> non-strict passes integrity (live_chat_verified=False), strict fails!
            no_tags_dir, _, _ = _build_real_loopback_v226_run(root / "no_tags", runtime_origin="unverified", include_tags_probe=False)
            self.assertFalse(verify_http_capture.verify_run_http_captures(no_tags_dir, require_live_chat=False)["live_chat_verified"])
            rep_nt = verify_http_capture.verify_run_http_captures(no_tags_dir, require_live_chat=True)
            self.assertEqual(rep_nt["capture_status"], "FAILED")
            self.assertFalse(rep_nt["live_chat_verified"])

            # 4c) UNIT_TEST_MOCK_CAPTURE scan_provenance -> cannot get live_chat_verified=True!
            mock_sp_dir, _, _ = _build_real_loopback_v226_run(root / "mock_sp", runtime_origin="unverified", include_live_scan_provenance=False)
            self.assertFalse(verify_http_capture.verify_run_http_captures(mock_sp_dir, require_live_chat=False)["live_chat_verified"])
            rep_sp = verify_http_capture.verify_run_http_captures(mock_sp_dir, require_live_chat=True)
            self.assertEqual(rep_sp["capture_status"], "FAILED")
            self.assertFalse(rep_sp["live_chat_verified"])

            # 4d) Missing Ollama created_at in raw response -> cannot get live_chat_verified=True!
            no_ts_dir, _, _ = _build_real_loopback_v226_run(root / "no_created_at", runtime_origin="unverified", include_ollama_created_at=False)
            self.assertFalse(verify_http_capture.verify_run_http_captures(no_ts_dir, require_live_chat=False)["live_chat_verified"])
            rep_ts = verify_http_capture.verify_run_http_captures(no_ts_dir, require_live_chat=True)
            self.assertEqual(rep_ts["capture_status"], "FAILED")
            self.assertFalse(rep_ts["live_chat_verified"])

            # 4e) Forged model_digest in ollama-tags-check.json -> fails live_chat_verified!
            bad_dig_dir, _, _ = _build_real_loopback_v226_run(root / "bad_tags_digest", runtime_origin="unverified")
            ot_p = bad_dig_dir / "ollama-tags-check.json"
            ot = json.loads(ot_p.read_text(encoding="utf-8"))
            ot["model_digest"] = "0" * 64
            ot_p.write_text(json.dumps(ot, indent=2), encoding="utf-8")
            self.assertFalse(verify_http_capture.verify_run_http_captures(bad_dig_dir, require_live_chat=False)["live_chat_verified"])
            rep_bd = verify_http_capture.verify_run_http_captures(bad_dig_dir, require_live_chat=True)
            self.assertEqual(rep_bd["capture_status"], "FAILED")
            self.assertFalse(rep_bd["live_chat_verified"])

    def test_05_live_check_rejects_forged_origin_missing_runtime_contract_and_m2_bypass(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            _, rec, row = _build_real_loopback_v226_run(Path(td) / "lc_base", runtime_origin="unverified")

            # Positive control
            ok = live_check.inspect([row], minimum=1, require_prompt_metadata=True)
            self.assertEqual(ok["protocol_status"], "OLLAMA_REPORTED_UNATTESTED")

            # Forged origin fails live_check
            r_org = copy.deepcopy(row)
            r_org["assessment"]["runtime"]["origin"] = "forged"
            self.assertEqual(live_check.inspect([r_org], minimum=1)["protocol_status"], "PENDING")

            # Missing runtime.prompt_contract on v2.2.6 fails live_check
            r_mc = copy.deepcopy(row)
            r_mc["assessment"]["runtime"].pop("prompt_contract", None)
            self.assertEqual(live_check.inspect([r_mc], minimum=1)["protocol_status"], "PENDING")
            self.assertFalse(live_check.inspect([r_mc], minimum=1)["warnings"][0]["request_payload_bound"])

            # Tampered security_conclusion_verified / model_runtime_verified fails live_check
            r_sec = copy.deepcopy(row)
            r_sec["assessment"]["security_conclusion_verified"] = True
            self.assertEqual(live_check.inspect([r_sec], minimum=1)["protocol_status"], "PENDING")
            r_mrv = copy.deepcopy(row)
            r_mrv["assessment"]["runtime"]["model_runtime_verified"] = True
            self.assertEqual(live_check.inspect([r_mrv], minimum=1)["protocol_status"], "PENDING")

            # Mismatched reported_eval_count fails live_check
            r_ev = copy.deepcopy(row)
            r_ev["assessment"]["runtime"]["reported_eval_count"] = 99999
            self.assertEqual(live_check.inspect([r_ev], minimum=1)["protocol_status"], "PENDING")

            # Minimal M2 row still works when require_prompt_metadata=False, blocked when require_prompt_metadata=True
            m2_ev = {k: v for k, v in rec.items() if k != "prompt_contract"}
            req_sha = digest(json.dumps(ollama.request_payload(m2_ev, "qwen3.5:9b-q4_K_M")).encode("utf-8"))
            resp = copy.deepcopy(row["assessment"]["raw_response"])
            m2_row = {
                "id": rec["id"],
                "evidence": m2_ev,
                "assessment": {
                    "status": "UNDETERMINED",
                    "model": "qwen3.5:9b-q4_K_M",
                    "runtime": {
                        "origin": "unverified",
                        "request_attempted": True,
                        "http_response_received": True,
                        "http_status": 200,
                        "finding_id": rec["id"],
                        "request_payload_sha256": req_sha,
                        "response_json_sha256": digest(json.dumps(resp, sort_keys=True, ensure_ascii=False, allow_nan=False).encode("utf-8")),
                    },
                    "raw_response": resp,
                },
            }
            m2_ok = live_check.inspect([m2_row], minimum=1, require_prompt_metadata=False)
            self.assertEqual(m2_ok["protocol_status"], "OLLAMA_REPORTED_UNATTESTED")
            self.assertEqual(m2_ok["warnings"][0]["protocol_metadata_mode"], "MINIMAL_M2_PROTOCOL_NO_PROMPT_METADATA")
            self.assertFalse(m2_ok["independently_verified_model_runtime"])
            m2_strict = live_check.inspect([m2_row], minimum=1, require_prompt_metadata=True)
            self.assertEqual(m2_strict["protocol_status"], "PENDING")

    def test_06_preflight_verdict_binding_bundle_contract_error_and_precheck_invariants(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            base_dir, rec, _ = _build_real_loopback_v226_run(root / "base_v226", runtime_origin="unverified")
            fid = rec["id"]

            def _edit_json(path: Path, fn):
                doc = json.loads(path.read_text(encoding="utf-8"))
                fn(doc)
                path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

            def _edit_row(d: Path, fn):
                p = d / "assessments.jsonl"
                row = json.loads(p.read_text(encoding="utf-8").strip())
                fn(row)
                p.write_text(json.dumps(row, ensure_ascii=False) + "\n", encoding="utf-8")

            def _expect_fail(label: str, src_dir: Path, mutator, *, check_binding: bool = False, check_lc_pending: bool = False):
                d = root / f"case_{label}"
                shutil.copytree(src_dir, d)
                mutator(d)
                rf = verify_http_capture.verify_run_http_captures(d, require_live_chat=False)
                rt = verify_http_capture.verify_run_http_captures(d, require_live_chat=True)
                self.assertEqual(rf["capture_status"], "FAILED", f"{label}: {rf}")
                self.assertFalse(rf["capture_integrity_ok"], label)
                self.assertFalse(rf["live_chat_verified"], label)
                self.assertEqual(rt["capture_status"], "FAILED", label)
                self.assertFalse(rt["live_chat_verified"], label)
                if check_binding:
                    self.assertEqual(rf["findings"][0]["prompt_metadata_binding"], "FAILED", label)
                if check_lc_pending:
                    rows = [json.loads(l) for l in (d / "assessments.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
                    lc = live_check.inspect(rows, minimum=1, require_prompt_metadata=True)
                    self.assertEqual(lc["protocol_status"], "PENDING", f"{label} live_check: {lc}")

            # 1. Validated verdict flip SUPPORTED -> REFUTED while raw response.body.bin says SUPPORTED
            _expect_fail(
                "flip_supported_to_refuted",
                base_dir,
                lambda d: _edit_row(
                    d,
                    lambda r: (
                        r.__setitem__("validated_status", "REFUTED"),
                        r["assessment"].__setitem__("status", "REFUTED"),
                        r["assessment"].__setitem__("validated_status", "REFUTED"),
                    ),
                ),
                check_lc_pending=True,
            )
            # 2. Assessment failure_kind vs runtime.failure_kind contradiction
            _expect_fail(
                "ass_fk_mismatch",
                base_dir,
                lambda d: _edit_row(d, lambda r: r["assessment"].__setitem__("failure_kind", "UNVERIFIED_HELPER_FLOW")),
                check_lc_pending=True,
            )
            # 3. Top-level row.validated_status / row.state / requires_human_review tampering
            _expect_fail(
                "row_validated_status_mismatch",
                base_dir,
                lambda d: _edit_row(d, lambda r: r.__setitem__("validated_status", "REFUTED")),
                check_lc_pending=True,
            )
            _expect_fail(
                "requires_human_review_false",
                base_dir,
                lambda d: _edit_row(d, lambda r: r["assessment"].__setitem__("requires_human_review", False)),
                check_lc_pending=True,
            )
            _expect_fail(
                "row_state_confirmed_false",
                base_dir,
                lambda d: _edit_row(
                    d,
                    lambda r: (
                        r.__setitem__("state", "CONFIRMED_FALSE"),
                        r.__setitem__("human_review_state", "CONFIRMED_FALSE"),
                    ),
                ),
                check_lc_pending=True,
            )
            # 4. evidence.json top-level prompt_contract contradicting record prompt_contract
            _expect_fail(
                "bundle_prompt_contract_mismatch",
                base_dir,
                lambda d: _edit_json(d / "evidence.json", lambda x: x.__setitem__("prompt_contract", "neutral_hints")),
                check_binding=True,
            )
            # 5. receipt.http_status tampered to 503 fails both overall AND prompt_metadata_binding
            _expect_fail(
                "receipt_http_status_503",
                base_dir,
                lambda d: _edit_json(d / "llm_io" / f"{fid}.http-capture.json", lambda x: x.__setitem__("http_status", 503)),
                check_binding=True,
            )
            # 6. Post-gate downgrade (real apply_integration_gate) + missing downgrade_reason / failure_kind / synchronized tamper rejection
            from v2.api.triage_gate import apply_integration_gate

            h6_src = root / "gate6_src"
            h6_src.mkdir()
            h6_java = (
                "public class Gate6Helper {\n"
                "  void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt) throws Exception {\n"
                '    String input = req.getParameter("u");\n'
                "    String clean = ExternalUtil.transform(input);\n"
                '    stmt.executeQuery("SELECT * FROM users WHERE u=" + clean);\n'
                "  }\n"
                "}\n"
            )
            (h6_src / "Gate6Helper.java").write_bytes(h6_java.encode("utf-8"))
            h6_lke = h6_java.splitlines(keepends=True)
            h6_ls = h6_java.splitlines()
            h6_pt = lambda ln, col: {"line": ln, "col": col, "offset": sum(len(x.encode("utf-8")) for x in h6_lke[: ln - 1]) + col - 1}
            h6_loc = lambda ln, txt: {"path": "Gate6Helper.java", "start": h6_pt(ln, h6_ls[ln - 1].index(txt) + 1), "end": h6_pt(ln, h6_ls[ln - 1].index(txt) + 1 + len(txt.encode("utf-8")))}
            h6_scan = {
                "results": [{
                    "check_id": "test.cwe89", "path": "Gate6Helper.java",
                    "start": h6_loc(5, 'stmt.executeQuery("SELECT * FROM users WHERE u=" + clean)')["start"],
                    "end": h6_loc(5, 'stmt.executeQuery("SELECT * FROM users WHERE u=" + clean)')["end"],
                    "extra": {
                        "severity": "ERROR", "metadata": {"cwe": ["CWE-89"]}, "message": "SQLi",
                        "dataflow_trace": {
                            "taint_source": ["CliLoc", [h6_loc(3, 'req.getParameter("u")'), 'req.getParameter("u")']],
                            "intermediate_vars": [],
                            "taint_sink": ["CliLoc", [h6_loc(5, 'stmt.executeQuery("SELECT * FROM users WHERE u=" + clean)'), 'stmt.executeQuery("SELECT * FROM users WHERE u=" + clean)']],
                        },
                    },
                }], "errors": [],
            }
            h6_sp = {
                "origin": "recorded_capture_unsigned", "producer": "ntk-local-scan-capture",
                "source_capture_verified": True, "exit_capture_verified": True,
                "recorded_engine_exit": 0, "declared_engine_exit": None,
                "independently_attested": False, "manifest_path": "capture/scan-manifest.json",
                "manifest_sha256": "a" * 64,
            }
            h6_bundle = collect(json.dumps(h6_scan), h6_src, engine_exit=0, scan_provenance=h6_sp)
            h6_bundle["prompt_contract"] = "blind"
            h6_rec = h6_bundle["records"][0]
            h6_rec["prompt_contract"] = "blind"
            h6_sha = h6_rec["snapshots"]["Gate6Helper.java"]["sha256"]
            h6_model = "qwen3.5:9b-q4_K_M"
            h6_digest = "56671c2ab9385f9cfcb404638e32cd62d88e3501d44822208363c010179a3c90"
            h6_chat = json.dumps({
                "model": h6_model, "created_at": "2026-11-26T05:00:00.000000Z",
                "message": {"role": "assistant", "content": json.dumps({
                    "explanation": "Input flows through ExternalUtil.transform to SQL sink.",
                    "citations": [{"path": "Gate6Helper.java", "start_line": 5, "end_line": 5, "quote": h6_ls[4], "sha256": h6_sha}],
                    "status": "SUPPORTED", "fix_suggestion": "Use PreparedStatement.",
                })},
                "done": True, "done_reason": "stop", "eval_count": 25, "eval_duration": 120000000,
            }).encode("utf-8")
            h6_tags = json.dumps({"models": [{"name": h6_model, "model": h6_model, "digest": h6_digest, "size": 6550825550}]}).encode("utf-8")

            class _G6H(BaseHTTPRequestHandler):
                def log_message(self, *args):
                    pass

                def do_GET(self):
                    self.send_response(200, "OK")
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(h6_tags)))
                    self.end_headers()
                    self.wfile.write(h6_tags)

                def do_POST(self):
                    n = int(self.headers.get("Content-Length", "0"))
                    if n:
                        self.rfile.read(n)
                    self.send_response(200, "OK")
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(h6_chat)))
                    self.end_headers()
                    self.wfile.write(h6_chat)

            srv6 = ThreadingHTTPServer(("127.0.0.1", 0), _G6H)
            th6 = threading.Thread(target=srv6.serve_forever, daemon=True)
            th6.start()
            try:
                gate_dir = root / "gate_downgraded"
                gate_dir.mkdir()
                cl6 = OllamaClient(
                    endpoint=f"http://127.0.0.1:{srv6.server_port}",
                    model=h6_model, timeout=10, runtime_origin="unverified",
                    io_log_dir=gate_dir / "llm_io", capture_root=gate_dir,
                )
                inv6 = cl6.verify_model_installed()
                (gate_dir / "ollama-tags-check.json").write_text(json.dumps(inv6, indent=2), encoding="utf-8")
                raw6 = cl6.analyze(h6_rec)
            finally:
                srv6.shutdown()
                srv6.server_close()
                th6.join(timeout=2)

            gated6 = apply_integration_gate(h6_rec, raw6)
            (gate_dir / "evidence.json").write_text(json.dumps(h6_bundle, indent=2, ensure_ascii=False), encoding="utf-8")
            (gate_dir / "assessments.jsonl").write_text(
                json.dumps({
                    "schema_version": SCHEMA_VERSION, "id": h6_rec["id"], "alert_id": h6_rec["alert_id"],
                    "scan_sha256": h6_rec["scan_sha256"], "finding_index": h6_rec["finding_index"],
                    "state": "OPEN", "human_review_state": "OPEN",
                    "raw_model_status": gated6.get("raw_model_status"),
                    "validated_status": gated6.get("validated_status"),
                    "evidence": h6_rec, "assessment": gated6,
                }, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            gate_rep_f = verify_http_capture.verify_run_http_captures(gate_dir, require_live_chat=False)
            self.assertEqual(gate_rep_f["capture_status"], "VERIFIED_COMPLETE", gate_rep_f["errors"])
            self.assertTrue(gate_rep_f["artifact_integrity_ok"])
            self.assertTrue(gate_rep_f["endpoint_reported_protocol_ok"])
            self.assertEqual(gate_rep_f["findings"][0]["post_gate_downgrade_verification"], "RECOMPUTED_EXACT_MATCH")
            self.assertFalse(gate_rep_f["live_chat_verified"])
            gate_rep_t = verify_http_capture.verify_run_http_captures(gate_dir, require_live_chat=True)
            self.assertEqual(gate_rep_t["capture_status"], "FAILED")
            self.assertTrue(gate_rep_t["artifact_integrity_ok"])
            self.assertFalse(gate_rep_t["live_chat_verified"])
            _expect_fail(
                "postgate_missing_downgrade_reason",
                gate_dir,
                lambda d: _edit_row(d, lambda r: r["assessment"].pop("downgrade_reason", None)),
            )
            _expect_fail(
                "postgate_fk_mismatch",
                gate_dir,
                lambda d: _edit_row(d, lambda r: r["assessment"].__setitem__("failure_kind", "NONE")),
                check_lc_pending=True,
            )
            _expect_fail(
                "postgate_sync_dr_expl_tamper",
                gate_dir,
                lambda d: _edit_row(
                    d,
                    lambda r: (
                        r["assessment"].__setitem__("downgrade_reason", "Human Review confirmed the finding safe."),
                        r["assessment"].__setitem__(
                            "explanation",
                            "Human Review confirmed the finding safe. (Model returned SUPPORTED; Human Review remains OPEN. Prior note: Input flows through ExternalUtil.transform to SQL sink.)",
                        ),
                    ),
                ),
            )

            # 7. HTTP 500 error branch tampering (http_status=200 or forged raw_response)
            err_body = b'{"error":"internal"}'

            class _Err500Handler(BaseHTTPRequestHandler):
                def log_message(self, *args):
                    pass

                def do_POST(self):
                    n = int(self.headers.get("Content-Length", "0"))
                    if n:
                        self.rfile.read(n)
                    self.send_response(500)
                    self.send_header("Content-Length", str(len(err_body)))
                    self.end_headers()
                    self.wfile.write(err_body)

            srv = ThreadingHTTPServer(("127.0.0.1", 0), _Err500Handler)
            th = threading.Thread(target=srv.serve_forever, daemon=True)
            th.start()
            try:
                err_tdir = root / "err500" / "triage"
                err_tdir.mkdir(parents=True)
                cl_err = OllamaClient(
                    endpoint=f"http://127.0.0.1:{srv.server_port}",
                    model="qwen3.5:9b-q4_K_M",
                    timeout=5,
                    runtime_origin="unverified",
                    io_log_dir=err_tdir / "llm_io",
                    capture_root=err_tdir,
                )
                ass_err = cl_err.analyze(rec)
            finally:
                srv.shutdown()
                srv.server_close()
                th.join(timeout=2)

            ev_doc = json.loads((base_dir / "evidence.json").read_text(encoding="utf-8"))
            (err_tdir / "evidence.json").write_text(json.dumps(ev_doc, indent=2), encoding="utf-8")
            err_row = {
                "schema_version": SCHEMA_VERSION,
                "id": rec["id"],
                "alert_id": rec["alert_id"],
                "scan_sha256": rec["scan_sha256"],
                "finding_index": rec["finding_index"],
                "state": "OPEN",
                "human_review_state": "OPEN",
                "raw_model_status": ass_err.get("raw_model_status"),
                "validated_status": ass_err.get("validated_status"),
                "evidence": rec,
                "assessment": ass_err,
            }
            (err_tdir / "assessments.jsonl").write_text(json.dumps(err_row) + "\n", encoding="utf-8")
            rep_err_ok = verify_http_capture.verify_run_http_captures(err_tdir, require_live_chat=False)
            self.assertEqual(rep_err_ok["capture_status"], "VERIFIED_ERROR_OR_PARTIAL_CAPTURED", rep_err_ok["errors"])
            self.assertFalse(rep_err_ok["live_chat_verified"])
            _expect_fail(
                "http500_tamper_status_200",
                err_tdir,
                lambda d: (
                    _edit_row(d, lambda r: r["assessment"]["runtime"].__setitem__("http_status", 200)),
                    _edit_json(d / "llm_io" / f"{fid}.response.json", lambda x: x["runtime"].__setitem__("http_status", 200)),
                    _edit_json(d / "llm_io" / f"{fid}.http-capture.json", lambda x: x.__setitem__("http_status", 200)),
                ),
            )
            _expect_fail(
                "http500_forged_raw_response",
                err_tdir,
                lambda d: (
                    _edit_row(d, lambda r: r["assessment"].__setitem__("raw_response", {"forged": True})),
                    _edit_json(d / "llm_io" / f"{fid}.response.json", lambda x: x.__setitem__("raw_response", {"forged": True})),
                ),
            )

            # 8. Precheck-aborted .response.json tampering (origin / prompt_contract / error)
            pre_rec = copy.deepcopy(rec)
            pre_rec["issues"] = ["synthetic precheck failure"]
            pre_ev = copy.deepcopy(ev_doc)
            pre_ev["records"] = [pre_rec]
            pre_tdir = root / "precheck" / "triage"
            pre_tdir.mkdir(parents=True)
            cl_pre = OllamaClient(
                endpoint="http://127.0.0.1:11434",
                model="qwen3.5:9b-q4_K_M",
                timeout=5,
                runtime_origin="unverified",
                io_log_dir=pre_tdir / "llm_io",
                capture_root=pre_tdir,
            )
            ass_pre = cl_pre.analyze(pre_rec)
            (pre_tdir / "evidence.json").write_text(json.dumps(pre_ev, indent=2), encoding="utf-8")
            pre_row = {
                "schema_version": SCHEMA_VERSION,
                "id": pre_rec["id"],
                "alert_id": pre_rec["alert_id"],
                "scan_sha256": pre_rec["scan_sha256"],
                "finding_index": pre_rec["finding_index"],
                "state": "OPEN",
                "human_review_state": "OPEN",
                "raw_model_status": ass_pre.get("raw_model_status"),
                "validated_status": ass_pre.get("validated_status"),
                "evidence": pre_rec,
                "assessment": ass_pre,
            }
            (pre_tdir / "assessments.jsonl").write_text(json.dumps(pre_row) + "\n", encoding="utf-8")
            self.assertEqual(
                verify_http_capture.verify_run_http_captures(pre_tdir, require_live_chat=False)["capture_status"],
                "VERIFIED_ERROR_OR_PARTIAL_CAPTURED",
            )
            _expect_fail(
                "precheck_tampered_response_json",
                pre_tdir,
                lambda d: _edit_json(
                    d / "llm_io" / f"{fid}.response.json",
                    lambda x: (
                        x["runtime"].__setitem__("origin", "forged"),
                        x["runtime"].__setitem__("prompt_contract", "neutral_hints"),
                        x.__setitem__("error", None),
                    ),
                ),
            )

    def test_07_ir_p1_http_01_live_provenance_trust_boundary_invariants(self) -> None:
        """IR-P1-HTTP-01 fail-closed trust boundary across loopback fixtures, coordinated forgery, CLI, and secondary checks."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            # Group 1: Full loopback fixture with neutral/live-shaped metadata, tags, digest, timing, scan_provenance
            a2_dir, rec, row = _build_real_loopback_v226_run(root / "a2_live_shape", runtime_origin="unverified")
            fid = rec["id"]

            rep_f = verify_http_capture.verify_run_http_captures(a2_dir, require_live_chat=False)
            rep_t = verify_http_capture.verify_run_http_captures(a2_dir, require_live_chat=True)
            self.assertEqual(rep_f["capture_status"], "VERIFIED_COMPLETE", rep_f["errors"])
            self.assertTrue(rep_f["capture_integrity_ok"])
            self.assertTrue(rep_f["artifact_integrity_ok"])
            self.assertTrue(rep_f["endpoint_reported_protocol_ok"])
            self.assertFalse(rep_f["live_chat_verified"])
            self.assertFalse(rep_f["live_origin_verified"])
            self.assertEqual(rep_f["live_origin_trust_status"], "UNVERIFIED_OFFLINE_NO_TRUSTED_EXTERNAL_PROVENANCE")
            self.assertEqual(rep_f["live_non_mock_complete_captures"], 0)
            self.assertFalse(rep_f["findings"][0]["live_provenance_ok"])
            self.assertFalse(rep_f["independently_verified_model_runtime"])
            self.assertFalse(rep_f["security_conclusion_verified"])

            self.assertEqual(rep_t["capture_status"], "FAILED")
            self.assertFalse(rep_t["capture_integrity_ok"])
            self.assertTrue(rep_t["artifact_integrity_ok"])
            self.assertTrue(rep_t["endpoint_reported_protocol_ok"])
            self.assertFalse(rep_t["live_chat_verified"])
            self.assertFalse(rep_t["live_origin_verified"])
            self.assertFalse(rep_t["findings"][0]["verified"])
            self.assertTrue(any("UNVERIFIED_LIVE_RUNTIME_ORIGIN" in e for e in rep_t["errors"]), rep_t["errors"])

            # CLI exit code parity: normal mode -> exit 0; strict --require-live-chat -> exit 2
            self.assertEqual(verify_http_capture.main([str(a2_dir), "--no-write"]), 0)
            self.assertEqual(verify_http_capture.main([str(a2_dir), "--require-live-chat", "--no-write"]), 2)

            # Group 1b: Coordinated forgery mimicking 127.0.0.1:11434 + production provenance + realistic timing/tags/digest
            forged_dir = root / "coord_11434_forgery"
            shutil.copytree(a2_dir, forged_dir)
            fake_ep = "http://127.0.0.1:11434"
            for relp in (
                f"llm_io/{fid}.http-capture.json",
                f"llm_io/{fid}.response.json",
                "ollama-tags-check.json",
            ):
                p = forged_dir / relp
                d = json.loads(p.read_text(encoding="utf-8"))
                d["endpoint"] = fake_ep
                if relp.endswith(".http-capture.json"):
                    d["elapsed_seconds"] = 4.25
                    d["latency_ms"] = 4250.0
                p.write_text(json.dumps(d, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            for tp in sorted((forged_dir / "llm_io" / "_tags").glob("*.http-capture.json")):
                tdoc = json.loads(tp.read_text(encoding="utf-8"))
                tdoc["endpoint"] = fake_ep
                tp.write_text(json.dumps(tdoc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            ap = forged_dir / "assessments.jsonl"
            arow = json.loads(ap.read_text(encoding="utf-8").strip())
            arow["assessment"]["endpoint"] = fake_ep
            ap.write_text(json.dumps(arow, ensure_ascii=False) + "\n", encoding="utf-8")

            f_norm = verify_http_capture.verify_run_http_captures(forged_dir, require_live_chat=False)
            f_strict = verify_http_capture.verify_run_http_captures(forged_dir, require_live_chat=True)
            self.assertEqual(f_norm["capture_status"], "VERIFIED_COMPLETE", f_norm["errors"])
            self.assertTrue(f_norm["artifact_integrity_ok"])
            self.assertTrue(f_norm["endpoint_reported_protocol_ok"])
            self.assertFalse(f_norm["live_chat_verified"])
            self.assertFalse(f_norm["live_origin_verified"])
            self.assertEqual(f_strict["capture_status"], "FAILED")
            self.assertFalse(f_strict["live_chat_verified"])
            self.assertFalse(f_strict["live_origin_verified"])
            self.assertTrue(any("UNVERIFIED_LIVE_RUNTIME_ORIGIN" in e for e in f_strict["errors"]))

            # Group 1c: live_check exposes explicit scope and false live/model/security flags
            lc = live_check.inspect([arow], minimum=1, require_prompt_metadata=True)
            self.assertEqual(lc["protocol_status"], "OLLAMA_REPORTED_UNATTESTED")
            self.assertEqual(lc["verification_scope"], "assessment_rows_protocol_only_no_sidecar_or_live_origin_attestation")
            self.assertFalse(lc["live_origin_verified"])
            self.assertFalse(lc["independently_verified_model_runtime"])
            self.assertFalse(lc["security_conclusion_verified"])

            # Group 4a: Unvalidated raw_model_status tamper is now rejected (not gated solely by sidecar_answer_validated=True)
            unval_dir = root / "unval_raw_status_tamper"
            shutil.copytree(a2_dir, unval_dir)
            r_path = unval_dir / "assessments.jsonl"
            r_obj = json.loads(r_path.read_text(encoding="utf-8").strip())
            r_obj["validated_status"] = "UNDETERMINED"
            r_obj["raw_model_status"] = "REFUTED"
            r_obj["assessment"]["status"] = "UNDETERMINED"
            r_obj["assessment"]["validated_status"] = "UNDETERMINED"
            r_obj["assessment"]["raw_model_status"] = "REFUTED"
            r_obj["assessment"]["failure_kind"] = "INVALID_CITATION"
            r_obj["assessment"]["runtime"]["answer_validated"] = False
            r_obj["assessment"]["runtime"]["failure_kind"] = "INVALID_CITATION"
            r_path.write_text(json.dumps(r_obj, ensure_ascii=False) + "\n", encoding="utf-8")
            s_path = unval_dir / "llm_io" / f"{fid}.response.json"
            s_obj = json.loads(s_path.read_text(encoding="utf-8"))
            s_obj["runtime"]["answer_validated"] = False
            s_obj["runtime"]["failure_kind"] = "INVALID_CITATION"
            s_obj["error"] = r_obj["assessment"]["explanation"]
            s_path.write_text(json.dumps(s_obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            unval_rep = verify_http_capture.verify_run_http_captures(unval_dir, require_live_chat=False)
            self.assertEqual(unval_rep["capture_status"], "FAILED")
            self.assertFalse(unval_rep["artifact_integrity_ok"])
            self.assertTrue(any("raw_model_status" in e for e in unval_rep["errors"]), unval_rep["errors"])

            # Group 4b: Precheck .request.json semantic tamper (wrong model / mismatched messages) is rejected
            pre_dir = root / "precheck_req_json_tamper" / "triage"
            pre_dir.mkdir(parents=True)
            ev_doc = json.loads((a2_dir / "evidence.json").read_text(encoding="utf-8"))
            pre_rec = copy.deepcopy(ev_doc["records"][0])
            pre_rec["issues"] = ["synthetic precheck"]
            ev_doc["records"] = [pre_rec]
            cl_pre = OllamaClient(
                endpoint="http://127.0.0.1:11434",
                model="qwen3.5:9b-q4_K_M",
                timeout=5,
                runtime_origin="unverified",
                io_log_dir=pre_dir / "llm_io",
                capture_root=pre_dir,
            )
            ass_pre = cl_pre.analyze(pre_rec)
            (pre_dir / "evidence.json").write_text(json.dumps(ev_doc, indent=2), encoding="utf-8")
            pre_row = {
                "schema_version": SCHEMA_VERSION,
                "id": pre_rec["id"],
                "alert_id": pre_rec["alert_id"],
                "scan_sha256": pre_rec["scan_sha256"],
                "finding_index": pre_rec["finding_index"],
                "state": "OPEN",
                "human_review_state": "OPEN",
                "raw_model_status": ass_pre.get("raw_model_status"),
                "validated_status": ass_pre.get("validated_status"),
                "evidence": pre_rec,
                "assessment": ass_pre,
            }
            (pre_dir / "assessments.jsonl").write_text(json.dumps(pre_row) + "\n", encoding="utf-8")
            (pre_dir / "llm_io" / f"{fid}.request.json").write_text(
                json.dumps({"model": "other-forged-model", "stream": True, "messages": []}, indent=2),
                encoding="utf-8",
            )
            pre_rep = verify_http_capture.verify_run_http_captures(pre_dir, require_live_chat=False)
            self.assertEqual(pre_rep["capture_status"], "FAILED")
            self.assertFalse(pre_rep["artifact_integrity_ok"])
            self.assertTrue(any(".request.json" in e for e in pre_rep["errors"]), pre_rep["errors"])

    def test_08_ir_p2_http_03_cli_output_error_semantics(self) -> None:
        """IR-P2-HTTP-03: CLI output write refusal/error never fabricates artifact_integrity_ok=False."""
        import contextlib
        import io

        def _cli(argv: list[str]) -> tuple[int, dict]:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = verify_http_capture.main(argv)
            return rc, json.loads(buf.getvalue())

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            triage_dir, rec, _row = _build_real_loopback_v226_run(root / "clean_run", runtime_origin="unverified")
            fid = rec["id"]
            out_path = root / "report.json"

            # 1. First write succeeds (normal mode, exit 0)
            rc1, doc1 = _cli([str(triage_dir), "--minimum-findings", "1", "--output", str(out_path)])
            self.assertEqual(rc1, 0)
            self.assertEqual(doc1["capture_status"], "VERIFIED_COMPLETE")
            self.assertTrue(doc1["artifact_integrity_ok"])
            self.assertTrue(doc1["endpoint_reported_protocol_ok"])
            self.assertFalse(doc1["live_origin_verified"])
            orig_bytes = out_path.read_bytes()

            # 2. Second write to same existing output (normal mode) -> exit 2, file untouched, artifact_integrity_ok=True preserved
            rc2, doc2 = _cli([str(triage_dir), "--minimum-findings", "1", "--output", str(out_path)])
            self.assertEqual(rc2, 2)
            self.assertEqual(out_path.read_bytes(), orig_bytes)
            self.assertTrue(doc2["verification_executed"])
            self.assertTrue(doc2["artifact_integrity_ok"])
            self.assertTrue(doc2["endpoint_reported_protocol_ok"])
            self.assertEqual(doc2["capture_status"], "VERIFIED_COMPLETE")
            self.assertTrue(doc2["capture_integrity_ok"])
            self.assertFalse(doc2["live_origin_verified"])
            self.assertFalse(doc2["report_write_ok"])
            self.assertEqual(doc2["report_write_status"], "REFUSED_EXISTING_OUTPUT")
            self.assertIn("OUTPUT_WRITE_REFUSED_EXISTING_FILE", doc2["report_write_error"])
            self.assertEqual(doc2["errors"], [])

            # 3. Second write to same existing output (strict mode) -> exit 2, file untouched, artifact_integrity_ok=True preserved
            rc3, doc3 = _cli([str(triage_dir), "--minimum-findings", "1", "--require-live-chat", "--output", str(out_path)])
            self.assertEqual(rc3, 2)
            self.assertEqual(out_path.read_bytes(), orig_bytes)
            self.assertTrue(doc3["verification_executed"])
            self.assertTrue(doc3["artifact_integrity_ok"])
            self.assertTrue(doc3["endpoint_reported_protocol_ok"])
            self.assertEqual(doc3["capture_status"], "FAILED")
            self.assertFalse(doc3["capture_integrity_ok"])
            self.assertFalse(doc3["live_origin_verified"])
            self.assertFalse(doc3["report_write_ok"])
            self.assertEqual(doc3["report_write_status"], "REFUSED_EXISTING_OUTPUT")
            self.assertTrue(any("UNVERIFIED_LIVE_RUNTIME_ORIGIN" in e for e in doc3["errors"]))

            # 4. Corrupted capture + existing output -> preserves TRUE artifact_integrity_ok=False AND reports output refusal
            bad_dir = root / "corrupt_run"
            shutil.copytree(triage_dir, bad_dir)
            resp_bin = bad_dir / "llm_io" / f"{fid}.response.body.bin"
            resp_bin.write_bytes(resp_bin.read_bytes() + b"X")
            rc4, doc4 = _cli([str(bad_dir), "--minimum-findings", "1", "--output", str(out_path)])
            self.assertEqual(rc4, 2)
            self.assertEqual(out_path.read_bytes(), orig_bytes)
            self.assertTrue(doc4["verification_executed"])
            self.assertFalse(doc4["artifact_integrity_ok"])
            self.assertEqual(doc4["capture_status"], "FAILED")
            self.assertFalse(doc4["report_write_ok"])
            self.assertEqual(doc4["report_write_status"], "REFUSED_EXISTING_OUTPUT")

            # 5. Unsafe output target (parent traversal '..') -> exit 2, preserves artifact_integrity_ok=True
            rc5, doc5 = _cli([str(triage_dir), "--minimum-findings", "1", "--output", str(root / ".." / "escape.json")])
            self.assertEqual(rc5, 2)
            self.assertTrue(doc5["verification_executed"])
            self.assertTrue(doc5["artifact_integrity_ok"])
            self.assertFalse(doc5["report_write_ok"])
            self.assertEqual(doc5["report_write_status"], "REFUSED_UNSAFE_OUTPUT_TARGET")

            # 6. Unwritable parent (regular file as parent dir) -> exit 2, preserves artifact_integrity_ok=True
            blocker_file = root / "file_parent"
            blocker_file.write_text("not a dir", encoding="utf-8")
            rc6, doc6 = _cli([str(triage_dir), "--minimum-findings", "1", "--output", str(blocker_file / "r.json")])
            self.assertEqual(rc6, 2)
            self.assertTrue(doc6["verification_executed"])
            self.assertTrue(doc6["artifact_integrity_ok"])
            self.assertFalse(doc6["report_write_ok"])
            self.assertIn(doc6["report_write_status"], ("REFUSED_UNSAFE_OUTPUT_TARGET", "OUTPUT_WRITE_IO_ERROR"))

            # 7. CLI success / --no-write expose consistent report_write_ok and cli_operation_ok fields
            self.assertTrue(doc1["verification_executed"])
            self.assertTrue(doc1["report_write_ok"])
            self.assertEqual(doc1["report_write_status"], "WRITTEN")
            self.assertTrue(doc1["cli_operation_ok"])
            rc_nw, doc_nw = _cli([str(triage_dir), "--minimum-findings", "1", "--no-write"])
            self.assertEqual(rc_nw, 0)
            self.assertTrue(doc_nw["verification_executed"])
            self.assertIsNone(doc_nw["report_write_ok"])
            self.assertEqual(doc_nw["report_write_status"], "SKIPPED_NO_WRITE")
            self.assertTrue(doc_nw["cli_operation_ok"])

            # 8. --minimum-findings > actual count fails closed in normal mode too (never exit 0!)
            rc_min, doc_min = _cli([str(triage_dir), "--minimum-findings", "2", "--no-write"])
            self.assertEqual(rc_min, 2)
            self.assertEqual(doc_min["capture_status"], "FAILED")
            self.assertFalse(doc_min["artifact_integrity_ok"])
            self.assertFalse(doc_min["capture_integrity_ok"])
            self.assertFalse(doc_min["endpoint_reported_protocol_ok"])
            self.assertFalse(doc_min["cli_operation_ok"])
            self.assertTrue(any("at least 2 finding" in e for e in doc_min["errors"]), doc_min["errors"])

            # 9. Existing directory target classified as REFUSED_UNSAFE_OUTPUT_TARGET (not REFUSED_EXISTING_OUTPUT)
            dir_target = root / "existing_dir_target"
            dir_target.mkdir()
            rc_dir, doc_dir = _cli([str(triage_dir), "--minimum-findings", "1", "--output", str(dir_target)])
            self.assertEqual(rc_dir, 2)
            self.assertTrue(doc_dir["artifact_integrity_ok"])
            self.assertFalse(doc_dir["report_write_ok"])
            self.assertEqual(doc_dir["report_write_status"], "REFUSED_UNSAFE_OUTPUT_TARGET")
            self.assertFalse(doc_dir["cli_operation_ok"])

            # 10. Mid-write failure leaves ZERO partial/corrupt report file on disk and preserves artifact_integrity_ok=True
            partial_target = root / "atomic_midwrite.json"
            real_open = Path.open

            class _MidWriteFail:
                def __init__(self, f):
                    self._f = f
                def __enter__(self):
                    return self
                def __exit__(self, *a):
                    return self._f.__exit__(*a)
                def write(self, data):
                    self._f.write(data[:16])
                    self._f.flush()
                    raise OSError("Simulated ENOSPC mid-write")

            def _fail_tmp_open(self_p, mode="r", *a, **kw):
                fh = real_open(self_p, mode, *a, **kw)
                if mode == "xb" and self_p.name.startswith(".atomic_midwrite.json."):
                    return _MidWriteFail(fh)
                return fh

            with patch.object(Path, "open", _fail_tmp_open):
                rc_mw, doc_mw = _cli([str(triage_dir), "--minimum-findings", "1", "--output", str(partial_target)])
            self.assertEqual(rc_mw, 2)
            self.assertFalse(partial_target.exists(), "Mid-write failure must never leave a partial report on disk")
            self.assertEqual(list(root.glob(".atomic_midwrite.json.*.tmp")), [], "Temp sibling file must be cleaned up")
            self.assertTrue(doc_mw["artifact_integrity_ok"])
            self.assertFalse(doc_mw["report_write_ok"])
            self.assertEqual(doc_mw["report_write_status"], "OUTPUT_WRITE_IO_ERROR")
            self.assertFalse(doc_mw["cli_operation_ok"])

            # 11. Serialization failure (NaN or unserializable object) fails closed with exit 2 without writing target
            ser_target = root / "ser_err.json"
            for bad_label, bad_val in (("nan", float("nan")), ("object", object())):
                with self.subTest(serialization_case=bad_label):
                    bad_res = dict(doc1)
                    bad_res["bad_payload"] = bad_val
                    with patch.object(verify_http_capture, "verify_run_http_captures", return_value=bad_res):
                        rc_ser, doc_ser = _cli([str(triage_dir), "--output", str(ser_target)])
                    self.assertEqual(rc_ser, 2)
                    self.assertFalse(ser_target.exists())
                    self.assertTrue(doc_ser["verification_executed"])
                    self.assertTrue(doc_ser["artifact_integrity_ok"])
                    self.assertFalse(doc_ser["report_write_ok"])
                    self.assertEqual(doc_ser["report_write_status"], "REPORT_SERIALIZATION_ERROR")
                    self.assertFalse(doc_ser["live_origin_verified"])
                    self.assertFalse(doc_ser["cli_operation_ok"])

    def test_09_p1_assessment_content_binding_matrix_and_loopback_controls(self) -> None:
        """P1 content binding: raw HTTP response <-> assessment (clean, downgrade, errors, loopback writer)."""
        def _run_loopback_custom(
            root: Path,
            *,
            java_text: str,
            raw_scan: dict,
            chat_status: int = 200,
            chat_body_bytes: bytes | None = None,
            model_answer_obj: dict | None = None,
            post_transform=None,
            extra_issues: list[str] | None = None,
        ) -> tuple[Path, dict, dict]:
            src_root = root / "src"
            src_root.mkdir(parents=True, exist_ok=True)
            (src_root / "DemoSql.java").write_bytes(java_text.encode("utf-8"))
            scan_prov = {
                "origin": "recorded_capture_unsigned",
                "producer": "ntk-local-scan-capture",
                "source_capture_verified": True,
                "exit_capture_verified": True,
                "recorded_engine_exit": 0,
                "declared_engine_exit": None,
                "independently_attested": False,
                "manifest_path": "capture/scan-manifest.json",
                "manifest_sha256": "b" * 64,
            }
            bundle = collect(json.dumps(raw_scan), src_root, engine_exit=0, scan_provenance=scan_prov)
            bundle["prompt_contract"] = "blind"
            rec = bundle["records"][0]
            rec["prompt_contract"] = "blind"
            if extra_issues:
                rec["issues"].extend(extra_issues)
            model = "qwen3.5:9b-q4_K_M"
            model_digest = "56671c2ab9385f9cfcb404638e32cd62d88e3501d44822208363c010179a3c90"
            if chat_body_bytes is None:
                assert model_answer_obj is not None
                chat_resp = {
                    "model": model,
                    "created_at": "2026-11-26T05:00:00.000000Z",
                    "message": {"role": "assistant", "content": json.dumps(model_answer_obj, ensure_ascii=False)},
                    "done": True,
                    "done_reason": "stop",
                    "eval_count": 28,
                    "eval_duration": 120000000,
                }
                chat_body_bytes = json.dumps(chat_resp, ensure_ascii=False).encode("utf-8")
            tags_bytes = json.dumps(
                {"models": [{"name": model, "model": model, "digest": model_digest, "size": 6550825550}]},
                ensure_ascii=False,
            ).encode("utf-8")

            class _H(BaseHTTPRequestHandler):
                def log_message(self, *args):
                    pass

                def do_GET(self):
                    self.send_response(200, "OK")
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(tags_bytes)))
                    self.end_headers()
                    self.wfile.write(tags_bytes)

                def do_POST(self):
                    n = int(self.headers.get("Content-Length", "0"))
                    if n:
                        self.rfile.read(n)
                    self.send_response(chat_status)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(chat_body_bytes)))
                    self.end_headers()
                    self.wfile.write(chat_body_bytes)

            srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
            th = threading.Thread(target=srv.serve_forever, daemon=True)
            th.start()
            try:
                tdir = root / "triage"
                tdir.mkdir(parents=True, exist_ok=True)
                client = OllamaClient(
                    endpoint=f"http://127.0.0.1:{srv.server_port}",
                    model=model,
                    timeout=10,
                    runtime_origin="unverified",
                    io_log_dir=tdir / "llm_io",
                    capture_root=tdir,
                )
                inv = client.verify_model_installed()
                (tdir / "ollama-tags-check.json").write_text(json.dumps(inv, indent=2), encoding="utf-8")
                ass = client.analyze(rec)
            finally:
                srv.shutdown()
                srv.server_close()
                th.join(timeout=2)

            if post_transform is not None:
                ass = post_transform(rec, ass)
            (tdir / "evidence.json").write_text(json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8")
            row = {
                "schema_version": SCHEMA_VERSION,
                "id": rec["id"],
                "alert_id": rec["alert_id"],
                "scan_sha256": rec["scan_sha256"],
                "finding_index": rec["finding_index"],
                "state": "OPEN",
                "human_review_state": "OPEN",
                "raw_model_status": ass.get("raw_model_status"),
                "validated_status": ass.get("validated_status"),
                "evidence": rec,
                "assessment": ass,
            }
            (tdir / "assessments.jsonl").write_text(json.dumps(row, ensure_ascii=False) + "\n", encoding="utf-8")
            return tdir, rec, row

        def _edit_row(d: Path, fn):
            p = d / "assessments.jsonl"
            row = json.loads(p.read_text(encoding="utf-8").strip())
            fn(row)
            p.write_text(json.dumps(row, ensure_ascii=False) + "\n", encoding="utf-8")

        with tempfile.TemporaryDirectory(prefix="ntk_p1_content_") as td:
            root = Path(td)
            base_dir, rec, row = _build_real_loopback_v226_run(root / "base_supported", runtime_origin="unverified")
            src_lines = {ln["line"]: ln["text"] for ln in rec["snippets"][0]["lines"]}
            snap_sha = rec["snapshots"]["DemoSql.java"]["sha256"]

            # 1. Clean SUPPORTED control passes normal mode and fails closed on live origin in strict mode
            rn = verify_http_capture.verify_run_http_captures(base_dir, require_live_chat=False)
            rs = verify_http_capture.verify_run_http_captures(base_dir, require_live_chat=True)
            self.assertEqual(rn["capture_status"], "VERIFIED_COMPLETE", rn["errors"])
            self.assertTrue(rn["artifact_integrity_ok"])
            self.assertFalse(rn["live_origin_verified"])
            self.assertFalse(rn["live_chat_verified"])
            self.assertEqual(rs["capture_status"], "FAILED")
            self.assertTrue(rs["artifact_integrity_ok"])
            self.assertFalse(rs["live_origin_verified"])
            self.assertFalse(rs["live_chat_verified"])

            def _assert_tamper_fails(label: str, src_tdir: Path, mutator):
                cdir = root / f"tamper_{label}"
                shutil.copytree(src_tdir, cdir)
                _edit_row(cdir, mutator)
                rep_n = verify_http_capture.verify_run_http_captures(cdir, require_live_chat=False)
                rep_s = verify_http_capture.verify_run_http_captures(cdir, require_live_chat=True)
                self.assertEqual(rep_n["capture_status"], "FAILED", f"{label} unexpectedly passed: {rep_n}")
                self.assertFalse(rep_n["artifact_integrity_ok"], f"{label} artifact_integrity_ok must be False")
                self.assertFalse(rep_n["endpoint_reported_protocol_ok"], label)
                self.assertFalse(rep_n["live_origin_verified"], label)
                self.assertFalse(rep_n["live_chat_verified"], label)
                self.assertEqual(rep_s["capture_status"], "FAILED", label)
                self.assertFalse(rep_s["artifact_integrity_ok"], label)
                self.assertFalse(rep_s["live_origin_verified"], label)
                self.assertFalse(rep_s["live_chat_verified"], label)

            # 2. All 6 original ChatGPT counterexamples + citation field/substitution/type/missing mutations
            _assert_tamper_fails("ce1_quote", base_dir, lambda r: r["assessment"]["citations"][0].__setitem__("quote", "not in Java source"))
            _assert_tamper_fails("ce2_empty_cites", base_dir, lambda r: r["assessment"].__setitem__("citations", []))
            _assert_tamper_fails("ce3_cc_none", base_dir, lambda r: r["assessment"].__setitem__("citation_check", "NONE"))
            _assert_tamper_fails("ce4_explanation", base_dir, lambda r: r["assessment"].__setitem__("explanation", "Text not returned by endpoint"))
            _assert_tamper_fails("ce5_fix_suggestion", base_dir, lambda r: r["assessment"].__setitem__("fix_suggestion", "Different suggestion"))
            _assert_tamper_fails("ce6_del_raw_model_status", base_dir, lambda r: (r.pop("raw_model_status", None), r["assessment"].pop("raw_model_status", None)))
            _assert_tamper_fails("cite_path", base_dir, lambda r: r["assessment"]["citations"][0].__setitem__("path", "Other.java"))
            _assert_tamper_fails("cite_start_line", base_dir, lambda r: r["assessment"]["citations"][0].__setitem__("start_line", 3))
            _assert_tamper_fails("cite_end_line", base_dir, lambda r: r["assessment"]["citations"][0].__setitem__("end_line", 5))
            _assert_tamper_fails("cite_sha", base_dir, lambda r: r["assessment"]["citations"][0].__setitem__("sha256", "0" * 64))
            _assert_tamper_fails("cite_bool_line", base_dir, lambda r: r["assessment"]["citations"][0].__setitem__("start_line", True))
            # Substitution with a DIFFERENT REAL source line that is valid in Java source & prompt but NOT in raw HTTP response
            _assert_tamper_fails(
                "cite_substitute_real_source_line",
                base_dir,
                lambda r: r["assessment"].__setitem__(
                    "citations",
                    [{"path": "DemoSql.java", "start_line": 3, "end_line": 3, "quote": src_lines[3], "sha256": snap_sha}],
                ),
            )
            # Missing / null / wrong-type required fields
            _assert_tamper_fails("null_raw_model_status", base_dir, lambda r: (r.__setitem__("raw_model_status", None), r["assessment"].__setitem__("raw_model_status", None)))
            _assert_tamper_fails("wrong_type_raw_model_status", base_dir, lambda r: (r.__setitem__("raw_model_status", 123), r["assessment"].__setitem__("raw_model_status", 123)))
            _assert_tamper_fails("missing_explanation", base_dir, lambda r: r["assessment"].pop("explanation", None))
            _assert_tamper_fails("null_explanation", base_dir, lambda r: r["assessment"].__setitem__("explanation", None))
            _assert_tamper_fails("missing_fix_suggestion", base_dir, lambda r: r["assessment"].pop("fix_suggestion", None))
            _assert_tamper_fails("null_fix_suggestion", base_dir, lambda r: r["assessment"].__setitem__("fix_suggestion", None))
            _assert_tamper_fails("missing_citations", base_dir, lambda r: r["assessment"].pop("citations", None))
            _assert_tamper_fails("wrong_type_citations", base_dir, lambda r: r["assessment"].__setitem__("citations", "not-a-list"))
            _assert_tamper_fails("missing_citation_check", base_dir, lambda r: r["assessment"].pop("citation_check", None))
            _assert_tamper_fails("null_citation_provenance", base_dir, lambda r: r["assessment"].__setitem__("citation_provenance", None))
            _assert_tamper_fails("forged_prov_in_source_false", base_dir, lambda r: r["assessment"]["citation_provenance"].__setitem__("citation_in_source", False))
            _assert_tamper_fails("forged_prov_claim_true", base_dir, lambda r: r["assessment"]["citation_provenance"].__setitem__("supports_security_claim_verified", True))

            # 3. Clean REFUTED, clean UNDETERMINED (empty citations AND with valid citation), via real loopback writer
            java_safe = (
                "public class DemoSql {\n"
                "  void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt) throws Exception {\n"
                '    String input = req.getParameter("u");\n'
                '    input = "constant_safe";\n'
                '    stmt.executeQuery("SELECT * FROM users WHERE u = " + input);\n'
                "  }\n"
                "}\n"
            )
            ls_ke = java_safe.splitlines(keepends=True)
            ls = java_safe.splitlines()

            def _pt(ln: int, col: int) -> dict[str, int]:
                return {"line": ln, "col": col, "offset": sum(len(x.encode("utf-8")) for x in ls_ke[: ln - 1]) + col - 1}

            def _loc(ln: int, txt: str) -> dict:
                c = ls[ln - 1].index(txt) + 1
                return {"path": "DemoSql.java", "start": _pt(ln, c), "end": _pt(ln, c + len(txt.encode("utf-8")))}

            sink_expr = 'stmt.executeQuery("SELECT * FROM users WHERE u = " + input)'
            sink_loc = _loc(5, sink_expr)
            raw_scan_safe = {
                "results": [
                    {
                        "check_id": "test.cwe89",
                        "path": "DemoSql.java",
                        "start": sink_loc["start"],
                        "end": sink_loc["end"],
                        "extra": {
                            "severity": "ERROR",
                            "metadata": {"cwe": ["CWE-89"]},
                            "message": "SQLi",
                            "dataflow_trace": {
                                "taint_source": ["CliLoc", [_loc(3, 'req.getParameter("u")'), 'req.getParameter("u")']],
                                "intermediate_vars": [],
                                "taint_sink": ["CliLoc", [sink_loc, sink_expr]],
                            },
                        },
                    }
                ],
                "errors": [],
            }
            safe_sha = digest(java_safe.encode("utf-8"))

            from v2.api.triage_gate import apply_integration_gate

            ref_dir, _, ref_row = _run_loopback_custom(
                root / "clean_refuted",
                java_text=java_safe,
                raw_scan=raw_scan_safe,
                model_answer_obj={
                    "explanation": "Biến input bị ghi đè hoàn toàn bởi hằng chuỗi cố định trước sink.",
                    "citations": [{"path": "DemoSql.java", "start_line": 4, "end_line": 4, "quote": ls[3], "sha256": safe_sha}],
                    "status": "REFUTED",
                    "fix_suggestion": "",
                },
                post_transform=apply_integration_gate,
            )
            self.assertEqual(ref_row["assessment"]["validated_status"], "REFUTED")
            self.assertEqual(ref_row["assessment"].get("independent_refutation_proof"), "UNCONDITIONAL_CONSTANT_SINK_FLOW")
            ref_rep = verify_http_capture.verify_run_http_captures(ref_dir, require_live_chat=False)
            self.assertEqual(ref_rep["capture_status"], "VERIFIED_COMPLETE", ref_rep["errors"])
            self.assertTrue(ref_rep["artifact_integrity_ok"])
            self.assertEqual(ref_rep["findings"][0]["integration_gate_verification"], "RECOMPUTED_EXACT_MATCH")
            _assert_tamper_fails("clean_refuted_missing_proof", ref_dir, lambda r: r["assessment"].pop("independent_refutation_proof", None))
            _assert_tamper_fails("clean_refuted_wrong_proof", ref_dir, lambda r: r["assessment"].__setitem__("independent_refutation_proof", "CWE22_CANONICAL_CONTAINMENT_GUARD"))

            und_empty_dir, _, und_empty_row = _run_loopback_custom(
                root / "clean_und_empty",
                java_text=java_safe,
                raw_scan=raw_scan_safe,
                model_answer_obj={
                    "explanation": "Không đủ bằng chứng để kết luận.",
                    "citations": [],
                    "status": "UNDETERMINED",
                    "fix_suggestion": "",
                },
            )
            self.assertEqual(und_empty_row["assessment"]["citation_check"], "NONE")
            und_e_rep = verify_http_capture.verify_run_http_captures(und_empty_dir, require_live_chat=False)
            self.assertEqual(und_e_rep["capture_status"], "VERIFIED_COMPLETE", und_e_rep["errors"])
            self.assertEqual(und_e_rep["findings"][0]["integration_gate_verification"], "RECOMPUTED_EXACT_MATCH")
            _assert_tamper_fails("und_empty_forged_cc_matched", und_empty_dir, lambda r: r["assessment"].__setitem__("citation_check", "MATCHED"))
            _assert_tamper_fails("und_empty_forged_proof", und_empty_dir, lambda r: r["assessment"].__setitem__("independent_refutation_proof", "UNCONDITIONAL_CONSTANT_SINK_FLOW"))

            und_cite_dir, _, und_cite_row = _run_loopback_custom(
                root / "clean_und_cite",
                java_text=java_safe,
                raw_scan=raw_scan_safe,
                model_answer_obj={
                    "explanation": "Cần kiểm tra thêm ngoài phạm vi snippet.",
                    "citations": [{"path": "DemoSql.java", "start_line": 4, "end_line": 4, "quote": ls[3], "sha256": safe_sha}],
                    "status": "UNDETERMINED",
                    "fix_suggestion": "",
                },
            )
            self.assertEqual(und_cite_row["assessment"]["citation_check"], "MATCHED")
            und_c_rep = verify_http_capture.verify_run_http_captures(und_cite_dir, require_live_chat=False)
            self.assertEqual(und_c_rep["capture_status"], "VERIFIED_COMPLETE", und_c_rep["errors"])
            self.assertEqual(und_c_rep["findings"][0]["integration_gate_verification"], "RECOMPUTED_EXACT_MATCH")

            # 4. Real apply_integration_gate post-gate downgrades (Gate-1 UNVERIFIED_HELPER_FLOW, Gate-2 UNVERIFIED_REFUTATION),
            # Layer-1 INVALID_CITATION strip, and explicit rejection of ungrounded hand-patched downgrades!

            java_helper = (
                "public class DemoSql {\n"
                "  void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt) throws Exception {\n"
                '    String input = req.getParameter("u");\n'
                "    String clean = ExternalUtil.transform(input);\n"
                '    stmt.executeQuery("SELECT * FROM users WHERE u = " + clean);\n'
                "  }\n"
                "}\n"
            )
            h_lke = java_helper.splitlines(keepends=True)
            h_ls = java_helper.splitlines()
            h_pt = lambda ln, col: {"line": ln, "col": col, "offset": sum(len(x.encode("utf-8")) for x in h_lke[: ln - 1]) + col - 1}
            h_loc = lambda ln, txt: {"path": "DemoSql.java", "start": h_pt(ln, h_ls[ln - 1].index(txt) + 1), "end": h_pt(ln, h_ls[ln - 1].index(txt) + 1 + len(txt.encode("utf-8")))}
            h_sink_expr = 'stmt.executeQuery("SELECT * FROM users WHERE u = " + clean)'
            h_sink_loc = h_loc(5, h_sink_expr)
            raw_scan_helper = {
                "results": [{
                    "check_id": "test.cwe89", "path": "DemoSql.java",
                    "start": h_sink_loc["start"], "end": h_sink_loc["end"],
                    "extra": {
                        "severity": "ERROR", "metadata": {"cwe": ["CWE-89"]}, "message": "SQLi",
                        "dataflow_trace": {
                            "taint_source": ["CliLoc", [h_loc(3, 'req.getParameter("u")'), 'req.getParameter("u")']],
                            "intermediate_vars": [],
                            "taint_sink": ["CliLoc", [h_sink_loc, h_sink_expr]],
                        },
                    },
                }], "errors": [],
            }
            helper_sha = digest(java_helper.encode("utf-8"))
            pg_dir, _, pg_row = _run_loopback_custom(
                root / "post_gate_helper",
                java_text=java_helper,
                raw_scan=raw_scan_helper,
                model_answer_obj={
                    "explanation": "Biến đi qua helper chưa xác minh.",
                    "citations": [{"path": "DemoSql.java", "start_line": 5, "end_line": 5, "quote": h_ls[4], "sha256": helper_sha}],
                    "status": "SUPPORTED",
                    "fix_suggestion": "Kiểm tra hàm helper.",
                },
                post_transform=apply_integration_gate,
            )
            self.assertEqual(pg_row["assessment"]["failure_kind"], "UNVERIFIED_HELPER_FLOW")
            pg_rep = verify_http_capture.verify_run_http_captures(pg_dir, require_live_chat=False)
            self.assertEqual(pg_rep["capture_status"], "VERIFIED_COMPLETE", pg_rep["errors"])
            self.assertEqual(pg_rep["findings"][0]["post_gate_downgrade_verification"], "RECOMPUTED_EXACT_MATCH")
            _assert_tamper_fails("pg_tamper_fix", pg_dir, lambda r: r["assessment"].__setitem__("fix_suggestion", "Tampered fix"))
            _assert_tamper_fails("pg_tamper_expl", pg_dir, lambda r: r["assessment"].__setitem__("explanation", "Arbitrary unrelated explanation"))
            _assert_tamper_fails(
                "pg_tamper_sync_dr_and_expl_codex_p1",
                pg_dir,
                lambda r: (
                    r["assessment"].__setitem__("downgrade_reason", "Human Review confirmed the finding safe."),
                    r["assessment"].__setitem__(
                        "explanation",
                        "Human Review confirmed the finding safe. (Model returned SUPPORTED; Human Review remains OPEN. Prior note: Biến đi qua helper chưa xác minh.)",
                    ),
                ),
            )
            _assert_tamper_fails("pg_tamper_cites_empty", pg_dir, lambda r: r["assessment"].__setitem__("citations", []))
            _assert_tamper_fails("pg_forged_upgrade_supported", pg_dir, lambda r: (r.__setitem__("validated_status", "SUPPORTED"), r["assessment"].__setitem__("status", "SUPPORTED"), r["assessment"].__setitem__("validated_status", "SUPPORTED")))

            # Real Layer-1 INVALID_CITATION (model emits non-matching quote) -> citations stripped to []
            l1_ic_dir, _, l1_ic_row = _run_loopback_custom(
                root / "layer1_inv_cite",
                java_text=java_safe,
                raw_scan=raw_scan_safe,
                model_answer_obj={
                    "explanation": "Model explanation.",
                    "citations": [{"path": "DemoSql.java", "start_line": 4, "end_line": 4, "quote": "non matching quote", "sha256": safe_sha}],
                    "status": "SUPPORTED",
                    "fix_suggestion": "Fix it.",
                },
                post_transform=apply_integration_gate,
            )
            self.assertEqual(l1_ic_row["assessment"]["failure_kind"], "INVALID_CITATION")
            self.assertEqual(l1_ic_row["assessment"]["citations"], [])
            self.assertEqual(verify_http_capture.verify_run_http_captures(l1_ic_dir, require_live_chat=False)["capture_status"], "VERIFIED_COMPLETE")
            _assert_tamper_fails("l1_ic_kept_bad_cite", l1_ic_dir, lambda r: r["assessment"].__setitem__("citations", [{"path": "DemoSql.java", "start_line": 4, "end_line": 4, "quote": ls[3], "sha256": safe_sha}]))

            # Ungrounded synthetic hand-patched downgrade on java_safe MUST FAIL CLOSED (cannot invent extCheck!)
            def _forged_synthetic_helper(_rec, ass):
                out = copy.deepcopy(ass)
                dr = "Blocked conclusive verdict due to unverified helper flow dependency: extCheck."
                orig_e = out["explanation"].strip()
                out["status"] = "UNDETERMINED"
                out["validated_status"] = "UNDETERMINED"
                out["validator_downgraded"] = True
                out["failure_kind"] = "UNVERIFIED_HELPER_FLOW"
                out["downgrade_reason"] = dr
                out["explanation"] = f"{dr} (Model returned {out['raw_model_status']}; Human Review remains OPEN. Prior note: {orig_e})"
                out["runtime"]["answer_validated"] = False
                out["runtime"]["failure_kind"] = "UNVERIFIED_HELPER_FLOW"
                out["runtime"]["validator_downgraded"] = True
                return out

            forged_pg_dir, _, _ = _run_loopback_custom(
                root / "forged_ungrounded_helper",
                java_text=java_safe,
                raw_scan=raw_scan_safe,
                model_answer_obj={
                    "explanation": "Model explanation.",
                    "citations": [{"path": "DemoSql.java", "start_line": 4, "end_line": 4, "quote": ls[3], "sha256": safe_sha}],
                    "status": "SUPPORTED",
                    "fix_suggestion": "Fix it.",
                },
                post_transform=_forged_synthetic_helper,
            )
            forged_rep = verify_http_capture.verify_run_http_captures(forged_pg_dir, require_live_chat=False)
            self.assertEqual(forged_rep["capture_status"], "FAILED")
            self.assertFalse(forged_rep["artifact_integrity_ok"])

            # 5. HTTP 500 error, malformed JSON, precheck_not_attempted, and PROMPT_TOO_LARGE
            err500_dir, _, _ = _run_loopback_custom(
                root / "http500_bind",
                java_text=java_safe,
                raw_scan=raw_scan_safe,
                chat_status=500,
                chat_body_bytes=b'{"error":"server exploded"}',
            )
            self.assertEqual(verify_http_capture.verify_run_http_captures(err500_dir, require_live_chat=False)["capture_status"], "VERIFIED_ERROR_OR_PARTIAL_CAPTURED")
            _assert_tamper_fails("http500_forged_cite", err500_dir, lambda r: r["assessment"].__setitem__("citations", [{"path": "DemoSql.java", "start_line": 4, "end_line": 4, "quote": ls[3], "sha256": safe_sha}]))
            _assert_tamper_fails("http500_forged_fix", err500_dir, lambda r: r["assessment"].__setitem__("fix_suggestion", "Fabricated fix"))

            mal_dir, _, _ = _run_loopback_custom(
                root / "malformed_json_bind",
                java_text=java_safe,
                raw_scan=raw_scan_safe,
                chat_status=200,
                chat_body_bytes=b'{"not valid json',
            )
            self.assertEqual(verify_http_capture.verify_run_http_captures(mal_dir, require_live_chat=False)["capture_status"], "VERIFIED_COMPLETE")
            _assert_tamper_fails("mal_del_raw_ms", mal_dir, lambda r: (r.pop("raw_model_status", None), r["assessment"].pop("raw_model_status", None)))

            pre_dir, _, _ = _run_loopback_custom(
                root / "precheck_oversize_bind",
                java_text=java_safe,
                raw_scan=raw_scan_safe,
                model_answer_obj={"explanation": "unused", "citations": [], "status": "UNDETERMINED", "fix_suggestion": ""},
                extra_issues=["prompt byte budget exceeded (40000 > 32000 bytes); inference aborted fail-closed"],
            )
            self.assertEqual(verify_http_capture.verify_run_http_captures(pre_dir, require_live_chat=False)["capture_status"], "VERIFIED_ERROR_OR_PARTIAL_CAPTURED")
            _assert_tamper_fails("precheck_forged_cite", pre_dir, lambda r: r["assessment"].__setitem__("citations", [{"path": "DemoSql.java", "start_line": 4, "end_line": 4, "quote": ls[3], "sha256": safe_sha}]))
            _assert_tamper_fails("precheck_forged_raw_ms", pre_dir, lambda r: (r.__setitem__("raw_model_status", "SUPPORTED"), r["assessment"].__setitem__("raw_model_status", "SUPPORTED")))

    def test_10_fsync_and_atomic_publish_fault_injection(self) -> None:
        """Simulated fault injection (not physical disk fault): fsync/publish failures never publish or clobber files."""
        import contextlib
        import errno
        import io

        def _cli(argv: list[str]) -> tuple[int, dict]:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = verify_http_capture.main(argv)
            return rc, json.loads(buf.getvalue())

        with tempfile.TemporaryDirectory(prefix="ntk_fsync_vhc_") as td:
            root = Path(td)
            triage_dir, _, _ = _build_real_loopback_v226_run(root / "clean_run", runtime_origin="unverified")
            # Foreign sibling temp file from another process must NEVER be deleted on error
            foreign_tmp = root / ".report.json.999999.deadbeef.tmp"
            foreign_tmp.write_bytes(b"other-process-temp")

            # 1. Fault-injected fsync errors: EIO, ENOSPC, EACCES/PermissionError
            for label, exc_obj in (
                ("fsync_eio", OSError(errno.EIO, "Simulated EIO during fsync")),
                ("fsync_enospc", OSError(errno.ENOSPC, "Simulated ENOSPC during fsync")),
                ("fsync_perm", PermissionError(errno.EACCES, "Simulated EACCES during fsync")),
            ):
                with self.subTest(case=label):
                    target = root / f"{label}.json"
                    with patch("v2.triage.verify_http_capture.os.fsync", side_effect=exc_obj):
                        rc, doc = _cli([str(triage_dir), "--minimum-findings", "1", "--output", str(target)])
                    self.assertEqual(rc, 2)
                    self.assertFalse(target.exists(), f"{label} must never publish target file")
                    self.assertEqual(list(root.glob(f".{target.name}.*.tmp")), [], f"{label} must clean its own temp")
                    self.assertTrue(foreign_tmp.exists(), f"{label} must not delete another process's temp file")
                    self.assertTrue(doc["verification_executed"])
                    self.assertTrue(doc["artifact_integrity_ok"])
                    self.assertTrue(doc["endpoint_reported_protocol_ok"])
                    self.assertEqual(doc["capture_status"], "VERIFIED_COMPLETE")
                    self.assertFalse(doc["report_write_ok"])
                    self.assertEqual(doc["report_write_status"], "OUTPUT_WRITE_IO_ERROR")
                    self.assertFalse(doc["cli_operation_ok"])

            # 2. Fault-injected os.link unsupported hardlink (EOPNOTSUPP/EXDEV/ENOSYS) & publish PermissionError
            for label, exc_obj in (
                ("link_eopnotsupp", OSError(getattr(errno, "EOPNOTSUPP", errno.EXDEV), "Hard links unsupported")),
                ("link_exdev", OSError(errno.EXDEV, "Cross-device link")),
                ("link_enosys", OSError(errno.ENOSYS, "Function not implemented")),
                ("link_perm", PermissionError(errno.EACCES, "Publish permission denied")),
            ):
                with self.subTest(case=label):
                    target = root / f"{label}.json"
                    with patch("v2.triage.verify_http_capture.os.link", side_effect=exc_obj):
                        rc, doc = _cli([str(triage_dir), "--minimum-findings", "1", "--output", str(target)])
                    self.assertEqual(rc, 2)
                    self.assertFalse(target.exists(), f"{label} must fail closed without non-atomic fallback")
                    self.assertEqual(list(root.glob(f".{target.name}.*.tmp")), [])
                    self.assertTrue(foreign_tmp.exists())
                    self.assertTrue(doc["artifact_integrity_ok"])
                    self.assertFalse(doc["report_write_ok"])
                    self.assertEqual(doc["report_write_status"], "OUTPUT_WRITE_IO_ERROR")
                    if label != "link_perm":
                        self.assertIn("ATOMIC_PUBLISH_UNSUPPORTED", doc["report_write_error"])

            # 3. Existing target preserved byte-for-byte even when os.link races with FileExistsError
            existing = root / "already_there.json"
            existing.write_bytes(b"SEALED_ORIGINAL_CONTENT\n")
            with patch("v2.triage.verify_http_capture.os.link", side_effect=FileExistsError("race")):
                rc_ex, doc_ex = _cli([str(triage_dir), "--minimum-findings", "1", "--output", str(existing)])
            self.assertEqual(rc_ex, 2)
            self.assertEqual(existing.read_bytes(), b"SEALED_ORIGINAL_CONTENT\n")
            self.assertEqual(doc_ex["report_write_status"], "REFUSED_EXISTING_OUTPUT")
            self.assertTrue(doc_ex["artifact_integrity_ok"])
            self.assertTrue(foreign_tmp.exists())

    def test_11_p1_downgrade_reason_and_p2_precheck_full_contract_matrix(self) -> None:
        """Complete 12-dimension assessment data contract matrix closing Codex P1, Codex P2, and sibling blind spots."""
        import time as _time
        from v2.api.qwen_triage import run_bounded_triage
        from v2.api.triage_gate import apply_integration_gate
        from v2.triage.store import ReviewStore

        def _make_java_bundle(root: Path, fname: str, java_text: str, src_ln: int, src_txt: str, sink_ln: int, sink_txt: str):
            src_root = root / "src"
            src_root.mkdir(parents=True, exist_ok=True)
            (src_root / fname).write_bytes(java_text.encode("utf-8"))
            lke = java_text.splitlines(keepends=True)
            ls = java_text.splitlines()
            pt = lambda ln, col: {"line": ln, "col": col, "offset": sum(len(x.encode("utf-8")) for x in lke[: ln - 1]) + col - 1}
            loc = lambda ln, txt: {"path": fname, "start": pt(ln, ls[ln - 1].index(txt) + 1), "end": pt(ln, ls[ln - 1].index(txt) + 1 + len(txt.encode("utf-8")))}
            raw_scan = {
                "results": [{
                    "check_id": "test.cwe89", "path": fname,
                    "start": loc(sink_ln, sink_txt)["start"], "end": loc(sink_ln, sink_txt)["end"],
                    "extra": {
                        "severity": "ERROR", "metadata": {"cwe": ["CWE-89"]}, "message": "SQLi",
                        "dataflow_trace": {
                            "taint_source": ["CliLoc", [loc(src_ln, src_txt), src_txt]],
                            "intermediate_vars": [],
                            "taint_sink": ["CliLoc", [loc(sink_ln, sink_txt), sink_txt]],
                        },
                    },
                }], "errors": [],
            }
            sp = {
                "origin": "recorded_capture_unsigned", "producer": "ntk-local-scan-capture",
                "source_capture_verified": True, "exit_capture_verified": True,
                "recorded_engine_exit": 0, "declared_engine_exit": None,
                "independently_attested": False, "manifest_path": "capture/scan-manifest.json",
                "manifest_sha256": "a" * 64,
            }
            bundle = collect(json.dumps(raw_scan), src_root, engine_exit=0, scan_provenance=sp)
            bundle["prompt_contract"] = "blind"
            bundle["records"][0]["prompt_contract"] = "blind"
            return src_root, bundle, ls

        def _run_real_pipeline(
            cdir: Path,
            bundle: dict,
            *,
            chat_status: int = 200,
            chat_body_bytes: bytes | None = None,
            model_answer: dict | None = None,
            apply_gate: bool = True,
        ) -> tuple[Path, dict, dict, list[str]]:
            rec = bundle["records"][0]
            model = "qwen3.5:9b-q4_K_M"
            model_digest = "56671c2ab9385f9cfcb404638e32cd62d88e3501d44822208363c010179a3c90"
            if chat_body_bytes is None:
                assert model_answer is not None
                chat_body_bytes = json.dumps({
                    "model": model, "created_at": "2026-11-26T07:00:00.000000Z",
                    "message": {"role": "assistant", "content": json.dumps(model_answer, ensure_ascii=False)},
                    "done": True, "done_reason": "stop", "eval_count": 24, "eval_duration": 100000000,
                }, ensure_ascii=False).encode("utf-8")
            tags_bytes = json.dumps({"models": [{"name": model, "model": model, "digest": model_digest, "size": 6550825550}]}).encode("utf-8")

            class _H(BaseHTTPRequestHandler):
                def log_message(self, *args):
                    pass

                def do_GET(self):
                    self.send_response(200, "OK")
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(tags_bytes)))
                    self.end_headers()
                    self.wfile.write(tags_bytes)

                def do_POST(self):
                    n = int(self.headers.get("Content-Length", "0"))
                    if n:
                        self.rfile.read(n)
                    self.send_response(chat_status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(chat_body_bytes)))
                    self.end_headers()
                    self.wfile.write(chat_body_bytes)

            srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
            th = threading.Thread(target=srv.serve_forever, daemon=True)
            th.start()
            try:
                tdir = cdir / "triage"
                tdir.mkdir(parents=True, exist_ok=True)
                cl = OllamaClient(
                    endpoint=f"http://127.0.0.1:{srv.server_port}",
                    model=model, timeout=10, runtime_origin="unverified",
                    io_log_dir=tdir / "llm_io", capture_root=tdir,
                )
                inv = cl.verify_model_installed()
                (tdir / "ollama-tags-check.json").write_text(json.dumps(inv, indent=2), encoding="utf-8")
                ass = cl.analyze(rec)
            finally:
                srv.shutdown()
                srv.server_close()
                th.join(timeout=2)

            if apply_gate:
                ass = apply_integration_gate(rec, ass)
            (tdir / "evidence.json").write_text(json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8")
            row = {
                "schema_version": SCHEMA_VERSION, "id": rec["id"], "alert_id": rec["alert_id"],
                "scan_sha256": rec["scan_sha256"], "finding_index": rec["finding_index"],
                "state": "OPEN", "human_review_state": "OPEN",
                "raw_model_status": ass.get("raw_model_status"),
                "validated_status": ass.get("validated_status"),
                "evidence": rec, "assessment": ass,
            }
            (tdir / "assessments.jsonl").write_text(json.dumps(row, ensure_ascii=False) + "\n", encoding="utf-8")
            st = ReviewStore(tdir / "review.sqlite")
            try:
                st.add(bundle, [ass])
                q_states = [item["state"] for item in st.queue()]
            finally:
                st.close()
            return tdir, rec, row, q_states

        with tempfile.TemporaryDirectory(prefix="ntk_p1p2_matrix_") as td:
            root = Path(td)

            def _assert_tamper_fails(label: str, src_dir: Path, mutator):
                d = root / f"tamper_{label}"
                shutil.copytree(src_dir, d)
                aj = d / "assessments.jsonl"
                r = json.loads(aj.read_text(encoding="utf-8").strip())
                mutator(r)
                aj.write_text(json.dumps(r, ensure_ascii=False) + "\n", encoding="utf-8")
                rn = verify_http_capture.verify_run_http_captures(d, require_live_chat=False)
                rs = verify_http_capture.verify_run_http_captures(d, require_live_chat=True)
                self.assertEqual(rn["capture_status"], "FAILED", f"{label} unexpectedly passed: {rn}")
                self.assertFalse(rn["artifact_integrity_ok"], label)
                self.assertFalse(rn["live_origin_verified"], label)
                self.assertEqual(rs["capture_status"], "FAILED", label)
                self.assertFalse(rs["artifact_integrity_ok"], label)
                self.assertFalse(rs["live_origin_verified"], label)

            # Dim 1 & 12: Clean validated assessment -> PASS; injecting stray downgrade_reason -> FAIL
            clean_dir, _, _ = _build_real_loopback_v226_run(root / "dim1_clean", runtime_origin="unverified")
            r_clean = verify_http_capture.verify_run_http_captures(clean_dir, require_live_chat=False)
            self.assertEqual(r_clean["capture_status"], "VERIFIED_COMPLETE", r_clean["errors"])
            self.assertTrue(r_clean["artifact_integrity_ok"])
            _assert_tamper_fails("clean_stray_downgrade_reason", clean_dir, lambda r: r["assessment"].__setitem__("downgrade_reason", "Human Review confirmed the finding safe."))
            _assert_tamper_fails("clean_missing_validated_status", clean_dir, lambda r: r["assessment"].pop("validated_status", None))

            # Dim 2, 3, 4, 5, 9: Real Gate-1 UNVERIFIED_HELPER_FLOW & Real Gate-2 UNVERIFIED_REFUTATION downgrades
            j_helper = (
                "public class HelperSql {\n"
                "  void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt) throws Exception {\n"
                '    String input = req.getParameter("u");\n'
                "    String clean = ExternalUtil.transform(input);\n"
                '    stmt.executeQuery("SELECT * FROM users WHERE u=" + clean);\n'
                "  }\n"
                "}\n"
            )
            _, hb, hls = _make_java_bundle(root / "dim2_g1", "HelperSql.java", j_helper, 3, 'req.getParameter("u")', 5, 'stmt.executeQuery("SELECT * FROM users WHERE u=" + clean)')
            hsha = hb["records"][0]["snapshots"]["HelperSql.java"]["sha256"]
            g1_dir, _, g1_row, g1_q = _run_real_pipeline(
                root / "dim2_g1", hb,
                model_answer={"explanation": "Input flows via ExternalUtil.transform.", "citations": [{"path": "HelperSql.java", "start_line": 5, "end_line": 5, "quote": hls[4], "sha256": hsha}], "status": "SUPPORTED", "fix_suggestion": "Use PreparedStatement."},
            )
            self.assertEqual(g1_row["assessment"]["raw_model_status"], "SUPPORTED")
            self.assertEqual(g1_row["assessment"]["validated_status"], "UNDETERMINED")
            self.assertEqual(g1_row["assessment"]["failure_kind"], "UNVERIFIED_HELPER_FLOW")
            self.assertEqual(g1_q, ["OPEN"])
            g1_rep = verify_http_capture.verify_run_http_captures(g1_dir, require_live_chat=False)
            self.assertEqual(g1_rep["capture_status"], "VERIFIED_COMPLETE", g1_rep["errors"])
            self.assertEqual(g1_rep["findings"][0]["post_gate_downgrade_verification"], "RECOMPUTED_EXACT_MATCH")

            # Codex P1 simultaneous downgrade_reason + explanation edit, +1 char append, unwrapped raw_expl + forged dr, failure_kind swap, missing validated_status, gate unavailable
            fake_hr = "Human Review confirmed the finding safe."
            _assert_tamper_fails("g1_codex_p1_sync_edit", g1_dir, lambda r: (r["assessment"].__setitem__("downgrade_reason", fake_hr), r["assessment"].__setitem__("explanation", f"{fake_hr} (Model returned SUPPORTED; Human Review remains OPEN. Prior note: Input flows via ExternalUtil.transform.)")))
            _assert_tamper_fails("g1_append_extra_prose", g1_dir, lambda r: (r["assessment"].__setitem__("downgrade_reason", r["assessment"]["downgrade_reason"] + " Safe."), r["assessment"].__setitem__("explanation", f"{r['assessment']['downgrade_reason']} Safe. (Model returned SUPPORTED; Human Review remains OPEN. Prior note: Input flows via ExternalUtil.transform.)")))
            _assert_tamper_fails("g1_unwrapped_expl_with_forged_dr", g1_dir, lambda r: (r["assessment"].__setitem__("downgrade_reason", fake_hr), r["assessment"].__setitem__("explanation", "Input flows via ExternalUtil.transform.")))
            _assert_tamper_fails("g1_swap_failure_kind", g1_dir, lambda r: (r["assessment"].__setitem__("failure_kind", "UNVERIFIED_REFUTATION"), r["assessment"]["runtime"].__setitem__("failure_kind", "UNVERIFIED_REFUTATION")))
            _assert_tamper_fails("g1_missing_validated_status", g1_dir, lambda r: r["assessment"].pop("validated_status", None))
            _assert_tamper_fails("g1_non_str_dr", g1_dir, lambda r: r["assessment"].__setitem__("downgrade_reason", ["bad"]))
            with patch.object(verify_http_capture, "_load_authoritative_integration_gate", return_value=None):
                gate_unavail = verify_http_capture.verify_run_http_captures(g1_dir, require_live_chat=False)
            self.assertEqual(gate_unavail["capture_status"], "FAILED")
            self.assertFalse(gate_unavail["artifact_integrity_ok"])
            self.assertEqual(gate_unavail["findings"][0]["post_gate_downgrade_verification"], "FAILED_GATE_UNAVAILABLE")

            # Real Gate-2 UNVERIFIED_REFUTATION downgrade (CustomGuardSql.java)
            j_guard = (
                "public class CustomGuardSql {\n"
                "  void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt) throws Exception {\n"
                '    String input = req.getParameter("u");\n'
                "    if (input.length() > 10) { return; }\n"
                '    stmt.executeQuery("SELECT * FROM users WHERE u=" + input);\n'
                "  }\n"
                "}\n"
            )
            _, gb, gls = _make_java_bundle(root / "dim2_g2", "CustomGuardSql.java", j_guard, 3, 'req.getParameter("u")', 5, 'stmt.executeQuery("SELECT * FROM users WHERE u=" + input)')
            gsha = gb["records"][0]["snapshots"]["CustomGuardSql.java"]["sha256"]
            g2_dir, _, g2_row, g2_q = _run_real_pipeline(
                root / "dim2_g2", gb,
                model_answer={"explanation": "Length check prevents SQL injection.", "citations": [{"path": "CustomGuardSql.java", "start_line": 4, "end_line": 4, "quote": gls[3], "sha256": gsha}], "status": "REFUTED", "fix_suggestion": ""},
            )
            self.assertEqual(g2_row["assessment"]["raw_model_status"], "REFUTED")
            self.assertEqual(g2_row["assessment"]["validated_status"], "UNDETERMINED")
            self.assertEqual(g2_row["assessment"]["failure_kind"], "UNVERIFIED_REFUTATION")
            self.assertEqual(g2_q, ["OPEN"])
            g2_rep = verify_http_capture.verify_run_http_captures(g2_dir, require_live_chat=False)
            self.assertEqual(g2_rep["capture_status"], "VERIFIED_COMPLETE", g2_rep["errors"])
            self.assertEqual(g2_rep["findings"][0]["post_gate_downgrade_verification"], "RECOMPUTED_EXACT_MATCH")
            _assert_tamper_fails("g2_codex_p1_sync_edit", g2_dir, lambda r: (r["assessment"].__setitem__("downgrade_reason", fake_hr), r["assessment"].__setitem__("explanation", f"{fake_hr} (Model returned REFUTED; Human Review remains OPEN. Prior note: Length check prevents SQL injection.)")))
            _assert_tamper_fails("g2_forged_refutation_proof_field", g2_dir, lambda r: r["assessment"].__setitem__("independent_refutation_proof", "UNCONDITIONAL_CONSTANT_SINK_FLOW"))

            # Dim 7: Precheck WITH .response.json sidecar (OllamaClient.analyze) -> Codex P2 + error-wrapper + prompt_version spoof
            _, pb, _ = _make_java_bundle(root / "dim7_pre", "HelperSql.java", j_helper, 3, 'req.getParameter("u")', 5, 'stmt.executeQuery("SELECT * FROM users WHERE u=" + clean)')
            pb["records"][0]["issues"].append("synthetic precheck issue")
            pre_dir, _, pre_row, pre_q = _run_real_pipeline(root / "dim7_pre", pb, model_answer={"explanation": "unused", "citations": [], "status": "UNDETERMINED", "fix_suggestion": ""})
            self.assertEqual(pre_q, ["OPEN"])
            pre_rep = verify_http_capture.verify_run_http_captures(pre_dir, require_live_chat=False)
            self.assertEqual(pre_rep["capture_status"], "VERIFIED_ERROR_OR_PARTIAL_CAPTURED", pre_rep["errors"])
            self.assertTrue(pre_rep["artifact_integrity_ok"])
            _assert_tamper_fails("p2_precheck_missing_validated_status", pre_dir, lambda r: r["assessment"].pop("validated_status", None))
            _assert_tamper_fails("p2_precheck_null_validated_status", pre_dir, lambda r: r["assessment"].__setitem__("validated_status", None))
            _assert_tamper_fails("p2_precheck_wrong_type_validated_status", pre_dir, lambda r: r["assessment"].__setitem__("validated_status", 123))
            _assert_tamper_fails("p2_precheck_drop_pv_and_vs", pre_dir, lambda r: (r["assessment"].pop("prompt_version", None), r["assessment"].pop("validated_status", None)))
            _assert_tamper_fails(
                "p1_precheck_forged_wrapper",
                pre_dir,
                lambda r: (
                    r["assessment"].__setitem__("validator_downgraded", True),
                    r["assessment"].__setitem__("downgrade_reason", fake_hr),
                    r["assessment"].__setitem__("explanation", f"{fake_hr} (Model returned None; Human Review remains OPEN. Prior note: {r['assessment']['explanation']})"),
                ),
            )
            _assert_tamper_fails("p1_precheck_stray_dr", pre_dir, lambda r: r["assessment"].__setitem__("downgrade_reason", fake_hr))

            # Dim 7b: Precheck WITHOUT .response.json sidecar (run_bounded_triage PROMPT_TOO_LARGE) -> Codex P2 + spoof v2.2.5 bypass
            bt_root = root / "dim7_bounded"
            bt_src, bt_bundle, _ = _make_java_bundle(bt_root, "HelperSql.java", j_helper, 3, 'req.getParameter("u")', 5, 'stmt.executeQuery("SELECT * FROM users WHERE u=" + clean)')
            eng = bt_root / "engine"
            eng.mkdir()
            raw_j = eng / "opengrep.json"
            raw_j.write_text(json.dumps(bt_bundle["raw_document"]), encoding="utf-8")
            rules_p = eng / "rules.snapshot.yml"
            rules_p.write_text("rules: []\n", encoding="utf-8")
            man_p = eng / "scan-manifest.json"
            r_sha = digest(rules_p.read_bytes())
            man_p.write_text(json.dumps({
                "schema_version": "1.0", "recorded_engine_exit": 0, "engine_exit": 0,
                "opengrep_json_sha256": digest(raw_j.read_bytes()),
                "rules_before_sha256": r_sha, "rules_after_sha256": r_sha,
                "source_hashes": {"HelperSql.java": digest((bt_src / "HelperSql.java").read_bytes())},
                "artifacts": {"rules.snapshot.yml": r_sha, "opengrep.json": digest(raw_j.read_bytes())},
            }), encoding="utf-8")
            bt_triage = bt_root / "triage"
            run_bounded_triage(
                source_root=bt_src, triage_dir=bt_triage, raw_json_path=raw_j, manifest_path=man_p,
                path_maps=[], rules_path=rules_p, no_llm=False, prompt_contract="blind",
                ollama_endpoint="http://127.0.0.1:11434", ollama_model="qwen3.5:9b-q4_K_M",
                ollama_timeout_seconds=1.0, runtime_origin="mock", deadline_mono=_time.monotonic() + 20.0,
                max_prompt_bytes=200,
            )
            self.assertEqual(verify_http_capture.verify_run_http_captures(bt_triage, require_live_chat=False)["capture_status"], "VERIFIED_ERROR_OR_PARTIAL_CAPTURED")
            _assert_tamper_fails("p2_bounded_precheck_missing_vs", bt_triage, lambda r: r["assessment"].pop("validated_status", None))
            _assert_tamper_fails("p2_bounded_precheck_spoof_v225_missing_vs", bt_triage, lambda r: (r["assessment"].__setitem__("prompt_version", ollama.PREVIOUS_V225_PROMPT_VERSION), r["assessment"].pop("validated_status", None)))
            _assert_tamper_fails("p2_bounded_precheck_spoof_legacy_steered_missing_vs", bt_triage, lambda r: (r["assessment"].__setitem__("prompt_version", ollama.LEGACY_STEERED_PROMPT_VERSION), r["assessment"].pop("validated_status", None)))
            _assert_tamper_fails("p1_bounded_precheck_stray_dr", bt_triage, lambda r: r["assessment"].__setitem__("downgrade_reason", fake_hr))

            # Dim 8: Error branches (HTTP 500, malformed JSON HTTP 200, Layer-1 UNVERIFIED_REFUTATION, unrecognized raw_model_status="MAYBE_SAFE")
            _, eb5, _ = _make_java_bundle(root / "dim8_500", "HelperSql.java", j_helper, 3, 'req.getParameter("u")', 5, 'stmt.executeQuery("SELECT * FROM users WHERE u=" + clean)')
            e5_dir, _, _, _ = _run_real_pipeline(root / "dim8_500", eb5, chat_status=500, chat_body_bytes=b'{"error":"server fail"}')
            self.assertEqual(verify_http_capture.verify_run_http_captures(e5_dir, require_live_chat=False)["capture_status"], "VERIFIED_ERROR_OR_PARTIAL_CAPTURED")
            _assert_tamper_fails("p2_http500_missing_vs", e5_dir, lambda r: r["assessment"].pop("validated_status", None))
            _assert_tamper_fails(
                "p1_http500_forged_wrapper",
                e5_dir,
                lambda r: (
                    r["assessment"].__setitem__("validator_downgraded", True),
                    r["assessment"].__setitem__("downgrade_reason", fake_hr),
                    r["assessment"].__setitem__("explanation", f"{fake_hr} (Model returned None; Human Review remains OPEN. Prior note: {r['assessment']['explanation']})"),
                ),
            )

            _, eb_bad, _ = _make_java_bundle(root / "dim8_mal", "HelperSql.java", j_helper, 3, 'req.getParameter("u")', 5, 'stmt.executeQuery("SELECT * FROM users WHERE u=" + clean)')
            mal_dir, _, _, _ = _run_real_pipeline(root / "dim8_mal", eb_bad, chat_status=200, chat_body_bytes=b'{"broken":')
            self.assertEqual(verify_http_capture.verify_run_http_captures(mal_dir, require_live_chat=False)["capture_status"], "VERIFIED_COMPLETE")
            _assert_tamper_fails("p2_mal_missing_vs", mal_dir, lambda r: r["assessment"].pop("validated_status", None))
            _assert_tamper_fails("p1_mal_stray_dr", mal_dir, lambda r: r["assessment"].__setitem__("downgrade_reason", fake_hr))

            # Layer-1 unrecognized raw_model_status="MAYBE_SAFE" -> Gate deterministic INVALID_SCHEMA status-contradiction downgrade PASSES; tampering dr FAILS!
            _, eb_inv, ils = _make_java_bundle(root / "dim8_inv_st", "HelperSql.java", j_helper, 3, 'req.getParameter("u")', 5, 'stmt.executeQuery("SELECT * FROM users WHERE u=" + clean)')
            isha = eb_inv["records"][0]["snapshots"]["HelperSql.java"]["sha256"]
            inv_dir, _, inv_row, _ = _run_real_pipeline(
                root / "dim8_inv_st", eb_inv,
                model_answer={"explanation": "Unclear.", "citations": [{"path": "HelperSql.java", "start_line": 5, "end_line": 5, "quote": ils[4], "sha256": isha}], "status": "MAYBE_SAFE", "fix_suggestion": ""},
            )
            self.assertEqual(inv_row["assessment"]["raw_model_status"], "MAYBE_SAFE")
            self.assertEqual(inv_row["assessment"]["validated_status"], "UNDETERMINED")
            self.assertTrue(inv_row["assessment"]["validator_downgraded"])
            self.assertEqual(verify_http_capture.verify_run_http_captures(inv_dir, require_live_chat=False)["capture_status"], "VERIFIED_COMPLETE")
            _assert_tamper_fails(
                "p1_inv_status_tamper_dr_and_expl",
                inv_dir,
                lambda r: (
                    r["assessment"].__setitem__("downgrade_reason", fake_hr),
                    r["assessment"].__setitem__("explanation", f"{fake_hr} (Model returned MAYBE_SAFE; Human Review remains OPEN. Prior note: invalid status)"),
                ),
            )

            # Layer-1 UNVERIFIED_REFUTATION with preserved verified citation -> tampering downgrade_reason FAILS!
            j_badsan = (
                "public class BadSan {\n"
                "  void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement st) throws Exception {\n"
                '    String input = req.getParameter("u");\n'
                "    String encoded = org.owasp.esapi.ESAPI.encoder().encodeForHTML(input);\n"
                '    st.executeQuery("SELECT * FROM t WHERE u=" + encoded);\n'
                "  }\n"
                "}\n"
            )
            _, bsb, bsls = _make_java_bundle(root / "dim8_l1_unref", "BadSan.java", j_badsan, 3, 'req.getParameter("u")', 5, 'st.executeQuery("SELECT * FROM t WHERE u=" + encoded)')
            bssha = bsb["records"][0]["snapshots"]["BadSan.java"]["sha256"]
            l1u_dir, _, l1u_row, _ = _run_real_pipeline(
                root / "dim8_l1_unref", bsb,
                model_answer={"explanation": "encodeForHTML is safe.", "citations": [{"path": "BadSan.java", "start_line": 4, "end_line": 4, "quote": bsls[3], "sha256": bssha}], "status": "REFUTED", "fix_suggestion": ""},
            )
            self.assertEqual(l1u_row["assessment"]["failure_kind"], "UNVERIFIED_REFUTATION")
            self.assertEqual(len(l1u_row["assessment"]["citations"]), 1)
            self.assertEqual(verify_http_capture.verify_run_http_captures(l1u_dir, require_live_chat=False)["capture_status"], "VERIFIED_COMPLETE")
            _assert_tamper_fails("p1_l1_unref_tamper_dr", l1u_dir, lambda r: r["assessment"].__setitem__("downgrade_reason", fake_hr))

            # Dim 10: Historical v2.2.4 grammar + evidence-grounded identifier verifier (direct unit & spoof checks)
            self.assertTrue(
                verify_http_capture._verify_historical_v224_helper_downgrade_reason(
                    "Blocked conclusive verdict due to unverified helper flow dependency: unverified_decisive_calls (['executeQuery']).",
                    hb["records"][0],
                )
            )
            self.assertFalse(
                verify_http_capture._verify_historical_v224_helper_downgrade_reason(
                    "Blocked conclusive verdict due to unverified helper flow dependency: unverified_decisive_calls (['nonExistentMethod']).",
                    hb["records"][0],
                )
            )
            self.assertFalse(
                verify_http_capture._verify_historical_v224_helper_downgrade_reason(
                    fake_hr,
                    hb["records"][0],
                )
            )
            self.assertFalse(
                verify_http_capture._verify_historical_v224_helper_downgrade_reason(
                    "Blocked conclusive verdict due to unverified helper flow dependency: Human Review confirmed safe.",
                    hb["records"][0],
                )
            )
            # Spoofing prompt_version=v2.2.4 on a v2.2.6 capture MUST FAIL CLOSED!
            _assert_tamper_fails(
                "dim10_spoof_v224_on_v226_downgrade",
                g1_dir,
                lambda r: r["assessment"].__setitem__("prompt_version", ollama.PREVIOUS_MINIMAL_SINGLELINE_PROMPT_VERSION),
            )

    def test_12_unified_integration_gate_invariants_across_all_assessment_branches(self) -> None:
        """Unified Integration Gate verification invariant matrix across clean, downgrade, Layer-1 reject, non-Gate, and multi-file root paths."""
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading
        from v2.api.triage_gate import apply_integration_gate
        from v2.triage.evidence import SCHEMA_VERSION, collect, digest
        from v2.triage.ollama import OllamaClient
        from v2.triage.store import ReviewStore

        def _make_multi_bundle(
            broot: Path,
            files: dict[str, str],
            primary_rel: str,
            src_ln: int,
            src_txt: str,
            sink_ln: int,
            sink_txt: str,
        ) -> tuple[Path, dict, list[str]]:
            src_root = broot / "src"
            src_root.mkdir(parents=True, exist_ok=True)
            for rel, txt in files.items():
                p = src_root / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(txt.encode("utf-8"))
            primary_txt = files[primary_rel]
            lke = primary_txt.splitlines(keepends=True)
            ls = primary_txt.splitlines()
            pt = lambda ln, col: {"line": ln, "col": col, "offset": sum(len(x.encode("utf-8")) for x in lke[: ln - 1]) + col - 1}
            loc = lambda ln, txt: {"path": primary_rel, "start": pt(ln, ls[ln - 1].index(txt) + 1), "end": pt(ln, ls[ln - 1].index(txt) + 1 + len(txt.encode("utf-8")))}
            raw_scan = {
                "results": [{
                    "check_id": "test.cwe89", "path": primary_rel,
                    "start": loc(sink_ln, sink_txt)["start"], "end": loc(sink_ln, sink_txt)["end"],
                    "extra": {
                        "severity": "ERROR", "metadata": {"cwe": ["CWE-89"]}, "message": "SQLi",
                        "dataflow_trace": {
                            "taint_source": ["CliLoc", [loc(src_ln, src_txt), src_txt]],
                            "intermediate_vars": [],
                            "taint_sink": ["CliLoc", [loc(sink_ln, sink_txt), sink_txt]],
                        },
                    },
                }], "errors": [],
            }
            sp = {
                "origin": "recorded_capture_unsigned", "producer": "ntk-local-scan-capture",
                "source_capture_verified": True, "exit_capture_verified": True,
                "recorded_engine_exit": 0, "declared_engine_exit": None,
                "independently_attested": False, "manifest_path": "capture/scan-manifest.json",
                "manifest_sha256": "a" * 64,
            }
            bundle = collect(json.dumps(raw_scan), src_root, engine_exit=0, scan_provenance=sp)
            bundle["prompt_contract"] = "blind"
            bundle["records"][0]["prompt_contract"] = "blind"
            return src_root, bundle, ls

        def _run_pair_same_raw_bytes(
            croot: Path,
            bundle_template: dict,
            *,
            model_answer: dict | None = None,
            chat_status: int = 200,
            chat_body_bytes: bytes | None = None,
        ) -> tuple[dict[str, Path], dict[str, dict], dict[str, list[str]], bool]:
            model = "qwen3.5:9b-q4_K_M"
            model_digest = "56671c2ab9385f9cfcb404638e32cd62d88e3501d44822208363c010179a3c90"
            if chat_body_bytes is None:
                assert model_answer is not None
                chat_body_bytes = json.dumps({
                    "model": model, "created_at": "2026-11-26T09:00:00.000000Z",
                    "message": {"role": "assistant", "content": json.dumps(model_answer, ensure_ascii=False)},
                    "done": True, "done_reason": "stop", "eval_count": 26, "eval_duration": 110000000,
                }, ensure_ascii=False).encode("utf-8")
            tags_bytes = json.dumps({"models": [{"name": model, "model": model, "digest": model_digest, "size": 6550825550}]}).encode("utf-8")

            class _H(BaseHTTPRequestHandler):
                def log_message(self, *args):
                    pass

                def do_GET(self):
                    self.send_response(200, "OK")
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(tags_bytes)))
                    self.end_headers()
                    self.wfile.write(tags_bytes)

                def do_POST(self):
                    n = int(self.headers.get("Content-Length", "0"))
                    if n:
                        self.rfile.read(n)
                    self.send_response(chat_status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(chat_body_bytes)))
                    self.end_headers()
                    self.wfile.write(chat_body_bytes)

            srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
            th = threading.Thread(target=srv.serve_forever, daemon=True)
            th.start()
            dirs: dict[str, Path] = {}
            rows: dict[str, dict] = {}
            queues: dict[str, list[str]] = {}
            raw_bins: dict[str, bytes] = {}
            try:
                for label, use_gate in (("pre_gate", False), ("gate_applied", True)):
                    b = copy.deepcopy(bundle_template)
                    rec = b["records"][0]
                    tdir = croot / label / "triage"
                    tdir.mkdir(parents=True, exist_ok=True)
                    cl = OllamaClient(
                        endpoint=f"http://127.0.0.1:{srv.server_port}",
                        model=model, timeout=10, runtime_origin="unverified",
                        io_log_dir=tdir / "llm_io", capture_root=tdir,
                    )
                    inv = cl.verify_model_installed()
                    (tdir / "ollama-tags-check.json").write_text(json.dumps(inv, indent=2), encoding="utf-8")
                    ass = cl.analyze(rec)
                    if use_gate:
                        ass = apply_integration_gate(rec, ass)
                    (tdir / "evidence.json").write_text(json.dumps(b, indent=2, ensure_ascii=False), encoding="utf-8")
                    row = {
                        "schema_version": SCHEMA_VERSION, "id": rec["id"], "alert_id": rec["alert_id"],
                        "scan_sha256": rec["scan_sha256"], "finding_index": rec["finding_index"],
                        "state": "OPEN", "human_review_state": "OPEN",
                        "raw_model_status": ass.get("raw_model_status"),
                        "validated_status": ass.get("validated_status"),
                        "evidence": rec, "assessment": ass,
                    }
                    (tdir / "assessments.jsonl").write_text(json.dumps(row, ensure_ascii=False) + "\n", encoding="utf-8")
                    st = ReviewStore(tdir / "review.sqlite")
                    try:
                        st.add(b, [ass])
                        queues[label] = [item["state"] for item in st.queue(include_all=True)]
                    finally:
                        st.close()
                    sid = verify_http_capture._safe_id(rec["id"])
                    rbin = tdir / "llm_io" / f"{sid}.response.body.bin"
                    raw_bins[label] = rbin.read_bytes() if rbin.exists() else b""
                    dirs[label] = tdir
                    rows[label] = row
            finally:
                srv.shutdown()
                srv.server_close()
                th.join(timeout=2)
            return dirs, rows, queues, (raw_bins["pre_gate"] == raw_bins["gate_applied"])

        with tempfile.TemporaryDirectory(prefix="ntk_unified_gate_") as td:
            root = Path(td)

            # 1. Exact Codex gate-controls.log pair: Gate-1 SUPPORTED on ExternalUtil.transform (same raw HTTP bytes)
            j_g1 = (
                "public class DemoSql {\n"
                "  void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt) throws Exception {\n"
                '    String input = req.getParameter("u");\n'
                "    String clean = ExternalUtil.transform(input);\n"
                '    stmt.executeQuery("SELECT * FROM users WHERE u = " + clean);\n'
                "  }\n"
                "}\n"
            )
            _, b_g1, ls_g1 = _make_multi_bundle(
                root / "g1_pair", {"DemoSql.java": j_g1}, "DemoSql.java",
                3, 'req.getParameter("u")', 5, 'stmt.executeQuery("SELECT * FROM users WHERE u = " + clean)',
            )
            sha_g1 = b_g1["records"][0]["snapshots"]["DemoSql.java"]["sha256"]
            d_g1, r_g1, q_g1, same_g1 = _run_pair_same_raw_bytes(
                root / "g1_pair", b_g1,
                model_answer={
                    "explanation": "Input flows via ExternalUtil.transform.",
                    "citations": [{"path": "DemoSql.java", "start_line": 5, "end_line": 5, "quote": ls_g1[4], "sha256": sha_g1}],
                    "status": "SUPPORTED", "fix_suggestion": "Use PreparedStatement.",
                },
            )
            self.assertTrue(same_g1)
            self.assertEqual(q_g1["pre_gate"], ["OPEN"])
            self.assertEqual(q_g1["gate_applied"], ["OPEN"])
            self.assertEqual(r_g1["pre_gate"]["assessment"]["validated_status"], "SUPPORTED")
            self.assertEqual(r_g1["gate_applied"]["assessment"]["validated_status"], "UNDETERMINED")
            self.assertEqual(r_g1["gate_applied"]["assessment"]["failure_kind"], "UNVERIFIED_HELPER_FLOW")

            rep_g1_pre = verify_http_capture.verify_run_http_captures(d_g1["pre_gate"], require_live_chat=False)
            self.assertEqual(rep_g1_pre["capture_status"], "FAILED", rep_g1_pre)
            self.assertFalse(rep_g1_pre["artifact_integrity_ok"])
            self.assertFalse(rep_g1_pre["live_origin_verified"])
            self.assertEqual(rep_g1_pre["findings"][0]["integration_gate_verification"], "FAILED_RECOMPUTATION_MISMATCH")
            self.assertEqual(rep_g1_pre["findings"][0]["post_gate_downgrade_verification"], "FAILED_RECOMPUTATION_MISMATCH")

            rep_g1_post = verify_http_capture.verify_run_http_captures(d_g1["gate_applied"], require_live_chat=False)
            self.assertEqual(rep_g1_post["capture_status"], "VERIFIED_COMPLETE", rep_g1_post["errors"])
            self.assertTrue(rep_g1_post["artifact_integrity_ok"])
            self.assertFalse(rep_g1_post["live_origin_verified"])
            self.assertEqual(rep_g1_post["findings"][0]["integration_gate_verification"], "RECOMPUTED_EXACT_MATCH")
            self.assertEqual(rep_g1_post["findings"][0]["post_gate_downgrade_verification"], "RECOMPUTED_EXACT_MATCH")

            # Spoofing prompt_version=v2.2.2 on pre-gate v2.2.6 capture MUST FAIL CLOSED (cannot reach HISTORICAL_PRE_GATE_CONTRACT)
            d_g1_spoof = root / "g1_spoof_v222"
            shutil.copytree(d_g1["pre_gate"], d_g1_spoof)
            sp_row = json.loads((d_g1_spoof / "assessments.jsonl").read_text("utf-8").strip())
            sp_row["assessment"]["prompt_version"] = ollama.PREVIOUS_CANONICAL_PROMPT_VERSION
            sp_row["assessment"]["runtime"]["prompt_version"] = ollama.PREVIOUS_CANONICAL_PROMPT_VERSION
            (d_g1_spoof / "assessments.jsonl").write_text(json.dumps(sp_row, ensure_ascii=False) + "\n", encoding="utf-8")
            rep_spoof_v222 = verify_http_capture.verify_run_http_captures(d_g1_spoof, require_live_chat=False)
            self.assertEqual(rep_spoof_v222["capture_status"], "FAILED")
            self.assertFalse(rep_spoof_v222["artifact_integrity_ok"])

            # 2. Sibling Gate-2 pair: REFUTED on unused Integer.parseInt (Layer-1 accepts, Gate-2 downgrades)
            j_g2 = (
                "public class VulnSql {\n"
                "  void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt) throws Exception {\n"
                '    String u = req.getParameter("u");\n'
                '    int unused = Integer.parseInt("1");\n'
                '    stmt.executeQuery("SELECT * FROM users WHERE u = " + u);\n'
                "  }\n"
                "}\n"
            )
            _, b_g2, ls_g2 = _make_multi_bundle(
                root / "g2_pair", {"VulnSql.java": j_g2}, "VulnSql.java",
                3, 'req.getParameter("u")', 5, 'stmt.executeQuery("SELECT * FROM users WHERE u = " + u)',
            )
            sha_g2 = b_g2["records"][0]["snapshots"]["VulnSql.java"]["sha256"]
            d_g2, r_g2, _, same_g2 = _run_pair_same_raw_bytes(
                root / "g2_pair", b_g2,
                model_answer={
                    "explanation": "Claims Integer.parseInt protects query.",
                    "citations": [{"path": "VulnSql.java", "start_line": 4, "end_line": 4, "quote": ls_g2[3], "sha256": sha_g2}],
                    "status": "REFUTED", "fix_suggestion": "",
                },
            )
            self.assertTrue(same_g2)
            self.assertEqual(r_g2["pre_gate"]["assessment"]["validated_status"], "REFUTED")
            self.assertEqual(r_g2["gate_applied"]["assessment"]["validated_status"], "UNDETERMINED")
            self.assertEqual(r_g2["gate_applied"]["assessment"]["failure_kind"], "UNVERIFIED_REFUTATION")
            rep_g2_pre = verify_http_capture.verify_run_http_captures(d_g2["pre_gate"], require_live_chat=False)
            self.assertEqual(rep_g2_pre["capture_status"], "FAILED", rep_g2_pre)
            self.assertFalse(rep_g2_pre["artifact_integrity_ok"])
            self.assertEqual(rep_g2_pre["findings"][0]["integration_gate_verification"], "FAILED_RECOMPUTATION_MISMATCH")
            rep_g2_post = verify_http_capture.verify_run_http_captures(d_g2["gate_applied"], require_live_chat=False)
            self.assertEqual(rep_g2_post["capture_status"], "VERIFIED_COMPLETE", rep_g2_post["errors"])
            self.assertEqual(rep_g2_post["findings"][0]["integration_gate_verification"], "RECOMPUTED_EXACT_MATCH")
            self.assertEqual(rep_g2_post["findings"][0]["post_gate_downgrade_verification"], "RECOMPUTED_EXACT_MATCH")

            # 3. Clean REFUTED proof pair (SafeSql constant overwrite): pre-gate (missing proof) FAILS, gate-applied PASSES
            j_safe = (
                "public class SafeSql {\n"
                "  void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt) throws Exception {\n"
                '    String u = req.getParameter("u");\n'
                '    u = "const_safe";\n'
                '    stmt.executeQuery("SELECT * FROM users WHERE u = " + u);\n'
                "  }\n"
                "}\n"
            )
            _, b_safe, ls_safe = _make_multi_bundle(
                root / "safe_ref_pair", {"SafeSql.java": j_safe}, "SafeSql.java",
                3, 'req.getParameter("u")', 5, 'stmt.executeQuery("SELECT * FROM users WHERE u = " + u)',
            )
            sha_safe = b_safe["records"][0]["snapshots"]["SafeSql.java"]["sha256"]
            d_safe, r_safe, _, same_safe = _run_pair_same_raw_bytes(
                root / "safe_ref_pair", b_safe,
                model_answer={
                    "explanation": "u overwritten by constant literal.",
                    "citations": [{"path": "SafeSql.java", "start_line": 4, "end_line": 4, "quote": ls_safe[3], "sha256": sha_safe}],
                    "status": "REFUTED", "fix_suggestion": "",
                },
            )
            self.assertTrue(same_safe)
            self.assertIsNone(r_safe["pre_gate"]["assessment"].get("independent_refutation_proof"))
            self.assertEqual(r_safe["gate_applied"]["assessment"].get("independent_refutation_proof"), "UNCONDITIONAL_CONSTANT_SINK_FLOW")
            rep_safe_pre = verify_http_capture.verify_run_http_captures(d_safe["pre_gate"], require_live_chat=False)
            self.assertEqual(rep_safe_pre["capture_status"], "FAILED", rep_safe_pre)
            self.assertEqual(rep_safe_pre["findings"][0]["integration_gate_verification"], "FAILED_RECOMPUTATION_MISMATCH")
            rep_safe_post = verify_http_capture.verify_run_http_captures(d_safe["gate_applied"], require_live_chat=False)
            self.assertEqual(rep_safe_post["capture_status"], "VERIFIED_COMPLETE", rep_safe_post["errors"])
            self.assertEqual(rep_safe_post["findings"][0]["integration_gate_verification"], "RECOMPUTED_EXACT_MATCH")
            self.assertEqual(rep_safe_post["findings"][0]["post_gate_downgrade_verification"], "NOT_APPLICABLE")

            # 4. Clean SUPPORTED + Clean UNDETERMINED: Gate-unavailable fails closed, forged proof/flag rejected
            clean_dir, _, _ = _build_real_loopback_v226_run(root / "clean_sup", runtime_origin="unverified")
            rep_clean = verify_http_capture.verify_run_http_captures(clean_dir, require_live_chat=False)
            self.assertEqual(rep_clean["capture_status"], "VERIFIED_COMPLETE", rep_clean["errors"])
            self.assertEqual(rep_clean["findings"][0]["integration_gate_verification"], "RECOMPUTED_EXACT_MATCH")
            self.assertEqual(rep_clean["findings"][0]["post_gate_downgrade_verification"], "NOT_APPLICABLE")
            with patch.object(verify_http_capture, "_load_authoritative_integration_gate", return_value=None):
                rep_clean_nogate = verify_http_capture.verify_run_http_captures(clean_dir, require_live_chat=False)
            self.assertEqual(rep_clean_nogate["capture_status"], "FAILED")
            self.assertFalse(rep_clean_nogate["artifact_integrity_ok"])
            self.assertEqual(rep_clean_nogate["findings"][0]["integration_gate_verification"], "FAILED_GATE_UNAVAILABLE")

            for label, mut in (
                ("clean_sup_forged_proof", lambda r: r["assessment"].__setitem__("independent_refutation_proof", "UNCONDITIONAL_CONSTANT_SINK_FLOW")),
                ("clean_sup_forged_supports_true", lambda r: r["assessment"].__setitem__("supports_security_claim_verified", True)),
            ):
                cd = root / label
                shutil.copytree(clean_dir, cd)
                rr = json.loads((cd / "assessments.jsonl").read_text("utf-8").strip())
                mut(rr)
                (cd / "assessments.jsonl").write_text(json.dumps(rr, ensure_ascii=False) + "\n", encoding="utf-8")
                rr_rep = verify_http_capture.verify_run_http_captures(cd, require_live_chat=False)
                self.assertEqual(rr_rep["capture_status"], "FAILED", label)
                self.assertFalse(rr_rep["artifact_integrity_ok"], label)

            # 5. Layer-1 rejected unified Gate pairs: MAYBE_SAFE & UNVERIFIED_REFUTATION (pre-gate FAILS, gate-applied PASSES)
            d_ms, _, _, same_ms = _run_pair_same_raw_bytes(
                root / "l1_maybe_safe_pair", b_g1,
                model_answer={"explanation": "Unclear.", "citations": [], "status": "MAYBE_SAFE", "fix_suggestion": ""},
            )
            self.assertTrue(same_ms)
            rep_ms_pre = verify_http_capture.verify_run_http_captures(d_ms["pre_gate"], require_live_chat=False)
            self.assertEqual(rep_ms_pre["capture_status"], "FAILED", rep_ms_pre)
            self.assertFalse(rep_ms_pre["artifact_integrity_ok"])
            rep_ms_post = verify_http_capture.verify_run_http_captures(d_ms["gate_applied"], require_live_chat=False)
            self.assertEqual(rep_ms_post["capture_status"], "VERIFIED_COMPLETE", rep_ms_post["errors"])
            self.assertEqual(rep_ms_post["findings"][0]["integration_gate_verification"], "RECOMPUTED_EXACT_MATCH")
            self.assertEqual(rep_ms_post["findings"][0]["post_gate_downgrade_verification"], "RECOMPUTED_EXACT_MATCH")

            j_badsan = (
                "public class BadSan {\n"
                "  void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement st) throws Exception {\n"
                '    String input = req.getParameter("u");\n'
                "    String encoded = org.owasp.esapi.ESAPI.encoder().encodeForHTML(input);\n"
                '    st.executeQuery("SELECT * FROM t WHERE u=" + encoded);\n'
                "  }\n"
                "}\n"
            )
            _, b_bs, ls_bs = _make_multi_bundle(
                root / "l1_unref_pair", {"BadSan.java": j_badsan}, "BadSan.java",
                3, 'req.getParameter("u")', 5, 'st.executeQuery("SELECT * FROM t WHERE u=" + encoded)',
            )
            sha_bs = b_bs["records"][0]["snapshots"]["BadSan.java"]["sha256"]
            d_bs, _, _, same_bs = _run_pair_same_raw_bytes(
                root / "l1_unref_pair", b_bs,
                model_answer={
                    "explanation": "encodeForHTML neutralizes input.",
                    "citations": [{"path": "BadSan.java", "start_line": 4, "end_line": 4, "quote": ls_bs[3], "sha256": sha_bs}],
                    "status": "REFUTED", "fix_suggestion": "",
                },
            )
            self.assertTrue(same_bs)
            rep_bs_pre = verify_http_capture.verify_run_http_captures(d_bs["pre_gate"], require_live_chat=False)
            self.assertEqual(rep_bs_pre["capture_status"], "FAILED", rep_bs_pre)
            self.assertFalse(rep_bs_pre["artifact_integrity_ok"])
            rep_bs_post = verify_http_capture.verify_run_http_captures(d_bs["gate_applied"], require_live_chat=False)
            self.assertEqual(rep_bs_post["capture_status"], "VERIFIED_COMPLETE", rep_bs_post["errors"])
            self.assertEqual(rep_bs_post["findings"][0]["integration_gate_verification"], "RECOMPUTED_EXACT_MATCH")
            # Deleting downgrade_reason from gate-applied Layer-1 UNVERIFIED_REFUTATION MUST FAIL!
            d_bs_nodr = root / "l1_unref_nodr"
            shutil.copytree(d_bs["gate_applied"], d_bs_nodr)
            bs_r = json.loads((d_bs_nodr / "assessments.jsonl").read_text("utf-8").strip())
            bs_r["assessment"].pop("downgrade_reason", None)
            (d_bs_nodr / "assessments.jsonl").write_text(json.dumps(bs_r, ensure_ascii=False) + "\n", encoding="utf-8")
            self.assertEqual(verify_http_capture.verify_run_http_captures(d_bs_nodr, require_live_chat=False)["capture_status"], "FAILED")

            # 6. Non-Gate branches (precheck, HTTP 500, HTTP 200 parse fail) MUST NOT invoke Integration Gate unconditionally
            b_pre = copy.deepcopy(b_g1)
            b_pre["records"][0]["issues"].append("synthetic precheck issue")
            d_pre, _, _, _ = _run_pair_same_raw_bytes(
                root / "nongate_precheck", b_pre,
                model_answer={"explanation": "unused", "citations": [], "status": "UNDETERMINED", "fix_suggestion": ""},
            )
            d_500, _, _, _ = _run_pair_same_raw_bytes(
                root / "nongate_http500", b_g1,
                chat_status=500, chat_body_bytes=b'{"error":"boom"}',
            )
            d_mal, _, _, _ = _run_pair_same_raw_bytes(
                root / "nongate_mal200", b_g1,
                chat_status=200, chat_body_bytes=b'{"broken":',
            )
            with patch.object(
                verify_http_capture,
                "_load_authoritative_integration_gate",
                side_effect=AssertionError("Gate must not be called on non-Gate branches"),
            ):
                r_pre = verify_http_capture.verify_run_http_captures(d_pre["pre_gate"], require_live_chat=False)
                r_500 = verify_http_capture.verify_run_http_captures(d_500["pre_gate"], require_live_chat=False)
                r_mal = verify_http_capture.verify_run_http_captures(d_mal["pre_gate"], require_live_chat=False)
            self.assertEqual(r_pre["capture_status"], "VERIFIED_ERROR_OR_PARTIAL_CAPTURED", r_pre["errors"])
            self.assertEqual(r_pre["findings"][0]["integration_gate_verification"], "NOT_APPLICABLE")
            self.assertEqual(r_500["capture_status"], "VERIFIED_ERROR_OR_PARTIAL_CAPTURED", r_500["errors"])
            self.assertEqual(r_500["findings"][0]["integration_gate_verification"], "NOT_APPLICABLE")
            self.assertEqual(r_mal["capture_status"], "VERIFIED_COMPLETE", r_mal["errors"])
            self.assertEqual(r_mal["findings"][0]["integration_gate_verification"], "NOT_APPLICABLE")

            # 7. Multi-file source root portability control (exact reproduction of Codex gate-controls.log multifile_replay)
            j_entry = (
                "package demo;\n"
                "public class Entry {\n"
                "  void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt) throws Exception {\n"
                '    String input = req.getParameter("u");\n'
                "    String clean = String.valueOf(input);\n"
                '    stmt.executeQuery("SELECT * FROM users WHERE u = " + clean);\n'
                "  }\n"
                "}\n"
            )
            j_shadow = (
                "package demo;\n"
                "class String {\n"
                "  static java.lang.String valueOf(java.lang.String s) { return s; }\n"
                "}\n"
            )
            mf_src, b_mf, ls_mf = _make_multi_bundle(
                root / "multifile_ctrl",
                {"demo/Entry.java": j_entry, "demo/String.java": j_shadow},
                "demo/Entry.java",
                4, 'req.getParameter("u")', 6, 'stmt.executeQuery("SELECT * FROM users WHERE u = " + clean)',
            )
            sha_mf = b_mf["records"][0]["snapshots"]["demo/Entry.java"]["sha256"]
            d_mf, r_mf, _, same_mf = _run_pair_same_raw_bytes(
                root / "multifile_ctrl", b_mf,
                model_answer={
                    "explanation": "Input flows through shadowed String.valueOf.",
                    "citations": [{"path": "demo/Entry.java", "start_line": 6, "end_line": 6, "quote": ls_mf[5], "sha256": sha_mf}],
                    "status": "SUPPORTED", "fix_suggestion": "Use PreparedStatement.",
                },
            )
            self.assertTrue(same_mf)
            self.assertEqual(r_mf["gate_applied"]["assessment"]["failure_kind"], "UNVERIFIED_HELPER_FLOW")
            # Pre-gate SUPPORTED fails; gate-applied passes with source root present
            mf_pre = verify_http_capture.verify_run_http_captures(d_mf["pre_gate"], require_live_chat=False)
            self.assertEqual(mf_pre["capture_status"], "FAILED")
            self.assertEqual(mf_pre["findings"][0]["integration_gate_verification"], "FAILED_RECOMPUTATION_MISMATCH")
            ev_sha_before = digest((d_mf["gate_applied"] / "evidence.json").read_bytes())
            mf_present = verify_http_capture.verify_run_http_captures(d_mf["gate_applied"], require_live_chat=False)
            self.assertEqual(mf_present["capture_status"], "VERIFIED_COMPLETE", mf_present["errors"])
            self.assertEqual(mf_present["findings"][0]["integration_gate_verification"], "RECOMPUTED_EXACT_MATCH")
            # Temporarily move whole source root away -> evidence SHA-256 unchanged, Layer-1 check_current fails closed FIRST!
            moved_src = root / "multifile_ctrl" / "src_moved"
            mf_src.rename(moved_src)
            try:
                self.assertEqual(digest((d_mf["gate_applied"] / "evidence.json").read_bytes()), ev_sha_before)
                mf_absent = verify_http_capture.verify_run_http_captures(d_mf["gate_applied"], require_live_chat=False)
                self.assertEqual(mf_absent["capture_status"], "FAILED")
                self.assertFalse(mf_absent["artifact_integrity_ok"])
                self.assertEqual(mf_absent["findings"][0]["layer1_verification"], "FAILED_SOURCE_UNAVAILABLE_OR_DRIFTED")
                self.assertEqual(mf_absent["findings"][0]["integration_gate_verification"], "FAILED_LAYER1_SOURCE_UNAVAILABLE")
                self.assertEqual(mf_absent["findings"][0]["post_gate_downgrade_verification"], "FAILED_LAYER1_SOURCE_UNAVAILABLE")
            finally:
                moved_src.rename(mf_src)
            # Move ONLY sibling helper demo/String.java while snapshot file demo/Entry.java stays intact ->
            # Layer-1 passes (RECOMPUTED_EXACT_MATCH), Integration Gate loses sibling class -> FAILED_RECOMPUTATION_MISMATCH!
            sib_file = mf_src / "demo" / "String.java"
            sib_moved = root / "multifile_ctrl" / "String.java.moved"
            sib_file.rename(sib_moved)
            try:
                self.assertEqual(digest((d_mf["gate_applied"] / "evidence.json").read_bytes()), ev_sha_before)
                mf_sib_absent = verify_http_capture.verify_run_http_captures(d_mf["gate_applied"], require_live_chat=False)
                self.assertEqual(mf_sib_absent["capture_status"], "FAILED")
                self.assertFalse(mf_sib_absent["artifact_integrity_ok"])
                self.assertEqual(mf_sib_absent["findings"][0]["layer1_verification"], "RECOMPUTED_EXACT_MATCH")
                self.assertEqual(mf_sib_absent["findings"][0]["integration_gate_verification"], "FAILED_RECOMPUTATION_MISMATCH")
                self.assertEqual(mf_sib_absent["findings"][0]["post_gate_downgrade_verification"], "FAILED_RECOMPUTATION_MISMATCH")
            finally:
                sib_moved.rename(sib_file)
            mf_restored = verify_http_capture.verify_run_http_captures(d_mf["gate_applied"], require_live_chat=False)
            self.assertEqual(mf_restored["capture_status"], "VERIFIED_COMPLETE", mf_restored["errors"])
            self.assertEqual(mf_restored["findings"][0]["layer1_verification"], "RECOMPUTED_EXACT_MATCH")
            self.assertEqual(mf_restored["findings"][0]["integration_gate_verification"], "RECOMPUTED_EXACT_MATCH")

    def test_13_layer1_binding_invariants_across_all_transitions_and_trust_boundaries(self) -> None:
        """Exhaustive Layer-1 + Gate independent binding matrix closing P1-LAYER1-ASSESSMENT-BINDING (Groups A-F, H)."""
        from v2.api.triage_gate import apply_integration_gate
        from v2.triage.evidence import SCHEMA_VERSION, collect, digest
        from v2.triage.ollama import (
            OllamaClient,
            PREVIOUS_CANONICAL_PROMPT_VERSION,
            PREVIOUS_MINIMAL_SINGLELINE_PROMPT_VERSION,
            PREVIOUS_V225_PROMPT_VERSION,
            PROMPT_SERIALIZER_FINGERPRINTS,
            request_payload_for_version,
            undecided,
        )

        model = "qwen3.5:9b-q4_K_M"
        model_digest = "56671c2ab9385f9cfcb404638e32cd62d88e3501d44822208363c010179a3c90"
        tags_bytes = json.dumps({"models": [{"name": model, "model": model, "digest": model_digest, "size": 6550825550}]}).encode("utf-8")

        def _make_bundle(broot: Path, filename: str, java_text: str, src_ln: int, src_txt: str, sink_ln: int, sink_txt: str):
            src_root = broot / "src"
            src_root.mkdir(parents=True, exist_ok=True)
            (src_root / filename).write_bytes(java_text.encode("utf-8"))
            lke = java_text.splitlines(keepends=True)
            ls = java_text.splitlines()
            pt = lambda ln, col: {"line": ln, "col": col, "offset": sum(len(x.encode("utf-8")) for x in lke[: ln - 1]) + col - 1}
            loc = lambda ln, txt: {"path": filename, "start": pt(ln, ls[ln - 1].index(txt) + 1), "end": pt(ln, ls[ln - 1].index(txt) + 1 + len(txt.encode("utf-8")))}
            raw_scan = {
                "results": [{
                    "check_id": "test.cwe89", "path": filename,
                    "start": loc(sink_ln, sink_txt)["start"], "end": loc(sink_ln, sink_txt)["end"],
                    "extra": {
                        "severity": "ERROR", "metadata": {"cwe": ["CWE-89"]}, "message": "SQLi",
                        "dataflow_trace": {
                            "taint_source": ["CliLoc", [loc(src_ln, src_txt), src_txt]],
                            "intermediate_vars": [],
                            "taint_sink": ["CliLoc", [loc(sink_ln, sink_txt), sink_txt]],
                        },
                    },
                }], "errors": [],
            }
            sp = {
                "origin": "recorded_capture_unsigned", "producer": "ntk-local-scan-capture",
                "source_capture_verified": True, "exit_capture_verified": True,
                "recorded_engine_exit": 0, "declared_engine_exit": None,
                "independently_attested": False, "manifest_path": "capture/scan-manifest.json",
                "manifest_sha256": "a" * 64,
            }
            bundle = collect(json.dumps(raw_scan), src_root, engine_exit=0, scan_provenance=sp)
            bundle["prompt_contract"] = "blind"
            bundle["records"][0]["prompt_contract"] = "blind"
            return src_root, bundle, ls

        def _capture_run(
            croot: Path,
            bundle_template: dict,
            *,
            envelope_obj: dict | None = None,
            chat_status: int = 200,
            chat_body_bytes: bytes | None = None,
            use_gate: bool = True,
            extra_issues: list[str] | None = None,
        ) -> tuple[Path, dict, dict]:
            b = copy.deepcopy(bundle_template)
            rec = b["records"][0]
            if extra_issues:
                rec["issues"].extend(extra_issues)
            if chat_body_bytes is None:
                assert envelope_obj is not None
                chat_body_bytes = json.dumps(envelope_obj, ensure_ascii=False).encode("utf-8")

            class _H(BaseHTTPRequestHandler):
                def log_message(self, *args):
                    pass

                def do_GET(self):
                    self.send_response(200, "OK")
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(tags_bytes)))
                    self.end_headers()
                    self.wfile.write(tags_bytes)

                def do_POST(self):
                    n = int(self.headers.get("Content-Length", "0"))
                    if n:
                        self.rfile.read(n)
                    self.send_response(chat_status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(chat_body_bytes)))
                    self.end_headers()
                    self.wfile.write(chat_body_bytes)

            srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
            th = threading.Thread(target=srv.serve_forever, daemon=True)
            th.start()
            tdir = croot / "triage"
            tdir.mkdir(parents=True, exist_ok=True)
            try:
                cl = OllamaClient(
                    endpoint=f"http://127.0.0.1:{srv.server_port}",
                    model=model, timeout=10, runtime_origin="unverified",
                    io_log_dir=tdir / "llm_io", capture_root=tdir,
                )
                inv = cl.verify_model_installed()
                (tdir / "ollama-tags-check.json").write_text(json.dumps(inv, indent=2), encoding="utf-8")
                ass = cl.analyze(rec)
                if use_gate:
                    ass = apply_integration_gate(rec, ass)
            finally:
                srv.shutdown()
                srv.server_close()
                th.join(timeout=2)
            (tdir / "evidence.json").write_text(json.dumps(b, indent=2, ensure_ascii=False), encoding="utf-8")
            row = {
                "schema_version": SCHEMA_VERSION, "id": rec["id"], "alert_id": rec["alert_id"],
                "scan_sha256": rec["scan_sha256"], "finding_index": rec["finding_index"],
                "state": "OPEN", "human_review_state": "OPEN",
                "raw_model_status": ass.get("raw_model_status"),
                "validated_status": ass.get("validated_status"),
                "evidence": rec, "assessment": ass,
            }
            (tdir / "assessments.jsonl").write_text(json.dumps(row, ensure_ascii=False) + "\n", encoding="utf-8")
            return tdir, rec, row

        def _env(content_obj: dict, *, done: bool = True, done_reason: str | None = "stop", resp_model: str = model) -> dict:
            return {
                "model": resp_model,
                "created_at": "2026-11-26T09:00:00.000000Z",
                "message": {"role": "assistant", "content": json.dumps(content_obj, ensure_ascii=False)},
                "done": done,
                "done_reason": done_reason,
                "eval_count": 26,
                "eval_duration": 110000000,
            }

        def _clone_and_edit(src_dir: Path, dst_dir: Path, rec_id: str, mutator):
            shutil.copytree(src_dir, dst_dir)
            sid = verify_http_capture._safe_id(rec_id)
            rp = dst_dir / "llm_io" / f"{sid}.response.json"
            aj = dst_dir / "assessments.jsonl"
            rdoc = json.loads(rp.read_text(encoding="utf-8"))
            row = json.loads(aj.read_text(encoding="utf-8").strip())
            mutator(dst_dir, rdoc, row)
            rp.write_text(json.dumps(rdoc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            aj.write_text(json.dumps(row, ensure_ascii=False) + "\n", encoding="utf-8")
            return verify_http_capture.verify_run_http_captures(dst_dir, require_live_chat=False)

        def _snapshot_other_files(tdir: Path, rec_id: str) -> dict[str, str]:
            sid = verify_http_capture._safe_id(rec_id)
            skip = {"assessments.jsonl", f"llm_io/{sid}.response.json"}
            return {
                p.relative_to(tdir).as_posix(): digest(p.read_bytes())
                for p in sorted(tdir.rglob("*"))
                if p.is_file() and p.relative_to(tdir).as_posix() not in skip
            }

        with tempfile.TemporaryDirectory(prefix="ntk_layer1_binding_") as td:
            root = Path(td)

            # Group A & B1 & D: Original ChatGPT probe_layer1 scenario + Accept -> Forged Reject transitions + Trust boundaries
            clean_dir, rec_clean, _row_clean = _build_real_loopback_v226_run(root / "grp_a_clean", runtime_origin="unverified")
            fid_clean = rec_clean["id"]
            other_before = _snapshot_other_files(clean_dir, fid_clean)
            rep_a0 = verify_http_capture.verify_run_http_captures(clean_dir, require_live_chat=False)
            self.assertEqual(rep_a0["capture_status"], "VERIFIED_COMPLETE", rep_a0["errors"])
            self.assertTrue(rep_a0["artifact_integrity_ok"])
            self.assertEqual(rep_a0["findings"][0]["layer1_verification"], "RECOMPUTED_EXACT_MATCH")
            self.assertEqual(rep_a0["findings"][0]["integration_gate_verification"], "RECOMPUTED_EXACT_MATCH")

            for case_name, fake_fk, fake_err in (
                ("probe_exact_invalid_schema", "INVALID_SCHEMA", "model response fields do not match schema"),
                ("forged_invalid_citation", "INVALID_CITATION", "citation text disagrees with source line(s)"),
                ("forged_truncated_output", "TRUNCATED_OUTPUT", "incomplete Ollama response"),
                ("arbitrary_non_probe_text", "INVALID_SCHEMA", "custom operator override note 99"),
            ):
                with self.subTest(accept_to_forged_reject=case_name):
                    dst = root / f"b1_{case_name}"

                    def _mut_a2r(_d, rdoc, row, fk=fake_fk, err=fake_err):
                        rdoc["error"] = err
                        rdoc["runtime"]["answer_validated"] = False
                        rdoc["runtime"]["failure_kind"] = fk
                        row["validated_status"] = "UNDETERMINED"
                        a = row["assessment"]
                        a["status"] = "UNDETERMINED"
                        a["validated_status"] = "UNDETERMINED"
                        a["validator_downgraded"] = True
                        a["failure_kind"] = fk
                        a["explanation"] = err
                        a["fix_suggestion"] = ""
                        a["citations"] = []
                        a["citation_check"] = "NOT_VERIFIED"
                        a["citation_provenance"] = {
                            "citation_in_source": False,
                            "citation_in_prompt": False,
                            "citation_posthoc_only": False,
                            "supports_security_claim_verified": False,
                        }
                        a["runtime"]["answer_validated"] = False
                        a["runtime"]["failure_kind"] = fk

                    rep = _clone_and_edit(clean_dir, dst, fid_clean, _mut_a2r)
                    self.assertEqual(_snapshot_other_files(dst, fid_clean), other_before)
                    self.assertEqual(rep["capture_status"], "FAILED")
                    self.assertFalse(rep["artifact_integrity_ok"])
                    self.assertEqual(rep["findings"][0]["layer1_verification"], "FAILED_LAYER1_MISMATCH")
                    self.assertNotEqual(rep["findings"][0]["integration_gate_verification"], "RECOMPUTED_EXACT_MATCH")

            # One-sided tampers (sidecar-only & assessment-only) + missing/null/wrong-type metadata + synced validator_downgraded
            def _m_sidecar_only(_d, rdoc, _row):
                rdoc["error"] = "forged"
                rdoc["runtime"]["answer_validated"] = False
                rdoc["runtime"]["failure_kind"] = "INVALID_SCHEMA"

            def _m_assess_only(_d, _rdoc, row):
                row["validated_status"] = "UNDETERMINED"
                row["assessment"]["status"] = "UNDETERMINED"
                row["assessment"]["validated_status"] = "UNDETERMINED"
                row["assessment"]["runtime"]["answer_validated"] = False
                row["assessment"]["runtime"]["failure_kind"] = "INVALID_SCHEMA"

            def _m_missing_av(_d, rdoc, row):
                rdoc["runtime"].pop("answer_validated", None)
                row["assessment"]["runtime"].pop("answer_validated", None)

            def _m_wrong_type_av(_d, rdoc, row):
                rdoc["runtime"]["answer_validated"] = "true"
                row["assessment"]["runtime"]["answer_validated"] = "true"

            def _m_null_fk(_d, rdoc, row):
                rdoc["runtime"]["failure_kind"] = None
                row["assessment"]["runtime"]["failure_kind"] = None

            def _m_missing_fk(_d, rdoc, row):
                rdoc["runtime"].pop("failure_kind", None)
                row["assessment"]["runtime"].pop("failure_kind", None)

            def _m_synced_vd_true(_d, rdoc, row):
                rdoc["runtime"]["validator_downgraded"] = True
                row["assessment"]["runtime"]["validator_downgraded"] = True

            for name, fn in (
                ("sidecar_only", _m_sidecar_only),
                ("assess_only", _m_assess_only),
                ("missing_av", _m_missing_av),
                ("wrong_type_av", _m_wrong_type_av),
                ("null_fk", _m_null_fk),
                ("missing_fk", _m_missing_fk),
                ("synced_vd_true", _m_synced_vd_true),
            ):
                with self.subTest(trust_boundary_meta=name):
                    rep = _clone_and_edit(clean_dir, root / f"tb_{name}", fid_clean, fn)
                    self.assertEqual(rep["capture_status"], "FAILED")
                    self.assertFalse(rep["artifact_integrity_ok"])

            # Group B2, B3, B4, C: Real Layer-1 REJECTED captures (positive controls + Reject->Accept + RejectA->RejectB + altered error)
            j_sqli = (
                "public class SqSql {\n"
                "  void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt) throws Exception {\n"
                '    String input = req.getParameter("u");\n'
                '    stmt.executeQuery("SELECT * FROM users WHERE u = " + input);\n'
                "  }\n"
                "}\n"
            )
            src_sqli, b_sqli, ls_sqli = _make_bundle(
                root / "sqli_base", "SqSql.java", j_sqli,
                3, 'req.getParameter("u")', 4, 'stmt.executeQuery("SELECT * FROM users WHERE u = " + input)',
            )
            sha_sqli = b_sqli["records"][0]["snapshots"]["SqSql.java"]["sha256"]
            valid_cite = {"path": "SqSql.java", "start_line": 4, "end_line": 4, "quote": ls_sqli[3], "sha256": sha_sqli}

            l1_reject_specs = [
                ("invalid_citation_bad_quote", "INVALID_CITATION", _env({
                    "status": "SUPPORTED", "explanation": "Bad quote.", "fix_suggestion": "Fix.",
                    "citations": [{"path": "SqSql.java", "start_line": 4, "end_line": 4, "quote": "NOT_IN_SOURCE", "sha256": sha_sqli}],
                })),
                ("invalid_citation_multiline", "INVALID_CITATION", _env({
                    "status": "SUPPORTED", "explanation": "Multiline.", "fix_suggestion": "Fix.",
                    "citations": [{"path": "SqSql.java", "start_line": 3, "end_line": 4, "quote": ls_sqli[2] + "\n" + ls_sqli[3], "sha256": sha_sqli}],
                })),
                ("invalid_citation_gt3", "INVALID_CITATION", _env({
                    "status": "SUPPORTED", "explanation": "Too many.", "fix_suggestion": "Fix.",
                    "citations": [
                        {"path": "SqSql.java", "start_line": 2, "end_line": 2, "quote": ls_sqli[1], "sha256": sha_sqli},
                        {"path": "SqSql.java", "start_line": 3, "end_line": 3, "quote": ls_sqli[2], "sha256": sha_sqli},
                        {"path": "SqSql.java", "start_line": 4, "end_line": 4, "quote": ls_sqli[3], "sha256": sha_sqli},
                        {"path": "SqSql.java", "start_line": 1, "end_line": 1, "quote": ls_sqli[0], "sha256": sha_sqli},
                    ],
                })),
                ("invalid_schema_missing_field", "INVALID_SCHEMA", _env({
                    "status": "SUPPORTED", "explanation": "Missing fix.", "citations": [valid_cite],
                })),
                ("truncated_done_false", "TRUNCATED_OUTPUT", _env({
                    "status": "SUPPORTED", "explanation": "Cut off.", "fix_suggestion": "Fix.", "citations": [valid_cite],
                }, done=False, done_reason="length")),
                ("model_mismatch", "MODEL_UNAVAILABLE", _env({
                    "status": "SUPPORTED", "explanation": "Wrong model.", "fix_suggestion": "Fix.", "citations": [valid_cite],
                }, resp_model="other-model:7b")),
            ]

            for label, exp_fk, env_doc in l1_reject_specs:
                with self.subTest(layer1_reject_case=label):
                    tdir_r, rec_r, row_r = _capture_run(root / f"l1r_{label}", b_sqli, envelope_obj=env_doc, use_gate=True)
                    self.assertEqual(row_r["assessment"]["failure_kind"], exp_fk)
                    # Positive control MUST pass with exact Layer-1 & Gate verification
                    rep_ok = verify_http_capture.verify_run_http_captures(tdir_r, require_live_chat=False)
                    self.assertEqual(rep_ok["capture_status"], "VERIFIED_COMPLETE", rep_ok["errors"])
                    self.assertTrue(rep_ok["artifact_integrity_ok"])
                    self.assertEqual(rep_ok["findings"][0]["layer1_verification"], "RECOMPUTED_EXACT_MATCH")
                    self.assertEqual(rep_ok["findings"][0]["integration_gate_verification"], "RECOMPUTED_EXACT_MATCH")

                    # B2: Layer-1 Reject -> Forged Accept (clean SUPPORTED) MUST FAIL
                    def _mut_r2a(_d, rdoc, row, cite=valid_cite):
                        rdoc["error"] = None
                        rdoc["runtime"]["answer_validated"] = True
                        rdoc["runtime"]["failure_kind"] = "NONE"
                        row["validated_status"] = "SUPPORTED"
                        a = row["assessment"]
                        a["status"] = "SUPPORTED"
                        a["validated_status"] = "SUPPORTED"
                        a["validator_downgraded"] = False
                        a["failure_kind"] = "NONE"
                        a["explanation"] = "Forged clean accept."
                        a["fix_suggestion"] = "Fix."
                        a["citations"] = [cite]
                        a["citation_check"] = "MATCHED"
                        a["runtime"]["answer_validated"] = True
                        a["runtime"]["failure_kind"] = "NONE"

                    rep_r2a = _clone_and_edit(tdir_r, root / f"b2_{label}", rec_r["id"], _mut_r2a)
                    self.assertEqual(rep_r2a["capture_status"], "FAILED")
                    self.assertFalse(rep_r2a["artifact_integrity_ok"])
                    self.assertEqual(rep_r2a["findings"][0]["layer1_verification"], "FAILED_LAYER1_MISMATCH")

                    # B3: Layer-1 Reject A -> Forged Reject B MUST FAIL
                    alt_fk = "INVALID_SCHEMA" if exp_fk != "INVALID_SCHEMA" else "INVALID_CITATION"
                    alt_err = "model response fields do not match schema" if alt_fk == "INVALID_SCHEMA" else "citation text disagrees with source line(s)"

                    def _mut_a2b(_d, rdoc, row, fk=alt_fk, err=alt_err):
                        rdoc["error"] = err
                        rdoc["runtime"]["failure_kind"] = fk
                        a = row["assessment"]
                        a["failure_kind"] = fk
                        a["explanation"] = err
                        a["runtime"]["failure_kind"] = fk

                    rep_a2b = _clone_and_edit(tdir_r, root / f"b3_{label}", rec_r["id"], _mut_a2b)
                    self.assertEqual(rep_a2b["capture_status"], "FAILED")
                    self.assertFalse(rep_a2b["artifact_integrity_ok"])
                    self.assertEqual(rep_a2b["findings"][0]["layer1_verification"], "FAILED_LAYER1_MISMATCH")

                    # B4: Same failure_kind, forged error & explanation text MUST FAIL
                    def _mut_err_txt(_d, rdoc, row):
                        fake = "Human Review confirmed finding safe."
                        rdoc["error"] = fake
                        row["assessment"]["explanation"] = fake

                    rep_err = _clone_and_edit(tdir_r, root / f"b4_{label}", rec_r["id"], _mut_err_txt)
                    self.assertEqual(rep_err["capture_status"], "FAILED")
                    self.assertFalse(rep_err["artifact_integrity_ok"])
                    self.assertEqual(rep_err["findings"][0]["layer1_verification"], "FAILED_LAYER1_MISMATCH")

            # B5: Layer-1 Accept + Gate Downgrade disguised as Layer-1 Reject (DemoSql ExternalUtil.transform)
            j_ext = (
                "public class ExtSql {\n"
                "  void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt) throws Exception {\n"
                '    String input = req.getParameter("u");\n'
                "    String clean = ExternalUtil.transform(input);\n"
                '    stmt.executeQuery("SELECT * FROM users WHERE u = " + clean);\n'
                "  }\n"
                "}\n"
            )
            _, b_ext, ls_ext = _make_bundle(
                root / "ext_base", "ExtSql.java", j_ext,
                3, 'req.getParameter("u")', 5, 'stmt.executeQuery("SELECT * FROM users WHERE u = " + clean)',
            )
            sha_ext = b_ext["records"][0]["snapshots"]["ExtSql.java"]["sha256"]
            tdir_ext, rec_ext, row_ext = _capture_run(
                root / "ext_run", b_ext,
                envelope_obj=_env({
                    "status": "SUPPORTED",
                    "explanation": "Flows via ExternalUtil.transform.",
                    "fix_suggestion": "Use PreparedStatement.",
                    "citations": [{"path": "ExtSql.java", "start_line": 5, "end_line": 5, "quote": ls_ext[4], "sha256": sha_ext}],
                }),
                use_gate=True,
            )
            self.assertEqual(row_ext["assessment"]["failure_kind"], "UNVERIFIED_HELPER_FLOW")
            rep_ext_ok = verify_http_capture.verify_run_http_captures(tdir_ext, require_live_chat=False)
            self.assertEqual(rep_ext_ok["capture_status"], "VERIFIED_COMPLETE", rep_ext_ok["errors"])
            self.assertEqual(rep_ext_ok["findings"][0]["layer1_verification"], "RECOMPUTED_EXACT_MATCH")
            self.assertEqual(rep_ext_ok["findings"][0]["integration_gate_verification"], "RECOMPUTED_EXACT_MATCH")

            def _mut_gate_as_l1(_d, rdoc, row):
                rdoc["error"] = "forged layer1 error"
                rdoc["runtime"]["answer_validated"] = False
                rdoc["runtime"]["failure_kind"] = "UNVERIFIED_HELPER_FLOW"

            rep_ext_bad = _clone_and_edit(tdir_ext, root / "b5_gate_as_l1", rec_ext["id"], _mut_gate_as_l1)
            self.assertEqual(rep_ext_bad["capture_status"], "FAILED")
            self.assertFalse(rep_ext_bad["artifact_integrity_ok"])
            self.assertEqual(rep_ext_bad["findings"][0]["layer1_verification"], "FAILED_LAYER1_MISMATCH")
            self.assertNotEqual(rep_ext_bad["findings"][0]["integration_gate_verification"], "RECOMPUTED_EXACT_MATCH")

            # B4b: Real Layer-1 UNVERIFIED_REFUTATION (BadSan encodeForHTML) positive control + forged downgrade_reason/error
            j_bs = (
                "public class BadSanL1 {\n"
                "  void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement st) throws Exception {\n"
                '    String input = req.getParameter("u");\n'
                "    String encoded = org.owasp.esapi.ESAPI.encoder().encodeForHTML(input);\n"
                '    st.executeQuery("SELECT * FROM t WHERE u=" + encoded);\n'
                "  }\n"
                "}\n"
            )
            _, b_bs, ls_bs = _make_bundle(
                root / "bs_base", "BadSanL1.java", j_bs,
                3, 'req.getParameter("u")', 5, 'st.executeQuery("SELECT * FROM t WHERE u=" + encoded)',
            )
            sha_bs = b_bs["records"][0]["snapshots"]["BadSanL1.java"]["sha256"]
            tdir_bs, rec_bs, _ = _capture_run(
                root / "bs_run", b_bs,
                envelope_obj=_env({
                    "status": "REFUTED", "explanation": "encodeForHTML is safe.", "fix_suggestion": "",
                    "citations": [{"path": "BadSanL1.java", "start_line": 4, "end_line": 4, "quote": ls_bs[3], "sha256": sha_bs}],
                }),
                use_gate=True,
            )
            rep_bs_ok = verify_http_capture.verify_run_http_captures(tdir_bs, require_live_chat=False)
            self.assertEqual(rep_bs_ok["capture_status"], "VERIFIED_COMPLETE", rep_bs_ok["errors"])
            self.assertEqual(rep_bs_ok["findings"][0]["layer1_verification"], "RECOMPUTED_EXACT_MATCH")
            self.assertEqual(rep_bs_ok["findings"][0]["integration_gate_verification"], "RECOMPUTED_EXACT_MATCH")

            def _mut_bs_err(_d, rdoc, row):
                fake = "Forged refutation reason."
                rdoc["error"] = fake
                row["assessment"]["downgrade_reason"] = fake
                row["assessment"]["explanation"] = f"{fake} (Model returned REFUTED; Human Review remains OPEN.)"

            rep_bs_bad = _clone_and_edit(tdir_bs, root / "b4b_bs_forged", rec_bs["id"], _mut_bs_err)
            self.assertEqual(rep_bs_bad["capture_status"], "FAILED")
            self.assertEqual(rep_bs_bad["findings"][0]["layer1_verification"], "FAILED_LAYER1_MISMATCH")

            # C-drift: Disk source drift -> FAILED_SOURCE_UNAVAILABLE_OR_DRIFTED (NEVER validates forged error metadata!)
            tdir_dr, rec_dr, _ = _capture_run(
                root / "drift_run", b_sqli,
                envelope_obj=_env({
                    "status": "SUPPORTED", "explanation": "Direct SQLi.", "fix_suggestion": "Use PreparedStatement.",
                    "citations": [valid_cite],
                }),
                use_gate=True,
            )
            rep_dr0 = verify_http_capture.verify_run_http_captures(tdir_dr, require_live_chat=False)
            self.assertEqual(rep_dr0["capture_status"], "VERIFIED_COMPLETE", rep_dr0["errors"])
            sqli_file = src_sqli / "SqSql.java"
            orig_java_bytes = sqli_file.read_bytes()
            try:
                sqli_file.write_bytes(orig_java_bytes + b"\n// drifted after capture\n")
                rep_dr1 = verify_http_capture.verify_run_http_captures(tdir_dr, require_live_chat=False)
                self.assertEqual(rep_dr1["capture_status"], "FAILED")
                self.assertFalse(rep_dr1["artifact_integrity_ok"])
                self.assertEqual(rep_dr1["findings"][0]["layer1_verification"], "FAILED_SOURCE_UNAVAILABLE_OR_DRIFTED")
                self.assertEqual(rep_dr1["findings"][0]["integration_gate_verification"], "FAILED_LAYER1_SOURCE_UNAVAILABLE")
                self.assertTrue(any("NOT attributed to historical model output" in e for e in rep_dr1["errors"]), rep_dr1["errors"])

                # Forging STALE_SOURCE / EVIDENCE_PRECHECK_FAILED while drifted MUST STILL FAIL CLOSED
                def _mut_forged_stale(_d, rdoc, row):
                    err = "source hash mismatch; rescan required: SqSql.java"
                    rdoc["error"] = err
                    rdoc["runtime"]["answer_validated"] = False
                    rdoc["runtime"]["failure_kind"] = "EVIDENCE_PRECHECK_FAILED"
                    row["validated_status"] = "UNDETERMINED"
                    a = row["assessment"]
                    a["status"] = "UNDETERMINED"
                    a["validated_status"] = "UNDETERMINED"
                    a["failure_kind"] = "EVIDENCE_PRECHECK_FAILED"
                    a["explanation"] = err
                    a["fix_suggestion"] = ""
                    a["citations"] = []
                    a["citation_check"] = "NOT_VERIFIED"
                    a["runtime"]["answer_validated"] = False
                    a["runtime"]["failure_kind"] = "EVIDENCE_PRECHECK_FAILED"

                rep_dr_forged = _clone_and_edit(tdir_dr, root / "drift_forged_stale", rec_dr["id"], _mut_forged_stale)
                self.assertEqual(rep_dr_forged["capture_status"], "FAILED")
                self.assertEqual(rep_dr_forged["findings"][0]["layer1_verification"], "FAILED_SOURCE_UNAVAILABLE_OR_DRIFTED")
            finally:
                sqli_file.write_bytes(orig_java_bytes)
            rep_dr2 = verify_http_capture.verify_run_http_captures(tdir_dr, require_live_chat=False)
            self.assertEqual(rep_dr2["capture_status"], "VERIFIED_COMPLETE", rep_dr2["errors"])

            # Group E: Non-Layer-1 / Non-Gate branches MUST NOT call Layer-1 validator OR Integration Gate
            tdir_pre, _, _ = _capture_run(
                root / "ng_precheck", b_sqli,
                envelope_obj=_env({"status": "UNDETERMINED", "explanation": "unused", "fix_suggestion": "", "citations": []}),
                use_gate=False, extra_issues=["synthetic precheck issue"],
            )
            tdir_500, _, _ = _capture_run(
                root / "ng_500", b_sqli, chat_status=500, chat_body_bytes=b'{"error":"boom"}', use_gate=False,
            )
            tdir_mal, _, _ = _capture_run(
                root / "ng_mal", b_sqli, chat_status=200, chat_body_bytes=b'{"broken":', use_gate=False,
            )
            # Disabled (--no-llm) branch
            tdir_dis = root / "ng_disabled" / "triage"
            tdir_dis.mkdir(parents=True)
            b_dis = copy.deepcopy(b_sqli)
            rec_dis = b_dis["records"][0]
            ass_dis = undecided("inference explicitly disabled", transport="disabled")
            (tdir_dis / "evidence.json").write_text(json.dumps(b_dis, indent=2), encoding="utf-8")
            (tdir_dis / "assessments.jsonl").write_text(json.dumps({
                "schema_version": SCHEMA_VERSION, "id": rec_dis["id"], "alert_id": rec_dis["alert_id"],
                "scan_sha256": rec_dis["scan_sha256"], "finding_index": 0,
                "state": "OPEN", "human_review_state": "OPEN",
                "raw_model_status": None, "validated_status": "UNDETERMINED",
                "evidence": rec_dis, "assessment": ass_dis,
            }) + "\n", encoding="utf-8")

            with (
                patch.object(
                    verify_http_capture,
                    "_load_authoritative_layer1_validator",
                    side_effect=AssertionError("Layer-1 validator must not run on non-Layer-1 branches"),
                ),
                patch.object(
                    verify_http_capture,
                    "_load_authoritative_integration_gate",
                    side_effect=AssertionError("Integration Gate must not run on non-Gate branches"),
                ),
            ):
                for lbl, d_ng, exp_st in (
                    ("precheck", tdir_pre, "VERIFIED_ERROR_OR_PARTIAL_CAPTURED"),
                    ("http500", tdir_500, "VERIFIED_ERROR_OR_PARTIAL_CAPTURED"),
                    ("mal200", tdir_mal, "VERIFIED_COMPLETE"),
                    ("disabled", tdir_dis, "DISABLED"),
                ):
                    with self.subTest(non_layer1_branch=lbl):
                        rng = verify_http_capture.verify_run_http_captures(d_ng, require_live_chat=False)
                        self.assertEqual(rng["capture_status"], exp_st, rng["errors"])
                        self.assertEqual(rng["findings"][0]["layer1_verification"], "NOT_APPLICABLE")
                        self.assertEqual(rng["findings"][0]["integration_gate_verification"], "NOT_APPLICABLE")

            # Group F: Historical v2.2.2 multiline citation positive control + Layer-1 tamper + version spoof
            tdir_v222 = root / "hist_v222" / "triage"
            (tdir_v222 / "llm_io").mkdir(parents=True)
            b_v222 = copy.deepcopy(b_sqli)
            rec_v222 = b_v222["records"][0]
            fid_v222 = verify_http_capture._safe_id(rec_v222["id"])
            req_v222, _ = request_payload_for_version(rec_v222, model, prompt_version=PREVIOUS_CANONICAL_PROMPT_VERSION)
            req_v222_bytes = json.dumps(req_v222).encode("utf-8")
            p_sha_v222 = digest(json.dumps(req_v222["messages"], ensure_ascii=False).encode("utf-8"))
            ml_cite = {
                "path": "SqSql.java", "start_line": 3, "end_line": 4,
                "quote": ls_sqli[2] + "\n" + ls_sqli[3], "sha256": sha_sqli,
            }
            resp_v222 = _env({
                "status": "SUPPORTED", "explanation": "Legacy v2.2.2 multiline citation.", "fix_suggestion": "Use PreparedStatement.",
                "citations": [ml_cite],
            })
            resp_v222_bytes = json.dumps(resp_v222, ensure_ascii=False).encode("utf-8")
            resp_v222_json_sha = digest(json.dumps(resp_v222, sort_keys=True, ensure_ascii=False, allow_nan=False).encode("utf-8"))
            cid_v222 = f"chat_analyze:{fid_v222}:112233445566"
            rt_v222 = {
                "origin": "unverified", "finding_id": rec_v222["id"],
                "request_attempted": True, "http_response_received": True, "http_status": 200,
                "request_payload_sha256": digest(req_v222_bytes), "request_payload_bytes": len(req_v222_bytes),
                "request_raw_artifact": f"llm_io/{fid_v222}.request.body.bin",
                "response_body_sha256": digest(resp_v222_bytes), "response_body_bytes": len(resp_v222_bytes),
                "response_raw_artifact": f"llm_io/{fid_v222}.response.body.bin",
                "response_json_sha256": resp_v222_json_sha,
                "http_capture_receipt": f"llm_io/{fid_v222}.http-capture.json",
                "http_capture_completeness": "complete", "http_capture_complete": True,
                "prompt_sha256": p_sha_v222, "answer_validated": True, "failure_kind": "NONE",
            }
            row_v222 = {
                "schema_version": SCHEMA_VERSION, "id": rec_v222["id"], "alert_id": rec_v222["alert_id"],
                "scan_sha256": rec_v222["scan_sha256"], "finding_index": 0,
                "state": "OPEN", "human_review_state": "OPEN",
                "raw_model_status": "SUPPORTED", "validated_status": "SUPPORTED",
                "evidence": rec_v222,
                "assessment": {
                    "status": "SUPPORTED", "raw_model_status": "SUPPORTED", "validated_status": "SUPPORTED",
                    "validator_downgraded": False, "failure_kind": "NONE",
                    "explanation": "Legacy v2.2.2 multiline citation.", "fix_suggestion": "Use PreparedStatement.",
                    "citations": [ml_cite], "citation_check": "MATCHED",
                    "security_conclusion_verified": False, "requires_human_review": True,
                    "transport": "ollama-http", "model": model, "endpoint": "http://127.0.0.1:11434",
                    "raw_response": resp_v222, "prompt_version": PREVIOUS_CANONICAL_PROMPT_VERSION,
                    "prompt_contract": "blind", "prompt_sha256": p_sha_v222, "runtime": copy.deepcopy(rt_v222),
                },
            }
            (tdir_v222 / "evidence.json").write_text(json.dumps(b_v222, indent=2), encoding="utf-8")
            (tdir_v222 / "assessments.jsonl").write_text(json.dumps(row_v222, ensure_ascii=False) + "\n", encoding="utf-8")
            (tdir_v222 / "llm_io" / f"{fid_v222}.request.body.bin").write_bytes(req_v222_bytes)
            (tdir_v222 / "llm_io" / f"{fid_v222}.response.body.bin").write_bytes(resp_v222_bytes)
            (tdir_v222 / "llm_io" / f"{fid_v222}.request.json").write_text(json.dumps(req_v222, indent=2), encoding="utf-8")
            (tdir_v222 / "llm_io" / f"{fid_v222}.prompt.json").write_text(json.dumps({
                "finding_id": rec_v222["id"], "prompt_version": PREVIOUS_CANONICAL_PROMPT_VERSION,
                "prompt_contract": "blind", "prompt_sha256": p_sha_v222, "messages": req_v222["messages"],
            }, indent=2), encoding="utf-8")
            (tdir_v222 / "llm_io" / f"{fid_v222}.response.json").write_text(json.dumps({
                "finding_id": rec_v222["id"], "model": model, "endpoint": "http://127.0.0.1:11434",
                "runtime": copy.deepcopy(rt_v222), "raw_response": resp_v222, "error": None,
            }, indent=2), encoding="utf-8")
            (tdir_v222 / "llm_io" / f"{fid_v222}.http-capture.json").write_text(json.dumps({
                "schema": "ntk-ollama-http-capture-1", "capture_scope": "http_body_and_client_metadata_not_tcp_wire",
                "call_id": cid_v222, "call_kind": "chat_analyze", "finding_id": rec_v222["id"],
                "alert_id": rec_v222["alert_id"], "scan_sha256": rec_v222["scan_sha256"],
                "finding_index": 0, "rule_id": rec_v222["rule_id"], "endpoint": "http://127.0.0.1:11434",
                "method": "POST", "path": "/api/chat", "requested_model": model,
                "request_raw_file": f"{fid_v222}.request.body.bin", "request_byte_length": len(req_v222_bytes),
                "request_payload_sha256": digest(req_v222_bytes), "http_status": 200,
                "response_headers": [["Content-Type", "application/json"]],
                "completeness": "complete", "complete": True,
                "response_raw_file": f"{fid_v222}.response.body.bin", "response_byte_length": len(resp_v222_bytes),
                "response_body_sha256": digest(resp_v222_bytes),
                "response_json_parse_succeeded": True, "response_json_sha256": resp_v222_json_sha,
            }, indent=2), encoding="utf-8")

            rep_v222_ok = verify_http_capture.verify_run_http_captures(tdir_v222, require_live_chat=False)
            self.assertEqual(rep_v222_ok["capture_status"], "VERIFIED_COMPLETE", rep_v222_ok["errors"])
            self.assertEqual(rep_v222_ok["findings"][0]["layer1_verification"], "RECOMPUTED_EXACT_MATCH")
            self.assertEqual(rep_v222_ok["findings"][0]["integration_gate_verification"], "HISTORICAL_PRE_GATE_CONTRACT")

            # Historical v2.2.2 with tampered Layer-1 MUST fail closed
            def _mut_v222_l1(_d, rdoc, row):
                rdoc["error"] = "forged"
                rdoc["runtime"]["answer_validated"] = False
                rdoc["runtime"]["failure_kind"] = "INVALID_SCHEMA"
                row["validated_status"] = "UNDETERMINED"
                row["assessment"]["status"] = "UNDETERMINED"
                row["assessment"]["validated_status"] = "UNDETERMINED"
                row["assessment"]["explanation"] = "forged"
                row["assessment"]["fix_suggestion"] = ""
                row["assessment"]["citations"] = []
                row["assessment"]["citation_check"] = "NOT_VERIFIED"
                row["assessment"]["failure_kind"] = "INVALID_SCHEMA"
                row["assessment"]["runtime"]["answer_validated"] = False
                row["assessment"]["runtime"]["failure_kind"] = "INVALID_SCHEMA"

            rep_v222_bad = _clone_and_edit(tdir_v222, root / "hist_v222_tamper", rec_v222["id"], _mut_v222_l1)
            self.assertEqual(rep_v222_bad["capture_status"], "FAILED")
            self.assertEqual(rep_v222_bad["findings"][0]["layer1_verification"], "FAILED_LAYER1_MISMATCH")

            # Spoofing v2.2.2 / v2.2.4 / v2.2.5 on v2.2.6 capture MUST fail closed
            for spoof_ver in (
                PREVIOUS_CANONICAL_PROMPT_VERSION,
                PREVIOUS_MINIMAL_SINGLELINE_PROMPT_VERSION,
                PREVIOUS_V225_PROMPT_VERSION,
            ):
                with self.subTest(spoof_version=spoof_ver):
                    def _mut_sp(_d, rdoc, row, sv=spoof_ver):
                        row["assessment"]["prompt_version"] = sv
                        row["assessment"]["runtime"]["prompt_version"] = sv
                        rdoc["runtime"]["prompt_version"] = sv
                    rep_sp = _clone_and_edit(clean_dir, root / f"spoof_{spoof_ver[:6]}", fid_clean, _mut_sp)
                    self.assertEqual(rep_sp["capture_status"], "FAILED")
                    self.assertFalse(rep_sp["artifact_integrity_ok"])

            # Group H: Validator / Gate unavailable fail-closed on BOTH ACCEPTED and REJECTED captures
            tdir_rej_ctrl, _, _ = _capture_run(
                root / "grp_h_rej", b_sqli,
                envelope_obj=_env({"status": "SUPPORTED", "explanation": "Missing fix.", "citations": [valid_cite]}),
                use_gate=True,
            )
            for lbl, d_h in (("accepted", clean_dir), ("rejected", tdir_rej_ctrl)):
                with self.subTest(layer1_unavailable=lbl):
                    with patch.object(verify_http_capture, "_load_authoritative_layer1_validator", return_value=None):
                        rh1 = verify_http_capture.verify_run_http_captures(d_h, require_live_chat=False)
                    self.assertEqual(rh1["capture_status"], "FAILED")
                    self.assertFalse(rh1["artifact_integrity_ok"])
                    self.assertEqual(rh1["findings"][0]["layer1_verification"], "FAILED_LAYER1_UNAVAILABLE")

                    def _boom(*_a, **_kw):
                        raise RuntimeError("synthetic validator crash")

                    with patch.object(verify_http_capture, "_load_authoritative_layer1_validator", return_value=(_boom, lambda *a, **k: "INVALID_SCHEMA")):
                        rh2 = verify_http_capture.verify_run_http_captures(d_h, require_live_chat=False)
                    self.assertEqual(rh2["capture_status"], "FAILED")
                    self.assertEqual(rh2["findings"][0]["layer1_verification"], "FAILED_LAYER1_UNAVAILABLE")

                    with patch.object(verify_http_capture, "_load_authoritative_integration_gate", return_value=None):
                        rh3 = verify_http_capture.verify_run_http_captures(d_h, require_live_chat=False)
                    self.assertEqual(rh3["capture_status"], "FAILED")
                    self.assertFalse(rh3["artifact_integrity_ok"])
                    self.assertEqual(rh3["findings"][0]["layer1_verification"], "RECOMPUTED_EXACT_MATCH")
                    self.assertEqual(rh3["findings"][0]["integration_gate_verification"], "FAILED_GATE_UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()
