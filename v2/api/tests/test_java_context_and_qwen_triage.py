"""Tests for v2.api.java_context_v2, v2.api.qwen_cache, and v2.api.qwen_triage."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest

from v2.api.java_context_v2 import (
    DEFAULT_MAX_PROMPT_BYTES,
    enrich_bundle_context,
    extract_java_context_v2,
    parse_java_structure_v2,
)
from v2.api.qwen_cache import ProvenanceQwenCache
from v2.api.qwen_triage import run_bounded_triage
from v2.triage import verify_http_capture
from v2.triage.evidence import EvidenceError, collect, digest
from v2.triage.ollama import OllamaClient, assert_prompt_contract, prompt as build_prompt, validate_answer


def _make_manifest_and_opengrep(
    source_root: Path,
    java_rel: str,
    *,
    rule_id: str,
    cwe: str,
    source_line: int,
    source_text: str,
    sink_line: int,
    sink_text: str,
    rules_path: Path,
) -> tuple[Path, Path]:
    java_file = source_root / java_rel
    raw_bytes = java_file.read_bytes()
    text = raw_bytes.decode("utf-8")
    lines = text.splitlines(keepends=True)

    def _loc(ln: int, snippet: str) -> dict:
        line_raw = lines[ln - 1].rstrip("\r\n")
        col0 = line_raw.index(snippet)
        prefix_bytes = sum(len(x.encode("utf-8")) for x in lines[: ln - 1])
        start_off = prefix_bytes + len(line_raw[:col0].encode("utf-8"))
        end_off = start_off + len(snippet.encode("utf-8"))
        return {
            "path": java_rel,
            "start": {"line": ln, "col": len(line_raw[:col0].encode("utf-8")) + 1, "offset": start_off},
            "end": {"line": ln, "col": len(line_raw[: col0 + len(snippet)].encode("utf-8")) + 1, "offset": end_off},
        }

    src_loc = _loc(source_line, source_text)
    snk_loc = _loc(sink_line, sink_text)
    og_doc = {
        "version": "1.25.0",
        "results": [
            {
                "check_id": rule_id,
                "path": java_rel,
                "start": snk_loc["start"],
                "end": snk_loc["end"],
                "extra": {
                    "message": f"[{cwe}] synthetic finding",
                    "severity": "ERROR",
                    "metadata": {"cwe": [cwe]},
                    "dataflow_trace": {
                        "taint_source": ["CliLoc", [src_loc, source_text]],
                        "intermediate_vars": [],
                        "taint_sink": ["CliLoc", [snk_loc, sink_text]],
                    },
                },
            }
        ],
        "errors": [],
        "paths": {"scanned": [java_rel], "skipped": []},
    }
    cap_dir = source_root.parent / "capture"
    cap_dir.mkdir(parents=True, exist_ok=True)
    og_path = cap_dir / "opengrep.json"
    og_bytes = json.dumps(og_doc, indent=2).encode("utf-8")
    og_path.write_bytes(og_bytes)
    sarif_doc = {
        "version": "2.1.0",
        "runs": [
            {
                "results": [
                    {
                        "ruleId": rule_id,
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": java_rel},
                                    "region": {"startLine": sink_line},
                                }
                            }
                        ],
                    }
                ]
            }
        ],
    }
    sarif_bytes = json.dumps(sarif_doc, indent=2).encode("utf-8")
    (cap_dir / "opengrep.sarif").write_bytes(sarif_bytes)
    rules_bytes = rules_path.read_bytes()
    (cap_dir / "rules.snapshot.yml").write_bytes(rules_bytes)
    ver_cmd = ["opengrep", "--version"]
    json_cmd = ["opengrep", "scan", "--json", str(source_root)]
    sarif_cmd = ["opengrep", "scan", "--sarif", str(source_root)]
    extra_files = {
        "opengrep.json": og_bytes,
        "opengrep.sarif": sarif_bytes,
        "rules.snapshot.yml": rules_bytes,
        "version.exit.txt": b"0",
        "version.command.json": json.dumps(ver_cmd).encode("utf-8"),
        "json.exit.txt": b"0",
        "json.command.json": json.dumps(json_cmd).encode("utf-8"),
        "json.stdout.txt": og_bytes,
        "sarif.exit.txt": b"0",
        "sarif.command.json": json.dumps(sarif_cmd).encode("utf-8"),
        "sarif.stdout.txt": sarif_bytes,
    }
    artifacts: dict[str, str] = {}
    for fname, fbytes in extra_files.items():
        (cap_dir / fname).write_bytes(fbytes)
        artifacts[fname] = digest(fbytes)

    manifest = {
        "schema": "ntk-scan-capture-1",
        "producer": "unit_test_local_capture",
        "success": True,
        "issues": [],
        "target_kind": "directory",
        "sources_before": {java_rel: digest(raw_bytes)},
        "sources_after": {java_rel: digest(raw_bytes)},
        "rules_before_sha256": digest(rules_bytes),
        "rules_after_sha256": digest(rules_bytes),
        "artifacts": artifacts,
        "runs": {
            "version": {"argv": ver_cmd, "exit_code": 0},
            "json": {"argv": json_cmd, "exit_code": 0, "output_mode": "stdout"},
            "sarif": {"argv": sarif_cmd, "exit_code": 0, "output_mode": "stdout"},
        },
    }
    manifest_path = cap_dir / "scan-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return og_path, manifest_path


class JavaContextAndTriageTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.rules_file = self.root / "rules.yml"
        self.rules_file.write_text("rules: []\n", encoding="utf-8")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_spring_mvc_nested_paren_annotations_parsed(self) -> None:
        java = (
            "package demo;\n"
            "import java.io.*;\n"
            "import java.nio.file.*;\n"
            "import org.springframework.web.bind.annotation.*;\n"
            "@RestController\n"
            "public class UploadCtrl {\n"
            "    @PostMapping(\n"
            "        value = \"/api/download\",\n"
            "        produces = \"application/octet-stream\"\n"
            "    )\n"
            "    public byte[] download(\n"
            "        @RequestParam(value = \"file\", required = false) String fileName,\n"
            "        @RequestHeader(\"X-Tenant\") String tenant\n"
            "    ) throws IOException {\n"
            "        Path p = resolveSafe(fileName);\n"
            "        return Files.readAllBytes(p);\n"
            "    }\n"
            "    private Path resolveSafe(String name) {\n"
            "        return Paths.get(\"/srv/files\", name);\n"
            "    }\n"
            "}\n"
        )
        parsed = parse_java_structure_v2(java)
        names = [m["name"] for m in parsed["methods"]]
        self.assertEqual(names, ["download", "resolveSafe"])
        dl = parsed["methods"][0]
        self.assertTrue(dl["is_entrypoint"])
        self.assertIn("PostMapping", dl["annotations"])
        self.assertEqual(len(dl["parameters"]), 2)

        jctx, distant, _ = extract_java_context_v2(java, 16, 16, trace_lines=[12, 16])
        self.assertIsNotNone(jctx["enclosing_method"])
        self.assertEqual(jctx["enclosing_method"]["name"], "download")
        self.assertEqual([c["name"] for c in jctx["same_file_callees"]], ["resolveSafe"])
        self.assertEqual(distant, [])

    def test_distant_same_file_helper_attached_and_citable(self) -> None:
        src_dir = self.root / "src_helper"
        src_dir.mkdir()
        filler = "\n".join(f"    private void filler{i}() {{ int x = {i}; }}" for i in range(160))
        java = (
            "package demo;\n"
            "import java.nio.file.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class BigController {\n"
            "    public byte[] handle(HttpServletRequest req) throws Exception {\n"
            "        String f = req.getParameter(\"f\");\n"
            "        String p = buildPath(f);\n"
            "        return Files.readAllBytes(Paths.get(p));\n"
            "    }\n"
            + filler
            + "\n"
            "    private String buildPath(String raw) {\n"
            "        return \"/srv/data/\" + raw;\n"
            "    }\n"
            "}\n"
        )
        java_path = src_dir / "BigController.java"
        java_path.write_text(java, encoding="utf-8")
        helper_line = next(i for i, l in enumerate(java.splitlines(), 1) if 'return "/srv/data/" + raw;' in l)
        og_path, _ = _make_manifest_and_opengrep(
            src_dir,
            "BigController.java",
            rule_id="ntk.api.java.cwe22.path-traversal",
            cwe="CWE-22",
            source_line=6,
            source_text='req.getParameter("f")',
            sink_line=8,
            sink_text="Files.readAllBytes(Paths.get(p))",
            rules_path=self.rules_file,
        )
        bundle = collect(
            og_path.read_bytes(),
            src_dir,
            engine_exit=0,
            scan_provenance={"origin": "unit", "source_capture_verified": True, "exit_capture_verified": True, "recorded_engine_exit": 0},
        )
        stats = enrich_bundle_context(bundle, src_dir, max_prompt_bytes=DEFAULT_MAX_PROMPT_BYTES)
        self.assertEqual(stats["helpers_attached"], 1)
        self.assertGreaterEqual(stats["compacted_snippets"], 1)
        self.assertLess(stats["after_prompt_bytes_total"], stats["before_prompt_bytes_total"] + 1500)

        rec = bundle["records"][0]
        helper_snips = [s for s in rec["snippets"] if s.get("role") == "helper"]
        self.assertEqual(len(helper_snips), 1)
        self.assertEqual(helper_snips[0]["sha256"], rec["snapshots"]["BigController.java"]["sha256"])

        msgs = build_prompt(rec)
        assert_prompt_contract(json.loads(msgs[1]["content"]), "blind")

        # Verify a citation inside the distant helper snippet passes sealed validate_answer!
        helper_text = java.splitlines()[helper_line - 1]
        answer = json.dumps(
            {
                "status": "SUPPORTED",
                "explanation": "Ham phu buildPath noi truc tiep tham so dau vao.",
                "fix_suggestion": "Chuan hoa duong dan bang getCanonicalPath() va kiem tra bien thu muc.",
                "citations": [
                    {
                        "path": "BigController.java",
                        "start_line": helper_line,
                        "end_line": helper_line,
                        "quote": helper_text,
                        "sha256": rec["snapshots"]["BigController.java"]["sha256"],
                    }
                ],
            }
        )
        validated = validate_answer(answer, rec)
        self.assertEqual(validated["validated_status"], "SUPPORTED")
        self.assertTrue(validated["citation_provenance"]["citation_in_prompt"])

    def test_redundant_source_sink_compacted_and_32kb_bounded(self) -> None:
        src_dir = self.root / "src_big"
        src_dir.mkdir()
        long_lines = "\n".join(f'        String pad{i} = "' + ("A" * 240) + '";' for i in range(135))
        java = (
            "package demo;\n"
            "import java.sql.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class HugeMethod {\n"
            "    public void run(HttpServletRequest req, Statement stmt) throws Exception {\n"
            "        String u = req.getParameter(\"u\");\n"
            + long_lines
            + "\n"
            "        stmt.executeQuery(\"SELECT * FROM t WHERE u='\" + u + \"'\");\n"
            "    }\n"
            "}\n"
        )
        (src_dir / "HugeMethod.java").write_text(java, encoding="utf-8")
        sink_ln = next(i for i, l in enumerate(java.splitlines(), 1) if "stmt.executeQuery" in l)
        og_path, _ = _make_manifest_and_opengrep(
            src_dir,
            "HugeMethod.java",
            rule_id="ntk.api.java.cwe89.sql-injection",
            cwe="CWE-89",
            source_line=6,
            source_text='req.getParameter("u")',
            sink_line=sink_ln,
            sink_text='stmt.executeQuery("SELECT * FROM t WHERE u=\'" + u + "\'")',
            rules_path=self.rules_file,
        )
        bundle = collect(
            og_path.read_bytes(),
            src_dir,
            engine_exit=0,
            scan_provenance={"origin": "unit", "source_capture_verified": True, "exit_capture_verified": True, "recorded_engine_exit": 0},
        )
        stats = enrich_bundle_context(bundle, src_dir, max_prompt_bytes=DEFAULT_MAX_PROMPT_BYTES)
        self.assertGreater(stats["before_prompt_bytes_max"], DEFAULT_MAX_PROMPT_BYTES)
        self.assertLessEqual(stats["after_prompt_bytes_max"], DEFAULT_MAX_PROMPT_BYTES)
        self.assertEqual(stats["budget_trimmed"], 1)

    def test_spring_protected_fp_recovered_while_unsafe_guard_still_rejected(self) -> None:
        # 1. Safe Spring MVC canonical + separator guard -> REFUTED accepted
        safe_dir = self.root / "src_spring_safe"
        safe_dir.mkdir()
        safe_java = (
            "package demo;\n"
            "import java.io.*;\n"
            "import org.springframework.web.bind.annotation.*;\n"
            "public class SafeSpring {\n"
            "    @GetMapping(\"/report\")\n"
            "    public FileInputStream open(@RequestParam(\"report\") String reportName) throws IOException {\n"
            "        File base = new File(\"/srv/reports\");\n"
            "        File target = new File(base, reportName);\n"
            "        String baseCanon = base.getCanonicalPath();\n"
            "        String targetCanon = target.getCanonicalPath();\n"
            "        if (!targetCanon.startsWith(baseCanon + File.separator)) {\n"
            "            throw new SecurityException(\"outside\");\n"
            "        }\n"
            "        return new FileInputStream(target);\n"
            "    }\n"
            "}\n"
        )
        (safe_dir / "SafeSpring.java").write_text(safe_java, encoding="utf-8")
        og_safe, _ = _make_manifest_and_opengrep(
            safe_dir,
            "SafeSpring.java",
            rule_id="ntk.api.java.cwe22.path-traversal",
            cwe="CWE-22",
            source_line=6,
            source_text="reportName",
            sink_line=14,
            sink_text="new FileInputStream(target)",
            rules_path=self.rules_file,
        )
        b_safe = collect(
            og_safe.read_bytes(),
            safe_dir,
            engine_exit=0,
            scan_provenance={"origin": "unit", "source_capture_verified": True, "exit_capture_verified": True, "recorded_engine_exit": 0},
        )
        enrich_bundle_context(b_safe, safe_dir)
        rec_safe = b_safe["records"][0]
        guard_line = 11
        guard_txt = safe_java.splitlines()[guard_line - 1]
        refute_payload = json.dumps(
            {
                "status": "REFUTED",
                "explanation": "Duong dan da duoc chuan hoa va kiem tra bien thu muc co File.separator.",
                "fix_suggestion": "",
                "citations": [
                    {
                        "path": "SafeSpring.java",
                        "start_line": guard_line,
                        "end_line": guard_line,
                        "quote": guard_txt,
                        "sha256": rec_safe["snapshots"]["SafeSpring.java"]["sha256"],
                    }
                ],
            }
        )
        val_safe = validate_answer(refute_payload, rec_safe)
        self.assertEqual(val_safe["validated_status"], "REFUTED")

        # 2. Unsafe Spring MVC startsWith WITHOUT separator -> REFUTED MUST still be rejected!
        unsafe_dir = self.root / "src_spring_unsafe"
        unsafe_dir.mkdir()
        unsafe_java = safe_java.replace("baseCanon + File.separator", '"/srv/reports"')
        (unsafe_dir / "SafeSpring.java").write_text(unsafe_java, encoding="utf-8")
        og_unsafe, _ = _make_manifest_and_opengrep(
            unsafe_dir,
            "SafeSpring.java",
            rule_id="ntk.api.java.cwe22.path-traversal",
            cwe="CWE-22",
            source_line=6,
            source_text="reportName",
            sink_line=14,
            sink_text="new FileInputStream(target)",
            rules_path=self.rules_file,
        )
        b_unsafe = collect(
            og_unsafe.read_bytes(),
            unsafe_dir,
            engine_exit=0,
            scan_provenance={"origin": "unit", "source_capture_verified": True, "exit_capture_verified": True, "recorded_engine_exit": 0},
        )
        enrich_bundle_context(b_unsafe, unsafe_dir)
        rec_unsafe = b_unsafe["records"][0]
        unsafe_guard_txt = unsafe_java.splitlines()[guard_line - 1]
        bad_refute = json.dumps(
            {
                "status": "REFUTED",
                "explanation": "Claimed safe startsWith without separator.",
                "fix_suggestion": "",
                "citations": [
                    {
                        "path": "SafeSpring.java",
                        "start_line": guard_line,
                        "end_line": guard_line,
                        "quote": unsafe_guard_txt,
                        "sha256": rec_unsafe["snapshots"]["SafeSpring.java"]["sha256"],
                    }
                ],
            }
        )
        with self.assertRaises(EvidenceError):
            validate_answer(bad_refute, rec_unsafe)

    def test_bounded_triage_http_capture_and_job_timeout(self) -> None:
        src_dir = self.root / "src_triage"
        src_dir.mkdir()
        java = (
            "package demo;\n"
            "import java.sql.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class DemoSql {\n"
            "    public void run(HttpServletRequest req, Statement st) throws Exception {\n"
            "        String u = req.getParameter(\"u\");\n"
            "        st.executeQuery(\"SELECT * FROM users WHERE u='\" + u + \"'\");\n"
            "    }\n"
            "}\n"
        )
        (src_dir / "DemoSql.java").write_text(java, encoding="utf-8")
        og_path, manifest_path = _make_manifest_and_opengrep(
            src_dir,
            "DemoSql.java",
            rule_id="ntk.api.java.cwe89.sql-injection",
            cwe="CWE-89",
            source_line=6,
            source_text='req.getParameter("u")',
            sink_line=7,
            sink_text='st.executeQuery("SELECT * FROM users WHERE u=\'" + u + "\'")',
            rules_path=self.rules_file,
        )
        file_sha = digest((src_dir / "DemoSql.java").read_bytes())
        sink_line_txt = java.splitlines()[6]
        model_name = "qwen3.5:9b-q4_K_M"

        class _MockOllama(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                return

            def do_GET(self):
                if self.path == "/api/tags":
                    body = json.dumps({"models": [{"name": model_name, "digest": "a" * 64, "size": 100}]}).encode("utf-8")
                else:
                    body = json.dumps({"models": []}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                n = int(self.headers.get("Content-Length", "0"))
                _ = self.rfile.read(n)
                ans = json.dumps(
                    {
                        "status": "SUPPORTED",
                        "explanation": "Noi chuoi truc tiep vao executeQuery.",
                        "fix_suggestion": "Dung PreparedStatement voi ?.",
                        "citations": [
                            {
                                "path": "DemoSql.java",
                                "start_line": 7,
                                "end_line": 7,
                                "quote": sink_line_txt,
                                "sha256": file_sha,
                            }
                        ],
                    }
                )
                body = json.dumps(
                    {
                        "model": model_name,
                        "done": True,
                        "done_reason": "stop",
                        "mock_test_fixture": True,
                        "message": {"role": "assistant", "content": ans},
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _MockOllama)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            endpoint = f"http://127.0.0.1:{srv.server_port}"
            triage_ok = self.root / "triage_ok"
            res = run_bounded_triage(
                source_root=src_dir,
                triage_dir=triage_ok,
                raw_json_path=og_path,
                manifest_path=manifest_path,
                path_maps=[],
                rules_path=self.rules_file,
                no_llm=False,
                prompt_contract="blind",
                ollama_endpoint=endpoint,
                ollama_model=model_name,
                ollama_timeout_seconds=10.0,
                runtime_origin="mock",
                deadline_mono=time.monotonic() + 60.0,
            )
            self.assertEqual(res["triage_exit"], 0)
            self.assertEqual(res["assessments_list"][0]["validated_status"], "SUPPORTED")
            cap_check = verify_http_capture.verify_run_http_captures(triage_ok, require_live_chat=False)
            self.assertTrue(cap_check["capture_integrity_ok"], cap_check["errors"])
            self.assertEqual(cap_check["capture_status"], "VERIFIED_COMPLETE")

            # Expired job deadline -> fail-closed JOB_TIMEOUT UNDETERMINED, still passes capture integrity!
            triage_to = self.root / "triage_timeout"
            res_to = run_bounded_triage(
                source_root=src_dir,
                triage_dir=triage_to,
                raw_json_path=og_path,
                manifest_path=manifest_path,
                path_maps=[],
                rules_path=self.rules_file,
                no_llm=False,
                prompt_contract="blind",
                ollama_endpoint=endpoint,
                ollama_model=model_name,
                ollama_timeout_seconds=10.0,
                runtime_origin="mock",
                deadline_mono=time.monotonic() - 1.0,
            )
            self.assertEqual(res_to["timeout_aborts"], 1)
            self.assertEqual(res_to["assessments_list"][0]["validated_status"], "UNDETERMINED")
            self.assertEqual(res_to["assessments_list"][0]["failure_kind"], "JOB_TIMEOUT")
            cap_to = verify_http_capture.verify_run_http_captures(triage_to, require_live_chat=False)
            self.assertTrue(cap_to["capture_integrity_ok"], cap_to["errors"])
        finally:
            srv.shutdown()
            srv.server_close()

    def test_provenance_qwen_cache_strict_invalidation(self) -> None:
        src_dir = self.root / "src_cache"
        src_dir.mkdir()
        java = (
            "package demo;\n"
            "import java.sql.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class CacheSql {\n"
            "    public void run(HttpServletRequest req, Statement st) throws Exception {\n"
            "        String u = req.getParameter(\"u\");\n"
            "        st.executeQuery(\"SELECT * FROM users WHERE u='\" + u + \"'\");\n"
            "    }\n"
            "}\n"
        )
        jf = src_dir / "CacheSql.java"
        jf.write_text(java, encoding="utf-8")
        og_path, _ = _make_manifest_and_opengrep(
            src_dir,
            "CacheSql.java",
            rule_id="ntk.api.java.cwe89.sql-injection",
            cwe="CWE-89",
            source_line=6,
            source_text='req.getParameter("u")',
            sink_line=7,
            sink_text='st.executeQuery("SELECT * FROM users WHERE u=\'" + u + "\'")',
            rules_path=self.rules_file,
        )
        bundle = collect(
            og_path.read_bytes(),
            src_dir,
            engine_exit=0,
            scan_provenance={"origin": "unit", "source_capture_verified": True, "exit_capture_verified": True, "recorded_engine_exit": 0},
        )
        rec = bundle["records"][0]
        rec["prompt_contract"] = "blind"
        sha = rec["snapshots"]["CacheSql.java"]["sha256"]
        ans_content = json.dumps(
            {
                "status": "SUPPORTED",
                "explanation": "Noi chuoi truc tiep.",
                "fix_suggestion": "Dung PreparedStatement.",
                "citations": [
                    {
                        "path": "CacheSql.java",
                        "start_line": 7,
                        "end_line": 7,
                        "quote": java.splitlines()[6],
                        "sha256": sha,
                    }
                ],
            }
        )
        raw_resp_obj = {"model": "qwen3.5:9b-q4_K_M", "done": True, "message": {"content": ans_content}}
        resp_json_sha = digest(json.dumps(raw_resp_obj, sort_keys=True, ensure_ascii=False, allow_nan=False).encode("utf-8"))
        inv = {"CacheSql.java": sha}
        verified_assessment = {
            "status": "SUPPORTED",
            "validated_status": "SUPPORTED",
            "failure_kind": "NONE",
            "raw_response": raw_resp_obj,
            "runtime": {
                "origin": "unverified",
                "answer_validated": True,
                "request_attempted": True,
                "http_response_received": True,
                "http_status": 200,
                "response_complete": True,
                "http_capture_complete": True,
                "model_identity_matched": True,
                "request_payload_sha256": "a" * 64,
                "response_body_sha256": "b" * 64,
                "response_json_sha256": resp_json_sha,
            },
        }
        cache = ProvenanceQwenCache(self.root / "cache")
        self.assertFalse(cache.is_enabled())
        rules_sha = "1" * 64
        model_digest = "2" * 64

        # Cache is SAFELY_DISABLED: store() and lookup() always refuse reuse (return None)
        self.assertIsNone(
            cache.store(rec, verified_assessment, rules_sha256=rules_sha, ollama_model="qwen3.5:9b-q4_K_M", model_digest=model_digest, source_inventory=inv)
        )
        self.assertIsNone(
            cache.lookup(rec, rules_sha256=rules_sha, ollama_model="qwen3.5:9b-q4_K_M", model_digest=model_digest, endpoint="http://127.0.0.1:11434", source_inventory=inv, source_root=src_dir)
        )

        # Explicitly requesting enable_qwen_cache=True in run_bounded_triage MUST fail closed
        with self.assertRaises(EvidenceError):
            run_bounded_triage(
                source_root=src_dir,
                triage_dir=self.root / "triage_cache_refused",
                raw_json_path=og_path,
                manifest_path=src_dir.parent / "capture" / "scan-manifest.json",
                path_maps=[],
                rules_path=self.rules_file,
                no_llm=True,
                prompt_contract="blind",
                ollama_endpoint="http://127.0.0.1:11434",
                ollama_model="qwen3.5:9b-q4_K_M",
                ollama_timeout_seconds=10.0,
                runtime_origin="mock",
                deadline_mono=time.monotonic() + 20.0,
                enable_qwen_cache=True,
            )

        # Defense-in-depth inventory verifier: rejects modified, deleted, or newly added .java files
        from v2.api.qwen_cache import _verify_source_inventory_on_disk
        self.assertTrue(_verify_source_inventory_on_disk(src_dir, inv))
        added_jf = src_dir / "AddedAfter.java"
        added_jf.write_text("public class AddedAfter {}\n", encoding="utf-8")
        self.assertFalse(_verify_source_inventory_on_disk(src_dir, inv))
        added_jf.unlink()

        orig_stat = jf.stat()
        same_len_java = java.replace("WHERE u='", "WHERE v='", 1)
        self.assertEqual(len(same_len_java.encode("utf-8")), len(java.encode("utf-8")))
        jf.write_text(same_len_java, encoding="utf-8")
        os.utime(jf, ns=(orig_stat.st_atime_ns, orig_stat.st_mtime_ns))
        self.assertFalse(_verify_source_inventory_on_disk(src_dir, inv))

    def test_citation_counterexamples_wrong_file_line_hash_posthoc_and_external_helper(self) -> None:
        src_dir = self.root / "src_cite_ce"
        src_dir.mkdir()
        padding = "\n".join(f'        String pad{i} = "' + ("B" * 220) + '";' for i in range(125))
        java = (
            "package demo;\n"
            "import java.io.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class CiteCounterexample {\n"
            "    public FileInputStream open(HttpServletRequest req) throws Exception {\n"
            "        String raw = req.getParameter(\"p\");\n"
            + padding
            + "\n"
            "        String resolved = ExternalPathPolicy.normalizeDocumentPath(raw);\n"
            "        return new FileInputStream(resolved);\n"
            "    }\n"
            "}\n"
        )
        jf = src_dir / "CiteCounterexample.java"
        jf.write_text(java, encoding="utf-8")
        lines = java.splitlines()
        sink_ln = next(i for i, l in enumerate(lines, 1) if "new FileInputStream(resolved)" in l)
        og_path, _ = _make_manifest_and_opengrep(
            src_dir,
            "CiteCounterexample.java",
            rule_id="ntk.api.java.cwe22.path-traversal",
            cwe="CWE-22",
            source_line=6,
            source_text='req.getParameter("p")',
            sink_line=sink_ln,
            sink_text="new FileInputStream(resolved)",
            rules_path=self.rules_file,
        )
        bundle = collect(
            og_path.read_bytes(),
            src_dir,
            engine_exit=0,
            scan_provenance={"origin": "unit", "source_capture_verified": True, "exit_capture_verified": True, "recorded_engine_exit": 0},
        )
        enrich_bundle_context(bundle, src_dir, max_prompt_bytes=DEFAULT_MAX_PROMPT_BYTES)
        rec = bundle["records"][0]
        sha = rec["snapshots"]["CiteCounterexample.java"]["sha256"]

        def _ans(status: str, path: str, sl: int, el: int, quote: str, h: str) -> str:
            return json.dumps({
                "status": status,
                "explanation": "counterexample test",
                "fix_suggestion": "use canonical check",
                "citations": [{"path": path, "start_line": sl, "end_line": el, "quote": quote, "sha256": h}],
            })

        # 1. Wrong file path
        with self.assertRaises(EvidenceError):
            validate_answer(_ans("SUPPORTED", "Other.java", sink_ln, sink_ln, lines[sink_ln - 1], sha), rec)
        # 2. Wrong source hash
        with self.assertRaises(EvidenceError):
            validate_answer(_ans("SUPPORTED", "CiteCounterexample.java", sink_ln, sink_ln, lines[sink_ln - 1], "0" * 64), rec)
        # 3. Wrong line text
        with self.assertRaises(EvidenceError):
            validate_answer(_ans("SUPPORTED", "CiteCounterexample.java", sink_ln, sink_ln, "fabricated();", sha), rec)
        # 4. Citation exists in source file snapshot, but was trimmed outside prompt window (posthoc only)
        prompt_lines = {ln["line"] for s in rec["snippets"] for ln in (s.get("lines") or [])}
        trimmed_ln = next(i for i in range(10, sink_ln - 10) if i not in prompt_lines)
        rec["snapshots"]["CiteCounterexample.java"]["lines"] = lines
        with self.assertRaises(EvidenceError) as ctx_posthoc:
            validate_answer(_ans("SUPPORTED", "CiteCounterexample.java", trimmed_ln, trimmed_ln, lines[trimmed_ln - 1], sha), rec)
        self.assertIn("outside compacted prompt window", str(ctx_posthoc.exception))
        # 5. External helper absent from evidence -> REFUTED must be rejected fail-closed!
        with self.assertRaises(EvidenceError):
            validate_answer(_ans("REFUTED", "CiteCounterexample.java", sink_ln - 1, sink_ln - 1, lines[sink_ln - 2], sha), rec)

    def test_prompt_truncation_at_guard_fails_closed_while_fitting_guard_preserved(self) -> None:
        # Case A: Method > 140 lines where canonical guard is near top and sink near bottom -> guard truncated -> fail-closed UNDETERMINED
        src_long = self.root / "src_guard_cut"
        src_long.mkdir()
        filler = "\n".join(f"        int step{i} = {i};" for i in range(145))
        java_long = (
            "package demo;\n"
            "import java.io.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class LongGuardCut {\n"
            "    public FileInputStream open(HttpServletRequest req) throws IOException {\n"
            "        String p = req.getParameter(\"p\");\n"
            "        File base = new File(\"/srv/reports\");\n"
            "        File target = new File(base, p);\n"
            "        String baseCanon = base.getCanonicalPath();\n"
            "        String targetCanon = target.getCanonicalPath();\n"
            "        if (!targetCanon.startsWith(baseCanon + File.separator)) {\n"
            "            throw new SecurityException(\"outside\");\n"
            "        }\n"
            + filler
            + "\n"
            "        return new FileInputStream(target);\n"
            "    }\n"
            "}\n"
        )
        (src_long / "LongGuardCut.java").write_text(java_long, encoding="utf-8")
        lines_long = java_long.splitlines()
        sink_ln = next(i for i, l in enumerate(lines_long, 1) if "new FileInputStream(target)" in l)
        og_long, _ = _make_manifest_and_opengrep(
            src_long,
            "LongGuardCut.java",
            rule_id="ntk.api.java.cwe22.path-traversal",
            cwe="CWE-22",
            source_line=6,
            source_text='req.getParameter("p")',
            sink_line=sink_ln,
            sink_text="new FileInputStream(target)",
            rules_path=self.rules_file,
        )
        b_long = collect(
            og_long.read_bytes(),
            src_long,
            engine_exit=0,
            scan_provenance={"origin": "unit", "source_capture_verified": True, "exit_capture_verified": True, "recorded_engine_exit": 0},
        )
        enrich_bundle_context(b_long, src_long, max_prompt_bytes=DEFAULT_MAX_PROMPT_BYTES)
        rec_long = b_long["records"][0]
        self.assertTrue(any("truncated guard or sanitizer" in iss for iss in rec_long["issues"]), rec_long["issues"])
        # Because issues is non-empty, validate_answer MUST fail closed (refuse SUPPORTED or REFUTED)!
        sha_long = rec_long["snapshots"]["LongGuardCut.java"]["sha256"]
        with self.assertRaises(EvidenceError):
            validate_answer(
                json.dumps({
                    "status": "SUPPORTED",
                    "explanation": "Claims vulnerable without seeing truncated guard.",
                    "fix_suggestion": "Check canonical path.",
                    "citations": [{"path": "LongGuardCut.java", "start_line": sink_ln, "end_line": sink_ln, "quote": lines_long[sink_ln - 1], "sha256": sha_long}],
                }),
                rec_long,
            )

        # Case B: Method fits within 140 lines, padded to exceed 32 KB -> budget trimmer preserves strong guard block intact!
        src_fit = self.root / "src_guard_kept"
        src_fit.mkdir()
        pad_lines = "\n".join(f'        String pad{i} = "' + ("P" * 260) + '";' for i in range(110))
        java_fit = (
            "package demo;\n"
            "import java.io.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class GuardPreserved {\n"
            "    public FileInputStream open(HttpServletRequest req) throws IOException {\n"
            "        String p = req.getParameter(\"p\");\n"
            "        File base = new File(\"/srv/reports\");\n"
            "        File target = new File(base, p);\n"
            "        String baseCanon = base.getCanonicalPath();\n"
            "        String targetCanon = target.getCanonicalPath();\n"
            "        if (!targetCanon.startsWith(baseCanon + File.separator)) {\n"
            "            throw new SecurityException(\"outside\");\n"
            "        }\n"
            + pad_lines
            + "\n"
            "        return new FileInputStream(target);\n"
            "    }\n"
            "}\n"
        )
        (src_fit / "GuardPreserved.java").write_text(java_fit, encoding="utf-8")
        lines_fit = java_fit.splitlines()
        sink_fit = next(i for i, l in enumerate(lines_fit, 1) if "new FileInputStream(target)" in l)
        og_fit, _ = _make_manifest_and_opengrep(
            src_fit,
            "GuardPreserved.java",
            rule_id="ntk.api.java.cwe22.path-traversal",
            cwe="CWE-22",
            source_line=6,
            source_text='req.getParameter("p")',
            sink_line=sink_fit,
            sink_text="new FileInputStream(target)",
            rules_path=self.rules_file,
        )
        b_fit = collect(
            og_fit.read_bytes(),
            src_fit,
            engine_exit=0,
            scan_provenance={"origin": "unit", "source_capture_verified": True, "exit_capture_verified": True, "recorded_engine_exit": 0},
        )
        st_fit = enrich_bundle_context(b_fit, src_fit, max_prompt_bytes=DEFAULT_MAX_PROMPT_BYTES)
        rec_fit = b_fit["records"][0]
        self.assertEqual(st_fit["budget_trimmed"], 1)
        self.assertLessEqual(st_fit["after_prompt_bytes_max"], DEFAULT_MAX_PROMPT_BYTES)
        self.assertEqual(rec_fit["issues"], [])
        kept_lns = {ln["line"] for ln in rec_fit["snippets"][0]["lines"]}
        for gln in (9, 10, 11, 12, 13):
            self.assertIn(gln, kept_lns)

    def test_multi_finding_job_timeout_keeps_all_open_and_fails_closed_remaining(self) -> None:
        src_dir = self.root / "src_multi_timeout"
        src_dir.mkdir()
        java = (
            "package demo;\n"
            "import java.sql.*;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class MultiSql {\n"
            "    public void run(HttpServletRequest req, Statement st) throws Exception {\n"
            "        String u = req.getParameter(\"u\");\n"
            "        st.executeQuery(\"SELECT 1 FROM a WHERE u='\" + u + \"'\");\n"
            "        st.executeQuery(\"SELECT 2 FROM b WHERE u='\" + u + \"'\");\n"
            "        st.executeQuery(\"SELECT 3 FROM c WHERE u='\" + u + \"'\");\n"
            "        st.executeQuery(\"SELECT 4 FROM d WHERE u='\" + u + \"'\");\n"
            "    }\n"
            "}\n"
        )
        jf = src_dir / "MultiSql.java"
        jf.write_text(java, encoding="utf-8")
        raw_bytes = jf.read_bytes()
        lines = raw_bytes.decode("utf-8").splitlines(keepends=True)
        file_sha = digest(raw_bytes)

        def _loc(ln: int, snippet: str) -> dict:
            raw_l = lines[ln - 1].rstrip("\r\n")
            c0 = raw_l.index(snippet)
            pref = sum(len(x.encode("utf-8")) for x in lines[: ln - 1])
            s_off = pref + len(raw_l[:c0].encode("utf-8"))
            return {
                "path": "MultiSql.java",
                "start": {"line": ln, "col": len(raw_l[:c0].encode("utf-8")) + 1, "offset": s_off},
                "end": {"line": ln, "col": len(raw_l[: c0 + len(snippet)].encode("utf-8")) + 1, "offset": s_off + len(snippet.encode("utf-8"))},
            }

        src_loc = _loc(6, 'req.getParameter("u")')
        results = []
        sarif_results = []
        for idx_l in (7, 8, 9, 10):
            snk_txt = lines[idx_l - 1].strip().rstrip(";")
            snk_loc = _loc(idx_l, snk_txt)
            results.append({
                "check_id": "ntk.api.java.cwe89.sql-injection",
                "path": "MultiSql.java",
                "start": snk_loc["start"],
                "end": snk_loc["end"],
                "extra": {
                    "message": "[CWE-89] multi",
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-89"]},
                    "dataflow_trace": {
                        "taint_source": ["CliLoc", [src_loc, 'req.getParameter("u")']],
                        "intermediate_vars": [],
                        "taint_sink": ["CliLoc", [snk_loc, snk_txt]],
                    },
                },
            })
            sarif_results.append({
                "ruleId": "ntk.api.java.cwe89.sql-injection",
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "MultiSql.java"},
                        "region": {
                            "startLine": snk_loc["start"]["line"],
                            "endLine": snk_loc["end"]["line"],
                            "startColumn": snk_loc["start"]["col"],
                            "endColumn": snk_loc["end"]["col"],
                        },
                    }
                }],
            })
        cap_dir = src_dir.parent / "capture_multi"
        cap_dir.mkdir(parents=True, exist_ok=True)
        og_bytes = json.dumps({"version": "1.25.0", "results": results, "errors": [], "paths": {"scanned": ["MultiSql.java"], "skipped": []}}).encode("utf-8")
        og_path = cap_dir / "opengrep.json"
        og_path.write_bytes(og_bytes)
        rules_bytes = self.rules_file.read_bytes()
        ver_cmd = ["opengrep", "--version"]
        json_cmd = ["opengrep", "scan", "--json", str(src_dir)]
        sarif_cmd = ["opengrep", "scan", "--sarif", str(src_dir)]
        sarif_bytes = json.dumps({"version": "2.1.0", "runs": [{"results": sarif_results}]}).encode("utf-8")
        extras = {
            "opengrep.json": og_bytes, "opengrep.sarif": sarif_bytes, "rules.snapshot.yml": rules_bytes,
            "version.exit.txt": b"0", "version.command.json": json.dumps(ver_cmd).encode("utf-8"),
            "json.exit.txt": b"0", "json.command.json": json.dumps(json_cmd).encode("utf-8"), "json.stdout.txt": og_bytes,
            "sarif.exit.txt": b"0", "sarif.command.json": json.dumps(sarif_cmd).encode("utf-8"), "sarif.stdout.txt": sarif_bytes,
        }
        artifacts = {}
        for fn, fb in extras.items():
            (cap_dir / fn).write_bytes(fb)
            artifacts[fn] = digest(fb)
        manifest_path = cap_dir / "scan-manifest.json"
        manifest_path.write_text(json.dumps({
            "schema": "ntk-scan-capture-1", "producer": "unit_test_local_capture", "success": True, "issues": [],
            "target_kind": "directory", "sources_before": {"MultiSql.java": file_sha}, "sources_after": {"MultiSql.java": file_sha},
            "rules_before_sha256": digest(rules_bytes), "rules_after_sha256": digest(rules_bytes), "artifacts": artifacts,
            "runs": {"version": {"argv": ver_cmd, "exit_code": 0}, "json": {"argv": json_cmd, "exit_code": 0, "output_mode": "stdout"}, "sarif": {"argv": sarif_cmd, "exit_code": 0, "output_mode": "stdout"}},
        }), encoding="utf-8")

        model_name = "qwen3.5:9b-q4_K_M"
        line7_txt = java.splitlines()[6]

        class _SlowFirstOllama(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                return

            def do_GET(self):
                body = json.dumps({"models": [{"name": model_name, "digest": "b" * 64, "size": 100}]}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                n = int(self.headers.get("Content-Length", "0"))
                _ = self.rfile.read(n)
                time.sleep(1.0)  # Consumes budget so subsequent findings hit JOB_TIMEOUT (<2.0s left)
                ans = json.dumps({
                    "status": "SUPPORTED",
                    "explanation": "SQL concat",
                    "fix_suggestion": "Use PreparedStatement",
                    "citations": [{"path": "MultiSql.java", "start_line": 7, "end_line": 7, "quote": line7_txt, "sha256": file_sha}],
                })
                body = json.dumps({"model": model_name, "done": True, "done_reason": "stop", "mock_test_fixture": True, "message": {"role": "assistant", "content": ans}}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _SlowFirstOllama)
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        try:
            triage_dir = self.root / "triage_multi_to"
            res = run_bounded_triage(
                source_root=src_dir,
                triage_dir=triage_dir,
                raw_json_path=og_path,
                manifest_path=manifest_path,
                path_maps=[],
                rules_path=self.rules_file,
                no_llm=False,
                prompt_contract="blind",
                ollama_endpoint=f"http://127.0.0.1:{srv.server_port}",
                ollama_model=model_name,
                ollama_timeout_seconds=10.0,
                runtime_origin="mock",
                deadline_mono=time.monotonic() + 2.8,  # Allows 1st call (1.0s), triggers JOB_TIMEOUT (<2.0s left) on #2..#4
            )
            self.assertEqual(res["live_calls"], 1)
            self.assertEqual(res["timeout_aborts"], 3)
            self.assertEqual(res["assessments_list"][0]["validated_status"], "SUPPORTED")
            for a in res["assessments_list"][1:]:
                self.assertEqual(a["validated_status"], "UNDETERMINED")
                self.assertEqual(a["failure_kind"], "JOB_TIMEOUT")
            self.assertTrue(all(r["state"] == "OPEN" for r in res["assessments_rows"]))
            cap_chk = verify_http_capture.verify_run_http_captures(triage_dir, require_live_chat=False)
            self.assertTrue(cap_chk["capture_integrity_ok"], cap_chk["errors"])
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main()
