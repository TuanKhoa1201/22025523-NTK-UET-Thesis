"""Byte-for-byte raw HTTP capture & SHA-256 verification tests (B1).

All HTTP responses in this test module are explicit local loopback MOCK fixtures;
zero calls are made to real Ollama/Qwen.
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import unittest

from v2.triage import live_check
from v2.triage.evidence import collect, digest, strict_json
from v2.triage.ollama import (
    MAX_HTTP_BODY_BYTES,
    CaptureWriteError,
    OllamaClient,
    _prepare_safe_capture_dir,
    request_payload,
)
from v2.triage.runtime import SCHEMA_VERSION
from v2.triage.store import ReviewStore
from v2.triage.verify_http_capture import (
    _verify_tags_captures,
    main as verify_cli_main,
    verify_run_http_captures,
)


def _write_triage_run_files(triage_dir: Path, bundle: dict, assessments: list[dict]) -> None:
    triage_dir.mkdir(parents=True, exist_ok=True)
    (triage_dir / "evidence.json").write_text(json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = []
    for rec, assessment in zip(bundle["records"], assessments):
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
        lines.append(json.dumps(row, ensure_ascii=False))
    (triage_dir / "assessments.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")


class RawHttpCaptureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tmp_root = Path(self.tmp.name).resolve()
        self.src_root = self.tmp_root / "src"
        self.src_root.mkdir()
        self.java_file = self.src_root / "Demo.java"
        self.java_text = (
            "class Demo {\n"
            "  void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt) throws Exception {\n"
            '    String input = req.getParameter("x");\n'
            '    String sql = "SELECT " + input;\n'
            "    stmt.executeQuery(sql);\n"
            "    java.io.FileInputStream fis = new java.io.FileInputStream(input);\n"
            "    fis.close();\n"
            "  }\n"
            "}\n"
        )
        self.java_file.write_bytes(self.java_text.encode("utf-8"))
        lines_ke = self.java_text.splitlines(keepends=True)
        lines = self.java_text.splitlines()

        def pt(ln: int, col: int) -> dict[str, int]:
            return {"line": ln, "col": col, "offset": sum(len(x.encode("utf-8")) for x in lines_ke[: ln - 1]) + col - 1}

        def loc(ln: int, txt: str) -> dict:
            c = lines[ln - 1].index(txt) + 1
            return {"path": "Demo.java", "start": pt(ln, c), "end": pt(ln, c + len(txt.encode("utf-8")))}

        def tag(ln: int, txt: str) -> list:
            return ["CliLoc", [loc(ln, txt), txt]]

        self.raw_scan = {
            "results": [
                {
                    "check_id": "test.cwe89",
                    "path": "Demo.java",
                    "start": pt(5, 5),
                    "end": pt(5, 27),
                    "extra": {
                        "severity": "ERROR",
                        "metadata": {"cwe": ["CWE-89"]},
                        "message": "SQLi",
                        "dataflow_trace": {
                            "taint_source": tag(3, 'req.getParameter("x")'),
                            "intermediate_vars": [{"location": loc(4, "sql"), "content": "sql"}],
                            "taint_sink": tag(5, "stmt.executeQuery(sql)"),
                        },
                    },
                },
                {
                    "check_id": "test.cwe22",
                    "path": "Demo.java",
                    "start": pt(6, 35),
                    "end": pt(6, 69),
                    "extra": {
                        "severity": "ERROR",
                        "metadata": {"cwe": ["CWE-22"]},
                        "message": "Path traversal",
                        "dataflow_trace": {
                            "taint_source": tag(3, 'req.getParameter("x")'),
                            "intermediate_vars": [],
                            "taint_sink": tag(6, "new java.io.FileInputStream(input)"),
                        },
                    },
                },
            ],
            "errors": [],
        }
        self.bundle_two = collect(
            json.dumps(self.raw_scan),
            self.src_root,
            engine_exit=0,
            scan_provenance={"origin": "UNIT_TEST_MOCK_CAPTURE", "source_capture_verified": True},
        )
        self.bundle_one = collect(
            json.dumps({"results": [self.raw_scan["results"][0]], "errors": []}),
            self.src_root,
            engine_exit=0,
            scan_provenance={"origin": "UNIT_TEST_MOCK_CAPTURE", "source_capture_verified": True},
        )
        self.record0 = self.bundle_one["records"][0]
        self.snap_sha = self.record0["snapshots"]["Demo.java"]["sha256"]

    def _valid_content_json(self, line_no: int = 5) -> str:
        quote = self.java_text.splitlines()[line_no - 1]
        return json.dumps(
            {
                "status": "SUPPORTED",
                "explanation": "MOCK: Tiếng Việt — đường dẫn / truy vấn nhận dữ liệu chưa lọc.",
                "citations": [
                    {
                        "path": "Demo.java",
                        "start_line": line_no,
                        "end_line": line_no,
                        "quote": quote,
                        "sha256": self.snap_sha,
                    }
                ],
                "fix_suggestion": "MOCK: Sử dụng tham số hóa hoặc chuẩn hóa đường dẫn.",
            },
            ensure_ascii=False,
        )

    def test_01_http200_preserves_exact_unicode_whitespace_crlf_and_key_order_bytes(self):
        received_requests: list[tuple[str, str, bytes]] = []
        content_escaped = json.dumps(self._valid_content_json(5), ensure_ascii=False)
        # Hand-crafted raw bytes with irregular whitespace, CRLF, tabs, unsorted keys, raw UTF-8 + \uXXXX escape
        server_sent_bytes = (
            '{\r\n'
            '   "mock_test_fixture" : true ,\r\n'
            '\t"eval_duration" :  9876543 ,\r\n'
            '  "eval_count": 42,\n'
            '  "done_reason" : "stop" ,\r\n'
            '  "model" : "qwen3.5:9b-q4_K_M",\r\n'
            '  " unicode_probe_note_not_forbidden " : false,\r\n'
            f'  "message" :\r\n    {{\r\n      "role": "assistant",\r\n      "content" : {content_escaped}\r\n    }} ,\r\n'
            '  "done" :   true\r\n'
            '}\r\n'
        ).replace('" unicode_probe_note_not_forbidden " : false,\r\n', "")
        # Also inject a \uXXXX escape inside message.role-adjacent envelope string (created_at) so escape representation differs from json.dumps!
        server_sent_bytes_raw = server_sent_bytes.replace(
            '"done" :   true',
            '"created_at" : "2026-11-14T00:00:00Z\\u002b00:00 — Ti\u1ebfng Vi\u1ec7t",\r\n  "done" :   true',
        ).encode("utf-8")

        class _ExactBytesHandler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                req_raw = self.rfile.read(length)
                received_requests.append((self.command, self.path, req_raw))
                self.send_response(200, "OK")
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("X-Test-Header", "same-call-raw")
                self.send_header("Content-Length", str(len(server_sent_bytes_raw)))
                self.end_headers()
                self.wfile.write(server_sent_bytes_raw)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _ExactBytesHandler)
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        self.addCleanup(lambda: (srv.shutdown(), srv.server_close(), th.join(timeout=2)))

        triage_dir = self.tmp_root / "run_01" / "triage"
        io_dir = triage_dir / "llm_io"
        client = OllamaClient(
            endpoint=f"http://127.0.0.1:{srv.server_port}",
            model="qwen3.5:9b-q4_K_M",
            timeout=10,
            runtime_origin="mock",
            io_log_dir=io_dir,
        )
        assessment = client.analyze(self.record0)
        _write_triage_run_files(triage_dir, self.bundle_one, [assessment])

        # Exactly 1 HTTP POST — never a second call to obtain raw bytes
        self.assertEqual(len(received_requests), 1)
        self.assertEqual(received_requests[0][0], "POST")
        self.assertEqual(received_requests[0][1], "/api/chat")

        fid = self.record0["id"]
        req_bin = (io_dir / f"{fid}.request.body.bin").read_bytes()
        resp_bin = (io_dir / f"{fid}.response.body.bin").read_bytes()
        receipt = strict_json((io_dir / f"{fid}.http-capture.json").read_text(encoding="utf-8"))
        resp_json_wrapper = strict_json((io_dir / f"{fid}.response.json").read_text(encoding="utf-8"))

        # Request raw bytes == exact bytes received by HTTP server == canonical request_payload serialization
        self.assertEqual(req_bin, received_requests[0][2])
        self.assertEqual(req_bin, json.dumps(request_payload(self.record0, "qwen3.5:9b-q4_K_M")).encode("utf-8"))
        self.assertEqual(digest(req_bin), assessment["runtime"]["request_payload_sha256"])
        self.assertEqual(digest(req_bin), receipt["request_payload_sha256"])

        # Response raw bytes == exact server-sent bytes (including CRLF, tabs, key order, and \u002b escape!)
        self.assertEqual(resp_bin, server_sent_bytes_raw)
        self.assertIn(b"\r\n\t\"eval_duration\" :  9876543", resp_bin)
        self.assertIn(b"\\u002b00:00", resp_bin)
        self.assertNotEqual(resp_bin, json.dumps(assessment["raw_response"], ensure_ascii=False).encode("utf-8"))
        self.assertNotEqual(resp_bin, (io_dir / f"{fid}.response.json").read_bytes())

        # SHA-256 of raw response body matches disk file, distinct from canonical JSON SHA-256
        self.assertEqual(digest(resp_bin), assessment["runtime"]["response_body_sha256"])
        self.assertEqual(digest(resp_bin), receipt["response_body_sha256"])
        self.assertNotEqual(assessment["runtime"]["response_body_sha256"], assessment["runtime"]["response_json_sha256"])

        # Scope honesty & compatibility JSON preservation
        self.assertEqual(receipt["capture_scope"], "http_body_and_client_metadata_not_tcp_wire")
        self.assertIn("response.body.bin", resp_json_wrapper["raw_response_note"])
        self.assertEqual(assessment["validated_status"], "SUPPORTED")
        self.assertTrue(assessment["runtime"]["answer_validated"])

        # Verifier passes
        ver = verify_run_http_captures(triage_dir, require_live_chat=False)
        self.assertTrue(ver["capture_integrity_ok"], ver["errors"])
        self.assertEqual(ver["capture_status"], "VERIFIED_COMPLETE")
        # Mock origin must NOT pass require_live_chat=True!
        ver_live = verify_run_http_captures(triage_dir, require_live_chat=True)
        self.assertFalse(ver_live["live_chat_verified"])

    def test_02_malformed_json_duplicate_keys_and_invalid_utf8_preserve_raw_bytes_and_stay_open(self):
        payloads = [
            ("truncated_json", b'{"done":true,"model":"qwen3.5:9b-q4_K_M","message":{"content":"{\\"status\\":\\"REFUTED\\"\r\n'),
            ("duplicate_keys", b'{"done": true, "done": true, "model": "qwen3.5:9b-q4_K_M", "message": {"content": "{}"}}'),
            ("invalid_utf8", b'\xff\xfe\x80\x00{"broken_utf8": true}\r\n'),
        ]
        for label, bad_bytes in payloads:
            with self.subTest(case=label):
                post_count = 0

                class _BadBodyHandler(BaseHTTPRequestHandler):
                    def log_message(self, *args):
                        pass

                    def do_POST(self):
                        nonlocal post_count
                        post_count += 1
                        length = int(self.headers.get("Content-Length", "0"))
                        if length:
                            self.rfile.read(length)
                        self.send_response(200)
                        self.send_header("Content-Length", str(len(bad_bytes)))
                        self.end_headers()
                        self.wfile.write(bad_bytes)

                srv = ThreadingHTTPServer(("127.0.0.1", 0), _BadBodyHandler)
                th = threading.Thread(target=srv.serve_forever, daemon=True)
                th.start()
                try:
                    triage_dir = self.tmp_root / f"run_02_{label}" / "triage"
                    io_dir = triage_dir / "llm_io"
                    client = OllamaClient(
                        endpoint=f"http://127.0.0.1:{srv.server_port}",
                        model="qwen3.5:9b-q4_K_M",
                        timeout=10,
                        runtime_origin="mock",
                        io_log_dir=io_dir,
                    )
                    assessment = client.analyze(self.record0)
                    _write_triage_run_files(triage_dir, self.bundle_one, [assessment])

                    self.assertEqual(post_count, 1, "must never retry on malformed JSON / invalid UTF-8")
                    self.assertIsNone(assessment["raw_response"])
                    self.assertEqual(assessment["validated_status"], "UNDETERMINED")
                    self.assertEqual(assessment["failure_kind"], "MALFORMED_JSON")
                    self.assertFalse(assessment["runtime"]["answer_validated"])

                    fid = self.record0["id"]
                    saved_raw = (io_dir / f"{fid}.response.body.bin").read_bytes()
                    self.assertEqual(saved_raw, bad_bytes)
                    self.assertEqual(digest(bad_bytes), assessment["runtime"]["response_body_sha256"])

                    store = ReviewStore(triage_dir / "review.sqlite")
                    try:
                        store.add(self.bundle_one, [assessment])
                        q = store.queue()
                        self.assertEqual(len(q), 1)
                        self.assertEqual(q[0]["state"], "OPEN")
                    finally:
                        store.close()

                    ver = verify_run_http_captures(triage_dir, require_live_chat=False)
                    self.assertTrue(ver["capture_integrity_ok"], ver["errors"])
                    self.assertEqual(ver["capture_status"], "VERIFIED_COMPLETE")
                finally:
                    srv.shutdown()
                    srv.server_close()
                    th.join(timeout=2)

    def test_03_http_404_and_500_preserve_undecodable_binary_error_bodies(self):
        cases = [
            (404, b'{"error":"model not found"}\xff\xfe', "MODEL_UNAVAILABLE"),
            (500, b"\x89PNG\r\n\x1a\n\xff\x00internal server binary dump", "HTTP_ERROR"),
        ]
        for code, err_bytes, expected_kind in cases:
            with self.subTest(http_status=code):
                class _ErrHandler(BaseHTTPRequestHandler):
                    def log_message(self, *args):
                        pass

                    def do_POST(self):
                        length = int(self.headers.get("Content-Length", "0"))
                        if length:
                            self.rfile.read(length)
                        self.send_response(code)
                        self.send_header("X-Error-Tag", f"err-{code}")
                        self.send_header("Content-Length", str(len(err_bytes)))
                        self.end_headers()
                        self.wfile.write(err_bytes)

                srv = ThreadingHTTPServer(("127.0.0.1", 0), _ErrHandler)
                th = threading.Thread(target=srv.serve_forever, daemon=True)
                th.start()
                try:
                    triage_dir = self.tmp_root / f"run_03_{code}" / "triage"
                    io_dir = triage_dir / "llm_io"
                    client = OllamaClient(
                        endpoint=f"http://127.0.0.1:{srv.server_port}",
                        model="qwen3.5:9b-q4_K_M",
                        timeout=10,
                        runtime_origin="mock",
                        io_log_dir=io_dir,
                    )
                    assessment = client.analyze(self.record0)
                    _write_triage_run_files(triage_dir, self.bundle_one, [assessment])

                    fid = self.record0["id"]
                    saved_err = (io_dir / f"{fid}.response.body.bin").read_bytes()
                    receipt = strict_json((io_dir / f"{fid}.http-capture.json").read_text(encoding="utf-8"))
                    self.assertEqual(saved_err, err_bytes)
                    self.assertEqual(digest(err_bytes), assessment["runtime"]["response_body_sha256"])
                    self.assertEqual(receipt["completeness"], "complete_http_error_body")
                    self.assertEqual(receipt["http_status"], code)
                    self.assertTrue(any(k.lower() == "x-error-tag" for k, _ in receipt["response_headers"]))
                    self.assertEqual(assessment["failure_kind"], expected_kind)
                    self.assertEqual(assessment["validated_status"], "UNDETERMINED")

                    ver = verify_run_http_captures(triage_dir, require_live_chat=False)
                    self.assertTrue(ver["capture_integrity_ok"], ver["errors"])
                    self.assertEqual(ver["capture_status"], "VERIFIED_ERROR_OR_PARTIAL_CAPTURED")
                finally:
                    srv.shutdown()
                    srv.server_close()
                    th.join(timeout=2)

    def test_04_timeout_partial_read_and_oversize_body_never_claim_complete_hash(self):
        # 4a) Timeout before HTTP response headers/body
        sock_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock_srv.bind(("127.0.0.1", 0))
        sock_srv.listen(1)
        port_timeout = sock_srv.getsockname()[1]

        def _stall_peer():
            try:
                conn, _ = sock_srv.accept()
                with conn:
                    conn.recv(4096)
                    time.sleep(0.45)
            except OSError:
                pass
            finally:
                sock_srv.close()

        th_timeout = threading.Thread(target=_stall_peer, daemon=True)
        th_timeout.start()
        triage_t = self.tmp_root / "run_04_timeout" / "triage"
        client_t = OllamaClient(
            endpoint=f"http://127.0.0.1:{port_timeout}",
            model="qwen3.5:9b-q4_K_M",
            timeout=0.15,
            runtime_origin="mock",
            io_log_dir=triage_t / "llm_io",
        )
        a_t = client_t.analyze(self.record0)
        th_timeout.join(timeout=2)
        _write_triage_run_files(triage_t, self.bundle_one, [a_t])
        fid = self.record0["id"]
        self.assertTrue((triage_t / "llm_io" / f"{fid}.request.body.bin").is_file())
        self.assertFalse((triage_t / "llm_io" / f"{fid}.response.body.bin").exists())
        self.assertFalse((triage_t / "llm_io" / f"{fid}.response.incomplete.bin").exists())
        self.assertIsNone(a_t["runtime"]["response_body_sha256"])
        self.assertEqual(a_t["failure_kind"], "TIMEOUT")
        rec_t = strict_json((triage_t / "llm_io" / f"{fid}.http-capture.json").read_text(encoding="utf-8"))
        self.assertEqual(rec_t["completeness"], "no_body_received")
        self.assertFalse(rec_t["complete"])
        self.assertTrue(verify_run_http_captures(triage_t)["capture_integrity_ok"])

        # 4b) Partial HTTP body truncated mid-stream relative to Content-Length (clean FIN after partial bytes)
        partial_payload = b'{"done":false,"partial":123'

        class _PartialBodyHandler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                if length:
                    self.rfile.read(length)
                self.wfile.write(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: 500\r\n"
                    b"Connection: close\r\n\r\n"
                    + partial_payload
                )
                self.wfile.flush()

        srv_part = ThreadingHTTPServer(("127.0.0.1", 0), _PartialBodyHandler)
        th_part = threading.Thread(target=srv_part.serve_forever, daemon=True)
        th_part.start()
        try:
            triage_p = self.tmp_root / "run_04_partial" / "triage"
            client_p = OllamaClient(
                endpoint=f"http://127.0.0.1:{srv_part.server_port}",
                model="qwen3.5:9b-q4_K_M",
                timeout=5,
                runtime_origin="mock",
                io_log_dir=triage_p / "llm_io",
            )
            a_p = client_p.analyze(self.record0)
            _write_triage_run_files(triage_p, self.bundle_one, [a_p])
            self.assertFalse((triage_p / "llm_io" / f"{fid}.response.body.bin").exists())
            inc_file = triage_p / "llm_io" / f"{fid}.response.incomplete.bin"
            self.assertTrue(inc_file.is_file())
            self.assertEqual(inc_file.read_bytes(), partial_payload)
            self.assertIsNone(a_p["runtime"]["response_body_sha256"])
            self.assertEqual(a_p["failure_kind"], "TRUNCATED_OUTPUT")
            rec_p = strict_json((triage_p / "llm_io" / f"{fid}.http-capture.json").read_text(encoding="utf-8"))
            self.assertEqual(rec_p["completeness"], "partial_read_error")
            self.assertFalse(rec_p["complete"])
            self.assertEqual(rec_p["response_incomplete_sha256"], digest(partial_payload))
            self.assertTrue(verify_run_http_captures(triage_p)["capture_integrity_ok"])
        finally:
            srv_part.shutdown()
            srv_part.server_close()
            th_part.join(timeout=2)

        # 4b-chunked) Truncated chunked transfer raising http.client.IncompleteRead with partial bytes
        chunk_partial = b'{"chunked_partial":true'

        class _ChunkedTruncatedHandler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                if length:
                    self.rfile.read(length)
                # Deliver chunk 1 cleanly, then close socket before terminating 0\r\n\r\n chunk!
                first_chunk_frame = f"{len(chunk_partial):x}\r\n".encode("ascii") + chunk_partial + b"\r\n"
                self.wfile.write(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Transfer-Encoding: chunked\r\n"
                    b"Connection: close\r\n\r\n"
                    + first_chunk_frame
                )
                self.wfile.flush()

        srv_chk = ThreadingHTTPServer(("127.0.0.1", 0), _ChunkedTruncatedHandler)
        th_chk = threading.Thread(target=srv_chk.serve_forever, daemon=True)
        th_chk.start()
        try:
            triage_c = self.tmp_root / "run_04_chunked_incomplete" / "triage"
            client_c = OllamaClient(
                endpoint=f"http://127.0.0.1:{srv_chk.server_port}",
                model="qwen3.5:9b-q4_K_M",
                timeout=5,
                runtime_origin="mock",
                io_log_dir=triage_c / "llm_io",
            )
            a_c = client_c.analyze(self.record0)
            _write_triage_run_files(triage_c, self.bundle_one, [a_c])
            self.assertFalse((triage_c / "llm_io" / f"{fid}.response.body.bin").exists())
            inc_chk = triage_c / "llm_io" / f"{fid}.response.incomplete.bin"
            self.assertTrue(inc_chk.is_file())
            self.assertEqual(inc_chk.read_bytes(), chunk_partial)
            self.assertIsNone(a_c["runtime"]["response_body_sha256"])
            self.assertEqual(a_c["failure_kind"], "TRUNCATED_OUTPUT")
            self.assertTrue(verify_run_http_captures(triage_c)["capture_integrity_ok"])
        finally:
            srv_chk.shutdown()
            srv_chk.server_close()
            th_chk.join(timeout=2)

        # 4c) Oversized HTTP body exceeding MAX_HTTP_BODY_BYTES
        oversized = b"X" * (MAX_HTTP_BODY_BYTES + 2048)

        class _OversizeHandler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                if length:
                    self.rfile.read(length)
                self.send_response(200)
                self.send_header("Content-Length", str(len(oversized)))
                self.end_headers()
                self.wfile.write(oversized)

        srv_o = ThreadingHTTPServer(("127.0.0.1", 0), _OversizeHandler)
        th_o = threading.Thread(target=srv_o.serve_forever, daemon=True)
        th_o.start()
        try:
            triage_o = self.tmp_root / "run_04_oversize" / "triage"
            client_o = OllamaClient(
                endpoint=f"http://127.0.0.1:{srv_o.server_port}",
                model="qwen3.5:9b-q4_K_M",
                timeout=10,
                runtime_origin="mock",
                io_log_dir=triage_o / "llm_io",
            )
            a_o = client_o.analyze(self.record0)
            _write_triage_run_files(triage_o, self.bundle_one, [a_o])
            self.assertFalse((triage_o / "llm_io" / f"{fid}.response.body.bin").exists())
            inc_o = (triage_o / "llm_io" / f"{fid}.response.incomplete.bin").read_bytes()
            self.assertEqual(len(inc_o), MAX_HTTP_BODY_BYTES)
            self.assertIsNone(a_o["runtime"]["response_body_sha256"])
            self.assertEqual(a_o["failure_kind"], "PROMPT_TOO_LARGE")
            rec_o = strict_json((triage_o / "llm_io" / f"{fid}.http-capture.json").read_text(encoding="utf-8"))
            self.assertEqual(rec_o["completeness"], "exceeded_max_bytes_prefix_only")
            self.assertFalse(rec_o["complete"])
            self.assertTrue(verify_run_http_captures(triage_o)["capture_integrity_ok"])
        finally:
            srv_o.shutdown()
            srv_o.server_close()
            th_o.join(timeout=2)

    def test_05_consecutive_findings_and_tags_probe_isolation(self):
        tags_raw = b'{\r\n  "models": [ { "name": "qwen3.5:9b-q4_K_M", "digest": "sha256:mock123", "size": 1234 } ]\r\n}\r\n'
        f1_content = self._valid_content_json(6)
        f1_raw = json.dumps({
            "mock_test_fixture": True,
            "done": True,
            "done_reason": "stop",
            "model": "qwen3.5:9b-q4_K_M",
            "eval_count": 19,
            "eval_duration": 100000,
            "message": {"role": "assistant", "content": f1_content},
        }, ensure_ascii=False).encode("utf-8")
        chat_step = 0

        class _MultiHandler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", str(len(tags_raw)))
                self.end_headers()
                self.wfile.write(tags_raw)

            def do_POST(self):
                nonlocal chat_step
                chat_step += 1
                length = int(self.headers.get("Content-Length", "0"))
                if length:
                    self.rfile.read(length)
                if chat_step == 1:
                    err = b'{"error":"temporary 500 on first finding"}'
                    self.send_response(500)
                    self.send_header("Content-Length", str(len(err)))
                    self.end_headers()
                    self.wfile.write(err)
                else:
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(f1_raw)))
                    self.end_headers()
                    self.wfile.write(f1_raw)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _MultiHandler)
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        self.addCleanup(lambda: (srv.shutdown(), srv.server_close(), th.join(timeout=2)))

        triage_dir = self.tmp_root / "run_05" / "triage"
        io_dir = triage_dir / "llm_io"
        client = OllamaClient(
            endpoint=f"http://127.0.0.1:{srv.server_port}",
            model="qwen3.5:9b-q4_K_M",
            timeout=10,
            runtime_origin="mock",
            io_log_dir=io_dir,
        )
        inv = client.verify_model_installed()
        self.assertTrue(inv["reachable"])
        self.assertTrue(inv["model_found"])
        self.assertEqual((io_dir / "_tags" / "tags-0001.response.body.bin").read_bytes(), tags_raw)

        rec_a, rec_b = self.bundle_two["records"]
        a0 = client.analyze(rec_a)
        a1 = client.analyze(rec_b)
        _write_triage_run_files(triage_dir, self.bundle_two, [a0, a1])

        self.assertEqual(a0["failure_kind"], "HTTP_ERROR")
        self.assertEqual(a0["validated_status"], "UNDETERMINED")
        self.assertEqual(a1["failure_kind"], "NONE")
        self.assertEqual(a1["validated_status"], "SUPPORTED")

        # Verify distinct call_ids and no cross-finding contamination
        r0 = strict_json((io_dir / f"{rec_a['id']}.http-capture.json").read_text(encoding="utf-8"))
        r1 = strict_json((io_dir / f"{rec_b['id']}.http-capture.json").read_text(encoding="utf-8"))
        rt = strict_json((io_dir / "_tags" / "tags-0001.http-capture.json").read_text(encoding="utf-8"))
        self.assertEqual(len({r0["call_id"], r1["call_id"], rt["call_id"]}), 3)
        self.assertIsNone(
            strict_json((io_dir / f"{rec_b['id']}.response.json").read_text(encoding="utf-8"))["http_error_body"]
        )

        ver = verify_run_http_captures(triage_dir, require_live_chat=False)
        self.assertTrue(ver["capture_integrity_ok"], ver["errors"])
        self.assertEqual(len(ver["tags_probes"]), 1)

    def test_06_collision_tamper_missing_and_unwritable_capture_fail_closed(self):
        good_raw = json.dumps({
            "mock_test_fixture": True,
            "done": True,
            "done_reason": "stop",
            "model": "qwen3.5:9b-q4_K_M",
            "eval_count": 15,
            "eval_duration": 50000,
            "message": {"role": "assistant", "content": self._valid_content_json(5)},
        }).encode("utf-8")
        post_calls = 0

        class _GoodHandler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                nonlocal post_calls
                post_calls += 1
                length = int(self.headers.get("Content-Length", "0"))
                if length:
                    self.rfile.read(length)
                self.send_response(200)
                self.send_header("Content-Length", str(len(good_raw)))
                self.end_headers()
                self.wfile.write(good_raw)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _GoodHandler)
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        self.addCleanup(lambda: (srv.shutdown(), srv.server_close(), th.join(timeout=2)))

        # 6a) Collision on same finding_id in same io_log_dir refuses overwrite & does NOT call server again
        triage_dir = self.tmp_root / "run_06_collision" / "triage"
        io_dir = triage_dir / "llm_io"
        client = OllamaClient(
            endpoint=f"http://127.0.0.1:{srv.server_port}",
            model="qwen3.5:9b-q4_K_M",
            timeout=10,
            runtime_origin="mock",
            io_log_dir=io_dir,
        )
        first = client.analyze(self.record0)
        self.assertEqual(first["validated_status"], "SUPPORTED")
        self.assertEqual(post_calls, 1)
        fid = self.record0["id"]
        orig_resp_bytes = (io_dir / f"{fid}.response.body.bin").read_bytes()

        second = client.analyze(self.record0)
        self.assertEqual(post_calls, 1, "collision must fail before issuing a duplicate HTTP request")
        self.assertEqual(second["validated_status"], "UNDETERMINED")
        self.assertEqual(second["failure_kind"], "EVIDENCE_CAPTURE_WRITE_FAILED")
        self.assertFalse(second["runtime"]["answer_validated"])
        self.assertFalse(second["security_conclusion_verified"])
        self.assertEqual((io_dir / f"{fid}.response.body.bin").read_bytes(), orig_resp_bytes)

        # 6b) Response-write failure AFTER HTTP 200 (pre-seeded colliding .response.body.bin only):
        # preserves raw_model_status='SUPPORTED', downgrades validated_status='UNDETERMINED', no retry!
        triage_partial_fail = self.tmp_root / "run_06_resp_write_fail" / "triage"
        io_partial = triage_partial_fail / "llm_io"
        io_partial.mkdir(parents=True)
        (io_partial / f"{fid}.response.body.bin").write_bytes(b"preexisting-collision")
        client_pf = OllamaClient(
            endpoint=f"http://127.0.0.1:{srv.server_port}",
            model="qwen3.5:9b-q4_K_M",
            timeout=10,
            runtime_origin="mock",
            io_log_dir=io_partial,
        )
        res_pf = client_pf.analyze(self.record0)
        self.assertEqual(post_calls, 2)
        self.assertEqual(res_pf["raw_model_status"], "SUPPORTED")
        self.assertEqual(res_pf["validated_status"], "UNDETERMINED")
        self.assertTrue(res_pf["validator_downgraded"])
        self.assertEqual(res_pf["failure_kind"], "EVIDENCE_CAPTURE_WRITE_FAILED")
        self.assertFalse(res_pf["runtime"]["answer_validated"])
        self.assertEqual((io_partial / f"{fid}.response.body.bin").read_bytes(), b"preexisting-collision")
        _write_triage_run_files(triage_partial_fail, self.bundle_one, [res_pf])
        self.assertFalse(verify_run_http_captures(triage_partial_fail)["capture_integrity_ok"])

        # 6c) Unwritable io_log_dir (regular file blocking directory creation)
        blocker_file = self.tmp_root / "blocked_io_file"
        blocker_file.write_bytes(b"not a directory")
        client_unw = OllamaClient(
            endpoint=f"http://127.0.0.1:{srv.server_port}",
            model="qwen3.5:9b-q4_K_M",
            timeout=10,
            runtime_origin="mock",
            io_log_dir=blocker_file,
        )
        res_unw = client_unw.analyze(self.record0)
        self.assertEqual(res_unw["validated_status"], "UNDETERMINED")
        self.assertEqual(res_unw["failure_kind"], "EVIDENCE_CAPTURE_WRITE_FAILED")
        self.assertFalse(res_unw["runtime"]["answer_validated"])

        # 6d) Verifier detects 1-byte tamper, missing file, and orphan file; CLI --no-write keeps triage untouched
        _write_triage_run_files(triage_dir, self.bundle_one, [first])
        self.assertEqual(verify_cli_main([str(triage_dir), "--no-write"]), 0)
        self.assertFalse((triage_dir / "http-capture-check.json").exists())

        resp_path = io_dir / f"{fid}.response.body.bin"
        resp_path.write_bytes(orig_resp_bytes + b" ")
        tampered = verify_run_http_captures(triage_dir)
        self.assertFalse(tampered["capture_integrity_ok"])
        self.assertEqual(tampered["capture_status"], "FAILED")

        # Restore bytes, then plant orphan file -> detected
        resp_path.write_bytes(orig_resp_bytes)
        self.assertTrue(verify_run_http_captures(triage_dir)["capture_integrity_ok"])
        orphan = io_dir / "stray.response.body.bin"
        orphan.write_bytes(b"{}")
        self.assertFalse(verify_run_http_captures(triage_dir)["capture_integrity_ok"])
        orphan.unlink()

        # Delete raw response file -> detected
        resp_path.unlink()
        self.assertFalse(verify_run_http_captures(triage_dir)["capture_integrity_ok"])

    def test_07_f01_rejects_junction_and_symlink_escape_before_io_or_http(self):
        post_hits = {"count": 0}
        get_hits = {"count": 0}

        class _CountingHandler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                get_hits["count"] += 1
                body = json.dumps({"models": [{"name": "qwen3.5:9b-q4_K_M", "digest": "d", "size": 1}]}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                post_hits["count"] += 1
                length = int(self.headers.get("Content-Length", "0"))
                self.rfile.read(length)
                self.send_error(500)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _CountingHandler)
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        self.addCleanup(lambda: (srv.shutdown(), srv.server_close(), th.join(timeout=2)))
        endpoint = f"http://127.0.0.1:{srv.server_port}"

        outside = self.tmp_root / "outside_escape_target"
        outside.mkdir()

        def _make_link(link_path: Path, target: Path, *, is_dir: bool = True) -> bool:
            if os.name == "nt" and is_dir:
                proc = subprocess.run(
                    ["cmd.exe", "/c", "mklink", "/J", str(link_path), str(target)],
                    capture_output=True,
                    text=True,
                )
                return proc.returncode == 0
            try:
                os.symlink(str(target), str(link_path), target_is_directory=is_dir)
                return True
            except (OSError, NotImplementedError):
                return False

        # Case A: llm_io itself is a junction / directory symlink -> zero external writes, zero POST calls
        triage_a = self.tmp_root / "triage_junc_io"
        triage_a.mkdir()
        io_a = triage_a / "llm_io"
        if not _make_link(io_a, outside, is_dir=True):
            self.skipTest("Neither Windows mklink /J nor os.symlink is available")

        client_a = OllamaClient(
            endpoint=endpoint,
            model="qwen3.5:9b-q4_K_M",
            timeout=10,
            runtime_origin="mock",
            io_log_dir=io_a,
            capture_root=triage_a,
        )
        res_a = client_a.analyze(self.record0)
        self.assertEqual(res_a["validated_status"], "UNDETERMINED")
        self.assertEqual(res_a["failure_kind"], "EVIDENCE_CAPTURE_WRITE_FAILED")
        self.assertEqual(post_hits["count"], 0)
        self.assertEqual(list(outside.iterdir()), [])
        _write_triage_run_files(triage_a, self.bundle_one, [res_a])
        rep_a = verify_run_http_captures(triage_a)
        self.assertFalse(rep_a["capture_integrity_ok"])

        # Case B: parent triage directory is a junction / directory symlink
        triage_b = self.tmp_root / "triage_junc_parent"
        self.assertTrue(_make_link(triage_b, outside, is_dir=True))
        client_b = OllamaClient(
            endpoint=endpoint,
            model="qwen3.5:9b-q4_K_M",
            timeout=10,
            runtime_origin="mock",
            io_log_dir=triage_b / "llm_io",
            capture_root=triage_b,
        )
        res_b = client_b.analyze(self.record0)
        self.assertEqual(res_b["validated_status"], "UNDETERMINED")
        self.assertEqual(res_b["failure_kind"], "EVIDENCE_CAPTURE_WRITE_FAILED")
        self.assertEqual(post_hits["count"], 0)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual(verify_cli_main([str(triage_b)]), 2)
        self.assertFalse((outside / "http-capture-check.json").exists())

        # Case C: llm_io/_tags is a junction / directory symlink -> verify_model_installed refuses before GET
        triage_c = self.tmp_root / "triage_junc_tags"
        io_c = triage_c / "llm_io"
        io_c.mkdir(parents=True)
        self.assertTrue(_make_link(io_c / "_tags", outside, is_dir=True))
        client_c = OllamaClient(
            endpoint=endpoint,
            model="qwen3.5:9b-q4_K_M",
            timeout=10,
            runtime_origin="mock",
            io_log_dir=io_c,
            capture_root=triage_c,
        )
        inv_tags = client_c.verify_model_installed()
        self.assertFalse(inv_tags["reachable"])
        self.assertIsNotNone(inv_tags["error"])
        self.assertEqual(get_hits["count"], 0)
        self.assertEqual(list(outside.iterdir()), [])

        # Case D: OS symlink when unprivileged/privileged symlink creation succeeds
        triage_sym = self.tmp_root / "triage_os_symlink"
        triage_sym.mkdir()
        try:
            os.symlink(str(outside), str(triage_sym / "llm_io"), target_is_directory=True)
        except (OSError, NotImplementedError):
            pass
        else:
            client_sym = OllamaClient(
                endpoint=endpoint,
                model="qwen3.5:9b-q4_K_M",
                timeout=10,
                runtime_origin="mock",
                io_log_dir=triage_sym / "llm_io",
                capture_root=triage_sym,
            )
            res_sym = client_sym.analyze(self.record0)
            self.assertEqual(res_sym["failure_kind"], "EVIDENCE_CAPTURE_WRITE_FAILED")
            self.assertEqual(post_hits["count"], 0)
            self.assertEqual(list(outside.iterdir()), [])

    def test_08_f02_verifier_rejects_tags_escape_noncanonical_receipts_and_oversize_raw(self):
        content_escaped = json.dumps(self._valid_content_json(5), ensure_ascii=False)
        ok_body = json.dumps(
            {
                "done": True,
                "done_reason": "stop",
                "model": "qwen3.5:9b-q4_K_M",
                "mock_test_fixture": True,
                "message": {"role": "assistant", "content": json.loads(content_escaped)},
            },
            ensure_ascii=False,
        ).encode("utf-8")

        class _OkHandler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                body = json.dumps({"models": [{"name": "qwen3.5:9b-q4_K_M", "digest": "d", "size": 1}]}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                self.rfile.read(length)
                self.send_response(200)
                self.send_header("Content-Length", str(len(ok_body)))
                self.end_headers()
                self.wfile.write(ok_body)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _OkHandler)
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        self.addCleanup(lambda: (srv.shutdown(), srv.server_close(), th.join(timeout=2)))

        triage_dir = self.tmp_root / "triage_f02"
        io_dir = triage_dir / "llm_io"
        client = OllamaClient(
            endpoint=f"http://127.0.0.1:{srv.server_port}",
            model="qwen3.5:9b-q4_K_M",
            timeout=10,
            runtime_origin="mock",
            io_log_dir=io_dir,
            capture_root=triage_dir,
        )
        inv = client.verify_model_installed()
        self.assertTrue(inv["reachable"])
        self.assertTrue(inv["model_found"])
        res = client.analyze(self.record0)
        _write_triage_run_files(triage_dir, self.bundle_one, [res])
        self.assertTrue(verify_run_http_captures(triage_dir)["capture_integrity_ok"])

        tags_dir = io_dir / "_tags"
        tags_receipt = tags_dir / "tags-0001.http-capture.json"
        orig_receipt = tags_receipt.read_bytes()
        receipt_doc = json.loads(orig_receipt.decode("utf-8"))

        # 2a) Absolute path in tags response_raw_file -> FAIL
        outside_bin = self.tmp_root / "outside_tags_raw.bin"
        outside_bin.write_bytes(b'{"models":[]}')
        tampered_abs = dict(receipt_doc, response_raw_file=str(outside_bin), response_sha256=digest(b'{"models":[]}'))
        tags_receipt.write_text(json.dumps(tampered_abs), encoding="utf-8")
        self.assertFalse(verify_run_http_captures(triage_dir)["capture_integrity_ok"])

        # 2b) Parent traversal '../' in tags response_raw_file -> FAIL
        tampered_trav = dict(receipt_doc, response_raw_file="../" + self.record0["id"] + ".response.body.bin")
        tags_receipt.write_text(json.dumps(tampered_trav), encoding="utf-8")
        self.assertFalse(verify_run_http_captures(triage_dir)["capture_integrity_ok"])

        # Restore valid receipt, add unexpected JSON file -> FAIL
        tags_receipt.write_bytes(orig_receipt)
        self.assertTrue(verify_run_http_captures(triage_dir)["capture_integrity_ok"])
        stray_json = tags_dir / "tags-9999.unexpected.json"
        stray_json.write_text("{}", encoding="utf-8")
        self.assertFalse(verify_run_http_captures(triage_dir)["capture_integrity_ok"])
        stray_json.unlink()

        # 2c) Oversize raw body in _tags rejected by st_size BEFORE reading bytes
        raw_tags_bin = tags_dir / receipt_doc["response_raw_file"]
        orig_tags_raw = raw_tags_bin.read_bytes()
        with raw_tags_bin.open("wb") as handle:
            handle.seek(MAX_HTTP_BODY_BYTES + 1)
            handle.write(b"x")
        rep_huge = verify_run_http_captures(triage_dir)
        self.assertFalse(rep_huge["capture_integrity_ok"])
        self.assertTrue(any("exceeds byte bound" in e for e in rep_huge["errors"]), rep_huge["errors"])
        raw_tags_bin.write_bytes(orig_tags_raw)

        # 2d) '..' in triage_dir argument itself -> FAIL
        rep_dots = verify_run_http_captures(triage_dir / ".." / "triage_f02")
        self.assertFalse(rep_dots["capture_integrity_ok"])

    def test_09_f03_precheck_failure_clears_prior_http_and_error_state(self):
        call_num = {"n": 0}
        content_escaped = json.dumps(self._valid_content_json(5), ensure_ascii=False)
        ok_body = json.dumps(
            {
                "done": True,
                "done_reason": "stop",
                "model": "qwen3.5:9b-q4_K_M",
                "mock_test_fixture": True,
                "message": {"role": "assistant", "content": json.loads(content_escaped)},
            },
            ensure_ascii=False,
        ).encode("utf-8")

        class _ErrThenOkHandler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                call_num["n"] += 1
                length = int(self.headers.get("Content-Length", "0"))
                self.rfile.read(length)
                if call_num["n"] == 1:
                    err = b'{"error": "SENTINEL_PRIOR_HTTP_500_BODY"}'
                    self.send_response(500)
                    self.send_header("Content-Length", str(len(err)))
                    self.end_headers()
                    self.wfile.write(err)
                else:
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(ok_body)))
                    self.end_headers()
                    self.wfile.write(ok_body)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _ErrThenOkHandler)
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        self.addCleanup(lambda: (srv.shutdown(), srv.server_close(), th.join(timeout=2)))

        triage_dir = self.tmp_root / "triage_f03"
        io_dir = triage_dir / "llm_io"
        client = OllamaClient(
            endpoint=f"http://127.0.0.1:{srv.server_port}",
            model="qwen3.5:9b-q4_K_M",
            timeout=10,
            runtime_origin="mock",
            io_log_dir=io_dir,
            capture_root=triage_dir,
        )

        # Call 1: HTTP 500 error sets _last_error_body_text during call 1
        rec_a = dict(self.bundle_two["records"][0])
        res_err = client.analyze(rec_a)
        self.assertEqual(res_err["validated_status"], "UNDETERMINED")

        # Call 2: Same record re-keyed succeeds -> sets _last_raw_model_status="SUPPORTED" if not cleared
        rec_b = dict(self.bundle_two["records"][1])
        rec_b_ok = dict(self.record0, id="0" * 64, alert_id="0" * 64)
        res_ok = client.analyze(rec_b_ok)
        self.assertEqual(res_ok["validated_status"], "SUPPORTED")

        # Call 3: Precheck failure BEFORE HTTP -> must NOT leak Call 1 body or Call 2 raw_model_status="SUPPORTED"
        precheck_bad = dict(rec_b, issues=["missing source snippet"])
        res_pre = client.analyze(precheck_bad)
        self.assertEqual(res_pre["validated_status"], "UNDETERMINED")
        self.assertEqual(res_pre["failure_kind"], "EVIDENCE_PRECHECK_FAILED")
        self.assertIsNone(res_pre["raw_model_status"])
        self.assertFalse(res_pre["runtime"]["http_response_received"])
        self.assertIsNone(res_pre["runtime"]["http_status"])
        self.assertEqual(call_num["n"], 2, "precheck failure must not invoke HTTP POST")
        self.assertNotIn("SENTINEL_PRIOR_HTTP_500_BODY", json.dumps(res_pre, ensure_ascii=False))
        self.assertEqual(client._last_error_body_text, "")
        self.assertIsNone(client._last_raw_model_status)

    def test_10_f04_same_id_precheck_failure_preserves_prior_sidecar_bytes(self):
        content_escaped = json.dumps(self._valid_content_json(5), ensure_ascii=False)
        ok_body = json.dumps(
            {
                "done": True,
                "done_reason": "stop",
                "model": "qwen3.5:9b-q4_K_M",
                "mock_test_fixture": True,
                "message": {"role": "assistant", "content": json.loads(content_escaped)},
            },
            ensure_ascii=False,
        ).encode("utf-8")

        class _OkHandler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                self.rfile.read(length)
                self.send_response(200)
                self.send_header("Content-Length", str(len(ok_body)))
                self.end_headers()
                self.wfile.write(ok_body)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _OkHandler)
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        self.addCleanup(lambda: (srv.shutdown(), srv.server_close(), th.join(timeout=2)))

        triage_dir = self.tmp_root / "triage_f04"
        io_dir = triage_dir / "llm_io"
        client = OllamaClient(
            endpoint=f"http://127.0.0.1:{srv.server_port}",
            model="qwen3.5:9b-q4_K_M",
            timeout=10,
            runtime_origin="mock",
            io_log_dir=io_dir,
            capture_root=triage_dir,
        )

        res1 = client.analyze(self.record0)
        self.assertEqual(res1["validated_status"], "SUPPORTED")
        fid = self.record0["id"]
        _write_triage_run_files(triage_dir, self.bundle_one, [res1])
        self.assertTrue(verify_run_http_captures(triage_dir)["capture_integrity_ok"])

        orig_prompt = (io_dir / f"{fid}.prompt.json").read_bytes()
        orig_req = (io_dir / f"{fid}.request.json").read_bytes()
        orig_resp = (io_dir / f"{fid}.response.json").read_bytes()
        orig_raw = (io_dir / f"{fid}.response.body.bin").read_bytes()
        orig_req_raw = (io_dir / f"{fid}.request.body.bin").read_bytes()
        orig_receipt = (io_dir / f"{fid}.http-capture.json").read_bytes()

        # Re-run analyze() with the SAME id but failing precheck before HTTP
        bad_same_id = dict(self.record0, issues=["precheck blocked after completed capture"])
        res2 = client.analyze(bad_same_id)
        self.assertEqual(res2["validated_status"], "UNDETERMINED")
        self.assertEqual(res2["failure_kind"], "EVIDENCE_PRECHECK_FAILED")
        self.assertEqual(res2["runtime"]["sidecar_artifact_stem"], f"{fid}.attempt-0002")

        # Prior canonical sidecars & raw bytes are 100% preserved
        self.assertEqual((io_dir / f"{fid}.prompt.json").read_bytes(), orig_prompt)
        self.assertEqual((io_dir / f"{fid}.request.json").read_bytes(), orig_req)
        self.assertEqual((io_dir / f"{fid}.response.json").read_bytes(), orig_resp)
        self.assertEqual((io_dir / f"{fid}.response.body.bin").read_bytes(), orig_raw)
        self.assertEqual((io_dir / f"{fid}.request.body.bin").read_bytes(), orig_req_raw)
        self.assertEqual((io_dir / f"{fid}.http-capture.json").read_bytes(), orig_receipt)
        self.assertEqual(res2["runtime"]["sidecar_artifacts"], [f"{fid}.attempt-0002.response.json"])
        attempt_resp_path = io_dir / f"{fid}.attempt-0002.response.json"
        self.assertTrue(attempt_resp_path.is_file())
        attempt_doc = strict_json(attempt_resp_path.read_text(encoding="utf-8"))
        self.assertEqual(attempt_doc["runtime"]["sidecar_artifact_stem"], f"{fid}.attempt-0002")
        self.assertFalse(attempt_doc["runtime"]["http_response_received"])

    def test_11_f01_f02_deep_ancestor_junction_capture_and_tags_rejection(self):
        post_hits = {"count": 0}
        get_hits = {"count": 0}
        content_escaped = json.dumps(self._valid_content_json(5), ensure_ascii=False)
        ok_body = json.dumps(
            {
                "done": True,
                "done_reason": "stop",
                "model": "qwen3.5:9b-q4_K_M",
                "mock_test_fixture": True,
                "message": {"role": "assistant", "content": json.loads(content_escaped)},
            },
            ensure_ascii=False,
        ).encode("utf-8")

        class _DeepCheckHandler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                get_hits["count"] += 1
                body = json.dumps({"models": [{"name": "qwen3.5:9b-q4_K_M", "digest": "d", "size": 1}]}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                post_hits["count"] += 1
                length = int(self.headers.get("Content-Length", "0"))
                self.rfile.read(length)
                self.send_response(200)
                self.send_header("Content-Length", str(len(ok_body)))
                self.end_headers()
                self.wfile.write(ok_body)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _DeepCheckHandler)
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        self.addCleanup(lambda: (srv.shutdown(), srv.server_close(), th.join(timeout=2)))
        endpoint = f"http://127.0.0.1:{srv.server_port}"

        # 1) Normal deep nested valid path (positive control)
        normal_triage = self.tmp_root / "normal_deep" / "a" / "b" / "triage"
        normal_io = normal_triage / "llm_io"
        client_ok = OllamaClient(
            endpoint=endpoint,
            model="qwen3.5:9b-q4_K_M",
            timeout=10,
            runtime_origin="mock",
            io_log_dir=normal_io,
            capture_root=normal_triage,
        )
        inv_ok = client_ok.verify_model_installed()
        self.assertTrue(inv_ok["reachable"])
        self.assertTrue(inv_ok["model_found"])
        res_ok = client_ok.analyze(self.record0)
        self.assertEqual(res_ok["validated_status"], "SUPPORTED")
        _write_triage_run_files(normal_triage, self.bundle_one, [res_ok])
        ver_ok = verify_run_http_captures(normal_triage)
        self.assertTrue(ver_ok["capture_integrity_ok"], ver_ok["errors"])
        self.assertEqual(len(ver_ok["tags_probes"]), 1)
        self.assertEqual(get_hits["count"], 1)
        self.assertEqual(post_hits["count"], 1)

        # Verifier CLI writes fresh report once, then refuses overwriting existing evidence
        out_report = self.tmp_root / "normal_deep_report.json"
        self.assertEqual(verify_cli_main([str(normal_triage), "--output", str(out_report)]), 0)
        orig_report_bytes = out_report.read_bytes()
        self.assertEqual(verify_cli_main([str(normal_triage), "--output", str(out_report)]), 2)
        self.assertEqual(out_report.read_bytes(), orig_report_bytes)

        # 2) Deep ancestor junction / directory symlink above boundary parent (negative control)
        junc_holder = self.tmp_root / "deep_holder"
        junc_holder.mkdir()
        outside = self.tmp_root / "deep_outside"
        outside_io = outside / "a" / "b" / "triage" / "llm_io"
        outside_io.mkdir(parents=True)
        link = junc_holder / "link"
        if os.name == "nt":
            proc = subprocess.run(
                ["cmd.exe", "/c", "mklink", "/J", str(link), str(outside)],
                capture_output=True,
                text=True,
            )
            if proc.returncode != 0:
                self.skipTest("Windows mklink /J unavailable")
        else:
            os.symlink(str(outside), str(link), target_is_directory=True)

        deep_triage = link / "a" / "b" / "triage"
        deep_io = deep_triage / "llm_io"

        # 2a) analyze() rejects deep existing junction ancestor with zero external writes & zero POSTs
        client_deep = OllamaClient(
            endpoint=endpoint,
            model="qwen3.5:9b-q4_K_M",
            timeout=10,
            runtime_origin="mock",
            io_log_dir=deep_io,
            capture_root=deep_triage,
        )
        res_deep = client_deep.analyze(self.record0)
        self.assertEqual(res_deep["validated_status"], "UNDETERMINED")
        self.assertEqual(res_deep["failure_kind"], "EVIDENCE_CAPTURE_WRITE_FAILED")
        self.assertEqual(post_hits["count"], 1, "deep junction must block before issuing HTTP POST")
        self.assertEqual(list(outside_io.iterdir()), [], "must write zero files into outside target")

        # 2b) verify_model_installed() rejects deep junction in _tags ancestor with zero GETs & zero external dirs
        inv_deep = client_deep.verify_model_installed()
        self.assertFalse(inv_deep["reachable"])
        self.assertEqual(get_hits["count"], 1, "deep junction must block before issuing HTTP GET")
        self.assertEqual(list(outside_io.iterdir()), [])

        # 2c) _prepare_safe_capture_dir(..., create=True) on non-existent subtree under deep junction creates nothing outside
        with self.assertRaises(CaptureWriteError):
            _prepare_safe_capture_dir(link / "uncreated" / "sub" / "llm_io", boundary_root=link / "uncreated" / "sub", create=True)
        self.assertFalse((outside / "uncreated").exists())

        # 2d) _verify_tags_captures and verify_run_http_captures reject deep junction in _tags branch without accepting probes
        outside_tags = outside_io / "_tags"
        outside_tags.mkdir()
        canary_body = b'{"models":[],"note":"MOCK_DEEP_TAGS_CANARY"}'
        (outside_tags / "tags-0001.response.body.bin").write_bytes(canary_body)
        (outside_tags / "tags-0001.http-capture.json").write_text(
            json.dumps({
                "schema": "ntk-ollama-http-capture-1",
                "call_id": "MOCK:deep-tags-0001",
                "call_kind": "tags_probe",
                "method": "GET",
                "path": "/api/tags",
                "finding_id": None,
                "request_raw_file": None,
                "http_status": 200,
                "completeness": "complete",
                "complete": True,
                "response_raw_file": "tags-0001.response.body.bin",
                "response_byte_length": len(canary_body),
                "response_body_sha256": digest(canary_body),
            }),
            encoding="utf-8",
        )
        tags_errors: list[str] = []
        probes = _verify_tags_captures(deep_io / "_tags", set(), tags_errors)
        self.assertTrue(tags_errors, "deep junction in _tags ancestor must produce verification error")
        self.assertEqual(probes, [])

        _write_triage_run_files(outside / "a" / "b" / "triage", self.bundle_one, [res_deep])
        rep_deep = verify_run_http_captures(deep_triage)
        self.assertFalse(rep_deep["capture_integrity_ok"])
        self.assertTrue(rep_deep["errors"])


if __name__ == "__main__":
    unittest.main()
