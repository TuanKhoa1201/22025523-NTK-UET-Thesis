"""Synthetic unit/integration tests. All model responses in this suite are MOCKS."""
import copy
import io
import json
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout, redirect_stderr
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError

from v2.triage.evidence import collect, EvidenceError, SourceTree, check_current, digest
from v2.triage.ollama import OllamaClient, validate_answer, undecided
from v2.triage.store import ReviewStore
from v2.triage.cli import main

BASE = Path(__file__).resolve().parents[1]


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=BASE / "evidence")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve() / "project"
        self.root.mkdir()
        self.source = self.root / "Demo.java"
        self.text = ('class Demo {\n'
                     ' void run(Request req, Statement stmt) {\n'
                     '  String input = req.getParameter("x");\n'
                     '  String sql = "SELECT " + input;\n'
                     '  stmt.executeQuery(sql);\n'
                     ' }\n}\n')
        self.source.write_bytes(self.text.encode())
        self.doc = {"results": [{"check_id": "test.cwe89", "path": "Demo.java",
                                "start": self.point(5, 3), "end": self.point(5, 25),
                                "extra": {"severity": "WARNING", "metadata": {"cwe": ["CWE-89"]},
                                          "message": "synthetic SQL finding", "dataflow_trace": {
                                              "taint_source": self.tag(3, 'req.getParameter("x")'),
                                              "intermediate_vars": [{"location": self.loc(4, "sql"), "content": "sql"}],
                                              "taint_sink": self.tag(5, "stmt.executeQuery(sql)")}}}], "errors": []}
        self.bundle = self.collect()
        self.record = self.bundle["records"][0]

    def point(self, line, col):
        parts = self.text.splitlines(keepends=True)
        return {"line": line, "col": col,
                "offset": sum(len(x.encode()) for x in parts[:line-1]) + col - 1}

    def loc(self, line, content):
        col = self.text.splitlines()[line-1].index(content) + 1
        return {"path": "Demo.java", "start": self.point(line, col),
                "end": self.point(line, col + len(content.encode()))}

    def tag(self, line, content):
        return ["CliLoc", [self.loc(line, content), content]]

    def collect(self, doc=None, **kwargs):
        kwargs.setdefault("engine_exit", 0)
        return collect(json.dumps(self.doc if doc is None else doc), self.root, **kwargs)

    def answer(self, status="SUPPORTED"):
        snippet = self.record["snippets"][0]
        quote = next(x["text"] for x in snippet["lines"] if x["line"] == 5)
        return {"status": status, "explanation": "MOCK: SQL sink receives request-derived input.",
                "citations": [{"path": "Demo.java", "start_line": 5, "end_line": 5,
                               "quote": quote, "sha256": snippet["sha256"]}],
                "fix_suggestion": "MOCK: consider a prepared statement after human review."}

    def store(self, assessment=None):
        store = ReviewStore(Path(self.tmp.name) / "review.sqlite")
        self.addCleanup(store.close)
        store.add(self.bundle, [assessment or undecided("MOCK", transport="mock")])
        return store


class EvidenceTests(Fixture):
    def test_full_trace_and_hash_match_actual_source(self):
        self.assertEqual(self.record["issues"], [])
        self.assertEqual(self.record["snapshots"]["Demo.java"]["sha256"], digest(self.source.read_bytes()))
        self.assertEqual([s["role"] for s in self.record["snippets"]], ["finding", "source", "intermediate", "sink"])
        for snippet in self.record["snippets"]:
            for line in snippet["lines"]:
                self.assertEqual(line["text"], self.text.splitlines()[line["line"]-1])
        self.assertEqual(self.record["raw_finding"], self.doc["results"][0])

    def test_invalid_json_and_duplicate_keys(self):
        for raw in ("not JSON", '{"results":[],"results":[]}', '{"results":NaN}', '[]', '{}'):
            result = collect(raw, self.root)
            self.assertTrue(result["issues"])
            self.assertEqual(result["records"], [])

    def test_partial_scan_keeps_all_findings(self):
        self.doc["errors"] = [{"message": "timeout"}]
        result = self.collect(engine_exit=2)
        self.assertEqual(len(result["records"]), 1)
        self.assertTrue(result["records"][0]["issues"])

    def test_skipped_paths_are_not_clean(self):
        self.doc["paths"] = {"skipped": [{"path": "Other.java", "reason": "size"}]}
        self.assertTrue(self.collect()["issues"])

    def test_missing_trace_not_inferred(self):
        del self.doc["results"][0]["extra"]["dataflow_trace"]
        record = self.collect()["records"][0]
        self.assertTrue(record["issues"])
        self.assertEqual([x["role"] for x in record["snippets"]], ["finding"])

    def test_unknown_trace_preserved(self):
        trace = {"taint_source": ["CliCall", {"unrecognized": True}]}
        self.doc["results"][0]["extra"]["dataflow_trace"] = trace
        record = self.collect()["records"][0]
        self.assertEqual(record["raw_trace"], trace)
        self.assertTrue(record["issues"])

    def test_wrong_trace_content_or_offset_rejected(self):
        source = self.doc["results"][0]["extra"]["dataflow_trace"]["taint_source"][1]
        source[1] = "invented source"
        self.assertTrue(self.collect()["records"][0]["issues"])
        source[1] = 'req.getParameter("x")'
        source[0]["start"]["offset"] += 1
        self.assertTrue(self.collect()["records"][0]["issues"])

    def test_missing_file_and_bad_location(self):
        for change in ({"path": "Missing.java"}, {"start": {"line": 0, "col": 1}},
                       {"end": {"line": 999, "col": 1}}):
            doc = copy.deepcopy(self.doc)
            doc["results"][0].update(change)
            self.assertTrue(self.collect(doc)["records"][0]["issues"])

    def test_traversal_and_absolute_outside_forbidden_before_read(self):
        outside = self.root.parent / "Outside.java"
        outside.write_text("SECRET outside project")
        for path in ("../Outside.java", str(outside), str(self.root.parent)):
            with self.assertRaises((EvidenceError, OSError)):
                SourceTree(self.root).read(path)
        self.doc["results"][0]["path"] = "../Outside.java"
        record = self.collect()["records"][0]
        self.assertTrue(record["issues"])
        self.assertNotIn("SECRET", json.dumps(record["snippets"]))

    def test_outside_trace_file_forbidden(self):
        self.doc["results"][0]["extra"]["dataflow_trace"]["taint_source"][1][0]["path"] = "../Outside.java"
        self.assertTrue(self.collect()["records"][0]["issues"])

    def test_symlink_escape_forbidden(self):
        outside = self.root.parent / "Outside.java"
        outside.write_text("SECRET")
        link = self.root / "Link.java"
        try:
            link.symlink_to(outside)
        except OSError:
            self.skipTest("Windows account cannot create symlinks")
        with self.assertRaises(EvidenceError):
            SourceTree(self.root).read("Link.java")

    def test_source_change_hash_detected(self):
        self.source.write_text(self.text + "// change\n")
        with self.assertRaises(EvidenceError):
            check_current(self.record)

    def test_unknown_engine_exit_never_clean(self):
        result = collect(json.dumps(self.doc), self.root)
        self.assertTrue(result["records"][0]["issues"])

    def test_crlf_and_utf8_coordinates(self):
        self.text = self.text.replace("class Demo {", "class Demo { // é").replace("\n", "\r\n")
        self.source.write_bytes(self.text.encode())
        item = self.doc["results"][0]
        item["start"], item["end"] = self.point(5, 3), self.point(5, 25)
        item["extra"]["dataflow_trace"] = {
            "taint_source": self.tag(3, 'req.getParameter("x")'), "intermediate_vars": [],
            "taint_sink": self.tag(5, "stmt.executeQuery(sql)")}
        record = self.collect()["records"][0]
        self.assertEqual(record["issues"], [])
        self.assertEqual(record["snippets"][1]["matched"], 'req.getParameter("x")')

    def test_multifile_trace_hashes_both_files(self):
        other = self.root / "Other.java"
        other.write_bytes(self.source.read_bytes())
        self.doc["results"][0]["extra"]["dataflow_trace"]["taint_source"][1][0]["path"] = "Other.java"
        record = self.collect()["records"][0]
        self.assertEqual(set(record["snapshots"]), {"Demo.java", "Other.java"})
        other.write_text("changed")
        with self.assertRaises(EvidenceError):
            check_current(record)

    def test_relative_path_base_explicit(self):
        self.doc["results"][0]["path"] = "project/Demo.java"
        record = self.collect(path_base=self.root.parent)["records"][0]
        self.assertTrue(record["issues"])  # trace paths use a different base; no guessing

    def test_malformed_finding_is_retained(self):
        self.doc["results"].append(None)
        records = self.collect()["records"]
        self.assertEqual(len(records), 2)
        self.assertIsNone(records[1]["raw_finding"])
        self.assertTrue(records[1]["issues"])


class AnswerTests(Fixture):
    def test_valid_citation_is_not_security_proof(self):
        answer = validate_answer(json.dumps(self.answer()), self.record)
        self.assertEqual(answer["status"], "SUPPORTED")
        self.assertEqual(answer["citation_check"], "MATCHED")
        self.assertFalse(answer["security_conclusion_verified"])
        self.assertTrue(answer["requires_human_review"])

    def test_wrong_position_text_hash_and_path_rejected(self):
        for key, value in (("start_line", 4), ("quote", "invented"), ("sha256", "0"*64),
                           ("path", "../Outside.java"), ("end_line", True)):
            answer = self.answer()
            answer["citations"][0][key] = value
            with self.subTest(key=key), self.assertRaises(EvidenceError):
                validate_answer(json.dumps(answer), self.record)

    def test_invalid_schema_json_or_no_citations(self):
        answers = ["bad", "[]", "{}"]
        for key, value in (("status", "SAFE"), ("explanation", 1), ("fix_suggestion", []), ("citations", [])):
            answer = self.answer()
            answer[key] = value
            answers.append(json.dumps(answer))
        for raw in answers:
            with self.subTest(raw=raw), self.assertRaises(EvidenceError):
                validate_answer(raw, self.record)

    def test_missing_evidence_rejects_even_correct_quote(self):
        self.record["issues"].append("no trace")
        with self.assertRaises(EvidenceError):
            validate_answer(json.dumps(self.answer()), self.record)

    def test_changed_source_rejects_model_response(self):
        self.source.write_text("changed")
        with self.assertRaises(EvidenceError):
            validate_answer(json.dumps(self.answer()), self.record)

    def test_refuted_never_changes_human_queue(self):
        response = validate_answer(json.dumps(self.answer("REFUTED")), self.record)
        response["transport"] = "mock"
        store = self.store(response)
        self.assertEqual(store.queue()[0]["state"], "OPEN")
        self.assertEqual(store.history(self.record["id"]), [])


class OllamaTests(Fixture):
    def test_only_loopback_and_local_models(self):
        for endpoint in ("https://api.example.com", "http://192.168.1.2:11434", "http://127.0.0.1@evil.com",
                         "http://127.0.0.1:11434/api", "http://127.0.0.1:11434?x=1"):
            with self.assertRaises(EvidenceError):
                OllamaClient(endpoint)
        with self.assertRaises(EvidenceError):
            OllamaClient(model="qwen:cloud")
        self.assertEqual(OllamaClient("http://localhost:11434").endpoint, "http://127.0.0.1:11434")

    def test_mock_good_bad_and_incomplete_responses(self):
        for response, expected in (({"done": True, "model": "qwen3.5:9b-q4_K_M", "message": {"content": json.dumps(self.answer())}}, "SUPPORTED"),
                                   ({"done": True, "message": {"content": "invalid"}}, "UNDETERMINED"),
                                   ({"done": False}, "UNDETERMINED"),
                                   ({"done": True, "done_reason": "length"}, "UNDETERMINED")):
            response.setdefault("model", "qwen3.5:9b-q4_K_M")
            with patch.object(OllamaClient, "request", return_value=response):
                self.assertEqual(OllamaClient().analyze(self.record)["status"], expected)

    def test_unexpected_model_is_not_accepted(self):
        with patch.object(OllamaClient, "request", return_value={"done": True, "model": "other-model",
                                                               "message": {"content": json.dumps(self.answer())}}):
            self.assertEqual(OllamaClient().analyze(self.record)["status"], "UNDETERMINED")

    def test_mock_service_unavailable_timeout(self):
        for exc in (URLError("MOCK unavailable"), TimeoutError("MOCK timeout")):
            with patch.object(OllamaClient, "request", side_effect=exc):
                result = OllamaClient().analyze(self.record)
                self.assertEqual(result["status"], "UNDETERMINED")
                self.assertIn("MOCK", result["explanation"])

    def test_insufficient_evidence_never_sends_source(self):
        self.record["issues"].append("missing trace")
        with patch.object(OllamaClient, "request") as request:
            self.assertEqual(OllamaClient().analyze(self.record)["status"], "UNDETERMINED")
            request.assert_not_called()


class ReviewTests(Fixture):
    def test_confirm_false_history_reopen(self):
        store = self.store()
        item = store.decide(self.record["id"], "confirm-false", "human-tester", "manual inspection")
        self.assertEqual(item["state"], "CONFIRMED_FALSE")
        self.assertEqual(len(store.queue()), 1)  # even human-confirmed false remains visible
        event = store.history(self.record["id"])[0]
        for key in ("actor", "timestamp", "reason", "source_version", "observed_version", "evidence_sha256"):
            self.assertTrue(event[key])
        store.decide(self.record["id"], "reopen", "human-tester", "new review")
        self.assertEqual(store.get(self.record["id"])["state"], "OPEN")
        self.assertEqual(len(store.history(self.record["id"])), 2)

    def test_changed_missing_or_hash_mismatch_blocks_false(self):
        store = self.store()
        self.source.write_text(self.text + "// changed")
        with self.assertRaises(EvidenceError):
            store.decide(self.record["id"], "confirm-false", "tester", "reason")
        self.source.unlink()
        with self.assertRaises(EvidenceError):
            store.decide(self.record["id"], "confirm-false", "tester", "reason")
        self.assertEqual(store.history(self.record["id"]), [])
        self.assertEqual(store.get(self.record["id"])["state"], "OPEN")

    def test_incomplete_evidence_blocks_false(self):
        self.bundle["records"][0]["issues"].append("partial scan")
        store = self.store()
        with self.assertRaises(EvidenceError):
            store.decide(self.record["id"], "confirm-false", "tester", "reason")

    def test_human_true_and_required_fields(self):
        store = self.store()
        for actor, reason in (("", "why"), ("human", "")):
            with self.assertRaises(EvidenceError):
                store.decide(self.record["id"], "confirm-true", actor, reason)
        self.assertEqual(store.decide(self.record["id"], "confirm-true", "human", "reviewed")["state"], "CONFIRMED_TRUE")

    def test_duplicate_import_does_not_overwrite_review(self):
        store = self.store()
        store.decide(self.record["id"], "confirm-true", "human", "reviewed")
        with self.assertRaises(sqlite3.IntegrityError):
            store.add(self.bundle, [undecided("MOCK")])
        self.assertEqual(store.get(self.record["id"])["state"], "CONFIRMED_TRUE")

    def test_tampered_evidence_hash_blocks_false(self):
        self.bundle["records"][0]["snapshots"]["Demo.java"]["sha256"] = "0"*64
        store = self.store()
        with self.assertRaises(EvidenceError):
            store.decide(self.record["id"], "confirm-false", "human", "test mismatch")
        self.assertEqual(store.get(self.record["id"])["state"], "OPEN")

    def test_changed_trace_source_file_blocks_false(self):
        other = self.root / "Other.java"
        other.write_bytes(self.source.read_bytes())
        self.doc["results"][0]["extra"]["dataflow_trace"]["taint_source"][1][0]["path"] = "Other.java"
        self.bundle = self.collect()
        self.record = self.bundle["records"][0]
        store = self.store()
        other.write_text("changed source only")
        with self.assertRaises(EvidenceError):
            store.decide(self.record["id"], "confirm-false", "human", "test multifile freshness")


class CLIIntegrationTests(Fixture):
    def test_failed_engine_keeps_partial_findings_for_review(self):
        sys.path.insert(0, str(BASE.parent / "baseline/fork"))
        from semgrepai.scanner import SemgrepScanner, ScanError
        doc = self.doc
        def failed_scan(scanner, root):
            scanner.output_dir.mkdir(parents=True)
            (scanner.output_dir / "opengrep.json").write_text(json.dumps(doc))
            raise ScanError("MOCK engine partial run")
        output = Path(self.tmp.name) / "partial-engine"
        with patch.object(SemgrepScanner, "scan", failed_scan), redirect_stdout(io.StringIO()):
            self.assertEqual(main(["run", "--source-root", str(self.root), "--output-dir", str(output), "--no-llm"]), 2)
        store = ReviewStore(output / "review.sqlite")
        self.addCleanup(store.close)
        self.assertEqual(len(store.queue()), 1)
        self.assertEqual(store.queue()[0]["state"], "OPEN")
        self.assertTrue(store.queue()[0]["evidence"]["issues"])

    def test_postscan_version_read_failure_preserves_queue(self):
        sys.path.insert(0, str(BASE.parent / "baseline/fork"))
        from semgrepai.scanner import SemgrepScanner
        doc = self.doc
        def mock_scan(scanner, root):
            scanner.output_dir.mkdir(parents=True)
            (scanner.output_dir / "opengrep.json").write_text(json.dumps(doc))
        output = Path(self.tmp.name) / "postscan-failure"
        with patch.object(SemgrepScanner, "scan", mock_scan), \
             patch("v2.triage.cli.source_versions", side_effect=[{}, OSError("MOCK disappeared")]), \
             redirect_stdout(io.StringIO()):
            self.assertEqual(main(["run", "--source-root", str(self.root), "--output-dir", str(output), "--no-llm"]), 2)
        self.assertEqual(len(json.loads((output / "evidence.json").read_text())["records"]), 1)

    def test_import_export_queue_show_decide_history_and_reopen(self):
        input_path = Path(self.tmp.name) / "input.json"
        input_path.write_text(json.dumps(self.doc))
        output = Path(self.tmp.name) / "run"
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(main(["run", "--source-root", str(self.root), "--json", str(input_path),
                                   "--output-dir", str(output), "--engine-exit", "0", "--no-llm"]), 0)
            lines = (output / "assessments.jsonl").read_text().splitlines()
            item = json.loads(lines[0])
            self.assertEqual(item["assessment"]["status"], "UNDETERMINED")
            db, identifier = str(output / "review.sqlite"), item["id"]
            for command in (["queue", "--db", db], ["show", "--db", db, identifier],
                            ["decide", "--db", db, identifier, "confirm-false", "--actor", "human", "--reason", "synthetic test"],
                            ["history", "--db", db, identifier],
                            ["decide", "--db", db, identifier, "reopen", "--actor", "human", "--reason", "synthetic reopen"]):
                self.assertEqual(main(command), 0)
            self.assertEqual(main(["run", "--source-root", str(self.root), "--json", str(input_path),
                                   "--output-dir", str(output), "--no-llm"]), 2)

    def test_invalid_import_still_has_scan_issue_in_queue(self):
        input_path = Path(self.tmp.name) / "bad.json"
        input_path.write_text("not JSON")
        output = Path(self.tmp.name) / "bad-run"
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(main(["run", "--source-root", str(self.root), "--json", str(input_path),
                                   "--output-dir", str(output), "--no-llm"]), 2)
        store = ReviewStore(output / "review.sqlite")
        self.addCleanup(store.close)
        self.assertTrue(store.scans()[0]["issues"])

    def test_module_entrypoint(self):
        result = subprocess.run([sys.executable, "-m", "v2.triage", "--help"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("run", result.stdout)


class HTTPIntegrationTests(Fixture):
    def test_http_error_is_received_but_not_inference(self):
        class ErrorHandler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                self.send_error(503, "MOCK model unavailable")
        server = ThreadingHTTPServer(("127.0.0.1", 0), ErrorHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = OllamaClient(f"http://127.0.0.1:{server.server_port}", runtime_origin="mock").analyze(self.record)
            self.assertEqual(result["status"], "UNDETERMINED")
            self.assertTrue(result["runtime"]["http_response_received"])
            self.assertEqual(result["runtime"]["http_status"], 503)
            self.assertFalse(result["runtime"]["model_runtime_verified"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_real_http_transport_with_explicit_mock_server(self):
        answer = self.answer("REFUTED")
        requests = []
        class MockHandler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                requests.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                body = json.dumps({"done": True, "model": "qwen3.5:9b-q4_K_M", "mock_test_fixture": True,
                                   "eval_count": 17, "eval_duration": 123456,
                                   "message": {"content": json.dumps(answer)}}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        server = ThreadingHTTPServer(("127.0.0.1", 0), MockHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = OllamaClient(f"http://127.0.0.1:{server.server_port}")
            result = client.analyze(self.record)
            self.assertEqual(result["status"], "REFUTED")
            self.assertTrue(requests[0]["format"]["properties"])
            self.assertFalse(requests[0]["stream"])
            self.assertFalse(requests[0]["think"])
            self.assertEqual(requests[0]["model"], "qwen3.5:9b-q4_K_M")
            # The HTTP call is real; this is explicitly not model-runtime evidence.
            self.assertTrue(result["raw_response"]["mock_test_fixture"])
            self.assertTrue(result["runtime"]["http_response_received"])
            self.assertEqual(result["runtime"]["http_status"], 200)
            self.assertTrue(result["runtime"]["response_body_sha256"])
            self.assertEqual(result["runtime"]["origin"], "mock")
            from v2.triage.runtime import summary
            counts = summary([result])
            self.assertEqual(counts["http_responses_received"], 1)
            self.assertEqual(counts["ollama_reported_inference"], 0)
            self.assertEqual(counts["verified_model_runtime_count"], 0)
            store = self.store({**result, "transport": "mock-http"})
            self.assertEqual(store.queue()[0]["state"], "OPEN")
            input_path = Path(self.tmp.name) / "mock-input.json"
            input_path.write_text(json.dumps(self.doc))
            output = Path(self.tmp.name) / "mock-http-run"
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["run", "--source-root", str(self.root), "--json", str(input_path),
                                       "--engine-exit", "0", "--output-dir", str(output),
                                       "--endpoint", client.endpoint]), 0)
            exported = json.loads((output / "assessments.jsonl").read_text().splitlines()[0])
            self.assertEqual(exported["assessment"]["status"], "REFUTED")
            self.assertEqual(exported["state"], "OPEN")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_redirect_never_forwards_source(self):
        class RedirectHandler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                self.send_response(302)
                self.send_header("Location", "http://example.com/forbidden")
                self.end_headers()
        server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = OllamaClient(f"http://127.0.0.1:{server.server_port}").analyze(self.record)
            self.assertEqual(result["status"], "UNDETERMINED")
            self.assertIn("redirect", result["explanation"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
