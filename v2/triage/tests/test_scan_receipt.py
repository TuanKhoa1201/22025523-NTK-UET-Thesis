"""MOCK process receipts test integrity only, never model/engine runtime claims."""
import copy
import io
import json
from pathlib import Path
from contextlib import redirect_stdout, redirect_stderr
from test_triage import Fixture
from capture_fixture import make_capture
from v2.triage.cli import main
from v2.triage.scan_receipt import verify_receipt
from v2.triage.evidence import digest
from v2.triage.live_check import inspect
from v2.triage.ollama import request_payload


class ReceiptTests(Fixture):
    def receipt(self):
        raw = json.dumps(self.doc).encode()
        path = make_capture(self.root, raw, Path(self.tmp.name) / "capture")
        return path, raw

    def test_bound_capture_and_declared_exit_are_distinct(self):
        path, raw = self.receipt()
        metadata, issues = verify_receipt(path, raw, self.root)
        self.assertEqual(issues, [])
        self.assertEqual(metadata["origin"], "recorded_capture_unsigned")
        self.assertEqual(metadata["recorded_engine_exit"], 0)
        self.assertIsNone(metadata["declared_engine_exit"])
        self.assertFalse(metadata["independently_attested"])

    def test_old_scan_source_changed_outside_trace_is_refused(self):
        path, raw = self.receipt()
        self.source.write_bytes(self.source.read_bytes() + b"// noncited source edit\n")
        metadata, issues = verify_receipt(path, raw, self.root, 0)
        self.assertTrue(issues)
        self.assertFalse(metadata["source_capture_verified"])
        self.assertTrue(metadata["exit_capture_verified"])
        self.assertEqual(metadata["recorded_engine_exit"], 0)

    def test_wrong_output_hash(self):
        path, raw = self.receipt()
        (path.parent / "json.stdout.txt").write_bytes(raw + b" ")
        self.assertTrue(verify_receipt(path, raw, self.root, 0)[1])

    def test_wrong_declared_exit(self):
        path, raw = self.receipt()
        self.assertTrue(verify_receipt(path, raw, self.root, 2)[1])

    def test_wrong_recorded_exit_even_when_declaration_is_zero(self):
        path, raw = self.receipt()
        doc = json.loads(path.read_text())
        doc["runs"]["json"]["exit_code"] = 2
        path.write_text(json.dumps(doc))
        self.assertTrue(verify_receipt(path, raw, self.root, 0)[1])

    def test_invalid_manifest_and_unsafe_artifact(self):
        path, raw = self.receipt()
        original = path.read_bytes()
        path.write_text("not-json")
        self.assertTrue(verify_receipt(path, raw, self.root)[1])
        doc = json.loads(original)
        doc["artifacts"]["../outside.txt"] = "0" * 64
        path.write_text(json.dumps(doc))
        self.assertTrue(verify_receipt(path, raw, self.root)[1])

    def test_no_manifest_keeps_warning_but_cannot_authorize_false_confirmation(self):
        raw = json.dumps(self.doc).encode()
        file = Path(self.tmp.name) / "old.json"
        file.write_bytes(raw)
        out = Path(self.tmp.name) / "legacy-import"
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(main(["run", "--source-root", str(self.root), "--json", str(file), "--engine-exit", "0",
                                   "--output-dir", str(out), "--no-llm"]), 2)
        document = json.loads((out / "evidence.json").read_text())
        self.assertEqual(len(document["records"]), 1)
        self.assertEqual(document["scan_provenance"]["origin"], "declared_only")
        self.assertTrue(document["records"][0]["issues"])
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(main(["decide", "--db", str(out / "review.sqlite"), document["records"][0]["id"],
                                   "confirm-false", "--actor", "SCRIPTED-DEMO", "--reason", "must be refused"]), 2)

    def test_source_added_after_scan_is_refused(self):
        path, raw = self.receipt()
        (self.root / "New.java").write_text("class New {}")
        self.assertTrue(verify_receipt(path, raw, self.root)[1])

    def test_legacy_stored_record_cannot_authorize_new_false_confirmation(self):
        from v2.triage.evidence import EvidenceError
        del self.bundle["records"][0]["scan_provenance"]
        store = self.store()
        with self.assertRaises(EvidenceError):
            store.decide(self.record["id"], "confirm-false", "SCRIPTED-DEMO", "old record must require rescan")
        self.assertEqual(store.history(self.record["id"]), [])


class RuntimeProtocolTests(Fixture):
    def row(self):
        response = {"model": "qwen3.5:9b-q4_K_M", "done": True, "eval_count": 3, "eval_duration": 42,
                    "message": {"content": '{"status":"UNDETERMINED"}'}}
        runtime = {"origin": "unverified", "request_attempted": True, "http_response_received": True,
                   "http_status": 200, "finding_id": self.record["id"],
                   "request_payload_sha256": digest(json.dumps(request_payload(self.record, response["model"])).encode()),
                   "response_json_sha256": digest(json.dumps(response, sort_keys=True, ensure_ascii=False).encode())}
        return {"id": self.record["id"], "evidence": self.record,
                "assessment": {"status": "UNDETERMINED", "model": response["model"], "runtime": runtime, "raw_response": response}}

    def test_protocol_accepts_undetermined_without_claiming_verified_model(self):
        result = inspect([self.row()])
        self.assertEqual(result["protocol_status"], "OLLAMA_REPORTED_UNATTESTED")
        self.assertFalse(result["independently_verified_model_runtime"])

    def test_mock_timeout_wrong_finding_or_payload_cannot_pass_protocol(self):
        for change in ("mock", "timeout", "id", "hash", "request"):
            row = self.row()
            r = row["assessment"]["runtime"]
            if change == "mock":
                r["origin"] = "mock"
            elif change == "timeout":
                r["http_response_received"] = False
            elif change == "id":
                row["id"] = "0" * 64
            elif change == "request":
                r["request_payload_sha256"] = "0" * 64
            else:
                r["response_json_sha256"] = "0" * 64
            self.assertEqual(inspect([row])["protocol_status"], "PENDING", change)
