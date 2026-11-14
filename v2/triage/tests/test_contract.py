import copy
import io
import json
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch
from test_triage import Fixture
from v2.triage.evidence import digest, EvidenceError
from v2.triage.ollama import OllamaClient, validate_answer
from v2.triage.runtime import summary
from v2.triage.export_pilot import adapt


class ContractTests(Fixture):
    def test_version_index_and_alert_alias_do_not_change_id(self):
        record = self.record
        self.assertEqual(record["schema_version"], "1.1")
        self.assertEqual(record["finding_index"], 0)
        self.assertEqual(record["id"], digest((digest(json.dumps(self.doc).encode()) + ":0").encode()))
        self.assertEqual(record["alert_id"], record["id"])

    def row(self, status="REFUTED"):
        return {"id": self.record["id"], "evidence": self.record, "state": "OPEN",
                "assessment": validate_answer(json.dumps(self.answer(status)), self.record)}

    def test_paired_export_status_and_exact_join(self):
        for status, expected in (("REFUTED", "PROPOSED_FP"), ("SUPPORTED", "KEEP_TP")):
            alerts, triage = adapt([self.row(status)], json.dumps(self.doc))
            self.assertEqual(alerts["alerts"][0]["alert_id"], self.record["id"])
            self.assertEqual(triage["triage_results"][0]["verdict"], expected)
            self.assertFalse(triage["triage_results"][0]["auto_dismissed"])
            self.assertFalse(triage["triage_results"][0]["human_confirmed"])

    def test_wrong_raw_bytes_or_finding_or_alias_refused(self):
        with self.assertRaises(EvidenceError):
            adapt([self.row()], json.dumps(self.doc) + " ")
        row = copy.deepcopy(self.row())
        row["evidence"]["raw_finding"]["path"] = "tampered.java"
        with self.assertRaises(EvidenceError):
            adapt([row], json.dumps(self.doc))
        row = {**self.row(), "scan_sha256": "0" * 64}
        with self.assertRaises(EvidenceError):
            adapt([row], json.dumps(self.doc))

    def test_legacy_index_recovered_by_hash_not_location(self):
        row = copy.deepcopy(self.row())
        del row["evidence"]["finding_index"]
        alerts, _ = adapt([row], json.dumps(self.doc))
        self.assertEqual(alerts["alerts"][0]["finding_index"], 0)

    def test_raw_finding_json_types_are_not_coerced(self):
        row = copy.deepcopy(self.row())
        row["evidence"]["raw_finding"]["start"]["line"] = 5.0
        with self.assertRaises(EvidenceError):
            adapt([row], json.dumps(self.doc))

    def test_invalid_evidence_exported_as_review(self):
        self.record["issues"].append("missing trace")
        row = {"id": self.record["id"], "evidence": self.record,
               "assessment": {"status": "REFUTED", "explanation": "MOCK invalid", "citations": []}}
        _, triage = adapt([row], json.dumps(self.doc))
        self.assertEqual(triage["triage_results"][0]["verdict"], "REVIEW")

    def test_mocked_request_does_not_claim_received_http_or_real_model(self):
        response = {"done": True, "model": "qwen3.5:9b-q4_K_M", "eval_count": 99,
                    "message": {"content": json.dumps(self.answer())}}
        with patch.object(OllamaClient, "request", return_value=response):
            result = OllamaClient(runtime_origin="mock").analyze(self.record)
        self.assertEqual(result["status"], "SUPPORTED")
        self.assertFalse(result["runtime"]["http_response_received"])
        counts = summary([result])
        self.assertEqual(counts["mock_records"], 1)
        self.assertEqual(counts["verified_model_runtime_count"], 0)
        self.assertEqual(counts["ollama_reported_inference"], 0)

    def test_execution_is_per_warning_not_reused(self):
        client = OllamaClient()
        client.runtime["http_response_received"] = True
        self.record["issues"].append("missing trace")
        result = client.analyze(self.record)
        self.assertFalse(result["runtime"]["http_response_received"])
        self.assertEqual(result["status"], "UNDETERMINED")
