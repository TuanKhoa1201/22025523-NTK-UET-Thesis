"""Comprehensive positive and negative test suite for the Human Review Workflow (Stage 6).

Verifies all 11 mandatory governance & fail-closed invariants:
1. Model REFUTED (PROPOSED_FP) never auto-dismisses; warning remains OPEN in default queue.
2. Valid `confirm-false` with actor, reason, matching source hash, and verified scan provenance
   transitions to CONFIRMED_FALSE, hides from default queue, appears in `queue --all`, and records audit history.
3. `confirm-false` with empty/whitespace actor is refused.
4. `confirm-false` with empty/whitespace reason is refused.
5. `confirm-false` after primary source file modification is refused (stale source guard).
6. `confirm-false` after dataflow-trace file modification is refused (multifile freshness guard).
7. `confirm-false` after source file deletion is refused.
8. `confirm-false` when evidence has `issues` or unverified scan provenance is refused.
9. `confirm-true` transitions to CONFIRMED_TRUE, remains visible in default queue, and records audit trail.
10. `reopen` transitions CONFIRMED_FALSE back to OPEN, restores visibility in default queue, and preserves full history.
11. Duplicate import of the same scan/warning never overwrites an existing human decision.
"""
from __future__ import annotations

import io
import json
import sqlite3
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from capture_fixture import make_capture
from test_triage import Fixture
from v2.triage.cli import main
from v2.triage.evidence import EvidenceError
from v2.triage.ollama import undecided, validate_answer
from v2.triage.store import ReviewStore


class HumanReviewNegativeAndGovernanceSuite(Fixture):
    def _cli(self, argv: list[str], expected_exit: int = 0):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
        self.assertEqual(code, expected_exit, f"CLI {argv} exited with {code}, stderr={err.getvalue()}")
        return json.loads(out.getvalue()) if out.getvalue().strip() else err.getvalue()

    def test_01_model_refuted_never_auto_dismisses_and_stays_open_in_queue(self):
        refuted_assessment = validate_answer(json.dumps(self.answer("REFUTED")), self.record)
        refuted_assessment["transport"] = "mock"
        store = self.store(refuted_assessment)
        db = str(Path(self.tmp.name) / "review.sqlite")

        q_default = self._cli(["queue", "--db", db])
        self.assertEqual(len(q_default["warnings"]), 1)
        self.assertEqual(q_default["warnings"][0]["id"], self.record["id"])
        self.assertEqual(q_default["warnings"][0]["state"], "OPEN")
        self.assertEqual(q_default["warnings"][0]["model_status"], "REFUTED")
        self.assertEqual(store.history(self.record["id"]), [])

    def test_02_valid_confirm_false_hides_from_default_queue_shows_in_all_and_logs_history(self):
        refuted_assessment = validate_answer(json.dumps(self.answer("REFUTED")), self.record)
        refuted_assessment["transport"] = "mock"
        self.store(refuted_assessment)
        db = str(Path(self.tmp.name) / "review.sqlite")
        wid = self.record["id"]

        decided = self._cli(
            [
                "decide",
                "--db",
                db,
                wid,
                "confirm-false",
                "--actor",
                "ntk-auditor",
                "--reason",
                "Verified constant branch in source line 5",
            ],
            expected_exit=0,
        )
        self.assertEqual(decided["state"], "CONFIRMED_FALSE")

        q_default = self._cli(["queue", "--db", db])
        self.assertEqual(q_default["warnings"], [])

        q_all = self._cli(["queue", "--db", db, "--all"])
        self.assertEqual(len(q_all["warnings"]), 1)
        self.assertEqual(q_all["warnings"][0]["state"], "CONFIRMED_FALSE")

        hist = self._cli(["history", "--db", db, wid])
        self.assertEqual(len(hist), 1)
        self.assertEqual(hist[0]["action"], "confirm-false")
        self.assertEqual(hist[0]["actor"], "ntk-auditor")
        self.assertIn("Verified constant branch", hist[0]["reason"])
        self.assertTrue(hist[0]["source_version"])
        self.assertTrue(hist[0]["observed_version"])
        self.assertTrue(hist[0]["evidence_sha256"])

    def test_03_confirm_false_missing_actor_is_refused(self):
        store = self.store()
        db = str(Path(self.tmp.name) / "review.sqlite")
        wid = self.record["id"]

        for bad_actor in ("", "   "):
            err_msg = self._cli(
                ["decide", "--db", db, wid, "confirm-false", "--actor", bad_actor, "--reason", "valid reason"],
                expected_exit=2,
            )
            self.assertIn("operation refused", err_msg)
        self.assertEqual(store.get(wid)["state"], "OPEN")
        self.assertEqual(store.history(wid), [])

    def test_04_confirm_false_missing_reason_is_refused(self):
        store = self.store()
        db = str(Path(self.tmp.name) / "review.sqlite")
        wid = self.record["id"]

        for bad_reason in ("", "   "):
            err_msg = self._cli(
                ["decide", "--db", db, wid, "confirm-false", "--actor", "ntk-auditor", "--reason", bad_reason],
                expected_exit=2,
            )
            self.assertIn("operation refused", err_msg)
        self.assertEqual(store.get(wid)["state"], "OPEN")
        self.assertEqual(store.history(wid), [])

    def test_05_confirm_false_after_primary_source_modified_is_refused(self):
        store = self.store()
        db = str(Path(self.tmp.name) / "review.sqlite")
        wid = self.record["id"]

        self.source.write_text(self.text + "// modified after scan\n", encoding="utf-8")
        err_msg = self._cli(
            ["decide", "--db", db, wid, "confirm-false", "--actor", "ntk-auditor", "--reason", "stale source test"],
            expected_exit=2,
        )
        self.assertIn("rescan required", err_msg)
        self.assertEqual(store.get(wid)["state"], "OPEN")
        self.assertEqual(store.history(wid), [])

    def test_06_confirm_false_after_trace_file_modified_is_refused(self):
        trace_file = self.root / "TraceSource.java"
        trace_file.write_bytes(self.source.read_bytes())
        self.doc["results"][0]["extra"]["dataflow_trace"]["taint_source"][1][0]["path"] = "TraceSource.java"
        self.bundle = self.collect()
        self.record = self.bundle["records"][0]
        store = self.store()
        db = str(Path(self.tmp.name) / "review.sqlite")
        wid = self.record["id"]

        # Modify only the upstream trace source file, keeping sink file unchanged
        trace_file.write_text(self.text + "// trace source changed\n", encoding="utf-8")
        err_msg = self._cli(
            ["decide", "--db", db, wid, "confirm-false", "--actor", "ntk-auditor", "--reason", "trace file stale"],
            expected_exit=2,
        )
        self.assertIn("rescan required", err_msg)
        self.assertEqual(store.get(wid)["state"], "OPEN")
        self.assertEqual(store.history(wid), [])

    def test_07_confirm_false_after_source_file_deleted_is_refused(self):
        store = self.store()
        db = str(Path(self.tmp.name) / "review.sqlite")
        wid = self.record["id"]

        self.source.unlink()
        err_msg = self._cli(
            ["decide", "--db", db, wid, "confirm-false", "--actor", "ntk-auditor", "--reason", "deleted source file"],
            expected_exit=2,
        )
        self.assertIn("operation refused", err_msg)
        self.assertEqual(store.get(wid)["state"], "OPEN")
        self.assertEqual(store.history(wid), [])

    def test_08_confirm_false_with_evidence_issues_or_missing_provenance_is_refused(self):
        # Case A: evidence has issues
        self.bundle["records"][0]["issues"].append("incomplete trace")
        store = self.store()
        with self.assertRaises(EvidenceError):
            store.decide(self.record["id"], "confirm-false", "ntk-auditor", "has evidence issue")
        self.assertEqual(store.get(self.record["id"])["state"], "OPEN")

        # Case B: unverified scan provenance
        self.bundle["records"][0]["issues"] = []
        self.bundle["records"][0]["scan_provenance"] = {"origin": "declared_only", "source_capture_verified": False}
        db2 = Path(self.tmp.name) / "review_no_prov.sqlite"
        store2 = ReviewStore(db2)
        self.addCleanup(store2.close)
        store2.add(self.bundle, [undecided("MOCK", transport="mock")])
        with self.assertRaises(EvidenceError):
            store2.decide(self.record["id"], "confirm-false", "ntk-auditor", "unverified provenance")
        self.assertEqual(store2.get(self.record["id"])["state"], "OPEN")

    def test_09_confirm_true_transitions_state_and_keeps_warning_in_default_queue(self):
        self.store()
        db = str(Path(self.tmp.name) / "review.sqlite")
        wid = self.record["id"]

        decided = self._cli(
            [
                "decide",
                "--db",
                db,
                wid,
                "confirm-true",
                "--actor",
                "ntk-auditor",
                "--reason",
                "Confirmed exploitable SQL injection flow",
            ],
            expected_exit=0,
        )
        self.assertEqual(decided["state"], "CONFIRMED_TRUE")

        q_default = self._cli(["queue", "--db", db])
        self.assertEqual(len(q_default["warnings"]), 1)
        self.assertEqual(q_default["warnings"][0]["state"], "CONFIRMED_TRUE")

        hist = self._cli(["history", "--db", db, wid])
        self.assertEqual(len(hist), 1)
        self.assertEqual(hist[0]["action"], "confirm-true")

    def test_10_reopen_restores_open_state_and_preserves_full_audit_history(self):
        self.store()
        db = str(Path(self.tmp.name) / "review.sqlite")
        wid = self.record["id"]

        self._cli(
            ["decide", "--db", db, wid, "confirm-false", "--actor", "ntk-auditor", "--reason", "Initial dismissal"],
            expected_exit=0,
        )
        self.assertEqual(self._cli(["queue", "--db", db])["warnings"], [])

        reopened = self._cli(
            ["decide", "--db", db, wid, "reopen", "--actor", "lead-reviewer", "--reason", "Re-evaluating upstream caller"],
            expected_exit=0,
        )
        self.assertEqual(reopened["state"], "OPEN")

        q_default = self._cli(["queue", "--db", db])
        self.assertEqual(len(q_default["warnings"]), 1)
        self.assertEqual(q_default["warnings"][0]["state"], "OPEN")

        hist = self._cli(["history", "--db", db, wid])
        self.assertEqual(len(hist), 2)
        self.assertEqual([h["action"] for h in hist], ["confirm-false", "reopen"])
        self.assertEqual([h["actor"] for h in hist], ["ntk-auditor", "lead-reviewer"])

    def test_11_duplicate_import_does_not_overwrite_human_review_decision(self):
        store = self.store()
        wid = self.record["id"]
        store.decide(wid, "confirm-false", "ntk-auditor", "Verified safe constant")
        self.assertEqual(store.get(wid)["state"], "CONFIRMED_FALSE")

        with self.assertRaises(sqlite3.IntegrityError):
            store.add(self.bundle, [undecided("MOCK overwrite attempt", transport="mock")])

        # State and history must remain intact
        self.assertEqual(store.get(wid)["state"], "CONFIRMED_FALSE")
        self.assertEqual(len(store.history(wid)), 1)


if __name__ == "__main__":
    unittest.main()
