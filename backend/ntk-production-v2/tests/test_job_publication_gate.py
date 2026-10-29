"""Regression test: no COMPLETED scan is published until the result index is ready."""
import sys
import threading
import time
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import ntk_pipeline_telemetry_and_datasets as telemetry


class PublicationGateTests(unittest.TestCase):
    def test_finished_pipeline_is_masked_while_persisting(self):
        entered_persistence = threading.Event()
        commit_done = threading.Event()

        def execute(job_rec):
            tr = job_rec.tracker
            tr.start_stage(1)
            tr.complete_stage(1)
            tr.start_stage(10)
            tr.complete_stage(10)
            # This simulates the real backend which finalizes the 10-stage trace
            # before record_scan() has finished writing JSON and SQLite.
            tr.finish_pipeline(success=True)
            entered_persistence.set()
            if not commit_done.wait(timeout=3):
                raise TimeoutError("test did not unblock simulated persistence")
            return {"status": "OK", "summary": {"total_scanner_candidates": 0}}

        manager = telemetry.ScanJobManager(execute_job_callable=execute)
        status, submitted = manager.submit_job({"repo_url": "https://github.com/example/java-demo"})
        self.assertEqual(status, 202)
        job_id = submitted["job_id"]
        self.assertTrue(entered_persistence.wait(timeout=2))
        try:
            current = manager.get_job_snapshot(job_id)
            self.assertEqual(current["state"], "RUNNING")
            self.assertFalse(current["results_ready"])
            self.assertEqual(current["publication_state"], "PERSISTING_RESULTS")
            self.assertEqual(manager.list_jobs()[0]["state"], "RUNNING")
            status_dup, duplicate = manager.submit_job({"repo_url": "https://github.com/example/java-demo"})
            self.assertEqual(status_dup, 202)
            self.assertEqual(duplicate["job_id"], job_id)
            self.assertTrue(duplicate["deduplicated_existing_job"])
            self.assertEqual(duplicate["state"], "RUNNING")
        finally:
            commit_done.set()

        for _ in range(100):
            completed = manager.get_job_snapshot(job_id)
            if completed["state"] == "COMPLETED":
                break
            time.sleep(0.015)
        self.assertEqual(completed["state"], "COMPLETED")
        self.assertTrue(completed["results_ready"])
        self.assertEqual(completed["publication_state"], "READY")
        self.assertEqual(manager.list_jobs()[0]["state"], "COMPLETED")

    def test_persistence_failure_is_not_published_as_success(self):
        def execute(job_rec):
            tracker = job_rec.tracker
            tracker.start_stage(1)
            tracker.complete_stage(1)
            tracker.start_stage(10)
            tracker.complete_stage(10)
            tracker.finish_pipeline(success=True)
            raise IOError("simulated disk-full while committing SQLite")

        manager = telemetry.ScanJobManager(execute_job_callable=execute)
        status, submitted = manager.submit_job({"repo_url": "https://github.com/example/java-demo"})
        self.assertEqual(status, 202)
        job_id = submitted["job_id"]
        for _ in range(150):
            current = manager.get_job_snapshot(job_id)
            if current["state"] == "FAILED":
                break
            time.sleep(0.01)
        self.assertEqual(current["state"], "FAILED")
        self.assertFalse(current["results_ready"])
        self.assertEqual(current["publication_state"], "NOT_READY")

    def test_restored_trace_without_findings_is_not_results_ready(self):
        manager = telemetry.ScanJobManager(execute_job_callable=lambda _: {"status": "ERROR"})
        old_trace = {"state": "COMPLETED", "scan_id": "SCAN-HISTORICAL-1", "job_id": "JOB-HISTORICAL-1"}
        job_id = manager.restore_completed_job_from_trace(
            old_trace, has_full_scan_payload=False, restoration_status="RESTORED_TRACE_ONLY"
        )
        self.assertEqual(job_id, "JOB-HISTORICAL-1")
        state = manager.get_job_snapshot(job_id)
        self.assertEqual(state["state"], "COMPLETED")
        self.assertFalse(state["results_ready"])
        self.assertEqual(state["publication_state"], "TRACE_ONLY")

    def test_fresh_scan_has_distinct_deduplication_key(self):
        base = {"repo_url": "https://github.com/example/java-demo"}
        fresh = {**base, "force_fresh_scan": True}
        self.assertNotEqual(
            telemetry.ScanJobManager.compute_request_fingerprint(base),
            telemetry.ScanJobManager.compute_request_fingerprint(fresh),
        )

    def test_manifest_uses_eo06_canonical_fields(self):
        provenance = telemetry.get_eo06_training_provenance()
        self.assertEqual(provenance["primary_training_dataset_id"], "track_b_audited_full")
        self.assertEqual(provenance["primary_training_dataset_rows"], 781)
        self.assertEqual(provenance["validation_dataset_rows"], 166)
        self.assertTrue(provenance["track_a_is_strict_subset_of_track_b"])
        self.assertEqual(len(provenance["best_adapter_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
