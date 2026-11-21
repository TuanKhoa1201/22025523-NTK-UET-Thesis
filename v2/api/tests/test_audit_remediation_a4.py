"""Counterexample & remediation tests for Audit Finding A4 (torn SQLite state vs history snapshot)."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from v2.api.config import ApiConfig
from v2.api.service import ApiServiceError, TriageApiService
from v2.triage import evidence, store


SAMPLE_JAVA = (
    "package demo;\n"
    "public class RaceDemo {\n"
    "    public void query(javax.servlet.http.HttpServletRequest req, java.sql.Statement st) throws Exception {\n"
    '        String id = req.getParameter("id");\n'
    '        st.executeQuery("SELECT * FROM users WHERE id=" + id);\n'
    "    }\n"
    "}\n"
)

ACTION_TO_STATE = {
    "confirm-true": "CONFIRMED_TRUE",
    "confirm-false": "CONFIRMED_FALSE",
    "reopen": "OPEN",
}


def _create_scan(base_dir: Path, tag: str = "a4") -> tuple[Path, Path, str, str]:
    src_dir = base_dir / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    java_file = src_dir / "RaceDemo.java"
    code = SAMPLE_JAVA + f"// {tag}\n"
    java_file.write_text(code, encoding="utf-8")
    lines = code.splitlines()
    src_txt = 'req.getParameter("id")'
    sink_txt = 'st.executeQuery("SELECT * FROM users WHERE id=" + id)'
    cs = lines[3].index(src_txt) + 1
    ck = lines[4].index(sink_txt) + 1
    src_loc = {"path": "RaceDemo.java", "start": {"line": 4, "col": cs}, "end": {"line": 4, "col": cs + len(src_txt)}}
    sink_loc = {"path": "RaceDemo.java", "start": {"line": 5, "col": ck}, "end": {"line": 5, "col": ck + len(sink_txt)}}
    finding = {
        "check_id": "v2.g1.java.cwe89.sqli",
        **sink_loc,
        "extra": {
            "severity": "ERROR",
            "message": f"SQLi test ({tag})",
            "metadata": {"cwe": ["CWE-89: SQL Injection"]},
            "dataflow_trace": {
                "taint_source": ["CliLoc", [src_loc, src_txt]],
                "taint_sink": ["CliLoc", [sink_loc, sink_txt]],
                "intermediate_vars": [],
            },
        },
    }
    raw_bytes = json.dumps({"results": [finding], "errors": []}).encode("utf-8")
    sha = evidence.digest(java_file.read_bytes())
    prov = {
        "origin": "recorded_capture_unsigned",
        "source_capture_verified": True,
        "exit_capture_verified": True,
        "recorded_engine_exit": 0,
        "source_hashes": {"RaceDemo.java": sha},
    }
    bundle = evidence.collect(raw_bytes, src_dir, engine_exit=0, scan_provenance=prov)
    bundle["scan_provenance"] = prov
    bundle["pre_scan_hashes"] = {"RaceDemo.java": sha}
    rec = bundle["records"][0]
    ass = {
        "status": "REFUTED",
        "raw_model_status": "REFUTED",
        "validated_status": "REFUTED",
        "validator_downgraded": False,
        "failure_kind": None,
        "explanation": "A4 snapshot consistency fixture",
        "fix_suggestion": "PreparedStatement",
        "citations": [{"path": "RaceDemo.java", "start_line": 5, "end_line": 5, "quote": lines[4], "sha256": sha}],
        "citation_check": "MATCHED",
        "requires_human_review": True,
        "security_conclusion_verified": False,
        "analyzed_at": evidence.now(),
        "runtime": {"origin": "unverified", "model_runtime_verified": False},
    }
    scan_dir = base_dir / "scan"
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "input.opengrep.json").write_bytes(raw_bytes)
    (scan_dir / "evidence.json").write_text(json.dumps(bundle), encoding="utf-8")
    rs = store.ReviewStore(scan_dir / "review.sqlite")
    try:
        rs.add(bundle, [ass])
    finally:
        rs.close()
    return scan_dir, java_file, bundle["scan_sha256"], rec["id"]


class AuditRemediationA4Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def _make_service(self, scan_dir: Path, name: str) -> TriageApiService:
        return TriageApiService(
            ApiConfig(
                host="127.0.0.1",
                port=0,
                data_dir=self.root / f"api_{name}",
                reviewable_scan_dirs=(scan_dir,),
                api_token="remediation-a4-token-20261117",
            )
        )

    def _assert_snapshot_consistent(self, detail: dict) -> None:
        events = detail["review_events"]
        seqs = [e["sequence"] for e in events]
        self.assertEqual(seqs, sorted(seqs), f"Events must be ordered by sequence: {seqs}")
        if events:
            expected_state = ACTION_TO_STATE[events[-1]["action"]]
            self.assertEqual(
                detail["human_review_state"],
                expected_state,
                f"Torn snapshot! state={detail['human_review_state']} vs latest event={events[-1]}",
            )
        else:
            self.assertEqual(detail["human_review_state"], "OPEN")

    def test_a4_interleaved_commit_between_warning_and_history_never_tears_snapshot(self) -> None:
        scan_dir, _, scan_id, finding_id = _create_scan(self.root / "race", tag="race")
        svc_a = self._make_service(scan_dir, "a")
        svc_b = self._make_service(scan_dir, "b")  # Separate service instance (distinct _review_lock!)

        # Seed initial confirm-true so state starts at CONFIRMED_TRUE
        svc_a.decide_finding(scan_id, finding_id, "confirm-true", "actor-init", "Initial confirm-true")

        # Force B to attempt committing confirm-false right between A's warnings SELECT and A's audit SELECT.
        orig_query_audit = TriageApiService._query_audit_on_conn
        a_reached_audit = threading.Event()
        b_finished = threading.Event()
        hook_active = {"enabled": True}

        def _hooked_query_audit(self_svc, *args, **kwargs):
            if hook_active["enabled"]:
                hook_active["enabled"] = False
                a_reached_audit.set()
                # Hold briefly (< SQLite 5s busy timeout) while B tries to commit between A's reads.
                b_finished.wait(timeout=0.25)
            return orig_query_audit(self_svc, *args, **kwargs)

        b_errors: list[Exception] = []

        def _writer_b() -> None:
            if not a_reached_audit.wait(timeout=2.0):
                return
            try:
                svc_b.decide_finding(scan_id, finding_id, "confirm-false", "actor-b", "Concurrent B confirm-false")
            except Exception as exc:
                b_errors.append(exc)
            finally:
                b_finished.set()

        with patch.object(TriageApiService, "_query_audit_on_conn", _hooked_query_audit):
            t_b = threading.Thread(target=_writer_b, daemon=True)
            t_b.start()
            detail_a = svc_a.get_finding_detail(scan_id, finding_id)
            t_b.join(timeout=6.0)

        self.assertEqual(b_errors, [], f"Writer B failed unexpectedly: {b_errors}")
        # Snapshot returned to A MUST match (both state and latest event from the same SQLite read snapshot)
        self._assert_snapshot_consistent(detail_a)

        # Also check decide_finding when B commits right before A reads its post-decision detail snapshot
        orig_get_detail = TriageApiService.get_finding_detail
        hook2 = {"enabled": True}

        def _hooked_get_detail(self_svc, s_id, f_id):
            if hook2["enabled"] and self_svc is svc_a:
                hook2["enabled"] = False
                svc_b.decide_finding(s_id, f_id, "confirm-true", "actor-b2", "Interleaved B confirm-true")
            return orig_get_detail(self_svc, s_id, f_id)

        with patch.object(TriageApiService, "get_finding_detail", _hooked_get_detail):
            detail_after_decide = svc_a.decide_finding(scan_id, finding_id, "reopen", "actor-a2", "A reopen")
        self._assert_snapshot_consistent(detail_after_decide)

        # Also check get_finding_history consistency
        hist = svc_a.get_finding_history(scan_id, finding_id, include_rejected=True)
        self.assertEqual(hist["human_review_state"], ACTION_TO_STATE[hist["events"][-1]["action"]])
        self.assertEqual(len(hist["events"]), 4)

    def test_a4_decide_finding_uses_consistent_snapshot_and_preserves_stale_source_and_rejected(self) -> None:
        scan_dir, java_file, scan_id, finding_id = _create_scan(self.root / "conc_inst", tag="conc_inst")
        svc_1 = self._make_service(scan_dir, "s1")
        svc_2 = self._make_service(scan_dir, "s2")

        # 1. Two independent service instances racing on the same SQLite DB must neither tear nor fail with SQLITE_BUSY
        def _worker(idx: int) -> dict:
            svc = svc_1 if idx % 2 == 0 else svc_2
            action = "confirm-true" if idx % 2 == 0 else "reopen"
            return svc.decide_finding(scan_id, finding_id, action, f"actor-{idx}", f"Concurrent decision #{idx}")

        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(_worker, range(8)))

        for res in results:
            self._assert_snapshot_consistent(res)

        final_hist = svc_1.get_finding_history(scan_id, finding_id, include_rejected=True)
        self.assertEqual(len(final_hist["events"]), 8)
        self.assertEqual(final_hist["human_review_state"], ACTION_TO_STATE[final_hist["events"][-1]["action"]])

        # 2. Mutate Java source on disk -> confirm-false must still fail with 409 STALE_SOURCE and record rejected_decisions
        java_file.write_text(SAMPLE_JAVA + "// drifted after concurrent decisions\n", encoding="utf-8")
        with self.assertRaises(ApiServiceError) as ctx:
            svc_2.decide_finding(scan_id, finding_id, "confirm-false", "actor-fp", "Attempt FP after drift")
        err = ctx.exception
        self.assertEqual(err.http_status, 409)
        self.assertEqual(err.error_code, "STALE_SOURCE")
        self.assertEqual(err.extra["human_review_state"], final_hist["human_review_state"])
        self.assertEqual(len(err.extra["review_events"]), 8)
        self.assertEqual(len(err.extra["rejected_decisions"]), 1)
        self.assertEqual(err.extra["rejected_decisions"][0]["rejection_code"], "STALE_SOURCE")

        # Verify rejected_decisions also appears cleanly in detail & report
        detail = svc_1.get_finding_detail(scan_id, finding_id)
        self._assert_snapshot_consistent(detail)
        self.assertEqual(len(detail["rejected_decisions"]), 1)

        report = svc_1.export_scan_report(scan_id)
        self.assertEqual(report["audit_trail"]["events_count"], 8)
        self.assertEqual(report["audit_trail"]["rejected_decisions_count"], 1)
        self.assertEqual(
            report["findings"][0]["human_review_state"],
            ACTION_TO_STATE[report["audit_trail"]["events"][0]["action"]],  # scan_review_history is DESC
        )


if __name__ == "__main__":
    unittest.main()
