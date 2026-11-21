"""Counterexample & remediation tests for corrupt/invalid-typed assessments.jsonl fail-closed behavior."""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from v2.api.config import ApiConfig
from v2.api.server import ThesisApiServer
from v2.triage import evidence, store


TEST_TOKEN = "remediation-jsonl-token-20261117"

SAMPLE_JAVA = (
    "package demo;\n"
    "public class JsonlAuditDemo {\n"
    "    public java.io.File open(javax.servlet.http.HttpServletRequest req) {\n"
    '        String p = req.getParameter("p");\n'
    '        return new java.io.File("/srv/data", p);\n'
    "    }\n"
    "}\n"
)


def _create_scan(
    base_dir: Path,
    *,
    tag: str,
    jsonl_content: str | None = None,
    omit_runtime_in_jsonl: bool = False,
) -> tuple[Path, Path, str, str]:
    src_dir = base_dir / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    java_file = src_dir / "JsonlAuditDemo.java"
    code = SAMPLE_JAVA + f"// {tag}\n"
    java_file.write_text(code, encoding="utf-8")
    lines = code.splitlines()
    src_txt = 'req.getParameter("p")'
    sink_txt = 'new java.io.File("/srv/data", p)'
    cs = lines[3].index(src_txt) + 1
    ck = lines[4].index(sink_txt) + 1
    src_loc = {"path": "JsonlAuditDemo.java", "start": {"line": 4, "col": cs}, "end": {"line": 4, "col": cs + len(src_txt)}}
    sink_loc = {"path": "JsonlAuditDemo.java", "start": {"line": 5, "col": ck}, "end": {"line": 5, "col": ck + len(sink_txt)}}
    finding = {
        "check_id": "v2.g1.java.cwe22.path-traversal",
        **sink_loc,
        "extra": {
            "severity": "ERROR",
            "message": f"CWE-22 finding ({tag})",
            "metadata": {"cwe": ["CWE-22: Path Traversal"]},
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
        "source_hashes": {"JsonlAuditDemo.java": sha},
    }
    bundle = evidence.collect(raw_bytes, src_dir, engine_exit=0, scan_provenance=prov)
    bundle["scan_provenance"] = prov
    bundle["pre_scan_hashes"] = {"JsonlAuditDemo.java": sha}
    rec = bundle["records"][0]
    ass = {
        "status": "REFUTED",
        "raw_model_status": "REFUTED",
        "validated_status": "REFUTED",
        "validator_downgraded": False,
        "failure_kind": None,
        "explanation": "JSONL fail-closed test",
        "fix_suggestion": "Normalize path",
        "citations": [{"path": "JsonlAuditDemo.java", "start_line": 5, "end_line": 5, "quote": lines[4], "sha256": sha}],
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

    if jsonl_content is None:
        jsonl_ass = dict(ass)
        if omit_runtime_in_jsonl:
            jsonl_ass.pop("runtime", None)
        jsonl_row = {
            "schema_version": bundle["schema_version"],
            "id": rec["id"],
            "alert_id": rec["id"],
            "scan_sha256": bundle["scan_sha256"],
            "finding_index": 0,
            "state": "OPEN",
            "evidence": rec,
            "assessment": jsonl_ass,
        }
        jsonl_content = json.dumps(jsonl_row) + "\n"
    (scan_dir / "assessments.jsonl").write_text(jsonl_content, encoding="utf-8")

    rs = store.ReviewStore(scan_dir / "review.sqlite")
    try:
        rs.add(bundle, [ass])
    finally:
        rs.close()

    return scan_dir, java_file, bundle["scan_sha256"], rec["id"]


def _snapshot_sqlite(db_path: Path) -> tuple[list[tuple], list[tuple], list[tuple]]:
    conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
    try:
        warnings = [tuple(r) for r in conn.execute("SELECT id, state FROM warnings ORDER BY rowid").fetchall()]
        events = [tuple(r) for r in conn.execute("SELECT sequence, warning_id, action FROM events ORDER BY sequence").fetchall()]
        rejected = [tuple(r) for r in conn.execute("SELECT sequence, warning_id, rejection_code FROM rejected_decisions ORDER BY sequence").fetchall()]
        return warnings, events, rejected
    finally:
        conn.close()


class JsonlFailClosedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def _start_server(self, scan_dirs: tuple[Path, ...]) -> str:
        srv = ThesisApiServer(
            ApiConfig(
                host="127.0.0.1",
                port=0,
                data_dir=self.root / "api_data",
                reviewable_scan_dirs=scan_dirs,
                api_token=TEST_TOKEN,
            )
        )
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: (srv.shutdown(), thread.join(timeout=2.0), srv.server_close()))
        host, port = srv.server_address[:2]
        return f"http://{host}:{port}"

    def _http(self, url: str, *, method: str = "GET", body: dict | None = None) -> tuple[int, dict]:
        headers = {"Authorization": f"Bearer {TEST_TOKEN}", "Connection": "close"}
        raw = None
        if body is not None:
            raw = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = Request(url, data=raw, headers=headers, method=method)
        try:
            with urlopen(req, timeout=15) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_corrupt_jsonl_before_mock_marker_fails_closed_for_all_review_actions(self) -> None:
        mock_line = json.dumps({"evidence": {}, "assessment": {"runtime": {"origin": "mock"}}})
        scan_dir, _, scan_id, finding_id = _create_scan(
            self.root / "corrupt_before_mock",
            tag="corrupt_before_mock",
            jsonl_content="{invalid-json-line\n" + mock_line + "\n",
        )
        base = self._start_server((scan_dir,))
        db_path = scan_dir / "review.sqlite"
        before = _snapshot_sqlite(db_path)

        for action in ("confirm-true", "confirm-false", "reopen"):
            with self.subTest(action=action):
                code, err = self._http(
                    f"{base}/api/scans/{scan_id}/findings/{finding_id}/{action}",
                    method="POST",
                    body={"actor": "auditor", "reason": f"Try {action} with corrupt JSONL"},
                )
                self.assertEqual(code, 409, f"Expected 409 ARTIFACT_PROVENANCE_MISMATCH, got {code}: {err}")
                self.assertEqual(err["error_code"], "ARTIFACT_PROVENANCE_MISMATCH")

        after = _snapshot_sqlite(db_path)
        self.assertEqual(before, after, "SQLite must remain untouched when JSONL is corrupt!")

    def test_invalid_nested_types_in_jsonl_never_500_on_review_or_report(self) -> None:
        bad_payloads = {
            "assessment_list": '{"assessment":[1],"evidence":{}}\n',
            "runtime_list": '{"assessment":{"runtime":[1]},"evidence":{}}\n',
            "scan_prov_str": '{"assessment":{},"evidence":{"scan_provenance":"bad"}}\n',
            "top_level_list": '[1, 2, 3]\n',
        }
        scan_entries: list[tuple[str, Path, str, str]] = []
        for label, content in bad_payloads.items():
            sdir, _, sid, fid = _create_scan(self.root / label, tag=label, jsonl_content=content)
            scan_entries.append((label, sdir, sid, fid))

        base = self._start_server(tuple(x[1] for x in scan_entries))
        for label, sdir, sid, fid in scan_entries:
            db_path = sdir / "review.sqlite"
            before = _snapshot_sqlite(db_path)
            with self.subTest(case=label, endpoint="confirm-true"):
                code, err = self._http(
                    f"{base}/api/scans/{sid}/findings/{fid}/confirm-true",
                    method="POST",
                    body={"actor": "auditor", "reason": "Try review with invalid nested types"},
                )
                self.assertEqual(code, 409, f"[{label}] Expected 409, got {code}: {err}")
                self.assertEqual(err["error_code"], "ARTIFACT_PROVENANCE_MISMATCH")
                self.assertEqual(before, _snapshot_sqlite(db_path))

            with self.subTest(case=label, endpoint="report"):
                code, err = self._http(f"{base}/api/scans/{sid}/report")
                self.assertEqual(code, 409, f"[{label}] Expected 409 (never 500), got {code}: {err}")
                self.assertEqual(err["error_code"], "ARTIFACT_PROVENANCE_MISMATCH")

    def test_valid_scan_and_stale_source_not_regressed(self) -> None:
        # Also verify valid JSONL where optional assessment.runtime is omitted works cleanly
        scan_dir_opt, _, sid_opt, fid_opt = _create_scan(
            self.root / "opt_rt",
            tag="opt_rt",
            omit_runtime_in_jsonl=True,
        )
        scan_dir_ok, java_file_ok, sid_ok, fid_ok = _create_scan(
            self.root / "valid_ok",
            tag="valid_ok",
        )
        base = self._start_server((scan_dir_opt, scan_dir_ok))

        code, d_opt = self._http(
            f"{base}/api/scans/{sid_opt}/findings/{fid_opt}/confirm-true",
            method="POST",
            body={"actor": "reviewer", "reason": "Optional runtime omitted in JSONL is valid"},
        )
        self.assertEqual(code, 200, d_opt)
        self.assertEqual(d_opt["human_review_state"], "CONFIRMED_TRUE")

        # Full confirm-false -> reopen -> 409 STALE_SOURCE flow on valid scan
        code, d_fp = self._http(
            f"{base}/api/scans/{sid_ok}/findings/{fid_ok}/confirm-false",
            method="POST",
            body={"actor": "reviewer", "reason": "Valid confirm-false"},
        )
        self.assertEqual(code, 200)
        self.assertEqual(d_fp["human_review_state"], "CONFIRMED_FALSE")

        code, d_re = self._http(
            f"{base}/api/scans/{sid_ok}/findings/{fid_ok}/reopen",
            method="POST",
            body={"actor": "reviewer", "reason": "Reopen before drift check"},
        )
        self.assertEqual(code, 200)
        self.assertEqual(d_re["human_review_state"], "OPEN")

        java_file_ok.write_text(SAMPLE_JAVA + "// drifted\n", encoding="utf-8")
        code, stale = self._http(
            f"{base}/api/scans/{sid_ok}/findings/{fid_ok}/confirm-false",
            method="POST",
            body={"actor": "reviewer", "reason": "Should trigger STALE_SOURCE"},
        )
        self.assertEqual(code, 409)
        self.assertEqual(stale["error_code"], "STALE_SOURCE")
        self.assertEqual(stale["human_review_state"], "OPEN")
        self.assertEqual(len(stale["rejected_decisions"]), 1)
        self.assertEqual(stale["rejected_decisions"][0]["rejection_code"], "STALE_SOURCE")


if __name__ == "__main__":
    unittest.main()
