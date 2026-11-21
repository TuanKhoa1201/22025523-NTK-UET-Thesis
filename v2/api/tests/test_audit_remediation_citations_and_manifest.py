"""Counterexample & remediation tests for invalid JSONL citations/nested types and non-object manifest root."""
from __future__ import annotations

from contextlib import closing
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


TEST_TOKEN = "remediation-citations-manifest-token-20261117"

SAMPLE_JAVA = (
    "package demo;\n"
    "public class ManifestCiteDemo {\n"
    "    public java.io.File open(javax.servlet.http.HttpServletRequest req) {\n"
    '        String f = req.getParameter("f");\n'
    '        return new java.io.File("/srv/data", f);\n'
    "    }\n"
    "}\n"
)


def _snapshot_sqlite(db_path: Path) -> tuple[list[tuple], list[tuple], list[tuple]]:
    with closing(sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)) as conn:
        warnings = [tuple(r) for r in conn.execute("SELECT id, state FROM warnings ORDER BY rowid").fetchall()]
        events = [tuple(r) for r in conn.execute("SELECT sequence, warning_id, action FROM events ORDER BY sequence").fetchall()]
        rejected = [
            tuple(r)
            for r in conn.execute("SELECT sequence, warning_id, rejection_code FROM rejected_decisions ORDER BY sequence").fetchall()
        ]
        return warnings, events, rejected


def _build_scan(
    base_dir: Path,
    *,
    tag: str,
    jsonl_mutator=None,
    g1_manifest_text: str | None = None,
    meta_text: str | None = None,
) -> tuple[Path, Path, str, str]:
    src_dir = base_dir / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    java_file = src_dir / "ManifestCiteDemo.java"
    code = SAMPLE_JAVA + f"// {tag}\n"
    java_file.write_text(code, encoding="utf-8")
    lines = code.splitlines()
    src_txt = 'req.getParameter("f")'
    sink_txt = 'new java.io.File("/srv/data", f)'
    cs = lines[3].index(src_txt) + 1
    ck = lines[4].index(sink_txt) + 1
    src_loc = {"path": "ManifestCiteDemo.java", "start": {"line": 4, "col": cs}, "end": {"line": 4, "col": cs + len(src_txt)}}
    sink_loc = {"path": "ManifestCiteDemo.java", "start": {"line": 5, "col": ck}, "end": {"line": 5, "col": ck + len(sink_txt)}}
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
    sarif_bytes = json.dumps({"version": "2.1.0", "runs": [{"results": []}]}).encode("utf-8")
    scan_manifest_bytes = json.dumps({"success": True, "runs": {}}).encode("utf-8")
    cli_origin_bytes = json.dumps({"mode": "local-triage"}).encode("utf-8")
    sha = evidence.digest(java_file.read_bytes())
    prov = {
        "origin": "recorded_capture_unsigned",
        "source_capture_verified": True,
        "exit_capture_verified": True,
        "recorded_engine_exit": 0,
        "source_hashes": {"ManifestCiteDemo.java": sha},
    }
    bundle = evidence.collect(raw_bytes, src_dir, engine_exit=0, scan_provenance=prov)
    bundle["scan_provenance"] = prov
    bundle["pre_scan_hashes"] = {"ManifestCiteDemo.java": sha}
    rec = bundle["records"][0]
    ass = {
        "status": "REFUTED",
        "raw_model_status": "REFUTED",
        "validated_status": "REFUTED",
        "validator_downgraded": False,
        "failure_kind": None,
        "explanation": "Manifest and citations validation test",
        "fix_suggestion": "Normalize path",
        "citations": [{"path": "ManifestCiteDemo.java", "start_line": 5, "end_line": 5, "quote": lines[4], "sha256": sha}],
        "citation_check": "MATCHED",
        "requires_human_review": True,
        "security_conclusion_verified": False,
        "analyzed_at": evidence.now(),
        "runtime": {"origin": "unverified", "model_runtime_verified": False},
    }

    scan_dir = base_dir / "scan"
    capture_dir = scan_dir / "capture"
    triage_dir = scan_dir / "triage"
    capture_dir.mkdir(parents=True, exist_ok=True)
    triage_dir.mkdir(parents=True, exist_ok=True)

    og_json = capture_dir / "opengrep.json"
    og_sarif = capture_dir / "opengrep.sarif"
    scan_manifest = capture_dir / "scan-manifest.json"
    cli_origin = capture_dir / "cli-origin.json"
    ev_path = triage_dir / "evidence.json"
    jsonl_path = triage_dir / "assessments.jsonl"
    db_path = triage_dir / "review.sqlite"

    og_json.write_bytes(raw_bytes)
    og_sarif.write_bytes(sarif_bytes)
    scan_manifest.write_bytes(scan_manifest_bytes)
    cli_origin.write_bytes(cli_origin_bytes)
    ev_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")

    jsonl_row = {
        "schema_version": bundle["schema_version"],
        "id": rec["id"],
        "alert_id": rec["id"],
        "scan_sha256": bundle["scan_sha256"],
        "finding_index": 0,
        "state": "OPEN",
        "evidence": rec,
        "assessment": ass,
    }
    if jsonl_mutator is not None:
        jsonl_mutator(jsonl_row)
    jsonl_path.write_text(json.dumps(jsonl_row) + "\n", encoding="utf-8")

    rs = store.ReviewStore(db_path)
    try:
        rs.add(bundle, [ass])
    finally:
        rs.close()

    if g1_manifest_text is None:
        http_check_path = triage_dir / "http-capture-check.json"
        http_check_path.write_text(
            json.dumps({"capture_status": "VERIFIED_COMPLETE", "capture_integrity_ok": True}, indent=2) + "\n",
            encoding="utf-8",
        )
        g1_manifest = {
            "schema": "ntk-g1-run-manifest-1",
            "ollama": {
                "enabled": True,
                "endpoint": "http://127.0.0.1:11434",
                "requested_model": "qwen3.5:9b-q4_K_M",
                "runtime_origin": "unverified",
            },
            "findings_summary": {
                "total_findings": 1,
                "validated_statuses": ["REFUTED"],
                "human_review_states": ["OPEN"],
            },
            "artifacts": {
                "opengrep_json": {"path": str(og_json), "sha256": evidence.digest(og_json.read_bytes())},
                "opengrep_sarif": {"path": str(og_sarif), "sha256": evidence.digest(og_sarif.read_bytes())},
                "scan_manifest": {"path": str(scan_manifest), "sha256": evidence.digest(scan_manifest.read_bytes())},
                "cli_origin": {"path": str(cli_origin), "sha256": evidence.digest(cli_origin.read_bytes())},
                "evidence_json": {"path": str(ev_path), "sha256": evidence.digest(ev_path.read_bytes())},
                "assessments_jsonl": {"path": str(jsonl_path), "sha256": evidence.digest(jsonl_path.read_bytes())},
                "review_sqlite": {"path": str(db_path), "sha256": evidence.digest(db_path.read_bytes())},
                "http_capture_check": {"path": str(http_check_path), "sha256": evidence.digest(http_check_path.read_bytes())},
            },
        }
        g1_manifest_text = json.dumps(g1_manifest, indent=2)
    (scan_dir / "g1-run-manifest.json").write_text(g1_manifest_text, encoding="utf-8")

    if meta_text is not None:
        (scan_dir / "api-scan-meta.json").write_text(meta_text, encoding="utf-8")

    return scan_dir, java_file, bundle["scan_sha256"], rec["id"]


class AuditRemediationCitationsAndManifestTests(unittest.TestCase):
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

    def test_jsonl_invalid_citations_blocks_all_review_actions_without_sqlite_mutation(self) -> None:
        cases = {
            "citations_object_instead_of_list": lambda row: row["assessment"].__setitem__(
                "citations", {"invalid": "object-instead-of-list"}
            ),
            "citation_element_not_dict": lambda row: row["assessment"].__setitem__("citations", ["not-a-dict"]),
            "citation_element_bad_line_type": lambda row: row["assessment"].__setitem__(
                "citations",
                [{"path": "ManifestCiteDemo.java", "start_line": "5", "end_line": 5, "quote": "x", "sha256": "a" * 64}],
            ),
            "evidence_snippets_not_list": lambda row: row["evidence"].__setitem__("snippets", {"bad": True}),
        }
        built: list[tuple[str, Path, str, str]] = []
        for label, mutator in cases.items():
            sdir, _, sid, fid = _build_scan(self.root / label, tag=label, jsonl_mutator=mutator)
            built.append((label, sdir, sid, fid))

        base = self._start_server(tuple(x[1] for x in built))
        for label, sdir, sid, fid in built:
            db_path = sdir / "triage" / "review.sqlite"
            before = _snapshot_sqlite(db_path)
            for action in ("confirm-true", "confirm-false", "reopen"):
                with self.subTest(case=label, action=action):
                    code, payload = self._http(
                        f"{base}/api/scans/{sid}/findings/{fid}/{action}",
                        method="POST",
                        body={"actor": "auditor", "reason": f"Try {action} with {label}"},
                    )
                    self.assertEqual(
                        code,
                        409,
                        f"[{label}/{action}] Expected 409 ARTIFACT_PROVENANCE_MISMATCH, got {code}: {payload}",
                    )
                    self.assertEqual(payload["error_code"], "ARTIFACT_PROVENANCE_MISMATCH")
            self.assertEqual(before, _snapshot_sqlite(db_path), f"[{label}] SQLite mutated despite invalid JSONL!")

            with self.subTest(case=label, endpoint="report"):
                code_rep, p_rep = self._http(f"{base}/api/scans/{sid}/report")
                self.assertEqual(code_rep, 409)
                self.assertEqual(p_rep["error_code"], "ARTIFACT_PROVENANCE_MISMATCH")

    def test_manifest_non_object_root_and_corrupt_fail_closed_no_500(self) -> None:
        manifest_cases = {
            "g1_list_root": ("[]", None),
            "g1_null_root": ("null", None),
            "g1_corrupt_json": ("{not-json", None),
            "meta_list_root": (None, "[]"),
        }
        built: list[tuple[str, Path, str, str]] = []
        for label, (g1_txt, meta_txt) in manifest_cases.items():
            sdir, _, sid, fid = _build_scan(
                self.root / label,
                tag=label,
                g1_manifest_text=g1_txt,
                meta_text=meta_txt,
            )
            built.append((label, sdir, sid, fid))

        base = self._start_server(tuple(x[1] for x in built))
        for label, sdir, sid, fid in built:
            db_path = sdir / "triage" / "review.sqlite"
            before = _snapshot_sqlite(db_path)
            for method, suffix, body in (
                ("GET", f"/api/scans/{sid}/report", None),
                ("GET", f"/api/scans/{sid}", None),
                ("GET", f"/api/scans/{sid}/findings/{fid}", None),
                ("POST", f"/api/scans/{sid}/findings/{fid}/confirm-true", {"actor": "auditor", "reason": "Review with bad manifest"}),
                ("POST", f"/api/scans/{sid}/findings/{fid}/confirm-false", {"actor": "auditor", "reason": "Review with bad manifest"}),
                ("POST", f"/api/scans/{sid}/findings/{fid}/reopen", {"actor": "auditor", "reason": "Review with bad manifest"}),
            ):
                with self.subTest(case=label, endpoint=suffix):
                    code, payload = self._http(f"{base}{suffix}", method=method, body=body)
                    self.assertEqual(
                        code,
                        409,
                        f"[{label} {suffix}] Expected 409 ARTIFACT_PROVENANCE_MISMATCH (never 500), got {code}: {payload}",
                    )
                    self.assertEqual(payload["error_code"], "ARTIFACT_PROVENANCE_MISMATCH")
            self.assertEqual(before, _snapshot_sqlite(db_path))

    def test_valid_manifest_human_review_and_stale_source_preserved(self) -> None:
        sdir, java_file, sid, fid = _build_scan(self.root / "valid_full", tag="valid_full")
        base = self._start_server((sdir,))

        code_rep, rep = self._http(f"{base}/api/scans/{sid}/report")
        self.assertEqual(code_rep, 200, rep)
        self.assertEqual(rep["data_origin"], "REAL_SCAN")

        code_cf, d_cf = self._http(
            f"{base}/api/scans/{sid}/findings/{fid}/confirm-false",
            method="POST",
            body={"actor": "reviewer", "reason": "Valid confirm-false"},
        )
        self.assertEqual(code_cf, 200, d_cf)
        self.assertEqual(d_cf["human_review_state"], "CONFIRMED_FALSE")

        code_re, d_re = self._http(
            f"{base}/api/scans/{sid}/findings/{fid}/reopen",
            method="POST",
            body={"actor": "reviewer", "reason": "Valid reopen"},
        )
        self.assertEqual(code_re, 200, d_re)
        self.assertEqual(d_re["human_review_state"], "OPEN")

        code_ct, d_ct = self._http(
            f"{base}/api/scans/{sid}/findings/{fid}/confirm-true",
            method="POST",
            body={"actor": "reviewer", "reason": "Valid confirm-true"},
        )
        self.assertEqual(code_ct, 200, d_ct)
        self.assertEqual(d_ct["human_review_state"], "CONFIRMED_TRUE")

        code_re2, _ = self._http(
            f"{base}/api/scans/{sid}/findings/{fid}/reopen",
            method="POST",
            body={"actor": "reviewer", "reason": "Reopen before source drift"},
        )
        self.assertEqual(code_re2, 200)

        # Trigger 409 STALE_SOURCE after modifying the analyzed Java source file
        java_file.write_text(SAMPLE_JAVA + "// drifted\n", encoding="utf-8")
        code_stale, stale = self._http(
            f"{base}/api/scans/{sid}/findings/{fid}/confirm-false",
            method="POST",
            body={"actor": "reviewer", "reason": "Should fail with STALE_SOURCE"},
        )
        self.assertEqual(code_stale, 409, stale)
        self.assertEqual(stale["error_code"], "STALE_SOURCE")
        self.assertEqual(stale["human_review_state"], "OPEN")
        self.assertEqual(len(stale["rejected_decisions"]), 1)
        self.assertEqual(stale["rejected_decisions"][0]["rejection_code"], "STALE_SOURCE")


if __name__ == "__main__":
    unittest.main()
