"""Counterexample & remediation tests for Audit Findings A1 (body read/drain timeout) and A2 (mock DB mutation before 403)."""
from __future__ import annotations

from http.client import HTTPConnection
import json
from pathlib import Path
import socket
import sqlite3
import tempfile
import threading
import time
import unittest

from v2.api.config import ApiConfig
from v2.api.server import ThesisApiServer
from v2.triage import evidence, store


TEST_TOKEN = "remediation-a1-a2-token-20261117"

SAMPLE_JAVA = (
    "package demo;\n"
    "public class AuditDemo {\n"
    "    public java.io.File read(javax.servlet.http.HttpServletRequest req) {\n"
    '        String p = req.getParameter("p");\n'
    '        return new java.io.File("/var/tmp", p);\n'
    "    }\n"
    "}\n"
)


def _create_scan(base_dir: Path, *, mark_mock: bool, tag: str) -> tuple[Path, str, str]:
    src_dir = base_dir / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    java_file = src_dir / "AuditDemo.java"
    code = SAMPLE_JAVA + f"// {tag}\n"
    java_file.write_text(code, encoding="utf-8")
    lines = code.splitlines()
    src_txt = 'req.getParameter("p")'
    sink_txt = 'new java.io.File("/var/tmp", p)'
    cs = lines[3].index(src_txt) + 1
    ck = lines[4].index(sink_txt) + 1
    src_loc = {"path": "AuditDemo.java", "start": {"line": 4, "col": cs}, "end": {"line": 4, "col": cs + len(src_txt)}}
    sink_loc = {"path": "AuditDemo.java", "start": {"line": 5, "col": ck}, "end": {"line": 5, "col": ck + len(sink_txt)}}
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
        "origin": "UNIT_TEST_MOCK_CAPTURE" if mark_mock else "recorded_capture_unsigned",
        "source_capture_verified": True,
        "exit_capture_verified": True,
        "recorded_engine_exit": 0,
        "source_hashes": {"AuditDemo.java": sha},
    }
    bundle = evidence.collect(raw_bytes, src_dir, engine_exit=0, scan_provenance=prov)
    bundle["scan_provenance"] = prov
    bundle["pre_scan_hashes"] = {"AuditDemo.java": sha}
    ass = {
        "status": "REFUTED",
        "raw_model_status": "REFUTED",
        "validated_status": "REFUTED",
        "validator_downgraded": False,
        "failure_kind": None,
        "explanation": "Audit A1/A2 fixture",
        "fix_suggestion": "Normalize path",
        "citations": [{"path": "AuditDemo.java", "start_line": 5, "end_line": 5, "quote": lines[4], "sha256": sha}],
        "citation_check": "MATCHED",
        "requires_human_review": True,
        "security_conclusion_verified": False,
        "analyzed_at": evidence.now(),
        "runtime": {"origin": "mock" if mark_mock else "unverified", "model_runtime_verified": False},
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
    return scan_dir, bundle["scan_sha256"], bundle["records"][0]["id"]


def _snapshot_sqlite(db_path: Path) -> tuple[list[tuple], list[tuple], list[tuple]]:
    conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
    try:
        warnings = [tuple(r) for r in conn.execute("SELECT id, state FROM warnings ORDER BY rowid").fetchall()]
        events = [tuple(r) for r in conn.execute("SELECT sequence, warning_id, action, actor, reason FROM events ORDER BY sequence").fetchall()]
        rejected = [tuple(r) for r in conn.execute("SELECT sequence, warning_id, attempted_action, rejection_code FROM rejected_decisions ORDER BY sequence").fetchall()]
        return warnings, events, rejected
    finally:
        conn.close()


class AuditRemediationA1A2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def _start_server(self, config: ApiConfig) -> tuple[ThesisApiServer, str, int]:
        srv = ThesisApiServer(config)
        # Use short deadlines during tests so incomplete-body cases complete deterministically.
        if hasattr(srv, "drain_timeout_seconds"):
            srv.drain_timeout_seconds = 0.25
        if hasattr(srv, "body_read_timeout_seconds"):
            srv.body_read_timeout_seconds = 0.4
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: (srv.shutdown(), thread.join(timeout=2.0), srv.server_close()))
        host, port = srv.server_address[:2]
        return srv, str(host), int(port)

    def _raw_partial_post(
        self,
        host: str,
        port: int,
        path: str,
        *,
        headers: dict[str, str],
        declared_length: int,
        sent_prefix: bytes,
        client_timeout: float = 1.5,
    ) -> tuple[int, dict, str]:
        with socket.create_connection((host, port), timeout=client_timeout) as sock:
            sock.settimeout(client_timeout)
            req_lines = [
                f"POST {path} HTTP/1.1",
                f"Host: {host}:{port}",
                f"Content-Length: {declared_length}",
                "Content-Type: application/json",
            ]
            for k, v in headers.items():
                req_lines.append(f"{k}: {v}")
            raw_head = ("\r\n".join(req_lines) + "\r\n\r\n").encode("ascii")
            sock.sendall(raw_head + sent_prefix)

            chunks: list[bytes] = []
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
                joined = b"".join(chunks)
                if b"\r\n\r\n" in joined:
                    head_part, body_part = joined.split(b"\r\n\r\n", 1)
                    head_txt = head_part.decode("iso-8859-1")
                    cl = None
                    for line in head_txt.splitlines()[1:]:
                        if line.lower().startswith("content-length:"):
                            cl = int(line.split(":", 1)[1].strip())
                    if cl is not None and len(body_part) >= cl:
                        status_line = head_txt.splitlines()[0]
                        status_code = int(status_line.split()[1])
                        return status_code, json.loads(body_part[:cl].decode("utf-8")), head_txt
            raise AssertionError(f"Socket closed before complete HTTP response; received={b''.join(chunks)!r}")

    def test_a1_incomplete_post_body_never_blocks_indefinitely_and_keepalive_works(self) -> None:
        rw_dir, scan_id, finding_id = _create_scan(self.root / "a1", mark_mock=False, tag="a1")
        _, host, port = self._start_server(
            ApiConfig(
                host="127.0.0.1",
                port=0,
                data_dir=self.root / "data_a1",
                reviewable_scan_dirs=(rw_dir,),
                api_token=TEST_TOKEN,
            )
        )
        action_path = f"/api/scans/{scan_id}/findings/{finding_id}/confirm-true"

        # 1. Missing token + declared Content-Length: 100 + incomplete body -> 401 within deadline
        t0 = time.monotonic()
        code, payload, head = self._raw_partial_post(
            host,
            port,
            action_path,
            headers={},
            declared_length=100,
            sent_prefix=b'{"actor":',
            client_timeout=1.5,
        )
        elapsed = time.monotonic() - t0
        self.assertEqual(code, 401)
        self.assertEqual(payload["error_code"], "UNAUTHORIZED")
        self.assertIn("connection: close", head.lower())
        self.assertLess(elapsed, 1.2)

        # 2. Wrong token + declared Content-Length: 100 + incomplete body -> 401 within deadline
        t0 = time.monotonic()
        code, payload, head = self._raw_partial_post(
            host,
            port,
            action_path,
            headers={"Authorization": "Bearer wrong-token-value"},
            declared_length=100,
            sent_prefix=b'{"actor":"x"',
            client_timeout=1.5,
        )
        elapsed = time.monotonic() - t0
        self.assertEqual(code, 401)
        self.assertEqual(payload["error_code"], "UNAUTHORIZED")
        self.assertIn("connection: close", head.lower())
        self.assertLess(elapsed, 1.2)

        # 3. Valid token + incomplete body -> 408 timeout within deadline (does not hang forever)
        t0 = time.monotonic()
        code, payload, head = self._raw_partial_post(
            host,
            port,
            action_path,
            headers={"Authorization": f"Bearer {TEST_TOKEN}"},
            declared_length=100,
            sent_prefix=b'{"actor":"reviewer",',
            client_timeout=1.5,
        )
        elapsed = time.monotonic() - t0
        self.assertEqual(code, 408)
        self.assertEqual(payload["error_code"], "REQUEST_BODY_TIMEOUT")
        self.assertIn("connection: close", head.lower())
        self.assertLess(elapsed, 1.2)

        # 4 & 5. Valid POST with full body + consecutive keep-alive request on same HTTPConnection
        conn = HTTPConnection(host, port, timeout=5)
        self.addCleanup(conn.close)
        conn.request(
            "POST",
            action_path,
            body=json.dumps({"actor": "reviewer-a1", "reason": "Full body over keep-alive"}),
            headers={"Authorization": f"Bearer {TEST_TOKEN}", "Content-Type": "application/json"},
        )
        r1 = conn.getresponse()
        d1 = json.loads(r1.read().decode("utf-8"))
        self.assertEqual(r1.status, 200)
        self.assertEqual(d1["human_review_state"], "CONFIRMED_TRUE")

        conn.request(
            "POST",
            f"/api/scans/{scan_id}/findings/{finding_id}/reopen",
            body=json.dumps({"actor": "reviewer-a1", "reason": "Second request on same keep-alive socket"}),
            headers={"Authorization": f"Bearer {TEST_TOKEN}", "Content-Type": "application/json"},
        )
        r2 = conn.getresponse()
        d2 = json.loads(r2.read().decode("utf-8"))
        self.assertEqual(r2.status, 200)
        self.assertEqual(d2["human_review_state"], "OPEN")
        self.assertEqual(len(d2["review_events"]), 2)

    def test_a1_slow_trickle_post_body_respects_overall_deadline(self) -> None:
        rw_dir, scan_id, finding_id = _create_scan(self.root / "trickle", mark_mock=False, tag="trickle")
        _, host, port = self._start_server(
            ApiConfig(
                host="127.0.0.1",
                port=0,
                data_dir=self.root / "data_trickle",
                reviewable_scan_dirs=(rw_dir,),
                api_token=TEST_TOKEN,
            )
        )
        action_path = f"/api/scans/{scan_id}/findings/{finding_id}/confirm-true"

        def _run_trickle(headers: dict[str, str], expected_status: int, expected_code: str) -> None:
            with socket.create_connection((host, port), timeout=2.0) as sock:
                sock.settimeout(2.0)
                req_lines = [
                    f"POST {action_path} HTTP/1.1",
                    f"Host: {host}:{port}",
                    "Content-Length: 80",
                    "Content-Type: application/json",
                ]
                for k, v in headers.items():
                    req_lines.append(f"{k}: {v}")
                sock.sendall(("\r\n".join(req_lines) + "\r\n\r\n").encode("ascii"))

                stop_trickle = threading.Event()

                def _trickle_sender() -> None:
                    for _ in range(30):
                        if stop_trickle.is_set():
                            return
                        try:
                            sock.sendall(b"x")
                        except OSError:
                            return
                        time.sleep(0.08)

                sender = threading.Thread(target=_trickle_sender, daemon=True)
                sender.start()
                t0 = time.monotonic()
                try:
                    chunks: list[bytes] = []
                    while True:
                        data = sock.recv(4096)
                        if not data:
                            break
                        chunks.append(data)
                        joined = b"".join(chunks)
                        if b"\r\n\r\n" in joined:
                            head_part, body_part = joined.split(b"\r\n\r\n", 1)
                            head_txt = head_part.decode("iso-8859-1")
                            cl = None
                            for line in head_txt.splitlines()[1:]:
                                if line.lower().startswith("content-length:"):
                                    cl = int(line.split(":", 1)[1].strip())
                            if cl is not None and len(body_part) >= cl:
                                elapsed = time.monotonic() - t0
                                status_code = int(head_txt.splitlines()[0].split()[1])
                                payload = json.loads(body_part[:cl].decode("utf-8"))
                                self.assertEqual(status_code, expected_status)
                                self.assertEqual(payload["error_code"], expected_code)
                                self.assertIn("connection: close", head_txt.lower())
                                self.assertLess(elapsed, 1.2)
                                return
                    raise AssertionError(f"Socket closed without HTTP response: {b''.join(chunks)!r}")
                finally:
                    stop_trickle.set()
                    sender.join(timeout=1.0)

        # Authenticated slow-trickle (1 byte every 80ms < 400ms per-recv timeout) must still trip overall 0.4s deadline!
        _run_trickle({"Authorization": f"Bearer {TEST_TOKEN}"}, 408, "REQUEST_BODY_TIMEOUT")
        # Unauthenticated slow-trickle (1 byte every 80ms < 250ms drain timeout) must still abort drain at 0.25s and return 401!
        _run_trickle({}, 401, "UNAUTHORIZED")

    def test_a2_mock_scan_cannot_be_mutated_before_403_and_real_scan_still_works(self) -> None:
        mock_dir, mock_scan, mock_finding = _create_scan(self.root / "mock", mark_mock=True, tag="mock_a2")
        real_dir, real_scan, real_finding = _create_scan(self.root / "real", mark_mock=False, tag="real_a2")
        _, host, port = self._start_server(
            ApiConfig(
                host="127.0.0.1",
                port=0,
                data_dir=self.root / "data_a2",
                reviewable_scan_dirs=(mock_dir, real_dir),
                api_token=TEST_TOKEN,
            )
        )

        mock_db = mock_dir / "review.sqlite"
        before_snapshot = _snapshot_sqlite(mock_db)

        conn = HTTPConnection(host, port, timeout=5)
        self.addCleanup(conn.close)

        for action in ("confirm-true", "confirm-false", "reopen"):
            conn.request(
                "POST",
                f"/api/scans/{mock_scan}/findings/{mock_finding}/{action}",
                body=json.dumps({"actor": "auditor", "reason": f"Try {action} on mock"}),
                headers={"Authorization": f"Bearer {TEST_TOKEN}", "Content-Type": "application/json"},
            )
            resp = conn.getresponse()
            err = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(resp.status, 403, f"Expected 403 for mock {action}, got {resp.status}: {err}")
            self.assertEqual(err["error_code"], "TEST_DATA_ISOLATED")

        after_snapshot = _snapshot_sqlite(mock_db)
        self.assertEqual(before_snapshot, after_snapshot, "Mock SQLite DB MUST remain byte/row unchanged!")

        # Real reviewable scan must still work without regression
        conn.request(
            "POST",
            f"/api/scans/{real_scan}/findings/{real_finding}/confirm-false",
            body=json.dumps({"actor": "reviewer-a2", "reason": "Real scan intact source"}),
            headers={"Authorization": f"Bearer {TEST_TOKEN}", "Content-Type": "application/json"},
        )
        r_real = conn.getresponse()
        d_real = json.loads(r_real.read().decode("utf-8"))
        self.assertEqual(r_real.status, 200)
        self.assertEqual(d_real["human_review_state"], "CONFIRMED_FALSE")


if __name__ == "__main__":
    unittest.main()
