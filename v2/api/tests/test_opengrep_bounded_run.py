"""Counterexample tests for bounded OpenGrep execution in v2.api scan jobs.

Regression scenario: a Windows wrapper timeout ("opengrep.cmd --version timed out after 90 seconds")
could stay blocked far past the timeout when descendant processes inherit stdout/stderr pipes.
A fake `opengrep.cmd -> python child -> python grandchild` chain (grandchild inherits stdout/stderr,
like wsl.exe under a Windows wrapper) reproduces the Windows pipe-hold behaviour without running
real OpenGrep, WSL2 or Qwen. All data is in isolated temporary directories.
"""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import zipfile

from v2.api import intake
from v2.api.tests.test_github_intake_timeout import _Proc

IS_WINDOWS = os.name == "nt"
HOLD_SECONDS = 50

FAKE_OPENGREP = r'''
import json, os, subprocess, sys, time

args = sys.argv[1:]
pid_file = os.environ.get("NTK_FAKE_OG_PIDFILE", "")
hang = os.environ.get("NTK_FAKE_OG_HANG", "")
hold = float(os.environ.get("NTK_FAKE_OG_HOLD", "50"))

def record(*pids):
    if pid_file:
        with open(pid_file, "a", encoding="utf-8") as fh:
            fh.write(" ".join(str(p) for p in pids) + "\n")

label = "version" if "--version" in args else ("json" if "--json" in args else ("sarif" if "--sarif" in args else "other"))
if label == hang:
    gc = subprocess.Popen([sys.executable, "-c", f"import time; time.sleep({hold})"])
    record(os.getpid(), gc.pid)
    sys.stderr.write("fake opengrep stalled (wsl.exe style)\n")
    sys.stderr.flush()
    time.sleep(hold)
    sys.exit(0)
if label == "version":
    code = int(os.environ.get("NTK_FAKE_OG_VERSION_EXIT", "0"))
    if code:
        sys.stderr.write("fake version failure\n")
        sys.exit(code)
    print("1.25.0")
    sys.exit(0)
if label == "json":
    print(json.dumps({"results": [], "errors": [], "paths": {"scanned": []}, "version": "1.25.0"}))
    sys.exit(0)
if label == "sarif":
    print(json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "opengrep", "rules": []}}, "results": []}]}))
    sys.exit(0)
sys.exit(2)
'''

SAMPLE_JAVA = "package demo;\npublic class Demo {\n    public int x() { return 1; }\n}\n"


@unittest.skipUnless(IS_WINDOWS, "Windows wrapper / Job Object behaviour")
class _FakeOpenGrepBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ntk-og-bounded-")
        self.root = Path(self.tmp.name)
        script = self.root / "fake_opengrep.py"
        script.write_text(FAKE_OPENGREP, encoding="utf-8")
        self.fake = self.root / "opengrep.cmd"
        self.fake.write_text(f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n', encoding="utf-8")
        self.pid_file = self.root / "pids.txt"
        self.env_patch = patch.dict(os.environ, {
            "NTK_FAKE_OG_PIDFILE": str(self.pid_file),
            "NTK_FAKE_OG_HOLD": str(HOLD_SECONDS),
            "NTK_FAKE_OG_HANG": "",
            "NTK_FAKE_OG_VERSION_EXIT": "0",
        })
        self.env_patch.start()
        self.procs: dict[int, _Proc] = {}
        self._stop = threading.Event()
        self._watcher = threading.Thread(target=self._watch, daemon=True)
        self._watcher.start()
        self.src = self.root / "src"
        self.src.mkdir()
        (self.src / "Demo.java").write_text(SAMPLE_JAVA, encoding="utf-8")

    def _watch(self):
        while not self._stop.is_set():
            self._absorb()
            time.sleep(0.01)

    def _absorb(self):
        if not self.pid_file.is_file():
            return
        try:
            text = self.pid_file.read_text(encoding="utf-8")
        except OSError:
            return
        for tok in text.split():
            pid = int(tok)
            if pid not in self.procs:
                self.procs[pid] = _Proc(pid)

    def tearDown(self):
        self._stop.set()
        self._watcher.join(timeout=2)
        try:
            intake._reconcile_lingering_git_jobs()
        except Exception:
            pass
        for p in self.procs.values():
            p.terminate_if_owned()
            p.close()
        self.env_patch.stop()
        self.tmp.cleanup()

    def _assert_descendants_exited(self, expected: int = 2, settle: float = 2.0):
        end = time.monotonic() + 3
        while time.monotonic() < end and len(self.procs) < expected:
            self._absorb()
            time.sleep(0.02)
        self.assertGreaterEqual(len(self.procs), expected, "fake opengrep did not record PIDs")
        end = time.monotonic() + settle
        while time.monotonic() < end and any(p.state() == _Proc.ALIVE for p in self.procs.values()):
            time.sleep(0.05)
        for pid, p in self.procs.items():
            self.assertEqual(p.state(), _Proc.EXITED, f"descendant PID {pid} is {p.state()}")


class ScanJobOpenGrepTimeoutTests(_FakeOpenGrepBase):
    """Job-level counterexample: same configuration path as the website (POST /api/scan-jobs)."""

    def test_version_hang_fails_within_bound_and_kills_tree(self):
        from v2.api.config import ApiConfig
        from v2.api.jobs import ScanJobManager

        os.environ["NTK_FAKE_OG_HANG"] = "version"
        cfg = ApiConfig(data_dir=self.root / "data", opengrep_binary=str(self.fake), opengrep_timeout_seconds=1)
        bound = cfg.opengrep_timeout_seconds + 30  # unchanged baseline bound
        mgr = ScanJobManager(cfg)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("proj/Demo.java", SAMPLE_JAVA)
        try:
            t0 = time.monotonic()
            job = mgr.submit_zip_job("proj.zip", buf.getvalue(), no_llm=True)
            deadline = t0 + HOLD_SECONDS + 30
            while time.monotonic() < deadline and mgr.get_job(job["job_id"])["state"] not in ("FAILED", "COMPLETED"):
                time.sleep(0.1)
            elapsed = time.monotonic() - t0
            doc = mgr.get_job(job["job_id"])
        finally:
            mgr.shutdown(wait=True)
        self.assertEqual(doc["state"], "FAILED")
        self.assertLess(elapsed, bound + 8, f"stage 2 returned after {elapsed:.1f}s, bound {bound}s")
        self.assertEqual(doc["error_code"], "OPENGREP_TIMEOUT", doc.get("error_message"))
        self.assertEqual(doc["stages"][1]["state"], "FAILED")
        self.assertTrue(all(s["state"] == "SKIPPED" for s in doc["stages"][2:]))
        details = doc.get("error_details") or {}
        self.assertEqual(details.get("engine_step"), "version")
        self.assertTrue((details.get("process_cleanup") or {}).get("clean"), details)
        failure = self.root / "data" / "scans" / job["job_id"] / "capture" / "version.failure.txt"
        self.assertTrue(failure.is_file())
        self.assertIn("OPENGREP_TIMEOUT", failure.read_text(encoding="utf-8"))
        self._assert_descendants_exited()


class BoundedScannerTests(_FakeOpenGrepBase):
    """Scanner-level tests with a short bound (2 s) to keep runtime low."""

    def _scanner(self, out_name="capture"):
        from v2.api.jobs import _load_baseline_scanner
        from v2.api.opengrep_runner import make_bounded_scanner_class
        from v2.g1_integration.bridge import DEFAULT_G1_RULES

        OpenGrepConfig, SemgrepScanner, ScanError = _load_baseline_scanner()
        cls = make_bounded_scanner_class(SemgrepScanner, ScanError)
        cfg = OpenGrepConfig(executable=str(self.fake), rules=DEFAULT_G1_RULES, timeout=1, jobs=1)
        scanner = cls(cfg, self.root / out_name)
        return scanner, ScanError

    def _run_short(self, scanner):
        with patch.object(type(scanner), "_process_timeout", lambda self: 2):
            return scanner.scan(self.src, None)

    def test_success_path_preserves_capture_and_outputs(self):
        scanner, _ = self._scanner()
        results = self._run_short(scanner)
        self.assertEqual(results["engine_version"], "1.25.0")
        out = self.root / "capture"
        for name in ("version.command.json", "version.stdout.txt", "version.exit.txt", "json.exit.txt",
                     "sarif.exit.txt", "opengrep.json", "opengrep.sarif", "scan-manifest.json"):
            self.assertTrue((out / name).is_file(), name)
        manifest = json.loads((out / "scan-manifest.json").read_text(encoding="utf-8"))
        self.assertTrue(manifest["success"])
        self.assertEqual(set(manifest["runs"]), {"version", "json", "sarif"})

    def test_json_scan_hang_is_bounded_and_tree_killed(self):
        os.environ["NTK_FAKE_OG_HANG"] = "json"
        scanner, ScanError = self._scanner()
        t0 = time.monotonic()
        with self.assertRaises(ScanError) as ctx:
            self._run_short(scanner)
        self.assertLess(time.monotonic() - t0, 2 + 8)
        self.assertEqual(getattr(ctx.exception, "error_code", None), "OPENGREP_TIMEOUT")
        self.assertTrue(ctx.exception.details["process_cleanup"]["clean"])
        manifest = json.loads((self.root / "capture" / "scan-manifest.json").read_text(encoding="utf-8"))
        self.assertFalse(manifest["success"])
        self._assert_descendants_exited()

    def test_nonzero_version_exit_is_preserved(self):
        os.environ["NTK_FAKE_OG_VERSION_EXIT"] = "3"
        scanner, ScanError = self._scanner()
        with self.assertRaises(ScanError) as ctx:
            self._run_short(scanner)
        self.assertIn("version exited 3", str(ctx.exception))
        self.assertEqual((self.root / "capture" / "version.exit.txt").read_text(encoding="utf-8"), "3")
        self.assertIn("fake version failure", (self.root / "capture" / "version.stderr.txt").read_text(encoding="utf-8"))

    def test_cleanup_failure_is_reported_and_blocks_next_run(self):
        os.environ["NTK_FAKE_OG_HANG"] = "version"
        real_call = intake._win_job_call

        def no_terminate(name, *args):
            if name == "TerminateJobObject":
                return 0
            return real_call(name, *args)

        scanner, ScanError = self._scanner()
        with patch.object(intake, "_win_job_call", side_effect=no_terminate), \
             patch.object(intake.subprocess.Popen, "kill", lambda self: None):
            with self.assertRaises(ScanError) as ctx:
                self._run_short(scanner)
            self.assertEqual(ctx.exception.error_code, "OPENGREP_TIMEOUT")
            self.assertEqual(ctx.exception.details.get("cleanup_status"), "CLEANUP_FAILED")
            self.assertFalse(ctx.exception.details["process_cleanup"]["clean"])
            failure = (self.root / "capture" / "version.failure.txt").read_text(encoding="utf-8")
            self.assertIn("CLEANUP_FAILED", failure)

            os.environ["NTK_FAKE_OG_HANG"] = ""
            before = set(self.procs)
            scanner2, _ = self._scanner("capture2")
            with self.assertRaises(ScanError) as ctx2:
                self._run_short(scanner2)
            self.assertEqual(ctx2.exception.error_code, "OPENGREP_CLEANUP_PENDING")
            time.sleep(0.3)
            self._absorb()
            self.assertEqual(set(self.procs), before, "no OpenGrep process may start while cleanup is pending")
        self.assertEqual(intake._reconcile_lingering_git_jobs(), 0)
        self._assert_descendants_exited()

    def test_isolation_unavailable_fails_closed_without_running(self):
        os.environ["NTK_FAKE_OG_HANG"] = "version"
        scanner, ScanError = self._scanner()
        with patch.object(intake, "_win_create_kill_on_close_job", return_value=None):
            with self.assertRaises(ScanError) as ctx:
                self._run_short(scanner)
        self.assertEqual(ctx.exception.error_code, "OPENGREP_PROCESS_ISOLATION_FAILED")
        time.sleep(0.5)
        self._absorb()
        self.assertEqual(self.procs, {})


class JobsWiringTests(unittest.TestCase):
    def test_opengrep_error_details_pass_allowlist(self):
        from v2.api.jobs import _safe_error_details

        d = _safe_error_details({
            "engine_step": "version", "timeout_seconds": 31, "cleanup_status": "CLEANUP_FAILED",
            "process_cleanup": {"step": "opengrep-version", "clean": False, "remaining_processes": 2},
            "stderr_bytes": 10, "raw": "secret text",
        })
        self.assertEqual(d["engine_step"], "version")
        self.assertEqual(d["process_cleanup"]["step"], "opengrep-version")
        self.assertNotIn("raw", d)


if __name__ == "__main__":
    unittest.main()
