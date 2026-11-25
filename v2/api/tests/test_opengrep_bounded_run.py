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
import shutil
import struct
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


def _write_minimal_native_executable(path: Path, *, is_dll: bool = False, overlay: bytes = b"") -> Path:
    """Create a minimal platform-valid native executable header for capability-boundary unit tests."""
    if os.name == "nt":
        # Minimal valid PE32+ executable: 64-byte DOS header + 24-byte COFF + 240-byte PE32+ optional + 40-byte .text section.
        e_lfanew = 64
        opt_size = 240
        sec_ptr = 512
        sec_size = 512
        buf = bytearray(sec_ptr + sec_size)
        buf[0:2] = b"MZ"
        struct.pack_into("<I", buf, 60, e_lfanew)
        buf[e_lfanew : e_lfanew + 4] = b"PE\x00\x00"
        chars = 0x0002 | (0x2000 if is_dll else 0)
        struct.pack_into("<HHIIIHH", buf, e_lfanew + 4, 0x8664, 1, 0, 0, 0, opt_size, chars)
        opt_off = e_lfanew + 24
        struct.pack_into("<H", buf, opt_off, 0x020B)  # PE32+
        struct.pack_into("<I", buf, opt_off + 108, 16)  # NumberOfRvaAndSizes
        sh_off = opt_off + opt_size
        buf[sh_off : sh_off + 5] = b".text"
        struct.pack_into("<IIII", buf, sh_off + 8, sec_size, 0x1000, sec_size, sec_ptr)
        struct.pack_into("<I", buf, sh_off + 36, 0x60000020)  # CODE | EXECUTE | READ
        buf[sec_ptr] = 0xC3  # ret
        data = bytes(buf) + overlay
    elif sys.platform.startswith("linux"):
        buf = bytearray(64)
        buf[0:4] = b"\x7fELF"
        buf[4] = 2  # 64-bit
        buf[5] = 1  # little-endian
        buf[6] = 1  # EV_CURRENT
        struct.pack_into("<H", buf, 16, 2)  # ET_EXEC
        data = bytes(buf) + overlay
    elif sys.platform == "darwin":
        buf = bytearray(64)
        buf[0:4] = b"\xcf\xfa\xed\xfe"  # MH_MAGIC_64
        data = bytes(buf) + overlay
    else:
        data = b"\x00" * 64 + overlay
    path.write_bytes(data)
    if os.name != "nt":
        path.chmod(0o755)
    return path


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

    def test_single_pass_dual_output_receipt_fallback_and_fail_closed_guards(self):
        from v2.api import opengrep_runner
        from v2.api.config import ApiConfig
        from v2.api.jobs import _load_baseline_scanner
        from v2.api.opengrep_runner import make_bounded_scanner_class
        from v2.g1_integration.bridge import DEFAULT_G1_RULES
        from v2.g1_integration.finding_identity import compare_findings
        from v2.triage.scan_receipt import verify_receipt

        OpenGrepConfig, SemgrepScanner, ScanError = _load_baseline_scanner()
        Bounded = make_bounded_scanner_class(SemgrepScanner, ScanError)

        with tempfile.TemporaryDirectory(prefix="ntk-sp-test-") as td:
            root = Path(td)
            src = root / "src"
            src.mkdir()
            jf = src / "Demo.java"
            jf.write_text(SAMPLE_JAVA, encoding="utf-8")

            j_doc = {
                "version": "1.25.0",
                "results": [
                    {
                        "check_id": "ntk.test.cwe89",
                        "path": str(jf),
                        "start": {"line": 2, "col": 1},
                        "end": {"line": 2, "col": 10},
                        "extra": {"severity": "ERROR", "metadata": {"cwe": ["CWE-89"]}},
                    }
                ],
                "errors": [],
                "paths": {"scanned": [str(jf)]},
            }
            s_doc = {
                "version": "2.1.0",
                "runs": [
                    {
                        "results": [
                            {
                                "ruleId": "ntk.test.cwe89",
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": str(jf)},
                                            "region": {
                                                "startLine": 2,
                                                "startColumn": 1,
                                                "endLine": 2,
                                                "endColumn": 10,
                                            },
                                        }
                                    }
                                ],
                            }
                        ]
                    }
                ],
            }

            # 1. Verified native binary: invokes scan ONCE, writes --sarif-output, passes sealed verify_receipt!
            native_bin = _write_minimal_native_executable(
                root / ("opengrep_sp.exe" if IS_WINDOWS else "opengrep_sp")
            )
            seen_sp_cmds: list[list[str]] = []

            def run_native_sp(step, cmd, **_kw):
                seen_sp_cmds.append(list(cmd))
                if "--version" in cmd:
                    return subprocess.CompletedProcess(cmd, 0, b"1.25.0\n", b"")
                if "--sarif-output" in cmd:
                    Path(cmd[cmd.index("--sarif-output") + 1]).write_text(json.dumps(s_doc), encoding="utf-8")
                if "--sarif" in cmd:
                    return subprocess.CompletedProcess(cmd, 0, json.dumps(s_doc).encode("utf-8"), b"")
                return subprocess.CompletedProcess(cmd, 0, json.dumps(j_doc).encode("utf-8"), b"")

            out_sp = root / "cap_sp"
            cfg_sp = OpenGrepConfig(executable=str(native_bin), rules=DEFAULT_G1_RULES, timeout=15, jobs=2)
            scanner_sp = Bounded(cfg_sp, out_sp)
            with patch.object(intake, "_run_git_step", side_effect=run_native_sp):
                res_sp = scanner_sp.scan(src, DEFAULT_G1_RULES)
            self.assertEqual(res_sp["engine_version"], "1.25.0")
            self.assertEqual(scanner_sp.last_timing["single_pass_capability"], "NATIVE_SINGLE_PASS_ELIGIBLE")
            self.assertTrue(scanner_sp.last_timing["single_pass_dual_output"])
            self.assertFalse(scanner_sp.last_timing["fallback_to_two_pass"])
            self.assertEqual(scanner_sp.last_timing["jobs"], 2)
            self.assertEqual(len(seen_sp_cmds), 2, f"Expected 1 version + 1 dual-output scan, got: {seen_sp_cmds}")
            self.assertEqual([p.name for p in out_sp.iterdir() if p.name.endswith(".tmp")], [])

            raw_json = (out_sp / "opengrep.json").read_bytes()
            meta, issues = verify_receipt(out_sp / "scan-manifest.json", raw_json, src, declared_exit=0)
            self.assertEqual(issues, [], issues)
            self.assertTrue(meta["source_capture_verified"])
            self.assertTrue(meta["exit_capture_verified"])
            parity = compare_findings(
                json.loads(raw_json.decode("utf-8")),
                json.loads((out_sp / "opengrep.sarif").read_text(encoding="utf-8")),
            )
            self.assertTrue(parity["rule_ids_and_locations_match"])

            # 2. Legacy native engine rejecting --sarif-output falls back cleanly to 2-pass and passes verify_receipt!
            def run_native_fb(step, cmd, **_kw):
                if "--version" in cmd:
                    return subprocess.CompletedProcess(cmd, 0, b"1.25.0\n", b"")
                if "--sarif-output" in cmd:
                    return subprocess.CompletedProcess(cmd, 2, b"", b"error: unknown option --sarif-output\n")
                if "--sarif" in cmd:
                    return subprocess.CompletedProcess(cmd, 0, json.dumps({"version": "2.1.0", "runs": [{"results": []}]}).encode("utf-8"), b"")
                return subprocess.CompletedProcess(
                    cmd, 0, json.dumps({"version": "1.25.0", "results": [], "errors": [], "paths": {"scanned": []}}).encode("utf-8"), b""
                )

            out_fb = root / "cap_fb"
            scanner_fb = Bounded(OpenGrepConfig(executable=str(native_bin), rules=DEFAULT_G1_RULES, timeout=15, jobs=1), out_fb)
            with patch.object(intake, "_run_git_step", side_effect=run_native_fb):
                scanner_fb.scan(src, DEFAULT_G1_RULES)
            self.assertEqual(scanner_fb.last_timing["single_pass_capability"], "NATIVE_SINGLE_PASS_ELIGIBLE")
            self.assertFalse(scanner_fb.last_timing["single_pass_dual_output"])
            self.assertTrue(scanner_fb.last_timing["fallback_to_two_pass"])
            _, fb_issues = verify_receipt(out_fb / "scan-manifest.json", (out_fb / "opengrep.json").read_bytes(), src, declared_exit=0)
            self.assertEqual(fb_issues, [], fb_issues)

            # 3. Oversized --sarif-output file on native binary fails closed with OPENGREP_OUTPUT_LIMIT_EXCEEDED
            out_cap = root / "cap_limit"
            scanner_lim = Bounded(cfg_sp, out_cap)
            with patch.object(opengrep_runner, "MAX_OPENGREP_OUTPUT_BYTES", 64), \
                 patch.object(intake, "_run_git_step", side_effect=run_native_sp):
                with self.assertRaises(ScanError) as ctx_lim:
                    scanner_lim.scan(src, DEFAULT_G1_RULES)
            self.assertEqual(getattr(ctx_lim.exception, "error_code", None), "OPENGREP_OUTPUT_LIMIT_EXCEEDED")

            # 4. Fingerprinted wrapper (.cmd/.sh -> python bridge) runs two-pass stdout, never receives --sarif-output
            inv_log = root / "inv_wrap.log"
            wrap_py = root / "wrap_engine.py"
            wrap_py.write_text(
                "import json, pathlib, sys\n"
                "args = sys.argv[1:]\n"
                f"with open({str(inv_log)!r}, 'a', encoding='utf-8') as lf:\n"
                "    lf.write(' '.join(args) + '\\n')\n"
                "if '--version' in args:\n"
                "    print('1.25.0'); sys.exit(0)\n"
                "if '--sarif-output' in args:\n"
                "    sys.stderr.write('output path translation failed\\n'); sys.exit(2)\n"
                f"j_doc = {j_doc!r}\n"
                f"s_doc = {s_doc!r}\n"
                "if '--sarif' in args:\n"
                "    print(json.dumps(s_doc)); sys.exit(0)\n"
                "print(json.dumps(j_doc)); sys.exit(0)\n",
                encoding="utf-8",
            )
            wrap_bin = root / ("opengrep_wrap.cmd" if IS_WINDOWS else "opengrep_wrap.sh")
            if IS_WINDOWS:
                wrap_bin.write_text(f'@echo off\r\n"{sys.executable}" "{wrap_py}" %*\r\n', encoding="utf-8")
            else:
                wrap_bin.write_text(f'#!/bin/sh\n"{sys.executable}" "{wrap_py}" "$@"\n', encoding="utf-8")
                wrap_bin.chmod(0o755)
            out_wrap = root / "cap_wrap"
            scanner_wrap = Bounded(OpenGrepConfig(executable=str(wrap_bin), rules=DEFAULT_G1_RULES, timeout=15, jobs=1), out_wrap)
            scanner_wrap.scan(src, DEFAULT_G1_RULES)
            self.assertEqual(scanner_wrap.last_timing["single_pass_capability"], "WRAPPER_SINGLE_PASS_CAPABILITY_NOT_VERIFIED")
            self.assertFalse(scanner_wrap.last_timing["single_pass_dual_output"])
            self.assertFalse(scanner_wrap.last_timing["fallback_to_two_pass"])
            wrap_inv = inv_log.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(wrap_inv), 3, wrap_inv)
            self.assertTrue(all("--sarif-output" not in line for line in wrap_inv), wrap_inv)
            _, wrap_issues = verify_receipt(out_wrap / "scan-manifest.json", (out_wrap / "opengrep.json").read_bytes(), src, declared_exit=0)
            self.assertEqual(wrap_issues, [], wrap_issues)

            # 5. ApiConfig.opengrep_jobs bounds validation (1..8)
            ok_cfg = ApiConfig(data_dir=root / "d_ok", rules_path=DEFAULT_G1_RULES, opengrep_jobs=4, runtime_origin="mock")
            self.assertEqual(ok_cfg.opengrep_jobs, 4)
            for bad_j in (0, -1, 9):
                with self.assertRaises(ValueError):
                    ApiConfig(data_dir=root / f"d_bad_{bad_j}", rules_path=DEFAULT_G1_RULES, opengrep_jobs=bad_j, runtime_origin="mock")

    def test_fin05_wsl_bridge_capability_gate_and_fail_closed_guards(self):
        from v2.api import opengrep_runner
        from v2.api.jobs import _load_baseline_scanner
        from v2.api.opengrep_runner import make_bounded_scanner_class
        from v2.g1_integration.bridge import DEFAULT_G1_RULES
        from v2.g1_integration.finding_identity import compare_findings
        from v2.triage.scan_receipt import verify_receipt

        OpenGrepConfig, SemgrepScanner, ScanError = _load_baseline_scanner()
        Bounded = make_bounded_scanner_class(SemgrepScanner, ScanError)

        with tempfile.TemporaryDirectory(prefix="ntk-fin05-wsl-") as td:
            root = Path(td)
            src = root / "src"
            src.mkdir()
            jf = src / "Demo.java"
            jf.write_text(SAMPLE_JAVA, encoding="utf-8")

            j_doc = {
                "version": "1.25.0",
                "results": [
                    {
                        "check_id": "ntk.test.cwe89",
                        "path": str(jf),
                        "start": {"line": 2, "col": 1},
                        "end": {"line": 2, "col": 10},
                        "extra": {"severity": "ERROR", "metadata": {"cwe": ["CWE-89"]}},
                    }
                ],
                "errors": [],
                "paths": {"scanned": [str(jf)]},
            }
            s_doc = {
                "version": "2.1.0",
                "runs": [
                    {
                        "results": [
                            {
                                "ruleId": "ntk.test.cwe89",
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": str(jf)},
                                            "region": {
                                                "startLine": 2,
                                                "startColumn": 1,
                                                "endLine": 2,
                                                "endColumn": 10,
                                            },
                                        }
                                    }
                                ],
                            }
                        ]
                    }
                ],
            }

            # 1. Unverified WSL2 bridge wrapper MUST NOT receive --sarif-output and MUST use two-pass stdout
            wsl_py = root / "opengrep_wsl_bridge.py"
            wsl_py.write_text(
                "import subprocess, sys\n"
                "def main():\n"
                "    cmd = ['wsl.exe', '-d', 'Ubuntu-IRIS', '--', '/usr/local/bin/opengrep', *sys.argv[1:]]\n"
                "    return subprocess.run(cmd, check=False).returncode\n"
                "if __name__ == '__main__':\n"
                "    sys.exit(main())\n",
                encoding="utf-8",
            )
            wsl_cmd = root / ("opengrep_counted.cmd" if IS_WINDOWS else "opengrep_counted.sh")
            if IS_WINDOWS:
                wsl_cmd.write_text(f'@echo off\r\n"{sys.executable}" "{wsl_py}" %*\r\n', encoding="utf-8")
            else:
                wsl_cmd.write_text(f'#!/bin/sh\n"{sys.executable}" "{wsl_py}" "$@"\n', encoding="utf-8")
                wsl_cmd.chmod(0o755)

            seen_wsl_cmds: list[list[str]] = []

            def fake_wsl_run(step, cmd, **_kw):
                seen_wsl_cmds.append(list(cmd))
                if "--version" in cmd:
                    return subprocess.CompletedProcess(cmd, 0, b"1.25.0\n", b"")
                if "--json" in cmd:
                    return subprocess.CompletedProcess(cmd, 0, json.dumps(j_doc).encode("utf-8"), b"")
                if "--sarif" in cmd:
                    return subprocess.CompletedProcess(cmd, 0, json.dumps(s_doc).encode("utf-8"), b"")
                return subprocess.CompletedProcess(cmd, 2, b"", b"unexpected args")

            out_wsl = root / "cap_wsl"
            scanner_wsl = Bounded(OpenGrepConfig(executable=str(wsl_cmd), rules=DEFAULT_G1_RULES, timeout=15, jobs=2), out_wsl)
            with patch.object(intake, "_run_git_step", side_effect=fake_wsl_run):
                res_wsl = scanner_wsl.scan(src, DEFAULT_G1_RULES)
            self.assertEqual(res_wsl["engine_version"], "1.25.0")
            self.assertEqual(scanner_wsl.last_timing["single_pass_capability"], "WSL_SINGLE_PASS_CAPABILITY_NOT_VERIFIED")
            self.assertFalse(scanner_wsl.last_timing["single_pass_dual_output"])
            self.assertFalse(scanner_wsl.last_timing["fallback_to_two_pass"])
            self.assertEqual(len(seen_wsl_cmds), 3)
            self.assertTrue(all("--sarif-output" not in c for c in seen_wsl_cmds), seen_wsl_cmds)
            raw_json = (out_wsl / "opengrep.json").read_bytes()
            _, wsl_issues = verify_receipt(out_wsl / "scan-manifest.json", raw_json, src, declared_exit=0)
            self.assertEqual(wsl_issues, [], wsl_issues)
            self.assertTrue(
                compare_findings(
                    json.loads(raw_json.decode("utf-8")),
                    json.loads((out_wsl / "opengrep.sarif").read_text(encoding="utf-8")),
                )["rule_ids_and_locations_match"]
            )

            # 2. Verified native executable stub for fail-closed single-pass error tests
            native_bin = _write_minimal_native_executable(
                root / ("opengrep_native.exe" if IS_WINDOWS else "opengrep_native")
            )
            native_cfg = OpenGrepConfig(executable=str(native_bin), rules=DEFAULT_G1_RULES, timeout=15, jobs=2)

            # 2a. Empty 0-byte --sarif-output file MUST fail closed without falling back to two-pass
            calls_empty: list[list[str]] = []

            def run_empty_sarif(step, cmd, **_kw):
                calls_empty.append(list(cmd))
                if "--version" in cmd:
                    return subprocess.CompletedProcess(cmd, 0, b"1.25.0\n", b"")
                if "--sarif-output" in cmd:
                    Path(cmd[cmd.index("--sarif-output") + 1]).write_bytes(b"")
                    return subprocess.CompletedProcess(cmd, 0, json.dumps(j_doc).encode("utf-8"), b"")
                raise AssertionError(f"Unexpected fallback call: {cmd}")

            out_empty = root / "cap_empty"
            with patch.object(intake, "_run_git_step", side_effect=run_empty_sarif):
                with self.assertRaises(ScanError) as ctx_empty:
                    Bounded(native_cfg, out_empty).scan(src, DEFAULT_G1_RULES)
            self.assertIn("empty sarif-output", str(ctx_empty.exception))
            self.assertEqual(len(calls_empty), 2)
            self.assertEqual([p.name for p in out_empty.iterdir() if p.name.endswith(".tmp")], [])

            # 2b. Corrupt JSON in --sarif-output file MUST fail closed without falling back
            calls_corrupt: list[list[str]] = []

            def run_corrupt_sarif(step, cmd, **_kw):
                calls_corrupt.append(list(cmd))
                if "--version" in cmd:
                    return subprocess.CompletedProcess(cmd, 0, b"1.25.0\n", b"")
                if "--sarif-output" in cmd:
                    Path(cmd[cmd.index("--sarif-output") + 1]).write_text("{not-json", encoding="utf-8")
                    return subprocess.CompletedProcess(cmd, 0, json.dumps(j_doc).encode("utf-8"), b"")
                raise AssertionError(f"Unexpected fallback call: {cmd}")

            out_corrupt = root / "cap_corrupt"
            with patch.object(intake, "_run_git_step", side_effect=run_corrupt_sarif):
                with self.assertRaises(ScanError) as ctx_corrupt:
                    Bounded(native_cfg, out_corrupt).scan(src, DEFAULT_G1_RULES)
            self.assertIn("invalid sarif", str(ctx_corrupt.exception))
            self.assertEqual(len(calls_corrupt), 2)
            self.assertEqual([p.name for p in out_corrupt.iterdir() if p.name.endswith(".tmp")], [])

            # 2c. Symlink --sarif-output stage path MUST fail closed without falling back
            calls_sym: list[list[str]] = []
            orig_is_symlink = Path.is_symlink

            def fake_is_symlink(p: Path) -> bool:
                if p.name == ".opengrep.singlepass.sarif.tmp" and p.exists():
                    return True
                return orig_is_symlink(p)

            def run_sym_sarif(step, cmd, **_kw):
                calls_sym.append(list(cmd))
                if "--version" in cmd:
                    return subprocess.CompletedProcess(cmd, 0, b"1.25.0\n", b"")
                if "--sarif-output" in cmd:
                    Path(cmd[cmd.index("--sarif-output") + 1]).write_text(json.dumps(s_doc), encoding="utf-8")
                    return subprocess.CompletedProcess(cmd, 0, json.dumps(j_doc).encode("utf-8"), b"")
                raise AssertionError(f"Unexpected fallback call: {cmd}")

            out_sym = root / "cap_sym"
            with patch.object(intake, "_run_git_step", side_effect=run_sym_sarif), \
                 patch.object(Path, "is_symlink", fake_is_symlink):
                with self.assertRaises(ScanError) as ctx_sym:
                    Bounded(native_cfg, out_sym).scan(src, DEFAULT_G1_RULES)
            self.assertIn("symlink", str(ctx_sym.exception))
            self.assertEqual(len(calls_sym), 2)
            self.assertEqual([p.name for p in out_sym.iterdir() if p.name.endswith(".tmp")], [])

            # 2d. Non-zero exit NOT rejecting --sarif-output, timeout, and cleanup failure MUST NOT fall back
            for case_name, side_fx, expected_code in (
                (
                    "nonzero_unrelated",
                    lambda step, cmd, **_kw: subprocess.CompletedProcess(cmd, 0, b"1.25.0\n", b"")
                    if "--version" in cmd
                    else subprocess.CompletedProcess(cmd, 2, b"", b"rule syntax error"),
                    None,
                ),
                (
                    "timeout_no_fallback",
                    lambda step, cmd, **_kw: subprocess.CompletedProcess(cmd, 0, b"1.25.0\n", b"")
                    if "--version" in cmd
                    else (_ for _ in ()).throw(
                        intake._GitStepTimeout("opengrep-json", {"clean": True}, 0)
                    ),
                    "OPENGREP_TIMEOUT",
                ),
                (
                    "cleanup_failed_no_fallback",
                    lambda step, cmd, **_kw: subprocess.CompletedProcess(cmd, 0, b"1.25.0\n", b"")
                    if "--version" in cmd
                    else (_ for _ in ()).throw(
                        intake._GitStepCleanupFailed("opengrep-json", 0, {"clean": False})
                    ),
                    "OPENGREP_CLEANUP_FAILED",
                ),
            ):
                with self.subTest(no_fallback=case_name):
                    calls_nf: list[list[str]] = []

                    def _wrap(step, cmd, _fx=side_fx, _log=calls_nf, **kw):
                        _log.append(list(cmd))
                        return _fx(step, cmd, **kw)

                    with patch.object(intake, "_run_git_step", side_effect=_wrap):
                        with self.assertRaises(ScanError) as ctx_nf:
                            Bounded(native_cfg, root / f"cap_{case_name}").scan(src, DEFAULT_G1_RULES)
                    self.assertEqual(len(calls_nf), 2, f"{case_name} unexpectedly retried: {calls_nf}")
                    if expected_code is not None:
                        self.assertEqual(getattr(ctx_nf.exception, "error_code", None), expected_code)

            # 2e. Expired job deadline MUST fail with JOB_TIMEOUT before spawning any extra OpenGrep step
            calls_dl: list[list[str]] = []
            with patch.object(intake, "_run_git_step", side_effect=lambda s, c, **_k: calls_dl.append(list(c))):
                with self.assertRaises(ScanError) as ctx_dl:
                    Bounded(native_cfg, root / "cap_dl", deadline_mono=time.monotonic() - 1.0).scan(src, DEFAULT_G1_RULES)
            self.assertEqual(getattr(ctx_dl.exception, "error_code", None), "JOB_TIMEOUT")
            self.assertEqual(calls_dl, [], "Expired deadline must not spawn any OpenGrep command")

            # 3. Executable capability boundary matrix (positive verification invariant)
            cap_scanner = Bounded(native_cfg, root / "cap_matrix")

            # 3a. Fingerprinted wrapper with bridge_script (found=True, wsl=False) -> NOT native
            w_dir = root / "w_bridge"
            w_dir.mkdir()
            (w_dir / "helper.py").write_text("print('wrapper')\n", encoding="utf-8")
            w_cmd = w_dir / "opengrep.cmd"
            w_cmd.write_text(f'@echo off\r\n"{sys.executable}" "{w_dir / "helper.py"}" %*\r\n', encoding="utf-8")
            w_ident = opengrep_runner.inspect_opengrep_binary_identity(str(w_cmd))
            self.assertTrue(w_ident["found"] and w_ident["wrapper_targets"] and not w_ident["wsl_target"]["detected"])
            self.assertEqual(
                cap_scanner._evaluate_single_pass_capability(str(w_cmd)),
                (False, "WRAPPER_SINGLE_PASS_CAPABILITY_NOT_VERIFIED"),
            )

            # 3b. Standalone script wrappers with 0 targets/interpreters (.cmd, .ps1, .sh, .py, extensionless #!) -> NOT native
            inline_cmd = root / "opengrep_inline.cmd"
            inline_cmd.write_text("@echo off\r\necho 1.25.0\r\n", encoding="utf-8")
            inline_ps1 = root / "opengrep_inline.ps1"
            inline_ps1.write_text("Write-Output '1.25.0'\n", encoding="utf-8")
            inline_sh = root / "opengrep_inline.sh"
            inline_sh.write_text("#!/bin/sh\necho 1.25.0\n", encoding="utf-8")
            inline_py = root / "opengrep_inline.py"
            inline_py.write_text("print('1.25.0')\n", encoding="utf-8")
            extless_sh = root / "opengrep"
            extless_sh.write_text("#!/bin/sh\necho 1.25.0\n", encoding="utf-8")

            # 3c. Fake text .exe, DLL .exe, distlib/pip shim .exe (PE + #!/ZIP overlay), PyInstaller .exe -> NOT native
            fake_text_exe = root / "opengrep_text.exe"
            fake_text_exe.write_text("not a PE binary at all" * 8, encoding="utf-8")
            dll_exe = _write_minimal_native_executable(root / "opengrep_dll.exe", is_dll=True)
            pip_shim_exe = _write_minimal_native_executable(
                root / "opengrep_shim.exe", overlay=b"#!C:\\Python313\\python.exe\r\nPK\x03\x04dummy"
            )
            pyinst_exe = _write_minimal_native_executable(
                root / "opengrep_pyinst.exe", overlay=b"\x00" * 32 + b"MEI\x0c\x0b\x0a\x0b\x0e" + b"\x00" * 16
            )

            # 3d. Unknown / unresolved executable chain -> NOT native
            missing_bin = root / "opengrep_missing.exe"
            broken_wrap = root / "opengrep_broken.cmd"
            broken_wrap.write_text("@echo off\r\npython.exe nonexistent_target.py %*\r\n", encoding="utf-8")

            for label, cand in (
                ("inline_cmd", inline_cmd),
                ("inline_ps1", inline_ps1),
                ("inline_sh", inline_sh),
                ("inline_py", inline_py),
                ("extless_shebang", extless_sh),
                ("fake_text_exe", fake_text_exe),
                ("dll_exe", dll_exe),
                ("pip_launcher_shim_exe", pip_shim_exe),
                ("pyinstaller_bundle_exe", pyinst_exe),
                ("missing_binary", missing_bin),
                ("broken_wrapper", broken_wrap),
                ("invalid_name", root / "not_an_engine.exe"),
            ):
                with self.subTest(capability_rejected=label):
                    self.assertEqual(
                        cap_scanner._evaluate_single_pass_capability(str(cand)),
                        (False, "WRAPPER_SINGLE_PASS_CAPABILITY_NOT_VERIFIED"),
                    )

            # 3e. WSL bridge: unverified default -> WSL_SINGLE_PASS_CAPABILITY_NOT_VERIFIED;
            # broken/ambiguous WSL bridge even with wsl_single_pass_verified=True -> still rejected;
            # complete verified WSL bridge with explicit wsl_single_pass_verified=True -> WSL_SINGLE_PASS_VERIFIED.
            self.assertEqual(
                cap_scanner._evaluate_single_pass_capability(str(wsl_cmd)),
                (False, "WSL_SINGLE_PASS_CAPABILITY_NOT_VERIFIED"),
            )
            wsl_verified_scanner = Bounded(native_cfg, root / "cap_wsl_v", wsl_single_pass_verified=True)
            self.assertEqual(
                wsl_verified_scanner._evaluate_single_pass_capability(str(wsl_cmd)),
                (True, "WSL_SINGLE_PASS_VERIFIED"),
            )
            amb_py = root / "amb_wsl.py"
            amb_py.write_text(
                "import os, subprocess\n"
                "p = ['wsl.exe', '-d', 'Ubuntu-IRIS', '--', '/usr/local/bin/opengrep']\n"
                "a = ['wsl.exe', '-d', 'Ubuntu-IRIS', '--', '/opt/opengrep']\n"
                "subprocess.run(a if os.environ.get('ALT') else p)\n",
                encoding="utf-8",
            )
            amb_cmd = root / ("opengrep_amb.cmd" if IS_WINDOWS else "opengrep_amb.sh")
            amb_cmd.write_text(
                f'@echo off\r\n"{sys.executable}" "{amb_py}" %*\r\n'
                if IS_WINDOWS
                else f'#!/bin/sh\n"{sys.executable}" "{amb_py}" "$@"\n',
                encoding="utf-8",
            )
            self.assertEqual(
                wsl_verified_scanner._evaluate_single_pass_capability(str(amb_cmd)),
                (False, "WSL_SINGLE_PASS_CAPABILITY_NOT_VERIFIED"),
            )

            # 3f. Eligible verified native binary (synthetic minimal native + real local opengrep when installed)
            self.assertEqual(
                cap_scanner._evaluate_single_pass_capability(str(native_bin)),
                (True, "NATIVE_SINGLE_PASS_ELIGIBLE"),
            )
            real_og = shutil.which("opengrep")
            if real_og:
                real_ident = opengrep_runner.inspect_opengrep_binary_identity(real_og)
                if real_ident["found"] and not real_ident["wrapper_targets"] and not real_ident["wsl_target"]["detected"]:
                    self.assertEqual(
                        cap_scanner._evaluate_single_pass_capability(real_og),
                        (True, "NATIVE_SINGLE_PASS_ELIGIBLE"),
                    )


if __name__ == "__main__":
    unittest.main()
