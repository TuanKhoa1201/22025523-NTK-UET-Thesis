"""Counterexample and invariant tests for unified Windows/POSIX subprocess lifecycle management.

Covers:
1. Codex CE-1: Root exits normally (0 or non-zero) while Windows Job still has live members and
   handle close / termination fails -> must NOT report clean or succeed; must retain pending and fail closed.
2. Codex CE-2: Resume fails, root has exited, but Job cleanup is unverified (query returns None,
   live member remains, or CloseHandle fails) -> must mark CLEANUP_FAILED and retain pending.
3. Codex CE-3: Deterministic two-worker barrier (no random sleeps) where Worker 1 publishes a
   pending uncleaned tree after Worker 2 passed initial check and assigned its suspended process ->
   Worker 2 must NOT resume its child and must fail closed with CLEANUP_PENDING.
4. Root exits early while child still runs (normal OS, no fault injection) -> child is terminated
   and verified EXITED before returning.
5. Timeout with grandchild holding stdout/stderr handles -> bounded wall-clock return and tree killed.
6. Job Object unavailable or assignment refused -> fail closed without executing target code.
7. Output exceeding byte cap -> explicit OUTPUT_LIMIT_EXCEEDED error, never silent truncation.
8. Monotonic deadline across reconciliation -> N lingering entries bounded by one budget, not N * 2s.
9. Normal success and non-zero exit codes -> full capture/manifest/parity preserved.
"""
from __future__ import annotations

import inspect
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from v2.api import intake, opengrep_runner
from v2.api.config import IntakeLimits
from v2.api.intake import IntakeError, clone_github_repo
from v2.api.jobs import _load_baseline_scanner
from v2.api.opengrep_runner import make_bounded_scanner_class
from v2.api.tests.test_github_intake_timeout import _Proc
from v2.g1_integration.bridge import DEFAULT_G1_RULES

IS_WINDOWS = os.name == "nt"
URL = "https://github.com/spring-guides/gs-rest-service"
SAMPLE_JAVA = "package demo;\npublic class Demo {\n    public int ok() { return 7; }\n}\n"

FAKE_TOOL = r'''
import json, os, subprocess, sys, time
from pathlib import Path

args = sys.argv[1:]
mode = os.environ.get("NTK_LC_MODE", "normal")
pid_file = os.environ.get("NTK_LC_PIDFILE", "")
hold = float(os.environ.get("NTK_LC_HOLD", "25"))
exit_code = int(os.environ.get("NTK_LC_EXIT", "0"))
flood_bytes = int(os.environ.get("NTK_LC_FLOOD_BYTES", "0"))
flood_stream = os.environ.get("NTK_LC_FLOOD_STREAM", "stdout")

def record(*pids):
    if pid_file:
        with open(pid_file, "a", encoding="utf-8") as fh:
            fh.write(" ".join(str(p) for p in pids) + "\n")

def await_ack(*pids):
    # Handshake: wait (bounded) until the test watcher has opened a handle for every pid.
    ack_dir = os.environ.get("NTK_LC_ACK_DIR", "")
    if not ack_dir:
        return
    end = time.monotonic() + 10
    while time.monotonic() < end and not all(os.path.exists(os.path.join(ack_dir, f"ack_{p}")) for p in pids):
        time.sleep(0.01)

is_git = any(x in args for x in ("clone", "checkout", "rev-parse"))
if is_git:
    step = "clone" if "clone" in args else ("checkout" if "checkout" in args else "rev-parse")
else:
    step = "version" if "--version" in args else ("json" if "--json" in args else ("sarif" if "--sarif" in args else "other"))

target_step = os.environ.get("NTK_LC_TARGET_STEP", step)

if step == target_step and mode == "hang_with_grandchild":
    gc = subprocess.Popen([sys.executable, "-c", f"import time; time.sleep({hold})"])
    record(os.getpid(), gc.pid)
    sys.stderr.write("stalled with grandchild holding output\n")
    sys.stderr.flush()
    time.sleep(hold)
    sys.exit(0)

if step == target_step and mode == "exit_early_with_live_child":
    gc = subprocess.Popen([sys.executable, "-c", f"import time; time.sleep({hold})"])
    record(os.getpid(), gc.pid)
    await_ack(os.getpid(), gc.pid)
    if is_git and step == "clone":
        dest = Path(args[-1])
        (dest / ".git").mkdir(parents=True, exist_ok=True)
        (dest / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
        (dest / "src").mkdir(exist_ok=True)
        (dest / "src" / "Demo.java").write_text("public class Demo {}\n", encoding="utf-8")
    elif step == "version":
        sys.stdout.write("1.25.0\n")
        sys.stdout.flush()
    sys.exit(exit_code)

if step == target_step and mode == "flood_output":
    record(os.getpid())
    target = sys.stdout.buffer if flood_stream == "stdout" else sys.stderr.buffer
    target.write(b"A" * flood_bytes + b"\n")
    target.flush()
    if is_git and step == "clone":
        dest = Path(args[-1])
        (dest / ".git").mkdir(parents=True, exist_ok=True)
        (dest / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
        (dest / "src").mkdir(exist_ok=True)
        (dest / "src" / "Demo.java").write_text("public class Demo {}\n", encoding="utf-8")
    sys.exit(exit_code)

record(os.getpid())
if is_git:
    if step == "clone":
        if exit_code != 0:
            sys.stderr.write("fatal: repository not found\n")
            sys.exit(exit_code)
        dest = Path(args[-1])
        (dest / ".git").mkdir(parents=True, exist_ok=True)
        (dest / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
        (dest / "src").mkdir(exist_ok=True)
        (dest / "src" / "Demo.java").write_text("public class Demo {}\n", encoding="utf-8")
        sys.exit(0)
    if step == "checkout":
        sys.exit(exit_code)
    if step == "rev-parse":
        sys.stdout.write("c" * 40 + "\n")
        sys.exit(0)
else:
    if exit_code != 0 and step == target_step:
        sys.stderr.write(f"step {step} failed with {exit_code}\n")
        sys.exit(exit_code)
    if step == "version":
        print("1.25.0")
        sys.exit(0)
    if step == "json":
        print(json.dumps({"results": [], "errors": [], "paths": {"scanned": []}, "version": "1.25.0"}))
        sys.exit(0)
    if step == "sarif":
        print(json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "opengrep", "rules": []}}, "results": []}]}))
        sys.exit(0)
sys.exit(2)
'''




class _HookLock:
    """Lock wrapper: when `armed` for the hook thread, the release signals `released` and waits for
    `proceed` before returning, exposing the instant right after the lock is released."""

    def __init__(self, real):
        self._real = real
        self.hook_thread = None
        self.armed = False
        self.released = threading.Event()
        self.proceed = threading.Event()

    def __enter__(self):
        self._real.acquire()
        return self

    def __exit__(self, *exc):
        self._real.release()
        if self.armed and threading.current_thread() is self.hook_thread:
            self.armed = False
            self.released.set()
            assert self.proceed.wait(timeout=15), "hook lock barrier timed out"
        return False


class _Kernel32Proxy:
    """ctypes.WinDLL('kernel32') proxy: SetInformationJobObject fails, and CloseHandle fails for the Job
    handle created through this proxy while `fail_close` is set."""

    def __init__(self, real, state):
        self._real = real
        self._state = state

    def __getattr__(self, name):
        fn = getattr(self._real, name)
        state = self._state

        class _Fn:
            restype = None
            argtypes = None

            def __call__(self_inner, *args):
                if self_inner.restype is not None:
                    fn.restype = self_inner.restype
                if self_inner.argtypes is not None:
                    fn.argtypes = self_inner.argtypes
                if name == "SetInformationJobObject":
                    return 0
                if name == "CloseHandle" and state["fail_close"] and args:
                    if int(getattr(args[0], "value", args[0]) or 0) in state["jobs"]:
                        return 0
                res = fn(*args)
                if name == "CreateJobObjectW" and res:
                    state["jobs"].add(int(res))
                return res

        return _Fn()


class _FaultyRegistry(list):
    """Registry list whose append() raises MemoryError while armed (fault injection)."""

    armed = False

    def append(self, item):
        if self.armed:
            raise MemoryError("injected registry append failure")
        super().append(item)


@unittest.skipUnless(IS_WINDOWS, "Windows Job Object / suspended-process lifecycle")
class UnifiedProcessLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ntk-lc-inv-")
        self.root = Path(self.tmp.name)
        script = self.root / "fake_tool.py"
        script.write_text(FAKE_TOOL, encoding="utf-8")
        self.fake_og = self.root / "opengrep.cmd"
        self.fake_og.write_text(f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n', encoding="utf-8")
        self.fake_git = self.root / "git.cmd"
        self.fake_git.write_text(f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n', encoding="utf-8")

        self.pid_file = self.root / "pids.txt"
        self.src = self.root / "src"
        self.src.mkdir()
        (self.src / "Demo.java").write_text(SAMPLE_JAVA, encoding="utf-8")

        self.env_patch = patch.dict(os.environ, {
            "NTK_LC_MODE": "normal",
            "NTK_LC_PIDFILE": str(self.pid_file),
            "NTK_LC_HOLD": "25",
            "NTK_LC_EXIT": "0",
            "NTK_LC_FLOOD_BYTES": "0",
            "NTK_LC_FLOOD_STREAM": "stdout",
            "NTK_LC_ACK_DIR": str(self.root),
        })
        self.env_patch.start()
        real_which = shutil.which
        self.which_patch = patch(
            "v2.api.intake.shutil.which",
            side_effect=lambda name, *a, **k: str(self.fake_git) if name == "git" else real_which(name, *a, **k),
        )
        self.which_patch.start()

        # Track jobs and Popen instances created during test so pre-fix leaks are safely cleaned in tearDown.
        self._created_jobs: list[int] = []
        real_create_job = intake._win_create_kill_on_close_job

        def tracked_create_job(*a, **k):
            j = real_create_job(*a, **k)
            if j:
                self._created_jobs.append(int(j))
            return j

        self.job_create_patch = patch.object(intake, "_win_create_kill_on_close_job", side_effect=tracked_create_job)
        self.job_create_patch.start()

        self._created_popens: list = []
        orig_popen_init = intake.subprocess.Popen.__init__

        def tracked_popen_init(p, *a, **k):
            orig_popen_init(p, *a, **k)
            self._created_popens.append(p)

        self.popen_patch = patch.object(intake.subprocess.Popen, "__init__", tracked_popen_init)
        self.popen_patch.start()

        self._watch_lock = threading.Lock()
        self.procs: dict[int, _Proc] = {}
        self.child_pids: set[int] = set()
        self._stop = threading.Event()
        self._watcher = threading.Thread(target=self._watch, daemon=True)
        self._watcher.start()

    def _watch(self):
        while not self._stop.is_set():
            self._absorb()
            time.sleep(0.01)

    def _absorb(self, path: Path | None = None):
        pf = path or self.pid_file
        with self._watch_lock:
            if not pf.is_file():
                return
            try:
                text = pf.read_text(encoding="utf-8")
            except OSError:
                return
            for line in text.splitlines():
                toks = [int(t) for t in line.split()]
                for i, pid in enumerate(toks):
                    if pid not in self.procs:
                        proc = _Proc(pid)
                        self.procs[pid] = proc
                        if proc.handle is not None:
                            (self.root / f"ack_{pid}").write_text("1", encoding="utf-8")
                    if len(toks) == 2 and i == 1:
                        self.child_pids.add(pid)

    def _reset_observed_pids(self) -> None:
        with self._watch_lock:
            for p in self.procs.values():
                p.close()
            self.procs.clear()
            self.child_pids.clear()
            if self.pid_file.exists():
                self.pid_file.unlink()
            for ack_f in self.root.glob("ack_*"):
                try:
                    ack_f.unlink()
                except OSError:
                    pass

    def tearDown(self):
        self._stop.set()
        self._watcher.join(timeout=2)
        try:
            intake._reconcile_lingering_git_jobs()
        except Exception:
            pass
        # Only release handles still owned by a pending entry (never blind-close handle values that the
        # product may already have closed: a reused value could belong to another live handle).
        from ctypes import wintypes
        with intake._LINGERING_LOCK:
            for entry in list(intake._LINGERING_GIT_TREES):
                if entry.get("kind") == "job" and entry.get("job") and not entry.get("job_closed"):
                    try:
                        intake._win_job_call("TerminateJobObject", wintypes.HANDLE(entry["job"]), 1)
                        if intake._win_job_call("CloseHandle", wintypes.HANDLE(entry["job"])):
                            entry["job_closed"] = True
                    except Exception:
                        pass
            intake._LINGERING_GIT_TREES.clear()
        if hasattr(intake, "_REGISTRY_FAULT"):
            intake._REGISTRY_FAULT = False
        for p in self.procs.values():
            p.terminate_if_owned()
            p.close()
        self.popen_patch.stop()
        self.job_create_patch.stop()
        for popen in self._created_popens:
            try:
                if popen.poll() is None:
                    popen.kill()
                    popen.wait(timeout=3)
            except Exception:
                pass
        self.which_patch.stop()
        self.env_patch.stop()
        self.tmp.cleanup()

    def _make_scanner(self, out_name: str = "capture", timeout: int = 1):
        OpenGrepConfig, SemgrepScanner, ScanError = _load_baseline_scanner()
        cls = make_bounded_scanner_class(SemgrepScanner, ScanError)
        out_dir = self.root / out_name
        out_dir.mkdir(parents=True, exist_ok=True)
        cfg = OpenGrepConfig(executable=str(self.fake_og), rules=DEFAULT_G1_RULES, timeout=timeout, jobs=1)
        return cls(cfg, out_dir), ScanError

    def _assert_all_exited(self, expected: int = 2, settle: float = 2.0, require_child: bool = True):
        """Every recorded PID must be handle-observed and EXITED; UNKNOWN is never accepted.
        When the fixture records a "root child" pair, that specific child must be among them."""
        end = time.monotonic() + 3.0
        while time.monotonic() < end and len(self.procs) < expected:
            self._absorb()
            time.sleep(0.02)
        self.assertGreaterEqual(len(self.procs), expected, "expected PIDs were not recorded")
        if require_child:
            self.assertTrue(self.child_pids, "fixture child PID was not identified")
        end = time.monotonic() + settle
        while time.monotonic() < end and any(p.state() == _Proc.ALIVE for p in self.procs.values()):
            time.sleep(0.05)
        for pid in self.child_pids:
            self.assertIsNotNone(self.procs[pid].handle, f"child PID {pid} was not observed (insufficient evidence)")
        for pid, p in self.procs.items():
            self.assertEqual(p.state(), _Proc.EXITED, f"PID {pid} state={p.state()} (expected EXITED)")

    # --- 1. Codex Counterexample 1 -------------------------------------------------------------

    def test_codex_ce1_root_exits_zero_with_live_job_member_and_close_handle_fails(self):
        """CE-1: Root exits 0, child remains in Job, CloseHandle (and/or TerminateJobObject) fails."""
        os.environ["NTK_LC_MODE"] = "exit_early_with_live_child"
        os.environ["NTK_LC_TARGET_STEP"] = "version"
        real_call = intake._win_job_call

        # Subcase A: Only CloseHandle fails (exact scenario on 95f2726 where normal exit relied solely on CloseHandle).
        def fail_close_only(name, *args):
            if name == "CloseHandle":
                return 0
            return real_call(name, *args)

        scanner, ScanError = self._make_scanner("ce1_close_only")
        with patch.object(type(scanner), "_process_timeout", lambda _s: 2.0), \
             patch.object(intake, "_win_job_call", side_effect=fail_close_only):
            with self.assertRaises(ScanError, msg="CE-1a: CloseHandle failure on exit must fail closed") as ctx:
                scanner.verify_semgrep_installation()
            exc = ctx.exception
            self.assertEqual(getattr(exc, "error_code", None), "OPENGREP_CLEANUP_FAILED")
            self.assertEqual(exc.details.get("cleanup_status"), "CLEANUP_FAILED")
            self.assertFalse(exc.details["process_cleanup"]["clean"])
            self.assertGreaterEqual(len(intake._LINGERING_GIT_TREES), 1)

            # Subsequent OpenGrep run must be blocked while cleanup is unverified.
            scanner2, _ = self._make_scanner("ce1_blocked")
            with self.assertRaises(ScanError) as ctx2:
                scanner2.verify_semgrep_installation()
            self.assertEqual(getattr(ctx2.exception, "error_code", None), "OPENGREP_CLEANUP_PENDING")

        # Fault lifted -> reconciliation closes handle and unblocks.
        self.assertEqual(intake._reconcile_lingering_git_jobs(), 0)
        self._assert_all_exited(expected=2)

    def test_codex_ce1_git_root_exits_with_live_member_and_terminate_plus_close_fail(self):
        """CE-1 on Git path: root clone exits 0 with live child in Job while TerminateJobObject & CloseHandle fail."""
        os.environ["NTK_LC_MODE"] = "exit_early_with_live_child"
        os.environ["NTK_LC_TARGET_STEP"] = "clone"
        real_call = intake._win_job_call

        def fail_term_and_close(name, *args):
            if name in ("TerminateJobObject", "CloseHandle"):
                return 0
            return real_call(name, *args)

        dest = self.root / "ws" / "clone1"
        dest.parent.mkdir(parents=True, exist_ok=True)
        with patch.object(intake, "_win_job_call", side_effect=fail_term_and_close):
            with self.assertRaises(IntakeError, msg="CE-1b: live Job member on normal exit must fail closed") as ctx:
                clone_github_repo(URL, None, dest, IntakeLimits(), timeout_seconds=3)
            self.assertEqual(ctx.exception.error_code, "GITHUB_GIT_CLEANUP_FAILED")
            self.assertEqual(ctx.exception.details.get("cleanup_status"), "CLEANUP_FAILED")
            self.assertFalse(ctx.exception.details["process_cleanup"]["clean"])
            self.assertFalse(dest.exists())

            dest2 = self.root / "ws" / "clone2"
            with self.assertRaises(IntakeError) as ctx2:
                clone_github_repo(URL, None, dest2, IntakeLimits(), timeout_seconds=3)
            self.assertEqual(ctx2.exception.error_code, "GITHUB_GIT_CLEANUP_PENDING")

        self.assertEqual(intake._reconcile_lingering_git_jobs(), 0)
        self._assert_all_exited(expected=2)

    # --- 2. Codex Counterexample 2 -------------------------------------------------------------

    def test_codex_ce2_resume_fails_root_exited_but_job_cleanup_unverified(self):
        """CE-2: _win_resume_suspended_process fails and root exits, yet Job state is unverified or non-empty."""
        for sub, active_val, close_ok in (
            ("query_none", None, True),
            ("active_remaining", 1, True),
            ("close_failed", 0, False),
        ):
            with self.subTest(case=sub):
                intake._LINGERING_GIT_TREES.clear()
                real_call = intake._win_job_call

                def patched_job_call(name, *args):
                    if name == "TerminateJobObject" and active_val == 1:
                        return 0
                    if name == "CloseHandle" and not close_ok:
                        return 0
                    return real_call(name, *args)

                scanner, ScanError = self._make_scanner(f"ce2_{sub}")
                with patch.object(intake, "_win_resume_suspended_process", return_value=False), \
                     patch.object(intake, "_win_job_active_processes", return_value=active_val), \
                     patch.object(intake, "_win_job_call", side_effect=patched_job_call):
                    with self.assertRaises(ScanError) as ctx:
                        scanner.verify_semgrep_installation()
                    exc = ctx.exception
                    self.assertEqual(getattr(exc, "error_code", None), "OPENGREP_PROCESS_ISOLATION_FAILED")
                    self.assertEqual(exc.details.get("reason"), "RESUME_FAILED")
                    self.assertTrue(exc.details.get("root_exited"))
                    self.assertEqual(
                        exc.details.get("cleanup_status"), "CLEANUP_FAILED",
                        f"CE-2 ({sub}): root exited must NOT mask unverified Job cleanup: {exc.details}",
                    )
                    self.assertFalse(exc.details["process_cleanup"]["clean"])
                    self.assertEqual(len(intake._LINGERING_GIT_TREES), 1)

                    # Next launch must be blocked while pending entry remains.
                    scanner_next, _ = self._make_scanner(f"ce2_{sub}_next")
                    with self.assertRaises(ScanError) as ctx_next:
                        scanner_next.verify_semgrep_installation()
                    self.assertEqual(getattr(ctx_next.exception, "error_code", None), "OPENGREP_CLEANUP_PENDING")

                # Once faults are lifted, reconciliation cleans up and clears pending.
                self.assertEqual(intake._reconcile_lingering_git_jobs(), 0)

    # --- 3. Codex Counterexample 3 (deterministic barrier, zero random sleeps) -----------------

    def test_codex_ce3_concurrent_workers_pending_published_between_check_and_resume(self):
        """CE-3: W2 passes initial pending check & assigns Job, pauses at barrier; W1 fails cleanup and
        publishes pending; W2 resumes from barrier and MUST NOT resume its child process."""
        w1_pids = self.root / "w1_pids.txt"
        w2_pids = self.root / "w2_pids.txt"
        w2_script = self.root / "fake_w2.py"
        w2_script.write_text(
            f'from pathlib import Path\nPath({str(w2_pids)!r}).write_text("RAN\\n", encoding="utf-8")\nprint("1.25.0")\n',
            encoding="utf-8",
        )
        fake_og_w2 = self.root / "opengrep_w2.cmd"
        fake_og_w2.write_text(f'@echo off\r\n"{sys.executable}" "{w2_script}" %*\r\n', encoding="utf-8")

        evt_w2_assigned = threading.Event()
        evt_w1_pending_ready = threading.Event()
        w1_job_box: list[int] = []
        tls = threading.local()
        real_create = intake._win_create_kill_on_close_job
        real_call = intake._win_job_call

        def create_job_tagged(*a, **k):
            j = real_create(*a, **k)
            if getattr(tls, "worker", None) == "W1" and j:
                w1_job_box.append(int(j))
            return j

        def job_call_barrier(name, *args):
            worker = getattr(tls, "worker", None)
            if worker == "W1" and name == "TerminateJobObject":
                return 0  # Force W1 cleanup to fail and publish a pending entry.
            res = real_call(name, *args)
            if worker == "W2" and name == "AssignProcessToJobObject":
                evt_w2_assigned.set()
                assert evt_w1_pending_ready.wait(timeout=15), "barrier timed out waiting for W1 pending state"
            return res

        OpenGrepConfig, SemgrepScanner, ScanError = _load_baseline_scanner()
        cls = make_bounded_scanner_class(SemgrepScanner, ScanError)
        out1 = self.root / "w1_out"
        out1.mkdir()
        out2 = self.root / "w2_out"
        out2.mkdir()
        s1 = cls(OpenGrepConfig(executable=str(self.fake_og), rules=DEFAULT_G1_RULES, timeout=1, jobs=1), out1)
        s2 = cls(OpenGrepConfig(executable=str(fake_og_w2), rules=DEFAULT_G1_RULES, timeout=1, jobs=1), out2)

        results: dict[str, BaseException | str] = {}

        def run_w1():
            tls.worker = "W1"
            assert evt_w2_assigned.wait(timeout=15), "barrier timed out waiting for W2 assignment"
            try:
                with patch.object(type(s1), "_process_timeout", lambda _s: 0.4):
                    s1.verify_semgrep_installation()
                results["W1"] = "UNEXPECTED_OK"
            except BaseException as exc:
                results["W1"] = exc
            finally:
                evt_w1_pending_ready.set()

        def run_w2():
            tls.worker = "W2"
            try:
                with patch.object(type(s2), "_process_timeout", lambda _s: 5.0):
                    results["W2"] = s2.verify_semgrep_installation()
            except BaseException as exc:
                results["W2"] = exc

        os.environ["NTK_LC_MODE"] = "hang_with_grandchild"
        os.environ["NTK_LC_TARGET_STEP"] = "version"
        os.environ["NTK_LC_PIDFILE"] = str(w1_pids)

        with patch.object(intake, "_win_create_kill_on_close_job", side_effect=create_job_tagged), \
             patch.object(intake, "_win_job_call", side_effect=job_call_barrier):
            t2 = threading.Thread(target=run_w2)
            t1 = threading.Thread(target=run_w1)
            t2.start()
            t1.start()
            t1.join(timeout=20)
            t2.join(timeout=20)
            self.assertFalse(t1.is_alive(), "W1 deadlocked")
            self.assertFalse(t2.is_alive(), "W2 deadlocked")

        self._absorb(w1_pids)
        self.assertIsInstance(results.get("W1"), ScanError)
        self.assertEqual(getattr(results["W1"], "error_code", None), "OPENGREP_TIMEOUT")
        self.assertEqual(results["W1"].details.get("cleanup_status"), "CLEANUP_FAILED")

        self.assertIsInstance(
            results.get("W2"), ScanError,
            f"CE-3: W2 resumed and returned {results.get('W2')!r} despite W1 publishing pending state!",
        )
        self.assertEqual(getattr(results["W2"], "error_code", None), "OPENGREP_CLEANUP_PENDING")
        self.assertFalse(w2_pids.exists(), "CE-3: W2 child process must NEVER execute any instruction")

        self.assertEqual(intake._reconcile_lingering_git_jobs(), 0)
        self._assert_all_exited(expected=2)

    # --- 4. Root exits early while child still runs (real OS, no fault injection) --------------

    def test_root_exits_early_with_live_child_terminates_child_before_return(self):
        for code in (0, 4):
            with self.subTest(exit_code=code):
                self._reset_observed_pids()
                os.environ["NTK_LC_MODE"] = "exit_early_with_live_child"
                os.environ["NTK_LC_TARGET_STEP"] = "version"
                os.environ["NTK_LC_EXIT"] = str(code)
                scanner, ScanError = self._make_scanner(f"early_exit_{code}")
                if code == 0:
                    ver = scanner.verify_semgrep_installation()
                    self.assertEqual(ver, "1.25.0")
                else:
                    with self.assertRaises(ScanError) as ctx:
                        scanner.verify_semgrep_installation()
                    self.assertIn("version exited 4", str(ctx.exception))
                # Root and its live child must both be observed and EXITED once _run returned.
                self._assert_all_exited(expected=2)

    # --- 5 & 6. Grandchild output-hold timeout & Job isolation failures ------------------------

    def test_grandchild_holding_output_times_out_within_monotonic_bound(self):
        os.environ["NTK_LC_MODE"] = "hang_with_grandchild"
        os.environ["NTK_LC_TARGET_STEP"] = "version"
        scanner, ScanError = self._make_scanner("hang_gc")
        t0 = time.monotonic()
        with patch.object(type(scanner), "_process_timeout", lambda _s: 1.0):
            with self.assertRaises(ScanError) as ctx:
                scanner.verify_semgrep_installation()
        elapsed = time.monotonic() - t0
        self.assertLess(elapsed, 6.0, f"took {elapsed:.2f}s despite 1.0s timeout + bounded cleanup")
        self.assertEqual(getattr(ctx.exception, "error_code", None), "OPENGREP_TIMEOUT")
        self.assertTrue(ctx.exception.details["process_cleanup"]["clean"])
        self._assert_all_exited(expected=2)

    def test_job_assign_refused_with_close_handle_failure_keeps_pending(self):
        real_call = intake._win_job_call

        def refuse_and_fail_close(name, *args):
            if name in ("AssignProcessToJobObject", "CloseHandle"):
                return 0
            return real_call(name, *args)

        scanner, ScanError = self._make_scanner("assign_close_fail")
        with patch.object(intake, "_win_job_call", side_effect=refuse_and_fail_close):
            with self.assertRaises(ScanError) as ctx:
                scanner.verify_semgrep_installation()
            self.assertEqual(getattr(ctx.exception, "error_code", None), "OPENGREP_PROCESS_ISOLATION_FAILED")
            self.assertEqual(ctx.exception.details.get("cleanup_status"), "CLEANUP_FAILED")
            self.assertEqual(len(intake._LINGERING_GIT_TREES), 1)
        self.assertEqual(intake._reconcile_lingering_git_jobs(), 0)

    # --- 7. Output exceeding byte limit fails closed without truncation ------------------------

    def test_output_exceeding_byte_limit_fails_closed_for_opengrep_and_git(self):
        os.environ["NTK_LC_MODE"] = "flood_output"
        os.environ["NTK_LC_FLOOD_BYTES"] = "8192"

        # OpenGrep stdout flood
        os.environ["NTK_LC_TARGET_STEP"] = "json"
        os.environ["NTK_LC_FLOOD_STREAM"] = "stdout"
        scanner, ScanError = self._make_scanner("flood_og", timeout=5)
        # Clear output dir created by helper so scan() sees empty directory
        shutil.rmtree(scanner.output_dir)
        with patch.object(opengrep_runner, "MAX_OPENGREP_OUTPUT_BYTES", 4096, create=True), \
             patch.object(intake, "MAX_SUBPROCESS_OUTPUT_BYTES", 4096, create=True):
            with self.assertRaises(ScanError, msg="Oversized OpenGrep stdout must fail closed") as ctx:
                scanner.scan(self.src, None)
            self.assertEqual(getattr(ctx.exception, "error_code", None), "OPENGREP_OUTPUT_LIMIT_EXCEEDED")
            self.assertEqual(ctx.exception.details.get("output_stream"), "stdout")
            self.assertFalse((scanner.output_dir / "opengrep.json").exists(), "truncated JSON must not be written")
            manifest = json.loads((scanner.output_dir / "scan-manifest.json").read_text(encoding="utf-8"))
            self.assertFalse(manifest["success"])

        # Git stderr flood
        os.environ["NTK_LC_TARGET_STEP"] = "clone"
        os.environ["NTK_LC_FLOOD_STREAM"] = "stderr"
        dest = self.root / "ws" / "flood_git"
        dest.parent.mkdir(parents=True, exist_ok=True)
        with patch.object(intake, "MAX_GIT_OUTPUT_BYTES", 4096, create=True), \
             patch.object(intake, "MAX_SUBPROCESS_OUTPUT_BYTES", 4096, create=True):
            with self.assertRaises(IntakeError, msg="Oversized Git stderr must fail closed") as gctx:
                clone_github_repo(URL, None, dest, IntakeLimits(), timeout_seconds=5)
            self.assertEqual(gctx.exception.error_code, "GITHUB_OUTPUT_LIMIT_EXCEEDED")
            self.assertFalse(dest.exists())

    # --- 8. Single monotonic deadline across reconciliation ------------------------------------

    def test_reconcile_uses_single_monotonic_deadline_across_multiple_entries(self):
        fake_entries = [
            {"kind": "job", "job": 0, "proc": None, "assigned": True, "job_closed": False, "lock": threading.Lock()}
            for _ in range(3)
        ]
        intake._LINGERING_GIT_TREES[:] = list(fake_entries)
        try:
            with patch.object(intake, "_win_job_active_processes", return_value=1), \
                 patch.object(intake, "_win_job_call", return_value=0):
                t0 = time.monotonic()
                sig = inspect.signature(intake._reconcile_lingering_git_jobs)
                if "budget_seconds" in sig.parameters:
                    rem = intake._reconcile_lingering_git_jobs(budget_seconds=0.6)
                    limit = 1.6
                else:
                    rem = intake._reconcile_lingering_git_jobs()
                    limit = 2.6  # Single 2.0s budget; 95f2726 slept 3 * 2.0s = 6.0s!
                elapsed = time.monotonic() - t0
            self.assertEqual(rem, 3)
            self.assertLess(elapsed, limit, f"reconcile multiplied waits across entries: {elapsed:.2f}s")
        finally:
            intake._LINGERING_GIT_TREES.clear()

    # --- 9. Normal success & non-zero exit preserved -------------------------------------------

    def test_normal_scan_success_and_nonzero_exit_preserved(self):
        os.environ["NTK_LC_MODE"] = "normal"
        os.environ["NTK_LC_EXIT"] = "0"
        scanner, ScanError = self._make_scanner("normal_ok", timeout=5)
        shutil.rmtree(scanner.output_dir)
        res = scanner.scan(self.src, None)
        self.assertEqual(res["engine_version"], "1.25.0")
        manifest = json.loads((scanner.output_dir / "scan-manifest.json").read_text(encoding="utf-8"))
        self.assertTrue(manifest["success"])

        os.environ["NTK_LC_EXIT"] = "2"
        os.environ["NTK_LC_TARGET_STEP"] = "json"
        scanner_nz, _ = self._make_scanner("normal_nz", timeout=5)
        shutil.rmtree(scanner_nz.output_dir)
        with self.assertRaises(ScanError) as ctx:
            scanner_nz.scan(self.src, None)
        self.assertIn("json exited 2", str(ctx.exception))
        self.assertEqual((scanner_nz.output_dir / "json.exit.txt").read_text(encoding="utf-8"), "2")
        manifest_nz = json.loads((scanner_nz.output_dir / "scan-manifest.json").read_text(encoding="utf-8"))
        self.assertFalse(manifest_nz["success"])

    # --- Audit round 3: exception paths must keep ownership (P1) ------------------------------

    def _blocked_next_then_reconcile(self):
        scanner_next, ScanError = self._make_scanner("next_after_fault")
        with self.assertRaises(ScanError) as ctx:
            scanner_next.verify_semgrep_installation()
        self.assertEqual(getattr(ctx.exception, "error_code", None), "OPENGREP_CLEANUP_PENDING")

    def test_exception_in_resume_finalizes_suspended_root(self):
        os.environ["NTK_LC_MODE"] = "normal"
        scanner, ScanError = self._make_scanner("resume_raises")
        with patch.object(intake, "_win_resume_suspended_process", side_effect=RuntimeError("injected")):
            with self.assertRaises(ScanError) as ctx:
                scanner.verify_semgrep_installation()
        exc = ctx.exception
        self.assertEqual(getattr(exc, "error_code", None), "OPENGREP_PROCESS_ERROR")
        self.assertEqual(exc.details.get("primary_error"), "RuntimeError")
        self.assertTrue(exc.details["process_cleanup"]["clean"], exc.details)
        self.assertEqual(intake._LINGERING_GIT_TREES, [])
        time.sleep(0.3)
        self._absorb()
        self.assertEqual(self.procs, {}, "suspended root must never execute code")

    def test_exception_in_poll_finalizes_running_tree(self):
        os.environ["NTK_LC_MODE"] = "hang_with_grandchild"
        os.environ["NTK_LC_TARGET_STEP"] = "version"
        scanner, ScanError = self._make_scanner("poll_raises")
        real_poll = intake.subprocess.Popen.poll
        state = {"raised": False}

        def poll_once_raises(p):
            # Raise once, after the fake tool has recorded its PIDs and the background watcher
            # has opened the child process handle (prevents TerminateJobObject racing _watcher).
            cids = list(self.child_pids)
            if (
                not state["raised"]
                and cids
                and all(cid in self.procs and self.procs[cid].handle is not None for cid in cids)
            ):
                state["raised"] = True
                raise OSError("injected poll failure")
            return real_poll(p)

        with patch.object(intake.subprocess.Popen, "poll", poll_once_raises), \
             patch.object(type(scanner), "_process_timeout", lambda _s: 20.0):
            with self.assertRaises(ScanError) as ctx:
                scanner.verify_semgrep_installation()
        self.assertTrue(state["raised"])
        self.assertEqual(getattr(ctx.exception, "error_code", None), "OPENGREP_PROCESS_ERROR")
        self.assertEqual(ctx.exception.details.get("primary_error"), "OSError")
        self.assertTrue(ctx.exception.details["process_cleanup"]["clean"])
        self._assert_all_exited(expected=2)

    def test_tempfile_failure_after_job_allocation_closes_job(self):
        calls = []
        real_call = intake._win_job_call

        def record_call(name, *args):
            calls.append((name, int(args[0].value) if args and hasattr(args[0], "value") else None))
            return real_call(name, *args)

        real_tmp = intake.tempfile.TemporaryFile
        made = {"n": 0}

        def second_tmp_fails(*a, **k):
            made["n"] += 1
            if made["n"] == 2:
                raise OSError("injected tempfile failure")
            return real_tmp(*a, **k)

        scanner, ScanError = self._make_scanner("tmp_fails")
        with patch.object(intake, "_win_job_call", side_effect=record_call), \
             patch.object(intake.tempfile, "TemporaryFile", side_effect=second_tmp_fails):
            with self.assertRaises(ScanError):
                scanner.verify_semgrep_installation()
        job = self._created_jobs[-1]
        self.assertIn(("CloseHandle", job), calls, "Job allocated before tempfile failure was not closed")
        self.assertEqual(intake._LINGERING_GIT_TREES, [])

    def test_exception_inside_cleanup_keeps_pending_and_primary_error(self):
        os.environ["NTK_LC_MODE"] = "hang_with_grandchild"
        os.environ["NTK_LC_TARGET_STEP"] = "version"
        scanner, ScanError = self._make_scanner("cleanup_raises")
        with patch.object(intake, "_wait_tree_empty", side_effect=RuntimeError("injected cleanup failure")), \
             patch.object(type(scanner), "_process_timeout", lambda _s: 1.0):
            with self.assertRaises(ScanError) as ctx:
                scanner.verify_semgrep_installation()
            exc = ctx.exception
            self.assertEqual(getattr(exc, "error_code", None), "OPENGREP_TIMEOUT", "primary error must be kept")
            self.assertEqual(exc.details.get("cleanup_status"), "CLEANUP_FAILED")
            self.assertEqual(exc.details["process_cleanup"].get("cleanup_error"), "RuntimeError")
            self.assertFalse(exc.details["process_cleanup"]["clean"])
            self.assertEqual(len(intake._LINGERING_GIT_TREES), 1)
            self._blocked_next_then_reconcile()
        self.assertEqual(intake._reconcile_lingering_git_jobs(), 0)
        self._assert_all_exited(expected=2)

    # --- Audit round 3: output decisions after cleanup (P2) -----------------------------------

    def test_output_growing_during_cleanup_is_not_returned(self):
        os.environ["NTK_LC_MODE"] = "normal"
        scanner, ScanError = self._make_scanner("grow_in_cleanup")
        files = []
        real_tmp = intake.tempfile.TemporaryFile
        real_finalize = intake._finalize_tree

        def tracking_tmp(*a, **k):
            f = real_tmp(*a, **k)
            files.append(f)
            return f

        def finalize_with_late_output(entry, step, deadline):
            files[0].seek(0, os.SEEK_END)
            files[0].write(b"Z" * 5000)  # bytes that arrive after the last in-loop size check
            files[0].flush()
            return real_finalize(entry, step, deadline)

        with patch.object(opengrep_runner, "MAX_OPENGREP_OUTPUT_BYTES", 4096), \
             patch.object(intake.tempfile, "TemporaryFile", side_effect=tracking_tmp), \
             patch.object(intake, "_finalize_tree", side_effect=finalize_with_late_output):
            with self.assertRaises(ScanError) as ctx:
                scanner.verify_semgrep_installation()
        self.assertEqual(getattr(ctx.exception, "error_code", None), "OPENGREP_OUTPUT_LIMIT_EXCEEDED")
        self.assertFalse((scanner.output_dir / "version.stdout.txt").exists())

    def test_unknown_output_size_is_not_treated_as_within_limit(self):
        os.environ["NTK_LC_MODE"] = "normal"
        scanner, ScanError = self._make_scanner("size_unknown")
        with patch.object(intake, "_file_size", return_value=-1):
            with self.assertRaises(ScanError) as ctx:
                scanner.verify_semgrep_installation()
        self.assertEqual(getattr(ctx.exception, "error_code", None), "OPENGREP_OUTPUT_UNVERIFIED")
        self.assertFalse((scanner.output_dir / "version.stdout.txt").exists())

    def test_output_exactly_at_cap_passes_and_cap_plus_one_fails(self):
        os.environ["NTK_LC_MODE"] = "flood_output"
        os.environ["NTK_LC_TARGET_STEP"] = "version"
        os.environ["NTK_LC_FLOOD_STREAM"] = "stdout"
        # Fake writes N bytes + b"\n"; on Windows text mode is not used (buffer), so total = N + 1.
        os.environ["NTK_LC_FLOOD_BYTES"] = "4095"
        scanner, ScanError = self._make_scanner("cap_exact")
        with patch.object(opengrep_runner, "MAX_OPENGREP_OUTPUT_BYTES", 4096):
            ver = scanner.verify_semgrep_installation()
        self.assertEqual(len(ver), 4095)
        self.assertEqual((scanner.output_dir / "version.stdout.txt").stat().st_size, 4096)

        os.environ["NTK_LC_FLOOD_BYTES"] = "4096"
        scanner2, _ = self._make_scanner("cap_plus_one")
        with patch.object(opengrep_runner, "MAX_OPENGREP_OUTPUT_BYTES", 4096):
            with self.assertRaises(ScanError) as ctx:
                scanner2.verify_semgrep_installation()
        self.assertEqual(getattr(ctx.exception, "error_code", None), "OPENGREP_OUTPUT_LIMIT_EXCEEDED")
        self.assertEqual(ctx.exception.details.get("output_bytes"), 4097)

    # --- Audit round 4: ownership registered before OS resources (Codex P1/P2) ----------------

    def _arm_after_launch(self, reg):
        real_size = intake._file_size

        def size_and_arm(fh):
            if self.pid_file.is_file() and len(self.pid_file.read_text().split()) >= 2:
                reg.armed = True  # the process tree exists: later registry appends fail
            return real_size(fh)

        return patch.object(intake, "_file_size", side_effect=size_and_arm)

    def _cleanup_cannot_finish(self):
        real_call = intake._win_job_call

        def no_terminate(name, *args):
            if name == "TerminateJobObject":
                return 0
            return real_call(name, *args)

        return (patch.object(intake, "_win_job_call", side_effect=no_terminate),
                patch.object(intake.subprocess.Popen, "kill", lambda _p: None))

    def test_codex_p1_registry_append_failure_after_launch_keeps_pending(self):
        os.environ["NTK_LC_MODE"] = "hang_with_grandchild"
        os.environ["NTK_LC_TARGET_STEP"] = "version"
        reg = _FaultyRegistry()
        scanner, ScanError = self._make_scanner("p1_append")
        p_call, p_kill = self._cleanup_cannot_finish()
        with patch.object(intake, "_LINGERING_GIT_TREES", reg):
            with p_call, p_kill, self._arm_after_launch(reg), \
                 patch.object(type(scanner), "_process_timeout", lambda _s: 1.0):
                with self.assertRaises(ScanError) as ctx:
                    scanner.verify_semgrep_installation()
                self.assertEqual(getattr(ctx.exception, "error_code", None), "OPENGREP_TIMEOUT")
                self.assertEqual(ctx.exception.details.get("cleanup_status"), "CLEANUP_FAILED")
                os.environ["NTK_LC_MODE"] = "normal"
                self._blocked_next_then_reconcile()
            reg.armed = False
            self.assertEqual(intake._reconcile_lingering_git_jobs(), 0)
        self._assert_all_exited(expected=2)

    def test_ownership_registration_failure_creates_no_job_or_process(self):
        os.environ["NTK_LC_MODE"] = "normal"
        reg = _FaultyRegistry()
        reg.armed = True
        jobs_before = len(self._created_jobs)
        scanner, ScanError = self._make_scanner("reg_fails")
        with patch.object(intake, "_LINGERING_GIT_TREES", reg):
            with self.assertRaises(ScanError) as ctx:
                scanner.verify_semgrep_installation()
        self.assertEqual(getattr(ctx.exception, "error_code", None), "OPENGREP_PROCESS_ISOLATION_FAILED")
        self.assertEqual(ctx.exception.details.get("reason"), "OWNERSHIP_REGISTRATION_FAILED")
        self.assertEqual(len(self._created_jobs), jobs_before, "no Job may be created without an owner")
        time.sleep(0.3)
        self._absorb()
        self.assertEqual(self.procs, {})

    def test_codex_p2_empty_job_close_failure_keeps_ownership(self):
        real_call = intake._win_job_call

        def close_fails(name, *args):
            if name == "CloseHandle":
                return 0
            return real_call(name, *args)

        scanner, ScanError = self._make_scanner("p2_empty_job")
        with patch.object(intake.tempfile, "TemporaryFile", side_effect=OSError("injected tempfile failure")), \
             patch.object(intake, "_win_job_call", side_effect=close_fails):
            with self.assertRaises(ScanError):
                scanner.verify_semgrep_installation()
            self.assertEqual(len(intake._LINGERING_GIT_TREES), 1, "empty Job handle lost after CloseHandle failure")
            entry = intake._LINGERING_GIT_TREES[0]
            self.assertFalse(entry.get("job_closed"))
            self.assertIsNone(entry.get("proc"))
            self._blocked_next_then_reconcile()
        self.assertEqual(intake._reconcile_lingering_git_jobs(), 0)
        self.assertTrue(entry.get("job_closed"))
        self.assertEqual([e for e in intake._LINGERING_GIT_TREES if e.get("state") != "CLOSED"], [])

    def test_registry_state_update_failure_fails_closed(self):
        os.environ["NTK_LC_MODE"] = "hang_with_grandchild"
        os.environ["NTK_LC_TARGET_STEP"] = "version"
        real_set = getattr(intake, "_set_state", None)

        def set_state(entry, state):
            if state == "PENDING":
                raise MemoryError("injected state update failure")
            return real_set(entry, state)

        scanner, ScanError = self._make_scanner("state_fails")
        p_call, p_kill = self._cleanup_cannot_finish()
        with p_call, p_kill, patch.object(intake, "_set_state", side_effect=set_state, create=True), \
             patch.object(type(scanner), "_process_timeout", lambda _s: 1.0):
            with self.assertRaises(ScanError):
                scanner.verify_semgrep_installation()
        self.assertTrue(getattr(intake, "_REGISTRY_FAULT", False), "registry fault must switch to fail-closed")
        os.environ["NTK_LC_MODE"] = "normal"
        self._blocked_next_then_reconcile()

    # --- Audit round 5: atomic registry fault / launch contract and Job ownership -------------

    def test_ce_a_pending_update_failure_and_fault_flag_are_atomic_for_concurrent_resume(self):
        """CE-A: A fails _set_state(PENDING); B attempts its launch exactly when A releases the lock."""
        os.environ["NTK_LC_MODE"] = "hang_with_grandchild"
        os.environ["NTK_LC_TARGET_STEP"] = "version"
        b_marker = self.root / "b_ran.txt"
        b_script = self.root / "fake_b.py"
        b_script.write_text(
            f'from pathlib import Path\nPath({str(b_marker)!r}).write_text("RAN", encoding="utf-8")\nprint("1.25.0")\n',
            encoding="utf-8")
        fake_b = self.root / "opengrep_b.cmd"
        fake_b.write_text(f'@echo off\r\n"{sys.executable}" "{b_script}" %*\r\n', encoding="utf-8")

        hook = _HookLock(intake._LINGERING_LOCK)
        tls = threading.local()
        real_set = intake._set_state
        real_call = intake._win_job_call
        real_kill = intake.subprocess.Popen.kill

        def set_state(entry, state):
            if getattr(tls, "worker", None) == "A" and state == "PENDING":
                hook.armed = True  # the next lock release by A is the boundary under test
                raise MemoryError("injected PENDING update failure")
            return real_set(entry, state)

        def job_call(name, *args):
            if getattr(tls, "worker", None) == "A" and name == "TerminateJobObject":
                return 0
            return real_call(name, *args)

        def kill(p):
            if getattr(tls, "worker", None) == "A":
                return None
            return real_kill(p)

        OpenGrepConfig, SemgrepScanner, ScanError = _load_baseline_scanner()
        cls = make_bounded_scanner_class(SemgrepScanner, ScanError)
        out_a, out_b = self.root / "a_out", self.root / "b_out"
        out_a.mkdir()
        out_b.mkdir()
        sa = cls(OpenGrepConfig(executable=str(self.fake_og), rules=DEFAULT_G1_RULES, timeout=1, jobs=1), out_a)
        sb = cls(OpenGrepConfig(executable=str(fake_b), rules=DEFAULT_G1_RULES, timeout=1, jobs=1), out_b)
        results = {}

        def run_a():
            tls.worker = "A"
            hook.hook_thread = threading.current_thread()
            try:
                sa.verify_semgrep_installation()
                results["A"] = "UNEXPECTED_OK"
            except BaseException as exc:
                results["A"] = exc
            finally:
                hook.released.set()

        def run_b():
            tls.worker = "B"
            try:
                assert hook.released.wait(timeout=20), "A never reached the lock-release boundary"
                results["B"] = sb.verify_semgrep_installation()
            except BaseException as exc:
                results["B"] = exc
            finally:
                hook.proceed.set()

        with patch.object(intake, "_LINGERING_LOCK", hook), \
             patch.object(intake, "_set_state", side_effect=set_state), \
             patch.object(intake, "_win_job_call", side_effect=job_call), \
             patch.object(intake.subprocess.Popen, "kill", kill), \
             patch.object(cls, "_process_timeout", lambda _s: 1.0):
            ta, tb = threading.Thread(target=run_a), threading.Thread(target=run_b)
            ta.start()
            tb.start()
            ta.join(timeout=40)
            tb.join(timeout=40)
            self.assertFalse(ta.is_alive() or tb.is_alive(), "deadlock between workers")

        self.assertIsInstance(results.get("A"), ScanError)
        self.assertTrue(intake._REGISTRY_FAULT)
        self.assertIsInstance(results.get("B"), ScanError, f"B resumed during A's fault boundary: {results.get('B')!r}")
        self.assertEqual(getattr(results["B"], "error_code", None), "OPENGREP_CLEANUP_PENDING")
        self.assertFalse(b_marker.exists(), "B's process must never run")

    def test_ce_b_running_state_failure_prevents_resume(self):
        os.environ["NTK_LC_MODE"] = "normal"
        real_set = intake._set_state
        real_resume = intake._win_resume_suspended_process
        resume_calls = []

        def set_state(entry, state):
            if state == "RUNNING":
                raise MemoryError("injected RUNNING update failure")
            return real_set(entry, state)

        def resume(pid):
            resume_calls.append(pid)
            return real_resume(pid)

        scanner, ScanError = self._make_scanner("ce_b")
        with patch.object(intake, "_set_state", side_effect=set_state), \
             patch.object(intake, "_win_resume_suspended_process", side_effect=resume):
            with self.assertRaises(ScanError) as ctx:
                scanner.verify_semgrep_installation()
        self.assertEqual(resume_calls, [], "process was resumed although RUNNING was not recorded")
        self.assertTrue(intake._REGISTRY_FAULT)
        self.assertEqual(getattr(ctx.exception, "error_code", None), "OPENGREP_PROCESS_ISOLATION_FAILED")
        self.assertEqual(ctx.exception.details.get("reason"), "REGISTRY_STATE_UPDATE_FAILED")
        self.assertIn("process_cleanup", ctx.exception.details)
        time.sleep(0.3)
        self._absorb()
        self.assertEqual(self.procs, {}, "suspended process must never run")
        self._blocked_next_then_reconcile()

    def test_ce_c_job_configuration_and_close_failure_keeps_handle_owned(self):
        import ctypes

        state = {"fail_close": True, "jobs": set()}
        real_windll = ctypes.WinDLL

        def windll(name, *a, **k):
            lib = real_windll(name, *a, **k)
            return _Kernel32Proxy(lib, state) if str(name).lower().startswith("kernel32") else lib

        os.environ["NTK_LC_MODE"] = "normal"
        scanner, ScanError = self._make_scanner("ce_c")
        popen_before = len(self._created_popens)
        self.job_create_patch.stop()  # exercise the real helper (its own CreateJob/SetInformation/CloseHandle)
        try:
            with patch.object(ctypes, "WinDLL", side_effect=windll):
                with self.assertRaises(ScanError) as ctx:
                    scanner.verify_semgrep_installation()
                self.assertEqual(getattr(ctx.exception, "error_code", None), "OPENGREP_PROCESS_ISOLATION_FAILED")
                self.assertEqual(len(self._created_popens), popen_before, "no process may be created")
                self.assertEqual(len(intake._LINGERING_GIT_TREES), 1, "created Job handle lost its owner")
                entry = intake._LINGERING_GIT_TREES[0]
                self.assertIn(int(entry["job"]), state["jobs"])
                self.assertFalse(entry["job_closed"])
                self.assertEqual(intake._reconcile_lingering_git_jobs(), 1, "unverified close must not be reported clean")
                self._blocked_next_then_reconcile()
                state["fail_close"] = False
                self.assertEqual(intake._reconcile_lingering_git_jobs(), 0)
                self.assertTrue(entry["job_closed"])
        finally:
            self.job_create_patch.start()


if __name__ == "__main__":
    unittest.main()
