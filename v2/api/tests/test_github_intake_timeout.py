"""Counterexample tests for GitHub intake timeouts and Git process-tree ownership/cleanup.

Observed runtime evidence: GITHUB_CLONE_TIMEOUT only after ~16m55s with a 60s limit.
A fake `git` launcher (wrapper -> Python child -> Python grandchild) reproduces Git for Windows,
where `cmd\\git.exe` is a launcher and descendants inherit stdout/stderr. All data lives in isolated
temporary directories; no network is used and no real GitHub clone is claimed by these tests.

Descendant PIDs are tracked through process HANDLES opened as soon as the fake git records them
(identity checked by image path), so state is ALIVE / EXITED / UNKNOWN and teardown only terminates
processes proven to belong to this test run (never a possibly reused bare PID).
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from v2.api import intake
from v2.api.config import IntakeLimits
from v2.api.intake import IntakeError, clone_github_repo

IS_WINDOWS = os.name == "nt"
HOLD_SECONDS = 15
TIMEOUT_SECONDS = 2
# requested timeout + bounded cleanup budget (+1s injected assignment delay), far below HOLD_SECONDS.
MAX_ELAPSED = TIMEOUT_SECONDS + 7
SHA = "a" * 40
URL = "https://github.com/spring-guides/gs-rest-service"
SECRET = "ghp_SECRETtoken1234567890"

FAKE_GIT = r'''
import os, subprocess, sys, time
from pathlib import Path

args = sys.argv[1:]
mode = os.environ.get("NTK_FAKE_GIT_HANG", "")
pid_file = os.environ.get("NTK_FAKE_GIT_PIDFILE", "")
hold = float(os.environ.get("NTK_FAKE_GIT_HOLD", "15"))
orphan = os.environ.get("NTK_FAKE_GIT_ORPHAN") == "1"

def record(*pids):
    if pid_file:
        with open(pid_file, "a", encoding="utf-8") as fh:
            fh.write(" ".join(str(p) for p in pids) + "\n")

def emit_stderr(default):
    path = os.environ.get("NTK_FAKE_GIT_STDERR_FILE")
    data = Path(path).read_bytes() if path else default.encode("utf-8")
    sys.stderr.buffer.write(data)
    sys.stderr.flush()

if "--spawn-orphan" in args:
    # Intermediate that starts the pipe holder and exits at once, orphaning it (stale PPID).
    gc = subprocess.Popen([sys.executable, "-c", f"import time; time.sleep({hold})"])
    record(gc.pid)
    sys.exit(0)

if "clone" in args:
    stage = "clone"
elif "checkout" in args:
    stage = "checkout"
elif "rev-parse" in args:
    stage = "rev-parse"
else:
    stage = "other"

if stage == mode:
    record(os.getpid())
    if orphan:
        subprocess.run([sys.executable, os.path.abspath(__file__), "--spawn-orphan"])
    else:
        gc = subprocess.Popen([sys.executable, "-c", f"import time; time.sleep({hold})"])
        record(gc.pid)
    emit_stderr("fatal: unable to access 'https://user:" + os.environ.get("NTK_FAKE_GIT_SECRET", "x") + "@github.com/a/b.git/': stalled\n")
    time.sleep(hold)
    sys.exit(0)

if stage == "clone":
    if os.environ.get("NTK_FAKE_GIT_CLONE_FAIL") == "1":
        emit_stderr("fatal: repository not found\n")
        sys.exit(128)
    dest = Path(args[-1])
    (dest / ".git").mkdir(parents=True)
    (dest / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (dest / "src").mkdir()
    (dest / "src" / "Demo.java").write_text("public class Demo {}\n", encoding="utf-8")
    sys.exit(0)
if stage == "checkout":
    sys.exit(0)
if stage == "rev-parse":
    sys.stdout.write("b" * 40 + "\n")
    sys.exit(0)
sys.exit(2)
'''


class _Proc:
    """Handle-backed view of a test-owned process (prevents PID reuse confusion)."""

    ALIVE, EXITED, UNKNOWN = "ALIVE", "EXITED", "UNKNOWN"

    def __init__(self, pid: int):
        self.pid = pid
        self.handle = None
        if IS_WINDOWS:
            import ctypes
            from ctypes import wintypes

            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.OpenProcess.restype = wintypes.HANDLE
            k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            # PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE | PROCESS_TERMINATE
            h = k32.OpenProcess(0x1000 | 0x00100000 | 0x0001, False, int(pid))
            if h:
                buf = ctypes.create_unicode_buffer(32768)
                size = wintypes.DWORD(len(buf))
                k32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
                ok = k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size))
                if ok and os.path.normcase(os.path.realpath(buf.value)) == os.path.normcase(os.path.realpath(sys.executable)):
                    self.handle = h
                else:
                    k32.CloseHandle(h)

    def state(self) -> str:
        if not IS_WINDOWS:
            try:
                os.kill(self.pid, 0)
                return self.ALIVE
            except ProcessLookupError:
                return self.EXITED
            except OSError:
                return self.UNKNOWN
        if self.handle is None:
            return self.UNKNOWN
        import ctypes
        from ctypes import wintypes

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        k32.WaitForSingleObject.restype = wintypes.DWORD
        rc = k32.WaitForSingleObject(self.handle, 0)
        if rc == 0:
            return self.EXITED
        if rc == 0x102:  # WAIT_TIMEOUT
            return self.ALIVE
        return self.UNKNOWN

    def terminate_if_owned(self) -> None:
        if IS_WINDOWS and self.handle is not None and self.state() == self.ALIVE:
            import ctypes
            from ctypes import wintypes

            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
            k32.TerminateProcess(self.handle, 1)

    def close(self) -> None:
        if IS_WINDOWS and self.handle is not None:
            import ctypes
            from ctypes import wintypes

            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.CloseHandle.argtypes = [wintypes.HANDLE]
            k32.CloseHandle(self.handle)
            self.handle = None


@unittest.skipUnless(IS_WINDOWS, "Windows-specific Git launcher / Job Object behaviour")
class GithubIntakeTimeoutTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ntk-git-timeout-")
        self.root = Path(self.tmp.name)
        script = self.root / "fake_git.py"
        script.write_text(FAKE_GIT, encoding="utf-8")
        self.fake_git = self.root / "git.cmd"
        self.fake_git.write_text(f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n', encoding="utf-8")
        self.pid_file = self.root / "pids.txt"
        self.dest = self.root / "workspace" / "source"
        self.dest.parent.mkdir(parents=True)
        self.env_patch = patch.dict(os.environ, {
            "NTK_FAKE_GIT_PIDFILE": str(self.pid_file),
            "NTK_FAKE_GIT_HOLD": str(HOLD_SECONDS),
            "NTK_FAKE_GIT_HANG": "",
            "NTK_FAKE_GIT_SECRET": SECRET,
        })
        self.env_patch.start()
        real_which = shutil.which
        self.which_patch = patch(
            "v2.api.intake.shutil.which",
            side_effect=lambda name, *a, **k: str(self.fake_git) if name == "git" else real_which(name, *a, **k),
        )
        self.which_patch.start()
        # Record Popen objects created during the test so teardown can stop leftovers via their own
        # handles (never by bare PID), e.g. a suspended root leaked by pre-fix code.
        self.created_popens: list = []
        orig_init = subprocess.Popen.__init__
        created = self.created_popens

        def recording_init(p, *a, **k):
            orig_init(p, *a, **k)
            created.append(p)

        self.popen_patch = patch.object(subprocess.Popen, "__init__", recording_init)
        self.popen_patch.start()
        # Watcher opens handles to recorded PIDs immediately, before any reuse is possible.
        self.procs: dict[int, _Proc] = {}
        self._stop = threading.Event()
        self._watcher = threading.Thread(target=self._watch, daemon=True)
        self._watcher.start()

    def _watch(self):
        while not self._stop.is_set():
            self._absorb_pids()
            time.sleep(0.01)

    def _absorb_pids(self):
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
        reconcile = getattr(intake, "_reconcile_lingering_git_jobs", None)
        if reconcile is not None:
            try:
                reconcile()
            except Exception:
                pass
        for p in self.procs.values():
            p.terminate_if_owned()
            p.close()
        self.popen_patch.stop()
        for popen in self.created_popens:
            try:
                if popen.poll() is None:
                    popen.kill()  # handle-based TerminateProcess on our own child
                    popen.wait(timeout=5)
            except Exception:
                pass
        self.which_patch.stop()
        self.env_patch.stop()
        self.tmp.cleanup()

    def _clone(self, commit_sha=None):
        return clone_github_repo(URL, commit_sha, self.dest, IntakeLimits(), timeout_seconds=TIMEOUT_SECONDS)

    def _wait_recorded(self, n: int, budget: float = 3.0):
        end = time.monotonic() + budget
        while time.monotonic() < end and len(self.procs) < n:
            self._absorb_pids()
            time.sleep(0.02)

    def _assert_all_exited(self, label: str, expected: int = 2, settle_seconds: float = 2.0):
        self._wait_recorded(expected)
        self.assertGreaterEqual(len(self.procs), expected, f"{label}: fake git did not record descendant PIDs")
        # Kernel signals process objects shortly after job accounting drops to zero; allow a short,
        # bounded settle window, but UNKNOWN or ALIVE after it is a failure (never treated as exited).
        end = time.monotonic() + settle_seconds
        while time.monotonic() < end and any(p.state() == _Proc.ALIVE for p in self.procs.values()):
            time.sleep(0.05)
        for pid, p in self.procs.items():
            self.assertEqual(p.state(), _Proc.EXITED, f"{label}: descendant PID {pid} state is {p.state()} (must be EXITED)")

    def _timeout_case(self, hang_stage: str, expected_code: str, commit_sha=None):
        os.environ["NTK_FAKE_GIT_HANG"] = hang_stage
        t0 = time.monotonic()
        with self.assertRaises(IntakeError) as ctx:
            self._clone(commit_sha)
        elapsed = time.monotonic() - t0
        exc = ctx.exception
        self.assertEqual(exc.error_code, expected_code, str(exc))
        self.assertEqual(exc.http_status, 504)
        self.assertLess(elapsed, MAX_ELAPSED, f"{hang_stage}: returned after {elapsed:.2f}s")
        self.assertEqual(exc.details.get("git_step"), hang_stage)
        cleanup = exc.details.get("process_cleanup") or {}
        self.assertTrue(cleanup.get("clean"), f"cleanup not verified: {cleanup}")
        self.assertNotIn("cleanup_status", exc.details)
        self._assert_all_exited(hang_stage)
        self.assertFalse(self.dest.exists(), "isolated clone workspace must be removed after timeout")
        return exc

    # --- Timeout classification (regression) -------------------------------------------------

    def test_clone_timeout_is_enforced_and_kills_descendants(self):
        self._timeout_case("clone", "GITHUB_CLONE_TIMEOUT")

    def test_checkout_timeout_is_reported_separately(self):
        self._timeout_case("checkout", "GITHUB_CHECKOUT_TIMEOUT", SHA)

    def test_rev_parse_timeout_is_reported_separately(self):
        self._timeout_case("rev-parse", "GITHUB_REV_PARSE_TIMEOUT")

    # --- P1: ownership must be established before the Git process runs ------------------------

    def test_job_object_unavailable_fails_closed_without_running_git(self):
        os.environ["NTK_FAKE_GIT_HANG"] = "clone"
        with patch.object(intake, "_win_create_kill_on_close_job", return_value=None):
            with self.assertRaises(IntakeError) as ctx:
                self._clone()
        self.assertEqual(ctx.exception.error_code, "GIT_PROCESS_ISOLATION_FAILED", str(ctx.exception))
        time.sleep(0.5)
        self._absorb_pids()
        self.assertEqual(self.procs, {}, "git must not start any code when ownership cannot be established")
        self.assertFalse(self.dest.exists())

    def test_job_assignment_refused_fails_closed_without_running_git(self):
        os.environ["NTK_FAKE_GIT_HANG"] = "clone"
        real_call = intake._win_job_call

        def refuse(name, *args):
            if name == "AssignProcessToJobObject":
                return 0
            return real_call(name, *args)

        with patch.object(intake, "_win_job_call", side_effect=refuse):
            with self.assertRaises(IntakeError) as ctx:
                self._clone()
        self.assertEqual(ctx.exception.error_code, "GIT_PROCESS_ISOLATION_FAILED", str(ctx.exception))
        time.sleep(0.5)
        self._absorb_pids()
        self.assertEqual(self.procs, {}, "suspended git must be terminated before running any code")

    def test_orphaned_grandchild_created_before_late_assignment_is_still_owned(self):
        """Codex counterexample: descendant spawned before AssignProcessToJobObject survived cleanup."""
        os.environ["NTK_FAKE_GIT_HANG"] = "clone"
        os.environ["NTK_FAKE_GIT_ORPHAN"] = "1"
        real_call = intake._win_job_call

        def delayed_assign(name, *args):
            if name == "AssignProcessToJobObject":
                time.sleep(1.0)
            return real_call(name, *args)

        with patch.object(intake, "_win_job_call", side_effect=delayed_assign):
            with self.assertRaises(IntakeError) as ctx:
                self._clone()
        self.assertEqual(ctx.exception.error_code, "GITHUB_CLONE_TIMEOUT", str(ctx.exception))
        self.assertTrue((ctx.exception.details.get("process_cleanup") or {}).get("clean"))
        self._assert_all_exited("orphan", expected=2)

    def test_failing_taskkill_cannot_produce_false_clean(self):
        os.environ["NTK_FAKE_GIT_HANG"] = "clone"
        os.environ["NTK_FAKE_GIT_ORPHAN"] = "1"
        real_run = subprocess.run

        def failing_taskkill(cmd, *a, **k):
            if isinstance(cmd, (list, tuple)) and cmd and str(cmd[0]).lower().startswith("taskkill"):
                return subprocess.CompletedProcess(cmd, 1, b"", b"ERROR: access denied")
            return real_run(cmd, *a, **k)

        with patch.object(intake, "_win_create_kill_on_close_job", return_value=None), \
             patch("v2.api.intake.subprocess.run", side_effect=failing_taskkill):
            with self.assertRaises(IntakeError) as ctx:
                self._clone()
        exc = ctx.exception
        clean = (exc.details.get("process_cleanup") or {}).get("clean")
        self.assertFalse(clean is True and exc.error_code == "GITHUB_CLONE_TIMEOUT",
                         f"reported clean=True while ownership unverified: {exc.details}")
        self.assertEqual(exc.error_code, "GIT_PROCESS_ISOLATION_FAILED", str(exc))
        time.sleep(0.5)
        self._absorb_pids()
        for pid, p in self.procs.items():
            self.assertNotEqual(p.state(), _Proc.ALIVE, f"PID {pid} survived")

    # --- P1/P2: unverifiable cleanup is CLEANUP_FAILED, evidence kept, no new Git started -----

    def test_job_query_failure_is_cleanup_failed_not_success(self):
        os.environ["NTK_FAKE_GIT_HANG"] = "clone"
        with patch.object(intake, "_win_job_active_processes", return_value=None):
            with self.assertRaises(IntakeError) as ctx:
                self._clone()
        exc = ctx.exception
        self.assertEqual(exc.error_code, "GITHUB_CLONE_TIMEOUT")
        self.assertEqual(exc.details.get("cleanup_status"), "CLEANUP_FAILED")
        self.assertFalse(exc.details["process_cleanup"].get("clean"))

    def test_cleanup_failure_keeps_redacted_evidence_and_blocks_new_git(self):
        os.environ["NTK_FAKE_GIT_HANG"] = "clone"
        real_call = intake._win_job_call
        real_run = subprocess.run

        def no_terminate(name, *args):
            if name == "TerminateJobObject":
                return 0
            return real_call(name, *args)

        def failing_taskkill(cmd, *a, **k):
            if isinstance(cmd, (list, tuple)) and cmd and str(cmd[0]).lower().startswith("taskkill"):
                return subprocess.CompletedProcess(cmd, 1, b"", b"")
            return real_run(cmd, *a, **k)

        with patch.object(intake, "_win_job_call", side_effect=no_terminate), \
             patch("v2.api.intake.subprocess.run", side_effect=failing_taskkill), \
             patch.object(intake.subprocess.Popen, "kill", lambda self: None):
            with self.assertRaises(IntakeError) as ctx:
                self._clone()
            exc = ctx.exception
            self.assertEqual(exc.error_code, "GITHUB_CLONE_TIMEOUT")
            self.assertEqual(exc.details.get("cleanup_status"), "CLEANUP_FAILED")
            # Raw Git stderr never enters error details; only controlled, non-content diagnostics.
            self.assertNotIn("stderr_tail", exc.details)
            self.assertGreater(exc.details.get("stderr_bytes", 0), 0)
            self.assertNotIn(SECRET, str(exc.details))
            self.assertNotIn(SECRET, str(exc))

            # While the previous Git tree may still be alive, no further Git process may start.
            self.dest = self.root / "workspace" / "source2"
            before = set(self.procs)
            with self.assertRaises(IntakeError) as ctx2:
                self._clone()
            self.assertEqual(ctx2.exception.error_code, "GITHUB_GIT_CLEANUP_PENDING", str(ctx2.exception))
            self.assertEqual(ctx2.exception.http_status, 503)
            time.sleep(0.3)
            self._absorb_pids()
            self.assertEqual(set(self.procs), before, "no new git process may be started while cleanup is pending")

        # After the fault is gone, reconciliation terminates the retained job and unblocks intake.
        intake._reconcile_lingering_git_jobs()
        self._assert_all_exited("lingering-reconciled")

    # --- Regression: success path, failures, URL allowlist ------------------------------------

    def test_successful_clone_path_preserved(self):
        inv = self._clone(SHA)
        self.assertEqual(inv["resolved_commit"], "b" * 40)
        self.assertEqual(inv["repo_url"], URL)
        self.assertEqual(inv["java_files_count"], 1)
        self.assertFalse((self.dest / ".git").exists())

    def test_clone_failure_keeps_failed_code_and_safe_classification(self):
        with patch.dict(os.environ, {"NTK_FAKE_GIT_CLONE_FAIL": "1"}):
            with self.assertRaises(IntakeError) as ctx:
                self._clone()
        self.assertEqual(ctx.exception.error_code, "GITHUB_CLONE_FAILED")
        self.assertEqual(ctx.exception.details.get("git_failure_kind"), "REPOSITORY_NOT_FOUND")
        self.assertEqual(ctx.exception.details.get("git_exit_code"), 128)
        self.assertNotIn("fatal:", str(ctx.exception))
        self.assertFalse(self.dest.exists())

    def test_url_allowlist_rejects_before_git_runs(self):
        for bad in ("http://github.com/a/b", "https://gitlab.com/a/b", "https://github.com/a/b?x=1",
                    "https://github.com/--upload-pack/x", "https://user:pw@github.com/a/b"):
            with self.assertRaises(IntakeError) as ctx:
                clone_github_repo(bad, None, self.dest, IntakeLimits(), timeout_seconds=TIMEOUT_SECONDS)
            self.assertEqual(ctx.exception.error_code, "INVALID_GITHUB_URL")
        self.assertFalse(self.pid_file.exists())

    # --- Lỗi 2: assignment refused + root cannot be stopped must stay pending ------------------

    def _assign_refused_root_unstoppable(self):
        os.environ["NTK_FAKE_GIT_HANG"] = "clone"
        real_call = intake._win_job_call

        def refuse(name, *args):
            if name == "AssignProcessToJobObject":
                return 0
            return real_call(name, *args)

        return patch.object(intake, "_win_job_call", side_effect=refuse)

    def test_assign_refused_and_root_alive_keeps_pending_until_root_exits(self):
        with self._assign_refused_root_unstoppable(), \
             patch.object(intake.subprocess.Popen, "kill", lambda self: None):
            with self.assertRaises(IntakeError) as ctx:
                self._clone()
            exc = ctx.exception
            self.assertEqual(exc.error_code, "GIT_PROCESS_ISOLATION_FAILED")
            self.assertEqual(exc.details.get("cleanup_status"), "CLEANUP_FAILED")
            self.assertFalse(exc.details.get("root_exited"))
            # Job is empty (root was never assigned), but the suspended root is still alive.
            self.assertEqual(intake._reconcile_lingering_git_jobs(), 1, "empty Job must not release a live root")
            self.dest = self.root / "workspace" / "source2"
            with self.assertRaises(IntakeError) as ctx2:
                self._clone()
            self.assertEqual(ctx2.exception.error_code, "GITHUB_GIT_CLEANUP_PENDING")
        time.sleep(0.3)
        self._absorb_pids()
        self.assertEqual(self.procs, {}, "refused/suspended git root must never execute Git code")
        # Root becomes stoppable again: reconciliation terminates it via its own handle and unblocks.
        self.assertEqual(intake._reconcile_lingering_git_jobs(), 0)
        os.environ["NTK_FAKE_GIT_HANG"] = ""
        self.dest = self.root / "workspace" / "source3"
        inv = self._clone(SHA)
        self.assertEqual(inv["resolved_commit"], "b" * 40)

    def test_unobservable_root_state_keeps_pending(self):
        with self._assign_refused_root_unstoppable(), \
             patch.object(intake.subprocess.Popen, "kill", lambda self: None):
            with self.assertRaises(IntakeError):
                self._clone()

            def broken_poll(self):
                raise OSError("cannot observe root")

            with patch.object(intake.subprocess.Popen, "poll", broken_poll):
                self.assertEqual(intake._reconcile_lingering_git_jobs(), 1, "UNKNOWN root state must stay pending")
        self.assertEqual(intake._reconcile_lingering_git_jobs(), 0)


@unittest.skipUnless(IS_WINDOWS, "Windows fake git launcher")
class CredentialLeakTests(unittest.TestCase):
    """Lỗi 1: credentials in Git stderr must not reach job JSON on disk or HTTP responses."""

    PASSWORD = "P4ssw0rdLEAK987654"
    TOKEN_BODY = "TOKENBODYLEAK1234567890abcdef"
    BEARER = "BEARERLEAK5555666677778888"
    CTRL = "CTRLLEAK0123456789"
    API_TOKEN = "credential-leak-test-token-123456"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ntk-git-leak-")
        self.root = Path(self.tmp.name)
        script = self.root / "fake_git.py"
        script.write_text(FAKE_GIT, encoding="utf-8")
        self.fake_git = self.root / "git.cmd"
        self.fake_git.write_text(f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n', encoding="utf-8")
        self.stderr_file = self.root / "stderr.bin"
        real_which = shutil.which
        self.patches = [
            patch.dict(os.environ, {
                "NTK_FAKE_GIT_STDERR_FILE": str(self.stderr_file),
                "NTK_FAKE_GIT_HOLD": "6",
                "NTK_FAKE_GIT_HANG": "",
                "NTK_FAKE_GIT_PIDFILE": str(self.root / "pids.txt"),
            }),
            patch("v2.api.intake.shutil.which",
                  side_effect=lambda name, *a, **k: str(self.fake_git) if name == "git" else real_which(name, *a, **k)),
        ]
        for p in self.patches:
            p.start()
        from v2.api.config import ApiConfig
        from v2.api.server import ThesisApiServer

        self.data_dir = self.root / "api-data"
        cfg = ApiConfig(host="127.0.0.1", port=0, data_dir=self.data_dir, api_token=self.API_TOKEN,
                        git_clone_timeout_seconds=2, max_queued_jobs=8)
        self.srv = ThesisApiServer(cfg)
        self.thread = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.thread.start()
        h, port = self.srv.server_address[:2]
        self.base = f"http://{h}:{port}"

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        intake._reconcile_lingering_git_jobs()
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def _cases(self) -> dict[str, tuple[bytes, list[str]]]:
        cut = intake.MAX_GIT_STDERR_EVIDENCE_BYTES if hasattr(intake, "MAX_GIT_STDERR_EVIDENCE_BYTES") else 2048

        def at_cut(head: str, secret_tail: str) -> bytes:
            # Place the 2048-byte tail boundary exactly between `head` and the secret.
            tail = secret_tail.encode("utf-8")
            pad = b"Y" * max(0, cut - len(tail))
            return b"X" * 64 + head.encode("utf-8") + tail + pad

        return {
            "url_userinfo_cut": (at_cut("fatal: unable to access 'https://user:", f"{self.PASSWORD}@github.com/a/b.git/'\n"), [self.PASSWORD]),
            "github_token_cut": (at_cut("remote: token ghp_", f"{self.TOKEN_BODY} rejected\n"), [self.TOKEN_BODY]),
            "authorization_cut": (at_cut("Authorization: ", f"Bearer {self.BEARER}\n"), [self.BEARER]),
            "control_chars": (("Authori\x07zation: Bearer " + self.CTRL + "\nhttps://us\x07er:" + self.PASSWORD + "@github.com\n").encode("utf-8"),
                              [self.CTRL, self.PASSWORD]),
        }

    def _http(self, path, method="GET", body=None):
        from urllib.request import Request, urlopen
        from urllib.error import HTTPError
        import json as _json

        data = _json.dumps(body).encode("utf-8") if body is not None else None
        req = Request(self.base + path, data=data, method=method,
                      headers={"Authorization": f"Bearer {self.API_TOKEN}", "Content-Type": "application/json"})
        try:
            with urlopen(req, timeout=20) as r:
                return r.status, r.read().decode("utf-8")
        except HTTPError as e:
            return e.code, e.read().decode("utf-8")

    def _run_job(self, mode_env: dict) -> tuple[str, str, str]:
        import json as _json

        with patch.dict(os.environ, mode_env):
            code, body = self._http("/api/scan-jobs", "POST", {"repo_url": URL})
            self.assertIn(code, (200, 201, 202), body)
            job_id = _json.loads(body)["job_id"]
            end = time.monotonic() + 30
            while time.monotonic() < end:
                code, body = self._http(f"/api/scan-jobs/{job_id}")
                if _json.loads(body).get("state") == "FAILED":
                    break
                time.sleep(0.1)
        _, listing = self._http("/api/scan-jobs")
        disk = (self.data_dir / "jobs" / f"{job_id}.json").read_text(encoding="utf-8")
        return body, listing, disk

    def _check(self, mode_env: dict, expected_code: str):
        import json as _json

        for name, (stderr_bytes, secrets) in self._cases().items():
            with self.subTest(case=name):
                intake._reconcile_lingering_git_jobs()
                self.stderr_file.write_bytes(stderr_bytes)
                detail, listing, disk = self._run_job(mode_env)
                self.assertEqual(_json.loads(detail)["error_code"], expected_code, detail)
                for secret in secrets:
                    for label, blob in (("HTTP detail", detail), ("HTTP list", listing), ("disk JSON", disk)):
                        self.assertNotIn(secret, blob, f"{name}: secret leaked into {label}")
                self.assertNotIn("stderr_tail", detail)
                self.assertNotIn("stderr_tail", disk)

    def test_timeout_stderr_never_leaks_credentials(self):
        self._check({"NTK_FAKE_GIT_HANG": "clone"}, "GITHUB_CLONE_TIMEOUT")

    def test_clone_failure_stderr_never_leaks_credentials(self):
        self._check({"NTK_FAKE_GIT_CLONE_FAIL": "1"}, "GITHUB_CLONE_FAILED")


@unittest.skipUnless(IS_WINDOWS, "Windows handle semantics")
class ProcessObservationTests(unittest.TestCase):
    def test_unobservable_pid_is_unknown_not_exited(self):
        # PID 4 (System) cannot be opened/identified as a test-owned python process.
        self.assertEqual(_Proc(4).state(), _Proc.UNKNOWN)

    def test_exited_process_reports_exited_via_handle(self):
        p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(0.5)"])
        obs = _Proc(p.pid)
        try:
            self.assertEqual(obs.state(), _Proc.ALIVE)
            p.wait(timeout=10)
            self.assertEqual(obs.state(), _Proc.EXITED)
        finally:
            obs.close()


class JobErrorEvidenceTests(unittest.TestCase):
    def test_intake_error_details_are_persisted_on_failed_job(self):
        from v2.api.config import ApiConfig
        from v2.api.jobs import ScanJobManager

        with tempfile.TemporaryDirectory(prefix="ntk-job-evidence-") as tmp:
            cfg = ApiConfig(data_dir=Path(tmp) / "data")
            mgr = ScanJobManager(cfg)
            details = {"git_step": "clone", "cleanup_status": "CLEANUP_FAILED", "stderr_bytes": 7,
                       "stderr_tail": "https://user:P4ssLEAK@github.com", "unexpected_key": "x"}
            err = IntakeError("GITHUB_CLONE_TIMEOUT", "timeout", http_status=504, details=details)
            try:
                with patch("v2.api.jobs.clone_github_repo", side_effect=err):
                    job = mgr.submit_github_job(URL)
                    end = time.monotonic() + 10
                    while time.monotonic() < end and mgr.get_job(job["job_id"])["state"] != "FAILED":
                        time.sleep(0.05)
                doc = mgr.get_job(job["job_id"])
            finally:
                mgr.shutdown(wait=True)
            self.assertEqual(doc["state"], "FAILED")
            self.assertEqual(doc["error_code"], "GITHUB_CLONE_TIMEOUT")
            self.assertEqual(doc.get("error_details"),
                             {"git_step": "clone", "cleanup_status": "CLEANUP_FAILED", "stderr_bytes": 7})
            self.assertNotIn("P4ssLEAK", (Path(tmp) / "data" / "jobs" / f"{job['job_id']}.json").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
