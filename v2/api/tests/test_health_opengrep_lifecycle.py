"""Counterexample & lifecycle tests for OpenGrep probe cleanup verification and controlled server shutdown."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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
from urllib.request import Request, urlopen

from v2.api.config import ApiConfig
from v2.api.server import ThesisApiServer


TEST_TOKEN = "opengrep-lifecycle-token-20261117"


def _is_os_pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k32.OpenProcess.restype = wintypes.HANDLE
        k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        k32.GetExitCodeProcess.restype = wintypes.BOOL
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = k32.OpenProcess(0x1000, False, int(pid))
        if not handle:
            return False
        try:
            code = wintypes.DWORD(0)
            if not k32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return False
            return code.value == 259  # STILL_ACTIVE
        finally:
            k32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _force_kill_test_pids(pids: list[int]) -> None:
    for pid in pids:
        if pid > 0 and _is_os_pid_alive(pid):
            if os.name == "nt":
                subprocess.run(
                    ["taskkill", "/PID", str(int(pid)), "/T", "/F"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                    timeout=3.0,
                    check=False,
                )
            else:
                try:
                    os.kill(pid, 9)
                except OSError:
                    pass


def _make_mock_ollama_server() -> tuple[ThreadingHTTPServer, threading.Thread, str]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_GET(self):
            if self.path == "/api/tags":
                raw = json.dumps({"models": [{"name": "qwen3.5:9b-q4_K_M", "digest": "sha256:test"}]}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                return
            self.send_response(404)
            self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    h, p = srv.server_address[:2]
    return srv, th, f"http://{h}:{p}"


def _write_cmd_wrapper(directory: Path, name: str, py_body: str) -> Path:
    script = directory / f"{name}.py"
    script.write_text(py_body, encoding="utf-8")
    if os.name == "nt":
        wrapper = directory / f"{name}.cmd"
        wrapper.write_text(f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n', encoding="utf-8")
        return wrapper
    wrapper = directory / f"{name}.sh"
    wrapper.write_text(f'#!/bin/sh\n"{sys.executable}" "{script}" "$@"\n', encoding="utf-8")
    wrapper.chmod(0o755)
    return wrapper


def _read_recorded_pids(pid_file: Path) -> list[int]:
    if not pid_file.is_file():
        return []
    out = []
    for line in pid_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.isdigit():
            out.append(int(line))
    return out


@unittest.skip(
    "LEGACY_NOT_APPLICABLE: /api/health no longer spawns OpenGrep probe processes or Windows Job Objects."
)
class HealthOpenGrepLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.rules_file = self.root / "rules.yml"
        self.rules_file.write_text("rules: []\n", encoding="utf-8")
        self.ol_srv, self.ol_th, self.ollama_url = _make_mock_ollama_server()
        self.addCleanup(lambda: (self.ol_srv.shutdown(), self.ol_th.join(timeout=2.0), self.ol_srv.server_close()))
        self._tracked_pids_for_cleanup: list[int] = []
        self.addCleanup(lambda: _force_kill_test_pids(self._tracked_pids_for_cleanup))

    def _start_api(self, og_binary: str) -> tuple[ThesisApiServer, str]:
        srv = ThesisApiServer(
            ApiConfig(
                host="127.0.0.1",
                port=0,
                data_dir=self.root / "api_data",
                rules_path=self.rules_file,
                opengrep_binary=og_binary,
                ollama_endpoint=self.ollama_url,
                ollama_model="qwen3.5:9b-q4_K_M",
                api_token=TEST_TOKEN,
                read_auth_mode="required",
            )
        )
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        self.addCleanup(lambda: (srv.shutdown(), th.join(timeout=2.0), srv.server_close()))
        h, p = srv.server_address[:2]
        return srv, f"http://{h}:{p}"

    def _get(self, url: str) -> tuple[int, dict, float]:
        t0 = time.monotonic()
        req = Request(url, headers={"Authorization": f"Bearer {TEST_TOKEN}", "Connection": "close"}, method="GET")
        with urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8")), time.monotonic() - t0

    def test_1_successful_timeout_cleanup_kills_wrapper_and_grandchild(self) -> None:
        wdir = self.root / "clean_ok"
        wdir.mkdir(parents=True, exist_ok=True)
        pid_file = wdir / "pids.txt"
        wrapper = _write_cmd_wrapper(
            wdir,
            "opengrep_clean_ok",
            (
                "import os, subprocess, sys, time\n"
                f"pf = {str(pid_file)!r}\n"
                "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(15.0)'], cwd='.')\n"
                "with open(pf, 'a', encoding='utf-8') as f:\n"
                "    f.write(f'{os.getpid()}\\n{child.pid}\\n')\n"
                "time.sleep(15.0)\n"
            ),
        )
        srv, base = self._start_api(str(wrapper))
        srv.service._opengrep_http_wait_seconds = 0.2
        srv.service._opengrep_subprocess_timeout_seconds = 0.6

        code, d1, _ = self._get(f"{base}/api/health")
        self.assertEqual(code, 200)
        self.assertEqual(d1["status"], "DEGRADED")
        self.assertFalse(d1["opengrep"]["available"])

        time.sleep(0.75)
        pids = _read_recorded_pids(pid_file)
        self._tracked_pids_for_cleanup.extend(pids)
        self.assertGreaterEqual(len(pids), 2)
        for pid in pids:
            self.assertFalse(_is_os_pid_alive(pid), f"Test PID {pid} survived cleanup!")

        code2, d2, _ = self._get(f"{base}/api/health")
        self.assertEqual(code2, 200)
        self.assertEqual(d2["opengrep"].get("probe_status"), "TIMEOUT")

    def test_2_taskkill_oserror_reports_cleanup_failed_blocks_new_probe_then_recovers(self) -> None:
        wdir = self.root / "tk_oserror"
        wdir.mkdir(parents=True, exist_ok=True)
        pid_file = wdir / "pids.txt"
        count_file = wdir / "count.txt"
        mode_file = wdir / "mode.txt"
        mode_file.write_text("hang", encoding="utf-8")
        wrapper = _write_cmd_wrapper(
            wdir,
            "opengrep_tk_oserror",
            (
                "import os, pathlib, subprocess, sys, time\n"
                f"with open({str(count_file)!r}, 'a', encoding='utf-8') as f: f.write('1\\n')\n"
                f"if pathlib.Path({str(mode_file)!r}).read_text(encoding='utf-8').strip() == 'ok':\n"
                "    print('1.25.0')\n"
                "    sys.exit(0)\n"
                "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(15.0)'], cwd='.')\n"
                f"with open({str(pid_file)!r}, 'a', encoding='utf-8') as f: f.write(f'{{os.getpid()}}\\n{{child.pid}}\\n')\n"
                "time.sleep(15.0)\n"
            ),
        )
        srv, base = self._start_api(str(wrapper))
        srv.service._opengrep_http_wait_seconds = 0.2
        srv.service._opengrep_subprocess_timeout_seconds = 0.5
        srv.service._opengrep_failure_ttl_seconds = 0.25

        real_run = subprocess.run

        def fail_taskkill(cmd, *args, **kwargs):
            if isinstance(cmd, (list, tuple)) and cmd and str(cmd[0]).lower().startswith("taskkill"):
                raise OSError("simulated taskkill launch failure")
            return real_run(cmd, *args, **kwargs)

        with patch("subprocess.run", side_effect=fail_taskkill):
            code1, d1, _ = self._get(f"{base}/api/health")
            self.assertEqual(code1, 200)
            self.assertEqual(d1["status"], "DEGRADED")

            time.sleep(0.6)  # wait past subprocess_timeout -> taskkill fails!
            pids = _read_recorded_pids(pid_file)
            self._tracked_pids_for_cleanup.extend(pids)
            self.assertTrue(any(_is_os_pid_alive(p) for p in pids), "Expected probe tree to still be alive when taskkill failed")

            code2, d2, _ = self._get(f"{base}/api/health")
            self.assertEqual(code2, 200)
            self.assertEqual(d2["status"], "DEGRADED")
            self.assertFalse(d2["opengrep"]["available"])
            self.assertEqual(d2["opengrep"].get("probe_status"), "CLEANUP_FAILED")

            # Wait past failure_ttl while taskkill STILL fails -> MUST NOT spawn a second overlapping probe!
            time.sleep(0.35)
            code3, d3, _ = self._get(f"{base}/api/health")
            self.assertEqual(code3, 200)
            self.assertEqual(d3["opengrep"].get("probe_status"), "CLEANUP_FAILED")
            invocations = len(count_file.read_text(encoding="utf-8").splitlines())
            self.assertEqual(invocations, 1, f"Dangerous overlapping probe spawned ({invocations}) during CLEANUP_FAILED!")

        # Restore taskkill and switch wrapper mode to ok -> after failure_ttl expires, lingering tree is cleaned and API recovers!
        mode_file.write_text("ok", encoding="utf-8")
        time.sleep(0.35)
        code4, d4, _ = self._get(f"{base}/api/health")
        self.assertEqual(code4, 200)
        self.assertEqual(d4["status"], "OK", d4)
        self.assertTrue(d4["opengrep"]["available"])
        self.assertEqual(d4["opengrep"].get("probe_status"), "VERIFIED")
        self.assertEqual(d4["opengrep"]["version"], "1.25.0")
        for pid in pids:
            self.assertFalse(_is_os_pid_alive(pid), f"Lingering PID {pid} was not cleaned up on recovery!")

    def test_3_taskkill_nonzero_exit_reports_cleanup_failed_and_blocks_new_probe(self) -> None:
        wdir = self.root / "tk_nonzero"
        wdir.mkdir(parents=True, exist_ok=True)
        pid_file = wdir / "pids.txt"
        count_file = wdir / "count.txt"
        wrapper = _write_cmd_wrapper(
            wdir,
            "opengrep_tk_nonzero",
            (
                "import os, subprocess, sys, time\n"
                f"with open({str(count_file)!r}, 'a', encoding='utf-8') as f: f.write('1\\n')\n"
                "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(15.0)'], cwd='.')\n"
                f"with open({str(pid_file)!r}, 'a', encoding='utf-8') as f: f.write(f'{{os.getpid()}}\\n{{child.pid}}\\n')\n"
                "time.sleep(15.0)\n"
            ),
        )
        srv, base = self._start_api(str(wrapper))
        srv.service._opengrep_http_wait_seconds = 0.2
        srv.service._opengrep_subprocess_timeout_seconds = 0.5
        srv.service._opengrep_failure_ttl_seconds = 0.2

        real_run = subprocess.run

        def nonzero_taskkill(cmd, *args, **kwargs):
            if isinstance(cmd, (list, tuple)) and cmd and str(cmd[0]).lower().startswith("taskkill"):
                return subprocess.CompletedProcess(cmd, 5, b"", b"ERROR: Access is denied.")
            return real_run(cmd, *args, **kwargs)

        with patch("subprocess.run", side_effect=nonzero_taskkill):
            self._get(f"{base}/api/health")
            time.sleep(0.6)
            pids = _read_recorded_pids(pid_file)
            self._tracked_pids_for_cleanup.extend(pids)

            code2, d2, _ = self._get(f"{base}/api/health")
            self.assertEqual(code2, 200)
            self.assertEqual(d2["opengrep"].get("probe_status"), "CLEANUP_FAILED")
            self.assertFalse(d2["opengrep"]["available"])

            time.sleep(0.3)  # past failure TTL
            code3, d3, _ = self._get(f"{base}/api/health")
            self.assertEqual(code3, 200)
            self.assertEqual(d3["opengrep"].get("probe_status"), "CLEANUP_FAILED")
            self.assertEqual(len(count_file.read_text(encoding="utf-8").splitlines()), 1)

    def test_4_parent_exited_but_grandchild_alive_cleanup_and_taskkill_fail_detected(self) -> None:
        wdir = self.root / "orphan_grandchild"
        wdir.mkdir(parents=True, exist_ok=True)
        parent_pid_file = wdir / "parent_pid.txt"
        grand_pid_file = wdir / "grand_pid.txt"
        # 4a. Parent exits quickly with invalid/empty stdout while leaving grandchild alive;
        # when taskkill fails, CLEANUP_FAILED must be detected even though parent already exited!
        wdir_fail = self.root / "orphan_gc_fail"
        wdir_fail.mkdir(parents=True, exist_ok=True)
        ppid_f2 = wdir_fail / "parent_pid.txt"
        gpid_f2 = wdir_fail / "grand_pid.txt"
        wrapper_fail = _write_cmd_wrapper(
            wdir_fail,
            "opengrep_orphan_gc_fail",
            (
                "import os, subprocess, sys, time\n"
                "gc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(15.0)'], cwd='.')\n"
                f"with open({str(ppid_f2)!r}, 'w', encoding='utf-8') as f: f.write(str(os.getpid()))\n"
                f"with open({str(gpid_f2)!r}, 'w', encoding='utf-8') as f: f.write(str(gc.pid))\n"
                "time.sleep(0.25)\n"
                "sys.exit(0)\n"
            ),
        )
        srv_f, base_f = self._start_api(str(wrapper_fail))
        srv_f.service._opengrep_http_wait_seconds = 1.5
        real_run = subprocess.run

        def fail_tk(cmd, *args, **kwargs):
            if isinstance(cmd, (list, tuple)) and cmd and str(cmd[0]).lower().startswith("taskkill"):
                raise OSError("taskkill unavailable on orphaned grandchild")
            return real_run(cmd, *args, **kwargs)

        with patch("subprocess.run", side_effect=fail_tk):
            code_f, d_f, _ = self._get(f"{base_f}/api/health")
            self.assertEqual(code_f, 200)
            self.assertEqual(d_f["opengrep"].get("probe_status"), "CLEANUP_FAILED", d_f)
            gpids_f = _read_recorded_pids(gpid_f2)
            self._tracked_pids_for_cleanup.extend(_read_recorded_pids(ppid_f2) + gpids_f)
            self.assertEqual(len(gpids_f), 1)
            self.assertTrue(_is_os_pid_alive(gpids_f[0]))
            self.assertIn(gpids_f[0], d_f["opengrep"].get("lingering_pids", []))

        # Shutting down now (real taskkill restored) MUST find and kill the lingering grandchild PID!
        srv_f.shutdown()
        srv_f.server_close()
        self.assertTrue(srv_f.opengrep_shutdown_status["clean"], srv_f.opengrep_shutdown_status)
        self.assertFalse(_is_os_pid_alive(gpids_f[0]), f"Orphaned grandchild PID {gpids_f[0]} survived shutdown!")

        # 4b. Parent exits 0 with valid version `1.25.0` while leaving detached grandchild alive ->
        # shutdown MUST also clean up that detached grandchild!
        wrapper = _write_cmd_wrapper(
            wdir,
            "opengrep_orphan_gc",
            (
                "import os, subprocess, sys, time\n"
                "gc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(15.0)'], cwd='.')\n"
                f"with open({str(parent_pid_file)!r}, 'w', encoding='utf-8') as f: f.write(str(os.getpid()))\n"
                f"with open({str(grand_pid_file)!r}, 'w', encoding='utf-8') as f: f.write(str(gc.pid))\n"
                "print('1.25.0')\n"
                "sys.stdout.flush()\n"
                "time.sleep(0.25)\n"
                "sys.exit(0)\n"
            ),
        )
        srv, base = self._start_api(str(wrapper))
        srv.service._opengrep_http_wait_seconds = 1.5
        code, d1, _ = self._get(f"{base}/api/health")
        self.assertEqual(code, 200)
        self.assertTrue(d1["opengrep"]["available"])

        ppids = _read_recorded_pids(parent_pid_file)
        gpids = _read_recorded_pids(grand_pid_file)
        self._tracked_pids_for_cleanup.extend(ppids + gpids)
        self.assertEqual(len(gpids), 1)
        gpid = gpids[0]
        self.assertTrue(_is_os_pid_alive(gpid), "Expected grandchild to still be alive after parent exited")

        # Now shut down server cleanly -> MUST clean up orphaned grandchild too!
        srv.shutdown()
        srv.server_close()
        self.assertIsNotNone(getattr(srv, "opengrep_shutdown_status", None))
        self.assertTrue(srv.opengrep_shutdown_status["clean"], srv.opengrep_shutdown_status)
        self.assertFalse(_is_os_pid_alive(gpid), f"Orphaned grandchild PID {gpid} survived server shutdown!")

    def test_5_shutdown_while_pending_kills_probe_bounded_and_clean(self) -> None:
        wdir = self.root / "shutdown_pending"
        wdir.mkdir(parents=True, exist_ok=True)
        pid_file = wdir / "pids.txt"
        wrapper = _write_cmd_wrapper(
            wdir,
            "opengrep_shutdown_pending",
            (
                "import os, subprocess, sys, time\n"
                "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20.0)'], cwd='.')\n"
                f"with open({str(pid_file)!r}, 'a', encoding='utf-8') as f: f.write(f'{{os.getpid()}}\\n{{child.pid}}\\n')\n"
                "time.sleep(20.0)\n"
            ),
        )
        srv, base = self._start_api(str(wrapper))
        srv.service._opengrep_http_wait_seconds = 0.2
        srv.service._opengrep_subprocess_timeout_seconds = 15.0

        code, d1, _ = self._get(f"{base}/api/health")
        self.assertEqual(code, 200)
        self.assertEqual(d1["opengrep"].get("probe_status"), "PENDING")
        pids = _read_recorded_pids(pid_file)
        self._tracked_pids_for_cleanup.extend(pids)
        self.assertTrue(any(_is_os_pid_alive(p) for p in pids))

        t0 = time.monotonic()
        srv.shutdown()
        srv.server_close()
        close_elapsed = time.monotonic() - t0
        self.assertLess(close_elapsed, 4.0, f"Shutdown hung ({close_elapsed:.2f}s)")
        st = getattr(srv, "opengrep_shutdown_status", None)
        self.assertIsNotNone(st)
        self.assertTrue(st["clean"], st)
        self.assertEqual(st["cleanup_status"], "CLEAN")
        for pid in pids:
            self.assertFalse(_is_os_pid_alive(pid), f"PID {pid} survived PENDING server shutdown!")

        # No new probe accepted after shutdown
        after_res = srv.service.probe_opengrep()
        self.assertFalse(after_res["available"])
        self.assertEqual(after_res["probe_status"], "SHUTTING_DOWN")

    def test_6_shutdown_after_completed_probe_clean(self) -> None:
        wdir = self.root / "shutdown_done"
        wdir.mkdir(parents=True, exist_ok=True)
        wrapper = _write_cmd_wrapper(
            wdir,
            "opengrep_shutdown_done",
            "print('1.25.0')\n",
        )
        srv, base = self._start_api(str(wrapper))
        code, d1, _ = self._get(f"{base}/api/health")
        self.assertEqual(code, 200)
        self.assertTrue(d1["opengrep"]["available"])
        t0 = time.monotonic()
        srv.shutdown()
        srv.server_close()
        self.assertLess(time.monotonic() - t0, 2.0)
        st = getattr(srv, "opengrep_shutdown_status", None)
        self.assertIsNotNone(st)
        self.assertTrue(st["clean"], st)
        self.assertEqual(st["cleanup_status"], "CLEAN")

    def test_7_shutdown_when_taskkill_fails_reports_unclean_not_hang(self) -> None:
        wdir = self.root / "shutdown_tk_fail"
        wdir.mkdir(parents=True, exist_ok=True)
        pid_file = wdir / "pids.txt"
        wrapper = _write_cmd_wrapper(
            wdir,
            "opengrep_shutdown_tk_fail",
            (
                "import os, subprocess, sys, time\n"
                "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(15.0)'], cwd='.')\n"
                f"with open({str(pid_file)!r}, 'a', encoding='utf-8') as f: f.write(f'{{os.getpid()}}\\n{{child.pid}}\\n')\n"
                "time.sleep(15.0)\n"
            ),
        )
        srv, base = self._start_api(str(wrapper))
        srv.service._opengrep_http_wait_seconds = 0.2
        srv.service._opengrep_subprocess_timeout_seconds = 15.0

        code, d1, _ = self._get(f"{base}/api/health")
        self.assertEqual(code, 200)
        self.assertEqual(d1["opengrep"].get("probe_status"), "PENDING")
        pids = _read_recorded_pids(pid_file)
        self._tracked_pids_for_cleanup.extend(pids)

        real_run = subprocess.run

        def fail_tk(cmd, *args, **kwargs):
            if isinstance(cmd, (list, tuple)) and cmd and str(cmd[0]).lower().startswith("taskkill"):
                return subprocess.CompletedProcess(cmd, 1, b"", b"Access denied")
            return real_run(cmd, *args, **kwargs)

        with patch("subprocess.run", side_effect=fail_tk):
            t0 = time.monotonic()
            srv.shutdown()
            srv.server_close()
            self.assertLess(time.monotonic() - t0, 5.0)
            st = getattr(srv, "opengrep_shutdown_status", None)
            self.assertIsNotNone(st)
            self.assertFalse(st["clean"], f"Shutdown must NOT claim clean when taskkill failed: {st}")
            self.assertEqual(st["cleanup_status"], "CLEANUP_FAILED")
            self.assertTrue(len(st["lingering_pids"]) >= 1)


if __name__ == "__main__":
    unittest.main()
