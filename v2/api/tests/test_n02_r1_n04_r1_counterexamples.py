"""Counterexample regression suite for Codex R1 blockers: N02-R1 and N04-R1.

- N02-R1: `BaseException` (e.g., `KeyboardInterrupt`) raised during auxiliary scratch-stream
  `fh.close()` in `intake._run_git_step()` MUST NEVER mask `_GitStepCleanupFailed` when cleanup
  already failed, MUST still close remaining streams, MUST preserve the interrupt in the exception
  chain and cleanup metadata, and MUST propagate `KeyboardInterrupt` (never swallow / return PASS)
  when process cleanup was clean.
- N04-R1: `opengrep_runner._collect_wsl_candidates_from_py_ast()` MUST bind WSL targets ONLY from
  process-launch call sites (never treat uncalled documentation tuples or unused module constants
  with no WSL call site as executed WSL targets), while keeping ADMIN-PC `opengrep_counted.py`
  support and fail-closed rejection on ambiguous or unresolvable WSL call sites.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from ctypes import wintypes
from pathlib import Path
from unittest.mock import patch

from v2.api import intake, opengrep_runner as og
from v2.api.config import ApiConfig, DEFAULT_BACKEND_RULES
from v2.api.tests.test_n01_n05_counterexamples import _make_canary_step_stub, _make_stub_proc


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


class _InterruptOnCloseStream:
    """Wrapper around a real TemporaryFile that closes the underlying fd then raises KeyboardInterrupt."""

    def __init__(self, stream, *, name_tag: str, closed_log: list[str], interrupt_exc: BaseException | None = None):
        self._stream = stream
        self._name_tag = name_tag
        self._closed_log = closed_log
        self._interrupt_exc = interrupt_exc

    def __getattr__(self, attr: str):
        return getattr(self._stream, attr)

    def close(self) -> None:
        self._closed_log.append(self._name_tag)
        self._stream.close()
        if self._interrupt_exc is not None:
            raise self._interrupt_exc


class TestN02R1StreamCloseInterruptCounterexamples(unittest.TestCase):
    """N02-R1: Scratch-stream close KeyboardInterrupt vs cleanup failure & clean-cleanup propagation."""

    def setUp(self) -> None:
        self._reset_health_registry()
        self.addCleanup(self._reset_health_registry)

    def _reset_health_registry(self) -> None:
        to_finalize: list[dict] = []
        with intake._LINGERING_LOCK:
            for e in list(intake._LINGERING_GIT_TREES):
                if str(e.get("step") or "").startswith("opengrep-health-"):
                    to_finalize.append(e)
            intake._REGISTRY_FAULT = False
        for e in to_finalize:
            try:
                if e.get("proc") is not None or (e.get("job") is not None and not e.get("job_closed")):
                    intake._finalize_tree_safe(e, str(e.get("step") or "cleanup"), time.monotonic() + 2.0)
            except BaseException:
                pass
            intake._unregister(e)
        with intake._LINGERING_LOCK:
            intake._REGISTRY_FAULT = False

    def _assert_lingering_lock_not_deadlocked(self) -> None:
        acquired = intake._LINGERING_LOCK.acquire(timeout=1.0)
        self.assertTrue(acquired, "_LINGERING_LOCK appears deadlocked!")
        intake._LINGERING_LOCK.release()

    def test_n02_r1_cleanup_failed_with_keyboard_interrupt_on_stream_close_preserves_cleanup_failed(self) -> None:
        """Codex N02-R1: KeyboardInterrupt in fh.close() MUST NOT replace _GitStepCleanupFailed."""
        control = subprocess.Popen(
            [sys.executable, "-B", "-c", "import time; time.sleep(20)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.addCleanup(lambda: (control.kill() if control.poll() is None else None, control.wait(timeout=4)))

        real_tmp = intake.tempfile.TemporaryFile
        real_fin = intake._finalize_tree
        closed_log: list[str] = []
        spawned_pids: list[int] = []
        stream_idx = {"n": 0}

        def make_faulty_tmp():
            stream_idx["n"] += 1
            tag = "stdout" if stream_idx["n"] == 1 else "stderr"
            return _InterruptOnCloseStream(
                real_tmp(),
                name_tag=tag,
                closed_log=closed_log,
                interrupt_exc=KeyboardInterrupt(f"audit interrupt closing {tag}"),
            )

        def dirty_fin(entry, step, deadline):
            if entry.get("proc") is not None:
                spawned_pids.append(int(entry["proc"].pid))
            state = real_fin(entry, step, deadline)
            self.assertTrue(state["clean"], f"Real process cleanup should succeed cleanly first: {state}")
            state["clean"] = False
            return state

        stop = threading.Event()
        stop.set()

        caught: BaseException | None = None
        with patch.object(intake, "_finalize_tree", side_effect=dirty_fin), patch.object(
            intake.tempfile, "TemporaryFile", side_effect=make_faulty_tmp
        ):
            try:
                intake._run_git_step(
                    "opengrep-health-n02-r1-dirty-interrupt",
                    [sys.executable, "-B", "-c", "import time; time.sleep(10)"],
                    timeout_seconds=3.0,
                    env=os.environ.copy(),
                    cancel_event=stop,
                )
            except BaseException as exc:
                caught = exc

        self.assertIsNotNone(caught, "Expected _GitStepCleanupFailed to be raised")
        self.assertIsInstance(
            caught,
            intake._GitStepCleanupFailed,
            f"N02-R1 REPRODUCED: outer exception was {type(caught).__name__!r} instead of _GitStepCleanupFailed!",
        )
        cleanup_meta = getattr(caught, "cleanup", None)
        self.assertIsInstance(cleanup_meta, dict, f"Outer _GitStepCleanupFailed missing cleanup metadata: {caught!r}")
        self.assertFalse(cleanup_meta["clean"])

        # Both stdout and stderr streams MUST be closed even when stdout.close() raises KeyboardInterrupt
        self.assertEqual(closed_log, ["stdout", "stderr"], f"Remaining stream close was skipped: {closed_log}")

        # Interrupt details preserved in cleanup metadata AND exception chain
        close_errs = cleanup_meta.get("stream_close_errors") or []
        self.assertEqual(len(close_errs), 2, close_errs)
        self.assertEqual({e.get("stream") for e in close_errs}, {"stdout", "stderr"})
        self.assertTrue(all(e.get("error_type") == "KeyboardInterrupt" for e in close_errs), close_errs)
        self.assertIsInstance(
            caught.__cause__,
            KeyboardInterrupt,
            f"KeyboardInterrupt from stream close not preserved in exception chain: cause={caught.__cause__!r}",
        )

        # Child process exited, registry clean, no lock deadlock, sibling untouched
        self.assertEqual(len(spawned_pids), 1)
        self.assertFalse(_is_os_pid_alive(spawned_pids[0]), f"Child PID {spawned_pids[0]} still alive!")
        reg = intake.inspect_lingering_registry_state(step_prefix="opengrep-health-")
        self.assertEqual(reg["matching_count"], 0, reg)
        self._assert_lingering_lock_not_deadlocked()
        self.assertIsNone(control.poll(), "Unrelated sibling control process was killed!")

    def test_n02_r1_cleanup_clean_with_keyboard_interrupt_on_stream_close_propagates_interrupt(self) -> None:
        """N02-R1: When process cleanup IS clean and fh.close() raises KeyboardInterrupt, MUST NOT swallow it."""
        control = subprocess.Popen(
            [sys.executable, "-B", "-c", "import time; time.sleep(20)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.addCleanup(lambda: (control.kill() if control.poll() is None else None, control.wait(timeout=4)))

        real_tmp = intake.tempfile.TemporaryFile
        real_fin = intake._finalize_tree
        closed_log: list[str] = []
        spawned_pids: list[int] = []
        stream_idx = {"n": 0}

        def make_faulty_tmp():
            stream_idx["n"] += 1
            tag = "stdout" if stream_idx["n"] == 1 else "stderr"
            # Raise KeyboardInterrupt on stdout.close(); stderr.close() must STILL execute!
            exc = KeyboardInterrupt("audit clean-path interrupt on stdout close") if tag == "stdout" else None
            return _InterruptOnCloseStream(real_tmp(), name_tag=tag, closed_log=closed_log, interrupt_exc=exc)

        def recording_fin(entry, step, deadline):
            if entry.get("proc") is not None:
                spawned_pids.append(int(entry["proc"].pid))
            return real_fin(entry, step, deadline)

        caught: BaseException | None = None
        returned = None
        with patch.object(intake, "_finalize_tree", side_effect=recording_fin), patch.object(
            intake.tempfile, "TemporaryFile", side_effect=make_faulty_tmp
        ):
            try:
                returned = intake._run_git_step(
                    "opengrep-health-n02-r1-clean-interrupt",
                    [sys.executable, "-B", "-c", "print('clean-ok')"],
                    timeout_seconds=5.0,
                    env=os.environ.copy(),
                )
            except BaseException as exc:
                caught = exc

        self.assertIsNone(returned, f"KeyboardInterrupt on clean path was swallowed and returned PASS: {returned!r}")
        self.assertIsInstance(caught, KeyboardInterrupt, f"Expected KeyboardInterrupt, got {caught!r}")
        self.assertEqual(
            closed_log,
            ["stdout", "stderr"],
            f"N02-R1 REPRODUCED: stderr.close() skipped after stdout KeyboardInterrupt! {closed_log}",
        )
        cleanup_meta = getattr(caught, "cleanup", None)
        self.assertIsInstance(cleanup_meta, dict, f"Expected clean cleanup metadata on interrupt: {caught!r}")
        self.assertTrue(cleanup_meta["clean"], cleanup_meta)
        close_errs = cleanup_meta.get("stream_close_errors") or []
        self.assertEqual(len(close_errs), 1, close_errs)
        self.assertEqual(close_errs[0].get("stream"), "stdout")
        self.assertEqual(close_errs[0].get("error_type"), "KeyboardInterrupt")

        self.assertEqual(len(spawned_pids), 1)
        self.assertFalse(_is_os_pid_alive(spawned_pids[0]))
        reg = intake.inspect_lingering_registry_state(step_prefix="opengrep-health-")
        self.assertEqual(reg["matching_count"], 0, reg)
        self._assert_lingering_lock_not_deadlocked()
        self.assertIsNone(control.poll(), "Unrelated sibling control process was killed!")

    def test_n02_r1_cancelled_clean_with_keyboard_interrupt_on_stream_close_propagates_interrupt(self) -> None:
        """N02-R1 boundary: Clean cancellation (_GitStepCancelled) + KeyboardInterrupt on close propagates interrupt."""
        real_tmp = intake.tempfile.TemporaryFile
        closed_log: list[str] = []
        stream_idx = {"n": 0}

        def make_faulty_tmp():
            stream_idx["n"] += 1
            tag = "stdout" if stream_idx["n"] == 1 else "stderr"
            exc = KeyboardInterrupt("audit cancel-clean interrupt") if tag == "stdout" else None
            return _InterruptOnCloseStream(real_tmp(), name_tag=tag, closed_log=closed_log, interrupt_exc=exc)

        stop = threading.Event()
        stop.set()
        caught: BaseException | None = None
        with patch.object(intake.tempfile, "TemporaryFile", side_effect=make_faulty_tmp):
            try:
                intake._run_git_step(
                    "opengrep-health-n02-r1-cancel-clean-interrupt",
                    [sys.executable, "-B", "-c", "import time; time.sleep(10)"],
                    timeout_seconds=3.0,
                    env=os.environ.copy(),
                    cancel_event=stop,
                )
            except BaseException as exc:
                caught = exc

        self.assertIsInstance(caught, KeyboardInterrupt)
        self.assertEqual(closed_log, ["stdout", "stderr"])
        self.assertIsInstance(caught.__context__, intake._GitStepCancelled)
        cleanup_meta = getattr(caught, "cleanup", None)
        self.assertIsInstance(cleanup_meta, dict)
        self.assertTrue(cleanup_meta["clean"])
        self._assert_lingering_lock_not_deadlocked()

    def test_n02_r1_positive_control_normal_execution_and_clean_close(self) -> None:
        """Positive control: normal process exit with clean stream close returns stdout cleanly."""
        res = intake._run_git_step(
            "opengrep-health-n02-r1-pos",
            [sys.executable, "-B", "-c", "print('n02-r1-ok')"],
            timeout_seconds=5.0,
            env=os.environ.copy(),
        )
        self.assertEqual(res.returncode, 0)
        self.assertEqual(res.stdout.decode("utf-8").strip(), "n02-r1-ok")
        reg = intake.inspect_lingering_registry_state(step_prefix="opengrep-health-")
        self.assertEqual(reg["matching_count"], 0, reg)
        self._assert_lingering_lock_not_deadlocked()


class TestN04R1WslAstExecutionBindingCounterexamples(unittest.TestCase):
    """N04-R1: Only call-site-bound WSL commands enter execution-chain WSL identity."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ntk_n04_r1_")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def _put(self, subdir: Path, rel: str, text: str) -> Path:
        p = subdir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        return p

    def test_n04_r1_uncalled_doc_tuple_and_module_constant_not_detected_as_wsl_target(self) -> None:
        """Codex N04-R1: Uncalled doc tuple / module constant with no WSL call site MUST NOT set wsl_target.detected."""
        # 1. Exact Codex N04-R1 defensive-checks.py reproducer
        d1 = self.root / "doc_only"
        w1 = self._put(d1, "opengrep.cmd", f'@echo off\n"{sys.executable}" "%~dp0bridge.py" %*\n')
        self._put(
            d1,
            "bridge.py",
            'def documented_example():\n'
            '    return ("wsl.exe", "--", "/usr/local/bin/opengrep")\n',
        )
        id1 = og.inspect_opengrep_binary_identity(str(w1))
        self.assertTrue(id1["found"], id1)
        self.assertTrue(id1["identity_complete"], id1)
        self.assertFalse(
            id1["wsl_target"]["detected"],
            f"N04-R1 REPRODUCED: uncalled documented_example() tuple detected as WSL target! {id1}",
        )

        # 2. Module-level unused list/tuple constant with NO subprocess call site
        d2 = self.root / "const_only"
        w2 = self._put(d2, "opengrep.cmd", f'@echo off\n"{sys.executable}" "%~dp0bridge.py" %*\n')
        self._put(
            d2,
            "bridge.py",
            'EXAMPLE_CMD = ["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"]\n'
            'print("local native runner")\n',
        )
        id2 = og.inspect_opengrep_binary_identity(str(w2))
        self.assertTrue(id2["found"], id2)
        self.assertFalse(
            id2["wsl_target"]["detected"],
            f"N04-R1 REPRODUCED: unused module constant detected as WSL target! {id2}",
        )

        # 3. Uncalled doc tuple in module that ONLY executes a non-WSL subprocess
        d3 = self.root / "non_wsl_call"
        w3 = self._put(d3, "opengrep.cmd", f'@echo off\n"{sys.executable}" "%~dp0bridge.py" %*\n')
        self._put(
            d3,
            "bridge.py",
            'import subprocess, sys\n'
            'def documented_example():\n'
            '    return ("wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep")\n'
            'subprocess.run([sys.executable, "-c", "print(1)"], check=False)\n',
        )
        id3 = og.inspect_opengrep_binary_identity(str(w3))
        self.assertTrue(id3["found"], id3)
        self.assertFalse(
            id3["wsl_target"]["detected"],
            f"N04-R1 REPRODUCED: uncalled doc tuple flagged despite only non-WSL subprocess! {id3}",
        )

        # 4. Uncalled doc function with DIFFERENT tuple alongside a real executed ADMIN-PC WSL call site
        d4 = self.root / "doc_plus_real"
        w4 = self._put(d4, "opengrep.cmd", f'@echo off\n"{sys.executable}" "%~dp0opengrep_counted.py" %*\n')
        self._put(
            d4,
            "opengrep_counted.py",
            'import subprocess, sys\n'
            'def documented_example():\n'
            '    return ("wsl.exe", "-d", "OtherDistro", "--", "/opt/example/opengrep")\n'
            'def main():\n'
            '    translated_args = sys.argv[1:]\n'
            '    cmd = ["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep", *translated_args]\n'
            '    return subprocess.run(cmd, capture_output=True).returncode\n'
            'if __name__ == "__main__":\n'
            '    raise SystemExit(main())\n',
        )
        id4 = og.inspect_opengrep_binary_identity(str(w4))
        self.assertTrue(id4["found"], f"Uncalled doc tuple should NOT create false ambiguity against real call site: {id4}")
        self.assertEqual(
            id4["wsl_target"],
            {"detected": True, "distro": "Ubuntu-IRIS", "linux_binary_path": "/usr/local/bin/opengrep"},
        )

    def test_n04_r1_admin_pc_bridge_and_call_site_patterns_positive_controls(self) -> None:
        """Positive controls: ADMIN-PC bridge shape, main() helper, aliased subprocess, and local dep hashing."""
        # 1. Exact ADMIN-PC opengrep_counted.py shape + local imported helper + unrelated sibling file
        d1 = self.root / "admin_pc"
        w1 = self._put(d1, "opengrep.cmd", f'@echo off\n"{sys.executable}" "%~dp0opengrep_counted.py" %*\n')
        helper = self._put(d1, "arg_helper.py", "def translate(xs):\n    return list(xs)\n")
        sibling = self._put(d1, "unreferenced_note.py", "DOC = ('wsl.exe', '--', '/opt/ignored')\n")
        self._put(
            d1,
            "opengrep_counted.py",
            'import subprocess, sys\n'
            'import arg_helper\n'
            'def main():\n'
            '    translated_args = arg_helper.translate(sys.argv[1:])\n'
            '    cmd = ["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep", *translated_args]\n'
            '    proc = subprocess.run(cmd, capture_output=True)\n'
            '    return proc.returncode\n'
            'if __name__ == "__main__":\n'
            '    raise SystemExit(main())\n',
        )
        id_a = og.inspect_opengrep_binary_identity(str(w1))
        self.assertTrue(id_a["found"], id_a)
        self.assertTrue(id_a["identity_complete"])
        self.assertEqual(
            id_a["wsl_target"],
            {"detected": True, "distro": "Ubuntu-IRIS", "linux_binary_path": "/usr/local/bin/opengrep"},
        )
        dep_names = {Path(x["path"]).name for x in id_a["wrapper_targets"]}
        self.assertEqual(dep_names, {"opengrep_counted.py", "arg_helper.py"})

        # Mutating unreferenced sibling MUST NOT change identity hash; mutating imported dep MUST change it
        sibling.write_text("DOC = ('changed',)\n", encoding="utf-8")
        id_b = og.inspect_opengrep_binary_identity(str(w1))
        self.assertEqual(id_a["binary_identity_sha256"], id_b["binary_identity_sha256"])

        helper.write_text("def translate(xs):\n    return ['--extra', *xs]\n", encoding="utf-8")
        id_c = og.inspect_opengrep_binary_identity(str(w1))
        self.assertNotEqual(id_a["binary_identity_sha256"], id_c["binary_identity_sha256"])

        # 2. Aliased subprocess import + helper function returning command list
        d2 = self.root / "aliased_helper"
        w2 = self._put(d2, "opengrep.cmd", f'@echo off\n"{sys.executable}" "%~dp0bridge.py" %*\n')
        self._put(
            d2,
            "bridge.py",
            'from subprocess import run as exec_run\n'
            'def build_cmd(extra):\n'
            '    return ["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep", *extra]\n'
            'exec_run(build_cmd([]), capture_output=True)\n',
        )
        id2 = og.inspect_opengrep_binary_identity(str(w2))
        self.assertTrue(id2["found"], id2)
        self.assertEqual(
            id2["wsl_target"],
            {"detected": True, "distro": "Ubuntu-IRIS", "linux_binary_path": "/usr/local/bin/opengrep"},
        )

    def test_n04_r1_fail_closed_on_ambiguous_or_unresolvable_wsl_call_sites_and_probe_fail(self) -> None:
        """Fail-closed controls: multiple conflicting call sites, conditional cmd, dynamic/shell/subscript, and probe failure."""
        # 1. Two conflicting WSL call sites -> WSL_TARGET_AMBIGUOUS
        d_two = self.root / "two_calls"
        w_two = self._put(d_two, "opengrep.cmd", f'@echo off\n"{sys.executable}" "%~dp0bridge.py" %*\n')
        self._put(
            d_two,
            "bridge.py",
            'import subprocess, os\n'
            'if os.environ.get("ALT"):\n'
            '    subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/opt/alt/opengrep"])\n'
            'else:\n'
            '    subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"])\n',
        )
        id_two = og.inspect_opengrep_binary_identity(str(w_two))
        self.assertFalse(id_two["found"], id_two)
        self.assertEqual(id_two["failure_code"], "WSL_TARGET_AMBIGUOUS")

        # 2. Subscript mutation of cmd before subprocess.run -> WSL_TARGET_UNRESOLVABLE
        d_mut = self.root / "subscript_mut"
        w_mut = self._put(d_mut, "opengrep.cmd", f'@echo off\n"{sys.executable}" "%~dp0bridge.py" %*\n')
        self._put(
            d_mut,
            "bridge.py",
            'import subprocess\n'
            'cmd = ["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"]\n'
            'cmd[4] = "/opt/hijacked"\n'
            'subprocess.run(cmd)\n',
        )
        id_mut = og.inspect_opengrep_binary_identity(str(w_mut))
        self.assertFalse(id_mut["found"], id_mut)
        self.assertEqual(id_mut["failure_code"], "WSL_TARGET_UNRESOLVABLE")

        # 3. Real call site targeting unresolvable WSL distro fails closed in OpenGrepHealthProbe
        d_fail = self.root / "wsl_probe_fail"
        w_fail = self._put(d_fail, "opengrep.cmd", f'@echo off\n"{sys.executable}" "%~dp0bridge.py" %*\n')
        self._put(
            d_fail,
            "bridge.py",
            'import subprocess, sys\n'
            'cmd = ["wsl.exe", "-d", "NonExistentDistroXYZ", "--", "/usr/local/bin/opengrep", *sys.argv[1:]]\n'
            'subprocess.run(cmd, capture_output=True)\n',
        )
        id_fail = og.inspect_opengrep_binary_identity(str(w_fail))
        self.assertTrue(id_fail["found"], id_fail)
        self.assertEqual(id_fail["wsl_target"]["distro"], "NonExistentDistroXYZ")

        cfg = ApiConfig(
            data_dir=self.root / "probe_fail_data",
            rules_path=DEFAULT_BACKEND_RULES,
            opengrep_binary=str(w_fail),
            api_token="n04-r1-test-token",
            port=0,
        )
        stub = _make_canary_step_stub()

        def fail_realpath(step, args, **kw):
            if step.endswith("realpath"):
                return _make_stub_proc(args, b"", code=1)
            return stub(step, args, **kw)

        probe = og.OpenGrepHealthProbe(cfg)
        self.addCleanup(probe.shutdown)
        with patch.object(intake, "_run_git_step", side_effect=fail_realpath):
            snap = probe._execute_probe_once()[0]
        self.assertFalse(snap["available"], snap)
        self.assertEqual(snap["failure_code"], "WSL_BINARY_IDENTITY_FAILED")


if __name__ == "__main__":
    unittest.main()
