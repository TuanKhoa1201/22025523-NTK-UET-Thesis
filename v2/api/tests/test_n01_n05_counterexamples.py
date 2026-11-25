"""Counterexample and boundary regression suite for independent audit defects N01-N05.

Locked BEFORE production repairs (expected RED on N01-N05 counterexamples, GREEN on positive controls)
and re-verified AFTER production repairs without weakening any assertion:
- N01: Health consistency under split-read / torn-input interleaving in `evaluate_readiness_snapshot()`
       and `_execute_probe_once()` post-scan TOCTOU check, plus synchronized `rules.name`/`sha256`.
- N02: Process lifecycle cleanup under `RUNNING`/`PREPARING`/`FINALIZING` probe registry entries,
       `BaseException` (`SystemExit`) interruption on genuine Windows child processes, and
       `finally` stream-close faults that must never mask `_GitStepCleanupFailed`.
- N03: Canary oracle validation of exact `HEALTH_CANARY_SOURCE` content, `(line, col)` spans,
       consistent LF/CRLF `offset` values, canonical path equality (not basename-only), and
       per-rule `mode: taint` trace enforcement in mixed search/taint rulesets.
- N04: Execution-chain identity fail-closed handling when exceeding depth/file caps, encountering
       unresolved interpreters/scripts/imports or broken Python files, or encountering ambiguous /
       dynamic WSL targets, plus pre/post WSL binary identity verification and ADMIN-PC bridge shape.
- N05: Java JLS §6.5.2 leading-segment variable/field/TypeName shadowing on `java.lang.System.out`
       and other qualified stdlib calls (with real `javac` verification), chained calls, taint
       passthrough, truncation monotonicity, and verified-source positive controls.
"""
from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import yaml

from v2.api import intake, opengrep_runner as og
from v2.api.config import ApiConfig, DEFAULT_BACKEND_RULES
from v2.api.java_context_v2 import analyze_flow_dependencies
from v2.api.server import ThesisApiServer
from v2.api.service import TriageApiService
from v2.api.tests.test_backend_quality_repairs import _make_record, _supported_assessment
from v2.api.tests.test_health_opengrep_active_probe import _is_os_pid_alive
from v2.api.triage_gate import apply_integration_gate


def _load_real_canary_doc() -> dict:
    """Return a deterministic, self-contained OpenGrep 1.25.0 canary fixture.

    The exact (line, col, offset) spans and CRLF byte offsets match verified
    OpenGrep 1.25.0 JSON output on `og.HEALTH_CANARY_SOURCE` without reading any
    machine-local evidence tree outside the repository.
    """
    jf = "C:/synthetic/canary/src/OpenGrepHealthCanary.java"
    return {
        "version": "1.25.0",
        "results": [
            {
                "check_id": "v2.api.rules.ntk.api.java.cwe89.sql-injection",
                "path": jf,
                "start": {"line": 10, "col": 25, "offset": 322},
                "end": {"line": 10, "col": 61, "offset": 358},
                "extra": {
                    "message": "[CWE-89] SQLi",
                    "metadata": {
                        "cwe": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"],
                        "owasp": ["A03:2021 - Injection"],
                        "category": "security",
                        "technology": ["java"],
                        "confidence": "HIGH",
                        "provenance": "NTK V2 backend local taint ruleset for Java CWE-89",
                    },
                    "severity": "ERROR",
                    "lines": '        st.executeQuery("SELECT * FROM users WHERE id=" + id);',
                    "dataflow_trace": {
                        "taint_source": [
                            "CliLoc",
                            [
                                {"path": jf, "start": {"line": 9, "col": 21, "offset": 273}, "end": {"line": 9, "col": 43, "offset": 295}},
                                'req.getParameter("id")',
                            ],
                        ],
                        "intermediate_vars": [
                            {
                                "location": {"path": jf, "start": {"line": 9, "col": 16, "offset": 268}, "end": {"line": 9, "col": 18, "offset": 270}},
                                "content": "id",
                            }
                        ],
                        "taint_sink": [
                            "CliLoc",
                            [
                                {"path": jf, "start": {"line": 10, "col": 25, "offset": 322}, "end": {"line": 10, "col": 61, "offset": 358}},
                                '"SELECT * FROM users WHERE id=" + id',
                            ],
                        ],
                    },
                },
            },
            {
                "check_id": "v2.api.rules.ntk.api.java.cwe22.path-traversal",
                "path": jf,
                "start": {"line": 15, "col": 9, "offset": 498},
                "end": {"line": 15, "col": 49, "offset": 538},
                "extra": {
                    "message": "[CWE-22] Path traversal",
                    "metadata": {
                        "cwe": ["CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"],
                        "owasp": ["A01:2021 - Broken Access Control"],
                        "category": "security",
                        "technology": ["java"],
                        "confidence": "MEDIUM",
                        "provenance": "NTK V2 backend local taint ruleset for Java CWE-22",
                    },
                    "severity": "ERROR",
                    "lines": '        new FileInputStream("/srv/data/" + name);',
                    "dataflow_trace": {
                        "taint_source": [
                            "CliLoc",
                            [
                                {"path": jf, "start": {"line": 14, "col": 23, "offset": 463}, "end": {"line": 14, "col": 47, "offset": 487}},
                                'req.getParameter("file")',
                            ],
                        ],
                        "intermediate_vars": [
                            {
                                "location": {"path": jf, "start": {"line": 14, "col": 16, "offset": 456}, "end": {"line": 14, "col": 20, "offset": 460}},
                                "content": "name",
                            }
                        ],
                        "taint_sink": [
                            "CliLoc",
                            [
                                {"path": jf, "start": {"line": 15, "col": 9, "offset": 498}, "end": {"line": 15, "col": 49, "offset": 538}},
                                'new FileInputStream("/srv/data/" + name)',
                            ],
                        ],
                    },
                },
            },
        ],
        "errors": [],
        "interfile_languages_used": [],
        "skipped_rules": [],
        "paths": {"scanned": [jf]},
    }


def _make_stub_proc(args, stdout: bytes = b"", code: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args, code, stdout, b"")


def _make_canary_step_stub(raw_doc_bytes: bytes | None = None):
    payload = raw_doc_bytes if raw_doc_bytes is not None else json.dumps(_load_real_canary_doc()).encode("utf-8")

    def _stub(step, args, **kw):
        if step.endswith("-version"):
            return _make_stub_proc(args, b"1.25.0\n")
        if step.endswith("canary"):
            # Rewrite canary paths dynamically to match actual canary temp dir if present in args
            try:
                target_dir = Path(args[-1])
                canary_file = target_dir / og.HEALTH_CANARY_FILENAME
                if canary_file.is_file():
                    d = json.loads(payload.decode("utf-8"))
                    p_str = canary_file.resolve().as_posix()
                    d["paths"]["scanned"] = [p_str]
                    for r in d["results"]:
                        r["path"] = p_str
                        tr = r["extra"].get("dataflow_trace") or {}
                        for k in ("taint_source", "taint_sink"):
                            if k in tr:
                                tr[k][1][0]["path"] = p_str
                        for iv in tr.get("intermediate_vars") or []:
                            iv["location"]["path"] = p_str
                    return _make_stub_proc(args, json.dumps(d).encode("utf-8"))
            except Exception:
                pass
            return _make_stub_proc(args, payload)
        return _make_stub_proc(args, b"")

    return _stub


class TestN01HealthConsistencyCounterexamples(unittest.TestCase):
    """N01: Split-read / torn-input consistency across binary identity, rules SHA-256, and config."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ntk_n01_")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.wrapper = self.root / "opengrep.cmd"
        self.wrapper.write_text("@echo off\nrem n01 baseline\n", encoding="utf-8")
        self.rules = self.root / "rules.yml"
        self.rules.write_bytes(DEFAULT_BACKEND_RULES.read_bytes())

    def _make_service(self, clock_box: list[float]) -> tuple[TriageApiService, og.OpenGrepHealthProbe]:
        cfg = ApiConfig(
            data_dir=self.root / f"data_{time.monotonic_ns()}",
            rules_path=self.rules,
            opengrep_binary=str(self.wrapper),
            api_token="audit-n01-token",
            port=0,
        )
        svc = TriageApiService(cfg)
        probe = og.OpenGrepHealthProbe(cfg, clock=lambda: clock_box[0])
        svc._opengrep_probe = probe
        svc.probe_ollama = lambda: {"reachable": True, "model_installed": True}
        self.addCleanup(probe.shutdown)
        return svc, probe

    def _seed_verified(self, probe: og.OpenGrepHealthProbe) -> None:
        with patch.object(intake, "_run_git_step", side_effect=_make_canary_step_stub()):
            self.assertTrue(probe.start_background_probe())
            self.assertTrue(probe.wait_for_probe(5.0))
        self.assertTrue(probe.get_status(trigger_refresh=False)["available"])

    def test_n01_split_read_wrapper_and_rules_never_simultaneously_current(self) -> None:
        """Codex N01: Cached (wrapper B, rules B) must NOT return OK/VERIFIED when disk flips (B, A) -> (A, B) mid-read."""
        now_box = [10.0]
        svc, probe = self._make_service(now_box)

        wa = self.wrapper.read_bytes()
        ra = self.rules.read_bytes()
        wb = wa + b"rem version B\n"
        rb = ra + b"\n# rules B\n"

        # Seed cached VERIFIED snapshot with pair (wrapper B, rules B)
        self.wrapper.write_bytes(wb)
        self.rules.write_bytes(rb)
        self._seed_verified(probe)
        self.assertEqual(svc.health(authenticated=True)["status"], "OK")

        # Set disk to (wrapper B, rules A) — pair (B, B) is NOT current!
        self.rules.write_bytes(ra)

        real_inspect = og.inspect_opengrep_binary_identity
        calls = {"n": 0}

        def interleave(binary: str):
            calls["n"] += 1
            observed = real_inspect(binary)
            # Right after first binary read observes B, flip disk to (wrapper A, rules B)
            self.wrapper.write_bytes(wa)
            self.rules.write_bytes(rb)
            return observed

        with patch.object(og, "inspect_opengrep_binary_identity", side_effect=interleave), patch.object(
            intake, "_run_git_step", side_effect=_make_canary_step_stub()
        ):
            out = svc.health(authenticated=True)
            probe.wait_for_probe(5.0)

        self.assertEqual(out["status"], "DEGRADED", f"N01 REPRODUCED: split-read returned OK! {out}")
        self.assertFalse(out["opengrep"]["available"])
        self.assertFalse(out["opengrep"]["runtime_verified"])
        self.assertEqual(out["opengrep"]["probe_status"], "NOT_VERIFIED")
        self.assertEqual(out["opengrep"]["rules_sha256"], out["rules"]["sha256"])
        self.assertIn(
            out["opengrep"]["failure_code"],
            ("BINARY_IDENTITY_CHANGED", "INPUT_CHANGED_DURING_EVALUATION"),
        )

    def test_n01_post_scan_toctou_split_read_rejected(self) -> None:
        """Boundary N01: Split-read during `_execute_probe_once()` post-scan TOCTOU check must NOT commit VERIFIED."""
        now_box = [10.0]
        _svc, probe = self._make_service(now_box)

        wa = self.wrapper.read_bytes()
        ra = self.rules.read_bytes()
        wb = wa + b"rem B\n"
        rb = ra + b"\n# B\n"
        self.wrapper.write_bytes(wb)
        self.rules.write_bytes(rb)

        real_inspect = og.inspect_opengrep_binary_identity
        inspect_calls = {"n": 0}
        base_stub = _make_canary_step_stub()

        def step_mutates_rules_before_post_check(step, args, **kw):
            res = base_stub(step, args, **kw)
            if step.endswith("canary"):
                # Right as canary finishes, disk is (wrapper B, rules A)
                self.rules.write_bytes(ra)
            return res

        def interleave_post(binary: str):
            inspect_calls["n"] += 1
            obs = real_inspect(binary)
            if inspect_calls["n"] == 2:
                # First post-scan binary read saw wrapper B; flip disk to (wrapper A, rules B)
                self.wrapper.write_bytes(wa)
                self.rules.write_bytes(rb)
            return obs

        with patch.object(intake, "_run_git_step", side_effect=step_mutates_rules_before_post_check), patch.object(
            og, "inspect_opengrep_binary_identity", side_effect=interleave_post
        ):
            snap = probe._execute_probe_once()[0]

        self.assertFalse(snap["available"], f"N01 post-scan split-read committed VERIFIED: {snap}")
        self.assertEqual(snap["probe_status"], "NOT_VERIFIED")
        self.assertEqual(snap["failure_code"], "INPUT_CHANGED_DURING_PROBE")

    def test_n01_ttl_expiry_between_read_phases_rejected_and_ollama_lock_free(self) -> None:
        """Boundary + positive control: TTL expiry across phases fails closed; probe lock stays free during Ollama."""
        now_box = [10.0]
        svc, probe = self._make_service(now_box)
        self._seed_verified(probe)

        # Positive control: lock is NOT held during probe_ollama()
        entered = threading.Event()
        release = threading.Event()

        def blocking_ollama():
            entered.set()
            self.assertTrue(release.wait(4.0))
            return {"reachable": True, "model_installed": True}

        svc.probe_ollama = blocking_ollama
        with ThreadPoolExecutor(max_workers=1) as pool:
            fut = pool.submit(svc.health, authenticated=True)
            self.assertTrue(entered.wait(4.0))
            unlocked = probe._lock.acquire(timeout=1.0)
            if unlocked:
                probe._lock.release()
            release.set()
            ok_out = fut.result(5.0)
        self.assertTrue(unlocked, "OpenGrepHealthProbe._lock must never be held across probe_ollama()")
        self.assertEqual(ok_out["status"], "OK")
        self.assertEqual(ok_out["rules"]["name"], self.rules.name)
        self.assertEqual(ok_out["opengrep"]["rules_sha256"], ok_out["rules"]["sha256"])

        # Advance clock to expiry right when second-phase inspect runs
        svc.probe_ollama = lambda: {"reachable": True, "model_installed": True}
        real_inspect = og.inspect_opengrep_binary_identity
        seen = {"n": 0}

        def expire_on_second_read(binary: str):
            seen["n"] += 1
            res = real_inspect(binary)
            if seen["n"] >= 1:
                now_box[0] = probe._snapshot_expires_mono
            return res

        with patch.object(og, "inspect_opengrep_binary_identity", side_effect=expire_on_second_read), patch.object(
            intake, "_run_git_step", side_effect=_make_canary_step_stub()
        ):
            exp_out = svc.health(authenticated=True)
            probe.wait_for_probe(5.0)

        self.assertEqual(exp_out["status"], "DEGRADED")
        self.assertFalse(exp_out["opengrep"]["available"])
        self.assertEqual(exp_out["opengrep"]["probe_status"], "EXPIRED")
        self.assertEqual(exp_out["opengrep"]["failure_code"], "SNAPSHOT_EXPIRED")


class TestN02ProcessLifecycleAndCleanupCounterexamples(unittest.TestCase):
    """N02: Non-CLOSED probe registry entries, BaseException finalization, and finally stream-close masking."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ntk_n02_")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.wrapper = self.root / "opengrep.cmd"
        self.wrapper.write_text("@echo off\nrem n02\n", encoding="utf-8")
        self.rules = self.root / "rules.yml"
        self.rules.write_bytes(DEFAULT_BACKEND_RULES.read_bytes())
        self.addCleanup(self._reset_intake_registry)

    def _reset_intake_registry(self) -> None:
        intake._reconcile_lingering_git_jobs(2.0)
        # Collect entries under _LINGERING_LOCK, then finalize OUTSIDE the lock so
        # `_finalize_tree_safe -> _transition` never self-deadlocks on non-reentrant `_LINGERING_LOCK`.
        with intake._LINGERING_LOCK:
            to_finalize = [
                e for e in list(intake._LINGERING_GIT_TREES)
                if str(e.get("step") or "").startswith("opengrep-health-") and e.get("proc") is not None
            ]
        for e in to_finalize:
            intake._finalize_tree_safe(e, str(e.get("step")), time.monotonic() + 2.0)
        with intake._LINGERING_LOCK:
            intake._REGISTRY_FAULT = False
            intake._LINGERING_GIT_TREES[:] = [
                e for e in intake._LINGERING_GIT_TREES if not str(e.get("step") or "").startswith("opengrep-health-")
            ]

    def _cfg(self) -> ApiConfig:
        return ApiConfig(
            data_dir=self.root / f"data_{time.monotonic_ns()}",
            rules_path=self.rules,
            opengrep_binary=str(self.wrapper),
            api_token="audit-n02-token",
            port=0,
        )

    def test_n02_shutdown_with_running_preparing_finalizing_registry_entry_reports_cleanup_failed(self) -> None:
        """Codex N02: Any non-CLOSED `opengrep-health-*` registry entry MUST prevent shutdown from reporting clean=True."""
        for active_state in (intake._STATE_RUNNING, intake._STATE_PREPARING, intake._STATE_FINALIZING):
            with self.subTest(state=active_state):
                entry = intake._register_owner(f"opengrep-health-audit-{active_state.lower()}", "job")
                try:
                    intake._transition(entry, active_state)
                    probe = og.OpenGrepHealthProbe(self._cfg())
                    fake_srv = ThesisApiServer.__new__(ThesisApiServer)
                    fake_srv.service = SimpleNamespace(shutdown_opengrep_probe=probe.shutdown)
                    fake_srv.jobs = SimpleNamespace(shutdown=lambda wait: None)
                    with patch.object(ThreadingHTTPServer, "server_close", return_value=None):
                        fake_srv.server_close()

                    sd = fake_srv.last_probe_shutdown_status
                    self.assertIsInstance(sd, dict)
                    self.assertFalse(sd["clean"], f"N02 REPRODUCED: {active_state} entry allowed clean=True! {sd}")
                    self.assertEqual(sd["status"], "CLEANUP_FAILED", sd)
                    self.assertIsNotNone(sd["failure_code"], sd)
                    self.assertFalse(sd["children_exited"], sd)
                    self.assertFalse(sd["job_closed"], sd)
                    self.assertEqual(sd["registry_state"], active_state)

                    post = probe.get_status(trigger_refresh=False)
                    self.assertEqual(post["probe_status"], "CLEANUP_FAILED", post)
                    self.assertFalse(post["available"])
                finally:
                    intake._unregister(entry)

    def test_n02_base_exception_system_exit_finalizes_real_windows_child_without_touching_sibling(self) -> None:
        """Codex N02: SystemExit in `_output_check` MUST finalize genuine Windows child tree and leave 0 RUNNING leaks."""
        control = subprocess.Popen(
            [sys.executable, "-B", "-c", "import time; time.sleep(20)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.addCleanup(lambda: (control.kill() if control.poll() is None else None, control.wait(timeout=4)))

        recorded_pids: list[int] = []
        actual_run = intake._run_git_step

        def real_child(step, args, **kw):
            return actual_run(step, [sys.executable, "-B", "-c", "import time; time.sleep(15)"], **kw)

        def abort_with_system_exit(*args):
            # Capture child PID currently registered before interrupting with BaseException
            with intake._LINGERING_LOCK:
                for ent in intake._LINGERING_GIT_TREES:
                    if str(ent.get("step") or "").startswith("opengrep-health-") and ent.get("proc") is not None:
                        recorded_pids.append(int(ent["proc"].pid))
            raise SystemExit("audit BaseException interruption")

        probe = og.OpenGrepHealthProbe(self._cfg())
        with patch.object(intake, "_run_git_step", side_effect=real_child), patch.object(
            intake, "_output_check", side_effect=abort_with_system_exit
        ):
            self.assertTrue(probe.start_background_probe())
            self.assertTrue(probe.wait_for_probe(6.0))
            if probe._worker_thread is not None:
                probe._worker_thread.join(timeout=3.0)

        # Verify: real child was spawned, finalized cleanly on SystemExit, NOT left RUNNING, and sibling is untouched!
        self.assertGreaterEqual(len(recorded_pids), 1, "Expected real child PID to be spawned before interruption")
        for pid in recorded_pids:
            self.assertFalse(_is_os_pid_alive(pid), f"N02 REPRODUCED: child PID {pid} survived SystemExit!")

        reg = intake.inspect_lingering_registry_state(step_prefix="opengrep-health-")
        self.assertEqual(reg["matching_count"], 0, f"N02 REPRODUCED: leaked health registry entry after SystemExit! {reg}")
        self.assertIsNone(control.poll(), "Unrelated control sibling process must NEVER be killed!")

        # Boundary: if `_finalize_tree` fails during SystemExit, entry MUST stay PENDING & shutdown MUST report CLEANUP_FAILED
        real_fin = intake._finalize_tree

        def failing_fin(entry, step, deadline):
            res = real_fin(entry, step, deadline)
            intake._transition(entry, intake._STATE_PENDING, terminal=True)
            res["clean"] = False
            res["registry_state"] = intake._STATE_PENDING
            return res

        probe2 = og.OpenGrepHealthProbe(self._cfg())
        try:
            with patch.object(intake, "_run_git_step", side_effect=real_child), patch.object(
                intake, "_output_check", side_effect=abort_with_system_exit
            ), patch.object(intake, "_finalize_tree", side_effect=failing_fin):
                self.assertTrue(probe2.start_background_probe())
                self.assertTrue(probe2.wait_for_probe(6.0))
                if probe2._worker_thread is not None:
                    probe2._worker_thread.join(timeout=3.0)
            sd2 = probe2.shutdown(wait_seconds=2.0)
            self.assertFalse(sd2["clean"], f"Dirty cleanup under SystemExit must fail closed: {sd2}")
            self.assertEqual(sd2["status"], "CLEANUP_FAILED")
        finally:
            intake._reconcile_lingering_git_jobs(2.0)

    def test_n02_finally_stream_close_fault_never_masks_cleanup_failed(self) -> None:
        """Codex N02: Exception raised by `fh.close()` in `finally:` MUST NEVER replace `_GitStepCleanupFailed`."""
        class CloseFault:
            def __init__(self, fh):
                self._fh = fh

            def __getattr__(self, key):
                return getattr(self._fh, key)

            def close(self):
                self._fh.close()
                raise ValueError("audit close fault")

        real_tmp = intake.tempfile.TemporaryFile
        real_fin = intake._finalize_tree

        def dirty_fin(entry, step, deadline):
            out = real_fin(entry, step, deadline)
            out["clean"] = False
            return out

        cancel = threading.Event()
        cancel.set()
        with patch.object(intake.tempfile, "TemporaryFile", side_effect=lambda: CloseFault(real_tmp())), patch.object(
            intake, "_finalize_tree", side_effect=dirty_fin
        ):
            with self.assertRaises(intake._GitStepCleanupFailed) as ctx:
                intake._run_git_step(
                    "opengrep-health-audit-close",
                    [sys.executable, "-B", "-c", "import time; time.sleep(1)"],
                    timeout_seconds=1.0,
                    env=os.environ.copy(),
                    cancel_event=cancel,
                )
        self.assertFalse(ctx.exception.cleanup["clean"])
        self.assertEqual(ctx.exception.primary_outcome, "cancelled")
        self.assertTrue(
            ctx.exception.cleanup.get("stream_close_errors"),
            f"Secondary stream close error should be recorded cleanly in cleanup metadata: {ctx.exception.cleanup}",
        )

        # Positive control: clean cancel without fault still raises _GitStepCancelled cleanly
        cancel2 = threading.Event()
        cancel2.set()
        with self.assertRaises(intake._GitStepCancelled) as ctx_clean:
            intake._run_git_step(
                "opengrep-health-audit-clean-cancel",
                [sys.executable, "-B", "-c", "import time; time.sleep(1)"],
                timeout_seconds=1.0,
                env=os.environ.copy(),
                cancel_event=cancel2,
            )
        self.assertTrue(ctx_clean.exception.cleanup["clean"])


class TestN03CanaryOracleCounterexamples(unittest.TestCase):
    """N03: Canary dataflow trace content/span/offset, canonical path, and per-rule taint mode."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ntk_n03_")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.rules_info = og.inspect_rules_for_canary(DEFAULT_BACKEND_RULES)
        self.assertTrue(self.rules_info["ok"], self.rules_info)
        self.raw_doc = _load_real_canary_doc()

    def _verify(self, doc: dict, rules_info: dict | None = None, expected_path: Path | None = None):
        kwargs = {
            "expected_version_tuple": (1, 25, 0),
            "rules_info": rules_info or self.rules_info,
        }
        if expected_path is not None:
            kwargs["expected_canary_path"] = expected_path
        return og.verify_canary_scan_output(json.dumps(doc).encode("utf-8"), **kwargs)

    def test_n03_real_opengrep_raw_positive_control_and_lf_variant_pass(self) -> None:
        """Positive control: Real OpenGrep 1.25.0 raw output (CRLF offsets) and LF-offset equivalent both PASS."""
        exec_ok, ver_ok, summary, fcode, err = self._verify(copy.deepcopy(self.raw_doc))
        self.assertTrue(exec_ok and ver_ok, f"Real OpenGrep raw control failed: {fcode} {err} {summary}")

        # Convert offsets from CRLF to LF (subtract line - 1 from each offset) -> must also PASS!
        lf_doc = copy.deepcopy(self.raw_doc)

        def _to_lf(loc: dict):
            loc["start"]["offset"] -= loc["start"]["line"] - 1
            loc["end"]["offset"] -= loc["end"]["line"] - 1

        for r in lf_doc["results"]:
            _to_lf(r)
            tr = r["extra"]["dataflow_trace"]
            _to_lf(tr["taint_source"][1][0])
            _to_lf(tr["taint_sink"][1][0])
            for iv in tr.get("intermediate_vars") or []:
                _to_lf(iv["location"])

        exec_lf, ver_lf, _sum_lf, fcode_lf, err_lf = self._verify(lf_doc)
        self.assertTrue(exec_lf and ver_lf, f"LF-offset canary failed: {fcode_lf} {err_lf}")

    def test_n03_wrong_content_col_or_offset_on_same_line_rejected(self) -> None:
        """Codex N03: Wrong content, col, or offset on the same line MUST be rejected."""
        def _src(d):
            return d["results"][0]["extra"]["dataflow_trace"]["taint_source"][1]

        def _sink(d):
            return d["results"][0]["extra"]["dataflow_trace"]["taint_sink"][1]

        mutations = {
            "codex_n03_wrong_content_and_pos": lambda d: (
                _src(d).__setitem__(1, "unrelated"),
                _src(d)[0]["start"].update(col=1, offset=0),
            ),
            "wrong_source_content_only": lambda d: _src(d).__setitem__(1, "unrelated"),
            "wrong_source_slice_same_line": lambda d: (
                _src(d).__setitem__(1, "String"),
                _src(d)[0]["start"].update(col=9, offset=261),
                _src(d)[0]["end"].update(col=15, offset=267),
            ),
            "wrong_source_col_only": lambda d: _src(d)[0]["start"].update(col=20),
            "wrong_source_offset_only": lambda d: _src(d)[0]["start"].update(offset=0),
            "wrong_sink_content": lambda d: _sink(d).__setitem__(1, "unrelated"),
            "wrong_sink_col": lambda d: _sink(d)[0]["end"].update(col=60),
            "wrong_intermediate_content": lambda d: d["results"][0]["extra"]["dataflow_trace"]["intermediate_vars"][0].update(content="bogus"),
            "wrong_finding_col": lambda d: d["results"][0]["start"].update(col=1, offset=0),
            "mixed_lf_and_crlf_offsets": lambda d: (
                _src(d)[0]["start"].update(offset=_src(d)[0]["start"]["offset"] - 8),
                _src(d)[0]["end"].update(offset=_src(d)[0]["end"]["offset"] - 8),
            ),
        }
        for label, mut in mutations.items():
            with self.subTest(case=label):
                d = copy.deepcopy(self.raw_doc)
                mut(d)
                _ex, ver_ok, _s, fcode, _e = self._verify(d)
                self.assertFalse(ver_ok, f"N03 REPRODUCED ({label}): oracle wrongly accepted mutated trace/span!")
                self.assertEqual(fcode, "CANARY_ORACLE_MISMATCH")

    def test_n03_wrong_same_basename_file_rejected(self) -> None:
        """Codex N03: Trace/finding path with same basename in different directory MUST be rejected."""
        wrong_path = "other/" + og.HEALTH_CANARY_FILENAME
        mutations = {
            "codex_n03_source_same_basename": lambda d: d["results"][0]["extra"]["dataflow_trace"]["taint_source"][1][0].update(path=wrong_path),
            "sink_same_basename": lambda d: d["results"][1]["extra"]["dataflow_trace"]["taint_sink"][1][0].update(path=wrong_path),
            "inter_same_basename": lambda d: d["results"][0]["extra"]["dataflow_trace"]["intermediate_vars"][0]["location"].update(path=wrong_path),
            "finding_same_basename": lambda d: d["results"][0].update(path=wrong_path),
        }
        for label, mut in mutations.items():
            with self.subTest(case=label):
                d = copy.deepcopy(self.raw_doc)
                mut(d)
                _ex, ver_ok, _s, fcode, _e = self._verify(d)
                self.assertFalse(ver_ok, f"N03 REPRODUCED ({label}): wrong same-basename path accepted!")
                self.assertEqual(fcode, "CANARY_ORACLE_MISMATCH")

        # Expected canary path mismatch when caller provides actual temp file path
        _ex, ver_ok, _s, fcode, _e = self._verify(
            copy.deepcopy(self.raw_doc),
            expected_path=self.root / "actual_tmp" / og.HEALTH_CANARY_FILENAME,
        )
        self.assertFalse(ver_ok, "Mismatched expected_canary_path must be rejected")
        self.assertIn(fcode, ("CANARY_FILE_NOT_SCANNED", "CANARY_ORACLE_MISMATCH"))

    def test_n03_mixed_search_and_taint_rules_still_require_taint_trace(self) -> None:
        """Codex N03: Adding search-mode rules for CWE-22/89 MUST NOT exempt taint-mode rule findings from trace validation."""
        original = yaml.safe_load(DEFAULT_BACKEND_RULES.read_bytes())
        mixed = copy.deepcopy(original)
        for idx, cwe_label in enumerate(("CWE-89: SQL Injection", "CWE-22: Path Traversal")):
            mixed["rules"].append(
                {
                    "id": f"audit.search.{idx}",
                    "languages": ["java"],
                    "metadata": {"cwe": [cwe_label]},
                    "message": "audit search fixture",
                    "severity": "ERROR",
                    "pattern": "placeholder()",
                }
            )
        mixed_file = self.root / "mixed_rules.yml"
        mixed_file.write_text(yaml.safe_dump(mixed), encoding="utf-8")
        ri = og.inspect_rules_for_canary(mixed_file)
        self.assertTrue(ri["ok"], ri)

        # 1. Exact Codex N03: taint-rule findings with dataflow_trace removed -> MUST REJECT!
        d_no_trace = copy.deepcopy(self.raw_doc)
        for item in d_no_trace["results"]:
            item["extra"].pop("dataflow_trace")
        _ex, ver_ok, _s, fcode, _e = self._verify(d_no_trace, rules_info=ri)
        self.assertFalse(ver_ok, "N03 REPRODUCED: mixed search/taint ruleset accepted taint findings without trace!")
        self.assertEqual(fcode, "CANARY_ORACLE_MISMATCH")

        # 2. Boundary: only search-mode rule fires (without trace) while taint rule is silent -> MUST REJECT!
        d_search_only = copy.deepcopy(self.raw_doc)
        d_search_only["results"][0]["check_id"] = "audit.search.0"
        d_search_only["results"][0]["extra"].pop("dataflow_trace")
        _ex2, ver_ok2, _s2, fcode2, _e2 = self._verify(d_search_only, rules_info=ri)
        self.assertFalse(ver_ok2, "Search-only finding must not mask missing taint trace when ruleset has taint rules!")
        self.assertEqual(fcode2, "CANARY_ORACLE_MISMATCH")

        # 3. Positive control: valid taint findings WITH valid traces in mixed ruleset -> MUST PASS!
        exec_ok3, ver_ok3, _s3, fcode3, err3 = self._verify(copy.deepcopy(self.raw_doc), rules_info=ri)
        self.assertTrue(exec_ok3 and ver_ok3, f"Valid mixed-mode taint findings wrongly rejected: {fcode3} {err3}")


class TestN04ExecutionChainIdentityCounterexamples(unittest.TestCase):
    """N04: Fail-closed execution-chain bounds, unresolved targets, and unambiguous WSL target verification."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ntk_n04_")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.rules = self.root / "rules.yml"
        self.rules.write_bytes(DEFAULT_BACKEND_RULES.read_bytes())

    def _put(self, subdir: Path, rel: str, text: str) -> Path:
        p = subdir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        return p

    def _cfg(self, wrapper: Path) -> ApiConfig:
        return ApiConfig(
            data_dir=self.root / f"data_{time.monotonic_ns()}",
            rules_path=self.rules,
            opengrep_binary=str(wrapper),
            api_token="audit-n04-token",
            port=0,
        )

    def test_n04_depth_limit_exceeded_fails_closed_and_within_limit_passes(self) -> None:
        """Codex N04: Dependency chain deeper than _MAX_CHAIN_DEPTH MUST fail closed, never silently truncate."""
        d_deep = self.root / "deep"
        w = self._put(d_deep, "opengrep.cmd", "@echo off\npython.exe bridge.py\n")
        self._put(d_deep, "bridge.py", "import layer0\n")
        for i in range(7):
            self._put(d_deep, f"layer{i}.py", f"import layer{i + 1}\n" if i < 6 else "value = 1\n")

        ident = og.inspect_opengrep_binary_identity(str(w))
        self.assertFalse(ident["found"], f"N04 REPRODUCED: depth > 4 silently accepted! {ident}")
        self.assertTrue(ident.get("binary_exists"))
        self.assertFalse(ident.get("identity_complete", True))
        self.assertIsNone(ident["binary_identity_sha256"])
        self.assertEqual(ident["failure_code"], "CHAIN_DEPTH_EXCEEDED")

        probe = og.OpenGrepHealthProbe(self._cfg(w))
        self.addCleanup(probe.shutdown)
        with patch.object(intake, "_run_git_step", side_effect=_make_canary_step_stub()):
            probe.start_background_probe()
            probe.wait_for_probe(5.0)
            st = probe.get_status(trigger_refresh=False)
        self.assertFalse(st["available"])
        self.assertNotEqual(st["probe_status"], "VERIFIED")
        self.assertEqual(st["failure_code"], "CHAIN_DEPTH_EXCEEDED")

        # Boundary positive control: exact depth 4 leaf (`opengrep.cmd` d0 -> `bridge.py` d1 -> `l0` d2 -> `l1` d3 -> `l2` d4)
        d_ok = self.root / "depth_ok"
        w_ok = self._put(d_ok, "opengrep.cmd", "@echo off\npython.exe bridge.py\n")
        self._put(d_ok, "bridge.py", "import l0\n")
        self._put(d_ok, "l0.py", "import l1\n")
        self._put(d_ok, "l1.py", "import l2\n")
        self._put(d_ok, "l2.py", "LEAF = 1\n")
        ident_ok = og.inspect_opengrep_binary_identity(str(w_ok))
        self.assertTrue(ident_ok["found"], ident_ok)
        self.assertIsNotNone(ident_ok["binary_identity_sha256"])

    def test_n04_file_cap_exceeded_fails_closed_and_within_cap_passes(self) -> None:
        """Codex N04: Dependency count exceeding _MAX_CHAIN_FILES (64) MUST fail closed."""
        d_cap = self.root / "cap_over"
        w = self._put(d_cap, "opengrep.cmd", "@echo off\npython.exe bridge.py\n")
        self._put(d_cap, "bridge.py", "".join(f"import mod{i}\n" for i in range(65)))
        for i in range(65):
            self._put(d_cap, f"mod{i}.py", "value = 1\n")

        ident = og.inspect_opengrep_binary_identity(str(w))
        self.assertFalse(ident["found"], f"N04 REPRODUCED: >64 files silently truncated! {ident}")
        self.assertTrue(ident.get("binary_exists"))
        self.assertFalse(ident.get("identity_complete", True))
        self.assertIsNone(ident["binary_identity_sha256"])
        self.assertEqual(ident["failure_code"], "CHAIN_FILE_LIMIT_EXCEEDED")

        # Positive boundary: bridge.py + 63 modules = 64 files total -> MUST PASS!
        d_exact = self.root / "cap_exact"
        w_ok = self._put(d_exact, "opengrep.cmd", "@echo off\npython.exe bridge.py\n")
        self._put(d_exact, "bridge.py", "".join(f"import mod{i}\n" for i in range(63)))
        for i in range(63):
            self._put(d_exact, f"mod{i}.py", "value = 1\n")
        ident_ok = og.inspect_opengrep_binary_identity(str(w_ok))
        self.assertTrue(ident_ok["found"], ident_ok)
        self.assertEqual(len(ident_ok["wrapper_targets"]), 64)

    def test_n04_unresolved_interpreter_script_and_broken_bridge_fail_closed(self) -> None:
        """Codex N04: Missing wrapper interpreter/script, syntax errors, and dynamic imports MUST fail closed."""
        # 1. Exact Codex N04 missing interpreter + absent script
        d1 = self.root / "unres"
        w1 = self._put(d1, "opengrep.cmd", '@echo off\n"C:/missing-audit/python.exe" absent.py\n')
        id1 = og.inspect_opengrep_binary_identity(str(w1))
        self.assertFalse(id1["found"], f"N04 REPRODUCED: missing interpreter/script accepted! {id1}")
        self.assertTrue(id1.get("binary_exists"))
        self.assertIsNone(id1["binary_identity_sha256"])
        self.assertEqual(id1["failure_code"], "WRAPPER_TARGET_UNRESOLVED")

        # Verify OpenGrepHealthProbe keeps verification_level="BINARY_FOUND" for existing broken wrapper
        probe = og.OpenGrepHealthProbe(self._cfg(w1))
        self.addCleanup(probe.shutdown)
        st = probe.get_status(trigger_refresh=False)
        self.assertFalse(st["available"])
        self.assertEqual(st["verification_level"], "BINARY_FOUND")
        self.assertEqual(st["failure_code"], "WRAPPER_TARGET_UNRESOLVED")

        # 2. Boundary: SyntaxError in bridge.py -> fail closed
        d2 = self.root / "bad_py"
        w2 = self._put(d2, "opengrep.cmd", "@echo off\npython.exe bridge.py\n")
        self._put(d2, "bridge.py", "def broken(:\n")
        id2 = og.inspect_opengrep_binary_identity(str(w2))
        self.assertFalse(id2["found"], id2)
        self.assertIsNone(id2["binary_identity_sha256"])

        # 3. Boundary: Unresolved relative import -> fail closed
        d3 = self.root / "bad_rel"
        w3 = self._put(d3, "opengrep.cmd", "@echo off\npython.exe bridge.py\n")
        self._put(d3, "bridge.py", "from . import absent_helper\n")
        id3 = og.inspect_opengrep_binary_identity(str(w3))
        self.assertFalse(id3["found"], id3)
        self.assertIsNone(id3["binary_identity_sha256"])

        # 4. Boundary: Dynamic importlib.import_module(var) -> fail closed
        d4 = self.root / "dyn_imp"
        w4 = self._put(d4, "opengrep.cmd", "@echo off\npython.exe bridge.py\n")
        self._put(d4, "bridge.py", "import importlib\nname = 'x'\nimportlib.import_module(name)\n")
        id4 = og.inspect_opengrep_binary_identity(str(w4))
        self.assertFalse(id4["found"], id4)
        self.assertIsNone(id4["binary_identity_sha256"])

    def test_n04_ambiguous_or_dynamic_wsl_target_rejected_and_admin_pc_bridge_shape_accepted(self) -> None:
        """Codex N04: Conflicting/dynamic WSL commands MUST fail closed; single target + trailing *args MUST pass."""
        base_stub = _make_canary_step_stub()

        def wsl_stub(step, args, **kw):
            if step.endswith("realpath"):
                return _make_stub_proc(args, b"/usr/local/bin/opengrep\n")
            if step.endswith("sha256"):
                return _make_stub_proc(args, b"a" * 64 + b"  /usr/local/bin/opengrep\n")
            return base_stub(step, args, **kw)

        # 1. Conflicting reachable WSL targets (aligned with active N04-R1-B/R2 call-site reachability contract;
        # unreferenced dead constants are tested separately in test_n04_r2_call_site_reachability.py) -> MUST fail closed!
        d_amb = self.root / "wsl_amb"
        w_amb = self._put(d_amb, "opengrep.cmd", "@echo off\npython.exe bridge.py\n")
        self._put(
            d_amb,
            "bridge.py",
            'import os, subprocess\n'
            'primary=["wsl.exe","-d","Audit","--","/usr/local/bin/opengrep"]\n'
            'alternate=["wsl.exe","-d","Audit","--","/opt/opengrep"]\n'
            'selected=alternate if os.environ.get("USE_ALT") else primary\n'
            'subprocess.run(selected)\n',
        )
        id_amb = og.inspect_opengrep_binary_identity(str(w_amb))
        self.assertFalse(id_amb["found"], f"N04 REPRODUCED: ambiguous WSL candidates accepted! {id_amb}")
        self.assertEqual(id_amb["failure_code"], "WSL_TARGET_AMBIGUOUS")

        probe_amb = og.OpenGrepHealthProbe(self._cfg(w_amb))
        self.addCleanup(probe_amb.shutdown)
        with patch.object(intake, "_run_git_step", side_effect=wsl_stub):
            snap_amb = probe_amb._execute_probe_once()[0]
        self.assertNotEqual(snap_amb["probe_status"], "VERIFIED", f"N04 REPRODUCED: ambiguous WSL verified! {snap_amb}")
        self.assertIsNone(snap_amb["wsl_binary_identity"])

        # 2. Boundary: Dynamic WSL binary path or shell wrapper -> WSL_TARGET_UNRESOLVABLE
        for label, body in (
            ("dynamic_bin", 'import subprocess\nbin_p="/opt/og"\nsubprocess.run(["wsl.exe","-d","Audit","--",bin_p])\n'),
            ("dynamic_distro", 'import subprocess\nd="Audit"\nsubprocess.run(["wsl.exe","-d",d,"--","/usr/local/bin/opengrep"])\n'),
            ("shell_wrapper", 'import subprocess\nsubprocess.run(["wsl.exe","-d","Audit","--","/bin/sh","-c","/opt/og"])\n'),
            ("split_concat", 'import subprocess\ncmd=["wsl.exe","-d","Audit","--"] + ["/opt/og"]\nsubprocess.run(cmd)\n'),
        ):
            with self.subTest(case=label):
                dd = self.root / f"wsl_{label}"
                wd = self._put(dd, "opengrep.cmd", "@echo off\npython.exe bridge.py\n")
                self._put(dd, "bridge.py", body)
                idd = og.inspect_opengrep_binary_identity(str(wd))
                self.assertFalse(idd["found"], f"{label} should fail closed: {idd}")
                self.assertEqual(idd["failure_code"], "WSL_TARGET_UNRESOLVABLE")

        # 3. Positive control: ADMIN-PC bridge shape with single WSL executable + trailing dynamic `*args`
        d_ok = self.root / "wsl_ok"
        w_ok = self._put(d_ok, "opengrep.cmd", f'@echo off\n"{sys.executable}" "{d_ok / "opengrep_counted.py"}" %*\n')
        self._put(
            d_ok,
            "opengrep_counted.py",
            'import subprocess, sys\n'
            'extra = sys.argv[1:]\n'
            'cmd = ["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep", *extra]\n'
            'subprocess.run(cmd, check=False)\n',
        )
        id_ok = og.inspect_opengrep_binary_identity(str(w_ok))
        self.assertTrue(id_ok["found"], id_ok)
        self.assertEqual(
            id_ok["wsl_target"],
            {"detected": True, "distro": "Ubuntu-IRIS", "linux_binary_path": "/usr/local/bin/opengrep"},
        )

        # 4. Boundary: Mid-probe WSL binary SHA-256 mutation (pre vs post check) -> INPUT_CHANGED_DURING_PROBE
        sha_calls = {"n": 0}

        def mutating_wsl_stub(step, args, **kw):
            if step.endswith("realpath"):
                return _make_stub_proc(args, b"/opt/opengrep/cli/v1.25.0/opengrep\n")
            if step.endswith("sha256"):
                sha_calls["n"] += 1
                h = (b"a" * 64) if sha_calls["n"] == 1 else (b"b" * 64)
                return _make_stub_proc(args, h + b"  /opt/opengrep/cli/v1.25.0/opengrep\n")
            return base_stub(step, args, **kw)

        probe_mut = og.OpenGrepHealthProbe(self._cfg(w_ok))
        self.addCleanup(probe_mut.shutdown)
        with patch.object(intake, "_run_git_step", side_effect=mutating_wsl_stub):
            snap_mut = probe_mut._execute_probe_once()[0]
        self.assertFalse(snap_mut["available"], f"Mid-probe WSL binary swap must NOT commit VERIFIED: {snap_mut}")
        self.assertEqual(snap_mut["probe_status"], "NOT_VERIFIED")
        self.assertEqual(snap_mut["failure_code"], "INPUT_CHANGED_DURING_PROBE")


class TestN05JavaShadowingAndHelperGateCounterexamples(unittest.TestCase):
    """N05: JLS §6.5.2 variable/field/TypeName shadowing on `java.lang.System.out` and qualified stdlib calls."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ntk_n05_")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def _eval(
        self,
        name: str,
        code: str,
        *,
        sink_line: int,
        source_line: int,
        unresolved_calls: list[dict] | None = None,
        truncate_before_line: int | None = None,
        drop_disk_root: bool = False,
    ) -> tuple[dict, dict]:
        case_dir = self.root / name
        rec = _make_record(
            case_dir,
            "Example.java",
            code,
            sink_line=sink_line,
            source_line=source_line,
            unresolved_calls=unresolved_calls,
        )
        if truncate_before_line is not None:
            rec["snippets"][0]["lines"] = [
                ln for ln in rec["snippets"][0]["lines"] if ln["line"] >= truncate_before_line
            ]
            if drop_disk_root:
                rec["root"] = str(case_dir / "absent_root")
                jctx = dict(rec.get("java_context") or {})
                enc = dict(jctx.get("enclosing_method") or {})
                enc["parameters"] = []
                enc["header_line"] = truncate_before_line - 1
                jctx["enclosing_method"] = enc
                jctx.pop("enclosing_class_field_types", None)
                jctx.pop("enclosing_class_fields", None)
                rec["java_context"] = jctx
        dep = analyze_flow_dependencies(rec)
        gated = apply_integration_gate(rec, _supported_assessment(rec, sink_line))
        return dep, gated

    def test_n05_javac_valid_variable_java_shadowing_java_lang_system_out_fails_closed(self) -> None:
        """Codex N05: Valid compilable Java `void run(Root java)` + `java.lang.System.out.format` MUST be UNDETERMINED."""
        code = (
            "import java.io.FileInputStream;\n"
            "class Example {\n"
            "  static class Root { Lang lang = new Lang(); }\n"
            "  static class Lang { Sys System = new Sys(); }\n"
            "  static class Sys { AppPrinter out = new AppPrinter(); }\n"
            "  static class AppPrinter { String format(String s) { return s; } }\n"
            "  void run(Root java) throws Exception {\n"
            '    var item = java.lang.System.out.format("item");\n'
            "    new FileInputStream(item);\n"
            "  }\n"
            "}\n"
        )
        javac = shutil.which("javac")
        if javac:
            jc_dir = self.root / "javac_check"
            jc_dir.mkdir(parents=True, exist_ok=True)
            (jc_dir / "Example.java").write_text(code, encoding="utf-8")
            cp = subprocess.run([javac, "-d", str(jc_dir), str(jc_dir / "Example.java")], capture_output=True, text=True, timeout=30)
            self.assertEqual(cp.returncode, 0, f"Fixture must be valid Java: {cp.stderr}")

        dep, gated = self._eval("n05_var_java", code, sink_line=9, source_line=8)
        self.assertTrue(dep["has_unverified_helper_dependency"], f"N05 REPRODUCED: `Root java` bypassed gate! {dep}")
        self.assertEqual(gated["validated_status"], "UNDETERMINED")
        self.assertEqual(gated["failure_kind"], "UNVERIFIED_HELPER_FLOW")

        # Monotonicity boundary: truncating `Root java` with absent disk root must stay UNDETERMINED
        dep_t, gated_t = self._eval(
            "n05_var_java_trunc", code, sink_line=9, source_line=8, truncate_before_line=8, drop_disk_root=True
        )
        self.assertTrue(dep_t["has_unverified_helper_dependency"], dep_t)
        self.assertEqual(gated_t["validated_status"], "UNDETERMINED")

    def test_n05_chained_err_bottom_field_typename_and_passthrough_shadowing_variants(self) -> None:
        """Boundary N05 variants: chained call, System.err, field declared after method, TypeName `class java`, passthrough."""
        # 1. Chained call on shadowed `java.lang.System.out.format(...).trim()`
        code_chain = (
            "import java.io.FileInputStream;\n"
            "class Example {\n"
            "  void run(AppRequest java) throws Exception {\n"
            '    var item = java.lang.System.out.format("item").trim();\n'
            "    new FileInputStream(item);\n"
            "  }\n"
            "}\n"
        )
        dep1, g1 = self._eval("n05_chain", code_chain, sink_line=5, source_line=4)
        self.assertTrue(dep1["has_unverified_helper_dependency"], dep1)
        self.assertEqual(g1["validated_status"], "UNDETERMINED")

        # 2. `java.lang.System.err.format(...)` shadowed by `java`
        code_err = code_chain.replace("System.out.format(\"item\").trim()", 'System.err.format("item")')
        dep2, g2 = self._eval("n05_err", code_err, sink_line=5, source_line=4)
        self.assertTrue(dep2["has_unverified_helper_dependency"], dep2)
        self.assertEqual(g2["validated_status"], "UNDETERMINED")

        # 3. Class field `private Root java;` declared AFTER the method
        code_field_after = (
            "import java.io.FileInputStream;\n"
            "class Example {\n"
            "  void run() throws Exception {\n"
            '    var item = java.lang.System.out.format("item");\n'
            "    new FileInputStream(item);\n"
            "  }\n"
            "  private AppRoot java;\n"
            "}\n"
        )
        dep3, g3 = self._eval("n05_field_after", code_field_after, sink_line=5, source_line=4)
        self.assertTrue(dep3["has_unverified_helper_dependency"], dep3)
        self.assertEqual(g3["validated_status"], "UNDETERMINED")

        # 4. TypeName shadowing: nested `static class java` shadows package `java` (valid javac!)
        code_type_shadow = (
            "import java.io.FileInputStream;\n"
            "class Example {\n"
            "  static class java {\n"
            "    static class lang {\n"
            "      static class System { static AppPrinter out = new AppPrinter(); }\n"
            "    }\n"
            "  }\n"
            "  static class AppPrinter { String format(String s) { return s; } }\n"
            "  void run() throws Exception {\n"
            '    var item = java.lang.System.out.format("item");\n'
            "    new FileInputStream(item);\n"
            "  }\n"
            "}\n"
        )
        javac = shutil.which("javac")
        if javac:
            jc_dir = self.root / "javac_type_shadow"
            jc_dir.mkdir(parents=True, exist_ok=True)
            (jc_dir / "Example.java").write_text(code_type_shadow, encoding="utf-8")
            cp = subprocess.run([javac, "-d", str(jc_dir), str(jc_dir / "Example.java")], capture_output=True, text=True, timeout=30)
            self.assertEqual(cp.returncode, 0, f"TypeName shadow fixture must be valid Java: {cp.stderr}")

        dep4, g4 = self._eval("n05_type_shadow", code_type_shadow, sink_line=11, source_line=10)
        self.assertTrue(dep4["has_unverified_helper_dependency"], dep4)
        self.assertEqual(g4["validated_status"], "UNDETERMINED")

        # 5. Variable named `String` shadowing `_STD_TAINT_PASSTHROUGH_CALLS` (`String.valueOf`)
        code_pass = (
            "import java.io.FileInputStream;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "class Example {\n"
            "  void run(HttpServletRequest req, AppHelper String) throws Exception {\n"
            '    var item = String.valueOf(req.getParameter("item"));\n'
            '    new FileInputStream("" + item);\n'
            "  }\n"
            "}\n"
        )
        dep5, g5 = self._eval(
            "n05_passthrough_shadow",
            code_pass,
            sink_line=6,
            source_line=5,
            unresolved_calls=[{"qualifier": "String", "method": "valueOf", "line": 5}],
        )
        self.assertTrue(dep5["has_unverified_helper_dependency"], dep5)
        self.assertEqual(g5["validated_status"], "UNDETERMINED")

    def test_n05_positive_controls_valid_stdlib_and_midfile_verified_source_stay_supported(self) -> None:
        """Positive controls: genuine stdlib calls (including mid-file snippet backed by SHA-256 verified source) stay SUPPORTED."""
        # 1. Valid `java.lang.String.valueOf(req.getParameter("item"))`
        code_str = (
            "import java.io.FileInputStream;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "class Example {\n"
            "  void run(HttpServletRequest req) throws Exception {\n"
            '    var item = java.lang.String.valueOf(req.getParameter("item"));\n'
            '    new FileInputStream("" + item);\n'
            "  }\n"
            "}\n"
        )
        dep1, g1 = self._eval("n05_pos_str", code_str, sink_line=6, source_line=5)
        self.assertFalse(dep1["has_unverified_helper_dependency"], dep1)
        self.assertEqual(g1["validated_status"], "SUPPORTED")

        # 2. Valid `java.lang.System.out.format(...)`, `System.out.format(...)`, and `java.lang.Integer.parseInt(...)`
        code_sys = (
            "import java.io.FileInputStream;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "class Example {\n"
            "  void run(HttpServletRequest req) throws Exception {\n"
            '    var raw = req.getParameter("item");\n'
            '    var item = java.lang.System.out.format(raw);\n'
            '    var log2 = System.out.format("%s", item);\n'
            '    int n = java.lang.Integer.parseInt("42");\n'
            '    new FileInputStream("" + item + log2 + n);\n'
            "  }\n"
            "}\n"
        )
        dep2, g2 = self._eval("n05_pos_sys", code_sys, sink_line=9, source_line=5)
        self.assertFalse(dep2["has_unverified_helper_dependency"], dep2)
        self.assertEqual(g2["validated_status"], "SUPPORTED")

        # 3. Mid-file snippet WITH valid disk source + matching SHA-256 -> MUST stay SUPPORTED (no over-downgrade!)
        padding = "\n".join(f"  // pad {i}" for i in range(1, 55))
        code_mid = (
            "import java.io.FileInputStream;\n"
            "import javax.servlet.http.HttpServletRequest;\n"
            "class Example {\n"
            f"{padding}\n"
            "  void run(HttpServletRequest req) throws Exception {\n"
            '    var item = java.lang.String.valueOf(req.getParameter("item"));\n'
            '    java.lang.System.out.format("log: %s", item);\n'
            '    new FileInputStream("" + item);\n'
            "  }\n"
            "}\n"
        )
        lines = code_mid.splitlines()
        src_ln = next(i for i, l in enumerate(lines, 1) if "getParameter" in l)
        snk_ln = next(i for i, l in enumerate(lines, 1) if "FileInputStream(" in l)
        dep3, g3 = self._eval("n05_pos_midfile_verified", code_mid, sink_line=snk_ln, source_line=src_ln)
        self.assertFalse(dep3["has_unverified_helper_dependency"], dep3)
        self.assertEqual(g3["validated_status"], "SUPPORTED")


if __name__ == "__main__":
    unittest.main()
