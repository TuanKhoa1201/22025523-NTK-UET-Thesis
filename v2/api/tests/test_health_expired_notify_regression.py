"""Regression tests for OpenGrepHealthProbe expired-VERIFIED recovery via notify_real_scan_completed.

Verifies the exact staging defect where a previously VERIFIED snapshot expired past its TTL while
no GET /api/health arrived, a real Stage 2 OpenGrep scan completed and called
notify_real_scan_completed(), and the probe previously returned False instead of clearing the
expired snapshot and spawning one single-flight active canary re-probe.
"""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from v2.api.config import ApiConfig
from v2.api.opengrep_runner import OpenGrepHealthProbe
from v2.api.tests.test_health_opengrep_active_probe import (
    VALID_MINIMAL_RULES_YAML,
    _write_canary_wrapper,
)


class TestHealthExpiredNotifyRegression(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory(prefix="ntk_health_exp_notify_")
        self.root = Path(self._td.name)
        self.rules = self.root / "rules.yml"
        self.rules.write_text(VALID_MINIMAL_RULES_YAML, encoding="utf-8")

    def tearDown(self) -> None:
        self._td.cleanup()

    def _cfg(
        self,
        binary: str,
        *,
        ttl: float = 60.0,
        timeout: float = 10.0,
        data_sub: str = "data",
    ) -> ApiConfig:
        return ApiConfig(
            host="127.0.0.1",
            port=0,
            data_dir=self.root / data_sub,
            rules_path=self.rules,
            opengrep_binary=binary,
            ollama_endpoint="http://127.0.0.1:11434",
            api_token="health-expired-notify-test-token-1234",
            opengrep_health_probe_enabled=True,
            opengrep_health_probe_ttl_seconds=ttl,
            opengrep_health_probe_timeout_seconds=timeout,
        )

    def test_expired_verified_snapshot_triggers_canary_on_real_scan_completed_without_faking_verified(self) -> None:
        log_f = self.root / "og_ok" / "inv.log"
        wrapper, _ = _write_canary_wrapper(self.root / "og_ok", sleep_scan=0.4, log_file=log_f)
        now_box = {"t": 1000.0}
        probe = OpenGrepHealthProbe(self._cfg(str(wrapper), ttl=60.0), clock=lambda: now_box["t"])
        self.addCleanup(probe.shutdown)

        # 1. Initial probe -> VERIFIED
        self.assertTrue(probe.start_background_probe())
        self.assertTrue(probe.wait_for_probe(timeout=10.0))
        st1 = probe.get_status(trigger_refresh=False)
        self.assertTrue(st1["available"])
        self.assertEqual(st1["probe_status"], "VERIFIED")
        self.assertEqual(probe.probe_run_count(), 1)

        # 2. Fresh VERIFIED: notify_real_scan_completed MUST NOT spawn a redundant probe
        now_box["t"] += 30.0
        self.assertFalse(probe.notify_real_scan_completed(engine_version="1.25.0"))
        self.assertEqual(probe.probe_run_count(), 1)

        # 3. Advance clock past TTL without calling get_status() first -> snapshot is expired VERIFIED
        now_box["t"] += 40.0  # total +70s > 60s TTL
        triggered = probe.notify_real_scan_completed(engine_version="1.25.0")
        self.assertTrue(triggered, "Expired VERIFIED snapshot must trigger single-flight canary re-probe")

        # Immediately while canary is in flight: MUST NOT fake VERIFIED!
        st_mid = probe.get_status(trigger_refresh=False)
        self.assertFalse(st_mid["available"])
        self.assertFalse(st_mid["runtime_verified"])
        self.assertEqual(st_mid["probe_status"], "NOT_VERIFIED")
        self.assertTrue(st_mid["probe_in_progress"])

        # Concurrent notify while in flight must remain single-flight
        self.assertFalse(probe.notify_real_scan_completed(engine_version="1.25.0"))

        # After canary completes -> freshly VERIFIED again without GET /api/health seeing EXPIRED
        self.assertTrue(probe.wait_for_probe(timeout=10.0))
        st_after = probe.get_status(trigger_refresh=True)
        self.assertTrue(st_after["available"])
        self.assertTrue(st_after["runtime_verified"])
        self.assertEqual(st_after["probe_status"], "VERIFIED")
        self.assertEqual(probe.probe_run_count(), 2)

        sd = probe.shutdown(wait_seconds=5.0)
        self.assertTrue(sd["clean"])

    def test_expired_verified_respects_active_scan_busy_guard(self) -> None:
        wrapper, _ = _write_canary_wrapper(self.root / "og_busy")
        now_box = {"t": 2000.0}
        busy_box = {"busy": False}
        probe = OpenGrepHealthProbe(
            self._cfg(str(wrapper), ttl=60.0, data_sub="data_busy"),
            clock=lambda: now_box["t"],
            scan_busy_check=lambda: busy_box["busy"],
        )
        self.addCleanup(probe.shutdown)

        self.assertTrue(probe.start_background_probe())
        self.assertTrue(probe.wait_for_probe(timeout=10.0))
        now_box["t"] += 120.0
        busy_box["busy"] = True
        # Must NOT spawn canary while another Stage 2 OpenGrep scan is busy
        self.assertFalse(probe.notify_real_scan_completed(engine_version="1.25.0"))
        # And get_status must STILL fail-closed as EXPIRED (never fake VERIFIED)
        st_exp = probe.get_status(trigger_refresh=False)
        self.assertFalse(st_exp["available"])
        self.assertEqual(st_exp["probe_status"], "EXPIRED")
        self.assertEqual(st_exp["invalidation_reason"], "SNAPSHOT_EXPIRED")

    def test_four_distinct_health_states_preserved(self) -> None:
        # 1. ENGINE_MISSING -> UNAVAILABLE
        p_missing = OpenGrepHealthProbe(self._cfg(str(self.root / "opengrep_missing.cmd"), data_sub="d_miss"))
        self.addCleanup(p_missing.shutdown)
        st_miss = p_missing.get_status(trigger_refresh=False)
        self.assertFalse(st_miss["available"])
        self.assertEqual(st_miss["probe_status"], "UNAVAILABLE")
        self.assertEqual(st_miss["failure_code"], "BINARY_NOT_FOUND")

        # 2. PROBE_TIMEOUT -> TIMEOUT
        w_to, _ = _write_canary_wrapper(self.root / "og_to", sleep_scan=5.0)
        p_to = OpenGrepHealthProbe(self._cfg(str(w_to), timeout=0.6, data_sub="d_to"))
        self.addCleanup(p_to.shutdown)
        self.assertTrue(p_to.start_background_probe())
        self.assertTrue(p_to.wait_for_probe(timeout=8.0))
        st_to = p_to.get_status(trigger_refresh=False)
        self.assertFalse(st_to["available"])
        self.assertEqual(st_to["probe_status"], "TIMEOUT")
        self.assertEqual(st_to["failure_code"], "PROBE_TIMEOUT")

        # 3. NOT_VERIFIED (initial before probe runs) -> 4. VERIFIED (after real canary passes)
        w_ok, _ = _write_canary_wrapper(self.root / "og_states", sleep_scan=0.25)
        p_ok = OpenGrepHealthProbe(self._cfg(str(w_ok), data_sub="d_ok"))
        self.addCleanup(p_ok.shutdown)
        st_nv = p_ok.get_status(trigger_refresh=False)
        self.assertFalse(st_nv["available"])
        self.assertEqual(st_nv["probe_status"], "NOT_VERIFIED")

        self.assertTrue(p_ok.start_background_probe())
        self.assertTrue(p_ok.wait_for_probe(timeout=8.0))
        st_v = p_ok.get_status(trigger_refresh=False)
        self.assertTrue(st_v["available"])
        self.assertTrue(st_v["runtime_verified"])
        self.assertEqual(st_v["probe_status"], "VERIFIED")
        self.assertEqual(st_v["version"], "1.25.0")


if __name__ == "__main__":
    unittest.main()
