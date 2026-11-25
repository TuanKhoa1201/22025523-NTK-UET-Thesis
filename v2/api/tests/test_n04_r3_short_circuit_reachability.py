"""Counterexample & contract suite for Codex N04-R2-C1: Python BoolOp short-circuit reachability.

All cases execute end-to-end through `.cmd -> Python bridge -> inspect_opengrep_binary_identity()`
without executing the bridge script itself (pure static AST inspection).

Contracts verified:
- Negative controls (statically unevaluated RHS of `and`/`or` MUST NOT be detected as WSL target):
  * `if False and subprocess.run(["wsl.exe", "--", "/usr/local/bin/opengrep"]): pass` (exact Codex F-05)
  * `False and launch()`, `0 and launch()`, `True or launch()`, `1 or launch()`
  * Nested `and`/`or` expressions where an operand is guaranteed not to be evaluated
    (`(True and False) and launch()`, `(False or True) or launch()`, `(not True) and (True or launch())`,
     `flag and False and launch()`, `flag or True or launch()`)
- Positive controls (evaluated operands & side effects MUST be preserved):
  * `False or launch()`, `True and launch()`
  * Left-side side effects before short-circuit: `launch() and False`, `launch() or True`
  * Live operand alongside short-circuited dead operand with a different target resolves ONLY the live target
  * Unknown runtime variable (`flag and launch()`, `flag or launch()`) retains feasible launch
  * Valid ADMIN-PC bridge (`if __name__ == "__main__": sys.exit(main())`) resolves `Ubuntu-IRIS` + `/usr/local/bin/opengrep`
- Security controls (fail-closed):
  * Two genuinely reachable conflicting WSL targets -> `WSL_TARGET_AMBIGUOUS`
  * Dynamic target or distro in a reachable `BoolOp` branch -> `WSL_TARGET_UNRESOLVABLE`
  * Unreferenced documentation tuple beside a valid launch -> no false `WSL_TARGET_AMBIGUOUS`
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from v2.api import opengrep_runner as og


class TestN04R3BoolOpShortCircuitReachability(unittest.TestCase):
    """N04-R2-C1: Python left-to-right short-circuit semantics for ast.BoolOp in static reachability."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ntk_n04_r3_")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def _make_wrapper(self, name: str, bridge_code: str) -> Path:
        sub = self.root / name
        sub.mkdir(parents=True, exist_ok=True)
        bridge = sub / "bridge.py"
        bridge.write_text(bridge_code, encoding="utf-8")
        wrapper = sub / "opengrep.cmd"
        wrapper.write_text(f'@echo off\n"{sys.executable}" "%~dp0bridge.py" %*\n', encoding="utf-8")
        return wrapper

    def test_n04_r2_c1_false_and_true_or_short_circuit_negative_controls(self) -> None:
        """Negative controls: `False and launch()` and `True or launch()` MUST NOT detect a WSL target."""
        cases = {
            "codex_f05_if_false_and_subprocess_run": (
                "import subprocess\n"
                'if False and subprocess.run(["wsl.exe", "--", "/usr/local/bin/opengrep"]):\n'
                "    pass\n"
            ),
            "expr_false_and_helper_launch": (
                "import subprocess\n"
                "def launch():\n"
                '    return subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"])\n'
                "False and launch()\n"
            ),
            "assign_zero_and_launch": (
                "import subprocess\n"
                'res = 0 and subprocess.run(["wsl.exe", "--", "/usr/local/bin/opengrep"])\n'
            ),
            "if_true_or_subprocess_run": (
                "import subprocess\n"
                'if True or subprocess.run(["wsl.exe", "--", "/usr/local/bin/opengrep"]):\n'
                '    print("native")\n'
            ),
            "expr_true_or_helper_launch": (
                "import subprocess\n"
                "def launch():\n"
                '    return subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"])\n'
                "True or launch()\n"
            ),
            "assign_one_or_launch": (
                "import subprocess\n"
                'res = 1 or subprocess.run(["wsl.exe", "--", "/usr/local/bin/opengrep"])\n'
            ),
        }
        for label, code in cases.items():
            with self.subTest(case=label):
                w = self._make_wrapper(f"neg_{label}", code)
                state = og.inspect_opengrep_binary_identity(str(w))
                self.assertTrue(state["found"], f"{label}: expected found=True, observed={state}")
                self.assertTrue(state["identity_complete"], f"{label}: expected identity_complete=True, observed={state}")
                self.assertFalse(
                    state["wsl_target"]["detected"],
                    f"N04-R2-C1 REPRODUCED ({label}): expected wsl_target.detected=False, observed={state['wsl_target']}",
                )

    def test_n04_r2_c1_nested_boolop_dead_branches_negative_controls(self) -> None:
        """Negative controls: nested `and`/`or` short-circuited branches MUST NOT detect a WSL target."""
        cases = {
            "nested_true_and_false_and_launch": (
                "import subprocess\n"
                "def launch():\n"
                '    return subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"])\n'
                "if (True and False) and launch():\n"
                "    pass\n"
            ),
            "nested_false_or_true_or_launch": (
                "import subprocess\n"
                "def launch():\n"
                '    return subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"])\n'
                "(False or True) or launch()\n"
            ),
            "nested_not_true_and_true_or_launch": (
                "import subprocess\n"
                "def launch():\n"
                '    return subprocess.run(["wsl.exe", "--", "/usr/local/bin/opengrep"])\n'
                "if (not True) and (True or launch()):\n"
                "    pass\n"
            ),
            "nested_dead_cond_and_dead_body": (
                "import subprocess\n"
                "def launch():\n"
                '    return subprocess.run(["wsl.exe", "--", "/usr/local/bin/opengrep"])\n'
                "if (False and launch()) or False:\n"
                "    launch()\n"
            ),
            "three_operand_unknown_and_false_and_dead": (
                "import os, subprocess\n"
                'flag = bool(os.environ.get("FLAG"))\n'
                "def launch():\n"
                '    return subprocess.run(["wsl.exe", "--", "/usr/local/bin/opengrep"])\n'
                "if flag and False and launch():\n"
                "    pass\n"
            ),
            "three_operand_unknown_or_true_or_dead": (
                "import os, subprocess\n"
                'flag = bool(os.environ.get("FLAG"))\n'
                "def launch():\n"
                '    return subprocess.run(["wsl.exe", "--", "/usr/local/bin/opengrep"])\n'
                "if flag or True or launch():\n"
                '    print("native")\n'
            ),
        }
        for label, code in cases.items():
            with self.subTest(case=label):
                w = self._make_wrapper(f"nested_neg_{label}", code)
                state = og.inspect_opengrep_binary_identity(str(w))
                self.assertTrue(state["found"], f"{label}: expected found=True, observed={state}")
                self.assertTrue(state["identity_complete"], f"{label}: expected identity_complete=True, observed={state}")
                self.assertFalse(
                    state["wsl_target"]["detected"],
                    f"N04-R2-C1 REPRODUCED ({label}): expected wsl_target.detected=False, observed={state['wsl_target']}",
                )

    def test_n04_r2_c1_short_circuit_dead_rhs_beside_live_lhs_resolves_only_live_target(self) -> None:
        """Evaluated LHS + short-circuited RHS with different target MUST bind ONLY the live target (no false ambiguity)."""
        expected_live = {"detected": True, "distro": "Ubuntu-IRIS", "linux_binary_path": "/usr/local/bin/opengrep"}
        cases = {
            "live_and_false_and_dead": (
                "import subprocess\n"
                "def live():\n"
                '    return subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"])\n'
                "def dead():\n"
                '    return subprocess.run(["wsl.exe", "-d", "DeadDistro", "--", "/opt/dead/opengrep"])\n'
                "if live() and False and dead():\n"
                "    dead()\n"
            ),
            "live_or_true_or_dead": (
                "import subprocess\n"
                "def live():\n"
                '    return subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"])\n'
                "def dead():\n"
                '    return subprocess.run(["wsl.exe", "-d", "DeadDistro", "--", "/opt/dead/opengrep"])\n'
                "if live() or True or dead():\n"
                "    pass\n"
            ),
            "false_and_dead_or_live": (
                "import subprocess\n"
                "def live():\n"
                '    return subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"])\n'
                "def dead():\n"
                '    return subprocess.run(["wsl.exe", "-d", "DeadDistro", "--", "/opt/dead/opengrep"])\n'
                "(False and dead()) or live()\n"
            ),
            "true_or_dead_and_live": (
                "import subprocess\n"
                "def live():\n"
                '    return subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"])\n'
                "def dead():\n"
                '    return subprocess.run(["wsl.exe", "-d", "DeadDistro", "--", "/opt/dead/opengrep"])\n'
                "(True or dead()) and live()\n"
            ),
        }
        for label, code in cases.items():
            with self.subTest(case=label):
                w = self._make_wrapper(f"mixed_{label}", code)
                state = og.inspect_opengrep_binary_identity(str(w))
                self.assertTrue(
                    state["found"],
                    f"N04-R2-C1 REPRODUCED ({label}): short-circuited dead operand caused failure! observed={state}",
                )
                self.assertEqual(
                    state["wsl_target"],
                    expected_live,
                    f"{label}: expected={expected_live}, observed={state['wsl_target']}",
                )

    def test_n04_r2_c1_positive_controls_evaluated_operands_side_effects_unknown_var_and_admin_pc(self) -> None:
        """Positive controls: `False or launch()`, `True and launch()`, LHS side effects, unknown var, and ADMIN-PC bridge."""
        expected = {"detected": True, "distro": "Ubuntu-IRIS", "linux_binary_path": "/usr/local/bin/opengrep"}
        cases = {
            "false_or_launch": (
                "import subprocess\n"
                "def launch():\n"
                '    return subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"])\n'
                "False or launch()\n"
            ),
            "true_and_launch": (
                "import subprocess\n"
                "def launch():\n"
                '    return subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"])\n'
                "True and launch()\n"
            ),
            "if_launch_and_false_preserves_lhs": (
                "import subprocess\n"
                "def launch():\n"
                '    return subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"])\n'
                "if launch() and False:\n"
                "    pass\n"
            ),
            "if_launch_or_true_preserves_lhs": (
                "import subprocess\n"
                "def launch():\n"
                '    return subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"])\n'
                "if launch() or True:\n"
                "    pass\n"
            ),
            "unknown_var_and_launch": (
                "import os, subprocess\n"
                'flag = os.environ.get("RUN_WSL")\n'
                "def launch():\n"
                '    return subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"])\n'
                "if flag and launch():\n"
                "    pass\n"
            ),
            "unknown_var_or_launch": (
                "import os, subprocess\n"
                'flag = os.environ.get("SKIP_WSL")\n'
                "def launch():\n"
                '    return subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"])\n'
                "if flag or launch():\n"
                "    pass\n"
            ),
            "admin_pc_valid_bridge": (
                "import subprocess, sys\n"
                "def main() -> int:\n"
                "    translated_args = sys.argv[1:]\n"
                '    cmd = ["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep", *translated_args]\n'
                "    return subprocess.run(cmd, capture_output=True).returncode\n"
                'if __name__ == "__main__":\n'
                "    sys.exit(main())\n"
            ),
        }
        for label, code in cases.items():
            with self.subTest(case=label):
                w = self._make_wrapper(f"pos_{label}", code)
                state = og.inspect_opengrep_binary_identity(str(w))
                self.assertTrue(state["found"], f"{label}: expected found=True, observed={state}")
                self.assertTrue(state["identity_complete"], f"{label}: expected identity_complete=True, observed={state}")
                self.assertEqual(
                    state["wsl_target"],
                    expected,
                    f"{label}: expected={expected}, observed={state['wsl_target']}",
                )

    def test_n04_r2_c1_security_controls_conflicting_reachable_dynamic_and_doc_tuple(self) -> None:
        """Security controls: reachable conflicting targets fail closed; dynamic target fails closed; doc tuple stays benign."""
        # 1. Two genuinely reachable conflicting WSL targets -> WSL_TARGET_AMBIGUOUS
        for label, code in (
            (
                "lhs_and_rhs_both_reachable",
                "import subprocess\n"
                'subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"]) and '
                'subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/opt/alt/opengrep"])\n',
            ),
            (
                "lhs_side_effect_and_else_branch_conflict",
                "import subprocess\n"
                'if subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"]) and False:\n'
                "    pass\n"
                "else:\n"
                '    subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/opt/alt/opengrep"])\n',
            ),
            (
                "unknown_flag_two_targets",
                "import os, subprocess\n"
                'flag = os.environ.get("ALT")\n'
                'flag and subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/opt/alt/opengrep"])\n'
                'subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"])\n',
            ),
        ):
            with self.subTest(case=label):
                w = self._make_wrapper(f"sec_amb_{label}", code)
                state = og.inspect_opengrep_binary_identity(str(w))
                self.assertFalse(state["found"], f"{label}: expected found=False, observed={state}")
                self.assertEqual(
                    state["failure_code"],
                    "WSL_TARGET_AMBIGUOUS",
                    f"{label}: expected WSL_TARGET_AMBIGUOUS, observed={state['failure_code']}",
                )

        # 2. Dynamic / unresolvable target or distro on reachable BoolOp branch -> WSL_TARGET_UNRESOLVABLE
        for label, code in (
            (
                "true_and_dynamic_distro",
                "import os, subprocess\n"
                'distro = os.environ.get("WSL_DISTRO", "Ubuntu-IRIS")\n'
                'True and subprocess.run(["wsl.exe", "-d", distro, "--", "/usr/local/bin/opengrep"])\n',
            ),
            (
                "false_or_dynamic_binary",
                "import os, subprocess\n"
                'bin_path = os.environ.get("OG_BIN", "/usr/local/bin/opengrep")\n'
                'False or subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", bin_path])\n',
            ),
        ):
            with self.subTest(case=label):
                w = self._make_wrapper(f"sec_dyn_{label}", code)
                state = og.inspect_opengrep_binary_identity(str(w))
                self.assertFalse(state["found"], f"{label}: expected found=False, observed={state}")
                self.assertEqual(
                    state["failure_code"],
                    "WSL_TARGET_UNRESOLVABLE",
                    f"{label}: expected WSL_TARGET_UNRESOLVABLE, observed={state['failure_code']}",
                )

        # 3. Unreferenced documentation tuple beside valid launch -> no false conflict
        w_doc = self._make_wrapper(
            "sec_doc_tuple",
            "import subprocess\n"
            'DOC_EXAMPLE = ("wsl.exe", "-d", "DocDistro", "--", "/opt/example/opengrep")\n'
            'True and subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"])\n',
        )
        state_doc = og.inspect_opengrep_binary_identity(str(w_doc))
        self.assertTrue(state_doc["found"], f"doc_tuple: expected found=True, observed={state_doc}")
        self.assertEqual(
            state_doc["wsl_target"],
            {"detected": True, "distro": "Ubuntu-IRIS", "linux_binary_path": "/usr/local/bin/opengrep"},
        )


if __name__ == "__main__":
    unittest.main()
