"""Counterexample & truth-matrix suite for Codex N04-R3-C1: equal-truth `ast.IfExp` short-circuiting.

Every case runs end-to-end through `.cmd -> Python bridge -> inspect_opengrep_binary_identity()`
without executing the bridge script itself (pure static AST inspection).

Matrix & contracts verified:
A. Negative controls (equal-truth IfExp short-circuits RHS -> `wsl_target.detected=False`):
   - `(False if flag else False) and launch()` (including exact Codex G-03)
   - `(True if flag else True) or launch()`
   - Multi-level nested IfExp where every path yields False before `and`
   - Multi-level nested IfExp where every path yields True before `or`
   - Equal-truth IfExp directly as `if` branch condition guarding an unreachable launch
B. Positive controls (mixed/unknown truth or non-short-circuiting operator -> `wsl_target.detected=True`):
   - `(False if flag else True) and launch()`, `(True if flag else False) and launch()`
   - `(True if flag else False) or launch()`, `(False if flag else True) or launch()`
   - `(False if flag else False) or launch()`, `(True if flag else True) and launch()`
   - Unknown arm `(False if flag else other) and launch()`, `(True if flag else other) or launch()`
   - Nested mixed-truth IfExp before `and`
C. Side-effect controls (evaluated condition & feasible arms MUST be retained while dead RHS is excluded):
   - `(False if trigger() else False) and dead_launch()` retains `trigger()` WSL target, excludes `dead_launch()`
   - `(True if trigger() else True) or dead_launch()` retains `trigger()` WSL target, excludes `dead_launch()`
   - Feasible arm side effects inside constant-truth IfExp:
     `((live() and False) if flag else False) and dead_launch()` and
     `([live()] if flag else [1]) or dead_launch()` retain `live()` and exclude `dead_launch()`
D. Security & compatibility controls:
   - Two reachable conflicting WSL targets -> `WSL_TARGET_AMBIGUOUS`
   - Dynamic target/distro on reachable branch -> `WSL_TARGET_UNRESOLVABLE`
   - Unreferenced doc tuple/list beside valid launch -> no false ambiguity
   - Valid ADMIN-PC bridge with `*translated_args` and `capture_output=True` -> exact target
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from v2.api import opengrep_runner as og


class TestN04R4IfExpEqualTruthShortCircuit(unittest.TestCase):
    """N04-R3-C1: Static truth-value invariant for ast.IfExp combined with BoolOp short-circuiting."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ntk_n04_r4_")
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

    def test_n04_r3_c1_a_equal_truth_ifexp_short_circuit_negative_controls(self) -> None:
        """A. Negative controls: equal-truth IfExp (single & nested) short-circuits dead WSL launch."""
        cases = {
            "codex_g03_false_if_flag_else_false_and_subprocess_run": (
                "import os, subprocess\n"
                'flag = os.environ.get("AUDIT_BRANCH")\n'
                'if (False if flag else False) and subprocess.run(["wsl.exe", "--", "/usr/local/bin/opengrep"]):\n'
                "    pass\n"
            ),
            "false_if_flag_else_false_and_helper_launch": (
                "import os, subprocess\n"
                'flag = os.environ.get("FLAG")\n'
                "def launch():\n"
                '    return subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"])\n'
                "(False if flag else False) and launch()\n"
            ),
            "falsy_literals_0_if_flag_else_empty_str_and_launch": (
                "import os, subprocess\n"
                'flag = os.environ.get("FLAG")\n'
                'if (0 if flag else "") and subprocess.run(["wsl.exe", "--", "/usr/local/bin/opengrep"]):\n'
                "    pass\n"
            ),
            "true_if_flag_else_true_or_launch": (
                "import os, subprocess\n"
                'flag = os.environ.get("FLAG")\n'
                "def launch():\n"
                '    return subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"])\n'
                "(True if flag else True) or launch()\n"
            ),
            "truthy_literals_1_if_flag_else_str_or_launch": (
                "import os, subprocess\n"
                'flag = os.environ.get("FLAG")\n'
                'if (1 if flag else "ok") or subprocess.run(["wsl.exe", "--", "/usr/local/bin/opengrep"]):\n'
                '    print("native")\n'
            ),
            "nested_all_false_ifexp_and_launch": (
                "import os, subprocess\n"
                'f1, f2, f3 = os.environ.get("A"), os.environ.get("B"), os.environ.get("C")\n'
                "def launch():\n"
                '    return subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"])\n'
                '((False if f1 else 0) if f2 else ("" if f3 else [])) and launch()\n'
            ),
            "nested_all_true_ifexp_or_launch": (
                "import os, subprocess\n"
                'f1, f2, f3 = os.environ.get("A"), os.environ.get("B"), os.environ.get("C")\n'
                "def launch():\n"
                '    return subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"])\n'
                '((True if f1 else 1) if f2 else ("x" if f3 else [1])) or launch()\n'
            ),
            "equal_false_ifexp_guards_if_body": (
                "import os, subprocess\n"
                'flag = os.environ.get("FLAG")\n'
                "if (False if flag else False):\n"
                '    subprocess.run(["wsl.exe", "--", "/usr/local/bin/opengrep"])\n'
            ),
            "equal_true_ifexp_guards_else_body": (
                "import os, subprocess\n"
                'flag = os.environ.get("FLAG")\n'
                "if (True if flag else True):\n"
                '    print("native")\n'
                "else:\n"
                '    subprocess.run(["wsl.exe", "--", "/usr/local/bin/opengrep"])\n'
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
                    f"N04-R3-C1 REPRODUCED ({label}): expected wsl_target.detected=False, observed={state['wsl_target']}",
                )

    def test_n04_r3_c1_b_mixed_unknown_and_non_short_circuit_positive_controls(self) -> None:
        """B. Positive controls: all truth-matrix cells where RHS launch CAN or MUST execute."""
        expected = {"detected": True, "distro": "Ubuntu-IRIS", "linux_binary_path": "/usr/local/bin/opengrep"}
        header = (
            "import os, subprocess\n"
            'flag = os.environ.get("FLAG")\n'
            'other = os.environ.get("OTHER")\n'
            'f1, f2, f3 = os.environ.get("A"), os.environ.get("B"), os.environ.get("C")\n'
            "def launch():\n"
            '    return subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"])\n'
        )
        expressions = {
            "false_if_flag_else_true_and_launch": "(False if flag else True) and launch()\n",
            "true_if_flag_else_false_and_launch": "(True if flag else False) and launch()\n",
            "true_if_flag_else_false_or_launch": "(True if flag else False) or launch()\n",
            "false_if_flag_else_true_or_launch": "(False if flag else True) or launch()\n",
            "false_if_flag_else_false_or_launch": "(False if flag else False) or launch()\n",
            "true_if_flag_else_true_and_launch": "(True if flag else True) and launch()\n",
            "false_if_flag_else_unknown_and_launch": "(False if flag else other) and launch()\n",
            "true_if_flag_else_unknown_or_launch": "(True if flag else other) or launch()\n",
            "unknown_if_flag_else_false_and_launch": "(other if flag else False) and launch()\n",
            "unknown_if_flag_else_true_or_launch": "(other if flag else True) or launch()\n",
            "nested_mixed_truth_ifexp_and_launch": "((True if f1 else True) if f2 else (False if f3 else False)) and launch()\n",
        }
        for label, expr in expressions.items():
            with self.subTest(case=label):
                w = self._make_wrapper(f"pos_{label}", header + expr)
                state = og.inspect_opengrep_binary_identity(str(w))
                self.assertTrue(state["found"], f"{label}: expected found=True, observed={state}")
                self.assertTrue(state["identity_complete"], f"{label}: expected identity_complete=True, observed={state}")
                self.assertEqual(
                    state["wsl_target"],
                    expected,
                    f"{label}: expected={expected}, observed={state['wsl_target']}",
                )

    def test_n04_r3_c1_c_side_effects_in_condition_and_arms_retained_while_dead_rhs_excluded(self) -> None:
        """C. Side-effect controls: condition & feasible arms of equal-truth IfExp retained; dead RHS excluded."""
        expected_live = {"detected": True, "distro": "Ubuntu-IRIS", "linux_binary_path": "/usr/local/bin/opengrep"}
        helper_defs = (
            "import os, subprocess\n"
            'flag = os.environ.get("FLAG")\n'
            "def trigger():\n"
            '    return subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"])\n'
            "def dead_launch():\n"
            '    return subprocess.run(["wsl.exe", "-d", "DeadDistro", "--", "/opt/dead/opengrep"])\n'
        )
        cases = {
            "cond_trigger_in_equal_false_and_dead_rhs": (
                helper_defs + "(False if trigger() else False) and dead_launch()\n"
            ),
            "cond_trigger_in_equal_true_or_dead_rhs": (
                helper_defs + "(True if trigger() else True) or dead_launch()\n"
            ),
            "body_arm_side_effect_in_equal_false_and_dead_rhs": (
                helper_defs + "((trigger() and False) if flag else False) and dead_launch()\n"
            ),
            "orelse_arm_side_effect_in_equal_false_and_dead_rhs": (
                helper_defs + "(False if flag else (trigger() and False)) and dead_launch()\n"
            ),
            "body_arm_list_side_effect_in_equal_true_or_dead_rhs": (
                helper_defs + "([trigger()] if flag else [1]) or dead_launch()\n"
            ),
            "cond_trigger_in_equal_false_if_stmt_with_dead_body": (
                helper_defs + "if (False if trigger() else False):\n    dead_launch()\n"
            ),
        }
        for label, code in cases.items():
            with self.subTest(case=label):
                w = self._make_wrapper(f"se_{label}", code)
                state = og.inspect_opengrep_binary_identity(str(w))
                self.assertTrue(
                    state["found"],
                    f"N04-R3-C1 REPRODUCED ({label}): dead RHS caused failure or dropped live target! observed={state}",
                )
                self.assertEqual(
                    state["wsl_target"],
                    expected_live,
                    f"{label}: expected={expected_live}, observed={state['wsl_target']}",
                )

    def test_n04_r3_c1_d_security_and_admin_pc_compatibility_controls(self) -> None:
        """D. Security/compatibility controls: conflicting reachable targets, dynamic target, doc tuple, ADMIN-PC bridge."""
        # 1. Two genuinely reachable conflicting WSL targets -> WSL_TARGET_AMBIGUOUS
        for label, code in (
            (
                "mixed_ifexp_and_two_targets",
                "import os, subprocess\n"
                'flag = os.environ.get("ALT")\n'
                '(False if flag else True) and subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/opt/alt/opengrep"])\n'
                'subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"])\n',
            ),
            (
                "both_arms_of_equal_false_ifexp_conflict",
                "import os, subprocess\n"
                'flag = os.environ.get("ALT")\n'
                '((subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"]) and False) '
                'if flag else '
                '(subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/opt/alt/opengrep"]) and False)) and True\n',
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

        # 2. Dynamic target / distro on reachable path -> WSL_TARGET_UNRESOLVABLE
        for label, code in (
            (
                "equal_false_or_dynamic_distro",
                "import os, subprocess\n"
                'flag = os.environ.get("F")\n'
                'distro = os.environ.get("WSL_DISTRO", "Ubuntu-IRIS")\n'
                '(False if flag else False) or subprocess.run(["wsl.exe", "-d", distro, "--", "/usr/local/bin/opengrep"])\n',
            ),
            (
                "equal_true_and_dynamic_binary",
                "import os, subprocess\n"
                'flag = os.environ.get("F")\n'
                'bin_path = os.environ.get("OG_BIN", "/usr/local/bin/opengrep")\n'
                '(True if flag else True) and subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", bin_path])\n',
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

        # 3. Unreferenced documentation tuple/list beside valid launch -> no false ambiguity
        w_doc = self._make_wrapper(
            "sec_doc_tuple_and_list",
            "import os, subprocess\n"
            'flag = os.environ.get("F")\n'
            'DOC_TUPLE = ("wsl.exe", "-d", "DocDistro", "--", "/opt/doc/opengrep")\n'
            'DOC_LIST = ["wsl.exe", "-d", "DocDistro2", "--", "/opt/doc2/opengrep"]\n'
            '(True if flag else True) and subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"])\n',
        )
        state_doc = og.inspect_opengrep_binary_identity(str(w_doc))
        self.assertTrue(state_doc["found"], f"doc_tuple: expected found=True, observed={state_doc}")
        self.assertEqual(
            state_doc["wsl_target"],
            {"detected": True, "distro": "Ubuntu-IRIS", "linux_binary_path": "/usr/local/bin/opengrep"},
        )

        # 4. Valid ADMIN-PC bridge with `*translated_args` and `capture_output=True`
        w_admin = self._make_wrapper(
            "sec_admin_pc_bridge",
            "import subprocess, sys\n"
            "def main() -> int:\n"
            "    translated_args = sys.argv[1:]\n"
            '    cmd = ["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep", *translated_args]\n'
            "    proc = subprocess.run(cmd, capture_output=True)\n"
            "    return proc.returncode\n"
            'if __name__ == "__main__":\n'
            "    sys.exit(main())\n",
        )
        state_admin = og.inspect_opengrep_binary_identity(str(w_admin))
        self.assertTrue(state_admin["found"], f"admin_pc: expected found=True, observed={state_admin}")
        self.assertTrue(state_admin["identity_complete"])
        self.assertEqual(
            state_admin["wsl_target"],
            {"detected": True, "distro": "Ubuntu-IRIS", "linux_binary_path": "/usr/local/bin/opengrep"},
        )


if __name__ == "__main__":
    unittest.main()
