"""Counterexample & contract suite for Codex R2 blockers: N04-R1-A and N04-R1-B.

- N04-R1-A (unreachable launch sites):
  * Uncalled helper function containing `subprocess.run(["wsl.exe", ...])` MUST NOT set `wsl_target.detected=True`.
  * Statically dead branch (`if False:`, `if 0:`, `if not True:`, `while False:`) containing `subprocess.run(["wsl.exe", ...])`
    MUST NOT set `wsl_target.detected=True`.
  * Reachable entry paths — module top-level, `if __name__ == "__main__":`, `main()`, `sys.exit(main())`,
    `raise SystemExit(main())`, direct helper calls, helper returning command, and imported local helper called
    by the bridge — MUST resolve the executed WSL target.
  * Dynamic / unverifiable call dispatch (`getattr(subprocess, ...)`, `eval`, `exec`, dynamic dict dispatch to a
    WSL launcher) in reachable code when WSL strings/launches exist MUST fail closed (`WSL_TARGET_UNRESOLVABLE`).

- N04-R1-B (unrelated documentation tuple/list beside valid launch):
  * Adding an unreferenced documentation tuple/list (e.g. `DOC_EXAMPLE = ("wsl.exe", "--", "/opt/example/opengrep")`
    or an unreferenced `unused = ["wsl.exe", ...]`) in the same scope as a single valid WSL launch MUST NOT cause
    `WSL_TARGET_AMBIGUOUS`; execution identity binds ONLY to the actually executed launch target.
  * Two reachable WSL call sites with distinct targets (or conditional assignment to an executed `cmd` variable)
    MUST STILL fail closed with `WSL_TARGET_AMBIGUOUS`.
  * Dynamic binary/distro, subscript mutation, shell wrapper, and `shell=True` MUST STILL fail closed with
    `WSL_TARGET_UNRESOLVABLE`.
"""

from __future__ import annotations

import ast
import sys
import tempfile
import unittest
from pathlib import Path
from time import perf_counter
from unittest.mock import patch

from v2.api import intake, opengrep_runner as og
from v2.api.config import ApiConfig, DEFAULT_BACKEND_RULES
from v2.api.tests.test_n01_n05_counterexamples import _make_canary_step_stub, _make_stub_proc


class TestN04R2CallSiteReachabilityAndUnrelatedLiterals(unittest.TestCase):
    """N04-R1-A & N04-R1-B: Static reachability from supported entry points and call-site-only binding."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ntk_n04_r2_")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def _make_wrapper(self, name: str, bridge_code: str, *, extra_files: dict[str, str] | None = None) -> Path:
        sub = self.root / name
        sub.mkdir(parents=True, exist_ok=True)
        bridge = sub / "bridge.py"
        bridge.write_text(bridge_code, encoding="utf-8")
        for rel, content in (extra_files or {}).items():
            ep = sub / rel
            ep.parent.mkdir(parents=True, exist_ok=True)
            ep.write_text(content, encoding="utf-8")
        wrapper = sub / "opengrep.cmd"
        wrapper.write_text(f'@echo off\n"{sys.executable}" "%~dp0bridge.py" %*\n', encoding="utf-8")
        return wrapper

    def test_n04_r1_a_uncalled_function_and_constant_false_branches_are_not_detected(self) -> None:
        """Codex N04-R1-A: Launch call inside an uncalled function or statically false branch MUST NOT set detected=True."""
        cases = {
            "uncalled_function": (
                "import subprocess\n"
                "def unused_example():\n"
                '    subprocess.run(["wsl.exe", "--", "/usr/local/bin/opengrep"])\n'
            ),
            "constant_false": (
                "import subprocess\n"
                "if False:\n"
                '    subprocess.run(["wsl.exe", "--", "/usr/local/bin/opengrep"])\n'
            ),
            "constant_zero_and_not_true": (
                "import subprocess\n"
                "if 0:\n"
                '    subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"])\n'
                "if not True:\n"
                '    subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/opt/other"])\n'
                "while False:\n"
                '    subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/opt/never"])\n'
            ),
            "else_of_constant_true": (
                "import subprocess\n"
                "if True:\n"
                '    print("native mode")\n'
                "else:\n"
                '    subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"])\n'
            ),
            "uncalled_transitive_chain": (
                "import subprocess\n"
                "def dead_a():\n"
                "    return dead_b()\n"
                "def dead_b():\n"
                '    subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"])\n'
            ),
        }
        for label, body in cases.items():
            with self.subTest(case=label):
                w = self._make_wrapper(f"n04_r1_a_{label}", body)
                state = og.inspect_opengrep_binary_identity(str(w))
                self.assertTrue(state["found"], f"{label} should still inspect cleanly: {state}")
                self.assertTrue(state["identity_complete"], state)
                self.assertFalse(
                    state["wsl_target"]["detected"],
                    f"N04-R1-A REPRODUCED ({label}): unreachable launch detected as WSL target! {state}",
                )

    def test_n04_r1_a_supported_entry_points_and_admin_pc_main_bridge_positive_control(self) -> None:
        """Positive control: ADMIN-PC bridge with `if __name__ == '__main__': sys.exit(main())` & helpers detected cleanly."""
        # 1. Exact ADMIN-PC bridge shape using main() + sys.exit(main()) + dead branch + dead helper
        code_admin_pc = (
            "import subprocess\n"
            "import sys\n"
            "def unused_doc_launch():\n"
            '    subprocess.run(["wsl.exe", "-d", "OtherDistro", "--", "/opt/dead/opengrep"])\n'
            "def build_cmd(translated_args):\n"
            "    if False:\n"
            '        return ["wsl.exe", "-d", "DeadDistro", "--", "/opt/never/opengrep"]\n'
            '    return ["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep", *translated_args]\n'
            "def main() -> int:\n"
            "    translated_args = sys.argv[1:]\n"
            "    cmd = build_cmd(translated_args)\n"
            "    proc = subprocess.run(cmd, capture_output=True)\n"
            "    return proc.returncode\n"
            'if __name__ == "__main__":\n'
            "    sys.exit(main())\n"
        )
        w_admin = self._make_wrapper("admin_pc_main", code_admin_pc)
        id_admin = og.inspect_opengrep_binary_identity(str(w_admin))
        self.assertTrue(id_admin["found"], id_admin)
        self.assertTrue(id_admin["identity_complete"])
        self.assertEqual(
            id_admin["wsl_target"],
            {"detected": True, "distro": "Ubuntu-IRIS", "linux_binary_path": "/usr/local/bin/opengrep"},
        )

        # 2. Direct helper call from main() + raise SystemExit(main())
        code_helper = (
            "import subprocess, sys\n"
            "def invoke_opengrep(args):\n"
            '    cmd = ["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep", *args]\n'
            "    return subprocess.run(cmd, capture_output=True).returncode\n"
            "def main():\n"
            "    return invoke_opengrep(sys.argv[1:])\n"
            'if __name__ == "__main__":\n'
            "    raise SystemExit(main())\n"
        )
        w_helper = self._make_wrapper("admin_pc_helper", code_helper)
        id_helper = og.inspect_opengrep_binary_identity(str(w_helper))
        self.assertTrue(id_helper["found"], id_helper)
        self.assertEqual(
            id_helper["wsl_target"],
            {"detected": True, "distro": "Ubuntu-IRIS", "linux_binary_path": "/usr/local/bin/opengrep"},
        )

        # 3. Imported local helper module whose called function launches WSL (while its uncalled sibling does not interfere)
        code_caller = "import sys, wsl_mod\nsys.exit(wsl_mod.run_og(sys.argv[1:]))\n"
        code_dep = (
            "import subprocess\n"
            "def unused_other():\n"
            '    subprocess.run(["wsl.exe", "-d", "WrongDistro", "--", "/opt/wrong"])\n'
            "def run_og(extra):\n"
            '    cmd = ["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep", *extra]\n'
            "    return subprocess.run(cmd, capture_output=True).returncode\n"
        )
        w_dep = self._make_wrapper("imported_helper", code_caller, extra_files={"wsl_mod.py": code_dep})
        id_dep = og.inspect_opengrep_binary_identity(str(w_dep))
        self.assertTrue(id_dep["found"], id_dep)
        self.assertEqual(
            id_dep["wsl_target"],
            {"detected": True, "distro": "Ubuntu-IRIS", "linux_binary_path": "/usr/local/bin/opengrep"},
        )

    def test_n04_r1_b_unrelated_doc_tuple_or_unused_list_beside_valid_launch_accepted(self) -> None:
        """Codex N04-R1-B: Unreferenced doc tuple or unused list in the SAME scope MUST NOT trigger WSL_TARGET_AMBIGUOUS."""
        # 1. Exact Codex N04-R1-B reproducer
        base_code = 'import subprocess\nsubprocess.run(["wsl.exe", "--", "/usr/local/bin/opengrep"])\n'
        doc_code = 'DOC_EXAMPLE = ("wsl.exe", "--", "/opt/example/opengrep")\n' + base_code
        w_base = self._make_wrapper("n04_r1_b_base", base_code)
        w_doc = self._make_wrapper("n04_r1_b_with_doc", doc_code)
        id_base = og.inspect_opengrep_binary_identity(str(w_base))
        id_doc = og.inspect_opengrep_binary_identity(str(w_doc))
        self.assertTrue(id_base["found"], id_base)
        self.assertTrue(
            id_doc["found"],
            f"N04-R1-B REPRODUCED: adding unreferenced DOC_EXAMPLE tuple broke valid bridge! {id_doc}",
        )
        self.assertEqual(id_doc["wsl_target"], id_base["wsl_target"])

        # 2. Unreferenced `unused` list beside executed `selected` list (explicit replacement contract for legacy conflict)
        code_unused_vs_selected = (
            "import subprocess\n"
            'unused = ["wsl.exe", "-d", "Audit", "--", "/usr/local/bin/opengrep"]\n'
            'selected = ["wsl.exe", "-d", "Audit", "--", "/opt/opengrep"]\n'
            "subprocess.run(selected)\n"
        )
        w_sel = self._make_wrapper("n04_r1_b_unused_vs_selected", code_unused_vs_selected)
        id_sel = og.inspect_opengrep_binary_identity(str(w_sel))
        self.assertTrue(id_sel["found"], f"Unreferenced `unused` must not shadow/conflict executed `selected`: {id_sel}")
        self.assertEqual(
            id_sel["wsl_target"],
            {"detected": True, "distro": "Audit", "linux_binary_path": "/opt/opengrep"},
        )

        # 3. Same-function unreferenced doc tuple inside main() beside ADMIN-PC launch
        code_in_main = (
            "import subprocess, sys\n"
            "def main():\n"
            '    doc_tuple = ("wsl.exe", "-d", "DocDistro", "--", "/opt/doc/opengrep")\n'
            '    cmd = ["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep", *sys.argv[1:]]\n'
            "    return subprocess.run(cmd, capture_output=True).returncode\n"
            'if __name__ == "__main__":\n'
            "    sys.exit(main())\n"
        )
        w_in_main = self._make_wrapper("n04_r1_b_in_main", code_in_main)
        id_in_main = og.inspect_opengrep_binary_identity(str(w_in_main))
        self.assertTrue(id_in_main["found"], id_in_main)
        self.assertEqual(
            id_in_main["wsl_target"],
            {"detected": True, "distro": "Ubuntu-IRIS", "linux_binary_path": "/usr/local/bin/opengrep"},
        )

    def test_n04_r2_two_reachable_conflicting_call_sites_and_dynamic_dispatch_fail_closed(self) -> None:
        """Fail-closed contracts: two reachable conflicting WSL call sites -> WSL_TARGET_AMBIGUOUS; dynamic -> WSL_TARGET_UNRESOLVABLE."""
        # 1. Two reachable call sites with different WSL targets -> WSL_TARGET_AMBIGUOUS
        code_two_calls = (
            "import os, subprocess\n"
            "def main():\n"
            '    if os.environ.get("USE_ALT"):\n'
            '        subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/opt/alt/opengrep"])\n'
            "    else:\n"
            '        subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"])\n'
            'if __name__ == "__main__":\n'
            "    main()\n"
        )
        w_two = self._make_wrapper("two_reachable_calls", code_two_calls)
        id_two = og.inspect_opengrep_binary_identity(str(w_two))
        self.assertFalse(id_two["found"], id_two)
        self.assertEqual(id_two["failure_code"], "WSL_TARGET_AMBIGUOUS")

        # 2. Reachable conditional reassignment to executed cmd -> WSL_TARGET_AMBIGUOUS
        code_cond_cmd = (
            "import os, subprocess\n"
            'cmd = ["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"]\n'
            'if os.environ.get("ALT"):\n'
            '    cmd = ["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/opt/alt/opengrep"]\n'
            "subprocess.run(cmd)\n"
        )
        w_cond = self._make_wrapper("cond_cmd_amb", code_cond_cmd)
        id_cond = og.inspect_opengrep_binary_identity(str(w_cond))
        self.assertFalse(id_cond["found"], id_cond)
        self.assertEqual(id_cond["failure_code"], "WSL_TARGET_AMBIGUOUS")

        # 3. Dynamic call dispatch / unverifiable indirect call in reachable code with WSL -> WSL_TARGET_UNRESOLVABLE
        for label, body in (
            (
                "getattr_subprocess",
                'import subprocess\nfn = getattr(subprocess, "run")\nfn(["wsl.exe", "--", "/usr/local/bin/opengrep"])\n',
            ),
            (
                "dict_dispatch_to_wsl_func",
                "import os, subprocess\n"
                "def launch_a():\n"
                '    subprocess.run(["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"])\n'
                'table = {"a": launch_a}\n'
                'table[os.environ.get("K", "a")]()\n',
            ),
            (
                "eval_with_wsl_str",
                'import subprocess\nCMD = "wsl.exe -- /usr/local/bin/opengrep"\neval("subprocess.run(CMD.split())")\n',
            ),
            (
                "subscript_mutation",
                'import subprocess\ncmd = ["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep"]\ncmd[4] = "/opt/evil"\nsubprocess.run(cmd)\n',
            ),
            (
                "shell_true",
                'import subprocess\nsubprocess.run("wsl.exe -d Ubuntu-IRIS -- /usr/local/bin/opengrep", shell=True)\n',
            ),
        ):
            with self.subTest(case=label):
                wd = self._make_wrapper(f"dyn_{label}", body)
                idd = og.inspect_opengrep_binary_identity(str(wd))
                self.assertFalse(idd["found"], f"{label} MUST fail closed: {idd}")
                self.assertEqual(idd["failure_code"], "WSL_TARGET_UNRESOLVABLE")

    def test_n04_r2_bounded_ast_controls_and_probe_chain_end_to_end(self) -> None:
        """Bounded AST runtime/cycle safety + OpenGrepHealthProbe end-to-end binding on reachable call site."""
        # 1. Ordinary large script + alias cycle (terminates cleanly and fast)
        large = "import subprocess\n" + "\n".join(f"v_{i} = {i}" for i in range(3500)) + '\nsubprocess.run(["wsl.exe","--","/usr/local/bin/opengrep"])\n'
        cycle = 'import subprocess\nDOC = ("wsl.exe","--","/usr/local/bin/opengrep")\na = b\nb = a\nsubprocess.run(a)\n'
        t0 = perf_counter()
        c_large, i_large = og._collect_wsl_candidates_from_py_ast(ast.parse(large))
        dt_large = perf_counter() - t0
        self.assertEqual(len(c_large), 1)
        self.assertEqual(i_large, [])
        self.assertLess(dt_large, 2.0)

        t1 = perf_counter()
        c_cycle, i_cycle = og._collect_wsl_candidates_from_py_ast(ast.parse(cycle))
        dt_cycle = perf_counter() - t1
        self.assertEqual(len(c_cycle), 0)
        self.assertEqual(i_cycle, [])
        self.assertLess(dt_cycle, 1.0)

        # 2. End-to-end probe with simulated WSL I/O binds exact target from main() and ignores unreferenced doc tuple
        w = self._make_wrapper(
            "e2e_probe_wsl",
            'import subprocess, sys\n'
            'DOC_EXAMPLE = ("wsl.exe", "-d", "WrongDistro", "--", "/opt/doc/opengrep")\n'
            'def main():\n'
            '    cmd = ["wsl.exe", "-d", "Ubuntu-IRIS", "--", "/usr/local/bin/opengrep", *sys.argv[1:]]\n'
            '    return subprocess.run(cmd, capture_output=True).returncode\n'
            'if __name__ == "__main__":\n'
            '    sys.exit(main())\n',
        )
        cfg = ApiConfig(
            data_dir=self.root / "probe_e2e_data",
            rules_path=DEFAULT_BACKEND_RULES,
            opengrep_binary=str(w),
            api_token="n04-r2-token",
            port=0,
        )
        stub = _make_canary_step_stub()
        seen_wsl_steps: list[tuple[str, list[str]]] = []

        def wsl_sim(step, args, **kw):
            if "-wsl-" in step:
                seen_wsl_steps.append((step, list(args)))
                if step.endswith("realpath"):
                    return _make_stub_proc(args, b"/opt/opengrep/cli/v1.25.0/opengrep\n")
                if step.endswith("sha256"):
                    return _make_stub_proc(args, b"a" * 64 + b"  /opt/opengrep/cli/v1.25.0/opengrep\n")
                return _make_stub_proc(args, b"1.25.0\n")
            return stub(step, args, **kw)

        probe = og.OpenGrepHealthProbe(cfg)
        self.addCleanup(probe.shutdown)
        with patch.object(intake, "_run_git_step", side_effect=wsl_sim):
            snap = probe._execute_probe_once()[0]
        self.assertTrue(snap["available"], snap)
        self.assertEqual(snap["probe_status"], "VERIFIED")
        self.assertEqual(snap["wsl_binary_identity"]["distro"], "Ubuntu-IRIS")
        self.assertEqual(snap["wsl_binary_identity"]["configured_path"], "/usr/local/bin/opengrep")
        self.assertTrue(any(s == "opengrep-health-wsl-sha256" for s, _ in seen_wsl_steps))


if __name__ == "__main__":
    unittest.main()
