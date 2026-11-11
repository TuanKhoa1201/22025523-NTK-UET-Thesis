import ast
import importlib.util
import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
from prepare_upstream_local import overlay_cli


class UpstreamOverlayTests(unittest.TestCase):
    def test_pinned_cli_preserves_scanner_call_without_eager_llm_imports(self):
        original = (BASE / "upstream/semgrepai/cli.py").read_text()
        patched = overlay_cli(original)
        tree = ast.parse(patched)
        imports = [n.module for n in tree.body if isinstance(n, ast.ImportFrom)]
        for forbidden in ("rag", "validator", "reporter", "config"):
            self.assertNotIn(forbidden, imports)
        scan = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "scan")
        self.assertIn("scan_only", [a.arg for a in scan.args.args])
        self.assertIn("results = scanner.scan(target_path, rules_path)", patched)
        self.assertLess(patched.index('        return\n'), patched.index("rag = RAGStore()"))
        self.assertIn("SemgrepScanner(config_path=", patched)
        for name in ("search", "serve", "init_db", "config"):
            node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
            self.assertTrue(any(isinstance(s, ast.Raise) for s in node.body[:2]))

    def test_unexpected_cli_is_rejected(self):
        with self.assertRaises(ValueError):
            overlay_cli("# not the pinned CLI\n")

    def test_scan_config_does_not_import_provider_stack(self):
        path = BASE / "upstream_local_support/scanner_config.py"
        spec = importlib.util.spec_from_file_location("ntk_local_scanner_config", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cfg = module.ConfigManager(BASE / "upstream/semgrepai.yml")
        self.assertEqual(cfg.config.semgrep.binary, "opengrep")
        self.assertEqual(cfg.config.semgrep.default_rules, [])
