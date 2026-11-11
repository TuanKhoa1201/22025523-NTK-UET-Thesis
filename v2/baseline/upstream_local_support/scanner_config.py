"""NTK scan-only config: reads only scanner fields, never imports LLM providers."""
from pathlib import Path
from types import SimpleNamespace
import yaml


class ConfigManager:
    def __init__(self, config_path=None):
        path = Path(config_path or "semgrepai.yml")
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) if path.is_file() else {}
        scanner = (doc or {}).get("semgrep", {})
        binary = scanner.get("binary", "opengrep")
        if not Path(binary).name.lower().startswith("opengrep"):
            raise ValueError("local verification allows only OpenGrep")
        # CLI must pass --rules-path; do not resolve stale registry/default YAML paths.
        self.config = SimpleNamespace(semgrep=SimpleNamespace(
            binary=binary, default_rules=[], timeout=scanner.get("timeout", 60),
            jobs=scanner.get("jobs", 1), dataflow_traces=True,
            taint_intrafile=scanner.get("taint_intrafile", True)))
