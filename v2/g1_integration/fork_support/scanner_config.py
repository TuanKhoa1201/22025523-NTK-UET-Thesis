"""G1 local scanner config: reads only scanner fields, enforces OpenGrep, never imports cloud/LLM providers."""
import os
from pathlib import Path
from types import SimpleNamespace
import yaml


def validate_opengrep_binary(binary):
    if not isinstance(binary, str) or not binary.strip():
        raise ValueError("scanner binary must be a non-empty OpenGrep executable name or path")
    name = Path(binary).name.lower()
    if not name.startswith("opengrep"):
        raise ValueError(f"G1 local pipeline allows only OpenGrep, got: {binary!r}")
    return binary


class ConfigManager:
    def __init__(self, config_path=None):
        path = Path(config_path or "semgrepai.yml")
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) if path.is_file() else {}
        scanner = (doc or {}).get("semgrep", {}) if isinstance(doc, dict) else {}
        env_binary = os.environ.get("OPENGREP_BINARY")
        binary = validate_opengrep_binary(env_binary or scanner.get("binary", "opengrep"))
        # CLI must pass explicit local rules or use G1 local default rules; never resolve registry "auto".
        self.config = SimpleNamespace(
            semgrep=SimpleNamespace(
                binary=binary,
                default_rules=[],
                timeout=scanner.get("timeout", 60),
                jobs=scanner.get("jobs", 1),
                dataflow_traces=True,
                taint_intrafile=scanner.get("taint_intrafile", True),
            )
        )
