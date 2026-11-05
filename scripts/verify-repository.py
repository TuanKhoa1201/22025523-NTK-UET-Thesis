#!/usr/bin/env python3
"""Kiem tra cau truc ban giao ma nguon, khong can trong so mo hinh."""
from __future__ import annotations
import ast
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BACKEND = ROOT / "backend" / "ntk-production-v2"
FRONTEND = ROOT / "apps" / "22025523-thesis"
REQUIRED = (
    ROOT / "README.md",
    ROOT / "docs" / "architecture.md",
    ROOT / "docs" / "chay-tren-may-khac.md",
    ROOT / "evaluation" / "bao-cao-kiem-thu-da-xac-minh.md",
    BACKEND / "scripts" / "ntk_web_backend_service.py",
    BACKEND / "scripts" / "ntk_original_iris_adapter.py",
    BACKEND / "scripts" / "ntk_cwss_workflow.py",
    BACKEND / "scripts" / "eo06_main_train_eval_e2e_pipeline.py",
    BACKEND / "scripts" / "javac_ast_bridge" / "NtkJavacAstExtractor.java",
    BACKEND / "rules" / "ntk_opengrep_java_ruleset_v1_4.yaml",
    FRONTEND / "src" / "pages" / "DatasetExplorer.jsx",
    FRONTEND / "src" / "pages" / "LiveFindings.jsx",
    FRONTEND / "src" / "components" / "results" / "FindingsExplorer.jsx",
    FRONTEND / "src" / "components" / "results" / "OverviewCharts.jsx",
    ROOT / "scripts" / "windows" / "configure-backend.ps1",
    ROOT / "scripts" / "windows" / "start-backend.ps1",
    ROOT / "scripts" / "windows" / "check-backend.ps1",
    ROOT / "scripts" / "linux" / "start-backend.sh",
    ROOT / ".github" / "workflows" / "kiem-tra-ma-nguon.yml",
)
def main() -> int:
    missing = [p.relative_to(ROOT).as_posix() for p in REQUIRED if not p.is_file()]
    if missing:
        raise SystemExit("Thieu tep: " + ", ".join(missing))
    pyfiles = sorted((BACKEND / "scripts").glob("*.py"))
    pyfiles += sorted((BACKEND / "tests").glob("test_*.py"))
    for file in pyfiles:
        ast.parse(file.read_text(encoding="utf-8-sig"), filename=str(file))
    manifests = []
    for p in ROOT.rglob("*.json"):
        if any(part in (".git", "node_modules", "dist", ".venv") for part in p.parts):
            continue
        if p.stat().st_size < 2_000_000:
            json.loads(p.read_text(encoding="utf-8-sig"))
            manifests.append(p.relative_to(ROOT).as_posix())
    tracked = subprocess.check_output(
        ["git", "-C", str(ROOT), "ls-files", "-z"], text=False
    ).decode("utf-8").split("\0")
    forbidden = re.compile(
        r"(^|/)(node_modules|dist|__pycache__|checkpoints|private.repro|dataset_vnext_3_1|persisted_api_store)/"
        r"|\.(?:safetensors|gguf|ckpt|sqlite3?|db|pem|key|jsonl)$"
        r"|(^|/)config/ntk_backend\.env$",
        flags=re.I,
    )
    bad = [name for name in tracked if name and forbidden.search(name)]
    if bad:
        raise SystemExit("Tep khong duoc phep theo doi: " + ", ".join(bad))
    print(f"PASS: {len(REQUIRED)} tep bat buoc, {len(pyfiles)} module Python, "
          f"{len(manifests)} JSON hop le, khong co artifact rieng trong git index.")
    return 0
if __name__ == "__main__":
    raise SystemExit(main())
