#!/usr/bin/env python3
"""Cross-platform V2 Integration Quality Gate workflow runner (no GPU/Ollama required).

Executes the mandatory P0.2 integration checks for branches matching v2/**:
1. Repository policy verification (scripts/verify-repository.py).
2. Upstream patch byte-exact & git apply verification (v2/baseline/verify_patch.py).
3. All V2 unit test suites (v2/baseline/tests, v2/triage/tests, v2/evaluation/tests, v2/demo/tests).
4. Data structure and contract verification in deterministic offline/replay mode:
   - Replay scan-hash & provenance contract (v2/demo/verify_repro_contract.py replay)
   - Offline triage import & SQLite ingestion (python -m v2.triage run --no-llm)
   - Paired pilot export contract (python -m v2.triage.export_pilot)
   - Pilot lock validator in SMOKE mode (pass) and STRICT_LOCK mode on fixtures (fail-closed)
   - Paired pilot table generation (v2/evaluation/build_paired_pilot_table.py)
   - Pilot scoring verification (v2/evaluation/score_pilot.py)

Can also install a local Git pre-push hook (--install-git-hook) that enforces this gate
automatically on any push from a v2/** branch.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]


def _run_step(
    name: str,
    cmd: list[str],
    cwd: Path = REPO_ROOT,
    env_overrides: dict[str, str] | None = None,
    expected_nonzero: bool = False,
) -> dict[str, Any]:
    env = dict(os.environ)
    if env_overrides:
        env.update(env_overrides)
    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    passed = (proc.returncode != 0) if expected_nonzero else (proc.returncode == 0)
    status = "PASS" if passed else "FAIL"
    print(f"[{status}] {name} (exit_code={proc.returncode})")
    if not passed:
        if proc.stdout:
            print(proc.stdout, file=sys.stderr)
        if proc.stderr:
            print(proc.stderr, file=sys.stderr)
        raise RuntimeError(f"Quality gate step '{name}' failed with exit code {proc.returncode}")
    return {
        "step": name,
        "status": status,
        "exit_code": proc.returncode,
        "command": cmd,
    }


def run_quality_gate(
    output_report: Path | None = None,
    skip_pytest: bool = False,
) -> dict[str, Any]:
    steps: list[dict[str, Any]] = []
    py = sys.executable

    steps.append(
        _run_step(
            "repository_policy",
            [py, "scripts/verify-repository.py"],
        )
    )
    steps.append(
        _run_step(
            "upstream_patch_verification",
            [py, "v2/baseline/verify_patch.py"],
        )
    )

    if not skip_pytest and os.environ.get("NTK_V2_IN_QUALITY_GATE_TEST") != "1":
        steps.append(
            _run_step(
                "v2_unit_tests",
                [
                    py,
                    "-m",
                    "pytest",
                    "v2/baseline/tests",
                    "v2/triage/tests",
                    "v2/evaluation/tests",
                    "v2/demo/tests",
                    "-q",
                ],
                env_overrides={"NTK_V2_IN_QUALITY_GATE_TEST": "1"},
            )
        )

    with tempfile.TemporaryDirectory(prefix="ntk_v2_ci_gate_") as tmp_str:
        tmp = Path(tmp_str)
        steps.append(
            _run_step(
                "contract_replay_verification",
                [
                    py,
                    "v2/demo/verify_repro_contract.py",
                    "replay",
                    "--opengrep",
                    "v2/demo/smoke_m1_rules_raw.opengrep.json",
                    "--triage",
                    "v2/demo/triage_qwen35_9b_smoke_m1_assessments.jsonl",
                    "--labels",
                    "v2/evaluation/smoke_m1_verified_labels.json",
                    "--output-report",
                    str(tmp / "replay_contract.json"),
                ],
            )
        )
        steps.append(
            _run_step(
                "triage_offline_import_contract",
                [
                    py,
                    "-m",
                    "v2.triage",
                    "run",
                    "--source-root",
                    str(REPO_ROOT),
                    "--path-base",
                    str(REPO_ROOT),
                    "--json",
                    "v2/demo/smoke_m1_rules_raw.opengrep.json",
                    "--engine-exit",
                    "0",
                    "--output-dir",
                    str(tmp / "triage_no_llm"),
                    "--no-llm",
                ],
            )
        )
        steps.append(
            _run_step(
                "triage_export_pilot_contract",
                [
                    py,
                    "-m",
                    "v2.triage.export_pilot",
                    str(tmp / "triage_no_llm" / "assessments.jsonl"),
                    "--raw-json",
                    str(tmp / "triage_no_llm" / "input.opengrep.json"),
                    "--output-dir",
                    str(tmp / "export_pilot"),
                ],
            )
        )
        eval_env = {"PYTHONPATH": str(REPO_ROOT / "v2" / "evaluation")}
        steps.append(
            _run_step(
                "pilot_lock_smoke_write_and_verify",
                [
                    py,
                    "v2/evaluation/validate_pilot_lock.py",
                    "--mode",
                    "SMOKE",
                    "--opengrep",
                    str(tmp / "export_pilot" / "alerts.json"),
                    "--labels",
                    "v2/evaluation/smoke_m1_verified_labels.json",
                    "--source-root",
                    str(REPO_ROOT),
                    "--write-lock",
                    str(tmp / "smoke_lock.json"),
                    "--verify-lock",
                    str(tmp / "smoke_lock.json"),
                ],
                env_overrides=eval_env,
            )
        )
        steps.append(
            _run_step(
                "pilot_lock_strict_rejects_smoke_fixture",
                [
                    py,
                    "v2/evaluation/validate_pilot_lock.py",
                    "--mode",
                    "STRICT_LOCK",
                    "--opengrep",
                    str(tmp / "export_pilot" / "alerts.json"),
                    "--labels",
                    "v2/evaluation/smoke_m1_verified_labels.json",
                    "--source-root",
                    str(REPO_ROOT),
                ],
                env_overrides=eval_env,
                expected_nonzero=True,
            )
        )
        steps.append(
            _run_step(
                "paired_pilot_table_contract",
                [
                    py,
                    "v2/evaluation/build_paired_pilot_table.py",
                    "--opengrep",
                    "v2/demo/smoke_m1_rules_raw.opengrep.json",
                    "--labels",
                    "v2/evaluation/smoke_m1_verified_labels.json",
                    "--qwen35-triage",
                    "v2/demo/triage_qwen35_9b_smoke_m1_assessments.jsonl",
                    "--qwen3-8b-reference",
                    "v2/demo/triage_qwen3_8b_summary.json",
                    "--source-root",
                    str(REPO_ROOT),
                    "--output-csv",
                    str(tmp / "paired_pilot.csv"),
                    "--output-json",
                    str(tmp / "paired_pilot.json"),
                ],
            )
        )
        steps.append(
            _run_step(
                "score_pilot_replay_contract",
                [
                    py,
                    "-m",
                    "v2.evaluation.score_pilot",
                    "--opengrep",
                    "v2/demo/smoke_m1_rules_raw.opengrep.json",
                    "--labels",
                    "v2/evaluation/smoke_m1_verified_labels.json",
                    "--triage",
                    "v2/demo/triage_qwen35_9b_smoke_m1_assessments.jsonl",
                    "--source-root",
                    str(REPO_ROOT),
                    "--output-json",
                    str(tmp / "score_pilot.json"),
                    "--output-md",
                    str(tmp / "score_pilot.md"),
                ],
                env_overrides=eval_env,
            )
        )

    summary = {
        "status": "PASS",
        "total_steps": len(steps),
        "steps": steps,
    }
    if output_report is not None:
        output_report.parent.mkdir(parents=True, exist_ok=True)
        output_report.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"PASS: V2 Integration Quality Gate completed ({len(steps)}/{len(steps)} checks passed).")
    return summary


def install_git_pre_push_hook(repo_root: Path = REPO_ROOT) -> Path:
    hooks_dir_raw = subprocess.check_output(
        ["git", "-C", str(repo_root), "rev-parse", "--git-path", "hooks"],
        text=True,
    ).strip()
    hooks_dir = Path(hooks_dir_raw)
    if not hooks_dir.is_absolute():
        hooks_dir = (repo_root / hooks_dir).resolve()
    hook_path = hooks_dir / "pre-push"
    hook_content = """#!/usr/bin/env sh
set -eu
BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo '')"
case "$BRANCH" in
  v2/*)
    echo "[v2-quality-gate] Running V2 Integration Quality Gate before push on $BRANCH..."
    python v2/scripts/run_v2_quality_gate.py
    ;;
esac
"""
    hook_path.parent.mkdir(parents=True, exist_ok=True)
    hook_path.write_text(hook_content, encoding="utf-8", newline="\n")
    try:
        hook_path.chmod(0o755)
    except OSError:
        pass
    print(f"PASS: Installed v2/** pre-push hook at {hook_path}")
    return hook_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-report", type=Path, help="Optional path to write JSON gate receipt.")
    parser.add_argument("--skip-pytest", action="store_true", help="Skip nested pytest invocation.")
    parser.add_argument(
        "--install-git-hook",
        action="store_true",
        help="Install local .git/hooks/pre-push quality gate for v2/** branches.",
    )
    args = parser.parse_args(argv)
    try:
        if args.install_git_hook:
            install_git_pre_push_hook(REPO_ROOT)
        run_quality_gate(output_report=args.output_report, skip_pytest=args.skip_pytest)
        return 0
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
