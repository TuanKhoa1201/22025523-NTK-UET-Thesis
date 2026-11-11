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
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def verify_strict_lock_rejection_output(stdout_text: str, returncode: int) -> dict[str, Any]:
    """Verify STRICT_LOCK exited with code 1 and emitted the expected JSON rejection errors."""
    if returncode != 1:
        raise RuntimeError(
            f"STRICT_LOCK step must exit with code 1 on smoke fixture, got {returncode}"
        )
    try:
        payload = json.loads(stdout_text)
    except Exception as exc:
        raise RuntimeError(f"STRICT_LOCK did not emit valid JSON stdout: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("STRICT_LOCK stdout JSON must be an object")
    if payload.get("lock_mode") != "STRICT_LOCK":
        raise RuntimeError(f"Expected lock_mode='STRICT_LOCK', got {payload.get('lock_mode')!r}")
    if payload.get("valid_lock_candidate") is not False:
        raise RuntimeError("STRICT_LOCK must set valid_lock_candidate=False on smoke fixture")
    if payload.get("m4_acceptance_ready") is not False:
        raise RuntimeError("STRICT_LOCK must set m4_acceptance_ready=False on smoke fixture")
    errors = payload.get("errors")
    if not isinstance(errors, list) or not errors:
        raise RuntimeError("STRICT_LOCK must report non-empty errors[] list on smoke fixture")
    joined = "\n".join(str(e) for e in errors)
    if "outside required pilot window [30, 60]" not in joined:
        raise RuntimeError(
            f"STRICT_LOCK errors missing pilot window [30, 60] rejection: {errors}"
        )
    if "SYNTHETIC_GROUND_TRUTH" not in joined and "synthetic TEST FIXTURE" not in joined:
        raise RuntimeError(
            f"STRICT_LOCK errors missing synthetic ground-truth/fixture rejection: {errors}"
        )
    return payload


def _run_step(
    name: str,
    cmd: list[str],
    cwd: Path = REPO_ROOT,
    env_overrides: dict[str, str] | None = None,
    expected_exit_code: int = 0,
) -> tuple[dict[str, Any], subprocess.CompletedProcess[str]]:
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
    passed = proc.returncode == expected_exit_code
    status = "PASS" if passed else "FAIL"
    print(f"[{status}] {name} (exit_code={proc.returncode}, expected={expected_exit_code})")
    if not passed:
        if proc.stdout:
            print(proc.stdout, file=sys.stderr)
        if proc.stderr:
            print(proc.stderr, file=sys.stderr)
        raise RuntimeError(
            f"Quality gate step '{name}' failed with exit code {proc.returncode} "
            f"(expected {expected_exit_code})"
        )
    return (
        {
            "step": name,
            "status": status,
            "exit_code": proc.returncode,
            "expected_exit_code": expected_exit_code,
            "command": cmd,
        },
        proc,
    )


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
        )[0]
    )
    steps.append(
        _run_step(
            "upstream_patch_verification",
            [py, "v2/baseline/verify_patch.py"],
        )[0]
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
            )[0]
        )

    with tempfile.TemporaryDirectory(prefix="ntk_v2_ci_gate_") as tmp_str:
        tmp = Path(tmp_str)
        smoke_root = REPO_ROOT / "v2" / "evaluation" / "smoke_evidence"
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
            )[0]
        )
        # 1. Verify legacy --json import WITHOUT --scan-manifest fails closed (exit code 2)
        step_legacy, _ = _run_step(
            "triage_legacy_declared_import_fails_closed",
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
                str(tmp / "triage_declared_only"),
                "--no-llm",
            ],
            expected_exit_code=2,
        )
        declared_ev = json.loads((tmp / "triage_declared_only" / "evidence.json").read_text(encoding="utf-8"))
        if (
            declared_ev.get("scan_provenance", {}).get("origin") != "declared_only"
            or declared_ev.get("scan_provenance", {}).get("source_capture_verified") is not False
        ):
            raise RuntimeError("Legacy declared import did not record origin='declared_only' and source_capture_verified=False")
        steps.append(step_legacy)

        # 2. Verify manifest-bound import contract passes (exit code 0)
        from v2.triage.tests.capture_fixture import make_capture

        raw_smoke_bytes = (REPO_ROOT / "v2" / "demo" / "smoke_m1_rules_raw.opengrep.json").read_bytes()
        capture_dir = tmp / "manifest_capture"
        manifest_path = make_capture(smoke_root, raw_smoke_bytes, capture_dir)

        step_manifest, _ = _run_step(
            "triage_manifest_bound_import_contract",
            [
                py,
                "-m",
                "v2.triage",
                "run",
                "--source-root",
                str(smoke_root),
                "--path-base",
                str(REPO_ROOT),
                "--json",
                str(capture_dir / "opengrep.json"),
                "--scan-manifest",
                str(manifest_path),
                "--engine-exit",
                "0",
                "--output-dir",
                str(tmp / "triage_no_llm"),
                "--no-llm",
            ],
            expected_exit_code=0,
        )
        bound_ev = json.loads((tmp / "triage_no_llm" / "evidence.json").read_text(encoding="utf-8"))
        if bound_ev.get("scan_provenance", {}).get("source_capture_verified") is not True:
            raise RuntimeError("Manifest-bound import did not record source_capture_verified=True")
        steps.append(step_manifest)

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
            )[0]
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
                    str(smoke_root),
                    "--write-lock",
                    str(tmp / "smoke_lock.json"),
                    "--verify-lock",
                    str(tmp / "smoke_lock.json"),
                ],
                env_overrides=eval_env,
            )[0]
        )
        step_strict, proc_strict = _run_step(
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
                str(smoke_root),
            ],
            env_overrides=eval_env,
            expected_exit_code=1,
        )
        verify_strict_lock_rejection_output(proc_strict.stdout, proc_strict.returncode)
        steps.append(step_strict)
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
            )[0]
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
            )[0]
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
TOPLEVEL="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$TOPLEVEL"
BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo '')"
SHOULD_RUN=0
case "$BRANCH" in
  v2/*) SHOULD_RUN=1 ;;
esac
while read -r local_ref local_sha remote_ref remote_sha; do
  case "$local_ref" in
    refs/heads/v2/*) SHOULD_RUN=1 ;;
  esac
  case "$remote_ref" in
    refs/heads/v2/*) SHOULD_RUN=1 ;;
  esac
done
if [ "$SHOULD_RUN" -eq 1 ]; then
  echo "[v2-quality-gate] Running V2 Integration Quality Gate before push in $TOPLEVEL (branch=$BRANCH)..."
  python v2/scripts/run_v2_quality_gate.py
fi
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
