"""Reproducible 4-scenario G1 end-to-end demo runner via the inherited simple_semgrepAI CLI.

Executes all 4 mandatory G1 scenarios into a fresh private directory outside Git:
- Demo 1: True-positive Java CWE-89 & CWE-22 alerts (real OpenGrep + real local Qwen + confirm-true)
- Demo 2: Protected Java CWE-22 candidate (real OpenGrep + real local Qwen + confirm-false -> queue -> queue --all -> reopen -> history)
- Demo 3: UNDETERMINED handling:
    3a) Real OpenGrep + real local Qwen on missing external helper implementation
    3b) Explicitly labeled SYNTHETIC_MOCK_HTTP malformed JSON response -> UNDETERMINED + OPEN queue retention
- Demo 4: STALE_SOURCE guard on post-scan modified Java copy -> confirm-false refused (exit 2), warning stays OPEN, 0 accepted events, 1 rejected_decisions row.

Also supports `--auxiliary-controls-only` to run strictly Demo 3b (`SYNTHETIC_MOCK_HTTP`) and
Demo 4 (`--no-llm` mutable copy `STALE_SOURCE`) with zero real Qwen HTTP calls, preventing
duplicate 8-call model invocations when Demo 1 / Demo 2 / Demo 3a are already executed once in
the primary acceptance set.
"""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import sys
import threading
from typing import Any

from v2.g1_integration.exec_receipt import execute_with_receipt
from v2.triage.evidence import digest

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_DIR = Path(__file__).resolve().parent / "demo_fixtures"
DEFAULT_RULES = Path(__file__).resolve().parent / "rules" / "java_g1_cwe22_cwe89.yml"


def _db_sha256(db_path: Path) -> str | None:
    return digest(db_path.read_bytes()) if db_path.is_file() else None


def _snapshot_db_readonly_copy(db_path: Path, snapshot_path: Path) -> str | None:
    if not db_path.is_file():
        return None
    if snapshot_path.exists():
        raise FileExistsError(f"refusing to overwrite DB snapshot: {snapshot_path}")
    shutil.copy2(db_path, snapshot_path)
    for ext in ("-wal", "-shm"):
        side = Path(str(db_path) + ext)
        if side.is_file():
            shutil.copy2(side, Path(str(snapshot_path) + ext))
    return digest(snapshot_path.read_bytes())


def _run_semgrepai_cli(
    prepared_source: Path,
    cli_args: list[str],
    *,
    expected_exit: int | None = 0,
    receipt_dir: Path | None = None,
    step_name: str | None = None,
) -> dict[str, Any]:
    env = os.environ.copy()
    existing_pp = env.get("PYTHONPATH", "")
    parts = [str(prepared_source.resolve()), str(REPO_ROOT.resolve())]
    if existing_pp:
        parts.append(existing_pp)
    env["PYTHONPATH"] = os.pathsep.join(parts)
    env["NTK_G1_REPO_ROOT"] = str(REPO_ROOT.resolve())
    env["PYTHONUTF8"] = "1"

    cmd = [sys.executable, "-X", "utf8", "-B", "-m", "semgrepai", *cli_args]
    if receipt_dir is not None and step_name is not None:
        receipt = execute_with_receipt(
            cmd,
            receipt_dir=receipt_dir,
            step=step_name,
            cwd=REPO_ROOT.resolve(),
            env=env,
            expected_exits=None,
        )
        stdout_bytes = (receipt_dir / receipt["stdout_raw_file"]).read_bytes()
        stderr_bytes = (receipt_dir / receipt["stderr_raw_file"]).read_bytes()
        returncode = int(receipt["exit_code"])
    else:
        import subprocess
        proc = subprocess.run(cmd, cwd=str(REPO_ROOT.resolve()), env=env, capture_output=True, text=False)
        stdout_bytes = bytes(proc.stdout or b"")
        stderr_bytes = bytes(proc.stderr or b"")
        returncode = proc.returncode
        receipt = None

    stdout_text = stdout_bytes.decode("utf-8", errors="replace")
    stderr_text = stderr_bytes.decode("utf-8", errors="replace")
    if expected_exit is not None and returncode != expected_exit:
        raise RuntimeError(
            f"CLI command failed (expected exit {expected_exit}, got {returncode}): {cmd}\n"
            f"STDOUT:\n{stdout_text}\nSTDERR:\n{stderr_text}"
        )

    parsed_stdout = None
    stripped = stdout_text.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            parsed_stdout = json.loads(stripped)
        except ValueError:
            parsed_stdout = None
    if parsed_stdout is None and "--output-dir" in cli_args:
        out_idx = cli_args.index("--output-dir") + 1
        if out_idx < len(cli_args):
            summary_file = Path(cli_args[out_idx]) / "g1-cli-summary.json"
            if summary_file.is_file():
                parsed_stdout = json.loads(summary_file.read_text(encoding="utf-8"))
    return {
        "argv": cmd,
        "exit_code": returncode,
        "stdout": stdout_text,
        "stderr": stderr_text,
        "stdout_sha256": digest(stdout_bytes),
        "stderr_sha256": digest(stderr_bytes),
        "receipt_file": receipt["step"] + ".receipt.json" if receipt is not None else None,
        "json": parsed_stdout,
    }


def run_demo_suite(
    *,
    prepared_source: Path,
    output_dir: Path,
    executable: str = "opengrep",
    endpoint: str = "http://127.0.0.1:11434",
    model: str = "qwen3.5:9b-q4_K_M",
    timeout: float = 180.0,
    no_llm: bool = False,
    auxiliary_controls_only: bool = False,
) -> dict[str, Any]:
    prepared_source = Path(prepared_source).resolve(strict=True)
    output_dir = Path(output_dir).resolve()
    if output_dir.exists():
        raise FileExistsError(f"Demo output_dir must not already exist: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=False)
    receipts_dir = output_dir / "child_receipts"
    receipts_dir.mkdir(parents=True, exist_ok=False)

    step_seq = 0

    def _step(label: str, cli_args: list[str], *, expected_exit: int | None = 0) -> dict[str, Any]:
        nonlocal step_seq
        step_seq += 1
        return _run_semgrepai_cli(
            prepared_source,
            cli_args,
            expected_exit=expected_exit,
            receipt_dir=receipts_dir,
            step_name=f"{step_seq:02d}_{label}",
        )

    llm_flags = ["--no-llm"] if no_llm else ["--endpoint", endpoint, "--model", model, "--timeout", str(timeout)]
    evidence_kind = "DISABLED_NO_LLM" if no_llm else "REAL_RUNTIME"
    scenarios: dict[str, Any] = {}

    if not auxiliary_controls_only:
        # ---------------------------------------------------------------------
        # Demo 1: True Positive (CWE-89 & CWE-22)
        # ---------------------------------------------------------------------
        demo1_dir = output_dir / "demo1_true_positive"
        d1_scan = _step(
            "demo1_scan",
            [
                "scan",
                str(FIXTURES_DIR / "Demo1TruePositive.java"),
                "--rules-path",
                str(DEFAULT_RULES),
                "--output-dir",
                str(demo1_dir),
                "--local-triage",
                "--executable",
                executable,
                "--prompt-contract",
                "blind",
                *llm_flags,
            ],
            expected_exit=0,
        )
        d1_db_path = demo1_dir / "triage" / "review.sqlite"
        d1_ingestion_db_sha = _snapshot_db_readonly_copy(
            d1_db_path, demo1_dir / "triage" / "review.post_ingestion.sqlite"
        )
        d1_db = str(d1_db_path)
        d1_queue_before = _step("demo1_queue_initial", ["queue", "--db", d1_db], expected_exit=0)["json"]
        d1_first_id = d1_queue_before["warnings"][0]["id"]
        d1_show = _step("demo1_show", ["show", d1_first_id, "--db", d1_db], expected_exit=0)["json"]
        d1_confirm = _step(
            "demo1_confirm_true",
            [
                "confirm-true",
                d1_first_id,
                "--db",
                d1_db,
                "--actor",
                "ntk-demo-operator",
                "--reason",
                "Confirmed unsanitized request parameter reaching sink along direct taint trace",
            ],
            expected_exit=0,
        )["json"]
        d1_after_confirm_db_sha = _db_sha256(d1_db_path)
        d1_history = _step("demo1_history", ["history", d1_first_id, "--db", d1_db], expected_exit=0)["json"]

        scenarios["demo1_true_positive"] = {
            "evidence_kind": evidence_kind,
            "scan_summary": d1_scan["json"],
            "post_ingestion_db_sha256": d1_ingestion_db_sha,
            "after_confirm_true_db_sha256": d1_after_confirm_db_sha,
            "initial_queue": d1_queue_before["warnings"],
            "confirmed_true_warning_id": d1_first_id,
            "confirmed_state": d1_confirm["state"],
            "history_events": len(d1_history),
            "has_trace": bool(d1_show["evidence"].get("raw_trace")),
        }

        # ---------------------------------------------------------------------
        # Demo 2: Protected Candidate -> confirm-false -> hidden -> queue --all -> reopen
        # ---------------------------------------------------------------------
        demo2_dir = output_dir / "demo2_false_positive_reopen"
        d2_scan = _step(
            "demo2_scan",
            [
                "scan",
                str(FIXTURES_DIR / "Demo2ProtectedFalsePositive.java"),
                "--rules-path",
                str(DEFAULT_RULES),
                "--output-dir",
                str(demo2_dir),
                "--local-triage",
                "--executable",
                executable,
                "--prompt-contract",
                "blind",
                *llm_flags,
            ],
            expected_exit=0,
        )
        d2_db_path = demo2_dir / "triage" / "review.sqlite"
        d2_ingestion_db_sha = _snapshot_db_readonly_copy(
            d2_db_path, demo2_dir / "triage" / "review.post_ingestion.sqlite"
        )
        d2_db = str(d2_db_path)
        d2_queue_initial = _step("demo2_queue_initial", ["queue", "--db", d2_db], expected_exit=0)["json"]
        d2_id = d2_queue_initial["warnings"][0]["id"]
        d2_confirm_false = _step(
            "demo2_confirm_false",
            [
                "confirm-false",
                d2_id,
                "--db",
                d2_db,
                "--actor",
                "ntk-demo-operator",
                "--reason",
                "Verified getCanonicalPath().startsWith('/srv/reports/') boundary guard prior to FileInputStream",
            ],
            expected_exit=0,
        )["json"]
        d2_after_false_db_sha = _snapshot_db_readonly_copy(
            d2_db_path, demo2_dir / "triage" / "review.after_confirm_false.sqlite"
        )
        d2_queue_after_false = _step("demo2_queue_after_false", ["queue", "--db", d2_db], expected_exit=0)["json"]
        d2_queue_all = _step("demo2_queue_all", ["queue", "--db", d2_db, "--all"], expected_exit=0)["json"]
        d2_reopen = _step(
            "demo2_reopen",
            [
                "reopen",
                d2_id,
                "--db",
                d2_db,
                "--actor",
                "ntk-lead-reviewer",
                "--reason",
                "Reopened to verify symlink policy on /srv/reports mount",
            ],
            expected_exit=0,
        )["json"]
        d2_after_reopen_db_sha = _db_sha256(d2_db_path)
        d2_queue_reopened = _step("demo2_queue_after_reopen", ["queue", "--db", d2_db], expected_exit=0)["json"]
        d2_history = _step("demo2_history", ["history", d2_id, "--db", d2_db], expected_exit=0)["json"]

        scenarios["demo2_false_positive_reopen"] = {
            "evidence_kind": evidence_kind,
            "scan_summary": d2_scan["json"],
            "post_ingestion_db_sha256": d2_ingestion_db_sha,
            "after_confirm_false_db_sha256": d2_after_false_db_sha,
            "after_reopen_db_sha256": d2_after_reopen_db_sha,
            "warning_id": d2_id,
            "initial_state": d2_queue_initial["warnings"][0]["state"],
            "after_confirm_false_default_queue_count": len(d2_queue_after_false["warnings"]),
            "after_confirm_false_all_queue_state": d2_queue_all["warnings"][0]["state"],
            "after_reopen_default_queue_state": d2_queue_reopened["warnings"][0]["state"],
            "history_actions": [e["action"] for e in d2_history],
        }

        # ---------------------------------------------------------------------
        # Demo 3A: Missing external helper context -> real OpenGrep + real Qwen
        # ---------------------------------------------------------------------
        demo3a_dir = output_dir / "demo3a_missing_helper_real"
        d3a_scan = _step(
            "demo3a_scan",
            [
                "scan",
                str(FIXTURES_DIR / "Demo3ExternalHelperUndetermined.java"),
                "--rules-path",
                str(DEFAULT_RULES),
                "--output-dir",
                str(demo3a_dir),
                "--local-triage",
                "--executable",
                executable,
                "--prompt-contract",
                "blind",
                *llm_flags,
            ],
            expected_exit=0,
        )
        d3a_db_path = demo3a_dir / "triage" / "review.sqlite"
        d3a_ingestion_db_sha = _snapshot_db_readonly_copy(
            d3a_db_path, demo3a_dir / "triage" / "review.post_ingestion.sqlite"
        )
        d3a_db = str(d3a_db_path)
        d3a_queue = _step("demo3a_queue_initial", ["queue", "--db", d3a_db], expected_exit=0)["json"]

        scenarios["demo3a_missing_helper_real"] = {
            "evidence_kind": evidence_kind,
            "scan_summary": d3a_scan["json"],
            "post_ingestion_db_sha256": d3a_ingestion_db_sha,
            "queue_warnings": d3a_queue["warnings"],
        }

    # -------------------------------------------------------------------------
    # Demo 3B: Explicit SYNTHETIC_MOCK_HTTP malformed JSON -> UNDETERMINED + OPEN
    # -------------------------------------------------------------------------
    class _MalformedJsonMockHandler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path == "/api/tags":
                body = json.dumps({"models": [{"name": "qwen-mock:synthetic", "digest": "mock", "size": 0}]}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_error(404)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            if length:
                self.rfile.read(length)
            body = json.dumps({
                "done": True,
                "done_reason": "stop",
                "model": "qwen-mock:synthetic",
                "mock_test_fixture": True,
                "message": {"role": "assistant", "content": '{"status":"REFUTED","explanation":"SYNTHETIC truncated JSON'},
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    mock_server = ThreadingHTTPServer(("127.0.0.1", 0), _MalformedJsonMockHandler)
    mock_thread = threading.Thread(target=mock_server.serve_forever, daemon=True)
    mock_thread.start()
    try:
        demo3b_dir = output_dir / "demo3b_malformed_llm_synthetic_mock"
        d3b_scan = _step(
            "demo3b_mock_scan",
            [
                "scan",
                str(FIXTURES_DIR / "Demo2ProtectedFalsePositive.java"),
                "--rules-path",
                str(DEFAULT_RULES),
                "--output-dir",
                str(demo3b_dir),
                "--local-triage",
                "--executable",
                executable,
                "--endpoint",
                f"http://127.0.0.1:{mock_server.server_port}",
                "--model",
                "qwen-mock:synthetic",
                "--runtime-origin",
                "mock",
            ],
            expected_exit=0,
        )
        d3b_db_path = demo3b_dir / "triage" / "review.sqlite"
        _snapshot_db_readonly_copy(
            d3b_db_path, demo3b_dir / "triage" / "review.post_ingestion.sqlite"
        )
        d3b_db = str(d3b_db_path)
        d3b_queue = _step("demo3b_mock_queue", ["queue", "--db", d3b_db], expected_exit=0)["json"]
    finally:
        mock_server.shutdown()
        mock_server.server_close()
        mock_thread.join(timeout=2)

    scenarios["demo3b_malformed_json_mock"] = {
        "evidence_kind": "SYNTHETIC_MOCK_HTTP",
        "excluded_from_real_qwen_denominator": True,
        "scan_summary": d3b_scan["json"],
        "queue_warnings": d3b_queue["warnings"],
    }

    # -------------------------------------------------------------------------
    # Demo 4: STALE_SOURCE on post-scan modified Java copy -> confirm-false refused
    # -------------------------------------------------------------------------
    demo4_ws = output_dir / "demo4_workspace"
    demo4_ws.mkdir(parents=True, exist_ok=False)
    demo4_target = demo4_ws / "Demo4MutableCopy.java"
    shutil.copy2(FIXTURES_DIR / "Demo2ProtectedFalsePositive.java", demo4_target)
    pre_mutation_bytes = demo4_target.read_bytes()
    pre_mutation_sha = digest(pre_mutation_bytes)
    (demo4_ws / "Demo4MutableCopy.pre_mutation.snapshot").write_bytes(pre_mutation_bytes)

    demo4_dir = output_dir / "demo4_stale_source"
    d4_scan = _step(
        "demo4_scan_no_llm",
        [
            "scan",
            str(demo4_target),
            "--rules-path",
            str(DEFAULT_RULES),
            "--output-dir",
            str(demo4_dir),
            "--local-triage",
            "--executable",
            executable,
            "--no-llm",
        ],
        expected_exit=0,
    )
    d4_db_path = demo4_dir / "triage" / "review.sqlite"
    d4_ingestion_db_sha = _snapshot_db_readonly_copy(
        d4_db_path, demo4_dir / "triage" / "review.post_ingestion.sqlite"
    )
    d4_db = str(d4_db_path)
    d4_queue_initial = _step("demo4_queue_initial", ["queue", "--db", d4_db], expected_exit=0)["json"]
    d4_id = d4_queue_initial["warnings"][0]["id"]

    # Mutate copied Java file after scan to trigger STALE_SOURCE
    demo4_target.write_text(
        demo4_target.read_text(encoding="utf-8") + "\n// Post-scan edit: invalidates SHA-256 snapshot\n",
        encoding="utf-8",
    )
    post_mutation_bytes = demo4_target.read_bytes()
    post_mutation_sha = digest(post_mutation_bytes)
    (demo4_ws / "Demo4MutableCopy.post_mutation.snapshot").write_bytes(post_mutation_bytes)

    d4_refused = _step(
        "demo4_confirm_false_refused",
        [
            "confirm-false",
            d4_id,
            "--db",
            d4_db,
            "--actor",
            "ntk-demo-operator",
            "--reason",
            "Attempted false confirmation after source file changed on disk",
        ],
        expected_exit=2,
    )
    d4_after_refusal_db_sha = _db_sha256(d4_db_path)
    d4_queue_after = _step("demo4_queue_after_refusal", ["queue", "--db", d4_db], expected_exit=0)["json"]
    d4_history_events = _step("demo4_history_events", ["history", d4_id, "--db", d4_db], expected_exit=0)["json"]
    d4_history_with_rejected = _step(
        "demo4_history_with_rejected",
        ["history", d4_id, "--db", d4_db, "--include-rejected"],
        expected_exit=0,
    )["json"]

    scenarios["demo4_stale_source"] = {
        "evidence_kind": "REAL_OPENGREP_SCAN_AND_SQLITE_GUARD",
        "excluded_from_real_qwen_denominator": True,
        "scan_summary": d4_scan["json"],
        "pre_mutation_source_sha256": pre_mutation_sha,
        "post_mutation_source_sha256": post_mutation_sha,
        "post_ingestion_db_sha256": d4_ingestion_db_sha,
        "after_refused_confirm_false_db_sha256": d4_after_refusal_db_sha,
        "warning_id": d4_id,
        "confirm_false_exit_code": d4_refused["exit_code"],
        "confirm_false_stderr": d4_refused["stderr"].strip(),
        "queue_state_after_refusal": d4_queue_after["warnings"][0]["state"],
        "accepted_events_count": len(d4_history_events),
        "rejected_decisions": d4_history_with_rejected["rejected_decisions"],
    }

    summary_doc = {
        "schema": "ntk-g1-demo-summary-1",
        "output_dir": str(output_dir),
        "child_receipts_dir": str(receipts_dir),
        "prepared_source": str(prepared_source),
        "executable": executable,
        "auxiliary_controls_only": auxiliary_controls_only,
        "ollama_endpoint": None if (no_llm or auxiliary_controls_only) else endpoint,
        "requested_model": None if (no_llm or auxiliary_controls_only) else model,
        "scenarios": scenarios,
    }
    (output_dir / "demo-summary.json").write_text(
        json.dumps(summary_doc, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return summary_doc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run reproducible G1 demo scenarios via inherited semgrepai CLI")
    parser.add_argument("--prepared-source", type=Path, required=True, help="Path to <prepared_fork>/source")
    parser.add_argument("--output-dir", type=Path, required=True, help="Fresh private directory for demo outputs")
    parser.add_argument("--executable", default="opengrep", help="OpenGrep binary name or path")
    parser.add_argument("--endpoint", default="http://127.0.0.1:11434", help="Loopback HTTP Ollama endpoint")
    parser.add_argument("--model", default="qwen3.5:9b-q4_K_M", help="Local Qwen model tag in Ollama")
    parser.add_argument("--timeout", type=float, default=180.0, help="Per-finding Ollama HTTP timeout")
    parser.add_argument("--no-llm", action="store_true", help="Skip live Ollama calls (dry-run)")
    parser.add_argument(
        "--auxiliary-controls-only",
        action="store_true",
        help="Run only Demo 3b (SYNTHETIC_MOCK_HTTP) and Demo 4 (--no-llm STALE_SOURCE) with zero real Qwen calls",
    )
    args = parser.parse_args(argv)
    summary_doc = run_demo_suite(
        prepared_source=args.prepared_source,
        output_dir=args.output_dir,
        executable=args.executable,
        endpoint=args.endpoint,
        model=args.model,
        timeout=args.timeout,
        no_llm=args.no_llm,
        auxiliary_controls_only=args.auxiliary_controls_only,
    )
    print(json.dumps(summary_doc, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
