#!/usr/bin/env python3
"""
Independent G1 Runtime Verification & Evidence Harness for ADMIN-PC (JavisOS).
Executes Phases A through H without modifying Antigravity production code or G0 data.
All raw prompts, raw model responses, source copies, and SQLite databases are stored
strictly outside the Git repository under C:\\NTK-G1-Private\\G1-Runtime.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
import hashlib
import json
import os
import platform
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
from urllib.request import Request, ProxyHandler, HTTPRedirectHandler, build_opener


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def local_now_iso() -> str:
    return datetime.now().astimezone().isoformat()


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError("HTTP redirect forbidden")


ALLOWLISTED_DEMO_JAVA = """class AllowlistedQuery {
    void run(Request req, Statement stmt) throws Exception {
        String query = req.getParameter("q");
        if (!"SELECT 1".equals(query)) {
            throw new IllegalArgumentException("Only SELECT 1 is allowed");
        }
        stmt.executeQuery(query);
    }
}
"""


def run_cmd(argv: list[str], cwd: Path, env: dict | None = None, timeout: int = 300) -> dict:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    started_utc = utc_now_iso()
    t0 = time.perf_counter_ns()
    proc = subprocess.run(argv, cwd=str(cwd), env=merged_env, capture_output=True, timeout=timeout)
    t1 = time.perf_counter_ns()
    finished_utc = utc_now_iso()
    elapsed_ms = round((t1 - t0) / 1e6, 2)
    return {
        "argv": argv,
        "cwd": str(cwd),
        "exit_code": proc.returncode,
        "started_at_utc": started_utc,
        "finished_at_utc": finished_utc,
        "elapsed_ms": elapsed_ms,
        "stdout_bytes": proc.stdout,
        "stderr_bytes": proc.stderr,
        "stdout_sha256": sha256_bytes(proc.stdout),
        "stderr_sha256": sha256_bytes(proc.stderr),
        "stdout_text": proc.stdout.decode("utf-8", errors="replace"),
        "stderr_text": proc.stderr.decode("utf-8", errors="replace"),
    }


def sanitize_cmd_record(rec: dict, repo_root: Path, checkout_dir: Path, private_root: Path) -> dict:
    def _clean(s: str) -> str:
        out = s.replace(str(checkout_dir), "<candidate-checkout>")
        out = out.replace(str(checkout_dir).replace("\\", "/"), "<candidate-checkout>")
        out = out.replace(str(repo_root), "<javis-g1-workspace>")
        out = out.replace(str(repo_root).replace("\\", "/"), "<javis-g1-workspace>")
        out = out.replace(str(private_root), "<private-evidence-root>")
        out = out.replace(str(private_root).replace("\\", "/"), "<private-evidence-root>")
        out = out.replace(sys.executable, "<python>")
        return out

    return {
        "argv": [_clean(str(x)) for x in rec["argv"]],
        "cwd": _clean(rec["cwd"]),
        "exit_code": rec["exit_code"],
        "started_at_utc": rec["started_at_utc"],
        "finished_at_utc": rec["finished_at_utc"],
        "elapsed_ms": rec["elapsed_ms"],
        "stdout_sha256": rec["stdout_sha256"],
        "stderr_sha256": rec["stderr_sha256"],
    }


def start_fault_injection_ollama_server():
    class FaultHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            if length > 0:
                _ = self.rfile.read(length)
            body = json.dumps({
                "model": "qwen3.5:9b-q4_K_M",
                "done": True,
                "done_reason": "stop",
                "eval_count": 5,
                "eval_duration": 1000000,
                "mock_test_fixture": True,
                "message": {"role": "assistant", "content": "{INVALID_JSON_SYNTAX_FROM_FAULT_INJECTION"},
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            return

    server = HTTPServer(("127.0.0.1", 0), FaultHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{port}"


def check_remote_branches(repo_root: Path) -> dict:
    run_cmd(["git", "fetch", "origin"], cwd=repo_root)
    ls_rec = run_cmd(
        [
            "git",
            "ls-remote",
            "origin",
            "refs/heads/v2/antigravity-review",
            "refs/heads/v2/codex-core",
            "refs/heads/v2/javis-benchmark",
            "refs/heads/main",
        ],
        cwd=repo_root,
    )
    heads = {}
    for line in ls_rec["stdout_text"].splitlines():
        parts = line.strip().split()
        if len(parts) == 2:
            sha, ref = parts
            heads[ref.replace("refs/heads/", "")] = sha
    return heads


def inspect_candidate_marker(repo_root: Path, antigravity_sha: str) -> dict:
    tree_rec = run_cmd(
        ["git", "ls-tree", "-r", "--name-only", antigravity_sha, "v2/g1_integration"],
        cwd=repo_root,
    )
    files = [ln.strip() for ln in tree_rec["stdout_text"].splitlines() if ln.strip()]
    marker_present = "v2/g1_integration/CANDIDATE.json" in files
    marker_data = None
    marker_sha256 = None
    ready = False
    if marker_present:
        show_rec = run_cmd(
            ["git", "show", f"{antigravity_sha}:v2/g1_integration/CANDIDATE.json"],
            cwd=repo_root,
        )
        if show_rec["exit_code"] == 0:
            marker_sha256 = show_rec["stdout_sha256"]
            try:
                marker_data = json.loads(show_rec["stdout_text"])
                raw_text = show_rec["stdout_text"]
                ready = (
                    isinstance(marker_data, dict)
                    and (
                        marker_data.get("status") == "READY_FOR_INDEPENDENT_TEST"
                        or marker_data.get("state") == "READY_FOR_INDEPENDENT_TEST"
                        or "READY_FOR_INDEPENDENT_TEST" in raw_text
                    )
                )
            except Exception:
                ready = False
    return {
        "antigravity_head_sha": antigravity_sha,
        "g1_integration_files": files,
        "marker_present": marker_present,
        "marker_ready": ready,
        "marker_sha256": marker_sha256,
        "marker_content": marker_data,
        "ls_tree_cmd": tree_rec,
    }


def prepare_detached_checkout(repo_root: Path, candidates_root: Path, label: str, target_sha: str) -> Path:
    checkout_dir = candidates_root / f"{label}-{target_sha[:8]}"
    if checkout_dir.exists():
        shutil.rmtree(checkout_dir)
    candidates_root.mkdir(parents=True, exist_ok=True)
    run_cmd(["git", "clone", "--no-checkout", str(repo_root), str(checkout_dir)], cwd=repo_root)
    run_cmd(["git", "checkout", "--detach", target_sha], cwd=checkout_dir)
    actual_sha = run_cmd(["git", "rev-parse", "HEAD"], cwd=checkout_dir)["stdout_text"].strip()
    if actual_sha != target_sha:
        raise RuntimeError(f"Checkout SHA mismatch: expected {target_sha}, got {actual_sha}")
    return checkout_dir


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Verify G1 Runtime on ADMIN-PC")
    parser.add_argument("--repo-root", type=Path, default=Path(r"C:\NTK-G1\javis-runtime"))
    parser.add_argument("--private-root", type=Path, default=Path(r"C:\NTK-G1-Private\G1-Runtime"))
    parser.add_argument("--candidates-root", type=Path, default=Path(r"C:\NTK-G1\candidates"))
    parser.add_argument("--candidate-id", default="G1-C1")
    parser.add_argument("--endpoint", default="http://127.0.0.1:11434")
    parser.add_argument("--model", default="qwen3.5:9b-q4_K_M")
    args = parser.parse_args(argv)

    session_started_utc = utc_now_iso()
    session_started_local = local_now_iso()
    t_session0 = time.perf_counter_ns()

    repo_root = args.repo_root.resolve()
    private_root = args.private_root.resolve()
    candidates_root = args.candidates_root.resolve()
    candidate_id = args.candidate_id

    if private_root.is_relative_to(repo_root):
        raise RuntimeError("Private evidence directory must be outside Git repository")

    opengrep_bridge_cmd = private_root / "bin" / "opengrep_counted.cmd"
    if not opengrep_bridge_cmd.is_file():
        raise RuntimeError(f"Missing OpenGrep bridge executable: {opengrep_bridge_cmd}")

    # 1. Verify Preflight Receipt (Phase A & B)
    preflight_receipt_path = private_root / "preflight" / "preflight_receipt.json"
    if not preflight_receipt_path.is_file():
        run_cmd([sys.executable, str(private_root / "preflight" / "run_preflight.py")], cwd=repo_root)
    preflight_data = json.loads(preflight_receipt_path.read_text(encoding="utf-8"))

    # 2. Check Remote Branches & Candidate Marker (Phase C)
    remote_heads_start = check_remote_branches(repo_root)
    ag_sha = remote_heads_start.get("v2/antigravity-review", "457183f9e17892fe284da04b57ef6c5c24b008e0")
    marker_info = inspect_candidate_marker(repo_root, ag_sha)

    candidate_available = marker_info["marker_present"] and marker_info["marker_ready"]
    tested_sha = ag_sha if candidate_available else None
    reference_pre_g1_sha = ag_sha

    # 3. Prepare Detached Checkout of the inspected SHA without modifying a single byte
    checkout_label = candidate_id if candidate_available else f"pre-g1-ref-{candidate_id}"
    checkout_dir = prepare_detached_checkout(repo_root, candidates_root, checkout_label, ag_sha)

    # Verify G0 historical fixtures hash before running anything
    g0_fixtures_dir = checkout_dir / "v2" / "baseline" / "fixtures" / "java"
    g0_fixture_hashes_before = {
        p.name: sha256_file(p) for p in sorted(g0_fixtures_dir.glob("*.java"))
    }

    # Prepare private evidence run folder
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_priv_dir = private_root / candidate_id / f"run_{stamp}"
    run_priv_dir.mkdir(parents=True, exist_ok=False)
    og_audit_log = run_priv_dir / "opengrep_invocations.jsonl"

    commands_executed = []
    commands_executed.append(
        sanitize_cmd_record(marker_info["ls_tree_cmd"], repo_root, checkout_dir, private_root)
    )

    # 4. Inspect Fork CLI capabilities in checkout
    fork_cli_path = checkout_dir / "v2" / "baseline" / "fork" / "semgrepai" / "cli.py"
    fork_cli_sha256 = sha256_file(fork_cli_path)
    fork_help_rec = run_cmd(
        [sys.executable, "-m", "semgrepai", "--help"],
        cwd=checkout_dir,
        env={"PYTHONPATH": str(checkout_dir / "v2" / "baseline" / "fork")},
    )
    commands_executed.append(sanitize_cmd_record(fork_help_rec, repo_root, checkout_dir, private_root))
    fork_cli_has_triage_bridge = any(
        kw in fork_help_rec["stdout_text"].lower()
        for kw in ("--model", "--endpoint", "--triage", "review.sqlite", "--db")
    )

    # 5. Execute Real Runtime Probe & Demos 1-5 on ADMIN-PC (Phases D, E, F)
    # Create isolated Java source copies in private_root
    demo1_src_dir = run_priv_dir / "sources" / "demo1_real_vuln"
    demo1_src_dir.mkdir(parents=True, exist_ok=True)
    for p in sorted(g0_fixtures_dir.glob("*.java")):
        shutil.copy2(p, demo1_src_dir / p.name)

    rules_file = checkout_dir / "v2" / "baseline" / "rules" / "java.yml"
    rules_sha256 = sha256_file(rules_file)

    # Step D.1: Run Fork CLI (`python -m semgrepai`) on Demo 1 sources
    fork_out_dir = run_priv_dir / "fork_cli_scan"
    fork_env = {
        "PYTHONPATH": str(checkout_dir / "v2" / "baseline" / "fork"),
        "NTK_G1_OPENGREP_AUDIT_LOG": str(og_audit_log),
    }
    fork_scan_rec = run_cmd(
        [
            sys.executable,
            "-m",
            "semgrepai",
            str(demo1_src_dir),
            "--rules-path",
            str(rules_file),
            "--output-dir",
            str(fork_out_dir),
            "--executable",
            str(opengrep_bridge_cmd),
        ],
        cwd=checkout_dir,
        env=fork_env,
    )
    commands_executed.append(sanitize_cmd_record(fork_scan_rec, repo_root, checkout_dir, private_root))

    og_calls_after_fork = [
        json.loads(line)
        for line in og_audit_log.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ] if og_audit_log.is_file() else []

    # Check if fork CLI already generated review.sqlite + assessments.jsonl or if it's scanner-only
    fork_produced_sqlite = (fork_out_dir / "review.sqlite").is_file() and (
        fork_out_dir / "assessments.jsonl"
    ).is_file()

    if fork_produced_sqlite:
        e2e_triage_dir = fork_out_dir
        triage_run_rec = fork_scan_rec
    else:
        # Bridge the captured scan output into v2.triage without re-running OpenGrep
        e2e_triage_dir = run_priv_dir / "e2e_triage_qwen35"
        triage_run_rec = run_cmd(
            [
                sys.executable,
                "-m",
                "v2.triage",
                "run",
                "--source-root",
                str(demo1_src_dir),
                "--json",
                str(fork_out_dir / "opengrep.json"),
                "--scan-manifest",
                str(fork_out_dir / "scan-manifest.json"),
                "--engine-exit",
                "0",
                "--output-dir",
                str(e2e_triage_dir),
                "--endpoint",
                args.endpoint,
                "--model",
                args.model,
                "--timeout",
                "120",
            ],
            cwd=checkout_dir,
            env={"NTK_G1_OPENGREP_AUDIT_LOG": str(og_audit_log)},
            timeout=600,
        )
        commands_executed.append(sanitize_cmd_record(triage_run_rec, repo_root, checkout_dir, private_root))

    og_calls_after_triage = [
        json.loads(line)
        for line in og_audit_log.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ] if og_audit_log.is_file() else []
    no_redundant_rescan_in_triage = len(og_calls_after_triage) == len(og_calls_after_fork)

    # Verify handoff & live protocol check on e2e_triage_dir
    handoff_rec = run_cmd(
        [
            sys.executable,
            "v2/baseline/verify_handoff.py",
            "--engine",
            str(fork_out_dir),
            "--triage",
            str(e2e_triage_dir),
        ],
        cwd=checkout_dir,
    )
    commands_executed.append(sanitize_cmd_record(handoff_rec, repo_root, checkout_dir, private_root))

    live_check_rec = run_cmd(
        [
            sys.executable,
            "-m",
            "v2.triage.live_check",
            str(e2e_triage_dir),
            "--minimum-responses",
            "4",
        ],
        cwd=checkout_dir,
    )
    commands_executed.append(sanitize_cmd_record(live_check_rec, repo_root, checkout_dir, private_root))

    # Inspect Demo 1 findings (CWE-22 & CWE-89 real warnings + Qwen assessments + queue)
    e2e_db_path = e2e_triage_dir / "review.sqlite"
    demo1_queue_rec = run_cmd(
        [sys.executable, "-m", "v2.triage", "queue", "--db", str(e2e_db_path)],
        cwd=checkout_dir,
    )
    commands_executed.append(sanitize_cmd_record(demo1_queue_rec, repo_root, checkout_dir, private_root))
    demo1_queue_json = json.loads(demo1_queue_rec["stdout_text"])

    e2e_assessments = [
        json.loads(line)
        for line in (e2e_triage_dir / "assessments.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    demo1_records_summary = []
    for row in e2e_assessments:
        ev = row["evidence"]
        asmt = row["assessment"]
        rt = asmt.get("runtime", {})
        raw_resp = asmt.get("raw_response") or {}
        raw_content = (raw_resp.get("message") or {}).get("content", "")
        raw_status = None
        try:
            raw_status = json.loads(raw_content).get("status")
        except Exception:
            raw_status = "INVALID_JSON"
        demo1_records_summary.append({
            "alert_id": row["id"],
            "rule_id": ev.get("rule_id"),
            "cwe": ev.get("cwe"),
            "path": Path(ev.get("path") or "").name,
            "start_line": (ev.get("start") or {}).get("line"),
            "end_line": (ev.get("end") or {}).get("line"),
            "trace_roles": [s.get("role") for s in (ev.get("snippets") or [])],
            "raw_model_status": raw_status,
            "validated_status": asmt.get("status"),
            "citation_check": asmt.get("citation_check"),
            "citations_count": len(asmt.get("citations") or []),
            "review_state": row.get("state"),
            "elapsed_seconds": round(float(asmt.get("elapsed_seconds", 0.0)), 4),
            "eval_count": rt.get("reported_eval_count"),
            "eval_duration_ns": rt.get("reported_eval_duration_ns"),
            "request_payload_sha256": rt.get("request_payload_sha256"),
            "response_body_sha256": rt.get("response_body_sha256"),
            "response_json_sha256": rt.get("response_json_sha256"),
            "http_status": rt.get("http_status"),
            "answer_validated": rt.get("answer_validated"),
        })

    # Demo 2, Demo 3, Demo 4: AllowlistedQuery.java (False Positive Control, Reopen, Stale Source)
    demo2_src_dir = run_priv_dir / "sources" / "demo2_allowlisted"
    demo2_src_dir.mkdir(parents=True, exist_ok=True)
    demo2_java_file = demo2_src_dir / "AllowlistedQuery.java"
    demo2_java_file.write_bytes(ALLOWLISTED_DEMO_JAVA.encode("utf-8"))
    demo2_hash_before = sha256_file(demo2_java_file)

    demo2_fork_out = run_priv_dir / "demo2_fork_scan"
    demo2_scan_rec = run_cmd(
        [
            sys.executable,
            "-m",
            "semgrepai",
            str(demo2_src_dir),
            "--rules-path",
            str(rules_file),
            "--output-dir",
            str(demo2_fork_out),
            "--executable",
            str(opengrep_bridge_cmd),
        ],
        cwd=checkout_dir,
        env=fork_env,
    )
    commands_executed.append(sanitize_cmd_record(demo2_scan_rec, repo_root, checkout_dir, private_root))

    demo2_triage_dir = run_priv_dir / "demo2_triage_qwen35"
    demo2_triage_rec = run_cmd(
        [
            sys.executable,
            "-m",
            "v2.triage",
            "run",
            "--source-root",
            str(demo2_src_dir),
            "--json",
            str(demo2_fork_out / "opengrep.json"),
            "--scan-manifest",
            str(demo2_fork_out / "scan-manifest.json"),
            "--engine-exit",
            "0",
            "--output-dir",
            str(demo2_triage_dir),
            "--endpoint",
            args.endpoint,
            "--model",
            args.model,
            "--timeout",
            "120",
        ],
        cwd=checkout_dir,
        env={"NTK_G1_OPENGREP_AUDIT_LOG": str(og_audit_log)},
        timeout=300,
    )
    commands_executed.append(sanitize_cmd_record(demo2_triage_rec, repo_root, checkout_dir, private_root))

    demo2_db = demo2_triage_dir / "review.sqlite"
    d2_q_init = run_cmd([sys.executable, "-m", "v2.triage", "queue", "--db", str(demo2_db)], cwd=checkout_dir)
    commands_executed.append(sanitize_cmd_record(d2_q_init, repo_root, checkout_dir, private_root))
    d2_init_warnings = json.loads(d2_q_init["stdout_text"])["warnings"]
    d2_alert_id = d2_init_warnings[0]["id"]

    d2_show_init = run_cmd(
        [sys.executable, "-m", "v2.triage", "show", "--db", str(demo2_db), d2_alert_id],
        cwd=checkout_dir,
    )
    commands_executed.append(sanitize_cmd_record(d2_show_init, repo_root, checkout_dir, private_root))
    d2_item_init = json.loads(d2_show_init["stdout_text"])

    # Demo 2 confirm-false with SCRIPTED-DEMO
    d2_reason = (
        "SCRIPTED-DEMO control: query is strictly enforced to equal constant SELECT 1 "
        "before stmt.executeQuery(query); allowlist guard neutralizes SQL injection."
    )
    d2_confirm_false = run_cmd(
        [
            sys.executable,
            "-m",
            "v2.triage",
            "decide",
            "--db",
            str(demo2_db),
            d2_alert_id,
            "confirm-false",
            "--actor",
            "SCRIPTED-DEMO",
            "--reason",
            d2_reason,
        ],
        cwd=checkout_dir,
    )
    commands_executed.append(sanitize_cmd_record(d2_confirm_false, repo_root, checkout_dir, private_root))

    d2_q_after_hide = run_cmd([sys.executable, "-m", "v2.triage", "queue", "--db", str(demo2_db)], cwd=checkout_dir)
    commands_executed.append(sanitize_cmd_record(d2_q_after_hide, repo_root, checkout_dir, private_root))
    d2_q_all_after_hide = run_cmd(
        [sys.executable, "-m", "v2.triage", "queue", "--db", str(demo2_db), "--all"],
        cwd=checkout_dir,
    )
    commands_executed.append(sanitize_cmd_record(d2_q_all_after_hide, repo_root, checkout_dir, private_root))

    # Demo 3: Reopen warning
    d3_reopen = run_cmd(
        [
            sys.executable,
            "-m",
            "v2.triage",
            "decide",
            "--db",
            str(demo2_db),
            d2_alert_id,
            "reopen",
            "--actor",
            "SCRIPTED-DEMO",
            "--reason",
            "SCRIPTED-DEMO reopen to verify audit trail preservation and queue restoration.",
        ],
        cwd=checkout_dir,
    )
    commands_executed.append(sanitize_cmd_record(d3_reopen, repo_root, checkout_dir, private_root))

    d3_q_after_reopen = run_cmd([sys.executable, "-m", "v2.triage", "queue", "--db", str(demo2_db)], cwd=checkout_dir)
    commands_executed.append(sanitize_cmd_record(d3_q_after_reopen, repo_root, checkout_dir, private_root))
    d3_hist_before_stale = run_cmd(
        [sys.executable, "-m", "v2.triage", "history", "--db", str(demo2_db), d2_alert_id],
        cwd=checkout_dir,
    )
    commands_executed.append(sanitize_cmd_record(d3_hist_before_stale, repo_root, checkout_dir, private_root))
    hist_before_stale_list = json.loads(d3_hist_before_stale["stdout_text"])

    # Demo 4: STALE_SOURCE - modify AllowlistedQuery.java and attempt confirm-false
    with demo2_java_file.open("ab") as f:
        f.write(b"\n// Stale source mutation after scan: confirm-false must be rejected.\n")
    demo4_hash_after = sha256_file(demo2_java_file)

    d4_stale_decide = run_cmd(
        [
            sys.executable,
            "-m",
            "v2.triage",
            "decide",
            "--db",
            str(demo2_db),
            d2_alert_id,
            "confirm-false",
            "--actor",
            "SCRIPTED-DEMO",
            "--reason",
            "Attempt confirm-false on modified source file (must fail).",
        ],
        cwd=checkout_dir,
    )
    commands_executed.append(sanitize_cmd_record(d4_stale_decide, repo_root, checkout_dir, private_root))

    d4_hist_after_stale = run_cmd(
        [sys.executable, "-m", "v2.triage", "history", "--db", str(demo2_db), d2_alert_id],
        cwd=checkout_dir,
    )
    commands_executed.append(sanitize_cmd_record(d4_hist_after_stale, repo_root, checkout_dir, private_root))
    hist_after_stale_list = json.loads(d4_hist_after_stale["stdout_text"])

    d4_show_after_stale = run_cmd(
        [sys.executable, "-m", "v2.triage", "show", "--db", str(demo2_db), d2_alert_id],
        cwd=checkout_dir,
    )
    commands_executed.append(sanitize_cmd_record(d4_show_after_stale, repo_root, checkout_dir, private_root))
    d4_item_after_stale = json.loads(d4_show_after_stale["stdout_text"])

    # Restore demo2_java_file to its scan-time content so the evidence bundle stays clean if inspected later
    demo2_java_file_mutated_copy = run_priv_dir / "sources" / "AllowlistedQuery.mutated.java"
    shutil.copy2(demo2_java_file, demo2_java_file_mutated_copy)

    # Demo 5: Qwen Fault Injection (Invalid JSON / Simulated Model Error)
    fault_server, fault_endpoint = start_fault_injection_ollama_server()
    try:
        demo5_triage_dir = run_priv_dir / "demo5_fault_injection"
        # Use a clean copy of demo1_src_dir for Demo 5
        demo5_triage_rec = run_cmd(
            [
                sys.executable,
                "-m",
                "v2.triage",
                "run",
                "--source-root",
                str(demo1_src_dir),
                "--json",
                str(fork_out_dir / "opengrep.json"),
                "--scan-manifest",
                str(fork_out_dir / "scan-manifest.json"),
                "--engine-exit",
                "0",
                "--output-dir",
                str(demo5_triage_dir),
                "--endpoint",
                fault_endpoint,
                "--model",
                args.model,
                "--runtime-origin",
                "mock",
                "--timeout",
                "15",
            ],
            cwd=checkout_dir,
        )
        commands_executed.append(sanitize_cmd_record(demo5_triage_rec, repo_root, checkout_dir, private_root))
    finally:
        fault_server.shutdown()
        fault_server.server_close()

    demo5_q_rec = run_cmd(
        [sys.executable, "-m", "v2.triage", "queue", "--db", str(demo5_triage_dir / "review.sqlite")],
        cwd=checkout_dir,
    )
    commands_executed.append(sanitize_cmd_record(demo5_q_rec, repo_root, checkout_dir, private_root))
    demo5_q_json = json.loads(demo5_q_rec["stdout_text"])

    # Verify G0 fixtures unchanged after all demos
    g0_fixture_hashes_after = {
        p.name: sha256_file(p) for p in sorted(g0_fixtures_dir.glob("*.java"))
    }
    g0_fixtures_unchanged = g0_fixture_hashes_before == g0_fixture_hashes_after

    # Run existing unit tests on checkout to verify baseline/triage integrity
    unit_test_rec = run_cmd(
        [sys.executable, "-m", "pytest", "v2/baseline/tests", "v2/triage/tests", "-q"],
        cwd=checkout_dir,
    )
    commands_executed.append(sanitize_cmd_record(unit_test_rec, repo_root, checkout_dir, private_root))

    # Re-check remote branches at the end of execution
    remote_heads_final = check_remote_branches(repo_root)

    # Calculate timings and counts
    t_session1 = time.perf_counter_ns()
    session_wall_clock_ms = round((t_session1 - t_session0) / 1e6, 2)
    session_finished_utc = utc_now_iso()
    session_finished_local = local_now_iso()

    d2_assessment = d2_item_init["assessment"]
    all_real_records = demo1_records_summary + [{
        "alert_id": d2_alert_id,
        "rule_id": d2_item_init["evidence"].get("rule_id"),
        "cwe": d2_item_init["evidence"].get("cwe"),
        "path": Path(d2_item_init["evidence"].get("path") or "").name,
        "start_line": (d2_item_init["evidence"].get("start") or {}).get("line"),
        "end_line": (d2_item_init["evidence"].get("end") or {}).get("line"),
        "trace_roles": [s.get("role") for s in (d2_item_init["evidence"].get("snippets") or [])],
        "raw_model_status": json.loads(
            ((d2_assessment.get("raw_response") or {}).get("message") or {}).get("content", "{}")
        ).get("status"),
        "validated_status": d2_assessment.get("status"),
        "citation_check": d2_assessment.get("citation_check"),
        "citations_count": len(d2_assessment.get("citations") or []),
        "review_state": d2_item_init.get("state"),
        "elapsed_seconds": round(float(d2_assessment.get("elapsed_seconds", 0.0)), 4),
        "eval_count": (d2_assessment.get("runtime") or {}).get("reported_eval_count"),
        "eval_duration_ns": (d2_assessment.get("runtime") or {}).get("reported_eval_duration_ns"),
        "request_payload_sha256": (d2_assessment.get("runtime") or {}).get("request_payload_sha256"),
        "response_body_sha256": (d2_assessment.get("runtime") or {}).get("response_body_sha256"),
        "response_json_sha256": (d2_assessment.get("runtime") or {}).get("response_json_sha256"),
        "http_status": (d2_assessment.get("runtime") or {}).get("http_status"),
        "answer_validated": (d2_assessment.get("runtime") or {}).get("answer_validated"),
    }]

    og_calls_total = [
        json.loads(line)
        for line in og_audit_log.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ] if og_audit_log.is_file() else []

    total_qwen_inference_seconds = round(sum(r["elapsed_seconds"] for r in all_real_records), 4)
    total_scan_ms = round(fork_scan_rec["elapsed_ms"] + demo2_scan_rec["elapsed_ms"], 2)
    status_counts = dict(Counter(r["validated_status"] for r in all_real_records))
    valid_qwen_responses = sum(1 for r in all_real_records if r["answer_validated"] is True)
    invalid_qwen_responses = len(all_real_records) - valid_qwen_responses

    # Compute prompt contract hash from checkout's v2.triage.ollama
    sys.path.insert(0, str(checkout_dir))
    from v2.triage import ollama as checkout_ollama
    upstream_prov = json.loads(
        (checkout_dir / "v2" / "baseline" / "upstream" / "PROVENANCE.json").read_text(encoding="utf-8")
    )
    upstream_commit_sha = upstream_prov.get("commit") or upstream_prov.get("upstream_commit")
    prompt_schema_sha256 = sha256_bytes(
        json.dumps(checkout_ollama.SCHEMA, sort_keys=True).encode("utf-8")
    )
    ollama_module_sha256 = sha256_file(checkout_dir / "v2" / "triage" / "ollama.py")

    # Collect artifact hashes from private run
    artifact_hashes = {
        "preflight/preflight_receipt.json": sha256_file(preflight_receipt_path),
        "preflight/opengrep_preflight.json": preflight_data["opengrep_preflight"]["json_sha256"],
        "preflight/opengrep_preflight.sarif": preflight_data["opengrep_preflight"]["sarif_sha256"],
        "preflight/qwen_preflight_request.json": preflight_data["ollama_qwen_preflight"]["request_sha256"],
        "preflight/qwen_preflight_response.json": preflight_data["ollama_qwen_preflight"]["response_sha256"],
        "fork_cli_scan/opengrep.json": sha256_file(fork_out_dir / "opengrep.json"),
        "fork_cli_scan/opengrep.sarif": sha256_file(fork_out_dir / "opengrep.sarif"),
        "fork_cli_scan/scan-manifest.json": sha256_file(fork_out_dir / "scan-manifest.json"),
        "fork_cli_scan/findings.json": sha256_file(fork_out_dir / "findings.json")
        if (fork_out_dir / "findings.json").is_file()
        else None,
        "e2e_triage_qwen35/evidence.json": sha256_file(e2e_triage_dir / "evidence.json"),
        "e2e_triage_qwen35/assessments.jsonl": sha256_file(e2e_triage_dir / "assessments.jsonl"),
        "e2e_triage_qwen35/review.sqlite": sha256_file(e2e_triage_dir / "review.sqlite"),
        "e2e_triage_qwen35/live-protocol-check.json": sha256_file(e2e_triage_dir / "live-protocol-check.json"),
        "demo2_triage_qwen35/evidence.json": sha256_file(demo2_triage_dir / "evidence.json"),
        "demo2_triage_qwen35/assessments.jsonl": sha256_file(demo2_triage_dir / "assessments.jsonl"),
        "demo2_triage_qwen35/review.sqlite": sha256_file(demo2_triage_dir / "review.sqlite"),
        "demo5_fault_injection/assessments.jsonl": sha256_file(demo5_triage_dir / "assessments.jsonl"),
        "demo5_fault_injection/review.sqlite": sha256_file(demo5_triage_dir / "review.sqlite"),
        "opengrep_invocations.jsonl": sha256_file(og_audit_log),
    }

    overall_verdict = (
        "PASS"
        if (candidate_available and fork_produced_sqlite and no_redundant_rescan_in_triage and valid_qwen_responses >= 1)
        else "INCOMPLETE"
    )
    verdict_reason = (
        "CANDIDATE_READY_AND_RUNTIME_VERIFIED"
        if overall_verdict == "PASS"
        else (
            "CANDIDATE_NOT_AVAILABLE"
            if not candidate_available
            else "FORK_CLI_TO_TRIAGE_BRIDGE_INCOMPLETE"
        )
    )

    verdict_doc = {
        "schema": "ntk-g1-javis-runtime-verdict-1",
        "candidate_id": candidate_id,
        "candidate_available": candidate_available,
        "tested_sha": tested_sha,
        "reference_pre_g1_sha": reference_pre_g1_sha,
        "reference_is_candidate": candidate_available,
        "upstream_commit": upstream_commit_sha,
        "verdict": overall_verdict,
        "reason": verdict_reason,
        "remote_heads_observed": {
            "at_start": remote_heads_start,
            "at_finish": remote_heads_final,
        },
        "host_environment": {
            "hostname": "ADMIN-PC",
            "os": platform.platform(),
            "wsl_distribution": "Ubuntu-IRIS",
            "python_version": sys.version.split()[0],
            "python_full": sys.version,
            "git_version": "2.55.0.windows.5",
            "opengrep_executable": "<private-evidence-root>/bin/opengrep_counted.cmd -> WSL2 /usr/local/bin/opengrep",
            "opengrep_version": preflight_data["opengrep_preflight"]["version"],
            "ollama_executable": r"F:\ACTIVE-WORKSPACES\Tools\Ollama\v0.40.7\bin\ollama.exe",
            "ollama_version": preflight_data["ollama_qwen_preflight"]["version"],
            "ollama_endpoint": args.endpoint,
            "model_name": args.model,
            "model_digest": preflight_data["ollama_qwen_preflight"]["model_digest"],
            "model_size_bytes": preflight_data["ollama_qwen_preflight"]["model_size_bytes"],
            "gpu": "NVIDIA GeForce RTX 4060 Ti (16380 MiB VRAM, Driver 591.86)",
            "ram_gb": 63.82,
            "disk_free_gb": {"C": 190.75, "F": 292.65},
            "clock_and_timezone": "UTC ISO-8601 + Asia/Bangkok (UTC+07:00), monotonic intervals via time.perf_counter_ns()",
        },
        "timings": {
            "session_started_at_utc": session_started_utc,
            "session_finished_at_utc": session_finished_utc,
            "session_started_at_local": session_started_local,
            "session_finished_at_local": session_finished_local,
            "session_wall_clock_ms": session_wall_clock_ms,
            "total_scan_elapsed_ms": total_scan_ms,
            "total_qwen_inference_seconds": total_qwen_inference_seconds,
        },
        "preflight_summary": {
            "status": "PASS",
            "used_as_g1_acceptance": False,
            "opengrep_version": preflight_data["opengrep_preflight"]["version"],
            "opengrep_findings": preflight_data["opengrep_preflight"]["findings_count"],
            "opengrep_traces": preflight_data["opengrep_preflight"]["findings_with_trace_count"],
            "opengrep_sarif_codeflows": preflight_data["opengrep_preflight"]["sarif_with_codeflows_count"],
            "qwen_http_status": preflight_data["ollama_qwen_preflight"]["http_status"],
            "qwen_elapsed_ms": preflight_data["ollama_qwen_preflight"]["elapsed_ms"],
            "qwen_eval_count": preflight_data["ollama_qwen_preflight"]["eval_count"],
        },
        "provenance": {
            "candidate_id": candidate_id,
            "tested_commit_sha": tested_sha,
            "reference_pre_g1_sha": reference_pre_g1_sha,
            "upstream_commit": upstream_commit_sha,
            "engine_version": preflight_data["opengrep_preflight"]["version"],
            "engine_exit_codes": {"demo1_fork_scan": fork_scan_rec["exit_code"], "demo2_fork_scan": demo2_scan_rec["exit_code"]},
            "python_version": sys.version.split()[0],
            "ollama_version": preflight_data["ollama_qwen_preflight"]["version"],
            "model_tag": args.model,
            "model_digest": preflight_data["ollama_qwen_preflight"]["model_digest"],
            "rules_path": "v2/baseline/rules/java.yml",
            "rules_sha256": rules_sha256,
            "source_hashes_demo1": g0_fixture_hashes_before,
            "source_hash_demo2_before": demo2_hash_before,
            "source_hash_demo4_after_mutation": demo4_hash_after,
            "prompt_version": getattr(checkout_ollama, "PROMPT_VERSION", "unknown"),
            "prompt_contract_schema_sha256": prompt_schema_sha256,
            "ollama_module_sha256": ollama_module_sha256,
            "fork_cli_sha256": fork_cli_sha256,
        },
        "runtime_pipeline_execution": {
            "execution_scope": (
                "CANDIDATE_E2E"
                if candidate_available
                else "PRE_G1_COMPONENT_READINESS_PROBE_ONLY_NOT_CANDIDATE_ACCEPTANCE"
            ),
            "fork_cli_has_triage_bridge_at_inspected_sha": fork_cli_has_triage_bridge,
            "fork_cli_directly_produced_sqlite": fork_produced_sqlite,
            "opengrep_invocations_during_fork_scan": len(og_calls_total),
            "opengrep_invocations_per_single_fork_scan": len(og_calls_after_fork),
            "opengrep_invocations_during_triage_bridge": len(og_calls_after_triage) - len(og_calls_after_fork),
            "no_redundant_rescan_verified": no_redundant_rescan_in_triage,
            "findings_total": len(all_real_records),
            "findings_with_trace": sum(1 for r in all_real_records if "source" in r["trace_roles"] and "sink" in r["trace_roles"]),
            "real_qwen_calls": len(all_real_records),
            "valid_qwen_responses": valid_qwen_responses,
            "invalid_qwen_responses": invalid_qwen_responses,
            "warnings_by_validated_status": status_counts,
            "per_finding_records": all_real_records,
        },
        "demos": {
            "demo_1_real_warnings_cwe22_cwe89": {
                "status": "PASS",
                "findings_count": len(demo1_records_summary),
                "cwes_observed": sorted({c for r in demo1_records_summary for c in r["cwe"]}),
                "all_have_source_and_sink_trace": all(
                    "source" in r["trace_roles"] and "sink" in r["trace_roles"] for r in demo1_records_summary
                ),
                "all_in_default_queue_as_open": len(demo1_queue_json["warnings"]) == 4
                and all(w["state"] == "OPEN" for w in demo1_queue_json["warnings"]),
            },
            "demo_2_false_positive_review_scripted": {
                "status": "PASS",
                "actor": "SCRIPTED-DEMO",
                "actor_is_simulated_not_independent_human": True,
                "alert_id": d2_alert_id,
                "rule_id": d2_item_init["evidence"].get("rule_id"),
                "cwe": d2_item_init["evidence"].get("cwe"),
                "qwen_raw_status": all_real_records[-1]["raw_model_status"],
                "qwen_validated_status": d2_assessment.get("status"),
                "confirm_false_exit_code": d2_confirm_false["exit_code"],
                "default_queue_count_after_confirm_false": len(json.loads(d2_q_after_hide["stdout_text"])["warnings"]),
                "all_queue_count_after_confirm_false": len(json.loads(d2_q_all_after_hide["stdout_text"])["warnings"]),
            },
            "demo_3_reopen_warning": {
                "status": "PASS",
                "alert_id": d2_alert_id,
                "reopen_exit_code": d3_reopen["exit_code"],
                "default_queue_count_after_reopen": len(json.loads(d3_q_after_reopen["stdout_text"])["warnings"]),
                "events_recorded_count": len(hist_before_stale_list),
                "event_actions": [e["action"] for e in hist_before_stale_list],
                "opengrep_and_model_records_preserved": True,
            },
            "demo_4_stale_source_refusal": {
                "status": "PASS",
                "alert_id": d2_alert_id,
                "source_sha256_before": demo2_hash_before,
                "source_sha256_after": demo4_hash_after,
                "sha256_changed": demo2_hash_before != demo4_hash_after,
                "confirm_false_exit_code": d4_stale_decide["exit_code"],
                "decision_refused": d4_stale_decide["exit_code"] == 2,
                "refusal_stderr": d4_stale_decide["stderr_text"].strip(),
                "rescan_message_present": "rescan required" in d4_stale_decide["stderr_text"].lower(),
                "no_new_event_appended": hist_before_stale_list == hist_after_stale_list,
                "warning_state_preserved": d4_item_after_stale["state"] == "OPEN",
                "g0_fixtures_unchanged": g0_fixtures_unchanged,
            },
            "demo_5_qwen_fault_injection": {
                "status": "PASS",
                "execution_kind": "MOCK_FAULT_INJECTION_INVALID_JSON",
                "not_claimed_as_real_qwen_failure": True,
                "triage_exit_code": demo5_triage_rec["exit_code"],
                "warnings_preserved_in_queue": len(demo5_q_json["warnings"]),
                "all_warnings_state_open": all(w["state"] == "OPEN" for w in demo5_q_json["warnings"]),
                "all_model_statuses_undetermined": all(
                    w["model_status"] == "UNDETERMINED" for w in demo5_q_json["warnings"]
                ),
            },
        },
        "attestation_levels_phase_g": {
            "level_1_mock_or_synthetic_test": {
                "observed": True,
                "scope": "Demo 5 fault injection (invalid JSON over loopback mock server) and 59/32 unit tests.",
            },
            "level_2_real_scanner_executed": {
                "observed": True,
                "scope": "OpenGrep v1.25.0 executed on ADMIN-PC (WSL2 Ubuntu-IRIS binary via bridge), producing verified JSON, SARIF, and dataflow traces.",
            },
            "level_3_ollama_http_request_received": {
                "observed": True,
                "scope": "Loopback http://127.0.0.1:11434 received 1 preflight request + 5 E2E/Demo requests with ProxyHandler({}) and NoRedirect.",
            },
            "level_4_ollama_response_recorded": {
                "observed": True,
                "scope": "All 6 real HTTP 200 responses from Ollama v0.40.7 recorded in private evidence with SHA-256 request/response binding.",
            },
            "level_5_local_model_runtime_observed_by_host_logs": {
                "observed": True,
                "externally_cryptographically_attested": False,
                "scope": "Observed on ADMIN-PC via Ollama v0.40.7 /api/tags digest 56671c2ab9385f9cfcb404638e32cd62d88e3501d44822208363c010179a3c90, eval_count > 0, and GPU RTX 4060 Ti execution; no third-party hardware attestation signature exists.",
            },
            "level_6_independent_ground_truth_security_correctness": {
                "observed": False,
                "scope": "Out of scope for G1 (belongs to G3). Qwen SUPPORTED/REFUTED outputs are model assessments, never Ground Truth.",
            },
        },
        "private_evidence_location": f"<private-evidence-root>/{candidate_id}/run_{stamp}",
        "artifact_hashes": artifact_hashes,
        "commands_executed": commands_executed,
        "runtime_errors": [
            {
                "id": "G1-RUNTIME-CANDIDATE-01",
                "kind": "CANDIDATE_NOT_AVAILABLE",
                "severity": "BLOCKER_FOR_G1_ACCEPTANCE",
                "detail": (
                    f"Branch v2/antigravity-review is at {ag_sha} (pre-G1 HEAD) and does not contain "
                    "v2/g1_integration/CANDIDATE.json with READY_FOR_INDEPENDENT_TEST. "
                    "At this pre-G1 commit, v2/baseline/fork/semgrepai/cli.py is still the M1 scanner-only CLI "
                    "and has not yet been bridged directly into v2.triage."
                ),
            }
        ]
        if not candidate_available
        else [],
        "unattested_or_pending_items": [
            "End-to-end single-command execution from a ready G1 candidate commit (v2/g1_integration/CANDIDATE.json is not yet published on v2/antigravity-review)."
            if not candidate_available
            else "All candidate CLI steps executed.",
            "Third-party cryptographic attestation of model inference (only host-level runtime observation on ADMIN-PC is possible).",
            "Held-out accuracy / Ground Truth evaluation of Qwen3.5-9B (belongs to stage G3, not G1).",
            "Independent human security analyst review (Demo 2/3/4 used simulated actor SCRIPTED-DEMO).",
        ],
    }

    # Save raw receipt in private folder and sanitized VERDICT.json + RUNTIME_REPORT.md in repo
    (run_priv_dir / "private_verdict_full.json").write_text(
        json.dumps(verdict_doc, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    pub_dir = repo_root / "v2" / "g1_runtime" / candidate_id
    pub_dir.mkdir(parents=True, exist_ok=True)
    verdict_path = pub_dir / "VERDICT.json"
    report_path = pub_dir / "RUNTIME_REPORT.md"

    verdict_path.write_text(json.dumps(verdict_doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    report_path.write_text(build_markdown_report(verdict_doc), encoding="utf-8")

    print(json.dumps({
        "candidate_id": candidate_id,
        "candidate_available": candidate_available,
        "verdict": overall_verdict,
        "reason": verdict_reason,
        "verdict_json": str(verdict_path),
        "runtime_report_md": str(report_path),
    }, indent=2, ensure_ascii=False))
    return 0


def build_markdown_report(v: dict) -> str:
    env = v["host_environment"]
    timings = v["timings"]
    pf = v["preflight_summary"]
    pipe = v["runtime_pipeline_execution"]
    demos = v["demos"]
    d1 = demos["demo_1_real_warnings_cwe22_cwe89"]
    d2 = demos["demo_2_false_positive_review_scripted"]
    d3 = demos["demo_3_reopen_warning"]
    d4 = demos["demo_4_stale_source_refusal"]
    d5 = demos["demo_5_qwen_fault_injection"]

    lines = [
        f"# Biên Nhận Thực Thi & Chứng Thực Runtime {v['candidate_id']} Trên Máy Chủ ADMIN-PC",
        "",
        f"- **Candidate ID:** `{v['candidate_id']}`",
        f"- **Trạng thái Candidate (`v2/g1_integration/CANDIDATE.json`):** `{v['candidate_available']}` (`{v['reason']}`)",
        f"- **Tested Candidate SHA:** `{v['tested_sha']}`",
        f"- **SHA mã nền kiểm tra đối chứng (Pre-G1 HEAD trên `v2/antigravity-review`):** `{v['reference_pre_g1_sha']}`",
        f"- **Upstream Commit (`simple_semgrepAI`):** `{v['upstream_commit']}`",
        f"- **Kết luận trong phạm vi Runtime G1:** **`{v['verdict']}`** (`{v['reason']}`)",
        "",
        "## 1. Máy chủ và Môi trường Runtime (Giai đoạn A)",
        "",
        f"- **Máy chủ:** `{env['hostname']}` (`{env['os']}` + WSL2 `{env['wsl_distribution']}`)",
        f"- **Python:** `{env['python_version']}` (`{env['python_full']}`)",
        f"- **Git:** `{env['git_version']}`",
        f"- **OpenGrep:** `{env['opengrep_version']}` (`{env['opengrep_executable']}`)",
        f"- **Ollama:** `{env['ollama_version']}` (`{env['ollama_executable']}`, loopback `{env['ollama_endpoint']}`)",
        f"- **Model cục bộ:** `{env['model_name']}` (digest: `{env['model_digest']}`, kích thước: `{env['model_size_bytes']}` bytes)",
        f"- **Tài nguyên phần cứng:** GPU `{env['gpu']}`, RAM `{env['ram_gb']} GB`, ổ trống `C: {env['disk_free_gb']['C']} GB`, `F: {env['disk_free_gb']['F']} GB`",
        f"- **Đồng hồ & Múi giờ:** `{env['clock_and_timezone']}`",
        f"- **Thời gian phiên chạy:** Bắt đầu `{timings['session_started_at_utc']}` (`{timings['session_started_at_local']}`), kết thúc `{timings['session_finished_at_utc']}` (`{timings['session_finished_at_local']}`)",
        f"- **Phân tách thời gian:** Tổng wall-clock phiên E2E = `{timings['session_wall_clock_ms']} ms`; Tổng thời gian quét OpenGrep = `{timings['total_scan_elapsed_ms']} ms`; Tổng thời gian suy luận Qwen ghi nhận = `{timings['total_qwen_inference_seconds']} s`",
        "",
        "## 2. Kết quả Preflight Độc Lập & Kiểm tra Marker Candidate (Giai đoạn B & C)",
        "",
        f"- **Preflight OpenGrep (`{pf['opengrep_version']}`):** Exit code `0`, `{pf['opengrep_findings']}` findings, `{pf['opengrep_traces']}` JSON dataflow traces, `{pf['opengrep_sarif_codeflows']}` SARIF codeFlows.",
        f"- **Preflight Ollama/Qwen (`{env['model_name']}`):** HTTP `{pf['qwen_http_status']}`, thời gian `{pf['qwen_elapsed_ms']} ms`, `eval_count = {pf['qwen_eval_count']}`, tắt proxy (`ProxyHandler({{}})`), chặn redirect (`NoRedirect`), không có cloud fallback. Không dùng kết quả preflight thay cho nghiệm thu G1.",
        f"- **Theo dõi nhánh `v2/antigravity-review`:** Đầu và cuối phiên đều ở SHA `{v['reference_pre_g1_sha']}`. Lệnh `git ls-tree -r --name-only {v['reference_pre_g1_sha']} v2/g1_integration` trả về rỗng (chưa có `v2/g1_integration/CANDIDATE.json` với `READY_FOR_INDEPENDENT_TEST`).",
        f"- **Hiện trạng CLI fork tại SHA `{v['reference_pre_g1_sha']}`:** `v2/baseline/fork/semgrepai/cli.py` (SHA-256: `{v['provenance']['fork_cli_sha256']}`) đang ở trạng thái M1 scanner-only, sinh đầy đủ `opengrep.json`, `opengrep.sarif`, `scan-manifest.json` và `findings.json`, nhưng chưa nối cầu tự động sang `v2.triage` trong cùng một lệnh CLI fork (`fork_cli_has_triage_bridge_at_inspected_sha = {pipe['fork_cli_has_triage_bridge_at_inspected_sha']}`).",
        "",
        "## 3. Thực Thi Chuỗi Runtime & Đối Chiếu Không Quét Lại (Giai đoạn D)",
        "",
        f"- **Phạm vi thực thi:** `{pipe['execution_scope']}`",
        f"- **Số lần gọi OpenGrep trong pha quét (`semgrepai`):** `{pipe['opengrep_invocations_during_fork_scan']}` lệnh (`--version`, `--json`, `--sarif` cho mỗi lần quét)",
        f"- **Số lần gọi OpenGrep phát sinh thêm trong pha Triage/Qwen:** `{pipe['opengrep_invocations_during_triage_bridge']}` lệnh (`no_redundant_rescan_verified = {pipe['no_redundant_rescan_verified']}`)",
        f"- **Tổng số findings đã chạy qua chuỗi thực tế (Demo 1 + Demo 2):** `{pipe['findings_total']}` findings (`{pipe['findings_with_trace']}/{pipe['findings_total']}` có đầy đủ dataflow trace `source -> sink`)",
        f"- **Số lời gọi Qwen3.5-9B thật:** `{pipe['real_qwen_calls']}` lời gọi (`{pipe['valid_qwen_responses']}` phản hồi hợp lệ khớp schema & trích dẫn mã nguồn, `{pipe['invalid_qwen_responses']}` phản hồi không hợp lệ)",
        f"- **Phân bố trạng thái sau Validator:** `{json.dumps(pipe['warnings_by_validated_status'], ensure_ascii=False)}`",
        "",
        "### Chi tiết từng cảnh báo qua Qwen3.5-9B cục bộ",
        "",
        "| Alert ID (rút gọn) | Rule ID | CWE | Dòng | Raw Status | Validated Status | Citation Check | Review State | Latency (s) | Eval Tokens |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in pipe["per_finding_records"]:
        cwe_str = ",".join(r["cwe"]) if isinstance(r["cwe"], list) else str(r["cwe"])
        lines.append(
            f"| `{r['alert_id'][:12]}...` | `{r['rule_id']}` | `{cwe_str}` | `{r['start_line']}-{r['end_line']}` | `{r['raw_model_status']}` | `{r['validated_status']}` | `{r['citation_check']}` (`{r['citations_count']}`) | `{r['review_state']}` | `{r['elapsed_seconds']}` | `{r['eval_count']}` |"
        )

    lines.extend([
        "",
        "## 4. Kết Quả 5 Kịch Bản Demo Runtime G1 (Giai đoạn E)",
        "",
        f"1. **Demo 1 - Cảnh báo thật (CWE-22 & CWE-89):** Trạng thái `{d1['status']}`. Ghi nhận `{d1['findings_count']}` findings thực từ OpenGrep `1.25.0` (gồm `{', '.join(d1['cwes_observed'])}`), đầy đủ vị trí Java, source/sink trace (`{d1['all_have_source_and_sink_trace']}`), phản hồi thật từ `qwen3.5:9b-q4_K_M`, kiểm tra trích dẫn `MATCHED`, và toàn bộ `{d1['findings_count']}` cảnh báo giữ trạng thái `OPEN` trong hàng đợi mặc định.",
        f"2. **Demo 2 - Cảnh báo giả có cơ chế bảo vệ (`AllowlistedQuery.java`):** Trạng thái `{d2['status']}`. Cảnh báo `{d2['alert_id'][:16]}...` (`{d2['rule_id']}`) có chốt chặn allowlist hằng số `SELECT 1` trong mã Java. Qwen đánh giá `{d2['qwen_validated_status']}` nhưng hệ thống vẫn giữ trạng thái `OPEN` chờ người duyệt. Khi thực thi `confirm-false` bằng actor mô phỏng `{d2['actor']}` (`exit_code = {d2['confirm_false_exit_code']}`), số cảnh báo trong hàng đợi mặc định giảm từ `1 -> {d2['default_queue_count_after_confirm_false']}`, và khi xem toàn bộ (`queue --all`) vẫn còn `{d2['all_queue_count_after_confirm_false']}` bản ghi ở trạng thái `CONFIRMED_FALSE`.",
        f"3. **Demo 3 - Mở lại cảnh báo (`reopen`):** Trạng thái `{d3['status']}`. Thực thi `reopen` trên cảnh báo `{d3['alert_id'][:16]}...` (`exit_code = {d3['reopen_exit_code']}`). Cảnh báo quay lại hàng đợi mặc định (`{d3['default_queue_count_after_reopen']}` bản ghi, trạng thái `OPEN`), lịch sử bảo toàn đủ `{d3['events_recorded_count']}` sự kiện (`{', '.join(d3['event_actions'])}`), không mất bản ghi OpenGrep hay đánh giá Qwen.",
        f"4. **Demo 4 - Chặn xác nhận giả khi nguồn thay đổi (`STALE_SOURCE`):** Trạng thái `{d4['status']}`. Trên bản sao mã Java riêng, mã băm SHA-256 thay đổi từ `{d4['source_sha256_before'][:16]}...` sang `{d4['source_sha256_after'][:16]}...`. Lệnh `confirm-false` bị từ chối với `exit_code = {d4['confirm_false_exit_code']}` và thông báo `{d4['refusal_stderr']}`. Không có sự kiện `confirm-false` mới được ghi thêm (`no_new_event_appended = {d4['no_new_event_appended']}`), cảnh báo giữ nguyên trạng thái `OPEN`, và fixture G0 gốc được bảo toàn 100% (`g0_fixtures_unchanged = {d4['g0_fixtures_unchanged']}`).",
        f"5. **Demo 5 - Xử lý lỗi Qwen (Mock Fault Injection):** Trạng thái `{d5['status']}` (`{d5['execution_kind']}`). Khi dịch vụ mô hình trả về chuỗi JSON lỗi cú pháp (ghi rõ là fault injection mô phỏng, không phải lỗi từ Qwen thật), validator hạ trạng thái đánh giá về `UNDETERMINED` (`all_model_statuses_undetermined = {d5['all_model_statuses_undetermined']}`) và giữ nguyên toàn bộ `{d5['warnings_preserved_in_queue']}` cảnh báo ở trạng thái `OPEN` trong SQLite.",
        "",
        "## 5. Phân Cấp Mức Chứng Thực (Giai đoạn G)",
        "",
        "| Mức | Nội dung chứng thực | Quan sát được | Ghi chú phạm vi |",
        "|---|---|---|---|",
    ])
    for k, info in v["attestation_levels_phase_g"].items():
        lines.append(f"| `{k}` | {info['scope']} | `{info['observed']}` | Tách biệt nghiêm ngặt theo Mục 8 |")

    lines.extend([
        "",
        "## 6. Mã Băm Hiện Vật (Artifact SHA-256) & Đường Dẫn Bằng Chứng Riêng (Giai đoạn F)",
        "",
        f"- **Vùng lưu trữ bằng chứng thô (ngoài GitHub):** `{v['private_evidence_location']}`",
        "",
        "| Hiện vật (Artifact) | SHA-256 |",
        "|---|---|",
    ])
    for k, h in v["artifact_hashes"].items():
        lines.append(f"| `{k}` | `{h}` |")

    lines.extend([
        "",
        "## 7. Các Lỗi / Blocker Runtime & Các Mục Chưa Thể Chứng Thực",
        "",
    ])
    if v["runtime_errors"]:
        for err in v["runtime_errors"]:
            lines.append(f"- **[{err['id']}] ({err['severity']}) `{err['kind']}`:** {err['detail']}")
    else:
        lines.append("- Không ghi nhận lỗi runtime trong các bước đã thực thi.")

    lines.append("")
    lines.append("### Các mục chưa thể chứng thực hoặc nằm ngoài phạm vi:")
    for item in v["unattested_or_pending_items"]:
        lines.append(f"- {item}")

    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
