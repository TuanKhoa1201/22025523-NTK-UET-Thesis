"""Minimal local CLI for scan/import, evidence, inference and human review."""
import argparse
import json
import sqlite3
import sys
from pathlib import Path
from .evidence import collect, EvidenceError, SourceTree, digest
from .ollama import OllamaClient, undecided
from .store import ReviewStore
from .runtime import SCHEMA_VERSION, summary


def show(value):
    # ensure_ascii prevents terminal control sequences embedded in source from executing.
    print(json.dumps(value, indent=2, ensure_ascii=True))


def source_versions(root):
    tree = SourceTree(root)
    versions = {}
    for path in sorted(tree.root.rglob("*.java")):
        relative, data, _ = tree.read(str(path))
        versions[relative] = digest(data)
    return versions


def run(args):
    root = Path(args.source_root).resolve(strict=True)
    output = Path(args.output_dir)
    # Validate network configuration before creating artifacts or scanning.
    client = None if args.no_llm else OllamaClient(args.endpoint, args.model, args.timeout, args.runtime_origin)
    output.mkdir(parents=True, exist_ok=False)
    issues = []
    exit_code = args.engine_exit
    before = None
    if args.json:
        raw = Path(args.json).read_bytes()
    else:
        # Reuse M1 scanner; never import upstream cloud/RAG/web code.
        fork = Path(__file__).resolve().parents[1] / "baseline/fork"
        sys.path.insert(0, str(fork))
        from semgrepai.scanner import SemgrepScanner, ScanError
        from semgrepai.config import OpenGrepConfig, DEFAULT_RULES
        before = source_versions(root)
        exit_code = 0
        scanner = SemgrepScanner(OpenGrepConfig(args.executable, Path(args.rules) if args.rules else DEFAULT_RULES), output / "engine")
        try:
            scanner.scan(root)
        except ScanError as exc:
            issues.append("scanner failed: " + str(exc))
            exit_code = 2
        try:
            after = source_versions(root)
            if before != after:
                issues.append("source version changed while OpenGrep ran; rescan required")
        except (EvidenceError, OSError, ValueError, RuntimeError) as exc:
            issues.append("cannot recheck source version after scan; rescan required: " + str(exc))
        raw_path = output / "engine/opengrep.json"
        if not raw_path.exists():
            raw_path = output / "engine/json.stdout.txt"
        raw = raw_path.read_bytes() if raw_path.exists() else b""
    (output / "input.opengrep.json").write_bytes(raw)
    bundle = collect(raw, root, args.path_base, exit_code, issues)
    if before is not None:
        bundle["pre_scan_hashes"] = before
    (output / "evidence.json").write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    assessments = [client.analyze(record) if client else undecided("inference explicitly disabled", transport="disabled")
                   for record in bundle["records"]]
    store = ReviewStore(output / "review.sqlite")
    try:
        store.add(bundle, assessments)
    finally:
        store.close()
    with (output / "assessments.jsonl").open("x", encoding="utf-8") as stream:
        for record, assessment in zip(bundle["records"], assessments):
            stream.write(json.dumps({"schema_version": SCHEMA_VERSION, "id": record["id"], "alert_id": record["id"],
                                     "scan_sha256": record["scan_sha256"], "finding_index": record["finding_index"],
                                     "state": "OPEN", "evidence": record,
                                     "assessment": assessment}, ensure_ascii=False) + "\n")
    runtime_counts = summary(assessments)
    show({"scan_sha256": bundle["scan_sha256"], "warnings": len(bundle["records"]),
          "scan_issues": bundle["issues"], "states": [a["status"] for a in assessments],
          "db": str(output / "review.sqlite"), "schema_version": SCHEMA_VERSION,
          "runtime_summary": runtime_counts,
          "qwen_runtime_verified": bool(assessments) and runtime_counts["verified_model_runtime_count"] == len(assessments)})
    return 2 if bundle["issues"] or any(r["issues"] for r in bundle["records"]) else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Local Java OpenGrep evidence and human review")
    sub = parser.add_subparsers(dest="command", required=True)
    pipeline = sub.add_parser("run", help="scan Java or import raw OpenGrep JSON")
    pipeline.add_argument("--source-root", required=True)
    pipeline.add_argument("--output-dir", required=True, help="must not already exist")
    pipeline.add_argument("--json", help="import existing OpenGrep JSON instead of scanning")
    pipeline.add_argument("--path-base", help="base for relative engine paths; resolved files must remain inside source-root")
    pipeline.add_argument("--engine-exit", type=int, help="original engine exit code when importing JSON; unknown forces UNDETERMINED")
    pipeline.add_argument("--rules")
    pipeline.add_argument("--executable", default="opengrep")
    pipeline.add_argument("--no-llm", action="store_true")
    pipeline.add_argument("--endpoint", default="http://127.0.0.1:11434")
    pipeline.add_argument("--model", default="qwen3.5:9b-q4_K_M")
    pipeline.add_argument("--timeout", type=float, default=60)
    pipeline.add_argument("--runtime-origin", choices=("unverified", "mock"), default="unverified",
                          help="label simulated services; an HTTP reply alone cannot attest real inference")
    for command in ("queue", "show", "history", "decide"):
        p = sub.add_parser(command)
        p.add_argument("--db", required=True)
        if command != "queue":
            p.add_argument("id")
        if command == "decide":
            p.add_argument("action", choices=("confirm-true", "confirm-false", "reopen"))
            p.add_argument("--actor", required=True)
            p.add_argument("--reason", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            return run(args)
        if not Path(args.db).is_file():
            raise EvidenceError("review database does not exist")
        store = ReviewStore(args.db)
        try:
            if args.command == "queue":
                show({"scans": [{"scan_sha256": b["scan_sha256"], "issues": b["issues"]} for b in store.scans()],
                      "warnings": [{"id": x["id"], "state": x["state"], "rule_id": x["evidence"]["rule_id"],
                                    "cwe": x["evidence"]["cwe"], "model_status": x["assessment"]["status"]}
                                   for x in store.queue()]})
            elif args.command == "show":
                show(store.get(args.id))
            elif args.command == "history":
                show(store.history(args.id))
            else:
                show(store.decide(args.id, args.action, args.actor, args.reason))
        finally:
            store.close()
        return 0
    except (EvidenceError, OSError, ValueError, sqlite3.Error, RuntimeError) as exc:
        print("UNDETERMINED / operation refused: " + str(exc), file=sys.stderr)
        return 2
