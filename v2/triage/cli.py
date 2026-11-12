"""Minimal local CLI for scan/import, evidence, inference and human review."""
import argparse
import json
import sqlite3
import sys
from pathlib import Path
from .evidence import collect, EvidenceError, StaleSourceError, SourceTree, digest
from .ollama import OllamaClient, undecided, PROMPT_CONTRACTS, DEFAULT_PROMPT_CONTRACT
from .heuristics import heuristic_analyze
from .store import ReviewStore
from .runtime import SCHEMA_VERSION, summary
from .scan_receipt import verify_receipt


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
    mode = getattr(args, "mode", "evidence+llm") or "evidence+llm"
    prompt_contract = getattr(args, "prompt_contract", DEFAULT_PROMPT_CONTRACT) or DEFAULT_PROMPT_CONTRACT
    if prompt_contract not in PROMPT_CONTRACTS:
        raise EvidenceError("unknown prompt contract: " + repr(prompt_contract))
    use_llm = (not args.no_llm) and (mode in ("evidence+llm", "llm"))
    # Validate network configuration before creating artifacts or scanning.
    client = (
        OllamaClient(
            args.endpoint,
            args.model,
            args.timeout,
            args.runtime_origin,
            io_log_dir=output / "llm_io",
        )
        if use_llm
        else None
    )
    output.mkdir(parents=True, exist_ok=False)
    issues = []
    exit_code = args.engine_exit
    before = None
    if args.json:
        raw = Path(args.json).read_bytes()
        receipt_path = args.scan_manifest
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
            exit_code = None  # wrapper failure is not the original JSON engine exit
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
        receipt_path = output / "engine/scan-manifest.json"
    receipt, receipt_issues = verify_receipt(receipt_path, raw, root, args.engine_exit if args.json else None)
    issues.extend(receipt_issues)
    if receipt["exit_capture_verified"]:
        exit_code = receipt["recorded_engine_exit"]
    (output / "input.opengrep.json").write_bytes(raw)
    bundle = collect(raw, root, args.path_base, exit_code, issues, path_maps=args.path_map, scan_provenance=receipt)
    bundle["scan_provenance"] = receipt
    bundle["prompt_contract"] = prompt_contract
    for record in bundle["records"]:
        record["prompt_contract"] = prompt_contract
        if mode != "evidence+llm":
            record["triage_mode"] = mode
        if receipt["source_capture_verified"]:
            for path, snapshot in record["snapshots"].items():
                if receipt["source_hashes"].get(path) != snapshot["sha256"]:
                    record["issues"].append("finding/trace source not bound to captured scan: " + path)
    if before is not None:
        bundle["pre_scan_hashes"] = before
    (output / "evidence.json").write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    model_inventory = client.verify_model_installed() if client is not None else None
    if model_inventory is not None:
        (output / "ollama-tags-check.json").write_text(json.dumps(model_inventory, indent=2), encoding="utf-8")
    if args.no_llm:
        assessments = [undecided("inference explicitly disabled", transport="disabled") for _ in bundle["records"]]
    elif mode == "heuristic":
        assessments = [heuristic_analyze(record) for record in bundle["records"]]
    else:
        assessments = []
        ckpt_path = Path(args.checkpoint) if getattr(args, "checkpoint", None) else None
        if ckpt_path:
            ckpt_path.parent.mkdir(parents=True, exist_ok=True)
        for record in bundle["records"]:
            assessment = client.analyze(record)
            assessments.append(assessment)
            if ckpt_path:
                with ckpt_path.open("a", encoding="utf-8") as ckpt_stream:
                    ckpt_stream.write(json.dumps({"id": record["id"], "assessment": assessment}, ensure_ascii=False) + "\n")
    store = ReviewStore(output / "review.sqlite")
    try:
        store.add(bundle, assessments)
    finally:
        store.close()
    with (output / "assessments.jsonl").open("x", encoding="utf-8") as stream:
        for record, assessment in zip(bundle["records"], assessments):
            stream.write(json.dumps({
                "schema_version": SCHEMA_VERSION,
                "id": record["id"],
                "alert_id": record["id"],
                "scan_sha256": record["scan_sha256"],
                "finding_index": record["finding_index"],
                "state": "OPEN",
                "human_review_state": "OPEN",
                "raw_model_status": assessment.get("raw_model_status"),
                "validated_status": assessment.get("validated_status", assessment.get("status")),
                "evidence": record,
                "assessment": assessment,
            }, ensure_ascii=False) + "\n")
    runtime_counts = summary(assessments)
    show({"scan_sha256": bundle["scan_sha256"], "warnings": len(bundle["records"]),
          "scan_issues": bundle["issues"], "states": [a["status"] for a in assessments],
          "raw_model_statuses": [a.get("raw_model_status") for a in assessments],
          "validated_statuses": [a.get("validated_status", a["status"]) for a in assessments],
          "prompt_contract": prompt_contract,
          "db": str(output / "review.sqlite"), "schema_version": SCHEMA_VERSION,
          "mode": "disabled" if args.no_llm else mode,
          "model_inventory": model_inventory,
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
    pipeline.add_argument("--scan-manifest", type=Path, help="scan-time manifest with original source, rule and exit artifacts")
    pipeline.add_argument("--path-base", help="base for relative engine paths; resolved files must remain inside source-root")
    pipeline.add_argument("--path-map", action="append", default=[], metavar="PREFIX=LOCAL_DIR",
                          help="explicit WSL/POSIX prefix mapping into source-root; raw JSON is unchanged")
    pipeline.add_argument("--engine-exit", type=int, help="original engine exit code when importing JSON; unknown forces UNDETERMINED")
    pipeline.add_argument("--rules")
    pipeline.add_argument("--executable", default="opengrep")
    pipeline.add_argument("--no-llm", action="store_true")
    pipeline.add_argument("--mode", choices=("evidence+llm", "heuristic", "llm"), default="evidence+llm",
                          help="triage mode: evidence+llm (default Arm C), heuristic (Arm B), or llm (Ablation Arm D)")
    pipeline.add_argument("--prompt-contract", choices=PROMPT_CONTRACTS, default=DEFAULT_PROMPT_CONTRACT,
                          help="LLM payload contract: blind (G1 default) or neutral_hints (controlled structural whitelist)")
    pipeline.add_argument("--checkpoint", help="optional JSONL checkpoint file outside repository")
    pipeline.add_argument("--endpoint", default="http://127.0.0.1:11434")
    pipeline.add_argument("--model", default="qwen3.5:9b-q4_K_M")
    pipeline.add_argument("--timeout", type=float, default=60)
    pipeline.add_argument("--runtime-origin", choices=("unverified", "mock"), default="unverified",
                          help="label simulated services; an HTTP reply alone cannot attest real inference")
    for command in ("queue", "show", "history", "decide", "confirm-true", "confirm-false", "reopen"):
        p = sub.add_parser(command)
        p.add_argument("--db", required=True)
        if command == "queue":
            p.add_argument("--all", action="store_true", dest="include_all", help="include human-confirmed false warnings")
        if command != "queue":
            p.add_argument("id")
        if command == "history":
            p.add_argument("--include-rejected", action="store_true", help="include rejected decision attempts (e.g. STALE_SOURCE)")
        if command == "decide":
            p.add_argument("action", choices=("confirm-true", "confirm-false", "reopen"))
            p.add_argument("--actor", required=True)
            p.add_argument("--reason", required=True)
        if command in ("confirm-true", "confirm-false", "reopen"):
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
                      "warnings": [{
                          "id": x["id"],
                          "state": x["state"],
                          "human_review_state": x["state"],
                          "rule_id": x["evidence"]["rule_id"],
                          "cwe": x["evidence"]["cwe"],
                          "path": x["evidence"].get("path"),
                          "model_status": x["assessment"]["status"],
                          "raw_model_status": x["assessment"].get("raw_model_status"),
                          "validated_status": x["assessment"].get("validated_status", x["assessment"]["status"]),
                      } for x in store.queue(include_all=args.include_all)]})
            elif args.command == "show":
                item = store.get(args.id)
                show({
                    **item,
                    "human_review_state": item["state"],
                    "raw_model_status": item["assessment"].get("raw_model_status"),
                    "validated_status": item["assessment"].get("validated_status", item["assessment"].get("status")),
                    "rejected_decisions": store.rejected_decisions(args.id),
                })
            elif args.command == "history":
                if getattr(args, "include_rejected", False):
                    show({
                        "events": store.history(args.id),
                        "rejected_decisions": store.rejected_decisions(args.id),
                    })
                else:
                    show(store.history(args.id))
            elif args.command in ("confirm-true", "confirm-false", "reopen"):
                decided = store.decide(args.id, args.command, args.actor, args.reason)
                show({**decided, "human_review_state": decided["state"]})
            else:
                decided = store.decide(args.id, args.action, args.actor, args.reason)
                show({**decided, "human_review_state": decided["state"]})
        finally:
            store.close()
        return 0
    except StaleSourceError as exc:
        print(
            "UNDETERMINED / operation refused [STALE_SOURCE]: " + str(exc) + "\n" + json.dumps(exc.to_dict(), ensure_ascii=True),
            file=sys.stderr,
        )
        return 2
    except (EvidenceError, OSError, ValueError, sqlite3.Error, RuntimeError) as exc:
        print("UNDETERMINED / operation refused: " + str(exc), file=sys.stderr)
        return 2
