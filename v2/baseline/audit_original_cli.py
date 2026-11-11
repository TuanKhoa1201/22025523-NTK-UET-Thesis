"""Read-only audit of an existing upstream CLI proof; never reruns or rewrites it."""
import argparse
import json
from pathlib import Path
from prove_original_cli import BASE, PIN, inspect_capture, sha, validate_dependencies
from verify_handoff import verify

LABELS = {"dependencies", "cli-help", "cli-scan", "triage"}


def verify_commands(root, commands):
    if not isinstance(commands, list) or len(commands) != len(LABELS):
        raise ValueError("missing or extra command evidence")
    labels = [c.get("label") for c in commands if isinstance(c, dict)]
    if len(labels) != len(commands) or set(labels) != LABELS:
        raise ValueError("missing/duplicate command label")
    verified = []
    for c in commands:
        if type(c.get("exit")) is not int or c["exit"] != 0 or c.get("timed_out") is not False:
            raise ValueError("command failed or timed out: " + c["label"])
        if not isinstance(c.get("argv"), list) or not all(isinstance(a, str) for a in c["argv"]):
            raise ValueError("invalid command argv")
        for stream in ("stdout", "stderr"):
            data = (root / (c["label"] + "." + stream + ".txt")).read_bytes()
            if sha(data) != c.get(stream + "_sha256"):
                raise ValueError("command log hash differs: " + c["label"] + "." + stream)
        verified.append({"label": c["label"], "exit": c["exit"], "timed_out": False})
    return verified


def audit(root):
    root = Path(root).resolve(strict=True)
    before = (root / "proof.json").read_bytes()
    proof = json.loads(before)
    if not isinstance(proof, dict) or proof.get("upstream_commit") != PIN:
        raise ValueError("wrong upstream commit in proof")
    expected = json.loads((BASE / "pinned_upstream_tree.json").read_text(encoding="utf-8"))
    preparation = json.loads((root / "prepared/preparation.json").read_text(encoding="utf-8"))
    if (not isinstance(preparation, dict) or preparation != proof.get("preparation") or preparation.get("full_checkout_verified") is not True or
            preparation.get("upstream_tree_sha") != expected["tree_sha"] or
            preparation.get("upstream_files_verified") != len(expected["files"])):
        raise ValueError("prepared checkout identity evidence differs")
    commands = verify_commands(root, proof.get("commands"))
    scan = next(c for c in proof["commands"] if c["label"] == "cli-scan")
    argv = scan["argv"]
    if len(argv) < 5 or argv[1:4] != ["-m", "semgrepai", "scan"] or "--scan-only" not in argv or "--rules-path" not in argv:
        raise ValueError("recorded invocation is not the upstream scan-only CLI")
    java = Path(argv[4])
    rules = Path(argv[argv.index("--rules-path") + 1])
    dependencies = json.loads((root / "dependencies.stdout.txt").read_text(encoding="utf-8"))
    validate_dependencies(dependencies)
    patch = json.loads((root / "prepared/patch-results.json").read_text(encoding="utf-8"))
    if (not isinstance(patch, list) or len(patch) != 2 or
            any(not isinstance(c, dict) or not isinstance(c.get("argv"), list) for c in patch) or
            any(type(c.get("exit")) is not int or c["exit"] != 0 for c in patch)
            or "--check" not in patch[0]["argv"] or "--check" in patch[1]["argv"]
            or any("apply" not in c["argv"] for c in patch)):
        raise ValueError("patch check/apply evidence is incomplete")
    overlay = (root / "prepared/ntk-local-overlay.patch").read_bytes()
    private_patch = (root / "prepared/advisor-private.patch").read_bytes()
    if sha(overlay) != preparation["overlay_sha256"] or sha(private_patch) != preparation["advisor_patch_sha256"]:
        raise ValueError("patch/overlay hash differs")
    captured = inspect_capture(root / "prepared/source", root / "capture", preparation, java, rules)
    handoff = verify(root / "capture", root / "triage", write_report=False)
    if not {"CWE-22", "CWE-89"}.issubset(captured["examples"]):
        raise ValueError("required demo examples absent")
    for component in ("cli", "scanner", "handoff"):
        if proof.get(component, {}).get("status") != "PASS":
            raise ValueError("recorded component is not PASS: " + component)
    manifest = json.loads((root / "capture/scan-manifest.json").read_text(encoding="utf-8"))
    if (root / "proof.json").read_bytes() != before:
        raise ValueError("proof changed during read-only audit")
    return {"audit_status": "PASS", "cli_runtime": "PASS", "recorded_host": proof.get("observed_host"), "server_acceptance": "PENDING",
            "original_proof_status_unchanged": proof.get("M1_ORIGINAL_CLI"),
            "evidence_root": str(root), "proof_sha256": sha(before), "dependencies": dependencies,
            "artifact_hashes_verified": len(manifest["artifacts"]), "source_hashes_verified": len(manifest["sources_before"]),
            "commands_verified": commands, "capture": captured, "handoff": handoff,
            "note": "Read-only component audit; does not attest server role or rewrite aggregate acceptance"}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("evidence", type=Path)
    p.add_argument("--output", type=Path, help="optional fresh audit file outside original evidence")
    args = p.parse_args()
    try:
        if args.output and args.output.resolve().is_relative_to(args.evidence.resolve()):
            raise ValueError("audit output must be outside original evidence")
        result = audit(args.evidence)
        if args.output:
            with args.output.open("x", encoding="utf-8") as stream:
                json.dump(result, stream, indent=2)
        print(json.dumps({k: v for k, v in result.items() if k not in ("capture", "handoff")}, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError) as exc:
        print("AUDIT FAIL: " + str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
