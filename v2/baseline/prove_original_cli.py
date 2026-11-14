"""Run the inherited upstream CLI, never a direct scanner substitute.

All outputs are local/private. Component verification is not server acceptance.
"""
import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from prepare_upstream_local import BASE, PIN, prepare, prepared_hashes
from finding_identity import compare_findings


def sha(data):
    return hashlib.sha256(data).hexdigest()


def validate_dependencies(document):
    if not isinstance(document, dict) or not isinstance(document.get("python"), str) or not isinstance(document.get("executable"), str):
        raise ValueError("dependency probe did not identify its Python interpreter")
    packages = document.get("packages")
    if not isinstance(packages, dict):
        raise ValueError("dependency probe missing package versions")
    missing = [name for name in ("typer", "rich", "PyYAML") if not isinstance(packages.get(name), str) or not packages[name].strip()]
    if missing:
        raise ValueError("required CLI dependencies unavailable: " + ", ".join(missing))


def validate_cli_origin(source, origin, hashes):
    source = Path(source).resolve()
    if origin.get("stage") != "exit" or origin.get("main_module") != "semgrepai.__main__":
        raise ValueError("not a completed python -m semgrepai CLI invocation")
    if origin.get("function") != "semgrepai.cli.scan" or origin.get("producer") != "inherited-cli-function-hook":
        raise ValueError("not the inherited CLI scan function")
    if origin.get("forbidden_imports") != []:
        raise ValueError("RAG/provider imports observed")
    argv = origin.get("argv")
    if (not isinstance(argv, list) or len(argv) < 3 or
            Path(argv[0]).resolve() != source / "semgrepai/__main__.py" or
            argv[1] != "scan" or "--scan-only" not in argv):
        raise ValueError("CLI argv does not identify the original package entrypoint")
    for key, name in (("cli", "cli.py"), ("scanner", "scanner.py")):
        relative = "semgrepai/" + name
        file = Path(origin[key + "_file"]).resolve()
        if file != source / relative or origin[key + "_sha256"] != hashes[relative] or sha(file.read_bytes()) != hashes[relative]:
            raise ValueError("CLI/scanner origin or code hash mismatch")


def inspect_capture(source, capture, preparation, java_root, rules):
    # Disable incidental bytecode writes outside baseline when importing existing triage code.
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(BASE.parents[1]))
    from v2.triage.scan_receipt import verify_receipt
    from v2.triage.evidence import collect
    raw = (capture / "opengrep.json").read_bytes()
    manifest = json.loads((capture / "scan-manifest.json").read_text(encoding="utf-8"))
    origin = json.loads((capture / "cli-origin.json").read_text(encoding="utf-8"))
    validate_cli_origin(source, origin, preparation["prepared_files_sha256"])
    if prepared_hashes(source) != preparation["prepared_files_sha256"]:
        raise ValueError("prepared code changed during CLI execution")
    if manifest.get("producer") != "ntk-instrumented-upstream-scanner":
        raise ValueError("capture is not from the inherited upstream scanner")
    receipt, issues = verify_receipt(capture / "scan-manifest.json", raw, java_root)
    if issues or receipt["source_capture_verified"] is not True:
        raise ValueError("capture verification failed: " + "; ".join(issues))
    if sha(Path(rules).read_bytes()) != manifest["rules_before_sha256"]:
        raise ValueError("CLI did not capture the requested rule version")
    bundle = collect(raw, java_root, engine_exit=receipt["recorded_engine_exit"], scan_provenance=receipt)
    if bundle["issues"] or any(r["issues"] for r in bundle["records"]):
        raise ValueError("unverified source/trace in CLI output")
    doc = json.loads(raw)
    sarif = json.loads((capture / "opengrep.sarif").read_bytes())
    identity = compare_findings(doc, sarif)
    examples = {}
    for finding, record in zip(doc["results"], bundle["records"]):
        for cwe in record["cwe"]:
            cwe = cwe.split(":", 1)[0].strip()
            if cwe in ("CWE-22", "CWE-89") and cwe not in examples:
                examples[cwe] = {"rule_id": finding["check_id"], "path": record["snippets"][0]["path"],
                    "finding_start": finding["start"], "finding_end": finding["end"],
                    "locations": [{"role": s["role"], "path": s["path"], "start": s["start"],
                                   "end": s["end"], "matched": s["matched"], "sha256": s["sha256"]}
                                  for s in record["snippets"]]}
    return {"findings": len(doc["results"]), "sarif_findings": sum(len(r.get("results", [])) for r in sarif["runs"]),
            "json_sarif_rule_ids_and_locations_match": identity["rule_ids_and_locations_match"],
            "engine_version": (capture / "version.stdout.txt").read_text(encoding="utf-8").strip(),
            "scan_sha256": sha(raw), "original_engine_exits": {k: v["exit_code"] for k, v in manifest["runs"].items()},
            "examples": examples, "origin": origin}


def run(upstream, advisor, output, python=sys.executable, source=None, rules=None, timeout=180):
    output = Path(output).resolve()
    if output.is_relative_to(Path(upstream).resolve()):
        raise ValueError("evidence must be outside the original upstream checkout")
    output.mkdir(parents=True, exist_ok=False)
    source = Path(source or BASE / "fixtures/java").resolve()
    rules = Path(rules or BASE / "rules/java.yml").resolve()
    python = Path(python).resolve()
    result = {"upstream_commit": PIN, "M1_ORIGINAL_CLI": "SERVER_RUNTIME_PENDING",
              "cli": {"status": "NOT_RUN"}, "scanner": {"status": "NOT_RUN"}, "handoff": {"status": "NOT_RUN"},
              "web_rag": {"status": "NOT_REQUESTED", "reason": "disabled; not part of this proof"},
              "observed_host": socket.gethostname(), "platform": sys.platform, "started_at": datetime.now(timezone.utc).isoformat(),
              "server_role_independently_verified": False, "commands": []}
    def save():
        (output / "proof.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    def execute(label, command, cwd, environment):
        try:
            proc = subprocess.run([str(x) for x in command], cwd=cwd, env=environment, capture_output=True, timeout=timeout)
            code, stdout, stderr, timed_out = proc.returncode, proc.stdout, proc.stderr, False
        except subprocess.TimeoutExpired as exc:
            code, stdout, stderr, timed_out = None, exc.stdout or b"", exc.stderr or b"", True
        except OSError as exc:
            code, stdout, stderr, timed_out = None, b"", (type(exc).__name__ + ": " + str(exc)).encode("utf-8"), False
        (output / (label + ".stdout.txt")).write_bytes(stdout)
        (output / (label + ".stderr.txt")).write_bytes(stderr)
        result["commands"].append({"label": label, "argv": [str(x) for x in command], "cwd": str(cwd),
                                   "exit": code, "timed_out": timed_out, "stdout_sha256": sha(stdout), "stderr_sha256": sha(stderr)})
        save()
        return code
    stage = "inputs"
    try:
        if not source.is_dir() or not rules.is_file() or not python.is_file() or timeout <= 0:
            raise ValueError("source directory, existing local rules, Python executable and positive timeout required")
        if output.is_relative_to(source):
            raise ValueError("evidence directory must be outside the scanned Java root")
        stage = "prepare"
        preparation = prepare(upstream, advisor, output / "prepared")
        result["preparation"] = preparation
        prepared = output / "prepared/source"
        if prepared_hashes(prepared) != preparation["prepared_files_sha256"]:
            raise ValueError("prepared tree changed before execution")
        env = os.environ.copy()
        for name in ("PYTHONPATH", "PYTHONHOME", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OPENROUTER_API_KEY"):
            env.pop(name, None)
        env.update(PYTHONUTF8="1", PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1",
                   OPENGREP_ENABLE_VERSION_CHECK="0", SEMGREP_ENABLE_VERSION_CHECK="0", SEMGREP_SEND_METRICS="off",
                   SEMGREP_LOG_FILE=str(output / "opengrep.log"), SEMGREP_SETTINGS_FILE=str(output / "settings.yml"))
        probe = ('import json,sys,importlib.metadata as m\npackages={}\n'
                 'for n in ("typer","rich","PyYAML"):\n'
                 ' try: packages[n]=m.version(n)\n'
                 ' except m.PackageNotFoundError: packages[n]=None\n'
                 'print(json.dumps({"python":sys.version,"executable":sys.executable,"packages":packages}))')
        stage = "dependencies"
        if execute("dependencies", [python, "-c", probe], prepared, env) != 0:
            raise ValueError("dependency probe failed; inspect dependencies.stderr.txt")
        validate_dependencies(json.loads((output / "dependencies.stdout.txt").read_text(encoding="utf-8")))
        stage = "cli-help"
        if execute("cli-help", [python, "-m", "semgrepai", "--help"], prepared, env) != 0:
            result["cli"]["status"] = "BLOCKED"
            raise ValueError("original CLI help failed; inspect cli-help.stderr.txt and dependencies.stderr.txt")
        stage = "cli-scan"
        capture = output / "capture"
        command = [python, "-m", "semgrepai", "scan", source, "--rules-path", rules,
                   "--config-path", prepared / "semgrepai.yml", "--output-dir", capture, "--scan-only"]
        if execute("cli-scan", command, prepared, env) != 0:
            result["cli"]["status"] = "FAIL"
            raise ValueError("original CLI scan failed; inspect cli-scan.stderr.txt/stdout.txt")
        result["cli"]["status"] = "PARTIAL"
        stage = "capture"
        result["scanner"] = {"status": "PASS", **inspect_capture(prepared, capture, preparation, source, rules)}
        result["cli"]["status"] = "PASS"
        stage = "handoff"
        handoff = output / "triage"
        code = execute("triage", [python, "-m", "v2.triage", "run", "--source-root", source,
                    "--json", capture / "opengrep.json", "--scan-manifest", capture / "scan-manifest.json",
                    "--output-dir", handoff, "--no-llm"], BASE.parents[1], env)
        if code != 0:
            result["handoff"]["status"] = "FAIL"
            raise ValueError("triage handoff failed")
        from verify_handoff import verify
        result["handoff"] = verify(capture, handoff)
        if not {"CWE-22", "CWE-89"}.issubset(result["scanner"]["examples"]):
            result["demo_examples"] = "PARTIAL: required CWE examples not found"
        else:
            result["demo_examples"] = "PASS"
        result["remaining_acceptance"] = "Review these real command logs on the JavisOS server before changing M1 ORIGINAL CLI to PASS"
        save()
        return result, 0 if result["demo_examples"] == "PASS" else 2
    except (OSError, ValueError, RuntimeError, KeyError, AssertionError, subprocess.SubprocessError, zipfile.BadZipFile) as exc:
        result["first_failure_stage"] = stage
        result["error"] = str(exc)
        if stage == "capture":
            result["scanner"]["status"] = "FAIL"
        if result["cli"]["status"] == "NOT_RUN":
            result["cli"]["status"] = "BLOCKED"
        save()
        return result, 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--advisor-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--source", type=Path)
    parser.add_argument("--rules", type=Path)
    parser.add_argument("--timeout", type=float, default=180)
    a = parser.parse_args()
    try:
        result, code = run(a.upstream, a.advisor_dir, a.output_dir, a.python, a.source, a.rules, a.timeout)
    except FileExistsError:
        parser.error("output directory exists; choose a fresh directory")
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps({k: v for k, v in result.items() if k not in ("preparation", "commands")}, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
