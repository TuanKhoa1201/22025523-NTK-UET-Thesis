"""Minimal contract bridge between the prepared simple_semgrepAI fork CLI and v2.triage.

Guarantees:
1. Entry comes through inherited `semgrepai.__main__` / `semgrepai.cli:app` and `SemgrepScanner`.
2. OpenGrep runs ONCE in the scanner stage; triage imports raw `capture/opengrep.json` +
   `capture/scan-manifest.json` with zero implicit rescanning.
3. Raw JSON, SARIF, byte offsets, CWE metadata, and ATD `dataflow_trace` are preserved lossless.
4. Every alert (including Qwen errors, timeouts, malformed JSON, or missing trace) enters SQLite
   with human state `OPEN`.
5. Wrapper exit code `0` is never conflated with Qwen/validator success: `g1-run-manifest.json`
   reports independent statuses for scanner, source integrity, JSON/SARIF parity, handoff, Qwen HTTP,
   validator, and review queue.
"""
from __future__ import annotations

from collections.abc import Sequence
from contextlib import contextmanager, redirect_stdout
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
from types import SimpleNamespace
from typing import Any

from v2.g1_integration import G1_INTEGRATION_VERSION, UPSTREAM_COMMIT, UPSTREAM_REPO, UPSTREAM_VERSION
from v2.g1_integration.finding_identity import compare_findings
from v2.g1_integration.fork_support.scanner_config import validate_opengrep_binary
from v2.triage import cli as triage_cli
from v2.triage import live_check
from v2.triage.evidence import EvidenceError, SourceTree, digest, now, strict_json
from v2.triage.ollama import DEFAULT_PROMPT_CONTRACT, PROMPT_CONTRACTS, PROMPT_VERSION, OllamaClient
from v2.triage.runtime import SCHEMA_VERSION
from v2.triage.store import ReviewStore

DEFAULT_G1_RULES = Path(__file__).resolve().parent / "rules" / "java_g1_cwe22_cwe89.yml"

KNOWN_ANALYSIS_LIMITS = [
    "Java structural context covers the enclosing method plus same-file helper callees within bounded line span (<=150 lines).",
    "Cross-file helper implementations and call chains exceeding bounded hop depth are not inferred; validator fails closed to UNDETERMINED and blocks REFUTED.",
    "Actor identity in CLI review commands is an unauthenticated operator-supplied string recorded for local audit trail.",
    "SQLite review store enforces application-level append-only history and foreign-key invariants, not OS-level tamper-proof hardware/MAC controls.",
    "HTTP 200 from loopback Ollama proves local HTTP protocol completion, not cryptographic attestation of model weights.",
]


@contextmanager
def _forbid_implicit_scanner_rescan():
    """Hard runtime guard ensuring triage handoff never spawns OpenGrep or Semgrep a second time."""
    real_run = subprocess.run
    real_popen = subprocess.Popen

    def _check_cmd(cmd):
        first = ""
        if isinstance(cmd, (list, tuple)) and cmd:
            first = Path(str(cmd[0])).name.lower()
        elif isinstance(cmd, str) and cmd.strip():
            first = Path(cmd.strip().split()[0]).name.lower()
        if first.startswith("opengrep") or first.startswith("semgrep"):
            raise RuntimeError(f"implicit scanner rescan forbidden during triage handoff: {cmd!r}")

    def guarded_run(cmd, *args, **kwargs):
        _check_cmd(cmd)
        return real_run(cmd, *args, **kwargs)

    class GuardedPopen(real_popen):  # type: ignore[misc,valid-type]
        def __init__(self, cmd, *args, **kwargs):
            _check_cmd(cmd)
            super().__init__(cmd, *args, **kwargs)

    subprocess.run = guarded_run
    subprocess.Popen = GuardedPopen  # type: ignore[assignment]
    try:
        yield
    finally:
        subprocess.run = real_run
        subprocess.Popen = real_popen  # type: ignore[assignment]


def _source_inventory(target_path: Path) -> tuple[Path, dict[str, str]]:
    raw_target = Path(target_path).expanduser()
    lexical_parent = raw_target.absolute().parent.resolve(strict=True)
    resolved_target = raw_target.resolve(strict=True)
    if resolved_target.is_file():
        if not resolved_target.is_relative_to(lexical_parent):
            raise EvidenceError("single-file scan target symlink escapes parent directory")
        if resolved_target.suffix.lower() != ".java":
            raise EvidenceError("single-file target must be a .java file")
        source_root = resolved_target.parent
        tree = SourceTree(source_root)
        rel, data, _ = tree.read(resolved_target.name)
        return source_root, {rel: digest(data)}
    if not resolved_target.is_dir():
        raise EvidenceError("scan target must be an existing Java file or directory")
    if raw_target.is_symlink() or (hasattr(raw_target, "is_junction") and raw_target.is_junction()):
        if not resolved_target.is_relative_to(lexical_parent):
            raise EvidenceError("directory scan target symlink/junction escapes parent directory")
    tree = SourceTree(resolved_target)

    def _reject_walk_error(exc: OSError) -> None:
        raise EvidenceError("cannot enumerate source directories") from exc

    for parent, child_dirs, _ in os.walk(
        tree.root, topdown=True, followlinks=False,
        onerror=_reject_walk_error
    ):
        for child_name in child_dirs:
            child = Path(parent) / child_name
            try:
                resolved_child = child.resolve(strict=True)
            except (OSError, RuntimeError) as exc:
                raise EvidenceError("cannot resolve source directory; rescan required") from exc
            if not resolved_child.is_relative_to(tree.root):
                raise EvidenceError("directory link outside configured root")
            if child.is_symlink() or (
                hasattr(child, "is_junction") and child.is_junction()
            ):
                raise EvidenceError("linked source directory cannot be safely inventoried")

    inv: dict[str, str] = {}
    for java_file in sorted(tree.root.rglob("*.java")):
        rel, data, _ = tree.read(str(java_file))
        inv[rel] = digest(data)
    return resolved_target, inv


def derive_trusted_path_maps(
    source_root: Path,
    extra_path_maps: Sequence[str] | None = None,
    *,
    os_name: str | None = None,
) -> list[str]:
    """Derive verified POSIX/WSL2 -> Windows path mappings strictly from trusted `source_root`.

    Security invariants:
    - Never inspects or trusts arbitrary paths emitted in `opengrep.json` / `opengrep.sarif`.
    - Only maps local single-letter Windows drive subdirectories (`/mnt/<drive>/<rel_source_root>=<source_root>`);
      refuses UNC network shares, bare drive roots (`C:\\`), cross-drive targets, `..` traversal, and symlinks
      escaping `source_root`.
    - On pure POSIX/Linux (`os_name != 'nt'`), synthesizes zero automatic mappings and preserves native flow.
    """
    root = Path(source_root).resolve(strict=True)
    if not root.is_dir():
        raise EvidenceError("source root must be a directory")

    explicit_entries = [str(entry) for entry in (extra_path_maps or ()) if entry is not None]
    explicit_tree = SourceTree(root, path_maps=explicit_entries)
    explicit_by_prefix = {m["from"]: Path(m["to"]).resolve(strict=True) for m in explicit_tree.path_maps}

    combined: list[str] = list(explicit_entries)
    active_os = os.name if os_name is None else os_name
    if active_os == "nt" and re.fullmatch(r"[A-Za-z]:", root.drive):
        rel_posix = root.relative_to(root.anchor).as_posix().strip("/")
        if rel_posix and ".." not in PurePosixPath(rel_posix).parts and "\\" not in rel_posix and ":" not in rel_posix:
            wsl_prefix = str(PurePosixPath(f"/mnt/{root.drive[0].lower()}/{rel_posix}"))
            if wsl_prefix not in explicit_by_prefix:
                combined.insert(0, f"{wsl_prefix}={root}")

    verified_tree = SourceTree(root, path_maps=combined)
    return [f"{m['from']}={m['to']}" for m in verified_tree.path_maps]


def _verify_handoff_records(raw_json_bytes: bytes, evidence_bundle: dict[str, Any], queue_rows: list[dict[str, Any]]) -> dict[str, Any]:
    checks = {
        "raw_json_parseable": False,
        "finding_count_matches": False,
        "ids_match_formula": False,
        "rule_ids_and_locations_preserved": False,
        "cwe_preserved": False,
        "traces_preserved_lossless": False,
        "queue_count_matches_findings": False,
        "all_queue_states_open": False,
        "raw_findings_count": 0,
        "triage_records_count": len(evidence_bundle.get("records") or []),
        "queue_rows_count": len(queue_rows),
        "findings_with_trace_count": 0,
        "discrepancies": [],
    }
    discrepancies: list[str] = checks["discrepancies"]
    try:
        raw_doc = strict_json(raw_json_bytes.decode("utf-8"))
    except (EvidenceError, UnicodeError) as exc:
        discrepancies.append(f"raw JSON unparseable: {exc}")
        return checks
    if not isinstance(raw_doc, dict) or not isinstance(raw_doc.get("results"), list):
        discrepancies.append("raw JSON missing results[] list")
        return checks
    checks["raw_json_parseable"] = True
    raw_results = raw_doc["results"]
    checks["raw_findings_count"] = len(raw_results)
    records = evidence_bundle.get("records") or []
    scan_sha = digest(raw_json_bytes)

    if len(records) == len(raw_results):
        checks["finding_count_matches"] = True
    else:
        discrepancies.append(f"finding count mismatch: raw={len(raw_results)} vs triage={len(records)}")

    ids_ok = True
    rules_locs_ok = True
    cwe_ok = True
    traces_ok = True
    trace_count = 0

    for idx, (orig, rec) in enumerate(zip(raw_results, records)):
        expected_id = digest(f"{scan_sha}:{idx}".encode("utf-8"))
        if rec.get("finding_index") != idx or rec.get("id") != expected_id or rec.get("alert_id") != expected_id:
            ids_ok = False
            discrepancies.append(f"finding[{idx}] ID/index mismatch")
        if isinstance(orig, dict):
            if rec.get("rule_id") != orig.get("check_id") or rec.get("path") != orig.get("path"):
                rules_locs_ok = False
                discrepancies.append(f"finding[{idx}] rule_id/path mismatch")
            if rec.get("start") != orig.get("start") or rec.get("end") != orig.get("end"):
                rules_locs_ok = False
                discrepancies.append(f"finding[{idx}] start/end coordinates mismatch")
            if rec.get("raw_finding") != orig:
                traces_ok = False
                discrepancies.append(f"finding[{idx}] raw_finding differs from original result")
            extra = orig.get("extra") if isinstance(orig.get("extra"), dict) else {}
            orig_trace = extra.get("dataflow_trace", orig.get("dataflow_trace"))
            if rec.get("raw_trace") != orig_trace:
                traces_ok = False
                discrepancies.append(f"finding[{idx}] raw_trace differs from original dataflow_trace")
            if isinstance(orig_trace, dict) and orig_trace:
                trace_count += 1
            meta = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
            orig_cwe = meta.get("cwe", [])
            if isinstance(orig_cwe, str):
                orig_cwe = [orig_cwe]
            if isinstance(orig_cwe, list) and all(isinstance(x, str) for x in orig_cwe) and orig_cwe:
                if rec.get("cwe") != orig_cwe:
                    cwe_ok = False
                    discrepancies.append(f"finding[{idx}] CWE metadata mismatch")

    checks["ids_match_formula"] = ids_ok and checks["finding_count_matches"]
    checks["rule_ids_and_locations_preserved"] = rules_locs_ok and checks["finding_count_matches"]
    checks["cwe_preserved"] = cwe_ok and checks["finding_count_matches"]
    checks["traces_preserved_lossless"] = traces_ok and checks["finding_count_matches"]
    checks["findings_with_trace_count"] = trace_count

    if len(queue_rows) == len(raw_results):
        checks["queue_count_matches_findings"] = True
    else:
        discrepancies.append(f"SQLite queue count ({len(queue_rows)}) != raw findings ({len(raw_results)})")

    if all(r.get("state") == "OPEN" for r in queue_rows):
        checks["all_queue_states_open"] = True
    else:
        discrepancies.append("one or more ingested findings did not start in OPEN human state")

    return checks


def run_local_triage_from_cli(
    *,
    cli_file: str,
    scanner_cls: Any,
    recording_fn: Any,
    record_cli_origin_fn: Any,
    get_invocations_fn: Any,
    reset_invocations_fn: Any,
    target_path: Path,
    rules_path: Path | None,
    output_dir: Path,
    config_path: Path | None = None,
    executable: str | None = None,
    endpoint: str = "http://127.0.0.1:11434",
    model: str = "qwen3.5:9b-q4_K_M",
    prompt_contract: str = DEFAULT_PROMPT_CONTRACT,
    timeout: float = 120.0,
    no_llm: bool = False,
    runtime_origin: str = "unverified",
    path_map: Sequence[str] | None = None,
    argv: list[str] | None = None,
) -> tuple[int, dict[str, Any]]:
    """Execute the full G1 pipeline starting from the inherited simple_semgrepAI CLI."""
    output_dir = Path(output_dir).resolve()
    if output_dir.exists():
        raise EvidenceError(f"output_dir must not already exist (refusing to overwrite): {output_dir}")

    if prompt_contract not in PROMPT_CONTRACTS:
        raise EvidenceError(f"unsupported prompt_contract: {prompt_contract!r}")

    if executable is not None:
        validate_opengrep_binary(executable)

    resolved_rules = Path(rules_path).resolve(strict=True) if rules_path is not None else DEFAULT_G1_RULES.resolve(strict=True)
    if not resolved_rules.is_file():
        raise EvidenceError(f"local rules file does not exist: {resolved_rules}")

    source_root, pre_scan_sources = _source_inventory(Path(target_path))
    resolved_target = Path(target_path).expanduser().resolve(strict=True)
    trusted_path_maps = derive_trusted_path_maps(source_root, extra_path_maps=path_map)

    # Validate local loopback Ollama configuration BEFORE creating directories or running OpenGrep.
    if not no_llm:
        OllamaClient(endpoint=endpoint, model=model, timeout=timeout, runtime_origin=runtime_origin)

    output_dir.mkdir(parents=True, exist_ok=False)
    capture_dir = output_dir / "capture"
    triage_dir = output_dir / "triage"

    reset_invocations_fn()
    scanner_error: str | None = None
    with recording_fn(resolved_target, resolved_rules, capture_dir, cli_mode="local-triage"):
        record_cli_origin_fn(cli_file, scanner_cls, "enter", mode="local-triage")
        try:
            scanner = scanner_cls(
                binary=executable,
                config_path=str(config_path) if config_path else None,
            )
            scanner.scan(resolved_target, resolved_rules)
            record_cli_origin_fn(cli_file, scanner_cls, "exit", mode="local-triage")
        except Exception as exc:
            scanner_error = f"{type(exc).__name__}: {exc}"
            try:
                record_cli_origin_fn(cli_file, scanner_cls, "error", mode="local-triage")
            except Exception:
                pass

    # If scanner_error was caught inside `with recording_fn(...)`, `recording_fn` treated the block as normal exit;
    # ensure `scan-manifest.json` explicitly marks scanner failure if `scanner_error` occurred!
    manifest_path = capture_dir / "scan-manifest.json"
    if scanner_error is not None and manifest_path.is_file():
        mdoc = json.loads(manifest_path.read_text(encoding="utf-8"))
        mdoc["success"] = False
        mdoc.setdefault("issues", []).append("scanner raised error: " + scanner_error)
        manifest_path.write_text(json.dumps(mdoc, indent=2), encoding="utf-8")

    scanner_invocations = get_invocations_fn()

    raw_json_path = capture_dir / "opengrep.json"
    raw_sarif_path = capture_dir / "opengrep.sarif"
    if not raw_json_path.is_file():
        raw_json_path.write_bytes(b"")

    raw_json_bytes = raw_json_path.read_bytes()
    parity_report: dict[str, Any] = {"rule_ids_and_locations_match": False, "error": None}
    if raw_json_bytes and raw_sarif_path.is_file():
        try:
            j_doc = strict_json(raw_json_bytes.decode("utf-8"))
            s_doc = strict_json(raw_sarif_path.read_bytes().decode("utf-8"))
            parity_report = {**compare_findings(j_doc, s_doc), "error": None}
        except (EvidenceError, ValueError, UnicodeError) as exc:
            parity_report = {"rule_ids_and_locations_match": False, "error": str(exc)}
    else:
        parity_report = {
            "rule_ids_and_locations_match": False,
            "error": "missing opengrep.json or opengrep.sarif capture",
        }

    # Handoff to v2.triage in import mode (--json + --scan-manifest) under strict no-rescan guard.
    triage_args = SimpleNamespace(
        source_root=str(source_root),
        output_dir=str(triage_dir),
        json=str(raw_json_path),
        scan_manifest=manifest_path if manifest_path.is_file() else None,
        path_base=None,
        path_map=list(trusted_path_maps),
        engine_exit=None,
        rules=str(resolved_rules),
        executable=executable or "opengrep",
        no_llm=bool(no_llm),
        mode="evidence+llm",
        prompt_contract=prompt_contract,
        checkpoint=None,
        endpoint=endpoint,
        model=model,
        timeout=float(timeout),
        runtime_origin=runtime_origin,
    )

    triage_stdout_buf = io.StringIO()
    with _forbid_implicit_scanner_rescan(), redirect_stdout(triage_stdout_buf):
        triage_exit = triage_cli.run(triage_args)

    post_triage_invocations = get_invocations_fn()
    triage_subprocess_count = len(post_triage_invocations) - len(scanner_invocations)
    if triage_subprocess_count != 0:
        raise RuntimeError(f"triage stage unexpectedly invoked scanner {triage_subprocess_count} time(s)")

    triage_summary = json.loads(triage_stdout_buf.getvalue()) if triage_stdout_buf.getvalue().strip() else {}

    # Post-triage source consistency check
    post_source_error: str | None = None
    try:
        _, post_triage_sources = _source_inventory(Path(target_path))
        source_consistent = pre_scan_sources == post_triage_sources
        if not source_consistent:
            post_source_error = "source files changed between pre-scan and post-triage verification"
    except (EvidenceError, OSError, ValueError, RuntimeError) as exc:
        post_triage_sources = {}
        source_consistent = False
        post_source_error = str(exc)

    evidence_bundle = json.loads((triage_dir / "evidence.json").read_text(encoding="utf-8"))
    assessments_rows = [
        strict_json(line)
        for line in (triage_dir / "assessments.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    store = ReviewStore(triage_dir / "review.sqlite")
    try:
        queue_all = store.queue(include_all=True)
    finally:
        store.close()

    handoff_checks = _verify_handoff_records(raw_json_bytes, evidence_bundle, queue_all)

    protocol_check = None
    if not no_llm:
        protocol_check = live_check.inspect(assessments_rows, minimum=max(1, len(assessments_rows)))
        (triage_dir / "live-protocol-check.json").write_text(
            json.dumps(protocol_check, indent=2), encoding="utf-8"
        )

    version_txt = (capture_dir / "version.stdout.txt").read_text(encoding="utf-8", errors="replace").strip() if (capture_dir / "version.stdout.txt").is_file() else None
    scan_manifest_doc = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.is_file() else {}

    # Compute independent per-stage statuses (never conflating wrapper exit 0 with Qwen/validator success!)
    scanner_ok = (
        scanner_error is None
        and scan_manifest_doc.get("success") is True
        and all(
            isinstance(scan_manifest_doc.get("runs", {}).get(k), dict)
            and scan_manifest_doc["runs"][k].get("exit_code") == 0
            for k in ("version", "json", "sarif")
        )
        and not evidence_bundle.get("issues")
    )
    source_ok = bool(
        source_consistent
        and evidence_bundle.get("scan_provenance", {}).get("source_capture_verified") is True
    )
    parity_ok = parity_report.get("rule_ids_and_locations_match") is True
    handoff_ok = (
        handoff_checks["raw_json_parseable"]
        and handoff_checks["finding_count_matches"]
        and handoff_checks["ids_match_formula"]
        and handoff_checks["rule_ids_and_locations_preserved"]
        and handoff_checks["cwe_preserved"]
        and handoff_checks["traces_preserved_lossless"]
        and handoff_checks["queue_count_matches_findings"]
        and handoff_checks["all_queue_states_open"]
        and triage_subprocess_count == 0
    )

    assessments_list = [row["assessment"] for row in assessments_rows]
    if no_llm:
        qwen_status = "DISABLED"
        validator_status = "NOT_APPLICABLE"
    elif not assessments_list:
        qwen_status = "NO_FINDINGS"
        validator_status = "NOT_APPLICABLE"
    else:
        http_ok_count = sum(
            1 for a in assessments_list
            if a.get("runtime", {}).get("http_response_received") is True
            and a.get("runtime", {}).get("http_status") == 200
            and a.get("runtime", {}).get("response_complete") is True
            and a.get("runtime", {}).get("model_identity_matched") is True
        )
        validated_count = sum(1 for a in assessments_list if a.get("runtime", {}).get("answer_validated") is True)
        qwen_status = "ALL_HTTP_COMPLETED" if http_ok_count == len(assessments_list) else "PARTIAL_OR_FAILED"
        validator_status = "ALL_VALIDATED" if validated_count == len(assessments_list) else "DOWNGRADED_TO_UNDETERMINED"

    wrapper_exit_code = 0 if (triage_exit == 0 and scanner_ok and source_ok and parity_ok and handoff_ok) else 2
    all_stages_succeeded = bool(
        wrapper_exit_code == 0
        and (
            no_llm
            or not assessments_list
            or (qwen_status == "ALL_HTTP_COMPLETED" and validator_status == "ALL_VALIDATED")
        )
    )

    artifact_paths = {
        "opengrep_json": raw_json_path,
        "opengrep_sarif": raw_sarif_path,
        "scan_manifest": manifest_path,
        "cli_origin": capture_dir / "cli-origin.json",
        "evidence_json": triage_dir / "evidence.json",
        "assessments_jsonl": triage_dir / "assessments.jsonl",
        "review_sqlite": triage_dir / "review.sqlite",
    }
    artifact_hashes = {
        key: digest(p.read_bytes()) if p.is_file() else None
        for key, p in artifact_paths.items()
    }

    g1_manifest = {
        "schema": "ntk-g1-run-manifest-1",
        "g1_integration_version": G1_INTEGRATION_VERSION,
        "triage_schema_version": SCHEMA_VERSION,
        "prompt_version": PROMPT_VERSION,
        "prompt_contract": prompt_contract,
        "upstream": {
            "repository": UPSTREAM_REPO,
            "version": UPSTREAM_VERSION,
            "pinned_commit": UPSTREAM_COMMIT,
        },
        "recorded_at": now(),
        "cli_argv": list(argv) if argv is not None else None,
        "target_path": str(Path(target_path).resolve()),
        "source_root": str(source_root),
        "trusted_path_maps": list(trusted_path_maps),
        "rules_path": str(resolved_rules),
        "rules_sha256": digest(resolved_rules.read_bytes()),
        "opengrep_version": version_txt,
        "scanner_subprocess_invocations": scanner_invocations,
        "triage_subprocess_invocations": triage_subprocess_count,
        "scanner_error": scanner_error,
        "post_source_error": post_source_error,
        "pre_scan_sources_sha256": pre_scan_sources,
        "post_triage_sources_sha256": post_triage_sources,
        "json_sarif_parity": parity_report,
        "handoff_verification": handoff_checks,
        "stage_statuses": {
            "scanner_status": "OK" if scanner_ok else "FAILED",
            "source_integrity_status": "VERIFIED" if source_ok else "FAILED",
            "json_sarif_parity_status": "MATCHED" if parity_ok else "MISMATCH",
            "handoff_status": "VERIFIED" if handoff_ok else "DEGRADED",
            "qwen_inference_status": qwen_status,
            "validator_status": validator_status,
            "queue_status": "OPEN_READY" if handoff_checks["queue_count_matches_findings"] and handoff_checks["all_queue_states_open"] else "DEGRADED",
            "all_stages_succeeded": all_stages_succeeded,
            "wrapper_exit_code": wrapper_exit_code,
        },
        "findings_summary": {
            "total_findings": handoff_checks["raw_findings_count"],
            "findings_with_trace": handoff_checks["findings_with_trace_count"],
            "raw_model_statuses": [a.get("raw_model_status") for a in assessments_list],
            "validated_statuses": [a.get("validated_status", a.get("status")) for a in assessments_list],
            "failure_kinds": [a.get("failure_kind") for a in assessments_list],
            "human_review_states": [r.get("state") for r in queue_all],
        },
        "ollama": {
            "enabled": not no_llm,
            "endpoint": endpoint if not no_llm else None,
            "requested_model": model if not no_llm else None,
            "runtime_origin": runtime_origin if not no_llm else "disabled",
            "tags_inventory": triage_summary.get("model_inventory"),
            "runtime_summary": triage_summary.get("runtime_summary"),
            "live_protocol_check": protocol_check,
        },
        "artifacts": {
            key: {"path": str(p), "sha256": artifact_hashes[key]}
            for key, p in artifact_paths.items()
        },
        "known_analysis_limits": KNOWN_ANALYSIS_LIMITS,
    }

    (output_dir / "g1-run-manifest.json").write_text(
        json.dumps(g1_manifest, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    cli_summary = {
        "g1_run_manifest": str(output_dir / "g1-run-manifest.json"),
        "review_db": str(triage_dir / "review.sqlite"),
        "scan_sha256": evidence_bundle.get("scan_sha256"),
        "prompt_contract": prompt_contract,
        "stage_statuses": g1_manifest["stage_statuses"],
        "findings_summary": g1_manifest["findings_summary"],
    }
    (output_dir / "g1-cli-summary.json").write_text(
        json.dumps(cli_summary, indent=2, ensure_ascii=True),
        encoding="utf-8",
    )
    print(json.dumps(cli_summary, indent=2, ensure_ascii=True))
    return wrapper_exit_code, g1_manifest


def run_review_command_from_cli(argv_tail: list[str]) -> int:
    """Delegate human review operations from inherited `semgrepai` CLI directly to `v2.triage.cli`."""
    with _forbid_implicit_scanner_rescan():
        return triage_cli.main(argv_tail)
