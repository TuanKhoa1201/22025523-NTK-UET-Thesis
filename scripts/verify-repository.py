#!/usr/bin/env python3
"""Kiem tra cau truc ban giao ma nguon, khong can trong so mo hinh."""
from __future__ import annotations
import ast
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

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

FORBIDDEN_DIR_RE = re.compile(
    r"(^|/)(node_modules|dist|__pycache__|checkpoints|private.repro|dataset_vnext_3_1|persisted_api_store|_advisor_sources)/",
    flags=re.I,
)

FORBIDDEN_PATH_RE = re.compile(
    r"(^|/)(node_modules|dist|__pycache__|checkpoints|private.repro|dataset_vnext_3_1|persisted_api_store|_advisor_sources)/"
    r"|\.(?:safetensors|gguf|ckpt|sqlite3?|db|pem|key|jsonl)$"
    r"|(^|/)config/ntk_backend\.env$",
    flags=re.I,
)

SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")

SENSITIVE_CONTENT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key_block", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("api_secret_token", re.compile(r"\bsk-[A-Za-z0-9\-_]{16,}\b|\bAIza[0-9A-Za-z\-_]{35}\b|\bAKIA[0-9A-Z]{16}\b")),
    ("auth_header", re.compile(r"\bAuthorization\s*:\s*(?:Bearer|Basic)\s+[A-Za-z0-9\-._~+/]+=*", flags=re.I)),
    (
        "credential_field",
        re.compile(
            r'"(?:api_key|apikey|secret_key|client_secret|access_token|refresh_token|private_key|password|passwd)"\s*:',
            flags=re.I,
        ),
    ),
    (
        "private_dataset_or_advisor_artifact",
        re.compile(
            r"(?:dataset_vnext_3_1|01_TRAIN_VNEXT|02_DEV_VNEXT|track_b_quarantine|private\.repro|_advisor_sources|Bo_ma_OpenGrep_Java_Qwen|opengrep-triage\.zip)",
            flags=re.I,
        ),
    ),
)

APPROVED_JSONL_POLICIES: dict[str, dict[str, Any]] = {
    "v2/demo/triage_qwen35_9b_smoke_m1_assessments.jsonl": {
        "kind": "smoke_replay_evidence",
        "max_bytes": 65_536,
        "max_rows": 10,
        "expected_scan_sha256": "005863f208b58de1195d252a9544fbcef53c53801281345328cf0aff32d4ccb4",
        "expected_source_path": "v2/evaluation/smoke_evidence/SmokeVulnSample.java",
    },
    "v2/evaluation/fixtures/codex_assessments.fixture.jsonl": {
        "kind": "codex_fixture",
        "max_bytes": 32_768,
        "max_rows": 25,
    },
    "v2/evaluation/fixtures/qwen_triage_outputs.fixture.jsonl": {
        "kind": "qwen_fixture",
        "max_bytes": 32_768,
        "max_rows": 25,
    },
}


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, val in pairs:
        if key in obj:
            raise ValueError(f"duplicate JSON key '{key}'")
        obj[key] = val
    return obj


def validate_approved_jsonl(
    file_path: Path,
    rel_path: str,
    policy: dict[str, Any] | None = None,
) -> list[str]:
    """Validate an allowlisted synthetic fixture or smoke replay JSONL file."""
    norm_rel = rel_path.replace("\\", "/")
    active_policy = policy or APPROVED_JSONL_POLICIES.get(norm_rel)
    if not active_policy:
        return [f"{norm_rel}: unapproved JSONL path"]

    if not file_path.is_file():
        return [f"{norm_rel}: approved JSONL file does not exist"]

    raw_bytes = file_path.read_bytes()
    size = len(raw_bytes)
    max_bytes = int(active_policy.get("max_bytes", 65_536))
    if size == 0:
        return [f"{norm_rel}: empty JSONL file is not allowed"]
    if size > max_bytes:
        return [f"{norm_rel}: file size {size} exceeds limit {max_bytes} bytes"]
    if raw_bytes.startswith(b"\xef\xbb\xbf"):
        return [f"{norm_rel}: UTF-8 BOM is not allowed in JSONL"]
    if b"\x00" in raw_bytes:
        return [f"{norm_rel}: null byte detected in JSONL"]

    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        return [f"{norm_rel}: invalid UTF-8 encoding ({exc})"]

    errors: list[str] = []
    for label, pattern in SENSITIVE_CONTENT_PATTERNS:
        if pattern.search(text):
            errors.append(f"{norm_rel}: sensitive or forbidden content pattern '{label}' detected")

    lines = text.splitlines()
    max_rows = int(active_policy.get("max_rows", 25))
    if not lines:
        errors.append(f"{norm_rel}: no JSONL rows found")
        return errors
    if len(lines) > max_rows:
        errors.append(f"{norm_rel}: row count {len(lines)} exceeds limit {max_rows}")
        return errors

    kind = str(active_policy.get("kind") or "")
    for idx, line in enumerate(lines, start=1):
        if not line.strip():
            errors.append(f"{norm_rel}:{idx}: blank line in JSONL")
            continue
        try:
            row = json.loads(line, object_pairs_hook=_reject_duplicate_keys)
        except Exception as exc:
            errors.append(f"{norm_rel}:{idx}: invalid JSONL row ({exc})")
            continue
        if not isinstance(row, dict):
            errors.append(f"{norm_rel}:{idx}: JSONL row must be a JSON object")
            continue

        if kind == "codex_fixture":
            if row.get("_fixture_notice") != "TEST_FIXTURE_ONLY":
                errors.append(f"{norm_rel}:{idx}: missing _fixture_notice='TEST_FIXTURE_ONLY'")
            if not isinstance(row.get("id"), str) or not row["id"].strip():
                errors.append(f"{norm_rel}:{idx}: missing non-empty string 'id'")
            if not isinstance(row.get("evidence"), dict):
                errors.append(f"{norm_rel}:{idx}: missing 'evidence' object")
            assessment = row.get("assessment")
            if not isinstance(assessment, dict) or assessment.get("status") not in {
                "SUPPORTED",
                "REFUTED",
                "UNDETERMINED",
            }:
                errors.append(f"{norm_rel}:{idx}: invalid 'assessment.status'")
        elif kind == "qwen_fixture":
            if row.get("_fixture_notice") != "TEST_FIXTURE_ONLY":
                errors.append(f"{norm_rel}:{idx}: missing _fixture_notice='TEST_FIXTURE_ONLY'")
            if not isinstance(row.get("alert_id"), str) or not row["alert_id"].strip():
                errors.append(f"{norm_rel}:{idx}: missing non-empty string 'alert_id'")
            if row.get("verdict") not in {"TP", "FP", "UNDETERMINED"}:
                errors.append(f"{norm_rel}:{idx}: invalid fixture 'verdict'")
            if not isinstance(row.get("cited_lines"), list):
                errors.append(f"{norm_rel}:{idx}: 'cited_lines' must be a list")
            sha = str(row.get("source_sha256") or "")
            if not SHA256_HEX_RE.match(sha):
                errors.append(f"{norm_rel}:{idx}: invalid 64-hex 'source_sha256'")
        elif kind == "smoke_replay_evidence":
            if row.get("schema_version") != "1.1":
                errors.append(f"{norm_rel}:{idx}: expected schema_version='1.1'")
            rid = str(row.get("id") or "")
            aid = str(row.get("alert_id") or "")
            if not SHA256_HEX_RE.match(rid) or rid != aid:
                errors.append(f"{norm_rel}:{idx}: invalid or mismatched 64-hex id/alert_id")
            expected_scan = str(active_policy.get("expected_scan_sha256") or "")
            if row.get("scan_sha256") != expected_scan:
                errors.append(f"{norm_rel}:{idx}: scan_sha256 does not match locked smoke scan")
            if row.get("state") != "OPEN":
                errors.append(f"{norm_rel}:{idx}: replay evidence state must remain 'OPEN'")
            ev = row.get("evidence")
            expected_path = str(active_policy.get("expected_source_path") or "")
            if not isinstance(ev, dict) or ev.get("path") != expected_path:
                errors.append(f"{norm_rel}:{idx}: evidence.path must equal '{expected_path}'")
            assessment = row.get("assessment")
            if not isinstance(assessment, dict):
                errors.append(f"{norm_rel}:{idx}: missing 'assessment' object")
            else:
                if assessment.get("status") not in {"SUPPORTED", "REFUTED", "UNDETERMINED"}:
                    errors.append(f"{norm_rel}:{idx}: invalid assessment.status")
                if assessment.get("requires_human_review") is not True:
                    errors.append(f"{norm_rel}:{idx}: requires_human_review must be True")
                if assessment.get("security_conclusion_verified") is not False:
                    errors.append(f"{norm_rel}:{idx}: security_conclusion_verified must be False")
        else:
            errors.append(f"{norm_rel}:{idx}: unknown JSONL policy kind '{kind}'")

    return errors


def evaluate_tracked_paths(tracked_paths: list[str], root: Path = ROOT) -> list[str]:
    """Return list of policy violation descriptions for git-tracked paths."""
    violations: list[str] = []
    for raw_name in tracked_paths:
        if not raw_name:
            continue
        name = raw_name.replace("\\", "/")
        if not FORBIDDEN_PATH_RE.search(name):
            continue

        # Any file inside a forbidden directory is unconditionally rejected.
        if FORBIDDEN_DIR_RE.search(name):
            violations.append(name)
            continue

        # Only exact allowlisted synthetic/replay .jsonl paths may undergo content verification.
        if name.lower().endswith(".jsonl") and name in APPROVED_JSONL_POLICIES:
            jsonl_errors = validate_approved_jsonl(
                root / name, name, APPROVED_JSONL_POLICIES[name]
            )
            if jsonl_errors:
                violations.extend(jsonl_errors)
            continue

        violations.append(name)
    return violations


def main() -> int:
    missing = [p.relative_to(ROOT).as_posix() for p in REQUIRED if not p.is_file()]
    if missing:
        raise SystemExit("Thieu tep: " + ", ".join(missing))
    pyfiles = sorted((BACKEND / "scripts").glob("*.py"))
    pyfiles += sorted((BACKEND / "tests").glob("test_*.py"))
    v2_dir = ROOT / "v2"
    if v2_dir.is_dir():
        pyfiles += sorted(
            p
            for p in v2_dir.rglob("*.py")
            if not any(part in ("__pycache__", ".pytest_cache", ".venv") for part in p.parts)
        )
    for file in pyfiles:
        ast.parse(file.read_text(encoding="utf-8-sig"), filename=str(file))
    manifests = []
    for p in ROOT.rglob("*.json"):
        if any(
            part in (".git", "node_modules", "dist", ".venv", "__pycache__", ".pytest_cache", "_advisor_sources")
            for part in p.parts
        ):
            continue
        if p.stat().st_size < 2_000_000:
            json.loads(p.read_text(encoding="utf-8-sig"))
            manifests.append(p.relative_to(ROOT).as_posix())
    tracked = subprocess.check_output(
        ["git", "-C", str(ROOT), "ls-files", "-z"], text=False
    ).decode("utf-8").split("\0")
    bad = evaluate_tracked_paths(tracked, root=ROOT)
    if bad:
        raise SystemExit("Tep khong duoc phep theo doi: " + ", ".join(bad))
    print(f"PASS: {len(REQUIRED)} tep bat buoc, {len(pyfiles)} module Python, "
          f"{len(manifests)} JSON hop le, {len(APPROVED_JSONL_POLICIES)} JSONL fixture/replay da xac minh, "
          f"khong co artifact rieng trong git index.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
