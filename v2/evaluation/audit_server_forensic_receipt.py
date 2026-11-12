"""Independent Server Forensic Audit for Post-Report CWE-22 & CWE-89 Evidence.

NOTE: This is a newly created independent audit script (`audit_server_forensic_receipt.py`),
distinct from the historical Javis Brain `scripts/ground_truth_verifier.py`.
It operates strictly READ-ONLY on historical worktrees and evidence roots, writing all
deliverables exclusively to an external audit directory (`server_forensic_audit_20261112`).
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

EVAL_DIR = Path(__file__).resolve().parent
REPO_ROOT = EVAL_DIR.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(EVAL_DIR) not in sys.path:
    sys.path.insert(0, str(EVAL_DIR))

from v2.evaluation import score_pilot, validate_pilot_lock
from v2.evaluation.server_forensic_helpers import (
    compute_contract_alert_id,
    inspect_sqlite_readonly_copy,
    load_owasp_expected_csv,
    normalize_cwe,
    read_zip_member_sha256,
    scan_json_for_forbidden_label_keys,
    sha256_bytes,
    sha256_file,
    sha256_lf_text,
    summarize_latencies_ms,
)
from v2.triage import ollama as triage_ollama
from v2.triage.scan_receipt import verify_receipt

EXPECTED_SCAN_SHAS = {
    "stage1_dev_set_16_scan": "ecc1fa4634bfc86266c43dd6790422546367293d1810712fddc7c0d15a6c015f",
    "stage1_heldout_set_40_scan": "67c3b04903e75f4bd7294cb17452d0dcb2b6d56244330cec485c4422efabfa8b",
    "stage5_real_projects_scan": "99d2445c218030fb10082176c299bc328eeb62c6b23c7ab745cffd824f31f041",
}

EXPECTED_BENCHMARK_COMMIT = "8b67a88d73b2594570fc21150705283de884620b"
EXPECTED_WEBGOAT_COMMIT = "5357a65e054976cd7d79b81ef3906ded050ed921"
EXPECTED_JAVASECCODE_COMMIT = "4711f4e186258c6e0dd5c3863e7c9592e7e9026a"
EXPECTED_OWASP_CSV_SHA = "1809f6a690c6cf7dd6685df6ebe2eef8fe3ca93d19a7ca0ce45987ca4f5d78e1"
EXPECTED_ADVISOR_ZIP_SHA = "5f39d2fb84bbc50e63b0b2b0c4618f84d7878bab1458cc99377223ee9c31b1cd"

REAL_PROJECT_MANUAL_LABELS: dict[int, dict[str, Any]] = {
    0: {"label": "TRUE_POSITIVE", "locus": "WebGoat/Assignment5.java:login_sql", "confidence": "HIGH"},
    1: {"label": "TRUE_POSITIVE", "locus": "WebGoat/Assignment5.java:login_sql", "confidence": "HIGH"},
    2: {"label": "TRUE_POSITIVE", "locus": "WebGoat/ProfileUploadRetrieval.java:catPicture", "confidence": "HIGH"},
    3: {"label": "TRUE_POSITIVE", "locus": "WebGoat/Servers.java:sort_order_by", "confidence": "HIGH"},
    4: {"label": "TRUE_POSITIVE", "locus": "WebGoat/SqlInjectionLesson5a.java:injectableQuery", "confidence": "HIGH"},
    5: {"label": "TRUE_POSITIVE", "locus": "WebGoat/SqlInjectionLesson5a.java:injectableQuery", "confidence": "HIGH"},
    6: {"label": "TRUE_POSITIVE", "locus": "WebGoat/SqlInjectionLesson8.java:injectableQueryConfidentiality", "confidence": "HIGH"},
    7: {"label": "TRUE_POSITIVE", "locus": "WebGoat/SqlInjectionLesson8.java:injectableQueryConfidentiality", "confidence": "HIGH"},
    8: {
        "label": "FALSE_POSITIVE",
        "locus": "WebGoat/SqlInjectionLesson8.java:log_insert",
        "confidence": "MEDIUM",
        "independent_evidence": (
            "Line 148 executes action = action.replace('\\'', '\"') prior to single-quoted HSQLDB literal "
            "INSERT at lines 154/158. In WebGoat's default HSQLDB dialect (standard SQL quoting without MySQL "
            "backslash-escape), single-quote breakout is neutralized; however, String.replace is dialect-specific "
            "defense rather than PreparedStatement parameterization."
        ),
    },
    9: {
        "label": "FALSE_POSITIVE",
        "locus": "WebGoat/SqlInjectionLesson8.java:log_insert",
        "confidence": "MEDIUM",
        "independent_evidence": (
            "Paired executeUpdate sink at line 158 consuming logQuery built at line 154 after line 148 "
            "action.replace('\\'', '\"'). Unexploitable in default HSQLDB lesson context, though non-parameterized."
        ),
    },
    10: {
        "label": "FALSE_POSITIVE",
        "locus": "WebGoat/UserService.java:createLessonsForUser",
        "confidence": "MEDIUM_LOW",
        "independent_evidence": (
            "Line 52 concatenates webGoatUser.getUsername() into CREATE SCHEMA \"...\" authorization dba. "
            "Form registration (RegistrationController.registration -> @Valid UserForm, UserForm.java:20) enforces "
            "@Pattern(regexp = \"[a-z0-9-]*\"), preventing quote injection on /register.mvc. However, note two "
            "forensic nuances: (1) Stage 5/7 prose docs misattributed @Pattern to WebGoatUser.java instead of "
            "UserForm.java; (2) RegistrationController.registrationOAUTH (line 54) calls userService.addUser("
            "authentication.getName(), ...) without UserForm validation, making safety caller-dependent."
        ),
    },
    11: {"label": "TRUE_POSITIVE", "locus": "demo/UserDao.java:findUnsafe", "confidence": "HIGH"},
    12: {"label": "TRUE_POSITIVE", "locus": "demo/UserDao.java:findUnsafe", "confidence": "HIGH"},
    13: {"label": "TRUE_POSITIVE", "locus": "demo/UserDao.java:findViaHelper_runQuery", "confidence": "HIGH"},
    14: {"label": "TRUE_POSITIVE", "locus": "demo/UserDao.java:findViaHelper_runQuery", "confidence": "HIGH"},
    15: {
        "label": "FALSE_POSITIVE",
        "locus": "demo/UserDao.java:open_canonical_guard",
        "confidence": "HIGH",
        "independent_evidence": (
            "Line 63 constructs File f = new File(BASE_DIR + fileName) with BASE_DIR = \"/var/app/files/\" "
            "(trailing slash prevents sibling-prefix bypass), performs zero filesystem I/O before line 64 "
            "if (!f.getCanonicalPath().startsWith(BASE_DIR)) throw new IOException(\"blocked\"), and only returns "
            "f at line 67 if canonical prefix check passes."
        ),
    },
    16: {"label": "TRUE_POSITIVE", "locus": "java-sec-code/SQLI.java:jdbc_sqli_vul", "confidence": "HIGH"},
    17: {"label": "TRUE_POSITIVE", "locus": "java-sec-code/SQLI.java:jdbc_sqli_vul", "confidence": "HIGH"},
    18: {"label": "TRUE_POSITIVE", "locus": "java-sec-code/SQLI.java:jdbc_ps_vuln", "confidence": "HIGH"},
    19: {"label": "TRUE_POSITIVE", "locus": "java-sec-code/SQLI.java:jdbc_ps_vuln", "confidence": "HIGH"},
}


def now_iso() -> str:
    return dt.datetime.now(dt.timezone(dt.timedelta(hours=7))).isoformat(timespec="seconds")


def build_file_inventory(evidence_root: Path, worktree_root: Path) -> dict[str, Any]:
    ev_files: list[dict[str, Any]] = []
    for p in sorted(evidence_root.rglob("*")):
        if p.is_file():
            raw = p.read_bytes()
            st = p.stat()
            ev_files.append(
                {
                    "scope": "evidence_root",
                    "rel_path": p.relative_to(evidence_root).as_posix(),
                    "size_bytes": st.st_size,
                    "mtime_ns": st.st_mtime_ns,
                    "sha256": sha256_bytes(raw),
                    "lf_sha256": sha256_lf_text(raw),
                }
            )

    wt_files: list[dict[str, Any]] = []
    for sub in ("v2/evaluation/post_report", "v2/docs"):
        base = worktree_root / sub
        if not base.exists():
            continue
        for p in sorted(base.rglob("*")):
            if p.is_file():
                raw = p.read_bytes()
                st = p.stat()
                wt_files.append(
                    {
                        "scope": "worktree_post_report_and_docs",
                        "rel_path": p.relative_to(worktree_root).as_posix(),
                        "size_bytes": st.st_size,
                        "mtime_ns": st.st_mtime_ns,
                        "sha256": sha256_bytes(raw),
                        "lf_sha256": sha256_lf_text(raw),
                    }
                )

    return {
        "generated_at": now_iso(),
        "evidence_root": str(evidence_root),
        "evidence_file_count": len(ev_files),
        "worktree_root": str(worktree_root),
        "worktree_checked_file_count": len(wt_files),
        "evidence_files": ev_files,
        "worktree_files": wt_files,
    }


def query_wsl_upstream_hashes(evidence_root: Path) -> dict[str, Any]:
    """Verify WSL upstream git commits and file-for-file SHA-256 matches."""
    dev_names = sorted(p.name for p in (evidence_root / "sources" / "dev_set_16").glob("*.java"))
    held_names = sorted(p.name for p in (evidence_root / "sources" / "heldout_set_40").glob("*.java"))

    bash_script = """
set -e
python3 - <<'PY'
import hashlib, json, subprocess
from pathlib import Path

def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def git_info(repo):
    head = subprocess.check_output(["git", "-C", repo, "rev-parse", "HEAD"], text=True).strip()
    status = subprocess.check_output(["git", "-C", repo, "status", "--porcelain"], text=True).strip()
    return {"head": head, "clean": status == "", "status_lines": status.splitlines() if status else []}

bm_root = Path("/home/tuankhoa/migration/ntk_ft211_sources/BenchmarkJava")
wg_root = Path("/home/tuankhoa/iris/data/project-sources/WebGoat")
jsc_root = Path("/home/tuankhoa/migration/ntk_ft211_sources/java-sec-code")

bm_testcode = bm_root / "src/main/java/org/owasp/benchmark/testcode"
wg_files = {
    "WebGoat/ProfileUploadRetrieval.java": wg_root / "src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUploadRetrieval.java",
    "WebGoat/UserService.java": wg_root / "src/main/java/org/owasp/webgoat/container/users/UserService.java",
    "WebGoat/Assignment5.java": wg_root / "src/main/java/org/owasp/webgoat/lessons/challenges/challenge5/Assignment5.java",
    "WebGoat/SqlInjectionLesson5a.java": wg_root / "src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson5a.java",
    "WebGoat/SqlInjectionLesson8.java": wg_root / "src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson8.java",
    "WebGoat/Servers.java": wg_root / "src/main/java/org/owasp/webgoat/lessons/sqlinjection/mitigation/Servers.java",
}
out = {
    "BenchmarkJava": git_info(str(bm_root)),
    "WebGoat": git_info(str(wg_root)),
    "java_sec_code": git_info(str(jsc_root)),
    "expectedresults_csv_sha256": sha(bm_root / "expectedresults-1.2.csv"),
    "p_java_raw_yaml_sha256": sha("/home/tuankhoa/migration/phase8a_opengrep_baseline_cache_decision_v1_20260929/current_pinned_ruleset_evidence/p-java.raw.yaml"),
    "wsl_opengrep_usr_local_sha256": sha("/usr/local/bin/opengrep") if Path("/usr/local/bin/opengrep").exists() else None,
    "wsl_opengrep_home_local_sha256": sha("/home/tuankhoa/.local/bin/opengrep") if Path("/home/tuankhoa/.local/bin/opengrep").exists() else None,
    "wsl_opengrep_cli_latest_exists": Path("/home/tuankhoa/.opengrep/cli/latest/opengrep").exists(),
    "benchmark_java_shas": {},
    "real_project_shas": {},
}
for p in sorted(bm_testcode.glob("BenchmarkTest*.java")):
    out["benchmark_java_shas"][p.name] = sha(p)
for k, p in wg_files.items():
    out["real_project_shas"][k] = sha(p)
out["real_project_shas"]["java-sec-code/SQLI.java"] = sha(jsc_root / "src/main/java/org/joychou/controller/SQLI.java")
print(json.dumps(out))
PY
"""
    proc = subprocess.run(
        ["wsl.exe", "-d", "Ubuntu-IRIS", "-e", "bash", "-lc", bash_script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )
    if proc.returncode != 0:
        return {"ok": False, "returncode": proc.returncode, "stderr": proc.stderr}
    data = json.loads(proc.stdout.strip())

    # Compare dev_16 and heldout_40 and real_projects against WSL upstream
    dev_mismatches = []
    for name in dev_names:
        local_sha = sha256_file(evidence_root / "sources" / "dev_set_16" / name)
        wsl_sha = data["benchmark_java_shas"].get(name)
        if local_sha != wsl_sha:
            dev_mismatches.append({"file": name, "local": local_sha, "wsl": wsl_sha})

    held_mismatches = []
    for name in held_names:
        local_sha = sha256_file(evidence_root / "sources" / "heldout_set_40" / name)
        wsl_sha = data["benchmark_java_shas"].get(name)
        if local_sha != wsl_sha:
            held_mismatches.append({"file": name, "local": local_sha, "wsl": wsl_sha})

    real_mismatches = []
    for rel_key, wsl_sha in data["real_project_shas"].items():
        local_sha = sha256_file(evidence_root / "sources" / "real_projects" / rel_key)
        if local_sha != wsl_sha:
            real_mismatches.append({"file": rel_key, "local": local_sha, "wsl": wsl_sha})

    return {
        "ok": True,
        "BenchmarkJava": data["BenchmarkJava"],
        "WebGoat": data["WebGoat"],
        "java_sec_code": data["java_sec_code"],
        "expectedresults_csv_sha256": data["expectedresults_csv_sha256"],
        "p_java_raw_yaml_sha256": data["p_java_raw_yaml_sha256"],
        "wsl_opengrep_usr_local_sha256": data["wsl_opengrep_usr_local_sha256"],
        "wsl_opengrep_home_local_sha256": data["wsl_opengrep_home_local_sha256"],
        "wsl_opengrep_cli_latest_exists": data["wsl_opengrep_cli_latest_exists"],
        "dev_set_16_upstream_exact_matches": len(dev_names) - len(dev_mismatches),
        "dev_set_16_upstream_mismatches": dev_mismatches,
        "heldout_set_40_upstream_exact_matches": len(held_names) - len(held_mismatches),
        "heldout_set_40_upstream_mismatches": held_mismatches,
        "real_projects_7_wsl_exact_matches": len(data["real_project_shas"]) - len(real_mismatches),
        "real_projects_wsl_mismatches": real_mismatches,
    }


def audit_opengrep_scans(
    evidence_root: Path,
    worktree_root: Path,
    advisor_zip_path: Path | None,
    wsl_info: dict[str, Any],
) -> dict[str, Any]:
    rules_path = worktree_root / "v2" / "evaluation" / "post_report" / "rules" / "p_java_cwe22_cwe89.yml"
    rules_sha = sha256_file(rules_path)
    rules_doc = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
    rules_list = rules_doc.get("rules", []) if isinstance(rules_doc, dict) else []
    rule_ids = [r.get("id") for r in rules_list if isinstance(r, dict)]

    userdao_zip_check = (
        read_zip_member_sha256(advisor_zip_path, "examples/demo/src/main/java/demo/UserDao.java")
        if advisor_zip_path is not None and advisor_zip_path.is_file()
        else {"skipped": True}
    )
    local_userdao_sha = sha256_file(
        evidence_root / "sources" / "real_projects" / "demo" / "UserDao.java"
    )
    local_userdao_lf_sha = sha256_lf_text(
        (evidence_root / "sources" / "real_projects" / "demo" / "UserDao.java").read_bytes()
    )

    scan_Targets = [
        ("stage1_dev_set_16_scan", evidence_root / "sources" / "dev_set_16", 16),
        ("stage1_heldout_set_40_scan", evidence_root / "sources" / "heldout_set_40", 40),
        ("stage5_real_projects_scan", evidence_root / "sources" / "real_projects", 8),
    ]

    scans_report: list[dict[str, Any]] = []
    for run_name, src_dir, expected_src_files in scan_Targets:
        run_dir = evidence_root / "runs" / run_name
        og_path = run_dir / "opengrep.json"
        raw_bytes = og_path.read_bytes()
        actual_sha = sha256_bytes(raw_bytes)
        expected_sha = EXPECTED_SCAN_SHAS[run_name]
        og_doc = json.loads(raw_bytes.decode("utf-8"))

        results = og_doc.get("results", [])
        errors = og_doc.get("errors", [])
        paths_obj = og_doc.get("paths", {})
        scanned_paths = paths_obj.get("scanned", []) if isinstance(paths_obj, dict) else []
        skipped_paths = paths_obj.get("skipped", []) if isinstance(paths_obj, dict) else []

        findings_with_trace = 0
        cwe_counts: dict[str, int] = {}
        rule_hit_counts: dict[str, int] = {}
        for r in results:
            extra = r.get("extra", {}) if isinstance(r.get("extra"), dict) else {}
            if isinstance(extra.get("dataflow_trace"), dict):
                dt_obj = extra["dataflow_trace"]
                if dt_obj.get("taint_source") and dt_obj.get("taint_sink"):
                    findings_with_trace += 1
            meta = extra.get("metadata", {}) if isinstance(extra.get("metadata"), dict) else {}
            cwe = normalize_cwe(meta.get("cwe"))
            cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
            cid = str(r.get("check_id") or "")
            rule_hit_counts[cid] = rule_hit_counts.get(cid, 0) + 1

        manifest_path = run_dir / "scan-manifest.json"
        m_doc = json.loads(manifest_path.read_text(encoding="utf-8"))
        m_sha = sha256_file(manifest_path)
        receipt_meta, receipt_issues = verify_receipt(manifest_path, raw_bytes, src_dir)

        sources_before = m_doc.get("sources_before") or {}
        sources_after = m_doc.get("sources_after") or {}
        sources_unchanged_during_scan = (
            isinstance(sources_before, dict)
            and len(sources_before) == expected_src_files
            and sources_before == sources_after
        )

        # Verify disk source files match sources_after
        disk_source_map = {
            p.relative_to(src_dir).as_posix(): sha256_file(p)
            for p in sorted(src_dir.rglob("*.java"))
        }
        disk_matches_manifest = disk_source_map == sources_after

        rules_before_sha = m_doc.get("rules_before_sha256")
        rules_after_sha = m_doc.get("rules_after_sha256")
        rules_snapshot_path = run_dir / "rules.snapshot.yml"
        rules_snapshot_sha = sha256_file(rules_snapshot_path) if rules_snapshot_path.is_file() else None

        json_cmd_path = run_dir / "json.command.json"
        json_cmd = json.loads(json_cmd_path.read_text(encoding="utf-8")) if json_cmd_path.is_file() else None
        json_stderr = (run_dir / "json.stderr.txt").read_text(encoding="utf-8", errors="replace").strip() if (run_dir / "json.stderr.txt").is_file() else ""
        ver_stdout = (run_dir / "version.stdout.txt").read_text(encoding="utf-8", errors="replace").strip() if (run_dir / "version.stdout.txt").is_file() else ""

        scans_report.append(
            {
                "run_name": run_name,
                "opengrep_json_path": str(og_path),
                "size_bytes": len(raw_bytes),
                "expected_sha256": expected_sha,
                "actual_sha256": actual_sha,
                "sha256_matched": actual_sha == expected_sha,
                "opengrep_version_in_json": og_doc.get("version"),
                "version_stdout": ver_stdout,
                "findings_count": len(results),
                "findings_with_complete_dataflow_trace": findings_with_trace,
                "cwe_distribution": cwe_counts,
                "rule_hit_counts": rule_hit_counts,
                "scan_errors_count": len(errors),
                "scan_errors": errors,
                "paths_scanned_count": len(scanned_paths),
                "paths_skipped_count": len(skipped_paths),
                "paths_skipped": skipped_paths,
                "command_record": json_cmd,
                "stderr_excerpt": json_stderr[:500],
                "manifest_sha256": m_sha,
                "manifest_schema": m_doc.get("schema"),
                "manifest_producer": m_doc.get("producer"),
                "manifest_signed_or_independently_attested": m_doc.get("signed_or_independently_attested"),
                "verify_receipt_meta": receipt_meta,
                "verify_receipt_issues": receipt_issues,
                "sources_count_recorded": len(sources_before),
                "sources_unchanged_before_after": sources_unchanged_during_scan,
                "disk_sources_match_manifest": disk_matches_manifest,
                "rules_before_sha256": rules_before_sha,
                "rules_after_sha256": rules_after_sha,
                "rules_unchanged_before_after": (
                    rules_before_sha is not None
                    and rules_before_sha == rules_after_sha == rules_sha
                ),
                "rules_snapshot_sha256": rules_snapshot_sha,
                "rules_snapshot_matches_repo_yaml": rules_snapshot_sha == rules_sha,
            }
        )

    # Also check full benchmark scan artifact in runs/stage1_full_benchmark_cwe22_cwe89
    full_bm_dir = evidence_root / "runs" / "stage1_full_benchmark_cwe22_cwe89"
    full_bm_info: dict[str, Any] = {"present": full_bm_dir.is_dir()}
    if full_bm_dir.is_dir():
        for fname in ("opengrep.json", "opengrep_raw.json", "opengrep_raw.sarif", "p_java_cwe22_cwe89_subset.yaml"):
            fp = full_bm_dir / fname
            if fp.is_file():
                full_bm_info[fname] = {
                    "size_bytes": fp.stat().st_size,
                    "sha256": sha256_file(fp),
                }

    return {
        "generated_at": now_iso(),
        "pinned_ruleset": {
            "path": str(rules_path),
            "sha256": rules_sha,
            "rule_count": len(rules_list),
            "rule_ids": rule_ids,
        },
        "upstream_provenance": {
            "wsl_verification": wsl_info,
            "advisor_zip_sha256": (
                sha256_file(advisor_zip_path)
                if advisor_zip_path is not None and advisor_zip_path.is_file()
                else None
            ),
            "advisor_zip_expected_sha256": EXPECTED_ADVISOR_ZIP_SHA,
            "userdao_in_advisor_zip": userdao_zip_check,
            "userdao_in_evidence_sources_sha256": local_userdao_sha,
            "userdao_in_evidence_sources_lf_sha256": local_userdao_lf_sha,
            "userdao_exact_or_lf_match": (
                userdao_zip_check.get("sha256") == local_userdao_sha
                or userdao_zip_check.get("lf_sha256") == local_userdao_lf_sha
            ),
        },
        "three_primary_scans": scans_report,
        "full_benchmark_auxiliary_scan": full_bm_info,
    }


def _resolve_source_root_for_run(run_name: str, evidence_root: Path) -> Path:
    if "dev16" in run_name:
        return evidence_root / "sources" / "dev_set_16"
    if "heldout40" in run_name:
        return evidence_root / "sources" / "heldout_set_40"
    if "real_projects" in run_name:
        return evidence_root / "sources" / "real_projects"
    raise ValueError(f"Cannot infer source_root for run {run_name}")


def _load_ground_truth_for_run(run_name: str, worktree_root: Path, scan_sha: str) -> dict[str, str]:
    post_dir = worktree_root / "v2" / "evaluation" / "post_report"
    if "dev16" in run_name:
        doc = json.loads((post_dir / "labels_development.json").read_text(encoding="utf-8"))
        return {item["alert_id"]: item["ground_truth"] for item in doc["labels"]}
    if "heldout40" in run_name:
        doc = json.loads((post_dir / "labels_heldout.json").read_text(encoding="utf-8"))
        return {item["alert_id"]: item["ground_truth"] for item in doc["labels"]}
    if "real_projects" in run_name:
        return {
            compute_contract_alert_id(scan_sha, idx): meta["label"]
            for idx, meta in REAL_PROJECT_MANUAL_LABELS.items()
        }
    return {}


def audit_all_10_assessments(
    evidence_root: Path,
    worktree_root: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    runs_dir = evidence_root / "runs"
    ckpt_dir = evidence_root / "checkpoints"

    # Load all checkpoint files first
    checkpoints_by_run: dict[str, dict[str, dict[str, Any]]] = {}
    checkpoint_summaries: list[dict[str, Any]] = []
    if ckpt_dir.is_dir():
        for cp in sorted(ckpt_dir.glob("*.ckpt.jsonl")):
            run_key = cp.name[: -len(".ckpt.jsonl")]
            lines = [ln for ln in cp.read_text(encoding="utf-8").splitlines() if ln.strip()]
            parsed_map: dict[str, dict[str, Any]] = {}
            malformed_ckpt = 0
            for ln in lines:
                try:
                    obj = json.loads(ln)
                    parsed_map[str(obj.get("id"))] = obj
                except Exception:
                    malformed_ckpt += 1
            checkpoints_by_run[run_key] = parsed_map
            checkpoint_summaries.append(
                {
                    "checkpoint_file": cp.name,
                    "run_name": run_key,
                    "size_bytes": cp.stat().st_size,
                    "sha256": sha256_file(cp),
                    "line_count": len(lines),
                    "unique_ids": len(parsed_map),
                    "malformed_lines": malformed_ckpt,
                }
            )

    assessment_dirs = sorted(
        d for d in runs_dir.iterdir() if d.is_dir() and (d / "assessments.jsonl").is_file()
    )

    runs_audit: list[dict[str, Any]] = []
    comparison_rows: list[dict[str, Any]] = []

    for rdir in assessment_dirs:
        run_name = rdir.name
        aj_path = rdir / "assessments.jsonl"
        in_og_path = rdir / "input.opengrep.json"
        ev_json_path = rdir / "evidence.json"
        sq_path = rdir / "review.sqlite"

        src_root = _resolve_source_root_for_run(run_name, evidence_root)
        raw_scan_bytes = in_og_path.read_bytes()
        input_scan_sha = sha256_bytes(raw_scan_bytes)
        og_doc = json.loads(raw_scan_bytes.decode("utf-8"))
        og_results = og_doc.get("results", [])

        gt_map = _load_ground_truth_for_run(run_name, worktree_root, input_scan_sha)
        ckpt_map = checkpoints_by_run.get(run_name, {})

        raw_lines = [ln for ln in aj_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        malformed_lines = 0
        records: list[dict[str, Any]] = []
        for idx_ln, ln in enumerate(raw_lines, start=1):
            try:
                records.append(json.loads(ln))
            except Exception:
                malformed_lines += 1

        # Per-record forensic counters
        alert_id_matches = 0
        scan_sha_matches = 0
        transport_counts: dict[str, int] = {}
        model_counts: dict[str, int] = {}
        raw_response_present = 0
        substantive_raw_content = 0
        done_true_count = 0
        done_reasons: dict[str, int] = {}
        response_json_sha_verified = 0
        request_payload_sha_present = 0
        request_payload_matches_current_v2_1_code = 0
        literal_prompt_saved_count = 0
        forbidden_gt_leak_hits: list[str] = []
        heuristic_signals_present_count = 0
        heuristic_recommended_status_present_count = 0
        heuristic_candidate_citations_present_count = 0
        evidence_signals_passed_to_llm_count = 0
        source_snapshot_sha_verified = 0
        trace_locations_verified = 0
        citations_verified_against_disk = 0
        handling_breakdown: dict[str, int] = {}
        raw_status_counts: dict[str, int] = {}
        post_status_counts: dict[str, int] = {}
        concordance_heur_vs_raw_qwen = 0
        concordance_heur_vs_gt = 0
        ckpt_exact_timestamp_matches = 0
        latencies_ms: list[float] = []
        eval_counts: list[int] = []
        anomalies: list[str] = []

        for idx, rec in enumerate(records):
            expected_aid = compute_contract_alert_id(input_scan_sha, idx)
            rec_id = str(rec.get("id") or rec.get("alert_id") or "")
            if rec_id == expected_aid and rec.get("alert_id") == expected_aid:
                alert_id_matches += 1
            else:
                anomalies.append(f"Row {idx}: id={rec_id} != expected {expected_aid}")

            ev = rec.get("evidence") if isinstance(rec.get("evidence"), dict) else {}
            ass = rec.get("assessment") if isinstance(rec.get("assessment"), dict) else {}
            rt = ass.get("runtime") if isinstance(ass.get("runtime"), dict) else {}

            if rec.get("scan_sha256") == input_scan_sha and ev.get("scan_sha256") == input_scan_sha:
                scan_sha_matches += 1
            else:
                anomalies.append(f"Row {idx}: scan_sha256 mismatch")

            # Check prompt storage
            if any(k in ass or k in rt or k in rec for k in ("prompt", "messages", "request_body", "raw_request")):
                literal_prompt_saved_count += 1

            # Check forbidden label leakage in evidence
            leaks = scan_json_for_forbidden_label_keys(ev)
            if leaks:
                forbidden_gt_leak_hits.extend(f"row[{idx}]:{x}" for x in leaks)

            triage_mode = str(
                ev.get("triage_mode")
                or ("heuristic" if ass.get("transport") in ("heuristic", "heuristic-only") else "v1.0_or_default")
            )
            hs = ev.get("heuristic_signals")
            heur_rec_status = None
            if isinstance(hs, dict):
                heuristic_signals_present_count += 1
                if "recommended_status" in hs:
                    heuristic_recommended_status_present_count += 1
                    heur_rec_status = str(hs.get("recommended_status"))
                if "candidate_citations" in hs and isinstance(hs.get("candidate_citations"), list):
                    heuristic_candidate_citations_present_count += 1

            transport = str(ass.get("transport") or "NONE")
            if transport == "ollama-http" and triage_mode != "llm" and isinstance(hs, dict):
                evidence_signals_passed_to_llm_count += 1
            transport_counts[transport] = transport_counts.get(transport, 0) + 1
            model_name = str(ass.get("model") or "NONE")
            model_counts[model_name] = model_counts.get(model_name, 0) + 1

            elapsed_s = ass.get("elapsed_seconds")
            if isinstance(elapsed_s, (int, float)):
                latencies_ms.append(float(elapsed_s) * 1000.0)

            # Inspect raw_response
            raw_resp = ass.get("raw_response")
            raw_qwen_status = "NO_LLM_CALL"
            raw_qwen_cites_count = 0
            raw_parse_error = None
            if isinstance(raw_resp, dict):
                raw_response_present += 1
                if raw_resp.get("done") is True:
                    done_true_count += 1
                dr = str(raw_resp.get("done_reason") or "UNKNOWN")
                done_reasons[dr] = done_reasons.get(dr, 0) + 1
                if isinstance(raw_resp.get("eval_count"), int):
                    eval_counts.append(int(raw_resp["eval_count"]))

                # Verify response_json_sha256
                recomputed_resp_sha = sha256_bytes(
                    json.dumps(raw_resp, sort_keys=True, ensure_ascii=False, allow_nan=False).encode("utf-8")
                )
                if rt.get("response_json_sha256") == recomputed_resp_sha:
                    response_json_sha_verified += 1
                else:
                    anomalies.append(f"Row {idx}: response_json_sha256 mismatch")

                msg_content = (raw_resp.get("message") or {}).get("content")
                if isinstance(msg_content, str) and len(msg_content.strip()) > 10:
                    substantive_raw_content += 1
                    try:
                        parsed_ans = json.loads(msg_content)
                        raw_qwen_status = str(parsed_ans.get("status") or "MISSING_STATUS")
                        raw_qwen_cites_count = len(parsed_ans.get("citations") or [])
                    except Exception as exc:
                        raw_qwen_status = "RAW_JSON_PARSE_ERROR"
                        raw_parse_error = str(exc)

            if rt.get("request_payload_sha256"):
                request_payload_sha_present += 1
                try:
                    rebuilt_payload = triage_ollama.request_payload(ev, model_name)
                    rebuilt_sha = sha256_bytes(json.dumps(rebuilt_payload).encode("utf-8"))
                    if rebuilt_sha == rt.get("request_payload_sha256"):
                        request_payload_matches_current_v2_1_code += 1
                except Exception:
                    pass

            post_status = str(ass.get("status") or "MISSING")
            raw_status_counts[raw_qwen_status] = raw_status_counts.get(raw_qwen_status, 0) + 1
            post_status_counts[post_status] = post_status_counts.get(post_status, 0) + 1

            # Determine handling path
            downgrade_reason = ""
            if transport in ("heuristic", "heuristic-only"):
                handling_path = "HEURISTIC_DETERMINISTIC_NO_LLM"
            elif raw_resp is None:
                ev_issues = ev.get("issues") or []
                handling_path = "PRE_LLM_EVIDENCE_GUARD_FALLBACK"
                downgrade_reason = "; ".join(str(x) for x in ev_issues) or str(ass.get("explanation") or "")
            elif raw_parse_error:
                handling_path = "POST_LLM_JSON_PARSE_DOWNGRADE"
                downgrade_reason = raw_parse_error
            elif raw_qwen_status != post_status:
                handling_path = "POST_LLM_VALIDATOR_DOWNGRADE"
                downgrade_reason = str(ass.get("explanation") or "")
            else:
                handling_path = "MODEL_LIVE_HTTP_ACCEPTED"
            handling_breakdown[handling_path] = handling_breakdown.get(handling_path, 0) + 1

            # Compare with checkpoint if present
            if rec_id in ckpt_map:
                ckpt_ass = ckpt_map[rec_id].get("assessment") or {}
                if ckpt_ass.get("analyzed_at") == ass.get("analyzed_at"):
                    ckpt_exact_timestamp_matches += 1

            # Verify source snapshot SHA & trace locations against actual disk file
            rel_path = str(ev.get("path") or "")
            disk_file = src_root / rel_path
            disk_lines: dict[int, str] = {}
            disk_sha = None
            if disk_file.is_file():
                disk_bytes = disk_file.read_bytes()
                disk_sha = sha256_bytes(disk_bytes)
                disk_lines = {
                    lno + 1: text_ln
                    for lno, text_ln in enumerate(disk_bytes.decode("utf-8").splitlines())
                }
                snaps = ev.get("snapshots") or {}
                snap_entry = snaps.get(rel_path) or {}
                if snap_entry.get("sha256") == disk_sha:
                    source_snapshot_sha_verified += 1
                else:
                    anomalies.append(f"Row {idx}: snapshot sha256 != disk sha256 for {rel_path}")

            # Verify OpenGrep raw finding source/sink line numbers exist in disk file
            raw_alert = og_results[idx] if idx < len(og_results) else {}
            s_line = ((raw_alert.get("start") or {}).get("line"))
            e_line = ((raw_alert.get("end") or {}).get("line"))
            if isinstance(s_line, int) and isinstance(e_line, int) and s_line in disk_lines and e_line in disk_lines:
                trace_locations_verified += 1

            # Verify post-validator citations against disk source lines
            cites = ass.get("citations") or []
            cites_ok = True
            if post_status in ("SUPPORTED", "REFUTED") and not cites:
                cites_ok = False
            for c_obj in cites:
                c_path = str(c_obj.get("path") or "")
                c_sl = c_obj.get("start_line")
                c_el = c_obj.get("end_line")
                c_quote = c_obj.get("quote")
                c_sha = c_obj.get("sha256")
                c_disk = src_root / c_path
                if not c_disk.is_file():
                    cites_ok = False
                    break
                c_disk_bytes = c_disk.read_bytes()
                if c_sha != sha256_bytes(c_disk_bytes):
                    cites_ok = False
                    break
                c_map = {
                    i + 1: ltxt for i, ltxt in enumerate(c_disk_bytes.decode("utf-8").splitlines())
                }
                if not isinstance(c_sl, int) or not isinstance(c_el, int) or c_sl > c_el:
                    cites_ok = False
                    break
                try:
                    actual_txt = "\n".join(c_map[i] for i in range(c_sl, c_el + 1))
                except KeyError:
                    cites_ok = False
                    break
                if actual_txt != c_quote:
                    cites_ok = False
                    break
            if cites_ok:
                citations_verified_against_disk += 1
            else:
                anomalies.append(f"Row {idx}: citation verification failed against disk")

            gt_label = gt_map.get(rec_id, "UNLABELED")
            if heur_rec_status and raw_qwen_status in ("SUPPORTED", "REFUTED", "UNDETERMINED"):
                if heur_rec_status == raw_qwen_status:
                    concordance_heur_vs_raw_qwen += 1
            if heur_rec_status and gt_label in ("TRUE_POSITIVE", "FALSE_POSITIVE"):
                expected_status_from_gt = "SUPPORTED" if gt_label == "TRUE_POSITIVE" else "REFUTED"
                if heur_rec_status == expected_status_from_gt:
                    concordance_heur_vs_gt += 1

            effective_decision = (
                "KEEP_TP"
                if post_status == "SUPPORTED"
                else ("PROPOSED_FP" if post_status == "REFUTED" else "REVIEW")
            )

            comparison_rows.append(
                {
                    "run_name": run_name,
                    "triage_mode": triage_mode,
                    "finding_index": idx,
                    "alert_id": rec_id,
                    "file_path": rel_path,
                    "sink_line": s_line,
                    "cwe": normalize_cwe(ev.get("cwe")),
                    "ground_truth": gt_label,
                    "evidence_signals_passed_to_llm": bool(
                        transport == "ollama-http" and triage_mode != "llm" and isinstance(hs, dict)
                    ),
                    "heuristic_recommended_status": heur_rec_status or "N/A",
                    "handling_path": handling_path,
                    "raw_qwen_status": raw_qwen_status,
                    "raw_qwen_citations_count": raw_qwen_cites_count,
                    "post_validator_status": post_status,
                    "citation_check": str(ass.get("citation_check") or ""),
                    "effective_decision": effective_decision,
                    "downgrade_or_fallback_reason": downgrade_reason[:220],
                    "elapsed_seconds": elapsed_s,
                }
            )

        sqlite_info = inspect_sqlite_readonly_copy(sq_path)

        runs_audit.append(
            {
                "run_name": run_name,
                "assessments_path": str(aj_path),
                "assessments_size_bytes": aj_path.stat().st_size,
                "assessments_sha256": sha256_file(aj_path),
                "evidence_json_sha256": sha256_file(ev_json_path) if ev_json_path.is_file() else None,
                "input_opengrep_sha256": input_scan_sha,
                "record_count": len(records),
                "malformed_jsonl_lines": malformed_lines,
                "alert_id_1to1_matches": alert_id_matches,
                "scan_sha256_matches": scan_sha_matches,
                "transport_counts": transport_counts,
                "model_counts": model_counts,
                "raw_response_present_count": raw_response_present,
                "substantive_raw_content_count": substantive_raw_content,
                "done_true_count": done_true_count,
                "done_reasons": done_reasons,
                "response_json_sha256_verified_count": response_json_sha_verified,
                "request_payload_sha256_present_count": request_payload_sha_present,
                "request_payload_matches_current_v2_1_code_count": request_payload_matches_current_v2_1_code,
                "literal_prompt_saved_count": literal_prompt_saved_count,
                "prompt_attestation_status": (
                    "PROMPT_NOT_ATTESTED" if literal_prompt_saved_count == 0 else "ATTESTED"
                ),
                "ollama_runtime_attestation_level": (
                    "OLLAMA_SELF_REPORTED_LOCAL_HTTP_UNATTESTED"
                    if raw_response_present > 0
                    else "NO_LLM_USED"
                ),
                "forbidden_ground_truth_leak_hits": forbidden_gt_leak_hits,
                "heuristic_signals_present_in_evidence_count": heuristic_signals_present_count,
                "heuristic_recommended_status_present_count": heuristic_recommended_status_present_count,
                "heuristic_candidate_citations_present_count": heuristic_candidate_citations_present_count,
                "evidence_signals_passed_to_llm_count": evidence_signals_passed_to_llm_count,
                "concordance_heuristic_recommended_vs_raw_qwen": concordance_heur_vs_raw_qwen,
                "concordance_heuristic_recommended_vs_ground_truth": concordance_heur_vs_gt,
                "source_snapshot_sha256_verified_count": source_snapshot_sha_verified,
                "trace_source_sink_lines_verified_count": trace_locations_verified,
                "citations_verified_against_disk_count": citations_verified_against_disk,
                "handling_breakdown": handling_breakdown,
                "raw_qwen_status_counts": raw_status_counts,
                "post_validator_status_counts": post_status_counts,
                "checkpoint_present": run_name in checkpoints_by_run,
                "checkpoint_exact_timestamp_matches": ckpt_exact_timestamp_matches,
                "latency_summary_ms": summarize_latencies_ms(latencies_ms),
                "eval_token_count_total": sum(eval_counts),
                "sqlite_readonly_audit": sqlite_info,
                "anomalies": anomalies,
            }
        )

    # Also inspect stage6_human_review_demo/review_demo.sqlite in RO mode
    stage6_demo_db = inspect_sqlite_readonly_copy(
        runs_dir / "stage6_human_review_demo" / "review_demo.sqlite"
    )

    return (
        {
            "generated_at": now_iso(),
            "total_assessments_jsonl_files": len(runs_audit),
            "total_assessment_records_audited": sum(r["record_count"] for r in runs_audit),
            "checkpoint_files_audited": checkpoint_summaries,
            "stage6_human_review_demo_sqlite": stage6_demo_db,
            "runs": runs_audit,
        },
        comparison_rows,
    )


def audit_historical_ground_truth_verifier(
    ntk_root: Path,
    brain_root: Path,
) -> dict[str, Any]:
    worktree_checks: list[dict[str, Any]] = []
    for name in (
        "post-report-cwe22-cwe89",
        "integration-pilot",
        "advisor-evaluation-javis",
        "advisor-m1-proof-ref",
        "javis",
    ):
        wt = ntk_root / name
        candidate = wt / "scripts" / "ground_truth_verifier.py"
        worktree_checks.append(
            {
                "worktree": str(wt),
                "exists": wt.is_dir(),
                "ground_truth_verifier_exists": candidate.is_file(),
            }
        )

    brain_script = brain_root / "scripts" / "ground_truth_verifier.py"
    brain_receipt = brain_root / "scratch" / "ground_truth_receipts" / "receipt_20261112_124648.json"
    javis_os_root = brain_root.parents[1]

    script_info: dict[str, Any] = {"exists": brain_script.is_file(), "path": str(brain_script)}
    if brain_script.is_file():
        raw = brain_script.read_bytes()
        txt = raw.decode("utf-8")
        script_info.update(
            {
                "size_bytes": len(raw),
                "line_count": len(txt.splitlines()),
                "sha256": sha256_bytes(raw),
                "mutates_brain_scratch_on_normal_run": (
                    "ground_truth_sqlite_baseline.json" in txt and "ground_truth_latest.json" in txt
                ),
            }
        )

    git_check = subprocess.run(
        ["git", "-C", str(javis_os_root), "check-ignore", "-v", "brains-canhan/Brain Default/scripts/ground_truth_verifier.py"],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    ls_files = subprocess.run(
        ["git", "-C", str(javis_os_root), "ls-files", "brains-canhan/Brain Default/scripts/ground_truth_verifier.py"],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )

    help_run = subprocess.run(
        [sys.executable, str(brain_script), "--help"],
        cwd=str(brain_root),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=15,
    )

    receipt_analysis: dict[str, Any] = {"exists": brain_receipt.is_file(), "path": str(brain_receipt)}
    if brain_receipt.is_file():
        r_doc = json.loads(brain_receipt.read_text(encoding="utf-8"))
        gates_summary = []
        thesis_files_touched = 0
        for g in r_doc.get("gates", []):
            gname = g.get("gate")
            if "checked_files" in g:
                paths = [x.get("path", "") for x in g["checked_files"]]
                ntk_hits = [p for p in paths if "ntk-thesis" in p.lower()]
                thesis_files_touched += len(ntk_hits)
                gates_summary.append(
                    {
                        "gate": gname,
                        "passed": g.get("passed"),
                        "checked_count": g.get("checked_count"),
                        "sample_targets": paths[:5],
                        "ntk_thesis_targets_count": len(ntk_hits),
                    }
                )
            elif "endpoints" in g:
                eps = [x.get("url", "") for x in g["endpoints"]]
                gates_summary.append(
                    {
                        "gate": gname,
                        "passed": g.get("passed"),
                        "endpoints": eps,
                        "checks_ollama_11434": any("11434" in u for u in eps),
                        "checks_opengrep": False,
                    }
                )
            elif "databases" in g:
                dbs = [x.get("db_path", "") for x in g["databases"]]
                ntk_dbs = [d for d in dbs if "ntk-thesis" in d.lower()]
                thesis_files_touched += len(ntk_dbs)
                gates_summary.append(
                    {
                        "gate": gname,
                        "passed": g.get("passed"),
                        "databases_checked": g.get("databases_checked"),
                        "database_names": [x.get("db_name") for x in g["databases"]],
                        "ntk_thesis_databases_count": len(ntk_dbs),
                    }
                )
            else:
                gates_summary.append(
                    {
                        "gate": gname,
                        "passed": g.get("passed"),
                        "files_parsed": g.get("files_parsed"),
                        "ntk_thesis_targets_count": 0,
                    }
                )

        receipt_analysis.update(
            {
                "sha256": sha256_file(brain_receipt),
                "verified_at": r_doc.get("verified_at"),
                "vault_root_cwd_when_executed": r_doc.get("vault_root"),
                "overall_passed": r_doc.get("overall_passed"),
                "thesis_artifacts_checked_across_all_4_gates": thesis_files_touched,
                "gates_breakdown": gates_summary,
            }
        )

    return {
        "generated_at": now_iso(),
        "thesis_gate_reproduction_status": "HISTORICAL_GATE_NOT_REPRODUCED",
        "classification": "HOST_JAVIS_BRAIN_INFRASTRUCTURE_SCRIPT_NOT_THESIS_VERIFIER",
        "why_missing_in_thesis_worktree": (
            "The command `python scripts/ground_truth_verifier.py` was executed from Javis Second Brain CWD "
            "(`C:\\Users\\Admin\\AppData\\Local\\javis-os\\brains-canhan\\Brain Default`) as required by Javis Hub "
            "session rules (AGENTS.md section 9.9), NOT inside `C:\\Users\\Admin\\ntk-thesis-v2\\post-report-cwe22-cwe89`. "
            "No file named `ground_truth_verifier.py` has ever existed in any commit or worktree of `ntk-thesis-v2`."
        ),
        "ntk_thesis_worktree_checks": worktree_checks,
        "located_script": script_info,
        "git_tracking_in_javis_os": {
            "javis_os_repo_root": str(javis_os_root),
            "tracked_files_output": ls_files.stdout.strip(),
            "is_tracked_in_git": bool(ls_files.stdout.strip()),
            "gitignore_match": git_check.stdout.strip() or "untracked_under_junction_brains_canhan",
        },
        "historical_interpreter": sys.executable,
        "safe_help_invocation": {
            "command": [sys.executable, str(brain_script), "--help"],
            "returncode": help_run.returncode,
            "stdout": help_run.stdout.strip(),
        },
        "why_full_rerun_skipped": (
            "Running `ground_truth_verifier.py` without arguments writes/overwrites Javis Brain state files "
            "(`scratch/ground_truth_sqlite_baseline.json`, `scratch/ground_truth_latest.json`) and checks ZERO "
            "files, ports, or SQLite databases in `ntk-thesis-v2`. Therefore it has zero evidentiary value for "
            "thesis artifacts, and we refuse to conflate host Javis/Zalo health checks with thesis verification."
        ),
        "historical_receipt_audit": receipt_analysis,
    }


def audit_ground_truth_labels(
    evidence_root: Path,
    worktree_root: Path,
) -> dict[str, Any]:
    post_dir = worktree_root / "v2" / "evaluation" / "post_report"
    owasp_csv_path = evidence_root / "sources" / "expectedresults-1.2.csv"
    owasp_csv_sha = sha256_file(owasp_csv_path)
    owasp_map = load_owasp_expected_csv(owasp_csv_path)

    dev_labels = json.loads((post_dir / "labels_development.json").read_text(encoding="utf-8"))["labels"]
    held_labels = json.loads((post_dir / "labels_heldout.json").read_text(encoding="utf-8"))["labels"]

    dev_og = json.loads((evidence_root / "runs" / "stage1_dev_set_16_scan" / "opengrep.json").read_text(encoding="utf-8"))["results"]
    held_og = json.loads((evidence_root / "runs" / "stage1_heldout_set_40_scan" / "opengrep.json").read_text(encoding="utf-8"))["results"]
    real_og = json.loads((evidence_root / "runs" / "stage5_real_projects_scan" / "opengrep.json").read_text(encoding="utf-8"))["results"]

    def _verify_benchmark_split(
        split_name: str,
        labels: list[dict[str, Any]],
        og_results: list[dict[str, Any]],
        src_dir: Path,
    ) -> dict[str, Any]:
        # Count findings per file in raw OpenGrep scan to test testcase-vs-finding equivalence
        findings_per_file: dict[str, int] = {}
        for r in og_results:
            fn = Path(str(r.get("path") or "")).name
            findings_per_file[fn] = findings_per_file.get(fn, 0) + 1

        owasp_exact_matches = 0
        cwe_exact_matches = 0
        sink_code_verified = 0
        mismatches: list[dict[str, Any]] = []
        rationale_notes: list[dict[str, Any]] = []
        per_item: list[dict[str, Any]] = []

        sink_tokens = (
            "File(",
            "FileInputStream(",
            "FileOutputStream(",
            "Files.",
            "Paths.get",
            "executeQuery(",
            "executeUpdate(",
            "execute(",
            "prepareStatement(",
            "prepareCall(",
            "batchUpdate(",
            "addBatch(",
            "executeBatch(",
            "JDBCtemplate.query(",
            "queryFor",
        )

        for item in labels:
            fname = Path(str(item["file_path"])).name
            test_name = fname[:-5] if fname.endswith(".java") else fname
            owasp_ref = owasp_map.get(test_name)
            if not owasp_ref:
                mismatches.append({"file": fname, "reason": "Test name not in expectedresults-1.2.csv"})
                continue

            lbl_ok = item["ground_truth"] == owasp_ref["expected_label"]
            cwe_ok = normalize_cwe(item["cwe"]) == owasp_ref["cwe"]
            if lbl_ok:
                owasp_exact_matches += 1
            else:
                mismatches.append({"file": fname, "label": item["ground_truth"], "owasp": owasp_ref["expected_label"]})
            if cwe_ok:
                cwe_exact_matches += 1
            else:
                mismatches.append({"file": fname, "cwe": item["cwe"], "owasp_cwe": owasp_ref["cwe"]})

            java_path = src_dir / fname
            lines = java_path.read_text(encoding="utf-8").splitlines()
            sl = int(item["start_line"])
            el = int(item["end_line"])
            span_txt = "\n".join(lines[max(0, sl - 1) : min(len(lines), el)])
            has_sink = any(tok in span_txt for tok in sink_tokens)
            if has_sink:
                sink_code_verified += 1
            else:
                mismatches.append({"file": fname, "lines": f"{sl}-{el}", "span": span_txt, "reason": "No recognizable sink token"})

            full_java = "\n".join(lines)
            if "scr.getTheValue(" in full_java and "ThingFactory.createThing()" in full_java:
                rationale_notes.append(
                    {
                        "file": fname,
                        "owasp_label": owasp_ref["expected_label"],
                        "note": (
                            "Label FALSE_POSITIVE matches OWASP CSV, and actual safe mechanism in Java is "
                            "`SeparateClassRequest.getTheValue(...)` (which returns constant `\"bar\"` in "
                            "`SeparateClassRequest.java:51`), whereas `Thing1`/`Thing2` pass input through. "
                            "Note `LABELING_PROTOCOL.md` line 27 misdescribed `ThingInterface` as returning a constant."
                        ),
                    }
                )

            per_item.append(
                {
                    "split": split_name,
                    "test_name": test_name,
                    "alert_id": item["alert_id"],
                    "cwe": normalize_cwe(item["cwe"]),
                    "owasp_cwe": owasp_ref["cwe"],
                    "ground_truth": item["ground_truth"],
                    "owasp_expected_label": owasp_ref["expected_label"],
                    "sink_lines": f"{sl}-{el}",
                    "findings_in_file_count": findings_per_file.get(fname, 0),
                    "sink_token_verified": has_sink,
                }
            )

        return {
            "split_name": split_name,
            "count": len(labels),
            "owasp_label_matches": owasp_exact_matches,
            "owasp_cwe_matches": cwe_exact_matches,
            "sink_code_verified_count": sink_code_verified,
            "single_finding_per_testcase_count": sum(1 for v in findings_per_file.values() if v == 1),
            "max_findings_per_testcase": max(findings_per_file.values()) if findings_per_file else 0,
            "mismatches": mismatches,
            "forensic_rationale_notes": rationale_notes,
            "items": per_item,
        }

    dev_audit = _verify_benchmark_split(
        "dev_set_16", dev_labels, dev_og, evidence_root / "sources" / "dev_set_16"
    )
    held_audit = _verify_benchmark_split(
        "heldout_set_40", held_labels, held_og, evidence_root / "sources" / "heldout_set_40"
    )

    dev_files_set = {Path(x["file_path"]).name for x in dev_labels}
    held_files_set = {Path(x["file_path"]).name for x in held_labels}
    dev_shas_set = {x["source_sha256"] for x in dev_labels}
    held_shas_set = {x["source_sha256"] for x in held_labels}
    dev_aids_set = {x["alert_id"] for x in dev_labels}
    held_aids_set = {x["alert_id"] for x in held_labels}

    # Verify STRICT_LOCK programmatically via validate_pilot_lock
    held_alerts_path = post_dir / "heldout_alerts.json"
    held_labels_path = post_dir / "labels_heldout.json"
    strict_lock_report = validate_pilot_lock.validate_pilot_dataset(
        opengrep_data=json.loads(held_alerts_path.read_text(encoding="utf-8")),
        labels_data=json.loads(held_labels_path.read_text(encoding="utf-8")),
        mode="STRICT_LOCK",
        source_root=evidence_root / "sources" / "heldout_set_40",
    )
    recomputed_lock = validate_pilot_lock.create_lock_manifest(
        held_alerts_path,
        held_labels_path,
        mode="STRICT_LOCK",
        m4_acceptance_ready=strict_lock_report["m4_acceptance_ready"],
    )
    saved_lock_manifest = json.loads(
        (post_dir / "heldout_strict_lock_manifest.json").read_text(encoding="utf-8")
    )
    lock_ok, lock_errs = validate_pilot_lock.verify_lock_manifest(
        saved_lock_manifest,
        held_alerts_path,
        held_labels_path,
        require_m4_acceptance=True,
    )

    # Audit Real Projects 20 manual labels independently of Qwen
    real_src_root = evidence_root / "sources" / "real_projects"
    real_scan_sha = EXPECTED_SCAN_SHAS["stage5_real_projects_scan"]
    real_items: list[dict[str, Any]] = []
    distinct_loci = set()
    for idx, r in enumerate(real_og):
        meta = REAL_PROJECT_MANUAL_LABELS[idx]
        distinct_loci.add(meta["locus"])
        raw_path = str(r.get("path") or "")
        # Normalize path relative to sources/real_projects
        norm_rel = raw_path.replace("\\", "/")
        if "sources/real_projects/" in norm_rel:
            norm_rel = norm_rel.split("sources/real_projects/", 1)[1]
        disk_f = real_src_root / norm_rel
        lines = disk_f.read_text(encoding="utf-8").splitlines()
        sl = int(r["start"]["line"])
        el = int(r["end"]["line"])
        code_excerpt = " ".join(ln.strip() for ln in lines[max(0, sl - 1) : min(len(lines), el)])
        real_items.append(
            {
                "finding_index": idx,
                "alert_id": compute_contract_alert_id(real_scan_sha, idx),
                "file_path": norm_rel,
                "lines": f"{sl}-{el}",
                "rule_id": str(r.get("check_id") or "").split(".")[-1],
                "cwe": normalize_cwe(((r.get("extra") or {}).get("metadata") or {}).get("cwe")),
                "manual_label": meta["label"],
                "locus_id": meta["locus"],
                "confidence": meta["confidence"],
                "code_at_sink": code_excerpt[:180],
                "independent_evidence": meta.get("independent_evidence", "Direct unsanitized taint flow to sink verified in Java source."),
            }
        )

    return {
        "generated_at": now_iso(),
        "owasp_expectedresults_csv": {
            "path": str(owasp_csv_path),
            "sha256": owasp_csv_sha,
            "matches_benchmark_v1_2_sha256": owasp_csv_sha == EXPECTED_OWASP_CSV_SHA,
            "total_owasp_testcases_parsed": len(owasp_map),
        },
        "testcase_vs_finding_distinction": {
            "owasp_benchmark_56": (
                "OWASP `expectedresults-1.2.csv` provides TESTCASE-level labels (`1` servlet = `1` label). "
                "Across all 56 selected files (`16` dev + `40` held-out), OpenGrep with `p_java_cwe22_cwe89.yml` "
                "emitted exactly `1` finding per file at the servlet's real vulnerability/false-positive sink line, "
                "making testcase-level and finding-level labels 1-to-1 aligned on this subset."
            ),
            "real_projects_20": (
                "On real projects (`8` files), OpenGrep emitted `20` findings across `12` distinct code loci "
                "because two overlapping SQLi rules (`tainted-sql-*` at string construction + `formatted-sql-string` "
                "at `executeQuery`/`executeUpdate`) fire on the same SQL flow in `8` cases (`Assignment5`, "
                "`SqlInjectionLesson5a`, `SqlInjectionLesson8` x2, `UserDao` x2, `SQLI.java` x2). Therefore, "
                "alert-level counts (`16 TP / 4 FP = 20 alerts`) represent `12` unique code-level flows (`9 TP / 3 FP loci`)."
            ),
        },
        "overlap_verification": {
            "filename_overlap_count": len(dev_files_set & held_files_set),
            "source_sha256_overlap_count": len(dev_shas_set & held_shas_set),
            "alert_id_overlap_count": len(dev_aids_set & held_aids_set),
            "is_strictly_disjoint": (
                len(dev_files_set & held_files_set) == 0
                and len(dev_shas_set & held_shas_set) == 0
                and len(dev_aids_set & held_aids_set) == 0
            ),
        },
        "strict_lock_verification": {
            "valid_lock_candidate": strict_lock_report.get("valid_lock_candidate"),
            "m4_acceptance_ready": strict_lock_report.get("m4_acceptance_ready"),
            "recomputed_combined_lock_sha256": recomputed_lock.get("combined_lock_sha256"),
            "saved_manifest_combined_lock_sha256": saved_lock_manifest.get("combined_lock_sha256"),
            "lock_hash_matches": lock_ok,
            "lock_verify_errors": lock_errs,
            "errors": strict_lock_report.get("errors"),
            "warnings": strict_lock_report.get("warnings"),
        },
        "dev_set_16_audit": dev_audit,
        "heldout_set_40_audit": held_audit,
        "real_projects_20_manual_audit": {
            "total_alerts": len(real_items),
            "distinct_code_loci": len(distinct_loci),
            "alert_level_tp": sum(1 for x in real_items if x["manual_label"] == "TRUE_POSITIVE"),
            "alert_level_fp": sum(1 for x in real_items if x["manual_label"] == "FALSE_POSITIVE"),
            "four_manual_fps": [x for x in real_items if x["manual_label"] == "FALSE_POSITIVE"],
            "all_20_items": real_items,
        },
    }


def _compute_bucket_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    tp_rows = [r for r in rows if r["ground_truth"] == "TRUE_POSITIVE"]
    fp_rows = [r for r in rows if r["ground_truth"] == "FALSE_POSITIVE"]

    tp_supported = sum(1 for r in tp_rows if r["post_status"] == "SUPPORTED")
    tp_refuted = sum(1 for r in tp_rows if r["post_status"] == "REFUTED")
    tp_undetermined = sum(1 for r in tp_rows if r["post_status"] == "UNDETERMINED")

    fp_refuted = sum(1 for r in fp_rows if r["post_status"] == "REFUTED")
    fp_supported = sum(1 for r in fp_rows if r["post_status"] == "SUPPORTED")
    fp_undetermined = sum(1 for r in fp_rows if r["post_status"] == "UNDETERMINED")

    undetermined_total = sum(1 for r in rows if r["post_status"] == "UNDETERMINED")
    decided_total = total - undetermined_total
    decided_correct = tp_supported + fp_refuted
    citation_matched = sum(1 for r in rows if r["citation_check"] == "MATCHED")

    # Policy 1: drop_fp -> retain SUPPORTED + UNDETERMINED; drop REFUTED (proposed_fp)
    drop_fp_retained_tp = tp_supported + tp_undetermined
    drop_fp_retained_fp = fp_supported + fp_undetermined
    drop_fp_denom = drop_fp_retained_tp + drop_fp_retained_fp

    # Policy 2: keep_tp_only -> retain SUPPORTED only
    keep_tp_denom = tp_supported + fp_supported

    lat_ms = [float(r["elapsed_seconds"]) * 1000.0 for r in rows if isinstance(r.get("elapsed_seconds"), (int, float))]

    return {
        "total_alerts": total,
        "labeled_tp": len(tp_rows),
        "labeled_fp": len(fp_rows),
        "tp_kept_supported": f"{tp_supported}/{len(tp_rows)}",
        "tp_kept_supported_count": tp_supported,
        "tp_retained_with_review": f"{drop_fp_retained_tp}/{len(tp_rows)}",
        "fp_proposed_refuted": f"{fp_refuted}/{len(fp_rows)}",
        "fp_proposed_refuted_count": fp_refuted,
        "tp_erroneously_refuted": f"{tp_refuted}/{len(tp_rows)}",
        "tp_erroneously_refuted_count": tp_refuted,
        "fp_erroneously_kept_supported": f"{fp_supported}/{len(fp_rows)}",
        "fp_erroneously_kept_supported_count": fp_supported,
        "undetermined_count": undetermined_total,
        "undetermined_display": f"{undetermined_total}/{total}",
        "coverage_display": f"{decided_total}/{total}",
        "accuracy_on_decided_display": f"{decided_correct}/{decided_total}" if decided_total else "0/0",
        "citation_matched_display": f"{citation_matched}/{total}",
        "citation_matched_count": citation_matched,
        "policy_drop_fp_precision": f"{drop_fp_retained_tp}/{drop_fp_denom}" if drop_fp_denom else "0/0",
        "policy_drop_fp_precision_pct": round(100.0 * drop_fp_retained_tp / drop_fp_denom, 1) if drop_fp_denom else 0.0,
        "policy_drop_fp_recall": f"{drop_fp_retained_tp}/{len(tp_rows)}" if tp_rows else "0/0",
        "policy_keep_tp_only_precision": f"{tp_supported}/{keep_tp_denom}" if keep_tp_denom else "0/0",
        "policy_keep_tp_only_precision_pct": round(100.0 * tp_supported / keep_tp_denom, 1) if keep_tp_denom else 0.0,
        "policy_keep_tp_only_recall": f"{tp_supported}/{len(tp_rows)}" if tp_rows else "0/0",
        "latency_ms": summarize_latencies_ms(lat_ms),
    }


def recompute_metrics_and_consistency(
    evidence_root: Path,
    worktree_root: Path,
    comparison_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    post_dir = worktree_root / "v2" / "evaluation" / "post_report"

    # Group comparison_rows by run_name
    by_run: dict[str, list[dict[str, Any]]] = {}
    for r in comparison_rows:
        row_copy = {
            **r,
            "post_status": r["post_validator_status"],
        }
        by_run.setdefault(r["run_name"], []).append(row_copy)

    # Synthesize Arm A (OpenGrep-only) on heldout_set_40 from Arm C alert list
    held_base = by_run["stage4_heldout40_armC_evidence_llm"]
    arm_a_rows = [
        {
            **r,
            "post_status": "SUPPORTED",
            "citation_check": "N/A",
            "elapsed_seconds": 0.0,
        }
        for r in held_base
    ]

    heldout_recomputed: dict[str, Any] = {}
    for arm_key, rows in (
        ("Arm_A_OpenGrep_Only", arm_a_rows),
        ("Arm_B_Heuristic", by_run["stage4_heldout40_armB_heuristic"]),
        ("Arm_C_Evidence_Plus_Qwen", by_run["stage4_heldout40_armC_evidence_llm"]),
        ("Arm_D_Qwen_Ablation", by_run["stage4_heldout40_armD_llm_ablation"]),
    ):
        heldout_recomputed[arm_key] = {
            "ALL": _compute_bucket_metrics(rows),
            "CWE-22": _compute_bucket_metrics([x for x in rows if x["cwe"] == "CWE-22"]),
            "CWE-89": _compute_bucket_metrics([x for x in rows if x["cwe"] == "CWE-89"]),
        }

    # Also cross-check via official score_pilot.evaluate_pilot on Held-Out Arm B, C, D
    held_og = json.loads((evidence_root / "runs" / "stage1_heldout_set_40_scan" / "opengrep.json").read_text(encoding="utf-8"))
    held_lbl = json.loads((post_dir / "labels_heldout.json").read_text(encoding="utf-8"))
    score_pilot_crosscheck: dict[str, Any] = {}
    for run_name in (
        "stage4_heldout40_armB_heuristic",
        "stage4_heldout40_armC_evidence_llm",
        "stage4_heldout40_armD_llm_ablation",
    ):
        triage_txt = (evidence_root / "runs" / run_name / "assessments.jsonl").read_text(encoding="utf-8")
        rep = score_pilot.evaluate_pilot(
            opengrep_data=held_og,
            labels_data=held_lbl,
            triage_data=triage_txt,
            source_root=evidence_root / "sources" / "heldout_set_40",
            expected_scan_sha256=EXPECTED_SCAN_SHAS["stage1_heldout_set_40_scan"],
        )
        ov_dict = (rep.get("summary") or {}).get("overall") or {}
        ov = ov_dict.get("counts", {})
        score_pilot_crosscheck[run_name] = {
            "kept_tp_on_true_tp": ov.get("kept_tp_on_true_tp"),
            "kept_tp_on_true_fp": ov.get("kept_tp_on_true_fp"),
            "proposed_fp_on_true_fp": ov.get("proposed_fp_on_true_fp"),
            "erroneously_proposed_fp_on_tp": ov.get("erroneously_proposed_fp_on_tp"),
            "needs_review_total": ov.get("needs_review_total"),
            "anomalies_total": sum(len(v) for v in (rep.get("anomalies") or {}).values() if isinstance(v, list)),
        }

    # Verify PAIRED_EVALUATION.csv row-by-row against raw JSONL
    paired_csv_mismatches: list[str] = []
    with (post_dir / "PAIRED_EVALUATION.csv").open("r", encoding="utf-8-sig", newline="") as fh:
        csv_rows = list(csv.DictReader(fh))
    if len(csv_rows) != 40:
        paired_csv_mismatches.append(f"PAIRED_EVALUATION.csv row count {len(csv_rows)} != 40")
    arm_b_map = {r["alert_id"]: r for r in by_run["stage4_heldout40_armB_heuristic"]}
    arm_c_map = {r["alert_id"]: r for r in by_run["stage4_heldout40_armC_evidence_llm"]}
    arm_d_map = {r["alert_id"]: r for r in by_run["stage4_heldout40_armD_llm_ablation"]}
    for cr in csv_rows:
        aid = cr["alert_id"]
        rb, rc, rd = arm_b_map.get(aid), arm_c_map.get(aid), arm_d_map.get(aid)
        if not (rb and rc and rd):
            paired_csv_mismatches.append(f"Missing alert_id {aid} in raw runs")
            continue
        if cr["arm_b_heuristic_status"] != rb["post_status"]:
            paired_csv_mismatches.append(f"{aid}: arm_b status {cr['arm_b_heuristic_status']} != {rb['post_status']}")
        if cr["arm_c_qwen35_raw_status"] != rc["raw_qwen_status"]:
            paired_csv_mismatches.append(f"{aid}: arm_c raw {cr['arm_c_qwen35_raw_status']} != {rc['raw_qwen_status']}")
        if cr["arm_c_qwen35_post_citation_status"] != rc["post_status"]:
            paired_csv_mismatches.append(f"{aid}: arm_c post {cr['arm_c_qwen35_post_citation_status']} != {rc['post_status']}")
        if cr["arm_d_llm_ablation_raw_status"] != rd["raw_qwen_status"]:
            paired_csv_mismatches.append(f"{aid}: arm_d raw {cr['arm_d_llm_ablation_raw_status']} != {rd['raw_qwen_status']}")

    dev_recomputed = {
        rname: _compute_bucket_metrics(by_run[rname])
        for rname in (
            "stage2_dev16_baseline_v1_0",
            "stage3_dev16_armB_heuristic",
            "stage3_dev16_armC_evidence_llm",
            "stage3_dev16_armC_v2_1_evidence_llm",
            "stage3_dev16_armD_llm_ablation",
        )
    }
    real_recomputed = {
        rname: _compute_bucket_metrics(by_run[rname])
        for rname in (
            "stage5_real_projects_armB_heuristic",
            "stage5_real_projects_armC_evidence_llm",
        )
    }

    # Error taxonomy across key runs
    def _error_taxonomy(rows: list[dict[str, Any]]) -> dict[str, int]:
        return {
            "json_parse_errors": sum(1 for r in rows if r["handling_path"] == "POST_LLM_JSON_PARSE_DOWNGRADE"),
            "pre_llm_missing_evidence_or_clicall": sum(1 for r in rows if r["handling_path"] == "PRE_LLM_EVIDENCE_GUARD_FALLBACK"),
            "post_llm_citation_validator_downgrade": sum(1 for r in rows if r["handling_path"] == "POST_LLM_VALIDATOR_DOWNGRADE"),
            "qwen_false_positive_kept_as_supported": sum(
                1 for r in rows if r["ground_truth"] == "FALSE_POSITIVE" and r["post_status"] == "SUPPORTED"
            ),
            "qwen_true_positive_erroneously_refuted": sum(
                1 for r in rows if r["ground_truth"] == "TRUE_POSITIVE" and r["post_status"] == "REFUTED"
            ),
            "model_raw_undetermined": sum(1 for r in rows if r["raw_qwen_status"] == "UNDETERMINED"),
        }

    # Task F: Historical Consistency Checks
    consistency_findings = [
        {
            "check": "YAML Rule Count vs Documentation",
            "status": "DISCREPANCY_FOUND",
            "ground_truth_on_disk": "`p_java_cwe22_cwe89.yml` contains exactly `9` rules (`2` CWE-22 + `7` CWE-89), matching `DATASET_PROVENANCE.json` (`rule_count: 9`) and `DATASET_MANIFEST.md` (`9 rule`).",
            "inconsistent_docs": "`v2/docs/POST_REPORT_IMPLEMENTATION_HANDOVER.md` (line 80) and `v2/docs/thesis/CHUONG_4_THUC_NGHIEM_VA_DANH_GIA.md` (line 7) inaccurately state `14 quy tắc Java CWE-22/CWE-89`.",
        },
        {
            "check": "dev_set_16 scan_sha256 Consistency",
            "status": "DISCREPANCY_FOUND",
            "ground_truth_on_disk": "`runs/stage1_dev_set_16_scan/opengrep.json`, all 5 dev run `input.opengrep.json` + `assessments.jsonl`, `DATASET_PROVENANCE.json`, `DATASET_MANIFEST.md`, and `labels_development.csv/json` all bind to `ecc1fa4634bfc86266c43dd6790422546367293d1810712fddc7c0d15a6c015f`.",
            "inconsistent_docs": "`v2/docs/thesis/CHUONG_4_THUC_NGHIEM_VA_DANH_GIA.md` (line 14) and Javis Brain receipt `v2_prompt13_post_report_cwe22_cwe89_20261112.md` (line 15) cite `c1be1d5e1be23a7ddba48fa7e0d61049234fd6003be057cf15893977c04d08c2`, which matches ZERO files across all 263 evidence artifacts.",
        },
        {
            "check": "expectedresults-1.2.csv SHA-256 Consistency",
            "status": "DISCREPANCY_FOUND",
            "ground_truth_on_disk": "Both WSL `/home/tuankhoa/migration/ntk_ft211_sources/BenchmarkJava/expectedresults-1.2.csv` and `sources/expectedresults-1.2.csv` have SHA-256 `1809f6a690c6cf7dd6685df6ebe2eef8fe3ca93d19a7ca0ce45987ca4f5d78e1` (matching `DATASET_PROVENANCE.json`, `DATASET_MANIFEST.md`, and `LABELING_PROTOCOL.md`).",
            "inconsistent_docs": "`v2/docs/POST_REPORT_IMPLEMENTATION_HANDOVER.md` (line 85) cites `353762c72ef5bcd7fd2dc9ad3bc8dc1fa2fae1ade4cd4aa1dedf7ea42de2a040`, which matches ZERO files on disk.",
        },
        {
            "check": "heldout_set_40 & real_projects scan_sha256 Consistency",
            "status": "CONSISTENT",
            "ground_truth_on_disk": "`heldout_set_40` (`67c3b04903e75f4bd7294cb17452d0dcb2b6d56244330cec485c4422efabfa8b`) and `real_projects` (`99d2445c218030fb10082176c299bc328eeb62c6b23c7ab745cffd824f31f041`) match 100% across raw scans, manifests, assessments, and all docs.",
            "inconsistent_docs": "None.",
        },
        {
            "check": "OpenGrep Binary Path & Invocation Mode",
            "status": "DISCREPANCY_FOUND",
            "ground_truth_on_disk": (
                "All 3 primary scans in `runs/` (`stage1_dev_set_16_scan`, `stage1_heldout_set_40_scan`, and "
                "`stage5_real_projects_scan`) executed Windows native `C:\\Users\\Admin\\ntk-thesis-v2\\tools\\opengrep\\v1.25.0\\opengrep.exe` "
                "(`1.25.0`, SHA-256 `b010709bb790086083442eabe9a0b6bf48064ed87cdf808591baecdb60ccdf73`), as recorded in `json.command.json` "
                "and `scan-manifest.json`. Meanwhile, `logs/wsl_scan_real_projects.py` was an auxiliary script referencing "
                "`/home/tuankhoa/.local/bin/opengrep` (now absent; WSL currently has `/usr/local/bin/opengrep` `1.25.0`, SHA-256 `9ac4aebb...`)."
            ),
            "inconsistent_docs": "`POST_REPORT_BASELINE_AUDIT.md` (line 29) and `POST_REPORT_IMPLEMENTATION_HANDOVER.md` (line 76) state `opengrep.exe` bridges to `/home/tuankhoa/.opengrep/cli/latest/opengrep` (which does not exist in WSL; `opengrep.exe` is a standalone 48.5 MB Windows PE binary).",
        },
        {
            "check": "Why Held-Out OWASP Refuted 20/20 FPs vs Real Projects Refuted 0/4 FPs (20/20 SUPPORTED)",
            "status": "EXPLAINED_BY_CONCRETE_EVIDENCE",
            "ground_truth_on_disk": (
                "Verified directly from `assessments.jsonl` (`evidence.heuristic_signals`): "
                "(1) On `heldout_set_40` Arm C, `heuristics.extract_evidence_signals` pre-computed "
                "`recommended_status = 'REFUTED'` on `20/20` OWASP FPs and `'SUPPORTED'` on `20/20` OWASP TPs "
                "(`40/40 = 100%` match with OWASP ground truth!) because `heuristics.py` explicitly models OWASP "
                "Benchmark's 5 synthetic patterns (`guess.charAt(1)` switch, arithmetic ternary, `valuesList.remove(0)+get(1)`, "
                "`map.get('keyA-...')`, `SeparateClassRequest.getTheValue`), and `ollama.py` passed `evidence_signals` "
                "(including `recommended_status`, `recommendation_reason`, and `candidate_citations`) into the Arm C prompt. "
                "Qwen agreed with `recommended_status` on `40/40` (`100%`) held-out alerts! "
                "(2) Conversely, on `real_projects` (`n=20`), NONE of the 4 manual FPs triggered `heuristics.py`'s pre-sink "
                "regexes (`SqlInjectionLesson8.java:148` uses `action.replace('\\'', '\"')` which is not in `sanitizers.yaml`; "
                "`UserService.java:52` relies on cross-file `@Pattern` in `UserForm.java`; `UserDao.java:63` checks "
                "`getCanonicalPath().startsWith(BASE_DIR)` at line `64 > sink_line 63`, skipped by `if ln_no <= sink_line:` "
                "in `heuristics.py:433`). Thus `heuristic_signals.recommended_status` defaulted to `'SUPPORTED'` for all "
                "`20/20` real-project alerts (`16/20` match with manual labels), and Qwen output `'SUPPORTED'` for all `20/20`!"
            ),
            "inconsistent_docs": (
                "While `REAL_PROJECT_EVALUATION.md` correctly notes the cross-file, post-sink, and `String.replace` limits, "
                "the strong prompt-coupling via `evidence_signals.recommended_status` (`100%` agreement between "
                "`heuristic_signals.recommended_status` and Qwen's output across `16/16` dev v2.1, `40/40` held-out Arm C, "
                "and `20/20` real projects Arm C = `76/76` total!) is a critical methodological finding for Antigravity and Codex: "
                "Arm B (`--mode heuristic`) withheld `callee_method_flow`, `list_index_*`, and `map_key_*` as `UNDETERMINED` (`24/40`), "
                "whereas `extract_evidence_signals` in Arm C ALREADY resolved them deterministically into `recommended_status` before calling Qwen."
            ),
        },
    ]

    return {
        "generated_at": now_iso(),
        "inputs_used": {
            "heldout_raw_scan": "runs/stage1_heldout_set_40_scan/opengrep.json",
            "heldout_labels": "v2/evaluation/post_report/labels_heldout.json",
            "heldout_jsonl_runs": [
                "runs/stage4_heldout40_armB_heuristic/assessments.jsonl",
                "runs/stage4_heldout40_armC_evidence_llm/assessments.jsonl",
                "runs/stage4_heldout40_armD_llm_ablation/assessments.jsonl",
            ],
            "dev_jsonl_runs": [
                "runs/stage2_dev16_baseline_v1_0/assessments.jsonl",
                "runs/stage3_dev16_armB_heuristic/assessments.jsonl",
                "runs/stage3_dev16_armC_evidence_llm/assessments.jsonl",
                "runs/stage3_dev16_armC_v2_1_evidence_llm/assessments.jsonl",
                "runs/stage3_dev16_armD_llm_ablation/assessments.jsonl",
            ],
            "real_projects_jsonl_runs": [
                "runs/stage5_real_projects_armB_heuristic/assessments.jsonl",
                "runs/stage5_real_projects_armC_evidence_llm/assessments.jsonl",
            ],
        },
        "heldout_40_recomputed": heldout_recomputed,
        "score_pilot_official_crosscheck": score_pilot_crosscheck,
        "paired_evaluation_csv_cell_mismatches": paired_csv_mismatches,
        "dev_16_recomputed": dev_recomputed,
        "real_projects_20_recomputed": real_recomputed,
        "error_taxonomy_by_run": {
            rname: _error_taxonomy(rows) for rname, rows in by_run.items()
        },
        "historical_consistency_audit": consistency_findings,
    }


def verify_evidence_root_immutability(pre_snapshot_path: Path, evidence_root: Path) -> dict[str, Any]:
    pre_doc = json.loads(pre_snapshot_path.read_text(encoding="utf-8"))
    pre_map = {item["rel_path"]: item for item in pre_doc["files"]}

    post_map: dict[str, dict[str, Any]] = {}
    for p in sorted(evidence_root.rglob("*")):
        if p.is_file():
            st = p.stat()
            post_map[p.relative_to(evidence_root).as_posix()] = {
                "size_bytes": st.st_size,
                "mtime_ns": st.st_mtime_ns,
                "sha256": sha256_file(p),
            }

    added = sorted(set(post_map) - set(pre_map))
    removed = sorted(set(pre_map) - set(post_map))
    modified = []
    for k in sorted(set(pre_map) & set(post_map)):
        if (
            pre_map[k]["sha256"] != post_map[k]["sha256"]
            or pre_map[k]["size_bytes"] != post_map[k]["size_bytes"]
        ):
            modified.append({"rel_path": k, "before": pre_map[k], "after": post_map[k]})

    return {
        "verified_at": now_iso(),
        "pre_file_count": len(pre_map),
        "post_file_count": len(post_map),
        "added_files": added,
        "removed_files": removed,
        "modified_files": modified,
        "zero_mutation_verified": len(added) == 0 and len(removed) == 0 and len(modified) == 0,
    }


def write_markdown_deliverables(
    out_dir: Path,
    inv: dict[str, Any],
    scans: dict[str, Any],
    ollama_audit: dict[str, Any],
    comp_rows: list[dict[str, Any]],
    gt_script_audit: dict[str, Any],
    gt_labels_audit: dict[str, Any],
    metrics_audit: dict[str, Any],
) -> None:
    # 1. Inventory CSV + MD
    with (out_dir / "01_file_inventory_sha256.csv").open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["scope", "rel_path", "size_bytes", "sha256", "lf_sha256"])
        w.writeheader()
        for item in inv["evidence_files"] + inv["worktree_files"]:
            w.writerow({k: item.get(k) for k in ["scope", "rel_path", "size_bytes", "sha256", "lf_sha256"]})

    lines1 = [
        "# 01. Danh Mục Tệp Kiểm Toán, Kích Thước & Mã Băm SHA-256",
        "",
        f"- **Thời điểm kiểm kê:** `{inv['generated_at']}`",
        f"- **Thư mục bằng chứng lịch sử (`evidence_root`, READ-ONLY):** `{inv['evidence_root']}` (**`{inv['evidence_file_count']}`** tệp)",
        f"- **Worktree đối chiếu (`worktree_root`, READ-ONLY):** `{inv['worktree_root']}` (**`{inv['worktree_checked_file_count']}`** tệp trong `v2/evaluation/post_report` & `v2/docs`)",
        "- Danh sách đầy đủ từng tệp kèm kích thước byte, `sha256` nguyên bản và `lf_sha256` được xuất tại `01_file_inventory_sha256.csv` và `01_file_inventory_sha256.json`.",
        "",
        "## Các Hiện Vật Trọng Tâm Được Đối Chiếu Mã Băm",
        "",
        "| Phạm vi | Đường dẫn tương đối | Kích thước (bytes) | SHA-256 thực tế |",
        "|---|---|---:|---|",
    ]
    key_rels = {
        "runs/stage1_dev_set_16_scan/opengrep.json",
        "runs/stage1_dev_set_16_scan/scan-manifest.json",
        "runs/stage1_heldout_set_40_scan/opengrep.json",
        "runs/stage1_heldout_set_40_scan/scan-manifest.json",
        "runs/stage5_real_projects_scan/opengrep.json",
        "runs/stage5_real_projects_scan/scan-manifest.json",
        "runs/stage3_dev16_armC_v2_1_evidence_llm/assessments.jsonl",
        "runs/stage4_heldout40_armB_heuristic/assessments.jsonl",
        "runs/stage4_heldout40_armC_evidence_llm/assessments.jsonl",
        "runs/stage4_heldout40_armD_llm_ablation/assessments.jsonl",
        "runs/stage5_real_projects_armC_evidence_llm/assessments.jsonl",
        "sources/expectedresults-1.2.csv",
        "v2/evaluation/post_report/rules/p_java_cwe22_cwe89.yml",
        "v2/evaluation/post_report/heldout_strict_lock_manifest.json",
        "v2/evaluation/post_report/labels_development.json",
        "v2/evaluation/post_report/labels_heldout.json",
        "v2/evaluation/post_report/PAIRED_EVALUATION.csv",
    }
    for item in inv["evidence_files"] + inv["worktree_files"]:
        if item["rel_path"] in key_rels:
            lines1.append(
                f"| `{item['scope']}` | `{item['rel_path']}` | `{item['size_bytes']}` | `{item['sha256']}` |"
            )
    (out_dir / "01_file_inventory_sha256.md").write_text("\n".join(lines1) + "\n", encoding="utf-8")

    # 2. OpenGrep Scans MD
    lines2 = [
        "# 02. Biên Nhận Kiểm Toán Ba Bản Quét Gốc OpenGrep (`Task A`)",
        "",
        f"- **Thời điểm kiểm toán:** `{scans['generated_at']}`",
        f"- **Bộ quy tắc thực tế (`p_java_cwe22_cwe89.yml`):** `{scans['pinned_ruleset']['rule_count']}` quy tắc, SHA-256 = `{scans['pinned_ruleset']['sha256']}`",
        "",
        "| Bản quét | Số tệp quét / bỏ qua | Số cảnh báo (có trace) | Lỗi quét (`errors`) | Mã thoát | `sources_before == after` | `rules_before == after` | SHA-256 thực tế (`opengrep.json`) | Khớp kỳ vọng |",
        "|---|---:|---:|---:|---:|---|---|---|---|",
    ]
    for s in scans["three_primary_scans"]:
        cmd_rec = s.get("command_record")
        rc = cmd_rec.get("returncode") if isinstance(cmd_rec, dict) else s["verify_receipt_meta"].get("recorded_engine_exit")
        lines2.append(
            f"| `{s['run_name']}` | `{s['paths_scanned_count']} / {s['paths_skipped_count']}` | "
            f"`{s['findings_count']} ({s['findings_with_complete_dataflow_trace']})` | `{s['scan_errors_count']}` | "
            f"`{rc}` | `{s['sources_unchanged_before_after']}` | `{s['rules_unchanged_before_after']}` | "
            f"`{s['actual_sha256']}` | `{s['sha256_matched']}` |"
        )
    (out_dir / "02_raw_opengrep_scans_receipt.md").write_text("\n".join(lines2) + "\n", encoding="utf-8")

    # 3. 10 Ollama JSONL Receipt MD
    lines3 = [
        "# 03. Biên Nhận Kiểm Toán Toàn Bộ 10 Tệp `assessments.jsonl` (`Task B`)",
        "",
        "| Lượt chạy (`runs/`) | Số bản ghi | Lỗi JSONL | Transport | `raw_response` có nội dung | `done=true` | `response_json_sha256` khớp | `request_payload_sha256` khớp code `v2.1` | Prompt thô được lưu | `heuristic_signals` lưu JSONL / truyền vào LLM | SQLite `OPEN` / Events |",
        "|---|---:|---:|---|---:|---:|---:|---:|---|---|---|",
    ]
    for r in ollama_audit["runs"]:
        sq = r["sqlite_readonly_audit"]
        st_str = f"{sq.get('warning_states')} / ev={sq.get('human_events_count')}"
        lines3.append(
            f"| `{r['run_name']}` | `{r['record_count']}` | `{r['malformed_jsonl_lines']}` | "
            f"`{list(r['transport_counts'].keys())}` | `{r['substantive_raw_content_count']}/{r['record_count']}` | "
            f"`{r['done_true_count']}/{r['record_count']}` | `{r['response_json_sha256_verified_count']}/{r['raw_response_present_count']}` | "
            f"`{r['request_payload_matches_current_v2_1_code_count']}/{r['request_payload_sha256_present_count']}` | "
            f"`{r['prompt_attestation_status']}` | `{r['heuristic_recommended_status_present_count']}/{r['record_count']} (LLM: {r['evidence_signals_passed_to_llm_count']}/{r['record_count']})` | `{st_str}` |"
        )
    (out_dir / "03_ollama_10_assessments_receipt.md").write_text("\n".join(lines3) + "\n", encoding="utf-8")

    # 4. Raw vs Post-Validator CSV + MD
    fieldnames4 = list(comp_rows[0].keys()) if comp_rows else []
    with (out_dir / "04_raw_vs_post_validator_comparison.csv").open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames4)
        w.writeheader()
        w.writerows(comp_rows)

    heur_only_count = sum(1 for r in comp_rows if r["handling_path"] == "HEURISTIC_DETERMINISTIC_NO_LLM")
    llm_mode_count = len(comp_rows) - heur_only_count
    downgraded = [
        r for r in comp_rows if r["handling_path"] not in ("MODEL_LIVE_HTTP_ACCEPTED", "HEURISTIC_DETERMINISTIC_NO_LLM")
    ]
    pre_llm_cnt = sum(1 for r in downgraded if r["handling_path"] == "PRE_LLM_EVIDENCE_GUARD_FALLBACK")
    parse_err_cnt = sum(1 for r in downgraded if r["handling_path"] == "POST_LLM_JSON_PARSE_DOWNGRADE")
    val_down_cnt = sum(1 for r in downgraded if r["handling_path"] == "POST_LLM_VALIDATOR_DOWNGRADE")
    lines4 = [
        "# 04. Đối Chiếu Phán Quyết Thô Của Qwen Với Kết Quả Sau Bộ Kiểm Chứng (`Task B.5`)",
        "",
        f"- Tổng số bản ghi trên 10 tệp JSONL: **`{len(comp_rows)}`** (`{llm_mode_count}` bản ghi ở 7 lượt gọi LLM, `{heur_only_count}` bản ghi ở 3 lượt `--mode heuristic`).",
        f"- Số bản ghi bị chặn trước khi gọi LLM hoặc bị bộ kiểm chứng hạ xuống `UNDETERMINED`: **`{len(downgraded)}`** (`{pre_llm_cnt}` bản ghi bị chặn pre-LLM do `CliCall`, `{parse_err_cnt}` bản ghi lỗi JSON parse ở `stage2_dev16_baseline_v1_0`, và `{val_down_cnt}` bản ghi bị bộ kiểm chứng trích dẫn hạ từ `SUPPORTED` xuống `UNDETERMINED`).",
        "",
        "| Run | `#` | File | CWE | Ground Truth | Heuristic `recommended_status` | Handling Path | Raw Qwen | Post-Validator | Lý do hạ cấp / Fallback |",
        "|---|---:|---|---|---|---|---|---|---|---|",
    ]
    for d in downgraded:
        lines4.append(
            f"| `{d['run_name']}` | `{d['finding_index']}` | `{d['file_path']}` | `{d['cwe']}` | "
            f"`{d['ground_truth']}` | `{d['heuristic_recommended_status']}` | `{d['handling_path']}` | "
            f"`{d['raw_qwen_status']}` | `{d['post_validator_status']}` | `{d['downgrade_or_fallback_reason']}` |"
        )
    (out_dir / "04_raw_vs_post_validator_comparison.md").write_text("\n".join(lines4) + "\n", encoding="utf-8")

    # 5. Historical ground_truth_verifier.py MD
    lines5 = [
        "# 05. Biên Bản Truy Tìm & Xác Minh `scripts/ground_truth_verifier.py` (`Task C`)",
        "",
        f"- **Kết luận tái lập cho đồ án:** **`{gt_script_audit['thesis_gate_reproduction_status']}`** (`{gt_script_audit['classification']}`).",
        f"- **Đường dẫn thực tế tìm thấy:** `{gt_script_audit['located_script']['path']}`",
        f"- **SHA-256 của script:** `{gt_script_audit['located_script'].get('sha256')}` (`{gt_script_audit['located_script'].get('size_bytes')}` bytes, `{gt_script_audit['located_script'].get('line_count')}` dòng).",
        f"- **Biên nhận lịch sử tìm thấy:** `{gt_script_audit['historical_receipt_audit']['path']}` (`SHA-256 = {gt_script_audit['historical_receipt_audit'].get('sha256')}`, `verified_at = {gt_script_audit['historical_receipt_audit'].get('verified_at')}`).",
        f"- **Số hiện vật thuộc `ntk-thesis-v2` được kiểm tra qua cả 4 cổng:** **`{gt_script_audit['historical_receipt_audit'].get('thesis_artifacts_checked_across_all_4_gates')}`** (`0` tệp, `0` cổng mạng đồ án, `0` SQLite đồ án).",
        "",
        "## Giải thích nguyên nhân gốc rễ",
        gt_script_audit["why_missing_in_thesis_worktree"],
        "",
        "## Lý do không chạy lại chế độ ghi của script này",
        gt_script_audit["why_full_rerun_skipped"],
    ]
    (out_dir / "05_historical_ground_truth_verifier_audit.md").write_text("\n".join(lines5) + "\n", encoding="utf-8")

    # 6. OWASP & Manual Ground Truth CSV + MD
    with (out_dir / "06_owasp_and_manual_ground_truth_audit.csv").open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=["split", "test_name", "alert_id", "cwe", "owasp_cwe", "ground_truth", "owasp_expected_label", "sink_lines", "findings_in_file_count", "sink_token_verified"],
        )
        w.writeheader()
        w.writerows(gt_labels_audit["dev_set_16_audit"]["items"] + gt_labels_audit["heldout_set_40_audit"]["items"])

    lines6 = [
        "# 06. Kết Quả Kiểm Toán Nhãn Chuẩn OWASP Benchmark v1.2 & Nhãn Thủ Công Dự Án Thực Tế (`Task D`)",
        "",
        f"- `expectedresults-1.2.csv` SHA-256: `{gt_labels_audit['owasp_expectedresults_csv']['sha256']}` (khớp chuẩn: `{gt_labels_audit['owasp_expectedresults_csv']['matches_benchmark_v1_2_sha256']}`).",
        f"- `dev_set_16`: khớp nhãn OWASP `{gt_labels_audit['dev_set_16_audit']['owasp_label_matches']}/16`, khớp CWE `{gt_labels_audit['dev_set_16_audit']['owasp_cwe_matches']}/16`, khớp dòng sink Java `{gt_labels_audit['dev_set_16_audit']['sink_code_verified_count']}/16`.",
        f"- `heldout_set_40`: khớp nhãn OWASP `{gt_labels_audit['heldout_set_40_audit']['owasp_label_matches']}/40`, khớp CWE `{gt_labels_audit['heldout_set_40_audit']['owasp_cwe_matches']}/40`, khớp dòng sink Java `{gt_labels_audit['heldout_set_40_audit']['sink_code_verified_count']}/40`.",
        f"- Giao tập (`dev_set_16` vs `heldout_set_40`): `0` tệp trùng, `0` SHA-256 nguồn trùng, `0` `alert_id` trùng (`is_strictly_disjoint = {gt_labels_audit['overlap_verification']['is_strictly_disjoint']}`).",
        f"- `STRICT_LOCK`: `combined_lock_sha256 = {gt_labels_audit['strict_lock_verification']['recomputed_combined_lock_sha256']}` (`lock_hash_matches = {gt_labels_audit['strict_lock_verification']['lock_hash_matches']}`).",
        "",
        "## Đánh Giá Độc Lập 4 Cảnh Báo False Positive Thủ Công Trên Dự Án Thực Tế",
        "",
        "| `#` | Tệp & Dòng | CWE | Độ tin cậy nhãn FP | Bằng chứng mã nguồn độc lập (không dựa trên Qwen) |",
        "|---:|---|---|---|---|",
    ]
    for fp_item in gt_labels_audit["real_projects_20_manual_audit"]["four_manual_fps"]:
        lines6.append(
            f"| `{fp_item['finding_index']}` | `{fp_item['file_path']}:{fp_item['lines']}` | `{fp_item['cwe']}` | "
            f"`{fp_item['confidence']}` | {fp_item['independent_evidence']} |"
        )
    (out_dir / "06_owasp_and_manual_ground_truth_audit.md").write_text("\n".join(lines6) + "\n", encoding="utf-8")

    # 7. Independent Metrics Recomputation CSV + MD
    rows7_csv = []
    for arm_name, groups in metrics_audit["heldout_40_recomputed"].items():
        for grp_name, m in groups.items():
            rows7_csv.append(
                {
                    "dataset": "heldout_set_40",
                    "arm": arm_name,
                    "cwe_group": grp_name,
                    "total_alerts": m["total_alerts"],
                    "tp_kept_supported": m["tp_kept_supported"],
                    "fp_proposed_refuted": m["fp_proposed_refuted"],
                    "tp_erroneously_refuted": m["tp_erroneously_refuted"],
                    "fp_erroneously_kept_supported": m["fp_erroneously_kept_supported"],
                    "undetermined": m["undetermined_display"],
                    "coverage": m["coverage_display"],
                    "citation_matched": m["citation_matched_display"],
                    "drop_fp_precision": m["policy_drop_fp_precision"],
                    "drop_fp_recall": m["policy_drop_fp_recall"],
                    "keep_tp_only_precision": m["policy_keep_tp_only_precision"],
                    "keep_tp_only_recall": m["policy_keep_tp_only_recall"],
                    "mean_latency_ms": m["latency_ms"]["mean_ms"],
                    "total_time_s": m["latency_ms"]["total_s"],
                }
            )
    with (out_dir / "07_independent_metrics_recomputation.csv").open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows7_csv[0].keys()))
        w.writeheader()
        w.writerows(rows7_csv)

    lines7 = [
        "# 07. Tái Tính Độc Lập Các Chỉ Số & Kiểm Toán Nhất Quán Lịch Sử (`Task E & Task F`)",
        "",
        f"- Đối chiếu từng ô với `PAIRED_EVALUATION.csv`: số sai lệch = **`{len(metrics_audit['paired_evaluation_csv_cell_mismatches'])}`**.",
        "",
        "| Arm (`heldout_set_40`) | Nhóm | TP giữ (`SUPPORTED`) | FP bác bỏ (`REFUTED`) | Loại nhầm TP | FP lọt Nhóm 1 | `UNDETERMINED` | Coverage | Citation `MATCHED` | `drop_fp` Precision / Recall | `keep_tp_only` Precision / Recall | Mean ms / Total s |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r7 in rows7_csv:
        lines7.append(
            f"| `{r7['arm']}` | `{r7['cwe_group']}` | `{r7['tp_kept_supported']}` | `{r7['fp_proposed_refuted']}` | "
            f"`{r7['tp_erroneously_refuted']}` | `{r7['fp_erroneously_kept_supported']}` | `{r7['undetermined']}` | "
            f"`{r7['coverage']}` | `{r7['citation_matched']}` | `{r7['drop_fp_precision']} / {r7['drop_fp_recall']}` | "
            f"`{r7['keep_tp_only_precision']} / {r7['keep_tp_only_recall']}` | `{r7['mean_latency_ms']} / {r7['total_time_s']}s` |"
        )
    lines7.extend(["", "## Phát Hiện Kiểm Toán Nhất Quán Lịch Sử (`Task F`)", ""])
    for item in metrics_audit["historical_consistency_audit"]:
        lines7.append(f"### {item['check']} — `{item['status']}`")
        lines7.append(f"- **Sự thật trên đĩa:** {item['ground_truth_on_disk']}")
        lines7.append(f"- **Đối chiếu tài liệu:** {item['inconsistent_docs']}")
        lines7.append("")
    (out_dir / "07_independent_metrics_recomputation.md").write_text("\n".join(lines7) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run read-only server forensic audit on post-report evidence.")
    parser.add_argument(
        "--ntk-root",
        type=Path,
        default=Path(r"C:\Users\Admin\ntk-thesis-v2"),
    )
    parser.add_argument(
        "--worktree-root",
        type=Path,
        default=Path(r"C:\Users\Admin\ntk-thesis-v2\post-report-cwe22-cwe89"),
    )
    parser.add_argument(
        "--evidence-root",
        type=Path,
        default=Path(r"C:\Users\Admin\ntk-thesis-v2\evidence\post_report_cwe22_cwe89_20261112"),
    )
    parser.add_argument(
        "--advisor-zip",
        type=Path,
        default=None,
        help="Optional local path to reference zip archive (read-only checksum check; never committed).",
    )
    parser.add_argument(
        "--brain-root",
        type=Path,
        default=Path(r"C:\Users\Admin\AppData\Local\javis-os\brains-canhan\Brain Default"),
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path(r"C:\Users\Admin\ntk-thesis-v2\evidence\server_forensic_audit_20261112"),
    )
    parser.add_argument(
        "--skip-wsl",
        action="store_true",
        help="Skip WSL upstream git check (useful in unit tests).",
    )
    args = parser.parse_args(argv)

    args.out_dir.mkdir(parents=True, exist_ok=True)

    inv = build_file_inventory(args.evidence_root, args.worktree_root)
    (args.out_dir / "01_file_inventory_sha256.json").write_text(
        json.dumps(inv, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    wsl_info = {"skipped": True} if args.skip_wsl else query_wsl_upstream_hashes(args.evidence_root)
    scans = audit_opengrep_scans(args.evidence_root, args.worktree_root, args.advisor_zip, wsl_info)
    (args.out_dir / "02_raw_opengrep_scans_receipt.json").write_text(
        json.dumps(scans, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    ollama_audit, comp_rows = audit_all_10_assessments(args.evidence_root, args.worktree_root)
    (args.out_dir / "03_ollama_10_assessments_receipt.json").write_text(
        json.dumps(ollama_audit, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    gt_script_audit = audit_historical_ground_truth_verifier(args.ntk_root, args.brain_root)
    (args.out_dir / "05_historical_ground_truth_verifier_audit.json").write_text(
        json.dumps(gt_script_audit, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    gt_labels_audit = audit_ground_truth_labels(args.evidence_root, args.worktree_root)
    (args.out_dir / "06_owasp_and_manual_ground_truth_audit.json").write_text(
        json.dumps(gt_labels_audit, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    metrics_audit = recompute_metrics_and_consistency(args.evidence_root, args.worktree_root, comp_rows)
    (args.out_dir / "07_independent_metrics_recomputation.json").write_text(
        json.dumps(metrics_audit, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    write_markdown_deliverables(
        args.out_dir,
        inv,
        scans,
        ollama_audit,
        comp_rows,
        gt_script_audit,
        gt_labels_audit,
        metrics_audit,
    )

    pre_snap = args.out_dir / "_pre_audit_evidence_snapshot.json"
    immutability = (
        verify_evidence_root_immutability(pre_snap, args.evidence_root)
        if pre_snap.is_file()
        else {"zero_mutation_verified": None, "note": "No pre-snapshot file present"}
    )
    (args.out_dir / "immutability_verification.json").write_text(
        json.dumps(immutability, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    print(
        json.dumps(
            {
                "status": "AUDIT_COMPLETED",
                "out_dir": str(args.out_dir),
                "evidence_files_inventoried": inv["evidence_file_count"],
                "three_scans_sha_matched": [s["sha256_matched"] for s in scans["three_primary_scans"]],
                "assessments_files_audited": ollama_audit["total_assessments_jsonl_files"],
                "total_assessment_records": ollama_audit["total_assessment_records_audited"],
                "paired_csv_mismatches": len(metrics_audit["paired_evaluation_csv_cell_mismatches"]),
                "thesis_ground_truth_script_status": gt_script_audit["thesis_gate_reproduction_status"],
                "zero_mutation_verified": immutability.get("zero_mutation_verified"),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
