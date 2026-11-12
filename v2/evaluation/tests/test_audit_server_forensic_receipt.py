"""Unit and 16 counter-factual integration tests for the fail-closed server forensic auditor.

Verifies Section VI & Section XIII requirements:
- Exit 0 (PASS): All mandatory acceptance criteria verified and passed.
- Exit 1 (FAIL): Any tampered, contradictory, or invalid evidence.
- Exit 2 (INCOMPLETE): Any missing mandatory file or unverified criterion; never coerced to PASS.
"""
from __future__ import annotations

import csv
import json
import shutil
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import pytest

from v2.evaluation.audit_server_forensic_receipt import (
    EXPECTED_RULESET_SHA,
    EXPECTED_SCAN_SHAS,
    MANDATORY_ASSESSMENT_RUNS,
    REAL_PROJECT_MANUAL_LABELS,
    _compute_bucket_metrics,
    main as audit_cli_main,
    verify_evidence_root_immutability,
)
from v2.evaluation.server_forensic_gates import (
    EXIT_FAIL,
    EXIT_INCOMPLETE,
    EXIT_PASS,
    evaluate_acceptance_gates,
)
from v2.evaluation.server_forensic_helpers import (
    compute_contract_alert_id,
    inspect_sqlite_readonly_copy,
    load_owasp_expected_csv,
    normalize_cwe,
    scan_json_for_forbidden_label_keys,
    sha256_bytes,
    sha256_file,
    sha256_lf_text,
    verify_sarif_against_opengrep_json,
)
from v2.triage import ollama as triage_ollama

REAL_EVIDENCE_ROOT = Path(r"C:\Users\Admin\ntk-thesis-v2\evidence\post_report_cwe22_cwe89_20261112")
REAL_WORKTREE_ROOT = Path(r"C:\Users\Admin\ntk-thesis-v2\post-report-cwe22-cwe89")


def _build_synthetic_sandbox(root: Path) -> tuple[Path, Path, Path]:
    """Build a self-contained deterministic sandbox when running on CI without ADMIN-PC evidence."""
    ev_root = root / "evidence"
    wt_root = root / "worktree"
    post_dir = wt_root / "v2" / "evaluation" / "post_report"
    rules_dir = post_dir / "rules"
    docs_dir = wt_root / "v2" / "docs"
    rules_dir.mkdir(parents=True, exist_ok=True)
    docs_dir.mkdir(parents=True, exist_ok=True)

    # Copy real ruleset & post_report files from current repo worktree if present
    repo_root = Path(__file__).resolve().parents[3]
    repo_rules = repo_root / "v2" / "evaluation" / "post_report" / "rules" / "p_java_cwe22_cwe89.yml"
    if repo_rules.is_file():
        shutil.copy2(repo_rules, rules_dir / "p_java_cwe22_cwe89.yml")
    else:
        rules_yaml = {"rules": [{"id": f"rule-{i}", "message": "m", "languages": ["java"], "severity": "ERROR"} for i in range(9)]}
        import yaml
        (rules_dir / "p_java_cwe22_cwe89.yml").write_text(yaml.safe_dump(rules_yaml), encoding="utf-8")
    rules_sha = sha256_file(rules_dir / "p_java_cwe22_cwe89.yml")

    # Create sources for dev_set_16, heldout_set_40, real_projects
    dev_src = ev_root / "sources" / "dev_set_16"
    held_src = ev_root / "sources" / "heldout_set_40"
    real_src = ev_root / "sources" / "real_projects"
    dev_src.mkdir(parents=True, exist_ok=True)
    held_src.mkdir(parents=True, exist_ok=True)
    real_src.mkdir(parents=True, exist_ok=True)

    owasp_lines = ["# test name, category, real vulnerability, cwe, benchmark version: 1.2"]
    for i in range(1, 17):
        tname = f"BenchmarkTest{i:05d}"
        cwe_num = "22" if i <= 8 else "89"
        is_tp = (i % 2 == 1)
        owasp_lines.append(f"{tname},{'pathtraver' if cwe_num == '22' else 'sqli'},{'true' if is_tp else 'false'},{cwe_num}")
        java_txt = (
            "package org.owasp.benchmark.testcode;\n"
            f"public class {tname} {{\n"
            "  public void doPost(String param) throws Exception {\n"
            + ("    java.io.FileInputStream fis = new java.io.FileInputStream(param);\n" if cwe_num == "22" else "    java.sql.Statement st = null; st.executeQuery(param);\n")
            + "  }\n}\n"
        )
        (dev_src / f"{tname}.java").write_text(java_txt, encoding="utf-8", newline="\n")

    for i in range(101, 141):
        idx0 = i - 101
        tname = f"BenchmarkTest{i:05d}"
        cwe_num = "22" if idx0 < 20 else "89"
        is_tp = (idx0 % 2 == 0)
        owasp_lines.append(f"{tname},{'pathtraver' if cwe_num == '22' else 'sqli'},{'true' if is_tp else 'false'},{cwe_num}")
        java_txt = (
            "package org.owasp.benchmark.testcode;\n"
            f"public class {tname} {{\n"
            "  public void doPost(String param) throws Exception {\n"
            + ("    java.io.FileInputStream fis = new java.io.FileInputStream(param);\n" if cwe_num == "22" else "    java.sql.Statement st = null; st.executeQuery(param);\n")
            + "  }\n}\n"
        )
        (held_src / f"{tname}.java").write_text(java_txt, encoding="utf-8", newline="\n")

    owasp_csv = ev_root / "sources" / "expectedresults-1.2.csv"
    owasp_csv.write_text("\n".join(owasp_lines) + "\n", encoding="utf-8", newline="\n")
    owasp_csv_sha = sha256_file(owasp_csv)

    real_rel_files = [
        "WebGoat/Assignment5.java",
        "WebGoat/ProfileUploadRetrieval.java",
        "WebGoat/Servers.java",
        "WebGoat/SqlInjectionLesson5a.java",
        "WebGoat/SqlInjectionLesson8.java",
        "WebGoat/UserService.java",
        "demo/UserDao.java",
        "java-sec-code/SQLI.java",
    ]
    for rf in real_rel_files:
        fp = real_src / rf
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(
            "public class Sample {\n"
            "  public void sink(String s) throws Exception {\n"
            "    java.sql.Statement st = null; st.executeQuery(s);\n"
            "    java.io.File f = new java.io.File(s);\n"
            "  }\n}\n",
            encoding="utf-8",
            newline="\n",
        )

    def _make_scan(run_name: str, src_dir: Path, items: list[tuple[str, str, int]]) -> str:
        sdir = ev_root / "runs" / run_name
        sdir.mkdir(parents=True, exist_ok=True)
        results = []
        sarif_results = []
        scanned = []
        for rel_p, cwe_str, line_no in items:
            if rel_p not in scanned:
                scanned.append(rel_p)
            rule_id = "java.lang.security.audit.cwe-22-path-traversal" if "22" in cwe_str else "java.lang.security.audit.cwe-89-sqli"
            results.append(
                {
                    "check_id": rule_id,
                    "path": rel_p,
                    "start": {"line": line_no, "col": 5},
                    "end": {"line": line_no, "col": 40},
                    "extra": {
                        "message": "tainted sink",
                        "severity": "ERROR",
                        "metadata": {"cwe": [f"{cwe_str}: Sample"]},
                        "dataflow_trace": {
                            "taint_source": ["CliLoc", [{"path": rel_p, "start": {"line": 3, "col": 1}, "end": {"line": 3, "col": 10}}, "param"]],
                            "intermediate_vars": [],
                            "taint_sink": ["CliLoc", [{"path": rel_p, "start": {"line": line_no, "col": 5}, "end": {"line": line_no, "col": 40}}, "sink"]],
                        },
                    },
                }
            )
            sarif_results.append(
                {
                    "ruleId": rule_id,
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": rel_p},
                                "region": {"startLine": line_no, "endLine": line_no},
                            }
                        }
                    ],
                }
            )
        og_doc = {
            "version": "1.25.0",
            "results": results,
            "errors": [],
            "paths": {"scanned": scanned, "skipped": []},
        }
        og_bytes = json.dumps(og_doc, indent=2).encode("utf-8")
        (sdir / "opengrep.json").write_bytes(og_bytes)
        scan_sha = sha256_bytes(og_bytes)
        sarif_bytes = json.dumps({"version": "2.1.0", "runs": [{"results": sarif_results}]}, indent=2).encode("utf-8")
        (sdir / "opengrep.sarif").write_bytes(sarif_bytes)
        (sdir / "rules.snapshot.yml").write_bytes((rules_dir / "p_java_cwe22_cwe89.yml").read_bytes())

        ver_cmd = ["opengrep", "--version"]
        json_cmd = ["opengrep", "scan", "--json"]
        sarif_cmd = ["opengrep", "scan", "--sarif"]
        (sdir / "version.exit.txt").write_bytes(b"0\n")
        (sdir / "version.command.json").write_bytes(json.dumps(ver_cmd).encode("utf-8"))
        (sdir / "version.stdout.txt").write_bytes(b"1.25.0\n")
        (sdir / "json.exit.txt").write_bytes(b"0\n")
        (sdir / "json.command.json").write_bytes(json.dumps(json_cmd).encode("utf-8"))
        (sdir / "json.stdout.txt").write_bytes(og_bytes)
        (sdir / "sarif.exit.txt").write_bytes(b"0\n")
        (sdir / "sarif.command.json").write_bytes(json.dumps(sarif_cmd).encode("utf-8"))
        (sdir / "sarif.stdout.txt").write_bytes(sarif_bytes)

        artifact_names = [
            "opengrep.json",
            "opengrep.sarif",
            "rules.snapshot.yml",
            "version.exit.txt",
            "version.command.json",
            "version.stdout.txt",
            "json.exit.txt",
            "json.command.json",
            "json.stdout.txt",
            "sarif.exit.txt",
            "sarif.command.json",
            "sarif.stdout.txt",
        ]
        artifacts_map = {name: sha256_file(sdir / name) for name in artifact_names}
        src_map = {
            p.relative_to(src_dir).as_posix(): sha256_file(p)
            for p in sorted(src_dir.rglob("*.java"))
        }
        manifest = {
            "schema": "ntk-scan-capture-1",
            "producer": "v2.baseline.opengrep_runner",
            "signed_or_independently_attested": False,
            "success": True,
            "issues": [],
            "target_kind": "directory",
            "scan_sha256": scan_sha,
            "engine_exit_code": 0,
            "rules_before_sha256": rules_sha,
            "rules_after_sha256": rules_sha,
            "sources_before": src_map,
            "sources_after": src_map,
            "artifacts": artifacts_map,
            "runs": {
                "version": {"argv": ver_cmd, "exit_code": 0, "output_mode": "stdout"},
                "json": {"argv": json_cmd, "exit_code": 0, "output_mode": "stdout"},
                "sarif": {"argv": sarif_cmd, "exit_code": 0, "output_mode": "stdout"},
            },
        }
        (sdir / "scan-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return scan_sha

    dev_items = [(f"BenchmarkTest{i:05d}.java", "CWE-22" if i <= 8 else "CWE-89", 4) for i in range(1, 17)]
    held_items = [(f"BenchmarkTest{i:05d}.java", "CWE-22" if (i - 101) < 20 else "CWE-89", 4) for i in range(101, 141)]
    real_map_files = [
        ("WebGoat/Assignment5.java", "CWE-89", 3),
        ("WebGoat/Assignment5.java", "CWE-89", 3),
        ("WebGoat/ProfileUploadRetrieval.java", "CWE-22", 4),
        ("WebGoat/Servers.java", "CWE-89", 3),
        ("WebGoat/SqlInjectionLesson5a.java", "CWE-89", 3),
        ("WebGoat/SqlInjectionLesson5a.java", "CWE-89", 3),
        ("WebGoat/SqlInjectionLesson8.java", "CWE-89", 3),
        ("WebGoat/SqlInjectionLesson8.java", "CWE-89", 3),
        ("WebGoat/SqlInjectionLesson8.java", "CWE-89", 3),
        ("WebGoat/SqlInjectionLesson8.java", "CWE-89", 3),
        ("WebGoat/UserService.java", "CWE-89", 3),
        ("demo/UserDao.java", "CWE-89", 3),
        ("demo/UserDao.java", "CWE-89", 3),
        ("demo/UserDao.java", "CWE-89", 3),
        ("demo/UserDao.java", "CWE-89", 3),
        ("demo/UserDao.java", "CWE-22", 4),
        ("java-sec-code/SQLI.java", "CWE-89", 3),
        ("java-sec-code/SQLI.java", "CWE-89", 3),
        ("java-sec-code/SQLI.java", "CWE-89", 3),
        ("java-sec-code/SQLI.java", "CWE-89", 3),
    ]

    dev_scan_sha = _make_scan("stage1_dev_set_16_scan", dev_src, dev_items)
    held_scan_sha = _make_scan("stage1_heldout_set_40_scan", held_src, held_items)
    real_scan_sha = _make_scan("stage5_real_projects_scan", real_src, real_map_files)

    # Write labels_development.json, labels_heldout.json, heldout_alerts.json, heldout_strict_lock_manifest.json
    from v2.evaluation import validate_pilot_lock

    def _build_labels(scan_sha: str, src_dir: Path, items: list[tuple[str, str, int]], is_dev: bool) -> dict[str, Any]:
        lbls = []
        for idx, (rel_p, cwe_str, line_no) in enumerate(items):
            aid = compute_contract_alert_id(scan_sha, idx)
            tnum = int(rel_p[len("BenchmarkTest") : -len(".java")])
            is_tp = (tnum % 2 == 1) if is_dev else ((idx % 2) == 0)
            lbls.append(
                {
                    "alert_id": aid,
                    "finding_index": idx,
                    "scan_sha256": scan_sha,
                    "file_path": rel_p,
                    "source_sha256": sha256_file(src_dir / rel_p),
                    "rule_id": "java.lang.security.audit.cwe-22-path-traversal" if "22" in cwe_str else "java.lang.security.audit.cwe-89-sqli",
                    "cwe": cwe_str,
                    "start_line": line_no,
                    "end_line": line_no,
                    "ground_truth": "TRUE_POSITIVE" if is_tp else "FALSE_POSITIVE",
                    "label_type": "INDEPENDENT_GROUND_TRUTH",
                    "label_source": "OWASP_BENCHMARK_1_2",
                    "annotator_id": "owasp-v1.2",
                    "annotated_at": "2026-11-12T00:00:00Z",
                    "rationale": "Verified OWASP Benchmark v1.2 ground truth sink.",
                }
            )
        return {"schema_version": "1.0", "scan_sha256": scan_sha, "labels": lbls}

    dev_lbl_doc = _build_labels(dev_scan_sha, dev_src, dev_items, is_dev=True)
    held_lbl_doc = _build_labels(held_scan_sha, held_src, held_items, is_dev=False)
    (post_dir / "labels_development.json").write_text(json.dumps(dev_lbl_doc, indent=2), encoding="utf-8")
    (post_dir / "labels_heldout.json").write_text(json.dumps(held_lbl_doc, indent=2), encoding="utf-8")
    held_og_raw = json.loads((ev_root / "runs" / "stage1_heldout_set_40_scan" / "opengrep.json").read_text(encoding="utf-8"))
    held_alerts_doc = {
        "scan_sha256": held_scan_sha,
        "results": [
            {
                **r,
                "alert_id": held_lbl_doc["labels"][idx]["alert_id"],
                "source_sha256": held_lbl_doc["labels"][idx]["source_sha256"],
            }
            for idx, r in enumerate(held_og_raw["results"])
        ],
    }
    (post_dir / "heldout_alerts.json").write_text(json.dumps(held_alerts_doc, indent=2), encoding="utf-8")

    lock_rep = validate_pilot_lock.validate_pilot_dataset(
        opengrep_data=json.loads((post_dir / "heldout_alerts.json").read_text(encoding="utf-8")),
        labels_data=held_lbl_doc,
        mode="STRICT_LOCK",
        source_root=held_src,
    )
    lock_man = validate_pilot_lock.create_lock_manifest(
        post_dir / "heldout_alerts.json",
        post_dir / "labels_heldout.json",
        mode="STRICT_LOCK",
        m4_acceptance_ready=lock_rep["m4_acceptance_ready"],
    )
    (post_dir / "heldout_strict_lock_manifest.json").write_text(json.dumps(lock_man, indent=2), encoding="utf-8")

    # Build the 10 assessment runs + SQLite + 6 checkpoints + PAIRED_EVALUATION.csv
    ckpt_dir = ev_root / "checkpoints"
    ckpt_dir.mkdir(parents=True, exist_ok=True)
    ckpt_runs = {
        "stage3_dev16_armC_evidence_llm",
        "stage3_dev16_armC_v2_1_evidence_llm",
        "stage3_dev16_armD_llm_ablation",
        "stage4_heldout40_armC_evidence_llm",
        "stage4_heldout40_armD_llm_ablation",
        "stage5_real_projects_armC_evidence_llm",
    }

    for rname, count in MANDATORY_ASSESSMENT_RUNS.items():
        rdir = ev_root / "runs" / rname
        rdir.mkdir(parents=True, exist_ok=True)
        if "dev16" in rname:
            scan_sha = dev_scan_sha
            src_dir = dev_src
            scan_src = ev_root / "runs" / "stage1_dev_set_16_scan" / "opengrep.json"
            items = dev_items
            gt_list = [x["ground_truth"] for x in dev_lbl_doc["labels"]]
        elif "heldout40" in rname:
            scan_sha = held_scan_sha
            src_dir = held_src
            scan_src = ev_root / "runs" / "stage1_heldout_set_40_scan" / "opengrep.json"
            items = held_items
            gt_list = [x["ground_truth"] for x in held_lbl_doc["labels"]]
        else:
            scan_sha = real_scan_sha
            src_dir = real_src
            scan_src = ev_root / "runs" / "stage5_real_projects_scan" / "opengrep.json"
            items = real_map_files
            gt_list = [REAL_PROJECT_MANUAL_LABELS[i]["label"] for i in range(20)]

        shutil.copy2(scan_src, rdir / "input.opengrep.json")
        is_heur = "armB_heuristic" in rname
        is_ablation = "armD_llm_ablation" in rname

        jsonl_lines = []
        conn = sqlite3.connect(str(rdir / "review.sqlite"))
        conn.execute("CREATE TABLE scans (id TEXT PRIMARY KEY, bundle TEXT)")
        conn.execute(
            "CREATE TABLE warnings (id TEXT PRIMARY KEY, scan_id TEXT, state TEXT, evidence TEXT, assessment TEXT)"
        )
        conn.execute(
            "CREATE TABLE events (sequence INTEGER PRIMARY KEY AUTOINCREMENT, warning_id TEXT NOT NULL, actor TEXT NOT NULL, timestamp TEXT NOT NULL, action TEXT NOT NULL, reason TEXT NOT NULL, source_version TEXT NOT NULL, observed_version TEXT NOT NULL, evidence_sha256 TEXT NOT NULL)"
        )
        conn.execute(
            "INSERT INTO scans VALUES (?, ?)",
            (scan_sha, json.dumps({"scan_sha256": scan_sha, "issues": []})),
        )

        tp_seen = 0
        fp_seen = 0
        for idx in range(count):
            rel_p, cwe_str, line_no = items[idx]
            aid = compute_contract_alert_id(scan_sha, idx)
            f_bytes = (src_dir / rel_p).read_bytes()
            f_sha = sha256_bytes(f_bytes)
            f_lines = f_bytes.decode("utf-8").splitlines()
            quote_txt = f_lines[line_no - 1]
            gt_val = gt_list[idx]
            if gt_val == "TRUE_POSITIVE":
                tp_seen += 1
                cur_tp_idx = tp_seen
            else:
                fp_seen += 1
                cur_fp_idx = fp_seen

            rec_status = (
                "SUPPORTED"
                if "real_projects" in rname
                else ("SUPPORTED" if gt_val == "TRUE_POSITIVE" else "REFUTED")
            )
            if is_heur:
                if "heldout40" in rname:
                    if gt_val == "TRUE_POSITIVE":
                        post_st = "SUPPORTED" if cur_tp_idx <= 9 else "UNDETERMINED"
                    else:
                        post_st = "REFUTED" if cur_fp_idx <= 7 else "UNDETERMINED"
                else:
                    post_st = "SUPPORTED"
                raw_st = "NO_LLM_CALL"
                lat_s = 0.0
            elif is_ablation and "heldout40" in rname:
                raw_st = "SUPPORTED"
                if gt_val == "TRUE_POSITIVE":
                    post_st = "UNDETERMINED" if cur_tp_idx > 17 else "SUPPORTED"
                else:
                    post_st = "UNDETERMINED" if cur_fp_idx > 14 else "SUPPORTED"
                lat_s = 7.52655
            elif "heldout40_armC" in rname:
                raw_st = rec_status
                post_st = rec_status
                lat_s = 10.525
            else:
                raw_st = rec_status
                post_st = rec_status
                lat_s = 5.0

            cites = (
                [
                    {
                        "path": rel_p,
                        "start_line": line_no,
                        "end_line": line_no,
                        "quote": quote_txt,
                        "sha256": f_sha,
                    }
                ]
                if post_st in ("SUPPORTED", "REFUTED")
                else []
            )
            rule_id_str = (
                "java.lang.security.audit.cwe-22-path-traversal"
                if "22" in cwe_str
                else "java.lang.security.audit.cwe-89-sqli"
            )
            ev_obj: dict[str, Any] = {
                "alert_id": aid,
                "scan_sha256": scan_sha,
                "root": str(src_dir),
                "path": rel_p,
                "rule_id": rule_id_str,
                "cwe": cwe_str,
                "triage_mode": "heuristic" if is_heur else ("llm" if is_ablation else "evidence+llm"),
                "issues": [],
                "scan_provenance": {"source_capture_verified": True},
                "snapshots": {rel_p: {"sha256": f_sha, "lines": f_lines}},
                "heuristic_signals": {
                    "recommended_status": rec_status,
                    "recommendation_reason": "synthetic pattern check",
                    "candidate_citations": cites,
                },
            }
            model_name = "heuristic-only" if is_heur else "qwen3.5:9b-q4_K_M"
            if is_heur:
                raw_resp = None
                rt_obj: dict[str, Any] = {}
            else:
                ans_obj = {"status": raw_st, "explanation": "ok", "citations": cites}
                raw_resp = {
                    "model": model_name,
                    "done": True,
                    "done_reason": "stop",
                    "eval_count": 64,
                    "message": {"role": "assistant", "content": json.dumps(ans_obj, ensure_ascii=False)},
                }
                resp_sha = sha256_bytes(
                    json.dumps(raw_resp, sort_keys=True, ensure_ascii=False, allow_nan=False).encode("utf-8")
                )
                req_payload = triage_ollama.request_payload(ev_obj, model_name)
                req_sha = sha256_bytes(json.dumps(req_payload).encode("utf-8"))
                rt_obj = {
                    "http_status": 200,
                    "response_json_sha256": resp_sha,
                    "request_payload_sha256": req_sha,
                }

            ass_obj = {
                "status": post_st,
                "citation_check": "MATCHED" if post_st in ("SUPPORTED", "REFUTED") else "NOT_VERIFIED",
                "citations": cites,
                "explanation": "synthetic explanation",
                "transport": "heuristic-only" if is_heur else "ollama-http",
                "model": model_name,
                "analyzed_at": "2026-11-12T01:00:00Z",
                "elapsed_seconds": lat_s,
                "raw_response": raw_resp,
                "runtime": rt_obj,
            }
            rec_obj = {
                "id": aid,
                "alert_id": aid,
                "scan_sha256": scan_sha,
                "state": "OPEN",
                "evidence": ev_obj,
                "assessment": ass_obj,
            }
            line_str = json.dumps(rec_obj, ensure_ascii=False)
            jsonl_lines.append(line_str)
            conn.execute(
                "INSERT INTO warnings VALUES (?, ?, 'OPEN', ?, ?)",
                (
                    aid,
                    scan_sha,
                    json.dumps(ev_obj, ensure_ascii=False, sort_keys=True),
                    json.dumps(ass_obj, ensure_ascii=False, sort_keys=True),
                ),
            )

        conn.commit()
        conn.close()
        (rdir / "assessments.jsonl").write_text("\n".join(jsonl_lines) + "\n", encoding="utf-8")
        if rname in ckpt_runs:
            (ckpt_dir / f"{rname}.ckpt.jsonl").write_text("\n".join(jsonl_lines) + "\n", encoding="utf-8")

    # Build PAIRED_EVALUATION.csv from heldout runs
    b_rows = [json.loads(x) for x in (ev_root / "runs" / "stage4_heldout40_armB_heuristic" / "assessments.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]
    c_rows = [json.loads(x) for x in (ev_root / "runs" / "stage4_heldout40_armC_evidence_llm" / "assessments.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]
    d_rows = [json.loads(x) for x in (ev_root / "runs" / "stage4_heldout40_armD_llm_ablation" / "assessments.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]

    csv_cols = [
        "alert_id",
        "finding_index",
        "scan_sha256",
        "source_sha256",
        "cwe",
        "rule_id",
        "path",
        "line",
        "verified_ground_truth",
        "label_type",
        "arm_a_opengrep_decision",
        "arm_b_heuristic_status",
        "arm_b_heuristic_decision",
        "arm_b_citation_check",
        "arm_c_qwen35_raw_status",
        "arm_c_qwen35_post_citation_status",
        "arm_c_qwen35_decision",
        "arm_c_citation_check",
        "arm_c_cited_lines",
        "arm_c_latency_ms",
        "arm_c_model_id",
        "arm_c_human_review_state",
        "arm_d_llm_ablation_raw_status",
        "arm_d_llm_ablation_decision",
        "arm_d_citation_check",
        "arm_d_latency_ms",
        "arm_c_explanation",
    ]
    with (post_dir / "PAIRED_EVALUATION.csv").open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=csv_cols)
        w.writeheader()
        for idx in range(40):
            lbl = held_lbl_doc["labels"][idx]
            rb, rc, rd = b_rows[idx]["assessment"], c_rows[idx]["assessment"], d_rows[idx]["assessment"]
            w.writerow(
                {
                    "alert_id": lbl["alert_id"],
                    "finding_index": str(idx),
                    "scan_sha256": held_scan_sha,
                    "source_sha256": lbl["source_sha256"],
                    "cwe": lbl["cwe"],
                    "rule_id": lbl["rule_id"],
                    "path": lbl["file_path"],
                    "line": str(lbl["start_line"]),
                    "verified_ground_truth": lbl["ground_truth"],
                    "label_type": lbl["label_type"],
                    "arm_a_opengrep_decision": "KEEP",
                    "arm_b_heuristic_status": rb["status"],
                    "arm_b_heuristic_decision": "KEEP_TP" if rb["status"] == "SUPPORTED" else ("PROPOSED_FP" if rb["status"] == "REFUTED" else "REVIEW"),
                    "arm_b_citation_check": rb["citation_check"],
                    "arm_c_qwen35_raw_status": rc["status"],
                    "arm_c_qwen35_post_citation_status": rc["status"],
                    "arm_c_qwen35_decision": "KEEP_TP" if rc["status"] == "SUPPORTED" else "PROPOSED_FP",
                    "arm_c_citation_check": rc["citation_check"],
                    "arm_c_cited_lines": str(lbl["start_line"]),
                    "arm_c_latency_ms": f"{rc['elapsed_seconds'] * 1000.0:.1f}",
                    "arm_c_model_id": rc["model"],
                    "arm_c_human_review_state": "OPEN",
                    "arm_d_llm_ablation_raw_status": "SUPPORTED",
                    "arm_d_llm_ablation_decision": "KEEP_TP" if rd["status"] == "SUPPORTED" else "REVIEW",
                    "arm_d_citation_check": rd["citation_check"],
                    "arm_d_latency_ms": f"{rd['elapsed_seconds'] * 1000.0:.2f}",
                    "arm_c_explanation": rc["explanation"],
                }
            )

    exp_hashes_path = root / "expected_hashes.json"
    exp_hashes_path.write_text(
        json.dumps(
            {
                "scan_shas": {
                    "stage1_dev_set_16_scan": dev_scan_sha,
                    "stage1_heldout_set_40_scan": held_scan_sha,
                    "stage5_real_projects_scan": real_scan_sha,
                },
                "ruleset_sha256": rules_sha,
                "owasp_csv_sha256": owasp_csv_sha,
                "strict_lock_sha256": lock_man["combined_lock_sha256"],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return ev_root, wt_root, exp_hashes_path


@pytest.fixture(scope="module")
def forensic_sandbox(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    """Create an isolated temporary sandbox (cloning real server evidence when available)."""
    base = tmp_path_factory.mktemp("server_forensic_sandbox")
    if REAL_EVIDENCE_ROOT.is_dir() and REAL_WORKTREE_ROOT.is_dir():
        ev_root = base / "evidence"
        wt_root = base / "worktree"
        shutil.copytree(REAL_EVIDENCE_ROOT, ev_root)
        (wt_root / "v2" / "evaluation").mkdir(parents=True, exist_ok=True)
        shutil.copytree(
            REAL_WORKTREE_ROOT / "v2" / "evaluation" / "post_report",
            wt_root / "v2" / "evaluation" / "post_report",
        )
        exp_hashes_path = base / "expected_hashes.json"
        exp_hashes_path.write_text(
            json.dumps(
                {
                    "scan_shas": dict(EXPECTED_SCAN_SHAS),
                    "ruleset_sha256": EXPECTED_RULESET_SHA,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    else:
        ev_root, wt_root, exp_hashes_path = _build_synthetic_sandbox(base)

    return {
        "base": base,
        "evidence_root": ev_root,
        "worktree_root": wt_root,
        "expected_hashes_json": exp_hashes_path,
    }


@contextmanager
def _backup_and_restore(paths: list[Path]) -> Iterator[None]:
    """Backup target sandbox files in memory and restore exact bytes & mtime after a counter-factual test."""
    saved: list[tuple[Path, bytes | None]] = []
    for p in paths:
        saved.append((p, p.read_bytes() if p.is_file() else None))
    try:
        yield
    finally:
        for p, raw in saved:
            if raw is None:
                if p.is_file():
                    p.unlink()
            else:
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(raw)


def _run_sandbox_audit(
    sandbox: dict[str, Path],
    out_dir: Path,
    extra_args: list[str] | None = None,
) -> tuple[int, dict[str, Any]]:
    argv = [
        "--evidence-root",
        str(sandbox["evidence_root"]),
        "--worktree-root",
        str(sandbox["worktree_root"]),
        "--expected-hashes-json",
        str(sandbox["expected_hashes_json"]),
        "--out-dir",
        str(out_dir),
        "--skip-wsl",
    ]
    if extra_args:
        argv.extend(extra_args)
    exit_code = audit_cli_main(argv)
    verdict_path = out_dir / "11_fail_closed_gate_verdict.json"
    verdict_doc = json.loads(verdict_path.read_text(encoding="utf-8"))
    return exit_code, verdict_doc


# ============================================================================
# Unit tests for core forensic helpers
# ============================================================================


def test_contract_alert_id_deterministic() -> None:
    scan_sha = "67c3b04903e75f4bd7294cb17452d0dcb2b6d56244330cec485c4422efabfa8b"
    aid0 = compute_contract_alert_id(scan_sha.upper(), 0)
    aid0_lower = compute_contract_alert_id(scan_sha.lower(), 0)
    assert aid0 == aid0_lower
    assert len(aid0) == 64
    assert aid0 != compute_contract_alert_id(scan_sha, 1)


def test_normalize_cwe_variants() -> None:
    assert normalize_cwe(["CWE-22: Improper Limitation of a Pathname"]) == "CWE-22"
    assert normalize_cwe("CWE-089") == "CWE-89"
    assert normalize_cwe("22") == "CWE-22"
    assert normalize_cwe("89") == "CWE-89"


def test_forbidden_label_key_scanner() -> None:
    clean_evidence = {
        "rule_id": "tainted-sql-string",
        "heuristic_signals": {
            "recommended_status": "REFUTED",
            "candidate_citations": [{"line": 10}],
        },
    }
    assert scan_json_for_forbidden_label_keys(clean_evidence) == []

    leaked_evidence = {
        "rule_id": "tainted-sql-string",
        "nested": [{"ground_truth": "TRUE_POSITIVE"}, {"annotated_by": "human"}],
    }
    hits = scan_json_for_forbidden_label_keys(leaked_evidence)
    assert "nested[0].ground_truth" in hits
    assert "nested[1].annotated_by" in hits


def test_owasp_expected_csv_parser(tmp_path: Path) -> None:
    csv_file = tmp_path / "expectedresults-1.2.csv"
    csv_file.write_text(
        "# test name, category, real vulnerability, cwe, benchmark version: 1.2\n"
        "BenchmarkTest00001,pathtraver,true,22\n"
        "BenchmarkTest00002,sqli,false,89\n",
        encoding="utf-8",
    )
    parsed = load_owasp_expected_csv(csv_file)
    assert parsed["BenchmarkTest00001"]["expected_label"] == "TRUE_POSITIVE"
    assert parsed["BenchmarkTest00001"]["cwe"] == "CWE-22"
    assert parsed["BenchmarkTest00002"]["expected_label"] == "FALSE_POSITIVE"
    assert parsed["BenchmarkTest00002"]["cwe"] == "CWE-89"


def test_sqlite_readonly_copy_preserves_original_bytes(tmp_path: Path) -> None:
    db_path = tmp_path / "review.sqlite"
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE scans (id TEXT PRIMARY KEY, bundle TEXT)")
    conn.execute("CREATE TABLE warnings (id TEXT PRIMARY KEY, scan_id TEXT, state TEXT)")
    conn.execute("CREATE TABLE events (sequence INTEGER PRIMARY KEY, warning_id TEXT, action TEXT)")
    conn.execute("INSERT INTO scans VALUES ('abc123', '{}')")
    conn.execute("INSERT INTO warnings VALUES ('w1', 'abc123', 'OPEN')")
    conn.commit()
    conn.close()

    before_sha = sha256_file(db_path)
    before_mtime = db_path.stat().st_mtime_ns

    info = inspect_sqlite_readonly_copy(db_path)
    assert info["present"] is True
    assert info["valid"] is True
    assert info["integrity_check"] == "ok"
    assert info["warning_states"] == {"OPEN": 1}
    assert info["human_events_count"] == 0
    assert sha256_file(db_path) == before_sha
    assert db_path.stat().st_mtime_ns == before_mtime


def test_bucket_metrics_drop_fp_and_keep_tp_only() -> None:
    rows = [
        {"ground_truth": "TRUE_POSITIVE", "post_status": "SUPPORTED", "citation_check": "MATCHED", "elapsed_seconds": 1.0},
        {"ground_truth": "TRUE_POSITIVE", "post_status": "UNDETERMINED", "citation_check": "NOT_VERIFIED", "elapsed_seconds": 2.0},
        {"ground_truth": "FALSE_POSITIVE", "post_status": "REFUTED", "citation_check": "MATCHED", "elapsed_seconds": 3.0},
        {"ground_truth": "FALSE_POSITIVE", "post_status": "UNDETERMINED", "citation_check": "NOT_VERIFIED", "elapsed_seconds": 4.0},
    ]
    m = _compute_bucket_metrics(rows)
    assert m["tp_kept_supported"] == "1/2"
    assert m["fp_proposed_refuted"] == "1/2"
    assert m["tp_erroneously_refuted"] == "0/2"
    assert m["undetermined_display"] == "2/4"
    assert m["policy_drop_fp_precision"] == "2/3"
    assert m["policy_drop_fp_recall"] == "2/2"
    assert m["policy_keep_tp_only_precision"] == "1/1"
    assert m["policy_keep_tp_only_recall"] == "1/2"


def test_evidence_immutability_detector(tmp_path: Path) -> None:
    ev_dir = tmp_path / "evidence"
    ev_dir.mkdir()
    f1 = ev_dir / "a.txt"
    f1.write_bytes(b"hello\r\nworld")
    assert sha256_lf_text(f1.read_bytes()) == sha256_bytes(b"hello\nworld")

    snap = tmp_path / "pre.json"
    snap.write_text(
        json.dumps(
            {
                "files": [
                    {
                        "rel_path": "a.txt",
                        "size_bytes": f1.stat().st_size,
                        "mtime_ns": f1.stat().st_mtime_ns,
                        "sha256": sha256_file(f1),
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    res_clean = verify_evidence_root_immutability(snap, ev_dir)
    assert res_clean["zero_mutation_verified"] is True

    f1.write_bytes(b"tampered")
    res_tampered = verify_evidence_root_immutability(snap, ev_dir)
    assert res_tampered["zero_mutation_verified"] is False
    assert len(res_tampered["modified_files"]) == 1


def test_sarif_crosscheck_detects_line_and_rule_mismatch() -> None:
    og_doc = {
        "results": [
            {"check_id": "rule-1", "path": "A.java", "start": {"line": 10}, "end": {"line": 10}},
            {"check_id": "rule-2", "path": "B.java", "start": {"line": 20}, "end": {"line": 22}},
        ]
    }
    sarif_ok = {
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "rule-1",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "A.java"},
                                    "region": {"startLine": 10, "endLine": 10},
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "rule-2",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "B.java"},
                                    "region": {"startLine": 20, "endLine": 22},
                                }
                            }
                        ],
                    },
                ]
            }
        ]
    }
    res_ok = verify_sarif_against_opengrep_json(og_doc, sarif_ok)
    assert res_ok["passed"] is True
    assert res_ok["order_preserved"] is True

    # Reordered SARIF results must still pass without false order dependency
    sarif_reordered = {
        "runs": [
            {
                "results": list(reversed(sarif_ok["runs"][0]["results"])),
            }
        ]
    }
    res_reordered = verify_sarif_against_opengrep_json(og_doc, sarif_reordered)
    assert res_reordered["passed"] is True
    assert res_reordered["order_preserved"] is False

    sarif_bad = json.loads(json.dumps(sarif_ok))
    sarif_bad["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] = 99
    res_bad = verify_sarif_against_opengrep_json(og_doc, sarif_bad)
    assert res_bad["passed"] is False
    assert any("lines=10-10" in m for m in res_bad["mismatches"])
    assert any("lines=99-10" in m for m in res_bad["mismatches"])


# ============================================================================
# Baseline PASS + 16 Mandatory Counter-Factual Integration Tests (Section XIII)
# ============================================================================


def test_baseline_untampered_sandbox_passes_exit_0(
    forensic_sandbox: dict[str, Path], tmp_path: Path
) -> None:
    code, verdict = _run_sandbox_audit(forensic_sandbox, tmp_path / "out_pass")
    assert code == EXIT_PASS == 0
    assert verdict["overall_verdict"] == "PASS"
    assert verdict["passed_count"] == 9
    assert verdict["failed_criteria"] == []
    assert verdict["incomplete_criteria"] == []


def test_synthetic_ci_sandbox_passes_all_9_gates(tmp_path: Path) -> None:
    ev_root, wt_root, exp_hashes_path = _build_synthetic_sandbox(tmp_path / "syn_ci")
    syn_box = {
        "evidence_root": ev_root,
        "worktree_root": wt_root,
        "expected_hashes_json": exp_hashes_path,
    }
    code, verdict = _run_sandbox_audit(syn_box, tmp_path / "out_syn_ci")
    assert code == EXIT_PASS == 0
    assert verdict["overall_verdict"] == "PASS"
    assert verdict["passed_count"] == 9
    assert verdict["failed_criteria"] == []
    assert verdict["incomplete_criteria"] == []


def test_cf01_missing_raw_opengrep_returns_incomplete_exit_2(
    forensic_sandbox: dict[str, Path], tmp_path: Path
) -> None:
    """1. Thiếu raw OpenGrep -> Exit 2 (INCOMPLETE)."""
    target = forensic_sandbox["evidence_root"] / "runs" / "stage1_heldout_set_40_scan" / "opengrep.json"
    with _backup_and_restore([target]):
        target.unlink()
        code, verdict = _run_sandbox_audit(forensic_sandbox, tmp_path / "out_cf01")
        assert code == EXIT_INCOMPLETE == 2
        assert verdict["overall_verdict"] == "INCOMPLETE"


def test_cf02_missing_scan_manifest_returns_incomplete_exit_2(
    forensic_sandbox: dict[str, Path], tmp_path: Path
) -> None:
    """2. Thiếu scan manifest -> Exit 2 (INCOMPLETE)."""
    target = forensic_sandbox["evidence_root"] / "runs" / "stage1_heldout_set_40_scan" / "scan-manifest.json"
    with _backup_and_restore([target]):
        target.unlink()
        code, verdict = _run_sandbox_audit(forensic_sandbox, tmp_path / "out_cf02")
        assert code == EXIT_INCOMPLETE == 2
        assert verdict["overall_verdict"] == "INCOMPLETE"


def test_cf03_wrong_sha_returns_fail_exit_1(
    forensic_sandbox: dict[str, Path], tmp_path: Path
) -> None:
    """3. Sai SHA -> Exit 1 (FAIL)."""
    bad_hashes = tmp_path / "bad_hashes.json"
    bad_hashes.write_text(
        json.dumps(
            {
                "scan_shas": {
                    "stage1_heldout_set_40_scan": "0" * 64,
                }
            }
        ),
        encoding="utf-8",
    )
    code, verdict = _run_sandbox_audit(
        forensic_sandbox,
        tmp_path / "out_cf03",
        extra_args=["--expected-hashes-json", str(bad_hashes)],
    )
    assert code == EXIT_FAIL == 1
    assert verdict["overall_verdict"] == "FAIL"
    assert "C02_opengrep_three_scans_and_9_rules" in verdict["failed_criteria"]


def test_cf04_wrong_tp_fp_label_returns_fail_exit_1(
    forensic_sandbox: dict[str, Path], tmp_path: Path
) -> None:
    """4. Sai một nhãn TP/FP -> Exit 1 (FAIL)."""
    lbl_path = forensic_sandbox["worktree_root"] / "v2" / "evaluation" / "post_report" / "labels_heldout.json"
    with _backup_and_restore([lbl_path]):
        doc = json.loads(lbl_path.read_text(encoding="utf-8"))
        orig = doc["labels"][0]["ground_truth"]
        doc["labels"][0]["ground_truth"] = "FALSE_POSITIVE" if orig == "TRUE_POSITIVE" else "TRUE_POSITIVE"
        lbl_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")

        code, verdict = _run_sandbox_audit(forensic_sandbox, tmp_path / "out_cf04")
        assert code == EXIT_FAIL == 1
        assert verdict["overall_verdict"] == "FAIL"
        assert "C06_ground_truth_56_owasp_and_20_real_projects" in verdict["failed_criteria"]


def test_cf05_swapped_cwe_returns_fail_exit_1(
    forensic_sandbox: dict[str, Path], tmp_path: Path
) -> None:
    """5. Đổi CWE -> Exit 1 (FAIL)."""
    csv_path = forensic_sandbox["worktree_root"] / "v2" / "evaluation" / "post_report" / "PAIRED_EVALUATION.csv"
    with _backup_and_restore([csv_path]):
        with csv_path.open("r", encoding="utf-8-sig", newline="") as fh:
            reader = csv.DictReader(fh)
            fieldnames = list(reader.fieldnames or [])
            rows = list(reader)
        rows[0]["cwe"] = "CWE-89" if "22" in rows[0]["cwe"] else "CWE-22"
        with csv_path.open("w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=fieldnames)
            w.writeheader()
            w.writerows(rows)

        code, verdict = _run_sandbox_audit(forensic_sandbox, tmp_path / "out_cf05")
        assert code == EXIT_FAIL == 1
        assert verdict["overall_verdict"] == "FAIL"
        assert "C05_paired_evaluation_per_alert_table" in verdict["failed_criteria"]


def test_cf06_duplicate_alert_id_returns_fail_exit_1(
    forensic_sandbox: dict[str, Path], tmp_path: Path
) -> None:
    """6. Trùng alert_id -> Exit 1 (FAIL)."""
    csv_path = forensic_sandbox["worktree_root"] / "v2" / "evaluation" / "post_report" / "PAIRED_EVALUATION.csv"
    with _backup_and_restore([csv_path]):
        with csv_path.open("r", encoding="utf-8-sig", newline="") as fh:
            reader = csv.DictReader(fh)
            fieldnames = list(reader.fieldnames or [])
            rows = list(reader)
        rows[1]["alert_id"] = rows[0]["alert_id"]
        with csv_path.open("w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=fieldnames)
            w.writeheader()
            w.writerows(rows)

        code, verdict = _run_sandbox_audit(forensic_sandbox, tmp_path / "out_cf06")
        assert code == EXIT_FAIL == 1
        assert verdict["overall_verdict"] == "FAIL"
        assert "C05_paired_evaluation_per_alert_table" in verdict["failed_criteria"]


def test_cf07_missing_alert_in_arm_c_returns_fail_exit_1(
    forensic_sandbox: dict[str, Path], tmp_path: Path
) -> None:
    """7. Thiếu alert trong Arm C -> Exit 1 (FAIL)."""
    arm_c_path = (
        forensic_sandbox["evidence_root"]
        / "runs"
        / "stage4_heldout40_armC_evidence_llm"
        / "assessments.jsonl"
    )
    with _backup_and_restore([arm_c_path]):
        lines = [ln for ln in arm_c_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        arm_c_path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")

        code, verdict = _run_sandbox_audit(forensic_sandbox, tmp_path / "out_cf07")
        assert code == EXIT_FAIL == 1
        assert verdict["overall_verdict"] == "FAIL"
        assert "C03_ollama_10_assessments_and_6_checkpoints" in verdict["failed_criteria"]
        assert "C05_paired_evaluation_per_alert_table" in verdict["failed_criteria"]


def test_cf08_changed_arm_b_status_returns_fail_exit_1(
    forensic_sandbox: dict[str, Path], tmp_path: Path
) -> None:
    """8. Đổi trạng thái Arm B -> Exit 1 (FAIL)."""
    csv_path = forensic_sandbox["worktree_root"] / "v2" / "evaluation" / "post_report" / "PAIRED_EVALUATION.csv"
    with _backup_and_restore([csv_path]):
        with csv_path.open("r", encoding="utf-8-sig", newline="") as fh:
            reader = csv.DictReader(fh)
            fieldnames = list(reader.fieldnames or [])
            rows = list(reader)
        rows[0]["arm_b_heuristic_status"] = (
            "REFUTED" if rows[0]["arm_b_heuristic_status"] != "REFUTED" else "SUPPORTED"
        )
        with csv_path.open("w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=fieldnames)
            w.writeheader()
            w.writerows(rows)

        code, verdict = _run_sandbox_audit(forensic_sandbox, tmp_path / "out_cf08")
        assert code == EXIT_FAIL == 1
        assert verdict["overall_verdict"] == "FAIL"
        assert "C05_paired_evaluation_per_alert_table" in verdict["failed_criteria"]


def test_cf09_changed_arm_d_post_validator_status_returns_fail_exit_1(
    forensic_sandbox: dict[str, Path], tmp_path: Path
) -> None:
    """9. Đổi trạng thái hậu kiểm Arm D -> Exit 1 (FAIL)."""
    csv_path = forensic_sandbox["worktree_root"] / "v2" / "evaluation" / "post_report" / "PAIRED_EVALUATION.csv"
    with _backup_and_restore([csv_path]):
        with csv_path.open("r", encoding="utf-8-sig", newline="") as fh:
            reader = csv.DictReader(fh)
            fieldnames = list(reader.fieldnames or [])
            rows = list(reader)
        rows[0]["arm_d_llm_ablation_decision"] = (
            "PROPOSED_FP" if rows[0]["arm_d_llm_ablation_decision"] != "PROPOSED_FP" else "KEEP_TP"
        )
        with csv_path.open("w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=fieldnames)
            w.writeheader()
            w.writerows(rows)

        code, verdict = _run_sandbox_audit(forensic_sandbox, tmp_path / "out_cf09")
        assert code == EXIT_FAIL == 1
        assert verdict["overall_verdict"] == "FAIL"
        assert "C05_paired_evaluation_per_alert_table" in verdict["failed_criteria"]


def test_cf10_compensating_latency_swap_returns_fail_exit_1(
    forensic_sandbox: dict[str, Path], tmp_path: Path
) -> None:
    """10. Đổi latency hai alert bù trừ nhau (tổng & trung bình không đổi) -> Exit 1 (FAIL)."""
    csv_path = forensic_sandbox["worktree_root"] / "v2" / "evaluation" / "post_report" / "PAIRED_EVALUATION.csv"
    with _backup_and_restore([csv_path]):
        with csv_path.open("r", encoding="utf-8-sig", newline="") as fh:
            reader = csv.DictReader(fh)
            fieldnames = list(reader.fieldnames or [])
            rows = list(reader)
        lat0 = float(rows[0]["arm_c_latency_ms"])
        lat1 = float(rows[1]["arm_c_latency_ms"])
        rows[0]["arm_c_latency_ms"] = f"{lat0 + 500.0:.3f}"
        rows[1]["arm_c_latency_ms"] = f"{lat1 - 500.0:.3f}"
        with csv_path.open("w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=fieldnames)
            w.writeheader()
            w.writerows(rows)

        code, verdict = _run_sandbox_audit(forensic_sandbox, tmp_path / "out_cf10")
        assert code == EXIT_FAIL == 1
        assert verdict["overall_verdict"] == "FAIL"
        assert "C05_paired_evaluation_per_alert_table" in verdict["failed_criteria"]


def test_cf11_citation_mismatch_against_source_returns_fail_exit_1(
    forensic_sandbox: dict[str, Path], tmp_path: Path
) -> None:
    """11. Citation sai mã nguồn -> Exit 1 (FAIL)."""
    arm_c_path = (
        forensic_sandbox["evidence_root"]
        / "runs"
        / "stage4_heldout40_armC_evidence_llm"
        / "assessments.jsonl"
    )
    with _backup_and_restore([arm_c_path]):
        rows = [json.loads(ln) for ln in arm_c_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        rows[0]["assessment"]["citations"][0]["quote"] = "// tampered non-existent quote on disk"
        arm_c_path.write_text(
            "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n",
            encoding="utf-8",
        )

        code, verdict = _run_sandbox_audit(forensic_sandbox, tmp_path / "out_cf11")
        assert code == EXIT_FAIL == 1
        assert verdict["overall_verdict"] == "FAIL"
        assert "C04_citations_and_post_validator_integrity" in verdict["failed_criteria"]


def test_cf12_invalid_ollama_response_returns_fail_exit_1(
    forensic_sandbox: dict[str, Path], tmp_path: Path
) -> None:
    """12. Ollama response không hợp lệ -> Exit 1 (FAIL)."""
    arm_c_path = (
        forensic_sandbox["evidence_root"]
        / "runs"
        / "stage4_heldout40_armC_evidence_llm"
        / "assessments.jsonl"
    )
    with _backup_and_restore([arm_c_path]):
        rows = [json.loads(ln) for ln in arm_c_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        rows[0]["assessment"]["raw_response"]["message"]["content"] = "{malformed_ollama_json"
        rows[0]["assessment"]["runtime"]["http_status"] = 500
        arm_c_path.write_text(
            "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n",
            encoding="utf-8",
        )

        code, verdict = _run_sandbox_audit(forensic_sandbox, tmp_path / "out_cf12")
        assert code == EXIT_FAIL == 1
        assert verdict["overall_verdict"] == "FAIL"
        assert "C03_ollama_10_assessments_and_6_checkpoints" in verdict["failed_criteria"]


def test_cf13_ollama_done_false_returns_fail_exit_1(
    forensic_sandbox: dict[str, Path], tmp_path: Path
) -> None:
    """13. done=false -> Exit 1 (FAIL)."""
    arm_c_path = (
        forensic_sandbox["evidence_root"]
        / "runs"
        / "stage4_heldout40_armC_evidence_llm"
        / "assessments.jsonl"
    )
    with _backup_and_restore([arm_c_path]):
        rows = [json.loads(ln) for ln in arm_c_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        rows[0]["assessment"]["raw_response"]["done"] = False
        arm_c_path.write_text(
            "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n",
            encoding="utf-8",
        )

        code, verdict = _run_sandbox_audit(forensic_sandbox, tmp_path / "out_cf13")
        assert code == EXIT_FAIL == 1
        assert verdict["overall_verdict"] == "FAIL"
        assert "C03_ollama_10_assessments_and_6_checkpoints" in verdict["failed_criteria"]


def test_cf14_sqlite_event_state_mismatch_returns_fail_exit_1(
    forensic_sandbox: dict[str, Path], tmp_path: Path
) -> None:
    """14. SQLite event không khớp trạng thái -> Exit 1 (FAIL)."""
    db_path = (
        forensic_sandbox["evidence_root"]
        / "runs"
        / "stage4_heldout40_armC_evidence_llm"
        / "review.sqlite"
    )
    with _backup_and_restore([db_path]):
        conn = sqlite3.connect(str(db_path))
        wid = str(conn.execute("SELECT id FROM warnings LIMIT 1").fetchone()[0])
        # Insert confirm-false event while leaving warnings.state == 'OPEN'
        cols = [c[1] for c in conn.execute("PRAGMA table_info(events)").fetchall()]
        if "source_version" in cols:
            conn.execute(
                "INSERT INTO events (warning_id, actor, timestamp, action, reason, source_version, observed_version, evidence_sha256) "
                "VALUES (?, 'auditor', '2026-11-12T00:00:00Z', 'confirm-false', 'contradictory event', '{}', '{}', ?)",
                (wid, "0" * 64),
            )
        elif "previous_state" in cols and "new_state" in cols:
            conn.execute(
                "INSERT INTO events (warning_id, action, previous_state, new_state, actor, reason, timestamp) "
                "VALUES (?, 'confirm-false', 'OPEN', 'CONFIRMED_FALSE', 'auditor', 'contradictory event', '2026-11-12T00:00:00Z')",
                (wid,),
            )
        else:
            conn.execute(
                "INSERT INTO events (warning_id, action, actor, reason, timestamp) "
                "VALUES (?, 'confirm-false', 'auditor', 'contradictory event', '2026-11-12T00:00:00Z')",
                (wid,),
            )
        conn.commit()
        conn.close()

        code, verdict = _run_sandbox_audit(forensic_sandbox, tmp_path / "out_cf14")
        assert code == EXIT_FAIL == 1
        assert verdict["overall_verdict"] == "FAIL"
        assert "C07_sqlite_readonly_and_stale_source_lifecycle" in verdict["failed_criteria"]


def test_cf15_wrong_source_hash_returns_fail_exit_1(
    forensic_sandbox: dict[str, Path], tmp_path: Path
) -> None:
    """15. Sai source hash -> Exit 1 (FAIL)."""
    held_src = forensic_sandbox["evidence_root"] / "sources" / "heldout_set_40"
    first_java = sorted(held_src.glob("*.java"))[0]
    with _backup_and_restore([first_java]):
        first_java.write_text(
            first_java.read_text(encoding="utf-8") + "\n// mutated source hash counter-factual\n",
            encoding="utf-8",
        )

        code, verdict = _run_sandbox_audit(forensic_sandbox, tmp_path / "out_cf15")
        assert code == EXIT_FAIL == 1
        assert verdict["overall_verdict"] == "FAIL"
        assert "C02_opengrep_three_scans_and_9_rules" in verdict["failed_criteria"]
        assert "C04_citations_and_post_validator_integrity" in verdict["failed_criteria"]
        assert "C05_paired_evaluation_per_alert_table" in verdict["failed_criteria"]


def test_cf16_incomplete_or_failed_evidence_with_force_pass_blocked(
    forensic_sandbox: dict[str, Path], tmp_path: Path
) -> None:
    """16. Không đủ bằng chứng nhưng chương trình định ghi PASS -> bị chặn (Exit 2 INCOMPLETE, không bao giờ Exit 0)."""
    code, verdict = _run_sandbox_audit(
        forensic_sandbox,
        tmp_path / "out_cf16",
        extra_args=["--skip-lifecycle-check", "--attempt-force-pass"],
    )
    assert code == EXIT_INCOMPLETE == 2
    assert verdict["overall_verdict"] == "INCOMPLETE"
    assert verdict["force_pass_attempt_blocked"] is True
    assert "C07_sqlite_readonly_and_stale_source_lifecycle" in verdict["incomplete_criteria"]

    # Also test direct gate evaluator when a criterion claims PASS with empty evidence dict
    direct_verdict = evaluate_acceptance_gates(
        {"C01_historical_immutability": {"status": "PASS", "issues": [], "evidence": {}}},
        attempt_force_pass=True,
    )
    assert direct_verdict["exit_code"] == EXIT_INCOMPLETE == 2
    assert direct_verdict["overall_verdict"] == "INCOMPLETE"
    assert direct_verdict["force_pass_attempt_blocked"] is True
