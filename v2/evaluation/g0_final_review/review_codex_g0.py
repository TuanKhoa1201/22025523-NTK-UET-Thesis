"""Antigravity G0 final review helpers: acceptance-logic probes, a stricter proposed acceptance rule,
public-vs-resolution metric consistency, and a publication-safety scan of the Codex crosscheck set.

Read-only with respect to the Codex directory (default: env NTK_CODEX_CROSSCHECK). Uses only:
- Codex files as objects under review (never as expected answers),
- this repository's published post_report files (unchanged since 86636b9),
- public OWASP/WebGoat sources via verify_owasp_public.py / verify_manual_fp_sources.py.

Exit codes of the CLI: 0 = every check consistent, 2 = at least one defect found, 3 = input missing.
"""
from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import importlib.util
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CODEX_DIR = Path(os.environ.get("NTK_CODEX_CROSSCHECK", r"C:\NTK-G0-Safety\codex-publish-20261113\v2\crosscheck"))
PUBLIC_POST_REPORT = REPO_ROOT / "v2" / "evaluation" / "post_report"

# SHA-256 of the exact Codex artifacts reviewed on 2026-11-13 (pins the object under review).
REVIEWED_CODEX_SHA256 = {
    "resolve_g0.py": "265c36e2e2d07ea7f6bfd9422e077da0b9a1aca9f19530908da10aa1dc016f86",
    "audit_raw_bundle.py": "2e23fd50abaa8621fe5a1e549da40ceb798d46f06fe136258b7ebcedb9bed201",
    "recompute.py": "15ededf2ff8b695f0b36bb232c2947c013c1a11b60f3cce6bdd8a7caade52921",
    "G0_FINAL_RESOLUTION.json": "01f03b8dbf89ee42868f53bf1573a453491cf6c0116c4cb737083aa02205dda4",
    "G0_RAW_INDEPENDENT_VERDICT.json": "5b4a357cbbe0f9e3b249929835ab2cb5f629589e799b86bb4fb3150967c4d711",
    "G0_DISCREPANCY_REGISTER.csv": "be5805484279375a66f8a0dcd6ff66fae8be75bf4a1b19b8eba32597da4bd679",
    "G0_RESOLUTION_REGISTER.csv": "841187021a0e43651f7b7cf8448033fc30e455188dc25bb494a1d4a6ffc81c22",
}

# --- Proposed stricter acceptance (offered to Codex as a patch; does not alter Codex files) ---------
REQUIRED_PASS = (
    "transfer_integrity", "scan_development", "scan_heldout", "scan_manual",
    "owasp_labels_and_sources", "heldout_published_comparison", "immutability",
    # Every held-out arm that feeds a published metric must itself have been re-derived from raw.
    "run_stage4_heldout40_armB_heuristic", "run_stage4_heldout40_armC_evidence_llm",
    "run_stage4_heldout40_armD_llm_ablation",
)
# FAIL rows that are documentation/rationale text only and have a sourced correction in G0_ERRATA.md.
# Listed explicitly so that the same rule gives the same answer for the raw and the merged register.
DOC_ONLY_FAIL = frozenset({
    ("document_consistency", "manual.total_seconds"),
    ("document_consistency", "manual.mean_seconds"),
    ("document_consistency", "Arm D FP CWE-22"),
    ("document_consistency", "Arm D FP CWE-89"),
    ("annotation_rationale", "annotator_rationale / sanitizer_or_reason"),
})
# A not-measured latency is a documented absence; anything else open in the aggregate check blocks.
_LATENCY_RE = re.compile(r"(mean|p50|p95)_latency_ms not verifiable")


def proposed_acceptance(criteria: dict, register: list, csv_rows_equal: bool):
    """Return (verdict, open_criteria, reasons). Conditions are derived from data, not hard-coded."""
    reasons = []
    for key in REQUIRED_PASS:
        if criteria.get(key) != "PASS":
            reasons.append(f"required criterion {key} is {criteria.get(key)!r}")
    if not csv_rows_equal:
        reasons.append("published paired CSV differs from raw rows/columns")
    agg = criteria.get("heldout_aggregate_comparison")
    if agg not in ("PASS", "INCOMPLETE"):
        reasons.append(f"heldout_aggregate_comparison is {agg!r}")
    for row in register:
        if row.get("criterion") == "heldout_aggregate_comparison" and row.get("status") == "INCOMPLETE":
            if not _LATENCY_RE.search(str(row.get("actual", ""))):
                reasons.append("aggregate comparison incomplete for a non-latency field: " + str(row.get("actual"))[:80])
        if row.get("status") == "FAIL" and (row.get("criterion"), row.get("field")) not in DOC_ONLY_FAIL:
            reasons.append(f"unresolved FAIL {row.get('criterion')}/{row.get('field')}")
    open_criteria = sorted({r["criterion"] for r in register if r.get("status") == "INCOMPLETE"}
                           | {k for k, v in criteria.items() if v == "INCOMPLETE"})
    return ("BLOCKED" if reasons else "CONDITIONAL"), open_criteria, reasons


# --- Helpers ---------------------------------------------------------------------------------------
def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_codex_module(codex_dir: Path, name: str):
    """Import a Codex module from its directory without writing bytecode into it."""
    sys.dont_write_bytecode = True
    if str(codex_dir) not in sys.path:
        sys.path.insert(0, str(codex_dir))
    spec = importlib.util.spec_from_file_location(name, codex_dir / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def hardcoded_report_fields(resolve_src: str) -> dict:
    """Find report-dict keys in resolve_g0.main() whose values are literals (not computed)."""
    tree = ast.parse(resolve_src)
    out = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            keys = [k.value for k in node.keys if isinstance(k, ast.Constant)]
            if "G0_AUDIT_COMPLETED" in keys:
                for k, v in zip(node.keys, node.values):
                    if isinstance(k, ast.Constant):
                        literal = isinstance(v, ast.Constant) or (
                            isinstance(v, (ast.Dict, ast.List)) and all(
                                isinstance(x, ast.Constant) for x in ast.walk(v) if isinstance(x, ast.expr)
                                and not isinstance(x, (ast.Dict, ast.List))))
                        out[k.value] = literal
    return out


def public_heldout_matrix() -> dict:
    labels = {r["alert_id"]: r for r in json.loads((PUBLIC_POST_REPORT / "labels_heldout.json").read_text("utf-8"))["labels"]}
    rows = list(csv.DictReader((PUBLIC_POST_REPORT / "PAIRED_EVALUATION.csv").open(encoding="utf-8", newline="")))
    dec = {"KEEP_TP": "SUPPORTED", "PROPOSED_FP": "REFUTED", "REVIEW": "UNDETERMINED"}
    post = {"A": Counter(), "B": Counter(), "C": Counter(), "D": Counter()}
    raw = {"C": Counter(), "D": Counter()}
    latency = {"C": 0.0, "D": 0.0}
    for r in rows:
        gt = labels[r["alert_id"]]["ground_truth"]
        post["A"][(gt, "SUPPORTED")] += 1
        post["B"][(gt, r["arm_b_heuristic_status"])] += 1
        post["C"][(gt, r["arm_c_qwen35_post_citation_status"])] += 1
        post["D"][(gt, dec[r["arm_d_llm_ablation_decision"]])] += 1
        raw["C"][(gt, r["arm_c_qwen35_raw_status"])] += 1
        raw["D"][(gt, r["arm_d_llm_ablation_raw_status"])] += 1
        latency["C"] += float(r["arm_c_latency_ms"])
        latency["D"] += float(r["arm_d_latency_ms"])
    return {"post": post, "raw": raw, "latency": latency, "n": len(rows)}


def consistency_with_public(resolution: dict) -> list:
    """Codex raw-derived held-out matrices vs. this repository's published per-alert CSV (replay level)."""
    pub = public_heldout_matrix()
    problems = []
    for arm in "ABCD":
        m = resolution["heldout_metrics"][arm]["ALL"]["post_gt_matrix"]
        for gt, states in m.items():
            for st, n in states.items():
                if pub["post"][arm][(gt, st)] != n:
                    problems.append(f"{arm} post {gt}/{st}: codex {n} vs public {pub['post'][arm][(gt, st)]}")
    for arm in "CD":
        m = resolution["heldout_metrics"][arm]["ALL"]["raw_gt_matrix"]
        for gt, states in m.items():
            for st, n in states.items():
                if pub["raw"][arm][(gt, st)] != n:
                    problems.append(f"{arm} raw {gt}/{st}: codex {n} vs public {pub['raw'][arm][(gt, st)]}")
        total = float(resolution["heldout_metrics"][arm]["ALL"]["latency"]["observed_total_ms"])
        if abs(total - pub["latency"][arm]) > 0.5:
            problems.append(f"{arm} latency total codex {total} vs public {pub['latency'][arm]}")
    return problems


ABS_PATH_RE = re.compile(r"(?i)\b[A-Z]:[\\/]+(?:\\\\)?Users[\\/]+(?:\\\\)?[^\\/\s\"'`|,)]+[^\s\"'`|,)]*")
SECRET_RES = {
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    "bearer": re.compile(r"(?i)bearer\s+[A-Za-z0-9._-]{12,}"),
    "password_assignment": re.compile(r"(?i)password\s*[:=]\s*\S"),
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]{2,}"),
    "chat_messages": re.compile(r'"messages"\s*:\s*\['),
    "raw_model_response": re.compile(r'"raw_response"\s*:\s*\{'),
}


def publication_scan(codex_dir: Path) -> dict:
    paths, secrets = [], []
    for f in sorted(p for p in codex_dir.rglob("*") if p.is_file()):
        for n, line in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            for m in ABS_PATH_RE.finditer(line):
                paths.append({"file": f.relative_to(codex_dir).as_posix(), "line": n, "path": m.group(0)})
            for name, rx in SECRET_RES.items():
                if rx.search(line):
                    secrets.append({"file": f.relative_to(codex_dir).as_posix(), "line": n, "kind": name})
    return {"absolute_user_paths": paths, "secret_like": secrets,
            "files": sum(1 for p in codex_dir.rglob("*") if p.is_file())}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--codex-dir", type=Path, default=DEFAULT_CODEX_DIR)
    args = ap.parse_args(argv)
    cx = args.codex_dir
    if not (cx / "resolve_g0.py").is_file():
        print(json.dumps({"status": "INCOMPLETE", "reason": f"Codex directory not readable: {cx}"}))
        return 3
    pins = {n: {"expected": h, "actual": sha256_file(cx / n)} for n, h in REVIEWED_CODEX_SHA256.items()}
    resolve = load_codex_module(cx, "resolve_g0")
    verdict = json.loads((cx / "G0_RAW_INDEPENDENT_VERDICT.json").read_text("utf-8"))
    resolution = json.loads((cx / "G0_FINAL_RESOLUTION.json").read_text("utf-8"))
    published_inputs = {"criteria": verdict["criteria"], "register": verdict["register"]}
    out = {
        "codex_pins_match": all(v["expected"] == v["actual"] for v in pins.values()),
        "codex_acceptance_on_published_verdict": resolve.acceptance(published_inputs, {"rows_columns_equal": True}),
        "codex_resolution_declares": resolution["G0_ACCEPTANCE"],
        "proposed_acceptance_on_published_verdict": proposed_acceptance(verdict["criteria"], verdict["register"], True),
        "hardcoded_report_fields": hardcoded_report_fields((cx / "resolve_g0.py").read_text("utf-8")),
        "public_consistency_problems": consistency_with_public(resolution),
        "publication_scan": publication_scan(cx),
        "acceptance_statements": {
            "G0_RAW_INDEPENDENT_VERDICT.json:g0_acceptance": verdict.get("g0_acceptance"),
            "G0_FINAL_RESOLUTION.json:G0_ACCEPTANCE": resolution.get("G0_ACCEPTANCE"),
        },
    }
    defects = (not out["codex_pins_match"]) or out["public_consistency_problems"] or \
        out["codex_acceptance_on_published_verdict"] != out["codex_resolution_declares"] or \
        out["publication_scan"]["absolute_user_paths"] or out["publication_scan"]["secret_like"]
    print(json.dumps(out, ensure_ascii=False, indent=1, default=str))
    return 2 if defects else 0


if __name__ == "__main__":
    sys.exit(main())
