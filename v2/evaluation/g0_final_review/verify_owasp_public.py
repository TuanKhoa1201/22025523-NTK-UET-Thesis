"""Independent public re-check of the 56 OWASP Benchmark labels and source blobs (G0 final review).

Reads ONLY public data: OWASP-Benchmark/BenchmarkJava at a pinned commit (downloaded over HTTPS
into a cache directory OUTSIDE the repository) and the label files already published in this
repository (v2/evaluation/post_report/labels_{development,heldout}.json, unchanged since 86636b9).
It never reads private server evidence, never imports Codex/JavisOS auditors, and never uses a
published metric or another agent's receipt as an expected answer.

Exit codes: 0 = all compared fields equal; 2 = at least one mismatch; 3 = input unavailable.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import sys
import urllib.request
from pathlib import Path

OWASP_COMMIT = "8b67a88d73b2594570fc21150705283de884620b"
RAW_BASE = f"https://raw.githubusercontent.com/OWASP-Benchmark/BenchmarkJava/{OWASP_COMMIT}/"
TESTCODE = "src/main/java/org/owasp/benchmark/testcode/"
HELPERS = [
    "src/main/java/org/owasp/benchmark/helpers/SeparateClassRequest.java",
    "src/main/java/org/owasp/benchmark/helpers/ThingFactory.java",
    "src/main/java/org/owasp/benchmark/helpers/Thing1.java",
    "src/main/java/org/owasp/benchmark/helpers/Thing2.java",
]
REPO_ROOT = Path(__file__).resolve().parents[3]
LABEL_FILES = [
    REPO_ROOT / "v2/evaluation/post_report/labels_development.json",
    REPO_ROOT / "v2/evaluation/post_report/labels_heldout.json",
]


def git_blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def fetch(rel: str, cache: Path) -> bytes:
    target = cache / rel
    if target.is_file():
        return target.read_bytes()
    with urllib.request.urlopen(RAW_BASE + rel, timeout=60) as resp:
        data = resp.read()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return data


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cache", required=True, type=Path, help="download cache outside the repository")
    ap.add_argument("--codex-reference", type=Path, help="optional owasp_reference_blobs.json to cross-check")
    ap.add_argument("--excerpt", action="append", default=[], help="CASE:START-END line excerpt to print")
    args = ap.parse_args(argv)
    if args.cache.resolve().is_relative_to(REPO_ROOT):
        ap.error("cache must be outside the repository")
    mismatches: list[dict] = []
    try:
        csv_bytes = fetch("expectedresults-1.2.csv", args.cache)
        official = {r[0]: r for r in csv.reader(io.StringIO(csv_bytes.decode("utf-8"))) if r and not r[0].startswith("#")}
        labels = []
        for f in LABEL_FILES:
            labels += json.loads(f.read_text(encoding="utf-8"))["labels"]
        blobs = {"expectedresults-1.2.csv": git_blob(csv_bytes)}
        for rel in HELPERS:
            blobs[rel] = git_blob(fetch(rel, args.cache))
        counts = {"labels": 0, "TRUE_POSITIVE": 0, "FALSE_POSITIVE": 0}
        for lab in labels:
            name = lab["file_path"]
            case = Path(name).stem
            data = fetch(TESTCODE + name, args.cache)
            blobs[TESTCODE + name] = git_blob(data)
            row = official.get(case)
            if row is None:
                mismatches.append({"case": case, "field": "official_row", "expected": "present", "actual": None})
                continue
            exp_gt = "TRUE_POSITIVE" if row[2].strip() == "true" else "FALSE_POSITIVE"
            for field, exp, act in (
                ("cwe", "CWE-" + row[3].strip(), lab["cwe"]),
                ("ground_truth", exp_gt, lab["ground_truth"]),
                ("source_sha256", hashlib.sha256(data).hexdigest(), lab["source_sha256"]),
                ("category", {"22": "pathtraver", "89": "sqli"}.get(row[3].strip()), row[1].strip()),
            ):
                if exp != act:
                    mismatches.append({"case": case, "field": field, "expected": exp, "actual": act})
            lines = data.decode("utf-8").splitlines()
            if not (1 <= lab["start_line"] <= lab["end_line"] <= len(lines)):
                mismatches.append({"case": case, "field": "sink_range", "expected": f"1..{len(lines)}",
                                   "actual": [lab["start_line"], lab["end_line"]]})
            counts["labels"] += 1
            counts[lab["ground_truth"]] += 1
        ref_check = None
        if args.codex_reference:
            ref = json.loads(args.codex_reference.read_text(encoding="utf-8"))
            ref_map = {x["path"]: x["sha"] for x in ref["files"]}
            compared = [p for p in blobs if p in ref_map]
            diff = [p for p in compared if ref_map[p] != blobs[p]]
            ref_check = {"commit_matches": ref.get("commit") == OWASP_COMMIT, "compared": len(compared),
                         "mismatched": diff, "reference_only": sorted(set(ref_map) - set(blobs))}
            if diff or not ref_check["commit_matches"]:
                mismatches.append({"case": "*", "field": "codex_reference_blobs", "expected": "equal", "actual": diff})
        excerpts = {}
        for spec in args.excerpt:
            case, span = spec.split(":")
            a, b = (int(x) for x in span.split("-"))
            rel = case if "/" in case else TESTCODE + "BenchmarkTest" + case + ".java"
            text = fetch(rel, args.cache).decode("utf-8").splitlines()
            excerpts[spec] = [f"{i}: {text[i - 1]}" for i in range(a, min(b, len(text)) + 1)]
    except OSError as exc:
        print(json.dumps({"status": "INCOMPLETE", "error": f"{type(exc).__name__}: {exc}"}))
        return 3
    out = {"status": "FAIL" if mismatches else "PASS", "owasp_commit": OWASP_COMMIT,
           "official_csv_sha256": hashlib.sha256(csv_bytes).hexdigest(), "counts": counts,
           "mismatches": mismatches, "codex_reference_cross_check": ref_check, "excerpts": excerpts,
           "helper_blobs": {k: v for k, v in blobs.items() if "helpers" in k}}
    print(json.dumps(out, ensure_ascii=False, indent=1))
    return 2 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
