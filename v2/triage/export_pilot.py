"""Explicit adapter for Antigravity score_pilot; never creates ground-truth labels."""
import argparse
import json
from pathlib import Path
from .evidence import EvidenceError, strict_json, digest
from .runtime import SCHEMA_VERSION


def adapt(rows, raw_json):
    raw_bytes = raw_json if isinstance(raw_json, bytes) else raw_json.encode("utf-8")
    raw = strict_json(raw_bytes.decode("utf-8"))
    scan_sha = digest(raw_bytes)
    if not isinstance(raw, dict) or not isinstance(raw.get("results"), list):
        raise EvidenceError("raw OpenGrep results required for exact join")
    alerts, triage = [], []
    seen = set()
    for row in rows:
        record, assessment = row["evidence"], row["assessment"]
        identifier = record["id"]
        if record.get("alert_id", identifier) != identifier:
            raise EvidenceError("mismatched evidence alert_id alias")
        if record["scan_sha256"] != scan_sha:
            raise EvidenceError("assessment belongs to a different raw scan")
        for alias, expected in (("alert_id", identifier), ("scan_sha256", scan_sha)):
            if alias in row and row[alias] != expected:
                raise EvidenceError("mismatched assessment alias: " + alias)
        if identifier in seen or row["id"] != identifier:
            raise EvidenceError("duplicate or mismatched assessment ID")
        seen.add(identifier)
        index = record.get("finding_index")
        if index is None:
            index = row.get("finding_index")
        if index is None:
            index = next((i for i in range(len(raw["results"]))
                          if digest((scan_sha + ":" + str(i)).encode()) == identifier), None)
        if type(index) is not int or digest((record["scan_sha256"] + ":" + str(index)).encode()) != identifier:
            raise EvidenceError("missing/incorrect finding_index; join using original raw JSON before exporting legacy rows")
        if (not 0 <= index < len(raw["results"]) or
                json.dumps(raw["results"][index], sort_keys=True) != json.dumps(record["raw_finding"], sort_keys=True)):
            raise EvidenceError("raw finding differs at bound index")
        if "finding_index" in row and (type(row["finding_index"]) is not int or row["finding_index"] != index):
            raise EvidenceError("mismatched finding_index alias")
        finding = next((s for s in record["snippets"] if s["role"] == "finding"), None)
        path = finding["path"] if finding else str(record.get("path") or "").replace("\\", "/")
        sha = finding["sha256"] if finding else None
        cwes = record["cwe"]
        cwe = cwes[0].split(":", 1)[0].strip().upper() if cwes else "UNKNOWN_CWE"
        common = {"alert_id": identifier, "rule_id": record["rule_id"], "cwe": cwe,
                  "file_path": path, "start_line": (record.get("start") or {}).get("line"),
                  "end_line": (record.get("end") or {}).get("line"), "source_sha256": sha,
                  "scan_sha256": record["scan_sha256"], "finding_index": index}
        alerts.append(common)
        valid = not record["issues"] and assessment.get("citation_check") == "MATCHED"
        verdict = {"SUPPORTED": "KEEP_TP", "REFUTED": "PROPOSED_FP"}.get(assessment.get("status"), "REVIEW") if valid else "REVIEW"
        cited = sorted({line for c in assessment.get("citations", []) if c["path"] == path
                        for line in range(c["start_line"], c["end_line"] + 1)})
        if verdict == "PROPOSED_FP" and not cited:
            verdict = "REVIEW"  # scorer's line-only grounding cannot represent another file
        lines = [l["line"] for s in record["snippets"] if s["path"] == path for l in s["lines"]]
        elapsed = assessment.get("elapsed_seconds")
        triage.append({**common, "verdict": verdict, "model_status": assessment["status"],
                       "rationale": assessment["explanation"], "cited_lines": cited,
                       "context_start_line": min(lines) if lines else None, "context_end_line": max(lines) if lines else None,
                       "latency_ms": elapsed * 1000 if type(elapsed) in (int, float) and elapsed >= 0 else None,
                       "auto_dismissed": False, "human_confirmed": False, "human_review_required": True,
                       "runtime": assessment.get("runtime"), "citations": assessment.get("citations", [])})
    return {"schema_version": SCHEMA_VERSION, "alerts": alerts}, {"schema_version": SCHEMA_VERSION, "triage_results": triage}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("assessments", type=Path)
    parser.add_argument("--raw-json", type=Path, required=True, help="exact raw input.opengrep.json used for this run")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    rows = [strict_json(line) for line in args.assessments.read_text(encoding="utf-8").splitlines() if line.strip()]
    alerts, triage = adapt(rows, args.raw_json.read_bytes())
    args.output_dir.mkdir(parents=True, exist_ok=False)
    for name, data in (("alerts.json", alerts), ("triage.json", triage)):
        (args.output_dir / name).write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"Exported {len(rows)} paired records; no ground truth or human approval generated")


if __name__ == "__main__":
    main()
