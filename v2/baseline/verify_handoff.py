"""Verify exact raw OpenGrep -> NTK triage handoff without dropping findings or trace."""
import argparse
import hashlib
import json
from pathlib import Path
from finding_identity import compare_findings


def verify(engine, triage, *, write_report=True):
    original = (engine / "opengrep.json").read_bytes()
    copied = (triage / "input.opengrep.json").read_bytes()
    if original != copied:
        raise ValueError("raw JSON was rewritten")
    raw = json.loads(original)
    sarif = json.loads((engine / "opengrep.sarif").read_bytes())
    bundle = json.loads((triage / "evidence.json").read_bytes())
    scan_sha = hashlib.sha256(original).hexdigest()
    if raw.get("errors") or bundle["issues"]:
        raise ValueError("scan or evidence reports errors")
    if bundle.get("scan_provenance", {}).get("source_capture_verified") is not True:
        raise ValueError("scan-time source provenance is not verified")
    if bundle["scan_sha256"] != scan_sha or len(raw["results"]) != len(bundle["records"]):
        raise ValueError("handoff scan hash or finding count differs")
    identity = compare_findings(raw, sarif)
    for index, (finding, record) in enumerate(zip(raw["results"], bundle["records"])):
        if type(record["finding_index"]) is not int or record["finding_index"] != index:
            raise ValueError("handoff finding index differs")
        if record["id"] != hashlib.sha256((scan_sha + ":" + str(index)).encode()).hexdigest():
            raise ValueError("handoff finding ID differs")
        if record["raw_finding"] != finding or record["rule_id"] != finding["check_id"]:
            raise ValueError("handoff raw finding or rule ID differs")
        if record["raw_trace"] != finding["extra"].get("dataflow_trace") or record["issues"]:
            raise ValueError("handoff trace differs or evidence is incomplete")
    result = {"status": "PASS", "raw_json_bytes_unchanged": True, "scan_sha256": scan_sha,
              "findings_in": len(raw["results"]), "findings_out": len(bundle["records"]),
              "sarif_findings": sum(len(r["results"]) for r in sarif["runs"]),
              "rule_ids_and_trace_preserved": True,
              "json_sarif_rule_ids_and_locations_match": identity["rule_ids_and_locations_match"]}
    if write_report:
        (triage / "handoff-verification.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--engine", type=Path, required=True)
    p.add_argument("--triage", type=Path, required=True)
    a = p.parse_args()
    print(json.dumps(verify(a.engine, a.triage), indent=2))
