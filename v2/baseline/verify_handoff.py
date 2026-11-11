"""Verify exact raw OpenGrep -> NTK triage handoff without dropping findings or trace."""
import argparse
import hashlib
import json
from pathlib import Path


def verify(engine, triage):
    original = (engine / "opengrep.json").read_bytes()
    copied = (triage / "input.opengrep.json").read_bytes()
    assert original == copied, "raw JSON was rewritten"
    raw = json.loads(original)
    sarif = json.loads((engine / "opengrep.sarif").read_bytes())
    bundle = json.loads((triage / "evidence.json").read_bytes())
    scan_sha = hashlib.sha256(original).hexdigest()
    assert not raw.get("errors") and not bundle["issues"]
    assert bundle.get("scan_provenance", {}).get("source_capture_verified") is True
    assert bundle["scan_sha256"] == scan_sha
    assert len(raw["results"]) == len(bundle["records"])
    assert sum(len(r["results"]) for r in sarif["runs"]) == len(raw["results"])
    for index, (finding, record) in enumerate(zip(raw["results"], bundle["records"])):
        assert record["finding_index"] == index
        assert record["id"] == hashlib.sha256((scan_sha + ":" + str(index)).encode()).hexdigest()
        assert record["raw_finding"] == finding and record["rule_id"] == finding["check_id"]
        assert record["raw_trace"] == finding["extra"].get("dataflow_trace")
        assert not record["issues"]
    result = {"status": "PASS", "raw_json_bytes_unchanged": True, "scan_sha256": scan_sha,
              "findings_in": len(raw["results"]), "findings_out": len(bundle["records"]),
              "sarif_findings": sum(len(r["results"]) for r in sarif["runs"]),
              "rule_ids_and_trace_preserved": True}
    (triage / "handoff-verification.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--engine", type=Path, required=True)
    p.add_argument("--triage", type=Path, required=True)
    a = p.parse_args()
    print(json.dumps(verify(a.engine, a.triage), indent=2))
