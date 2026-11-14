"""Explicit MOCK process capture for protocol tests; never real-engine evidence."""
import json
from pathlib import Path
from v2.baseline.fork.semgrepai.scan_manifest import ScanCapture
from v2.triage.scan_receipt import verify_receipt


def mock_sarif_for(raw):
    """MOCK SARIF mirroring the JSON findings (rule, uri, region) like a real OpenGrep JSON/SARIF pair.
    Malformed JSON yields an empty SARIF run so receipt verification still fails closed on the JSON."""
    try:
        doc = json.loads(raw.decode("utf-8") if isinstance(raw, bytes) else raw)
        results = [
            {"ruleId": r["check_id"], "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": r["path"]},
                "region": {"startLine": r["start"]["line"], "endLine": r.get("end", r["start"])["line"]}}}]}
            for r in doc.get("results", [])
        ]
    except (ValueError, KeyError, TypeError, AttributeError):
        results = []
    return json.dumps({"runs": [{"tool": {"driver": {"name": "MOCK"}}, "results": results}]}).encode("utf-8")


def make_capture(root, raw, output, sarif=None):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    rules = output / "fixture-rules.yml"
    rules.write_text("# MOCK rules, no engine executed\n", encoding="utf-8")
    cap = ScanCapture(root, rules, output)
    sarif_body = mock_sarif_for(raw) if sarif is None else sarif
    for label, body in (("version", b"MOCK version"), ("json", raw), ("sarif", sarif_body)):
        argv = ["MOCK_ENGINE", label]
        cap.runs[label] = {"argv": argv, "exit_code": 0}
        (output / (label + ".stdout.txt")).write_bytes(body)
        (output / (label + ".stderr.txt")).write_bytes(b"")
        (output / (label + ".exit.txt")).write_text("0")
        (output / (label + ".command.json")).write_text(json.dumps(argv))
        if label != "version":
            (output / ("opengrep." + label)).write_bytes(body)
    cap.finish(True)
    path = output / "scan-manifest.json"
    doc = json.loads(path.read_text())
    doc["producer"] = "UNIT_TEST_MOCK_CAPTURE"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def fixture_provenance(root, raw, output):
    path = make_capture(root, raw, output)
    metadata, issues = verify_receipt(path, raw, root, 0)
    assert not issues, issues
    return metadata
