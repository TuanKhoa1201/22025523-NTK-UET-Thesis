"""Verify captured real OpenGrep evidence on the committed synthetic Java inputs."""
import argparse
import hashlib
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("run", type=Path)
    args = parser.parse_args()
    run = args.run.resolve()
    base = Path(__file__).resolve().parent
    document = json.loads((run / "opengrep.json").read_text(encoding="utf-8"))
    normalized = json.loads((run / "findings.json").read_text(encoding="utf-8"))
    sarif = json.loads((run / "opengrep.sarif").read_text(encoding="utf-8"))
    assert document["errors"] == [], "engine errors"
    assert len(document["results"]) == len(normalized["findings"]) == 4
    assert sum(len(r["results"]) for r in sarif["runs"]) == 4
    assert {Path(p).name for p in document["paths"]["scanned"]} == {"Safe.java", "Vulnerable.java"}
    assert {r["extra"]["metadata"]["cwe"][0] for r in document["results"]} == {
        "CWE-22", "CWE-78", "CWE-79", "CWE-89"}
    trace_locations = []
    for raw, processed in zip(document["results"], normalized["findings"]):
        assert Path(raw["path"]).resolve() == (base / "fixtures/java/Vulnerable.java").resolve()
        assert processed["review_status"] == "REVIEW"
        trace = raw["extra"]["dataflow_trace"]
        assert processed["dataflow"] == trace, "trace changed during normalization"
        locations = []
        for key in ("taint_source", "taint_sink"):
            tag, payload = trace[key]
            assert tag == "CliLoc", "unexpected trace shape; inspect rather than guess"
            locations.append(payload)
        locations.extend((step["location"], step["content"]) for step in trace["intermediate_vars"])
        for loc, content in locations:
            source = Path(loc["path"]).resolve()
            assert source == (base / "fixtures/java/Vulnerable.java").resolve()
            data = source.read_bytes()
            start, end = loc["start"], loc["end"]
            actual = data[start["offset"]:end["offset"]].decode("utf-8")
            assert actual == content, (actual, content)
            lines = data.decode("utf-8").splitlines()
            assert start["line"] == end["line"]
            assert lines[start["line"]-1][start["col"]-1:end["col"]-1] == content
            trace_locations.append({"line": start["line"], "content": content})
        assert trace["taint_source"][1][0]["start"]["line"] == 5
        assert trace["taint_sink"][1][0]["start"]["line"] == raw["start"]["line"]
    for label in ("version", "json", "sarif"):
        assert (run / (label + ".exit.txt")).read_text() == "0"
    inputs = [base / "rules/java.yml", *sorted((base / "fixtures/java").glob("*.java")),
              *sorted((base / "fork/semgrepai").glob("*.py"))]
    artifacts = [p for p in run.iterdir() if p.is_file() and p.suffix in (".json", ".sarif", ".txt")]
    summary = {"status": "PASS", "scope": "synthetic functional demonstration; no accuracy benchmark",
               "version": normalized["engine_version"], "findings": 4, "sarif_findings": 4,
               "safe_findings": 0, "trace_locations_checked": len(trace_locations),
               "sha256": {str(p.relative_to(base)): hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in inputs + artifacts},
               "example_trace": document["results"][0]["extra"]["dataflow_trace"]}
    # Verification may be rerun; exclude the verifier's own summary from its input hashes.
    summary["sha256"].pop(str((run / "verification.json").relative_to(base)), None)
    (run / "verification.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"PASS: 4 findings, 4 SARIF results, 0 Safe.java findings; {len(trace_locations)} trace locations match source")


if __name__ == "__main__":
    main()
