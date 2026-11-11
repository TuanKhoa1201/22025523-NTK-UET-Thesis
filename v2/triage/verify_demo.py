"""Verify a real CLI demo on baseline's two synthetic Java files (not a benchmark)."""
import argparse
import json
from pathlib import Path
from .evidence import check_current, digest
from .store import ReviewStore


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("run", type=Path)
    args = parser.parse_args()
    root = args.run.resolve()
    bundle = json.loads((root / "evidence.json").read_text(encoding="utf-8"))
    raw = json.loads((root / "engine/opengrep.json").read_text(encoding="utf-8"))
    sarif = json.loads((root / "engine/opengrep.sarif").read_text(encoding="utf-8"))
    assert not bundle["issues"] and not raw["errors"]
    assert len(raw["results"]) == len(bundle["records"]) == 4
    assert sum(len(r["results"]) for r in sarif["runs"]) == 4
    assert {Path(p).name for p in raw["paths"]["scanned"]} == {"Safe.java", "Vulnerable.java"}
    checked = 0
    for original, record in zip(raw["results"], bundle["records"]):
        assert not record["issues"]
        assert original == record["raw_finding"]
        assert original["extra"]["dataflow_trace"] == record["raw_trace"]
        check_current(record)
        assert {s["role"] for s in record["snippets"]} == {"finding", "source", "intermediate", "sink"}
        for snippet in record["snippets"]:
            data = (Path(record["root"]) / snippet["path"]).read_bytes()
            assert digest(data) == snippet["sha256"]
            start, end = snippet["start"], snippet["end"]
            assert data[start["offset"]:end["offset"]].decode("utf-8") == snippet["matched"]
            for line in snippet["lines"]:
                assert data.decode("utf-8").splitlines()[line["line"]-1] == line["text"]
            checked += 1
    for label in ("version", "json", "sarif"):
        assert (root / ("engine/" + label + ".exit.txt")).read_text() == "0"
    store = ReviewStore(root / "review.sqlite")
    try:
        queue = store.queue()
        assert len(queue) == 4
        assert all(item["state"] == "OPEN" for item in queue)
        assert all(item["assessment"]["status"] == "UNDETERMINED" for item in queue)
    finally:
        store.close()
    artifacts = [p for p in root.rglob("*") if p.is_file() and p.name != "demo-verification.json"]
    result = {"status": "PASS", "scope": "synthetic real-engine functional demo, unavailable Ollama",
              "findings": 4, "sarif_results": 4, "grounded_locations": checked,
              "all_human_states": "OPEN", "all_model_states": "UNDETERMINED",
              "qwen_runtime_executed": False,
              "sha256": {str(p.relative_to(root)): digest(p.read_bytes()) for p in artifacts}}
    (root / "demo-verification.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"PASS: 4 real findings, 4 SARIF results, {checked} grounded locations; Qwen unavailable, all OPEN")


if __name__ == "__main__":
    main()
