"""Real-engine synthetic demo: stale source refuses false confirmation, preserving audit."""
import argparse
import io
import json
import shutil
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from .cli import main as triage_main
from .evidence import EvidenceError, check_current, digest
from .store import ReviewStore


def run(output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    fixtures = Path(__file__).resolve().parents[1] / "baseline/fixtures/java"
    original_hashes = {p.name: digest(p.read_bytes()) for p in fixtures.glob("*.java")}
    with tempfile.TemporaryDirectory(prefix="synthetic-source-", dir=output) as temporary:
        source = Path(temporary).resolve()
        for file in fixtures.glob("*.java"):
            shutil.copyfile(file, source / file.name)
        pipeline_log = io.StringIO()
        with redirect_stdout(pipeline_log):
            code = triage_main(["run", "--source-root", str(source), "--output-dir", str(output / "run"), "--no-llm"])
        (output / "pipeline-summary.json").write_text(pipeline_log.getvalue(), encoding="utf-8")
        assert code == 0, "real scan/evidence failed"
        store = ReviewStore(output / "run/review.sqlite")
        try:
            item = next(x for x in store.queue() if "CWE-89" in x["evidence"]["cwe"])
            record = item["evidence"]
            check_current(record)
            # Explicitly a scripted review API exercise, never an actual user's decision.
            store.decide(item["id"], "confirm-true", "SCRIPTED-DEMO",
                         "Synthetic vulnerable positive control; scripted review API exercise, not independent human labeling")
            before = store.history(item["id"])
            version_before = digest((source / "Vulnerable.java").read_bytes())
            with (source / "Vulnerable.java").open("ab") as stream:
                stream.write(b"\n// Synthetic edit for stale-evidence demonstration.\n")
            version_after = digest((source / "Vulnerable.java").read_bytes())
            try:
                store.decide(item["id"], "confirm-false", "SCRIPTED-DEMO", "This request must be refused: stale evidence")
            except EvidenceError as exc:
                refusal = str(exc)
            else:
                raise AssertionError("stale false confirmation was accepted")
            after = store.history(item["id"])
            assert before == after and len(after) == 1
            assert store.get(item["id"])["state"] == "CONFIRMED_TRUE"
            assert version_before != version_after and "rescan" in refusal
            result = {"status": "PASS", "engine": "real OpenGrep", "model": "disabled",
                      "review_actor_kind": "SCRIPTED_SYNTHETIC_NOT_REAL_HUMAN", "alert_id": item["id"],
                      "source_sha256_before": version_before, "source_sha256_after": version_after,
                      "false_confirmation": "REFUSED", "refusal": refusal,
                      "history_before": before, "history_after": after, "history_unchanged": before == after,
                      "final_human_state": "CONFIRMED_TRUE", "original_fixture_hashes": original_hashes}
        finally:
            store.close()
    assert original_hashes == {p.name: digest(p.read_bytes()) for p in fixtures.glob("*.java")}
    result["original_fixtures_unchanged"] = True
    (output / "freshness-demo.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.output_dir)
    print("PASS: real scan; synthetic copy edited; FALSE_POSITIVE refused; audit and original fixtures unchanged")
