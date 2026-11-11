"""Real OpenGrep + scripted review of a synthetic fixed-query allowlist control."""
import argparse
import io
import json
import tempfile
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from .cli import main
from .evidence import digest
from .store import ReviewStore

SAFE_JAVA = '''class AllowlistedQuery {
    void run(Request req, Statement stmt) throws Exception {
        String query = req.getParameter("q");
        if (!"SELECT 1".equals(query)) {
            throw new IllegalArgumentException("Only SELECT 1 is allowed");
        }
        stmt.executeQuery(query);
    }
}
'''


def run(output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    calls = []
    def invoke(arguments, expected=0):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(arguments)
        calls.append({"argv": arguments, "exit": code, "stderr": stderr.getvalue()})
        assert code == expected, stderr.getvalue()
        return json.loads(stdout.getvalue()) if stdout.getvalue() else None
    with tempfile.TemporaryDirectory(prefix="queue-source-", dir=output) as temporary:
        source = Path(temporary).resolve()
        file = source / "AllowlistedQuery.java"
        file.write_bytes(SAFE_JAVA.encode("utf-8"))
        invoke(["run", "--source-root", str(source), "--output-dir", str(output / "run"), "--no-llm"])
        db = str(output / "run/review.sqlite")
        initial = invoke(["queue", "--db", db])
        assert len(initial["warnings"]) == 1, "demo needs exactly one real taint warning"
        identifier = initial["warnings"][0]["id"]
        original = invoke(["show", "--db", db, identifier])
        assert "CWE-89" in original["evidence"]["cwe"]
        reason = "SCRIPTED synthetic control: query must equal constant SELECT 1 before SQL sink; demo rule lacks this allowlist sanitizer"
        invoke(["decide", "--db", db, identifier, "confirm-false", "--actor", "SCRIPTED-DEMO", "--reason", reason])
        hidden = invoke(["queue", "--db", db])
        all_rows = invoke(["queue", "--db", db, "--all"])
        assert hidden["warnings"] == [] and len(all_rows["warnings"]) == 1
        assert invoke(["show", "--db", db, identifier])["state"] == "CONFIRMED_FALSE"
        first_history = invoke(["history", "--db", db, identifier])
        assert len(first_history) == 1
        invoke(["decide", "--db", db, identifier, "reopen", "--actor", "SCRIPTED-DEMO", "--reason", "Scripted re-review of synthetic control"])
        reopened = invoke(["queue", "--db", db])
        assert len(reopened["warnings"]) == 1
        history_before = invoke(["history", "--db", db, identifier])
        before_hash = digest(file.read_bytes())
        with file.open("ab") as stream:
            stream.write(b"\n// Scripted source edit: old evidence must no longer authorize false confirmation.\n")
        after_hash = digest(file.read_bytes())
        invoke(["decide", "--db", db, identifier, "confirm-false", "--actor", "SCRIPTED-DEMO", "--reason", "Must fail: stale evidence"], expected=2)
        history_after = invoke(["history", "--db", db, identifier])
        assert history_before == history_after and len(history_after) == 2
        assert "rescan" in calls[-2]["stderr"]
        store = ReviewStore(db)
        try:
            assert store.get(identifier)["state"] == "OPEN"
            assert store.get(identifier)["evidence"] == original["evidence"]
            assert store.db.execute("SELECT count(*) FROM warnings").fetchone()[0] == 1
        finally:
            store.close()
        result = {"status": "PASS", "engine": "REAL OpenGrep", "model": "disabled",
                  "actor": "SCRIPTED-DEMO", "not_independent_human_ground_truth": True,
                  "synthetic_control": SAFE_JAVA, "default_queue_counts": [1, 0, 1], "all_rows_after_hide": 1,
                  "alert_id": identifier, "source_sha256_before": before_hash, "source_sha256_after": after_hash,
                  "stale_false_confirmation_exit": 2, "history_unchanged_after_refusal": True,
                  "history_before_refusal": history_before, "history_after_refusal": history_after,
                  "final_state": "OPEN", "original_evidence_unchanged": True, "cli_calls": calls}
    (output / "queue-demo.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    run(args.output_dir)
    print("PASS: real engine; SCRIPTED-DEMO queue 1->0->1; history preserved; stale confirm-false refused")
