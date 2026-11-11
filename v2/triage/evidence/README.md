# Local generated evidence

Logs, JSON/JSONL and SQLite databases here are ignored by Git. Only synthetic Java
fixtures were scanned. Never commit private source or research outputs.

Current P0 handover: `p0-triage-tests.txt` records 51 tests (50 pass, 1 skip).
`freshness-p0/` retains the real-engine synthetic source-change scenario, scripted
review actor, refused false confirmation and unchanged audit. The temporary Java
copy has been removed; original repository fixtures were not modified.
`pilot-contract/` contains paired exports and the pinned scorer's smoke output with
empty labels; all four alerts are intentionally UNLABELED. `antigravity-score-pinned.py`
is an ignored read-only inspection copy, not vendored project code.

- `m1-tests.txt`: 22 existing M1 tests, regression PASS.
- `triage-tests.txt`: final evidence/model-validation/review/CLI/HTTP test log.
  Every model response in these tests is explicitly simulated; no Qwen executed.
- `ollama-probe.json`: actual loopback tags request, timeout; model runtime not executed.
- `demo-real-cli.txt`, `demo-queue.json`: real CLI scan/import summary and open queue.
- `demo-real/engine/`: actual OpenGrep 1.20.0 command arrays, stdout/stderr,
  JSON/SARIF output and exit codes.
- `demo-real/evidence.json`, `assessments.jsonl`, `review.sqlite`: source-grounded
  dossiers, failed-local-Ollama assessments (UNDETERMINED) and OPEN review queue.
- `demo-real/demo-verification.json`: verified real-engine counts, 20 grounded
  locations and hashes of generated artifacts. This verifies the supplied synthetic
  demo, not model correctness or benchmark accuracy.
