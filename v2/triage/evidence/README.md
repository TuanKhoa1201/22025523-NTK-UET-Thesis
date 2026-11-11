# Local generated evidence

Logs, JSON/JSONL and SQLite databases here are ignored by Git. Only synthetic Java
fixtures were scanned. Never commit private source or research outputs.

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
