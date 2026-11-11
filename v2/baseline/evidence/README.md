Generated evidence stays local and is ignored by Git. Only synthetic Java inputs were scanned.

- `real-01/`: failed real engine attempt; unsupported `--metrics` option, exit 2.
- `real-02/`: successful real OpenGrep 1.20.0 JSON/SARIF runs.
- `unit-tests.txt`: unit tests, including mocked subprocesses (not runtime proof).
- `opengrep-help.txt`: actual installed CLI help consulted for flag compatibility.

Each real run captures version/JSON/SARIF argv, stdout, stderr and exit code. A successful
run also retains raw `opengrep.json`, `opengrep.sarif`, normalized `findings.json`.
`verify_real.py` produces `verification.json` with input/output SHA-256 and a raw trace example.
Do not commit large outputs or private scanned code. Use a fresh output directory each run.
