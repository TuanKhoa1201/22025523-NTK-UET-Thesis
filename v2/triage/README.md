# Local Java warning triage

Integration: [SCHEMA_CONTRACT.md](SCHEMA_CONTRACT.md) specifies additive schema 1.1,
exact raw-scan/index/ID joins, runtime provenance and the paired Antigravity exporter.
`--runtime-origin mock` labels simulated HTTP services. Received HTTP, validated
answers and independently verified model execution are separate per-warning fields.

Reproduce the real-engine stale-source refusal without editing repository fixtures:

```powershell
python -m v2.triage.demo_freshness --output-dir v2/triage/evidence/freshness-run
```

The review actor in that demo is explicitly scripted/synthetic, never a real person's
approval; it records confirm-true and proves that stale confirm-false is refused.

Python standard library only. Run from the workspace root with Python 3.10+.
This module reuses the M1 OpenGrep scanner; it does not initialize upstream web,
RAG, cloud validators or false-positive learning. Priorities are CWE-22 and CWE-89;
the four M1 demo rules also cover CWE-78 and CWE-79.

## Scan or import

```powershell
python -m v2.triage run --source-root v2/baseline/fixtures/java --output-dir v2/triage/evidence/my-run --timeout 5
```

This runs the installed OpenGrep with M1's local rules and captures JSON/SARIF,
then collects evidence, attempts local Ollama and creates a SQLite review queue.
`--rules` selects another local rule file; `--executable` selects the local engine.
The output directory must not already exist: previous evidence is never replaced.
Do not write output inside the scanned source directory.

Import an existing raw OpenGrep JSON document instead:

```powershell
python -m v2.triage run --source-root v2/baseline/fixtures/java --json v2/baseline/evidence/real-02/opengrep.json --engine-exit 0 --output-dir v2/triage/evidence/import-run --no-llm
```

Pass the original engine exit code, not a guessed success. If omitted, completeness
is unknown and assessments stay UNDETERMINED. Use `--path-base` when relative paths
in JSON are relative to the engine's working directory rather than `--source-root`.
Resolved source files must still be Java files inside `--source-root`. No path
stripping or fallback to arbitrary working-directory files is attempted.

Artifacts: `input.opengrep.json` (unchanged raw input), `evidence.json` (raw document,
original warnings, hashes, verified snippets, raw trace and issues),
`assessments.jsonl` (warning + evidence + model assessment), `review.sqlite`
(queue and decision history). Engine runs additionally produce `engine/` logs,
commands, exit codes and JSON/SARIF. Generated artifacts under `evidence/` are ignored
by Git. Malformed JSON produces a scan issue in the database, not an invented finding.

CLI exit 0 means scan/evidence ingestion succeeded; it does not mean Qwen succeeded
or that any warning is safe. Scan/evidence errors return 2; model failures are
retained per warning as UNDETERMINED. Queue output includes scan-level errors even
when there were no readable findings.

## Ollama and validation

Default endpoint: `http://127.0.0.1:11434`; default model: `qwen3.5:9b-q4_K_M`.
`--endpoint`, `--model`, `--timeout` configure the adapter. Only literal loopback
HTTP or `localhost` (normalized to 127.0.0.1) is allowed. Proxies and HTTP redirects
are disabled; model names must start with `qwen` and cloud variants are rejected.
For JavisOS's server use an externally managed loopback tunnel; this module does
not install Ollama, pull models, configure networking or provision hardware.

The adapter follows the official [Ollama chat API](https://docs.ollama.com/api/chat)
and [structured-output API](https://docs.ollama.com/capabilities/structured-outputs):
`POST /api/chat`, schema in `format`, `stream: false`, `think: false`, temperature 0,
4096 context, bounded output. Server/model compatibility still requires real testing.
No provider fallback or cloud LLM call exists in this module.

The prompt contains verified source/source-sink/intermediate snippets, exact line
numbers, CWE, locations and SHA-256 values. Source text is untrusted data. Responses
must contain exactly `status`, `explanation`, `citations`, `fix_suggestion` with
validated types. A citation contains `path`, `start_line`, `end_line`, `quote`,
`sha256`; its quote must equal complete supplied source line(s), including indentation.
Quotes and current file versions are checked again after the model responds.

| Model state | Meaning | Human state after ingestion |
| --- | --- | --- |
| SUPPORTED | Evidence supports the proposed risk | OPEN |
| REFUTED | Proposed rebuttal for human evaluation | OPEN |
| UNDETERMINED | Insufficient evidence or analysis failure | OPEN |

Correct citations do not establish a correct security conclusion. Every assessment
has `security_conclusion_verified: false` and `requires_human_review: true`.
Incomplete evidence is not sent to the model. Missing/unknown traces, mismatched
content/offsets, partial scans, missing files, bad JSON, model mismatch, HTTP errors,
timeouts, truncated responses and invalid citations fail to UNDETERMINED.
Suggestions are displayed only; there is no source-rewrite action.

## Human review

```powershell
python -m v2.triage queue --db v2/triage/evidence/my-run/review.sqlite
python -m v2.triage show --db v2/triage/evidence/my-run/review.sqlite FINDING_ID
python -m v2.triage decide --db v2/triage/evidence/my-run/review.sqlite FINDING_ID confirm-true --actor reviewer --reason 'Manual inspection confirms the risk'
python -m v2.triage decide --db v2/triage/evidence/my-run/review.sqlite FINDING_ID confirm-false --actor reviewer --reason 'Describe concrete rebuttal evidence'
python -m v2.triage history --db v2/triage/evidence/my-run/review.sqlite FINDING_ID
python -m v2.triage decide --db v2/triage/evidence/my-run/review.sqlite FINDING_ID reopen --actor reviewer --reason 'Recheck after discussion'
```

`show` includes original warning, raw trace, verified evidence and Qwen's proposed
assessment. The queue includes all human states, including CONFIRMED_FALSE; no
finding is automatically deleted, hidden or dismissed. Each explicit decision
stores actor, UTC timestamp, reason, warning ID, expected/observed source hashes
and a digest of the evidence. Actor names are locally supplied, not authenticated.
SQLite transactions keep history/state updates together; duplicate imports cannot
replace existing decisions. History is append-only through this application, not
a tamper-proof ledger against someone editing the database directly.

Before `confirm-false`, every Java file referenced by the finding/trace must still
exist inside the configured root and match its evidence SHA-256. Missing files,
changed hashes or incomplete evidence refuse the action and require a fresh scan.
`confirm-true` and `reopen` remain available and record observed versions.

## Verification and limits

```powershell
python -m unittest discover -s v2/triage/tests -v
python -m unittest discover -s v2/baseline/tests -v
python -m v2.triage.verify_demo v2/triage/evidence/demo-real
```

The demo verifier is specifically for the supplied two-file synthetic Java example,
an unavailable Ollama, and an untouched OPEN queue. It is not a general benchmark.
Unit/integration model replies, including the loopback HTTP server, are MOCKS.
This laptop's real Ollama probe timed out; no real Qwen execution is claimed.
See [M2_M3_REPORT.md](M2_M3_REPORT.md) for observed outcomes and pending acceptance.

Evidence collection supports OpenGrep's observed `CliLoc` source/sink plus
`intermediate_vars`. Unknown structures such as `CliCall` are retained raw and
flagged for review, not guessed. UTF-8/CRLF line and byte coordinates are checked.
Scans hash Java inputs before/after engine execution; an existing imported JSON
cannot prove historical source identity. Its hashes describe evidence collection
time, and only its supplied locations/content can be verified.

Keep source trees stationary during scan, inference and human confirmation.
Hash checks detect normal changes; this local tool does not provide OS isolation
against a concurrent adversary replacing files between checks. Source files are
bounded to 1 MB, evidence ranges to 150 lines and prompt/HTTP output sizes are bounded.
Conservative limits or unfamiliar traces lead to UNDETERMINED. The demo rules have
narrow coverage and no measured precision/recall. Full upstream UI/LLM integration,
real Qwen/server acceptance and labeled evaluation remain separate work.

No `opengrep-triage.zip` was found in the inspected workspace (including ignored
files outside legacy directories). This module is independently authored; it does
not claim to include the advisor's package. Public interfaces for later integration:
`evidence.collect`, `OllamaClient.analyze`, `ReviewStore` and the CLI.
