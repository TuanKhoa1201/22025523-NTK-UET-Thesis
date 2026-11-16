# NTK triage data contract 1.1

## Scan-capture reliability extension (additive, current producer)

Data IDs/layout remain compatible; trust policy is stricter. New scans create
`scan-manifest.json` schema `ntk-scan-capture-1` before/after real subprocesses.
It binds source inventory and rule hashes, original command/exit/stdout/stderr
artifacts and raw JSON/SARIF. Captured stdout mode requires raw-byte equality;
instrumented upstream file-output mode binds the original --output argv and copied
raw file bytes instead. The two modes are explicit, never inferred from triage exit.

Bundle/record `scan_provenance` distinguishes `declared_only` / `collection_only`
from `recorded_capture_unsigned`; fields include declared_engine_exit,
recorded_engine_exit, exit_capture_verified, source_capture_verified, manifest_sha256,
manifest_path and independently_attested=false. Original exits can be valid while
source identity fails; a wrapper error is not fabricated as engine exit 2. Source
keys are canonical relative paths and all current source hashes/inventory must match.
Record metadata excludes the full source_hashes table to avoid duplicating a corpus.

Historical raw JSON without a contemporaneous valid manifest is still retained but
must REVIEW; do not generate a new manifest after the fact to bless an old scan.
New confirm-false and model analysis require scan-time provenance as well as current
hash equality. Legacy records/history are not deleted or rewritten. Mapping never
rewrites raw JSON, source SHA, scan SHA or IDs. Old export proposals without captured
source identity now map to REVIEW.

Runtime adds finding_id, request_payload_sha256 and canonical response_json_sha256
to the observed HTTP metadata. `live_check` independently verifies their join,
nonmock origin, matching returned model and positive reported eval counters. Any
status, including UNDETERMINED, can demonstrate protocol execution; a SUPPORTED
prediction is not required or treated as ground truth. Result remains UNATTESTED;
unsigned files and HTTP alone cannot prove physical model execution.

Contract owner: `v2/codex-core`. Scope: additive fields only; existing IDs, nested
assessment layout, three model states and SQLite human states are unchanged.
Missing `schema_version` denotes legacy 1.0. New bundles/records/JSONL rows carry
`schema_version: "1.1"`. Readers must tolerate additive fields; reject unsupported
major changes rather than silently reinterpreting verdicts.

## Raw scan and exact join

`input.opengrep.json` is the exact byte input, not pretty-printed/re-encoded JSON.
Its OpenGrep envelope contains `results[]`, `errors[]`, optionally `paths` and
`version`. Each raw result keeps `check_id`, `path`, `start/end` with 1-based
line/column and optional 0-based byte offset, `extra.severity`, metadata and
`extra.dataflow_trace`. `end` is exclusive. Preserve unknown extra fields.

```text
scan_sha256 = SHA256(exact input.opengrep.json bytes), lowercase hex
finding_index = zero-based index in original results[], including malformed entries
id = alert_id = SHA256(UTF8(scan_sha256 + ":" + decimal(finding_index)))
```

Whitespace/re-encoding/path edits to raw JSON change the scan identity. Duplicate
findings at the same position remain distinct by index. `extra.fingerprint`, rule ID
and file/line tuples are not substituted for this identity. Join with the exact raw
scan hash + index, recompute ID, then compare `raw_finding` to `results[index]`.
The exporter below performs those checks and rejects mismatches. A legacy record
without index can recover it by testing the ID formula against all raw indices;
never guess it from location. Do not inject IDs into or rewrite the raw scan.

## Evidence records

`evidence.json`: `{schema_version, scan_sha256, root, collected_at, issues,
records, raw_document}` plus `pre_scan_hashes` for direct scans. `raw_document` is
parsed JSON (raw bytes remain in the separate input file); invalid JSON keeps a scan
issue and no invented record. `collected_at` is UTC ISO 8601.

Each `records[]` entry has `id`, `alert_id`, `finding_index`, `scan_sha256`, `root`,
`rule_id` (=raw check_id), `cwe` (list preserving metadata strings), `severity`, raw
`path/start/end`, `raw_finding`, `raw_trace`, `snapshots`, `snippets`, `issues`.
CWE strings may contain a description; the pilot adapter normalizes the first CWE
for the scorer's one-CWE bucket without expanding or relabeling alerts.

`snapshots` maps root-relative POSIX Java paths to `{sha256, size}`. SHA-256 is over
the exact Java file bytes, including CRLF; do not use normalized text hashing.
`snippets[]` has `role` (`finding/source/intermediate/sink`), root-relative `path`,
original `start/end`, `sha256`, exact matched content and `lines[]: {line,text}`.
Line text excludes CR/LF terminators, retaining indentation; offsets/columns are byte
coordinates and validated against UTF-8 source. `CliLoc` and intermediate_vars are
supported; unknown `CliCall` structures remain raw and force UNDETERMINED.

`root` is machine-local. Relative engine paths use configured `path_base` or root;
canonical resolution must remain inside root. No automatic Windows↔WSL rewriting
exists. `--path-map /mnt/c/project=C:\project` explicitly maps a POSIX prefix into
source-root, with longest-prefix/segment-boundary matching. `path_mappings: [{from,to}]`
is additive metadata in bundle/records; snippets retain `raw_path` alongside the local
relative `path`. Raw JSON/trace and scan hashes/IDs remain unchanged. Targets must be
inside root and every resolved trace location still passes hash/line/column/offset
checks. No path guessing, traversal suffixes, or newline repairs are allowed.
Collect on the scanning host, or use explicit mappings for absolute WSL paths and
`path_base` for relative JSON. Direct scans hash inputs before/after;
imported JSON cannot establish historical file identity beyond supplied traces.

## Assessment and human review

`assessments.jsonl` contains one object per warning, **not** a top-level model verdict:

```json
{"schema_version":"1.1","id":"<hex>","alert_id":"<same hex>","scan_sha256":"<hex>","finding_index":0,"state":"OPEN","evidence":{},"assessment":{}}
```

`evidence` is the complete record above. `assessment` retains `status`, `explanation`,
`citations`, `fix_suggestion`, `citation_check`, `requires_human_review: true`,
`security_conclusion_verified: false`, `analyzed_at`; attempted model calls additionally
include `transport`, requested `model`, `endpoint`, `raw_response`, `elapsed_seconds`.
`raw_response` is the parsed Ollama envelope, including message content, or null.
Do not treat `transport: ollama-http` alone as proof of a successful request.

Citations: `{path,start_line,end_line,quote,sha256}`, with a relative snapshot path,
inclusive line range and quote equal to complete supplied line(s), joined by LF and
preserving indentation. The quote/hash/current source are checked; successful matching
does not prove a security conclusion. Proposed fixes are display-only.

| Model status | Meaning | Pilot verdict | Human state on ingestion |
| --- | --- | --- | --- |
| SUPPORTED | Evidence supports proposed risk | KEEP_TP | OPEN |
| REFUTED | Proposed rebuttal only | PROPOSED_FP | OPEN |
| UNDETERMINED | Unknown/error/insufficient evidence | REVIEW | OPEN |

These are **not ground truth labels**. Even SUPPORTED/REFUTED are unverified security
opinions. Ground truth belongs to a separate locked, independently reviewed label file.

`review.sqlite`: `scans(id,bundle)`, `warnings(id,scan_id,evidence,assessment,state)`,
`events(sequence,warning_id,actor,timestamp,action,reason,source_version,observed_version,
evidence_sha256)`. JSON documents carry additive schema metadata; SQL tables are unchanged.
Human states are OPEN / CONFIRMED_TRUE / CONFIRMED_FALSE. Human actions are
`confirm-true`, `confirm-false`, `reopen`; CLI does not accept model states as actions.
`confirm-false` requires complete evidence and current hashes of **all** referenced
Java files. Failure appends no event and changes no state. Default queue excludes only
CONFIRMED_FALSE; `queue --all` / `ReviewStore.queue(include_all=True)` includes every
state. `show`/`history` still retrieve excluded rows; reopen returns them to default
queue. The only change is query behavior; SQL tables, evidence and history are unchanged.
Actor is locally supplied, not authenticated. JSONL is an ingestion snapshot; later
human state/history must be read from SQLite, not inferred from old JSONL `state`.

## Execution metadata: HTTP is not model attestation

Each new assessment has `runtime`:

| Field | Evidence represented |
| --- | --- |
| origin | `disabled`, `mock`, or `unverified`; default endpoint is never implicitly trusted |
| request_attempted | Actual HTTP request method entered; false for skipped inference or a mocked request method |
| request_payload_sha256 / request_payload_bytes | SHA-256 and byte length of exact UTF-8 payload bytes passed to `urllib.request.Request` |
| request_raw_artifact | Relative path (`llm_io/<id>.request.body.bin`) of exact client-sent HTTP request payload bytes |
| http_response_received / http_status | Response observed by the real urllib transport, including real HTTP from a fake server |
| response_body_sha256 / response_body_bytes | Hash and byte length of exact bounded HTTP response body bytes, before UTF-8/JSON parsing; null if no complete bounded body |
| response_raw_artifact | Relative path (`llm_io/<id>.response.body.bin`) of exact complete bounded HTTP response body bytes (including HTTP 4xx/5xx error bodies and malformed JSON/invalid UTF-8 HTTP 200 bodies) |
| response_incomplete_raw_artifact | Relative path (`llm_io/<id>.response.incomplete.bin`) when transfer truncated early or exceeded `1_000_000` bytes (prefix only; `response_body_sha256` remains null) |
| response_json_sha256 | Canonical sorted-key UTF-8 JSON hash of parsed `raw_response` envelope when strict JSON parsing succeeded |
| http_capture_receipt / http_capture_completeness / http_capture_complete / http_capture_error | Per-call receipt (`llm_io/<id>.http-capture.json`, schema `ntk-ollama-http-capture-1`) and capture integrity state |
| response_complete | Server JSON reports done=true and non-truncated completion |
| model_identity_matched | Server-reported model string equals requested tag |
| reported_eval_count / reported_eval_duration_ns | Server-reported counters, not independent measurements of inference |
| answer_validated | Model JSON/schema/citations/current-version AND mandatory evidence capture writes succeeded |
| model_runtime_verified | False: this adapter has no independent server-run attestation |

### Same-call raw HTTP body capture (`ntk-ollama-http-capture-1`)

When `io_log_dir` is configured (`<run>/triage/llm_io`), `OllamaClient.request` writes
raw binary artifacts using exclusive (`xb`) file creation during the **same** HTTP call
(never issuing a second Qwen call and never JSON re-serializing response bytes):

- `llm_io/<id>.request.body.bin` — exact bytes passed to `Request(..., data=data)`; SHA-256 equals `runtime.request_payload_sha256`.
- `llm_io/<id>.response.body.bin` — exact bounded HTTP response body bytes (`<= 1,000,000` bytes) persisted **prior** to `.decode("utf-8")` and `strict_json`, preserving CRLF, whitespace, key order, `\uXXXX` escapes, malformed JSON, invalid UTF-8, and HTTP error bodies; SHA-256 equals `runtime.response_body_sha256`.
- `llm_io/<id>.response.incomplete.bin` — bounded partial/prefix bytes when a socket truncates mid-body or exceeds `1,000,000` bytes (`complete: false`, `response_body_sha256: null`). Timeout prior to receiving body bytes records `completeness: "no_body_received"` without fabricating a response binary.
- `llm_io/<id>.http-capture.json` — structured receipt (`schema: "ntk-ollama-http-capture-1"`, `capture_scope: "http_body_and_client_metadata_not_tcp_wire"`) binding `call_id`, `finding_id`, `scan_sha256`, `finding_index`, `rule_id`, `method`, `path`, `http_status`, `response_headers`, timestamps, byte lengths, and SHA-256 digests.
- `llm_io/_tags/tags-NNNN.{response.body.bin,http-capture.json}` — isolated capture for `GET /api/tags` probes so tag checks never collide with `/api/chat` finding artifacts.
- Compatibility JSON sidecars (`<id>.prompt.json`, `<id>.request.json`, `<id>.response.json`) remain preserved; `<id>.response.json["raw_response"]` is explicitly documented as the parsed JSON envelope (or `null` on parse/transport failure), distinct from `<id>.response.body.bin`.
- Scope boundary: captures client-sent HTTP request payload bytes and client-received HTTP response body bytes, **not** raw TCP/chunked wire framing or server-side weight attestation.
- Fail-closed write guard: any collision or OS write error raises `CaptureWriteError`, setting `failure_kind: "EVIDENCE_CAPTURE_WRITE_FAILED"`, `validated_status: "UNDETERMINED"`, `answer_validated: false` (preserving `raw_model_status` without HTTP retry) while keeping the warning `OPEN` in SQLite.
- Independent verifier: `python -m v2.triage.verify_http_capture <triage_dir> [--require-live-chat] [--minimum-findings N] [--output <PATH> | --no-write]` verifies byte lengths, SHA-256 digests, unique `call_id`s, and tamper/orphan absence without altering `live_check.py` semantics.

Pass `--runtime-origin mock` for a simulated endpoint. The known fixture marker
`mock_test_fixture: true` also forces origin=mock. A fake HTTP server can copy all
Ollama fields; therefore even unmarked HTTP/counters **never** become verified model
execution. `runtime_summary` counts received responses, validated answers, mock
records, Ollama-reported inference and verified runtime separately per warning.
Ollama-reported inference requires a nonmock received/complete matching-model response
with positive integer eval_count; it is still unverified. Never reuse runtime metadata
from a previous warning. Invalid citations can coexist with a received HTTP response.

The legacy `qwen_runtime_verified` CLI summary is retained for compatibility, derived
from verified-runtime count and nonempty warning count. It stays false until an
independent attestation mechanism exists; use the per-warning fields above to distinguish
timeouts from received/validated output. JavisOS must preserve actual server model
tag/digest, daemon/run logs, invocation/output hashes and timing to establish real M2
runtime evidence outside this API. No model identity/timing is fabricated by this client.

## Antigravity compatibility (read, not modified)

Inspected [score_pilot.py at 103e5f0](https://github.com/TuanKhoa1201/22025523-NTK-UET-Thesis/blob/103e5f0411bcf962cf4b31ee8c07f181ec2dd444/v2/evaluation/score_pilot.py)
on `v2/antigravity-review`; blob `a827c907a6a7b493ee076bf74b67349799191415`.
It expects top-level `alert_id/verdict`, does not recognize SUPPORTED/REFUTED and
generates a location-derived fallback ID for raw OpenGrep. Feeding nested JSONL to it
directly will not join. Use the explicit paired adapter:

```powershell
python -m v2.triage.export_pilot v2/triage/evidence/MY_RUN/assessments.jsonl --raw-json v2/triage/evidence/MY_RUN/input.opengrep.json --output-dir v2/triage/evidence/MY_EXPORT
```

Export `alerts.json` has `{alerts:[...]}` with canonical SHA-based IDs, file_path,
rule/CWE, start/end lines, source_sha256, scan hash and index. `triage.json` has
`{triage_results:[...]}` with matching IDs, mapped verdict, rationale/cited_lines,
source SHA, measured elapsed time converted to ms (null if unavailable), full citations
and runtime. It **always** sets auto_dismissed=false and human_confirmed=false; it
never copies model state into human approval or creates labels. Incomplete evidence
maps to REVIEW; REFUTED whose citations are only in other files maps to REVIEW because
the scorer's line-only format cannot safely represent that grounding.

Pass paired alerts + triage and separately locked labels to the scorer. Its current
FP grounding check is weaker than the producer's exact quote/hash check; it does not
attest runtime. Exclude mock/unverified runs from claims of real Qwen benchmarks until
server evidence is reviewed. Label files prepared for its old location-based IDs need
an explicit reviewed migration to canonical IDs, never an order-only or fuzzy match.

A smoke run of the pinned scorer on four real-engine demo alerts plus four disabled
inference REVIEW records found no missing/orphan/duplicate/CWE/location/hash join
anomalies. Labels were deliberately empty: four UNLABELED alerts, no accuracy claim.

## Mandatory REVIEW / UNDETERMINED

Invalid/duplicate-key JSON; nonzero or unknown engine exit; engine errors/skipped paths;
missing/escaped/non-Java source; unsupported or missing trace; trace/position mismatch;
missing CWE; source version change; HTTP error/timeout/redirect; incomplete response;
wrong model; invalid schema/status/citations; or failed raw-scan/index/ID join. A failed
join is rejected rather than scored against another finding. Unknown runtime does not
by itself change a valid proposed status, but prohibits claims of verified model execution.
