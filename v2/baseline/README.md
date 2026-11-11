# M1: simple_semgrepAI → local OpenGrep

Latest original-task verification: [ROOT_CAUSE_REPAIR_REPORT.md](ROOT_CAUSE_REPAIR_REPORT.md).
`prepare_upstream_local.py` requires a clean full pinned checkout and the private
advisor ZIP, and prepares the inherited Typer scan path with a guarded --scan-only
overlay, minimal scanner config and real subprocess recording. It never activates
RAG/cloud. This is distinct from the extracted scanner-only fork below; full CLI
runtime remains PENDING here. The NTK patch now includes the new scan_manifest.py
module (four resulting fork files), not only the original three-file extraction.

Current original-task status (including private advisor-patch comparison and the
blocked full-upstream CLI attempt): [ADVISOR_ORIGINAL_TASK_STATUS.md](ADVISOR_ORIGINAL_TASK_STATUS.md).
`advisor_probe.py` accepts private `--advisor-dir` and optional `--upstream` clean
pinned clone, recording patch/help/scan as separate outcomes. It does not publish
advisor source. `verify_handoff.py` checks that raw JSON, findings, rule IDs and
traces survive transfer to NTK triage unchanged.

Advisor handover: [ADVISOR_M1_EVIDENCE.md](ADVISOR_M1_EVIDENCE.md), including
copyable real-engine and source-change demos. Verify patch reproduction/application
with `python v2/baseline/verify_patch.py`; this checks actual Git apply and exact upstream blobs.

This is a bounded scanner-only fork of [hardw00t/simple_semgrepAI](https://github.com/hardw00t/simple_semgrepAI/tree/2c79a58a16d11e9dea3723e30d2a7faffba7bdc9),
version 0.2.0, commit `2c79a58a16d11e9dea3723e30d2a7faffba7bdc9`, MIT.
The exact targeted snapshot is in `upstream/`, with Git blob hashes in
`upstream/PROVENANCE.json`; it is not a complete upstream checkout. MIT notices are retained.

Run from the workspace root in PowerShell (Python 3.10+ and a separately installed
OpenGrep are required; verified here with Python 3.13.3 / OpenGrep 1.20.0):

```powershell
$env:PYTHONPATH = Join-Path (Get-Location) 'v2/baseline/fork'
python -m semgrepai v2/baseline/fixtures/java --output-dir v2/baseline/evidence/my-run
python v2/baseline/verify_real.py v2/baseline/evidence/my-run
python -m unittest discover -s v2/baseline/tests -v
python v2/baseline/make_patch.py
```

Use a fresh output directory. The verifier specifically checks the supplied synthetic
two-file demonstration, not arbitrary target code. For another Java project:

```powershell
python -m semgrepai 'C:\path\to\java-project' --rules-path v2/baseline/rules/java.yml --output-dir v2/baseline/evidence/project-run
```

Optional flags: `--executable`, `--timeout` (per rule/file seconds; process limit is
timeout + 30 seconds for each invocation), `--jobs`. The local rule file is required.
The scanner performs separate real JSON and SARIF invocations, preserving each
command, exit code, stdout/stderr and raw output. It restricts targets to `*.java`.
`--no-git-ignore` prevents engine Git calls and includes Git-ignored Java files;
choose the target directory carefully. Logs/settings go into the selected output
directory because this Windows sandbox cannot write OpenGrep's default home log.
No installation, ACL change, administrator access or global Git trust change is needed.

Inherited from upstream: the `SemgrepScanner` class name, `scan` result envelope,
finding metadata, code-context extraction, reference and security-pattern helpers.
Changed here: executable/argv, explicit local configuration, evidence capture, error
handling, safe empty results, and native `extra.dataflow_trace` preservation (including
tagged `CliLoc`/nested values). The legacy top-level trace is only a fallback.
Missing traces remain empty; unknown trace shapes are retained without invented steps.
The normalized `dataflow` field can therefore be a native object, not upstream's list.
The verifier checks the real trace content against exact source byte offsets and lines.

The original scanner used `semgrep`, registry `auto`, and read only a top-level
trace list. Upstream config/CLI initialize cloud-capable LLM/RAG modules and do not
wire scanner config consistently. This fork replaces the config and CLI with a
standard-library scanner path; it never imports validators, calls cloud inference,
learns false positives, or dismisses findings. All findings require human REVIEW.
Engine failures, invalid JSON/SARIF or engine-reported errors exit nonzero with
REVIEW/UNDETERMINED; an empty successful scan still returns a results envelope.
Local Ollama/Qwen inference belongs to M2 and has not been implemented or tested here.
Do not install the upstream pyproject as the fork's runtime package.

`rules/java.yml` contains four new demonstration taint rules for CWE-22/78/79/89.
They recognize `getParameter` sources and a small set of sinks. They do not model
all frameworks, sanitizers, interprocedural cases, or every vulnerable/safe idiom.
`Safe.java` is a constant-only negative control; these fixtures are not a benchmark.

Review `opengrep.patch` against the pinned files; regenerate it with `make_patch.py`.
The runnable fork also adds package entrypoints and retains the MIT license.
This patch is for the scanner-only extraction; applying it to the full upstream
application does not make its web/LLM modules compatible or local-only.

See [M1_REPORT.md](M1_REPORT.md) for actual results and [evidence/README.md](evidence/README.md)
for local artifact paths. Generated outputs remain ignored by Git.
