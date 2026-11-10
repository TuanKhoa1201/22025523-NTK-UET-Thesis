# NTK Thesis V2 - Agent working contract

Scope: the new `v2/` implementation for Java CWE-22, CWE-78, CWE-79 and CWE-89. Do not refactor, remove or overwrite the legacy `backend/`, `apps/`, `research/` or `evaluation/` unless an explicitly assigned task requires it.

1. Read `v2/docs/TASK_BOARD.md` for the current milestone. Read only task-relevant files; do not load the whole repository or old transcripts.
2. M1 first: prove the original `simple_semgrepAI` -> OpenGrep replacement with genuine commands, stdout/stderr and JSON. A mock is not runtime evidence.
3. Runtime vulnerability analysis uses local OpenGrep + Ollama/Qwen. Never silently send scanned code to a cloud inference endpoint.
4. Ground every LLM evidence citation in actual source lines/trace. Insufficient evidence, malformed JSON or model failure => REVIEW/UNDETERMINED. Never auto-dismiss a finding based on LLM output; require human confirmation.
5. Do not invent metrics, runs, model outputs, citations, SHA values or test results. Distinguish real, fixture/mock and pending work in every report.
6. One agent owns one task/branch/worktree. Avoid editing another agent's files. Commit small, reviewable changes; do not force-push or commit secrets, private source, datasets, checkpoints or large scan outputs.
7. Run focused tests and record exact commands. At the end report: changed files; commands and pass/fail; evidence paths; unresolved issues; commit SHA (if committed). Be concise.

Use `v2/docs/MODEL_POLICY.md` for model/effort decisions and `v2/docs/M0_CHECKLIST.md` before doing Day 1 work.
