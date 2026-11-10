# NTK Thesis V2 - OpenGrep + local Qwen

Isolated 72-hour implementation track. The previous thesis implementation remains unchanged under `backend/ntk-production-v2/` and `apps/22025523-thesis/`.

Priorities, in order:
1. Prove `simple_semgrepAI` running **real OpenGrep** (the original advisor task).
2. Adapt the advisor-supplied `opengrep-triage` package; demonstrate **real** Ollama/Qwen inference.
3. Ground evidence and preserve REVIEW/UNDETERMINED; add human review and source SHA-256 validation.
4. Run an independent labeled evaluation (prioritize CWE-22 and CWE-89; smoke-test CWE-78 and CWE-79).
5. Prepare report, GitHub milestones and CLI/HTML demo. Reuse the old frontend only if time remains.

Follow: `docs/TASK_BOARD.md`, `docs/MODEL_POLICY.md`, `docs/M0_CHECKLIST.md`.
Teacher-provided archives and PDFs must be kept in a private local `incoming/` folder **outside** the Git repository until licensing and attribution are checked.
