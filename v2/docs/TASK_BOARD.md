# V2 task board (do not mark done without evidence)

| Gate | Owner | Acceptance evidence | Status |
|---|---|---|---|
| M0 - isolated workspaces | Student + Codex | branches/worktrees, version inventory, no legacy overwrite | TODO |
| M1 - original task | Codex | fork/patch, real OpenGrep command, diff, findings JSON/SARIF, example trace | TODO |
| M2 - real local Qwen | JavisOS + Codex | model ID, actual JSON output and time, log, no mock | TODO |
| M3 - grounded review | Codex + Antigravity | line checks, fail-safe REVIEW, human approval, SHA-256 tests | TODO |
| M4 - locked evaluation | JavisOS + Student | fixed corpus/labels/config, no test-set tuning | TODO |
| M5 - benchmark results | JavisOS + Antigravity | raw counts including erroneously dropped true findings, timing | TODO |
| M6 - advisor handover | Student | three reports, commit links, demo, reproduction instructions | TODO |

Before each milestone update: commit hash, command, result, limitations, and evidence path. Do not mark PASS on text description alone.
