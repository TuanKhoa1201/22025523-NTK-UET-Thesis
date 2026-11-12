# G0 publication and G1 handoff

Branch: `v2/codex-core`. Base: `8db7dafae6c4abc99ca8a78e9b2e83a0e0b9f204`.
Implementation commit: `92c1d4aac5d642b0311505061f9c5c2d8b890edd`. This handoff receipt is a subsequent documentation commit; its SHA is available from Git history.

AUDIT_EXECUTION_COMPLETED=true, based on positive required-section receipts, nonempty check counts, recorded exit and limitations. This attests execution within the recorded scope, not independent historical runtime authenticity.
G0_ACCEPTANCE=CONDITIONAL. READY_FOR_G1=CONDITIONAL. UNRESOLVED_BLOCKERS=none in the recorded core checks; advisor approval of exclusions/errata remains pending before unconditional acceptance.

Data integrity: PASS within delivered-artifact checks. Metrics: measured C/D recomputation and classification A/B/C/D supported; A/B latency NOT_MEASURED. GT: 56 OWASP cases supported, manual 20 not independently attested; #10 requires review. LLM contribution: CONFOUNDED; no independent improvement over OpenGrep-only is demonstrated.

Historical limitations remain: five INCOMPLETE dispositions; missing original prompt/options and runtime attestation; checkpoint/config and pre-run lock provenance; absent historical stale-source attempt; conditional manual labels. No retrospective evidence was created. Errata approval is PENDING. Supplemental E1?E3 use explicitly attributed peer review, not new local source/runtime attestation.

G1 may proceed only within the disclosed scope with advisor acceptance of exclusions and errata. G1 must capture prompt/argv/model/config/checkpoints and pre-run locks from the beginning. No G1 implementation was performed here.

Validation on 2026-11-13:

- `python -X utf8 -B -m unittest discover -s v2/crosscheck -q`: 54 tests PASS, exit 0 (43 pre-existing tests retained; one unsafe expectation updated to reject unbound errata, 11 new tests). Synthetic fixtures are not runtime evidence.
- Python `ast.parse` on every crosscheck Python module: PASS.
- `python -X utf8 -B v2/crosscheck/finalize_public.py`: exit 0; reproduces true / CONDITIONAL / CONDITIONAL from public receipts and registers.
- `git -c safe.directory=<WORKSPACE> diff --cached --check`: PASS.
- Staged file review: only crosscheck code, documents and public derived tables; no SQLite, raw responses, private payloads, evidence directories or credentials. Personal absolute paths redacted across Markdown/JSON/CSV/Python.

Evidence: G0_FINAL_RESOLUTION.json, G0_RESOLUTION_REGISTER.csv, G0_ERRATA_REGISTER.json, G0_ERRATA.md, historical G0_RAW_INDEPENDENT_VERDICT.* and test_final_gate.py. Public disposition reproduction does not replace raw recalculation, which requires the private evidence package. No OpenGrep/Qwen rerun and no raw edits occurred.

Publication scope includes the initially untracked crosscheck baseline plus this repair. Legacy directories are unchanged. The proposed Antigravity patch was reviewed but replaced with stricter evidence-bound errata and positive execution receipts.
