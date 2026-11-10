# Model and token policy (based on models visible in the user's 11 Nov 2026 screenshots)

- **Codex implementation:** GPT-6 Astra, Medium. Escalate reasoning for tricky taint/sanitizer and data-integrity bugs only when supported.
- **Antigravity routine checks/docs:** Gemini 3.8 Flash, Medium. **Security/architecture review:** Gemini 4 Argon, High for a narrow review task only. Alternative second opinion: Claude Sonnet 5.5 if accessible.
- **JavisOS:** prioritize terminal execution and precise logs; use the least costly available general model for setup, escalate only if an actual blocker exists.
- **Product inference:** Ollama `qwen3.5:9b-q4_K_M` on an adequately provisioned server; begin with 4096 context and structured JSON, thinking disabled when required for JSON. If unavailable, test 4B and disclose the change.
- Do not claim relative token price or quality as measured without real usage records.

## Save agent context
1. One task = one bounded prompt with explicit paths, acceptance tests and expected output.
2. Ask the agent to inspect the relevant 2-5 files, not the entire old project.
3. Prefer diff/test output summaries over huge stdout. Preserve full logs in local evidence.
4. Use a new compact handoff when changing agents. Do not repeatedly paste the full teacher PDFs or 21-page plan.
5. Give coding to Codex, review/tests to Antigravity and real execution/evaluation to JavisOS. No concurrent edits to one branch.
