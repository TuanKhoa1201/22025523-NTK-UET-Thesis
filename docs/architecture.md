# NTK production architecture

## System identity

- **Static candidate scanner:** OpenGrep OSS (production source lists v1.25.0), Java ruleset `backend/ntk-production-v2/rules/ntk_opengrep_java_ruleset_v1_4.yaml`.
- **Program analysis:** OpenJDK 17 `JavacTask` AST extraction and intra-procedural source/sink/guard evidence. The AST Java source is `scripts/javac_ast_bridge/NtkJavacAstExtractor.java`.
- **Model:** local `Qwen/Qwen2.5-Coder-0.5B-Instruct` with EO06 LoRA adapter `eo06_vnext31_trackb_main` (selected checkpoint identified in production handoff). The role classifier predicts `source`, `sink`, `taint-propagator`, or `none` and can abstain.
- **Evidence and triage:** `ntk_alert_verification.py`, `ntk_iris_shared.py`; decisions `REPORT`, `REVIEW`, `SUPPRESS` with AST-gated automatic suppression.
- **Service:** Python REST server, async jobs, live ten-stage telemetry, scan JSON persistence and SQLite pagination index.
- **Frontend:** React/Vite in `apps/22025523-thesis`, using the configured `VITE_API_BASE_URL`.

## Ten-stage pipeline

| Stage | Purpose | Evidence / implementation |
|---|---|---|
| 01 | Receive GitHub URL or Java ZIP | Safe intake and async job orchestration |
| 02 | Inventory Java source files | `.java` discovery with source-size / count limits |
| 03 | OpenGrep candidate detection | Versioned four-CWE ruleset |
| 04 | Extract relevant source context | Candidate-linked code and callable context |
| 05 | IRIS-inspired Java program analysis | Real Javac AST; intra-procedural taint and guards |
| 06 | Local Qwen LoRA API role classification | Structured response; strict parsing / abstention |
| 07 | Fuse static, AST and model evidence | Explicit provenance and reason codes |
| 08 | Calculate evidence-based heuristic score | `evaluate_bounded_safety_floor` V1.2 |
| 09 | Triage alert | `REPORT`, `REVIEW`, or AST-gated `SUPPRESS` |
| 10 | Persist, index and present results | Scan JSON, SQLite findings pagination, trace |

## Scope and boundaries

Supported rule categories in the production ruleset: **CWE-022, CWE-078, CWE-079, CWE-089**. Other vulnerabilities may appear in intentionally vulnerable Java fixtures, but the four-category ruleset must not be represented as covering those categories. Intra-procedural AST reasoning is not equivalent to complete project-wide interprocedural dataflow. A scanner candidate is not automatically a confirmed vulnerability.

## Trust and network boundary

The LoRA model runs on the ADMIN-PC locally; it is not a cloud LLM. Source acquisition from GitHub is still a network operation. The production health endpoint has previously been accessed through a Tailscale Funnel address; **a public endpoint must be authenticated or restricted**, not merely hidden in a frontend `.env.local`. Do not store dataset rows, tokens, scan contents, or local host paths in public documentation.

## Primary source files

- `backend/ntk-production-v2/scripts/ntk_web_backend_service.py`
- `backend/ntk-production-v2/scripts/ntk_pipeline_telemetry_and_datasets.py`
- `backend/ntk-production-v2/scripts/ntk_alert_verification.py`
- `backend/ntk-production-v2/scripts/ntk_iris_shared.py`
- `backend/ntk-production-v2/scripts/javac_ast_bridge/NtkJavacAstExtractor.java`
- `backend/ntk-production-v2/scripts/eo06_main_train_eval_e2e_pipeline.py`
