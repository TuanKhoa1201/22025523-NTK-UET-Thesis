# Research program: OpenGrep + IRIS-inspired AST + local LLM

## Present production research track (EO06 / VNext3.1)

1. **Data:** provenance-qualified Java API examples for four security-role labels; audited split isolation and difficult negatives.
2. **Model:** local `Qwen2.5-Coder-0.5B-Instruct` LoRA; current production arm `eo06_vnext31_trackb_main`.
3. **Operation:** OpenGrep candidate generation, real Javac AST evidence, structured model predictions, conservative fusion and three-way alert disposition.
4. **Scientific evaluation:** separate classification metrics, finding-level precision/recall, triage safety, rank quality, and complete browser E2E integration.

Read:
- [Dataset provenance and split checks](dataset_provenance.md)
- [Fine-tuning procedure and proof obligations](finetuning_protocol.md)
- [V1.2 scoring specification derived from source](scoring_v1_2.md)
- [Legacy research lineage](legacy_research_index.md)
- [Related scientific and technical work](related_work.md)
- [Evaluation protocol](../evaluation/evaluation_protocol.md)

The repository contains executable **training and inference source**, not necessarily all datasets, model weights, curated manual reviews or raw test predictions. A training program on disk is not proof of a specific metric unless the associated run artifacts are provided and checked.
