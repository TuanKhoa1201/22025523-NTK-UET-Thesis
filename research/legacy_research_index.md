# Scientific and code lineage: historical vs current

Historical repository: https://github.com/TuanKhoa1201/NTK-UET-Thesis

Production migration commits on its `feature/production-e2e-20261028` branch:
- `804d520`: imported React/Vite frontend snapshot.
- `a02edc9`: imported public production backend source.

Original research references include the IRIS research framework and an earlier Semgrep/CodeQL-inspired research path. The current production backend invokes OpenGrep, real OpenJDK 17 Javac AST and a locally fine-tuned Qwen 0.5B LoRA arm.

## Historical reports worth linking, not silently reusing

| Prior repository path | Historical scope | Why it is not production evidence |
|---|---|---|
| `docs/dataset/DATASET_LEAKAGE_AUDIT.md` | V3 split and prompt leakage audit | Different dataset release |
| `docs/dataset/DATASET_TRAINING_READINESS_DECISION.md` | V3 data quality gate | Different data and split strategy |
| `docs/finetuning/FINAL_MODEL_SELECTION_DECISION.md` | 1.5B QLoRA checkpoint | Different base model/adapter |
| `docs/evaluation/FINAL_BENCHMARK_REPORT.md` | 1.5B model; older testing scope | Not EO06 0.5B results |
| `docs/scoring/SAST_SCORING_SPEC_FINAL.md` | SAST scoring V2.1 | Not current bounded safety floor V1.2 |
| `docs/engineering/LOCAL_HYBRID_STATUS.md` | Prior CodeQL-hybrid workbench | Not present production pipeline |

For an academic defense, cite these as **prior work, investigations and corrections**. Copy into the new repository only when provenance labels are retained and legal/privacy checks pass. Retain third-party notices for any redistributed source.
