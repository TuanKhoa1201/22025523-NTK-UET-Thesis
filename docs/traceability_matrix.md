# Thesis requirements and verifiable evidence

| Requirement | Implementation anchor | Evidence needed for defense | Status at repository initialization |
|---|---|---|---|
| Open-source static detection | `backend/ntk-production-v2/rules/ntk_opengrep_java_ruleset_v1_4.yaml` | Version and command capture; candidate examples | Source present; runtime health reported available |
| Real program analysis | `scripts/javac_ast_bridge/NtkJavacAstExtractor.java` and `ntk_alert_verification.py` | Parse and flow traces on positive/negative cases | Source present; fresh E2E regression pending |
| Local LLM | `scripts/eo06_main_train_eval_e2e_pipeline.py` and service inference | Local load logs; no cloud inference; device/cold-start | Source and handoff evidence exist; clean-machine reproduction pending |
| Fine-tuning with provenance | `research/dataset_provenance.md`, `research/finetuning_protocol.md` | Split manifests, labels, checkpoint hash, train/dev/test evaluation | Evidence selection in progress |
| SAST scoring and FP triage | `research/scoring_v1_2.md` and `ntk_iris_shared.py` | Formula, sensitivity and human-reviewed outcome validation | Implementation inspected; calibration/accuracy not claimed |
| Two-stage training and operation | EO06 training script and 10-stage REST pipeline | Model checkpoint, trace, end-to-end results | Runtime trace regression pending |
| Demo on GitHub Java/ZIP | React app, REST backend and fixture | Browser run with video/screenshots/trace | Health/build verified, browser E2E pending |
| Version control progression | Current production repository plus legacy research repository | Commits, timestamps, reports and evidence hash | Production initialized, later work must use separate commits |

**Important:** These statuses do not imply that an independent jury has validated the experiments. Cite exact source files and immutable evaluation outputs in the thesis report.
