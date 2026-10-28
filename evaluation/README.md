# Evaluation: reproducible evidence, not marketing metrics

- [Evaluation protocol](evaluation_protocol.md)
- [Evidence register and validation status](evidence_register.md)
- [Current scoring method](../research/scoring_v1_2.md)

## Four separate evaluations

1. **API-role classifier:** precision/recall/F1 per role, macro F1, base-vs-LoRA on locked samples.
2. **SAST finding detection:** per-CWE and per-project findings TP/FP/FN with externally justified labels.
3. **Fusion/scoring/triage:** false-positive suppression safety, ranking and `REVIEW` decision quality; do not treat a heuristic score as a probability.
4. **End-to-end website:** successful job submission, real progress trace, complete index/pagination and reports.

Never describe a health check, successful frontend build, or historical model result as an independent end-to-end benchmark.
