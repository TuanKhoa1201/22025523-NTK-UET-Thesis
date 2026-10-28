# Production evaluation protocol (draft; metrics pending verification)

## Experimental units and gold standard

- **API-classification unit:** a qualified Java API/callee with CWE context and a locked role label.
- **Detection unit:** a source finding with stable project commit, file, line/region, CWE and adjudicated vulnerable/safe status. Match findings to gold using a documented tolerance and avoid counting multiple overlapping candidates as multiple TPs.
- **Triage unit:** one candidate and its `REPORT`/`REVIEW`/`SUPPRESS` decision; a suppressed false negative is a major safety error.
- **UI unit:** a complete `scan_id`/`job_id` with stage trace, result-store state and paginated findings.

## Baselines / ablations (only claim measured arms)

- OpenGrep candidate-only.
- OpenGrep + Javac AST evidence.
- OpenGrep + local untuned/base Qwen where a comparable base run is feasible.
- Full OpenGrep + AST + LoRA evidence fusion V1.2.

Evaluate each arm on **the same locked corpus** with rule versions, model revisions, compute and prompts held constant as much as feasible. Do not cross-compare earlier 1.5B reports with the current 0.5B release as if they were controlled same-corpus experiments.

## Required measures

- Roles: macro-F1, per-role precision/recall/F1, confusion, abstention and invalid schema rate.
- Detection: per-CWE TP/FP/FN, precision/recall/F1, prevalence and class balance; report uncertain labels separately.
- Triage: per-decision counts, FN among auto-suppressed, human review queue and trace completeness.
- Ranking: Precision@K and other ranking metrics on independently labelled findings; sensitivity to role delta and safety floor.
- Runtime: cold/warm model inference, stage latencies, total E2E, source inventory limits and API persistence/index consistency.

## Isolation and integrity gates

1. Record corpus version, commit or exact ZIP checksum and source license.
2. Lock split by family/class as appropriate, verify duplicates and prompt collisions.
3. Do not train/select based on held-out test scores.
4. Preserve raw prediction metadata and the exact evaluation script and version.
5. Record GPU, Python, OpenGrep, Java, model and adapter SHA-256.
6. Save reproducible structured summaries, then manually check a sample of reported and suppressed findings.
7. Record explicit limitation: not all unsupported CWEs or frameworks are covered.

## Security/privacy

Perform corpus evaluations on isolated, approved fixtures and licensed inputs. Never upload private prompts, code or model weights to GitHub merely to make the demo easier to reproduce.
