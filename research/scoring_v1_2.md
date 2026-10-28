# Production heuristic SAST evidence fusion V1.2

> **Method classification:** a deterministic heuristic ranking/triage method, **not** CVSS, not a calibrated P(vulnerability), and not an independently validated score of exploitable severity.

## What the current source actually implements

`backend/ntk-production-v2/scripts/ntk_iris_shared.py`, function `evaluate_bounded_safety_floor`, computes:

```text
s = float(base_scanner_score)        # base score is supplied by caller
if valid LLM role == sink: s = min(1, s + 0.15)
if valid LLM role == none: s = max(0, s - 0.35)
# source, taint-propagator, absent or invalid predictions: no role delta
if static severity in {HIGH, CRITICAL, ERROR} and no verified AST release:
    s = max(s, 0.55)                 # safety floor
if AST release is verified:
    effective_post_release_score = 0
else:
    effective_post_release_score = round(s, 4)
```

The function itself does not clamp the initial base score; a base input within [0, 1] is assumed by the surrounding pipeline. The code also records `safety_floor_applied`, `explicit_ast_release_verified`, `llm_role_delta` and a retention threshold of 0.50. The actual `base_scanner_score` mapping is elsewhere in the pipeline; document and test it before claiming this text is a complete score specification.

## How a final alert is triaged

`backend/ntk-production-v2/scripts/ntk_alert_verification.py`, function `verify_and_triage_finding`, uses more than the scalar score:

1. **SUPPRESS / LIKELY_FALSE_POSITIVE:** requires an explicit, structurally verified safe AST release, the Javac AST parser engine, and approved safe trace statuses. Merely labeling an API `none` does not permit automatic suppression.
2. **REPORT / LIKELY_TRUE_POSITIVE:** requires verified AST taint reaches the sink, an approved risky trace status, and a valid LLM `sink` role.
3. **REVIEW / NEEDS_REVIEW:** used for ambiguous evidence, conflicts, abstention/timeouts, or missing trust conditions; the finding remains available for a human.

The review state is distinct from ground truth: the code keeps `review_status=NOT_REVIEWED` unless an explicit manual review record confirms true or false positive.

## Scientific questions before thesis defense

- Why +0.15, -0.35, 0.55 and 0.50? These are **engineering choices**, not scientifically calibrated constants by virtue of appearing in source code.
- Check monotonicity, boundaries, score stability, sensitivity to each parameter, high-severity false-negative protection and ranking quality on independent labelled findings.
- Compare OpenGrep-only, OpenGrep+AST, OpenGrep+LLM, and the full fusion where possible.
- Report precision/recall, missed positives, suppression mistakes and Precision@K with confidence intervals if the sample supports them.
- Do not substitute older V2.1/V2.2 scoring documents or old Qwen 1.5B benchmark for this V1.2 method.
