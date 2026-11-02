# NTK Graduation Thesis - Final Evidence Checkpoint

- Assessment: **PASS_WITH_DECLARED_LIMITATIONS**
- Commit: `b1e8004912aa1b3e5cd3c54804276f2079c5c1b1`
- Website scan: `SCAN-20261102114457-676FB9`
- Archive SHA256: `366689f2774ce5d4ea4a1dcdd7d01277f3527d2783fceb41a22278c5df6c94be`
- Java inventory: **355/355**
- Findings: **175**; decisions: **{'REVIEW': 106, 'REPORT': 59, 'SUPPRESS': 10}**
- CWSS 16-metric provenance: **175**
- Source provenance: **True**
- GPU calls: **76**; API identities classified: **76**
- Original IRIS: **IRIS_PARTIAL**; reasons: `['API_ROLE_CONTRACT_UNSUPPORTED', 'NATIVE_PARAMETER_CONTRACT_UNSUPPORTED']`

## Verification gates

| Test | Status | Detail |
|---|---|---|
| Stored scan status OK | PASS | OK |
| Java source inventory 355/355 | PASS | 355 found, 355 scanned, 0 skipped |
| 175 persisted findings | PASS | 175 |
| Decision counts | PASS | {'REVIEW': 106, 'REPORT': 59, 'SUPPRESS': 10} |
| Source provenance verified | PASS | True |
| CWSS complete 16-metric provenance 175 | PASS | 175 |
| Full Java inventory contract | PASS | PASS |
| 76 actual Qwen GPU inference calls on first website run | PASS | 76 |
| IRIS was actually enabled | PASS | IRIS_PARTIAL |
| Live backend health | PASS | ntk-iris-local-sast-backend |
| Live API summary | PASS | HTTP 200 |
| Live API trace | PASS | HTTP 200 |
| Recorded 10 pipeline stages | PASS | 10 stages |
| Live API report | PASS | HTTP 200 |
| All 175 findings returned across 4 API pages | PASS | 175 IDs, 175 unique |
| CWSS ranking 175 rows with all 16 metrics | PASS | 175/175 |
| CWSS conditional scenario correctly labeled | PASS | hypothetical=True, verified_deployment=False, rows=5 |

## Existing OWASP benchmark data (development, not held-out)

40 test cases. Review is an abstention: count it separately before defining a binary classifier.

| Engine / evaluation policy | TP | FP | TN | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| OpenGrep candidate detection | 18 | 16 | 4 | 2 | 52.9% | 90.0% | 66.7% |
| NTK REPORT-only (REVIEW negative) | 3 | 0 | 20 | 17 | 100.0% | 15.0% | 26.1% |
| NTK REVIEW treated as positive | 18 | 15 | 5 | 2 | 54.5% | 90.0% | 67.9% |
| NTK decided-only subset | 3 | 0 | 5 | 2 | 100.0% | 60.0% | 75.0% |

- B and C have identical REPORT-only confusion matrices on these cases: True. This does not prove an incremental Qwen accuracy improvement.

## Explicit scientific limitations

- IRIS_PARTIAL is a real mining contract limitation, not a successful full semantic coverage proof.
- 355/355 Java file inventory means source coverage within the configured scope, not exhaustive bug detection.
- REPORT, REVIEW, SUPPRESS are automated decisions, not independent ground-truth labels.
- CWSS values are conditional weakness-priority scores with declared assumptions, not CVSS or true-positive probabilities.
- Current Original IRIS license/source binding and reused CodeQL database are pinned to an attested WebGoat commit; do not claim arbitrary GitHub repository support was demonstrated.
- Existing OWASP 40 cases are development checks, not held-out generalization estimates.

## Manual website acceptance (check during a short demonstration)

- [ ] Scanner accepts exact public GitHub URL and commit SHA, without bounded partial mode.
- [ ] History opens this persisted scan after a browser refresh.
- [ ] Findings page 1-4 lists all 175 distinct records; filtering/pagination works.
- [ ] At least one REPORT and one SUPPRESS detail shows OpenGrep/IRIS/Qwen evidence and 16 CWSS metric provenance fields.
- [ ] CWSS scenario clearly states it is hypothetical, separate from GENERAL_JAVA.
- [ ] Report JSON or HTML can be opened/downloaded; source files are not exposed as secrets.
- [ ] Replay displays actual 10 backend stages and IRIS_PARTIAL transparently.

No engines, model inference, Git checkout mutation, or SQLite changes were executed by this audit.
