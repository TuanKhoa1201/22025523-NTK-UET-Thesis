# NTK Thesis V2 — Advisor Paired Comparison Table: OpenGrep Standalone (Arm A) vs. OpenGrep + Local Qwen3.5-9B (Arm B)

> [!IMPORTANT]
> **`SYNTHETIC SMOKE PILOT, n=3` (`SYNTHETIC_GROUND_TRUTH`, NOT `INDEPENDENT_GROUND_TRUTH`)**
> - **Dataset Scope**: This paired pilot evaluates the 3 OpenGrep alerts emitted on the synthetic smoke sample `v2/evaluation/smoke_evidence/SmokeVulnSample.java` (`2` synthetic `TRUE_POSITIVE`, `1` synthetic `FALSE_POSITIVE`).
> - **Statistical Restriction**: Because $n=3$ is a synthetic smoke sample and is below the M4 locked benchmark threshold ($n \in [30, 60]$, $\ge 70\%$ CWE-22/CWE-89, `INDEPENDENT_GROUND_TRUTH`), **no generalized Precision, Recall, or False Positive Rate claims** are made from this table. Every metric below is reported with its exact numerator and denominator (`num/den`).
> - **Historical Integrity**: The `qwen3.5:9b-q4_K_M` run (`v2/demo/triage_qwen35_9b_smoke_m1_assessments.jsonl` from `v2/integration-pilot` commit `da26b87206fd0d7a5873e957dc1713cde03fe322`) is preserved unaltered. Alert `[2]` (`safeFileRead`, line 47, `FALSE_POSITIVE` under CWE-22 path traversal) was conservatively classified by `qwen3.5:9b-q4_K_M` as `SUPPORTED` (`KEEP_TP`), resulting in **`0/1 (0.0%)` FP proposed for removal** and **`0/2 (0.0%)` TP erroneously proposed for removal**.
> - **Audit Reference**: See `v2/evaluation/INDEPENDENT_EVALUATION_AUDIT_20261111.md` for the full independent audit of `n=3` provenance (`P0.1`), label validity & lexical leakage analysis (`P0.2`), scorer anti-tampering tests (`P0.3`), and the 30–60 alert independent benchmark protocol (`P0.4`).

---

## 1. Provenance & Cryptographic Lock Manifest

| Provenance Field | Value |
|---|---|
| **Shared OpenGrep Input File** | `v2/demo/smoke_m1_rules_raw.opengrep.json` (OpenGrep `1.16.0`, rule pack `v2/baseline/rules`) |
| **Canonical `scan_sha256` (Contract 1.1)** | `005863f208b58de1195d252a9544fbcef53c53801281345328cf0aff32d4ccb4` (`5698` bytes CRLF working tree; LF git blob SHA-256: `b571e95ec7643d310866c5810a12ba0a0e208f573e173bf2cb264e977753aaaa`, `5509` bytes) |
| **Target Java Source File** | `v2/evaluation/smoke_evidence/SmokeVulnSample.java` (`2131` bytes) |
| **Java `source_sha256`** | `090c9349e4837588c47ae0d920cb841611252c7905b0654fda931648c421a9f9` |
| **Verified Ground-Truth Labels File** | `v2/evaluation/smoke_m1_verified_labels.json` (`label_type = SYNTHETIC_GROUND_TRUTH`, `lock_mode = SMOKE`, `m4_acceptance_ready = false`) |
| **Arm B Primary Triage Input (`Qwen3.5-9B`)** | `v2/demo/triage_qwen35_9b_smoke_m1_assessments.jsonl` (`model = qwen3.5:9b-q4_K_M`, 3/3 saved records, `SHA-256 = dc73a82c6452b9cb5d4eedf88d1e7d2f9344ed517b51b0e60bcd0fff7587c5b5`) |
| **Historical Reference Input (`Qwen3:8b`)** | `v2/demo/triage_qwen3_8b_summary.json` (`run2_smoke_m1_baseline_rules`, `model = qwen3:8b`, reported separately for citation-stability comparison only) |
| **Deterministic `alert_id` Formula** | `SHA256(UTF8(scan_sha256 + ":" + decimal(finding_index)))` per `v2/triage/SCHEMA_CONTRACT.md` §1.1 |

---

## 2. Three-Layer Evaluation Separation (Advisor Methodology Requirement)

To prevent conflating scanner rules, raw LLM classification, and deterministic pipeline gates, all metrics are separated into three distinct layers:

1. **Layer 1 — Scanner Alert Composition (OpenGrep Standalone on Corpus)**:
   - Measures what OpenGrep emits on the target source (`3` alerts total: `2` `TRUE_POSITIVE`, `1` `FALSE_POSITIVE`). Because `SmokeVulnSample.java` is a 3-method synthetic file rather than an external multi-project corpus with known false negatives, scanner-level recall on silent code is not claimed here.
2. **Layer 2 — Raw LLM Classification Quality (`raw_model_status` on OpenGrep Alerts)**:
   - Measures the raw JSON status returned by `qwen3.5:9b-q4_K_M` (`SUPPORTED`, `REFUTED`, `UNDETERMINED`) **before** deterministic citation/SHA-256 gates.
   - Any raw `REFUTED` on a `TRUE_POSITIVE` is explicitly counted in `raw_model_refuted_on_tp` (`0/2` in this run) so that downstream fail-safe gates can never hide a raw LLM false-negative error.
3. **Layer 3 — Post-Gate Pipeline Decision & Human Review Queue (`effective_verdict` + `human_review_state`)**:
   - Measures the final decision after deterministic SHA-256, file/line, and quote verification (`KEEP_TP`, `PROPOSED_FP`, `REVIEW`) alongside the operational human review state (`OPEN`, `CONFIRMED_TRUE`, `CONFIRMED_FALSE`).
   - A `REFUTED` output is surfaced as `PROPOSED_FP` **only** if `citation_check == MATCHED` and source SHA-256 + line quotes match; even then, `human_review_state` remains `OPEN` (`auto_dismissed = 0/3`).

---

## 3. Per-Alert Paired Comparison Table (Arm A vs. Arm B on Identical `scan_sha256`)

| `finding_index` | Contract 1.1 `alert_id` | CWE & `rule_id` | `path:line` & `source_sha256` | Verified Ground Truth (`label_type`) | Arm A: OpenGrep Standalone | Arm B (`qwen3.5:9b-q4_K_M`): Raw $\to$ Post-Check $\to$ Scorer Decision | Arm B Citation Grounding & Latency (`ms`) | Arm B Human Queue State | Historical Ref (`qwen3:8b`, Separate): Raw $\to$ Post-Check $\to$ Decision |
|---:|---|---|---|---|---|---|---|---|---|
| `0` | `5c3fa49a9a739ca38e3711e51b676c5c9894a523a8ef1e5f276a3b7d033672b0` | `CWE-89`<br>`v2.baseline.rules.ntk.java.cwe89` | `v2/evaluation/smoke_evidence/SmokeVulnSample.java:28`<br>`090c9349...648c421a9f9` | `TRUE_POSITIVE`<br>(`SYNTHETIC_GROUND_TRUTH`) | `KEEP` | `SUPPORTED` $\to$ `SUPPORTED` $\to$ **`KEEP_TP`** | `MATCHED` (lines `25,26,27,28`; `sha256=VERIFIED`)<br>`19719.0 ms` (incl. `10895.5 ms` cold load) | `OPEN` | `SUPPORTED` $\to$ `SUPPORTED` $\to$ `KEEP_TP`<br>(`MATCHED`, lines `25..28`, `6719.0 ms`) |
| `1` | `76501a37112c42a9d4e46cf1fadeb1794aa417284ce0ce4d415a6986f5a773e9` | `CWE-22`<br>`v2.baseline.rules.ntk.java.cwe22` | `v2/evaluation/smoke_evidence/SmokeVulnSample.java:33`<br>`090c9349...648c421a9f9` | `TRUE_POSITIVE`<br>(`SYNTHETIC_GROUND_TRUTH`) | `KEEP` | `SUPPORTED` $\to$ `SUPPORTED` $\to$ **`KEEP_TP`** | `MATCHED` (lines `32,33`; `sha256=VERIFIED`)<br>`10953.0 ms` | `OPEN` | `SUPPORTED` $\to$ `UNDETERMINED` $\to$ `REVIEW`<br>(`NOT_VERIFIED`, cited line `2` out of snippet, `8219.0 ms`) |
| `2` | `3252602faf5bdb45ef2a393cdf9d72350514515468d9b170d1083410e7716249` | `CWE-22`<br>`v2.baseline.rules.ntk.java.cwe22` | `v2/evaluation/smoke_evidence/SmokeVulnSample.java:47`<br>`090c9349...648c421a9f9` | `FALSE_POSITIVE`*<br>(`SYNTHETIC_GROUND_TRUTH`) | `KEEP` | `SUPPORTED` $\to$ `SUPPORTED` $\to$ **`KEEP_TP`** | `MATCHED` (lines `45,46,47`; `sha256=VERIFIED`)<br>`10078.0 ms` | `OPEN` | `SUPPORTED` $\to$ `UNDETERMINED` $\to$ `REVIEW`<br>(`NOT_VERIFIED`, cited line `2` out of snippet, `9641.0 ms`) |

*\*Note on Alert `[2]` (`safeFileRead`, line 47): Labeled `FALSE_POSITIVE` (`SYNTHETIC_GROUND_TRUTH`) for CWE-22 directory traversal outside `/var/app/reports/` because `FilenameUtils.getName(rawReportName)` strips all directory prefixes and `/` or `\` separators. However, `qwen3.5:9b-q4_K_M` returned `SUPPORTED` (`KEEP_TP`), reasoning that arbitrary file access **within** `/var/app/reports/` without an explicit allowlist or canonical path check remains a risk. See §5 and `INDEPENDENT_EVALUATION_AUDIT_20261111.md` §2 for full adjudication notes.*

---

## 4. Mandatory Summary Metrics (`num/den` — `SYNTHETIC SMOKE PILOT, n=3`)

| Metric Category | Mandatory Metric | Arm A: OpenGrep Standalone | Arm B: OpenGrep + `qwen3.5:9b-q4_K_M` (Audited Run) | Historical Ref: OpenGrep + `qwen3:8b` (Separate) |
|---|---|---|---|---|
| **Layer 1: Corpus & Labels** | Total OpenGrep Alerts Evaluated | `3/3 (100.0%)` | `3/3 (100.0%)` | `3/3 (100.0%)` |
| **Layer 1: Corpus & Labels** | Verified `TRUE_POSITIVE` Alerts (`SYNTHETIC_GROUND_TRUTH`) | `2` (`CWE-89`: 1, `CWE-22`: 1) | `2` (`CWE-89`: 1, `CWE-22`: 1) | `2` (`CWE-89`: 1, `CWE-22`: 1) |
| **Layer 1: Corpus & Labels** | Verified `FALSE_POSITIVE` Alerts (`SYNTHETIC_GROUND_TRUTH`) | `1` (`CWE-22`: 1) | `1` (`CWE-22`: 1) | `1` (`CWE-22`: 1) |
| **Layer 2: Raw LLM Output** | Raw LLM `REFUTED` on `FALSE_POSITIVE` (Pre-Gate FP Removal) | `0/1 (0.0%)` | **`0/1 (0.0%)`** | `0/1 (0.0%)` |
| **Layer 2: Raw LLM Output** | Raw LLM `REFUTED` on `TRUE_POSITIVE` (Pre-Gate Erroneous TP Removal) | `0/2 (0.0%)` | **`0/2 (0.0%)`** | `0/2 (0.0%)` |
| **Layer 3: Post-Gate Decision** | **FP Correctly Proposed for Removal (`PROPOSED_FP` on True FP)** | `0/1 (0.0%)` | **`0/1 (0.0%)`** | `0/1 (0.0%)` |
| **Layer 3: Post-Gate Decision** | **TP Erroneously Proposed for Removal (`PROPOSED_FP` on True TP)** | `0/2 (0.0%)` | **`0/2 (0.0%)`** | `0/2 (0.0%)` |
| **Layer 3: Post-Gate Decision** | TP Retained via Direct `KEEP_TP` (`SUPPORTED` + `MATCHED`) | `2/2 (100.0%)` | **`2/2 (100.0%)`** | `1/2 (50.0%)` |
| **Layer 3: Post-Gate Decision** | TP Retained via Fail-Safe `REVIEW` (`UNDETERMINED`) | `0/2 (0.0%)` | **`0/2 (0.0%)`** | `1/2 (50.0%)` |
| **Layer 3: Post-Gate Decision** | **Total TP Retained (Not Proposed for Removal)** | `2/2 (100.0%)` | **`2/2 (100.0%)`** | `2/2 (100.0%)` |
| **Layer 3: Post-Gate Decision** | Total Alerts Routed to `UNDETERMINED` / `REVIEW` | `0/3 (0.0%)` | **`0/3 (0.0%)`** | `2/3 (66.7%)` |
| **Reliability & Grounding** | Valid JSON Response Rate | `N/A` | **`3/3 (100.0%)`** | `3/3 (100.0%)` |
| **Reliability & Grounding** | Verified Source Citation Rate (`citation_check = MATCHED`) | `N/A` | **`3/3 (100.0%)`** | `1/3 (33.3%)` |
| **Reliability & Grounding** | Insufficient Evidence Count | `N/A` | **`0/3`** | `0/3` |
| **Reliability & Grounding** | Technical / Runtime / JSON Error Count | `N/A` | **`0/3`** | `0/3` |
| **Reliability & Grounding** | Invalid / Out-of-Range Citation Count (`NOT_VERIFIED`) | `N/A` | **`0/3`** | `2/3` (Alerts `[1]`, `[2]`) |
| **Latency (`ms`)** | Per-Alert Processing Time (`[0]`, `[1]`, `[2]`) | `< 1000 ms` (batch scan) | **`19719.0 ms`, `10953.0 ms`, `10078.0 ms`** | `6719.0 ms`, `8219.0 ms`, `9641.0 ms` |
| **Latency (`ms`)** | Mean / Median (`P50`) / Max (`P95`) Latency (`ms`) | `N/A` | **`13583.3 ms` / `10953.0 ms` / `19719.0 ms`** | `8193.0 ms` / `8219.0 ms` / `9641.0 ms` |
| **Safety Contract** | **Alerts Auto-Dismissed Without Human Confirmation** | **`0/3 (0.0%)`** | **`0/3 (0.0%)`** (all 3 `OPEN`) | `0/3 (0.0%)` (all 3 `OPEN`) |

---

## 5. Independent Audit Findings & Limitations on `n=3` (Summary of `P0.1` & `P0.2`)

1. **Why `qwen3.5:9b-q4_K_M` Outperformed `qwen3:8b` on Grounding Stability (`3/3` vs `1/3` `MATCHED`)**:
   - In the earlier `qwen3:8b` run, the model cited relative line `"line": 2` inside the snippet instead of the actual file lines `32–33` and `45–47`, causing `citation_check = NOT_VERIFIED` on 2 of 3 alerts.
   - `qwen3.5:9b-q4_K_M` cited exact file line numbers (`25–28`, `32–33`, `45–47`) and exact verbatim source quotes on all 3 alerts (`3/3 MATCHED`).
2. **Why `qwen3.5:9b-q4_K_M` Kept Alert `[2]` (`safeFileRead`) as `SUPPORTED` (`KEEP_TP`)**:
   - Even though the method is named `safeFileRead` and calls `FilenameUtils.getName(rawReportName)` at line 46, `qwen3.5:9b-q4_K_M` argued: *"While `FilenameUtils.getName` strips path prefixes, it does not validate that the resulting filename is safe or within an allowed list, and `new File` concatenation remains risky depending on the input and underlying OS handling."*
   - **Security Validity & Unstated Assumptions (`REQUIRES_HUMAN_ADJUDICATION`)**:
     - `FilenameUtils.getName` prevents **parent-directory traversal (`../`)** outside `/var/app/reports/`, which is why the synthetic fixture labeled line 47 `FALSE_POSITIVE` for CWE-22 directory escape.
     - However, `safeFileRead` lacks: (a) an allowlist or per-user authorization check for sensitive sibling files inside `/var/app/reports/`, (b) `Path.toRealPath(LinkOption.NOFOLLOW_LINKS)` protection against symlinks/junctions inside `/var/app/reports/` pointing outside the base directory, and (c) explicit file-type/regular-file checks (`Files.isRegularFile`).
     - Therefore, the historical `FALSE_POSITIVE` (`SYNTHETIC_GROUND_TRUTH`) label is preserved unaltered (`0/1` FP removal), and this exact distinction (inter-directory path traversal vs. intra-directory file access / symlink resolution) is documented as an explicit boundary condition requiring human adjudication in M4.
3. **Lexical Data Leakage Risk in `SmokeVulnSample.java`**:
   - The 7-line context snippets sent to the LLM include the method signatures `unsafeSqlLookup`, `unsafeFileRead`, and `safeFileRead` (and class `SmokeVulnSample`). Such identifier names leak author intent to the LLM. In M4 (`n=30..60`), all benchmark cases must strip diagnostic comments and neutralize `safe*`/`unsafe*`/`vuln*`/`bad*`/`good*` identifiers before scanning and triage.
4. **Formal Citation Grounding $\neq$ Security Proof**:
   - Alert `[2]` demonstrates why `citation_check = MATCHED` + valid `SHA-256` is a **necessary gate**, not a **sufficient proof** of a security conclusion: `qwen3.5:9b-q4_K_M` cited lines `45, 46, 47` with 100% accurate quotes and SHA-256, yet disagreed with the synthetic ground-truth label (`SUPPORTED` vs `FALSE_POSITIVE`).

---

## 6. Reproducible Verification Commands

```powershell
# 1. Regenerate ADVISOR_PAIRED_PILOT_20261111.csv and audit JSON summary
python v2/evaluation/build_paired_pilot_table.py `
  --opengrep v2/demo/smoke_m1_rules_raw.opengrep.json `
  --labels v2/evaluation/smoke_m1_verified_labels.json `
  --qwen35-triage v2/demo/triage_qwen35_9b_smoke_m1_assessments.jsonl `
  --qwen3-8b-reference v2/demo/triage_qwen3_8b_summary.json `
  --source-root v2/evaluation/smoke_evidence `
  --output-csv v2/evaluation/ADVISOR_PAIRED_PILOT_20261111.csv `
  --output-json v2/evaluation/logs/smoke_m1_qwen35_9b_audit_report.json

# 2. Run the 28-test evaluation & anti-tampering unit test suite
python -m unittest discover -s v2/evaluation/tests -p "test_*.py" -v
```
