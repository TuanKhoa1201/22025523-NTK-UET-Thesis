# NTK Thesis V2 — Independent Evaluation Audit & M4 Experimental Design (`P0.1`–`P0.4`)

- **Audit Date**: `2026-11-11`
- **Auditor Role**: Independent Evaluation Auditor & Experimental Methodology Engineer (`v2/antigravity-review`)
- **Base Commit Audited**: `c061d7ff8a62d58e57ab368ecc6297a938cea28c` (`v2/antigravity-review`)
- **Cross-Checked Integration Commit**: `da26b87206fd0d7a5873e957dc1713cde03fe322` (`origin/v2/integration-pilot`)
- **Advisor Reference Sources**: `C:\Users\HP\OneDrive\Documents\NTK-Thesis-V2\_advisor_sources` (21-page Thesis V2 Plan §§4.3, 7.3, 8–10, 16–17; 5-page Immediate Action Plan pp. 4–5; Reference Code `benchmark.py`, `triage.py`, `tests/test_pipeline.py`; `REQUIREMENTS_MATRIX.md`)

---

## 1. `P0.1` — Independent Audit of the `n=3` Paired Dataset & Saved `Qwen3.5-9B` Records

### 1.1 Cryptographic & Provenance Verification Across All 4 Artifacts

We independently inspected and cross-verified the raw bytes, SHA-256 digests, line numbers, and Contract 1.1 `alert_id` joins across:
1. **Target Java Source**: `v2/evaluation/smoke_evidence/SmokeVulnSample.java`
   - Size: `2,131` bytes
   - `source_sha256`: `090c9349e4837588c47ae0d920cb841611252c7905b0654fda931648c421a9f9`
2. **Shared Raw OpenGrep JSON**: `v2/demo/smoke_m1_rules_raw.opengrep.json`
   - Engine: OpenGrep `1.16.0`, rule pack `v2/baseline/rules`
   - Canonical `scan_sha256` (Windows CRLF working tree, `5,698` bytes):
     `005863f208b58de1195d252a9544fbcef53c53801281345328cf0aff32d4ccb4`
   - Git LF blob `SHA-256` (`5,509` bytes):
     `b571e95ec7643d310866c5810a12ba0a0e208f573e173bf2cb264e977753aaaa`
3. **Saved Real `Qwen3.5-9B` Triage JSONL**: `v2/demo/triage_qwen35_9b_smoke_m1_assessments.jsonl` (from `origin/v2/integration-pilot` commit `da26b87206fd0d7a5873e957dc1713cde03fe322`)
   - Size: `34,784` bytes (`3` JSONL lines)
   - File `SHA-256`: `dc73a82c6452b9cb5d4eedf88d1e7d2f9344ed517b51b0e60bcd0fff7587c5b5`
4. **Verified Labels File**: `v2/evaluation/smoke_m1_verified_labels.json`
   - `label_type`: `SYNTHETIC_GROUND_TRUTH` (`lock_mode = SMOKE`, `m4_acceptance_ready = false`)

### 1.2 Verification Checklist for `P0.1`

| Audit Check | Expected Requirement | Verified Actual Value | Status |
|---|---|---|---|
| **Shared `scan_sha256`** | Identical across OpenGrep JSON, labels, and all 3 `Qwen3.5` records | `005863f208b58de1195d252a9544fbcef53c53801281345328cf0aff32d4ccb4` on all 3 records (`evidence.scan_sha256`) | **PASS** |
| **Shared `source_sha256`** | Identical across `SmokeVulnSample.java`, labels, snapshots, snippets, and citations | `090c9349e4837588c47ae0d920cb841611252c7905b0654fda931648c421a9f9` on all 3 records (`snapshots`, `snippets`, `citations[*].sha256`) | **PASS** |
| **Contract 1.1 `alert_id` Join** | Exact 1-to-1 join via `SHA256(UTF8(scan_sha256 + ":" + decimal(finding_index)))` | `[0]`: `5c3fa49a9a739ca38e3711e51b676c5c9894a523a8ef1e5f276a3b7d033672b0`<br>`[1]`: `76501a37112c42a9d4e46cf1fadeb1794aa417284ce0ce4d415a6986f5a773e9`<br>`[2]`: `3252602faf5bdb45ef2a393cdf9d72350514515468d9b170d1083410e7716249` | **PASS** |
| **Declared & Runtime Model ID** | Must be `qwen3.5:9b-q4_K_M`; no `qwen3:8b` substitution | `assessment.model = "qwen3.5:9b-q4_K_M"`, `runtime.model = "qwen3.5:9b-q4_K_M"`, `raw_response.model = "qwen3.5:9b-q4_K_M"` on all 3 records | **PASS** |
| **Saved Historical Output Integrity** | All 3 records are saved outputs (`SUPPORTED` + `MATCHED`), not regenerated or altered | HTTP 200 responses with distinct `response_body_sha256` (`440566cc...`, `0933cda5...`, `c15b05b5...`); all 3 have `status = "SUPPORTED"` and `citation_check = "MATCHED"` | **PASS** |
| **Alert `[2]` (Line 47 FP) Behavior** | `safeFileRead` (line 47, `FALSE_POSITIVE`) conservatively kept as `KEEP_TP` | Raw `SUPPORTED` $\to$ Post-check `SUPPORTED` $\to$ Scorer `KEEP_TP` (`kept_tp_on_true_fp = 1`) | **PASS** |
| **Exact Mandatory Ratios** | FP proposed for removal `0/1`; erroneous TP removal `0/2`; auto-dismissed `0/3` | FP removal: **`0/1 (0.0%)`**; Erroneous TP removal: **`0/2 (0.0%)`**; Auto-dismissed: **`0/3 (0.0%)`** (all 3 `state = "OPEN"`) | **PASS** |

### 1.3 Detailed Record-by-Record Telemetry (`triage_qwen35_9b_smoke_m1_assessments.jsonl`)

| `finding_index` | `alert_id` | Rule & Line | `response_body_sha256` | `elapsed_seconds` (`latency_ms`) | Ollama `load_duration` / `eval_count` | Citations Verified (`MATCHED`) | Raw & Final Verdict |
|---:|---|---|---|---:|---|---|---|
| `0` | `5c3fa49a...033672b0` | `cwe89` (`SmokeVulnSample.java:28`) | `440566cc08c04964e9d279521d9b149844c3a06ff840942fd6174759680c51cd` | `19.719 s` (`19719.0 ms`) | `10.895 s` cold model load / `334` tokens | Lines `25, 26, 27, 28` | `SUPPORTED` $\to$ `KEEP_TP` (`OPEN`) |
| `1` | `76501a37...5a773e9` | `cwe22` (`SmokeVulnSample.java:33`) | `0933cda5ddbba7095e056377bd32b6f548b5c39bd813af34caa078b70e28c0c5` | `10.953 s` (`10953.0 ms`) | `0.105 s` warm / `458` tokens | Lines `32, 33` | `SUPPORTED` $\to$ `KEEP_TP` (`OPEN`) |
| `2` | `3252602f...6249` | `cwe22` (`SmokeVulnSample.java:47`) | `c15b05b5462870f724da546060f8bef873f22efcbf75322da7c6d2bfa9d55b28` | `10.078 s` (`10078.0 ms`) | `0.097 s` warm / `409` tokens | Lines `45, 46, 47` | `SUPPORTED` $\to$ `KEEP_TP` (`OPEN`) |

> [!NOTE]
> **Runtime Telemetry Observation**: In all 3 records of `triage_qwen35_9b_smoke_m1_assessments.jsonl`, `runtime` records `http_response_received: true`, `http_status: 200`, `model_identity_matched: true`, and `answer_validated: true`, while `origin: "unverified"` and `model_runtime_verified: false`. Inspection of `v2/triage/ollama.py` confirms that `model_runtime_verified` is only set to `true` when an auxiliary `/api/ps` process-table snapshot is attached alongside `/api/chat`. For M4 benchmark runs, we recommend enabling the `/api/ps` runtime check so `model_runtime_verified` is `true` in every record.

---

## 2. `P0.2` — Audit of Label Validity, Sanitizer Assumptions & Data Leakage Risks

### 2.1 Investigation 1: Lexical Label Leakage via Method and Class Identifiers

In `SmokeVulnSample.java`, the three methods are named:
- Line 24: `public ResultSet unsafeSqlLookup(HttpServletRequest request, Connection connection)`
- Line 31: `public FileInputStream unsafeFileRead(HttpServletRequest request)`
- Line 44: `public FileInputStream safeFileRead(HttpServletRequest request)`

**How the leakage reaches the LLM**:
When `v2/triage/evidence.py` extracts a `±3` line window around each OpenGrep finding (`lines 25–31` for Alert `[0]`, `lines 30–36` for Alert `[1]`, and `lines 44–50` for Alert `[2]`), the method declarations `unsafeFileRead` (line 31) and `safeFileRead` (line 44) are **directly included inside `evidence.snippets[0].lines`** and passed verbatim in the prompt to `qwen3.5:9b-q4_K_M`. Furthermore, line 46 uses the local variable name `String cleanName = FilenameUtils.getName(rawReportName);`.

- **Impact on `n=3` Smoke Pilot**: Interestingly, despite the strong lexical hint `safeFileRead` and `cleanName` at lines 44–46, `qwen3.5:9b-q4_K_M` **did not** blindly trust the method name; it still returned `SUPPORTED` (`KEEP_TP`). However, on a larger benchmark, identifier names like `safe*`, `unsafe*`, `vuln*`, `good*`, `bad*`, or benchmark comments (`// BAD`, `// GOOD`, `// CWE-89`) create severe **lexical label leakage** that can artificially inflate LLM accuracy without testing real dataflow/sanitizer reasoning.
- **Mandatory Mitigation for M4 (`n=30..60`)**: All M4 evaluation files must undergo deterministic **Lexical Neutralization** before locking `source_sha256`:
  1. Strip all diagnostic comments (`//`, `/* ... */`) that mention CWE numbers, `safe`/`unsafe`, `good`/`bad`, `TP`/`FP`, or benchmark provenance.
  2. Rename telltale class, method, and local variable identifiers (`safeFileRead` $\to$ `handleRequestB`, `unsafeFileRead` $\to$ `handleRequestA`, `cleanName` $\to$ `value2`) using deterministic identifier normalization before computing `source_sha256` and running OpenGrep + Qwen3.5.

### 2.2 Investigation 2: Under What Exact Conditions Is `FilenameUtils.getName` a CWE-22 Sanitizer?

In `SmokeVulnSample.java` (lines 44–49):
```java
44:     public FileInputStream safeFileRead(HttpServletRequest request) throws Exception {
45:         String rawReportName = request.getParameter("report");
46:         String cleanName = FilenameUtils.getName(rawReportName);
47:         File reportFile = new File("/var/app/reports/" + cleanName);
48:         return new FileInputStream(reportFile);
49:     }
```

Our independent code audit identifies the exact boundary between **inter-directory path traversal** (where `FilenameUtils.getName` acts as a sanitizer) and **intra-directory / filesystem-level risks** (where unstated assumptions remain):

1. **What `FilenameUtils.getName(rawReportName)` Guarantees (Why Line 47 Is Labeled `SYNTHETIC_GROUND_TRUTH = FALSE_POSITIVE` for Directory Escape)**:
   - Apache Commons IO `FilenameUtils.getName(String)` locates the last forward slash (`/`) or backslash (`\`) and returns only the substring after it (and throws `IllegalArgumentException` if a NUL byte `\u0000` is present).
   - Therefore, an input such as `"../../etc/passwd"` becomes `"passwd"`, and `new File("/var/app/reports/" + cleanName)` resolves to `"/var/app/reports/passwd"`. The attacker **cannot traverse into parent or sibling directories** outside `/var/app/reports/` via `../` or `..\` sequences.
   - Degenerate inputs:
     - `rawReportName = ""`, `"foo/"`, or `null` $\to$ `cleanName` is `""` or `"null"`. For `""`, `new File("/var/app/reports/")` is a directory, so `new FileInputStream(reportFile)` throws `FileNotFoundException` (cannot read directory as stream).
     - `rawReportName = "."` or `".."` $\to$ `new File("/var/app/reports/.")` or `new File("/var/app/reports/..")` resolves to a directory (`new FileInputStream` throws `FileNotFoundException`).

2. **Unstated Security Assumptions & Residual Risks (`REQUIRES_HUMAN_ADJUDICATION` in Real Production Code)**:
   - **Assumption A — Single-Tenant / Public-Within-Directory Policy**: `safeFileRead` enforces **no allowlist, file extension check, or user-level authorization** on files inside `/var/app/reports/`. If `/var/app/reports/` stores reports belonging to multiple users (`userA_report.pdf`, `admin_secret.pdf`) or application configuration files, any caller can read any sibling file inside `/var/app/reports/`. Notice that `qwen3.5:9b-q4_K_M` explicitly cited this reason (*"it does not validate that the resulting filename is safe or within an allowed list"*).
   - **Assumption B — Absence of Symbolic Links / Junctions Inside `/var/app/reports/`**: Because `safeFileRead` uses `new File(...)` without resolving canonical paths via `Path.toRealPath(LinkOption.NOFOLLOW_LINKS)` and checking `realPath.startsWith(realBaseDir)`, if an attacker or another process can plant a symlink inside `/var/app/reports/link_to_shadow` pointing to `/etc/shadow`, `new FileInputStream("/var/app/reports/link_to_shadow")` will follow the symlink outside `/var/app/reports/`.
   - **Assumption C — OS / Filesystem Semantics**: On Windows NTFS, `FilenameUtils.getName("report.txt:secret_ads")` does not strip colon (`:`) alternate data stream suffixes or Windows reserved device names (`CON`, `NUL`, `COM1`).

**Audit Decision on Historical Dataset**:
Per `P0.2` rules, **we do not alter the historical `FALSE_POSITIVE` (`SYNTHETIC_GROUND_TRUTH`) label or recalculate the `0/1` score**. Instead, we document that `SmokeVulnSample.java:47` is a `SYNTHETIC_GROUND_TRUTH` false positive **strictly under the narrow CWE-22 parent-directory escape definition** (assuming a trusted, symlink-free `/var/app/reports/` directory where all regular files are public to the caller), and that `qwen3.5:9b-q4_K_M`'s conservative `SUPPORTED` (`KEEP_TP`) verdict reflects a stricter allowlist/canonical-path security posture (`REQUIRES_HUMAN_ADJUDICATION`).

### 2.3 Investigation 3: Why Agent-Verified Labels on `SmokeVulnSample.java` Are `SYNTHETIC_GROUND_TRUTH`, Not `INDEPENDENT_GROUND_TRUTH`

1. **Author & Evaluator Coupling**: `SmokeVulnSample.java` was authored inside the project specifically to test the 2 baseline rules (`cwe22`, `cwe89`) with 2 vulnerable methods and 1 `FilenameUtils.getName` method.
2. **Agent Verification vs. Independent Ground Truth**: When an AI agent (`antigravity-audit-verification`) inspects `SmokeVulnSample.java` to confirm what the code does, that verification confirms **internal consistency with the fixture's design**, not **external benchmark independence**.
3. **Enforcement in Code**:
   - In `v2/evaluation/smoke_m1_verified_labels.json`, every label is stamped `"label_type": "SYNTHETIC_GROUND_TRUTH"`, `"lock_mode": "SMOKE"`, and `"m4_acceptance_ready": false`.
   - In `v2/evaluation/score_pilot.py` and `v2/evaluation/validate_pilot_lock.py`, we added hard programmatic checks (`FORBIDDEN_INDEPENDENT_LABEL_ANNOTATORS = {"antigravity", "agent", "javis", "synthetic", "fixture", "ai"}`) that **reject** any label claiming `"label_type": "INDEPENDENT_GROUND_TRUTH"` (or attempting to pass `STRICT_LOCK`) if `annotated_by` is missing or contains any agent/synthetic identifier.

### 2.4 Investigation 4: Does Valid `SHA-256` + Exact Line Citation Prove the Security Conclusion Is Correct?

**No.** Formal citation grounding (`citation_check = MATCHED` + matching `source_sha256` + verbatim `quote` match) is a **necessary syntactic/provenance condition**, never a **sufficient semantic proof** of a security verdict:

1. **What `SHA-256` + Line Citation Proves**:
   - The LLM read the exact locked version of the file (`source_sha256`).
   - The line numbers and code quotes cited by the LLM actually exist in that file and are non-blank, non-comment code lines (`verified_line_map`).
   - The LLM did not hallucinate non-existent lines (which happened in 2/3 alerts with `qwen3:8b`, where it cited `"line": 2`).
2. **What It Does NOT Prove (Empirical Proof from Alert `[2]`)**:
   - A model can cite the **exact right lines** (`45, 46, 47`) with a **100% valid `source_sha256`** and **exact verbatim quotes** (`String cleanName = FilenameUtils.getName(rawReportName);`), and still reach a **different or incorrect security conclusion** (e.g., `qwen3.5:9b-q4_K_M` concluding `SUPPORTED` on Alert `[2]`, or conversely, a model citing a partial check that does not actually sanitize the sink and concluding `REFUTED`).
3. **Why Both Gates Are Required**:
   - **Gate 1 (Deterministic Citation & SHA-256 Gate)**: Blocks hallucinated or ungrounded `REFUTED` claims from ever becoming `PROPOSED_FP`.
   - **Gate 2 (Independent Ground-Truth Labels in Evaluation / Human Confirmation in Production)**: Evaluates whether a grounded `PROPOSED_FP` is actually a `FALSE_POSITIVE` (`proposed_fp_on_true_fp`) or an erroneous dismissal of a `TRUE_POSITIVE` (`erroneously_proposed_fp_on_tp`), and requires human sign-off (`CONFIRMED_FALSE` / `CONFIRMED_TRUE`) before any alert leaves the operational queue.

---

## 3. `P0.3` — Scorer Hardening & Anti-Tampering Unit Test Verification

### 3.1 Code Hardening Applied in `v2/evaluation/`

We hardened `v2/evaluation/codex_adapter.py`, `v2/evaluation/score_pilot.py`, `v2/evaluation/validate_pilot_lock.py`, and `v2/evaluation/build_paired_pilot_table.py` against all 6 failure/tampering modes required in `P0.3`:

| `P0.3` Threat / Failure Mode | Hardening Implemented in `v2/evaluation/` | Unit Test Coverage |
|---|---|---|
| **1. Shuffled finding order vs. wrong/swapped `alert_id` join (including intra-file swaps)** | `codex_adapter.match_and_convert_codex_records` and `score_pilot.evaluate_pilot` now verify not only `file_path`, but also `start_line`, `rule_id`, and `finding_index` when matching by explicit `alert_id` or `codex_id`. Reordered JSONL records join 1-to-1 cleanly, while swapping two `alert_id`s inside the same file (`SmokeVulnSample.java` line 33 vs. line 47) is caught and routed to `REVIEW`. | `test_2_deterministic_id_matching_and_mismatch_rejection`,<br>`test_12_shuffled_finding_order_vs_intra_file_alert_id_swap` |
| **2. Wrong `model_id` (e.g. `qwen3:8b` substituting for `qwen3.5`)** | `score_pilot.evaluate_pilot(..., expected_model_prefix="qwen3.5")` logs mismatches in `anomalies.model_mismatches` and overrides `effective_verdict` to `REVIEW`. `build_paired_pilot_table._verify_model_family` raises `ValueError` if non-`qwen3.5` records are passed to `--qwen35-triage`. | `test_11_paired_pilot_table_rejects_qwen3_8b_masquerade_and_builds_rows`,<br>`test_13_wrong_model_id_rejected_and_routed_to_review` |
| **3. Wrong `source_sha256`, wrong/missing citations, or fabricated citation `quote` text** | `codex_adapter.convert_single_codex_record` extracts per-citation `quote` and `sha256` (`citation_quotes`). `score_pilot._validate_evidence_grounding` rejects `PROPOSED_FP` if `citation_check == "NOT_VERIFIED"`, if per-citation `sha256` mismatches `expected_sha`, or if `quote` does not match `verified_line_map[line]`. | `test_3_wrong_or_missing_sha256_blocks_refuted_fp`,<br>`test_4_refuted_with_nonexistent_or_comment_citation_overridden_to_review`,<br>`test_14_wrong_citation_quote_and_citation_sha256_blocked` |
| **4. Duplicate evaluation data (`duplicate_alert_ids`, `duplicate_label_ids`, `duplicate_triage_ids`)** | Duplicate alert/label/triage IDs are logged in `IntegrityAnomalies` AND any alert with `duplicate_label_ids` or `duplicate_triage_ids` is fail-safe routed to `REVIEW` (`override_reasons` includes `"duplicate_label_id"` / `"duplicate_triage_id"`), preventing duplicate records from ever producing a `PROPOSED_FP`. | `test_duplicate_ids_detection_and_deduplication`,<br>`test_15_duplicate_triage_and_label_records_fail_safe_to_review` |
| **5. Labels missing provenance or masquerading as `INDEPENDENT_GROUND_TRUTH`** | `score_pilot.py` and `validate_pilot_lock.py` reject labels claiming `INDEPENDENT_GROUND_TRUTH` when `annotated_by` is missing, contains agent/synthetic tokens (`FORBIDDEN_INDEPENDENT_LABEL_ANNOTATORS`), or lacks `annotator_rationale` ($\ge 10$ chars). | `test_6_no_ground_truth_and_reject_auto_generated_labels`,<br>`test_16_labels_missing_provenance_or_masquerading_as_independent_rejected` |
| **6. `TRUE_POSITIVE` proposed for removal counted in both Layer 2 (raw LLM) and Layer 3 (post-gate)** | `CweBucketMetrics` tracks both Layer 2 (`raw_model_refuted_on_tp` / `raw_model_erroneous_tp_removal` and `fail_safe_blocked_tp_refutations`) and Layer 3 (`erroneously_proposed_fp_on_tp` / `erroneous_tp_removal`), ensuring that even if a raw `REFUTED` on a TP is blocked by citation/SHA-256 gates, the raw LLM error is still counted and visible. | `test_8_erroneously_proposed_tp_removal_tracked_with_numerator_denominator`,<br>`test_17_tp_proposed_for_removal_counted_in_both_raw_layer2_and_post_gate_layer3` |

---

## 4. `P0.4` — Concrete Experimental Design for the Next M4 Independent Benchmark (`n = 30..60` Alerts)

To transition from `SYNTHETIC SMOKE PILOT, n=3` (`SYNTHETIC_GROUND_TRUTH`) to an advisor-grade M4 evaluation (`STRICT_LOCK`, `m4_acceptance_ready = true`), the next experiment must follow this locked 6-step protocol:

### 4.1 Target Size & CWE Stratification (`n = 30..60`, $\ge 70\%$ Priority CWEs)

| Tier | CWE | Target Alert Count | Share of Locked Benchmark (`n = 40` Target) | Required Ground-Truth Mix |
|---|---|---:|---:|---|
| **Priority Tier 1** ($\ge 70\%$ required) | `CWE-22` (Path Traversal) | `15–20` alerts | `37.5%–45.0%` | $\ge 6$ `TRUE_POSITIVE`, $\ge 6$ `FALSE_POSITIVE` |
| **Priority Tier 1** ($\ge 70\%$ required) | `CWE-89` (SQL Injection) | `15–20` alerts | `37.5%–45.0%` | $\ge 6$ `TRUE_POSITIVE`, $\ge 6$ `FALSE_POSITIVE` |
| **Secondary Tier 2** ($\le 30\%$, reported separately) | `CWE-78` (OS Command Injection) & `CWE-79` (XSS) | `6–10` alerts | `15.0%–25.0%` | $\ge 3$ `TRUE_POSITIVE`, $\ge 3$ `FALSE_POSITIVE` |
| **Total Locked M4 Benchmark** | **All 4 Scoped Java CWEs** | **`36–50` alerts** (within `[30, 60]`) | **`100.0%`** ($\ge 75\%$ Tier 1) | Balanced TP/FP with explicit `AMBIGUOUS` bucket |

### 4.2 Independent Source Selection & Data Split Firewall (Preventing Tuning on Test Data)

1. **Strict Dev / Test Split (`DEV_TUNING_SPLIT` vs. `M4_LOCKED_EVAL_SPLIT`)**:
   - **Rule & Prompt Tuning Split (`DEV_TUNING_SPLIT`)**: `SmokeVulnSample.java` (`n=3`) and any iterative rule/prompt debugging samples belong exclusively to `DEV_TUNING_SPLIT`. Codex and JavisOS may inspect errors on `DEV_TUNING_SPLIT` to refine OpenGrep YAML patterns or prompt instructions.
   - **Locked Evaluation Split (`M4_LOCKED_EVAL_SPLIT`, `n=30..60`)**: Drawn from external, publicly auditable Java benchmark/CVE sources (e.g., OWASP Benchmark for Java, Juliet Java Test Suite 1.3 for CWE-22/78/79/89, or pinned real-world vulnerable/patched Java servlet/JDBC classes) that were **not** used to write the baseline rules or prompt templates.
   - **Zero Post-Lock Tuning Rule**: Once `validate_pilot_lock.py --mode strict` generates the `combined_lock_sha256` manifest for `M4_LOCKED_EVAL_SPLIT`, **no changes** to `v2/baseline/rules/` or `v2/triage/` prompts are permitted without incrementing the experiment version and reporting both pre-change and post-change runs.

### 4.3 Mandatory Pre-Scan Lexical Neutralization (Anti-Leakage Step)

Before computing `source_sha256` or running OpenGrep on `M4_LOCKED_EVAL_SPLIT`:
1. **Comment Stripping**: Remove all header/inline comments (`/* ... */`, `// ...`) from the Java files so benchmark metadata (such as OWASP Benchmark's `//real vulnerability` or Juliet's `/* POTENTIAL FLAW */` / `goodG2B()`) cannot leak labels to `qwen3.5:9b-q4_K_M`.
2. **Identifier Neutralization**: Rename method, class, and variable identifiers containing `safe`, `unsafe`, `good`, `bad`, `vuln`, `fixed`, `sanitized`, `cwe22`, `cwe89`, `cwe78`, `cwe79` to neutral domain identifiers (`processReport`, `queryAccount`, `resolveTarget`, `paramValue`).
3. **Explicit CWE-22 Sanitizer Patterns in Corpus**: Include distinct, realistic Java sanitizer idioms across the `FALSE_POSITIVE` cases so the evaluation tests genuine sanitizer reasoning rather than a single API:
   - Pattern A: `Path target = baseDir.resolve(userInput).normalize(); if (!target.startsWith(baseDir)) throw new SecurityException();`
   - Pattern B: Strict allowlist validation (`if (!ALLOWED_FILES.contains(fileName)) throw ...` or `^[a-zA-Z0-9_.-]+$` regex check).
   - Pattern C: `FilenameUtils.getName(input)` combined with explicit directory/allowlist context, plus adversarial cases where `normalize()` is called **without** `startsWith(baseDir)` (`TRUE_POSITIVE`) to test whether the LLM catches incomplete sanitization.

### 4.4 Independent Ground-Truth Labeling & Adjudication Protocol

1. **Dual Provenance (`INDEPENDENT_GROUND_TRUTH`)**:
   - Every alert in `M4_LOCKED_EVAL_SPLIT` must be linked to:
     - `external_benchmark_source`: upstream benchmark test ID / CVE / commit SHA, AND
     - `annotated_by`: human reviewer identifier (e.g., `"ntk-human-reviewer-1"`), **never** an LLM or agent identifier.
     - `annotator_rationale`: concrete source-to-sink dataflow or sanitizer explanation ($\ge 10$ chars) citing exact line numbers.
2. **Blinded Labeling Before LLM Execution**:
   - `labels.json` must be finalized and locked via `validate_pilot_lock.py --mode strict` **before** running `qwen3.5:9b-q4_K_M` triage on the scan.
   - Any alert where sanitizer completeness depends on external environment assumptions (e.g., symlink policy or intra-directory multi-tenant access) must be explicitly labeled `"ground_truth": "AMBIGUOUS"` upfront (`needs_review_on_ambiguous`), rather than retroactively relabeled after seeing the model's output.

### 4.5 Execution & Gate Verification Checklist for M4 Run

```powershell
# Step 1: Validate STRICT_LOCK readiness (must return exit code 0 and m4_acceptance_ready = true)
python v2/evaluation/validate_pilot_lock.py `
  --mode strict `
  --opengrep v2/evaluation/m4_locked_scan.opengrep.json `
  --labels v2/evaluation/m4_locked_labels.json `
  --source-root <path-to-neutralized-java-corpus> `
  --output-manifest v2/evaluation/m4_lock_manifest.json

# Step 2: Score Arm A (OpenGrep) vs. Arm B (OpenGrep + qwen3.5:9b-q4_K_M)
python v2/evaluation/build_paired_pilot_table.py `
  --opengrep v2/evaluation/m4_locked_scan.opengrep.json `
  --labels v2/evaluation/m4_locked_labels.json `
  --qwen35-triage v2/evaluation/m4_qwen35_9b_assessments.jsonl `
  --source-root <path-to-neutralized-java-corpus> `
  --output-csv v2/evaluation/M4_PAIRED_BENCHMARK_RESULTS.csv `
  --output-json v2/evaluation/logs/m4_paired_benchmark_summary.json
```
