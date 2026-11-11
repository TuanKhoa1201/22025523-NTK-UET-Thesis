# NHẬT KÝ THỰC NGHIỆM PROMPT & SO SÁNH CÁC NHÁNH TRÊN TẬP DEVELOPMENT (`PROMPT_EXPERIMENT_LOG`)

- **Giai đoạn:** Stage 3 — Tinh chỉnh Heuristic & Prompt cho `CWE-22` / `CWE-89` trên tập Development (`dev_set_16`, `n = 16`)
- **Nhánh thực thi:** `v2/post-report-cwe22-cwe89-20261112`
- **Bản đầy đủ:** Xem tại [`v2/evaluation/post_report/PROMPT_EXPERIMENT_LOG.md`](../evaluation/post_report/PROMPT_EXPERIMENT_LOG.md).

---

## Tóm tắt kết quả trên `dev_set_16` (`n = 16`: `8 TP, 8 FP`)

- **Baseline `v1.0`:** `TP SUPPORTED = 4/8`, `FP REFUTED = 0/8`, `UNDETERMINED = 10/16`, `citations_matched = 6/16`.
- **Arm B (`--mode heuristic`):** `TP SUPPORTED = 4/8`, `FP REFUTED = 3/8`, `UNDETERMINED = 9/16`, `TP bị đề xuất loại nhầm = 0/8`.
- **Arm D (`--mode llm` ablation — ít ngữ cảnh):** `TP SUPPORTED = 7/8`, `FP REFUTED = 0/8`, `FP SUPPORTED = 8/8`, `citations_matched = 15/16`.
- **Arm C (`--mode evidence+llm`, Prompt `v2.1` khóa cứng):** `TP SUPPORTED = 8/8 (100.0%)`, `FP REFUTED = 8/8 (100.0%)`, `TP bị đề xuất loại nhầm = 0/8 (0.0%)`, `citations_matched = 16/16 (100.0%)`.
