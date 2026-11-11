# PHƯƠNG PHÁP ĐÁNH GIÁ THỰC NGHIỆM BẮT CẶP (`EVALUATION_METHOD`)

- **Giai đoạn:** Stage 4 — Đánh giá thực nghiệm bắt cặp (Paired Evaluation) trên tập Held-Out khóa cứng (`n = 40`)
- **Nhánh thực thi:** `v2/post-report-cwe22-cwe89-20261112`
- **Bản đầy đủ:** Xem tại [`v2/evaluation/post_report/EVALUATION_METHOD.md`](../evaluation/post_report/EVALUATION_METHOD.md).

---

## Tóm tắt thiết kế thực nghiệm

1. **Tập Held-Out khóa cứng (`n = 40`):** `20 CWE-22` (`10 TP, 10 FP`) + `20 CWE-89` (`10 TP, 10 FP`), tách biệt 100% với `dev_set_16` (`n = 16`), kiểm chứng qua `validate_pilot_lock.py --mode STRICT_LOCK`.
2. **Bốn nhánh so sánh trên cùng một bản quét OpenGrep:**
   - **Nhánh A (`OpenGrep-only`):** Đầu ra gốc của công cụ phân tích tĩnh.
   - **Nhánh B (`OpenGrep + heuristic`):** `--mode heuristic` (luật nội phương thức không dùng LLM).
   - **Nhánh C (`OpenGrep + evidence + Qwen`):** `--mode evidence+llm` (ngữ cảnh Java mở rộng + tín hiệu dẫn xuất + `qwen3.5:9b-q4_K_M` + kiểm tra trích dẫn + cổng duyệt thủ công).
   - **Nhánh D (`Ablation: OpenGrep + Qwen ít ngữ cảnh`):** `--mode llm` (cửa sổ hẹp `±3` dòng, không có ngữ cảnh phương thức mở rộng và tín hiệu dẫn xuất).
3. **Chỉ số an toàn tối thượng:** `TP bị đề xuất loại nhầm` (`erroneously_proposed_fp_on_tp`), kèm đầy đủ `tử số / mẫu số` cho mọi tỷ lệ phần trăm.
