# KIỂM TOÁN CHẤT LƯỢNG BẰNG CHỨNG MÃ NGUỒN JAVA & ĐỘ BAO PHỦ NGỮ CẢNH (`EVIDENCE_QUALITY_AUDIT`)

- **Giai đoạn:** Stage 2 — Nâng cấp trích xuất ngữ cảnh Java, làm giàu bằng chứng và kiểm tra trích dẫn
- **Ngày thực hiện:** `2026-11-12`
- **Nhánh thực thi:** `v2/post-report-cwe22-cwe89-20261112`
- **Bản đầy đủ:** Xem tại [`v2/evaluation/post_report/EVIDENCE_QUALITY_AUDIT.md`](../evaluation/post_report/EVIDENCE_QUALITY_AUDIT.md).

---

## Tóm tắt kết quả Stage 2

- **Khắc phục lỗi `CliCall`:** Nâng tỷ lệ thu thập bằng chứng `CWE-22` trên `dev_set_16` từ `2/8 (25.0%)` lên `8/8 (100.0%)` (`16/16 = 100.0%` trên toàn bộ `dev_set_16` và `40/40 = 100.0%` trên `heldout_set_40`).
- **Mở rộng ngữ cảnh Java (`v2/triage/java_context.py`):** Bao phủ 100% phương thức chính (`enclosing_method`) và phương thức phụ trợ cùng tệp (`same_file_callees`, như `Test.doSomething`).
- **Loại bỏ trùng lặp snippet và nâng `num_ctx = 8192`:** Triệt tiêu hoàn toàn lỗi `incomplete Ollama response` (`done_reason = length` giảm từ `2/10` xuống `0/16`).
