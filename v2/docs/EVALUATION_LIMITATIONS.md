# HẠN CHẾ THỰC NGHIỆM & CÁC ĐE DỌA TỚI GIÁ TRỊ NGHIÊN CỨU (`EVALUATION_LIMITATIONS`)

- **Giai đoạn:** Stage 4 — Đánh giá thực nghiệm bắt cặp (Paired Evaluation) trên tập Held-Out khóa cứng (`n = 40`)
- **Nhánh thực thi:** `v2/post-report-cwe22-cwe89-20261112`
- **Bản đầy đủ:** Xem tại [`v2/evaluation/post_report/EVALUATION_LIMITATIONS.md`](../evaluation/post_report/EVALUATION_LIMITATIONS.md).

---

## Tóm tắt các giới hạn chính

1. **Internal Validity:** Phản hồi HTTP từ Ollama cục bộ được ràng buộc SHA-256 (`request_payload_sha256`, `response_json_sha256`), nhưng không có chữ ký phần cứng độc lập (`OLLAMA_REPORTED_UNATTESTED`).
2. **External Validity:** Tập Held-Out (`n = 40`) tập trung sâu vào `CWE-22` và `CWE-89` trên OWASP BenchmarkJava v1.2, được bổ trợ bởi quét thực tế trên `OWASP WebGoat` và `java-sec-code` ở Stage 5.
3. **Construct Validity:** `citation_check == MATCHED` chỉ chứng minh trích dẫn khớp nguyên văn mã nguồn, không phải chứng minh toán học về an toàn bảo mật (`security_conclusion_verified = False`, `requires_human_review = True`).
