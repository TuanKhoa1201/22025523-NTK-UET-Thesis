# HẠN CHẾ THỰC NGHIỆM & CÁC ĐE DỌA TỚI GIÁ TRỊ NGHIÊN CỨU (`EVALUATION_LIMITATIONS`)

- **Giai đoạn:** Stage 4 — Đánh giá thực nghiệm bắt cặp (Paired Evaluation) trên tập Held-Out khóa cứng (`n = 40`)
- **Nhánh thực thi:** `v2/post-report-cwe22-cwe89-20261112`

---

## 1. Đe dọa tới giá trị nội tại (Internal Validity)

1. **Tính bất định tiềm ẩn của mô hình ngôn ngữ lớn (LLM Stochasticity & Prompt Sensitivity):**
   - Dù pipeline đã cố định `temperature = 0`, `stream = False`, `think = False` và `num_ctx = 8192` với bản lượng tử hóa `qwen3.5:9b-q4_K_M`, kết quả của mô hình 9B vẫn phụ thuộc vào cách biểu diễn cấu trúc bằng chứng trong prompt.
   - **Biện pháp giảm thiểu:** Mọi kết luận `SUPPORTED` và `REFUTED` đều phải đi qua bộ kiểm tra trích dẫn строг (`validate_answer`) đối chiếu từng ký tự với tệp nguồn và mã băm SHA-256; nếu lệch dù chỉ một ký tự hoặc dòng trống, hệ thống tự động hạ về `UNDETERMINED` (fail-closed).
2. **Giới hạn của biên nhận HTTP cục bộ (Unsigned Local HTTP Telemetry):**
   - Giao thức HTTP loopback (`127.0.0.1:11434`) ghi nhận đầy đủ `request_payload_sha256`, `response_json_sha256`, `eval_count` và `eval_duration`, nhưng bản thân phản hồi HTTP từ tiến trình Ollama không có chữ ký mật mã phần cứng (TEE/HSM). Do đó, trong `v2/triage/live_check.py`, trạng thái giao thức được báo cáo trung thực là `OLLAMA_REPORTED_UNATTESTED` (`independently_verified_model_runtime = False`).

---

## 2. Đe dọa tới giá trị ngoại tại (External Validity)

1. **Quy mô tập đánh giá bắt cặp (`n = 56` tổng: `16` Development + `40` Held-Out):**
   - Tập Held-Out (`n = 40`, gồm `20 CWE-22` và `20 CWE-89`) vượt ngưỡng tối thiểu `>= 30` cảnh báo của đề cương sau Báo cáo lần 1 và đủ để kiểm chứng thống kê sự khác biệt giữa 4 nhánh (`OpenGrep-only`, `OpenGrep + heuristic`, `OpenGrep + evidence + Qwen`, và `Ablation`), nhưng vẫn là quy mô thực nghiệm vừa phải so với hàng nghìn dự án doanh nghiệp đa mô-đun.
2. **Đặc thù cấu trúc của OWASP BenchmarkJava v1.2:**
   - Các servlet trong OWASP BenchmarkJava v1.2 được thiết kế có chủ đích để kiểm tra khả năng theo vết dòng chảy qua nhánh `switch`, toán tử số học hằng, danh sách `ArrayList`, bản đồ `HashMap`, và lớp nội bộ `Test.doSomething`.
   - Trong các dự án mã nguồn mở lớn (như `OWASP WebGoat` và `java-sec-code` được đánh giá bổ sung ở Stage 5), luồng dữ liệu có thể đi qua nhiều tầng DI (Dependency Injection), ORM (Hibernate/JPA), hoặc bộ lọc chuỗi liên tệp phức tạp hơn.
3. **Phạm vi lớp lỗ hổng trọng tâm (`CWE-22` và `CWE-89`):**
   - Nghiên cứu này đi sâu vào 2 lớp lỗ hổng phụ thuộc mạnh vào dòng chảy dữ liệu và ngữ cảnh làm sạch là `CWE-22` (Path Traversal) và `CWE-89` (SQL Injection). Các lớp lỗ hổng liên quan đến logic nghiệp vụ, điều kiện tranh chấp (Race Condition) hoặc cấu hình sai hệ thống nằm ngoài phạm vi kiểm chứng.

---

## 3. Đe dọa tới giá trị cấu trúc (Construct Validity)

1. **Trích dẫn đúng dòng không đồng nghĩa với chứng minh bảo mật tuyệt đối (`Citation Correctness != Security Proof`):**
   - Mô hình có thể trích dẫn đúng dòng mã nguồn (`citation_check == MATCHED`) nhưng vẫn hiểu sai hàm làm sạch tùy chỉnh của dự án.
   - Do đó, trường `security_conclusion_verified` luôn được gán cứng là `False` và `requires_human_review = True`; phán quyết `REFUTED` chỉ được coi là đề xuất (`PROPOSED_FP`) chứ tuyệt đối không tự động đóng cảnh báo.
2. **Giới hạn phân tích liên tệp của công cụ trích xuất ngữ cảnh (`Same-File Callee Scope`):**
   - Mô-đun `v2/triage/java_context.py` mở rộng ngữ cảnh bao phủ phương thức bao quanh (`enclosing_method`) và các phương thức phụ trợ nằm trong **cùng tệp `.java`** (`same_file_callees`), kết hợp với các vị trí liên tệp có mặt trong `dataflow_trace` của OpenGrep. Nếu một hàm làm sạch tùy chỉnh nằm ở tệp `.java` khác mà OpenGrep không ghi vào `dataflow_trace`, pipeline sẽ không tự suy đoán nội dung tệp ngoài trace và ưu tiên giữ cảnh báo để người duyệt kiểm tra.
