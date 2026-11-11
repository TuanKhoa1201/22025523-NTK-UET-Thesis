# KIỂM TOÁN CHẤT LƯỢNG BẰNG CHỨNG MÃ NGUỒN JAVA & ĐỘ BAO PHỦ NGỮ CẢNH (`EVIDENCE_QUALITY_AUDIT`)

- **Giai đoạn:** Stage 2 — Nâng cấp trích xuất ngữ cảnh Java, làm giàu bằng chứng và kiểm tra trích dẫn
- **Ngày thực hiện:** `2026-11-12`
- **Nhánh thực thi:** `v2/post-report-cwe22-cwe89-20261112`
- **Phạm vi kiểm toán:** `SmokeVulnSample.java` (`n = 3`), `UserDao.java` (`n = 5`), và tập phát triển `dev_set_16` (`n = 16`, gồm `8 CWE-22` và `8 CWE-89`)

---

## 1. Bốn điểm nghẽn kỹ thuật của `v2/triage` v1.0 (trước nâng cấp)

Qua thực nghiệm baseline v1.0 (`runs/stage2_dev16_baseline_v1_0`) trên tập `dev_set_16` (`n = 16`), chúng tôi xác định 4 nguyên nhân gốc rễ làm suy giảm chất lượng bằng chứng và tỷ lệ suy luận thành công:

1. **Từ chối cấu trúc `CliCall` trong `dataflow_trace` (`6/8` cảnh báo `CWE-22` trong `dev_set_16`, và `214/234 = 91.5%` cảnh báo `CWE-22` trên toàn bộ OWASP BenchmarkJava v1.2):**
   - Trong `v2/triage/evidence.py` v1.0 (dòng 202–208), hàm `visit()` chỉ chấp nhận `["CliLoc", [loc, content]]` và lập tức đánh dấu `issues = ["unsupported or missing source/sink trace structure"]` khi gặp `["CliCall", [[loc, content], intermediates, inner]]`.
   - Hệ quả: `6/8` (`75.0%`) cảnh báo `CWE-22` trong `dev_set_16` (`BenchmarkTest00131`, `00216`, `00527`, `00620`, `00863`, `01031`) bị ép về `UNDETERMINED` trước khi gọi Qwen (`http_responses_received = 10/16`).
2. **Cửa sổ trích xuất `[sl - 3, el + 3]` quá hẹp, bỏ sót khối điều kiện và phương thức phụ trợ cùng tệp:**
   - Trong `v2/triage/evidence.py` v1.0 (dòng 135), mỗi snippet chỉ lấy `±3` dòng quanh vị trí dòng chảy.
   - Hệ quả:
     - Các khối `switch (switchTarget)` (`BenchmarkTest00131`, `00191`, `01096`), thao tác danh sách `valuesList.remove(0)` (`BenchmarkTest00190`, `00620`, `01010`, `01031`), và phương thức nội bộ `private class Test { public String doSomething(...) }` nằm ngoài cửa sổ `±3` dòng.
     - Không những Qwen không nhìn thấy các dòng quyết định này, mà bộ kiểm tra trích dẫn `validate_answer()` cũng từ chối mọi trích dẫn trỏ tới các dòng nằm ngoài `record["snippets"]`.
3. **Trùng lặp snippet trung gian làm phình kích thước prompt và chạm trần `num_ctx = 4096` (`2/10` lời gọi HTTP bị `done_reason = length`):**
   - Với các cảnh báo có `10–14` bước `intermediate_vars`, v1.0 lặp lại hàng chục cửa sổ 7 dòng chồng lấn trong JSON gửi cho Ollama.
   - Tại `BenchmarkTest00998.java` (`prompt_eval_count = 3921`, `eval_count = 175`, tổng `4096`) và `BenchmarkTest01096.java` (`prompt_eval_count = 3372`, `eval_count = 724`, tổng `4096`), Qwen bị cắt ngang phản hồi JSON do chạm giới hạn `num_ctx = 4096`, dẫn tới `incomplete Ollama response -> UNDETERMINED`.
4. **Trích dẫn đa dòng (`start_line < end_line`) dễ lệch dòng trống hoặc thụt lề (`2/10` lời gọi HTTP bị `citation text disagrees with source line(s)`):**
   - Tại `BenchmarkTest00103.java` và `BenchmarkTest01010.java`, khi Qwen trích dẫn khoảng 3–8 dòng liên tiếp, mô hình bỏ sót dòng trống ở giữa hoặc thiếu ký tự `;` cuối biểu thức.

---

## 2. Giải pháp nâng cấp trong Stage 2 (`v2/triage/java_context.py` & `v2/triage/evidence.py`)

1. **Bóc tách và kiểm chứng đầy đủ `CliCall` (`v2/triage/evidence.py`):**
   - Hỗ trợ đệ quy cấu trúc 3 phần tử hợp lệ `["CliCall", [[loc, content], call_steps, inner]]`, kiểm chứng byte-offset và nội dung của từng vị trí `call_site`, `call_steps` và `inner` đối chiếu trực tiếp với tệp nguồn.
   - Giữ nguyên cơ chế fail-closed đối với mọi cấu trúc `CliCall` dị dạng (ví dụ `["CliCall", {"unrecognized": True}]`), bảo toàn 100% kiểm thử đơn vị hiện hành (`test_unknown_trace_preserved`).
2. **Trích xuất cấu trúc phương thức Java và mở rộng cửa sổ ngữ cảnh (`v2/triage/java_context.py`):**
   - Phân tích `package`, `imports`, lớp bao quanh (`enclosing_class`), phương thức bao quanh (`enclosing_method` kèm chữ ký, tham số, annotation, cờ `is_entrypoint`), và các phương thức phụ trợ cùng tệp (`same_file_callees` như `doSomething`, `runQuery` và `same_file_callers`).
   - Mở rộng snippet `"finding"` (`snippets[0]`) bao phủ toàn bộ phương thức bao quanh và phương thức phụ trợ cùng tệp trong giới hạn an toàn `<= 140` dòng (`< 150` dòng của `evidence.py`).
3. **Loại bỏ trùng lặp snippet trung gian và nâng `num_ctx = 8192` (`v2/triage/ollama.py`):**
   - Hàm `_compact_snippets_for_prompt()` loại bỏ các snippet `intermediate` đã nằm trọn trong snippet `"finding"`, giảm kích thước prompt từ `~3.900` token xuống `~1.100–1.500` token, đồng thời nâng `num_ctx` từ `4096` lên `8192`.
4. **Chuẩn hóa trích dẫn đơn dòng (`start_line == end_line`) và `candidate_citations`:**
   - Cung cấp danh sách `candidate_citations` đã kiểm chứng SHA-256 và yêu cầu Qwen trích dẫn đơn dòng nguyên văn từng ký tự.

---

## 3. Kết quả định lượng trước và sau nâng cấp Stage 2 trên `dev_set_16` (`n = 16`)

| Chỉ số kiểm toán bằng chứng | Trước nâng cấp (v1.0) | Sau nâng cấp (Stage 2/3 v2.0) | Thay đổi |
|---|---:|---:|---|
| Số cảnh báo thu thập thành công không có `evidence.issues` | `10/16 (62.5%)` | `16/16 (100.0%)` | `+6` cảnh báo `CWE-22` (`CliCall`) |
| Số cảnh báo `CWE-22` không bị lỗi `unsupported trace structure` | `2/8 (25.0%)` | `8/8 (100.0%)` | Khắc phục triệt để `CliCall` |
| Độ phủ toàn bộ thân phương thức chính (`enclosing_method`) | `2/16 (12.5%)` | `16/16 (100.0%)` | Bao phủ 100% `doPost` |
| Độ phủ phương thức phụ trợ nội bộ (`Test.doSomething`) | `0/5 (0.0%)` | `5/5 (100.0%)` | Bao phủ 100% `same_file_callees` |
| Số phản hồi Ollama bị cắt cụt do `num_ctx` (`done_reason = length`) | `2/10 (20.0%)` | `0/16 (0.0%)` | Triệt tiêu lỗi tràn ngữ cảnh |
| Tỷ lệ `citation_check == MATCHED` trên tập phát triển (`dev_set_16`) | `6/16 (37.5%)` | `16/16 (100.0%)` (sau chuẩn hóa `candidate_citations`) | Tăng từ `37.5%` lên `100.0%` |
