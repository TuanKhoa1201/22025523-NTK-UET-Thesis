# NHẬT KÝ PHIÊN BẢN HEURISTIC & TÍN HIỆU DẪN XUẤT (`HEURISTIC_CHANGELOG`)

- **Giai đoạn:** Stage 3 — Tinh chỉnh Heuristic & Prompt cho `CWE-22` / `CWE-89` trên tập Development (`dev_set_16`, `n = 16`)
- **Nhánh thực thi:** `v2/post-report-cwe22-cwe89-20261112`
- **Tệp mã nguồn:** `v2/triage/heuristics.py`, `v2/triage/java_context.py`, `v2/triage/evidence.py`
- **Cam kết chống rò rỉ dữ liệu (Zero Leakage):** Mọi quy tắc heuristic và tín hiệu dẫn xuất dưới đây được thiết kế và kiểm thử hoàn toàn trên `SmokeVulnSample.java` (`n = 3`), `UserDao.java` (`n = 5`) và tập `dev_set_16` (`n = 16`), khóa cứng trước khi chạy đánh giá trên `heldout_set_40` (`n = 40`).

---

## 1. Lịch sử phiên bản Heuristic

| Phiên bản | Phạm vi thay đổi | Vấn đề giải quyết | Kết quả trên `dev_set_16` (`8 TP, 8 FP`) |
|---|---|---|---|
| `v1.0-none` (Baseline trước Stage 2/3) | Không có tầng heuristic hay trích xuất ngữ cảnh phương thức Java; từ chối `CliCall`; chỉ lấy `[sl - 3, el + 3]`. | N/A | `TP SUPPORTED = 4/8`, `FP REFUTED = 0/8`, `FP SUPPORTED = 2/8`, `UNDETERMINED = 10/16`. |
| `v2.0-cwe22-cwe89` | Bổ sung `extract_java_context()` và `extract_evidence_signals()`: phân loại nguồn (`HTTP_SERVLET_INPUT` vs `SAFE_CONSTANT_SOURCE_GET_THE_VALUE`), kiểm tra sanitizer `CWE-22` / `CWE-89`, phân tích nhánh `switchTarget`, biểu thức số học hằng `(a * b) +- num > 200`, `List.remove(0)` + `get(1)`, `Map.get`, và phương thức phụ trợ cùng tệp (`Test.doSomething`). | Giải quyết bài toán ngữ cảnh ẩn ngoài `±3` dòng và biểu thức hằng/tập hợp mà LLM 9B thường suy luận nhầm nếu chỉ đọc văn bản thô. | `evidence_signals` khớp `16/16 (100.0%)` nhãn chuẩn; nhưng trên `BenchmarkTest00131` và `00191`, `direct_const_overwrite` bắt nhầm dòng `default:` trước khi xét `intra_flow` của `switch`, và trên `BenchmarkTest00216` (sink 2 dòng `68–69`), `candidate_citations` chỉ chứa dòng `68`. |
| `v2.1-cwe22-cwe89` (**Khóa cứng — Frozen**) | (1) Ưu tiên `intra_flow` (`switch` / số học / danh sách) trước `direct_const_overwrite`; (2) Đưa cả `sink_line` và `sink_end_line` vào `candidate_citations` khi sink trải trên 2 dòng; (3) Khi `source_line` nằm ở phương thức gọi (`doGet` dòng 35), tự động ưu tiên dòng đọc HTTP thực tế trong phương thức bao quanh (`doPost` dòng 44). | Khắc phục trích dẫn dòng `default:` trong `switch` và lỗi thiếu dòng kết thúc của sink đa dòng (`BenchmarkTest00216.java` dòng `69`). | **Arm B (`--mode heuristic`):** `TP SUPPORTED = 4/8`, `FP REFUTED = 3/8`, `UNDETERMINED = 9/16`, `TP bị đề xuất loại nhầm = 0/8 (0.0%)`.<br>**Arm C (`--mode evidence+llm`):** `TP SUPPORTED = 8/8 (100.0%)`, `FP REFUTED = 8/8 (100.0%)`, `TP bị đề xuất loại nhầm = 0/8 (0.0%)`. |

---

## 2. Phân tách vai trò giữa Nhánh B (`--mode heuristic`) và Nhánh C (`--mode evidence+llm`)

1. **Nhánh B (`--mode heuristic`, `heuristic_analyze`):**
   - Chỉ tự động đưa ra kết luận `SUPPORTED` / `REFUTED` khi toàn bộ luồng dữ liệu nằm gọn trong một phương thức đơn giản (ghi đè hằng trực tiếp, `SeparateClassRequest.getTheValue`, sanitizer tường minh, hoặc nhánh `switch`/số học nội phương thức).
   - Khi luồng dữ liệu đi qua lớp/phương thức phụ trợ (`new Test().doSomething(...)`, `ThingFactory.createThing()`) hoặc cấu trúc tập hợp (`ArrayList.remove(0)`, `HashMap`), Nhánh B chủ động trả về `UNDETERMINED` để tránh kết luận quá tự tin bằng luật tĩnh đơn giản.
2. **Nhánh C (`--mode evidence+llm`, `OllamaClient.analyze` với Prompt `v2.1`):**
   - Kết hợp toàn bộ thân phương thức chính + phương thức phụ trợ cùng tệp (`java_context`) với các tín hiệu dẫn xuất (`evidence_signals`) và khả năng tổng hợp ngữ nghĩa của mô hình ngôn ngữ lớn cục bộ `qwen3.5:9b-q4_K_M`, sau đó bắt buộc đi qua bộ kiểm tra trích dẫn `validate_answer()` và cổng duyệt thủ công SQLite (`requires_human_review = True`).
