# Phân Tích Nhóm 3 (`UNDETERMINED` / `REVIEW`) — Nguyên Nhân và Cơ Chế An Toàn

## 1. Vai Trò Của Nhóm 3 (`UNDETERMINED`) Trong Kiến Trúc Triage 3 Nhóm

Khác với cách tiếp cận phân loại nhị phân cưỡng bức (`TP` hoặc `FP`), hệ thống trong đồ án thiết kế **Nhóm 3 (`UNDETERMINED` / `REVIEW`)** làm vùng đệm an toàn (fail-closed fallback). Một cảnh báo được đưa vào Nhóm 3 khi:
1. Bằng chứng trong cửa sổ ngữ cảnh hiện tại không đủ để khẳng định chắc chắn dòng dữ liệu bẩn đi tới sink hay đã bị chặn (`model_status == UNDETERMINED`).
2. Mô hình trả về `SUPPORTED` hoặc `REFUTED` nhưng trích dẫn (`citations`) không khớp nguyên văn với dòng mã nguồn đã xác thực SHA-256 (`citation_check == NOT_VERIFIED`).
3. Xảy ra lỗi kỹ thuật ở tầng suy luận cục bộ (quá thời gian chờ `timeout`, tràn cửa sổ ngữ cảnh `done_reason == length`, hoặc JSON không đúng schema).
4. Tệp mã nguồn hoặc `dataflow_trace` của OpenGrep có cảnh báo toàn vẹn (`evidence.issues` khác rỗng).

---

## 2. Thống Kê Phân Rã Nguyên Nhân `UNDETERMINED` Qua Các Nhánh Thực Nghiệm

### 2.1. Trên Tập Phát Triển `dev_set_16` (`n = 16`)

| Nhánh thực nghiệm | Tổng `UNDETERMINED` | (a) Lỗi trích dẫn (`citation_check = NOT_VERIFIED`) | (b) Lỗi kỹ thuật (`done_reason = length` / JSON lỗi) | (c) Thiếu ngữ cảnh / Bằng chứng chưa đủ kết luận |
|---|---|---|---|---|
| **Exp 1: `v1.0_baseline` (Trước nâng cấp Stage 2–3)** | `10/16 (62.5%)` | `8/16 (50.0%)` | `1/16 (6.2%)` (`BenchmarkTest00018.java`, tràn 4096 token) | `1/16 (6.2%)` (`CliCall` bị từ chối trong `evidence.py`) |
| **Exp 2: `Arm B Heuristic` (`--mode heuristic`)** | `9/16 (56.2%)` | `0/16 (0.0%)` | `0/16 (0.0%)` | `9/16 (56.2%)` (luồng qua helper `Test.doSomething` / `HashMap` ngoài khả năng quy tắc đơn giản) |
| **Exp 3: `Arm D LLM Ablation` (`--mode llm`)** | `1/16 (6.2%)` | `1/16 (6.2%)` | `0/16 (0.0%)` | `0/16 (0.0%)` (nhưng phán nhầm `8/8` FP thành `SUPPORTED` vì thiếu ngữ cảnh!) |
| **Exp 4: `Arm C v2.0` (`--mode evidence+llm`)** | `1/16 (6.2%)` | `1/16 (6.2%)` (`BenchmarkTest00216.java` thiếu dấu `;` ở dòng 69) | `0/16 (0.0%)` | `0/16 (0.0%)` |
| **Exp 5: `Arm C v2.1 Frozen` (`--mode evidence+llm`)** | **`0/16 (0.0%)`** | **`0/16 (0.0%)`** | **`0/16 (0.0%)`** | **`0/16 (0.0%)`** |

### 2.2. Trên Tập Held-Out Đóng Băng `heldout_set_40` (`n = 40`)

| Nhánh thực nghiệm | Tổng `UNDETERMINED` | Phân bố theo nhãn thật (`TP` / `FP`) | Phân bố theo CWE (`CWE-22` / `CWE-89`) | Nguyên nhân chính |
|---|---|---|---|---|
| **Arm B: `Heuristic` (`--mode heuristic`)** | `24/40 (60.0%)` | `11 TP`, `13 FP` | `11 CWE-22`, `13 CWE-89` | Bộ quy tắc tất định chủ động trả về `UNDETERMINED` cho các mẫu truyền qua phương thức nội bộ `Test.doSomething(...)`, `HashMap`, hoặc chuỗi biến đổi phức tạp để tránh đoán mò. |
| **Arm D: `LLM Ablation` (`--mode llm`)** | `9/40 (22.5%)` | `3 TP`, `6 FP` | `7 CWE-22`, `2 CWE-89` | Khi thiếu `java_context` và `heuristic_signals`, mô hình trích dẫn lệch dòng hoặc thiếu dấu chấm phẩy trên `9/40` cảnh báo (`citation_check = NOT_VERIFIED` chuyển về `UNDETERMINED`). |
| **Arm C: `Full Pipeline` (`--mode evidence+llm`)** | **`0/40 (0.0%)`** | `0 TP`, `0 FP` | `0 CWE-22`, `0 CWE-89` | Việc mở rộng snippet bao trùm phương thức + callee cùng tệp, kết hợp `candidate_citations` đơn dòng đã xác thực và `num_ctx = 8192`, giúp giải quyết triệt để cả lỗi kỹ thuật lẫn lỗi lệch trích dẫn trên tập `heldout_set_40`. |

---

## 3. Khi Nào Nhóm 3 (`UNDETERMINED`) Xuất Hiện Trên Mã Nguồn Thực Tế?

Mặc dù trên các tệp tự chứa (self-contained single-file servlets/controllers) của `heldout_set_40`, Arm C giải quyết được `40/40` cảnh báo mà không cần rơi vào `UNDETERMINED`, Nhóm 3 vẫn giữ vai trò thiết yếu khi áp dụng lên các dự án phần mềm thực tế lớn (như được phân tích ở Stage 5 và `EVALUATION_LIMITATIONS.md`):
- Khi hàm làm sạch dữ liệu (sanitizer/validator) hoặc hàm truy vấn nằm ở **một tệp `.java` khác** (cross-file inter-procedural flow) mà bước trích xuất ngữ cảnh nội bộ tệp (`java_context.py`) không đọc tới.
- Khi câu lệnh SQL hoặc đường dẫn tệp phụ thuộc vào cấu hình runtime bên ngoài (Spring XML/properties, biến môi trường) không hiện diện trong mã nguồn tĩnh.
- Khi máy chủ Ollama cục bộ bị quá tải hoặc phản hồi bị cắt cụt: cơ chế fail-closed đảm bảo mọi trường hợp không chắc chắn đều được giữ lại ở Nhóm 3 (`REVIEW`) để con người kiểm tra, tuyệt đối không làm mất lỗ hổng thật.
