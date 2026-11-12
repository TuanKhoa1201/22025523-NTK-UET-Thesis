# Chương 3: Phương Pháp Đề Xuất và Kiến Trúc Hệ Thống

## 3.1. Tổng Quan Kiến Trúc Đường Ống 7 Bước (End-to-End Pipeline)

Hệ thống được thiết kế theo nguyên tắc **bảo toàn nguồn gốc bằng chứng (Provenance Integrity)** và **an toàn khi gặp lỗi (Fail-Closed by Default)**, gồm 7 bước tuần tự:

```text
[1. Mã nguồn Java]
       │
       ▼ (ScanCapture + OpenGrep v1.25.0 --dataflow-traces --taint-intrafile)
[2. Cảnh báo JSON/SARIF + Biên nhận scan-manifest.json (SHA-256)]
       │
       ▼ (v2/triage/evidence.py + v2/triage/java_context.py + v2/triage/heuristics.py)
[3. Bản ghi Bằng chứng (Evidence Record): CliCall flattened + Enclosing Method/Callee + Heuristic Signals]
       │
       ▼ (v2/triage/ollama.py — Prompt v2.1-cwe22-cwe89-grounded, num_ctx=8192, temperature=0)
[4. Suy luận cục bộ Qwen3.5-9B (qwen3.5:9b-q4_K_M @ 127.0.0.1:11434)]
       │
       ▼ (verify_citations — Kiểm tra SHA-256 tệp, số dòng, và quote nguyên văn)
[5. Phân nhóm 3 trạng thái: Nhóm 1 SUPPORTED | Nhóm 2 REFUTED (PROPOSED_FP) | Nhóm 3 UNDETERMINED]
       │
       ▼ (v2/triage/review.py — Hàng đợi SQLite bất biến, bắt buộc --reviewer, --reason, --cite)
[6. Xác nhận thủ công của Kỹ sư Bảo mật (Human-in-the-Loop Confirmation)]
       │
       ▼ (v2/evaluation/score_pilot.py & build_paired_pilot_table.py)
[7. Đánh giá bắt cặp đa nhánh (Paired Evaluation: Arm A, Arm B, Arm C, Arm D)]
```

---

## 3.2. Định Danh Cảnh Báo Tất Định và Biên Nhận Quét (`ScanCapture` & `scan_receipt.py`)

Mỗi lần quét OpenGrep được bọc bởi lớp `ScanCapture` (`v2/baseline/fork/semgrepai/scan_manifest.py`) và kiểm định lại bằng `v2/triage/scan_receipt.py`:
1. Trước và sau khi chạy OpenGrep, hệ thống tính mã băm SHA-256 của toàn bộ tệp `.java` trong thư mục đích (`sources_before`, `sources_after`) và tệp quy tắc (`rules.snapshot.yml`). Nếu bất kỳ tệp nào thay đổi trong quá trình quét, biên nhận bị từ chối.
2. Mỗi cảnh báo thứ `i` (`finding_index = i`) trong tệp `opengrep.json` (có mã băm `scan_sha256`) được gán một mã định danh duy nhất theo Hợp đồng 1.1:
   `alert_id = SHA256(UTF8(scan_sha256 + ":" + decimal(finding_index)))`.
3. Cơ chế này ngăn chặn triệt để việc ghép nhầm kết quả phân loại của lần quét cũ với tệp quét mới (`verify_repro_contract.py` kiểm tra độc lập và dừng với mã lỗi `3` nếu lệch `scan_sha256`).

---

## 3.3. Nâng Cấp Trích Xuất Bằng Chứng, Giải Phẳng `CliCall` và Mở Rộng Ngữ Cảnh Java (`evidence.py` & `java_context.py`)

Trong giai đoạn sau Báo cáo lần 1, mô-đun trích xuất bằng chứng đã được nâng cấp toàn diện để giải quyết các điểm mù của phiên bản cơ sở `v1.0`:
1. **Giải phẳng đệ quy nút `CliCall` có kiểm chứng byte-offset (`v2/triage/evidence.py`):**
   Khi `dataflow_trace.taint_sink` là một cấu trúc `["CliCall", [[loc, content], call_steps, inner]]` hợp lệ (3 phần tử), hàm `visit` trích xuất vị trí gọi hàm, kiểm chứng byte-offset với tệp nguồn thực tế, thu thập các biến trung gian `call_steps`, và đệ quy vào `inner` để lấy biểu thức sink cuối cùng. Các nút `CliCall` dị dạng (thiếu phần tử hoặc sai cấu trúc) vẫn bị gắn cờ lỗi trong `evidence.issues` để giữ nguyên tính chất fail-closed.
2. **Mở rộng ngữ cảnh phương thức và hàm phụ trợ trong cùng tệp (`v2/triage/java_context.py`):**
   Thay vì chỉ cắt cửa sổ `±5` dòng quanh điểm báo động, hàm `extract_java_context` phân tích cấu trúc lớp và phương thức của tệp Java (tối đa `140` dòng cho snippet `finding`) để bao trùm:
   - Toàn bộ thân phương thức bao ngoài (`enclosing_method`, ví dụ `doPost` hoặc phương thức controller kèm annotation `@RequestMapping`/`@PostMapping`).
   - Toàn bộ thân phương thức phụ trợ trong cùng tệp được gọi trên đường truyền dữ liệu (`same_file_callees`, ví dụ `private class Test { public String doSomething(...) }`).
3. **Loại bỏ trùng lặp snippet và chuẩn hóa ứng viên trích dẫn (`_compact_snippets_for_prompt` & `_candidate_citations`):**
   Các đoạn trích `trace` đã nằm trọn bên trong phạm vi dòng của snippet `finding` được hợp nhất để giảm số lượng token prompt từ `~3,900` xuống `~1,800–2,400` token (kết hợp nâng `num_ctx` từ `4096` lên `8192`). Đồng thời, trường `"matched"` (vốn chỉ chứa một phần dòng mã không có dấu `;`) được lược bỏ khỏi prompt, và danh sách `candidate_citations` cung cấp tối đa 3 dòng đơn (`start_line == end_line`) đã xác thực SHA-256 theo thứ tự tăng dần (`[source_line, middle_line, sink_line]`).

---

## 3.4. Bộ Tín Hiệu Phân Tích Tĩnh Phụ Trợ (`v2/triage/heuristics.py`)

Mô-đun `v2/triage/heuristics.py` đóng hai vai trò: (1) cung cấp trường `heuristic_signals` đi kèm mỗi bản ghi bằng chứng cho chế độ đầy đủ (`--mode evidence+llm`), và (2) vận hành độc lập như một bộ phân loại tất định không dùng LLM ở chế độ đối chứng (`--mode heuristic`, Arm B). Các tín hiệu chính gồm:
- **Tín hiệu nguồn hằng và nhánh điều kiện bất khả thi (`fp_signals`):**
  - `constant_source_wrapper`: Nguồn dữ liệu lấy từ phương thức bọc trả về hằng cố định (`SeparateClassRequest.getTheValue(...)`).
  - `constant_switch_branch`: Biến đích được gán trong cấu trúc `switch (switchTarget)` với `switchTarget = guess.charAt(...)` chọn nhánh hằng số.
  - `constant_conditional_branch`: Biến đích được quyết định bởi biểu thức số học hằng (`(7 * 42) - num > 200`, `(7 * 18) + num > 200`) luôn rơi vào nhánh gán chuỗi hằng.
  - `collection_safe_index_or_remove0`: Phần tử bẩn ở đầu danh sách đã bị xóa bởi `valuesList.remove(0)` trước khi gọi `valuesList.get(...)`, hoặc truy xuất chỉ số chứa hằng số.
  - `map_safe_constant_key`: Truy xuất `map.get("keyA-...")` ứng với khóa chứa chuỗi hằng thay vì khóa chứa dữ liệu người dùng.
  - `cwe22_path_sanitizer` & `cwe89_parameterized_query`: Phát hiện `FilenameUtils.getName`, `getCanonicalPath().startsWith(...)`, hoặc `prepareStatement` sử dụng dấu `?` mà không nối chuỗi động.
- **Tín hiệu bảo toàn dữ liệu bẩn (`tp_signals`):**
  - `collection_tainted_index_preserved`: Khi `"safe"` được thêm ở chỉ số `0` và `valuesList.remove(0)` xóa `"safe"`, đẩy dữ liệu bẩn `param` về đúng chỉ số được lấy ra.
  - `map_tainted_key_retrieved`: Khi khóa được lấy ra tại `map.get(...)` chính là khóa đã gắn dữ liệu bẩn `param`.
  - `cwe89_dynamic_sql_concatenation`: Khi chuỗi truy vấn SQL được ghép nối trực tiếp với biến bẩn trước khi truyền vào `executeQuery`, `executeUpdate` hoặc `prepareStatement`.

---

## 3.5. Cổng Kiểm Chứng Trích Dẫn và Hàng Đợi Xác Nhận Thủ Công (`ollama.py` & `review.py`)

1. **Cổng kiểm chứng trích dẫn (`verify_citations` trong `v2/triage/ollama.py`):**
   Sau khi nhận phản hồi JSON từ `qwen3.5:9b-q4_K_M`, hệ thống kiểm tra từng phần tử trong `citations`:
   - Đường dẫn `path` phải khớp với tệp trong bản ghi bằng chứng.
   - Phạm vi dòng `start_line..end_line` phải nằm trong các dòng đã trích xuất và xác thực SHA-256.
   - Nội dung `quote` phải khớp chính xác từng dòng (sau khi cắt khoảng trắng hai đầu) với tệp mã nguồn gốc.
   Nếu bất kỳ điều kiện nào vi phạm, hoặc danh sách `citations` rỗng đối với kết luận `SUPPORTED`/`REFUTED`, hàm `verify_citations` ghi nhận `citation_check = NOT_VERIFIED` và tự động chuyển `status` về `UNDETERMINED`.
2. **Hàng đợi rà soát thủ công bất biến (`v2/triage/review.py`):**
   Mọi cảnh báo thuộc Nhóm 2 (`REFUTED` / `PROPOSED_FP`) và Nhóm 3 (`UNDETERMINED`) đều mang trạng thái khởi tạo `OPEN` trong bảng `findings` của SQLite. Lệnh `python -m v2.triage decide` chỉ cho phép chuyển trạng thái sang `CONFIRMED_TRUE` hoặc `CONFIRMED_FALSE` khi người duyệt cung cấp đầy đủ `--reviewer`, `--reason` không rỗng, và ít nhất một `--cite path:start-end` nằm trong phạm vi dòng bằng chứng đã xác thực của chính cảnh báo đó. Mọi thao tác đều được ghi nối thêm (append-only) vào bảng `review_events` và tệp nhật ký `decisions.jsonl`.
