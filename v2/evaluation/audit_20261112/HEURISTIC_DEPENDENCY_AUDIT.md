# BIÊN BẢN KIỂM TOÁN SÂU NGUY CƠ MÔ HÌNH QWEN PHỤ THUỘC ĐÁP ÁN HEURISTIC

- **Mã kiểm toán**: `AUDIT-20261112-HEURISTIC-STEERING`
- **Nhánh đối tượng**: `v2/post-report-cwe22-cwe89-20261112` @ `86636b9de22e59efcca2d3786434727c6ae082e4`
- **Các tệp mã nguồn kiểm toán trực tiếp**:
  - `v2/triage/evidence.py` (dòng `250–288`)
  - `v2/triage/heuristics.py` (dòng `17–640`)
  - `v2/triage/ollama.py` (dòng `35–191`, `246–280`)
  - `v2/triage/cli.py` (dòng `68–144`)
- **Kết luận kiểm toán mục 4.C**: **`FAIL` (Mức `CRITICAL` — Rò rỉ phán quyết tiền định của heuristic vào prompt của Qwen ở chế độ `evidence+llm` và bất đối xứng baseline giữa Arm B / Arm C)**; đối với nội dung nguyên văn của 40 prompt thực tế trên máy chủ `ADMIN-PC`: **`NOT_VERIFIED`** (chờ JavisOS đối chiếu `assessments.jsonl`).

---

## 1. Phân biệt bắt buộc 5 thực thể dữ liệu (Không đồng nhất)

Theo yêu cầu kiểm toán mục 4.C, biên bản này tách biệt tuyệt đối 5 trường/khái niệm sau trong toàn bộ luồng dữ liệu:

| STT | Thực thể dữ liệu | Nguồn sinh thực tế trong mã nguồn | Vị trí lưu / truyền | Vai trò bản chất | Có truyền vào prompt Qwen (`Arm C`)? |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | **Tín hiệu kỹ thuật hỗ trợ Qwen** (*Technical signals*) | `extract_evidence_signals()` (`v2/triage/heuristics.py:532-542`) và `extract_java_context()` (`v2/triage/evidence.py:258`) | `record["java_context"]` và một phần của `record["heuristic_signals"]` (`source_kind`, `source_line`, `sink_line`, `uses_inner_helper`, `uses_thing_factory`, `sanitizers_found`, `non_sanitizers_found`) | Cấu trúc hóa thông tin phương thức bao quanh, hàm nội bộ cùng tệp và vị trí source/sink | **CÓ** (`ollama.py:150-158`) |
| **2** | **Phán quyết do heuristic đề xuất trước** (*Heuristic pre-verdict*) | `extract_evidence_signals()` (`v2/triage/heuristics.py:446-529, 543-545`) | `record["heuristic_signals"]["recommended_status"]`, `["recommendation_reason"]`, `["candidate_citations"]`, `["intra_method_flow"]["outcome"]`, `["callee_method_flow"]["outcome"]` | Kết luận phân loại định sẵn (`"SUPPORTED"` hoặc `"REFUTED"`), lời giải thích tiếng Việt hoàn chỉnh và danh sách trích dẫn dựng sẵn | **CÓ — RÒ RỈ TRỰC TIẾP** (`ollama.py:157-158, 174-177`) |
| **3** | **Nhãn chuẩn từ OWASP** (*Official Ground Truth*) | `expectedresults-1.2.csv` (OWASP BenchmarkJava v1.2 @ `8b67a88d...`) -> `labels_development.*`, `labels_heldout.*` | Chỉ nạp trong `v2/evaluation/score_pilot.py` sau khi suy luận đã kết thúc | Nhãn tham chiếu độc lập (`TRUE_POSITIVE` / `FALSE_POSITIVE`) dùng để chấm điểm | **KHÔNG** (Đã xác minh `evidence.py`, `heuristics.py`, `ollama.py`, `cli.py` không đọc tệp nhãn hay trường `ground_truth`/`expected_label`) |
| **4** | **Phán quyết nguyên gốc do Qwen tạo ra** (*Raw Qwen verdict*) | Phản hồi JSON từ `POST /api/chat` của Ollama (`qwen3.5:9b-q4_K_M`) | `response["message"]["content"]` (`ollama.py:275`), ghi nhận ở `PAIRED_EVALUATION.csv` cột `*_raw_status` | Đầu ra trực tiếp của LLM trước khi kiểm tra trích dẫn/ngữ cảnh | Đầu ra của LLM |
| **5** | **Phán quyết cuối cùng sau bộ kiểm chứng** (*Post-verifier verdict*) | `validate_answer()` (`ollama.py:35-75`) tại runtime và `_verify_proposed_fp_evidence()` / `normalize_triage_record()` (`score_pilot.py:553-677`, `codex_adapter.py`) khi chấm điểm | `assessment["status"]` (hạ về `"UNDETERMINED"` nếu vi phạm schema/trích dẫn/hash) và cột `*_post_status` trong `PAIRED_EVALUATION.csv` | Kết luận đề xuất sau khi kiểm tra sự tồn tại dòng mã, `quote` và `sha256` (vẫn giữ `requires_human_review = True`) | Hậu xử lý sau LLM |

---

## 2. Truy vết đường truyền dữ liệu thực tế trong mã nguồn (`file:line`)

### Bước 1: Sinh `heuristic_signals` ngay khi đóng gói bằng chứng (`evidence.py`)
Tại `v2/triage/evidence.py:279-283`, ngay trong hàm `collect()` (trước khi gọi bất kỳ chế độ phân tích nào), mọi bản ghi cảnh báo có `snippets` đều được gắn sẵn kết quả của `extract_evidence_signals(rec_obj)`:

```python
# v2/triage/evidence.py:279-283
try:
    from .heuristics import extract_evidence_signals
    rec_obj["heuristic_signals"] = extract_evidence_signals(rec_obj) if snippets else None
except Exception:
    rec_obj["heuristic_signals"] = None
```

### Bước 2: `extract_evidence_signals()` giải sẵn toàn bộ các mẫu OWASP Benchmark và luôn gán nhãn nhị phân `SUPPORTED` / `REFUTED` (`heuristics.py`)
Trong `v2/triage/heuristics.py`:
1. **Regex chuyên biệt cho cấu trúc mã của OWASP BenchmarkJava v1.2** (dòng `53-81`):
   - `SAFE_SOURCE_RE` (dòng `23`): bắt `getTheValue(` (hàm nguồn hằng số `"bar"` của `SeparateClassRequest` trong OWASP Benchmark).
   - `THING_FACTORY_RE` (dòng `54`): bắt `ThingFactory.createThing()`.
   - `GUESS_LITERAL_RE` & `SWITCH_TARGET_RE` (dòng `57-61`): giải tường minh hằng `String guess = "ABC"; char switchTarget = guess.charAt(2);` và từng nhánh `case` trong `switch` (`_analyze_method_block`, dòng `179-245`).
   - `INT_NUM_RE`, `ARITH_TERNARY_RE`, `ARITH_IF_RE` (dòng `63-70`): tính toán biểu thức số học hằng kiểu `(7 * 42) - num > 200` hoặc `(7 * 18) + num > 200` (`_analyze_method_block`, dòng `247-291`).
   - `LIST_ADD_RE`, `LIST_REMOVE_RE`, `LIST_GET_RE` (dòng `72-76`): mô phỏng danh sách `valuesList.add(...)`, `valuesList.remove(0)`, `valuesList.get(idx)` (`_analyze_method_block`, dòng `139-151, 293-315`).
   - `MAP_PUT_RE`, `MAP_GET_RE` (dòng `78-81`): mô phỏng bảng băm `map.put("keyA-...", ...)`, `map.get("keyB-...")` (`_analyze_method_block`, dòng `152-155, 317-337`).
   - Duyệt cả phương thức bao quanh (`enc_lines`, dòng `405-406`) **lẫn phương thức nội bộ cùng tệp** như `Test.doSomething` (`callee_flow`, dòng `408-426`).
2. **Không tồn tại nhánh `"UNDETERMINED"` trong `recommended_status`** (dòng `446-515`):
   - Dòng `447` khởi tạo mặc định: `recommended_status = "SUPPORTED"` kèm `recommendation_reason` tiếng Việt khẳng định dữ liệu truyền tới sink không qua làm sạch.
   - Các nhánh `if/elif` từ dòng `456-514` chuyển `recommended_status` sang `"REFUTED"` hoặc giữ `"SUPPORTED"`, đồng thời sinh sẵn câu giải thích tiếng Việt (`recommendation_reason`) và tối đa 3 đối tượng trích dẫn hoàn chỉnh (`candidate_citations`, dòng `517-529`) có sẵn `path`, `start_line`, `end_line`, `quote` và `sha256`.

### Bước 3: Truyền nguyên vẹn `heuristic_signals` vào JSON user prompt và hướng dẫn Qwen sao chép trong system prompt (`ollama.py`)
Tại `v2/triage/ollama.py:125-179`:
- Ở chế độ mặc định `mode = "evidence+llm"` (`Arm C`), dòng `157-158` đưa **nguyên khối** `record["heuristic_signals"]` (bao gồm `recommended_status`, `recommendation_reason`, `candidate_citations`, `intra_method_flow`, `callee_method_flow`) vào payload gửi cho Qwen:
  ```python
  # v2/triage/ollama.py:157-158
  if record.get("heuristic_signals"):
      evidence["evidence_signals"] = record["heuristic_signals"]
  ```
- Trong `system` prompt (dòng `174-178`), Qwen được chỉ thị trực tiếp:
  > `"When evidence_signals is supplied, carefully verify its dataflow analysis and candidate_citations against snippets. CRITICAL CITATION RULE: Include 1 to 3 citation objects copied directly from evidence_signals.candidate_citations without changing start_line, end_line, or quote..."`
- Ngược lại, ở chế độ `mode = "llm"` (`Arm D`, dòng `84-99` và `135`), Qwen **đồng thời** bị cắt hai thứ cùng lúc:
  1. Cửa sổ mã nguồn bị thu hẹp xuống `[sl - 3, el + 3]` (không mở rộng toàn hàm `doPost` và không có `Test.doSomething`).
  2. Toàn bộ `trace_steps`, `java_context_summary` **và** `evidence_signals` đều bị tắt (`if mode != "llm":` tại dòng `135`).

---

## 3. Thực nghiệm kiểm chứng độc lập trên toàn bộ 56 tệp nguồn OWASP BenchmarkJava v1.2

Trong bộ kiểm toán độc lập (`v2/evaluation/audit_20261112/independent_audit.py`), chúng tôi đã nạp trực tiếp 56 tệp `.java` chuẩn của OWASP BenchmarkJava v1.2 tại commit `8b67a88d73b2594570fc21150705283de884620b`, dựng ngữ cảnh qua `extract_java_context()` và chạy cả `extract_evidence_signals()` (hàm mớm cho Arm C) lẫn `heuristic_analyze()` (hàm chấm cho Arm B):

| Tập dữ liệu | Tổng số cảnh báo | `extract_evidence_signals()["recommended_status"]` khớp Ground Truth OWASP | Kết quả Arm C (`PAIRED_EVALUATION.csv` / `DEVELOPMENT_EVALUATION.csv`) | Kết quả Arm B (`heuristic_analyze()`) | Số ca Arm B bị ép về `UNDETERMINED` dù `recommended_status` đã giải đúng |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`dev_set_16`** | `16` (`8 TP, 8 FP`) | **`16 / 16 (100.0%)`** (`8 SUPPORTED`, `8 REFUTED`, `0 UNDETERMINED`) | `16 / 16 (100.0%)` (Exp 3) | Không báo cáo riêng | `9 / 16` |
| **`heldout_set_40`** | `40` (`20 TP, 20 FP`) | **`40 / 40 (100.0%)`** (`20 SUPPORTED`, `20 REFUTED`, `0 UNDETERMINED`) | **`40 / 40 (100.0%)`** (`20 SUPPORTED`, `20 REFUTED`, `0 UNDETERMINED`) | `16 / 40` kết luận (`9 TP SUPPORTED`, `7 FP REFUTED`), **`24 / 40 UNDETERMINED`** | **`24 / 40 (100% số ca UNDETERMINED của Arm B)`** |

### Phát hiện trọng yếu 1: `recommended_status` đã đạt `40/40` trên `heldout_set_40` trước khi gọi Qwen
Trên toàn bộ 40 cảnh báo `heldout_set_40`, bộ giải tĩnh `extract_evidence_signals()` trong `heuristics.py` đã cho sẵn `recommended_status == "SUPPORTED"` cho đúng 20/20 ca `TRUE_POSITIVE` và `recommended_status == "REFUTED"` cho đúng 20/20 ca `FALSE_POSITIVE`, kèm theo `candidate_citations` hợp lệ khớp từng ký tự và `sha256`.

Do đó, kết quả `20/20 FP đề xuất loại đúng, 0/20 TP loại nhầm, 40/40 trích dẫn MATCHED` của `Arm C` **không thể được diễn giải là năng lực suy luận độc lập của riêng Qwen trên ngữ cảnh mở rộng**, vì Qwen đã nhận sẵn đáp án phân loại đúng 100% (`recommended_status`), lý do giải thích tiếng Việt (`recommendation_reason`) và trích dẫn mẫu (`candidate_citations`) ngay trong đầu vào JSON.

### Phát hiện trọng yếu 2: Bất đối xứng nhân tạo giữa `Arm B` (`heuristic`) và `Arm C` (`evidence+llm`)
Tại `v2/triage/heuristics.py:588-617`, hàm `heuristic_analyze()` (dùng cho `Arm B`) gọi chính `extract_evidence_signals(record)`, nhưng ngay sau đó dùng câu lệnh chặn tại dòng `596-603`:

```python
# v2/triage/heuristics.py:596-604
if not is_safe_source_or_sanitizer and (
    not signals.get("intra_procedural_decisive", True)
    or signals.get("uses_inner_helper")
    or signals.get("uses_thing_factory")
    or intra_mech.startswith("list_index_")
    or intra_mech.startswith("map_key_")
):
    return {"status": "UNDETERMINED", ...}
```

Hệ quả kỹ thuật:
- Mặc dù `extract_evidence_signals()` **đã giải xong** các luồng `Test.doSomething` (`callee_flow`), `ThingFactory`, `list_index_*` và `map_key_*` với độ khớp `24/24` trên 24 ca còn lại của `heldout_set_40`, `Arm B` lại chủ động hủy bỏ kết quả đó và trả về `"UNDETERMINED"` (không trích dẫn), trong khi **cũng chính kết quả đã giải đó lại được chuyển nguyên vẹn sang cho Qwen ở `Arm C`**.
- Điều này tạo ra hiệu ứng chênh lệch giả tạo (*confounded ablation*) khi so sánh `Arm B` (`7/20 FP`, `24 UNDETERMINED`) với `Arm C` (`20/20 FP`, `0 UNDETERMINED`), và khi so sánh `Arm D` (bị cắt cả ngữ cảnh phương thức lẫn `evidence_signals`) với `Arm C` (được cấp cả ngữ cảnh phương thức lẫn đáp án `recommended_status`).

### Phát hiện trọng yếu 3: Khi chạy ngoài các mẫu OWASP Benchmark (`Stage 5` — 20 cảnh báo dự án thực tế/demo), heuristic rơi về mặc định `"SUPPORTED"` và Qwen cũng trả `20/20 SUPPORTED`
Trên 20 cảnh báo Stage 5 (`WebGoat` + `java-sec-code` + `demo/UserDao.java`), không có `SeparateClassRequest.getTheValue` hay mẫu `switchTarget`/`num` của OWASP Benchmark, và mẫu sanitizer ở `UserDao.java:63-64` nằm sau dòng khởi tạo `File` (`ln_no > sink_line`, xem kiểm toán mục 4.D). Khi đó `extract_evidence_signals()` rơi về mặc định dòng `447` (`recommended_status = "SUPPORTED"`), và kết quả thực nghiệm Stage 5 ghi nhận Qwen trả **`20/20 SUPPORTED` (`0/4` FP được phát hiện, FPR giảm `0.0%`)**. Hiện tượng đối lập hoàn toàn giữa `heldout_set_40` (`20/20` FP phát hiện) và Stage 5 (`0/4` FP phát hiện) củng cố mạnh mẽ bằng chứng rằng phán quyết của Qwen đang bám chặt theo `recommended_status` của heuristic.

---

## 4. Giới hạn bằng chứng đối với 40 lượt suy luận LIVE trên máy chủ `ADMIN-PC`

Theo đúng quy tắc kiểm toán mục 4.C:
1. **Đã xác minh từ mã nguồn hiện hành (`PASS` về mặt truy vết mã)**: Tại commit `86636b9de22e59efcca2d3786434727c6ae082e4`, hàm `prompt(record)` trong `v2/triage/ollama.py:125-179` chắc chắn truyền `recommended_status`, `recommendation_reason` và `candidate_citations` vào prompt của chế độ `evidence+llm`, và **không** truyền tệp nhãn OWASP (`expectedresults-1.2.csv` / `labels_*.json`).
2. **Chưa xác minh trên raw evidence máy chủ (`NOT_VERIFIED`)**:
   - 10 tệp `assessments.jsonl` trên `ADMIN-PC` không nằm trên máy kiểm toán hiện tại.
   - Hơn nữa, ngay cả trong `OllamaClient.analyze()` (`v2/triage/ollama.py:216-260`), mã nguồn chỉ lưu băm `request_payload_sha256` và `raw_response` của Ollama chứ **không lưu văn bản `messages` của prompt gửi đi** vào `assessment`.
   - Do đó, kiểm toán viên **không khẳng định đã đọc nguyên văn từng prompt của 40 lượt LIVE**; chỉ kết luận ở mức mã nguồn đã khóa tại commit `86636b9de22e59efcca2d3786434727c6ae082e4` và yêu cầu JavisOS đối chiếu `request_payload_sha256` cùng `PROMPT_VERSION` từ `assessments.jsonl` trên `ADMIN-PC`.

---

## 5. Đề xuất phương án thí nghiệm đối chứng (Blind Ablation) cho giai đoạn tiếp theo

> **Lưu ý tuân thủ phạm vi**: Không chạy thêm 40 lượt suy luận Qwen trong giai đoạn kiểm toán này và không sửa mã thực nghiệm gốc trên nhánh `v2/post-report-cwe22-cwe89-20261112`.

Để tách bạch minh bạch đóng góp của **(a) mở rộng ngữ cảnh mã nguồn Java**, **(b) bộ giải tĩnh heuristic**, và **(c) suy luận thực chất của Qwen** ở giai đoạn tiếp theo, cần bổ sung hai cấu hình đối chứng sạch (*clean ablations*):

1. **Cấu hình `Arm B-Full` (Heuristic không bị chặn nhân tạo)**:
   - Cho phép `heuristic_analyze()` xuất trực tiếp kết luận từ `_analyze_method_block` + `callee_flow` mà không ép `UNDETERMINED` tại dòng `596-603`, đồng thời sửa các giả định không tổng quát (`ThingFactory`, `SeparateClassRequest`, `.startsWith(` bất kỳ). Điều này đo trung thực trần của phân tích tĩnh nội tệp không dùng LLM.
2. **Cấu hình `Arm C-Blind` (`context+llm` không mớm đáp án — Blind Context Prompt)**:
   - Giữ nguyên toàn bộ phần mở rộng ngữ cảnh hợp lệ cho Qwen: `snippets` toàn phương thức bao quanh + `same_file_callees`, `trace_steps`, và các vị trí khách quan (`source_line`, `sink_line`, `enclosing_method`).
   - **Loại bỏ hoàn toàn** khỏi payload gửi Qwen các trường định hướng đáp án và trích dẫn dựng sẵn:
     - `recommended_status`
     - `recommendation_reason`
     - `candidate_citations`
     - `intra_method_flow.outcome` / `intra_method_flow.reason`
     - `callee_method_flow.outcome` / `callee_method_flow.reason`
   - Bỏ câu lệnh `copied directly from evidence_signals.candidate_citations` khỏi `system` prompt; yêu cầu Qwen tự chọn dòng từ danh sách `[line_no]: code` trong `snippets` và để `validate_answer()` kiểm chứng độc lập.
   - Lưu đầy đủ `prompt_messages` (hoặc tệp `prompts.jsonl` riêng ngoài repo kèm SHA-256) để kiểm toán độc lập có thể tái tạo 100% payload gửi vào Ollama.
