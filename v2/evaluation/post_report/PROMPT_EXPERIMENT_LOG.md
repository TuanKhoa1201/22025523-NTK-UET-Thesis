# NHẬT KÝ THỰC NGHIỆM PROMPT & SO SÁNH CÁC NHÁNH TRÊN TẬP DEVELOPMENT (`PROMPT_EXPERIMENT_LOG`)

- **Giai đoạn:** Stage 3 — Tinh chỉnh Heuristic & Prompt cho `CWE-22` / `CWE-89` trên tập Development (`dev_set_16`, `n = 16`)
- **Nhánh thực thi:** `v2/post-report-cwe22-cwe89-20261112`
- **Mô hình cục bộ:** `qwen3.5:9b-q4_K_M` qua Ollama loopback (`http://127.0.0.1:11434`)
- **Tập dữ liệu tinh chỉnh:** `dev_set_16` (`n = 16`: `8 CWE-22` [`4 TP, 4 FP`] + `8 CWE-89` [`4 TP, 4 FP`]), hoàn toàn tách biệt với `heldout_set_40` (`n = 40`).

---

## 1. Bảng so sánh thực nghiệm các phiên bản Prompt & chế độ chạy trên `dev_set_16` (`n = 16`)

| Thử nghiệm / Phiên bản | Chế độ (`--mode`) | `TP -> SUPPORTED` (`n=8`) | `TP -> REFUTED` (Loại nhầm TP) | `TP -> UNDETERMINED` | `FP -> REFUTED` (`PROPOSED_FP`, `n=8`) | `FP -> SUPPORTED` (Bỏ lọt FP) | `FP -> UNDETERMINED` | `citation_check == MATCHED` | Thời gian chạy |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **Exp 1: Baseline `v1.0`** (Trước nâng cấp Stage 2/3) | `v1.0` | `4/8 (50.0%)` | `0/8 (0.0%)` | `4/8 (50.0%)` | `0/8 (0.0%)` | `2/8 (25.0%)` | `6/8 (75.0%)` | `6/16 (37.5%)` | `135.39s` |
| **Exp 2: Arm B — Heuristic Only (`v2.1`)** | `heuristic` | `4/8 (50.0%)` | `0/8 (0.0%)` | `4/8 (50.0%)` | `3/8 (37.5%)` | `0/8 (0.0%)` | `5/8 (62.5%)` | `7/16 (43.8%)` | `0.27s` |
| **Exp 3: Arm D — Ablation (`v2.0`, Qwen ít ngữ cảnh)** | `llm` | `7/8 (87.5%)` | `0/8 (0.0%)` | `1/8 (12.5%)` | `0/8 (0.0%)` | `8/8 (100.0%)` | `0/8 (0.0%)` | `15/16 (93.8%)` | `142.72s` |
| **Exp 4: Arm C — Evidence + Qwen (`v2.0`)** | `evidence+llm` | `7/8 (87.5%)` | `0/8 (0.0%)` | `1/8 (12.5%)` | `8/8 (100.0%)` | `0/8 (0.0%)` | `0/8 (0.0%)` | `15/16 (93.8%)` | `164.53s` |
| **Exp 5: Arm C — Evidence + Qwen (`v2.1` — Frozen)** | `evidence+llm` | `8/8 (100.0%)` | `0/8 (0.0%)` | `0/8 (0.0%)` | `8/8 (100.0%)` | `0/8 (0.0%)` | `0/8 (0.0%)` | `16/16 (100.0%)` | `~155s` |

---

## 2. Phân tích chi tiết từng bước cải tiến trên `dev_set_16`

### 2.1. Từ `v1.0-baseline` (Exp 1) sang `v2.0-cwe22-cwe89-grounded` (Exp 4)
1. **Khắc phục `CliCall` và mở rộng ngữ cảnh phương thức + callee (`v2/triage/java_context.py`, `v2/triage/evidence.py`):**
   - Trong Exp 1 (`v1.0`), 6/8 cảnh báo `CWE-22` bị từ chối ngay từ bước thu thập bằng chứng vì `CliCall`. Sau khi nâng cấp `visit()`, cả 16/16 cảnh báo đều có `issues = []`.
2. **Vai trò quyết định của ngữ cảnh mở rộng và `evidence_signals` (So sánh Exp 3 `llm` vs Exp 4 `evidence+llm`):**
   - Ở **Exp 3 (`--mode llm`, Ablation — Qwen ít ngữ cảnh)**, dù đã sửa `CliCall` và quy tắc trích dẫn đơn dòng (`cites_matched = 15/16`), khi chỉ cung cấp cửa sổ ngắn `[sl - 3, el + 3]` mà không có thân phương thức mở rộng và `evidence_signals`, Qwen3.5-9B kết luận `SUPPORTED` cho **cả 8/8 cảnh báo False Positive** (`0/8` FP được phát hiện!).
   - Ở **Exp 4 (`--mode evidence+llm`)**, nhờ cung cấp toàn bộ thân phương thức `doPost` + `Test.doSomething` và tín hiệu dẫn xuất `evidence_signals`, Qwen3.5-9B phát hiện chính xác **8/8 (`100.0%`) cảnh báo False Positive** (`REFUTED`), đồng thời không loại nhầm bất kỳ True Positive nào (`TP -> REFUTED = 0/8`).

### 2.2. Tinh chỉnh từ `v2.0` (Exp 4) sang `v2.1` (Exp 5 — Phiên bản khóa cứng)
- Trong Exp 4 (`v2.0`), chỉ còn duy nhất 1 cảnh báo (`BenchmarkTest00216.java`, `CWE-22`, `TRUE_POSITIVE`) rơi vào `UNDETERMINED` do lỗi `citation text disagrees with source line(s)`.
- **Nguyên nhân gốc rễ:** Câu lệnh sink của `BenchmarkTest00216.java` trải trên 2 dòng (dòng 68: `java.io.File fileTarget =` và dòng 69: `new java.io.File(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR, bar);`). Trong `v2.0`, trường `"matched"` của snippet chứa chuỗi khớp của OpenGrep không có dấu `;` ở cuối dòng 69, khiến Qwen trích dẫn dòng 69 bị thiếu dấu `;`.
- **Giải pháp trong `v2.1`:**
  1. Loại bỏ trường `"matched"` (biểu thức con không trọn dòng) khỏi bản sao snippet trong prompt gửi cho LLM, để mô hình chỉ nhìn thấy các dòng mã nguồn nguyên vẹn trong `snippets[i].lines` và `candidate_citations`.
  2. Bổ sung cả `sink_line` và `sink_end_line` vào `candidate_citations` khi câu lệnh sink trải trên nhiều dòng.
- **Quyết định khóa cứng:** Khóa cứng Prompt `v2.1-cwe22-cwe89-grounded` và Heuristic `v2.1` trước khi tiến hành Stage 4 trên tập `heldout_set_40` (`n = 40`).
