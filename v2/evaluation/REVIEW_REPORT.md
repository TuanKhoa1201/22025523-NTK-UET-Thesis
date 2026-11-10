# NTK Thesis V2 — Báo cáo Kiểm tra Độc lập M0 & Chuẩn bị Đánh giá M4/M5

**Vai trò thực hiện**: Kỹ sư kiểm thử độc lập & phụ trách phương pháp thực nghiệm (Antigravity)
**Thời điểm cập nhật**: `2026-11-11T02:50:00+07:00`
**Phạm vi tác động**: Chỉ làm việc trong [`v2/evaluation/`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/evaluation); không chỉnh sửa mã nguồn đồ án cũ (`backend/`, `apps/`, `research/`, `evaluation/`) hay các thư mục của Codex (`v2/baseline/`, `v2/triage/`).

---

## 1. Kết quả Giai đoạn A — Kiểm tra M0 (Environment & Workspace Verification)

| Hạng mục kiểm tra | Kết quả | Chi tiết bằng chứng |
|---|---|---|
| **Thư mục Workspace** | **PASS** | `c:\Users\HP\OneDrive\Documents\NTK-Thesis-V2\antigravity` |
| **Cấu hình Git Worktree & Nhánh `v2/antigravity-review`** | **PASS (kèm lưu ý Sandbox)** | Tệp [`.git`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/.git) trỏ tới `gitdir: C:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/integration/.git/worktrees/antigravity`, khớp với cấu hình nhánh `v2/antigravity-review` trong [`v2/scripts/setup_laptop_worktrees.ps1`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/scripts/setup_laptop_worktrees.ps1#L33). **Trở ngại quyền Sandbox**: Thư mục `.git` chung nằm tại `../integration/.git` bên ngoài biên sandbox của workspace `antigravity`, nên lệnh `git` trong sandbox không đọc được metadata ngoài thư mục. Tuân thủ nguyên tắc không tự vượt quyền/không treo chờ duyệt ngoài sandbox, toàn bộ tệp được lưu sạch trong `v2/evaluation/` để commit an toàn từ terminal máy chủ. |
| **Khả năng đọc [`AGENTS.md`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/AGENTS.md) & [`v2/docs/TASK_BOARD.md`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/docs/TASK_BOARD.md)** | **PASS** | Đã đọc và đối chiếu đầy đủ [`AGENTS.md`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/AGENTS.md), [`v2/docs/TASK_BOARD.md`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/docs/TASK_BOARD.md), [`v2/docs/M0_CHECKLIST.md`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/docs/M0_CHECKLIST.md), [`v2/docs/MODEL_POLICY.md`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/docs/MODEL_POLICY.md) và quy tắc bảo mật [`.agents/rules/ntk-security-review.md`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/.agents/rules/ntk-security-review.md). |
| **Khả năng chạy lệnh kiểm tra đơn giản** | **PASS** | `python --version` $\to$ `Python 3.13.3` (thực thi trực tiếp trong sandbox). |

---

## 2. Kết quả Giai đoạn B — Danh mục Tệp Đã Tạo cho Đánh giá M3/M4/M5

| Tệp đã tạo | Mô tả chức năng |
|---|---|
| [`v2/evaluation/PILOT_PROTOCOL.md`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/evaluation/PILOT_PROTOCOL.md) | Giao thức thực nghiệm M4/M5 so sánh **OpenGrep đơn lẻ** vs. **OpenGrep + Local Qwen**, phân tách đánh giá triage từng cảnh báo với đánh giá phát hiện toàn bộ benchmark, ưu tiên `CWE-22`/`CWE-89` và báo cáo riêng `CWE-78`/`CWE-79`, quy định schema nhãn, quy tắc ghép nối/chống lệch CWE, công thức tính chỉ số, mẫu bảng kết quả và mẫu case study trống (`PENDING REAL RUN`). |
| [`v2/evaluation/score_pilot.py`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/evaluation/score_pilot.py) | Script Python (standard library) chấm điểm và kiểm tra toàn vẹn dữ liệu: tính số cảnh báo giả đề xuất loại đúng (`proposed_fp_on_true_fp / labeled_fp`), số cảnh báo thật bị đề xuất loại nhầm (`erroneously_proposed_fp_on_tp / labeled_tp` luôn kèm tử số & mẫu số), số ca cần xem thêm (`REVIEW`), độ phủ triage, độ trễ xử lý (`mean`, `p50`, `p95`, `max`, `total`), đồng thời phát hiện thiếu nhãn, sai CWE, trùng ID, lệch `source_sha256`, thiếu trích dẫn dòng, vi phạm tự động ẩn cảnh báo và lỗi JSON. |
| [`v2/evaluation/validate_pilot_lock.py`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/evaluation/validate_pilot_lock.py) | Công cụ khóa cứng tập dữ liệu M4 (`create_lock_manifest`, `verify_lock_manifest`, `validate_pilot_dataset`) phát hiện chỉnh sửa hậu kỳ trên tập nhãn/cảnh báo, và công cụ kiểm chứng M3 (`verify_source_grounding`) đối chiếu `source_sha256` cùng các dòng trích dẫn `cited_lines` trực tiếp trên tệp mã nguồn `.java` (bắt lỗi trích dẫn vào dòng trống hoặc dòng comment). |
| [`v2/evaluation/tests/test_score_pilot.py`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/evaluation/tests/test_score_pilot.py) | 8 unit test kiểm thử toàn diện `score_pilot.py` trên dữ liệu giả lập `TEST_FIXTURE_ONLY`. |
| [`v2/evaluation/tests/test_validate_pilot_lock.py`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/evaluation/tests/test_validate_pilot_lock.py) | 2 unit test kiểm thử khóa manifest SHA-256 (M4) và kiểm chứng dòng mã nguồn Java thực tế (M3) trên dữ liệu `TEST_FIXTURE_ONLY`. |
| [`v2/evaluation/fixtures/opengrep_alerts.fixture.json`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/evaluation/fixtures/opengrep_alerts.fixture.json) | Dữ liệu cảnh báo giả lập (`TEST_FIXTURE_ONLY`) gồm 6 cảnh báo mẫu thuộc `CWE-22`, `CWE-89`, `CWE-78`, `CWE-79`. |
| [`v2/evaluation/fixtures/ground_truth_labels.fixture.json`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/evaluation/fixtures/ground_truth_labels.fixture.json) | Dữ liệu nhãn giả lập (`TEST_FIXTURE_ONLY`) khớp với 6 cảnh báo mẫu. |
| [`v2/evaluation/fixtures/qwen_triage_outputs.fixture.jsonl`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/evaluation/fixtures/qwen_triage_outputs.fixture.jsonl) | Dữ liệu đầu ra triage giả lập (`TEST_FIXTURE_ONLY`) định dạng JSONL. |
| [`v2/evaluation/logs/unittest_and_fixture_smoke.log`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/evaluation/logs/unittest_and_fixture_smoke.log) | Tệp log lưu toàn bộ đầu ra kiểm thử unit test và chạy thử CLI (nằm trong thư mục `logs/` được `.gitignore` giữ cục bộ). |

---

## 3. Lệnh Kiểm thử & Kết quả Thực thi (PASS/FAIL)

### Lệnh 1 — Chạy toàn bộ Unit Tests (10/10 tests)
```powershell
python -m unittest discover -s v2/evaluation/tests -p "test_*.py" -v
```
- **Kết quả**: **PASS** (`Ran 10 tests in 0.088s — OK`, exit code `0`).
  1. `test_cli_end_to_end_with_fixture_flag`: **PASS**
  2. `test_duplicate_ids_detection_and_deduplication`: **PASS**
  3. `test_malformed_json_and_corrupted_llm_outputs_fallback_to_review`: **PASS**
  4. `test_missing_labels_and_unlabeled_handling`: **PASS**
  5. `test_security_review_guards_sha256_ungrounded_fp_and_human_approval`: **PASS**
  6. `test_standard_priority_and_secondary_cwe_scoring`: **PASS**
  7. `test_wrong_cwe_join_detection`: **PASS**
  8. `test_zero_denominators_safe_division`: **PASS**
  9. `test_source_grounding_catches_comment_lines_and_sha_mismatch`: **PASS**
  10. `test_validate_fixture_files_and_lock_manifest_tamper_detection`: **PASS**

### Lệnh 2 — Chạy thử CLI Chấm điểm & Khóa Manifest trên `fixtures/`
```powershell
python v2/evaluation/score_pilot.py --opengrep v2/evaluation/fixtures/opengrep_alerts.fixture.json --labels v2/evaluation/fixtures/ground_truth_labels.fixture.json --triage v2/evaluation/fixtures/qwen_triage_outputs.fixture.jsonl --scan-time-ms 420.0 --fixture --output-json v2/evaluation/logs/fixture_smoke_report.json
python v2/evaluation/validate_pilot_lock.py --opengrep v2/evaluation/fixtures/opengrep_alerts.fixture.json --labels v2/evaluation/fixtures/ground_truth_labels.fixture.json --min-alerts 1 --max-alerts 10 --write-lock v2/evaluation/logs/fixture_lock_manifest.json
```
- **Kết quả**: **PASS** (exit code `0`, log đầy đủ lưu tại [`v2/evaluation/logs/unittest_and_fixture_smoke.log`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/evaluation/logs/unittest_and_fixture_smoke.log)).

---

## 4. Giả định Phương pháp, Dữ liệu Còn thiếu & Những gì Chưa được Kiểm chứng

### 4.1. Giả định Phương pháp
1. **Hỗ trợ đa định dạng đầu vào**: [`score_pilot.py`](file:///c:/Users/HP/OneDrive/Documents/NTK-Thesis-V2/antigravity/v2/evaluation/score_pilot.py) nhận trực tiếp cả cấu trúc JSON gốc của OpenGrep (`{"results": [...]}`) lẫn danh sách cảnh báo chuẩn hóa, cũng như đầu ra Qwen ở dạng JSON hoặc JSONL từng dòng.
2. **Cơ chế Fail-Safe 3 trạng thái**: Mọi lỗi cú pháp JSON, thiếu nhãn, lệch CWE, lệch `source_sha256`, hoặc đề xuất `FP` thiếu trích dẫn dòng hợp lệ đều tự động chuyển về `REVIEW`, đảm bảo không làm mất cảnh báo thật.
3. **Không tự động ẩn cảnh báo**: Mọi đề xuất `FP` từ mô hình đều mang trạng thái `PROPOSED_FP` chờ xác nhận của con người; nếu bản ghi có `auto_dismissed=True` sẽ bị đánh dấu vi phạm vào `human_approval_violations` và ép về `REVIEW`.

### 4.2. Dữ liệu Thực tế Còn thiếu & Chưa được Kiểm chứng (`PENDING REAL RUN`)
- **Chưa có kết quả quét OpenGrep thật (M1)**: Chờ nhánh `v2/codex-core` cung cấp bản chạy thật của `simple_semgrepAI` với OpenGrep.
- **Chưa có kết quả suy luận Local Qwen thật (M2/M3)**: Chờ JavisOS & Codex chạy Ollama (`qwen3.5:9b-q4_K_M` hoặc `4B`) trên máy chủ và xuất log/JSONL thật.
- **Chưa có bộ nhãn khóa cứng 30–60 cảnh báo thật (M4)**: Các tệp trong `v2/evaluation/fixtures/` chỉ là `TEST_FIXTURE_ONLY` để kiểm thử phần mềm chấm điểm, hoàn toàn **không phải** kết quả benchmark thật.
- **Commit Git**: Chưa tạo commit từ bên trong sandbox do `.git` worktree trỏ ra `../integration/.git/worktrees/antigravity` ngoài phạm vi sandbox. Khi chạy trên terminal ngoài sandbox, thực hiện:
  ```powershell
  git -C C:\Users\HP\OneDrive\Documents\NTK-Thesis-V2\antigravity status -sb
  git -C C:\Users\HP\OneDrive\Documents\NTK-Thesis-V2\antigravity add v2/evaluation/
  git -C C:\Users\HP\OneDrive\Documents\NTK-Thesis-V2\antigravity commit -m "v2(eval): add M4/M5 pilot protocol, scoring/lock scripts, fixtures, and unit tests"
  ```
