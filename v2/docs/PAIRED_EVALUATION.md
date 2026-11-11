# Đánh Giá Bắt Cặp (Paired Evaluation) Trên Tập Held-Out Đóng Băng (`n = 40`) — CWE-22 & CWE-89

## 1. Thông tin Provenance & Khóa Dữ Liệu (STRICT_LOCK)

- **Tập dữ liệu đánh giá:** `heldout_set_40` (`n = 40` cảnh báo OpenGrep độc lập: `20` CWE-22 Path Traversal [10 TP, 10 FP] và `20` CWE-89 SQL Injection [10 TP, 10 FP]).
- **Trạng thái khóa:** Đã khóa trước khi chạy thực nghiệm Stage 4 (`validate_pilot_lock.py --mode STRICT_LOCK` đạt `exit_code = 0`, `valid_lock_candidate = true`, `m4_acceptance_ready = true`).
- **Tách biệt tập dữ liệu:** Hoàn toàn độc lập (`0` trùng lặp file/alert) với tập `dev_set_16` (`n = 16`) dùng ở Stage 2–3.
- **Mã băm (Hashes) xác thực:**
  - `scan_sha256` (`opengrep.json`): `67c3b04903e75f4bd7294cb17452d0dcb2b6d56244330cec485c4422efabfa8b`
  - `manifest_sha256` (`scan-manifest.json`): `3f5488d9a8de308b33111b5b5b88fd2bf6342ff3a18d8b9458b6936725b64fab`
  - `combined_lock_sha256` (`heldout_strict_lock_manifest.json`): `4fb556371eb9eb520aec6df96e4a151685df261025b2893eb7bae51c435bca09`
- **Kiểm tra hợp đồng Runtime LIVE (`verify_repro_contract.py live` & `v2.triage.live_check`):**
  - `status = PASS`, `provenance_classification = LIVE_MANIFEST_VERIFIED`, `source_capture_verified = true`, `live_protocol_status = OLLAMA_REPORTED_UNATTESTED` (`40/40` phản hồi HTTP 200 từ `qwen3.5:9b-q4_K_M` qua `127.0.0.1:11434`).

---

## 2. Bảng Tổng Hợp Kết Quả 4 Nhánh (Arm A, Arm B, Arm C, Arm D) Trên Tập `heldout_set_40` (`n = 40`)

| Chỉ số thực nghiệm (kèm `tử_số/mẫu_số`) | Arm A: OpenGrep Standalone | Arm B: OpenGrep + Heuristic (`--mode heuristic`) | Arm C: Full Pipeline (`--mode evidence+llm`, Qwen3.5-9B) | Arm D: Ablation (`--mode llm`, không ngữ cảnh mở rộng & không tín hiệu tĩnh) |
|---|---|---|---|---|
| **Tổng số cảnh báo (`N`)** | `40/40 (100.0%)` | `40/40 (100.0%)` | `40/40 (100.0%)` | `40/40 (100.0%)` |
| **TP giữ lại ở Nhóm 1 (`SUPPORTED` / `KEEP_TP`)** | `20/20 (100.0%)` | `9/20 (45.0%)` | **`20/20 (100.0%)`** | `17/20 (85.0%)` |
| **TP giữ lại tổng cộng (`KEEP_TP + REVIEW`)** | `20/20 (100.0%)` | `20/20 (100.0%)` | **`20/20 (100.0%)`** | `20/20 (100.0%)` |
| **FP đề xuất loại đúng ở Nhóm 2 (`REFUTED` / `PROPOSED_FP`)** | `0/20 (0.0%)` | `7/20 (35.0%)` | **`20/20 (100.0%)`** | `0/20 (0.0%)` |
| **TP bị đề xuất loại nhầm (`erroneously_proposed_fp_on_tp`)** | **`0/20 (0.0%)`** | **`0/20 (0.0%)`** | **`0/20 (0.0%)`** | **`0/20 (0.0%)`** |
| **FP bị xếp nhầm vào Nhóm 1 (`SUPPORTED` trên FP)** | `20/20 (100.0%)` | `0/20 (0.0%)` | **`0/20 (0.0%)`** | `14/20 (70.0%)` |
| **Tỷ lệ Nhóm 3 (`UNDETERMINED` / `REVIEW`)** | `0/40 (0.0%)` | `24/40 (60.0%)` | **`0/40 (0.0%)`** | `9/40 (22.5%)` |
| **Tỷ lệ Citation khớp mã nguồn (`citation_check == MATCHED`)** | `N/A` | `16/40 (40.0%)` | **`40/40 (100.0%)`** | `31/40 (77.5%)` |
| **Tỷ lệ phản hồi JSON hợp lệ (`triage_coverage`)** | `N/A` | `40/40 (100.0%)` | **`40/40 (100.0%)`** | `40/40 (100.0%)` |
| **Tỷ lệ tự động đóng cảnh báo không qua xác nhận người dùng** | `0/40 (0.0%)` | `0/40 (0.0%)` | **`0/40 (0.0%)`** | `0/40 (0.0%)` |
| **Độ trễ trung bình (`mean_latency_ms`)** | `0.0 ms` | `< 15.0 ms` (`0.58s / 40`) | `10,525.0 ms` (`10.53s`) | `7,526.6 ms` (`7.53s`) |
| **Độ trễ trung vị (`p50_latency_ms`) / `p95_latency_ms`** | `0.0 / 0.0 ms` | `< 15.0 / < 15.0 ms` | `10,961.0 / 12,687.0 ms` | `6,359.0 / 12,109.0 ms` |

---

## 3. Đánh Giá Theo 3 Chính Sách Vận Hành (Operational Policies)

| Chính sách (Policy) | Chỉ số | Arm A (Baseline) | Arm B (Heuristic) | Arm C (Full Pipeline) | Arm D (LLM Ablation) |
|---|---|---|---|---|---|
| **Policy 1: `baseline`** (Giữ tất cả cảnh báo OpenGrep) | Precision / TP Recall | `20/40 (50.0%)` / `20/20 (100.0%)` | `20/40 (50.0%)` / `20/20 (100.0%)` | `20/40 (50.0%)` / `20/20 (100.0%)` | `20/40 (50.0%)` / `20/20 (100.0%)` |
| **Policy 2: `drop_fp`** (Loại Nhóm 2 `PROPOSED_FP` sau khi người dùng xác nhận; giữ Nhóm 1 + Nhóm 3) | Precision / TP Recall | `20/40 (50.0%)` / `20/20 (100.0%)` | `20/33 (60.6%)` / `20/20 (100.0%)` | **`20/20 (100.0%)`** / **`20/20 (100.0%)`** | `20/40 (50.0%)` / `20/20 (100.0%)` |
| **Policy 3: `keep_tp_only`** (Chỉ lấy Nhóm 1 `KEEP_TP` ưu tiên xử lý trước) | Precision / TP Recall | `20/40 (50.0%)` / `20/20 (100.0%)` | `9/9 (100.0%)` / `9/20 (45.0%)` | **`20/20 (100.0%)`** / **`20/20 (100.0%)`** | `17/31 (54.8%)` / `17/20 (85.0%)` |

---

## 4. Phân Tích Kết Quả Theo Từng Nhóm Lỗ Hổng (`CWE-22` vs `CWE-89`)

### 4.1. Nhóm `CWE-22` (Path Traversal, `n = 20`: `10 TP`, `10 FP`)
- **Arm A (OpenGrep):** Giữ `20/20`, Precision = `10/20 (50.0%)`, không lọc được `0/10` FP.
- **Arm B (`--mode heuristic`):** Xác nhận đúng `4/10 (40.0%)` TP (nhánh trực tiếp không qua luồng dữ liệu phức tạp) và đề xuất loại đúng `5/10 (50.0%)` FP (nhánh hằng số `SeparateClassRequest.getTheValue`, `switchTarget`, và phép toán số học). Còn `11/20 (55.0%)` cảnh báo (gồm các mẫu qua `List.remove(0)`, `HashMap` hoặc helper `Test.doSomething`) phải chuyển sang `UNDETERMINED`.
- **Arm D (`--mode llm` ablation):** Khi không có ngữ cảnh phương thức mở rộng (`java_context.py`) và không có `heuristic_signals`, mô hình Qwen3.5-9B giữ được `7/10 (70.0%)` TP nhưng không phát hiện được `0/10 (0.0%)` FP (`4/10` FP bị phán nhầm là `SUPPORTED`, `6/10` FP rơi vào `UNDETERMINED`).
- **Arm C (`--mode evidence+llm`):** Đạt `10/10 (100.0%)` TP `SUPPORTED`, `10/10 (100.0%)` FP `REFUTED`, `0/10 (0.0%)` TP bị đề xuất loại nhầm, `20/20 (100.0%)` citation khớp mã nguồn, độ trễ trung bình `10,845.4 ms`.

### 4.2. Nhóm `CWE-89` (SQL Injection, `n = 20`: `10 TP`, `10 FP`)
- **Arm A (OpenGrep):** Giữ `20/20`, Precision = `10/20 (50.0%)`, không lọc được `0/10` FP.
- **Arm B (`--mode heuristic`):** Xác nhận đúng `5/10 (50.0%)` TP và đề xuất loại đúng `2/10 (20.0%)` FP, chuyển `13/20 (65.0%)` sang `UNDETERMINED` vì bộ quy tắc tĩnh không tự giải được các luồng qua phương thức nội bộ `new Test().doSomething(request, param)` khi biến đổi nằm bên trong lớp phụ trợ.
- **Arm D (`--mode llm` ablation):** Giữ được `10/10 (100.0%)` TP nhưng phán nhầm cả `10/10 (100.0%)` FP thành `SUPPORTED` (`0/10` FP `REFUTED`), bởi vì nếu chỉ nhìn thấy dòng nguồn `request.getCookies()` / `getTheParameter()` và dòng đích `connection.prepareStatement(sql)` mà thiếu thân hàm `Test.doSomething(...)`, mô hình lầm tưởng dữ liệu bẩn đi thẳng tới câu lệnh SQL.
- **Arm C (`--mode evidence+llm`):** Nhờ mở rộng ngữ cảnh bao trùm cả phương thức bao ngoài lẫn hàm phụ trợ `Test.doSomething` trong cùng tệp và bổ sung tín hiệu `heuristic_signals`, Arm C đạt `10/10 (100.0%)` TP `SUPPORTED`, `10/10 (100.0%)` FP `REFUTED`, `0/10 (0.0%)` TP bị đề xuất loại nhầm, `20/20 (100.0%)` citation khớp mã nguồn, độ trễ trung bình `10,204.6 ms`.
