# LABEL VALIDATION REPORT — Báo Cáo Kiểm Định Nhãn & Khóa STRICT_LOCK (Stage 1)

## 1. Kết Quả Kiểm Định Tự Động (`validate_pilot_lock.py`)

### 1.1. Kiểm định Tập Held-Out (`n = 40`) ở chế độ `STRICT_LOCK`
- **Lệnh thực thi:**
  ```powershell
  python v2/evaluation/validate_pilot_lock.py --mode STRICT_LOCK --opengrep v2/evaluation/post_report/heldout_alerts.json --labels v2/evaluation/post_report/labels_heldout.json --source-root "C:\Users\Admin\ntk-thesis-v2\evidence\post_report_cwe22_cwe89_20261112\sources\heldout_set_40" --write-lock v2/evaluation/post_report/heldout_strict_lock_manifest.json
  ```
- **Mã thoát (`exit_code`):** `0`
- **Kết quả chi tiết:**
  - `lock_mode`: `STRICT_LOCK`
  - `valid_lock_candidate`: `true`
  - `m4_acceptance_ready`: `true`
  - `total_unique_alerts`: `40` (nằm trong khoảng bắt buộc `[30, 60]`)
  - `total_unique_labels`: `40` (khớp 1-đối-1 100%)
  - `priority_cwe_alerts`: `40` (`20 CWE-22` + `20 CWE-89`)
  - `priority_cwe_share`: `1.0` (`100.0% >= 70.0%`)
  - `errors`: `[]` (`0` lỗi)
  - `warnings`: `[]` (`0` cảnh báo)
  - `combined_lock_sha256`: `4fb556371eb9eb520aec6df96e4a151685df261025b2893eb7bae51c435bca09`

### 1.2. Kiểm định Tập Development (`n = 16`)
- **Lệnh thực thi:**
  ```powershell
  python v2/evaluation/validate_pilot_lock.py --mode SMOKE --opengrep v2/evaluation/post_report/dev_alerts.json --labels v2/evaluation/post_report/labels_development.json --source-root "C:\Users\Admin\ntk-thesis-v2\evidence\post_report_cwe22_cwe89_20261112\sources\dev_set_16"
  ```
- **Mã thoát (`exit_code`):** `0`
- **Kết quả chi tiết:**
  - `total_unique_alerts`: `16` (`8 CWE-22` + `8 CWE-89`)
  - `total_unique_labels`: `16` (khớp 1-đối-1 100%)
  - `priority_cwe_share`: `1.0` (`100.0%`)
  - `errors`: `[]` (`0` lỗi)

## 2. Kiểm Định Biên Bản Chụp Quét (`ScanCapture` & `verify_receipt`)

| Tập dữ liệu | Số tệp `.java` | Số cảnh báo | `exit_capture_verified` | `source_capture_verified` | `recorded_engine_exit` | `issues` |
|---|---:|---:|---|---|---:|---|
| `dev_set_16` | 16 | 16 | `True` | `True` | `0` | `[]` |
| `heldout_set_40` | 40 | 40 | `True` | `True` | `0` | `[]` |

## 3. Phân Bố Cơ Chế Kỹ Thuật Trên 56 Cảnh Báo

| Nhóm CWE | Nhãn Chuẩn | Tập Dev (`n=16`) | Tập Held-Out (`n=40`) | Tổng (`n=56`) | Các cơ chế đại diện trong mã nguồn |
|---|---|---:|---:|---:|---|
| `CWE-22` (Path Traversal) | `TRUE_POSITIVE` | 4 | 10 | 14 | Luồng trực tiếp `doPost`, luồng qua hàm nội bộ `doSomething`, nhánh `switch` bẩn, phần tử `List` bẩn, khóa `HashMap` bẩn, `ThingInterface` |
| `CWE-22` (Path Traversal) | `FALSE_POSITIVE` | 4 | 10 | 14 | Nhánh `switch` hằng (`guess.charAt(1) == 'B'`), phần tử `List` an toàn sau `remove(0)`, khóa `HashMap` hằng, toán tử 3 ngôi số học hằng, `ThingInterface` |
| `CWE-89` (SQL Injection) | `TRUE_POSITIVE` | 4 | 10 | 14 | Nối chuỗi vào `executeQuery`/`executeUpdate`/`batchUpdate`, nối chuỗi trước `prepareStatement(sql)`, luồng qua `doSomething` |
| `CWE-89` (SQL Injection) | `FALSE_POSITIVE` | 4 | 10 | 14 | Nhánh `switch` hằng (`guess.charAt(1) == 'B'`), phần tử `List` an toàn sau `remove(0)` (cả trực tiếp và qua `doSomething`) |
