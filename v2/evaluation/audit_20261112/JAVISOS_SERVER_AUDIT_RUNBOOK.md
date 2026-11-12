# HƯỚNG DẪN NGẮN CHO JAVISOS CHẠY KIỂM TOÁN TRÊN MÁY CHỦ `ADMIN-PC`

- **Đối tượng thực thi**: `JavisOS` trên máy chủ thực nghiệm `ADMIN-PC`
- **Mục tiêu**: Xác minh trực tiếp 10 tệp `assessments.jsonl`, các tệp raw `opengrep.json` / `scan-manifest.json`, cơ sở dữ liệu `review.sqlite` và nguồn gốc `ground_truth_verifier.py` mà không đưa raw evidence lớn hoặc đường dẫn nhạy cảm lên GitHub.
- **Nhánh kiểm toán cần checkout**: `kiem-toan/du-lieu-va-ket-qua-20261112`

---

## 1. Phạm vi đầu vào cần có trên `ADMIN-PC`

1. Bản checkout sạch của nhánh `kiem-toan/du-lieu-va-ket-qua-20261112` từ repository `22025523-NTK-UET-Thesis`.
2. Thư mục chứa **10 tệp `assessments.jsonl`** (gồm các lượt chạy `dev_set_16`, `heldout_set_40` cho Arm B / Arm C / Arm D và Stage 5) cùng các tệp `opengrep.json`, `scan-manifest.json` và `*.sqlite` đi kèm.
3. Bản clone OWASP BenchmarkJava v1.2 đúng tại commit `8b67a88d73b2594570fc21150705283de884620b` (chứa `expectedresults-1.2.csv` và thư mục `src/main/java/org/owasp/benchmark/testcode`).

---

## 2. Quy trình chạy bộ kiểm toán độc lập (PowerShell trên `ADMIN-PC`)

### Bước 1: Kiểm tra trạng thái Git và chạy unit test phản chứng
```powershell
git fetch origin
git checkout kiem-toan/du-lieu-va-ket-qua-20261112
git status -sb

python -B -m unittest discover -s v2/evaluation/audit_20261112 -p "test_*.py" -v
```
- **Kỳ vọng**: `Ran 16 tests ... OK` (`exit code = 0`).

### Bước 2: Chạy kiểm toán đầy đủ kèm cờ bắt buộc xác minh máy chủ (`--require-server-evidence`)
Thay `<SERVER_EVIDENCE_DIR>`, `<OWASP_ROOT>` và `<SAFE_RECEIPT_JSON>` bằng đường dẫn thực tế ngoài cây thư mục Git (ví dụ lưu biên nhận tạm ra thư mục riêng trước khi kiểm duyệt):

```powershell
python -B v2/evaluation/audit_20261112/independent_audit.py `
  --server-evidence-dir "<SERVER_EVIDENCE_DIR>" `
  --expectedresults-csv "<OWASP_ROOT>/expectedresults-1.2.csv" `
  --benchmark-java-root "<OWASP_ROOT>" `
  --require-server-evidence `
  --output-json "<SAFE_RECEIPT_JSON>"

Write-Host "EXIT_CODE=$LASTEXITCODE"
```

### Ý nghĩa mã thoát (`exit code`):
- `0`: Toàn bộ 56 nhãn boolean OWASP khớp, số liệu bảng CSV khớp, tìm thấy đủ `>= 10` tệp `assessments.jsonl` hợp lệ, mọi phán quyết `SUPPORTED`/`REFUTED` đều có trích dẫn khớp snapshot và `sha256`, mọi lượt Ollama đều là `ollama-http` hoàn tất (`done=True`, đúng `model` `qwen3.5:9b-q4_K_M`), và không có cảnh báo nào bị tự động đóng (`CONFIRMED_FALSE`) trong SQLite khi chưa có sự kiện người duyệt (`events_count == 0`).
- `1`: Phát hiện sai lệch nhãn boolean, sai ghép khóa `alert_id`/`scan_sha256`, hoặc lệch phép tính bảng CSV.
- `2`: Thiếu `< 10` tệp `assessments.jsonl` hoặc phát hiện lỗi trong raw evidence máy chủ (xem chi tiết tại mảng `server_raw_evidence_audit.errors` trong tệp JSON xuất ra).

---

## 3. Kiểm tra nguồn gốc `ground_truth_verifier.py` trên `ADMIN-PC`

Tệp `ground_truth_verifier.py` không tồn tại trên nhánh GitHub `v2/post-report-cwe22-cwe89-20261112`. JavisOS cần kiểm tra trên ổ đĩa `ADMIN-PC` và ghi vào biên nhận:

```powershell
Get-ChildItem -Path "<SERVER_WORKSPACE_ROOT>" -Recurse -Filter "*ground_truth_verifier*" -ErrorAction SilentlyContinue |
  ForEach-Object {
    [PSCustomObject]@{
      Name          = $_.Name
      LengthBytes   = $_.Length
      LastWriteTime = $_.LastWriteTimeUtc.ToString("o")
      Sha256        = (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLower()
    }
  } | ConvertTo-Json -Depth 4
```

Cần trả lời rõ 3 câu hỏi kỹ thuật trong biên nhận máy chủ:
1. Tệp `ground_truth_verifier.py` đọc trực tiếp `expectedresults-1.2.csv` hay sinh `rationale` tự động bằng mẫu chuỗi (nguyên nhân gây sai `rationale` ở `BenchmarkTest01746` và `BenchmarkTest00863`)?
2. Dấu thời gian tạo tệp `heldout_alerts.json` / `labels_heldout.json` so với dấu thời gian dòng đầu tiên trong `assessments.jsonl` của `heldout_set_40` có chứng minh được việc chốt tập `40` cảnh báo **trước** khi chạy suy luận Qwen hay không?
3. Các giá trị `request_payload_sha256` trong `assessments.jsonl` của `Arm C` có khớp với hàm `request_payload(record, "qwen3.5:9b-q4_K_M")` tại commit `86636b9de22e59efcca2d3786434727c6ae082e4` (tức có chứa `evidence_signals.recommended_status`) hay không?

---

## 4. Quy tắc an toàn khi bàn giao biên nhận về GitHub

1. **CHỈ bàn giao tệp JSON tóm tắt** (chứa số đếm hàng, `sha256`, `scan_shas`, `models`, `transports`, `warning_states`, `errors`) sau khi kiểm tra không còn đường dẫn cá nhân (`C:\Users\...`).
2. **TUYỆT ĐỐI KHÔNG commit**:
   - 10 tệp `assessments.jsonl` hoặc `*.ckpt.jsonl`
   - Tệp `review.sqlite` / `*.db`
   - Raw `opengrep.json` kích thước lớn hoặc mã nguồn OWASP BenchmarkJava / dự án thứ ba
   - Tài liệu PDF/ZIP hướng dẫn riêng của giảng viên
