# Phụ lục báo cáo tiến độ lần 1: simple_semgrepAI chạy OpenGrep

Ngày chốt hồ sơ: 11/11/2026. Phạm vi: CLI kế thừa đã vá, chạy trên laptop;
nghiệm thu máy chủ còn **PENDING**. Mã triển khai đã push tại
[`7bd442d0ccca08cb089dd01762237cb62fe88698`](https://github.com/TuanKhoa1201/22025523-NTK-UET-Thesis/commit/7bd442d0ccca08cb089dd01762237cb62fe88698),
nhánh `v2/advisor-m1-proof-20261111`. Phụ lục này bổ sung hồ sơ sau commit đó.

## A. Môi trường thực nghiệm

| Thành phần | Giá trị được ghi nhận trong lượt chạy laptop |
| --- | --- |
| Hệ điều hành | Windows, tiến trình native `win32`, máy `LAPTOP-PSMH40NJ`; capture không ghi edition/build Windows |
| Python và thư viện CLI | Python 3.12.3; Typer 0.17.5; Rich 15.0.0; PyYAML 6.0.3 |
| Engine | OpenGrep native Windows 1.20.0 |
| Công cụ kế thừa | simple_semgrepAI, phiên bản dự án 0.2.0, giấy phép MIT |
| Upstream commit | `2c79a58a16d11e9dea3723e30d2a7faffba7bdc9` |
| Git tree upstream | `c0ab3e20152ce5c3e6b80e1525288ad59c9aee93`, đủ 96 tệp được kiểm chứng |
| LLM | Không tham gia phép thử này; handoff chạy `--no-llm`, không có suy luận Qwen hay API LLM đám mây |

Nguồn số liệu là `proof.json`, `dependencies.stdout.txt`,
`prepared/preparation.json` và các receipt trong thư mục evidence **E**:
`C:\Users\HP\NTK-M1-Runtime\proof-20261111-224908-bf784076`.
Nguồn upstream được ghim tại [commit gốc](https://github.com/hardw00t/simple_semgrepAI/tree/2c79a58a16d11e9dea3723e30d2a7faffba7bdc9).
ZIP/PDF riêng của giảng viên và toàn bộ evidence runtime không đưa vào Git public.

## B. Tích hợp simple_semgrepAI với OpenGrep

| Nguồn đóng góp | Thành phần và phạm vi |
| --- | --- |
| Upstream nguyên bản | CLI Typer, scanner Semgrep, JSON/SARIF; validator có nhận định, giải thích, risk score và gợi ý sửa; provider Ollama, API review và RAG/web. Sự tồn tại của mã không chứng minh các chức năng đó đã chạy trong phép thử này. |
| Patch tham khảo của giảng viên | Sửa `pyproject.toml`, `semgrepai.yml`, `semgrepai/config.py`, `semgrepai/scanner.py`: OpenGrep cấu hình được, rules cục bộ, cờ trace/taint intrafile, đọc `extra.dataflow_trace` và xử lý dạng CliLoc/CliCall. |
| NTK bổ sung | Overlay giữ entrypoint và hàm scan kế thừa; thêm `--scan-only`, cô lập import RAG/validator/provider, truyền cấu hình scanner, ghi lệnh/exit code/raw output, manifest nguồn–rules–artifact, kiểm tra nguồn và handoff sang triage. |

`--scan-only` **do NTK bổ sung**, không phải tính năng upstream nguyên bản.
Nó cho phép kiểm chứng riêng đường CLI → scanner mà không khởi tạo RAG/LLM.
Đường thực thi ghi nhận là `semgrepai.__main__` → `semgrepai.cli.scan` → scanner
đã vá, không thay bằng CLI mới hoặc gọi trực tiếp scanner để nhận PASS.

Diff rút gọn của overlay NTK, sau patch giảng viên:

```diff
-from .rag import RAGStore
-from .validator import AIValidator
+from .scan_recording import recording, record_cli_origin
@@ scan(...)
+    scan_only: bool = typer.Option(False, "--scan-only", ...)
-    scanner = SemgrepScanner()
-    results = scanner.scan(target_path, rules_path)
+    with recording(target_path, rules_path, output_dir):
+        record_cli_origin(__file__, SemgrepScanner, "enter")
+        scanner = SemgrepScanner(config_path=str(config_path) if config_path else None)
+        results = scanner.scan(target_path, rules_path)
+        record_cli_origin(__file__, SemgrepScanner, "exit")
+    return  # trước nhánh RAG/validator kế thừa
```

Overlay thật trong `E/prepared/ntk-local-overlay.patch` đổi 6 tệp,
199 dòng thêm, 17 dòng xóa. Patch scanner-only `opengrep.patch` của NTK là sản phẩm
riêng; việc tái tạo patch đó không thay thế bằng chứng chạy CLI full checkout.

## C. Các lệnh tái lập

Chạy từ root checkout NTK của nhánh proof. Các lệnh dưới đây dành cho **lượt chạy
mới** trên máy đủ điều kiện; không cần quét lại laptop đã PASS. Đặt `$Advisor`
đúng thư mục chứa ZIP riêng; OpenGrep phải được cài riêng và có trong PATH.
Không đặt `PYTHONPATH` trỏ vào `v2/baseline/fork`. Giữ upstream gốc sạch.

```powershell
$Repo = (Get-Location).Path
$Work = 'C:\private\ntk-report1'
$Advisor = 'C:\private\advisor-sources'
$Proof = "$Work\proof-new-01" # phải chưa tồn tại
New-Item -ItemType Directory -Force $Work | Out-Null
git clone https://github.com/hardw00t/simple_semgrepAI.git "$Work\upstream"
if ($LASTEXITCODE -ne 0) { throw 'Clone failed' }
git -C "$Work\upstream" checkout --detach 2c79a58a16d11e9dea3723e30d2a7faffba7bdc9
if ($LASTEXITCODE -ne 0) { throw 'Checkout failed' }
py -3.12 -m venv "$Work\venv"
if ($LASTEXITCODE -ne 0) { throw 'Venv failed' }
$Py = "$Work\venv\Scripts\python.exe"
& $Py -m pip install typer==0.17.5 rich==15.0.0 PyYAML==6.0.3
if ($LASTEXITCODE -ne 0) { throw 'Dependencies failed' }
& $Py v2/baseline/verify_patch.py # kiểm tra patch scanner-only NTK riêng
if ($LASTEXITCODE -ne 0) { throw 'NTK patch verification failed' }
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
& $Py v2/baseline/prove_original_cli.py --upstream "$Work\upstream" `
  --advisor-dir $Advisor --output-dir $Proof --python $Py --timeout 180
if ($LASTEXITCODE -ne 0) { throw 'Inspect proof.json and command logs' }
& $Py v2/baseline/audit_original_cli.py $Proof
if ($LASTEXITCODE -ne 0) { throw 'Evidence audit failed' }
```

Runner kiểm tra commit/tree/96 tệp, tạo bản sao riêng, chạy
`git apply --check` rồi `git apply` patch giảng viên, sau đó áp overlay NTK.
Kết quả nằm trong `prepared/patch-results.json` và `preparation.json`.
Nó thực thi đúng lệnh sau với working directory `$Proof\prepared\source`
(minh họa lệnh con, **không chạy lần hai vào cùng capture**):

```powershell
& $Py -m semgrepai scan "$Repo\v2\baseline\fixtures\java" `
  --rules-path "$Repo\v2\baseline\rules\java.yml" `
  --config-path "$Proof\prepared\source\semgrepai.yml" `
  --output-dir "$Proof\capture" --scan-only
```

Runner tiếp tục nhập `capture/opengrep.json` cùng `scan-manifest.json` vào
`python -m v2.triage run ... --no-llm`, lưu `triage/input.opengrep.json` và
`triage/evidence.json`. Auditor kiểm tra hash, full rule ID, đường dẫn và tọa độ
JSON/SARIF; đối chiếu raw JSON, finding ID và trace sau handoff. Auditor chỉ đọc,
không chạy lại engine. Mã thoát 0 của triage không phải bằng chứng LLM đã suy luận.
Lệnh WSL/Linux tương đương nằm tại [báo cáo CLI, mục 5](ADVISOR_M1_ORIGINAL_CLI_PROOF.md#5-reproduction-and-javisos-handoff).

## D. Kết quả thực nghiệm laptop

| Phép kiểm chứng | Kết quả thực tế |
| --- | --- |
| Runner; kiểm toán độc lập do người dùng xác nhận | Exit 0; exit 0 |
| Patch giảng viên check/apply | Exit 0/0 |
| Dependencies, CLI help, CLI scan, triage | Exit 0/0/0/0; không timeout |
| OpenGrep version, JSON, SARIF | Exit 0/0/0 |
| Số findings | JSON **4**, SARIF **4**, triage **4**; raw JSON không đổi |
| Thu thập nguồn và artifact | 16 artifact khớp SHA-256, 2 tệp Java khớp hash nguồn |
| Kiểm toán chỉ đọc của Codex ở bước 11.2 | Exit 0; đối chiếu rule ID/vị trí và handoff; không quét lại |
| Unit test baseline ở bước 11.2 | 50 PASS, 1 SKIP, exit 0; SKIP lượt live tùy chọn, không thay thế evidence thật |

SHA-256 của `E/capture/opengrep.json`:
`fe8dcfe7279b3d4448d22418948673fc686f25f6be1c6e38165fa9821be8f8a2`.
Đầu vào là `fixtures/java/Vulnerable.java`, `Safe.java` và `rules/java.yml`
tương đối với `v2/baseline/`. Hai ví dụ từ trace thật trong `Vulnerable.java`:

| CWE | Source | Bước trung gian | Sink/finding |
| --- | --- | --- | --- |
| CWE-22 | Dòng 5, cột 24–49: `req.getParameter("input")` | `input` dòng 5, cột 16–21; `forwarded` dòng 6, cột 16–25 | Dòng 7, cột 9–28: `new File(forwarded)` |
| CWE-89 | Cùng source trên | Cùng hai biến trên | Dòng 10, cột 9–80: `stmt.executeQuery("SELECT * FROM users WHERE name='" + forwarded + "'")` |

Tọa độ bắt đầu từ 1, cột kết thúc loại trừ. Full rule ID giữ nguyên tiền tố
`C.Users.HP.OneDrive.Documents.NTK-Thesis-V2.codex.v2.baseline.rules.` và hậu tố
`ntk.java.cwe22`/`ntk.java.cwe89`; không ghép finding chỉ bằng hậu tố.
`extra.dataflow_trace` và các đoạn mã được kiểm tra với dòng, byte offset và hash
nguồn; không suy diễn source/sink ngoài trace. Chi tiết: `E/capture/`, `E/triage/`
và [báo cáo CLI](ADVISOR_M1_ORIGINAL_CLI_PROOF.md).

## E. Giới hạn

Demo dùng hai Java fixture tổng hợp và luật intrafile cục bộ, chưa phải benchmark
quy mô lớn hay kiểm chứng trên dự án thực tế. Bốn findings không phải số TP đã có
nhãn độc lập. Không có kết quả Qwen trong lượt scan-only này; chưa thể tính độ
chính xác TP/FP, precision hoặc recall. Chưa nhận hồ sơ nghiệm thu độc lập trên
máy chủ. Việc CLI kế thừa chạy thành công không chứng minh toàn bộ RAG/web của
upstream hoạt động. `proof.json` giữ nguyên `SERVER_RUNTIME_PENDING`.

## F. Hướng tiếp theo

JavisOS phụ trách tái lập và nghiệm thu server CLI, kiểm toán Qwen LIVE và review
queue theo Prompt 12-R. Sau khi nhận bàn giao, đối chiếu 2–3 phản hồi Qwen thật,
nguồn và lịch sử kiểm duyệt; chuẩn bị benchmark có nhãn và so sánh trên cùng raw
scan. Sinh viên cùng JavisOS tổng hợp báo cáo lần 1 từ nguồn Markdown này.
Codex không thực hiện thay các phép nghiệm thu đó hoặc tạo PDF báo cáo cuối.
