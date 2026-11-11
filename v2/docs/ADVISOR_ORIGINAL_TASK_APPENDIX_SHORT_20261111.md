# Phụ lục Ngắn Báo cáo Tiến độ Lần 1: Kết quả Thực hiện Nhiệm vụ Ban đầu (simple_semgrepAI -> OpenGrep + Local Qwen)

> **Ghi chú tài liệu:** Đây là bản phụ lục rút gọn (độ dài mục tiêu khoảng 2-3 trang khi xuất ra định dạng văn bản/PDF; số trang thực tế phụ thuộc định dạng xuất). Bản phụ lục kỹ thuật đầy đủ kèm toàn bộ mã băm SHA-256 được lưu tại `v2/docs/ADVISOR_ORIGINAL_TASK_APPENDIX_20261111.md`, và bảng đối chứng A/B chính thức tại `v2/evaluation/ADVISOR_PAIRED_PILOT_20261111.md` (`.csv`).

- **Repository & Nhánh:** `https://github.com/TuanKhoa1201/22025523-NTK-UET-Thesis/tree/v2/integration-pilot`
- **Các nhánh thành phần đã hợp nhất (`git merge --no-ff`):** `v2/codex-core` (`0c2ffa10c5f0d565325681e8ec2e33796fd4a68c`), `v2/antigravity-review` (`c061d7ff8a62d58e57ab368ecc6297a938cea28c`), `v2/javis-benchmark` (`43e1d648402704b9bc42698e62175805d720f7ff`).

---

## 1. Môi trường Thực nghiệm & Phạm vi Nhiệm vụ Gốc

| Hạng mục | Cấu hình / Trạng thái đã xác minh trên máy chủ `ADMIN-PC` |
|---|---|
| **Hệ điều hành & Python** | Windows 11 Pro (`10.0.26200`, Python `3.12.10`) + WSL2 `Ubuntu-IRIS` (Python `3.10.22`, OpenJDK `17.0.20.1`) |
| **Công cụ SAST** | `OpenGrep 1.25.0` chạy trong WSL2 (`/usr/local/bin/opengrep`) + cầu nối Windows `opengrep.cmd` |
| **Hạ tầng LLM cục bộ** | `Ollama 0.40.7` (`127.0.0.1:11434`, `OLLAMA_NOPRUNE=true`) trên GPU **`NVIDIA RTX 4060 Ti 16 GB`** (`100% GPU`) |
| **Mô hình đã chạy thật** | **`qwen3.5:9b-q4_K_M`** (mô hình chính, `manifest SHA-256: 7dd7bb31...`, `5.63 GB` + `mmproj 921.7 MB`) và **`qwen3:8b`** |
| **Nguồn Upstream** | `hardw00t/simple_semgrepAI` (`commit 2c79a58a16d11e9dea3723e30d2a7faffba7bdc9`, giấy phép `MIT`) |

**Phân định rõ phạm vi kế thừa và sửa đổi (`v2/baseline/opengrep.patch` vs. gói tham khảo `opengrep-triage.zip` của giảng viên):**
1. **Scanner/CLI tinh gọn (`v2/baseline/fork/semgrepai/`) đã chạy thật:** Chuyển từ `semgrep scan --config=auto` sang `opengrep scan` cục bộ với `--json`/`--sarif`, `--dataflow-traces`, `--no-git-ignore`, `--disable-version-check`, `--jobs 1`; sửa lỗi mất vết dữ liệu của upstream bằng cách đọc đúng `result['extra']['dataflow_trace']` (`taint_source`, `intermediate_vars`, `taint_sink`) và giữ trạng thái mặc định `REVIEW`.
2. **Toàn bộ ứng dụng `simple_semgrepAI` upstream đầy đủ chưa chạy thành công:** Các thành phần FastAPI web, ChromaDB (RAG) và LangChain cloud LLM của upstream bị lược bỏ do xung đột phụ thuộc và để bảo đảm mã nguồn chỉ xử lý cục bộ (`127.0.0.1`).
3. **Đối chiếu với `opengrep-triage.zip` của thầy:** Đã kiểm thử cô lập ngoài Git worktree (`15/15 pytest PASS`, `git apply --check` cho patch 4 file của thầy đạt `PASS`). Bản vá của đồ án (`v2/baseline/opengrep.patch`, sửa 3 file `scanner.py`, `config.py`, `cli.py`) giữ nguyên cấu trúc ATD `CliLoc` để kiểm chứng dòng/cột/byte offset/SHA-256 thay vì làm phẳng (`flatten`) như bản tham khảo. Tệp `Bo_ma_OpenGrep_Java_Qwen.zip` nhắc trong PDF 5 trang không có trong thư mục nguồn (**NOT PROVIDED**).

---

## 2. Lệnh Chạy Tối thiểu Đã Xác minh trên Máy chủ (`exit_code = 0`)

Chạy từ PowerShell tại thư mục gốc `C:\Users\Admin\ntk-thesis-v2\integration-pilot` (sử dụng thư mục đầu ra mới `$ReproDir` để không ghi đè bằng chứng đã lưu hay tệp trong Git):

```powershell
Set-Location "C:\Users\Admin\ntk-thesis-v2\integration-pilot"
$ReproDir = "C:\Users\Admin\ntk-thesis-v2\evidence\repro_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Force -Path $ReproDir | Out-Null
$env:PATH = "C:\Users\Admin\ntk-thesis-v2\tools\opengrep\v1.25.0;$env:PATH"

# 1. Kiểm chứng patch upstream và chạy toàn bộ 105 bài Unit Test (M1: 24, M2/M3: 59, Evaluation: 22) -> exit_code = 0
python v2/baseline/verify_patch.py
python -m pytest v2/baseline/tests v2/triage/tests v2/evaluation/tests -v

# 2. Chạy demo quy trình kiểm duyệt liên hoàn (confirm-false -> ẩn khỏi queue mặc định -> --all/show/history -> reopen -> chặn khi đổi SHA-256) -> exit_code = 0
python -m v2.triage.demo_queue --output-dir "$ReproDir\queue_demo"
python -m v2.triage.demo_freshness --output-dir "$ReproDir\freshness_demo"
python v2/baseline/verify_handoff.py --engine "$ReproDir\freshness_demo\run\engine" --triage "$ReproDir\freshness_demo\run"

# 3. Tạo lại bảng đối chứng A/B (.csv/.json) và chấm điểm từ bằng chứng Qwen3.5-9B đã lưu (không gọi lại Qwen) -> exit_code = 0
python v2/evaluation/build_paired_pilot_table.py `
  --opengrep "v2/demo/smoke_m1_rules_raw.opengrep.json" `
  --labels "v2/evaluation/smoke_m1_verified_labels.json" `
  --qwen35-triage "v2/demo/triage_qwen35_9b_smoke_m1_assessments.jsonl" `
  --qwen3-8b-reference "v2/demo/triage_qwen3_8b_summary.json" `
  --source-root "C:\Users\Admin\ntk-thesis-v2\integration-pilot" `
  --output-csv "$ReproDir\ADVISOR_PAIRED_PILOT_20261111.csv" `
  --output-json "$ReproDir\paired_pilot_summary.json"

$env:PYTHONPATH = "v2/evaluation"
python -m v2.evaluation.score_pilot `
  --opengrep "v2/demo/smoke_m1_rules_raw.opengrep.json" `
  --labels "v2/evaluation/smoke_m1_verified_labels.json" `
  --triage "v2/demo/triage_qwen35_9b_smoke_m1_assessments.jsonl" `
  --source-root "C:\Users\Admin\ntk-thesis-v2\integration-pilot" `
  --output-json "$ReproDir\score_pilot_verified.json" `
  --output-md "$ReproDir\score_pilot_verified.md"
Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
```

---

## 3. Kết quả Thực nghiệm Sơ bộ trên Mã Java Tổng hợp (`SYNTHETIC SMOKE TEST`, `n = 3`)

Trên tệp `v2/evaluation/smoke_evidence/SmokeVulnSample.java` (`2 TP`, `1 FP`, `SHA-256: 090c9349...`), phép quét `v2/baseline/rules/java.yml` sinh **3 cảnh báo** (`v2/demo/smoke_m1_rules_raw.opengrep.json`, `SHA-256: 005863f2...`). Kết quả chạy thật `qwen3.5:9b-q4_K_M` (`v2/demo/triage_qwen35_9b_smoke_m1_assessments.jsonl`, `SHA-256: dc73a82c...`):

| Finding / CWE / Vị trí | Nhãn Fixture (`SYNTHETIC`) | Dataflow Trace (`Source -> Sink`) | Kết quả `qwen3.5:9b-q4_K_M` & Kiểm chứng trích dẫn | Độ trễ / Hàng đợi |
|---|---|---|---|---|
| **#0 (`5c3fa49a...`)**<br>`CWE-89` - Dòng 28 (`unsafeSqlLookup`) | `TRUE_POSITIVE` | `getParameter("username")` (d.25) -> `query` (d.26) -> `executeQuery(query)` (d.28) | `SUPPORTED` (`KEEP_TP`)<br>`citation_check = MATCHED` (dòng 25-28) | `19719.0 ms`<br>(`334` tokens), `OPEN` |
| **#1 (`76501a37...`)**<br>`CWE-22` - Dòng 33 (`unsafeFileRead`) | `TRUE_POSITIVE` | `getParameter("report")` (d.32) -> `new File("/var/app/reports/" + rawReportName)` (d.33) | `SUPPORTED` (`KEEP_TP`)<br>`citation_check = MATCHED` (dòng 32-33) | `10953.0 ms`<br>(`458` tokens), `OPEN` |
| **#2 (`3252602f...`)**<br>`CWE-22` - Dòng 47 (`safeFileRead`) | `FALSE_POSITIVE` (có `FilenameUtils.getName` ở d.46) | `getParameter("report")` (d.45) -> `cleanName` (d.46) -> `new File(... + cleanName)` (d.47) | **`SUPPORTED` (Nhận định sai FP thành TP)**<br>`citation_check = MATCHED` (dòng 45-47) | `10078.0 ms`<br>(`409` tokens), `OPEN` |

**Tổng hợp đối chứng A/B (`n = 3`, `SYNTHETIC SMOKE TEST`):**
- **Nhánh A (OpenGrep 1.25.0 đơn lẻ):** Giữ cả `3/3` cảnh báo (`2 TP`, `1 FP`).
- **Nhánh B (OpenGrep 1.25.0 + `qwen3.5:9b-q4_K_M`):**
  - **FP được đề xuất loại đúng:** **`0/1 (0.0%)`** (mô hình nhận ra `FilenameUtils.getName` ở dòng 46 nhưng vẫn xếp `SUPPORTED` vì yêu cầu thêm whitelist tên tệp).
  - **TP bị đề xuất loại nhầm:** **`0/2 (0.0%)`** (cả 2 lỗ hổng thật đều được giữ lại chính xác).
  - **Tỷ lệ trích dẫn khớp mã nguồn & SHA-256:** **`3/3 (100.0%)`** (`REVIEW / UNDETERMINED = 0/3`, cải thiện rõ rệt so với `1/3 MATCHED` ở `qwen3:8b`).
  - **Số cảnh báo tự động bị loại bỏ:** **`0/3 (0.0%)`** (100% giữ `state = OPEN`, bắt buộc con người xác nhận).
  - **Độ trễ trung bình:** **`13583.333 ms` (`13.583 giây/cảnh báo`, tổng `40.750s`)**.

---

## 4. Kết quả Kiểm duyệt Liên hoàn & Hạn chế Kỹ thuật Còn Tồn tại

1. **Demo quy trình kiểm duyệt liên hoàn sau merge (`P0.3` - `HOÀN THÀNH 100% PASS`):**
   - `python -m v2.triage.demo_queue` (`exit_code = 0`) và kịch bản CLI 7 bước trên bản sao `SmokeVulnSample.java` (`evidence/p0_final_integration_20261111/smoke_m1_cli_workflow`) đã xác nhận đầy đủ:
     - `decide ... confirm-false --actor SCRIPTED-DEMO` (`exit_code = 0`) -> **ẩn cảnh báo `CONFIRMED_FALSE` khỏi hàng đợi `queue` mặc định** (`1 -> 0` trong `demo_queue.py`; `3 -> 2` trên `SmokeVulnSample.java`).
     - `queue --all` vẫn bảo toàn toàn bộ bản ghi trong SQLite (`1` và `3`); `show` trả về `state = "CONFIRMED_FALSE"`; `history` lưu đầy đủ `actor`, `timestamp`, `action`, `reason`, `source_version` và `evidence_sha256`.
     - `decide ... reopen --actor SCRIPTED-DEMO` (`exit_code = 0`) -> cảnh báo xuất hiện lại trong `queue` mặc định (`0 -> 1` và `2 -> 3`).
     - Sửa bản sao tệp Java sau lượt quét làm đổi SHA-256 -> thao tác `confirm-false` bị **từ chối với `exit_code = 2`** (`source hash mismatch; rescan required`), lịch sử `history` giữ nguyên không bị ghi đè.
2. **Xử lý tương thích Windows/WSL2 & Git:**
   - Binary `opengrep_windows_x86.exe` bị Windows 11 Smart App Control chặn (`Error 4551`), đã giải quyết qua `/usr/local/bin/opengrep` trong WSL2 `Ubuntu-IRIS` kết hợp cầu nối `opengrep.cmd` và cờ `--path-map` (`INT-01`).
   - Các tệp snapshot upstream trong `v2/baseline/upstream/**` và `v2/baseline/opengrep.patch` được bảo toàn nguyên vẹn từng byte bằng thuộc tính **`-text`** trong `v2/baseline/.gitattributes`, giúp `verify_patch.py` và toàn bộ `105/105` bài test (`24` M1 + `59` M2/M3 + `22` Evaluation) đạt `PASS`.
3. **Các hạng mục chưa thực hiện (`NOT DONE`):**
   - Chưa chạy thành công toàn bộ ứng dụng web/RAG/cloud `simple_semgrepAI` upstream (chỉ kế thừa và chuẩn hóa phần scanner/CLI).
   - Chưa thực hiện quét dự án Java thực tế (`P0.4`) và chưa có kết quả benchmark độc lập trên tập 30-60 cảnh báo / OWASP Benchmark.
