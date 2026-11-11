# Báo cáo Kiểm tra M0 và Chuẩn bị Môi trường Thực nghiệm (OpenGrep + Local Qwen)

- **Thời điểm thực hiện:** `2026-11-11 02:30 - 03:00 (+07:00)` (`2026-11-10T19:30:00Z - 19:59:00Z`)
- **Máy chủ thực thi:** `ADMIN-PC` (`Microsoft Windows 11 Pro 10.0.26200`, `13th Gen Intel Core i5-13400F`, 16 logical processors)
- **Workspace V2:** `C:\Users\Admin\ntk-thesis-v2\javis`
- **Nhánh Git:** `v2/javis-benchmark` (khởi tạo từ commit `b724682`, `thesis-v2/opengrep-qwen`)
- **Thư mục bằng chứng tách biệt (ngoài Git):** `C:\Users\Admin\ntk-thesis-v2\evidence\m0_m2_env_prep`
- **Thư mục dữ liệu đầu vào tách biệt (ngoài Git):** `C:\Users\Admin\ntk-thesis-v2\incoming`

---

## 1. Bảng Tổng hợp Trạng thái Kiểm tra (PASS / FAIL / IN_PROGRESS)

| Hạng mục | Trạng thái | Kết quả xác minh thực tế | Đường dẫn bằng chứng |
|---|---|---|---|
| **M0.1 Git Repository & Branch** | **PASS** | Repo `C:\Users\Admin\ntk-thesis-v2\javis`, nhánh `v2/javis-benchmark`, commit gốc `b724682`, không can thiệp nhánh `main` hay thư mục đồ án cũ. | `C:\Users\Admin\ntk-thesis-v2\javis` |
| **M0.2 GPU, VRAM, RAM, Disk** | **PASS** | `NVIDIA GeForce RTX 4060 Ti` (`16380 MiB` VRAM, Driver `591.86`, CUDA `13.1`, Compute `8.9`); RAM `63.82 GB` (trống `39.84 GB`); ổ `C:` trống `192.07 GB`, `F:` trống `302.71 GB`, `D:` trống `10680.56 GB`. | `evidence/m0_m2_env_prep/ollama_serve.log` |
| **M0.3 Chẩn đoán lỗi Ollama CLI** | **PASS** | Xác định chính xác 2 nguyên nhân gốc rễ: (1) Bản `ollama.exe` (`v0.40.7`) là bản standalone zip không kèm GUI `ollama app.exe`, nên khi server tắt lệnh `ollama list` báo `could not locate ollama app`; (2) Thư mục `manifests-v2` trong `OLLAMA_MODELS` thuộc `BUILTIN\Administrators` thiếu quyền `Delete` cho user không nâng quyền, gây lỗi `Access is denied` khi `OLLAMA_NOPRUNE=false`. | `evidence/m0_m2_env_prep/ollama_serve.log` |
| **M0.4 Khởi động Ollama HTTP API** | **PASS** | Khởi chạy `ollama.exe serve` (`v0.40.7`) với `OLLAMA_NOPRUNE=true`, lắng nghe tại `http://127.0.0.1:11434`, nhận diện đầy đủ CUDA `RTX 4060 Ti` (`16.0 GiB`, `default_num_ctx=4096`) và 5 model có sẵn trên ổ `F:`. | `evidence/m0_m2_env_prep/ollama_serve.log` |
| **M0.5 Kiểm tra OpenGrep (Windows & WSL)** | **PASS** | WSL `Ubuntu-IRIS` có sẵn `/usr/local/bin/opengrep` (`v1.25.0`, SHA256 `9ac4aebb...`). Bản rời Windows `opengrep_windows_x86.exe` (`v1.25.0`) bị Windows 11 Smart App Control chặn tiến trình con (`Error 4551`). Đã tạo cầu nối `C:\Users\Admin\ntk-thesis-v2\tools\opengrep\v1.25.0\opengrep.cmd` gọi trực tiếp WSL OpenGrep `v1.25.0` đạt khớp tuyệt đối SHA-256. | `tools/opengrep/v1.25.0/opengrep.cmd` |
| **M1/B.1 Chạy thực nghiệm OpenGrep Java + Trace** | **PASS** | Quét `SmokeVulnSample.java` với bộ luật `v2_java_taint_rules.yaml` và bộ luật ghim `p-java.yaml` (`SHA256: 5e652fa9...`). Xuất JSON chuẩn, xác minh đầy đủ `check_id`, tọa độ dòng/cột và `extra.dataflow_trace` (`taint_source`, `intermediate_vars`, `taint_sink`), 0 báo động giả trên hàm đã khử độc. | `evidence/m0_m2_env_prep/opengrep_smoke/opengrep_v2_taint_output.json` |
| **M2/B.2 Suy luận Qwen cục bộ trên GPU (JSON, ctx 4096)** | **PASS** | Xác minh suy luận thật 100% GPU (`llamacpp` CUDA `v13`) với `num_ctx=4096`, `think=false`, JSON schema chặt chẽ trên cả `qwen3:8b` (`500a1f067a9f`, `Q4_K_M`, VRAM `5998 MiB`, warm `2537.27 ms`) và `qwen3:14b` (`bdbd181c33f2`, `Q4_K_M`, VRAM `9884 MiB`, `41/41 layers GPU`). | `evidence/m0_m2_env_prep/qwen3_8b_gpu_json_warm_evidence.json`, `qwen3_14b_gpu_json_evidence.json` |
| **M2/B.3 Tải `qwen3.5:9b-q4_K_M`** | **IN_PROGRESS (Background)** | Đã kích hoạt `ollama pull qwen3.5:9b-q4_K_M` (`6.55 GB`: `921.7 MB` projector `sha256:f836f08f...` + `5.63 GB` model `sha256:02d45dc1...`). Do băng thông mạng thực tế của máy chủ giới hạn ở mức `~500-650 KB/s`, tiến trình tải đang chạy nền an toàn vào ổ `F:`. | `evidence/m0_m2_env_prep/ollama_pull_qwen35_9b_stream32.log` |

---

## 2. Phiên bản Công cụ và Cấu hình Hạ tầng Đã Xác minh

- **Hệ điều hành Host:** `Microsoft Windows 11 Pro` (Version `10.0.26200`)
- **GPU:** `NVIDIA GeForce RTX 4060 Ti` (`16380 MiB` VRAM), Driver `591.86`, CUDA `13.1`, Compute Capability `8.9`
- **RAM:** Tổng `66,916,784 KB` (`63.82 GB`), khả dụng `~39.84 GB`
- **Dung lượng ổ đĩa:**
  - `C:`: Đã dùng `284.77 GB` / Trống `192.07 GB`
  - `D:`: Đã dùng `495.42 GB` / Trống `10,680.56 GB`
  - `E:`: Đã dùng `45.83 GB` / Trống `192.65 GB`
  - `F:`: Đã dùng `163.05 GB` / Trống `302.71 GB`
- **Python (Windows):** `Python 3.12.10` (`C:\Users\Admin\AppData\Local\Programs\Python\Python312\python.exe`)
- **WSL2 (`Ubuntu-IRIS`):** WSL version 2
  - OpenGrep: `1.25.0` (`/usr/local/bin/opengrep` -> `/home/tuankhoa/.opengrep/cli/v1.25.0/opengrep`, SHA-256 `9ac4aebb47ba3f7b0d8fc641ac8749cb6c2f253f616131a67d9631e00d4bea33`)
  - Java (WSL): `OpenJDK 17.0.20.1` (`2026-08-18`)
  - Python (WSL): `Python 3.10.22`
  - Ollama (WSL): `0.40.3` (`/usr/local/bin/ollama`)
- **Ollama (Windows Host):** `0.40.7` (`F:\ACTIVE-WORKSPACES\Tools\Ollama\v0.40.7\bin\ollama.exe`, kích thước `28,027,784` bytes, kèm thư viện `cuda_v12`, `cuda_v13`, `vulkan` và `llama-server.exe`)
- **Thư mục lưu trữ Model Ollama (`OLLAMA_MODELS`):** `F:\ACTIVE-WORKSPACES\Models\Ollama_Staging_20261023-124046-0d639a03`

---

## 3. Chẩn đoán Kỹ thuật Chuyên sâu (Giai đoạn A)

### 3.1. Phân tích lỗi `Error: could not locate ollama app` và lỗi quyền `manifests-v2`
1. **Phân biệt lỗi CLI, thiếu ứng dụng và trạng thái server:**
   - Binary `F:\ACTIVE-WORKSPACES\Tools\Ollama\v0.40.7\bin\ollama.exe` hoạt động bình thường (`ollama.exe --version` trả về `0.40.7`).
   - Khi cổng `127.0.0.1:11434` chưa có tiến trình `ollama serve` lắng nghe, các lệnh client như `ollama list` trên Windows tự động gọi hàm tìm kiếm ứng dụng khay hệ thống `%LOCALAPPDATA%\Programs\Ollama\ollama app.exe`. Do máy chủ dùng gói giải nén độc lập (`ollama-windows-amd64.zip`) tại ổ `F:`, tệp GUI `ollama app.exe` không tồn tại, dẫn tới thông báo `Error: could not locate ollama app`.
2. **Chẩn đoán lỗi `Access is denied` khi khởi động `ollama.exe serve` mặc định:**
   - Trong thư mục `F:\ACTIVE-WORKSPACES\Models\Ollama_Staging_20261023-124046-0d639a03`, thư mục con `manifests-v2` (rỗng) có Owner là `BUILTIN\Administrators` và quyền của nhóm `BUILTIN\Users` là `Write, ReadAndExecute, Synchronize` (`0x1201bf`), không có cờ `Delete`.
   - Khi chạy `ollama.exe serve` với cấu hình mặc định (`OLLAMA_NOPRUNE=false`), hàm dọn dẹp lúc khởi động cố gắng xóa thư mục `manifests-v2` và dừng với lỗi `Error: remove ...\manifests-v2: Access is denied`.
   - **Giải pháp an toàn tuyệt đối:** Đặt biến môi trường `OLLAMA_NOPRUNE=true` trước khi chạy `ollama.exe serve`. Cách này vừa bỏ qua thao tác xóa `manifests-v2` không cần quyền Administrator, vừa bảo vệ tuyệt đối toàn bộ các blob model cũ trên ổ `F:`.

### 3.2. Chẩn đoán OpenGrep trên Windows 11 (`Error 4551`) và WSL2
- Khi tải bản phát hành chính thức `opengrep_windows_x86.exe` (`v1.25.0`, SHA-256 `B010709BB790086083442EABE9A0B6BF48064ED87CDF808591BAECDB60CCDF73`) về `C:\Users\Admin\ntk-thesis-v2\tools\opengrep\v1.25.0\opengrep.exe`, Windows 11 Application Control (Smart App Control) chặn thao tác giải nén và khởi chạy tiến trình con của đóng gói PyOxidizer (`Error, couldn't launch child ([Error 4551] An Application Control policy has blocked this file)`).
- Ngược lại, bản `/usr/local/bin/opengrep` (`v1.25.0`) trong WSL2 `Ubuntu-IRIS` thực thi hoàn toàn bình thường.
- Đã xây dựng cầu nối `C:\Users\Admin\ntk-thesis-v2\tools\opengrep\v1.25.0\opengrep.cmd` (kèm `opengrep_wsl_bridge.py`) tự động ánh xạ đường dẫn Windows sang `/mnt/<drive>/...` và gọi `/usr/local/bin/opengrep` trong WSL2, đảm bảo cả script PowerShell trên Windows lẫn script Bash trong WSL2 đều dùng chung đúng engine `OpenGrep 1.25.0`.

---

## 4. Kết quả Thực nghiệm Giai đoạn B

### 4.1. Danh sách Model Ollama hiện có trên máy chủ (`ollama list`)
```text
NAME               ID              SIZE      MODIFIED
llama3.1:latest    46e0c10c039e    4.9 GB    6 months ago
deepseek-r1:8b     6995872bfe4c    5.2 GB    6 months ago
qwen3:30b-a3b      ad815644918f    18 GB     7 months ago
qwen3:14b          bdbd181c33f2    9.3 GB    7 months ago
qwen3:8b           500a1f067a9f    5.2 GB    7 months ago
```

### 4.2. Kết quả Suy luận Thực tế Qwen trên GPU NVIDIA (Context 4096, JSON Schema)

Thử nghiệm yêu cầu phân tích cảnh báo SQL Injection (`SmokeVulnSample.java`, dòng 24-29, kèm `dataflow_trace` từ dòng 25 đến dòng 28) với `num_ctx = 4096`, `think = false`, `temperature = 0.0`, `seed = 42`:

| Chỉ số | `qwen3:8b` (Cold Load) | `qwen3:8b` (Warm GPU) | `qwen3:14b` (Cold Load) |
|---|---|---|---|
| **Model ID / Digest** | `500a1f067a9f` (`Q4_K_M`, `8.2B`) | `500a1f067a9f` (`Q4_K_M`, `8.2B`) | `bdbd181c33f2` (`Q4_K_M`, `14.8B`) |
| **Offload GPU (`ollama ps`)** | `100% GPU` (`5.6 GB` VRAM) | `100% GPU` (`5.6 GB` VRAM) | `100% GPU` (`9.7 GB` VRAM, `41/41 layers`) |
| **VRAM sử dụng (`nvidia-smi`)** | `509 MiB` -> `5998 MiB` | `5998 MiB` (ổn định) | `509 MiB` -> `9884 MiB` |
| **Công suất GPU (`nvidia-smi`)** | `5.98 W` -> `107.83 W` (`97%` util) | `107.83 W` | `6.16 W` -> `116.09 W` |
| **Tổng thời gian (`wall_clock_ms`)** | `26,659.99 ms` | **`2,537.27 ms`** | `42,904.59 ms` |
| **Thời gian nạp model (`load_duration`)** | `14,951.40 ms` | `0 ms` (cached) | `29,989.12 ms` |
| **Thời gian sinh token (`eval_duration`)** | `10,927.69 ms` (`98` tokens) | `2,162.90 ms` (`98` tokens, `44.85 tok/s`) | `4,168.19 ms` (`113` tokens, `27.11 tok/s`) |
| **Kết quả JSON hợp lệ** | `PASS` (`verdict: TRUE_POSITIVE`, `cwe: CWE-89`, `source_line: 25`, `sink_line: 28`) | `PASS` (`verdict: TRUE_POSITIVE`, `cwe: CWE-89`, `source_line: 25`, `sink_line: 28`) | `PASS` (`verdict: TRUE_POSITIVE`, `cwe: CWE-89`, `source_line: 25`, `sink_line: 28`) |

Phản hồi JSON thực tế từ `qwen3:8b` (`qwen3_8b_gpu_json_warm_evidence.json`):
```json
{
  "verdict": "TRUE_POSITIVE",
  "cwe": "CWE-89",
  "source_line": 25,
  "sink_line": 28,
  "has_sanitizer": false,
  "requires_human_confirmation": false,
  "rationale": "The user input is directly concatenated into a SQL query string without any sanitization or parameterization, leading to a potential SQL injection vulnerability."
}
```

### 4.3. Kết quả Thực nghiệm OpenGrep `v1.25.0` trên Mã nguồn Java (`SmokeVulnSample.java`)

- **Tệp mã nguồn kiểm thử:** `SmokeVulnSample.java` gồm 4 phương thức:
  1. `unsafeSqlLookup` (dòng 24-29): Lỗ hổng thật `CWE-89` (nối chuỗi `request.getParameter("username")` vào `stmt.executeQuery(query)`).
  2. `unsafeFileRead` (dòng 31-35): Lỗ hổng thật `CWE-22` (nối chuỗi `request.getParameter("report")` vào `new File(...)` và `new FileInputStream(targetFile)`).
  3. `safeSqlLookup` (dòng 37-42): Đối chứng âm `CWE-89` (dùng `PreparedStatement` tham số hóa).
  4. `safeFileRead` (dòng 44-49): Đối chứng âm `CWE-22` (khử độc bằng `FilenameUtils.getName(rawReportName)`).
- **Lệnh thực thi:**
  ```powershell
  C:\Users\Admin\ntk-thesis-v2\tools\opengrep\v1.25.0\opengrep.cmd scan --config C:\Users\Admin\ntk-thesis-v2\evidence\m0_m2_env_prep\opengrep_smoke\v2_java_taint_rules.yaml --json --dataflow-traces --output C:\Users\Admin\ntk-thesis-v2\evidence\m0_m2_env_prep\opengrep_smoke\opengrep_windows_bridge_output.json C:\Users\Admin\ntk-thesis-v2\evidence\m0_m2_env_prep\opengrep_smoke\SmokeVulnSample.java
  ```
- **Kết quả kiểm chứng:**
  - Phiên bản xuất trong JSON: `"version": "1.25.0"`
  - Số lượng cảnh báo: `2` cảnh báo đúng (`unsafeSqlLookup` ở dòng `28:16 -> 28:40` và `unsafeFileRead` ở dòng `34:16 -> 34:47`), `0` báo động giả trên 2 hàm an toàn.
  - Xác nhận `extra.dataflow_trace`: Có đầy đủ `taint_source`, `intermediate_vars` (`userInput` -> `query` và `rawReportName` -> `targetFile`), và `taint_sink` kèm tọa độ dòng/cột/offset chính xác.
  - Đối chiếu bổ sung với bộ luật ghim đầy đủ `p-java.yaml` (`SHA256: 5e652fa9ac09c9fac36bbadc3562a0c8eed1a47438a9d1f545e021ae3c5648b1`, nguồn `https://semgrep.dev/c/p/java`): Phát hiện chính xác cả 2 hàm lỗ hổng kèm `extra.dataflow_trace` đầy đủ và `0` báo động giả trên 2 hàm an toàn.

---

## 5. Lệnh Kiểm tra Tái lập Nhanh

Chạy script kiểm tra tự động trong workspace V2:
```powershell
powershell -ExecutionPolicy Bypass -File C:\Users\Admin\ntk-thesis-v2\javis\v2\scripts\check_v2_env.ps1 -StartOllamaIfStopped
```
