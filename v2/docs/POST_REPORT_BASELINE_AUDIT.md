# KIỂM TOÁN ĐIỂM XUẤT PHÁT SAU BÁO CÁO TIẾN ĐỘ LẦN 1 (`POST_REPORT_BASELINE_AUDIT`)

- **Ngày kiểm toán:** `2026-11-12` (Asia/Bangkok)
- **Máy chủ thực thi:** `ADMIN-PC` (Windows 11 + WSL2 Ubuntu)
- **Worktree thực thi mới:** `C:\Users\Admin\ntk-thesis-v2\post-report-cwe22-cwe89`
- **Nhánh phát triển:** `v2/post-report-cwe22-cwe89-20261112` (tách từ commit đã nghiệm thu `150dccab3c7faa7af9e37533378dd863cb643292`)
- **Thư mục bằng chứng độc lập:** `C:\Users\Admin\ntk-thesis-v2\evidence\post_report_cwe22_cwe89_20261112`

---

## 1. Hiện trạng Môi trường, Phần cứng & Các Worktree Liên quan

### 1.1. Trạng thái các Git Worktree (Read-only Verification)

| Worktree | Đường dẫn | Nhánh / HEAD | Commit SHA | Trạng thái Git |
|---|---|---|---|---|
| `advisor-evaluation-javis` | `C:\Users\Admin\ntk-thesis-v2\advisor-evaluation-javis` | `v2/advisor-evaluation-javis-20261111` | `150dccab3c7faa7af9e37533378dd863cb643292` | Sạch (không sửa đổi) |
| `advisor-m1-proof-ref` | `C:\Users\Admin\ntk-thesis-v2\advisor-m1-proof-ref` | `detached HEAD` (`origin/v2/advisor-m1-proof-20261111` @ `8db7daf`) | `7bd442d0ccca08cb089dd01762237cb62fe88698` | Sạch (không sửa đổi) |
| `integration-pilot` | `C:\Users\Admin\ntk-thesis-v2\integration-pilot` | `v2/integration-pilot` | `940363f22b3e303a281140861c39264d218725a0` | Sạch (không sửa đổi) |
| `javis` | `C:\Users\Admin\ntk-thesis-v2\javis` | `v2/javis-benchmark` | `43e1d645df5529085c4f9737e2667a8a4b211a98` | Sạch (không sửa đổi) |
| `post-report-cwe22-cwe89` | `C:\Users\Admin\ntk-thesis-v2\post-report-cwe22-cwe89` | `v2/post-report-cwe22-cwe89-20261112` | Khởi tạo từ `150dcca` | Nhánh làm việc hiện hành |

### 1.2. Phiên bản Công cụ, Mô hình & Tài nguyên Phần cứng

- **Hệ điều hành:** Windows 11 Pro + WSL2 Ubuntu.
- **Python:**
  - Windows Host: `Python 3.12.10` (`C:\Users\Admin\AppData\Local\Programs\Python\Python312\python.exe`).
  - WSL2 Ubuntu: `Python 3.10.22` (`/usr/bin/python3.10`).
- **OpenGrep:** `1.25.0` (`C:\Users\Admin\ntk-thesis-v2\tools\opengrep\v1.25.0\opengrep.exe` cầu nối sang binary WSL2 `/home/tuankhoa/.opengrep/cli/latest/opengrep`).
- **Ollama & Mô hình cục bộ:**
  - Endpoint: `http://127.0.0.1:11434` (chỉ lắng nghe loopback cục bộ, không gọi cloud API).
  - Model chính: `qwen3.5:9b-q4_K_M` (`digest: 56671c2ab9385f9cfcb404638e32cd62d88e3501d44822208363c010179a3c90`, `size: 6,550,825,550` bytes, `parameter_size: 9.0B`, `quantization_level: Q4_K_M`).
  - Trạng thái `/api/ps` khi kiểm toán: `models: []` (xác nhận không có batch suy luận nào khác đang tranh chấp GPU).
- **GPU & Bộ nhớ:**
  - GPU: `NVIDIA GeForce RTX 4060 Ti` (`16,380 MiB` tổng VRAM, `629 MiB` đang dùng, `15,479 MiB` trống, utilization `8%`).
  - Dung lượng đĩa trống: Ổ `C:` trống `189.17 GB` (`287.66 GB` đã dùng); ổ `F:` trống `292.57 GB` (`173.19 GB` đã dùng).

### 1.3. Xác minh Tài liệu và Gói Mã Nguồn Giảng viên

| Tài liệu / Gói mã | Trạng thái | Đường dẫn | SHA-256 thực tế |
|---|---|---|---|
| Tài liệu A (21 trang) | `VERIFIED` | `C:\Users\Admin\ntk-thesis-v2\_advisor_sources\Phan_tich_va_ke_hoach_hoan_thien_khoa_luan_OpenGrep_LLM.pdf` | `49b9400fd68025d474fef4fb7cf037f21920ef97828e35b4984a05452a94e641` |
| Tài liệu B (5 trang) | `VERIFIED` | `C:\Users\Admin\ntk-thesis-v2\_advisor_sources\Phuong_an_hoan_thien_khoa_luan_OpenGrep_Qwen.pdf` | `ff0224d4fffcf85f6a35eaf6f6d32fb81163832f73cda69c5b1b361ea77fe83a` |
| Mã nguồn C (`opengrep-triage.zip`) | `VERIFIED` | `C:\Users\Admin\ntk-thesis-v2\_advisor_sources\opengrep-triage.zip` | `5f39d2fb84bbc50e63b0b2b0c4618f84d7878bab1458cc99377223ee9c31b1cd` |
| `Bo_ma_OpenGrep_Java_Qwen.zip` | `NOT_PROVIDED` | Được nhắc ở trang 3 của Tài liệu B (5 trang) nhưng không có mặt trên máy chủ | `N/A (NOT_PROVIDED)` |

---

## 2. Phân loại Trạng thái Các Thành phần Hiện có

### 2.1. Những thành phần đã đạt (Verified & Production-Ready trong phạm vi khóa luận)

1. **Chứng minh nhiệm vụ gốc (`v2/baseline`):**
   - Đã vá `simple_semgrepAI` (`2c79a58a...`) để gọi `opengrep`, đọc `extra.dataflow_trace`, xuất JSON/SARIF kèm biên nhận `scan-manifest.json` (`ntk-scan-capture-1`), chạy thực tế trên `AllowlistedQuery.java` (`4` cảnh báo JSON/SARIF khớp 1-1).
2. **Hàng đợi kiểm duyệt con người và kiểm tra phiên bản nguồn (`v2/triage/store.py`, `v2/triage/scan_receipt.py`):**
   - Lưu trạng thái cảnh báo trong SQLite (`review.sqlite`) với 3 trạng thái `OPEN`, `CONFIRMED_TRUE`, `CONFIRMED_FALSE`.
   - Không tự động xóa hoặc ẩn cảnh báo dựa trên kết luận của Qwen (`requires_human_review = True`).
   - Ghi lịch sử sự kiện (`events` table: `actor`, `timestamp`, `action`, `reason`, `source_version`, `observed_version`, `evidence_sha256`), hỗ trợ mở lại (`reopen`).
   - Chặn thao tác `confirm-false` nếu tệp mã nguồn Java đã bị sửa đổi hoặc xóa sau thời điểm quét (`source_sha256` mismatch).
3. **Kiểm chứng trích dẫn mã nguồn (`v2/triage/ollama.py`, `v2/evaluation/codex_adapter.py`, `v2/evaluation/score_pilot.py`):**
   - Kiểm tra cả phạm vi dòng (`start_line`, `end_line`), mã băm `sha256` của tệp nguồn và nội dung `quote` (cả đơn dòng và đa dòng). Nếu trích dẫn không khớp, tự động hạ về `UNDETERMINED` / `REVIEW`.
4. **Bộ kiểm thử tự động & Quality Gate (`v2/scripts/run_v2_quality_gate.py`):**
   - `178` bài kiểm thử pytest (`26` subtests) và `11/11` bước trong `run_v2_quality_gate.py` đạt `PASS`.

### 2.2. Những thành phần chỉ mới Smoke-Test (`SYNTHETIC_SMOKE_PILOT`)

1. **Thực nghiệm đối chứng OpenGrep vs. OpenGrep + Qwen (`SmokeVulnSample.java`, `n = 3`):**
   - Mới chạy trên 3 cảnh báo tổng hợp (`2 TP`, `1 FP`).
   - Kết quả hiện tại: Qwen giữ cả 3 cảnh báo (`SUPPORTED`), dẫn đến **FP được đề xuất loại đúng = `0/1` (`0.0%`)**, **TP bị đề xuất loại nhầm = `0/2` (`0.0%`)**.
   - Đặc biệt, ở finding #2 (`SmokeVulnSample.java` dòng 47, `CWE-22`), dù mã nguồn dòng 46 có `String cleanName = FilenameUtils.getName(rawReportName);`, Qwen vẫn trả về `SUPPORTED` thay vì `REFUTED`.
2. **Chạy gói mẫu `opengrep-triage.zip` của giảng viên:**
   - Mới chạy trên `examples/demo/src/main/java/demo/UserDao.java` (`4` cảnh báo -> `3 TP`, `1 FP`).

### 2.3. Những phần chưa được chứng minh (`PENDING` trước Giai đoạn 1–7)

1. **Tập dữ liệu đối chứng có nhãn độc lập 30–60 cảnh báo (`CWE-22` và `CWE-89`):** Chưa xây dựng từ OWASP BenchmarkJava v1.2 và chưa tách `development set` / `held-out evaluation set`.
2. **Đánh giá 3 cấu hình đối chứng (`Arm A: OpenGrep-only`, `Arm B: OpenGrep + heuristic`, `Arm C: OpenGrep + evidence + Qwen`, cùng chế độ `llm` không trace) và 3 chính sách (`baseline`, `drop_fp`, `keep_tp_only`):** Chưa thực hiện trên tập held-out có nhãn độc lập.
3. **Quét và phân tích định tính trên một dự án Java mã nguồn mở thực tế (ví dụ OWASP WebGoat):** Chưa thực hiện trong nhánh V2.
4. **Nghiên cứu tình huống (5 case studies thực tế) & Bản nháp 5 chương khóa luận:** Chưa biên soạn từ số liệu thực nghiệm.

---

## 3. Các Điểm Mù Kỹ Thuật Phát Hiện Qua Đối Chiếu `v2/triage` và `opengrep_triage` (Gói Mẫu Giảng Viên)

Qua đối chiếu trực tiếp mã nguồn `v2/triage` hiện tại với gói `opengrep_triage` (`SHA-256: 5f39d2fb...`) của giảng viên, phát hiện **5 điểm mù kỹ thuật quan trọng**:

1. **Điểm mù 1 — Lỗi lệch 1 byte (`\r\n` vs `\n`) của `v2/demo/smoke_m1_rules_raw.opengrep.json` khi tạo Git worktree mới:**
   - *Nguyên nhân:* File `.gitattributes` ở thư mục gốc có dòng `*.json text eol=lf`. Khi `smoke_m1_rules_raw.opengrep.json` được tạo trên Windows (`5,698` bytes kết thúc bằng `\r\n`, `SHA-256: 005863f208b58de1195d252a9544fbcef53c53801281345328cf0aff32d4ccb4`), Git lưu blob trong kho đối tượng ở dạng `LF` (`5,697` bytes, `SHA-256: b571e95ec7643d310866c5810a12ba0a0e208f573e173bf2cb264e977753aaaa`). Khi checkout sang worktree mới (`post-report-cwe22-cwe89`), file trên đĩa có `5,697` bytes nên bị `verify_repro_contract.py` từ chối với lỗi `SCAN_HASH_MISMATCH (exit_code = 3)`.
   - *Khắc phục ở Giai đoạn 0:* Đã thêm `v2/demo/.gitattributes` (`smoke_m1_rules_raw.opengrep.json -text`) và khôi phục đúng blob `5,698` bytes (`005863f2...`), giúp toàn bộ `11/11` bước của `run_v2_quality_gate.py` đạt `PASS` (`exit_code = 0`).
2. **Điểm mù 2 — `v2/triage/evidence.py` từ chối cấu trúc `CliCall` trong `dataflow_trace` xuyên phương thức (`--taint-intrafile`):**
   - *Hiện trạng:* Tại `v2/triage/evidence.py` dòng 207–208, mọi nút `CliCall` (sinh ra khi luồng dữ liệu đi qua hàm phụ trong cùng một file Java, rất phổ biến trong OWASP Benchmark và dự án thực tế) đều bị gán lỗi `"unsupported or missing source/sink trace structure"` vào `record["issues"]`, khiến cảnh báo tự động bị ép về `UNDETERMINED` trước khi gọi Qwen.
   - *Giải pháp từ gói mẫu giảng viên:* `opengrep_triage/findings.py` (`_flatten_call_trace`) làm phẳng đệ quy cả `CliLoc` và `CliCall` (trích xuất bước `call`, `intermediate_vars` và trace bên trong) mà vẫn kiểm chứng được vị trí dòng mã thực tế.
3. **Điểm mù 3 — `v2/triage/evidence.py` chỉ lấy `±3` dòng quanh vị trí cảnh báo, thiếu ngữ cảnh phương thức Java và hàm gọi cùng file:**
   - *Hiện trạng:* `location_evidence` chỉ cắt `[sl - 3, el + 3]` dòng quanh điểm source/sink. Nếu bước làm sạch (`sanitizer`), bước gán lại hằng (`constant_reassignment`), nhánh `if (false)` hoặc hàm helper nằm cách sink hơn 3 dòng (như trong hầu hết các servlet của OWASP BenchmarkJava), Qwen hoàn toàn không nhìn thấy đoạn mã đó và cũng không được phép trích dẫn các dòng đó!
   - *Giải pháp từ gói mẫu giảng viên:* Tái sử dụng logic trích xuất phương thức bao quanh + `callees`/`callers` cùng file từ `opengrep_triage/java_context.py` đưa vào `snippets` của `record` trong `v2/triage/evidence.py`.
4. **Điểm mù 4 — Thiếu tín hiệu heuristic xác định (`sanitizers.yaml`) và hướng dẫn phân biệt `CWE-22`/`CWE-89` trong prompt của `v2/triage/ollama.py`:**
   - *Hiện trạng:* Prompt trong `v2/triage/ollama.py` chỉ có 8 dòng tổng quát bằng tiếng Anh, không định nghĩa tiêu chí 3 nhóm cho `CWE-22`/`CWE-89`, không yêu cầu giải thích tiếng Việt, và câu `"Do not infer missing flows or sanitizers"` khiến Qwen không dám kết luận `REFUTED` ngay cả khi thấy rõ `FilenameUtils.getName(rawReportName)` ở dòng 46 của `SmokeVulnSample.java`.
   - *Giải pháp từ gói mẫu giảng viên:* Tích hợp bộ thu thập tín hiệu xác định (`EvidenceCollector` + `sanitizers.yaml` cho `CWE-22`/`CWE-89`) và tinh chỉnh prompt/chế độ chạy (`heuristic`, `llm`, `evidence+llm`) theo đúng Phụ lục B của Tài liệu A (21 trang).
5. **Điểm mù 5 — `v2/triage` chưa có cơ chế Cache theo SHA-256 request và Checkpoint resume theo từng cảnh báo:**
   - *Giải pháp:* Bổ sung `--cache-dir` và `--checkpoint` (append-only JSONL) để khi chạy thực nghiệm 30–60 cảnh báo với Qwen3.5-9B cục bộ, tiến trình có thể resume tức thì nếu gián đoạn mà không gọi lại các cảnh báo đã hoàn tất.

---

## 4. Nguồn Dữ Liệu Sẵn Có Trên Máy Chủ Phục Vụ Giai Đoạn 1–5

1. **OWASP BenchmarkJava v1.2:**
   - Đường dẫn WSL2: `/home/tuankhoa/migration/ntk_ft211_sources/BenchmarkJava`
   - Commit cố định: `8b67a88d73b2594570fc21150705283de884620b` (`clean working tree`).
   - File nhãn gốc: `expectedresults-1.2.csv` (`2,740` test cases, trong đó `pathtraver` CWE-22 có `268` test cases và `sqli` CWE-89 có `504` test cases).
2. **Dự án Java mã nguồn mở thực tế:**
   - **OWASP WebGoat:** `/home/tuankhoa/iris/data/project-sources/WebGoat` (commit `5357a65e054976cd7d79b81ef3906ded050ed921`, clean).
   - **java-sec-code:** `/home/tuankhoa/migration/ntk_ft211_sources/java-sec-code` (commit `4711f4e186258c6e0dd5c3863e7c9592e7e9026a`, clean).
3. **Bộ quy tắc OpenGrep Java đã ghim phiên bản:**
   - `p-java.raw.yaml` (`SHA-256: 5e652fa9ac09c9fac36bbadc3562a0c8eed1a47438a9d1f545e021ae3c5648b1`) và bộ quy tắc taint CWE-22/CWE-89 trong `v2/baseline/rules/java.yml` & `v2/evaluation/smoke_evidence/v2_java_taint_rules.yaml`.
