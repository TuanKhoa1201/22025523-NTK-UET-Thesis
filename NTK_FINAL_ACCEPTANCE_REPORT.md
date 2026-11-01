# NTK — Báo cáo nghiệm thu cuối

Ngày kiểm tra pipeline: 01/11/2026. Nghiệm thu bổ sung Real25 và trình duyệt: 02/11/2026. Worktree: `NTK-CWSS-V2-220`.

**Kết quả cuối: PASS trong phạm vi demo bảo vệ và các tiêu chí nghiệm thu được yêu cầu.** Pipeline, Real10 proof, Real25 private, API, build và 12 trang bằng Edge thực đã được kiểm chứng. PASS không có nghĩa đã chứng minh khả năng khai thác thực tế, kiểm thử mọi trình duyệt hoặc thực hiện reboot Windows thật; xem mục 10 về phạm vi và giới hạn.

## 1. Môi trường và dữ liệu được bảo vệ

- Thực thi Python, Git, Java và OpenGrep qua `wsl.exe -d Ubuntu-22.04`.
- Python: `/home/tuankhoa/.venvs/ntk-production-20261028/bin/python`, 3.10.20.
- JDK: `/usr/lib/jvm/java-17-openjdk-amd64`, 17.0.20.1. Shell mặc định Java 21 không được dùng cho backend nghiệm thu.
- OpenGrep 1.25.0; PyTorch 2.5.1 / CUDA 12.4; RTX 2050 4 GB.
- Qwen2.5-Coder-0.5B-Instruct + EO06 LoRA, checkpoint epoch 3; adapter SHA-256 `176b9b32ada029ba38a561b0937ccb75cb18c720979dbb58824fdcc112d2ce84`.
- Model, LoRA và tensor generate thực tế ở `cuda:0`; `local_files_only=true`, `cloud_calls_enabled=false`; bật Hugging Face/Transformers offline. Không huấn luyện lại, không chạy inference CUDA đồng thời.
- Đã kiểm tra worktree, branches, staged/unstaged diff. Sao lưu trước sửa tại `work/codex-backup-20261101-231804`, gồm source và binary Git patches. Staged diff ban đầu rỗng; các thay đổi có sẵn được giữ và tích hợp.
- Nhánh được tạo an toàn từ detached HEAD: `cwss-inference-v2-220`, nền `597ffab04408a83d8625c4f3b509b7be4c20dd09`. Không sửa nội dung worktree main, không merge/reset/clean/force-push.

## 2. Nguyên nhân Real10 và bản sửa

Scan cũ `SCAN-20261101150533-750A61` có snapshot gồm SHA bindings nhưng `files=[]`, `java_ast={}`. Findings dùng đường dẫn từ **gốc repository**, ví dụ `src/main/java/.../BenchmarkTest00006.java`; `graph.collect()` lại nhận `src_path` trỏ vào **target_subpath**. Collector tìm sai đường dẫn, nên không lưu source tương ứng.

Đã kiểm tra vòng đời: collection được gọi **trước** `scan_github_repository_and_triage()` chạy `finally` cleanup. Cleanup không xảy ra trước collector; lỗi nằm ở source root. Cleanup sau đó làm snapshot thiếu không thể tự bổ sung. Cache checkout của lần scan lịch sử rỗng; không tự dựng lại hoặc sửa revision lịch sử.

Bản sửa:

1. Collector và context collector dùng `effective_rel_root`, cùng gốc với provenance verifier và `file_path`.
2. Đọc các finding sources trước khi duyệt inventory phụ; báo `FINDING_SOURCE_UNAVAILABLE` khi thiếu source, thay vì âm thầm trả snapshot rỗng.
3. Lưu source text, raw SHA, content SHA, resolved commit, Javac AST và kết quả tái phân tích local proof khi checkout còn tồn tại. Sidecar revision chứa snapshot để replay sau cleanup.
4. Snapshot mới phải có proof tái phân tích bind cùng SHA, identity, semantic parser, state và sink coverage. Thiếu proof không được nâng thành safe/taint. Snapshot cũ giữ đường replay tương thích.
5. Sửa binding riêng cho `printf(Locale, literal_format, Object[])`: bind đúng mảng varargs có khai báo và trace, xác định slot `arg2`. Không suy diễn từ tên tham số bất kỳ. Có negative test khi thiếu proof độc lập.
6. Inventory cache phải kiểm tra SHA **từng file**, không chỉ sự tồn tại file đầu/cuối; checkout cache phải sạch, commit phải khớp. Cache bẩn bị từ chối và được giữ để điều tra; mirror bẩn không được tái sử dụng. Chặn path traversal và symlink.
7. Finding mới và báo cáo dùng assessment CWSS Inference V2 đã publish, thay vì preliminary assessment trước collection.

## 3. Scan nghiệm thu mới và đối chiếu từng finding

Scan chính để demo: **`SCAN-20261101164045-3AA266`**.

- Repository: `https://github.com/OWASP-Benchmark/BenchmarkJava.git`.
- Resolved commit: `f40c618c5a709afce350ef06ed2899c85cf586e9`.
- Cùng SHA của cả 6 source files với scan lịch sử; fresh checkout/inference, scan ID mới, cleanup bật.
- Phạm vi: `PARTIAL_BOUNDED`, 6 file Java được chọn, không phải toàn bộ OWASP Benchmark.
- 10 candidates; 2 REPORT, 6 REVIEW, 2 SUPPRESS; 5 inference GPU thực.
- Trace: 10/10 stages COMPLETED, 32,667.086 ms. Trace là ranh giới thời gian pipeline hiện có; collection/publication CWSS sau triage không được coi là phép đo riêng toàn bộ latency giao diện.
- 6 source snapshots và AST snapshots phục vụ đủ 10 findings; source hash binding 10/10. Unsupported constructor/sink binding vẫn có rejection reasons, không được biến thành proof.

| Finding | IRIS | Triage giữ nguyên | GENERAL trước → sau | Reference trước → sau | CWSS proof mới |
|---|---|---|---|---|---|
| 001 CWE-22 L72 | UNKNOWN | REVIEW | 12.6 → 12.6 | 67.1 → 67.1 | Chưa xác minh |
| 002 CWE-79 L75 | UNKNOWN | REVIEW | 12.6 → 12.6 | 67.1 → 67.1 | Chưa xác minh |
| 003 CWE-79 L87 | UNKNOWN | REVIEW | 12.6 → 12.6 | 67.1 → 67.1 | Chưa xác minh |
| 004 CWE-22 L73 | UNKNOWN | REVIEW | 12.6 → 12.6 | 67.1 → 67.1 | Chưa xác minh |
| 005 CWE-79 L74 | UNKNOWN | REVIEW | 12.6 → 12.6 | 67.1 → 67.1 | Chưa xác minh |
| 006 CWE-78 L69 | PROVEN_TAINT | REPORT | 12.6 → 16.0 | 67.1 → 84.0 | Source/AST/receiver-state sink-slot xác nhận |
| 007 CWE-78 L61 | UNKNOWN | REVIEW | 12.6 → 12.6 | 67.1 → 67.1 | Chưa xác minh |
| 008 CWE-79 L65 | PROVEN_SAFE | SUPPRESS | 12.6 → 0.0 | 67.1 → 0.0 | Safe proof độc lập, TI=N |
| 009 CWE-89 L58 | PROVEN_TAINT | REPORT | 12.6 → 16.4 | 67.1 → 86.0 | Source/AST/receiver-state sink-slot xác nhận |
| 010 CWE-79 L54 | PROVEN_SAFE | SUPPRESS | 12.6 → 0.0 | 67.1 → 0.0 | Safe proof + printf varargs binding, TI=N |

Điểm được đọc từ API assessment thực, không hardcode vào engine hoặc frontend. FC không được nâng thành Proven True. Tất cả `review_status=NOT_REVIEWED`. CWSS không thay đổi triage.

Archive gốc vẫn có SHA-256 `27f78b2a890bad97ce692c2214bcdcdd236e5b833a010707c3c4710b0d59cb79`, khớp giá trị đã đọc trước sửa. Replay 30 revisions của scan cũ và 30 revisions của scan mới đều thành công trên bản sao runtime; không backfill dữ liệu giả vào scan cũ.

## 4. Chuẩn CWSS và provenance 16 metrics

Đối chiếu [MITRE CWSS 1.0.1](https://cwe.mitre.org/cwss/cwss_v1.0.1.html), các bảng trọng số và mục 3.1–3.3. Engine giữ công thức Decimal hiện có:

```text
Base = (10*TI + 5*(AP+AL) + 5*FC) * f(TI) * IC * 4
AttackSurface = (20*(RP+RL+AV) + 20*SC + 15*IN + 5*AS) / 100
Environment = (10*BI + 3*DI + 4*EX + 3*P) * f(BI) * EC / 20
CWSS = Base * AttackSurface * Environment
f(x) = 0 khi x = 0, ngược lại bằng 1
```

Đủ 16 metrics: TI, AP, AL, IC, FC, RP, RL, AV, AS, IN, SC, BI, DI, EX, EC, P. Cả hai chế độ có code, weight, classification, rule_id, evidence và provenance cho từng finding.

- **GENERAL_JAVA:** dùng local proof khi đủ; metric chưa đủ dùng `MITRE_DEFAULT`, không coi default là bằng chứng deployment.
- **Reference:** context có attribution/rationale, phân loại `REFERENCE_ASSUMPTION`. Giả định business critical/Internet không mô tả deployment thật.
- TI=N chỉ ở hai local safe proofs đã xác nhận; UNKNOWN không tự thành safe/taint. FC giữ gate độc lập; P=NA theo targeted policy.
- Điểm không phải xác suất TP, không phải CVSS, không phải chứng minh khai thác được.

Artifacts công khai không chứa source snapshots hay dataset records:

- `docs/cwss-inference-v2/FINAL_REAL10_ACCEPTANCE.json`: đối chiếu 10 findings, source hashes và điểm.
- `docs/cwss-inference-v2/FINAL_REAL10_METRICS.csv`: **320 dòng** = 10 findings × 2 chế độ × 16 metrics.
- Chi tiết local: `work/acceptance/verified/metric-provenance.json`, `metrics.csv`, toàn bộ phản hồi API và HTML report.

## 5. Legacy heuristic

**Đã loại khỏi luồng production đang nghiệm thu; chưa xóa toàn bộ mã tương thích lịch sử.**

- Production scan không gọi `evaluate_bounded_safety_floor()` ở bước 8 hoặc triage. Dùng semantic release, source/flow evidence, strict API role và sink coverage.
- Regression test thay scorer cũ bằng hàm gây lỗi: production triage vẫn hoạt động; thay base score 0/0.7/1 không đổi quyết định.
- Finding mới có `final_heuristic_score=null`, `confidence_score=null`, `numeric_score_used_for_decision=false`. Không dùng CWSS làm ngưỡng REPORT/REVIEW/SUPPRESS.
- Gỡ các điểm heuristic hiện hành khỏi adapter React, review list, HTML report và mô tả Scoring/Architecture/scanner. Trang Scoring trình bày CWSS V2.
- Hàm/scorer cũ, trường DTO và schema index V1 còn được giữ cho API/replay lịch sử. Cột sort NOT NULL của index V1 dùng placeholder nội bộ; JSON trả null cho dữ liệu mới, không hiển thị placeholder như điểm.
- Không tuyên bố đã xóa mọi dấu vết heuristic khỏi repository, lịch sử nghiên cứu hoặc importer legacy.

## 6. Kết quả kiểm thử

| Kiểm tra | Kết quả |
|---|---|
| Backend unittest discovery | **224 tests PASS**, 0 failures/errors |
| Private Real25 DTO group | **2 PASS**, 0 failed, 0 skipped; SHA256SUMS 7/7 hợp lệ; nghiệm thu bổ sung 02/11 |
| Frontend Node tests | **10 PASS**, 0 failed, 0 skipped trong lượt có scan ID thực; thêm regression cho History |
| Trình duyệt thật | **12 trang PASS**, Edge headless 156.0.4314.58; screenshots và tương tác đã kiểm tra |
| Adapter frontend → backend thực | PASS: ID joins, hai CWSS modes, detail, model, dataset, report, trace và 404 |
| API/CORS acceptance | **37 checks PASS** |
| Dataset records/JSONL/CSV | **12 requests HTTP 200** cho 4 datasets |
| Dataset integrity | SHA/row-count verified: 275, 781, 166, 137 |
| OpenGrep smoke | PASS, 6 fixture hits |
| Javac AST smoke | PASS, 3 methods thực; đã sửa smoke cũ đọc nhầm AST root và báo 0 methods |
| Immutable revision replay | **60 PASS**: 30 cũ + 30 mới |
| Vite production build | PASS, 445 modules; cảnh báo chunk lớn >500 kB vẫn còn |
| Frontend server | HTTP 200 tại `http://127.0.0.1:5173` |
| Backend health/model | HTTP 200 tại `http://127.0.0.1:8765`; CUDA loaded |
| Secrets / diff whitespace | Không phát hiện secret theo các mẫu rõ ràng; `git diff --check` sạch |

Các lỗi phát hiện trong quá trình thực thi đã được sửa và kiểm tra lại: collector root mismatch; printf varargs binding; checkpoint mặc định trỏ ổ F cũ; Dataset dùng đường dẫn cũ; index V1 không chấp nhận null score; frontend contract tests chưa cập nhật API V2; mã hóa tiếng Việt khi truyền script qua PowerShell. Đợt bổ sung sửa breadcrumb cho route Results/Detail/Replay và ánh xạ lifecycle/UTC metadata của History. Lượt kiểm tra cuối không còn các lỗi này. Real25 và kiểm thử trực quan đã hoàn tất trong phạm vi mục 10.

## 7. Website và runtime cuối

Đã kiểm tra build/routing/API cho Tổng quan, Scanner GitHub, tiến trình 10 giai đoạn, History, Findings, Detail, Review, Scoring, Reports, Architecture, Dataset, Training, Evaluation và Trace Replay. Training/Evaluation lấy model provenance và historical receipt từ `/api/model`, không hiển thị các chỉ số hardcode trước đó như phép đo runtime mới. Review không có scan phải yêu cầu chọn scan LIVE.

**Kiểm thử trình duyệt bổ sung:** dùng Edge có sẵn qua Chrome DevTools Protocol và WebSocket tích hợp của Node 24, không cài Playwright/Puppeteer. Đã kiểm tra 12 trang được yêu cầu, tải report trong browser và sanity responsive trang Results. Chưa kiểm thử mọi tổ hợp viewport/browser hoặc accessibility đầy đủ. Backend chưa có quy trình chuyên gia xác nhận được UI kết nối; UI giữ reviewer status read-only thay vì tự xác nhận.

Backend cuối chạy trên cổng 8765, frontend hiện có trên 5173. Backend dùng bản sao storage để giữ lịch sử, thêm scan mới trong **`work/acceptance/runtime/storage`**, cache trong `work/acceptance/runtime/cache`. Runtime gốc dưới `/home/tuankhoa/ntk-production-runtime-20261028/ntk-e2e-20261101-E56FC8` được giữ. Paths model/dataset private chỉ được đọc; không commit dữ liệu này.

Runtime mới nằm trong writable worktree để tuân thủ phạm vi ghi của phiên Windows. Đây là filesystem `/mnt/c`, không phải ext4; khi vận hành dài hạn nên chuyển một bản runtime mới sang ext4 với quyền ghi phù hợp. Không tự thay đổi runtime gốc. Cấu hình khởi chạy thực nằm trong `work/acceptance/runtime/launch-env.json`, PID trong `backend.pid`, logs và artifacts trong `work/acceptance/` (đã gitignore).

## 8. File thay đổi và Git

Backend: `ntk_web_backend_service.py`, `ntk_cwss_automatic.py`, `ntk_cwss_evidence_graph.py`, `ntk_alert_verification.py`, `ntk_iris_shared.py`, `ntk_pipeline_telemetry_and_datasets.py`, `ntk_cwss_reference_scenario_api.py`, `verify_public_smoke.py`, `verify_final_acceptance.py`.

Backend tests: `test_ntk_cwss_v2.py`, `test_evidence_triage_policy.py`, `test_source_inventory_binding.py`.

Frontend pages: `Architecture.jsx`, `LiveResults.jsx`, `ResearchPages.jsx`, `Results.jsx`, `Scoring.jsx`, `UtilityPages.jsx`; services `api.js`, `liveScan.js`, `scanData.js`; scanner components `AnalysisCore.jsx`, `JobPanels.jsx`; data `research.js`, `scanGuide.js`.

Frontend tests: `cwss-route-wiring.test.cjs`, `scan-contract.test.cjs`, `live-api-acceptance.cjs`. Thêm `.gitignore` cho `/work/`, báo cáo này và hai artifacts CWSS công khai.

Git sử dụng WSL, nhánh `cwss-inference-v2-220`; remote branch trước đồng bộ ở `597ffab`. Chỉ stage source/tests/report/artifacts công khai. Không stage checkpoint, database, cache, source snapshot, private repro hoặc dữ liệu nghiên cứu private.

Đã push thành công tới `TuanKhoa1201/22025523-NTK-UET-Thesis`, đúng nhánh `cwss-inference-v2-220`, không force. Các commit triển khai: `b2e4cc1` (backend/proof/triage), `fad5596` (frontend/API), `8ba5933` (acceptance và provenance). Bản cập nhật trạng thái báo cáo được commit/push tiếp trên cùng nhánh. Worktree sạch sau đồng bộ; không merge main.

## 9. Kịch bản demo bảo vệ

1. Mở `http://127.0.0.1:5173/#/results?scan_id=SCAN-20261101164045-3AA266`.
2. Chỉ rõ phạm vi 6 file, 10 candidates; mở Trace Replay để trình bày 10 sự kiện backend thực.
3. Finding 006/009: source hash, AST, sink-slot, local taint; so sánh GENERAL với kịch bản 84.0/86.0.
4. Finding 008/010: chỉ ra safe proof, slot `arg0`/`arg2`, TI=N dẫn đến 0 theo công thức, không phải hardcode.
5. Một finding UNKNOWN: giải thích vì sao REVIEW và vì sao điểm giả định 67.1 không xác nhận vulnerability.
6. Mở 16 metrics: phân biệt VERIFIED, ESTIMATED, MITRE_DEFAULT, REFERENCE_ASSUMPTION; FC không phải Proven True.
7. Mở Reports, Dataset và Training/Evaluation; phân biệt receipt lịch sử với phép đo scan hiện tại.
8. Nếu cần quét trực tiếp: dùng cấu hình bounded/allowlist đã lưu trong `work/acceptance/request.json`; không quét toàn bộ Benchmark khi thời gian bảo vệ hạn chế. Chỉ chạy một scan CUDA mỗi lúc.

Không suy rộng local static proof thành whole-program soundness, khả năng khai thác từ Internet hoặc accuracy toàn GitHub. Không công bố số TP/FP ground-truth mới khi chưa có audit độc lập.

```text
NTK_THESIS_E2E_READY=PASS
CWSS_REAL10_PROOF_STATUS=PASS_10_SOURCE_BOUND_2_TAINT_2_SAFE_6_UNKNOWN
LEGACY_HEURISTIC_REMOVAL_STATUS=PRODUCTION_REMOVED_HISTORY_COMPATIBILITY_RETAINED
FRONTEND_STATUS=PASS_EDGE_12_PAGES_BUILD_AND_LIVE_API
BACKEND_STATUS=PASS_LOCAL_CUDA_10_STAGES
TESTS_PASSED=224_BACKEND_BASELINE_2_REAL25_10_FRONTEND_12_BROWSER_37_API_60_REPLAY_4_STARTUP
TESTS_FAILED=0_FINAL_RUN
GITHUB_SYNC_STATUS=PASS_BRANCH_PUSHED
DEMO_URL=http://127.0.0.1:5173/#/results?scan_id=SCAN-20261101164045-3AA266
```

## 10. Nghiệm thu bổ sung sau commit 557d8be — 02/11/2026

### Real25 private

Đã đọc đúng `/home/tuankhoa/ntk-production-runtime-20261028/cwss-v2-real25`, kiểm tra SHA256SUMS **7/7 files**, đặt `NTK_REAL25_DIR` trong môi trường tiến trình rồi chạy `test_ntk_cwss_v2.Real25PrivateDTOTests` với Python virtualenv và JDK 17 nêu trên. **Cả hai tests PASS, không skipped**: đối chiếu 25 findings và HTTP modes/replay sau persisted index. Không có regression; không sửa expected scores hoặc private DTO. Kiểm tra SHA256SUMS lại sau tests vẫn khớp. Không đưa private DTO, nội dung records, snapshots hay screenshots Dataset lên GitHub.

Log chỉ lưu local: `work/final-validation/real25-tests.log`, `real25-checksums.json`. Bộ 224 backend tests ở mục 6 là lượt nền trước đó; đợt này chạy riêng nhóm Real25 còn thiếu vì không sửa production backend.

### Trình duyệt thật và lỗi đã sửa

Edge **156.0.4314.58**, profile riêng trong `work/final-validation/edge-profile`, headless, CDP chỉ localhost. Không dùng browser profile của người dùng, không cài dependency mới. `tools/verify-demo-browser.cjs` thực thi Node WebSocket/CDP.

| Trang | Kết quả thực tế |
|---|---|
| Overview | Render đúng tiếng Việt; đợi stats tải xong; số liệu từ backend, không còn ảnh chụp trạng thái đang tải |
| Scanner | Form GitHub, 10 bước và validation URL không hợp lệ hoạt động; không gửi scan CUDA mới trong lượt browser này |
| History | Đọc history thực; các scan COMPLETED hiện HOÀN TẤT, đúng repository, UTC timestamps, counters và link findings/report/replay |
| Results | 10 rows; 2 REPORT / 6 REVIEW / 2 SUPPRESS; cả hai CWSS modes tải và join đúng ID |
| Finding Detail | Finding 009 hiện 86.0; bảng đủ 16 metrics; source provenance và IRIS/Qwen evidence hiển thị |
| Review | Tab REPORT có 2, REVIEW có 6, SUPPRESS có 2 rows; không thay đổi reviewer verdict |
| CWSS Scoring | 16 metric, công thức MITRE và chú thích reference assumption hiển thị đúng |
| Reports | Bấm nút tải; nhận sự kiện download completed của browser; parse tệp JSON và đối chiếu scan_id |
| Dataset | Manifest, 4 datasets và bảng records tải thực; screenshot chứa dữ liệu nên chỉ giữ local |
| Training | Model path identity, adapter SHA, CUDA device và receipt từ backend hiển thị |
| Evaluation | Historical receipt có chú thích phạm vi; không trình bày như phép đo accuracy E2E mới |
| Trace Replay | 10 rows; next đến stage 10, reset/play/pause hoạt động; không tạo scan mới |

Đã xem screenshots; lượt cuối có **0 JavaScript runtime exceptions, 0 HTTP responses lỗi**, 0 alerts không mong đợi trên các trang, không phát hiện mojibake trong DOM text. Các trang desktop kiểm tra ở 1440×1000; sanity Results ở 390×844. Có **19 PNG screenshots**, page text, download và `browser-acceptance.json` trong `work/final-validation/browser/`. Không commit/publish thư mục này.

Hai lỗi được sửa, không mở rộng tính năng:

1. `AppShell.jsx`: route `/results`, `/finding/:id` trước đó không khớp nav `/findings`, nên breadcrumb rơi về Tổng quan và menu không active. Nay dùng route alias đúng; Replay có tên breadcrumb riêng.
2. `HistoryPage.jsx` / `scanHistory.js`: response `status=OK` từng ghi đè lifecycle COMPLETED và bỏ sót `repository_url`, `_utc` timestamps, `triage_totals`. Nay normalize lifecycle đúng, chỉ dùng state hợp lệ và cho backend sửa metadata cache cũ mà không xóa field chưa có. Ba regression tests mới PASS; không cập nhật database backend.

Build sau sửa: PASS, 445 modules; Node frontend tests: **10/10 PASS** gồm adapter nối backend thật. Cảnh báo bundle >500 kB còn tồn tại, không phải lỗi build.

### Scan, service và khởi động demo

Đã chạy lại verifier 37 API checks cho **`SCAN-20261101164045-3AA266`**, vẫn PASS. Xác nhận trực tiếp: 10 findings, triage 2/6/2, scenario 006/008/009/010 lần lượt **84.0, 0.0, 86.0, 0.0**; bảng 16 metrics, source hashes, commit và provenance đúng. Không tạo scan ID mới trong đợt nghiệm thu này.

Backend 8765 và frontend 5173 vẫn chạy; PID production backend giữ **15125** trong đợt kiểm tra này. Đã xác minh directory runtime/cache/model/dataset/JDK tồn tại, base model config tồn tại và tính lại SHA adapter safetensors khớp `176b9b32ada029ba38a561b0937ccb75cb18c720979dbb58824fdcc112d2ce84`. Không thay đổi checkpoint hay dependency.

Thêm `tools/start-demo.ps1`, `tools/start_demo_backend.py` và hướng dẫn `tools/README.md`:

- Kiểm tra service identity, PID/command, port, JDK 17, paths, scan và database sẵn có; gọi WSL bằng `--exec` để giữ nguyên path.
- Healthy service được tái sử dụng. PID thuộc tiến trình khác hoặc port bị chiếm bị từ chối; không tự kill/restart hay ghi đè database. Thiếu runtime/checkpoint thì báo lỗi, không tạo store rỗng thay thế.
- Windows frontend chạy hidden; WSL backend dùng local/offline model và đúng private dataset. Không đăng ký autostart task trên Windows.
- **Đã thực hiện thật:** `-CheckOnly` và chạy launcher thường trên demo hiện có đều PASS, không restart. Trên **bản sao runtime riêng** ở cổng 8767: cold-start, gọi lại idempotent, health-check và từ chối foreign PID đều PASS (**4 checks**). Tiến trình backend test được dừng sau khi xác minh đúng PID/script/port; production và database gốc được giữ.
- **Chưa thực hiện:** reboot Windows thật; cold-start nhánh frontend của launcher trên cổng 5173 vì frontend đang dùng cho demo. Đã kiểm tra nhánh tái sử dụng frontend thật và lệnh/cấu hình khởi động; không tuyên bố đã kiểm thử reboot hoặc autostart hệ điều hành.

Sau khi mở lại máy, dùng một lệnh từ worktree:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-demo.ps1
```

Lệnh chỉ áp dụng execution policy cho tiến trình PowerShell đó, không đổi policy hệ thống. Giữ nguyên `work/acceptance/runtime` trên máy trước buổi bảo vệ vì directory này không được commit. Model có thể `NOT_LOADED` sau khởi động mới cho đến khi chạy scan cần inference; đọc findings/reports/replay lịch sử không cần huấn luyện hoặc tải model qua mạng.

### Chốt phạm vi

Kết quả public không chứa private DTO hay screenshot: `docs/cwss-inference-v2/FINAL_DEMO_VALIDATION.json`. Bằng chứng chi tiết chỉ local dưới `work/final-validation/`. Bản sửa UI đã commit tại `0892b2e`; scripts nghiệm thu/khởi động và báo cáo được commit tiếp và push cùng trên nhánh `cwss-inference-v2-220`, không merge main. Không còn blocker trong các bước nghiệm thu được yêu cầu. Các giới hạn nghiên cứu, reviewer status read-only, bounded scan và phạm vi browser/boot nêu trên vẫn giữ nguyên. Dừng sửa tính năng mới sau khi đồng bộ nhánh.
