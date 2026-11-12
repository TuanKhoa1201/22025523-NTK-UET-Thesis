# Dữ liệu cần chuyển từ ADMIN-PC, không đưa lên GitHub

## Tình trạng thực nhận ngày 13/11/2026

Đã nhận và tự đọc gói tại
`<PRIVATE_PATH>`.
SHA-256 archive:
`4664dcdbfc50620cc713cde20095d6fe3051335ec6c47cc39cd9c6d8bac1c6ba`.
`files.sha256.csv` khớp 289/289 tệp, kích thước và đúng tập đường dẫn; hash trước
và sau kiểm toán không đổi. Không cần gửi lại toàn bộ gói.

- `extracted/evidence/post_report_cwe22_cwe89_20261112/`: 263 tệp (**E**).
- `extracted/evidence/server_forensic_audit_failclosed_20261112/`: 26 tệp (**F mới**).
- Ba scan đã kiểm tra: `runs/stage1_dev_set_16_scan/`,
  `runs/stage1_heldout_set_40_scan/`, `runs/stage5_real_projects_scan/`.
- Đã nhận 10 assessments/evidence/input/SQLite, 6 checkpoint với 148 bản ghi,
  64 Java và `sources/expectedresults-1.2.csv`. Gói còn có một scan toàn Benchmark;
  không coi scan thêm đó là đã kiểm toán ngữ nghĩa trong phạm vi ba scan này.
- Đã nhận DB và transcript 13 bước ở `runs/stage6_human_review_demo/`.
  Không có thao tác stale-source trong transcript này.

56 Java OWASP và CSV chuẩn đã đối chiếu Git blob với repository OWASP độc lập
tại commit `8b67a88d73b2594570fc21150705283de884620b`. Metadata công khai ở
`owasp_reference_blobs.json`; không cần gửi lại các tệp OWASP đã khớp.
Biên nhận F mới chỉ dùng so kết quả sau khi tái tính, không dùng làm đáp án.

## Phần còn thiếu — chỉ yêu cầu lịch sử thực sự tồn tại

| Đường dẫn tương đối hoặc điểm xuất phát | Cần bổ sung / tình trạng | Mục đích, giới hạn |
|---|---|---|
| `W/v2/evaluation/post_report/heldout_strict_lock_manifest.json` | Bản nguyên byte lúc khóa, dấu thời gian/commit trước thực nghiệm nếu có | Bản public ở `86636b9` đã đọc; hash CRLF khớp E, nhưng `config_file/config_sha256=null`, không chứng minh đầy đủ cấu hình/thời điểm khóa |
| `W/v2/evaluation/post_report/PROMPT_VERSION_MANIFEST.json` | Bản lịch sử gắn với từng run, mã/config được nó tham chiếu | Bản public đã đọc; không có trong E. Không dùng manifest public thay request đã gửi |
| `E/checkpoints/stage2_dev16_baseline_v1_0.ckpt.jsonl` | Thiếu checkpoint của run baseline; nếu chưa từng lưu ghi `NOT_RECORDED` | Assessments/DB baseline đã có; thiếu đối chiếu checkpoint của lần đó, không chặn riêng metric held-out |
| `E/runs/stage4_heldout40_armC_evidence_llm/`, `stage4_heldout40_armD_llm_ablation/`, các run C/D còn lại | Request payload gốc, HTTP body/biên nhận transport, model digest/options/version và log thời điểm chạy nếu có | Chưa thấy tệp payload/body trong inventory. **Không biết tên tệp lịch sử**, cần người giữ máy chủ chỉ đúng tên/đường dẫn; không tự đặt tên rồi tái dựng. Response JSON bên trong assessment đã có |
| `W/v2/triage/{cli,evidence,java_context,heuristics,ollama,store}.py` và script tạo bảng lúc chạy | Commit, dirty diff và config/options đúng phiên thực nghiệm | Đọc được code public không chứng minh bản process đã chạy; không sửa module của agent khác |
| `E/runs/stage6_human_review_demo/cli_lifecycle_transcript.json`, `review.sqlite` | Hai tệp đã có; cần **log/DB riêng có sẵn** của lần stale-source nếu thực sự đã làm | F mới nói test tạm PASS nhưng không có input/DB tạm để tự đọc. Không ghi thêm event vào DB cũ hoặc thay transcript lịch sử |
| `E/sources/real_projects/WebGoat/SqlInjectionLesson8.java` (#08/#09) | Cấu hình datasource/SQL dialect/driver/dependency lock và các caller tại commit nguồn | Tệp Java đã có; việc escape quote phải phù hợp ngữ cảnh/dialect của Connection được truyền vào |
| `E/sources/real_projects/WebGoat/UserService.java` (#10) | Full checkout ghim đúng commit; tìm `WebGoatUser.java`, `UserForm.java`, controller đăng ký và mọi caller `addUser` | Gói không có các tệp này. Chưa xác định được đường dẫn package lịch sử; không khẳng định annotation DTO đã được thực thi |
| `E/sources/real_projects/demo/UserDao.java` (#15) | Caller sử dụng File, cấu hình nền tảng và quyền/symlink filesystem ở phép thử nếu đã lưu | Có dấu phân cách cuối BASE_DIR; không kết luận bypass chỉ từ startsWith. Demo riêng của thầy, chuyển riêng, không public |
| Các log run A/B/C/D gốc nếu có | Đồng hồ start/end toàn run; riêng A/B cần phép đo thực tế theo alert nếu từng ghi | `elapsed_seconds=0.0` của heuristic là placeholder. Không thể tạo lại phép đo lịch sử; thiếu thì để null/NOT_RECORDED |

**W** là worktree thật dùng lúc chạy, cần người giữ máy chủ xác nhận; không đoán
đường dẫn W từ máy Codex. Những mục chưa biết tên tệp đã ghi rõ, không có yêu cầu
chuyển một tên file tự nghĩ ra. Gửi inventory bổ sung `relative_path,size,sha256`
trước, chỉ chuyển bản sao lịch sử qua kênh riêng. Không chạy lại model để lấp
khoảng trống, không tạo khóa mới rồi gán là khóa trước thực nghiệm.

Đối chiếu [kết luận độc lập](G0_RAW_INDEPENDENT_VERDICT.md) và các hàng
INCOMPLETE trong [sổ sai lệch](G0_DISCREPANCY_REGISTER.csv). Không cần thêm raw
để xác nhận các tổng held-out hiện đã khớp; phần bổ sung nhằm kiểm chứng nguồn
gốc thực thi, nhãn thủ công, khóa cấu hình và demo stale-source lịch sử.

## Yêu cầu chuyển ban đầu ngày 12/11 — chỉ giữ làm lịch sử

Các câu “chưa có” và danh sách cần chuyển bên dưới phản ánh thời điểm **trước
khi nhận gói**. Tình trạng hiện tại và yêu cầu bổ sung là hai mục phía trên.

Nguồn thực nghiệm **E**:
`<PRIVATE_PATH>`.
Nguồn biên nhận **F**:
`<PRIVATE_PATH>`.
Nguồn cấu hình/bảng **W**: worktree dùng khi thực nghiệm; mã JavisOS tại commit
`e81c75681605034449820f5eb3fe7db9c2b4fcfc` mặc định là
`<PRIVATE_PATH>`.
Người giữ máy chủ xác nhận W qua argv/inventory, không suy ra W vẫn còn tồn tại.
Giữ nguyên cấu trúc thư mục, byte, CRLF/LF và timestamp gốc. Biên nhận F chỉ là
nguồn đối chiếu thứ hai, không thay raw E. Không tạo lại prompt/lock rồi gán là lịch sử.

Laptop hiện **chưa có raw E hoặc F**. Danh sách dưới dựa trên đường dẫn trong mã
và tài liệu công khai đã ghim, chưa phải inventory được đọc trực tiếp trên ADMIN-PC.
Ưu tiên gửi inventory trước để xác nhận đường dẫn và các tệp không tồn tại.

## Ưu tiên 1: held-out và ba raw scan

| Đường dẫn tương đối E | Tệp cần chuyển | Mục đích |
|---|---|---|
| `runs/stage1_dev_set_16_scan/` | `opengrep.json`, `opengrep.sarif`, `scan-manifest.json`, `rules.snapshot.yml`; toàn bộ artifact được manifest liệt kê | Scan 16, SHA nguồn/rules, exit và trace |
| `runs/stage1_heldout_set_40_scan/` | Cùng tập tệp trên | Scan 40 và định danh cố định |
| `runs/stage5_real_projects_scan/` | Cùng tập tệp trên | Scan 20, đếm lại vị trí sink độc lập với rule |
| `sources/dev_set_16/`, `sources/heldout_set_40/`, `sources/real_projects/` | Tất cả Java đã quét, giữ thư mục con | Nguồn tại thời điểm scan, byte/line/offset; phân biệt UserDao demo |
| `sources/expectedresults-1.2.csv` | Tệp gốc | Đối chiếu nguồn OWASP độc lập |

Artifact manifest thường gồm `version.command.json`, `version.exit.txt`,
`version.stdout.txt`, `version.stderr.txt` và bốn tệp tương ứng cho `json`, `sarif`.
Nếu manifest chỉ tới tên khác hoặc có output file riêng, chuyển đúng tất cả tên
trong manifest; không thay bằng stdout tự dựng. Cần cả inventory đường dẫn thực.

Với ba thư mục dưới đây, chuyển chính xác `assessments.jsonl`,
`input.opengrep.json`, `evidence.json`, `review.sqlite` và log stdout/stderr/exit
nếu được lưu trong lần chạy:

- `runs/stage4_heldout40_armB_heuristic/`
- `runs/stage4_heldout40_armC_evidence_llm/`
- `runs/stage4_heldout40_armD_llm_ablation/`

Mục đích: ghép từng finding, raw/post-validator, quote/hash/citation, latency,
human state và lịch sử. SQLite phải là bản chụp nhất quán; không bỏ WAL/SHM khi
còn dữ liệu chưa checkpoint. Người giữ máy chủ xuất bản sao nhất quán, không
thay đổi DB lịch sử; kèm SHA DB/bản sao và mô tả cách chụp.
Nếu dùng SQLite backup tạo bản sao mới, ghi riêng hash file lịch sử và hash bản
sao: hai hash không bắt buộc bằng nhau. Không mở DB gốc bằng công cụ có thể ghi.
`assessment.elapsed_seconds` là thời gian theo alert; cần log thời điểm bắt đầu/
kết thúc run riêng để kiểm tra wall-clock, không suy ra từ tổng elapsed_seconds.

## Ưu tiên 2: development, dự án/demo và con số 76/76

Cùng bốn tệp assessments/input/evidence/DB cho các thư mục:

- `runs/stage2_dev16_baseline_v1_0/`
- `runs/stage3_dev16_armB_heuristic/`
- `runs/stage3_dev16_armD_llm_ablation/`
- `runs/stage3_dev16_armC_evidence_llm/`
- `runs/stage3_dev16_armC_v2_1_evidence_llm/`
- `runs/stage5_real_projects_armB_heuristic/`
- `runs/stage5_real_projects_armC_evidence_llm/`

Chuyển mọi `checkpoints/<run-name>.ckpt.jsonl` thực sự tồn tại cho các run trên;
cần inventory tên cụ thể trước khi chuyển vì hiện laptop chưa biết đầy đủ tên.
Không tự tạo checkpoint cho run không có. Đối chiếu assessment theo ID, không
theo thứ tự hoặc chỉ timestamp.

Các tên checkpoint cần kiểm tra dưới E (đều có tiền tố `checkpoints/`):

```text
stage2_dev16_baseline_v1_0.ckpt.jsonl
stage3_dev16_armB_heuristic.ckpt.jsonl
stage3_dev16_armD_llm_ablation.ckpt.jsonl
stage3_dev16_armC_evidence_llm.ckpt.jsonl
stage3_dev16_armC_v2_1_evidence_llm.ckpt.jsonl
stage4_heldout40_armB_heuristic.ckpt.jsonl
stage4_heldout40_armC_evidence_llm.ckpt.jsonl
stage4_heldout40_armD_llm_ablation.ckpt.jsonl
stage5_real_projects_armB_heuristic.ckpt.jsonl
stage5_real_projects_armC_evidence_llm.ckpt.jsonl
```

Đây là tên suy ra từ quy ước `<run>.ckpt.jsonl` trong auditor, **không khẳng định
cả 10 tệp tồn tại**. Heuristic không gọi HTTP nên không đòi tạo checkpoint Ollama
cho Arm B. Nếu checkpoint thực tế mang tên khác, giữ tên gốc và ghi ánh xạ run.

## Cấu hình và biên nhận lịch sử

- Bản bytes **đã dùng tại thời điểm chạy** dưới `W/v2/evaluation/post_report/`:

  ```text
  labels_development.json       labels_development.csv
  labels_heldout.json           labels_heldout.csv
  dev_alerts.json               heldout_alerts.json
  heldout_strict_lock_manifest.json
  DATASET_PROVENANCE.json       PROMPT_VERSION_MANIFEST.json
  PAIRED_EVALUATION.csv         METRICS_BY_CWE.csv
  DEVELOPMENT_EVALUATION.csv    REAL_PROJECT_EVALUATION.md
  DATASET_MANIFEST.md           LABELING_PROTOCOL.md
  EVALUATION_METHOD.md          EVALUATION_LIMITATIONS.md
  rules/p_java_cwe22_cwe89.yml
  ```

  Mục đích: so hash raw/LF, khóa split, nhãn và bảng theo alert; không lấy public LF
  thay cho bản CRLF được hash trong khóa. Nếu W đã thay đổi, cung cấp bản lưu lịch
  sử nếu có và ghi riêng W hiện tại. Không ghi đè khóa để hợp với file mới.
- Payload request/HTTP response gốc nếu có, gắn ID và timestamp; nếu không lưu,
  ghi `NOT_RECORDED`. Không dùng request tái dựng làm chứng thực prompt lịch sử.
- Snapshot mã/commit của extractor/heuristic/prompt/validator và script tạo bảng;
  Ollama version, model digest/options, log process/model và receipt HTTP hiện có.
  Cụ thể cần nội dung đúng phiên bản `v2/triage/{cli,evidence,java_context,heuristics,ollama,store}.py`,
  cấu hình được argv tham chiếu, script tạo CSV bốn arm và Git dirty diff nếu từng
  chạy với mã chưa commit. Đây là bản sao lịch sử, không yêu cầu sửa module.
- Snapshot/commit nguồn WebGoat/java-sec-code, DTO `UserForm.java`, caller/guard
  liên quan tới UserService; UserDao bản demo riêng và căn cứ bốn nhãn FP thủ công.
- Từ F: `01_file_inventory_sha256.csv/json`, `02_raw_opengrep_scans_receipt.json`,
  `03_ollama_10_assessments_receipt.json`, `04_raw_vs_post_validator_comparison.csv`,
  `06_owasp_and_manual_ground_truth_audit.json`, `07_independent_metrics_recomputation.json`
  nếu tồn tại; kèm argv, stdout/stderr, exit và snapshot trước/sau audit.
  Tên artifact cần xác nhận qua inventory F, không đổi tên tệp cũ để khớp danh sách.
  Chuyển thêm `07_independent_metrics_recomputation.csv`,
  `06_owasp_and_manual_ground_truth_audit.csv`, `immutability_verification.json`
  và `_pre_audit_evidence_snapshot.json` nếu có. Bản ghi kiểm toán mới của JavisOS
  cần kèm SHA mã thực thi và trạng thái/exit cuối, không thay thế biên nhận cũ.
  Không cần chuyển lịch sử Javis Brain/ground_truth_verifier làm chứng minh chất lượng.

## Từng khoảng trống cần đóng bằng tệp nào

| Phép kiểm toán còn INCOMPLETE | Input tối thiểu | Điều kiện có thể kết luận |
|---|---|---|
| Số finding/ID/rule/CWE và ánh xạ Windows/WSL | 3 bộ scan E, snapshot nguồn, cấu hình path-map gốc nếu có | Hash scan và nguồn khớp manifest; mapping có căn cứ, raw JSON không sửa |
| B: 7 FP/20, C: 20 FP/20, D: raw 40 S → post 31 S/9 U | 3 assessments held-out, input/evidence, W labels/CSV | Ghép từng ID, tái tính từ assessment; giải thích từng downgrade từ response/validator |
| Citation thật và membership trong prompt | Java tại scan + request/response/checkpoint gốc | Dòng/quote/hash khớp; snippet thực sự được gửi, không request tái dựng |
| Latency C/D, thời gian B/A | elapsed_seconds theo ID + checkpoint + log run | Đơn vị rõ, không mất/trùng mẫu; phân biệt Ollama duration, client latency và wall-clock |
| HTTP/runtime/model | Receipt transport, response gốc, model digest/options/log có sẵn | Không chỉ tin trường model tự khai; thiếu lịch sử ghi NOT_RECORDED |
| Human decision/stale-source | SQLite nhất quán + audit history + hồ sơ demo/log đã có | Đọc trạng thái/lịch sử, source hash và lần từ chối; không tự tạo quyết định mới |
| Khóa lịch sử/tách tập | W nguyên byte + inventory/commit/config/prompt lúc chạy | Hash raw/LF có nguồn, không lập khóa hồi tố |
| Dev16, đồng thuận 76/76 và 20 alert dự án/demo | 7 run bổ sung, nguồn/GT/manual rationale/caller/guard | Đối chiếu độc lập từng finding; số sink riêng không suy ra từ số alert |

Nếu chưa lưu request, log hay snapshot tại thời điểm chạy, người gửi ghi rõ
`NOT_RECORDED`; công cụ nhận dữ liệu không thể phục dựng bằng chứng lịch sử đó.
Các tệp F chỉ giúp so hai kết quả kiểm toán, không đóng được các hàng thiếu E.

## Bảo mật và tính nguyên vẹn

Chuyển qua kênh riêng có kiểm soát truy cập; lưu ngoài repository ở laptop.
Không đẩy raw source, prompt, response, SQLite, checkpoint, private ZIP/PDF của
thầy hoặc token lên GitHub. Không cần gửi venv/model/binary hay toàn bộ ZIP của
thầy. Nếu log có secret: giữ bản gốc tại máy chủ, tạo bản đã che riêng, ghi rõ tệp
nào bị che và hash nào thuộc bản gốc/bản che; không giả định hash hai bản giống nhau.
Người gửi xuất inventory `relative_path,size_bytes,raw_sha256,lf_sha256` cùng SHA
của gói truyền; người nhận tự tính lại. Không chuẩn hóa newline của artifact gốc.
Gắn thêm `scope` (E/W/F), trạng thái có/thiếu/đã che và cách lấy bản sao. Inventory
cho lần chuyển là tài liệu **mới**, có ngày tạo, không thay khóa trước thực nghiệm.
LF hash chỉ tính cho text bằng CRLF→LF (không đổi encoding/BOM/nội dung khác);
file nhị phân dùng raw hash, LF hash để trống. Không gửi secret trong argv/env.

Thiếu một tệp bắt buộc phải giữ INCOMPLETE đúng mục đó. Không cài/chạy lại model
để bù khoảng trống của bằng chứng lịch sử trong mốc kiểm toán này.
