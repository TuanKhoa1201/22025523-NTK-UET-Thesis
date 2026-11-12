> Historical results retained. Current acceptance disposition: [G0_FINAL_RESOLUTION.md](G0_FINAL_RESOLUTION.md). Raw FAIL/INCOMPLETE is not replaced by the derived CONDITIONAL decision.

# Kiểm toán độc lập dữ liệu thô — 13/11/2026

**Chưa nghiệm thu G0.** Đã đọc dữ liệu chuyển từ máy chủ và tái tính bằng mã
Python độc lập, không gọi scorer sản xuất, OpenGrep, Qwen hoặc auditor JavisOS.
Các số chính held-out khớp raw. Kiểm toán tự động trả **FAIL, exit 2** vì hai
số thời gian trong tài liệu dự án/demo khác dữ liệu. Nhãn thủ công, payload
lịch sử và một số điều kiện tái lập còn **INCOMPLETE**. Không thay dữ liệu gốc
để làm mất các trạng thái này.

## 1. Nguồn đã thực sự đọc

Gói riêng:
`<PRIVATE_PATH>`.
SHA-256 archive:
`4664dcdbfc50620cc713cde20095d6fe3051335ec6c47cc39cd9c6d8bac1c6ba`.
Đã tự kiểm tra `files.sha256.csv`: **289/289 tệp**, kích thước và tập đường dẫn
khớp. Toàn bộ 289 hash trước/sau kiểm toán không đổi.

Hai cây con thực nhận dưới `extracted/evidence/`:

- `post_report_cwe22_cwe89_20261112/` (E): 263 tệp thực nghiệm.
- `server_forensic_audit_failclosed_20261112/` (F): 26 tệp biên nhận đối chiếu.

Đã đọc 3 bộ JSON/SARIF/manifest/rules, 10 run với **240 assessments**, 6
checkpoint với **148 bản ghi**, 11 SQLite gồm demo, 64 Java và CSV OWASP.
158 assessment có raw response JSON và hash canonical JSON khớp receipt client.
Đây là tính nhất quán hiện vật, **không phải 158 chứng thực HTTP/model độc lập**.
Một scan toàn Benchmark khác trong gói không nằm trong phạm vi ba scan kiểm tra.

Nguồn chuẩn ngoài máy chủ: Git tree chính thức
[OWASP BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava/tree/8b67a88d73b2594570fc21150705283de884620b),
commit `8b67a88d73b2594570fc21150705283de884620b`. Metadata 61 blob công khai ở
[owasp_reference_blobs.json](owasp_reference_blobs.json). Đã đối chiếu blob của
56 Java và `expectedresults-1.2.csv`, đọc helper liên quan tại cùng commit.
SHA-256 CSV chuẩn:
`1809f6a690c6cf7dd6685df6ebe2eef8fe3ca93d19a7ca0ce45987ca4f5d78e1`.
Biên nhận F không được dùng làm nguồn chuẩn của nhãn hoặc đáp án metric.

## 2. Kết quả theo tiêu chí

| Tiêu chí | Kết quả và giới hạn |
|---|---|
| Tính nguyên vẹn gói | PASS: inventory, SHA-256, kích thước, không thay input |
| Ba scan, manifest, Java và trace | PASS trong các kiểm tra đã chạy; không chạy lại engine |
| Nhãn OWASP | PASS: 16 development = 8 TP/8 FP; 40 held-out = 20 TP/20 FP; không trùng đường dẫn/hash nguồn giữa hai tập |
| Finding → assessment → checkpoint → SQLite | PASS về ID và trường đã kiểm tra; baseline development thiếu checkpoint nên mục đó INCOMPLETE |
| Held-out theo từng alert | PASS: rule/CWE/path/hash, raw/post, decision, citation và latency đối chiếu CSV |
| Latency A/B | INCOMPLETE: số 0.0 của heuristic được gán trong mã, không phải phép đo |
| Nhãn dự án/demo | INCOMPLETE: 16 TP/4 FP là nhãn người lập tập, không phải GT chuẩn đã được Codex xác nhận |
| Lịch sử review | Đọc và kiểm tra được DB/transcript; thiếu hiện vật lần thử stale-source lịch sử |
| Khóa dữ liệu | Hash CRLF khớp khóa public, Git LF cùng nội dung JSON; cấu hình/thời điểm khóa còn INCOMPLETE |
| Tài liệu | FAIL: thời gian dự án/demo, hai giải thích OWASP và phân bố Arm D theo CWE sai |
| Nguồn gốc thực thi | INCOMPLETE: response client không thay original request/model digest/options/code lock |

**71.276 phép đối chiếu** được đếm theo trường, có kiểm tra lặp giữa các bản lưu;
không phải 71.276 alert độc lập. Raw audit có 2 FAIL tự động và 27 thông báo
INCOMPLETE (18 thông báo là các cột thời gian A/B trên ba nhóm). Rà soát thủ công
bổ sung 4 FAIL tài liệu/lý do GT, 4 INCOMPLETE nhãn dự án và 2 PASS luồng OWASP.
[Sổ sai lệch](G0_DISCREPANCY_REGISTER.csv) có **57 hàng: 6 FAIL, 31 INCOMPLETE,
20 PASS**; số hàng không phải số lỗi độc lập. Các hàng PASS ghi phạm vi/số phép
kiểm tra thay vì ngầm coi tất cả mọi thuộc tính đã được xác minh.

### Scan và định danh

| Tập | JSON / SARIF | Java | SHA-256 raw JSON |
|---|---:|---:|---|
| Development | 16 / 16 | 16 | `ecc1fa4634bfc86266c43dd6790422546367293d1810712fddc7c0d15a6c015f` |
| Held-out | 40 / 40 | 40 | `67c3b04903e75f4bd7294cb17452d0dcb2b6d56244330cec485c4422efabfa8b` |
| Dự án/demo | 20 / 20 | 8 | `99d2445c218030fb10082176c299bc328eeb62c6b23c7ab745cffd824f31f041` |

Capture ghi OpenGrep **1.25.0**, exit version/JSON/SARIF đều 0. JSON và SARIF
được sinh bởi hai lệnh cùng capture; không gọi đó là một lần gọi engine duy nhất.
Cả ba snapshot có **9 rule**, SHA-256
`4d12f6deabee1bcf17f1bcce845f05eaf84b312ee13aa6a9cd9721ea879695f9`.
So JSON/SARIF bằng multiset rule ID, path, vị trí và trace, không theo thứ tự.
So line/column/byte offset và nội dung trace trực tiếp với Java đã hash.

Alert ID của schema lịch sử là SHA-256 chuỗi `scan_sha256:finding_index`.
Mã kiểm toán không sửa/sắp lại raw JSON; assessment ghép bằng ID, không theo
thứ tự hàng. Path chỉ chuẩn hóa dấu phân cách hoặc bỏ đúng prefix source root
ghi trong manifest; đường dẫn ngoài root hoặc mapping không đúng bị từ chối.

## 3. Tái tính held-out từ assessments

S/R/U là **post-validator** SUPPORTED/REFUTED/UNDETERMINED. Với Arm A, S chỉ là
quy ước biểu diễn giữ tất cả cảnh báo, không phải phán quyết mô hình.

| Arm | TP S/R/U | FP S/R/U | FP đề xuất loại đúng | TP đề xuất loại nhầm | FP xếp S | U | Coverage | Citation MATCHED |
|---|---|---|---|---|---|---|---|---|
| A | 20/0/0 | 20/0/0 | 0/20 | 0/20 | 20/20 | 0/40 | Không áp dụng mô hình | Không áp dụng |
| B | 9/0/11 | 0/7/13 | **7/20** | 0/20 | 0/20 | 24/40 | 16/40 | 16/40 |
| C | 20/0/0 | 0/20/0 | **20/20** | 0/20 | 0/20 | 0/40 | 40/40 | 40/40 |
| D | 17/0/3 | 14/0/6 | **0/20** | 0/20 | 14/20 | 9/40 | 31/40 | 31/40 |

| Arm | drop_fp: TP/FP giữ | Precision / TP retention recall | keep_tp_only: TP/FP giữ | Precision / TP retention recall | TP bị bỏ khỏi nhóm giữ khi keep_tp_only |
|---|---|---|---|---|---|
| A | 20/20 | 20/40 ; 20/20 | 20/20 | 20/40 ; 20/20 | 0/20 |
| B | 20/13 | 20/33 ; 20/20 | 9/0 | 9/9 ; 9/20 | **11/20** |
| C | 20/0 | 20/20 ; 20/20 | 20/0 | 20/20 ; 20/20 | 0/20 |
| D | 20/20 | 20/40 ; 20/20 | 17/14 | 17/31 ; 17/20 | **3/20** |

`drop_fp` chỉ đề xuất bỏ R; `keep_tp_only` chỉ tính S là giữ, **không phải chính
sách vận hành**. Cả hai là phép tính giả định, không phải người dùng đã đóng
cảnh báo. Recall ở đây là giữ TP trong các cảnh báo đã chọn, không phải recall
phát hiện toàn bộ Benchmark.

Coverage = (S+R)/N; accuracy toàn tập = (TP_S+FP_R)/N; selective accuracy dùng
mẫu số S+R. B/C/D có accuracy lần lượt **16/40, 40/40, 17/40** và selective
accuracy **16/16, 40/40, 17/31**. Citation khớp văn bản không chứng minh kết luận
bảo mật đúng. Mọi tỷ lệ chi tiết theo CWE có tử/mẫu số trong JSON tổng hợp.

| Arm / CWE | TP S/R/U | FP S/R/U |
|---|---|---|
| B / 22 | 4/0/6 | 0/5/5 |
| B / 89 | 5/0/5 | 0/2/8 |
| C / 22 | 10/0/0 | 0/10/0 |
| C / 89 | 10/0/0 | 0/10/0 |
| D / 22 | 7/0/3 | 6/0/4 |
| D / 89 | 10/0/0 | 8/0/2 |

Arm D raw Qwen **40/40 S**, sau hậu kiểm **31 S/9 U**. Đã replay độc lập 9
trích dẫn không khớp nguồn, giữ phân biệt raw quote bị loại với fallback không
còn citation. Trong 9 trường hợp: 3 TP CWE-22, 4 FP CWE-22, 2 FP CWE-89.
Không lấy raw status làm kết quả cuối, không lấy heuristic thay raw Qwen.

Latency tính bằng Decimal từ `elapsed_seconds` thực nhận theo ID. CSV lịch sử
làm tròn đến 0.001 ms; kiểm toán so từng alert tại đúng độ chính xác đó, giữ
giá trị chưa làm tròn trong output riêng. Không biến thiếu latency thành 0.

| Arm | Mẫu đo | Tổng latency từng alert (ms) | Trung bình (ms) |
|---|---|---:|---:|
| A/B | Không có phép đo tương đương theo alert | null | null |
| C | 40/40 | 421000.000 | 10525.000 |
| D | 40/40 | 301062.000 | 7526.550 |

Đây **không phải thời gian wall-clock toàn quy trình**. Các phần dư nhỏ của
số float trong JSON được giữ trong kết quả máy đọc, không coi là sai lệch dữ
liệu khi CSV chỉ công bố ba chữ số thập phân.

## 4. Ground Truth và dự án/demo

Nhãn case OWASP chuẩn khác nhãn finding; kiểm toán còn ghép case với đúng rule,
CWE, nguồn, vị trí và hash finding. Không dùng đáp án Qwen làm GT, không đổi nhãn.
Đã rà soát các câu lệnh luồng dữ liệu liên quan của 56 Java; đây không phải chứng
minh hình thức mọi đường chạy hoặc độ độc lập theo template của tập 16/40.

| Case OWASP | Bằng chứng mã nguồn | Kết luận |
|---|---|---|
| 00863 | Nguồn `getTheValue` dòng 45; helper SeparateClassRequest 53–56 trả hằng. Thing1/Thing2 bảo toàn đối số; sink 51 | Nhãn FP đúng; lý do `external_thing_interface_constant_return` sai cơ chế |
| 01746 | Nguồn hằng dòng 45; helper 94–96: (7×42)−106 = 188, chọn param; sink 66 | Nhãn FP đúng; rationale dùng (7×18)+106 và nhánh true là sai |
| 01752 | Nguồn hằng 45; put keyB dòng 80, get cùng keyB dòng 82; sink 60–61 | FP đúng. Nhãn nhận được không nói rõ keyA; không gán cho nó lời giải thích keyA chưa có căn cứ |
| 00864 | Nguồn hằng 45; list 50–56, remove(0), get(1) lấy hằng; sink 59 | FP đúng; có cả nguồn hằng và lựa chọn phần tử an toàn |

20 cảnh báo dự án/demo có **18 vị trí bắt đầu**, **20 khoảng mã** không tính
rule và **12 nhóm phương thức** theo khai báo gần nhất đã rà soát. Không coi 12
nhóm là 12 lỗ hổng độc lập. UserDao là demo riêng của thầy, không phải dự án thực
tế độc lập. Theo nhãn tác giả 16 TP/4 FP, B/C đều S 20/20 nên **0/4 FP được đề
xuất loại**. Metric này có điều kiện theo nhãn chưa được xác nhận độc lập.

| Nhãn đang tranh luận | Đối chiếu trực tiếp | Phần còn thiếu |
|---|---|---|
| #08/#09 SqlInjectionLesson8 | Escape quote ở 148, concat 154, execute 158; cùng phương thức nhưng hai vị trí/rule | Dialect/driver, nguồn Connection và callers; chưa thể nâng nhãn FP thành chắc chắn |
| #10 UserService | addUser chuyển username tới createLessonsForUser, SQL ở 52 | DTO, controller, @Valid/validator và mọi caller tại đúng commit; annotation được nhắc trong báo cáo chưa chứng minh đã chạy |
| #15 demo UserDao | BASE_DIR dòng 17 có dấu phân cách cuối; canonical-path guard ở 64 trước return 67; tạo File không tự thực hiện I/O | Không có bypass prefix-sibling đơn giản từ đoạn này. File trả về chưa canonical; caller, quyền/symlink filesystem, thời điểm mở và nền tảng chưa đủ để kết luận an toàn toàn luồng |

ID và SHA-256 nguồn chính xác của bốn trường hợp nằm trong CSV/JSON; không đưa
nguyên mã riêng vào repository. Không tự kết luận bốn nhãn là sai hay đổi sang TP.

## 5. Những sai lệch và giới hạn cần xử lý

1. **FAIL tài liệu thời gian:** `E/cases/REAL_PROJECT_EVALUATION.md:55` ghi
   182.00 s / 9.10 s. Raw C dự án/demo tổng 181703 ms, trung bình 9085.15 ms;
   làm tròn hai chữ số là **181.70 s / 9.09 s**. Sửa tài liệu có dẫn nguồn,
   không cần chạy lại model.
2. **FAIL tài liệu Arm D:** `E/metrics/PAIRED_EVALUATION.md:51,57` mô tả FP
   CWE-22 là 4 S/6 U và CWE-89 cả 10 S. Raw/CSV đúng là **6 S/4 U** và **8 S/2 U**.
   Sửa diễn giải, không sửa raw/CSV hoặc chạy lại model.
3. **FAIL lý do nhãn:** hai case 00863/01746 ở trên. Sửa phần giải thích sau khi
   chủ dữ liệu đối chiếu; giữ nhãn chuẩn và dữ liệu gốc, không cần suy luận mới.
4. **INCOMPLETE nhãn thủ công:** cần nguồn/cấu hình nêu ở mục 4. Thiếu đường chạy
   không được thay bằng khẳng định của người tạo nhãn hoặc confidence trong receipt.
5. **INCOMPLETE khóa lịch sử:** hash CRLF labels/alerts khớp khóa public tại
   `86636b9de22e59efcca2d3786434727c6ae082e4`; bản LF Git cùng JSON. Khóa tổng
   `4fb556371eb9eb520aec6df96e4a151685df261025b2893eb7bae51c435bca09`
   tái tính đúng, nhưng `config_file/config_sha256=null`. Không chứng minh đã
   khóa trước chạy hoặc không chọn mẫu sau khi xem kết quả.
6. **INCOMPLETE prompt/runtime:** source code cho thấy C đưa recommended_status,
   recommendation_reason vào prompt; raw Qwen đồng thuận **76/76** ở dev C v2.1,
   held-out C và real C. Đây là pipeline có heuristic hướng dẫn, không phải
   Qwen đơn lẻ đạt 100%. Không có request body lịch sử để xác minh chính xác
   snippet membership hay loại trừ GT leakage qua payload thực gửi.
7. **INCOMPLETE review stale-source:** 10 DB run có 240 cảnh báo OPEN, không
   có event tự đóng. DB demo còn 16 hàng, ba event confirm-false/reopen/confirm-true;
   cuối cùng 15 OPEN/1 CONFIRMED_TRUE. Transcript 13 bước có hide/all/history/reopen,
   nhưng không có lần thử sửa nguồn rồi confirm-false. Actor `ntk-auditor` chỉ là
   chuỗi ghi trong demo, không chứng thực người duyệt. Test âm tổng hợp không
   thay bằng chứng lịch sử lần thử stale-source.

F mới `11_fail_closed_gate_verdict.json` ghi PASS/exit 0. Chỉ đọc sau khi tính
độc lập: C04 kiểm tra nhất quán citation không có nghĩa mọi citation MATCHED;
C06 không đóng được nhãn FP thủ công; C07 nói thử trên DB tạm nhưng DB/log tạm
không có để đọc; C08 prompt dựng lại không chứng thực request gốc. Đồng thuận
76/76 và các trường CSV cùng kiểm tra thì khớp. Không nhận toàn bộ PASS của F.
Không sửa, chạy lại hoặc chứng nhận một bản vá mới của Antigravity/JavisOS.

## 6. Lệnh và hiện vật tái lập

Đã đọc `--help` thật của `recompute.py` và `audit_raw_bundle.py` (exit 0).
Xuất sáu input công khai từ Git đúng commit, tránh PowerShell đổi newline/encoding:

```powershell
$publicDir = Join-Path $env:TEMP ('ntk-public-' + [guid]::NewGuid().ToString('N'))
@'
import pathlib, subprocess, sys
out = pathlib.Path(sys.argv[1]); out.mkdir()
repo = pathlib.Path.cwd().as_posix()
commit = '86636b9de22e59efcca2d3786434727c6ae082e4'
names = ['heldout_strict_lock_manifest.json', 'PROMPT_VERSION_MANIFEST.json',
         'labels_development.json', 'labels_heldout.json', 'heldout_alerts.json', 'dev_alerts.json']
for name in names:
    data = subprocess.run(['git', '-c', 'safe.directory='+repo, 'show',
                           commit+':v2/evaluation/post_report/'+name], check=True, capture_output=True).stdout
    (out/name).write_bytes(data)
'@ | python -X utf8 -B - $publicDir
if ($LASTEXITCODE -ne 0) { throw 'Không xuất được input Git đã ghim' }
$pkg = '<PRIVATE_PATH>
$out = Join-Path $env:TEMP ('ntk-independent-' + [guid]::NewGuid().ToString('N'))
python -X utf8 -B v2/crosscheck/audit_raw_bundle.py --package $pkg --archive-sha256 4664DCDBFC50620CC713CDE20095D6FE3051335EC6C47CC39CD9C6D8BAC1C6BA --public-post-report $publicDir --output $out
$auditExit = $LASTEXITCODE
Write-Output "audit exit=$auditExit; output=$out"
python -X utf8 -B -m unittest discover -s v2/crosscheck -v
```

Lần chạy đã hoàn tất dùng public export
`<PRIVATE_PATH>` và output riêng:
`<PRIVATE_PATH>`.
SHA-256 output riêng:
`40e945a5468f92c70bcf5b3b723f7de7ca1c7d8352e19aac919461d41a1e5f91`.
Giữ tệp này ngoài Git; nếu thư mục tạm bị dọn có thể tái chạy phép đọc từ gói
nguyên vẹn, không chạy lại thực nghiệm. JSON/CSV bàn giao là bản tổng hợp chọn
trường an toàn cộng ghi chú rà soát thủ công; output private là bản máy tính đầy đủ.

Hợp đồng mã thoát của Codex: **0 PASS, 2 FAIL, 3 INCOMPLETE**, FAIL ưu tiên khi
đồng thời thiếu bằng chứng. Raw driver luôn giữ các mục chưa có chứng thực lịch
sử, không có cờ ép PASS. Không dùng hợp đồng exit của JavisOS.

36 unit test PASS, exit 0 (21 cũ + 15 mới). Phản chứng gồm raw scan thiếu/sửa,
JSON sai, rule/vị trí SARIF sai, hoán thứ tự hợp lệ, ID trùng/thiếu/tráo arm,
nhãn/CWE sai, raw/post sai, citation sai nguồn/hash, nguồn thay đổi, citation
đa dòng, mapping sai, latency bị hoán đổi nhưng tổng không đổi, SQLite state/event
mâu thuẫn, stale confirm-false và thiếu dữ liệu dù receipt cố ghi PASS.

Đã sửa hai điểm trong chính auditor: so latency ở độ chính xác CSV công bố,
và phân biệt citation raw bị bác bỏ với citation rỗng của fallback. Không sửa
assessment để khớp test. Test dùng fixture tổng hợp, không phải suy luận thật.

## 7. Bàn giao và điều kiện còn thiếu

Mã/tài liệu chỉ trong `v2/crosscheck/`: `audit_raw_bundle.py`, `test_raw_bundle.py`,
`owasp_reference_blobs.json`, cập nhật `recompute.py`, README/FINDINGS/
TRANSFER_REQUEST và ba hiện vật G0. Giữ bộ test/bảng public cũ để truy vết.
Không thêm raw response, SQLite, source riêng, ZIP của thầy hoặc model vào Git.

Để nghiệm thu: xử lý sáu dòng FAIL có nguồn; đối chiếu bốn nhãn thủ công;
bổ sung hoặc thừa nhận NOT_RECORDED cho request/config/code/model lock, khóa
trước thực nghiệm và demo stale-source lịch sử. Xem
[TRANSFER_REQUEST.md](TRANSFER_REQUEST.md) cho đường dẫn và mục đích từng input.
Chỉ chứng nhận phần đã kiểm tra, không kết luận hoàn thành toàn hệ thống.

HEAD khi kiểm toán: `8db7dafae6c4abc99ca8a78e9b2e83a0e0b9f204`.
**Chưa commit/push.** Đã kiểm tra HEAD/status/worktree/branch và không thấy process
Git đang chạy. `git switch v2/codex-core` thất bại exit **128** khi tạo
`integration/.git/worktrees/codex/index.lock: Permission denied`. Không xóa lock,
đổi ACL hoặc vượt sandbox. Branch vẫn `v2/advisor-m1-proof-20261111` đã mất remote;
18 tệp crosscheck đều chưa được Git theo dõi, không có sửa đổi tracked bên ngoài.
Worktree Antigravity đang ở commit khác; không thay đổi hoặc tuyên bố đã kiểm tra
bản vá mới của họ trong lần kiểm toán dữ liệu này.

Kiểm tra cuối: compile 4 module, so hash code/evidence/báo cáo, 57 hàng CSV khớp
JSON, metric tổng hợp khớp output private, UTF-8 và liên kết tương đối: **PASS,
exit 0**. `git diff --check`: exit **0**, nhưng không bao phủ file untracked;
đã kiểm tra thêm whitespace trực tiếp trên mọi tệp crosscheck: PASS.
Không có `.sqlite`, `.java`, `.zip`, `.gz` hoặc raw `.jsonl` trong thư mục bàn giao.

Lệnh bàn giao PowerShell ngoài sandbox, tại worktree Codex; dừng nếu bất kỳ
bước bảo vệ nào lỗi. Local codex-core hiện cũ hơn origin, nên cần fast-forward
trước commit; không reset/force hoặc chuyển worktree của agent khác:

```powershell
$r=(Get-Location).Path.Replace('\','/')
git -c "safe.directory=$r" status --short --branch
git -c "safe.directory=$r" diff --cached --quiet
if ($LASTEXITCODE -ne 0) { throw 'Index có thay đổi khác: kiểm tra trước khi tiếp tục' }
git -c "safe.directory=$r" diff --quiet
if ($LASTEXITCODE -ne 0) { throw 'Có sửa đổi tracked cần bảo toàn' }
git -c "safe.directory=$r" switch v2/codex-core
if ($LASTEXITCODE -ne 0) { throw 'Không chuyển được nhánh; không xóa lock hoặc ép checkout' }
git -c "safe.directory=$r" merge --ff-only origin/v2/codex-core
if ($LASTEXITCODE -ne 0) { throw 'Không fast-forward được; dừng để đối chiếu' }
$branch = git -c "safe.directory=$r" branch --show-current
if ($LASTEXITCODE -ne 0 -or $branch -ne 'v2/codex-core') { throw 'Sai nhánh' }
$files = @(
  'v2/crosscheck/.gitignore', 'v2/crosscheck/README.md',
  'v2/crosscheck/FINDINGS.md', 'v2/crosscheck/TRANSFER_REQUEST.md',
  'v2/crosscheck/recompute.py', 'v2/crosscheck/test_recompute.py',
  'v2/crosscheck/audit_raw_bundle.py', 'v2/crosscheck/test_raw_bundle.py',
  'v2/crosscheck/owasp_reference_blobs.json',
  'v2/crosscheck/G0_RAW_INDEPENDENT_VERDICT.md',
  'v2/crosscheck/G0_RAW_INDEPENDENT_VERDICT.json',
  'v2/crosscheck/G0_DISCREPANCY_REGISTER.csv',
  'v2/crosscheck/results/discrepancies.csv',
  'v2/crosscheck/results/ground_truth_56.csv',
  'v2/crosscheck/results/interpretation_discrepancies.csv',
  'v2/crosscheck/results/published_metrics.json',
  'v2/crosscheck/results/published_per_alert.csv',
  'v2/crosscheck/results/status_transitions.csv'
)
git -c "safe.directory=$r" add -- $files
if ($LASTEXITCODE -ne 0) { throw 'Không stage được; không thay quyền' }
$staged = @(git -c "safe.directory=$r" diff --cached --name-only)
if ($LASTEXITCODE -ne 0 -or @($staged | Where-Object { $_ -notin $files }).Count -gt 0) {
  throw 'Index có tệp ngoài danh sách bàn giao'
}
git -c "safe.directory=$r" diff --cached --check
if ($LASTEXITCODE -ne 0) { throw 'Diff không đạt kiểm tra' }
git -c "safe.directory=$r" diff --cached --stat
# Kiểm tra danh sách trên trước khi thực hiện hai lệnh cuối.
git -c "safe.directory=$r" commit -m 'Tái tính từ dữ liệu thô và đối chiếu độc lập nhãn cảnh báo'
if ($LASTEXITCODE -ne 0) { throw 'Commit thất bại' }
git -c "safe.directory=$r" push origin v2/codex-core
```

Không thực thi các lệnh add/commit/push trên nhánh cũ. Báo cáo giữ HEAD kiểm
toán và hash code để truy vết; SHA commit mới chỉ có sau khi chủ workspace commit.
