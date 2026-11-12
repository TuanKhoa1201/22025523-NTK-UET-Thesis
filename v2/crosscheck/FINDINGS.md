# Đối chiếu hiện vật và phần còn thiếu

## Cập nhật ngày 13/11/2026 — đã nhận dữ liệu thô

Kết luận hiện tại nằm trong [G0_RAW_INDEPENDENT_VERDICT.md](G0_RAW_INDEPENDENT_VERDICT.md).
Phần bên dưới giữ nguyên hồ sơ kiểm tra công khai ngày 12/11, **không phải trạng
thái tiếp nhận dữ liệu hiện tại**. Các thông tin mới thay thế những hạn chế cũ:

- Đã đọc và xác minh 289 tệp; ba scan 16/40/20, 240 assessments, 6 checkpoint
  với 148 bản ghi và 11 SQLite. 71.276 phép đối chiếu tự động; không phải 71.276
  cảnh báo hay phép thử độc lập. 36 unit test PASS.
- Đã tái tính B 7/20 FP, C 20/20 FP, D raw 40 S → post 31 S/9 U và latency
  từng alert. Hai số thời gian dự án/demo trong Markdown không khớp raw.
- Hash CRLF của labels/alerts nhận được khớp khóa công khai; bản Git LF có cùng
  nội dung JSON. Không còn coi chênh lệch newline này là bằng chứng mất dữ liệu.
  Thời điểm khóa và đầy đủ cấu hình lịch sử vẫn chưa được xác minh.
- Đã tự tính đồng thuận raw Qwen–heuristic 76/76 cho ba run C cuối được chọn.
  20 alert dự án/demo có 18 vị trí bắt đầu, 20 khoảng mã và 12 nhóm phương thức;
  không có căn cứ gọi chúng là 20 hoặc 12 lỗ hổng độc lập.
- Nhận biên nhận mới `server_forensic_audit_failclosed_20261112` để đối chiếu sau
  khi tính độc lập. PASS của biên nhận không thay thế raw hoặc đóng nhãn thủ công.
- Riêng BenchmarkTest01752, nhãn trong gói nói chung về neutralized/overwritten;
  không đủ căn cứ gán lời giải thích sai `keyA` cho chính nhãn đã nhận. Mã lấy
  `keyB` chứa param, an toàn nhờ nguồn hằng. Hai giải thích sai xác định được
  trong nhãn nhận là BenchmarkTest00863 và BenchmarkTest01746; giữ nguyên GT.
- UserDao #15 có dấu phân cách cuối BASE_DIR và kiểm tra trước return. Không
  kết luận lỗi prefix-sibling đơn giản; còn thiếu caller và điều kiện filesystem.

## Hồ sơ công khai ngày 12/11/2026 — giữ để truy vết

Trạng thái: **INCOMPLETE**, không nghiệm thu toàn bộ hệ thống hay raw runtime.
Ngày 12/11/2026. Kết quả công khai tại `86636b9`; đối chiếu nguồn OWASP commit
`8b67a88d73b2594570fc21150705283de884620b` và expectedresults CSV có SHA-256
`1809f6a690c6cf7dd6685df6ebe2eef8fe3ca93d19a7ca0ce45987ca4f5d78e1`.

## Số liệu tái tính từ CSV, không phải raw Ollama

| Arm | TP S/R/U | FP S/R/U | FP đề xuất loại đúng | TP đề xuất loại nhầm | Drop_fp precision / TP retention | Keep_tp_only precision / TP retention | Latency tổng / trung bình ms |
|---|---|---|---|---|---|---|---|
| A | 20/0/0 | 20/0/0 | 0/20 | 0/20 | 20/40; 20/20 | 20/40; 20/20 | Không đo ở bảng này |
| B | 9/0/11 | 0/7/13 | 7/20 | 0/20 | 20/33; 20/20 | 9/9; 9/20 | Không có thời gian đo độc lập |
| C | 20/0/0 | 0/20/0 | 20/20 | 0/20 | 20/20; 20/20 | 20/20; 20/20 | 421000 / 10525 |
| D | 17/0/3 | 14/0/6 | 0/20 | 0/20 | 20/40; 20/20 | 17/31; 17/20 | 301062 / 7526.55 |

S/R/U là post-validator; raw D trong CSV là SUPPORTED 40/40. Chi tiết từng CWE
và tử/mẫu số tại JSON kết quả. Không dùng các giá trị bảng này làm đáp án trong script.
Mọi hàng C vẫn OPEN, không có bằng chứng con người đã xác nhận các REFUTED là giả.

## Bổ sung kiểm tra bộ tái tính ngày 12/11/2026

Chỉ thay đổi `v2/crosscheck/`. Không chạy lại engine/model, không sửa nhãn,
không sửa auditor JavisOS và không kiểm tra một commit mới của họ trong đợt này.

- Chạy lại 13 bài cũ: PASS, exit 0. Bổ sung 8 bài: tổng 21 PASS, exit 0.
  Test mới có subprocess CLI thực tế, kiểm tra missing input → 3, JSON/decision/
  latency sai → 2, ưu tiên FAIL khi đồng thời thiếu bằng chứng, chống ghi đè output,
  tỷ lệ/latency bảng tổng hợp bị sửa và tách raw/post. Đây đều là test tổng hợp.
- Tái tính public: **INCOMPLETE, exit 3**, 1442 phép đối chiếu; gồm 304 phép so
  bảng tổng hợp. Không có mismatch trong phạm vi đó. Bản trước có 858 phép;
  con số tăng do kiểm tra thêm trường CSV và aggregate, không phải thêm dữ liệu.
- 19 thông báo thiếu ở output gồm raw runtime chưa có và 18 trường mean/p50/p95
  của A/B trên ba nhóm không có mẫu thời gian để xác minh. Không biến số 0.0 của
  bảng tổng hợp thành phép đo. Những khoảng trống ngữ nghĩa/lịch sử bên dưới cũng
  chưa được đóng; số 19 không phải tổng số mọi vấn đề nghiên cứu còn lại.
- Cùng 56 nhãn/nguồn public, 40 alert và 160 hàng dẫn xuất A/B/C/D. Input SHA-256
  ghi trong `results/published_metrics.json`; không đưa raw server vào thư mục này.

Lệnh đã chạy (PowerShell; output mới ở mỗi lần):

```powershell
python -X utf8 -B -m unittest discover -s v2/crosscheck -v
$cache = Join-Path $env:TEMP 'ntk-crosscheck-7dda28aa9ef94c7d9b787fef77b8374d'
$out = Join-Path $env:TEMP ('ntk-crosscheck-' + [guid]::NewGuid().ToString('N'))
python -X utf8 -B v2/crosscheck/recompute.py --published "$cache/v2/evaluation/post_report" --expectedresults "$cache/owasp_csv.txt" --owasp-sources "$cache/owasp" --reference-commit 86636b9de22e59efcca2d3786434727c6ae082e4 --output $out
$auditExit = $LASTEXITCODE
Write-Output "AUDIT_EXIT=$auditExit"
```

Cache chứa bản đọc công khai từ commit đã ghim, **không phải thư mục raw trên
ADMIN-PC**. Trên máy khác, thay ba input bằng bản checkout/download cùng commit,
kiểm tra hash ghi trong kết quả trước khi đối chiếu. Không chuẩn hóa byte input.
Output thật của lần chạy hoàn thiện:
`<PRIVATE_PATH>`.
Các bảng nhỏ được xuất tự động rồi chép sang `results/`; `audit.json` không vào Git.
Log unittest nằm cạnh đó ở `unit-tests.txt` (21 tests, OK, mã thoát native 0).
`compile()` cho hai tệp Python, kiểm tra whitespace của mọi tệp mã/tài liệu mới
và kiểm tra số hàng dẫn xuất: PASS, exit 0. `git diff --check`: exit 0; vì thư mục
còn untracked nên phép này không thay kiểm tra whitespace riêng vừa nêu.

### Heuristic 7/20 và các mẫu số

Arm B đúng là **7 FP được đề xuất loại / 20 FP**, gồm 5/10 CWE-22 và 2/10 CWE-89.
Không phải loại 7/20 cảnh báo tổng cộng và không phải bảy quyết định của người dùng.
Drop_fp giữ 20 TP + 13 FP → precision 20/33, TP retention 20/20.
Keep_tp_only giữ 9 TP + 0 FP → precision 9/9 nhưng bỏ khỏi nhóm giữ **11/20 TP**
chưa xác định. Arm D tương ứng loại khỏi nhóm giữ 3/20 TP ở keep_tp_only, dù
TP bị đề xuất REFUTED là 0/20. Với drop_fp, cả bốn arm đề xuất loại nhầm TP 0/20
theo CSV hiện có; chưa chứng thực từ assessment thô.

Arm B không phải toàn bộ tín hiệu heuristic được đưa vào C: tại commit `86636b9`,
`v2/triage/heuristics.py:590–619` chủ động trả UNDETERMINED cho một số dạng flow
trong chế độ B; `v2/triage/ollama.py:157–175` đưa evidence_signals và candidate_citations
vào prompt C. Không lấy chênh lệch 7/20 → 20/20 làm hiệu quả riêng Qwen. Con số
đồng thuận 76/76 vẫn chưa được Codex tái tính từ raw.

### Raw khác post: số liệu và sai lệch tài liệu

Nguồn dưới đây đều tại commit `86636b9de22e59efcca2d3786434727c6ae082e4`:

| Nội dung | Kết quả từ từng hàng CSV | Đối chiếu / tác động |
|---|---|---|
| Arm C | Raw và post đều 20 SUPPORTED + 20 REFUTED, không hàng đổi | CSV không chứng minh request/response hoặc citation thật; 40 human state là OPEN |
| Arm D | Raw 40 SUPPORTED; post suy từ decision: 31 SUPPORTED + 9 UNDETERMINED | Không gán 9 UNDETERMINED cho raw Qwen; cần response và validator để xác nhận lý do |
| D, FP CWE-22 | 6 SUPPORTED / 4 UNDETERMINED | `PAIRED_EVALUATION.md:51` viết 4/6, đảo số; cần sửa lời kể, không sửa dữ liệu |
| D, FP CWE-89 | 8 SUPPORTED / 2 UNDETERMINED | `PAIRED_EVALUATION.md:57` viết cả 10 SUPPORTED; không khớp post và dùng lẫn raw/post |
| Citation B | 16/40 trên mọi alert; 16/16 trên nhóm có kết luận | `EVALUATION_METHOD.md:64` dùng mẫu số có kết luận; `METRICS_BY_CWE.csv:5` dùng toàn tập |
| Citation D | 31/40 trên mọi alert; 31/31 trên nhóm có kết luận | Không dùng hai tỷ lệ này thay nhau hoặc coi tỷ lệ khớp là độ đúng bảo mật |

9 chuyển trạng thái D gồm 3 TP CWE-22, 4 FP CWE-22, 2 FP CWE-89. Danh sách ID,
tên Java, raw/post và latency ở `results/status_transitions.csv`. Không suy ra
nguyên nhân thiếu dấu chấm phẩy/lệch dòng chỉ từ cột NOT_VERIFIED. Diễn giải nguyên
nhân trong `UNDETERMINED_ANALYSIS.md` còn cần raw quote và thông báo validator.

Coverage B/C/D lần lượt 16/40, 40/40, 31/40. Accuracy toàn tập lần lượt 16/40,
40/40, 17/40; selective accuracy là 16/16, 40/40, 17/31. Đây là tỷ lệ trên alert
đã chọn, không phải độ phát hiện trên toàn Benchmark. Tổng latency C/D là tổng
40 quan sát trong CSV, chưa đối chiếu đồng hồ/client/raw response trên máy chủ.

### Những phép kiểm tra vẫn INCOMPLETE

1. Raw OpenGrep/manifest/source/rules tại lượt scan; ID và đường dẫn Windows/WSL.
2. Assessment B/C/D, checkpoint, raw JSON model, hậu kiểm và latency từng alert.
3. Citation có thật trong request lịch sử, tính đúng ngữ nghĩa source–sink/guard.
4. Runtime Ollama/model/options và thời gian wall-clock; không chỉ lời khai model.
5. SQLite human state/history, confirm-false và stale-source từ bằng chứng máy chủ.
6. Khóa lịch sử raw/LF, cấu hình/prompt/heuristic lúc chạy; không lập khóa hồi tố.
7. Raw development/real-project: đồng thuận 76/76, 20 alert trùng sink, 4 nhãn FP
   thủ công. Kiểm tra nhãn test case công khai không thay cho kiểm tra mỗi finding.
8. Đối chiếu bản sửa/biên nhận mới của JavisOS/Antigravity khi họ bàn giao. Những
   commit được đọc ở các mục dưới là bản trước, không phải xác nhận trạng thái mới.

Input cụ thể, đường dẫn E/W/F và yêu cầu bảo mật có trong `TRANSFER_REQUEST.md`.
Không có phép kiểm toán raw nào được nâng PASS vì test của bộ tái tính đã PASS.

## Ground Truth

16 development và 40 held-out: nhãn/CWE khớp OWASP; 56 hash Java khớp nguồn ghim,
không giao tập theo tên tệp hoặc hash nguồn. Bảng 56 hàng lưu riêng. Các dòng sink
có tồn tại; việc chứng minh luồng cho toàn bộ 56 finding chưa được tự động suy ra
từ nhãn test case. Raw scan/trace vẫn cần đối chiếu.

Đọc trực tiếp bốn Java và helper `SeparateClassRequest.java` tại commit OWASP:

| Ca | Bằng chứng Java | Kết luận độc lập |
|---|---|---|
| BenchmarkTest01746 | Dòng 45 gọi getTheValue, helper trả "bar". Dòng 94 num=106; dòng 96: (7*42)-106=188, không >200, nên chọn param. Sink File dòng 66. | FP đúng theo OWASP, nhưng lời giải thích chọn nhánh hằng của toán tử ba ngôi là sai. An toàn bắt nguồn từ source hằng. |
| BenchmarkTest00863 | Dòng 45 nguồn hằng; 47–49 ThingFactory/thing.doSomething(param); File dòng 51. | Không được khẳng định ThingInterface tự trả hằng chỉ từ interface/call site. Lý do nguồn hằng bị mô tả sai thành cơ chế helper. Không đổi nhãn OWASP. |
| BenchmarkTest01752 | Dòng 45 nguồn hằng; 80 đưa param vào keyB-11351; 82 lấy đúng keyB, sink FileInputStream dòng 61. | Không phải lấy khóa keyA an toàn. Nhãn FP vẫn đúng; param đã hằng từ nguồn. |
| BenchmarkTest00864 | Dòng 45 nguồn hằng; list 50–52: safe,param,moresafe; remove(0) ở 54; get(1) ở 56 chọn moresafe; File dòng 59. | Có cả nguồn hằng và lựa chọn phần tử an toàn. Mô tả chỉ một cơ chế là thiếu, không sai nhãn. |

Không dùng ground_truth_verifier.py của Javis Brain. Chưa chứng minh 56 phép
kiểm tra sink/flow/guard thủ công đầy đủ hoặc tính độc lập theo template.

## Antigravity

Commit đã đọc: `8a5645e4f19fa77720b98ad5758e16b15d7b0c9c`.
`independent_audit.py` là bộ kiểm toán mới; đã chạy `test_independent_audit.py`:
16 test PASS, exit 0, trên bản sao tạm có các input public.
Các blob heuristics.py, ollama.py, java_context.py, evidence.py, store.py vẫn
giống `86636b9`; không có patch sản xuất để xác nhận đã sửa các phản ví dụ.
Không đóng lỗi parseInt không liên quan, ghi đè có điều kiện, getTheValue tùy ý,
canonicalPath/startsWith, citation ngoài prompt hoặc comment/blank.
Test auditor PASS không phải test model PASS. Chưa chạy lại toàn bộ audit raw.

## JavisOS

Commit đã đọc: `e81c75681605034449820f5eb3fe7db9c2b4fcfc`.
Biên nhận summary được đọc như lời khai có nguồn, không phải raw đối chứng.
`audit_server_forensic_receipt.py:1416–1436` so CSV chỉ kiểm tra số hàng,
ID và bốn trường trạng thái. Chưa so đủ CWE/rule/path/source hash, citation,
latency từng alert và decision D ở vòng này. Vì vậy tuyên bố 0 mismatch chỉ có
nghĩa trong tập trường hạn chế đó.
Hàm main ở dòng 1934–1947 xuất AUDIT_COMPLETED rồi return 0, không tổng hợp lỗi
đã phát hiện thành exit FAIL/INCOMPLETE. Cần thêm cổng tổng hợp và phản chứng hash
sai/CSV latency sai nhưng vẫn chạy tới cuối. Không suy luận exit 0 = nghiệm thu.
Pytest runner chưa chạy: Python mặc định laptop thiếu pytest (No module named pytest).
Sau đó dùng Python 3.12 trong venv đã có PyYAML, gọi trực tiếp 7 hàm test nguyên bản
bằng harness stdlib (cấp TemporaryDirectory cho tmp_path): 7 PASS, exit 0.
Đây không phải kết quả pytest và chưa phải phản chứng cổng main/exit; 7 test hiện
chỉ phủ helpers, metrics và immutability, không đóng khoảng trống acceptance gate.
Không sửa mã JavisOS hoặc cài hạ tầng thay họ.

## Các vấn đề chưa đóng

- Nghiêm trọng: heuristic có thể đề xuất loại TP từ sanitizer/ghi đè không ràng buộc luồng.
- Nghiêm trọng về tái lập: khóa CRLF không khớp JSON LF trong Git. Giữ khóa lịch sử;
  cần receipt raw/LF riêng, không lập khóa mới rồi nói đã có từ trước.
- Chưa khóa đủ prompt/code/options/rules và chưa có request thô: NOT_VERIFIED.
- Arm C truyền recommended_status/recommendation_reason/candidate_citations.
  Chưa tự kiểm chứng con số đồng thuận 76/76 từ raw. Không kết luận riêng Qwen 100%.
- Dự án/demo: 20 alert theo báo cáo, có trùng sink; 12 locus là số Javis báo,
  chưa được tự tính từ raw. UserDao là demo của thầy, không là dự án thực tế độc lập.
- Hai FP SqlInjectionLesson8 do thay dấu quote: phụ thuộc SQL dialect/đường chạy;
  UserService @Pattern cần xác minh DTO, @Valid và mọi caller, không chỉ annotation;
  UserDao canonicalPath+String.startsWith cần kiểm tra directory boundary và guard.
  Bốn nhãn FP thủ công chưa được Codex nghiệm thu; không nâng thành chắc chắn theo
  confidence trong biên nhận. Với nhãn công bố, FP đề xuất loại đúng vẫn là 0/4.
- Tài liệu: 14 rules thay vì 9; hash dev và expectedresults sai trong một số báo cáo;
  diễn giải Arm D theo CWE khác CSV. Không sửa dữ liệu để khớp lời kể.

## Git và bàn giao

Ở lần kiểm tra đầu tiên trước khi tạo bộ này, worktree sạch tại `8db7daf`;
remote codex-core khi đó cũng cùng SHA. Lần tiếp tục hiện tại đã thấy `?? v2/crosscheck/`.
Remote nhánh cũ đã xóa; local vẫn đang nhánh cũ vì switch bị chặn index.lock.
Không thấy tiến trình Git hoạt động; không xóa lock/đổi ACL/reset/tạo remote branch.
Lần tiếp tục chỉ đọc branch/HEAD/status, không thử sửa metadata lần nữa. HEAD vẫn
`8db7dafae6c4abc99ca8a78e9b2e83a0e0b9f204`; chưa có commit/push cho bộ crosscheck.
Chỉ thêm thư mục riêng v2/crosscheck, chưa commit/push. Chủ workspace phải chuyển
về codex-core trong PowerShell ngoài sandbox rồi kiểm tra và commit đúng các tệp mới:

```powershell
$r=(Get-Location).Path.Replace('\','/')
git -c "safe.directory=$r" switch v2/codex-core
if ($LASTEXITCODE -ne 0) { throw 'Không chuyển được nhánh' }
git -c "safe.directory=$r" status --short --branch
git -c "safe.directory=$r" add -- v2/crosscheck
if ($LASTEXITCODE -ne 0) { throw 'Không stage được' }
git -c "safe.directory=$r" diff --cached --check
if ($LASTEXITCODE -ne 0) { throw 'Lỗi kiểm tra diff' }
git -c "safe.directory=$r" diff --cached --stat
git -c "safe.directory=$r" commit -m "Đối chiếu kết quả phân loại từng cảnh báo và xác minh nhãn OWASP"
if ($LASTEXITCODE -ne 0) { throw 'Commit thất bại' }
git -c "safe.directory=$r" push origin v2/codex-core
```
