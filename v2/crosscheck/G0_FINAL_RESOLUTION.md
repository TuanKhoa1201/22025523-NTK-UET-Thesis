# Current G0 disposition ? 2026-11-13

AUDIT_EXECUTION_COMPLETED=true; G0_ACCEPTANCE=CONDITIONAL; READY_FOR_G1=CONDITIONAL.

This derived disposition supersedes earlier acceptance prose only. Historical raw audit FAIL (exit 2), missing evidence and original registers remain intact. Execution completion means required sections have recorded receipts and limitations; it does not attest missing historical data. No mandatory core failure is waived. Errata require exact expected/actual, alert, source hash and named entry; all approvals remain PENDING.

Reproduce: `python -X utf8 -B v2/crosscheck/finalize_public.py`. Inputs are the published raw verdict receipt, paired comparison in resolution JSON and G0_ERRATA_REGISTER.json. This command derives the three states; exit 0 only means successful execution. Raw recalculation still requires the private package. PASS requires all mandatory checks and no pending limitations; BLOCKED covers mandatory failure/missing core run; INCOMPLETE covers insufficient execution receipts; CONDITIONAL covers core completion with disclosed historical limits awaiting approval.

Five historical INCOMPLETE items remain unchanged. A/B latency is unmeasured. Manual 20 labels are not independent GT; #10 needs label review. Historical prompt, checkpoint/config, pre-run lock timing and stale-source attempt remain unattested. Qwen contribution remains CONFOUNDED; independent improvement over OpenGrep-only is not demonstrated.

The original Antigravity patch was reviewed and not applied verbatim: a field-name allowlist and absence of UNRESOLVED_FAIL cannot establish evidence-specific errata or execution completion. Existing per-alert audit logic was retained and tested with compensating mutations.

## Historical resolution text (retained for context; current contract above governs)

# Chốt đối chiếu G0 — 13/11/2026

**G0_AUDIT_COMPLETED = true; G0_ACCEPTANCE = CONDITIONAL; READY_FOR_G1 = CONDITIONAL.**
Đây là đề xuất bàn giao có điều kiện để người hướng dẫn quyết định, không phải
chứng nhận mọi bằng chứng lịch sử hoặc chất lượng Qwen. Không chạy thêm engine,
model, benchmark hay triển khai G1. Đã phân loại toàn bộ vấn đề trong phạm vi;
không mở vòng kiểm toán tiếp theo.

## Phán quyết năm trục

| Trục | Kết luận | Giới hạn phải giữ |
|---|---|---|
| DATA_INTEGRITY | PASS trong gói đã nhận: 289/289 hash, ba scan, nguồn, trace, SQLite và liên kết alert nhất quán | Không chứng thực bên ngoài tiến trình lịch sử hoặc thời điểm khóa trước run |
| METRIC_RECOMPUTATION | PASS cho phân loại A/B/C/D và thời gian đã đo C/D, theo từng ID và tổng | A/B latency NOT_MEASURED; tổng từng alert không phải wall-clock |
| GROUND_TRUTH_ATTESTATION | 56 nhãn OWASP/CWE khớp nguồn chuẩn; đính chính giải thích, không đổi nhãn | 20 nhãn dự án/demo không phải GT chuẩn độc lập; #08/#09/#15 CONDITIONAL, #10 LABEL_REVIEW_REQUIRED |
| LLM_CONTRIBUTION | CONFOUNDED | Raw C đồng thuận heuristic 76/76; không quy kết 100% cho Qwen đơn lẻ |
| G1_READINESS | CONDITIONAL | Người hướng dẫn chấp nhận errata, loại nhãn chưa chứng thực khỏi kết luận chuẩn, công bố biến nhiễu và giới hạn lịch sử trước khi duyệt nghiên cứu mới |

Không có sai lệch chưa giải quyết trong giá trị nhãn chuẩn OWASP hoặc các metric
held-out bắt buộc có dữ liệu đo. Nhãn #10 chặn việc coi 20 nhãn thủ công là ground
truth đã kiểm chứng; nó không phủ định phép tái tính trên 40 OWASP. Thiếu prompt,
config và dấu thời gian khóa chặn tuyên bố tái lập nguyên vẹn phiên suy luận,
nhưng không chặn đối chiếu các bản ghi đã lưu. Không cần chứng minh Qwen cải thiện
hiệu năng để hoàn tất G0. Mọi thí nghiệm G1/G3 tương lai là dữ liệu mới, không
được dùng thay thế hiện vật thiếu của phiên lịch sử.

## Đầu vào, bảo toàn và phiên bản

- HEAD Codex: `8db7dafae6c4abc99ca8a78e9b2e83a0e0b9f204`; local vẫn ở
  `v2/advisor-m1-proof-20261111` đã mất remote. Nhánh đích duy nhất: `v2/codex-core`.
- Commit thực nghiệm: `86636b9de22e59efcca2d3786434727c6ae082e4`.
- OWASP: `8b67a88d73b2594570fc21150705283de884620b`; đối chiếu blob 56 Java
  và CSV chuẩn, không dùng nhãn LLM. CSV chuẩn SHA-256:
  `1809f6a690c6cf7dd6685df6ebe2eef8fe3ca93d19a7ca0ce45987ca4f5d78e1`.
- Peer đọc để đối chiếu: JavisOS `bf19b5e1392645baba55e5039ebc0d71a1af9aaa`.
  Không dùng PASS của peer làm đáp án. Không chứng nhận lại các bản vá Antigravity.
- Backup và workspace **18/18 tệp khớp byte** trước sửa. Giữ nguyên toàn bộ 18
  tệp đó; thêm hai module kiểm toán/bảy test và bốn sản phẩm bàn giao.
- Archive SHA-256:
  `4664dcdbfc50620cc713cde20095d6fe3051335ec6c47cc39cd9c6d8bac1c6ba`.
- Alias **E**: `extracted/evidence/post_report_cwe22_cwe89_20261112` (263 tệp);
  **F**: `extracted/evidence/server_forensic_audit_failclosed_20261112` (26 tệp).
  Gói được đặt ngoài repository. Không công bố đường dẫn tài khoản cá nhân.
- `G0_DISCREPANCY_REGISTER.csv` gốc được giữ nguyên, SHA-256:
  `be5805484279375a66f8a0dcd6ff66fae8be75bf4a1b19b8eba32597da4bd679`.

Raw đủ cho ba scan 16/40/20, 240 assessments, 148 dòng trong sáu checkpoint,
11 DB gồm demo, 64 Java. Tính lại 71.276 phép so trường từ gói bất biến; đây
không phải số alert độc lập. Output riêng mới vẫn FAIL/exit 2: hai con số thời
gian tài liệu sai, 27 thông báo thiếu. Không chỉnh raw để đổi mã thoát.

## Xử lý register

Register gốc: **6 FAIL, 31 INCOMPLETE, 20 PASS**. Register mới có 65 hàng:
57 hàng truy vết cũ cùng 8 hàng đối chiếu bổ sung trong phạm vi được yêu cầu.

| Sau phân loại | Số hàng | Ý nghĩa |
|---|---:|---|
| ERRATA_ISSUED | 14 | Sáu FAIL cũ + bảy cơ chế Java còn lại + một hash sai trong tài liệu peer; không đổi FAIL lịch sử thành PASS |
| PASS | 20 | Giữ phạm vi cũ |
| NOT_MEASURED | 19 | 18 cột A/B mean/p50/p95 và một giới hạn thời gian tổng quát; không có mẫu đo |
| REFERENCE_AVAILABLE_LIMITED | 2 | Có lock/prompt manifest trong Git, không có chứng thực phiên chạy |
| PROMPT_NOT_ATTESTED | 1 | Không có payload nguyên văn lịch sử |
| CONDITIONAL | 3 | Nhãn #08/#09/#15 |
| LABEL_REVIEW_REQUIRED | 1 | Nhãn #10 |
| INCOMPLETE | 5 | Checkpoint baseline; demo stale-source lịch sử; config lock null; thời điểm khóa; GT thủ công tổng thể |

31 hàng chưa đủ chứng cứ được phân loại lại, **không có hàng nào được nâng lên
PASS/N/A**. Năm INCOMPLETE còn nguyên nhân cụ thể trong register. `--checkpoint`
là optional trong CLI commit 86636b9; không có argv baseline nên không kết luận
N/A. Các thiếu sót lịch sử không thể phục dựng thành bằng chứng gốc.

Đã xử lý sáu sai lệch xác định được bằng errata có nguồn: 182.00/9.10 giây thành
181.70/9.09 giây; cơ chế 00863/01746; Arm D FP CWE-22 là 6 S/4 U, CWE-89 là
8 S/2 U. Giữ nguyên GT và raw. Xem [G0_ERRATA.md](G0_ERRATA.md).

Chín case Java được đọc lại: 00863, 01746, 01752, 00864, 00062, 01006, 01156,
00949, 00950. Đặc biệt **00949/00950 không có toán tử ba ngôi**: helper chỉ
gán rồi trả param. Nhận định ngược trong bàn giao JavisOS bị bác bỏ bằng mã
nguồn ghim. Với 01752, nguồn đã hằng và map lấy lại keyB; nhãn nhận không nói keyA.
Ba case map chỉ thiếu mô tả bước trung gian, không sai nhãn TP.

## Bảng bắt cặp và metric

Raw E, Git 86636b9 và CSV trên nhánh JavisOS bf19b5e khớp byte:
**34.388 byte**, UTF-8 không BOM, LF, SHA-256
`e19fc5140be6548eca8d62cb7c01f02baa96f4a493753015a7596c9616453347`.
Hash input đã ghi trong kết quả public Codex cũng đúng hash này. Đã so 40 alert
× 27 cột; Git blob peer `9cb4e96e67e235cd828070cc7596e6ceb5ac16ad` xác nhận
byte tải về. Hash `e19fc514e04d...` và 35.627 byte trong văn xuôi bàn giao peer
không khớp; không có bản byte tương ứng để kết luận nguồn gốc lỗi. Không gọi đó
là chênh newline giữa các bản đã đọc. Đây là đính chính tài liệu, không sửa CSV.

| Arm | TP S/R/U | FP S/R/U | FP đề xuất loại / tổng FP | TP loại nhầm / tổng TP | drop_fp precision; recall | keep_tp_only precision; recall |
|---|---|---|---|---|---|---|
| A | 20/0/0 | 20/0/0 | 0/20 | 0/20 | 20/40; 20/20 | 20/40; 20/20 |
| B | 9/0/11 | 0/7/13 | 7/20 | 0/20 | 20/33; 20/20 | 9/9; 9/20 |
| C | 20/0/0 | 0/20/0 | 20/20 | 0/20 | 20/20; 20/20 | 20/20; 20/20 |
| D | 17/0/3 | 14/0/6 | 0/20 | 0/20 | 20/40; 20/20 | 17/31; 17/20 |

Precision = TP giữ/(TP giữ+FP giữ); recall ở đây = TP giữ/tổng TP **trong tập
cảnh báo đã chọn**, không phải recall phát hiện toàn Benchmark. drop_fp giữ S+U;
keep_tp_only chỉ giữ S, nên bỏ khỏi nhóm giữ 11/20 TP của B và 3/20 TP của D.
Đây là chính sách chấm giả định, không phải quyết định đóng cảnh báo của con người.
Coverage=(S+R)/N: B16/40, C40/40, D31/40. Accuracy toàn tập=(TP_S+FP_R)/N;
selective accuracy chia cho S+R. JSON có tử/mẫu số và bảng riêng từng CWE.

Raw Qwen D 40 S; post-validator 31 S/9 U (3 TP+6 FP). Citation matched C40/40,
D31/40 không chứng minh kết luận bảo mật đúng. Human state của các run vẫn OPEN.
C có 40 mẫu thời gian: tổng 421000 ms, trung bình 10525 ms; D có 40 mẫu: tổng
301062 ms, trung bình 7526.55 ms (làm tròn). Thiếu phép đo A/B giữ null; không
gán 0. Tổng các elapsed_seconds không đại diện đồng hồ đầu-cuối phiên chạy.

## Giới hạn và điều kiện bàn giao

- #08/#09: escape quote phải được đánh giá theo SQL dialect/Connection/caller;
  không tự nhận cấu hình được nhắc trong peer là cấu hình đã xác minh trên laptop.
- #15: BASE_DIR có dấu phân cách cuối; không suy ra prefix bypass đơn giản.
  Thiếu caller, symlink/quyền ghi và điều kiện mở File, chỉ kết luận có điều kiện.
- #10: chưa đủ chứng cứ validator/caller; giữ LABEL_REVIEW_REQUIRED, không ép TP/FP.
  Nhận định OAuth của peer chưa được chứng minh bằng full checkout trong nhiệm vụ này.
- Kết quả 0/4 FP bị đề xuất loại ở dự án/demo phụ thuộc nhãn tác giả chưa được
  chứng thực. Không dùng nhóm này để tuyên bố độ chính xác chuẩn của Qwen.
- Prompt/model/runtime, config lock đầy đủ, thời điểm khóa và lần thử stale-source
  lịch sử còn giới hạn. Không đòi tạo mới để đóng giả lịch sử; công bố rõ ở G3.
- Arm C là hệ kết hợp có tín hiệu heuristic dẫn dắt; đóng góp Qwen CONFOUNDED.
  Nếu sau này cần kết luận độc lập phải có thiết kế được duyệt riêng. Không thực hiện ở đây.

## Kiểm thử, tái lập và Git

43 test thực tế PASS, exit 0, gồm bảy test mới về phân biệt hash byte/nội dung,
hoán latency, ID trùng, bảo toàn FAIL, timing thiếu, checkpoint, prompt và chặn
acceptance khi thiếu kiểm tra bắt buộc hoặc raw bị sai. Unit test không chứng
thực thực nghiệm. CLI raw Codex: 0 PASS / 2 FAIL / 3 INCOMPLETE; lần chạy mới
exit 2 đúng hợp đồng. CLI `resolve_g0.py` exit 0 chỉ nghĩa xuất được tài liệu.

Các lệnh (đặt biến trỏ tới dữ liệu riêng đã có; output phải mới):

```powershell
python -X utf8 -B -m unittest discover -s v2/crosscheck -v
python -X utf8 -B v2/crosscheck/audit_raw_bundle.py --package $pkg --archive-sha256 4664DCDBFC50620CC713CDE20095D6FE3051335EC6C47CC39CD9C6D8BAC1C6BA --public-post-report $public --output $rawOut
python -X utf8 -B v2/crosscheck/resolve_g0.py --package $pkg --raw-audit "$rawOut/audit.private.json" --public-dir $public --peer-handoff $peerMarkdown --peer-paired $peerCSV --output $newOutput
```

`$public` gồm bảy tệp xuất nguyên byte bằng `git show 86636b9:v2/evaluation/post_report/<file>`:
lock manifest, PROMPT_VERSION_MANIFEST, labels_development/heldout,
dev_alerts/heldout_alerts và PAIRED_EVALUATION.csv. Hai input peer là
`v2/evaluation/post_report_audit/G0_SERVER_FINAL_HANDOFF.md` và
`v2/evaluation/post_report/PAIRED_EVALUATION.csv` tại bf19b5e. Gói riêng không
được thay đổi. Kết quả máy đọc chứa hash raw audit, input và code để tái lập.
Markdown này là biên bản rà soát; script xuất JSON/CSV/errata, không giả tự động
chứng minh nhận định ngữ nghĩa Java.

Đã thử xử lý Git đúng một lần: switch exit 128 (index.lock Permission denied);
clone sạch ngoài OneDrive exit 128 (Git HTTPS bị chặn). Không xóa lock/đổi quyền,
không tiếp tục thử đường vòng. GitHub connector xác nhận đúng bốn nhánh remote.
**Chưa commit/push, không có SHA mới.** git diff --check exit 0; kiểm tra riêng
whitespace file untracked và compile Python cũng phải được ghi cùng validation
trong JSON. Chưa stage nên không tuyên bố đã kiểm tra một index chứa thay đổi.

Bàn giao thủ công ngoài sandbox: tạo clone mới của `v2/codex-core`, sao chép
chọn lọc sáu module Python, metadata OWASP, bốn hồ sơ cuối, register gốc và
`results/published_metrics.json`; đối chiếu SHA với workspace trước stage.
Không sao toàn thư mục vì hồ sơ lịch sử cũ có đường dẫn tài khoản riêng.
Giữ các hồ sơ cũ/backup tại laptop, không sửa để che lịch sử.

```powershell
# Chạy ngoài sandbox; $source là worktree Codex hiện tại, $dest là thư mục mới ngoài OneDrive.
if (Test-Path -LiteralPath $dest) { throw 'Đích đã tồn tại' }
git clone --single-branch --branch v2/codex-core https://github.com/TuanKhoa1201/22025523-NTK-UET-Thesis.git $dest
if ($LASTEXITCODE -ne 0) { throw 'Clone thất bại; dừng' }
# Sao chép chọn lọc và so SHA trước, không dùng backup làm bản mới mặc định.
# Sau khi kiểm tra branch, HEAD và danh sách riêng tư:
git -C $dest status --short --branch
# git -C $dest add -- <danh sách tệp đã so hash và rà soát>
git -C $dest diff --cached --check
git -C $dest diff --cached --name-only
# Chỉ commit sau khi rà soát chính xác index:
# git -C $dest commit -m 'Đính chính sai lệch và chốt đối chiếu dữ liệu thực nghiệm'
# git -C $dest push origin v2/codex-core
```

Dừng tại bàn giao này. Không triển khai G1; điều kiện chuyển giai đoạn cần người
hướng dẫn quyết định trên giới hạn đã công bố, không phải một tuyên bố PASS mới.
