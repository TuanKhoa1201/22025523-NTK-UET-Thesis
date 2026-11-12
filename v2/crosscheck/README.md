> Historical results retained. Current acceptance disposition: [G0_FINAL_RESOLUTION.md](G0_FINAL_RESOLUTION.md). Raw FAIL/INCOMPLETE is not replaced by the derived CONDITIONAL decision.

# Tái tính và đối chiếu độc lập

Mã Codex riêng, Python standard library; không import scorer, heuristic hoặc auditor
của hai agent khác. Không chạy OpenGrep, HTTP/Ollama, không tạo nhãn từ model.
Mã nền: `8db7dafae6c4abc99ca8a78e9b2e83a0e0b9f204`.

## Kết quả dữ liệu thô ngày 13/11/2026

Đã đọc gói riêng trên laptop, xác minh **289/289 tệp** và tái tính từ raw
scan/assessments/checkpoints/SQLite, không dùng biên nhận JavisOS làm đáp án.
Xem [kết luận](G0_RAW_INDEPENDENT_VERDICT.md),
[JSON tổng hợp](G0_RAW_INDEPENDENT_VERDICT.json) và
[sổ sai lệch](G0_DISCREPANCY_REGISTER.csv).
Kiểm toán tự động: **FAIL, exit 2** vì hai số thời gian trong tài liệu dự án/demo
khác raw. Nhãn thủ công và bằng chứng lịch sử còn thiếu: **G0 INCOMPLETE**.
36 unit test PASS, exit 0; test tổng hợp không thay thế kết quả kiểm toán.

`audit_raw_bundle.py` mở rộng bộ tái tính cho đúng cấu trúc gói đã nhận. Công cụ
đọc SQLite ở chế độ read-only/immutable, kiểm tra trace byte offset, JSON/SARIF,
source/manifest hash, từng alert và replay hậu kiểm; không import scorer sản xuất.
PASS từng tiêu chí chỉ có nghĩa trong các trường được đếm ở `checked_fields`.
Chưa xác thực được payload prompt lịch sử, model digest/options hoặc bốn nhãn FP
thủ công. Kết luận đó không thay đổi chỉ vì biên nhận máy chủ ghi PASS.

```powershell
python -X utf8 -B v2/crosscheck/audit_raw_bundle.py --help
$pkg = '<PRIVATE_PATH>
$out = Join-Path $env:TEMP ('ntk-independent-' + [guid]::NewGuid().ToString('N'))
# publicDir: xuất nguyên byte sáu tệp từ commit 86636b9 theo báo cáo đính kèm.
python -X utf8 -B v2/crosscheck/audit_raw_bundle.py --package $pkg --archive-sha256 4664DCDBFC50620CC713CDE20095D6FE3051335EC6C47CC39CD9C6D8BAC1C6BA --public-post-report $publicDir --output $out
$auditExit = $LASTEXITCODE
Write-Output "audit exit=$auditExit; private output=$out"
```

Output chi tiết `audit.private.json` phải ở ngoài repository và gói đầu vào.
Ba báo cáo G0 trong Git là bản tổng hợp đã rà soát: không chứa raw response,
prompt, SQLite hoặc mã Java riêng. Phần rà soát ngữ nghĩa thủ công được đánh dấu
`review_method`, không giả làm kết quả của thuật toán.

## Lệnh

```powershell
python -X utf8 -B -m unittest discover -s v2/crosscheck -v
python -X utf8 -B v2/crosscheck/recompute.py --published <thu-muc-post_report> --expectedresults <expectedresults-1.2.csv> --owasp-sources <thu-muc-56-java> --reference-commit 86636b9de22e59efcca2d3786434727c6ae082e4 --output <thu-muc-moi-ngoai-input>
python -X utf8 -B v2/crosscheck/recompute.py --spec <spec.json> --output <thu-muc-moi-ngoai-evidence>
```

Exit 0 = đầy đủ trong hợp đồng kiểm tra; 2 = mâu thuẫn/định dạng sai;
3 = INCOMPLETE. Published luôn INCOMPLETE hoặc FAIL, không thay raw evidence.
FAIL có ưu tiên hơn INCOMPLETE: vừa thiếu dữ liệu vừa có mâu thuẫn vẫn exit 2.
Thiếu tệp/quyền đọc cho exit 3; JSON sai, ID trùng hoặc decision trái status
cho exit 2. PASS của một hàm kiểm tra chỉ áp dụng cho hợp đồng hẹp của hàm đó.
Hiện cả hai chế độ CLI đều giữ INCOMPLETE khi chưa có xác minh runtime/prompt;
không có đường biến một bảng CSV đủ 40 hàng thành nghiệm thu toàn bộ.
Không ghi đè output đã tồn tại. Đặt output raw ngoài thư mục evidence/nguồn;
không commit output raw, SQLite, checkpoint, prompt hoặc mã riêng.

Spec raw, đường dẫn tuyệt đối trên máy kiểm toán:

```json
{
  "source_root": "<nguon-Java>",
  "scan": "<runs/stage1_heldout_set_40_scan/opengrep.json>",
  "scan_manifest": "<runs/stage1_heldout_set_40_scan/scan-manifest.json>",
  "labels": "<labels_heldout.json>",
  "paired_csv": "<PAIRED_EVALUATION.csv>",
  "arms": {
    "B": {"assessments": "<runs/stage4_heldout40_armB_heuristic/assessments.jsonl>"},
    "C": {"assessments": "<runs/stage4_heldout40_armC_evidence_llm/assessments.jsonl>"},
    "D": {"assessments": "<runs/stage4_heldout40_armD_llm_ablation/assessments.jsonl>"}
  }
}
```

Script ghép bằng SHA scan + finding index, kiểm tra tập ID, trùng/mất hàng,
rule/CWE/path/source hash, nguyên finding, snapshot, raw/post status, citation,
transport/mode và latency từng alert. Không fallback raw status sang post.
`discrepancies.csv`: alert_id, field, expected, actual, source_file, source_sha256.
`checked_fields` ghi số phép kiểm tra thực hiện, kể cả khi không có sai lệch.

Raw mode **của recompute.py --spec** kiểm tra receipt/citation và
replay hậu kiểm cơ bản. Nó **chưa chứng minh membership trong prompt lịch sử,
runtime độc lập, byte offset trace, SQLite hoặc toàn bộ schema receipt**. Những
phần đó không được ngầm tính PASS. Request gốc/biên nhận còn thiếu được ghi
INCOMPLETE. Bộ test raw là fixture giao thức tổng hợp, không phải engine/model thật.

## Công thức

Mọi tỷ lệ có numerator/denominator; mẫu số 0 trả value=null.
Coverage = (SUPPORTED+REFUTED)/N. Accuracy toàn tập = (TP_SUPPORTED+FP_REFUTED)/N.
Selective accuracy dùng mẫu số có kết luận. Drop_fp giữ SUPPORTED+UNDETERMINED;
keep_tp_only chỉ giữ SUPPORTED, không phải chính sách vận hành thực tế.
Mỗi policy có precision, TP retention recall, TP/FP bị loại khỏi nhóm giữ.
TP retention không phải recall phát hiện trên toàn bộ Benchmark.
`supported_precision` = TP_SUPPORTED / (TP_SUPPORTED + FP_SUPPORTED);
`supported_tp_recall` = TP_SUPPORTED / tổng TP. Tỷ lệ đề xuất loại FP đúng dùng
mẫu số tổng FP, còn đề xuất loại TP nhầm dùng tổng TP. `keep_tp_only` cũng loại
TP_UNDETERMINED khỏi nhóm giữ: không được gộp rủi ro này với TP_REFUTED.
Latency dùng Decimal, giữ từng finding; thiếu thời gian không thay bằng 0.
`total_ms`/`mean_ms`/median/p95 chỉ có khi đủ mẫu; nếu thiếu thì chỉ xuất tổng và
trung bình **phần đã quan sát** ở `observed_*`. P95 dùng nearest-rank (ceil(0.95*N)).
Tổng latency không phải thời gian wall-clock toàn pipeline. Bảng A/B ghi 0.0
không phải bằng chứng đo thời gian, nên công cụ giữ các trường đo là null.
Arm A SUPPORTED là biểu diễn baseline giữ cảnh báo, không phải suy luận model.
`status_basis` đánh dấu điều này; không diễn giải coverage/accuracy A như model.
Raw Qwen, post-validator, nhãn OWASP và human state được giữ thành các trường riêng.
Arm D CSV không có cột post status riêng: suy ra từ decision bằng ánh xạ cố định,
chưa xác minh được post status thô nếu thiếu assessments. `raw_to_post` ghi các
chuyển trạng thái có raw; raw thiếu không được lấy từ post để lấp chỗ trống.
Citation có hai mẫu số: toàn bộ alert và chỉ alert có kết luận; không dùng lẫn.
Citation khớp không chứng minh kết luận bảo mật đúng.

## Kết quả công khai trước khi nhận gói — lịch sử ngày 12/11/2026

`results/published_metrics.json`, `ground_truth_56.csv`, `discrepancies.csv` chỉ
chứa dẫn xuất từ dữ liệu public tại `86636b9de22e59efcca2d3786434727c6ae082e4`.
Có 1442 phép đối chiếu, gồm 304 phép kiểm tra bảng tổng hợp, 0 sai lệch trong
phạm vi các trường đã kiểm tra. Không có
raw assessments/scan máy chủ trên laptop **ở thời điểm đó**; trạng thái tổng INCOMPLETE.
Các vấn đề giải thích GT/khóa được ghi riêng trong `FINDINGS.md`, nên CSV rỗng
không có nghĩa không tồn tại vấn đề phương pháp hoặc thực nghiệm.
`published_per_alert.csv` chứa 160 hàng A/B/C/D dẫn xuất public, gồm thời gian
từng finding C/D; B/A không có thời gian đo nên để trống. `interpretation_discrepancies.csv`
ghi riêng bốn đối chiếu lý do GT với Java (gồm cả mô tả thiếu, không phải bốn nhãn sai).
Không gộp các đối chiếu ngữ nghĩa này vào con số 0 sai lệch catalog.

`recompute.py --published` tự xuất các bảng public và `status_transitions.csv`
(9 hàng Arm D đổi SUPPORTED → UNDETERMINED). `audit.json` đầy đủ nằm trong output
tạm. Hash input được ghi trong kết quả; `--reference-commit` chỉ là commit người
chạy khai báo, không tự chứng thực checkout. Không sửa các tệp nguồn trong cache.
Schema dẫn xuất là `ntk-crosscheck-2`; không thay schema thí nghiệm của JavisOS.

21 test tổng hợp PASS ở lần trước (13 bài cũ và 8 bài bổ sung), có chạy subprocess kiểm tra
mã thoát thật; không suy ra độ chính xác model từ test. `.gitignore` tại đây chỉ
cho phép sáu bảng dẫn xuất public cụ thể trong results; không mở cả thư mục để
đưa raw evidence vào Git. Xem `FINDINGS.md` và `TRANSFER_REQUEST.md` cho phạm vi
chưa nghiệm thu và dữ liệu cần nhận. Nhánh local vẫn là nhánh cũ, không commit/push.
