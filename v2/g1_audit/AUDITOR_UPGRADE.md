# Gia cố bộ nghiệm thu G1

Tiếp nối commit `b74e5a31f24daa2141bb17ff5195801923b1512c`. Biên nhận tiền ứng viên G1-C1 được giữ nguyên. `reference_sha = 457183f9e17892fe284da04b57ef6c5c24b008e0`; chưa có candidate READY ở hai lần kiểm tra remote đầu phiên tiếp nối. Baseline lịch sử 59 PASS không được cộng vào lượt mới.

## Các thay đổi đã kiểm thử

- JSON/JSONL dùng parser chung từ chối duplicate keys, NaN/Infinity và số thực tràn; kiểm tra schema major, trường bắt buộc, status, ID/index/order, raw finding/trace và liên kết xuyên bundle/JSONL/SQLite.
- Manifest kiểm tra tất cả log/hash theo `ntk-scan-capture-1`, argv/exit/format, executable/rules/target không đổi giữa JSON và SARIF, thời gian, rules và nguồn trước/sau, phiên bản từ stdout/raw/SARIF khi producer có cung cấp. Không đòi thêm binary digest mà producer chưa có; executable/version chỉ là capture unsigned.
- SARIF đối chiếu multiset full rule/path/line, cột khi có, severity từ result hoặc rule defaultConfiguration, CWE từ metadata/tags khi có. Matching hai phía giữ multiplicity. Không bắt buộc metadata/cột mà phiên bản producer không xuất; số trường thực sự đối chiếu được ghi vào report.
- SQLite mở chỉ đọc, đóng connection chắc chắn, kiểm tra scan join/foreign keys, nguồn sự kiện so với snapshot, digest evidence, actor/reason/timestamp, replay trạng thái. Sửa lỗi auditor cũ so sánh nhầm snapshot object với observed hash string; positive control confirm-false/reopen hợp lệ hiện thông qua.
- Runner dùng `TestLoader.countTestCases` và `TextTestResult` tạo receipt có từng outcome; đối chiếu discovered/run/outcome, số test trong log và exit. Zero discovery/import error/subtest failure/skip đều có kiểm thử riêng. Receipt không còn được suy ra chỉ bằng regex `... ok`.

## Lượt xác minh checkpoint

Lượt `deep-02`: **97 PASS, 0 FAIL, 0 ERROR, 0 SKIP**, sáu tiến trình exit 0. Trong đó 65 bài kiểm tra do Codex sở hữu và 32 bài prompt/review của Antigravity. Đây là synthetic/mock; một test đọc cặp JSON/SARIF lịch sử chỉ để kiểm tra tương thích định dạng, không xác thực lại runtime lịch sử/G0.

Lệnh:

```text
python -X utf8 -B v2/g1_audit/run_checks.py --checkout v2/g1_audit/.local/reference --expected-sha 457183f9e17892fe284da04b57ef6c5c24b008e0 --output v2/g1_audit/.local/deep-02
```

Khi tái lập phải dùng output mới. Receipt công khai: `receipts/HARDENING_CHECKPOINT.json`; log gốc chỉ ở `.local/deep-02/`. Lượt `deep-01` thất bại do connection SQLite fixture/auditor chưa được đóng trên Windows và một test cũ thiếu trường manifest; đã sửa auditor/fixture, không sửa producer, rồi chạy lại toàn bộ.

## Giới hạn

Chưa có CLI integration/runtime G1 để chốt PASS. Manifest/HTTP/SQLite unsigned không là chứng thực vật lý máy chủ hoặc actor. Auditor không suy ra kết luận an ninh từ citation đúng. Các gate cần quan sát độc lập tiếp tục INCOMPLETE. Các phần mở rộng phản chứng, thiết kế CLI, Git attributes và đối chiếu runtime được báo cáo riêng ở cuối phiên.
