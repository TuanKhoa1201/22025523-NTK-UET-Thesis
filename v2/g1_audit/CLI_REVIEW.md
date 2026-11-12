# Kiểm tra đường gọi CLI kế thừa

Phạm vi: static source tại `457183f9e17892fe284da04b57ef6c5c24b008e0`, đối chiếu M1 trên Codex ban đầu `b74e5a3`. Không có candidate READY để đánh giá bridge mới. Inventory AST/hash: `receipts/STATIC_CLI_REFERENCE.json`. **Gate Fork CLI: INCOMPLETE.**

## Những gì mã nền thực sự có

| Đường chạy | Vị trí tại reference | Nhận định trong phạm vi static |
|---|---|---|
| `python -m v2.triage run` | `v2/triage/cli.py:40`, `:53`, `:73`, `:100` | Có nhánh import raw hoặc tự gọi scanner, collect và SQLite; không chứng minh đã qua CLI kế thừa |
| Scanner-only `semgrepai` trong `v2/baseline/fork` | `semgrepai/__main__.py:1`, `cli.py:10` | Gọi `cli.main` argparse, không phải `cli.app` Typer upstream; chạy được đường này không đủ Gate 1 |
| Full upstream chuẩn bị bằng overlay | `v2/baseline/prepare_upstream_local.py:18`, `:34`, `:37`, `:42` | Sửa chính hàm Typer `scan`, giữ `results = scanner.scan(target_path, rules_path)`, bọc recording; sau scanner có return scan-only, chưa có bridge G1 trong snapshot |
| Upstream pin và patch | `prepare_upstream_local.py:15`, `:67`, `:84`, `:94` | Pin `2c79a58a16d11e9dea3723e30d2a7faffba7bdc9`, áp patch giảng viên trong cây sao chép riêng, ghi check/apply và hash; chưa chạy lại preparation trong audit này |

Upstream `pyproject.toml` khai báo `semgrepai = semgrepai.cli:app`. Snapshot `upstream/` có chủ ý chỉ chứa một số file; không nhận là full clone. Cần kiểm cây full prepared có `semgrepai.__main__` và blob đúng pin. Code M1 trên Codex có inventory toàn tree và `record_cli_origin`; reference Antigravity cũ còn recorder không có hook origin đó. Đây là chênh lệch tiền tích hợp cần kiểm khi có candidate, không là kết luận lỗi candidate chưa tồn tại.

Scanner upstream chưa vá gọi Semgrep; patch giảng viên/overlay phải thay binary và cấu hình scanner thực tế. Không được suy ra có OpenGrep chỉ từ tên lớp `SemgrepScanner`. Overlay dùng config riêng tránh eager import RAG/cloud. Không chạy private patch trong phiên này và không công bố nội dung patch riêng.

## Checklist cho candidate thực

1. Fetch, xác minh READY/candidate_id, lấy Git HEAD thực; checkout detached sạch và hash marker. Không tin claimed SHA thay cho Git.
2. Đọc full prepared entrypoint hoặc console script. Runtime `argv`, `__main__.__spec__`, nguồn `semgrepai.cli`/scanner và hash phải cùng prepared tree đã khóa. Hash module hiện có chưa chứng minh module đã chạy.
3. Theo dấu call trong chính Typer `scan`: scanner thực chạy trước handoff. Wrapper gọi scanner-only rồi chạy triage bên ngoài không đủ. Wrapper launch **đúng CLI kế thừa và bridge trong đường gọi đó** vẫn có thể hợp lệ nếu có receipts chứng minh.
4. Binary OpenGrep thực, version, local rules, config, argv và exit được ghi tại thời điểm subprocess. Giữ stdout/stderr/raw JSON/SARIF, không tạo manifest hồi tố. Kiểm cả layout stdout và file-output của upstream (target có thể đứng trước `--json --output`).
5. Handoff phải dùng đúng byte raw/manifest vừa tạo; cùng scan hash/index/ID và raw trace; không gọi thêm scanner trong nhánh import triage. JSON và SARIF có thể là hai engine subprocess trong cùng scan session theo thiết kế M1; không gọi đó là rescan trái thiết kế.
6. Chứng minh Qwen local nhận payload đúng warning/prompt contract; validator và SQLite nằm sau handoff, độc lập với model status. Lỗi model không xóa finding; thiếu evidence → UNDETERMINED.
7. Đối chiếu command receipt cả thành công và thất bại. `exit 0`, lời in console, `cli-origin.json` unsigned hoặc AST call inventory riêng lẻ đều chưa đủ nghiệm thu runtime.

Không phát hiện bridge G1 để phản chứng tại SHA hiện có. Kết luận thiết kế tích hợp của candidate được để trống cho tới marker READY. Không thay Antigravity triển khai bridge.
