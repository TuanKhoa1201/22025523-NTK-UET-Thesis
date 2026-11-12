# Hướng dẫn theo dõi mã nguồn và kết quả kiểm toán

Đề tài: **Phát triển công cụ phát hiện lỗ hổng mã nguồn kết hợp phân tích tĩnh nguồn mở và mô hình ngôn ngữ lớn**.

**Trạng thái:** Đang kiểm toán dữ liệu và kết quả thực nghiệm. Chưa được công nhận hoàn thành kiểm toán, chưa kết luận Qwen độc lập đạt độ chính xác 100%.

## Bốn nhánh làm việc lâu dài

| Nhánh | Mục đích | Nguồn bàn giao |
| --- | --- | --- |
| [`main`](https://github.com/TuanKhoa1201/22025523-NTK-UET-Thesis/tree/main) | Giữ nguyên đồ án phát triển trước khi thầy điều chỉnh phạm vi; không phải phiên bản thực nghiệm mới nhất | Lịch sử cũ |
| [`v2/codex-core`](https://github.com/TuanKhoa1201/22025523-NTK-UET-Thesis/tree/v2/codex-core) | Nghiên cứu, bảo toàn nhiệm vụ gốc simple_semgrepAI → OpenGrep và kiểm tra chéo mã nguồn | Commit `8db7daf` |
| [`v2/antigravity-review`](https://github.com/TuanKhoa1201/22025523-NTK-UET-Thesis/tree/v2/antigravity-review) | Kiểm toán độc lập nhãn OWASP, số liệu, bằng chứng và chất lượng kết luận | Commit `a1b9130` |
| [`v2/javis-benchmark`](https://github.com/TuanKhoa1201/22025523-NTK-UET-Thesis/tree/v2/javis-benchmark) | Chạy thực nghiệm, lưu biên nhận và kiểm chứng từ máy chủ dùng OpenGrep + Qwen cục bộ | Commit `e81c756` |

Đường dẫn tài liệu trên mỗi nhánh và commit SHA cần được giữ chính xác; không suy luận rằng một báo cáo trên nhánh này là bằng chứng đã được kiểm chứng trên nhánh khác.

## Bằng chứng có thể tra cứu

- [Chứng minh nhiệm vụ gốc và phụ lục lệnh chạy](https://github.com/TuanKhoa1201/22025523-NTK-UET-Thesis/blob/v2/codex-core/v2/baseline/ADVISOR_M1_ORIGINAL_CLI_PROOF.md).
- [Kiểm toán độc lập từ GitHub, các vấn đề về heuristic và Ground Truth](https://github.com/TuanKhoa1201/22025523-NTK-UET-Thesis/blob/v2/antigravity-review/v2/evaluation/audit_20261112/DISCREPANCY_AND_EVIDENCE_AUDIT.md).
- [Báo cáo kiểm toán chứng cứ máy chủ](https://github.com/TuanKhoa1201/22025523-NTK-UET-Thesis/blob/v2/javis-benchmark/v2/evaluation/post_report_audit/SERVER_FORENSIC_AUDIT_SUMMARY_20261112.md).
- [Bảng đối chứng thực nghiệm 40 cảnh báo](https://github.com/TuanKhoa1201/22025523-NTK-UET-Thesis/blob/v2/javis-benchmark/v2/evaluation/post_report/PAIRED_EVALUATION.csv).

**Lưu ý về hai hệ thống đối chứng:** OpenGrep chỉ phát hiện ứng viên; Qwen và heuristic đưa ra nhận định để người dùng xem xét. `REFUTED` không đồng nghĩa người dùng đã xác nhận và xóa cảnh báo. Cần báo riêng các lỗ hổng thật bị đề xuất loại nhầm và các kết quả `UNDETERMINED`.

## Những vấn đề đang được xử lý

1. Tái tính mọi chỉ số từ bản ghi thô, khớp theo `alert_id`, CWE và nhãn chuẩn. Bản ghi kiểm tra trên máy chủ gần nhất cho thấy 40 trường hợp được chia 20 CWE-22 + 20 CWE-89; heuristic có 9 `SUPPORTED`, 7 `REFUTED` và 24 `UNDETERMINED`.
2. Sửa điều kiện nghiệm thu của bộ kiểm toán: phát hiện mất/sai bằng chứng phải trả lỗi, không chỉ kết thúc chương trình với mã 0.
3. Kiểm tra quan hệ giữa sanitizer, nguồn dữ liệu và sink; tránh nhầm sự hiện diện của một kiểm tra an toàn không liên quan với bảo vệ lỗ hổng.
4. Đối chiếu citation với mã Java thực tế, đúng bản chụp mã và những dòng đã đưa cho Qwen.
5. Phân biệt kết luận heuristic được đưa vào prompt với khả năng suy luận độc lập của Qwen; chưa quy kết kết quả 40/40 cho riêng mô hình.
6. Đính chính lỗi lịch sử: kiểm tra `ground_truth_verifier.py` “4/4 gates” trước đây là cổng kiểm tra hệ thống Javis, không phải kiểm định dữ liệu của đồ án.

## Nguyên tắc cộng tác

- Một vấn đề chỉ có một chủ sở hữu thay đổi mã; hai đơn vị còn lại kiểm tra độc lập.
- Không sửa tệp evidence lịch sử để phù hợp báo cáo; lưu biên nhận mới kèm SHA-256.
- Mỗi thay đổi cần test phản chứng, kết quả chạy, commit và trường hợp còn hạn chế.
- Không viết đè hoặc ép đẩy nhánh của đơn vị khác; chỉ hợp nhất thay đổi đã được kiểm chứng.
- Commit sử dụng câu tiếng Việt tự nhiên, mô tả chính xác nội dung đã làm, không dùng tiền tố `feat(...)`, `fix(...)`, `chore(...)` hoặc mã phân chia giai đoạn.
- Chỉ tập trung Java CWE-22/CWE-89 và OpenGrep + Qwen cục bộ; không mở rộng sang IRIS, CodeQL, fine-tuning hoặc xây dựng giao diện mới ở giai đoạn này.

## Lịch sử nhánh

Các nhánh công việc từng tạo theo từng phiên trước được giữ nguyên trong lịch sử commit của ba nhánh làm việc lâu dài. Commit gốc vẫn có thể truy cập bằng SHA khi các nhánh tham chiếu cũ được dọn khỏi danh sách branch. Không force-push để viết lại lịch sử.
