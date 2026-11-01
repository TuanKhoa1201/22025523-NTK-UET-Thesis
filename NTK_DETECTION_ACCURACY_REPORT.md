# NTK — Detection accuracy scope

VULNERABILITY_DETECTION_ACCURACY=EVALUATED cho OWASP 6+40 case, theo test case và target CWE; **8_PROJECT_GLOBAL_ACCURACY=NOT_EVALUATED** vì không có exhaustive ground truth cho toàn bộ 8 source trees.

Định nghĩa TP/FP/TN/FN, quy ước REVIEW, cách match multiple findings, số liệu trước/sau sửa và component observations: [NTK_GROUND_TRUTH_EVALUATION.md](NTK_GROUND_TRUTH_EVALUATION.md). Không gộp cùng WebGoat source thành hai mẫu độc lập. Không dùng chữ CVE/vuln/fixed làm nhãn.

Source diff + advisory Spark xác nhận vị trí cần đối chiếu nhưng scanner chưa phân biệt được traversal; không tính 9 UNKNOWN findings thành TP chỉ dựa vào tên bản vuln. Fixture SQL mini có manifest và mã nguồn cho một method Statement string concat và một method PreparedStatement binding; kết quả tương ứng REPORT/SUPPRESS là kiểm tra kiểm soát nhỏ, không đại diện precision/recall tám dự án.

6 ca OWASP đã dùng phát triển chỉ là hồi quy. 40 ca mở rộng đã loại identifiable prior cases nhưng không chứng minh leakage-free. Một lỗi switch được phát hiện và sửa; kết quả trước sửa giữ nguyên, sau sửa là kiểm tra hồi quy, không còn là tập independent unseen. Chưa có full production configuration ablation ba mô hình độc lập; chỉ có measurements A/OpenGrep, B/fresh AST proof policy, C/full production trên cùng source bytes.

REPORT không có nghĩa chuyên gia xác nhận TP; SUPPRESS không chứng minh toàn chương trình safe; REVIEW là abstention. Precision có thể cao trên vài auto reports trong khi review rate lớn và recall tự động thấp. CWSS không được dùng để gán nhãn hoặc làm xác suất TP/FP. Không thay threshold/rules để khớp expected score.
