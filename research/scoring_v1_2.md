# Nghiên cứu chấm điểm và phân loại cảnh báo

## Cơ chế hiện tại

Cần phân biệt hai nhiệm vụ:

1. **Xác minh và phân loại cảnh báo**: OpenGrep phát hiện ứng viên; phân tích Java AST, IRIS khi được cấu hình và Qwen LoRA cung cấp bằng chứng để đưa ra `REPORT`, `REVIEW` hoặc `SUPPRESS`. Không dùng điểm CWSS làm kết luận cảnh báo thật hoặc giả.
2. **Sắp xếp mức ưu tiên theo CWSS**: MITRE Common Weakness Scoring System 1.0.1 đánh giá điểm yếu bằng 16 metric của Base Finding, Attack Surface và Environmental. Đây là một phép đánh giá điểm yếu có giả định, không phải mô hình thống kê được hiệu chỉnh từ nhãn TP/FP.

## Công thức CWSS

```text
CWSS = Base Finding x Attack Surface x Environmental
```

Base Finding được biểu diễn trên thang 0 đến 100. Attack Surface và Environmental là các hệ số trong khoảng 0 đến 1. Cách chuyển các giá trị metric sang trọng số và quy tắc làm tròn nằm tại `backend/ntk-production-v2/scripts/ntk_cwss_v101.py`. Các module bổ sung xử lý bằng chứng, suy luận và kịch bản tại `scripts/ntk_cwss_automatic.py`, `scripts/ntk_cwss_complete.py`, `scripts/ntk_cwss_workflow.py`.

Nguồn đặc tả: <https://cwe.mitre.org/cwss/cwss_v1.0.1.html>.

## Giới hạn khoa học

Các giá trị về quyền truy cập, tác động kinh doanh, bảo vệ, Internet và môi trường triển khai thường không xác minh được chỉ từ mã Java. Do đó cần giữ `UNKNOWN` hoặc đánh dấu rõ giả định; không âm thầm chọn giá trị có vẻ hợp lý rồi khẳng định là đo thực tế.

Kết quả chạy trên kịch bản tham chiếu chỉ cho phép xếp ưu tiên theo tình huống đã giả định. Không nên coi điểm tuyệt đối của hai dự án khác môi trường là trực tiếp so sánh được nếu chưa kiểm soát yếu tố khác biệt.

## Những phép đo còn cần có

- So sánh các điểm cùng nhãn TP/FP được kiểm tra độc lập.
- Phân tích độ nhạy với từng nhóm metric và các trường UNKNOWN.
- So sánh mức ưu tiên giữa các cấu hình áp dụng chung một tập cảnh báo.
- Ghi nguồn từng giá trị metric, có hay không chứng cứ từ mã nguồn, có hay không giả định người dùng.

## Ghi chú lịch sử

Tài liệu cũ về điểm heuristic V1.2 là cơ sở nghiên cứu trước khi bổ sung đánh giá CWSS. Phần triage vẫn dựa trên bằng chứng và chính sách an toàn; không đồng nhất công thức heuristic cũ với công thức MITRE CWSS.

Không sử dụng điểm CWSS để nói một cảnh báo có xác suất đúng là x%.
