# NTK — Component ablation acceptance

**FULL_CONFIGURATION_ABLATION=NOT_RUN; QWEN_CONTRIBUTION=NOT_PROVEN.** Không dùng các stage của một scan rồi gắn lại tên thành bốn deployment độc lập.

## Runner và cấu hình

`tools/run_engine_ablation.py` tạo directory mới trong ignored `work/`, freeze Java source hashes, implementation hashes, CWE scope và arm selection. Không nhận ground truth; không ghi đè output cũ hoặc demo store. Mỗi arm tự thực thi scanner/engine, force-fresh mining; chạy tuần tự, dùng resource bounds và local GPU lock hiện hữu.

| Arm | Cấu hình | Ý nghĩa output |
|---|---|---|
| A | OpenGrep-only | Candidate detection; không phải triage TP/FP |
| B | OpenGrep + original IRIS/CodeQL, không posthoc | IRIS vẫn cần local Qwen để mining specs; không gọi đây là cấu hình không LLM |
| C | B + native local contextual/posthoc attempt | Posthoc advisory; negative LLM không phải safe proof và không được tự loại path |
| D | Full NTK strict original mode + local classification + fusion/triage/CWSS | REPORT/REVIEW/SUPPRESS và provenance; CWSS không phải dự đoán TP |

Arm A đã được **chạy thật bằng runner mới** trên public servlet regression BenchmarkTest00006, cùng commit/source bytes dùng trong smoke: một candidate CWE-78, zero GPU calls, khoảng 2.33 giây. Freeze và `A.json` nằm tại `work/original-iris-engineering-20261102/ablation-A-only-smoke/`. Đây chỉ là kiểm tra runner A, không phải full ablation hay held-out accuracy.

Các execution original IRIS, fresh full NTK và Spark được báo riêng vì khác scope/config/order. Không coi chúng là một bảng A/B/C/D có kiểm soát. Các code paths B/C/D của runner chưa được nghiệm thu thành một matrix hoàn chỉnh; phải kiểm tra runtime thật trước khi dùng số liệu khoa học từ runner.

## Điều chưa thể kết luận

Không có metric A/B/C/D độc lập trên cùng held-out set. Không có ước lượng causal gain riêng của Qwen. Việc model chạy CUDA không chứng minh tăng precision/recall; việc model dự đoán nhiều SOURCE hơn sau đổi lịch mining cũng không đủ.

Để so sánh hợp lệ cần freeze source/case IDs, code/config/model/prompt/policy và cách gộp case-CWE; chạy từng cấu hình với cache policy công bố; giữ REVIEW là abstention; báo runtime cold/warm riêng. CodeQL compiler caches có thể còn warm ngay cả khi model-mining workspace mới, nên runner không gọi latency đó là cold-start benchmark công bằng.

Hiện local API-role compatibility chưa bao phủ mọi signature, function-source ngoài training contract và posthoc có lỗi logic. Đánh giá mới bị giới hạn bởi các điều kiện này; không tạo số liệu cho arm chưa chạy, không đưa expected labels vào inference và không chỉnh threshold để tạo kết luận thuận lợi.

Các stage-observation A/B/C trong báo cáo ground truth cũ vẫn là bằng chứng lịch sử ở đúng phạm vi đã ghi; không đổi tên hồi tố thành full-configuration ablation. Xem [detection report](NTK_DETECTION_IMPROVEMENT_REPORT.md) và [release acceptance](NTK_FINAL_ENGINE_ACCEPTANCE.md).
