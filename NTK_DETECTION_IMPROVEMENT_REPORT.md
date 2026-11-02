# NTK — Detection evidence and limitations

**DETECTION_IMPROVEMENT=NO_DEMONSTRATED_GAIN.** Có bản sửa coverage và engine execution thật; chưa có benchmark held-out/ablation đủ điều kiện để công bố cải thiện accuracy.

## Frozen baseline

Các báo cáo cũ và `docs/evaluation-20261102/` không được viết lại. OWASP BenchmarkJava commit `f40c618c5a709afce350ef06ed2899c85cf586e9`: 6 cases là regression; 40 cases là baseline/post-fix regression sau khi phát hiện lỗi switch. Không gọi chúng là unseen sau tối ưu.

Đơn vị: `(test case, target CWE)`. Nhiều callsites chỉ gộp một quyết định. Other-CWE findings báo riêng, không tự gán FP theo CSV chỉ nhãn target. REPORT ưu tiên; không REPORT mà có REVIEW thì abstain; còn lại SUPPRESS/no candidate là operational negative, không chứng minh an toàn.

| Frozen 40-case, report-only convention | Giá trị |
|---|---:|
| TP / FP / TN / FN | 3 / 0 / 20 / 17 |
| Precision trên 3 REPORT | 100% |
| Recall tự động REPORT | 15% |
| FPR / F1 | 0% / 26.09% |
| REVIEW / automatic decision coverage | 75% / 25% |
| Candidate recall | 90% |

REVIEW được quy thành negative **chỉ** để đo khả năng tự động REPORT; không coi là verified TN/FN hoặc safe. Selective convention loại REVIEW: TP=3, FP=0, TN=5, FN=2; recall 60%, F1 75%, đọc cùng coverage 25%. Precision 3/3 không phải accuracy 100%. Mẫu cân bằng có chủ đích không phản ánh prevalence thực tế.

## REVIEW taxonomy từ output thật

Đúng target CWE: **30 findings / 30 cases REVIEW**. Nếu cộng other-CWE, có 51 REVIEW findings trên 34 case; không tráo hai đơn vị này.

| CWE | Helper return unproven | Mutable array state unproven | Insufficient local trace | Target REVIEW |
|---|---:|---:|---:|---:|
| 22 | 4 | 0 | 2 | 6 |
| 78 | 7 | 3 | 0 | 10 |
| 79 | 6 | 0 | 0 | 6 |
| 89 | 5 | 2 | 1 | 8 |

Đây là reason codes từ local Javac analysis của baseline, không phải diagnostics CodeQL chạy hồi tố. Target REVIEW ở tập này có Qwen role JSON hợp lệ nhưng thiếu verified local flow. Không gán mọi REVIEW cho LLM, không giả có CodeQL DB failures trong baseline vốn chưa chạy original IRIS.

## Thay đổi đã kiểm chứng

1. Stage 05 gọi upstream SAPipeline/CodeQL riêng, có union IRIS-only discoveries, strict/fallback rõ ràng và source binding.
2. Path + safe-proof conflict chuyển REVIEW; no path/LLM negative không cấp quyền SUPPRESS. Typed API context chặn cross-CWE và môi trường `Runtime.exec` chưa xác định command slot.
3. Sửa scanner scope: luôn đưa explicit inventory và `--no-git-ignore`, kiểm tra `paths.scanned`; cache key mới ngăn dùng batch thiếu coverage cũ. Test thật xác nhận `src/test` được quét và allowlist vẫn được tôn trọng.
4. Bounded mining thử ưu tiên framework frontier để tránh alphabet starvation. Đây là lịch chạy, không phải source/sink labels. Cả hai policy đều có coverage hạn chế; không công bố tăng recall từ số model roles.
5. Sparse Git checkout/filter có counts của phần đã materialize, không đủ kết luận toàn repository. Đã sửa nhãn thành PARTIAL_BOUNDED cả khi inventory cache hit; tổng Java chưa checkout giữ unknown thay vì đoán.

Không đổi OpenGrep rules, CWSS weights, triage thresholds hoặc checkpoint. Không tự REPORT mọi UNKNOWN. Bộ chống false suppression hiện hữu tiếp tục kiểm tra switch/if/try/loop/reassignment/arrays/helpers/overloads và các safe controls; tests mới kiểm tra xung đột CodeQL/local proof, source URI/SHA và sink context.

## Leakage, held-out và đo sau sửa

Đã kiểm tra metadata trong Track B 781, Track A 275, validation 166, quarantine 137 records. Không thấy 46 Benchmark case IDs trong bốn artifacts này. Tuy nhiên, records chủ yếu là API-role prompts, không đủ toàn bộ source corpus/historical tuning registry để chứng minh exact/normalized/near-duplicate exclusion. **LEAKAGE_FREE=NOT_PROVEN**; zero ID matches không phải chứng minh không overlap.

Chưa chạy một tập held-out mới hoặc 40-case evaluation dưới original engine hoàn chỉnh. Native posthoc có output logic sai và bounded mining còn partial, nên không hợp lệ để công bố số liệu cải thiện/đóng góp nhân quả của Qwen. REVIEW_RATE_AFTER và AUTO_REPORT_RECALL_AFTER cho cấu hình mới là **NOT_MEASURED**, không chép baseline thành kết quả sau sửa.

Xem [IRIS integration](NTK_ORIGINAL_IRIS_INTEGRATION_REPORT.md), [Spark](NTK_SPARK_CVE_2016_9177_ANALYSIS.md), [ablation](NTK_COMPONENT_ABLATION_REPORT.md) và [release acceptance](NTK_FINAL_ENGINE_ACCEPTANCE.md). CSV provenance/metadata công khai nằm trong `docs/engine-evaluation-20261102/`; raw/model/dataset artifacts ở ignored runtime.
