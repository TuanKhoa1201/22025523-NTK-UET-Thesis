# Trạng thái thực hiện đồ án

Cập nhật ngày 27/11/2026, tổng hợp từ hồ sơ kiểm chứng đã có. Không thực hiện thêm lượt nghiệm thu runtime khi cập nhật tài liệu này.

## Phạm vi và phiên bản

Phạm vi hiện hành gồm fork `simple_semgrepAI`, OpenGrep, Qwen3.5-9B chạy cục bộ qua Ollama và quy trình kiểm chứng, kiểm duyệt cảnh báo Java CWE-22/CWE-89. Không mở rộng sang IRIS, CodeQL, fine-tuning, CWSS hoặc SAST scoring. Orchestrator vẫn dừng phát triển.

| Thành phần | Phiên bản ghi nhận |
| --- | --- |
| Upstream | `hardw00t/simple_semgrepAI` v0.2.0, `2c79a58a16d11e9dea3723e30d2a7faffba7bdc9` |
| OpenGrep / Ollama (vận hành) | 1.25.0 / 0.40.7 |
| OpenGrep / Ollama (bộ tham chiếu) | 1.33.1 / 0.40.16 |
| Python (vận hành) | 3.11.9 |
| Model | `qwen3.5:9b-q4_K_M` |
| Prompt của bản tích hợp | `v2.2.6-cwe22-cwe89-strict-singleline-max3-citations` |
| Commit mã nguồn | [`c5a778a4cf198d8edabd3f9582431536400b4af6`](https://github.com/TuanKhoa1201/22025523-NTK-UET-Thesis/commit/c5a778a4cf198d8edabd3f9582431536400b4af6) |
| Git tree của commit mã nguồn | `3f0cee0cfc75d91c48b92950f4d8f627fa3c78f6` |

## Nhiệm vụ ban đầu và bộ mã tham chiếu

Xem [hồ sơ CLI ban đầu](../v2/baseline/ADVISOR_M1_ORIGINAL_CLI_PROOF.md) và [tài liệu baseline](../v2/baseline/README.md) để phân biệt mã kế thừa với phần phát triển thêm.

Theo [báo cáo ngày 14/11/2026](https://github.com/TuanKhoa1201/22025523-NTK-UET-Thesis/blob/f16dfd5d0a987c1ca6d83500daacf052134aa619/docs/trang-thai-hien-tai.md), bộ mã tham chiếu đạt 9/9 bài kiểm thử ngoại tuyến. OpenGrep 1.33.1 phát hiện 8 cảnh báo demo. Lượt smoke hai cảnh báo đạt hợp đồng kỹ thuật. Lượt full-8 đầu tiên thất bại với 7 phản hồi hợp lệ và 1 `invalid_response` trong 8 lượt gọi. Kết quả trên RTX 4060 Ti khác kết quả Colab Tesla T4. Tám mẫu demo tổng hợp không được dùng làm Ground Truth cho thực nghiệm chính.

Báo cáo cũ cũng ghi nhận tái kiểm toán A7 của Orchestrator chưa đạt (`REMEDIATION_INCOMPLETE_REVIEW_REQUIRED`), với 5 phát hiện, gồm 3 blocker. Lịch sử và bằng chứng được giữ nguyên; không tiếp tục phát triển hoặc triển khai công cụ điều phối này.

## Kiểm chứng qua API và giao diện web

Kết quả ghi nhận ngày 26-27/11/2026:

| Lượt kiểm chứng | Tệp Java được quét | Cảnh báo OpenGrep | SUPPORTED | REFUTED | UNDETERMINED |
| --- | ---: | ---: | ---: | ---: | ---: |
| JVL qua API | 19 | 8 | 7 | 0 | 1 |
| WebGoat qua Chrome | 389 | 14 | 9 | 0 | 5 |

WebGoat có 498 tệp Java, trong đó 109 tệp bị bỏ qua. Có 2 cảnh báo CWE-22 và 12 cảnh báo CWE-89. Hồ sơ ghi nhận 14 lượt gọi mô hình, 0 lượt dùng cache và 14 HTTP capture. Kết quả tái tính lớp kiểm chứng và Integration Gate khớp 14/14. Trong 14 nhận định sau kiểm chứng, 5 trường hợp được giữ ở `UNDETERMINED` (3 trích dẫn không hợp lệ, 2 luồng qua hàm phụ trợ chưa kiểm chứng). Kết quả khớp ở lớp kiểm chứng không xác nhận cảnh báo là TP hay FP.

Các bài kiểm tra chức năng bao gồm xác nhận cảnh báo thật, xác nhận cảnh báo giả trên fixture riêng, mở lại cảnh báo, kiểm tra SHA-256 và từ chối thao tác khi mã nguồn thay đổi (`409 STALE_SOURCE`). Đã đối chiếu báo cáo và lịch sử kiểm duyệt với dữ liệu lưu trên máy chủ. Các quyết định dùng để thử chức năng không phải nhãn Ground Truth.

Pha A API được người vận hành chấp nhận trong phạm vi API. Pha B được chấp nhận có giới hạn (`ACCEPTED_WITH_LIMITATIONS`), chỉ áp dụng cho vận hành nội bộ. Ba mục chưa đủ bằng chứng là PB-FE-01 (danh tính frontend tại thời điểm chạy), PB-DR-02 (biên nhận HTTP 409 trực tiếp cùng lượt) và PB-T3-03 (baseline full-tree ở một số mốc). Hash tại các mốc không loại trừ khả năng ghi rồi hoàn nguyên giữa hai lần kiểm tra; checkpoint cũng nằm ngoài manifest bất biến. Đây là ngoại lệ do người vận hành phê duyệt, không phải xác nhận đã đáp ứng đầy đủ chính sách nghiệm thu.

Hai cờ `independently_verified_model_runtime=false` và `security_conclusion_verified=false` vẫn giữ nguyên. Nghiệm thu nội bộ không thay thế nghiệm thu G2, G3 hoặc G4.

## Thực nghiệm đối chứng

Thực nghiệm sử dụng Ground Truth OWASP trong phạm vi CWE-22/CWE-89. Ở tập development 40 mẫu, OpenGrep có TP=15, FP=6, FN=5, TN=14. Trong tập holdout 60 mẫu, có 19 cảnh báo TP và 13 cảnh báo FP theo phép ghép đã dùng.

Kết quả lịch sử với prompt v2.2.5 trên các cảnh báo đã ghép:

| Chỉ tiêu | Development | Holdout |
| --- | ---: | ---: |
| TP được nhận định SUPPORTED | 15/15 | 13/19 |
| FP được đề xuất loại đúng | 0/6 | 0/13 |
| TP bị đề xuất loại nhầm | 0/15 | 0/19 |

Chưa có bằng chứng về giảm FP trong thực nghiệm này. Các con số thuộc phiên bản v2.2.5, không phải kết quả suy luận mới của v2.2.6. Việc kiểm chứng lại dữ liệu lưu từ lượt chạy cũ (replay) không được tính là suy luận mới. Không cung cấp nhãn Ground Truth cho prompt hoặc chạy lại holdout để chọn kết quả thuận lợi.

| Hạng mục | Trạng thái |
| --- | --- |
| `G3_RESEARCH_OUTCOME` | `PARTIAL` |
| `HOLDOUT_FREEZE_ATTESTATION` | `NOT_PROVEN` |
| `G4_STATUS` | `NOT_TESTED` |
| `CLI_R03_STATUS` | `OUTSTANDING` |

Chưa kết luận G0, G1 hoặc G2 đạt toàn bộ chỉ dựa vào kết quả demo và kiểm thử ngoại tuyến.

## Công bố mã nguồn và CI

Commit `c5a778a` cập nhật 31 tệp (6 thêm, 25 sửa, 0 xóa) sau kiểm toán độc lập. 97 Git blob của frontend giữ nguyên. So với backend đã kiểm chứng, bản tích hợp chỉ hòa giải bốn tệp tài liệu/metadata và hai tệp test; mã vận hành khớp khi đối chiếu theo Git LF. Không có lệnh triển khai lại hoặc khởi động lại hệ thống trong đợt công bố.

| Workflow tại commit c5a778a | Kết quả |
| --- | --- |
| [Kiểm tra hồ sơ nhánh chính](https://github.com/TuanKhoa1201/22025523-NTK-UET-Thesis/actions/runs/45990840625) | PASS |
| [Kiểm toán Codex và biên nhận JavisOS](https://github.com/TuanKhoa1201/22025523-NTK-UET-Thesis/actions/runs/45990840740) | PASS |
| [Kiểm tra nền tảng OpenGrep](https://github.com/TuanKhoa1201/22025523-NTK-UET-Thesis/actions/runs/45990840614) | FAIL |

Workflow OpenGrep báo lỗi `R03RelocationOfflineSyntheticTests.setUpClass` khi quét `Demo2ProtectedFalsePositive.java` (`rc=2`). Suite ghi `Ran 35 tests`, `FAILED (errors=1, skipped=12)`. Kiểm toán xác định lỗi BL-CI-R03 đã tồn tại trong backend trước hòa giải. CLI kế thừa chưa áp dụng Integration Gate giống luồng API, dẫn tới kết quả lưu không nhất quán với phép xác minh lại. Chưa có bằng chứng từ lỗi này cho thấy luồng web bị hồi quy.

Người vận hành phê duyệt ngoại lệ CI cho mốc mã nguồn này, không phê duyệt nghiệm thu CLI. Danh tính binary tại thời điểm một số lượt quét fixture, replay P11 và mức tương đương của các môi trường kiểm thử vẫn còn giới hạn. Không tắt workflow hoặc bỏ test để che lỗi. Nếu commit chỉ sửa tài liệu có CI đạt, kết quả đó không thay thế kết quả kiểm thử tại `c5a778a`.

## Lịch sử và công việc tiếp theo

[Thesis-History](https://github.com/TuanKhoa1201/Thesis-History) lưu snapshot gồm 127 commit, 5 nhánh và 1 tag, đã kiểm chứng khôi phục ngày 27/11/2026. Repository ở chế độ Private. Xem [README](../README.md) để tra cứu SHA các nhánh cũ và [quy trình cập nhật GitHub](quy-trinh-cap-nhat-github.md) trước khi thu gọn nhánh.

Công việc tiếp theo là hoàn thiện hồ sơ đối chứng, báo cáo gửi giảng viên và luận văn. Giữ nguyên hệ thống đang vận hành; chỉ xử lý các giới hạn kỹ thuật khi có phê duyệt riêng. Bảo toàn kết quả FAIL, ERROR, SKIP, BLOCKED, NOT_PROVEN và NOT_TESTED. Không công bố token, trọng số mô hình, raw HTTP, cơ sở dữ liệu vận hành hoặc mã nguồn quét riêng tư. Mỗi kết quả cần kèm lệnh chạy, phạm vi, phiên bản công cụ, bằng chứng và giới hạn kết luận.
