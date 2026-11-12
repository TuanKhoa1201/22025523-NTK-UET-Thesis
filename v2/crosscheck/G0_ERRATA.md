# Đính chính hiện vật lịch sử

Không sửa raw, nhãn, manifest, SQLite hoặc register gốc. ERRATA_ISSUED không đổi FAIL lịch sử thành PASS.

## Sáu sai lệch đã có

| ID | Trường | Bản cũ | Theo nguồn | Xử lý |
|---|---|---|---|---|
| OLD-002 | manual.total_seconds | 182.00 | 181.70 | Đính chính; không đổi GT/metrics raw |
| OLD-003 | manual.mean_seconds | 9.10 | 9.09 | Đính chính; không đổi GT/metrics raw |
| OLD-030 | annotator_rationale / sanitizer_or_reason | Nhãn giải thích external_thing_interface_constant_return | Nguồn getTheValue là hằng; Thing1/Thing2 bảo toàn đối số | Đính chính; không đổi GT/metrics raw |
| OLD-031 | annotator_rationale / sanitizer_or_reason | Rationale dùng (7*18)+106 và nói nhánh true trả hằng | (7*42)-106 = 188 <= 200: chọn param đã hằng từ source | Đính chính; không đổi GT/metrics raw |
| OLD-038 | Arm D FP CWE-22 | Tài liệu dòng 51 ghi 4 SUPPORTED / 6 UNDETERMINED | {"REFUTED": 0, "SUPPORTED": 6, "UNDETERMINED": 4} | Đính chính; không đổi GT/metrics raw |
| OLD-039 | Arm D FP CWE-89 | Tài liệu dòng 57 ghi cả 10 FP SUPPORTED | {"REFUTED": 0, "SUPPORTED": 8, "UNDETERMINED": 2} | Đính chính; không đổi GT/metrics raw |

## Chín cơ chế Java đã đối chiếu trực tiếp

Các diễn giải dưới là rà soát tĩnh nguồn đã khớp blob OWASP, không phải chạy Java mới. Ba mô tả map thiếu chi tiết không đồng nghĩa nhãn sai.

| Case | Nhãn giữ nguyên | Phân loại | Cơ chế đúng |
|---|---|---|---|
| 00863 | FALSE_POSITIVE | Sai cơ chế | 45 source hằng getTheValue; Thing1/Thing2 truyền đối số; sink 51 |
| 01746 | FALSE_POSITIVE | Sai phép toán/nhánh | 45 source hằng; 94-96: (7*42)-106=188, nhánh false chọn param; sink 66 |
| 01752 | FALSE_POSITIVE | Diễn giải quá chung | 45 source hằng; put keyB 80/get keyB 82 giữ param; sink 60-61. Nhãn nhận không nói keyA |
| 00864 | FALSE_POSITIVE | Thiếu một cơ chế | 45 source hằng; 50-56 list remove(0)/get(1) lấy hằng; sink 59 |
| 00062 | TRUE_POSITIVE | Thiếu bước trung gian | 54-60 cookie; map keyB put 69/get 71; sink 78 |
| 01006 | TRUE_POSITIVE | Thiếu bước trung gian | 54-60 cookie; helper 96/98 map keyB giữ param; SQL 68, sink 73-74 |
| 01156 | TRUE_POSITIVE | Thiếu bước trung gian | 44-51 header; helper 100/102 map keyB giữ param; URI 64-71/File 72 |
| 00949 | TRUE_POSITIVE | Peer mô tả sai nhánh | 54-60 cookie; helper 91/93 gán bar=param rồi return; sink 68-69. Không có toán tử ba ngôi |
| 00950 | TRUE_POSITIVE | Peer mô tả sai nhánh | 54-60 cookie; helper 90/92 gán bar=param rồi return; sink 68. Không có toán tử ba ngôi |

Hai mô tả ba ngôi 00949/00950 trong bàn giao JavisOS là sai; mã thực tế chỉ gán và trả param. Không chấp nhận tự động cả chín mô tả của peer. SHA nguồn và rationale cũ có trong JSON.

## SHA bảng bắt cặp

Raw E và Git 86636b9: `e19fc5140be6548eca8d62cb7c01f02baa96f4a493753015a7596c9616453347`, 34388 byte. Khớp byte, 40 alert × 27 cột; UTF-8 không BOM, LF.

Bàn giao JavisOS tại bf19b5e ghi `e19fc514e04d786ab3465d83eb66494955e6507d8b5b2a04b8ca29c469062ae5` / 35.627 byte: không khớp. Không phải chênh CRLF/LF giữa hai bản đã có. Không có bản byte mang hash peer để suy ra nguyên nhân; đính chính lời khai, không sửa raw.

Đây là lỗi truy xuất trong tài liệu peer, không làm thay đổi kết quả tái tính từ bản raw đã định danh. Không cần chạy lại model.

## Publication additions E1?E3 (PENDING advisor approval)

These corrections cite Antigravity's supplied independent review, sections 3 and 5.3; they are peer source-review findings, not new local runtime evidence. Review SHA-256: `0c4852e46242b69e4322fbf0e74d7a8d6c3ec3c63467488ef3f2a20c8980cdfc`. No historical data is edited and no approval is inferred.

| ID | Historical claim / location | Correction | Evidence / status |
|---|---|---|---|
| E1 | METRICS_BY_CWE A/B 0.0 ms; PAIRED_EVALUATION.md:31 <15 ms; CHUONG_4:59; POST_REPORT_IMPLEMENTATION_HANDOVER:115 | A/B latency NOT_MEASURED; zero and <15 ms are not measured results | Existing 19 NOT_MEASURED register entries; PENDING |
| E2 | REAL_PROJECT_EVALUATION:37,60; CHUONG_4:82 place @Pattern in WebGoatUser | @Pattern is UserForm.java:19; RegistrationController:44 uses @Valid, OAuth caller :54 does not pass this validator | Peer review 5.3; #10 remains LABEL_REVIEW_REQUIRED; PENDING |
| E3a | POST_REPORT_IMPLEMENTATION_HANDOVER:122,124 calls BenchmarkTest00002/00033 FP | Both are true in pinned OWASP CSV | Peer review section 3; PENDING |
| E3b | CASE_STUDIES_CWE22_CWE89 describes 01110/01215 as list/HashMap | Actual mechanism switch(switchTarget), lines 107/110 and 82/85 respectively | Peer source review section 3; PENDING |
| E3c | POST_REPORT_IMPLEMENTATION_HANDOVER:80; CHUONG_4:7 claims 14 rules | Actual snapshot has 9 rules | Published scan receipts, rules_count=9; PENDING |
| E3d | CHUONG_4:14 development scan hash | Correct development scan hash is in G0_FINAL_RESOLUTION.json scans.development.scan_sha256 | Published scan receipt; PENDING |

Nine Java explanations, Arm D FP counts and the incorrect peer paired-CSV hash are retained above. Exact check IDs, alert IDs, expected/actual and source SHA-256 for issued errata are in G0_ERRATA_REGISTER.json and G0_RESOLUTION_REGISTER.csv. Every issued entry is PENDING, not APPROVED. E1?E3 are supplementary publication corrections, not exemptions for any mandatory failure. Source hashes not independently supplied for individual E2/E3 documents are not invented; the peer-review hash identifies that evidence and local re-attestation is not claimed.
