# Checklist nghiệm thu báo cáo tiến độ lần 1

Ngày đối chiếu: 11/11/2026, Prompt 11.3. Commit triển khai laptop đã push:
[`7bd442d0ccca08cb089dd01762237cb62fe88698`](https://github.com/TuanKhoa1201/22025523-NTK-UET-Thesis/commit/7bd442d0ccca08cb089dd01762237cb62fe88698),
nhánh `v2/advisor-m1-proof-20261111`.

**PASS** chỉ áp dụng phạm vi ghi trong hàng; **PENDING** là chưa có bàn giao đủ
bằng chứng tương đương, không có nghĩa đã chạy và thất bại; **FAIL** dùng khi
phép nghiệm thu tương ứng có bằng chứng thất bại. Không có FAIL hiện được xác lập
trong checklist này. Không dùng unit test/mock để thay runtime thật.

Nguồn đối chiếu: `REQUIREMENTS_MATRIX.md` trong thư mục riêng `_advisor_sources`,
các tài liệu giảng viên đã đối chiếu trong báo cáo CLI và yêu cầu Prompt 11.3.
Matrix có ghi một số kết quả máy chủ lịch sử; chúng không thay thế bàn giao
Prompt 12-R hiện tại. Không sao chép tài liệu riêng lên public repository.

Quy ước bằng chứng:

- **E** = `C:\Users\HP\NTK-M1-Runtime\proof-20261111-224908-bf784076` (laptop, ngoài Git).
- **R** = [ADVISOR_M1_ORIGINAL_CLI_PROOF.md](ADVISOR_M1_ORIGINAL_CLI_PROOF.md).
- **P** = [ADVISOR_REPORT1_CLI_APPENDIX.md](ADVISOR_REPORT1_CLI_APPENDIX.md).
- Với hồ sơ máy chủ chưa nhận, ghi rõ **chưa bàn giao đường dẫn**, không đặt một
  đường dẫn giả như thể artifact đã tồn tại.

| Nhóm / yêu cầu | Trạng thái | Đường dẫn bằng chứng hiện có hoặc còn thiếu | Người phụ trách | Điều kiện nghiệm thu |
| --- | --- | --- | --- | --- |
| 1. Upstream đúng commit/tree, giấy phép; patch OpenGrep áp dụng trên full checkout laptop | PASS | `pinned_upstream_tree.json`; `E/prepared/preparation.json`, `patch-results.json`, `ntk-local-overlay.patch`; R mục 2–3 | Codex; sinh viên chạy laptop | Pin `2c79a58…`, tree `c0ab3e…`, 96 tệp; check/apply 0/0; phân biệt upstream, patch thầy, overlay NTK; giữ MIT |
| 2. Lệnh cài đặt và tái lập laptop | PASS | `E/dependencies.stdout.txt`, `E/proof.json`; P mục A/C; R mục 5 | Codex; sinh viên chạy laptop | Phiên bản cụ thể; command/cwd/exit có log; không cài RAG/cloud; output mới không ghi đè evidence |
| 3a. CLI kế thừa thực thi OpenGrep thật trên laptop | PASS | `E/cli-help.*.txt`, `cli-scan.*.txt`, `capture/cli-origin.json`, `proof.json` | Codex; sinh viên chạy laptop | `semgrepai.__main__` → `semgrepai.cli.scan`; scan exit 0, hook hoàn tất, hash code khớp, không import dịch vụ bị cấm |
| 3b. Tái lập và nghiệm thu CLI trên máy chủ | PENDING | Chưa bàn giao đường dẫn proof/log máy chủ Prompt 12-R; P mục C là hướng dẫn, không phải output server | JavisOS | Full checkout ghim; log lệnh/phiên bản/exit; JSON/SARIF/manifest và handoff kiểm toán thành công trên máy chủ |
| 4. JSON/SARIF và findings qua handoff laptop | PASS | `E/capture/opengrep.json`, `opengrep.sarif`, `scan-manifest.json`; `E/triage/input.opengrep.json`, `evidence.json`, `handoff-verification.json` | Codex; sinh viên chạy laptop | 4/4/4; khớp multiset full rule ID + tệp + vị trí; raw JSON/SHA-256 không đổi; không mất finding ID/trace |
| 5. Dataflow trace và bằng chứng Java laptop | PASS | `E/capture/opengrep.json` (`extra.dataflow_trace`); `E/triage/evidence.json`; `fixtures/java/`; P mục D | Codex | Hai ví dụ CWE-22/89 khớp source, sink, biến trung gian, dòng/cột/offset; hash 2 tệp Java và 16 artifact khớp |
| 6. Qwen local LIVE | PENDING | Chưa bàn giao đường dẫn HTTP/runtime receipt và cấu hình model máy chủ Prompt 12-R; evidence E dùng `--no-llm` | JavisOS | Model/Ollama/params/version, HTTP thực nhận và bằng chứng runtime được kiểm toán; phân biệt REPLAY/LIVE/mock, không gọi cloud |
| 7. Hai đến ba phản hồi Qwen thật | PENDING | Chưa bàn giao đường dẫn response/assessments thật kèm raw scan và nguồn tương ứng | JavisOS; sinh viên rà soát | 2–3 phản hồi thật ghép đúng finding/scan hash; giữ lỗi và UNDETERMINED; kiểm tra citation, không coi citation đúng là kết luận bảo mật chắc chắn đúng |
| 8. JSONL/SQLite review queue được kiểm toán | PENDING | Chưa bàn giao đường dẫn JSONL, SQLite và log kiểm toán máy chủ; `E/triage/evidence.json` chỉ chứng minh handoff | JavisOS | Ghép assessment/finding đúng; trạng thái mô hình tách khỏi quyết định người duyệt; REFUTED không tự ẩn/xóa; giữ row và lịch sử |
| 9. Human confirmation, reopen và stale-source | PENDING | Chưa bàn giao đường dẫn bản sao Java, hash trước/sau và lịch sử quyết định cùng lượt demo Prompt 12-R | JavisOS; sinh viên kiểm duyệt | Xác nhận giả → ẩn queue mặc định → xem history → reopen; nguồn đổi/thiếu chặn confirm-false và yêu cầu quét lại; actor demo ghi SCRIPTED-DEMO, không sửa lịch sử |
| 10. So sánh OpenGrep-only / OpenGrep+Qwen | PENDING | Chưa bàn giao đường dẫn bảng ghép cặp, raw scan cố định, nhãn và output Qwen của lượt nghiệm thu | JavisOS; sinh viên phụ trách nhãn | Cùng raw scan/nguồn/rules; có nhãn độc lập hoặc ghi rõ tổng hợp/chưa quyết định; báo cả lỗi và cảnh báo thật bị đề xuất loại nhầm; không suy ra precision/recall khi thiếu nhãn |
| 11. Công bố giới hạn thực nghiệm CLI | PASS | R mục 1/4/6; P mục E | Codex; sinh viên tổng hợp | Nêu fixture tổng hợp, chưa benchmark lớn, không Qwen trong lượt này, server PENDING và không tuyên bố full RAG/web PASS |
| 12a. Nguồn Markdown phụ lục CLI lần 1 | PASS | P mục A–F; R mục 7; checklist này | Codex | Có môi trường, nguồn gốc, diff, lệnh, exit, SHA-256, 2 ví dụ, giới hạn; PASS cho nguồn Markdown, chưa xác nhận bố cục PDF |
| 12b. Ghép phụ lục và chốt báo cáo tiến độ cuối cùng | PENDING | Chưa bàn giao đường dẫn báo cáo tổng hợp/PDF và commit hồ sơ thực nghiệm máy chủ | JavisOS; sinh viên | Bổ sung hồ sơ Prompt 12-R; kiểm tra thống nhất bảng số liệu/commit/đường dẫn; rà soát bản trình bày cuối trước khi gửi thầy |

Kết luận trong phạm vi hồ sơ hiện có: **M1 CLI laptop PASS; server acceptance
PENDING**. `E/proof.json` vẫn là `SERVER_RUNTIME_PENDING`, không sửa artifact để
đổi nhãn nghiệm thu. Không suy rộng PASS của 5 nhóm CLI laptop thành PASS của Qwen,
review queue hoặc toàn bộ khóa luận.

Codex chỉ cập nhật ba tệp Markdown trong `v2/baseline/` ở đợt 11.3. Không thực hiện
auditor máy chủ, REPLAY/LIVE, Qwen, SQLite, bảng A/B hoặc tạo PDF thay JavisOS.
