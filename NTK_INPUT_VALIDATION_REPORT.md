# NTK — Input validation acceptance, 02/11/2026

NON_JAVA_INPUT_HANDLING=PASS; ZERO_FINDINGS_HANDLING=PASS; MIXED_LANGUAGE_SOURCE_HANDLING=PASS trong phạm vi hợp đồng đã kiểm thử. Không có tuyên bố “100% an toàn” khi 0 findings. Backend không chạy script, Maven/Gradle hay uploaded code.

## Kết quả thực

| Input type | Expected result | Actual result | API status/code | Frontend result | Test status |
|---|---|---|---|---|---|
| ZIP python-only | FAILED | FAILED | 202 submit; 200 poll FAILED / NO_JAVA_FILES_IN_ZIP | Browser upload verified | PASS |
| ZIP javascript-only | FAILED | FAILED | 202 submit; 200 poll FAILED / NO_JAVA_FILES_IN_ZIP | Browser upload verified | PASS |
| ZIP typescript-only | FAILED | FAILED | 202 submit; 200 poll FAILED / NO_JAVA_FILES_IN_ZIP | Browser upload verified | PASS |
| ZIP cpp-only | FAILED | FAILED | 202 submit; 200 poll FAILED / NO_JAVA_FILES_IN_ZIP | Browser upload verified | PASS |
| ZIP go-only | FAILED | FAILED | 202 submit; 200 poll FAILED / NO_JAVA_FILES_IN_ZIP | Browser upload verified | PASS |
| ZIP readme-only | FAILED | FAILED | 202 submit; 200 poll FAILED / NO_JAVA_FILES_IN_ZIP | Browser upload verified | PASS |
| ZIP empty | FAILED | FAILED | 202 submit; 200 poll FAILED / NO_JAVA_FILES_IN_ZIP | Browser upload verified | PASS |
| ZIP mixed | COMPLETED | COMPLETED | 200 / OK | Browser upload verified | PASS |
| ZIP nested-java | COMPLETED | COMPLETED | 200 / OK | Browser upload verified | PASS |
| ZIP zero-java | COMPLETED | COMPLETED | 200 / OK | Browser upload verified | PASS |
| ZIP fake-java | FAILED | FAILED | 202 submit; 200 poll FAILED / JAVA_SYNTAX_ERROR | Browser upload verified | PASS |
| ZIP syntax-error | FAILED | FAILED | 202 submit; 200 poll FAILED / JAVA_SYNTAX_ERROR | Browser upload verified | PASS |
| ZIP traversal | FAILED | FAILED | 202 submit; 200 poll FAILED / ZIP_SLIP_PATH_TRAVERSAL_REJECTED | Results browser / API / safety regression | PASS |
| ZIP bytecode | FAILED | FAILED | 202 submit; 200 poll FAILED / ZIP_FORBIDDEN_EXECUTABLE_OR_BYTECODE_REJECTED | Results browser / API / safety regression | PASS |
| ZIP corrupt | REJECTED_OR_FAILED | FAILED | 202 submit; 200 poll FAILED / MALFORMED_ZIP_ARCHIVE_REJECTED | Browser upload verified | PASS |
| ZIP renamed-zip | REJECTED_OR_FAILED | REJECTED | 400 / INVALID_ZIP_MAGIC_BYTES_REJECTED | Browser upload verified | PASS |
| ZIP verified-safe | COMPLETED | COMPLETED | 200 / OK | Results browser / API / safety regression | PASS |
| ZIP prepared-safe | COMPLETED | COMPLETED | 200 / OK | Results browser / API / safety regression | PASS |
| ZIP path-safe | COMPLETED | COMPLETED | 200 / OK | Results browser / API / safety regression | PASS |
| ZIP encoded-safe | COMPLETED | COMPLETED | 200 / OK | Results browser / API / safety regression | PASS |
| ZIP unknown | COMPLETED | COMPLETED | 200 / OK | Results browser / API / safety regression | PASS |
| GitHub python | FAILED | FAILED | 202 submit; 200 poll FAILED / NO_JAVA_FILES_FOUND | Browser code verified | PASS |
| GitHub javascript | FAILED | FAILED | 202 submit; 200 poll FAILED / NO_JAVA_FILES_FOUND | Browser code verified | PASS |
| GitHub c | FAILED | FAILED | 202 submit; 200 poll FAILED / NO_JAVA_FILES_FOUND | Browser code verified | PASS |
| GitHub go | FAILED | FAILED | 202 submit; 200 poll FAILED / NO_JAVA_FILES_FOUND | Browser code verified | PASS |
| GitHub readme | FAILED | FAILED | 202 submit; 200 poll FAILED / NO_JAVA_FILES_FOUND | Browser code verified | PASS |
| GitHub mixed | COMPLETED | COMPLETED | 200 / OK | API + shared error contract; no dedicated browser submission | PASS |
| GitHub invalid-url | REJECTED | REJECTED | 400 / HOST_NOT_IN_GITHUB_ALLOWLIST | API + shared error contract; no dedicated browser submission | PASS |
| GitHub nonexistent | FAILED | FAILED | 202 submit; 200 poll FAILED / GIT_CLONE_FAILED | API + shared error contract; no dedicated browser submission | PASS |
| GitHub invalid-branch | FAILED | FAILED | 202 submit; 200 poll FAILED / GIT_CLONE_FAILED | Browser code verified | PASS |
| GitHub invalid-commit | FAILED | FAILED | 202 submit; 200 poll FAILED / GIT_CHECKOUT_FAILED | Browser code verified | PASS |
| GitHub no-java-subpath | FAILED | FAILED | 202 submit; 200 poll FAILED / NO_JAVA_FILES_MATCHED_FILTERS | Browser code verified | PASS |
| ZIP symlink | Reject | ZIP_SYMLINK_ENTRY_REJECTED | Service regression | Shared error handler | PASS |
| ZIP size/entries/uncompressed/file/ratio | Reject with bounded fixture | All 5 limits rejected | Service regression, small limits | Frontend size validation + shared errors | PASS |
| Local directory non-Java/Java/mixed | Java-only; do not alter source | Real parser/OpenGrep; zero candidates; symlink preserved | Library mode test; HTTP local mode 400 MISSING_SCAN_SOURCE | No arbitrary path input exposed | PASS |
| Valid Java no candidate | Complete, 0 triage, no Qwen/CWSS | Petclinic + plain + mixed + nested ZIP | 200 scan/report; stage06 SKIPPED | Empty state + Java/rules coverage verified | PASS |
| Safe / UNKNOWN candidate | SUPPRESS only proof; UNKNOWN REVIEW | constant/prepared/encoded SUPPRESS; unknown REVIEW | 200, audit finding retained | Rows and triage retained | PASS |
| Guarded path intended safe | Conservative if guard unsupported | REVIEW, not verified safe | 200, TI=D | Evidence blocker retained | PASS with analysis limitation |


21 ca ZIP/safe/unknown và 11 ca GitHub được gửi API thật; library regressions dùng parser/OpenGrep thật. GitHub mixed dùng repository NTK thật, bounded 2 Java, không phân tích phần Python/JS. No-Java Git/ZIP có inventory=0, terminal FAILED, không hoàn tất 10 stages và không Qwen. Source tồn tại nhưng filter/subpath loại hết dùng NO_JAVA_FILES_MATCHED_FILTERS; không đánh đồng với lỗi Git clone/checkout.

Các public Git tests: pypa/sampleproject, jonschlinkert/is-number, jserv/mini-arm-os, golang/example, octocat/Hello-World; refs/checkout SHA của lần test được giữ trong responses local. Repo không tồn tại và branch không tồn tại cùng GIT_CLONE_FAILED do download; commit fetch không tồn tại GIT_CHECKOUT_FAILED. URL ngoài allowlist bị 400 HOST_NOT_IN_GITHUB_ALLOWLIST trước clone. Không giả tạo CVE hay chạy mã của các repo.

## Contract và an toàn

- `/api/scan-jobs`: POST multipart/raw ZIP/JSON trả 202 + job_id; GET poll 200 với lifecycle QUEUED/RUNNING/COMPLETED/FAILED. Lỗi validation trước tạo job trả 400; job được chấp nhận nhưng không có Java kết thúc FAILED. Không HTTP 500 trên các ca đã thử.
- `/api/scans/zip`: kiểm tra thêm sync non-Java **422 NO_JAVA_FILES_IN_ZIP**, plain renamed ZIP **400 INVALID_ZIP_MAGIC_HEADER_REJECTED**. Async precheck tương đương dùng alias **INVALID_ZIP_MAGIC_BYTES_REJECTED**; giữ compatibility, không đổi contract để khớp tên giả định.
- Symlink, traversal, executable/bytecode, upload bytes, entries, decompressed Java bytes, per-file size và ratio được kiểm tra trước phân tích. Payload giới hạn nhỏ; ratio fixture chỉ khoảng 70 KiB giải nén, không thử gây cạn tài nguyên. Không tải archive 25 MiB để kiểm tra bằng sức brute force.
- Scan upload hiện không yêu cầu bearer auth trên API loopback; không tuyên bố đây là dịch vụ multi-user Internet. CWSS mutation auth giữ nguyên. Không mở local-directory HTTP API: request `/etc` bị 400 MISSING_SCAN_SOURCE. Các tests local chỉ gọi library trực tiếp ở thư mục tạm có kiểm soát.
- Mixed ZIP bỏ qua source Python/JS, không giải nén/thực thi chúng; binary/bytecode/script restrictions khác giữ nguyên. API công bố Java-only coverage và non_java_files_ignored; FULL Java không có nghĩa toàn repository an toàn.
- JavacTask parse-only xác nhận cú pháp, không chạy annotation processors/build hoặc mã không tin cậy. `.java` giả và syntax errors dừng với JAVA_SYNTAX_ERROR trước OpenGrep/Qwen. Đây không phải Java type-check/link/compile mọi dependency.

## Bản sửa và website

Scanner đã có ZIP upload dùng endpoint cũ, file/extension/size validation, multipart boundary đúng, upload/scanning/completed/failed và khóa double-click bằng ref đồng bộ. Git ref/subpath/bounded scope có thể khai báo. Backend trả cấu trúc lỗi; UI tiếng Việt giữ `[error_code]` thật. Kết quả rỗng hiện đúng successful empty state, số Java/rules và cảnh báo phạm vi, không synthesize score hay metric. Candidate SUPPRESS vẫn là audit row; REVIEW còn proof blockers; failed input không có link kết quả thành công giả.

Đã sửa race: reset job_id khi gửi yêu cầu mới kích hoạt effect restore scan cũ và ghi đè HTTP error. Restore nay dừng khi đang submit/busy; chỉ clear active selection của panel mới, không xóa history. Browser double-click và nhiều lần upload liên tiếp được kiểm tra thật.

Đã sửa local inventory từng unlink source symlink: nay chỉ bỏ qua và giữ file gốc. Đã sửa cache DrvFS: read-only Git status bỏ qua executable bit (core.filemode=false cho riêng lệnh), vẫn kiểm tra bytes/untracked/commit và SHA; regression chứng minh sửa nội dung thật vẫn bị chặn. Không sửa Git config của source/worktree.

Backend final: **237/237 tests PASS**, có Real25 với đúng NTK_REAL25_DIR, ZIP limits, source SHA, no-unnecessary-LLM, CWSS no-empty-score, lifecycle/report/index tests. Frontend **17/17 tests PASS**, build **445 modules PASS**; còn cảnh báo bundle >500 kB. Browser thật Edge Edg/156.0.4314.58: **33 input/project checks PASS**, **12 trang demo PASS**, report download và replay 10 stages PASS. Screenshots và browser failures trước sửa được giữ local để audit; kết quả cuối có 0 runtime exceptions. Không cài thêm dependency browser.

History được kiểm tra thêm sau khi xóa riêng cache của browser test trên origin 5174: **92/92 scan hiện**, gồm đủ 8 project IDs; failed jobs không thành successful empty scans. Đã sửa việc chỉ lấy trang đầu 25 và dùng cache 50 làm danh sách hiển thị. Cache vẫn tối đa 50; UI merge trực tiếp authoritative summaries và giữ hide/restore cục bộ. Client tải tối đa 20 trang × 100 summaries; vượt giới hạn sẽ cảnh báo còn lịch sử cũ, không xóa backend. Có 4 regression tests mới cho pagination/cap/merge/hiding. Công cụ `tools/verify-history-browser.cjs` chạy kiểm tra thật, không mock kết quả.
