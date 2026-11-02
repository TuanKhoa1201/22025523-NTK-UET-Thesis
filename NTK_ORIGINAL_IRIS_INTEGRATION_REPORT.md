# NTK — Original IRIS integration, 2026-11-02

**Kết luận: PARTIAL.** NTK đã thực thi IRIS upstream và CodeQL thật, có Java database, query và source-bound taint path. Đây không còn chỉ là Javac AST được đặt tên IRIS. Tuy nhiên, chưa đủ bằng chứng để nghiệm thu đầy đủ các tác vụ LLM nguyên bản và toàn bộ bốn CWE.

## Upstream và môi trường

`/home/tuankhoa/iris` là thesis fork, remote `TuanKhoa1201/NTK-UET-Thesis`, HEAD `51c2aaf`; không được coi là upstream nguyên trạng. `src/iris.py` khác bản official hàng nghìn dòng. Thư mục này không bị ghi đè.

Clone official riêng: [iris-sast/iris v2](https://github.com/iris-sast/iris/tree/3a12f45750f58135bcc58c7fdf4c20786b600e31), exact commit `3a12f45750f58135bcc58c7fdf4c20786b600e31`, tại `/home/tuankhoa/ntk-original-iris-research-20261102/upstream-iris-v2-3a12f457`. Git HEAD và tracked status được kiểm tra trước execution. NTK import `src.iris.SAPipeline` từ clone này; không sửa source upstream. [Changelog official](https://iris-sast.github.io/iris/development/changelog.html) phân biệt v1/v2 và hỗ trợ CWE-89 của v2.

CodeQL CLI **2.25.6**, build `7c492d06b1175b24bf72bfb8e0daba1bb3a21847`; Java extractor **1.22.1**. Query packs đã có: `codeql/java-all@9.1.2`, `codeql/java-queries@1.11.4`. Không nâng environment production hoặc tải base model. Python production 3.10.20 sử dụng các packages hiện hữu trong environment iris; JDK 17 và RTX 2050 được kiểm tra trực tiếp.

## Phân biệt giấy phép

| Thành phần | License/phạm vi đã kiểm tra |
|---|---|
| OpenGrep 1.25.0 source | [LGPL 2.1](https://github.com/opengrep/opengrep/blob/v1.25.0/LICENSE) |
| IRIS upstream source | [MIT](https://github.com/iris-sast/iris/blob/3a12f45750f58135bcc58c7fdf4c20786b600e31/LICENSE) |
| GitHub CodeQL queries/libraries source | [MIT](https://github.com/github/codeql/blob/main/LICENSE); tách biệt engine |
| CodeQL CLI/engine | [GitHub CodeQL Terms](https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md), không phải engine hoàn toàn mã nguồn mở |

Lượt này chỉ dùng CodeQL cho nghiên cứu trên public OWASP BenchmarkJava/GPLv2 và Spark/Apache-2.0. Adapter yêu cầu attestation public-source identity + license trước khi chạy. Không suy quyền sử dụng cho mọi private ZIP/codebase hoặc dịch vụ hosted. Không phân phối binaries CodeQL, databases, source archives hay private dataset trong Git.

## Execution thật và thay đổi tương thích

`ntk_original_iris_worker.py` gọi `SAPipeline.run()`: external API discovery → function-parameter discovery → local API-role mining → project-specific QLL generation → native taint query → location/postprocessing → native contextual prompt. Upstream CVE evaluation được tắt; expected-results/nhãn không đưa vào scanner.

NTK extensions: isolated runtime paths; pinned existing query packs; canonical EO06 API-role protocol; strict JSON/identity/parameter validation; bounded framework-frontier scheduling; không lấy README từ fixing-commit metadata. Project description để trống: đây là giới hạn của function-source mining, không phải tái lập đầy đủ context upstream.

Database dùng `--language=java --build-mode=none --threads=1 --ram=2048`, `--search-path` trỏ Java extractor hiện hữu. Source staging chỉ có Java và license: không có Maven/Gradle descriptors hoặc project scripts. XML/properties extraction tắt vì bundle hiện tại không tự resolve các extractor phụ. No-build vẫn có thể truy vấn dependency metadata/JARs; không tuyên bố network sandbox tuyệt đối. Chưa nghiệm thu XML/framework configuration coverage.

Database thử đầu tiên thất bại ở XML discovery được giữ nguyên. Database Java-only tiếp theo thành công; query discovery native xuất BQRS/CSV thật. Sáu servlet OWASP đối chiếu byte-for-byte với Git object `f40c618c5a709afce350ef06ed2899c85cf586e9`.

Smoke sáu case: 54 API identities, 57 CUDA generations gồm posthoc; một generic constructor trả sai identity ở lượt Stage 05 strict. Backend trả `ORIGINAL_IRIS_STRICT_REQUIREMENT_NOT_MET`, không tạo scan thành công giả. Query vẫn có bốn paths: có path sai ngữ cảnh CWE do mined specs; không coi cả bốn là verified vulnerabilities.

Smoke một servlet hoàn thành 10 stage, 14 CUDA generations, 1 IRIS-only candidate, 1 raw CodeQL path. Scan đầu được lưu dưới `SCAN-20261102040240-F4CEF6`; history/trace/CWSS/report trên localhost:8780 đều HTTP 200. Path `getHeader` L46 → `argList` tại `pb.command` L66 có sáu steps, SHA nguồn `8671e8cd2686594b31abba5a17021472e25c5e3d074362a164dae2a5a4e8deda`. Candidate L66 giữ REVIEW vì chưa chứng minh execution sink/context; OpenGrep L69 giữ REPORT theo local proof. Không cộng thành hai TP.

## Stage 05 và proof policy

Original mode phân tích toàn Java inventory đã chọn, kể cả khi OpenGrep không có candidate. Union/dedup theo source/CWE/callsite, giữ path IDs và engine origins; IRIS-only không được đưa giả vào raw OpenGrep output. Fallback được ghi `NTK_JAVAC_AST_FALLBACK`; lỗi/partial có trạng thái riêng. Strict mode dừng nếu upstream chưa hoàn thành.

SARIF thread-flow phải có ít nhất hai nodes, URI local nằm trong snapshot, đúng SHA và line. Phải có thêm typed source/sink/CWE context để path nâng REPORT. Path mâu thuẫn local safe proof → REVIEW. Không tìm thấy path, LLM negative hoặc parser failure không phải safe proof. CWSS không quyết định triage.

Cache binds source manifest/commit, upstream/query templates, CodeQL version/build, worker/adapter/prompt code, base weights, adapter và build/policy. Cache hit thật đã kiểm tra: zero fresh inference. Policy đổi làm cache miss; cancellation dừng process group mới, không chạm demo.

## Qwen compatibility và artifacts

EO06 LoRA SHA `176b9b32ada029ba38a561b0937ccb75cb18c720979dbb58824fdcc112d2ce84`. Training metadata xác nhận tác vụ API-role: Track B 781, Track A 275, validation 166; không có bằng chứng checkpoint được huấn luyện cho native function-source hoặc posthoc vulnerability reasoning. Posthoc đã chạy thật nhưng có câu trả lời logic sai; chỉ lưu advisory, không dùng negative để SUPPRESS.

HF offline, `local_files_only=True`, cloud calls disabled, API-key environment loại khỏi worker, Python HTTP/socket outbound bị chặn. Generation được khóa liên process và kiểm tra input/output `cuda:0`. Không retrain hoặc đổi adapter.

Logs/requests/SARIF/query output tại ignored `work/original-iris-engineering-20261102/`; databases/source staging tại ext4 research root nêu trên. `original-iris-smoke-v1.log`, `stage05-fresh-result.json`, `stage05-single-fresh-result.json`, `research-api-acceptance.json`, `original-iris-cache-hit.json` chứa receipts thật.

Lượt release HTTP strict `SCAN-20261102043446-FCD123` thực thi 14 CUDA generations mới. Lượt `SCAN-20261102044459-B082A2` xác minh sửa sparse scope thành PARTIAL_BOUNDED, sử dụng cache hợp lệ với zero inference mới. Không dùng nhãn FULL sai của record đầu để tuyên bố full Benchmark coverage. Xem [nghiệm thu cuối](NTK_FINAL_ENGINE_ACCEPTANCE.md) cho code commits và trạng thái đầy đủ.
