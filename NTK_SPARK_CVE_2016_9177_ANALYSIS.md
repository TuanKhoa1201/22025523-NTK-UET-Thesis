# NTK — Spark CVE-2016-9177

**Chưa chứng minh phân biệt đúng vulnerable/fixed.** Khác biệt tổng findings không được dùng làm kết quả nghiệm thu CVE.

## Ground truth và nguồn

Hai source cùng repository [perwendel/spark](https://github.com/perwendel/spark): vulnerable `ce57dfb949ed183405f75dee8cf3262b45c9b3b5`; fixed `efcb46c710e3f56805b9257a63d1306882f4faf9`. Git status sạch và mọi Java byte được đối chiếu Git objects trước tạo database. Đây không phải suy luận từ tên thư mục.

[Issue #700](https://github.com/perwendel/spark/issues/700) liên kết CVE và arbitrary file read qua static resources; [PR #701](https://github.com/perwendel/spark/pull/701) liên kết merge fixed nói trên. Thông tin maintainer xác định bản phát hành 2.5.2 có bản sửa. Báo cáo này không khẳng định mọi path traversal khác đều được sửa.

## Luồng và diff

`AbstractResourceHandler.getResource(HttpServletRequest)` lấy `getPathInfo()` L51/L55, ghép `servletPath/pathInfo` bằng `addPaths`, rồi gọi overload `getResource(String)`. `ExternalResourceHandler` ghép base resource với path, tạo `ExternalResource`. Constructor gọi `new File(StringUtils.cleanPath(path))`; `ExternalResource.getInputStream()` L67 mở `new FileInputStream(file)`. Taint cần đi qua overload, dynamic dispatch, constructor/field và method khác; local intraprocedural AST không nối đủ chuỗi này.

Fixed thêm `DirectoryTraversal.protectAgainstForExternal(resource.getPath())` và `protectAgainstInClassPath(...)`, configuration-root state trong `StaticFilesFolder`, cùng catch riêng cho traversal detection. Guard dùng kiểm tra prefix sau xử lý slash. Không mặc định coi mọi `cleanPath`, normalization hoặc `startsWith` là sanitizer đầy đủ; cần chứng minh base/path/canonicalization và control dependence của đúng luồng.

Diff thật được lưu `work/e2e-multiproject-acceptance/spark-pair-source.diff`; source/archive lớn không commit.

## Các execution đã thực hiện

Database Java-only no-build thành công trên **168 Java vulnerable / 167 Java fixed**, lần lượt khoảng 59.47/54.86 giây. Không build/chạy ứng dụng, Maven hoặc test code.

Native IRIS CWE-22 discovery trên vulnerable có 4.884 API call rows, 799 filtered API identities và 70 function-parameter candidates. Lượt V1 tối đa 64 inference, native query chạy thành công, zero paths; 64 model outputs không có source. Upstream cache filter sắp API theo tuple alphabet nên budget hết trước HTTP source APIs. Đây là **partial mining**, không phải chứng minh absence of flow.

V2 thử lịch framework-frontier trước: vẫn 64 inference, chỉ thay thứ tự, không gán roles. Trên vulnerable model dự đoán 18 sources, 2 sinks, 44 none. Mining chưa bao phủ toàn bộ APIs/slots; function-source và posthoc cũng có thể không được thực hiện khi hết budget. Các giới hạn này phải đọc cùng raw query results ở bảng release cuối; không suy chất lượng từ số SOURCE model dự đoán.

Baseline NTK: mỗi bản 9 REVIEW, chủ yếu candidate tại method khác với chain gây CVE. OpenGrep quét explicit toàn Java lần này có 19/20 candidates; 9 main-code candidates mỗi bản như cũ, phần tăng nằm trong tests. **Khác biệt 19/20 không phân biệt CVE**; fixed còn thêm test dùng file API. Root cause coverage backend đã sửa: directory scan trước đó mặc định bỏ qua tests dù inventory tính đầy đủ.

## Kết luận kỹ thuật

Zero IRIS path với specs thiếu source/sink không xác nhận safe. Local AST thiếu interprocedural/field-state propagation; bounded native mining thiếu coverage; custom traversal guard chưa được xác minh là CodeQL barrier. Không thêm rule phụ thuộc project/CVE/commit hoặc đổi score/threshold.

Kết quả cuối: cả vulnerable/fixed ở V1 và V2 đều **zero raw thread flows**. V2 đưa HTTP sources vào budget nhưng 64 lượt vẫn chưa mining đủ JDK file sinks. Native queries hoàn thành; global analysis giữ IRIS_PARTIAL do `LOCAL_MODEL_CALL_BUDGET_EXCEEDED`. Đây không phải bằng chứng bản vá thất bại hoặc repository an toàn. Chi tiết bốn execution trong [public receipts](docs/engine-evaluation-20261102/spark-native-executions.json).

Giữ UNKNOWN/REVIEW khi không có proof phù hợp. Bản fixed không được gắn safe toàn repository. Các query/database/log receipts mới được giữ trong ignored research runtime; không dùng baseline scan làm output mới. [Báo cáo nghiệm thu](NTK_FINAL_ENGINE_ACCEPTANCE.md) ghi số paths V1/V2, durations, source coverage và blocker cuối.
