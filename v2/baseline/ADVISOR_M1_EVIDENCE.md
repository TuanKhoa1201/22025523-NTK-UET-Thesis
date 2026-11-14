# Bằng chứng M1 gửi giảng viên

## Kết luận và nguồn gốc

**PASS cho bản chuyển scanner/CLI sang OpenGrep trên mẫu Java tổng hợp.**
Chưa khẳng định toàn bộ ứng dụng simple_semgrepAI (web/RAG/LLM) đã chạy hoặc đã
đánh giá trên dự án thực tế.

- Upstream: [hardw00t/simple_semgrepAI, commit 2c79a58](https://github.com/hardw00t/simple_semgrepAI/tree/2c79a58a16d11e9dea3723e30d2a7faffba7bdc9),
  phiên bản 0.2.0, MIT (copyright 2025 hardw00t).
- Sáu tệp nguyên bản và Git blob SHA nằm trong `upstream/PROVENANCE.json`;
  kiểm chứng byte nguyên vẹn, không sửa whitespace upstream.
- Kế thừa: giao diện `SemgrepScanner.scan`, envelope JSON/SARIF, metadata,
  code-context, references/security-pattern helpers. Sửa: executable OpenGrep,
  cấu hình luật Java local, CLI chỉ quét, lưu lỗi/bằng chứng, đọc và giữ nguyên
  `extra.dataflow_trace` thay vì chỉ tìm trace ở top-level.
- `opengrep.patch` sinh tự động bởi `make_patch.py`, áp lên ba tệp tương ứng
  trong snapshot để tái tạo scanner/config/CLI. Package entrypoints và license
  bổ sung nằm trong `fork/`; đây là extraction, không phải patch chạy cả web upstream.

## Lệnh PowerShell tái lập

Chạy từ workspace root, Python 3.13.3 và OpenGrep **1.20.0** đã được dùng thực tế.
Chọn thư mục output mới nếu tên dưới đây đã tồn tại.

```powershell
python v2/baseline/make_patch.py
python v2/baseline/verify_patch.py
python -m unittest discover -s v2/baseline/tests -v
$env:PYTHONPATH = Join-Path (Get-Location) 'v2/baseline/fork'
python -m semgrepai v2/baseline/fixtures/java --rules-path v2/baseline/rules/java.yml --output-dir v2/baseline/evidence/advisor-run
python v2/baseline/verify_real.py v2/baseline/evidence/advisor-run
```

`verify_patch.py` kiểm tra sáu blob, so patch với kết quả generator và thực sự
chạy `git apply --check`, `git apply` trên bản sao snapshot trong thư mục tạm;
ba tệp kết quả khớp fork. `core.autocrlf=false` chỉ áp dụng trong lệnh kiểm chứng.
`.gitattributes` giữ byte snapshot/patch khi checkout Windows, không che lỗi whitespace.

Lệnh engine thực tế được lưu thành argv trong `json.command.json` và
`sarif.command.json`: `opengrep scan --config <local-java.yml> --json` hoặc
`--sarif`, kèm `--dataflow-traces --no-git-ignore --disable-version-check
--jobs 1 --timeout 60 --include *.java <target>`. Scanner đặt log/settings local
trong output; không gọi cloud LLM.

## Kết quả thật của đợt kiểm chứng này

Đầu vào: `fixtures/java/Vulnerable.java`, `fixtures/java/Safe.java`;
luật: `rules/java.yml` (4 luật taint Java viết trong đồ án).

| Mục | Kết quả quan sát |
| --- | --- |
| Version / JSON / SARIF subprocess | Exit 0 / 0 / 0 |
| JSON | 2 file được quét, 4 findings, `errors: []` |
| SARIF | 4 results |
| Safe.java | Được quét, 0 findings |
| Trace | 16 vị trí source/intermediate/sink khớp byte offset và dòng/cột nguồn |
| M1 tests | 24 PASS: 22 bài cũ + 2 bài patch/provenance |

Ví dụ từ JSON thật, file `Vulnerable.java` (cột kết thúc không bao gồm ký tự tại cột đó):

| CWE / rule suffix | Source | Intermediate | Sink |
| --- | --- | --- | --- |
| CWE-22 / `ntk.java.cwe22` | 5:24–49, `req.getParameter("input")` | `input` dòng 5, `forwarded` dòng 6 | 7:9–28, `new File(forwarded)` |
| CWE-89 / `ntk.java.cwe89` | 5:24–49, cùng source | Cùng hai biến trên | 10:9–80, `stmt.executeQuery("SELECT * FROM users WHERE name='" + forwarded + "'")` |

JSON chứa tagged `CliLoc` ở `extra.dataflow_trace.taint_source/taint_sink` và
`intermediate_vars`. Rule ID đầy đủ trong lần chạy này có tiền tố
`v2.baseline.rules.`; không dùng riêng rule ID hoặc vị trí để ghép assessment.

Bằng chứng local (Git ignore): `evidence/advisor-m1/` gồm version, command argv,
stdout/stderr, exit code, `opengrep.json`, `opengrep.sarif`, `findings.json`,
`verification.json`; `evidence/patch-verification.json`; `evidence/p0-m1-tests.txt`.
Chỉ mẫu Java an toàn/tổng hợp và mã kiểm chứng được đưa vào source control.

## Demo phát hiện nguồn thay đổi

```powershell
python -m v2.triage.demo_freshness --output-dir v2/triage/evidence/freshness-run
```

Script quét thật bản sao tạm của fixtures, ghi SHA-256 và kiểm tra nguồn chưa đổi;
thực hiện một quyết định **confirm-true** qua API review với actor ghi rõ
`SCRIPTED-SYNTHETIC-DEMO` (không giả danh người thật), rồi thêm comment vào bản sao.
Yêu cầu `confirm-false` / FALSE_POSITIVE với hồ sơ cũ bị từ chối: `source hash
mismatch; rescan required`. History trước/sau giống nhau, vẫn chỉ có quyết định
confirm-true ban đầu; không có false confirmation thành công. Fixture gốc không đổi.

Kịch bản đã chạy PASS, kết quả ở
`v2/triage/evidence/freshness-p0/freshness-demo.json`. Source copy tạm được dọn sau
demo; không dùng database demo đó để tiếp tục review trên nguồn đã bị dọn.

## Giới hạn và phân loại bằng chứng

OpenGrep và patch apply ở trên chạy **thật**. Unit test subprocess/Ollama có mock,
được ghi nhãn; demo freshness tắt LLM, review API là thao tác kịch bản tổng hợp.
Không có bằng chứng Qwen thật mới trong đợt này.

Bốn luật chỉ nhận một số `getParameter` source và sink; chưa bao phủ framework,
sanitizer, interprocedural flow hay toàn bộ CWE. Placeholder Request/Response/Statement
không cần biên dịch cho demo phân tích cú pháp này. Không suy ra precision/recall
từ hai fixture. Toàn bộ web/RAG/LLM upstream, gói ZIP riêng của thầy và nghiệm thu
Qwen thật vẫn là các phạm vi chưa được chứng minh ở đây.
