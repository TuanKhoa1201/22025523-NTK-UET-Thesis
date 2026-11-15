# G1-C4 — Kế Hoạch Tiếp Nhận Nguồn và Nghiệm Thu Runtime Trên `ADMIN-PC` (R01–R03)

Tài liệu này là quy trình thực thi chuẩn cho ứng viên **`G1-C4`** trên `ADMIN-PC` do người vận hành / JavisOS chạy sau khi kiểm toán độc lập phê duyệt. Quy trình khắc phục toàn bộ sai lệch B1/B2 được chỉ ra trong `G1_C3_RUNTIME_PLAN_DELTA_REVIEW.md` và `G1_C3_R01_R03_CHECKLIST.json`.

> [!IMPORTANT]
> - `G1-C2` (`6ebf3ec6668741a346199f860cf349332ad94eae`) giữ nguyên kết quả lịch sử **`G1_C2_RUNTIME_ACCEPTANCE_FAILED`**.
> - `G1-C3` (`236439ead654d12448bb2cf711e534a243007afd`) giữ nguyên kết luận kiểm toán cổng runtime **`RUNTIME_PLAN_REQUIRES_CORRECTION`**.
> - `G1-C4` hiện ở trạng thái **`NOT_TESTED`** đối với `REAL_OLLAMA` / `R01–R03`. Không dùng kết quả kiểm thử offline hoặc CLI `exit 0` để suy luận `PASS` cho runtime thật.

---

## 1. Đối Chiếu Môi Trường Tham Chiếu Của Giảng Viên và `ADMIN-PC` Thực Tế

Không nâng cấp, hạ cấp hay thay đổi cấu hình dịch vụ trên `ADMIN-PC`; ghi nhận trung thực toàn bộ phiên bản và mã băm thực tế vào biên nhận preflight:

| Thành phần | Bộ tham chiếu của giảng viên | Môi trường `ADMIN-PC` thực tế | Quy tắc provenance bắt buộc |
|---|---|---|---|
| **OpenGrep CLI** | `1.33.1` | `1.25.0` (qua cầu nối WSL2 wrapper) | Ghi nhận đầu ra `opengrep --version`, SHA-256 của tệp wrapper trên Windows, tên distro WSL2, đường dẫn mount `/mnt/<drive>/...`, `cwd` và kiểm chứng wrapper truyền nguyên mã thoát (`exit code`) của tiến trình con. |
| **Ollama Server** | `0.40.16` | `0.40.7` (`http://127.0.0.1:11434`) | Ghi nhận tiến trình/phiên bản Ollama trên Windows, lưu nguyên body `/api/tags` cùng `digest` của model, kèm nhật ký daemon/model-run cùng thời điểm chạy. |
| **Model Qwen cục bộ** | `qwen3.5:9b-q4_K_M` | `qwen3.5:9b-q4_K_M` | Chỉ gọi qua loopback HTTP cục bộ; cấm hoàn toàn cloud LLM, retry ngầm hoặc sửa/repair phản hồi của model. |
| **Python venv cô lập** | `>= 3.11` (checklist P1: `3.11.9`) | Venv cô lập `3.11.9` (`typer==0.29.1`, `rich==15.0.0`, `PyYAML==6.0.3`) | Tạo venv mới với `include-system-site-packages = false`. Nếu máy thực thi dùng `3.12.x` thay vì `3.11.9`, phải ghi rõ phiên bản thực tế và **không** tự đánh dấu đóng điều kiện parity `Python 3.11.9` của P1. |

---

## 2. Cấu Trúc Tập Thực Nghiệm (Loại Bỏ Hoàn Toàn Hiện Tượng Nhân Đôi 8 Lượt Gọi Qwen)

Mỗi lần nghiệm thu dùng một `$RunId` mới duy nhất bên ngoài checkout Git, chia tách rạch ròi hai nhóm:

1. **Tập thực nghiệm chính (`$RunRoot\primary` — ĐÚNG 4 lượt gọi `/api/chat` thật tới Qwen = `2 + 1 + 1`, chỉ chạy MỘT lần):**
   - `demo1_true_positive` (`Demo1TruePositive.java`): **2 cảnh báo** (`CWE-89` SQL Injection và `CWE-22` Path Traversal).
   - `demo2_protected_fp` (`Demo2ProtectedFalsePositive.java`): **1 cảnh báo** (`CWE-22` tại dòng 15–20: `new File("/srv/reports/", reportName)` -> `candidate.getCanonicalPath()` -> `startsWith("/srv/reports/")` -> `new FileInputStream(candidate)`).
   - `demo3a_missing_helper` (`Demo3ExternalHelperUndetermined.java`): **1 cảnh báo** (`CWE-22` tại dòng 13–15: `ExternalPathPolicy.normalizeDocumentPath(rawDocId)` -> `new FileInputStream(delegatedPath)`, thiếu mã nguồn lớp helper bên ngoài).
   - Ngay sau khi quét xong tập chính và **trước** khi chạy thao tác con người R03, tạo bản chụp bất biến `review.post_ingestion.sqlite` để khóa bằng chứng trạng thái khởi tạo `OPEN`, rồi thực hiện vòng đời kiểm duyệt R03 trực tiếp trên `Demo1` và `Demo2`.
2. **Tập đối chứng phụ (`$RunRoot\auxiliary` — 0 lượt gọi Qwen thật, tách khỏi mẫu số 4 cảnh báo của R01):**
   - `m1_scan_only`: `semgrepai scan Demo1TruePositive.java --scan-only` (chứng minh tương thích M1, không tạo thư mục `triage`, 0 lượt gọi HTTP, byte-equal với báo cáo legacy, đối chiếu đa tập JSON/SARIF).
   - `controls_suite` (`run_g1_demo --auxiliary-controls-only`): chỉ chạy `demo3b_malformed_llm_synthetic_mock` (nhãn `SYNTHETIC_MOCK_HTTP`, kiểm chứng lưu nguyên raw bytes phản hồi JSON hỏng và giữ `UNDETERMINED` + `OPEN`) và `demo4_stale_source` (`--no-llm` trên bản sao `Demo4MutableCopy.java`, sửa tệp sau quét, kiểm chứng `confirm-false` bị từ chối với mã thoát `2` / `STALE_SOURCE`, `0` sự kiện được chấp nhận và `1` bản ghi `rejected_decisions`).

---

## 3. Ánh Xạ Chính Xác Đường Dẫn Hiện Vật, Trường Schema và Cảnh Báo

- **Evidence bundle:** `<scenario>\triage\evidence.json` (không tồn tại `evidence.jsonl`).
- **Assessments:** `<scenario>\triage\assessments.jsonl` (mỗi dòng có `row.state == "OPEN"` lúc nạp; phiên bản và hợp đồng prompt nằm tại `row.assessment.prompt_version` và `row.assessment.prompt_contract`).
- **Prompt & tương thích JSON:** `<scenario>\triage\llm_io\<id>.prompt.json`, `<id>.request.json`, `<id>.response.json` (không tồn tại `*.prompt.txt`). Trong `<id>.response.json`, trường `raw_response` là JSON envelope đã parse (hoặc `null` nếu lỗi parse/transport). Quy tắc P01 cấm khóa metadata `"raw_path"` trong `snippets[]` / `trace_steps[]` của prompt, **không** cấm chuỗi đường dẫn xuất hiện tự nhiên trong mã nguồn Java.
- **Bằng chứng HTTP body gốc cùng lượt gọi (B1):**
  - `<scenario>\triage\llm_io\<id>.request.body.bin` (bytes UTF-8 nguyên bản truyền vào `Request`, khớp `request_payload_sha256`).
  - `<scenario>\triage\llm_io\<id>.response.body.bin` (bytes HTTP response body nguyên bản nhận từ cùng lượt gọi `urllib` trước khi decode UTF-8 / parse JSON, khớp `response_body_sha256`; hoặc `<id>.response.incomplete.bin` với `response_body_sha256 = null` nếu đứt kết nối/vượt ngưỡng `1,000,000` bytes).
  - `<scenario>\triage\llm_io\<id>.http-capture.json` (`schema: "ntk-ollama-http-capture-1"`, `capture_scope: "http_body_and_client_metadata_not_tcp_wire"` — chỉ bảo toàn HTTP payload/body và header phía client, không tuyên bố ghi nhận khung truyền TCP/wire thô).
  - `<scenario>\triage\llm_io\_tags\tags-NNNN.{response.body.bin,http-capture.json}` (tách riêng lượt thăm dò `GET /api/tags` khỏi `POST /api/chat`).
  - `<scenario>\triage\http-capture-check.json` (kết quả kiểm chứng tự động của `v2.triage.verify_http_capture`).
- **Contract / version manifest:** đọc `prompt_contract` và `prompt_version` từ `<scenario>\g1-run-manifest.json`, `<id>.prompt.json` và `row.assessment` (không đọc từ `live-protocol-check.json`).
- **Warning ID trong hàng đợi CLI:** đọc từ `$QueueJson.warnings[0].id` (không dùng `.warning_id`).

---

## 4. Hàm Bảo Vệ Fail-Fast và Khởi Tạo Vùng Chạy Mới (PowerShell)

Không dùng `New-Item -Force`, `venv --clear`, `*>` hay `Tee-Object`. Mọi lệnh ngoại vi đều kiểm tra mã thoát ngay lập tức và lưu biên nhận nhị phân `.stdout.bin` / `.stderr.bin` / `.receipt.json` qua `v2.g1_integration.exec_receipt`:

```powershell
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-LastExit {
    param([Parameter(Mandatory=$true)][string]$Step, [int[]]$Allowed = @(0))
    $code = $LASTEXITCODE
    if ($Allowed -notcontains $code) {
        throw "FAIL-FAST [$Step]: unexpected exit code $code (allowed: $($Allowed -join ','))"
    }
}

function Assert-FreshAbsent {
    param([Parameter(Mandatory=$true)][string]$TargetPath)
    if (Test-Path -LiteralPath $TargetPath) {
        throw "FAIL-FAST [FRESHNESS]: path already exists, refusing reuse/overwrite: $TargetPath"
    }
}

# Người vận hành điền đường dẫn tuyệt đối thực tế trên ADMIN-PC và SHA từ G1_C4_COMMIT_MANIFEST.json:
$RunId          = "g1-c4-accept-" + (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$BundlePath     = "<ABSOLUTE_PATH_TO_G1_C4_BUNDLE_FILE>"
$ExpectedBundleSha256 = "<LOWERCASE_64_HEX_BUNDLE_SHA256_FROM_MANIFEST>"
$ExpectedCommit = "<FULL_40_HEX_G1_C4_COMMIT_SHA_FROM_MANIFEST>"
$ExpectedParent = "236439ead654d12448bb2cf711e534a243007afd"
$ExpectedTree   = "<FULL_40_HEX_G1_C4_TREE_SHA_FROM_MANIFEST>"
$BasePython311  = "<ABSOLUTE_PATH_TO_ADMIN_PC_PYTHON_3_11_9_EXE>"
$OpenGrepExe    = "<ABSOLUTE_PATH_TO_OPENGREP_WSL_WRAPPER_OR_BINARY>"
$UpstreamClone  = "<ABSOLUTE_PATH_TO_CLEAN_SIMPLE_SEMGREPAI_2C79A58A>"

$SessionRoot    = "C:\NTK-G1-Runtime-Runs\$RunId"
$CheckoutDir    = "$SessionRoot\checkout-detached"
$VenvDir        = "$SessionRoot\venv-g1-c4"
$ReceiptsDir    = "$SessionRoot\process-receipts"
$TempDir        = "$SessionRoot\temp"
$ForkDir        = "$SessionRoot\fork-g1"
$PrimaryRoot    = "$SessionRoot\primary"
$AuxRoot        = "$SessionRoot\auxiliary"
$AuditOut       = "$SessionRoot\audit"

foreach ($p in @($SessionRoot, $CheckoutDir, $VenvDir, $ReceiptsDir, $TempDir, $ForkDir, $PrimaryRoot, $AuxRoot, $AuditOut)) {
    Assert-FreshAbsent -TargetPath $p
}
New-Item -ItemType Directory -Path $SessionRoot | Out-Null
New-Item -ItemType Directory -Path $ReceiptsDir | Out-Null
New-Item -ItemType Directory -Path $TempDir | Out-Null
New-Item -ItemType Directory -Path $PrimaryRoot | Out-Null
New-Item -ItemType Directory -Path $AuxRoot | Out-Null
New-Item -ItemType Directory -Path $AuditOut | Out-Null
```

---

## 5. Giai Đoạn 0 — Tiếp Nhận Git Bundle An Toàn và Xác Minh Nguồn Cô Lập

```powershell
# 0.1. Kiểm tra SHA-256 của tệp Git bundle trước khi giải nén
$ActualBundleSha = (Get-FileHash -LiteralPath $BundlePath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($ActualBundleSha -ne $ExpectedBundleSha256) {
    throw "FAIL-FAST [BUNDLE_SHA256]: expected $ExpectedBundleSha256, observed $ActualBundleSha"
}

# 0.2. Khởi tạo repository trống cô lập (cấm autocrlf biến đổi CRLF/LF của nguồn)
New-Item -ItemType Directory -Path $CheckoutDir | Out-Null
git -C $CheckoutDir init
Assert-LastExit "0.2_git_init"
git -C $CheckoutDir config core.autocrlf false
Assert-LastExit "0.2_git_autocrlf_false"
git -C $CheckoutDir config core.eol lf
Assert-LastExit "0.2_git_eol_lf"

# 0.3. Kiểm tra tính hợp lệ của bundle và nạp đúng ref ứng viên (nếu bundle có prerequisite commit thì phải nạp vào repo đã có sẵn prerequisite parent 236439ea... hoặc full bundle độc lập)
git -C $CheckoutDir bundle list-heads $BundlePath
Assert-LastExit "0.3_bundle_list_heads"
git -C $CheckoutDir bundle verify $BundlePath
Assert-LastExit "0.3_bundle_verify"
git -C $CheckoutDir fetch --no-tags $BundlePath "refs/heads/v2/g1-c4-runtime-remediation:refs/remotes/bundle/g1-c4"
Assert-LastExit "0.3_git_fetch_bundle"
git -C $CheckoutDir checkout --detach "refs/remotes/bundle/g1-c4"
Assert-LastExit "0.3_git_checkout_detached"

# 0.4. Đối chiếu chính xác HEAD, parent, tree và trạng thái worktree CLEAN (kiểm exit code TRƯỚC khi xét chuỗi rỗng)
$HeadSha   = (git -C $CheckoutDir rev-parse --verify HEAD).Trim()
Assert-LastExit "0.4_rev_parse_head"
$ParentSha = (git -C $CheckoutDir rev-parse --verify "HEAD^1").Trim()
Assert-LastExit "0.4_rev_parse_parent"
$TreeSha   = (git -C $CheckoutDir rev-parse --verify "HEAD^{tree}").Trim()
Assert-LastExit "0.4_rev_parse_tree"
$SymRef    = ""
git -C $CheckoutDir symbolic-ref -q HEAD | Out-Null
$DetachedExit = $LASTEXITCODE
if ($DetachedExit -ne 1) {
    throw "FAIL-FAST [DETACHED_HEAD]: checkout must be detached HEAD (expected git symbolic-ref exit 1, got $DetachedExit)"
}
$GitStatus = (git -C $CheckoutDir status --porcelain=v1 --ignored=matching | Out-String).Trim()
Assert-LastExit "0.4_git_status"

if ($HeadSha -ne $ExpectedCommit -or $ParentSha -ne $ExpectedParent -or $TreeSha -ne $ExpectedTree -or $GitStatus -ne "") {
    throw "FAIL-FAST [SOURCE_IDENTITY]: HEAD=$HeadSha Parent=$ParentSha Tree=$TreeSha Status='$GitStatus'"
}
```

---

## 6. Giai Đoạn 1 — Preflight Môi Trường, Venv Cô Lập và Kiểm Tra Wrapper WSL2 / Ollama

```powershell
Set-Location -LiteralPath $CheckoutDir
$env:PYTHONUTF8 = "1"
$env:PYTHONDONTWRITEBYTECODE = "1"
$env:G1_CHECKOUT = $CheckoutDir
$env:G1_EXPECTED_SHA = $ExpectedCommit
$env:TEMP = $TempDir
$env:TMP = $TempDir
$env:SEMGREP_LOG_FILE = "$SessionRoot\scanner-runtime.log"
$env:SEMGREP_SETTINGS_FILE = "$SessionRoot\scanner-settings.yml"
$env:SEMGREP_SEND_METRICS = "off"
$env:SEMGREP_ENABLE_VERSION_CHECK = "0"
$env:OPENGREP_ENABLE_VERSION_CHECK = "0"

# 1.1. Tạo venv mới (không dùng --clear) và cài đặt gói phụ thuộc đã ghim
& $BasePython311 -m venv $VenvDir
Assert-LastExit "1.1_create_venv"
$VenvPython = "$VenvDir\Scripts\python.exe"
& $VenvPython -X utf8 -B -m pip install --disable-pip-version-check "typer==0.29.1" "rich==15.0.0" "PyYAML==6.0.3"
Assert-LastExit "1.1_pip_install_pins"

function Invoke-ReceiptStep {
    param(
        [Parameter(Mandatory=$true)][string]$Step,
        [Parameter(Mandatory=$true)][string[]]$CommandArgv,
        [int[]]$ExpectedExit = @(0)
    )
    $expectFlags = @()
    foreach ($code in $ExpectedExit) { $expectFlags += @("--expect-exit", "$code") }
    & $VenvPython -X utf8 -B -m v2.g1_integration.exec_receipt `
        --receipt-dir $ReceiptsDir `
        --step $Step `
        --cwd $CheckoutDir `
        @expectFlags `
        -- @CommandArgv | Out-Null
    Assert-LastExit -Step "receipt_$Step" -Allowed @(0)
}

# 1.2. Ghi biên nhận nhị phân phiên bản Python, pip freeze, OpenGrep, WSL2 distro/mount và Ollama
Invoke-ReceiptStep -Step "01_python_version" -CommandArgv @($VenvPython, "-VV")
Invoke-ReceiptStep -Step "02_pip_freeze" -CommandArgv @($VenvPython, "-m", "pip", "freeze")
Invoke-ReceiptStep -Step "03_opengrep_version" -CommandArgv @($OpenGrepExe, "--version")
# Kiểm chứng wrapper truyền nguyên mã thoát khác 0 khi đối số sai (không nuốt lỗi child exit):
& $VenvPython -X utf8 -B -m v2.g1_integration.exec_receipt `
    --receipt-dir $ReceiptsDir --step "04_opengrep_nonzero_exit_probe" --cwd $CheckoutDir --allow-any-exit `
    -- $OpenGrepExe --definitely-invalid-flag-probe | Out-Null
Assert-LastExit "04_probe_wrapper"
$ProbeDoc = Get-Content -LiteralPath "$ReceiptsDir\04_opengrep_nonzero_exit_probe.receipt.json" -Raw | ConvertFrom-Json
if ($ProbeDoc.exit_code -eq 0) {
    throw "FAIL-FAST [WRAPPER_EXIT_PROPAGATION]: OpenGrep wrapper suppressed non-zero child exit code"
}

Invoke-ReceiptStep -Step "05_wsl_status_inventory" -CommandArgv @("wsl.exe", "--status")
Invoke-ReceiptStep -Step "06_ollama_cli_version" -CommandArgv @("ollama", "--version")

# 1.3. Lưu nguyên HTTP body của GET /api/tags và kiểm tra model qwen3.5:9b-q4_K_M sẵn sàng trước khi tiếp tục
Invoke-ReceiptStep -Step "07_ollama_tags_probe" -CommandArgv @(
    $VenvPython, "-X", "utf8", "-B", "-c",
    "import json, pathlib, sys; from v2.triage.ollama import OllamaClient; c = OllamaClient(io_log_dir=pathlib.Path(r'$AuditOut\preflight_tags_io')); inv = c.verify_model_installed(); print(json.dumps(inv, indent=2)); sys.exit(0 if inv['reachable'] and inv['model_found'] else 2)"
)
```

---

## 7. Giai Đoạn 2 — Kiểm Thử Hồi Quy Offline & Dựng Bản Fork `simple_semgrepAI`

```powershell
# 2.1. Bốn bộ kiểm thử offline + verify_patch + detached audit gate trên chính ADMIN-PC
Invoke-ReceiptStep -Step "08_suite_g1_integration" -CommandArgv @($VenvPython, "-X", "utf8", "-B", "-m", "unittest", "discover", "-s", "v2/g1_integration/tests", "-p", "test_*.py", "-v")
Invoke-ReceiptStep -Step "09_suite_triage" -CommandArgv @($VenvPython, "-X", "utf8", "-B", "-m", "unittest", "discover", "-s", "v2/triage/tests", "-p", "test_*.py", "-v")
Invoke-ReceiptStep -Step "10_suite_baseline" -CommandArgv @($VenvPython, "-X", "utf8", "-B", "-m", "unittest", "discover", "-s", "v2/baseline/tests", "-p", "test_*.py", "-v")
Invoke-ReceiptStep -Step "11_suite_g1_audit" -CommandArgv @($VenvPython, "-X", "utf8", "-B", "-m", "unittest", "discover", "-s", "v2/g1_audit", "-p", "test_*.py", "-v")
Invoke-ReceiptStep -Step "12_verify_patch" -CommandArgv @($VenvPython, "-X", "utf8", "-B", "v2/baseline/verify_patch.py")
if (Test-Path -LiteralPath "$CheckoutDir\v2\baseline\evidence\patch-verification.json") {
    Move-Item -LiteralPath "$CheckoutDir\v2\baseline\evidence\patch-verification.json" -Destination "$AuditOut\patch-verification.json"
}
Invoke-ReceiptStep -Step "13_run_checks_gate" -CommandArgv @($VenvPython, "-X", "utf8", "-B", "v2/g1_audit/run_checks.py", "--checkout", $CheckoutDir, "--expected-sha", $ExpectedCommit, "--output", "$AuditOut\offline-gate")
Invoke-ReceiptStep -Step "14_verify_test_receipt" -CommandArgv @($VenvPython, "-X", "utf8", "-B", "v2/g1_audit/verify_test_receipt.py", "$AuditOut\offline-gate")

# 2.2. Xác minh commit/tree của upstream simple_semgrepAI rồi dựng bản fork vào vùng riêng
$UpSha  = (git -C $UpstreamClone rev-parse --verify HEAD).Trim()
Assert-LastExit "2.2_upstream_head"
$UpTree = (git -C $UpstreamClone rev-parse --verify "HEAD^{tree}").Trim()
Assert-LastExit "2.2_upstream_tree"
$UpStat = (git -C $UpstreamClone status --porcelain=v1 | Out-String).Trim()
Assert-LastExit "2.2_upstream_status"
if ($UpSha -ne "2c79a58a16d11e9dea3723e30d2a7faffba7bdc9" -or $UpTree -ne "c0ab3e20152ce5c3e6b80e1525288ad59c9aee93" -or $UpStat -ne "") {
    throw "FAIL-FAST [UPSTREAM_INTEGRITY]: SHA=$UpSha Tree=$UpTree Status='$UpStat'"
}

Invoke-ReceiptStep -Step "15_prepare_g1_fork" -CommandArgv @(
    $VenvPython, "-X", "utf8", "-B", "-m", "v2.g1_integration.prepare_g1_fork",
    "--upstream", $UpstreamClone,
    "--scanner-layer", "ntk-cleanroom",
    "--output-dir", $ForkDir
)

$env:PYTHONPATH = "$ForkDir\source;$CheckoutDir"
$env:NTK_G1_REPO_ROOT = $CheckoutDir
# Xác minh nguồn gốc module thực tế được nạp từ PYTHONPATH vừa cấu hình
Invoke-ReceiptStep -Step "16_verify_module_origins" -CommandArgv @(
    $VenvPython, "-X", "utf8", "-B", "-c",
    "import json, semgrepai, semgrepai.cli, v2.triage.ollama, v2.g1_integration.bridge; print(json.dumps({'semgrepai': semgrepai.__file__, 'semgrepai_cli': semgrepai.cli.__file__, 'ollama': v2.triage.ollama.__file__, 'bridge': v2.g1_integration.bridge.__file__}, indent=2))"
)
```

---

## 8. Giai Đoạn 3 — Tập Đối Chứng Phụ Không Gọi Qwen Thật (`0` Real Qwen Calls)

```powershell
# 3.1. Đối chứng R02 M1 (--scan-only): không tạo triage/, không gọi HTTP
$M1Dir = "$AuxRoot\m1_scan_only"
Invoke-ReceiptStep -Step "17_m1_scan_only" -CommandArgv @(
    $VenvPython, "-X", "utf8", "-B", "-m", "semgrepai", "scan",
    "v2/g1_integration/demo_fixtures/Demo1TruePositive.java",
    "--rules-path", "v2/g1_integration/rules/java_g1_cwe22_cwe89.yml",
    "--output-dir", $M1Dir,
    "--executable", $OpenGrepExe,
    "--scan-only"
)

# 3.2. Đối chứng Demo3b (SYNTHETIC_MOCK_HTTP malformed JSON) + Demo4 (--no-llm STALE_SOURCE exit 2)
$ControlsDir = "$AuxRoot\controls_suite"
Invoke-ReceiptStep -Step "18_auxiliary_controls_suite" -CommandArgv @(
    $VenvPython, "-X", "utf8", "-B", "-m", "v2.g1_integration.run_g1_demo",
    "--prepared-source", "$ForkDir\source",
    "--output-dir", $ControlsDir,
    "--executable", $OpenGrepExe,
    "--auxiliary-controls-only"
)
```

---

## 9. Giai Đoạn 4 — Tập Thực Nghiệm Chính Với Qwen Thật (`4` Lượt Gọi `/api/chat` Duy Nhất: `2 + 1 + 1`)

```powershell
$Demo1Dir  = "$PrimaryRoot\demo1_true_positive"
$Demo2Dir  = "$PrimaryRoot\demo2_protected_fp"
$Demo3aDir = "$PrimaryRoot\demo3a_missing_helper"

# 4.1. Demo 1: Demo1TruePositive.java (2 findings: CWE-89 + CWE-22)
Invoke-ReceiptStep -Step "19_primary_demo1_scan" -CommandArgv @(
    $VenvPython, "-X", "utf8", "-B", "-m", "semgrepai", "scan",
    "v2/g1_integration/demo_fixtures/Demo1TruePositive.java",
    "--rules-path", "v2/g1_integration/rules/java_g1_cwe22_cwe89.yml",
    "--output-dir", $Demo1Dir,
    "--executable", $OpenGrepExe,
    "--local-triage",
    "--endpoint", "http://127.0.0.1:11434",
    "--model", "qwen3.5:9b-q4_K_M",
    "--prompt-contract", "blind",
    "--timeout", "180"
)
Copy-Item -LiteralPath "$Demo1Dir\triage\review.sqlite" -Destination "$Demo1Dir\triage\review.post_ingestion.sqlite"

# 4.2. Demo 2: Demo2ProtectedFalsePositive.java (1 finding: CWE-22 getCanonicalPath().startsWith("/srv/reports/") at lines 16-18)
Invoke-ReceiptStep -Step "20_primary_demo2_scan" -CommandArgv @(
    $VenvPython, "-X", "utf8", "-B", "-m", "semgrepai", "scan",
    "v2/g1_integration/demo_fixtures/Demo2ProtectedFalsePositive.java",
    "--rules-path", "v2/g1_integration/rules/java_g1_cwe22_cwe89.yml",
    "--output-dir", $Demo2Dir,
    "--executable", $OpenGrepExe,
    "--local-triage",
    "--endpoint", "http://127.0.0.1:11434",
    "--model", "qwen3.5:9b-q4_K_M",
    "--prompt-contract", "blind",
    "--timeout", "180"
)
Copy-Item -LiteralPath "$Demo2Dir\triage\review.sqlite" -Destination "$Demo2Dir\triage\review.post_ingestion.sqlite"

# 4.3. Demo 3a: Demo3ExternalHelperUndetermined.java (1 finding: CWE-22 ExternalPathPolicy.normalizeDocumentPath)
Invoke-ReceiptStep -Step "21_primary_demo3a_scan" -CommandArgv @(
    $VenvPython, "-X", "utf8", "-B", "-m", "semgrepai", "scan",
    "v2/g1_integration/demo_fixtures/Demo3ExternalHelperUndetermined.java",
    "--rules-path", "v2/g1_integration/rules/java_g1_cwe22_cwe89.yml",
    "--output-dir", $Demo3aDir,
    "--executable", $OpenGrepExe,
    "--local-triage",
    "--endpoint", "http://127.0.0.1:11434",
    "--model", "qwen3.5:9b-q4_K_M",
    "--prompt-contract", "blind",
    "--timeout", "180"
)
Copy-Item -LiteralPath "$Demo3aDir\triage\review.sqlite" -Destination "$Demo3aDir\triage\review.post_ingestion.sqlite"

# 4.4. Kiểm chứng giao thức live_check (minimum 2 / 1 / 1) và raw HTTP capture (B1) không ghi đè vào triage/
Invoke-ReceiptStep -Step "22_live_check_demo1" -CommandArgv @($VenvPython, "-X", "utf8", "-B", "-m", "v2.triage.live_check", "$Demo1Dir\triage", "--minimum-responses", "2")
Invoke-ReceiptStep -Step "23_live_check_demo2" -CommandArgv @($VenvPython, "-X", "utf8", "-B", "-m", "v2.triage.live_check", "$Demo2Dir\triage", "--minimum-responses", "1")
Invoke-ReceiptStep -Step "24_live_check_demo3a" -CommandArgv @($VenvPython, "-X", "utf8", "-B", "-m", "v2.triage.live_check", "$Demo3aDir\triage", "--minimum-responses", "1")

Invoke-ReceiptStep -Step "25_http_capture_demo1" -CommandArgv @($VenvPython, "-X", "utf8", "-B", "-m", "v2.triage.verify_http_capture", "$Demo1Dir\triage", "--require-live-chat", "--minimum-findings", "2", "--output", "$AuditOut\demo1-http-capture-audit.json")
Invoke-ReceiptStep -Step "26_http_capture_demo2" -CommandArgv @($VenvPython, "-X", "utf8", "-B", "-m", "v2.triage.verify_http_capture", "$Demo2Dir\triage", "--require-live-chat", "--minimum-findings", "1", "--output", "$AuditOut\demo2-http-capture-audit.json")
Invoke-ReceiptStep -Step "27_http_capture_demo3a" -CommandArgv @($VenvPython, "-X", "utf8", "-B", "-m", "v2.triage.verify_http_capture", "$Demo3aDir\triage", "--require-live-chat", "--minimum-findings", "1", "--output", "$AuditOut\demo3a-http-capture-audit.json")

# 4.5. Chạy bộ kiểm toán độc lập v2/g1_audit/audit.py (ghi nhận INCOMPLETE có chủ đích cho model attestation bằng --allow-any-exit, sau đó kiểm tra từng mục dữ liệu)
foreach ($pair in @(
    @{ Name = "demo1"; Dir = $Demo1Dir },
    @{ Name = "demo2"; Dir = $Demo2Dir },
    @{ Name = "demo3a"; Dir = $Demo3aDir }
)) {
    & $VenvPython -X utf8 -B -m v2.g1_integration.exec_receipt `
        --receipt-dir $ReceiptsDir `
        --step "28_audit_py_$($pair.Name)" `
        --cwd $CheckoutDir `
        --expect-exit 0 --expect-exit 2 `
        -- $VenvPython -X utf8 -B v2/g1_audit/audit.py `
            --checkout $CheckoutDir `
            --evidence "$($pair.Dir)\triage" `
            --capture "$($pair.Dir)\capture" `
            --output "$AuditOut\audit-$($pair.Name)" | Out-Null
    Assert-LastExit -Step "28_audit_py_$($pair.Name)" -Allowed @(0)
}
```

---

## 10. Giai Đoạn 5 — Vòng Đời Kiểm Duyệt Con Người Qua CLI Kế Thừa (R03)

Sử dụng đúng trường `.warnings[0].id` (kiểm tra định dạng 64 ký tự hex trước khi truyền lệnh) và ghi nhận biên nhận nhị phân cho mọi thao tác:

```powershell
$OperatorActor = "admin-pc-acceptance-operator"
$LeadActor     = "admin-pc-acceptance-reviewer"

# 5.1. Demo 1: queue -> show -> confirm-true -> history
$D1Db = "$Demo1Dir\triage\review.sqlite"
Invoke-ReceiptStep -Step "29_d1_queue_initial" -CommandArgv @($VenvPython, "-X", "utf8", "-B", "-m", "semgrepai", "queue", "--db", $D1Db)
$D1Queue = [System.Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes("$ReceiptsDir\29_d1_queue_initial.stdout.bin")) | ConvertFrom-Json
$D1Id = [string]$D1Queue.warnings[0].id
if ($D1Id -notmatch "^[0-9a-f]{64}$") { throw "FAIL-FAST [D1_WARNING_ID]: invalid warning id '$D1Id'" }

Invoke-ReceiptStep -Step "30_d1_show" -CommandArgv @($VenvPython, "-X", "utf8", "-B", "-m", "semgrepai", "show", $D1Id, "--db", $D1Db)
Invoke-ReceiptStep -Step "31_d1_confirm_true" -CommandArgv @(
    $VenvPython, "-X", "utf8", "-B", "-m", "semgrepai", "confirm-true", $D1Id,
    "--db", $D1Db, "--actor", $OperatorActor,
    "--reason", "Verified unsanitized servlet parameter reaching sink along captured taint trace in Demo1TruePositive.java"
)
Invoke-ReceiptStep -Step "32_d1_queue_after_true" -CommandArgv @($VenvPython, "-X", "utf8", "-B", "-m", "semgrepai", "queue", "--db", $D1Db)
Invoke-ReceiptStep -Step "33_d1_history" -CommandArgv @($VenvPython, "-X", "utf8", "-B", "-m", "semgrepai", "history", $D1Id, "--db", $D1Db, "--include-rejected")

# 5.2. Demo 2: queue -> show -> confirm-false -> queue (ẩn) -> queue --all (giữ CONFIRMED_FALSE) -> reopen -> queue (OPEN) -> history
$D2Db = "$Demo2Dir\triage\review.sqlite"
Invoke-ReceiptStep -Step "34_d2_queue_initial" -CommandArgv @($VenvPython, "-X", "utf8", "-B", "-m", "semgrepai", "queue", "--db", $D2Db)
$D2Queue = [System.Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes("$ReceiptsDir\34_d2_queue_initial.stdout.bin")) | ConvertFrom-Json
$D2Id = [string]$D2Queue.warnings[0].id
if ($D2Id -notmatch "^[0-9a-f]{64}$") { throw "FAIL-FAST [D2_WARNING_ID]: invalid warning id '$D2Id'" }

Invoke-ReceiptStep -Step "35_d2_show" -CommandArgv @($VenvPython, "-X", "utf8", "-B", "-m", "semgrepai", "show", $D2Id, "--db", $D2Db)
Invoke-ReceiptStep -Step "36_d2_confirm_false" -CommandArgv @(
    $VenvPython, "-X", "utf8", "-B", "-m", "semgrepai", "confirm-false", $D2Id,
    "--db", $D2Db, "--actor", $OperatorActor,
    "--reason", "Verified candidate.getCanonicalPath().startsWith('/srv/reports/') boundary check prior to FileInputStream in Demo2ProtectedFalsePositive.java"
)
Copy-Item -LiteralPath $D2Db -Destination "$Demo2Dir\triage\review.after_confirm_false.sqlite"
Invoke-ReceiptStep -Step "37_d2_queue_after_false" -CommandArgv @($VenvPython, "-X", "utf8", "-B", "-m", "semgrepai", "queue", "--db", $D2Db)
Invoke-ReceiptStep -Step "38_d2_queue_all" -CommandArgv @($VenvPython, "-X", "utf8", "-B", "-m", "semgrepai", "queue", "--db", $D2Db, "--all")
Invoke-ReceiptStep -Step "39_d2_reopen" -CommandArgv @(
    $VenvPython, "-X", "utf8", "-B", "-m", "semgrepai", "reopen", $D2Id,
    "--db", $D2Db, "--actor", $LeadActor,
    "--reason", "Reopened to verify filesystem symlink policy under /srv/reports"
)
Invoke-ReceiptStep -Step "40_d2_queue_after_reopen" -CommandArgv @($VenvPython, "-X", "utf8", "-B", "-m", "semgrepai", "queue", "--db", $D2Db)
Invoke-ReceiptStep -Step "41_d2_history" -CommandArgv @($VenvPython, "-X", "utf8", "-B", "-m", "semgrepai", "history", $D2Id, "--db", $D2Db, "--include-rejected")
```

---

## 11. Giai Đoạn 6 — Cổng Đánh Giá Độc Lập Read-Only R01–R03 & Kiểm Tra Sạch Sau Chạy

Không suy luận `PASS` từ việc các bước trên trả `exit 0`. Chạy bộ đánh giá chỉ-đọc `v2.g1_integration.evaluate_r01_r03` (mở SQLite bằng URI `?mode=ro`, replay lại `validate_answer` từ chính `<id>.response.body.bin`):

```powershell
# 6.1. Đánh giá quyết định R01, R02, R03 (trả exit 0 CHỈ KHI cả R01, R02 và R03 đều PASS)
Invoke-ReceiptStep -Step "42_evaluate_r01_r03" -CommandArgv @(
    $VenvPython, "-X", "utf8", "-B", "-m", "v2.g1_integration.evaluate_r01_r03",
    "--demo1-dir", $Demo1Dir,
    "--demo2-dir", $Demo2Dir,
    "--demo3a-dir", $Demo3aDir,
    "--m1-dir", $M1Dir,
    "--demo3b-dir", "$ControlsDir\demo3b_malformed_llm_synthetic_mock",
    "--demo4-dir", "$ControlsDir\demo4_stale_source",
    "--output", "$AuditOut\r01_r03_evaluation.json"
)

# 6.2. Hậu kiểm Git checkout vẫn sạch tuyệt đối và không bị thay đổi HEAD/tree
$PostHead   = (git -C $CheckoutDir rev-parse --verify HEAD).Trim()
Assert-LastExit "6.2_post_rev_parse_head"
$PostTree   = (git -C $CheckoutDir rev-parse --verify "HEAD^{tree}").Trim()
Assert-LastExit "6.2_post_rev_parse_tree"
$PostStatus = (git -C $CheckoutDir status --porcelain=v1 --ignored=matching | Out-String).Trim()
Assert-LastExit "6.2_post_git_status"
if ($PostHead -ne $ExpectedCommit -or $PostTree -ne $ExpectedTree -or $PostStatus -ne "") {
    throw "FAIL-FAST [POST_RUN_CLEANLINESS]: checkout mutated during run: HEAD=$PostHead Tree=$PostTree Status='$PostStatus'"
}
```

### Quy Tắc Kết Luận Bắt Buộc Cho R01–R03

- **`R01 = PASS`** khi và chỉ khi toàn bộ **4 cảnh báo thật (`2 + 1 + 1`)** có đầy đủ raw HTTP request/response bytes cùng lượt gọi khớp SHA-256 (`verify_http_capture --require-live-chat` đạt), prompt `blind` / `v2.2.2-cwe22-cwe89-canonical-citations` không rò rỉ khóa `raw_path`, **Demo1 (2 cảnh báo) đạt `SUPPORTED` hợp lệ qua bộ validator không sửa đổi với canonical citation**, **Demo2 (1 cảnh báo) đạt `REFUTED` hợp lệ qua bộ validator không sửa đổi với canonical citation**, **Demo3a (1 cảnh báo thiếu helper) tự abstain `raw_model_status == "UNDETERMINED"` và `validated_status == "UNDETERMINED"` (`failure_kind == "NONE"`, `answer_validated == true`)**, và toàn bộ hàng đợi khởi tạo ở trạng thái `OPEN`.
- **`R01 = FAIL`** nếu phát sinh `INVALID_CITATION` hoặc thiếu kết luận dứt khoát hợp lệ trên Demo1/Demo2, hoặc Demo3a trả `SUPPORTED` / `REFUTED` (kể cả khi bị validator chặn xuống `UNDETERMINED`) hay chỉ thành `UNDETERMINED` do lỗi JSON/timeout. Giữ nguyên toàn bộ hiện vật lần chạy thất bại; **cấm chạy đè hoặc xóa lần lỗi**.
- **`R02 = PASS`** khi và chỉ khi M1 `--scan-only` không tạo `triage/` và khớp byte với báo cáo legacy, `triage_subprocess_invocations == 0` ở cả ba lượt G1, mã băm nguồn trước/sau khớp tuyệt đối, và đối chiếu đa tập JSON/SARIF (`contracts.compare_sarif`) đạt.
- **`R03 = PASS`** khi và chỉ khi kiểm tra SQLite chỉ-đọc (`?mode=ro`) xác nhận đầy đủ chuyển trạng thái `OPEN -> CONFIRMED_TRUE` (Demo1), `OPEN -> CONFIRMED_FALSE` (ẩn khỏi `queue`, còn trong `queue --all`) `-> OPEN` (Demo2), và từ chối `STALE_SOURCE` mã thoát `2` trên `Demo4` (`OPEN`, `0` accepted events, `1` `rejected_decisions`).

---

## 12. Bản Đề Xuất Điều Chỉnh Ca Xác Nhận FP Cho R03 (`PROPOSED` — Chờ Phê Duyệt)

> [!WARNING]
> **CHƯA THAY THẾ HỢP ĐỒNG KHÓA G1-C5 TRƯỚC KHI ĐƯỢC PHÊ DUYỆT.**
> Các bước dưới đây chỉ áp dụng khi người vận hành / giảng viên phê duyệt chuyển ca xác nhận False Positive (`confirm-false -> reopen`) trong `R03` từ `Demo2ProtectedFalsePositive.java` sang `AllowlistedQuery.java`. Toàn bộ kết quả `R01`/`R02` đã ghi nhận và bằng chứng `Demo2` (`REFUTED` lịch sử) được giữ nguyên vẹn để phân tích giới hạn bảo mật (`TOCTOU`/symlink trên `getCanonicalPath().startsWith("/srv/reports/")`), không xóa hay ghi đè dữ liệu G1-C5 cũ.

### 12.1. Lý Do Đề Xuất & Phạm Vi Thay Đổi

1. **`Demo2ProtectedFalsePositive.java` giữ nguyên cho phân tích giới hạn bảo mật:** mẫu `File.getCanonicalPath().startsWith("/srv/reports/")` trước `new FileInputStream(candidate)` có rủi ro `TOCTOU`/symlink giữa thời điểm kiểm tra đường dẫn và thời điểm mở tệp, nên người kiểm duyệt con người có cơ sở bảo mật hợp lý để không xác nhận FP đối với `Demo2`.
2. **Ca FP thay thế `v2/g1_integration/demo_fixtures/AllowlistedQuery.java` (`sha256=abc630a66432797904d5f81d69a80b14e73dbea55cad80beddcc505d41e2ea43`):** tái sử dụng mẫu `SAFE_JAVA` từ `v2/triage/demo_queue.py`. Đầu vào SQL không tin cậy `req.getParameter("q")` đi qua rule `CWE-89`, nhưng nhánh phòng vệ `if (!"SELECT 1".equals(query)) { throw new IllegalArgumentException("Only SELECT 1 is allowed"); }` chỉ cho phép đúng hằng chuỗi `"SELECT 1"` tới `stmt.executeQuery(query)`, hoàn toàn trong bộ nhớ, không phụ thuộc hệ thống tệp/symlink/`TOCTOU`.
3. **Tách biệt tuyệt đối phiên G1-C5 lịch sử và lượt bổ sung `AllowlistedQuery` (`R01`/`R02` bất biến):**
   - `R01` giữ nguyên tuyệt đối **đúng 4 lượt Qwen thật lịch sử của G1-C5 (`Demo1=2 + Demo2=1 + Demo3a=1`)**; `R02`, `M1`, `Demo3b` (`SYNTHETIC_MOCK_HTTP`) và `Demo4` (`STALE_SOURCE`, exit code `2`) giữ nguyên toàn bộ tiêu chí và kết quả lịch sử.
   - `Demo2` giữ nguyên trạng thái `OPEN` (`0` sự kiện xác nhận FP) trong chế độ `proposed-allowlisted-fp`.
   - Lượt chạy `AllowlistedQuery` được ghi vào thư mục riêng và vùng báo cáo tách biệt (`supplementary_r03_control`), **không cộng vào mẫu số R01 (`4`, không đổi thành `5`)** và **không gộp chung hai phiên chạy khác nhau thành một phiên thực nghiệm đồng nhất**.
4. **Phân biệt ba lớp đối với kiểm duyệt người dùng:**
   - (1) **Chức năng vòng đời SQLite hoạt động đúng** (`confirm-true`, `confirm-false`, `queue`, `queue --all`, `reopen`, `history`, `STALE_SOURCE`), có thể kiểm chứng kỹ thuật bằng dữ liệu kiểm thử tách biệt (`--allow-mock-primary` cho test tự động).
   - (2) **Quyết định thực sự được người vận hành phê duyệt** tại nghiệm thu chính thức (`allow_mock_primary=False`): mọi sự kiện gắn nhãn `SCRIPTED_TEST_ONLY`, `mock`, `synthetic`, `replay` hoặc thiếu HTTP capture thật đều bị từ chối.
   - (3) **Giới hạn kiểm chứng danh tính ở mức hệ thống:** tham số `--actor` chỉ lưu chuỗi định danh vận hành cục bộ (được kiểm tra khác rỗng, không chứa dấu hiệu kiểm thử giả/mock/scripted), **không phải xác thực danh tính bằng mật mã**.

### 12.2. Thực Thi Bổ Sung Trên `ADMIN-PC` Sau Khi Được Phê Duyệt (`1` Lượt Qwen Thật Bổ Sung + Vòng Đời R03)

Sử dụng thư mục chạy mới hoàn toàn cho riêng phần bổ sung và **tuyệt đối không sửa** thư mục đã kiểm toán của `G1-C5` (dùng `$OperatorActor` và `$LeadActor` thật của phiên vận hành; không dùng `SCRIPTED_TEST_ONLY`):

```powershell
# Khởi tạo thư mục con mới cho AllowlistedQuery (không ghi đè run G1-C5 đã khóa)
$AllowQDir = "$SessionRoot\allowlisted_query_fp"
Assert-FreshAbsent -TargetPath $AllowQDir

# 1. Quét OpenGrep + Qwen cục bộ (--prompt-contract blind, raw HTTP capture) trên AllowlistedQuery.java
Invoke-ReceiptStep -Step "P1_allowq_scan_qwen" -CommandArgv @(
    $VenvPython, "-X", "utf8", "-B", "-m", "semgrepai", "scan",
    "$CheckoutDir\v2\g1_integration\demo_fixtures\AllowlistedQuery.java",
    "--rules-path", "$CheckoutDir\v2\g1_integration\rules\java_g1_cwe22_cwe89.yml",
    "--output-dir", $AllowQDir,
    "--executable", $OpenGrepExe,
    "--local-triage",
    "--endpoint", "http://127.0.0.1:11434",
    "--model", "qwen3.5:9b-q4_K_M",
    "--prompt-contract", "blind",
    "--timeout", "180"
)
Copy-Item -LiteralPath "$AllowQDir\triage\review.sqlite" -Destination "$AllowQDir\triage\review.post_ingestion.sqlite"

# 2. Xác minh HTTP capture thật và trạng thái OPEN trước khi con người kiểm duyệt
Invoke-ReceiptStep -Step "P2_allowq_verify_http" -CommandArgv @(
    $VenvPython, "-X", "utf8", "-B", "-m", "v2.triage.verify_http_capture",
    "$AllowQDir\triage", "--require-live-chat", "--minimum-findings", "1",
    "--output", "$AuditOut\allowlisted_query-http.json"
)
$AllowQDb = "$AllowQDir\triage\review.sqlite"
$AllowQQueueRaw = Invoke-ReceiptStep -Step "P3_allowq_queue_initial" -CommandArgv @($VenvPython, "-X", "utf8", "-B", "-m", "semgrepai", "queue", "--db", $AllowQDb)
$AllowQJson = $AllowQQueueRaw.stdout | ConvertFrom-Json
$AllowQId = $AllowQJson.warnings[0].id

# 3. Người kiểm duyệt con người thực hiện R03 lifecycle: confirm-false -> queue (ẩn) -> queue --all -> reopen -> history
Invoke-ReceiptStep -Step "P4_allowq_show" -CommandArgv @($VenvPython, "-X", "utf8", "-B", "-m", "semgrepai", "show", $AllowQId, "--db", $AllowQDb)
Invoke-ReceiptStep -Step "P5_allowq_confirm_false" -CommandArgv @(
    $VenvPython, "-X", "utf8", "-B", "-m", "semgrepai", "confirm-false", $AllowQId,
    "--db", $AllowQDb, "--actor", $OperatorActor,
    "--reason", "Verified in-memory exact literal allowlist !SELECT-1.equals(query) throws before executeQuery; no TOCTOU risk"
)
Copy-Item -LiteralPath $AllowQDb -Destination "$AllowQDir\triage\review.after_confirm_false.sqlite"
Invoke-ReceiptStep -Step "P6_allowq_queue_hidden" -CommandArgv @($VenvPython, "-X", "utf8", "-B", "-m", "semgrepai", "queue", "--db", $AllowQDb)
Invoke-ReceiptStep -Step "P7_allowq_queue_all" -CommandArgv @($VenvPython, "-X", "utf8", "-B", "-m", "semgrepai", "queue", "--db", $AllowQDb, "--all")
Invoke-ReceiptStep -Step "P8_allowq_reopen" -CommandArgv @(
    $VenvPython, "-X", "utf8", "-B", "-m", "semgrepai", "reopen", $AllowQId,
    "--db", $AllowQDb, "--actor", $LeadActor,
    "--reason", "R03 reopen lifecycle verification on AllowlistedQuery control"
)
Invoke-ReceiptStep -Step "P9_allowq_queue_reopened" -CommandArgv @($VenvPython, "-X", "utf8", "-B", "-m", "semgrepai", "queue", "--db", $AllowQDb)
Invoke-ReceiptStep -Step "P10_allowq_history" -CommandArgv @($VenvPython, "-X", "utf8", "-B", "-m", "semgrepai", "history", $AllowQId, "--db", $AllowQDb, "--include-rejected")

# 4. Đánh giá bằng chế độ opt-in đề xuất (chỉ dùng sau khi chế độ proposed-allowlisted-fp được phê duyệt)
Invoke-ReceiptStep -Step "P11_evaluate_r01_r03_proposed" -CommandArgv @(
    $VenvPython, "-X", "utf8", "-B", "-m", "v2.g1_integration.evaluate_r01_r03",
    "--demo1-dir", $Demo1Dir,
    "--demo2-dir", $Demo2Dir,
    "--demo3a-dir", $Demo3aDir,
    "--m1-dir", $M1Dir,
    "--demo3b-dir", "$ControlsDir\demo3b_malformed_llm_synthetic_mock",
    "--demo4-dir", "$ControlsDir\demo4_stale_source",
    "--r03-fp-mode", "proposed-allowlisted-fp",
    "--allowlisted-fp-dir", $AllowQDir,
    "--output", "$AuditOut\r01_r03_proposed_evaluation.json"
)
```

### 12.3. Tiêu Chí Chế Độ Đề Xuất (`--r03-fp-mode proposed-allowlisted-fp`)

- Mặc định (`--r03-fp-mode locked-demo2`) vẫn giữ nguyên toàn bộ hợp đồng `G1-C5` đã khóa.
- Ở chế độ `proposed-allowlisted-fp`, bộ đánh giá chỉ-đọc `v2.g1_integration.evaluate_r01_r03`:
  - Giữ nguyên tuyệt đối `R01` (**4** lượt Qwen thật G1-C5: `Demo1=2`, `Demo2=1`, `Demo3a=1`, cộng `Demo3b` mock control) và `R02` (`M1` + parity 4 lượt lịch sử), không thay đổi kết quả hay mẫu số `R01`.
  - Xác minh riêng `allowlisted_query_fp_control` trong phạm vi `R03` (`supplementary_r03_control` tách biệt): đúng định danh/SHA-256 fixture `AllowlistedQuery.java` và guard `throw`, HTTP capture thật, prompt `blind`, validator/replay không bị hạ cấp (`validator_downgraded == false`, `failure_kind == "NONE"`, citation hợp lệ khi có kết luận hoặc trích dẫn), cùng chuỗi `review.post_ingestion.sqlite` (`OPEN`) -> `review.after_confirm_false.sqlite` (`CONFIRMED_FALSE`) -> `reopen` (`OPEN`) bởi actor không mang nhãn `SCRIPTED_TEST_ONLY`/mock/replay.
  - **Không ép trạng thái Qwen thành `REFUTED`:** `OBSERVED_VALID_TRIAGE` chấp nhận kết luận hợp lệ (`REFUTED`, `SUPPORTED`, hoặc `UNDETERMINED`) miễn là qua validator/replay và citation hợp lệ. Nếu Qwen trả `SUPPORTED` hoặc `UNDETERMINED` hợp lệ, bộ đánh giá giữ nguyên trạng thái quan sát được trong `supplementary_r03_control`, ghi rõ `model_fp_concurrence` (`DISAGREED_SUPPORTED` / `ABSTAINED_UNDETERMINED`) và `acceptance_impact` để người kiểm duyệt / giảng viên xác nhận chính sách ngoại lệ FP thay vì chạy lại hoặc che giấu kết quả. Nếu Qwen hỏng định dạng/JSON hoặc citation sai chuẩn (`INVALID_CITATION`, fallback/downgrade), `R03 = FAIL` (vẫn không làm đổi `R01`).
