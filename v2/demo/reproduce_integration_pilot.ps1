<#
.SYNOPSIS
    Fail-closed reproducible verification script for NTK Thesis V2 Integration Pilot.
.DESCRIPTION
    Supports two strictly separated execution modes into a brand-new timestamped directory ($EvidenceRoot):
    - REPLAY (default): Uses locked raw scan + verified Qwen3.5:9b-q4_K_M assessments without new LLM inference.
      Refuses to pair any raw scan with assessments or labels if scan_sha256 does not match.
    - LIVE (-Mode LIVE or -RunLiveLlm): Runs fresh OpenGrep scan (JSON + SARIF), executes live Ollama triage,
      verifies live model runtime metadata on every warning, projects labels to the live scan_sha256, and scores.
    Every external command (python, pytest, wsl.exe/opengrep) is checked for exit code; any non-zero exit code
    immediately aborts before the COMPLETE banner can be printed.
#>
param(
    [ValidateSet("REPLAY", "LIVE")]
    [string]$Mode = "REPLAY",
    [string]$Model = "qwen3.5:9b-q4_K_M",
    [string]$Endpoint = "http://127.0.0.1:11434",
    [string]$EvidenceRoot = "",
    [string]$ReplayOpenGrepJson = "v2/demo/smoke_m1_rules_raw.opengrep.json",
    [string]$ReplayTriageJsonl = "v2/demo/triage_qwen35_9b_smoke_m1_assessments.jsonl",
    [string]$LabelsJson = "v2/evaluation/smoke_m1_verified_labels.json",
    [string]$InjectFailureStep = "",
    [switch]$SkipHeavyDemos = $false,
    [switch]$RunLiveLlm = $false
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($RunLiveLlm) {
    $Mode = "LIVE"
}
$Mode = $Mode.ToUpperInvariant()

$ValidSteps = @(
    "verify_repository",
    "verify_patch",
    "pytest_core",
    "pytest_quality_gate",
    "demo_queue",
    "demo_freshness",
    "verify_handoff",
    "opengrep_json_scan",
    "opengrep_sarif_scan",
    "live_triage_run",
    "verify_scan_hash_contract",
    "build_paired_pilot_table",
    "score_pilot"
)

if (-not [string]::IsNullOrWhiteSpace($InjectFailureStep) -and ($ValidSteps -notcontains $InjectFailureStep)) {
    [Console]::Error.WriteLine("[FAIL-CLOSED] Unknown InjectFailureStep '$InjectFailureStep'. Valid steps: $($ValidSteps -join ', ')")
    exit 64
}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $RepoRoot

if ([string]::IsNullOrWhiteSpace($EvidenceRoot)) {
    $Stamp = (Get-Date).ToString("yyyyMMdd_HHmmss_fff")
    $DefaultBase = if ($env:OS -eq "Windows_NT") { "C:\Users\Admin\ntk-thesis-v2\evidence" } else { [System.IO.Path]::GetTempPath() }
    $EvidenceRoot = Join-Path $DefaultBase "repro_$($Mode.ToLowerInvariant())_$Stamp"
}

$NormalizedEvidenceRoot = [System.IO.Path]::GetFullPath($EvidenceRoot)
$NormalizedRepoRoot = [System.IO.Path]::GetFullPath($RepoRoot)
if ($NormalizedEvidenceRoot.StartsWith($NormalizedRepoRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    [Console]::Error.WriteLine("[FAIL-CLOSED] EvidenceRoot '$NormalizedEvidenceRoot' cannot be inside Git repository '$NormalizedRepoRoot'.")
    exit 2
}
if (Test-Path -LiteralPath $NormalizedEvidenceRoot) {
    [Console]::Error.WriteLine("[FAIL-CLOSED] EvidenceRoot '$NormalizedEvidenceRoot' already exists. Refusing to overwrite existing evidence.")
    exit 2
}

New-Item -ItemType Directory -Path $NormalizedEvidenceRoot | Out-Null
$EvidenceRoot = $NormalizedEvidenceRoot
$LocalOpenGrepDir = "C:\Users\Admin\ntk-thesis-v2\tools\opengrep\v1.25.0"
if (Test-Path -LiteralPath $LocalOpenGrepDir) {
    $env:PATH = "$LocalOpenGrepDir;$env:PATH"
}

function Invoke-CheckedStep {
    param(
        [Parameter(Mandatory = $true)][string]$StepName,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )
    $global:LASTEXITCODE = 0
    if (-not [string]::IsNullOrWhiteSpace($InjectFailureStep) -and ($InjectFailureStep -ieq $StepName)) {
        [Console]::Error.WriteLine("[FAULT-INJECTION] Triggering intentional failure at step '$StepName'.")
        python -c "import sys; sys.stderr.write('Intentional fault injected at step $StepName\n'); sys.exit(99)"
    } else {
        & $Action
    }
    $exitCode = $LASTEXITCODE
    if ($null -ne $exitCode -and $exitCode -ne 0) {
        [Console]::Error.WriteLine("[FAIL-CLOSED] Step '$StepName' failed with exit code $exitCode. Aborting reproduction.")
        exit $exitCode
    }
}

try {
    if (-not $SkipHeavyDemos) {
        Write-Host "=== [1/4] [MODE=$Mode] Verifying Repository Policy, Upstream Patch, and V2 Unit Tests ==="
        Invoke-CheckedStep "verify_repository" {
            python scripts/verify-repository.py
        }
        Invoke-CheckedStep "verify_patch" {
            python v2/baseline/verify_patch.py
        }
        Invoke-CheckedStep "pytest_core" {
            python -m pytest v2/baseline/tests v2/triage/tests v2/evaluation/tests -q
        }
        if ($env:NTK_V2_IN_QUALITY_GATE_TEST -ne "1") {
            Invoke-CheckedStep "pytest_quality_gate" {
                python -m pytest v2/demo/tests -q
            }
        }

        Write-Host "=== [2/4] [MODE=$Mode] Running End-to-End Review Queue & SHA-256 Freshness Tamper Verification ==="
        Invoke-CheckedStep "demo_queue" {
            python -m v2.triage.demo_queue --output-dir (Join-Path $EvidenceRoot "queue_demo")
        }
        Invoke-CheckedStep "demo_freshness" {
            python -m v2.triage.demo_freshness --output-dir (Join-Path $EvidenceRoot "freshness_demo")
        }
        Invoke-CheckedStep "verify_handoff" {
            python v2/baseline/verify_handoff.py `
                --engine (Join-Path $EvidenceRoot "freshness_demo\run\engine") `
                --triage (Join-Path $EvidenceRoot "freshness_demo\run")
        }
    }

    if ($Mode -eq "REPLAY") {
        Write-Host "=== [3/4] [MODE=REPLAY] Verifying Locked Scan-Hash & Provenance Contract (No Live Inference) ==="
        $ScanJsonForEval = $ReplayOpenGrepJson
        $TriageJsonlForEval = $ReplayTriageJsonl
        $LabelsJsonForEval = $LabelsJson

        Invoke-CheckedStep "verify_scan_hash_contract" {
            python v2/demo/verify_repro_contract.py replay `
                --opengrep $ScanJsonForEval `
                --triage $TriageJsonlForEval `
                --labels $LabelsJsonForEval `
                --output-report (Join-Path $EvidenceRoot "contract_verification_receipt.json")
        }
    } else {
        Write-Host "=== [3/4] [MODE=LIVE] Running Fresh OpenGrep Scan (ScanCapture), Live Ollama Triage, and Runtime Verification ==="
        $LiveScanDir = Join-Path $EvidenceRoot "live_scan"
        $SmokeSourceRoot = Join-Path $RepoRoot "v2\evaluation\smoke_evidence"
        $LiveOpenGrepJson = Join-Path $LiveScanDir "opengrep.json"
        $LiveOpenGrepSarif = Join-Path $LiveScanDir "opengrep.sarif"
        $LiveScanManifest = Join-Path $LiveScanDir "scan-manifest.json"

        $env:PYTHONPATH = "v2/baseline/fork"
        try {
            Invoke-CheckedStep "opengrep_json_scan" {
                python -m semgrepai $SmokeSourceRoot `
                    --rules-path "v2/baseline/rules/java.yml" `
                    --output-dir $LiveScanDir
            }
        } finally {
            Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
        }

        Invoke-CheckedStep "opengrep_sarif_scan" {
            python -c "import pathlib, sys; p_j, p_s, p_m = map(pathlib.Path, sys.argv[1:4]); sys.exit(0 if (p_j.is_file() and p_s.is_file() and p_m.is_file()) else 2)" `
                $LiveOpenGrepJson $LiveOpenGrepSarif $LiveScanManifest
        }

        $LiveOut = Join-Path $EvidenceRoot "triage_live_qwen35"
        Invoke-CheckedStep "live_triage_run" {
            python -m v2.triage run `
                --source-root $SmokeSourceRoot `
                --json $LiveOpenGrepJson `
                --scan-manifest $LiveScanManifest `
                --engine-exit 0 `
                --output-dir $LiveOut `
                --endpoint $Endpoint `
                --model $Model `
                --timeout 180
        }

        Invoke-CheckedStep "verify_handoff" {
            python v2/baseline/verify_handoff.py `
                --engine $LiveScanDir `
                --triage $LiveOut
        }

        Invoke-CheckedStep "verify_handoff" {
            python -m v2.triage.live_check $LiveOut --minimum-responses 3
        }

        $ScanJsonForEval = $LiveOpenGrepJson
        $TriageJsonlForEval = Join-Path $LiveOut "assessments.jsonl"
        $LabelsJsonForEval = Join-Path $LiveScanDir "smoke_m1_live_labels.json"

        Invoke-CheckedStep "verify_scan_hash_contract" {
            python v2/demo/verify_repro_contract.py live `
                --opengrep $ScanJsonForEval `
                --scan-manifest $LiveScanManifest `
                --source-root $SmokeSourceRoot `
                --triage $TriageJsonlForEval `
                --template-labels $LabelsJson `
                --expected-model $Model `
                --output-labels $LabelsJsonForEval `
                --output-report (Join-Path $EvidenceRoot "contract_verification_receipt.json")
        }
    }

    Write-Host "=== [4/4] [MODE=$Mode] Building Paired Pilot Table (.csv/.json) and Scoring Verified Evidence ==="
    Invoke-CheckedStep "build_paired_pilot_table" {
        python v2/evaluation/build_paired_pilot_table.py `
            --opengrep $ScanJsonForEval `
            --labels $LabelsJsonForEval `
            --qwen35-triage $TriageJsonlForEval `
            --qwen3-8b-reference "v2/demo/triage_qwen3_8b_summary.json" `
            --source-root $RepoRoot `
            --output-csv (Join-Path $EvidenceRoot "ADVISOR_PAIRED_PILOT_20261111.csv") `
            --output-json (Join-Path $EvidenceRoot "paired_pilot_summary.json")
    }

    $env:PYTHONPATH = "v2/evaluation"
    try {
        Invoke-CheckedStep "score_pilot" {
            if ($Mode -eq "LIVE") {
                python -m v2.evaluation.score_pilot `
                    --opengrep $ScanJsonForEval `
                    --labels $LabelsJsonForEval `
                    --triage $TriageJsonlForEval `
                    --source-root $RepoRoot `
                    --require-scan-provenance `
                    --output-json (Join-Path $EvidenceRoot "score_pilot_verified.json") `
                    --output-md (Join-Path $EvidenceRoot "score_pilot_verified.md")
            } else {
                python -m v2.evaluation.score_pilot `
                    --opengrep $ScanJsonForEval `
                    --labels $LabelsJsonForEval `
                    --triage $TriageJsonlForEval `
                    --source-root $RepoRoot `
                    --output-json (Join-Path $EvidenceRoot "score_pilot_verified.json") `
                    --output-md (Join-Path $EvidenceRoot "score_pilot_verified.md")
            }
        }
    } finally {
        Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
    }

    Write-Host "=== COMPLETE: [MODE=$Mode] All verification artifacts written to $EvidenceRoot ==="
    exit 0
} catch {
    [Console]::Error.WriteLine("[FAIL-CLOSED] Unhandled exception in reproduction script: $($_.Exception.Message)")
    exit 1
}
