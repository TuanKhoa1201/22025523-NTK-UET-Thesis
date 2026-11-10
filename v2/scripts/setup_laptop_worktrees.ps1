param()
$ErrorActionPreference = "Stop"

$repoPath = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
$workspaceRoot = Split-Path -Parent $repoPath
$baseBranch = "thesis-v2/opengrep-qwen"
if (-not (Test-Path -LiteralPath (Join-Path $repoPath ".git"))) {
    throw "Run this script from a cloned repository in a parent workspace (integration)."
}
$currentBranch = (& git -C $repoPath branch --show-current)
if ($LASTEXITCODE -ne 0 -or $currentBranch.Trim() -ne $baseBranch) {
    throw "Checkout $baseBranch in integration before creating worktrees."
}
foreach ($name in @("incoming", "evidence")) {
    New-Item -ItemType Directory -Force -Path (Join-Path $workspaceRoot $name) | Out-Null
}

function Add-Worktree([string]$name, [string]$branch) {
    $path = Join-Path $workspaceRoot $name
    if (Test-Path -LiteralPath $path) {
        Write-Host "Already exists; inspect manually: $path" -ForegroundColor Yellow
        return
    }
    & git -C $repoPath show-ref --verify --quiet "refs/heads/$branch"
    if ($LASTEXITCODE -eq 0) {
        & git -C $repoPath worktree add $path $branch
    } else {
        & git -C $repoPath worktree add -b $branch $path $baseBranch
    }
    if ($LASTEXITCODE -ne 0) { throw "Failed creating worktree: $name" }
}
Add-Worktree "codex" "v2/codex-core"
Add-Worktree "antigravity" "v2/antigravity-review"
Write-Host ""
Write-Host "Prepared NTK V2 workspaces (legacy repo untouched):" -ForegroundColor Green
Write-Host "INTEGRATION: $repoPath"
Write-Host "CODEX:       $(Join-Path $workspaceRoot 'codex')"
Write-Host "ANTIGRAVITY: $(Join-Path $workspaceRoot 'antigravity')"
Write-Host "INCOMING:    $(Join-Path $workspaceRoot 'incoming')"
Write-Host "EVIDENCE:    $(Join-Path $workspaceRoot 'evidence')"
& git -C $repoPath worktree list
