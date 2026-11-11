param(
    [Parameter(Mandatory=$true)][string]$Upstream,
    [Parameter(Mandatory=$true)][string]$AdvisorDir,
    [Parameter(Mandatory=$true)][string]$EvidenceDir,
    [Parameter(Mandatory=$true)][string]$PythonExe,
    [int]$TimeoutSeconds = 180
)

# No branch changes, installation, network bootstrap, or security configuration changes.
$ErrorActionPreference = 'Stop'
$workspacePath = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../..')).Path
$workerPython = (Resolve-Path -LiteralPath $PythonExe).Path
$upstreamPath = (Resolve-Path -LiteralPath $Upstream).Path
$advisorPath = (Resolve-Path -LiteralPath $AdvisorDir).Path
$evidencePath = [System.IO.Path]::GetFullPath($EvidenceDir)
if (Test-Path -LiteralPath $evidencePath) {
    throw 'EvidenceDir already exists. Choose a new directory; previous evidence will not be replaced.'
}
$previousUtf8 = $env:PYTHONUTF8
$previousIoEncoding = $env:PYTHONIOENCODING
$previousBytecode = $env:PYTHONDONTWRITEBYTECODE
Push-Location -LiteralPath $workspacePath
try {
    $env:PYTHONUTF8 = '1'
    $env:PYTHONIOENCODING = 'utf-8'
    $env:PYTHONDONTWRITEBYTECODE = '1'
    & $workerPython (Join-Path $PSScriptRoot 'prove_original_cli.py') `
        --upstream $upstreamPath --advisor-dir $advisorPath --output-dir $evidencePath `
        --python $workerPython --timeout $TimeoutSeconds
    $proofExit = $LASTEXITCODE
} finally {
    $env:PYTHONUTF8 = $previousUtf8
    $env:PYTHONIOENCODING = $previousIoEncoding
    $env:PYTHONDONTWRITEBYTECODE = $previousBytecode
    Pop-Location
}
exit $proofExit
