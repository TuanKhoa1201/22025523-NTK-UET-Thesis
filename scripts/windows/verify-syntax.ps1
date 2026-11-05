$ErrorActionPreference = "Stop"
$files = @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter "*.ps1" -File)
if ($files.Count -eq 0) { throw "Khong tim thay script PowerShell can kiem tra." }
foreach ($file in $files) {
    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile(
        $file.FullName, [ref]$tokens, [ref]$errors
    ) | Out-Null
    if ($errors.Count -gt 0) {
        foreach ($item in $errors) { Write-Error "$($file.Name): $($item.Message)" }
        throw "Script PowerShell co loi cu phap."
    }
}
Write-Host "PASS: $($files.Count) script PowerShell hop le." -ForegroundColor Green
