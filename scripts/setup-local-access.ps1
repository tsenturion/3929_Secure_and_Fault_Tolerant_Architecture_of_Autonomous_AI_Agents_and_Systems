[CmdletBinding()]
param([switch]$Iam, [switch]$Interagent, [switch]$Postgres)

$ErrorActionPreference = 'Stop'
$projectEnv = Join-Path (Join-Path $PSScriptRoot '..') '.env'
$envText = if (Test-Path -LiteralPath $projectEnv) { [IO.File]::ReadAllText($projectEnv) } else { '' }
$encoding = [Text.UTF8Encoding]::new($false)
$updated = @()

$names = @('SERVICE_TOKEN', 'DUTY_OPERATOR_TOKEN', 'OBSERVER_TOKEN', 'MONITORING_TOKEN', 'RUNBOOK_CATALOG_TOKEN')
if ($Iam) { $names += 'IAM_EXECUTOR_CLIENT_SECRET', 'IAM_MONITORING_CLIENT_SECRET' }
if ($Interagent) { $names += 'IAM_RUNBOOK_CLIENT_SECRET' }
if ($Postgres) { $names += 'POSTGRES_ADMIN_PASSWORD', 'DISPATCHER_DB_PASSWORD', 'AUDIT_DB_PASSWORD' }
foreach ($name in $names) {
    $pattern = "(?m)^[ \t]*$name[ \t]*=[^\r\n]*"
    $entries = [regex]::Matches($envText, $pattern)
    if ($entries.Count -gt 1) { throw "Параметр $name задан несколько раз." }
    if ($entries.Count -eq 1) {
        $value = ($entries[0].Value -split '=', 2)[1].Trim().Trim('"').Trim("'")
        if ($value) {
            if ($value.Length -lt 32) { throw "Параметр $name должен содержать минимум 32 символа." }
            continue
        }
    }
    $bytes = New-Object byte[] 32
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $random.GetBytes($bytes) } finally { $random.Dispose() }
    $token = [BitConverter]::ToString($bytes).Replace('-', '').ToLowerInvariant()
    $entry = "$name=$token"
    if ($entries.Count -eq 1) {
        $envText = [regex]::Replace($envText, $pattern, $entry)
    } else {
        $envText = $envText.TrimEnd("`r", "`n") + [Environment]::NewLine + $entry + [Environment]::NewLine
    }
    $updated += $name
}

if ($updated.Count -gt 0) {
    [IO.File]::WriteAllText($projectEnv, $envText, $encoding)
    Write-Output ("Настроены параметры: " + ($updated -join ', '))
} else {
    Write-Output 'Ключи локального стенда уже настроены.'
}
