[CmdletBinding()]
param([switch]$Rotate, [switch]$CertificatesOnly, [switch]$GigaChat)

$ErrorActionPreference = 'Stop'
$previousSigner = $env:TPM_SIGNER_URL
Push-Location -LiteralPath (Split-Path $PSScriptRoot -Parent)
try {
    if ($Rotate) {
        uv run --locked python -m dispatcher.identity.workload_identity.identity_pki --rotate
        if ($LASTEXITCODE -ne 0) { throw 'Не удалось выпустить новый сертификат агента.' }
        return
    }
    & (Join-Path $PSScriptRoot 'setup-local-access.ps1')
    uv run --locked python -m dispatcher.identity.workload_identity.identity_pki
    if ($LASTEXITCODE -ne 0) { throw 'Не удалось подготовить сертификаты.' }
    $composeArgs = @('-f', 'compose.yaml', '-f', 'deploy/workload_identity/compose.yaml')
    if ($GigaChat) { $composeArgs += '-f', 'deploy/model_gateway/compose.yaml' }
    if ($CertificatesOnly) {
        $env:TPM_SIGNER_URL = ''
    } else {
        $composeArgs += '--profile', 'tpm'
        $env:TPM_SIGNER_URL = 'http://tpm-signer:8003'
    }
    docker compose @composeArgs up -d --build --wait --wait-timeout 120
    if ($LASTEXITCODE -ne 0) { throw 'Стенд идентификации не запустился. Проверьте журналы Docker Compose.' }
    $cabinetAddress = docker compose @composeArgs port frontend 8080
    if ($LASTEXITCODE -eq 0 -and $cabinetAddress) {
        Write-Output "Откройте кабинет стенда с сертификатами по адресу http://$cabinetAddress"
    }
} finally {
    $env:TPM_SIGNER_URL = $previousSigner
    Pop-Location
}
