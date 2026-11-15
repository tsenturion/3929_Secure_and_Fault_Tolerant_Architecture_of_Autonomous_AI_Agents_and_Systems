[CmdletBinding()]
param([switch]$GigaChat)

$ErrorActionPreference = 'Stop'
Push-Location -LiteralPath (Split-Path $PSScriptRoot -Parent)
try {
    & (Join-Path $PSScriptRoot 'setup-local-access.ps1') -Postgres
    $composeArgs = @('-f', 'compose.yaml', '-f', 'deploy/distributed_recovery/compose.yaml')
    if ($GigaChat) { $composeArgs += '-f', 'deploy/model_gateway/compose.yaml' }
    docker compose @composeArgs pull --policy missing postgres
    if ($LASTEXITCODE -ne 0) { throw 'Не удалось загрузить образ PostgreSQL.' }
    docker compose @composeArgs up -d --build --wait --wait-timeout 100
    if ($LASTEXITCODE -ne 0) { throw 'Стенд восстановления не запустился.' }
} finally {
    Pop-Location
}
