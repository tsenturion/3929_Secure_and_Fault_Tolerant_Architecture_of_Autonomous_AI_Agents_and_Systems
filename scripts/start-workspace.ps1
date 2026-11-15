[CmdletBinding()]
param([switch]$Postgres, [switch]$Observability, [switch]$GigaChat)

$ErrorActionPreference = 'Stop'
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Для запуска установите Docker Desktop с Compose.'
}
$dockerOS = docker info --format '{{.OSType}}'
if ($LASTEXITCODE -ne 0 -or $dockerOS -ne 'linux') {
    throw 'Запустите Docker Desktop в режиме контейнеров Linux.'
}
docker compose version --short | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'В Docker должен быть доступен Compose.' }

$previousProvider = $env:MODEL_PROVIDER
Push-Location -LiteralPath (Split-Path $PSScriptRoot -Parent)
try {
    & (Join-Path $PSScriptRoot 'setup-local-access.ps1') -Postgres:$Postgres
    $composeArgs = @('-f', 'compose.yaml')
    if ($Postgres) { $composeArgs += '-f', 'deploy/distributed_recovery/compose.yaml' }
    if ($Observability) { $composeArgs += '-f', 'deploy/tracing/compose.yaml' }
    if ($GigaChat) {
        $composeArgs += '-f', 'deploy/model_gateway/compose.yaml'
        $env:MODEL_PROVIDER = 'gigachat'
    }
    docker compose @composeArgs up -d --build --wait --wait-timeout 100
    if ($LASTEXITCODE -ne 0) { throw 'Рабочий кабинет не запустился.' }
    Write-Output 'Порт рабочего кабинета указан в выводе docker compose port frontend 8080.'
    docker compose @composeArgs port frontend 8080
} finally {
    if ($GigaChat) { $env:MODEL_PROVIDER = $previousProvider }
    Pop-Location
}
