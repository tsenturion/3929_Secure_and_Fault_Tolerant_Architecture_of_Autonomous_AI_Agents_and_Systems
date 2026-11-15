[CmdletBinding()]
param([switch]$GigaChat)

$ErrorActionPreference = 'Stop'
Push-Location -LiteralPath (Split-Path $PSScriptRoot -Parent)
try {
    & (Join-Path $PSScriptRoot 'setup-local-access.ps1')
    $composeArgs = @('-f', 'compose.yaml', '-f', 'deploy/tracing/compose.yaml')
    if ($GigaChat) { $composeArgs += '-f', 'deploy/model_gateway/compose.yaml' }
    docker compose @composeArgs pull --policy missing loki log-collector
    if ($LASTEXITCODE -ne 0) { throw 'Не удалось загрузить образы Loki и Fluent Bit.' }
    docker compose @composeArgs up -d --build --wait --wait-timeout 120
    if ($LASTEXITCODE -ne 0) { throw 'Стенд наблюдаемости не запустился.' }
    @'
from time import monotonic, sleep
from urllib.request import urlopen

deadline = monotonic() + 45
while True:
    try:
        with urlopen("http://loki:3100/ready", timeout=2):
            break
    except OSError:
        if monotonic() >= deadline:
            raise SystemExit(1)
        sleep(1)
'@ | docker compose @composeArgs exec -T agent python -
    if ($LASTEXITCODE -ne 0) { throw 'Loki не подтвердил готовность. Проверьте журналы контейнера.' }
} finally {
    Pop-Location
}
