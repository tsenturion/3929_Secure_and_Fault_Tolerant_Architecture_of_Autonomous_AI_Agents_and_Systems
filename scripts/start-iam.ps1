[CmdletBinding()]
param([switch]$GigaChat)

$ErrorActionPreference = 'Stop'
$project = Split-Path $PSScriptRoot -Parent
Push-Location -LiteralPath $project
try {
    & (Join-Path $PSScriptRoot 'setup-local-access.ps1') -Iam
    $composeFiles = @('-f', 'compose.yaml', '-f', 'deploy/ephemeral_tokens/compose.yaml')
    if ($GigaChat) { $composeFiles += '-f', 'deploy/model_gateway/compose.yaml' }
    docker compose @composeFiles pull --policy missing keycloak
    if ($LASTEXITCODE -ne 0) { throw 'Не удалось загрузить образ Keycloak.' }
    docker compose @composeFiles up -d --build --wait --wait-timeout 180
    if ($LASTEXITCODE -ne 0) { throw 'Стенд IAM не запустился. Проверьте журналы Docker Compose.' }
} finally {
    Pop-Location
}
