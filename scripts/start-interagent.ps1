[CmdletBinding()]
param([switch]$GigaChat)

$ErrorActionPreference = 'Stop'
Push-Location -LiteralPath (Split-Path $PSScriptRoot -Parent)
try {
    & (Join-Path $PSScriptRoot 'setup-local-access.ps1') -Iam -Interagent
    uv run --locked python -m dispatcher.identity.workload_identity.identity_pki --interagent
    if ($LASTEXITCODE -ne 0) { throw 'Не удалось подготовить сертификаты агентов.' }
    $composeArgs = @('-f', 'compose.yaml', '-f', 'deploy/ephemeral_tokens/compose.yaml',
        '-f', 'deploy/workload_identity/compose.yaml', '-f', 'deploy/interagent_auth/compose.yaml')
    if ($GigaChat) { $composeArgs += '-f', 'deploy/model_gateway/compose.yaml' }
    docker compose @composeArgs pull --policy missing keycloak
    if ($LASTEXITCODE -ne 0) { throw 'Не удалось загрузить образ Keycloak.' }
    docker compose @composeArgs up -d --build --wait --wait-timeout 180
    if ($LASTEXITCODE -ne 0) { throw 'Стенд межагентной аутентификации не запустился.' }
} finally {
    Pop-Location
}
