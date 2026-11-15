[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Push-Location -LiteralPath (Join-Path $PSScriptRoot '..')
try {
    uv sync --locked --extra qwen
    if ($LASTEXITCODE -ne 0) {
        throw 'Не удалось установить зависимости локальной модели.'
    }
} finally {
    Pop-Location
}
