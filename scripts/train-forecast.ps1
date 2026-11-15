[CmdletBinding()]
param([switch]$PyTorch, [string]$PythonPath = '')

$ErrorActionPreference = 'Stop'
Push-Location -LiteralPath (Split-Path $PSScriptRoot -Parent)
try {
    $backend = if ($PyTorch) { 'pytorch' } else { 'numpy' }
    if ($PythonPath) {
        & $PythonPath -m dispatcher.resilience.forecasting.train_forecast --backend $backend
    } elseif ($PyTorch) {
        uv run --index https://download.pytorch.org/whl/cpu --with numpy --with torch python -m dispatcher.resilience.forecasting.train_forecast --backend $backend
    } else {
        uv run --with numpy python -m dispatcher.resilience.forecasting.train_forecast --backend $backend
    }
    if ($LASTEXITCODE -ne 0) { throw 'Обучение прогноза завершилось ошибкой.' }
} finally {
    Pop-Location
}
