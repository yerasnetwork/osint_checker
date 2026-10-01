param([int]$Port = 8765)
$ErrorActionPreference = 'Stop'
Push-Location -LiteralPath $PSScriptRoot
try {
    python -m cybercheck serve --port $Port
} finally {
    Pop-Location
}
