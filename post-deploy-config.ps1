###############################################################################
# post-deploy-config.ps1
# Deploys Function App code to Azure
###############################################################################

param(
    [string]$ResourceGroup = "rg-bruteforce-defense"
)

$ErrorActionPreference = "Stop"
$deployInfo = Get-Content (Join-Path $PSScriptRoot "deploy-info.json") | ConvertFrom-Json

$FUNC_APP = $deployInfo.FunctionApp
$VM = $deployInfo.DefenderVM

# 1. Deploy Function App code with dependencies bundled in the zip
Write-Host "`n▶ Installing Python packages locally..." -ForegroundColor Cyan
Push-Location (Join-Path $PSScriptRoot "function-app")

# Install packages for Python 3.11 Linux x86_64 (matching the Function App runtime)
$pkgDir = Join-Path (Get-Location) ".python_packages" "lib" "site-packages"
if (Test-Path (Join-Path (Get-Location) ".python_packages")) {
    Remove-Item -Recurse -Force (Join-Path (Get-Location) ".python_packages")
}
pip install -r requirements.txt --target $pkgDir `
    --platform manylinux2014_x86_64 --python-version 3.11 `
    --only-binary=:all: --quiet --no-deps 2>$null

pip install -r requirements.txt --target $pkgDir `
    --platform manylinux2014_x86_64 --python-version 3.11 `
    --only-binary=:all: --quiet 2>$null
Write-Host "  ✔ Python packages installed" -ForegroundColor Green

Write-Host "`n▶ Deploying Function App code..." -ForegroundColor Cyan
$zipPath = Join-Path $PSScriptRoot "function-app.zip"
if (Test-Path $zipPath) { Remove-Item $zipPath }
Compress-Archive -Path * -DestinationPath $zipPath

# Remove the connection-string AzureWebJobsStorage if present (SharedKey policy blocks it)
az functionapp config appsettings delete `
    -g $ResourceGroup -n $FUNC_APP `
    --setting-names AzureWebJobsStorage --output none 2>$null

az functionapp deployment source config-zip `
    -g $ResourceGroup -n $FUNC_APP --src $zipPath --timeout 300 --output none

Pop-Location
Write-Host "  ✔ Function App deployed (SimulateAttack + AnalyzeLogs)" -ForegroundColor Green

# 2. Summary
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║              Post-Deployment Complete!                     ║" -ForegroundColor Green
Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Green
Write-Host "║ Function Endpoints:                                        ║" -ForegroundColor White
Write-Host "║   SimulateAttack → /api/SimulateAttack                    ║" -ForegroundColor White
Write-Host "║   AnalyzeLogs    → /api/AnalyzeLogs                       ║" -ForegroundColor White
Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Green
Write-Host "║ Ready:  .\simulate-attack.ps1                             ║" -ForegroundColor Yellow
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
