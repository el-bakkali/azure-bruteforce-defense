###############################################################################
# simulate-attack.ps1
# Triggers the SimulateAttack function to brute-force SSH the defender VM
# Then calls AnalyzeLogs to get the attack report
###############################################################################

param(
    [string]$ResourceGroup = "rg-bruteforce-defense",
    [int]$Attempts = 15
)

$deployInfo = Get-Content (Join-Path $PSScriptRoot "deploy-info.json") | ConvertFrom-Json
$FUNC_APP = $deployInfo.FunctionApp
$DEFENDER_IP = $deployInfo.DefenderIP

Write-Host "`n▶ Triggering SSH brute-force simulation via Function App" -ForegroundColor Cyan
Write-Host "  Target: $DEFENDER_IP | Attempts: $Attempts" -ForegroundColor White

# Get function key
$FUNC_KEY = az functionapp keys list `
    -g $ResourceGroup -n $FUNC_APP `
    --query "functionKeys.default" -o tsv

$BASE_URL = "https://${FUNC_APP}.azurewebsites.net/api"

# 1. Run attack simulation
Write-Host "`n▶ Phase 1: SimulateAttack" -ForegroundColor Yellow
$attackBody = @{ target = $DEFENDER_IP; username = "root"; attempts = $Attempts } | ConvertTo-Json
$attackResult = Invoke-RestMethod -Uri "${BASE_URL}/SimulateAttack?code=${FUNC_KEY}" `
    -Method Post -Body $attackBody -ContentType "application/json"

Write-Host "  Auth failures: $($attackResult.auth_failures)/$($attackResult.total_attempts)" -ForegroundColor White
Write-Host "  $($attackResult.message)" -ForegroundColor Green

# 2. Wait for logs to propagate
Write-Host "`n▶ Waiting 30s for Fail2ban + log ingestion..." -ForegroundColor Yellow
Start-Sleep -Seconds 30

# 3. Analyze logs
Write-Host "`n▶ Phase 2: AnalyzeLogs" -ForegroundColor Yellow
$analyzeBody = @{ hours = 1 } | ConvertTo-Json
$report = Invoke-RestMethod -Uri "${BASE_URL}/AnalyzeLogs?code=${FUNC_KEY}" `
    -Method Post -Body $analyzeBody -ContentType "application/json"

Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                   Attack Analysis Report                   ║" -ForegroundColor Cyan
Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
Write-Host "║ Severity        : $($report.severity)" -ForegroundColor $(if ($report.severity -eq "HIGH" -or $report.severity -eq "CRITICAL") { "Red" } else { "Yellow" })
Write-Host "║ Failed Logins   : $($report.summary.total_failed_logins)" -ForegroundColor White
Write-Host "║ Successful      : $($report.summary.total_successful_logins)" -ForegroundColor White
Write-Host "║ IPs Banned      : $($report.summary.ips_banned_by_fail2ban)" -ForegroundColor White
Write-Host "║ Unique Attackers: $($report.summary.unique_attacker_ips)" -ForegroundColor White
Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
Write-Host "║ Recommendations:" -ForegroundColor Yellow
foreach ($rec in $report.recommendations) {
    Write-Host "║   • $rec" -ForegroundColor White
}
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

# Save report
$report | ConvertTo-Json -Depth 5 | Out-File (Join-Path $PSScriptRoot "attack-report.json") -Encoding utf8
Write-Host "`n  ✔ Full report saved to attack-report.json" -ForegroundColor Green
