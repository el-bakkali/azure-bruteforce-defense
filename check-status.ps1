###############################################################################
# check-status.ps1
# Verifies the demo environment is working correctly
###############################################################################

param(
    [string]$ResourceGroup = "rg-bruteforce-defense"
)

$deployInfo = Get-Content (Join-Path $PSScriptRoot "deploy-info.json") | ConvertFrom-Json

Write-Host "`n═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Environment Status Check: $ResourceGroup" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════`n" -ForegroundColor Cyan

# 1. Defender VM
Write-Host "▶ Defender VM:" -ForegroundColor Yellow
az vm show -g $ResourceGroup -n $deployInfo.DefenderVM --show-details `
    --query "{Name:name, PowerState:powerState, PublicIP:publicIps}" -o table

# 2. NSG rules (check for auto-added deny rules)
Write-Host "`n▶ NSG Rules:" -ForegroundColor Yellow
az network nsg rule list -g $ResourceGroup --nsg-name $deployInfo.NSG `
    --query "[].{Name:name, Priority:priority, Access:access, Direction:direction, SrcAddr:sourceAddressPrefix, DstPort:destinationPortRange}" `
    -o table

# 3. Fail2ban
Write-Host "`n▶ Fail2ban Status:" -ForegroundColor Yellow
az vm run-command invoke -g $ResourceGroup -n $deployInfo.DefenderVM `
    --command-id RunShellScript `
    --scripts "sudo fail2ban-client status sshd 2>/dev/null || echo 'Fail2ban not running'" `
    --query "value[0].message" -o tsv

# 4. Function App + Functions
Write-Host "`n▶ Function App:" -ForegroundColor Yellow
az functionapp show -g $ResourceGroup -n $deployInfo.FunctionApp `
    --query "{Name:name, State:state, URL:defaultHostName}" -o table

Write-Host "`n▶ Deployed Functions:" -ForegroundColor Yellow
az functionapp function list -g $ResourceGroup -n $deployInfo.FunctionApp `
    --query "[].{Name:name}" -o table

# 5. Log Analytics
Write-Host "`n▶ Log Analytics Workspace:" -ForegroundColor Yellow
az monitor log-analytics workspace show -g $ResourceGroup -n $deployInfo.LAWorkspace `
    --query "{Name:name, CustomerId:customerId, RetentionDays:retentionInDays}" -o table

# 6. Sentinel
Write-Host "`n▶ Microsoft Sentinel:" -ForegroundColor Yellow
az security insights show -g $ResourceGroup -n $deployInfo.LAWorkspace `
    --query "{Name:name}" -o table 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "  (Sentinel check requires 'az security' extension)" -ForegroundColor DarkGray
}

# 7. DCRs
Write-Host "`n▶ Data Collection Rules:" -ForegroundColor Yellow
az monitor data-collection rule list -g $ResourceGroup `
    --query "[].{Name:name, Location:location}" -o table

# 8. Alert Rules
Write-Host "`n▶ Log Alert Rules:" -ForegroundColor Yellow
az monitor scheduled-query list -g $ResourceGroup `
    --query "[].{Name:name, Severity:severity, Enabled:enabled}" -o table 2>$null

Write-Host "`n═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Status check complete" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════`n" -ForegroundColor Cyan
