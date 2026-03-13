###############################################################################
# deploy-infrastructure.ps1
# Deploys "Defend an Azure Linux VM from Brute-Force SSH" demo environment
#
# Architecture (no attacker VM — Function App does everything):
#   1 Defender VM (B2s) — Fail2ban + AMA + auditd
#   1 Function App with 2 functions:
#     - SimulateAttack  → paramiko SSH brute-force against defender VM
#     - AnalyzeLogs     → queries Log Analytics, returns attack analysis
#   Log Analytics + Sentinel + DCRs (syslog + audit.log) + Log Alerts
###############################################################################

param(
    [string]$ResourceGroup  = "rg-bruteforce-defense",
    [string]$Location       = "uksouth",
    [string]$SubscriptionId = "",  # Your Azure subscription ID
    [string]$AdminUsername   = "azuredefender",
    [string]$AdminPassword   = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step { param([string]$msg) Write-Host "`n▶ $msg" -ForegroundColor Cyan }
function Write-OK   { param([string]$msg) Write-Host "  ✔ $msg" -ForegroundColor Green }
function Write-Warn { param([string]$msg) Write-Host "  ⚠ $msg" -ForegroundColor Yellow }

# ── Pre-flight ───────────────────────────────────────────────────────────────
Write-Step "Pre-flight checks"
az account set --subscription $SubscriptionId
Write-OK "Subscription: $SubscriptionId"

if (-not $AdminPassword) {
    # Auto-generate a password safe from cmd.exe special-char issues
    $safeChars = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789@#_-.'
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] 16
    $rng.GetBytes($bytes)
    $pw = ($bytes | ForEach-Object { $safeChars[$_ % $safeChars.Length] }) -join ''
    # Ensure complexity: prepend guaranteed upper + lower + digit + special
    $AdminPassword = "Aa1@" + $pw
    Write-Host "  Generated VM password (save this): $AdminPassword" -ForegroundColor Yellow
}

$PREFIX = "bfdef"
$VNET   = "$PREFIX-vnet"
$SUBNET = "snet-defender"
$NSG    = "$PREFIX-nsg"
$VM     = "$PREFIX-vm"
$LA_WORKSPACE = "$PREFIX-law"
$FUNC_APP     = "$PREFIX-func-$(Get-Random -Maximum 9999)"
$STORAGE_ACCT = "${PREFIX}stor$(Get-Random -Maximum 99999)"

# ── 1. Resource Group ────────────────────────────────────────────────────────
Write-Step "Creating Resource Group: $ResourceGroup ($Location)"
az group create --name $ResourceGroup --location $Location --output none
Write-OK "Resource group created"

# ── 2. VNet + Subnet ─────────────────────────────────────────────────────────
Write-Step "Creating VNet"
az network vnet create `
    --resource-group $ResourceGroup --name $VNET `
    --address-prefix "10.0.0.0/16" `
    --subnet-name $SUBNET --subnet-prefix "10.0.1.0/24" `
    --output none
Write-OK "VNet $VNET created"

# ── 3. NSG ───────────────────────────────────────────────────────────────────
Write-Step "Creating NSG"
az network nsg create --resource-group $ResourceGroup --name $NSG --output none
az network nsg rule create `
    --resource-group $ResourceGroup --nsg-name $NSG `
    --name "AllowSSH" --priority 1000 --direction Inbound `
    --access Allow --protocol Tcp --destination-port-ranges 22 `
    --source-address-prefixes "*" --output none
Write-OK "NSG created with SSH allow rule"

# ── 4. Defender VM (B2s) ─────────────────────────────────────────────────────
Write-Step "Creating Defender VM: $VM (Standard_B2s)"
az vm create `
    --resource-group $ResourceGroup --name $VM `
    --image "Canonical:0001-com-ubuntu-server-jammy:22_04-lts-gen2:latest" `
    --size "Standard_B2s" `
    --vnet-name $VNET --subnet $SUBNET --nsg $NSG `
    --admin-username $AdminUsername --admin-password "$AdminPassword" `
    --authentication-type password --public-ip-sku Standard `
    --output none
Write-OK "Defender VM created"

$DEFENDER_IP = az vm show -g $ResourceGroup -n $VM --show-details --query publicIps -o tsv
Write-OK "Public IP: $DEFENDER_IP"

# ── 5. Log Analytics Workspace ───────────────────────────────────────────────
Write-Step "Creating Log Analytics Workspace"
az monitor log-analytics workspace create `
    --resource-group $ResourceGroup --workspace-name $LA_WORKSPACE `
    --location $Location --retention-time 30 --output none

$LAW_ID = az monitor log-analytics workspace show `
    -g $ResourceGroup -n $LA_WORKSPACE --query customerId -o tsv
$LAW_RES_ID = az monitor log-analytics workspace show `
    -g $ResourceGroup -n $LA_WORKSPACE --query id -o tsv

$LAW_KEY = az monitor log-analytics workspace get-shared-keys `
    -g $ResourceGroup -n $LA_WORKSPACE --query primarySharedKey -o tsv
Write-OK "LAW: $LA_WORKSPACE ($LAW_ID)"

# ── 6. Azure Monitor Agent ──────────────────────────────────────────────────
Write-Step "Installing AMA on VM"
az vm extension set `
    -g $ResourceGroup --vm-name $VM `
    --name AzureMonitorLinuxAgent --publisher Microsoft.Azure.Monitor `
    --enable-auto-upgrade true --output none
Write-OK "AMA installed"

# ── 7. DCRs ─────────────────────────────────────────────────────────────────
Write-Step "Creating Data Collection Rules"

# 7a. Syslog DCR (auth/authpriv)
$DCR_SYSLOG = "$PREFIX-dcr-syslog"
$dcrSyslogJson = @"
{
  "location": "$Location",
  "properties": {
    "dataSources": {
      "syslog": [{
        "name": "syslogAuth",
        "streams": ["Microsoft-Syslog"],
        "facilityNames": ["auth", "authpriv"],
        "logLevels": ["Debug","Info","Notice","Warning","Error","Critical","Alert","Emergency"]
      }]
    },
    "destinations": {
      "logAnalytics": [{
        "workspaceResourceId": "$LAW_RES_ID",
        "name": "lawDest"
      }]
    },
    "dataFlows": [{
      "streams": ["Microsoft-Syslog"],
      "destinations": ["lawDest"]
    }]
  }
}
"@
$dcrSyslogFile = Join-Path $PSScriptRoot "dcr-syslog.json"
$dcrSyslogJson | Out-File $dcrSyslogFile -Encoding utf8

az monitor data-collection rule create `
    -g $ResourceGroup -n $DCR_SYSLOG --location $Location `
    --rule-file $dcrSyslogFile --output none

$VM_RES_ID = az vm show -g $ResourceGroup -n $VM --query id -o tsv
$DCR_SYSLOG_ID = az monitor data-collection rule show -g $ResourceGroup -n $DCR_SYSLOG --query id -o tsv

az monitor data-collection rule association create `
    --name "${DCR_SYSLOG}-assoc" --resource $VM_RES_ID `
    --rule-id $DCR_SYSLOG_ID --output none
Write-OK "DCR: Syslog (auth/authpriv)"

# 7b. Audit.log DCR (custom text log)
$DCR_AUDIT = "$PREFIX-dcr-audit"
$CUSTOM_TABLE = "AuditLog_CL"

az monitor log-analytics workspace table create `
    -g $ResourceGroup --workspace-name $LA_WORKSPACE `
    --name $CUSTOM_TABLE --retention-time 30 --total-retention-time 30 `
    --output none 2>$null

$dcrAuditJson = @"
{
  "location": "$Location",
  "properties": {
    "dataSources": {
      "logFiles": [{
        "name": "auditLogFile",
        "streams": ["Custom-${CUSTOM_TABLE}"],
        "filePatterns": ["/var/log/audit/audit.log"],
        "format": "text",
        "settings": { "text": { "recordStartTimestampFormat": "ISO 8601" } }
      }]
    },
    "destinations": {
      "logAnalytics": [{
        "workspaceResourceId": "$LAW_RES_ID",
        "name": "lawDest"
      }]
    },
    "dataFlows": [{
      "streams": ["Custom-${CUSTOM_TABLE}"],
      "destinations": ["lawDest"],
      "outputStream": "Custom-${CUSTOM_TABLE}"
    }]
  }
}
"@
$dcrAuditFile = Join-Path $PSScriptRoot "dcr-audit.json"
$dcrAuditJson | Out-File $dcrAuditFile -Encoding utf8

az monitor data-collection rule create `
    -g $ResourceGroup -n $DCR_AUDIT --location $Location `
    --rule-file $dcrAuditFile --output none 2>$null

$DCR_AUDIT_ID = az monitor data-collection rule show -g $ResourceGroup -n $DCR_AUDIT --query id -o tsv 2>$null
if ($DCR_AUDIT_ID) {
    az monitor data-collection rule association create `
        --name "${DCR_AUDIT}-assoc" --resource $VM_RES_ID `
        --rule-id $DCR_AUDIT_ID --output none
    Write-OK "DCR: audit.log → AuditLog_CL"
} else {
    Write-Warn "DCR for audit.log skipped (may need portal config for custom text logs)"
}

# ── 8. Microsoft Sentinel ────────────────────────────────────────────────────
Write-Step "Enabling Sentinel"
az sentinel onboarding-state create `
    -g $ResourceGroup --workspace-name $LA_WORKSPACE `
    --name "default" --output none 2>$null
Write-OK "Sentinel enabled"

# ── 9. Function App (B1 App Service Plan — no Azure Files / shared keys needed) ──
Write-Step "Creating Function App: $FUNC_APP"
az storage account create `
    -g $ResourceGroup -n $STORAGE_ACCT --location $Location `
    --sku Standard_LRS --output none

$STORAGE_RES_ID = az storage account show -g $ResourceGroup -n $STORAGE_ACCT --query id -o tsv

# Create a B1 Linux App Service Plan (avoids WEBSITE_CONTENTAZUREFILECONNECTIONSTRING requirement)
$ASP_NAME = "$PREFIX-asp"
az appservice plan create `
    -g $ResourceGroup -n $ASP_NAME --location $Location `
    --sku B1 --is-linux --output none

az functionapp create `
    -g $ResourceGroup -n $FUNC_APP `
    --storage-account $STORAGE_ACCT `
    --plan $ASP_NAME `
    --runtime python --runtime-version 3.11 `
    --functions-version 4 --os-type Linux `
    --output none

az functionapp config appsettings set `
    -g $ResourceGroup -n $FUNC_APP `
    --settings `
        "AzureWebJobsStorage__accountName=$STORAGE_ACCT" `
        "NSG_NAME=$NSG" `
        "RESOURCE_GROUP=$ResourceGroup" `
        "SUBSCRIPTION_ID=$SubscriptionId" `
        "DEFENDER_VM_IP=$DEFENDER_IP" `
        "DEFENDER_VM_USER=$AdminUsername" `
        "LAW_WORKSPACE_ID=$LAW_ID" `
        "LAW_RESOURCE_ID=$LAW_RES_ID" `
    --output none
Write-OK "Function App created on B1 plan"

# Managed Identity + roles
az functionapp identity assign -g $ResourceGroup -n $FUNC_APP --output none

$FUNC_PRINCIPAL = az functionapp identity show `
    -g $ResourceGroup -n $FUNC_APP --query principalId -o tsv

$NSG_RES_ID = az network nsg show -g $ResourceGroup -n $NSG --query id -o tsv

Start-Sleep -Seconds 15

# Storage roles for identity-based AzureWebJobsStorage
az role assignment create `
    --assignee $FUNC_PRINCIPAL --role "Storage Blob Data Owner" `
    --scope $STORAGE_RES_ID --output none
az role assignment create `
    --assignee $FUNC_PRINCIPAL --role "Storage Account Contributor" `
    --scope $STORAGE_RES_ID --output none

# LAW role
az role assignment create `
    --assignee $FUNC_PRINCIPAL --role "Log Analytics Reader" `
    --scope $LAW_RES_ID --output none
Write-OK "Managed Identity + RBAC roles assigned"

# ── 10. Fail2ban + auditd on VM ─────────────────────────────────────────────
Write-Step "Installing Fail2ban + auditd on Defender VM"

$fail2banScript = @'
#!/bin/bash
set -e
sudo apt-get update -y
sudo apt-get install -y fail2ban auditd jq curl

# auditd rules for SSH
sudo tee /etc/audit/rules.d/ssh.rules > /dev/null << 'AUDITEOF'
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /var/log/auth.log -p r -k auth_log_read
AUDITEOF
sudo systemctl enable auditd && sudo systemctl restart auditd

# Fail2ban jail
sudo tee /etc/fail2ban/jail.local > /dev/null << 'JAILEOF'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 3
backend  = systemd

[sshd]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 3600
action   = iptables-multiport[name=sshd, port="ssh", protocol=tcp]
JAILEOF

sudo systemctl enable fail2ban && sudo systemctl restart fail2ban
echo "Fail2ban + auditd configured"
'@

$f2bFile = Join-Path $PSScriptRoot "setup-fail2ban.sh"
$fail2banScript | Out-File $f2bFile -Encoding utf8 -NoNewline
(Get-Content $f2bFile -Raw) -replace "`r`n", "`n" | Set-Content $f2bFile -NoNewline

az vm run-command invoke `
    -g $ResourceGroup -n $VM --command-id RunShellScript `
    --scripts @$f2bFile --output none
Write-OK "Fail2ban + auditd configured"

# ── 11. Summary ──────────────────────────────────────────────────────────────
Write-Step "DEPLOYMENT COMPLETE"
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║          Brute-Force Defense Demo — Ready                  ║" -ForegroundColor Green
Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Green
Write-Host "║ Resource Group : $ResourceGroup" -ForegroundColor White
Write-Host "║ Defender VM    : $VM ($DEFENDER_IP) [B2s]" -ForegroundColor White
Write-Host "║ Function App   : $FUNC_APP (B1 plan, 2 functions)" -ForegroundColor White
Write-Host "║ Log Analytics  : $LA_WORKSPACE" -ForegroundColor White
Write-Host "║ Sentinel       : Enabled" -ForegroundColor White
Write-Host "║ Admin User     : $AdminUsername" -ForegroundColor White
Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Green
Write-Host "║ NEXT:                                                      ║" -ForegroundColor Yellow
Write-Host "║   1. .\post-deploy-config.ps1 (deploy code + webhook)     ║" -ForegroundColor White
Write-Host "║   2. Configure alerts manually (see alerts-guide.md)      ║" -ForegroundColor White
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green

$deployInfo = @{
    ResourceGroup    = $ResourceGroup
    Location         = $Location
    DefenderVM       = $VM
    DefenderIP       = $DEFENDER_IP
    FunctionApp      = $FUNC_APP
    StorageAccount   = $STORAGE_ACCT
    LAWorkspace      = $LA_WORKSPACE
    LAWorkspaceId    = $LAW_ID
    LAWorkspaceResId = $LAW_RES_ID
    NSG              = $NSG
    AdminUsername     = $AdminUsername
}
$deployInfo | ConvertTo-Json | Out-File (Join-Path $PSScriptRoot "deploy-info.json") -Encoding utf8
Write-OK "Deployment info saved to deploy-info.json"
