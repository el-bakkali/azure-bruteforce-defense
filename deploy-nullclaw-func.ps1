###############################################################################
# deploy-nullclaw-func.ps1
# Deploys NullClaw as an Azure Function App custom handler
# Uses ModelAPI (qwen2.5:0.5b) as the AI provider — no external API keys
###############################################################################

param(
    [string]$ResourceGroup = "rg-bruteforce-defense",
    [string]$Location      = "uksouth"
)

$ErrorActionPreference = "Stop"

function Write-Step { param([string]$msg) Write-Host "`n▶ $msg" -ForegroundColor Cyan }
function Write-OK   { param([string]$msg) Write-Host "  ✔ $msg" -ForegroundColor Green }

$deployInfo = Get-Content (Join-Path $PSScriptRoot "deploy-info.json") | ConvertFrom-Json

$EXISTING_FUNC  = $deployInfo.FunctionApp
$STORAGE_ACCT   = $deployInfo.StorageAccount
$ASP_NAME       = "bfdef-asp"
$NC_FUNC_APP    = "bfdef-nullclaw-$(Get-Random -Maximum 9999)"

# ── 1. Get existing function endpoints ──────────────────────────────────────
Write-Step "Getting existing endpoint URLs"

$FUNC_KEY = $null
for ($i = 1; $i -le 4; $i++) {
    $FUNC_KEY = az functionapp keys list `
        -g $ResourceGroup -n $EXISTING_FUNC `
        --query "functionKeys.default" -o tsv 2>$null
    if ($FUNC_KEY -and $FUNC_KEY -notmatch "Operation returned") { break }
    Start-Sleep 10
    $FUNC_KEY = $null
}
if (-not $FUNC_KEY) {
    Write-Host "  ✗ Could not get function key from $EXISTING_FUNC" -ForegroundColor Red
    return
}

$ANALYZE_URL = "https://${EXISTING_FUNC}.azurewebsites.net/api/AnalyzeLogs?code=${FUNC_KEY}"
$MODEL_URL   = "https://${EXISTING_FUNC}.azurewebsites.net/api"
Write-OK "AnalyzeLogs + ModelAPI endpoints obtained"

# ── 2. Download NullClaw binary ─────────────────────────────────────────────
Write-Step "Downloading NullClaw binary (linux x86_64)"
$ncDir = Join-Path $PSScriptRoot "nullclaw-func"
$ncBinary = Join-Path $ncDir "nullclaw"

$releaseUrl = "https://github.com/nullclaw/nullclaw/releases/latest/download/nullclaw-linux-x86_64"
try {
    Invoke-WebRequest -Uri $releaseUrl -OutFile $ncBinary -UseBasicParsing
    Write-OK "NullClaw binary downloaded ($(((Get-Item $ncBinary).Length / 1KB).ToString('N0')) KB)"
} catch {
    Write-Host "  ⚠ Could not download from releases. Trying alternative..." -ForegroundColor Yellow
    $altUrl = "https://github.com/nullclaw/nullclaw/releases/latest/download/nullclaw"
    try {
        Invoke-WebRequest -Uri $altUrl -OutFile $ncBinary -UseBasicParsing
        Write-OK "NullClaw binary downloaded"
    } catch {
        Write-Host "  ✗ Could not download NullClaw automatically." -ForegroundColor Red
        Write-Host "    Build manually: git clone https://github.com/nullclaw/nullclaw.git" -ForegroundColor Yellow
        Write-Host "    zig build -Doptimize=ReleaseSmall && cp zig-out/bin/nullclaw $ncDir/" -ForegroundColor Yellow
        return
    }
}

# ── 3. Generate NullClaw config (pointing to ModelAPI) ──────────────────────
Write-Step "Generating NullClaw config"

$ncConfig = @"
{
  "models": {
    "providers": {
      "local": {
        "type": "openai",
        "api_base": "$MODEL_URL",
        "api_key": "$FUNC_KEY"
      }
    }
  },
  "agents": {
    "defaults": {
      "model": {
        "primary": "local/qwen2.5-0.5b-instruct"
      }
    }
  },
  "tools": {
    "http_request": { "enabled": true },
    "file_read":    { "enabled": true },
    "file_write":   { "enabled": true }
  },
  "autonomy": {
    "level": "full",
    "workspace_only": true,
    "block_high_risk_commands": true
  },
  "memory": {
    "backend": "sqlite",
    "auto_save": true,
    "hygiene_enabled": true
  },
  "gateway": {
    "port": 3000,
    "require_pairing": false,
    "allow_public_bind": false
  },
  "security": {
    "audit": { "enabled": true, "retention_days": 30 }
  }
}
"@

$ncConfig | Out-File (Join-Path $ncDir "config.json") -Encoding utf8
Write-OK "Config generated (provider: ModelAPI @ $EXISTING_FUNC)"

# ── 4. Create Function App (reuse existing storage + plan) ──────────────────
Write-Step "Creating Function App: $NC_FUNC_APP"

az functionapp create `
    -g $ResourceGroup -n $NC_FUNC_APP `
    --storage-account $STORAGE_ACCT `
    --plan $ASP_NAME `
    --runtime custom --functions-version 4 --os-type Linux `
    --output none

# Identity-based storage (SharedKey disabled by policy)
az functionapp identity assign -g $ResourceGroup -n $NC_FUNC_APP --output none

$NC_PRINCIPAL = az functionapp identity show `
    -g $ResourceGroup -n $NC_FUNC_APP --query principalId -o tsv
$STOR_RES_ID = az storage account show -g $ResourceGroup -n $STORAGE_ACCT --query id -o tsv

Start-Sleep 10
az role assignment create --assignee $NC_PRINCIPAL --role "Storage Blob Data Owner" `
    --scope $STOR_RES_ID --output none
az role assignment create --assignee $NC_PRINCIPAL --role "Storage Account Contributor" `
    --scope $STOR_RES_ID --output none

az functionapp config appsettings set `
    -g $ResourceGroup -n $NC_FUNC_APP `
    --settings `
        "AzureWebJobsStorage__accountName=$STORAGE_ACCT" `
        "ANALYZE_LOGS_URL=$ANALYZE_URL" `
        "MODEL_API_URL=$MODEL_URL" `
    --output none

az functionapp config appsettings delete `
    -g $ResourceGroup -n $NC_FUNC_APP `
    --setting-names AzureWebJobsStorage --output none 2>$null

az functionapp cors add -g $ResourceGroup -n $NC_FUNC_APP `
    --allowed-origins "https://ms.portal.azure.com" "https://portal.azure.com" --output none

Write-OK "Function App created on B1 plan (shared)"

# ── 5. Deploy code ──────────────────────────────────────────────────────────
Write-Step "Deploying NullClaw to Function App"

Push-Location $ncDir

(Get-Content "start.sh" -Raw) -replace "`r`n", "`n" | Set-Content "start.sh" -NoNewline

$zipPath = Join-Path $PSScriptRoot "nullclaw-func.zip"
if (Test-Path $zipPath) { Remove-Item $zipPath }
Compress-Archive -Path * -DestinationPath $zipPath

az functionapp deployment source config-zip `
    -g $ResourceGroup -n $NC_FUNC_APP --src $zipPath `
    --timeout 120 --output none

Pop-Location

az functionapp config set -g $ResourceGroup -n $NC_FUNC_APP `
    --startup-file "chmod +x /home/site/wwwroot/start.sh && chmod +x /home/site/wwwroot/nullclaw && /home/site/wwwroot/start.sh" `
    --output none

Write-OK "NullClaw deployed"

# ── 6. Summary ──────────────────────────────────────────────────────────────
Write-Step "NULLCLAW DEPLOYMENT COMPLETE"

$NC_URL = "https://${NC_FUNC_APP}.azurewebsites.net/api/webhook"
$NC_HEALTH = "https://${NC_FUNC_APP}.azurewebsites.net/api/health"

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║        NullClaw AI Agent — Syslog Hunter                   ║" -ForegroundColor Magenta
Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Magenta
Write-Host "║ Function App : $NC_FUNC_APP" -ForegroundColor White
Write-Host "║ Binary       : NullClaw (Zig, <1 MB)" -ForegroundColor White
Write-Host "║ AI Provider  : ModelAPI (qwen2.5:0.5b, local, free)" -ForegroundColor White
Write-Host "║ Data Source  : AnalyzeLogs → LAW Syslog table" -ForegroundColor White
Write-Host "║ Memory       : SQLite (threat intelligence DB)" -ForegroundColor White
Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Magenta
Write-Host "║ Endpoints:                                                 ║" -ForegroundColor Yellow
Write-Host "║   POST  /api/webhook  — send analysis requests            ║" -ForegroundColor White
Write-Host "║   GET   /api/health   — health check                      ║" -ForegroundColor White
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host ""
Write-Host "  Health check: curl $NC_HEALTH" -ForegroundColor Cyan
Write-Host "  Analyze:      curl -X POST '$NC_URL' \\" -ForegroundColor Cyan
Write-Host "                  -H 'Content-Type: application/json' \\" -ForegroundColor Cyan
Write-Host "                  -d '{`"message`":`"analyze SSH attacks last 6h`"}'" -ForegroundColor Cyan

$ncInfo = @{
    NullClawFuncApp = $NC_FUNC_APP
    NullClawURL     = $NC_URL
    NullClawHealth  = $NC_HEALTH
    ModelProvider   = "ModelAPI (local qwen2.5:0.5b)"
}
$ncInfo | ConvertTo-Json | Out-File (Join-Path $PSScriptRoot "nullclaw-info.json") -Encoding utf8
Write-OK "Deployment info saved to nullclaw-info.json"
Write-OK "NullClaw info saved to nullclaw-info.json"
