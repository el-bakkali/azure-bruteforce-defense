###############################################################################
# deploy-sentinel-rules.ps1
# Creates Sentinel analytics rules for SSH brute-force detection
###############################################################################

param(
    [string]$ResourceGroup = "rg-bruteforce-defense"
)

$deployInfo = Get-Content (Join-Path $PSScriptRoot "deploy-info.json") | ConvertFrom-Json
$LA_WORKSPACE = $deployInfo.LAWorkspace

Write-Host "▶ Creating Sentinel Analytics Rules..." -ForegroundColor Cyan

# ── Rule 1: SSH Brute-Force Detection ────────────────────────────────────────
$rule1 = @"
{
  "kind": "Scheduled",
  "properties": {
    "displayName": "SSH Brute-Force Attack Detected",
    "description": "Detects multiple failed SSH login attempts from a single IP address within a short time window, indicating a potential brute-force attack.",
    "severity": "High",
    "enabled": true,
    "query": "Syslog\n| where Facility == \"auth\" or Facility == \"authpriv\"\n| where SyslogMessage has \"Failed password\" or SyslogMessage has \"authentication failure\"\n| extend AttackerIP = extract(@\"from (\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\", 1, SyslogMessage)\n| where isnotempty(AttackerIP)\n| summarize FailedAttempts = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by AttackerIP, HostName\n| where FailedAttempts >= 5\n| extend Duration = LastSeen - FirstSeen\n| project AttackerIP, HostName, FailedAttempts, FirstSeen, LastSeen, Duration",
    "queryFrequency": "PT5M",
    "queryPeriod": "PT15M",
    "triggerOperator": "GreaterThan",
    "triggerThreshold": 0,
    "suppressionDuration": "PT1H",
    "suppressionEnabled": true,
    "tactics": ["CredentialAccess", "InitialAccess"],
    "techniques": ["T1110"],
    "incidentConfiguration": {
      "createIncident": true,
      "groupingConfiguration": {
        "enabled": true,
        "reopenClosedIncident": false,
        "lookbackDuration": "PT1H",
        "matchingMethod": "AllEntities",
        "groupByEntities": ["IP"]
      }
    },
    "entityMappings": [
      {
        "entityType": "IP",
        "fieldMappings": [
          {
            "identifier": "Address",
            "columnName": "AttackerIP"
          }
        ]
      },
      {
        "entityType": "Host",
        "fieldMappings": [
          {
            "identifier": "HostName",
            "columnName": "HostName"
          }
        ]
      }
    ]
  }
}
"@

# ── Rule 2: Off-Hours SSH Access ─────────────────────────────────────────────
$rule2 = @"
{
  "kind": "Scheduled",
  "properties": {
    "displayName": "Anomalous Off-Hours SSH Login Attempt",
    "description": "Detects SSH login attempts during unusual hours (midnight to 5 AM UTC), which may indicate an attack from a different timezone.",
    "severity": "Medium",
    "enabled": true,
    "query": "Syslog\n| where Facility == \"auth\" or Facility == \"authpriv\"\n| where SyslogMessage has \"Failed password\" or SyslogMessage has \"Accepted password\"\n| extend HourOfDay = datetime_part('hour', TimeGenerated)\n| where HourOfDay >= 0 and HourOfDay < 5\n| extend SourceIP = extract(@\"from (\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\", 1, SyslogMessage)\n| where isnotempty(SourceIP)\n| summarize Attempts = count() by SourceIP, HostName, bin(TimeGenerated, 1h)",
    "queryFrequency": "PT1H",
    "queryPeriod": "PT6H",
    "triggerOperator": "GreaterThan",
    "triggerThreshold": 0,
    "suppressionDuration": "PT6H",
    "suppressionEnabled": true,
    "tactics": ["InitialAccess"],
    "techniques": ["T1078"],
    "incidentConfiguration": {
      "createIncident": true,
      "groupingConfiguration": {
        "enabled": true,
        "reopenClosedIncident": false,
        "lookbackDuration": "PT6H",
        "matchingMethod": "AllEntities",
        "groupByEntities": ["IP"]
      }
    },
    "entityMappings": [
      {
        "entityType": "IP",
        "fieldMappings": [
          {
            "identifier": "Address",
            "columnName": "SourceIP"
          }
        ]
      }
    ]
  }
}
"@

# ── Rule 3: Fail2ban Ban Event ───────────────────────────────────────────────
$rule3 = @"
{
  "kind": "Scheduled",
  "properties": {
    "displayName": "Fail2ban IP Ban Detected",
    "description": "Detects when Fail2ban has banned an IP address, indicating automated defense response to brute-force attacks.",
    "severity": "Informational",
    "enabled": true,
    "query": "Syslog\n| where ProcessName == \"fail2ban-server\" or SyslogMessage has \"fail2ban\"\n| where SyslogMessage has \"Ban\"\n| extend BannedIP = extract(@\"Ban (\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\", 1, SyslogMessage)\n| where isnotempty(BannedIP)\n| project TimeGenerated, HostName, BannedIP, SyslogMessage",
    "queryFrequency": "PT5M",
    "queryPeriod": "PT10M",
    "triggerOperator": "GreaterThan",
    "triggerThreshold": 0,
    "suppressionDuration": "PT30M",
    "suppressionEnabled": false,
    "tactics": ["Impact"],
    "incidentConfiguration": {
      "createIncident": true,
      "groupingConfiguration": {
        "enabled": true,
        "reopenClosedIncident": false,
        "lookbackDuration": "PT1H",
        "matchingMethod": "AllEntities",
        "groupByEntities": ["IP"]
      }
    },
    "entityMappings": [
      {
        "entityType": "IP",
        "fieldMappings": [
          {
            "identifier": "Address",
            "columnName": "BannedIP"
          }
        ]
      }
    ]
  }
}
"@

# Deploy rules
$rules = @(
    @{ Name = "ssh-bruteforce-detection"; Json = $rule1 },
    @{ Name = "off-hours-ssh-access"; Json = $rule2 },
    @{ Name = "fail2ban-ban-event"; Json = $rule3 }
)

foreach ($rule in $rules) {
    $tempFile = Join-Path $PSScriptRoot "$($rule.Name).json"
    $rule.Json | Out-File $tempFile -Encoding utf8

    Write-Host "  Creating rule: $($rule.Name)..." -ForegroundColor White
    az sentinel alert-rule create `
        --resource-group $ResourceGroup `
        --workspace-name $LA_WORKSPACE `
        --rule-id (New-Guid).ToString() `
        --alert-rule @$tempFile `
        --output none 2>$null

    Remove-Item $tempFile -ErrorAction SilentlyContinue
}

Write-Host "  ✔ Sentinel analytics rules created" -ForegroundColor Green
