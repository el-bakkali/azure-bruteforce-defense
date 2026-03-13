# Log Alerts & Sentinel Rules — Manual Setup Guide

> Configure these after running `deploy-infrastructure.ps1` and `post-deploy-config.ps1`.

## Prerequisites

- Resource Group: `rg-bruteforce-defense`
- Log Analytics Workspace: `<your-law-name>`
- Microsoft Sentinel: already enabled on the workspace

---

## 1. Create an Action Group

**Portal:** Monitor → Alerts → Action groups → Create

| Field | Value |
|-------|-------|
| Resource group | `rg-bruteforce-defense` |
| Action group name | `bfdef-action-group` |
| Short name | `BFDefAlert` |
| Notification type | Email/SMS/Push/Voice |
| Email | your email address |

---

## 2. Log Alert Rule: SSH Brute-Force (5+ failures)

**Portal:** Monitor → Alerts → Alert rules → Create → Custom log search

| Field | Value |
|-------|-------|
| Scope | `<your-law-name>` (Log Analytics workspace) |
| Condition | Custom log search |
| Severity | 1 - Error |
| Evaluation frequency | 5 minutes |
| Window size | 10 minutes |
| Action group | `bfdef-action-group` |
| Alert rule name | `bfdef-alert-ssh-bruteforce` |
| Display name | `SSH Brute-Force (5+ failures)` |

**KQL Query:**
```kql
Syslog
| where Facility in ("auth", "authpriv")
| where SyslogMessage has "Failed password"
| extend AttackerIP = extract(@"from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", 1, SyslogMessage)
| where isnotempty(AttackerIP)
| summarize FailedAttempts = count() by AttackerIP, HostName, bin(TimeGenerated, 10m)
| where FailedAttempts >= 5
```

**Trigger:** Count > 0

---

## 3. Log Alert Rule: Fail2ban IP Banned

**Portal:** Monitor → Alerts → Alert rules → Create → Custom log search

| Field | Value |
|-------|-------|
| Scope | `<your-law-name>` |
| Condition | Custom log search |
| Severity | 2 - Warning |
| Evaluation frequency | 5 minutes |
| Window size | 10 minutes |
| Action group | `bfdef-action-group` |
| Alert rule name | `bfdef-alert-fail2ban-ban` |
| Display name | `Fail2ban IP Banned` |

**KQL Query:**
```kql
Syslog
| where SyslogMessage has "fail2ban" and SyslogMessage has "Ban"
| extend BannedIP = extract(@"Ban (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", 1, SyslogMessage)
| where isnotempty(BannedIP)
| project TimeGenerated, HostName, BannedIP, SyslogMessage
```

**Trigger:** Count > 0

---

## 4. Sentinel Analytics Rules

**Portal:** Microsoft Sentinel → Analytics → Create → Scheduled query rule

### Rule A: SSH Brute-Force Detection

| Field | Value |
|-------|-------|
| Name | `SSH Brute-Force Attack Detected` |
| Severity | High |
| MITRE ATT&CK | Credential Access (T1110) |
| Run query every | 5 minutes |
| Lookup data from | 15 minutes |
| Trigger alert when | > 0 results |
| Suppression | 1 hour |
| Create incidents | Yes |
| Group by | IP entity |

**KQL Query:**
```kql
Syslog
| where Facility == "auth" or Facility == "authpriv"
| where SyslogMessage has "Failed password" or SyslogMessage has "authentication failure"
| extend AttackerIP = extract(@"from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", 1, SyslogMessage)
| where isnotempty(AttackerIP)
| summarize FailedAttempts = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by AttackerIP, HostName
| where FailedAttempts >= 5
| extend Duration = LastSeen - FirstSeen
```

**Entity mapping:**
- IP → `AttackerIP`
- Host → `HostName`

---

### Rule B: Anomalous Off-Hours SSH Login

| Field | Value |
|-------|-------|
| Name | `Anomalous Off-Hours SSH Login Attempt` |
| Severity | Medium |
| MITRE ATT&CK | Initial Access (T1078) |
| Run query every | 1 hour |
| Lookup data from | 6 hours |
| Suppression | 6 hours |

**KQL Query:**
```kql
Syslog
| where Facility == "auth" or Facility == "authpriv"
| where SyslogMessage has "Failed password" or SyslogMessage has "Accepted password"
| extend HourOfDay = datetime_part('hour', TimeGenerated)
| where HourOfDay >= 0 and HourOfDay < 5
| extend SourceIP = extract(@"from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", 1, SyslogMessage)
| where isnotempty(SourceIP)
| summarize Attempts = count() by SourceIP, HostName, bin(TimeGenerated, 1h)
```

**Entity mapping:**
- IP → `SourceIP`

---

### Rule C: Fail2ban Ban Event

| Field | Value |
|-------|-------|
| Name | `Fail2ban IP Ban Detected` |
| Severity | Informational |
| MITRE ATT&CK | Impact |
| Run query every | 5 minutes |
| Lookup data from | 10 minutes |

**KQL Query:**
```kql
Syslog
| where ProcessName == "fail2ban-server" or SyslogMessage has "fail2ban"
| where SyslogMessage has "Ban"
| extend BannedIP = extract(@"Ban (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", 1, SyslogMessage)
| where isnotempty(BannedIP)
| project TimeGenerated, HostName, BannedIP, SyslogMessage
```

**Entity mapping:**
- IP → `BannedIP`

---

## 5. Hunting Query: NullClaw / Zig Detection (MDE)

> This is for Microsoft Defender for Endpoint Advanced Hunting, not Sentinel Syslog.

```kql
let Lookback = 30d;
let InstallCmd = "https://github.com/nullclaw/nullclaw.git";
let ZigEP =
DeviceProcessEvents
| where Timestamp > ago(Lookback)
| where InitiatingProcessCommandLine == "zig build-exe"
| distinct DeviceName;
DeviceProcessEvents
| where Timestamp > ago(1h)
| where InitiatingProcessCommandLine has InstallCmd or ProcessCommandLine has InstallCmd
| where DeviceName has_any(ZigEP)
```
