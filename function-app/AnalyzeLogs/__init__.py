"""
AnalyzeLogs — Queries Log Analytics for SSH attack data and returns
a structured analysis report. Includes NullClaw hunting capabilities.

GET  → returns last 1h of SSH attack summary
POST → { "hours": 6, "query": "custom KQL" }
POST → { "hunt": "nullclaw" } — runs NullClaw/Zig detection queries
"""

import json
import logging
import os
import datetime
import traceback
import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus


ATTACK_SUMMARY_KQL = """
Syslog
| where TimeGenerated > ago({hours}h)
| where Facility in ("auth", "authpriv")
| where SyslogMessage has "Failed password" or SyslogMessage has "Accepted password" or SyslogMessage has "fail2ban"
| extend EventType = case(
    SyslogMessage has "Failed password", "FailedLogin",
    SyslogMessage has "Accepted password", "SuccessfulLogin",
    SyslogMessage has "Ban", "Fail2banBan",
    SyslogMessage has "Unban", "Fail2banUnban",
    "Other"
  )
| extend SourceIP = extract(@"from ([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)", 1, SyslogMessage)
| extend TargetUser = extract(@"for (\\S+)", 1, SyslogMessage)
| summarize
    TotalEvents = count(),
    FailedLogins = countif(EventType == "FailedLogin"),
    SuccessfulLogins = countif(EventType == "SuccessfulLogin"),
    BannedIPs = dcountif(SourceIP, EventType == "Fail2banBan"),
    UniqueAttackerIPs = dcount(SourceIP),
    TargetedUsers = make_set(TargetUser, 20),
    AttackerIPs = make_set(SourceIP, 50),
    FirstEvent = min(TimeGenerated),
    LastEvent = max(TimeGenerated)
  by bin(TimeGenerated, 10m)
| order by TimeGenerated desc
"""

TOP_ATTACKERS_KQL = """
Syslog
| where TimeGenerated > ago({hours}h)
| where Facility in ("auth", "authpriv")
| where SyslogMessage has "Failed password"
| extend SourceIP = extract(@"from ([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)", 1, SyslogMessage)
| extend TargetUser = extract(@"for (\\S+)", 1, SyslogMessage)
| where isnotempty(SourceIP)
| summarize
    Attempts = count(),
    TargetedUsers = make_set(TargetUser, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
  by SourceIP
| extend AttackDuration = LastSeen - FirstSeen
| order by Attempts desc
| take 20
"""

# ── NullClaw Hunting Queries ─────────────────────────────────────────────────
# NullClaw is a Zig-built AI assistant (678KB binary, ~1MB RAM, <2ms boot).
# These queries detect NullClaw installation/build/execution via Syslog + auditd.

NULLCLAW_INSTALL_KQL = """
// Detect NullClaw git clone or download attempts via Syslog/auditd
Syslog
| where TimeGenerated > ago({hours}h)
| where SyslogMessage has_any ("nullclaw", "nullclaw.git", "github.com/nullclaw")
| project TimeGenerated, HostName, Facility, SyslogMessage
| order by TimeGenerated desc
"""

NULLCLAW_ZIG_BUILD_KQL = """
// Detect Zig compiler usage (NullClaw is built with Zig)
Syslog
| where TimeGenerated > ago({hours}h)
| where SyslogMessage has_any ("zig build-exe", "zig build", "zig cc", "zig-linux")
| project TimeGenerated, HostName, Facility, SyslogMessage
| order by TimeGenerated desc
"""

NULLCLAW_RAPID_SSH_KQL = """
// Detect NullClaw-style rapid SSH brute-force (Zig speed = sub-second bursts)
Syslog
| where TimeGenerated > ago({hours}h)
| where Facility in ("auth", "authpriv")
| where SyslogMessage has "Failed password"
| extend SourceIP = extract(@"from ([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)", 1, SyslogMessage)
| where isnotempty(SourceIP)
| summarize
    Attempts = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
  by SourceIP, bin(TimeGenerated, 1m)
| where Attempts >= 10
| extend AttacksPerSecond = round(Attempts / max_of(datetime_diff('second', LastSeen, FirstSeen), 1.0), 2)
| order by AttacksPerSecond desc
| take 20
"""

NULLCLAW_SUSPICIOUS_BINARY_KQL = """
// Detect small unknown binaries typical of Zig builds (no runtime, tiny footprint)
Syslog
| where TimeGenerated > ago({hours}h)
| where SyslogMessage has_any ("execve", "PROCTITLE", "SYSCALL")
| where SyslogMessage has_any ("nullclaw", "zig-out", "zig-cache", ".zig")
| project TimeGenerated, HostName, SyslogMessage
| order by TimeGenerated desc
"""


def run_kql(workspace_id: str, query: str, hours: int) -> list:
    """Execute a KQL query against Log Analytics."""
    credential = DefaultAzureCredential()
    client = LogsQueryClient(credential)

    query = query.replace("{hours}", str(hours))
    end_time = datetime.datetime.utcnow()
    start_time = end_time - datetime.timedelta(hours=hours)

    response = client.query_workspace(
        workspace_id=workspace_id,
        query=query,
        timespan=(start_time, end_time),
    )

    if response.status == LogsQueryStatus.SUCCESS:
        rows = []
        for table in response.tables:
            columns = [col if isinstance(col, str) else col.name for col in table.columns]
            for row in table.rows:
                rows.append(dict(zip(columns, [str(v) for v in row])))
        return rows
    else:
        logging.error(f"KQL query failed: {response.partial_error}")
        return [{"error": str(response.partial_error)}]


def build_report(summary_data: list, attacker_data: list, hours: int) -> dict:
    """Build a structured attack analysis report."""
    total_failed = 0
    total_success = 0
    total_banned = 0
    unique_ips = set()

    for row in summary_data:
        total_failed += int(row.get("FailedLogins", 0))
        total_success += int(row.get("SuccessfulLogins", 0))
        total_banned += int(row.get("BannedIPs", 0))
        ips = row.get("AttackerIPs", "[]")
        if isinstance(ips, str):
            try:
                for ip in json.loads(ips):
                    unique_ips.add(ip)
            except (json.JSONDecodeError, TypeError):
                pass

    # Determine severity
    if total_failed > 100 or total_success > 0:
        severity = "CRITICAL" if total_success > 0 else "HIGH"
    elif total_failed > 20:
        severity = "MEDIUM"
    elif total_failed > 0:
        severity = "LOW"
    else:
        severity = "NONE"

    return {
        "report_time": datetime.datetime.utcnow().isoformat() + "Z",
        "analysis_window_hours": hours,
        "severity": severity,
        "summary": {
            "total_failed_logins": total_failed,
            "total_successful_logins": total_success,
            "ips_banned_by_fail2ban": total_banned,
            "unique_attacker_ips": len(unique_ips),
        },
        "top_attackers": attacker_data[:10],
        "recommendations": _get_recommendations(severity, total_failed, total_success, total_banned),
    }


def _get_recommendations(severity: str, failed: int, success: int, banned: int) -> list:
    """Generate actionable recommendations based on attack data."""
    recs = []
    if severity == "NONE":
        recs.append("No SSH attack activity detected in the analysis window.")
        return recs
    if success > 0:
        recs.append("URGENT: Successful SSH login detected — verify if authorized.")
        recs.append("Rotate credentials on the compromised account immediately.")
        recs.append("Check for persistence mechanisms (crontab, authorized_keys, systemd services).")
    if failed > 50:
        recs.append("High-volume brute-force detected — consider geo-IP blocking in NSG.")
        recs.append("Review Fail2ban findtime/maxretry — tighten to maxretry=2 if needed.")
    if failed > 0 and banned == 0:
        recs.append("Failed logins detected but no Fail2ban bans — verify Fail2ban is running.")
    if banned > 0:
        recs.append(f"Fail2ban auto-banned {banned} IPs — review NSG deny rules.")
    recs.append("Consider disabling SSH password auth and using key-based auth only.")
    return recs


def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("AnalyzeLogs triggered")

    try:
        return _handle(req)
    except Exception as e:
        logging.error(f"AnalyzeLogs crashed: {traceback.format_exc()}")
        return func.HttpResponse(
            json.dumps({"error": str(e), "trace": traceback.format_exc()}),
            status_code=500, mimetype="application/json",
        )


def _handle(req: func.HttpRequest) -> func.HttpResponse:
    workspace_id = os.environ.get("LAW_WORKSPACE_ID", "")
    if not workspace_id:
        return func.HttpResponse(
            json.dumps({"error": "LAW_WORKSPACE_ID not configured"}),
            status_code=500, mimetype="application/json",
        )

    try:
        body = req.get_json()
    except ValueError:
        body = {}

    hours = min(int(body.get("hours", 1)), 168)  # cap at 7 days
    hunt = body.get("hunt", "")
    custom_query = body.get("query", "")

    # NullClaw hunting mode
    if hunt == "nullclaw":
        report = hunt_nullclaw(workspace_id, hours)
        return func.HttpResponse(
            json.dumps(report, default=str),
            status_code=200, mimetype="application/json",
        )

    # If a custom KQL query is provided, run it directly
    if custom_query:
        results = run_kql(workspace_id, custom_query, hours)
        return func.HttpResponse(
            json.dumps({"query": custom_query, "results": results}, default=str),
            status_code=200, mimetype="application/json",
        )

    # Otherwise, run the standard attack analysis
    summary_data = run_kql(workspace_id, ATTACK_SUMMARY_KQL, hours)
    attacker_data = run_kql(workspace_id, TOP_ATTACKERS_KQL, hours)
    report = build_report(summary_data, attacker_data, hours)

    return func.HttpResponse(
        json.dumps(report, default=str),
        status_code=200, mimetype="application/json",
    )


def hunt_nullclaw(workspace_id: str, hours: int) -> dict:
    """Run NullClaw/Zig hunting queries and return a structured threat report."""
    logging.info(f"Hunting NullClaw — lookback {hours}h")

    install_hits = run_kql(workspace_id, NULLCLAW_INSTALL_KQL, hours)
    zig_hits = run_kql(workspace_id, NULLCLAW_ZIG_BUILD_KQL, hours)
    rapid_ssh = run_kql(workspace_id, NULLCLAW_RAPID_SSH_KQL, hours)
    binary_hits = run_kql(workspace_id, NULLCLAW_SUSPICIOUS_BINARY_KQL, hours)

    # Determine threat level
    indicators_found = sum([
        len(install_hits) > 0,
        len(zig_hits) > 0,
        len(rapid_ssh) > 0,
        len(binary_hits) > 0,
    ])

    if indicators_found >= 3:
        threat_level = "CRITICAL"
    elif indicators_found == 2:
        threat_level = "HIGH"
    elif indicators_found == 1:
        threat_level = "MEDIUM"
    else:
        threat_level = "NONE"

    return {
        "hunt": "NullClaw",
        "description": "NullClaw is a Zig-built AI assistant (678KB, ~1MB RAM, <2ms boot). "
                       "These queries detect installation, compilation, and attack patterns.",
        "report_time": datetime.datetime.utcnow().isoformat() + "Z",
        "analysis_window_hours": hours,
        "threat_level": threat_level,
        "indicators_found": indicators_found,
        "findings": {
            "nullclaw_install_attempts": {
                "description": "Git clone or download of nullclaw repository",
                "hits": len(install_hits),
                "events": install_hits[:10],
            },
            "zig_compiler_usage": {
                "description": "Zig build-exe / build commands detected (NullClaw build chain)",
                "hits": len(zig_hits),
                "events": zig_hits[:10],
            },
            "rapid_ssh_bruteforce": {
                "description": "High-speed SSH brute-force (10+ attempts/min — Zig speed signature)",
                "hits": len(rapid_ssh),
                "events": rapid_ssh[:10],
            },
            "suspicious_zig_binaries": {
                "description": "Execution of Zig-compiled binaries (zig-out, zig-cache, .zig)",
                "hits": len(binary_hits),
                "events": binary_hits[:10],
            },
        },
        "recommendations": _nullclaw_recommendations(threat_level, indicators_found, install_hits, rapid_ssh),
    }


def _nullclaw_recommendations(threat_level, indicators, install_hits, rapid_ssh):
    recs = []
    if threat_level == "NONE":
        recs.append("No NullClaw indicators detected in the analysis window.")
        return recs
    if install_hits:
        recs.append("ALERT: NullClaw installation attempt detected — investigate the source host.")
        recs.append("Block outbound access to github.com/nullclaw if not authorized.")
    if rapid_ssh:
        recs.append("High-speed SSH brute-force detected — consistent with Zig-compiled attack tools.")
        recs.append("Tighten Fail2ban: maxretry=2, findtime=60 for faster response.")
    if indicators >= 2:
        recs.append("Multiple NullClaw indicators — likely active compromise. Isolate affected hosts.")
    recs.append("Add auditd rule: -a always,exit -F arch=b64 -S execve -k cmd_exec for deeper visibility.")
    recs.append("Consider deploying MDE for DeviceProcessEvents-level detection (advanced hunting).")
    return recs
