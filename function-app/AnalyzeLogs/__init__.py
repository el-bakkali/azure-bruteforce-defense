"""
AnalyzeLogs — Queries the full Syslog table from Log Analytics live
and lets Azure OpenAI analyze it via natural language.

POST → { "question": "who's attacking me?", "hours": 6 }
POST → { "query": "custom KQL" }  (advanced escape hatch)
GET  → default AI security summary
"""

import json
import logging
import os
import datetime
import traceback
import urllib.request
import urllib.error
import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus

# Single credential instance — reused across KQL and OpenAI calls
_credential = DefaultAzureCredential()

FULL_SYSLOG_KQL = """
Syslog
| where TimeGenerated > ago({hours}h)
| project TimeGenerated, HostName, Facility, SeverityLevel, SyslogMessage
| order by TimeGenerated desc
| take 500
"""


def run_kql(workspace_id: str, query: str, hours: int) -> list:
    """Execute a KQL query against Log Analytics."""
    client = LogsQueryClient(_credential)

    query = query.replace("{hours}", str(hours))
    end_time = datetime.datetime.now(datetime.timezone.utc)
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


def analyze_with_openai(rows: list, hours: int, question: str) -> dict:
    """Send Syslog rows to Azure OpenAI for analysis."""
    log_text = "\n".join(
        f"[{r.get('TimeGenerated')}] {r.get('HostName')} "
        f"{r.get('Facility')}/{r.get('SeverityLevel')}: "
        f"{r.get('SyslogMessage', '')[:300]}"
        for r in rows
    )

    token = _credential.get_token("https://cognitiveservices.azure.com/.default")

    aoai_endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT", "")
    deployment = os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4o-mini")

    if not aoai_endpoint:
        return {
            "question": question,
            "hours": hours,
            "rows_analyzed": len(rows),
            "analysis": "Error: AZURE_OPENAI_ENDPOINT not configured.",
        }

    payload = json.dumps({
        "messages": [
            {"role": "system", "content": (
                "You are a Linux security analyst. You have access to the raw Syslog "
                "data below from an Azure-monitored VM. Analyze it and answer the "
                "user's question. Be specific about IPs, timestamps, usernames, "
                "facilities, and patterns. If you see threats, rate severity "
                "(CRITICAL/HIGH/MEDIUM/LOW/NONE). Mention Fail2ban bans, brute-force "
                "attempts, successful logins, and anything suspicious. Use bullet "
                "points and be concise."
            )},
            {"role": "user", "content": f"Question: {question}\n\nSyslog ({len(rows)} rows, last {hours}h):\n{log_text}"},
        ],
        "max_tokens": 2000,
        "temperature": 0.2,
    }).encode("utf-8")

    url = f"{aoai_endpoint}openai/deployments/{deployment}/chat/completions?api-version=2024-02-15-preview"
    req = urllib.request.Request(url, data=payload, headers={
        "Authorization": f"Bearer {token.token}",
        "Content-Type": "application/json",
    }, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            result = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        logging.error(f"Azure OpenAI error {e.code}: {error_body}")
        return {
            "question": question,
            "hours": hours,
            "rows_analyzed": len(rows),
            "analysis": f"Azure OpenAI returned HTTP {e.code}. Check deployment and endpoint config.",
        }

    return {
        "question": question,
        "hours": hours,
        "rows_analyzed": len(rows),
        "analysis": result["choices"][0]["message"]["content"],
    }


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

    # Custom KQL escape hatch for advanced users
    custom_query = body.get("query", "")
    if custom_query:
        results = run_kql(workspace_id, custom_query, hours)
        return func.HttpResponse(
            json.dumps({"query": custom_query, "results": results}, default=str),
            status_code=200, mimetype="application/json",
        )

    # AI-powered analysis — live KQL query + OpenAI
    question = body.get("question", "")
    if not question:
        question = "Give me a full security summary of what's happening in my logs."

    rows = run_kql(workspace_id, FULL_SYSLOG_KQL, hours)

    # Don't waste an OpenAI call if KQL returned an error
    if rows and "error" in rows[0]:
        return func.HttpResponse(
            json.dumps({"error": "KQL query failed", "details": rows[0]["error"]}, default=str),
            status_code=502, mimetype="application/json",
        )

    result = analyze_with_openai(rows, hours, question)
    return func.HttpResponse(
        json.dumps(result, default=str),
        status_code=200, mimetype="application/json",
    )
