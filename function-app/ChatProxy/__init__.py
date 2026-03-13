"""
ChatProxy — Proxies chat completions to Azure OpenAI using managed identity.
NullClaw calls this as an OpenAI-compatible endpoint.
No API keys needed — uses DefaultAzureCredential for Azure AD auth.
"""

import json
import logging
import os
import traceback
import azure.functions as func
from azure.identity import DefaultAzureCredential
import urllib.request


def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("ChatProxy — /v1/chat/completions")

    try:
        return _handle(req)
    except Exception as e:
        logging.error(f"ChatProxy crashed: {traceback.format_exc()}")
        return func.HttpResponse(
            json.dumps({"error": {"message": str(e), "trace": traceback.format_exc()}}),
            status_code=500, mimetype="application/json",
        )


def _handle(req: func.HttpRequest) -> func.HttpResponse:
    aoai_endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT", "")
    deployment = os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4o-mini")

    if not aoai_endpoint:
        return func.HttpResponse(
            json.dumps({"error": {"message": "AZURE_OPENAI_ENDPOINT not configured"}}),
            status_code=500, mimetype="application/json",
        )

    try:
        body = req.get_body()
    except Exception:
        return func.HttpResponse(
            json.dumps({"error": {"message": "Invalid request body"}}),
            status_code=400, mimetype="application/json",
        )

    # Get Azure AD token for Cognitive Services
    credential = DefaultAzureCredential()
    token = credential.get_token("https://cognitiveservices.azure.com/.default")

    # Forward to Azure OpenAI
    url = f"{aoai_endpoint}openai/deployments/{deployment}/chat/completions?api-version=2024-02-15-preview"

    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": f"Bearer {token.token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=120) as resp:
            result = resp.read()
            return func.HttpResponse(result, status_code=200, mimetype="application/json")
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        logging.error(f"Azure OpenAI error {e.code}: {error_body}")
        return func.HttpResponse(error_body, status_code=e.code, mimetype="application/json")
