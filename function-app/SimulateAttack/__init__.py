"""
SimulateAttack — HTTP-triggered function that runs a brute-force SSH
simulation against the Defender VM using paramiko.  No attacker VM needed.

POST body (all optional — defaults from app settings):
  { "target": "1.2.3.4", "username": "root", "attempts": 15 }
"""

import json
import logging
import os
import time
import azure.functions as func
import paramiko


def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("SimulateAttack triggered")

    try:
        body = req.get_json()
    except ValueError:
        body = {}

    target = body.get("target", os.environ.get("DEFENDER_VM_IP", ""))
    username = body.get("username", "root")
    attempts = min(int(body.get("attempts", 15)), 50)  # cap at 50

    if not target:
        return func.HttpResponse(
            json.dumps({"error": "No target IP. Set DEFENDER_VM_IP or pass 'target' in body."}),
            status_code=400, mimetype="application/json",
        )

    results = []
    for i in range(1, attempts + 1):
        fake_password = f"wrongpass{i}"
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=target,
                username=username,
                password=fake_password,
                timeout=5,
                look_for_keys=False,
                allow_agent=False,
            )
            results.append({"attempt": i, "status": "unexpected_success"})
        except paramiko.AuthenticationException:
            results.append({"attempt": i, "status": "auth_failed"})
        except Exception as e:
            results.append({"attempt": i, "status": "error", "detail": str(e)})
        finally:
            client.close()
        time.sleep(0.3)

    failed = sum(1 for r in results if r["status"] == "auth_failed")
    errors = sum(1 for r in results if r["status"] == "error")

    response = {
        "target": target,
        "username": username,
        "total_attempts": attempts,
        "auth_failures": failed,
        "connection_errors": errors,
        "detail": results,
        "message": f"Brute-force simulation complete. {failed} auth failures should trigger Fail2ban.",
    }

    logging.info(f"SimulateAttack: {failed}/{attempts} auth failures against {target}")
    return func.HttpResponse(
        json.dumps(response), status_code=200, mimetype="application/json"
    )
