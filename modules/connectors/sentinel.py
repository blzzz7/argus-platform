"""Sentinel ingestion with DCR API and legacy workspace compatibility."""
import base64
import hashlib
import hmac
import json
from datetime import datetime, timezone
from urllib.parse import quote
from .base import post


def send(event, settings):
    body = json.dumps([event], ensure_ascii=False).encode("utf-8")
    if settings.get("dcr_id"):
        from msal import ConfidentialClientApplication
        app = ConfidentialClientApplication(settings["client_id"], authority="https://login.microsoftonline.com/" + settings["entra_tenant_id"], client_credential=settings["client_secret"], timeout=20)
        token = app.acquire_token_for_client(scopes=["https://monitor.azure.com/.default"])
        if not token.get("access_token"):
            raise RuntimeError("Sentinel authentication failed.")
        url = settings["endpoint"].rstrip("/") + "/dataCollectionRules/" + quote(settings["dcr_id"], safe="") + "/streams/" + quote(settings["stream"], safe="") + "?api-version=2023-01-01"
        headers = {"Authorization": "Bearer " + token["access_token"], "Content-Type": "application/json"}
    else:
        workspace = settings["workspace_id"]
        # Workspace IDs are UUIDs, never arbitrary hosts.
        from uuid import UUID
        workspace = str(UUID(workspace))
        date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
        signing = f"POST\n{len(body)}\napplication/json\nx-ms-date:{date}\n/api/logs"
        signature = base64.b64encode(hmac.new(base64.b64decode(settings["shared_key"], validate=True), signing.encode(), hashlib.sha256).digest()).decode()
        url = f"https://{workspace}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
        headers = {"Authorization": f"SharedKey {workspace}:{signature}", "Content-Type": "application/json", "x-ms-date": date, "Log-Type": settings.get("log_type", "ArgusITDR")}
    return post(url, data=body, headers=headers)
