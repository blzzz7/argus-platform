"""Tenant-bound live probes and end-to-end SIEM verification."""
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit
import requests
from modules.authorization import require
from modules import config, integrations


def bridge_settings():
    p = require("admin")
    settings = integrations.get_active_wazuh_config()
    if not settings.get("ingest_url") or not settings.get("ingest_token"):
        raise RuntimeError("Configure the tenant log bridge URL and token.")
    return settings


def bridge_request(method, path, **kwargs):
    settings = bridge_settings()
    url = urlsplit(settings["ingest_url"])
    endpoint = urlunsplit((url.scheme, url.netloc, path, "", ""))
    response = requests.request(method, endpoint, headers={"Authorization": "Bearer " + settings["ingest_token"], "ngrok-skip-browser-warning": "true"}, timeout=(5, 20), allow_redirects=False, **kwargs)
    response.raise_for_status()
    return response.json()


def health_checks():
    p = require("admin")
    def database():
        if p.client is None:
            raise RuntimeError("Configure Supabase credentials for this workspace.")
        p.client.table("events").select("id").eq("tenant_id", p.tenant_id).limit(1).execute()
        return "Connected"
    def graph():
        from modules.graph_client import GraphClient, secrets
        settings = secrets()
        GraphClient(settings)
        return "Connected (Tenant ID: " + str(settings["entra_tenant_id"])[:8] + "\u2026)"
    def bridge():
        result = bridge_request("GET", "/health")
        if not result.get("ok") or not result.get("wazuh_reachable") or result.get("tenant_id") != p.tenant_id:
            raise RuntimeError("Bridge or Wazuh unavailable, or bridge tenant assignment does not match this workspace.")
        return "Connected: bridge and Wazuh"
    def groq():
        from modules.llm import settings, resolve_model
        base, key, model = settings()
        return "Connected: " + resolve_model(base, key, model)
    results = {}
    for name, probe in {"Microsoft Entra ID": graph, "Local Log Bridge & Wazuh": bridge, "Supabase Database": database, "Groq AI Engine": groq}.items():
        try:
            results[name] = {"ok": True, "detail": probe()}
        except Exception:
            results[name] = {"ok": False, "detail": "Unavailable. Check credentials and connectivity."}
    return results


def pipeline_test():
    p = require("admin")
    health = bridge_request("GET", "/health")
    if health.get("tenant_id") != p.tenant_id:
        raise PermissionError("Bridge tenant assignment does not match this workspace.")
    identifier = str(uuid.uuid4())
    payload = {"id": identifier, "timestamp": datetime.now(timezone.utc).isoformat(), "event_id": 4625, "source": "argus-siem-test", "tenant_id": p.tenant_id, "rule_title": "Argus SIEM pipeline verification", "severity": "Low"}
    started = time.perf_counter()
    delivery = bridge_request("POST", "/ingest", json=payload)
    from modules import storage
    import pandas as pd
    storage.append_events(pd.DataFrame([{"EventID": 4625, "TargetUserName": "argus-siem-test", "Status": "TEST", "AuthMethod": "SIEM pipeline verification", "Timestamp": payload["timestamp"]}]))
    time.sleep(2)
    result = bridge_request("GET", "/audit-read", params={"event_uuid": identifier})
    hits = result.get("hits", {}).get("hits", [])
    confirmed = any(str(hit.get("_source", {}).get("data", hit.get("_source", {})).get("id")) == identifier for hit in hits)
    return {"confirmed": confirmed, "latency_ms": round((time.perf_counter() - started) * 1000), "payload": payload, "delivery": delivery, "audit_response": result}
