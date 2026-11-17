"""Tenant-authorized SIEM dispatch, separate from frozen Red Team forwarding."""
from modules.authorization import require
from . import wazuh, splunk, sentinel

ADAPTERS = {"wazuh": wazuh, "splunk": splunk, "sentinel": sentinel}


def validate_settings(provider, settings):
    from .base import https_url
    if not isinstance(settings, dict):
        raise ValueError("Connector settings must be an object.")
    if provider == "wazuh":
        https_url(settings["ingest_url"])
        if not settings.get("ingest_token"):
            raise ValueError("A bridge token is required.")
    elif provider == "splunk":
        https_url(settings.get("url") or settings["endpoint_url"])
        if not (settings.get("token") or settings.get("hec_token")):
            raise ValueError("A Splunk HEC token is required.")
    elif provider == "sentinel":
        from uuid import UUID
        if settings.get("dcr_id"):
            https_url(settings["endpoint"])
            UUID(settings["entra_tenant_id"])
            UUID(settings["client_id"])
            if not settings.get("stream") or not settings.get("client_secret"):
                raise ValueError("Sentinel stream and credentials are required.")
        else:
            import base64
            UUID(settings["workspace_id"])
            if not base64.b64decode(settings["shared_key"], validate=True):
                raise ValueError("A valid workspace shared key is required.")
    else:
        raise ValueError("Unknown connector.")


def dispatch(event, provider, settings):
    p = require("write")
    if provider not in ADAPTERS:
        raise ValueError("Unknown connector.")
    validate_settings(provider, settings)
    status = "FAILED"
    try:
        ADAPTERS[provider].send(event, settings)
        status = "DELIVERED"
    finally:
        p.client.table("delivery_attempts").insert({"tenant_id": p.tenant_id, "connector": provider, "status": status}).execute()
    return status
