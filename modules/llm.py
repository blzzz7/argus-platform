"""Shared OpenAI-compatible model discovery for health checks and chat."""
import requests
from modules import config


def settings():
    from modules.authorization import require
    from modules.integrations import get_integration
    principal = require("write")
    row = get_integration("ai_groq")
    if row and row.get("enabled") and row.get("config"):
        values = row["config"]
        return (values.get("base_url") or "https://api.groq.com/openai/v1").rstrip("/"), values.get("api_key", ""), values.get("model") or config.GROQ_MODEL
    if not principal.local_admin and principal.tenant_id != config.LEGACY_TENANT_ID:
        raise RuntimeError("Configure a tenant AI connector.")
    return (config.LLM_BASE_URL or "https://api.groq.com/openai/v1").rstrip("/"), config.GROQ_API_KEY or config.LLM_API_KEY, config.LLM_MODEL or config.GROQ_MODEL


def resolve_model(base_url, key, preferred):
    if not key:
        raise RuntimeError("Configure GROQ_API_KEY or LLM_API_KEY.")
    response = requests.get(base_url.rstrip("/") + "/models", headers={"Authorization": "Bearer " + key}, timeout=15)
    response.raise_for_status()
    models = [item["id"] for item in response.json().get("data", []) if item.get("active", True)]
    if preferred in models:
        return preferred
    for candidate in ("llama-3.3-70b-versatile", "llama-3.1-8b-instant"):
        if candidate in models:
            return candidate
    raise RuntimeError("Configured model is unavailable; select an active chat model from the provider catalog.")
