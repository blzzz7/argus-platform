"""Admin-configured SOC webhooks; LLM output cannot set destinations."""
from modules.connectors.base import post


def alert(settings, text):
    url = settings.get("soc_webhook_url")
    if not url:
        raise RuntimeError("A SOC webhook is required for Tier 3.")
    post(url, json={"text": text})
