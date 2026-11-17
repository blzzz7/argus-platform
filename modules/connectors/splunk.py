"""Splunk HEC event adapter."""
from .base import post


def send(event, settings):
    url = (settings.get("url") or settings["endpoint_url"]).rstrip("/")
    if "/services/collector" not in url:
        url += "/services/collector/event"
    body = {"event": event, "sourcetype": "argus:itdr"}
    if settings.get("index"):
        body["index"] = settings["index"]
    response = post(url, json=body, headers={"Authorization": "Splunk " + (settings.get("token") or settings["hec_token"])})
    if response.json().get("code") != 0:
        raise RuntimeError("Splunk HEC rejected the event.")
    return response
