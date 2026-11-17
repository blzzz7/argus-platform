"""Forward unchanged event bodies to an existing Argus bridge."""
from .base import post


def send(event, settings):
    return post(settings["ingest_url"], json=event, headers={
        "X-Argus-Token": settings["ingest_token"],
        "Content-Type": "application/json", "ngrok-skip-browser-warning": "true",
    })
