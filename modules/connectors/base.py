"""Bounded HTTPS transport shared by SIEM adapters."""
from urllib.parse import urlsplit
import requests


def https_url(value):
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("An HTTPS endpoint without embedded credentials is required.")
    return value.rstrip("/")


def post(url, **kwargs):
    response = requests.post(https_url(url), timeout=(5, 20), verify=True, allow_redirects=False, **kwargs)
    response.raise_for_status()
    if not 200 <= response.status_code < 300:
        raise RuntimeError("Connector returned an unexpected status.")
    return response
