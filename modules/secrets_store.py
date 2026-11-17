"""Encrypt connector configuration before database persistence."""
from cryptography.fernet import Fernet
from modules import config
import json


def seal(settings):
    if not config.CONFIG_ENCRYPTION_KEY:
        raise RuntimeError("Set ARGUS_CONFIG_ENCRYPTION_KEY before saving integration credentials.")
    return {"encrypted": Fernet(config.CONFIG_ENCRYPTION_KEY.encode()).encrypt(json.dumps(settings).encode()).decode()}


def unseal(settings):
    if "encrypted" not in settings:
        # Legacy records remain readable during migration; save again to encrypt.
        return settings
    if not config.CONFIG_ENCRYPTION_KEY:
        raise RuntimeError("Integration decryption key is unavailable.")
    return json.loads(Fernet(config.CONFIG_ENCRYPTION_KEY.encode()).decrypt(settings["encrypted"].encode()))
