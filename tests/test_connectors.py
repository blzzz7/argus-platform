import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from modules.connectors import splunk, sentinel
from modules.connectors.base import https_url
import receiver


class ConnectorTests(unittest.TestCase):
    def test_configuration_encryption_and_tamper_detection(self):
        from cryptography.fernet import Fernet, InvalidToken
        from modules.secrets_store import seal, unseal
        with patch("modules.secrets_store.config.CONFIG_ENCRYPTION_KEY", Fernet.generate_key().decode()):
            sealed = seal({"token": "synthetic-secret"})
            self.assertNotIn("synthetic-secret", str(sealed))
            self.assertEqual(unseal(sealed), {"token": "synthetic-secret"})
            with self.assertRaises(InvalidToken):
                unseal({"encrypted": sealed["encrypted"][:-8] + "tampered"})

    def test_https_required(self):
        for url in ["http://example.test", "https://user:secret@example.test", "file:///tmp/test"]:
            with self.assertRaises(ValueError):
                https_url(url)

    @patch("modules.connectors.splunk.post")
    def test_splunk_checks_application_error(self, post):
        post.return_value.json.return_value = {"code": 6}
        with self.assertRaises(RuntimeError):
            splunk.send({"EventID": 4625}, {"url": "https://splunk.test", "token": "synthetic"})

    @patch("modules.connectors.sentinel.post")
    def test_legacy_sentinel_signs_utf8_bytes(self, post):
        sentinel.send({"user": "\u00e9"}, {"workspace_id": "00000000-0000-0000-0000-000000000001", "shared_key": "c3ludGhldGlj"})
        self.assertIsInstance(post.call_args.kwargs["data"], bytes)
        self.assertIn("SharedKey", post.call_args.kwargs["headers"]["Authorization"])

    def test_bridge_missing_token_fails_closed(self):
        with patch.object(receiver, "ARGUS_INGEST_TOKEN", ""), patch.object(receiver, "TENANT_BRIDGE_KEYS", {}):
            self.assertEqual(receiver.app.test_client().post("/ingest", json={}).status_code, 401)

    def test_legacy_payload_and_response_unchanged(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(receiver, "LOG_FILE", Path(directory) / "events.json"), patch.object(receiver, "ARGUS_INGEST_TOKEN", "synthetic"), patch.object(receiver, "LEGACY_TENANT_ID", "00000000-0000-0000-0000-000000000001"):
            client = receiver.app.test_client()
            headers = {"X-Argus-Token": "synthetic"}
            payload = {"event_id": 4625, "user": "synthetic@example.test"}
            response = client.post("/ingest", json=payload, headers=headers)
            self.assertEqual(response.status_code, 201)
            self.assertTrue(response.json["written"])
            import json
            self.assertEqual(json.loads(receiver.LOG_FILE.read_text()), payload)
            self.assertEqual(client.post("/ingest", json=[], headers=headers).status_code, 400)
            self.assertEqual(client.post("/search", json={"index": "foreign"}, headers=headers).status_code, 403)
            self.assertEqual(client.post("/search", json=[], headers=headers).status_code, 400)
