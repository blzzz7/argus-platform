"""Local workspace credentials and shared model discovery regressions."""
import time
import socket
import unittest
import httpx
from unittest.mock import MagicMock, patch
from modules import auth, config
from modules.authorization import bind, require, Principal
from modules.llm import resolve_model, settings
from modules.graph_client import secrets
from modules.integrations import get_active_wazuh_config


class WorkspaceTests(unittest.TestCase):
    def tearDown(self):
        bind(None)

    def test_database_failure_uses_authorized_environment_credentials(self):
        from modules.integrations import get_integration
        for error in (httpx.ConnectError("unreachable"), socket.gaierror("DNS failed"), RuntimeError("database unavailable")):
            with self.subTest(error=type(error).__name__):
                client = MagicMock()
                client.table.return_value.select.return_value.eq.return_value.eq.return_value.limit.return_value.execute.side_effect = error
                bind(Principal("actor", "local", "Admin", client, local_admin=True))
                with patch.multiple(config, TENANT_SECRETS_JSON="{}", TENANT_ID="entra", CLIENT_ID="client", CLIENT_SECRET="secret", ARGUS_INGEST_URL="https://bridge.test/ingest", ARGUS_INGEST_TOKEN="synthetic", GROQ_API_KEY="synthetic", LLM_MODEL="preferred"):
                    self.assertIsNone(get_integration("wazuh"))
                    self.assertEqual(get_active_wazuh_config()["source"], "env")
                    self.assertEqual(get_active_wazuh_config()["ingest_token"], "synthetic")
                    self.assertEqual(settings()[1:], ("synthetic", "preferred"))
                    self.assertEqual(secrets()["client_secret"], "secret")
                    bind(Principal("actor", "unrelated", "Admin", client))
                    with self.assertRaises(PermissionError):
                        get_active_wazuh_config()
                    with self.assertRaises(RuntimeError):
                        settings()
                    with self.assertRaises(RuntimeError):
                        secrets()

    def test_integration_decryption_failure_still_surfaces(self):
        from modules.integrations import get_integration
        client = MagicMock()
        client.table.return_value.select.return_value.eq.return_value.eq.return_value.limit.return_value.execute.return_value.data = [{"config": {"encrypted": "synthetic"}}]
        bind(Principal("actor", "local", "Admin", client, local_admin=True))
        with patch("modules.integrations.unseal", side_effect=RuntimeError("decryption failed")):
            with self.assertRaisesRegex(RuntimeError, "decryption failed"):
                get_integration("wazuh")

    def test_local_admin_service_client_and_uuid_actor(self):
        from uuid import UUID
        client = MagicMock()
        with patch.multiple(config, SUPABASE_URL="https://synthetic.test", SUPABASE_KEY="synthetic", LOCAL_TENANT_ID="local"), patch("supabase.create_client", return_value=client) as create:
            state = {"auth_local": True, "authenticated": True, "auth_started_at": time.time()}
            auth.restore(state)
            self.assertIs(require().client, client)
            self.assertTrue(require().local_admin)
            UUID(require().user_id)
            auth.restore(state)
            create.assert_called_once_with("https://synthetic.test", "synthetic")
            client.table.assert_not_called()

    def test_env_credentials_are_local_only(self):
        bind(Principal("actor", "local", "Admin", None, local_admin=True))
        with patch.multiple(config, TENANT_SECRETS_JSON="{}", TENANT_ID="entra", CLIENT_ID="client", CLIENT_SECRET="secret", ARGUS_INGEST_URL="https://bridge.test/ingest", ARGUS_INGEST_TOKEN="synthetic", GROQ_API_KEY="synthetic", LLM_MODEL="preferred"):
            self.assertEqual(secrets()["entra_tenant_id"], "entra")
            self.assertEqual(get_active_wazuh_config()["ingest_token"], "synthetic")
            self.assertEqual(settings()[2], "preferred")
            bind(Principal("actor", "other", "Admin", None))
            with self.assertRaises(RuntimeError):
                secrets()
            with self.assertRaises(PermissionError):
                get_active_wazuh_config()
            with self.assertRaises(RuntimeError):
                settings()

    def test_models_catalog_and_retired_model_fallback(self):
        with patch("modules.llm.requests.get") as get:
            get.return_value.json.return_value = {"data": [{"id": "retired", "active": False}, {"id": "llama-3.1-8b-instant", "active": True}]}
            self.assertEqual(resolve_model("https://api.groq.com/openai/v1", "synthetic", "retired"), "llama-3.1-8b-instant")
            self.assertEqual(get.call_args.args[0], "https://api.groq.com/openai/v1/models")
            self.assertEqual(get.call_args.kwargs["headers"]["Authorization"], "Bearer synthetic")

    def test_local_admin_redteam_controls_render_without_requests(self):
        import sys
        from pathlib import Path
        from types import SimpleNamespace
        from streamlit.testing.v1 import AppTest
        engine = MagicMock()
        engine.users = ["user13@example.test", "fake_user_1@example.test"]
        fake = SimpleNamespace(DOMAIN="example.test", IdentityAttackEngine=MagicMock(return_value=engine), USERS_FILE="synthetic-users", PASSWORDS_FILE="synthetic-passwords", generate_wordlists=MagicMock(return_value={"graph_fetch_ok": True, "real_user_count": 1}))
        def restore(state):
            state.update(authenticated=True, auth_username="admin", auth_role="Admin", active_tenant_id="local")
            bind(Principal("actor", "local", "Admin", None, local_admin=True))
            return [{"tenant_id": "local", "role": "Admin"}]
        with patch.dict(sys.modules, {"modules.attack_engine": fake}), patch("modules.auth.restore", side_effect=restore), patch("modules.integrations.get_active_wazuh_config", return_value={"ingest_url": "", "ingest_token": "", "source": "env"}):
            app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "app_ui.py")).run(timeout=30)
            app.radio[0].set_value("Red Team Attack Controller").run(timeout=30)
            self.assertFalse(app.exception)
            self.assertTrue(any(item.value == "Workspace: Default" for item in app.caption))
            self.assertTrue(any(item.label == "Attack vector" for item in app.selectbox))
            self.assertTrue(any(item.label == "Target domain" for item in app.text_input))
            self.assertTrue(any(item.label == "MFA iteration limit" for item in app.slider))
            self.assertTrue(any(item.label == "Execute Selected Attack" and not item.disabled for item in app.button))
            self.assertFalse(any("Guest preview" in item.value for item in app.caption))
            limit = next(item for item in app.number_input if item.label == "Max Target Limit")
            self.assertEqual(limit.value, 1)
            self.assertEqual(limit.max, len(engine.users))
            self.assertFalse(any("Identity source:" in item.value for item in app.success))
            self.assertFalse(any("Simulation / Sandbox Mode" in item.value for item in app.warning))
            self.assertFalse(any("Events use" in item.value for item in app.caption))
            self.assertIn("user13@example.test", engine.users)
            engine.public_app.acquire_token_by_username_password.assert_not_called()
