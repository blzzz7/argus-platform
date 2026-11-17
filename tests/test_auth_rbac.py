import time
import unittest
from unittest.mock import MagicMock, patch
from types import SimpleNamespace
from modules.authorization import Principal, bind, require
from modules import auth


class AuthTests(unittest.TestCase):
    def tearDown(self):
        bind(None)

    def test_role_matrix_and_missing_context(self):
        bind(None)
        with self.assertRaises(PermissionError):
            require()
        for role in ["Admin", "SOC Analyst", "Read-Only Auditor"]:
            bind(Principal("user", "tenant", role, MagicMock()))
            require("read")
            for action in ["write", "admin", "sandbox", "remediate"]:
                allowed = role == "Admin" or (role == "SOC Analyst" and action == "write")
                if allowed:
                    require(action)
                else:
                    with self.assertRaises(PermissionError):
                        require(action)

    @patch("modules.auth.config.AUTH_REQUIRE_MFA", True)
    def test_mfa_blocks_binding(self):
        client = MagicMock()
        client.auth.get_user.return_value.user.id = "user"
        client.auth.mfa.get_authenticator_assurance_level.return_value.current_level = "aal1"
        state = {"authenticated": True, "auth_client": client, "auth_started_at": time.time(), "auth_expires_at": time.time() + 1000}
        self.assertEqual(auth.restore(state), [])
        self.assertTrue(state["auth_mfa_pending"])
        with self.assertRaises(PermissionError):
            require()

    @patch("modules.auth.config.AUTH_REQUIRE_MFA", False)
    def test_tenant_switch_clears_old_data_but_keeps_key_names_usable(self):
        client = MagicMock()
        client.auth.get_user.return_value.user.id = "user"
        client.table.return_value.select.return_value.eq.return_value.execute.return_value.data = [{"tenant_id": "second", "role": "SOC Analyst"}]
        state = {"authenticated": True, "auth_client": client, "auth_started_at": time.time(), "auth_expires_at": time.time() + 1000, "active_tenant_id": "second", "bound_identity": ("user", "first"), "df": "old tenant data", "resolved_users": {"old"}, "ai_chat_history": ["secret"], "live_chat": ["secret"], "live_report": {"pdf": b"secret"}}
        auth.restore(state)
        self.assertEqual(require().tenant_id, "second")
        for key in ["df", "resolved_users", "ai_chat_history", "live_chat", "live_report"]:
            self.assertNotIn(key, state)

    def test_logout_invalidates_even_if_provider_fails(self):
        client = MagicMock()
        client.auth.sign_out.side_effect = RuntimeError()
        state = {"auth_client": client, "authenticated": True, "df": "secret"}
        auth.logout(state)
        self.assertFalse(state["authenticated"])
        self.assertNotIn("df", state)
