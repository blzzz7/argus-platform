import unittest
from unittest.mock import MagicMock, patch
from uuid import uuid4
from modules.authorization import Principal, bind
from modules import remediation


class PlaybookTests(unittest.TestCase):
    def setUp(self):
        self.client = MagicMock()
        bind(Principal("user", "tenant", "Admin", self.client))

    def tearDown(self):
        bind(None)

    @patch("modules.remediation.config.ENABLE_REAL_REMEDIATION", False)
    @patch("modules.remediation.GraphClient")
    def test_simulation_never_acquires_graph_credentials(self, graph):
        result = remediation.execute(str(uuid4()), "user@example.test", "8.8.8.8", "Critical", approved=True)
        self.assertEqual(result["status"], "SIMULATED")
        self.assertEqual(len(result["steps"]), 4)
        graph.assert_not_called()

    def test_requires_explicit_approval(self):
        with self.assertRaises(ValueError):
            remediation.execute(str(uuid4()), "user", "8.8.8.8", "High")
        self.client.table.assert_not_called()

    @patch("modules.remediation.config.ENABLE_REAL_REMEDIATION", True)
    @patch("modules.remediation.secrets", return_value={"protected_accounts": ["breakglass@example.test"]})
    @patch("modules.remediation.GraphClient")
    def test_partial_failure_stops_remaining_steps(self, graph, secrets):
        graph.return_value.resolve.side_effect = lambda account: {"id": account, "userPrincipalName": account}
        graph.return_value.disable.side_effect = RuntimeError("synthetic failure")
        with self.assertRaises(RuntimeError):
            remediation.execute(str(uuid4()), "user@example.test", "8.8.8.8", "High", approved=True)
        graph.return_value.revoke.assert_called_once()
        graph.return_value.block_ip.assert_not_called()
        updates = self.client.table.return_value.update.call_args_list
        self.assertTrue(any(c.args[0].get("status") == "FAILED" for c in updates))

    @patch("modules.remediation.config.ENABLE_REAL_REMEDIATION", True)
    @patch("modules.remediation.secrets", return_value={"protected_accounts": ["breakglass@example.test"]})
    @patch("modules.remediation.GraphClient")
    def test_protected_account_never_touched(self, graph, secrets):
        with self.assertRaises(PermissionError):
            remediation.execute(str(uuid4()), "BREAKGLASS@example.test", "8.8.8.8", "High", approved=True)
        graph.assert_not_called()

    @patch("modules.remediation.config.ENABLE_REAL_REMEDIATION", True)
    @patch("modules.remediation.secrets", return_value={"protected_accounts": ["breakglass@example.test"]})
    @patch("modules.remediation.GraphClient")
    def test_alias_cannot_bypass_emergency_account_protection(self, graph, secrets):
        graph.return_value.resolve.return_value = {"id": "same-protected-object", "userPrincipalName": "breakglass@example.test"}
        with self.assertRaises(PermissionError):
            remediation.execute(str(uuid4()), "alias@example.test", "8.8.8.8", "High", approved=True)
        graph.return_value.revoke.assert_not_called()
        graph.return_value.disable.assert_not_called()

    @patch("modules.remediation.config.ENABLE_REAL_REMEDIATION", True)
    @patch("modules.remediation.secrets", return_value={"protected_accounts": ["breakglass@example.test"], "protected_networks": [], "soc_webhook_url": "https://soc.example.test"})
    @patch("modules.remediation.GraphClient")
    def test_critical_preflight_failure_prevents_all_writes(self, graph, secrets):
        graph.return_value.resolve.side_effect = lambda account: {"id": account, "userPrincipalName": account}
        graph.return_value.block_ip.side_effect = ValueError("invalid IP")
        with self.assertRaises(ValueError):
            remediation.execute(str(uuid4()), "user@example.test", "invalid", "Critical", approved=True)
        graph.return_value.revoke.assert_not_called()
        graph.return_value.disable.assert_not_called()

    @patch("modules.remediation.GraphClient")
    def test_duplicate_reservation_prevents_graph_calls(self, graph):
        self.client.table.return_value.insert.return_value.execute.side_effect = RuntimeError("duplicate run")
        with patch("modules.remediation.config.ENABLE_REAL_REMEDIATION", False):
            with self.assertRaises(RuntimeError):
                remediation.execute(str(uuid4()), "user@example.test", "8.8.8.8", "Critical", approved=True)
        graph.assert_not_called()

    def test_ai_recommendations_are_schema_validated(self):
        from modules.ai_generator import AIServiceSwitcher
        engine = AIServiceSwitcher.__new__(AIServiceSwitcher)
        engine.chat = MagicMock(return_value=(True, '{"severity":"Critical","rationale":"Observed suspicious sign-in evidence."}'))
        self.assertEqual(engine.recommend_playbook({"EventID": 4625})["tier"], 3)
        for reply in ['{"severity":"Execute arbitrary code","rationale":"bad"}', '{"severity":"Low","rationale":"ok","url":"https://untrusted.test"}']:
            engine.chat.return_value = (True, reply)
            with self.assertRaises(ValueError):
                engine.recommend_playbook({"EventID": 4625})
