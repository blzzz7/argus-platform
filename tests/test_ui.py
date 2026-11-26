"""Streamlit workflow checks with synthetic identities and no external calls."""
from pathlib import Path
from types import SimpleNamespace
import unittest
import ast
from unittest.mock import patch
import pandas as pd
from streamlit.testing.v1 import AppTest
from modules.authorization import Principal, bind

APP = Path(__file__).resolve().parents[1] / "app_ui.py"


class Query:
    def __getattr__(self, name):
        if name == "execute":
            return lambda: SimpleNamespace(data=[])
        return lambda *args, **kwargs: self


class UIWorkflowTests(unittest.TestCase):
    def tearDown(self):
        bind(None)

    def test_guest_copilot_and_privacy_navigation(self):
        app = AppTest.from_file(str(APP)).run(timeout=30)
        next(button for button in app.button if button.label == "AI Copilot").click().run()
        self.assertTrue(any(item.value == "AI Copilot" for item in app.subheader))
        self.assertFalse(app.chat_input)
        next(button for button in app.button if button.label == "Close").click().run()
        self.assertFalse(any(item.value == "AI Copilot" for item in app.subheader))
        app.query_params["page"] = "privacy"
        app.run()
        self.assertEqual(app.title[0].value, "Privacy Policy")
        self.assertTrue(any("Microsoft Entra ID & Graph API Permissions" in item.value for item in app.markdown))
        app.button(key="privacy_back").click().run()
        self.assertEqual(app.title[0].value, "Argus ITDR SOC Workspace")

    def test_guest_workspace_and_create_workspace_route(self):
        app = AppTest.from_file(str(APP)).run(timeout=30)
        self.assertFalse(app.exception)
        self.assertEqual(app.title[0].value, "Argus ITDR SOC Workspace")
        self.assertEqual(len(app.radio[0].options), 7)
        self.assertTrue(any("Guest Mode" in item.value for item in app.caption))
        create = next(button for button in app.button if button.label == "Create Workspace")
        create.click().run(timeout=30)
        self.assertFalse(app.exception)
        self.assertEqual(app.query_params["auth_mode"], ["signup"])
        self.assertTrue(any(item.label == "Organization / Tenant Name" for item in app.text_input))

    def test_guest_can_browse_every_route_without_service_calls(self):
        with patch("modules.storage.load_events") as events, patch("modules.live_ui.incident_records") as records, patch("modules.connectors.live.health_checks") as health:
            app = AppTest.from_file(str(APP)).run(timeout=30)
            for route in app.radio[0].options:
                with self.subTest(route=route):
                    app.radio[0].set_value(route).run(timeout=30)
                    self.assertFalse(app.exception)
                    self.assertEqual(app.title[0].value, "Argus ITDR SOC Workspace")
            events.assert_not_called()
            records.assert_not_called()
            health.assert_not_called()

    def test_guest_sensitive_actions_prompt_authentication(self):
        app = AppTest.from_file(str(APP)).run(timeout=30)
        actions = {
            "Red Team Attack Controller": "Run simulation",
            "SIEM Integration Test": "Send Test Event to SIEM",
            "Security Audit Report": "Generate audit report",
            "Integrations": "Manage integrations",
        }
        for route, label in actions.items():
            app.radio[0].set_value(route).run(timeout=30)
            next(button for button in app.button if button.label == label).click().run(timeout=30)
            self.assertFalse(app.exception)
            self.assertTrue(any("Sign in or create" in item.value for item in app.info))
        app.radio[0].set_value("Live Log Ingestion").run(timeout=30)
        self.assertTrue(app.get("file_uploader")[0].proto.disabled)

    def test_analyst_tabs_and_restricted_routes(self):
        client = SimpleNamespace(table=lambda *args: Query())

        def restore(state):
            state["authenticated"] = True
            state["auth_username"] = "analyst@example.test"
            state["auth_role"] = "SOC Analyst"
            state["active_tenant_id"] = "00000000-0000-0000-0000-000000000001"
            state.setdefault("df", pd.DataFrame([{"EventID": "4625", "TargetUserName": "<untrusted & account>@example.test", "IpAddress": "198.51.100.1", "Status": "FAILED", "AuthMethod": "PasswordSpray", "ErrorCode": "invalid_grant"}]))
            state.setdefault("resolved_users", set())
            bind(Principal("synthetic", state["active_tenant_id"], "SOC Analyst", client))
            return [{"tenant_id": state["active_tenant_id"], "role": "SOC Analyst"}]

        with patch("modules.auth.restore", side_effect=restore):
            app = AppTest.from_file(str(APP))
            app.query_params["page"] = "app"
            app.run(timeout=30)
            self.assertFalse(app.exception)
            options = app.radio[0].options
            tree = ast.parse(APP.read_text(encoding="utf-8"))
            routes = ast.literal_eval(next(n.value for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "MENU_OPTIONS" for t in n.targets)))
            for index, option in enumerate(options):
                with self.subTest(route=option):
                    # options are display labels; underlying values preserve the legacy route strings.
                    app.radio[0].set_value(routes[index]).run(timeout=30)
                    self.assertFalse(app.exception)
                    if "Red Team" in option:
                        self.assertTrue(any("Admin access" in item.value for item in app.warning))
                        self.assertFalse(any("Launch" in button.label for button in app.button))
                    if option == "Integrations":
                        self.assertTrue(any("Admin access" in item.value for item in app.info))
