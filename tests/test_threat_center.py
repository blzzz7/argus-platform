import json
import unittest
from unittest.mock import patch, MagicMock
import yaml
from streamlit.testing.v1 import AppTest
from modules.authorization import Principal, bind
from modules.threat_center import compromised_alerts, compute_severity, canonical_route, generate_sigma, generate_actions, CENTER_ROUTE, LEGACY_ROUTES


def event(i, code="4625", severity="Low", user="test@example.test"):
    return {"id": i, "EventID": code, "TargetUserName": user, "IpAddress": "198.51.100.1", "severity": severity, "created_at": f"2026-11-17T10:00:{i:02d}Z", "AuthMethod": "Password"}


class ThreatCenterTests(unittest.TestCase):
    def tearDown(self):
        bind(None)

    def test_alert_signals_and_raw_log_exclusion(self):
        self.assertEqual(compromised_alerts([event(1)]), [])
        self.assertEqual(len(compromised_alerts([event(i) for i in range(6)])), 1)
        self.assertEqual(len(compromised_alerts([event(1, severity="High")])), 1)
        rows = [event(i) for i in range(3)] + [event(4, "4624")]
        self.assertIn("Success after", compromised_alerts(rows)[0]["pattern"])
        rows[-1]["created_at"] = "2026-11-17T11:00:00Z"
        self.assertEqual(len(compromised_alerts(rows)), 1)

    def test_accounts_do_not_share_failure_thresholds(self):
        self.assertEqual(compromised_alerts([event(i, user=f"user{i}@example.test") for i in range(8)]), [])

    def test_shared_severity_uses_sequence_burst_and_existing_risk(self):
        for rows, expected in [
            ([event(i) for i in range(6)], "MEDIUM"),
            ([event(i) for i in range(10)], "HIGH"),
            ([event(1, severity="High")], "HIGH"),
            ([event(1, severity="Critical")], "CRITICAL"),
            ([event(i) for i in range(3)] + [event(4, "4624")], "CRITICAL"),
        ]:
            with self.subTest(severity=expected):
                self.assertEqual(compute_severity(compromised_alerts(rows)[0]), expected)

    def test_contained_accounts_use_confirmed_audit_steps_only(self):
        from modules.db import contained_accounts
        rows = [event(1), event(2, user="TEST@example.test"), event(3, user="preview@example.test")]
        audit = [
            {"action": "INCIDENT_RESPONSE", "detail": {"incident_id": 1, "action": "revoke", "http_status": 200}},
            {"action": "INCIDENT_RESPONSE", "detail": {"incident_id": 2, "action": "block", "http_status": 204}},
            {"action": "INCIDENT_RESPONSE", "detail": {"incident_id": 3, "action": "block", "http_status": 403}},
            {"action": "CONTAINMENT_PREVIEW", "detail": {"user": "preview@example.test", "status": "DRY_RUN"}},
        ]
        with patch("modules.db.containment_audit", return_value=audit):
            self.assertEqual(contained_accounts(rows), 1)
            self.assertEqual(contained_accounts([]), "N/A")

    def test_dry_run_records_audit_without_graph(self):
        app = AppTest.from_string("from modules.threat_center_ui import response_center\nfrom modules.authorization import bind, Principal\nimport streamlit as st\nbind(Principal('actor','tenant','Admin',None))\nresponse_center(st.session_state['rows'])")
        app.session_state["rows"] = [event(1, severity="High")]
        with patch("modules.config.ENABLE_REAL_REMEDIATION", False), patch("modules.threat_center_ui.response_target") as target, patch("modules.threat_center_ui.respond_to_incident") as response, patch("modules.threat_center_ui.audit") as audit:
            app.run()
            next(b for b in app.button if b.label == "Preview containment (DRY-RUN)").click().run()
            self.assertFalse(app.exception)
            audit.assert_called_once_with("CONTAINMENT_PREVIEW", {"user": "test@example.test", "incident_id": 1, "mode": "DRY-RUN", "status": "DRY_RUN"})
            target.assert_not_called()
            response.assert_not_called()

    def test_aliases(self):
        for old in LEGACY_ROUTES:
            self.assertEqual(canonical_route(old), CENTER_ROUTE)

    def test_ai_requires_write_and_validates_outputs(self):
        alert = compromised_alerts([event(1, severity="High")])[0]
        bind(Principal("actor", "tenant", "Read-Only Auditor", None))
        with patch("modules.threat_center.soc_chat") as chat:
            with self.assertRaises(PermissionError):
                generate_sigma(alert)
            with self.assertRaises(PermissionError):
                generate_actions(alert)
            chat.assert_not_called()
        bind(Principal("actor", "tenant", "SOC Analyst", None))
        with patch("modules.threat_center.soc_chat", return_value="title: Test\nlogsource: {product: windows}\ndetection:\n  selection: {EventID: 4625}\n  condition: selection"):
            rule = yaml.safe_load(generate_sigma(alert))
            self.assertEqual(rule["detection"]["argus_account"]["TargetUserName"], alert["user"])
        with patch("modules.threat_center.soc_chat", return_value="invalid"):
            with self.assertRaises(ValueError):
                generate_sigma(alert)
        with patch("modules.threat_center.soc_chat", return_value=json.dumps([{"Possible Actions": "Revoke sessions", "Expected Outcomes & Impact": "Requires fresh authentication"}])):
            self.assertEqual(len(generate_actions(alert)), 1)

    def test_center_features_and_selection_reset(self):
        rows = [event(1, severity="High"), event(2, severity="High", user="other@example.test")]
        app = AppTest.from_string("from modules.live_ui import response_center\nfrom modules.authorization import bind, Principal\nimport streamlit as st\nbind(Principal('actor','tenant','Admin',None))\nresponse_center(st.session_state['rows'])")
        app.session_state["rows"] = rows
        with patch("modules.config.ENABLE_REAL_REMEDIATION", True), patch("modules.threat_center_ui.response_target"), patch("modules.threat_center_ui.respond_to_incident", return_value=[{"action": "block", "http_status": 204}]) as response, patch("modules.threat_center.generate_sigma", return_value="title: test"), patch("modules.threat_center.generate_actions", return_value=[{"Possible Actions": "Review", "Expected Outcomes & Impact": "Evidence"}]):
            app.run()
            self.assertFalse(app.exception)
            next(b for b in app.button if b.label == "Generate Sigma Rule").click().run()
            self.assertEqual(app.code[0].value, "title: test")
            next(b for b in app.button if b.label == "Generate Possible Actions").click().run()
            self.assertEqual(len(app.checkbox), 0)
            next(b for b in app.button if b.label == "Revoke Sessions & Disable Account").click().run()
            response.assert_called_once_with(2, "both")
            app.run()
            self.assertTrue(next(b for b in app.button if b.label == "Revoke Sessions & Disable Account").disabled)
            response.assert_called_once_with(2, "both")
            app.button(key="account_alert_1").click().run()
            self.assertFalse(app.radio)
            self.assertIn("Selected", app.button(key="account_alert_1").label)
            self.assertIn("test@example.test", app.button(key="account_alert_1").label)
            self.assertNotIn("center_response", app.session_state)
            self.assertNotIn("center_actions", app.session_state)
            self.assertEqual(len(app.checkbox), 0)
            self.assertEqual(len(app.code), 0)

    def test_ui_auditor_cannot_generate_or_remediate(self):
        app = AppTest.from_string("from modules.live_ui import response_center\nfrom modules.authorization import bind, Principal\nimport streamlit as st\nbind(Principal('actor','tenant','Read-Only Auditor',None))\nresponse_center(st.session_state['rows'])")
        app.session_state["rows"] = [event(1, severity="High")]
        app.run()
        self.assertFalse(app.exception)
        self.assertFalse(app.button(key="account_alert_0").disabled)
        self.assertTrue(all(b.disabled for b in app.button if b.key != "account_alert_0"))
        self.assertEqual(len(app.checkbox), 0)

    def test_legacy_query_routes_redirect(self):
        from pathlib import Path
        for old in LEGACY_ROUTES:
            app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "app_ui.py"))
            app.query_params["route"] = old
            app.run(timeout=30)
            self.assertFalse(app.exception)
            self.assertEqual(app.radio[0].value, CENTER_ROUTE)
            self.assertEqual(app.query_params["route"], [CENTER_ROUTE])

    def test_response_service_refuses_protected_target(self):
        from modules.remediation import respond_to_incident
        client = MagicMock()
        q = client.table.return_value
        q.select.return_value = q
        q.eq.return_value = q
        q.execute.return_value.data = [event(1, severity="High")]
        bind(Principal("actor", "tenant", "Admin", client))
        graph = MagicMock()
        graph.resolve.return_value = {"id": "protected-target"}
        with patch("modules.remediation.config.ENABLE_REAL_REMEDIATION", True), patch("modules.remediation.secrets", return_value={"protected_accounts": ["emergency@example.test"]}), patch("modules.remediation.GraphClient", return_value=graph):
            with self.assertRaises(PermissionError):
                respond_to_incident(1, "both")
            graph.request.assert_not_called()
            q.update.assert_not_called()

    def test_action_table_combines_separate_outcome_and_impact(self):
        bind(Principal("actor", "tenant", "SOC Analyst", None))
        alert = compromised_alerts([event(1, severity="High")])[0]
        raw = [{"Possible Actions": "Revoke sessions", "Expected Outcomes": "Invalidates tokens.", "Impact": "Fresh authentication required."}]
        with patch("modules.threat_center.soc_chat", return_value=json.dumps({"actions": raw})) as chat:
            self.assertIn("Fresh authentication", generate_actions(alert)[0]["Expected Outcomes & Impact"])
            self.assertEqual(chat.call_args.kwargs["response_format"], {"type": "json_object"})

    def test_protected_account_disables_direct_action(self):
        app = AppTest.from_string("from modules.threat_center_ui import response_center\nfrom modules.authorization import bind, Principal\nimport streamlit as st\nbind(Principal('actor','tenant','Admin',None))\nresponse_center(st.session_state['rows'])")
        app.session_state["rows"] = [event(1, severity="High")]
        with patch("modules.config.ENABLE_REAL_REMEDIATION", True), patch("modules.threat_center_ui.response_target", side_effect=PermissionError("Protected account cannot be remediated.")), patch("modules.threat_center_ui.respond_to_incident") as response:
            app.run()
            self.assertTrue(next(b for b in app.button if b.label == "Revoke Sessions & Disable Account").disabled)
            self.assertIn("test@example.test", app.button(key="account_alert_0").label)
            self.assertEqual(len(app.checkbox), 0)
            response.assert_not_called()
