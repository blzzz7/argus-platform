"""Live integration contracts with synthetic evidence and mocked upstream services."""
import hashlib
import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
import receiver
from modules import auth
from modules.authorization import Principal, bind, require
from modules.db import incident_records
from modules.detection import evaluate
from modules.reports import build_report
from modules.connectors.live import pipeline_test
from modules.remediation import respond_to_incident

TENANT = "00000000-0000-0000-0000-000000000001"
OTHER = "00000000-0000-0000-0000-000000000002"


class LiveIntegrationTests(unittest.TestCase):
    def tearDown(self):
        bind(None)

    def test_local_admin_is_tenant_bound_without_configured_storage(self):
        with patch.multiple(auth.config, ADMIN_USER="local@example.test", ADMIN_PASS="synthetic-password", ADMIN_HASH="", LOCAL_TENANT_ID=TENANT, SUPABASE_URL="", SUPABASE_KEY=""):
            state = {}
            auth.login(state, "local@example.test", "synthetic-password")
            self.assertTrue(auth.restore(state))
            self.assertEqual(require().tenant_id, TENANT)
            self.assertIsNone(require().client)
            with self.assertRaises(RuntimeError):
                incident_records()
            state["auth_started_at"] = 0
            self.assertEqual(auth.restore(state), [])

    def test_signup_provides_organization_metadata_without_client_role_assignment(self):
        client = MagicMock()
        client.auth.sign_up.return_value.session = None
        with patch("modules.auth.new_client", return_value=client):
            self.assertFalse(auth.signup({}, "owner@example.test", "synthetic-password", "Example Organization"))
        options = client.auth.sign_up.call_args.args[0]["options"]
        self.assertEqual(options, {"data": {"organization_name": "Example Organization"}})
        client.table.assert_not_called()

    def test_detection_uses_recent_failures_and_five_minute_boundary(self):
        rows = [{"id": i, "EventID": "4625", "TargetUserName": "user@example.test", "created_at": f"2026-11-17T10:0{i}:00Z"} for i in range(6)]
        findings = evaluate(rows, "2026-11-17T10:05:00Z")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["failed_logins"], 6)
        self.assertEqual(evaluate(rows[:5], "2026-11-17T10:05:00Z"), [])
        self.assertEqual(evaluate(rows, "2026-11-17T11:05:00Z"), [])
        self.assertEqual(evaluate([{**r, "EventID": "4624"} for r in rows], "2026-11-17T10:05:00Z"), [])

    def test_event_reads_page_and_filter_by_trusted_tenant(self):
        client = MagicMock()
        query = client.table.return_value
        query.select.return_value = query
        query.eq.return_value = query
        query.order.return_value = query
        query.range.return_value = query
        query.execute.side_effect = [SimpleNamespace(data=[{"id": i} for i in range(1000)]), SimpleNamespace(data=[{"id": 1000}])]
        bind(Principal("actor", TENANT, "SOC Analyst", client))
        self.assertEqual(len(incident_records()), 1001)
        self.assertEqual(query.eq.call_args_list[0].args, ("tenant_id", TENANT))
        self.assertEqual(query.range.call_args_list[-1].args, (1000, 1999))

    def test_report_escapes_untrusted_content_and_generates_pdf(self):
        html, pdf = build_report([{"created_at": "2026-11-17", "TargetUserName": "<script>bad</script>", "severity": "High", "status": "New"}], "Observed <evidence>", TENANT, "2026-11-17")
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<script>", html)
        self.assertTrue(pdf.startswith(b"%PDF"))
        self.assertIn("background:#FFFFFF;color:#111827", html)
        self.assertIn('name="color-scheme" content="light"', html)
        self.assertIn("<html lang=", html)
        self.assertIn("1 high or critical", html)

    def test_bearer_bridge_is_bound_to_server_assignment(self):
        token = "synthetic-token"
        mapping = {hashlib.sha256(token.encode()).hexdigest(): {"tenant_id": TENANT, "index": "tenant-one"}}
        with tempfile.TemporaryDirectory() as folder, patch.object(receiver, "TENANT_BRIDGE_KEYS", mapping), patch.object(receiver, "ARGUS_LOG_DIR", folder):
            client = receiver.app.test_client()
            headers = {"Authorization": "Bearer " + token}
            payload = {"tenant_id": OTHER, "event_id": 4625}
            self.assertEqual(client.post("/ingest", json=payload, headers=headers).status_code, 201)
            self.assertTrue((Path(folder) / TENANT / receiver.ARGUS_LOG_FILENAME).exists())
            self.assertFalse((Path(folder) / OTHER).exists())
            self.assertEqual(client.post("/search", json={"index": "foreign"}, headers=headers).status_code, 403)
            self.assertEqual(client.get("/health").status_code, 200)

    def test_public_health_does_not_expose_tenant_or_probe_upstream(self):
        with patch("receiver.requests.post") as post:
            result = receiver.app.test_client().get("/health")
            self.assertEqual(result.status_code, 200)
            self.assertEqual(result.json, {"ok": True, "status": "alive", "token_required": True})
            post.assert_not_called()

    def test_empty_bridge_token_cannot_read_or_write_tenant_data(self):
        with patch.object(receiver, "ARGUS_INGEST_TOKEN", ""), patch.object(receiver, "TENANT_BRIDGE_KEYS", {}):
            client = receiver.app.test_client()
            for path in ["/ingest", "/search", "/forward/wazuh"]:
                self.assertEqual(client.post(path, json={}).status_code, 401)
            self.assertEqual(client.get("/audit-read?event_uuid=test").status_code, 401)

    def test_bridge_health_requires_wazuh_search_success(self):
        with patch.object(receiver, "ARGUS_INGEST_TOKEN", "synthetic"), patch.object(receiver, "LEGACY_TENANT_ID", TENANT), patch("receiver.requests.post") as post:
            post.return_value.json.return_value = {"hits": {"hits": []}}
            result = receiver.app.test_client().get("/health", headers={"Authorization": "Bearer synthetic"})
            self.assertEqual(result.status_code, 200)
            self.assertEqual(result.json["tenant_id"], TENANT)
            post.side_effect = RuntimeError("upstream down")
            self.assertEqual(receiver.app.test_client().get("/health", headers={"Authorization": "Bearer synthetic"}).status_code, 503)

    def test_pipeline_requires_matching_uuid_and_tenant(self):
        bind(Principal("actor", TENANT, "Admin", MagicMock()))
        def request(method, path, **kwargs):
            if path == "/health":
                return {"tenant_id": TENANT}
            if path == "/ingest":
                self.payload = kwargs["json"]
                return {"written": True}
            return {"hits": {"hits": [{"_source": {"data": {"id": self.payload["id"]}}}]}}
        with patch("modules.connectors.live.bridge_request", side_effect=request), patch("modules.connectors.live.time.sleep"):
            result = pipeline_test()
            self.assertTrue(result["confirmed"])
            self.assertEqual(result["payload"]["event_id"], 4625)
        with patch("modules.connectors.live.bridge_request", return_value={"tenant_id": OTHER}):
            with self.assertRaises(PermissionError):
                pipeline_test()

    def test_remediation_is_admin_only_and_disabled_by_default(self):
        for role in ["Read-Only Auditor", "SOC Analyst"]:
            bind(Principal("actor", TENANT, role, MagicMock()))
            with self.assertRaises(PermissionError):
                respond_to_incident(1, "both")
        bind(Principal("actor", TENANT, "Admin", MagicMock()))
        with patch("modules.remediation.config.ENABLE_REAL_REMEDIATION", False), patch("modules.remediation.GraphClient") as graph:
            with self.assertRaises(RuntimeError):
                respond_to_incident(1, "both")
            graph.assert_not_called()

    def test_confirmed_graph_actions_update_only_selected_tenant_incident(self):
        client = MagicMock()
        query = client.table.return_value
        for method in ["select", "eq", "update", "insert"]:
            getattr(query, method).return_value = query
        query.execute.return_value.data = [{"id": 7, "TargetUserName": "target@example.test"}]
        bind(Principal("actor", TENANT, "Admin", client))
        graph = MagicMock()
        graph.resolve.side_effect = [{"id": "target"}, {"id": "protected"}]
        graph.request.side_effect = [{"value": True}, {}]
        graph.last_status = 200
        with patch("modules.remediation.config.ENABLE_REAL_REMEDIATION", True), patch("modules.remediation.secrets", return_value={"protected_accounts": ["emergency@example.test"]}), patch("modules.remediation.GraphClient", return_value=graph):
            responses = respond_to_incident(7, "both")
        self.assertEqual(len(responses), 2)
        self.assertTrue(all(call.args[1] == TENANT for call in query.eq.call_args_list if call.args[0] == "tenant_id"))
        self.assertEqual(query.update.call_args.args[0]["action_taken"], "Session Revoked & Account Blocked")
        self.assertEqual(graph.request.call_args_list[1].args, ("PATCH", "users/target", {"accountEnabled": False}))
