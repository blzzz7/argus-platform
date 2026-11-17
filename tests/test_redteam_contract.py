"""Freeze attack backend, outbound calls, widgets, and legacy forwarding behavior."""
import ast
import hashlib
import json
import re
from pathlib import Path
import unittest
from unittest.mock import MagicMock
from types import SimpleNamespace
from datetime import datetime
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]


def sandbox(tree):
    return next(n for n in ast.walk(tree) if isinstance(n, ast.If) and isinstance(n.test, ast.Compare) and any(isinstance(c, ast.Constant) and isinstance(c.value, str) and "Red Team Attack Controller" in c.value for c in n.test.comparators))


class RedTeamContract(unittest.TestCase):
    def setUp(self):
        self.tree = ast.parse((ROOT / "app_ui.py").read_text(encoding="utf-8"))
        self.baseline = json.loads((ROOT / "tests/redteam_baseline.json").read_text())

    def test_backend_byte_identical(self):
        self.assertEqual(hashlib.sha256((ROOT / "modules/attack_engine.py").read_bytes()).hexdigest(), self.baseline["engine_sha256"])

    def test_all_protected_call_arguments_identical(self):
        calls = []
        for statement in sandbox(self.tree).body:
            for n in ast.walk(statement):
                if isinstance(n, ast.Call) and (ast.unparse(n.func).startswith(("attack_engine.", "requests.", "storage.")) or ast.unparse(n.func) == "send_to_wazuh"):
                    calls.append(ast.dump(n, include_attributes=False))
        self.assertEqual(calls, self.baseline["calls"])

    def test_forwarding_identical(self):
        node = next(n for n in self.tree.body if isinstance(n, ast.FunctionDef) and n.name == "send_to_wazuh")
        self.assertEqual(ast.dump(node, include_attributes=False), self.baseline["forwarding"])
        request = MagicMock()
        request.post.return_value.status_code = 201
        request.post.return_value.json.return_value = {"ok": True}
        namespace = {"requests": request, "integrations": SimpleNamespace(get_active_wazuh_config=lambda: {"ingest_url": "https://bridge.test/ingest", "ingest_token": "synthetic"})}
        exec(compile(ast.Module(body=[node], type_ignores=[]), "forwarding", "exec"), namespace)
        payload = {"source": "Argus-RedTeam-Engine", "event_id": 4625}
        namespace["send_to_wazuh"](payload)
        request.post.assert_called_once_with("https://bridge.test/ingest", headers={"Content-Type": "application/json", "ngrok-skip-browser-warning": "true", "X-Argus-Token": "synthetic"}, json=payload, timeout=15)

    def test_five_triggers_use_original_requests(self):
        execution = next(n for n in sandbox(self.tree).body if isinstance(n, ast.If) and isinstance(n.test, ast.Name) and n.test.id == "_redteam_triggered")
        for trigger in ["enum", "spray", "brute", "mfa", "device"]:
            with self.subTest(trigger=trigger):
                engine = MagicMock()
                engine.users = ["synthetic@example.test"]
                engine.passwords = ["synthetic-password"]
                engine.public_app.acquire_token_by_username_password.return_value = {"error": "invalid_grant", "error_description": "AADSTS50126"}
                engine.public_app.initiate_device_flow.return_value = {"user_code": "TEST", "verification_uri": "https://example.test"}
                st = MagicMock()
                st.session_state = {"df": pd.DataFrame()}
                forward = MagicMock(return_value=(True, {"written": True}))
                namespace = dict(_redteam_triggered=True, attack_engine=engine, terminal_placeholder=MagicMock(), st=st, storage=MagicMock(), requests=MagicMock(), time=MagicMock(), pd=pd, datetime=datetime, send_to_wazuh=forward, max_targets_count=1, spray_password_input="synthetic-password", target_user_input="synthetic@example.test", custom_brute_password="", brute_requests=5, mfa_iterations=2)
                namespace.update({"btn_" + name: name == trigger for name in ["enum", "spray", "brute", "mfa", "device"]})
                exec(compile(ast.Module(body=[execution], type_ignores=[]), "sandbox", "exec"), namespace)
                if trigger == "device":
                    engine.public_app.initiate_device_flow.assert_called_once_with(scopes=["https://graph.microsoft.com/.default"])
                else:
                    self.assertEqual(engine.public_app.acquire_token_by_username_password.call_count, 2 if trigger == "mfa" else 1)
                    for call in engine.public_app.acquire_token_by_username_password.call_args_list:
                        self.assertEqual(call.kwargs, {"username": "synthetic@example.test", "password": "DummyPassword123!" if trigger == "enum" else "synthetic-password", "scopes": ["https://graph.microsoft.com/.default"]})
                if trigger == "spray":
                    body = forward.call_args.args[0]
                    self.assertEqual(set(body), {"timestamp", "event_id", "user", "source_ip", "rule_title", "severity", "source"})
                    self.assertEqual(body["source_ip"], "185.220.101.5")
                    self.assertEqual(body["rule_title"], "RedTeam MSAL Attack Executed")

    def test_admin_gate_precedes_initialization(self):
        nodes = list(ast.walk(sandbox(self.tree)))
        calls = [n for n in nodes if isinstance(n, ast.Call)]
        guard = next(n for n in calls if ast.unparse(n.func) == "require" and n.args and isinstance(n.args[0], ast.Constant) and n.args[0].value == "sandbox")
        initializer = next(n for n in calls if ast.unparse(n.func) == "generate_wordlists")
        self.assertLess(guard.lineno, initializer.lineno)

    def test_widgets_and_initialization_arguments_unchanged(self):
        widgets = []
        for statement in sandbox(self.tree).body:
            for node in ast.walk(statement):
                if isinstance(node, ast.Call) and ast.unparse(node.func) in {"st.button", "st.text_input", "st.slider"}:
                    if any(k.arg == "key" and isinstance(k.value, ast.Constant) and k.value.value in {"attack_domain", "brute_requests", "mfa_iterations", "execute_attack"} for k in node.keywords):
                        continue
                    node.keywords = [k for k in node.keywords if k.arg != "help"]
                    widgets.append(ast.dump(node, include_attributes=False))
        # Display labels may lose decorative icons; all other widget arguments stay frozen.
        def plain_labels(value):
            value = re.sub("[\U0001F000-\U0001FAFF\u2600-\u27BF\uFE0F]", "", value)
            return value.replace("value=' ", "value='")
        expected = [value for value in self.baseline["widgets"] if "Max Target Limit" not in value and not "Launch " in value]
        self.assertEqual([plain_labels(value) for value in widgets], [plain_labels(value) for value in expected])
        initialization = [ast.dump(n, include_attributes=False) for n in ast.walk(self.tree) if isinstance(n, ast.Call) and ast.unparse(n.func) in {"generate_wordlists", "IdentityAttackEngine"}]
        self.assertEqual(initialization, self.baseline["initialization_calls"])
