"""Target completion uses mocked discovery and never sends authentication requests."""
import ast
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from modules.redteam_targets import controller_targets


class ControllerTargets(unittest.TestCase):
    def targets(self, existing, discovery, result=(True, [])):
        fetch = Mock(return_value=result)
        backend = SimpleNamespace(DOMAIN="example.test", fetch_tenant_users_from_graph=fetch)
        with patch.dict(sys.modules, {"modules.attack_engine": backend}):
            users = controller_targets(existing, discovery)
        return users, fetch

    def test_keeps_user13_and_every_synthetic_target(self):
        real = [f"user{i}@example.test" for i in range(1, 61)]
        users, fetch = self.targets(real, {"graph_fetch_ok": True, "real_user_count": 60})
        self.assertTrue(set(real).issubset(users))
        self.assertIn("victimuser@example.onmicrosoft.com", users)
        self.assertTrue(all(f"fake_user_{i}@example.test" in users for i in range(1, 100)))
        fetch.assert_not_called()

    def test_expands_graph_cap_and_preserves_existing_targets(self):
        real = [f"user{i}@example.test" for i in range(1, 1002)]
        users, fetch = self.targets([real[0], "corp_admin_1@example.test"],
                                    {"graph_fetch_ok": True, "real_user_count": 200}, (True, real))
        self.assertTrue(set(real).issubset(users))
        self.assertIn("corp_admin_1@example.test", users)
        self.assertEqual(len(users), len(set(users)))
        fetch.assert_called_once_with(max_users=sys.maxsize)

    def test_failed_complete_discovery_prevents_partial_execution(self):
        with self.assertRaisesRegex(RuntimeError, "Complete Graph target discovery failed"):
            self.targets([], {"graph_fetch_ok": True, "real_user_count": 200}, (False, "offline"))

    def test_limit_defaults_to_live_graph_count(self):
        tree = ast.parse((Path(__file__).resolve().parents[1] / "app_ui.py").read_text(encoding="utf-8"))
        widget = next(n for n in ast.walk(tree) if isinstance(n, ast.Call)
                      and ast.unparse(n.func) == "st.number_input" and n.args
                      and isinstance(n.args[0], ast.Constant) and n.args[0].value == "Max Target Limit")
        keywords = {k.arg: ast.unparse(k.value) for k in widget.keywords}
        self.assertEqual(keywords["value"], "default_target_limit")
        self.assertEqual(keywords["max_value"], "available_targets")

    def test_single_execution_button_and_live_default(self):
        tree = ast.parse((Path(__file__).resolve().parents[1] / "app_ui.py").read_text(encoding="utf-8"))
        labels = [n.args[0].value for n in ast.walk(tree) if isinstance(n, ast.Call) and ast.unparse(n.func) == "st.button" and n.args and isinstance(n.args[0], ast.Constant)]
        self.assertEqual(labels.count("Execute Selected Attack"), 1)
        self.assertFalse(any(label.startswith("Launch ") for label in labels))
        assignment = next(n for n in ast.walk(tree) if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "default_target_limit" for t in n.targets))
        for discovery, expected in [({"graph_fetch_ok": True, "real_user_count": 15}, 15), ({"graph_fetch_ok": False, "real_user_count": 15}, 163), ({"graph_fetch_ok": True, "real_user_count": 200}, 163)]:
            result = eval(compile(ast.Expression(assignment.value), "default_limit", "eval"), {"wordlist_info": discovery, "available_targets": 163})
            self.assertEqual(result, expected)
