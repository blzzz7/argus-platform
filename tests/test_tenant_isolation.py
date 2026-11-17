import unittest
from unittest.mock import MagicMock
import pandas as pd
from modules.authorization import Principal, bind
from modules import storage


class TenantTests(unittest.TestCase):
    def tearDown(self):
        bind(None)

    def test_writes_override_forged_tenant(self):
        client = MagicMock()
        bind(Principal("user", "trusted", "SOC Analyst", client))
        storage.append_events(pd.DataFrame([{"tenant_id": "forged", "EventID": 4625}]))
        record = client.table.return_value.insert.call_args.args[0][0]
        self.assertEqual(record["tenant_id"], "trusted")

    def test_admin_delete_is_tenant_scoped(self):
        client = MagicMock()
        bind(Principal("user", "trusted", "Admin", client))
        storage.clear_events()
        client.table.return_value.delete.return_value.eq.assert_called_once_with("tenant_id", "trusted")

    def test_auditor_write_is_rejected_before_insert(self):
        client = MagicMock()
        bind(Principal("user", "trusted", "Read-Only Auditor", client))
        with self.assertRaises(RuntimeError):
            storage.append_events(pd.DataFrame([{"EventID": 4625}]))
        client.table.return_value.insert.assert_not_called()
