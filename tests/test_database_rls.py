"""Optional real PostgreSQL policy checks; requires a disposable Docker container.

Run with ARGUS_TEST_POSTGRES_CONTAINER=argus-v2-verification-postgres.
This suite creates and drops only argus_verification and argus_legacy_verification.
Supabase JWT functions are emulated; hosted Auth/MFA still require staging checks.
"""
import json
import os
from pathlib import Path
import subprocess
import unittest

CONTAINER = os.getenv("ARGUS_TEST_POSTGRES_CONTAINER", "")
ROOT = Path(__file__).resolve().parents[1]
TENANT_A = "00000000-0000-0000-0000-000000000001"
TENANT_B = "00000000-0000-0000-0000-000000000002"
ADMIN_A = "10000000-0000-0000-0000-000000000001"
ANALYST_A = "10000000-0000-0000-0000-000000000002"
AUDITOR_A = "10000000-0000-0000-0000-000000000003"
ADMIN_B = "20000000-0000-0000-0000-000000000001"


@unittest.skipUnless(CONTAINER == "argus-v2-verification-postgres", "Disposable PostgreSQL test container not selected")
class DatabaseRLS(unittest.TestCase):
    @classmethod
    def sql(cls, text, database="argus_verification", ok=True):
        result = subprocess.run(["docker", "exec", "-i", CONTAINER, "psql", "-U", "postgres", "-d", database, "-v", "ON_ERROR_STOP=1", "-At"], input=text, text=True, encoding="utf-8", capture_output=True)
        if ok and result.returncode:
            raise AssertionError(result.stderr)
        return result

    @classmethod
    def setUpClass(cls):
        cls.sql("DROP DATABASE IF EXISTS argus_verification; CREATE DATABASE argus_verification;", "postgres")
        cls.sql("""
DO $$ BEGIN CREATE ROLE authenticated; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE anon; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
CREATE SCHEMA auth;
CREATE TABLE auth.users(id uuid primary key, raw_user_meta_data jsonb default '{}'::jsonb);
CREATE FUNCTION auth.jwt() RETURNS jsonb LANGUAGE sql STABLE AS $$ SELECT coalesce(nullif(current_setting('request.jwt.claims',true),'')::jsonb,'{}'::jsonb) $$;
CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS $$ SELECT (auth.jwt()->>'sub')::uuid $$;
GRANT USAGE ON SCHEMA auth TO authenticated,anon;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA auth TO authenticated,anon;
""")
        cls.sql((ROOT / "supabase/schema.sql").read_text(encoding="utf-8"))
        cls.sql(f"""
INSERT INTO public.tenants VALUES ('{TENANT_A}','Tenant A'),('{TENANT_B}','Tenant B');
INSERT INTO auth.users(id) VALUES ('{ADMIN_A}'),('{ANALYST_A}'),('{AUDITOR_A}'),('{ADMIN_B}');
INSERT INTO public.tenant_memberships VALUES
 ('{TENANT_A}','{ADMIN_A}','Admin'),('{TENANT_A}','{ANALYST_A}','SOC Analyst'),
 ('{TENANT_A}','{AUDITOR_A}','Read-Only Auditor'),('{TENANT_B}','{ADMIN_B}','Admin');
INSERT INTO public.events(tenant_id,"EventID","TargetUserName") VALUES
 ('{TENANT_A}','4625','a@example.test'),('{TENANT_B}','4625','b@example.test');
INSERT INTO public.integrations(tenant_id,id,name,config) VALUES
 ('{TENANT_A}','wazuh','Wazuh','{{}}'),('{TENANT_B}','wazuh','Wazuh','{{}}');
""")

    @classmethod
    def tearDownClass(cls):
        cls.sql("DROP DATABASE IF EXISTS argus_verification;", "postgres")

    def as_user(self, user, query, aal="aal2", ok=True):
        claims = json.dumps({"sub": user, "aal": aal})
        return self.sql(f"SET ROLE authenticated; SET request.jwt.claims='{claims}'; {query}", ok=ok)

    def test_cross_tenant_reads_and_writes(self):
        result = self.as_user(ADMIN_A, 'SELECT "TargetUserName" FROM public.events;')
        self.assertIn("a@example.test", result.stdout)
        self.assertNotIn("b@example.test", result.stdout)
        result = self.as_user(ADMIN_A, f"INSERT INTO public.events(tenant_id) VALUES('{TENANT_B}');", ok=False)
        self.assertNotEqual(result.returncode, 0)

    def test_auditor_cannot_insert_or_delete(self):
        result = self.as_user(AUDITOR_A, f"INSERT INTO public.events(tenant_id) VALUES('{TENANT_A}');", ok=False)
        self.assertNotEqual(result.returncode, 0)
        result = self.as_user(AUDITOR_A, "DELETE FROM public.events; SELECT count(*) FROM public.events;")
        self.assertIn("DELETE 0", result.stdout)
        self.assertGreaterEqual(int(result.stdout.rstrip().splitlines()[-1]), 1)

    def test_analyst_can_ingest_but_cannot_read_connector_secrets(self):
        self.as_user(ANALYST_A, f"INSERT INTO public.events(tenant_id) VALUES('{TENANT_A}');")
        result = self.as_user(ANALYST_A, "SELECT count(*) FROM public.integrations;")
        self.assertTrue(result.stdout.rstrip().endswith("0"))

    def test_mfa_and_membership_revocation(self):
        result = self.as_user(ADMIN_B, "SELECT count(*) FROM public.events;", aal="aal1")
        self.assertTrue(result.stdout.rstrip().endswith("0"))
        self.sql(f"DELETE FROM public.tenant_memberships WHERE user_id='{ADMIN_B}';")
        result = self.as_user(ADMIN_B, "SELECT count(*) FROM public.events;")
        self.assertTrue(result.stdout.rstrip().endswith("0"))
        self.sql(f"INSERT INTO public.tenant_memberships VALUES('{TENANT_B}','{ADMIN_B}','Admin');")

    def test_duplicate_identity_keys_are_tenant_local(self):
        for tenant, user in [(TENANT_A, ADMIN_A), (TENANT_B, ADMIN_B)]:
            self.as_user(user, f"INSERT INTO public.resolved_users(tenant_id,username) VALUES('{tenant}','shared@example.test');")

    def test_forged_audit_actor_rejected(self):
        result = self.as_user(ADMIN_A, f"INSERT INTO public.audit_events(tenant_id,actor_id,action) VALUES('{TENANT_A}','{ADMIN_B}','FORGED');", ok=False)
        self.assertNotEqual(result.returncode, 0)

    def test_migration_reruns(self):
        self.sql((ROOT / "supabase/migrations/002_tenant_isolation.sql").read_text(encoding="utf-8"))

    def test_legacy_migration_backfills_default_and_preserves_ownership(self):
        database = "argus_legacy_verification"
        self.sql(f"DROP DATABASE IF EXISTS {database}; CREATE DATABASE {database};", "postgres")
        try:
            self.sql("""
CREATE SCHEMA auth;
CREATE TABLE auth.users(id uuid primary key, raw_user_meta_data jsonb default '{}'::jsonb);
CREATE FUNCTION auth.jwt() RETURNS jsonb LANGUAGE sql STABLE AS $$ SELECT '{}'::jsonb $$;
CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS $$ SELECT NULL::uuid $$;
""", database)
            schema = (ROOT / "supabase/schema.sql").read_text(encoding="utf-8")
            self.sql(schema.split("-- v2 tenant isolation.")[0], database)
            self.sql('INSERT INTO public.events("EventID") VALUES(\'4625\');', database)
            self.sql("INSERT INTO public.resolved_users(username) VALUES ('legacy@example.test'); INSERT INTO public.integrations(id,name) VALUES ('wazuh','Wazuh');", database)
            migration = (ROOT / "supabase/migrations/002_tenant_isolation.sql").read_text(encoding="utf-8")
            self.sql(migration, database)
            default = "a41233e6-85f1-43f5-8b4c-3a368df76665"
            self.assertEqual(self.sql("SELECT tenant_id FROM public.events;", database).stdout.strip(), default)
            self.sql(f"SET argus.legacy_tenant_id='{TENANT_A}';\n" + migration, database)
            self.assertEqual(self.sql("SELECT tenant_id FROM public.events;", database).stdout.strip(), default)
            workspace = (ROOT / "supabase/migrations/003_live_workspace.sql").read_text(encoding="utf-8")
            self.sql(workspace, database)
            self.sql(workspace, database)
            for table in ("events", "resolved_users", "integrations"):
                self.assertEqual(self.sql(f"SELECT tenant_id FROM public.{table};", database).stdout.strip(), default)
        finally:
            self.sql(f"DROP DATABASE IF EXISTS {database};", "postgres")

    def test_only_one_running_response_per_tenant(self):
        self.as_user(ADMIN_A, f"INSERT INTO public.playbook_runs(id,tenant_id,status) VALUES('30000000-0000-0000-0000-000000000001','{TENANT_A}','RUNNING');")
        result = self.as_user(ADMIN_A, f"INSERT INTO public.playbook_runs(id,tenant_id,status) VALUES('30000000-0000-0000-0000-000000000002','{TENANT_A}','RUNNING');", ok=False)
        self.assertNotEqual(result.returncode, 0)
        self.as_user(ADMIN_A, "UPDATE public.playbook_runs SET status='SUCCEEDED';")
