# Argus ITDR v2

Enterprise Microsoft Entra ID investigation and response workspace built with Streamlit, Supabase, Wazuh, Groq/OpenAI-compatible AI, and Microsoft Graph.

## Architecture

- `app_ui.py`: English SOC workflows, role-aware navigation, sign-in/MFA, response previews, tenant-scoped reports.
- `modules/auth.py`, `authorization.py`: Supabase Auth sessions, verified membership, Admin / SOC Analyst / Read-Only Auditor permissions.
- `modules/db.py`, `storage.py`, `integrations.py`: user-scoped Supabase access, tenant constraints, encrypted connector settings.
- `modules/connectors/`: Wazuh bridge, Splunk HEC, Sentinel DCR ingestion and legacy workspace adapters.
- `modules/ai_generator.py`: existing AI/Sigma services plus validated severity recommendations.
- `modules/remediation.py`, `graph_client.py`, `notifications.py`: explicit Admin-approved response execution, Graph operations, SOC alerts, persistent step history.
- `receiver.py`: token-bound ingestion and audit proxy; separate `/forward/<provider>` adapter endpoint. `/ingest` preserves the legacy JSON body and successful response contract.
- `modules/attack_engine.py`: unchanged. Its UI initializes only inside the authorized Admin sandbox.

## Install and run

Use a virtual environment and install `requirements.txt`. The bridge now includes Flask as a declared dependency.

```powershell
python -m venv .venv
.venv/Scripts/Activate.ps1
python -m pip install -r requirements.txt
streamlit run app_ui.py --theme.base=dark
```

Set deployment environment variables explicitly. Never commit `.env`, credentials, tokens, or telemetry. The existing environment provider wiring remains supported. The application requires `SUPABASE_URL` and `SUPABASE_ANON_KEY` (publishable/anon key). Supabase Auth uses a publishable/anon key and user JWT. Local Admin sessions use a separate server-side `SUPABASE_URL` / `SUPABASE_KEY` client; never expose its key in browser controls.

## Database migration

Take a database backup and stop application writers before migration. Apply `supabase/schema.sql` for a new database. For an existing database, apply `supabase/migrations/002_tenant_isolation.sql`, then `003_live_workspace.sql`, in a maintenance session.

For existing data, explicitly choose its owner before applying the migration in that same SQL connection:

```sql
SET argus.legacy_tenant_id = '<existing-data-owner-UUID>';
-- Then execute 002_tenant_isolation.sql in this connection.
```

The migration creates this explicitly selected legacy tenant, backfills existing rows, enforces non-null foreign keys, and changes resolved-user and integration keys to tenant composites. Without an explicit setting, unassigned rows use the default workspace. Rows already assigned to tenants retain their ownership. Do not assign data from multiple organizations to one tenant; classify that data before migration.

Create Supabase Auth users, then provision memberships through trusted database administration:

```sql
INSERT INTO public.tenants(id,name) VALUES ('<tenant-UUID>','Organization');
INSERT INTO public.tenant_memberships(tenant_id,user_id,role)
VALUES ('<tenant-UUID>','<Supabase-Auth-user-UUID>','Admin');
```

Allowed roles are exactly `Admin`, `SOC Analyst`, and `Read-Only Auditor`. Membership changes are not exposed as self-service client writes. Database policies require authenticated tenant membership, enforce MFA by default, hide connector credentials from non-Admins, and prevent forged audit actors.

Rollback requires stopping writers and restoring the pre-migration backup together with the matching application version. Do not remove tenant columns from a populated multi-tenant database or deploy the old global client against v2 data. Reconcile any writes after the backup before a restore. Database transactions roll back a failed migration; external Graph changes never roll back automatically.

## Identity and RBAC

Production MFA is on by default (`AUTH_REQUIRE_MFA=true`), with TOTP enrollment and verification at sign-in. Supabase Auth supplies password hashing, token verification, refresh, and provider-side rate limiting. Enable provider abuse protection and disable unapproved public signup in your Auth project. App-local lockout is supplemental, not a distributed rate limiter.

Sessions expire after `AUTH_MAX_SESSION_SECONDS` (default 28800). Logout clears tenant data and invalidates the provider session. Changing tenant or identity clears cached telemetry, chat, response approvals, and connector form values without renaming the established session-state keys.

For isolated development only, disabling MFA requires BOTH `AUTH_REQUIRE_MFA=false` and changing `public.argus_settings` key `require_mfa` to JSON `false`. Do not disable it in production.

| Capability | Admin | SOC Analyst | Read-Only Auditor |
|---|---|---|---|
| View tenant data and export reports | Yes | Yes | Yes |
| Ingest, AI/Sigma, dispatch telemetry | Yes | Yes | No |
| Execute response playbooks, clear telemetry | Yes | No | No |
| Configure integrations | Yes | No | No |
| Authorized sandbox | Yes | No | No |

Anonymous users can browse route previews. Tenant data and outbound actions require sign-in and appropriate permissions.

## Tenant secrets and SIEM setup

Generate a Fernet key using `cryptography.fernet.Fernet.generate_key()` and store it in `ARGUS_CONFIG_ENCRYPTION_KEY`. New integration saves encrypt configuration before Supabase persistence. Retain the key securely; losing it makes encrypted settings unreadable. Existing plaintext settings remain readable during migration: re-save every legacy integration, verify its encrypted database representation, and rotate old credentials. Never publish decrypted forms or exports.

`ARGUS_LEGACY_TENANT_ID` binds existing environment Wazuh settings to one application tenant. Other tenants need dedicated credentials and destinations. `ARGUS_TENANT_SECRETS_JSON` is server-only JSON keyed by application tenant UUID. A tenant entry may include:

- `wazuh`: `ingest_url`, `ingest_token`, `index` for tenant forwarding/audit access.
- Graph response settings: `entra_tenant_id`, `client_id`, `client_secret`, `protected_accounts`, `protected_networks`, `block_location_id`, `block_policy_id`, `soc_webhook_url`.

These application tenant UUIDs are distinct from Entra directory IDs. Local Admin sessions may use configured environment Graph credentials; unrelated tenant sessions cannot inherit them.

Integration administrators may save provider settings through existing forms or advanced JSON. Splunk supports `url`/`token` and the existing `endpoint_url`/`hec_token` form keys, plus optional `index`. Sentinel DCR settings are `endpoint`, `dcr_id`, `stream`, `entra_tenant_id`, `client_id`, `client_secret`. Legacy Sentinel settings remain `workspace_id`, `shared_key`, `log_type`. Wazuh uses `ingest_url`, `ingest_token`. HTTPS certificate verification is required for new adapters; redirects are not followed. Delivery failures are not automatically replayed because ambiguous upstream timeouts can mean the event was already accepted. Review delivery records before resubmitting.

The Admin Integrations screen provides dispatch through all three adapters. Analyst Wazuh forwarding uses tenant-bound server configuration; connector secrets remain unavailable to analyst database clients.

## Receiver deployment

Run the bridge behind a production WSGI server and TLS reverse proxy. `python receiver.py` uses Flask's development server for local checks only. Configure request limits, rate limits, logging, log retention/rotation, and network restrictions at deployment.

The bridge fails closed when no credential is configured. Legacy `X-Argus-Token` requests retain their body and forwarding parameters; set both `ARGUS_INGEST_TOKEN` and `ARGUS_LEGACY_TENANT_ID`. Additional credentials use `ARGUS_BRIDGE_KEYS_JSON`, mapping SHA-256 token hex digests to objects containing `tenant_id` and `index`.

Additional tenant logs are written under `<ARGUS_LOG_DIR>/<tenant UUID>/<ARGUS_LOG_FILENAME>`. Preserve the legacy log path for the assigned legacy credential. Configure Wazuh collection/routing for these paths and use an exclusive audit index or exclusive index pattern for EACH tenant. Never assign a shared cross-tenant index pattern to a bridge credential. Token-selected index authorization cannot repair an incorrectly shared upstream index.

`POST /search` rejects a requested index different from the credential assignment and bounds supported queries. `POST /forward/wazuh`, `/forward/splunk`, and `/forward/sentinel` use server-side `ARGUS_BRIDGE_CONNECTORS_JSON`, keyed by application tenant UUID then provider. The original `/ingest` never silently fans Red Team events out to new providers. Protect these machine credentials; they authorize ingestion, search, and configured forwarding for their tenant.

`GET /health` reports liveness without exposing internal connection targets. Configure Wazuh TLS trust; `WAZUH_VERIFY_SSL` defaults to true.

## Admin-approved response playbooks

| Severity | Plan |
|---|---|
| Low | Record only |
| Medium | Revoke sign-in sessions |
| High | Revoke sessions, disable account |
| Critical | Revoke sessions, disable account, add IP to blocking Named Location, notify SOC |

AI recommends severity and English rationale; it never authorizes or executes operations. An Admin reviews the displayed tier and approves execution. The selected tier is explicit; recommendations do not silently change it.

Keep `ENABLE_REAL_REMEDIATION=false` during routine development. Simulation acquires no Graph token and performs no Graph writes or SOC webhook calls. Simulated and Low-tier executions do not mark an account remediated.

Real responses require tenant-specific credentials, required Graph application permissions and tenant admin consent. Critical responses require an existing enabled Conditional Access policy referencing the configured non-trusted Named Location with a block grant. Provision, test, and scope that policy deliberately; adding an IP to a Named Location alone does not guarantee access is blocked. Configure protected emergency accounts and networks. Targets and emergency accounts resolve to Graph object IDs before mutations, so aliases cannot bypass protection. Critical preflight checks validate the IP and policy before starting Graph writes.

Step intent and outcomes persist around each action. An uncertain last action is recorded as UNKNOWN, not silently replayed. A failed step stops later steps; earlier real actions remain in effect. A unique run ID prevents replay of the same request, and only one running playbook is permitted per tenant. A process interruption can leave RUNNING state. An administrator must reconcile Graph state and audit the recovery before clearing that run through trusted database administration. Never blindly replay or automatically re-enable accounts. Session revocation cannot be undone; IP removal and account re-enablement require separate, reviewed recovery actions.

The Slack/Teams webhook adapter sends a `text` message to the configured HTTPS endpoint. Configure the receiving Slack incoming webhook or Teams workflow to accept that schema. Test delivery separately before enabling Critical response.

## Sandbox preservation

`ARGUS_SANDBOX_TENANT_ID` is the application tenant UUID authorized to access the sandbox. Existing `ARGUS_TENANT_ID`, `ARGUS_CLIENT_ID`, `ARGUS_CLIENT_SECRET`, target selection, wordlists, OAuth calls, payloads, and Wazuh forwarding stay intact. Sandbox initialization runs only after verified Admin access to this application tenant. Authentication simulations still issue real requests to the configured test directory. Run them only with explicit authorization.

## Verification

```powershell
python -m pip install pytest
python -m pytest -q
python -m unittest discover -s tests -v
python -m compileall app_ui.py receiver.py modules tests
```

`tests/redteam_baseline.json` freezes attack backend bytes, request arguments, and forwarding behavior. Tests execute all five triggers with mocks, never against Entra ID. Other tests cover service RBAC, tenant context, simulation, partial failures, protected targets, bridge responses, and adapter contracts.

Optional real PostgreSQL policy tests use a disposable container, without published ports:

```powershell
docker run --detach --rm --name argus-v2-verification-postgres -e POSTGRES_PASSWORD=synthetic-test-only postgres:17-alpine
$env:ARGUS_TEST_POSTGRES_CONTAINER='argus-v2-verification-postgres'
python -m unittest tests.test_database_rls -v
docker stop argus-v2-verification-postgres
```

These tests emulate Supabase JWT helper functions on PostgreSQL. Before production, verify hosted Supabase Auth/MFA, two-tenant RLS access, real connector delivery, approved Graph permissions, Conditional Access scope, webhook schema, backups, and deployment controls in an authorized staging environment. Synthetic browser inspection does not establish production readiness or external service availability.

## Repository hygiene

Only application source, migrations, tests, public documentation, and empty configuration templates belong in version control. Local agent instructions, design reviews, credentials, telemetry, generated wordlists, and caches are ignored. Removing a file from current branches does not remove it from Git history. Rotate any credentials previously published.

## Credits

Original Argus ITDR authors: Rasul Kazimov, Huseyn Huseynov, Aydin Erebov, and Ferid Abdullayev.

Phase 2 live integration setup:

- Existing databases: apply `supabase/migrations/003_live_workspace.sql` after migration 002. Fresh databases: use `supabase/schema.sql`, which includes both migrations. The signup trigger atomically creates an organization and its Admin membership; it does not grant users access to existing organizations. Email confirmation and configured MFA still apply.
- Configure `SUPABASE_URL` and `SUPABASE_ANON_KEY` for user-scoped RLS access. Do not use a service-role key for user queries.
- Local development: set `ADMIN_USER` and `ADMIN_PASS` in `.env` or Streamlit secrets. Existing `ARGUS_ADMIN_USER` / `ARGUS_ADMIN_HASH` also work. Local Admin access opens an isolated workspace without Supabase email confirmation; persistent telemetry requires the configured server-side Supabase client. Restrict local Admin credentials and database keys to trusted operators.
- Set `GROQ_API_KEY` and optionally `GROQ_MODEL` (default `llama-3.3-70b-versatile`). Chat uses the latest 20 tenant records. Reports use full-period aggregates plus a bounded evidence sample. ReportLab is already listed in `requirements.txt`.
- Assign tenant response credentials through `ARGUS_TENANT_SECRETS_JSON`. Example structure with placeholders: `{"<application-tenant-uuid>": {"entra_tenant_id": "<Entra-tenant-uuid>", "client_id": "<client-uuid>", "client_secret": "<secret>", "protected_accounts": ["emergency@example.com"], "wazuh": {"ingest_url": "https://bridge.example.com/ingest", "ingest_token": "<tenant-token>"}}}`. These are operational credentials, separate from the unchanged sandbox attack engine configuration.
- In the bridge environment, assign each SHA-256 token hash in `ARGUS_BRIDGE_KEYS_JSON` to `{"tenant_id":"<application-tenant-uuid>","index":"<tenant-exclusive-index>"}`. Ensure Wazuh tails each tenant's `ARGUS_LOG_DIR/<tenant_id>/itdr-events.json` and routes it to that exclusive index. Index separation is required; never assign multiple tenants the same index. Existing legacy token deployments require `ARGUS_LEGACY_TENANT_ID`.
- `/health` without valid credentials reports process liveness only. Authenticated requests verify access to the assigned Wazuh index. Both `Authorization: Bearer ...` and existing `X-Argus-Token` remain supported. `/audit-read?event_uuid=...` verifies test-alert indexing. Delivery to the log file alone is not reported as indexing success; delayed indexing produces an unconfirmed result.
- Tenant SIEM credentials can also be saved through Integrations. Set `ARGUS_CONFIG_ENCRYPTION_KEY` to a Fernet key for encrypted storage. Splunk and Sentinel remain available.
- Keep `ENABLE_REAL_REMEDIATION=false` during routine development. Real responses require an Admin, explicit approval, tenant Graph credentials, Graph application permissions, and protected emergency accounts. Only confirmed responses update incident remediation status.
- Detection evaluates real 4625 events from the latest five minutes. CSV `timestamp`, `Timestamp`, or `created_at` values are preserved on ingestion. Legacy records use their stored ingestion timestamp. A repeated-user threshold is labeled Brute Force; password spray requires cross-account evidence.

Verification: `python -m compileall app_ui.py receiver.py modules` and `python -m unittest discover -s tests -v`. Database RLS tests additionally require the disposable database configured by the test suite.

## Threat Response & AI Center

The center replaces AI Threat Analysis & Auto-Fix, Interactive Analytics, and Threat Detection Engine. Legacy navigation state and `?route=` links map to the center. Alerts group accounts with High/Critical events, more than five failures in a rolling five-minute window, or a success following at least three consecutive recorded failures. The latter is a historical sequence signal without a fixed time limit, not proof of compromise. Counts cover the loaded tenant records.

Analysts and Admins can generate account-bound Sigma YAML and structured proposed action outcomes through the tenant AI provider. Sigma is parsed with pySigma; Wazuh deployment requires a Sigma-compatible backend and field mapping, not direct XML rule upload. Admins authorize session revocation and account disable by clicking the direct action button. A read-only preflight disables it for protected accounts or missing configuration; the response service repeats protection checks before mutation. Protected-account checks and tenant-scoped incident/audit writes remain enforced. Changing the selected account clears AI output and response results. Alerts are displayed as a vertical radio list.
