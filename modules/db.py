"""User-scoped Supabase access. No shared authenticated clients or RLS bypass."""
from modules.authorization import current
from modules import config


def get_client():
    return current().client


def is_configured():
    return bool(config.SUPABASE_URL and config.SUPABASE_ANON_KEY)


def containment_audit(limit=None):
    principal = current()
    rows = []
    while True:
        size = 1000 if limit is None else min(1000, limit - len(rows))
        page = (principal.client.table("audit_events").select("id,created_at,actor_id,action,detail")
                .eq("tenant_id", principal.tenant_id)
                .in_("action", ["INCIDENT_RESPONSE", "PLAYBOOK_SUCCEEDED", "CONTAINMENT_PREVIEW"])
                .order("created_at", desc=True).order("id", desc=True)
                .range(len(rows), len(rows) + size - 1).execute().data or [])
        rows.extend(page)
        if len(page) < size or len(rows) == limit:
            return rows


def contained_accounts(records):
    users = {str(row["id"]): row.get("TargetUserName") for row in records if row.get("id") is not None}
    contained = set()
    for row in containment_audit():
        detail = row.get("detail") or {}
        if detail.get("status") in {"DRY_RUN", "BLOCKED"} or detail.get("simulation"):
            continue
        if row["action"] == "INCIDENT_RESPONSE":
            status = detail.get("http_status")
            if detail.get("action") not in {"revoke", "block"} or not isinstance(status, int) or not 200 <= status < 300:
                continue
            user = users.get(str(detail.get("incident_id")))
            if not user:
                return "N/A"
        elif row["action"] == "PLAYBOOK_SUCCEEDED":
            if not any(step.get("action") in {"Revoke sessions", "Disable account"}
                       and step.get("status") == "SUCCEEDED" for step in detail.get("steps", [])):
                continue
            user = detail.get("user")
        else:
            continue
        if user:
            contained.add(str(user).casefold())
    return len(contained)


def incident_records(start=None, end=None):
    """Read complete records through RLS, paging without silent truncation."""
    p = current()
    if p.client is None:
        raise RuntimeError("Configure SUPABASE_URL and SUPABASE_KEY for local Admin storage, or sign in with Supabase.")
    rows = []
    while True:
        query = p.client.table("events").select("*").eq("tenant_id", p.tenant_id)
        if start:
            query = query.gte("created_at", start)
        if end:
            query = query.lt("created_at", end)
        page = query.order("id", desc=True).range(len(rows), len(rows) + 999).execute().data or []
        rows.extend(page)
        if len(page) < 1000:
            return rows
