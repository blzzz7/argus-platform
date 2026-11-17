"""User-scoped Supabase access. No shared authenticated clients or RLS bypass."""
from modules.authorization import current
from modules import config


def get_client():
    return current().client


def is_configured():
    return bool(config.SUPABASE_URL and config.SUPABASE_ANON_KEY)


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
