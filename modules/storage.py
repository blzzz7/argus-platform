"""
modules/storage.py
-------------------
Supabase (Postgres) əsaslı persistence qatı.

KÖK SƏBƏB DƏYİŞİKLİYİ (2026-10-05): əvvəlki versiya lokal SQLite faylında
(`data/argus_events.db`) saxlayırdı. Bu, Streamlit Community Cloud-un
ötəri (ephemeral) konteyner fayl sistemində hər yenidən başlatmada
İTİRİLİRDİ. İndi bütün event/resolved-user məlumatı Supabase-də (bulud
Postgres) saxlanılır — Cloud restart-larına davamlıdır.

`SUPABASE_URL` / `SUPABASE_KEY` hələ təyin olunmayıbsa (layihə hələ
qoşulmayıb), bütün funksiyalar boş/no-op davranır və çağıran UI
xəbərdarlıq göstərir (bax: app_ui.py) — tətbiq çökmür.

Sxema üçün bax: `supabase/schema.sql` (Supabase SQL Editor-da bir dəfə
işə salınmalıdır).
"""
import pandas as pd

from modules.db import get_client
from modules.authorization import require, audit

EVENT_COLUMNS = ["EventID", "TargetUserName", "IpAddress", "Status", "AuthMethod", "ErrorCode"]

EVENTS_TABLE = "events"
RESOLVED_USERS_TABLE = "resolved_users"


def load_events() -> pd.DataFrame:
    principal = require()
    client = principal.client
    if client is None:
        return pd.DataFrame(columns=EVENT_COLUMNS)
    try:
        rows = []
        offset = 0
        while True:
            page = client.table(EVENTS_TABLE).select(",".join(EVENT_COLUMNS)).eq("tenant_id", principal.tenant_id).order("id").range(offset, offset + 999).execute().data or []
            rows.extend(page)
            if len(page) < 1000:
                break
            offset += 1000
        if not rows:
            return pd.DataFrame(columns=EVENT_COLUMNS)
        return pd.DataFrame(rows)[EVENT_COLUMNS]
    except Exception as e:
        raise RuntimeError("Tenant storage operation failed.") from e


def append_events(df: pd.DataFrame):
    """DataFrame-i sütun formatına uyğunlaşdırır və Supabase-ə əlavə edir."""
    if df is None or df.empty:
        return
    principal = require()
    client = principal.client
    if client is None:
        print("[storage] Supabase qoşulmayıb (SUPABASE_URL/SUPABASE_KEY boşdur) — "
              "hadisələr persist olunmadı, yalnız bu sessiyada görünəcək.")
        return
    try:
        safe_df = pd.DataFrame({col: df.get(col, "") for col in EVENT_COLUMNS}).astype(str)
        records = safe_df.to_dict(orient="records")
        timestamp_column = next((c for c in ("timestamp", "Timestamp", "created_at") if c in df.columns), None)
        if timestamp_column:
            timestamps = pd.to_datetime(df[timestamp_column], utc=True, errors="coerce")
            for record, timestamp in zip(records, timestamps):
                if pd.notna(timestamp):
                    record["created_at"] = timestamp.isoformat()

        require("write")
        for record in records:
            record["tenant_id"] = principal.tenant_id
        audit("TELEMETRY_INGEST_REQUESTED", {"records": len(records)})
        client.table(EVENTS_TABLE).insert(records).execute()
    except Exception as e:
        raise RuntimeError("Tenant storage operation failed.") from e
        # Persistence xətası UI-nı çökdürməməlidir - sadəcə keçici olaraq itir.


def load_resolved_users() -> set:
    principal = require()
    client = principal.client
    if client is None:
        return set()
    try:
        resp = client.table(RESOLVED_USERS_TABLE).select("username").eq("tenant_id", principal.tenant_id).execute()
        return {r["username"] for r in (resp.data or [])}
    except Exception as e:
        raise RuntimeError("Tenant storage operation failed.") from e


def add_resolved_user(username: str):
    principal = require()
    client = principal.client
    if client is None:
        return
    try:
        require("remediate")
        client.table(RESOLVED_USERS_TABLE).upsert({"tenant_id": principal.tenant_id, "username": username}, on_conflict="tenant_id,username").execute()
    except Exception as e:
        raise RuntimeError("Tenant storage operation failed.") from e


def clear_events():
    """Bütün event-ləri silir. `app_ui.py`-dəki 'Clear/Reset Telemetry' düyməsi bunu çağırır.

    QEYD: əvvəlki versiyada bu funksiya mövcud olmadığı üçün (yalnız
    `reset_all()` var idi) düymə yalnız session_state-i təmizləyirdi,
    persist olunmuş data isə qalırdı — bu, həmin latent bug-ın düzəlişidir.
    """
    principal = require()
    client = principal.client
    if client is None:
        return
    try:
        require("admin")
        client.table(EVENTS_TABLE).delete().eq("tenant_id", principal.tenant_id).execute()
    except Exception as e:
        raise RuntimeError("Tenant storage operation failed.") from e


def clear_resolved_users():
    principal = require()
    client = principal.client
    if client is None:
        return
    try:
        require("admin")
        client.table(RESOLVED_USERS_TABLE).delete().eq("tenant_id", principal.tenant_id).execute()
    except Exception as e:
        raise RuntimeError("Tenant storage operation failed.") from e


def reset_all():
    """Geriyə uyğunluq üçün saxlanılıb (CLI/skript istifadəsi üçün)."""
    require("admin")
    audit("TELEMETRY_RESET_REQUESTED")
    clear_events()
    clear_resolved_users()
