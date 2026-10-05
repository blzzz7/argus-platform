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

EVENT_COLUMNS = ["EventID", "TargetUserName", "IpAddress", "Status", "AuthMethod", "ErrorCode"]

EVENTS_TABLE = "events"
RESOLVED_USERS_TABLE = "resolved_users"


def load_events() -> pd.DataFrame:
    client = get_client()
    if client is None:
        return pd.DataFrame(columns=EVENT_COLUMNS)
    try:
        resp = client.table(EVENTS_TABLE).select(",".join(EVENT_COLUMNS)).order("id").execute()
        rows = resp.data or []
        if not rows:
            return pd.DataFrame(columns=EVENT_COLUMNS)
        return pd.DataFrame(rows)[EVENT_COLUMNS]
    except Exception as e:
        print(f"[storage] load_events xətası: {e}")
        return pd.DataFrame(columns=EVENT_COLUMNS)


def append_events(df: pd.DataFrame):
    """DataFrame-i sütun formatına uyğunlaşdırır və Supabase-ə əlavə edir."""
    if df is None or df.empty:
        return
    client = get_client()
    if client is None:
        print("[storage] Supabase qoşulmayıb (SUPABASE_URL/SUPABASE_KEY boşdur) — "
              "hadisələr persist olunmadı, yalnız bu sessiyada görünəcək.")
        return
    try:
        safe_df = pd.DataFrame({col: df.get(col, "") for col in EVENT_COLUMNS}).astype(str)
        records = safe_df.to_dict(orient="records")
        client.table(EVENTS_TABLE).insert(records).execute()
    except Exception as e:
        # Persistence xətası UI-nı çökdürməməlidir - sadəcə keçici olaraq itir.
        print(f"[storage] append_events xətası: {e}")


def load_resolved_users() -> set:
    client = get_client()
    if client is None:
        return set()
    try:
        resp = client.table(RESOLVED_USERS_TABLE).select("username").execute()
        return {r["username"] for r in (resp.data or [])}
    except Exception as e:
        print(f"[storage] load_resolved_users xətası: {e}")
        return set()


def add_resolved_user(username: str):
    client = get_client()
    if client is None:
        return
    try:
        client.table(RESOLVED_USERS_TABLE).upsert({"username": username}).execute()
    except Exception as e:
        print(f"[storage] add_resolved_user xətası: {e}")


def clear_events():
    """Bütün event-ləri silir. `app_ui.py`-dəki 'Clear/Reset Telemetry' düyməsi bunu çağırır.

    QEYD: əvvəlki versiyada bu funksiya mövcud olmadığı üçün (yalnız
    `reset_all()` var idi) düymə yalnız session_state-i təmizləyirdi,
    persist olunmuş data isə qalırdı — bu, həmin latent bug-ın düzəlişidir.
    """
    client = get_client()
    if client is None:
        return
    try:
        client.table(EVENTS_TABLE).delete().gte("id", 0).execute()
    except Exception as e:
        print(f"[storage] clear_events xətası: {e}")


def clear_resolved_users():
    client = get_client()
    if client is None:
        return
    try:
        client.table(RESOLVED_USERS_TABLE).delete().neq("username", "").execute()
    except Exception as e:
        print(f"[storage] clear_resolved_users xətası: {e}")


def reset_all():
    """Geriyə uyğunluq üçün saxlanılıb (CLI/skript istifadəsi üçün)."""
    clear_events()
    clear_resolved_users()
