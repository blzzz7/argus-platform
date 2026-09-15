"""
modules/storage.py
-------------------
Sadə SQLite əsaslı persistence qatı.

Əvvəlki versiyada bütün telemetriya `st.session_state`-də saxlanırdı və
tətbiq yenidən başladıqda (restart) itirdi. Bu modul UI-ya TOXUNMADAN
(heç bir yeni tab/düymə əlavə etmədən) event-ləri və remediate edilmiş
istifadəçiləri diskə yazır ki, məlumat itməsin.
"""
import os
import sqlite3
import pandas as pd

DB_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
DB_PATH = os.path.join(DB_DIR, "argus_events.db")

EVENT_COLUMNS = ["EventID", "TargetUserName", "IpAddress", "Status", "AuthMethod", "ErrorCode"]


def _get_conn():
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            EventID TEXT,
            TargetUserName TEXT,
            IpAddress TEXT,
            Status TEXT,
            AuthMethod TEXT,
            ErrorCode TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS resolved_users (
            username TEXT PRIMARY KEY,
            resolved_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    return conn


def load_events() -> pd.DataFrame:
    try:
        conn = _get_conn()
        df = pd.read_sql_query(
            f"SELECT {', '.join(EVENT_COLUMNS)} FROM events ORDER BY id", conn
        )
        conn.close()
        return df
    except Exception:
        return pd.DataFrame(columns=EVENT_COLUMNS)


def append_events(df: pd.DataFrame):
    """DataFrame-i həm sütun formatına uyğunlaşdırır, həm də bazaya əlavə edir."""
    if df is None or df.empty:
        return
    try:
        safe_df = pd.DataFrame({col: df.get(col, "") for col in EVENT_COLUMNS})
        conn = _get_conn()
        safe_df.to_sql("events", conn, if_exists="append", index=False)
        conn.close()
    except Exception as e:
        # Persistence xətası UI-nı çökdürməməlidir - sadəcə keçici olaraq itir.
        print(f"[storage] append_events xətası: {e}")


def load_resolved_users() -> set:
    try:
        conn = _get_conn()
        rows = conn.execute("SELECT username FROM resolved_users").fetchall()
        conn.close()
        return {r[0] for r in rows}
    except Exception:
        return set()


def add_resolved_user(username: str):
    try:
        conn = _get_conn()
        conn.execute("INSERT OR IGNORE INTO resolved_users (username) VALUES (?)", (username,))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[storage] add_resolved_user xətası: {e}")


def reset_all():
    try:
        conn = _get_conn()
        conn.execute("DELETE FROM events")
        conn.execute("DELETE FROM resolved_users")
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[storage] reset_all xətası: {e}")