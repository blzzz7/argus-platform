"""
modules/integrations.py
------------------------
SIEM/inteqrasiya konfiqurasiyasının UI-dan idarə olunması (Faza 4, 2026-10-05).

ƏVVƏLKİ DAVRANIŞ TOXUNULMAYIB: Wazuh ingest bridge ünvanı/tokeni əvvəllər
yalnız `.env` (`ARGUS_INGEST_URL`, `ARGUS_INGEST_TOKEN`, bax modules/config.py)
üzərindən təyin olunurdu. İndi bu dəyərləri (⚙️ Integrations tab-ında) UI-dan
da redaktə etmək mümkündür — dəyərlər Supabase-in `integrations` cədvəlində
saxlanılır.

PRİORİTET: UI (Supabase) konfiqurasiyası YALNIZ `enabled=true` olduqda
`.env`-i əvəz edir. UI heç vaxt konfiqurasiya olunmayıbsa (və ya
`enabled=false`-dursa, və ya Supabase hələ qoşulmayıbsa) — tətbiq dəqiq
əvvəlki kimi, sadəcə `.env`-dəki dəyərlərlə işləyir. Başqa sözlə: bu modul
əlavədir, heç nəyi SİLMİR/ƏVƏZ ETMİR, yalnız üstünə yeni bir konfiqurasiya
qatı əlavə edir.
"""
from modules.db import get_client
from modules import config

WAZUH_INTEGRATION_ID = "wazuh"

# Gələcək fazalar üçün görünən, amma hələ icra məntiqinə qoşulmamış SIEM-lər.
# UI-da "Tezliklə" kimi göstərilir ki, istifadəçi nəyin mövcud olduğunu bilsin.
PLANNED_INTEGRATIONS = [
    {"id": "splunk", "name": "Splunk HEC"},
    {"id": "sentinel", "name": "Microsoft Sentinel"},
]


def get_integration(integration_id: str):
    client = get_client()
    if client is None:
        return None
    try:
        resp = client.table("integrations").select("*").eq("id", integration_id).limit(1).execute()
        rows = resp.data or []
        return rows[0] if rows else None
    except Exception as e:
        print(f"[integrations] get_integration xətası: {e}")
        return None


def list_integrations() -> list:
    client = get_client()
    if client is None:
        return []
    try:
        resp = client.table("integrations").select("*").order("id").execute()
        return resp.data or []
    except Exception as e:
        print(f"[integrations] list_integrations xətası: {e}")
        return []


def save_integration(integration_id: str, name: str, cfg: dict, enabled: bool):
    """Qaytarır: (ok: bool, error: str|None)."""
    client = get_client()
    if client is None:
        return False, "Supabase qoşulmayıb (SUPABASE_URL/SUPABASE_KEY boşdur)."
    try:
        client.table("integrations").upsert({
            "id": integration_id,
            "name": name,
            "config": cfg,
            "enabled": enabled,
        }).execute()
        return True, None
    except Exception as e:
        return False, str(e)


def get_active_wazuh_config() -> dict:
    """Runtime-da `send_to_wazuh()`-un istifadə edəcəyi Wazuh ingest
    konfiqurasiyasını qaytarır.

    Prioritet: Supabase UI konfiqurasiyası (`enabled=true`-dursa) > `.env`
    (`modules/config.py`, dəyişdirilmədən saxlanılıb — fallback).
    """
    row = get_integration(WAZUH_INTEGRATION_ID)
    if row and row.get("enabled") and row.get("config"):
        cfg = row["config"]
        return {
            "ingest_url": cfg.get("ingest_url") or config.ARGUS_INGEST_URL,
            "ingest_token": cfg.get("ingest_token") or config.ARGUS_INGEST_TOKEN,
            "source": "ui",
        }
    return {
        "ingest_url": config.ARGUS_INGEST_URL,
        "ingest_token": config.ARGUS_INGEST_TOKEN,
        "source": "env",
    }
