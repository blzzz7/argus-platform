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
əvvəlki kimi, sadəcə `.env`-dəki dəyərlərlə işləyir. `get_integration()`,
`list_integrations()`, `save_integration()` və `get_active_wazuh_config()`
funksiyaları — imza və davranış baxımından — HƏR HANSI BİR DƏYİŞİKLİYƏ
MƏRUZ QALMAYIB.

YENİ (Faza 6, 2026-10-07) — "Zero Breaking Changes" prinsipi ilə əlavə
olunub, heç bir mövcud funksiyanı SİLMİR/ƏVƏZ ETMİR:
  - Splunk HEC və Microsoft Sentinel üçün sabit ID-lər + konfiqurasiya
    kartları (`get_integration`/`save_integration`-ın eyni generic Supabase
    `integrations` cədvəlini istifadə etməsi sayəsində YENİ SQL/sxema
    DƏYİŞİKLİYİ TƏLƏB OLUNMUR).
  - AI/LLM provayder ID-ləri (Groq, OpenAI, Ollama) + aktiv provayder
    seçimini saxlamaq üçün ayrıca "ai_active_provider" qeydi. DİQQƏT: bu,
    yalnız UI-da görünən/saxlanılan bir PREFERENCE-dir — `ai_generator.py`
    (AIServiceSwitcher) hazırda DƏYİŞDİRİLMƏDİYİ üçün runtime AI çağırışları
    bundan asılı olmayaraq, əvvəlki kimi, YALNIZ `.env`/Secrets-dəki
    `AI_MODE`/`LLM_*`/`OPENAI_*`/`OLLAMA_*` dəyərlərini istifadə etməyə
    davam edir. Bu, qəsdən belədir (tələb olunan "mövcud funksiya
    imzalarını dəyişmə" qaydasına görə) — UI bunu aydın şəkildə göstərir.
  - Hər bir yeni inteqrasiya üçün "Test Connection" köməkçi funksiyaları
    (`test_splunk_hec`, `test_sentinel`, `test_groq`, `test_openai`,
    `test_ollama`) — hamısı saf HTTP sorğularıdır, heç bir mövcud modula
    toxunmur, heç vaxt exception buraxmır (bool, mesaj) qaytarır.
"""
import base64
import hashlib
import hmac as _hmac
import json
from datetime import datetime as _dt

import requests

from modules.db import get_client
from modules import config

# ----------------------------------------------------------------------
# Mövcud sabitlər (DƏYİŞDİRİLMƏYİB)
# ----------------------------------------------------------------------
WAZUH_INTEGRATION_ID = "wazuh"

# Əvvəllər bu siyahı "🚧 Tezliklə" kartlarını göstərirdi. İndi Splunk və
# Sentinel üçün tam funksional kartlar var (aşağıya bax), ona görə bura
# artıq boşdur — dəyişən SİLİNMİR (geriyə uyğunluq üçün saxlanılır), sadəcə
# heç bir "tezliklə" elementi yoxdur.
PLANNED_INTEGRATIONS = []

# ----------------------------------------------------------------------
# YENİ sabitlər — SIEM
# ----------------------------------------------------------------------
SPLUNK_INTEGRATION_ID = "splunk"
SENTINEL_INTEGRATION_ID = "sentinel"

SIEM_INTEGRATIONS = [
    {"id": WAZUH_INTEGRATION_ID, "name": "Wazuh SIEM", "icon": "🛡️"},
    {"id": SPLUNK_INTEGRATION_ID, "name": "Splunk HEC", "icon": "🟠"},
    {"id": SENTINEL_INTEGRATION_ID, "name": "Microsoft Sentinel", "icon": "🔷"},
]

# ----------------------------------------------------------------------
# YENİ sabitlər — AI / LLM Provayderləri
# ----------------------------------------------------------------------
AI_GROQ_ID = "ai_groq"
AI_OPENAI_ID = "ai_openai"
AI_OLLAMA_ID = "ai_ollama"
AI_ACTIVE_PROVIDER_ID = "ai_active_provider"  # config = {"provider": "groq"|"openai"|"ollama"}

AI_PROVIDERS = [
    {"id": AI_GROQ_ID, "name": "Groq Cloud AI", "icon": "⚡", "mode_value": "groq"},
    {"id": AI_OPENAI_ID, "name": "OpenAI", "icon": "🧠", "mode_value": "openai"},
    {"id": AI_OLLAMA_ID, "name": "Ollama / Local LLM", "icon": "🖥️", "mode_value": "local"},
]


# ========================================================================
# Generic Supabase CRUD (DƏYİŞDİRİLMƏYİB)
# ========================================================================
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


# ========================================================================
# YENİ — Generic helper (başqa heç bir mövcud funksiyaya toxunmur)
# ========================================================================
def get_active_integration_status(integration_id: str) -> dict:
    """Splunk/Sentinel/AI kartları üçün ümumi status: Supabase-də
    saxlanılıb-saxlanılmadığını və aktiv olub-olmadığını göstərir.
    Bu inteqrasiyaların (hələlik) `.env` fallback-ı yoxdur, ona görə
    `get_active_wazuh_config()`-dən fərqli olaraq sadəcə Supabase vəziyyətini
    əks etdirir.
    """
    row = get_integration(integration_id)
    cfg = (row or {}).get("config") or {}
    enabled = bool((row or {}).get("enabled", False))
    return {"config": cfg, "enabled": enabled, "configured": bool(cfg) and enabled}


# ========================================================================
# YENİ — Test Connection köməkçiləri (saf HTTP, heç vaxt exception atmır)
# ========================================================================
def test_splunk_hec(url: str, token: str) -> tuple:
    """Splunk HTTP Event Collector-a test hadisəsi göndərir."""
    if not url or not token:
        return False, "Endpoint URL və ya HEC Token boşdur."
    try:
        endpoint = url.rstrip("/")
        if "/services/collector" not in endpoint:
            endpoint = endpoint + "/services/collector/event"
        resp = requests.post(
            endpoint,
            headers={"Authorization": f"Splunk {token}", "Content-Type": "application/json"},
            json={"event": "Argus ITDR — test connection", "sourcetype": "argus:test"},
            timeout=10,
            verify=False,
        )
        if resp.status_code == 200:
            return True, "✅ Splunk HEC əlaqəsi uğurludur."
        return False, f"HTTP {resp.status_code}: {resp.text[:200]}"
    except Exception as e:
        return False, f"Bağlantı xətası: {e}"


def test_sentinel(workspace_id: str, shared_key: str) -> tuple:
    """Microsoft Sentinel / Log Analytics Data Collector API-sinə test
    yazısı göndərir (HTTP Data Collector API, SharedKey imzalama)."""
    if not workspace_id or not shared_key:
        return False, "Workspace ID və ya Shared Key boşdur."
    try:
        body = json.dumps([{"TestField": "Argus ITDR test connection"}])
        content_length = len(body)
        rfc1123date = _dt.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
        string_to_hash = (
            f"POST\n{content_length}\napplication/json\nx-ms-date:{rfc1123date}\n/api/logs"
        )
        decoded_key = base64.b64decode(shared_key)
        encoded_hash = base64.b64encode(
            _hmac.new(decoded_key, string_to_hash.encode("utf-8"), digestmod=hashlib.sha256).digest()
        ).decode()
        authorization = f"SharedKey {workspace_id}:{encoded_hash}"
        uri = f"https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
        headers = {
            "Content-Type": "application/json",
            "Authorization": authorization,
            "Log-Type": "ArgusITDRTest",
            "x-ms-date": rfc1123date,
        }
        resp = requests.post(uri, data=body, headers=headers, timeout=10)
        if resp.status_code in (200, 204):
            return True, "✅ Microsoft Sentinel (Log Analytics) əlaqəsi uğurludur."
        return False, f"HTTP {resp.status_code}: {resp.text[:200]}"
    except Exception as e:
        return False, f"Bağlantı xətası (Workspace ID / Shared Key formatını yoxlayın): {e}"


def test_groq(api_key: str, base_url: str, model: str) -> tuple:
    if not api_key:
        return False, "API Key boşdur."
    try:
        resp = requests.post(
            f"{(base_url or 'https://api.groq.com/openai/v1').rstrip('/')}/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": model or "llama-3.3-70b-versatile",
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 5,
            },
            timeout=15,
        )
        if resp.status_code == 200:
            return True, "✅ Groq Cloud AI əlaqəsi uğurludur."
        return False, f"HTTP {resp.status_code}: {resp.text[:200]}"
    except Exception as e:
        return False, f"Bağlantı xətası: {e}"


def test_openai(api_key: str, model: str) -> tuple:
    if not api_key:
        return False, "API Key boşdur."
    try:
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": model or "gpt-4o-mini",
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 5,
            },
            timeout=15,
        )
        if resp.status_code == 200:
            return True, "✅ OpenAI əlaqəsi uğurludur."
        return False, f"HTTP {resp.status_code}: {resp.text[:200]}"
    except Exception as e:
        return False, f"Bağlantı xətası: {e}"


def test_ollama(host: str, model: str) -> tuple:
    host = (host or "http://localhost:11434").rstrip("/")
    try:
        resp = requests.get(f"{host}/api/tags", timeout=10)
        if resp.status_code != 200:
            return False, f"HTTP {resp.status_code}: {resp.text[:200]}"
        names = [t.get("name", "") for t in (resp.json().get("models", []) or [])]
        if model and not any(model in n for n in names):
            return True, (
                f"⚠️ Ollama ayaqdadır, amma '{model}' modeli tapılmadı "
                f"(mövcud: {', '.join(names[:5]) or 'heç biri'}). `ollama pull {model}` icra edin."
            )
        return True, f"✅ Ollama əlaqəsi uğurludur ({len(names)} model tapıldı)."
    except Exception as e:
        return False, f"Bağlantı xətası (Ollama bu ünvanda işləyirmi?): {e}"