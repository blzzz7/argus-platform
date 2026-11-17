"""
modules/integrations.py
------------------------
(SIEM and detection integration)
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
from modules.authorization import require, audit
from modules.secrets_store import seal, unseal
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
    principal = require()
    client = principal.client
    if client is None:
        return None
    try:
        resp = client.table("integrations").select("*").eq("tenant_id", principal.tenant_id).eq("id", integration_id).limit(1).execute()
    except Exception:
        # Unavailable storage must not block authorized environment fallbacks.
        # Keep permission checks and credential decryption outside this handler.
        return None
    rows = resp.data or []
    if rows:
        rows[0]["config"] = unseal(rows[0].get("config") or {})
    return rows[0] if rows else None


def list_integrations() -> list:
    principal = require()
    client = principal.client
    if client is None:
        return []
    try:
        resp = client.table("integrations").select("*").eq("tenant_id", principal.tenant_id).order("id").execute()
        rows = resp.data or []
        for row in rows:
            row["config"] = unseal(row.get("config") or {})
        return rows
    except Exception as e:
        raise RuntimeError("Integration settings could not be loaded.") from e


def save_integration(integration_id: str, name: str, cfg: dict, enabled: bool):
    """Qaytarır: (ok: bool, error: str|None)."""
    principal = require()
    client = principal.client
    if client is None:
        return False, "Connection failed. Check credentials, endpoint, and certificate configuration."
    try:
        require("admin")
        if enabled and integration_id in {"wazuh", "splunk", "sentinel"}:
            from modules.connectors import validate_settings
            candidate = dict(cfg)
            if integration_id == "wazuh" and principal.tenant_id == config.LEGACY_TENANT_ID:
                candidate["ingest_url"] = candidate.get("ingest_url") or config.ARGUS_INGEST_URL
                candidate["ingest_token"] = candidate.get("ingest_token") or config.ARGUS_INGEST_TOKEN
            if not (integration_id == "wazuh" and principal.tenant_id == config.LEGACY_TENANT_ID and not candidate.get("ingest_url")):
                validate_settings(integration_id, candidate)
        encrypted = seal(cfg)
        audit("INTEGRATION_UPDATE_REQUESTED", {"provider": integration_id, "enabled": bool(enabled)})
        client.table("integrations").upsert({
            "tenant_id": principal.tenant_id,
            "id": integration_id,
            "name": name,
            "config": encrypted,
            "enabled": enabled,
        }, on_conflict="tenant_id,id").execute()
        return True, None
    except Exception as e:
        return False, "Integration settings could not be saved. Check encryption and database configuration."


def get_active_wazuh_config() -> dict:
    """Runtime-da `send_to_wazuh()`-un istifadə edəcəyi Wazuh ingest
    konfiqurasiyasını qaytarır.

    Prioritet: Supabase UI konfiqurasiyası (`enabled=true`-dursa) > `.env`
    (`modules/config.py`, dəyişdirilmədən saxlanılıb — fallback).
    """
    principal = require("write")
    tenant_wazuh = json.loads(config.TENANT_SECRETS_JSON).get(principal.tenant_id, {}).get("wazuh")
    if tenant_wazuh:
        return {"ingest_url": tenant_wazuh["ingest_url"], "ingest_token": tenant_wazuh["ingest_token"], "source": "tenant"}
    row = get_integration(WAZUH_INTEGRATION_ID)
    if not principal.local_admin and principal.tenant_id != config.LEGACY_TENANT_ID and not (row and row.get("enabled") and row.get("config", {}).get("ingest_url")):
        raise PermissionError("Configure a tenant-specific Wazuh bridge.")
    if row and row.get("enabled") and row.get("config"):
        cfg = row["config"]
        return {
            "ingest_url": cfg.get("ingest_url") or config.ARGUS_INGEST_URL,
            "ingest_token": cfg.get("ingest_token") or (config.ARGUS_INGEST_TOKEN if principal.local_admin or principal.tenant_id == config.LEGACY_TENANT_ID else ""),
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
    require("admin")
    if not url or not token:
        return False, "Connection failed. Check credentials, endpoint, and certificate configuration."
    try:
        endpoint = url.rstrip("/")
        if "/services/collector" not in endpoint:
            endpoint = endpoint + "/services/collector/event"
        resp = requests.post(
            endpoint,
            headers={"Authorization": f"Splunk {token}", "Content-Type": "application/json"},
            json={"event": "Argus ITDR — test connection", "sourcetype": "argus:test"},
            timeout=10,
            verify=True,
        )
        if resp.status_code == 200:
            return True, "Connection test succeeded."
        return False, "Connection failed. Check credentials, endpoint, and certificate configuration."
    except Exception as e:
        return False, "Connection failed. Check credentials, endpoint, and certificate configuration."


def test_sentinel(workspace_id: str, shared_key: str) -> tuple:
    """Microsoft Sentinel / Log Analytics Data Collector API-sinə test
    yazısı göndərir (HTTP Data Collector API, SharedKey imzalama)."""
    require("admin")
    if not workspace_id or not shared_key:
        return False, "Connection failed. Check credentials, endpoint, and certificate configuration."
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
            return True, "Connection test succeeded."
        return False, "Connection failed. Check credentials, endpoint, and certificate configuration."
    except Exception as e:
        return False, "Connection failed. Check credentials, endpoint, and certificate configuration."


def test_groq(api_key: str, base_url: str, model: str) -> tuple:
    require("admin")
    if not api_key:
        return False, "Connection failed. Check credentials, endpoint, and certificate configuration."
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
            return True, "Connection test succeeded."
        return False, "Connection failed. Check credentials, endpoint, and certificate configuration."
    except Exception as e:
        return False, "Connection failed. Check credentials, endpoint, and certificate configuration."


def test_openai(api_key: str, model: str) -> tuple:
    require("admin")
    if not api_key:
        return False, "Connection failed. Check credentials, endpoint, and certificate configuration."
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
            return True, "Connection test succeeded."
        return False, "Connection failed. Check credentials, endpoint, and certificate configuration."
    except Exception as e:
        return False, "Connection failed. Check credentials, endpoint, and certificate configuration."


def test_ollama(host: str, model: str) -> tuple:
    require("admin")
    host = (host or "http://localhost:11434").rstrip("/")
    try:
        resp = requests.get(f"{host}/api/tags", timeout=10)
        if resp.status_code != 200:
            return False, "Connection failed. Check credentials, endpoint, and certificate configuration."
        names = [t.get("name", "") for t in (resp.json().get("models", []) or [])]
        if model and not any(model in n for n in names):
            return False, f"Ollama is reachable, but model {model} is unavailable. Install the model before using this provider."
        return True, "Connection test succeeded."
    except Exception as e:
        return False, "Connection failed. Check credentials, endpoint, and certificate configuration."
