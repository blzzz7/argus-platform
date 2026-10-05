"""
modules/config.py
------------------
Mərkəzləşdirilmiş konfiqurasiya modulu.

QAYDA: Bu faylda HEÇ VAXT real şifrə, client secret və ya token saxlanmır.
Bütün sirlər `.env` faylından (lokal inkişaf üçün) və ya real mühit
dəyişənlərindən (production/deploy üçün, o cümlədən Streamlit Community
Cloud-un Secrets bölməsindən) oxunur.

QEYD (Streamlit Cloud): Cloud-un `secrets.toml`-unda TOP-LEVEL (nested
OLMAYAN) açarlar avtomatik OS environment variable kimi də expose olunur,
ona görə aşağıdakı `os.getenv()` əsaslı yanaşma əlavə körpü olmadan həm
lokalda, həm Cloud-da eyni cür işləyir.

İstifadədən əvvəl `.env.example` faylını `.env` adı ilə köçürüb doldurun:
    cp .env.example .env
"""
import os

try:
    from dotenv import load_dotenv
    load_dotenv(override=True)  # layihə kökündəki .env faylını (varsa) yükləyir
except ImportError:
    # python-dotenv quraşdırılmayıbsa, sadəcə mühit dəyişənlərinə etibar edirik
    pass


def _get(name: str, default: str = None, required: bool = False) -> str:
    val = os.getenv(name, default)
    if required and not val:
        raise RuntimeError(
            f"Tələb olunan mühit dəyişəni tapılmadı: '{name}'. "
            f".env faylını (yaxud Streamlit Cloud Secrets-i) yoxlayın."
        )
    return val


# ----------------------------------------------------------------------
# Wazuh SIEM Bağlantısı (YALNIZ audit-trail OXUMASI üçün — wazuh_auditor.py)
# ----------------------------------------------------------------------
# DİQQƏT (KÖK SƏBƏB): bu dəyişənlər artıq hadisə YAZMAQ üçün İSTİFADƏ
# OLUNMUR (bax aşağıda "ARGUS INGEST BRIDGE" bölməsi). Onlar yalnız
# wazuh_auditor.py-nin Wazuh Indexer-dən _search API-si ilə geri oxuması
# üçün lazımdır (Audit Trail).
WAZUH_ENDPOINT = _get("WAZUH_ENDPOINT", "https://localhost:9200/argus-itdr-events/_doc")

# Qeyd: .env-də tarixən həm WAZUH_USER, həm də WAZUH_USERNAME işlədilib —
# ikisi də qəbul olunur.
WAZUH_USER = _get("WAZUH_USER") or _get("WAZUH_USERNAME", "admin")
WAZUH_PASSWORD = _get("WAZUH_PASSWORD", "")
WAZUH_VERIFY_SSL = _get("WAZUH_VERIFY_SSL", "true").strip().lower() == "true"

# Audit-trail (WazuhAuditor) HANSI indeksi oxumalıdır. KÖK SƏBƏB DÜZƏLİŞİ:
# əvvəllər auditor bunun əvəzinə WAZUH_ENDPOINT-dən (argus-itdr-events)
# index adı çıxarırdı — bu indeks isə artıq heç vaxt yazılmır, ona görə
# audit oxuması həmişə boş qayıdırdı. Əsl alert-lər local_rules.xml-dən
# keçib bu pattern-ə (wazuh-alerts-*) düşür.
WAZUH_ALERTS_INDEX = _get("WAZUH_ALERTS_INDEX", "wazuh-alerts-*")

# Wazuh Indexer-in özünün bazası (ngrok və ya başqa reverse-proxy ünvanı ola
# bilər). Audit oxuması bura qarşı _search sorğusu göndərir.
WAZUH_INDEXER_BASE = _get("WAZUH_INDEXER_BASE", "https://localhost:9200")

# ----------------------------------------------------------------------
# ARGUS INGEST BRIDGE — Cloud (Streamlit Community Cloud) -> Ev şəbəkəsi
# ----------------------------------------------------------------------
# KÖK SƏBƏB DÜZƏLİŞİ: Cloud-da işləyən tətbiq sizin evinizdəki fayl
# sisteminə birbaşa YAZA BİLMƏZ (Cloud və ev tamam ayrı maşınlardır).
# Əvvəlki `send_to_wazuh()` local fayla yazırdı — bu, lokalda düzgün
# işləyir, amma Cloud-da yazılan fayl Cloud-un öz ötəri konteynerində
# itib-gedirdi və Wazuh manager-ə HEÇ VAXT çatmırdı.
#
# Həll: evinizdə kiçik bir "ingest bridge" HTTP servisi işə salıb (bax:
# receiver.py) onu ngrok ilə tunelləyirik. Cloud hadisələri BU URL-ə POST
# edir, bridge də onları Wazuh manager-in artıq tail etdiyi lokal NDJSON
# fayla yazır.
#
# ARGUS_INGEST_URL boş olarsa (default lokal development), send_to_wazuh()
# köhnə davranışa (birbaşa lokal fayla yazmaq) geri qayıdır — beləliklə
# eyni kod həm lokalda (Wazuh evinizdədirsə), həm Cloud-da (bridge
# quraşdırılıbsa) işləyir.
ARGUS_INGEST_URL = _get("ARGUS_INGEST_URL", "")  # məs. https://xxxx.ngrok-free.dev/ingest
ARGUS_INGEST_TOKEN = _get("ARGUS_INGEST_TOKEN", "")  # receiver.py ilə paylaşılan gizli açar

# ----------------------------------------------------------------------
# Argus -> Wazuh manager LOKAL fayl körpüsü (yalnız bridge/lokal tərəfdə)
# ----------------------------------------------------------------------
# Bu qovluq docker-compose.yml-də wazuh.manager konteynerinin
# /var/log/argus qovluğuna bind-mount edilməlidir.
#
# DİQQƏT: aşağıdakı default Windows yoludur (yalnız lokal inkişaf üçün
# məna kəsb edir). Cloud-da BU DƏYİŞƏN İSTİFADƏ OLUNMUR (yuxarıdakı
# ARGUS_INGEST_URL bridge-i əvəz edir) — yalnız receiver.py-ni işə
# saldığınız EV kompüterində lazımdır.
ARGUS_LOG_DIR = _get("ARGUS_LOG_DIR", r"C:\Users\rkazi\wazuh-docker\single-node\argus-logs")
ARGUS_LOG_FILENAME = _get("ARGUS_LOG_FILENAME", "itdr-events.json")

# ----------------------------------------------------------------------
# Supabase (Postgres) — əsas data persistence qatı (bax: modules/db.py, storage.py)
# ----------------------------------------------------------------------
# KÖK SƏBƏB (2026-10-05): əvvəlki SQLite (`data/argus_events.db`) Streamlit
# Community Cloud-un ötəri fayl sistemində hər restart-da itirdi. İndi
# events/resolved_users/integrations Supabase-də (bulud Postgres) saxlanılır.
#
# SUPABASE_KEY üçün `service_role` key tövsiyə olunur — Streamlit server-side
# işlədiyi üçün bu key brauzerə heç vaxt getmir (bax: modules/db.py).
SUPABASE_URL = _get("SUPABASE_URL", "")
SUPABASE_KEY = _get("SUPABASE_KEY", "")

# ----------------------------------------------------------------------
# Microsoft Entra ID / MSAL (Red Team Attack Engine üçün)
# ----------------------------------------------------------------------
TENANT_ID = _get("ARGUS_TENANT_ID")
CLIENT_ID = _get("ARGUS_CLIENT_ID")
CLIENT_SECRET = _get("ARGUS_CLIENT_SECRET")
DOMAIN = _get("ARGUS_DOMAIN", "")

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}" if TENANT_ID else None

TEST_IDENTITIES_JSON = _get("ARGUS_TEST_IDENTITIES_JSON", "")

# ----------------------------------------------------------------------
# Feature Flags
# ----------------------------------------------------------------------
ENABLE_REAL_REMEDIATION = _get("ENABLE_REAL_REMEDIATION", "false").strip().lower() == "true"


def has_graph_credentials() -> bool:
    """MSAL/Graph çağırışları üçün minimum tələb olunan dəyişənlərin mövcudluğunu yoxlayır."""
    return all([TENANT_ID, CLIENT_ID, CLIENT_SECRET])


# ----------------------------------------------------------------------
# AI / Sigma Rule Generator (ai_generator.py üçün)
# ----------------------------------------------------------------------
AI_MODE = _get("AI_MODE", "local").strip().lower()
OPENAI_API_KEY = _get("OPENAI_API_KEY")
OPENAI_MODEL = _get("OPENAI_MODEL", "gpt-4o-mini")
OLLAMA_MODEL = _get("OLLAMA_MODEL", "llama3")
OLLAMA_HOST = _get("OLLAMA_HOST", "http://127.0.0.1:11434")

# Groq / OpenAI-uyğun endpoint dəstəyi (Streamlit Cloud secrets-də
# AI_MODE="groq" göstərilibsə istifadə olunur).
LLM_BASE_URL = _get("LLM_BASE_URL", "")
LLM_API_KEY = _get("LLM_API_KEY", "")
LLM_MODEL = _get("LLM_MODEL", "")