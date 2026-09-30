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
# Wazuh SIEM Bağlantısı
# ----------------------------------------------------------------------
# DƏYİŞİKLİK (KÖK SƏBƏB DÜZƏLİŞİ): Argus artıq hadisələri BİRBAŞA
# OpenSearch-in "_doc" endpoint-inə YAZMIR (bax: app_ui.py -> send_to_wazuh()).
# Səbəb: özəl "argus-itdr-events" indeksinə birbaşa yazılan sənədlər Wazuh
# qaydalarından (rules) keçmir, ona görə Dashboard-un Overview / Threat
# Hunting ekranlarında (bunlar "wazuh-alerts-*" indeksinə baxır) HEÇ VAXT
# görünmürdü — loqlar "getmirdi" kimi görünməsinin əsl səbəbi bu idi.
#
# İndi hadisələr lokal NDJSON fayla yazılır (aşağıda ARGUS_LOG_DIR),
# Wazuh manager onu <localfile> ilə tail edir, local_rules.xml-dəki
# qaydalardan keçirir və nəticəni əsl "wazuh-alerts-*" indeksinə salır.
#
# WAZUH_ENDPOINT / WAZUH_USER / WAZUH_PASSWORD / WAZUH_VERIFY_SSL indi
# YALNIZ `wazuh_auditor.py`-nin audit-trail OXUMASI üçün istifadə olunur
# (Wazuh Indexer-dən _search API-si ilə geri oxumaq üçün).
WAZUH_ENDPOINT = _get("WAZUH_ENDPOINT", "https://localhost:9200/argus-itdr-events/_doc")

# Qeyd (DÜZƏLİŞ): .env-də tarixən həm WAZUH_USER, həm də WAZUH_USERNAME
# adı işlədilib. Əvvəlki kod yalnız WAZUH_USER-i oxuyurdu, ona görə
# .env-də WAZUH_USERNAME yazılanda bu SƏSSİZCƏ default "admin"-ə düşürdü
# (təsadüfən doğru qiymətlə üst-üstə düşdüyü üçün bug görünməz qalmışdı).
# İndi ikisi də qəbul olunur.
WAZUH_USER = _get("WAZUH_USER") or _get("WAZUH_USERNAME", "admin")
WAZUH_PASSWORD = _get("WAZUH_PASSWORD", "")  # boşdursa audit oxuması xəbərdarlıq edəcək
WAZUH_VERIFY_SSL = _get("WAZUH_VERIFY_SSL", "true").strip().lower() == "true"

# Audit-trail (WazuhAuditor) hansı indeksi/indeks pattern-ini oxumalıdır.
# local_rules.xml-dəki qaydalar group="argus,itdr," ilə işarələnib,
# auditor bunu filtr kimi istifadə edir.
WAZUH_ALERTS_INDEX = _get("WAZUH_ALERTS_INDEX", "wazuh-alerts-*")

# ----------------------------------------------------------------------
# Argus -> Wazuh manager lokal fayl körpüsü
# ----------------------------------------------------------------------
# send_to_wazuh() hadisələri bu qovluqdakı NDJSON fayla yazır. Bu qovluq
# docker-compose.yml-də wazuh.manager konteynerinin /var/log/argus
# qovluğuna bind-mount edilməlidir (bax: WAZUH_SETUP.md).
#
# DİQQƏT (Cloud portativlik qeydi): aşağıdakı default dəyər sizin öz Windows
# kompüterinizə (`C:\\Users\\rkazi\\...`) sabitlənib. Bu lokal inkişaf üçün
# problemsizdir, AMMA Streamlit Community Cloud-da (Linux mühiti) bu yol
# mövcud olmayacaq və fayla yazma cəhdi xəta verəcək. Cloud-a deploy edərkən
# Secrets-də `ARGUS_LOG_DIR` üçün Linux-uyğun bir yol təyin edin
# (məs. "/tmp/argus-logs" — Cloud-da Wazuh manager-in özü işləmədiyi üçün
# bu, sadəcə yazma xətası almamaq məqsədi daşıyır; real Wazuh inteqrasiyası
# yalnız Wazuh manager-in əlçatan olduğu mühitdə mənalıdır).
ARGUS_LOG_DIR = _get("ARGUS_LOG_DIR", r"C:\Users\rkazi\wazuh-docker\single-node\argus-logs")
ARGUS_LOG_FILENAME = _get("ARGUS_LOG_FILENAME", "itdr-events.json")

# ----------------------------------------------------------------------
# Microsoft Entra ID / MSAL (Red Team Attack Engine üçün)
# ----------------------------------------------------------------------
TENANT_ID = _get("ARGUS_TENANT_ID")
CLIENT_ID = _get("ARGUS_CLIENT_ID")
CLIENT_SECRET = _get("ARGUS_CLIENT_SECRET")
DOMAIN = _get("ARGUS_DOMAIN", "")

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}" if TENANT_ID else None

# YENİ: Cloud-da test istifadəçi/şifrə cütlüklərini TƏHLÜKƏSİZ şəkildə saxlamaq
# üçün (bax: modules/attack_engine.py -> _load_test_identities()). Streamlit
# Cloud secrets.toml-da çox sətirli string kimi verilə bilər:
#
#   ARGUS_TEST_IDENTITIES_JSON = """
#   {"domain": "yourtenant.onmicrosoft.com",
#    "credentials": {"victimuser@yourtenant.onmicrosoft.com": "RealTestPass123!"}}
#   """
#
# Boşdursa, attack_engine.py lokal data/test_identities.json faylına enir.
TEST_IDENTITIES_JSON = _get("ARGUS_TEST_IDENTITIES_JSON", "")

# ----------------------------------------------------------------------
# Feature Flags
# ----------------------------------------------------------------------
# True olduqda "Execute AI Remediation" düyməsi HƏQİQİ Graph API çağırışı ilə
# istifadəçinin sessiyalarını ləğv edir və hesabı deaktiv edir.
# False (default) olduqda proqram yalnız SİMULYASİYA edir və bunu UI-da açıq bildirir.
ENABLE_REAL_REMEDIATION = _get("ENABLE_REAL_REMEDIATION", "false").strip().lower() == "true"


def has_graph_credentials() -> bool:
    """MSAL/Graph çağırışları üçün minimum tələb olunan dəyişənlərin mövcudluğunu yoxlayır."""
    return all([TENANT_ID, CLIENT_ID, CLIENT_SECRET])


# ----------------------------------------------------------------------
# AI / Sigma Rule Generator (ai_generator.py üçün)
# ----------------------------------------------------------------------
# "local" -> lokal Ollama, "cloud" -> OpenAI API
AI_MODE = _get("AI_MODE", "local").strip().lower()
OPENAI_API_KEY = _get("OPENAI_API_KEY")
OPENAI_MODEL = _get("OPENAI_MODEL", "gpt-4o-mini")
OLLAMA_MODEL = _get("OLLAMA_MODEL", "llama3")
OLLAMA_HOST = _get("OLLAMA_HOST", "http://127.0.0.1:11434")