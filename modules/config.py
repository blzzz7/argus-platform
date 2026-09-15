"""
modules/config.py
------------------
Mərkəzləşdirilmiş konfiqurasiya modulu.

QAYDA: Bu faylda HEÇ VAXT real şifrə, client secret və ya token saxlanmır.
Bütün sirlər `.env` faylından (lokal inkişaf üçün) və ya real mühit
dəyişənlərindən (production/deploy üçün) oxunur.

İstifadədən əvvəl `.env.example` faylını `.env` adı ilə köçürüb doldurun:
    cp .env.example .env
"""
import os

try:
    from dotenv import load_dotenv
    load_dotenv()  # layihə kökündəki .env faylını (varsa) yükləyir
except ImportError:
    # python-dotenv quraşdırılmayıbsa, sadəcə mühit dəyişənlərinə etibar edirik
    pass


def _get(name: str, default: str = None, required: bool = False) -> str:
    val = os.getenv(name, default)
    if required and not val:
        raise RuntimeError(
            f"Tələb olunan mühit dəyişəni tapılmadı: '{name}'. "
            f".env faylını yoxlayın və ya export {name}=... edin."
        )
    return val


# ----------------------------------------------------------------------
# Wazuh SIEM Bağlantısı
# ----------------------------------------------------------------------
WAZUH_ENDPOINT = _get("WAZUH_ENDPOINT", "https://localhost:9200/argus-itdr-events/_doc")
WAZUH_USER = _get("WAZUH_USER", "admin")
WAZUH_PASSWORD = _get("WAZUH_PASSWORD", "")  # boşdursa send_to_wazuh xəbərdarlıq edəcək
WAZUH_VERIFY_SSL = _get("WAZUH_VERIFY_SSL", "true").strip().lower() == "true"

# ----------------------------------------------------------------------
# Microsoft Entra ID / MSAL (Red Team Attack Engine üçün)
# ----------------------------------------------------------------------
TENANT_ID = _get("ARGUS_TENANT_ID")
CLIENT_ID = _get("ARGUS_CLIENT_ID")
CLIENT_SECRET = _get("ARGUS_CLIENT_SECRET")
DOMAIN = _get("ARGUS_DOMAIN", "")

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}" if TENANT_ID else None

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