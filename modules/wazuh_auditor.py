"""
modules/wazuh_auditor.py
-------------------------
Argus ITDR üçün Audit modulu. İki əsas vəzifəsi var:

  1. AUDIT TRAIL — Wazuh Indexer-ə (OpenSearch, adətən port 9200) əvvəllər
     `send_to_wazuh()` ilə yazılmış hadisələri GERİ oxuyub göstərmək.
     (Qeyd: `app.py`/`app_ui.py`-dakı `send_to_wazuh()` yalnız YAZIR;
     bu modul isə OXUYUR — beləliklə "nə göndərdik, nə qaldı" sualına cavab verir.)

  2. COMPLIANCE CHECKS — daxil edilmiş identity telemetriyası üzərində
     bir sıra təhlükəsizlik qaydalarını yoxlayıb PASS/FAIL + tövsiyə
     şəklində nəticə verir (SOC-un "hansı boşluqlar var" sualına cavab).

Bu modul `modules/config.py`-dakı eyni WAZUH_* mühit dəyişənlərini istifadə edir,
yəni `.env`-də ayrıca heç nə əlavə etməyə ehtiyac yoxdur.
"""
import requests
import pandas as pd
from datetime import datetime, timedelta

from . import config


class WazuhAuditor:
    """
    Wazuh Indexer-dən audit məlumatı çəkən və identity compliance
    qaydalarını işlədən mərkəzləşdirilmiş sinif.
    """

    def __init__(self, endpoint=None, user=None, password=None, verify_ssl=None):
        # endpoint nümunəsi: https://localhost:9200/argus-itdr-events/_doc
        # Axtarış üçün bizə "_doc" olmadan indeks bazası lazımdır:
        raw_endpoint = endpoint or config.WAZUH_ENDPOINT
        self.index_base = raw_endpoint.rsplit("/_doc", 1)[0].rstrip("/")
        self.user = user or config.WAZUH_USER
        self.password = password or config.WAZUH_PASSWORD
        self.verify_ssl = config.WAZUH_VERIFY_SSL if verify_ssl is None else verify_ssl

    # ------------------------------------------------------------------
    # 1) AUDIT TRAIL — Wazuh Indexer-dən geri oxuma
    # ------------------------------------------------------------------
    def _auth(self):
        if not self.password:
            return None
        return (self.user, self.password)

    def fetch_alerts(self, size: int = 100, query: dict = None):
        """
        Wazuh Indexer-dəki (OpenSearch) sənədləri OpenSearch _search API-si ilə
        geri çəkir. `query` verilməzsə, son `size` sənədi tarixə görə sıralayıb qaytarır.

        Qaytarır: (ok: bool, data: list[dict] | str-xəta-mesajı)
        """
        if not self._auth():
            return False, "WAZUH_PASSWORD .env-də təyin olunmayıb."

        body = query or {
            "size": size,
            "sort": [{"timestamp": {"order": "desc", "unmapped_type": "date"}}],
            "query": {"match_all": {}}
        }

        try:
            resp = requests.post(
                f"{self.index_base}/_search",
                auth=self._auth(),
                headers={"Content-Type": "application/json"},
                json=body,
                verify=self.verify_ssl,
                timeout=10,
            )
        except Exception as e:
            return False, f"Bağlantı xətası: {e}"

        if resp.status_code != 200:
            return False, f"HTTP {resp.status_code}: {resp.text[:300]}"

        try:
            hits = resp.json().get("hits", {}).get("hits", [])
        except Exception as e:
            return False, f"Cavab parse xətası: {e}"

        alerts = [h.get("_source", {}) | {"_id": h.get("_id")} for h in hits]
        return True, alerts

    def fetch_alerts_for_user(self, username: str, size: int = 50):
        """Konkret istifadəçiyə aid audit qeydlərini gətirir."""
        query = {
            "size": size,
            "sort": [{"timestamp": {"order": "desc", "unmapped_type": "date"}}],
            "query": {
                "bool": {
                    "should": [
                        {"match": {"user": username}},
                        {"match": {"target_user": username}},
                    ],
                    "minimum_should_match": 1,
                }
            },
        }
        return self.fetch_alerts(query=query)

    def fetch_alerts_as_dataframe(self, size: int = 200) -> pd.DataFrame:
        """UI-da cədvəl kimi göstərmək üçün rahat DataFrame formatı."""
        ok, data = self.fetch_alerts(size=size)
        if not ok or not data:
            return pd.DataFrame()
        return pd.DataFrame(data)

    # ------------------------------------------------------------------
    # 2) COMPLIANCE CHECKS — Identity telemetriyası üzərində qayda mühərriki
    # ------------------------------------------------------------------
    @staticmethod
    def run_compliance_checks(df: pd.DataFrame, resolved_users: set = None) -> list:
        """
        Daxil edilmiş identity log-ları (Tab 1/3-dən gələn DataFrame) üzərində
        bir sıra ITDR compliance qaydalarını işlədir.

        Qaytarır: list[dict], hər biri:
            {id, title, severity, status ("PASS"/"FAIL"/"WARN"), description, recommendation}
        """
        resolved_users = resolved_users or set()
        findings = []

        if df is None or df.empty:
            findings.append({
                "id": "C0",
                "title": "Telemetriya mövcud deyil",
                "severity": "INFO",
                "status": "WARN",
                "description": "Audit üçün heç bir identity log daxil edilməyib.",
                "recommendation": "Tab 1-dən CSV yükləyin və ya Tab 3-də simulyasiya işə salın."
            })
            return findings

        cols = {
            "event": next((c for c in ["EventID", "event_id"] if c in df.columns), None),
            "user": next((c for c in ["TargetUserName", "user", "TargetUser"] if c in df.columns), None),
            "ip": next((c for c in ["IpAddress", "source_ip", "IP"] if c in df.columns), None),
        }
        event_col, user_col, ip_col = cols["event"], cols["user"], cols["ip"]

        failed_df = df[df[event_col] == 4625] if event_col else df

        # --- C1: Smart Lockout tələb edən hesablar varmı ---
        if event_col and user_col:
            lockout_counts = failed_df[user_col].value_counts()
            locked = lockout_counts[lockout_counts >= 3]
            if len(locked) > 0:
                findings.append({
                    "id": "C1",
                    "title": "Smart Lockout həddini keçən hesablar",
                    "severity": "CRITICAL",
                    "status": "FAIL",
                    "description": f"{len(locked)} hesab 3+ ardıcıl uğursuz cəhdə məruz qalıb: "
                                    f"{', '.join(locked.index[:5])}{'...' if len(locked) > 5 else ''}.",
                    "recommendation": "Conditional Access Smart Lockout siyasətini aktivləşdirin və "
                                       "bu hesabları dərhal remediate edin."
                })
            else:
                findings.append({
                    "id": "C1", "title": "Smart Lockout həddini keçən hesablar",
                    "severity": "LOW", "status": "PASS",
                    "description": "Heç bir hesab lockout həddini keçməyib.",
                    "recommendation": "Mövcud vəziyyəti saxlayın."
                })

        # --- C2: Eyni IP-dən çoxlu fərqli hesaba hücum (password spray əlaməti) ---
        if ip_col and user_col:
            spray_pattern = failed_df.groupby(ip_col)[user_col].nunique()
            spray_ips = spray_pattern[spray_pattern >= 3]
            if len(spray_ips) > 0:
                findings.append({
                    "id": "C2",
                    "title": "Password Spray nümunəsi aşkarlandı",
                    "severity": "HIGH",
                    "status": "FAIL",
                    "description": f"{len(spray_ips)} IP ünvanı 3+ fərqli hesaba qarşı uğursuz cəhd edib: "
                                    f"{', '.join(spray_ips.index[:5])}.",
                    "recommendation": "Bu IP ünvanlarını Conditional Access-də bloklayın və "
                                       "Entra ID Protection risk siyasətlərini nəzərdən keçirin."
                })
            else:
                findings.append({
                    "id": "C2", "title": "Password Spray nümunəsi aşkarlandı",
                    "severity": "LOW", "status": "PASS",
                    "description": "Aşkar password spray nümunəsi tapılmadı.",
                    "recommendation": "Monitorinqi davam etdirin."
                })

        # --- C3: Zəif autentifikasiya metodları (OAuth2/NTLM = MFA-sız) ---
        if "AuthMethod" in df.columns:
            weak_methods = df[df["AuthMethod"].astype(str).str.contains("NTLM|OAuth2", case=False, na=False)]
            if len(weak_methods) > 0:
                findings.append({
                    "id": "C3",
                    "title": "MFA-sız / köhnə autentifikasiya metodları",
                    "severity": "MEDIUM",
                    "status": "FAIL",
                    "description": f"{len(weak_methods)} hadisə MFA tələb etməyən metodla (NTLM/OAuth2) baş verib.",
                    "recommendation": "Phishing-resistant MFA (FIDO2, Certificate-Based Auth) tətbiq edin, "
                                       "legacy autentifikasiyanı bloklayın."
                })

        # --- C4: SOC cavab veriş sürəti (remediation coverage) ---
        threat_users = set(failed_df[user_col].unique()) if (event_col and user_col) else set()
        if threat_users:
            coverage = len(threat_users & resolved_users) / len(threat_users) * 100
            status = "PASS" if coverage >= 80 else ("WARN" if coverage >= 40 else "FAIL")
            severity = "LOW" if status == "PASS" else ("MEDIUM" if status == "WARN" else "HIGH")
            findings.append({
                "id": "C4",
                "title": "SOC Remediation Coverage",
                "severity": severity,
                "status": status,
                "description": f"Aşkarlanan {len(threat_users)} təhdid edilmiş hesabdan "
                                f"{len(threat_users & resolved_users)}-i remediate edilib ({coverage:.0f}%).",
                "recommendation": "Remediate edilməmiş qalan hesablar üçün Tab 2-dən aksiya götürün."
            })

        return findings

    @staticmethod
    def compliance_score(findings: list) -> int:
        """FAIL/WARN sayına görə sadə 0-100 uyğunluq balı hesablayır."""
        if not findings:
            return 100
        penalty = 0
        for f in findings:
            if f["status"] == "FAIL":
                penalty += 20 if f["severity"] in ("CRITICAL", "HIGH") else 10
            elif f["status"] == "WARN":
                penalty += 5
        return max(0, 100 - penalty)

    # ------------------------------------------------------------------
    # 3) Birləşdirilmiş audit xülasəsi (istəyə görə PDF/Dashboard-a bağlana bilər)
    # ------------------------------------------------------------------
    def build_audit_summary(self, df: pd.DataFrame, resolved_users: set = None) -> dict:
        findings = self.run_compliance_checks(df, resolved_users)
        return {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "compliance_score": self.compliance_score(findings),
            "findings": findings,
            "total_findings": len(findings),
            "failed": len([f for f in findings if f["status"] == "FAIL"]),
            "warned": len([f for f in findings if f["status"] == "WARN"]),
            "passed": len([f for f in findings if f["status"] == "PASS"]),
        }


if __name__ == "__main__":
    # Sadə mənual test: Wazuh-dan son 10 hadisəni çəkib göstərir.
    auditor = WazuhAuditor()
    ok, result = auditor.fetch_alerts(size=10)
    if ok:
        print(f"[+] {len(result)} audit qeydi tapıldı.")
        for r in result[:5]:
            print(" -", r)
    else:
        print(f"[-] Xəta: {result}")