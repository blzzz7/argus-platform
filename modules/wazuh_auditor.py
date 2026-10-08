"""
modules/wazuh_auditor.py
-------------------------
Argus ITDR üçün Audit modulu. üç  əsas vəzifəsi var:

  1. AUDIT TRAIL — Wazuh Indexer-ə (OpenSearch, adətən port 9200) daxil olan
     ƏSL alert-ləri (local_rules.xml-dən keçib "wazuh-alerts-*" indeksinə
     düşənləri) geri oxuyub göstərmək.
  2. COMPLIANCE CHECKS — daxil edilmiş identity telemetriyası üzərində
     bir sıra təhlükəsizlik qaydalarını yoxlayıb PASS/FAIL + tövsiyə
     şəklində nəticə verir.
  3. DETECTION SUPPORT — security events üçün audit və detection proseslərini dəstəkləyir.


KÖK SƏBƏB DÜZƏLİŞİ (bu versiyada): əvvəlki `WazuhAuditor.__init__` index
bazasını `config.WAZUH_ENDPOINT`-dən (`.../argus-itdr-events/_doc`) çıxarırdı.
Bu indeks isə send_to_wazuh() artıq ora yazmadığı üçün (bax: app_ui.py,
Argus Ingest Bridge) HEÇ VAXT dolmur — audit oxuması ona görə həmişə boş
qayıdırdı. İndi auditor `config.WAZUH_ALERTS_INDEX` ("wazuh-alerts-*") və
`config.WAZUH_INDEXER_BASE`-i istifadə edir — yəni local_rules.xml-dən keçib
ƏSL Wazuh alert-i olan sənədləri oxuyur.

Həmçinin: ngrok pulsuz tunelin HTML interstitial səhifəsini bypass etmək
üçün bütün sorğulara `ngrok-skip-browser-warning` header-i əlavə olunub —
bu olmadan `resp.json()` HTML-i parse etməyə çalışıb sükutla uğursuz olurdu.
"""
import requests
import pandas as pd
from datetime import datetime, timedelta

from . import config


def _event_matches(series: pd.Series, code) -> pd.Series:
    """
    EventID sütununu tipdən asılı olmadan (int, str, ya da qarışıq) müqayisə edir.
    `app_ui.py`-dəki `event_matches()` ilə eyni məntiq.
    """
    return series.astype(str).str.contains(str(code), na=False)


class WazuhAuditor:
    """
    Wazuh Indexer-dən audit məlumatı çəkən və identity compliance
    qaydalarını işlədən mərkəzləşdirilmiş sinif.
    """

    def __init__(self, indexer_base=None, index=None, user=None, password=None, verify_ssl=None):
        # KÖK SƏBƏB DÜZƏLİŞİ: artıq WAZUH_ENDPOINT-dən deyil, ayrıca
        # WAZUH_INDEXER_BASE (OpenSearch bazası) və WAZUH_ALERTS_INDEX
        # ("wazuh-alerts-*") dəyişənlərindən oxuyur.
        #
        # TUNEL MƏHDUDİYYƏTİ DÜZƏLİŞİ: ngrok-un pulsuz planı eyni anda
        # YALNIZ BİR aktiv tunelə icazə verir. Ona görə OpenSearch-ə ayrıca
        # tunel açmaq əvəzinə, receiver.py-dəki "/search" proksisi eyni
        # (Ingest Bridge üçün artıq açıq olan) tunel üzərindən istifadə
        # olunur. ARGUS_INGEST_URL təyin olunubsa, bu rejim avtomatik
        # aktivləşir; boşdursa, köhnə davranış (OpenSearch-ə birbaşa
        # sorğu) saxlanılır (Wazuh tətbiqlə EYNİ maşındadırsa məna kəsb edir).
        self.use_proxy = bool(config.ARGUS_INGEST_URL)
        self.proxy_url = config.ARGUS_INGEST_URL.rsplit("/ingest", 1)[0] + "/search" if self.use_proxy else None
        self.proxy_token = config.ARGUS_INGEST_TOKEN

        self.indexer_base = (indexer_base or config.WAZUH_INDEXER_BASE).rstrip("/")
        self.index = index or config.WAZUH_ALERTS_INDEX
        self.user = user or config.WAZUH_USER
        self.password = password or config.WAZUH_PASSWORD
        self.verify_ssl = config.WAZUH_VERIFY_SSL if verify_ssl is None else verify_ssl

    def _auth(self):
        if not self.password:
            return None
        return (self.user, self.password)

    def _headers(self):
        return {
            "Content-Type": "application/json",
            # ngrok pulsuz planın HTML interstitial səhifəsini bypass edir.
            "ngrok-skip-browser-warning": "true",
        }

    def fetch_alerts(self, size: int = 100, query: dict = None):
        """
        Wazuh Indexer-dəki (OpenSearch) "wazuh-alerts-*" sənədlərini
        _search API-si ilə geri çəkir.

        Qaytarır: (ok: bool, data: list[dict] | str-xəta-mesajı)
        """
        body = query or {
            "size": size,
            "sort": [{"timestamp": {"order": "desc", "unmapped_type": "date"}}],
            "query": {"match_all": {}}
        }

        if self.use_proxy:
            # TUNEL MƏHDUDİYYƏTİ DÜZƏLİŞİ: OpenSearch-ə birbaşa yox,
            # receiver.py-dəki /search proksisinə (eyni ngrok tuneli
            # üzərindən) sorğu göndərilir.
            try:
                headers = {"Content-Type": "application/json"}
                if self.proxy_token:
                    headers["X-Argus-Token"] = self.proxy_token
                resp = requests.post(
                    self.proxy_url,
                    headers=headers,
                    json={"index": self.index, "query": body},
                    timeout=15,
                )
            except Exception as e:
                return False, f"Ingest Bridge /search proksi bağlantı xətası: {e}"

            if resp.status_code != 200:
                return False, f"HTTP {resp.status_code}: {resp.text[:300]}"

            try:
                hits = resp.json().get("hits", {}).get("hits", [])
            except Exception as e:
                return False, f"Proksi cavab parse xətası: {e} | Cavab: {resp.text[:200]}"

            alerts = [h.get("_source", {}) | {"_id": h.get("_id")} for h in hits]
            return True, alerts

        # Köhnə rejim: OpenSearch-ə birbaşa (Wazuh tətbiqlə eyni maşındadırsa).
        if not self._auth():
            return False, "WAZUH_PASSWORD .env-də təyin olunmayıb."

        try:
            resp = requests.post(
                f"{self.indexer_base}/{self.index}/_search",
                auth=self._auth(),
                headers=self._headers(),
                json=body,
                verify=self.verify_ssl,
                timeout=15,
            )
        except Exception as e:
            return False, f"Bağlantı xətası: {e}"

        if resp.status_code != 200:
            return False, f"HTTP {resp.status_code}: {resp.text[:300]}"

        try:
            hits = resp.json().get("hits", {}).get("hits", [])
        except Exception as e:
            snippet = resp.text[:200] if hasattr(resp, "text") else str(e)
            return False, f"Cavab parse xətası (JSON deyil ola bilər): {e} | Cavab: {snippet}"

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
                        {"match": {"data.win.eventdata.targetUserName": username}},
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
    # COMPLIANCE CHECKS — Identity telemetriyası üzərində qayda mühərriki
    # ------------------------------------------------------------------
    @staticmethod
    def run_compliance_checks(df: pd.DataFrame, resolved_users: set = None) -> list:
        resolved_users = resolved_users or set()
        findings = []

        if df is None or df.empty:
            findings.append({
                "id": "C0",
                "title": "Telemetriya mövcud deyil",
                "severity": "INFO",
                "status": "WARN",
                "description": "Audit üçün heç bir identity log daxil edilməyib.",
                "recommendation": "Live Log Ingestion-dan CSV yükləyin və ya Red Team Attack Controller-də simulyasiya işə salın."
            })
            return findings

        cols = {
            "event": next((c for c in ["EventID", "event_id"] if c in df.columns), None),
            "user": next((c for c in ["TargetUserName", "user", "TargetUser"] if c in df.columns), None),
            "ip": next((c for c in ["IpAddress", "source_ip", "IP"] if c in df.columns), None),
        }
        event_col, user_col, ip_col = cols["event"], cols["user"], cols["ip"]

        failed_df = df[_event_matches(df[event_col], 4625)] if event_col else df

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

        if "AuthMethod" in df.columns:
            weak_methods = df[df["AuthMethod"].astype(str).str.contains("NTLM|OAuth2|PasswordSpray", case=False, na=False)]
            if len(weak_methods) > 0:
                findings.append({
                    "id": "C3",
                    "title": "MFA-sız / köhnə autentifikasiya metodları",
                    "severity": "MEDIUM",
                    "status": "FAIL",
                    "description": f"{len(weak_methods)} hadisə MFA tələb etməyən metodla (NTLM/OAuth2/Spray) baş verib.",
                    "recommendation": "Phishing-resistant MFA (FIDO2, Certificate-Based Auth) tətbiq edin, "
                                       "legacy autentifikasiyanı bloklayın."
                })

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
                "recommendation": "Remediate edilməmiş qalan hesablar üçün AI Threat Analysis menyusundan aksiya götürün."
            })

        return findings

    @staticmethod
    def compliance_score(findings: list) -> int:
        if not findings:
            return 100
        penalty = 0
        for f in findings:
            if f["status"] == "FAIL":
                penalty += 20 if f["severity"] in ("CRITICAL", "HIGH") else 10
            elif f["status"] == "WARN":
                penalty += 5
        return max(0, 100 - penalty)

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
    auditor = WazuhAuditor()
    ok, result = auditor.fetch_alerts(size=10)
    if ok:
        print(f"[+] {len(result)} audit qeydi tapıldı.")
        for r in result[:5]:
            print(" -", r)
    else:
        print(f"[-] Xəta: {result}")
