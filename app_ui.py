import streamlit as st
import pandas as pd
import requests
import time
import io
from datetime import datetime
import plotly.express as px

# ReportLab Imports for PDF Generation
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

# Streamlit Page Config
st.set_page_config(
    page_title="Argus ITDR - Identity Threat Detection",
    page_icon="🛡️",
    layout="wide"
)

WAZUH_ENDPOINT = "https://localhost:9200/argus-itdr-events/_doc"
WAZUH_AUTH = ("admin", "SecretPassword")

def send_to_wazuh(payload):
    try:
        response = requests.post(
            WAZUH_ENDPOINT,
            auth=WAZUH_AUTH,
            headers={"Content-Type": "application/json"},
            json=payload,
            verify=False
        )
        if response.status_code in [200, 201]:
            return True, response.json()
        else:
            return False, f"HTTP {response.status_code}: {response.text}"
    except Exception as e:
        return False, str(e)

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
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        textColor=colors.HexColor("#0E1117"),
        spaceAfter=6
    )
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        textColor=colors.HexColor("#555555"),
        spaceAfter=15
    )
    h2_style = ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        textColor=colors.HexColor("#1F77B4"),
        spaceBefore=12,
        spaceAfter=8
    )
    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        textColor=colors.HexColor("#222222")
    )
    
    elements = []

    # Document Header
    elements.append(Paragraph("🛡️ ARGUS ITDR - EXECUTIVE SECURITY AUDIT REPORT", title_style))
    elements.append(Paragraph(f"<b>Generated:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} | <b>Engine:</b> Argus Security AI & Analytics Platform", subtitle_style))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#1F77B4"), spaceAfter=15))

    # Executive Summary Metrics Table
    total_events = len(df)
    event_col = 'EventID' if 'EventID' in df.columns else ('event_id' if 'event_id' in df.columns else None)
    failed_attempts = len(df[df[event_col].astype(str).str.contains('4625')]) if event_col else total_events
    remediated_count = len(resolved_users)
    
    summary_data = [
        [Paragraph("<b>Metric</b>", body_style), Paragraph("<b>Value</b>", body_style), Paragraph("<b>Status / Context</b>", body_style)],
        [Paragraph("Security Posture Score", body_style), Paragraph(f"<b>{posture_score} / 100</b>", body_style), Paragraph("Evaluated via Real-time AI Engine", body_style)],
        [Paragraph("Total Ingested Events", body_style), Paragraph(str(total_events), body_style), Paragraph("Active Directory / Entra ID Telemetry", body_style)],
        [Paragraph("Identity Threats (Failed Logons)", body_style), Paragraph(str(failed_attempts), body_style), Paragraph("Event ID 4625 Anomalies Detected", body_style)],
        [Paragraph("Threats Auto-Remediated", body_style), Paragraph(str(remediated_count), body_style), Paragraph("Conditional Access & Token Revocation", body_style)]
    ]

    summary_table = Table(summary_data, colWidths=[180, 100, 260])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#EAEAEA")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.black),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#DDDDDD")),
    ]))
    
    elements.append(Paragraph("1. Executive Summary", h2_style))
    elements.append(summary_table)
    elements.append(Spacer(1, 15))

    # Threat Findings & AI Remediation Summary
    elements.append(Paragraph("2. Threat Analysis & Remediation Log", h2_style))
    
    user_col = 'TargetUserName' if 'TargetUserName' in df.columns else ('user' if 'user' in df.columns else 'TargetUser')
    ip_col = 'IpAddress' if 'IpAddress' in df.columns else ('source_ip' if 'source_ip' in df.columns else 'IP')
    
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
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1F77B4")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CCCCCC")),
    ]))
    
    elements.append(threat_table)
    elements.append(Spacer(1, 15))

    # Hardening Recommendations
    elements.append(Paragraph("3. AI Hardening & Strategic Recommendations", h2_style))
    recs = [
        "<b>Enforce Phishing-Resistant MFA:</b> Upgrade identity scopes to require FIDO2 Security Keys or Certificate-Based Authentication.",
        "<b>Deploy Entra ID Protection Policies:</b> Enable automated Smart Lockout thresholds to block password spray IP pools dynamically.",
        "<b>Continuous SIEM Dispatch:</b> Ensure all failed authentication spikes are streaming live into Wazuh Indexer for active SOAR triage.",
        "<b>Session Invalidation:</b> Automatically revoke Active Refresh Tokens for any user accumulating >3 failed sign-ins within 60 seconds."
    ]
    for r in recs:
        elements.append(Paragraph(f"• {r}", body_style))
        elements.append(Spacer(1, 4))

    # Build Document
    doc.build(elements)
    buffer.seek(0)
    return buffer

# Session state initialization
if 'df' not in st.session_state:
    st.session_state['df'] = pd.DataFrame(columns=['EventID', 'TargetUserName', 'IpAddress', 'Status', 'AuthMethod', 'ErrorCode'])

if 'resolved_users' not in st.session_state:
    st.session_state['resolved_users'] = set()

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
    
    if 'df' in st.session_state and not st.session_state['df'].empty:
        df = st.session_state['df']

        event_col = 'EventID' if 'EventID' in df.columns else ('event_id' if 'event_id' in df.columns else None)
        user_col = 'TargetUserName' if 'TargetUserName' in df.columns else ('user' if 'user' in df.columns else ('TargetUser' if 'TargetUser' in df.columns else None))
        ip_col = 'IpAddress' if 'IpAddress' in df.columns else ('source_ip' if 'source_ip' in df.columns else ('IP' if 'IP' in df.columns else None))

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
        st.subheader("💡 Dynamic AI Remediation Guidance & Action")

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
                        st.success(f"✅ Session for `{user}` revoked & account disabled in Entra ID.")
                    else:
                        st.error(f"🚨 **Risk Assessment:** Active Threat Detected on `{user}` via `{auth_method}`!")
                        st.info(f"🤖 **AI Auto-Fix Action:** Revoke all Active Refresh Tokens and trigger Conditional Access Lockout for `{user}`.")
                        
                        if st.button(f"🚫 Execute AI Remediation ({user})", key=f"btn_ai_block_{idx}_{user}"):
                            alert_payload = {
                                "timestamp": datetime.utcnow().isoformat() + "Z",
                                "event_type": "AI_AUTO_FIX_EXECUTION",
                                "target_user": user,
                                "source_ip": ip,
                                "action_taken": "ACCOUNT_DISABLED_ENTRA_ID",
                                "triggered_by": "Argus-AI-Engine",
                                "status": "SUCCESS"
                            }
                            send_to_wazuh(alert_payload)
                            st.session_state['resolved_users'].add(user)
                            st.success(f"✅ Remediated! Account `{user}` locked out and logged to Wazuh SIEM.")
                            st.rerun()
    else:
        st.warning("⚠️ No logs ingested or generated yet. Upload CSV or run Red Team Attack Simulation.")

# TAB 3: Red Team Attack Controller
with tab3:
    st.header("⚔️ Red Team Attack Controller & Simulation Engine")
    st.caption("Simulate real-world identity attacks against Entra ID / Active Directory and observe live MSAL responses.")
    
    col_left, col_right = st.columns([1, 1])
    
    with col_left:
        st.subheader("⚙️ Custom Attack Parameters")
        target_users = st.text_area("Target Users (One per line)", value="tyler.durden\nmarla.singer\ntrevor.reznik\nneo")
        passwords = st.text_input("Password / Password List", value="Spring2026! / Wordlist_v1.txt")
        attack_delay = st.slider("Attack Delay per Attempt (Seconds)", min_value=0.1, max_value=2.0, value=0.2, step=0.1)
        source_attacker_ip = st.text_input("Attacker Source IP", value="185.220.101.5 (Tor Exit Node)")
        
        st.markdown("---")
        st.subheader("🎯 Attack Controller Triggers")
        
        btn_spray = st.button("🚀 Launch Password Spray Attack")
        btn_brute = st.button("🔨 Launch Brute Force Attack")
        btn_enum = st.button("🔍 Launch User Enumeration")
        btn_device = st.button("🔑 Launch Device Code Flow Phishing")

    with col_right:
        st.subheader("🖥️ Live Attack Terminal Console (`attack_engine.py`)")
        terminal_placeholder = st.empty()
        
        terminal_placeholder.code(
            "[+] Attack Engine Standby...\n"
            "[+] MSAL Authentication Provider: Ready\n"
            "[+] Target Scope: https://login.microsoftonline.com/common\n"
            "[*] Awaiting operator trigger command...",
            language="bash"
        )

    if btn_spray or btn_brute or btn_enum or btn_device:
        user_list = [u.strip() for u in target_users.split("\n") if u.strip()]
        console_logs = []
        new_events = []
        
        if btn_spray:
            attack_type = "PASSWORD_SPRAY"
            console_logs.append(f"[*] Starting {attack_type} against {len(user_list)} accounts...")
            
            for u in user_list:
                console_logs.append(f"[>] [MSAL AUTH REQUEST] User: {u} | Grant: password")
                time.sleep(attack_delay)
                console_logs.append(f"[!] [MSAL RESPONSE 400] AADSTS50126: Invalid password for {u}")
                
                new_events.append({"EventID": 4625, "TargetUserName": u, "IpAddress": "185.220.101.5", "Status": "FAILED", "AuthMethod": "PasswordSpray", "ErrorCode": "AADSTS50126"})
                send_to_wazuh({
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "event_id": 4625, "user": u, "source_ip": "185.220.101.5",
                    "rule_title": "Entra ID Password Spray Attempt", "severity": "HIGH", "source": "Argus-RedTeam-Engine"
                })
                terminal_placeholder.code("\n".join(console_logs), language="bash")

        elif btn_brute:
            attack_type = "BRUTE_FORCE"
            target_user = user_list[0] if user_list else "tyler.durden"
            console_logs.append(f"[*] Starting {attack_type} targeting user: {target_user}")
            
            for i in range(1, 6):
                console_logs.append(f"[>] Attempt {i}/5 | Password: Pass#{i}23! | User: {target_user}")
                time.sleep(attack_delay)
                
                err_code = "AADSTS50053" if i >= 4 else "AADSTS50126"
                console_logs.append(f"[!] [401 Unauthorized] {err_code}: Bad credentials for {target_user}")
                
                new_events.append({"EventID": 4625, "TargetUserName": target_user, "IpAddress": "185.220.101.5", "Status": "FAILED", "AuthMethod": "BruteForce", "ErrorCode": err_code})
                send_to_wazuh({
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "event_id": 4625, "user": target_user, "source_ip": "185.220.101.5",
                    "rule_title": "Brute Force Authentication Attempt",
                    "severity": "CRITICAL" if err_code == "AADSTS50053" else "HIGH",
                    "source": "Argus-RedTeam-Engine"
                })
                terminal_placeholder.code("\n".join(console_logs), language="bash")

        elif btn_enum:
            attack_type = "USER_ENUMERATION"
            console_logs.append(f"[*] Starting {attack_type} probing tenant endpoints...")
            
            for u in user_list:
                console_logs.append(f"[>] Probing account existence: {u}@domain.com")
                time.sleep(attack_delay)
                err_code = "AADSTS50034"
                console_logs.append(f"[!] [404 Not Found] {err_code}: User account {u} does not exist in tenant")
                
                new_events.append({"EventID": 4625, "TargetUserName": u, "IpAddress": "185.220.101.5", "Status": "FAILED", "AuthMethod": "UserEnumAPI", "ErrorCode": err_code})
                send_to_wazuh({
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "event_id": 4625, "user": u, "source_ip": "185.220.101.5",
                    "rule_title": "Entra ID User Enumeration Attempt", "severity": "MEDIUM", "source": "Argus-RedTeam-Engine"
                })
                terminal_placeholder.code("\n".join(console_logs), language="bash")

        elif btn_device:
            attack_type = "DEVICE_CODE_PHISHING"
            console_logs.append("[*] Initializing OAuth2 Device Code Flow Phishing Simulation...")
            time.sleep(attack_delay)
            console_logs.append("[+] User Code Generated: [ D3V-C0D3 ]")
            console_logs.append("⚠️ [ALERT] Device Code Token Intercepted for user: trevor.reznik")
            
            new_events.append({"EventID": 4625, "TargetUserName": "trevor.reznik", "IpAddress": "185.220.101.5", "Status": "FAILED", "AuthMethod": "DeviceCodeFlow", "ErrorCode": "AADSTS70016"})
            send_to_wazuh({
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "event_id": 4625, "user": "trevor.reznik", "source_ip": "185.220.101.5",
                "rule_title": "OAuth2 Device Code Phishing Intercept", "severity": "CRITICAL", "source": "Argus-RedTeam-Engine"
            })
            terminal_placeholder.code("\n".join(console_logs), language="bash")

        new_df = pd.DataFrame(new_events)
        if st.session_state['df'].empty:
            st.session_state['df'] = new_df
        else:
            st.session_state['df'] = pd.concat([st.session_state['df'], new_df], ignore_index=True)
            
        st.success(f"⚡ {attack_type} completed! Refreshing state...")
        time.sleep(0.5)
        st.rerun()

# TAB 4: Blue Team & ITDR Dashboard
with tab4:
    st.header("🛡️ Blue Team & ITDR Monitoring Dashboard")
    st.caption("Real-time Event Feed, Entra ID Sign-in Logs & Microsoft Smart Lockout Watchlist")
    
    if 'df' in st.session_state and not st.session_state['df'].empty:
        df = st.session_state['df']
        
        user_col = 'TargetUserName' if 'TargetUserName' in df.columns else ('user' if 'user' in df.columns else 'TargetUser')
        event_col = 'EventID' if 'EventID' in df.columns else ('event_id' if 'event_id' in df.columns else None)
        ip_col = 'IpAddress' if 'IpAddress' in df.columns else ('source_ip' if 'source_ip' in df.columns else 'IP')

        st.subheader("🔒 Active Lockout Watchlist (Smart Lockout Triggered)")
        
        if event_col and user_col in df.columns:
            lockout_users = df[df[event_col] == 4625][user_col].value_counts()
            locked_accounts = lockout_users[lockout_users >= 3].index.tolist()
        else:
            locked_accounts = []
        
        if len(locked_accounts) > 0:
            cols = st.columns(min(len(locked_accounts), 4))
            for idx, account in enumerate(locked_accounts):
                with cols[idx % 4]:
                    st.error(f"👤 **Account:** `{account}`\n\n🚨 **Status:** LOCKED (AADSTS50053)\n\n📍 **Attempts:** {lockout_users[account]} Failures")
        else:
            st.success("✅ No accounts currently locked by Microsoft Smart Lockout threshold.")

        st.markdown("---")
        
        col_feed, col_logs = st.columns([1, 1.2])
        
        with col_feed:
            st.subheader("⚡ Live Incident Feed")
            severity_filter = st.selectbox("Filter by Severity", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
            
            for idx, row in df.iterrows():
                event_id = row.get(event_col, 4625)
                user = row.get(user_col, "Unknown")
                ip = row.get(ip_col, "127.0.0.1")
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
        user_col = 'TargetUserName' if 'TargetUserName' in df.columns else ('user' if 'user' in df.columns else 'TargetUser')
        event_col = 'EventID' if 'EventID' in df.columns else ('event_id' if 'event_id' in df.columns else None)

        col_left, col_right = st.columns(2)
        
        with col_left:
            st.subheader("🎯 Top 5 Targeted Accounts")
            if event_col and user_col in df.columns:
                failed_df = df[df[event_col] == 4625]
                if len(failed_df) > 0:
                    top_users = failed_df[user_col].value_counts().head(5).reset_index()
                    top_users.columns = ['Account Name', 'Failed Attempts']
                    
                    fig_bar = px.bar(top_users, x='Failed Attempts', y='Account Name', orientation='h', color='Failed Attempts', color_continuous_scale='Reds', text='Failed Attempts')
                    st.plotly_chart(fig_bar, use_container_width=True)
                else:
                    st.info("No failed logon attempts recorded.")

        with col_right:
            st.subheader("📊 Failure vs Success Ratio")
            if event_col:
                status_counts = df[event_col].map({4625: 'FAILED (4625)', 4624: 'SUCCESS (4624)'}).value_counts().reset_index()
                status_counts.columns = ['Logon Status', 'Event Count']
                
                fig_pie = px.pie(status_counts, names='Logon Status', values='Event Count', color='Logon Status', color_discrete_map={'FAILED (4625)':'#ef553b', 'SUCCESS (4624)':'#00cc96'}, hole=0.4)
                st.plotly_chart(fig_pie, use_container_width=True)

        st.markdown("---")
        st.subheader("📈 Attack Intensity Timeline & Velocity")
        df_timeline = df.copy()
        df_timeline['Attempt_Sequence'] = df_timeline.index + 1
        
        if event_col:
            df_timeline['Event_Type'] = df_timeline[event_col].apply(lambda x: "Failed Logon (4625)" if x == 4625 else "Success Logon (4624)")
            fig_line = px.line(df_timeline, x='Attempt_Sequence', y=df_timeline.index, color='Event_Type', markers=True, color_discrete_map={'Failed Logon (4625)':'#d62728', 'Success Logon (4624)':'#2ca02c'})
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

# TAB 8: Security Audit Report Generator (NEW MODULE)
with tab8:
    st.header("📄 Automated PDF Security Audit Report Generator")
    st.caption("Generate an official, executive-ready PDF Audit Report containing attack telemetry, risk scoring, and AI mitigation history.")

    if 'df' in st.session_state and not st.session_state['df'].empty:
        df = st.session_state['df']
        resolved_users = st.session_state.get('resolved_users', set())
        
        event_col = 'EventID' if 'EventID' in df.columns else ('event_id' if 'event_id' in df.columns else None)
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

        # Generate PDF Bytes
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
