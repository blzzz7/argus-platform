import streamlit as st
import json
import time
from modules.log_generator import generate_entra_logs

st.set_page_config(page_title="Argus ITDR Platform", layout="wide")
st.title("🛡️ Argus ITDR Platform")

# Sol tərəf: Rejim seçimi
st.sidebar.header("🕹️ Rejim Seçimi")
mode = st.sidebar.radio("Modu seçin:", ["Simulation Mode", "Live Detection", "Forensics"])

col1, col2 = st.columns([1, 1])

# Session state initialization for logs
if "logs" not in st.session_state:
    st.session_state.logs = "[INFO] Entra ID logları gözlənilir...\n[INFO] Splunk connector active."

# Orta panel: Attack Simulation & Logs
with col1:
    st.subheader("⚡ Attack Simulation")
    if st.button("🚀 Start Attack"):
        new_log = generate_entra_logs()
        formatted_log = json.dumps(new_log, indent=2)
        st.session_state.logs = f"[ALERT] Simulated Attack Event Generated:\n{formatted_log}\n\n" + st.session_state.logs
        st.warning("Hücum simulyasiyası işə salındı və log yaradıldı!")
    
    st.subheader("📋 Log Pəncərəsi")
    st.text_area("Sistem Logları:", value=st.session_state.logs, height=250)

# Sağ panel: AI Sigma Rule & Deploy Button
with col2:
    st.subheader("🤖 AI Generated Sigma Rule")
    sigma_code = """title: Suspicious Entra ID Privilege Escalation
logsource:
  product: azure
  service: entra_id
detection:
  selection:
    OperationName: "Add member to role"
  condition: selection
level: high"""
    st.code(sigma_code, language="yaml")
    
    if st.button("🔴 Deploy to Splunk"):
        with st.spinner("Splunk API ilə əlaqə qurulur..."):
            time.sleep(1)
        st.success("✅ Sigma qaydası Splunk SIEM-ə uğurla inteqrasiya olundu!")
        st.session_state.logs = f"[SUCCESS] Sigma rule deployed to Splunk SIEM at {time.strftime('%H:%M:%S')}\n" + st.session_state.logs
