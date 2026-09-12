import streamlit as st

st.set_page_config(page_title="Argus ITDR Platform", layout="wide")
st.title("🛡️ Argus ITDR Platform")

# Sol tərəf: Rejim seçimi
st.sidebar.header("🕹️ Rejim Seçimi")
mode = st.sidebar.radio("Modu seçin:", ["Simulation Mode", "Live Detection", "Forensics"])

col1, col2 = st.columns([1, 1])

# Orta panel: Attack Simulation & Logs
with col1:
    st.subheader("⚡ Attack Simulation")
    if st.button("🚀 Start Attack"):
        st.warning("Hücum simulyasiyası başladıldı...")
    
    st.subheader("📋 Log Pəncərəsi")
    st.text_area("Sistem Logları:", value="[INFO] Entra ID logları gözlənilir...\n[INFO] Splunk connector active.", height=180)

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
        st.success("Sigma qaydası uğurla Splunk SIEM-ə tətbiq olundu!")
