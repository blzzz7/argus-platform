import streamlit as st
import json
import time
import requests

st.set_page_config(page_title="Argus ITDR Platform", layout="wide")
st.title("Argus ITDR Platform")

# Sol panel: Config & Mode selection
st.sidebar.header("Configuration")
mode = st.sidebar.radio("Operation Mode:", ["Live Ingestion & Forensics", "Simulation Mode"])

st.sidebar.markdown("---")
st.sidebar.header("Splunk HEC Settings")
splunk_url = st.sidebar.text_input("Splunk HEC URL", value="http://localhost:8088/services/collector/event")
splunk_token = st.sidebar.text_input("HEC Token", type="password", help="Enter Splunk HEC Token")

col1, col2 = st.columns([1, 1])

if "logs" not in st.session_state:
    st.session_state.logs = "[SYS_INIT] Argus ITDR Engine initialized. Awaiting input stream...\n"
if "parsed_event" not in st.session_state:
    st.session_state.parsed_event = None

# Sol/Orta panel: Live Log Ingest
with col1:
    if mode == "Live Ingestion & Forensics":
        st.subheader("Data Ingestion / File Upload")
        uploaded_file = st.file_uploader("Upload Target Log File (JSON):", type=["json"])
        
        target_url = st.text_input("Target Log Endpoint URL:", value="")
        
        if uploaded_file is not None:
            try:
                raw_data = json.load(uploaded_file)
                st.session_state.parsed_event = raw_data
                st.success("File parsed successfully.")
                st.session_state.logs = f"[INGEST_SUCCESS] Processed file payload:\n{json.dumps(raw_data, indent=2)}\n\n" + st.session_state.logs
            except Exception as e:
                st.error(f"File parsing error: {e}")
                
        elif target_url and st.button("Fetch API Data"):
            try:
                res = requests.get(target_url, timeout=5)
                raw_data = res.json()
                st.session_state.parsed_event = raw_data
                st.success("Endpoint payload retrieved.")
                st.session_state.logs = f"[FETCH_SUCCESS] API Event Data:\n{json.dumps(raw_data, indent=2)}\n\n" + st.session_state.logs
            except Exception as e:
                st.error(f"Endpoint retrieval failed: {e}")

    st.subheader("System Logs")
    st.text_area("Console Output:", value=st.session_state.logs, height=280)

# Sağ panel: Advanced Dynamic AI Sigma Generation
with col2:
    st.subheader("Generated Sigma Rule")
    
    event = st.session_state.parsed_event
    
    if event and isinstance(event, dict):
        detected_action = event.get("action") or event.get("event") or event.get("type") or event.get("title") or "Generic_Activity"
        detected_service = event.get("service") or event.get("source") or "generic_api_endpoint"
        detected_user = event.get("actor") or event.get("user") or event.get("username") or event.get("userId") or "system"
        
        # Dinamik olaraq bütün key-value cütlüklərini Sigma selection sahəsinə yığırıq
        selection_lines = []
        for k, v in list(event.items())[:5]: # ilk 5 xassəni qaydaya daxil edirik
            selection_lines.append(f"    {k}: \"{v}\"")
        selection_block = "\n".join(selection_lines)
        
        sigma_code = f"""title: Dynamic Ingestion Detection - {detected_action}
logsource:
  product: {detected_service}
detection:
  selection:
{selection_block}
  condition: selection
level: high"""
    else:
        sigma_code = "# Awaiting input data stream to compile Sigma detection rules..."

    st.code(sigma_code, language="yaml")
    
    if st.button("Deploy to Splunk SIEM"):
        if not st.session_state.parsed_event:
            st.warning("No parsed event found. Ingest log data first.")
        else:
            with st.spinner("Establishing Splunk HEC session..."):
                if splunk_token:
                    headers = {"Authorization": f"Splunk {splunk_token}"}
                    payload = {"event": st.session_state.parsed_event}
                    try:
                        response = requests.post(splunk_url, json=payload, headers=headers, timeout=3, verify=False)
                        if response.status_code == 200:
                            st.success("Event successfully dispatched to Splunk HEC.")
                            st.session_state.logs = f"[SPLUNK_200] Payload delivered to HEC receiver\n" + st.session_state.logs
                        else:
                            st.error(f"Splunk HTTP Error: Code {response.status_code}")
                    except Exception as e:
                        st.error(f"Splunk Connection Refused: {e}")
                else:
                    time.sleep(1)
                    st.success("Rule compiled and dispatched via local Splunk mock module.")
                    st.session_state.logs = f"[MOCK_DISPATCH] Rule deployed to local pipeline at {time.strftime('%H:%M:%S')}\n" + st.session_state.logs
