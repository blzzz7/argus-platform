"""Compact account response workspace with native Streamlit controls."""
import pandas as pd
import streamlit as st
from modules.authorization import current
from modules.remediation import respond_to_incident


def response_center(rows):
    from modules import config
    from modules.threat_center import compromised_alerts, generate_sigma, generate_actions
    st.header("Threat Response & AI Center")
    if rows is None:
        return
    alerts = compromised_alerts(rows)
    if not alerts:
        st.info("No compromised or high-risk account alerts.")
        return
    selected_user = st.selectbox("Compromised User Alert", [a["user"] for a in alerts])
    alert = next(a for a in alerts if a["user"] == selected_user)
    identity = (current().tenant_id, selected_user, str(alert["incident_id"]))
    if st.session_state.get("center_selection") != identity:
        st.session_state["center_selection"] = identity
        st.session_state["center_approval"] = False
        st.session_state.pop("center_sigma", None)
        st.session_state.pop("center_actions", None)
        st.session_state.pop("center_response", None)
    st.dataframe(pd.DataFrame([{
        "UPN": alert["user"], "Source IP": alert["source_ip"], "Failed": alert["failed"],
        "Success": alert["success"], "Attack pattern": alert["pattern"], "Timestamp (UTC)": alert["timestamp"],
    }]), hide_index=True, width="stretch")
    writable = current().role in {"Admin", "SOC Analyst"}
    st.subheader("AI Sigma Rule Generator")
    if st.button("Generate Sigma Rule", disabled=not writable, width="content"):
        try:
            with st.spinner("Generating Sigma rule..."):
                st.session_state["center_sigma"] = generate_sigma(alert)
        except Exception as error:
            st.error(str(error))
    if st.session_state.get("center_sigma"):
        st.code(st.session_state["center_sigma"], language="yaml")
        st.download_button("Download Sigma .yml", st.session_state["center_sigma"], "argus-account-detection.yml", "application/yaml")
    st.subheader("Live Session Revoke & Account Disable")
    live = current().role == "Admin" and config.ENABLE_REAL_REMEDIATION and alert["incident_id"] is not None
    if current().role != "Admin":
        st.caption("Admin access required.")
    elif not config.ENABLE_REAL_REMEDIATION:
        st.caption("Real remediation is disabled.")
    approved = st.checkbox("I approve session revocation and account disable", key="center_approval", disabled=not live)
    if st.button("Revoke Sessions & Disable Account", disabled=not live or not approved, width="content"):
        try:
            st.session_state["center_response"] = respond_to_incident(alert["incident_id"], "both")
        except Exception as error:
            st.error(str(error))
    if st.session_state.get("center_response"):
        st.json(st.session_state["center_response"])
        st.success("Graph confirmed the response. Incident and audit updated.")
    st.subheader("AI Automated Playbook & Action Outcomes")
    if st.button("Generate Possible Actions", disabled=not writable, width="content"):
        try:
            with st.spinner("Generating action outcomes..."):
                st.session_state["center_actions"] = generate_actions(alert)
        except Exception as error:
            st.error(str(error))
    if st.session_state.get("center_actions"):
        st.dataframe(st.session_state["center_actions"], hide_index=True, width="stretch")


