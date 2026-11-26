"""Compact account response workspace with native Streamlit controls."""
import re
import streamlit as st
from modules.authorization import current
from modules.remediation import respond_to_incident, response_target


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
    tenant = current().tenant_id
    identities = [(tenant, alert["user"], str(alert["incident_id"])) for alert in alerts]
    selected = st.session_state.get("center_selection")
    selected_index = identities.index(selected) if selected in identities else 0

    def select_alert(index):
        st.session_state["center_clicked_alert"] = identities[index]

    clicked = st.session_state.pop("center_clicked_alert", None)
    if clicked in identities:
        selected_index = identities.index(clicked)
    with st.container(key="account_alerts"):
        st.subheader("Compromised User Alerts")
        for index, item in enumerate(alerts):
            active = index == selected_index
            user = re.sub(r"([^\w@.+-])", r"\\\1", " ".join(str(item["user"]).split()))
            ip = re.sub(r"([^\w.:+-])", r"\\\1", " ".join(str(item["source_ip"]).split()))
            st.button(
                f"**{user}**{' · Selected' if active else ''}  \n"
                f"*{item['pattern']}*  \n"
                f"Source IP {ip} · Failed {item['failed']} · Success {item['success']}",
                key=f"account_alert_{index}",
                type="primary" if active else "secondary",
                on_click=select_alert,
                args=(index,),
                width="stretch",
            )
    alert = alerts[selected_index]
    identity = identities[selected_index]
    if st.session_state.get("center_selection") != identity:
        st.session_state["center_selection"] = identity
        st.session_state.pop("center_sigma", None)
        st.session_state.pop("center_actions", None)
        st.session_state.pop("center_response", None)
    st.caption(f"Selected alert timestamp (UTC) · {alert['timestamp']}")
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
    if live:
        try:
            response_target(alert["user"])
        except Exception as error:
            live = False
            st.caption(str(error))
    if st.button("Revoke Sessions & Disable Account", disabled=not live, width="content"):
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


