"""Compact account response workspace with native Streamlit controls."""
import re
from datetime import datetime, timezone
import streamlit as st
from modules.authorization import audit, current, require
from modules.db import containment_audit
from modules.remediation import respond_to_incident, response_target
from modules.threat_center import compute_severity, mitre_techniques


def response_center(rows):
    from modules import config
    from modules.threat_center import compromised_alerts, generate_sigma, generate_actions
    st.header("Threat Response & AI Center")
    if rows is None:
        return
    try:
        alerts = compromised_alerts(rows)
    except Exception:
        st.error("Account alerts are unavailable.")
        return
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
    try:
        with st.container(key="account_alerts"):
            st.subheader("Compromised User Alerts")
            for index, item in enumerate(alerts):
                active = index == selected_index
                user = re.sub(r"([^\w@.+-])", r"\\\1", " ".join(str(item["user"]).split()))
                ip = re.sub(r"([^\w.:+-])", r"\\\1", " ".join(str(item["source_ip"]).split()))
                st.button(
                    f"**{user}**{' · Selected' if active else ''}  \n"
                    f"*{compute_severity(item).title()}* · Why flagged: {item['pattern']}  \n"
                    f"Source IP {ip} · Failed {item['failed']} · Success {item['success']}"
                    + "".join(f"  \n`{label}`" for label, _ in mitre_techniques(item)),
                    key=f"account_alert_{index}",
                    type="primary" if active else "secondary",
                    on_click=select_alert,
                    args=(index,),
                    width="stretch",
                )
    except Exception:
        st.error("Account alerts could not be displayed.")
        return
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
        except Exception:
            st.error("Sigma generation failed. Check the AI connection and try again.")
    if st.session_state.get("center_sigma"):
        st.code(st.session_state["center_sigma"], language="yaml")
        st.download_button("Download Sigma .yml", st.session_state["center_sigma"], "argus-account-detection.yml", "application/yaml")
        try:
            st.caption("Syntax validated with pySigma. Detection effectiveness and false-positive rate must be tested in your SIEM.")
        except Exception:
            pass
    st.subheader("Live Session Revoke & Account Disable")
    mode = "Dry-run (no changes)"
    try:
        if current().role == "Admin" and config.ENABLE_REAL_REMEDIATION:
            mode = st.selectbox("Containment mode", ["Live (real Graph changes)", "Dry-run (no changes)"])
        if current().role == "Admin":
            st.caption("LIVE" if mode.startswith("Live") else "DRY-RUN")
    except Exception:
        st.caption("Containment mode is unavailable.")
    live = mode.startswith("Live") and alert["incident_id"] is not None
    if current().role != "Admin":
        st.caption("Admin access required.")
    elif not config.ENABLE_REAL_REMEDIATION:
        st.caption("Real remediation is disabled.")
    locked = st.session_state.get("center_containment_attempts", set())
    if identity in locked:
        live = False
        st.caption("A live response was already requested for this incident in this session. Review the audit before retrying.")
    if live:
        try:
            response_target(alert["user"])
        except Exception:
            live = False
            st.caption("The target could not be cleared for containment. Check protected accounts and Graph configuration.")
    if st.button("Revoke Sessions & Disable Account", disabled=not live, width="content"):
        try:
            st.session_state["center_containment_attempts"] = locked | {identity}
            st.session_state["center_response"] = respond_to_incident(alert["incident_id"], "both")
            st.session_state["center_response_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        except Exception:
            st.error("Containment did not fully complete. Check Graph and the audit trail before retrying.")
    try:
        if st.session_state.get("center_response"):
            st.text(f"Target: {alert['user']} | Admin: {current().user_id} | UTC: {st.session_state.get('center_response_at', '')}")
            st.dataframe([{"Action": step["action"], "HTTP status": step["http_status"]}
                          for step in st.session_state["center_response"]], hide_index=True)
            st.success("Graph confirmed the response. Incident and audit updated.")
    except Exception:
        st.caption("Response details are unavailable. Review the containment audit.")
    try:
        if current().role == "Admin" and mode.startswith("Dry-run") and st.button("Preview containment (DRY-RUN)", width="content"):
            require("remediate")
            audit("CONTAINMENT_PREVIEW", {"user": alert["user"], "incident_id": alert["incident_id"],
                                          "mode": "DRY-RUN", "status": "DRY_RUN"})
            st.info("DRY-RUN: Live containment would revoke sign-in sessions and disable this account after eligibility checks.")
    except Exception:
        st.error("The dry-run audit could not be saved. No Graph changes were requested.")
    try:
        users = {str(row.get("id")): row.get("TargetUserName") for row in rows}
        entries = []
        for entry in containment_audit(limit=20):
            detail = entry.get("detail") or {}
            preview = entry["action"] == "CONTAINMENT_PREVIEW"
            entries.append({
                "UTC": entry["created_at"], "Admin ID": entry["actor_id"],
                "Target UPN": detail.get("user") or users.get(str(detail.get("incident_id"))) or "Unavailable",
                "Action": detail.get("action") or entry["action"], "Mode": "DRY-RUN" if preview else "LIVE",
                "Status": "DRY_RUN" if preview else "SUCCEEDED", "HTTP status": detail.get("http_status"),
            })
        if entries:
            st.subheader("Recent containment audit")
            st.dataframe(entries, hide_index=True, width="stretch")
    except Exception:
        st.caption("Containment audit is unavailable.")
    st.subheader("AI-Assisted Playbook & Action Outcomes")
    if st.button("Generate Possible Actions", disabled=not writable, width="content"):
        try:
            with st.spinner("Generating action outcomes..."):
                st.session_state["center_actions"] = generate_actions(alert)
        except Exception:
            st.error("Playbook generation failed. Check the AI connection and try again.")
    if st.session_state.get("center_actions"):
        st.dataframe(st.session_state["center_actions"], hide_index=True, width="stretch")


