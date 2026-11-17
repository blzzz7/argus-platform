"""Live SOC workflows; Streamlit stays a thin presentation layer."""
import json
from datetime import datetime, time, timedelta, timezone
import pandas as pd
import plotly.express as px
import streamlit as st
from modules.authorization import current, require
from modules.db import incident_records
from modules.detection import evaluate
from modules.ai_generator import soc_chat
from modules.connectors.live import health_checks, pipeline_test
from modules.remediation import respond_to_incident
from modules.reports import build_report


def records():
    try:
        return incident_records()
    except Exception as error:
        st.error(str(error))
        return None


def timeline_counts(timestamps, interval):
    """Count occupied UTC buckets without materializing gaps in telemetry."""
    buckets = pd.to_datetime(timestamps, utc=True, errors="coerce").dt.floor(
        "h" if interval == "Hour" else "min"
    )
    return buckets.dropna().value_counts().sort_index().rename_axis("Timestamp").reset_index(name="Events")


def dashboard(rows):
    st.header("Blue Team & ITDR Dashboard")
    if st.button("Refresh telemetry"):
        st.rerun()
    if rows is None:
        return
    st.caption("Tenant-scoped Supabase records. Session telemetry appears separately until persisted.")
    metrics = st.columns(3)
    metrics[0].metric("Total detected incidents", len(rows))
    metrics[1].metric("High / Critical threats", sum(str(r.get("severity", "")).lower() in {"high", "critical"} for r in rows))
    metrics[2].metric("Auto-remediated accounts", len({r.get("TargetUserName") for r in rows if r.get("action_taken") in {"Blocked", "Revoked", "Session Revoked & Account Blocked"} or r.get("status") in {"Blocked", "Revoked"}}))
    if not rows:
        st.info("No incidents recorded. Ingest tenant telemetry to begin monitoring.")
        return
    frame = pd.DataFrame(rows)
    frame["Timestamp"] = pd.to_datetime(frame["created_at"], utc=True, errors="coerce")
    interval = st.selectbox("Timeline interval", ["Hour", "Minute"])
    timeline = timeline_counts(frame["Timestamp"], interval)
    st.plotly_chart(
        px.bar(timeline, x="Timestamp", y="Events", title="Observed attack timeline",
               labels={"Timestamp": "Time bucket (UTC)"}).update_xaxes(type="date", nticks=10),
        use_container_width=True,
    )
    frame["Attack type"] = frame.apply(lambda r: r.get("attack_type") or r.get("AuthMethod") or "Unclassified", axis=1)
    counts = frame["Attack type"].value_counts().rename_axis("Attack type").reset_index(name="Events")
    left, right = st.columns(2)
    left.plotly_chart(px.bar(counts, x="Attack type", y="Events", title="Attack type distribution"), use_container_width=True)
    users = frame["TargetUserName"].value_counts().head(10).rename_axis("Target user").reset_index(name="Events")
    right.plotly_chart(px.bar(users, x="Events", y="Target user", orientation="h", title="Most targeted users"), use_container_width=True)
    query = st.text_input("Filter incident table", placeholder="Target user, severity, attack type, or status")
    filtered = frame[frame.astype(str).apply(lambda column: column.str.contains(query, case=False, regex=False)).any(axis=1)] if query else frame
    st.dataframe(filtered, hide_index=True, use_container_width=True)
    with st.expander("Current session telemetry"):
        st.dataframe(st.session_state.get("df", pd.DataFrame()), hide_index=True)


def chat(rows):
    st.header("Interactive Analysis · AI SOC Copilot")
    if rows is None:
        return
    st.caption("Answers use the latest 20 tenant records. AI guidance requires analyst review.")
    if current().role == "Read-Only Auditor":
        st.info("SOC Analyst or Admin access is required for AI requests.")
        return
    history = st.session_state.setdefault("live_chat", [])
    for message in history:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
    prompt = st.chat_input("Ask about observed threats, targeted users, or response priorities")
    if prompt:
        history.append({"role": "user", "content": prompt})
        try:
            with st.spinner("Analyzing tenant evidence..."):
                answer = soc_chat(history, rows[:20])
            history.append({"role": "assistant", "content": answer})
            st.rerun()
        except Exception as error:
            st.error(str(error))
    if st.button("Clear analysis conversation"):
        st.session_state["live_chat"] = []
        st.rerun()


def detection(rows):
    st.header("Threat Detection Engine")
    if rows is None:
        return
    st.caption("Rule: more than five failed logins for one user within a rolling five-minute window.")
    if st.button("Evaluate live rules", disabled=current().role == "Read-Only Auditor"):
        require("write")
        findings = evaluate(rows)
        st.dataframe(findings, hide_index=True)
        for finding in findings:
            for incident_id in finding["incident_ids"]:
                # Admin-only update policy prevents analysts from changing incident classification.
                if current().role == "Admin":
                    current().client.table("events").update({"attack_type": finding["attack_type"], "severity": finding["severity"]}).eq("tenant_id", current().tenant_id).eq("id", incident_id).execute()
        if not findings:
            st.info("No threshold breaches found in timestamped records.")
    if current().role != "Admin":
        st.info("Admin access is required for Microsoft Graph remediation.")
        return
    if not rows:
        return
    selected = st.selectbox("Incident to remediate", rows, format_func=lambda r: f"#{r['id']} · {r.get('TargetUserName', 'Unknown')} · {r.get('status', 'New')}")
    from modules import config
    if st.session_state.get("response_selected_id") != selected["id"]:
        st.session_state["response_selected_id"] = selected["id"]
        st.session_state["response_approved"] = False
    st.subheader("Response preview")
    st.write("Target account: " + str(selected.get("TargetUserName", "Unknown")))
    st.caption("Revoke Sessions invalidates refresh tokens and requires fresh authentication. Block User disables the account and prevents new sign-ins. Revoke & Block executes both actions; an upstream failure may leave a partial response.")
    if config.ENABLE_REAL_REMEDIATION:
        st.warning("Live response mode: approved actions change the selected account in Microsoft Entra ID.")
    else:
        st.info("Real remediation is disabled. Enable it explicitly in configuration before approving a live response.")
    approved = st.checkbox("I approve the selected account response", key="response_approved", disabled=not config.ENABLE_REAL_REMEDIATION)
    for column, label, action in zip(st.columns(3), ["Revoke Sessions", "Block User", "Revoke & Block"], ["revoke", "block", "both"]):
        if column.button(label, disabled=not approved or not config.ENABLE_REAL_REMEDIATION):
            try:
                st.json(respond_to_incident(selected["id"], action))
                st.success("Graph confirmed the response. Incident updated.")
            except Exception as error:
                st.error(str(error))
                response = getattr(error, "response", None)
                if response is not None:
                    try:
                        body = response.json()
                    except ValueError:
                        body = response.text[:4000]
                    st.json({"http_status": response.status_code, "response": body})


def report():
    st.header("Security Audit Report")
    today = datetime.now(timezone.utc).date()
    start = st.date_input("Start date (UTC)", today - timedelta(days=7))
    end = st.date_input("End date (UTC, inclusive)", today)
    if start > end:
        st.error("Start date must precede end date.")
        return
    if st.button("Generate audit report"):
        try:
            rows = incident_records(datetime.combine(start, time.min, timezone.utc).isoformat(), datetime.combine(end + timedelta(days=1), time.min, timezone.utc).isoformat())
            summary = f"The selected period contains {len(rows)} tenant incident records. AI executive summary unavailable."
            if current().role != "Read-Only Auditor" and rows:
                try:
                    summary = soc_chat([{"role": "user", "content": f"Write an executive summary and evidence-based recommendations. Full period aggregates: {json.dumps(report_aggregates(rows))}. The context is a sample of at most 20 records; do not infer population statistics from that sample."}], rows)
                except Exception as error:
                    st.warning("AI summary unavailable: " + str(error))
            html, pdf = build_report(rows, summary, current().tenant_id, f"{start} to {end}")
            st.session_state["live_report"] = {"html": html, "pdf": pdf}
        except Exception as error:
            st.error(str(error))
    result = st.session_state.get("live_report")
    if result:
        import streamlit.components.v1 as components
        components.html(result["html"], height=600, scrolling=True)
        st.download_button("Download executive PDF", result["pdf"], "argus-security-audit.pdf", "application/pdf")
        st.download_button("Download HTML report", result["html"], "argus-security-audit.html", "text/html")


def render(route):
    try:
        if "Integrations" in route or "SIEM Integration Test" in route:
            st.header("Integrations" if "Integrations" in route else "SIEM Pipeline Verification")
            if current().role != "Admin":
                st.info("Admin access is required for integration health checks and configuration.")
                return
            if "SIEM Integration Test" in route:
                st.caption("Sends a real test alert. Confirms its UUID through the tenant's Wazuh index after two seconds.")
                if st.button("Send Test Event to SIEM"):
                    result = pipeline_test()
                    st.json(result)
                    if result["confirmed"]:
                        st.success(f"Indexing confirmed · {result['latency_ms']} ms")
                    else:
                        st.warning("Delivery completed; indexing is not confirmed. Inspect the raw audit response and retry.")
            else:
                st.button("Test Connections")
                for name, result in health_checks().items():
                    (st.success if result["ok"] else st.error)(name + ": " + result["detail"])
                integration_editor()

            return
        if "Security Audit" in route:
            report()
            return
        rows = records()
        if "Blue Team" in route:
            dashboard(rows)
        elif "Threat Detection" in route:
            detection(rows)
        else:
            chat(rows)
    except Exception as error:
        st.error(str(error))



def integration_editor():
    from modules import integrations
    from modules.connectors import dispatch
    st.subheader("Tenant connectors")
    st.caption("Settings are encrypted before storage. Supply credentials only for this workspace.")
    provider = st.selectbox("Connector", ["wazuh", "splunk", "sentinel"])
    record = integrations.get_integration(provider) or {}
    existing = record.get("config", {})
    with st.form("tenant_connector_" + provider):
        enabled = st.checkbox("Enable connector", value=record.get("enabled", False))
        if provider == "wazuh":
            endpoint = st.text_input("Ingest URL", existing.get("ingest_url", ""))
            token = st.text_input("Bridge token (leave blank to retain saved token)", type="password")
            settings = {"ingest_url": endpoint, "ingest_token": token or existing.get("ingest_token", "")}
        elif provider == "splunk":
            endpoint = st.text_input("Splunk HEC URL", existing.get("url", ""))
            token = st.text_input("HEC token (leave blank to retain saved token)", type="password")
            settings = {"url": endpoint, "token": token or existing.get("token", "")}
        else:
            workspace = st.text_input("Sentinel workspace ID", existing.get("workspace_id", ""))
            key = st.text_input("Shared key (leave blank to retain saved key)", type="password")
            settings = {"workspace_id": workspace, "shared_key": key or existing.get("shared_key", "")}
        if st.form_submit_button("Save connector"):
            ok, error = integrations.save_integration(provider, provider.title(), settings, enabled)
            if ok:
                st.success("Tenant connector saved.")
            else:
                st.error(error)
    if provider in {"splunk", "sentinel"} and record.get("enabled") and st.button("Send connector test event"):
        from uuid import uuid4
        event = {"id": str(uuid4()), "tenant_id": current().tenant_id, "timestamp": datetime.now(timezone.utc).isoformat(), "source": "argus-siem-test", "event_id": 4625}
        st.success(dispatch(event, provider, existing))


def report_aggregates(rows):
    return {"total_records": len(rows), "high_critical": sum(str(r.get("severity", "")).lower() in {"high", "critical"} for r in rows), "remediated": sum(r.get("status") == "Remediated" for r in rows), "targeted_users": len({r.get("TargetUserName") for r in rows if r.get("TargetUserName")})}
