"""Live SOC workflows; Streamlit stays a thin presentation layer."""
from datetime import datetime, time, timedelta, timezone
import pandas as pd
import plotly.express as px
import streamlit as st
from modules.authorization import current, require
from modules.db import incident_records, contained_accounts
from modules.threat_center import compromised_alerts, compute_severity
from modules.connectors.live import health_checks, pipeline_test
from modules.reports import build_report


def records():
    try:
        return incident_records()
    except Exception:
        st.error("Workspace data or a configured service is unavailable.")
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
    try:
        contained = contained_accounts(rows)
    except Exception:
        contained = "N/A"
    try:
        alerts = compromised_alerts(rows)
        metrics = st.columns(4)
        metrics[0].metric("Total events", len(rows))
        metrics[1].metric("Detected incidents", len(alerts))
        metrics[2].metric("High / Critical threats", sum(compute_severity(a) in {"HIGH", "CRITICAL"} for a in alerts))
        metrics[3].metric("Contained accounts (admin-approved)", contained)
    except Exception:
        st.info("Dashboard metrics are unavailable.")
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
        width="stretch",
    )
    frame["Attack type"] = frame.apply(lambda r: r.get("attack_type") or r.get("AuthMethod") or "Unclassified", axis=1)
    counts = frame["Attack type"].value_counts().rename_axis("Attack type").reset_index(name="Events")
    left, right = st.columns(2)
    left.plotly_chart(px.bar(counts, x="Attack type", y="Events", title="Attack type distribution"), width="stretch")
    users = frame["TargetUserName"].value_counts().head(10).rename_axis("Target user").reset_index(name="Events")
    right.plotly_chart(px.bar(users, x="Events", y="Target user", orientation="h", title="Most targeted users"), width="stretch")
    query = st.text_input("Filter incident table", placeholder="Target user, severity, attack type, or status")
    filtered = frame[frame.astype(str).apply(lambda column: column.str.contains(query, case=False, regex=False)).any(axis=1)] if query else frame
    st.dataframe(filtered, hide_index=True, width="stretch")
    with st.expander("Current session telemetry"):
        st.dataframe(st.session_state.get("df", pd.DataFrame()), hide_index=True)


from modules.threat_center_ui import response_center


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
            totals = report_aggregates(rows)
            summary = (f"The selected period contains {totals['total_records']} events across "
                       f"{totals['targeted_users']} accounts. {totals['high_critical']} flagged accounts "
                       "have High or Critical severity.")
            html, pdf = build_report(rows, summary, current().tenant_id, f"{start} to {end}")
            st.session_state["live_report"] = {"html": html, "pdf": pdf}
        except Exception:
            st.error("The security audit report could not be generated.")
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
                    st.json({"confirmed": result["confirmed"], "latency_ms": result["latency_ms"],
                             "test_event_id": result["payload"]["id"]})
                    if result["confirmed"]:
                        st.success(f"Indexing confirmed · {result['latency_ms']} ms")
                    else:
                        st.warning("Delivery completed; indexing is not confirmed. Check Wazuh indexing before retrying.")
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
        else:
            response_center(rows)
    except Exception:
        st.error("Workspace data or a configured service is unavailable.")



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
            ok, _ = integrations.save_integration(provider, provider.title(), settings, enabled)
            if ok:
                st.success("Tenant connector saved.")
            else:
                st.error("The connector could not be saved. Check its configuration.")
    if provider in {"splunk", "sentinel"} and record.get("enabled") and st.button("Send connector test event"):
        from uuid import uuid4
        event = {"id": str(uuid4()), "tenant_id": current().tenant_id, "timestamp": datetime.now(timezone.utc).isoformat(), "source": "argus-siem-test", "event_id": 4625}
        dispatch(event, provider, existing)
        st.success("Connector test event delivered.")


def report_aggregates(rows):
    return {"total_records": len(rows), "high_critical": sum(compute_severity(a) in {"HIGH", "CRITICAL"} for a in compromised_alerts(rows)), "remediated": sum(r.get("status") == "Remediated" for r in rows), "targeted_users": len({r.get("TargetUserName") for r in rows if r.get("TargetUserName")})}
