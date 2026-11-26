"""Public privacy information for the deployed Argus workspace."""
import streamlit as st


def render_privacy_policy():
    with st.container(key="privacy_policy"):
        st.title("Privacy Policy")
        st.markdown("""
Argus ITDR processes identity security data to help organizations investigate suspicious sign-ins and respond to account threats. This notice describes how the workspace handles data. Your organization can provide deployment-specific privacy terms.

## Data Collection

The workspace may process account identifiers and role assignments, sign-in timestamps, source IP addresses, authentication methods, event outcomes, and audit records. This information comes from configured integrations, ingested telemetry, uploaded files, and workspace activity.

## Microsoft Entra ID & Graph API Permissions

When Microsoft Entra ID is connected, Argus uses the Microsoft Graph permissions granted to the configured application. Granted permissions determine which directory information it can read. Where real response is enabled, authorized administrators can request actions such as revoking sessions or disabling an account, subject to Graph permissions and workspace safeguards.

## Telemetry & SIEM Processing

Argus uses telemetry for investigations, detection rules, and reports. Configured SIEM integrations can receive or expose security events for ingestion and verification. When an authorized user requests AI assistance, the configured provider can receive the submitted question and relevant tenant evidence. Keep credentials and unrelated personal information out of chat prompts and uploaded data.

## Data Retention

Retention depends on your organization's deployment and its storage, SIEM, backup, and AI-provider settings. Consult your workspace administrator for applicable retention periods and procedures for deletion or export.

## Security & Encryption

Argus encrypts saved connector settings using the deployment's encryption key. Access to workspace actions is role-based. Transport security and underlying storage protections depend on the deployment and the configuration of connected services.

## Tenant Isolation

Workspace access is tied to verified tenant membership or the configured local workspace. Tenant identifiers scope stored workspace records, and workspace roles control access to data and response actions.

## Contact

Contact your workspace administrator or your organization's privacy contact for questions about data handling, access, correction, or deletion.
""")
        if st.button("Back to SOC workspace", key="privacy_back"):
            st.query_params["page"] = "app"
            st.rerun()
