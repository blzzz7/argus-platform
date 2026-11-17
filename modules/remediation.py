"""Deterministic SOAR steps with explicit approval, audit, and duplicate prevention."""
from uuid import UUID
from modules import config
from modules.authorization import require
from modules.graph_client import GraphClient, secrets
from modules.notifications import alert
from modules.connectors.base import https_url

TIERS = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}


def execute(run_id, user, ip, severity, approved=False):
    p = require("remediate")
    run_id = str(UUID(run_id))
    if not approved or severity not in TIERS or not user:
        raise ValueError("An approved, valid playbook and target are required.")
    tier = TIERS[severity]
    simulation = not config.ENABLE_REAL_REMEDIATION
    settings = secrets() if not simulation and tier else {}
    protected = {u.casefold() for u in settings.get("protected_accounts", [])}
    if user.casefold() in protected:
        raise PermissionError("Protected account cannot be remediated.")
    if not simulation and tier >= 1 and not protected:
        raise RuntimeError("Configure protected emergency accounts before destructive responses.")
    if not simulation and tier == 3 and "protected_networks" not in settings:
        raise RuntimeError("Configure protected network ranges before Tier 3 responses.")
    detail = {"user": user, "ip": ip, "severity": severity, "simulation": simulation, "steps": []}
    table = p.client.table("playbook_runs")
    # Unique run ID reserves execution. Duplicate inserts fail before Graph writes.
    table.insert({"id": run_id, "tenant_id": p.tenant_id, "actor_id": p.user_id, "status": "RUNNING", "detail": detail}).execute()
    status = "SIMULATED" if simulation else "SUCCEEDED"
    try:
        graph = GraphClient(settings) if not simulation and tier else None
        target = user
        if graph:
            resolved = graph.resolve(user)
            protected_ids = {graph.resolve(account)["id"] for account in settings["protected_accounts"]}
            if resolved["id"] in protected_ids:
                raise PermissionError("Target resolves to a protected emergency account.")
            target = resolved["id"]
            detail["resolved_user_id"] = target
        if not simulation and tier == 3:
            https_url(settings["soc_webhook_url"])
            graph.block_ip(ip, validate_only=True)
        steps = [("Revoke sessions", lambda: graph.revoke(target)), ("Disable account", lambda: graph.disable(target)), ("Block IP", lambda: graph.block_ip(ip)), ("Notify SOC", lambda: alert(settings, f"Critical identity response completed for {user}; IP {ip}."))]
        for name, operation in steps[:4 if tier == 3 else tier]:
            detail["steps"].append({"action": name, "status": "RUNNING"})
            checkpoint = table.update({"detail": detail}).eq("tenant_id", p.tenant_id).eq("id", run_id).execute()
            if not checkpoint.data:
                raise PermissionError("Execution record is no longer writable.")
            if not simulation:
                operation()
            detail["steps"][-1]["status"] = "SIMULATED" if simulation else "SUCCEEDED"
            table.update({"detail": detail}).eq("tenant_id", p.tenant_id).eq("id", run_id).execute()
    except Exception:
        status = "FAILED"
        if detail["steps"] and detail["steps"][-1]["status"] == "RUNNING":
            detail["steps"][-1]["status"] = "UNKNOWN"
        detail["error"] = "Response stopped. The last action may have completed upstream; reconcile state before creating a new run."
        raise
    finally:
        table.update({"status": status, "detail": detail}).eq("tenant_id", p.tenant_id).eq("id", run_id).execute()
        p.client.table("audit_events").insert({"tenant_id": p.tenant_id, "actor_id": p.user_id, "action": "PLAYBOOK_" + status, "detail": detail}).execute()
    return {"status": status, **detail}


def response_target(user):
    """Read-only eligibility check; execution repeats it before Graph mutations."""
    require("remediate")
    if not config.ENABLE_REAL_REMEDIATION:
        raise RuntimeError("Real remediation is disabled.")
    settings = secrets()
    if not settings.get("protected_accounts"):
        raise RuntimeError("Configure protected emergency accounts before remediation.")
    if user.casefold() in {str(account).casefold() for account in settings["protected_accounts"]}:
        raise PermissionError("Protected account cannot be remediated.")
    graph = GraphClient(settings)
    target = graph.resolve(user)
    if target["id"] in {graph.resolve(account)["id"] for account in settings["protected_accounts"]}:
        raise PermissionError("Protected account cannot be remediated.")
    return graph, target


def respond_to_incident(incident_id, action):
    """Execute an approved response and persist only confirmed Graph outcomes."""
    from urllib.parse import quote
    p = require("remediate")
    if not config.ENABLE_REAL_REMEDIATION:
        raise RuntimeError("Real remediation is disabled. Set ENABLE_REAL_REMEDIATION=true explicitly to execute Graph actions.")
    if action not in {"revoke", "block", "both"}:
        raise ValueError("Unknown response action.")
    rows = p.client.table("events").select("*").eq("tenant_id", p.tenant_id).eq("id", incident_id).execute().data
    if not rows:
        raise PermissionError("Incident does not belong to this workspace.")
    graph, target = response_target(rows[0]["TargetUserName"])
    path = "users/" + quote(target["id"], safe="")
    responses = []
    for step in (["revoke", "block"] if action == "both" else [action]):
        result = graph.request("POST" if step == "revoke" else "PATCH", path + "/revokeSignInSessions" if step == "revoke" else path, {} if step == "revoke" else {"accountEnabled": False})
        if step == "revoke" and result.get("value") is not True:
            raise RuntimeError("Graph did not confirm session revocation.")
        responses.append({"action": step, "http_status": graph.last_status, "response": result})
        values = {"status": "Remediated" if action != "both" or step == "block" else "Partially Remediated", "action_taken": "Session Revoked & Account Blocked" if action == "both" and step == "block" else "Revoked" if step == "revoke" else "Blocked"}
        p.client.table("events").update(values).eq("tenant_id", p.tenant_id).eq("id", incident_id).execute()
        p.client.table("audit_events").insert({"tenant_id": p.tenant_id, "actor_id": p.user_id, "action": "INCIDENT_RESPONSE", "detail": {"incident_id": incident_id, **responses[-1]}}).execute()
    return responses
