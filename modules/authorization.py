"""Trusted request context and service-level permissions."""
from contextvars import ContextVar
from dataclasses import dataclass


@dataclass(frozen=True)
class Principal:
    user_id: str
    tenant_id: str
    role: str
    client: object
    local_admin: bool = False


_principal = ContextVar("argus_principal", default=None)
ROLES = {"Admin", "SOC Analyst", "Read-Only Auditor"}


def bind(principal):
    _principal.set(principal)


def current():
    value = _principal.get()
    if value is None or value.role not in ROLES:
        raise PermissionError("An authenticated tenant membership is required.")
    return value


def require(action="read"):
    principal = current()
    if action not in {"read", "write", "admin", "remediate", "sandbox"}:
        raise PermissionError("Unknown permission.")
    permitted = {"Admin"} if action in {"admin", "remediate", "sandbox"} else ROLES if action == "read" else {"Admin", "SOC Analyst"}
    if principal.role not in permitted:
        raise PermissionError("Your role cannot perform this action.")
    return principal


def audit(action, detail=None):
    principal = require("write")
    if principal.local_admin:
        principal.client.table("tenants").upsert({"id": principal.tenant_id, "name": "Local workspace"}, on_conflict="id", ignore_duplicates=True).execute()
    principal.client.table("audit_events").insert({
        "tenant_id": principal.tenant_id, "actor_id": principal.user_id,
        "action": action, "detail": detail or {},
    }).execute()
