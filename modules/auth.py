"""Supabase-managed credentials; verified membership on every Streamlit rerun."""
import time

from modules import config
from modules.authorization import Principal, bind


def new_client():
    from supabase import create_client
    if not config.SUPABASE_URL or not config.SUPABASE_ANON_KEY:
        raise RuntimeError("Configure SUPABASE_URL and SUPABASE_ANON_KEY.")
    key = config.SUPABASE_ANON_KEY
    if key.startswith("sb_secret_"):
        raise RuntimeError("A publishable Supabase key is required.")
    if key.count(".") == 2:
        import base64
        import json
        payload = key.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        if claims.get("role") != "anon":
            raise RuntimeError("An anon Supabase key is required.")
    return create_client(config.SUPABASE_URL, key)


def login(state, email, password):
    import hmac
    import hashlib
    valid_local_password = (bool(config.ADMIN_PASS) and hmac.compare_digest(password, config.ADMIN_PASS)) or (bool(config.ADMIN_HASH) and hmac.compare_digest(hashlib.sha256(password.encode()).hexdigest(), config.ADMIN_HASH))
    if config.ADMIN_USER and hmac.compare_digest(email.strip(), config.ADMIN_USER) and valid_local_password:
        state.pop("auth_client", None)
        state.update(authenticated=True, auth_local=True, auth_username=email.strip(), auth_started_at=time.time())
        return
    state.pop("auth_local", None)
    client = new_client()
    result = client.auth.sign_in_with_password({"email": email.strip(), "password": password})
    if not result.session:
        raise PermissionError("Sign-in failed.")
    state["auth_client"] = client
    state["auth_expires_at"] = result.session.expires_at
    state["authenticated"] = True
    state["auth_username"] = email.strip()
    state["auth_started_at"] = time.time()


def logout(state):
    client = state.get("auth_client")
    try:
        if client:
            client.auth.sign_out()
    except Exception:
        pass
    finally:
        for key in list(state):
            if key not in {"login_attempts", "lockout_until"}:
                del state[key]
        state["authenticated"] = False
        state["auth_username"] = None
        bind(None)


def restore(state):
    bind(None)
    if state.get("auth_local") and state.get("authenticated"):
        if time.time() - state.get("auth_started_at", 0) > config.AUTH_MAX_SESSION_SECONDS:
            logout(state)
            return []
        identity = ("local-admin", config.LOCAL_TENANT_ID)
        if state.get("bound_identity") != identity:
            for key in list(state):
                if not key.startswith("auth_") and key not in {"authenticated", "login_attempts", "lockout_until"}:
                    del state[key]
            state["bound_identity"] = identity
        state.update(active_tenant_id=config.LOCAL_TENANT_ID, auth_role="Admin")
        client = state.get("auth_service_client")
        if client is None and config.SUPABASE_URL and config.SUPABASE_KEY:
            from supabase import create_client
            client = create_client(config.SUPABASE_URL, config.SUPABASE_KEY)
            state["auth_service_client"] = client
        from uuid import NAMESPACE_URL, uuid5
        actor = str(uuid5(NAMESPACE_URL, "argus:local-admin:" + config.ADMIN_USER))
        bind(Principal(actor, config.LOCAL_TENANT_ID, "Admin", client, local_admin=True))
        return [{"tenant_id": config.LOCAL_TENANT_ID, "role": "Admin"}]
    if not state.get("authenticated") or not state.get("auth_client"):
        return []
    try:
        client = state["auth_client"]
        if time.time() - state.get("auth_started_at", 0) > config.AUTH_MAX_SESSION_SECONDS:
            raise PermissionError("Session expired.")
        if time.time() >= state.get("auth_expires_at", 0) - 60:
            result = client.auth.refresh_session()
            state["auth_expires_at"] = result.session.expires_at
        user = client.auth.get_user().user
        if not user:
            raise PermissionError("Invalid session.")
        # Enforce AAL2 for production; TOTP challenge is exposed by the login UI.
        assurance = client.auth.mfa.get_authenticator_assurance_level()
        if config.AUTH_REQUIRE_MFA and assurance.current_level != "aal2":
            state["auth_mfa_pending"] = True
            return []
        state["auth_mfa_pending"] = False
        memberships = client.table("tenant_memberships").select("tenant_id,role").eq("user_id", user.id).execute().data or []
        selected = state.get("active_tenant_id")
        membership = next((m for m in memberships if m["tenant_id"] == selected), None)
        if membership is None and memberships:
            membership = memberships[0]
        if membership is None:
            raise PermissionError("No tenant membership.")
        identity = (user.id, membership["tenant_id"])
        if state.get("bound_identity") != identity:
            for key in list(state):
                if not key.startswith("auth_") and key not in {"authenticated", "login_attempts", "lockout_until"}:
                    del state[key]
            state["bound_identity"] = identity
        state["active_tenant_id"] = membership["tenant_id"]
        state["auth_role"] = membership["role"]
        bind(Principal(user.id, membership["tenant_id"], membership["role"], client))
        return memberships
    except Exception:
        logout(state)
        return []


def signup(state, email, password, organization):
    if not organization.strip() or len(password) < 12:
        raise ValueError("Enter an organization name and a password of at least 12 characters.")
    client = new_client()
    result = client.auth.sign_up({"email": email.strip(), "password": password,
                               "options": {"data": {"organization_name": organization.strip()}}})
    if result.session:
        state.pop("auth_local", None)
        state.update(auth_client=client, auth_expires_at=result.session.expires_at,
                     authenticated=True, auth_username=email.strip(), auth_started_at=time.time())
    return bool(result.session)
