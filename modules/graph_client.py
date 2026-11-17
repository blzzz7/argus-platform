"""Tenant-bound Graph client used only by response playbooks."""
import json
from urllib.parse import quote
import requests
import msal
from modules import config
from modules.authorization import require


def secrets():
    principal = require("admin")
    settings = json.loads(config.TENANT_SECRETS_JSON).get(principal.tenant_id)
    if not settings:
        from modules.integrations import get_integration
        row = get_integration("entra")
        if row and row.get("enabled"):
            settings = row.get("config")
        elif principal.local_admin and config.has_graph_credentials():
            settings = {"entra_tenant_id": config.TENANT_ID, "client_id": config.CLIENT_ID,
                        "client_secret": config.CLIENT_SECRET}
    if not settings:
        raise RuntimeError("Tenant response credentials are not configured.")
    return settings


class GraphClient:
    def __init__(self, settings):
        self.application_tenant_id = require("remediate").tenant_id
        self.settings = settings
        app = msal.ConfidentialClientApplication(settings["client_id"], authority="https://login.microsoftonline.com/" + settings["entra_tenant_id"], client_credential=settings["client_secret"], timeout=20)
        token = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
        if not token.get("access_token"):
            raise RuntimeError("Graph authentication failed: " + str(token.get("error_description", token.get("error", "Unknown error"))))
        self.headers = {"Authorization": "Bearer " + token["access_token"]}

    def request(self, method, path, body=None):
        if require("remediate").tenant_id != self.application_tenant_id:
            raise PermissionError("Graph client belongs to a different tenant.")
        response = requests.request(method, "https://graph.microsoft.com/v1.0/" + path, json=body, headers=self.headers, timeout=(5, 20), allow_redirects=False)
        self.last_status = response.status_code
        response.raise_for_status()
        if not 200 <= response.status_code < 300:
            raise RuntimeError("Graph returned an unexpected response status.")
        return response.json() if response.content else {}

    def resolve(self, user):
        result = self.request("GET", "users/" + quote(user, safe="") + "?$select=id,userPrincipalName,accountEnabled")
        if not result.get("id") or not result.get("userPrincipalName"):
            raise RuntimeError("Graph did not resolve the target account.")
        return result

    def revoke(self, user):
        result = self.request("POST", "users/" + quote(user, safe="") + "/revokeSignInSessions", {})
        if result.get("value") is not True:
            raise RuntimeError("Graph did not confirm session revocation.")

    def disable(self, user):
        self.request("PATCH", "users/" + quote(user, safe=""), {"accountEnabled": False})

    def block_ip(self, address, validate_only=False):
        import ipaddress
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise ValueError("Only globally routable malicious IP addresses may be blocked.")
        if any(ip in ipaddress.ip_network(n) for n in self.settings.get("protected_networks", [])):
            raise PermissionError("IP belongs to a protected network.")
        location = self.settings["block_location_id"]
        policy = self.request("GET", "identity/conditionalAccess/policies/" + quote(self.settings["block_policy_id"], safe=""))
        included = policy.get("conditions", {}).get("locations", {}).get("includeLocations", [])
        if policy.get("state") != "enabled" or location not in included or "block" not in policy.get("grantControls", {}).get("builtInControls", []):
            raise RuntimeError("An enabled blocking policy must reference the configured Named Location.")
        path = "identity/conditionalAccess/namedLocations/" + quote(location, safe="")
        existing = self.request("GET", path)
        if existing.get("isTrusted"):
            raise PermissionError("A trusted Named Location cannot be used as a blocklist.")
        excluded = policy.get("conditions", {}).get("locations", {}).get("excludeLocations", [])
        if location in excluded or "All" in excluded:
            raise RuntimeError("The block location is excluded from the policy.")
        ranges = existing.get("ipRanges", [])
        cidr = str(ip) + ("/32" if ip.version == 4 else "/128")
        if any(r.get("cidrAddress") == cidr for r in ranges):
            return
        ranges.append({"@odata.type": "#microsoft.graph.iPv4CidrRange" if ip.version == 4 else "#microsoft.graph.iPv6CidrRange", "cidrAddress": cidr})
        if validate_only:
            return
        self.request("PATCH", path, {"@odata.type": "#microsoft.graph.ipNamedLocation", "ipRanges": ranges})
