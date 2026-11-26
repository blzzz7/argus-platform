"""Account alert evidence and bounded AI response artifacts."""
import json
import pandas as pd
import yaml
from modules.authorization import require
from modules.ai_generator import soc_chat, _strip_markdown_fences, _detection_is_valid

CENTER_ROUTE = "Threat Response & AI Center"
LEGACY_ROUTES = {"AI Threat Analysis & Auto-Fix", "Interactive Analytics", "Threat Detection Engine"}
MITRE_TECHNIQUES = {
    "passwordspray": ("T1110.003 Password Spraying", "credential_access"),
    "bruteforce": ("T1110.001 Password Guessing", "credential_access"),
    "userenumeration": ("T1087.004 Account Discovery: Cloud Account", "discovery"),
    "mfafatigue": ("T1621 MFA Request Generation", "credential_access"),
    "devicecode": ("T1528 Steal Application Access Token", "credential_access"),
    "success_after": ("T1078.004 Valid Accounts: Cloud Accounts", "initial_access"),
}


def compute_severity(alert):
    risks = {str(row.get("severity", "")).lower() for row in alert["rows"]}
    if alert["success_after"] or "critical" in risks:
        return "CRITICAL"
    if alert["failure_peak"] >= 10 or "high" in risks:
        return "HIGH"
    return "MEDIUM"


def mitre_techniques(alert):
    methods = {
        "".join(ch for ch in str(row.get(field, "")).lower() if ch.isalnum())
        for row in alert["rows"] for field in ("AuthMethod", "attack_type")
    }
    if "devicecodeflow" in methods:
        methods.add("devicecode")
    if alert["success_after"]:
        methods.add("success_after")
    return [value for key, value in MITRE_TECHNIQUES.items() if key in methods]


def canonical_route(route):
    return CENTER_ROUTE if route in LEGACY_ROUTES else route


def compromised_alerts(rows):
    """Historical rolling-window evidence; high risk is not proof of compromise."""
    grouped = {}
    for row in rows:
        user = row.get("TargetUserName")
        if user:
            grouped.setdefault(str(user).casefold(), []).append(row)
    alerts = []
    for evidence in grouped.values():
        def stamp(row):
            return pd.to_datetime(row.get("timestamp") or row.get("created_at"), utc=True, errors="coerce")
        ordered = sorted((r for r in evidence if not pd.isna(stamp(r))), key=stamp)
        recent = []
        peak = 0
        failure_streak = 0
        success_after = False
        for row in ordered:
            at = stamp(row)
            recent = [t for t in recent if t >= at - pd.Timedelta(minutes=5)]
            code = str(row.get("EventID", ""))
            if code == "4625":
                failure_streak += 1
                recent.append(at)
                peak = max(peak, len(recent))
            elif code == "4624":
                success_after |= failure_streak >= 3
                failure_streak = 0
                recent = []
        high = [r for r in evidence if str(r.get("severity", "")).lower() in {"high", "critical"}]
        if not (high or peak > 5 or success_after):
            continue
        representative = (ordered or evidence)[-1]
        reasons = []
        if success_after:
            reasons.append("Success after 3+ consecutive failures")
        if peak > 5:
            reasons.append(f"{peak} failed sign-ins in five minutes")
        if high:
            reasons.append("High / Critical risk")
        alerts.append({"user": representative["TargetUserName"], "incident_id": representative.get("id"),
                       "source_ip": representative.get("IpAddress") or "Unknown",
                       "failed": sum(str(r.get("EventID")) == "4625" for r in evidence),
                       "success": sum(str(r.get("EventID")) == "4624" for r in evidence),
                       "pattern": "; ".join(reasons), "timestamp": str(stamp(representative)),
                       "success_after": success_after, "failure_peak": peak,
                       "rows": ordered or evidence})
    return sorted(alerts, key=lambda a: (a["timestamp"], a["user"]), reverse=True)


def generate_sigma(alert):
    require("write")
    prompt = ("Return only one valid Sigma YAML rule for Wazuh-collected identity telemetry. "
              "Use title, id (UUID), status, description, logsource, detection and level. "
              "Use observed field names EventID, TargetUserName, IpAddress, AuthMethod. "
              "Include an exact TargetUserName selector for the selected account. "
              "Use only observed EventID/IP/AuthMethod values. Generate a single-event indicator, not a correlation rule. No timeframe, aggregation or temporal detection claims. No claims of native Wazuh XML deployment. "
              "Selected alert: " + json.dumps({k: v for k, v in alert.items() if k != "rows"}, default=str))
    raw = soc_chat([{"role": "user", "content": prompt}], alert["rows"][-20:])
    text = _strip_markdown_fences(raw)
    rule = yaml.safe_load(text)
    if not isinstance(rule, dict) or not rule.get("title") or not isinstance(rule.get("logsource"), dict) or not _detection_is_valid(rule.get("detection")):
        raise ValueError("AI returned an invalid Sigma rule. Retry generation.")
    # Detection predicates are bound to observed telemetry, never model-invented values.
    latest = alert["rows"][-1]
    selection = {key: latest[key] for key in ("EventID", "IpAddress", "AuthMethod") if latest.get(key) is not None}
    rule["detection"] = {"selection": selection, "argus_account": {"TargetUserName": alert["user"]},
                         "condition": "selection and argus_account"}
    rule.pop("tags", None)
    rule["status"] = "experimental"
    rule["description"] = "Single-event indicator for the selected account. Investigation context: " + alert["pattern"]
    text = yaml.safe_dump(rule, sort_keys=False, allow_unicode=True)
    from sigma.rule import SigmaRule
    SigmaRule.from_yaml(text)
    tags = list(dict.fromkeys(
        tag for label, tactic in mitre_techniques(alert)
        for tag in (f"attack.{tactic}", f"attack.{label.split()[0].lower()}")
    ))
    if tags:
        rule["tags"] = tags
        tagged_text = yaml.safe_dump(rule, sort_keys=False, allow_unicode=True)
        try:
            SigmaRule.from_yaml(tagged_text)
        except Exception:
            return text
        return tagged_text
    return text


def generate_actions(alert):
    require("write")
    prompt = ("Return a JSON object with one key actions containing an array of 3 to 5 objects. Exact row keys: Possible Actions, "
              "Expected Outcomes & Impact. Each value under 180 characters, English only. "
              "Give specific response steps for the selected account; distinguish proposed actions from executed outcomes. "
              "Include session revocation, disabling the account, and evidence review. "
              "Never claim any action has run. Alert: " + json.dumps({k: v for k, v in alert.items() if k != "rows"}, default=str))
    result = json.loads(_strip_markdown_fences(soc_chat([{"role": "user", "content": prompt}], alert["rows"][-20:], response_format={"type": "json_object"})))
    if isinstance(result, dict):
        result = result.get("actions")
    if isinstance(result, list):
        for row in result:
            if isinstance(row, dict) and "Expected Outcomes & Impact" not in row:
                outcomes, impact = row.get("Expected Outcomes"), row.get("Impact")
                if isinstance(outcomes, str) and isinstance(impact, str):
                    row["Expected Outcomes & Impact"] = outcomes + " " + impact
    keys = ["Possible Actions", "Expected Outcomes & Impact"]
    if not isinstance(result, list) or not 1 <= len(result) <= 5 or any(not isinstance(r, dict) or any(not isinstance(r.get(k), str) or not r[k].strip() or len(r[k]) > 400 for k in keys) for r in result):
        raise ValueError("AI returned an invalid action table. Retry generation.")
    return [{k: r[k] for k in keys} for r in result]
