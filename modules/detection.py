"""Pure rolling-window identity detection over observed telemetry."""
import pandas as pd


def evaluate(records, now=None):
    frame = pd.DataFrame(records)
    if frame.empty:
        return []
    frame["time"] = pd.to_datetime(frame.get("timestamp", frame.get("created_at")), utc=True, errors="coerce")
    frame = frame.dropna(subset=["time"]).sort_values("time")
    now = pd.Timestamp.now(tz="UTC") if now is None else pd.Timestamp(now)
    frame = frame[(frame["time"] >= now - pd.Timedelta(minutes=5)) & (frame["time"] <= now)]
    if "TargetUserName" not in frame or "EventID" not in frame:
        return []
    findings = []
    for user, group in frame.groupby("TargetUserName"):
        failed = group[group["EventID"].astype(str).eq("4625")]
        if failed.empty or not user:
            continue
        counts = failed.set_index("time")["EventID"].rolling("5min", closed="both").count()
        if counts.max() > 5:
            findings.append({"target_user": user, "attack_type": "Brute Force", "severity": "High", "failed_logins": int(counts.max()), "incident_ids": failed["id"].tolist() if "id" in failed else [], "evidence": "More than five failed logins in a rolling five-minute window. Password spray requires cross-account evidence."})
    return findings
