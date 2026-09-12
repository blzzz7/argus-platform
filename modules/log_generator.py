import json
from datetime import datetime

def generate_entra_logs():
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": "Privilege Escalation",
        "service": "Entra ID",
        "actor": "attacker@domain.com",
        "action": "Add member to role",
        "target_role": "Global Administrator",
        "status": "Success"
    }
