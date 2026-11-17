"""
receiver.py  (v2 — tək ngrok tunel ilə YAZMA + OXUMA)
------------------------------------------------------
Argus Ingest & Audit Bridge — Streamlit Cloud-dan gələn:
  1) ITDR hadisələrini (POST /ingest) qəbul edib Wazuh manager-in tail
     etdiyi lokal NDJSON fayla yazır.
  2) Audit-oxuma sorğularını (POST /search) qəbul edib lokal OpenSearch-ə
     (https://localhost:9200) ötürür və nəticəni geri qaytarır.

NİYƏ BELƏ: ngrok-un PULSUZ planı eyni anda YALNIZ BİR aktiv tunel sessiyasına
icazə verir. Əvvəlki quraşdırmada 9200-ü (OpenSearch) və 8787-ni (receiver)
AYRI-AYRI tunelləmək istəyirdiniz — bu, ikinci tunel cəhdində "ERR_NGROK_314"
xətası yaradırdı. Bu versiyada YALNIZ 8787 tunellənir, o da lokal OpenSearch-ə
proksi kimi işləyir — yəni audit-oxuması da elə bu tək tunel üzərindən keçir.

İŞƏ SALMA:
    pip install flask requests

    $env:ARGUS_LOG_DIR = "C:\\Users\\rkazi\\wazuh-docker\\single-node\\argus-logs"
    $env:ARGUS_LOG_FILENAME = "itdr-events.json"
    $env:ARGUS_INGEST_TOKEN = "my-secret-token-12345"

    # Lokal OpenSearch-ə keçmək üçün (proksi tərəfi):
    $env:WAZUH_INDEXER_BASE = "https://localhost:9200"
    $env:WAZUH_USER = "admin"
    $env:WAZUH_PASSWORD = "<indexer-password>"
    $env:WAZUH_VERIFY_SSL = "false"

    python receiver.py

Ayrıca pəncərədə (YALNIZ BUNU, 9200-ü AYRICA tunelləməyin):
    ngrok http 8787

Streamlit Cloud secrets:
    ARGUS_INGEST_URL   = "https://xxxx.ngrok-free.dev/ingest"
    ARGUS_INGEST_TOKEN = "my-secret-token-12345"
    # Audit-oxuması da EYNİ tunel üzərindən (fərqli path):
    WAZUH_INDEXER_BASE = "https://xxxx.ngrok-free.dev"   # <-- eyni domain, /_search yox, /search proksi
    WAZUH_ALERTS_INDEX = "wazuh-alerts-*"
"""
import os
import json
import hmac
import hashlib
from pathlib import Path
from datetime import datetime, timezone

import requests
from flask import Flask, request, jsonify, g
from dotenv import load_dotenv

load_dotenv(Path(__file__).with_name(".env"), override=False)

# --- Ingest (yazma) tərəfi ---
ARGUS_LOG_DIR = os.getenv("ARGUS_LOG_DIR", r"C:\Users\rkazi\wazuh-docker\single-node\argus-logs")
ARGUS_LOG_FILENAME = os.getenv("ARGUS_LOG_FILENAME", "itdr-events.json")
ARGUS_INGEST_TOKEN = os.getenv("ARGUS_INGEST_TOKEN", "")
RECEIVER_PORT = int(os.getenv("ARGUS_RECEIVER_PORT", "8787"))
LOG_FILE = Path(ARGUS_LOG_DIR) / ARGUS_LOG_FILENAME

# --- Audit-read (oxuma) proksi tərəfi ---
WAZUH_INDEXER_BASE = os.getenv("WAZUH_INDEXER_BASE", "https://localhost:9200").rstrip("/")
WAZUH_USER = os.getenv("WAZUH_USER", "admin")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD", "")
WAZUH_VERIFY_SSL = os.getenv("WAZUH_VERIFY_SSL", "true").strip().lower() == "true"

if not WAZUH_VERIFY_SSL:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
# Hash keys map bridge credentials to trusted tenant assignments. No body/header tenant IDs.
TENANT_BRIDGE_KEYS = json.loads(os.getenv("ARGUS_BRIDGE_KEYS_JSON", "{}"))
LEGACY_TENANT_ID = os.getenv("ARGUS_LEGACY_TENANT_ID", "")
LEGACY_INDEX = os.getenv("WAZUH_ALERTS_INDEX", "wazuh-alerts-*")


def _check_token():
    token = request.headers.get("X-Argus-Token", "")
    if not token and request.headers.get("Authorization", "").startswith("Bearer "):
        token = request.headers["Authorization"][7:]
    digest = hashlib.sha256(token.encode()).hexdigest()
    assignment = TENANT_BRIDGE_KEYS.get(digest) if token else None
    if assignment:
        from uuid import UUID
        try:
            g.tenant_id = str(UUID(assignment["tenant_id"]))
        except (ValueError, KeyError, TypeError):
            return False
        g.audit_index = assignment["index"]
        g.log_file = Path(ARGUS_LOG_DIR) / g.tenant_id / ARGUS_LOG_FILENAME
        return True
    if token and ARGUS_INGEST_TOKEN and LEGACY_TENANT_ID and hmac.compare_digest(token, ARGUS_INGEST_TOKEN):
        g.tenant_id = LEGACY_TENANT_ID
        g.audit_index = LEGACY_INDEX
        g.log_file = LOG_FILE
        return True
    return False


@app.route("/ingest", methods=["POST"])
def ingest():
    if not _check_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"ok": False, "error": "invalid or missing JSON body"}), 400

    try:
        g.log_file.parent.mkdir(parents=True, exist_ok=True)
        with open(g.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception as e:
        return jsonify({"ok": False, "error": "log persistence failed"}), 500

    return jsonify({"ok": True, "written": True, "file": str(g.log_file)}), 201


@app.route("/search", methods=["POST"])
def search_proxy():
    """
    Cloud-dan gələn audit-oxuma sorğusunu lokal OpenSearch-ə ötürür.
    Gözlənilən body: {"index": "wazuh-alerts-*", "query": {...OpenSearch DSL...}}
    """
    if not _check_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"ok": False, "error": "JSON object required"}), 400
    index = payload.get("index", g.audit_index)
    if index != g.audit_index:
        return jsonify({"ok": False, "error": "forbidden index"}), 403
    query = payload.get("query", {"query": {"match_all": {}}, "size": 100})

    def safe_clause(clause):
        if not isinstance(clause, dict) or len(clause) != 1:
            return False
        name, value = next(iter(clause.items()))
        if name == "match_all":
            return value == {}
        if name in {"match", "term"}:
            return isinstance(value, dict) and len(value) == 1 and all(isinstance(v, (str, int, float, bool)) for v in value.values())
        if name == "bool" and isinstance(value, dict) and set(value) <= {"should", "must", "filter", "must_not", "minimum_should_match"}:
            return all((isinstance(v, int) and k == "minimum_should_match") or (isinstance(v, list) and len(v) <= 20 and all(safe_clause(c) for c in v)) for k, v in value.items())
        return False
    if not isinstance(query, dict) or set(query) - {"query", "size", "sort"} or not safe_clause(query.get("query", {"match_all": {}})):
        return jsonify({"ok": False, "error": "unsupported search query"}), 400
    if not isinstance(query.get("size", 100), int) or not 1 <= query.get("size", 100) <= 1000:
        return jsonify({"ok": False, "error": "search size must be 1..1000"}), 400
    try:
        resp = requests.post(
            f"{WAZUH_INDEXER_BASE}/{index}/_search",
            auth=(WAZUH_USER, WAZUH_PASSWORD) if WAZUH_PASSWORD else None,
            headers={"Content-Type": "application/json"},
            json=query,
            verify=WAZUH_VERIFY_SSL,
            timeout=15,
        )
    except Exception as e:
        return jsonify({"ok": False, "error": "audit upstream request failed"}), 502

    # OpenSearch-in cavabını olduğu kimi ötürürük (status kodu daxil).
    try:
        return jsonify(resp.json()), resp.status_code
    except Exception:
        return jsonify({"ok": False, "error": "audit upstream request failed"}), 502


@app.route("/forward/<provider>", methods=["POST"])
def forward(provider):
    if not _check_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    from modules.connectors import ADAPTERS, validate_settings
    assignments = json.loads(os.getenv("ARGUS_BRIDGE_CONNECTORS_JSON", "{}"))
    settings = assignments.get(g.tenant_id, {}).get(provider)
    if provider not in ADAPTERS or not settings:
        return jsonify({"ok": False, "error": "connector not enabled for tenant"}), 403
    event = request.get_json(silent=True)
    if not isinstance(event, dict):
        return jsonify({"ok": False, "error": "JSON object required"}), 400
    try:
        validate_settings(provider, settings)
        ADAPTERS[provider].send(event, settings)
        return jsonify({"ok": True, "status": "delivered"}), 200
    except Exception:
        return jsonify({"ok": False, "error": "connector delivery failed"}), 502


@app.route("/audit-read", methods=["GET"])
def audit_read():
    if not _check_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    identifier = request.args.get("event_uuid", "")
    if not identifier:
        return jsonify({"ok": False, "error": "event_uuid required"}), 400
    with app.test_request_context("/search", method="POST", headers=dict(request.headers), json={"query": {"size": 100, "query": {"bool": {"should": [{"term": {"data.id": identifier}}, {"term": {"id": identifier}}], "minimum_should_match": 1}}}}):
        return search_proxy()


@app.route("/health", methods=["GET"])
def health():
    if not _check_token():
        return jsonify({"ok": True, "status": "alive", "token_required": True}), 200
    try:
        response = requests.post(f"{WAZUH_INDEXER_BASE}/{g.audit_index}/_search", auth=(WAZUH_USER, WAZUH_PASSWORD) if WAZUH_PASSWORD else None, json={"size": 0, "query": {"match_all": {}}}, verify=WAZUH_VERIFY_SSL, timeout=10)
        response.raise_for_status()
        reachable = isinstance(response.json().get("hits"), dict)
    except Exception:
        reachable = False
    return jsonify({"ok": reachable, "tenant_id": g.tenant_id, "wazuh_reachable": reachable, "time": datetime.now(timezone.utc).isoformat(), "log_file_exists": g.log_file.exists(), "token_required": True}), 200 if reachable else 503


if __name__ == "__main__":
    print(f"[Argus Bridge] Yazılacaq fayl: {LOG_FILE}")
    print(f"[Argus Bridge] Audit-read proksi hədəfi: {WAZUH_INDEXER_BASE}")
    print(f"[Argus Bridge] Token tələb olunur: {bool(ARGUS_INGEST_TOKEN)}")
    print(f"[Argus Bridge] Port: {RECEIVER_PORT}")
    app.run(host="0.0.0.0", port=RECEIVER_PORT)
