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
    $env:WAZUH_PASSWORD = "SecretPassword"
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
from pathlib import Path
from datetime import datetime

import requests
from flask import Flask, request, jsonify

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
WAZUH_VERIFY_SSL = os.getenv("WAZUH_VERIFY_SSL", "false").strip().lower() == "true"

if not WAZUH_VERIFY_SSL:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)


def _check_token():
    if not ARGUS_INGEST_TOKEN:
        return True
    return request.headers.get("X-Argus-Token", "") == ARGUS_INGEST_TOKEN


@app.route("/ingest", methods=["POST"])
def ingest():
    if not _check_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({"ok": False, "error": "invalid or missing JSON body"}), 400

    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    return jsonify({"ok": True, "written": True, "file": str(LOG_FILE)}), 201


@app.route("/search", methods=["POST"])
def search_proxy():
    """
    Cloud-dan gələn audit-oxuma sorğusunu lokal OpenSearch-ə ötürür.
    Gözlənilən body: {"index": "wazuh-alerts-*", "query": {...OpenSearch DSL...}}
    """
    if not _check_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    payload = request.get_json(silent=True) or {}
    index = payload.get("index", "wazuh-alerts-*")
    query = payload.get("query", {"query": {"match_all": {}}, "size": 100})

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
        return jsonify({"ok": False, "error": f"OpenSearch bağlantı xətası: {e}"}), 502

    # OpenSearch-in cavabını olduğu kimi ötürürük (status kodu daxil).
    try:
        return jsonify(resp.json()), resp.status_code
    except Exception:
        return jsonify({"ok": False, "error": f"OpenSearch JSON-olmayan cavab qaytardı: {resp.text[:300]}"}), 502


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "ok": True,
        "time": datetime.utcnow().isoformat() + "Z",
        "log_file": str(LOG_FILE),
        "log_file_exists": LOG_FILE.exists(),
        "token_required": bool(ARGUS_INGEST_TOKEN),
        "opensearch_target": WAZUH_INDEXER_BASE,
    })


if __name__ == "__main__":
    print(f"[Argus Bridge] Yazılacaq fayl: {LOG_FILE}")
    print(f"[Argus Bridge] Audit-read proksi hədəfi: {WAZUH_INDEXER_BASE}")
    print(f"[Argus Bridge] Token tələb olunur: {bool(ARGUS_INGEST_TOKEN)}")
    print(f"[Argus Bridge] Port: {RECEIVER_PORT}")
    app.run(host="0.0.0.0", port=RECEIVER_PORT)