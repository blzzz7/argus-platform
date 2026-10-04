"""
modules/ai_generator.py
-------------------------
Argus ITDR-in HƏQİQİ "AI" komponenti.

Aşkarlanan identity hadisəsini (məsələn, Password Spray və ya Brute Force
nəticəsində yaranan DataFrame sətri) götürüb, LLM (lokal Ollama və ya
bulud — OpenAI, Groq, ya da hər hansı OpenAI-uyğun API) vasitəsilə real bir
Sigma Detection Rule (YAML) generasiya edir və pySigma ilə validasiya edir.

DİQQƏT: `sigma_rule.py`-dakı Sigma qaydası yalnız DETECTION üçündür (SIEM-ə
əlavə ediləcək monitorinq qaydası) — heç bir hücum/exploit əməliyyatı etmir.

KÖK SƏBƏB DÜZƏLİŞİ (bu versiyada): əvvəlki `AIServiceSwitcher.__init__`
yalnız `mode == "local"` və `mode == "cloud"`-u tanıyırdı — üçüncü hər hansı
dəyər (məs. "groq") birbaşa `ValueError`-a düşürdü, baxmayaraq ki
`config.py`-də artıq `LLM_BASE_URL` / `LLM_API_KEY` / `LLM_MODEL` kimi
Groq-uyğun dəyişənlər var idi. İndi "local" xaricindəki HƏR rejim (cloud,
groq, openai, və s.) vahid "remote OpenAI-compatible" yolu ilə işlənir:
Groq-un API-si OpenAI SDK-sı ilə tam uyğundur, sadəcə `base_url` dəyişir.

Konfiqurasiya `.env`-dən gəlir (bax: modules/config.py):
    AI_MODE=local             # "local" = Ollama; hər başqa dəyər (cloud/groq/openai/...) = remote
    OLLAMA_MODEL=llama3       # yalnız local rejimdə
    OLLAMA_HOST=http://localhost:11434

    # Remote rejimlər (cloud/groq/openai/...) üçün — LLM_* dəyişənləri
    # prioritetlidir, mövcud deyilsə OPENAI_* dəyişənlərinə fallback edir:
    LLM_BASE_URL=https://api.groq.com/openai/v1   # Groq üçün; boş qalsa rəsmi OpenAI endpoint-i işlənir
    LLM_API_KEY=gsk_...
    LLM_MODEL=llama-3.3-70b-versatile
    # (və ya köhnə adlarla): OPENAI_API_KEY=... / OPENAI_MODEL=gpt-4o-mini
"""
import json
import re
import uuid
from datetime import datetime, timezone

from . import config

# Bu kitabxanalar yalnız istifadə olunanda import olunur ki, quraşdırılmayıbsa
# tətbiqin qalan hissəsi çökməsin (məs. `ollama` quraşdırılmayıbsa belə,
# app_ui.py-ın digər tab-ları normal işləməlidir).
_OLLAMA_AVAILABLE = True
try:
    import ollama
except ImportError:
    _OLLAMA_AVAILABLE = False

# Groq, OpenAI, və hər hansı OpenAI-uyğun endpoint eyni `openai` SDK-sı ilə
# işlənir — yalnız `base_url` dəyişir, ona görə ayrıca "groq" kitabxanası
# lazım deyil.
_OPENAI_AVAILABLE = True
try:
    from openai import OpenAI
except ImportError:
    _OPENAI_AVAILABLE = False

_PYSIGMA_AVAILABLE = True
try:
    from sigma.rule import SigmaRule
except ImportError:
    _PYSIGMA_AVAILABLE = False

_YAML_AVAILABLE = True
try:
    import yaml as pyyaml
except ImportError:
    _YAML_AVAILABLE = False


_SYSTEM_PROMPT = (
    "You are an expert detection engineer. You ONLY output valid Sigma Rule YAML "
    "that strictly follows the official Sigma specification "
    "(https://github.com/SigmaHQ/sigma-specification). You never invent "
    "non-standard top-level keys such as 'rule' or 'output', and you never "
    "wrap your answer in explanations or markdown."
)

# Modelə göstərilən referans nümunə — düzgün struktur üçün "few-shot" nümunəsi.
_SIGMA_EXAMPLE = """title: Azure AD Password Spray Attempt Detected
id: 8f14e45f-ceea-4b19-9a19-0eabc6c5a3ff
status: experimental
description: Detects a sign-in event on Azure AD consistent with a password spray pattern.
author: Argus ITDR
date: 2026/09/15
logsource:
    category: authentication
    product: azure
    service: signinlogs
detection:
    selection:
        EventID: 4624
        AuthenticationMethod: PasswordSpray
    condition: selection
falsepositives:
    - Legitimate automated sign-in tooling
level: high
"""


def _build_prompt(entra_json_log: dict) -> str:
    return f"""Convert the following Microsoft Entra ID (Azure AD) JSON log into a single, strictly valid Sigma Rule in YAML format.

CRITICAL RULES (violating any of these makes the output invalid and unusable):
1. The very first line of your output MUST start with "title:". NEVER use "rule:" as a top-level key.
2. Do NOT invent custom top-level keys such as "rule", "when", "output", "selection" (outside of detection). Only use standard Sigma keys: title, id, status, description, author, date, references, logsource, detection, fields, falsepositives, level, tags.
3. "id" MUST be a valid UUIDv4 string (format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx).
4. "logsource" MUST contain at least a "category" or "product" field.
5. "detection" MUST contain at least one selection block (e.g. "selection") plus a "condition" field that references it by name (e.g. "condition: selection").
6. Output ONLY the raw YAML. No markdown code fences (no ```), no comments, no explanation before or after.

Reference example of the EXACT structure you must follow:
{_SIGMA_EXAMPLE}

Now generate a Sigma rule for this Entra ID JSON log:
{json.dumps(entra_json_log, indent=2, ensure_ascii=False)}
"""


def _strip_markdown_fences(text: str) -> str:
    """
    LLM-lər tez-tez ```yaml ... ``` formatında qaytarır, təlimata baxmayaraq.
    pySigma-ya ötürmədən əvvəl bunu təmizləyirik.
    """
    if not text:
        return text
    cleaned = text.strip()
    cleaned = re.sub(r"^```(?:yaml|yml)?\s*", "", cleaned)
    cleaned = re.sub(r"```\s*$", "", cleaned)
    return cleaned.strip()


_ALLOWED_SIGMA_KEYS = {
    "title", "id", "status", "description", "author", "date", "modified",
    "references", "logsource", "detection", "fields", "falsepositives",
    "level", "tags", "related",
}


def _detection_is_valid(detection) -> bool:
    """
    `detection` bloku yalnız o zaman etibarlı sayılır ki:
    - dict olsun,
    - içində string tipli 'condition' sahəsi olsun,
    - ən azı bir selector (məs. 'selection') olsun,
    - 'condition' o selector-un adına istinad etsin (məs. "selection", "selection1 or selection2").
    """
    if not isinstance(detection, dict):
        return False
    condition = detection.get("condition")
    if not isinstance(condition, str) or not condition.strip():
        return False
    selector_keys = [k for k in detection.keys() if k != "condition"]
    if not selector_keys:
        return False
    return any(key in condition for key in selector_keys)


def _sanitize_sigma_yaml(yaml_text: str, entra_json_log: dict) -> str:
    """
    "Safety net": LLM sərt təlimatlara tam əməl etməyə bilər (məs. `rule:` açarı
    yaratmaq, `title`-sız YAML qaytarmaq). Bu funksiya pySigma-nın mütləq tələb
    etdiyi sahələri (title, logsource, detection/condition) yoxdursa avtomatik
    doldurur ki, validasiyanın uğursuz olması tamamilə modelin keyfiyyətindən
    asılı olmasın.
    """
    if not _YAML_AVAILABLE:
        return yaml_text

    try:
        data = pyyaml.safe_load(yaml_text)
    except Exception:
        data = None

    if not isinstance(data, dict):
        data = {}

    nested_rule = data.pop("rule", None)
    if isinstance(nested_rule, dict):
        for k, v in nested_rule.items():
            data.setdefault(k, v)

    data.pop("output", None)

    event_id = entra_json_log.get("eventId")
    target_user = entra_json_log.get("targetUserName", "unknown")

    data.setdefault(
        "title",
        f"Auto-Generated Detection — EventID {event_id} on {target_user}"
    )

    existing_id = data.get("id")
    valid_uuid = False
    if isinstance(existing_id, str):
        try:
            uuid.UUID(existing_id)
            valid_uuid = True
        except ValueError:
            valid_uuid = False
    if not valid_uuid:
        data["id"] = str(uuid.uuid4())

    data.setdefault("status", "experimental")
    data.setdefault("description", "Auto-generated Sigma rule from Argus ITDR telemetry.")
    data.setdefault("author", "Argus ITDR (AI-assisted)")

    logsource = data.get("logsource")
    if not isinstance(logsource, dict) or not logsource:
        data["logsource"] = {"category": "authentication", "product": "azure"}

    detection = data.get("detection")
    if not _detection_is_valid(detection):
        selection = {}
        if event_id is not None:
            selection["EventID"] = event_id
        if entra_json_log.get("authenticationMethod"):
            selection["AuthenticationMethod"] = entra_json_log["authenticationMethod"]
        if not selection:
            selection = {"EventID": event_id or "unknown"}
        data["detection"] = {"selection": selection, "condition": "selection"}

    data.setdefault("level", "high")

    data = {k: v for k, v in data.items() if k in _ALLOWED_SIGMA_KEYS}

    try:
        return pyyaml.dump(data, sort_keys=False, allow_unicode=True)
    except Exception:
        return yaml_text


class AIServiceSwitcher:
    """
    "local" (Ollama) və "remote" (OpenAI-uyğun hər hansı API — OpenAI, Groq,
    Together, Azure OpenAI və s.) arasında keçid edən Sigma Rule generator.

    KÖK SƏBƏB DÜZƏLİŞİ: əvvəllər YALNIZ `mode in ("local", "cloud")` qəbul
    olunurdu. İndi `mode == "local"` xaricindəki İSTƏNİLƏN dəyər (cloud,
    groq, openai, ...) vahid "remote" yolu ilə işlənir — bu, `config.py`-dəki
    `LLM_BASE_URL` / `LLM_API_KEY` / `LLM_MODEL` dəyişənlərini (mövcud
    deyilsə `OPENAI_API_KEY` / `OPENAI_MODEL`-ə fallback edərək) istifadə
    edir. `base_url` təyin olunubsa (məs. Groq üçün
    "https://api.groq.com/openai/v1"), ora qoşulur; boş qalsa rəsmi OpenAI
    endpoint-i işlənir.
    """

    def __init__(self, mode: str = None, openai_api_key: str = None):
        self.mode = (mode or config.AI_MODE).strip().lower()
        self._remote = False

        if self.mode == "local":
            if not _OLLAMA_AVAILABLE:
                raise RuntimeError("`ollama` paketi quraşdırılmayıb: pip install ollama")
            # ollama python client-i OLLAMA_HOST mühit dəyişənini özü oxuyur,
            # amma explicit Client yaradaraq host-u təmin edirik:
            self.client = ollama.Client(host=config.OLLAMA_HOST)
            self.model = config.OLLAMA_MODEL
            return

        # --- Remote rejim: "cloud", "groq", "openai" və s. HAMISI bura düşür ---
        self._remote = True

        if not _OPENAI_AVAILABLE:
            raise RuntimeError("`openai` paketi quraşdırılmayıb: pip install openai")

        base_url = (config.LLM_BASE_URL or "").strip() or None
        key = (
            openai_api_key
            or (config.LLM_API_KEY or "").strip()
            or (config.OPENAI_API_KEY or "").strip()
        )
        self.model = (config.LLM_MODEL or "").strip() or config.OPENAI_MODEL

        if not key:
            raise ValueError(
                f"'{self.mode}' rejimi üçün API açarı tapılmadı. "
                f".env-də (yaxud Streamlit Cloud Secrets-də) LLM_API_KEY "
                f"(və ya OPENAI_API_KEY) dəyişənini təyin edin."
            )

        client_kwargs = {"api_key": key}
        if base_url:
            client_kwargs["base_url"] = base_url
        self.client = OpenAI(**client_kwargs)

    def generate_sigma_rule(self, entra_json_log: dict):
        """
        Qaytarır: (ok: bool, yaml_text_or_error: str)
        """
        prompt = _build_prompt(entra_json_log)

        try:
            if self._remote:
                # Groq, OpenAI və hər hansı OpenAI-uyğun endpoint eyni
                # chat.completions.create() çağırışı ilə işləyir.
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.2,
                )
                raw = response.choices[0].message.content

            else:  # local (Ollama)
                response = self.client.chat(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                )
                raw = response["message"]["content"]

        except Exception as e:
            hint = ""
            if not self._remote:
                hint = (f" ('{self.model}' modelinin yükləndiyini yoxlayın: "
                        f"`ollama pull {self.model}`, Ollama-nın işlədiyini yoxlayın: `ollama list`)")
            else:
                hint = (f" (rejim: '{self.mode}', model: '{self.model}' — "
                        f"LLM_BASE_URL/LLM_API_KEY/LLM_MODEL dəyərlərini və API açarının "
                        f"etibarlılığını yoxlayın)")
            return False, f"LLM çağırışı uğursuz oldu: {e}{hint}"

        cleaned = _strip_markdown_fences(raw)
        cleaned = _sanitize_sigma_yaml(cleaned, entra_json_log)
        return True, cleaned

    def validate_sigma_with_pysigma(self, yaml_content: str):
        """
        Qaytarır: (ok: bool, rule_or_error)
        """
        if not _PYSIGMA_AVAILABLE:
            return False, "`pysigma` paketi quraşdırılmayıb: pip install pysigma"
        try:
            rule = SigmaRule.from_yaml(yaml_content)
            return True, rule
        except Exception as e:
            return False, f"Sigma validasiya xətası: {e}"

    def generate_and_validate(self, entra_json_log: dict):
        """
        Tam axın: generasiya et + validasiya et. UI-da tək çağırışla istifadə üçün.

        Qaytarır: dict {
            "ok": bool,
            "yaml": str | None,
            "valid_sigma": bool,
            "error": str | None,
        }
        """
        ok, yaml_or_err = self.generate_sigma_rule(entra_json_log)
        if not ok:
            return {"ok": False, "yaml": None, "valid_sigma": False, "error": yaml_or_err}

        valid, rule_or_err = self.validate_sigma_with_pysigma(yaml_or_err)
        return {
            "ok": True,
            "yaml": yaml_or_err,
            "valid_sigma": valid,
            "error": None if valid else str(rule_or_err),
        }


# ------------------------------------------------------------------
# Köməkçi: DataFrame sətrini Entra ID tərzi JSON log-a çevirir
# ------------------------------------------------------------------
def row_to_entra_log(row: dict) -> dict:
    """
    app_ui.py-dakı DataFrame sətrini (EventID, TargetUserName, IpAddress, ...)
    Entra ID audit-log formatına bənzər JSON-a çevirir ki, LLM prompt-una
    birbaşa ötürülə bilsin.
    """
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "eventId": row.get("EventID"),
        "targetUserName": row.get("TargetUserName"),
        "ipAddress": row.get("IpAddress"),
        "status": row.get("Status"),
        "authenticationMethod": row.get("AuthMethod"),
        "errorCode": row.get("ErrorCode"),
        "service": "Entra ID",
    }


if __name__ == "__main__":
    sample_log = row_to_entra_log({
        "EventID": 4625,
        "TargetUserName": "victimuser@example.onmicrosoft.com",
        "IpAddress": "185.220.101.5",
        "Status": "FAILED",
        "AuthMethod": "PasswordSpray",
        "ErrorCode": "invalid_grant",
    })

    engine = AIServiceSwitcher()  # .env-dəki AI_MODE-a görə (default: local)
    result = engine.generate_and_validate(sample_log)

    if result["ok"]:
        print("=== Generated Sigma Rule (YAML) ===")
        print(result["yaml"])
        print(f"\nPySigma valid: {result['valid_sigma']}")
        if result["error"]:
            print(f"Validasiya qeydi: {result['error']}")
    else:
        print(f"[-] Xəta: {result['error']}")