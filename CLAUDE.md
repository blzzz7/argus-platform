# CLAUDE.md

Bu fayl Claude Code üçün layihə kontekstidir.

## Qayda (hər sessiyada)

- Hər sessiyanın sonunda (və ya əhəmiyyətli iş bitəndə) aşağıdakı **Sessiya jurnalı** bölməsinə yeni qeyd əlavə et: tarix, nə edildi, hansı fayllar dəyişdi, açıq qalan məsələlər.
- Qeydlər qısa olsun (3-8 bənd). Köhnə qeydləri silmə — yalnız yenisini əlavə et (ən yenisi ən üstdə).
- Real şifrə, token, client secret heç vaxt bu fayla və ya koda yazılmır (bax: `modules/config.py`).
- Kod şərhləri və istifadəçi ilə ünsiyyət Azərbaycan dilindədir.

## Layihə

**Argus Platform** — Microsoft Entra ID üçün avtonom, AI əsaslı ITDR (Identity Threat Detection & Response) platforması.

- UI: Streamlit (`app_ui.py`), Streamlit Community Cloud-da deploy olunur.
- `modules/config.py` — bütün konfiqurasiya `.env` / mühit dəyişənlərindən (Cloud-da Secrets) oxunur.
- `modules/ai_generator.py` — AI/Sigma qayda generatoru (`AI_MODE`: local/Ollama, OpenAI, Groq və s. OpenAI-uyğun endpoint).
- `modules/wazuh_auditor.py` — Wazuh Indexer-dən audit-trail oxuması (`WAZUH_ALERTS_INDEX`).
- `modules/db.py` — Supabase client (tək mərkəzi giriş nöqtəsi, `SUPABASE_URL`/`SUPABASE_KEY` yoxdursa `None` qaytarır).
- `modules/storage.py` — hadisələrin/resolved-users-in Supabase-də (Postgres) persist olunması. Əvvəllər SQLite idi (`data/argus_events.db`) — 2026-10-05-də Supabase-ə köçürüldü (bax Sessiya jurnalı).
- `supabase/schema.sql` — Supabase SQL Editor-da bir dəfə işə salınmalı sxem (`events`, `resolved_users`, `integrations`).
- `receiver.py` — evdə işləyən Flask "ingest & audit bridge" (`POST /ingest`, `POST /search`), ngrok ilə tunelləndirilir; Cloud -> ev Wazuh körpüsü.
- `argus-logs/itdr-events.json` — NDJSON hadisə faylı (Wazuh manager tail edir).
- `modules/attack_engine.py` — Red Team attack engine (MSAL/Graph). Git status-da hazırda silinmiş (`D`) görünür.

## Əsas konfiqurasiya dəyişənləri

`SUPABASE_URL`, `SUPABASE_KEY` (service_role tövsiyə olunur — bax `modules/db.py`), `WAZUH_*`, `ARGUS_INGEST_URL`, `ARGUS_INGEST_TOKEN`, `ARGUS_LOG_DIR`, `ARGUS_TENANT_ID/CLIENT_ID/CLIENT_SECRET`, `ENABLE_REAL_REMEDIATION`, `AI_MODE`, `OPENAI_*`, `OLLAMA_*`, `LLM_BASE_URL/LLM_API_KEY/LLM_MODEL`.

## Qeydlər

- Dependencies `requirements.txt`-dədir. `pySigma` build xətasına görə çıxarılıb (commit `9970a9b`) — geri əlavə etməzdən əvvəl deploy-u yoxla.
- Mühit: Windows 11, PowerShell. Test/run komandası hələ sənədləşdirilməyib (`streamlit run app_ui.py` gözlənilir).

## Sessiya jurnalı

### 2026-10-05 (8)
- **AI Chatbot əlavə olundu** (istifadəçinin sonradan xatırladığı tələb): sidebar-da sabit "🤖 AI Köməkçi" paneli, Groq (`.env`-dəki `AI_MODE=groq`) ilə işləyir.
- `modules/ai_generator.py`-ə `AIServiceSwitcher.chat()` metodu əlavə olundu (mövcud `generate_sigma_rule()`/`validate_sigma_with_pysigma()`-ya TOXUNULMADI — eyni client/model-dən istifadə edir, sadəcə sərbəst söhbət üçün).
- `app_ui.py`-ə `render_ai_chatbot_sidebar()` əlavə olundu — sidebar-ın altında, bütün 9 tab-da sabit görünür. Funksional əməliyyat sayılır → `require_login()` modelinə görə tam login tələb edir (baxış da daxil, çünki xarici ödənişli API çağırır).
- **Kritik tapıntı və düzəliş:** `.env`-dəki `LLM_MODEL=llama-3.3-70b-versatile` bu Groq API key ilə **mövcud deyildi** (404 `model_not_found`) — bu, həm yeni chatbot-u, həm də əvvəldən mövcud olan "Generate Sigma Rule" funksiyasını sındırırdı (mənim bu sessiyada etdiyim dəyişiklik deyil, əvvəldən belə idi). Key-ə hansı modellərin əlçatan olduğu `/models` endpoint-i ilə yoxlanıldı, 3 namizəd (`gpt-oss-20b`, `gpt-oss-120b`, `qwen3.8-27b`) canlı test edildi — `openai/gpt-oss-120b` ən yaxşı instruction-following göstərdi (system prompt-a düzgün əməl etdi). `.env`-də **yalnız bu bir sətir** dəyişdirildi, qalan hər şey toxunulmadan qaldı.
- **Doğrulama (canlı Groq API ilə, real sorğu):** authenticated session simulyasiya edilib sidebar chat-input-dan real mesaj göndərildi → Groq-dan düzgün, kontekstli Azərbaycanca cavab alındı, 0 exception. Tam 9 tab + landing reqressiyası təkrar keçdi.
- Dəyişən fayllar: `modules/ai_generator.py` (əlavə, `chat()` metodu), `app_ui.py` (əlavə), `.env` (yalnız `LLM_MODEL` dəyəri düzəldildi).
- Açıq: bu `LLM_MODEL` düzəlişini Streamlit Cloud Secrets-də də etmək lazımdır (əvvəlki Faza 6 secrets bloku indi köhnəlib — yenisini aşağıda ver).

### 2026-10-05 (7)
- **Faza 6 (Test + Deploy) — lokal hissə tamamlandı.** Konsolidasiya edilmiş E2E test (`AppTest` + canlı Supabase): landing → 9/9 tab guest-də exception-sız → guest gated əməliyyatda bloklanır → tam login axını → authenticated əməliyyat uğurla keçir → Supabase insert/read/clear canlı işləyir. Hamısı ✅.
- İstifadəçi öz əvvəlki `.env`-ini (ekran görüntüsü ilə) verdi: `ARGUS_TENANT_ID/CLIENT_ID/CLIENT_SECRET`, `WAZUH_ENDPOINT/USERNAME/PASSWORD/VERIFY_SSL`, `ENABLE_REAL_REMEDIATION=true`, `AI_MODE=groq` + Groq `LLM_*`, `ARGUS_ADMIN_USER=admin` + `ARGUS_ADMIN_HASH`. Bunlar mövcud Supabase bloku ilə **birləşdirildi** (heç nə silinmədi) — `.env` indi tam konfiqurasiyalıdır, gitignored olaraq qalır.
- **Kritik qeyd:** `ENABLE_REAL_REMEDIATION=true` — `attack_engine.py` geri qoyulan kimi "Execute Remediation" REAL Entra ID dəyişikliyi edəcək (simulyasiya deyil). İstifadəçiyə bildirildi.
- Doğrulandı: `config.has_graph_credentials()` → `True`, admin login warning yoxa çıxdı (`.env`-dən credential düzgün oxunur, login formu istifadəyə hazırdır).
- **Açıq/qalan tək addım (istifadəçinin özü etməlidir, mən edə bilmirəm):** eyni dəyərləri (Supabase + yuxarıdakı bütün dəyişənlər) Streamlit Community Cloud → App → Settings → Secrets-ə köçürmək. Bu, istifadəçinin öz Cloud hesabıdır, bu mühitdə browser inteqrasiyası yoxdur (yoxlanıldı, Faza 1-ə bax).
- Dəyişən fayl: `.env` (lokal, gitignored).

### 2026-10-05 (6)
- **Faza 5 tamamlandı:** UI/UX polish + **istifadəçinin açıq tapşırığı**: "mən öz attack engine-imi gətirəndə problemsiz işləsin".
- `app_ui.py`-də `attack_engine` import blokuna **tam kontrakt sənədləşməsi** əlavə olundu (`USERS_FILE`/`PASSWORDS_FILE`, `generate_wordlists()` dict formatı, `IdentityAttackEngine` tələb olunan atribut/metodlar) + **müdafiəedici runtime yoxlama**: fayl geri qoyulanda kontrakta tam uyğun olmasa (məs. metod əskikdirsə), bunu İMPORT ZAMANI aşkarlayıb aydın mesaj göstərir (`attack_engine = None`, düymələr disabled) — bir düymə basılanda gizli `AttributeError` ilə çökmək əvəzinə.
- Red Team tab-ındakı "Attack Engine yüklənmədi" mesajı genişləndirildi: indi bir expander-də tələb olunan tam interfeys siyahısını göstərir.
- Landing page-ə "Necə işləyir?" 3-addımlı izahat bölməsi əlavə olundu (Qeydiyyatsız bax → Lazım olanda daxil ol → Əməliyyatı icra et).
- **Doğrulama (üç ssenari, `streamlit.testing.AppTest` ilə):** (1) fayl yoxdur → mövcud davranış (error + disabled). (2) uydurma, kontrakta TAM uyğun `attack_engine.py` müvəqqəti qoyuldu → 0 xəta, düymələr aktivləşdi. (3) uydurma, QƏSDƏN `disable_account` əskik olan versiya qoyuldu → dəqiq "...əskik: disable_account" mesajı, çökmə yoxdur. Hər iki test faylı silinib, `modules/attack_engine.py` DƏQİQ əvvəlki (silinmiş, git `D`) vəziyyətinə qaytarıldı.
- Dəyişən fayl: yalnız `app_ui.py` (əlavələr).
- Növbəti: Faza 6 — Streamlit Cloud Secrets (istifadəçinin özü) + son uçdan-uca manual test.

### 2026-10-05 (5)
- **Faza 4 tamamlandı:** SIEM/Integration Settings UI. Yeni `modules/integrations.py` (Supabase `integrations` cədvəlini oxuyan/yazan) + `app_ui.py`-də yeni **"🔌 Integrations"** tab (mövcud tab-lar SİLİNMƏDİ/DƏYİŞDİRİLMƏDİ — sadəcə `MENU_OPTIONS`-un sonuna əlavə olundu).
- Wazuh ingest URL/token indi UI-dan (Integrations tab, form) redaktə oluna bilir, Supabase-də saxlanılır. **Prioritet modeli (əlavədir, əvəz etmir):** UI konfiqurasiyası `enabled=true`-dursa `.env`-i üstələyir; əks halda (UI boşdursa/söndürülübsə/Supabase qoşulu deyilsə) tətbiq DƏQİQ ƏVVƏLKİ KİMİ yalnız `.env` (`ARGUS_INGEST_URL`/`ARGUS_INGEST_TOKEN`) ilə işləyir — heç nə pozulmayıb, sıfır reqressiya.
- `send_to_wazuh()`-un daxili məntiqi (header-lər, fallback lokal fayla yazma, error handling) TOXUNULMADI — yalnız URL/token mənbəyi `integrations.get_active_wazuh_config()`-dan alınacaq şəkildə dəyişdi.
- Integrations tab: status (aktiv/yox + mənbə) hər kəsə görünür (sərbəst baxış), konfiqurasiyanı DƏYİŞMƏK `require_login()` ilə qorunur (eyni Faza 2+3 modeli). Splunk/Sentinel üçün "🚧 Tezliklə" placeholder-lər var (gələcək faza).
- **Doğrulama (canlı Supabase + AppTest, test datası sonradan silindi):** guest-də status görünür+login warning → authenticated-də form doldurulub saxlanıldı → `get_active_wazuh_config()` `source: "ui"` qaytardı (doğru dəyərlərlə) → test qeydi silindi, `.env` fallback-a geri qayıtdı (`source: "env"`) → bütün 9 tab + landing route reqressiya testindən keçdi (0 exception).
- `.env` TOXUNULMADI (yalnız Supabase dəyərləri var, admin credential-lar əlavə edilmədi — testlərdə müvəqqəti env var kimi istifadə olundu, heç yerə yazılmadı).
- Dəyişən fayllar: `app_ui.py` (əlavələr, heç nə silinmədi), yeni `modules/integrations.py`.
- Açıq: `modules/attack_engine.py` hələ silinmiş vəziyyətdədir (bu sessiyada toxunulmadı).
- Növbəti: Faza 5 — UI/UX MVP polish, Faza 6 — Streamlit Cloud Secrets (istifadəçinin özü) + son test.

### 2026-10-05 (4)
- **Faza 2+3 tamamlandı (birlikdə edildi, çünki bir-birindən ayrıla bilməzdi):** Landing page + sərbəst naviqasiya + action-level login.
- `app_ui.py`-ə `st.query_params["page"]` əsaslı router əlavə olundu: `landing` (default, login YOXDUR) → `app` (bütün 8 tab login olmadan açıqdır) / `login` (ayrıca səhifə). Köhnə qlobal `if not authenticated: render_login_page(); st.stop()` divarı götürüldü.
- Yeni `render_landing_page()` (hero + 4 feature kart + "Tətbiqə keç"/"Daxil ol" CTA) və `require_login(key, message)` helper əlavə olundu.
- `require_login()` aşağıdakı 7 data-dəyişən/xarici-sistemə-göndərən əməliyyata tətbiq olundu (yalnız bunlar login tələb edir, qalan hər şey — baxış, analytics, PDF export — sərbəstdir): CSV log yükləmə, Clear/Reset Telemetry, Execute Remediation, Generate Sigma Rule, Red Team Attack Triggers (5 düymə — tək giriş nöqtəsində qapılıb), Dispatch All Threats to Wazuh SIEM, Send Live Telemetry (Manual Injection).
- `render_logout_sidebar()` → `render_account_sidebar()` adlandırıldı: authenticated-da Logout, qonaqda "🔐 Daxil ol" düyməsi göstərir; hər iki halda "🏠 Ana səhifə" mövcuddur.
- **Doğrulama (`streamlit.testing.v1.AppTest` ilə, real brauzer olmadan):** landing route (2 CTA, 0 exception) → bütün 8 tab guest rejimində exception-sız render olundu → gated əməliyyata (Send Live Telemetry) qonaq kliklədikdə yalnız xəbərdarlıq göstərildi, heç bir real göndərmə baş vermədi → tam login axını (ephemeral test admin credential ilə, heç nə persist olunmadı) uğurla keçdi: login → `page=app`-a redirect → sidebar Logout göstərdi → eyni əməliyyat indi uğurla icra olundu.
- Dəyişən fayl: yalnız `app_ui.py` (+ bu sənəd).
- Açıq: `modules/attack_engine.py` hələ silinmiş vəziyyətdədir (Red Team tab-ı UI-da görünür, amma `attack_engine is None` olduğu üçün düymələr disabled qalır — crash yoxdur, sadəcə funksional deyil).
- Açıq: Streamlit Cloud Secrets-ə `SUPABASE_URL`/`SUPABASE_KEY` hələ əlavə olunmayıb (istifadəçinin özü etməlidir, Faza 1 qeydinə bax).
- Növbəti: Faza 4 — SIEM/Integration Settings UI (Wazuh config-i UI-dan idarə etmək, Supabase `integrations` cədvəlinə yazmaq).

### 2026-10-05 (3)
- **Faza 1 tam doğrulandı (canlı Supabase üzərində):** `supabase/schema.sql` tətbiq olundu (Supavisor session pooler `aws-0-ap-northeast-1.pooler.supabase.com:5432` üzərindən, çünki `db.<ref>.supabase.co` birbaşa host-u bu şəbəkədən DNS/IPv6 səbəbindən əlçatan deyildi — gələcəkdə eyni problemlə qarşılaşsaq, pooler host-u istifadə edilməlidir).
- `events`, `resolved_users`, `integrations` cədvəlləri yaradıldı və REST API (`service_role` key) ilə test olundu. `modules/storage.py` üzərindən uçdan-uca test edildi: insert → read → resolve_user → clear, hamısı canlı DB-də uğurla işlədi.
- DB şifrəsi (Postgres birbaşa qoşulma üçün) YALNIZ bir dəfəlik DDL icrası üçün istifadə olundu, heç bir fayla yazılmadı/saxlanılmadı — tətbiqin özü runtime-da yalnız `SUPABASE_URL`/`SUPABASE_KEY` (service_role, `.env`-də) istifadə edir, DB şifrəsi lazım deyil.
- Lokal `.env` yaradıldı (`SUPABASE_URL`, `SUPABASE_KEY`, `SUPABASE_ANON_KEY`) — gitignored, repoya düşmür.
- **Açıq qalan tək addım:** Streamlit Community Cloud Secrets-ə (deploy olunan versiya üçün) `SUPABASE_URL`/`SUPABASE_KEY` əlavə edilməlidir — bu, istifadəçinin öz Streamlit Cloud hesabı olduğu üçün mənim tərəfimdən edilə bilmir (browser inteqrasiyası bu mühitdə əlçatan deyil, yoxlanıldı).
- Növbəti: Faza 2 — Landing page + sərbəst naviqasiya routing-i.

### 2026-10-05 (2)
- MVP planı istifadəçi ilə razılaşdırıldı, fazalara bölündü: (1) Supabase DB, (2) Landing page + sərbəst naviqasiya, (3) action-level login (funksiyalar üçün giriş tələbi, səhifələr üçün yox), (4) SIEM/Integration Settings UI, (5) UI polish, (6) test+deploy.
- **Faza 1 tamamlandı — Supabase-ə keçid:** `modules/storage.py` SQLite-dan (`data/argus_events.db`) Supabase/Postgres-ə köçürüldü. Yeni `modules/db.py` (client singleton) əlavə olundu. `modules/config.py`-ə `SUPABASE_URL`/`SUPABASE_KEY` əlavə olundu. `requirements.txt`-ə `supabase` paketi əlavə olundu. `supabase/schema.sql` yaradıldı (`events`, `resolved_users`, `integrations` cədvəlləri + RLS).
- `storage.py`-ə `clear_events()`/`clear_resolved_users()` əlavə olundu — əvvəlki versiyada bu adlar mövcud olmadığı üçün `app_ui.py`-dəki "Clear/Reset Telemetry" düyməsi yalnız session_state-i təmizləyirdi, persist data isə qalırdı (latent bug, bu versiyada düzəldi).
- Lokal `data/*.db` faylı tapılmadı (yoxlanıldı) — köçürüləcək köhnə data yoxdur, təmiz başlanıldı.
- **Açıq/manual addım (avtomatlaşdırıla bilmədi):** istifadəçi Supabase-də layihə yaratmalı (hesab/email təsdiqi tələb etdiyi üçün mən tərəfimdən edilə bilmədi), `supabase/schema.sql`-i SQL Editor-da işə salmalı, `SUPABASE_URL`/`SUPABASE_KEY`-i `.env` (lokal) və Streamlit Cloud Secrets-ə əlavə etməlidir.
- Açıq: `modules/attack_engine.py` hələ də silinmiş vəziyyətdə (həll olunmayıb, Red Team tabı buna bağlıdır).
- Növbəti: Faza 2 — Landing page + sərbəst naviqasiya routing-i (`st.query_params` əsaslı).

### 2026-10-05
- `CLAUDE.md` yaradıldı: layihə icmalı və sessiya jurnalı qaydası əlavə edildi.
- Layihə strukturu oxundu (`README.md`, `modules/config.py`, `receiver.py`); kod dəyişdirilmədi.
- Açıq: `modules/attack_engine.py` working tree-də silinib (commit olunmayıb) — niyə silindiyi və lazım olub-olmadığı dəqiqləşdirilməlidir.
