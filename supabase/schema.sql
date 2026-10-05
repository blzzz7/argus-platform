-- Argus ITDR — Supabase sxema
-- ----------------------------------------------------------------------
-- Bu SQL-i Supabase Dashboard > SQL Editor-da BİR DƏFƏ işə salın
-- (layihə yaradıldıqdan sonra). Mövcud cədvəl varsa toxunulmur
-- ("if not exists"), ona görə təhlükəsiz şəkildə bir neçə dəfə də
-- işə salına bilər.

-- 1) Identity telemetriya hadisələri (əvvəlki SQLite "events" cədvəlinin yerinə)
create table if not exists events (
    id bigint generated always as identity primary key,
    "EventID" text,
    "TargetUserName" text,
    "IpAddress" text,
    "Status" text,
    "AuthMethod" text,
    "ErrorCode" text,
    created_at timestamptz not null default now()
);

create index if not exists events_target_user_idx on events ("TargetUserName");
create index if not exists events_created_at_idx on events (created_at);

-- 2) Remediate edilmiş (bloklanmış) istifadəçilər
create table if not exists resolved_users (
    username text primary key,
    resolved_at timestamptz not null default now()
);

-- 3) SIEM/inteqrasiya konfiqurasiyası (Faza 4 — UI-dan idarə olunan
--    Wazuh/Splunk/Sentinel və s. bağlantı parametrləri)
create table if not exists integrations (
    id text primary key,              -- məs. 'wazuh', 'splunk', 'sentinel'
    name text not null,
    config jsonb not null default '{}',
    enabled boolean not null default false,
    updated_at timestamptz not null default now()
);

-- ----------------------------------------------------------------------
-- Row Level Security
-- ----------------------------------------------------------------------
-- MVP mərhələsində Argus backend (Streamlit, server-side) `service_role`
-- key ilə qoşulur — bu key RLS-i avtomatik bypass edir, ona görə RLS
-- aktiv olsa belə yazma/oxuma problem yaratmır. RLS yenə də aktivləşdirilir
-- ki, gələcəkdə `anon`/client-side girişə təsadüfən açılmasın.
alter table events enable row level security;
alter table resolved_users enable row level security;
alter table integrations enable row level security;
