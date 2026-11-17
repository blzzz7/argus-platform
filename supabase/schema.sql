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

-- v2 tenant isolation.
-- Back up first. For populated tables, insert the legacy tenant then SET
-- argus.legacy_tenant_id = '<tenant UUID>' in the same SQL connection.
begin;
create table if not exists public.tenants (id uuid primary key, name text not null);
-- The legacy session setting is optional; unassigned rows use the default workspace.
insert into public.tenants(id,name)
values ('a41233e6-85f1-43f5-8b4c-3a368df76665'::uuid,'Default workspace') on conflict (id) do nothing;
do $$ declare legacy uuid; begin
 legacy:=coalesce(nullif(current_setting('argus.legacy_tenant_id',true),'')::uuid, 'a41233e6-85f1-43f5-8b4c-3a368df76665'::uuid);
 if legacy is not null then insert into public.tenants values(legacy,'Legacy organization') on conflict do nothing; end if;
end $$;
create table if not exists public.tenant_memberships (
 tenant_id uuid not null references public.tenants, user_id uuid not null references auth.users,
 role text not null check(role in ('Admin','SOC Analyst','Read-Only Auditor')),
 primary key(tenant_id,user_id));
create table if not exists public.argus_settings (key text primary key,value jsonb not null);
insert into public.argus_settings values ('require_mfa','true') on conflict do nothing;
alter table public.argus_settings enable row level security;
alter table public.tenants enable row level security;
alter table public.tenant_memberships enable row level security;
create or replace function public.argus_role(target uuid) returns text
language sql stable security definer set search_path='' as $$
 select role from public.tenant_memberships where tenant_id=target and user_id=auth.uid()
 and (not coalesce((select (value #>> '{}')::boolean from public.argus_settings where key='require_mfa'),true)
 or auth.jwt()->>'aal'='aal2')
$$;
revoke all on function public.argus_role(uuid) from public;
grant execute on function public.argus_role(uuid) to authenticated;
drop policy if exists membership_self on public.tenant_memberships;
create policy membership_self on public.tenant_memberships for select to authenticated using(user_id=auth.uid());
drop policy if exists tenant_member on public.tenants;
create policy tenant_member on public.tenants for select to authenticated using(public.argus_role(id) is not null);
do $$ declare t text; legacy uuid; begin
 legacy:=coalesce(nullif(current_setting('argus.legacy_tenant_id',true),'')::uuid, 'a41233e6-85f1-43f5-8b4c-3a368df76665'::uuid);
 foreach t in array array['events','resolved_users','integrations'] loop
  execute format('alter table public.%I add column if not exists tenant_id uuid references public.tenants',t);
  if legacy is not null then execute format('update public.%I set tenant_id=$1 where tenant_id is null',t) using legacy; end if;
  execute format('alter table public.%I alter column tenant_id set not null',t);
 end loop;
end $$;
alter table public.resolved_users drop constraint if exists resolved_users_pkey;
alter table public.resolved_users add primary key(tenant_id,username);
alter table public.integrations drop constraint if exists integrations_pkey;
alter table public.integrations add primary key(tenant_id,id);
create index if not exists events_tenant_id_idx on public.events(tenant_id,id);
create table if not exists public.audit_events (
 id uuid primary key default gen_random_uuid(),tenant_id uuid not null references public.tenants,
 actor_id uuid not null default auth.uid(),action text not null,detail jsonb not null default '{}',created_at timestamptz not null default now());
create table if not exists public.playbook_runs (
 id uuid primary key,tenant_id uuid not null references public.tenants,
 actor_id uuid not null default auth.uid(),status text not null,detail jsonb not null default '{}',created_at timestamptz not null default now());
create table if not exists public.delivery_attempts (
 id uuid primary key default gen_random_uuid(),tenant_id uuid not null references public.tenants,
 connector text not null,status text not null,detail jsonb not null default '{}',created_at timestamptz not null default now());
create unique index if not exists playbook_one_running_per_tenant on public.playbook_runs(tenant_id) where status='RUNNING';
do $$ declare t text; pol record; writers text; begin
 foreach t in array array['events','resolved_users','integrations','audit_events','playbook_runs','delivery_attempts'] loop
  execute format('alter table public.%I enable row level security',t);
  for pol in select policyname from pg_policies where schemaname='public' and tablename=t loop
   execute format('drop policy %I on public.%I',pol.policyname,t);
  end loop;
  execute format('create policy tenant_read on public.%I for select to authenticated using(public.argus_role(tenant_id) is not null)',t);
  if t='integrations' then
   execute format('drop policy tenant_read on public.%I',t);
   execute format('create policy tenant_read on public.%I for select to authenticated using(public.argus_role(tenant_id)=''Admin'')',t);
  end if;
  writers:=case when t in ('events','audit_events','delivery_attempts') then 'array[''Admin'',''SOC Analyst'']' else 'array[''Admin'']' end;
  execute format('create policy tenant_insert on public.%I for insert to authenticated with check(public.argus_role(tenant_id)=any(%s))',t,writers);
  if t in ('audit_events','playbook_runs') then
   execute format('create policy actor_identity on public.%I as restrictive for insert to authenticated with check(actor_id=auth.uid())',t);
  end if;
  if t not in ('audit_events','delivery_attempts') then
   execute format('create policy tenant_update on public.%I for update to authenticated using(public.argus_role(tenant_id)=''Admin'') with check(public.argus_role(tenant_id)=''Admin'')',t);
   execute format('create policy tenant_delete on public.%I for delete to authenticated using(public.argus_role(tenant_id)=''Admin'')',t);
  end if;
  execute format('grant select,insert,update,delete on public.%I to authenticated',t);
  execute format('revoke all on public.%I from anon',t);
 end loop;
end $$;
grant select on public.tenants,public.tenant_memberships to authenticated;
grant usage,select on sequence public.events_id_seq to authenticated;
commit;
-- Apply after 002. Provision membership atomically even when email confirmation is required.
begin;
-- Repair unassigned legacy rows before enforcing tenant isolation.
insert into public.tenants(id,name)
values ('a41233e6-85f1-43f5-8b4c-3a368df76665'::uuid,'Default workspace') on conflict (id) do nothing;
do $$ declare t text; begin
 foreach t in array array['events','resolved_users','integrations'] loop
  execute format('alter table public.%I add column if not exists tenant_id uuid references public.tenants',t);
  execute format('update public.%I set tenant_id=$1 where tenant_id is null',t)
   using 'a41233e6-85f1-43f5-8b4c-3a368df76665'::uuid;
  execute format('alter table public.%I alter column tenant_id set not null',t);
 end loop;
end $$;
create or replace function public.argus_provision_workspace() returns trigger
language plpgsql security definer set search_path='' as $$
declare workspace uuid := gen_random_uuid(); organization text;
begin
 organization := trim(new.raw_user_meta_data->>'organization_name');
 if organization is null or organization = '' then return new; end if;
 insert into public.tenants(id,name) values(workspace,left(organization,200));
 insert into public.tenant_memberships(tenant_id,user_id,role) values(workspace,new.id,'Admin');
 return new;
end $$;
revoke all on function public.argus_provision_workspace() from public;
drop trigger if exists argus_signup_workspace on auth.users;
create trigger argus_signup_workspace after insert on auth.users for each row execute function public.argus_provision_workspace();
alter table public.events add column if not exists severity text default 'Unknown';
alter table public.events add column if not exists status text default 'New';
alter table public.events add column if not exists action_taken text;
alter table public.events add column if not exists attack_type text;
commit;
