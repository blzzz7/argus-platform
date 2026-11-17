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
