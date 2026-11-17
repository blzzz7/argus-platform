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
