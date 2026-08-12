-- SAMICIOUS security hardening migration.
-- Apply with the Supabase CLI or SQL editor before enabling the gateway.
-- The service-role key is intentionally used only by the trusted gateway.

create table if not exists public.security_audit_log (
  id uuid primary key default gen_random_uuid(),
  user_id text,
  role text,
  action text not null,
  target_resource text,
  success boolean not null default false,
  authorization_decision text not null,
  request_metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

alter table public.security_audit_log enable row level security;
revoke all on public.security_audit_log from anon, authenticated;


-- Session lookup used by the server gateway. It never returns password material.
create or replace function public.rpc_get_session_context(p_token text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare result jsonb;
begin
  if p_token is null or length(p_token) < 16 then
    return null;
  end if;
  select jsonb_build_object(
    'userId', u.username,
    'username', u.username,
    'role', u.role,
    'active', coalesce(u.active, false),
    'usernameRevoked', coalesce(u."usernameRevoked", false),
    'passwordRevoked', coalesce(u."passwordRevoked", false),
    'branchId', u."branchId",
    'tenantId', u."tenantId",
    'organizationId', u."organizationId"
  ) into result
  from public.sessions s
  join public.users u on u.username = s.username
  where s.token = p_token
    and coalesce(s.expires_at, now() + interval '1 minute') > now();
  return result;
exception when undefined_table or undefined_column then
  -- A missing session schema must fail closed rather than grant access.
  return null;
end;
$$;

revoke all on function public.rpc_get_session_context(text) from public;
grant execute on function public.rpc_get_session_context(text) to service_role;

-- Direct browser database access is denied. The trusted gateway performs the
-- authorization decision and uses the service role only after validation.
do $$
declare table_name text;
begin
  foreach table_name in array array['users','branches','customers','savings','savingsTransactions','loans','loanTransactions','transactions','activityLog','auditLog','devSmsConfig','policySettings','controlledCashTransfers','termDeposits','cashVarianceEvents','cashHoldingLimits'] loop
    if to_regclass('public.' || quote_ident(table_name)) is not null then
      execute format('alter table public.%I enable row level security', table_name);
      execute format('revoke all on table public.%I from anon, authenticated', table_name);
    end if;
  end loop;
end $$;

comment on table public.security_audit_log is 'Append-only administrative authorization audit records; never store passwords, API keys, tokens, or service-role credentials.';
