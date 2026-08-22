-- Staff operational account numbers
-- Existing staff records remain valid because the field is nullable during backfill.
-- The application server generates values for eligible roles and preserves them thereafter.

alter table if exists public.users
  add column if not exists "staffAccountNumber" text;

create unique index if not exists users_staff_account_number_unique
  on public.users ("staffAccountNumber")
  where "staffAccountNumber" is not null;

create index if not exists users_staff_account_number_lookup
  on public.users ("staffAccountNumber");
