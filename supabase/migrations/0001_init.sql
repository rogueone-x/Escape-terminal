-- Escape the Terminal — leaderboard schema + RLS.
-- Run once in the Supabase SQL editor (or `supabase db push`).
-- Shared by the game (webapp/) and the TV showcase (leaderboard-tv/) —
-- both point at the same Supabase project and this same table.

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------------------
-- leaderboard
-- ---------------------------------------------------------------------------

create table if not exists public.leaderboard (
  id               uuid primary key,
  name             text not null,
  score            integer not null,
  outcome          text not null,
  levels_completed integer not null,
  total_seconds    numeric not null,
  created_at       timestamptz not null default now(),
  details          jsonb
);

alter table public.leaderboard enable row level security;

-- Anon (publishable key) can add a run and read the board...
create policy "leaderboard_insert_anon"
  on public.leaderboard for insert
  to anon
  with check (true);

create policy "leaderboard_select_anon"
  on public.leaderboard for select
  to anon
  using (true);

-- ...but never update or delete directly — that only happens through the
-- password-gated RPCs below, which run as the table owner and bypass RLS.

-- ---------------------------------------------------------------------------
-- admin_config — holds the hashed admin password, never exposed via the API
-- (no grants to anon/authenticated; only the SECURITY DEFINER functions below
-- can read it).
-- ---------------------------------------------------------------------------

create table if not exists public.admin_config (
  id            boolean primary key default true,
  password_hash text not null,
  constraint admin_config_singleton check (id)
);

alter table public.admin_config enable row level security;
-- No policies at all: RLS with zero policies denies every row to anon/authenticated,
-- so the table is reachable only from SECURITY DEFINER functions (which bypass RLS).

-- Set the real admin password once, from the SQL editor:
--   update public.admin_config set password_hash = crypt('choose-a-password', gen_salt('bf'));
insert into public.admin_config (id, password_hash)
values (true, crypt('change-me', gen_salt('bf')))
on conflict (id) do nothing;

-- ---------------------------------------------------------------------------
-- Admin RPCs — password-gated, callable by anon, run with owner privileges so
-- they can bypass RLS. No service-role key ever ships to the browser.
-- ---------------------------------------------------------------------------

create or replace function public.admin_delete_run(p_password text, p_id uuid)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  v_deleted integer;
begin
  if not exists (
    select 1 from public.admin_config
    where password_hash = crypt(p_password, password_hash)
  ) then
    raise exception 'invalid admin password';
  end if;

  delete from public.leaderboard where id = p_id;
  get diagnostics v_deleted = row_count;
  return v_deleted;
end;
$$;

create or replace function public.admin_clear_all(p_password text)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  v_deleted integer;
begin
  if not exists (
    select 1 from public.admin_config
    where password_hash = crypt(p_password, password_hash)
  ) then
    raise exception 'invalid admin password';
  end if;

  delete from public.leaderboard;
  get diagnostics v_deleted = row_count;
  return v_deleted;
end;
$$;

revoke all on function public.admin_delete_run(text, uuid) from public;
revoke all on function public.admin_clear_all(text) from public;
grant execute on function public.admin_delete_run(text, uuid) to anon;
grant execute on function public.admin_clear_all(text) to anon;

-- ---------------------------------------------------------------------------
-- Realtime (optional, used by the TV showcase for instant pop-ups)
-- ---------------------------------------------------------------------------
-- Run once, after this migration:
--   alter publication supabase_realtime add table public.leaderboard;
