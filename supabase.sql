-- Run this once in Supabase: SQL Editor > New query > Run

create table if not exists public.profiles (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null unique references auth.users(id) on delete cascade,
  username    text not null unique,
  name        text not null default '',
  profession  text not null default '',
  bio         text not null default '',
  location    text not null default '',
  website     text not null default '',
  email       text not null default '',
  phone       text not null default '',
  company     text not null default '',
  interests   text not null default '',
  available   text not null default '',
  instagram   text not null default '',
  facebook    text not null default '',
  tiktok      text not null default '',
  linkedin    text not null default '',
  photo       text not null default '',
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

create or replace function public.set_updated_at()
returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql;

drop trigger if exists profiles_updated_at on public.profiles;
create trigger profiles_updated_at
before update on public.profiles
for each row execute function public.set_updated_at();

-- Only your server (using the secret key) touches this table.
-- RLS on + no policies = the public/anon key cannot read or write it.
alter table public.profiles enable row level security;
