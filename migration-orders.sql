-- ===== Shop orders (/shop page). Safe to run more than once. =====
create table if not exists public.orders (
  id              bigint generated always as identity primary key,
  created_at      timestamptz not null default now(),
  series          text not null check (series in ('essential','signature')),
  name_on_card    text not null,
  contact         text not null,
  address         text not null default '',
  payment_method  text not null check (payment_method in ('gcash','bank','cod')),
  price           integer not null,
  proof_url       text not null default '',
  note            text not null default '',
  status          text not null default 'new' check (status in ('new','paid','done','cancelled'))
);
create index if not exists orders_created on public.orders (created_at desc);
alter table public.orders enable row level security;  -- server (secret key) only
