-- RSVP storage for the Ayman & Shahd invitation
-- (Supabase project jcuqwcwkowtjxcykstlf).
-- Guests can only add responses; reading them requires the passcode,
-- which is checked inside the database by get_ayman_shahd_rsvps().

-- Undo an earlier run that mistakenly targeted another wedding's table.
drop function if exists public.get_wedding_rsvps(text);

create table public.ayman_shahd_rsvps (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  attendance text not null check (attendance in ('yes', 'no')),
  full_name text not null check (char_length(full_name) between 1 and 500),
  guest_count int not null default 1 check (guest_count between 1 and 10),
  guests jsonb not null default '[]'::jsonb,
  dietary_requirements text check (char_length(dietary_requirements) <= 2000),
  message text check (char_length(message) <= 2000)
);

alter table public.ayman_shahd_rsvps enable row level security;

create policy "Guests can send an RSVP (Ayman & Shahd)" on public.ayman_shahd_rsvps
  for insert to anon, authenticated
  with check (true);

create function public.get_ayman_shahd_rsvps(p_key text)
returns setof public.ayman_shahd_rsvps
language plpgsql
security definer
set search_path = public
as $$
begin
  if p_key is distinct from '061126' then
    raise exception 'invalid passcode' using errcode = '28000';
  end if;
  return query select * from public.ayman_shahd_rsvps order by created_at desc;
end;
$$;

revoke all on function public.get_ayman_shahd_rsvps(text) from public;
grant execute on function public.get_ayman_shahd_rsvps(text) to anon, authenticated;
