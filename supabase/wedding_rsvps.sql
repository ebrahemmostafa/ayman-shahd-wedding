-- RSVP storage for the Ayman & Shahd invitation
-- (Supabase project jcuqwcwkowtjxcykstlf).
-- Guests can only add responses. Reading them goes through
-- get_ayman_shahd_rsvps(), which checks a bcrypt-hashed passcode and
-- stops answering a visitor for 15 minutes after 10 wrong attempts from them.
--
-- Replace <PASSCODE> before running. Never commit the real passcode:
-- this repository is public.

create table public.ayman_shahd_rsvps (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  attendance text not null check (attendance in ('yes', 'no')),
  full_name text not null check (char_length(full_name) between 1 and 500),
  guest_count int not null default 1 check (guest_count between 1 and 10),
  guests jsonb not null default '[]'::jsonb
    constraint guests_is_small_array check (
      jsonb_typeof(guests) = 'array'
      and jsonb_array_length(guests) <= 10
      and pg_column_size(guests) <= 8000
    ),
  dietary_requirements text check (char_length(dietary_requirements) <= 2000),
  message text check (char_length(message) <= 2000)
);

alter table public.ayman_shahd_rsvps enable row level security;

create policy "Guests can send an RSVP (Ayman & Shahd)" on public.ayman_shahd_rsvps
  for insert to anon, authenticated
  with check (true);

-- Passcode hash and failed-attempt log: no client access at all.
create table public.ayman_shahd_settings (
  id int primary key default 1 check (id = 1),
  key_hash text not null
);
alter table public.ayman_shahd_settings enable row level security;
revoke all on table public.ayman_shahd_settings from anon, authenticated;

create table public.ayman_shahd_key_attempts (
  at timestamptz not null default now(),
  client text not null default ''
);
alter table public.ayman_shahd_key_attempts enable row level security;
revoke all on table public.ayman_shahd_key_attempts from anon, authenticated;

insert into public.ayman_shahd_settings (id, key_hash)
values (1, extensions.crypt('<PASSCODE>', extensions.gen_salt('bf')))
on conflict (id) do update set key_hash = excluded.key_hash;

create function public.get_ayman_shahd_rsvps(p_key text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  h text;
  who text := coalesce(
    split_part(current_setting('request.headers', true)::json ->> 'x-forwarded-for', ',', 1),
    ''
  );
begin
  -- One check at a time, so parallel guesses can't slip past the limit.
  perform pg_advisory_xact_lock(hashtext('get_ayman_shahd_rsvps'));

  delete from public.ayman_shahd_key_attempts where at < now() - interval '1 day';

  -- Wrong guesses are limited per visitor, so a stranger can't lock the couple out.
  if (select count(*) from public.ayman_shahd_key_attempts
      where client = who and at > now() - interval '15 minutes') >= 10 then
    return jsonb_build_object('ok', false, 'error', 'locked');
  end if;

  select key_hash into h from public.ayman_shahd_settings where id = 1;
  if h is null or p_key is null or extensions.crypt(p_key, h) <> h then
    insert into public.ayman_shahd_key_attempts (client) values (who);
    return jsonb_build_object('ok', false, 'error', 'invalid');
  end if;

  return jsonb_build_object(
    'ok', true,
    'rows', coalesce(
      (select jsonb_agg(r order by r.created_at desc) from public.ayman_shahd_rsvps r),
      '[]'::jsonb
    )
  );
end;
$$;

revoke all on function public.get_ayman_shahd_rsvps(text) from public;
grant execute on function public.get_ayman_shahd_rsvps(text) to anon, authenticated;
