-- =====================================================================
-- AMANAT — база данных для Supabase
-- Выполните этот файл целиком: Supabase → SQL Editor → New query →
-- вставьте всё содержимое → Run.
-- =====================================================================

-- ---------- Профили пользователей и роли ----------
create table if not exists public.profiles (
  id         uuid primary key references auth.users(id) on delete cascade,
  email      text,
  label      text default '',
  role       text not null default 'pending'
             check (role in ('admin','full','manager','view','blocked','pending')),
  last_seen  timestamptz,
  created_at timestamptz not null default now()
);

-- Роль текущего пользователя (используется в правилах доступа)
create or replace function public.my_role()
returns text language sql stable security definer set search_path = public as $$
  select coalesce((select role from public.profiles where id = auth.uid()), 'none')
$$;

-- При регистрации создаём профиль. Первый зарегистрированный — администратор.
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, email, role)
  values (new.id, new.email,
          case when exists (select 1 from public.profiles) then 'pending' else 'admin' end);
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- Отметка «заходил» (пользователь не может сам поменять себе роль)
create or replace function public.touch_me()
returns void language sql security definer set search_path = public as $$
  update public.profiles set last_seen = now() where id = auth.uid()
$$;

alter table public.profiles enable row level security;

drop policy if exists profiles_select on public.profiles;
create policy profiles_select on public.profiles for select to authenticated
  using (id = auth.uid() or public.my_role() in ('admin','full','manager','view'));

drop policy if exists profiles_update on public.profiles;
create policy profiles_update on public.profiles for update to authenticated
  using (public.my_role() = 'admin' and id <> auth.uid())
  with check (public.my_role() = 'admin' and role <> 'admin');

-- ---------- Все данные приложения ----------
-- col — раздел (clients, deals, payments ...), id — запись, data — содержимое
create table if not exists public.docs (
  col        text not null,
  id         text not null,
  data       jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  primary key (col, id)
);

create or replace function public.docs_touch()
returns trigger language plpgsql as $$
begin new.updated_at = now(); return new; end $$;

drop trigger if exists docs_touch on public.docs;
create trigger docs_touch before update on public.docs
  for each row execute function public.docs_touch();

alter table public.docs enable row level security;

-- Чтение:
--   владелец и администратор — всё (кроме чужих ПИН-кодов);
--   менеджер и просмотр — клиенты, товары, сделки, платежи, расходы, фото, реквизиты, настройки;
--   ПИН-код — только свой.
drop policy if exists docs_select on public.docs;
create policy docs_select on public.docs for select to authenticated using (
  (col = 'pins' and id = auth.uid()::text)
  or (col <> 'pins' and public.my_role() in ('admin','full'))
  or (public.my_role() in ('manager','view')
      and col in ('clients','products','deals','payments','expenses','photos','company','settings'))
);

-- Добавление
drop policy if exists docs_insert on public.docs;
create policy docs_insert on public.docs for insert to authenticated with check (
  -- журнал: только от своего имени
  (col = 'log' and public.my_role() in ('admin','full','manager')
     and data->>'uid' = auth.uid()::text)
  -- свой ПИН
  or (col = 'pins' and id = auth.uid()::text
     and public.my_role() in ('admin','full','manager','view'))
  -- настройки (обязательный ПИН) — только администратор
  or (col = 'settings' and public.my_role() = 'admin')
  -- всё остальное — владелец и администратор
  or (col not in ('log','pins','settings') and public.my_role() in ('admin','full'))
  -- менеджер — рабочие разделы
  or (col in ('clients','products','deals','payments','expenses','photos')
     and public.my_role() = 'manager')
);

-- Изменение (журнал не меняется никем)
drop policy if exists docs_update on public.docs;
create policy docs_update on public.docs for update to authenticated
using (
  (col = 'pins' and id = auth.uid()::text)
  or (col = 'settings' and public.my_role() = 'admin')
  or (col not in ('log','pins','settings') and public.my_role() in ('admin','full'))
  or (col in ('clients','products','expenses','photos') and public.my_role() = 'manager')
)
with check (
  (col = 'pins' and id = auth.uid()::text)
  or (col = 'settings' and public.my_role() = 'admin')
  or (col not in ('log','pins','settings') and public.my_role() in ('admin','full'))
  or (col in ('clients','products','expenses','photos') and public.my_role() = 'manager')
);

-- Удаление (журнал не удаляется никем; менеджер может удалить только фото)
drop policy if exists docs_delete on public.docs;
create policy docs_delete on public.docs for delete to authenticated using (
  (col = 'pins' and (id = auth.uid()::text or public.my_role() = 'admin'))
  or (col not in ('log','pins','settings') and public.my_role() in ('admin','full'))
  or (col = 'photos' and public.my_role() = 'manager')
);

-- ---------- Обновления в реальном времени ----------
alter table public.docs replica identity full;
alter table public.profiles replica identity full;
do $$
begin
  begin alter publication supabase_realtime add table public.docs;     exception when duplicate_object then null; end;
  begin alter publication supabase_realtime add table public.profiles; exception when duplicate_object then null; end;
end $$;
