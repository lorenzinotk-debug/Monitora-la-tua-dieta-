-- ============================================================
-- Schema per "Monitora la tua dieta" — versione Supabase
-- ============================================================
-- Supabase Auth gestisce utenti, login, sessioni e reset password via
-- email (tabella auth.users). Questo schema aggiunge solo le due tabelle
-- applicative, entrambe protette da Row Level Security: ogni utente legge
-- e scrive esclusivamente le proprie righe, a livello di database — non
-- dipende dalla correttezza del codice lato client.
--
-- Il database non vede mai i dati in chiaro: "ciphertext" e "wrapped_*"
-- sono blob cifrati lato browser, illeggibili senza le chiavi che restano
-- sul dispositivo dell'utente.
--
-- Esecuzione: SQL Editor del progetto Supabase → incollare l'intero file
-- → Run. Un'unica esecuzione è sufficiente.
-- ============================================================

-- Estensione per generare UUID
create extension if not exists "pgcrypto";

-- ---------------------------------------------------------------
-- Cassaforte: la DEK (chiave che cifra i dati) è avvolta due volte,
-- una con una chiave derivata dalla password, una con una chiave derivata
-- dalla chiave di recupero. Login e recupero via chiave restano indipendenti.
-- ---------------------------------------------------------------
create table public.vault_keys (
    user_id           uuid primary key references auth.users(id) on delete cascade,
    salt_password     text not null,
    wrapped_password  text not null,
    salt_recovery     text not null,
    wrapped_recovery  text not null,
    updated_at        timestamptz not null default now()
);

alter table public.vault_keys enable row level security;

create policy "Ognuno legge solo la propria cassaforte"
    on public.vault_keys for select
    using (auth.uid() = user_id);

create policy "Ognuno crea solo la propria cassaforte"
    on public.vault_keys for insert
    with check (auth.uid() = user_id);

create policy "Ognuno aggiorna solo la propria cassaforte"
    on public.vault_keys for update
    using (auth.uid() = user_id);

-- ---------------------------------------------------------------
-- Record cifrati: diario, target, peso, allergie. Ogni riga è un blob
-- cifrato lato browser, identificato da una chiave testuale
-- (es. "diary:2026-07-05").
-- ---------------------------------------------------------------
create table public.encrypted_records (
    user_id       uuid not null references auth.users(id) on delete cascade,
    record_key    text not null,
    ciphertext    text not null,
    updated_at    timestamptz not null default now(),
    primary key (user_id, record_key)
);

alter table public.encrypted_records enable row level security;

create policy "Ognuno legge solo i propri record"
    on public.encrypted_records for select
    using (auth.uid() = user_id);

create policy "Ognuno scrive solo i propri record"
    on public.encrypted_records for insert
    with check (auth.uid() = user_id);

create policy "Ognuno aggiorna solo i propri record"
    on public.encrypted_records for update
    using (auth.uid() = user_id);

create policy "Ognuno elimina solo i propri record"
    on public.encrypted_records for delete
    using (auth.uid() = user_id);

create index idx_encrypted_records_user on public.encrypted_records(user_id);

-- By Lorè
