-- TRUST: Supabase schema
-- Run once in the Supabase dashboard: SQL Editor -> New query -> paste -> Run.
-- Safe to re-run: every statement is idempotent.
--
-- The backend connects with the service_role key, which bypasses Row Level Security.
-- RLS is still enabled with no policies, so the anon/public key cannot read or write anything.

-- ---------------------------------------------------------------------------
-- Identity registry (one row per agency user; public keys only, never private keys)
-- ---------------------------------------------------------------------------
create table if not exists public.users (
  uid               text primary key,
  email             text not null unique,
  display_name      text not null,
  role              text not null check (role in ('admin','investigator','analyst','judiciary','auditor')),
  requested_role    text,
  did               text not null unique,
  msp_id            text not null,
  status            text not null default 'pending' check (status in ('pending','approved','revoked')),
  auth_provider     text not null default 'key' check (auth_provider in ('firebase','key')),
  public_key_hex    text not null,
  public_key_pem    text not null,
  fingerprint       text not null,
  did_document      jsonb not null,
  firewall_warnings integer not null default 0,
  did_history       jsonb not null default '[]'::jsonb,   -- DIDs retired by key recovery
  authorized_by     text,
  tx_hash           text,
  created_at        timestamptz not null default now(),
  updated_at        timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- Evidence metadata (files live in the private storage bucket, AES-256-GCM encrypted)
-- ---------------------------------------------------------------------------
create table if not exists public.evidence (
  id                 text primary key,
  name               text not null,
  hash               text not null check (hash ~ '^[0-9a-f]{64}$'),
  uploaded_by        text not null,
  uploader_signature text not null,
  timestamp          timestamptz not null default now(),
  status             text not null default 'pending' check (status in ('pending','verified','flagged')),
  file_type          text,
  case_id            text not null,
  file_size          bigint,
  file_url           text,
  encryption         text not null default 'aes-256-gcm',
  tx_hash            text not null,
  block_number       bigint
);
create index if not exists evidence_case_idx on public.evidence (case_id);
create index if not exists evidence_status_idx on public.evidence (status);

-- ---------------------------------------------------------------------------
-- Custody audit log: every row pairs with one ledger transaction (tx_hash)
-- ---------------------------------------------------------------------------
create table if not exists public.audit_log (
  id            text primary key,
  evidence_id   text not null,
  case_id       text not null,
  action        text not null,
  performed_by  text not null,
  timestamp     timestamptz not null default now(),
  tx_hash       text not null,
  block_number  bigint,
  details       text
);
create index if not exists audit_evidence_idx on public.audit_log (evidence_id);
create index if not exists audit_case_idx on public.audit_log (case_id);
create index if not exists audit_performer_idx on public.audit_log (performed_by);
create index if not exists audit_action_idx on public.audit_log (action);
create index if not exists audit_ts_idx on public.audit_log (timestamp desc);

-- ---------------------------------------------------------------------------
-- Cases and time-bound delegation
-- ---------------------------------------------------------------------------
create table if not exists public.cases (
  case_id      text primary key,
  owner_did    text not null,
  created_at   timestamptz not null default now(),
  tx_hash      text not null,
  block_number bigint
);
create index if not exists cases_owner_idx on public.cases (owner_did);

create table if not exists public.case_access (
  id              text primary key,
  case_id         text not null references public.cases(case_id),
  grantee_did     text not null,
  permission      text not null check (permission in ('read','contribute')),
  granted_by      text not null,
  expires_at      timestamptz not null,
  revoked_at      timestamptz,
  revoked_by      text,
  expiry_recorded boolean not null default false,
  tx_hash         text not null,
  created_at      timestamptz not null default now()
);
create index if not exists case_access_grantee_idx on public.case_access (grantee_did);
create index if not exists case_access_case_idx on public.case_access (case_id);

-- ---------------------------------------------------------------------------
-- Lost-key recovery requests (need approvals from distinct administrators)
-- ---------------------------------------------------------------------------
create table if not exists public.recovery_requests (
  id                 text primary key,
  uid                text not null references public.users(uid),
  email              text not null,
  old_did            text not null,
  new_did            text not null,
  new_public_key_hex text not null,
  reason             text,
  status             text not null check (status in ('pending','completed','rejected','expired')),
  approvals          jsonb not null default '[]'::jsonb,
  required_approvals integer not null,
  reduced_quorum     boolean not null default false,
  created_at         timestamptz not null default now(),
  expires_at         timestamptz not null,
  completed_at       timestamptz,
  tx_hash            text not null
);

-- ---------------------------------------------------------------------------
-- Outbox for the case-management webhook connector
-- ---------------------------------------------------------------------------
create table if not exists public.webhook_outbox (
  id              text primary key,
  event_id        text not null,
  payload         text not null,
  attempts        integer not null default 0,
  next_attempt_at timestamptz not null default now(),
  delivered_at    timestamptz,
  last_error      text,
  created_at      timestamptz not null default now()
);
create index if not exists webhook_outbox_pending_idx on public.webhook_outbox (next_attempt_at) where delivered_at is null;

-- Upgrades from the earlier schema (adds columns if the tables already existed)
alter table public.evidence  add column if not exists uploader_signature text;
alter table public.evidence  add column if not exists encryption text not null default 'aes-256-gcm';
alter table public.evidence  add column if not exists tx_hash text;
alter table public.evidence  add column if not exists block_number bigint;
alter table public.audit_log add column if not exists block_number bigint;
alter table public.audit_log add column if not exists details text;
alter table public.users     add column if not exists did_history jsonb not null default '[]'::jsonb;

-- Older versions of this project linked audit_log.evidence_id to evidence.id. Audit rows now also
-- record identity and case events (evidence_id holds a DID or case ID), so drop any such foreign key.
do $$
declare c record;
begin
  for c in select conname from pg_constraint
           where conrelid = 'public.audit_log'::regclass and contype = 'f'
  loop
    execute format('alter table public.audit_log drop constraint %I', c.conname);
  end loop;
end $$;

-- The audit log is append-only: block UPDATE and DELETE even for the service role.
create or replace function public.trust_audit_log_append_only()
returns trigger language plpgsql as $$
begin
  raise exception 'audit_log is append-only (attempted %)', tg_op;
end;
$$;
drop trigger if exists audit_log_append_only on public.audit_log;
create trigger audit_log_append_only
  before update or delete on public.audit_log
  for each row execute function public.trust_audit_log_append_only();

-- Lock tables to the service role.
alter table public.users     enable row level security;
alter table public.evidence  enable row level security;
alter table public.audit_log enable row level security;
alter table public.cases enable row level security;
alter table public.case_access enable row level security;
alter table public.recovery_requests enable row level security;
alter table public.webhook_outbox enable row level security;

-- ---------------------------------------------------------------------------
-- Private storage bucket for encrypted evidence blobs
-- ---------------------------------------------------------------------------
insert into storage.buckets (id, name, public)
values ('evidence-files', 'evidence-files', false)
on conflict (id) do update set public = false;
