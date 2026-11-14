-- 0272 — EXPAND: dynamic recovery v4 (Stap 6), the SQL side of
-- formal/recovery-v4/RecoveryV4.tla. Independent of the v3 drafts 0268/0269
-- (left untouched; archiving them is the owner's call). Held in db-pending/
-- until the owner's GO.
--
-- One master row per member (vault_enclave.recovery_v4_vaults) and its
-- ceremonies. Every entry point is ONE self-contained transaction:
--   SELECT .. FOR UPDATE on the master row, lazy TTL expiry on the database
--   clock, idempotency key (a repeated key returns the stored answer), version
--   compare-and-swap, then the write. No session variables, advisory locks or
--   temp tables survive a step (Neon / PgBouncer pooling). The caller is taken
--   from the transaction context (vault_enclave.caller_user_id), never from a
--   parameter.
--
--   model action      function                                   answer.why on refusal
--   SBegin            recovery_v4_begin                          conflict busy invalid stepup malformed
--   SConfirm          recovery_v4_confirm_card                   conflict gone invalid card
--   SCommit           recovery_v4_commit                         conflict gone card stepup malformed
--   SAbort            recovery_v4_abort                          gone
--   SRemove           recovery_v4_remove                         conflict invalid stepup
--   ExpirePending     lazy in every step + recovery_v4_expire_due
--   Replay            idempotency table                          idem_mismatch (same key, other request)
--   ReportCompromise  recovery_v4_report_compromise              invalid
--   ReleaseServer     recovery_v4_server_share                   step_up_required
--
-- Levels: none, 2of3 (user_kek + server + paper), 3of4 (+ card). Threshold
-- K = 2 / 3. Owner decisions 2026-11-14: 2-of-3 until a card is linked;
-- pending TTL 10 minutes; a compromised share is excluded and ROUT's server
-- share is released without a fresh passkey step-up only while the
-- compromised shares plus the server share stay below K (CompromiseContained);
-- any commit or remove clears the compromise set (forced rotation).
--
-- Stored data are ciphertext or public only: RVE1 `mpc` envelopes (kind 3,
-- holder shard_factor 3), the sealed root (XChaCha20-Poly1305 under the
-- ceremony's generation key, opened only in the member's browser) and the
-- SHA-256 share commitments. Revoked and aborted ceremonies are shredded
-- (every blob set to NULL) in the same transaction.

alter table vault_enclave.audit_logs drop constraint audit_logs_action_check;
alter table vault_enclave.audit_logs add constraint audit_logs_action_check
  check (action in ('step_up_register', 'token_store', 'token_retrieve', 'server_key_register',
                    'sdm_card_register', 'sdm_recovery_retrieve', 'sdm_recovery_confirm',
                    'sdm_fleet_register', 'sdm_batch_register', 'sdm_batch_cards_register',
                    'sdm_tap_begin', 'sdm_tap_confirm', 'sdm_tap_consume',
                    'sdm_card_activate', 'sdm_batch_list', 'sdm_batch_export',
                    'sdm_station_register', 'sdm_station_list', 'sdm_station_retire',
                    'card_step_up_begin', 'card_step_up_complete', 'card_step_up_claim',
                    'sdm_card_revoke',
                    'pake_setup_register', 'pake_register', 'pake_signup_register',
                    'pake_unregister', 'pake_login',
                    'passkey_attestation_record',
                    'recovery_v4_begin', 'recovery_v4_confirm', 'recovery_v4_commit',
                    'recovery_v4_abort', 'recovery_v4_remove', 'recovery_v4_expire',
                    'recovery_v4_replay', 'recovery_v4_compromise', 'recovery_v4_server_share'));

-- RVE1 `mpc` envelope of exactly the size v4 writes: header magic, suite 1,
-- kind mpc (3), holder shard_factor (3); 1663 bytes of envelope overhead plus
-- a 33-byte share (x || 32-byte y) or the 72-byte sealed root.
create function vault_enclave.recovery_v4_is_mpc(p_env bytea, p_plain integer) returns boolean
language sql immutable set search_path = pg_catalog, pg_temp as $$
  select p_env is not null and octet_length(p_env) = 1663 + p_plain
     and substring(p_env from 1 for 4) = '\x52564531'::bytea
     and pg_catalog.get_byte(p_env, 4) = 1 and pg_catalog.get_byte(p_env, 5) = 3 and pg_catalog.get_byte(p_env, 6) = 3
$$;
revoke all on function vault_enclave.recovery_v4_is_mpc(bytea, integer) from public, rout_app;

create table vault_enclave.recovery_v4_vaults (
  user_id uuid primary key references public.users(id) on delete cascade,
  level text not null default 'none',
  ver bigint not null default 0,
  generation integer not null default 0,
  next_generation integer not null default 1,
  compromised text[] not null default '{}',
  updated_at timestamptz not null default pg_catalog.clock_timestamp(),
  constraint recovery_v4_vaults_level check (level in ('none', '2of3', '3of4')),
  constraint recovery_v4_vaults_gen check ((level = 'none') = (generation = 0) and generation >= 0 and next_generation > generation),
  constraint recovery_v4_vaults_comp check (compromised <@ array['user_kek', 'paper', 'card']::text[]
                                           and (level <> 'none' or compromised = '{}')
                                           and (level = '3of4' or not ('card' = any (compromised))))
);

create table vault_enclave.recovery_v4_ceremonies (
  ceremony_id uuid primary key,
  user_id uuid not null references vault_enclave.recovery_v4_vaults(user_id) on delete cascade,
  kind text not null,
  policy text not null,
  generation integer not null,
  status text not null,
  card_id uuid,
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  expires_at timestamptz not null,
  ended_at timestamptz,
  pending_root bytea,
  sealed_root bytea,
  shard_user_kek bytea, shard_server bytea, shard_paper bytea, shard_card bytea,
  commit_user_kek bytea, commit_server bytea, commit_paper bytea, commit_card bytea,
  constraint recovery_v4_cer_kind check (kind in ('setup', 'upgrade', 'downgrade', 'rotate')),
  constraint recovery_v4_cer_policy check (policy in ('2of3', '3of4')),
  constraint recovery_v4_cer_status check (status in ('pending', 'active', 'revoked', 'aborted')),
  constraint recovery_v4_cer_gen check (generation >= 1),
  constraint recovery_v4_cer_ttl check (expires_at = created_at + interval '10 minutes'),
  constraint recovery_v4_cer_ended check ((status in ('pending', 'active')) = (ended_at is null)),
  -- NoHalfOpen: an active 3of4 ceremony had its card proven by a tap.
  constraint recovery_v4_cer_card check (policy = '3of4' or card_id is null),
  constraint recovery_v4_cer_halfopen check (status <> 'active' or policy <> '3of4' or card_id is not null),
  -- Shapes per status; revoked/aborted ceremonies are shredded.
  constraint recovery_v4_cer_shape check (
    case status
      when 'pending' then pending_root is not null and sealed_root is null
      when 'active' then pending_root is null and sealed_root is not null
      else pending_root is null and sealed_root is null and shard_user_kek is null and shard_server is null
           and shard_paper is null and shard_card is null
    end),
  constraint recovery_v4_cer_shards check (
    status in ('revoked', 'aborted') or (
      shard_user_kek is not null and shard_server is not null and shard_paper is not null
      and (shard_card is not null) = (policy = '3of4')
      and commit_user_kek is not null and commit_server is not null and commit_paper is not null
      and (commit_card is not null) = (policy = '3of4'))),
  constraint recovery_v4_cer_commit_len check (
    coalesce(octet_length(commit_user_kek), 32) = 32 and coalesce(octet_length(commit_server), 32) = 32
    and coalesce(octet_length(commit_paper), 32) = 32 and coalesce(octet_length(commit_card), 32) = 32),
  constraint recovery_v4_cer_sealed_len check (sealed_root is null or octet_length(sealed_root) = 72),
  constraint recovery_v4_cer_envelopes check (
    (shard_user_kek is null or vault_enclave.recovery_v4_is_mpc(shard_user_kek, 33))
    and (shard_server is null or vault_enclave.recovery_v4_is_mpc(shard_server, 33))
    and (shard_paper is null or vault_enclave.recovery_v4_is_mpc(shard_paper, 33))
    and (shard_card is null or vault_enclave.recovery_v4_is_mpc(shard_card, 33))
    and (pending_root is null or vault_enclave.recovery_v4_is_mpc(pending_root, 72)))
);

-- Exclusivity (model invariant): at most one active and one pending ceremony per member.
create unique index recovery_v4_one_active on vault_enclave.recovery_v4_ceremonies (user_id) where status = 'active';
create unique index recovery_v4_one_pending on vault_enclave.recovery_v4_ceremonies (user_id) where status = 'pending';
create index recovery_v4_pending_due on vault_enclave.recovery_v4_ceremonies (expires_at) where status = 'pending';

create table vault_enclave.recovery_v4_idempotency (
  user_id uuid not null references vault_enclave.recovery_v4_vaults(user_id) on delete cascade,
  idem_key text not null,
  op text not null,
  request_digest bytea not null,
  answer jsonb not null,
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  primary key (user_id, idem_key),
  constraint recovery_v4_idem_key check (idem_key ~ '^[A-Za-z0-9_-]+$' and length(idem_key) between 16 and 64),
  constraint recovery_v4_idem_digest check (octet_length(request_digest) = 32)
);

revoke all on table vault_enclave.recovery_v4_vaults, vault_enclave.recovery_v4_ceremonies,
  vault_enclave.recovery_v4_idempotency from public, rout_app;
alter table vault_enclave.recovery_v4_vaults enable row level security;
alter table vault_enclave.recovery_v4_ceremonies enable row level security;
alter table vault_enclave.recovery_v4_idempotency enable row level security;
-- deny_all: RLS on without any policy; only the definers below (table owner) touch the rows.

-- ---------------------------------------------------------------- internal helpers

create function vault_enclave.recovery_v4_k(p_level text) returns integer
language sql immutable set search_path = pg_catalog, pg_temp as $$
  select case p_level when '3of4' then 3 when '2of3' then 2 else 0 end
$$;

create function vault_enclave.recovery_v4_factors(p_policy text) returns text[]
language sql immutable set search_path = pg_catalog, pg_temp as $$
  select case p_policy when '3of4' then array['user_kek', 'server', 'paper', 'card']
                       when '2of3' then array['user_kek', 'server', 'paper'] else '{}'::text[] end
$$;

-- BeginKinds(level) of the model.
create function vault_enclave.recovery_v4_begin_ok(p_level text, p_kind text, p_policy text) returns boolean
language sql immutable set search_path = pg_catalog, pg_temp as $$
  select case p_level
    when 'none' then p_kind = 'setup' and p_policy in ('2of3', '3of4')
    when '2of3' then (p_kind, p_policy) in (('upgrade', '3of4'), ('rotate', '2of3'))
    when '3of4' then (p_kind, p_policy) in (('downgrade', '2of3'), ('rotate', '3of4'))
    else false end
$$;

create function vault_enclave.recovery_v4_answer(
  p_op text, p_ok boolean, p_why text, p_cid uuid, p_ver bigint, p_level text, p_pend uuid, p_act uuid)
returns jsonb language sql immutable set search_path = pg_catalog, pg_temp as $$
  select pg_catalog.jsonb_build_object('op', p_op, 'ok', p_ok, 'why', p_why, 'cid', p_cid, 'ver', p_ver,
                                       'level', p_level, 'pend', p_pend, 'act', p_act)
$$;

-- Fresh(p): the caller's own passkey proof, unconsumed, verified within 300 s on the database clock.
create function vault_enclave.recovery_v4_fresh(p_caller uuid, p_proof uuid) returns boolean
language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  select p_proof is not null and exists (
    select 1 from vault_enclave.step_up_proofs s
     where s.proof_id = p_proof and s.user_id = p_caller and s.method = 'passkey' and s.consumed_at is null
       and s.verified_at >= pg_catalog.clock_timestamp() - interval '300 seconds'
       and s.verified_at <= pg_catalog.clock_timestamp())
$$;

-- Consume(p): marks a fresh proof used; a no-op otherwise.
create function vault_enclave.recovery_v4_consume(p_caller uuid, p_proof uuid) returns void
language sql security definer set search_path = pg_catalog, pg_temp as $$
  update vault_enclave.step_up_proofs s set consumed_at = pg_catalog.clock_timestamp()
   where s.proof_id = p_proof and s.user_id = p_caller and s.consumed_at is null
     and s.verified_at >= pg_catalog.clock_timestamp() - interval '300 seconds'
$$;

-- Ends a ceremony: shreds every blob in the same statement.
create function vault_enclave.recovery_v4_end(p_ceremony uuid, p_status text) returns void
language sql security definer set search_path = pg_catalog, pg_temp as $$
  update vault_enclave.recovery_v4_ceremonies c
     set status = p_status, ended_at = pg_catalog.clock_timestamp(),
         pending_root = null, sealed_root = null,
         shard_user_kek = null, shard_server = null, shard_paper = null, shard_card = null
   where c.ceremony_id = p_ceremony
$$;

-- Locks (creating if needed) the caller's master row, applies the TTL on the
-- database clock (ExpirePending: pending -> aborted, ver + 1) and prunes
-- idempotency rows older than one day. Returns the locked row.
create function vault_enclave.recovery_v4_lock(p_caller uuid) returns vault_enclave.recovery_v4_vaults
language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v vault_enclave.recovery_v4_vaults%rowtype;
  v_due uuid;
begin
  insert into vault_enclave.recovery_v4_vaults (user_id) values (p_caller) on conflict (user_id) do nothing;
  select * into v from vault_enclave.recovery_v4_vaults where user_id = p_caller for update;
  select c.ceremony_id into v_due from vault_enclave.recovery_v4_ceremonies c
   where c.user_id = p_caller and c.status = 'pending' and c.expires_at <= pg_catalog.clock_timestamp();
  if v_due is not null then
    perform vault_enclave.recovery_v4_end(v_due, 'aborted');
    update vault_enclave.recovery_v4_vaults set ver = ver + 1, updated_at = pg_catalog.clock_timestamp()
     where user_id = p_caller returning * into v;
    perform vault_enclave.append_audit(p_caller, 'recovery_v4_expire', 'granted', 'ttl', null);
  end if;
  delete from vault_enclave.recovery_v4_idempotency i
   where i.user_id = p_caller and i.created_at < pg_catalog.clock_timestamp() - interval '1 day';
  return v;
end $$;

-- Replay: the stored answer for the same key and request; 'idem_mismatch' for another request.
create function vault_enclave.recovery_v4_replay(p_caller uuid, p_key text, p_op text, p_digest bytea) returns jsonb
language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare r vault_enclave.recovery_v4_idempotency%rowtype;
begin
  select * into r from vault_enclave.recovery_v4_idempotency i where i.user_id = p_caller and i.idem_key = p_key;
  if not found then return null; end if;
  if r.op <> p_op or r.request_digest <> p_digest then
    perform vault_enclave.append_audit(p_caller, 'recovery_v4_replay', 'denied', 'idem_mismatch', null);
    return vault_enclave.recovery_v4_answer(p_op, false, 'idem_mismatch', null, null, null, null, null);
  end if;
  perform vault_enclave.append_audit(p_caller, 'recovery_v4_replay', 'granted', p_op, null);
  return r.answer;
end $$;

create function vault_enclave.recovery_v4_store(p_caller uuid, p_key text, p_op text, p_digest bytea, p_answer jsonb) returns jsonb
language sql security definer set search_path = pg_catalog, pg_temp as $$
  insert into vault_enclave.recovery_v4_idempotency (user_id, idem_key, op, request_digest, answer)
  values (p_caller, p_key, p_op, p_digest, p_answer) returning answer
$$;

create function vault_enclave.recovery_v4_ids(p_caller uuid, out p_pend uuid, out p_act uuid)
language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  select (select c.ceremony_id from vault_enclave.recovery_v4_ceremonies c where c.user_id = p_caller and c.status = 'pending'),
         (select c.ceremony_id from vault_enclave.recovery_v4_ceremonies c where c.user_id = p_caller and c.status = 'active')
$$;

create function vault_enclave.recovery_v4_digest(p_parts text[]) returns bytea
language sql immutable set search_path = pg_catalog, pg_temp as $$
  select pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.array_to_string(p_parts, '|', '~'), 'UTF8'))
$$;

create function vault_enclave.recovery_v4_key_ok(p_key text) returns boolean
language sql immutable set search_path = pg_catalog, pg_temp as $$
  select p_key is not null and p_key ~ '^[A-Za-z0-9_-]+$' and length(p_key) between 16 and 64
$$;
