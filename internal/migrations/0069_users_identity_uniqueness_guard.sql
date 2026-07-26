-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- 0069_users_identity_uniqueness_guard.sql — close the gap left by
-- 0002_users_unique_email_dedup.sql: state what that migration still does,
-- what it can no longer do, and hard-assert the contract that actually holds.
--
-- ban #5: new migration. 0002 is applied (prod) and is NOT edited here.
--
-- ─── What 0002 is today ────────────────────────────────────────────────────
-- 0002 was authored 2026-05-25 against the PRE-SQUASH schema. The baseline was
-- then regenerated (`0001_initial.sql`, "fresh-PG → goose up → pg_dump") and
-- deliberately dropped whole flows — SCIM, break-glass, CAEP, GDPR erasure, JIT
-- eligibility, access review, organization domain proofs. 0002 was kept verbatim
-- at position 2, so it now names relations that the chain never creates.
--
-- 1. ENFORCEMENT: DEAD. Both objects 0002 adds —
--      users_email_uniq        UNIQUE (email)
--      users_external_id_uniq  UNIQUE (external_id) WHERE external_id <> ''
--    were dropped again by 0011 as contradictory with the user-per-account model
--    (one identity legitimately holds one user-row per Account, all sharing an
--    email). Nothing 0002 enforces survives migration 11.
--
-- 2. DEDUP LOOPS: UNREACHABLE, and unsafe if ever reached. Both `FOR … LOOP`
--    bodies redirect user-references before deleting losers, and EIGHT of the
--    relations they update do not exist at 0002's position in the chain:
--      access_reviews, access_review_campaigns, organization_domain_proofs
--        — no migration in the tree mentions them at all;
--      gdpr_erasure_requests, access_bindings_jit_eligibility,
--      access_bindings_jit_pending
--        — 0001 states explicitly that these are "intentionally absent" in the
--          baseline;
--      caep_subscribers, caep_outbox
--        — never created; only DROP TABLE IF EXISTS in 0007 (a no-op).
--    (The rest — users, accounts, access_bindings, cluster_admin_grants,
--    group_members, subject_change_outbox, session_revocations,
--    refresh_token_counters, service_account_oauth_clients, and the
--    later-dropped cluster_break_glass_grants / scim_user_mappings — DO exist
--    when 0002 runs, so the statements naming them are fine.)
--    PL/pgSQL plans a statement on first execution, so those eight are invisible
--    while the loop never iterates — and on a fresh database it never does: 0001
--    seeds clusters and roles, no users, so there is no duplicate email to find.
--    The first genuine duplicate would abort the migration on 42P01
--    undefined_table, i.e. exactly when the dedup is finally needed. And even
--    with those relations present the loop would now be WRONG: under
--    user-per-account, two rows sharing an email are the normal case, and the
--    loop deletes them as "losers".
--    Nothing here can repair that from position 69 — a later migration cannot
--    make an earlier one safe. What this file does is record it where the next
--    reader of 0002 will look, and pin the contract 0002 no longer provides.
--
-- ─── What this migration enforces ──────────────────────────────────────────
-- The live users-identity contract is spread across two migrations and has no
-- single owner:
--   0001  users_account_email_unique        UNIQUE (account_id, lower(email))
--   0001  users_account_external_id_unique  UNIQUE (account_id, external_id)
--                                             WHERE external_id <> ''
--   0011  users_active_external_id_uniq     UNIQUE (external_id)
--                                             WHERE invite_status = 'ACTIVE'
--                                               AND external_id <> ''
-- GetByExternalID (oldest ACTIVE row), resolveCanonicalSubjectID and the gateway
-- LookupSubject all depend on the third one; the invite path depends on the first
-- two. The failure class this file guards is the one demonstrated above: a
-- regenerated baseline silently stops providing what the chain assumed, and
-- nobody notices until a duplicate identity mints a second user_id and the grants
-- stop applying. Fail-closed at migrate-time beats discovering it in production.
--
-- Symmetrically, the two GLOBAL objects from 0002 must be ABSENT: their presence
-- means the chain was replayed or hand-mutated into the state 0011 exists to undo,
-- and the next Invite into a second Account would fail on a unique violation.
--
-- No DDL: this migration asserts, it does not create. Down is a no-op.

-- +goose Up
-- +goose StatementBegin
DO $guard$
DECLARE
    v_required CONSTANT TEXT[] := ARRAY[
        'users_account_email_unique',
        'users_account_external_id_unique',
        'users_active_external_id_uniq'
    ];
    v_retired  CONSTANT TEXT[] := ARRAY[
        'users_email_uniq',
        'users_external_id_uniq'
    ];
    v_name    TEXT;
    v_missing TEXT[] := ARRAY[]::TEXT[];
    v_stale   TEXT[] := ARRAY[]::TEXT[];
BEGIN
    FOREACH v_name IN ARRAY v_required LOOP
        IF NOT EXISTS (
            SELECT 1
              FROM pg_class c
              JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = 'kacho_iam'
               AND c.relname = v_name
               AND c.relkind = 'i'
        ) THEN
            v_missing := v_missing || v_name;
        END IF;
    END LOOP;

    FOREACH v_name IN ARRAY v_retired LOOP
        IF EXISTS (
            SELECT 1
              FROM pg_class c
              JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = 'kacho_iam'
               AND c.relname = v_name
               AND c.relkind = 'i'
        ) THEN
            v_stale := v_stale || v_name;
        END IF;
    END LOOP;

    IF array_length(v_missing, 1) IS NOT NULL THEN
        RAISE EXCEPTION
            'users identity uniqueness broken: missing %  (0001 users_account_email_unique / users_account_external_id_unique, 0011 users_active_external_id_uniq). A duplicate identity would mint a second user_id and silently drop its grants.',
            array_to_string(v_missing, ', ');
    END IF;

    IF array_length(v_stale, 1) IS NOT NULL THEN
        RAISE EXCEPTION
            'users identity uniqueness contradictory: global %  present, which 0011 removed as incompatible with user-per-account. Invite into a second Account will fail on a unique violation.',
            array_to_string(v_stale, ', ');
    END IF;
END
$guard$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Nothing to reverse: the Up creates no object and changes no row.
SELECT 1;
-- +goose StatementEnd
