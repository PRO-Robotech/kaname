-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- +goose StatementBegin
--
-- Enforce one-user-per-email at the DB level.
--
-- Problem: UpsertFromIdentity did
-- SELECT-then-INSERT without a DB UNIQUE constraint → concurrent / retry
-- Kratos logins for the same identity created multiple user rows with
-- the SAME external_id and email. Admin grants stop applying after a
-- re-login because the new login mints a different user_id.
--
-- Fix:
--   - one user-row per email (UNIQUE email).
--   - one user-row per external_id once activated (partial UNIQUE
--     external_id WHERE external_id <> ''); PENDING invites have
--     external_id = '' and don't compete.
--
-- This migration runs in ONE transaction:
--   1. Dedup loop (by email): pick survivor = earliest with ACTIVE
--      preference; redirect every FK / logical user-ref to survivor;
--      delete losers.
--   2. Dedup loop (by external_id): catch any cross-email leftovers
--      (alias migration edge case).
--   3. Add UNIQUE (email) + partial UNIQUE (external_id WHERE != '').
--      If step 1+2 missed any group, the constraint adds RAISE — that's
--      the safety net.
--
-- FGA tuples are NOT touched (separate OpenFGA store — operator runs
-- a one-shot rewrite script after).
--

DO $migration$
DECLARE
  v_survivor TEXT;
  v_email    TEXT;
  v_losers   TEXT[];
BEGIN
  -- ─── Step 1: email-dedup ───────────────────────────────────────
  FOR v_email IN
    SELECT email FROM kacho_iam.users GROUP BY email HAVING COUNT(*) > 1
  LOOP
    SELECT id INTO v_survivor
      FROM kacho_iam.users
     WHERE email = v_email
     ORDER BY (invite_status = 'ACTIVE') DESC, created_at ASC
     LIMIT 1;

    SELECT array_agg(id) INTO v_losers
      FROM kacho_iam.users
     WHERE email = v_email AND id <> v_survivor;

    RAISE NOTICE 'dedup-by-email: email=% survivor=% losers=%', v_email, v_survivor, v_losers;

    -- Hard FKs to users.id.
    UPDATE kacho_iam.users                          SET invited_by              = v_survivor WHERE invited_by              = ANY(v_losers);
    UPDATE kacho_iam.accounts                       SET owner_user_id           = v_survivor WHERE owner_user_id           = ANY(v_losers);
    UPDATE kacho_iam.cluster_break_glass_grants     SET requested_by_user_id    = v_survivor WHERE requested_by_user_id    = ANY(v_losers);
    UPDATE kacho_iam.cluster_break_glass_grants     SET approver_a_user_id      = v_survivor WHERE approver_a_user_id      = ANY(v_losers);
    UPDATE kacho_iam.cluster_break_glass_grants     SET approver_b_user_id      = v_survivor WHERE approver_b_user_id      = ANY(v_losers);
    UPDATE kacho_iam.cluster_break_glass_grants     SET revoked_by_user_id      = v_survivor WHERE revoked_by_user_id      = ANY(v_losers);
    UPDATE kacho_iam.service_account_oauth_clients  SET created_by_user_id      = v_survivor WHERE created_by_user_id      = ANY(v_losers);
    UPDATE kacho_iam.session_revocations            SET user_id                 = v_survivor WHERE user_id                 = ANY(v_losers);
    UPDATE kacho_iam.session_revocations            SET revoked_by_user_id      = v_survivor WHERE revoked_by_user_id      = ANY(v_losers);
    UPDATE kacho_iam.refresh_token_counters         SET user_id                 = v_survivor WHERE user_id                 = ANY(v_losers);
    UPDATE kacho_iam.scim_user_mappings             SET user_id                 = v_survivor WHERE user_id                 = ANY(v_losers);
    UPDATE kacho_iam.access_reviews                 SET reviewer_user_id        = v_survivor WHERE reviewer_user_id        = ANY(v_losers);
    UPDATE kacho_iam.access_review_campaigns        SET reviewer_user_id        = v_survivor WHERE reviewer_user_id        = ANY(v_losers);
    UPDATE kacho_iam.caep_subscribers               SET created_by_user_id      = v_survivor WHERE created_by_user_id      = ANY(v_losers);
    UPDATE kacho_iam.organization_domain_proofs     SET requested_by_user_id    = v_survivor WHERE requested_by_user_id    = ANY(v_losers);

    -- Tables of removed flows still present in this baseline.
    UPDATE kacho_iam.gdpr_erasure_requests          SET user_id                 = v_survivor WHERE user_id                 = ANY(v_losers);
    UPDATE kacho_iam.gdpr_erasure_requests          SET requested_by_user_id    = v_survivor WHERE requested_by_user_id    = ANY(v_losers);
    UPDATE kacho_iam.access_bindings_jit_eligibility SET user_id                = v_survivor WHERE user_id                 = ANY(v_losers);
    UPDATE kacho_iam.access_bindings_jit_eligibility SET approver_user_id       = v_survivor WHERE approver_user_id        = ANY(v_losers);
    UPDATE kacho_iam.access_bindings_jit_pending    SET approver_user_id        = v_survivor WHERE approver_user_id        = ANY(v_losers);

    -- access_bindings: subject_id is TEXT (no FK); restrict by subject_type.
    UPDATE kacho_iam.access_bindings                SET subject_id              = v_survivor WHERE subject_type = 'USER'   AND subject_id              = ANY(v_losers);
    UPDATE kacho_iam.access_bindings                SET granted_by_user_id      = v_survivor WHERE granted_by_user_id      = ANY(v_losers);
    UPDATE kacho_iam.access_bindings                SET revoked_by_user_id      = v_survivor WHERE revoked_by_user_id      = ANY(v_losers);
    UPDATE kacho_iam.cluster_admin_grants           SET subject_id              = v_survivor WHERE subject_type = 'USER'   AND subject_id              = ANY(v_losers);
    UPDATE kacho_iam.cluster_break_glass_grants     SET subject_id              = v_survivor WHERE subject_type = 'USER'   AND subject_id              = ANY(v_losers);

    -- group_members: (member_id, member_type='USER').
    UPDATE kacho_iam.group_members                  SET member_id               = v_survivor WHERE member_type = 'USER'    AND member_id               = ANY(v_losers);

    -- Outbox/event subject_id columns (informational; eventually consumed/expired).
    UPDATE kacho_iam.caep_outbox                    SET subject_id              = v_survivor WHERE subject_id              = ANY(v_losers);
    UPDATE kacho_iam.subject_change_outbox          SET subject_id              = v_survivor WHERE subject_id              = ANY(v_losers);

    DELETE FROM kacho_iam.users WHERE id = ANY(v_losers);
  END LOOP;

  -- ─── Step 1.5: external_id-dedup (cross-email leftover) ────────
  FOR v_email IN
    SELECT external_id FROM kacho_iam.users
     WHERE external_id <> ''
     GROUP BY external_id HAVING COUNT(*) > 1
  LOOP
    SELECT id INTO v_survivor
      FROM kacho_iam.users
     WHERE external_id = v_email
     ORDER BY (invite_status = 'ACTIVE') DESC, created_at ASC
     LIMIT 1;

    SELECT array_agg(id) INTO v_losers
      FROM kacho_iam.users
     WHERE external_id = v_email AND id <> v_survivor;

    RAISE NOTICE 'dedup-by-ext: external_id=% survivor=% losers=%', v_email, v_survivor, v_losers;

    UPDATE kacho_iam.users                          SET invited_by              = v_survivor WHERE invited_by              = ANY(v_losers);
    UPDATE kacho_iam.accounts                       SET owner_user_id           = v_survivor WHERE owner_user_id           = ANY(v_losers);
    UPDATE kacho_iam.cluster_break_glass_grants     SET requested_by_user_id    = v_survivor WHERE requested_by_user_id    = ANY(v_losers);
    UPDATE kacho_iam.cluster_break_glass_grants     SET approver_a_user_id      = v_survivor WHERE approver_a_user_id      = ANY(v_losers);
    UPDATE kacho_iam.cluster_break_glass_grants     SET approver_b_user_id      = v_survivor WHERE approver_b_user_id      = ANY(v_losers);
    UPDATE kacho_iam.cluster_break_glass_grants     SET revoked_by_user_id      = v_survivor WHERE revoked_by_user_id      = ANY(v_losers);
    UPDATE kacho_iam.service_account_oauth_clients  SET created_by_user_id      = v_survivor WHERE created_by_user_id      = ANY(v_losers);
    UPDATE kacho_iam.session_revocations            SET user_id                 = v_survivor WHERE user_id                 = ANY(v_losers);
    UPDATE kacho_iam.session_revocations            SET revoked_by_user_id      = v_survivor WHERE revoked_by_user_id      = ANY(v_losers);
    UPDATE kacho_iam.refresh_token_counters         SET user_id                 = v_survivor WHERE user_id                 = ANY(v_losers);
    UPDATE kacho_iam.scim_user_mappings             SET user_id                 = v_survivor WHERE user_id                 = ANY(v_losers);
    UPDATE kacho_iam.access_reviews                 SET reviewer_user_id        = v_survivor WHERE reviewer_user_id        = ANY(v_losers);
    UPDATE kacho_iam.access_review_campaigns        SET reviewer_user_id        = v_survivor WHERE reviewer_user_id        = ANY(v_losers);
    UPDATE kacho_iam.caep_subscribers               SET created_by_user_id      = v_survivor WHERE created_by_user_id      = ANY(v_losers);
    UPDATE kacho_iam.organization_domain_proofs     SET requested_by_user_id    = v_survivor WHERE requested_by_user_id    = ANY(v_losers);
    UPDATE kacho_iam.gdpr_erasure_requests          SET user_id                 = v_survivor WHERE user_id                 = ANY(v_losers);
    UPDATE kacho_iam.gdpr_erasure_requests          SET requested_by_user_id    = v_survivor WHERE requested_by_user_id    = ANY(v_losers);
    UPDATE kacho_iam.access_bindings_jit_eligibility SET user_id                = v_survivor WHERE user_id                 = ANY(v_losers);
    UPDATE kacho_iam.access_bindings_jit_eligibility SET approver_user_id       = v_survivor WHERE approver_user_id        = ANY(v_losers);
    UPDATE kacho_iam.access_bindings_jit_pending    SET approver_user_id        = v_survivor WHERE approver_user_id        = ANY(v_losers);
    UPDATE kacho_iam.access_bindings                SET subject_id              = v_survivor WHERE subject_type = 'USER'   AND subject_id              = ANY(v_losers);
    UPDATE kacho_iam.access_bindings                SET granted_by_user_id      = v_survivor WHERE granted_by_user_id      = ANY(v_losers);
    UPDATE kacho_iam.access_bindings                SET revoked_by_user_id      = v_survivor WHERE revoked_by_user_id      = ANY(v_losers);
    UPDATE kacho_iam.cluster_admin_grants           SET subject_id              = v_survivor WHERE subject_type = 'USER'   AND subject_id              = ANY(v_losers);
    UPDATE kacho_iam.cluster_break_glass_grants     SET subject_id              = v_survivor WHERE subject_type = 'USER'   AND subject_id              = ANY(v_losers);
    UPDATE kacho_iam.group_members                  SET member_id               = v_survivor WHERE member_type = 'USER'    AND member_id               = ANY(v_losers);
    UPDATE kacho_iam.caep_outbox                    SET subject_id              = v_survivor WHERE subject_id              = ANY(v_losers);
    UPDATE kacho_iam.subject_change_outbox          SET subject_id              = v_survivor WHERE subject_id              = ANY(v_losers);

    DELETE FROM kacho_iam.users WHERE id = ANY(v_losers);
  END LOOP;

  -- ─── Step 2: enforce ──────────────────────────────────────────
  ALTER TABLE kacho_iam.users
    ADD CONSTRAINT users_email_uniq UNIQUE (email);

  CREATE UNIQUE INDEX users_external_id_uniq
    ON kacho_iam.users (external_id)
    WHERE external_id <> '';
END
$migration$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE kacho_iam.users DROP CONSTRAINT IF EXISTS users_email_uniq;
DROP INDEX IF EXISTS kacho_iam.users_external_id_uniq;
-- +goose StatementEnd
