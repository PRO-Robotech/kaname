-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- +goose StatementBegin
--
-- Block duplicate active access bindings — DB-level UNIQUE (within-service
-- refs / ban #10).
--
-- Problem:
--   Today nothing prevents the IAM API from creating multiple AccessBinding
--   rows that share the SAME (subject_type, subject_id, role_id,
--   resource_type, resource_id) tuple but differ only in id (and possibly
--   status — one ACTIVE row coexisting with N PENDING rows). The pre-existing
--   `access_bindings_unique` partial index covered only `status = 'ACTIVE'`,
--   leaving PENDING duplicates unblocked, and the Create use-case used
--   `ON CONFLICT DO UPDATE` which silently swallowed any conflict.
--   Net effect: "same permission" can be granted multiple times, each with a
--   distinct AccessBinding id, complicating revoke (revoking one leaves the
--   other(s) live) and inflating audit/outbox traffic.
--
-- Fix:
--   1. Backfill — for every cluster of duplicate (subject_type, subject_id,
--      role_id, resource_type, resource_id) rows with revoked_at IS NULL,
--      keep the earliest (by created_at, id) as survivor; soft-revoke the
--      rest via UPDATE … SET status='REVOKED', revoked_at=now(),
--      revoked_by_user_id='system:dedup'. DELETE is intentionally NOT used
--      so that the audit chain is preserved (revoked rows remain visible to
--      compliance reads).
--   2. Replace partial UNIQUE `access_bindings_unique` (WHERE status =
--      'ACTIVE') with the stronger `access_bindings_active_grant_uniq`
--      (WHERE revoked_at IS NULL). The new index ALSO catches PENDING
--      duplicates, which the prior index missed.
--
-- Service-layer:
--   The repo Insert no longer uses `ON CONFLICT DO UPDATE` for this 5-tuple
--   conflict — a duplicate now raises SQLSTATE 23505 which the IAM error
--   mapper translates into ErrAlreadyExists with verbatim text
--   "these permissions are already granted to <subject_id> on
--   <resource_type>:<resource_id>".

DO $migration$
DECLARE
  v_subject_type TEXT;
  v_subject_id   TEXT;
  v_role_id      TEXT;
  v_resource_t   TEXT;
  v_resource_id  TEXT;
  v_survivor     TEXT;
  v_count        INT;
BEGIN
  -- ─── Step 1: backfill — soft-revoke duplicate active grants ────
  FOR v_subject_type, v_subject_id, v_role_id, v_resource_t, v_resource_id IN
    SELECT subject_type, subject_id, role_id, resource_type, resource_id
      FROM kacho_iam.access_bindings
     WHERE revoked_at IS NULL
     GROUP BY subject_type, subject_id, role_id, resource_type, resource_id
    HAVING COUNT(*) > 1
  LOOP
    -- Survivor: earliest by (created_at, id) — deterministic tie-breaker.
    SELECT id INTO v_survivor
      FROM kacho_iam.access_bindings
     WHERE subject_type = v_subject_type
       AND subject_id   = v_subject_id
       AND role_id      = v_role_id
       AND resource_type = v_resource_t
       AND resource_id   = v_resource_id
       AND revoked_at IS NULL
     ORDER BY created_at ASC, id ASC
     LIMIT 1;

    -- Soft-revoke losers.
    -- access_bindings_revoked_consistency_ck demands status='REVOKED' iff
    -- revoked_at IS NOT NULL, so we must move BOTH fields atomically.
    UPDATE kacho_iam.access_bindings
       SET status              = 'REVOKED',
           revoked_at          = now(),
           revoked_by_user_id  = 'system:dedup'
     WHERE subject_type = v_subject_type
       AND subject_id   = v_subject_id
       AND role_id      = v_role_id
       AND resource_type = v_resource_t
       AND resource_id   = v_resource_id
       AND revoked_at IS NULL
       AND id <> v_survivor;

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RAISE NOTICE 'access_bindings dedup: subject=%/%, role=%, resource=%/%, survivor=%, soft-revoked=%',
      v_subject_type, v_subject_id, v_role_id, v_resource_t, v_resource_id, v_survivor, v_count;
  END LOOP;

  -- ─── Step 2: enforce ──────────────────────────────────────────
  -- Drop the prior partial UNIQUE — it covered only status='ACTIVE'; the
  -- replacement is strictly stronger (active = revoked_at IS NULL ⇒ status
  -- IN ('PENDING','ACTIVE')).
  DROP INDEX IF EXISTS kacho_iam.access_bindings_unique;

  CREATE UNIQUE INDEX access_bindings_active_grant_uniq
    ON kacho_iam.access_bindings
    (subject_id, subject_type, role_id, resource_type, resource_id)
    WHERE revoked_at IS NULL;
END
$migration$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS kacho_iam.access_bindings_active_grant_uniq;
CREATE UNIQUE INDEX access_bindings_unique
  ON kacho_iam.access_bindings
  (subject_type, subject_id, role_id, resource_type, resource_id)
  WHERE (status = 'ACTIVE');
-- +goose StatementEnd
