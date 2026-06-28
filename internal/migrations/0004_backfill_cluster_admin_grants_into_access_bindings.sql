-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- +goose StatementBegin
--
-- Backfill cluster_admin_grants -> access_bindings
-- (unify cluster admin into AccessBinding(resource_type=cluster)).
--
-- Until now cluster admins lived in a dedicated cluster_admin_grants table
-- and used a separate RPC family (InternalClusterService.{Grant,Revoke,List}
-- Admin). This unifies all role grants into a single mental model:
--
--     scope (account / project / cluster)
--   x role
--   x subject
--   = AccessBinding
--
-- This migration backfills the existing cluster_admin_grants rows
-- (BOTH active and revoked) into kacho_iam.access_bindings so the unified
-- read-path / list-path (AccessBindingService.ListByResource(cluster, ...))
-- and the unified emit-in-tx FGA flow can replace the cluster_admin_grants
-- code path going forward.
--
-- Design choices:
--
--   - The cluster_admin_grants table is NOT dropped. The InternalClusterService
--     handler is kept as a backwards-compat wrap that creates AccessBinding
--     rows; the legacy table stays for read-only audit until UI cutover (a
--     later migration drops it).
--
--   - Role choice -- every cluster admin gets the global "admin" role
--     (id = rol || substr(md5('admin'), 1, 17), the global super-admin
--     role seeded by 0001_initial.sql section 4.1). This matches the
--     existing FGA tuple emit (system_admin@cluster:cluster_kacho_root)
--     and keeps the "one role per tier" mental model uniform across
--     all scopes.
--
--   - granted_by_user_id mirrors cluster_admin_grants.granted_by (which
--     stores usr_<id> or 'bootstrap'; both pass the 1..64 length check).
--     The access_bindings.granted_by_user_id column has the same length
--     CHECK so the carry-over is field-compatible.
--
--   - Revoked grants get status='REVOKED', revoked_at = granted_until,
--     revoked_by_user_id = 'system:cluster-admin-backfill'. Per
--     access_bindings_revoked_consistency_ck both columns MUST move
--     atomically with status; the constant suffix is the literal we use
--     in the rest of the unify backfill.
--
--   - created_at carries over granted_at (the timestamp the cluster
--     admin was granted) so the audit timeline is preserved.
--
--   - Synthetic id format: 'abc' || substr(cag_id, 5, 17) -- strips the
--     legacy 'cag_' prefix (4 chars) and prepends the new 'abc' prefix
--     (3+17 = 20 chars total). The cag_id format is already validated
--     (regex ^cag_[…]{17}$) by cluster_admin_grants_id_check, so the
--     tail is exactly 17 Crockford base32 characters. Deterministic and
--     idempotent -- re-running the migration hits the PK conflict on the
--     same id.
--
--   - ON CONFLICT DO NOTHING -- the partial UNIQUE
--     access_bindings_active_grant_uniq (WHERE revoked_at IS NULL,
--     migration 0003) catches active-grant re-runs; PK (id) catches
--     revoked-history re-runs.
--
-- Idempotent -- safe to re-run.

DO $migration$
DECLARE
  v_admin_role_id TEXT;
  v_count_active  INT;
  v_count_revoked INT;
BEGIN
  -- Resolve the global "admin" role id once. The id format is deterministic
  -- (rol || substr(md5('admin'), 1, 17)) so the lookup by name is safe.
  SELECT id INTO v_admin_role_id
    FROM kacho_iam.roles
   WHERE name = 'admin'
     AND cluster_id = 'cluster_kacho_root'
     AND is_system  = true;

  IF v_admin_role_id IS NULL THEN
    RAISE EXCEPTION 'cluster-admin backfill: roles/admin (name=admin) not found in kacho_iam.roles -- seed missing';
  END IF;

  -- --- Step 1: backfill ACTIVE cluster_admin_grants ----------------------
  --
  -- access_bindings_active_grant_uniq (WHERE revoked_at IS NULL) catches
  -- re-runs. We use a deterministic synthetic id 'abc' || substr(cag_id, 5, 17)
  -- so the access_binding id is stable across re-runs (PK conflict =
  -- already backfilled = NO-OP).
  WITH src AS (
    SELECT id, subject_type, subject_id, granted_by, granted_at
      FROM kacho_iam.cluster_admin_grants
     WHERE granted_until IS NULL
  )
  INSERT INTO kacho_iam.access_bindings (
      id, subject_type, subject_id, role_id, resource_type, resource_id,
      status, granted_by_user_id, created_at
  )
  SELECT
      'abc' || substr(src.id, 5, 17),
      src.subject_type,
      src.subject_id,
      v_admin_role_id,
      'cluster',
      'cluster_kacho_root',
      'ACTIVE',
      CASE
        WHEN length(src.granted_by) <= 64 THEN src.granted_by
        ELSE substr(src.granted_by, 1, 64)
      END,
      src.granted_at
  FROM src
  ON CONFLICT DO NOTHING;
  GET DIAGNOSTICS v_count_active = ROW_COUNT;
  RAISE NOTICE 'cluster-admin backfill: active grants inserted=%', v_count_active;

  -- --- Step 2: backfill REVOKED cluster_admin_grants (history) -----------
  --
  -- Revoked rows have granted_until IS NOT NULL -> outside the partial
  -- UNIQUE for active grants. We de-dup via PK on the synthetic id
  -- (re-runs become NO-OP).
  WITH src AS (
    SELECT id, subject_type, subject_id, granted_by, granted_at, granted_until
      FROM kacho_iam.cluster_admin_grants
     WHERE granted_until IS NOT NULL
  )
  INSERT INTO kacho_iam.access_bindings (
      id, subject_type, subject_id, role_id, resource_type, resource_id,
      status, granted_by_user_id, revoked_at, revoked_by_user_id, created_at
  )
  SELECT
      'abc' || substr(src.id, 5, 17),
      src.subject_type,
      src.subject_id,
      v_admin_role_id,
      'cluster',
      'cluster_kacho_root',
      'REVOKED',
      CASE
        WHEN length(src.granted_by) <= 64 THEN src.granted_by
        ELSE substr(src.granted_by, 1, 64)
      END,
      src.granted_until,                          -- revoked_at = old granted_until
      'system:cluster-admin-backfill',            -- revoked_by_user_id
      src.granted_at
  FROM src
  ON CONFLICT (id) DO NOTHING;
  GET DIAGNOSTICS v_count_revoked = ROW_COUNT;
  RAISE NOTICE 'cluster-admin backfill: revoked grants inserted=%', v_count_revoked;
END
$migration$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
--
-- Reverse the backfill -- delete every access_bindings row that was created
-- by this migration. The synthetic id prefix 'abc' followed by a 17-char
-- crockford tail matching a cluster_admin_grants.id (modulo 'cag_'/'abc'
-- prefix swap) makes the targeted DELETE unambiguous.
DELETE FROM kacho_iam.access_bindings ab
 WHERE ab.resource_type = 'cluster'
   AND ab.resource_id   = 'cluster_kacho_root'
   AND EXISTS (
       SELECT 1
         FROM kacho_iam.cluster_admin_grants cag
        WHERE 'abc' || substr(cag.id, 5, 17) = ab.id
   );
-- +goose StatementEnd
