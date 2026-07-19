-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up

-- Btree index on resource_mirror.parent_project_id to support the ARM_ANCHOR (`all`)
-- reconcile scope push-down (MatchAllInScope → resource_mirror.AllByTypes).
--
-- The anchor arm now narrows the candidate set to the binding's containment scope IN SQL
-- (proven superset of the domain IsContainedIn re-verify) instead of reading the WHOLE
-- resource_mirror of the cluster and filtering in Go. The scope predicate is:
--
--   project scope → WHERE object_type = ANY(...) AND parent_project_id = $scope
--   account scope → WHERE object_type = ANY(...)
--                     AND COALESCE(NULLIF(parent_account_id,''), pj.account_id,'') = $scope
--                     (LEFT JOIN kacho_iam.projects pj ON pj.id = parent_project_id)
--
-- Index support (verified against the actual predicate — see doc-truthfulness note below):
--   * PROJECT scope — served DIRECTLY by this index (equality on parent_project_id) after the
--     PK (object_type, object_id) prefix narrows object_type. This is the PRIMARY win: the
--     hot newman/create path is a PROJECT-scoped creator grant (project owner/editor), so this
--     index turns that reconcile from O(cluster mirror) into O(scope) at the storage layer.
--   * ACCOUNT scope — NOT driven by this index. The predicate is
--     `COALESCE(NULLIF(parent_account_id,''), pj.account_id,'') = $acct` over a LEFT JOIN to
--     projects, and it is NOT null-rejecting on pj (a join-miss row still qualifies via
--     parent_account_id), so the planner CANNOT fold the LEFT JOIN to an inner join and MUST
--     keep resource_mirror as the outer relation — projects cannot become the driving side.
--     The account-scope anchor read therefore still scans O(rows-of-requested-types) at the
--     storage layer (via the PK on object_type), joining projects by PK per row. The scope
--     push-down STILL wins on this path — only the in-scope rows cross the pgx wire and hit
--     the Go IsContainedIn re-verify (was: whole mirror deserialized + filtered in Go) — but
--     the win is wire/CPU, not a smaller storage scan. Making the account path index-drivable
--     would require decomposing the predicate (resolve account→project_ids via
--     projects_account_idx, then `parent_account_id = $acct OR parent_project_id = ANY(pids)`)
--     — deferred until account-owner reconcile latency is shown (by EXPLAIN ANALYZE on real
--     data) to matter; the targeted register-forward path is the other lever (see reconcile.go).
--
-- resource_mirror grows with EVERY vpc/compute/nlb resource registered cluster-wide. Plain
-- (non-CONCURRENT) CREATE INDEX in the goose tx, matching the table's other index migrations
-- (0019 GIN); the table is append-mostly and small on fresh installs. On a matured cluster a
-- plain build briefly write-locks resource_mirror (stalling RegisterResource UPSERTs) — switch
-- to CREATE INDEX CONCURRENTLY (needs the goose NO-TRANSACTION directive, keep IF NOT EXISTS)
-- if that ever bites.
CREATE INDEX IF NOT EXISTS resource_mirror_parent_project_idx
    ON kacho_iam.resource_mirror (parent_project_id);

-- +goose Down

DROP INDEX IF EXISTS kacho_iam.resource_mirror_parent_project_idx;
