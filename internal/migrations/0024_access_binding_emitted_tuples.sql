-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up

-- Persisted exact emitted-tuple set per
-- AccessBinding (the FGA tuples that were ACTUALLY written to fga_outbox at
-- grant time / last reconcile time).
--
-- WHY this table exists (the orphan-tuple bug):
--   Before this table, AccessBinding revoke (delete.go) RE-DERIVED the tuple set
--   from the binding's CURRENT role.permissions and emitted EmitRelationDelete on
--   THAT. If Role.Update mutated the role's permissions between grant and revoke,
--   the re-derived set no longer matched what was actually granted → the revoke
--   deleted the wrong tuples and left orphan FGA tuples = standing privilege that
--   InternalIAMService.Check then resolves against forever. Symmetry must come
--   from a PERSISTED record of what was emitted, NOT from the (mutable) role.
--
--   Likewise Role.Update of an active role's permissions previously only emitted
--   an audit event and did NOT reconcile the FGA tuples of active bindings — so a
--   dropped permission left its tuple standing (an orphaned tuple). This table is the
--   diff base (old emitted-set) the reconcile fan-out diffs against the new
--   derive-from-role set to compute add/remove.
--
-- WITHIN-SERVICE INVARIANTS — DB-level only (ban #10):
--   * binding_id FK REFERENCES access_bindings(id) ON DELETE CASCADE — the
--     emitted-set rows are owned by their binding; deleting the binding row (the
--     revoke DELETE in delete.go) atomically drops the emitted-set rows in the
--     SAME tx (no software cleanup, no orphan store rows). The revoke SELECTs the
--     set BEFORE the DELETE so it can emit EmitRelationDelete on the exact set.
--   * PK (binding_id, fga_user, relation, object) — a tuple is recorded at most
--     once per binding (the natural key of an FGA tuple). A re-grant / repeated
--     reconcile of the SAME tuple is an idempotent no-op (INSERT … ON CONFLICT DO
--     NOTHING). No surrogate id — the tuple IS its identity.
--   * fga_user / relation / object NOT NULL + non-empty CHECK — mirror the
--     emitFGAOutbox tuple-completeness guard so a malformed tuple can never be
--     persisted as the revoke source of truth.
--
-- NOT on any API surface — internal exactness ledger for symmetric revoke +
-- Role.Update reconcile. Authoritative for "what was emitted", co-committed with
-- the fga_outbox emit in the SAME writer-tx (atomic, ban #10).

CREATE TABLE kacho_iam.access_binding_emitted_tuples (
  binding_id text NOT NULL
    REFERENCES kacho_iam.access_bindings(id) ON DELETE CASCADE,
  -- fga_user — the FGA user side of the tuple, already in canonical FGA form
  -- (e.g. "user:usr_x", "group:grp_y#member", "project:prj_z"). Stored verbatim
  -- as it was emitted to fga_outbox so EmitRelationDelete is byte-symmetric.
  fga_user text NOT NULL,
  relation text NOT NULL,
  object   text NOT NULL,

  CONSTRAINT access_binding_emitted_tuples_pk
    PRIMARY KEY (binding_id, fga_user, relation, object),
  CONSTRAINT access_binding_emitted_tuples_user_nonempty   CHECK (fga_user <> ''),
  CONSTRAINT access_binding_emitted_tuples_relation_nonempty CHECK (relation <> ''),
  CONSTRAINT access_binding_emitted_tuples_object_nonempty  CHECK (object <> '')
);

-- Lookup-by-binding: revoke (delete.go) and the Role.Update reconcile fan-out both
-- SELECT the stored set of ONE binding. The PK leading column (binding_id) already
-- serves equality lookups, so no extra index is required — documented here so a
-- future reviewer does not add a redundant one. (Kept as a comment, not an index.)

-- +goose Down

DROP TABLE IF EXISTS kacho_iam.access_binding_emitted_tuples;
