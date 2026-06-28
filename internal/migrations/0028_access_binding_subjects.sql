-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up

-- RBAC rules-model 2026 — multi-subject set of
-- an AccessBinding. A binding may grant the same role+scope to 1..32 subjects;
-- each subject is an INDEPENDENT grantee with its own FGA tuple-set lineage
-- (the existing access_binding_emitted_tuples ledger already distinguishes a
-- subject by its `fga_user` value — "user:usr_x" / "group:grp_y#member" — so
-- per-subject revoke needs no new ledger column). The access_bindings row keeps
-- the legacy single subject_type/subject_id = subjects[0] (read-projection
-- + the active-grant UNIQUE anchor, migration 0003).
--
-- WITHIN-SERVICE INVARIANTS — DB-level only (ban #10):
--   * binding_id FK → access_bindings(id) ON DELETE CASCADE — same-DB cascade
--     (ban #4 explicitly allows same-schema FK cascade). Deleting a binding row
--     atomically drops all its subject rows (no software cleanup, no orphans).
--   * PRIMARY KEY (binding_id, subject_type, subject_id) — exactly one row per
--     (binding, subject); a duplicate subject in subjects[] raises 23505 (the
--     use-case also rejects it sync via domain.NormalizeSubjects, defense-in-
--     depth). Concurrent double-insert of the same (binding,subject) serializes
--     on the PK row-lock leaving exactly one row.
--   * subject_type CHECK — closed set (user|service_account|group), mirrors the
--     domain SubjectType enum so an arbitrary type can never land.
--   * subject_id non-empty CHECK.
--
-- NOT infra-sensitive — tenant-facing grant metadata (who the role is granted
-- to). Surfaced on read via the dual subjects[]/legacy projection.

CREATE TABLE kacho_iam.access_binding_subjects (
  binding_id   text NOT NULL
    REFERENCES kacho_iam.access_bindings(id) ON DELETE CASCADE,
  subject_type text NOT NULL,
  subject_id   text NOT NULL,
  -- ordinal preserves the request order of subjects[] so the read-side returns
  -- the set in a stable order and subjects[0] (= the legacy single projection)
  -- is deterministic across reads.
  ordinal      int  NOT NULL DEFAULT 0,

  CONSTRAINT access_binding_subjects_pk
    PRIMARY KEY (binding_id, subject_type, subject_id),
  CONSTRAINT access_binding_subjects_type_ck
    CHECK (subject_type IN ('user', 'service_account', 'group')),
  CONSTRAINT access_binding_subjects_id_nonempty_ck
    CHECK (subject_id <> '')
);

-- Read-side loads ALL subjects of ONE binding (Get) or MANY bindings (List /
-- ListByRole batch). The PK leading column (binding_id) serves the single-binding
-- equality lookup; a dedicated index covers the batch `binding_id = ANY($1)` load
-- and keeps the ordinal ordering cheap.
CREATE INDEX access_binding_subjects_binding_ordinal_idx
  ON kacho_iam.access_binding_subjects (binding_id, ordinal);

-- Backfill: one subject row per EXISTING binding from its legacy single subject
-- (reverse projection — a legacy-single binding carries a one-element
-- subjects[]). Idempotent on re-apply (ON CONFLICT DO NOTHING). Skips rows with
-- an empty subject_id (none expected — the column is NOT NULL with a non-empty
-- domain invariant — but guard defensively so the backfill never inserts an
-- invalid child row).
INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id, ordinal)
SELECT id, subject_type, subject_id, 0
  FROM kacho_iam.access_bindings
 WHERE subject_id <> ''
ON CONFLICT (binding_id, subject_type, subject_id) DO NOTHING;

-- +goose Down

DROP TABLE IF EXISTS kacho_iam.access_binding_subjects;
