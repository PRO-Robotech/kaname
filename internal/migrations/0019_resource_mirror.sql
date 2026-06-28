-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up

-- kacho_iam.resource_mirror is an OUTPUT-ONLY mirror (cross-domain rule:
-- denormalized read-only copy) of the labels + parent-scope of resources owned
-- by OTHER services (compute first; vpc later).
-- It is fed PUSH-style over the existing `compute→iam` FGA-proxy edge
-- (RegisterResource / UnregisterResource, Internal-only :9091) — IAM never pulls
-- from compute, so the cross-domain graph stays acyclic (no iam→compute edge).
--
-- Source of truth = the owning service (compute). This table is NOT authoritative,
-- is never validated on a public-API input path, and must gracefully survive a
-- dangling ref (the owner object disappearing without an Unregister).
--
-- This migration only FILLS the mirror. Neither selector-matching nor the
-- containment gate reads it for authz decisions — that is the read-side. The
-- labels + parent_* are denormalized copies kept SAME-DB so the read-side can
-- match a selector (labels @> {...}) and enforce containment (object under
-- scope = parent_* == scope-anchor) WITHOUT the forbidden iam→compute peer
-- call (resolved with DATA, not a peer call).
--
-- WITHIN-SERVICE INVARIANTS — DB-level only (ban #10):
--   * PK (object_type, object_id) — exactly one row per object ⇒ UPSERT
--     idempotency under the at-least-once drainer: a repeated
--     RegisterResource (drainer retry) is a no-op-equivalent ON CONFLICT DO
--     UPDATE; a concurrent double-register of the same object serializes on the
--     PK row-lock, leaving exactly one row with a deterministic last-write.
--     No software check-then-act.
--   * source_version — a MONOTONIC
--     per-object marker stamped at the SOURCE (compute) when it emits the
--     register/unregister intent inside its writer-tx. The UPSERT applies a
--     register ONLY when EXCLUDED.source_version > the stored one, so the mirror
--     is LAST-SOURCE-STATE-WINS, not last-applier-wins: under an HA register-
--     drainer that reorders two intents of one object (replica applies v2, then
--     a stale v1) the stale intent is a DB-level no-op (0 rows updated), never an
--     overwrite with older labels. Symmetrically DELETE only fires when the
--     unregister tombstone-version >= the stored register, so a Delete-after-
--     Update reorder cannot wipe a fresher row. DEFAULT '-infinity' makes a
--     legacy/empty source_version (older producer) behave as the old
--     unconditional last-write (back-compat: any register/delete still applies).
--     Residual edge — a *stale* register arriving AFTER an unregister (the row is
--     already gone, so the conditional INSERT cannot compare and would resurrect)
--     is left to the reconcile-sweep (the mirror is never read for an authz
--     decision while it is only being filled; benign dangling). See docs/architecture.
--   * CHECK labels IS a JSONB object — minimal DB-level sanity guard so an
--     arbitrary non-object JSONB can never land (the full Kachō label-pattern
--     sanity validation lives in the use-case, defense-in-depth).
--
-- CROSS-DOMAIN (ban #4/#8): object_id is an opaque cross-DB soft-ref — NO FK to
-- any compute/vpc table (different database). dangling is tolerated, not cascaded.
--
-- GIN on labels: the read-side will probe `labels @> '{"env":"prod"}'`
-- for selector matching — the index is created now so the read-side needs no
-- schema change.

CREATE TABLE kacho_iam.resource_mirror (
  object_type       text        NOT NULL,
  object_id         text        NOT NULL,
  parent_project_id text        NOT NULL DEFAULT '',
  parent_account_id text        NOT NULL DEFAULT '',
  labels            jsonb       NOT NULL DEFAULT '{}'::jsonb,
  source_version    timestamptz NOT NULL DEFAULT '-infinity',
  updated_at        timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT resource_mirror_pkey PRIMARY KEY (object_type, object_id),
  CONSTRAINT resource_mirror_type_nonempty CHECK (object_type <> ''),
  CONSTRAINT resource_mirror_id_nonempty   CHECK (object_id <> ''),
  CONSTRAINT resource_mirror_labels_object CHECK (jsonb_typeof(labels) = 'object')
);

-- Read-side selector-matching probe (`labels @> '{...}'`); this migration just fills.
CREATE INDEX resource_mirror_labels_gin ON kacho_iam.resource_mirror USING gin (labels);

-- +goose Down

DROP TABLE IF EXISTS kacho_iam.resource_mirror;
