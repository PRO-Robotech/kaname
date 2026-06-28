-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up

-- The reconcile
-- event queue. When RegisterResource/UnregisterResource UPSERTs/DELETEs a
-- kacho_iam.resource_mirror row, it ALSO enqueues a reconcile event HERE in the
-- SAME writer-tx (atomic co-commit with the mirror change, ban #10). The
-- reconciler-worker consumes these events and re-evaluates every
-- access_binding_target_member that references the changed object (recompute
-- membership / containment for affected selector + byName bindings).
--
-- WHY event-driven: it reuses the existing kacho-iam outbox-tx
-- path (atomic with the mirror upsert) without a new poll-cycle on the hot
-- RegisterResource path. A periodic reconcile-sweep is the defense-in-depth
-- complement that catches a lost event / a worker restart before drain — so the
-- queue is an OPTIMIZATION (fast path), never the sole correctness guarantee.
--
-- WITHIN-SERVICE INVARIANTS — DB-level only (ban #10):
--   * id bigserial PK — drain order; the reconciler claims a batch and marks
--     sent_at, mirroring kacho_iam.fga_outbox / subject_change_outbox.
--   * sent_at NULL until drained — a partial index over the unsent tail keeps the
--     drain claim-scan tight (the hot path is "next unsent events").
--   * object_type/object_id — the changed mirror object the event is about; the
--     reconciler re-evaluates members referencing it (by-object index on
--     access_binding_target_members). NOT a tuple — the reconcile event is a
--     "this object changed, recompute" signal, distinct from fga_outbox tuples.
--
-- This table is an INTERNAL coordination queue (never on any API surface); it is
-- NOT authoritative state — the authoritative desired-state is
-- access_binding_target_members, recomputed from resource_mirror (source = owner).

CREATE TABLE kacho_iam.resource_reconcile_outbox (
  id          bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  object_type text        NOT NULL,
  object_id   text        NOT NULL,
  -- event_type — 'mirror.upsert' | 'mirror.delete'; the reconciler treats both
  -- as "this object's mirror state changed, recompute affected memberships" and
  -- recomputes from the LIVE resource_mirror (so a delete event simply finds the
  -- row gone). Kept for observability / future selectivity.
  event_type  text        NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  sent_at     timestamptz,
  last_error  text,
  attempt_count integer   NOT NULL DEFAULT 0,

  CONSTRAINT resource_reconcile_outbox_type_nonempty CHECK (object_type <> ''),
  CONSTRAINT resource_reconcile_outbox_id_nonempty   CHECK (object_id <> ''),
  CONSTRAINT resource_reconcile_outbox_event_valid
    CHECK (event_type IN ('mirror.upsert', 'mirror.delete'))
);

-- Drain claim-scan: the reconciler polls the unsent tail ordered by id.
CREATE INDEX resource_reconcile_outbox_unsent_idx
  ON kacho_iam.resource_reconcile_outbox (id)
  WHERE sent_at IS NULL;

-- +goose Down

DROP TABLE IF EXISTS kacho_iam.resource_reconcile_outbox;
